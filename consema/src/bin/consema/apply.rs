//! `consema apply`: the batch write command (RFC 0015 §9; implementation
//! plan §6 M8).
//!
//! `apply` consumes one plan manifest (the positional path; strictly decoded
//! as `core.batch-plan@1` via [`crate::manifest::decode_plan_manifest`]) and,
//! per file, executes the frozen six-step flow of RFC 0015 §9.3:
//!
//! ```text
//! 1. re-read the file, recompute the digest, compare against the plan's
//!    source_digest              ← stale → skipped-stale
//!                                  (core.source.patch-base-mismatch@1), no write
//! 2. verify each replacement's original-bytes precondition (SourcePatch
//!    semantics; the SDK re-checks the base digest, encoding facts, and every
//!    original byte at its offset)
//! 3. mark this file pending and persist the result manifest (R-5: pending
//!    first — a crash here leaves the file untouched and truthfully pending)
//! 4. atomically write the target file (fsio: same-directory temp + atomic
//!    replace, symlink/read-only/directory policy enforced)
//! 5. read back and verify the target digest (mismatch →
//!    core.source.patch-target-mismatch@1 plus the cli.write.io@1
//!    environment diagnostic; the file is replaced and not rolled back)
//! 6. mark this file completed and persist the result manifest
//! ```
//!
//! Before the fresh flow, every file is branched through the RFC 0015 §9.4
//! recovery three-way rule on the **current disk bytes**: digest ==
//! `source_digest` → execute the full flow; digest == `target_digest` →
//! already effective, mark completed and skip (no rewrite); any other digest
//! → `skipped-stale` (exit 4). This is what makes a re-run resume a crashed
//! or interrupted batch: completed files are recognized by their bytes,
//! failed files are re-reported, pending files are redone.
//!
//! The result manifest (`core.batch-result@1`) is persisted **before any
//! write** in an all-pending state and **after each file** in its new state,
//! through the fsio atomic engine; the default path is `{plan-file}.result.json`
//! (RFC 0015 §8.3), overridden by `--output`. A completed run's manifest
//! contains no `pending`; a pending entry appears only in manifests written
//! by interruption or crash.
//!
//! # Exit codes
//!
//! Any `failed` or `skipped-stale` file → exit 4 (RFC 0015 §5.2, regardless
//! of that file's failure_code — file-level failures are uniformly unfulfilled
//! write preconditions); all `completed` → 0. CLI-layer failures classify
//! normally: usage 1, plan-manifest decode 2, limits 3, result-manifest
//! write 4, interruption 4.
//!
//! # Interruption (RFC 0015 §5.4/§9.4)
//!
//! The binary is std-only with `unsafe_code = forbid` (workspace lint), so a
//! real OS signal handler cannot be installed; the graceful-shutdown
//! sequence is therefore reachable through the **documented injection point**
//! `CONSEMA_APPLY_INTERRUPT_AFTER=<n>` (0-based file index), which fires at
//! the exact code point a SIGINT/SIGTERM would be handled: after the pending
//! manifest of file `n` is persisted (step 3) and before its target write
//! (step 4). The sequence writes no further bytes to stdout (RFC 0015 §4.2:
//! interruption never produces an envelope), emits
//! `cli.interrupted.signal@1` on stderr, and exits 4, leaving the in-flight
//! file pending in the on-disk manifest. The shell-convention code 130 is
//! not adopted (RFC 0015 §5.4; §17).
//!
//! # Failure injection
//!
//! Permission and disk-full failures cannot be produced deterministically
//! against a real filesystem on every platform (Windows ACLs, no tiny
//! volumes); following the milestone-M6 `FsBackend` approach at the process
//! level, `CONSEMA_APPLY_WRITE_FAILURE=permission|io` makes the **first**
//! atomic target write fail with the named `cli.write.*` error. All other
//! failure injections (stale digest, tampered patch, read-only, symlink/
//! junction, directory target, result-manifest write failure) use real
//! filesystem states.
//!
//! # Per-file `redacted` fact
//!
//! RFC 0015 §11.3: the result entry's `redacted` flag is true when the
//! file's edit operations contain at least one key name matching the
//! presentation redaction policy. On the wire the plan manifest's operations
//! are the SDK's content-free operation summaries (RFC 0015 §8.2), so the
//! key names available at apply time are the summaries' argument names
//! (e.g. `representation_policy`, `value_scalars`); target entry key names
//! are deliberately not part of the plan manifest (the M7 content-free
//! summary contract), so they cannot be consulted here. The manifest bytes
//! themselves are never redacted (RFC 0015 §11.4; hard gate 3).

use crate::args::ParsedArgs;
use crate::edit_cmd::redact_policy;
use crate::manifest;
use crate::query_cmd::{FlowError, emit_envelope, emit_failure, internal_failure};
use crate::redact::RedactPolicy;
use consema::document::{
    ContentDigest, EncodingRequest, SourceLimits, SourcePatch, SourcePatchError, SourcePatchLimits,
    SourceSnapshot,
};
use consema::protocol::{
    BatchPlanFileEntry, BatchPlanFileStatus, BatchPlanMessage, BatchResultFileEntry,
    BatchResultFileStatus, BatchResultMessage, CliCommand, ExitClass, ProtocolLimits,
    classify_error_code,
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

/// The frozen batch file-count cap of RFC 0015 §12.
const DEFAULT_MAX_FILES: u64 = 1000;

/// The frozen stale-digest failure code of RFC 0015 §9.3 step 1/§9.4.
const STALE_CODE: &str = "core.source.patch-base-mismatch@1";

/// The frozen interruption code of RFC 0015 §13.1.
const INTERRUPTED_CODE: &str = "cli.interrupted.signal@1";

/// The documented interruption injection point (see the module docs).
const INTERRUPT_AFTER_ENV: &str = "CONSEMA_APPLY_INTERRUPT_AFTER";

/// The documented write-failure injection point (see the module docs).
const WRITE_FAILURE_ENV: &str = "CONSEMA_APPLY_WRITE_FAILURE";

/// Runs `consema apply` (the plan manifest is the single positional; the
/// result manifest defaults to `{plan-file}.result.json`, overridden by
/// `--output`).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let policy = match redact_policy(parsed) {
        Ok(policy) => policy,
        Err(error) => return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr),
    };
    let plan_path = &parsed.positionals[0];
    let cap = parsed
        .max_bytes
        .unwrap_or_else(|| u64::try_from(ProtocolLimits::default().max_bytes).expect("fits u64"));
    let plan_bytes = match read_plan_file(plan_path, cap) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr),
    };
    let plan = match manifest::decode_plan_manifest(&plan_bytes) {
        Ok(plan) => plan,
        Err(error) => return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr),
    };
    let file_cap = parsed.max_files.unwrap_or(DEFAULT_MAX_FILES);
    if u64::try_from(plan.files().len()).expect("usize fits u64") > file_cap {
        let error = FlowError::new(
            "cli.limit.batch-count@1",
            format!(
                "plan batch of {} files exceeds the {file_cap}-file cap (--max-files)",
                plan.files().len()
            ),
        );
        return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr);
    }
    let result_path = parsed
        .output
        .clone()
        .unwrap_or_else(|| format!("{plan_path}.result.json"));
    let injections = Injections::from_env();
    let outcome = match run_batch(&plan, &result_path, cap, &policy, &injections, stderr) {
        Ok(outcome) => outcome,
        Err(error) => return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr),
    };
    if outcome.interrupted {
        // RFC 0015 §5.4/§4.2: after interruption stdout receives no further
        // bytes (no envelope, no report); the stderr line was already written
        // by the state machine, and the pending manifest stays on disk.
        return classify_error_code(INTERRUPTED_CODE).exit_code();
    }
    let exit_class = if outcome.entries.iter().any(|entry| {
        matches!(
            entry.status,
            BatchResultFileStatus::Failed | BatchResultFileStatus::SkippedStale
        )
    }) {
        ExitClass::Precondition
    } else {
        ExitClass::Success
    };
    let message = match result_message(&outcome.entries) {
        Ok(message) => message,
        Err(error) => {
            return emit_failure(CliCommand::Apply, parsed, &error, stdout, stderr);
        }
    };
    if parsed.json {
        match emit_envelope(
            CliCommand::Apply,
            exit_class,
            message.to_value(),
            Vec::new(),
            parsed,
            stdout,
        ) {
            Ok(()) => exit_class.exit_code(),
            Err(message) => internal_failure("apply", &message, stderr),
        }
    } else {
        match write_apply_report(&outcome.entries, stdout) {
            Ok(()) => exit_class.exit_code(),
            Err(message) => internal_failure("apply", &message, stderr),
        }
    }
}

/// The per-file result state (the mutable working form of a
/// `core.batch-result@1` entry).
#[derive(Clone, Debug)]
struct EntryState {
    /// The user-supplied path spelling, verbatim (RFC 0015 §3.3).
    path: String,
    /// The current per-file status.
    status: BatchResultFileStatus,
    /// The frozen failure code of failed/skipped-stale files.
    failure_code: Option<String>,
    /// The verified target digest of completed files.
    target_digest: Option<ContentDigest>,
    /// Whether the file's edit operations match a redaction key pattern.
    redacted: bool,
}

/// The outcome of one apply run.
struct BatchOutcome {
    /// Per-file result states in plan order.
    entries: Vec<EntryState>,
    /// Whether the run was interrupted (the pending manifest stays on disk).
    interrupted: bool,
}

/// The documented process-level injection seam (see the module docs).
#[derive(Clone, Debug, Default)]
struct Injections {
    /// Interrupt after the pending manifest of this 0-based file index.
    interrupt_after: Option<usize>,
    /// Fail the first atomic target write with these (code, message) facts.
    write_failure: Option<(String, String)>,
    /// Whether the injected write failure has been consumed.
    write_failure_fired: Cell<bool>,
}

impl Injections {
    /// Reads the injection points from the environment (deterministic: an
    /// absent, malformed, or out-of-range value disables the injection).
    fn from_env() -> Self {
        let interrupt_after = std::env::var(INTERRUPT_AFTER_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        let write_failure = match std::env::var(WRITE_FAILURE_ENV).ok().as_deref() {
            Some("permission") => Some((
                "cli.write.permission@1".to_owned(),
                format!("injected permission failure ({WRITE_FAILURE_ENV}=permission)"),
            )),
            Some("io") => Some((
                "cli.write.io@1".to_owned(),
                format!("injected disk-full failure ({WRITE_FAILURE_ENV}=io)"),
            )),
            _ => None,
        };
        Self {
            interrupt_after,
            write_failure,
            write_failure_fired: Cell::new(false),
        }
    }

    /// The injected write failure, consumed exactly once (the first atomic
    /// target write of the run).
    fn take_write_failure(&self) -> Option<(String, String)> {
        if self.write_failure_fired.get() {
            return None;
        }
        self.write_failure_fired.set(true);
        self.write_failure.clone()
    }
}

/// Runs the apply state machine against the real filesystem (RFC 0015 §9.3).
///
/// Every state transition persists the result manifest atomically; a
/// persistence failure aborts the whole run with its `cli.write.*` error
/// (the batch cannot continue truthfully without a recovery record).
fn run_batch(
    plan: &BatchPlanMessage,
    result_path: &str,
    cap: u64,
    policy: &RedactPolicy,
    injections: &Injections,
    stderr: &mut dyn Write,
) -> Result<BatchOutcome, FlowError> {
    let mut entries: Vec<EntryState> = plan
        .files()
        .iter()
        .map(|entry| EntryState {
            path: entry.path().to_owned(),
            status: BatchResultFileStatus::Pending,
            failure_code: None,
            target_digest: None,
            redacted: entry_redacted(entry, policy),
        })
        .collect();
    // RFC 0015 §9.3 step 3 for the whole batch, risk point R-5: the pending
    // manifest is persisted BEFORE any target write, so a crash at any point
    // before a file's write leaves that file truthfully pending.
    persist_entries(&entries, result_path)?;
    for (index, plan_entry) in plan.files().iter().enumerate() {
        if plan_entry.status() == BatchPlanFileStatus::Failed {
            // RFC 0015 §9.4: failed files are re-reported on every run — the
            // plan could not plan them, so apply has nothing to write.
            let code = plan_entry
                .failure_code()
                .expect("failed plan entries carry a failure code")
                .to_owned();
            let _ = writeln!(
                stderr,
                "consema: error: apply: {}: plan-time failure re-reported (code {code})",
                plan_entry.path()
            );
            entries[index].status = BatchResultFileStatus::Failed;
            entries[index].failure_code = Some(code);
            entries[index].target_digest = None;
            persist_entries(&entries, result_path)?;
            continue;
        }
        // Planned files: the RFC 0015 §9.4 three-way recovery rule branches
        // on the current disk bytes first.
        let patch = plan_entry
            .source_patch()
            .expect("planned entries carry a source patch");
        let source_digest = plan_entry
            .source_digest()
            .expect("planned entries carry a source digest");
        let target_digest = patch.target_digest();
        // Step 1 (RFC 0015 §9.3): re-read the file and recompute the digest.
        let bytes = match read_target(plan_entry.path(), cap) {
            Ok(bytes) => bytes,
            Err((code, message)) => {
                fail_entry(&mut entries[index], &code, &message, stderr);
                persist_entries(&entries, result_path)?;
                continue;
            }
        };
        let digest = ContentDigest::of(&bytes);
        if digest == target_digest {
            // RFC 0015 §9.4: already effective — mark completed, skip (no
            // rewrite; the bytes were verified against the plan's target
            // digest just now).
            entries[index].status = BatchResultFileStatus::Completed;
            entries[index].failure_code = None;
            entries[index].target_digest = Some(target_digest);
            persist_entries(&entries, result_path)?;
            continue;
        }
        if digest != source_digest {
            // RFC 0015 §9.3 step 1/§9.4 third branch: the current bytes no
            // longer match the planned base — skipped-stale, no write at all.
            fail_entry_stale(
                &mut entries[index],
                "the current file bytes no longer match the planned base digest; \
                 the file was not rewritten",
                stderr,
            );
            persist_entries(&entries, result_path)?;
            continue;
        }
        // Step 2 (RFC 0015 §9.3): verify each replacement's original-bytes
        // precondition. The SDK's `SourcePatch::apply` re-checks the base
        // digest, the encoding facts, and every original byte at its offset
        // (SourcePatch semantics — the CLI re-implements none of it).
        let snapshot = match snapshot_for(&bytes, patch) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let code = error.code();
                let message =
                    format!("the plan's source patch does not apply to the current bytes: {error}");
                fail_entry(&mut entries[index], code, &message, stderr);
                persist_entries(&entries, result_path)?;
                continue;
            }
        };
        let target = match patch.apply(&snapshot, SourcePatchLimits::default()) {
            Ok(target) => target,
            Err(error) => {
                let code = error.code();
                let message =
                    format!("the plan's source patch does not apply to the current bytes: {error}");
                fail_entry(&mut entries[index], code, &message, stderr);
                persist_entries(&entries, result_path)?;
                continue;
            }
        };
        // Step 3 (RFC 0015 §9.3, risk point R-5): mark this file pending and
        // persist the manifest BEFORE the target write.
        entries[index].status = BatchResultFileStatus::Pending;
        entries[index].failure_code = None;
        entries[index].target_digest = None;
        persist_entries(&entries, result_path)?;
        // The documented interruption injection point: SIGINT/SIGTERM would
        // be handled exactly here, after the pending manifest and before the
        // write (RFC 0015 §5.4; the graceful-shutdown sequence).
        if injections.interrupt_after == Some(index) {
            let _ = writeln!(
                stderr,
                "consema: error: apply: interrupted by SIGINT/SIGTERM: the result \
                 manifest keeps the in-flight file '{}' pending; re-run apply with \
                 the same plan to resume (code {INTERRUPTED_CODE})",
                plan_entry.path()
            );
            return Ok(BatchOutcome {
                entries,
                interrupted: true,
            });
        }
        // Steps 4 + 5 (RFC 0015 §9.3): atomic write with read-back target
        // digest verification, all inside fsio (same-directory temp, atomic
        // replace, symlink/read-only/directory policy, residue cleanup).
        let write_result = match injections.take_write_failure() {
            Some((code, message)) => Err((code, message)),
            None => match crate::fsio::write_atomic(
                Path::new(plan_entry.path()),
                target.bytes(),
                crate::fsio::WriteOptions::default(),
            ) {
                Ok(outcome) => Ok(outcome.digest),
                Err(error) => Err(write_failure_facts(&error)),
            },
        };
        match write_result {
            Ok(verified_digest) => {
                // Step 6: completed — the on-disk bytes were verified by the
                // read-back to be exactly the written bytes.
                entries[index].status = BatchResultFileStatus::Completed;
                entries[index].failure_code = None;
                entries[index].target_digest = Some(verified_digest);
                persist_entries(&entries, result_path)?;
            }
            Err((code, message)) => {
                fail_entry(&mut entries[index], &code, &message, stderr);
                persist_entries(&entries, result_path)?;
            }
        }
    }
    Ok(BatchOutcome {
        entries,
        interrupted: false,
    })
}

/// Reconstructs the source snapshot of the current bytes under the plan
/// patch's encoding facts (the same resolution inputs the plan's base
/// snapshot used; `SourcePatch::apply` re-verifies the resulting facts).
fn snapshot_for(bytes: &[u8], patch: &SourcePatch) -> Result<SourceSnapshot, SourcePatchError> {
    let facts = patch.encoding_facts();
    let mut request =
        EncodingRequest::new(facts.profile_default()).with_bom_policy(facts.bom_policy());
    if let Some(declaration) = facts.declaration() {
        request = request.with_declaration(declaration);
    }
    if let Some(caller_override) = facts.caller_override() {
        request = request.with_caller_override(caller_override);
    }
    SourceSnapshot::from_raw(Arc::<[u8]>::from(bytes), request, SourceLimits::default())
        .map_err(SourcePatchError::Source)
}

/// The per-file `redacted` fact of RFC 0015 §9.2/§11.3: the file's edit
/// operations (the plan manifest's operation summaries) contain at least one
/// key name matching the presentation redaction policy.
fn entry_redacted(plan_entry: &BatchPlanFileEntry, policy: &RedactPolicy) -> bool {
    plan_entry.operations().is_some_and(|operations| {
        operations.iter().any(|operation| {
            operation
                .summary
                .keys()
                .any(|key| crate::redact::key_matches(policy, key))
        })
    })
}

/// Reads one target file with the CLI byte cap (RFC 0015 §12). Per-file
/// failures are `(code, message)` facts recorded in the batch result: an
/// over-cap file is `cli.limit.file-size@1`, an unreadable file is
/// `cli.data.io@1` (RFC 0015 §5.2: file-level failures are uniformly
/// unfulfilled write preconditions → exit 4).
fn read_target(path: &str, cap: u64) -> Result<Vec<u8>, (String, String)> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return Err((
                "cli.data.io@1".to_owned(),
                format!("cannot read source file '{path}': {error}"),
            ));
        }
    };
    let mut buffer = Vec::new();
    if let Err(error) = file.take(cap.saturating_add(1)).read_to_end(&mut buffer) {
        return Err((
            "cli.data.io@1".to_owned(),
            format!("cannot read source file '{path}': {error}"),
        ));
    }
    if u64::try_from(buffer.len()).expect("usize fits u64") > cap {
        return Err((
            "cli.limit.file-size@1".to_owned(),
            format!("source file '{path}' exceeds the {cap}-byte read cap"),
        ));
    }
    Ok(buffer)
}

/// Reads the plan-manifest file with the CLI byte cap (RFC 0015 §12: the
/// manifest-size cap is `cli.limit.manifest-size@1`, an unreadable plan is
/// `cli.data.io@1`).
fn read_plan_file(path: &str, cap: u64) -> Result<Vec<u8>, FlowError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return Err(FlowError::new(
                "cli.data.io@1",
                format!("cannot read plan manifest '{path}': {error}"),
            ));
        }
    };
    let mut buffer = Vec::new();
    if let Err(error) = file.take(cap.saturating_add(1)).read_to_end(&mut buffer) {
        return Err(FlowError::new(
            "cli.data.io@1",
            format!("cannot read plan manifest '{path}': {error}"),
        ));
    }
    if u64::try_from(buffer.len()).expect("usize fits u64") > cap {
        return Err(FlowError::new(
            "cli.limit.manifest-size@1",
            format!("plan manifest '{path}' exceeds the {cap}-byte input cap"),
        ));
    }
    Ok(buffer)
}

/// Normalizes one fsio write failure into the per-file failure facts. A
/// read-back digest mismatch (RFC 0015 §9.3 step 5; the typed
/// [`crate::fsio::WriteError::ReadBackMismatch`] variant) carries the frozen
/// `core.source.patch-target-mismatch@1` code with the `cli.write.io@1`
/// environment diagnostic named on the stderr line; every other failure
/// keeps its frozen `cli.write.*` code. The typed variant is matched, never
/// the diagnostic text — a wording change of the mismatch message must not
/// change the mapping.
fn write_failure_facts(error: &crate::fsio::WriteError) -> (String, String) {
    if let crate::fsio::WriteError::ReadBackMismatch { .. } = error {
        return (
            "core.source.patch-target-mismatch@1".to_owned(),
            format!(
                "{} (environment diagnostic cli.write.io@1)",
                error.message()
            ),
        );
    }
    (error.code().to_owned(), error.message())
}

/// Marks one entry failed and writes its deterministic stderr line.
fn fail_entry(entry: &mut EntryState, code: &str, message: &str, stderr: &mut dyn Write) {
    entry.status = BatchResultFileStatus::Failed;
    entry.failure_code = Some(code.to_owned());
    entry.target_digest = None;
    let _ = writeln!(
        stderr,
        "consema: error: apply: {}: {message} (code {code})",
        entry.path
    );
}

/// Marks one entry skipped-stale and writes its deterministic stderr line.
fn fail_entry_stale(entry: &mut EntryState, message: &str, stderr: &mut dyn Write) {
    entry.status = BatchResultFileStatus::SkippedStale;
    entry.failure_code = Some(STALE_CODE.to_owned());
    entry.target_digest = None;
    let _ = writeln!(
        stderr,
        "consema: error: apply: {}: {message} (code {STALE_CODE})",
        entry.path
    );
}

/// Builds the transferable result message of the current state (the entries
/// are constructed by the machine with the §9.2 presence rules, so the
/// protocol validation cannot fail; the error is defensive).
fn result_message(entries: &[EntryState]) -> Result<BatchResultMessage, FlowError> {
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        files.push(
            BatchResultFileEntry::new(
                entry.path.clone(),
                entry.status,
                entry.failure_code.clone(),
                entry.target_digest,
                entry.redacted,
            )
            .map_err(|error| {
                FlowError::new(
                    "cli.internal.unclassified@1",
                    format!("result entry construction failed: {error}"),
                )
            })?,
        );
    }
    BatchResultMessage::new(crate::PRODUCT_VERSION, files).map_err(|error| {
        FlowError::new(
            "cli.internal.unclassified@1",
            format!("batch-result construction failed: {error}"),
        )
    })
}

/// Encodes and atomically persists the current result state (RFC 0015 §9.3
/// manifest ordering: pending before a write, completed/failed after).
fn persist_entries(entries: &[EntryState], result_path: &str) -> Result<(), FlowError> {
    let message = result_message(entries)?;
    let bytes = manifest::encode_result_manifest(&message)?;
    manifest::persist_result_manifest(result_path, &bytes)
}

/// Deterministic human apply report (RFC 0015 §2.4: the same per-file facts
/// as the machine manifest, rendered as text).
fn write_apply_report(entries: &[EntryState], stdout: &mut dyn Write) -> Result<(), String> {
    use std::fmt::Write as FmtWrite;
    let mut text = String::new();
    let _ = writeln!(text, "consema apply: {} file(s)", entries.len());
    for entry in entries {
        match entry.status {
            BatchResultFileStatus::Completed => {
                let digest = entry
                    .target_digest
                    .map_or_else(|| "?".to_owned(), ContentDigest::to_hex);
                let _ = writeln!(text, "  {}: completed (target sha256:{digest})", entry.path);
            }
            BatchResultFileStatus::Failed => {
                let _ = writeln!(
                    text,
                    "  {}: failed {}",
                    entry.path,
                    entry.failure_code.as_deref().unwrap_or("?")
                );
            }
            BatchResultFileStatus::Pending => {
                let _ = writeln!(text, "  {}: pending", entry.path);
            }
            BatchResultFileStatus::SkippedStale => {
                let _ = writeln!(
                    text,
                    "  {}: skipped-stale {}",
                    entry.path,
                    entry.failure_code.as_deref().unwrap_or("?")
                );
            }
        }
    }
    stdout
        .write_all(text.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::document::{FormatOperationId, ProfileId, SourceReplacement};
    use consema::protocol::{EditOperationSummaryMessage, ErrorCodeRegistry};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "consema-apply-{name}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create test scratch dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn source_bytes() -> &'static [u8] {
        b"[db]\nport=8080\npassword=hunter2\n"
    }

    fn target_bytes() -> &'static [u8] {
        b"[db]\nport=9090\npassword=hunter2\n"
    }

    /// One planned entry: replace `port` (bytes 10..14) with `9090`.
    fn planned_entry(path: &str, tamper_original: bool) -> BatchPlanFileEntry {
        let base =
            SourceSnapshot::from_utf8(Arc::<[u8]>::from(source_bytes())).expect("base snapshot");
        let source_patch = SourcePatch::create(
            &base,
            vec![SourceReplacement::new(10, 14, &b"8080"[..], &b"9090"[..])],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .expect("patch");
        let source_patch = if tamper_original {
            // A structurally valid patch whose original bytes do not match
            // the base at the (shifted) offset — the RFC 0015 §9.3 step-2
            // precondition failure.
            SourcePatch::new(
                source_patch.base_digest(),
                source_patch.target_digest(),
                source_patch.encoding_facts(),
                vec![SourceReplacement::new(11, 15, &b"8080"[..], &b"9090"[..])],
                BTreeMap::new(),
                SourcePatchLimits::default(),
            )
            .expect("structurally valid tampered patch")
        } else {
            source_patch
        };
        // The summary mirrors the SDK's content-free operation summary of
        // the wired vocabulary (argument-name keys, no raw values).
        BatchPlanFileEntry::new(
            path,
            BatchPlanFileStatus::Planned,
            Some(ProfileId::new("ini.portable", 1)),
            Some(source_patch.base_digest()),
            Some(vec![EditOperationSummaryMessage {
                operation: FormatOperationId::new("ini.edit.replace-semantic-value", 1),
                summary: BTreeMap::from([("value_scalars".to_owned(), "4".to_owned())]),
            }]),
            Some(source_patch),
            None,
            None,
            ErrorCodeRegistry::v7(),
        )
        .expect("valid planned entry")
    }

    fn plan_of(entries: Vec<BatchPlanFileEntry>) -> BatchPlanMessage {
        BatchPlanMessage::new(crate::PRODUCT_VERSION, entries).expect("valid plan")
    }

    fn write_source(dir: &TestDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        path.to_string_lossy().into_owned()
    }

    /// Runs the machine and returns (outcome, on-disk manifest bytes, stderr).
    fn run_machine(
        plan: &BatchPlanMessage,
        dir: &TestDir,
        injections: Injections,
    ) -> (BatchOutcome, Vec<u8>, Vec<u8>) {
        let result_path = dir.join("result.json");
        let mut stderr = Vec::new();
        let outcome = run_batch(
            plan,
            &result_path.to_string_lossy(),
            u64::try_from(ProtocolLimits::default().max_bytes).expect("fits"),
            &RedactPolicy::conservative(),
            &injections,
            &mut stderr,
        )
        .unwrap_or_else(|error| panic!("machine failed: {}", error.message));
        let manifest_bytes = std::fs::read(&result_path).expect("result manifest");
        (outcome, manifest_bytes, stderr)
    }

    fn decode_result(bytes: &[u8]) -> BatchResultMessage {
        let limits = ProtocolLimits::default();
        BatchResultMessage::from_value(
            &consema::protocol::decode_json(bytes, limits).expect("manifest decodes"),
        )
        .expect("byte-valid batch-result")
    }

    #[test]
    fn machine_happy_path_writes_targets_and_completes_all_entries() {
        let dir = TestDir::new("happy");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        let (outcome, manifest, stderr) = run_machine(&plan, &dir, Injections::default());
        assert!(!outcome.interrupted);
        assert!(stderr.is_empty(), "no diagnostics on full success");
        let statuses: Vec<_> = outcome.entries.iter().map(|entry| entry.status).collect();
        assert_eq!(
            statuses,
            vec![
                BatchResultFileStatus::Completed,
                BatchResultFileStatus::Completed
            ]
        );
        assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
        assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
        let decoded = decode_result(&manifest);
        assert_eq!(decoded.product_version(), crate::PRODUCT_VERSION);
        assert_eq!(decoded.files().len(), 2);
        for entry in decoded.files() {
            assert_eq!(entry.status(), BatchResultFileStatus::Completed);
            assert_eq!(entry.failure_code(), None);
            assert!(!entry.redacted());
            assert_eq!(
                entry.target_digest(),
                Some(ContentDigest::of(target_bytes()))
            );
        }
    }

    #[test]
    fn machine_stale_source_is_skipped_stale_without_rewrite() {
        let dir = TestDir::new("stale");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        // The file changes after the plan: digest differs from both source
        // and target digests.
        std::fs::write(&a, b"[db]\nport=8080\npassword=hunter3\n").expect("external change");
        let (outcome, _, stderr) = run_machine(&plan, &dir, Injections::default());
        assert_eq!(
            outcome.entries[0].status,
            BatchResultFileStatus::SkippedStale
        );
        assert_eq!(
            outcome.entries[0].failure_code.as_deref(),
            Some("core.source.patch-base-mismatch@1")
        );
        assert_eq!(outcome.entries[1].status, BatchResultFileStatus::Completed);
        assert_eq!(
            std::fs::read(&a).expect("a untouched"),
            b"[db]\nport=8080\npassword=hunter3\n"
        );
        assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("core.source.patch-base-mismatch@1"), "{text}");
    }

    #[test]
    fn machine_tampered_patch_is_failed_original_mismatch() {
        let dir = TestDir::new("tamper");
        let a = write_source(&dir, "a.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, true)]);
        let (outcome, _, stderr) = run_machine(&plan, &dir, Injections::default());
        assert_eq!(outcome.entries[0].status, BatchResultFileStatus::Failed);
        assert_eq!(
            outcome.entries[0].failure_code.as_deref(),
            Some("core.source.patch-original-mismatch@1")
        );
        assert_eq!(std::fs::read(&a).expect("a untouched"), source_bytes());
        let text = String::from_utf8_lossy(&stderr);
        assert!(
            text.contains("core.source.patch-original-mismatch@1"),
            "{text}"
        );
    }

    #[test]
    fn machine_write_failure_marks_failed_and_continues_the_batch() {
        let dir = TestDir::new("write-failure");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        let injections = Injections {
            interrupt_after: None,
            write_failure: Some(("cli.write.io@1".to_owned(), "injected disk full".to_owned())),
            write_failure_fired: Cell::new(false),
        };
        let (outcome, _, stderr) = run_machine(&plan, &dir, injections);
        assert_eq!(outcome.entries[0].status, BatchResultFileStatus::Failed);
        assert_eq!(
            outcome.entries[0].failure_code.as_deref(),
            Some("cli.write.io@1")
        );
        assert_eq!(outcome.entries[1].status, BatchResultFileStatus::Completed);
        // The failed file is untouched; the batch never aborts mid-way.
        assert_eq!(std::fs::read(&a).expect("a untouched"), source_bytes());
        assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("cli.write.io@1"), "{text}");
    }

    #[test]
    fn write_failure_facts_maps_read_back_mismatch_by_typed_variant_not_text() {
        // RFC 0015 §9.3 step 5: a read-back digest mismatch maps to
        // `core.source.patch-target-mismatch@1` with the `cli.write.io@1`
        // environment diagnostic named on the stderr line. The mapping
        // matches the typed `WriteError::ReadBackMismatch` variant, so a
        // wording change of the diagnostic text must not revert the mapping
        // to plain `cli.write.io@1` (round-2 audit finding F5).
        let mismatch = crate::fsio::WriteError::ReadBackMismatch {
            target: PathBuf::from("app.conf"),
            source: crate::fsio::IoFailure {
                kind: std::io::ErrorKind::InvalidData,
                message: "read-back digest mismatch after atomic replace of 'app.conf' \
                          (the file has been replaced and is not rolled back)"
                    .to_owned(),
            },
        };
        let (code, message) = write_failure_facts(&mismatch);
        assert_eq!(code, "core.source.patch-target-mismatch@1");
        assert!(message.contains("cli.write.io@1"), "{message}");
        // A reworded diagnostic text keeps the mapping.
        let reworded = crate::fsio::WriteError::ReadBackMismatch {
            target: PathBuf::from("app.conf"),
            source: crate::fsio::IoFailure {
                kind: std::io::ErrorKind::InvalidData,
                message: "the post-replace read-back verification failed".to_owned(),
            },
        };
        let (code, _) = write_failure_facts(&reworded);
        assert_eq!(code, "core.source.patch-target-mismatch@1");
        // Every other failure keeps its frozen `cli.write.*` code.
        let io = crate::fsio::WriteError::Io {
            target: PathBuf::from("app.conf"),
            source: crate::fsio::IoFailure {
                kind: std::io::ErrorKind::StorageFull,
                message: "disk full".to_owned(),
            },
        };
        let (code, _) = write_failure_facts(&io);
        assert_eq!(code, "cli.write.io@1");
    }

    #[test]
    fn machine_interruption_persists_pending_before_write_and_resume_completes() {
        let dir = TestDir::new("interrupt");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        // Interrupt at file 1's pending mark (before its write): the on-disk
        // manifest must show [completed, pending] — file 0's completed state
        // was persisted after its write, file 1 is pending before its write
        // (RFC 0015 §9.3 ordering, risk point R-5).
        let injections = Injections {
            interrupt_after: Some(1),
            write_failure: None,
            write_failure_fired: Cell::new(false),
        };
        let (outcome, manifest, stderr) = run_machine(&plan, &dir, injections);
        assert!(outcome.interrupted);
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("cli.interrupted.signal@1"), "{text}");
        let decoded = decode_result(&manifest);
        assert_eq!(decoded.files().len(), 2);
        assert_eq!(
            decoded.files()[0].status(),
            BatchResultFileStatus::Completed
        );
        assert_eq!(decoded.files()[1].status(), BatchResultFileStatus::Pending);
        assert_eq!(
            decoded.files()[1].failure_code(),
            None,
            "pending entries carry neither failure_code nor target_digest"
        );
        assert_eq!(decoded.files()[1].target_digest(), None);
        assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
        assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
        // Re-run without injection: file 0 is skipped (disk == target),
        // file 1 is redone (disk == source) — all completed, no pending.
        let (outcome, manifest, stderr) = run_machine(&plan, &dir, Injections::default());
        assert!(!outcome.interrupted);
        assert!(stderr.is_empty());
        let decoded = decode_result(&manifest);
        for entry in decoded.files() {
            assert_eq!(entry.status(), BatchResultFileStatus::Completed);
            assert_eq!(
                entry.target_digest(),
                Some(ContentDigest::of(target_bytes()))
            );
        }
        assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
    }

    #[test]
    fn machine_resume_skips_completed_and_only_rewrites_pending() {
        // The skip is proven by the write-failure injection: the re-run's
        // first write is file 1's — if file 0 were rewritten, the injection
        // would have failed file 0 instead.
        let dir = TestDir::new("resume-skip");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        let interrupted = run_machine(
            &plan,
            &dir,
            Injections {
                interrupt_after: Some(1),
                write_failure: None,
                write_failure_fired: Cell::new(false),
            },
        )
        .0;
        assert!(interrupted.interrupted);
        let resumed = run_machine(
            &plan,
            &dir,
            Injections {
                interrupt_after: None,
                write_failure: Some(("cli.write.io@1".to_owned(), "injected disk full".to_owned())),
                write_failure_fired: Cell::new(false),
            },
        );
        assert_eq!(
            resumed.0.entries[0].status,
            BatchResultFileStatus::Completed
        );
        assert_eq!(resumed.0.entries[1].status, BatchResultFileStatus::Failed);
        assert_eq!(
            resumed.0.entries[1].failure_code.as_deref(),
            Some("cli.write.io@1")
        );
        assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
    }

    #[test]
    fn machine_resume_external_modification_is_skipped_stale() {
        // RFC 0015 §9.4 third branch: an external concurrent modification of
        // a pending file makes the re-run skip it as stale.
        let dir = TestDir::new("resume-stale");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let plan = plan_of(vec![planned_entry(&a, false), planned_entry(&b, false)]);
        let interrupted = run_machine(
            &plan,
            &dir,
            Injections {
                interrupt_after: Some(1),
                write_failure: None,
                write_failure_fired: Cell::new(false),
            },
        )
        .0;
        assert!(interrupted.interrupted);
        std::fs::write(&b, b"[db]\nport=8080\npassword=hunter4\n").expect("external change");
        let (outcome, _, _) = run_machine(&plan, &dir, Injections::default());
        assert_eq!(outcome.entries[0].status, BatchResultFileStatus::Completed);
        assert_eq!(
            outcome.entries[1].status,
            BatchResultFileStatus::SkippedStale
        );
        assert_eq!(
            outcome.entries[1].failure_code.as_deref(),
            Some("core.source.patch-base-mismatch@1")
        );
        assert_eq!(
            std::fs::read(&b).expect("b untouched"),
            b"[db]\nport=8080\npassword=hunter4\n"
        );
    }

    #[test]
    // The clippy warning about `set_readonly(false)` targets Unix semantics
    // (world-writable); the call below is cfg(windows)-only and is the only
    // std way to clear the READONLY attribute before the scratch cleanup.
    #[allow(clippy::permissions_set_readonly_false)]
    fn machine_readonly_target_is_failed_read_only() {
        let dir = TestDir::new("readonly");
        let a = write_source(&dir, "a.conf", source_bytes());
        #[cfg(windows)]
        {
            let mut permissions = std::fs::metadata(&a).expect("metadata").permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&a, permissions).expect("mark readonly");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o444))
                .expect("mark readonly mode");
        }
        let plan = plan_of(vec![planned_entry(&a, false)]);
        let (outcome, _, stderr) = run_machine(&plan, &dir, Injections::default());
        assert_eq!(outcome.entries[0].status, BatchResultFileStatus::Failed);
        assert_eq!(
            outcome.entries[0].failure_code.as_deref(),
            Some("cli.write.read-only@1")
        );
        assert_eq!(std::fs::read(&a).expect("a untouched"), source_bytes());
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("cli.write.read-only@1"), "{text}");
        // Clear the read-only attribute so the scratch dir can be removed.
        #[cfg(windows)]
        {
            let mut permissions = std::fs::metadata(&a).expect("metadata").permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(&a, permissions).expect("clear readonly");
        }
    }

    #[test]
    fn machine_plan_failed_entry_is_re_reported_failed() {
        let dir = TestDir::new("plan-failed");
        let a = write_source(&dir, "a.conf", source_bytes());
        let b = write_source(&dir, "b.conf", source_bytes());
        let failed = BatchPlanFileEntry::new(
            &b,
            BatchPlanFileStatus::Failed,
            None,
            None,
            None,
            None,
            Some("core.edit.target-not-found@1".to_owned()),
            Some(vec![crate::query_cmd::diagnostic_for(
                "core.edit.target-not-found@1",
                "target absent",
            )]),
            ErrorCodeRegistry::v7(),
        )
        .expect("valid failed entry");
        let plan = plan_of(vec![planned_entry(&a, false), failed]);
        let (outcome, _, stderr) = run_machine(&plan, &dir, Injections::default());
        assert_eq!(outcome.entries[0].status, BatchResultFileStatus::Completed);
        assert_eq!(outcome.entries[1].status, BatchResultFileStatus::Failed);
        assert_eq!(
            outcome.entries[1].failure_code.as_deref(),
            Some("core.edit.target-not-found@1")
        );
        assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
        assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("core.edit.target-not-found@1"), "{text}");
    }

    #[test]
    fn entry_redacted_flag_follows_the_policy_on_summary_key_names() {
        let policy = RedactPolicy::conservative();
        let plain = planned_entry("x.conf", false);
        // The frozen default policy matches nothing in the content-free
        // summary keys of the wired INI vocabulary.
        assert!(!entry_redacted(&plain, &policy));
        // An explicit glob matching a summary key flips the fact.
        let matching = RedactPolicy::conservative()
            .with_extra_patterns(&["value*"])
            .expect("valid glob");
        assert!(entry_redacted(&plain, &matching));
        // --show-secrets is the sole opt-out and disables matching entirely.
        assert!(!entry_redacted(&plain, &RedactPolicy::show_secrets()));
        // A failed plan entry has no operations: never redacted.
        let failed = BatchPlanFileEntry::new(
            "y.conf",
            BatchPlanFileStatus::Failed,
            None,
            None,
            None,
            None,
            Some("core.edit.target-not-found@1".to_owned()),
            Some(vec![crate::query_cmd::diagnostic_for(
                "core.edit.target-not-found@1",
                "target absent",
            )]),
            ErrorCodeRegistry::v7(),
        )
        .expect("valid failed entry");
        assert!(!entry_redacted(&failed, &matching));
    }
}
