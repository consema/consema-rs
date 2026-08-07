//! `consema plan`: the read-only multi-file batch planner (RFC 0015 §8;
//! implementation plan §6 M7).
//!
//! Per file, in command-line argument order: read the raw bytes → parse
//! under the `--profile` selection → dry-run the `cli.edit-request@1`
//! operations (the shared edit_cmd pipeline) → aggregate one
//! `core.batch-plan@1` manifest whose file entries are `planned` (with
//! profile, source_digest, operation summaries, and the embedded
//! `core.source-patch@2`) or `failed` (with the stable failure code and
//! diagnostics). **A per-file failure never fails the batch**: the manifest
//! is the complete result and carries the failed entry truthfully, so
//! `plan` exits 0 even when some files failed to plan (RFC 0015 §5.2 —
//! per-file failures are manifest content, never disguised success and
//! never an aborted batch).
//!
//! The plan manifest is an **artifact, not a write authorization**
//! (IMPLEMENTATION.md lines 261-263): `plan` never writes any target file;
//! the manifest record goes to stdout (the `--json` envelope payload line)
//! or, with `--output`, to that path via the fsio atomic engine (RFC 0015
//! §8.3 — the same `core.batch-plan@1` record, without envelope wrapping,
//! byte-identical to the envelope payload).
//!
//! # Presentation and redaction
//!
//! The manifest record itself is **never redacted** (RFC 0015 §8.3: its
//! `original`/`replacement` bytes are apply's precondition facts; hard gate
//! 3). The human view (non-`--json` stdout) renders each file's operations
//! through the shared per-item redaction of edit_cmd (key names and
//! value-bearing arguments matching the frozen patterns render as
//! `$REDACTED$`), and a deterministic redaction notice goes to stderr when
//! any value was replaced (RFC 0015 §4.4).
//!
//! # Resource limits (RFC 0015 §12)
//!
//! The batch file-count cap (`--max-files`, default 1000) is
//! `cli.limit.batch-count@1`; the manifest-size cap travels through the
//! transport limits and is `cli.limit.manifest-size@1`. Both are
//! limit-class failures (exit 3), never truncated disguised success. The
//! per-file read cap (`--max-bytes`, default 64 MiB) makes that file a
//! `failed` entry (`cli.limit.file-size@1`), like any other per-file
//! failure.

use crate::args::ParsedArgs;
use crate::edit_cmd::{
    FilePlanFailure, PlanRenderItem, decode_edit_request, dry_run_plan, plan_render_item,
    prepare_edit, redact_policy, write_plan_report,
};
use crate::manifest;
use crate::query_cmd::{emit_envelope, emit_failure, internal_failure, read_request_bytes};
use consema::protocol::{
    BatchPlanFileEntry, BatchPlanFileStatus, BatchPlanMessage, CliCommand, DiagnosticMessage,
    EditOperationSummaryMessage, ErrorCodeRegistry, ExitClass,
};
use std::io::Write;

/// The frozen batch file-count cap of RFC 0015 §12.
const DEFAULT_MAX_FILES: u64 = 1000;

/// Runs `consema plan` (request from `--request-file` or stdin; files are
/// the positionals).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let policy = match redact_policy(parsed) {
        Ok(policy) => policy,
        Err(error) => return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr),
    };
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, &policy, stdout, stderr)
}

/// Runs `consema plan` against already-read request bytes (testable without
/// stdin or fixture files).
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    policy: &crate::redact::RedactPolicy,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let input = match decode_edit_request(request, parsed) {
        Ok(input) => input,
        Err(error) => return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr),
    };
    let cap = parsed.max_files.unwrap_or(DEFAULT_MAX_FILES);
    if u64::try_from(parsed.positionals.len()).expect("usize fits u64") > cap {
        let error = crate::query_cmd::FlowError::new(
            "cli.limit.batch-count@1",
            format!(
                "batch of {} files exceeds the {cap}-file cap (--max-files)",
                parsed.positionals.len()
            ),
        );
        return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr);
    }
    let mut entries: Vec<BatchPlanFileEntry> = Vec::new();
    let mut render_items: Vec<PlanRenderItem> = Vec::new();
    for path in &parsed.positionals {
        // The shared per-file pipeline: read → parse → complete-gate →
        // typed transaction → dry-run. Any per-file failure becomes a
        // `failed` manifest entry; the batch never aborts (RFC 0015 §8.2).
        let outcome = match prepare_edit(&input, path, parsed)
            .and_then(|prepared| dry_run_plan(&prepared, path))
        {
            Ok(outcome) => outcome,
            Err(failure) => {
                let entry = match failed_entry(path, &failure) {
                    Ok(entry) => entry,
                    Err(error) => {
                        return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr);
                    }
                };
                entries.push(entry);
                render_items.push(failed_render_item(path, &failure));
                let _ = writeln!(
                    stderr,
                    "consema: error: plan: {}: {} (code {})",
                    path, failure.message, failure.code
                );
                continue;
            }
        };
        let entry = match planned_entry(path, &outcome.plan) {
            Ok(entry) => entry,
            Err(error) => {
                return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr);
            }
        };
        render_items.push(plan_render_item(&input, &entry, policy));
        entries.push(entry);
    }
    let manifest = match BatchPlanMessage::new(crate::PRODUCT_VERSION, entries) {
        Ok(manifest) => manifest,
        Err(error) => {
            return internal_failure(
                "plan",
                &format!("batch-plan construction failed: {error}"),
                stderr,
            );
        }
    };
    // Encode once: the same bytes go to the envelope payload and, with
    // --output, to the manifest file (RFC 0015 §8.3: the file carries the
    // same record without envelope wrapping; byte-identical).
    let bytes = match manifest::encode_manifest(&manifest) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr),
    };
    if let Some(path) = &parsed.output {
        if let Err(error) = manifest::persist_manifest(path, &bytes) {
            return emit_failure(CliCommand::Plan, parsed, &error, stdout, stderr);
        }
    }
    let value = match manifest.to_value() {
        Ok(value) => value,
        Err(error) => {
            return internal_failure(
                "plan",
                &format!("batch-plan encoding failed: {error}"),
                stderr,
            );
        }
    };
    if parsed.json {
        match emit_envelope(
            CliCommand::Plan,
            ExitClass::Success,
            value,
            Vec::new(),
            parsed,
            stdout,
        ) {
            Ok(()) => ExitClass::Success.exit_code(),
            Err(message) => internal_failure("plan", &message, stderr),
        }
    } else {
        match write_plan_report(&render_items, stdout) {
            Ok(redacted) => {
                if redacted > 0 {
                    let _ = writeln!(
                        stderr,
                        "consema: plan: redacted {redacted} value(s) in the human view \
                         (--show-secrets reveals)"
                    );
                }
                ExitClass::Success.exit_code()
            }
            Err(message) => internal_failure("plan", &message, stderr),
        }
    }
}

/// Builds the `planned` file entry of one dry-run (RFC 0015 §8.2 presence
/// rules; the decoder revalidates `source_digest == source_patch.base_digest`).
fn planned_entry(
    path: &str,
    plan: &consema::document::EditPlan,
) -> Result<BatchPlanFileEntry, crate::query_cmd::FlowError> {
    let operations = plan
        .operations()
        .iter()
        .map(|operation| EditOperationSummaryMessage {
            operation: operation.operation().clone(),
            summary: operation.arguments().clone(),
        })
        .collect();
    BatchPlanFileEntry::new(
        path,
        BatchPlanFileStatus::Planned,
        Some(plan.profile().clone()),
        Some(plan.base_digest()),
        Some(operations),
        Some(plan.source_patch().clone()),
        None,
        None,
        ErrorCodeRegistry::v7(),
    )
    .map_err(|error| {
        crate::query_cmd::FlowError::new(
            "cli.internal.unclassified@1",
            format!("plan entry construction failed: {error}"),
        )
    })
}

/// Builds the `failed` file entry of one per-file failure (RFC 0015 §8.2:
/// failure_code and diagnostics present, planning facts null; the decoder
/// requires a non-empty diagnostics sequence).
fn failed_entry(
    path: &str,
    failure: &FilePlanFailure,
) -> Result<BatchPlanFileEntry, crate::query_cmd::FlowError> {
    let diagnostics: Vec<DiagnosticMessage> = failure.diagnostics.clone();
    BatchPlanFileEntry::new(
        path,
        BatchPlanFileStatus::Failed,
        None,
        None,
        None,
        None,
        Some(failure.code.clone()),
        Some(diagnostics),
        ErrorCodeRegistry::v7(),
    )
    .map_err(|error| {
        crate::query_cmd::FlowError::new(
            "cli.internal.unclassified@1",
            format!("plan entry construction failed: {error}"),
        )
    })
}

/// The human plan-view item of one failed file.
fn failed_render_item(path: &str, failure: &FilePlanFailure) -> PlanRenderItem {
    PlanRenderItem {
        path: path.to_owned(),
        planned: false,
        operation_lines: Vec::new(),
        base_digest: None,
        target_digest: None,
        replacements: None,
        failure_code: Some(failure.code.clone()),
        redacted: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::{BigInteger, ObjectBuilder, PortableValue, SequenceBuilder};
    use consema::document::ContentDigest;
    use consema::protocol::{BatchPlanMessage, CliOutputMessage, ProtocolLimits, encode_json};
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
                "consema-{name}-{}-{}",
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

    fn parse(args: &[&str]) -> ParsedArgs {
        crate::args::parse_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("valid invocation")
    }

    fn run_request(args: &[&str], request: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let parsed = parse(args);
        let policy = redact_policy(&parsed).unwrap_or_else(|error| panic!("{}", error.message));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, request, &policy, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    fn envelope_of(stdout: &[u8]) -> CliOutputMessage {
        assert!(stdout.ends_with(b"\n"), "envelope line ends in one LF");
        assert!(!stdout[..stdout.len() - 1].contains(&b'\n'));
        CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
            .expect("byte-valid envelope")
    }

    fn request_value() -> PortableValue {
        let mut reference = ObjectBuilder::new();
        reference
            .insert(
                "id",
                PortableValue::string("ini.edit.replace-semantic-value"),
            )
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("entry"))
            .expect("unique");
        target
            .insert("section", PortableValue::string("db"))
            .expect("unique");
        target
            .insert("key", PortableValue::string("port"))
            .expect("unique");
        target
            .insert("occurrence", PortableValue::integer(BigInteger::from(0)))
            .expect("unique");
        let mut arguments = ObjectBuilder::new();
        arguments
            .insert("value", PortableValue::string("9090"))
            .expect("unique");
        arguments
            .insert(
                "representation_policy",
                PortableValue::string("preserve-compatible"),
            )
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", arguments.build())
            .expect("unique");
        let mut items = SequenceBuilder::new();
        items.push(operation.build());
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert(
                "schema",
                PortableValue::string(crate::edit_cmd::EDIT_REQUEST_SCHEMA),
            )
            .expect("unique");
        wrapper.insert("operations", items.build()).expect("unique");
        wrapper.build()
    }

    fn request_json() -> Vec<u8> {
        encode_json(&request_value(), ProtocolLimits::default()).expect("canonical bytes")
    }

    fn write_source(dir: &TestDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        path.to_string_lossy().into_owned()
    }

    fn source_db() -> &'static [u8] {
        // ini.portable rejects spaces around `=` (conservative ASCII
        // exchange subset); entries require a section header.
        b"[db]\nport=8080\npassword=hunter2\n"
    }

    #[test]
    fn plan_mixed_batch_exits_zero_with_planned_and_failed_entries() {
        // RFC 0015 §5.2: a per-file failure never changes plan's exit code —
        // the manifest is the complete result and carries the failed entry.
        let dir = TestDir::new("plan-mixed");
        let good = write_source(&dir, "good.conf", source_db());
        let missing = write_source(&dir, "missing.conf", b"[db]\nhost=db.internal\n");
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &good,
                &missing,
                "--profile",
                "ini.portable",
                "--json",
            ],
            &request_json(),
        );
        assert_eq!(
            code,
            0,
            "plan exits 0 with per-file failed: {}",
            stderr_text(&stderr)
        );
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.command(), CliCommand::Plan);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert!(envelope.diagnostics().is_empty());
        let manifest = BatchPlanMessage::from_value(envelope.payload()).expect("batch-plan record");
        assert_eq!(manifest.product_version(), crate::PRODUCT_VERSION);
        let files = manifest.files();
        assert_eq!(files.len(), 2, "one entry per file, in argument order");
        assert_eq!(files[0].path(), good);
        assert_eq!(files[0].status(), BatchPlanFileStatus::Planned);
        assert_eq!(files[0].profile().expect("profile").id(), "ini.portable");
        assert_eq!(
            files[0].source_digest().expect("digest"),
            ContentDigest::of(source_db())
        );
        // The cross constraint: source_digest == source_patch.base_digest.
        assert_eq!(
            files[0].source_digest(),
            Some(files[0].source_patch().expect("patch").base_digest())
        );
        assert_eq!(files[0].operations().expect("operations").len(), 1);
        assert_eq!(
            files[0].operations().expect("operations")[0].operation.id(),
            "ini.edit.replace-semantic-value"
        );
        assert!(files[0].failure_code().is_none());
        assert!(files[0].diagnostics().is_none());
        // The second file lacks the target key: failed entry, no planning
        // facts, truthful failure code and diagnostics.
        assert_eq!(files[1].path(), missing);
        assert_eq!(files[1].status(), BatchPlanFileStatus::Failed);
        assert_eq!(
            files[1].failure_code(),
            Some("core.edit.target-not-found@1")
        );
        assert!(files[1].profile().is_none());
        assert!(files[1].source_digest().is_none());
        assert!(files[1].source_patch().is_none());
        let diagnostics = files[1].diagnostics().expect("diagnostics");
        assert!(
            !diagnostics.is_empty(),
            "failed entries require diagnostics"
        );
        // The stderr carries the per-file failure line (RFC 0015 §3.3).
        assert!(stderr_text(&stderr).contains("core.edit.target-not-found@1"));
        // The manifest round-trips byte-exactly through its typed decoder.
        let limits = ProtocolLimits::default();
        let manifest_bytes = encode_json(envelope.payload(), limits).expect("re-encode");
        let redecoded = BatchPlanMessage::from_value(
            &consema::protocol::decode_json(&manifest_bytes, limits).expect("decode"),
        )
        .expect("round trip");
        assert_eq!(redecoded, manifest);
    }

    #[test]
    fn plan_invalid_redact_keys_pattern_is_usage_without_envelope() {
        // RFC 0015 §11.2: an invalid --redact-keys pattern is a usage error
        // (cli.usage.redaction-pattern@1, exit 1) — never an envelope.
        let dir = TestDir::new("plan-redact-keys");
        let good = write_source(&dir, "good.conf", source_db());
        let parsed = parse(&[
            "plan",
            &good,
            "--profile",
            "ini.portable",
            "--redact-keys",
            "ke[y]",
        ]);
        let error = redact_policy(&parsed).expect_err("bracket syntax is rejected");
        assert_eq!(error.code, "cli.usage.redaction-pattern@1");
        assert_eq!(error.exit_class(), ExitClass::Usage);
        // The run() path turns it into a stderr-only usage failure.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = crate::query_cmd::emit_failure(
            CliCommand::Plan,
            &parsed,
            &error,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "usage failures never emit an envelope");
        assert!(stderr_text(&stderr).contains("cli.usage.redaction-pattern@1"));
    }

    #[test]
    fn plan_manifest_bytes_match_the_output_file() {
        // RFC 0015 §8.3: with --output the manifest file carries the same
        // core.batch-plan@1 record without envelope wrapping, byte-identical
        // to the envelope payload.
        let dir = TestDir::new("plan-output");
        let good = write_source(&dir, "good.conf", source_db());
        let output = dir.join("batch.plan.json");
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &good,
                "--profile",
                "ini.portable",
                "--json",
                "--output",
                output.to_str().expect("utf8"),
            ],
            &request_json(),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope = envelope_of(&stdout);
        let limits = ProtocolLimits::default();
        let payload_bytes = encode_json(envelope.payload(), limits).expect("payload bytes");
        let file_bytes = std::fs::read(&output).expect("manifest file exists");
        assert_eq!(
            file_bytes, payload_bytes,
            "the --output file carries the same record bytes as the envelope payload"
        );
        let manifest = BatchPlanMessage::from_value(
            &consema::protocol::decode_json(&file_bytes, limits).expect("file decodes"),
        )
        .expect("file is a byte-valid batch-plan record");
        assert_eq!(manifest.files().len(), 1);
        assert_eq!(manifest.files()[0].status(), BatchPlanFileStatus::Planned);
    }

    #[test]
    fn plan_human_view_redacts_matching_key_names() {
        let dir = TestDir::new("plan-human");
        let good = write_source(&dir, "good.conf", source_db());
        // A replace on the password entry: the human view redacts the key
        // name and the new value; the manifest itself is never redacted.
        let mut reference = ObjectBuilder::new();
        reference
            .insert(
                "id",
                PortableValue::string("ini.edit.replace-semantic-value"),
            )
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("entry"))
            .expect("unique");
        target
            .insert("section", PortableValue::string("db"))
            .expect("unique");
        target
            .insert("key", PortableValue::string("password"))
            .expect("unique");
        target
            .insert("occurrence", PortableValue::integer(BigInteger::from(0)))
            .expect("unique");
        let mut arguments = ObjectBuilder::new();
        arguments
            .insert("value", PortableValue::string("hunter3"))
            .expect("unique");
        arguments
            .insert(
                "representation_policy",
                PortableValue::string("preserve-compatible"),
            )
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", arguments.build())
            .expect("unique");
        let mut items = SequenceBuilder::new();
        items.push(operation.build());
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert(
                "schema",
                PortableValue::string(crate::edit_cmd::EDIT_REQUEST_SCHEMA),
            )
            .expect("unique");
        wrapper.insert("operations", items.build()).expect("unique");
        let request = encode_json(&wrapper.build(), ProtocolLimits::default()).expect("bytes");
        let (code, stdout, stderr) =
            run_request(&["plan", &good, "--profile", "ini.portable"], &request);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains(crate::redact::PLACEHOLDER), "{text}");
        assert!(!text.contains("password"), "the key name is hidden: {text}");
        assert!(!text.contains("hunter3"), "the new value is hidden: {text}");
        assert!(
            stderr_text(&stderr).contains("redacted"),
            "the notice names the redaction: {}",
            stderr_text(&stderr)
        );
        // --show-secrets is the sole opt-out.
        let (code, stdout, stderr) = run_request(
            &["plan", &good, "--profile", "ini.portable", "--show-secrets"],
            &request,
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("password"), "{text}");
        assert!(text.contains("hunter3"), "{text}");
        assert!(!text.contains(crate::redact::PLACEHOLDER), "{text}");
    }

    #[test]
    fn plan_read_failures_are_per_file_failed_entries() {
        let dir = TestDir::new("plan-read");
        let good = write_source(&dir, "good.conf", source_db());
        let missing = dir.join("missing.conf").to_string_lossy().into_owned();
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &good,
                &missing,
                "--profile",
                "ini.portable",
                "--json",
            ],
            &request_json(),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope = envelope_of(&stdout);
        let manifest = BatchPlanMessage::from_value(envelope.payload()).expect("record");
        assert_eq!(manifest.files()[0].status(), BatchPlanFileStatus::Planned);
        assert_eq!(manifest.files()[1].status(), BatchPlanFileStatus::Failed);
        assert_eq!(manifest.files()[1].failure_code(), Some("cli.data.io@1"));
        assert!(!manifest.files()[1].diagnostics().expect("diags").is_empty());
        // A file over the per-file read cap is a failed entry with the limit
        // code; the batch still completes with exit 0.
        let (code, stdout, _) = run_request(
            &[
                "plan",
                &good,
                "--profile",
                "ini.portable",
                "--max-bytes",
                "4",
                "--json",
            ],
            &request_json(),
        );
        assert_eq!(code, 0);
        let envelope = envelope_of(&stdout);
        let manifest = BatchPlanMessage::from_value(envelope.payload()).expect("record");
        assert_eq!(manifest.files()[0].status(), BatchPlanFileStatus::Failed);
        assert_eq!(
            manifest.files()[0].failure_code(),
            Some("cli.limit.file-size@1")
        );
    }

    #[test]
    fn plan_batch_count_limit_is_a_limit_error() {
        let dir = TestDir::new("plan-limit");
        let a = write_source(&dir, "a.conf", source_db());
        let b = write_source(&dir, "b.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &a,
                &b,
                "--profile",
                "ini.portable",
                "--max-files",
                "1",
                "--json",
            ],
            &request_json(),
        );
        assert_eq!(code, 3, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("cli.limit.batch-count@1"));
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Limit);
    }

    #[test]
    fn plan_request_decode_failure_is_a_data_error() {
        let dir = TestDir::new("plan-request");
        let good = write_source(&dir, "good.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &["plan", &good, "--profile", "ini.portable", "--json"],
            b"not-a-request",
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Data);
    }

    #[test]
    fn plan_output_write_failures_are_precondition_errors() {
        // An --output target that is a directory is refused by the fsio
        // policy (cli.write.target-is-directory@1, exit 4).
        let dir = TestDir::new("plan-write");
        let good = write_source(&dir, "good.conf", source_db());
        let output_dir = dir.join("out-dir");
        std::fs::create_dir(&output_dir).expect("directory target");
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &good,
                "--profile",
                "ini.portable",
                "--json",
                "--output",
                output_dir.to_str().expect("utf8"),
            ],
            &request_json(),
        );
        assert_eq!(code, 4, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("cli.write.target-is-directory@1"));
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    }

    #[test]
    fn plan_human_view_renders_all_planned_operations() {
        let dir = TestDir::new("plan-human-plain");
        let good = write_source(&dir, "good.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &["plan", &good, "--profile", "ini.portable"],
            &request_json(),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty(), "no notice without redaction hits");
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("consema plan: 1 file(s)"), "{text}");
        assert!(text.contains(&format!("{good}: planned")), "{text}");
        assert!(
            text.contains("ini.edit.replace-semantic-value@1 on entry 'db':'port'"),
            "{text}"
        );
        assert!(text.contains("base sha256:"), "{text}");
        assert!(text.contains("target sha256:"), "{text}");
    }

    #[test]
    fn plan_output_file_round_trips_through_the_typed_decoder() {
        // The manifest byte-round-trip gate: the persisted file decodes to
        // the exact same BatchPlanMessage the CLI emitted.
        let dir = TestDir::new("plan-roundtrip");
        let good = write_source(&dir, "good.conf", source_db());
        let missing = write_source(&dir, "missing.conf", b"[db]\nhost=db.internal\n");
        let output = dir.join("batch.plan.json");
        let (code, stdout, stderr) = run_request(
            &[
                "plan",
                &good,
                &missing,
                "--profile",
                "ini.portable",
                "--json",
                "--output",
                output.to_str().expect("utf8"),
            ],
            &request_json(),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope = envelope_of(&stdout);
        let expected = BatchPlanMessage::from_value(envelope.payload()).expect("envelope record");
        let limits = ProtocolLimits::default();
        let file_bytes = std::fs::read(&output).expect("manifest file");
        let decoded = BatchPlanMessage::from_value(
            &consema::protocol::decode_json(&file_bytes, limits).expect("strict decode"),
        )
        .expect("file decodes");
        assert_eq!(decoded, expected, "manifest byte round-trip");
    }
}
