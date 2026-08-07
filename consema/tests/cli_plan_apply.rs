//! Process-level tests of the milestone-M8 apply command: the full
//! plan→apply→result-manifest round trip, the RFC 0015 §9.3 six-step
//! pre-write revalidation (stale digest, original-bytes precondition), the
//! write-policy failures (read-only, symlink/junction, permission, disk
//! full), the §9.4 interruption-recovery contract (pending manifest before
//! write, completed after write, re-run resume), the per-file `redacted`
//! fact, and the CLI-layer exit-code classification. Launches the built
//! binary via `env!("CARGO_BIN_EXE_consema")` (zero dev-dependencies,
//! implementation plan §8.3) against scratch directories; the
//! `cli.edit-request@1` fixtures under `tests/fixtures/` are only ever read
//! (apply writes its own copies).
//!
//! The interruption and write-failure injection points are the documented
//! env seams of `apply.rs` (`CONSEMA_APPLY_INTERRUPT_AFTER`,
//! `CONSEMA_APPLY_WRITE_FAILURE`); every other failure state uses a real
//! filesystem state (RFC 0015 §10 policy matrix, implementation plan §6 M8).

use consema::core::{ObjectBuilder, PortableValue, SequenceBuilder};
use consema::protocol::{
    BatchPlanMessage, BatchResultFileStatus, BatchResultMessage, CliCommand, CliOutputMessage,
    ExitClass, ProtocolLimits,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_consema"))
        .args(args)
        .output()
        .expect("spawn the built consema binary")
}

fn run_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_consema"));
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("spawn the built consema binary")
}

fn status(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process terminated by a signal")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// One isolated scratch directory, removed on drop.
struct TestDir {
    path: PathBuf,
}

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

impl TestDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "consema-cli-plan-apply-{name}-{}-{}",
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

/// The fixture request file for replacing `port` (m7_edit_request.json).
const EDIT_REQUEST: &str = "m7_edit_request.json";

/// The fixture source: `[db]` with `port=8080` and `password=hunter2`.
fn source_bytes() -> &'static [u8] {
    b"[db]\nport=8080\npassword=hunter2\n"
}

/// The expected target bytes after the fixture edit (`port=9090`).
fn target_bytes() -> &'static [u8] {
    b"[db]\nport=9090\npassword=hunter2\n"
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Copies one fixture into the scratch dir and returns the copy's spelling.
fn copy_fixture(dir: &TestDir, name: &str, dest: &str) -> String {
    let bytes = std::fs::read(fixture(name)).expect("fixture readable");
    let path = dir.join(dest);
    std::fs::write(&path, bytes).expect("copy fixture");
    path.to_string_lossy().into_owned()
}

/// Writes one source file in the scratch dir and returns its spelling.
fn write_source(dir: &TestDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write source");
    path.to_string_lossy().into_owned()
}

/// Runs `consema plan` for the given source paths (the fixture edit request)
/// and returns the plan-manifest path.
fn plan_batch(dir: &TestDir, sources: &[&str]) -> String {
    let plan_path = dir.join("batch.plan.json");
    let plan_spelling = plan_path.to_str().expect("utf8").to_owned();
    let request = fixture(EDIT_REQUEST);
    let mut args = vec!["plan"];
    args.extend(sources.iter().copied());
    args.extend([
        "--request-file",
        &request,
        "--profile",
        "ini.portable",
        "--output",
        &plan_spelling,
    ]);
    let output = run(&args);
    assert_eq!(status(&output), 0, "plan failed: {}", stderr_text(&output));
    plan_spelling
}

/// Decodes the one-line envelope and asserts the byte loop closes.
fn decode_envelope(output: &Output) -> CliOutputMessage {
    assert!(
        output.stdout.ends_with(b"\n"),
        "envelope line ends in one LF"
    );
    assert!(
        !output.stdout[..output.stdout.len() - 1].contains(&b'\n'),
        "stdout is exactly one envelope line"
    );
    let envelope_bytes = &output.stdout[..output.stdout.len() - 1];
    let limits = ProtocolLimits::default();
    let envelope = CliOutputMessage::from_json(envelope_bytes, limits)
        .expect("stdout is a byte-valid core.cli-output@1 envelope");
    assert_eq!(
        envelope.to_json(limits).expect("re-encode"),
        envelope_bytes,
        "machine output is byte-deterministic"
    );
    envelope
}

/// Strictly decodes one result-manifest file.
fn decode_result(bytes: &[u8]) -> BatchResultMessage {
    let limits = ProtocolLimits::default();
    BatchResultMessage::from_value(
        &consema::protocol::decode_json(bytes, limits).expect("strict manifest decode"),
    )
    .expect("byte-valid core.batch-result@1 record")
}

/// The statuses of a result manifest, in plan order.
fn result_statuses(manifest: &BatchResultMessage) -> Vec<BatchResultFileStatus> {
    manifest
        .files()
        .iter()
        .map(consema::protocol::BatchResultFileEntry::status)
        .collect()
}

/// Asserts the directory holds no leftover `*.consema-*.tmp` residue.
fn assert_no_temp_residue(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.contains(".consema-") || !name.ends_with(".tmp"),
            "temp residue left behind: {name}"
        );
    }
}

/// Flips one byte of the first replacement's `original` in a plan manifest
/// (same lengths — the strict decoder still accepts the record; only the
/// RFC 0015 §9.3 step-2 original-bytes precondition detects it).
fn tamper_first_original(plan_bytes: &[u8]) -> Vec<u8> {
    let limits = ProtocolLimits::default();
    let value = consema::protocol::decode_json(plan_bytes, limits).expect("plan decodes");
    let mut rebuilt = ObjectBuilder::new();
    for field in value.as_object().expect("plan object") {
        if field.key() == "files" {
            let mut files = SequenceBuilder::new();
            for file in field.value().as_sequence().expect("files sequence") {
                let mut file_builder = ObjectBuilder::new();
                for file_field in file.as_object().expect("file object") {
                    if file_field.key() == "source_patch" {
                        file_builder
                            .insert("source_patch", tamper_patch(file_field.value()))
                            .expect("unique");
                    } else {
                        file_builder
                            .insert(file_field.key(), file_field.value().clone())
                            .expect("unique");
                    }
                }
                files.push(file_builder.build());
            }
            rebuilt.insert("files", files.build()).expect("unique");
        } else {
            rebuilt
                .insert(field.key(), field.value().clone())
                .expect("unique");
        }
    }
    consema::protocol::encode_json(&rebuilt.build(), limits).expect("canonical re-encode")
}

fn tamper_patch(patch: &PortableValue) -> PortableValue {
    let mut rebuilt = ObjectBuilder::new();
    for field in patch.as_object().expect("patch object") {
        if field.key() == "replacements" {
            let mut replacements = SequenceBuilder::new();
            for (index, replacement) in field
                .value()
                .as_sequence()
                .expect("replacements sequence")
                .iter()
                .enumerate()
            {
                let mut item = ObjectBuilder::new();
                for rfield in replacement.as_object().expect("replacement object") {
                    if index == 0 && rfield.key() == "original" {
                        let mut bytes = rfield.value().as_bytes().expect("bytes").to_vec();
                        bytes[0] ^= 0xFF;
                        item.insert("original", PortableValue::bytes(bytes))
                            .expect("unique");
                    } else {
                        item.insert(rfield.key(), rfield.value().clone())
                            .expect("unique");
                    }
                }
                replacements.push(item.build());
            }
            rebuilt
                .insert("replacements", replacements.build())
                .expect("unique");
        } else {
            rebuilt
                .insert(field.key(), field.value().clone())
                .expect("unique");
        }
    }
    rebuilt.build()
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[test]
fn apply_full_round_trip_writes_targets_and_result_manifest() {
    let dir = TestDir::new("happy");
    let a = copy_fixture(&dir, "m7_src.conf", "a.conf");
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    // Default result path: {plan-file}.result.json (RFC 0015 §8.3).
    let result_path = format!("{plan_path}.result.json");
    let output = run(&["apply", &plan_path]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty(), "no diagnostics on success");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("consema apply: 1 file(s)"), "{text}");
    assert!(text.contains("completed (target sha256:"), "{text}");
    // The target file carries exactly the plan's rendered bytes.
    assert_eq!(std::fs::read(&a).expect("target written"), target_bytes());
    assert_no_temp_residue(&dir.path);
    // The result manifest is the byte-valid core.batch-result@1 record: one
    // completed entry with the verified target digest, no failure code, and
    // no pending anywhere.
    let manifest = decode_result(&std::fs::read(&result_path).expect("result manifest exists"));
    assert_eq!(manifest.product_version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest.files().len(), 1);
    assert_eq!(manifest.files()[0].path(), a);
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(manifest.files()[0].failure_code(), None);
    assert_eq!(
        manifest.files()[0].target_digest(),
        Some(consema::document::ContentDigest::of(target_bytes())),
        "the completed entry's target digest is the verified read-back digest"
    );
    assert!(!manifest.files()[0].redacted());
}

#[test]
fn apply_json_envelope_payload_is_byte_identical_to_the_result_file() {
    let dir = TestDir::new("json");
    let a = copy_fixture(&dir, "m7_src.conf", "a.conf");
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let result_path = dir.join("result.json");
    let result_spelling = result_path.to_str().expect("utf8").to_owned();
    let output = run(&["apply", &plan_path, "--json", "--output", &result_spelling]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Apply);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    // RFC 0015 §8.3: the --output file carries the same record bytes as the
    // envelope payload, without envelope wrapping.
    let limits = ProtocolLimits::default();
    let payload_bytes = consema::protocol::encode_json(envelope.payload(), limits)
        .expect("canonical payload bytes");
    let file_bytes = std::fs::read(&result_path).expect("result manifest written");
    assert_eq!(
        file_bytes, payload_bytes,
        "the result file is byte-identical to the envelope payload"
    );
    let manifest = decode_result(&file_bytes);
    assert_eq!(manifest.files().len(), 1);
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(
        decode_result(&payload_bytes),
        manifest,
        "the file and the envelope carry the same manifest"
    );
}

#[test]
fn apply_multi_file_batch_completes_in_plan_order() {
    let dir = TestDir::new("multi");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let c = write_source(&dir, "c.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str(), c.as_str()]);
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    let statuses = result_statuses(&manifest);
    assert_eq!(
        statuses,
        vec![
            BatchResultFileStatus::Completed,
            BatchResultFileStatus::Completed,
            BatchResultFileStatus::Completed
        ]
    );
    assert_eq!(manifest.files()[0].path(), a);
    assert_eq!(manifest.files()[1].path(), b);
    assert_eq!(manifest.files()[2].path(), c);
    for path in [&a, &b, &c] {
        assert_eq!(std::fs::read(path).expect("target written"), target_bytes());
    }
    assert_no_temp_residue(&dir.path);
}

// ---------------------------------------------------------------------
// Pre-write revalidation (RFC 0015 §9.3 steps 1-2)
// ---------------------------------------------------------------------

#[test]
fn apply_stale_source_is_skipped_stale_exit_four() {
    // Step 1: the file changed after the plan — digest differs from both
    // source and target digests → skipped-stale (core.source.patch-base-
    // mismatch@1), no write at all; the untouched file of the same batch
    // still completes (cross-file non-interference).
    let dir = TestDir::new("stale");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let touched = b"[db]\nport=8080\npassword=hunter2\n# touched after plan\n";
    std::fs::write(&a, touched).expect("external modification");
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("core.source.patch-base-mismatch@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::SkippedStale
    );
    assert_eq!(
        manifest.files()[0].failure_code(),
        Some("core.source.patch-base-mismatch@1")
    );
    assert_eq!(manifest.files()[0].target_digest(), None);
    assert_eq!(
        manifest.files()[1].status(),
        BatchResultFileStatus::Completed
    );
    // The stale file keeps the externally modified bytes; nothing was written.
    assert_eq!(std::fs::read(&a).expect("stale file untouched"), touched);
    assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
}

#[test]
fn apply_tampered_patch_original_bytes_is_failed_original_mismatch() {
    // Step 2: the plan manifest's patch original bytes no longer match the
    // current (base-digest-equal) bytes — a tampered manifest — is caught by
    // the SDK's original-bytes precondition verification
    // (core.source.patch-original-mismatch@1), never by a silent write.
    let dir = TestDir::new("tamper");
    let a = copy_fixture(&dir, "m7_src.conf", "a.conf");
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let plan_bytes = std::fs::read(&plan_path).expect("plan file");
    let tampered = tamper_first_original(&plan_bytes);
    assert_ne!(tampered, plan_bytes, "the tampered bytes differ");
    std::fs::write(&plan_path, &tampered).expect("write tampered plan");
    // The tampered plan still strictly decodes (same lengths, same digests).
    let limits = ProtocolLimits::default();
    BatchPlanMessage::from_value(
        &consema::protocol::decode_json(&tampered, limits).expect("tampered plan decodes"),
    )
    .expect("tampered plan is a byte-valid record");
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("core.source.patch-original-mismatch@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files()[0].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[0].failure_code(),
        Some("core.source.patch-original-mismatch@1")
    );
    assert_eq!(std::fs::read(&a).expect("target untouched"), source_bytes());
}

// ---------------------------------------------------------------------
// Write-policy failures (RFC 0015 §10)
// ---------------------------------------------------------------------

#[test]
// The clippy warning about `set_readonly(false)` targets Unix semantics
// (world-writable); the call below is cfg(windows)-only and is the only
// std way to clear the READONLY attribute before the scratch cleanup.
#[allow(clippy::permissions_set_readonly_false)]
fn apply_readonly_target_is_failed_read_only_exit_four() {
    let dir = TestDir::new("readonly");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    #[cfg(windows)]
    {
        let mut permissions = std::fs::metadata(&b).expect("metadata").permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&b, permissions).expect("mark readonly");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o444))
            .expect("mark readonly mode");
    }
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.write.read-only@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(manifest.files()[1].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[1].failure_code(),
        Some("cli.write.read-only@1")
    );
    assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
    assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
    assert_no_temp_residue(&dir.path);
    // Clear the attribute so the scratch dir can be removed.
    #[cfg(windows)]
    {
        let mut permissions = std::fs::metadata(&b).expect("metadata").permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&b, permissions).expect("clear readonly");
    }
}

#[test]
fn apply_directory_target_is_failed_data_io_exit_four() {
    // A target that is a directory cannot even be read (the digest
    // precondition of §9.3 step 1); on both platforms the read step fails
    // with cli.data.io@1 and the entry is failed — exit 4, nothing written.
    let dir = TestDir::new("dir-target");
    let a = write_source(&dir, "a.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let a_path = Path::new(&a);
    std::fs::remove_file(&a).expect("remove planned file");
    std::fs::create_dir(a_path).expect("replace with a directory");
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.data.io@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files()[0].status(), BatchResultFileStatus::Failed);
    assert_eq!(manifest.files()[0].failure_code(), Some("cli.data.io@1"));
}

#[test]
fn apply_symlink_or_junction_target_is_failed_symlink_policy() {
    // RFC 0015 §10 symlink policy: a write path through a symlink/junction
    // component is refused (cli.write.symlink-policy@1); the real file is
    // never touched. On Windows a directory junction (mklink /J, no admin
    // rights) stands in for the symlink; std reports it as a symlink.
    let dir = TestDir::new("symlink");
    let real = dir.join("real");
    std::fs::create_dir(&real).expect("real dir");
    let real_path = real.join("app.conf");
    std::fs::write(&real_path, source_bytes()).expect("seed real file");
    let junction = dir.join("link");
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction.to_str().expect("utf8"),
                real.to_str().expect("utf8"),
            ])
            .output()
            .expect("run mklink");
        if !output.status.success() {
            eprintln!(
                "skipping junction probe: mklink unavailable ({})",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return;
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, &junction).expect("create directory symlink");
    }
    // Plan through the link: reading resolves the real file.
    let through = junction.join("app.conf").to_string_lossy().into_owned();
    let plan_path = plan_batch(&dir, &[through.as_str()]);
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.write.symlink-policy@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files()[0].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[0].failure_code(),
        Some("cli.write.symlink-policy@1")
    );
    assert_eq!(
        std::fs::read(&real_path).expect("real file untouched"),
        source_bytes()
    );
    assert_no_temp_residue(&real);
    // Remove the link before the scratch dir is dropped.
    let _ = std::fs::remove_dir_all(&junction);
}

#[test]
fn apply_permission_failure_injection_is_failed_permission_exit_four() {
    // Permission denial cannot be produced deterministically on Windows with
    // std-only filesystem states; the documented injection seam
    // (CONSEMA_APPLY_WRITE_FAILURE=permission) fails the first atomic target
    // write with cli.write.permission@1. The batch never aborts: the second
    // file completes normally.
    let dir = TestDir::new("permission");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let output = run_env(
        &["apply", &plan_path, "--json"],
        &[("CONSEMA_APPLY_WRITE_FAILURE", "permission")],
    );
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.write.permission@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files()[0].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[0].failure_code(),
        Some("cli.write.permission@1")
    );
    assert_eq!(
        manifest.files()[1].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(std::fs::read(&a).expect("a untouched"), source_bytes());
    assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
    assert_no_temp_residue(&dir.path);
}

#[test]
fn apply_disk_full_injection_is_failed_io_exit_four() {
    let dir = TestDir::new("diskfull");
    let a = write_source(&dir, "a.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let output = run_env(
        &["apply", &plan_path, "--json"],
        &[("CONSEMA_APPLY_WRITE_FAILURE", "io")],
    );
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.write.io@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files()[0].status(), BatchResultFileStatus::Failed);
    assert_eq!(manifest.files()[0].failure_code(), Some("cli.write.io@1"));
    assert_eq!(std::fs::read(&a).expect("a untouched"), source_bytes());
    assert_no_temp_residue(&dir.path);
}

// ---------------------------------------------------------------------
// Interruption recovery (RFC 0015 §5.4/§9.4; risk point R-5)
// ---------------------------------------------------------------------

#[test]
fn apply_interruption_leaves_pending_manifest_and_rerun_resumes() {
    // The injection fires at the R-5 critical window: after file 1's pending
    // manifest is persisted (step 3), before its target write (step 4). The
    // on-disk manifest must show [completed, pending] — file 0's completed
    // state was persisted after its write, file 1 stays pending before its
    // write. The process exits 4 with cli.interrupted.signal@1 on stderr and
    // no further stdout bytes (RFC 0015 §4.2: interruption never produces an
    // envelope).
    let dir = TestDir::new("interrupt");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let result_path = format!("{plan_path}.result.json");
    let output = run_env(
        &["apply", &plan_path, "--json"],
        &[("CONSEMA_APPLY_INTERRUPT_AFTER", "1")],
    );
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(
        output.stdout.is_empty(),
        "interruption never emits stdout bytes"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("cli.interrupted.signal@1"), "{stderr}");
    assert!(stderr.contains("pending"), "{stderr}");
    // The pending manifest is on disk, truthfully: file 0 completed (its
    // write finished and was verified), file 1 pending (its write never
    // started).
    let manifest = decode_result(&std::fs::read(&result_path).expect("pending manifest"));
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(manifest.files()[1].status(), BatchResultFileStatus::Pending);
    assert_eq!(manifest.files()[1].failure_code(), None);
    assert_eq!(manifest.files()[1].target_digest(), None);
    assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
    assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
    // Re-run with the same plan: file 0 is recognized as already effective
    // (disk digest == target digest) and skipped; file 1 is untouched
    // (digest == source) and redone. All completed, exit 0, no pending.
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    for entry in manifest.files() {
        assert_eq!(entry.status(), BatchResultFileStatus::Completed);
        assert_eq!(
            entry.target_digest(),
            Some(consema::document::ContentDigest::of(target_bytes()))
        );
    }
    assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
    assert_eq!(std::fs::read(&b).expect("b written"), target_bytes());
    // The on-disk manifest carries the same final record.
    assert_eq!(
        decode_result(&std::fs::read(&result_path).expect("final manifest")),
        manifest
    );
    assert_no_temp_residue(&dir.path);
}

#[test]
fn apply_rerun_skips_completed_files_and_redoes_pending() {
    // The skip is proven by the write-failure injection: the re-run's first
    // atomic write is file 1's — if file 0 were rewritten, the injection
    // would have failed file 0 instead. RFC 0015 §9.4: "completed (digest
    // matches) skipped, failed re-reported, pending redone".
    let dir = TestDir::new("resume-skip");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let interrupted = run_env(
        &["apply", &plan_path],
        &[("CONSEMA_APPLY_INTERRUPT_AFTER", "1")],
    );
    assert_eq!(status(&interrupted), 4, "{}", stderr_text(&interrupted));
    let output = run_env(
        &["apply", &plan_path, "--json"],
        &[("CONSEMA_APPLY_WRITE_FAILURE", "io")],
    );
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed,
        "file 0 was skipped: no write of file 0 happened on the re-run"
    );
    assert_eq!(manifest.files()[1].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[1].failure_code(),
        Some("cli.write.io@1"),
        "the injection hit the first actual write, which is file 1's"
    );
    assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
    assert_eq!(std::fs::read(&b).expect("b untouched"), source_bytes());
}

#[test]
fn apply_rerun_external_modification_is_skipped_stale() {
    // RFC 0015 §9.4 third branch: an external concurrent modification of a
    // pending file between interruption and re-run matches neither digest →
    // skipped-stale (exit 4), never a blind rewrite.
    let dir = TestDir::new("resume-stale");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let interrupted = run_env(
        &["apply", &plan_path],
        &[("CONSEMA_APPLY_INTERRUPT_AFTER", "1")],
    );
    assert_eq!(status(&interrupted), 4, "{}", stderr_text(&interrupted));
    let touched = b"[db]\nport=8080\npassword=hunter2\n# concurrent edit\n";
    std::fs::write(&b, touched).expect("external modification of the pending file");
    let output = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("core.source.patch-base-mismatch@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(
        manifest.files()[1].status(),
        BatchResultFileStatus::SkippedStale
    );
    assert_eq!(
        manifest.files()[1].failure_code(),
        Some("core.source.patch-base-mismatch@1")
    );
    assert_eq!(std::fs::read(&b).expect("b untouched"), touched);
}

// ---------------------------------------------------------------------
// Plan-side failed entries and per-file redaction facts
// ---------------------------------------------------------------------

#[test]
fn apply_plan_failed_entries_are_re_reported_failed() {
    // RFC 0015 §9.4 "failed re-reported": a file that could not be planned
    // has nothing to write — apply re-reports the plan's failure code as a
    // failed result entry; the planned file still completes.
    let dir = TestDir::new("plan-failed");
    let a = copy_fixture(&dir, "m7_src.conf", "a.conf");
    let missing = copy_fixture(&dir, "m7_src_missing.conf", "missing.conf");
    let plan_path = dir.join("mixed.plan.json");
    let plan_spelling = plan_path.to_str().expect("utf8").to_owned();
    let output = run(&[
        "plan",
        &a,
        &missing,
        "--request-file",
        &fixture(EDIT_REQUEST),
        "--profile",
        "ini.portable",
        "--output",
        &plan_spelling,
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let output = run(&["apply", &plan_spelling, "--json"]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("core.edit.target-not-found@1"));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    let manifest = BatchResultMessage::from_value(envelope.payload()).expect("result record");
    assert_eq!(manifest.files().len(), 2);
    assert_eq!(
        manifest.files()[0].status(),
        BatchResultFileStatus::Completed
    );
    assert_eq!(manifest.files()[1].status(), BatchResultFileStatus::Failed);
    assert_eq!(
        manifest.files()[1].failure_code(),
        Some("core.edit.target-not-found@1")
    );
    assert_eq!(std::fs::read(&a).expect("a written"), target_bytes());
}

#[test]
fn apply_redacted_flag_follows_the_redaction_policy() {
    // RFC 0015 §11.3: the per-file `redacted` fact is true when the file's
    // edit operations (the plan manifest's operation summaries) contain a
    // key name matching the presentation policy. The default frozen patterns
    // match nothing in the content-free summaries; an explicit
    // --redact-keys glob matching a summary key flips the fact; --show-secrets
    // (the sole opt-out) disables matching entirely. The manifest bytes
    // themselves are never redacted (RFC 0015 §11.4).
    let dir = TestDir::new("redacted");
    let a = copy_fixture(&dir, "m7_src.conf", "a.conf");
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let plain = run(&["apply", &plan_path, "--json"]);
    assert_eq!(status(&plain), 0, "{}", stderr_text(&plain));
    let manifest =
        BatchResultMessage::from_value(decode_envelope(&plain).payload()).expect("result record");
    assert!(!manifest.files()[0].redacted());
    let matched = run(&["apply", &plan_path, "--json", "--redact-keys", "value*"]);
    assert_eq!(status(&matched), 0, "{}", stderr_text(&matched));
    let manifest =
        BatchResultMessage::from_value(decode_envelope(&matched).payload()).expect("result record");
    assert!(
        manifest.files()[0].redacted(),
        "the 'value_scalars' summary key matches the 'value*' glob"
    );
    let revealed = run(&[
        "apply",
        &plan_path,
        "--json",
        "--show-secrets",
        "--redact-keys",
        "value*",
    ]);
    assert_eq!(status(&revealed), 0, "{}", stderr_text(&revealed));
    let manifest = BatchResultMessage::from_value(decode_envelope(&revealed).payload())
        .expect("result record");
    assert!(
        !manifest.files()[0].redacted(),
        "--show-secrets disables matching"
    );
}

// ---------------------------------------------------------------------
// CLI-layer failure classification (RFC 0015 §5)
// ---------------------------------------------------------------------

#[test]
fn apply_cli_layer_failures_classify_correctly() {
    let dir = TestDir::new("cli-layer");
    let a = write_source(&dir, "a.conf", source_bytes());
    let b = write_source(&dir, "b.conf", source_bytes());

    // Missing plan manifest → data error (cli.data.io@1, exit 2).
    let missing = dir.join("missing.plan.json").to_string_lossy().into_owned();
    let output = run(&["apply", &missing, "--json"]);
    assert_eq!(status(&output), 2, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.data.io@1"));
    assert_eq!(decode_envelope(&output).exit_class(), ExitClass::Data);

    // A plan file that is not a byte-valid core.batch-plan@1 record → data
    // error (cli.data.invalid-request@1, exit 2).
    let garbage = dir.join("garbage.plan.json").to_string_lossy().into_owned();
    std::fs::write(&garbage, b"not-a-plan").expect("garbage plan");
    let output = run(&["apply", &garbage, "--json"]);
    assert_eq!(status(&output), 2, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.data.invalid-request@1"));
    assert_eq!(decode_envelope(&output).exit_class(), ExitClass::Data);

    // A plan manifest over the --max-bytes input cap → limit error
    // (cli.limit.manifest-size@1, exit 3).
    let plan_path = plan_batch(&dir, &[a.as_str()]);
    let output = run(&["apply", &plan_path, "--max-bytes", "4", "--json"]);
    assert_eq!(status(&output), 3, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.limit.manifest-size@1"));
    assert_eq!(decode_envelope(&output).exit_class(), ExitClass::Limit);

    // A plan batch over the --max-files cap → limit error
    // (cli.limit.batch-count@1, exit 3).
    let plan_path = plan_batch(&dir, &[a.as_str(), b.as_str()]);
    let output = run(&["apply", &plan_path, "--max-files", "1", "--json"]);
    assert_eq!(status(&output), 3, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.limit.batch-count@1"));
    assert_eq!(decode_envelope(&output).exit_class(), ExitClass::Limit);

    // A result-manifest --output target that is a directory → precondition
    // error (cli.write.target-is-directory@1, exit 4).
    let out_dir = dir.join("out-dir").to_string_lossy().into_owned();
    std::fs::create_dir(&out_dir).expect("output directory target");
    let output = run(&["apply", &plan_path, "--output", &out_dir]);
    assert_eq!(status(&output), 4, "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("cli.write.target-is-directory@1"));
}

#[test]
fn apply_usage_failures_never_emit_an_envelope() {
    // RFC 0015 §4.2: usage-class failures produce no stdout bytes. The
    // parser rejects missing positionals and foreign flags before apply
    // runs.
    for args in [
        &["apply"][..],
        &["apply", "a.plan.json", "b.plan.json"][..],
        &["apply", "a.plan.json", "--request-file", "r.json"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} emits no stdout bytes");
        assert!(stderr_text(&output).contains("cli.usage."), "{args:?}");
    }
}
