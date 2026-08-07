//! Process-level tests of the milestone-M7 edit/plan commands: the
//! `cli.edit-request@1` request input (RFC 0015 §3.2), the single-file
//! dry-run payload (`cli.edit@1`), the multi-file batch-plan manifest
//! (`core.batch-plan@1`), the plan exit-0-with-failed-files semantics
//! (RFC 0015 §5.2), and the human-view redaction (RFC 0015 §11). Launches
//! the built binary via `env!("CARGO_BIN_EXE_consema")` (zero
//! dev-dependencies, implementation plan §8.3) against the repository
//! fixtures under `tests/fixtures/`.
//!
//! The fixture request files are canonical tagged JSON (the CLI strictly
//! rejects any non-canonical byte form), so they double as request-input
//! positive cases; the canonical bytes are pinned by the edit_cmd unit test
//! `fixture_request_bytes_are_canonical_and_stable`.

use consema::protocol::{CliCommand, CliOutputMessage, ExitClass, ProtocolLimits};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_consema"))
        .args(args)
        .output()
        .expect("spawn the built consema binary")
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

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Decodes the one-line envelope and asserts the byte loop closes
/// (RFC 0015 §3.3: byte-deterministic machine output).
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

#[test]
fn edit_request_file_end_to_end_is_a_dry_run() {
    // The M7 gate invocation shape: `consema edit <file> --request-file
    // <fixture> --profile ini.portable --json`.
    let output = run(&[
        "edit",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_edit_request.json"),
        "--profile",
        "ini.portable",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty(), "no diagnostics on success");
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Edit);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let payload = envelope.payload();
    let fields = payload.as_object().expect("payload object");
    assert_eq!(fields[0].value().as_string(), Some("cli.edit@1"));
    assert_eq!(fields[3].key(), "committed");
    assert_eq!(fields[3].value().as_boolean(), Some(false), "dry-run only");
    // The embedded plan and change-set records decode through their typed
    // decoders (round-trip gate).
    let plan =
        consema::protocol::EditPlanMessage::from_value(fields[1].value()).expect("edit plan");
    assert_eq!(plan.profile().id(), "ini.portable");
    assert_eq!(plan.replacements().len(), 1);
    let change_set =
        consema::protocol::ChangeSetMessage::from_value(fields[2].value()).expect("change set");
    assert_eq!(change_set.source_edits().len(), 1);
}

#[test]
fn edit_write_flag_is_usage_without_envelope() {
    let output = run(&[
        "edit",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_edit_request.json"),
        "--profile",
        "ini.portable",
        "--write",
        "--json",
    ]);
    assert_eq!(
        status(&output),
        1,
        "usage: --write is a milestone-M8 feature"
    );
    assert!(output.stdout.is_empty(), "usage never emits an envelope");
    assert!(stderr_text(&output).contains("--write"));
}

#[test]
fn plan_request_file_end_to_end_emits_a_batch_plan_envelope() {
    // The M7 gate invocation: `consema plan <file> --request-file <fixture>
    // --json`.
    let output = run(&[
        "plan",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_edit_request.json"),
        "--profile",
        "ini.portable",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Plan);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let manifest =
        consema::protocol::BatchPlanMessage::from_value(envelope.payload()).expect("batch plan");
    assert_eq!(manifest.files().len(), 1);
    let entry = &manifest.files()[0];
    assert_eq!(entry.path(), fixture("m7_src.conf"));
    assert_eq!(
        entry.status(),
        consema::protocol::BatchPlanFileStatus::Planned
    );
    assert_eq!(entry.profile().expect("profile").id(), "ini.portable");
    assert_eq!(
        entry.source_digest(),
        Some(entry.source_patch().expect("patch").base_digest()),
        "source_digest == source_patch.base_digest"
    );
    assert_eq!(
        entry.operations().expect("operations")[0].operation.id(),
        "ini.edit.replace-semantic-value"
    );
}

#[test]
fn plan_mixed_batch_with_fixture_files_exits_zero() {
    // The second fixture lacks the target key: its entry is `failed`, the
    // first stays `planned`, and plan still exits 0 (RFC 0015 §5.2: the
    // manifest is the complete result; per-file failures are its content).
    let output = run(&[
        "plan",
        &fixture("m7_src.conf"),
        &fixture("m7_src_missing.conf"),
        "--request-file",
        &fixture("m7_edit_request.json"),
        "--profile",
        "ini.portable",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    let manifest =
        consema::protocol::BatchPlanMessage::from_value(envelope.payload()).expect("batch plan");
    let files = manifest.files();
    assert_eq!(files.len(), 2, "one entry per file, in argument order");
    assert_eq!(
        files[0].status(),
        consema::protocol::BatchPlanFileStatus::Planned
    );
    assert_eq!(
        files[1].status(),
        consema::protocol::BatchPlanFileStatus::Failed
    );
    assert_eq!(
        files[1].failure_code(),
        Some("core.edit.target-not-found@1")
    );
    assert!(files[1].source_patch().is_none());
    assert!(files[1].profile().is_none());
    assert!(!files[1].diagnostics().expect("diagnostics").is_empty());
    assert!(
        stderr_text(&output).contains("core.edit.target-not-found@1"),
        "the per-file failure line goes to stderr"
    );
}

#[test]
fn plan_human_view_redacts_secret_shaped_key_names() {
    // The redaction fixture replaces the `password` entry: the human view
    // must hide the key name and the new value ($REDACTED$), while
    // --show-secrets (the sole opt-out) reveals them.
    let output = run(&[
        "plan",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_redact_request.json"),
        "--profile",
        "ini.portable",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("$REDACTED$"), "{text}");
    assert!(!text.contains("password"), "the key name is hidden: {text}");
    assert!(!text.contains("hunter3"), "the new value is hidden: {text}");
    assert!(
        stderr_text(&output).contains("redacted"),
        "the redaction notice goes to stderr"
    );
    let revealed = run(&[
        "plan",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_redact_request.json"),
        "--profile",
        "ini.portable",
        "--show-secrets",
    ]);
    assert_eq!(status(&revealed), 0, "{}", stderr_text(&revealed));
    let text = String::from_utf8_lossy(&revealed.stdout);
    assert!(text.contains("password"), "{text}");
    assert!(text.contains("hunter3"), "{text}");
    assert!(!text.contains("$REDACTED$"), "{text}");
}

#[test]
fn plan_output_writes_the_byte_identical_manifest_record() {
    // RFC 0015 §8.3: with --output the manifest file carries the same
    // core.batch-plan@1 record without envelope wrapping, byte-identical to
    // the envelope payload; the file strictly decodes back to the same
    // manifest (the apply input contract).
    let output_path = format!(
        "{}/tests/fixtures/.m7-plan-output-{}.json",
        env!("CARGO_MANIFEST_DIR"),
        std::process::id()
    );
    let output = run(&[
        "plan",
        &fixture("m7_src.conf"),
        "--request-file",
        &fixture("m7_edit_request.json"),
        "--profile",
        "ini.portable",
        "--json",
        "--output",
        &output_path,
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    let limits = ProtocolLimits::default();
    let payload_bytes = consema::protocol::encode_json(envelope.payload(), limits)
        .expect("canonical payload bytes");
    let file_bytes = std::fs::read(&output_path).expect("manifest file written");
    assert_eq!(
        file_bytes, payload_bytes,
        "the --output file is byte-identical to the envelope payload"
    );
    let decoded = consema::protocol::BatchPlanMessage::from_value(
        &consema::protocol::decode_json(&file_bytes, limits).expect("strict file decode"),
    )
    .expect("the file is a byte-valid core.batch-plan@1 record");
    assert_eq!(
        decoded,
        consema::protocol::BatchPlanMessage::from_value(envelope.payload())
            .expect("envelope manifest")
    );
    let _ = std::fs::remove_file(&output_path);
}
