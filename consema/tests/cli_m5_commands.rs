//! Process-level tests of the milestone-M5 request commands
//! (query/project/materialize/convert): the strict request-input contract
//! (RFC 0015 §3.2), the machine envelope, exit-code classification, and
//! stdout/stderr separation. Launches the built binary via
//! `env!("CARGO_BIN_EXE_consema")` (zero dev-dependencies, implementation
//! plan §8.3) against repository fixtures under `tests/fixtures/`.
//!
//! The fixture request files are canonical tagged JSON (the CLI strictly
//! rejects any non-canonical byte form), so they double as request-input
//! positive cases; the negative cases below exercise malformed inputs.

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
fn query_request_file_end_to_end_emits_a_success_envelope() {
    // The M5 gate invocation: `consema query --request-file <fixture> --json`.
    let output = run(&[
        "query",
        "--request-file",
        &fixture("m5_query_request.json"),
        "--profile",
        "json.strict",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty(), "no diagnostics on success");
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Query);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let result = consema::protocol::QueryResultMessage::from_value(envelope.payload())
        .expect("core.query-result@1 record");
    assert_eq!(result.matches().len(), 3, "three sequence elements");
}

#[test]
fn query_human_mode_prints_match_lines_only() {
    let output = run(&[
        "query",
        "--request-file",
        &fixture("m5_query_request.json"),
        "--profile",
        "json.strict",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("match 0: $[0] = 1"), "{text}");
    assert!(text.contains("match 2: $[2] = 3"), "{text}");
}

#[test]
fn query_malformed_request_is_a_data_error_with_envelope() {
    let output = run(&[
        "query",
        "--request-file",
        &fixture("m5_bad_request.json"),
        "--profile",
        "json.strict",
        "--json",
    ]);
    assert_eq!(status(&output), 2);
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert!(
        stderr_text(&output).contains("cli.data.invalid-request@1"),
        "stderr names the request decode failure"
    );
}

#[test]
fn query_unknown_profile_is_usage_without_envelope() {
    let output = run(&[
        "query",
        "--request-file",
        &fixture("m5_query_request.json"),
        "--profile",
        "json.bogus",
        "--json",
    ]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty(), "usage never emits an envelope");
    assert!(stderr_text(&output).contains("unknown profile 'json.bogus'"));
}

#[test]
fn project_usage_rejection_and_missing_request_input() {
    // Missing --profile: args-level usage.
    let output = run(&[
        "project",
        "--request-file",
        &fixture("m5_query_request.json"),
    ]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("--profile"));
}

#[test]
fn materialize_output_flag_is_refused_until_fsio() {
    let output = run(&[
        "materialize",
        "--request-file",
        &fixture("m5_query_request.json"),
        "--profile",
        "json.strict",
        "--output",
        "out.json",
    ]);
    assert_eq!(status(&output), 1, "usage: --output is an M6 feature");
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("--output"));
}

#[test]
fn convert_request_file_is_accepted_for_the_two_stage_request() {
    // The convert request carries the two-stage operation; the source is the
    // positional path (the M3 args freeze). The fixture is an XML source
    // converting to JSON, which the record-consumption gate rejects
    // atomically — a deterministic data error that exercises the full
    // convert wiring end to end.
    let output = run(&[
        "convert",
        &fixture("m5_src.xml"),
        "--profile",
        "xml.1.0-safe",
        "--request-file",
        &fixture("m5_convert_request.json"),
        "--json",
    ]);
    assert_eq!(status(&output), 2, "{}", stderr_text(&output));
    assert!(
        stderr_text(&output).contains("core.conversion.materialization-failed@1"),
        "the atomic conversion failure carries the stable code"
    );
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Convert);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    let payload = envelope.payload();
    let fields = payload.as_object().expect("payload object");
    assert_eq!(fields[0].value().as_string(), Some("cli.convert@1"));
    // Atomic failure form: no report, no target.
    assert_eq!(fields[1].value(), &consema::core::PortableValue::null());
    assert_eq!(fields[2].value(), &consema::core::PortableValue::null());
}
