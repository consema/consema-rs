//! Process-level skeleton tests for the `consema` binary (milestone M3).
//!
//! Launches the built binary via `env!("CARGO_BIN_EXE_consema")` (cargo
//! built-in; zero dev-dependencies, implementation plan §8.3) and asserts
//! the frozen contract: exit codes follow the RFC 0015 §5 classification
//! table and stay within the closed set 0-5 (§5.3), usage failures emit no
//! stdout bytes (§4.2), success paths keep stderr clean (§3.3), and the
//! `conformance --json` envelope round-trips byte-exactly through the
//! protocol decoder.

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

#[test]
fn help_exits_zero_and_prints_the_full_command_surface_on_stdout() {
    let output = run(&["--help"]);
    assert_eq!(status(&output), 0);
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    for command in [
        "inspect",
        "capabilities",
        "query",
        "project",
        "materialize",
        "convert",
        "edit",
        "plan",
        "apply",
        "conformance",
        "explain",
    ] {
        assert!(text.contains(command), "--help must list {command}");
    }
    assert!(text.contains("Exit codes"));
}

#[test]
fn version_exits_zero_and_is_not_a_command() {
    let output = run(&["--version"]);
    assert_eq!(status(&output), 0);
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    // "version" is outside the RFC 0015 §6.1 closed command set.
    let output = run(&["version"]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("unknown command 'version'"));
}

#[test]
fn unknown_command_and_abbreviation_guessing_are_usage_exit_one() {
    for args in [
        &["frobnicate"][..],
        &["ins"][..],
        &["conform"][..],
        &["detect"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} emits no stdout bytes");
        assert!(!output.stderr.is_empty(), "{args:?} diagnoses on stderr");
    }
}

#[test]
fn unknown_arguments_are_rejected() {
    for args in [
        &["--bogus"][..],
        &["conformance", "--bogus"][..],
        &["inspect", "app.conf", "--bogus"][..],
        &["-x"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} emits no stdout bytes");
    }
}

#[test]
fn missing_command_is_usage_exit_one() {
    for args in [&[][..], &["--json"][..], &["--profile", "ini.portable"][..]] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(stderr_text(&output).contains("missing command"), "{args:?}");
    }
}

#[test]
fn parse_class_commands_without_profile_are_usage_exit_one() {
    for args in [
        &["query"][..],
        &["query", "--request-file", "r.json"][..],
        &["project"][..],
        &["materialize"][..],
        &["convert", "src.json"][..],
        &["edit", "app.conf"][..],
        &["plan", "app.conf"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(
            stderr_text(&output).contains("--profile"),
            "{args:?}: missing --profile must be diagnosed"
        );
    }
}

#[test]
fn no_recognized_command_remains_unimplemented() {
    // Milestones M4/M5 implemented inspect/capabilities/explain and
    // query/project/materialize/convert; milestone M7 implemented edit/plan;
    // milestone M8 wired apply — the placeholder behavior is retired for the
    // whole surface. The dispatch proof: apply with a missing plan manifest
    // is a data-class failure (exit 2, cli.data.io@1), never the old
    // "not yet implemented" usage error.
    let output = run(&["apply", "missing-plan.json", "--json"]);
    assert_eq!(
        status(&output),
        2,
        "apply is wired and reaches the manifest input"
    );
    assert!(
        !output.stdout.is_empty(),
        "data-class failures carry the envelope"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("cli.data.io@1"), "{stderr}");
    assert!(!stderr.contains("not yet implemented"), "{stderr}");
}

#[test]
fn conformance_exits_zero_with_a_human_report_on_stdout() {
    let output = run(&["conformance"]);
    assert_eq!(status(&output), 0);
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("consema.cli.conformance@1"));
    assert!(text.contains("[PASS] cli.envelope@1"));
    assert!(text.contains("[PASS] cli.exit-code@1"));
    assert!(text.contains("[PASS] cli.redaction@1"));
    assert!(text.contains("3 passed, 0 failed"));
}

#[test]
fn conformance_json_emits_a_byte_valid_envelope_that_decodes_back() {
    let output = run(&["conformance", "--json"]);
    assert_eq!(status(&output), 0);
    assert!(output.stderr.is_empty(), "no diagnostics on success");
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
    assert_eq!(envelope.command(), CliCommand::Conformance);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    assert_eq!(envelope.product_version(), env!("CARGO_PKG_VERSION"));
    let payload_entries = envelope.payload().as_object().expect("payload object");
    assert_eq!(payload_entries[0].key(), "schema");
    assert_eq!(
        payload_entries[0].value().as_string(),
        Some("cli.conformance@1"),
        "payload schema matches the command (RFC 0015 §4.3)"
    );
    assert!(!envelope.redaction().redacted());
    assert_eq!(envelope.redaction().count(), 0);
    // The loop closes byte-exactly: SDK-side re-encoding reproduces stdout.
    assert_eq!(
        envelope.to_json(limits).expect("re-encode"),
        envelope_bytes,
        "machine output is byte-deterministic (RFC 0015 §3.3)"
    );
}

/// Removes whitespace outside string literals (test-only inverse of the
/// binary's deterministic indenter).
fn collapse_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_string = false;
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'"' => {
                in_string = !in_string;
                out.push(b'"');
                index += 1;
            }
            b'\\' if in_string => {
                out.push(input[index]);
                out.push(input[index + 1]);
                index += 2;
            }
            b' ' | b'\n' | b'\r' | b'\t' if !in_string => index += 1,
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

#[test]
fn conformance_pretty_json_indents_without_changing_semantics() {
    let compact = run(&["conformance", "--json"]);
    let pretty = run(&["conformance", "--json", "--pretty"]);
    assert_eq!(status(&compact), 0);
    assert_eq!(status(&pretty), 0);
    assert!(compact.stderr.is_empty());
    assert!(pretty.stderr.is_empty());
    assert_ne!(compact.stdout, pretty.stdout);
    assert!(pretty.stdout.contains(&b'\n'));
    assert_eq!(
        collapse_whitespace(&pretty.stdout),
        &compact.stdout[..compact.stdout.len() - 1],
        "pretty output is the compact envelope with whitespace inserted"
    );
}

#[test]
fn pretty_without_json_is_usage_exit_one() {
    let output = run(&["conformance", "--pretty"]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("requires '--json'"));
}

#[test]
fn stdout_carries_only_result_data_and_stderr_only_diagnostics() {
    for args in [
        &["frobnicate"][..],
        &["--bogus"][..],
        &["ins"][..],
        &[][..],
        &["inspect"][..],
        &["conformance", "--pretty"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 1, "{args:?}");
        assert!(
            output.stdout.is_empty(),
            "usage failures emit no stdout for {args:?}"
        );
        assert!(
            !output.stderr.is_empty(),
            "usage diagnostics go to stderr for {args:?}"
        );
    }
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["conformance"][..],
        &["conformance", "--json"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 0, "{args:?}");
        assert!(
            !output.stdout.is_empty(),
            "result data goes to stdout for {args:?}"
        );
        assert!(
            output.stderr.is_empty(),
            "no diagnostics on success for {args:?}"
        );
    }
}

#[test]
fn observed_exit_codes_stay_within_the_closed_set() {
    // RFC 0015 §5.3: the classification set is closed at {0..=5}; v1 never
    // emits 6-255.
    let battery: &[&[&str]] = &[
        &[],
        &["--help"],
        &["--version"],
        &["version"],
        &["detect"],
        &["frobnicate"],
        &["--bogus"],
        &["ins"],
        &["-x"],
        &["inspect"],
        &["inspect", "a", "b"],
        &["inspect", "x"],
        &["capabilities"],
        &["capabilities", "x"],
        &["query"],
        &["query", "--profile", "ini.portable"],
        &["project", "--profile", "x"],
        &["materialize", "--profile", "x"],
        &["convert", "x"],
        &["convert", "x", "--profile", "json.strict"],
        &["edit", "x", "--profile", "ini.portable"],
        &["plan", "a", "b", "--profile", "ini.portable"],
        &["apply"],
        &["apply", "plan.json"],
        &["conformance"],
        &["conformance", "--json"],
        &["conformance", "--json", "--pretty"],
        &["conformance", "--pretty"],
        &["explain", "contract"],
    ];
    for args in battery {
        let code = status(&run(args));
        assert!(
            (0..=5).contains(&code),
            "exit code {code} for {args:?} escapes the closed set 0-5"
        );
    }
}
