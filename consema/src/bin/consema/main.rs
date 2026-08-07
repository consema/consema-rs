//! The official `consema` CLI binary.
//!
//! Entry point, command dispatch, exit-code wiring, and stdout/stderr
//! separation. The binary is std-only and sits inside the facade crate, so
//! it can reach format semantics only through the facade public API (hard
//! gate 1 of RFC 0015 §2.3; implementation plan §0.3). All 11 formal
//! commands are wired (milestones M3-M8); `consema conformance` lives in
//! `conformance_cmd.rs` (milestone M9): the embedded self-check subset of
//! RFC 0015 §16.4, with the full language-neutral
//! `consema.cli.conformance@1` suite staying repository-level
//! (`cargo test -p consema-conformance`).
//!
//! Exit-code wiring: every error path maps through
//! `protocol::classify_error_code` (RFC 0015 §5); the process exits with
//! the classified code, never a hand-picked number. Under `--json`, stdout
//! carries exactly one line of canonical `core.cli-output@1` envelope and
//! nothing else; all diagnostics and progress go to stderr (RFC 0015 §3.3).

mod apply;
mod args;
mod capabilities;
mod conformance_cmd;
mod convert_cmd;
mod detect;
mod edit_cmd;
mod explain;
// Milestone M6: fsio (atomic-write engine) and redact (presentation
// redaction) are pure infrastructure with unit tests, consumed by the
// edit/plan/apply milestones M7/M8; until then no item of either module is
// reachable, so dead-code is expected and the allow is the standing
// declaration (it stays harmless once the engines are wired).
#[allow(dead_code)]
mod fsio;
mod inspect;
mod manifest;
mod materialize_cmd;
mod output;
mod plan;
mod project_cmd;
mod query_cmd;
#[allow(dead_code)]
mod redact;
mod registry;

use args::ParseError;
use consema::protocol::{CliCommand, ExitClass, classify_error_code};
use std::ffi::OsString;
use std::io::Write;

/// The release product version string (RFC 0015 §3.3: the workspace version,
/// without git hashes or build metadata).
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let exit_code = match collect_args(std::env::args_os().skip(1)) {
        Ok(args) => run_with_io(&args, &mut stdout, &mut stderr),
        Err(error) => {
            let _ = write_usage_error(&error, &mut stderr);
            usage_exit_code(&error)
        }
    };
    std::process::exit(i32::from(exit_code));
}

/// Converts process arguments to UTF-8 strings; a non-UTF-8 argument is a
/// usage-class failure (RFC 0015 §5.1 argument row; the wire path needs
/// UTF-8 spellings, and hardening coverage for non-UTF-8 file names is
/// milestone M9).
fn collect_args<I>(raw: I) -> Result<Vec<String>, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = Vec::new();
    for argument in raw {
        match argument.into_string() {
            Ok(text) => args.push(text),
            Err(_) => return Err(ParseError::NonUtf8Argument),
        }
    }
    Ok(args)
}

/// Runs one parsed invocation against the given writers and returns the
/// frozen process exit code. Both writers are injected for testability.
fn run_with_io(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let parsed = match args::parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = write_usage_error(&error, stderr);
            return usage_exit_code(&error);
        }
    };
    if parsed.help {
        let _ = write_help(stdout);
        return ExitClass::Success.exit_code();
    }
    if parsed.version {
        let _ = writeln!(stdout, "{PRODUCT_VERSION}");
        return ExitClass::Success.exit_code();
    }
    let Some(command) = parsed.command else {
        // parse_args already rejects a missing command unless help/version
        // was requested; keep the path closed defensively.
        let error = ParseError::MissingCommand;
        let _ = write_usage_error(&error, stderr);
        return usage_exit_code(&error);
    };
    match command {
        CliCommand::Capabilities => capabilities::run(&parsed, stdout, stderr),
        CliCommand::Conformance => conformance_cmd::run(&parsed, stdout, stderr),
        CliCommand::Explain => explain::run(&parsed, stdout, stderr),
        CliCommand::Inspect => inspect::run(&parsed, stdout, stderr),
        CliCommand::Query => query_cmd::run(&parsed, stdout, stderr),
        CliCommand::Project => project_cmd::run(&parsed, stdout, stderr),
        CliCommand::Materialize => materialize_cmd::run(&parsed, stdout, stderr),
        CliCommand::Convert => convert_cmd::run(&parsed, stdout, stderr),
        // Milestone M7: edit (single-file dry-run) and plan (multi-file
        // batch-plan manifest) share the cli.edit-request@1 pipeline;
        // milestone M8 wires apply (batch write from a prior plan manifest).
        CliCommand::Edit => edit_cmd::run(&parsed, stdout, stderr),
        CliCommand::Plan => plan::run(&parsed, stdout, stderr),
        CliCommand::Apply => apply::run(&parsed, stdout, stderr),
    }
}

/// Frozen exit code for one usage-class parse failure (RFC 0015 §5.2:
/// `cli.usage.*` -> 1).
fn usage_exit_code(error: &ParseError) -> u8 {
    classify_error_code(error.code()).exit_code()
}

/// One deterministic stderr diagnostic line for a usage failure.
fn write_usage_error(error: &ParseError, stderr: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        stderr,
        "consema: error: {} (code {})",
        error.message(),
        error.code()
    )
}

/// Writes the version line plus the static usage text (RFC §4.2: requested
/// help is the command result, not a diagnostic).
fn write_help(stdout: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        stdout,
        "consema {PRODUCT_VERSION} — deterministic multi-format configuration tool"
    )?;
    stdout.write_all(args::HELP.as_bytes())
}

/// One OsString that is not valid UTF-8, shared by the bin unit tests of
/// `args.rs` and `main.rs` (Windows: a lone surrogate; Unix: a 0xFF byte).
#[cfg(test)]
fn make_non_utf8_argument() -> OsString {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xD800])
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![0xFF])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::protocol::ExitClass;

    fn run(args: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_io(&owned, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    #[test]
    fn help_and_version_exit_zero_on_stdout() {
        let (code, stdout, stderr) = run(&["--help"]);
        assert_eq!(code, 0);
        assert!(stdout.starts_with(format!("consema {PRODUCT_VERSION} ").as_bytes()));
        assert!(String::from_utf8_lossy(&stdout).contains("Commands (RFC 0015 §6.1)"));
        assert!(stderr.is_empty());
        let (code, stdout, stderr) = run(&["--version"]);
        assert_eq!(code, 0);
        assert_eq!(stdout, format!("{PRODUCT_VERSION}\n").as_bytes());
        assert!(stderr.is_empty());
    }

    #[test]
    fn unknown_command_and_unknown_arguments_exit_usage_with_no_stdout() {
        for args in [&["frobnicate"][..], &["--bogus"][..], &["ins"][..], &[][..]] {
            let (code, stdout, stderr) = run(args);
            assert_eq!(code, 1, "{args:?}");
            assert!(stdout.is_empty(), "{args:?} must not emit stdout bytes");
            assert!(stderr_text(&stderr).contains("consema: error:"), "{args:?}");
        }
    }

    #[test]
    fn apply_is_wired_and_a_missing_plan_is_a_data_error() {
        // Milestone M8 wired apply into the dispatch table; no recognized
        // command remains unimplemented (implementation plan §6 M3 rule
        // retired). A missing plan manifest is a data-class failure (exit 2,
        // cli.data.io@1) carrying the envelope under --json.
        let (code, stdout, stderr) = run(&["apply", "missing-plan.json", "--json"]);
        assert_eq!(code, 2, "missing plan manifest is a data-class failure");
        assert!(!stdout.is_empty(), "data-class failures carry the envelope");
        let text = stderr_text(&stderr);
        assert!(text.contains("cli.data.io@1"), "{text}");
        assert!(text.contains("missing-plan.json"), "{text}");
    }

    #[test]
    fn malformed_arguments_map_to_usage_exit_one() {
        for args in [
            &["query", "--request-file", "r.json"][..],
            &["convert", "x.json"][..],
            &["conformance", "--pretty"][..],
            &["conformance", "--output"][..],
            &["inspect"][..],
            &["inspect", "a", "b"][..],
        ] {
            let (code, _, stderr) = run(args);
            assert_eq!(code, 1, "{args:?}");
            assert!(
                stderr_text(&stderr).contains("(code cli.usage."),
                "{args:?}"
            );
        }
    }

    #[test]
    fn conformance_succeeds_with_a_human_report_on_stdout() {
        let (code, stdout, stderr) = run(&["conformance"]);
        assert_eq!(code, 0);
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains(conformance_cmd::CONFORMANCE_SUITE));
        assert!(text.contains("[PASS] cli.envelope@1"));
        assert!(text.contains("[PASS] cli.exit-code@1"));
        assert!(text.contains("[PASS] cli.redaction@1"));
        assert!(text.contains("3 passed, 0 failed"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn conformance_json_emits_a_byte_valid_envelope_loop() {
        let (code, stdout, stderr) = run(&["conformance", "--json"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        assert!(
            !stdout[..stdout.len() - 1].contains(&b'\n'),
            "exactly one line"
        );
        let envelope_bytes = &stdout[..stdout.len() - 1];
        let limits = consema::protocol::ProtocolLimits::default();
        let envelope = consema::protocol::CliOutputMessage::from_json(envelope_bytes, limits)
            .expect("byte-valid core.cli-output@1 envelope");
        assert_eq!(envelope.command(), CliCommand::Conformance);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(envelope.product_version(), PRODUCT_VERSION);
        let payload = envelope.payload();
        let entries = payload.as_object().expect("payload object");
        assert_eq!(entries[0].key(), "schema");
        assert_eq!(entries[0].value().as_string(), Some("cli.conformance@1"));
        assert!(!envelope.redaction().redacted());
        assert_eq!(envelope.redaction().count(), 0);
        // The byte loop closes: re-encoding reproduces the exact stdout bytes.
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            envelope_bytes,
            "stdout envelope bytes must be byte-deterministic"
        );
    }

    #[test]
    fn conformance_failure_is_reported_as_internal_exit_five() {
        fn broken_check() -> Result<&'static str, (&'static str, String)> {
            Err(("cli.envelope@1", "injected failure".to_owned()))
        }
        let parsed = args::parse_args(&["conformance", "--json"].map(String::from)).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = conformance_cmd::run_conformance_with_checks(
            &parsed,
            &[broken_check],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 5);
        assert!(stderr_text(&stderr).contains("self-check failed: cli.envelope@1"));
        let limits = consema::protocol::ProtocolLimits::default();
        let envelope =
            consema::protocol::CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits)
                .expect("failure envelope stays byte-valid");
        assert_eq!(envelope.exit_class(), ExitClass::Internal);
        assert_eq!(envelope.diagnostics().len(), 1);
        assert_eq!(
            envelope.diagnostics()[0].code,
            "cli.internal.unclassified@1"
        );
    }

    #[test]
    fn every_exit_class_maps_through_the_bin_wiring() {
        // The bin's own exit wiring uses classify_error_code everywhere; the
        // closed 0-5 table must hold for every reachable path.
        let codes = [
            classify_error_code("cli.usage.unknown-command@1").exit_code(),
            classify_error_code("cli.usage.missing-required@1").exit_code(),
            classify_error_code("cli.usage.unknown-argument@1").exit_code(),
            classify_error_code("cli.usage.invalid-argument@1").exit_code(),
            classify_error_code("cli.usage.invalid-format@1").exit_code(),
            classify_error_code("cli.data.io@1").exit_code(),
            classify_error_code("cli.limit.file-size@1").exit_code(),
            classify_error_code("cli.write.io@1").exit_code(),
            classify_error_code("cli.internal.unclassified@1").exit_code(),
        ];
        for code in codes {
            assert!(code <= 5, "closed set 0-5 violated: {code}");
        }
        assert_eq!(
            usage_exit_code(&ParseError::UnknownCommand("x".to_owned())),
            1
        );
        assert_eq!(
            usage_exit_code(&ParseError::MissingRequired("--profile")),
            1
        );
    }

    #[test]
    fn non_utf8_process_arguments_exit_usage() {
        let error = collect_args([make_non_utf8_argument()]).expect_err("non-UTF-8 rejected");
        assert_eq!(error, ParseError::NonUtf8Argument);
        let mut stderr = Vec::new();
        write_usage_error(&error, &mut stderr).expect("Vec writer");
        assert_eq!(usage_exit_code(&error), 1);
        assert!(stderr_text(&stderr).contains("not valid UTF-8"));
    }
}
