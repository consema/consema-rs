//! `consema conformance`: the embedded protocol self-check subset of
//! RFC 0015 §16.4 (implementation plan §8.4).
//!
//! The release artifact executes a small self-check subset — envelope
//! round-trip, exit classification, and the redaction contract — with **no
//! repository fixtures** (the release does not ship `conformance/vectors`);
//! the full language-neutral `consema.cli.conformance@1` suite stays
//! repository-level (`cargo test -p consema-conformance`, milestone M9).
//! The subset mirrors the library-side vector semantics case for case: the
//! checks here are the embedded counterparts of the `cli.envelope@1`,
//! `cli.exit-code@1`, and `cli.redaction@1` vector capabilities.
//!
//! All checks pass -> exit 0. Any check fails -> the envelope carries
//! `internal` (RFC 0015 §5.1) with `cli.internal.unclassified@1` and the
//! process exits 5; that failure envelope is itself pinned byte-for-byte by
//! the M9 vector case `cli.envelope.conformance-failure-semantics`.

use super::args::ParsedArgs;
use super::output;
use super::redact::{PLACEHOLDER, RedactPolicy, redact_value};
use consema::core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, ObjectBuilder, PortableValue,
    SequenceBuilder,
};
use consema::protocol::{
    CliCommand, CliOutputMessage, DiagnosticMessage, ErrorCodeRegistry, ExitClass, ProtocolLimits,
    Redaction, classify, classify_error_code,
};
use std::io::Write;

/// The frozen conformance suite id of RFC 0015 §6.2/§16.1.
pub(crate) const CONFORMANCE_SUITE: &str = "consema.cli.conformance@1";

/// One deterministic embedded self-check: `Ok(id)` when it passes, otherwise
/// the failing check id and a human message.
type SelfCheck = fn() -> Result<&'static str, (&'static str, String)>;

/// The embedded self-check subset, in deterministic order (RFC 0015 §16.4).
const SELF_CHECKS: &[SelfCheck] = &[
    check_envelope_round_trip,
    check_exit_classification,
    check_redaction_contract,
];

/// `consema conformance`: runs the embedded self-check subset and reports.
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    run_conformance_with_checks(parsed, SELF_CHECKS, stdout, stderr)
}

/// Runs one deterministic self-check list against the writers and returns
/// the frozen process exit code (shared by the bin unit tests for failure
/// injection).
pub(crate) fn run_conformance_with_checks(
    parsed: &ParsedArgs,
    checks: &[SelfCheck],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let mut passed_ids: Vec<&'static str> = Vec::new();
    let mut failed_items: Vec<(&'static str, String)> = Vec::new();
    for check in checks {
        match check() {
            Ok(id) => passed_ids.push(id),
            Err((id, message)) => failed_items.push((id, message)),
        }
    }
    let exit_class = if failed_items.is_empty() {
        ExitClass::Success
    } else {
        classify_error_code("cli.internal.unclassified@1")
    };
    let diagnostics = if failed_items.is_empty() {
        Vec::new()
    } else {
        // RFC 0015 §5.1 internal row: the template names the command and the
        // diagnostic code.
        vec![internal_conformance_diagnostic()]
    };
    let envelope = match CliOutputMessage::new(
        CliCommand::Conformance,
        exit_class,
        PRODUCT_VERSION,
        conformance_payload(&passed_ids, &failed_items),
        diagnostics,
        Redaction::new(false, 0).expect("redaction invariant redacted == (count > 0)"),
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            return internal_error(
                &format!("conformance envelope construction failed: {error}"),
                stderr,
            );
        }
    };
    let write_result: Result<(), String> = if parsed.json {
        output::emit_envelope(&envelope, parsed.pretty, stdout)
            .map_err(|error| error.message().to_owned())
    } else {
        write_conformance_report(&passed_ids, &failed_items, stdout)
    };
    if let Err(message) = write_result {
        return internal_error(&message, stderr);
    }
    for (id, message) in &failed_items {
        let _ = writeln!(
            stderr,
            "consema: error: conformance self-check failed: {id}: {message} \
             (code cli.internal.unclassified@1)"
        );
    }
    exit_class.exit_code()
}

/// The release product version string (RFC 0015 §3.3: the workspace version,
/// without git hashes or build metadata).
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reports an unclassified internal failure on stderr and returns exit 5
/// (RFC 0015 §5.1 internal row; the message names the command and code).
fn internal_error(message: &str, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "consema: error: conformance: {message} (code cli.internal.unclassified@1)"
    );
    classify_error_code("cli.internal.unclassified@1").exit_code()
}

/// The frozen `cli.conformance@1` payload record of RFC 0015 §6.2.
fn conformance_payload(
    passed: &[&'static str],
    failed: &[(&'static str, String)],
) -> PortableValue {
    let mut passed_values = SequenceBuilder::new();
    for id in passed {
        passed_values.push(PortableValue::string(*id));
    }
    let mut failed_values = SequenceBuilder::new();
    for (id, message) in failed {
        let mut entry = ObjectBuilder::new();
        entry
            .insert("id", PortableValue::string(*id))
            .expect("unique keys");
        entry
            .insert("message", PortableValue::string(message.as_str()))
            .expect("unique keys");
        failed_values.push(entry.build());
    }
    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.conformance@1"))
        .expect("unique keys");
    payload
        .insert("suite", PortableValue::string(CONFORMANCE_SUITE))
        .expect("unique keys");
    payload
        .insert("passed", passed_values.build())
        .expect("unique keys");
    payload
        .insert("failed", failed_values.build())
        .expect("unique keys");
    payload.build()
}

/// The `cli.internal.unclassified@1` diagnostic carried by a failed
/// conformance envelope. The category matches the v7 registry descriptor
/// (RFC 0015 §13.1), so construction cannot fail.
fn internal_conformance_diagnostic() -> DiagnosticMessage {
    let mut diagnostic = Diagnostic::new(
        "cli.internal.unclassified@1",
        DiagnosticCategory::Semantic,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("command".to_owned(), "conformance".to_owned());
    DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v7())
        .expect("cli.internal.unclassified@1 is a registered v7 Semantic code")
}

/// Deterministic human conformance report (RFC 0015 §16.4 "plus a human
/// report"); it draws from the same check results as the machine payload.
fn write_conformance_report(
    passed: &[&'static str],
    failed: &[(&'static str, String)],
    stdout: &mut dyn Write,
) -> Result<(), String> {
    writeln!(stdout, "consema conformance ({CONFORMANCE_SUITE})").map_err(io_message)?;
    for id in passed {
        writeln!(stdout, "  [PASS] {id}").map_err(io_message)?;
    }
    for (id, _) in failed {
        writeln!(stdout, "  [FAIL] {id}").map_err(io_message)?;
    }
    writeln!(stdout, "  {} passed, {} failed", passed.len(), failed.len()).map_err(io_message)?;
    Ok(())
}

fn io_message(error: std::io::Error) -> String {
    format!("stdout write failed: {error}")
}

/// Self-check `cli.envelope@1`: the fixed `core.cli-output@1` envelope
/// round-trips on both transports and is byte-deterministic (RFC 0015 §3.3).
fn check_envelope_round_trip() -> Result<&'static str, (&'static str, String)> {
    const CHECK: &str = "cli.envelope@1";
    let limits = ProtocolLimits::default();
    let envelope = match CliOutputMessage::new(
        CliCommand::Conformance,
        ExitClass::Success,
        PRODUCT_VERSION,
        conformance_payload(&[], &[]),
        Vec::new(),
        Redaction::new(false, 0).expect("redaction invariant redacted == (count > 0)"),
    ) {
        Ok(envelope) => envelope,
        Err(error) => return Err((CHECK, error.to_string())),
    };
    let json = match envelope.to_json(limits) {
        Ok(bytes) => bytes,
        Err(error) => return Err((CHECK, error.to_string())),
    };
    match CliOutputMessage::from_json(&json, limits) {
        Ok(decoded) if decoded == envelope => {}
        Ok(_) => {
            return Err((
                CHECK,
                "envelope JSON round trip changed the message".to_owned(),
            ));
        }
        Err(error) => return Err((CHECK, error.to_string())),
    }
    let pvce = match envelope.to_pvce(limits) {
        Ok(bytes) => bytes,
        Err(error) => return Err((CHECK, error.to_string())),
    };
    match CliOutputMessage::from_pvce(&pvce, limits) {
        Ok(decoded) if decoded == envelope => {}
        Ok(_) => {
            return Err((
                CHECK,
                "envelope PVCE round trip changed the message".to_owned(),
            ));
        }
        Err(error) => return Err((CHECK, error.to_string())),
    }
    match envelope.to_json(limits) {
        Ok(again) if again == json => {}
        Ok(_) => return Err((CHECK, "envelope JSON is not byte-deterministic".to_owned())),
        Err(error) => return Err((CHECK, error.to_string())),
    }
    Ok(CHECK)
}

/// Self-check `cli.exit-code@1`: the closed class-to-code table and one
/// representative per error family classify per RFC 0015 §5.1/§5.2.
fn check_exit_classification() -> Result<&'static str, (&'static str, String)> {
    const CHECK: &str = "cli.exit-code@1";
    const TABLE: [(ExitClass, u8); 6] = [
        (ExitClass::Success, 0),
        (ExitClass::Usage, 1),
        (ExitClass::Data, 2),
        (ExitClass::Limit, 3),
        (ExitClass::Precondition, 4),
        (ExitClass::Internal, 5),
    ];
    const FAMILIES: [(&str, ExitClass); 5] = [
        ("cli.usage.unknown-command@1", ExitClass::Usage),
        ("cli.data.io@1", ExitClass::Data),
        ("cli.limit.file-size@1", ExitClass::Limit),
        ("cli.write.io@1", ExitClass::Precondition),
        ("cli.internal.unclassified@1", ExitClass::Internal),
    ];
    for (exit_class, expected) in TABLE {
        let actual = classify(exit_class);
        if actual != expected || exit_class.exit_code() != expected {
            return Err((
                CHECK,
                format!(
                    "{} maps to {actual} instead of {expected}",
                    exit_class.name()
                ),
            ));
        }
    }
    for (code, expected) in FAMILIES {
        let actual = classify_error_code(code);
        if actual != expected {
            return Err((
                CHECK,
                format!(
                    "{code} classifies as {} instead of {}",
                    actual.name(),
                    expected.name()
                ),
            ));
        }
    }
    Ok(CHECK)
}

/// Self-check `cli.redaction@1`: the presentation-only redaction contract
/// of RFC 0015 §11 — the frozen key-name pattern set, the `$REDACTED$`
/// placeholder and facts, the `redacted == (count > 0)` record invariant,
/// `--show-secrets` as the sole opt-out, and the hard-gate-3 boundary that
/// byte payloads under non-matching keys survive untouched.
fn check_redaction_contract() -> Result<&'static str, (&'static str, String)> {
    const CHECK: &str = "cli.redaction@1";
    let mut payload = ObjectBuilder::new();
    payload
        .insert("host", PortableValue::string("db.internal"))
        .expect("unique keys");
    payload
        .insert("password", PortableValue::string("hunter2"))
        .expect("unique keys");
    payload
        .insert("api_key", PortableValue::string("k-1234"))
        .expect("unique keys");
    payload
        .insert("original", PortableValue::bytes([0x6f, 0x6c, 0x64]))
        .expect("unique keys");
    let value = payload.build();
    let policy = RedactPolicy::conservative();
    let (redacted, facts) = redact_value(&policy, &value);
    if facts.count() != 2 || facts.keys() != ["password".to_owned(), "api_key".to_owned()] {
        return Err((CHECK, format!("redaction facts mismatch: {facts:?}")));
    }
    if !facts.protocol().redacted() || Redaction::new(facts.count() > 0, facts.count()).is_err() {
        return Err((CHECK, "redaction record invariant broken".to_owned()));
    }
    let entries = redacted.as_object().expect("redacted object");
    if entries[1].value().as_string() != Some(PLACEHOLDER)
        || entries[2].value().as_string() != Some(PLACEHOLDER)
        || entries[0].value().as_string() != Some("db.internal")
    {
        return Err((CHECK, "placeholder replacement mismatch".to_owned()));
    }
    // Hard gate 3 / RFC 0015 §11.4: byte payloads under non-matching keys
    // are preserved exactly (redaction never touches precondition facts).
    if entries[3].value().as_bytes() != Some(&[0x6f, 0x6c, 0x64][..]) {
        return Err((CHECK, "byte payload changed by redaction".to_owned()));
    }
    // --show-secrets is the sole opt-out: the tree is returned untouched.
    let (shown, shown_facts) = redact_value(&RedactPolicy::show_secrets(), &value);
    if shown != value || shown_facts.count() != 0 || shown_facts.protocol().redacted() {
        return Err((
            CHECK,
            "--show-secrets must return the value untouched".to_owned(),
        ));
    }
    Ok(CHECK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args;

    #[test]
    fn every_self_check_passes_independently() {
        for check in SELF_CHECKS {
            let result = check();
            assert!(result.is_ok(), "self-check failed: {result:?}");
        }
    }

    #[test]
    fn the_embedded_subset_runs_successfully_through_the_command() {
        let parsed = args::parse_args(&["conformance", "--json"].map(String::from)).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_conformance_with_checks(&parsed, SELF_CHECKS, &mut stdout, &mut stderr);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(envelope.command(), CliCommand::Conformance);
    }
}
