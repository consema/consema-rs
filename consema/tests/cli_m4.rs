//! Process-level milestone M4 tests for the `consema` binary
//! (registry/capabilities/inspect/explain/detect).
//!
//! Launches the built binary via `env!("CARGO_BIN_EXE_consema")` (cargo
//! built-in; zero dev-dependencies, implementation plan §8.3) and asserts
//! the milestone M4 acceptance gates (implementation plan §6 M4): every
//! command has a success path, a usage rejection, and a data-error path;
//! detection ambiguity is a first-class success result (RFC 0015 §7.2 rule
//! 3); the registry inventory is complete (16 profiles across 8 families,
//! 21 query domains, 187 error codes, one operation registry per profile);
//! under `--json`, data-class failures carry an envelope while usage
//! failures never do (RFC 0015 §4.2), and in human mode envelope-class
//! failures write zero stdout bytes (RFC 0015 §3.3); stdout carries only
//! result data while diagnostics go to stderr (RFC 0015 §3.3).

use consema::protocol::{CliCommand, CliOutputMessage, ExitClass, ProtocolLimits};
use std::fs;
use std::path::PathBuf;
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

fn decode_envelope(output: &Output) -> CliOutputMessage {
    assert!(
        output.stdout.ends_with(b"\n"),
        "envelope line ends in one LF"
    );
    assert!(
        !output.stdout[..output.stdout.len() - 1].contains(&b'\n'),
        "stdout is exactly one envelope line"
    );
    CliOutputMessage::from_json(
        &output.stdout[..output.stdout.len() - 1],
        ProtocolLimits::default(),
    )
    .expect("stdout is a byte-valid core.cli-output@1 envelope")
}

/// One unique temp file; the caller removes it.
fn temp_file(name: &str, content: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("consema-cli-m4-{}-{name}", std::process::id()));
    fs::write(&path, content).expect("write fixture");
    path
}

fn payload_field<'a>(
    envelope: &'a CliOutputMessage,
    key: &str,
) -> &'a consema::core::PortableValue {
    envelope
        .payload()
        .as_object()
        .expect("payload object")
        .iter()
        .find(|entry| entry.key() == key)
        .expect("field present")
        .value()
}

// ---------------------------------------------------------------------------
// registry / capabilities
// ---------------------------------------------------------------------------

#[test]
fn capabilities_reports_the_full_facade_inventory() {
    let output = run(&["capabilities", "--json"]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Capabilities);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let payload_entries = envelope.payload().as_object().expect("payload object");
    assert_eq!(
        payload_entries[0].value().as_string(),
        Some("cli.capabilities@1"),
        "payload schema first field (RFC 0015 §6.2)"
    );
    let families = payload_field(&envelope, "families")
        .as_sequence()
        .expect("families");
    assert_eq!(families.len(), 8, "eight format families");
    let profiles = payload_field(&envelope, "profiles")
        .as_sequence()
        .expect("profiles");
    assert_eq!(
        profiles.len(),
        16,
        "sixteen profiles (registry completeness)"
    );
    let profile_ids: Vec<&str> = profiles
        .iter()
        .map(|profile| {
            profile
                .as_object()
                .expect("profile reference")
                .iter()
                .find(|entry| entry.key() == "id")
                .expect("id field")
                .value()
                .as_string()
                .expect("id string")
        })
        .collect();
    for expected in [
        "hcl.native",
        "hcl.tfvars",
        "ini.portable",
        "ini.windows",
        "ini.python-configparser",
        "java-properties.reader",
        "java-properties.latin1",
        "json.strict",
        "jsonc.bounded",
        "json5.standard",
        "plist.xml",
        "plist.binary",
        "toml.1.0",
        "xml.1.0-safe",
        "yaml.1.2-core",
        "yaml.1.1-compat",
    ] {
        assert!(
            profile_ids.contains(&expected),
            "profile {expected} present"
        );
    }
    let domains = payload_field(&envelope, "query_domains")
        .as_sequence()
        .expect("query domains");
    assert_eq!(domains.len(), 21, "query-domain constructor inventory");
    let operations = payload_field(&envelope, "operations")
        .as_sequence()
        .expect("operations");
    assert_eq!(operations.len(), 16, "one operation registry per profile");
    for operation in operations {
        let entries = operation.as_object().expect("operation registry record");
        assert_eq!(
            entries[0].value().as_string(),
            Some("core.format-operation-registry@1")
        );
    }
    let codes = payload_field(&envelope, "error_codes")
        .as_sequence()
        .expect("error codes");
    assert_eq!(codes.len(), 187, "v7 error-code count");
    let code_strings: Vec<&str> = codes
        .iter()
        .map(|code| code.as_string().expect("code string"))
        .collect();
    for pair in code_strings.windows(2) {
        assert!(pair[0] < pair[1], "error codes strictly sorted");
    }
}

#[test]
fn capabilities_human_output_is_deterministic_data() {
    let output = run(&["capabilities"]);
    assert_eq!(status(&output), 0);
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("consema capabilities\n"));
    assert!(text.contains("families (8):"));
    assert!(text.contains("profiles (16):"));
    assert!(text.contains("query domains (21):"));
    assert!(text.contains("error codes (187):"));
}

#[test]
fn capabilities_rejects_extra_positionals_as_usage() {
    let output = run(&["capabilities", "extra"]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty(), "usage failures emit no envelope");
    assert!(!output.stderr.is_empty());
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

#[test]
fn inspect_reports_ambiguity_successfully_with_a_complete_envelope() {
    // A leading [section] line is both an INI section and a TOML table
    // header: the ambiguity fact report is itself the complete result
    // (RFC 0015 §7.2 rule 3; plan §3.2 marker-collision matrix).
    let path = temp_file("app-ambiguity.conf", b"[section]\nvalue=1\n");
    let output = run(&["inspect", path.to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    assert!(output.stderr.is_empty());
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.command(), CliCommand::Inspect);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let payload = envelope.payload();
    let entries = payload.as_object().expect("payload object");
    assert_eq!(entries[0].value().as_string(), Some("cli.inspect@1"));
    assert_eq!(
        payload_field(&envelope, "path").as_string(),
        Some(path.to_str().unwrap()),
        "path field carries the user-supplied spelling verbatim (RFC 0015 §3.3)"
    );
    assert_eq!(
        payload_field(&envelope, "bom"),
        &consema::core::PortableValue::null(),
        "no BOM fact"
    );
    assert_eq!(
        payload_field(&envelope, "symlink"),
        &consema::core::PortableValue::boolean(false)
    );
    let markers = payload_field(&envelope, "markers")
        .as_sequence()
        .expect("markers");
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].as_string(), Some("[section] line"));
    let candidates = payload_field(&envelope, "candidates")
        .as_sequence()
        .expect("candidates");
    assert_eq!(candidates.len(), 4, "ini family plus toml.1.0");
    assert_eq!(
        payload_field(&envelope, "ambiguous"),
        &consema::core::PortableValue::boolean(true),
        "candidate set > 1 is ambiguous (RFC 0015 §7.1)"
    );
    let reasons = payload_field(&envelope, "ambiguity_reasons")
        .as_sequence()
        .expect("ambiguity reasons");
    assert!(!reasons.is_empty());
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_reports_byte_and_bom_facts_deterministically() {
    // UTF-8 BOM + JSON object: marker, bom fact, digest of exact bytes.
    let content = b"\xef\xbb\xbf{\"a\":1}";
    let path = temp_file("bom.json", content);
    let output = run(&["inspect", path.to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    assert_eq!(payload_field(&envelope, "bom").as_string(), Some("Utf8"));
    let bytes = payload_field(&envelope, "bytes")
        .as_object()
        .expect("bytes");
    let size = bytes
        .iter()
        .find(|entry| entry.key() == "size")
        .expect("size")
        .value()
        .as_integer()
        .expect("integer size");
    assert_eq!(size.to_string(), "10");
    let digest = bytes
        .iter()
        .find(|entry| entry.key() == "digest")
        .expect("digest")
        .value();
    let digest_entries = digest.as_object().expect("digest object");
    let algorithm = digest_entries
        .iter()
        .find(|entry| entry.key() == "algorithm")
        .expect("algorithm")
        .value()
        .as_string();
    assert_eq!(algorithm, Some("sha256"));
    let hex = digest_entries
        .iter()
        .find(|entry| entry.key() == "hex")
        .expect("hex")
        .value()
        .as_string()
        .expect("hex string");
    assert_eq!(hex, consema::document::ContentDigest::of(content).to_hex());
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_parse_facts_require_an_explicit_profile_and_are_complete() {
    let path = temp_file("app-parse.conf", b"[section]\nvalue=1\n");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "ini.portable",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    let parse = payload_field(&envelope, "parse")
        .as_object()
        .expect("parse facts present under --profile (RFC 0015 §7.1)");
    let parse_entries: Vec<&str> = parse.iter().map(consema::core::ObjectEntry::key).collect();
    assert_eq!(
        parse_entries,
        vec![
            "schema",
            "profile",
            "formation_status",
            "diagnostics",
            "structure_counts"
        ],
        "cli.parse-facts@1 fixed fields"
    );
    assert_eq!(parse[0].value().as_string(), Some("cli.parse-facts@1"));
    assert_eq!(
        parse
            .iter()
            .find(|entry| entry.key() == "formation_status")
            .expect("formation status")
            .value()
            .as_string(),
        Some("Complete")
    );
    let counts = parse
        .iter()
        .find(|entry| entry.key() == "structure_counts")
        .expect("counts")
        .value()
        .as_object()
        .expect("counts object");
    let sections = counts
        .iter()
        .find(|entry| entry.key() == "ini.sections")
        .expect("ini.sections")
        .value()
        .as_integer()
        .expect("integer");
    assert_eq!(sections.to_string(), "1");
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_recovered_files_exit_zero_with_a_full_report() {
    // A recovered INI line must not fail inspect: the Recovered-state report
    // is a complete result (RFC 0015 §5.1 success row).
    let path = temp_file("broken.conf", b"[section]\nvalue=1\nbad line\n");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "ini.portable",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let parse = payload_field(&envelope, "parse")
        .as_object()
        .expect("parse facts");
    assert_eq!(
        parse
            .iter()
            .find(|entry| entry.key() == "formation_status")
            .expect("formation status")
            .value()
            .as_string(),
        Some("Recovered")
    );
    let diagnostics = parse
        .iter()
        .find(|entry| entry.key() == "diagnostics")
        .expect("diagnostics")
        .value()
        .as_sequence()
        .expect("diagnostics sequence");
    assert!(!diagnostics.is_empty(), "recovery diagnostics are reported");
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_unreadable_file_is_a_data_error_with_an_envelope() {
    let missing = std::env::temp_dir().join("consema-cli-m4-no-such-file.conf");
    let output = run(&["inspect", missing.to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 2, "cli.data.io@1 classifies as data");
    assert!(!output.stdout.is_empty(), "data failures carry an envelope");
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert_eq!(envelope.diagnostics()[0].code, "cli.data.io@1");
    assert!(stderr_text(&output).contains("(code cli.data.io@1)"));
}

#[test]
fn inspect_fatal_parse_failure_is_a_data_error() {
    // Invalid UTF-8 under the json.strict profile is a fatal formation
    // failure (core.source.invalid-utf8@1): data-class (RFC 0015 §5.1) and
    // the failure diagnostics travel in the envelope.
    let path = temp_file("not-json.conf", b"\xff\xfe\x00\x01");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "json.strict",
        "--json",
    ]);
    assert_eq!(status(&output), 2, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert!(!envelope.diagnostics().is_empty());
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_format_local_fatal_is_a_data_error_not_an_internal_error() {
    // B-9 regression: a fatal parse carrying a format-local code
    // (`xml.limit.depth@1`, not registry-bound) must report the data fact
    // (exit 2) with the registered fallback code in the envelope and the
    // true code on stderr — never exit 5 `cli.internal.unclassified@1`.
    let path = temp_file("deep.xml", "<a>".repeat(300).as_bytes());
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "xml.1.0-safe",
        "--json",
    ]);
    assert_eq!(status(&output), 2, "{}", stderr_text(&output));
    assert!(
        stderr_text(&output).contains("xml.limit.depth@1"),
        "stderr keeps the true format-local code"
    );
    assert!(
        !stderr_text(&output).contains("cli.internal.unclassified@1"),
        "the failure is a data fact, never an internal error"
    );
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert!(!envelope.diagnostics().is_empty());
    assert_eq!(
        envelope.diagnostics()[0].code,
        "core.source.invalid-sequence@1",
        "the envelope carries only registry-bound codes (RFC 0015 §4.3)"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_recovered_json_reports_successfully() {
    // Malformed JSON is recovered, not fatal: the Recovered-state report is
    // the complete result (exit 0; RFC 0015 §5.1).
    let path = temp_file("recovered.json", b"value = 1\n");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "json.strict",
        "--json",
    ]);
    assert_eq!(status(&output), 0, "{}", stderr_text(&output));
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    let parse = payload_field(&envelope, "parse")
        .as_object()
        .expect("parse facts");
    assert_eq!(
        parse
            .iter()
            .find(|entry| entry.key() == "formation_status")
            .expect("formation status")
            .value()
            .as_string(),
        Some("Recovered")
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_limit_budget_is_a_limit_error() {
    let path = temp_file("big.conf", b"[section]\nvalue=1\n");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--json",
        "--max-bytes",
        "4",
    ]);
    assert_eq!(
        status(&output),
        3,
        "cli.limit.file-size@1 classifies as limit"
    );
    let envelope = decode_envelope(&output);
    assert_eq!(envelope.exit_class(), ExitClass::Limit);
    assert_eq!(envelope.diagnostics()[0].code, "cli.limit.file-size@1");
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_unknown_profile_value_is_usage() {
    let path = temp_file("app-profile.conf", b"value=1\n");
    let output = run(&[
        "inspect",
        path.to_str().unwrap(),
        "--profile",
        "example.unknown",
    ]);
    assert_eq!(
        status(&output),
        1,
        "invalid --format is usage (RFC 0015 §5.1)"
    );
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("invalid --profile value"));
    let _ = fs::remove_file(&path);
}

#[test]
fn inspect_missing_path_argument_is_usage() {
    let output = run(&["inspect"]);
    assert_eq!(status(&output), 1);
    assert!(output.stdout.is_empty());
    assert!(stderr_text(&output).contains("missing required argument"));
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

#[test]
fn explain_contract_and_error_code_and_profile_succeed() {
    for (args, expected_kind) in [
        (
            &["explain", "contract", "core.cli-output@1", "--json"][..],
            "contract",
        ),
        (
            &["explain", "error-code", "cli.data.io@1", "--json"][..],
            "error-code",
        ),
        (
            &["explain", "profile", "ini.portable@1", "--json"][..],
            "profile",
        ),
        (&["explain", "core.batch-plan@1", "--json"][..], "contract"),
        (
            &["explain", "cli.limit.file-size@1", "--json"][..],
            "error-code",
        ),
        (&["explain", "hcl.tfvars@1", "--json"][..], "profile"),
    ] {
        let output = run(args);
        assert_eq!(status(&output), 0, "{args:?}: {}", stderr_text(&output));
        assert!(output.stderr.is_empty(), "{args:?}");
        let envelope = decode_envelope(&output);
        assert_eq!(envelope.command(), CliCommand::Explain);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(
            payload_field(&envelope, "kind").as_string(),
            Some(expected_kind),
            "{args:?}"
        );
        let record = payload_field(&envelope, "record")
            .as_object()
            .expect("record object");
        assert!(!record.is_empty(), "{args:?} record is populated");
    }
}

#[test]
fn explain_unknown_id_is_a_data_error() {
    let output = run(&["explain", "example.unknown@1"]);
    assert_eq!(status(&output), 2, "failed lookups classify as data");
    assert!(
        output.stdout.is_empty(),
        "human-mode failures write zero stdout bytes (RFC 0015 §3.3)"
    );
    assert!(
        stderr_text(&output).contains("(code cli.data.invalid-request@1)"),
        "human-mode failures diagnose on stderr"
    );
    // The --json sibling still carries the failure envelope (RFC 0015 §4.2).
    let json = run(&["explain", "example.unknown@1", "--json"]);
    assert_eq!(status(&json), 2);
    let envelope = decode_envelope(&json);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert_eq!(envelope.diagnostics()[0].code, "cli.data.invalid-request@1");
}

#[test]
fn explain_kind_without_id_is_usage() {
    let output = run(&["explain", "contract"]);
    assert_eq!(status(&output), 1, "missing required argument is usage");
    assert!(
        output.stdout.is_empty(),
        "usage failures never produce an envelope"
    );
    assert!(stderr_text(&output).contains("missing required argument"));
}

#[test]
fn explain_capability_kind_is_a_data_error_until_a_declaration_source_exists() {
    let output = run(&["explain", "capability", "core.query.ordered-results@1"]);
    assert_eq!(
        status(&output),
        2,
        "the 0.12.0 SDK publishes no capability-declaration registry"
    );
    assert!(
        output.stdout.is_empty(),
        "human-mode failures write zero stdout bytes (RFC 0015 §3.3)"
    );
    assert!(
        stderr_text(&output).contains("(code cli.data.invalid-request@1)"),
        "human-mode failures diagnose on stderr"
    );
    // The --json sibling still carries the failure envelope (RFC 0015 §4.2).
    let json = run(&[
        "explain",
        "capability",
        "core.query.ordered-results@1",
        "--json",
    ]);
    assert_eq!(status(&json), 2);
    let envelope = decode_envelope(&json);
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert_eq!(envelope.diagnostics()[0].code, "cli.data.invalid-request@1");
}

// ---------------------------------------------------------------------------
// detection facts across the marker matrix
// ---------------------------------------------------------------------------

#[test]
fn detection_ambiguity_cases_are_first_class_reports() {
    // RFC 0015 §7.2 rule 5 candidate-marker collisions: INI vs Properties,
    // JSON vs JSON5, XML vs plist.xml, TOML table vs INI section.
    let cases: &[(&str, &[u8], usize, bool)] = &[
        ("key=value line", b"name=api\n", 5, true),
        ("first non-whitespace '{'", b"{\"a\":1}", 3, true),
        ("XML declaration", b"<?xml version=\"1.0\"?><a/>", 2, true),
        ("[section] line", b"[section]\nvalue=1\n", 4, true),
        ("a = 1 shape", b"a = 1\n", 3, true),
        ("bplist00 header", b"bplist00\x5f\x78", 1, false),
        (
            "plist root element",
            b"<plist version=\"1.0\"><string>x</string></plist>",
            1,
            false,
        ),
    ];
    for (marker, content, candidates, ambiguous) in cases {
        let path = temp_file(&format!("case-{marker}"), content);
        let output = run(&["inspect", path.to_str().unwrap(), "--json"]);
        assert_eq!(
            status(&output),
            0,
            "{marker}: ambiguity reports are complete results: {}",
            stderr_text(&output)
        );
        let envelope = decode_envelope(&output);
        let markers = payload_field(&envelope, "markers")
            .as_sequence()
            .expect("markers");
        assert_eq!(markers.len(), 1, "{marker}");
        assert_eq!(markers[0].as_string(), Some(*marker), "{marker}");
        let candidates_field = payload_field(&envelope, "candidates")
            .as_sequence()
            .expect("candidates");
        assert_eq!(candidates_field.len(), *candidates, "{marker}");
        assert_eq!(
            payload_field(&envelope, "ambiguous"),
            &consema::core::PortableValue::boolean(*ambiguous),
            "{marker}"
        );
        let _ = fs::remove_file(&path);
    }
}
