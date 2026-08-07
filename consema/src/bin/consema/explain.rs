//! `consema explain`: authoritative single-item explanations (RFC 0015
//! §6.1/§6.2; implementation plan §3.1).
//!
//! The machine payload is the frozen `cli.explain@1` record: `kind` in
//! {contract, error-code, profile, capability}, the explained id and
//! version, and the per-kind record (contract → id/version/stability;
//! error-code → the `ErrorCodeDescriptor` fields; profile → the
//! `core.profile-descriptor@1` record; capability → a
//! `core.capability-declaration@1` record). The id may be given with an
//! explicit kind (`consema explain error-code cli.data.io@1`) or bare
//! (`consema explain cli.data.io@1`), in which case the kind is inferred by
//! lookup order: error-code → contract → profile. Every record derives from
//! the v7 registries and the facade profile inventory — nothing is
//! redeclared (plan §11 item 3).
//!
//! The capability kind is reserved by RFC 0015 §6.2 but the 0.12.0 SDK
//! publishes no capability-declaration registry: an explicit capability
//! lookup is a data error (exit 2) instead of an invented declaration.

use consema::core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, ObjectBuilder, PortableValue,
};
use consema::protocol::{
    CliCommand, CliOutputMessage, ContractStability, DiagnosticMessage, ErrorCodeRegistry,
    ExitClass, ProfileDescriptor, Redaction, classify_error_code,
};
use std::io::Write;

use super::registry;
use super::{args::ParsedArgs, output};

/// One explainable record kind (RFC 0015 §6.2 closed set).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// A `ContractRegistry::v7()` contract.
    Contract,
    /// An `ErrorCodeRegistry::v7()` error code.
    ErrorCode,
    /// A facade profile.
    Profile,
    /// A capability declaration (reserved; no declaration source yet).
    Capability,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::ErrorCode => "error-code",
            Self::Profile => "profile",
            Self::Capability => "capability",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "contract" => Some(Self::Contract),
            "error-code" => Some(Self::ErrorCode),
            "profile" => Some(Self::Profile),
            "capability" => Some(Self::Capability),
            _ => None,
        }
    }
}

/// Runs one `consema explain` invocation and returns the frozen exit code.
pub fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let positionals = &parsed.positionals;
    let (kind, id) = if let Some(kind) = Kind::parse(positionals[0].as_str()) {
        let Some(id) = positionals.get(1) else {
            // A kind without its id is a usage failure: no envelope,
            // stderr diagnostic, exit 1 (RFC 0015 §4.2).
            let _ = writeln!(
                stderr,
                "consema: error: missing required argument: an id after the kind \
                 (code cli.usage.missing-required@1)"
            );
            return classify_error_code("cli.usage.missing-required@1").exit_code();
        };
        (kind, id.as_str())
    } else {
        let id = positionals[0].as_str();
        let Some(kind) = infer_kind(id) else {
            return emit_explain_failure(
                parsed,
                "error-code",
                id,
                id_version_or_zero(id),
                &[cli_diagnostic(
                    "cli.data.invalid-request@1",
                    format!(
                        "explain: '{id}' is not a registered v7 error code, v7 contract, or facade profile"
                    ),
                )],
                stdout,
                stderr,
            );
        };
        (kind, id)
    };

    let outcome = match kind {
        Kind::Contract => explain_contract(id),
        Kind::ErrorCode => explain_error_code(id),
        Kind::Profile => explain_profile(id),
        Kind::Capability => {
            return emit_explain_failure(
                parsed,
                kind.name(),
                id,
                id_version_or_zero(id),
                &[cli_diagnostic(
                    "cli.data.invalid-request@1",
                    "explain: capability declarations are not published by this SDK build \
                     (RFC 0015 §6.2 reserves the kind; the 0.12.0 SDK has no \
                     capability-declaration registry)"
                        .to_owned(),
                )],
                stdout,
                stderr,
            );
        }
    };
    let record = match outcome {
        Ok(record) => record,
        Err(message) => {
            return emit_explain_failure(
                parsed,
                kind.name(),
                id,
                id_version_or_zero(id),
                &[cli_diagnostic("cli.data.invalid-request@1", message)],
                stdout,
                stderr,
            );
        }
    };

    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.explain@1"))
        .expect("unique keys");
    payload
        .insert("kind", PortableValue::string(kind.name()))
        .expect("unique keys");
    payload
        .insert("id", PortableValue::string(id))
        .expect("unique keys");
    payload
        .insert("version", registry::u64_integer(u64::from(record.version)))
        .expect("unique keys");
    payload
        .insert("record", record.value.clone())
        .expect("unique keys");

    let envelope = match CliOutputMessage::new(
        CliCommand::Explain,
        ExitClass::Success,
        super::PRODUCT_VERSION,
        payload.build(),
        Vec::new(),
        no_redaction(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => return internal_error(&format!("explain envelope: {error}"), stderr),
    };
    let record_value = record.value;
    let write_result = if parsed.json {
        output::emit_envelope(&envelope, parsed.pretty, stdout)
            .map_err(|error| error.message().to_owned())
    } else {
        write_human_report(kind, id, record.version, &record_value, stdout)
    };
    match write_result {
        Ok(()) => ExitClass::Success.exit_code(),
        Err(message) => internal_error(&message, stderr),
    }
}

/// One resolved explanation: the payload version and the per-kind record.
struct Explanation {
    version: u32,
    value: PortableValue,
}

/// Infers the kind of a bare id by deterministic lookup order: error-code,
/// then contract, then profile.
fn infer_kind(id: &str) -> Option<Kind> {
    if explain_error_code(id).is_ok() {
        return Some(Kind::ErrorCode);
    }
    if explain_contract(id).is_ok() {
        return Some(Kind::Contract);
    }
    if explain_profile(id).is_ok() {
        return Some(Kind::Profile);
    }
    None
}

/// Resolves one `core.cli-output@1`-style contract reference.
fn explain_contract(id: &str) -> Result<Explanation, String> {
    let (contract_id, version) = parse_reference(id, "contract")?;
    let descriptor = registry::contracts()
        .iter()
        .find(|descriptor| descriptor.id == contract_id && descriptor.version == version)
        .ok_or_else(|| format!("explain: no v7 contract '{id}'"))?;
    let stability = match descriptor.stability {
        ContractStability::Stable => "Stable",
        ContractStability::Transport => "Transport",
    };
    let mut record = ObjectBuilder::new();
    record
        .insert("id", PortableValue::string(descriptor.id))
        .expect("unique keys");
    record
        .insert(
            "version",
            registry::u64_integer(u64::from(descriptor.version)),
        )
        .expect("unique keys");
    record
        .insert("stability", PortableValue::string(stability))
        .expect("unique keys");
    Ok(Explanation {
        version: descriptor.version,
        value: record.build(),
    })
}

/// Resolves one `cli.data.io@1`-style error-code reference.
fn explain_error_code(id: &str) -> Result<Explanation, String> {
    let (_, version) = parse_reference(id, "error-code")?;
    let descriptor = ErrorCodeRegistry::v7()
        .descriptor(id)
        .ok_or_else(|| format!("explain: no v7 error code '{id}'"))?;
    let mut record = ObjectBuilder::new();
    record
        .insert("code", PortableValue::string(descriptor.code))
        .expect("unique keys");
    record
        .insert(
            "category",
            PortableValue::string(category_name(descriptor.category)),
        )
        .expect("unique keys");
    record
        .insert("introduced", PortableValue::string(descriptor.introduced))
        .expect("unique keys");
    record
        .insert("description", PortableValue::string(descriptor.description))
        .expect("unique keys");
    Ok(Explanation {
        version,
        value: record.build(),
    })
}

/// Resolves one `ini.portable@1`-style facade profile reference into the
/// `core.profile-descriptor@1` record (RFC 0015 §6.2 profile row). The
/// descriptor carries only the facts the facade publishes: family and
/// profile ids/versions; differences and required capabilities are empty
/// because the SDK publishes no such declaration source.
fn explain_profile(id: &str) -> Result<Explanation, String> {
    let (profile_id, version) = parse_reference(id, "profile")?;
    let entry = registry::profile_entries()
        .into_iter()
        .find(|entry| entry.profile.id() == profile_id && entry.profile.version() == version)
        .ok_or_else(|| format!("explain: no facade profile '{id}'"))?;
    let descriptor = ProfileDescriptor::new(
        entry.family_id,
        entry.family_version,
        entry.profile.id(),
        entry.profile.version(),
        None,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| format!("explain: profile descriptor failed: {error}"))?;
    Ok(Explanation {
        version,
        value: descriptor.to_value(),
    })
}

/// Parses the mandatory `namespace.id@N` reference shape of one explain id.
fn parse_reference(id: &str, kind: &str) -> Result<(String, u32), String> {
    let (name, version) = registry::parse_versioned_id(id)
        .ok_or_else(|| format!("explain: '{id}' must carry a @version suffix ({kind} ids)"))?;
    Ok((name, version))
}

/// The version of a failed lookup (0 when the id has no parseable version).
fn id_version_or_zero(id: &str) -> u32 {
    registry::parse_versioned_id(id).map_or(0, |(_, version)| version)
}

/// The stable category name of a diagnostic category (presentation mapping;
/// the wire record of `RegistryManifest` uses the same names).
fn category_name(category: consema::core::DiagnosticCategory) -> &'static str {
    match category {
        consema::core::DiagnosticCategory::Lexical => "Lexical",
        consema::core::DiagnosticCategory::Syntax => "Syntax",
        consema::core::DiagnosticCategory::Conformance => "Conformance",
        consema::core::DiagnosticCategory::Semantic => "Semantic",
        consema::core::DiagnosticCategory::Query => "Query",
        consema::core::DiagnosticCategory::Projection => "Projection",
        consema::core::DiagnosticCategory::Materialization => "Materialization",
        consema::core::DiagnosticCategory::Conversion => "Conversion",
        consema::core::DiagnosticCategory::Edit => "Edit",
        consema::core::DiagnosticCategory::Resource => "Resource",
        consema::core::DiagnosticCategory::Encoding => "Encoding",
    }
}

/// One data-class explain failure envelope: `cli.explain@1` with the given
/// kind/id/version and an empty record, plus the failure diagnostic
/// (RFC 0015 §4.2: data-class failures carry envelopes). The envelope is
/// written only under `--json`; in human mode the failure writes zero stdout
/// bytes and the diagnostics below are the failure surface (RFC 0015 §3.3).
fn emit_explain_failure(
    parsed: &ParsedArgs,
    kind: &str,
    id: &str,
    version: u32,
    diagnostics: &[DiagnosticMessage],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let record = ObjectBuilder::new();
    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.explain@1"))
        .expect("unique keys");
    payload
        .insert("kind", PortableValue::string(kind))
        .expect("unique keys");
    payload
        .insert("id", PortableValue::string(id))
        .expect("unique keys");
    payload
        .insert("version", registry::u64_integer(u64::from(version)))
        .expect("unique keys");
    payload
        .insert("record", record.build())
        .expect("unique keys");
    let exit_class = diagnostics.first().map_or(ExitClass::Data, |diagnostic| {
        classify_error_code(&diagnostic.code)
    });
    let envelope = match CliOutputMessage::new(
        CliCommand::Explain,
        exit_class,
        super::PRODUCT_VERSION,
        payload.build(),
        diagnostics.to_vec(),
        no_redaction(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => return internal_error(&format!("explain failure envelope: {error}"), stderr),
    };
    let write_result = if parsed.json {
        output::emit_envelope(&envelope, parsed.pretty, stdout)
            .map_err(|error| error.message().to_owned())
    } else {
        // RFC 0015 §3.3: without --json the failure carries no envelope
        // bytes on stdout; the diagnostics below are the entire human
        // failure surface.
        Ok(())
    };
    match write_result {
        Ok(()) => {
            for diagnostic in diagnostics {
                let _ = writeln!(
                    stderr,
                    "consema: error: explain: {} (code {})",
                    diagnostic_message(diagnostic),
                    diagnostic.code
                );
            }
            exit_class.exit_code()
        }
        Err(message) => internal_error(&message, stderr),
    }
}

/// One frozen `cli.data.invalid-request@1` diagnostic for a failed lookup
/// (the nearest frozen data-class code; RFC 0015 §13.1).
fn cli_diagnostic(code: &'static str, message: String) -> DiagnosticMessage {
    let mut diagnostic = Diagnostic::new(
        code,
        DiagnosticCategory::Encoding,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic.arguments.insert("message".to_owned(), message);
    DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v7())
        .expect("cli.data.invalid-request@1 is a registered v7 Encoding code")
}

/// Deterministic stderr message of a failure diagnostic.
fn diagnostic_message(diagnostic: &DiagnosticMessage) -> String {
    diagnostic
        .arguments
        .get("message")
        .cloned()
        .unwrap_or_else(|| "see the envelope diagnostics".to_owned())
}

/// The always-present, always-empty v7 redaction record (redaction lands in
/// milestone M6; these commands carry no secret-shaped values).
fn no_redaction() -> Redaction {
    Redaction::new(false, 0).expect("redaction invariant redacted == (count > 0)")
}

/// Reports an unclassified internal failure on stderr and returns exit 5.
fn internal_error(message: &str, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "consema: error: explain: {message} (code cli.internal.unclassified@1)"
    );
    classify_error_code("cli.internal.unclassified@1").exit_code()
}

/// Deterministic human explanation; it renders the same record the machine
/// payload carries (implementation plan §2.4).
fn write_human_report(
    kind: Kind,
    id: &str,
    version: u32,
    record: &PortableValue,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut report = String::new();
    writeln!(report, "consema explain {} {id}", kind.name())
        .expect("writing to String cannot fail");
    writeln!(report, "  kind: {}", kind.name()).expect("writing to String cannot fail");
    writeln!(report, "  version: {version}").expect("writing to String cannot fail");
    report.push_str("  record:\n");
    if let Some(entries) = record.as_object() {
        for entry in entries {
            let value = entry.value().as_string().map_or_else(
                || {
                    entry
                        .value()
                        .as_integer()
                        .map(ToString::to_string)
                        .unwrap_or_default()
                },
                ToString::to_string,
            );
            writeln!(report, "    {}: {value}", entry.key())
                .expect("writing to String cannot fail");
        }
    }
    stdout
        .write_all(report.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::document::ProfileId;
    use consema::protocol::ProtocolLimits;

    fn run(args: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        let parsed = crate::args::parse_args(&owned).expect("valid invocation");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = super::run(&parsed, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    #[test]
    fn explain_contract_by_inferred_kind() {
        let (code, stdout, stderr) = run(&["explain", "core.cli-output@1"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("consema explain contract core.cli-output@1"));
        assert!(text.contains("kind: contract"));
        assert!(text.contains("stability: Stable"));
    }

    #[test]
    fn explain_error_code_with_explicit_kind() {
        let (code, stdout, stderr) = run(&["explain", "error-code", "cli.data.io@1"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("kind: error-code"));
        assert!(text.contains("category: Encoding"));
        assert!(text.contains("code: cli.data.io@1"));
    }

    #[test]
    fn explain_profile_reports_the_profile_descriptor_record() {
        let (code, stdout, stderr) = run(&["explain", "profile", "ini.portable@1"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("kind: profile"));
        assert!(text.contains("profile_id: ini.portable"));
        assert!(text.contains("format_family_id: ini"));
    }

    #[test]
    fn explain_unknown_id_is_a_data_error() {
        let (code, stdout, stderr) = run(&["explain", "example.unknown@1", "--json"]);
        assert_eq!(code, 2, "a failed lookup is a data-class failure");
        assert!(!stdout.is_empty(), "data failures carry an envelope");
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid failure envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert_eq!(envelope.diagnostics()[0].code, "cli.data.invalid-request@1");
        assert!(stderr_text(&stderr).contains("(code cli.data.invalid-request@1)"));
    }

    #[test]
    fn explain_capability_kind_is_reserved_with_a_data_error() {
        let (code, stdout, stderr) =
            run(&["explain", "capability", "core.query.ordered-results@1"]);
        assert_eq!(
            code, 2,
            "no capability-declaration source in the 0.12.0 SDK"
        );
        assert!(
            stdout.is_empty(),
            "human-mode failures write zero stdout bytes (RFC 0015 §3.3)"
        );
        assert!(
            stderr_text(&stderr).contains("(code cli.data.invalid-request@1)"),
            "human-mode failures diagnose on stderr"
        );
    }

    #[test]
    fn explain_kind_without_id_is_usage() {
        let (code, stdout, stderr) = run(&["explain", "contract"]);
        assert_eq!(code, 1, "missing required argument is usage");
        assert!(
            stdout.is_empty(),
            "usage failures never produce an envelope"
        );
        assert!(stderr_text(&stderr).contains("missing required argument"));
    }

    #[test]
    fn explain_id_without_version_is_a_data_error() {
        let (code, stdout, stderr) = run(&["explain", "core.cli-output"]);
        assert_eq!(code, 2, "ids must carry the @version suffix");
        assert!(
            stdout.is_empty(),
            "human-mode failures write zero stdout bytes (RFC 0015 §3.3)"
        );
        assert!(
            stderr_text(&stderr).contains("(code cli.data.invalid-request@1)"),
            "human-mode failures diagnose on stderr"
        );
    }

    #[test]
    fn explain_profile_id_round_trips_the_profile_descriptor() {
        let profile = ProfileId::new("hcl.tfvars", 1);
        let explanation = explain_profile("hcl.tfvars@1").expect("registered profile");
        assert_eq!(explanation.version, 1);
        let fields = explanation.value.as_object().expect("descriptor object");
        assert_eq!(fields[0].key(), "schema");
        assert_eq!(
            fields[0].value().as_string(),
            Some("core.profile-descriptor@1")
        );
        let contract = explain_contract("core.batch-result@1").expect("registered contract");
        assert_eq!(contract.version, 1);
        assert_eq!(
            explain_error_code("ini.parse.malformed-line@1")
                .expect("registered")
                .version,
            1
        );
        assert!(explain_error_code("ini.parse.malformed-line@2").is_err());
        let _ = profile;
    }
}
