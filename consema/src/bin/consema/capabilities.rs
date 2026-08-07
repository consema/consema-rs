//! `consema capabilities`: the facade capability inventory (RFC 0015 §6.1/
//! §6.2; implementation plan §3.1).
//!
//! The machine payload is the frozen `cli.capabilities@1` record: the eight
//! format families, the sixteen profiles, the query-domain inventory, the
//! per-profile `core.format-operation-registry@1` records, and every
//! `ErrorCodeRegistry::v7()` code (strictly sorted). Every fact derives from
//! the facade public API through [`crate::registry`] — nothing is
//! redeclared (plan §11 item 3), and the registry-completeness tests assert
//! the inventory against the facade types so the CLI and the SDK cannot
//! drift (plan §10 capabilities row). Read-only, no side effects.

use consema::core::{ObjectBuilder, PortableValue, SequenceBuilder};
use consema::protocol::{
    CliCommand, CliOutputMessage, ExitClass, FormatOperationRegistryMessage, Redaction,
};
use std::io::Write;

use super::registry;
use super::{args::ParsedArgs, output};

/// Runs one `consema capabilities` invocation and returns the frozen exit
/// code (always 0: the inventory is the complete result).
pub fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let payload = capabilities_payload();
    let envelope = match CliOutputMessage::new(
        CliCommand::Capabilities,
        ExitClass::Success,
        super::PRODUCT_VERSION,
        payload,
        Vec::new(),
        no_redaction(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => return internal_error(&format!("capabilities envelope: {error}"), stderr),
    };
    let write_result = if parsed.json {
        output::emit_envelope(&envelope, parsed.pretty, stdout)
            .map_err(|error| error.message().to_owned())
    } else {
        write_human_report(stdout)
    };
    match write_result {
        Ok(()) => ExitClass::Success.exit_code(),
        Err(message) => internal_error(&message, stderr),
    }
}

/// The frozen `cli.capabilities@1` payload record (RFC 0015 §6.2).
fn capabilities_payload() -> PortableValue {
    let families = consema::registry::format_families();
    let profiles = registry::profile_entries();
    let domains = consema::registry::query_domains();

    let mut family_values = SequenceBuilder::new();
    for family in &families {
        family_values.push(registry::reference_value(family.id(), family.version()));
    }

    let mut profile_values = SequenceBuilder::new();
    for entry in &profiles {
        profile_values.push(registry::reference_value(
            entry.profile.id(),
            entry.profile.version(),
        ));
    }

    let mut domain_values = SequenceBuilder::new();
    for domain in &domains {
        domain_values.push(registry::reference_value(domain.id(), domain.version()));
    }

    let mut operation_values = SequenceBuilder::new();
    for entry in &profiles {
        let operation_registry = consema::registry::operation_registry(&entry.profile)
            .expect("every facade profile publishes an operation registry");
        operation_values
            .push(FormatOperationRegistryMessage::from_registry(&operation_registry).to_value());
    }

    let mut code_values = SequenceBuilder::new();
    for code in registry::error_codes() {
        code_values.push(PortableValue::string(code));
    }

    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.capabilities@1"))
        .expect("unique keys");
    payload
        .insert("families", family_values.build())
        .expect("unique keys");
    payload
        .insert("profiles", profile_values.build())
        .expect("unique keys");
    payload
        .insert("query_domains", domain_values.build())
        .expect("unique keys");
    payload
        .insert("operations", operation_values.build())
        .expect("unique keys");
    payload
        .insert("error_codes", code_values.build())
        .expect("unique keys");
    payload.build()
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
        "consema: error: capabilities: {message} (code cli.internal.unclassified@1)"
    );
    consema::protocol::classify_error_code("cli.internal.unclassified@1").exit_code()
}

/// Deterministic human capability inventory; it draws from the same facade
/// facts as the machine payload (implementation plan §2.4).
fn write_human_report(stdout: &mut dyn Write) -> Result<(), String> {
    use std::fmt::Write as _;
    let families = consema::registry::format_families();
    let profiles = registry::profile_entries();
    let domains = consema::registry::query_domains();
    let codes = registry::error_codes();

    let mut report = String::new();
    writeln!(report, "consema capabilities").expect("writing to String cannot fail");
    writeln!(report, "  families ({}):", families.len()).expect("writing to String cannot fail");
    for family in &families {
        writeln!(report, "    {}@{}", family.id(), family.version())
            .expect("writing to String cannot fail");
    }
    writeln!(report, "  profiles ({}):", profiles.len()).expect("writing to String cannot fail");
    for entry in &profiles {
        writeln!(
            report,
            "    {}@{} (family {})",
            entry.profile.id(),
            entry.profile.version(),
            entry.family_id
        )
        .expect("writing to String cannot fail");
    }
    writeln!(report, "  query domains ({}):", domains.len())
        .expect("writing to String cannot fail");
    for domain in &domains {
        writeln!(report, "    {}@{}", domain.id(), domain.version())
            .expect("writing to String cannot fail");
    }
    writeln!(report, "  operations ({} registries):", profiles.len())
        .expect("writing to String cannot fail");
    for entry in &profiles {
        let operation_registry = consema::registry::operation_registry(&entry.profile)
            .expect("every facade profile publishes an operation registry");
        let operations = operation_registry
            .operations()
            .iter()
            .map(|operation| format!("{}@{}", operation.id().id(), operation.id().version()))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            report,
            "    {}@{}: {}",
            entry.profile.id(),
            entry.profile.version(),
            operations
        )
        .expect("writing to String cannot fail");
    }
    writeln!(report, "  error codes ({}):", codes.len()).expect("writing to String cannot fail");
    writeln!(report, "    {}", codes.join(", ")).expect("writing to String cannot fail");
    stdout
        .write_all(report.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::protocol::ProtocolLimits;

    fn run(args: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        let parsed = crate::args::parse_args(&owned).expect("valid invocation");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = super::run(&parsed, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    #[test]
    fn capabilities_human_report_lists_the_facade_inventory() {
        let (code, stdout, stderr) = run(&["capabilities"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("families (8):"));
        assert!(text.contains("profiles (16):"));
        assert!(text.contains("ini.portable@1 (family ini)"));
        assert!(text.contains("plist.binary@1 (family plist)"));
        assert!(text.contains("query domains (21):"));
        assert!(text.contains("error codes (187):"));
    }

    #[test]
    fn capabilities_json_payload_matches_the_rfc_record() {
        let (code, stdout, stderr) = run(&["capabilities", "--json"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid envelope");
        assert_eq!(envelope.command(), CliCommand::Capabilities);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        let entries = envelope.payload().as_object().expect("payload object");
        assert_eq!(entries[0].value().as_string(), Some("cli.capabilities@1"));
        let field = |key: &str| {
            entries
                .iter()
                .find(|entry| entry.key() == key)
                .expect("field present")
                .value()
        };
        assert_eq!(field("families").as_sequence().expect("families").len(), 8);
        assert_eq!(field("profiles").as_sequence().expect("profiles").len(), 16);
        assert_eq!(
            field("query_domains")
                .as_sequence()
                .expect("query domains")
                .len(),
            21
        );
        assert_eq!(
            field("operations").as_sequence().expect("operations").len(),
            16,
            "one core.format-operation-registry@1 record per profile"
        );
        assert_eq!(
            field("error_codes")
                .as_sequence()
                .expect("error codes")
                .len(),
            187
        );
    }

    #[test]
    fn capabilities_usage_rejections_are_frozen() {
        // An extra positional is rejected at parse time (usage, no envelope).
        let owned: Vec<String> = vec!["capabilities".to_owned(), "extra".to_owned()];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = crate::run_with_io(&owned, &mut stdout, &mut stderr);
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
    }
}
