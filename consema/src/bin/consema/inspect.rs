//! `consema inspect`: read-only file-facts reporting (RFC 0015 §6.1/§7).
//!
//! Inspect reads exactly one file and reports source-level facts (size,
//! SHA-256 digest, BOM facts, symlink/junction facts) plus the detection
//! facts of [`crate::detect`] (markers, candidate profiles, ambiguity) — the
//! file is **not parsed for content** unless `--profile` is explicit, in
//! which case the `parse` field carries `cli.parse-facts@1` (formation
//! status, diagnostics, structure counts). Detection facts never produce a
//! conclusion (hard gate 2): ambiguity is reported as a first-class success
//! result (exit 0; RFC 0015 §7.2 rule 3), while a file that cannot be read
//! is a data error (`cli.data.io@1`, exit 2; RFC 0015 §5.1) and a read that
//! exceeds the CLI byte budget is a limit error (`cli.limit.file-size@1`,
//! exit 3; RFC 0015 §12). No side effects (implementation plan §4.1: R-4
//! reports the symlink fact; writes refuse symlinks in milestone M8).

use consema::core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, ObjectBuilder, PortableValue,
    SequenceBuilder,
};
use consema::document::ContentDigest;
use consema::protocol::{
    CliCommand, CliOutputMessage, DiagnosticMessage, ErrorCodeRegistry, ExitClass, ProtocolLimits,
    Redaction, classify_error_code,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};

use super::detect::{self, DetectFacts};
use super::registry;
use super::{args::ParsedArgs, output};

/// Runs one `consema inspect` invocation and returns the frozen exit code.
pub fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let path = parsed.positionals[0].as_str();
    let budget = match parsed.max_bytes {
        Some(bytes) => usize::try_from(bytes).unwrap_or(usize::MAX),
        None => ProtocolLimits::default().max_bytes,
    };

    // Metadata facts first: the symlink/junction fact (R-4) is reported even
    // when the read itself fails.
    let metadata = std::fs::symlink_metadata(path);
    let symlink = metadata.as_ref().is_ok_and(is_symlink_fact);

    let (bytes, fully_read) = match read_capped(path, budget) {
        Ok((bytes, fully_read)) => (bytes, fully_read),
        Err(io_error) => {
            // The stat size is a fact when metadata succeeded; without it the
            // size fact is absent (0).
            let size = metadata.as_ref().map_or(0, std::fs::Metadata::len);
            return emit_inspect_failure(
                parsed,
                path,
                symlink,
                size,
                None,
                &[cli_diagnostic(
                    "cli.data.io@1",
                    DiagnosticCategory::Encoding,
                    format!("cannot read '{path}': {io_error}"),
                )],
                stdout,
                stderr,
            );
        }
    };

    if !fully_read {
        return emit_inspect_failure(
            parsed,
            path,
            symlink,
            u64::try_from(bytes.len()).expect("read sizes fit u64"),
            None,
            &[cli_diagnostic(
                "cli.limit.file-size@1",
                DiagnosticCategory::Resource,
                format!(
                    "'{path}' exceeds the CLI read budget of {budget} bytes (RFC 0015 §12); \
                     raise it with --max-bytes"
                ),
            )],
            stdout,
            stderr,
        );
    }

    let facts = detect::detect(&bytes, true);
    let parse = match &parsed.profile {
        None => None,
        Some(profile_id) => match parse_facts_value(profile_id, path, &bytes, stderr) {
            ParseOutcome::Facts(value) => Some(value),
            ParseOutcome::Fatal(diagnostics) => {
                return emit_inspect_failure(
                    parsed,
                    path,
                    symlink,
                    facts.size,
                    facts.digest,
                    &diagnostics,
                    stdout,
                    stderr,
                );
            }
            ParseOutcome::Usage => {
                return classify_error_code("cli.usage.invalid-format@1").exit_code();
            }
        },
    };

    let payload = inspect_payload(path, &facts, symlink, parse.as_ref());
    let envelope = match CliOutputMessage::new(
        CliCommand::Inspect,
        ExitClass::Success,
        super::PRODUCT_VERSION,
        payload,
        Vec::new(),
        no_redaction(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => return internal_error(&format!("inspect envelope: {error}"), stderr),
    };
    let write_result = if parsed.json {
        output::emit_envelope(&envelope, parsed.pretty, stdout)
            .map_err(|error| error.message().to_owned())
    } else {
        write_human_report(path, &facts, symlink, parse.as_ref(), stdout)
    };
    match write_result {
        Ok(()) => ExitClass::Success.exit_code(),
        Err(message) => internal_error(&message, stderr),
    }
}

/// Reads at most `budget` bytes; the second tuple element is `false` when the
/// file exceeds the budget (the buffer holds exactly `budget` bytes then).
fn read_capped(path: &str, budget: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    // `File` implements both Read and Write; the Read view is the only one
    // used here (the read budget is RFC 0015 §12's CLI-layer cap).
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(budget).expect("budget fits u64") + 1)
        .read_to_end(&mut bytes)?;
    let fully_read = bytes.len() <= budget;
    if !fully_read {
        bytes.truncate(budget);
    }
    Ok((bytes, fully_read))
}

/// Whether the path fact is a symlink or (on Windows) any reparse point
/// (junction); reported for the write policy (R-4).
fn is_symlink_fact(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// One data/limit failure envelope for inspect (RFC 0015 §4.2: data-class
/// failures carry an envelope; the payload keeps the facts that exist).
#[allow(clippy::too_many_arguments)]
fn emit_inspect_failure(
    parsed: &ParsedArgs,
    path: &str,
    symlink: bool,
    size: u64,
    digest: Option<ContentDigest>,
    diagnostics: &[DiagnosticMessage],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let facts = DetectFacts {
        size,
        digest,
        bom: None,
        markers: Vec::new(),
        candidates: Vec::new(),
        ambiguous: false,
        ambiguity_reasons: Vec::new(),
    };
    let payload = inspect_payload(path, &facts, symlink, None);
    let exit_class = diagnostics.first().map_or(ExitClass::Data, |diagnostic| {
        classify_error_code(&diagnostic.code)
    });
    let envelope = match CliOutputMessage::new(
        CliCommand::Inspect,
        exit_class,
        super::PRODUCT_VERSION,
        payload,
        diagnostics.to_vec(),
        no_redaction(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            return internal_error(&format!("inspect failure envelope: {error}"), stderr);
        }
    };
    let write_result = output::emit_envelope(&envelope, parsed.pretty, stdout)
        .map_err(|error| error.message().to_owned());
    match write_result {
        Ok(()) => {
            for diagnostic in diagnostics {
                let _ = writeln!(
                    stderr,
                    "consema: error: inspect: {} (code {})",
                    diagnostic_message(diagnostic),
                    diagnostic.code
                );
            }
            exit_class.exit_code()
        }
        Err(message) => internal_error(&message, stderr),
    }
}

/// The frozen `cli.inspect@1` payload record (RFC 0015 §7.1).
fn inspect_payload(
    path: &str,
    facts: &DetectFacts,
    symlink: bool,
    parse: Option<&PortableValue>,
) -> PortableValue {
    let mut bytes = ObjectBuilder::new();
    bytes
        .insert("size", registry::u64_integer(facts.size))
        .expect("unique keys");
    let digest = match facts.digest {
        Some(digest) => {
            let mut value = ObjectBuilder::new();
            value
                .insert("algorithm", PortableValue::string(digest.algorithm()))
                .expect("unique keys");
            value
                .insert("hex", PortableValue::string(digest.to_hex()))
                .expect("unique keys");
            value.build()
        }
        None => PortableValue::null(),
    };
    bytes.insert("digest", digest).expect("unique keys");

    let bom = match facts.bom {
        Some(name) => PortableValue::string(name),
        None => PortableValue::null(),
    };

    let mut markers = SequenceBuilder::new();
    for marker in &facts.markers {
        markers.push(PortableValue::string(*marker));
    }

    let mut candidates = SequenceBuilder::new();
    for candidate in &facts.candidates {
        let mut entry = ObjectBuilder::new();
        entry
            .insert(
                "profile",
                registry::reference_value(candidate.profile.id(), candidate.profile.version()),
            )
            .expect("unique keys");
        entry
            .insert("reason", PortableValue::string(candidate.reason.as_str()))
            .expect("unique keys");
        candidates.push(entry.build());
    }

    let mut ambiguity_reasons = SequenceBuilder::new();
    for reason in &facts.ambiguity_reasons {
        ambiguity_reasons.push(PortableValue::string(reason.as_str()));
    }

    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.inspect@1"))
        .expect("unique keys");
    payload
        .insert("path", PortableValue::string(path))
        .expect("unique keys");
    payload.insert("bytes", bytes.build()).expect("unique keys");
    payload.insert("bom", bom).expect("unique keys");
    payload
        .insert("symlink", PortableValue::boolean(symlink))
        .expect("unique keys");
    payload
        .insert("markers", markers.build())
        .expect("unique keys");
    payload
        .insert("candidates", candidates.build())
        .expect("unique keys");
    payload
        .insert("ambiguous", PortableValue::boolean(facts.ambiguous))
        .expect("unique keys");
    payload
        .insert("ambiguity_reasons", ambiguity_reasons.build())
        .expect("unique keys");
    payload
        .insert(
            "parse",
            parse.map_or_else(PortableValue::null, PortableValue::clone),
        )
        .expect("unique keys");
    payload.build()
}

/// The outcome of the optional `--profile` parse.
enum ParseOutcome {
    /// The parse facts were assembled.
    Facts(PortableValue),
    /// The parse failed fatally; these are the failure diagnostics.
    Fatal(Vec<DiagnosticMessage>),
    /// The `--profile` value is not a facade profile: a usage failure.
    Usage,
}

/// Binds one core parse diagnostic to the semantic-model v7 registry.
///
/// Diagnostics carrying format-local codes (the XML/plist/HCL parse
/// families are not registry members) or a category that contradicts the
/// registry descriptor cannot enter the envelope as-is (RFC 0015 §4.3: the
/// envelope can only carry registry-bound codes). They bind under the
/// registered fallback code with the registry's own category; the true
/// format code is preserved on stderr through the bound `message` argument.
/// The Recovered/fatal parse fact is still reported (exit 0/2), never an
/// internal error (B-9).
fn bind_parse_diagnostic(diagnostic: &Diagnostic, path: &str) -> DiagnosticMessage {
    if let Ok(message) =
        DiagnosticMessage::from_core_with_registry(diagnostic, Some(path), ErrorCodeRegistry::v7())
    {
        return message;
    }
    let code = crate::query_cmd::registered_code(&diagnostic.code);
    let category = ErrorCodeRegistry::v7()
        .descriptor(code)
        .map_or(DiagnosticCategory::Semantic, |descriptor| {
            descriptor.category
        });
    let mut rebound = diagnostic.clone();
    code.clone_into(&mut rebound.code);
    rebound.category = category;
    if rebound.code != diagnostic.code {
        rebound.arguments.insert(
            "message".to_owned(),
            format!("format-local code {}", diagnostic.code),
        );
    }
    DiagnosticMessage::from_core_with_registry(&rebound, Some(path), ErrorCodeRegistry::v7())
        .expect("the fallback code binds to its own descriptor category")
}

/// Parses the file under the explicit `--profile` and assembles the
/// `cli.parse-facts@1` record (RFC 0015 §7.1).
///
/// `path` is the caller-stable source binding of every parse diagnostic:
/// diagnostics carry process-local snapshot locations that must be
/// externalized to caller-stable locators on the wire (RFC 0015 §3.3;
/// SECURITY.md line 28), and the user-supplied path spelling is that
/// locator (the same spelling the envelope's `path` field carries).
fn parse_facts_value(
    profile_id: &str,
    path: &str,
    bytes: &[u8],
    stderr: &mut dyn Write,
) -> ParseOutcome {
    let Some(entry) = registry::profile_by_id(profile_id) else {
        let _ = writeln!(
            stderr,
            "consema: error: invalid --profile value '{profile_id}': not a facade profile \
             (code cli.usage.invalid-format@1)"
        );
        return ParseOutcome::Usage;
    };
    let document = match consema::registry::parse_document(
        std::sync::Arc::from(bytes.to_vec()),
        &entry.profile,
    ) {
        Ok(document) => document,
        Err(failure) => {
            let diagnostics = failure
                .diagnostics()
                .iter()
                .map(|diagnostic| bind_parse_diagnostic(diagnostic, path))
                .collect();
            return ParseOutcome::Fatal(diagnostics);
        }
    };

    let formation = match document.formation_status() {
        consema::document::FormationStatus::Complete => "Complete",
        consema::document::FormationStatus::Recovered => "Recovered",
    };
    let mut diagnostics = SequenceBuilder::new();
    for diagnostic in document.diagnostics() {
        diagnostics.push(bind_parse_diagnostic(diagnostic, path).to_value());
    }
    let counts = structure_counts(&document);
    let mut structure = ObjectBuilder::new();
    for (key, count) in &counts {
        structure
            .insert(*key, registry::u64_integer(*count))
            .expect("unique keys");
    }
    let mut payload = ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("cli.parse-facts@1"))
        .expect("unique keys");
    payload
        .insert(
            "profile",
            registry::reference_value(entry.profile.id(), entry.profile.version()),
        )
        .expect("unique keys");
    payload
        .insert("formation_status", PortableValue::string(formation))
        .expect("unique keys");
    payload
        .insert("diagnostics", diagnostics.build())
        .expect("unique keys");
    payload
        .insert("structure_counts", structure.build())
        .expect("unique keys");
    ParseOutcome::Facts(payload.build())
}

/// Format-owned stable structure-count keys (RFC 0015 §7.1
/// `structure_counts`; the keys are pinned per format by the M9 vectors).
/// Counts derive from the facade typed adapters only.
fn structure_counts(document: &consema::Document) -> BTreeMap<&'static str, u64> {
    let mut counts = BTreeMap::new();
    if let Ok(ini) = document.as_ini() {
        counts.insert("ini.sections", ini.sections().len() as u64);
        counts.insert("ini.entries", ini.entries().len() as u64);
        counts.insert("ini.error_lines", ini.error_lines().len() as u64);
    } else if let Ok(properties) = document.as_properties() {
        counts.insert(
            "java-properties.entries",
            properties.properties().len() as u64,
        );
    } else if let Ok(json) = document.as_json() {
        use consema::json::SemanticAvailability;
        let root = json.root();
        match root.object_members() {
            SemanticAvailability::Available(Some(members)) => {
                counts.insert("json.object_members", members.len() as u64);
            }
            _ => match root.array_elements() {
                SemanticAvailability::Available(Some(elements)) => {
                    counts.insert("json.array_elements", elements.len() as u64);
                }
                SemanticAvailability::Available(None) => {
                    counts.insert("json.scalar_root", 1);
                }
                SemanticAvailability::Unavailable(_) => {}
            },
        }
    } else if let Ok(toml) = document.as_toml() {
        if let Some(entries) = toml.root().table_entries() {
            counts.insert("toml.entries", entries.len() as u64);
        }
    } else if let Ok(yaml) = document.as_yaml() {
        counts.insert("yaml.documents", yaml.document_count() as u64);
    } else if let Ok(xml) = document.as_xml() {
        counts.insert("xml.nodes", xml.nodes().len() as u64);
    } else if let Ok(plist) = document.as_plist() {
        if let Some(plist_document) = plist.document() {
            counts.insert("plist.nodes", plist_document.node_count() as u64);
        }
    } else if let Ok(hcl) = document.as_hcl() {
        counts.insert("hcl.body_items", hcl.document().body().items().len() as u64);
    }
    counts
}

/// One frozen `cli.*` diagnostic for a failure envelope.
fn cli_diagnostic(
    code: &'static str,
    category: DiagnosticCategory,
    message: String,
) -> DiagnosticMessage {
    let mut diagnostic = Diagnostic::new(code, category, DiagnosticSeverity::Error, None, 0);
    diagnostic.arguments.insert("message".to_owned(), message);
    DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v7())
        .expect("cli.* codes are registered v7 codes")
}

/// Deterministic stderr message of a failure diagnostic.
fn diagnostic_message(diagnostic: &DiagnosticMessage) -> String {
    diagnostic
        .arguments
        .get("message")
        .cloned()
        .unwrap_or_else(|| "see the envelope diagnostics".to_owned())
}

/// Reports an unclassified internal failure on stderr and returns exit 5.
fn internal_error(message: &str, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "consema: error: inspect: {message} (code cli.internal.unclassified@1)"
    );
    classify_error_code("cli.internal.unclassified@1").exit_code()
}

/// The always-present, always-empty v7 redaction record (redaction lands in
/// milestone M6; these commands carry no secret-shaped values).
fn no_redaction() -> Redaction {
    Redaction::new(false, 0).expect("redaction invariant redacted == (count > 0)")
}

/// Deterministic human inspect report; it draws from the same facade facts
/// as the machine payload (implementation plan §2.4).
fn write_human_report(
    path: &str,
    facts: &DetectFacts,
    symlink: bool,
    parse: Option<&PortableValue>,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut report = String::new();
    writeln!(report, "consema inspect {path}").expect("writing to String cannot fail");
    match facts.digest {
        Some(digest) => writeln!(
            report,
            "  bytes: {} bytes sha256:{}",
            facts.size,
            digest.to_hex()
        )
        .expect("writing to String cannot fail"),
        None => writeln!(report, "  bytes: {} bytes digest: unavailable", facts.size)
            .expect("writing to String cannot fail"),
    }
    let bom = match facts.bom {
        Some("Utf8") => "utf-8",
        Some("Utf16Le") => "utf-16-le",
        Some("Utf16Be") => "utf-16-be",
        Some(_) => unreachable!("closed BOM fact set"),
        None => "none",
    };
    writeln!(report, "  bom: {bom}").expect("writing to String cannot fail");
    writeln!(report, "  symlink: {}", if symlink { "yes" } else { "no" })
        .expect("writing to String cannot fail");
    let markers = if facts.markers.is_empty() {
        "none".to_owned()
    } else {
        facts.markers.join(", ")
    };
    writeln!(report, "  markers: {markers}").expect("writing to String cannot fail");
    let candidates = if facts.candidates.is_empty() {
        "none".to_owned()
    } else {
        facts
            .candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{}@{} ({})",
                    candidate.profile.id(),
                    candidate.profile.version(),
                    candidate.reason
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    writeln!(report, "  candidates: {candidates}").expect("writing to String cannot fail");
    let ambiguous = if facts.ambiguous {
        format!("yes: {}", facts.ambiguity_reasons.join("; "))
    } else {
        "no".to_owned()
    };
    writeln!(report, "  ambiguous: {ambiguous}").expect("writing to String cannot fail");
    if let Some(parse) = parse {
        write_human_parse(&mut report, parse);
    }
    stdout
        .write_all(report.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))
}

/// Appends the human parse-facts view (derived from the same record as the
/// machine view).
fn write_human_parse(report: &mut String, parse: &PortableValue) {
    use std::fmt::Write as _;
    let entries = parse.as_object().expect("cli.parse-facts@1 object");
    let mut profile = None;
    let mut formation = None;
    let mut diagnostics = Vec::new();
    let mut counts = Vec::new();
    for entry in entries {
        match entry.key() {
            "profile" => {
                let profile_entries = entry.value().as_object().expect("profile object");
                profile = Some(format!(
                    "{}@{}",
                    profile_entries[0].value().as_string().expect("profile id"),
                    profile_entries[1]
                        .value()
                        .as_integer()
                        .map(ToString::to_string)
                        .unwrap_or_default()
                ));
            }
            "formation_status" => {
                formation = entry.value().as_string().map(ToString::to_string);
            }
            "diagnostics" => {
                for item in entry.value().as_sequence().expect("diagnostics sequence") {
                    let object = item.as_object().expect("diagnostic object");
                    let mut code = None;
                    let mut message = None;
                    for field in object {
                        match field.key() {
                            "code" => {
                                code = field.value().as_string().map(ToString::to_string);
                            }
                            "arguments" => {
                                message = field
                                    .value()
                                    .as_object()
                                    .expect("arguments object")
                                    .iter()
                                    .find(|argument| argument.key() == "message")
                                    .map(|argument| {
                                        argument
                                            .value()
                                            .as_string()
                                            .expect("message string")
                                            .to_owned()
                                    });
                            }
                            _ => {}
                        }
                    }
                    if let Some(code) = code {
                        // Format-local codes bind under the registered
                        // fallback (B-9); the true code travels in the
                        // `message` argument and is rendered here.
                        match message {
                            Some(message) => diagnostics.push(format!("{code} ({message})")),
                            None => diagnostics.push(code),
                        }
                    }
                }
            }
            "structure_counts" => {
                for field in entry.value().as_object().expect("counts object") {
                    counts.push(format!(
                        "{}: {}",
                        field.key(),
                        field
                            .value()
                            .as_integer()
                            .map(ToString::to_string)
                            .unwrap_or_default()
                    ));
                }
            }
            _ => {}
        }
    }
    if let (Some(profile), Some(formation)) = (profile, formation) {
        writeln!(report, "  parse ({profile}): {formation}")
            .expect("writing to String cannot fail");
    }
    if diagnostics.is_empty() {
        report.push_str("    diagnostics: none\n");
    } else {
        writeln!(
            report,
            "    diagnostics: {}: {}",
            diagnostics.len(),
            diagnostics.join(", ")
        )
        .expect("writing to String cannot fail");
    }
    if counts.is_empty() {
        report.push_str("    structure counts: none\n");
    } else {
        writeln!(report, "    structure counts: {}", counts.join(", "))
            .expect("writing to String cannot fail");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn run(args: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        let parsed = crate::args::parse_args(&owned).expect("valid invocation");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = super::run(&parsed, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    fn temp_file(content: &[u8]) -> std::path::PathBuf {
        // The nonce keeps every call's path unique: several tests share
        // content lengths, and a shared path plus the trailing
        // remove_file() would race under the parallel test runner (one
        // test's cleanup deleting another test's in-flight fixture).
        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "consema-inspect-test-{}-{}-{}",
            std::process::id(),
            content.len(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, content).expect("write fixture");
        path
    }

    #[test]
    fn inspect_reports_file_facts_and_ambiguity_successfully() {
        let path = temp_file(b"[section]\nvalue=1\n");
        let (code, stdout, stderr) = run(&["inspect", path.to_str().unwrap()]);
        assert_eq!(code, 0, "ambiguity fact report is a complete result");
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("consema inspect"));
        assert!(text.contains("bytes: 18 bytes sha256:"));
        assert!(text.contains("bom: none"));
        assert!(text.contains("symlink: no"));
        assert!(text.contains("markers: [section] line"));
        assert!(text.contains("candidates:"));
        assert!(text.contains(
            "ambiguous: yes: [section] line is consistent with format families: ini, toml"
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_json_emits_the_frozen_payload_shape() {
        let path = temp_file(b"{\"a\":1}");
        let (code, stdout, stderr) = run(&["inspect", path.to_str().unwrap(), "--json"]);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid envelope");
        assert_eq!(envelope.command(), CliCommand::Inspect);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        let payload = envelope.payload();
        let entries = payload.as_object().expect("payload object");
        assert_eq!(entries[0].value().as_string(), Some("cli.inspect@1"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_unreadable_file_is_a_data_error_with_an_envelope() {
        let missing = std::env::temp_dir().join("consema-inspect-missing-0.12.0-file");
        let (code, stdout, stderr) = run(&["inspect", missing.to_str().unwrap(), "--json"]);
        assert_eq!(code, 2, "cli.data.io@1 classifies as data");
        assert!(!stdout.is_empty(), "data failures carry an envelope");
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid failure envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert_eq!(envelope.diagnostics()[0].code, "cli.data.io@1");
        assert!(stderr_text(&stderr).contains("(code cli.data.io@1)"));
    }

    #[test]
    fn inspect_unknown_profile_value_is_usage() {
        let path = temp_file(b"value=1\n");
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "example.unknown",
        ]);
        assert_eq!(code, 1, "invalid --format value is usage (RFC 0015 §5.1)");
        assert!(
            stdout.is_empty(),
            "usage failures never produce an envelope"
        );
        assert!(stderr_text(&stderr).contains("invalid --profile value"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_parse_facts_report_recovered_files_with_exit_zero() {
        // A line with a forbidden continuation is recovered, not fatal:
        // inspect must report the Recovered formation status and exit 0.
        let path = temp_file(b"[section]\nvalue=1\nbad line\n");
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "ini.portable",
        ]);
        assert_eq!(code, 0, "Recovered-state report is a complete result");
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("parse (ini.portable@1): Recovered"));
        assert!(text.contains("ini.sections: 1"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_xml_fatal_is_a_data_error_with_the_registered_fallback() {
        // A nesting-depth limit failure is a fatal parse with a format-local
        // code (`xml.limit.depth@1`, not registry-bound). B-9: inspect must
        // report the fatal fact (exit 2) with the registered fallback code in
        // the envelope and the true code on stderr — never an internal error.
        let path = temp_file(b"<a>".repeat(300).as_slice());
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "xml.1.0-safe",
            "--json",
        ]);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("xml.limit.depth@1"),
            "stderr keeps the true format-local code"
        );
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid failure envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert_eq!(
            envelope.diagnostics()[0].code,
            "core.source.invalid-sequence@1",
            "the envelope carries only registry-bound codes (RFC 0015 §4.3)"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_plist_fatal_is_a_data_error_with_the_registered_fallback() {
        let mut content = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>".to_vec();
        content.extend(b"<dict>".repeat(300));
        content.extend(b"</dict>".repeat(300));
        content.extend(b"</dict></plist>");
        let path = temp_file(&content);
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "plist.xml",
            "--json",
        ]);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("plist.limit.nesting-depth@1"));
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid failure envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert_eq!(
            envelope.diagnostics()[0].code,
            "core.source.invalid-sequence@1"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_hcl_fatal_is_a_data_error_with_the_registered_fallback() {
        let mut content = b"a = {".to_vec();
        content.extend(b"a = {".repeat(300));
        content.extend(b"}".repeat(301));
        let path = temp_file(&content);
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "hcl.native",
            "--json",
        ]);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("hcl.limit.expression-depth@1"));
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid failure envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert_eq!(
            envelope.diagnostics()[0].code,
            "core.source.invalid-sequence@1"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_recovered_format_local_diagnostics_report_with_fallback_binding() {
        // Recovered documents with format-local codes are complete reports
        // (exit 0); the parse-facts diagnostics carry the registered fallback
        // binding and the human view keeps the true code (B-9).
        let cases: &[(&[u8], &str, &str, &str)] = &[
            (
                b"<root>\n<item>x</item>\n</roott>\n",
                "xml.1.0-safe",
                "xml.tree.mismatched-end-tag@1",
                "xml.tree.mismatched-end-tag@1",
            ),
            (
                b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>a</key><integer>x</integer></dict></plist>",
                "plist.xml",
                "plist.parse.dict-missing-value@1",
                "plist.parse.dict-missing-value@1",
            ),
            (
                b"a = 1\nb {\n  c = 2\n",
                "hcl.native",
                "hcl.parse.block@1",
                "hcl.parse.block@1",
            ),
        ];
        for (bytes, profile, true_code, _) in cases {
            let path = temp_file(bytes);
            let (code, stdout, stderr) = run(&[
                "inspect",
                path.to_str().unwrap(),
                "--profile",
                *profile,
                "--json",
            ]);
            assert_eq!(code, 0, "{}", stderr_text(&stderr));
            assert!(stderr.is_empty(), "recovered reports write no stderr");
            let envelope =
                CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                    .expect("byte-valid envelope");
            assert_eq!(envelope.exit_class(), ExitClass::Success);
            let payload = envelope.payload();
            let parse = payload
                .as_object()
                .expect("payload object")
                .iter()
                .find(|entry| entry.key() == "parse")
                .expect("parse facts")
                .value()
                .as_object()
                .expect("parse facts object");
            let diagnostics = parse
                .iter()
                .find(|entry| entry.key() == "diagnostics")
                .expect("diagnostics")
                .value()
                .as_sequence()
                .expect("diagnostics sequence");
            assert!(!diagnostics.is_empty(), "recovery diagnostics are reported");
            // The human view renders the true code inside the fallback
            // binding (write_human_parse is the same record, no loss).
            let human = run(&["inspect", path.to_str().unwrap(), "--profile", *profile]);
            assert_eq!(human.0, 0, "{}", stderr_text(&human.2));
            let text = String::from_utf8_lossy(&human.1);
            assert!(
                text.contains(*true_code),
                "human view keeps the true format-local code {true_code}: {text}"
            );
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn inspect_ini_category_contradiction_recovery_binds_the_registry_category() {
        // The python-configparser profile recovers an entry before any
        // section with `ini.parse.missing-section@1` under the crate's Syntax
        // category, while the registry pins Conformance; the binding must
        // take the registry's category (B-9), keeping the true code.
        let path = temp_file(b"key=value\n");
        let (code, stdout, stderr) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--profile",
            "ini.python-configparser",
            "--json",
        ]);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        let payload = envelope.payload();
        let parse = payload
            .as_object()
            .expect("payload object")
            .iter()
            .find(|entry| entry.key() == "parse")
            .expect("parse facts")
            .value()
            .as_object()
            .expect("parse facts object");
        let diagnostics = parse
            .iter()
            .find(|entry| entry.key() == "diagnostics")
            .expect("diagnostics")
            .value()
            .as_sequence()
            .expect("diagnostics sequence");
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = diagnostics[0].as_object().expect("diagnostic object");
        let fields: Vec<_> = diagnostic.iter().collect();
        let code_field = fields
            .iter()
            .find(|entry| entry.key() == "code")
            .expect("code field");
        assert_eq!(
            code_field.value().as_string(),
            Some("ini.parse.missing-section@1"),
            "registered codes keep the true code in the envelope"
        );
        let category_field = fields
            .iter()
            .find(|entry| entry.key() == "category")
            .expect("category field");
        assert_eq!(
            category_field.value().as_string(),
            Some("Conformance"),
            "the registry descriptor's category wins over the crate's Syntax"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn inspect_limit_budget_is_a_limit_error() {
        let path = temp_file(b"value=1\n");
        let (code, stdout, _) = run(&[
            "inspect",
            path.to_str().unwrap(),
            "--json",
            "--max-bytes",
            "4",
        ]);
        assert_eq!(code, 3, "cli.limit.file-size@1 classifies as limit");
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("byte-valid limit envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Limit);
        assert_eq!(envelope.diagnostics()[0].code, "cli.limit.file-size@1");
        assert_eq!(
            envelope.diagnostics()[0].arguments["message"],
            format!(
                "'{}' exceeds the CLI read budget of 4 bytes (RFC 0015 §12); \
                 raise it with --max-bytes",
                path.to_str().unwrap()
            )
        );
        let _ = fs::remove_file(&path);
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }
}
