//! `consema query` and the shared strict request-input contract (RFC 0015 §3.2).
//!
//! All four request commands (query/project/materialize/convert) consume a
//! request document passed via `--request-file <path>` or stdin, accepted as
//! canonical tagged JSON or PVCE/1 (distinguished by the leading `PVCE`
//! magic, RFC 0015 §3.2) and strictly decoded. For query/project/materialize
//! the request is the CLI-local `cli.request@1` wrapper that carries the
//! source (a path or inline hex bytes), the profile, and the operation
//! payload; the convert command uses its own `cli.convert-request@1` record
//! (module docs of `convert_cmd.rs`; its source is the positional path).
//!
//! ```text
//! cli.request@1 (CLI-local, not registered; strict exact-fields decode):
//!   schema   String   "cli.request@1" (first field)
//!   source   { kind: "path", path: String } | { kind: "bytes", bytes: String }
//!   profile  { id: String, version: Integer } | absent
//!   payload  Object   the operation payload (schema checked per command:
//!                     core.query-definition@1 / core.projection-request@1 /
//!                     core.materialization-request@2)
//! ```
//!
//! The RFC payload records themselves (`core.query-definition@1` etc.) do
//! not carry the document, so the CLI wraps them; the wrapper is the
//! milestone-M5 answer to the M3 zero-positionals freeze — the request fully
//! describes the source, so the commands need no positionals (reported in
//! the M5 milestone report).
//!
//! # The query command flow
//!
//! parse the source under the request profile → bind the request's
//! [`QueryDefinition`] (consema-core query.rs) → execute on the default
//! portable projection of the document → emit the `core.query-result@1`
//! record of RFC 0015 §6.1 with matches in source order. Cardinality
//! failures (fail-not-null semantics, `RequireOne`) surface as data errors
//! with the failed completion carrying `core.query.cardinality-violation@1`.
//!
//! # Machine output and failure algebra
//!
//! Under `--json`, stdout carries exactly one canonical
//! `core.cli-output@1` line; human views render the same facade results.
//! Envelope-class failures (data/limit/precondition/internal) carry the
//! command record in its failed form plus diagnostics; usage-class failures
//! (RFC 0015 §4.2) never produce an envelope. Every error code maps through
//! `classify_error_code` (RFC 0015 §5.2) — the bin never invents classes.

use crate::args::ParsedArgs;
use consema::core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, Diagnostic, DiagnosticCategory,
    DiagnosticSeverity, ObjectBuilder, PortableValue, QueryDefinition, QueryDomain, QueryFailure,
    QueryLimits, StableFailure, ValuePath, ValuePathSegment,
};
use consema::document::{FatalFormationFailure, FormationStatus, ParseLimits, ProfileId};
use consema::protocol::{
    CliCommand, CliOutputMessage, Completion, CompletionStatus, DiagnosticMessage,
    ErrorCodeRegistry, ExitClass, ProtocolError, ProtocolLimits, QueryResultMessage, Redaction,
    classify_error_code, decode_json, decode_pvce,
};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::sync::Arc;

/// The CLI-local request wrapper schema shared by query/project/materialize.
pub(crate) const REQUEST_SCHEMA: &str = "cli.request@1";

/// The only query domain wired in this milestone (native domains need
/// caller-externalized node locators, which the facade does not expose yet).
pub(crate) const PORTABLE_QUERY_DOMAIN: &str = "core.portable-value-query";

/// One fully decoded strict request (`cli.request@1`).
pub(crate) struct RequestInput {
    /// User-supplied source label (the path spelling verbatim, or `inline`).
    pub(crate) source_label: String,
    /// Exact source bytes.
    pub(crate) source: Arc<[u8]>,
    /// Resolved source profile (id and registry version).
    pub(crate) profile: ProfileId,
    /// The operation payload (schema revalidated per command).
    pub(crate) payload: PortableValue,
}

/// One frozen failure of a request-command flow.
///
/// `code` is always a registered stable code (format-owned codes are passed
/// through unchanged); the exit class is derived exclusively through
/// [`classify_error_code`] (RFC 0015 §5.2). Envelope-class failures carry the
/// command record in its failed form when constructible (`payload`), plus
/// diagnostics; usage-class failures (`cli.usage.*`) never produce an
/// envelope (RFC 0015 §4.2).
pub(crate) struct FlowError {
    /// Stable registered diagnostic code.
    pub(crate) code: String,
    /// Deterministic human message (stderr line).
    pub(crate) message: String,
    /// Ordered envelope diagnostics.
    pub(crate) diagnostics: Vec<DiagnosticMessage>,
    /// Failed-form payload record; `None` falls back to the minimal
    /// `{schema}` record (un-decodable by typed decoders, carrying the
    /// failure in the envelope diagnostics only).
    pub(crate) payload: Option<PortableValue>,
}

impl FlowError {
    /// Creates a data-class failure with one registry-bound diagnostic.
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        let diagnostics = vec![diagnostic_for(&code, &message)];
        Self {
            code,
            message,
            diagnostics,
            payload: None,
        }
    }

    /// Creates a usage-class failure (never an envelope, RFC 0015 §4.2).
    pub(crate) fn usage(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            diagnostics: Vec::new(),
            payload: None,
        }
    }

    /// Attaches the failed-form payload record of the envelope.
    pub(crate) fn with_payload(mut self, payload: PortableValue) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Replaces the envelope diagnostics (the first document diagnostic
    /// determines the code; the full ordered set is carried in the envelope).
    pub(crate) fn with_diagnostics(mut self, diagnostics: Vec<DiagnosticMessage>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    /// Frozen exit class of the failure (RFC 0015 §5.2 pure mapping).
    pub(crate) fn exit_class(&self) -> ExitClass {
        classify_error_code(&self.code)
    }

    /// Frozen process exit code.
    pub(crate) fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }
}

/// The registered fallback code for format-local diagnostics that the
/// semantic-model registry does not carry (the envelope and the failed
/// completions can only carry registered codes; the stderr line keeps the
/// true format code, so no information is lost for humans).
const UNREGISTERED_CODE_FALLBACK: &str = "core.source.invalid-sequence@1";

/// Returns the code itself when it is registered in v7, else the registered
/// fallback (the envelope can only carry registry-bound codes, RFC 0015
/// §4.3; the XML/plist/HCL format-local parse families are not part of the
/// semantic-model registry).
pub(crate) fn registered_code(code: &str) -> &str {
    if ErrorCodeRegistry::v7().contains(code) {
        code
    } else {
        UNREGISTERED_CODE_FALLBACK
    }
}

/// Binds one core diagnostic to the semantic-model v7 registry.
///
/// The category is taken from the registry descriptor itself, so the bound
/// message can never contradict the registry (the typed decoder revalidates
/// exactly this). Unregistered format-local codes bind under the registered
/// fallback; the stderr line carries the true code.
pub(crate) fn diagnostic_for(code: &str, _message: &str) -> DiagnosticMessage {
    let code = registered_code(code);
    let category = ErrorCodeRegistry::v7()
        .descriptor(code)
        .map_or(DiagnosticCategory::Semantic, |descriptor| {
            descriptor.category
        });
    // The core Diagnostic carries no free-text message (only structured
    // facts); the human message travels on stderr, the code/category facts
    // travel in the envelope.
    let diagnostic = Diagnostic::new(code, category, DiagnosticSeverity::Error, None, 0);
    DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v7())
        .expect("registered code binds to its own descriptor category")
}

/// Reads the strict request input: `--request-file` content or stdin.
///
/// The request-input size cap is `cli.limit.manifest-size@1` (RFC 0015 §12);
/// a file that cannot be read is `cli.data.io@1`.
pub(crate) fn read_request_bytes(parsed: &ParsedArgs) -> Result<Vec<u8>, FlowError> {
    let cap = parsed
        .max_bytes
        .unwrap_or(u64::try_from(ProtocolLimits::default().max_bytes).expect("64 MiB fits u64"));
    if let Some(path) = &parsed.request_file {
        match read_capped(std::path::Path::new(path), cap) {
            Ok(bytes) => Ok(bytes),
            Err(ReadFailure::OverLimit) => Err(FlowError::new(
                "cli.limit.manifest-size@1",
                format!("request file '{path}' exceeds the {cap}-byte input cap"),
            )),
            Err(ReadFailure::Io(error)) => Err(FlowError::new(
                "cli.data.io@1",
                format!("cannot read request file '{path}': {error}"),
            )),
        }
    } else {
        let mut buffer = Vec::new();
        std::io::stdin()
            .lock()
            .take(cap.saturating_add(1))
            .read_to_end(&mut buffer)
            .map_err(|error| {
                FlowError::new(
                    "cli.data.io@1",
                    format!("cannot read request from stdin: {error}"),
                )
            })?;
        if u64::try_from(buffer.len()).expect("usize fits u64") > cap {
            return Err(FlowError::new(
                "cli.limit.manifest-size@1",
                format!("request input from stdin exceeds the {cap}-byte input cap"),
            ));
        }
        Ok(buffer)
    }
}

/// One bounded file read outcome.
enum ReadFailure {
    /// The file exceeds the caller's byte cap.
    OverLimit,
    /// The file could not be opened or read.
    Io(std::io::Error),
}

/// Reads at most `cap + 1` bytes of one file.
fn read_capped(path: &std::path::Path, cap: u64) -> Result<Vec<u8>, ReadFailure> {
    let file = std::fs::File::open(path).map_err(ReadFailure::Io)?;
    let mut buffer = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(ReadFailure::Io)?;
    if u64::try_from(buffer.len()).expect("usize fits u64") > cap {
        return Err(ReadFailure::OverLimit);
    }
    Ok(buffer)
}

/// Strictly decodes one `cli.request@1` wrapper and resolves its source.
///
/// The transport is chosen by magic (`PVCE` prefix -> PVCE/1, otherwise
/// strict canonical JSON, RFC 0015 §3.2). Unknown, reordered, or missing
/// wrapper fields, non-canonical representations, and malformed inline bytes
/// are all rejected (`cli.data.invalid-request@1`); transport
/// `ResourceLimit` is a limit-class failure (exit 3).
pub(crate) fn decode_request(
    bytes: &[u8],
    parsed: &ParsedArgs,
    payload_schema: &str,
) -> Result<RequestInput, FlowError> {
    let limits = ProtocolLimits::default();
    let value = if bytes.starts_with(b"PVCE") {
        decode_pvce(bytes, limits)
    } else {
        decode_json(bytes, limits)
    }
    .map_err(protocol_error)?;
    let entries = value.as_object().ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            "cli.request@1 must be an Object",
        )
    })?;
    if !matches!(entries.len(), 3 | 4) {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "cli.request@1 requires exactly schema/source[/profile]/payload",
        ));
    }
    if entries[0].key() != "schema" || entries[0].value().as_string() != Some(REQUEST_SCHEMA) {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "schema must be the first field with value \"cli.request@1\"",
        ));
    }
    if entries[1].key() != "source" {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "source must be the second field",
        ));
    }
    let (source_label, source) = decode_source(entries[1].value(), parsed)?;
    let (profile_entry, payload_entry) = if entries.len() == 3 {
        if entries[2].key() != "payload" {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                "payload must follow the source",
            ));
        }
        (None, Some(entries[2].value()))
    } else {
        if entries[2].key() != "profile" {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                "profile must follow the source",
            ));
        }
        if entries[3].key() != "payload" {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                "payload must be the last field",
            ));
        }
        (Some(entries[2].value()), Some(entries[3].value()))
    };
    let profile = resolve_profile(
        parsed
            .profile
            .as_deref()
            .expect("args.rs requires --profile for parse-class commands"),
    )?;
    if let Some(requested) = profile_entry {
        validate_request_profile(requested, &profile)?;
    }
    let payload = payload_entry.expect("one payload entry always present");
    if payload
        .as_object()
        .and_then(|fields| fields.first())
        .and_then(|first| first.value().as_string())
        != Some(payload_schema)
    {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!("payload schema must be \"{payload_schema}\""),
        ));
    }
    Ok(RequestInput {
        source_label,
        source,
        profile,
        payload: payload.clone(),
    })
}

/// Reads one source file with the CLI byte cap (RFC 0015 §12: over-cap is
/// `cli.limit.file-size@1`, unreadable is `cli.data.io@1`). Shared by the
/// request wrapper's path sources and the convert command's positional.
pub(crate) fn read_source_capped(path: &str, cap: u64) -> Result<Arc<[u8]>, FlowError> {
    match read_capped(std::path::Path::new(path), cap) {
        Ok(bytes) => Ok(Arc::from(bytes.as_slice())),
        Err(ReadFailure::OverLimit) => Err(FlowError::new(
            "cli.limit.file-size@1",
            format!("source file '{path}' exceeds the {cap}-byte read cap"),
        )),
        Err(ReadFailure::Io(error)) => Err(FlowError::new(
            "cli.data.io@1",
            format!("cannot read source file '{path}': {error}"),
        )),
    }
}

/// Decodes the `source` member: a path (read with the CLI read cap) or
/// inline lowercase-hex bytes.
fn decode_source(
    value: &PortableValue,
    parsed: &ParsedArgs,
) -> Result<(String, Arc<[u8]>), FlowError> {
    let entries = value
        .as_object()
        .ok_or_else(|| FlowError::new("cli.data.invalid-request@1", "source must be an Object"))?;
    if !matches!(entries.len(), 2) || entries[0].key() != "kind" {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "source requires exactly kind and one value field",
        ));
    }
    match entries[0].value().as_string() {
        Some("path") => {
            if entries[1].key() != "path" {
                return Err(FlowError::new(
                    "cli.data.invalid-request@1",
                    "path sources require the path field",
                ));
            }
            let path = entries[1]
                .value()
                .as_string()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    FlowError::new(
                        "cli.data.invalid-request@1",
                        "source path must be non-empty",
                    )
                })?;
            let cap = parsed
                .max_bytes
                .unwrap_or(u64::try_from(ProtocolLimits::default().max_bytes).expect("fits u64"));
            let bytes = read_source_capped(path, cap)?;
            Ok((path.to_owned(), bytes))
        }
        Some("bytes") => {
            if entries[1].key() != "bytes" {
                return Err(FlowError::new(
                    "cli.data.invalid-request@1",
                    "bytes sources require the bytes field",
                ));
            }
            let hex = entries[1].value().as_string().ok_or_else(|| {
                FlowError::new(
                    "cli.data.invalid-request@1",
                    "inline bytes must be a String",
                )
            })?;
            let bytes = decode_hex(hex).ok_or_else(|| {
                FlowError::new(
                    "cli.data.invalid-request@1",
                    "inline bytes must be even-length lowercase hex",
                )
            })?;
            Ok(("inline".to_owned(), Arc::from(bytes.as_slice())))
        }
        _ => Err(FlowError::new(
            "cli.data.invalid-request@1",
            "source kind must be \"path\" or \"bytes\"",
        )),
    }
}

/// Decodes even-length lowercase hex into bytes.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect()
}

/// Validates the optional request profile against the CLI `--profile`
/// selection and the registry version.
fn validate_request_profile(
    requested: &PortableValue,
    resolved: &ProfileId,
) -> Result<(), FlowError> {
    let entries = requested
        .as_object()
        .ok_or_else(|| FlowError::new("cli.data.invalid-request@1", "profile must be an Object"))?;
    if !matches!(entries.len(), 2) || entries[0].key() != "id" || entries[1].key() != "version" {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "profile requires exactly {id, version}",
        ));
    }
    let id = entries[0].value().as_string().ok_or_else(|| {
        FlowError::new("cli.data.invalid-request@1", "profile id must be a String")
    })?;
    if id != resolved.id() {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "request profile '{id}' contradicts the --profile selection '{}'",
                resolved.id()
            ),
        ));
    }
    let version = entries[1]
        .value()
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            FlowError::new(
                "cli.data.invalid-request@1",
                "profile version must be an Integer",
            )
        })?;
    if version != resolved.version() {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "request profile version {version} is not the published {}@{}",
                resolved.id(),
                resolved.version()
            ),
        ));
    }
    Ok(())
}

/// Resolves one profile id to its registry ProfileId through the facade
/// profile enums (the CLI declares no profile knowledge of its own). An
/// unknown id is a usage-class failure (`--format` invalid, RFC 0015 §5.1).
pub(crate) fn resolve_profile(id: &str) -> Result<ProfileId, FlowError> {
    let profile = match id {
        "json.strict" => consema::json::JsonProfile::StrictV1.id(),
        "jsonc.bounded" => consema::json::JsonProfile::JsoncBoundedV1.id(),
        "json5.standard" => consema::json::JsonProfile::Json5StandardV1.id(),
        "toml.1.0" => consema::toml::TomlProfile::Toml10V1.id(),
        "yaml.1.2-core" => consema::yaml::YamlProfile::Yaml12CoreV1.id(),
        "yaml.1.1-compat" => consema::yaml::YamlProfile::Yaml11CompatV1.id(),
        "ini.portable" => consema::ini::IniProfile::PortableV1.id(),
        "ini.windows" => consema::ini::IniProfile::WindowsV1.id(),
        "ini.python-configparser" => consema::ini::IniProfile::PythonConfigParserV1.id(),
        "java-properties.reader" => consema::properties::PropertiesProfile::ReaderV1.id(),
        "java-properties.latin1" => consema::properties::PropertiesProfile::Latin1V1.id(),
        "xml.1.0-safe" => consema::xml::XmlProfile::SafeV1.id(),
        "plist.xml" => consema::plist::PlistProfile::XmlV1.id(),
        "plist.binary" => consema::plist::PlistProfile::BinaryV1.id(),
        "hcl.native" => consema::hcl::HclProfile::NativeV1.id(),
        "hcl.tfvars" => consema::hcl::HclProfile::TfvarsV1.id(),
        _ => {
            return Err(FlowError::usage(
                "cli.usage.invalid-format@1",
                format!("unknown profile '{id}'"),
            ));
        }
    };
    Ok(profile)
}

/// Parses the resolved source bytes under the exact profile (facade only).
pub(crate) fn parse_document(
    source: Arc<[u8]>,
    profile: &ProfileId,
) -> Result<consema::Document, FlowError> {
    let result = match profile.id() {
        "json.strict" => consema::Document::parse_json(
            source,
            consema::json::JsonProfile::StrictV1,
            ParseLimits::default(),
        ),
        "jsonc.bounded" => consema::Document::parse_json(
            source,
            consema::json::JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        ),
        "json5.standard" => consema::Document::parse_json(
            source,
            consema::json::JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        ),
        "toml.1.0" => consema::Document::parse_toml(
            source,
            consema::toml::TomlProfile::Toml10V1,
            ParseLimits::default(),
        ),
        "yaml.1.2-core" => consema::Document::parse_yaml(
            source,
            consema::yaml::YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        ),
        "yaml.1.1-compat" => consema::Document::parse_yaml(
            source,
            consema::yaml::YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        ),
        "ini.portable" => consema::Document::parse_ini(
            source,
            consema::ini::IniProfile::PortableV1,
            consema::ini::IniEncodingSelection::ProfileDefault,
            consema::ini::IniParseLimits::default(),
        ),
        "ini.windows" => consema::Document::parse_ini(
            source,
            consema::ini::IniProfile::WindowsV1,
            consema::ini::IniEncodingSelection::ProfileDefault,
            consema::ini::IniParseLimits::default(),
        ),
        "ini.python-configparser" => consema::Document::parse_ini(
            source,
            consema::ini::IniProfile::PythonConfigParserV1,
            consema::ini::IniEncodingSelection::ProfileDefault,
            consema::ini::IniParseLimits::default(),
        ),
        "java-properties.reader" => consema::Document::parse_properties(
            source,
            consema::properties::PropertiesProfile::ReaderV1,
            consema::properties::PropertiesEncodingSelection::Reader(
                consema::document::SourceEncoding::Utf8,
            ),
            consema::properties::PropertiesParseLimits::default(),
        ),
        "java-properties.latin1" => consema::Document::parse_properties(
            source,
            consema::properties::PropertiesProfile::Latin1V1,
            consema::properties::PropertiesEncodingSelection::Latin1,
            consema::properties::PropertiesParseLimits::default(),
        ),
        "xml.1.0-safe" => consema::Document::parse_xml(
            source,
            consema::xml::XmlProfile::SafeV1,
            consema::xml::XmlEncodingSelection::ProfileDefault,
            consema::xml::XmlParseLimits::default(),
        ),
        "plist.xml" => consema::Document::parse_plist(
            source,
            consema::plist::PlistProfile::XmlV1,
            consema::plist::PlistEncodingSelection::ProfileDefault,
            consema::plist::PlistParseLimits::default(),
        ),
        "plist.binary" => consema::Document::parse_plist(
            source,
            consema::plist::PlistProfile::BinaryV1,
            consema::plist::PlistEncodingSelection::ProfileDefault,
            consema::plist::PlistParseLimits::default(),
        ),
        "hcl.native" => consema::Document::parse_hcl(
            source,
            consema::hcl::HclProfile::NativeV1,
            consema::hcl::HclEncodingSelection::ProfileDefault,
            consema::hcl::HclParseLimits::default(),
        ),
        "hcl.tfvars" => consema::Document::parse_hcl(
            source,
            consema::hcl::HclProfile::TfvarsV1,
            consema::hcl::HclEncodingSelection::ProfileDefault,
            consema::hcl::HclParseLimits::default(),
        ),
        other => {
            return Err(FlowError::usage(
                "cli.usage.invalid-format@1",
                format!("profile '{other}' is not a parseable source profile"),
            ));
        }
    };
    result.map_err(formation_failure)
}

/// Maps a fatal formation failure to a data-class failure carrying the
/// format's own stable diagnostic codes.
fn formation_failure(failure: FatalFormationFailure) -> FlowError {
    let diagnostics = failure.diagnostics();
    let code = diagnostics.first().map_or_else(
        || "core.source.invalid-utf8@1".to_owned(),
        |diagnostic| diagnostic.code.clone(),
    );
    let message = format!("source failed formation ({code})");
    FlowError::new(code, message).with_diagnostics(bind_diagnostics(diagnostics, None))
}

/// Binds core diagnostics to registry messages under one source label.
pub(crate) fn bind_diagnostics(
    diagnostics: &[Diagnostic],
    source_label: Option<&str>,
) -> Vec<DiagnosticMessage> {
    diagnostics
        .iter()
        .filter_map(|diagnostic| {
            DiagnosticMessage::from_core_with_registry(
                diagnostic,
                source_label,
                ErrorCodeRegistry::v7(),
            )
            .ok()
        })
        .collect()
}

/// Rejects Recovered documents for parse-class operations (RFC 0015 §5.1:
/// `consema query` exits 2 on input that cannot form a Complete document;
/// Recovered documents never project, IMPLEMENTATION.md line 224).
pub(crate) fn require_complete(
    document: &consema::Document,
    source_label: &str,
) -> Result<(), FlowError> {
    if document.formation_status() == FormationStatus::Complete {
        return Ok(());
    }
    let diagnostics = document.diagnostics();
    let code = diagnostics.first().map_or_else(
        || "core.source.invalid-utf8@1".to_owned(),
        |diagnostic| diagnostic.code.clone(),
    );
    Err(FlowError::new(
        code,
        format!("source '{source_label}' is Recovered; the operation requires a Complete document"),
    )
    .with_diagnostics(bind_diagnostics(diagnostics, Some(source_label))))
}

/// Maps a request transport failure per RFC 0015 §3.2: a request that fails
/// strict decode is a data error with `cli.data.invalid-request@1`, except
/// decode `ResourceLimit`, which is a limit error (exit 3).
pub(crate) fn protocol_error(error: ProtocolError) -> FlowError {
    if error.kind() == consema::protocol::ProtocolErrorKind::ResourceLimit {
        return FlowError::new(
            "core.protocol.resource-limit@1",
            format!("request transport decode exceeded a protocol limit: {error}"),
        );
    }
    FlowError::new(
        "cli.data.invalid-request@1",
        format!("request transport decode failed: {error}"),
    )
}

/// Maps one core `StableFailure` to its data-class failure.
pub(crate) fn stable_failure(failure: &impl StableFailure, message: String) -> FlowError {
    let code = failure.diagnostic_code();
    FlowError::new(code, message)
}

/// The typed per-format projection request of the request commands.
pub(crate) enum WireProjectionRequest {
    /// JSON projection request.
    Json(consema::json::ProjectionRequest),
    /// TOML projection request.
    Toml(consema::toml::ProjectionRequest),
    /// INI projection request.
    Ini(consema::ini::ProjectionRequest),
    /// Java Properties projection request.
    Properties(consema::properties::ProjectionRequest),
    /// YAML value projection request.
    Yaml(consema::yaml::ValueProjectionRequest),
    /// XML projection request.
    Xml(consema::xml::ProjectionRequest),
    /// Property List projection request.
    Plist(consema::plist::ProjectionRequest),
    /// HCL projection request.
    Hcl(consema::hcl::ProjectionRequest),
}

/// The default exact projection request of each format family.
///
/// These are the SDK's conservative exact defaults (duplicates rejected, no
/// authorized loss); the request commands never invent policies (roadmap §10
/// line 818). The record formats' defaults publish their versioned internal
/// records, consumed only by the owning family's materializer.
pub(crate) fn default_projection_request(family: &str) -> Result<WireProjectionRequest, FlowError> {
    match family {
        "json" => Ok(WireProjectionRequest::Json(
            consema::json::ProjectionRequestBuilder::new(
                consema::json::ProjectionTarget::BestExactCoreV1,
            )
            .build()
            .map_err(|failure| {
                stable_failure(
                    &failure,
                    "JSON default projection request is invalid".to_owned(),
                )
            })?,
        )),
        "toml" => Ok(WireProjectionRequest::Toml(
            consema::toml::ProjectionRequest::new(consema::toml::ProjectionTarget::BestExactCoreV1),
        )),
        "ini" => Ok(WireProjectionRequest::Ini(
            consema::ini::ProjectionRequest::best_exact_entry_mapping(),
        )),
        "properties" => Ok(WireProjectionRequest::Properties(
            consema::properties::ProjectionRequest::best_exact_entry_mapping(),
        )),
        "yaml" => Ok(WireProjectionRequest::Yaml(
            consema::yaml::ValueProjectionRequest::best_exact_v1(),
        )),
        "xml" => Ok(WireProjectionRequest::Xml(
            consema::xml::ProjectionRequest::element_tree(),
        )),
        "plist" => Ok(WireProjectionRequest::Plist(
            consema::plist::ProjectionRequest::value_tree(),
        )),
        "hcl" => Ok(WireProjectionRequest::Hcl(
            consema::hcl::ProjectionRequest::body(),
        )),
        _ => Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!("no default projection for format family '{family}'"),
        )),
    }
}

/// Projects one document under its format request, returning the value.
///
/// Format projection failures keep the format's own stable codes (the
/// Recovered-document rejection is SDK semantics: Recovered documents never
/// project).
pub(crate) fn project_value(
    document: &consema::Document,
    request: WireProjectionRequest,
) -> Result<PortableValue, FlowError> {
    match request {
        WireProjectionRequest::Json(request) => {
            let document = document.as_json().map_err(|_| format_mismatch("json"))?;
            match document.project(&request) {
                consema::json::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::json::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "JSON projection failed",
                )),
            }
        }
        WireProjectionRequest::Toml(request) => {
            let document = document.as_toml().map_err(|_| format_mismatch("toml"))?;
            match document.project(request) {
                consema::toml::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::toml::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "TOML projection failed",
                )),
            }
        }
        WireProjectionRequest::Ini(request) => {
            let document = document.as_ini().map_err(|_| format_mismatch("ini"))?;
            match document.project(request) {
                consema::ini::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::ini::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "INI projection failed",
                )),
            }
        }
        WireProjectionRequest::Properties(request) => {
            let document = document
                .as_properties()
                .map_err(|_| format_mismatch("java-properties"))?;
            match document.project(request) {
                consema::properties::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::properties::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "Properties projection failed",
                )),
            }
        }
        WireProjectionRequest::Yaml(request) => {
            let document = document.as_yaml().map_err(|_| format_mismatch("yaml"))?;
            match document.project_value(request) {
                consema::yaml::ValueProjectionResult::Complete(projection) => Ok(projection.value),
                consema::yaml::ValueProjectionResult::Failed(failure) => Err(stable_failure(
                    &failure,
                    "YAML value projection failed".to_owned(),
                )),
            }
        }
        WireProjectionRequest::Xml(request) => {
            let document = document.as_xml().map_err(|_| format_mismatch("xml"))?;
            match document.project(request) {
                consema::xml::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::xml::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "XML projection failed",
                )),
            }
        }
        WireProjectionRequest::Plist(request) => {
            let document = document.as_plist().map_err(|_| format_mismatch("plist"))?;
            match consema::plist::project(document, request) {
                consema::plist::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::plist::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "plist projection failed",
                )),
            }
        }
        WireProjectionRequest::Hcl(request) => {
            let document = document.as_hcl().map_err(|_| format_mismatch("hcl"))?;
            match consema::hcl::project(document, request) {
                consema::hcl::ProjectionResult::Complete(projection) => Ok(projection.value),
                consema::hcl::ProjectionResult::Failed(failure) => Err(attempt_failure(
                    &failure.diagnostics,
                    "HCL projection failed",
                )),
            }
        }
    }
}

fn format_mismatch(format: &str) -> FlowError {
    FlowError::new(
        "cli.internal.unclassified@1",
        format!("the parsed document is not a {format} document (facade adapter mismatch)"),
    )
}

/// Fails a projection attempt with the first diagnostic's stable code.
fn attempt_failure(diagnostics: &[Diagnostic], fallback: &str) -> FlowError {
    let code = diagnostics
        .first()
        .map_or("core.projection.target-not-applicable@1", |diagnostic| {
            diagnostic.code.as_str()
        });
    FlowError::new(code, fallback).with_diagnostics(bind_diagnostics(diagnostics, None))
}

/// The format family of one profile id (mirrors the facade's conversion
/// composition; the family decides the projection/materialization dispatch).
pub(crate) fn format_family(profile_id: &str) -> Option<&'static str> {
    match profile_id {
        "json.strict" | "jsonc.bounded" | "json5.standard" => Some("json"),
        "toml.1.0" => Some("toml"),
        "yaml.1.2-core" | "yaml.1.1-compat" => Some("yaml"),
        "ini.portable" | "ini.windows" | "ini.python-configparser" => Some("ini"),
        "java-properties.reader" | "java-properties.latin1" => Some("properties"),
        "xml.1.0-safe" => Some("xml"),
        "plist.xml" | "plist.binary" => Some("plist"),
        "hcl.native" | "hcl.tfvars" => Some("hcl"),
        _ => None,
    }
}

/// The published record envelope ids of the record-format projections (the
/// materialize command re-checks the facade's record-consumption gate,
/// conversion.rs, because the facade gate is private to the lib).
pub(crate) fn published_record(value: &PortableValue) -> Option<&'static str> {
    let object = value.as_object()?;
    let record = object.iter().find(|entry| entry.key() == "record")?;
    let id = record.value().as_string()?;
    match id {
        "xml.element-tree@1" => Some("xml"),
        "plist.value-tree@1" => Some("plist"),
        "hcl.body@1" => Some("hcl"),
        _ => None,
    }
}

/// Emits one validated `core.cli-output@1` envelope line (RFC 0015 §4).
pub(crate) fn emit_envelope(
    command: CliCommand,
    exit_class: ExitClass,
    payload: PortableValue,
    diagnostics: Vec<DiagnosticMessage>,
    parsed: &ParsedArgs,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    let envelope = CliOutputMessage::new(
        command,
        exit_class,
        crate::PRODUCT_VERSION,
        payload,
        diagnostics,
        Redaction::new(false, 0).expect("redaction invariant redacted == (count > 0)"),
    )
    .map_err(|error| format!("{} envelope construction failed: {error}", command.name()))?;
    crate::output::emit_envelope(&envelope, parsed.pretty, stdout)
        .map_err(|error| error.message().to_owned())
}

/// Writes the minimal `{schema}` failure record of one command (the envelope
/// carries the failure in its diagnostics; typed decoders reject the partial
/// record, which is the truthful statement that no complete result exists).
pub(crate) fn minimal_record(command: CliCommand) -> PortableValue {
    let mut record = ObjectBuilder::new();
    record
        .insert(
            "schema",
            PortableValue::string(
                *command
                    .payload_schemas()
                    .first()
                    .expect("every command publishes at least one payload schema"),
            ),
        )
        .expect("unique key");
    record.build()
}

/// Emits the failure path of one request command: usage-class failures write
/// only a stderr line (no envelope, RFC 0015 §4.2); envelope-class failures
/// write the envelope with the failed record form plus diagnostics, then the
/// stderr line, and exit with the classified code.
pub(crate) fn emit_failure(
    command: CliCommand,
    parsed: &ParsedArgs,
    error: &FlowError,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let _ = writeln!(
        stderr,
        "consema: error: {}: {} (code {})",
        command.name(),
        error.message,
        error.code
    );
    if error.exit_class() == ExitClass::Usage {
        return error.exit_code();
    }
    let payload = error
        .payload
        .clone()
        .unwrap_or_else(|| minimal_record(command));
    match emit_envelope(
        command,
        error.exit_class(),
        payload,
        error.diagnostics.clone(),
        parsed,
        stdout,
    ) {
        Ok(()) => error.exit_code(),
        Err(message) => internal_failure(command.name(), &message, stderr),
    }
}

/// Reports an unclassified internal failure on stderr and returns exit 5
/// (RFC 0015 §5.1 internal row).
pub(crate) fn internal_failure(command: &str, message: &str, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "consema: error: {command}: {message} (code cli.internal.unclassified@1)"
    );
    classify_error_code("cli.internal.unclassified@1").exit_code()
}

/// Runs `consema query` (request from `--request-file` or stdin).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Query, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, stdout, stderr)
}

/// Runs `consema query` against already-read request bytes (testable without
/// stdin or fixture files).
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let input = match decode_request(request, parsed, "core.query-definition@1") {
        Ok(input) => input,
        Err(error) => return emit_failure(CliCommand::Query, parsed, &error, stdout, stderr),
    };
    match execute_query(&input) {
        Ok(result) => {
            if parsed.json {
                match emit_envelope(
                    CliCommand::Query,
                    ExitClass::Success,
                    result.to_value(),
                    Vec::new(),
                    parsed,
                    stdout,
                ) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("query", &message, stderr),
                }
            } else {
                match write_query_report(&result, stdout) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("query", &message, stderr),
                }
            }
        }
        Err(error) => emit_failure(CliCommand::Query, parsed, &error, stdout, stderr),
    }
}

/// Executes the request's query definition against the document's default
/// portable projection, returning the `core.query-result@1` message with
/// matches in source order.
fn execute_query(input: &RequestInput) -> Result<QueryResultMessage, FlowError> {
    let definition = QueryDefinition::from_protocol_value(&input.payload)
        .map_err(|failure| query_failure(&failure, "the query definition is invalid"))?;
    let domain = definition.domain().clone();
    if domain.id() != PORTABLE_QUERY_DOMAIN || domain.version() != 1 {
        return Err(query_failure(
            &consema::core::QueryFailure::DomainMismatch(domain.clone()),
            &format!(
                "query domain '{}{}' is not wired in this milestone; only {PORTABLE_QUERY_DOMAIN}@1 \
                 is supported (native domains need caller-externalized node locators, which the \
                 facade does not yet expose)",
                domain.id(),
                domain.version()
            ),
        ));
    }
    let document = parse_document(input.source.clone(), &input.profile)?;
    require_complete(&document, &input.source_label)?;
    let family = format_family(input.profile.id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("profile '{}' has no format family", input.profile.id()),
        )
    })?;
    if matches!(family, "xml" | "plist" | "hcl") {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "the {PORTABLE_QUERY_DOMAIN}@1 domain cannot query {family} sources: their \
                 default projection publishes a versioned internal record (the native query \
                 domains require caller locators not yet exposed by the facade)"
            ),
        ));
    }
    let value = project_value(&document, default_projection_request(family)?)?;
    let validated = definition
        .validate()
        .map_err(|failure| query_failure(&failure, "the query definition failed validation"))?;
    let role = validated.output_role();
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let executable = validated.bind(&capabilities).map_err(|failure| {
        query_failure(&failure, "the query definition could not bind capabilities")
    })?;
    let execution = executable
        .execute_portable(&value, QueryLimits::default(), &CancellationToken::new())
        .map_err(|failure| query_failure(&failure, "the query execution failed"))?;
    QueryResultMessage::from_portable_execution(domain.clone(), role, &execution).map_err(|error| {
        FlowError::new(
            error.kind().code(),
            format!("query result encoding failed: {error}"),
        )
    })
}

/// Maps one query failure to a data/limit-class failure carrying the failed
/// `core.query-result@1` record (completion Failed with the stable code).
fn query_failure(failure: &QueryFailure, message: &str) -> FlowError {
    let code = failure.diagnostic_code();
    let payload = failed_query_result(code).unwrap_or_else(|| minimal_record(CliCommand::Query));
    FlowError::new(code, format!("{message} ({code})")).with_payload(payload)
}

/// The failed `core.query-result@1` record form: zero matches, completion
/// Failed with the stable code, the code diagnostic attached.
fn failed_query_result(code: &str) -> Option<PortableValue> {
    let completion = Completion::new_with_registry(
        CompletionStatus::Failed,
        0,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v7(),
    )
    .ok()?;
    QueryResultMessage::new(
        QueryDomain::portable_value_v1(),
        consema::core::MatchRole::Value,
        Vec::new(),
        completion,
        Vec::new(),
    )
    .ok()
    .map(|message| message.to_value())
}

/// Deterministic human query report (same facade result as the machine
/// payload; RFC 0015 §2.1 human/machine draw from the same call).
fn write_query_report(result: &QueryResultMessage, stdout: &mut dyn Write) -> Result<(), String> {
    let matches = result.matches();
    if matches.is_empty() {
        return writeln!(stdout, "no matches").map_err(io_message);
    }
    for (index, item) in matches.iter().enumerate() {
        let line = match item {
            consema::protocol::ProtocolQueryMatch::Portable(
                consema::core::PortableMatch::Value { path, value },
            ) => format!(
                "match {index}: {} = {}",
                render_path(path),
                render_value(value)
            ),
            consema::protocol::ProtocolQueryMatch::Portable(
                consema::core::PortableMatch::ObjectEntry {
                    key,
                    value_path,
                    value,
                    ..
                },
            ) => format!(
                "match {index}: {} (key {key}) = {}",
                render_path(value_path),
                render_value(value)
            ),
            consema::protocol::ProtocolQueryMatch::Portable(
                consema::core::PortableMatch::EntryMappingEntry {
                    key,
                    value_path,
                    value,
                    ..
                },
            ) => format!(
                "match {index}: {} (key {key:?}) = {}",
                render_path(value_path),
                render_value(value)
            ),
            consema::protocol::ProtocolQueryMatch::Native(locator) => format!(
                "match {index}: native {} {}",
                locator.node_locator(),
                render_role(locator.role())
            ),
        };
        writeln!(stdout, "{line}").map_err(io_message)?;
    }
    Ok(())
}

fn render_role(role: consema::core::MatchRole) -> &'static str {
    match role {
        consema::core::MatchRole::Value => "Value",
        consema::core::MatchRole::ObjectEntry => "ObjectEntry",
        consema::core::MatchRole::EntryMappingEntry => "EntryMappingEntry",
        _ => "native",
    }
}

/// Compact deterministic path spelling (`$`, `.key`, `[0]`).
pub(crate) fn render_path(path: &ValuePath) -> String {
    let mut out = String::from("$");
    for segment in path.segments() {
        match segment {
            ValuePathSegment::ObjectValue(key) => {
                out.push('.');
                out.push_str(key);
            }
            ValuePathSegment::SequenceElement(index) => {
                let _ = write!(out, "[{index}]");
            }
            ValuePathSegment::EntryKey(index) => {
                let _ = write!(out, "[key {index}]");
            }
            ValuePathSegment::EntryValue(index) => {
                let _ = write!(out, "[value {index}]");
            }
        }
    }
    out
}

/// Deterministic human rendering of a PortableValue (single-line, stable).
pub(crate) fn render_value(value: &PortableValue) -> String {
    match value.kind() {
        consema::core::PortableValueKind::Null => "null".to_owned(),
        consema::core::PortableValueKind::Boolean => {
            format!("{}", value.as_boolean().expect("kind matches"))
        }
        consema::core::PortableValueKind::Integer => {
            format!("{}", value.as_integer().expect("kind matches"))
        }
        consema::core::PortableValueKind::Decimal => {
            format!("{:?}", value.as_decimal().expect("kind matches"))
        }
        consema::core::PortableValueKind::String => {
            format!(
                "\"{}\"",
                escape_text(value.as_string().expect("kind matches"))
            )
        }
        consema::core::PortableValueKind::Bytes => format!(
            "b\"{}\"",
            value
                .as_bytes()
                .expect("kind matches")
                .iter()
                .fold(String::new(), |mut text, byte| {
                    let _ = write!(text, "{byte:02x}");
                    text
                })
        ),
        consema::core::PortableValueKind::Sequence => {
            let items = value.as_sequence().expect("kind matches");
            format!(
                "[{}]",
                items
                    .iter()
                    .map(render_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        consema::core::PortableValueKind::Object => {
            let entries = value.as_object().expect("kind matches");
            format!(
                "{{{}}}",
                entries
                    .iter()
                    .map(|entry| format!(
                        "{}: {}",
                        escape_text(entry.key()),
                        render_value(entry.value())
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        consema::core::PortableValueKind::EntryMapping => {
            let entries = value.as_entry_mapping().expect("kind matches");
            format!(
                "{{{}:}}",
                entries
                    .iter()
                    .map(|entry| format!(
                        "{}: {}",
                        render_value(entry.key()),
                        render_value(entry.value())
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        // Exotic kinds (binary floats, dates, times) render through their
        // deterministic Debug spelling; no information is invented.
        other => format!("{other:?}({value:?})"),
    }
}

/// Escapes one text for the human view (quotes, backslashes, controls).
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

fn io_message(error: std::io::Error) -> String {
    format!("stdout write failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::protocol::{ProtocolQueryMatch, encode_json};

    fn parse(args: &[&str]) -> ParsedArgs {
        crate::args::parse_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("valid invocation")
    }

    fn run_request(args: &[&str], request: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let parsed = parse(args);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, request, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    /// Builds one strict request value (wrapper + query payload).
    fn request_value(
        source_hex: &str,
        selection: &str,
        expression: PortableValue,
    ) -> PortableValue {
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("core.query-definition@1"))
            .expect("unique");
        payload
            .insert("domain_id", PortableValue::string(PORTABLE_QUERY_DOMAIN))
            .expect("unique");
        payload
            .insert(
                "domain_version",
                PortableValue::integer(BigInteger::from(1)),
            )
            .expect("unique");
        payload
            .insert("selection", PortableValue::string(selection))
            .expect("unique");
        payload.insert("expression", expression).expect("unique");
        let mut source = ObjectBuilder::new();
        source
            .insert("kind", PortableValue::string("bytes"))
            .expect("unique");
        source
            .insert("bytes", PortableValue::string(source_hex))
            .expect("unique");
        let mut profile = ObjectBuilder::new();
        profile
            .insert("id", PortableValue::string("json.strict"))
            .expect("unique");
        profile
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert("schema", PortableValue::string(REQUEST_SCHEMA))
            .expect("unique");
        wrapper.insert("source", source.build()).expect("unique");
        wrapper.insert("profile", profile.build()).expect("unique");
        wrapper.insert("payload", payload.build()).expect("unique");
        wrapper.build()
    }

    fn input_expression() -> PortableValue {
        let mut input = ObjectBuilder::new();
        input
            .insert("kind", PortableValue::string("Input"))
            .expect("unique");
        input.build()
    }

    fn sequence_elements_expression() -> PortableValue {
        let arguments = ObjectBuilder::new();
        let mut operator = ObjectBuilder::new();
        operator
            .insert("id", PortableValue::string("core.try-sequence-elements"))
            .expect("unique");
        operator
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        operator
            .insert("arguments", arguments.build())
            .expect("unique");
        let mut apply = ObjectBuilder::new();
        apply
            .insert("kind", PortableValue::string("Apply"))
            .expect("unique");
        apply.insert("input", input_expression()).expect("unique");
        apply.insert("operator", operator.build()).expect("unique");
        apply.build()
    }

    fn request_json(source_hex: &str, expression: PortableValue) -> Vec<u8> {
        encode_json(
            &request_value(source_hex, "All", expression),
            ProtocolLimits::default(),
        )
        .expect("canonical request bytes")
    }

    /// The SDK-side envelope the CLI must byte-match (machine-output
    /// byte-equality gate, implementation plan §10 R-8).
    fn sdk_envelope(expected: &QueryResultMessage) -> Vec<u8> {
        CliOutputMessage::new(
            CliCommand::Query,
            ExitClass::Success,
            crate::PRODUCT_VERSION,
            expected.to_value(),
            Vec::new(),
            Redaction::new(false, 0).expect("invariant"),
        )
        .expect("valid envelope")
        .to_json(ProtocolLimits::default())
        .expect("canonical bytes")
    }

    #[test]
    fn query_json_success_round_trips_and_matches_sdk_bytes() {
        // Source `[1,2,3]` under `core.try-sequence-elements`: three value
        // matches in source order.
        let args = &["query", "--profile", "json.strict", "--json"];
        let (code, stdout, stderr) = run_request(
            args,
            &request_json("5b312c322c335d", sequence_elements_expression()),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        assert!(!stdout[..stdout.len() - 1].contains(&b'\n'));
        let limits = ProtocolLimits::default();
        let envelope_bytes = &stdout[..stdout.len() - 1];
        let envelope =
            CliOutputMessage::from_json(envelope_bytes, limits).expect("byte-valid envelope");
        assert_eq!(envelope.command(), CliCommand::Query);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        // Byte-determinism: re-encoding reproduces the stdout bytes.
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            envelope_bytes,
            "stdout envelope must be byte-deterministic"
        );
        // The payload decodes through the typed decoder (round-trip gate).
        let result =
            QueryResultMessage::from_value(envelope.payload()).expect("query-result record");
        assert_eq!(result.completion().status(), CompletionStatus::Success);
        assert_eq!(result.matches().len(), 3);
        // Source-order assertion: paths `[0]`, `[1]`, `[2]` with values 1,2,3.
        let paths: Vec<String> = result
            .matches()
            .iter()
            .map(|item| match item {
                ProtocolQueryMatch::Portable(consema::core::PortableMatch::Value {
                    path, ..
                }) => render_path(path),
                other => panic!("unexpected match kind {other:?}"),
            })
            .collect();
        assert_eq!(paths, vec!["$[0]", "$[1]", "$[2]"]);
        let values: Vec<Option<String>> = result
            .matches()
            .iter()
            .map(|item| match item {
                ProtocolQueryMatch::Portable(consema::core::PortableMatch::Value {
                    value, ..
                }) => Some(render_value(value)),
                _ => None,
            })
            .collect();
        assert_eq!(
            values,
            vec![
                Some("1".to_owned()),
                Some("2".to_owned()),
                Some("3".to_owned())
            ]
        );
        // Machine-output byte equality with the SDK encode of the same
        // operation (implementation plan §11 item 2).
        assert_eq!(envelope_bytes, sdk_envelope(&result));
    }

    #[test]
    fn query_object_entries_keep_document_order() {
        // `{"a":1,"b":2}` under Input.then(core.try-object-entries): object
        // entries in source order a then b.
        let mut operator = ObjectBuilder::new();
        operator
            .insert("id", PortableValue::string("core.try-object-entries"))
            .expect("unique");
        operator
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        operator
            .insert("arguments", ObjectBuilder::new().build())
            .expect("unique");
        let mut apply = ObjectBuilder::new();
        apply
            .insert("kind", PortableValue::string("Apply"))
            .expect("unique");
        apply.insert("input", input_expression()).expect("unique");
        apply.insert("operator", operator.build()).expect("unique");
        let (code, stdout, _) = run_request(
            &["query", "--profile", "json.strict", "--json"],
            &request_json("7b2261223a312c2262223a327d", apply.build()),
        );
        assert_eq!(code, 0);
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        let result = QueryResultMessage::from_value(envelope.payload()).expect("record");
        let keys: Vec<String> = result
            .matches()
            .iter()
            .map(|item| match item {
                ProtocolQueryMatch::Portable(consema::core::PortableMatch::ObjectEntry {
                    key,
                    ..
                }) => key.clone(),
                other => panic!("unexpected match {other:?}"),
            })
            .collect();
        assert_eq!(keys, vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn query_require_one_fail_not_null_is_a_data_error() {
        // Selection RequireOne on `[1,2,3]` (three matches) violates the
        // cardinality selector: data error with the failed completion.
        let value = request_value(
            "5b312c322c335d",
            "RequireOne",
            sequence_elements_expression(),
        );
        let request = encode_json(&value, ProtocolLimits::default()).expect("bytes");
        let (code, stdout, stderr) =
            run_request(&["query", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("core.query.cardinality-violation@1"));
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        let result = QueryResultMessage::from_value(envelope.payload()).expect("failed record");
        assert_eq!(result.completion().status(), CompletionStatus::Failed);
        assert_eq!(
            result.completion().failure_code(),
            Some("core.query.cardinality-violation@1")
        );
        assert!(result.matches().is_empty());
    }

    #[test]
    fn query_unknown_profile_is_usage_exit_one_without_envelope() {
        let (code, stdout, stderr) = run_request(
            &["query", "--profile", "json.bogus", "--json"],
            &request_json("5b312c322c335d", sequence_elements_expression()),
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "usage failures never emit an envelope");
        assert!(stderr_text(&stderr).contains("unknown profile 'json.bogus'"));
    }

    #[test]
    fn query_request_transport_and_wrapper_negatives_are_rejected() {
        // PVCE transport is accepted.
        let value = request_value("5b312c322c335d", "All", sequence_elements_expression());
        let pvce = consema::protocol::encode_pvce(&value, ProtocolLimits::default()).expect("pvce");
        let (code, stdout, _) =
            run_request(&["query", "--profile", "json.strict", "--json"], &pvce);
        assert_eq!(code, 0, "PVCE request input must decode");
        let limits = ProtocolLimits::default();
        let envelope = CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits)
            .expect("envelope from PVCE-driven run");
        assert_eq!(envelope.exit_class(), ExitClass::Success);

        // Malformed bytes (not canonical JSON, not PVCE) -> data error.
        let (code, _, stderr) = run_request(
            &["query", "--profile", "json.strict", "--json"],
            b"not-a-request",
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));

        // Unknown wrapper field -> rejected.
        let mut wrapper = request_value("5b312c322c335d", "All", sequence_elements_expression());
        let mut entries = ObjectBuilder::new();
        for entry in wrapper.as_object().expect("object") {
            entries
                .insert(entry.key(), entry.value().clone())
                .expect("unique");
        }
        entries
            .insert("extra", PortableValue::boolean(true))
            .expect("unique");
        wrapper = entries.build();
        let request = encode_json(&wrapper, limits).expect("bytes");
        let (code, _, stderr) =
            run_request(&["query", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 2, "unknown wrapper fields must be rejected");
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));

        // Malformed inline hex -> rejected.
        let (code, _, stderr) = run_request(
            &["query", "--profile", "json.strict", "--json"],
            &request_json("5b31zz", sequence_elements_expression()),
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("lowercase hex"));
    }

    #[test]
    fn query_recovered_source_is_a_data_error() {
        // `[section]` with a malformed continuation line recovers under
        // ini.portable; querying a Recovered document exits 2.
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("core.query-definition@1"))
            .expect("unique");
        payload
            .insert("domain_id", PortableValue::string(PORTABLE_QUERY_DOMAIN))
            .expect("unique");
        payload
            .insert(
                "domain_version",
                PortableValue::integer(BigInteger::from(1)),
            )
            .expect("unique");
        payload
            .insert("selection", PortableValue::string("All"))
            .expect("unique");
        payload
            .insert("expression", input_expression())
            .expect("unique");
        let mut source = ObjectBuilder::new();
        source
            .insert("kind", PortableValue::string("bytes"))
            .expect("unique");
        // "[section\nvalue=1\n" — an unterminated section header recovers
        // under ini.portable (malformed-section diagnostics).
        source
            .insert(
                "bytes",
                PortableValue::string("5b73656374696f6e0a76616c75653d310a"),
            )
            .expect("unique");
        let mut profile = ObjectBuilder::new();
        profile
            .insert("id", PortableValue::string("ini.portable"))
            .expect("unique");
        profile
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert("schema", PortableValue::string(REQUEST_SCHEMA))
            .expect("unique");
        wrapper.insert("source", source.build()).expect("unique");
        wrapper.insert("profile", profile.build()).expect("unique");
        wrapper.insert("payload", payload.build()).expect("unique");
        let request = encode_json(&wrapper.build(), ProtocolLimits::default()).expect("bytes");
        let (code, stdout, stderr) =
            run_request(&["query", "--profile", "ini.portable", "--json"], &request);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("Recovered"),
            "the stderr line names the recovered state"
        );
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert!(!envelope.diagnostics().is_empty());
    }

    #[test]
    fn query_native_domain_is_rejected_clearly() {
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("core.query-definition@1"))
            .expect("unique");
        payload
            .insert(
                "domain_id",
                PortableValue::string("json.native-semantic-query"),
            )
            .expect("unique");
        payload
            .insert(
                "domain_version",
                PortableValue::integer(BigInteger::from(1)),
            )
            .expect("unique");
        payload
            .insert("selection", PortableValue::string("All"))
            .expect("unique");
        payload
            .insert("expression", input_expression())
            .expect("unique");
        let mut source = ObjectBuilder::new();
        source
            .insert("kind", PortableValue::string("bytes"))
            .expect("unique");
        source
            .insert("bytes", PortableValue::string("7b7d"))
            .expect("unique");
        let mut profile = ObjectBuilder::new();
        profile
            .insert("id", PortableValue::string("json.strict"))
            .expect("unique");
        profile
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert("schema", PortableValue::string(REQUEST_SCHEMA))
            .expect("unique");
        wrapper.insert("source", source.build()).expect("unique");
        wrapper.insert("profile", profile.build()).expect("unique");
        wrapper.insert("payload", payload.build()).expect("unique");
        let request = encode_json(&wrapper.build(), ProtocolLimits::default()).expect("bytes");
        let (code, _, stderr) =
            run_request(&["query", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("not wired in this milestone"));
    }

    #[test]
    fn query_human_report_renders_the_same_results() {
        let (code, stdout, stderr) = run_request(
            &["query", "--profile", "json.strict"],
            &request_json("5b312c322c335d", sequence_elements_expression()),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("match 0: $[0] = 1"), "{text}");
        assert!(text.contains("match 2: $[2] = 3"), "{text}");
    }

    #[test]
    fn query_rejects_request_profile_contradicting_profile_flag() {
        let mut wrapper = request_value("5b312c322c335d", "All", sequence_elements_expression());
        // Rewrite the profile id to a contradicting one.
        let mut builder = ObjectBuilder::new();
        for entry in wrapper.as_object().expect("object") {
            let value = if entry.key() == "profile" {
                let mut profile = ObjectBuilder::new();
                profile
                    .insert("id", PortableValue::string("toml.1.0"))
                    .expect("unique");
                profile
                    .insert("version", PortableValue::integer(BigInteger::from(1)))
                    .expect("unique");
                profile.build()
            } else {
                entry.value().clone()
            };
            builder.insert(entry.key(), value).expect("unique");
        }
        wrapper = builder.build();
        let request = encode_json(&wrapper, ProtocolLimits::default()).expect("bytes");
        let (code, _, stderr) =
            run_request(&["query", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 2, "contradicting request profile is a data error");
        assert!(stderr_text(&stderr).contains("contradicts the --profile selection"));
    }
}
