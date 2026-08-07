//! `consema convert`: the two-stage cross-format conversion, driven entirely
//! by the facade's `convert_*` composition (conversion.rs — projection plus
//! materialization with the record-consumption gate and reparse closure
//! already enforced by the lib).
//!
//! The request is the CLI-local `cli.convert-request@1` record (not
//! registered; envelope payloads only per RFC 0015 §6.2), passed via
//! `--request-file` or stdin:
//!
//! ```text
//! cli.convert-request@1:
//!   schema:                "cli.convert-request@1"
//!   projection_request:    core.projection-request@1 record
//!   materialization_request: core.materialization-request@2 record
//! ```
//!
//! Unlike the other three request commands, the source is the positional
//! path (the M3 args freeze gives convert exactly one positional, "a source
//! file path") and the profile is the mandatory `--profile`; the request
//! carries only the two-stage operation specifics. This asymmetry is the
//! milestone-M5 answer to the M3 zero-positionals freeze and is recorded in
//! the M5 milestone report.
//!
//! The machine payload is `cli.convert@1` = `{schema, report:
//! core.conversion-report@1, target: core.source-snapshot@2}` (RFC 0015
//! §6.1), externalized through the facade's own
//! [`CompleteConversion::protocol_report`] and the target document's
//! verified snapshot. Conversion failures are atomic (no target document,
//! no partial bytes) and surface as data errors carrying
//! `core.conversion.*@1` codes; in human mode the target bytes are written
//! to stdout. Milestone M5 never writes files: `--output` is refused as a
//! usage error until fsio lands.

use crate::args::ParsedArgs;
use consema::core::{ObjectBuilder, PortableValue, StableFailure};
use consema::protocol::{
    CliCommand, ExitClass, MaterializationRequestMessageV2, ProjectionRequestMessage,
    SourceSnapshotMessageV2,
};
use std::io::Write;

use crate::project_cmd::wire_projection_request;
use crate::query_cmd::{
    FlowError, bind_diagnostics, emit_envelope, emit_failure, format_family, internal_failure,
    parse_document, protocol_error, read_request_bytes, read_source_capped, require_complete,
};

/// The CLI-local two-stage request record of the convert command.
const CONVERT_REQUEST_SCHEMA: &str = "cli.convert-request@1";

/// The frozen `cli.convert@1` payload record of RFC 0015 §6.1.
const CONVERT_PAYLOAD_SCHEMA: &str = "cli.convert@1";

/// One strictly decoded two-stage convert request.
struct ConvertRequest {
    /// Typed projection request of the source format family.
    projection_request: crate::query_cmd::WireProjectionRequest,
    /// Typed materialization request of the target profile.
    materialization_request: consema::document::MaterializationRequest,
}

/// Runs `consema convert` (request from `--request-file` or stdin; source
/// path is the positional).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available in this build: convert writes only to stdout \
             (file writing lands with fsio in milestone M6)",
        );
        return emit_failure(CliCommand::Convert, parsed, &error, stdout, stderr);
    }
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Convert, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, stdout, stderr)
}

/// Runs `consema convert` against already-read request bytes.
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available in this build: convert writes only to stdout \
             (file writing lands with fsio in milestone M6)",
        );
        return emit_failure(CliCommand::Convert, parsed, &error, stdout, stderr);
    }
    let convert_request = match decode_convert_request(request, parsed) {
        Ok(request) => request,
        Err(error) => return emit_failure(CliCommand::Convert, parsed, &error, stdout, stderr),
    };
    let source_path = parsed
        .positionals
        .first()
        .expect("args.rs requires exactly one positional for convert");
    match execute_convert(source_path, parsed, &convert_request) {
        Ok((payload, target_bytes)) => {
            if parsed.json {
                match emit_envelope(
                    CliCommand::Convert,
                    ExitClass::Success,
                    payload,
                    Vec::new(),
                    parsed,
                    stdout,
                ) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("convert", &message, stderr),
                }
            } else {
                match stdout.write_all(&target_bytes) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("convert", &message.to_string(), stderr),
                }
            }
        }
        Err(error) => emit_failure(CliCommand::Convert, parsed, &error, stdout, stderr),
    }
}

/// Strictly decodes the `cli.convert-request@1` record: exact fields,
/// `projection_request` strictly decoded as `core.projection-request@1` and
/// mapped to the typed per-format request of the source family,
/// `materialization_request` strictly decoded as
/// `core.materialization-request@2`.
fn decode_convert_request(bytes: &[u8], parsed: &ParsedArgs) -> Result<ConvertRequest, FlowError> {
    let limits = consema::protocol::ProtocolLimits::default();
    let value = if bytes.starts_with(b"PVCE") {
        consema::protocol::decode_pvce(bytes, limits)
    } else {
        consema::protocol::decode_json(bytes, limits)
    }
    .map_err(protocol_error)?;
    let entries = value.as_object().ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            "cli.convert-request@1 must be an Object",
        )
    })?;
    if !matches!(entries.len(), 3)
        || entries[0].key() != "schema"
        || entries[0].value().as_string() != Some(CONVERT_REQUEST_SCHEMA)
        || entries[1].key() != "projection_request"
        || entries[2].key() != "materialization_request"
    {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "cli.convert-request@1 requires exactly schema/projection_request/\
             materialization_request in order",
        ));
    }
    if entries[1]
        .value()
        .as_object()
        .and_then(|fields| fields.first())
        .and_then(|first| first.value().as_string())
        != Some("core.projection-request@1")
    {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "projection_request must be a core.projection-request@1 record",
        ));
    }
    if entries[2]
        .value()
        .as_object()
        .and_then(|fields| fields.first())
        .and_then(|first| first.value().as_string())
        != Some("core.materialization-request@2")
    {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "materialization_request must be a core.materialization-request@2 record",
        ));
    }
    let profile = crate::query_cmd::resolve_profile(
        parsed
            .profile
            .as_deref()
            .expect("args.rs requires --profile for parse-class commands"),
    )?;
    let family = format_family(profile.id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("profile '{}' has no format family", profile.id()),
        )
    })?;
    let projection_message =
        ProjectionRequestMessage::from_value(entries[1].value()).map_err(protocol_error)?;
    let projection_request = wire_projection_request(family, &projection_message)?;
    let materialization_message =
        MaterializationRequestMessageV2::from_value(entries[2].value()).map_err(protocol_error)?;
    Ok(ConvertRequest {
        projection_request,
        materialization_request: materialization_message.request().clone(),
    })
}

/// Executes one conversion through the facade composition, returning the
/// `cli.convert@1` payload and the rendered target bytes.
fn execute_convert(
    source_path: &str,
    parsed: &ParsedArgs,
    request: &ConvertRequest,
) -> Result<(PortableValue, Vec<u8>), FlowError> {
    let cap = parsed.max_bytes.unwrap_or(
        u64::try_from(consema::protocol::ProtocolLimits::default().max_bytes).expect("fits u64"),
    );
    let source = read_source_capped(source_path, cap)?;
    let profile = crate::query_cmd::resolve_profile(
        parsed
            .profile
            .as_deref()
            .expect("args.rs requires --profile for parse-class commands"),
    )?;
    let document = parse_document(source, &profile)?;
    require_complete(&document, source_path)?;
    let result = convert_document(&document, request, profile.id())?;
    match result {
        consema::ConversionResult::Complete(complete) => {
            let report = complete
                .protocol_report(source_path, source_path)
                .map_err(|error| {
                    FlowError::new(
                        error.kind().code(),
                        format!("conversion report externalization failed: {error}"),
                    )
                })?;
            let snapshot = target_snapshot(&complete.document, request)?;
            let mut payload = ObjectBuilder::new();
            payload
                .insert("schema", PortableValue::string(CONVERT_PAYLOAD_SCHEMA))
                .expect("unique key");
            payload
                .insert("report", report.to_value())
                .expect("unique key");
            payload
                .insert(
                    "target",
                    SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value(),
                )
                .expect("unique key");
            Ok((payload.build(), complete.document.render().to_vec()))
        }
        consema::ConversionResult::Failed(failure) => {
            let code = failure.diagnostic_code();
            let mut payload = ObjectBuilder::new();
            payload
                .insert("schema", PortableValue::string(CONVERT_PAYLOAD_SCHEMA))
                .expect("unique key");
            // Milestone-M5 failure form of the CLI-local record: report and
            // target are null (there is no target document by construction);
            // the envelope diagnostics carry the atomic failure.
            payload
                .insert("report", PortableValue::null())
                .expect("unique key");
            payload
                .insert("target", PortableValue::null())
                .expect("unique key");
            Err(
                FlowError::new(code, format!("conversion failed atomically ({code})"))
                    .with_payload(payload.build())
                    .with_diagnostics(failure_diagnostics(&failure, source_path)),
            )
        }
    }
}

/// Dispatches the facade `convert_*` composition by source family. The
/// record-consumption gate and the reparse closure are inside the facade
/// (conversion.rs); the CLI only selects the family and the typed requests.
fn convert_document(
    document: &consema::Document,
    request: &ConvertRequest,
    source_profile_id: &str,
) -> Result<consema::ConversionResult, FlowError> {
    let materialization = &request.materialization_request;
    let result = match (source_profile_id, &request.projection_request) {
        (
            "json.strict" | "jsonc.bounded" | "json5.standard",
            crate::query_cmd::WireProjectionRequest::Json(projection),
        ) => consema::convert_json(
            document.as_json().expect("family matches the adapter"),
            projection,
            materialization,
        ),
        ("toml.1.0", crate::query_cmd::WireProjectionRequest::Toml(projection)) => {
            consema::convert_toml(
                document.as_toml().expect("family matches the adapter"),
                *projection,
                materialization,
            )
        }
        (
            "ini.portable" | "ini.windows" | "ini.python-configparser",
            crate::query_cmd::WireProjectionRequest::Ini(projection),
        ) => consema::convert_ini(
            document.as_ini().expect("family matches the adapter"),
            *projection,
            materialization,
        ),
        (
            "java-properties.reader" | "java-properties.latin1",
            crate::query_cmd::WireProjectionRequest::Properties(projection),
        ) => consema::convert_properties(
            document
                .as_properties()
                .expect("family matches the adapter"),
            *projection,
            materialization,
        ),
        (
            "yaml.1.2-core" | "yaml.1.1-compat",
            crate::query_cmd::WireProjectionRequest::Yaml(projection),
        ) => consema::convert_yaml(
            document.as_yaml().expect("family matches the adapter"),
            *projection,
            materialization,
        ),
        ("xml.1.0-safe", crate::query_cmd::WireProjectionRequest::Xml(projection)) => {
            consema::convert_xml(
                document.as_xml().expect("family matches the adapter"),
                *projection,
                materialization,
            )
        }
        (
            "plist.xml" | "plist.binary",
            crate::query_cmd::WireProjectionRequest::Plist(projection),
        ) => consema::convert_plist(
            document.as_plist().expect("family matches the adapter"),
            *projection,
            materialization,
        ),
        ("hcl.native" | "hcl.tfvars", crate::query_cmd::WireProjectionRequest::Hcl(projection)) => {
            consema::convert_hcl(
                document.as_hcl().expect("family matches the adapter"),
                *projection,
                materialization,
            )
        }
        _ => {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                format!("projection target does not match source profile '{source_profile_id}'"),
            ));
        }
    };
    Ok(result)
}

/// The verified target snapshot of a complete conversion (all eight format
/// documents expose their immutable source through the facade adapters).
fn target_snapshot(
    document: &consema::Document,
    request: &ConvertRequest,
) -> Result<consema::document::SourceSnapshot, FlowError> {
    let snapshot = match format_family(request.materialization_request.target_profile().id()) {
        Some("json") => document
            .as_json()
            .expect("family matches the adapter")
            .source(),
        Some("toml") => document
            .as_toml()
            .expect("family matches the adapter")
            .source(),
        Some("ini") => document
            .as_ini()
            .expect("family matches the adapter")
            .source(),
        Some("properties") => document
            .as_properties()
            .expect("family matches the adapter")
            .source(),
        Some("yaml") => document
            .as_yaml()
            .expect("family matches the adapter")
            .source(),
        Some("xml") => document
            .as_xml()
            .expect("family matches the adapter")
            .source(),
        Some("plist") => document
            .as_plist()
            .expect("family matches the adapter")
            .source(),
        Some("hcl") => document
            .as_hcl()
            .expect("family matches the adapter")
            .source(),
        _ => {
            return Err(FlowError::new(
                "core.materialization.unsupported-profile@1",
                format!(
                    "target profile '{}' is not materializable",
                    request.materialization_request.target_profile().id()
                ),
            ));
        }
    };
    Ok(snapshot.clone())
}

/// Binds the atomic conversion failure facts to envelope diagnostics.
fn failure_diagnostics(
    failure: &consema::ConversionFailure,
    source_path: &str,
) -> Vec<consema::protocol::DiagnosticMessage> {
    let mut diagnostics = Vec::new();
    if let consema::ConversionFailure::ProjectionFailed {
        diagnostics: format_diagnostics,
        ..
    } = failure
    {
        // The projection-failed variant carries the format's own diagnostics;
        // the other failure variants carry none at the facade level (their
        // reports stay inside the failure value, which the CLI failure form
        // does not externalize in milestone M5).
        diagnostics.extend(bind_diagnostics(format_diagnostics, Some(source_path)));
    }
    if diagnostics.is_empty() {
        diagnostics.push(crate::query_cmd::diagnostic_for(
            failure.diagnostic_code(),
            &format!(
                "conversion failed atomically ({})",
                failure.diagnostic_code()
            ),
        ));
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::BigInteger;
    use consema::document::{
        MappingPolicy, MaterializationLimits, MaterializationRequest, MaterializationStyleId,
        NewlinePolicy, ProfileId, SourceEncoding,
    };
    use consema::protocol::{CliOutputMessage, ProtocolLimits, encode_json};

    fn parse(args: &[&str]) -> ParsedArgs {
        crate::args::parse_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("valid invocation")
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    /// Builds one strict `cli.convert-request@1` for a JSON source.
    fn convert_request(
        projection_target_id: &str,
        target_profile: &str,
        style_id: &str,
    ) -> Vec<u8> {
        let mut target = ObjectBuilder::new();
        target
            .insert("id", PortableValue::string(projection_target_id))
            .expect("unique");
        target
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let target_value = target.build();
        let mut default_policy = ObjectBuilder::new();
        default_policy
            .insert(
                "id",
                PortableValue::string("core.projection.exact-or-reject"),
            )
            .expect("unique");
        default_policy
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        default_policy
            .insert("arguments", ObjectBuilder::new().build())
            .expect("unique");
        let mut projection = ObjectBuilder::new();
        projection
            .insert("schema", PortableValue::string("core.projection-request@1"))
            .expect("unique");
        projection.insert("target", target_value).expect("unique");
        projection
            .insert("default_policy", default_policy.build())
            .expect("unique");
        projection
            .insert("rules", consema::core::SequenceBuilder::new().build())
            .expect("unique");
        projection
            .insert("limits", ObjectBuilder::new().build())
            .expect("unique");
        let materialization = MaterializationRequest::new(
            ProfileId::new(target_profile, 1),
            MaterializationStyleId::new(style_id, 1),
        )
        .with_encoding(match target_profile {
            "plist.binary" => SourceEncoding::Binary,
            _ => SourceEncoding::Utf8,
        })
        .with_newline(match target_profile {
            "json.strict" => NewlinePolicy::None,
            _ => NewlinePolicy::Lf,
        })
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
        .with_limits(MaterializationLimits::default());
        let mut request = ObjectBuilder::new();
        request
            .insert("schema", PortableValue::string(CONVERT_REQUEST_SCHEMA))
            .expect("unique");
        request
            .insert("projection_request", projection.build())
            .expect("unique");
        request
            .insert(
                "materialization_request",
                MaterializationRequestMessageV2::from_request(&materialization)
                    .to_value()
                    .expect("wire value"),
            )
            .expect("unique");
        encode_json(&request.build(), ProtocolLimits::default()).expect("canonical bytes")
    }

    /// Writes a small source fixture into the system temp dir and returns
    /// its path (test-only file creation; the bin itself never writes).
    fn write_source(label: &str, bytes: &[u8]) -> (std::path::PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "consema-m5-convert-{label}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("test fixture write");
        let spelling = path.to_string_lossy().into_owned();
        (path, spelling)
    }

    #[test]
    fn convert_json_to_toml_round_trips_and_is_byte_deterministic() {
        let (_path, source_path) = write_source("toml", br#"{"a":1,"b":"x"}"#);
        let request = convert_request(
            "json.projection.best-exact-core",
            "toml.1.0",
            "toml.canonical-document",
        );
        let parsed = parse(&[
            "convert",
            &source_path,
            "--profile",
            "json.strict",
            "--json",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, &request, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        let limits = ProtocolLimits::default();
        let envelope_bytes = &stdout[..stdout.len() - 1];
        let envelope = CliOutputMessage::from_json(envelope_bytes, limits).expect("envelope");
        assert_eq!(envelope.command(), CliCommand::Convert);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            envelope_bytes,
            "stdout envelope must be byte-deterministic"
        );
        let payload = envelope.payload();
        let fields = payload.as_object().expect("payload object");
        assert_eq!(fields[0].key(), "schema");
        assert_eq!(fields[0].value().as_string(), Some(CONVERT_PAYLOAD_SCHEMA));
        // The report decodes as core.conversion-report@1 and names the
        // source/target profiles.
        let report = consema::protocol::ConversionReportMessage::from_value(fields[1].value())
            .expect("conversion report record");
        assert_eq!(report.source_profile().id(), "json.strict");
        assert_eq!(report.target_profile().id(), "toml.1.0");
        // The target decodes as core.source-snapshot@2 and carries the
        // materialized document.
        let target = SourceSnapshotMessageV2::from_value(
            fields[2].value(),
            consema::document::SourceLimits::default(),
        )
        .expect("source snapshot v2");
        let bytes = std::str::from_utf8(target.snapshot().bytes()).expect("utf8");
        assert!(
            bytes.contains("\"a\" = 1"),
            "the target snapshot carries the materialized bytes: {bytes}"
        );
    }

    #[test]
    fn convert_java_properties_source_to_toml_end_to_end() {
        // B-6: java-properties sources were unreachable through convert
        // because the family-prefix check rejected `java-properties.projection.*`
        // targets under the wire family "properties"; the full convert path
        // (source parse -> projection -> materialization) must succeed.
        let (_path, source_path) = write_source("jp", b"name=api\nport=8080\n");
        let request = convert_request(
            "java-properties.projection.best-exact-entry-mapping",
            "toml.1.0",
            "toml.canonical-document",
        );
        let parsed = parse(&[
            "convert",
            &source_path,
            "--profile",
            "java-properties.reader",
            "--json",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, &request, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("success envelope");
        assert_eq!(envelope.command(), CliCommand::Convert);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        let fields = envelope.payload().as_object().expect("payload object");
        assert_eq!(fields[0].value().as_string(), Some(CONVERT_PAYLOAD_SCHEMA));
        let report = consema::protocol::ConversionReportMessage::from_value(fields[1].value())
            .expect("conversion report record");
        assert_eq!(report.source_profile().id(), "java-properties.reader");
        assert_eq!(report.target_profile().id(), "toml.1.0");
        let target = SourceSnapshotMessageV2::from_value(
            fields[2].value(),
            consema::document::SourceLimits::default(),
        )
        .expect("source snapshot v2");
        let bytes = std::str::from_utf8(target.snapshot().bytes()).expect("utf8");
        assert!(
            bytes.contains("\"name\" = \"api\"") && bytes.contains("\"port\" = \"8080\""),
            "the target snapshot carries the materialized TOML: {bytes}"
        );
    }

    #[test]
    fn convert_human_mode_writes_the_target_bytes() {
        let (_path, source_path) = write_source("self", br#"{"a":1}"#);
        let request = convert_request(
            "json.projection.best-exact-core",
            "json.strict",
            "json.canonical-compact",
        );
        let parsed = parse(&["convert", &source_path, "--profile", "json.strict"]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, &request, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(
            text.contains("{\"a\":1}"),
            "human mode carries the target bytes: {text}"
        );
    }

    #[test]
    fn convert_output_flag_is_usage_exit_one() {
        let (_path, source_path) = write_source("self", br#"{"a":1}"#);
        let request = convert_request(
            "json.projection.best-exact-core",
            "json.strict",
            "json.canonical-compact",
        );
        let parsed = parse(&[
            "convert",
            &source_path,
            "--profile",
            "json.strict",
            "--output",
            "out.json",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, &request, &mut stdout, &mut stderr);
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "usage failures never emit an envelope");
        assert!(stderr_text(&stderr).contains("--output"));
    }

    #[test]
    fn convert_atomic_failure_is_a_data_error_without_target_bytes() {
        // An XML source projects the xml.element-tree@1 record; a JSON target
        // is not its owning family, so the facade's record-consumption gate
        // fails the conversion atomically (no target document, no partial
        // bytes).
        let (_path, source_path) = write_source("gate", br"<root>x</root>");
        let request = convert_request(
            "xml.projection.element-tree",
            "json.strict",
            "json.canonical-compact",
        );
        let parsed = parse(&[
            "convert",
            &source_path,
            "--profile",
            "xml.1.0-safe",
            "--json",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, &request, &mut stdout, &mut stderr);
        let stderr = stderr_text(&stderr);
        assert_eq!(code, 2, "{stderr}");
        let limits = ProtocolLimits::default();
        let envelope = CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits)
            .expect("data-error envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert!(
            !envelope.diagnostics().is_empty(),
            "stderr: {stderr}; envelope: {}",
            String::from_utf8_lossy(&stdout[..stdout.len() - 1])
        );
        let payload = envelope.payload();
        let fields = payload.as_object().expect("payload object");
        assert_eq!(fields[0].value().as_string(), Some(CONVERT_PAYLOAD_SCHEMA));
        // The failure form carries no report and no target (atomic failure).
        assert_eq!(fields[1].value(), &PortableValue::null());
        assert_eq!(fields[2].value(), &PortableValue::null());
    }

    #[test]
    fn convert_request_negatives_are_rejected() {
        let (_path, source_path) = write_source("self", br#"{"a":1}"#);
        // Unknown request schema -> data error.
        let parsed = parse(&[
            "convert",
            &source_path,
            "--profile",
            "json.strict",
            "--json",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut bad = ObjectBuilder::new();
        bad.insert("schema", PortableValue::string("cli.bogus@1"))
            .expect("unique");
        let bytes = encode_json(&bad.build(), ProtocolLimits::default()).expect("bytes");
        let code = run_with_request(&parsed, &bytes, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);

        // Missing --request-file input is an empty-stdin decode failure, but
        // the unit path never reads stdin; instead assert the args-level
        // rejection for convert without a positional.
        let error =
            crate::args::parse_args(&["convert", "--profile", "json.strict"].map(String::from))
                .expect_err("missing positional");
        assert!(error.message().contains("source file path"));
    }
}
