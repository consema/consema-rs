//! `consema materialize`: parse the source under the request profile, project
//! it under the source format's default exact projection, and materialize the
//! projected value under the request's `core.materialization-request@2`
//! record (RFC 0015 §6.1).
//!
//! The machine payload is `core.materialization-result@2`: Complete embeds
//! the verified target `core.source-snapshot@2` plus fidelity, report, and
//! provenance; Failed carries the stable failure, report, and analyzed input
//! paths (RFC 0015 §6.1). In human mode the materialized bytes are written to
//! stdout (the command's result data); under `--json` the bytes live inside
//! the envelope snapshot and stdout carries exactly the one envelope line
//! (RFC 0015 §3.3).
//!
//! Milestone M5 never writes files: `--output` is refused as a usage error
//! until fsio lands (implementation plan §6 M5; hard gate 4). The facade's
//! record-consumption gate is re-checked here because the gate lives in the
//! lib's private composition: a record-format source projects a versioned
//! internal record that only its owning family's materializer consumes, and
//! presenting it to a foreign family would be an internal record dump.

use crate::args::ParsedArgs;
use consema::core::PortableValue;
use consema::protocol::{
    CliCommand, ExitClass, MaterializationFailureMessage, MaterializationProvenanceMapMessage,
    MaterializationReportMessage, MaterializationRequestMessageV2, MaterializationResultMessageV2,
    SourceSnapshotMessageV2,
};
use std::io::Write;

use crate::query_cmd::{
    FlowError, RequestInput, decode_request, default_projection_request, emit_envelope,
    emit_failure, format_family, internal_failure, parse_document, project_value, protocol_error,
    published_record, read_request_bytes, require_complete,
};

/// Runs `consema materialize` (request from `--request-file` or stdin).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available in this build: materialize writes only to stdout \
             (file writing lands with fsio in milestone M6)",
        );
        return emit_failure(CliCommand::Materialize, parsed, &error, stdout, stderr);
    }
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Materialize, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, stdout, stderr)
}

/// Runs `consema materialize` against already-read request bytes.
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available in this build: materialize writes only to stdout \
             (file writing lands with fsio in milestone M6)",
        );
        return emit_failure(CliCommand::Materialize, parsed, &error, stdout, stderr);
    }
    let input = match decode_request(request, parsed, "core.materialization-request@2") {
        Ok(input) => input,
        Err(error) => return emit_failure(CliCommand::Materialize, parsed, &error, stdout, stderr),
    };
    match execute_materialize(&input) {
        Ok((payload, target_bytes)) => {
            if parsed.json {
                match emit_envelope(
                    CliCommand::Materialize,
                    ExitClass::Success,
                    payload,
                    Vec::new(),
                    parsed,
                    stdout,
                ) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("materialize", &message, stderr),
                }
            } else {
                match stdout.write_all(&target_bytes) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("materialize", &message.to_string(), stderr),
                }
            }
        }
        Err(error) => emit_failure(CliCommand::Materialize, parsed, &error, stdout, stderr),
    }
}

/// Executes one materialization: parse -> default projection -> materialize.
///
/// Returns the `core.materialization-result@2` payload and the rendered
/// target bytes (the human result data).
fn execute_materialize(input: &RequestInput) -> Result<(PortableValue, Vec<u8>), FlowError> {
    let message =
        MaterializationRequestMessageV2::from_value(&input.payload).map_err(protocol_error)?;
    let request = message.request();
    let source_family = format_family(input.profile.id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("profile '{}' has no format family", input.profile.id()),
        )
    })?;
    let document = parse_document(input.source.clone(), &input.profile)?;
    require_complete(&document, &input.source_label)?;
    let value = project_value(&document, default_projection_request(source_family)?)?;
    // The record-consumption gate (conversion.rs): a record-format source
    // projects a versioned internal record consumed only by its owning
    // family's materializer.
    let target_family = format_family(request.target_profile().id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "target profile '{}' has no format family",
                request.target_profile().id()
            ),
        )
    })?;
    if let Some(record_family) = published_record(&value) {
        if record_family != target_family {
            return Err(failed_materialization(
                request.target_profile(),
                consema::document::MaterializationFailure::InvalidRequest(
                    "the projected value is a versioned internal record that only its owning \
                     format family's materializer consumes",
                ),
                consema::document::MaterializationReport::default(),
                Vec::new(),
                &input.source_label,
                &format!(
                    "the record-consumption gate rejected the materialization: the projected \
                     value is the internal {} record, which only the {} family materializer \
                     consumes; target family is '{target_family}'",
                    record_family_record_id(&value).expect("published record id present"),
                    record_family
                ),
            ));
        }
    }
    let source_label = input.source_label.clone();
    let outcome = materialize_value(&value, request)?;
    match outcome {
        MaterializeOutcome::Complete {
            snapshot,
            fidelity,
            report,
            rendered,
            ..
        } => {
            let payload = MaterializationResultMessageV2::complete(
                request.target_profile().clone(),
                source_label.clone(),
                SourceSnapshotMessageV2::from_snapshot(&snapshot),
                fidelity,
                MaterializationReportMessage::from_report(&report, Some(&source_label)).map_err(
                    |error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("materialization report externalization failed: {error}"),
                        )
                    },
                )?,
                // Milestone-M5 boundary: the materialization provenance map
                // requires caller locators for every target node (the
                // protocol refuses process-local NodeRefs), and the facade
                // exposes no locator API yet, so the provenance entries
                // cannot be externalized truthfully; the record carries the
                // empty map and the gap is reported in the M5 milestone
                // report (a facade locator API is the M10 review item).
                MaterializationProvenanceMapMessage::new(Vec::new())
                    .expect("empty provenance map is valid"),
            )
            .map_err(|error| {
                FlowError::new(
                    error.kind().code(),
                    format!("materialization result encoding failed: {error}"),
                )
            })?;
            Ok((payload.to_value(), rendered))
        }
        MaterializeOutcome::Failed {
            failure,
            report,
            analyzed_input_paths,
        } => Err(failed_materialization(
            request.target_profile(),
            failure,
            report,
            analyzed_input_paths,
            &source_label,
            "materialization failed",
        )),
    }
}

/// The stable record envelope id behind one published record family.
fn record_family_record_id(value: &PortableValue) -> Option<&str> {
    value
        .as_object()?
        .iter()
        .find(|entry| entry.key() == "record")
        .and_then(|entry| entry.value().as_string())
}

/// One materialization outcome with the facts the payload record needs.
enum MaterializeOutcome {
    /// Complete target snapshot, report, and rendered bytes.
    Complete {
        /// Verified immutable target source.
        snapshot: consema::document::SourceSnapshot,
        /// Whole-operation semantic fidelity.
        fidelity: consema::document::MaterializationFidelity,
        /// Ordered materialization report.
        report: consema::document::MaterializationReport,
        /// Rendered target bytes (human result data).
        rendered: Vec<u8>,
    },
    /// Failed attempt with no target bytes.
    Failed {
        /// Stable failure.
        failure: consema::document::MaterializationFailure,
        /// Ordered events discovered before failure.
        report: consema::document::MaterializationReport,
        /// Stable input paths analyzed before failure.
        analyzed_input_paths: Vec<consema::core::ValuePath>,
    },
}

/// Builds the data-class failure of a failed materialization with the
/// failed `core.materialization-result@2` record as payload.
fn failed_materialization(
    target_profile: &consema::document::ProfileId,
    failure: consema::document::MaterializationFailure,
    report: consema::document::MaterializationReport,
    analyzed_input_paths: Vec<consema::core::ValuePath>,
    source_label: &str,
    context: &str,
) -> FlowError {
    let failure_message = MaterializationFailureMessage::from_failure(&failure);
    let code = failure_message.code();
    let payload = MaterializationResultMessageV2::failed(
        target_profile.clone(),
        failure_message,
        MaterializationReportMessage::from_report(&report, Some(source_label)).unwrap_or_default(),
        analyzed_input_paths,
    )
    .map_or_else(
        |_| crate::query_cmd::minimal_record(CliCommand::Materialize),
        |message| message.to_value(),
    );
    FlowError::new(code, format!("{context} ({code})")).with_payload(payload)
}

/// Dispatches the per-format materializer (facade re-exports; the CLI only
/// selects the family, never implements materialization). Each format
/// document type is distinct, so the outcome extraction is a per-family
/// closure passed to the shared reducer.
fn materialize_value(
    value: &PortableValue,
    request: &consema::document::MaterializationRequest,
) -> Result<MaterializeOutcome, FlowError> {
    let family = format_family(request.target_profile().id()).expect("target family checked");
    Ok(match family {
        "json" => reduce_materialization(consema::json::materialize(value, request), |document| {
            (document.source().clone(), document.render().to_vec())
        }),
        "toml" => reduce_materialization(consema::toml::materialize(value, request), |document| {
            (document.source().clone(), document.render().to_vec())
        }),
        "ini" => reduce_materialization(consema::ini::materialize(value, request), |document| {
            (document.source().clone(), document.render().to_vec())
        }),
        "properties" => reduce_materialization(
            consema::properties::materialize(value, request),
            |document| (document.source().clone(), document.render().to_vec()),
        ),
        "yaml" => reduce_materialization(
            consema::yaml::materialize_value(value, request),
            |document| (document.source().clone(), document.render().to_vec()),
        ),
        "xml" => reduce_materialization(consema::xml::materialize(value, request), |document| {
            (document.source().clone(), document.render().to_vec())
        }),
        "plist" => {
            reduce_materialization(consema::plist::materialize(value, request), |document| {
                (document.source().clone(), document.render().to_vec())
            })
        }
        "hcl" => reduce_materialization(consema::hcl::materialize(value, request), |document| {
            (document.source().clone(), document.render().to_vec())
        }),
        other => {
            return Err(FlowError::new(
                "core.materialization.unsupported-profile@1",
                format!("target profile family '{other}' is unknown"),
            ));
        }
    })
}

/// Reduces one per-format materialization result into the common outcome,
/// extracting the snapshot and rendered bytes through the family closure.
fn reduce_materialization<D>(
    result: consema::document::MaterializationResult<D>,
    facts: impl FnOnce(&D) -> (consema::document::SourceSnapshot, Vec<u8>),
) -> MaterializeOutcome {
    match result {
        consema::document::MaterializationResult::Complete(complete) => {
            let (snapshot, rendered) = facts(&complete.document);
            MaterializeOutcome::Complete {
                snapshot,
                fidelity: complete.fidelity,
                report: complete.report,
                rendered,
            }
        }
        consema::document::MaterializationResult::Failed(attempt) => MaterializeOutcome::Failed {
            failure: attempt.failure,
            report: attempt.report,
            analyzed_input_paths: attempt.analyzed_input_paths,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::{BigInteger, ObjectBuilder};
    use consema::document::{
        MappingPolicy, MaterializationLimits, MaterializationRequest, MaterializationStyleId,
        NewlinePolicy, ProfileId, SourceEncoding,
    };
    use consema::protocol::{CliOutputMessage, ErrorCodeRegistry, ProtocolLimits, encode_json};

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

    /// Builds one strict `cli.request@1` wrapper with the wire encoding of a
    /// materialization request for the given target profile/style.
    fn materialize_request(
        source_hex: &str,
        profile_id: &str,
        target_profile: &str,
        style_id: &str,
    ) -> Vec<u8> {
        let request = MaterializationRequest::new(
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
        let payload = MaterializationRequestMessageV2::from_request(&request)
            .to_value()
            .expect("wire request value");
        let mut source = ObjectBuilder::new();
        source
            .insert("kind", PortableValue::string("bytes"))
            .expect("unique");
        source
            .insert("bytes", PortableValue::string(source_hex))
            .expect("unique");
        let mut profile = ObjectBuilder::new();
        profile
            .insert("id", PortableValue::string(profile_id))
            .expect("unique");
        profile
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert(
                "schema",
                PortableValue::string(crate::query_cmd::REQUEST_SCHEMA),
            )
            .expect("unique");
        wrapper.insert("source", source.build()).expect("unique");
        wrapper.insert("profile", profile.build()).expect("unique");
        wrapper.insert("payload", payload).expect("unique");
        encode_json(&wrapper.build(), ProtocolLimits::default()).expect("canonical bytes")
    }

    #[test]
    fn materialize_json_to_toml_round_trips_and_is_byte_deterministic() {
        let request = materialize_request(
            "7b2261223a312c2262223a2278227d",
            "json.strict",
            "toml.1.0",
            "toml.canonical-document",
        );
        let (code, stdout, stderr) = run_request(
            &["materialize", "--profile", "json.strict", "--json"],
            &request,
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        let limits = ProtocolLimits::default();
        let envelope_bytes = &stdout[..stdout.len() - 1];
        let envelope = CliOutputMessage::from_json(envelope_bytes, limits).expect("envelope");
        assert_eq!(envelope.command(), CliCommand::Materialize);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            envelope_bytes,
            "stdout envelope must be byte-deterministic"
        );
        // The payload round-trips through the typed v2 decoder.
        let result = MaterializationResultMessageV2::from_value_with_registry(
            envelope.payload(),
            ErrorCodeRegistry::v7(),
        )
        .expect("materialization-result@2 record");
        assert_eq!(result.target_profile().id(), "toml.1.0");
        match result.outcome() {
            consema::protocol::MaterializationOutcomeMessageV2::Complete { snapshot, .. } => {
                let bytes = std::str::from_utf8(snapshot.snapshot().bytes()).expect("utf8 target");
                assert!(
                    bytes.contains("\"a\" = 1"),
                    "the target snapshot carries the materialized document: {bytes}"
                );
            }
            other @ consema::protocol::MaterializationOutcomeMessageV2::Failed { .. } => {
                panic!("unexpected outcome {other:?}")
            }
        }
    }

    #[test]
    fn materialize_human_mode_writes_raw_bytes_to_stdout() {
        let request = materialize_request(
            "7b2261223a317d",
            "json.strict",
            "json.strict",
            "json.canonical-compact",
        );
        let (code, stdout, stderr) =
            run_request(&["materialize", "--profile", "json.strict"], &request);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        let text = String::from_utf8_lossy(&stdout);
        assert!(
            text.contains("{\"a\":1}"),
            "human mode carries the raw target bytes: {text}"
        );
    }

    #[test]
    fn materialize_output_flag_is_usage_exit_one() {
        // --output is not wired until fsio (milestone M6): explicit refusal.
        let request = materialize_request(
            "7b2261223a317d",
            "json.strict",
            "json.strict",
            "json.canonical-compact",
        );
        let parsed = parse(&[
            "materialize",
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
        assert!(
            stderr_text(&stderr).contains("--output"),
            "{}",
            stderr_text(&stderr)
        );
    }

    #[test]
    fn materialize_unrepresentable_target_is_a_data_error() {
        // `{"a":{"b":1}}` materialized to ini.portable: the nested object
        // cannot be expressed by the INI value vocabulary, so the
        // materializer fails with its stable unrepresentable code.
        let request = materialize_request(
            "7b2261223a7b2262223a317d7d",
            "json.strict",
            "ini.portable",
            "ini.portable-canonical",
        );
        let (code, stdout, stderr) = run_request(
            &["materialize", "--profile", "json.strict", "--json"],
            &request,
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("core.materialization.unrepresentable@1"),
            "the format's stable code is surfaced: {}",
            stderr_text(&stderr)
        );
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
    }

    #[test]
    fn materialize_record_gate_rejects_cross_family_targets() {
        // An XML source projects the xml.element-tree@1 record; a JSON target
        // is not its owning family, so the gate fails atomically with
        // core.materialization.invalid-request@1.
        let request = materialize_request(
            "3c726f6f743e783c2f726f6f743e",
            "xml.1.0-safe",
            "json.strict",
            "json.canonical-compact",
        );
        let (code, stdout, stderr) = run_request(
            &["materialize", "--profile", "xml.1.0-safe", "--json"],
            &request,
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("core.materialization.invalid-request@1"),
            "the record gate uses the shared invalid-request vocabulary"
        );
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        let result = MaterializationResultMessageV2::from_value_with_registry(
            envelope.payload(),
            ErrorCodeRegistry::v7(),
        )
        .expect("failed materialization record");
        match result.outcome() {
            consema::protocol::MaterializationOutcomeMessageV2::Failed { failure, .. } => {
                assert_eq!(failure.code(), "core.materialization.invalid-request@1");
            }
            other @ consema::protocol::MaterializationOutcomeMessageV2::Complete { .. } => {
                panic!("unexpected outcome {other:?}")
            }
        }
    }
}
