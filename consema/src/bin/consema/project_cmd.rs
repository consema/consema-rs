//! `consema project` and the wire-to-typed projection request mapping shared
//! with the convert command.
//!
//! The request is the strict `cli.request@1` wrapper of `query_cmd.rs` with
//! payload `core.projection-request@1`. The generic wire request (target
//! contract + default policy + rules + limits) is mapped onto the typed
//! per-format projection requests of the facade (hard gate 1: the CLI never
//! re-implements projection semantics, it only selects published targets and
//! policies). The mapping table is the CLI's only projection knowledge and
//! every entry is a published format target; the conservative default policy
//! (`core.projection.exact-or-reject@1`, no rules, no limits) is the SDK's
//! own default, never invented (roadmap §10 line 818).
//!
//! The machine payload is the `core.projection-result@1` record (RFC 0015
//! §6.1): value, fidelity, report, and provenance, externalized from the
//! format-owned results. Milestone M5 wires the report/provenance
//! externalization for the baseline formats whose reports are closed
//! (JSON structured events, TOML diagnostics); the other formats are
//! rejected with an explicit data error rather than emitting an incomplete
//! record.

use crate::args::ParsedArgs;
use consema::core::Diagnostic;
use consema::protocol::{
    CliCommand, Completion, CompletionStatus, ErrorCodeRegistry, ExitClass, LossClassification,
    ProjectedLocationMessage, ProjectionEventMessage, ProjectionFidelity, ProjectionPolicy,
    ProjectionReportMessage, ProjectionRequestMessage, ProjectionResultMessage,
    ProvenanceEntryMessage, ProvenanceMapMessage, ProvenanceRelation, SourceOriginMessage,
};
use std::collections::BTreeMap;
use std::io::Write;

use crate::query_cmd::{
    FlowError, RequestInput, WireProjectionRequest, bind_diagnostics, decode_request,
    emit_envelope, emit_failure, format_family, internal_failure, minimal_record, parse_document,
    protocol_error, read_request_bytes, render_value, require_complete,
};

/// The conservative default policy contract of the wire request.
const EXACT_OR_REJECT_CONTRACT: (&str, u32) = ("core.projection.exact-or-reject", 1);

/// Maps the wire projection request onto the typed per-format request.
///
/// The `target` contract selects one published format projection target; the
/// default policy must be the conservative exact-or-reject default; rules and
/// named limits are not mapped by milestone M5 and are rejected as data
/// errors instead of being silently ignored (no half-success, roadmap §3.4).
pub(crate) fn wire_projection_request(
    source_family: &str,
    message: &ProjectionRequestMessage,
) -> Result<WireProjectionRequest, FlowError> {
    let target = message.target();
    let family = match source_family {
        "json" | "toml" | "ini" | "properties" | "yaml" | "xml" | "plist" | "hcl" => source_family,
        other => {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                format!(
                    "projection target '{}' does not apply to family '{other}'",
                    target.id()
                ),
            ));
        }
    };
    // The java-properties family's published projection targets are
    // namespaced `java-properties.projection.*` (RFC 0010) while its wire
    // family name is "properties" (the facade conversion boundary,
    // `query_cmd::format_family`); the family-prefix check needs the special
    // case or every java-properties target is rejected (B-6).
    let mut prefix = format!("{family}.projection.");
    if family == "properties" {
        "java-properties.projection.".clone_into(&mut prefix);
    }
    if !target.id().starts_with(&prefix) {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "projection target '{}' does not belong to the '{family}' format family",
                target.id()
            ),
        ));
    }
    validate_default_policy(message.default_policy())?;
    if !message.rules().is_empty() {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "projection rules are not mapped by milestone M5 (targets and the default policy \
             only); refusing instead of silently ignoring them",
        ));
    }
    if !message.limits().is_empty() {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "projection named limits are not mapped by milestone M5 (format-owned limits only); \
             refusing instead of silently ignoring them",
        ));
    }
    build_wire_request(family, target.id(), target.version())
}

/// The default policy must be the conservative exact-or-reject contract with
/// no arguments; any other policy is rejected (the CLI never invents loss
/// authorization, RFC 0015 §2.2).
fn validate_default_policy(policy: &ProjectionPolicy) -> Result<(), FlowError> {
    if policy.contract().id() == EXACT_OR_REJECT_CONTRACT.0
        && policy.contract().version() == EXACT_OR_REJECT_CONTRACT.1
        && policy.arguments().is_empty()
    {
        return Ok(());
    }
    Err(FlowError::new(
        "cli.data.invalid-request@1",
        format!(
            "projection policy '{}{}' is not mapped by milestone M5 (only the conservative \
             exact-or-reject default is wired)",
            policy.contract().id(),
            policy.contract().version()
        ),
    ))
}

/// Constructs one typed per-format request from the published target table.
fn build_wire_request(
    family: &str,
    target_id: &str,
    version: u32,
) -> Result<WireProjectionRequest, FlowError> {
    let request = match (family, target_id, version) {
        ("json", "json.projection.project-as-object", 1) => WireProjectionRequest::Json(
            json_target(consema::json::ProjectionTarget::ProjectAsObjectV1)?,
        ),
        ("json", "json.projection.project-as-entry-mapping", 1) => WireProjectionRequest::Json(
            json_target(consema::json::ProjectionTarget::ProjectAsEntryMappingV1)?,
        ),
        ("json", "json.projection.best-exact-core", 1) => WireProjectionRequest::Json(json_target(
            consema::json::ProjectionTarget::BestExactCoreV1,
        )?),
        ("json", "json.projection.json5-best-exact-core", 1) => WireProjectionRequest::Json(
            json_target(consema::json::ProjectionTarget::Json5BestExactCoreV1)?,
        ),
        ("toml", "toml.projection.best-exact-core", 1) => WireProjectionRequest::Toml(
            consema::toml::ProjectionRequest::new(consema::toml::ProjectionTarget::BestExactCoreV1),
        ),
        ("ini", "ini.projection.best-exact-entry-mapping", 1) => {
            WireProjectionRequest::Ini(consema::ini::ProjectionRequest::best_exact_entry_mapping())
        }
        ("ini", "ini.projection.require-object", 1) => {
            WireProjectionRequest::Ini(consema::ini::ProjectionRequest::require_object(
                consema::ini::NameComparison::OriginalExact,
                consema::ini::CollisionPolicy::Reject,
            ))
        }
        ("properties", "java-properties.projection.best-exact-entry-mapping", 1) => {
            WireProjectionRequest::Properties(
                consema::properties::ProjectionRequest::best_exact_entry_mapping(),
            )
        }
        ("properties", "java-properties.projection.require-object", 1) => {
            WireProjectionRequest::Properties(
                consema::properties::ProjectionRequest::require_object(
                    consema::properties::DuplicatePolicy::RequireUnique,
                ),
            )
        }
        ("yaml", "yaml.projection.best-exact-value", 1) => {
            WireProjectionRequest::Yaml(consema::yaml::ValueProjectionRequest::best_exact_v1())
        }
        ("xml", "xml.projection.element-tree", 1) => {
            WireProjectionRequest::Xml(consema::xml::ProjectionRequest::element_tree())
        }
        ("plist", "plist.projection.value-tree", 1) => {
            WireProjectionRequest::Plist(consema::plist::ProjectionRequest::value_tree())
        }
        ("hcl", "hcl.projection.body", 1) => {
            WireProjectionRequest::Hcl(consema::hcl::ProjectionRequest::body())
        }
        _ => {
            return Err(FlowError::new(
                "cli.data.invalid-request@1",
                format!("projection target '{target_id}'@{version} is not published by this build"),
            ));
        }
    };
    Ok(request)
}

fn json_target(
    target: consema::json::ProjectionTarget,
) -> Result<consema::json::ProjectionRequest, FlowError> {
    consema::json::ProjectionRequestBuilder::new(target)
        .build()
        .map_err(|failure| {
            crate::query_cmd::stable_failure(
                &failure,
                "JSON projection request is invalid".to_owned(),
            )
        })
}

/// Runs `consema project` (request from `--request-file` or stdin).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Project, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, stdout, stderr)
}

/// Runs `consema project` against already-read request bytes.
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let input = match decode_request(request, parsed, "core.projection-request@1") {
        Ok(input) => input,
        Err(error) => return emit_failure(CliCommand::Project, parsed, &error, stdout, stderr),
    };
    match execute_project(&input) {
        Ok(result) => {
            if parsed.json {
                match emit_envelope(
                    CliCommand::Project,
                    ExitClass::Success,
                    result.to_value(),
                    Vec::new(),
                    parsed,
                    stdout,
                ) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("project", &message, stderr),
                }
            } else {
                let value = result
                    .value()
                    .expect("successful projection always carries a value");
                match writeln!(stdout, "{}", render_value(value)) {
                    Ok(()) => ExitClass::Success.exit_code(),
                    Err(message) => internal_failure("project", &message.to_string(), stderr),
                }
            }
        }
        Err(error) => emit_failure(CliCommand::Project, parsed, &error, stdout, stderr),
    }
}

/// Executes the request's projection, returning the complete or failed
/// `core.projection-result@1` message.
fn execute_project(input: &RequestInput) -> Result<ProjectionResultMessage, FlowError> {
    let family = format_family(input.profile.id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("profile '{}' has no format family", input.profile.id()),
        )
    })?;
    if !matches!(family, "json" | "toml") {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "the project command is not wired for the '{family}' family in milestone M5 \
                 (its report/provenance externalization is not yet implemented); refusing \
                 instead of emitting an incomplete record"
            ),
        ));
    }
    let message = ProjectionRequestMessage::from_value(&input.payload).map_err(protocol_error)?;
    let request = wire_projection_request(family, &message)?;
    let document = parse_document(input.source.clone(), &input.profile)?;
    require_complete(&document, &input.source_label)?;
    let source_label = input.source_label.as_str();
    match request {
        WireProjectionRequest::Json(request) => {
            let document = document
                .as_json()
                .expect("profile family matches the adapter");
            match document.project(&request) {
                consema::json::ProjectionResult::Complete(projection) => {
                    let report = json_report_message(
                        &projection.report,
                        &projection.provenance,
                        source_label,
                    )
                    .map_err(|error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("projection report externalization failed: {error}"),
                        )
                    })?;
                    let provenance = json_provenance_message(&projection.provenance, source_label)
                        .map_err(|error| {
                            FlowError::new(
                                error.kind().code(),
                                format!("projection provenance externalization failed: {error}"),
                            )
                        })?;
                    let completion = Completion::new_with_registry(
                        CompletionStatus::Success,
                        1,
                        1,
                        None,
                        None,
                        ErrorCodeRegistry::v7(),
                    )
                    .map_err(|error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("completion encoding failed: {error}"),
                        )
                    })?;
                    ProjectionResultMessage::new(
                        completion,
                        Some(projection.value),
                        Some(json_fidelity(projection.fidelity)),
                        report,
                        provenance,
                        Vec::new(),
                    )
                    .map_err(|error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("projection result encoding failed: {error}"),
                        )
                    })
                }
                consema::json::ProjectionResult::Failed(failure) => {
                    Err(projection_attempt_failure(
                        &failure.diagnostics,
                        "JSON projection failed",
                        json_report_message(
                            &failure.report,
                            &consema::json::ProvenanceMap::default(),
                            source_label,
                        )
                        .unwrap_or_default(),
                    ))
                }
            }
        }
        WireProjectionRequest::Toml(request) => {
            let document = document
                .as_toml()
                .expect("profile family matches the adapter");
            match document.project(request) {
                consema::toml::ProjectionResult::Complete(projection) => {
                    let report = toml_report_message(&projection.report)?;
                    let provenance = toml_provenance_message(&projection.provenance, source_label)
                        .map_err(|error| {
                            FlowError::new(
                                error.kind().code(),
                                format!("projection provenance externalization failed: {error}"),
                            )
                        })?;
                    let completion = Completion::new_with_registry(
                        CompletionStatus::Success,
                        1,
                        1,
                        None,
                        None,
                        ErrorCodeRegistry::v7(),
                    )
                    .map_err(|error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("completion encoding failed: {error}"),
                        )
                    })?;
                    ProjectionResultMessage::new(
                        completion,
                        Some(projection.value),
                        Some(toml_fidelity(projection.fidelity)),
                        report,
                        provenance,
                        Vec::new(),
                    )
                    .map_err(|error| {
                        FlowError::new(
                            error.kind().code(),
                            format!("projection result encoding failed: {error}"),
                        )
                    })
                }
                consema::toml::ProjectionResult::Failed(failure) => {
                    Err(projection_attempt_failure(
                        &failure.diagnostics,
                        "TOML projection failed",
                        toml_report_message(&failure.report).unwrap_or_default(),
                    ))
                }
            }
        }
        WireProjectionRequest::Ini(_)
        | WireProjectionRequest::Properties(_)
        | WireProjectionRequest::Yaml(_)
        | WireProjectionRequest::Xml(_)
        | WireProjectionRequest::Plist(_)
        | WireProjectionRequest::Hcl(_) => unreachable!("family gated to json/toml above"),
    }
}

/// Builds the failed `core.projection-result@1` record: completion Failed
/// with the format's stable code, the partial report, no value or
/// provenance, and the attempt diagnostics.
fn projection_attempt_failure(
    diagnostics: &[Diagnostic],
    fallback: &str,
    report: ProjectionReportMessage,
) -> FlowError {
    let code = diagnostics
        .first()
        .map_or("core.projection.target-not-applicable@1", |diagnostic| {
            diagnostic.code.as_str()
        });
    let completion = Completion::new_with_registry(
        CompletionStatus::Failed,
        0,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v7(),
    )
    .expect("format projection codes are registered in v7");
    let payload = ProjectionResultMessage::new(
        completion,
        None,
        None,
        report,
        ProvenanceMapMessage::default(),
        bind_diagnostics(diagnostics, None),
    )
    .map_or_else(
        |_| minimal_record(CliCommand::Project),
        |message| message.to_value(),
    );
    FlowError::new(code, fallback).with_payload(payload)
}

/// Externalizes one JSON projection report (mirrors the facade's own
/// externalization pattern in conversion.rs; pure fact translation).
fn json_report_message(
    report: &consema::json::ProjectionReport,
    provenance: &consema::json::ProvenanceMap,
    source_id: &str,
) -> Result<ProjectionReportMessage, consema::protocol::ProtocolError> {
    let events = report
        .events()
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let mut locations = Vec::new();
            for origin in provenance
                .entries()
                .iter()
                .flat_map(|entry| entry.origins.iter())
                .filter(|origin| origin.node == event.source)
            {
                let start = u64::try_from(origin.span.start_byte()).map_err(|_| {
                    consema::protocol::ProtocolError::new(
                        consema::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].source_locations"),
                        "source offset exceeds u64",
                    )
                })?;
                let end = u64::try_from(origin.span.end_byte()).map_err(|_| {
                    consema::protocol::ProtocolError::new(
                        consema::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].source_locations"),
                        "source offset exceeds u64",
                    )
                })?;
                if !locations
                    .iter()
                    .any(|location: &consema::protocol::SourceLocation| {
                        location.start_byte() == start && location.end_byte() == end
                    })
                {
                    locations.push(consema::protocol::SourceLocation::new(
                        source_id, start, end,
                    )?);
                }
            }
            if locations.is_empty() {
                return Err(consema::protocol::ProtocolError::new(
                    consema::protocol::ProtocolErrorKind::ProcessLocalHandle,
                    format!("$.projection_report.events[{index}].source"),
                    "projection event source requires complete external provenance",
                ));
            }
            let projected_location = event.projected.as_ref().map(|location| match location {
                consema::json::ProjectedLocation::Value(path) => {
                    ProjectedLocationMessage::Value(path.clone())
                }
                consema::json::ProjectedLocation::Association(association) => {
                    ProjectedLocationMessage::Association(association.clone())
                }
            });
            let (code, event_kind) = match event.kind {
                consema::json::ProjectionEventKind::StructureReencoded => (
                    "json.projection.structure-reencoded@1",
                    "StructureReencoded",
                ),
                consema::json::ProjectionEventKind::DuplicateCollapsed => {
                    ("json.object.duplicate-member@1", "DuplicateCollapsed")
                }
                consema::json::ProjectionEventKind::TypeMapped
                | consema::json::ProjectionEventKind::KeyStringified
                | consema::json::ProjectionEventKind::ValueRounded
                | consema::json::ProjectionEventKind::FieldDropped => {
                    return Err(consema::protocol::ProtocolError::new(
                        consema::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].kind"),
                        "event kind has no frozen semantic-model wire code",
                    ));
                }
            };
            let mut arguments = BTreeMap::new();
            arguments.insert("event_kind".to_owned(), event_kind.to_owned());
            Ok(ProjectionEventMessage {
                code: code.to_owned(),
                policy_rule_id: event.policy.map(json_policy_rule_id).map(str::to_owned),
                source_locations: locations,
                projected_location,
                old_category: Some(event.old_category.clone()),
                new_category: Some(event.new_category.clone()),
                reversible: event.reversible,
                loss_classification: match event.loss {
                    consema::json::Fidelity::Exact => LossClassification::None,
                    consema::json::Fidelity::Transformed => LossClassification::Reversible,
                    consema::json::Fidelity::Lossy => LossClassification::Lossy,
                },
                arguments,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ProjectionReportMessage::new_with_registry(events, ErrorCodeRegistry::v7())
}

const fn json_policy_rule_id(policy: consema::json::DuplicateKeyPolicy) -> &'static str {
    match policy {
        consema::json::DuplicateKeyPolicy::Reject => "json.duplicate-key.reject@1",
        consema::json::DuplicateKeyPolicy::FirstWins => "json.duplicate-key.first-wins@1",
        consema::json::DuplicateKeyPolicy::LastWins => "json.duplicate-key.last-wins@1",
    }
}

/// Externalizes one JSON provenance map (sorted, merged, locator-free).
fn json_provenance_message(
    provenance: &consema::json::ProvenanceMap,
    source_id: &str,
) -> Result<ProvenanceMapMessage, consema::protocol::ProtocolError> {
    provenance_message(
        provenance.entries(),
        |entry| match &entry.projected {
            consema::json::ProjectedLocation::Value(path) => {
                ProjectedLocationMessage::Value(path.clone())
            }
            consema::json::ProjectedLocation::Association(association) => {
                ProjectedLocationMessage::Association(association.clone())
            }
        },
        |entry| {
            entry
                .origins
                .iter()
                .map(|origin| {
                    (
                        origin.span.start_byte(),
                        origin.span.end_byte(),
                        match origin.relation {
                            consema::json::ProvenanceRelation::Direct => ProvenanceRelation::Direct,
                            consema::json::ProvenanceRelation::Derived => {
                                ProvenanceRelation::Derived
                            }
                            consema::json::ProvenanceRelation::Expanded => {
                                ProvenanceRelation::Expanded
                            }
                            consema::json::ProvenanceRelation::Merged => ProvenanceRelation::Merged,
                            consema::json::ProvenanceRelation::Generated => {
                                ProvenanceRelation::Generated
                            }
                        },
                    )
                })
                .collect::<Vec<_>>()
        },
        source_id,
    )
}

/// Externalizes one TOML provenance map (its relation set is Direct/Derived).
fn toml_provenance_message(
    provenance: &consema::toml::ProvenanceMap,
    source_id: &str,
) -> Result<ProvenanceMapMessage, consema::protocol::ProtocolError> {
    provenance_message(
        provenance.entries(),
        |entry| match &entry.projected {
            consema::toml::ProjectedLocation::Value(path) => {
                ProjectedLocationMessage::Value(path.clone())
            }
            consema::toml::ProjectedLocation::Association(association) => {
                ProjectedLocationMessage::Association(association.clone())
            }
        },
        |entry| {
            entry
                .origins
                .iter()
                .map(|origin| {
                    (
                        origin.span.start_byte(),
                        origin.span.end_byte(),
                        match origin.relation {
                            consema::toml::ProvenanceRelation::Direct => ProvenanceRelation::Direct,
                            consema::toml::ProvenanceRelation::Derived => {
                                ProvenanceRelation::Derived
                            }
                        },
                    )
                })
                .collect::<Vec<_>>()
        },
        source_id,
    )
}

/// The shared provenance externalization: entries sorted by projected
/// location (the protocol map requires sorted unique locations; the format
/// maps are traversal-ordered), equal locations merged, origins bound to the
/// source label with byte spans and no process-local identities.
#[allow(clippy::type_complexity)]
fn provenance_message<E, P, O>(
    entries: &[E],
    projected: P,
    origins_of: O,
    source_id: &str,
) -> Result<ProvenanceMapMessage, consema::protocol::ProtocolError>
where
    P: Fn(&E) -> ProjectedLocationMessage,
    O: Fn(&E) -> Vec<(usize, usize, ProvenanceRelation)>,
{
    let mut messages: Vec<ProvenanceEntryMessage> = Vec::new();
    for entry in entries {
        let mut origins = Vec::new();
        for (start, end, relation) in origins_of(entry) {
            origins.push(SourceOriginMessage::new(
                source_id,
                None,
                u64::try_from(start).map_err(|_| {
                    consema::protocol::ProtocolError::new(
                        consema::protocol::ProtocolErrorKind::InvalidValue,
                        "$.entries[].origins[].start_byte",
                        "source offset exceeds u64",
                    )
                })?,
                u64::try_from(end).map_err(|_| {
                    consema::protocol::ProtocolError::new(
                        consema::protocol::ProtocolErrorKind::InvalidValue,
                        "$.entries[].origins[].end_byte",
                        "source offset exceeds u64",
                    )
                })?,
                relation,
            )?);
        }
        messages.push(ProvenanceEntryMessage {
            projected: projected(entry),
            origins,
        });
    }
    messages.sort_by(|left, right| left.projected.cmp(&right.projected));
    let mut merged: Vec<ProvenanceEntryMessage> = Vec::new();
    for message in messages {
        if let Some(last) = merged.last_mut() {
            if last.projected == message.projected {
                last.origins.extend(message.origins);
                continue;
            }
        }
        merged.push(message);
    }
    ProvenanceMapMessage::new(merged)
}

/// TOML projection reports are closed (`core::Diagnostic` events; module docs
/// of the format state that exact TOML 1.0 projections emit no events, so the
/// report is empty in practice). A non-empty TOML report cannot be
/// externalized without loss semantics and is refused.
fn toml_report_message(
    report: &consema::toml::ProjectionReport,
) -> Result<ProjectionReportMessage, FlowError> {
    if report.events().is_empty() {
        return Ok(ProjectionReportMessage::default());
    }
    let code = report.events().first().map_or_else(
        || "cli.data.invalid-request@1".to_owned(),
        |diagnostic| diagnostic.code.clone(),
    );
    Err(FlowError::new(
        code,
        "non-empty TOML projection reports are not externalizable by milestone M5",
    ))
}

const fn json_fidelity(fidelity: consema::json::Fidelity) -> ProjectionFidelity {
    match fidelity {
        consema::json::Fidelity::Exact => ProjectionFidelity::Exact,
        consema::json::Fidelity::Transformed => ProjectionFidelity::Transformed,
        consema::json::Fidelity::Lossy => ProjectionFidelity::Lossy,
    }
}

const fn toml_fidelity(fidelity: consema::toml::Fidelity) -> ProjectionFidelity {
    match fidelity {
        consema::toml::Fidelity::Exact => ProjectionFidelity::Exact,
        consema::toml::Fidelity::Transformed => ProjectionFidelity::Transformed,
        consema::toml::Fidelity::Lossy => ProjectionFidelity::Lossy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::{BigInteger, ObjectBuilder, PortableValue};
    use consema::protocol::{CliOutputMessage, ProtocolLimits, encode_json};

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

    /// Builds one strict `cli.request@1` wrapper with a projection-request
    /// payload for the given target contract.
    fn project_request(source_hex: &str, profile_id: &str, target_id: &str) -> Vec<u8> {
        let mut target = ObjectBuilder::new();
        target
            .insert("id", PortableValue::string(target_id))
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
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("core.projection-request@1"))
            .expect("unique");
        payload.insert("target", target_value).expect("unique");
        payload
            .insert("default_policy", default_policy.build())
            .expect("unique");
        let rules = consema::core::SequenceBuilder::new();
        payload.insert("rules", rules.build()).expect("unique");
        let limits = ObjectBuilder::new();
        payload.insert("limits", limits.build()).expect("unique");

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
        wrapper.insert("payload", payload.build()).expect("unique");
        encode_json(&wrapper.build(), ProtocolLimits::default()).expect("canonical bytes")
    }

    #[test]
    fn project_json_success_round_trips_and_is_byte_deterministic() {
        // `{"a":1,"b":2}` under best-exact-core: an exact Object value.
        let request = project_request(
            "7b2261223a312c2262223a327d",
            "json.strict",
            "json.projection.best-exact-core",
        );
        let (code, stdout, stderr) =
            run_request(&["project", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        let limits = ProtocolLimits::default();
        let envelope_bytes = &stdout[..stdout.len() - 1];
        let envelope = CliOutputMessage::from_json(envelope_bytes, limits).expect("envelope");
        assert_eq!(envelope.command(), CliCommand::Project);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            envelope_bytes,
            "stdout envelope must be byte-deterministic"
        );
        // Round-trip through the typed projection decoder.
        let result = ProjectionResultMessage::from_value(envelope.payload())
            .expect("projection-result record");
        assert_eq!(result.completion().status(), CompletionStatus::Success);
        assert_eq!(result.fidelity(), Some(ProjectionFidelity::Exact));
        let value = result.value().expect("projected value");
        assert_eq!(
            value.as_object().map(<[consema::core::ObjectEntry]>::len),
            Some(2)
        );
        // Provenance is externalized with byte spans and no locators.
        assert!(!result.provenance().entries().is_empty());
        assert!(result.provenance().entries().iter().all(|entry| {
            entry
                .origins
                .iter()
                .all(|origin| origin.node_locator.is_none())
        }));
    }

    #[test]
    fn project_json_duplicate_keys_fail_as_data_error() {
        // `{"a":1,"a":2}` under project-as-object (Reject): the projection
        // fails with the format's stable duplicate-keys code.
        let request = project_request(
            "7b2261223a312c2261223a327d",
            "json.strict",
            "json.projection.project-as-object",
        );
        let (code, stdout, stderr) =
            run_request(&["project", "--profile", "json.strict", "--json"], &request);
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("json.projection.duplicate-keys@1"),
            "the format's stable code is surfaced"
        );
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        let result = ProjectionResultMessage::from_value(envelope.payload())
            .expect("failed projection record");
        assert_eq!(result.completion().status(), CompletionStatus::Failed);
        assert_eq!(result.value(), None);
        assert!(!envelope.diagnostics().is_empty());
    }

    #[test]
    fn project_toml_success_maps_entry_mapping() {
        // `value = 1` under best-exact-core: an EntryMapping value.
        let request = project_request(
            "76616c7565203d20310a",
            "toml.1.0",
            "toml.projection.best-exact-core",
        );
        let (code, stdout, _) =
            run_request(&["project", "--profile", "toml.1.0", "--json"], &request);
        assert_eq!(code, 0);
        let limits = ProtocolLimits::default();
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], limits).expect("envelope");
        let result = ProjectionResultMessage::from_value(envelope.payload())
            .expect("projection-result record");
        assert_eq!(result.completion().status(), CompletionStatus::Success);
        assert_eq!(result.fidelity(), Some(ProjectionFidelity::Exact));
        let value = result.value().expect("projected value");
        assert!(
            value.as_object().is_some(),
            "TOML core projection maps the root table to an Object: {value:?}"
        );
    }

    #[test]
    fn project_usage_and_data_rejections() {
        // Unknown --profile -> usage exit 1, no envelope.
        let request = project_request("7b7d", "json.strict", "json.projection.best-exact-core");
        let (code, stdout, stderr) =
            run_request(&["project", "--profile", "json.bogus", "--json"], &request);
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(stderr_text(&stderr).contains("unknown profile 'json.bogus'"));

        // A target outside the family -> data error.
        let (code, _, stderr) = run_request(
            &["project", "--profile", "json.strict", "--json"],
            &project_request("7b7d", "json.strict", "toml.projection.best-exact-core"),
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("does not belong to the 'json' format family"));

        // An unknown target -> data error.
        let (code, _, stderr) = run_request(
            &["project", "--profile", "json.strict", "--json"],
            &project_request("7b7d", "json.strict", "json.projection.frobnicate"),
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("not published by this build"));
    }

    #[test]
    fn wire_projection_request_accepts_published_java_properties_targets() {
        // B-6: the properties family's published targets are namespaced
        // `java-properties.projection.*` (RFC 0010); the family-prefix check
        // must accept them for the wire family "properties".
        let parsed = parse(&["project", "--profile", "java-properties.reader"]);
        let decode = |target_id: &str| {
            let request =
                project_request("6e616d653d6170690a", "java-properties.reader", target_id);
            match crate::query_cmd::decode_request(&request, &parsed, "core.projection-request@1") {
                Ok(input) => ProjectionRequestMessage::from_value(&input.payload)
                    .expect("projection request"),
                Err(error) => panic!("strict request decodes: {}", error.message),
            }
        };
        let mapped = wire_projection_request(
            "properties",
            &decode("java-properties.projection.best-exact-entry-mapping"),
        );
        assert!(
            matches!(mapped, Ok(WireProjectionRequest::Properties(_))),
            "the published java-properties target maps for the properties family"
        );

        let mapped = wire_projection_request(
            "properties",
            &decode("java-properties.projection.require-object"),
        );
        assert!(
            matches!(mapped, Ok(WireProjectionRequest::Properties(_))),
            "require-object maps for the properties family"
        );

        // A target of another family stays rejected.
        match wire_projection_request("properties", &decode("toml.projection.best-exact-core")) {
            Ok(_) => panic!("a toml target does not belong to the properties family"),
            Err(error) => assert_eq!(error.code, "cli.data.invalid-request@1"),
        }
    }

    #[test]
    fn project_java_properties_source_is_refused_at_the_family_gate() {
        // The wire mapping now accepts java-properties targets (B-6), so the
        // only remaining blocker for `consema project` is the documented
        // milestone-M5 family gate (B-3): non-json/toml families are refused
        // with an explicit data error, never the target-prefix rejection.
        let request = project_request(
            "6e616d653d6170690a",
            "java-properties.reader",
            "java-properties.projection.best-exact-entry-mapping",
        );
        let (code, stdout, stderr) = run_request(
            &["project", "--profile", "java-properties.reader", "--json"],
            &request,
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("not wired for the 'properties' family"),
            "the family gate is the documented boundary (B-3): {}",
            stderr_text(&stderr)
        );
        assert!(
            !stderr_text(&stderr).contains("does not belong"),
            "the prefix check must not be the rejection reason"
        );
        let envelope =
            CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
                .expect("data-error envelope");
        assert_eq!(envelope.exit_class(), ExitClass::Data);
    }

    #[test]
    fn project_recovered_source_is_a_data_error() {
        // Recovered INI source: project must fail (Recovered never projects).
        let mut source = ObjectBuilder::new();
        source
            .insert("kind", PortableValue::string("bytes"))
            .expect("unique");
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
            .insert(
                "schema",
                PortableValue::string(crate::query_cmd::REQUEST_SCHEMA),
            )
            .expect("unique");
        wrapper.insert("source", source.build()).expect("unique");
        wrapper.insert("profile", profile.build()).expect("unique");
        // A minimal (schema-only) payload: the family gate rejects ini before
        // the payload is consulted, but the wrapper decode still needs the
        // core.projection-request@1 schema.
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("core.projection-request@1"))
            .expect("unique");
        wrapper.insert("payload", payload.build()).expect("unique");
        let request = encode_json(&wrapper.build(), ProtocolLimits::default()).expect("bytes");
        let (code, _, stderr) = run_request(
            &["project", "--profile", "ini.portable", "--json"],
            &request,
        );
        // The ini family is not wired for project in M5, so the rejection is
        // the family gate (data error), not the recovered-state rejection.
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("not wired for the 'ini' family"));
    }
}
