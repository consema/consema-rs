//! Audited projection-to-materialization composition.

use crate::{Document, DocumentInner, core, document, json, toml};
use core::{OperationKind, PortableValue, StableFailure};
use document::{
    CompleteMaterialization, MaterializationFidelity, MaterializationProvenanceMap,
    MaterializationReport, MaterializationRequest, ProfileId,
};
use std::collections::BTreeMap;

/// Whole-conversion semantic fidelity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConversionFidelity {
    /// Both stages retain exact portable semantics.
    Exact,
    /// At least one stage performs an authorized reversible transformation.
    Transformed,
    /// Projection contains explicitly authorized irreversible loss.
    Lossy,
}

/// Complete format-owned projection report retained without flattening facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversionProjectionReport {
    /// JSON projection report.
    Json(json::ProjectionReport),
    /// TOML projection report.
    Toml(toml::ProjectionReport),
}

/// Complete format-owned source provenance retained for local audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversionProjectionProvenance {
    /// JSON projection provenance.
    Json(json::ProvenanceMap),
    /// TOML projection provenance.
    Toml(toml::ProvenanceMap),
}

/// Complete ordered report for both conversion stages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionReport {
    projection_fidelity: ConversionFidelity,
    projection_report: ConversionProjectionReport,
    materialization_fidelity: MaterializationFidelity,
    materialization_report: MaterializationReport,
    overall_fidelity: ConversionFidelity,
    source_profile: ProfileId,
    target_profile: ProfileId,
}

impl ConversionReport {
    /// Projection-stage fidelity.
    #[must_use]
    pub const fn projection_fidelity(&self) -> ConversionFidelity {
        self.projection_fidelity
    }

    /// Complete format-owned projection report.
    #[must_use]
    pub const fn projection_report(&self) -> &ConversionProjectionReport {
        &self.projection_report
    }

    /// Materialization-stage fidelity.
    #[must_use]
    pub const fn materialization_fidelity(&self) -> MaterializationFidelity {
        self.materialization_fidelity
    }

    /// Complete ordered materialization report.
    #[must_use]
    pub const fn materialization_report(&self) -> &MaterializationReport {
        &self.materialization_report
    }

    /// Worst fidelity across both stages.
    #[must_use]
    pub const fn overall_fidelity(&self) -> ConversionFidelity {
        self.overall_fidelity
    }

    /// Exact source profile.
    #[must_use]
    pub const fn source_profile(&self) -> &ProfileId {
        &self.source_profile
    }

    /// Exact target profile.
    #[must_use]
    pub const fn target_profile(&self) -> &ProfileId {
        &self.target_profile
    }
}

/// Complete conversion result with both provenance directions kept distinct.
#[derive(Clone, Debug)]
pub struct CompleteConversion {
    /// Newly materialized target document.
    pub document: Document,
    /// Exact intermediate portable value used between the two stages.
    pub projected_value: PortableValue,
    /// Source-document-to-portable-value provenance.
    pub projection_provenance: ConversionProjectionProvenance,
    /// Portable-value-to-target-document provenance.
    pub materialization_provenance: MaterializationProvenanceMap,
    /// Complete two-stage report.
    pub report: ConversionReport,
}

impl CompleteConversion {
    /// Externalizes the complete two-stage report under semantic-model v3.
    ///
    /// Caller-assigned source IDs replace process-local snapshot identities;
    /// an event whose source node cannot be resolved from complete projection
    /// provenance fails instead of losing its location.
    pub fn protocol_report(
        &self,
        source_id: &str,
        target_source_id: &str,
    ) -> Result<crate::protocol::ConversionReportMessage, crate::protocol::ProtocolError> {
        crate::protocol::SourceLocation::new(source_id, 0, 0)?;
        crate::protocol::SourceLocation::new(target_source_id, 0, 0)?;
        let projection_report = match (&self.report.projection_report, &self.projection_provenance)
        {
            (
                ConversionProjectionReport::Json(report),
                ConversionProjectionProvenance::Json(provenance),
            ) => json_projection_report_message(report, provenance, source_id)?,
            (ConversionProjectionReport::Toml(report), ConversionProjectionProvenance::Toml(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            _ => {
                return Err(crate::protocol::ProtocolError::new(
                    crate::protocol::ProtocolErrorKind::InvalidValue,
                    "$.projection_report",
                    "projection report and provenance variants do not match the source profile",
                ));
            }
        };
        let materialization_report = crate::protocol::MaterializationReportMessage::from_report(
            &self.report.materialization_report,
            Some(target_source_id),
        )?;
        crate::protocol::ConversionReportMessage::new(
            self.report.source_profile.clone(),
            self.report.target_profile.clone(),
            conversion_fidelity_message(self.report.projection_fidelity),
            projection_report,
            self.report.materialization_fidelity,
            materialization_report,
            conversion_fidelity_message(self.report.overall_fidelity),
        )
    }

    /// Externalizes the completed target snapshot, report, and provenance.
    pub fn protocol_materialization_result<F>(
        &self,
        target_source_id: &str,
        locator: F,
    ) -> Result<crate::protocol::MaterializationResultMessage, crate::protocol::ProtocolError>
    where
        F: FnMut(document::NodeRef) -> Option<String>,
    {
        let snapshot = match &self.document.inner {
            DocumentInner::Json(document) => document.source(),
            DocumentInner::Toml(document) => document.source(),
        };
        let report = crate::protocol::MaterializationReportMessage::from_report(
            &self.report.materialization_report,
            Some(target_source_id),
        )?;
        let provenance = crate::protocol::MaterializationProvenanceMapMessage::from_provenance(
            &self.materialization_provenance,
            target_source_id,
            locator,
        )?;
        crate::protocol::MaterializationResultMessage::complete(
            self.report.target_profile.clone(),
            target_source_id,
            crate::protocol::SourceSnapshotMessage::from_snapshot(snapshot),
            self.report.materialization_fidelity,
            report,
            provenance,
        )
    }
}

/// Conversion failure without a partial target document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversionFailure {
    /// Projection did not produce a complete portable value.
    ProjectionFailed {
        /// Complete stage report produced before failure.
        report: ConversionProjectionReport,
        /// Ordered structured failure diagnostics.
        diagnostics: Vec<core::Diagnostic>,
        /// Stable locally analyzed paths.
        partial_analysis: Vec<String>,
    },
    /// Materialization did not produce target bytes or a target document.
    MaterializationFailed {
        /// Stable materialization failure.
        failure: document::MaterializationFailure,
        /// Complete stage report produced before failure.
        report: MaterializationReport,
        /// Stable portable paths analyzed before failure.
        analyzed_input_paths: Vec<core::ValuePath>,
    },
    /// A lossy projection event lacked an explicit authorizing source policy.
    UnauthorizedLoss,
}

impl StableFailure for ConversionFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Conversion
    }

    fn failure_kind(&self) -> core::FailureKind {
        match self {
            Self::ProjectionFailed { .. } | Self::MaterializationFailed { .. } => {
                core::FailureKind::NotApplicable
            }
            Self::UnauthorizedLoss => core::FailureKind::InvalidInput,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::ProjectionFailed { .. } => "core.conversion.projection-failed@1",
            Self::MaterializationFailed { .. } => "core.conversion.materialization-failed@1",
            Self::UnauthorizedLoss => "core.conversion.unauthorized-loss@1",
        }
    }
}

/// Complete or explicitly failed conversion.
#[derive(Clone, Debug)]
pub enum ConversionResult {
    /// Complete target document and all required audit artifacts.
    Complete(Box<CompleteConversion>),
    /// Failure without a target document or partial target bytes.
    Failed(ConversionFailure),
}

/// Converts one JSON document by composing its published projection and a target materializer.
#[must_use]
pub fn convert_json(
    source: &json::Document,
    projection_request: &json::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project(projection_request) {
        json::ProjectionResult::Complete(projection) => {
            if projection.fidelity == json::Fidelity::Lossy
                && projection
                    .report
                    .events()
                    .iter()
                    .any(|event| event.loss == json::Fidelity::Lossy && event.policy.is_none())
            {
                return ConversionResult::Failed(ConversionFailure::UnauthorizedLoss);
            }
            complete_conversion(
                source.profile(),
                projection.value,
                json_fidelity(projection.fidelity),
                ConversionProjectionReport::Json(projection.report),
                ConversionProjectionProvenance::Json(projection.provenance),
                materialization_request,
            )
        }
        json::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Json(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: failure.partial_analysis,
            })
        }
    }
}

/// Converts one TOML document by composing its published projection and a target materializer.
#[must_use]
pub fn convert_toml(
    source: &toml::Document,
    projection_request: toml::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project(projection_request) {
        toml::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            toml_fidelity(projection.fidelity),
            ConversionProjectionReport::Toml(projection.report),
            ConversionProjectionProvenance::Toml(projection.provenance),
            materialization_request,
        ),
        toml::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Toml(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: failure.partial_analysis,
            })
        }
    }
}

fn complete_conversion(
    source_profile: ProfileId,
    projected_value: PortableValue,
    projection_fidelity: ConversionFidelity,
    projection_report: ConversionProjectionReport,
    projection_provenance: ConversionProjectionProvenance,
    request: &MaterializationRequest,
) -> ConversionResult {
    let materialized = match materialize_target(&projected_value, request) {
        Ok(complete) => complete,
        Err(failure) => return ConversionResult::Failed(failure),
    };
    let MaterializedTarget {
        document,
        fidelity: materialization_fidelity,
        report: materialization_report,
        provenance: materialization_provenance,
    } = materialized;
    let materialization_overall = match materialization_fidelity {
        MaterializationFidelity::Exact => ConversionFidelity::Exact,
        MaterializationFidelity::Transformed => ConversionFidelity::Transformed,
    };
    ConversionResult::Complete(Box::new(CompleteConversion {
        document,
        projected_value,
        projection_provenance,
        materialization_provenance,
        report: ConversionReport {
            projection_fidelity,
            projection_report,
            materialization_fidelity,
            materialization_report,
            overall_fidelity: projection_fidelity.max(materialization_overall),
            source_profile,
            target_profile: request.target_profile().clone(),
        },
    }))
}

struct MaterializedTarget {
    document: Document,
    fidelity: MaterializationFidelity,
    report: MaterializationReport,
    provenance: MaterializationProvenanceMap,
}

fn materialize_target(
    value: &PortableValue,
    request: &MaterializationRequest,
) -> Result<MaterializedTarget, ConversionFailure> {
    match request.target_profile().id() {
        "json.strict" | "jsonc.bounded" => match json::materialize(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Json(document),
                },
                fidelity,
                report,
                provenance,
            }),
            document::MaterializationResult::Failed(failure) => {
                Err(materialization_failure(failure))
            }
        },
        "toml.1.0" => match toml::materialize(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Toml(document),
                },
                fidelity,
                report,
                provenance,
            }),
            document::MaterializationResult::Failed(failure) => {
                Err(materialization_failure(failure))
            }
        },
        _ => Err(ConversionFailure::MaterializationFailed {
            failure: document::MaterializationFailure::UnsupportedProfile,
            report: MaterializationReport::default(),
            analyzed_input_paths: Vec::new(),
        }),
    }
}

fn materialization_failure(failure: document::FailedMaterializationAttempt) -> ConversionFailure {
    ConversionFailure::MaterializationFailed {
        failure: failure.failure,
        report: failure.report,
        analyzed_input_paths: failure.analyzed_input_paths,
    }
}

const fn json_fidelity(fidelity: json::Fidelity) -> ConversionFidelity {
    match fidelity {
        json::Fidelity::Exact => ConversionFidelity::Exact,
        json::Fidelity::Transformed => ConversionFidelity::Transformed,
        json::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn toml_fidelity(fidelity: toml::Fidelity) -> ConversionFidelity {
    match fidelity {
        toml::Fidelity::Exact => ConversionFidelity::Exact,
        toml::Fidelity::Transformed => ConversionFidelity::Transformed,
        toml::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

fn json_projection_report_message(
    report: &json::ProjectionReport,
    provenance: &json::ProvenanceMap,
    source_id: &str,
) -> Result<crate::protocol::ProjectionReportMessage, crate::protocol::ProtocolError> {
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
                    crate::protocol::ProtocolError::new(
                        crate::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].source_locations"),
                        "source offset exceeds u64",
                    )
                })?;
                let end = u64::try_from(origin.span.end_byte()).map_err(|_| {
                    crate::protocol::ProtocolError::new(
                        crate::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].source_locations"),
                        "source offset exceeds u64",
                    )
                })?;
                if !locations
                    .iter()
                    .any(|location: &crate::protocol::SourceLocation| {
                        location.start_byte() == start && location.end_byte() == end
                    })
                {
                    locations.push(crate::protocol::SourceLocation::new(source_id, start, end)?);
                }
            }
            if locations.is_empty() {
                return Err(crate::protocol::ProtocolError::new(
                    crate::protocol::ProtocolErrorKind::ProcessLocalHandle,
                    format!("$.projection_report.events[{index}].source"),
                    "projection event source requires complete external provenance",
                ));
            }
            let projected_location = event.projected.as_ref().map(|location| match location {
                json::ProjectedLocation::Value(path) => {
                    crate::protocol::ProjectedLocationMessage::Value(path.clone())
                }
                json::ProjectedLocation::Association(association) => {
                    crate::protocol::ProjectedLocationMessage::Association(association.clone())
                }
            });
            let (code, event_kind) = match event.kind {
                json::ProjectionEventKind::StructureReencoded => (
                    "json.projection.structure-reencoded@1",
                    "StructureReencoded",
                ),
                json::ProjectionEventKind::DuplicateCollapsed => {
                    ("json.object.duplicate-member@1", "DuplicateCollapsed")
                }
                json::ProjectionEventKind::TypeMapped
                | json::ProjectionEventKind::KeyStringified
                | json::ProjectionEventKind::ValueRounded
                | json::ProjectionEventKind::FieldDropped => {
                    return Err(crate::protocol::ProtocolError::new(
                        crate::protocol::ProtocolErrorKind::InvalidValue,
                        format!("$.projection_report.events[{index}].kind"),
                        "event kind has no frozen semantic-model v3 wire code",
                    ));
                }
            };
            let mut arguments = BTreeMap::new();
            arguments.insert("event_kind".to_owned(), event_kind.to_owned());
            Ok(crate::protocol::ProjectionEventMessage {
                code: code.to_owned(),
                policy_rule_id: event.policy.map(json_policy_rule_id).map(str::to_owned),
                source_locations: locations,
                projected_location,
                old_category: Some(event.old_category.clone()),
                new_category: Some(event.new_category.clone()),
                reversible: event.reversible,
                loss_classification: match event.loss {
                    json::Fidelity::Exact => crate::protocol::LossClassification::None,
                    json::Fidelity::Transformed => crate::protocol::LossClassification::Reversible,
                    json::Fidelity::Lossy => crate::protocol::LossClassification::Lossy,
                },
                arguments,
            })
        })
        .collect::<Result<Vec<_>, crate::protocol::ProtocolError>>()?;
    crate::protocol::ProjectionReportMessage::new_with_registry(
        events,
        crate::protocol::ErrorCodeRegistry::v3(),
    )
}

const fn json_policy_rule_id(policy: json::DuplicateKeyPolicy) -> &'static str {
    match policy {
        json::DuplicateKeyPolicy::Reject => "json.duplicate-key.reject@1",
        json::DuplicateKeyPolicy::FirstWins => "json.duplicate-key.first-wins@1",
        json::DuplicateKeyPolicy::LastWins => "json.duplicate-key.last-wins@1",
    }
}

const fn conversion_fidelity_message(
    fidelity: ConversionFidelity,
) -> crate::protocol::ConversionFidelityMessage {
    match fidelity {
        ConversionFidelity::Exact => crate::protocol::ConversionFidelityMessage::Exact,
        ConversionFidelity::Transformed => crate::protocol::ConversionFidelityMessage::Transformed,
        ConversionFidelity::Lossy => crate::protocol::ConversionFidelityMessage::Lossy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;
    use document::{MappingPolicy, MaterializationStyleId, NewlinePolicy, ParseLimits};
    use json::{DuplicateKeyPolicy, ProjectionRequestBuilder};
    use std::collections::HashMap;

    fn projection_provenance_json(complete: &CompleteConversion) -> &[json::ProvenanceEntry] {
        match &complete.projection_provenance {
            ConversionProjectionProvenance::Json(provenance) => provenance.entries(),
            ConversionProjectionProvenance::Toml(_) => &[],
        }
    }

    fn toml_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("toml.1.0", 1),
            MaterializationStyleId::new("toml.canonical-document", 1),
        )
        .with_newline(NewlinePolicy::Lf)
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
    }

    fn json_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("json.strict", 1),
            MaterializationStyleId::new("json.canonical-compact", 1),
        )
        .with_newline(NewlinePolicy::None)
    }

    #[test]
    fn json_to_toml_keeps_both_stages_and_exact_target_closure() {
        let source = json::parse(
            br#"{"service":{"port":8080,"enabled":true}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ConversionResult::Complete(complete) =
            convert_json(&source, &projection, &toml_request())
        else {
            panic!("complete conversion expected")
        };
        assert_eq!(
            complete.document.render(),
            b"\"service\" = { \"port\" = 8080, \"enabled\" = true }\n"
        );
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert_eq!(
            complete.report.source_profile(),
            &ProfileId::new("json.strict", 1)
        );
        assert_eq!(
            complete.report.target_profile(),
            &ProfileId::new("toml.1.0", 1)
        );
        assert!(!projection_provenance_json(&complete).is_empty());
        assert!(!complete.materialization_provenance.entries().is_empty());

        let protocol_report = complete
            .protocol_report("source:json", "target:toml")
            .unwrap();
        assert_eq!(
            protocol::ConversionReportMessage::from_value(&protocol_report.to_value()).unwrap(),
            protocol_report
        );
        let mut locators = HashMap::new();
        let mut next_locator = 0_u64;
        let materialization = complete
            .protocol_materialization_result("target:toml", |node| {
                Some(
                    locators
                        .entry(node)
                        .or_insert_with(|| {
                            let locator = format!("toml:node:{next_locator}");
                            next_locator += 1;
                            locator
                        })
                        .clone(),
                )
            })
            .unwrap();
        assert_eq!(
            protocol::MaterializationResultMessage::from_value(&materialization.to_value())
                .unwrap(),
            materialization
        );
    }

    #[test]
    fn toml_to_json_is_exact_and_materialization_failure_has_no_document() {
        let source = toml::parse(
            b"name = \"api\"\nports = [80, 443]\n".as_slice(),
            toml::TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = toml::ProjectionRequest::new(toml::ProjectionTarget::BestExactCoreV1);
        let ConversionResult::Complete(complete) =
            convert_toml(&source, projection, &json_request())
        else {
            panic!("complete conversion expected")
        };
        assert_eq!(
            complete.document.render(),
            br#"{"name":"api","ports":[80,443]}"#
        );
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Exact
        );

        let temporal = toml::parse(
            b"when = 1979-05-27\n".as_slice(),
            toml::TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_toml(&temporal, projection, &json_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::Unrepresentable { .. },
                ..
            })
        ));
    }

    #[test]
    fn explicitly_lossy_json_projection_remains_observable() {
        let source = json::parse(
            br#"{"a":1,"a":2}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::ProjectAsObjectV1)
            .global_duplicate_policy(DuplicateKeyPolicy::LastWins)
            .build()
            .unwrap();
        let ConversionResult::Complete(complete) =
            convert_json(&source, &projection, &toml_request())
        else {
            panic!("explicitly authorized loss should complete")
        };
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Lossy
        );
        let ConversionProjectionReport::Json(report) = complete.report.projection_report() else {
            panic!("JSON report expected")
        };
        assert_eq!(report.events().len(), 1);
    }

    #[test]
    fn transformed_conversion_report_externalizes_both_authorized_events() {
        let source = json::parse(
            br#"{"name":"api"}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection =
            ProjectionRequestBuilder::new(json::ProjectionTarget::ProjectAsEntryMappingV1)
                .build()
                .unwrap();
        let ConversionResult::Complete(complete) =
            convert_json(&source, &projection, &toml_request())
        else {
            panic!("complete transformed conversion expected")
        };
        let report = complete
            .protocol_report("source:json", "target:toml")
            .unwrap();
        assert_eq!(
            report.overall_fidelity(),
            protocol::ConversionFidelityMessage::Transformed
        );
        assert_eq!(
            report.projection_report().events()[0].code,
            "json.projection.structure-reencoded@1"
        );
        assert_eq!(
            report.materialization_report().events()[0].code,
            "core.materialization.mapping-transformed@1"
        );
    }
}
