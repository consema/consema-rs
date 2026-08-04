//! Audited projection-to-materialization composition.

use crate::{Document, DocumentInner, core, document, json, toml};
use core::{OperationKind, PortableValue, StableFailure};
use document::{
    CompleteMaterialization, MaterializationFidelity, MaterializationProvenanceMap,
    MaterializationReport, MaterializationRequest, ProfileId,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use document::{MappingPolicy, MaterializationStyleId, NewlinePolicy, ParseLimits};
    use json::{DuplicateKeyPolicy, ProjectionRequestBuilder};

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
}
