//! Audited projection-to-materialization composition.
//!
//! Every `convert_*` function composes one format-owned projection and the
//! requested target materializer, retaining the intermediate portable value,
//! both provenance directions, and the two-stage report. The composition
//! never invents a cross-format convention: the baseline formats (JSON,
//! TOML, YAML, INI, Java Properties) project plain portable values, while
//! the record formats (XML, plist, HCL) project versioned internal records
//! (`xml.element-tree@1`, `plist.value-tree@1`, `hcl.body@1`; RFC 0012 §9,
//! RFC 0013 §9, RFC 0014 §8.2) that only their owning format family's
//! materializer consumes.
//!
//! # Record-consumption gate
//!
//! A conversion whose source is a record format projects the internal record
//! envelope; presenting that envelope as a target document would be an
//! internal record dump, not a conversion. The facade therefore fails the
//! conversion atomically — `ConversionFailure::MaterializationFailed` with
//! `core.materialization.invalid-request@1`, no target document and no
//! partial bytes — whenever the record's owning family is not the target
//! profile's family. Same-family directions (for example `plist.xml` to
//! `plist.binary`, or `hcl.native` to `hcl.tfvars`) pass the gate and the
//! owning materializer consumes the record under its own validation and
//! closure. The gate keys on the record-publishing projection, never on
//! value shape alone: a baseline source never projects an envelope, so a
//! `"record"` member in JSON/TOML/YAML/INI/Properties content is content
//! (`{"record":"my-app"}` remains ordinary JSON), and the explicit
//! non-record projection targets of the record formats (XML
//! `SimpleEntryMappingV1` and `TextContentV1`, plist `RequireObjectV1`)
//! publish plain portable values that convert like any baseline projection.

use crate::{
    Document, DocumentInner, core, document, hcl, ini, json, plist, properties, toml, xml, yaml,
};
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
    /// INI projection report.
    Ini(ini::ProjectionReport),
    /// Java Properties projection report.
    Properties(properties::ProjectionReport),
    /// JSON projection report.
    Json(json::ProjectionReport),
    /// TOML projection report.
    Toml(toml::ProjectionReport),
    /// HCL body projection report.
    Hcl(hcl::ProjectionReport),
    /// XML element-tree projection report.
    Xml(xml::ProjectionReport),
    /// Property List value-tree projection report.
    Plist(plist::ProjectionReport),
    /// YAML value-projection report.
    Yaml(yaml::ProjectionReport),
}

/// Complete format-owned source provenance retained for local audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversionProjectionProvenance {
    /// INI projection provenance.
    Ini(ini::ProvenanceMap),
    /// Java Properties projection provenance.
    Properties(properties::ProvenanceMap),
    /// JSON projection provenance.
    Json(json::ProvenanceMap),
    /// TOML projection provenance.
    Toml(toml::ProvenanceMap),
    /// HCL body projection provenance.
    Hcl(hcl::ProvenanceMap),
    /// XML element-tree projection provenance.
    Xml(xml::ProvenanceMap),
    /// Property List value-tree projection provenance.
    Plist(plist::ProvenanceMap),
    /// YAML value-projection provenance.
    Yaml(yaml::ProvenanceMap),
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
            (ConversionProjectionReport::Ini(report), ConversionProjectionProvenance::Ini(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            (
                ConversionProjectionReport::Properties(report),
                ConversionProjectionProvenance::Properties(provenance),
            ) => properties_projection_report_message(report, provenance, source_id)?,
            (ConversionProjectionReport::Toml(report), ConversionProjectionProvenance::Toml(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            (ConversionProjectionReport::Yaml(report), ConversionProjectionProvenance::Yaml(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            (ConversionProjectionReport::Hcl(report), ConversionProjectionProvenance::Hcl(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            (ConversionProjectionReport::Xml(report), ConversionProjectionProvenance::Xml(_))
                if report.events().is_empty() =>
            {
                crate::protocol::ProjectionReportMessage::default()
            }
            (
                ConversionProjectionReport::Plist(report),
                ConversionProjectionProvenance::Plist(_),
            ) if report.events().is_empty() => crate::protocol::ProjectionReportMessage::default(),
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
            DocumentInner::Hcl(document) => document.source(),
            DocumentInner::Ini(document) => document.source(),
            DocumentInner::Json(document) => document.source(),
            DocumentInner::Plist(document) => document.source(),
            DocumentInner::Properties(document) => document.source(),
            DocumentInner::Toml(document) => document.source(),
            DocumentInner::Xml(document) => document.source(),
            DocumentInner::Yaml(document) => document.source(),
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
            crate::protocol::SourceSnapshotMessage::from_snapshot(snapshot)?,
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
    /// YAML value projection failed before a portable tree existed.
    YamlProjectionFailed {
        /// Exact format-owned projection failure.
        failure: yaml::ValueProjectionFailure,
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
            Self::ProjectionFailed { .. }
            | Self::YamlProjectionFailed { .. }
            | Self::MaterializationFailed { .. } => core::FailureKind::NotApplicable,
            Self::UnauthorizedLoss => core::FailureKind::InvalidInput,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::ProjectionFailed { .. } | Self::YamlProjectionFailed { .. } => {
                "core.conversion.projection-failed@1"
            }
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

/// Converts one INI document by composing its explicit projection and a target materializer.
#[must_use]
pub fn convert_ini(
    source: &ini::Document,
    projection_request: ini::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project(projection_request) {
        ini::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            ini_fidelity(projection.fidelity),
            ConversionProjectionReport::Ini(projection.report),
            ConversionProjectionProvenance::Ini(projection.provenance),
            materialization_request,
        ),
        ini::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Ini(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: Vec::new(),
            })
        }
    }
}

/// Converts one Java Properties document through an explicit duplicate policy.
#[must_use]
pub fn convert_properties(
    source: &properties::Document,
    projection_request: properties::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project(projection_request) {
        properties::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            properties_fidelity(projection.fidelity),
            ConversionProjectionReport::Properties(projection.report),
            ConversionProjectionProvenance::Properties(projection.provenance),
            materialization_request,
        ),
        properties::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Properties(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: Vec::new(),
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

/// Converts one YAML stream through its explicit PortableValue projection.
#[must_use]
pub fn convert_yaml(
    source: &yaml::Document,
    projection_request: yaml::ValueProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project_value(projection_request) {
        yaml::ValueProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            yaml_fidelity(projection.fidelity),
            ConversionProjectionReport::Yaml(projection.report),
            ConversionProjectionProvenance::Yaml(projection.provenance),
            materialization_request,
        ),
        yaml::ValueProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::YamlProjectionFailed { failure })
        }
    }
}

/// Converts one XML document by composing its element-tree projection and a
/// target materializer.
///
/// The XML projection publishes the exact `xml.element-tree@1` record, which
/// only the XML materializer family consumes; the facade's record-consumption
/// gate rejects the record atomically for every non-XML target (module docs)
/// instead of presenting the internal envelope as a target document.
/// Recovered documents never project.
#[must_use]
pub fn convert_xml(
    source: &xml::Document,
    projection_request: xml::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match source.project(projection_request) {
        xml::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            xml_fidelity(projection.fidelity),
            ConversionProjectionReport::Xml(projection.report),
            ConversionProjectionProvenance::Xml(projection.provenance),
            materialization_request,
        ),
        xml::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Xml(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: Vec::new(),
            })
        }
    }
}

/// Converts one Property List document by composing its value-tree
/// projection and a target materializer.
///
/// The plist projection publishes the exact `plist.value-tree@1` record,
/// which only the plist materializer family consumes; the facade's
/// record-consumption gate rejects the record atomically for every non-plist
/// target (module docs) instead of presenting the internal envelope as a
/// target document. Recovered documents never project.
#[must_use]
pub fn convert_plist(
    source: &plist::Document,
    projection_request: plist::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match plist::project(source, projection_request) {
        plist::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            plist_fidelity(projection.fidelity),
            ConversionProjectionReport::Plist(projection.report),
            ConversionProjectionProvenance::Plist(projection.provenance),
            materialization_request,
        ),
        plist::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Plist(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: Vec::new(),
            })
        }
    }
}

/// Converts one HCL document by composing its body projection and a target
/// materializer.
///
/// The HCL projection publishes the exact `hcl.body@1` record, which only
/// the HCL materializer family consumes; the facade's record-consumption
/// gate rejects the record atomically for every non-HCL target (module docs)
/// instead of presenting the internal envelope as a target document.
/// Recovered documents never project.
///
/// The exact body target is the default `ExpressionPolicy::Fail`: an
/// attribute whose expression is derived (a variable reference, traversal,
/// call, binary operation, conditional, for-expression, or any template
/// containing interpolation or a directive) fails the conversion atomically
/// with `hcl.projection.non-literal-expression@1`. Conversion never
/// implicitly enables the `ProjectExpression` strategy; callers that want
/// derived expressions projected as `hcl.expression@1` ExtendedValues must
/// request that policy explicitly through the projection request (RFC 0014
/// §8.2).
#[must_use]
pub fn convert_hcl(
    source: &hcl::Document,
    projection_request: hcl::ProjectionRequest,
    materialization_request: &MaterializationRequest,
) -> ConversionResult {
    match hcl::project(source, projection_request) {
        hcl::ProjectionResult::Complete(projection) => complete_conversion(
            source.profile(),
            projection.value,
            hcl_fidelity(projection.fidelity),
            ConversionProjectionReport::Hcl(projection.report),
            ConversionProjectionProvenance::Hcl(projection.provenance),
            materialization_request,
        ),
        hcl::ProjectionResult::Failed(failure) => {
            ConversionResult::Failed(ConversionFailure::ProjectionFailed {
                report: ConversionProjectionReport::Hcl(failure.report),
                diagnostics: failure.diagnostics,
                partial_analysis: Vec::new(),
            })
        }
    }
}

/// Published record envelope ids produced by the record-format projections
/// (RFC 0012 §9, RFC 0013 §9, RFC 0014 §8.2). `hcl.expression@1` is nested
/// inside body items and is never the projected root.
const XML_ELEMENT_TREE_RECORD: &str = "xml.element-tree@1";
const PLIST_VALUE_TREE_RECORD: &str = "plist.value-tree@1";
const HCL_BODY_RECORD: &str = "hcl.body@1";

/// One published Consema format record envelope, identified by its exact
/// versioned `record` member; any other object is ordinary content.
fn published_record(value: &PortableValue) -> Option<&str> {
    let object = value.as_object()?;
    let record = object.iter().find(|entry| entry.key() == "record")?;
    let id = record.value().as_string()?;
    matches!(
        id,
        XML_ELEMENT_TREE_RECORD | PLIST_VALUE_TREE_RECORD | HCL_BODY_RECORD
    )
    .then_some(id)
}

/// Owning format family of one published record id.
fn record_family(record: &str) -> Option<&'static str> {
    match record {
        XML_ELEMENT_TREE_RECORD => Some("xml"),
        PLIST_VALUE_TREE_RECORD => Some("plist"),
        HCL_BODY_RECORD => Some("hcl"),
        _ => None,
    }
}

/// Exact invalid-request diagnostic for one published record id.
fn record_family_message(record: &str) -> &'static str {
    match record {
        XML_ELEMENT_TREE_RECORD => {
            "the projected value is the xml.element-tree@1 internal record; \
             only the xml family materializer consumes it"
        }
        PLIST_VALUE_TREE_RECORD => {
            "the projected value is the plist.value-tree@1 internal record; \
             only the plist family materializer consumes it"
        }
        HCL_BODY_RECORD => {
            "the projected value is the hcl.body@1 internal record; \
             only the hcl family materializer consumes it"
        }
        _ => {
            "the projected value is an internal format record; \
             only its owning format family materializer consumes it"
        }
    }
}

/// Format family of one profile id; unknown profiles return `None`.
fn format_family(profile_id: &str) -> Option<&'static str> {
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

/// Record-consumption gate of the composition (module docs).
///
/// A record-format source (XML, plist, HCL) projects its versioned internal
/// record envelope; the envelope is consumed only by the owning format
/// family's materializer. When the target profile belongs to a different
/// family, the conversion fails atomically with the shared invalid-request
/// vocabulary instead of presenting the envelope as a target document.
/// Baseline sources never project envelopes — a `"record"` member in their
/// content is content — and the explicit non-record projection targets of
/// the record formats publish plain values, so both pass the gate untouched.
fn validate_record_consumption(
    source_profile: &ProfileId,
    value: &PortableValue,
    request: &MaterializationRequest,
) -> Result<(), ConversionFailure> {
    let Some(source_family) = format_family(source_profile.id()) else {
        return Ok(());
    };
    if !matches!(source_family, "xml" | "plist" | "hcl") {
        return Ok(());
    }
    let Some(record) = published_record(value) else {
        return Ok(());
    };
    if record_family(record) == format_family(request.target_profile().id()) {
        return Ok(());
    }
    Err(ConversionFailure::MaterializationFailed {
        failure: document::MaterializationFailure::InvalidRequest(record_family_message(record)),
        report: MaterializationReport::default(),
        analyzed_input_paths: Vec::new(),
    })
}

fn complete_conversion(
    source_profile: ProfileId,
    projected_value: PortableValue,
    projection_fidelity: ConversionFidelity,
    projection_report: ConversionProjectionReport,
    projection_provenance: ConversionProjectionProvenance,
    request: &MaterializationRequest,
) -> ConversionResult {
    if let Err(failure) = validate_record_consumption(&source_profile, &projected_value, request) {
        return ConversionResult::Failed(failure);
    }
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
        "ini.portable" | "ini.windows" | "ini.python-configparser" => {
            match ini::materialize(value, request) {
                document::MaterializationResult::Complete(CompleteMaterialization {
                    document,
                    fidelity,
                    report,
                    provenance,
                }) => Ok(MaterializedTarget {
                    document: Document {
                        inner: DocumentInner::Ini(Box::new(document)),
                    },
                    fidelity,
                    report,
                    provenance,
                }),
                document::MaterializationResult::Failed(failure) => {
                    Err(materialization_failure(failure))
                }
            }
        }
        "java-properties.reader" | "java-properties.latin1" => {
            match properties::materialize(value, request) {
                document::MaterializationResult::Complete(CompleteMaterialization {
                    document,
                    fidelity,
                    report,
                    provenance,
                }) => Ok(MaterializedTarget {
                    document: Document {
                        inner: DocumentInner::Properties(Box::new(document)),
                    },
                    fidelity,
                    report,
                    provenance,
                }),
                document::MaterializationResult::Failed(failure) => {
                    Err(materialization_failure(failure))
                }
            }
        }
        "json.strict" | "jsonc.bounded" | "json5.standard" => {
            match json::materialize(value, request) {
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
            }
        }
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
        "yaml.1.2-core" | "yaml.1.1-compat" => match yaml::materialize_value(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Yaml(Box::new(document)),
                },
                fidelity,
                report,
                provenance,
            }),
            document::MaterializationResult::Failed(failure) => {
                Err(materialization_failure(failure))
            }
        },
        "hcl.native" | "hcl.tfvars" => match hcl::materialize(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Hcl(Box::new(document)),
                },
                fidelity,
                report,
                provenance,
            }),
            document::MaterializationResult::Failed(failure) => {
                Err(materialization_failure(failure))
            }
        },
        "xml.1.0-safe" => match xml::materialize(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Xml(Box::new(document)),
                },
                fidelity,
                report,
                provenance,
            }),
            document::MaterializationResult::Failed(failure) => {
                Err(materialization_failure(failure))
            }
        },
        "plist.xml" | "plist.binary" => match plist::materialize(value, request) {
            document::MaterializationResult::Complete(CompleteMaterialization {
                document,
                fidelity,
                report,
                provenance,
            }) => Ok(MaterializedTarget {
                document: Document {
                    inner: DocumentInner::Plist(Box::new(document)),
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

const fn ini_fidelity(fidelity: ini::Fidelity) -> ConversionFidelity {
    match fidelity {
        ini::Fidelity::Exact => ConversionFidelity::Exact,
        ini::Fidelity::Transformed => ConversionFidelity::Transformed,
        ini::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn properties_fidelity(fidelity: properties::Fidelity) -> ConversionFidelity {
    match fidelity {
        properties::Fidelity::Exact => ConversionFidelity::Exact,
        properties::Fidelity::Transformed => ConversionFidelity::Transformed,
        properties::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn toml_fidelity(fidelity: toml::Fidelity) -> ConversionFidelity {
    match fidelity {
        toml::Fidelity::Exact => ConversionFidelity::Exact,
        toml::Fidelity::Transformed => ConversionFidelity::Transformed,
        toml::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn yaml_fidelity(fidelity: yaml::Fidelity) -> ConversionFidelity {
    match fidelity {
        yaml::Fidelity::Exact => ConversionFidelity::Exact,
        yaml::Fidelity::Transformed => ConversionFidelity::Transformed,
        yaml::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn xml_fidelity(fidelity: xml::Fidelity) -> ConversionFidelity {
    match fidelity {
        xml::Fidelity::Exact => ConversionFidelity::Exact,
        xml::Fidelity::Transformed => ConversionFidelity::Transformed,
        xml::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn plist_fidelity(fidelity: plist::Fidelity) -> ConversionFidelity {
    match fidelity {
        plist::Fidelity::Exact => ConversionFidelity::Exact,
        plist::Fidelity::Transformed => ConversionFidelity::Transformed,
        plist::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

const fn hcl_fidelity(fidelity: hcl::Fidelity) -> ConversionFidelity {
    match fidelity {
        hcl::Fidelity::Exact => ConversionFidelity::Exact,
        hcl::Fidelity::Transformed => ConversionFidelity::Transformed,
        hcl::Fidelity::Lossy => ConversionFidelity::Lossy,
    }
}

fn properties_projection_report_message(
    report: &properties::ProjectionReport,
    provenance: &properties::ProvenanceMap,
    source_id: &str,
) -> Result<crate::protocol::ProjectionReportMessage, crate::protocol::ProtocolError> {
    let events = report
        .events()
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let projected = properties::ProjectedLocation::Association(event.projected.clone());
            let origins = provenance
                .entries()
                .iter()
                .find(|entry| entry.projected == projected)
                .map(|entry| entry.origins.as_slice())
                .unwrap_or_default();
            let mut locations = Vec::new();
            for origin in origins
                .iter()
                .filter(|origin| origin.node == event.discarded || origin.node == event.retained)
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
            if locations.len() != 2 {
                return Err(crate::protocol::ProtocolError::new(
                    crate::protocol::ProtocolErrorKind::ProcessLocalHandle,
                    format!("$.projection_report.events[{index}].source_locations"),
                    "duplicate collapse requires retained and discarded external provenance",
                ));
            }
            let mut arguments = BTreeMap::new();
            arguments.insert("event_kind".to_owned(), "DuplicateCollapsed".to_owned());
            arguments.insert(
                "policy".to_owned(),
                properties_duplicate_policy_name(event.policy).to_owned(),
            );
            Ok(crate::protocol::ProjectionEventMessage {
                code: event.code.to_owned(),
                policy_rule_id: Some(properties_duplicate_policy_rule_id(event.policy).to_owned()),
                source_locations: locations,
                projected_location: Some(crate::protocol::ProjectedLocationMessage::Association(
                    event.projected.clone(),
                )),
                old_category: Some("PropertiesPropertyOccurrence".to_owned()),
                new_category: Some("Collapsed".to_owned()),
                reversible: false,
                loss_classification: crate::protocol::LossClassification::Lossy,
                arguments,
            })
        })
        .collect::<Result<Vec<_>, crate::protocol::ProtocolError>>()?;
    crate::protocol::ProjectionReportMessage::new_with_registry(
        events,
        crate::protocol::ErrorCodeRegistry::v6(),
    )
}

const fn properties_duplicate_policy_name(policy: properties::DuplicatePolicy) -> &'static str {
    match policy {
        properties::DuplicatePolicy::RequireUnique => "RequireUnique",
        properties::DuplicatePolicy::FirstWins => "FirstWins",
        properties::DuplicatePolicy::LastWinsJdkTable => "LastWinsJdkTable",
    }
}

const fn properties_duplicate_policy_rule_id(policy: properties::DuplicatePolicy) -> &'static str {
    match policy {
        properties::DuplicatePolicy::RequireUnique => {
            "java-properties.duplicate-key.require-unique@1"
        }
        properties::DuplicatePolicy::FirstWins => "java-properties.duplicate-key.first-wins@1",
        properties::DuplicatePolicy::LastWinsJdkTable => {
            "java-properties.duplicate-key.last-wins-jdk-table@1"
        }
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
    use std::sync::Arc;

    fn projection_provenance_json(complete: &CompleteConversion) -> &[json::ProvenanceEntry] {
        match &complete.projection_provenance {
            ConversionProjectionProvenance::Json(provenance) => provenance.entries(),
            ConversionProjectionProvenance::Hcl(_)
            | ConversionProjectionProvenance::Ini(_)
            | ConversionProjectionProvenance::Plist(_)
            | ConversionProjectionProvenance::Properties(_)
            | ConversionProjectionProvenance::Toml(_)
            | ConversionProjectionProvenance::Xml(_)
            | ConversionProjectionProvenance::Yaml(_) => &[],
        }
    }

    fn ini_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("ini.portable", 1),
            MaterializationStyleId::new("ini.portable-canonical", 1),
        )
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

    fn json5_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("json5.standard", 1),
            MaterializationStyleId::new("json5.canonical-compact", 1),
        )
        .with_newline(NewlinePolicy::None)
    }

    fn yaml_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("yaml.1.2-core", 1),
            MaterializationStyleId::new("yaml.canonical-flow", 1),
        )
        .with_newline(NewlinePolicy::Lf)
    }

    fn properties_reader_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("java-properties.reader", 1),
            MaterializationStyleId::new("java-properties.reader-canonical", 1),
        )
        .with_encoding(document::SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::Lf)
    }

    fn xml_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("xml.1.0-safe", 1),
            MaterializationStyleId::new("xml.safe-canonical-document", 1),
        )
    }

    fn plist_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("plist.xml", 1),
            MaterializationStyleId::new("plist.xml-canonical", 1),
        )
        .with_encoding(document::SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::Lf)
    }

    fn plist_binary_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("plist.binary", 1),
            MaterializationStyleId::new("plist.binary-canonical", 1),
        )
        .with_encoding(document::SourceEncoding::Binary)
        .with_newline(NewlinePolicy::None)
    }

    fn hcl_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("hcl.native", 1),
            MaterializationStyleId::new("hcl.canonical-document", 1),
        )
        .with_encoding(document::SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::Lf)
    }

    fn hcl_tfvars_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("hcl.tfvars", 1),
            MaterializationStyleId::new("hcl.canonical-document", 1),
        )
        .with_encoding(document::SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::Lf)
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

    #[test]
    fn json_family_dialect_conversion_is_exact_or_explicitly_fails() {
        let strict = json::parse(
            br#"{"service":{"port":8080}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let strict_projection =
            ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
                .build()
                .unwrap();
        let ConversionResult::Complete(json5) =
            convert_json(&strict, &strict_projection, &json5_request())
        else {
            panic!("strict JSON to JSON5 should complete")
        };
        assert_eq!(json5.document.render(), br#"{"service":{"port":8080}}"#);
        assert_eq!(json5.report.overall_fidelity(), ConversionFidelity::Exact);
        assert_eq!(
            json5.report.source_profile(),
            &ProfileId::new("json.strict", 1)
        );
        assert_eq!(
            json5.report.target_profile(),
            &ProfileId::new("json5.standard", 1)
        );

        let json5_source = json::parse(
            b"{service:{port:8080,},}".as_slice(),
            json::JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        )
        .unwrap();
        let json5_projection =
            ProjectionRequestBuilder::new(json::ProjectionTarget::Json5BestExactCoreV1)
                .build()
                .unwrap();
        let ConversionResult::Complete(strict) =
            convert_json(&json5_source, &json5_projection, &json_request())
        else {
            panic!("finite JSON5 to strict JSON should complete")
        };
        assert_eq!(strict.document.render(), br#"{"service":{"port":8080}}"#);
        assert_eq!(strict.report.overall_fidelity(), ConversionFidelity::Exact);

        let non_finite = json::parse(
            b"Infinity".as_slice(),
            json::JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_json(&non_finite, &json5_projection, &json_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::Unrepresentable {
                    kind: core::PortableValueKind::BinaryFloat64,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn yaml_and_json_conversion_closes_exactly_in_both_directions() {
        let yaml_source = yaml::parse(
            b"service:\n  port: 8080\n  enabled: true\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(json_target) = convert_yaml(
            &yaml_source,
            yaml::ValueProjectionRequest::best_exact_v1(),
            &json_request(),
        ) else {
            panic!("YAML to JSON should complete exactly")
        };
        assert_eq!(
            json_target.document.render(),
            br#"{"service":{"port":8080,"enabled":true}}"#
        );
        assert_eq!(
            json_target.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert!(matches!(
            json_target.projection_provenance,
            ConversionProjectionProvenance::Yaml(_)
        ));
        let report = json_target
            .protocol_report("source:yaml", "target:json")
            .unwrap();
        assert_eq!(
            report.overall_fidelity(),
            protocol::ConversionFidelityMessage::Exact
        );

        let json_source = json::parse(
            br#"{"service":{"port":8080,"enabled":true}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ConversionResult::Complete(yaml_target) =
            convert_json(&json_source, &projection, &yaml_request())
        else {
            panic!("JSON to YAML should complete exactly")
        };
        assert_eq!(
            yaml_target.report.target_profile(),
            &ProfileId::new("yaml.1.2-core", 1)
        );
        assert_eq!(
            yaml_target.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        let yaml_document = yaml_target.document.as_yaml().unwrap();
        let yaml::ValueProjectionResult::Complete(round_trip) =
            yaml_document.project_value(yaml::ValueProjectionRequest::best_exact_v1())
        else {
            panic!("materialized YAML must project exactly")
        };
        assert_eq!(round_trip.value, yaml_target.projected_value);
        let mut yaml_locators = HashMap::new();
        let mut next_yaml_locator = 0_u64;
        let materialization = yaml_target
            .protocol_materialization_result("target:yaml", |node| {
                Some(
                    yaml_locators
                        .entry(node)
                        .or_insert_with(|| {
                            let locator = format!("yaml:node:{next_yaml_locator}");
                            next_yaml_locator += 1;
                            locator
                        })
                        .clone(),
                )
            })
            .unwrap();
        assert_eq!(
            materialization.target_profile(),
            &ProfileId::new("yaml.1.2-core", 1)
        );
    }

    #[test]
    fn yaml_compat_profile_is_explicit_at_both_conversion_stages() {
        let source = yaml::parse(
            b"%YAML 1.1\n---\nflag: yes\n".as_slice(),
            yaml::YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(json_target) = convert_yaml(
            &source,
            yaml::ValueProjectionRequest::best_exact_v1(),
            &json_request(),
        ) else {
            panic!("YAML 1.1 compatibility source should convert")
        };
        assert_eq!(json_target.document.render(), br#"{"flag":true}"#);
        assert_eq!(
            json_target.report.source_profile(),
            &ProfileId::new("yaml.1.1-compat", 1)
        );

        let json_source = json::parse(
            br#"{"flag":true}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let target = MaterializationRequest::new(
            ProfileId::new("yaml.1.1-compat", 1),
            MaterializationStyleId::new("yaml.canonical-flow", 1),
        )
        .with_newline(NewlinePolicy::Lf);
        let ConversionResult::Complete(yaml_target) =
            convert_json(&json_source, &projection, &target)
        else {
            panic!("YAML compatibility target should materialize")
        };
        assert_eq!(
            yaml_target.report.target_profile(),
            &ProfileId::new("yaml.1.1-compat", 1)
        );
        assert_eq!(
            yaml_target.document.as_yaml().unwrap().profile(),
            ProfileId::new("yaml.1.1-compat", 1)
        );
    }

    #[test]
    fn yaml_sharing_and_cycles_require_explicit_tree_projection_policy() {
        let shared = yaml::parse(
            b"value: &x [one]\ncopy: *x\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_yaml(
                &shared,
                yaml::ValueProjectionRequest::best_exact_v1(),
                &json_request(),
            ),
            ConversionResult::Failed(ConversionFailure::YamlProjectionFailed {
                failure: yaml::ValueProjectionFailure::Sharing { .. }
            })
        ));

        let duplicated = yaml::ValueProjectionRequest::best_exact_v1()
            .with_sharing(yaml::SharingPolicy::DuplicateAcyclic);
        let ConversionResult::Complete(converted) =
            convert_yaml(&shared, duplicated, &json_request())
        else {
            panic!("explicit acyclic duplication should complete")
        };
        assert_eq!(
            converted.report.overall_fidelity(),
            ConversionFidelity::Transformed
        );
        let ConversionProjectionReport::Yaml(report) = converted.report.projection_report() else {
            panic!("YAML projection report expected")
        };
        assert!(!report.events().is_empty());
        assert!(
            report
                .events()
                .iter()
                .all(|event| event.kind == yaml::ProjectionEventKind::SharingDuplicated)
        );

        let cyclic = yaml::parse(
            b"&x [*x]\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_yaml(&cyclic, duplicated, &json_request()),
            ConversionResult::Failed(ConversionFailure::YamlProjectionFailed {
                failure: yaml::ValueProjectionFailure::Cycle { .. }
            })
        ));
    }

    #[test]
    fn ini_and_json_convert_exactly_in_both_directions() {
        let ini_source = ini::parse(
            b"[service]\nname=api\nport=8080\n".as_slice(),
            ini::IniProfile::PortableV1,
            ini::IniEncodingSelection::ProfileDefault,
            ini::IniParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(json_target) = convert_ini(
            &ini_source,
            ini::ProjectionRequest::best_exact_entry_mapping(),
            &json_request(),
        ) else {
            panic!("INI to JSON should complete exactly")
        };
        assert_eq!(
            json_target.document.render(),
            br#"{"service":{"name":"api","port":"8080"}}"#
        );
        assert_eq!(
            json_target.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert!(matches!(
            json_target.projection_provenance,
            ConversionProjectionProvenance::Ini(_)
        ));
        let report = json_target
            .protocol_report("source:ini", "target:json")
            .unwrap();
        assert_eq!(
            report.overall_fidelity(),
            protocol::ConversionFidelityMessage::Exact
        );

        let json_source = json::parse(
            br#"{"service":{"name":"api","port":"8080"}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ConversionResult::Complete(ini_target) =
            convert_json(&json_source, &projection, &ini_request())
        else {
            panic!("JSON to INI should complete exactly")
        };
        assert_eq!(
            ini_target.document.render(),
            b"[service]\nname=api\nport=8080\n"
        );
        assert_eq!(
            ini_target.report.target_profile(),
            &ProfileId::new("ini.portable", 1)
        );
        assert_eq!(ini_target.document.as_ini().unwrap().entries().len(), 2);
    }

    #[test]
    fn properties_and_json_convert_exactly_in_both_directions() {
        let properties_source = properties::parse_reader(
            b"name=api\nport=8080\n".as_slice(),
            document::SourceEncoding::Utf8,
            properties::PropertiesParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(json_target) = convert_properties(
            &properties_source,
            properties::ProjectionRequest::best_exact_entry_mapping(),
            &json_request(),
        ) else {
            panic!("Properties to JSON should complete exactly")
        };
        assert_eq!(
            json_target.document.render(),
            br#"{"name":"api","port":"8080"}"#
        );
        assert_eq!(
            json_target.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert!(matches!(
            json_target.projection_provenance,
            ConversionProjectionProvenance::Properties(_)
        ));
        assert_eq!(
            json_target
                .protocol_report("source:properties", "target:json")
                .unwrap()
                .overall_fidelity(),
            protocol::ConversionFidelityMessage::Exact
        );

        let json_source = json::parse(
            br#"{"name":"api","port":"8080"}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ConversionResult::Complete(properties_target) =
            convert_json(&json_source, &projection, &properties_reader_request())
        else {
            panic!("JSON to Properties should complete exactly")
        };
        assert_eq!(
            properties_target.document.render(),
            b"name=api\nport=8080\n"
        );
        assert_eq!(
            properties_target.report.target_profile(),
            &ProfileId::new("java-properties.reader", 1)
        );
        assert_eq!(
            properties_target
                .document
                .as_properties()
                .unwrap()
                .properties()
                .len(),
            2
        );
    }

    #[test]
    fn properties_duplicate_collapse_is_audited_as_authorized_loss() {
        let source = properties::parse_reader(
            b"a=first\na=last\n".as_slice(),
            document::SourceEncoding::Utf8,
            properties::PropertiesParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(converted) = convert_properties(
            &source,
            properties::ProjectionRequest::require_object(properties::DuplicatePolicy::FirstWins),
            &json_request(),
        ) else {
            panic!("explicit first-wins conversion should complete")
        };
        assert_eq!(converted.document.render(), br#"{"a":"first"}"#);
        assert_eq!(
            converted.report.overall_fidelity(),
            ConversionFidelity::Lossy
        );
        let report = converted
            .protocol_report("source:properties", "target:json")
            .unwrap();
        assert_eq!(
            report.overall_fidelity(),
            protocol::ConversionFidelityMessage::Lossy
        );
        assert_eq!(report.projection_report().events().len(), 1);
        let event = &report.projection_report().events()[0];
        assert_eq!(
            event.code,
            "java-properties.projection.duplicate-collapsed@1"
        );
        assert_eq!(event.source_locations.len(), 2);
        assert!(!event.reversible);
        assert_eq!(
            event.loss_classification,
            protocol::LossClassification::Lossy
        );
    }

    #[test]
    fn properties_conversion_failures_publish_no_partial_target() {
        let unpaired = properties::parse_reader(
            br"a=\uD800".as_slice(),
            document::SourceEncoding::Utf8,
            properties::PropertiesParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_properties(
                &unpaired,
                properties::ProjectionRequest::best_exact_entry_mapping(),
                &json_request(),
            ),
            ConversionResult::Failed(ConversionFailure::ProjectionFailed { .. })
        ));

        let json_source = json::parse(
            br#"{"port":8080}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        assert!(matches!(
            convert_json(&json_source, &projection, &properties_reader_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::Unrepresentable { .. },
                ..
            })
        ));
    }

    #[test]
    fn ini_conversion_failures_publish_no_partial_target() {
        let malformed = ini::parse(
            b"[service]\nbroken\n".as_slice(),
            ini::IniProfile::PortableV1,
            ini::IniEncodingSelection::ProfileDefault,
            ini::IniParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            convert_ini(
                &malformed,
                ini::ProjectionRequest::best_exact_entry_mapping(),
                &json_request(),
            ),
            ConversionResult::Failed(ConversionFailure::ProjectionFailed { .. })
        ));

        let json_source = json::parse(
            br#"{"service":{"port":8080}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        assert!(matches!(
            convert_json(&json_source, &projection, &ini_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::Unrepresentable { .. },
                ..
            })
        ));
    }

    #[test]
    fn xml_converts_to_canonical_xml_exactly() {
        let source = xml::parse(
            b"<service><name>catalog</name></service>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(complete) = convert_xml(
            &source,
            xml::ProjectionRequest::element_tree(),
            &xml_request(),
        ) else {
            panic!("XML to canonical XML should complete exactly")
        };
        assert_eq!(
            complete.document.render(),
            b"<service><name>catalog</name></service>\n"
        );
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert_eq!(
            complete.report.source_profile(),
            &ProfileId::new("xml.1.0-safe", 1)
        );
        assert_eq!(
            complete.report.target_profile(),
            &ProfileId::new("xml.1.0-safe", 1)
        );
        assert!(matches!(
            complete.projection_provenance,
            ConversionProjectionProvenance::Xml(_)
        ));
        assert!(!complete.materialization_provenance.entries().is_empty());
        let report = complete
            .protocol_report("source:xml", "target:xml")
            .unwrap();
        assert_eq!(
            report.overall_fidelity(),
            protocol::ConversionFidelityMessage::Exact
        );
    }

    #[test]
    fn plist_value_tree_record_is_consumed_only_by_the_plist_family() {
        let source = plist::parse(
            Arc::from(
                b"<plist version=\"1.0\"><dict><key>name</key><string>api</string></dict></plist>"
                    .as_slice(),
            ),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        // The plist projection publishes the exact `plist.value-tree@1`
        // record (RFC 0013 §9). The facade's record-consumption gate never
        // presents that internal record as a JSON document: the JSON target
        // would be a record dump, not a conversion, so the conversion fails
        // atomically with the shared invalid-request vocabulary and no
        // target document.
        assert!(matches!(
            convert_plist(
                &source,
                plist::ProjectionRequest::value_tree(),
                &json_request()
            ),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        // The owning family still consumes the record exactly.
        assert!(matches!(
            convert_plist(
                &source,
                plist::ProjectionRequest::value_tree(),
                &plist_request()
            ),
            ConversionResult::Complete(_)
        ));
    }

    #[test]
    fn plist_converts_between_profiles_exactly() {
        // Same-family conversion: the facade composes the value-tree
        // projection and the target plist materializer, so the projected
        // record is the materialization input directly (RFC 0013 §9, §10).
        // The source carries a nested dict/array, repeated dict keys, a
        // date, and data.
        let source = plist::parse(
            Arc::from(
                b"<plist version=\"1.0\"><dict>\
                  <key>name</key><string>api</string>\
                  <key>port</key><integer>8080</integer>\
                  <key>enabled</key><true/>\
                  <key>nested</key><dict><key>tags</key>\
                  <array><string>a</string><string>b</string></array></dict>\
                  <key>dup</key><string>first</string>\
                  <key>dup</key><string>second</string>\
                  <key>created</key><date>2023-01-01T00:00:00Z</date>\
                  <key>payload</key><data>AQID</data>\
                  </dict></plist>"
                    .as_slice(),
            ),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(complete) = convert_plist(
            &source,
            plist::ProjectionRequest::value_tree(),
            &plist_binary_request(),
        ) else {
            panic!("plist to plist.binary should complete exactly")
        };
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Exact
        );
        assert_eq!(
            complete.report.target_profile(),
            &ProfileId::new("plist.binary", 1)
        );
        let rendered = complete.document.render();
        assert!(rendered.starts_with(b"bplist00"), "binary output header");
        // The conversion closed the loop: reparsing the generated bytes
        // yields the source native model exactly.
        let reparsed = plist::parse(
            Arc::from(rendered),
            plist::PlistProfile::BinaryV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        assert_eq!(reparsed.document(), source.document());
        // And back: plist.binary -> plist.xml preserves the same native
        // model.
        let ConversionResult::Complete(back) = convert_plist(
            &reparsed,
            plist::ProjectionRequest::value_tree(),
            &plist_request(),
        ) else {
            panic!("plist.binary to plist.xml should complete exactly")
        };
        assert_eq!(back.report.overall_fidelity(), ConversionFidelity::Exact);
        assert_eq!(
            back.report.target_profile(),
            &ProfileId::new("plist.xml", 1)
        );
        let re_reparsed = plist::parse(
            Arc::from(back.document.render()),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        assert_eq!(re_reparsed.document(), source.document());
    }

    #[test]
    fn json_cannot_materialize_into_record_formats() {
        let json_source = json::parse(
            br#"{"service":{"port":8080}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        assert!(matches!(
            convert_json(&json_source, &projection, &xml_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        assert!(matches!(
            convert_json(&json_source, &projection, &plist_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        assert!(matches!(
            convert_json(&json_source, &projection, &hcl_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
    }

    #[test]
    fn hcl_body_record_is_consumed_only_by_the_hcl_family() {
        let source = hcl::parse(
            Arc::<[u8]>::from(b"a = 1\n".as_slice()),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .unwrap();
        // The HCL projection publishes the exact `hcl.body@1` record (RFC
        // 0014 §8.2): one ordered `items` sequence. The facade's
        // record-consumption gate never presents that internal record as a
        // JSON document: the JSON target would be a record dump, not a
        // conversion, so the conversion fails atomically with the shared
        // invalid-request vocabulary and no target document.
        assert!(matches!(
            convert_hcl(&source, hcl::ProjectionRequest::body(), &json_request()),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        // The owning family still consumes the record exactly.
        assert!(matches!(
            convert_hcl(&source, hcl::ProjectionRequest::body(), &hcl_request()),
            ConversionResult::Complete(_)
        ));
    }

    #[test]
    fn xml_element_tree_record_is_consumed_only_by_the_xml_family() {
        let source = xml::parse(
            b"<service><name>catalog</name></service>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .unwrap();
        // The XML projection publishes the exact `xml.element-tree@1` record
        // (RFC 0012 §9). The facade's record-consumption gate never presents
        // that internal record as a JSON or TOML document: the target would
        // be a record dump, not a conversion, so the conversion fails
        // atomically with the shared invalid-request vocabulary and no
        // target document.
        assert!(matches!(
            convert_xml(
                &source,
                xml::ProjectionRequest::element_tree(),
                &json_request()
            ),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        assert!(matches!(
            convert_xml(
                &source,
                xml::ProjectionRequest::element_tree(),
                &toml_request()
            ),
            ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                failure: document::MaterializationFailure::InvalidRequest(_),
                ..
            })
        ));
        // The owning family still consumes the record exactly.
        assert!(matches!(
            convert_xml(
                &source,
                xml::ProjectionRequest::element_tree(),
                &xml_request()
            ),
            ConversionResult::Complete(_)
        ));
    }

    #[test]
    fn record_envelopes_fail_every_non_owning_target_atomically() {
        // One source per record format; every non-owning target fails the
        // record-consumption gate atomically (module docs), including the
        // other record families whose materializers also validate the record
        // marker.
        let xml_source = xml::parse(
            b"<root><name>api</name></root>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .unwrap();
        let plist_source = plist::parse(
            Arc::from(
                b"<plist version=\"1.0\"><dict><key>name</key><string>api</string></dict></plist>"
                    .as_slice(),
            ),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        let hcl_source = hcl::parse(
            Arc::<[u8]>::from(b"a = 1\n".as_slice()),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .unwrap();
        let toml_target = toml_request();
        let yaml_target = yaml_request();
        let ini_target = ini_request();
        let properties_target = properties_reader_request();
        let xml_target = xml_request();
        let plist_target = plist_request();
        let hcl_target = hcl_request();
        let targets: [&MaterializationRequest; 7] = [
            &toml_target,
            &yaml_target,
            &ini_target,
            &properties_target,
            &xml_target,
            &plist_target,
            &hcl_target,
        ];
        let assert_fails = |result: ConversionResult| {
            assert!(
                matches!(
                    result,
                    ConversionResult::Failed(ConversionFailure::MaterializationFailed {
                        failure: document::MaterializationFailure::InvalidRequest(_),
                        ..
                    })
                ),
                "record envelope must fail atomically on a non-owning target"
            );
        };
        for request in targets {
            let family = format_family(request.target_profile().id());
            // The owning family consumes the record (asserted by the
            // dedicated same-family tests); every other target fails.
            if family != Some("xml") {
                assert_fails(convert_xml(
                    &xml_source,
                    xml::ProjectionRequest::element_tree(),
                    request,
                ));
            }
            if family != Some("plist") {
                assert_fails(convert_plist(
                    &plist_source,
                    plist::ProjectionRequest::value_tree(),
                    request,
                ));
            }
            if family != Some("hcl") {
                assert_fails(convert_hcl(
                    &hcl_source,
                    hcl::ProjectionRequest::body(),
                    request,
                ));
            }
        }
    }

    #[test]
    fn explicit_non_record_projection_targets_convert_across_families() {
        // The record-consumption gate fires only on the record envelope
        // (module docs). The explicit non-record projection targets of the
        // record formats publish plain portable values that convert like any
        // baseline projection: XML simple-entry-mapping and plist
        // require-object both complete to JSON.
        let xml_source = xml::parse(
            b"<root><name>api</name><port>8080</port></root>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .unwrap();
        let subtree = xml_source.root().expect("root").node_ref();
        let ConversionResult::Complete(xml_target) = convert_xml(
            &xml_source,
            xml::ProjectionRequest::simple_entry_mapping(
                subtree,
                xml::AttributePolicy::RejectAttributes,
                xml::TextKeyPolicy::RejectText,
                xml::RepeatedChildPolicy::Reject,
                xml::ExpandedNameKeyPolicy::LocalOnly,
                xml::CollisionPolicy::Reject,
            ),
            &json_request(),
        ) else {
            panic!("explicit entry mapping should convert to JSON")
        };
        assert_eq!(
            xml_target.document.render(),
            br#"{"name":"api","port":"8080"}"#
        );
        assert_eq!(
            xml_target.report.overall_fidelity(),
            ConversionFidelity::Transformed
        );

        let plist_source = plist::parse(
            Arc::from(
                b"<plist version=\"1.0\"><dict><key>name</key><string>api</string><key>port</key><integer>8080</integer></dict></plist>"
                    .as_slice(),
            ),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(plist_target) = convert_plist(
            &plist_source,
            plist::ProjectionRequest::require_object(plist::CollisionPolicy::Reject),
            &json_request(),
        ) else {
            panic!("explicit require-object projection should convert to JSON")
        };
        assert_eq!(
            plist_target.document.render(),
            br#"{"name":"api","port":8080}"#
        );
    }

    #[test]
    fn record_member_content_from_baseline_sources_stays_content() {
        // The record-consumption gate keys on the record-publishing
        // projection, never on value shape (module docs): a baseline source
        // never projects an envelope, so `"record"` members in its content
        // are content and convert faithfully, including a member whose value
        // equals a published record id.
        let json_source = json::parse(
            br#"{"record":"plist.value-tree@1","root":{"name":"api"}}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let projection = ProjectionRequestBuilder::new(json::ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ConversionResult::Complete(toml_target) =
            convert_json(&json_source, &projection, &toml_request())
        else {
            panic!("record-shaped JSON content should convert as content")
        };
        let rendered = toml_target.document.render();
        assert!(
            std::str::from_utf8(rendered)
                .unwrap()
                .contains("\"record\" = \"plist.value-tree@1\""),
            "the record member is preserved as content: {}",
            String::from_utf8_lossy(rendered)
        );

        let yaml_source = yaml::parse(
            b"record: hcl.body@1\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(yaml_target) = convert_yaml(
            &yaml_source,
            yaml::ValueProjectionRequest::best_exact_v1(),
            &json_request(),
        ) else {
            panic!("YAML record-looking content should convert as content")
        };
        assert_eq!(yaml_target.document.render(), br#"{"record":"hcl.body@1"}"#);

        let unknown = json::parse(
            br#"{"record":"my-app","port":8080}"#.as_slice(),
            json::JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let ConversionResult::Complete(unknown_target) =
            convert_json(&unknown, &projection, &toml_request())
        else {
            panic!("unknown record member should convert as content")
        };
        assert_eq!(
            unknown_target.document.render(),
            b"\"record\" = \"my-app\"\n\"port\" = 8080\n"
        );
    }

    #[test]
    fn hcl_native_converts_to_canonical_tfvars_within_the_family() {
        // Same-family conversion closes the project→materialize loop through
        // the facade: an `hcl.native@1` source materializes canonically as
        // `hcl.tfvars@1` (RFC 0014 §9). Number spellings canonicalize
        // (`1.50` and `15e-1` both emit `1.5`), and the explicit
        // ProjectExpression policy carries the derived expression through as
        // the authorized `hcl.expression@1` ExtendedValue.
        let source = hcl::parse(
            Arc::<[u8]>::from(
                b"region = \"us-east-1\"\ncount = 3\nratio = 1.50\nsmall = 15e-1\nderived = 1 + 2\n"
                    .as_slice(),
            ),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .unwrap();
        let projection = hcl::ProjectionRequest::body_with_expression_policy(
            hcl::ExpressionPolicy::ProjectExpression,
        );
        let ConversionResult::Complete(complete) =
            convert_hcl(&source, projection, &hcl_tfvars_request())
        else {
            panic!("hcl.native to hcl.tfvars should complete exactly")
        };
        assert_eq!(
            complete.document.render(),
            b"region = \"us-east-1\"\ncount = 3\nratio = 1.5\nsmall = 1.5\nderived = 1 + 2\n"
        );
        assert_eq!(
            complete.report.overall_fidelity(),
            ConversionFidelity::Transformed
        );
        assert_eq!(
            complete.report.source_profile(),
            &ProfileId::new("hcl.native", 1)
        );
        assert_eq!(
            complete.report.target_profile(),
            &ProfileId::new("hcl.tfvars", 1)
        );
        assert!(matches!(
            complete.projection_provenance,
            ConversionProjectionProvenance::Hcl(_)
        ));
        assert!(!complete.materialization_provenance.entries().is_empty());
    }

    #[test]
    fn hcl_conversion_derived_expressions_fail_atomically() {
        // A derived expression under the default exact body target is an
        // atomic projection failure; conversion never implicitly enables the
        // ProjectExpression strategy (RFC 0014 §8.2).
        let source = hcl::parse(
            Arc::<[u8]>::from(b"a = b + 1\n".as_slice()),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .unwrap();
        assert_eq!(source.status(), document::FormationStatus::Complete);
        assert!(matches!(
            convert_hcl(&source, hcl::ProjectionRequest::body(), &hcl_request()),
            ConversionResult::Failed(ConversionFailure::ProjectionFailed { .. })
        ));
    }
}
