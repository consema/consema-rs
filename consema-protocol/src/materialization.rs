//! Semantic-model v3 materialization request, report, and provenance messages.

use crate::query::{association_value, parse_association, parse_path, path_value};
use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32, unsigned_u64,
};
use crate::{
    ContractId, DiagnosticMessage, ErrorCodeRegistry, ProtocolError, ProtocolErrorKind,
    SourceEncodingMessage, SourceSnapshotMessage, SourceSnapshotMessageV2,
};
use consema_core::{
    AssociationLocation, PortableValue, PortableValueKind, SequenceBuilder, ValuePath,
};
use consema_document::{
    MappingPolicy, MaterializationFailure, MaterializationFidelity, MaterializationInputLocation,
    MaterializationLimits, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationStyleId, NewlinePolicy, NodeRef,
    ProfileId, RepresentabilityPolicy, SourceEncoding, SourceLimits,
};
use std::collections::HashMap;

/// Transferable `core.materialization-request@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationRequestMessage {
    request: MaterializationRequest,
}

impl MaterializationRequestMessage {
    /// Copies one validated common request.
    #[must_use]
    pub fn from_request(request: &MaterializationRequest) -> Self {
        Self {
            request: request.clone(),
        }
    }

    /// Exact common request.
    #[must_use]
    pub const fn request(&self) -> &MaterializationRequest {
        &self.request
    }

    /// Encodes the fixed-field request schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        if matches!(self.request.encoding(), SourceEncoding::WindowsCodePage(_)) {
            return Err(crate::schema::invalid(
                "$.encoding",
                "core.materialization-request@1 does not support Windows code pages",
            ));
        }
        materialization_request_value(
            &self.request,
            "core.materialization-request@1",
            PortableValue::string(self.request.encoding().as_str()),
        )
    }

    /// Strictly decodes every request policy and bound.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        materialization_request_from_value(
            value,
            "core.materialization-request@1",
            parse_materialization_encoding_v1,
        )
        .map(|request| Self { request })
    }
}

/// Transferable `core.materialization-request@2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationRequestMessageV2 {
    request: MaterializationRequest,
}

impl MaterializationRequestMessageV2 {
    /// Copies one validated common request.
    #[must_use]
    pub fn from_request(request: &MaterializationRequest) -> Self {
        Self {
            request: request.clone(),
        }
    }

    /// Exact common request.
    #[must_use]
    pub const fn request(&self) -> &MaterializationRequest {
        &self.request
    }

    /// Encodes the exact materialization-request v2 schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        materialization_request_value(
            &self.request,
            "core.materialization-request@2",
            SourceEncodingMessage::from_encoding(self.request.encoding()).to_value(),
        )
    }

    /// Strictly decodes every v2 request policy and bound.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        materialization_request_from_value(
            value,
            "core.materialization-request@2",
            crate::source::source_encoding_from_value,
        )
        .map(|request| Self { request })
    }
}

fn materialization_request_value(
    request: &MaterializationRequest,
    schema: &'static str,
    encoding: PortableValue,
) -> Result<PortableValue, ProtocolError> {
    Ok(object(vec![
        ("schema", PortableValue::string(schema)),
        ("target_profile", profile_value(request.target_profile())),
        (
            "style",
            reference_value(request.style().id(), request.style().version()),
        ),
        ("encoding", encoding),
        (
            "newline",
            PortableValue::string(newline_name(request.newline())),
        ),
        (
            "mapping_policy",
            PortableValue::string(mapping_policy_name(request.mapping_policy())),
        ),
        (
            "representability",
            PortableValue::string(representability_name(request.representability())),
        ),
        ("limits", limits_value(request.limits())?),
    ]))
}

fn materialization_request_from_value(
    value: &PortableValue,
    schema: &'static str,
    parse_encoding: fn(&PortableValue, &str) -> Result<SourceEncoding, ProtocolError>,
) -> Result<MaterializationRequest, ProtocolError> {
    let fields = schema_fields(
        value,
        schema,
        &[
            "schema",
            "target_profile",
            "style",
            "encoding",
            "newline",
            "mapping_policy",
            "representability",
            "limits",
        ],
        "$",
    )?;
    let target_profile = parse_profile(fields[1], "$.target_profile")?;
    let (style_id, style_version) = parse_reference(fields[2], "$.style")?;
    let encoding = parse_encoding(fields[3], "$.encoding")?;
    let newline = parse_newline(string(fields[4], "$.newline")?, "$.newline")?;
    let mapping_policy =
        parse_mapping_policy(string(fields[5], "$.mapping_policy")?, "$.mapping_policy")?;
    if string(fields[6], "$.representability")? != "ExactOnly" {
        return Err(crate::schema::invalid(
            "$.representability",
            "requires ExactOnly",
        ));
    }
    Ok(MaterializationRequest::new(
        target_profile,
        MaterializationStyleId::new(style_id, style_version),
    )
    .with_encoding(encoding)
    .with_newline(newline)
    .with_mapping_policy(mapping_policy)
    .with_limits(parse_limits(fields[7], "$.limits")?))
}

fn parse_materialization_encoding_v1(
    value: &PortableValue,
    path: &str,
) -> Result<SourceEncoding, ProtocolError> {
    parse_encoding(string(value, path)?, path)
}

/// Ordered `core.materialization-report@1` diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializationReportMessage {
    events: Vec<DiagnosticMessage>,
}

impl MaterializationReportMessage {
    /// Validates all events against semantic-model v3.
    pub fn new(events: Vec<DiagnosticMessage>) -> Result<Self, ProtocolError> {
        Self::new_with_registry(events, ErrorCodeRegistry::v3())
    }

    /// Validates all events against one explicit semantic-model registry.
    pub fn new_with_registry(
        events: Vec<DiagnosticMessage>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        for event in &events {
            DiagnosticMessage::from_value_with_registry(&event.to_value(), registry)?;
        }
        Ok(Self { events })
    }

    /// Externalizes one common report, binding any target location explicitly.
    pub fn from_report(
        report: &MaterializationReport,
        target_source_id: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        Self::from_report_with_registry(report, target_source_id, ErrorCodeRegistry::v3())
    }

    /// Externalizes a report under one explicit semantic-model registry.
    pub fn from_report_with_registry(
        report: &MaterializationReport,
        target_source_id: Option<&str>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let events = report
            .events()
            .iter()
            .map(|event| {
                DiagnosticMessage::from_core_with_registry(event, target_source_id, registry)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new_with_registry(events, registry)
    }

    /// Ordered materialization events.
    #[must_use]
    pub fn events(&self) -> &[DiagnosticMessage] {
        &self.events
    }

    /// Encodes the fixed report schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut events = SequenceBuilder::new();
        for event in &self.events {
            events.push(event.to_value());
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.materialization-report@1"),
            ),
            ("events", events.build()),
        ])
    }

    /// Strictly decodes ordered v3 diagnostics.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v3())
    }

    /// Strictly decodes events under one explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.materialization-report@1",
            &["schema", "events"],
            "$",
        )?;
        let events = sequence(fields[1], "$.events")?
            .iter()
            .map(|event| DiagnosticMessage::from_value_with_registry(event, registry))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new_with_registry(events, registry)
    }
}

/// Portable input location in materialization provenance.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum MaterializationInputLocationMessage {
    /// Portable value path.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// Relationship from portable input to target syntax.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MaterializationRelationMessage {
    /// Direct exact semantic representation.
    Direct,
    /// Deterministic target-native re-encoding.
    Reencoded,
    /// Generated target syntax.
    Generated,
}

/// One transferable target origin with caller-stable identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedOriginMessage {
    /// Caller-stable target source identity.
    pub target_source_id: String,
    /// Caller-stable target node locator.
    pub target_node_locator: String,
    /// Inclusive target raw-byte start.
    pub start_byte: u64,
    /// Exclusive target raw-byte end.
    pub end_byte: u64,
    /// Input-to-output relation.
    pub relation: MaterializationRelationMessage,
}

/// One portable input location and all exact target origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationProvenanceEntryMessage {
    /// Portable input location.
    pub input: MaterializationInputLocationMessage,
    /// Non-empty ordered target origins.
    pub outputs: Vec<MaterializedOriginMessage>,
}

/// Transferable `core.materialization-provenance-map@1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializationProvenanceMapMessage {
    entries: Vec<MaterializationProvenanceEntryMessage>,
}

impl MaterializationProvenanceMapMessage {
    /// Validates stable identities, non-empty outputs, range order, and locator uniqueness.
    pub fn new(entries: Vec<MaterializationProvenanceEntryMessage>) -> Result<Self, ProtocolError> {
        let mut source_id = None::<&str>;
        let mut locator_ranges = HashMap::<&str, (u64, u64)>::new();
        for (entry_index, entry) in entries.iter().enumerate() {
            if entry.outputs.is_empty() {
                return Err(crate::schema::invalid(
                    &format!("$.entries[{entry_index}].outputs"),
                    "provenance entry requires at least one output",
                ));
            }
            for (output_index, output) in entry.outputs.iter().enumerate() {
                let path = format!("$.entries[{entry_index}].outputs[{output_index}]");
                if output.target_source_id.is_empty()
                    || output.target_source_id.len() > 1024
                    || output.target_node_locator.is_empty()
                    || output.target_node_locator.len() > 4096
                    || output.start_byte > output.end_byte
                {
                    return Err(crate::schema::invalid(&path, "invalid target origin"));
                }
                if source_id.is_some_and(|source| source != output.target_source_id) {
                    return Err(crate::schema::invalid(
                        &path,
                        "one provenance map must bind one target source",
                    ));
                }
                source_id = Some(&output.target_source_id);
                let range = (output.start_byte, output.end_byte);
                if locator_ranges
                    .insert(output.target_node_locator.as_str(), range)
                    .is_some_and(|previous| previous != range)
                {
                    return Err(crate::schema::invalid(
                        &path,
                        "one target node locator cannot identify contradictory ranges",
                    ));
                }
            }
        }
        Ok(Self { entries })
    }

    /// Externalizes a process-local map with mandatory caller-provided node locators.
    pub fn from_provenance<F>(
        provenance: &MaterializationProvenanceMap,
        target_source_id: &str,
        mut locator: F,
    ) -> Result<Self, ProtocolError>
    where
        F: FnMut(NodeRef) -> Option<String>,
    {
        if target_source_id.is_empty() || target_source_id.len() > 1024 {
            return Err(crate::schema::invalid(
                "$.target_source_id",
                "target source ID is invalid",
            ));
        }
        let mut locator_by_node = HashMap::<NodeRef, String>::new();
        let mut node_by_locator = HashMap::<String, NodeRef>::new();
        let entries = provenance
            .entries()
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                let input = match &entry.input {
                    MaterializationInputLocation::Value(path) => {
                        MaterializationInputLocationMessage::Value(path.clone())
                    }
                    MaterializationInputLocation::Association(location) => {
                        MaterializationInputLocationMessage::Association(location.clone())
                    }
                };
                let outputs = entry
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(output_index, output)| {
                        let target_node_locator = locator(output.node).ok_or_else(|| {
                            ProtocolError::new(
                                ProtocolErrorKind::ProcessLocalHandle,
                                format!(
                                    "$.entries[{entry_index}].outputs[{output_index}].target_node"
                                ),
                                "target node requires an external locator",
                            )
                        })?;
                        if locator_by_node
                            .insert(output.node, target_node_locator.clone())
                            .is_some_and(|previous| previous != target_node_locator)
                            || node_by_locator
                                .insert(target_node_locator.clone(), output.node)
                                .is_some_and(|previous| previous != output.node)
                        {
                            return Err(crate::schema::invalid(
                                &format!(
                                    "$.entries[{entry_index}].outputs[{output_index}].target_node_locator"
                                ),
                                "node locators must form a stable one-to-one identity mapping",
                            ));
                        }
                        Ok(MaterializedOriginMessage {
                            target_source_id: target_source_id.to_owned(),
                            target_node_locator,
                            start_byte: u64::try_from(output.span.start_byte()).map_err(|_| {
                                crate::schema::invalid("$.start_byte", "offset exceeds u64")
                            })?,
                            end_byte: u64::try_from(output.span.end_byte()).map_err(|_| {
                                crate::schema::invalid("$.end_byte", "offset exceeds u64")
                            })?,
                            relation: match output.relation {
                                MaterializationRelation::Direct => {
                                    MaterializationRelationMessage::Direct
                                }
                                MaterializationRelation::Reencoded => {
                                    MaterializationRelationMessage::Reencoded
                                }
                                MaterializationRelation::Generated => {
                                    MaterializationRelationMessage::Generated
                                }
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, ProtocolError>>()?;
                Ok(MaterializationProvenanceEntryMessage { input, outputs })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        Self::new(entries)
    }

    /// Ordered complete provenance entries.
    #[must_use]
    pub fn entries(&self) -> &[MaterializationProvenanceEntryMessage] {
        &self.entries
    }

    /// Encodes the fixed provenance schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut entries = SequenceBuilder::new();
        for entry in &self.entries {
            let mut outputs = SequenceBuilder::new();
            for output in &entry.outputs {
                outputs.push(object(vec![
                    (
                        "target_source_id",
                        PortableValue::string(output.target_source_id.as_str()),
                    ),
                    (
                        "target_node_locator",
                        PortableValue::string(output.target_node_locator.as_str()),
                    ),
                    ("start_byte", integer_u64(output.start_byte)),
                    ("end_byte", integer_u64(output.end_byte)),
                    (
                        "relation",
                        PortableValue::string(relation_name(output.relation)),
                    ),
                ]));
            }
            entries.push(object(vec![
                ("input", input_location_value(&entry.input)),
                ("outputs", outputs.build()),
            ]));
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.materialization-provenance-map@1"),
            ),
            ("entries", entries.build()),
        ])
    }

    /// Strictly decodes external identities and complete ordered mappings.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.materialization-provenance-map@1",
            &["schema", "entries"],
            "$",
        )?;
        let entries = sequence(fields[1], "$.entries")?
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                let path = format!("$.entries[{entry_index}]");
                let fields = exact_fields(entry, &["input", "outputs"], &path)?;
                let outputs = sequence(fields[1], &format!("{path}.outputs"))?
                    .iter()
                    .enumerate()
                    .map(|(output_index, output)| {
                        parse_output(output, &format!("{path}.outputs[{output_index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(MaterializationProvenanceEntryMessage {
                    input: parse_input_location(fields[0], &format!("{path}.input"))?,
                    outputs,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        Self::new(entries)
    }
}

/// Stable transferable materialization failure, without partial target bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationFailureMessage {
    /// Request fields contradict the target contract.
    InvalidRequest(String),
    /// Target profile is unavailable.
    UnsupportedProfile,
    /// Style is unavailable for the target profile.
    UnsupportedStyle,
    /// Encoding is unavailable for the target profile.
    UnsupportedEncoding,
    /// Newline policy is unavailable for the selected style.
    UnsupportedNewline,
    /// One complete input value cannot be represented.
    Unrepresentable {
        /// Stable portable input path.
        path: ValuePath,
        /// Unrepresentable core kind.
        kind: PortableValueKind,
    },
    /// A configured limit was reached.
    ResourceLimit(String),
    /// Generated bytes did not form a target document.
    FormationFailed,
}

impl MaterializationFailureMessage {
    /// Copies one common failure into its owned transferable representation.
    #[must_use]
    pub fn from_failure(failure: &MaterializationFailure) -> Self {
        match failure {
            MaterializationFailure::InvalidRequest(detail) => {
                Self::InvalidRequest((*detail).to_owned())
            }
            MaterializationFailure::UnsupportedProfile => Self::UnsupportedProfile,
            MaterializationFailure::UnsupportedStyle => Self::UnsupportedStyle,
            MaterializationFailure::UnsupportedEncoding => Self::UnsupportedEncoding,
            MaterializationFailure::UnsupportedNewline => Self::UnsupportedNewline,
            MaterializationFailure::Unrepresentable { path, kind } => Self::Unrepresentable {
                path: path.clone(),
                kind: *kind,
            },
            MaterializationFailure::ResourceLimit(limit) => {
                Self::ResourceLimit((*limit).to_owned())
            }
            MaterializationFailure::FormationFailed => Self::FormationFailed,
        }
    }

    /// Exact public error code registered by semantic-model v3.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "core.materialization.invalid-request@1",
            Self::UnsupportedProfile => "core.materialization.unsupported-profile@1",
            Self::UnsupportedStyle => "core.materialization.unsupported-style@1",
            Self::UnsupportedEncoding => "core.materialization.unsupported-encoding@1",
            Self::UnsupportedNewline => "core.materialization.unsupported-newline@1",
            Self::Unrepresentable { .. } => "core.materialization.unrepresentable@1",
            Self::ResourceLimit(_) => "core.materialization.resource-limit@1",
            Self::FormationFailed => "core.materialization.formation-failed@1",
        }
    }
}

/// Closed transferable materialization completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationOutcomeMessage {
    /// Complete target snapshot and every required audit fact.
    Complete {
        /// Caller-stable target source identity.
        target_source_id: String,
        /// Verified immutable target source.
        snapshot: SourceSnapshotMessage,
        /// Whole-operation semantic fidelity.
        fidelity: MaterializationFidelity,
        /// Ordered materialization report.
        report: MaterializationReportMessage,
        /// Complete externally bound input-to-target provenance.
        provenance: MaterializationProvenanceMapMessage,
    },
    /// Failed attempt with no target bytes or partial provenance.
    Failed {
        /// Stable failure detail.
        failure: MaterializationFailureMessage,
        /// Ordered events discovered before failure.
        report: MaterializationReportMessage,
        /// Stable input paths analyzed before failure.
        analyzed_input_paths: Vec<ValuePath>,
    },
}

/// Transferable `core.materialization-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationResultMessage {
    target_profile: ProfileId,
    outcome: MaterializationOutcomeMessage,
}

impl MaterializationResultMessage {
    /// Validates a complete result and binds every target fact to one stable source ID.
    pub fn complete(
        target_profile: ProfileId,
        target_source_id: impl Into<String>,
        snapshot: SourceSnapshotMessage,
        fidelity: MaterializationFidelity,
        report: MaterializationReportMessage,
        provenance: MaterializationProvenanceMapMessage,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            target_profile,
            MaterializationOutcomeMessage::Complete {
                target_source_id: target_source_id.into(),
                snapshot,
                fidelity,
                report,
                provenance,
            },
        )
    }

    /// Validates a failed result which cannot carry target bytes or provenance.
    pub fn failed(
        target_profile: ProfileId,
        failure: MaterializationFailureMessage,
        report: MaterializationReportMessage,
        analyzed_input_paths: Vec<ValuePath>,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            target_profile,
            MaterializationOutcomeMessage::Failed {
                failure,
                report,
                analyzed_input_paths,
            },
        )
    }

    fn new(
        target_profile: ProfileId,
        outcome: MaterializationOutcomeMessage,
    ) -> Result<Self, ProtocolError> {
        match &outcome {
            MaterializationOutcomeMessage::Complete {
                target_source_id,
                snapshot,
                fidelity,
                report,
                provenance,
            } => {
                validate_complete_materialization(
                    target_source_id,
                    snapshot.snapshot().bytes().len(),
                    *fidelity,
                    report,
                    provenance,
                )?;
            }
            MaterializationOutcomeMessage::Failed { report, .. } => {
                validate_failed_materialization(report)?;
            }
        }
        Ok(Self {
            target_profile,
            outcome,
        })
    }

    /// Exact target Profile.
    #[must_use]
    pub const fn target_profile(&self) -> &ProfileId {
        &self.target_profile
    }

    /// Complete or explicitly failed outcome.
    #[must_use]
    pub const fn outcome(&self) -> &MaterializationOutcomeMessage {
        &self.outcome
    }

    /// Encodes the fixed, explicitly tagged completion schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            (
                "schema",
                PortableValue::string("core.materialization-result@1"),
            ),
            ("target_profile", profile_value(&self.target_profile)),
            ("outcome", outcome_value(&self.outcome)),
        ])
    }

    /// Strictly decodes and revalidates snapshot, report, provenance, and failure facts.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v3())
    }

    /// Strictly decodes reports under one explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.materialization-result@1",
            &["schema", "target_profile", "outcome"],
            "$",
        )?;
        let target_profile = parse_profile(fields[1], "$.target_profile")?;
        let outcome_fields = fields[2].as_object().ok_or_else(|| {
            ProtocolError::new(ProtocolErrorKind::WrongType, "$.outcome", "expected Object")
        })?;
        let kind = outcome_fields
            .iter()
            .find(|entry| entry.key() == "kind")
            .ok_or_else(|| crate::schema::invalid("$.outcome", "missing kind"))?;
        match string(kind.value(), "$.outcome.kind")? {
            "Complete" => {
                let fields = exact_fields(
                    fields[2],
                    &[
                        "kind",
                        "target_source_id",
                        "snapshot",
                        "fidelity",
                        "report",
                        "provenance",
                    ],
                    "$.outcome",
                )?;
                Self::complete(
                    target_profile,
                    string(fields[1], "$.outcome.target_source_id")?,
                    SourceSnapshotMessage::from_value(fields[2], SourceLimits::default())?,
                    parse_fidelity(string(fields[3], "$.outcome.fidelity")?)?,
                    MaterializationReportMessage::from_value_with_registry(fields[4], registry)?,
                    MaterializationProvenanceMapMessage::from_value(fields[5])?,
                )
            }
            "Failed" => {
                let fields = exact_fields(
                    fields[2],
                    &["kind", "failure", "report", "analyzed_input_paths"],
                    "$.outcome",
                )?;
                let analyzed_input_paths = sequence(fields[3], "$.outcome.analyzed_input_paths")?
                    .iter()
                    .enumerate()
                    .map(|(index, path)| {
                        parse_path(path, &format!("$.outcome.analyzed_input_paths[{index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::failed(
                    target_profile,
                    parse_failure(fields[1], "$.outcome.failure")?,
                    MaterializationReportMessage::from_value_with_registry(fields[2], registry)?,
                    analyzed_input_paths,
                )
            }
            _ => Err(crate::schema::invalid(
                "$.outcome.kind",
                "unknown materialization outcome",
            )),
        }
    }
}

/// Closed transferable materialization-v2 completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationOutcomeMessageV2 {
    /// Complete target snapshot and every required audit fact.
    Complete {
        /// Caller-stable target source identity.
        target_source_id: String,
        /// Verified immutable source-v2 target.
        snapshot: SourceSnapshotMessageV2,
        /// Whole-operation semantic fidelity.
        fidelity: MaterializationFidelity,
        /// Ordered materialization report.
        report: MaterializationReportMessage,
        /// Complete externally bound input-to-target provenance.
        provenance: MaterializationProvenanceMapMessage,
    },
    /// Failed attempt with no target bytes or partial provenance.
    Failed {
        /// Stable failure detail.
        failure: MaterializationFailureMessage,
        /// Ordered events discovered before failure.
        report: MaterializationReportMessage,
        /// Stable input paths analyzed before failure.
        analyzed_input_paths: Vec<ValuePath>,
    },
}

/// Transferable `core.materialization-result@2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationResultMessageV2 {
    target_profile: ProfileId,
    outcome: MaterializationOutcomeMessageV2,
}

impl MaterializationResultMessageV2 {
    /// Validates a complete source-v2 result and every target binding.
    pub fn complete(
        target_profile: ProfileId,
        target_source_id: impl Into<String>,
        snapshot: SourceSnapshotMessageV2,
        fidelity: MaterializationFidelity,
        report: MaterializationReportMessage,
        provenance: MaterializationProvenanceMapMessage,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            target_profile,
            MaterializationOutcomeMessageV2::Complete {
                target_source_id: target_source_id.into(),
                snapshot,
                fidelity,
                report,
                provenance,
            },
        )
    }

    /// Validates a failed result which cannot carry target bytes or provenance.
    pub fn failed(
        target_profile: ProfileId,
        failure: MaterializationFailureMessage,
        report: MaterializationReportMessage,
        analyzed_input_paths: Vec<ValuePath>,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            target_profile,
            MaterializationOutcomeMessageV2::Failed {
                failure,
                report,
                analyzed_input_paths,
            },
        )
    }

    fn new(
        target_profile: ProfileId,
        outcome: MaterializationOutcomeMessageV2,
    ) -> Result<Self, ProtocolError> {
        match &outcome {
            MaterializationOutcomeMessageV2::Complete {
                target_source_id,
                snapshot,
                fidelity,
                report,
                provenance,
            } => validate_complete_materialization(
                target_source_id,
                snapshot.snapshot().bytes().len(),
                *fidelity,
                report,
                provenance,
            )?,
            MaterializationOutcomeMessageV2::Failed { report, .. } => {
                validate_failed_materialization(report)?;
            }
        }
        Ok(Self {
            target_profile,
            outcome,
        })
    }

    /// Exact target Profile.
    #[must_use]
    pub const fn target_profile(&self) -> &ProfileId {
        &self.target_profile
    }

    /// Complete or explicitly failed outcome.
    #[must_use]
    pub const fn outcome(&self) -> &MaterializationOutcomeMessageV2 {
        &self.outcome
    }

    /// Encodes the fixed, explicitly tagged result-v2 schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            (
                "schema",
                PortableValue::string("core.materialization-result@2"),
            ),
            ("target_profile", profile_value(&self.target_profile)),
            ("outcome", outcome_value_v2(&self.outcome)),
        ])
    }

    /// Strictly decodes reports under one explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.materialization-result@2",
            &["schema", "target_profile", "outcome"],
            "$",
        )?;
        let target_profile = parse_profile(fields[1], "$.target_profile")?;
        let outcome_fields = fields[2].as_object().ok_or_else(|| {
            ProtocolError::new(ProtocolErrorKind::WrongType, "$.outcome", "expected Object")
        })?;
        let kind = outcome_fields
            .iter()
            .find(|entry| entry.key() == "kind")
            .ok_or_else(|| crate::schema::invalid("$.outcome", "missing kind"))?;
        match string(kind.value(), "$.outcome.kind")? {
            "Complete" => {
                let fields = exact_fields(
                    fields[2],
                    &[
                        "kind",
                        "target_source_id",
                        "snapshot",
                        "fidelity",
                        "report",
                        "provenance",
                    ],
                    "$.outcome",
                )?;
                Self::complete(
                    target_profile,
                    string(fields[1], "$.outcome.target_source_id")?,
                    SourceSnapshotMessageV2::from_value(fields[2], SourceLimits::default())?,
                    parse_fidelity(string(fields[3], "$.outcome.fidelity")?)?,
                    MaterializationReportMessage::from_value_with_registry(fields[4], registry)?,
                    MaterializationProvenanceMapMessage::from_value(fields[5])?,
                )
            }
            "Failed" => {
                let fields = exact_fields(
                    fields[2],
                    &["kind", "failure", "report", "analyzed_input_paths"],
                    "$.outcome",
                )?;
                let analyzed_input_paths = sequence(fields[3], "$.outcome.analyzed_input_paths")?
                    .iter()
                    .enumerate()
                    .map(|(index, path)| {
                        parse_path(path, &format!("$.outcome.analyzed_input_paths[{index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::failed(
                    target_profile,
                    parse_failure(fields[1], "$.outcome.failure")?,
                    MaterializationReportMessage::from_value_with_registry(fields[2], registry)?,
                    analyzed_input_paths,
                )
            }
            _ => Err(crate::schema::invalid(
                "$.outcome.kind",
                "unknown materialization outcome",
            )),
        }
    }
}

fn validate_complete_materialization(
    target_source_id: &str,
    snapshot_len: usize,
    fidelity: MaterializationFidelity,
    report: &MaterializationReportMessage,
    provenance: &MaterializationProvenanceMapMessage,
) -> Result<(), ProtocolError> {
    validate_source_id(target_source_id, "$.outcome.target_source_id")?;
    validate_report_source(report, Some(target_source_id))?;
    let output_len = u64::try_from(snapshot_len)
        .map_err(|_| crate::schema::invalid("$.outcome.snapshot", "snapshot length exceeds u64"))?;
    for (entry_index, entry) in provenance.entries().iter().enumerate() {
        for (output_index, output) in entry.outputs.iter().enumerate() {
            if output.target_source_id != target_source_id || output.end_byte > output_len {
                return Err(crate::schema::invalid(
                    &format!("$.outcome.provenance.entries[{entry_index}].outputs[{output_index}]"),
                    "provenance target binding or range contradicts the snapshot",
                ));
            }
        }
    }
    if fidelity == MaterializationFidelity::Transformed
        && !report
            .events()
            .iter()
            .any(|event| event.code == "core.materialization.mapping-transformed@1")
    {
        return Err(crate::schema::invalid(
            "$.outcome.report",
            "Transformed fidelity requires an explicit transformation event",
        ));
    }
    Ok(())
}

fn validate_failed_materialization(
    report: &MaterializationReportMessage,
) -> Result<(), ProtocolError> {
    validate_report_source(report, None)
}

fn outcome_value(outcome: &MaterializationOutcomeMessage) -> PortableValue {
    match outcome {
        MaterializationOutcomeMessage::Complete {
            target_source_id,
            snapshot,
            fidelity,
            report,
            provenance,
        } => object(vec![
            ("kind", PortableValue::string("Complete")),
            (
                "target_source_id",
                PortableValue::string(target_source_id.as_str()),
            ),
            ("snapshot", snapshot.to_value()),
            ("fidelity", PortableValue::string(fidelity_name(*fidelity))),
            ("report", report.to_value()),
            ("provenance", provenance.to_value()),
        ]),
        MaterializationOutcomeMessage::Failed {
            failure,
            report,
            analyzed_input_paths,
        } => {
            let mut paths = SequenceBuilder::new();
            for path in analyzed_input_paths {
                paths.push(path_value(path));
            }
            object(vec![
                ("kind", PortableValue::string("Failed")),
                ("failure", failure_value(failure)),
                ("report", report.to_value()),
                ("analyzed_input_paths", paths.build()),
            ])
        }
    }
}

fn outcome_value_v2(outcome: &MaterializationOutcomeMessageV2) -> PortableValue {
    match outcome {
        MaterializationOutcomeMessageV2::Complete {
            target_source_id,
            snapshot,
            fidelity,
            report,
            provenance,
        } => object(vec![
            ("kind", PortableValue::string("Complete")),
            (
                "target_source_id",
                PortableValue::string(target_source_id.as_str()),
            ),
            ("snapshot", snapshot.to_value()),
            ("fidelity", PortableValue::string(fidelity_name(*fidelity))),
            ("report", report.to_value()),
            ("provenance", provenance.to_value()),
        ]),
        MaterializationOutcomeMessageV2::Failed {
            failure,
            report,
            analyzed_input_paths,
        } => {
            let mut paths = SequenceBuilder::new();
            for path in analyzed_input_paths {
                paths.push(path_value(path));
            }
            object(vec![
                ("kind", PortableValue::string("Failed")),
                ("failure", failure_value(failure)),
                ("report", report.to_value()),
                ("analyzed_input_paths", paths.build()),
            ])
        }
    }
}

fn failure_value(failure: &MaterializationFailureMessage) -> PortableValue {
    match failure {
        MaterializationFailureMessage::InvalidRequest(detail) => object(vec![
            ("kind", PortableValue::string("InvalidRequest")),
            ("code", PortableValue::string(failure.code())),
            ("detail", PortableValue::string(detail.as_str())),
        ]),
        MaterializationFailureMessage::UnsupportedProfile => {
            simple_failure_value("UnsupportedProfile", failure.code())
        }
        MaterializationFailureMessage::UnsupportedStyle => {
            simple_failure_value("UnsupportedStyle", failure.code())
        }
        MaterializationFailureMessage::UnsupportedEncoding => {
            simple_failure_value("UnsupportedEncoding", failure.code())
        }
        MaterializationFailureMessage::UnsupportedNewline => {
            simple_failure_value("UnsupportedNewline", failure.code())
        }
        MaterializationFailureMessage::Unrepresentable { path, kind } => object(vec![
            ("kind", PortableValue::string("Unrepresentable")),
            ("code", PortableValue::string(failure.code())),
            ("path", path_value(path)),
            ("value_kind", PortableValue::string(value_kind_name(*kind))),
        ]),
        MaterializationFailureMessage::ResourceLimit(limit) => object(vec![
            ("kind", PortableValue::string("ResourceLimit")),
            ("code", PortableValue::string(failure.code())),
            ("limit", PortableValue::string(limit.as_str())),
        ]),
        MaterializationFailureMessage::FormationFailed => {
            simple_failure_value("FormationFailed", failure.code())
        }
    }
}

fn simple_failure_value(kind: &str, code: &str) -> PortableValue {
    object(vec![
        ("kind", PortableValue::string(kind)),
        ("code", PortableValue::string(code)),
    ])
}

fn parse_failure(
    value: &PortableValue,
    path: &str,
) -> Result<MaterializationFailureMessage, ProtocolError> {
    let entries = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Object"))?;
    let kind_entry = entries
        .iter()
        .find(|entry| entry.key() == "kind")
        .ok_or_else(|| crate::schema::invalid(path, "missing kind"))?;
    let kind = string(kind_entry.value(), &format!("{path}.kind"))?;
    let failure = match kind {
        "InvalidRequest" => {
            let fields = exact_fields(value, &["kind", "code", "detail"], path)?;
            let detail = string(fields[2], &format!("{path}.detail"))?;
            if detail.is_empty() || detail.len() > 4096 {
                return Err(crate::schema::invalid(path, "invalid failure detail"));
            }
            MaterializationFailureMessage::InvalidRequest(detail.to_owned())
        }
        "UnsupportedProfile" => {
            exact_fields(value, &["kind", "code"], path)?;
            MaterializationFailureMessage::UnsupportedProfile
        }
        "UnsupportedStyle" => {
            exact_fields(value, &["kind", "code"], path)?;
            MaterializationFailureMessage::UnsupportedStyle
        }
        "UnsupportedEncoding" => {
            exact_fields(value, &["kind", "code"], path)?;
            MaterializationFailureMessage::UnsupportedEncoding
        }
        "UnsupportedNewline" => {
            exact_fields(value, &["kind", "code"], path)?;
            MaterializationFailureMessage::UnsupportedNewline
        }
        "Unrepresentable" => {
            let fields = exact_fields(value, &["kind", "code", "path", "value_kind"], path)?;
            MaterializationFailureMessage::Unrepresentable {
                path: parse_path(fields[2], &format!("{path}.path"))?,
                kind: parse_value_kind(string(fields[3], &format!("{path}.value_kind"))?, path)?,
            }
        }
        "ResourceLimit" => {
            let fields = exact_fields(value, &["kind", "code", "limit"], path)?;
            let limit = string(fields[2], &format!("{path}.limit"))?;
            if limit.is_empty()
                || limit.len() > 256
                || !limit
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(crate::schema::invalid(path, "invalid resource limit ID"));
            }
            MaterializationFailureMessage::ResourceLimit(limit.to_owned())
        }
        "FormationFailed" => {
            exact_fields(value, &["kind", "code"], path)?;
            MaterializationFailureMessage::FormationFailed
        }
        _ => {
            return Err(crate::schema::invalid(
                path,
                "unknown materialization failure",
            ));
        }
    };
    let code_entry = entries
        .iter()
        .find(|entry| entry.key() == "code")
        .ok_or_else(|| crate::schema::invalid(path, "missing code"))?;
    let code = string(code_entry.value(), &format!("{path}.code"))?;
    ErrorCodeRegistry::v3().validate_at(code, &format!("{path}.code"))?;
    if code != failure.code() {
        return Err(crate::schema::invalid(
            &format!("{path}.code"),
            "failure kind contradicts its registered code",
        ));
    }
    Ok(failure)
}

fn validate_source_id(source_id: &str, path: &str) -> Result<(), ProtocolError> {
    if source_id.is_empty() || source_id.len() > 1024 {
        return Err(crate::schema::invalid(path, "invalid source ID"));
    }
    Ok(())
}

fn validate_report_source(
    report: &MaterializationReportMessage,
    expected: Option<&str>,
) -> Result<(), ProtocolError> {
    for (index, event) in report.events().iter().enumerate() {
        let mismatched = event
            .primary
            .iter()
            .map(crate::SourceLocation::source_id)
            .chain(
                event
                    .related
                    .iter()
                    .map(|related| related.location.source_id()),
            )
            .chain(
                event
                    .fixes
                    .iter()
                    .filter_map(|fix| fix.location.as_ref())
                    .map(crate::SourceLocation::source_id),
            )
            .any(|source_id| expected != Some(source_id));
        if mismatched {
            return Err(crate::schema::invalid(
                &format!("$.outcome.report.events[{index}].location.source_id"),
                "report location contradicts the materialization outcome",
            ));
        }
    }
    Ok(())
}

const fn fidelity_name(fidelity: MaterializationFidelity) -> &'static str {
    match fidelity {
        MaterializationFidelity::Exact => "Exact",
        MaterializationFidelity::Transformed => "Transformed",
    }
}

fn parse_fidelity(value: &str) -> Result<MaterializationFidelity, ProtocolError> {
    match value {
        "Exact" => Ok(MaterializationFidelity::Exact),
        "Transformed" => Ok(MaterializationFidelity::Transformed),
        _ => Err(crate::schema::invalid(
            "$.outcome.fidelity",
            "unknown materialization fidelity",
        )),
    }
}

const fn value_kind_name(kind: PortableValueKind) -> &'static str {
    match kind {
        PortableValueKind::Null => "Null",
        PortableValueKind::Boolean => "Boolean",
        PortableValueKind::Integer => "Integer",
        PortableValueKind::Decimal => "Decimal",
        PortableValueKind::BinaryFloat32 => "BinaryFloat32",
        PortableValueKind::BinaryFloat64 => "BinaryFloat64",
        PortableValueKind::String => "String",
        PortableValueKind::Bytes => "Bytes",
        PortableValueKind::Date => "Date",
        PortableValueKind::Time => "Time",
        PortableValueKind::LocalDateTime => "LocalDateTime",
        PortableValueKind::OffsetDateTime => "OffsetDateTime",
        PortableValueKind::Sequence => "Sequence",
        PortableValueKind::Object => "Object",
        PortableValueKind::EntryMapping => "EntryMapping",
    }
}

fn parse_value_kind(value: &str, path: &str) -> Result<PortableValueKind, ProtocolError> {
    match value {
        "Null" => Ok(PortableValueKind::Null),
        "Boolean" => Ok(PortableValueKind::Boolean),
        "Integer" => Ok(PortableValueKind::Integer),
        "Decimal" => Ok(PortableValueKind::Decimal),
        "BinaryFloat32" => Ok(PortableValueKind::BinaryFloat32),
        "BinaryFloat64" => Ok(PortableValueKind::BinaryFloat64),
        "String" => Ok(PortableValueKind::String),
        "Bytes" => Ok(PortableValueKind::Bytes),
        "Date" => Ok(PortableValueKind::Date),
        "Time" => Ok(PortableValueKind::Time),
        "LocalDateTime" => Ok(PortableValueKind::LocalDateTime),
        "OffsetDateTime" => Ok(PortableValueKind::OffsetDateTime),
        "Sequence" => Ok(PortableValueKind::Sequence),
        "Object" => Ok(PortableValueKind::Object),
        "EntryMapping" => Ok(PortableValueKind::EntryMapping),
        _ => Err(crate::schema::invalid(path, "unknown portable value kind")),
    }
}

fn reference_value(id: &str, version: u32) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(id)),
        (
            "version",
            PortableValue::integer(consema_core::BigInteger::from(i64::from(version))),
        ),
    ])
}

fn profile_value(profile: &ProfileId) -> PortableValue {
    reference_value(profile.id(), profile.version())
}

fn parse_reference(value: &PortableValue, path: &str) -> Result<(String, u32), ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    let reference = ContractId::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )?;
    Ok((reference.id().to_owned(), reference.version()))
}

fn parse_profile(value: &PortableValue, path: &str) -> Result<ProfileId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    let reference = crate::ProfileReference::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )?;
    Ok(ProfileId::new(reference.id(), reference.version()))
}

fn limits_value(limits: MaterializationLimits) -> Result<PortableValue, ProtocolError> {
    let convert = |value: usize, path: &str| {
        u64::try_from(value).map_err(|_| crate::schema::invalid(path, "value exceeds u64"))
    };
    Ok(object(vec![
        (
            "max_input_nodes",
            integer_u64(convert(limits.max_input_nodes, "$.limits.max_input_nodes")?),
        ),
        (
            "max_output_bytes",
            integer_u64(convert(
                limits.max_output_bytes,
                "$.limits.max_output_bytes",
            )?),
        ),
        (
            "max_depth",
            integer_u64(convert(limits.max_depth, "$.limits.max_depth")?),
        ),
        (
            "max_report_entries",
            integer_u64(convert(
                limits.max_report_entries,
                "$.limits.max_report_entries",
            )?),
        ),
        (
            "max_provenance_entries",
            integer_u64(convert(
                limits.max_provenance_entries,
                "$.limits.max_provenance_entries",
            )?),
        ),
    ]))
}

fn parse_limits(value: &PortableValue, path: &str) -> Result<MaterializationLimits, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "max_input_nodes",
            "max_output_bytes",
            "max_depth",
            "max_report_entries",
            "max_provenance_entries",
        ],
        path,
    )?;
    Ok(MaterializationLimits {
        max_input_nodes: usize_value(fields[0], &format!("{path}.max_input_nodes"))?,
        max_output_bytes: usize_value(fields[1], &format!("{path}.max_output_bytes"))?,
        max_depth: usize_value(fields[2], &format!("{path}.max_depth"))?,
        max_report_entries: usize_value(fields[3], &format!("{path}.max_report_entries"))?,
        max_provenance_entries: usize_value(fields[4], &format!("{path}.max_provenance_entries"))?,
    })
}

fn usize_value(value: &PortableValue, path: &str) -> Result<usize, ProtocolError> {
    usize::try_from(unsigned_u64(value, path)?)
        .map_err(|_| crate::schema::invalid(path, "value exceeds usize"))
}

const fn newline_name(newline: NewlinePolicy) -> &'static str {
    match newline {
        NewlinePolicy::None => "None",
        NewlinePolicy::Lf => "Lf",
        NewlinePolicy::CrLf => "CrLf",
    }
}

fn parse_newline(value: &str, path: &str) -> Result<NewlinePolicy, ProtocolError> {
    match value {
        "None" => Ok(NewlinePolicy::None),
        "Lf" => Ok(NewlinePolicy::Lf),
        "CrLf" => Ok(NewlinePolicy::CrLf),
        _ => Err(crate::schema::invalid(path, "unknown newline policy")),
    }
}

const fn mapping_policy_name(policy: MappingPolicy) -> &'static str {
    match policy {
        MappingPolicy::RequireObject => "RequireObject",
        MappingPolicy::UniqueStringEntriesToObject => "UniqueStringEntriesToObject",
    }
}

fn parse_mapping_policy(value: &str, path: &str) -> Result<MappingPolicy, ProtocolError> {
    match value {
        "RequireObject" => Ok(MappingPolicy::RequireObject),
        "UniqueStringEntriesToObject" => Ok(MappingPolicy::UniqueStringEntriesToObject),
        _ => Err(crate::schema::invalid(path, "unknown mapping policy")),
    }
}

const fn representability_name(policy: RepresentabilityPolicy) -> &'static str {
    match policy {
        RepresentabilityPolicy::ExactOnly => "ExactOnly",
    }
}

fn parse_encoding(value: &str, path: &str) -> Result<SourceEncoding, ProtocolError> {
    match value {
        "binary" => Ok(SourceEncoding::Binary),
        "utf-8" => Ok(SourceEncoding::Utf8),
        "utf-16le" => Ok(SourceEncoding::Utf16Le),
        "utf-16be" => Ok(SourceEncoding::Utf16Be),
        "latin-1" => Ok(SourceEncoding::Latin1),
        _ => Err(crate::schema::invalid(path, "unknown source encoding")),
    }
}

fn input_location_value(input: &MaterializationInputLocationMessage) -> PortableValue {
    match input {
        MaterializationInputLocationMessage::Value(path) => object(vec![
            ("kind", PortableValue::string("Value")),
            ("value", path_value(path)),
        ]),
        MaterializationInputLocationMessage::Association(location) => object(vec![
            ("kind", PortableValue::string("Association")),
            ("value", association_value(location)),
        ]),
    }
}

fn parse_input_location(
    value: &PortableValue,
    path: &str,
) -> Result<MaterializationInputLocationMessage, ProtocolError> {
    let fields = exact_fields(value, &["kind", "value"], path)?;
    match string(fields[0], &format!("{path}.kind"))? {
        "Value" => parse_path(fields[1], &format!("{path}.value"))
            .map(MaterializationInputLocationMessage::Value),
        "Association" => parse_association(fields[1], &format!("{path}.value"))
            .map(MaterializationInputLocationMessage::Association),
        _ => Err(crate::schema::invalid(path, "unknown input location kind")),
    }
}

const fn relation_name(relation: MaterializationRelationMessage) -> &'static str {
    match relation {
        MaterializationRelationMessage::Direct => "Direct",
        MaterializationRelationMessage::Reencoded => "Reencoded",
        MaterializationRelationMessage::Generated => "Generated",
    }
}

fn parse_relation(
    value: &str,
    path: &str,
) -> Result<MaterializationRelationMessage, ProtocolError> {
    match value {
        "Direct" => Ok(MaterializationRelationMessage::Direct),
        "Reencoded" => Ok(MaterializationRelationMessage::Reencoded),
        "Generated" => Ok(MaterializationRelationMessage::Generated),
        _ => Err(crate::schema::invalid(
            path,
            "unknown materialization relation",
        )),
    }
}

fn parse_output(
    value: &PortableValue,
    path: &str,
) -> Result<MaterializedOriginMessage, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "target_source_id",
            "target_node_locator",
            "start_byte",
            "end_byte",
            "relation",
        ],
        path,
    )?;
    Ok(MaterializedOriginMessage {
        target_source_id: string(fields[0], &format!("{path}.target_source_id"))?.to_owned(),
        target_node_locator: string(fields[1], &format!("{path}.target_node_locator"))?.to_owned(),
        start_byte: unsigned_u64(fields[2], &format!("{path}.start_byte"))?,
        end_byte: unsigned_u64(fields[3], &format!("{path}.end_byte"))?,
        relation: parse_relation(string(fields[4], &format!("{path}.relation"))?, path)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProtocolLimits, decode_json, decode_pvce, encode_json, encode_pvce};
    use consema_document::{BomPolicy, EncodingRequest, SourceSnapshot};

    #[test]
    fn request_round_trip_keeps_every_explicit_field() {
        let request = MaterializationRequest::new(
            ProfileId::new("json.strict", 1),
            MaterializationStyleId::new("json.canonical-compact", 1),
        )
        .with_encoding(SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::None)
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
        .with_limits(MaterializationLimits {
            max_input_nodes: 11,
            max_output_bytes: 12,
            max_depth: 13,
            max_report_entries: 14,
            max_provenance_entries: 15,
        });
        let message = MaterializationRequestMessage::from_request(&request);
        let decoded =
            MaterializationRequestMessage::from_value(&message.to_value().unwrap()).unwrap();
        assert_eq!(decoded.request(), &request);
    }

    #[test]
    fn materialization_request_v1_rejects_windows_code_pages() {
        let request = MaterializationRequest::new(
            ProfileId::new("ini.windows", 1),
            MaterializationStyleId::new("ini.preserve", 1),
        )
        .with_encoding(SourceEncoding::WindowsCodePage(
            consema_document::WindowsCodePage::from_number(1252).unwrap(),
        ));
        let error = MaterializationRequestMessage::from_request(&request)
            .to_value()
            .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }

    #[test]
    fn materialization_request_v2_round_trips_windows_code_page() {
        let request = MaterializationRequest::new(
            ProfileId::new("ini.windows", 1),
            MaterializationStyleId::new("ini.preserve", 1),
        )
        .with_encoding(SourceEncoding::WindowsCodePage(
            consema_document::WindowsCodePage::from_number(936).unwrap(),
        ))
        .with_newline(NewlinePolicy::CrLf)
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
        .with_limits(MaterializationLimits {
            max_input_nodes: 21,
            max_output_bytes: 22,
            max_depth: 23,
            max_report_entries: 24,
            max_provenance_entries: 25,
        });
        let value = MaterializationRequestMessageV2::from_request(&request)
            .to_value()
            .unwrap();
        for transported in [
            decode_json(
                &encode_json(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
            decode_pvce(
                &encode_pvce(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
        ] {
            let decoded = MaterializationRequestMessageV2::from_value(&transported).unwrap();
            assert_eq!(decoded.request(), &request);
            assert_eq!(decoded.to_value().unwrap(), value);
        }
        assert!(MaterializationRequestMessage::from_value(&value).is_err());
    }

    #[test]
    fn provenance_round_trip_keeps_external_identity() {
        let message =
            MaterializationProvenanceMapMessage::new(vec![MaterializationProvenanceEntryMessage {
                input: MaterializationInputLocationMessage::Value(ValuePath::root()),
                outputs: vec![MaterializedOriginMessage {
                    target_source_id: "target".to_owned(),
                    target_node_locator: "$.root".to_owned(),
                    start_byte: 0,
                    end_byte: 1,
                    relation: MaterializationRelationMessage::Direct,
                }],
            }])
            .unwrap();
        assert_eq!(
            MaterializationProvenanceMapMessage::from_value(&message.to_value()).unwrap(),
            message
        );
    }

    #[test]
    fn provenance_rejects_missing_or_ambiguous_external_node_locators() {
        use consema_document::{
            DocumentAuthority, MaterializationProvenanceEntry, MaterializedOrigin, NodeRole,
        };

        let authority = DocumentAuthority::fresh();
        let provenance = MaterializationProvenanceMap::new(
            vec![MaterializationProvenanceEntry {
                input: MaterializationInputLocation::Value(ValuePath::root()),
                outputs: vec![MaterializedOrigin {
                    snapshot: authority.identity(),
                    node: authority.node_ref(0, NodeRole::Value),
                    span: authority.span(0, 1).unwrap(),
                    relation: MaterializationRelation::Direct,
                }],
            }],
            authority.identity(),
            MaterializationLimits::default(),
        )
        .unwrap();
        assert!(
            MaterializationProvenanceMapMessage::from_provenance(&provenance, "target:one", |_| {
                None
            },)
            .is_err_and(|error| error.kind() == ProtocolErrorKind::ProcessLocalHandle)
        );

        let two_nodes = MaterializationProvenanceMap::new(
            vec![MaterializationProvenanceEntry {
                input: MaterializationInputLocation::Value(ValuePath::root()),
                outputs: vec![
                    MaterializedOrigin {
                        snapshot: authority.identity(),
                        node: authority.node_ref(0, NodeRole::Value),
                        span: authority.span(0, 1).unwrap(),
                        relation: MaterializationRelation::Direct,
                    },
                    MaterializedOrigin {
                        snapshot: authority.identity(),
                        node: authority.node_ref(1, NodeRole::Value),
                        span: authority.span(1, 1).unwrap(),
                        relation: MaterializationRelation::Generated,
                    },
                ],
            }],
            authority.identity(),
            MaterializationLimits::default(),
        )
        .unwrap();
        assert!(
            MaterializationProvenanceMapMessage::from_provenance(&two_nodes, "target:one", |_| {
                Some("same-locator".to_owned())
            },)
            .is_err()
        );
    }

    #[test]
    fn complete_result_round_trip_keeps_snapshot_and_explicit_outcome() {
        let snapshot = SourceSnapshot::from_utf8(br#"{"ready":true}"#.as_slice()).unwrap();
        let message = MaterializationResultMessage::complete(
            ProfileId::new("json.strict", 1),
            "target:one",
            SourceSnapshotMessage::from_snapshot(&snapshot).unwrap(),
            MaterializationFidelity::Exact,
            MaterializationReportMessage::default(),
            MaterializationProvenanceMapMessage::default(),
        )
        .unwrap();
        assert_eq!(
            MaterializationResultMessage::from_value(&message.to_value()).unwrap(),
            message
        );
    }

    #[test]
    fn failed_result_round_trip_has_no_target_source_or_bytes() {
        let message = MaterializationResultMessage::failed(
            ProfileId::new("toml.1.0", 1),
            MaterializationFailureMessage::Unrepresentable {
                path: ValuePath::root(),
                kind: PortableValueKind::Null,
            },
            MaterializationReportMessage::default(),
            vec![ValuePath::root()],
        )
        .unwrap();
        let value = message.to_value();
        let encoded = format!("{value:?}");
        assert!(!encoded.contains("raw_bytes"));
        assert!(!encoded.contains("target_source_id"));
        assert_eq!(
            MaterializationResultMessage::from_value(&value).unwrap(),
            message
        );
    }

    #[test]
    fn complete_result_v2_round_trips_code_page_snapshot() {
        let snapshot = SourceSnapshot::from_raw(
            [0x80, b'=', b'1'],
            EncodingRequest::new(SourceEncoding::WindowsCodePage(
                consema_document::WindowsCodePage::from_number(1252).unwrap(),
            ))
            .with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        let message = MaterializationResultMessageV2::complete(
            ProfileId::new("ini.windows", 1),
            "target:windows-ini",
            SourceSnapshotMessageV2::from_snapshot(&snapshot),
            MaterializationFidelity::Exact,
            MaterializationReportMessage::default(),
            MaterializationProvenanceMapMessage::default(),
        )
        .unwrap();
        let value = message.to_value();
        for transported in [
            decode_json(
                &encode_json(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
            decode_pvce(
                &encode_pvce(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
        ] {
            let decoded = MaterializationResultMessageV2::from_value_with_registry(
                &transported,
                ErrorCodeRegistry::v5(),
            )
            .unwrap();
            assert_eq!(decoded, message);
            assert_eq!(decoded.to_value(), value);
        }
        assert!(MaterializationResultMessage::from_value(&value).is_err());
    }

    #[test]
    fn result_v2_rejects_snapshot_v1_and_failed_result_has_no_target() {
        let snapshot = SourceSnapshot::from_utf8(b"ok".as_slice()).unwrap();
        let message = MaterializationResultMessageV2::complete(
            ProfileId::new("json.strict", 1),
            "target:json",
            SourceSnapshotMessageV2::from_snapshot(&snapshot),
            MaterializationFidelity::Exact,
            MaterializationReportMessage::default(),
            MaterializationProvenanceMapMessage::default(),
        )
        .unwrap();
        let value = message.to_value();
        let fields = value.as_object().unwrap();
        let outcome = fields[2].value().as_object().unwrap();
        let forged_outcome = object(vec![
            ("kind", outcome[0].value().clone()),
            ("target_source_id", outcome[1].value().clone()),
            (
                "snapshot",
                SourceSnapshotMessage::from_snapshot(&snapshot)
                    .unwrap()
                    .to_value(),
            ),
            ("fidelity", outcome[3].value().clone()),
            ("report", outcome[4].value().clone()),
            ("provenance", outcome[5].value().clone()),
        ]);
        let forged = object(vec![
            ("schema", fields[0].value().clone()),
            ("target_profile", fields[1].value().clone()),
            ("outcome", forged_outcome),
        ]);
        assert!(
            MaterializationResultMessageV2::from_value_with_registry(
                &forged,
                ErrorCodeRegistry::v5(),
            )
            .is_err()
        );

        let failed = MaterializationResultMessageV2::failed(
            ProfileId::new("ini.portable", 1),
            MaterializationFailureMessage::UnsupportedEncoding,
            MaterializationReportMessage::default(),
            vec![ValuePath::root()],
        )
        .unwrap();
        let failed_value = failed.to_value();
        let encoded = format!("{failed_value:?}");
        assert!(!encoded.contains("raw_bytes"));
        assert!(!encoded.contains("target_source_id"));
        assert_eq!(
            MaterializationResultMessageV2::from_value_with_registry(
                &failed_value,
                ErrorCodeRegistry::v5(),
            )
            .unwrap(),
            failed
        );
    }
}
