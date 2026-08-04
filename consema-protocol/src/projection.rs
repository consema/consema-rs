//! Projection request, report, provenance, and result protocols.

use crate::query::{association_value, parse_association, parse_path, path_value};
use crate::schema::{
    boolean, exact_fields, integer_u64, nullable_string, object, optional_string, schema_fields,
    sequence, signed_i32, string, unsigned_u32, unsigned_u64,
};
use crate::{
    Completion, CompletionStatus, ContractId, DiagnosticMessage, ProtocolError, ProtocolErrorKind,
    SourceLocation,
};
use consema_core::{
    AssociationLocation, BigInteger, ObjectBuilder, PortableValue, QueryDefinition,
    SequenceBuilder, ValuePath,
};
use consema_document::NodeRef;
use std::collections::{BTreeMap, BTreeSet};

/// Versioned policy contract and deterministic arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPolicy {
    contract: ContractId,
    arguments: BTreeMap<String, PortableValue>,
}

impl ProjectionPolicy {
    /// Creates one policy contract.
    #[must_use]
    pub const fn new(contract: ContractId, arguments: BTreeMap<String, PortableValue>) -> Self {
        Self {
            contract,
            arguments,
        }
    }

    /// Policy identifier and version.
    #[must_use]
    pub const fn contract(&self) -> &ContractId {
        &self.contract
    }

    /// Deterministically sorted arguments.
    #[must_use]
    pub const fn arguments(&self) -> &BTreeMap<String, PortableValue> {
        &self.arguments
    }
}

/// Transferable projection rule scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionScope {
    /// Applies to the complete target.
    Global,
    /// Exact caller-defined native path in one stable source.
    ExactNativePath {
        /// Stable source ID.
        source_id: String,
        /// Format-native path contract string.
        path: String,
    },
    /// Scope resolved by a complete QueryDefinition.
    ResolvedQuery(QueryDefinition),
}

impl ProjectionScope {
    /// Explicitly refuses a raw process-local node scope.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.scope.node",
            "ExactNodeRef must be externalized before wire encoding",
        ))
    }
}

/// One auditable scoped projection policy rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRule {
    /// Stable request-local rule ID.
    pub rule_id: String,
    /// Transferable scope.
    pub scope: ProjectionScope,
    /// Explicit semantic priority.
    pub priority: i32,
    /// Policy contract.
    pub policy: ProjectionPolicy,
}

/// `core.projection-request@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRequestMessage {
    target: ContractId,
    default_policy: ProjectionPolicy,
    rules: Vec<ProjectionRule>,
    limits: BTreeMap<String, u64>,
}

impl ProjectionRequestMessage {
    /// Validates rule IDs, portable scopes, and semantic conflicts.
    pub fn new(
        target: ContractId,
        default_policy: ProjectionPolicy,
        rules: Vec<ProjectionRule>,
        limits: BTreeMap<String, u64>,
    ) -> Result<Self, ProtocolError> {
        let rule_ids = rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        if rule_ids.len() != rules.len()
            || rules
                .iter()
                .any(|rule| rule.rule_id.is_empty() || rule.rule_id.len() > 255)
        {
            return Err(crate::schema::invalid(
                "$.rules",
                "rule IDs must be non-empty and unique",
            ));
        }
        for scope in rules.iter().map(|rule| &rule.scope) {
            validate_scope(scope)?;
        }
        for (index, left) in rules.iter().enumerate() {
            for right in &rules[index.saturating_add(1)..] {
                if left.priority == right.priority
                    && left.scope == right.scope
                    && left.policy != right.policy
                {
                    return Err(crate::schema::invalid(
                        "$.rules",
                        "same-scope same-priority policies conflict",
                    ));
                }
            }
        }
        if limits.keys().any(|name| !valid_limit_name(name)) {
            return Err(crate::schema::invalid(
                "$.limits",
                "limit names must be stable lowercase identifiers",
            ));
        }
        Ok(Self {
            target,
            default_policy,
            rules,
            limits,
        })
    }

    /// Target contract.
    #[must_use]
    pub const fn target(&self) -> &ContractId {
        &self.target
    }

    /// Default policy.
    #[must_use]
    pub const fn default_policy(&self) -> &ProjectionPolicy {
        &self.default_policy
    }

    /// Auditable rule declaration order.
    #[must_use]
    pub fn rules(&self) -> &[ProjectionRule] {
        &self.rules
    }

    /// Named operation limits.
    #[must_use]
    pub const fn limits(&self) -> &BTreeMap<String, u64> {
        &self.limits
    }

    /// Encodes `core.projection-request@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut rules = SequenceBuilder::new();
        for rule in &self.rules {
            rules.push(rule_value(rule));
        }
        let mut limits = ObjectBuilder::new();
        for (name, limit) in &self.limits {
            limits
                .insert(name, integer_u64(*limit))
                .expect("BTreeMap keys are unique");
        }
        object(vec![
            ("schema", PortableValue::string("core.projection-request@1")),
            ("target", reference_value(&self.target)),
            ("default_policy", policy_value(&self.default_policy)),
            ("rules", rules.build()),
            ("limits", limits.build()),
        ])
    }

    /// Strictly decodes `core.projection-request@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.projection-request@1",
            &["schema", "target", "default_policy", "rules", "limits"],
            "$",
        )?;
        let rules = sequence(fields[3], "$.rules")?
            .iter()
            .enumerate()
            .map(|(index, item)| parse_rule(item, &format!("$.rules[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let limit_entries = fields[4].as_object().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorKind::WrongType,
                "$.limits",
                "expected Object<String, Integer>",
            )
        })?;
        let mut limits = BTreeMap::new();
        for entry in limit_entries {
            limits.insert(
                entry.key().to_owned(),
                unsigned_u64(entry.value(), &format!("$.limits.{}", entry.key()))?,
            );
        }
        Self::new(
            parse_reference(fields[1], "$.target")?,
            parse_policy(fields[2], "$.default_policy")?,
            rules,
            limits,
        )
    }
}

/// Projected value or association location.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProjectedLocationMessage {
    /// Portable value path.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// Provenance relationship from source fact to projected fact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProvenanceRelation {
    /// Direct semantic representation.
    Direct,
    /// Derived without source expansion.
    Derived,
    /// One source expanded into several projected facts.
    Expanded,
    /// Multiple sources merged.
    Merged,
    /// Generated by an explicit policy.
    Generated,
}

/// Transferable source origin with stable external identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOriginMessage {
    /// Stable source ID.
    pub source_id: String,
    /// Optional stable caller node locator.
    pub node_locator: Option<String>,
    /// Inclusive source byte start.
    pub start_byte: u64,
    /// Exclusive source byte end.
    pub end_byte: u64,
    /// Provenance relation.
    pub relation: ProvenanceRelation,
}

impl SourceOriginMessage {
    /// Validates a transferable source origin.
    pub fn new(
        source_id: impl Into<String>,
        node_locator: Option<String>,
        start_byte: u64,
        end_byte: u64,
        relation: ProvenanceRelation,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        if source_id.is_empty()
            || source_id.len() > 1024
            || start_byte > end_byte
            || node_locator
                .as_ref()
                .is_some_and(|locator| locator.is_empty() || locator.len() > 4096)
        {
            return Err(crate::schema::invalid(
                "$.origin",
                "invalid source identity, locator, or range",
            ));
        }
        Ok(Self {
            source_id,
            node_locator,
            start_byte,
            end_byte,
            relation,
        })
    }

    /// Explicitly refuses raw process-local provenance identities.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.origin.node",
            "NodeRef requires a stable caller locator",
        ))
    }
}

/// One projected location and all of its source origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntryMessage {
    /// Projected location.
    pub projected: ProjectedLocationMessage,
    /// One or more ordered origins.
    pub origins: Vec<SourceOriginMessage>,
}

/// Sorted unique `core.provenance-map@1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMapMessage {
    entries: Vec<ProvenanceEntryMessage>,
}

impl ProvenanceMapMessage {
    /// Validates sorted unique projected locations and non-empty origins.
    pub fn new(entries: Vec<ProvenanceEntryMessage>) -> Result<Self, ProtocolError> {
        if entries.iter().any(|entry| entry.origins.is_empty())
            || entries
                .windows(2)
                .any(|pair| pair[0].projected >= pair[1].projected)
        {
            return Err(crate::schema::invalid(
                "$.entries",
                "provenance locations must be sorted, unique, and have origins",
            ));
        }
        Ok(Self { entries })
    }

    /// Sorted provenance entries.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntryMessage] {
        &self.entries
    }

    /// Encodes `core.provenance-map@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut entries = SequenceBuilder::new();
        for entry in &self.entries {
            let mut origins = SequenceBuilder::new();
            for origin in &entry.origins {
                origins.push(origin_value(origin));
            }
            entries.push(object(vec![
                ("projected", projected_location_value(&entry.projected)),
                ("origins", origins.build()),
            ]));
        }
        object(vec![
            ("schema", PortableValue::string("core.provenance-map@1")),
            ("entries", entries.build()),
        ])
    }

    /// Strictly decodes `core.provenance-map@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(value, "core.provenance-map@1", &["schema", "entries"], "$")?;
        let entries = sequence(fields[1], "$.entries")?
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let path = format!("$.entries[{index}]");
                let fields = exact_fields(entry, &["projected", "origins"], &path)?;
                Ok(ProvenanceEntryMessage {
                    projected: parse_projected_location(fields[0], &format!("{path}.projected"))?,
                    origins: sequence(fields[1], &format!("{path}.origins"))?
                        .iter()
                        .enumerate()
                        .map(|(origin_index, origin)| {
                            parse_origin(origin, &format!("{path}.origins[{origin_index}]"))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        Self::new(entries)
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionFidelity {
    /// Direct complete representation.
    Exact,
    /// Reversible transformation.
    Transformed,
    /// Explicitly authorized information loss.
    Lossy,
}

/// Event loss classification independent from reversibility.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LossClassification {
    /// No relevant semantic loss.
    None,
    /// Information is preserved through a reversible transform.
    Reversible,
    /// Authorized semantic loss occurred.
    Lossy,
}

/// One machine-readable projection report event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEventMessage {
    /// Stable event code.
    pub code: String,
    /// Rule authorizing the event.
    pub policy_rule_id: Option<String>,
    /// Source ranges associated with the event.
    pub source_locations: Vec<SourceLocation>,
    /// Optional projected location.
    pub projected_location: Option<ProjectedLocationMessage>,
    /// Old semantic category.
    pub old_category: Option<String>,
    /// New semantic category.
    pub new_category: Option<String>,
    /// Whether the transform can be reversed from result plus report.
    pub reversible: bool,
    /// Loss classification.
    pub loss_classification: LossClassification,
    /// Stable sorted event arguments.
    pub arguments: BTreeMap<String, String>,
}

/// Ordered `core.projection-report@1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReportMessage {
    events: Vec<ProjectionEventMessage>,
}

impl ProjectionReportMessage {
    /// Validates event cross-field invariants.
    pub fn new(events: Vec<ProjectionEventMessage>) -> Result<Self, ProtocolError> {
        if events.iter().any(|event| {
            event.code.is_empty()
                || (event.loss_classification == LossClassification::Lossy && event.reversible)
                || (event.loss_classification == LossClassification::Reversible
                    && !event.reversible)
        }) {
            return Err(crate::schema::invalid(
                "$.events",
                "projection event fields are contradictory",
            ));
        }
        Ok(Self { events })
    }

    /// Ordered events.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEventMessage] {
        &self.events
    }

    /// Encodes `core.projection-report@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut events = SequenceBuilder::new();
        for event in &self.events {
            events.push(event_value(event));
        }
        object(vec![
            ("schema", PortableValue::string("core.projection-report@1")),
            ("events", events.build()),
        ])
    }

    /// Strictly decodes `core.projection-report@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.projection-report@1",
            &["schema", "events"],
            "$",
        )?;
        let events = sequence(fields[1], "$.events")?
            .iter()
            .enumerate()
            .map(|(index, event)| parse_event(event, &format!("$.events[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(events)
    }
}

/// Complete or explicitly failed `core.projection-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionResultMessage {
    completion: Completion,
    value: Option<PortableValue>,
    fidelity: Option<ProjectionFidelity>,
    report: ProjectionReportMessage,
    provenance: ProvenanceMapMessage,
    diagnostics: Vec<DiagnosticMessage>,
}

impl ProjectionResultMessage {
    /// Validates success/value/fidelity and loss-report invariants.
    pub fn new(
        completion: Completion,
        value: Option<PortableValue>,
        fidelity: Option<ProjectionFidelity>,
        report: ProjectionReportMessage,
        provenance: ProvenanceMapMessage,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        let success = completion.status() == CompletionStatus::Success;
        if success != value.is_some() || success != fidelity.is_some() {
            return Err(crate::schema::invalid(
                "$",
                "only successful projection may carry value and fidelity",
            ));
        }
        if fidelity == Some(ProjectionFidelity::Lossy)
            && !report
                .events()
                .iter()
                .any(|event| event.loss_classification == LossClassification::Lossy)
        {
            return Err(crate::schema::invalid(
                "$.report",
                "Lossy fidelity requires an explicit lossy event",
            ));
        }
        if !success && !provenance.entries().is_empty() {
            return Err(crate::schema::invalid(
                "$.provenance",
                "failed projection cannot claim completed provenance",
            ));
        }
        Ok(Self {
            completion,
            value,
            fidelity,
            report,
            provenance,
            diagnostics,
        })
    }

    /// Completion state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Complete projected value only on success.
    #[must_use]
    pub const fn value(&self) -> Option<&PortableValue> {
        self.value.as_ref()
    }

    /// Fidelity only on success.
    #[must_use]
    pub const fn fidelity(&self) -> Option<ProjectionFidelity> {
        self.fidelity
    }

    /// Projection report.
    #[must_use]
    pub const fn report(&self) -> &ProjectionReportMessage {
        &self.report
    }

    /// Complete provenance only on success.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceMapMessage {
        &self.provenance
    }

    /// Ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.projection-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.projection-result@1")),
            ("completion", self.completion.to_value()),
            (
                "value",
                self.value
                    .as_ref()
                    .map_or_else(PortableValue::null, |value| {
                        object(vec![("portable_value", value.clone())])
                    }),
            ),
            (
                "fidelity",
                self.fidelity.map_or_else(PortableValue::null, |fidelity| {
                    PortableValue::string(fidelity_name(fidelity))
                }),
            ),
            ("report", self.report.to_value()),
            ("provenance", self.provenance.to_value()),
            ("diagnostics", diagnostics.build()),
        ])
    }

    /// Strictly decodes `core.projection-result@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.projection-result@1",
            &[
                "schema",
                "completion",
                "value",
                "fidelity",
                "report",
                "provenance",
                "diagnostics",
            ],
            "$",
        )?;
        let projected = if fields[2] == &PortableValue::null() {
            None
        } else {
            Some(exact_fields(fields[2], &["portable_value"], "$.value")?[0].clone())
        };
        let fidelity = optional_string(fields[3], "$.fidelity")?
            .map(parse_fidelity)
            .transpose()?;
        let diagnostics = sequence(fields[6], "$.diagnostics")?
            .iter()
            .map(DiagnosticMessage::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            Completion::from_value(fields[1])?,
            projected,
            fidelity,
            ProjectionReportMessage::from_value(fields[4])?,
            ProvenanceMapMessage::from_value(fields[5])?,
            diagnostics,
        )
    }
}

fn validate_scope(scope: &ProjectionScope) -> Result<(), ProtocolError> {
    match scope {
        ProjectionScope::Global => Ok(()),
        ProjectionScope::ExactNativePath { source_id, path }
            if !source_id.is_empty()
                && source_id.len() <= 1024
                && !path.is_empty()
                && path.len() <= 4096 =>
        {
            Ok(())
        }
        ProjectionScope::ResolvedQuery(query) => {
            query.clone().validate().map(|_| ()).map_err(|error| {
                crate::schema::invalid("$.scope.query", format!("invalid query scope: {error:?}"))
            })
        }
        ProjectionScope::ExactNativePath { .. } => Err(crate::schema::invalid(
            "$.scope",
            "invalid exact native path scope",
        )),
    }
}

fn reference_value(contract: &ContractId) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(contract.id())),
        (
            "version",
            PortableValue::integer(BigInteger::from(i64::from(contract.version()))),
        ),
    ])
}

fn parse_reference(value: &PortableValue, path: &str) -> Result<ContractId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    ContractId::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )
}

fn policy_value(policy: &ProjectionPolicy) -> PortableValue {
    let mut arguments = ObjectBuilder::new();
    for (name, value) in &policy.arguments {
        arguments
            .insert(name, value.clone())
            .expect("BTreeMap keys are unique");
    }
    object(vec![
        ("id", PortableValue::string(policy.contract.id())),
        (
            "version",
            PortableValue::integer(BigInteger::from(i64::from(policy.contract.version()))),
        ),
        ("arguments", arguments.build()),
    ])
}

fn parse_policy(value: &PortableValue, path: &str) -> Result<ProjectionPolicy, ProtocolError> {
    let fields = exact_fields(value, &["id", "version", "arguments"], path)?;
    let argument_entries = fields[2].as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.arguments"),
            "expected Object",
        )
    })?;
    let arguments = argument_entries
        .iter()
        .map(|entry| (entry.key().to_owned(), entry.value().clone()))
        .collect();
    Ok(ProjectionPolicy::new(
        ContractId::new(
            string(fields[0], &format!("{path}.id"))?,
            unsigned_u32(fields[1], &format!("{path}.version"))?,
        )?,
        arguments,
    ))
}

fn scope_value(scope: &ProjectionScope) -> PortableValue {
    match scope {
        ProjectionScope::Global => object(vec![("kind", PortableValue::string("Global"))]),
        ProjectionScope::ExactNativePath { source_id, path } => object(vec![
            ("kind", PortableValue::string("ExactNativePath")),
            ("source_id", PortableValue::string(source_id.as_str())),
            ("path", PortableValue::string(path.as_str())),
        ]),
        ProjectionScope::ResolvedQuery(query) => object(vec![
            ("kind", PortableValue::string("ResolvedQuery")),
            (
                "query",
                query
                    .to_protocol_value()
                    .expect("ProjectionRequest validates query scope"),
            ),
        ]),
    }
}

fn parse_scope(value: &PortableValue, path: &str) -> Result<ProjectionScope, ProtocolError> {
    let entries = value.as_object().ok_or_else(|| {
        ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected scope Object")
    })?;
    let kind = entries
        .first()
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| crate::schema::invalid(path, "scope kind must be first"))?;
    match kind {
        "Global" => {
            exact_fields(value, &["kind"], path)?;
            Ok(ProjectionScope::Global)
        }
        "ExactNativePath" => {
            let fields = exact_fields(value, &["kind", "source_id", "path"], path)?;
            Ok(ProjectionScope::ExactNativePath {
                source_id: string(fields[1], &format!("{path}.source_id"))?.to_owned(),
                path: string(fields[2], &format!("{path}.path"))?.to_owned(),
            })
        }
        "ResolvedQuery" => {
            let fields = exact_fields(value, &["kind", "query"], path)?;
            QueryDefinition::from_protocol_value(fields[1])
                .map(ProjectionScope::ResolvedQuery)
                .map_err(|error| {
                    crate::schema::invalid(
                        &format!("{path}.query"),
                        format!("invalid query definition: {error:?}"),
                    )
                })
        }
        _ => Err(crate::schema::invalid(path, "unknown projection scope")),
    }
}

fn rule_value(rule: &ProjectionRule) -> PortableValue {
    object(vec![
        ("rule_id", PortableValue::string(rule.rule_id.as_str())),
        ("scope", scope_value(&rule.scope)),
        (
            "priority",
            PortableValue::integer(BigInteger::from(i64::from(rule.priority))),
        ),
        ("policy", policy_value(&rule.policy)),
    ])
}

fn parse_rule(value: &PortableValue, path: &str) -> Result<ProjectionRule, ProtocolError> {
    let fields = exact_fields(value, &["rule_id", "scope", "priority", "policy"], path)?;
    Ok(ProjectionRule {
        rule_id: string(fields[0], &format!("{path}.rule_id"))?.to_owned(),
        scope: parse_scope(fields[1], &format!("{path}.scope"))?,
        priority: signed_i32(fields[2], &format!("{path}.priority"))?,
        policy: parse_policy(fields[3], &format!("{path}.policy"))?,
    })
}

fn projected_location_value(location: &ProjectedLocationMessage) -> PortableValue {
    match location {
        ProjectedLocationMessage::Value(path) => object(vec![
            ("kind", PortableValue::string("ValuePath")),
            ("value", path_value(path)),
        ]),
        ProjectedLocationMessage::Association(association) => object(vec![
            ("kind", PortableValue::string("AssociationLocation")),
            ("value", association_value(association)),
        ]),
    }
}

fn parse_projected_location(
    value: &PortableValue,
    path: &str,
) -> Result<ProjectedLocationMessage, ProtocolError> {
    let fields = exact_fields(value, &["kind", "value"], path)?;
    match string(fields[0], &format!("{path}.kind"))? {
        "ValuePath" => {
            parse_path(fields[1], &format!("{path}.value")).map(ProjectedLocationMessage::Value)
        }
        "AssociationLocation" => parse_association(fields[1], &format!("{path}.value"))
            .map(ProjectedLocationMessage::Association),
        _ => Err(crate::schema::invalid(path, "unknown projected location")),
    }
}

fn origin_value(origin: &SourceOriginMessage) -> PortableValue {
    object(vec![
        (
            "source_id",
            PortableValue::string(origin.source_id.as_str()),
        ),
        (
            "node_locator",
            nullable_string(origin.node_locator.as_deref()),
        ),
        ("start_byte", integer_u64(origin.start_byte)),
        ("end_byte", integer_u64(origin.end_byte)),
        (
            "relation",
            PortableValue::string(relation_name(origin.relation)),
        ),
    ])
}

fn parse_origin(value: &PortableValue, path: &str) -> Result<SourceOriginMessage, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "source_id",
            "node_locator",
            "start_byte",
            "end_byte",
            "relation",
        ],
        path,
    )?;
    SourceOriginMessage::new(
        string(fields[0], &format!("{path}.source_id"))?,
        optional_string(fields[1], &format!("{path}.node_locator"))?.map(str::to_owned),
        unsigned_u64(fields[2], &format!("{path}.start_byte"))?,
        unsigned_u64(fields[3], &format!("{path}.end_byte"))?,
        parse_relation(string(fields[4], &format!("{path}.relation"))?)?,
    )
}

fn event_value(event: &ProjectionEventMessage) -> PortableValue {
    let mut source_locations = SequenceBuilder::new();
    for location in &event.source_locations {
        source_locations.push(object(vec![
            ("source_id", PortableValue::string(location.source_id())),
            ("start_byte", integer_u64(location.start_byte())),
            ("end_byte", integer_u64(location.end_byte())),
        ]));
    }
    let mut arguments = ObjectBuilder::new();
    for (name, value) in &event.arguments {
        arguments
            .insert(name, PortableValue::string(value.as_str()))
            .expect("BTreeMap keys are unique");
    }
    object(vec![
        ("code", PortableValue::string(event.code.as_str())),
        (
            "policy_rule_id",
            nullable_string(event.policy_rule_id.as_deref()),
        ),
        ("source_locations", source_locations.build()),
        (
            "projected_location",
            event
                .projected_location
                .as_ref()
                .map_or_else(PortableValue::null, projected_location_value),
        ),
        (
            "old_category",
            nullable_string(event.old_category.as_deref()),
        ),
        (
            "new_category",
            nullable_string(event.new_category.as_deref()),
        ),
        ("reversible", PortableValue::boolean(event.reversible)),
        (
            "loss_classification",
            PortableValue::string(loss_name(event.loss_classification)),
        ),
        ("arguments", arguments.build()),
    ])
}

fn parse_event(value: &PortableValue, path: &str) -> Result<ProjectionEventMessage, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "code",
            "policy_rule_id",
            "source_locations",
            "projected_location",
            "old_category",
            "new_category",
            "reversible",
            "loss_classification",
            "arguments",
        ],
        path,
    )?;
    let source_locations = sequence(fields[2], &format!("{path}.source_locations"))?
        .iter()
        .enumerate()
        .map(|(index, location)| {
            let location_path = format!("{path}.source_locations[{index}]");
            let fields = exact_fields(
                location,
                &["source_id", "start_byte", "end_byte"],
                &location_path,
            )?;
            SourceLocation::new(
                string(fields[0], &format!("{location_path}.source_id"))?,
                unsigned_u64(fields[1], &format!("{location_path}.start_byte"))?,
                unsigned_u64(fields[2], &format!("{location_path}.end_byte"))?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let projected_location = if fields[3] == &PortableValue::null() {
        None
    } else {
        Some(parse_projected_location(
            fields[3],
            &format!("{path}.projected_location"),
        )?)
    };
    let argument_entries = fields[8].as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.arguments"),
            "expected Object<String, String>",
        )
    })?;
    let mut arguments = BTreeMap::new();
    for entry in argument_entries {
        arguments.insert(
            entry.key().to_owned(),
            string(entry.value(), &format!("{path}.arguments.{}", entry.key()))?.to_owned(),
        );
    }
    Ok(ProjectionEventMessage {
        code: string(fields[0], &format!("{path}.code"))?.to_owned(),
        policy_rule_id: optional_string(fields[1], &format!("{path}.policy_rule_id"))?
            .map(str::to_owned),
        source_locations,
        projected_location,
        old_category: optional_string(fields[4], &format!("{path}.old_category"))?
            .map(str::to_owned),
        new_category: optional_string(fields[5], &format!("{path}.new_category"))?
            .map(str::to_owned),
        reversible: boolean(fields[6], &format!("{path}.reversible"))?,
        loss_classification: parse_loss(string(
            fields[7],
            &format!("{path}.loss_classification"),
        )?)?,
        arguments,
    })
}

const fn relation_name(relation: ProvenanceRelation) -> &'static str {
    match relation {
        ProvenanceRelation::Direct => "Direct",
        ProvenanceRelation::Derived => "Derived",
        ProvenanceRelation::Expanded => "Expanded",
        ProvenanceRelation::Merged => "Merged",
        ProvenanceRelation::Generated => "Generated",
    }
}

fn parse_relation(value: &str) -> Result<ProvenanceRelation, ProtocolError> {
    match value {
        "Direct" => Ok(ProvenanceRelation::Direct),
        "Derived" => Ok(ProvenanceRelation::Derived),
        "Expanded" => Ok(ProvenanceRelation::Expanded),
        "Merged" => Ok(ProvenanceRelation::Merged),
        "Generated" => Ok(ProvenanceRelation::Generated),
        _ => Err(crate::schema::invalid(
            "$.relation",
            "unknown provenance relation",
        )),
    }
}

const fn fidelity_name(fidelity: ProjectionFidelity) -> &'static str {
    match fidelity {
        ProjectionFidelity::Exact => "Exact",
        ProjectionFidelity::Transformed => "Transformed",
        ProjectionFidelity::Lossy => "Lossy",
    }
}

fn parse_fidelity(value: &str) -> Result<ProjectionFidelity, ProtocolError> {
    match value {
        "Exact" => Ok(ProjectionFidelity::Exact),
        "Transformed" => Ok(ProjectionFidelity::Transformed),
        "Lossy" => Ok(ProjectionFidelity::Lossy),
        _ => Err(crate::schema::invalid(
            "$.fidelity",
            "unknown projection fidelity",
        )),
    }
}

const fn loss_name(loss: LossClassification) -> &'static str {
    match loss {
        LossClassification::None => "None",
        LossClassification::Reversible => "Reversible",
        LossClassification::Lossy => "Lossy",
    }
}

fn parse_loss(value: &str) -> Result<LossClassification, ProtocolError> {
    match value {
        "None" => Ok(LossClassification::None),
        "Reversible" => Ok(LossClassification::Reversible),
        "Lossy" => Ok(LossClassification::Lossy),
        _ => Err(crate::schema::invalid(
            "$.loss_classification",
            "unknown loss classification",
        )),
    }
}

fn valid_limit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{AssociationRole, OperatorCall, QueryDomain, QueryExpression};
    use consema_document::{DocumentAuthority, NodeRole};

    fn exact_policy() -> ProjectionPolicy {
        ProjectionPolicy::new(
            ContractId::new("core.projection.exact-or-reject", 1).unwrap(),
            BTreeMap::new(),
        )
    }

    #[test]
    fn request_round_trip_includes_resolved_query_scope() {
        let query = QueryDefinition::new(QueryDomain::portable_value_v1()).with_expression(
            QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
        );
        let request = ProjectionRequestMessage::new(
            ContractId::new("json.projection.best-exact-core", 1).unwrap(),
            exact_policy(),
            vec![ProjectionRule {
                rule_id: "sequence-rule".to_owned(),
                scope: ProjectionScope::ResolvedQuery(query),
                priority: 10,
                policy: exact_policy(),
            }],
            BTreeMap::from([("max_value_nodes".to_owned(), 100)]),
        )
        .unwrap();
        assert_eq!(
            ProjectionRequestMessage::from_value(&request.to_value()).unwrap(),
            request
        );
    }

    #[test]
    fn complete_projection_round_trip_keeps_provenance() {
        let projected = ProjectedLocationMessage::Association(AssociationLocation::new(
            ValuePath::root(),
            0,
            AssociationRole::ObjectEntry,
        ));
        let provenance = ProvenanceMapMessage::new(vec![ProvenanceEntryMessage {
            projected,
            origins: vec![
                SourceOriginMessage::new(
                    "source:one",
                    Some("toml:entry:0".to_owned()),
                    0,
                    5,
                    ProvenanceRelation::Direct,
                )
                .unwrap(),
            ],
        }])
        .unwrap();
        let result = ProjectionResultMessage::new(
            Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap(),
            Some(PortableValue::string("x")),
            Some(ProjectionFidelity::Exact),
            ProjectionReportMessage::default(),
            provenance,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            ProjectionResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
    }

    #[test]
    fn successful_null_value_is_distinct_from_absent_value() {
        let result = ProjectionResultMessage::new(
            Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap(),
            Some(PortableValue::null()),
            Some(ProjectionFidelity::Exact),
            ProjectionReportMessage::default(),
            ProvenanceMapMessage::default(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            ProjectionResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
    }

    #[test]
    fn failed_result_cannot_carry_value_or_process_local_handle() {
        let failed = Completion::new(
            CompletionStatus::Failed,
            1,
            0,
            None,
            Some("core.projection.failed@1".to_owned()),
        )
        .unwrap();
        assert!(
            ProjectionResultMessage::new(
                failed,
                Some(PortableValue::null()),
                None,
                ProjectionReportMessage::default(),
                ProvenanceMapMessage::default(),
                Vec::new(),
            )
            .is_err()
        );
        let authority = DocumentAuthority::fresh();
        let node = authority.node_ref(0, NodeRole::Value);
        assert_eq!(
            ProjectionScope::from_process_local(node)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
    }
}
