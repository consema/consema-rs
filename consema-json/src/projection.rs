use crate::{
    Document, InternalValueKind, JsonObjectMember, JsonValue, JsonValueKind, SemanticAvailability,
    SemanticUnavailable,
};
use consema_core::{
    AssociationLocation, AssociationRole, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    EntryMappingBuilder, ObjectBuilder, PortableValue, SequenceBuilder, ValuePath,
    ValuePathSegment,
};
use consema_document::{NodeRef, SnapshotIdentity, Span};
use std::collections::{HashMap, HashSet};

/// Versioned projection target contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Every JSON object must become a unique-key PortableValue Object.
    ProjectAsObjectV1,
    /// Every JSON object becomes an ordered EntryMapping.
    ProjectAsEntryMappingV1,
    /// Frozen exact-first core selection algorithm.
    BestExactCoreV1,
}

/// Explicit duplicate member policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DuplicateKeyPolicy {
    /// Preserve nothing by guessing; fail when Object cannot represent duplicates.
    Reject,
    /// Retain the first member and report every collapsed later member.
    FirstWins,
    /// Retain the last member and report every collapsed earlier member.
    LastWins,
}

/// Scope supported by `0.1.0` projection policy rules.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionPolicyScope {
    /// All applicable native objects.
    Global,
    /// Exactly one snapshot-bound object NodeRef.
    ExactNodeRef(NodeRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DuplicateRule {
    scope: ProjectionPolicyScope,
    policy: DuplicateKeyPolicy,
}

/// Immutable versioned projection request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    duplicate_rules: Vec<DuplicateRule>,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Target contract.
    #[must_use]
    pub const fn target(&self) -> ProjectionTarget {
        self.target
    }

    /// Projection resource limits.
    #[must_use]
    pub const fn limits(&self) -> ProjectionLimits {
        self.limits
    }
}

/// Builder that rejects conflicting equal-precedence rules.
#[derive(Clone, Debug)]
pub struct ProjectionRequestBuilder {
    target: ProjectionTarget,
    duplicate_rules: Vec<DuplicateRule>,
    limits: ProjectionLimits,
}

impl ProjectionRequestBuilder {
    /// Starts with `ExactOrReject` behavior.
    #[must_use]
    pub fn new(target: ProjectionTarget) -> Self {
        Self {
            target,
            duplicate_rules: vec![DuplicateRule {
                scope: ProjectionPolicyScope::Global,
                policy: DuplicateKeyPolicy::Reject,
            }],
            limits: ProjectionLimits::default(),
        }
    }

    /// Replaces the global duplicate policy.
    #[must_use]
    pub fn global_duplicate_policy(mut self, policy: DuplicateKeyPolicy) -> Self {
        self.duplicate_rules
            .retain(|rule| rule.scope != ProjectionPolicyScope::Global);
        self.duplicate_rules.push(DuplicateRule {
            scope: ProjectionPolicyScope::Global,
            policy,
        });
        self
    }

    /// Adds an exact-node override.
    #[must_use]
    pub fn exact_node_duplicate_policy(
        mut self,
        node: NodeRef,
        policy: DuplicateKeyPolicy,
    ) -> Self {
        self.duplicate_rules.push(DuplicateRule {
            scope: ProjectionPolicyScope::ExactNodeRef(node),
            policy,
        });
        self
    }

    /// Sets immutable resource limits.
    #[must_use]
    pub const fn limits(mut self, limits: ProjectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Validates rule precedence and completes the request.
    pub fn build(self) -> Result<ProjectionRequest, ProjectionFailure> {
        for (index, left) in self.duplicate_rules.iter().enumerate() {
            for right in &self.duplicate_rules[index + 1..] {
                if left.scope == right.scope && left.policy != right.policy {
                    return Err(ProjectionFailure::ConflictingPolicyRules);
                }
            }
        }
        Ok(ProjectionRequest {
            target: self.target,
            duplicate_rules: self.duplicate_rules,
            limits: self.limits,
        })
    }
}

/// Projection resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum produced PortableValue nodes.
    pub max_value_nodes: usize,
    /// Maximum report events.
    pub max_report_entries: usize,
    /// Maximum provenance locations.
    pub max_provenance_entries: usize,
    /// Maximum recursion depth.
    pub max_depth: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_value_nodes: 1_000_000,
            max_report_entries: 100_000,
            max_provenance_entries: 2_000_000,
            max_depth: 256,
        }
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target directly and completely represents covered native semantics.
    Exact,
    /// Complete semantics survive an explicit reversible re-encoding.
    Transformed,
    /// At least one source fact cannot be recovered.
    Lossy,
}

/// Projected value or association location.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ProjectedLocation {
    /// Portable value location.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// Source-to-projection relation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProvenanceRelation {
    /// Direct native semantic origin.
    Direct,
    /// Derived without a one-to-one literal origin.
    Derived,
    /// Reference expansion origin.
    Expanded,
    /// Multiple sources merged.
    Merged,
    /// No source origin.
    Generated,
}

/// One exact source origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOrigin {
    /// Source document snapshot.
    pub snapshot: SnapshotIdentity,
    /// Exact structural identity.
    pub node: NodeRef,
    /// Exact source range.
    pub span: Span,
    /// Source relation.
    pub relation: ProvenanceRelation,
}

/// One many-valued provenance mapping entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected value or association.
    pub projected: ProjectedLocation,
    /// Zero or more source origins.
    pub origins: Vec<SourceOrigin>,
}

/// Immutable multi-map from projected locations to source origins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMap {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceMap {
    /// Deterministically generated entries.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }
}

/// Machine-readable projection event category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionEventKind {
    /// Object was reversibly represented as EntryMapping.
    StructureReencoded,
    /// Native/core type mapping was explicit.
    TypeMapped,
    /// Duplicate member was collapsed.
    DuplicateCollapsed,
    /// Key was stringified (not authorized by JSON v1 policies).
    KeyStringified,
    /// Value was rounded (not authorized by JSON v1 policies).
    ValueRounded,
    /// Field was dropped.
    FieldDropped,
}

/// One structured projection report event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event kind.
    pub kind: ProjectionEventKind,
    /// Policy rule that authorized it.
    pub policy: Option<DuplicateKeyPolicy>,
    /// Exact source identity.
    pub source: NodeRef,
    /// Result location when one exists.
    pub projected: Option<ProjectedLocation>,
    /// Stable old semantic category.
    pub old_category: String,
    /// Stable new semantic category.
    pub new_category: String,
    /// Whether the source fact can be recovered from output plus contract.
    pub reversible: bool,
    /// Fidelity impact.
    pub loss: Fidelity,
}

/// Complete ordered projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in source/operation order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }
}

/// Complete successful projection; its value is never partial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable value.
    pub value: PortableValue,
    /// Worst fidelity of the whole operation.
    pub fidelity: Fidelity,
    /// Machine-readable transformation/loss report.
    pub report: ProjectionReport,
    /// Basic value and association provenance.
    pub provenance: ProvenanceMap,
}

/// Failed attempt without a partial PortableValue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedProjectionAttempt {
    /// Ordered operation diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Events discovered before the failed completion check.
    pub report: ProjectionReport,
    /// Stable path descriptions of locally analyzed regions.
    pub partial_analysis: Vec<String>,
}

/// Projection completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionResult {
    /// Complete success.
    Complete(CompleteProjection),
    /// Failed attempt with no value.
    Failed(FailedProjectionAttempt),
}

/// Stable projection failure category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// Equal-precedence rules conflict.
    ConflictingPolicyRules,
    /// Exact NodeRef scope belongs to another snapshot or role.
    WrongSnapshotPolicy,
    /// Exact NodeRef scope does not identify an Object value.
    InvalidPolicyTarget,
    /// Root does not satisfy an explicitly requested mapping target.
    TargetNotApplicable,
    /// Duplicate member cannot enter Object under Reject.
    DuplicateKeys {
        /// Object node.
        node: NodeRef,
        /// Duplicated decoded name.
        name: String,
    },
    /// Native semantics are locally unavailable.
    SemanticUnavailable {
        /// Value node.
        node: NodeRef,
        /// Reason.
        reason: SemanticUnavailable,
    },
    /// Declared resource limit was reached; output is not truncated to success.
    ResourceLimit(&'static str),
}

impl Document {
    /// Applies an immutable request. A failure never contains a partial value.
    #[must_use]
    pub fn project(&self, request: &ProjectionRequest) -> ProjectionResult {
        for rule in &request.duplicate_rules {
            let ProjectionPolicyScope::ExactNodeRef(node) = rule.scope else {
                continue;
            };
            if node.snapshot() != self.snapshot_identity() {
                return failed(
                    ProjectionFailure::WrongSnapshotPolicy,
                    ProjectionReport::default(),
                );
            }
            let Ok(index) = self.validate_ref(node, &[consema_document::NodeRole::Value]) else {
                return failed(
                    ProjectionFailure::InvalidPolicyTarget,
                    ProjectionReport::default(),
                );
            };
            if !matches!(self.value_entity(index).kind, InternalValueKind::Object(_)) {
                return failed(
                    ProjectionFailure::InvalidPolicyTarget,
                    ProjectionReport::default(),
                );
            }
        }
        let root_kind = self.root().kind();
        if matches!(
            request.target,
            ProjectionTarget::ProjectAsObjectV1 | ProjectionTarget::ProjectAsEntryMappingV1
        ) && root_kind != SemanticAvailability::Available(JsonValueKind::Object)
        {
            return failed(
                ProjectionFailure::TargetNotApplicable,
                ProjectionReport::default(),
            );
        }
        let mut context = ProjectionContext {
            document: self,
            request,
            report: ProjectionReport::default(),
            provenance: ProvenanceMap::default(),
            fidelity: Fidelity::Exact,
            value_nodes: 0,
            partial_analysis: Vec::new(),
        };
        match context.project_value(self.root(), ValuePath::root(), 0) {
            Ok(value) => ProjectionResult::Complete(CompleteProjection {
                value,
                fidelity: context.fidelity,
                report: context.report,
                provenance: context.provenance,
            }),
            Err(error) => failed_with_analysis(error, context.report, context.partial_analysis),
        }
    }
}

struct ProjectionContext<'a> {
    document: &'a Document,
    request: &'a ProjectionRequest,
    report: ProjectionReport,
    provenance: ProvenanceMap,
    fidelity: Fidelity,
    value_nodes: usize,
    partial_analysis: Vec<String>,
}

impl ProjectionContext<'_> {
    fn project_value(
        &mut self,
        value: JsonValue<'_>,
        path: ValuePath,
        depth: usize,
    ) -> Result<PortableValue, ProjectionFailure> {
        if depth > self.request.limits.max_depth {
            return Err(ProjectionFailure::ResourceLimit("projection-depth"));
        }
        self.value_nodes = self.value_nodes.saturating_add(1);
        if self.value_nodes > self.request.limits.max_value_nodes {
            return Err(ProjectionFailure::ResourceLimit("projected-value-nodes"));
        }
        self.partial_analysis.push(format!("{path:?}:Projectable"));
        self.add_origin(
            ProjectedLocation::Value(path.clone()),
            value.node_ref(),
            value.span(),
        )?;
        match &self.document.value_entity(value.raw_index()).kind {
            InternalValueKind::Null => Ok(PortableValue::null()),
            InternalValueKind::Boolean(value) => Ok(PortableValue::boolean(*value)),
            InternalValueKind::Integer(value) => Ok(PortableValue::integer(value.clone())),
            InternalValueKind::Decimal(value) => Ok(PortableValue::decimal(value.clone())),
            InternalValueKind::String(value) => Ok(PortableValue::string(value.as_str())),
            InternalValueKind::Array(elements) => {
                let mut builder = SequenceBuilder::new();
                for (index, entity) in elements.iter().enumerate() {
                    let element = crate::JsonArrayElement {
                        document: self.document,
                        index: *entity,
                    };
                    builder.push(self.project_value(
                        element.value(),
                        path.child(ValuePathSegment::SequenceElement(index as u64)),
                        depth + 1,
                    )?);
                }
                Ok(builder.build())
            }
            InternalValueKind::Object(members) => {
                let members: Vec<_> = members
                    .iter()
                    .map(|index| JsonObjectMember {
                        document: self.document,
                        index: *index,
                    })
                    .collect();
                self.project_object(value, &members, path, depth)
            }
            InternalValueKind::Unavailable(reason) => Err(ProjectionFailure::SemanticUnavailable {
                node: value.node_ref(),
                reason: reason.clone(),
            }),
        }
    }

    fn project_object(
        &mut self,
        object: JsonValue<'_>,
        members: &[JsonObjectMember<'_>],
        path: ValuePath,
        depth: usize,
    ) -> Result<PortableValue, ProjectionFailure> {
        let mut names = Vec::with_capacity(members.len());
        for member in members {
            names.push(match member.name() {
                SemanticAvailability::Available(name) => name.to_owned(),
                SemanticAvailability::Unavailable(reason) => {
                    return Err(ProjectionFailure::SemanticUnavailable {
                        node: member.key_node_ref(),
                        reason,
                    });
                }
            });
        }
        let has_duplicates = {
            let mut seen = HashSet::new();
            names.iter().any(|name| !seen.insert(name))
        };
        let use_mapping = match self.request.target {
            ProjectionTarget::ProjectAsEntryMappingV1 => true,
            ProjectionTarget::BestExactCoreV1 if has_duplicates => true,
            ProjectionTarget::ProjectAsObjectV1 | ProjectionTarget::BestExactCoreV1 => false,
        };
        if use_mapping {
            if self.request.target != ProjectionTarget::ProjectAsObjectV1 {
                self.fidelity = self.fidelity.max(Fidelity::Transformed);
                self.push_event(ProjectionEvent {
                    kind: ProjectionEventKind::StructureReencoded,
                    policy: None,
                    source: object.node_ref(),
                    projected: Some(ProjectedLocation::Value(path.clone())),
                    old_category: "JsonObject".to_owned(),
                    new_category: "EntryMapping".to_owned(),
                    reversible: true,
                    loss: Fidelity::Transformed,
                })?;
            }
            let mut builder = EntryMappingBuilder::new();
            for (ordinal, (member, name)) in members.iter().zip(names.iter()).enumerate() {
                let key_path = path.child(ValuePathSegment::EntryKey(ordinal as u64));
                let value_path = path.child(ValuePathSegment::EntryValue(ordinal as u64));
                let association = AssociationLocation::new(
                    path.clone(),
                    ordinal as u64,
                    AssociationRole::EntryMappingEntry,
                );
                self.add_origin(
                    ProjectedLocation::Association(association),
                    member.node_ref(),
                    member.span(),
                )?;
                self.add_origin(
                    ProjectedLocation::Value(key_path),
                    member.key_node_ref(),
                    self.document.span(member.entity().key),
                )?;
                let projected = self.project_value(member.value(), value_path, depth + 1)?;
                builder.push(PortableValue::string(name.as_str()), projected);
            }
            return Ok(builder.build());
        }

        let policy = self.duplicate_policy(object.node_ref());
        let retained = select_members(members, &names, policy, object.node_ref())?;
        if retained.len() != members.len() {
            self.fidelity = Fidelity::Lossy;
        }
        let retained_set: HashSet<_> = retained.iter().copied().collect();
        let projected_ordinals: HashMap<_, _> = retained
            .iter()
            .enumerate()
            .map(|(ordinal, source)| (*source, ordinal))
            .collect();
        for (source_ordinal, member) in members.iter().enumerate() {
            if !retained_set.contains(&source_ordinal) {
                let name = &names[source_ordinal];
                let retained_source = retained
                    .iter()
                    .copied()
                    .find(|index| names[*index] == *name)
                    .expect("duplicate policy retained an occurrence");
                let projected_ordinal = projected_ordinals[&retained_source];
                self.push_event(ProjectionEvent {
                    kind: ProjectionEventKind::DuplicateCollapsed,
                    policy: Some(policy),
                    source: member.node_ref(),
                    projected: Some(ProjectedLocation::Association(AssociationLocation::new(
                        path.clone(),
                        projected_ordinal as u64,
                        AssociationRole::ObjectEntry,
                    ))),
                    old_category: "JsonObjectMember".to_owned(),
                    new_category: "Collapsed".to_owned(),
                    reversible: false,
                    loss: Fidelity::Lossy,
                })?;
            }
        }
        let mut builder = ObjectBuilder::new();
        for (projected_ordinal, source_ordinal) in retained.into_iter().enumerate() {
            let member = members[source_ordinal];
            let name = &names[source_ordinal];
            let value_path = path.child(ValuePathSegment::ObjectValue(name.clone()));
            self.add_origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    path.clone(),
                    projected_ordinal as u64,
                    AssociationRole::ObjectEntry,
                )),
                member.node_ref(),
                member.span(),
            )?;
            self.add_origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    path.clone(),
                    projected_ordinal as u64,
                    AssociationRole::ObjectKey,
                )),
                member.key_node_ref(),
                self.document.span(member.entity().key),
            )?;
            let value = self.project_value(member.value(), value_path, depth + 1)?;
            builder
                .insert(name.clone(), value)
                .expect("duplicate policy produced unique names");
        }
        Ok(builder.build())
    }

    fn duplicate_policy(&self, node: NodeRef) -> DuplicateKeyPolicy {
        self.request
            .duplicate_rules
            .iter()
            .find_map(|rule| match rule.scope {
                ProjectionPolicyScope::ExactNodeRef(candidate) if candidate == node => {
                    Some(rule.policy)
                }
                _ => None,
            })
            .or_else(|| {
                self.request.duplicate_rules.iter().find_map(|rule| {
                    (rule.scope == ProjectionPolicyScope::Global).then_some(rule.policy)
                })
            })
            .unwrap_or(DuplicateKeyPolicy::Reject)
    }

    fn add_origin(
        &mut self,
        projected: ProjectedLocation,
        node: NodeRef,
        span: Span,
    ) -> Result<(), ProjectionFailure> {
        if self.provenance.entries.len() >= self.request.limits.max_provenance_entries {
            return Err(ProjectionFailure::ResourceLimit("provenance-entries"));
        }
        self.provenance.entries.push(ProvenanceEntry {
            projected,
            origins: vec![SourceOrigin {
                snapshot: self.document.snapshot_identity(),
                node,
                span,
                relation: ProvenanceRelation::Direct,
            }],
        });
        Ok(())
    }

    fn push_event(&mut self, event: ProjectionEvent) -> Result<(), ProjectionFailure> {
        if self.report.events.len() >= self.request.limits.max_report_entries {
            return Err(ProjectionFailure::ResourceLimit(
                "projection-report-entries",
            ));
        }
        self.report.events.push(event);
        Ok(())
    }
}

fn select_members(
    members: &[JsonObjectMember<'_>],
    names: &[String],
    policy: DuplicateKeyPolicy,
    node: NodeRef,
) -> Result<Vec<usize>, ProjectionFailure> {
    let mut counts = HashMap::<&str, usize>::new();
    for name in names {
        *counts.entry(name).or_default() += 1;
    }
    if let Some(name) = names.iter().find(|name| counts[name.as_str()] > 1)
        && policy == DuplicateKeyPolicy::Reject
    {
        return Err(ProjectionFailure::DuplicateKeys {
            node,
            name: name.clone(),
        });
    }
    match policy {
        DuplicateKeyPolicy::Reject | DuplicateKeyPolicy::FirstWins => {
            let mut seen = HashSet::new();
            Ok((0..members.len())
                .filter(|index| seen.insert(names[*index].as_str()))
                .collect())
        }
        DuplicateKeyPolicy::LastWins => {
            let mut seen = HashSet::new();
            let mut retained: Vec<_> = (0..members.len())
                .rev()
                .filter(|index| seen.insert(names[*index].as_str()))
                .collect();
            retained.reverse();
            Ok(retained)
        }
    }
}

fn failed(error: ProjectionFailure, report: ProjectionReport) -> ProjectionResult {
    failed_with_analysis(error, report, Vec::new())
}

fn failed_with_analysis(
    error: ProjectionFailure,
    report: ProjectionReport,
    partial_analysis: Vec<String>,
) -> ProjectionResult {
    let mut diagnostic = Diagnostic::new(
        projection_code(&error),
        DiagnosticCategory::Projection,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("failure".to_owned(), format!("{error:?}"));
    ProjectionResult::Failed(FailedProjectionAttempt {
        diagnostics: vec![diagnostic],
        report,
        partial_analysis,
    })
}

const fn projection_code(error: &ProjectionFailure) -> &'static str {
    match error {
        ProjectionFailure::ConflictingPolicyRules => "core.projection.conflicting-policy@1",
        ProjectionFailure::WrongSnapshotPolicy => "core.projection.wrong-snapshot-policy@1",
        ProjectionFailure::InvalidPolicyTarget => "core.projection.invalid-policy-target@1",
        ProjectionFailure::TargetNotApplicable => "core.projection.target-not-applicable@1",
        ProjectionFailure::DuplicateKeys { .. } => "json.projection.duplicate-keys@1",
        ProjectionFailure::SemanticUnavailable { .. } => "json.projection.semantic-unavailable@1",
        ProjectionFailure::ResourceLimit(_) => "core.projection.resource-limit@1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsonProfile, parse};
    use consema_document::ParseLimits;

    #[test]
    fn best_exact_uses_entry_mapping_for_duplicates() {
        let document = parse(
            br#"{"a":1,"a":2}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        let ProjectionResult::Complete(result) = document.project(&request) else {
            panic!("projection failed");
        };
        assert!(result.value.as_entry_mapping().is_some());
        assert_eq!(result.fidelity, Fidelity::Transformed);
        assert_eq!(
            result
                .provenance
                .entries()
                .iter()
                .filter(|entry| matches!(entry.projected, ProjectedLocation::Association(_)))
                .count(),
            2
        );
    }

    #[test]
    fn object_projection_requires_explicit_duplicate_loss() {
        let document = parse(
            br#"{"a":1,"a":2}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let reject = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
            .build()
            .unwrap();
        assert!(matches!(
            document.project(&reject),
            ProjectionResult::Failed(_)
        ));

        let allow = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
            .global_duplicate_policy(DuplicateKeyPolicy::LastWins)
            .build()
            .unwrap();
        let ProjectionResult::Complete(result) = document.project(&allow) else {
            panic!("explicit lossy projection failed");
        };
        assert_eq!(result.fidelity, Fidelity::Lossy);
        assert_eq!(
            result.report.events()[0].kind,
            ProjectionEventKind::DuplicateCollapsed
        );
    }

    #[test]
    fn object_projection_emits_distinct_key_association_provenance() {
        let document = parse(
            br#"{"a":1,"b":2}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
            .build()
            .unwrap();
        let ProjectionResult::Complete(result) = document.project(&request) else {
            panic!("projection failed");
        };
        let associations: Vec<_> = result
            .provenance
            .entries()
            .iter()
            .filter_map(|entry| match &entry.projected {
                ProjectedLocation::Association(location) => Some((
                    location.role(),
                    entry.origins.first().expect("origin").node.role(),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            associations
                .iter()
                .filter(|(role, _)| *role == AssociationRole::ObjectEntry)
                .count(),
            2
        );
        assert_eq!(
            associations
                .iter()
                .filter(|(role, _)| *role == AssociationRole::ObjectKey)
                .count(),
            2
        );
        assert_eq!(
            associations
                .iter()
                .filter(|(role, source)| *role == AssociationRole::ObjectKey
                    && *source == consema_document::NodeRole::ObjectKey)
                .count(),
            2
        );
    }

    #[test]
    fn duplicate_policy_keeps_key_provenance_of_retained_occurrence() {
        let document = parse(
            br#"{"a":1,"a":2}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        for policy in [DuplicateKeyPolicy::FirstWins, DuplicateKeyPolicy::LastWins] {
            let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
                .global_duplicate_policy(policy)
                .build()
                .unwrap();
            let ProjectionResult::Complete(result) = document.project(&request) else {
                panic!("authorized projection failed");
            };
            let keys: Vec<_> = result
                .provenance
                .entries()
                .iter()
                .filter_map(|entry| match &entry.projected {
                    ProjectedLocation::Association(location)
                        if location.role() == AssociationRole::ObjectKey =>
                    {
                        entry.origins.first().map(|origin| origin.node)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(keys.len(), 1);
        }
    }

    #[test]
    fn key_provenance_limit_fails_whole_projection() {
        let document = parse(
            br#"{"a":1,"b":2,"c":3}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
            .limits(ProjectionLimits {
                max_provenance_entries: 6,
                ..ProjectionLimits::default()
            })
            .build()
            .unwrap();
        assert!(matches!(
            document.project(&request),
            ProjectionResult::Failed(_)
        ));
    }

    #[test]
    fn exact_node_policy_overrides_global_and_rejects_non_object_targets() {
        let document = parse(
            br#"{"a":1,"a":2}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
            .exact_node_duplicate_policy(document.root().node_ref(), DuplicateKeyPolicy::FirstWins)
            .build()
            .unwrap();
        assert!(matches!(
            document.project(&request),
            ProjectionResult::Complete(CompleteProjection {
                fidelity: Fidelity::Lossy,
                ..
            })
        ));

        let scalar = parse(
            b"1".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let invalid = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
            .exact_node_duplicate_policy(scalar.root().node_ref(), DuplicateKeyPolicy::FirstWins)
            .build()
            .unwrap();
        assert!(matches!(
            scalar.project(&invalid),
            ProjectionResult::Failed(_)
        ));
    }
}
