use crate::{Document, JavaStringStatus};
use consema_core::{
    AssociationLocation, AssociationRole, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    EntryMappingBuilder, ObjectBuilder, PortableValue, ValuePath, ValuePathSegment,
};
use consema_document::{FormationStatus, NodeRef, SnapshotIdentity, Span};
use std::collections::{HashMap, HashSet};

/// Versioned Java Properties projection target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Source-ordered EntryMapping preserving every association.
    BestExactEntryMappingV1,
    /// Unique-key Object under one explicit duplicate policy.
    RequireObjectV1,
}

/// Explicit duplicate behavior for `RequireObjectV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DuplicatePolicy {
    /// Reject every duplicate key.
    RequireUnique,
    /// Retain the first occurrence in source order.
    FirstWins,
    /// Retain the last occurrence, matching a newly loaded JDK Properties table.
    LastWinsJdkTable,
}

/// Immutable explicit Properties projection request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    duplicate_policy: DuplicatePolicy,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Exact default that preserves every property occurrence.
    #[must_use]
    pub fn best_exact_entry_mapping() -> Self {
        Self {
            target: ProjectionTarget::BestExactEntryMappingV1,
            duplicate_policy: DuplicatePolicy::RequireUnique,
            limits: ProjectionLimits::default(),
        }
    }

    /// Explicit unique Object request.
    #[must_use]
    pub fn require_object(duplicate_policy: DuplicatePolicy) -> Self {
        Self {
            target: ProjectionTarget::RequireObjectV1,
            duplicate_policy,
            limits: ProjectionLimits::default(),
        }
    }

    /// Replaces immutable resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: ProjectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Frozen target contract.
    #[must_use]
    pub const fn target(self) -> ProjectionTarget {
        self.target
    }

    /// Explicit Object duplicate policy.
    #[must_use]
    pub const fn duplicate_policy(self) -> DuplicatePolicy {
        self.duplicate_policy
    }

    /// Projection resource limits.
    #[must_use]
    pub const fn limits(self) -> ProjectionLimits {
        self.limits
    }
}

/// Java Properties projection limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum source property associations inspected.
    pub max_source_associations: usize,
    /// Maximum produced PortableValue nodes.
    pub max_value_nodes: usize,
    /// Maximum report events.
    pub max_report_entries: usize,
    /// Maximum projected locations plus source origins.
    pub max_provenance_units: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_source_associations: 2_000_000,
            max_value_nodes: 4_000_001,
            max_report_entries: 100_000,
            max_provenance_units: 8_000_000,
        }
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target directly represents every native association.
    Exact,
    /// Complete semantics survive an explicit reversible re-encoding.
    Transformed,
    /// At least one source fact cannot be recovered from the projected value and report.
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
    /// Direct property-association origin.
    Direct,
    /// Root value derived from the complete document.
    Derived,
    /// Raw source fragment contributing to a key.
    KeyFragment,
    /// Raw source fragment contributing to a value.
    ValueFragment,
    /// Escape source spelling contributing Java UTF-16 code units.
    EscapeDerived,
    /// Discarded duplicate related to the retained projected association.
    Collapsed,
}

/// One exact source origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOrigin {
    /// Source document snapshot.
    pub snapshot: SnapshotIdentity,
    /// Exact structural identity.
    pub node: NodeRef,
    /// Exact raw source range.
    pub span: Span,
    /// Source relation.
    pub relation: ProvenanceRelation,
}

/// One many-valued provenance entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected value or association.
    pub projected: ProjectedLocation,
    /// Ordered source origins.
    pub origins: Vec<SourceOrigin>,
}

/// Immutable many-valued provenance mapping.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMap {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceMap {
    /// Deterministically ordered projected locations and origins.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }
}

/// One explicit duplicate-collapse event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event code.
    pub code: &'static str,
    /// Policy that authorized the transformation.
    pub policy: DuplicatePolicy,
    /// Discarded source occurrence.
    pub discarded: NodeRef,
    /// Retained source occurrence.
    pub retained: NodeRef,
    /// Association produced from the retained occurrence.
    pub projected: AssociationLocation,
    /// Fidelity impact.
    pub impact: Fidelity,
}

/// Complete ordered projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in deterministic discarded-source order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }
}

/// Complete successful projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable mapping.
    pub value: PortableValue,
    /// Worst operation fidelity.
    pub fidelity: Fidelity,
    /// Structured duplicate-collapse report.
    pub report: ProjectionReport,
    /// Value and association provenance.
    pub provenance: ProvenanceMap,
}

/// Failed projection attempt without a partial value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedProjectionAttempt {
    /// Stable ordered diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Empty report: failed projections publish no partial transformation.
    pub report: ProjectionReport,
}

/// Projection completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionResult {
    /// Complete success.
    Complete(CompleteProjection),
    /// Failure with no value or provenance map.
    Failed(FailedProjectionAttempt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringComponent {
    Key,
    Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProjectionFailure {
    RecoveredDocument,
    UnpairedSurrogate {
        property: NodeRef,
        component: StringComponent,
    },
    DuplicateKey {
        retained: NodeRef,
        duplicate: NodeRef,
    },
    ResourceLimit(&'static str),
    CoreInvariant,
}

impl Document {
    /// Projects this snapshot under one explicit target and duplicate contract.
    #[must_use]
    pub fn project(&self, request: ProjectionRequest) -> ProjectionResult {
        if self.formation_status() != FormationStatus::Complete {
            return failed(self, ProjectionFailure::RecoveredDocument);
        }
        if self.properties.len() > request.limits.max_source_associations {
            return failed(
                self,
                ProjectionFailure::ResourceLimit("max_source_associations"),
            );
        }
        for property in self.properties.iter() {
            if property.key().status() == JavaStringStatus::UnpairedSurrogate {
                return failed(
                    self,
                    ProjectionFailure::UnpairedSurrogate {
                        property: property.node_ref(),
                        component: StringComponent::Key,
                    },
                );
            }
            if property.value().status() == JavaStringStatus::UnpairedSurrogate {
                return failed(
                    self,
                    ProjectionFailure::UnpairedSurrogate {
                        property: property.node_ref(),
                        component: StringComponent::Value,
                    },
                );
            }
        }
        let result = match request.target {
            ProjectionTarget::BestExactEntryMappingV1 => project_exact(self, request),
            ProjectionTarget::RequireObjectV1 => project_object(self, request),
        };
        match result {
            Ok(complete) => ProjectionResult::Complete(complete),
            Err(failure) => failed(self, failure),
        }
    }
}

struct Context<'a> {
    document: &'a Document,
    request: ProjectionRequest,
    provenance: ProvenanceMap,
    provenance_units: usize,
    report: ProjectionReport,
    fidelity: Fidelity,
}

impl Context<'_> {
    fn add_origin(
        &mut self,
        projected: ProjectedLocation,
        node: NodeRef,
        span: Span,
        relation: ProvenanceRelation,
    ) -> Result<(), ProjectionFailure> {
        let new_location = self
            .provenance
            .entries
            .iter()
            .all(|entry| entry.projected != projected);
        let increment = if new_location { 2 } else { 1 };
        self.provenance_units = self
            .provenance_units
            .checked_add(increment)
            .ok_or(ProjectionFailure::ResourceLimit("max_provenance_units"))?;
        if self.provenance_units > self.request.limits.max_provenance_units {
            return Err(ProjectionFailure::ResourceLimit("max_provenance_units"));
        }
        let origin = SourceOrigin {
            snapshot: self.document.snapshot_identity(),
            node,
            span,
            relation,
        };
        if let Some(entry) = self
            .provenance
            .entries
            .iter_mut()
            .find(|entry| entry.projected == projected)
        {
            if relation == ProvenanceRelation::Direct {
                entry.origins.insert(0, origin);
            } else {
                entry.origins.push(origin);
            }
        } else {
            self.provenance.entries.push(ProvenanceEntry {
                projected,
                origins: vec![origin],
            });
        }
        Ok(())
    }

    fn add_string_origins(
        &mut self,
        projected: ProjectedLocation,
        property_index: usize,
        component: StringComponent,
    ) -> Result<(), ProjectionFailure> {
        let property = &self.document.properties[property_index];
        let (fragments, relation) = match component {
            StringComponent::Key => (property.key_fragments(), ProvenanceRelation::KeyFragment),
            StringComponent::Value => (
                property.value_fragments(),
                ProvenanceRelation::ValueFragment,
            ),
        };
        if fragments.is_empty() {
            let anchor = match component {
                StringComponent::Key => property.key_anchor(),
                StringComponent::Value => property.value_anchor(),
            };
            self.add_origin(projected.clone(), property.node_ref(), anchor, relation)?;
        } else {
            for span in fragments {
                self.add_origin(projected.clone(), property.node_ref(), *span, relation)?;
            }
        }
        for escape_node in property.escapes() {
            let escape = self
                .document
                .escape(*escape_node)
                .expect("property escape belongs to the document");
            if escape.in_key() == (component == StringComponent::Key) {
                self.add_origin(
                    projected.clone(),
                    escape.node_ref(),
                    escape.span(),
                    ProvenanceRelation::EscapeDerived,
                )?;
            }
        }
        Ok(())
    }

    fn push_event(&mut self, event: ProjectionEvent) -> Result<(), ProjectionFailure> {
        if self.report.events.len() >= self.request.limits.max_report_entries {
            return Err(ProjectionFailure::ResourceLimit("max_report_entries"));
        }
        self.fidelity = self.fidelity.max(event.impact);
        self.report.events.push(event);
        Ok(())
    }

    fn add_root_origin(&mut self) -> Result<(), ProjectionFailure> {
        let root_span = self
            .document
            .authority
            .span(0, self.document.source().len())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        self.add_origin(
            ProjectedLocation::Value(ValuePath::root()),
            self.document.node_ref(),
            root_span,
            ProvenanceRelation::Derived,
        )
    }
}

fn project_exact(
    document: &Document,
    request: ProjectionRequest,
) -> Result<CompleteProjection, ProjectionFailure> {
    let required_nodes = document
        .properties
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ProjectionFailure::ResourceLimit("max_value_nodes"))?;
    if required_nodes > request.limits.max_value_nodes {
        return Err(ProjectionFailure::ResourceLimit("max_value_nodes"));
    }
    let mut context = Context {
        document,
        request,
        provenance: ProvenanceMap::default(),
        provenance_units: 0,
        report: ProjectionReport::default(),
        fidelity: Fidelity::Exact,
    };
    let root = ValuePath::root();
    let mut mapping = EntryMappingBuilder::new();
    for (ordinal, property) in document.properties.iter().enumerate() {
        let ordinal = to_u64(ordinal)?;
        let association =
            AssociationLocation::new(root.clone(), ordinal, AssociationRole::EntryMappingEntry);
        context.add_origin(
            ProjectedLocation::Association(association),
            property.node_ref(),
            property.span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_string_origins(
            ProjectedLocation::Value(root.child(ValuePathSegment::EntryKey(ordinal))),
            usize::try_from(ordinal)
                .map_err(|_| ProjectionFailure::ResourceLimit("portable_ordinal"))?,
            StringComponent::Key,
        )?;
        context.add_string_origins(
            ProjectedLocation::Value(root.child(ValuePathSegment::EntryValue(ordinal))),
            usize::try_from(ordinal)
                .map_err(|_| ProjectionFailure::ResourceLimit("portable_ordinal"))?,
            StringComponent::Value,
        )?;
        mapping.push(
            PortableValue::string(
                property
                    .key()
                    .to_unicode()
                    .expect("surrogates were rejected before projection"),
            ),
            PortableValue::string(
                property
                    .value()
                    .to_unicode()
                    .expect("surrogates were rejected before projection"),
            ),
        );
    }
    context.add_root_origin()?;
    Ok(CompleteProjection {
        value: mapping.build(),
        fidelity: context.fidelity,
        report: context.report,
        provenance: context.provenance,
    })
}

fn project_object(
    document: &Document,
    request: ProjectionRequest,
) -> Result<CompleteProjection, ProjectionFailure> {
    let keys = document
        .properties
        .iter()
        .map(|property| {
            property
                .key()
                .to_unicode()
                .expect("surrogates were rejected before projection")
        })
        .collect::<Vec<_>>();
    let retained = select_indices(document, &keys, request.duplicate_policy)?;
    let required_nodes = retained
        .len()
        .checked_add(1)
        .ok_or(ProjectionFailure::ResourceLimit("max_value_nodes"))?;
    if required_nodes > request.limits.max_value_nodes {
        return Err(ProjectionFailure::ResourceLimit("max_value_nodes"));
    }
    let mut context = Context {
        document,
        request,
        provenance: ProvenanceMap::default(),
        provenance_units: 0,
        report: ProjectionReport::default(),
        fidelity: Fidelity::Exact,
    };
    let root = ValuePath::root();
    let retained_set: HashSet<usize> = retained.iter().copied().collect();
    let retained_by_key: HashMap<&str, usize> = retained
        .iter()
        .map(|index| (keys[*index].as_str(), *index))
        .collect();
    let projected_ordinal: HashMap<usize, usize> = retained
        .iter()
        .enumerate()
        .map(|(projected, source)| (*source, projected))
        .collect();
    for (source_index, property) in document.properties.iter().enumerate() {
        if retained_set.contains(&source_index) {
            continue;
        }
        let retained_index = retained_by_key[keys[source_index].as_str()];
        let ordinal = to_u64(projected_ordinal[&retained_index])?;
        let location =
            AssociationLocation::new(root.clone(), ordinal, AssociationRole::ObjectEntry);
        context.push_event(ProjectionEvent {
            code: "java-properties.projection.duplicate-collapsed@1",
            policy: request.duplicate_policy,
            discarded: property.node_ref(),
            retained: document.properties[retained_index].node_ref(),
            projected: location.clone(),
            impact: Fidelity::Lossy,
        })?;
        context.add_origin(
            ProjectedLocation::Association(location),
            property.node_ref(),
            property.span(),
            ProvenanceRelation::Collapsed,
        )?;
    }

    let mut object = ObjectBuilder::new();
    for (ordinal, property_index) in retained.iter().copied().enumerate() {
        let property = &document.properties[property_index];
        let ordinal = to_u64(ordinal)?;
        let association =
            AssociationLocation::new(root.clone(), ordinal, AssociationRole::ObjectEntry);
        context.add_origin(
            ProjectedLocation::Association(association),
            property.node_ref(),
            property.span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_string_origins(
            ProjectedLocation::Association(AssociationLocation::new(
                root.clone(),
                ordinal,
                AssociationRole::ObjectKey,
            )),
            property_index,
            StringComponent::Key,
        )?;
        context.add_string_origins(
            ProjectedLocation::Value(
                root.child(ValuePathSegment::ObjectValue(keys[property_index].clone())),
            ),
            property_index,
            StringComponent::Value,
        )?;
        object
            .insert(
                keys[property_index].clone(),
                PortableValue::string(
                    property
                        .value()
                        .to_unicode()
                        .expect("surrogates were rejected before projection"),
                ),
            )
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
    }
    context.add_root_origin()?;
    Ok(CompleteProjection {
        value: object.build(),
        fidelity: context.fidelity,
        report: context.report,
        provenance: context.provenance,
    })
}

fn select_indices(
    document: &Document,
    keys: &[String],
    policy: DuplicatePolicy,
) -> Result<Vec<usize>, ProjectionFailure> {
    let mut first_by_key = HashMap::<&str, usize>::new();
    for (index, key) in keys.iter().enumerate() {
        if let Some(first) = first_by_key.get(key.as_str()).copied() {
            if policy == DuplicatePolicy::RequireUnique {
                return Err(ProjectionFailure::DuplicateKey {
                    retained: document.properties[first].node_ref(),
                    duplicate: document.properties[index].node_ref(),
                });
            }
        } else {
            first_by_key.insert(key, index);
        }
    }
    match policy {
        DuplicatePolicy::RequireUnique | DuplicatePolicy::FirstWins => {
            let mut seen = HashSet::new();
            Ok((0..keys.len())
                .filter(|index| seen.insert(keys[*index].as_str()))
                .collect())
        }
        DuplicatePolicy::LastWinsJdkTable => {
            let mut seen = HashSet::new();
            let mut retained = (0..keys.len())
                .rev()
                .filter(|index| seen.insert(keys[*index].as_str()))
                .collect::<Vec<_>>();
            retained.reverse();
            Ok(retained)
        }
    }
}

fn to_u64(value: usize) -> Result<u64, ProjectionFailure> {
    u64::try_from(value).map_err(|_| ProjectionFailure::ResourceLimit("portable_ordinal"))
}

fn failed(document: &Document, failure: ProjectionFailure) -> ProjectionResult {
    let mut diagnostic = Diagnostic::new(
        failure_code(&failure),
        DiagnosticCategory::Projection,
        DiagnosticSeverity::Error,
        failure_span(document, &failure).map(Span::diagnostic_location),
        0,
    );
    diagnostic.arguments.insert(
        "reason".to_owned(),
        match &failure {
            ProjectionFailure::RecoveredDocument => "incomplete-document",
            ProjectionFailure::UnpairedSurrogate { .. } => "unpaired-surrogate",
            ProjectionFailure::DuplicateKey { .. } => "duplicate-key",
            ProjectionFailure::ResourceLimit(_) => "resource-limit",
            ProjectionFailure::CoreInvariant => "target-not-applicable",
        }
        .to_owned(),
    );
    match &failure {
        ProjectionFailure::UnpairedSurrogate {
            property,
            component,
        } => {
            diagnostic.arguments.insert(
                "component".to_owned(),
                match component {
                    StringComponent::Key => "key",
                    StringComponent::Value => "value",
                }
                .to_owned(),
            );
            insert_property_ordinal(document, &mut diagnostic, "property_ordinal", *property);
        }
        ProjectionFailure::DuplicateKey {
            retained,
            duplicate,
        } => {
            insert_property_ordinal(document, &mut diagnostic, "retained_ordinal", *retained);
            insert_property_ordinal(document, &mut diagnostic, "duplicate_ordinal", *duplicate);
        }
        ProjectionFailure::ResourceLimit(name) => {
            diagnostic
                .arguments
                .insert("limit".to_owned(), (*name).to_owned());
        }
        ProjectionFailure::RecoveredDocument | ProjectionFailure::CoreInvariant => {}
    }
    let profile = document.profile();
    diagnostic.arguments.insert(
        "profile".to_owned(),
        format!("{}@{}", profile.id(), profile.version()),
    );
    ProjectionResult::Failed(FailedProjectionAttempt {
        diagnostics: vec![diagnostic],
        report: ProjectionReport::default(),
    })
}

fn insert_property_ordinal(
    document: &Document,
    diagnostic: &mut Diagnostic,
    argument: &str,
    node: NodeRef,
) {
    if let Some(ordinal) = document
        .properties()
        .iter()
        .position(|property| property.node_ref() == node)
    {
        diagnostic
            .arguments
            .insert(argument.to_owned(), ordinal.to_string());
    }
}

fn failure_span(document: &Document, failure: &ProjectionFailure) -> Option<Span> {
    let node = match failure {
        ProjectionFailure::UnpairedSurrogate { property, .. } => *property,
        ProjectionFailure::DuplicateKey { duplicate, .. } => *duplicate,
        ProjectionFailure::RecoveredDocument
        | ProjectionFailure::ResourceLimit(_)
        | ProjectionFailure::CoreInvariant => return None,
    };
    document.property(node).ok().map(crate::Property::span)
}

const fn failure_code(failure: &ProjectionFailure) -> &'static str {
    match failure {
        ProjectionFailure::RecoveredDocument => "java-properties.projection.incomplete-document@1",
        ProjectionFailure::UnpairedSurrogate { .. } => {
            "java-properties.projection.unpaired-surrogate@1"
        }
        ProjectionFailure::DuplicateKey { .. } | ProjectionFailure::CoreInvariant => {
            "core.projection.target-not-applicable@1"
        }
        ProjectionFailure::ResourceLimit(_) => "core.projection.resource-limit@1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PropertiesParseLimits, parse_reader};
    use consema_document::{NodeRole, SourceEncoding};

    fn parse(source: &[u8]) -> Document {
        parse_reader(
            source,
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn exact_projection_preserves_duplicates_and_fragmented_origins() {
        let document = parse(b"a\\ key=one\\\n two\\u0021\na\\ key=last\n");
        let ProjectionResult::Complete(result) =
            document.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("exact projection");
        };
        assert_eq!(result.fidelity, Fidelity::Exact);
        assert!(result.report.events().is_empty());
        let entries = result.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key().as_string(), Some("a key"));
        assert_eq!(entries[0].value().as_string(), Some("onetwo!"));
        assert_eq!(entries[1].key().as_string(), Some("a key"));
        assert!(result.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::EscapeDerived)
        }));
        assert!(result.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .filter(|origin| origin.relation == ProvenanceRelation::ValueFragment)
                .count()
                == 2
        }));
        assert!(result.provenance.entries().iter().any(|entry| {
            matches!(entry.projected, ProjectedLocation::Association(ref location)
                if location.role() == AssociationRole::EntryMappingEntry)
        }));
    }

    #[test]
    fn object_projection_requires_or_explicitly_collapses_duplicates() {
        let document = parse(b"a=first\nb=middle\na=last\n");
        let ProjectionResult::Failed(failed) = document.project(ProjectionRequest::require_object(
            DuplicatePolicy::RequireUnique,
        )) else {
            panic!("duplicate rejection");
        };
        assert_eq!(
            failed.diagnostics[0].code,
            "core.projection.target-not-applicable@1"
        );

        let ProjectionResult::Complete(first) = document.project(
            ProjectionRequest::require_object(DuplicatePolicy::FirstWins),
        ) else {
            panic!("first wins");
        };
        assert_eq!(first.fidelity, Fidelity::Lossy);
        assert_eq!(first.report.events()[0].impact, Fidelity::Lossy);
        assert_eq!(first.report.events().len(), 1);
        assert_eq!(
            first.report.events()[0].code,
            "java-properties.projection.duplicate-collapsed@1"
        );
        let first_entries = first.value.as_object().unwrap();
        assert_eq!(first_entries.len(), 2);
        assert_eq!(first_entries[0].key(), "a");
        assert_eq!(first_entries[0].value().as_string(), Some("first"));
        assert!(first.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::Collapsed)
        }));

        let ProjectionResult::Complete(last) = document.project(ProjectionRequest::require_object(
            DuplicatePolicy::LastWinsJdkTable,
        )) else {
            panic!("last wins");
        };
        let last_entries = last.value.as_object().unwrap();
        assert_eq!(last_entries.len(), 2);
        assert_eq!(last_entries[0].key(), "b");
        assert_eq!(last_entries[1].key(), "a");
        assert_eq!(last_entries[1].value().as_string(), Some("last"));
        assert_eq!(
            last.report.events()[0].retained,
            document.properties()[2].node_ref()
        );
    }

    #[test]
    fn unpaired_surrogates_and_recovery_fail_atomically() {
        let unpaired = parse(
            br"a=ok
b=\uD800",
        );
        let ProjectionResult::Failed(failed) =
            unpaired.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("unpaired rejection");
        };
        assert_eq!(
            failed.diagnostics[0].code,
            "java-properties.projection.unpaired-surrogate@1"
        );
        assert!(failed.report.events().is_empty());
        assert_eq!(
            failed.diagnostics[0].primary.as_ref().unwrap().start_byte,
            5
        );

        let recovered = parse(
            br"good=ok
bad=\u12G4",
        );
        let ProjectionResult::Failed(failed) =
            recovered.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("recovered rejection");
        };
        assert_eq!(
            failed.diagnostics[0].code,
            "java-properties.projection.incomplete-document@1"
        );
    }

    #[test]
    fn every_projection_limit_fails_without_partial_output() {
        let complete = parse(b"a=1\n");
        for limits in [
            ProjectionLimits {
                max_source_associations: 0,
                ..ProjectionLimits::default()
            },
            ProjectionLimits {
                max_value_nodes: 1,
                ..ProjectionLimits::default()
            },
            ProjectionLimits {
                max_provenance_units: 1,
                ..ProjectionLimits::default()
            },
        ] {
            let ProjectionResult::Failed(failed) =
                complete.project(ProjectionRequest::best_exact_entry_mapping().with_limits(limits))
            else {
                panic!("limit rejection");
            };
            assert_eq!(
                failed.diagnostics[0].code,
                "core.projection.resource-limit@1"
            );
            assert!(failed.report.events().is_empty());
        }

        let duplicate = parse(b"a=1\na=2\n");
        let ProjectionResult::Failed(failed) = duplicate.project(
            ProjectionRequest::require_object(DuplicatePolicy::FirstWins).with_limits(
                ProjectionLimits {
                    max_report_entries: 0,
                    ..ProjectionLimits::default()
                },
            ),
        ) else {
            panic!("report limit rejection");
        };
        assert_eq!(
            failed.diagnostics[0].code,
            "core.projection.resource-limit@1"
        );
        assert!(failed.report.events().is_empty());
    }

    #[test]
    fn object_key_origins_keep_property_identity() {
        let document = parse(b"name=value\n");
        let ProjectionResult::Complete(projected) = document.project(
            ProjectionRequest::require_object(DuplicatePolicy::RequireUnique),
        ) else {
            panic!("object projection");
        };
        assert!(projected.provenance.entries().iter().any(|entry| {
            matches!(entry.projected, ProjectedLocation::Association(ref location)
                if location.role() == AssociationRole::ObjectKey)
                && entry.origins.iter().all(|origin| {
                    matches!(
                        origin.node.role(),
                        NodeRole::PropertiesProperty | NodeRole::PropertiesEscape
                    )
                })
        }));
    }

    #[test]
    fn empty_keys_and_values_have_exact_zero_width_provenance_anchors() {
        let document = parse(b"=x\nempty=\nimplicit\n");
        let ProjectionResult::Complete(projected) =
            document.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("exact projection");
        };
        assert_eq!(projected.provenance.entries().len(), 10);
        let empty_origins = projected
            .provenance
            .entries()
            .iter()
            .flat_map(|entry| &entry.origins)
            .filter(|origin| {
                origin.span.is_empty()
                    && matches!(
                        origin.relation,
                        ProvenanceRelation::KeyFragment | ProvenanceRelation::ValueFragment
                    )
            })
            .count();
        assert_eq!(empty_origins, 3);
    }
}
