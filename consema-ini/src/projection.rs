use crate::{Document, IniProfile, IniQuoteStyle, IniSyntaxKind};
use consema_core::{
    AssociationLocation, AssociationRole, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    EntryMappingBuilder, ObjectBuilder, PortableValue, ValuePath, ValuePathSegment,
};
use consema_document::{FormationStatus, NodeRef, SnapshotIdentity, Span};
use std::collections::{HashMap, HashSet};

/// Versioned INI projection target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Exact nested EntryMapping preserving every section and entry occurrence.
    BestExactEntryMappingV1,
    /// Nested unique-key Objects under explicit comparison and collision policy.
    RequireObjectV1,
}

/// Name comparison used only by `RequireObjectV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NameComparison {
    /// Compare retained original decoded spelling exactly.
    OriginalExact,
    /// Apply the selected INI profile's frozen comparison rule.
    ProfileEquivalent,
}

/// Explicit collision behavior for Object projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CollisionPolicy {
    /// Reject every collision.
    Reject,
    /// Retain the first occurrence in source order.
    First,
    /// Retain the last occurrence while preserving retained-source order.
    Last,
}

/// Immutable explicit projection request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    comparison: NameComparison,
    collision_policy: CollisionPolicy,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Exact default that preserves duplicate associations.
    #[must_use]
    pub fn best_exact_entry_mapping() -> Self {
        Self {
            target: ProjectionTarget::BestExactEntryMappingV1,
            comparison: NameComparison::OriginalExact,
            collision_policy: CollisionPolicy::Reject,
            limits: ProjectionLimits::default(),
        }
    }

    /// Explicit unique Object request.
    #[must_use]
    pub fn require_object(comparison: NameComparison, collision_policy: CollisionPolicy) -> Self {
        Self {
            target: ProjectionTarget::RequireObjectV1,
            comparison,
            collision_policy,
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

    /// Explicit Object-name comparison.
    #[must_use]
    pub const fn comparison(self) -> NameComparison {
        self.comparison
    }

    /// Explicit Object collision policy.
    #[must_use]
    pub const fn collision_policy(self) -> CollisionPolicy {
        self.collision_policy
    }

    /// Projection resource limits.
    #[must_use]
    pub const fn limits(self) -> ProjectionLimits {
        self.limits
    }
}

/// INI projection limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum source section and entry associations inspected.
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
            max_value_nodes: 2_000_000,
            max_report_entries: 100_000,
            max_provenance_units: 4_000_000,
        }
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target directly represents every native association.
    Exact,
    /// An explicit reported collision policy transformed associations.
    Transformed,
    /// Source facts were irreversibly omitted without a retained source relation.
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
    /// Container value derived from a source record.
    Derived,
    /// More-indented Python physical-line value fragment.
    ContinuationFragment,
    /// Semantic content derived by removing exact Windows outer quotes.
    QuoteDerived,
    /// Discarded association related to the retained projected association.
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

/// Collision report category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionEventKind {
    /// Section association was collapsed.
    SectionCollisionCollapsed,
    /// Entry association was collapsed.
    EntryCollisionCollapsed,
}

/// One explicit Object collision event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event kind.
    pub kind: ProjectionEventKind,
    /// Policy that authorized the transformation.
    pub policy: CollisionPolicy,
    /// Comparison mode that formed the collision class.
    pub comparison: NameComparison,
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
    /// Events in deterministic source order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }
}

/// Complete successful projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable nested mapping.
    pub value: PortableValue,
    /// Worst operation fidelity.
    pub fidelity: Fidelity,
    /// Structured collision report.
    pub report: ProjectionReport,
    /// Value and association provenance.
    pub provenance: ProvenanceMap,
}

/// Failed projection attempt without a partial value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedProjectionAttempt {
    /// Stable ordered diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Empty report: failed projections publish no partial transformation result.
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

/// Stable INI projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// Recovered documents cannot publish partial semantic values.
    RecoveredDocument,
    /// Object collision under `Reject`.
    Collision {
        /// Colliding section or entry container.
        container: NodeRef,
        /// Comparison name that collided.
        name: String,
    },
    /// Declared projection resource limit was reached.
    ResourceLimit(&'static str),
    /// PortableValue construction invariant failed.
    CoreInvariant,
}

impl Document {
    /// Projects this snapshot under one explicit target and collision contract.
    #[must_use]
    pub fn project(&self, request: ProjectionRequest) -> ProjectionResult {
        if self.formation_status() != FormationStatus::Complete {
            return failed(self, ProjectionFailure::RecoveredDocument);
        }
        let source_associations = match self.sections.len().checked_add(self.entries.len()) {
            Some(value) if value <= request.limits.max_source_associations => value,
            _ => {
                return failed(
                    self,
                    ProjectionFailure::ResourceLimit("max_source_associations"),
                );
            }
        };
        let _ = source_associations;
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

    fn push_event(&mut self, event: ProjectionEvent) -> Result<(), ProjectionFailure> {
        if self.report.events.len() >= self.request.limits.max_report_entries {
            return Err(ProjectionFailure::ResourceLimit("max_report_entries"));
        }
        self.report.events.push(event);
        self.fidelity = self.fidelity.max(Fidelity::Transformed);
        Ok(())
    }

    fn add_entry_value_origins(
        &mut self,
        projected: ProjectedLocation,
        entry_index: usize,
    ) -> Result<(), ProjectionFailure> {
        let entry = &self.document.entries[entry_index];
        self.add_origin(
            projected.clone(),
            entry.node_ref(),
            entry.value_span(),
            if entry.quote_style() == IniQuoteStyle::None {
                ProvenanceRelation::Direct
            } else {
                ProvenanceRelation::QuoteDerived
            },
        )?;
        let logical = self
            .document
            .logical_line(entry.logical_line())
            .expect("entry logical line belongs to document");
        for physical_node in logical.physical_lines().iter().skip(1) {
            let physical = self
                .document
                .physical_line(*physical_node)
                .expect("logical constituent belongs to document");
            let pieces = self.document.lossless_structural_index().pieces();
            let start = pieces.partition_point(|piece| {
                piece.span().end_byte() <= physical.content_span().start_byte()
            });
            for (ordinal, piece) in pieces.iter().enumerate().skip(start) {
                if piece.span().start_byte() >= physical.content_span().end_byte() {
                    break;
                }
                if self.document.lossless_syntax_kinds()[ordinal] == IniSyntaxKind::EntryValue {
                    self.add_origin(
                        projected.clone(),
                        entry.node_ref(),
                        piece.span(),
                        ProvenanceRelation::ContinuationFragment,
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn project_exact(
    document: &Document,
    request: ProjectionRequest,
) -> Result<CompleteProjection, ProjectionFailure> {
    let required_nodes = document
        .sections
        .len()
        .checked_mul(2)
        .and_then(|value| {
            document
                .entries
                .len()
                .checked_mul(2)
                .and_then(|e| value.checked_add(e))
        })
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
    let mut outer = EntryMappingBuilder::new();
    let entries_by_section = group_entries(document);
    for (section_ordinal, section) in document.sections.iter().enumerate() {
        let outer_ordinal = to_u64(section_ordinal)?;
        let section_path = root.child(ValuePathSegment::EntryValue(outer_ordinal));
        let outer_association = AssociationLocation::new(
            root.clone(),
            outer_ordinal,
            AssociationRole::EntryMappingEntry,
        );
        context.add_origin(
            ProjectedLocation::Association(outer_association),
            section.node_ref(),
            section.span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_origin(
            ProjectedLocation::Value(root.child(ValuePathSegment::EntryKey(outer_ordinal))),
            section.node_ref(),
            section.name_span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_origin(
            ProjectedLocation::Value(section_path.clone()),
            section.node_ref(),
            section.span(),
            ProvenanceRelation::Derived,
        )?;
        let mut inner = EntryMappingBuilder::new();
        for (local_ordinal, entry_index) in entries_by_section
            .get(&section.node_ref())
            .into_iter()
            .flatten()
            .copied()
            .enumerate()
        {
            let entry = &document.entries[entry_index];
            let ordinal = to_u64(local_ordinal)?;
            let association = AssociationLocation::new(
                section_path.clone(),
                ordinal,
                AssociationRole::EntryMappingEntry,
            );
            context.add_origin(
                ProjectedLocation::Association(association),
                entry.node_ref(),
                entry.span(),
                ProvenanceRelation::Direct,
            )?;
            context.add_origin(
                ProjectedLocation::Value(section_path.child(ValuePathSegment::EntryKey(ordinal))),
                entry.node_ref(),
                entry.key_span(),
                ProvenanceRelation::Direct,
            )?;
            let value_path = section_path.child(ValuePathSegment::EntryValue(ordinal));
            context.add_entry_value_origins(ProjectedLocation::Value(value_path), entry_index)?;
            inner.push(
                PortableValue::string(entry.key()),
                PortableValue::string(entry.value()),
            );
        }
        outer.push(PortableValue::string(section.name()), inner.build());
    }
    let root_span = document
        .authority
        .span(0, document.source().len())
        .map_err(|_| ProjectionFailure::CoreInvariant)?;
    context.add_origin(
        ProjectedLocation::Value(root),
        document.node_ref(),
        root_span,
        ProvenanceRelation::Derived,
    )?;
    Ok(CompleteProjection {
        value: outer.build(),
        fidelity: context.fidelity,
        report: context.report,
        provenance: context.provenance,
    })
}

#[derive(Clone, Debug)]
struct SelectedSection {
    source_index: usize,
    all_entry_indices: Vec<usize>,
    entry_indices: Vec<usize>,
}

fn project_object(
    document: &Document,
    request: ProjectionRequest,
) -> Result<CompleteProjection, ProjectionFailure> {
    let section_names = document
        .sections
        .iter()
        .map(|section| comparison_name(document.profile, section.name(), request.comparison, false))
        .collect::<Vec<_>>();
    let retained_sections = select_indices(
        &section_names,
        request.collision_policy,
        document.node_ref(),
    )?;
    let entries_by_section = group_entries(document);
    let mut selected = Vec::with_capacity(retained_sections.len());
    for section_index in retained_sections {
        let section = &document.sections[section_index];
        let entry_indices = entries_by_section
            .get(&section.node_ref())
            .cloned()
            .unwrap_or_default();
        let entry_names = entry_indices
            .iter()
            .map(|index| {
                comparison_name(
                    document.profile,
                    document.entries[*index].key(),
                    request.comparison,
                    true,
                )
            })
            .collect::<Vec<_>>();
        let retained_local =
            select_indices(&entry_names, request.collision_policy, section.node_ref())?;
        selected.push(SelectedSection {
            source_index: section_index,
            all_entry_indices: entry_indices.clone(),
            entry_indices: retained_local
                .into_iter()
                .map(|local| entry_indices[local])
                .collect(),
        });
    }
    let retained_entries = selected.iter().try_fold(0usize, |total, section| {
        total.checked_add(section.entry_indices.len())
    });
    let required_nodes = retained_entries
        .and_then(|entries| entries.checked_add(selected.len()))
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
    let mut outer = ObjectBuilder::new();
    let retained_section_by_name: HashMap<&str, usize> = selected
        .iter()
        .map(|item| (section_names[item.source_index].as_str(), item.source_index))
        .collect();
    let projected_section_ordinal: HashMap<usize, usize> = selected
        .iter()
        .enumerate()
        .map(|(projected, item)| (item.source_index, projected))
        .collect();
    for (source_index, section) in document.sections.iter().enumerate() {
        let retained = retained_section_by_name[section_names[source_index].as_str()];
        if retained != source_index {
            let projected_ordinal = projected_section_ordinal[&retained];
            let location = AssociationLocation::new(
                root.clone(),
                to_u64(projected_ordinal)?,
                AssociationRole::ObjectEntry,
            );
            context.push_event(ProjectionEvent {
                kind: ProjectionEventKind::SectionCollisionCollapsed,
                policy: request.collision_policy,
                comparison: request.comparison,
                discarded: section.node_ref(),
                retained: document.sections[retained].node_ref(),
                projected: location.clone(),
                impact: Fidelity::Transformed,
            })?;
            context.add_origin(
                ProjectedLocation::Association(location),
                section.node_ref(),
                section.span(),
                ProvenanceRelation::Collapsed,
            )?;
        }
    }
    for (projected_section_ordinal, selected_section) in selected.iter().enumerate() {
        let section = &document.sections[selected_section.source_index];
        let section_path = root.child(ValuePathSegment::ObjectValue(section.name().to_owned()));
        let outer_location = AssociationLocation::new(
            root.clone(),
            to_u64(projected_section_ordinal)?,
            AssociationRole::ObjectEntry,
        );
        context.add_origin(
            ProjectedLocation::Association(outer_location.clone()),
            section.node_ref(),
            section.span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_origin(
            ProjectedLocation::Association(AssociationLocation::new(
                root.clone(),
                to_u64(projected_section_ordinal)?,
                AssociationRole::ObjectKey,
            )),
            section.node_ref(),
            section.name_span(),
            ProvenanceRelation::Direct,
        )?;
        context.add_origin(
            ProjectedLocation::Value(section_path.clone()),
            section.node_ref(),
            section.span(),
            ProvenanceRelation::Derived,
        )?;

        let retained_entry_set: HashSet<usize> =
            selected_section.entry_indices.iter().copied().collect();
        let retained_by_name: HashMap<String, usize> = selected_section
            .entry_indices
            .iter()
            .map(|index| {
                (
                    comparison_name(
                        document.profile,
                        document.entries[*index].key(),
                        request.comparison,
                        true,
                    ),
                    *index,
                )
            })
            .collect();
        let projected_entry_ordinal: HashMap<usize, usize> = selected_section
            .entry_indices
            .iter()
            .enumerate()
            .map(|(projected, source)| (*source, projected))
            .collect();
        for entry_index in selected_section.all_entry_indices.iter().copied() {
            if retained_entry_set.contains(&entry_index) {
                continue;
            }
            let entry = &document.entries[entry_index];
            let name = comparison_name(document.profile, entry.key(), request.comparison, true);
            let retained = retained_by_name[&name];
            let projected_ordinal = projected_entry_ordinal[&retained];
            let location = AssociationLocation::new(
                section_path.clone(),
                to_u64(projected_ordinal)?,
                AssociationRole::ObjectEntry,
            );
            context.push_event(ProjectionEvent {
                kind: ProjectionEventKind::EntryCollisionCollapsed,
                policy: request.collision_policy,
                comparison: request.comparison,
                discarded: entry.node_ref(),
                retained: document.entries[retained].node_ref(),
                projected: location.clone(),
                impact: Fidelity::Transformed,
            })?;
            context.add_origin(
                ProjectedLocation::Association(location),
                entry.node_ref(),
                entry.span(),
                ProvenanceRelation::Collapsed,
            )?;
        }

        let mut inner = ObjectBuilder::new();
        for (projected_entry_ordinal, entry_index) in
            selected_section.entry_indices.iter().copied().enumerate()
        {
            let entry = &document.entries[entry_index];
            let ordinal = to_u64(projected_entry_ordinal)?;
            context.add_origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    section_path.clone(),
                    ordinal,
                    AssociationRole::ObjectEntry,
                )),
                entry.node_ref(),
                entry.span(),
                ProvenanceRelation::Direct,
            )?;
            context.add_origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    section_path.clone(),
                    ordinal,
                    AssociationRole::ObjectKey,
                )),
                entry.node_ref(),
                entry.key_span(),
                ProvenanceRelation::Direct,
            )?;
            context.add_entry_value_origins(
                ProjectedLocation::Value(
                    section_path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                ),
                entry_index,
            )?;
            inner
                .insert(entry.key(), PortableValue::string(entry.value()))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        outer
            .insert(section.name(), inner.build())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
    }
    let root_span = document
        .authority
        .span(0, document.source().len())
        .map_err(|_| ProjectionFailure::CoreInvariant)?;
    context.add_origin(
        ProjectedLocation::Value(root),
        document.node_ref(),
        root_span,
        ProvenanceRelation::Derived,
    )?;
    Ok(CompleteProjection {
        value: outer.build(),
        fidelity: context.fidelity,
        report: context.report,
        provenance: context.provenance,
    })
}

fn select_indices(
    names: &[String],
    policy: CollisionPolicy,
    container: NodeRef,
) -> Result<Vec<usize>, ProjectionFailure> {
    let mut counts = HashMap::<&str, usize>::new();
    for name in names {
        *counts.entry(name).or_default() += 1;
    }
    if policy == CollisionPolicy::Reject {
        if let Some(name) = names.iter().find(|name| counts[name.as_str()] > 1) {
            return Err(ProjectionFailure::Collision {
                container,
                name: name.clone(),
            });
        }
    }
    match policy {
        CollisionPolicy::Reject | CollisionPolicy::First => {
            let mut seen = HashSet::new();
            Ok((0..names.len())
                .filter(|index| seen.insert(names[*index].as_str()))
                .collect())
        }
        CollisionPolicy::Last => {
            let mut seen = HashSet::new();
            let mut retained = (0..names.len())
                .rev()
                .filter(|index| seen.insert(names[*index].as_str()))
                .collect::<Vec<_>>();
            retained.reverse();
            Ok(retained)
        }
    }
}

fn group_entries(document: &Document) -> HashMap<NodeRef, Vec<usize>> {
    let mut groups = HashMap::<NodeRef, Vec<usize>>::new();
    for (index, entry) in document.entries.iter().enumerate() {
        groups.entry(entry.section()).or_default().push(index);
    }
    groups
}

fn comparison_name(
    profile: IniProfile,
    value: &str,
    comparison: NameComparison,
    is_key: bool,
) -> String {
    if comparison == NameComparison::OriginalExact {
        return value.to_owned();
    }
    match (profile, is_key) {
        (IniProfile::WindowsV1, _) => value.to_ascii_lowercase(),
        (IniProfile::PythonConfigParserV1, true) => crate::python_case::optionxform(value),
        (IniProfile::PortableV1 | IniProfile::PythonConfigParserV1, false)
        | (IniProfile::PortableV1, true) => value.to_owned(),
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
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("failure".to_owned(), format!("{failure:?}"));
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

const fn failure_code(failure: &ProjectionFailure) -> &'static str {
    match failure {
        ProjectionFailure::RecoveredDocument => "ini.projection.recovered-document@1",
        ProjectionFailure::Collision { .. } => "ini.projection.collision@1",
        ProjectionFailure::ResourceLimit(_) => "ini.projection.resource-limit@1",
        ProjectionFailure::CoreInvariant => "ini.projection.core-invariant@1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IniEncodingSelection, IniParseLimits, parse};
    use consema_document::NodeRole;

    fn parse_profile(profile: IniProfile, source: &str) -> Document {
        parse(
            source.as_bytes(),
            profile,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn exact_projection_preserves_duplicate_sections_and_entries() {
        let document = parse_profile(
            IniProfile::WindowsV1,
            "[Main]\r\nName=one\r\nname=two\r\n[main]\r\nOther=three\r\n",
        );
        let ProjectionResult::Complete(result) =
            document.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("exact projection");
        };
        assert_eq!(result.fidelity, Fidelity::Exact);
        assert!(result.report.events().is_empty());
        let sections = result.value.as_entry_mapping().unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].key().as_string(), Some("Main"));
        assert_eq!(sections[1].key().as_string(), Some("main"));
        let entries = sections[0].value().as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key().as_string(), Some("Name"));
        assert_eq!(entries[1].key().as_string(), Some("name"));
        assert!(result.provenance.entries().iter().any(|item| {
            matches!(
                item.projected,
                ProjectedLocation::Association(ref location)
                    if location.role() == AssociationRole::EntryMappingEntry
            )
        }));

        let python = parse_profile(
            IniProfile::PythonConfigParserV1,
            "[DEFAULT]\nbase=1\n[s]\nvalue=2\n",
        );
        let ProjectionResult::Complete(result) =
            python.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("default-section projection");
        };
        assert!(result.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.node.role() == NodeRole::IniDefaultSection)
        }));
    }

    #[test]
    fn object_projection_rejects_then_explicitly_reports_profile_collisions() {
        let document = parse_profile(
            IniProfile::WindowsV1,
            "[Main]\r\nName=one\r\nname=two\r\n[main]\r\nOther=three\r\n",
        );
        assert!(matches!(
            document.project(ProjectionRequest::require_object(
                NameComparison::ProfileEquivalent,
                CollisionPolicy::Reject,
            )),
            ProjectionResult::Failed(_)
        ));

        let ProjectionResult::Complete(first) =
            document.project(ProjectionRequest::require_object(
                NameComparison::ProfileEquivalent,
                CollisionPolicy::First,
            ))
        else {
            panic!("explicit first");
        };
        assert_eq!(first.fidelity, Fidelity::Transformed);
        assert_eq!(first.report.events().len(), 2);
        assert!(first.report.events().iter().any(|event| {
            event.kind == ProjectionEventKind::SectionCollisionCollapsed
                && event.discarded == document.sections()[1].node_ref()
        }));
        assert!(first.report.events().iter().any(|event| {
            event.kind == ProjectionEventKind::EntryCollisionCollapsed
                && event.discarded == document.entries()[1].node_ref()
        }));
        let sections = first.value.as_object().unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].key(), "Main");
        let entries = sections[0].value().as_object().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key(), "Name");
        assert_eq!(entries[0].value().as_string(), Some("one"));
        assert!(first.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::Collapsed)
        }));

        let ProjectionResult::Complete(last) = document.project(ProjectionRequest::require_object(
            NameComparison::ProfileEquivalent,
            CollisionPolicy::Last,
        )) else {
            panic!("explicit last");
        };
        let sections = last.value.as_object().unwrap();
        assert_eq!(sections[0].key(), "main");
        let entries = sections[0].value().as_object().unwrap();
        assert_eq!(entries[0].key(), "Other");
        assert_eq!(entries[0].value().as_string(), Some("three"));

        let ProjectionResult::Complete(original) =
            document.project(ProjectionRequest::require_object(
                NameComparison::OriginalExact,
                CollisionPolicy::Reject,
            ))
        else {
            panic!("case-distinct object");
        };
        assert_eq!(original.fidelity, Fidelity::Exact);
        assert_eq!(original.value.as_object().unwrap().len(), 2);
    }

    #[test]
    fn continuation_and_quote_origins_are_distinct() {
        let python = parse_profile(
            IniProfile::PythonConfigParserV1,
            "[s]\nkey = first\n  second\n",
        );
        let ProjectionResult::Complete(projected) =
            python.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("python projection");
        };
        assert!(projected.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::ContinuationFragment)
        }));

        let windows = parse_profile(IniProfile::WindowsV1, "[s]\r\nk=\" value \"\r\n");
        let ProjectionResult::Complete(projected) =
            windows.project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("windows projection");
        };
        assert!(projected.provenance.entries().iter().any(|entry| {
            entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::QuoteDerived)
        }));
    }

    #[test]
    fn recovered_and_each_projection_limit_fail_without_values() {
        let recovered = parse_profile(IniProfile::PortableV1, "[s]\nbare\n");
        assert!(matches!(
            recovered.project(ProjectionRequest::best_exact_entry_mapping()),
            ProjectionResult::Failed(_)
        ));

        let complete = parse_profile(IniProfile::PortableV1, "[s]\na=1\n");
        for limits in [
            ProjectionLimits {
                max_source_associations: 1,
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
            assert!(matches!(
                complete.project(ProjectionRequest::best_exact_entry_mapping().with_limits(limits)),
                ProjectionResult::Failed(_)
            ));
        }

        let duplicate = parse_profile(IniProfile::WindowsV1, "[s]\r\na=1\r\nA=2\r\n");
        assert!(matches!(
            duplicate.project(
                ProjectionRequest::require_object(
                    NameComparison::ProfileEquivalent,
                    CollisionPolicy::First,
                )
                .with_limits(ProjectionLimits {
                    max_report_entries: 0,
                    ..ProjectionLimits::default()
                })
            ),
            ProjectionResult::Failed(_)
        ));
    }
}
