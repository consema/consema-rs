//! Plist projection targets and explicit mapping policies (RFC 0013 §9).
//!
//! The default exact target is the versioned `plist.value-tree@1` record:
//! one root value, ordered dictionary associations (string key + value),
//! ordered array elements, and typed leaves — integer (signed 64-bit), real
//! (exact IEEE 754 double bits), boolean, date (exact double seconds plus the
//! fixed `2001-01-01T00:00:00Z` epoch constant), data (exact bytes), and
//! string. There is no key sorting, date formatting, or JSON convention
//! invention, and date, data, and integer never degrade through strings
//! (hard gate 3).
//!
//! The explicit secondary target is `plist.projection.require-object@1`: a
//! unique-key PortableValue Object over one dictionary, admitted only when
//! every value is a string/integer/real/boolean and the chosen collision
//! policy has no collision. Date, data, and UID leaves fail this target with
//! a diagnostic rather than being rendered as strings; any authorized
//! collapse is `Transformed`, emits one report event per discarded
//! association, and keeps retained and discarded provenance.
//!
//! UID values are never disguised as integers: under the explicit
//! `IncludeUid` policy of the value-tree target they project into a typed
//! UID member (an object with one `uid` member holding the unsigned 32-bit
//! value), and otherwise fail the projection atomically. Unpaired-surrogate
//! strings fail ordinary projection atomically, following the RFC 0010/0011
//! precedent.
//!
//! Provenance maps every projected value and association to its source
//! nodes: dictionary associations (`PlistDictEntry`), key identities
//! (`PlistKey`), array element associations (`PlistArrayElement`), and value
//! nodes (`PlistValue`), all scoped by the owning dict/array arena ordinal.
//! Shared identity from the binary object table is preserved: one source
//! node projected at several locations yields one origin per occurrence. The
//! native layer carries no byte spans, so every origin span is the complete
//! document source range.
//!
//! The module is the crate's public projection API, re-exported by `lib.rs`
//! in the M5-M8 integration milestone; until then no crate-root path reaches
//! these items, so the dead-code lint is disabled module-wide.
use crate::document::Document;
use crate::native::{PlistDocument, PlistKey, PlistString, PlistValue, PlistValueRef};
use consema_core::{
    AssociationLocation, AssociationRole, BigInteger, BinaryFloat64, Diagnostic,
    DiagnosticCategory, DiagnosticSeverity, EntryMappingBuilder, FailureKind, ObjectBuilder,
    OperationKind, PortableValue, StableFailure, ValuePath, ValuePathSegment,
};
use consema_document::{FormationStatus, NodeRef, NodeRole, SnapshotIdentity, Span};
use std::collections::HashMap;

/// Fixed XML spelling of the plist epoch, the origin of every `PlistDate`
/// value (RFC 0013 §5.5, §9).
const PLIST_EPOCH_SPELLING: &str = "2001-01-01T00:00:00Z";

/// Versioned plist projection target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Exact `plist.value-tree@1` record projection.
    ValueTreeV1,
    /// Explicit-policy unique-key Object projection over one dictionary
    /// (`plist.projection.require-object@1`).
    RequireObjectV1,
}

/// UID handling for the value-tree target (RFC 0013 §9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UidPolicy {
    /// UID values fail the projection atomically.
    Exclude,
    /// UID values project into a typed UID member and are never disguised
    /// as integers.
    Include,
}

/// Duplicate-key handling for the require-object target (RFC 0013 §9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CollisionPolicy {
    /// Reject the projection when any key repeats.
    Reject,
    /// Retain the first occurrence in association order.
    First,
    /// Retain the last occurrence.
    Last,
}

/// Explicit plist projection request; every policy is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    uid_policy: UidPolicy,
    collision: CollisionPolicy,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Exact `plist.value-tree@1` record request for the complete document.
    #[must_use]
    pub fn value_tree() -> Self {
        Self {
            target: ProjectionTarget::ValueTreeV1,
            uid_policy: UidPolicy::Exclude,
            collision: CollisionPolicy::Reject,
            limits: ProjectionLimits::default(),
        }
    }

    /// Exact `plist.value-tree@1` request with an explicit UID policy.
    #[must_use]
    pub fn value_tree_with_uid(policy: UidPolicy) -> Self {
        Self {
            target: ProjectionTarget::ValueTreeV1,
            uid_policy: policy,
            collision: CollisionPolicy::Reject,
            limits: ProjectionLimits::default(),
        }
    }

    /// Explicit `plist.projection.require-object@1` request with one
    /// duplicate-key loss policy.
    #[must_use]
    pub fn require_object(collision: CollisionPolicy) -> Self {
        Self {
            target: ProjectionTarget::RequireObjectV1,
            uid_policy: UidPolicy::Exclude,
            collision,
            limits: ProjectionLimits::default(),
        }
    }

    /// Applies explicit resource limits to this request.
    #[must_use]
    pub const fn with_limits(self, limits: ProjectionLimits) -> Self {
        Self { limits, ..self }
    }

    /// Projection target.
    #[must_use]
    pub const fn target(&self) -> ProjectionTarget {
        self.target
    }

    /// UID policy consumed by the value-tree target.
    #[must_use]
    pub const fn uid_policy(&self) -> UidPolicy {
        self.uid_policy
    }

    /// Collision policy consumed by the require-object target.
    #[must_use]
    pub const fn collision(&self) -> CollisionPolicy {
        self.collision
    }

    /// Resource limits.
    #[must_use]
    pub const fn limits(&self) -> ProjectionLimits {
        self.limits
    }
}

/// Plist projection resource limits.
///
/// Field names stay aligned with the XML crate's `ProjectionLimits`; the
/// lint fires only because the module is not yet re-exported from `lib.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum inspected native value nodes.
    pub max_source_nodes: usize,
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
            max_source_nodes: 2_000_000,
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
    /// An explicit reported policy transformed associations.
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
    /// Discarded occurrence related to the retained projected occurrence.
    Collapsed,
    /// Semantic content derived from reference resolution.
    ReferenceDerived,
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

    fn push(
        &mut self,
        entry: ProvenanceEntry,
        limits: ProjectionLimits,
    ) -> Result<(), ProjectionFailure> {
        let observed = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_provenance_units"))?;
        if observed > limits.max_provenance_units {
            return Err(ProjectionFailure::ResourceLimit("max_provenance_units"));
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// Projection report category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionEventKind {
    /// One duplicate-key association discarded under a `First` or `Last`
    /// collision policy.
    AssociationDiscarded,
}

/// One explicit transformation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event kind.
    pub kind: ProjectionEventKind,
    /// Discarded source occurrence.
    pub discarded: NodeRef,
    /// Fidelity impact.
    pub impact: Fidelity,
}

/// Complete ordered projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in deterministic association order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }

    fn push(
        &mut self,
        event: ProjectionEvent,
        limits: ProjectionLimits,
    ) -> Result<(), ProjectionFailure> {
        let observed = self
            .events
            .len()
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_report_entries"))?;
        if observed > limits.max_report_entries {
            return Err(ProjectionFailure::ResourceLimit("max_report_entries"));
        }
        self.events.push(event);
        Ok(())
    }
}

/// Complete successful projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable projected value.
    pub value: PortableValue,
    /// Worst operation fidelity.
    pub fidelity: Fidelity,
    /// Structured transformation report.
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

/// Stable plist projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// Recovered documents, or documents without a provable native value,
    /// cannot publish partial semantic values.
    IncompleteDocument,
    /// An unpaired-surrogate string or key cannot enter ordinary Unicode
    /// projection.
    UnpairedSurrogate,
    /// A duplicate key collided under `Reject`.
    Collision {
        /// Entry key that collided.
        key: String,
    },
    /// A native fact the target cannot represent: require-object admission
    /// (date, data, UID, container, or non-dict root) or a UID under
    /// `Exclude`.
    Unrepresentable(&'static str),
    /// Declared projection resource limit was reached.
    ResourceLimit(&'static str),
    /// PortableValue construction invariant failed.
    CoreInvariant,
}

impl StableFailure for ProjectionFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Projection
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::IncompleteDocument
            | Self::UnpairedSurrogate
            | Self::Collision { .. }
            | Self::Unrepresentable(_) => FailureKind::InvalidInput,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::CoreInvariant => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::IncompleteDocument => "plist.projection.incomplete-document@1",
            Self::UnpairedSurrogate => "plist.projection.unpaired-surrogate@1",
            Self::Collision { .. } => "plist.projection.collision@1",
            Self::Unrepresentable(_) => "plist.projection.unrepresentable@1",
            Self::ResourceLimit(_) => "plist.projection.resource-limit@1",
            Self::CoreInvariant => "plist.projection.core-invariant@1",
        }
    }
}

/// Projects one complete plist document under one explicit target and policy
/// contract (RFC 0013 §9).
///
/// The projection is atomic: a recovered source, an unpaired-surrogate
/// string, an unrepresentable leaf, or a resource limit returns no partial
/// value, provenance, or report (hard gate 3).
#[must_use]
pub fn project(document: &Document, request: ProjectionRequest) -> ProjectionResult {
    if document.status() != FormationStatus::Complete {
        return failed(ProjectionFailure::IncompleteDocument);
    }
    if document.document().is_none() {
        return failed(ProjectionFailure::IncompleteDocument);
    }
    let Ok(span) = document.authority().span(0, document.render().len()) else {
        return failed(ProjectionFailure::CoreInvariant);
    };
    let mut context = Context {
        document,
        limits: request.limits,
        report: ProjectionReport::default(),
        provenance: ProvenanceMap::default(),
        value_nodes: 0,
        source_nodes: 0,
        span,
    };
    let result = match request.target {
        ProjectionTarget::ValueTreeV1 => context.project_value_tree(request.uid_policy),
        ProjectionTarget::RequireObjectV1 => context.project_require_object(request.collision),
    };
    match result {
        Ok((value, fidelity)) => ProjectionResult::Complete(CompleteProjection {
            value,
            fidelity,
            report: context.report,
            provenance: context.provenance,
        }),
        Err(failure) => failed(failure),
    }
}

/// One retained association of the require-object target.
struct RetainedOccurrence {
    value: PortableValue,
    entry: NodeRef,
    value_node: NodeRef,
}

/// One discarded association of the require-object target.
struct DiscardedOccurrence {
    entry: NodeRef,
    value_node: NodeRef,
}

struct Context<'a> {
    document: &'a Document,
    limits: ProjectionLimits,
    report: ProjectionReport,
    provenance: ProvenanceMap,
    value_nodes: usize,
    source_nodes: usize,
    span: Span,
}

impl<'a> Context<'a> {
    /// Native value arena, borrowed from the document snapshot rather than
    /// from `self`, so projection state can mutate while the arena is live.
    fn native(&self) -> &'a PlistDocument {
        self.document
            .document()
            .expect("complete documents carry a native document")
    }

    fn step(&mut self) -> Result<(), ProjectionFailure> {
        self.source_nodes = self
            .source_nodes
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_source_nodes"))?;
        if self.source_nodes > self.limits.max_source_nodes {
            return Err(ProjectionFailure::ResourceLimit("max_source_nodes"));
        }
        Ok(())
    }

    fn reserve_value(&mut self, count: usize) -> Result<(), ProjectionFailure> {
        self.value_nodes = self
            .value_nodes
            .checked_add(count)
            .ok_or(ProjectionFailure::ResourceLimit("max_value_nodes"))?;
        if self.value_nodes > self.limits.max_value_nodes {
            return Err(ProjectionFailure::ResourceLimit("max_value_nodes"));
        }
        Ok(())
    }

    fn event(
        &mut self,
        kind: ProjectionEventKind,
        discarded: NodeRef,
        impact: Fidelity,
    ) -> Result<(), ProjectionFailure> {
        self.report.push(
            ProjectionEvent {
                kind,
                discarded,
                impact,
            },
            self.limits,
        )
    }

    fn origin(
        &mut self,
        projected: ProjectedLocation,
        node: NodeRef,
        relation: ProvenanceRelation,
    ) -> Result<(), ProjectionFailure> {
        self.provenance.push(
            ProvenanceEntry {
                projected,
                origins: vec![SourceOrigin {
                    snapshot: self.document.snapshot_identity(),
                    node,
                    span: self.span,
                    relation,
                }],
            },
            self.limits,
        )
    }

    /// Snapshot-bound handle of one native value node.
    fn value_node_ref(&self, node: PlistValueRef) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(node.index()).expect("arena ordinals fit u64"),
            NodeRole::PlistValue,
        )
    }

    /// Snapshot-bound handle of one dictionary association of the dict at
    /// `container`.
    fn entry_node_ref(&self, container: PlistValueRef) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(container.index()).expect("arena ordinals fit u64"),
            NodeRole::PlistDictEntry,
        )
    }

    /// Snapshot-bound handle of one string key identity of the dict at
    /// `container`.
    fn key_node_ref(&self, container: PlistValueRef) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(container.index()).expect("arena ordinals fit u64"),
            NodeRole::PlistKey,
        )
    }

    /// Snapshot-bound handle of one array element association of the array
    /// at `container`.
    fn element_node_ref(&self, container: PlistValueRef) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(container.index()).expect("arena ordinals fit u64"),
            NodeRole::PlistArrayElement,
        )
    }

    /// Exact `plist.value-tree@1` record for the document root.
    fn project_value_tree(
        &mut self,
        uid_policy: UidPolicy,
    ) -> Result<(PortableValue, Fidelity), ProjectionFailure> {
        let native = self.native();
        let root_path = ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned()));
        let root_value = self.value_of(native, native.root(), &root_path, uid_policy)?;
        self.reserve_value(1)?;
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string("plist.value-tree@1"))
            .and_then(|builder| builder.insert("root", root_value))
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        Ok((builder.build(), Fidelity::Exact))
    }

    /// One recursive value mapping; `path` is the location of this value
    /// inside the projected record.
    fn value_of(
        &mut self,
        native: &PlistDocument,
        node: PlistValueRef,
        path: &ValuePath,
        uid_policy: UidPolicy,
    ) -> Result<PortableValue, ProjectionFailure> {
        self.step()?;
        self.reserve_value(1)?;
        let value = native.get(node).ok_or(ProjectionFailure::CoreInvariant)?;
        let projected = match value {
            PlistValue::Dict(dict) => {
                let mut builder = EntryMappingBuilder::new();
                for (ordinal, entry) in dict.entries().iter().enumerate() {
                    let key = key_text(entry.key())?;
                    self.origin(
                        ProjectedLocation::Association(AssociationLocation::new(
                            path.clone(),
                            ordinal as u64,
                            AssociationRole::EntryMappingEntry,
                        )),
                        self.entry_node_ref(node),
                        ProvenanceRelation::Direct,
                    )?;
                    self.origin(
                        ProjectedLocation::Value(
                            path.child(ValuePathSegment::EntryKey(ordinal as u64)),
                        ),
                        self.key_node_ref(node),
                        ProvenanceRelation::Direct,
                    )?;
                    let entry_path = path.child(ValuePathSegment::EntryValue(ordinal as u64));
                    let child = self.value_of(native, entry.value(), &entry_path, uid_policy)?;
                    builder.push(PortableValue::string(key), child);
                }
                builder.build()
            }
            PlistValue::Array(array) => {
                let mut builder = consema_core::SequenceBuilder::new();
                for (ordinal, &element) in array.elements().iter().enumerate() {
                    self.origin(
                        ProjectedLocation::Value(
                            path.child(ValuePathSegment::SequenceElement(ordinal as u64)),
                        ),
                        self.element_node_ref(node),
                        ProvenanceRelation::Direct,
                    )?;
                    let element_path =
                        path.child(ValuePathSegment::SequenceElement(ordinal as u64));
                    let child = self.value_of(native, element, &element_path, uid_policy)?;
                    builder.push(child);
                }
                builder.build()
            }
            PlistValue::String(string) => string_value(string)?,
            PlistValue::Integer(integer) => {
                PortableValue::integer(BigInteger::from(integer.value()))
            }
            PlistValue::Real(real) => {
                PortableValue::binary_float64(BinaryFloat64::from_bits(real.as_f64().to_bits()))
            }
            PlistValue::Boolean(boolean) => PortableValue::boolean(boolean.value()),
            PlistValue::Date(date) => date_value(date.seconds())?,
            PlistValue::Data(data) => PortableValue::bytes(data.bytes().to_vec()),
            PlistValue::Uid(uid) => match uid_policy {
                UidPolicy::Exclude => {
                    return Err(ProjectionFailure::Unrepresentable("uid"));
                }
                UidPolicy::Include => uid_value(uid.value())?,
            },
        };
        self.origin(
            ProjectedLocation::Value(path.clone()),
            self.value_node_ref(node),
            ProvenanceRelation::Direct,
        )?;
        Ok(projected)
    }

    /// Unique-key Object over the document root dictionary under one
    /// explicit collision policy (RFC 0013 §9).
    fn project_require_object(
        &mut self,
        collision: CollisionPolicy,
    ) -> Result<(PortableValue, Fidelity), ProjectionFailure> {
        let native = self.native();
        let root = native.root();
        self.step()?;
        self.reserve_value(1)?;
        let PlistValue::Dict(dict) = native.get(root).ok_or(ProjectionFailure::CoreInvariant)?
        else {
            return Err(ProjectionFailure::Unrepresentable("root-not-dict"));
        };
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut retained: Vec<Option<(String, RetainedOccurrence)>> = Vec::new();
        let mut discards: Vec<Vec<(String, DiscardedOccurrence)>> = Vec::new();
        let mut fidelity = Fidelity::Exact;
        for entry in dict.entries() {
            let key = key_text(entry.key())?;
            let value_node = native
                .get(entry.value())
                .ok_or(ProjectionFailure::CoreInvariant)?;
            self.step()?;
            self.reserve_value(1)?;
            let scalar = match value_node {
                PlistValue::String(string) => string_value(string)?,
                PlistValue::Integer(integer) => {
                    PortableValue::integer(BigInteger::from(integer.value()))
                }
                PlistValue::Real(real) => {
                    PortableValue::binary_float64(BinaryFloat64::from_bits(real.as_f64().to_bits()))
                }
                PlistValue::Boolean(boolean) => PortableValue::boolean(boolean.value()),
                PlistValue::Date(_) => return Err(ProjectionFailure::Unrepresentable("date")),
                PlistValue::Data(_) => return Err(ProjectionFailure::Unrepresentable("data")),
                PlistValue::Uid(_) => return Err(ProjectionFailure::Unrepresentable("uid")),
                PlistValue::Dict(_) => return Err(ProjectionFailure::Unrepresentable("dict")),
                PlistValue::Array(_) => return Err(ProjectionFailure::Unrepresentable("array")),
            };
            let entry_ref = self.entry_node_ref(root);
            let value_ref = self.value_node_ref(entry.value());
            match seen.get(&key) {
                None => {
                    let position = retained.len();
                    seen.insert(key.clone(), position);
                    retained.push(Some((
                        key,
                        RetainedOccurrence {
                            value: scalar,
                            entry: entry_ref,
                            value_node: value_ref,
                        },
                    )));
                    discards.push(Vec::new());
                }
                Some(&position) => match collision {
                    CollisionPolicy::Reject => {
                        return Err(ProjectionFailure::Collision { key });
                    }
                    CollisionPolicy::First => {
                        fidelity = Fidelity::Transformed;
                        self.event(
                            ProjectionEventKind::AssociationDiscarded,
                            entry_ref,
                            Fidelity::Transformed,
                        )?;
                        discards[position].push((
                            key,
                            DiscardedOccurrence {
                                entry: entry_ref,
                                value_node: value_ref,
                            },
                        ));
                    }
                    CollisionPolicy::Last => {
                        fidelity = Fidelity::Transformed;
                        let previous = retained[position]
                            .as_ref()
                            .expect("seen positions are retained");
                        self.event(
                            ProjectionEventKind::AssociationDiscarded,
                            previous.1.entry,
                            Fidelity::Transformed,
                        )?;
                        discards[position].push((
                            previous.0.clone(),
                            DiscardedOccurrence {
                                entry: previous.1.entry,
                                value_node: previous.1.value_node,
                            },
                        ));
                        retained[position] = Some((
                            key,
                            RetainedOccurrence {
                                value: scalar,
                                entry: entry_ref,
                                value_node: value_ref,
                            },
                        ));
                    }
                },
            }
        }
        // Provenance follows the final retained object: every retained
        // association and key carries a Direct origin on its winning
        // occurrence, and every discarded association keeps a Collapsed
        // origin (RFC 0013 §9).
        let mut builder = ObjectBuilder::new();
        for (position, slot) in retained.into_iter().enumerate() {
            let Some((key, occurrence)) = slot else {
                continue;
            };
            builder
                .insert(key.clone(), occurrence.value)
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
            self.origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    ValuePath::root(),
                    position as u64,
                    AssociationRole::ObjectEntry,
                )),
                occurrence.entry,
                ProvenanceRelation::Direct,
            )?;
            self.origin(
                ProjectedLocation::Association(AssociationLocation::new(
                    ValuePath::root(),
                    position as u64,
                    AssociationRole::ObjectKey,
                )),
                self.key_node_ref(root),
                ProvenanceRelation::Direct,
            )?;
            self.origin(
                ProjectedLocation::Value(
                    ValuePath::root().child(ValuePathSegment::ObjectValue(key)),
                ),
                occurrence.value_node,
                ProvenanceRelation::Direct,
            )?;
            for (discard_key, discarded) in &discards[position] {
                self.origin(
                    ProjectedLocation::Association(AssociationLocation::new(
                        ValuePath::root(),
                        position as u64,
                        AssociationRole::ObjectEntry,
                    )),
                    discarded.entry,
                    ProvenanceRelation::Collapsed,
                )?;
                self.origin(
                    ProjectedLocation::Value(
                        ValuePath::root().child(ValuePathSegment::ObjectValue(discard_key.clone())),
                    ),
                    discarded.value_node,
                    ProvenanceRelation::Collapsed,
                )?;
            }
        }
        Ok((builder.build(), fidelity))
    }
}

/// Exact Unicode text of one key; an unpaired surrogate fails the
/// projection atomically.
fn key_text(key: &PlistKey) -> Result<String, ProjectionFailure> {
    key.to_unicode()
        .map_err(|_| ProjectionFailure::UnpairedSurrogate)
}

/// Exact Unicode string value; an unpaired surrogate fails the projection
/// atomically.
fn string_value(string: &PlistString) -> Result<PortableValue, ProjectionFailure> {
    string
        .to_unicode()
        .map(PortableValue::string)
        .map_err(|_| ProjectionFailure::UnpairedSurrogate)
}

/// Typed date member: exact double seconds since the fixed plist epoch
/// (RFC 0013 §9, hard gate 3).
fn date_value(seconds: f64) -> Result<PortableValue, ProjectionFailure> {
    let mut builder = ObjectBuilder::new();
    builder
        .insert("epoch", PortableValue::string(PLIST_EPOCH_SPELLING))
        .and_then(|builder| {
            builder.insert(
                "seconds",
                PortableValue::binary_float64(BinaryFloat64::from_bits(seconds.to_bits())),
            )
        })
        .map_err(|_| ProjectionFailure::CoreInvariant)?;
    Ok(builder.build())
}

/// Typed UID member, never an integer leaf (RFC 0013 §9).
fn uid_value(uid: u32) -> Result<PortableValue, ProjectionFailure> {
    let mut builder = ObjectBuilder::new();
    builder
        .insert(
            "uid",
            PortableValue::integer(BigInteger::from(i64::from(uid))),
        )
        .map_err(|_| ProjectionFailure::CoreInvariant)?;
    Ok(builder.build())
}

fn failed(failure: ProjectionFailure) -> ProjectionResult {
    let mut diagnostic = Diagnostic::new(
        failure.diagnostic_code(),
        DiagnosticCategory::Projection,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("failure".to_owned(), format!("{failure:?}"));
    match &failure {
        ProjectionFailure::Collision { key } => {
            diagnostic.arguments.insert("key".to_owned(), key.clone());
        }
        ProjectionFailure::Unrepresentable(fact) => {
            diagnostic
                .arguments
                .insert("fact".to_owned(), (*fact).to_owned());
        }
        ProjectionFailure::ResourceLimit(name) => {
            diagnostic
                .arguments
                .insert("limit".to_owned(), (*name).to_owned());
        }
        _ => {}
    }
    ProjectionResult::Failed(FailedProjectionAttempt {
        diagnostics: vec![diagnostic],
        report: ProjectionReport::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::ValuePathSegment;
    use std::sync::Arc;

    fn parse_xml(source: &str) -> Document {
        crate::parse(
            Arc::from(source.as_bytes()),
            crate::PlistProfile::XmlV1,
            crate::PlistEncodingSelection::ProfileDefault,
            crate::PlistParseLimits::default(),
        )
        .expect("xml plist forms")
    }

    /// Hand-built `bplist00` fixture: object table, 1-byte offset entries,
    /// minimal trailer.
    fn binary_document(objects: &[Vec<u8>], top: usize) -> Document {
        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object);
        }
        let offset_table_offset = bytes.len();
        for offset in offsets {
            bytes.push(offset as u8);
        }
        bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
        bytes.push(0); // sortVersion
        bytes.push(1); // offsetIntSize
        bytes.push(1); // objectRefSize
        bytes.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(top as u64).to_be_bytes());
        bytes.extend_from_slice(&(offset_table_offset as u64).to_be_bytes());
        crate::parse(
            Arc::from(bytes),
            crate::PlistProfile::BinaryV1,
            crate::PlistEncodingSelection::ProfileDefault,
            crate::PlistParseLimits::default(),
        )
        .expect("binary plist forms")
    }

    fn value_tree(document: &Document) -> ProjectionResult {
        project(document, ProjectionRequest::value_tree())
    }

    fn require_object(document: &Document, collision: CollisionPolicy) -> ProjectionResult {
        project(document, ProjectionRequest::require_object(collision))
    }

    fn complete(result: ProjectionResult) -> CompleteProjection {
        match result {
            ProjectionResult::Complete(complete) => complete,
            ProjectionResult::Failed(failed) => {
                panic!("projection failed: {:?}", failed.diagnostics)
            }
        }
    }

    fn failed_code(result: &ProjectionResult) -> String {
        match result {
            ProjectionResult::Complete(_) => panic!("projection must fail"),
            ProjectionResult::Failed(failed) => failed.diagnostics[0].code.clone(),
        }
    }

    fn failed_arg(result: &ProjectionResult, name: &str) -> Option<String> {
        match result {
            ProjectionResult::Complete(_) => panic!("projection must fail"),
            ProjectionResult::Failed(failed) => failed.diagnostics[0].arguments.get(name).cloned(),
        }
    }

    /// One leaf check of the root-scalar matrix.
    type LeafCheck = fn(&PortableValue);

    /// Splits one `plist.value-tree@1` record into its `record` and `root`
    /// members.
    fn record_parts(value: &PortableValue) -> (&str, &PortableValue) {
        let object = value.as_object().expect("record object");
        let record = object
            .iter()
            .find(|entry| entry.key() == "record")
            .expect("record member");
        let root = object
            .iter()
            .find(|entry| entry.key() == "root")
            .expect("root member");
        (
            record.value().as_string().expect("record spelling"),
            root.value(),
        )
    }

    fn entry_value<'a>(root: &'a PortableValue, key: &str) -> &'a PortableValue {
        let entries = root.as_entry_mapping().expect("root is an entry mapping");
        entries
            .iter()
            .find(|entry| entry.key().as_string() == Some(key))
            .expect("entry exists")
            .value()
    }

    fn object_value<'a>(root: &'a PortableValue, key: &str) -> &'a PortableValue {
        let object = root.as_object().expect("root is an object");
        object
            .iter()
            .find(|entry| entry.key() == key)
            .expect("object entry exists")
            .value()
    }

    #[test]
    fn value_tree_projects_all_value_kinds_and_record_shape() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>s</key><string>text</string>\
             <key>i</key><integer>-42</integer>\
             <key>r</key><real>1.5</real>\
             <key>t</key><true/>\
             <key>f</key><false/>\
             <key>d</key><data>AQID</data>\
             <key>dt</key><date>2023-01-01T00:00:00Z</date>\
             <key>a</key><array><string>x</string><dict/></array>\
             <key>e</key><string></string>\
             </dict></plist>",
        );
        let projection = complete(value_tree(&document));
        let (record, root) = record_parts(&projection.value);
        assert_eq!(record, "plist.value-tree@1");
        assert_eq!(projection.fidelity, Fidelity::Exact);
        assert!(projection.report.events().is_empty());
        let entries = root.as_entry_mapping().expect("dict maps to entry mapping");
        let keys = entries
            .iter()
            .map(|entry| entry.key().as_string().expect("string key"))
            .collect::<Vec<_>>();
        assert_eq!(keys, ["s", "i", "r", "t", "f", "d", "dt", "a", "e"]);
        assert_eq!(
            entry_value(root, "s").as_string(),
            Some("text"),
            "string projects as a string"
        );
        assert_eq!(
            entry_value(root, "i")
                .as_integer()
                .expect("integer")
                .to_string(),
            "-42"
        );
        assert_eq!(
            entry_value(root, "r")
                .as_binary_float64()
                .expect("real projects as exact binary64")
                .bits(),
            1.5_f64.to_bits()
        );
        assert_eq!(entry_value(root, "t").as_boolean(), Some(true));
        assert_eq!(entry_value(root, "f").as_boolean(), Some(false));
        assert_eq!(
            entry_value(root, "d")
                .as_bytes()
                .expect("data projects as bytes"),
            &[0x01, 0x02, 0x03]
        );
        let date = entry_value(root, "dt");
        assert_eq!(
            object_value(date, "epoch").as_string(),
            Some("2001-01-01T00:00:00Z"),
            "date keeps the fixed epoch constant"
        );
        assert_eq!(
            object_value(date, "seconds")
                .as_binary_float64()
                .expect("seconds are exact double bits")
                .bits(),
            694_224_000.0_f64.to_bits()
        );
        let array = entry_value(root, "a");
        let elements = array.as_sequence().expect("array projects as sequence");
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].as_string(), Some("x"));
        assert_eq!(
            elements[1].kind(),
            consema_core::PortableValueKind::EntryMapping,
            "nested dict projects as entry mapping"
        );
        assert_eq!(entry_value(root, "e").as_string(), Some(""));
    }

    #[test]
    fn value_tree_root_scalars_project_typed_leaves() {
        let cases: &[(&str, LeafCheck)] = &[
            (
                "<plist version=\"1.0\"><string>x</string></plist>",
                |root| {
                    assert_eq!(root.as_string(), Some("x"));
                },
            ),
            (
                "<plist version=\"1.0\"><integer>7</integer></plist>",
                |root| {
                    assert_eq!(root.as_integer().expect("integer").to_string(), "7");
                },
            ),
            ("<plist version=\"1.0\"><real>-0.5</real></plist>", |root| {
                assert_eq!(
                    root.as_binary_float64()
                        .expect("real projects as binary64")
                        .bits(),
                    (-0.5_f64).to_bits()
                );
            }),
            ("<plist version=\"1.0\"><true/></plist>", |root| {
                assert_eq!(root.as_boolean(), Some(true));
            }),
            (
                "<plist version=\"1.0\"><date>2023-01-01T00:00:00Z</date></plist>",
                |root| {
                    assert_eq!(
                        object_value(root, "seconds")
                            .as_binary_float64()
                            .expect("seconds")
                            .bits(),
                        694_224_000.0_f64.to_bits()
                    );
                },
            ),
            ("<plist version=\"1.0\"><data>AQID</data></plist>", |root| {
                assert_eq!(root.as_bytes().expect("bytes"), &[0x01, 0x02, 0x03]);
            }),
            ("<plist version=\"1.0\"><array/></plist>", |root| {
                assert_eq!(root.as_sequence().expect("sequence").len(), 0);
            }),
            ("<plist version=\"1.0\"><dict/></plist>", |root| {
                assert_eq!(root.as_entry_mapping().expect("mapping").len(), 0);
            }),
        ];
        for (source, check) in cases {
            let projection = complete(value_tree(&parse_xml(source)));
            let (record, root) = record_parts(&projection.value);
            assert_eq!(record, "plist.value-tree@1");
            check(root);
        }
    }

    #[test]
    fn value_tree_preserves_association_order_and_duplicate_keys() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>z</key><integer>1</integer>\
             <key>a</key><integer>2</integer>\
             <key>z</key><integer>3</integer>\
             </dict></plist>",
        );
        let projection = complete(value_tree(&document));
        let (_, root) = record_parts(&projection.value);
        let entries = root.as_entry_mapping().expect("entry mapping");
        assert_eq!(entries.len(), 3, "duplicate keys stay ordered associations");
        assert_eq!(entries[0].key().as_string(), Some("z"));
        assert_eq!(entries[1].key().as_string(), Some("a"));
        assert_eq!(entries[2].key().as_string(), Some("z"));
        assert_eq!(
            entries[0]
                .value()
                .as_integer()
                .expect("integer")
                .to_string(),
            "1"
        );
        assert_eq!(
            entries[2]
                .value()
                .as_integer()
                .expect("integer")
                .to_string(),
            "3"
        );
        assert_eq!(projection.fidelity, Fidelity::Exact);
        assert!(projection.report.events().is_empty());
    }

    #[test]
    fn value_tree_maps_exact_binary_facts() {
        // float32 width fact converts exactly; fractional seconds survive.
        let mut object = vec![0x22];
        object.extend_from_slice(&0.5_f32.to_bits().to_be_bytes());
        let mut date = vec![0x33];
        date.extend_from_slice(&0.5_f64.to_bits().to_be_bytes());
        let document = binary_document(
            &[
                vec![0x53, b'f', b'3', b'2'],
                vec![0x54, b'f', b'r', b'a', b'c'],
                vec![0x54, b'd', b'a', b't', b'a'],
                object,
                date,
                vec![0x42, 0x01, 0x02],
                vec![0xD3, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            ],
            6,
        );
        let projection = complete(value_tree(&document));
        let (_, root) = record_parts(&projection.value);
        assert_eq!(
            entry_value(root, "f32")
                .as_binary_float64()
                .expect("float32 projects as the exact double-converted bits")
                .bits(),
            f64::from(0.5_f32).to_bits()
        );
        assert_eq!(
            object_value(entry_value(root, "frac"), "seconds")
                .as_binary_float64()
                .expect("fractional seconds are exact")
                .bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            entry_value(root, "data").as_bytes().expect("bytes"),
            &[0x01, 0x02]
        );
    }

    #[test]
    fn value_tree_uid_policy_excludes_or_typed_member() {
        let document = binary_document(&[vec![0x80, 0x2A]], 0);
        let excluded = value_tree(&document);
        assert_eq!(
            failed_code(&excluded),
            "plist.projection.unrepresentable@1",
            "UIDs fail ordinary projection"
        );
        assert_eq!(failed_arg(&excluded, "fact").as_deref(), Some("uid"));

        let included = project(
            &document,
            ProjectionRequest::value_tree_with_uid(UidPolicy::Include),
        );
        let projection = complete(included);
        let (_, root) = record_parts(&projection.value);
        let uid = object_value(root, "uid")
            .as_integer()
            .expect("typed UID member holds the unsigned value");
        assert_eq!(uid.to_string(), "42");
    }

    #[test]
    fn value_tree_shared_identity_keeps_occurrence_provenance() {
        // One source string object referenced twice by one array.
        let document = binary_document(&[vec![0x51, b'x'], vec![0xA2, 0x00, 0x00]], 1);
        let projection = complete(value_tree(&document));
        let (_, root) = record_parts(&projection.value);
        let elements = root.as_sequence().expect("root array");
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].as_string(), Some("x"));
        assert_eq!(elements[1].as_string(), Some("x"));
        let origins = projection
            .provenance
            .entries()
            .iter()
            .map(|entry| entry.origins[0].node)
            .collect::<Vec<_>>();
        let value_origins = origins
            .iter()
            .filter(|node| node.role() == NodeRole::PlistValue && node.index() == 0)
            .count();
        assert_eq!(
            value_origins, 2,
            "both occurrences keep the same shared source node as their origin"
        );
        assert_eq!(
            projection.provenance.entries().len(),
            5,
            "two element associations, two value origins, and the root origin"
        );
    }

    #[test]
    fn require_object_collision_policies() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>a</key><string>one</string>\
             <key>a</key><string>last</string>\
             <key>b</key><string>two</string>\
             </dict></plist>",
        );
        let rejected = require_object(&document, CollisionPolicy::Reject);
        assert_eq!(
            failed_code(&rejected),
            "plist.projection.collision@1",
            "Reject fails on a duplicate key"
        );
        assert_eq!(failed_arg(&rejected, "key").as_deref(), Some("a"));

        let first = complete(require_object(&document, CollisionPolicy::First));
        assert_eq!(first.fidelity, Fidelity::Transformed);
        let entries = first.value.as_object().expect("object target");
        let keys = entries
            .iter()
            .map(consema_core::ObjectEntry::key)
            .collect::<Vec<_>>();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(object_value(&first.value, "a").as_string(), Some("one"));
        assert_eq!(object_value(&first.value, "b").as_string(), Some("two"));
        assert_eq!(
            first.report.events().len(),
            1,
            "one report event per discarded association"
        );
        assert_eq!(
            first.report.events()[0].kind,
            ProjectionEventKind::AssociationDiscarded
        );
        assert_eq!(first.report.events()[0].impact, Fidelity::Transformed);

        let last = complete(require_object(&document, CollisionPolicy::Last));
        assert_eq!(last.fidelity, Fidelity::Transformed);
        assert_eq!(object_value(&last.value, "a").as_string(), Some("last"));
        assert_eq!(last.report.events().len(), 1);
    }

    #[test]
    fn require_object_unique_scalars_are_exact() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>s</key><string>x</string>\
             <key>i</key><integer>42</integer>\
             <key>r</key><real>1.5</real>\
             <key>b</key><true/>\
             </dict></plist>",
        );
        let projection = complete(require_object(&document, CollisionPolicy::Reject));
        assert_eq!(projection.fidelity, Fidelity::Exact);
        assert!(projection.report.events().is_empty());
        assert_eq!(projection.value.as_object().expect("object").len(), 4);
        assert_eq!(object_value(&projection.value, "s").as_string(), Some("x"));
        assert_eq!(
            object_value(&projection.value, "i")
                .as_integer()
                .expect("integer")
                .to_string(),
            "42"
        );
        assert_eq!(
            object_value(&projection.value, "r")
                .as_binary_float64()
                .expect("real")
                .bits(),
            1.5_f64.to_bits()
        );
        assert_eq!(
            object_value(&projection.value, "b").as_boolean(),
            Some(true)
        );
    }

    #[test]
    fn require_object_rejection_matrix() {
        let date_document = parse_xml(
            "<plist version=\"1.0\"><dict><key>d</key><date>2023-01-01T00:00:00Z</date><key>s</key><string>x</string></dict></plist>",
        );
        let bytes_document =
            parse_xml("<plist version=\"1.0\"><dict><key>p</key><data>AQID</data></dict></plist>");
        let array_document = parse_xml(
            "<plist version=\"1.0\"><dict><key>a</key><array><string>x</string></array><key>d</key><dict/></dict></plist>",
        );
        let dict_document =
            parse_xml("<plist version=\"1.0\"><dict><key>d</key><dict/></dict></plist>");
        let scalar_root = parse_xml("<plist version=\"1.0\"><string>x</string></plist>");
        let uid_document = binary_document(
            &[vec![0x51, b'k'], vec![0x80, 0x2A], vec![0xD1, 0x00, 0x01]],
            2,
        );
        for (document, fact) in [
            (&date_document, "date"),
            (&bytes_document, "data"),
            (&uid_document, "uid"),
            (&array_document, "array"),
            (&dict_document, "dict"),
            (&scalar_root, "root-not-dict"),
        ] {
            let result = require_object(document, CollisionPolicy::Reject);
            assert_eq!(
                failed_code(&result),
                "plist.projection.unrepresentable@1",
                "date, data, UID, and container leaves never degrade through strings"
            );
            assert_eq!(failed_arg(&result, "fact").as_deref(), Some(fact));
        }
    }

    #[test]
    fn require_object_unpaired_surrogate_fails_atomically() {
        // Value string with an unpaired surrogate.
        let value_document = binary_document(
            &[
                vec![0x51, b'k'],
                vec![0x62, 0x00, 0x41, 0xD8, 0x00],
                vec![0xD1, 0x00, 0x01],
            ],
            2,
        );
        assert_eq!(
            failed_code(&require_object(&value_document, CollisionPolicy::Reject)),
            "plist.projection.unpaired-surrogate@1"
        );
        // Key with an unpaired surrogate.
        let key_document = binary_document(
            &[
                vec![0x62, 0x00, 0x41, 0xD8, 0x00],
                vec![0x51, b'x'],
                vec![0xD1, 0x00, 0x01],
            ],
            2,
        );
        assert_eq!(
            failed_code(&require_object(&key_document, CollisionPolicy::Reject)),
            "plist.projection.unpaired-surrogate@1"
        );
    }

    #[test]
    fn recovered_documents_fail_with_incomplete_document() {
        let recovered = parse_xml("<plist version=\"1.0\"><dict><key>a</key></dict></plist>");
        assert_eq!(recovered.status(), FormationStatus::Recovered);
        assert_eq!(
            failed_code(&value_tree(&recovered)),
            "plist.projection.incomplete-document@1"
        );
        assert_eq!(
            failed_code(&require_object(&recovered, CollisionPolicy::Reject)),
            "plist.projection.incomplete-document@1"
        );
        // Recovered without any provable native value.
        let no_native = parse_xml("<plist version=\"1.0\"><date>BAD</date></plist>");
        assert!(no_native.document().is_none());
        assert_eq!(
            failed_code(&value_tree(&no_native)),
            "plist.projection.incomplete-document@1"
        );
    }

    #[test]
    fn unpaired_surrogate_root_fails_atomically() {
        let document = binary_document(&[vec![0x62, 0x00, 0x41, 0xD8, 0x00]], 0);
        assert_eq!(
            failed_code(&value_tree(&document)),
            "plist.projection.unpaired-surrogate@1"
        );
        let root_string = require_object(&document, CollisionPolicy::Reject);
        assert_eq!(
            failed_code(&root_string),
            "plist.projection.unrepresentable@1",
            "a non-dict root fails require-object admission before value inspection"
        );
        assert_eq!(
            failed_arg(&root_string, "fact").as_deref(),
            Some("root-not-dict")
        );
    }

    #[test]
    fn projection_limits_are_atomic() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict><key>a</key><string>x</string><key>b</key><string>y</string></dict></plist>",
        );
        let limits = ProjectionLimits {
            max_source_nodes: 1,
            ..ProjectionLimits::default()
        };
        let result = project(
            &document,
            ProjectionRequest::value_tree().with_limits(limits),
        );
        assert_eq!(failed_code(&result), "plist.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_source_nodes")
        );

        let limits = ProjectionLimits {
            max_value_nodes: 2,
            ..ProjectionLimits::default()
        };
        let result = project(
            &document,
            ProjectionRequest::value_tree().with_limits(limits),
        );
        assert_eq!(failed_code(&result), "plist.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_value_nodes")
        );

        let limits = ProjectionLimits {
            max_provenance_units: 3,
            ..ProjectionLimits::default()
        };
        let result = project(
            &document,
            ProjectionRequest::value_tree().with_limits(limits),
        );
        assert_eq!(failed_code(&result), "plist.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_provenance_units")
        );

        let duplicate = parse_xml(
            "<plist version=\"1.0\"><dict><key>a</key><string>1</string><key>a</key><string>2</string></dict></plist>",
        );
        let limits = ProjectionLimits {
            max_report_entries: 0,
            ..ProjectionLimits::default()
        };
        let result = project(
            &duplicate,
            ProjectionRequest::require_object(CollisionPolicy::First).with_limits(limits),
        );
        assert_eq!(failed_code(&result), "plist.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_report_entries")
        );

        // Generous-enough explicit limits still complete.
        let limits = ProjectionLimits {
            max_source_nodes: 10,
            max_value_nodes: 10,
            max_report_entries: 10,
            max_provenance_units: 10,
        };
        let result = project(
            &document,
            ProjectionRequest::value_tree().with_limits(limits),
        );
        assert!(matches!(result, ProjectionResult::Complete(_)));
    }

    #[test]
    fn value_tree_provenance_uses_nested_value_paths() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>a</key><dict><key>b</key><array><string>x</string></array></dict>\
             <key>c</key><string>y</string>\
             </dict></plist>",
        );
        let projection = complete(value_tree(&document));
        let paths = projection
            .provenance
            .entries()
            .iter()
            .filter_map(|entry| match &entry.projected {
                ProjectedLocation::Value(path) => Some(path.segments().to_vec()),
                ProjectedLocation::Association(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(root),
                        ValuePathSegment::EntryValue(0),
                        ValuePathSegment::EntryValue(0),
                        ValuePathSegment::SequenceElement(0),
                    ] if root == "root"
                )
            }),
            "nested paths descend through root/entry/entry/element: {paths:?}"
        );
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(root),
                        ValuePathSegment::EntryKey(1),
                    ] if root == "root"
                )
            }),
            "dict keys are addressed as EntryKey ordinals: {paths:?}"
        );
        assert!(
            paths.iter().all(|segments| !segments.is_empty()),
            "no provenance entry may point at the bare root"
        );
        let associations = projection
            .provenance
            .entries()
            .iter()
            .filter_map(|entry| match &entry.projected {
                ProjectedLocation::Association(location) => Some(location),
                ProjectedLocation::Value(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(
            associations.iter().any(|location| {
                location.role() == AssociationRole::EntryMappingEntry && location.ordinal() == 1
            }),
            "dictionary associations publish EntryMappingEntry locations"
        );
    }

    #[test]
    fn require_object_provenance_keeps_retained_and_collapsed() {
        let document = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>a</key><string>one</string>\
             <key>a</key><string>last</string>\
             <key>b</key><string>two</string>\
             </dict></plist>",
        );
        let projection = complete(require_object(&document, CollisionPolicy::First));
        let relations = projection
            .provenance
            .entries()
            .iter()
            .map(|entry| entry.origins[0].relation)
            .collect::<Vec<_>>();
        assert_eq!(
            relations
                .iter()
                .filter(|relation| **relation == ProvenanceRelation::Direct)
                .count(),
            6,
            "two retained entries keep Direct association, key, and value origins"
        );
        assert_eq!(
            relations
                .iter()
                .filter(|relation| **relation == ProvenanceRelation::Collapsed)
                .count(),
            2,
            "the discarded association keeps a Collapsed association and value origin"
        );
        let collapsed_value_origin = projection
            .provenance
            .entries()
            .iter()
            .find(|entry| {
                entry.origins[0].relation == ProvenanceRelation::Collapsed
                    && matches!(entry.projected, ProjectedLocation::Value(_))
            })
            .expect("collapsed value origin");
        assert_eq!(
            collapsed_value_origin.origins[0].node.role(),
            NodeRole::PlistValue,
            "discarded provenance addresses the discarded value node"
        );
        assert_eq!(
            projection.provenance.entries().len(),
            8,
            "six retained origins (association, key, value per entry) plus two collapsed origins"
        );
    }

    #[test]
    fn integer_edges_project_exactly() {
        let document = parse_xml(
            "<plist version=\"1.0\"><array>\
             <integer>9223372036854775807</integer>\
             <integer>-9223372036854775808</integer>\
             </array></plist>",
        );
        let projection = complete(value_tree(&document));
        let (_, root) = record_parts(&projection.value);
        let elements = root.as_sequence().expect("root array");
        assert_eq!(
            elements[0].as_integer().expect("integer").to_string(),
            "9223372036854775807"
        );
        assert_eq!(
            elements[1].as_integer().expect("integer").to_string(),
            "-9223372036854775808"
        );
    }

    #[test]
    fn conformance_vector_value_tree_record() {
        let source = "<plist version=\"1.0\"><dict>\
            <key>name</key><string>text</string>\
            <key>count</key><integer>42</integer>\
            <key>ratio</key><real>1.5</real>\
            <key>enabled</key><true/>\
            <key>disabled</key><false/>\
            <key>payload</key><data>AQID</data>\
            <key>created</key><date>2023-01-01T00:00:00Z</date>\
            <key>tags</key><array><string>a</string><string>b</string></array>\
            </dict></plist>";
        let projection = complete(value_tree(&parse_xml(source)));
        let (record, root) = record_parts(&projection.value);
        assert_eq!(record, "plist.value-tree@1");
        let entries = root.as_entry_mapping().expect("dict");
        let keys = entries
            .iter()
            .map(|entry| entry.key().as_string().expect("key"))
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "name", "count", "ratio", "enabled", "disabled", "payload", "created", "tags"
            ]
        );
        assert_eq!(
            entry_value(root, "count")
                .as_integer()
                .expect("integer")
                .to_string(),
            "42"
        );
        assert_eq!(
            entry_value(root, "ratio")
                .as_binary_float64()
                .expect("real")
                .bits(),
            1.5_f64.to_bits()
        );
        assert_eq!(
            entry_value(root, "payload").as_bytes().expect("bytes"),
            &[0x01, 0x02, 0x03]
        );
        assert_eq!(
            object_value(entry_value(root, "created"), "seconds")
                .as_binary_float64()
                .expect("seconds")
                .bits(),
            694_224_000.0_f64.to_bits()
        );
        let tags = entry_value(root, "tags").as_sequence().expect("tags");
        assert_eq!(
            tags.iter()
                .map(|value| value.as_string().expect("tag"))
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn conformance_vector_require_object_policies() {
        let duplicate = parse_xml(
            "<plist version=\"1.0\"><dict>\
             <key>a</key><string>one</string>\
             <key>a</key><string>last</string>\
             <key>b</key><string>two</string>\
             </dict></plist>",
        );
        let rejected = require_object(&duplicate, CollisionPolicy::Reject);
        assert_eq!(
            failed_code(&rejected),
            "plist.projection.collision@1",
            "Reject fails"
        );
        let first = complete(require_object(&duplicate, CollisionPolicy::First));
        assert_eq!(first.fidelity, Fidelity::Transformed);
        let entries = first.value.as_object().expect("object");
        let keys = entries
            .iter()
            .map(consema_core::ObjectEntry::key)
            .collect::<Vec<_>>();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(object_value(&first.value, "a").as_string(), Some("one"));
        assert_eq!(object_value(&first.value, "b").as_string(), Some("two"));
        assert_eq!(first.report.events().len(), 1, "events_after_first is 1");

        let date_document = parse_xml(
            "<plist version=\"1.0\"><dict><key>d</key><date>2023-01-01T00:00:00Z</date><key>s</key><string>x</string></dict></plist>",
        );
        assert_eq!(
            failed_code(&require_object(&date_document, CollisionPolicy::Reject)),
            "plist.projection.unrepresentable@1"
        );
        let bytes_document =
            parse_xml("<plist version=\"1.0\"><dict><key>p</key><data>AQID</data></dict></plist>");
        assert_eq!(
            failed_code(&require_object(&bytes_document, CollisionPolicy::Reject)),
            "plist.projection.unrepresentable@1"
        );
    }

    #[test]
    fn conformance_vector_atomic_failures() {
        let recovered = parse_xml("<plist version=\"1.0\"><dict><key>a</key></dict></plist>");
        assert_eq!(
            failed_code(&value_tree(&recovered)),
            "plist.projection.incomplete-document@1"
        );
        let unpaired = binary_document(&[vec![0x62, 0xD8, 0x00, 0x00, 0x41]], 0);
        assert_eq!(
            failed_code(&value_tree(&unpaired)),
            "plist.projection.unpaired-surrogate@1"
        );
    }
}
