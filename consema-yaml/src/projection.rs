use std::collections::HashSet;

use consema_core::{
    AssociationLocation, AssociationRole, BigInteger, BinaryFloat64, Date, Decimal,
    EntryMappingBuilder, LocalDateTime, ObjectBuilder, OffsetDateTime, PortableValue,
    SequenceBuilder, Time, ValuePath, ValuePathSegment,
};
use consema_document::{NodeRef, NodeRole, SnapshotIdentity, Span};
use consema_graph::{GraphBuildError, GraphLimits, GraphNodeId, PortableGraph};

use crate::native::{
    NativeContent, NativeScalar, TAG_BINARY, TAG_BOOL, TAG_FLOAT, TAG_INT, TAG_MAP, TAG_NULL,
    TAG_SEQ, TAG_STR, TAG_TIMESTAMP,
};
use crate::{Document, GraphProjectionError, YamlScalarKind};

/// Graph projection resource contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphProjectionLimits {
    /// PortableGraph construction and traversal limits.
    pub graph: GraphLimits,
    /// Maximum projected-location plus origin records.
    pub max_provenance_entries: usize,
}

impl Default for GraphProjectionLimits {
    fn default() -> Self {
        Self {
            graph: GraphLimits::default(),
            max_provenance_entries: 2_000_000,
        }
    }
}

/// Immutable `yaml.projection.best-exact-graph@1` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphProjectionRequest {
    limits: GraphProjectionLimits,
}

impl GraphProjectionRequest {
    /// Creates the frozen exact graph request with default limits.
    #[must_use]
    pub fn best_exact_v1() -> Self {
        Self {
            limits: GraphProjectionLimits::default(),
        }
    }

    /// Replaces all graph projection limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: GraphProjectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Exact limits used by the request.
    #[must_use]
    pub const fn limits(self) -> GraphProjectionLimits {
        self.limits
    }
}

/// One exact projected graph location.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GraphProjectedLocation {
    /// Ordered root occurrence.
    Root(u64),
    /// Graph node identity.
    Node(GraphNodeId),
    /// Ordered sequence edge.
    SequenceElement {
        /// Parent sequence node.
        parent: GraphNodeId,
        /// Direct element ordinal.
        ordinal: u64,
    },
    /// Ordered mapping key edge.
    MappingKey {
        /// Parent mapping node.
        parent: GraphNodeId,
        /// Direct association ordinal.
        ordinal: u64,
    },
    /// Ordered mapping value edge.
    MappingValue {
        /// Parent mapping node.
        parent: GraphNodeId,
        /// Direct association ordinal.
        ordinal: u64,
    },
}

/// Source relation shared by graph and tree projection provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProvenanceRelation {
    /// Direct native semantic origin.
    Direct,
    /// Alias edge referring to a shared representation node.
    Reference,
    /// Alias edge explicitly duplicated into a PortableValue tree.
    Expanded,
    /// A tag was explicitly removed by policy.
    TagStripped,
}

/// One exact YAML source origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOrigin {
    /// Owning source snapshot.
    pub snapshot: SnapshotIdentity,
    /// Exact structural identity.
    pub node: NodeRef,
    /// Exact raw source span.
    pub span: Span,
    /// Source-to-result relation.
    pub relation: ProvenanceRelation,
}

/// One graph provenance multimap entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphProvenanceEntry {
    /// Projected graph location.
    pub projected: GraphProjectedLocation,
    /// One or more exact YAML origins.
    pub origins: Vec<SourceOrigin>,
}

/// Complete deterministic graph provenance multimap.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphProvenanceMap {
    entries: Vec<GraphProvenanceEntry>,
}

impl GraphProvenanceMap {
    /// Entries in root/node/association construction order.
    #[must_use]
    pub fn entries(&self) -> &[GraphProvenanceEntry] {
        &self.entries
    }
}

/// Complete exact graph projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteGraphProjection {
    /// Complete immutable graph.
    pub graph: PortableGraph,
    /// Complete native-to-graph provenance.
    pub provenance: GraphProvenanceMap,
}

/// Graph projection failure; no graph or provenance is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphProjectionFailure {
    /// Custom tag has no published graph canonical semantics.
    UnsupportedTag(String),
    /// Graph construction failed atomically.
    Graph(GraphBuildError),
    /// Provenance resource limit was exceeded atomically.
    ProvenanceLimit,
}

impl From<GraphProjectionError> for GraphProjectionFailure {
    fn from(value: GraphProjectionError) -> Self {
        match value {
            GraphProjectionError::UnsupportedTag(tag) => Self::UnsupportedTag(tag),
            GraphProjectionError::Graph(error) => Self::Graph(error),
        }
    }
}

/// Explicit YAML graph-sharing policy for PortableValue projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SharingPolicy {
    /// Sharing and aliases fail; graph identity is never silently discarded.
    Reject,
    /// Acyclic sharing is duplicated and reported; cycles still fail.
    DuplicateAcyclic,
}

/// Explicit YAML tag policy for PortableValue projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TagPolicy {
    /// Only tags with a frozen exact PortableValue lowering are accepted.
    RequireKnownPortableTag,
    /// Unsupported standard and custom tags are removed and reported.
    StripToNodeKind,
}

/// YAML mapping-to-tree selection policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MappingPolicy {
    /// Use Object only for unique string keys, otherwise EntryMapping.
    BestExactObjectOrEntryMapping,
    /// Require every mapping to satisfy unique-string Object invariants.
    RequireObject,
    /// Preserve every mapping as ordered EntryMapping.
    RequireEntryMapping,
}

/// PortableValue projection resource contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueProjectionLimits {
    /// Maximum projected native/value node visits.
    pub max_value_nodes: usize,
    /// Maximum recursive graph depth.
    pub max_depth: usize,
    /// Maximum report events.
    pub max_report_entries: usize,
    /// Maximum projected-location plus origin records.
    pub max_provenance_entries: usize,
    /// Maximum output-node visits divided by unique native nodes.
    pub max_amplification_ratio: usize,
}

impl Default for ValueProjectionLimits {
    fn default() -> Self {
        Self {
            max_value_nodes: 1_000_000,
            max_depth: 256,
            max_report_entries: 100_000,
            max_provenance_entries: 2_000_000,
            max_amplification_ratio: 16,
        }
    }
}

/// Immutable `yaml.projection.best-exact-value@1` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueProjectionRequest {
    sharing: SharingPolicy,
    tags: TagPolicy,
    mapping: MappingPolicy,
    limits: ValueProjectionLimits,
}

impl ValueProjectionRequest {
    /// Frozen default: one document, no sharing/cycles, known tags, exact-first mapping.
    #[must_use]
    pub fn best_exact_v1() -> Self {
        Self {
            sharing: SharingPolicy::Reject,
            tags: TagPolicy::RequireKnownPortableTag,
            mapping: MappingPolicy::BestExactObjectOrEntryMapping,
            limits: ValueProjectionLimits::default(),
        }
    }

    /// Explicitly replaces the sharing policy.
    #[must_use]
    pub const fn with_sharing(mut self, sharing: SharingPolicy) -> Self {
        self.sharing = sharing;
        self
    }

    /// Explicitly replaces the tag policy.
    #[must_use]
    pub const fn with_tags(mut self, tags: TagPolicy) -> Self {
        self.tags = tags;
        self
    }

    /// Explicitly replaces the mapping policy.
    #[must_use]
    pub const fn with_mapping(mut self, mapping: MappingPolicy) -> Self {
        self.mapping = mapping;
        self
    }

    /// Replaces all value projection limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: ValueProjectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Selected sharing policy.
    #[must_use]
    pub const fn sharing(self) -> SharingPolicy {
        self.sharing
    }

    /// Selected tag policy.
    #[must_use]
    pub const fn tags(self) -> TagPolicy {
        self.tags
    }

    /// Selected mapping policy.
    #[must_use]
    pub const fn mapping(self) -> MappingPolicy {
        self.mapping
    }

    /// Exact limits.
    #[must_use]
    pub const fn limits(self) -> ValueProjectionLimits {
        self.limits
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target completely represents all covered semantics.
    Exact,
    /// Explicit policy performed a declared structural transformation.
    Transformed,
    /// Explicit policy discarded an unrecoverable source fact.
    Lossy,
}

/// One PortableValue or association location.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ProjectedLocation {
    /// Portable value path.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// One PortableValue provenance entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected tree location.
    pub projected: ProjectedLocation,
    /// One or more exact YAML origins.
    pub origins: Vec<SourceOrigin>,
}

/// Complete deterministic PortableValue provenance multimap.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMap {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceMap {
    /// Entries in deterministic projection order.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }
}

/// Structured YAML value projection event category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionEventKind {
    /// Shared graph identity was explicitly duplicated into a tree.
    SharingDuplicated,
    /// Unsupported tag was explicitly removed.
    TagStripped,
}

/// One machine-readable projection transformation/loss event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event category.
    pub kind: ProjectionEventKind,
    /// Policy that authorized the event.
    pub policy: String,
    /// Exact source identity.
    pub source: NodeRef,
    /// Projected value location.
    pub projected: ValuePath,
    /// Stable old semantic category.
    pub old_category: String,
    /// Stable new semantic category.
    pub new_category: String,
    /// Whether output plus contract can recover the fact.
    pub reversible: bool,
    /// Fidelity impact.
    pub loss: Fidelity,
}

/// Complete ordered value projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in deterministic traversal order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }
}

/// Complete successful PortableValue projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteValueProjection {
    /// Complete immutable tree value.
    pub value: PortableValue,
    /// Worst fidelity of the complete operation.
    pub fidelity: Fidelity,
    /// Explicit transformation/loss report.
    pub report: ProjectionReport,
    /// Complete source-to-tree provenance.
    pub provenance: ProvenanceMap,
}

/// Value projection failure; no partial value or provenance is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueProjectionFailure {
    /// Stream does not contain exactly one document.
    DocumentCardinality {
        /// Actual number of stream documents.
        actual: usize,
    },
    /// Representation cycle cannot enter a tree.
    Cycle {
        /// First node that closes the active traversal cycle.
        node: NodeRef,
    },
    /// Shared identity requires explicit duplication authorization.
    Sharing {
        /// Revisited shared representation node.
        node: NodeRef,
    },
    /// Tag has no exact PortableValue lowering.
    UnsupportedTag {
        /// Tagged representation node.
        node: NodeRef,
        /// Resolved unsupported tag.
        tag: String,
    },
    /// Mapping cannot satisfy an explicitly required Object policy.
    MappingNotObject {
        /// Mapping node that violates Object invariants.
        node: NodeRef,
    },
    /// Canonical scalar could not form the promised PortableValue category.
    InvalidCanonicalScalar {
        /// Scalar node whose promised canonical form failed.
        node: NodeRef,
    },
    /// YAML timestamp is valid but outside PortableValue temporal categories.
    UnrepresentableTimestamp {
        /// Timestamp scalar outside the core temporal model.
        node: NodeRef,
    },
    /// Declared resource limit was reached.
    ResourceLimit(&'static str),
}

/// Complete-or-failed PortableValue projection algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueProjectionResult {
    /// Complete result.
    Complete(CompleteValueProjection),
    /// Failed result with no partial value, report, or provenance.
    Failed(ValueProjectionFailure),
}

impl Document {
    /// Applies exact graph projection with complete node/edge/alias provenance.
    pub fn project_graph_with_provenance(
        &self,
        request: GraphProjectionRequest,
    ) -> Result<CompleteGraphProjection, GraphProjectionFailure> {
        let (graph, ids) = self
            .native
            .project_graph_with_ids(request.limits.graph)
            .map_err(GraphProjectionFailure::from)?;
        let mut builder = GraphProvenanceBuilder {
            document: self,
            ids: &ids,
            max_entries: request.limits.max_provenance_entries,
            units: 0,
            map: GraphProvenanceMap::default(),
        };
        builder.build()?;
        Ok(CompleteGraphProjection {
            graph,
            provenance: builder.map,
        })
    }

    /// Applies explicit YAML-to-PortableValue tree projection.
    #[must_use]
    pub fn project_value(&self, request: ValueProjectionRequest) -> ValueProjectionResult {
        if self.document_count() != 1 {
            return ValueProjectionResult::Failed(ValueProjectionFailure::DocumentCardinality {
                actual: self.document_count(),
            });
        }
        if request.limits.max_amplification_ratio == 0 {
            return ValueProjectionResult::Failed(ValueProjectionFailure::ResourceLimit(
                "max_amplification_ratio",
            ));
        }
        let mut context = ValueContext {
            document: self,
            request,
            seen: HashSet::new(),
            stack: HashSet::new(),
            visits: 0,
            provenance_units: 0,
            report: ProjectionReport::default(),
            provenance: ProvenanceMap::default(),
            fidelity: Fidelity::Exact,
        };
        let root = self.native.documents[0].root;
        match context.project_node(root, &ValuePath::root(), 0, None) {
            Ok(value) => {
                let maximum = context
                    .seen
                    .len()
                    .saturating_mul(request.limits.max_amplification_ratio);
                if context.visits > maximum {
                    return ValueProjectionResult::Failed(ValueProjectionFailure::ResourceLimit(
                        "max_amplification_ratio",
                    ));
                }
                ValueProjectionResult::Complete(CompleteValueProjection {
                    value,
                    fidelity: context.fidelity,
                    report: context.report,
                    provenance: context.provenance,
                })
            }
            Err(failure) => ValueProjectionResult::Failed(failure),
        }
    }
}

struct GraphProvenanceBuilder<'a> {
    document: &'a Document,
    ids: &'a [GraphNodeId],
    max_entries: usize,
    units: usize,
    map: GraphProvenanceMap,
}

impl GraphProvenanceBuilder<'_> {
    fn build(&mut self) -> Result<(), GraphProjectionFailure> {
        for (ordinal, document) in self.document.native.documents.iter().enumerate() {
            self.add(
                GraphProjectedLocation::Root(ordinal as u64),
                SourceOrigin {
                    snapshot: self.document.snapshot_identity(),
                    node: self
                        .document
                        .authority
                        .node_ref(ordinal as u64, NodeRole::YamlDocument),
                    span: document.span,
                    relation: ProvenanceRelation::Direct,
                },
            )?;
        }
        for (index, node) in self.document.native.nodes.iter().enumerate() {
            self.add(
                GraphProjectedLocation::Node(self.ids[index]),
                SourceOrigin {
                    snapshot: self.document.snapshot_identity(),
                    node: crate::node_ref(&self.document.authority, index),
                    span: node.span,
                    relation: ProvenanceRelation::Direct,
                },
            )?;
            match &node.content {
                NativeContent::Scalar(_) => {}
                NativeContent::Sequence(items) => {
                    for (ordinal, item) in items.iter().enumerate() {
                        let location = GraphProjectedLocation::SequenceElement {
                            parent: self.ids[index],
                            ordinal: ordinal as u64,
                        };
                        self.add(
                            location,
                            SourceOrigin {
                                snapshot: self.document.snapshot_identity(),
                                node: self
                                    .document
                                    .authority
                                    .node_ref(item.identity, NodeRole::YamlSequenceElement),
                                span: item.span,
                                relation: ProvenanceRelation::Direct,
                            },
                        )?;
                        if let Some(alias) = item.alias {
                            self.add_alias(location, alias, ProvenanceRelation::Reference)?;
                        }
                    }
                }
                NativeContent::Mapping(entries) => {
                    for (ordinal, entry) in entries.iter().enumerate() {
                        for (location, alias) in [
                            (
                                GraphProjectedLocation::MappingKey {
                                    parent: self.ids[index],
                                    ordinal: ordinal as u64,
                                },
                                entry.key_alias,
                            ),
                            (
                                GraphProjectedLocation::MappingValue {
                                    parent: self.ids[index],
                                    ordinal: ordinal as u64,
                                },
                                entry.value_alias,
                            ),
                        ] {
                            self.add(
                                location,
                                SourceOrigin {
                                    snapshot: self.document.snapshot_identity(),
                                    node: self
                                        .document
                                        .authority
                                        .node_ref(entry.identity, NodeRole::YamlMappingEntry),
                                    span: entry.span,
                                    relation: ProvenanceRelation::Direct,
                                },
                            )?;
                            if let Some(alias) = alias {
                                self.add_alias(location, alias, ProvenanceRelation::Reference)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_alias(
        &mut self,
        location: GraphProjectedLocation,
        ordinal: usize,
        relation: ProvenanceRelation,
    ) -> Result<(), GraphProjectionFailure> {
        let alias = &self.document.native.aliases[ordinal];
        self.add(
            location,
            SourceOrigin {
                snapshot: self.document.snapshot_identity(),
                node: self
                    .document
                    .authority
                    .node_ref(alias.identity, NodeRole::YamlAlias),
                span: alias.span,
                relation,
            },
        )
    }

    fn add(
        &mut self,
        projected: GraphProjectedLocation,
        origin: SourceOrigin,
    ) -> Result<(), GraphProjectionFailure> {
        let existing = self
            .map
            .entries
            .iter()
            .position(|entry| entry.projected == projected);
        let observed = self
            .units
            .saturating_add(if existing.is_some() { 1 } else { 2 });
        if observed > self.max_entries {
            return Err(GraphProjectionFailure::ProvenanceLimit);
        }
        self.units = observed;
        if let Some(position) = existing {
            self.map.entries[position].origins.push(origin);
        } else {
            self.map.entries.push(GraphProvenanceEntry {
                projected,
                origins: vec![origin],
            });
        }
        Ok(())
    }
}

struct ValueContext<'a> {
    document: &'a Document,
    request: ValueProjectionRequest,
    seen: HashSet<usize>,
    stack: HashSet<usize>,
    visits: usize,
    provenance_units: usize,
    report: ProjectionReport,
    provenance: ProvenanceMap,
    fidelity: Fidelity,
}

impl ValueContext<'_> {
    fn project_node(
        &mut self,
        index: usize,
        path: &ValuePath,
        depth: usize,
        incoming_alias: Option<usize>,
    ) -> Result<PortableValue, ValueProjectionFailure> {
        if depth > self.request.limits.max_depth {
            return Err(ValueProjectionFailure::ResourceLimit("max_depth"));
        }
        self.visits = self.visits.saturating_add(1);
        if self.visits > self.request.limits.max_value_nodes {
            return Err(ValueProjectionFailure::ResourceLimit("max_value_nodes"));
        }
        let node_ref = crate::node_ref(&self.document.authority, index);
        if self.stack.contains(&index) {
            return Err(ValueProjectionFailure::Cycle { node: node_ref });
        }
        if self.seen.contains(&index) {
            if self.request.sharing == SharingPolicy::Reject {
                return Err(ValueProjectionFailure::Sharing { node: node_ref });
            }
            self.event(
                ProjectionEventKind::SharingDuplicated,
                "DuplicateAcyclicSharing@1",
                incoming_alias.map_or(node_ref, |ordinal| self.alias_ref(ordinal)),
                path,
                "SharedGraphNode",
                "DuplicatedTreeValue",
                false,
                Fidelity::Transformed,
            )?;
        }
        self.seen.insert(index);
        self.stack.insert(index);
        let node = &self.document.native.nodes[index];
        let supported_tag = is_portable_tag(&node.tag, &node.content);
        if !supported_tag {
            if self.request.tags == TagPolicy::RequireKnownPortableTag {
                return Err(ValueProjectionFailure::UnsupportedTag {
                    node: node_ref,
                    tag: node.tag.to_string(),
                });
            }
            self.event(
                ProjectionEventKind::TagStripped,
                "StripToNodeKind@1",
                node_ref,
                path,
                &node.tag,
                node_kind_name(&node.content),
                false,
                Fidelity::Lossy,
            )?;
        }
        let value = match &node.content {
            NativeContent::Scalar(scalar) => self.project_scalar(index, scalar, supported_tag)?,
            NativeContent::Sequence(items) => {
                let mut builder = SequenceBuilder::new();
                for (ordinal, item) in items.iter().enumerate() {
                    let child = path.child(ValuePathSegment::SequenceElement(ordinal as u64));
                    builder.push(self.project_node(
                        item.node,
                        &child,
                        depth.saturating_add(1),
                        item.alias,
                    )?);
                    self.add_origin(
                        ProjectedLocation::Value(child),
                        self.document
                            .authority
                            .node_ref(item.identity, NodeRole::YamlSequenceElement),
                        item.span,
                        ProvenanceRelation::Direct,
                    )?;
                }
                builder.build()
            }
            NativeContent::Mapping(entries) => self.project_mapping(index, entries, path, depth)?,
        };
        self.stack.remove(&index);
        self.add_origin(
            ProjectedLocation::Value(path.clone()),
            node_ref,
            node.span,
            if supported_tag {
                ProvenanceRelation::Direct
            } else {
                ProvenanceRelation::TagStripped
            },
        )?;
        if let Some(alias) = incoming_alias {
            let alias = &self.document.native.aliases[alias];
            self.add_origin(
                ProjectedLocation::Value(path.clone()),
                self.document
                    .authority
                    .node_ref(alias.identity, NodeRole::YamlAlias),
                alias.span,
                ProvenanceRelation::Expanded,
            )?;
        }
        Ok(value)
    }

    fn project_mapping(
        &mut self,
        index: usize,
        entries: &[crate::native::NativeMappingEntry],
        path: &ValuePath,
        depth: usize,
    ) -> Result<PortableValue, ValueProjectionFailure> {
        let object_names = object_names(self.document, entries);
        let use_object = match self.request.mapping {
            MappingPolicy::BestExactObjectOrEntryMapping => object_names.is_some(),
            MappingPolicy::RequireObject if object_names.is_some() => true,
            MappingPolicy::RequireObject => {
                return Err(ValueProjectionFailure::MappingNotObject {
                    node: crate::node_ref(&self.document.authority, index),
                });
            }
            MappingPolicy::RequireEntryMapping => false,
        };
        if use_object {
            let names = object_names.expect("checked object names");
            let mut builder = ObjectBuilder::new();
            for (ordinal, (entry, name)) in entries.iter().zip(names).enumerate() {
                self.visit_object_key(entry.key, entry.key_alias, path)?;
                let child = path.child(ValuePathSegment::ObjectValue(name.clone()));
                builder
                    .insert(
                        &name,
                        self.project_node(
                            entry.value,
                            &child,
                            depth.saturating_add(1),
                            entry.value_alias,
                        )?,
                    )
                    .expect("prevalidated unique object names");
                self.add_mapping_origins(path, ordinal, entry, true)?;
            }
            Ok(builder.build())
        } else {
            let mut builder = EntryMappingBuilder::new();
            for (ordinal, entry) in entries.iter().enumerate() {
                let key_path = path.child(ValuePathSegment::EntryKey(ordinal as u64));
                let value_path = path.child(ValuePathSegment::EntryValue(ordinal as u64));
                let key = self.project_node(
                    entry.key,
                    &key_path,
                    depth.saturating_add(1),
                    entry.key_alias,
                )?;
                let value = self.project_node(
                    entry.value,
                    &value_path,
                    depth.saturating_add(1),
                    entry.value_alias,
                )?;
                builder.push(key, value);
                self.add_mapping_origins(path, ordinal, entry, false)?;
            }
            Ok(builder.build())
        }
    }

    fn visit_object_key(
        &mut self,
        index: usize,
        alias: Option<usize>,
        path: &ValuePath,
    ) -> Result<(), ValueProjectionFailure> {
        let node = crate::node_ref(&self.document.authority, index);
        if self.stack.contains(&index) {
            return Err(ValueProjectionFailure::Cycle { node });
        }
        if self.seen.contains(&index) {
            if self.request.sharing == SharingPolicy::Reject {
                return Err(ValueProjectionFailure::Sharing { node });
            }
            self.event(
                ProjectionEventKind::SharingDuplicated,
                "DuplicateAcyclicSharing@1",
                alias.map_or(node, |ordinal| self.alias_ref(ordinal)),
                path,
                "SharedGraphNode",
                "DuplicatedObjectKey",
                false,
                Fidelity::Transformed,
            )?;
        }
        self.seen.insert(index);
        self.visits = self.visits.saturating_add(1);
        if self.visits > self.request.limits.max_value_nodes {
            return Err(ValueProjectionFailure::ResourceLimit("max_value_nodes"));
        }
        Ok(())
    }

    fn project_scalar(
        &self,
        index: usize,
        scalar: &NativeScalar,
        supported_tag: bool,
    ) -> Result<PortableValue, ValueProjectionFailure> {
        let invalid = || ValueProjectionFailure::InvalidCanonicalScalar {
            node: crate::node_ref(&self.document.authority, index),
        };
        if !supported_tag {
            return Ok(PortableValue::string(scalar.decoded.clone()));
        }
        match scalar.kind {
            YamlScalarKind::Null => Ok(PortableValue::null()),
            YamlScalarKind::Boolean => match scalar.canonical.as_ref() {
                "true" => Ok(PortableValue::boolean(true)),
                "false" => Ok(PortableValue::boolean(false)),
                _ => Err(invalid()),
            },
            YamlScalarKind::Integer => BigInteger::parse_decimal(&scalar.canonical)
                .map(PortableValue::integer)
                .map_err(|_| invalid()),
            YamlScalarKind::Float => match scalar.canonical.as_ref() {
                ".inf" => Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
                    0x7ff0_0000_0000_0000,
                ))),
                "-.inf" => Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
                    0xfff0_0000_0000_0000,
                ))),
                ".nan" => Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
                    0x7ff8_0000_0000_0000,
                ))),
                value => Decimal::parse_json_number(value)
                    .map(PortableValue::decimal)
                    .map_err(|_| invalid()),
            },
            YamlScalarKind::String => Ok(PortableValue::string(scalar.canonical.clone())),
            YamlScalarKind::Binary => decode_base64(&scalar.canonical)
                .map(PortableValue::bytes)
                .ok_or_else(invalid),
            YamlScalarKind::Timestamp => project_timestamp(&scalar.canonical).map_err(|()| {
                ValueProjectionFailure::UnrepresentableTimestamp {
                    node: crate::node_ref(&self.document.authority, index),
                }
            }),
            YamlScalarKind::Custom | YamlScalarKind::Tagged => {
                Ok(PortableValue::string(scalar.decoded.clone()))
            }
        }
    }

    fn add_mapping_origins(
        &mut self,
        path: &ValuePath,
        ordinal: usize,
        entry: &crate::native::NativeMappingEntry,
        object: bool,
    ) -> Result<(), ValueProjectionFailure> {
        let association = AssociationLocation::new(
            path.clone(),
            ordinal as u64,
            if object {
                AssociationRole::ObjectEntry
            } else {
                AssociationRole::EntryMappingEntry
            },
        );
        self.add_origin(
            ProjectedLocation::Association(association),
            self.document
                .authority
                .node_ref(entry.identity, NodeRole::YamlMappingEntry),
            entry.span,
            ProvenanceRelation::Direct,
        )?;
        if object {
            let key_location = ProjectedLocation::Association(AssociationLocation::new(
                path.clone(),
                ordinal as u64,
                AssociationRole::ObjectKey,
            ));
            let key = &self.document.native.nodes[entry.key];
            self.add_origin(
                key_location.clone(),
                crate::node_ref(&self.document.authority, entry.key),
                key.span,
                ProvenanceRelation::Direct,
            )?;
            if let Some(alias) = entry.key_alias {
                let alias = &self.document.native.aliases[alias];
                self.add_origin(
                    key_location,
                    self.document
                        .authority
                        .node_ref(alias.identity, NodeRole::YamlAlias),
                    alias.span,
                    ProvenanceRelation::Expanded,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn event(
        &mut self,
        kind: ProjectionEventKind,
        policy: &str,
        source: NodeRef,
        path: &ValuePath,
        old_category: &str,
        new_category: &str,
        reversible: bool,
        loss: Fidelity,
    ) -> Result<(), ValueProjectionFailure> {
        let observed = self.report.events.len().saturating_add(1);
        if observed > self.request.limits.max_report_entries {
            return Err(ValueProjectionFailure::ResourceLimit("max_report_entries"));
        }
        self.report.events.push(ProjectionEvent {
            kind,
            policy: policy.to_owned(),
            source,
            projected: path.clone(),
            old_category: old_category.to_owned(),
            new_category: new_category.to_owned(),
            reversible,
            loss,
        });
        self.fidelity = self.fidelity.max(loss);
        Ok(())
    }

    fn add_origin(
        &mut self,
        projected: ProjectedLocation,
        node: NodeRef,
        span: Span,
        relation: ProvenanceRelation,
    ) -> Result<(), ValueProjectionFailure> {
        let existing = self
            .provenance
            .entries
            .iter()
            .position(|entry| entry.projected == projected);
        let observed = self
            .provenance_units
            .saturating_add(if existing.is_some() { 1 } else { 2 });
        if observed > self.request.limits.max_provenance_entries {
            return Err(ValueProjectionFailure::ResourceLimit(
                "max_provenance_entries",
            ));
        }
        self.provenance_units = observed;
        let origin = SourceOrigin {
            snapshot: self.document.snapshot_identity(),
            node,
            span,
            relation,
        };
        if let Some(position) = existing {
            self.provenance.entries[position].origins.push(origin);
        } else {
            self.provenance.entries.push(ProvenanceEntry {
                projected,
                origins: vec![origin],
            });
        }
        Ok(())
    }

    fn alias_ref(&self, ordinal: usize) -> NodeRef {
        let alias = &self.document.native.aliases[ordinal];
        self.document
            .authority
            .node_ref(alias.identity, NodeRole::YamlAlias)
    }
}

fn object_names(
    document: &Document,
    entries: &[crate::native::NativeMappingEntry],
) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let mut names = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = &document.native.nodes[entry.key];
        let NativeContent::Scalar(scalar) = &key.content else {
            return None;
        };
        if key.tag.as_ref() != TAG_STR {
            return None;
        }
        let name = scalar.canonical.to_string();
        if !seen.insert(name.clone()) {
            return None;
        }
        names.push(name);
    }
    Some(names)
}

fn is_portable_tag(tag: &str, content: &NativeContent) -> bool {
    match content {
        NativeContent::Scalar(_) => matches!(
            tag,
            TAG_NULL | TAG_BOOL | TAG_INT | TAG_FLOAT | TAG_STR | TAG_TIMESTAMP | TAG_BINARY
        ),
        NativeContent::Sequence(_) => tag == TAG_SEQ,
        NativeContent::Mapping(_) => tag == TAG_MAP,
    }
}

fn node_kind_name(content: &NativeContent) -> &'static str {
    match content {
        NativeContent::Scalar(_) => "Scalar",
        NativeContent::Sequence(_) => "Sequence",
        NativeContent::Mapping(_) => "Mapping",
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let a = u32::from(base64_value(chunk[0])?);
        let b = u32::from(base64_value(chunk[1])?);
        let c = if chunk[2] == b'=' {
            0
        } else {
            u32::from(base64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            u32::from(base64_value(chunk[3])?)
        };
        let combined = (a << 18) | (b << 12) | (c << 6) | d;
        output.push((combined >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((combined >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(combined as u8);
        }
    }
    Some(output)
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn project_timestamp(value: &str) -> Result<PortableValue, ()> {
    let date = Date::new(
        BigInteger::parse_decimal(&value[..4]).map_err(|_| ())?,
        value[5..7].parse().map_err(|_| ())?,
        value[8..10].parse().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    if value.len() == 10 {
        return Ok(PortableValue::date(date));
    }
    let time_start = 11;
    let hour = value[time_start..time_start + 2].parse().map_err(|_| ())?;
    let minute = value[time_start + 3..time_start + 5]
        .parse()
        .map_err(|_| ())?;
    let second = value[time_start + 6..time_start + 8]
        .parse()
        .map_err(|_| ())?;
    let tail = &value[time_start + 8..];
    let zone_start = tail.find(['Z', '+', '-']).ok_or(())?;
    let fraction = if zone_start == 0 {
        Decimal::new(BigInteger::zero(), BigInteger::zero())
    } else {
        Decimal::parse_json_number(&format!("0{}", &tail[..zone_start])).map_err(|_| ())?
    };
    let time = Time::new(hour, minute, second, fraction).map_err(|_| ())?;
    let local = LocalDateTime::new(date, time);
    let zone = &tail[zone_start..];
    let offset = if zone == "Z" {
        0
    } else {
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let hours: i32 = zone[1..3].parse().map_err(|_| ())?;
        let minutes: i32 = zone[4..6].parse().map_err(|_| ())?;
        sign * (hours * 3600 + minutes * 60)
    };
    OffsetDateTime::new(local, offset)
        .map(PortableValue::offset_date_time)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{YamlProfile, parse};
    use consema_document::ParseLimits;

    #[test]
    fn exact_graph_projection_relates_nodes_edges_and_aliases() {
        let document = parse(
            b"&root [one, *root]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let result = document
            .project_graph_with_provenance(GraphProjectionRequest::best_exact_v1())
            .unwrap();
        assert_eq!(result.graph.node_count(), 2);
        assert!(result.provenance.entries().iter().any(|entry| {
            matches!(
                entry.projected,
                GraphProjectedLocation::SequenceElement { ordinal: 1, .. }
            ) && entry
                .origins
                .iter()
                .any(|origin| origin.relation == ProvenanceRelation::Reference)
        }));
    }

    #[test]
    fn value_projection_rejects_then_explicitly_duplicates_acyclic_sharing() {
        let document = parse(
            b"[&x {k: v}, *x]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            document.project_value(ValueProjectionRequest::best_exact_v1()),
            ValueProjectionResult::Failed(ValueProjectionFailure::Sharing { .. })
        ));
        let duplicated = document.project_value(
            ValueProjectionRequest::best_exact_v1().with_sharing(SharingPolicy::DuplicateAcyclic),
        );
        let ValueProjectionResult::Complete(duplicated) = duplicated else {
            panic!("explicit acyclic duplication must complete");
        };
        assert_eq!(duplicated.fidelity, Fidelity::Transformed);
        assert_eq!(duplicated.report.events().len(), 3);
        assert!(
            duplicated
                .report
                .events()
                .iter()
                .all(|event| event.kind == ProjectionEventKind::SharingDuplicated)
        );
    }

    #[test]
    fn cycles_never_enter_portable_values_and_custom_tags_need_policy() {
        let cycle = parse(
            b"&x [*x]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            cycle.project_value(
                ValueProjectionRequest::best_exact_v1()
                    .with_sharing(SharingPolicy::DuplicateAcyclic)
            ),
            ValueProjectionResult::Failed(ValueProjectionFailure::Cycle { .. })
        ));

        let tagged = parse(
            b"!example value".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            tagged.project_value(ValueProjectionRequest::best_exact_v1()),
            ValueProjectionResult::Failed(ValueProjectionFailure::UnsupportedTag { .. })
        ));
        let stripped = tagged.project_value(
            ValueProjectionRequest::best_exact_v1().with_tags(TagPolicy::StripToNodeKind),
        );
        let ValueProjectionResult::Complete(stripped) = stripped else {
            panic!("explicit stripping must complete");
        };
        assert_eq!(stripped.value.as_string(), Some("value"));
        assert_eq!(stripped.fidelity, Fidelity::Lossy);
    }

    #[test]
    fn scalar_and_mapping_lowering_is_exact_and_bounded() {
        let document = parse(
            b"bytes: !!binary SGVsbG8=\ntime: !!timestamp 2001-12-15T02:59:43Z\ndup: {a: 1, a: 2}\n"
                .as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        let result = document.project_value(ValueProjectionRequest::best_exact_v1());
        let ValueProjectionResult::Complete(result) = result else {
            panic!("exact value projection");
        };
        let root = result.value.as_object().unwrap();
        assert_eq!(root[0].value().as_bytes(), Some(b"Hello".as_slice()));
        assert!(root[1].value().as_offset_date_time().is_some());
        assert!(root[2].value().as_entry_mapping().is_some());

        assert!(matches!(
            document.project_value(ValueProjectionRequest::best_exact_v1().with_limits(
                ValueProjectionLimits {
                    max_value_nodes: 1,
                    ..ValueProjectionLimits::default()
                }
            )),
            ValueProjectionResult::Failed(ValueProjectionFailure::ResourceLimit("max_value_nodes"))
        ));
    }

    #[test]
    fn multidocument_stream_requires_an_explicit_non_value_target() {
        let document = parse(
            b"---\na\n---\nb\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            document.project_value(ValueProjectionRequest::best_exact_v1()),
            ValueProjectionResult::Failed(ValueProjectionFailure::DocumentCardinality {
                actual: 2
            })
        );
    }

    #[test]
    fn mapping_and_provenance_limits_are_explicit_and_atomic() {
        let document = parse(
            b"{a: 1, a: 2}".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            document.project_value(
                ValueProjectionRequest::best_exact_v1().with_mapping(MappingPolicy::RequireObject)
            ),
            ValueProjectionResult::Failed(ValueProjectionFailure::MappingNotObject { .. })
        ));
        let entry_mapping = document.project_value(
            ValueProjectionRequest::best_exact_v1()
                .with_mapping(MappingPolicy::RequireEntryMapping),
        );
        let ValueProjectionResult::Complete(entry_mapping) = entry_mapping else {
            panic!("explicit EntryMapping target");
        };
        assert_eq!(entry_mapping.value.as_entry_mapping().unwrap().len(), 2);

        assert_eq!(
            document.project_graph_with_provenance(
                GraphProjectionRequest::best_exact_v1().with_limits(GraphProjectionLimits {
                    max_provenance_entries: 1,
                    ..GraphProjectionLimits::default()
                })
            ),
            Err(GraphProjectionFailure::ProvenanceLimit)
        );
        assert!(matches!(
            document.project_value(ValueProjectionRequest::best_exact_v1().with_limits(
                ValueProjectionLimits {
                    max_provenance_entries: 1,
                    ..ValueProjectionLimits::default()
                }
            )),
            ValueProjectionResult::Failed(ValueProjectionFailure::ResourceLimit(
                "max_provenance_entries"
            ))
        ));
    }

    #[test]
    fn non_finite_bits_are_frozen_and_leap_seconds_are_not_rounded() {
        let non_finite = parse(
            b".inf".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let ValueProjectionResult::Complete(projected) =
            non_finite.project_value(ValueProjectionRequest::best_exact_v1())
        else {
            panic!("non-finite projection");
        };
        assert_eq!(
            projected.value.as_binary_float64().unwrap().bits(),
            0x7ff0_0000_0000_0000
        );

        let leap = parse(
            b"!!timestamp 2001-12-15T02:59:60Z".as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            leap.project_value(ValueProjectionRequest::best_exact_v1()),
            ValueProjectionResult::Failed(ValueProjectionFailure::UnrepresentableTimestamp { .. })
        ));
    }
}
