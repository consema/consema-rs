//! Immutable PortableGraph values.
//!
//! PortableGraph is independent from `PortableValue`: it preserves graph-local
//! identity, sharing, cycles, arbitrary mapping keys, duplicate associations,
//! and association order without adding references to the closed portable tree.

use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

mod pgce;

pub use pgce::{
    PGCE_MAGIC, PGCE_VERSION, PgceDecodeError, PgceEncodeError, PgceLimits, decode_pgce,
    encode_pgce, encode_pgce_bounded,
};

static NEXT_GRAPH: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GraphIdentity(u64);

/// Graph-local identity assigned by a [`GraphBuilder`].
///
/// IDs are valid only for the completed graph built by that builder. Their
/// numeric values are not part of strict graph equality or canonical encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GraphNodeId {
    graph: GraphIdentity,
    index: u64,
}

impl GraphNodeId {
    /// Builder-local numeric representation.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.index
    }

    fn index(self) -> Option<usize> {
        usize::try_from(self.index).ok()
    }
}

/// Stable node kind in PortableGraph@1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GraphNodeKind {
    /// Tagged canonical scalar content.
    Scalar,
    /// Ordered node references.
    Sequence,
    /// Ordered key/value graph associations.
    Mapping,
}

/// One ordered mapping association with arbitrary graph-node key and value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GraphMappingEntry {
    key: GraphNodeId,
    value: GraphNodeId,
}

impl GraphMappingEntry {
    /// Creates one key/value association.
    #[must_use]
    pub const fn new(key: GraphNodeId, value: GraphNodeId) -> Self {
        Self { key, value }
    }

    /// Key node.
    #[must_use]
    pub const fn key(self) -> GraphNodeId {
        self.key
    }

    /// Value node.
    #[must_use]
    pub const fn value(self) -> GraphNodeId {
        self.value
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum GraphNodeContent {
    Scalar(Arc<str>),
    Sequence(Arc<[GraphNodeId]>),
    Mapping(Arc<[GraphMappingEntry]>),
}

/// One immutable tagged graph node.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GraphNode {
    tag: Arc<str>,
    content: GraphNodeContent,
}

impl GraphNode {
    /// Resolved non-empty tag identifier.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Stable node kind.
    #[must_use]
    pub const fn kind(&self) -> GraphNodeKind {
        match self.content {
            GraphNodeContent::Scalar(_) => GraphNodeKind::Scalar,
            GraphNodeContent::Sequence(_) => GraphNodeKind::Sequence,
            GraphNodeContent::Mapping(_) => GraphNodeKind::Mapping,
        }
    }

    /// Canonical scalar content, when this is a scalar.
    #[must_use]
    pub fn scalar_content(&self) -> Option<&str> {
        match &self.content {
            GraphNodeContent::Scalar(content) => Some(content),
            GraphNodeContent::Sequence(_) | GraphNodeContent::Mapping(_) => None,
        }
    }

    /// Ordered item references, when this is a sequence.
    #[must_use]
    pub fn sequence_items(&self) -> Option<&[GraphNodeId]> {
        match &self.content {
            GraphNodeContent::Sequence(items) => Some(items),
            GraphNodeContent::Scalar(_) | GraphNodeContent::Mapping(_) => None,
        }
    }

    /// Ordered associations, when this is a mapping.
    #[must_use]
    pub fn mapping_entries(&self) -> Option<&[GraphMappingEntry]> {
        match &self.content {
            GraphNodeContent::Mapping(entries) => Some(entries),
            GraphNodeContent::Scalar(_) | GraphNodeContent::Sequence(_) => None,
        }
    }

    fn outgoing_reverse(&self, target: &mut Vec<GraphNodeId>) {
        match &self.content {
            GraphNodeContent::Scalar(_) => {}
            GraphNodeContent::Sequence(items) => target.extend(items.iter().rev().copied()),
            GraphNodeContent::Mapping(entries) => {
                for entry in entries.iter().rev() {
                    target.push(entry.value);
                    target.push(entry.key);
                }
            }
        }
    }
}

/// Resource bounds for graph construction and traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphLimits {
    /// Maximum ordered roots.
    pub max_roots: usize,
    /// Maximum graph nodes.
    pub max_nodes: usize,
    /// Maximum sequence-item plus mapping key/value edges.
    pub max_edges: usize,
    /// Maximum items or associations in one container.
    pub max_container_entries: usize,
    /// Maximum UTF-8 bytes in one tag identifier.
    pub max_tag_bytes: usize,
    /// Maximum UTF-8 bytes in one scalar's canonical content.
    pub max_scalar_bytes: usize,
    /// Maximum first-visit traversal depth.
    pub max_traversal_depth: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_roots: 1_000_000,
            max_nodes: 1_000_000,
            max_edges: 2_000_000,
            max_container_entries: 1_000_000,
            max_tag_bytes: 1024 * 1024,
            max_scalar_bytes: 64 * 1024 * 1024,
            max_traversal_depth: 256,
        }
    }
}

/// Stable graph construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphBuildError {
    /// A configured resource bound was exceeded.
    ResourceLimit {
        /// Stable limit name.
        name: &'static str,
        /// Observed amount.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A count or index exceeded the host representation.
    SizeOverflow,
    /// A graph-local node ID was not reserved by this builder.
    UnknownNode(GraphNodeId),
    /// A node ID belonged to a different builder or completed graph.
    WrongGraph,
    /// One reserved node was defined more than once.
    DuplicateDefinition(GraphNodeId),
    /// One reserved node had no definition at build time.
    UndefinedNode(GraphNodeId),
    /// A defined node was not reachable from any root.
    UnreachableNode(GraphNodeId),
    /// A tag was empty or contained ASCII control/whitespace.
    InvalidTag,
}

impl Display for GraphBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GraphBuildError {}

/// Mutable reservation/definition lifecycle for one immutable graph.
#[derive(Debug)]
pub struct GraphBuilder {
    identity: GraphIdentity,
    nodes: Vec<Option<GraphNode>>,
    roots: Vec<GraphNodeId>,
    edge_count: usize,
    limits: GraphLimits,
}

impl GraphBuilder {
    /// Creates an empty builder with explicit resource limits.
    #[must_use]
    pub fn new(limits: GraphLimits) -> Self {
        let identity = NEXT_GRAPH.fetch_add(1, Ordering::Relaxed);
        assert_ne!(identity, 0, "graph identity space exhausted");
        Self {
            identity: GraphIdentity(identity),
            nodes: Vec::new(),
            roots: Vec::new(),
            edge_count: 0,
            limits,
        }
    }

    /// Reserves one graph-local identity for later exact definition.
    pub fn reserve_node(&mut self) -> Result<GraphNodeId, GraphBuildError> {
        let observed = self
            .nodes
            .len()
            .checked_add(1)
            .ok_or(GraphBuildError::SizeOverflow)?;
        check_limit("graph-nodes", observed, self.limits.max_nodes)?;
        let id = GraphNodeId {
            graph: self.identity,
            index: u64::try_from(self.nodes.len()).map_err(|_| GraphBuildError::SizeOverflow)?,
        };
        self.nodes.push(None);
        Ok(id)
    }

    /// Appends one ordered graph root.
    pub fn push_root(&mut self, root: GraphNodeId) -> Result<&mut Self, GraphBuildError> {
        self.require_reserved(root)?;
        let observed = self
            .roots
            .len()
            .checked_add(1)
            .ok_or(GraphBuildError::SizeOverflow)?;
        check_limit("graph-roots", observed, self.limits.max_roots)?;
        self.roots.push(root);
        Ok(self)
    }

    /// Defines one reserved scalar node exactly once.
    pub fn define_scalar(
        &mut self,
        id: GraphNodeId,
        tag: impl Into<Arc<str>>,
        canonical_content: impl Into<Arc<str>>,
    ) -> Result<&mut Self, GraphBuildError> {
        let tag = tag.into();
        let canonical_content = canonical_content.into();
        validate_tag(&tag, self.limits)?;
        check_limit(
            "scalar-bytes",
            canonical_content.len(),
            self.limits.max_scalar_bytes,
        )?;
        self.define(
            id,
            GraphNode {
                tag,
                content: GraphNodeContent::Scalar(canonical_content),
            },
            0,
        )
    }

    /// Defines one reserved ordered sequence node exactly once.
    pub fn define_sequence(
        &mut self,
        id: GraphNodeId,
        tag: impl Into<Arc<str>>,
        items: Vec<GraphNodeId>,
    ) -> Result<&mut Self, GraphBuildError> {
        let tag = tag.into();
        validate_tag(&tag, self.limits)?;
        check_limit(
            "container-entries",
            items.len(),
            self.limits.max_container_entries,
        )?;
        for item in &items {
            self.require_reserved(*item)?;
        }
        let edges = items.len();
        self.define(
            id,
            GraphNode {
                tag,
                content: GraphNodeContent::Sequence(Arc::from(items)),
            },
            edges,
        )
    }

    /// Defines one reserved ordered mapping node exactly once.
    pub fn define_mapping(
        &mut self,
        id: GraphNodeId,
        tag: impl Into<Arc<str>>,
        entries: Vec<GraphMappingEntry>,
    ) -> Result<&mut Self, GraphBuildError> {
        let tag = tag.into();
        validate_tag(&tag, self.limits)?;
        check_limit(
            "container-entries",
            entries.len(),
            self.limits.max_container_entries,
        )?;
        for entry in &entries {
            self.require_reserved(entry.key)?;
            self.require_reserved(entry.value)?;
        }
        let edges = entries
            .len()
            .checked_mul(2)
            .ok_or(GraphBuildError::SizeOverflow)?;
        self.define(
            id,
            GraphNode {
                tag,
                content: GraphNodeContent::Mapping(Arc::from(entries)),
            },
            edges,
        )
    }

    fn define(
        &mut self,
        id: GraphNodeId,
        node: GraphNode,
        new_edges: usize,
    ) -> Result<&mut Self, GraphBuildError> {
        let index = self.require_reserved(id)?;
        if self.nodes[index].is_some() {
            return Err(GraphBuildError::DuplicateDefinition(id));
        }
        let edge_count = self
            .edge_count
            .checked_add(new_edges)
            .ok_or(GraphBuildError::SizeOverflow)?;
        check_limit("graph-edges", edge_count, self.limits.max_edges)?;
        self.nodes[index] = Some(node);
        self.edge_count = edge_count;
        Ok(self)
    }

    fn require_reserved(&self, id: GraphNodeId) -> Result<usize, GraphBuildError> {
        if id.graph != self.identity {
            return Err(GraphBuildError::WrongGraph);
        }
        id.index()
            .filter(|index| *index < self.nodes.len())
            .ok_or(GraphBuildError::UnknownNode(id))
    }

    /// Validates definitions, reachability and traversal depth, then freezes the graph.
    pub fn build(self) -> Result<PortableGraph, GraphBuildError> {
        let nodes = self
            .nodes
            .into_iter()
            .enumerate()
            .map(|(index, node)| {
                node.ok_or_else(|| {
                    GraphBuildError::UndefinedNode(GraphNodeId {
                        graph: self.identity,
                        index: u64::try_from(index).expect("reserved graph index fits u64"),
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let order = canonical_order(&nodes, &self.roots, Some(self.limits.max_traversal_depth))?;
        if order.len() != nodes.len() {
            let reachable: HashSet<_> = order.into_iter().collect();
            let index = (0..nodes.len())
                .find(|index| !reachable.contains(index))
                .expect("different counts imply an unreachable node");
            return Err(GraphBuildError::UnreachableNode(GraphNodeId {
                graph: self.identity,
                index: u64::try_from(index).expect("reserved graph index fits u64"),
            }));
        }
        Ok(PortableGraph {
            identity: self.identity,
            roots: Arc::from(self.roots),
            nodes: Arc::from(nodes),
            edge_count: self.edge_count,
        })
    }
}

fn validate_tag(tag: &str, limits: GraphLimits) -> Result<(), GraphBuildError> {
    if tag.is_empty()
        || tag
            .chars()
            .any(|character| character.is_ascii_control() || character.is_ascii_whitespace())
    {
        return Err(GraphBuildError::InvalidTag);
    }
    check_limit("tag-bytes", tag.len(), limits.max_tag_bytes)
}

fn check_limit(name: &'static str, observed: usize, limit: usize) -> Result<(), GraphBuildError> {
    if observed > limit {
        Err(GraphBuildError::ResourceLimit {
            name,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

/// Immutable rooted, directed, ordered, tagged graph value.
#[derive(Clone, Debug)]
pub struct PortableGraph {
    identity: GraphIdentity,
    roots: Arc<[GraphNodeId]>,
    nodes: Arc<[GraphNode]>,
    edge_count: usize,
}

impl PortableGraph {
    /// Ordered roots. An empty slice represents an empty root stream.
    #[must_use]
    pub fn roots(&self) -> &[GraphNodeId] {
        &self.roots
    }

    /// Number of reachable graph nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of sequence-item plus mapping key/value edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// Resolves one graph-local node ID.
    #[must_use]
    pub fn node(&self, id: GraphNodeId) -> Option<&GraphNode> {
        if id.graph != self.identity {
            return None;
        }
        id.index().and_then(|index| self.nodes.get(index))
    }

    /// Iterates builder-local IDs and nodes. Numeric ID order is not value semantics.
    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (GraphNodeId, &GraphNode)> {
        self.nodes.iter().enumerate().map(|(index, node)| {
            (
                GraphNodeId {
                    graph: self.identity,
                    index: u64::try_from(index).expect("graph index fits u64"),
                },
                node,
            )
        })
    }

    pub(crate) fn canonical_layout(&self) -> CanonicalLayout {
        let order = canonical_order(&self.nodes, &self.roots, None)
            .expect("completed graphs have valid traversal");
        let mut canonical_ids = vec![0_u64; self.nodes.len()];
        for (canonical, original) in order.iter().copied().enumerate() {
            canonical_ids[original] =
                u64::try_from(canonical).expect("graph index fits canonical u64");
        }
        CanonicalLayout {
            order,
            canonical_ids,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalLayout {
    pub(crate) order: Vec<usize>,
    pub(crate) canonical_ids: Vec<u64>,
}

fn canonical_order(
    nodes: &[GraphNode],
    roots: &[GraphNodeId],
    max_depth: Option<usize>,
) -> Result<Vec<usize>, GraphBuildError> {
    let mut order = Vec::with_capacity(nodes.len());
    let mut visited = vec![false; nodes.len()];
    let mut stack = Vec::new();
    for root in roots.iter().rev() {
        let index = root.index().ok_or(GraphBuildError::SizeOverflow)?;
        stack.push((index, 0_usize));
    }
    while let Some((index, depth)) = stack.pop() {
        if visited[index] {
            continue;
        }
        if max_depth.is_some_and(|limit| depth > limit) {
            return Err(GraphBuildError::ResourceLimit {
                name: "traversal-depth",
                observed: depth,
                limit: max_depth.expect("checked Some"),
            });
        }
        visited[index] = true;
        order.push(index);
        let mut outgoing = Vec::new();
        nodes[index].outgoing_reverse(&mut outgoing);
        let child_depth = depth.checked_add(1).ok_or(GraphBuildError::SizeOverflow)?;
        stack.extend(outgoing.into_iter().map(|id| {
            (
                id.index().expect("completed graph IDs fit usize"),
                child_depth,
            )
        }));
    }
    Ok(order)
}

impl PartialEq for PortableGraph {
    fn eq(&self, other: &Self) -> bool {
        if self.roots.len() != other.roots.len()
            || self.nodes.len() != other.nodes.len()
            || self.edge_count != other.edge_count
        {
            return false;
        }
        let left = self.canonical_layout();
        let right = other.canonical_layout();
        if self
            .roots
            .iter()
            .zip(other.roots.iter())
            .any(|(left_root, right_root)| {
                canonical_id(&left, *left_root) != canonical_id(&right, *right_root)
            })
        {
            return false;
        }
        left.order
            .iter()
            .zip(right.order.iter())
            .all(|(left_index, right_index)| {
                canonical_node_eq(
                    &self.nodes[*left_index],
                    &left,
                    &other.nodes[*right_index],
                    &right,
                )
            })
    }
}

impl Eq for PortableGraph {}

impl Hash for PortableGraph {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let layout = self.canonical_layout();
        self.roots.len().hash(state);
        for root in self.roots.iter().copied() {
            canonical_id(&layout, root).hash(state);
        }
        self.nodes.len().hash(state);
        for index in layout.order.iter().copied() {
            hash_canonical_node(&self.nodes[index], &layout, state);
        }
    }
}

fn canonical_id(layout: &CanonicalLayout, id: GraphNodeId) -> u64 {
    layout.canonical_ids[id.index().expect("completed graph ID fits usize")]
}

fn canonical_node_eq(
    left: &GraphNode,
    left_layout: &CanonicalLayout,
    right: &GraphNode,
    right_layout: &CanonicalLayout,
) -> bool {
    if left.tag != right.tag {
        return false;
    }
    match (&left.content, &right.content) {
        (GraphNodeContent::Scalar(left), GraphNodeContent::Scalar(right)) => left == right,
        (GraphNodeContent::Sequence(left), GraphNodeContent::Sequence(right)) => {
            left.len() == right.len()
                && left.iter().zip(right.iter()).all(|(left, right)| {
                    canonical_id(left_layout, *left) == canonical_id(right_layout, *right)
                })
        }
        (GraphNodeContent::Mapping(left), GraphNodeContent::Mapping(right)) => {
            left.len() == right.len()
                && left.iter().zip(right.iter()).all(|(left, right)| {
                    canonical_id(left_layout, left.key) == canonical_id(right_layout, right.key)
                        && canonical_id(left_layout, left.value)
                            == canonical_id(right_layout, right.value)
                })
        }
        _ => false,
    }
}

fn hash_canonical_node<H: Hasher>(node: &GraphNode, layout: &CanonicalLayout, state: &mut H) {
    node.tag.hash(state);
    node.kind().hash(state);
    match &node.content {
        GraphNodeContent::Scalar(content) => content.hash(state),
        GraphNodeContent::Sequence(items) => {
            items.len().hash(state);
            for item in items.iter().copied() {
                canonical_id(layout, item).hash(state);
            }
        }
        GraphNodeContent::Mapping(entries) => {
            entries.len().hash(state);
            for entry in entries.iter().copied() {
                canonical_id(layout, entry.key).hash(state);
                canonical_id(layout, entry.value).hash(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    const STR: &str = "tag:yaml.org,2002:str";
    const SEQ: &str = "tag:yaml.org,2002:seq";
    const MAP: &str = "tag:yaml.org,2002:map";

    fn graph_hash(graph: &PortableGraph) -> u64 {
        let mut hasher = DefaultHasher::new();
        graph.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn scalar_graph_is_immutable_and_inspectable() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        builder
            .define_scalar(root, STR, "catalog")
            .unwrap()
            .push_root(root)
            .unwrap();
        let graph = builder.build().unwrap();
        assert_eq!(graph.roots(), &[root]);
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.node(root).unwrap().kind(), GraphNodeKind::Scalar);
        assert_eq!(graph.node(root).unwrap().tag(), STR);
        assert_eq!(graph.node(root).unwrap().scalar_content(), Some("catalog"));
    }

    #[test]
    fn sharing_cycles_and_duplicate_arbitrary_keys_are_values() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let mapping = builder.reserve_node().unwrap();
        let key = builder.reserve_node().unwrap();
        let sequence = builder.reserve_node().unwrap();
        builder.define_scalar(key, STR, "self").unwrap();
        builder
            .define_sequence(sequence, SEQ, vec![mapping, key, key])
            .unwrap();
        builder
            .define_mapping(
                mapping,
                MAP,
                vec![
                    GraphMappingEntry::new(key, sequence),
                    GraphMappingEntry::new(key, mapping),
                ],
            )
            .unwrap()
            .push_root(mapping)
            .unwrap();
        let graph = builder.build().unwrap();
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 7);
        assert_eq!(
            graph.node(mapping).unwrap().mapping_entries().unwrap()[1].value(),
            mapping
        );
    }

    #[test]
    fn strict_equality_ignores_builder_ids_but_preserves_topology() {
        let mut first = GraphBuilder::new(GraphLimits::default());
        let first_root = first.reserve_node().unwrap();
        let first_shared = first.reserve_node().unwrap();
        first.define_scalar(first_shared, STR, "x").unwrap();
        first
            .define_sequence(first_root, SEQ, vec![first_shared, first_shared])
            .unwrap()
            .push_root(first_root)
            .unwrap();
        let first = first.build().unwrap();

        let mut second = GraphBuilder::new(GraphLimits::default());
        let second_shared = second.reserve_node().unwrap();
        let second_root = second.reserve_node().unwrap();
        second.define_scalar(second_shared, STR, "x").unwrap();
        second
            .define_sequence(second_root, SEQ, vec![second_shared, second_shared])
            .unwrap()
            .push_root(second_root)
            .unwrap();
        let second = second.build().unwrap();

        let mut duplicated = GraphBuilder::new(GraphLimits::default());
        let duplicated_root = duplicated.reserve_node().unwrap();
        let left = duplicated.reserve_node().unwrap();
        let right = duplicated.reserve_node().unwrap();
        duplicated.define_scalar(left, STR, "x").unwrap();
        duplicated.define_scalar(right, STR, "x").unwrap();
        duplicated
            .define_sequence(duplicated_root, SEQ, vec![left, right])
            .unwrap()
            .push_root(duplicated_root)
            .unwrap();
        let duplicated = duplicated.build().unwrap();

        assert_eq!(first, second);
        assert_eq!(graph_hash(&first), graph_hash(&second));
        assert_ne!(first, duplicated);
    }

    #[test]
    fn root_and_association_order_are_strict() {
        let make = |reverse: bool| {
            let mut builder = GraphBuilder::new(GraphLimits::default());
            let mapping = builder.reserve_node().unwrap();
            let a = builder.reserve_node().unwrap();
            let b = builder.reserve_node().unwrap();
            builder.define_scalar(a, STR, "a").unwrap();
            builder.define_scalar(b, STR, "b").unwrap();
            let entries = if reverse {
                vec![GraphMappingEntry::new(b, a), GraphMappingEntry::new(a, b)]
            } else {
                vec![GraphMappingEntry::new(a, b), GraphMappingEntry::new(b, a)]
            };
            builder
                .define_mapping(mapping, MAP, entries)
                .unwrap()
                .push_root(mapping)
                .unwrap();
            builder.build().unwrap()
        };
        assert_ne!(make(false), make(true));
    }

    #[test]
    fn builder_rejects_incomplete_unreachable_duplicate_and_invalid_tag() {
        let mut incomplete = GraphBuilder::new(GraphLimits::default());
        let missing = incomplete.reserve_node().unwrap();
        incomplete.push_root(missing).unwrap();
        assert_eq!(
            incomplete.build().unwrap_err(),
            GraphBuildError::UndefinedNode(missing)
        );

        let mut unreachable = GraphBuilder::new(GraphLimits::default());
        let root = unreachable.reserve_node().unwrap();
        let hidden = unreachable.reserve_node().unwrap();
        unreachable.define_scalar(root, STR, "root").unwrap();
        unreachable.define_scalar(hidden, STR, "hidden").unwrap();
        unreachable.push_root(root).unwrap();
        assert_eq!(
            unreachable.build().unwrap_err(),
            GraphBuildError::UnreachableNode(hidden)
        );

        let mut duplicate = GraphBuilder::new(GraphLimits::default());
        let node = duplicate.reserve_node().unwrap();
        duplicate.define_scalar(node, STR, "x").unwrap();
        assert_eq!(
            duplicate.define_scalar(node, STR, "y").unwrap_err(),
            GraphBuildError::DuplicateDefinition(node)
        );

        let mut invalid = GraphBuilder::new(GraphLimits::default());
        let node = invalid.reserve_node().unwrap();
        assert_eq!(
            invalid.define_scalar(node, "bad tag", "x").unwrap_err(),
            GraphBuildError::InvalidTag
        );

        let mut first = GraphBuilder::new(GraphLimits::default());
        let foreign = first.reserve_node().unwrap();
        let mut second = GraphBuilder::new(GraphLimits::default());
        assert_eq!(
            second.push_root(foreign).unwrap_err(),
            GraphBuildError::WrongGraph
        );
    }

    #[test]
    fn limits_fail_before_a_graph_exists() {
        let limits = GraphLimits {
            max_nodes: 2,
            max_edges: 1,
            max_traversal_depth: 0,
            ..GraphLimits::default()
        };
        let mut builder = GraphBuilder::new(limits);
        let root = builder.reserve_node().unwrap();
        let child = builder.reserve_node().unwrap();
        assert!(matches!(
            builder.reserve_node(),
            Err(GraphBuildError::ResourceLimit {
                name: "graph-nodes",
                ..
            })
        ));
        builder.define_scalar(child, STR, "x").unwrap();
        builder
            .define_sequence(root, SEQ, vec![child])
            .unwrap()
            .push_root(root)
            .unwrap();
        assert!(matches!(
            builder.build(),
            Err(GraphBuildError::ResourceLimit {
                name: "traversal-depth",
                ..
            })
        ));
    }
}
