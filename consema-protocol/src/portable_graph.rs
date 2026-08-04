//! Canonical readable plus PGCE/1 PortableGraph protocol payload.

use std::collections::HashMap;

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u64,
};
use crate::{ProtocolError, ProtocolErrorKind};
use consema_core::{PortableValue, SequenceBuilder};
use consema_graph::{
    GraphBuildError, GraphBuilder, GraphLimits, GraphMappingEntry, GraphNodeId, GraphNodeKind,
    PgceDecodeError, PgceEncodeError, PgceLimits, PortableGraph, decode_pgce, encode_pgce_bounded,
};

/// Validated `core.portable-graph@1` readable graph and exact PGCE/1 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableGraphMessage {
    graph: PortableGraph,
    pgce: Vec<u8>,
}

impl PortableGraphMessage {
    /// Canonically encodes one complete graph under explicit PGCE limits.
    pub fn from_graph(graph: PortableGraph, limits: PgceLimits) -> Result<Self, ProtocolError> {
        let pgce = encode_pgce_bounded(&graph, limits).map_err(encode_error)?;
        Ok(Self { graph, pgce })
    }

    /// Complete immutable graph.
    #[must_use]
    pub const fn graph(&self) -> &PortableGraph {
        &self.graph
    }

    /// Exact canonical PGCE/1 bytes.
    #[must_use]
    pub fn pgce(&self) -> &[u8] {
        &self.pgce
    }

    /// Encodes the fixed readable graph plus PGCE schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let layout = canonical_layout(&self.graph);
        let mut roots = SequenceBuilder::new();
        for root in self.graph.roots() {
            roots.push(integer_u64(layout.ids[root]));
        }
        let mut nodes = SequenceBuilder::new();
        for (id, node_id) in layout.order.iter().copied().enumerate() {
            let node = self
                .graph
                .node(node_id)
                .expect("completed graph IDs resolve");
            let id = u64::try_from(id).expect("graph node count fits u64");
            nodes.push(match node.kind() {
                GraphNodeKind::Scalar => object(vec![
                    ("id", integer_u64(id)),
                    ("kind", PortableValue::string("Scalar")),
                    ("tag", PortableValue::string(node.tag())),
                    (
                        "canonical_content",
                        PortableValue::string(
                            node.scalar_content().expect("scalar kind has content"),
                        ),
                    ),
                ]),
                GraphNodeKind::Sequence => {
                    let mut items = SequenceBuilder::new();
                    for item in node.sequence_items().expect("sequence kind has items") {
                        items.push(integer_u64(layout.ids[item]));
                    }
                    object(vec![
                        ("id", integer_u64(id)),
                        ("kind", PortableValue::string("Sequence")),
                        ("tag", PortableValue::string(node.tag())),
                        ("items", items.build()),
                    ])
                }
                GraphNodeKind::Mapping => {
                    let mut entries = SequenceBuilder::new();
                    for entry in node.mapping_entries().expect("mapping kind has entries") {
                        entries.push(object(vec![
                            ("key", integer_u64(layout.ids[&entry.key()])),
                            ("value", integer_u64(layout.ids[&entry.value()])),
                        ]));
                    }
                    object(vec![
                        ("id", integer_u64(id)),
                        ("kind", PortableValue::string("Mapping")),
                        ("tag", PortableValue::string(node.tag())),
                        ("entries", entries.build()),
                    ])
                }
            });
        }
        object(vec![
            ("schema", PortableValue::string("core.portable-graph@1")),
            ("encoding", PortableValue::string("PGCE/1")),
            ("roots", roots.build()),
            ("nodes", nodes.build()),
            ("pgce", PortableValue::bytes(self.pgce.as_slice())),
        ])
    }

    /// Strictly decodes and cross-validates readable graph and PGCE/1 forms.
    pub fn from_value(value: &PortableValue, limits: PgceLimits) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.portable-graph@1",
            &["schema", "encoding", "roots", "nodes", "pgce"],
            "$",
        )?;
        if string(fields[1], "$.encoding")? != "PGCE/1" {
            return Err(invalid("$.encoding", "expected PGCE/1"));
        }
        let root_values = sequence(fields[2], "$.roots")?;
        let node_values = sequence(fields[3], "$.nodes")?;
        check_count("$.roots", root_values.len(), limits.max_roots)?;
        check_count("$.nodes", node_values.len(), limits.max_nodes)?;
        let pgce = fields[4]
            .as_bytes()
            .ok_or_else(|| wrong_type("$.pgce", "expected Bytes"))?;
        check_count("$.pgce", pgce.len(), limits.max_stream_bytes)?;

        let graph_limits = GraphLimits {
            max_roots: limits.max_roots,
            max_nodes: limits.max_nodes,
            max_edges: limits.max_edges,
            max_container_entries: limits.max_container_entries,
            max_tag_bytes: limits.max_tag_bytes,
            max_scalar_bytes: limits.max_scalar_bytes,
            max_traversal_depth: limits.max_traversal_depth,
        };
        let mut builder = GraphBuilder::new(graph_limits);
        let mut ids = Vec::new();
        ids.try_reserve_exact(node_values.len())
            .map_err(|_| resource("$.nodes", "node allocation"))?;
        for _ in node_values {
            ids.push(builder.reserve_node().map_err(build_error)?);
        }

        for (index, record) in node_values.iter().enumerate() {
            define_record(&mut builder, &ids, index, record, limits)?;
        }
        for (index, root) in root_values.iter().enumerate() {
            let canonical = unsigned_u64(root, &format!("$.roots[{index}]"))?;
            let root = resolve_id(&ids, canonical, &format!("$.roots[{index}]"))?;
            builder.push_root(root).map_err(build_error)?;
        }
        let graph = builder.build().map_err(build_error)?;
        if canonical_layout(&graph).order != ids {
            return Err(invalid(
                "$.nodes",
                "node records are not in canonical first-discovery order",
            ));
        }
        let decoded = decode_pgce(pgce, limits).map_err(decode_error)?;
        if graph != decoded {
            return Err(invalid(
                "$",
                "readable graph and PGCE graph are not strictly equal",
            ));
        }
        let canonical = encode_pgce_bounded(&graph, limits).map_err(encode_error)?;
        if canonical.as_slice() != pgce {
            return Err(invalid("$.pgce", "PGCE bytes disagree with readable graph"));
        }
        Ok(Self {
            graph,
            pgce: canonical,
        })
    }

    /// Resolves a graph-local handle to its stable canonical wire ID.
    #[must_use]
    pub fn canonical_node_id(&self, node: GraphNodeId) -> Option<u64> {
        canonical_layout(&self.graph).ids.get(&node).copied()
    }

    /// Resolves a canonical wire ID to this message's graph-local handle.
    #[must_use]
    pub fn graph_node_id(&self, canonical: u64) -> Option<GraphNodeId> {
        usize::try_from(canonical)
            .ok()
            .and_then(|index| canonical_layout(&self.graph).order.get(index).copied())
    }

    pub(crate) fn wire_layout(&self) -> CanonicalLayout {
        canonical_layout(&self.graph)
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalLayout {
    pub(crate) order: Vec<GraphNodeId>,
    pub(crate) ids: HashMap<GraphNodeId, u64>,
}

fn canonical_layout(graph: &PortableGraph) -> CanonicalLayout {
    let mut order = Vec::with_capacity(graph.node_count());
    let mut ids = HashMap::with_capacity(graph.node_count());
    let mut stack = graph.roots().iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = stack.pop() {
        if ids.contains_key(&id) {
            continue;
        }
        let canonical = u64::try_from(order.len()).expect("graph node count fits u64");
        ids.insert(id, canonical);
        order.push(id);
        let node = graph.node(id).expect("completed graph IDs resolve");
        match node.kind() {
            GraphNodeKind::Scalar => {}
            GraphNodeKind::Sequence => {
                stack.extend(
                    node.sequence_items()
                        .expect("sequence kind has items")
                        .iter()
                        .rev()
                        .copied(),
                );
            }
            GraphNodeKind::Mapping => {
                for entry in node
                    .mapping_entries()
                    .expect("mapping kind has entries")
                    .iter()
                    .rev()
                {
                    stack.push(entry.value());
                    stack.push(entry.key());
                }
            }
        }
    }
    debug_assert_eq!(order.len(), graph.node_count());
    CanonicalLayout { order, ids }
}

fn define_record(
    builder: &mut GraphBuilder,
    ids: &[GraphNodeId],
    index: usize,
    value: &PortableValue,
    limits: PgceLimits,
) -> Result<(), ProtocolError> {
    let path = format!("$.nodes[{index}]");
    let entries = value
        .as_object()
        .ok_or_else(|| wrong_type(&path, "expected graph node Object"))?;
    let kind = entries
        .get(1)
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| invalid(&path, "kind must be the second String field"))?;
    match kind {
        "Scalar" => {
            let fields = exact_fields(value, &["id", "kind", "tag", "canonical_content"], &path)?;
            validate_record_id(fields[0], index, &path)?;
            builder
                .define_scalar(
                    ids[index],
                    string(fields[2], &format!("{path}.tag"))?,
                    string(fields[3], &format!("{path}.canonical_content"))?,
                )
                .map_err(build_error)?;
        }
        "Sequence" => {
            let fields = exact_fields(value, &["id", "kind", "tag", "items"], &path)?;
            validate_record_id(fields[0], index, &path)?;
            let values = sequence(fields[3], &format!("{path}.items"))?;
            check_count(
                &format!("{path}.items"),
                values.len(),
                limits.max_container_entries,
            )?;
            let mut items = Vec::new();
            items
                .try_reserve_exact(values.len())
                .map_err(|_| resource(format!("{path}.items"), "item allocation"))?;
            for (ordinal, value) in values.iter().enumerate() {
                let item_path = format!("{path}.items[{ordinal}]");
                items.push(resolve_id(
                    ids,
                    unsigned_u64(value, &item_path)?,
                    &item_path,
                )?);
            }
            builder
                .define_sequence(
                    ids[index],
                    string(fields[2], &format!("{path}.tag"))?,
                    items,
                )
                .map_err(build_error)?;
        }
        "Mapping" => {
            let fields = exact_fields(value, &["id", "kind", "tag", "entries"], &path)?;
            validate_record_id(fields[0], index, &path)?;
            let values = sequence(fields[3], &format!("{path}.entries"))?;
            check_count(
                &format!("{path}.entries"),
                values.len(),
                limits.max_container_entries,
            )?;
            let mut associations = Vec::new();
            associations
                .try_reserve_exact(values.len())
                .map_err(|_| resource(format!("{path}.entries"), "entry allocation"))?;
            for (ordinal, entry) in values.iter().enumerate() {
                let entry_path = format!("{path}.entries[{ordinal}]");
                let fields = exact_fields(entry, &["key", "value"], &entry_path)?;
                let key_path = format!("{entry_path}.key");
                let value_path = format!("{entry_path}.value");
                associations.push(GraphMappingEntry::new(
                    resolve_id(ids, unsigned_u64(fields[0], &key_path)?, &key_path)?,
                    resolve_id(ids, unsigned_u64(fields[1], &value_path)?, &value_path)?,
                ));
            }
            builder
                .define_mapping(
                    ids[index],
                    string(fields[2], &format!("{path}.tag"))?,
                    associations,
                )
                .map_err(build_error)?;
        }
        _ => return Err(invalid(format!("{path}.kind"), "unknown graph node kind")),
    }
    Ok(())
}

fn validate_record_id(
    value: &PortableValue,
    index: usize,
    path: &str,
) -> Result<(), ProtocolError> {
    let observed = unsigned_u64(value, &format!("{path}.id"))?;
    let expected = u64::try_from(index).map_err(|_| resource(path, "node ID"))?;
    if observed == expected {
        Ok(())
    } else {
        Err(invalid(
            format!("{path}.id"),
            "node ID must equal its canonical array index",
        ))
    }
}

fn resolve_id(ids: &[GraphNodeId], value: u64, path: &str) -> Result<GraphNodeId, ProtocolError> {
    usize::try_from(value)
        .ok()
        .and_then(|index| ids.get(index).copied())
        .ok_or_else(|| invalid(path, "canonical node ID is out of range"))
}

fn check_count(path: &str, observed: usize, limit: usize) -> Result<(), ProtocolError> {
    if observed > limit {
        Err(resource(path, format!("count {observed} exceeds {limit}")))
    } else {
        Ok(())
    }
}

fn build_error(error: GraphBuildError) -> ProtocolError {
    match error {
        GraphBuildError::ResourceLimit { .. } | GraphBuildError::SizeOverflow => {
            resource("$", format!("graph construction: {error:?}"))
        }
        _ => invalid("$", format!("invalid graph: {error:?}")),
    }
}

fn encode_error(error: PgceEncodeError) -> ProtocolError {
    resource("$.pgce", format!("PGCE encoding failed: {error:?}"))
}

fn decode_error(error: PgceDecodeError) -> ProtocolError {
    match error {
        PgceDecodeError::ResourceLimit { .. } | PgceDecodeError::VarintOverflow => {
            resource("$.pgce", format!("PGCE decoding failed: {error:?}"))
        }
        _ => invalid("$.pgce", format!("invalid PGCE: {error:?}")),
    }
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, message)
}

fn wrong_type(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::WrongType, path, message)
}

fn resource(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::ResourceLimit, path, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STR: &str = "tag:yaml.org,2002:str";
    const SEQ: &str = "tag:yaml.org,2002:seq";
    const MAP: &str = "tag:yaml.org,2002:map";

    fn topology() -> PortableGraph {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let shared = builder.reserve_node().unwrap();
        let mapping = builder.reserve_node().unwrap();
        let sequence = builder.reserve_node().unwrap();
        builder.define_scalar(shared, STR, "key").unwrap();
        builder
            .define_mapping(
                mapping,
                MAP,
                vec![
                    GraphMappingEntry::new(shared, sequence),
                    GraphMappingEntry::new(shared, mapping),
                ],
            )
            .unwrap();
        builder
            .define_sequence(sequence, SEQ, vec![shared, mapping])
            .unwrap();
        builder
            .push_root(mapping)
            .unwrap()
            .push_root(sequence)
            .unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn readable_graph_and_pgce_round_trip_shared_cyclic_topology() {
        let message = PortableGraphMessage::from_graph(topology(), PgceLimits::default()).unwrap();
        let decoded =
            PortableGraphMessage::from_value(&message.to_value(), PgceLimits::default()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(
            decoded.pgce(),
            encode_pgce_bounded(decoded.graph(), PgceLimits::default()).unwrap()
        );
    }

    #[test]
    fn builder_numbering_is_replaced_by_canonical_ids() {
        let message = PortableGraphMessage::from_graph(topology(), PgceLimits::default()).unwrap();
        let value = message.to_value();
        let fields = schema_fields(
            &value,
            "core.portable-graph@1",
            &["schema", "encoding", "roots", "nodes", "pgce"],
            "$",
        )
        .unwrap();
        let nodes = sequence(fields[3], "$.nodes").unwrap();
        for (index, node) in nodes.iter().enumerate() {
            let id = node.as_object().unwrap()[0].value();
            assert_eq!(id.as_integer().unwrap().to_usize(), Some(index));
        }
        assert_eq!(
            PortableGraphMessage::from_value(&value, PgceLimits::default())
                .unwrap()
                .graph(),
            message.graph()
        );
    }

    #[test]
    fn readable_and_pgce_disagreement_is_rejected() {
        let message = PortableGraphMessage::from_graph(topology(), PgceLimits::default()).unwrap();
        let value = message.to_value();
        let fields = schema_fields(
            &value,
            "core.portable-graph@1",
            &["schema", "encoding", "roots", "nodes", "pgce"],
            "$",
        )
        .unwrap();
        let changed = object(vec![
            ("schema", fields[0].clone()),
            ("encoding", fields[1].clone()),
            (
                "roots",
                PortableValue::sequence(Vec::<PortableValue>::new()),
            ),
            ("nodes", fields[3].clone()),
            ("pgce", fields[4].clone()),
        ]);
        assert_eq!(
            PortableGraphMessage::from_value(&changed, PgceLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::InvalidValue
        );
    }

    #[test]
    fn explicit_limits_apply_before_graph_allocation() {
        let message = PortableGraphMessage::from_graph(topology(), PgceLimits::default()).unwrap();
        let limits = PgceLimits {
            max_nodes: 1,
            ..PgceLimits::default()
        };
        assert_eq!(
            PortableGraphMessage::from_value(&message.to_value(), limits)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ResourceLimit
        );
    }
}
