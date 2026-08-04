//! Self-contained PortableGraph query-result protocol.

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32, unsigned_u64,
};
use crate::{
    Completion, CompletionStatus, DiagnosticMessage, ErrorCodeRegistry, PortableGraphMessage,
    ProtocolError, ProtocolErrorKind,
};
use consema_core::{
    BigInteger, MatchRole, PortableValue, QueryDomain, QueryExecution, SequenceBuilder,
};
use consema_graph::{GraphMatch, PgceLimits, PortableGraph};

/// One graph match expressed only with canonical wire node IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphQueryMatchMessage {
    /// One graph node.
    Node {
        /// Canonical node ID.
        node: u64,
    },
    /// One direct sequence association.
    SequenceElement {
        /// Canonical parent sequence ID.
        parent: u64,
        /// Zero-based association ordinal.
        ordinal: u64,
        /// Canonical child node ID.
        node: u64,
    },
    /// One direct mapping association.
    MappingEntry {
        /// Canonical parent mapping ID.
        parent: u64,
        /// Zero-based association ordinal.
        ordinal: u64,
        /// Canonical key node ID.
        key: u64,
        /// Canonical value node ID.
        value: u64,
    },
}

impl GraphQueryMatchMessage {
    const fn role(self) -> MatchRole {
        match self {
            Self::Node { .. } => MatchRole::GraphNode,
            Self::SequenceElement { .. } => MatchRole::GraphSequenceElement,
            Self::MappingEntry { .. } => MatchRole::GraphMappingEntry,
        }
    }
}

/// Complete or explicitly non-complete `core.graph-query-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphQueryResultMessage {
    domain: QueryDomain,
    role: MatchRole,
    graph: PortableGraphMessage,
    matches: Vec<GraphQueryMatchMessage>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

impl GraphQueryResultMessage {
    /// Validates graph binding, uniform match roles, associations, and counts.
    pub fn new(
        domain: QueryDomain,
        role: MatchRole,
        graph: PortableGraphMessage,
        matches: Vec<GraphQueryMatchMessage>,
        completion: Completion,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        if domain != QueryDomain::portable_graph_v1() || !is_graph_role(role) {
            return Err(invalid(
                "$",
                "graph result requires core.portable-graph-query@1 and a graph role",
            ));
        }
        let produced = u64::try_from(matches.len())
            .map_err(|_| resource("$.matches", "match count exceeds protocol range"))?;
        if completion.produced() != produced || matches.iter().any(|item| item.role() != role) {
            return Err(invalid(
                "$",
                "completion count or graph match role is inconsistent",
            ));
        }
        validate_matches(&graph, &matches)?;
        Ok(Self {
            domain,
            role,
            graph,
            matches,
            completion,
            diagnostics,
        })
    }

    /// Converts one completed in-process graph query to canonical wire IDs.
    pub fn from_execution(
        graph: &PortableGraph,
        role: MatchRole,
        execution: &QueryExecution<GraphMatch>,
        limits: PgceLimits,
    ) -> Result<Self, ProtocolError> {
        let graph = PortableGraphMessage::from_graph(graph.clone(), limits)?;
        let layout = graph.wire_layout();
        let mut matches = Vec::new();
        matches
            .try_reserve_exact(execution.matches().len())
            .map_err(|_| resource("$.matches", "match allocation"))?;
        for item in execution.matches() {
            matches.push(match item {
                GraphMatch::Node { node } => GraphQueryMatchMessage::Node {
                    node: layout.ids[node],
                },
                GraphMatch::SequenceElement {
                    parent,
                    ordinal,
                    node,
                } => GraphQueryMatchMessage::SequenceElement {
                    parent: layout.ids[parent],
                    ordinal: *ordinal,
                    node: layout.ids[node],
                },
                GraphMatch::MappingEntry {
                    parent,
                    ordinal,
                    key,
                    value,
                } => GraphQueryMatchMessage::MappingEntry {
                    parent: layout.ids[parent],
                    ordinal: *ordinal,
                    key: layout.ids[key],
                    value: layout.ids[value],
                },
            });
        }
        let count = u64::try_from(matches.len())
            .map_err(|_| resource("$.matches", "match count exceeds protocol range"))?;
        Self::new(
            QueryDomain::portable_graph_v1(),
            role,
            graph,
            matches,
            Completion::new(CompletionStatus::Success, count, count, None, None)?,
            Vec::new(),
        )
    }

    /// Exact query domain.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Uniform result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Complete graph that gives every canonical ID meaning.
    #[must_use]
    pub const fn graph(&self) -> &PortableGraphMessage {
        &self.graph
    }

    /// Ordered graph matches.
    #[must_use]
    pub fn matches(&self) -> &[GraphQueryMatchMessage] {
        &self.matches
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.graph-query-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut matches = SequenceBuilder::new();
        for item in &self.matches {
            matches.push(match_value(*item));
        }
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.graph-query-result@1")),
            ("domain_id", PortableValue::string(self.domain.id())),
            (
                "domain_version",
                PortableValue::integer(BigInteger::from(i64::from(self.domain.version()))),
            ),
            ("role", PortableValue::string(role_name(self.role))),
            ("graph", self.graph.to_value()),
            ("matches", matches.build()),
            ("completion", self.completion.to_value()),
            ("diagnostics", diagnostics.build()),
        ])
    }

    /// Strictly decodes with default PGCE limits.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, PgceLimits::default(), ErrorCodeRegistry::v1())
    }

    /// Strictly decodes with explicit PGCE limits.
    pub fn from_value_with_limits(
        value: &PortableValue,
        limits: PgceLimits,
    ) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, limits, ErrorCodeRegistry::v1())
    }

    /// Strictly decodes with explicit graph limits and semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        limits: PgceLimits,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.graph-query-result@1",
            &[
                "schema",
                "domain_id",
                "domain_version",
                "role",
                "graph",
                "matches",
                "completion",
                "diagnostics",
            ],
            "$",
        )?;
        let matches = sequence(fields[5], "$.matches")?
            .iter()
            .enumerate()
            .map(|(index, item)| parse_match(item, &format!("$.matches[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let diagnostics = sequence(fields[7], "$.diagnostics")?
            .iter()
            .map(|value| DiagnosticMessage::from_value_with_registry(value, registry))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            QueryDomain::new(
                string(fields[1], "$.domain_id")?,
                unsigned_u32(fields[2], "$.domain_version")?,
            ),
            parse_role(string(fields[3], "$.role")?)?,
            PortableGraphMessage::from_value(fields[4], limits)?,
            matches,
            Completion::from_value_with_registry(fields[6], registry)?,
            diagnostics,
        )
    }
}

fn validate_matches(
    message: &PortableGraphMessage,
    matches: &[GraphQueryMatchMessage],
) -> Result<(), ProtocolError> {
    let layout = message.wire_layout();
    for (index, item) in matches.iter().copied().enumerate() {
        let path = format!("$.matches[{index}]");
        match item {
            GraphQueryMatchMessage::Node { node } => {
                resolve(&layout.order, node, &format!("{path}.node"))?;
            }
            GraphQueryMatchMessage::SequenceElement {
                parent,
                ordinal,
                node,
            } => {
                let parent_id = resolve(&layout.order, parent, &format!("{path}.parent"))?;
                let node_id = resolve(&layout.order, node, &format!("{path}.node"))?;
                let parent = message
                    .graph()
                    .node(parent_id)
                    .expect("canonical graph ID resolves");
                let item = usize::try_from(ordinal)
                    .ok()
                    .and_then(|ordinal| {
                        parent.sequence_items().and_then(|items| items.get(ordinal))
                    })
                    .copied();
                if item != Some(node_id) {
                    return Err(invalid(&path, "sequence association does not match graph"));
                }
            }
            GraphQueryMatchMessage::MappingEntry {
                parent,
                ordinal,
                key,
                value,
            } => {
                let parent_id = resolve(&layout.order, parent, &format!("{path}.parent"))?;
                let key_id = resolve(&layout.order, key, &format!("{path}.key"))?;
                let value_id = resolve(&layout.order, value, &format!("{path}.value"))?;
                let parent = message
                    .graph()
                    .node(parent_id)
                    .expect("canonical graph ID resolves");
                let entry = usize::try_from(ordinal).ok().and_then(|ordinal| {
                    parent
                        .mapping_entries()
                        .and_then(|entries| entries.get(ordinal))
                });
                if entry.is_none_or(|entry| entry.key() != key_id || entry.value() != value_id) {
                    return Err(invalid(&path, "mapping association does not match graph"));
                }
            }
        }
    }
    Ok(())
}

fn resolve(
    canonical: &[consema_graph::GraphNodeId],
    value: u64,
    path: &str,
) -> Result<consema_graph::GraphNodeId, ProtocolError> {
    usize::try_from(value)
        .ok()
        .and_then(|index| canonical.get(index).copied())
        .ok_or_else(|| invalid(path, "canonical node ID is out of range"))
}

fn match_value(value: GraphQueryMatchMessage) -> PortableValue {
    match value {
        GraphQueryMatchMessage::Node { node } => object(vec![
            ("kind", PortableValue::string("Node")),
            ("node", integer_u64(node)),
        ]),
        GraphQueryMatchMessage::SequenceElement {
            parent,
            ordinal,
            node,
        } => object(vec![
            ("kind", PortableValue::string("SequenceElement")),
            ("parent", integer_u64(parent)),
            ("ordinal", integer_u64(ordinal)),
            ("node", integer_u64(node)),
        ]),
        GraphQueryMatchMessage::MappingEntry {
            parent,
            ordinal,
            key,
            value,
        } => object(vec![
            ("kind", PortableValue::string("MappingEntry")),
            ("parent", integer_u64(parent)),
            ("ordinal", integer_u64(ordinal)),
            ("key", integer_u64(key)),
            ("value", integer_u64(value)),
        ]),
    }
}

fn parse_match(value: &PortableValue, path: &str) -> Result<GraphQueryMatchMessage, ProtocolError> {
    let entries = value
        .as_object()
        .ok_or_else(|| wrong_type(path, "expected graph match Object"))?;
    let kind = entries
        .first()
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| invalid(path, "kind must be the first String field"))?;
    match kind {
        "Node" => {
            let fields = exact_fields(value, &["kind", "node"], path)?;
            Ok(GraphQueryMatchMessage::Node {
                node: unsigned_u64(fields[1], &format!("{path}.node"))?,
            })
        }
        "SequenceElement" => {
            let fields = exact_fields(value, &["kind", "parent", "ordinal", "node"], path)?;
            Ok(GraphQueryMatchMessage::SequenceElement {
                parent: unsigned_u64(fields[1], &format!("{path}.parent"))?,
                ordinal: unsigned_u64(fields[2], &format!("{path}.ordinal"))?,
                node: unsigned_u64(fields[3], &format!("{path}.node"))?,
            })
        }
        "MappingEntry" => {
            let fields = exact_fields(value, &["kind", "parent", "ordinal", "key", "value"], path)?;
            Ok(GraphQueryMatchMessage::MappingEntry {
                parent: unsigned_u64(fields[1], &format!("{path}.parent"))?,
                ordinal: unsigned_u64(fields[2], &format!("{path}.ordinal"))?,
                key: unsigned_u64(fields[3], &format!("{path}.key"))?,
                value: unsigned_u64(fields[4], &format!("{path}.value"))?,
            })
        }
        _ => Err(invalid(path, "unknown graph query match kind")),
    }
}

const fn is_graph_role(role: MatchRole) -> bool {
    matches!(
        role,
        MatchRole::GraphNode | MatchRole::GraphSequenceElement | MatchRole::GraphMappingEntry
    )
}

fn role_name(role: MatchRole) -> &'static str {
    match role {
        MatchRole::GraphNode => "GraphNode",
        MatchRole::GraphSequenceElement => "GraphSequenceElement",
        MatchRole::GraphMappingEntry => "GraphMappingEntry",
        _ => unreachable!("GraphQueryResultMessage construction validates the role"),
    }
}

fn parse_role(value: &str) -> Result<MatchRole, ProtocolError> {
    match value {
        "GraphNode" => Ok(MatchRole::GraphNode),
        "GraphSequenceElement" => Ok(MatchRole::GraphSequenceElement),
        "GraphMappingEntry" => Ok(MatchRole::GraphMappingEntry),
        _ => Err(invalid("$.role", "unknown graph query match role")),
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
    use consema_core::{
        CancellationToken, CapabilityId, CapabilitySet, OperatorCall, QueryDefinition,
        QueryExpression, QueryLimits,
    };
    use consema_graph::{GraphBuilder, GraphLimits, GraphMappingEntry};

    fn graph() -> PortableGraph {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let key = builder.reserve_node().unwrap();
        let mapping = builder.reserve_node().unwrap();
        let value = builder.reserve_node().unwrap();
        builder
            .define_scalar(key, "tag:yaml.org,2002:str", "key")
            .unwrap();
        builder
            .define_scalar(value, "tag:yaml.org,2002:str", "value")
            .unwrap();
        builder
            .define_mapping(
                mapping,
                "tag:yaml.org,2002:map",
                vec![GraphMappingEntry::new(key, value)],
            )
            .unwrap()
            .push_root(mapping)
            .unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn completed_mapping_query_round_trips_with_canonical_ids() {
        let graph = graph();
        let definition = QueryDefinition::new(QueryDomain::portable_graph_v1()).with_expression(
            QueryExpression::Input.then(OperatorCall::new("graph.try-mapping-entries", 1)),
        );
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        let execution = graph
            .query(
                &definition.validate().unwrap().bind(&capabilities).unwrap(),
                QueryLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        let result = GraphQueryResultMessage::from_execution(
            &graph,
            MatchRole::GraphMappingEntry,
            &execution,
            PgceLimits::default(),
        )
        .unwrap();
        assert_eq!(
            GraphQueryResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
        assert_eq!(
            result.matches(),
            &[GraphQueryMatchMessage::MappingEntry {
                parent: 0,
                ordinal: 0,
                key: 1,
                value: 2,
            }]
        );
    }

    #[test]
    fn dangling_or_wrong_kind_associations_are_rejected() {
        let graph = PortableGraphMessage::from_graph(graph(), PgceLimits::default()).unwrap();
        let completion = Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap();
        let wrong_kind = GraphQueryResultMessage::new(
            QueryDomain::portable_graph_v1(),
            MatchRole::GraphSequenceElement,
            graph.clone(),
            vec![GraphQueryMatchMessage::SequenceElement {
                parent: 0,
                ordinal: 0,
                node: 1,
            }],
            completion.clone(),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(wrong_kind.kind(), ProtocolErrorKind::InvalidValue);
        let dangling = GraphQueryResultMessage::new(
            QueryDomain::portable_graph_v1(),
            MatchRole::GraphNode,
            graph,
            vec![GraphQueryMatchMessage::Node { node: 99 }],
            completion,
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(dangling.kind(), ProtocolErrorKind::InvalidValue);
    }
}
