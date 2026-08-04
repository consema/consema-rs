use std::cmp::Ordering;
use std::collections::HashSet;

use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, QueryExecution, QueryExpression,
    QueryFailure, QueryLimits, QuerySelection,
};

use crate::{GraphNodeId, GraphNodeKind, PortableGraph};

/// Typed match produced by `core.portable-graph-query@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphMatch {
    /// One graph node identity.
    Node {
        /// Graph-local node identity.
        node: GraphNodeId,
    },
    /// One ordered sequence element association.
    SequenceElement {
        /// Owning sequence node.
        parent: GraphNodeId,
        /// Zero-based association ordinal.
        ordinal: u64,
        /// Referenced item node.
        node: GraphNodeId,
    },
    /// One ordered mapping association.
    MappingEntry {
        /// Owning mapping node.
        parent: GraphNodeId,
        /// Zero-based association ordinal.
        ordinal: u64,
        /// Arbitrary key node.
        key: GraphNodeId,
        /// Value node.
        value: GraphNodeId,
    },
}

impl GraphMatch {
    /// Returns the node for a node match.
    #[must_use]
    pub const fn node(&self) -> Option<GraphNodeId> {
        match self {
            Self::Node { node } => Some(*node),
            Self::SequenceElement { .. } | Self::MappingEntry { .. } => None,
        }
    }

    /// Returns the association parent and ordinal for an element or entry.
    #[must_use]
    pub const fn association(&self) -> Option<(GraphNodeId, u64)> {
        match self {
            Self::Node { .. } => None,
            Self::SequenceElement {
                parent, ordinal, ..
            }
            | Self::MappingEntry {
                parent, ordinal, ..
            } => Some((*parent, *ordinal)),
        }
    }

    fn identity(&self) -> GraphMatchIdentity {
        match self {
            Self::Node { node } => GraphMatchIdentity::Node(*node),
            Self::SequenceElement {
                parent, ordinal, ..
            } => GraphMatchIdentity::SequenceElement(*parent, *ordinal),
            Self::MappingEntry {
                parent, ordinal, ..
            } => GraphMatchIdentity::MappingEntry(*parent, *ordinal),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum GraphMatchIdentity {
    Node(GraphNodeId),
    SequenceElement(GraphNodeId, u64),
    MappingEntry(GraphNodeId, u64),
}

struct QueryContext<'a> {
    graph: &'a PortableGraph,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
    canonical_ids: Vec<u64>,
}

impl QueryContext<'_> {
    fn step(&mut self) -> Result<(), QueryFailure> {
        if self.cancellation.is_cancelled() {
            return Err(QueryFailure::Cancelled);
        }
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn check_results(&self, count: usize) -> Result<(), QueryFailure> {
        if count > self.limits.max_results {
            Err(QueryFailure::ResourceLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn extend_checked(
        &self,
        output: &mut Vec<GraphMatch>,
        values: impl IntoIterator<Item = GraphMatch>,
    ) -> Result<(), QueryFailure> {
        for value in values {
            output.push(value);
            self.check_results(output.len())?;
        }
        Ok(())
    }

    fn rank(&self, value: &GraphMatch) -> (u64, u8, u64) {
        match value {
            GraphMatch::Node { node } => (self.node_rank(*node), 0, 0),
            GraphMatch::SequenceElement {
                parent, ordinal, ..
            } => (self.node_rank(*parent), 1, *ordinal),
            GraphMatch::MappingEntry {
                parent, ordinal, ..
            } => (self.node_rank(*parent), 2, *ordinal),
        }
    }

    fn node_rank(&self, id: GraphNodeId) -> u64 {
        self.canonical_ids[id.index().expect("completed graph ID fits usize")]
    }
}

impl PortableGraph {
    /// Executes one validated, capability-bound portable-graph query.
    pub fn query(
        &self,
        query: &ExecutableQuery,
        limits: QueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<QueryExecution<GraphMatch>, QueryFailure> {
        if query.definition().domain() != &consema_core::QueryDomain::portable_graph_v1() {
            return Err(QueryFailure::DomainMismatch(
                query.definition().domain().clone(),
            ));
        }
        let layout = self.canonical_layout();
        let mut context = QueryContext {
            graph: self,
            limits,
            cancellation,
            steps: 0,
            canonical_ids: layout.canonical_ids,
        };
        let roots = self
            .roots()
            .iter()
            .copied()
            .map(|node| GraphMatch::Node { node })
            .collect::<Vec<_>>();
        context.check_results(roots.len())?;
        let matches = evaluate(query.definition().expression(), &roots, &mut context)?;
        let matches = apply_selection(query.definition().selection(), matches)?;
        context.check_results(matches.len())?;
        Ok(QueryExecution::completed(matches))
    }
}

fn evaluate(
    expression: &QueryExpression,
    input: &[GraphMatch],
    context: &mut QueryContext<'_>,
) -> Result<Vec<GraphMatch>, QueryFailure> {
    context.step()?;
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: inner,
            operator,
        } => {
            let values = evaluate(inner, input, context)?;
            apply_operator(operator, values, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = evaluate(branch, input, context)?;
                context.extend_checked(&mut output, values)?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = evaluate(branch, input, context)?;
                context.extend_checked(&mut output, values)?;
            }
            output.sort_by(|left, right| compare_rank(context, left, right));
            let mut seen = HashSet::new();
            output.retain(|value| seen.insert(value.identity()));
            Ok(output)
        }
    }
}

fn compare_rank(context: &QueryContext<'_>, left: &GraphMatch, right: &GraphMatch) -> Ordering {
    context.rank(left).cmp(&context.rank(right))
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<GraphMatch>,
    context: &mut QueryContext<'_>,
) -> Result<Vec<GraphMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "core.take" => {
            let count = operator.arguments()["count"]
                .as_integer()
                .and_then(consema_core::BigInteger::to_usize)
                .expect("query validation checked count");
            context.extend_checked(&mut output, input.into_iter().take(count))?;
        }
        "core.distinct-by-identity" => {
            let mut seen = HashSet::new();
            for value in input {
                context.step()?;
                if seen.insert(value.identity()) {
                    output.push(value);
                    context.check_results(output.len())?;
                }
            }
        }
        "graph.reachable-nodes" => {
            let mut seen = HashSet::new();
            for value in input {
                let GraphMatch::Node { node } = value else {
                    unreachable!("query validation checked graph node role")
                };
                let mut stack = vec![node];
                while let Some(node) = stack.pop() {
                    context.step()?;
                    if !seen.insert(node) {
                        continue;
                    }
                    output.push(GraphMatch::Node { node });
                    context.check_results(output.len())?;
                    let mut outgoing = Vec::new();
                    context
                        .graph
                        .node(node)
                        .expect("query node belongs to graph")
                        .outgoing_reverse(&mut outgoing);
                    stack.extend(outgoing);
                }
            }
        }
        "graph.where-kind" => {
            let expected = graph_kind(operator.arguments()["kind"].as_string().expect("string"));
            for value in input {
                context.step()?;
                let GraphMatch::Node { node } = value else {
                    unreachable!("query validation checked graph node role")
                };
                if context
                    .graph
                    .node(node)
                    .expect("query node belongs to graph")
                    .kind()
                    == expected
                {
                    output.push(GraphMatch::Node { node });
                    context.check_results(output.len())?;
                }
            }
        }
        "graph.where-tag" => {
            let expected = operator.arguments()["tag"].as_string().expect("string");
            for value in input {
                context.step()?;
                let GraphMatch::Node { node } = value else {
                    unreachable!("query validation checked graph node role")
                };
                if context
                    .graph
                    .node(node)
                    .expect("query node belongs to graph")
                    .tag()
                    == expected
                {
                    output.push(GraphMatch::Node { node });
                    context.check_results(output.len())?;
                }
            }
        }
        "graph.try-sequence-elements" => {
            for value in input {
                context.step()?;
                let GraphMatch::Node { node } = value else {
                    unreachable!("query validation checked graph node role")
                };
                if let Some(items) = context
                    .graph
                    .node(node)
                    .expect("query node belongs to graph")
                    .sequence_items()
                {
                    for (ordinal, item) in items.iter().copied().enumerate() {
                        output.push(GraphMatch::SequenceElement {
                            parent: node,
                            ordinal: u64::try_from(ordinal)
                                .map_err(|_| QueryFailure::ResourceLimitExceeded)?,
                            node: item,
                        });
                        context.check_results(output.len())?;
                    }
                }
            }
        }
        "graph.sequence-element-node" => {
            for value in input {
                context.step()?;
                let GraphMatch::SequenceElement { node, .. } = value else {
                    unreachable!("query validation checked sequence element role")
                };
                output.push(GraphMatch::Node { node });
                context.check_results(output.len())?;
            }
        }
        "graph.try-mapping-entries" => {
            for value in input {
                context.step()?;
                let GraphMatch::Node { node } = value else {
                    unreachable!("query validation checked graph node role")
                };
                if let Some(entries) = context
                    .graph
                    .node(node)
                    .expect("query node belongs to graph")
                    .mapping_entries()
                {
                    for (ordinal, entry) in entries.iter().copied().enumerate() {
                        output.push(GraphMatch::MappingEntry {
                            parent: node,
                            ordinal: u64::try_from(ordinal)
                                .map_err(|_| QueryFailure::ResourceLimitExceeded)?,
                            key: entry.key(),
                            value: entry.value(),
                        });
                        context.check_results(output.len())?;
                    }
                }
            }
        }
        "graph.mapping-entry-key" | "graph.mapping-entry-value" => {
            let key = operator.id() == "graph.mapping-entry-key";
            for value in input {
                context.step()?;
                let GraphMatch::MappingEntry {
                    key: entry_key,
                    value,
                    ..
                } = value
                else {
                    unreachable!("query validation checked mapping entry role")
                };
                output.push(GraphMatch::Node {
                    node: if key { entry_key } else { value },
                });
                context.check_results(output.len())?;
            }
        }
        _ => unreachable!("core validation rejected unknown graph operator"),
    }
    Ok(output)
}

fn graph_kind(name: &str) -> GraphNodeKind {
    match name {
        "Scalar" => GraphNodeKind::Scalar,
        "Sequence" => GraphNodeKind::Sequence,
        "Mapping" => GraphNodeKind::Mapping,
        _ => unreachable!("core validation checked graph kind"),
    }
}

fn apply_selection(
    selection: QuerySelection,
    mut values: Vec<GraphMatch>,
) -> Result<Vec<GraphMatch>, QueryFailure> {
    match selection {
        QuerySelection::All => Ok(values),
        QuerySelection::First => Ok(values.into_iter().take(1).collect()),
        QuerySelection::Last => Ok(values.pop().into_iter().collect()),
        QuerySelection::ZeroOrOne if values.len() <= 1 => Ok(values),
        QuerySelection::RequireOne if values.len() == 1 => Ok(values),
        QuerySelection::ZeroOrOne | QuerySelection::RequireOne => {
            Err(QueryFailure::CardinalityViolation {
                selection,
                actual: values.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use consema_core::{
        CapabilityId, CapabilitySet, MatchRole, PortableValue, QueryDefinition, QueryDomain,
    };

    use super::*;
    use crate::{GraphBuilder, GraphLimits, GraphMappingEntry};

    const STR: &str = "tag:yaml.org,2002:str";
    const SEQ: &str = "tag:yaml.org,2002:seq";
    const MAP: &str = "tag:yaml.org,2002:map";

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn graph() -> PortableGraph {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let mapping = builder.reserve_node().unwrap();
        let key = builder.reserve_node().unwrap();
        let sequence = builder.reserve_node().unwrap();
        builder.define_scalar(key, STR, "service").unwrap();
        builder
            .define_sequence(sequence, SEQ, vec![key, key, mapping])
            .unwrap();
        builder
            .define_mapping(mapping, MAP, vec![GraphMappingEntry::new(key, sequence)])
            .unwrap()
            .push_root(mapping)
            .unwrap();
        builder.build().unwrap()
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::portable_graph_v1())
            .with_expression(expression)
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap()
    }

    #[test]
    fn validation_is_domain_and_role_typed() {
        let query = QueryDefinition::new(QueryDomain::portable_graph_v1()).with_expression(
            QueryExpression::Input
                .then(OperatorCall::new("graph.try-mapping-entries", 1))
                .then(OperatorCall::new("graph.mapping-entry-value", 1)),
        );
        assert_eq!(
            query.validate().unwrap().output_role(),
            MatchRole::GraphNode
        );

        let invalid = QueryDefinition::new(QueryDomain::portable_graph_v1()).with_expression(
            QueryExpression::Input.then(OperatorCall::new("graph.mapping-entry-value", 1)),
        );
        assert!(matches!(
            invalid.validate(),
            Err(QueryFailure::InvalidOperatorComposition { .. })
        ));
    }

    #[test]
    fn reachable_order_is_canonical_and_cycles_do_not_expand() {
        let graph = graph();
        let query =
            executable(QueryExpression::Input.then(OperatorCall::new("graph.reachable-nodes", 1)));
        let result = graph
            .query(&query, QueryLimits::default(), &CancellationToken::new())
            .unwrap();
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].node(), Some(graph.roots()[0]));
    }

    #[test]
    fn reachable_nodes_visit_shared_nodes_once_across_roots() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let shared = builder.reserve_node().unwrap();
        let left = builder.reserve_node().unwrap();
        let right = builder.reserve_node().unwrap();
        builder.define_scalar(shared, STR, "shared").unwrap();
        builder.define_sequence(left, SEQ, vec![shared]).unwrap();
        builder.define_sequence(right, SEQ, vec![shared]).unwrap();
        builder.push_root(left).unwrap().push_root(right).unwrap();
        let graph = builder.build().unwrap();
        let query =
            executable(QueryExpression::Input.then(OperatorCall::new("graph.reachable-nodes", 1)));

        let result = graph
            .query(&query, QueryLimits::default(), &CancellationToken::new())
            .unwrap();
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].node(), Some(graph.roots()[0]));
        assert_eq!(result.matches()[2].node(), Some(graph.roots()[1]));
    }

    #[test]
    fn association_operators_keep_order_and_shared_identity() {
        let graph = graph();
        let expression = QueryExpression::Input
            .then(OperatorCall::new("graph.try-mapping-entries", 1))
            .then(OperatorCall::new("graph.mapping-entry-value", 1))
            .then(OperatorCall::new("graph.try-sequence-elements", 1))
            .then(OperatorCall::new("graph.sequence-element-node", 1));
        let query = executable(expression);
        let result = graph
            .query(&query, QueryLimits::default(), &CancellationToken::new())
            .unwrap();
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].node(), result.matches()[1].node());

        let distinct = executable(
            query
                .definition()
                .expression()
                .clone()
                .then(OperatorCall::new("core.distinct-by-identity", 1)),
        );
        let result = graph
            .query(&distinct, QueryLimits::default(), &CancellationToken::new())
            .unwrap();
        assert_eq!(result.matches().len(), 2);
    }

    #[test]
    fn filters_selection_limits_and_cancellation_are_explicit() {
        let graph = graph();
        let kind = executable(
            QueryExpression::Input
                .then(OperatorCall::new("graph.reachable-nodes", 1))
                .then(
                    OperatorCall::new("graph.where-kind", 1)
                        .with_argument("kind", PortableValue::string("Scalar")),
                ),
        );
        assert_eq!(
            graph
                .query(&kind, QueryLimits::default(), &CancellationToken::new())
                .unwrap()
                .matches()
                .len(),
            1
        );

        assert_eq!(
            graph
                .query(
                    &kind,
                    QueryLimits {
                        max_steps: 1,
                        max_results: 100,
                    },
                    &CancellationToken::new(),
                )
                .unwrap_err(),
            QueryFailure::ResourceLimitExceeded
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            graph
                .query(&kind, QueryLimits::default(), &cancelled)
                .unwrap_err(),
            QueryFailure::Cancelled
        );
    }

    #[test]
    fn graph_query_definitions_use_the_existing_language_neutral_envelope() {
        let definition = QueryDefinition::new(QueryDomain::portable_graph_v1());
        let encoded = definition.to_protocol_value().unwrap();
        assert_eq!(
            QueryDefinition::from_protocol_value(&encoded).unwrap(),
            definition
        );
    }
}
