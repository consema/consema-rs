//! Exact PortableGraph projection and externalized provenance protocols.

use crate::schema::{
    exact_fields, integer_u64, nullable_string, object, optional_string, schema_fields, sequence,
    string, unsigned_u64,
};
use crate::{
    Completion, CompletionStatus, DiagnosticMessage, ErrorCodeRegistry, PortableGraphMessage,
    ProtocolError, ProtocolErrorKind,
};
use consema_core::{PortableValue, SequenceBuilder};
use consema_document::NodeRef;
use consema_graph::{GraphNodeId, PgceLimits};

/// One projected PortableGraph location expressed with canonical node IDs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphProjectedLocationMessage {
    /// Ordered root occurrence.
    Root(u64),
    /// One graph node.
    Node(u64),
    /// One ordered sequence edge.
    SequenceElement {
        /// Canonical parent sequence ID.
        parent: u64,
        /// Direct association ordinal.
        ordinal: u64,
    },
    /// One ordered mapping key edge.
    MappingKey {
        /// Canonical parent mapping ID.
        parent: u64,
        /// Direct association ordinal.
        ordinal: u64,
    },
    /// One ordered mapping value edge.
    MappingValue {
        /// Canonical parent mapping ID.
        parent: u64,
        /// Direct association ordinal.
        ordinal: u64,
    },
}

/// Exact YAML-source relation to a projected graph fact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphProvenanceRelationMessage {
    /// Direct native representation origin.
    Direct,
    /// Alias occurrence referring to a shared graph node.
    Reference,
}

/// Transferable graph origin with caller-assigned identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphSourceOriginMessage {
    /// Stable source identity.
    pub source_id: String,
    /// Optional stable caller node locator.
    pub node_locator: Option<String>,
    /// Inclusive source byte start.
    pub start_byte: u64,
    /// Exclusive source byte end.
    pub end_byte: u64,
    /// Exact graph provenance relation.
    pub relation: GraphProvenanceRelationMessage,
}

impl GraphSourceOriginMessage {
    /// Validates one externalized graph origin.
    pub fn new(
        source_id: impl Into<String>,
        node_locator: Option<String>,
        start_byte: u64,
        end_byte: u64,
        relation: GraphProvenanceRelationMessage,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        if source_id.is_empty()
            || source_id.len() > 1024
            || start_byte > end_byte
            || node_locator
                .as_ref()
                .is_some_and(|locator| locator.is_empty() || locator.len() > 4096)
        {
            return Err(invalid(
                "$.origin",
                "invalid source identity, locator, or half-open range",
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

    /// Explicitly refuses an unbound process-local node handle.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.origin.node",
            "NodeRef requires a stable caller locator",
        ))
    }
}

/// One graph location and all ordered source origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphProvenanceEntryMessage {
    /// Projected graph location.
    pub projected: GraphProjectedLocationMessage,
    /// One or more source origins.
    pub origins: Vec<GraphSourceOriginMessage>,
}

/// Sorted unique `core.graph-provenance-map@1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphProvenanceMapMessage {
    entries: Vec<GraphProvenanceEntryMessage>,
}

impl GraphProvenanceMapMessage {
    /// Validates canonical location order, uniqueness, and non-empty origins.
    pub fn new(entries: Vec<GraphProvenanceEntryMessage>) -> Result<Self, ProtocolError> {
        if entries.iter().any(|entry| entry.origins.is_empty())
            || entries
                .windows(2)
                .any(|pair| pair[0].projected >= pair[1].projected)
        {
            return Err(invalid(
                "$.entries",
                "graph provenance locations must be sorted, unique, and have origins",
            ));
        }
        Ok(Self { entries })
    }

    /// Sorted provenance entries.
    #[must_use]
    pub fn entries(&self) -> &[GraphProvenanceEntryMessage] {
        &self.entries
    }

    /// Validates every projected location against one exact graph message.
    pub fn validate_against(&self, graph: &PortableGraphMessage) -> Result<(), ProtocolError> {
        let layout = graph.wire_layout();
        for (index, entry) in self.entries.iter().enumerate() {
            validate_location(
                graph,
                &layout.order,
                entry.projected,
                &format!("$.entries[{index}].projected"),
            )?;
        }
        Ok(())
    }

    /// Encodes `core.graph-provenance-map@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut entries = SequenceBuilder::new();
        for entry in &self.entries {
            let mut origins = SequenceBuilder::new();
            for origin in &entry.origins {
                origins.push(origin_value(origin));
            }
            entries.push(object(vec![
                ("projected", location_value(entry.projected)),
                ("origins", origins.build()),
            ]));
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.graph-provenance-map@1"),
            ),
            ("entries", entries.build()),
        ])
    }

    /// Strictly decodes one graph provenance map.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.graph-provenance-map@1",
            &["schema", "entries"],
            "$",
        )?;
        let entries = sequence(fields[1], "$.entries")?
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let path = format!("$.entries[{index}]");
                let fields = exact_fields(entry, &["projected", "origins"], &path)?;
                Ok(GraphProvenanceEntryMessage {
                    projected: parse_location(fields[0], &format!("{path}.projected"))?,
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

/// Atomic exact `core.graph-projection-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphProjectionResultMessage {
    completion: Completion,
    graph: Option<PortableGraphMessage>,
    provenance: GraphProvenanceMapMessage,
    diagnostics: Vec<DiagnosticMessage>,
}

impl GraphProjectionResultMessage {
    /// Validates atomic success, produced count, and complete graph provenance.
    pub fn new(
        completion: Completion,
        graph: Option<PortableGraphMessage>,
        provenance: GraphProvenanceMapMessage,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        let success = completion.status() == CompletionStatus::Success;
        if success != graph.is_some()
            || (success && completion.produced() != 1)
            || (!success && completion.produced() != 0)
        {
            return Err(invalid(
                "$",
                "only successful single-result projection may carry a graph",
            ));
        }
        if let Some(graph) = &graph {
            provenance.validate_against(graph)?;
        } else if !provenance.entries().is_empty() {
            return Err(invalid(
                "$.provenance",
                "failed projection cannot claim completed provenance",
            ));
        }
        Ok(Self {
            completion,
            graph,
            provenance,
            diagnostics,
        })
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Complete graph only on success.
    #[must_use]
    pub const fn graph(&self) -> Option<&PortableGraphMessage> {
        self.graph.as_ref()
    }

    /// Complete provenance only on success.
    #[must_use]
    pub const fn provenance(&self) -> &GraphProvenanceMapMessage {
        &self.provenance
    }

    /// Ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.graph-projection-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.graph-projection-result@1"),
            ),
            ("completion", self.completion.to_value()),
            (
                "graph",
                self.graph
                    .as_ref()
                    .map_or_else(PortableValue::null, |graph| {
                        object(vec![("portable_graph", graph.to_value())])
                    }),
            ),
            ("provenance", self.provenance.to_value()),
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
            "core.graph-projection-result@1",
            &["schema", "completion", "graph", "provenance", "diagnostics"],
            "$",
        )?;
        let graph = if fields[2] == &PortableValue::null() {
            None
        } else {
            let graph = exact_fields(fields[2], &["portable_graph"], "$.graph")?[0];
            Some(PortableGraphMessage::from_value(graph, limits)?)
        };
        let diagnostics = sequence(fields[4], "$.diagnostics")?
            .iter()
            .map(|value| DiagnosticMessage::from_value_with_registry(value, registry))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            Completion::from_value_with_registry(fields[1], registry)?,
            graph,
            GraphProvenanceMapMessage::from_value(fields[3])?,
            diagnostics,
        )
    }
}

fn validate_location(
    graph: &PortableGraphMessage,
    canonical: &[GraphNodeId],
    location: GraphProjectedLocationMessage,
    path: &str,
) -> Result<(), ProtocolError> {
    match location {
        GraphProjectedLocationMessage::Root(ordinal) => {
            let valid = usize::try_from(ordinal)
                .ok()
                .is_some_and(|ordinal| ordinal < graph.graph().roots().len());
            if !valid {
                return Err(invalid(path, "root ordinal is out of range"));
            }
        }
        GraphProjectedLocationMessage::Node(node) => {
            resolve(canonical, node, path)?;
        }
        GraphProjectedLocationMessage::SequenceElement { parent, ordinal } => {
            let parent = resolve(canonical, parent, path)?;
            let valid = usize::try_from(ordinal).ok().is_some_and(|ordinal| {
                graph
                    .graph()
                    .node(parent)
                    .and_then(|node| node.sequence_items())
                    .is_some_and(|items| ordinal < items.len())
            });
            if !valid {
                return Err(invalid(path, "sequence location does not exist"));
            }
        }
        GraphProjectedLocationMessage::MappingKey { parent, ordinal }
        | GraphProjectedLocationMessage::MappingValue { parent, ordinal } => {
            let parent = resolve(canonical, parent, path)?;
            let valid = usize::try_from(ordinal).ok().is_some_and(|ordinal| {
                graph
                    .graph()
                    .node(parent)
                    .and_then(|node| node.mapping_entries())
                    .is_some_and(|entries| ordinal < entries.len())
            });
            if !valid {
                return Err(invalid(path, "mapping location does not exist"));
            }
        }
    }
    Ok(())
}

fn resolve(
    canonical: &[GraphNodeId],
    value: u64,
    path: &str,
) -> Result<GraphNodeId, ProtocolError> {
    usize::try_from(value)
        .ok()
        .and_then(|index| canonical.get(index).copied())
        .ok_or_else(|| invalid(path, "canonical node ID is out of range"))
}

fn location_value(location: GraphProjectedLocationMessage) -> PortableValue {
    match location {
        GraphProjectedLocationMessage::Root(ordinal) => object(vec![
            ("kind", PortableValue::string("Root")),
            ("ordinal", integer_u64(ordinal)),
        ]),
        GraphProjectedLocationMessage::Node(node) => object(vec![
            ("kind", PortableValue::string("Node")),
            ("node", integer_u64(node)),
        ]),
        GraphProjectedLocationMessage::SequenceElement { parent, ordinal } => object(vec![
            ("kind", PortableValue::string("SequenceElement")),
            ("parent", integer_u64(parent)),
            ("ordinal", integer_u64(ordinal)),
        ]),
        GraphProjectedLocationMessage::MappingKey { parent, ordinal } => object(vec![
            ("kind", PortableValue::string("MappingKey")),
            ("parent", integer_u64(parent)),
            ("ordinal", integer_u64(ordinal)),
        ]),
        GraphProjectedLocationMessage::MappingValue { parent, ordinal } => object(vec![
            ("kind", PortableValue::string("MappingValue")),
            ("parent", integer_u64(parent)),
            ("ordinal", integer_u64(ordinal)),
        ]),
    }
}

fn parse_location(
    value: &PortableValue,
    path: &str,
) -> Result<GraphProjectedLocationMessage, ProtocolError> {
    let entries = value
        .as_object()
        .ok_or_else(|| wrong_type(path, "expected graph location Object"))?;
    let kind = entries
        .first()
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| invalid(path, "kind must be the first String field"))?;
    match kind {
        "Root" => {
            let fields = exact_fields(value, &["kind", "ordinal"], path)?;
            Ok(GraphProjectedLocationMessage::Root(unsigned_u64(
                fields[1],
                &format!("{path}.ordinal"),
            )?))
        }
        "Node" => {
            let fields = exact_fields(value, &["kind", "node"], path)?;
            Ok(GraphProjectedLocationMessage::Node(unsigned_u64(
                fields[1],
                &format!("{path}.node"),
            )?))
        }
        "SequenceElement" | "MappingKey" | "MappingValue" => {
            let fields = exact_fields(value, &["kind", "parent", "ordinal"], path)?;
            let parent = unsigned_u64(fields[1], &format!("{path}.parent"))?;
            let ordinal = unsigned_u64(fields[2], &format!("{path}.ordinal"))?;
            Ok(match kind {
                "SequenceElement" => {
                    GraphProjectedLocationMessage::SequenceElement { parent, ordinal }
                }
                "MappingKey" => GraphProjectedLocationMessage::MappingKey { parent, ordinal },
                _ => GraphProjectedLocationMessage::MappingValue { parent, ordinal },
            })
        }
        _ => Err(invalid(path, "unknown graph projected location")),
    }
}

fn origin_value(origin: &GraphSourceOriginMessage) -> PortableValue {
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
            PortableValue::string(match origin.relation {
                GraphProvenanceRelationMessage::Direct => "Direct",
                GraphProvenanceRelationMessage::Reference => "Reference",
            }),
        ),
    ])
}

fn parse_origin(
    value: &PortableValue,
    path: &str,
) -> Result<GraphSourceOriginMessage, ProtocolError> {
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
    GraphSourceOriginMessage::new(
        string(fields[0], &format!("{path}.source_id"))?,
        optional_string(fields[1], &format!("{path}.node_locator"))?.map(str::to_owned),
        unsigned_u64(fields[2], &format!("{path}.start_byte"))?,
        unsigned_u64(fields[3], &format!("{path}.end_byte"))?,
        match string(fields[4], &format!("{path}.relation"))? {
            "Direct" => GraphProvenanceRelationMessage::Direct,
            "Reference" => GraphProvenanceRelationMessage::Reference,
            _ => return Err(invalid(path, "unknown graph provenance relation")),
        },
    )
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, message)
}

fn wrong_type(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::WrongType, path, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::DocumentAuthority;
    use consema_graph::{GraphBuilder, GraphLimits, GraphMappingEntry};

    fn graph() -> PortableGraphMessage {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let mapping = builder.reserve_node().unwrap();
        let key = builder.reserve_node().unwrap();
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
        PortableGraphMessage::from_graph(builder.build().unwrap(), PgceLimits::default()).unwrap()
    }

    fn origin(relation: GraphProvenanceRelationMessage) -> GraphSourceOriginMessage {
        GraphSourceOriginMessage::new(
            "source:yaml",
            Some("yaml:node:0".to_owned()),
            0,
            3,
            relation,
        )
        .unwrap()
    }

    #[test]
    fn exact_graph_projection_and_reference_provenance_round_trip() {
        let graph = graph();
        let provenance = GraphProvenanceMapMessage::new(vec![
            GraphProvenanceEntryMessage {
                projected: GraphProjectedLocationMessage::Root(0),
                origins: vec![origin(GraphProvenanceRelationMessage::Direct)],
            },
            GraphProvenanceEntryMessage {
                projected: GraphProjectedLocationMessage::Node(0),
                origins: vec![origin(GraphProvenanceRelationMessage::Reference)],
            },
            GraphProvenanceEntryMessage {
                projected: GraphProjectedLocationMessage::MappingValue {
                    parent: 0,
                    ordinal: 0,
                },
                origins: vec![origin(GraphProvenanceRelationMessage::Direct)],
            },
        ])
        .unwrap();
        let result = GraphProjectionResultMessage::new(
            Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap(),
            Some(graph),
            provenance,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            GraphProjectionResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
    }

    #[test]
    fn invalid_locations_and_partial_failure_provenance_are_rejected() {
        let graph = graph();
        let invalid_map = GraphProvenanceMapMessage::new(vec![GraphProvenanceEntryMessage {
            projected: GraphProjectedLocationMessage::SequenceElement {
                parent: 0,
                ordinal: 0,
            },
            origins: vec![origin(GraphProvenanceRelationMessage::Direct)],
        }])
        .unwrap();
        assert_eq!(
            invalid_map.validate_against(&graph).unwrap_err().kind(),
            ProtocolErrorKind::InvalidValue
        );
        let nonempty = GraphProvenanceMapMessage::new(vec![GraphProvenanceEntryMessage {
            projected: GraphProjectedLocationMessage::Root(0),
            origins: vec![origin(GraphProvenanceRelationMessage::Direct)],
        }])
        .unwrap();
        assert_eq!(
            GraphProjectionResultMessage::new(
                Completion::new(
                    CompletionStatus::Failed,
                    1,
                    0,
                    None,
                    Some("core.projection.target-not-applicable@1".to_owned()),
                )
                .unwrap(),
                None,
                nonempty,
                Vec::new(),
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::InvalidValue
        );
    }

    #[test]
    fn process_local_node_requires_a_caller_locator() {
        let node = DocumentAuthority::fresh().node_ref(0, consema_document::NodeRole::YamlNode);
        assert_eq!(
            GraphSourceOriginMessage::from_process_local(node)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
    }
}
