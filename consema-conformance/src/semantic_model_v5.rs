//! Language-neutral semantic-model v5 graph and YAML protocol runner.

use std::collections::HashSet;

use consema_core::{
    BigInteger, MatchRole, ObjectBuilder, PortableValue, QueryDomain, SequenceBuilder,
};
use consema_document::{ContentDigest, DocumentAuthority, NodeRole};
use consema_graph::{GraphBuilder, GraphLimits, GraphMappingEntry, PgceLimits, PortableGraph};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{
    Completion, CompletionStatus, ContractId, ContractRegistry, ErrorCodeRegistry,
    GraphProjectedLocationMessage, GraphProjectionResultMessage, GraphProvenanceEntryMessage,
    GraphProvenanceMapMessage, GraphProvenanceRelationMessage, GraphQueryMatchMessage,
    GraphQueryResultMessage, GraphSourceOriginMessage, PortableGraphMessage, ProtocolLimits,
    ProtocolMessage, RegistryManifest, YamlMatchLocator, YamlQueryResultMessage,
};

use super::{ConformanceReport, VectorCase, object_field};

const SUITE: &str = "consema.semantic-model-v5.conformance@1";

/// Embedded language-neutral semantic-model v5 suite bytes.
pub const SEMANTIC_MODEL_V5_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/semantic-model-v5.json");

/// Runs the embedded `consema.semantic-model-v5.conformance@1` suite.
#[must_use]
pub fn run_semantic_model_v5() -> ConformanceReport {
    run_semantic_model_v5_json(SEMANTIC_MODEL_V5_VECTORS_JSON)
}

/// Runs one semantic-model v5 suite from strict JSON text.
#[must_use]
pub fn run_semantic_model_v5_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published semantic-model v5 vectors must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("semantic-model v5 vector root");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let semantic_model = object_field(root, "semantic_model")
        .and_then(PortableValue::as_string)
        .unwrap_or_default();
    if suite != SUITE || semantic_model != "core.semantic-model@5" {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "unexpected suite or semantic-model identifier".to_owned(),
            )],
        };
    }
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let fields = case.as_object().expect("semantic-model v5 case object");
        let id = object_field(fields, "id")
            .and_then(PortableValue::as_string)
            .expect("case id");
        let capability = object_field(fields, "capability")
            .and_then(PortableValue::as_string)
            .expect("case capability");
        let input = object_field(fields, "input").expect("case input");
        let expected = object_field(fields, "expected").expect("case expected");
        if !seen.insert(id) {
            report
                .failed
                .push((id.to_owned(), "duplicate case id".to_owned()));
            continue;
        }
        let vector = VectorCase {
            id,
            capability,
            input,
            expected,
        };
        match run_case(&vector) {
            Ok(()) => report.passed.push(id.to_owned()),
            Err(error) => report.failed.push((id.to_owned(), error)),
        }
    }
    report
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    let required = match case.id {
        "registry.v5-manifest" | "registry.v1-v4-frozen" | "registry.v5-additive-contracts" => {
            "core.registry-manifest@1"
        }
        "registry.v5-error-codes" => "core.error-code-registry@1",
        id if id.starts_with("portable-graph.") => "core.portable-graph@1",
        id if id.starts_with("graph-query.") => "core.graph-query-result@1",
        id if id.starts_with("graph-provenance.") => "core.graph-provenance-map@1",
        id if id.starts_with("graph-projection.") => "core.graph-projection-result@1",
        id if id.starts_with("yaml-query.") => "core.yaml-query-result@1",
        id if id.starts_with("protocol.") => "core.protocol-message@1",
        _ => return Err("runner does not recognize published v5 case".to_owned()),
    };
    if case.capability != required {
        return Err(format!("expected capability {required}"));
    }
    match case.id {
        "registry.v5-manifest" => registry_v5_manifest(case),
        "registry.v1-v4-frozen" => registry_frozen(case),
        "registry.v5-additive-contracts" => registry_additions(case),
        "registry.v5-error-codes" => registry_error_codes(case),
        "portable-graph.dual-transport" => portable_graph_transport(case),
        "portable-graph.reject-disagreement" => portable_graph_disagreement(case),
        "portable-graph.reject-node-limit" => portable_graph_limit(case),
        "graph-query.node-roundtrip"
        | "graph-query.sequence-roundtrip"
        | "graph-query.mapping-roundtrip"
        | "graph-query.reject-dangling-association" => graph_query(case),
        "graph-provenance.reject-order" => graph_provenance_order(case),
        "graph-projection.roundtrip" | "graph-projection.reject-out-of-range" => {
            graph_projection(case)
        }
        "yaml-query.native-roles" | "yaml-query.syntax-roundtrip" => yaml_query_roundtrip(case),
        "yaml-query.reject-domain-role" => yaml_query_domain_rejection(case),
        "yaml-query.reject-process-local" => yaml_query_process_local(case),
        "protocol.v4-reject-v5-contract" => protocol_v4_rejection(case),
        "protocol.v5-nested-error-code" => protocol_nested_error(case),
        "protocol.reject-truncated-pvce" => protocol_truncated_pvce(case),
        "protocol.reject-unknown-payload-field" => protocol_unknown_field(case),
        _ => Err("runner does not recognize published v5 case".to_owned()),
    }
}

fn registry_v5_manifest(case: &VectorCase<'_>) -> Result<(), String> {
    let manifest = RegistryManifest::v5();
    let roundtrip = RegistryManifest::from_value(&manifest.to_value()).map_err(string_error)?;
    require(
        manifest.semantic_model().schema() == expected_string(case, "semantic_model")?
            && manifest.contracts().len() == expected_usize(case, "contract_count")?
            && manifest.error_codes().len() == expected_usize(case, "error_code_count")?
            && roundtrip == manifest,
        "v5 manifest facts differ",
    )
}

fn registry_frozen(case: &VectorCase<'_>) -> Result<(), String> {
    let manifests = [
        RegistryManifest::v1(),
        RegistryManifest::v2(),
        RegistryManifest::v3(),
        RegistryManifest::v4(),
    ];
    let contract_counts = expected_usize_sequence(case, "contract_counts")?;
    let error_counts = expected_usize_sequence(case, "error_code_counts")?;
    require(
        manifests
            .iter()
            .zip(contract_counts.iter().zip(&error_counts))
            .enumerate()
            .all(|(index, (manifest, (contracts, errors)))| {
                manifest.semantic_model().version() == u32::try_from(index + 1).unwrap()
                    && manifest.contracts().len() == *contracts
                    && manifest.error_codes().len() == *errors
                    && !manifest.is_current()
                    && RegistryManifest::from_value(&manifest.to_value()).as_ref() == Ok(manifest)
            }),
        "a frozen registry changed",
    )
}

fn registry_additions(case: &VectorCase<'_>) -> Result<(), String> {
    let v4 = ContractRegistry::v4();
    let v5 = ContractRegistry::v5();
    let actual = v5
        .contracts()
        .iter()
        .filter(|candidate| {
            !v4.contracts()
                .iter()
                .any(|old| old.id == candidate.id && old.version == candidate.version)
        })
        .map(|descriptor| format!("{}@{}", descriptor.id, descriptor.version))
        .collect::<Vec<_>>();
    require(
        actual == expected_string_sequence(case, "contracts")?,
        format!("v5 additions differ: {actual:?}"),
    )
}

fn registry_error_codes(case: &VectorCase<'_>) -> Result<(), String> {
    let v4 = ErrorCodeRegistry::v4();
    let v5 = ErrorCodeRegistry::v5();
    let additions = v5
        .codes()
        .iter()
        .filter(|descriptor| !v4.contains(descriptor.code))
        .map(|descriptor| descriptor.code.to_owned())
        .collect::<Vec<_>>();
    let expected = expected_string_sequence(case, "new_codes")?;
    require(
        v5.codes().len() == expected_usize(case, "error_code_count")? && additions == expected,
        format!("v5 error additions differ: {additions:?}"),
    )
}

fn portable_graph_transport(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = input_graph(case)?;
    let payload =
        PortableGraphMessage::from_graph(graph, PgceLimits::default()).map_err(string_error)?;
    require(
        hex(payload.pgce()) == expected_string(case, "pgce_hex")?,
        format!("PGCE hex was {}", hex(payload.pgce())),
    )?;
    let message = protocol_message("core.portable-graph", payload.to_value())?;
    let limits = ProtocolLimits::default();
    let json = message.to_json(limits).map_err(string_error)?;
    let pvce = message.to_pvce(limits).map_err(string_error)?;
    let json_roundtrip =
        ProtocolMessage::from_json(&json, limits, ContractRegistry::v5()).map_err(string_error)?;
    let pvce_roundtrip =
        ProtocolMessage::from_pvce(&pvce, limits, ContractRegistry::v5()).map_err(string_error)?;
    require(
        json_roundtrip == message
            && pvce_roundtrip == message
            && digest(&json) == expected_string(case, "json_sha256")?
            && digest(&pvce) == expected_string(case, "pvce_sha256")?,
        format!(
            "transport identity differed: json={}, pvce={}",
            digest(&json),
            digest(&pvce)
        ),
    )
}

fn portable_graph_disagreement(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let value = graph.to_value();
    let nodes = field(&value, "nodes")?
        .as_sequence()
        .ok_or("nodes must be Sequence")?;
    let index = input_usize(case, "node_index")?;
    let mut changed_nodes = SequenceBuilder::new();
    for (ordinal, node) in nodes.iter().enumerate() {
        changed_nodes.push(if ordinal == index {
            replace_field(
                node,
                "canonical_content",
                PortableValue::string(input_string(case, "replacement")?),
            )?
        } else {
            node.clone()
        });
    }
    let changed = replace_field(&value, "nodes", changed_nodes.build())?;
    match PortableGraphMessage::from_value(&changed, PgceLimits::default()) {
        Ok(_) => Err("readable and PGCE forms unexpectedly agreed".to_owned()),
        Err(error) => require(
            error.code() == expected_string(case, "code")?,
            error.to_string(),
        ),
    }
}

fn portable_graph_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let message = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let limits = PgceLimits {
        max_nodes: input_usize(case, "max_nodes")?,
        ..PgceLimits::default()
    };
    let error = PortableGraphMessage::from_value(&message.to_value(), limits).unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn graph_query(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let role = parse_role(input_string(case, "role")?)?;
    let query_match = parse_graph_match(input_field(case, "match")?)?;
    let completion =
        Completion::new(CompletionStatus::Success, 1, 1, None, None).map_err(string_error)?;
    match GraphQueryResultMessage::new(
        QueryDomain::portable_graph_v1(),
        role,
        graph,
        vec![query_match],
        completion,
        Vec::new(),
    ) {
        Ok(result) => {
            require(expected_bool(case, "accepted")?, "expected rejection")?;
            dual_roundtrip("core.graph-query-result", result.to_value())
        }
        Err(error) => require(
            !expected_bool(case, "accepted")? && error.code() == expected_string(case, "code")?,
            error.to_string(),
        ),
    }
}

fn graph_provenance_order(case: &VectorCase<'_>) -> Result<(), String> {
    let entries = provenance_entries(case)?;
    let error = GraphProvenanceMapMessage::new(entries).unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn graph_projection(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let provenance =
        GraphProvenanceMapMessage::new(provenance_entries(case)?).map_err(string_error)?;
    let completion =
        Completion::new(CompletionStatus::Success, 1, 1, None, None).map_err(string_error)?;
    match GraphProjectionResultMessage::new(completion, Some(graph), provenance, Vec::new()) {
        Ok(result) => {
            require(expected_bool(case, "accepted")?, "expected rejection")?;
            dual_roundtrip("core.graph-projection-result", result.to_value())
        }
        Err(error) => require(
            !expected_bool(case, "accepted")? && error.code() == expected_string(case, "code")?,
            error.to_string(),
        ),
    }
}

fn yaml_query_roundtrip(case: &VectorCase<'_>) -> Result<(), String> {
    let roles = input_field(case, "roles")?
        .as_sequence()
        .ok_or("input.roles must be Sequence")?;
    let mut count = 0;
    for (ordinal, role) in roles.iter().enumerate() {
        let role = parse_role(role.as_string().ok_or("role must be String")?)?;
        let domain = if role == MatchRole::YamlSyntaxPiece {
            QueryDomain::yaml_lossless_syntax_v1()
        } else {
            QueryDomain::yaml_native_v1()
        };
        let locator = YamlMatchLocator::new(
            input_string(case, "source_id")?,
            format!("/nodes/{ordinal}"),
            role,
            u64::try_from(ordinal).unwrap(),
        )
        .map_err(string_error)?;
        let completion =
            Completion::new(CompletionStatus::Success, 1, 1, None, None).map_err(string_error)?;
        let result =
            YamlQueryResultMessage::new(domain, role, vec![locator], completion, Vec::new())
                .map_err(string_error)?;
        dual_roundtrip("core.yaml-query-result", result.to_value())?;
        count += 1;
    }
    require(
        count == expected_usize(case, "role_count")?,
        "role count differed",
    )
}

fn yaml_query_domain_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let role = parse_role(input_string(case, "role")?)?;
    let locator =
        YamlMatchLocator::new("sha256:source", "/syntax/0", role, 0).map_err(string_error)?;
    let completion =
        Completion::new(CompletionStatus::Success, 1, 1, None, None).map_err(string_error)?;
    let error = YamlQueryResultMessage::new(
        QueryDomain::yaml_native_v1(),
        role,
        vec![locator],
        completion,
        Vec::new(),
    )
    .unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn yaml_query_process_local(case: &VectorCase<'_>) -> Result<(), String> {
    let authority = DocumentAuthority::fresh();
    let node = authority.node_ref(0, NodeRole::YamlNode);
    let error = YamlMatchLocator::from_process_local(node).unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn protocol_v4_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let error = ProtocolMessage::new(
        contract("core.portable-graph")?,
        graph.to_value(),
        ContractRegistry::v4(),
    )
    .unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn protocol_nested_error(case: &VectorCase<'_>) -> Result<(), String> {
    let code = input_string(case, "failure_code")?;
    let v4 = Completion::new_with_registry(
        CompletionStatus::Failed,
        1,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v4(),
    );
    let completion = Completion::new_with_registry(
        CompletionStatus::Failed,
        1,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v5(),
    )
    .map_err(string_error)?;
    let message = protocol_message("core.completion", completion.to_value())?;
    let decoded = ProtocolMessage::from_value(&message.to_value(), ContractRegistry::v5())
        .map_err(string_error)?;
    require(
        v4.as_ref()
            .is_err_and(|error| error.code() == expected_string(case, "v4_code").unwrap())
            && decoded == message,
        "selected nested registry behavior differed",
    )
}

fn protocol_truncated_pvce(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let message = protocol_message("core.portable-graph", graph.to_value())?;
    let mut bytes = message
        .to_pvce(ProtocolLimits::default())
        .map_err(string_error)?;
    bytes.truncate(
        bytes
            .len()
            .saturating_sub(input_usize(case, "truncate_bytes")?),
    );
    let error =
        ProtocolMessage::from_pvce(&bytes, ProtocolLimits::default(), ContractRegistry::v5())
            .unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn protocol_unknown_field(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = PortableGraphMessage::from_graph(input_graph(case)?, PgceLimits::default())
        .map_err(string_error)?;
    let changed = append_field(&graph.to_value(), "unknown", PortableValue::null())?;
    let error = ProtocolMessage::new(
        contract("core.portable-graph")?,
        changed,
        ContractRegistry::v5(),
    )
    .unwrap_err();
    require(
        error.code() == expected_string(case, "code")?,
        error.to_string(),
    )
}

fn dual_roundtrip(contract_id: &str, payload: PortableValue) -> Result<(), String> {
    let message = protocol_message(contract_id, payload)?;
    let limits = ProtocolLimits::default();
    let json = message.to_json(limits).map_err(string_error)?;
    let pvce = message.to_pvce(limits).map_err(string_error)?;
    require(
        ProtocolMessage::from_json(&json, limits, ContractRegistry::v5()).map_err(string_error)?
            == message
            && ProtocolMessage::from_pvce(&pvce, limits, ContractRegistry::v5())
                .map_err(string_error)?
                == message,
        "dual transport did not close",
    )
}

fn protocol_message(contract_id: &str, payload: PortableValue) -> Result<ProtocolMessage, String> {
    ProtocolMessage::new(contract(contract_id)?, payload, ContractRegistry::v5())
        .map_err(string_error)
}

fn contract(id: &str) -> Result<ContractId, String> {
    ContractId::new(id, 1).map_err(string_error)
}

fn input_graph(case: &VectorCase<'_>) -> Result<PortableGraph, String> {
    graph_from_value(input_field(case, "graph")?)
}

fn graph_from_value(value: &PortableValue) -> Result<PortableGraph, String> {
    let fields = value.as_object().ok_or("graph must be Object")?;
    let nodes = object_field(fields, "nodes")
        .and_then(PortableValue::as_sequence)
        .ok_or("graph.nodes must be Sequence")?;
    let roots = object_field(fields, "roots")
        .and_then(PortableValue::as_sequence)
        .ok_or("graph.roots must be Sequence")?;
    let mut builder = GraphBuilder::new(GraphLimits::default());
    let ids = (0..nodes.len())
        .map(|_| builder.reserve_node().map_err(string_error))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, node) in nodes.iter().enumerate() {
        let node = node.as_object().ok_or("graph node must be Object")?;
        let kind = object_string(node, "kind")?;
        let tag = object_string(node, "tag")?;
        match kind {
            "Scalar" => {
                builder
                    .define_scalar(ids[index], tag, object_string(node, "content")?)
                    .map_err(string_error)?;
            }
            "Sequence" => {
                let items = object_field(node, "items")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("sequence.items must be Sequence")?
                    .iter()
                    .map(|item| graph_reference(item, &ids))
                    .collect::<Result<Vec<_>, _>>()?;
                builder
                    .define_sequence(ids[index], tag, items)
                    .map_err(string_error)?;
            }
            "Mapping" => {
                let entries = object_field(node, "entries")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("mapping.entries must be Sequence")?
                    .iter()
                    .map(|entry| {
                        let fields = entry.as_object().ok_or("mapping entry must be Object")?;
                        Ok(GraphMappingEntry::new(
                            graph_reference(
                                object_field(fields, "key").ok_or("missing key")?,
                                &ids,
                            )?,
                            graph_reference(
                                object_field(fields, "value").ok_or("missing value")?,
                                &ids,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                builder
                    .define_mapping(ids[index], tag, entries)
                    .map_err(string_error)?;
            }
            _ => return Err("unknown graph node kind".to_owned()),
        }
    }
    for root in roots {
        builder
            .push_root(graph_reference(root, &ids)?)
            .map_err(string_error)?;
    }
    builder.build().map_err(string_error)
}

fn graph_reference(
    value: &PortableValue,
    ids: &[consema_graph::GraphNodeId],
) -> Result<consema_graph::GraphNodeId, String> {
    value
        .as_integer()
        .and_then(BigInteger::to_usize)
        .and_then(|index| ids.get(index).copied())
        .ok_or_else(|| "graph reference out of range".to_owned())
}

fn parse_graph_match(value: &PortableValue) -> Result<GraphQueryMatchMessage, String> {
    let fields = value.as_object().ok_or("match must be Object")?;
    match object_string(fields, "kind")? {
        "Node" => Ok(GraphQueryMatchMessage::Node {
            node: object_u64(fields, "node")?,
        }),
        "SequenceElement" => Ok(GraphQueryMatchMessage::SequenceElement {
            parent: object_u64(fields, "parent")?,
            ordinal: object_u64(fields, "ordinal")?,
            node: object_u64(fields, "node")?,
        }),
        "MappingEntry" => Ok(GraphQueryMatchMessage::MappingEntry {
            parent: object_u64(fields, "parent")?,
            ordinal: object_u64(fields, "ordinal")?,
            key: object_u64(fields, "key")?,
            value: object_u64(fields, "value")?,
        }),
        _ => Err("unknown graph match kind".to_owned()),
    }
}

fn provenance_entries(case: &VectorCase<'_>) -> Result<Vec<GraphProvenanceEntryMessage>, String> {
    input_field(case, "locations")?
        .as_sequence()
        .ok_or("input.locations must be Sequence")?
        .iter()
        .map(|location| {
            Ok(GraphProvenanceEntryMessage {
                projected: parse_location(location)?,
                origins: vec![
                    GraphSourceOriginMessage::new(
                        input_string(case, "source_id")?,
                        Some(input_string(case, "node_locator")?.to_owned()),
                        input_u64(case, "start_byte")?,
                        input_u64(case, "end_byte")?,
                        match input_string(case, "relation")? {
                            "Direct" => GraphProvenanceRelationMessage::Direct,
                            "Reference" => GraphProvenanceRelationMessage::Reference,
                            _ => return Err("unknown graph provenance relation".to_owned()),
                        },
                    )
                    .map_err(string_error)?,
                ],
            })
        })
        .collect()
}

fn parse_location(value: &PortableValue) -> Result<GraphProjectedLocationMessage, String> {
    let fields = value.as_object().ok_or("location must be Object")?;
    match object_string(fields, "kind")? {
        "Root" => Ok(GraphProjectedLocationMessage::Root(object_u64(
            fields, "ordinal",
        )?)),
        "Node" => Ok(GraphProjectedLocationMessage::Node(object_u64(
            fields, "node",
        )?)),
        "SequenceElement" => Ok(GraphProjectedLocationMessage::SequenceElement {
            parent: object_u64(fields, "parent")?,
            ordinal: object_u64(fields, "ordinal")?,
        }),
        "MappingKey" => Ok(GraphProjectedLocationMessage::MappingKey {
            parent: object_u64(fields, "parent")?,
            ordinal: object_u64(fields, "ordinal")?,
        }),
        "MappingValue" => Ok(GraphProjectedLocationMessage::MappingValue {
            parent: object_u64(fields, "parent")?,
            ordinal: object_u64(fields, "ordinal")?,
        }),
        _ => Err("unknown projected location".to_owned()),
    }
}

fn parse_role(value: &str) -> Result<MatchRole, String> {
    match value {
        "GraphNode" => Ok(MatchRole::GraphNode),
        "GraphSequenceElement" => Ok(MatchRole::GraphSequenceElement),
        "GraphMappingEntry" => Ok(MatchRole::GraphMappingEntry),
        "YamlStream" => Ok(MatchRole::YamlStream),
        "YamlDocument" => Ok(MatchRole::YamlDocument),
        "YamlNode" => Ok(MatchRole::YamlNode),
        "YamlMappingEntry" => Ok(MatchRole::YamlMappingEntry),
        "YamlSequenceElement" => Ok(MatchRole::YamlSequenceElement),
        "YamlAnchorDefinition" => Ok(MatchRole::YamlAnchorDefinition),
        "YamlAliasOccurrence" => Ok(MatchRole::YamlAliasOccurrence),
        "YamlSyntaxPiece" => Ok(MatchRole::YamlSyntaxPiece),
        _ => Err(format!("unknown match role {value}")),
    }
}

fn field<'a>(value: &'a PortableValue, name: &str) -> Result<&'a PortableValue, String> {
    value
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing field {name}"))
}

fn replace_field(
    value: &PortableValue,
    target: &str,
    replacement: PortableValue,
) -> Result<PortableValue, String> {
    let fields = value.as_object().ok_or("value must be Object")?;
    if !fields.iter().any(|field| field.key() == target) {
        return Err(format!("field {target} is absent"));
    }
    let mut builder = ObjectBuilder::new();
    for field in fields {
        builder
            .insert(
                field.key(),
                if field.key() == target {
                    replacement.clone()
                } else {
                    field.value().clone()
                },
            )
            .map_err(string_error)?;
    }
    Ok(builder.build())
}

fn append_field(
    value: &PortableValue,
    name: &str,
    appended: PortableValue,
) -> Result<PortableValue, String> {
    let fields = value.as_object().ok_or("value must be Object")?;
    let mut builder = ObjectBuilder::new();
    for field in fields {
        builder
            .insert(field.key(), field.value().clone())
            .map_err(string_error)?;
    }
    builder.insert(name, appended).map_err(string_error)?;
    Ok(builder.build())
}

fn input_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.input
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing input.{name}"))
}

fn expected_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing expected.{name}"))
}

fn input_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    input_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("input.{name} must be String"))
}

fn expected_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    expected_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("expected.{name} must be String"))
}

fn expected_bool(case: &VectorCase<'_>, name: &str) -> Result<bool, String> {
    expected_field(case, name)?
        .as_boolean()
        .ok_or_else(|| format!("expected.{name} must be Boolean"))
}

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be host-size Integer"))
}

fn input_u64(case: &VectorCase<'_>, name: &str) -> Result<u64, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| format!("input.{name} must be non-negative Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be host-size Integer"))
}

fn expected_usize_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<usize>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_usize)
                .ok_or_else(|| format!("expected.{name} item must be host-size Integer"))
        })
        .collect()
}

fn expected_string_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<String>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("expected.{name} item must be String"))
        })
        .collect()
}

fn object_string<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a str, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("{name} must be String"))
}

fn object_u64(fields: &[consema_core::ObjectEntry], name: &str) -> Result<u64, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| format!("{name} must be non-negative Integer"))
}

fn digest(bytes: &[u8]) -> String {
    ContentDigest::of(bytes).to_hex()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("String write cannot fail");
        output
    })
}

fn require(condition: bool, detail: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_semantic_model_v5_suite_is_conformant() {
        let report = run_semantic_model_v5();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 22);
    }

    #[test]
    fn semantic_model_v5_vectors_drive_inputs_and_expectations() {
        let changed = SEMANTIC_MODEL_V5_VECTORS_JSON.replacen(
            "\"contract_count\": 30",
            "\"contract_count\": 29",
            1,
        );
        let report = run_semantic_model_v5_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "registry.v5-manifest"),
            "{report:#?}"
        );

        let changed = SEMANTIC_MODEL_V5_VECTORS_JSON.replacen(
            "\"replacement\": \"changed\"",
            "\"replacement\": \"k\"",
            1,
        );
        let report = run_semantic_model_v5_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "portable-graph.reject-disagreement"),
            "{report:#?}"
        );
    }
}
