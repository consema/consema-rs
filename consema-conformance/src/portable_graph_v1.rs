//! Language-neutral PortableGraph and PGCE/1 conformance runner.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, OperatorCall, PortableValue,
    QueryDefinition, QueryDomain, QueryExpression, QueryLimits,
};
use consema_graph::{
    GraphBuilder, GraphLimits, GraphMappingEntry, PgceDecodeError, PgceEncodeError, PgceLimits,
    PortableGraph, decode_pgce, encode_pgce, encode_pgce_bounded,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};

use super::{ConformanceReport, VectorCase, ensure, object_field};

const SUITE: &str = "consema.portable-graph.conformance@1";

/// Embedded language-neutral PortableGraph suite bytes.
pub const PORTABLE_GRAPH_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/portable-graph-v1.json");

/// Runs the embedded `consema.portable-graph.conformance@1` suite.
#[must_use]
pub fn run_portable_graph_v1() -> ConformanceReport {
    run_portable_graph_v1_json(PORTABLE_GRAPH_V1_VECTORS_JSON)
}

/// Runs one language-neutral PortableGraph suite from strict JSON text.
#[must_use]
pub fn run_portable_graph_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published graph vector JSON must form a document");
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
    let root = value.as_object().expect("graph vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    if suite != SUITE {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "unexpected suite identifier".to_owned(),
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
        let fields = case.as_object().expect("graph case object");
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
    let required_capability = match case.id {
        id if id.starts_with("pgce.") || id.starts_with("resource.pgce-") => "core.pgce.full@1",
        id if id.starts_with("graph.") => "core.portable-graph.strict-equality@1",
        id if id.starts_with("query.") => "core.portable-graph-query@1",
        _ => return Err("runner does not recognize published graph case".to_owned()),
    };
    if case.capability != required_capability {
        return Err("case capability does not match its operation".to_owned());
    }
    match case.id {
        "pgce.empty-vector" | "pgce.scalar-vector" => pgce_vector(case),
        "graph.isomorphic-builder-numbering" | "graph.sharing-is-not-duplication" => {
            graph_equality(case)
        }
        "pgce.cycle-roundtrip" => pgce_roundtrip(case),
        "pgce.reject-nonminimal-varint" | "pgce.reject-noncanonical-node-order" => {
            pgce_rejection(case)
        }
        "query.reachable-canonical-order" | "query.distinct-shared-identity" => graph_query(case),
        "resource.pgce-stream-limit" => pgce_limit(case),
        _ => Err("runner does not recognize published graph case".to_owned()),
    }
}

fn pgce_vector(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = input_graph(case, "graph")?;
    ensure(
        hex(&encode_pgce(&graph).map_err(|error| format!("{error:?}"))?)
            == expected_string(case, "hex")?,
    )
}

fn graph_equality(case: &VectorCase<'_>) -> Result<(), String> {
    let left = input_graph(case, "left")?;
    let right = input_graph(case, "right")?;
    let equal = left == right;
    let bytes_equal = encode_pgce(&left).map_err(|error| format!("{error:?}"))?
        == encode_pgce(&right).map_err(|error| format!("{error:?}"))?;
    let mut left_hasher = DefaultHasher::new();
    left.hash(&mut left_hasher);
    let mut right_hasher = DefaultHasher::new();
    right.hash(&mut right_hasher);
    let expected_equal = expected_bool(case, "strict_equal")?;
    let hash_matches = expected_optional_bool(case, "strict_hash_equal")?
        .is_none_or(|expected| (left_hasher.finish() == right_hasher.finish()) == expected);
    ensure(
        equal == expected_equal
            && bytes_equal == expected_bool(case, "pgce_equal")?
            && hash_matches,
    )
}

fn pgce_roundtrip(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = input_graph(case, "graph")?;
    let bytes = encode_pgce(&graph).map_err(|error| format!("{error:?}"))?;
    let decoded =
        decode_pgce(&bytes, PgceLimits::default()).map_err(|error| format!("{error:?}"))?;
    ensure(
        (decoded == graph) == expected_bool(case, "strict_equal")?
            && (encode_pgce(&decoded).map_err(|error| format!("{error:?}"))? == bytes)
                == expected_bool(case, "byte_stable")?,
    )
}

fn pgce_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let bytes = decode_hex(input_string(case, "hex")?)?;
    let error = decode_pgce(&bytes, PgceLimits::default())
        .expect_err("published rejection vector must fail");
    ensure(
        decode_error_name(&error) == expected_string(case, "failure")?
            && !expected_bool(case, "partial_graph")?,
    )
}

fn graph_query(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = input_graph(case, "graph")?;
    let pipeline = input_field(case, "pipeline")?
        .as_sequence()
        .ok_or("input.pipeline must be Sequence")?;
    let mut expression = QueryExpression::Input;
    for item in pipeline {
        let operator = item.as_string().ok_or("pipeline operator must be String")?;
        let (id, version) = parse_operator(operator)?;
        expression = expression.then(OperatorCall::new(id, version));
    }
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let query = QueryDefinition::new(QueryDomain::portable_graph_v1())
        .with_expression(expression)
        .validate()
        .map_err(|error| format!("{error:?}"))?
        .bind(&capabilities)
        .map_err(|error| format!("{error:?}"))?;
    let result = graph
        .query(&query, QueryLimits::default(), &CancellationToken::new())
        .map_err(|error| format!("{error:?}"))?;
    let ids = result
        .matches()
        .iter()
        .map(|item| {
            item.node()
                .map(consema_graph::GraphNodeId::as_u64)
                .ok_or("query result was not a node")
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure(
        ids == expected_u64_sequence(case, "builder_node_ids")?
            && ids.len() == expected_usize(case, "count")?,
    )
}

fn pgce_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let graph = input_graph(case, "graph")?;
    let limits = PgceLimits {
        max_stream_bytes: input_usize(case, "max_stream_bytes")?,
        ..PgceLimits::default()
    };
    let error =
        encode_pgce_bounded(&graph, limits).expect_err("published resource vector must fail");
    let (name, kind) = match error {
        PgceEncodeError::ResourceLimit { name, .. } => (name, "ResourceLimit"),
        PgceEncodeError::SizeOverflow => ("", "SizeOverflow"),
    };
    ensure(
        kind == expected_string(case, "failure")?
            && name == expected_string(case, "limit")?
            && !expected_bool(case, "partial_bytes")?,
    )
}

fn input_graph(case: &VectorCase<'_>, name: &str) -> Result<PortableGraph, String> {
    graph_from_value(input_field(case, name)?)
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
    let mut ids = Vec::with_capacity(nodes.len());
    for _ in nodes {
        ids.push(
            builder
                .reserve_node()
                .map_err(|error| format!("{error:?}"))?,
        );
    }
    for (index, node) in nodes.iter().enumerate() {
        let node_fields = node.as_object().ok_or("graph node must be Object")?;
        let kind = object_string(node_fields, "kind")?;
        let tag = object_string(node_fields, "tag")?;
        match kind {
            "Scalar" => {
                builder
                    .define_scalar(ids[index], tag, object_string(node_fields, "content")?)
                    .map_err(|error| format!("{error:?}"))?;
            }
            "Sequence" => {
                let items = object_field(node_fields, "items")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("sequence.items must be Sequence")?
                    .iter()
                    .map(|item| graph_reference(item, &ids))
                    .collect::<Result<Vec<_>, _>>()?;
                builder
                    .define_sequence(ids[index], tag, items)
                    .map_err(|error| format!("{error:?}"))?;
            }
            "Mapping" => {
                let entries = object_field(node_fields, "entries")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("mapping.entries must be Sequence")?
                    .iter()
                    .map(|entry| {
                        let entry = entry.as_object().ok_or("mapping entry must be Object")?;
                        Ok(GraphMappingEntry::new(
                            graph_reference(
                                object_field(entry, "key").ok_or("mapping entry key missing")?,
                                &ids,
                            )?,
                            graph_reference(
                                object_field(entry, "value")
                                    .ok_or("mapping entry value missing")?,
                                &ids,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                builder
                    .define_mapping(ids[index], tag, entries)
                    .map_err(|error| format!("{error:?}"))?;
            }
            _ => return Err("unknown graph node kind".to_owned()),
        }
    }
    for root in roots {
        builder
            .push_root(graph_reference(root, &ids)?)
            .map_err(|error| format!("{error:?}"))?;
    }
    builder.build().map_err(|error| format!("{error:?}"))
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

fn parse_operator(value: &str) -> Result<(&str, u32), String> {
    let (id, version) = value
        .rsplit_once('@')
        .ok_or("operator must include @version")?;
    let version = version
        .parse::<u32>()
        .map_err(|_| "invalid operator version".to_owned())?;
    Ok((id, version))
}

fn input_field<'a>(case: &VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.input
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing input.{name}"))
}

fn expected_field<'a>(case: &VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing expected.{name}"))
}

fn input_string<'a>(case: &VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    input_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("input.{name} must be String"))
}

fn expected_string<'a>(case: &VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    expected_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("expected.{name} must be String"))
}

fn expected_bool(case: &VectorCase<'_>, name: &str) -> Result<bool, String> {
    expected_field(case, name)?
        .as_boolean()
        .ok_or_else(|| format!("expected.{name} must be Boolean"))
}

fn expected_optional_bool(case: &VectorCase<'_>, name: &str) -> Result<Option<bool>, String> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .map(|value| {
            value
                .as_boolean()
                .ok_or_else(|| format!("expected.{name} must be Boolean"))
        })
        .transpose()
}

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be non-negative Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be non-negative Integer"))
}

fn expected_u64_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<u64>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_i64)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| format!("expected.{name} item must be non-negative Integer"))
        })
        .collect()
}

fn object_string<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a str, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("object.{name} must be String"))
}

fn decode_error_name(error: &PgceDecodeError) -> &'static str {
    match error {
        PgceDecodeError::ResourceLimit { .. } => "ResourceLimit",
        PgceDecodeError::InvalidMagic => "InvalidMagic",
        PgceDecodeError::UnsupportedVersion(_) => "UnsupportedVersion",
        PgceDecodeError::UnexpectedEof => "UnexpectedEof",
        PgceDecodeError::NonMinimalVarint => "NonMinimalVarint",
        PgceDecodeError::VarintOverflow => "VarintOverflow",
        PgceDecodeError::UnknownNodeKind(_) => "UnknownNodeKind",
        PgceDecodeError::InvalidUtf8 => "InvalidUtf8",
        PgceDecodeError::InvalidTag => "InvalidTag",
        PgceDecodeError::ReferenceOutOfRange(_) => "ReferenceOutOfRange",
        PgceDecodeError::NonCanonicalNodeOrder => "NonCanonicalNodeOrder",
        PgceDecodeError::TrailingBytes => "TrailingBytes",
        PgceDecodeError::InvalidGraph(_) => "InvalidGraph",
        PgceDecodeError::NonCanonicalEncoding => "NonCanonicalEncoding",
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, octet| {
        write!(output, "{octet:02x}").expect("String write");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_portable_graph_v1_suite_is_conformant() {
        let report = run_portable_graph_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 10);
    }

    #[test]
    fn graph_vector_inputs_and_expectations_drive_results() {
        let changed_expectation =
            PORTABLE_GRAPH_V1_VECTORS_JSON.replace("50474345010000", "50474345010001");
        let report = run_portable_graph_v1_json(&changed_expectation);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "pgce.empty-vector"),
            "{report:#?}"
        );

        let changed_input =
            PORTABLE_GRAPH_V1_VECTORS_JSON.replacen("\"content\": \"x\"", "\"content\": \"y\"", 1);
        let report = run_portable_graph_v1_json(&changed_input);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "pgce.scalar-vector"),
            "{report:#?}"
        );

        let changed_suite = PORTABLE_GRAPH_V1_VECTORS_JSON.replace(
            "consema.portable-graph.conformance@1",
            "consema.portable-graph.conformance@2",
        );
        let report = run_portable_graph_v1_json(&changed_suite);
        assert_eq!(report.failed[0].0, "suite.schema");

        let changed_capability = PORTABLE_GRAPH_V1_VECTORS_JSON.replacen(
            "core.portable-graph.strict-equality@1",
            "core.portable-graph.strict-equality@2",
            1,
        );
        let report = run_portable_graph_v1_json(&changed_capability);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "graph.isomorphic-builder-numbering"),
            "{report:#?}"
        );
    }
}
