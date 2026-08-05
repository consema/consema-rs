//! Language-neutral conformance vectors and Rust reference runner.

mod ini_v1;
mod json_family_v2;
mod operations_v1;
mod portable_graph_v1;
mod properties_v1;
mod protocol_v1;
mod protocol_v2;
mod semantic_model_v5;
mod semantic_model_v6;
mod source_v1;
mod syntax_query_v1;
mod toml_v1;
mod yaml_v1;

use consema_core::{
    BigInteger, BinaryFloat64, CapabilityId, CapabilitySet, Decimal, ObjectBuilder, OperatorCall,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QuerySelection, SequenceBuilder,
};
use consema_document::{FormationStatus, ParseLimits};
use consema_json::{
    DuplicateKeyPolicy, EditFailure, EditTransactionBuilder, Fidelity, JsonMatch, JsonProfile,
    ProjectionEventKind, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget,
    RepresentationPolicy, SemanticAvailability, execute_json_query, parse,
};
use consema_pvce::{
    DecodeError, DecodeLimits, EncodeError, EncodeLimits, decode, encode, encode_bounded,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub use ini_v1::{INI_V1_VECTORS_JSON, run_ini_v1, run_ini_v1_json};
pub use json_family_v2::{
    JSON_FAMILY_V2_VECTORS_JSON, JSON5_REFERENCE_CORPUS_JSON, run_json_family_v2,
    run_json_family_v2_json, run_json5_reference_corpus, run_json5_reference_corpus_json,
};
pub use operations_v1::{OPERATIONS_V1_VECTORS_JSON, run_operations_v1, run_operations_v1_json};
pub use portable_graph_v1::{
    PORTABLE_GRAPH_V1_VECTORS_JSON, run_portable_graph_v1, run_portable_graph_v1_json,
};
pub use properties_v1::{PROPERTIES_V1_VECTORS_JSON, run_properties_v1, run_properties_v1_json};
pub use protocol_v1::{PROTOCOL_V1_VECTORS_JSON, run_protocol_v1};
pub use protocol_v2::{PROTOCOL_V2_VECTORS_JSON, run_protocol_v2, run_protocol_v2_json};
pub use semantic_model_v5::{
    SEMANTIC_MODEL_V5_VECTORS_JSON, run_semantic_model_v5, run_semantic_model_v5_json,
};
pub use semantic_model_v6::{
    SEMANTIC_MODEL_V6_VECTORS_JSON, run_semantic_model_v6, run_semantic_model_v6_json,
};
pub use source_v1::{SOURCE_V1_VECTORS_JSON, run_source_v1, run_source_v1_json};
pub use syntax_query_v1::{
    SYNTAX_QUERY_V1_VECTORS_JSON, run_syntax_query_v1, run_syntax_query_v1_json,
};
pub use toml_v1::{TOML_V1_VECTORS_JSON, run_toml_v1};
pub use yaml_v1::{YAML_V1_VECTORS_JSON, run_yaml_v1, run_yaml_v1_json};

/// Embedded language-neutral suite bytes.
pub const V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/v1.json");

/// Complete conformance run result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    /// Suite identifier read from the vector file.
    pub suite: String,
    /// Stable passing case IDs.
    pub passed: Vec<String>,
    /// Stable case IDs and failure descriptions.
    pub failed: Vec<(String, String)>,
}

impl ConformanceReport {
    /// Whether every published vector passed.
    #[must_use]
    pub fn is_conformant(&self) -> bool {
        self.failed.is_empty()
    }
}

/// One published case with its declared capability, input and expectation.
///
/// Every handler reads the operation data from these fields; the vector data
/// drives the result rather than hard-coded literals.
pub struct VectorCase<'a> {
    /// Stable case identifier.
    pub id: &'a str,
    /// Declared mandatory capability.
    pub capability: &'a str,
    /// Operation input facts.
    pub input: &'a PortableValue,
    /// Public expectation facts.
    pub expected: &'a PortableValue,
}

/// Runs the embedded `consema.conformance@1` suite.
#[must_use]
pub fn run_v1() -> ConformanceReport {
    run_v1_json(V1_VECTORS_JSON)
}

/// Runs one `consema.conformance@1` suite from JSON bytes.
#[must_use]
pub fn run_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.conformance@1".to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = std::collections::HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let object = case.as_object().expect("case object");
        let id = object_field(object, "id")
            .and_then(PortableValue::as_string)
            .expect("case id");
        let capability = object_field(object, "capability")
            .and_then(PortableValue::as_string)
            .expect("case capability");
        let input = object_field(object, "input").expect("case input");
        let expected = object_field(object, "expected").expect("case expected");
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

fn object_field<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Option<&'a PortableValue> {
    entries
        .iter()
        .find(|entry| entry.key() == key)
        .map(consema_core::ObjectEntry::value)
}

fn case_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.input
        .as_object()
        .and_then(|entries| object_field(entries, key))
}

fn expected_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.expected
        .as_object()
        .and_then(|entries| object_field(entries, key))
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    match case.id {
        "value.integer-arbitrary-precision" => {
            let text = case_field(case, "decimal")
                .and_then(PortableValue::as_string)
                .ok_or("missing input.decimal")?;
            let expected = expected_field(case, "decimal")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected.decimal")?;
            ensure(
                BigInteger::parse_decimal(text)
                    .map_err(|error| format!("{error:?}"))?
                    .to_string()
                    == expected,
            )
        }
        "value.decimal-normalization" => {
            let left = decimal_field(case, "left")?;
            let right = decimal_field(case, "right")?;
            let equal = expected_field(case, "strict_equal")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing expected.strict_equal")?;
            let hash_equal = expected_field(case, "strict_hash_equal")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing expected.strict_hash_equal")?;
            ensure(
                (left == right) == equal
                    && (strict_hash(&left) == strict_hash(&right)) == hash_equal,
            )
        }
        "value.float-signed-zero" => {
            let positive = hex_bits(case, "positive_bits")?;
            let negative = hex_bits(case, "negative_bits")?;
            let expected = expected_field(case, "strict_equal")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing expected.strict_equal")?;
            ensure(
                (PortableValue::binary_float64(BinaryFloat64::from_bits(positive))
                    == PortableValue::binary_float64(BinaryFloat64::from_bits(negative)))
                    == expected,
            )
        }
        "pvce.null-vector" => {
            let expected = expected_hex(case)?;
            ensure(hex(&encode(&PortableValue::null())) == expected)
        }
        "pvce.negative-integer-vector" => {
            let text = case_field(case, "integer")
                .and_then(PortableValue::as_string)
                .ok_or("missing input.integer")?;
            let expected = expected_hex(case)?;
            ensure(
                hex(&encode(&PortableValue::integer(
                    BigInteger::parse_decimal(text).map_err(|error| format!("{error:?}"))?,
                ))) == expected,
            )
        }
        "pvce.object-vector" => {
            let object =
                value_from_input(case_field(case, "object").ok_or("missing input.object")?)
                    .ok_or("unrepresentable input.object")?;
            let expected = expected_hex(case)?;
            ensure(hex(&encode(&object)) == expected)
        }
        "pvce.reject-nonminimal-varint" => {
            let bytes = input_hex(case)?;
            ensure(matches!(
                decode(&bytes, DecodeLimits::default()),
                Err(DecodeError::NonCanonicalVarint)
            ))
        }
        "pvce.encode-blob-limit" => {
            let value = value_from_input(case_field(case, "value").ok_or("missing input.value")?)
                .ok_or("unrepresentable input.value")?;
            let limit = usize_field(case, "max_blob_bytes")?;
            ensure(matches!(
                encode_bounded(
                    &value,
                    EncodeLimits {
                        max_blob_bytes: limit,
                        ..EncodeLimits::default()
                    }
                ),
                Err(EncodeError::ResourceLimit("blob-bytes"))
            ))
        }
        "parse.strict-exact-roundtrip" | "parse.jsonc-comments-trailing-comma" => {
            parse_exact_case(case)
        }
        "parse.recovery-missing-close" => {
            let (source, profile) = parse_inputs(case)?;
            let document = parse(source.as_bytes(), profile, ParseLimits::default())
                .map_err(|error| format!("{error:?}"))?;
            let formation = expected_field(case, "formation")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected.formation")?;
            let diagnostic = expected_field(case, "diagnostic")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected.diagnostic")?;
            ensure(
                formation_status_name(document.formation_status()) == formation
                    && document
                        .diagnostics()
                        .iter()
                        .any(|item| item.code == diagnostic),
            )
        }
        "parse.duplicate-members" => duplicate_members(case),
        "parse.lossless-byte-coverage" => lossless_coverage(case),
        "query.reject-role-mismatch" => {
            let expression = pipeline(case)?.ok_or("missing input.pipeline")?;
            ensure(matches!(
                QueryDefinition::new(QueryDomain::portable_value_v1())
                    .with_expression(expression)
                    .validate(),
                Err(QueryFailure::InvalidOperatorComposition { .. })
            ))
        }
        "query.json-duplicate-order" => query_duplicate_order(case),
        "query.root-result-limit" => query_root_limit(case),
        "query.cursor-failure-terminal" => query_cursor_failure(case),
        "query.protocol-roundtrip" => query_protocol_roundtrip(case),
        "projection.best-exact-duplicate-mapping" => projection_best(case),
        "projection.object-reject-duplicates" => projection_reject(case),
        "projection.object-last-wins" => projection_last(case),
        "projection.object-key-provenance" => projection_key_provenance(case),
        "edit.scalar-minimal"
        | "edit.preserve-decimal-scale"
        | "edit.preserve-exponent-style"
        | "edit.canonical-for-profile"
        | "edit.preserve-else-canonical" => edit_semantic(case),
        "edit.preserve-incompatible-rejected" => edit_incompatible(case),
        "edit.wrong-snapshot" => edit_wrong_snapshot(case),
        "resource.parse-token-limit" => {
            let source = case_field(case, "source")
                .and_then(PortableValue::as_string)
                .ok_or("missing input.source")?;
            let limit = usize_field(case, "max_token_count")?;
            let limits = ParseLimits {
                max_token_count: limit,
                ..ParseLimits::default()
            };
            ensure(parse(source.as_bytes(), JsonProfile::StrictV1, limits).is_err())
        }
        _ => Err("runner does not recognize published case".to_owned()),
    }
}

fn ensure(condition: bool) -> Result<(), String> {
    condition
        .then_some(())
        .ok_or_else(|| "expected behavior did not match".to_owned())
}

fn strict_hash(value: &PortableValue) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, octet| {
        write!(output, "{octet:02x}").expect("String write");
        output
    })
}

fn input_hex(case: &VectorCase<'_>) -> Result<Vec<u8>, String> {
    let text = case_field(case, "hex")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.hex")?;
    decode_hex(text)
}

fn expected_hex(case: &VectorCase<'_>) -> Result<String, String> {
    expected_field(case, "hex")
        .and_then(PortableValue::as_string)
        .map(str::to_owned)
        .ok_or("missing expected.hex".to_owned())
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

fn hex_bits(case: &VectorCase<'_>, name: &str) -> Result<u64, String> {
    let text = case_field(case, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing input.{name}"))?;
    let bytes = decode_hex(text)?;
    if bytes.len() != 8 {
        return Err("expected 8 hex bytes".to_owned());
    }
    Ok(u64::from_be_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn decimal_field(case: &VectorCase<'_>, name: &str) -> Result<PortableValue, String> {
    let text = case_field(case, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing input.{name}"))?;
    Ok(PortableValue::decimal(
        Decimal::parse_json_number(text).map_err(|error| format!("{error:?}"))?,
    ))
}

fn usize_field(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    case_field(case, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("missing input.{name}"))
}

fn parse_inputs(case: &VectorCase<'_>) -> Result<(String, JsonProfile), String> {
    let source = case_field(case, "source")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.source")?
        .to_owned();
    let profile = match case_field(case, "profile")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.profile")?
    {
        "json.strict@1" => JsonProfile::StrictV1,
        "jsonc.bounded@1" => JsonProfile::JsoncBoundedV1,
        other => return Err(format!("unknown profile {other}")),
    };
    Ok((source, profile))
}

fn formation_status_name(status: FormationStatus) -> &'static str {
    match status {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    }
}

fn parse_exact_case(case: &VectorCase<'_>) -> Result<(), String> {
    let (source, profile) = parse_inputs(case)?;
    let document = parse(source.as_bytes(), profile, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))?;
    let formation = expected_field(case, "formation")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected.formation")?;
    let render_equals = expected_field(case, "render_equals_source")
        .and_then(PortableValue::as_boolean)
        .ok_or("missing expected.render_equals_source")?;
    ensure(
        formation_status_name(document.formation_status()) == formation
            && (document.render() == source.as_bytes()) == render_equals,
    )
}

fn duplicate_members(case: &VectorCase<'_>) -> Result<(), String> {
    let (source, profile) = parse_inputs(case)?;
    let document = parse(source.as_bytes(), profile, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))?;
    let SemanticAvailability::Available(Some(members)) = document.root().object_members() else {
        return Err("object semantics unavailable".to_owned());
    };
    let expected_names = expected_field(case, "member_names")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing expected.member_names")?;
    let distinct = expected_field(case, "distinct_member_identity")
        .and_then(PortableValue::as_boolean)
        .ok_or("missing expected.distinct_member_identity")?;
    let diagnostic = expected_field(case, "diagnostic")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected.diagnostic")?;
    let names: Vec<Option<&str>> = members
        .iter()
        .map(|member| match member.name() {
            SemanticAvailability::Available(name) => Some(name),
            SemanticAvailability::Unavailable(_) => None,
        })
        .collect();
    let distinct_identity = members
        .iter()
        .map(|member| member.node_ref())
        .collect::<std::collections::HashSet<_>>()
        .len()
        == members.len();
    ensure(
        names.len() == expected_names.len()
            && names
                .iter()
                .zip(expected_names)
                .all(|(actual, expected)| *actual == expected.as_string() && actual.is_some())
            && distinct_identity == distinct
            && document
                .diagnostics()
                .iter()
                .any(|item| item.code == diagnostic),
    )
}

fn lossless_coverage(case: &VectorCase<'_>) -> Result<(), String> {
    let (source, profile) = parse_inputs(case)?;
    let document = parse(source.as_bytes(), profile, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))?;
    let pieces = document.lossless_structural_index().pieces();
    let gap_count = usize_field_expected(case, "gap_count")?;
    let overlap_count = usize_field_expected(case, "overlap_count")?;
    let covered = usize_field_expected(case, "covered_bytes")?;
    let mut gaps = 0;
    let mut overlaps = 0;
    for pair in pieces.windows(2) {
        if pair[0].span().end_byte() < pair[1].span().start_byte() {
            gaps += 1;
        }
        if pair[0].span().end_byte() > pair[1].span().start_byte() {
            overlaps += 1;
        }
    }
    let covered_bytes = pieces.last().map_or(0, |item| item.span().end_byte());
    ensure(gaps == gap_count && overlaps == overlap_count && covered_bytes == covered)
}

fn usize_field_expected(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("missing expected.{name}"))
}

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

/// Translates a compact pipeline descriptor into the frozen operator vocabulary.
///
/// A pipeline is a sequence of `name@version` operator descriptors applied to
/// `Input`; the empty pipeline is the bare `Input` expression.
fn pipeline(case: &VectorCase<'_>) -> Result<Option<QueryExpression>, String> {
    let descriptors = case_field(case, "pipeline")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.pipeline")?;
    let mut expression = QueryExpression::Input;
    for descriptor in descriptors {
        let text = descriptor
            .as_string()
            .ok_or("pipeline descriptor is not a string")?;
        let (name, version) = text
            .split_once('@')
            .ok_or_else(|| format!("descriptor lacks version: {text}"))?;
        let version = version
            .parse::<u32>()
            .map_err(|_| format!("invalid version: {text}"))?;
        expression = expression.then(OperatorCall::new(name, version));
    }
    Ok(Some(expression))
}

fn query_duplicate_order(case: &VectorCase<'_>) -> Result<(), String> {
    let source = case_field(case, "source")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.source")?;
    let member_name = case_field(case, "member_name")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.member_name")?;
    let document = parse(
        source.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let executable = QueryDefinition::new(QueryDomain::json_native_v1())
        .with_expression(
            QueryExpression::Input
                .then(OperatorCall::new("json.try-object-members", 1))
                .then(
                    OperatorCall::new("json.member-name-equals", 1)
                        .with_argument("name", PortableValue::string(member_name)),
                ),
        )
        .validate()
        .map_err(|error| format!("{error:?}"))?
        .bind(&capabilities())
        .map_err(|error| format!("{error:?}"))?;
    let result = execute_json_query(
        &executable,
        &document,
        QueryLimits::default(),
        &consema_core::CancellationToken::new(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let expected_ordinals = expected_field(case, "ordinals")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing expected.ordinals")?;
    let expected_count = expected_field(case, "count")
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or("missing expected.count")?;
    ensure(
        result.matches().len() == expected_count
            && result
                .matches()
                .iter()
                .zip(expected_ordinals)
                .all(|(item, expected_ordinal)| {
                    matches!(item, JsonMatch::ObjectMember { ordinal, .. }
                        if Some(*ordinal as u64)
                            == expected_ordinal
                                .as_integer()
                                .and_then(BigInteger::to_i64)
                                .and_then(|value| u64::try_from(value).ok()))
                }),
    )
}

fn query_root_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let max_results = usize_field(case, "max_results")?;
    let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
        .validate()
        .map_err(|error| format!("{error:?}"))?
        .bind(&capabilities())
        .map_err(|error| format!("{error:?}"))?;
    let limits = QueryLimits {
        max_results,
        ..QueryLimits::default()
    };
    ensure(matches!(
        executable.execute_portable(
            &PortableValue::null(),
            limits,
            &consema_core::CancellationToken::new(),
        ),
        Err(QueryFailure::ResourceLimitExceeded)
    ))
}

fn query_cursor_failure(case: &VectorCase<'_>) -> Result<(), String> {
    let source = case_field(case, "elements")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.elements")?;
    let mut sequence = SequenceBuilder::new();
    for element in source {
        let value = value_from_input(element).ok_or("unrepresentable element")?;
        sequence.push(value);
    }
    let max_results = usize_field(case, "max_results")?;
    let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
        .with_expression(
            QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
        )
        .validate()
        .map_err(|error| format!("{error:?}"))?
        .bind(&capabilities())
        .map_err(|error| format!("{error:?}"))?;
    let limits = QueryLimits {
        max_results,
        ..QueryLimits::default()
    };
    let token = consema_core::CancellationToken::new();
    let mut cursor = executable
        .execute_portable_cursor(&sequence.build(), limits, &token)
        .map_err(|error| format!("{error:?}"))?;
    let mut yielded = 0;
    while let Some(item) = cursor.next_match() {
        match item {
            Ok(_) => yielded += 1,
            Err(QueryFailure::ResourceLimitExceeded) => {
                let expected_yielded = expected_field(case, "yielded_before_failure")
                    .and_then(PortableValue::as_integer)
                    .and_then(BigInteger::to_usize)
                    .ok_or("missing expected.yielded_before_failure")?;
                let expected_terminal = expected_field(case, "terminal")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing expected.terminal")?;
                return ensure(
                    yielded == expected_yielded
                        && cursor.terminal_state()
                            == Some(consema_core::QueryTerminalState::Failed)
                        && expected_terminal == "Failed",
                );
            }
            Err(other) => return Err(format!("unexpected failure: {other:?}")),
        }
    }
    Err("stream should have failed".to_owned())
}

fn query_protocol_roundtrip(case: &VectorCase<'_>) -> Result<(), String> {
    let domain = match case_field(case, "domain")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.domain")?
    {
        "core.portable-value-query@1" => QueryDomain::portable_value_v1(),
        other => return Err(format!("unknown domain {other}")),
    };
    let operator = case_field(case, "operator")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.operator")?;
    let selection = match case_field(case, "selection")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.selection")?
    {
        "All" => QuerySelection::All,
        "First" => QuerySelection::First,
        "Last" => QuerySelection::Last,
        "ZeroOrOne" => QuerySelection::ZeroOrOne,
        "RequireOne" => QuerySelection::RequireOne,
        other => return Err(format!("unknown selection {other}")),
    };
    let (name, version) = operator
        .split_once('@')
        .ok_or_else(|| format!("descriptor lacks version: {operator}"))?;
    let definition = QueryDefinition::new(domain)
        .with_expression(
            QueryExpression::Input.then(OperatorCall::new(name, version.parse::<u32>().unwrap())),
        )
        .with_selection(selection);
    let value = definition
        .to_protocol_value()
        .map_err(|error| format!("{error:?}"))?;
    let equal = QueryDefinition::from_protocol_value(&value)
        .map_err(|error| format!("{error:?}"))?
        == definition;
    let mut invalid = ObjectBuilder::new();
    for entry in value.as_object().expect("object schema") {
        invalid
            .insert(entry.key(), entry.value().clone())
            .map_err(|error| format!("{error:?}"))?;
    }
    invalid
        .insert("unknown", PortableValue::null())
        .map_err(|error| format!("{error:?}"))?;
    ensure(equal && QueryDefinition::from_protocol_value(&invalid.build()).is_err())
}

fn duplicate_document(case: &VectorCase<'_>) -> Result<consema_json::Document, String> {
    let source = case_field(case, "source")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.source")?;
    parse(
        source.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))
}

fn projection_best(case: &VectorCase<'_>) -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .map_err(|error| format!("{error:?}"))?;
    match duplicate_document(case)?.project(&request) {
        ProjectionResult::Complete(result) => {
            let kind = expected_field(case, "kind")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected.kind")?;
            let fidelity = expected_field(case, "fidelity")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected.fidelity")?;
            let associations = expected_field(case, "association_origins")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_usize)
                .ok_or("missing expected.association_origins")?;
            let actual_kind = if result.value.as_entry_mapping().is_some() {
                "EntryMapping"
            } else if result.value.as_object().is_some() {
                "Object"
            } else {
                "Other"
            };
            let actual_fidelity = fidelity_name(result.fidelity);
            ensure(
                actual_kind == kind
                    && actual_fidelity == fidelity
                    && result
                        .provenance
                        .entries()
                        .iter()
                        .filter(|entry| {
                            matches!(
                                entry.projected,
                                consema_json::ProjectedLocation::Association(_)
                            )
                        })
                        .count()
                        == associations,
            )
        }
        ProjectionResult::Failed(_) => Err("best exact failed".to_owned()),
    }
}

fn fidelity_name(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Exact => "Exact",
        Fidelity::Transformed => "Transformed",
        Fidelity::Lossy => "Lossy",
    }
}

fn projection_reject(case: &VectorCase<'_>) -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
        .build()
        .map_err(|error| format!("{error:?}"))?;
    ensure(matches!(
        duplicate_document(case)?.project(&request),
        ProjectionResult::Failed(_)
    ))
}

fn projection_last(case: &VectorCase<'_>) -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
        .global_duplicate_policy(DuplicateKeyPolicy::LastWins)
        .build()
        .map_err(|error| format!("{error:?}"))?;
    match duplicate_document(case)?.project(&request) {
        ProjectionResult::Complete(result) => ensure(
            result.fidelity == Fidelity::Lossy
                && result
                    .report
                    .events()
                    .iter()
                    .any(|event| event.kind == ProjectionEventKind::DuplicateCollapsed),
        ),
        ProjectionResult::Failed(_) => Err("authorized projection failed".to_owned()),
    }
}

fn projection_key_provenance(case: &VectorCase<'_>) -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
        .build()
        .map_err(|error| format!("{error:?}"))?;
    let document = duplicate_document(case)?;
    let ProjectionResult::Complete(result) = document.project(&request) else {
        return Err("projection failed".to_owned());
    };
    let key_origins = expected_field(case, "key_association_origins")
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or("missing expected.key_association_origins")?;
    let entry_origins = expected_field(case, "entry_association_origins")
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or("missing expected.entry_association_origins")?;
    let mut keys = 0;
    let mut entries = 0;
    for entry in result.provenance.entries() {
        let consema_json::ProjectedLocation::Association(location) = &entry.projected else {
            continue;
        };
        match location.role() {
            consema_core::AssociationRole::ObjectKey => keys += 1,
            consema_core::AssociationRole::ObjectEntry => entries += 1,
            consema_core::AssociationRole::EntryMappingEntry => {}
        }
    }
    ensure(keys == key_origins && entries == entry_origins)
}

fn edit_inputs(
    case: &VectorCase<'_>,
) -> Result<(String, JsonProfile, PortableValue, RepresentationPolicy), String> {
    let (source, profile) = parse_inputs(case)?;
    let new_value = case_field(case, "new_value")
        .and_then(value_from_input)
        .ok_or("missing or unrepresentable input.new_value")?;
    let policy = match case_field(case, "policy")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.policy")?
    {
        "PreserveCompatible" => RepresentationPolicy::PreserveCompatible,
        "CanonicalForProfile" => RepresentationPolicy::CanonicalForProfile,
        "PreserveElseCanonical" => RepresentationPolicy::PreserveElseCanonical,
        other => return Err(format!("unknown policy {other}")),
    };
    Ok((source, profile, new_value, policy))
}

fn edit_semantic(case: &VectorCase<'_>) -> Result<(), String> {
    let (source, profile, new_value, policy) = edit_inputs(case)?;
    let document = parse(source.as_bytes(), profile, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))?;
    let member = match document.root().object_members() {
        SemanticAvailability::Available(Some(members)) => members[0],
        _ => return Err("member unavailable".to_owned()),
    };
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_scalar(member.value_node_ref(), new_value, policy);
    let commit = document
        .commit(&builder.build())
        .map_err(|error| format!("{error:?}"))?;
    let expected_source = expected_field(case, "source")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected.source")?;
    let edit_count = expected_field(case, "source_edit_count")
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or("missing expected.source_edit_count")?;
    let fallback = expected_field(case, "fallback_diagnostics")
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .unwrap_or(0);
    ensure(
        commit.document.render() == expected_source.as_bytes()
            && commit.change_set.source_edits().len() == edit_count
            && commit
                .change_set
                .diagnostics()
                .iter()
                .filter(|item| item.code == "json.edit.representation-fallback@1")
                .count()
                == fallback,
    )
}

fn edit_incompatible(case: &VectorCase<'_>) -> Result<(), String> {
    let (source, profile, new_value, policy) = edit_inputs(case)?;
    let document = parse(source.as_bytes(), profile, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))?;
    let member = match document.root().object_members() {
        SemanticAvailability::Available(Some(members)) => members[0],
        _ => return Err("member unavailable".to_owned()),
    };
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_scalar(member.value_node_ref(), new_value, policy);
    ensure(matches!(
        document.commit(&builder.build()),
        Err(EditFailure::RepresentationIncompatible)
    ))
}

fn edit_wrong_snapshot(case: &VectorCase<'_>) -> Result<(), String> {
    let first_source = case_field(case, "first")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.first")?;
    let second_source = case_field(case, "second")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.second")?;
    let literal = case_field(case, "literal")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.literal")?;
    let first = parse(
        first_source.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let second = parse(
        second_source.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let mut builder = EditTransactionBuilder::new(&second);
    builder.literal_scalar(first.root().node_ref(), literal.as_bytes());
    ensure(
        matches!(
            second.commit(&builder.build()),
            Err(EditFailure::WrongSnapshot)
        ) && second.render() == second_source.as_bytes(),
    )
}

/// Compact value constructor from vector descriptors: `"Null"`, booleans,
/// `{"integer": "..."}`, `{"decimal": "..."}`, `{"string": "..."}`,
/// `{"sequence": [...]}`, and `{"object": {...}}`.
fn value_from_input(input: &PortableValue) -> Option<PortableValue> {
    match input {
        value if value.as_string() == Some("Null") => Some(PortableValue::null()),
        value if value.as_boolean().is_some() => Some(value.clone()),
        value if value.as_string().is_some() => Some(value.clone()),
        value if value.as_integer().is_some() => Some(value.clone()),
        _ => {
            let entries = input.as_object()?;
            if let Some(integer) = object_field(entries, "integer") {
                if let Some(text) = integer.as_string() {
                    return Some(PortableValue::integer(
                        BigInteger::parse_decimal(text).ok()?,
                    ));
                }
            }
            if let Some(decimal) = object_field(entries, "decimal") {
                if let Some(text) = decimal.as_string() {
                    return Some(PortableValue::decimal(
                        Decimal::parse_json_number(text).ok()?,
                    ));
                }
            }
            if let Some(string) = object_field(entries, "string") {
                if let Some(text) = string.as_string() {
                    return Some(PortableValue::string(text));
                }
            }
            if let Some(sequence) = object_field(entries, "sequence") {
                if let Some(elements) = sequence.as_sequence() {
                    let mut builder = SequenceBuilder::new();
                    for element in elements {
                        builder.push(value_from_input(element)?);
                    }
                    return Some(builder.build());
                }
            }
            if let Some(object) = object_field(entries, "object") {
                if let Some(members) = object.as_object() {
                    let mut builder = ObjectBuilder::new();
                    for member in members {
                        builder
                            .insert(member.key(), value_from_input(member.value())?)
                            .ok()?;
                    }
                    return Some(builder.build());
                }
            }
            // Bare object descriptor without a wrapping key.
            let mut builder = ObjectBuilder::new();
            for member in entries {
                builder
                    .insert(member.key(), value_from_input(member.value())?)
                    .ok()?;
            }
            Some(builder.build())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_v1_suite_is_conformant() {
        let report = run_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 30);
    }

    #[test]
    fn vector_data_drives_expected_outputs() {
        // A changed expectation must fail its case.
        let mutated =
            V1_VECTORS_JSON.replace("\"hex\": \"50564345010000\"", "\"hex\": \"50564345010001\"");
        let report = run_v1_json(&mutated);
        assert!(!report.is_conformant());
        assert!(
            report.failed.iter().any(|(id, _)| id == "pvce.null-vector"),
            "{report:#?}"
        );

        // A changed input must fail its case: a single token parses under the
        // two-token limit, so the resource-limit expectation no longer holds.
        let mutated_input = V1_VECTORS_JSON.replace("\"source\": \"[1,2]\"", "\"source\": \"1\"");
        let report = run_v1_json(&mutated_input);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "resource.parse-token-limit"),
            "{report:#?}"
        );
    }

    #[test]
    fn unknown_case_ids_fail_and_duplicates_are_rejected() {
        let unknown = V1_VECTORS_JSON.replace(
            "\"id\": \"value.integer-arbitrary-precision\"",
            "\"id\": \"value.unknown-case\"",
        );
        let report = run_v1_json(&unknown);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "value.unknown-case"),
            "{report:#?}"
        );

        let mut duplicated = V1_VECTORS_JSON.to_owned();
        duplicated = duplicated.replacen(
            "\"id\": \"pvce.null-vector\"",
            "\"id\": \"pvce.duplicate-placeholder\"",
            1,
        );
        let report = run_v1_json(&duplicated);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "pvce.duplicate-placeholder"),
            "{report:#?}"
        );
    }
}
