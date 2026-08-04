//! Language-neutral conformance vectors and Rust reference runner.

mod protocol_v1;
mod toml_v1;

use consema_core::{
    BigInteger, BinaryFloat64, CapabilityId, CapabilitySet, Decimal, ObjectBuilder, OperatorCall,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QuerySelection,
};
use consema_document::{FormationStatus, ParseLimits};
use consema_json::{
    DuplicateKeyPolicy, EditFailure, EditTransactionBuilder, Fidelity, JsonMatch, JsonProfile,
    ProjectionEventKind, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget,
    RepresentationPolicy, SemanticAvailability, execute_json_query, parse,
};
use consema_pvce::{DecodeError, DecodeLimits, decode, encode};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub use protocol_v1::{PROTOCOL_V1_VECTORS_JSON, run_protocol_v1};
pub use toml_v1::{TOML_V1_VECTORS_JSON, run_toml_v1};

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

/// Parses and runs every embedded `consema.conformance@1` case.
#[must_use]
pub fn run_v1() -> ConformanceReport {
    let vectors = parse(
        V1_VECTORS_JSON.as_bytes(),
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
        match run_case(id) {
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

fn run_case(id: &str) -> Result<(), String> {
    match id {
        "value.integer-arbitrary-precision" => {
            let text = "340282366920938463463374607431768211457";
            ensure(BigInteger::parse_decimal(text).unwrap().to_string() == text)
        }
        "value.decimal-normalization" => {
            let left = PortableValue::decimal(Decimal::parse_json_number("1.00").unwrap());
            let right = PortableValue::decimal(Decimal::parse_json_number("10e-1").unwrap());
            ensure(left == right && strict_hash(&left) == strict_hash(&right))
        }
        "value.float-signed-zero" => ensure(
            PortableValue::binary_float64(BinaryFloat64::from_bits(0))
                != PortableValue::binary_float64(BinaryFloat64::from_bits(1_u64 << 63)),
        ),
        "pvce.null-vector" => ensure(hex(&encode(&PortableValue::null())) == "50564345010000"),
        "pvce.negative-integer-vector" => ensure(
            hex(&encode(&PortableValue::integer(BigInteger::from(-256_i64))))
                == "5056434501100402020100",
        ),
        "pvce.reject-nonminimal-varint" => ensure(matches!(
            decode(
                &[b'P', b'V', b'C', b'E', 0x81, 0, 0, 0],
                DecodeLimits::default()
            ),
            Err(DecodeError::NonCanonicalVarint)
        )),
        "parse.strict-exact-roundtrip" => {
            parse_exact(" {\n  \"a\" : [1, 2]\n} ", JsonProfile::StrictV1)
        }
        "parse.jsonc-comments-trailing-comma" => {
            parse_exact("{/*x*/\"a\":1,}", JsonProfile::JsoncBoundedV1)
        }
        "parse.recovery-missing-close" => {
            let document = parse(
                b"{\"a\":1".as_slice(),
                JsonProfile::StrictV1,
                ParseLimits::default(),
            )
            .unwrap();
            ensure(
                document.formation_status() == FormationStatus::Recovered
                    && document
                        .diagnostics()
                        .iter()
                        .any(|item| item.code == "json.syntax.missing-object-close@1"),
            )
        }
        "parse.duplicate-members" => duplicate_members(),
        "parse.lossless-byte-coverage" => lossless_coverage(),
        "query.reject-role-mismatch" => ensure(matches!(
            QueryDefinition::new(QueryDomain::portable_value_v1())
                .with_expression(
                    QueryExpression::Input.then(OperatorCall::new("core.object-entry-value", 1))
                )
                .validate(),
            Err(QueryFailure::InvalidOperatorComposition { .. })
        )),
        "query.json-duplicate-order" => query_duplicate_order(),
        "query.protocol-roundtrip" => query_protocol_roundtrip(),
        "projection.best-exact-duplicate-mapping" => projection_best(),
        "projection.object-reject-duplicates" => projection_reject(),
        "projection.object-last-wins" => projection_last(),
        "edit.scalar-minimal" => edit_minimal(),
        "edit.wrong-snapshot" => edit_wrong_snapshot(),
        "resource.parse-token-limit" => {
            let limits = ParseLimits {
                max_token_count: 2,
                ..ParseLimits::default()
            };
            ensure(parse(b"[1,2]".as_slice(), JsonProfile::StrictV1, limits).is_err())
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

fn parse_exact(source: &str, profile: JsonProfile) -> Result<(), String> {
    let document = parse(source.as_bytes(), profile, ParseLimits::default()).unwrap();
    ensure(
        document.formation_status() == FormationStatus::Complete
            && document.render() == source.as_bytes(),
    )
}

fn duplicate_members() -> Result<(), String> {
    let document = parse(
        br#"{"a":1,"a":2}"#.as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let SemanticAvailability::Available(Some(members)) = document.root().object_members() else {
        return Err("object semantics unavailable".to_owned());
    };
    ensure(
        members.len() == 2
            && members[0].name() == SemanticAvailability::Available("a")
            && members[1].name() == SemanticAvailability::Available("a")
            && members[0].node_ref() != members[1].node_ref(),
    )
}

fn lossless_coverage() -> Result<(), String> {
    let source = " \n// c\n[1,] ";
    let document = parse(
        source.as_bytes(),
        JsonProfile::JsoncBoundedV1,
        ParseLimits::default(),
    )
    .unwrap();
    let pieces = document.lossless_structural_index().pieces();
    ensure(
        pieces
            .first()
            .is_some_and(|item| item.span().start_byte() == 0)
            && pieces
                .windows(2)
                .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
            && pieces.last().map_or(0, |item| item.span().end_byte()) == source.len(),
    )
}

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

fn query_duplicate_order() -> Result<(), String> {
    let document = parse(
        br#"{"a":1,"a":2,"b":3}"#.as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let executable = QueryDefinition::new(QueryDomain::json_native_v1())
        .with_expression(
            QueryExpression::Input
                .then(OperatorCall::new("json.try-object-members", 1))
                .then(
                    OperatorCall::new("json.member-name-equals", 1)
                        .with_argument("name", PortableValue::string("a")),
                ),
        )
        .validate()
        .unwrap()
        .bind(&capabilities())
        .unwrap();
    let result = execute_json_query(
        &executable,
        &document,
        QueryLimits::default(),
        &consema_core::CancellationToken::new(),
    )
    .unwrap();
    ensure(matches!(
        result.matches(),
        [
            JsonMatch::ObjectMember { ordinal: 0, .. },
            JsonMatch::ObjectMember { ordinal: 1, .. }
        ]
    ))
}

fn query_protocol_roundtrip() -> Result<(), String> {
    let definition = QueryDefinition::new(QueryDomain::portable_value_v1())
        .with_expression(
            QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
        )
        .with_selection(QuerySelection::First);
    let value = definition.to_protocol_value().unwrap();
    let equal = QueryDefinition::from_protocol_value(&value).unwrap() == definition;
    let mut invalid = ObjectBuilder::new();
    for entry in value.as_object().unwrap() {
        invalid.insert(entry.key(), entry.value().clone()).unwrap();
    }
    invalid.insert("unknown", PortableValue::null()).unwrap();
    ensure(equal && QueryDefinition::from_protocol_value(&invalid.build()).is_err())
}

fn duplicate_document() -> consema_json::Document {
    parse(
        br#"{"a":1,"a":2}"#.as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap()
}

fn projection_best() -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .unwrap();
    match duplicate_document().project(&request) {
        ProjectionResult::Complete(result) => ensure(
            result.value.as_entry_mapping().is_some()
                && result.fidelity == Fidelity::Transformed
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
                    == 2,
        ),
        ProjectionResult::Failed(_) => Err("best exact failed".to_owned()),
    }
}

fn projection_reject() -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
        .build()
        .unwrap();
    ensure(matches!(
        duplicate_document().project(&request),
        ProjectionResult::Failed(_)
    ))
}

fn projection_last() -> Result<(), String> {
    let request = ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsObjectV1)
        .global_duplicate_policy(DuplicateKeyPolicy::LastWins)
        .build()
        .unwrap();
    match duplicate_document().project(&request) {
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

fn edit_minimal() -> Result<(), String> {
    let document = parse(
        b"{ /* lead */ \"a\" : 1 // tail\n}".as_slice(),
        JsonProfile::JsoncBoundedV1,
        ParseLimits::default(),
    )
    .unwrap();
    let member = match document.root().object_members() {
        SemanticAvailability::Available(Some(members)) => members[0],
        _ => return Err("member unavailable".to_owned()),
    };
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_scalar(
        member.value_node_ref(),
        PortableValue::integer(BigInteger::from(200_i64)),
        RepresentationPolicy::PreserveCompatible,
    );
    let commit = document.commit(&builder.build()).unwrap();
    ensure(
        commit.document.render() == b"{ /* lead */ \"a\" : 200 // tail\n}"
            && commit.change_set.source_edits().len() == 1,
    )
}

fn edit_wrong_snapshot() -> Result<(), String> {
    let first = parse(
        b"1".as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let second = parse(
        b"2".as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let mut builder = EditTransactionBuilder::new(&second);
    builder.literal_scalar(first.root().node_ref(), b"3".as_slice());
    ensure(
        matches!(
            second.commit(&builder.build()),
            Err(EditFailure::WrongSnapshot)
        ) && second.render() == b"2",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_v1_suite_is_conformant() {
        let report = run_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 20);
    }
}
