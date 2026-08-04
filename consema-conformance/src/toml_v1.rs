use super::{ConformanceReport, capabilities, ensure, object_field};
use consema_core::{
    AssociationRole, BinaryFloat64, OperatorCall, PortableValue, PortableValueKind,
    QueryDefinition, QueryDomain, QueryExpression, QueryLimits,
};
use consema_document::{FormationStatus, ParseLimits};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder as JsonProjectionRequestBuilder,
    ProjectionResult as JsonProjectionResult, ProjectionTarget as JsonProjectionTarget,
    parse as parse_json,
};
use consema_toml::{
    Document, EditFailure, EditTransactionBuilder, Fidelity, ProjectedLocation, ProjectionRequest,
    ProjectionResult, ProjectionTarget, RepresentationPolicy, TomlItem, TomlItemKind, TomlMatch,
    TomlProfile, execute_toml_query, parse as parse_toml,
};

/// Embedded language-neutral TOML suite bytes.
pub const TOML_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/toml-v1.json");

const ALL_VALUES: &[u8] = include_bytes!("../../../conformance/fixtures/toml/all-values.toml");
const APPLICATION: &[u8] = include_bytes!("../../../conformance/fixtures/toml/application.toml");
const TRIVIA_AND_STRINGS: &[u8] =
    include_bytes!("../../../conformance/fixtures/toml/trivia-and-strings.toml");
const INVALID_DUPLICATE: &[u8] =
    include_bytes!("../../../conformance/fixtures/toml/invalid-duplicate.toml");

/// Parses and runs every embedded `consema.toml.conformance@1` case.
#[must_use]
pub fn run_toml_v1() -> ConformanceReport {
    let vectors = parse_json(
        TOML_V1_VECTORS_JSON.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published TOML vector JSON must form a document");
    let request = JsonProjectionRequestBuilder::new(JsonProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed JSON projection request");
    let value = match vectors.project(&request) {
        JsonProjectionResult::Complete(result) => result.value,
        JsonProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.toml.conformance@1".to_owned(),
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

fn run_case(id: &str) -> Result<(), String> {
    match id {
        "toml.parse.exact-roundtrip" => exact_roundtrip(),
        "toml.parse.lossless-byte-coverage" => lossless_coverage(),
        "toml.native.dotted-segments" => dotted_segments(),
        "toml.native.table-flavors" => table_flavors(),
        "toml.native.array-aot-distinct" => array_aot_distinct(),
        "toml.native.float-signed-zero" => float_signed_zero(),
        "toml.query.nested-entry-order" => nested_entry_query(),
        "toml.query.aot-element-order" => aot_query(),
        "toml.projection.all-core-kinds" => projection_all_kinds(),
        "toml.projection.provenance" => projection_provenance(),
        "toml.projection.reject-leap-second" => projection_leap_second(),
        "toml.edit.literal-minimal" => edit_literal_minimal(),
        "toml.edit.reject-unrepresentable" => edit_reject_unrepresentable(),
        "toml.parse.reject-invalid" => reject_invalid(),
        "toml.resource.token-limit" => token_limit(),
        "toml.resource.node-depth-limits" => node_depth_limits(),
        _ => Err("runner does not recognize published TOML case".to_owned()),
    }
}

fn parse_fixture(source: &[u8]) -> Result<Document, String> {
    parse_toml(source, TomlProfile::Toml10V1, ParseLimits::default())
        .map_err(|failure| format!("TOML formation failed: {failure:?}"))
}

fn direct_item<'a>(container: TomlItem<'a>, name: &str) -> Result<TomlItem<'a>, String> {
    container
        .table_entries()
        .ok_or_else(|| "item is not a table".to_owned())?
        .into_iter()
        .find(|entry| entry.name() == name)
        .map(consema_toml::TomlEntry::item)
        .ok_or_else(|| format!("missing direct entry {name}"))
}

fn exact_roundtrip() -> Result<(), String> {
    let document = parse_fixture(ALL_VALUES)?;
    ensure(
        document.render() == ALL_VALUES
            && document.formation_status() == FormationStatus::Complete
            && document.format_family().id() == "toml"
            && document.profile().id() == "toml.1.0"
            && document.diagnostics().is_empty(),
    )
}

fn lossless_coverage() -> Result<(), String> {
    let document = parse_fixture(TRIVIA_AND_STRINGS)?;
    let pieces = document.lossless_structural_index().pieces();
    ensure(
        pieces
            .first()
            .is_some_and(|piece| piece.span().start_byte() == 0)
            && pieces
                .windows(2)
                .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
            && pieces.last().map_or(0, |piece| piece.span().end_byte()) == TRIVIA_AND_STRINGS.len(),
    )
}

fn dotted_segments() -> Result<(), String> {
    let document = parse_fixture(b"alpha.beta.gamma = 1\n")?;
    let alpha = direct_item(document.root(), "alpha")?;
    let beta = direct_item(alpha, "beta")?;
    let gamma = direct_item(beta, "gamma")?;
    ensure(
        alpha.kind() == TomlItemKind::DottedTable
            && beta.kind() == TomlItemKind::DottedTable
            && gamma.kind() == TomlItemKind::Integer
            && gamma.as_integer() == Some(1),
    )
}

fn table_flavors() -> Result<(), String> {
    let document = parse_fixture(APPLICATION)?;
    ensure(
        direct_item(document.root(), "service")?.kind() == TomlItemKind::DottedTable
            && direct_item(document.root(), "database")?.kind() == TomlItemKind::StandardTable
            && direct_item(document.root(), "observability")?.kind() == TomlItemKind::ImplicitTable,
    )
}

fn array_aot_distinct() -> Result<(), String> {
    let document = parse_fixture(APPLICATION)?;
    let database = direct_item(document.root(), "database")?;
    let timeouts = direct_item(database, "timeouts")?;
    let upstreams = direct_item(document.root(), "upstreams")?;
    ensure(
        timeouts.kind() == TomlItemKind::Array
            && upstreams.kind() == TomlItemKind::ArrayOfTables
            && upstreams
                .array_elements()
                .is_some_and(|items| items.len() == 2),
    )
}

fn float_signed_zero() -> Result<(), String> {
    let document = parse_fixture(b"positive = 0.0\nnegative = -0.0\n")?;
    ensure(
        direct_item(document.root(), "positive")?
            .as_float()
            .is_some_and(|value| value.bits() == 0)
            && direct_item(document.root(), "negative")?
                .as_float()
                .is_some_and(|value| value.bits() == 1_u64 << 63),
    )
}

fn executable(expression: QueryExpression) -> Result<consema_core::ExecutableQuery, String> {
    QueryDefinition::new(QueryDomain::toml_native_v1())
        .with_expression(expression)
        .validate()
        .map_err(|failure| format!("validation: {failure:?}"))?
        .bind(&capabilities())
        .map_err(|failure| format!("binding: {failure:?}"))
}

fn named_root_item_expression(name: &str) -> QueryExpression {
    QueryExpression::Input
        .then(OperatorCall::new("toml.try-table-entries", 1))
        .then(
            OperatorCall::new("toml.entry-name-equals", 1)
                .with_argument("name", PortableValue::string(name)),
        )
        .then(OperatorCall::new("toml.entry-item", 1))
}

fn nested_entry_query() -> Result<(), String> {
    let document = parse_fixture(APPLICATION)?;
    let expression =
        named_root_item_expression("service").then(OperatorCall::new("toml.try-table-entries", 1));
    let result = execute_toml_query(
        &executable(expression)?,
        &document,
        QueryLimits::default(),
        &consema_core::CancellationToken::new(),
    )
    .map_err(|failure| format!("query: {failure:?}"))?;
    let names: Vec<&str> = result
        .matches()
        .iter()
        .filter_map(|item| match item {
            TomlMatch::Entry { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    ensure(names == ["name", "environment", "listen"])
}

fn aot_query() -> Result<(), String> {
    let document = parse_fixture(APPLICATION)?;
    let expression = named_root_item_expression("upstreams")
        .then(OperatorCall::new("toml.try-array-elements", 1));
    let result = execute_toml_query(
        &executable(expression)?,
        &document,
        QueryLimits::default(),
        &consema_core::CancellationToken::new(),
    )
    .map_err(|failure| format!("query: {failure:?}"))?;
    ensure(matches!(
        result.matches(),
        [
            TomlMatch::ArrayElement { ordinal: 0, .. },
            TomlMatch::ArrayElement { ordinal: 1, .. }
        ]
    ))
}

fn projection_request() -> ProjectionRequest {
    ProjectionRequest::new(ProjectionTarget::BestExactCoreV1)
}

fn projection_all_kinds() -> Result<(), String> {
    let document = parse_fixture(ALL_VALUES)?;
    let ProjectionResult::Complete(result) = document.project(projection_request()) else {
        return Err("exact projection failed".to_owned());
    };
    let root = result.value.as_object().ok_or("root is not Object")?;
    let kinds: Vec<PortableValueKind> = root.iter().map(|entry| entry.value().kind()).collect();
    ensure(
        result.fidelity == Fidelity::Exact
            && kinds.contains(&PortableValueKind::String)
            && kinds.contains(&PortableValueKind::Boolean)
            && kinds.contains(&PortableValueKind::Integer)
            && kinds.contains(&PortableValueKind::BinaryFloat64)
            && kinds.contains(&PortableValueKind::Date)
            && kinds.contains(&PortableValueKind::Time)
            && kinds.contains(&PortableValueKind::LocalDateTime)
            && kinds.contains(&PortableValueKind::OffsetDateTime)
            && kinds.contains(&PortableValueKind::Sequence)
            && kinds.contains(&PortableValueKind::Object),
    )
}

fn projection_provenance() -> Result<(), String> {
    let document = parse_fixture(b"point = { x = 1, y = 2 }\n")?;
    let ProjectionResult::Complete(result) = document.project(projection_request()) else {
        return Err("projection failed".to_owned());
    };
    let snapshot = document.snapshot_identity();
    ensure(
        result.provenance.entries().iter().all(|entry| {
            entry.origins.iter().all(|origin| {
                origin.snapshot == snapshot
                    && origin.node.snapshot() == snapshot
                    && origin.span.snapshot() == snapshot
            })
        }) && result.provenance.entries().iter().any(|entry| {
            matches!(
                &entry.projected,
                ProjectedLocation::Association(location)
                    if location.role() == AssociationRole::ObjectEntry
            )
        }),
    )
}

fn projection_leap_second() -> Result<(), String> {
    let document = parse_fixture(b"time = 23:59:60\n")?;
    let ProjectionResult::Failed(failure) = document.project(projection_request()) else {
        return Err("leap second projection succeeded".to_owned());
    };
    ensure(
        failure.diagnostics.len() == 1
            && failure.diagnostics[0].code == "toml.projection.unrepresentable-datetime@1",
    )
}

fn edit_literal_minimal() -> Result<(), String> {
    let document = parse_fixture(b"hex = 0x2A # keep\n")?;
    let target = direct_item(document.root(), "hex")?.node_ref();
    let mut builder = EditTransactionBuilder::new(&document);
    builder.literal_scalar(target, b"0x2B".as_slice());
    let commit = document
        .commit(&builder.build())
        .map_err(|failure| format!("edit: {failure:?}"))?;
    ensure(
        commit.document.render() == b"hex = 0x2B # keep\n"
            && commit.change_set.source_edits().len() == 1,
    )
}

fn edit_reject_unrepresentable() -> Result<(), String> {
    let document = parse_fixture(b"float = 1.0\n")?;
    let target = direct_item(document.root(), "float")?.node_ref();
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_scalar(
        target,
        PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0001)),
        RepresentationPolicy::CanonicalForProfile,
    );
    ensure(
        matches!(
            document.commit(&builder.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::BinaryFloat64
            ))
        ) && document.render() == b"float = 1.0\n",
    )
}

fn reject_invalid() -> Result<(), String> {
    let failure = parse_toml(
        INVALID_DUPLICATE,
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .expect_err("duplicate key must fail");
    ensure(
        failure.diagnostics().len() == 1 && failure.diagnostics()[0].code == "toml.parse.syntax@1",
    )
}

fn token_limit() -> Result<(), String> {
    let limits = ParseLimits {
        max_token_count: 3,
        ..ParseLimits::default()
    };
    ensure(
        parse_toml(
            b"values = [1, 2, 3]".as_slice(),
            TomlProfile::Toml10V1,
            limits,
        )
        .is_err(),
    )
}

fn node_depth_limits() -> Result<(), String> {
    let node_limits = ParseLimits {
        max_node_count: 3,
        ..ParseLimits::default()
    };
    let depth_limits = ParseLimits {
        max_nesting_depth: 2,
        ..ParseLimits::default()
    };
    let source = b"value = [[[[1]]]]".as_slice();
    ensure(
        parse_toml(source, TomlProfile::Toml10V1, node_limits).is_err()
            && parse_toml(source, TomlProfile::Toml10V1, depth_limits).is_err(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_toml_v1_suite_is_conformant() {
        let report = run_toml_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 16);
    }
}
