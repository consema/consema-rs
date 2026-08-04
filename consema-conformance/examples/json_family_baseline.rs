//! Reproducible wall-clock baseline for the frozen JSON-family production corpus.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition,
    QueryDomain, QueryExpression, QueryLimits,
};
use consema_document::{
    MaterializationRequest, MaterializationResult, MaterializationStyleId, NewlinePolicy,
    ParseLimits, ProfileId,
};
use consema_json::{
    EditTransactionBuilder, JsonProfile, ProjectionRequestBuilder, ProjectionResult,
    ProjectionTarget, RepresentationPolicy, SemanticAvailability, execute_json_syntax_query, parse,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const SOURCE: &[u8] =
    include_bytes!("../../../conformance/fixtures/json5/package-json5-v2.2.3.json5");

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let document = parse(SOURCE, JsonProfile::Json5StandardV1, ParseLimits::default())
        .expect("pinned JSON5 fixture must parse");
    let projection_request = ProjectionRequestBuilder::new(ProjectionTarget::Json5BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let ProjectionResult::Complete(projected) = document.project(&projection_request) else {
        panic!("pinned JSON5 fixture must project");
    };
    let materialization_request = MaterializationRequest::new(
        ProfileId::new("json5.standard", 1),
        MaterializationStyleId::new("json5.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None);
    let materialized_bytes =
        match consema_json::materialize(&projected.value, &materialization_request) {
            MaterializationResult::Complete(result) => result.document.render().len(),
            MaterializationResult::Failed(error) => {
                panic!("fixture materialization failed: {error:?}")
            }
        };

    let mut query_capabilities = CapabilitySet::new();
    query_capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let query = QueryDefinition::new(QueryDomain::json_lossless_syntax_v2())
        .with_expression(
            QueryExpression::Input.then(
                OperatorCall::new("json.syntax-kind-is", 1)
                    .with_argument("kind", PortableValue::string("Identifier")),
            ),
        )
        .validate()
        .expect("fixed query validates")
        .bind(&query_capabilities)
        .expect("fixed capabilities bind");
    let cancellation = CancellationToken::new();

    let members = match document.root().object_members() {
        SemanticAvailability::Available(Some(members)) => members,
        other => panic!("fixture root is not a complete object: {other:?}"),
    };
    let version = members
        .iter()
        .find(|member| matches!(member.name(), SemanticAvailability::Available("version")))
        .expect("fixture version member");
    let mut edit = EditTransactionBuilder::new(&document);
    edit.semantic_scalar(
        version.value_node_ref(),
        PortableValue::string("2.2.4"),
        RepresentationPolicy::PreserveCompatible,
    );
    let edit = edit.build();

    for _ in 0..100 {
        black_box(
            parse(
                black_box(SOURCE),
                JsonProfile::Json5StandardV1,
                ParseLimits::default(),
            )
            .expect("warm parse"),
        );
        black_box(document.project(black_box(&projection_request)));
    }

    let parse_time = measure(iterations, || {
        black_box(
            parse(
                black_box(SOURCE),
                JsonProfile::Json5StandardV1,
                ParseLimits::default(),
            )
            .expect("benchmark parse"),
        );
    });
    let query_time = measure(iterations, || {
        black_box(
            execute_json_syntax_query(
                black_box(&query),
                black_box(&document),
                QueryLimits::default(),
                &cancellation,
            )
            .expect("benchmark query"),
        );
    });
    let projection_time = measure(iterations, || {
        let result = document.project(black_box(&projection_request));
        assert!(matches!(result, ProjectionResult::Complete(_)));
        black_box(result);
    });
    let materialization_time = measure(iterations, || {
        let result = consema_json::materialize(
            black_box(&projected.value),
            black_box(&materialization_request),
        );
        assert!(matches!(result, MaterializationResult::Complete(_)));
        black_box(result);
    });
    let edit_time = measure(iterations, || {
        black_box(document.commit(black_box(&edit)).expect("benchmark edit"));
    });

    println!("suite=consema.json-family.benchmark@1");
    println!("package_version={}", env!("CARGO_PKG_VERSION"));
    println!(
        "host={}{}{}",
        std::env::consts::OS,
        std::path::MAIN_SEPARATOR,
        std::env::consts::ARCH
    );
    println!("iterations={iterations}");
    println!("source_bytes={}", SOURCE.len());
    println!(
        "source_pieces={}",
        document.lossless_structural_index().pieces().len()
    );
    println!("materialized_bytes={materialized_bytes}");
    print_result("parse", parse_time, iterations, Some(SOURCE.len()));
    print_result("syntax_query", query_time, iterations, None);
    print_result("projection", projection_time, iterations, None);
    print_result(
        "materialization",
        materialization_time,
        iterations,
        Some(materialized_bytes),
    );
    print_result("edit", edit_time, iterations, None);
}

fn measure(iterations: u64, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

fn print_result(name: &str, duration: Duration, iterations: u64, bytes: Option<usize>) {
    let nanos = duration.as_nanos() / u128::from(iterations);
    match bytes {
        Some(bytes) => {
            let mebibytes_per_second_x100 = u128::try_from(bytes)
                .expect("usize fits u128")
                .saturating_mul(u128::from(iterations))
                .saturating_mul(100)
                .saturating_mul(1_000_000_000)
                / duration.as_nanos().max(1)
                / (1024 * 1024);
            println!("{name}_ns_per_op={nanos}");
            println!(
                "{name}_mib_per_s={}.{:02}",
                mebibytes_per_second_x100 / 100,
                mebibytes_per_second_x100 % 100
            );
        }
        None => println!("{name}_ns_per_op={nanos}"),
    }
}
