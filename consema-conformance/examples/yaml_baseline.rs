//! Reproducible wall-clock baseline for the frozen anchor-heavy YAML corpus.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition,
    QueryDomain, QueryExpression, QueryLimits,
};
use consema_document::{
    MaterializationRequest, MaterializationStyleId, NewlinePolicy, ParseLimits, ProfileId,
};
use consema_graph::encode_pgce;
use consema_yaml::{
    EditTransactionBuilder, GraphMaterializationResult, SharingPolicy, ValueProjectionRequest,
    ValueProjectionResult, YamlProfile, execute_yaml_syntax_query, materialize_graph, parse,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const SOURCE: &[u8] = include_bytes!("../../../conformance/fixtures/yaml/anchor-heavy.yaml");

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let document = parse(SOURCE, YamlProfile::Yaml12CoreV1, ParseLimits::default())
        .expect("pinned YAML fixture must parse");
    let graph = document
        .project_graph()
        .expect("pinned YAML fixture must project to a graph");
    let pgce_bytes = encode_pgce(&graph)
        .expect("pinned YAML fixture graph must encode")
        .len();
    let value_request =
        ValueProjectionRequest::best_exact_v1().with_sharing(SharingPolicy::DuplicateAcyclic);
    let ValueProjectionResult::Complete(projected) = document.project_value(value_request) else {
        panic!("pinned YAML fixture must project under explicit duplication");
    };
    let materialization_request = MaterializationRequest::new(
        ProfileId::new("yaml.1.2-core", 1),
        MaterializationStyleId::new("yaml.canonical-block", 1),
    )
    .with_newline(NewlinePolicy::Lf);
    let GraphMaterializationResult::Complete(materialized) =
        materialize_graph(&graph, &materialization_request)
    else {
        panic!("pinned YAML graph must materialize");
    };
    let materialized_bytes = materialized.document.render().len();

    let mut query_capabilities = CapabilitySet::new();
    query_capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let query = QueryDefinition::new(QueryDomain::yaml_lossless_syntax_v1())
        .with_expression(
            QueryExpression::Input.then(
                OperatorCall::new("yaml.syntax-kind-is", 1)
                    .with_argument("kind", PortableValue::string("Alias")),
            ),
        )
        .validate()
        .expect("fixed query validates")
        .bind(&query_capabilities)
        .expect("fixed capabilities bind");
    let cancellation = CancellationToken::new();

    let anchor = document
        .document(0)
        .and_then(|item| item.root().mapping_entry(0))
        .map(consema_yaml::YamlMappingEntry::value)
        .and_then(consema_yaml::YamlNode::anchor_node_ref)
        .expect("fixture defaults anchor");
    let mut edit = EditTransactionBuilder::new(&document);
    edit.rename_anchor(anchor, "common");
    let edit = edit.build();

    for _ in 0..100 {
        black_box(
            parse(
                black_box(SOURCE),
                YamlProfile::Yaml12CoreV1,
                ParseLimits::default(),
            )
            .expect("warm parse"),
        );
        black_box(document.project_graph().expect("warm graph projection"));
    }

    let parse_time = measure(iterations, || {
        black_box(
            parse(
                black_box(SOURCE),
                YamlProfile::Yaml12CoreV1,
                ParseLimits::default(),
            )
            .expect("benchmark parse"),
        );
    });
    let query_time = measure(iterations, || {
        black_box(
            execute_yaml_syntax_query(
                black_box(&query),
                black_box(&document),
                QueryLimits::default(),
                &cancellation,
            )
            .expect("benchmark query"),
        );
    });
    let graph_projection_time = measure(iterations, || {
        black_box(
            document
                .project_graph()
                .expect("benchmark graph projection"),
        );
    });
    let pgce_time = measure(iterations, || {
        black_box(encode_pgce(black_box(&graph)).expect("benchmark PGCE encode"));
    });
    let value_projection_time = measure(iterations, || {
        let result = document.project_value(black_box(value_request));
        assert!(matches!(result, ValueProjectionResult::Complete(_)));
        black_box(result);
    });
    let materialization_time = measure(iterations, || {
        let result = materialize_graph(black_box(&graph), black_box(&materialization_request));
        assert!(matches!(result, GraphMaterializationResult::Complete(_)));
        black_box(result);
    });
    let edit_time = measure(iterations, || {
        black_box(document.commit(black_box(&edit)).expect("benchmark edit"));
    });

    println!("suite=consema.yaml.benchmark@1");
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
    println!("graph_nodes={}", graph.node_count());
    println!("pgce_bytes={pgce_bytes}");
    println!("duplicated_value_kind={:?}", projected.value.kind());
    println!("materialized_bytes={materialized_bytes}");
    print_result("parse", parse_time, iterations, Some(SOURCE.len()));
    print_result("syntax_query", query_time, iterations, None);
    print_result("graph_projection", graph_projection_time, iterations, None);
    print_result("pgce_encode", pgce_time, iterations, Some(pgce_bytes));
    print_result("value_projection", value_projection_time, iterations, None);
    print_result(
        "graph_materialization",
        materialization_time,
        iterations,
        Some(materialized_bytes),
    );
    print_result("anchor_edit", edit_time, iterations, None);
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
