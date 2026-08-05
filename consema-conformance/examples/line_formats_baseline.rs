//! Reproducible wall-clock baseline for the frozen INI and Properties production corpus.

use consema::{ini, properties};
use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, OperatorCall, QueryDefinition, QueryDomain,
    QueryExpression, QueryLimits,
};
use consema_document::{
    MappingPolicy, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    ProfileId, SourceEncoding,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const INI_SOURCE: &[u8] = include_bytes!("../../../conformance/fixtures/ini/desktop-settings.ini");
const PROPERTIES_SOURCE: &[u8] =
    include_bytes!("../../../conformance/fixtures/properties/logging.properties");

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let mut query_capabilities = CapabilitySet::new();
    query_capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let ini_query = QueryDefinition::new(QueryDomain::ini_native_v1())
        .with_expression(QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1)))
        .validate()
        .expect("fixed INI query validates")
        .bind(&query_capabilities)
        .expect("fixed INI query capabilities bind");
    let properties_query = QueryDefinition::new(QueryDomain::java_properties_native_v1())
        .with_expression(
            QueryExpression::Input.then(OperatorCall::new("properties.document-properties", 1)),
        )
        .validate()
        .expect("fixed Properties query validates")
        .bind(&query_capabilities)
        .expect("fixed Properties query capabilities bind");
    let cancellation = CancellationToken::new();

    let ini_document = parse_ini();
    let ini_projection_request = ini::ProjectionRequest::best_exact_entry_mapping();
    let ini::ProjectionResult::Complete(ini_projected) =
        ini_document.project(ini_projection_request)
    else {
        panic!("pinned INI fixture must project");
    };
    let ini_materialization_request = MaterializationRequest::new(
        ProfileId::new("ini.portable", 1),
        MaterializationStyleId::new("ini.portable-canonical", 1),
    )
    .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject);
    let ini_materialized_bytes =
        match ini::materialize(&ini_projected.value, &ini_materialization_request) {
            MaterializationResult::Complete(result) => result.document.render().len(),
            MaterializationResult::Failed(error) => {
                panic!("fixture INI materialization failed: {error:?}")
            }
        };
    let mut ini_edit = ini::EditTransactionBuilder::new(&ini_document);
    ini_edit.semantic_value(
        ini_document.entries()[0].node_ref(),
        "1600",
        ini::RepresentationPolicy::CanonicalForProfile,
    );
    let ini_edit = ini_edit.build();

    let properties_document = parse_properties();
    let properties_projection_request = properties::ProjectionRequest::best_exact_entry_mapping();
    let properties::ProjectionResult::Complete(properties_projected) =
        properties_document.project(properties_projection_request)
    else {
        panic!("pinned Properties fixture must project");
    };
    let properties_materialization_request = MaterializationRequest::new(
        ProfileId::new("java-properties.reader", 1),
        MaterializationStyleId::new("java-properties.reader-canonical", 1),
    );
    let properties_materialized_bytes = match properties::materialize(
        &properties_projected.value,
        &properties_materialization_request,
    ) {
        MaterializationResult::Complete(result) => result.document.render().len(),
        MaterializationResult::Failed(error) => {
            panic!("fixture Properties materialization failed: {error:?}")
        }
    };
    let mut properties_edit = properties::EditTransactionBuilder::new(&properties_document);
    properties_edit.semantic_value(
        properties_document.properties()[0].node_ref(),
        properties::JavaString::from_unicode("java.util.logging.ConsoleHandler"),
    );
    let properties_edit = properties_edit.build();

    for _ in 0..100 {
        black_box(parse_ini());
        black_box(ini_document.project(black_box(ini_projection_request)));
        black_box(parse_properties());
        black_box(properties_document.project(black_box(properties_projection_request)));
    }

    let ini_parse_time = measure(iterations, || {
        black_box(parse_ini());
    });
    let ini_query_time = measure(iterations, || {
        black_box(
            ini::execute_ini_query(
                black_box(&ini_query),
                black_box(&ini_document),
                QueryLimits::default(),
                &cancellation,
            )
            .expect("benchmark INI query"),
        );
    });
    let ini_projection_time = measure(iterations, || {
        let result = ini_document.project(black_box(ini_projection_request));
        assert!(matches!(result, ini::ProjectionResult::Complete(_)));
        black_box(result);
    });
    let ini_materialization_time = measure(iterations, || {
        let result = ini::materialize(
            black_box(&ini_projected.value),
            black_box(&ini_materialization_request),
        );
        assert!(matches!(result, MaterializationResult::Complete(_)));
        black_box(result);
    });
    let ini_edit_time = measure(iterations, || {
        black_box(
            ini_document
                .commit(black_box(&ini_edit))
                .expect("benchmark INI edit"),
        );
    });

    let properties_parse_time = measure(iterations, || {
        black_box(parse_properties());
    });
    let properties_query_time = measure(iterations, || {
        black_box(
            properties::execute_properties_query(
                black_box(&properties_query),
                black_box(&properties_document),
                QueryLimits::default(),
                &cancellation,
            )
            .expect("benchmark Properties query"),
        );
    });
    let properties_projection_time = measure(iterations, || {
        let result = properties_document.project(black_box(properties_projection_request));
        assert!(matches!(result, properties::ProjectionResult::Complete(_)));
        black_box(result);
    });
    let properties_materialization_time = measure(iterations, || {
        let result = properties::materialize(
            black_box(&properties_projected.value),
            black_box(&properties_materialization_request),
        );
        assert!(matches!(result, MaterializationResult::Complete(_)));
        black_box(result);
    });
    let properties_edit_time = measure(iterations, || {
        black_box(
            properties_document
                .commit(black_box(&properties_edit))
                .expect("benchmark Properties edit"),
        );
    });

    println!("suite=consema.line-formats.benchmark@1");
    println!("package_version={}", env!("CARGO_PKG_VERSION"));
    println!(
        "host={}{}{}",
        std::env::consts::OS,
        std::path::MAIN_SEPARATOR,
        std::env::consts::ARCH
    );
    println!("iterations={iterations}");
    println!("ini_source_bytes={}", INI_SOURCE.len());
    println!(
        "ini_source_pieces={}",
        ini_document.lossless_structural_index().pieces().len()
    );
    println!("ini_entries={}", ini_document.entries().len());
    println!("ini_materialized_bytes={ini_materialized_bytes}");
    println!("properties_source_bytes={}", PROPERTIES_SOURCE.len());
    println!(
        "properties_source_pieces={}",
        properties_document
            .lossless_structural_index()
            .pieces()
            .len()
    );
    println!(
        "properties_entries={}",
        properties_document.properties().len()
    );
    println!("properties_materialized_bytes={properties_materialized_bytes}");
    print_result(
        "ini_parse",
        ini_parse_time,
        iterations,
        Some(INI_SOURCE.len()),
    );
    print_result("ini_native_query", ini_query_time, iterations, None);
    print_result("ini_projection", ini_projection_time, iterations, None);
    print_result(
        "ini_materialization",
        ini_materialization_time,
        iterations,
        Some(ini_materialized_bytes),
    );
    print_result("ini_edit", ini_edit_time, iterations, None);
    print_result(
        "properties_parse",
        properties_parse_time,
        iterations,
        Some(PROPERTIES_SOURCE.len()),
    );
    print_result(
        "properties_native_query",
        properties_query_time,
        iterations,
        None,
    );
    print_result(
        "properties_projection",
        properties_projection_time,
        iterations,
        None,
    );
    print_result(
        "properties_materialization",
        properties_materialization_time,
        iterations,
        Some(properties_materialized_bytes),
    );
    print_result("properties_edit", properties_edit_time, iterations, None);
}

fn parse_ini() -> ini::Document {
    ini::parse(
        INI_SOURCE,
        ini::IniProfile::PortableV1,
        ini::IniEncodingSelection::ProfileDefault,
        ini::IniParseLimits::default(),
    )
    .expect("pinned INI fixture must parse")
}

fn parse_properties() -> properties::Document {
    properties::parse_reader(
        PROPERTIES_SOURCE,
        SourceEncoding::Utf8,
        properties::PropertiesParseLimits::default(),
    )
    .expect("pinned Properties fixture must parse")
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
