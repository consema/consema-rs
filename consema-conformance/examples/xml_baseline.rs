//! Reproducible wall-clock baseline for the frozen XML production corpus.

use consema::document::{
    MaterializationRequest, MaterializationResult, MaterializationStyleId, ProfileId,
};
use consema::xml::{
    ProjectionRequest, ProjectionResult, XmlEncodingSelection, XmlParseLimits, XmlProfile,
    materialize, parse,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const MAVEN_SOURCE: &[u8] = include_bytes!("../../../conformance/fixtures/xml/maven-pom.xml");
const SERVICE_SOURCE: &[u8] =
    include_bytes!("../../../conformance/fixtures/xml/namespaced-service.xml");

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let maven_document = parse_document(MAVEN_SOURCE);
    let service_document = parse_document(SERVICE_SOURCE);
    let maven_record = project(&maven_document);
    let service_record = project(&service_document);
    let materialization_request = MaterializationRequest::new(
        ProfileId::new("xml.1.0-safe", 1),
        MaterializationStyleId::new("xml.safe-canonical-document", 1),
    );

    let parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(MAVEN_SOURCE));
    }
    let parse_elapsed = parse_start.elapsed();

    let projection_start = Instant::now();
    for _ in 0..iterations {
        black_box(project(&maven_document));
    }
    let projection_elapsed = projection_start.elapsed();

    let materialization_start = Instant::now();
    for _ in 0..iterations {
        black_box(materialize(&maven_record, &materialization_request));
    }
    let materialization_elapsed = materialization_start.elapsed();

    let service_parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(SERVICE_SOURCE));
    }
    let service_parse_elapsed = service_parse_start.elapsed();

    println!("fixture maven-pom.xml bytes={}", MAVEN_SOURCE.len());
    println!(
        "parse maven {iterations} iterations in {:?} ({:.1} ns/op)",
        parse_elapsed,
        ns_per_op(parse_elapsed, iterations)
    );
    println!(
        "projection maven {iterations} iterations in {:?} ({:.1} ns/op)",
        projection_elapsed,
        ns_per_op(projection_elapsed, iterations)
    );
    println!(
        "materialization maven {iterations} iterations in {:?} ({:.1} ns/op)",
        materialization_elapsed,
        ns_per_op(materialization_elapsed, iterations)
    );
    println!(
        "fixture namespaced-service.xml bytes={}",
        SERVICE_SOURCE.len()
    );
    println!(
        "parse namespaced-service {iterations} iterations in {:?} ({:.1} ns/op)",
        service_parse_elapsed,
        ns_per_op(service_parse_elapsed, iterations)
    );

    // The closure contract: materializing the pinned record always succeeds.
    let MaterializationResult::Complete(complete) =
        materialize(&service_record, &materialization_request)
    else {
        panic!("pinned XML fixture must materialize");
    };
    assert_eq!(
        complete.fidelity,
        consema::document::MaterializationFidelity::Exact
    );
}

#[allow(clippy::cast_precision_loss)]
fn ns_per_op(elapsed: Duration, iterations: u64) -> f64 {
    // Microseconds keep both operands far below f64's 52-bit mantissa.
    elapsed.as_micros() as f64 * 1_000.0 / iterations as f64
}

fn parse_document(source: &[u8]) -> consema::xml::Document {
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(source);
    let document = parse(
        bytes,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        XmlParseLimits::default(),
    )
    .expect("pinned fixture must form");
    assert_eq!(
        document.status(),
        consema::document::FormationStatus::Complete
    );
    document
}

fn project(document: &consema::xml::Document) -> consema::core::PortableValue {
    let ProjectionResult::Complete(projected) = document.project(ProjectionRequest::element_tree())
    else {
        panic!("pinned fixture must project exactly");
    };
    projected.value
}
