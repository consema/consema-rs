//! Reproducible wall-clock baseline for the frozen HCL production corpus.

use consema::document::{
    MaterializationRequest, MaterializationResult, MaterializationStyleId, ProfileId,
};
use consema::hcl::{
    HclEncodingSelection, HclParseLimits, HclProfile, ProjectionRequest, ProjectionResult,
    materialize, parse, project,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const MAIN_TF_SOURCE: &[u8] = include_bytes!("../../../conformance/fixtures/hcl/tf/main.tf");
const TERRAFORM_TFVARS_SOURCE: &[u8] =
    include_bytes!("../../../conformance/fixtures/hcl/tfvars/terraform.tfvars");

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let native_document = parse_document(MAIN_TF_SOURCE, HclProfile::NativeV1);
    assert_eq!(
        native_document.render(),
        MAIN_TF_SOURCE,
        "pinned fixture renders byte-exactly"
    );
    let tfvars_document = parse_document(TERRAFORM_TFVARS_SOURCE, HclProfile::TfvarsV1);
    assert_eq!(
        tfvars_document.render(),
        TERRAFORM_TFVARS_SOURCE,
        "pinned fixture renders byte-exactly"
    );
    let tfvars_record = project_value(&tfvars_document);
    let materialization_request = MaterializationRequest::new(
        ProfileId::new("hcl.tfvars", 1),
        MaterializationStyleId::new("hcl.canonical-document", 1),
    );

    let native_parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(MAIN_TF_SOURCE, HclProfile::NativeV1));
    }
    let native_parse_elapsed = native_parse_start.elapsed();

    let tfvars_parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(
            TERRAFORM_TFVARS_SOURCE,
            HclProfile::TfvarsV1,
        ));
    }
    let tfvars_parse_elapsed = tfvars_parse_start.elapsed();

    let projection_start = Instant::now();
    for _ in 0..iterations {
        black_box(project_value(&tfvars_document));
    }
    let projection_elapsed = projection_start.elapsed();

    let materialization_start = Instant::now();
    for _ in 0..iterations {
        black_box(materialize(&tfvars_record, &materialization_request));
    }
    let materialization_elapsed = materialization_start.elapsed();

    println!("fixture main.tf bytes={}", MAIN_TF_SOURCE.len());
    println!(
        "parse hcl.native {iterations} iterations in {:?} ({:.1} ns/op)",
        native_parse_elapsed,
        ns_per_op(native_parse_elapsed, iterations)
    );
    println!(
        "fixture terraform.tfvars bytes={}",
        TERRAFORM_TFVARS_SOURCE.len()
    );
    println!(
        "parse hcl.tfvars {iterations} iterations in {:?} ({:.1} ns/op)",
        tfvars_parse_elapsed,
        ns_per_op(tfvars_parse_elapsed, iterations)
    );
    println!(
        "projection hcl.body {iterations} iterations in {:?} ({:.1} ns/op)",
        projection_elapsed,
        ns_per_op(projection_elapsed, iterations)
    );
    println!(
        "materialization hcl.canonical-document {iterations} iterations in {:?} ({:.1} ns/op)",
        materialization_elapsed,
        ns_per_op(materialization_elapsed, iterations)
    );

    // The closure contract: materializing the pinned record always succeeds.
    let MaterializationResult::Complete(complete) =
        materialize(&tfvars_record, &materialization_request)
    else {
        panic!("pinned HCL fixture must materialize");
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

fn parse_document(source: &[u8], profile: HclProfile) -> consema::hcl::Document {
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(source);
    let document = parse(
        bytes,
        profile,
        HclEncodingSelection::ProfileDefault,
        HclParseLimits::default(),
    )
    .expect("pinned fixture must form");
    assert_eq!(
        document.status(),
        consema::document::FormationStatus::Complete
    );
    document
}

fn project_value(document: &consema::hcl::Document) -> consema::core::PortableValue {
    let ProjectionResult::Complete(projected) = project(document, ProjectionRequest::body()) else {
        panic!("pinned fixture must project exactly");
    };
    projected.value
}
