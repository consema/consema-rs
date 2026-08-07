//! Real-configuration HCL fixtures closure for the 0.11.0 release gate.

use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    ProfileId,
};
use consema_hcl::{
    ExpressionPolicy, HclEncodingSelection, HclParseLimits, HclProfile, ProjectionRequest,
    materialize, parse, project,
};
use std::sync::Arc;

/// Native-profile fixtures: Terraform-like `.tf` modules and HCL-using
/// project files (Packer, Nomad, Vault shapes).
const NATIVE_FIXTURES: &[(&str, &[u8])] = &[
    (
        "tf/main.tf",
        include_bytes!("../../../conformance/fixtures/hcl/tf/main.tf"),
    ),
    (
        "tf/network.tf",
        include_bytes!("../../../conformance/fixtures/hcl/tf/network.tf"),
    ),
    (
        "tf/variables.tf",
        include_bytes!("../../../conformance/fixtures/hcl/tf/variables.tf"),
    ),
    (
        "tf/packer.pkr.hcl",
        include_bytes!("../../../conformance/fixtures/hcl/tf/packer.pkr.hcl"),
    ),
    (
        "tf/nomad.hcl",
        include_bytes!("../../../conformance/fixtures/hcl/tf/nomad.hcl"),
    ),
    (
        "tf/vault.hcl",
        include_bytes!("../../../conformance/fixtures/hcl/tf/vault.hcl"),
    ),
];

/// Tfvars-profile fixtures: attribute-only `.tfvars` documents.
const TFVARS_FIXTURES: &[(&str, &[u8])] = &[
    (
        "tfvars/terraform.tfvars",
        include_bytes!("../../../conformance/fixtures/hcl/tfvars/terraform.tfvars"),
    ),
    (
        "tfvars/prod.tfvars",
        include_bytes!("../../../conformance/fixtures/hcl/tfvars/prod.tfvars"),
    ),
];

fn parse_fixture(source: &[u8], profile: HclProfile) -> consema_hcl::Document {
    let bytes: Arc<[u8]> = Arc::from(source);
    let document = parse(
        bytes,
        profile,
        HclEncodingSelection::ProfileDefault,
        HclParseLimits::default(),
    )
    .expect("fixture forms");
    assert_eq!(
        document.status(),
        FormationStatus::Complete,
        "fixture must form completely"
    );
    document
}

#[test]
fn hcl_fixtures_form_completely_and_round_trip_byte_exactly() {
    for (name, source) in NATIVE_FIXTURES {
        let document = parse_fixture(source, HclProfile::NativeV1);
        assert_eq!(
            document.render(),
            *source,
            "{name} render must be byte-exact"
        );
        assert!(
            document.diagnostics().is_empty(),
            "{name} must form without diagnostics"
        );
        let index = document.lossless_structural_index();
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, source.len(), "{name} lossless coverage");
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            index.pieces().len(),
            "{name} kinds parallel pieces"
        );
    }
    for (name, source) in TFVARS_FIXTURES {
        let document = parse_fixture(source, HclProfile::TfvarsV1);
        assert_eq!(
            document.render(),
            *source,
            "{name} render must be byte-exact"
        );
        assert!(
            document.diagnostics().is_empty(),
            "{name} must form without diagnostics"
        );
        let index = document.lossless_structural_index();
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, source.len(), "{name} lossless coverage");
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            index.pieces().len(),
            "{name} kinds parallel pieces"
        );
    }
}

/// One canonical materialization request under one profile.
fn canonical_request(profile: HclProfile) -> MaterializationRequest {
    let profile_id = match profile {
        HclProfile::NativeV1 => ProfileId::new("hcl.native", 1),
        HclProfile::TfvarsV1 => ProfileId::new("hcl.tfvars", 1),
    };
    MaterializationRequest::new(
        profile_id,
        MaterializationStyleId::new("hcl.canonical-document", 1),
    )
}

#[test]
fn hcl_fixtures_project_and_materialize_back_to_the_same_record() {
    // Production configurations contain references, for-expressions, and
    // template interpolations — derived expressions under RFC 0014 §8.1 —
    // so the gate projects under the explicit ProjectExpression policy and
    // requires the materialized reparse to reproduce the exact record.
    for (name, source) in NATIVE_FIXTURES {
        let document = parse_fixture(source, HclProfile::NativeV1);
        let request =
            ProjectionRequest::body_with_expression_policy(ExpressionPolicy::ProjectExpression);
        let consema_hcl::ProjectionResult::Complete(first) = project(&document, request) else {
            panic!("{name} must project under the ProjectExpression policy");
        };
        // The projected `hcl.body@1` record is the materialization record
        // (RFC 0014 §8.2: one ordered body of items), so the round trip
        // materializes it directly.
        let MaterializationResult::Complete(complete) =
            materialize(&first.value, &canonical_request(HclProfile::NativeV1))
        else {
            let MaterializationResult::Failed(attempt) =
                materialize(&first.value, &canonical_request(HclProfile::NativeV1))
            else {
                unreachable!("materialization is deterministic");
            };
            panic!("{name} must materialize canonically: {:?}", attempt.failure);
        };
        assert_eq!(
            complete.document.status(),
            FormationStatus::Complete,
            "{name} materialized document is complete"
        );
        let consema_hcl::ProjectionResult::Complete(second) = project(&complete.document, request)
        else {
            panic!("{name} reparsed document must project exactly");
        };
        assert_eq!(
            second.value, first.value,
            "{name} projection must be a materialization fixed point"
        );
    }
    for (name, source) in TFVARS_FIXTURES {
        let document = parse_fixture(source, HclProfile::TfvarsV1);
        let request =
            ProjectionRequest::body_with_expression_policy(ExpressionPolicy::ProjectExpression);
        let consema_hcl::ProjectionResult::Complete(first) = project(&document, request) else {
            panic!("{name} must project under the ProjectExpression policy");
        };
        let MaterializationResult::Complete(complete) =
            materialize(&first.value, &canonical_request(HclProfile::TfvarsV1))
        else {
            panic!("{name} must materialize canonically under hcl.tfvars@1");
        };
        assert_eq!(
            complete.document.status(),
            FormationStatus::Complete,
            "{name} materialized document is complete"
        );
        let consema_hcl::ProjectionResult::Complete(second) = project(&complete.document, request)
        else {
            panic!("{name} reparsed document must project exactly");
        };
        assert_eq!(
            second.value, first.value,
            "{name} projection must be a materialization fixed point"
        );
    }
}
