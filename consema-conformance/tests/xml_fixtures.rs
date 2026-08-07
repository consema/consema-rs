//! Real-configuration XML fixtures closure for the 0.9.0 release gate.

use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    ProfileId,
};
use consema_xml::{
    ProjectionRequest, XmlEncodingSelection, XmlParseLimits, XmlProfile, materialize, parse,
};
use std::sync::Arc;

const FIXTURES: &[(&str, &[u8])] = &[
    (
        "maven-pom.xml",
        include_bytes!("../../../conformance/fixtures/xml/maven-pom.xml"),
    ),
    (
        "spring-application.xml",
        include_bytes!("../../../conformance/fixtures/xml/spring-application.xml"),
    ),
    (
        "logback.xml",
        include_bytes!("../../../conformance/fixtures/xml/logback.xml"),
    ),
    (
        "app-server-config.xml",
        include_bytes!("../../../conformance/fixtures/xml/app-server-config.xml"),
    ),
    (
        "namespaced-service.xml",
        include_bytes!("../../../conformance/fixtures/xml/namespaced-service.xml"),
    ),
];

fn parse_fixture(source: &[u8]) -> consema_xml::Document {
    let bytes: Arc<[u8]> = Arc::from(source);
    let document = parse(
        bytes,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        XmlParseLimits::default(),
    )
    .expect("fixture forms");
    assert_eq!(
        document.status(),
        FormationStatus::Complete,
        "fixture must be well-formed"
    );
    document
}

#[test]
fn xml_fixtures_form_completely_and_round_trip_byte_exactly() {
    for (name, source) in FIXTURES {
        let document = parse_fixture(source);
        assert_eq!(
            document.render(),
            *source,
            "{name} render must be byte-exact"
        );
        assert!(
            document.diagnostics().is_empty(),
            "{name} must form without diagnostics"
        );
        let index = document.lossless_structural_index().expect("index");
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, source.len(), "{name} lossless coverage");
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            index.pieces().len(),
            "{name} kinds parallel pieces"
        );
    }
}

#[test]
fn xml_fixtures_project_exactly_and_materialize_back_to_the_same_record() {
    let request = MaterializationRequest::new(
        ProfileId::new("xml.1.0-safe", 1),
        MaterializationStyleId::new("xml.safe-canonical-document", 1),
    );
    for (name, source) in FIXTURES {
        let document = parse_fixture(source);
        let consema_xml::ProjectionResult::Complete(first) =
            document.project(ProjectionRequest::element_tree())
        else {
            panic!("{name} must project exactly");
        };
        let MaterializationResult::Complete(complete) = materialize(&first.value, &request) else {
            panic!("{name} must materialize canonically");
        };
        assert_eq!(
            complete.document.status(),
            FormationStatus::Complete,
            "{name} materialized document is complete"
        );
        let consema_xml::ProjectionResult::Complete(second) =
            complete.document.project(ProjectionRequest::element_tree())
        else {
            panic!("{name} reparsed document must project exactly");
        };
        assert_eq!(
            second.value, first.value,
            "{name} projection must be a materialization fixed point"
        );
    }
}
