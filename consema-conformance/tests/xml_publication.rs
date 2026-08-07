//! XML publication properties for the 0.9.0 release gate: Send/Sync object
//! graph, fixture diagnostic bounds, and bounded materialization closure.

use consema_core::PortableValue;
use consema_document::{
    FailedMaterializationAttempt, FormationStatus, MaterializationFailure, MaterializationLimits,
    MaterializationRequest, MaterializationResult, MaterializationStyleId, ProfileId,
};
use consema_xml::{
    EditCommit, EditTransaction, ProjectionRequest, XmlElement, XmlEncodingSelection, XmlMatch,
    XmlParseLimits, XmlProfile, XmlSyntaxMatch, materialize, parse,
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
    parse(
        bytes,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        XmlParseLimits::default(),
    )
    .expect("fixture forms")
}

/// Projects one source document to its `xml.element-tree@1` record, the
/// legal `materialize` input shape.
fn element_tree(source: &[u8]) -> PortableValue {
    let document = parse_fixture(source);
    let consema_xml::ProjectionResult::Complete(projection) =
        document.project(ProjectionRequest::element_tree())
    else {
        panic!("fixture must project exactly");
    };
    projection.value
}

fn xml_materialization_request(limits: MaterializationLimits) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("xml.1.0-safe", 1),
        MaterializationStyleId::new("xml.safe-canonical-document", 1),
    )
    .with_limits(limits)
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn xml_publication_objects_are_send_and_sync() {
    assert_send_sync::<consema_xml::Document>();
    assert_send_sync::<XmlElement<'_>>();
    assert_send_sync::<XmlMatch>();
    assert_send_sync::<XmlSyntaxMatch>();
    assert_send_sync::<EditTransaction>();
    assert_send_sync::<EditCommit>();
}

#[test]
fn xml_fixture_diagnostics_stay_below_the_maximum() {
    let max_diagnostics = XmlParseLimits::default().common.max_diagnostics;
    for (name, source) in FIXTURES {
        let document = parse_fixture(source);
        assert_eq!(document.status(), FormationStatus::Complete, "{name}");
        assert!(
            document.diagnostics().len() <= max_diagnostics,
            "{name} diagnostics stay below the configured maximum"
        );
    }
}

#[test]
fn bounded_materialization_never_publishes_partial_documents() {
    // The `Failed` variant carries no Document and no output bytes by
    // construction; each case must fail with its stable resource limit while
    // never claiming to have analyzed more input than the node budget.
    let cases: Vec<(PortableValue, MaterializationLimits, MaterializationFailure)> = vec![
        (
            element_tree(br"<root><a/><b/><c/><d/><e/></root>"),
            MaterializationLimits {
                max_output_bytes: 8,
                ..MaterializationLimits::default()
            },
            MaterializationFailure::ResourceLimit("output-bytes"),
        ),
        (
            element_tree(br"<a><b><c><d/></c></b></a>"),
            MaterializationLimits {
                max_depth: 1,
                ..MaterializationLimits::default()
            },
            MaterializationFailure::ResourceLimit("input-depth"),
        ),
        (
            element_tree(br"<root><child>t</child></root>"),
            MaterializationLimits {
                max_provenance_entries: 0,
                ..MaterializationLimits::default()
            },
            MaterializationFailure::ResourceLimit("provenance-entries"),
        ),
    ];
    for (value, limits, expected) in cases {
        let result = materialize(&value, &xml_materialization_request(limits));
        let MaterializationResult::Failed(failure) = result else {
            panic!("bounded XML materialization completed with limits {limits:?}");
        };
        assert_eq!(failure.failure, expected, "stable failure under {limits:?}");
        assert!(
            failure.analyzed_input_paths.len() <= limits.max_input_nodes,
            "analyzed input paths stay within the node budget"
        );
    }

    // The writer enforces `max_input_nodes` during generation, after the
    // record has been fully validated, so a node-starved budget must fail
    // honestly instead of returning a partial tree.
    let wide = element_tree(br"<root><a/><b/><c/><d/><e/></root>");
    let limits = MaterializationLimits {
        max_input_nodes: 3,
        ..MaterializationLimits::default()
    };
    let result = materialize(&wide, &xml_materialization_request(limits));
    assert!(
        matches!(
            result,
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::ResourceLimit("input-nodes"),
                ..
            })
        ),
        "the writer must fail when the per-node budget is exhausted"
    );
}
