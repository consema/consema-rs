//! Compiles the exact XML example published in README.md.

use consema::document::{
    MaterializationRequest, MaterializationResult, MaterializationStyleId, ProfileId,
};
use consema::xml::{
    ContentPlacement, EditTransactionBuilder, NameFacts, ProjectionRequest, ProjectionResult,
    XmlEncodingSelection, XmlParseLimits, XmlProfile, materialize, parse,
};

#[test]
fn readme_xml_example_is_exact() {
    let source = br#"<service xmlns:cfg="urn:cfg" cfg:port="8080"><name>catalog</name></service>"#;
    let document = parse(
        source.as_slice(),
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        XmlParseLimits::default(),
    )
    .expect("well-formed namespaced XML");
    assert_eq!(document.render(), source);

    let ProjectionResult::Complete(projected) = document.project(ProjectionRequest::element_tree())
    else {
        panic!("exact projection");
    };
    let MaterializationResult::Complete(converted) = materialize(
        &projected.value,
        &MaterializationRequest::new(
            ProfileId::new("xml.1.0-safe", 1),
            MaterializationStyleId::new("xml.safe-canonical-document", 1),
        ),
    ) else {
        panic!("canonical materialization");
    };
    assert_eq!(
        converted.document.render(),
        br#"<service xmlns:cfg="urn:cfg" cfg:port="8080"><name>catalog</name></service>
"#
        .as_slice(),
    );

    let mut transaction = EditTransactionBuilder::new(&document);
    transaction.insert_element(
        document.root().expect("root").node_ref(),
        NameFacts::new(None, "replica".to_owned(), None),
        Some("backup".to_owned()),
        ContentPlacement::End,
    );
    let commit = document.commit(&transaction.build()).expect("commit");
    assert_eq!(
        commit.document.render(),
        br#"<service xmlns:cfg="urn:cfg" cfg:port="8080"><name>catalog</name><replica>backup</replica></service>"#
            .as_slice(),
    );
}
