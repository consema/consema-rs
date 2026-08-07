// Fuzz-target logic: consema-xml formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description.

use consema_core::{
    CapabilityId, CapabilitySet, CancellationToken, ExecutableQuery, QueryDefinition,
    QueryDomain, QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    ProfileId,
};
use consema_xml::{
    EditTransactionBuilder, ProjectionRequest, ProjectionResult, XmlEncodingSelection,
    XmlParseLimits, XmlProfile, execute_xml_query, execute_xml_syntax_query, materialize,
    parse,
};

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

fn executable(domain: QueryDomain) -> ExecutableQuery {
    QueryDefinition::new(domain)
        .validate()
        .expect("the bare Input query is valid for every domain")
        .bind(&capabilities())
        .expect("the bare Input query needs only core.query.ordered-results")
}

/// One formation-to-operation pass over a mutated input.
pub fn fuzz_operations(data: &[u8]) {
    let Ok(document) = parse(
        data,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        XmlParseLimits::default(),
    ) else {
        return; // fatal formation (including resource limits): pass
    };
    assert_eq!(document.render(), data, "formed documents render byte-exactly");
    let index = document.lossless_structural_index().expect("structural index");
    let covered: usize = index
        .pieces()
        .iter()
        .map(|piece| piece.span().len())
        .sum();
    assert_eq!(covered, data.len(), "formation covers the source exhaustively");

    let native = executable(QueryDomain::xml_native_v1());
    let syntax = executable(QueryDomain::xml_lossless_syntax_v1());
    let _ = execute_xml_query(
        &native,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );
    let _ = execute_xml_syntax_query(
        &syntax,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );

    let request = ProjectionRequest::element_tree();
    match document.formation_status() {
        FormationStatus::Recovered => {
            assert!(
                matches!(document.project(request), ProjectionResult::Failed(_)),
                "recovered documents must be rejected by projection"
            );
            let mut builder = EditTransactionBuilder::new(&document);
            if let Some(root) = document.root() {
                builder.replace_text(root.node_ref(), "fuzz");
            }
            let transaction = builder.build();
            assert!(
                document.commit(&transaction).is_err(),
                "recovered documents must be rejected by edit"
            );
        }
        FormationStatus::Complete => {
            if let ProjectionResult::Complete(projected) = document.project(request) {
                let materialization = MaterializationRequest::new(
                    ProfileId::new("xml.1.0-safe", 1),
                    MaterializationStyleId::new("xml.safe-canonical-document", 1),
                );
                match materialize(&projected.value, &materialization) {
                    MaterializationResult::Complete(materialized) => {
                        assert_eq!(
                            materialized.document.formation_status(),
                            FormationStatus::Complete,
                            "materialization never yields a recovered document"
                        );
                    }
                    MaterializationResult::Failed(attempt) => {
                        assert!(
                            attempt.analyzed_input_paths.len()
                                <= materialization.limits().max_input_nodes,
                            "a failed materialization never over-analyzes input beyond the node budget"
                        );
                    }
                }
            }
            let mut builder = EditTransactionBuilder::new(&document);
            if let Some(root) = document.root() {
                builder.replace_text(root.node_ref(), "fuzz");
            }
            let transaction = builder.build();
            let _ = document.commit(&transaction);
        }
    }
}
