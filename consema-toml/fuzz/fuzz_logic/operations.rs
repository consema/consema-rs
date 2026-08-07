// Fuzz-target logic: consema-toml formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description; the recovered-document gate
// (recovered documents never reach project/materialize/edit) is asserted
// here identically.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, ExecutableQuery, QueryDefinition, QueryDomain,
    QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, ParseLimits,
};
use consema_toml::{
    EditTransactionBuilder, ProjectionRequest, ProjectionResult, ProjectionTarget, TomlProfile,
    execute_toml_query, execute_toml_syntax_query, materialize, parse,
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
    let Ok(document) = parse(data, TomlProfile::Toml10V1, ParseLimits::default()) else {
        return; // fatal formation (including resource limits): pass
    };
    assert_eq!(
        document.render(),
        data,
        "formed documents render byte-exactly"
    );
    let index = document.lossless_structural_index();
    let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
    assert_eq!(
        covered,
        data.len(),
        "formation covers the source exhaustively"
    );

    let native = executable(QueryDomain::toml_native_v1());
    let syntax = executable(QueryDomain::toml_lossless_syntax_v1());
    let _ = execute_toml_query(
        &native,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );
    let _ = execute_toml_syntax_query(
        &syntax,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );

    let request = ProjectionRequest::new(ProjectionTarget::BestExactCoreV1);
    match document.formation_status() {
        FormationStatus::Recovered => {
            assert!(
                matches!(document.project(request), ProjectionResult::Failed(_)),
                "recovered documents must be rejected by projection"
            );
            let mut builder = EditTransactionBuilder::new(&document);
            builder.literal_scalar(document.root().node_ref(), b"1".as_slice());
            let transaction = builder.build();
            assert!(
                document.commit(&transaction).is_err(),
                "recovered documents must be rejected by edit"
            );
        }
        FormationStatus::Complete => {
            if let ProjectionResult::Complete(projected) = document.project(request) {
                let materialization = MaterializationRequest::new(
                    document.profile(),
                    MaterializationStyleId::new("toml.canonical-document", 1),
                )
                .with_newline(NewlinePolicy::Lf);
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
            builder.literal_scalar(document.root().node_ref(), b"1".as_slice());
            let transaction = builder.build();
            let _ = document.commit(&transaction);
        }
    }
}
