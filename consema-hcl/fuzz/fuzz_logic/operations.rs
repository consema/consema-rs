// Fuzz-target logic: consema-hcl formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, ExecutableQuery, QueryDefinition, QueryDomain,
    QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, ProfileId,
};
use consema_hcl::{
    BodyPath, EditTransactionBuilder, EditValue, HclEncodingSelection, HclParseLimits, HclProfile,
    ProjectionRequest, ProjectionResult, execute_hcl_native_query, execute_hcl_syntax_query,
    materialize, parse, project,
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

/// One formation-to-operation pass over a mutated input, per profile.
pub fn fuzz_operations(data: &[u8]) {
    for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
        let Ok(document) = parse(
            data,
            profile,
            HclEncodingSelection::ProfileDefault,
            HclParseLimits::default(),
        ) else {
            continue; // fatal formation (including resource limits): pass
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

        let native = executable(QueryDomain::hcl_native_v1());
        let syntax = executable(QueryDomain::hcl_lossless_syntax_v1());
        let _ = execute_hcl_native_query(
            &native,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );
        let _ = execute_hcl_syntax_query(
            &syntax,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );

        let request = ProjectionRequest::body();
        match document.formation_status() {
            FormationStatus::Recovered => {
                assert!(
                    matches!(project(&document, request), ProjectionResult::Failed(_)),
                    "recovered documents must be rejected by projection"
                );
                let mut builder = EditTransactionBuilder::new(&document);
                builder.set_attribute_value(BodyPath::root(), "fuzz", EditValue::Boolean(true));
                let transaction = builder.build();
                assert!(
                    document.commit(&transaction).is_err(),
                    "recovered documents must be rejected by edit"
                );
            }
            FormationStatus::Complete => {
                if let ProjectionResult::Complete(projected) = project(&document, request) {
                    let materialization = MaterializationRequest::new(
                        ProfileId::new("hcl.native", 1),
                        MaterializationStyleId::new("hcl.canonical-document", 1),
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
                builder.set_attribute_value(BodyPath::root(), "fuzz", EditValue::Boolean(true));
                let transaction = builder.build();
                let _ = document.commit(&transaction);
            }
        }
    }
}
