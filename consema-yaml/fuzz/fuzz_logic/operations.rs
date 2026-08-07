// Fuzz-target logic: consema-yaml formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description; the recovered-document gate
// is asserted here identically, and the graph projection entry
// (project_graph_bounded) is exercised because YAML anchors/aliases resolve
// there.

use consema_core::{
    CapabilityId, CapabilitySet, CancellationToken, ExecutableQuery, QueryDefinition,
    QueryDomain, QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, ParseLimits, ProfileId,
};
use consema_graph::GraphLimits;
use consema_yaml::{
    EditTransactionBuilder, ValueProjectionRequest, ValueProjectionResult, YamlProfile,
    execute_yaml_query, execute_yaml_syntax_query, materialize_value, parse,
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
    let Ok(document) = parse(data, YamlProfile::Yaml12CoreV1, ParseLimits::default()) else {
        return; // fatal formation (including resource limits): pass
    };
    assert_eq!(document.render(), data, "formed documents render byte-exactly");
    let index = document.lossless_structural_index();
    let covered: usize = index
        .pieces()
        .iter()
        .map(|piece| piece.span().len())
        .sum();
    assert_eq!(covered, data.len(), "formation covers the source exhaustively");

    let native = executable(QueryDomain::yaml_native_v1());
    let syntax = executable(QueryDomain::yaml_lossless_syntax_v1());
    let _ = execute_yaml_query(
        &native,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );
    let _ = execute_yaml_syntax_query(
        &syntax,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    );

    match document.formation_status() {
        FormationStatus::Recovered => {
            assert!(
                matches!(
                    document.project_value(ValueProjectionRequest::best_exact_v1()),
                    ValueProjectionResult::Failed(_)
                ),
                "recovered documents must be rejected by projection"
            );
            if let Some(root) = document.document(0) {
                let mut builder = EditTransactionBuilder::new(&document);
                builder.literal_scalar(root.node_ref(), b"1".as_slice());
                let transaction = builder.build();
                assert!(
                    document.commit(&transaction).is_err(),
                    "recovered documents must be rejected by edit"
                );
            }
            assert!(
                document.project_graph_bounded(GraphLimits::default()).is_err(),
                "recovered documents must be rejected by graph projection"
            );
        }
        FormationStatus::Complete => {
            if let ValueProjectionResult::Complete(projected) =
                document.project_value(ValueProjectionRequest::best_exact_v1())
            {
                let materialization = MaterializationRequest::new(
                    ProfileId::new("yaml.1.2-core", 1),
                    MaterializationStyleId::new("yaml.canonical-flow", 1),
                )
                .with_newline(NewlinePolicy::Lf);
                match materialize_value(&projected.value, &materialization) {
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
            let _ = document.project_graph_bounded(GraphLimits::default());
            if let Some(root) = document.document(0) {
                let mut builder = EditTransactionBuilder::new(&document);
                builder.literal_scalar(root.node_ref(), b"1".as_slice());
                let transaction = builder.build();
                let _ = document.commit(&transaction);
            }
        }
    }
}
