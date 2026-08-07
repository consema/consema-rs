// Fuzz-target logic: consema-json formation-to-operation gate
// (0.13.0 gate plan M2).
//
// Drives formation → operation with mutated inputs: parse with the
// production default limits, then exercise the query, projection,
// materialization and edit entry points. The 0.13.0 gate requires that
// recovered documents never reach project/materialize/edit — the gate
// rejects them — while query remains legitimate over recovered documents
// (the CLI inspect path). Resource limits are the production defaults, so
// a limit failure is a pass.
//
// Single source of truth included by the in-process harness
// (`crates/consema-conformance/tests/operation_fuzz.rs`) and wrapped by
// `crates/consema-json/fuzz/fuzz_targets/operations.rs`.

use consema_core::{
    CapabilityId, CapabilitySet, CancellationToken, ExecutableQuery, PortableValue,
    QueryDefinition, QueryDomain, QueryLimits,
};
use consema_document::{
    AssociationPlacement, FormationStatus, MaterializationRequest, MaterializationResult,
    MaterializationStyleId, NewlinePolicy, ParseLimits,
};
use consema_json::{
    Document, EditTransaction, EditTransactionBuilder, JsonProfile, JsonValueKind,
    ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, SemanticAvailability,
    execute_json_query, execute_json_syntax_query, materialize, parse,
};

/// Asserts the recovered-document projection gate. `Document::project`
/// rejects Recovered documents with the typed `ProjectionFailure::RecoveredDocument`
/// failure (fix of finding M2-F1), so any non-Failed outcome is a violation.
fn assert_recovered_projection(result: &ProjectionResult) {
    assert!(
        matches!(result, ProjectionResult::Failed(_)),
        "recovered documents must be rejected by projection"
    );
}

/// Asserts the recovered-document edit gate. `Document::commit` rejects
/// Recovered documents with `EditFailure::RecoveredDocument` (fix of
/// finding M2-F1), so any successful commit is a violation.
fn assert_recovered_edit(document: &Document, transaction: &EditTransaction) {
    assert!(
        document.commit(transaction).is_err(),
        "recovered documents must be rejected by edit"
    );
}

/// The single capability the fixed queries require.
pub fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

/// Builds one fixed valid query (bare `Input` over the whole document) for a
/// domain; a build failure is a harness bug, not an input property.
fn executable(domain: QueryDomain) -> ExecutableQuery {
    QueryDefinition::new(domain)
        .validate()
        .expect("the bare Input query is valid for every domain")
        .bind(&capabilities())
        .expect("the bare Input query needs only core.query.ordered-results")
}

/// One formation-to-operation pass over a mutated input, per profile.
pub fn fuzz_operations(data: &[u8]) {
    for profile in [
        JsonProfile::StrictV1,
        JsonProfile::JsoncBoundedV1,
        JsonProfile::Json5StandardV1,
    ] {
        let (native_domain, syntax_domain, target, style) = match profile {
            JsonProfile::StrictV1 | JsonProfile::JsoncBoundedV1 => (
                QueryDomain::json_native_v1(),
                QueryDomain::json_lossless_syntax_v1(),
                ProjectionTarget::BestExactCoreV1,
                "json.canonical-compact",
            ),
            JsonProfile::Json5StandardV1 => (
                QueryDomain::json_native_v2(),
                QueryDomain::json_lossless_syntax_v2(),
                ProjectionTarget::Json5BestExactCoreV1,
                "json5.canonical-compact",
            ),
        };
        let Ok(document) = parse(data, profile, ParseLimits::default()) else {
            continue; // fatal formation (including resource limits): pass
        };
        assert_eq!(document.render(), data, "formed documents render byte-exactly");
        let index = document.lossless_structural_index();
        let covered: usize = index
            .pieces()
            .iter()
            .map(|piece| piece.span().len())
            .sum();
        assert_eq!(covered, data.len(), "formation covers the source exhaustively");

        let native = executable(native_domain);
        let syntax = executable(syntax_domain);
        let _ = execute_json_query(
            &native,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );
        let _ = execute_json_syntax_query(
            &syntax,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );

        match document.formation_status() {
            FormationStatus::Recovered => {
                // Gate: recovered documents must never reach projection or
                // edit. Query above stays legitimate (CLI inspect path).
                let request = ProjectionRequestBuilder::new(target)
                    .build()
                    .expect("fixed projection request builds");
                let projection = document.project(&request);
                assert_recovered_projection(&projection);
                // The probe is a real structural edit (never an empty
                // transaction), so the rejection is meaningful.
                let mut builder = EditTransactionBuilder::new(&document);
                let root = document.root();
                if matches!(
                    root.kind(),
                    SemanticAvailability::Available(JsonValueKind::Object)
                ) {
                    builder.insert_member(
                        root.node_ref(),
                        "fuzz",
                        PortableValue::boolean(true),
                        AssociationPlacement::End,
                    );
                } else {
                    builder.literal_scalar(root.node_ref(), b"1".as_slice());
                }
                let transaction = builder.build();
                assert_recovered_edit(&document, &transaction);
            }
            FormationStatus::Complete => {
                let request = ProjectionRequestBuilder::new(target)
                    .build()
                    .expect("fixed projection request builds");
                if let ProjectionResult::Complete(projected) = document.project(&request) {
                    let materialization = MaterializationRequest::new(
                        document.profile(),
                        MaterializationStyleId::new(style, 1),
                    )
                    .with_newline(NewlinePolicy::None);
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
                // One real structural edit when the root is an Object, plus
                // the empty-transaction commit (base identity validation).
                let mut builder = EditTransactionBuilder::new(&document);
                let root = document.root();
                if matches!(
                    root.kind(),
                    SemanticAvailability::Available(JsonValueKind::Object)
                ) {
                    builder.insert_member(
                        root.node_ref(),
                        "fuzz",
                        PortableValue::boolean(true),
                        AssociationPlacement::End,
                    );
                }
                let transaction = builder.build();
                let _ = document.commit(&transaction);
            }
        }
    }
}
