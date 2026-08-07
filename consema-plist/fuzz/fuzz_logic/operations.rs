// Fuzz-target logic: consema-plist formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description. The binary profile drives
// the binary-structure query domain; the XML profile drives the native and
// syntax query domains.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, ExecutableQuery, QueryDefinition, QueryDomain,
    QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy,
};
use std::sync::Arc;

use consema_plist::{
    EditPath, EditTransactionBuilder, EditValue, PlistBoolean, PlistEncodingSelection,
    PlistParseLimits, PlistProfile, ProjectionRequest, ProjectionResult,
    execute_plist_binary_query, execute_plist_native_query, execute_plist_syntax_query,
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
    for profile in [PlistProfile::XmlV1, PlistProfile::BinaryV1] {
        let Ok(document) = parse(
            Arc::<[u8]>::from(data),
            profile,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        ) else {
            continue; // fatal formation (including resource limits): pass
        };
        assert_eq!(
            document.render(),
            data,
            "formed documents render byte-exactly"
        );
        if let Some(index) = document.lossless_structural_index() {
            let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
            assert_eq!(
                covered,
                data.len(),
                "formation covers the source exhaustively"
            );
        }

        match profile {
            PlistProfile::XmlV1 => {
                let native = executable(QueryDomain::plist_native_v1());
                let syntax = executable(QueryDomain::plist_lossless_syntax_v1());
                let _ = execute_plist_native_query(
                    &native,
                    &document,
                    QueryLimits::default(),
                    &CancellationToken::new(),
                );
                let _ = execute_plist_syntax_query(
                    &syntax,
                    &document,
                    QueryLimits::default(),
                    &CancellationToken::new(),
                );
            }
            PlistProfile::BinaryV1 => {
                let binary = executable(QueryDomain::plist_binary_structure_v1());
                let _ = execute_plist_binary_query(
                    &binary,
                    &document,
                    QueryLimits::default(),
                    &CancellationToken::new(),
                );
            }
        }

        let request = ProjectionRequest::value_tree();
        match document.formation_status() {
            FormationStatus::Recovered => {
                assert!(
                    matches!(project(&document, request), ProjectionResult::Failed(_)),
                    "recovered documents must be rejected by projection"
                );
                let mut builder = EditTransactionBuilder::new(&document);
                builder.set_value(
                    EditPath::root(),
                    EditValue::Boolean(PlistBoolean::new(true)),
                );
                let transaction = builder.build();
                assert!(
                    document.commit(&transaction).is_err(),
                    "recovered documents must be rejected by edit"
                );
            }
            FormationStatus::Complete => {
                if let ProjectionResult::Complete(projected) = project(&document, request) {
                    let style = match profile {
                        PlistProfile::XmlV1 => "plist.xml-canonical",
                        PlistProfile::BinaryV1 => "plist.binary-canonical",
                    };
                    let materialization = MaterializationRequest::new(
                        document.profile(),
                        MaterializationStyleId::new(style, 1),
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
                builder.set_value(
                    EditPath::root(),
                    EditValue::Boolean(PlistBoolean::new(true)),
                );
                let transaction = builder.build();
                let _ = document.commit(&transaction);
            }
        }
    }
}
