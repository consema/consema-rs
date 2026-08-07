// Fuzz-target logic: consema-ini formation-to-operation gate
// (0.13.0 gate plan M2). See crates/consema-json/fuzz/fuzz_logic/
// operations.rs for the full gate description. INI projection has an
// explicit `RecoveredDocument` gate; the harness asserts it.

use consema_core::{
    CancellationToken, CapabilityId, CapabilitySet, ExecutableQuery, QueryDefinition, QueryDomain,
    QueryLimits,
};
use consema_document::{
    FormationStatus, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy,
};
use consema_ini::{
    EditTransactionBuilder, IniEncodingSelection, IniParseLimits, IniProfile, ProjectionRequest,
    ProjectionResult, execute_ini_query, execute_ini_syntax_query, materialize, parse,
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

/// Materialization style per INI profile (production registry, RFC 0009).
fn style_for(profile: IniProfile) -> &'static str {
    match profile {
        IniProfile::PortableV1 => "ini.portable-canonical",
        IniProfile::WindowsV1 => "ini.windows-canonical",
        IniProfile::PythonConfigParserV1 => "ini.python-configparser-canonical",
    }
}

/// One formation-to-operation pass over a mutated input, per profile.
pub fn fuzz_operations(data: &[u8]) {
    for profile in [
        IniProfile::PortableV1,
        IniProfile::WindowsV1,
        IniProfile::PythonConfigParserV1,
    ] {
        let Ok(document) = parse(
            data,
            profile,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
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

        let native = executable(QueryDomain::ini_native_v1());
        let syntax = executable(QueryDomain::ini_lossless_syntax_v1());
        let _ = execute_ini_query(
            &native,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );
        let _ = execute_ini_syntax_query(
            &syntax,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        );

        let request = ProjectionRequest::best_exact_entry_mapping();
        match document.formation_status() {
            FormationStatus::Recovered => {
                assert!(
                    matches!(document.project(request), ProjectionResult::Failed(_)),
                    "recovered documents must be rejected by projection"
                );
                let transaction = EditTransactionBuilder::new(&document).build();
                assert!(
                    document.commit(&transaction).is_err(),
                    "recovered documents must be rejected by edit"
                );
            }
            FormationStatus::Complete => {
                if let ProjectionResult::Complete(projected) = document.project(request) {
                    let materialization = MaterializationRequest::new(
                        document.profile(),
                        MaterializationStyleId::new(style_for(profile), 1),
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
                let transaction = EditTransactionBuilder::new(&document).build();
                let _ = document.commit(&transaction);
            }
        }
    }
}
