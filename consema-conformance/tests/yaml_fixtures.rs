//! Production-shaped YAML fixture acceptance gates.

use consema_document::{
    FormationStatus, MaterializationFidelity, MaterializationRequest, MaterializationResult,
    MaterializationStyleId, NewlinePolicy, ParseLimits, ProfileId,
};
use consema_graph::{PgceLimits, decode_pgce, encode_pgce};
use consema_yaml::{
    Fidelity, GraphMaterializationResult, SharingPolicy, ValueProjectionRequest,
    ValueProjectionResult, YamlProfile, materialize_graph, materialize_value, parse,
    value_projection_failure_code,
};

struct Fixture {
    name: &'static str,
    source: &'static [u8],
    document_count: usize,
    alias_count: usize,
    tree_shaped: bool,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "kubernetes-workload",
        source: include_bytes!("../../../conformance/fixtures/yaml/kubernetes-workload.yaml"),
        document_count: 2,
        alias_count: 0,
        tree_shaped: true,
    },
    Fixture {
        name: "github-actions-ci",
        source: include_bytes!("../../../conformance/fixtures/yaml/github-actions-ci.yaml"),
        document_count: 1,
        alias_count: 0,
        tree_shaped: true,
    },
    Fixture {
        name: "compose-services",
        source: include_bytes!("../../../conformance/fixtures/yaml/compose-services.yaml"),
        document_count: 1,
        alias_count: 0,
        tree_shaped: true,
    },
    Fixture {
        name: "anchor-heavy",
        source: include_bytes!("../../../conformance/fixtures/yaml/anchor-heavy.yaml"),
        document_count: 1,
        alias_count: 5,
        tree_shaped: false,
    },
];

fn materialization_request() -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("yaml.1.2-core", 1),
        MaterializationStyleId::new("yaml.canonical-block", 1),
    )
    .with_newline(NewlinePolicy::Lf)
}

#[test]
fn real_project_yaml_fixtures_close_through_graph_and_pgce() {
    for fixture in FIXTURES {
        let document = parse(
            fixture.source,
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{} did not parse: {error:?}", fixture.name));
        assert_eq!(
            document.formation_status(),
            FormationStatus::Complete,
            "{}",
            fixture.name
        );
        assert_eq!(document.render(), fixture.source, "{}", fixture.name);
        assert_eq!(
            document.document_count(),
            fixture.document_count,
            "{}",
            fixture.name
        );
        assert_eq!(
            document.alias_count(),
            fixture.alias_count,
            "{}",
            fixture.name
        );
        assert_eq!(
            document
                .lossless_structural_index()
                .pieces()
                .iter()
                .map(|piece| piece.span().len())
                .sum::<usize>(),
            fixture.source.len(),
            "{}",
            fixture.name
        );

        let graph = document
            .project_graph()
            .unwrap_or_else(|error| panic!("{} graph projection failed: {error:?}", fixture.name));
        assert_eq!(
            graph.roots().len(),
            fixture.document_count,
            "{}",
            fixture.name
        );
        let pgce = encode_pgce(&graph)
            .unwrap_or_else(|error| panic!("{} PGCE encode failed: {error:?}", fixture.name));
        let decoded = decode_pgce(&pgce, PgceLimits::default())
            .unwrap_or_else(|error| panic!("{} PGCE decode failed: {error:?}", fixture.name));
        assert_eq!(decoded, graph, "{}", fixture.name);

        let GraphMaterializationResult::Complete(materialized) =
            materialize_graph(&graph, &materialization_request())
        else {
            panic!("{} graph materialization failed", fixture.name);
        };
        assert_eq!(
            materialized.fidelity,
            MaterializationFidelity::Exact,
            "{}",
            fixture.name
        );
        assert_eq!(
            materialized.document.project_graph().ok().as_ref(),
            Some(&graph),
            "{}",
            fixture.name
        );
    }
}

#[test]
fn yaml_fixture_tree_projection_is_explicit_about_sharing() {
    for fixture in FIXTURES {
        let document = parse(
            fixture.source,
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{} did not parse: {error:?}", fixture.name));

        if fixture.tree_shaped {
            if fixture.document_count != 1 {
                continue;
            }
            let ValueProjectionResult::Complete(projected) =
                document.project_value(ValueProjectionRequest::best_exact_v1())
            else {
                panic!("{} exact value projection failed", fixture.name);
            };
            assert_eq!(projected.fidelity, Fidelity::Exact, "{}", fixture.name);
            let MaterializationResult::Complete(materialized) =
                materialize_value(&projected.value, &materialization_request())
            else {
                panic!("{} value materialization failed", fixture.name);
            };
            assert!(matches!(
                materialized
                    .document
                    .project_value(ValueProjectionRequest::best_exact_v1()),
                ValueProjectionResult::Complete(ref result) if result.value == projected.value
            ));
        } else {
            let ValueProjectionResult::Failed(failure) =
                document.project_value(ValueProjectionRequest::best_exact_v1())
            else {
                panic!("{} silently erased sharing", fixture.name);
            };
            assert_eq!(
                value_projection_failure_code(&failure),
                "yaml.projection.sharing@1",
                "{}",
                fixture.name
            );
            let ValueProjectionResult::Complete(duplicated) = document.project_value(
                ValueProjectionRequest::best_exact_v1()
                    .with_sharing(SharingPolicy::DuplicateAcyclic),
            ) else {
                panic!("{} explicit acyclic duplication failed", fixture.name);
            };
            assert_eq!(
                duplicated.fidelity,
                Fidelity::Transformed,
                "{}",
                fixture.name
            );
        }
    }
}
