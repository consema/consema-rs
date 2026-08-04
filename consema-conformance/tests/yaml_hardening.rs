//! Adversarial YAML and PGCE closure properties for the 0.7.0 release gate.

use consema_document::ParseLimits;
use consema_graph::{PgceLimits, decode_pgce, encode_pgce, pgce_decode_error_code};
use consema_yaml::{
    Fidelity, SharingPolicy, TagPolicy, ValueProjectionLimits, ValueProjectionRequest,
    ValueProjectionResult, YamlProfile, parse, value_projection_failure_code,
};

fn parse_yaml(source: &[u8]) -> Result<consema_yaml::Document, String> {
    parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default())
        .map_err(|error| format!("{error:?}"))
}

fn assert_parse_closure(source: &[u8]) {
    if let Ok(document) = parse_yaml(source) {
        assert_eq!(document.render(), source);
        assert_eq!(
            document
                .lossless_structural_index()
                .pieces()
                .iter()
                .map(|piece| piece.span().len())
                .sum::<usize>(),
            source.len()
        );
        let _ = document.project_graph();
    }
}

#[test]
fn malformed_and_truncated_yaml_never_forms_partial_documents() {
    let malformed: &[&[u8]] = &[
        b"[*missing]\n",
        b"[unterminated\n",
        b"{key: value\n",
        b"%YAML 1.3\n---\nvalue\n",
        b"%YAML 1.2\n%YAML 1.2\n---\nvalue\n",
        b"key:\n\t- invalid\n",
        b"\xff",
        b"\xff\xfea",
    ];
    for source in malformed {
        assert!(parse_yaml(source).is_err(), "accepted {source:?}");
    }

    let seeds: &[&[u8]] = &[
        b"---\nname: service\nitems: [one, two]\n",
        "name: 配置\nemoji: \"🦀\"\n".as_bytes(),
        b"root: &root [one, *root]\n",
        b"text: |-\n  first\n  second\n",
    ];
    for seed in seeds {
        for length in 0..seed.len() {
            assert_parse_closure(&seed[..length]);
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                assert_parse_closure(&mutated);
            }
        }
    }
}

#[test]
fn yaml_parse_limits_reject_before_publishing_a_document() {
    let cases = [
        (
            b"key: value\n".as_slice(),
            ParseLimits {
                max_source_bytes: 4,
                ..ParseLimits::default()
            },
        ),
        (
            b"[[[[value]]]]\n".as_slice(),
            ParseLimits {
                max_nesting_depth: 2,
                ..ParseLimits::default()
            },
        ),
        (
            b"[one, two, three]\n".as_slice(),
            ParseLimits {
                max_token_count: 3,
                ..ParseLimits::default()
            },
        ),
        (
            b"{one: 1, two: 2}\n".as_slice(),
            ParseLimits {
                max_node_count: 2,
                ..ParseLimits::default()
            },
        ),
    ];
    for (source, limits) in cases {
        let error = parse(source, YamlProfile::Yaml12CoreV1, limits)
            .expect_err("bounded parse unexpectedly formed a document");
        assert_eq!(
            error.diagnostics().first().map(|item| item.code.as_str()),
            Some("core.parse.resource-limit@1")
        );
    }
}

#[test]
fn alias_bomb_stays_a_small_graph_and_tree_duplication_is_bounded() {
    let source = br"base: &base [zero, one]
level1: &level1 [*base, *base, *base, *base]
level2: &level2 [*level1, *level1, *level1, *level1]
level3: &level3 [*level2, *level2, *level2, *level2]
root: [*level3, *level3, *level3, *level3]
";
    let document = parse_yaml(source).expect("alias corpus must parse");
    assert_eq!(document.alias_count(), 16);
    let graph = document
        .project_graph()
        .expect("graph projection must not expand aliases");
    assert!(graph.node_count() < 32, "graph expanded aliases");

    let ValueProjectionResult::Failed(default_failure) =
        document.project_value(ValueProjectionRequest::best_exact_v1())
    else {
        panic!("default tree projection erased shared identity");
    };
    assert_eq!(
        value_projection_failure_code(&default_failure),
        "yaml.projection.sharing@1"
    );

    let bounded = ValueProjectionRequest::best_exact_v1()
        .with_sharing(SharingPolicy::DuplicateAcyclic)
        .with_limits(ValueProjectionLimits {
            max_value_nodes: 32,
            max_amplification_ratio: 64,
            ..ValueProjectionLimits::default()
        });
    let ValueProjectionResult::Failed(bounded_failure) = document.project_value(bounded) else {
        panic!("bounded duplication unexpectedly completed");
    };
    assert_eq!(
        value_projection_failure_code(&bounded_failure),
        "yaml.projection.resource-limit@1"
    );
}

#[test]
fn custom_tags_are_data_and_require_an_explicit_loss_policy() {
    for source in [
        b"!example scalar\n".as_slice(),
        b"!example [one, two]\n".as_slice(),
        b"!example {key: value}\n".as_slice(),
    ] {
        let document = parse_yaml(source).expect("custom tag must remain safe source data");
        assert!(document.project_graph().is_err());
        let ValueProjectionResult::Failed(failure) =
            document.project_value(ValueProjectionRequest::best_exact_v1())
        else {
            panic!("custom tag projected without an explicit policy");
        };
        assert_eq!(
            value_projection_failure_code(&failure),
            "yaml.projection.unsupported-tag@1"
        );
        let ValueProjectionResult::Complete(stripped) = document.project_value(
            ValueProjectionRequest::best_exact_v1().with_tags(TagPolicy::StripToNodeKind),
        ) else {
            panic!("explicit custom-tag stripping failed");
        };
        assert_eq!(stripped.fidelity, Fidelity::Lossy);
    }
}

#[test]
fn mutated_pgce_is_rejected_or_remains_canonical() {
    let document = parse_yaml(b"root: &root [one, *root]\n").expect("graph seed must parse");
    let graph = document.project_graph().expect("graph seed must project");
    let encoded = encode_pgce(&graph).expect("graph seed must encode");

    for length in 0..encoded.len() {
        assert!(
            decode_pgce(&encoded[..length], PgceLimits::default()).is_err(),
            "accepted truncated PGCE at {length}"
        );
    }
    let mut appended = encoded.clone();
    appended.push(0);
    assert!(decode_pgce(&appended, PgceLimits::default()).is_err());

    for index in 0..encoded.len() {
        for mask in [0x01, 0x80, 0xff] {
            let mut mutated = encoded.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = decode_pgce(&mutated, PgceLimits::default()) {
                assert_eq!(
                    encode_pgce(&decoded).ok().as_deref(),
                    Some(mutated.as_slice())
                );
            }
        }
    }

    let failure = decode_pgce(
        &encoded,
        PgceLimits {
            max_stream_bytes: encoded.len() - 1,
            ..PgceLimits::default()
        },
    )
    .expect_err("PGCE byte limit was not enforced");
    assert_eq!(
        pgce_decode_error_code(&failure),
        "core.pgce.resource-limit@1"
    );
}
