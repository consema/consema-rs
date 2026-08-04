//! Adversarial corpus and Rust publication-property checks.

use consema_core::{ExecutableQuery, PortableValue, QueryDefinition, QueryExecution, QueryLimits};
use consema_document::{ChangeSet, ParseLimits};
use consema_json::{
    CompleteProjection, Document, JsonProfile, ProjectionRequest, ProjectionResult, parse,
};
use consema_pvce::{DecodeLimits, decode};
use consema_toml::{
    CompleteProjection as TomlCompleteProjection, Document as TomlDocument,
    ProjectionRequest as TomlProjectionRequest, ProjectionResult as TomlProjectionResult,
    TomlProfile, parse as parse_toml,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn completed_public_objects_are_send_and_sync() {
    assert_send_sync::<Document>();
    assert_send_sync::<PortableValue>();
    assert_send_sync::<ExecutableQuery>();
    assert_send_sync::<QueryDefinition>();
    assert_send_sync::<QueryExecution<consema_core::PortableMatch>>();
    assert_send_sync::<ProjectionRequest>();
    assert_send_sync::<ProjectionResult>();
    assert_send_sync::<CompleteProjection>();
    assert_send_sync::<ChangeSet>();
    assert_send_sync::<TomlDocument>();
    assert_send_sync::<TomlProjectionRequest>();
    assert_send_sync::<TomlProjectionResult>();
    assert_send_sync::<TomlCompleteProjection>();
}

#[test]
fn bounded_toml_corpus_never_panics_or_fakes_completion() {
    let fragments = [
        "",
        "key = 1",
        "key = [",
        "key = [[[[[[[[1]]]]]]]]",
        "a.b.c = { x = [1, 2, 3] }",
        "value = \"unterminated",
        "value = 999999999999999999999999999999999999",
        "name = 'first'\nname = 'second'",
        "[[products]]\nname = 'one'\n[[products]]\nname = 'two'",
        "time = 23:59:60",
        "value = [nan, inf, -inf, -0.0]",
        "ключ = 'значение'",
        "\u{feff}key = 1",
    ];
    for fragment in fragments {
        let result = parse_toml(
            fragment.as_bytes(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        );
        if let Ok(document) = result {
            assert_eq!(document.render(), fragment.as_bytes());
            let pieces = document.lossless_structural_index().pieces();
            assert!(
                pieces
                    .windows(2)
                    .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
            );
            assert_eq!(
                pieces.last().map_or(0, |piece| piece.span().end_byte()),
                fragment.len()
            );
        }
    }
    assert!(
        parse_toml(
            [0xff_u8].as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default()
        )
        .is_err()
    );

    let limited = ParseLimits {
        max_nesting_depth: 3,
        max_token_count: 5,
        max_node_count: 5,
        ..ParseLimits::default()
    };
    assert!(
        parse_toml(
            b"value = [[[[1]]]]".as_slice(),
            TomlProfile::Toml10V1,
            limited
        )
        .is_err()
    );
    assert!(
        parse_toml(
            b"values = [0, 1, 2]".as_slice(),
            TomlProfile::Toml10V1,
            limited
        )
        .is_err()
    );
}

#[test]
fn bounded_utf8_malicious_corpus_never_panics_or_fakes_completion() {
    let fragments = [
        "",
        "[",
        "{",
        "[[[[[[[[[[[[[[[[[[[[",
        "{\"a\":",
        "\"\\uD800\"",
        "/* unterminated",
        "[1e999999999999999999999999999999]",
        "{\"a\":1,\"a\":2,\"a\":3}",
        "[,,,,,,,,]",
        "😀",
        "\u{feff}null",
    ];
    for fragment in fragments {
        for profile in [JsonProfile::StrictV1, JsonProfile::JsoncBoundedV1] {
            let result = parse(fragment.as_bytes(), profile, ParseLimits::default());
            if let Ok(document) = result {
                assert_eq!(document.render(), fragment.as_bytes());
                let pieces = document.lossless_structural_index().pieces();
                assert!(
                    pieces
                        .windows(2)
                        .all(|pair| { pair[0].span().end_byte() == pair[1].span().start_byte() })
                );
            }
        }
    }

    let limited = ParseLimits {
        max_nesting_depth: 2,
        max_token_count: 4,
        max_node_count: 4,
        ..ParseLimits::default()
    };
    assert!(parse(b"[[[[0]]]]".as_slice(), JsonProfile::StrictV1, limited).is_err());
    assert!(parse(b"[0,1,2]".as_slice(), JsonProfile::StrictV1, limited).is_err());
}

#[test]
fn mutated_pvce_corpus_is_strictly_bounded() {
    let seeds: &[&[u8]] = &[
        b"",
        b"PVCE",
        b"PVCE\x01\x00\x00",
        b"PVCE\x81\x00\x00\x00",
        b"PVCE\x01\x10\x03\x01\x01\x00",
        b"PVCE\x01\x40\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
    ];
    let limits = DecodeLimits {
        max_bytes: 1024,
        max_depth: 8,
        max_nodes: 32,
        max_container_entries: 32,
        max_integer_bytes: 32,
        max_blob_bytes: 128,
    };
    for seed in seeds {
        let _ = decode(seed, limits);
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                let _ = decode(&mutated, limits);
            }
        }
    }
}

#[test]
fn cancelled_query_never_reports_completed_result() {
    let token = consema_core::CancellationToken::new();
    token.cancel();
    let mut capabilities = consema_core::CapabilitySet::new();
    capabilities.insert(consema_core::CapabilityId::new(
        "core.query.ordered-results",
        1,
    ));
    let executable = QueryDefinition::new(consema_core::QueryDomain::portable_value_v1())
        .validate()
        .unwrap()
        .bind(&capabilities)
        .unwrap();
    assert!(matches!(
        executable.execute_portable(&PortableValue::null(), QueryLimits::default(), &token),
        Err(consema_core::QueryFailure::Cancelled)
    ));
}
