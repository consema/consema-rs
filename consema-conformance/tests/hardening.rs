//! Adversarial corpus and Rust publication-property checks.

use consema_core::{
    ExecutableQuery, ObjectBuilder, PortableValue, QueryDefinition, QueryExecution, QueryLimits,
};
use consema_document::{
    AssociationPlacement, ChangeSet, EncodingRequest, FormationStatus, MaterializationLimits,
    MaterializationRequest, MaterializationResult, MaterializationStyleId, NewlinePolicy,
    ParseLimits, ProfileId, SourceEncoding, SourceLimits, SourcePatch, SourcePatchError,
    SourcePatchLimits, SourceReplacement, SourceSnapshot,
};
use consema_json::{
    CompleteProjection, Document, EditTransactionBuilder as JsonEditBuilder, JsonProfile,
    ProjectionRequest, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{
    CapabilityDeclaration, ChangeSetMessage, ContractId, ContractRegistry, ConversionReportMessage,
    DiagnosticMessage, EditPlanMessage, FormatOperationRegistryMessage,
    MaterializationProvenanceMapMessage, MaterializationReportMessage,
    MaterializationRequestMessage, MaterializationResultMessage, ProfileDescriptor,
    ProjectionRequestMessage, ProjectionResultMessage, ProtocolError, ProtocolErrorKind,
    ProtocolLimits, ProtocolMessage, QueryResultMessage, RegistryManifest, SourcePatchMessage,
    SourceSnapshotMessage, decode_json, decode_pvce, encode_json, encode_pvce,
};
use consema_pvce::{DecodeLimits, decode};
use consema_toml::{
    CompleteProjection as TomlCompleteProjection, Document as TomlDocument,
    EditTransactionBuilder as TomlEditBuilder, ProjectionRequest as TomlProjectionRequest,
    ProjectionResult as TomlProjectionResult, TomlProfile, parse as parse_toml,
};
use std::collections::BTreeMap;
use std::sync::Arc;

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
    assert_send_sync::<ProtocolMessage>();
    assert_send_sync::<ProtocolError>();
    assert_send_sync::<ProfileDescriptor>();
    assert_send_sync::<CapabilityDeclaration>();
    assert_send_sync::<DiagnosticMessage>();
    assert_send_sync::<QueryResultMessage>();
    assert_send_sync::<ProjectionRequestMessage>();
    assert_send_sync::<ProjectionResultMessage>();
    assert_send_sync::<ChangeSetMessage>();
    assert_send_sync::<RegistryManifest>();
    assert_send_sync::<SourceSnapshot>();
    assert_send_sync::<SourcePatch>();
    assert_send_sync::<SourceSnapshotMessage>();
    assert_send_sync::<SourcePatchMessage>();
    assert_send_sync::<ConversionReportMessage>();
    assert_send_sync::<EditPlanMessage>();
    assert_send_sync::<FormatOperationRegistryMessage>();
    assert_send_sync::<MaterializationProvenanceMapMessage>();
    assert_send_sync::<MaterializationReportMessage>();
    assert_send_sync::<MaterializationRequestMessage>();
    assert_send_sync::<MaterializationResultMessage>();
}

fn object(key: &str, value: PortableValue) -> PortableValue {
    let mut object = ObjectBuilder::new();
    object.insert(key, value).unwrap();
    object.build()
}

fn json_materialization_request(limits: MaterializationLimits) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new("json.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None)
    .with_limits(limits)
}

fn toml_materialization_request(limits: MaterializationLimits) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("toml.1.0", 1),
        MaterializationStyleId::new("toml.canonical-document", 1),
    )
    .with_newline(NewlinePolicy::Lf)
    .with_limits(limits)
}

#[test]
fn bounded_materialization_never_returns_partial_documents() {
    let mut deep = PortableValue::boolean(true);
    for _ in 0..16 {
        deep = PortableValue::sequence(vec![deep]);
    }
    let cases = [
        (
            deep,
            MaterializationLimits {
                max_depth: 3,
                ..MaterializationLimits::default()
            },
        ),
        (
            PortableValue::sequence(vec![PortableValue::null(); 8]),
            MaterializationLimits {
                max_input_nodes: 4,
                ..MaterializationLimits::default()
            },
        ),
        (
            PortableValue::string("x".repeat(128)),
            MaterializationLimits {
                max_output_bytes: 16,
                ..MaterializationLimits::default()
            },
        ),
        (
            object("value", PortableValue::boolean(true)),
            MaterializationLimits {
                max_provenance_entries: 0,
                ..MaterializationLimits::default()
            },
        ),
    ];
    for (value, limits) in cases {
        match consema_json::materialize(&value, &json_materialization_request(limits)) {
            MaterializationResult::Complete(_) => panic!("bounded JSON materialization completed"),
            MaterializationResult::Failed(failure) => {
                assert!(failure.analyzed_input_paths.len() <= limits.max_input_nodes);
            }
        }
    }

    let toml_cases = [
        (
            object(
                "value",
                PortableValue::sequence(vec![PortableValue::sequence(vec![
                    PortableValue::sequence(vec![PortableValue::boolean(true)]),
                ])]),
            ),
            MaterializationLimits {
                max_depth: 2,
                ..MaterializationLimits::default()
            },
        ),
        (
            object("value", PortableValue::string("x".repeat(128))),
            MaterializationLimits {
                max_output_bytes: 16,
                ..MaterializationLimits::default()
            },
        ),
        (
            object("value", PortableValue::boolean(true)),
            MaterializationLimits {
                max_provenance_entries: 0,
                ..MaterializationLimits::default()
            },
        ),
    ];
    for (value, limits) in toml_cases {
        match consema_toml::materialize(&value, &toml_materialization_request(limits)) {
            MaterializationResult::Complete(_) => panic!("bounded TOML materialization completed"),
            MaterializationResult::Failed(failure) => {
                assert!(failure.analyzed_input_paths.len() <= limits.max_input_nodes);
            }
        }
    }
}

#[test]
fn structural_transactions_are_snapshot_bound_and_atomic() {
    let json_base = parse(
        br#"{"stable":true}"#.as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let json_other = parse(
        br#"{"stable":true}"#.as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let mut stale_json = JsonEditBuilder::new(&json_base);
    stale_json.insert_member(
        json_base.root().node_ref(),
        "added",
        PortableValue::boolean(true),
        AssociationPlacement::End,
    );
    assert!(json_other.commit(&stale_json.build()).is_err());
    assert_eq!(json_other.render(), br#"{"stable":true}"#);

    let mut conflicting_json = JsonEditBuilder::new(&json_base);
    conflicting_json
        .insert_member(
            json_base.root().node_ref(),
            "first",
            PortableValue::boolean(true),
            AssociationPlacement::End,
        )
        .insert_member(
            json_base.root().node_ref(),
            "second",
            PortableValue::boolean(false),
            AssociationPlacement::End,
        );
    assert!(json_base.commit(&conflicting_json.build()).is_err());
    assert_eq!(json_base.render(), br#"{"stable":true}"#);

    let toml_base = parse_toml(
        b"stable = true\n".as_slice(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .unwrap();
    let toml_other = parse_toml(
        b"stable = true\n".as_slice(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .unwrap();
    let mut stale_toml = TomlEditBuilder::new(&toml_base);
    stale_toml.insert_entry(
        toml_base.root().node_ref(),
        "added",
        PortableValue::boolean(true),
        AssociationPlacement::End,
    );
    assert!(toml_other.commit(&stale_toml.build()).is_err());
    assert_eq!(toml_other.render(), b"stable = true\n");

    let mut conflicting_toml = TomlEditBuilder::new(&toml_base);
    conflicting_toml
        .insert_entry(
            toml_base.root().node_ref(),
            "first",
            PortableValue::boolean(true),
            AssociationPlacement::End,
        )
        .insert_entry(
            toml_base.root().node_ref(),
            "second",
            PortableValue::boolean(false),
            AssociationPlacement::End,
        );
    assert!(toml_base.commit(&conflicting_toml.build()).is_err());
    assert_eq!(toml_base.render(), b"stable = true\n");
}

#[test]
fn bounded_source_and_patch_corpus_never_panics_or_returns_partial_facts() {
    let limits = SourceLimits {
        max_raw_bytes: 16,
        max_decoded_utf8_bytes: 16,
        max_decoded_scalars: 8,
    };
    let source_corpus = [
        (vec![], SourceEncoding::Utf8),
        (vec![0xff], SourceEncoding::Utf8),
        (vec![0xc0, 0x80], SourceEncoding::Utf8),
        (vec![0xff, 0xfe, 0x00, 0x00], SourceEncoding::Utf8),
        (vec![0xff, 0xfe, 0x41], SourceEncoding::Utf16Le),
        (vec![0x3d, 0xd8, 0x41, 0x00], SourceEncoding::Utf16Le),
        (vec![0xd8, 0x3d, 0x00, 0x41], SourceEncoding::Utf16Be),
        (vec![0xe9, 0xff], SourceEncoding::Latin1),
        (vec![0xff, 0xfe, 0x00, 0x00], SourceEncoding::Binary),
        (vec![b'a'; 17], SourceEncoding::Utf8),
    ];
    for (bytes, encoding) in source_corpus {
        let result = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(bytes.clone()),
            EncodingRequest::new(encoding),
            limits,
        );
        if let Ok(snapshot) = result {
            assert_eq!(snapshot.bytes(), bytes);
            assert_eq!(
                snapshot.digest(),
                consema_document::ContentDigest::of(&bytes)
            );
            if snapshot.decoded_text().is_some() {
                let terminal = snapshot.decoded_position(bytes.len()).unwrap();
                assert_eq!(terminal.raw_byte, bytes.len());
            }
        }
    }

    let base = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"abc".as_slice())).unwrap();
    let patch_limits = SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: 8,
            max_decoded_utf8_bytes: 8,
            max_decoded_scalars: 8,
        },
        max_replacements: 2,
        max_patch_bytes: 8,
    };
    let hostile_sets = [
        vec![SourceReplacement::new(
            usize::MAX,
            usize::MAX,
            [],
            b"x".as_slice(),
        )],
        vec![SourceReplacement::new(0, usize::MAX, [], [])],
        vec![
            SourceReplacement::new(1, 1, [], b"x".as_slice()),
            SourceReplacement::new(1, 1, [], b"y".as_slice()),
        ],
        vec![
            SourceReplacement::new(0, 2, b"ab".as_slice(), []),
            SourceReplacement::new(1, 3, b"bc".as_slice(), []),
        ],
        vec![SourceReplacement::new(3, 3, [], vec![b'x'; 32])],
    ];
    for replacements in hostile_sets {
        match SourcePatch::create(&base, replacements, BTreeMap::new(), patch_limits) {
            Ok(patch) => assert!(patch.apply(&base, patch_limits).is_err()),
            Err(error) => assert!(matches!(
                error,
                SourcePatchError::InvalidReplacement { .. }
                    | SourcePatchError::ReplacementOrder { .. }
                    | SourcePatchError::DuplicateInsertion { .. }
                    | SourcePatchError::OriginalMismatch { .. }
                    | SourcePatchError::ResourceLimit { .. }
            )),
        }
    }

    let too_many = vec![
        SourceReplacement::new(0, 0, [], []),
        SourceReplacement::new(1, 1, [], []),
        SourceReplacement::new(2, 2, [], []),
    ];
    assert!(matches!(
        SourcePatch::create(&base, too_many, BTreeMap::new(), patch_limits),
        Err(SourcePatchError::ResourceLimit { .. })
    ));
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
fn bounded_json5_mutation_corpus_never_panics_or_fakes_completion() {
    let fragments = [
        "",
        "// comment only",
        "/* unterminated",
        r"{a\u0021:1}",
        r"{π\u0021:1}",
        r"{\u0030bad:1}",
        r"{a:'\uD800'}",
        r"{a:'\x0g'}",
        r"{a:'\01'}",
        "{a:01}",
        "{a:0x}",
        "{a:1e+}",
        "{a:+Infinity,b:-NaN,c:0xFFFFFFFFFFFFFFFFFFFFFFFF}",
        "{a:[[[[[[[[[[0]]]]]]]]]]}",
        "{a:1,a:2,a:3,}",
        "{a:'line\\\ncontinuation'}",
        "{a:'\u{2028}\u{2029}'}",
        "\u{00a0}\u{1680}\u{2003}[1,2,]\u{3000}",
        "😀",
        "[,,,,,,,,]",
    ];
    for fragment in fragments {
        if let Ok(document) = parse(
            fragment.as_bytes(),
            JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        ) {
            assert_eq!(document.render(), fragment.as_bytes());
            assert!(document.diagnostics().len() <= ParseLimits::default().max_diagnostics);
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
            if document.formation_status() == FormationStatus::Complete {
                let request = ProjectionRequestBuilder::new(ProjectionTarget::Json5BestExactCoreV1)
                    .build()
                    .unwrap();
                assert!(matches!(
                    document.project(&request),
                    ProjectionResult::Complete(_)
                ));
            }
        }
    }

    let seed = br"{key:'value',hex:+0Xf,nf:-Infinity,list:[1,2,],}";
    for end in 0..seed.len() {
        if let Ok(document) = parse(
            &seed[..end],
            JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        ) {
            assert_eq!(document.render(), &seed[..end]);
        }
    }
    for index in 0..seed.len() {
        for mask in [0x01, 0x20, 0x80, 0xff] {
            let mut mutated = seed.to_vec();
            mutated[index] ^= mask;
            if let Ok(document) = parse(
                mutated.as_slice(),
                JsonProfile::Json5StandardV1,
                ParseLimits::default(),
            ) {
                assert_eq!(document.render(), mutated);
            }
        }
    }

    let nested = b"{a:[[[[0]]]]}";
    assert!(
        parse(
            nested.as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits {
                max_nesting_depth: 2,
                ..ParseLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        parse(
            b"[0,1,2,3]".as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits {
                max_token_count: 4,
                ..ParseLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        parse(
            b"{a:1,b:2}".as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits {
                max_node_count: 3,
                ..ParseLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        parse(
            b"{longName:'long value'}".as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits {
                max_source_bytes: 8,
                ..ParseLimits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn real_project_json_family_fixtures_close_through_strict_json() {
    let fixtures: &[(&[u8], JsonProfile, ProjectionTarget)] = &[
        (
            include_bytes!("../../../conformance/fixtures/real-world/package.json"),
            JsonProfile::StrictV1,
            ProjectionTarget::BestExactCoreV1,
        ),
        (
            include_bytes!("../../../conformance/fixtures/real-world/tsconfig.jsonc"),
            JsonProfile::JsoncBoundedV1,
            ProjectionTarget::BestExactCoreV1,
        ),
        (
            include_bytes!("../../../conformance/fixtures/real-world/vscode-settings.jsonc"),
            JsonProfile::JsoncBoundedV1,
            ProjectionTarget::BestExactCoreV1,
        ),
        (
            include_bytes!("../../../conformance/fixtures/real-world/application.json5"),
            JsonProfile::Json5StandardV1,
            ProjectionTarget::Json5BestExactCoreV1,
        ),
    ];

    for (source, profile, target) in fixtures {
        let document = parse(*source, *profile, ParseLimits::default()).unwrap();
        assert_eq!(document.formation_status(), FormationStatus::Complete);
        assert_eq!(document.render(), *source);
        let request = ProjectionRequestBuilder::new(*target).build().unwrap();
        let ProjectionResult::Complete(projected) = document.project(&request) else {
            panic!("fixture projection failed");
        };
        let MaterializationResult::Complete(materialized) = consema_json::materialize(
            &projected.value,
            &json_materialization_request(MaterializationLimits::default()),
        ) else {
            panic!("finite fixture did not materialize to strict JSON");
        };
        assert_eq!(
            materialized.document.formation_status(),
            FormationStatus::Complete
        );
        let strict_projection = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
            .build()
            .unwrap();
        assert!(matches!(
            materialized.document.project(&strict_projection),
            ProjectionResult::Complete(ref result) if result.value == projected.value
        ));
    }
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
fn bounded_protocol_corpus_never_panics_or_bypasses_payload_validation() {
    let limits = ProtocolLimits {
        max_bytes: 2048,
        max_depth: 8,
        max_nodes: 64,
        max_container_entries: 32,
        max_blob_bytes: 256,
        max_integer_bytes: 16,
    };
    let json_seeds: &[&[u8]] = &[
        b"",
        b"{",
        b"[]",
        b"\xff",
        br#" {"schema":"core.portable-value-json@1","value":{"type":"Null"}}"#,
        br#"{"schema":"core.portable-value-json@1","value":{"type":"String","value":"\u0078"}}"#,
        br#"{"schema":"core.portable-value-json@1","value":{"type":"Null","extra":true}}"#,
    ];
    for seed in json_seeds {
        let _ = decode_json(seed, limits);
    }

    let values = [
        PortableValue::null(),
        PortableValue::boolean(true),
        PortableValue::bytes([0, 0xff].as_slice()),
        PortableValue::sequence(vec![
            PortableValue::string("x"),
            PortableValue::integer(consema_core::BigInteger::from(-7)),
        ]),
    ];
    for value in values {
        let json = encode_json(&value, limits).unwrap();
        let pvce = encode_pvce(&value, limits).unwrap();
        assert_eq!(decode_json(&json, limits).unwrap(), value);
        assert_eq!(decode_pvce(&pvce, limits).unwrap(), value);
        for (bytes, json_transport) in [(&json, true), (&pvce, false)] {
            for index in 0..bytes.len() {
                for mask in [0x01, 0x80, 0xff] {
                    let mut mutated = bytes.clone();
                    mutated[index] ^= mask;
                    if json_transport {
                        let _ = decode_json(&mutated, limits);
                    } else {
                        let _ = decode_pvce(&mutated, limits);
                    }
                }
            }
            for end in 0..bytes.len() {
                if json_transport {
                    let _ = decode_json(&bytes[..end], limits);
                } else {
                    let _ = decode_pvce(&bytes[..end], limits);
                }
            }
        }
    }

    let mut deep = PortableValue::null();
    for _ in 0..6 {
        deep = PortableValue::sequence(vec![deep]);
    }
    let deep_json = encode_json(&deep, limits).unwrap();
    let shallow_limits = ProtocolLimits {
        max_depth: 2,
        ..limits
    };
    assert_eq!(
        decode_json(&deep_json, shallow_limits).unwrap_err().kind(),
        ProtocolErrorKind::ResourceLimit
    );

    let mut fake_payload = consema_core::ObjectBuilder::new();
    fake_payload
        .insert("schema", PortableValue::string("core.diagnostic@1"))
        .unwrap();
    fake_payload
        .insert("placeholder", PortableValue::null())
        .unwrap();
    let mut envelope = consema_core::ObjectBuilder::new();
    envelope
        .insert("schema", PortableValue::string("core.protocol-message@1"))
        .unwrap();
    envelope
        .insert("contract_id", PortableValue::string("core.diagnostic"))
        .unwrap();
    envelope
        .insert(
            "contract_version",
            PortableValue::integer(consema_core::BigInteger::from(1)),
        )
        .unwrap();
    envelope.insert("payload", fake_payload.build()).unwrap();
    let fake_json = encode_json(&envelope.build(), limits).unwrap();
    assert_eq!(
        ProtocolMessage::from_json(&fake_json, limits, consema_protocol::ContractRegistry::v1(),)
            .unwrap_err()
            .kind(),
        ProtocolErrorKind::UnknownField
    );
}

#[test]
fn protocol_v3_payloads_remain_registry_bound_under_mutation() {
    let limits = ProtocolLimits::default();
    let request = json_materialization_request(MaterializationLimits::default());
    let payload = MaterializationRequestMessage::from_request(&request)
        .to_value()
        .unwrap();
    let message = ProtocolMessage::new(
        ContractId::new("core.materialization-request", 1).unwrap(),
        payload,
        ContractRegistry::v3(),
    )
    .unwrap();
    let json = message.to_json(limits).unwrap();
    let pvce = message.to_pvce(limits).unwrap();

    assert_eq!(
        ProtocolMessage::from_json(&json, limits, ContractRegistry::v3()).unwrap(),
        message
    );
    assert_eq!(
        ProtocolMessage::from_pvce(&pvce, limits, ContractRegistry::v3()).unwrap(),
        message
    );
    assert_eq!(
        ProtocolMessage::from_json(&json, limits, ContractRegistry::v2())
            .unwrap_err()
            .kind(),
        ProtocolErrorKind::UnknownContract
    );

    for (bytes, json_transport) in [(&json, true), (&pvce, false)] {
        for index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x80;
            if json_transport {
                if let Ok(decoded) =
                    ProtocolMessage::from_json(&mutated, limits, ContractRegistry::v3())
                {
                    assert_eq!(decoded.to_json(limits).unwrap(), mutated);
                }
            } else if let Ok(decoded) =
                ProtocolMessage::from_pvce(&mutated, limits, ContractRegistry::v3())
            {
                assert_eq!(decoded.to_pvce(limits).unwrap(), mutated);
            }
        }
        for end in 0..bytes.len() {
            let decoded = if json_transport {
                ProtocolMessage::from_json(&bytes[..end], limits, ContractRegistry::v3())
            } else {
                ProtocolMessage::from_pvce(&bytes[..end], limits, ContractRegistry::v3())
            };
            assert!(decoded.is_err());
        }
    }

    let shallow = ProtocolLimits {
        max_depth: 2,
        ..limits
    };
    assert_eq!(
        ProtocolMessage::from_json(&json, shallow, ContractRegistry::v3())
            .unwrap_err()
            .kind(),
        ProtocolErrorKind::ResourceLimit
    );
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
