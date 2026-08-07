//! Adversarial CLI machine-protocol inputs (RFC 0015 §16; implementation
//! plan §6 M9). Malformed envelopes, truncated and mutated payloads,
//! pathological batch records, and oversized manifests must never panic and
//! must decode or reject with the documented `core.protocol.*` codes.

use consema::core::{BigInteger, ObjectBuilder, PortableValue, SequenceBuilder};
use consema::document::{
    ContentDigest, ProfileId, SourcePatch, SourcePatchLimits, SourceReplacement, SourceSnapshot,
};
use consema::protocol::{
    BatchPlanFileEntry, BatchPlanFileStatus, BatchPlanMessage, BatchResultFileEntry,
    BatchResultFileStatus, BatchResultMessage, CliOutputMessage, ErrorCodeRegistry, ExitClass,
    ProtocolErrorKind, ProtocolLimits, Redaction, classify_error_code, decode_json, decode_pvce,
    encode_json, encode_pvce,
};
use std::collections::BTreeMap;

/// The canonical RFC 0015 §4.4 envelope bytes (the canonical form; the
/// published example carries one spurious `}` and is rejected).
fn canonical_envelope() -> Vec<u8> {
    let payload = inspect_payload();
    let envelope = CliOutputMessage::new(
        consema::protocol::CliCommand::Inspect,
        ExitClass::Success,
        "0.12.0",
        payload,
        Vec::new(),
        Redaction::new(false, 0).unwrap(),
    )
    .unwrap();
    envelope.to_json(ProtocolLimits::default()).unwrap()
}

fn inspect_payload() -> PortableValue {
    let mut candidates = SequenceBuilder::new();
    candidates.push(object(vec![
        (
            "profile",
            object(vec![
                ("id", PortableValue::string("ini.portable")),
                ("version", PortableValue::integer(BigInteger::from(1))),
            ]),
        ),
        ("reason", PortableValue::string("leading [section] line")),
    ]));
    let mut markers = SequenceBuilder::new();
    markers.push(PortableValue::string("[section]"));
    let reasons = SequenceBuilder::new();
    object(vec![
        ("schema", PortableValue::string("cli.inspect@1")),
        ("path", PortableValue::string("app.conf")),
        (
            "bytes",
            object(vec![
                ("size", PortableValue::integer(BigInteger::from(43))),
                (
                    "digest",
                    object(vec![
                        ("algorithm", PortableValue::string("sha256")),
                        (
                            "hex",
                            PortableValue::string(
                                "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                            ),
                        ),
                    ]),
                ),
            ]),
        ),
        ("bom", PortableValue::null()),
        ("symlink", PortableValue::boolean(false)),
        ("markers", markers.build()),
        ("candidates", candidates.build()),
        ("ambiguous", PortableValue::boolean(false)),
        ("ambiguity_reasons", reasons.build()),
        ("parse", PortableValue::null()),
    ])
}

fn object(entries: Vec<(&str, PortableValue)>) -> PortableValue {
    let mut builder = ObjectBuilder::new();
    for (key, value) in entries {
        builder.insert(key, value).expect("unique keys");
    }
    builder.build()
}

fn base_snapshot() -> SourceSnapshot {
    let mut bytes = vec![b'a'; 16];
    bytes.extend_from_slice(b"oldzzz");
    SourceSnapshot::from_utf8(bytes).unwrap()
}

fn planned_entry() -> BatchPlanFileEntry {
    let snapshot = base_snapshot();
    let patch = SourcePatch::create(
        &snapshot,
        vec![SourceReplacement::new(
            16,
            19,
            b"old".to_vec(),
            b"new".to_vec(),
        )],
        BTreeMap::new(),
        SourcePatchLimits::default(),
    )
    .unwrap();
    let mut summary = BTreeMap::new();
    summary.insert("name".to_owned(), "password".to_owned());
    BatchPlanFileEntry::new(
        "app.conf",
        BatchPlanFileStatus::Planned,
        Some(ProfileId::new("ini.portable", 1)),
        Some(patch.base_digest()),
        Some(vec![consema::protocol::EditOperationSummaryMessage {
            operation: consema::document::FormatOperationId::new("ini.edit.set-entry-value", 1),
            summary,
        }]),
        Some(patch),
        None,
        None,
        ErrorCodeRegistry::v7(),
    )
    .unwrap()
}

fn failed_entry() -> BatchPlanFileEntry {
    BatchPlanFileEntry::new(
        "broken.conf",
        BatchPlanFileStatus::Failed,
        None,
        None,
        None,
        None,
        Some("ini.parse.malformed-section@1".to_owned()),
        Some(Vec::new()),
        ErrorCodeRegistry::v7(),
    )
    .unwrap()
}

fn target_digest() -> ContentDigest {
    let mut bytes = vec![b'a'; 16];
    bytes.extend_from_slice(b"newzzz");
    ContentDigest::of(&bytes)
}

/// Asserts that a decode returns either `Ok` or an error whose kind code is
/// one of the documented protocol codes — the closure never panics.
fn decode_envelope(bytes: &[u8]) {
    let limits = ProtocolLimits::default();
    match CliOutputMessage::from_json(bytes, limits) {
        Ok(_) => {}
        Err(error) => assert!(
            error.kind().code().starts_with("core.protocol."),
            "unexpected error kind: {error}"
        ),
    }
}

#[test]
fn envelope_truncations_and_mutations_never_panic() {
    let seed = canonical_envelope();
    for length in 0..seed.len() {
        decode_envelope(&seed[..length]);
    }
    for index in 0..seed.len() {
        for mask in [0x01, 0x80, 0xff] {
            let mut mutated = seed.clone();
            mutated[index] ^= mask;
            decode_envelope(&mutated);
        }
    }
}

#[test]
fn malformed_envelopes_reject_with_documented_codes() {
    let limits = ProtocolLimits::default();
    // Garbage and empty input: invalid JSON; a well-formed non-object value
    // rejects as a wrong envelope type.
    for bytes in [b"".as_slice(), b"{", b"nonsense"] {
        let error = CliOutputMessage::from_json(bytes, limits).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidJson, "{bytes:?}");
    }
    let error = CliOutputMessage::from_json(b"[1,2,3]", limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::WrongType);
    // The RFC §4.4 published typo (one spurious `}`): invalid JSON.
    let typo = String::from_utf8(canonical_envelope()).unwrap().replace(
        "\"leading [section] line\"}}]}]}}",
        "\"leading [section] line\"}}]}}]}}",
    );
    assert_ne!(typo.as_bytes(), canonical_envelope().as_slice());
    let error = CliOutputMessage::from_json(typo.as_bytes(), limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidJson);
    // Whitespace inside canonical bytes: non-canonical JSON.
    let spaced = String::from_utf8(canonical_envelope())
        .unwrap()
        .replacen('{', "{ ", 1);
    let error = CliOutputMessage::from_json(spaced.as_bytes(), limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::NonCanonicalJson);
    // Unknown envelope field: re-encode the canonical value with one extra
    // field; the decoder rejects the undeclared field.
    let mut with_extra = ObjectBuilder::new();
    let canonical_value = decode_json(&canonical_envelope(), limits).unwrap();
    for entry in canonical_value.as_object().unwrap() {
        with_extra
            .insert(entry.key(), entry.value().clone())
            .unwrap();
    }
    with_extra.insert("extra", PortableValue::null()).unwrap();
    let unknown = encode_json(&with_extra.build(), limits).unwrap();
    let error = CliOutputMessage::from_json(&unknown, limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::UnknownField);
    // Unknown command and unknown exit class values.
    let bad_command = String::from_utf8(canonical_envelope())
        .unwrap()
        .replace("\"inspect\"", "\"frobnicate\"");
    let error = CliOutputMessage::from_json(bad_command.as_bytes(), limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    let bad_class = String::from_utf8(canonical_envelope())
        .unwrap()
        .replace("\"success\"", "\"done\"");
    let error = CliOutputMessage::from_json(bad_class.as_bytes(), limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    // Product-version shapes.
    for version in ["0.12", "0.12.0.1", "0.12.01", "00.1.0", "0.12.a"] {
        let bad_version = String::from_utf8(canonical_envelope())
            .unwrap()
            .replace("\"0.12.0\"", &format!("\"{version}\""));
        let error = CliOutputMessage::from_json(bad_version.as_bytes(), limits).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue, "{version}");
        assert_eq!(error.path(), "$.product_version");
    }
    // Redaction invariant violations.
    for (redacted, count) in [(true, 0), (false, 3)] {
        let error = Redaction::new(redacted, count).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
        assert_eq!(error.path(), "$.redaction");
    }
    // Payload/command consistency: a query envelope carrying a cli.inspect@1
    // payload is rejected even though the envelope schema is valid.
    let mismatched = String::from_utf8(canonical_envelope())
        .unwrap()
        .replace("\"inspect\"", "\"query\"");
    let error = CliOutputMessage::from_json(mismatched.as_bytes(), limits).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);
    assert_eq!(error.path(), "$.payload.schema");
    // A non-object payload is rejected.
    let mut value = decode_json(&canonical_envelope(), limits).unwrap();
    let entries = value.as_object().unwrap();
    let mut builder = ObjectBuilder::new();
    for entry in entries {
        let replacement = if entry.key() == "payload" {
            PortableValue::string("cli.inspect@1")
        } else {
            entry.value().clone()
        };
        builder.insert(entry.key(), replacement).unwrap();
    }
    value = builder.build();
    let error = CliOutputMessage::from_value(&value).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::WrongType);
    assert_eq!(error.path(), "$.payload");
    // The schema must be the first payload field.
    let mut reordered_payload = ObjectBuilder::new();
    reordered_payload
        .insert("path", PortableValue::string("x"))
        .unwrap();
    reordered_payload
        .insert("schema", PortableValue::string("cli.inspect@1"))
        .unwrap();
    let error = CliOutputMessage::new(
        consema::protocol::CliCommand::Inspect,
        ExitClass::Success,
        "0.12.0",
        reordered_payload.build(),
        Vec::new(),
        Redaction::new(false, 0).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);
}

#[test]
fn pvce_envelopes_never_panic_on_garbage() {
    let limits = ProtocolLimits::default();
    let envelope = CliOutputMessage::new(
        consema::protocol::CliCommand::Conformance,
        ExitClass::Success,
        "0.12.0",
        object(vec![
            ("schema", PortableValue::string("cli.conformance@1")),
            ("suite", PortableValue::string("consema.cli.conformance@1")),
            ("passed", {
                let passed = SequenceBuilder::new();
                passed.build()
            }),
            ("failed", {
                let failed = SequenceBuilder::new();
                failed.build()
            }),
        ]),
        Vec::new(),
        Redaction::new(false, 0).unwrap(),
    )
    .unwrap();
    let pvce = envelope.to_pvce(limits).unwrap();
    // Round trip and byte determinism.
    assert_eq!(
        CliOutputMessage::from_pvce(&pvce, limits).unwrap(),
        envelope
    );
    assert_eq!(envelope.to_pvce(limits).unwrap(), pvce);
    for length in 0..pvce.len() {
        let _ = CliOutputMessage::from_pvce(&pvce[..length], limits);
    }
    for index in 0..pvce.len() {
        for mask in [0x01, 0x80, 0xff] {
            let mut mutated = pvce.clone();
            mutated[index] ^= mask;
            let _ = CliOutputMessage::from_pvce(&mutated, limits);
        }
    }
    // Garbage PVCE bytes reject without panicking.
    for bytes in [
        b"".as_slice(),
        b"PVCE",
        b"PVCE\x01\x02\xff",
        b"\x00\x01\x02",
    ] {
        let error = decode_pvce(bytes, limits).unwrap_err();
        assert!(
            error.kind().code().starts_with("core.protocol."),
            "{bytes:?}"
        );
    }
}

#[test]
fn pathological_batch_plans_never_panic() {
    let plan = BatchPlanMessage::new("0.12.0", vec![planned_entry(), failed_entry()]).unwrap();
    let value = plan.to_value().unwrap();
    // Unknown status spellings are rejected at the documented path.
    let mut unknown_status = ObjectBuilder::new();
    for entry in value.as_object().unwrap() {
        let replacement = if entry.key() == "files" {
            let files = entry.value().as_sequence().unwrap();
            let mut builder = SequenceBuilder::new();
            for (index, file) in files.iter().enumerate() {
                let file_object = file.as_object().unwrap();
                let mut file_builder = ObjectBuilder::new();
                for field in file_object {
                    let replacement = if index == 0 && field.key() == "status" {
                        PortableValue::string("queued")
                    } else {
                        field.value().clone()
                    };
                    file_builder.insert(field.key(), replacement).unwrap();
                }
                builder.push(file_builder.build());
            }
            builder.build()
        } else {
            entry.value().clone()
        };
        unknown_status.insert(entry.key(), replacement).unwrap();
    }
    let error = BatchPlanMessage::from_value(&unknown_status.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    assert!(error.path().starts_with("$.files["), "{}", error.path());
    // A plan with command "apply" is rejected.
    let mut command_apply = ObjectBuilder::new();
    for entry in value.as_object().unwrap() {
        let replacement = if entry.key() == "command" {
            PortableValue::string("apply")
        } else {
            entry.value().clone()
        };
        command_apply.insert(entry.key(), replacement).unwrap();
    }
    let error = BatchPlanMessage::from_value(&command_apply.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    assert_eq!(error.path(), "$.command");
    // Planned entries without a patch are rejected.
    let mut without_patch = ObjectBuilder::new();
    for entry in value.as_object().unwrap() {
        let replacement = if entry.key() == "files" {
            let files = entry.value().as_sequence().unwrap();
            let mut builder = SequenceBuilder::new();
            for (index, file) in files.iter().enumerate() {
                let file_object = file.as_object().unwrap();
                let mut file_builder = ObjectBuilder::new();
                for field in file_object {
                    let replacement = if index == 0 && field.key() == "source_patch" {
                        PortableValue::null()
                    } else {
                        field.value().clone()
                    };
                    file_builder.insert(field.key(), replacement).unwrap();
                }
                builder.push(file_builder.build());
            }
            builder.build()
        } else {
            entry.value().clone()
        };
        without_patch.insert(entry.key(), replacement).unwrap();
    }
    let error = BatchPlanMessage::from_value(&without_patch.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::WrongType);
    // Source digest mismatching the patch base digest is rejected.
    let snapshot = base_snapshot();
    let patch = SourcePatch::create(
        &snapshot,
        vec![SourceReplacement::new(
            16,
            19,
            b"old".to_vec(),
            b"new".to_vec(),
        )],
        BTreeMap::new(),
        SourcePatchLimits::default(),
    )
    .unwrap();
    let error = BatchPlanFileEntry::new(
        "app.conf",
        BatchPlanFileStatus::Planned,
        Some(ProfileId::new("ini.portable", 1)),
        Some(patch.target_digest()),
        Some(Vec::new()),
        Some(patch),
        None,
        None,
        ErrorCodeRegistry::v7(),
    )
    .unwrap_err();
    assert_eq!(error.path(), "$.files[].source_digest");
    // Oversized paths are rejected.
    let long_path = "x".repeat(1025);
    let error = BatchPlanFileEntry::new(
        &long_path,
        BatchPlanFileStatus::Failed,
        None,
        None,
        None,
        None,
        Some("ini.parse.malformed-section@1".to_owned()),
        Some(Vec::new()),
        ErrorCodeRegistry::v7(),
    )
    .unwrap_err();
    assert_eq!(error.path(), "$.files[].path");
    // A planned entry missing any planning fact is rejected.
    let error = BatchPlanFileEntry::new(
        "app.conf",
        BatchPlanFileStatus::Planned,
        None,
        None,
        None,
        None,
        None,
        None,
        ErrorCodeRegistry::v7(),
    )
    .unwrap_err();
    assert_eq!(error.path(), "$.files[]");
    // Every decode path above returned a documented error or a message; the
    // base plan still round-trips.
    assert_eq!(
        BatchPlanMessage::from_value(&plan.to_value().unwrap()).unwrap(),
        plan
    );
}

#[test]
fn pathological_batch_results_never_panic() {
    let result = BatchResultMessage::new(
        "0.12.0",
        vec![
            BatchResultFileEntry::new(
                "app.conf",
                BatchResultFileStatus::Completed,
                None,
                Some(target_digest()),
                true,
            )
            .unwrap(),
            BatchResultFileEntry::new(
                "broken.conf",
                BatchResultFileStatus::Failed,
                Some("core.source.patch-original-mismatch@1".to_owned()),
                None,
                false,
            )
            .unwrap(),
            BatchResultFileEntry::new(
                "pending.conf",
                BatchResultFileStatus::Pending,
                None,
                None,
                false,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let value = result.to_value();
    // completed without a digest is rejected.
    let error = BatchResultFileEntry::new(
        "app.conf",
        BatchResultFileStatus::Completed,
        None,
        None,
        false,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    assert_eq!(error.path(), "$.files[]");
    // failed without a code is rejected.
    let error = BatchResultFileEntry::new(
        "broken.conf",
        BatchResultFileStatus::Failed,
        None,
        None,
        false,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    // pending with facts is rejected.
    for (code, digest) in [
        (Some("cli.write.io@1".to_owned()), None),
        (None, Some(target_digest())),
    ] {
        let error = BatchResultFileEntry::new(
            "pending.conf",
            BatchResultFileStatus::Pending,
            code,
            digest,
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }
    // An unknown status string is rejected by the decoder.
    let mut unknown_status = ObjectBuilder::new();
    for entry in value.as_object().unwrap() {
        let replacement = if entry.key() == "files" {
            let files = entry.value().as_sequence().unwrap();
            let mut builder = SequenceBuilder::new();
            for (index, file) in files.iter().enumerate() {
                let file_object = file.as_object().unwrap();
                let mut file_builder = ObjectBuilder::new();
                for field in file_object {
                    let replacement = if index == 0 && field.key() == "status" {
                        PortableValue::string("committed")
                    } else {
                        field.value().clone()
                    };
                    file_builder.insert(field.key(), replacement).unwrap();
                }
                builder.push(file_builder.build());
            }
            builder.build()
        } else {
            entry.value().clone()
        };
        unknown_status.insert(entry.key(), replacement).unwrap();
    }
    let error = BatchResultMessage::from_value(&unknown_status.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    assert!(error.path().starts_with("$.files["), "{}", error.path());
    // The base result still round-trips.
    assert_eq!(
        BatchResultMessage::from_value(&result.to_value()).unwrap(),
        result
    );
}

#[test]
fn huge_manifests_never_panic_and_stay_bounded() {
    // A 2,000-entry result manifest decodes and round-trips byte-exactly.
    let mut entries = Vec::new();
    for index in 0..2000 {
        entries.push(
            BatchResultFileEntry::new(
                format!("file-{index:04}.conf"),
                if index % 2 == 0 {
                    BatchResultFileStatus::Completed
                } else {
                    BatchResultFileStatus::SkippedStale
                },
                if index % 2 == 0 {
                    None
                } else {
                    Some("core.source.patch-base-mismatch@1".to_owned())
                },
                if index % 2 == 0 {
                    Some(target_digest())
                } else {
                    None
                },
                index % 3 == 0,
            )
            .unwrap(),
        );
    }
    let result = BatchResultMessage::new("0.12.0", entries).unwrap();
    let value = result.to_value();
    let limits = ProtocolLimits::default();
    let json = encode_json(&value, limits).unwrap();
    let decoded = BatchResultMessage::from_value(&decode_json(&json, limits).unwrap()).unwrap();
    assert_eq!(decoded, result);
    assert_eq!(
        BatchResultMessage::from_value(
            &decode_pvce(&encode_pvce(&value, limits).unwrap(), limits).unwrap()
        )
        .unwrap(),
        result
    );
    // The manifest transport budget is enforced: an undersized budget
    // rejects the very same bytes with a resource-limit error.
    let budget = ProtocolLimits {
        max_bytes: 1024,
        ..ProtocolLimits::default()
    };
    let error = decode_json(&json, budget).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::ResourceLimit);
    assert_eq!(
        classify_error_code(error.kind().code()),
        ExitClass::Limit,
        "resource-limit classifies as limit (RFC 0015 §5.2)"
    );
}

#[test]
fn deeply_nested_envelopes_are_bounded_by_protocol_limits() {
    // Depth beyond the protocol budget rejects with ResourceLimit, never
    // panicking and never accepting the payload. The recursive transports
    // need more than the harness thread's default stack for 300 levels, so
    // the probes run on a dedicated large-stack thread.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut value = PortableValue::null();
            for _ in 0..300 {
                let mut builder = ObjectBuilder::new();
                builder.insert("nested", value).unwrap();
                value = builder.build();
            }
            let limits = ProtocolLimits::default();
            let error = encode_json(&value, limits).unwrap_err();
            assert_eq!(error.kind(), ProtocolErrorKind::ResourceLimit);
            let shallow = ProtocolLimits {
                max_depth: 8,
                ..ProtocolLimits::default()
            };
            let error = encode_json(&value, shallow).unwrap_err();
            assert_eq!(error.kind(), ProtocolErrorKind::ResourceLimit);
            // The same tree under the default budget round-trips on both
            // transports.
            let mut value = PortableValue::null();
            for _ in 0..100 {
                let mut builder = ObjectBuilder::new();
                builder.insert("nested", value).unwrap();
                value = builder.build();
            }
            let json = encode_json(&value, limits).unwrap();
            assert_eq!(decode_json(&json, limits).unwrap(), value);
            let pvce = encode_pvce(&value, limits).unwrap();
            assert_eq!(decode_pvce(&pvce, limits).unwrap(), value);
        })
        .expect("large-stack thread")
        .join()
        .expect("depth probes must not panic");
}

#[test]
fn envelope_field_order_and_presence_are_strict() {
    let limits = ProtocolLimits::default();
    // A missing field is a documented error, not a silent default.
    let mut missing = ObjectBuilder::new();
    let value = decode_json(&canonical_envelope(), limits).unwrap();
    for entry in value.as_object().unwrap() {
        if entry.key() != "redaction" {
            missing.insert(entry.key(), entry.value().clone()).unwrap();
        }
    }
    let error = CliOutputMessage::from_value(&missing.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::MissingField);
    // Reordered envelope fields are rejected.
    let entries = value.as_object().unwrap();
    let mut reordered = ObjectBuilder::new();
    reordered
        .insert("schema", entries[0].value().clone())
        .unwrap();
    reordered
        .insert("exit_class", entries[2].value().clone())
        .unwrap();
    reordered
        .insert("command", entries[1].value().clone())
        .unwrap();
    for entry in entries.iter().skip(3) {
        reordered
            .insert(entry.key(), entry.value().clone())
            .unwrap();
    }
    let error = CliOutputMessage::from_value(&reordered.build()).unwrap_err();
    assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);
    // Every fixed field of the canonical envelope is present and typed.
    let envelope = CliOutputMessage::from_value(&value).unwrap();
    assert_eq!(envelope.command(), consema::protocol::CliCommand::Inspect);
    assert_eq!(envelope.exit_class(), ExitClass::Success);
    assert_eq!(envelope.product_version(), "0.12.0");
    assert_eq!(envelope.diagnostics().len(), 0);
    assert!(!envelope.redaction().redacted());
    assert_eq!(envelope.redaction().count(), 0);
}
