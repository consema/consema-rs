//! Library-level CLI protocol e2e (implementation plan §6 M9, §7 agent I).
//!
//! The process-level e2e (`crates/consema/tests/cli_*.rs`, agent H) covers
//! process behavior — exit codes, fsio, interruption recovery — through the
//! binary; this file drives the same protocol semantics through the lib API
//! surface only (never the bin), per the plan's non-interchangeable split:
//! envelope round-trips, batch state machines, exit classification over the
//! vector corpus, and the redaction/presentation boundary.

use consema::core::{BigInteger, ObjectBuilder, PortableValue, SequenceBuilder};
use consema::document::{
    ContentDigest, FormatOperationId, ProfileId, SourcePatch, SourcePatchLimits, SourceReplacement,
    SourceSnapshot,
};
use consema::protocol::{
    BatchPlanFileEntry, BatchPlanFileStatus, BatchPlanMessage, BatchResultFileEntry,
    BatchResultFileStatus, BatchResultMessage, CliCommand, CliOutputMessage,
    EditOperationSummaryMessage, ErrorCodeRegistry, ExitClass, ProtocolLimits, Redaction,
    classify_error_code, decode_json, encode_json, encode_pvce,
};
use consema_conformance::{CLI_V1_VECTORS_JSON, run_cli_v1};
use std::collections::BTreeMap;

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
        Some(vec![EditOperationSummaryMessage {
            operation: FormatOperationId::new("ini.edit.set-entry-value", 1),
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

fn conformance_payload(passed: &[&str], failed: &[(&str, &str)]) -> PortableValue {
    let mut passed_values = SequenceBuilder::new();
    for id in passed {
        passed_values.push(PortableValue::string(*id));
    }
    let mut failed_values = SequenceBuilder::new();
    for (id, message) in failed {
        failed_values.push(object(vec![
            ("id", PortableValue::string(*id)),
            ("message", PortableValue::string(*message)),
        ]));
    }
    object(vec![
        ("schema", PortableValue::string("cli.conformance@1")),
        ("suite", PortableValue::string("consema.cli.conformance@1")),
        ("passed", passed_values.build()),
        ("failed", failed_values.build()),
    ])
}

#[test]
fn the_full_cli_vector_suite_passes_over_the_lib_api() {
    let report = run_cli_v1();
    assert!(report.is_conformant(), "{report:#?}");
    assert_eq!(report.passed.len(), 40);
}

#[test]
fn envelope_round_trips_are_byte_deterministic_on_both_transports() {
    let limits = ProtocolLimits::default();
    let envelope = CliOutputMessage::new(
        CliCommand::Conformance,
        ExitClass::Success,
        "0.12.0",
        conformance_payload(
            &["cli.envelope@1", "cli.exit-code@1", "cli.redaction@1"],
            &[],
        ),
        Vec::new(),
        Redaction::new(false, 0).unwrap(),
    )
    .unwrap();
    // Encode the same envelope three times: byte-identical JSON.
    let first = envelope.to_json(limits).unwrap();
    let second = envelope.to_json(limits).unwrap();
    let third = envelope.to_json(limits).unwrap();
    assert_eq!(first, second);
    assert_eq!(second, third);
    // Both transports decode to the identical message.
    let from_json = CliOutputMessage::from_json(&first, limits).unwrap();
    let pvce = envelope.to_pvce(limits).unwrap();
    let from_pvce = CliOutputMessage::from_pvce(&pvce, limits).unwrap();
    assert_eq!(from_json, from_pvce);
    assert_eq!(from_json, envelope);
    // A redacted payload view round-trips byte-exactly (presentation facts
    // are carried by the envelope, never by rewriting values).
    let redacted = CliOutputMessage::new(
        CliCommand::Inspect,
        ExitClass::Success,
        "0.12.0",
        object(vec![
            ("schema", PortableValue::string("cli.inspect@1")),
            ("password", PortableValue::string("hunter2")),
        ]),
        Vec::new(),
        Redaction::new(true, 1).unwrap(),
    )
    .unwrap();
    let bytes = redacted.to_json(limits).unwrap();
    assert_eq!(
        CliOutputMessage::from_json(&bytes, limits)
            .unwrap()
            .to_json(limits)
            .unwrap(),
        bytes
    );
}

#[test]
fn the_batch_state_machine_plan_to_result_holds_through_the_lib() {
    let limits = ProtocolLimits::default();
    // plan: one planned file (with its patch) and one failed file.
    let plan = BatchPlanMessage::new("0.12.0", vec![planned_entry(), failed_entry()]).unwrap();
    let plan_value = plan.to_value().unwrap();
    let plan_bytes = encode_json(&plan_value, limits).unwrap();
    let decoded_plan =
        BatchPlanMessage::from_value(&decode_json(&plan_bytes, limits).unwrap()).unwrap();
    assert_eq!(decoded_plan, plan);
    // The planned entry carries the true patch facts.
    let planned = decoded_plan
        .files()
        .iter()
        .find(|entry| entry.status() == BatchPlanFileStatus::Planned)
        .expect("planned entry");
    let patch = planned.source_patch().expect("source patch");
    assert_eq!(
        patch.base_digest(),
        planned.source_digest().expect("base digest")
    );
    assert_eq!(
        planned.source_digest(),
        Some(ContentDigest::of(base_snapshot().bytes()))
    );
    let replacement = &patch.replacements()[0];
    assert_eq!(replacement.original(), b"old");
    assert_eq!(replacement.replacement(), b"new");
    assert_eq!(patch.target_digest(), target_digest());
    // The failed file keeps the batch complete: plan carries both statuses.
    assert_eq!(
        decoded_plan
            .files()
            .iter()
            .map(|entry| match entry.status() {
                BatchPlanFileStatus::Planned => "planned",
                BatchPlanFileStatus::Failed => "failed",
            })
            .collect::<Vec<_>>(),
        vec!["planned", "failed"]
    );
    // apply: the result carries the same order, the completed entry holds
    // the plan's own target digest, and the per-file facts stay truthful.
    let result = BatchResultMessage::new(
        "0.12.0",
        vec![
            BatchResultFileEntry::new(
                "app.conf",
                BatchResultFileStatus::Completed,
                None,
                Some(patch.target_digest()),
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
        ],
    )
    .unwrap();
    let result_bytes = encode_json(&result.to_value(), limits).unwrap();
    let decoded_result =
        BatchResultMessage::from_value(&decode_json(&result_bytes, limits).unwrap()).unwrap();
    assert_eq!(decoded_result, result);
    // Cross-record invariant: the completed result digest equals the plan's
    // patch target digest, in the same file order.
    assert_eq!(
        decoded_result.files()[0].target_digest(),
        Some(patch.target_digest())
    );
    assert_eq!(
        decoded_result.files()[0].path(),
        decoded_plan.files()[0].path()
    );
    assert_eq!(
        decoded_result.files()[1].failure_code(),
        Some("core.source.patch-original-mismatch@1")
    );
    // The same flow round-trips through PVCE/1.
    let pvce = encode_pvce(&result.to_value(), limits).unwrap();
    assert_eq!(
        BatchResultMessage::from_value(&decode_json(&result_bytes, limits).unwrap()).unwrap(),
        BatchResultMessage::from_value(&consema::protocol::decode_pvce(&pvce, limits).unwrap())
            .unwrap()
    );
}

#[test]
fn interruption_recovery_semantics_hold_at_the_record_level() {
    // The RFC 0015 §9.4 three-way rule branches onto the frozen result
    // statuses: the in-flight manifest records pending (both facts null),
    // an effective file records completed (target digest present), and a
    // diverged file records skipped-stale (failure code present, terminal).
    let pending = BatchResultFileEntry::new(
        "app.conf",
        BatchResultFileStatus::Pending,
        None,
        None,
        false,
    )
    .unwrap();
    let skipped = BatchResultFileEntry::new(
        "app.conf",
        BatchResultFileStatus::SkippedStale,
        Some("core.source.patch-base-mismatch@1".to_owned()),
        None,
        false,
    )
    .unwrap();
    // A completed run's manifest contains no pending entry: the four statuses
    // are closed, and the recovery branch statuses carry exactly their
    // documented fields.
    let manifest = BatchResultMessage::new(
        "0.12.0",
        vec![
            BatchResultFileEntry::new(
                "app.conf",
                BatchResultFileStatus::Completed,
                None,
                Some(target_digest()),
                false,
            )
            .unwrap(),
            skipped.clone(),
        ],
    )
    .unwrap();
    assert!(
        manifest
            .files()
            .iter()
            .all(|entry| entry.status() != BatchResultFileStatus::Pending)
    );
    assert_eq!(pending.status(), BatchResultFileStatus::Pending);
    assert_eq!(pending.failure_code(), None);
    assert_eq!(pending.target_digest(), None);
    assert_eq!(skipped.status(), BatchResultFileStatus::SkippedStale);
    assert_eq!(
        skipped.failure_code(),
        Some("core.source.patch-base-mismatch@1")
    );
    assert_eq!(skipped.target_digest(), None);
    // Re-running apply against the same plan branches on the current disk
    // bytes; at the record level the three branches map to the closed status
    // vocabulary with the documented per-status presence (pinned data-driven
    // by the vector case cli.batch-result.recovery-three-way-rule).
    let limits = ProtocolLimits::default();
    let bytes = encode_json(&manifest.to_value(), limits).unwrap();
    let decoded = BatchResultMessage::from_value(&decode_json(&bytes, limits).unwrap()).unwrap();
    assert_eq!(decoded, manifest);
}

#[test]
fn exit_classification_over_the_vector_corpus_is_exhaustive() {
    // Walk the published exit-code cases and classify every pinned code:
    // the vector corpus and the pure classification function agree.
    let mut classified = 0;
    let mut expected_classes = 0;
    for case in vector_cases() {
        let capability = object_field(&case, "capability")
            .and_then(PortableValue::as_string)
            .expect("case capability");
        if capability != "cli.exit-code@1" {
            continue;
        }
        let input = object_field(&case, "input").expect("case input");
        if let Some(names) = object_field(input, "names").and_then(PortableValue::as_sequence) {
            let codes = object_field(input, "codes")
                .and_then(PortableValue::as_sequence)
                .expect("codes");
            assert_eq!(names.len(), codes.len());
            for (name, code) in names.iter().zip(codes.iter()) {
                let name = name.as_string().expect("class name");
                let exit_class = ExitClass::parse(name).expect("closed set");
                assert_eq!(
                    i64::from(exit_class.exit_code()),
                    code.as_integer()
                        .and_then(BigInteger::to_i64)
                        .expect("code"),
                    "class {name}"
                );
                classified += 1;
            }
            continue;
        }
        let codes = object_field(input, "codes")
            .and_then(PortableValue::as_sequence)
            .expect("codes");
        let classes = object_field(&case, "expected")
            .and_then(|expected| object_field(expected, "classes"))
            .and_then(PortableValue::as_sequence)
            .expect("expected classes");
        assert_eq!(codes.len(), classes.len());
        for (code, expected) in codes.iter().zip(classes.iter()) {
            let code = code.as_string().expect("code string");
            let actual = classify_error_code(code);
            assert_eq!(
                actual.name(),
                expected.as_string().expect("class string"),
                "code {code}"
            );
            assert!(actual.exit_code() <= 5, "closed set violated: {code}");
            classified += 1;
            expected_classes += 1;
        }
    }
    // Every exit-code case in the corpus was walked (no silent skips).
    assert!(classified >= 36, "classified {classified} codes");
    assert!(
        expected_classes >= 30,
        "expected {expected_classes} classes"
    );
}

/// The published vector cases as portable values, projected exactly like the
/// suite runner (consema-json strict parse + best-exact-core projection).
fn vector_cases() -> Vec<PortableValue> {
    let vectors = consema::json::parse(
        CLI_V1_VECTORS_JSON.as_bytes(),
        consema::json::JsonProfile::StrictV1,
        consema::document::ParseLimits::default(),
    )
    .expect("published vector JSON forms");
    let request = consema::json::ProjectionRequestBuilder::new(
        consema::json::ProjectionTarget::BestExactCoreV1,
    )
    .build()
    .expect("fixed projection request");
    let consema::json::ProjectionResult::Complete(result) = vectors.project(&request) else {
        panic!("vector JSON projects");
    };
    let cases = result
        .value
        .as_object()
        .expect("vector object")
        .iter()
        .find(|entry| entry.key() == "cases")
        .expect("cases field")
        .value()
        .as_sequence()
        .expect("cases sequence");
    cases.to_vec()
}

fn object_field<'v>(value: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    value.as_object().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry.key() == name)
            .map(consema::core::ObjectEntry::value)
    })
}
