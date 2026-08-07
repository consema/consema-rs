//! Shared language-neutral `consema.cli.conformance@1` runner.
//!
//! The library-side executor of the CLI machine-protocol vectors (RFC 0015
//! §16; implementation plan §6 M9): every case is dispatched by its
//! `capability` and executed against the consema-protocol v7 types — envelope
//! decode → revalidation → dual-transport comparison, exit classification via
//! [`classify_error_code`], batch state machines via the manifest types, and
//! the redaction record contract. The vector data drives every result; the
//! runner holds no expectation literals.

use super::{ConformanceReport, ensure, object_field};
use consema_core::{BigInteger, PortableValue};
use consema_document::{ParseLimits, SourcePatchLimits};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse as parse_json,
};
use consema_protocol::{
    BatchPlanFileEntry, BatchPlanFileStatus, BatchPlanMessage, BatchResultFileStatus,
    BatchResultMessage, CliOutputMessage, ErrorCodeRegistry, ExitClass, ProtocolErrorKind,
    ProtocolLimits, Redaction, classify_error_code, decode_json, encode_json, encode_pvce,
};
use std::collections::HashSet;

/// Frozen suite identifier expected in every CLI vector file.
const SUITE: &str = "consema.cli.conformance@1";

/// Embedded shared CLI suite bytes.
pub const CLI_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/cli-v1.json");

/// Runs the embedded `consema.cli.conformance@1` suite.
#[must_use]
pub fn run_cli_v1() -> ConformanceReport {
    run_cli_v1_json(CLI_V1_VECTORS_JSON)
}

/// Runs one CLI suite from JSON text.
#[must_use]
pub fn run_cli_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse_json(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published CLI vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("CLI vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    if suite != SUITE {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "unexpected suite identifier".to_owned(),
            )],
        };
    }
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for (index, case) in cases.iter().enumerate() {
        let id = object_value_field(case, "id")
            .and_then(PortableValue::as_string)
            .unwrap_or(&format!("case.{index}"))
            .to_owned();
        if !seen.insert(id.clone()) {
            report.failed.push((id, "duplicate case id".to_owned()));
            continue;
        }
        let result = run_case(case);
        match result {
            Ok(()) => report.passed.push(id),
            Err(message) => report.failed.push((id, message)),
        }
    }
    report
}

fn run_case(case: &PortableValue) -> Result<(), String> {
    let capability = object_value_field(case, "capability")
        .and_then(PortableValue::as_string)
        .ok_or("missing capability")?;
    match capability {
        "cli.envelope@1" => run_envelope(case),
        "cli.exit-code@1" => run_exit_code(case),
        "cli.batch-plan@1" => run_batch_plan(case),
        "cli.batch-result@1" => run_batch_result(case),
        "cli.redaction@1" => run_redaction(case),
        "cli.limit@1" => run_limit(case),
        "cli.detection@1" => Err(
            "cli.detection@1 is executed process-level (consema bin detect.rs); the \
             library-side suite covers protocol semantics only (RFC 0015 §16)"
                .to_owned(),
        ),
        _ => Err(format!("unknown capability {capability}")),
    }
}

fn object_value_field<'v>(value: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    value
        .as_object()
        .and_then(|object| object_field(object, name))
}

fn input_field<'v>(case: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    object_value_field(case, "input").and_then(|input| object_value_field(input, name))
}

fn expected_field<'v>(case: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    object_value_field(case, "expected").and_then(|expected| object_value_field(expected, name))
}

fn expected_string_field(case: &PortableValue, name: &str) -> Result<Option<String>, String> {
    Ok(match expected_field(case, name) {
        None => None,
        Some(value) => Some(
            value
                .as_string()
                .ok_or_else(|| format!("expected.{name} must be a string"))?
                .to_owned(),
        ),
    })
}

fn expected_integer_field(case: &PortableValue, name: &str) -> Result<Option<i64>, String> {
    Ok(match expected_field(case, name) {
        None => None,
        Some(value) => Some(
            value
                .as_integer()
                .and_then(BigInteger::to_i64)
                .ok_or_else(|| format!("expected.{name} must be an integer"))?,
        ),
    })
}

fn expected_boolean_field(case: &PortableValue, name: &str) -> Result<Option<bool>, String> {
    Ok(match expected_field(case, name) {
        None => None,
        Some(value) => Some(
            value
                .as_boolean()
                .ok_or_else(|| format!("expected.{name} must be a boolean"))?,
        ),
    })
}

fn expected_string_sequence_field(
    case: &PortableValue,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    Ok(match expected_field(case, name) {
        None => None,
        Some(value) => Some(
            value
                .as_sequence()
                .ok_or_else(|| format!("expected.{name} must be a sequence"))?
                .iter()
                .map(|item| {
                    item.as_string()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("expected.{name} items must be strings"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn input_string_sequence(case: &PortableValue, name: &str) -> Result<Vec<String>, String> {
    input_field(case, name)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("missing input.{name}"))?
        .iter()
        .map(|item| {
            item.as_string()
                .map(str::to_owned)
                .ok_or_else(|| format!("input.{name} items must be strings"))
        })
        .collect()
}

fn input_integer_sequence(case: &PortableValue, name: &str) -> Result<Vec<i64>, String> {
    input_field(case, name)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("missing input.{name}"))?
        .iter()
        .map(|item| {
            item.as_integer()
                .and_then(BigInteger::to_i64)
                .ok_or_else(|| format!("input.{name} items must be integers"))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// Runs one `cli.envelope@1` case.
///
/// Success cases decode `input.json` strictly, re-encode byte-exactly
/// (canonical bytes and byte-determinism), prove dual-transport equivalence
/// against the pinned PVCE bytes, and assert the fixed-field facts.
/// Rejection cases assert the documented `core.protocol.*` error code (and
/// path) of the strictly rejected bytes.
fn run_envelope(case: &PortableValue) -> Result<(), String> {
    let json_text = input_field(case, "json")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.json")?
        .to_owned();
    let limits = ProtocolLimits::default();
    if let Some(error_code) = expected_string_field(case, "error_code")? {
        let Err(error) = CliOutputMessage::from_json(json_text.as_bytes(), limits) else {
            return Err("envelope must be rejected".to_owned());
        };
        ensure(error.kind().code() == error_code)
            .map_err(|_| format!("envelope rejection {} != {error_code}", error.kind().code()))?;
        if let Some(error_path) = expected_string_field(case, "error_path")? {
            ensure(error.path() == error_path)
                .map_err(|_| format!("envelope rejection path {} != {error_path}", error.path()))?;
        }
        return Ok(());
    }
    let message = CliOutputMessage::from_json(json_text.as_bytes(), limits)
        .map_err(|error| format!("envelope decode: {error}"))?;
    let re_encoded = message
        .to_json(limits)
        .map_err(|error| format!("envelope re-encode: {error}"))?;
    ensure(re_encoded == json_text.as_bytes())
        .map_err(|_| "envelope re-encode must reproduce the input bytes exactly")?;
    let pvce = message
        .to_pvce(limits)
        .map_err(|error| format!("envelope PVCE encode: {error}"))?;
    if let Some(expected_pvce) = expected_string_field(case, "pvce_hex")? {
        ensure(hex(&pvce) == expected_pvce)
            .map_err(|_| format!("pvce_hex {} != {expected_pvce}", hex(&pvce)))?;
    }
    let decoded_pvce = CliOutputMessage::from_pvce(&pvce, limits)
        .map_err(|error| format!("envelope PVCE decode: {error}"))?;
    ensure(decoded_pvce == message)
        .map_err(|_| "dual transport must decode to the same envelope")?;
    let again = message
        .to_json(limits)
        .map_err(|error| format!("envelope re-encode 2: {error}"))?;
    ensure(again == re_encoded).map_err(|_| "envelope JSON is not byte-deterministic")?;
    assert_envelope_facts(&message, case)?;
    Ok(())
}

/// Asserts the optional fixed-field facts of one decoded envelope.
fn assert_envelope_facts(message: &CliOutputMessage, case: &PortableValue) -> Result<(), String> {
    if let Some(command) = expected_string_field(case, "command")? {
        ensure(message.command().name() == command)
            .map_err(|_| format!("command {} != {command}", message.command().name()))?;
    }
    if let Some(exit_class) = expected_string_field(case, "exit_class")? {
        ensure(message.exit_class().name() == exit_class)
            .map_err(|_| format!("exit_class {} != {exit_class}", message.exit_class().name()))?;
    }
    if let Some(product_version) = expected_string_field(case, "product_version")? {
        ensure(message.product_version() == product_version)
            .map_err(|_| "product_version mismatch".to_owned())?;
    }
    if let Some(payload_schema) = expected_string_field(case, "payload_schema")? {
        let actual = message
            .payload()
            .as_object()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.value().as_string())
            .ok_or("payload has no schema first field")?;
        ensure(actual == payload_schema)
            .map_err(|_| format!("payload schema {actual} != {payload_schema}"))?;
    }
    if let Some(redacted) = expected_boolean_field(case, "redacted")? {
        ensure(message.redaction().redacted() == redacted)
            .map_err(|_| "redaction.redacted mismatch".to_owned())?;
    }
    if let Some(count) = expected_integer_field(case, "count")? {
        ensure(i64::try_from(message.redaction().count()) == Ok(count))
            .map_err(|_| "redaction.count mismatch".to_owned())?;
    }
    if let Some(diagnostics) = expected_integer_field(case, "diagnostics_count")? {
        ensure(message.diagnostics().len() as i64 == diagnostics)
            .map_err(|_| "diagnostics count mismatch".to_owned())?;
    }
    if let Some(code) = expected_string_field(case, "diagnostic_code")? {
        ensure(message.diagnostics().iter().any(|item| item.code == code))
            .map_err(|_| format!("diagnostic {code} not found"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exit classification
// ---------------------------------------------------------------------------

/// Runs one `cli.exit-code@1` case.
///
/// The class-table case carries `input.names` and `input.codes` (the closed
/// RFC 0015 §5.1 table); the family-matrix cases carry `input.codes` and
/// `expected.classes` (the exhaustive RFC 0015 §5.2 family mapping).
fn run_exit_code(case: &PortableValue) -> Result<(), String> {
    if input_field(case, "names").is_some() {
        let names = input_string_sequence(case, "names")?;
        let codes = input_integer_sequence(case, "codes")?;
        ensure(names.len() == codes.len()).map_err(|_| "class table count mismatch".to_owned())?;
        for (index, (name, expected_code)) in names.iter().zip(codes.iter()).enumerate() {
            let exit_class =
                ExitClass::parse(name).ok_or_else(|| format!("unknown class {name}"))?;
            ensure(i64::from(exit_class.exit_code()) == *expected_code).map_err(|_| {
                format!(
                    "class table row {index}: {name} maps to {} instead of {expected_code}",
                    exit_class.exit_code()
                )
            })?;
        }
        return Ok(());
    }
    let codes = input_string_sequence(case, "codes")?;
    let classes =
        expected_string_sequence_field(case, "classes")?.ok_or("missing expected.classes")?;
    ensure(codes.len() == classes.len()).map_err(|_| "code/class count mismatch".to_owned())?;
    for (index, (code, expected)) in codes.iter().zip(classes.iter()).enumerate() {
        let actual = classify_error_code(code);
        ensure(actual.name() == expected).map_err(|_| {
            format!(
                "matrix row {index}: {code} classifies as {} instead of {expected}",
                actual.name()
            )
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Batch plan
// ---------------------------------------------------------------------------

fn planned_entry(plan: &BatchPlanMessage) -> Result<&BatchPlanFileEntry, String> {
    plan.files()
        .iter()
        .find(|entry| entry.status() == BatchPlanFileStatus::Planned)
        .ok_or_else(|| "no planned entry".to_owned())
}

/// Runs one `cli.batch-plan@1` case.
///
/// The record travels as `input.json` (the canonical tagged transport bytes,
/// the only JSON spelling that preserves `Bytes` precondition facts). Success
/// cases decode strictly, re-encode byte-exactly, prove PVCE equivalence, and
/// assert the status/presence facts; rejection cases assert the documented
/// error code and path of the tampered record.
fn run_batch_plan(case: &PortableValue) -> Result<(), String> {
    let json_text = input_field(case, "json")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.json")?
        .to_owned();
    let limits = ProtocolLimits::default();
    let record = decode_json(json_text.as_bytes(), limits)
        .map_err(|error| format!("plan transport decode: {error}"))?;
    if let Some(error_code) = expected_string_field(case, "error_code")? {
        let Err(error) = BatchPlanMessage::from_value(&record) else {
            return Err("plan record must be rejected".to_owned());
        };
        ensure(error.kind().code() == error_code)
            .map_err(|_| format!("plan rejection {} != {error_code}", error.kind().code()))?;
        if let Some(error_path) = expected_string_field(case, "error_path")? {
            ensure(error.path() == error_path)
                .map_err(|_| format!("plan rejection path {} != {error_path}", error.path()))?;
        }
        return Ok(());
    }
    let plan =
        BatchPlanMessage::from_value(&record).map_err(|error| format!("plan decode: {error}"))?;
    let transport =
        encode_json(&record, limits).map_err(|error| format!("plan re-encode: {error}"))?;
    ensure(transport == json_text.as_bytes())
        .map_err(|_| "plan record must re-encode to the exact input bytes")?;
    let re_encoded = plan
        .to_value()
        .map_err(|error| format!("plan re-encode: {error}"))?;
    ensure(re_encoded == record).map_err(|_| "plan re-encode must reproduce the record exactly")?;
    if let Some(pvce_hex) = expected_string_field(case, "pvce_hex")? {
        let pvce =
            encode_pvce(&record, limits).map_err(|error| format!("plan PVCE encode: {error}"))?;
        ensure(hex(&pvce) == pvce_hex)
            .map_err(|_| format!("plan pvce_hex {} != {pvce_hex}", hex(&pvce)))?;
    }
    if let Some(product_version) = expected_string_field(case, "product_version")? {
        ensure(plan.product_version() == product_version)
            .map_err(|_| "plan product_version mismatch".to_owned())?;
    }
    if let Some(statuses) = expected_string_sequence_field(case, "statuses")? {
        ensure(plan.files().len() == statuses.len()).map_err(|_| {
            format!(
                "plan file count {} != {}",
                plan.files().len(),
                statuses.len()
            )
        })?;
        for (entry, expected) in plan.files().iter().zip(statuses.iter()) {
            let actual = match entry.status() {
                BatchPlanFileStatus::Planned => "planned",
                BatchPlanFileStatus::Failed => "failed",
            };
            ensure(actual == expected)
                .map_err(|_| format!("plan status {actual} != {expected}"))?;
        }
    }
    if let Some(digest) = expected_string_field(case, "source_digest_hex")? {
        let entry = planned_entry(&plan)?;
        ensure(
            entry
                .source_digest()
                .is_some_and(|digest_owned| digest_owned.to_hex() == digest),
        )
        .map_err(|_| "plan source_digest mismatch".to_owned())?;
    }
    if let Some(digest) = expected_string_field(case, "target_digest_hex")? {
        let entry = planned_entry(&plan)?;
        let patch = entry
            .source_patch()
            .ok_or("planned entry without source_patch")?;
        ensure(patch.target_digest().to_hex() == digest)
            .map_err(|_| "plan patch target_digest mismatch".to_owned())?;
    }
    if let Some(code) = expected_string_field(case, "failure_code")? {
        let entry = plan
            .files()
            .iter()
            .find(|entry| entry.status() == BatchPlanFileStatus::Failed)
            .ok_or("no failed plan entry")?;
        ensure(entry.failure_code() == Some(code.as_str()))
            .map_err(|_| "plan failure_code mismatch".to_owned())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Batch result
// ---------------------------------------------------------------------------

/// Runs one `cli.batch-result@1` case.
///
/// The record travels as `input.json` (the canonical tagged transport bytes).
/// Success cases decode strictly, re-encode byte-exactly, prove PVCE
/// equivalence, and assert the status/presence facts; rejection cases assert
/// the documented error code and path. The recovery case carries
/// `input.branches` and pins the RFC 0015 §9.4 three-way rule data-driven.
fn run_batch_result(case: &PortableValue) -> Result<(), String> {
    if input_field(case, "branches").is_some() {
        return run_recovery_rule(case);
    }
    let json_text = input_field(case, "json")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.json")?
        .to_owned();
    let limits = ProtocolLimits::default();
    let record = decode_json(json_text.as_bytes(), limits)
        .map_err(|error| format!("result transport decode: {error}"))?;
    if let Some(error_code) = expected_string_field(case, "error_code")? {
        let Err(error) = BatchResultMessage::from_value(&record) else {
            return Err("result record must be rejected".to_owned());
        };
        ensure(error.kind().code() == error_code)
            .map_err(|_| format!("result rejection {} != {error_code}", error.kind().code()))?;
        if let Some(error_path) = expected_string_field(case, "error_path")? {
            ensure(error.path() == error_path)
                .map_err(|_| format!("result rejection path {} != {error_path}", error.path()))?;
        }
        return Ok(());
    }
    let result = BatchResultMessage::from_value(&record)
        .map_err(|error| format!("result decode: {error}"))?;
    let transport =
        encode_json(&record, limits).map_err(|error| format!("result re-encode: {error}"))?;
    ensure(transport == json_text.as_bytes())
        .map_err(|_| "result record must re-encode to the exact input bytes")?;
    let re_encoded = result.to_value();
    ensure(re_encoded == record)
        .map_err(|_| "result re-encode must reproduce the record exactly")?;
    if let Some(pvce_hex) = expected_string_field(case, "pvce_hex")? {
        let pvce =
            encode_pvce(&record, limits).map_err(|error| format!("result PVCE encode: {error}"))?;
        ensure(hex(&pvce) == pvce_hex)
            .map_err(|_| format!("result pvce_hex {} != {pvce_hex}", hex(&pvce)))?;
    }
    if let Some(product_version) = expected_string_field(case, "product_version")? {
        ensure(result.product_version() == product_version)
            .map_err(|_| "result product_version mismatch".to_owned())?;
    }
    if let Some(statuses) = expected_string_sequence_field(case, "statuses")? {
        ensure(result.files().len() == statuses.len()).map_err(|_| {
            format!(
                "result file count {} != {}",
                result.files().len(),
                statuses.len()
            )
        })?;
        for (entry, expected) in result.files().iter().zip(statuses.iter()) {
            let actual = match entry.status() {
                BatchResultFileStatus::Completed => "completed",
                BatchResultFileStatus::Failed => "failed",
                BatchResultFileStatus::Pending => "pending",
                BatchResultFileStatus::SkippedStale => "skipped-stale",
            };
            ensure(actual == expected)
                .map_err(|_| format!("result status {actual} != {expected}"))?;
        }
    }
    if let Some(digest) = expected_string_field(case, "target_digest_hex")? {
        let entry = result
            .files()
            .iter()
            .find(|entry| entry.status() == BatchResultFileStatus::Completed)
            .ok_or("no completed result entry")?;
        ensure(
            entry
                .target_digest()
                .is_some_and(|digest_owned| digest_owned.to_hex() == digest),
        )
        .map_err(|_| "result target_digest mismatch".to_owned())?;
    }
    if let Some(redacted) = expected_boolean_field(case, "redacted")? {
        let entry = result.files().first().ok_or("no result entries")?;
        ensure(entry.redacted() == redacted).map_err(|_| "result redacted mismatch".to_owned())?;
    }
    if let Some(code) = expected_string_field(case, "failure_code")? {
        let entry = result
            .files()
            .iter()
            .find(|entry| {
                matches!(
                    entry.status(),
                    BatchResultFileStatus::Failed | BatchResultFileStatus::SkippedStale
                )
            })
            .ok_or("no failed result entry")?;
        ensure(entry.failure_code() == Some(code.as_str()))
            .map_err(|_| "result failure_code mismatch".to_owned())?;
    }
    Ok(())
}

/// Pins the RFC 0015 §9.4 recovery three-way rule data-driven: the disk-byte
/// branch (`source`/`target`/`other`) maps to the frozen outcome
/// (`redo`/`skip`/`stale`); any branch outside the three-way rule is
/// rejected.
fn run_recovery_rule(case: &PortableValue) -> Result<(), String> {
    let branches = input_field(case, "branches")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.branches")?;
    for (index, branch) in branches.iter().enumerate() {
        let disk = object_value_field(branch, "disk")
            .and_then(PortableValue::as_string)
            .ok_or("missing branch.disk")?;
        let outcome = object_value_field(branch, "outcome")
            .and_then(PortableValue::as_string)
            .ok_or("missing branch.outcome")?;
        let expected = match disk {
            "source" => "redo",
            "target" => "skip",
            "other" => "stale",
            other => return Err(format!("unknown disk branch {other}")),
        };
        ensure(outcome == expected)
            .map_err(|_| format!("branch {index} outcome {outcome} != {expected}"))?;
    }
    if let Some(illegal) = input_field(case, "illegal_branch") {
        let disk = object_value_field(illegal, "disk")
            .and_then(PortableValue::as_string)
            .ok_or("missing illegal_branch.disk")?;
        ensure(!["source", "target", "other"].contains(&disk))
            .map_err(|_| format!("branch {disk} must not be in the three-way rule"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redaction contract
// ---------------------------------------------------------------------------

/// Runs one `cli.redaction@1` case.
///
/// Covers the `Redaction` record invariant matrix (`input.samples`), the
/// envelope embedding of redaction facts (`input.json`), the `$REDACTED$`
/// placeholder as an ordinary value that the transport never rewrites
/// (`input.json`), and the presentation-only boundary at the manifest level:
/// patch precondition bytes survive a plan decode/re-encode untouched
/// (`input.record`).
fn run_redaction(case: &PortableValue) -> Result<(), String> {
    if let Some(samples) = input_field(case, "samples").and_then(PortableValue::as_sequence) {
        for (index, sample) in samples.iter().enumerate() {
            let redacted = object_value_field(sample, "redacted")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing sample.redacted")?;
            let count = object_value_field(sample, "count")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
                .ok_or("missing sample.count")?;
            let valid = object_value_field(sample, "valid")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing sample.valid")?;
            let count =
                u64::try_from(count).map_err(|_| format!("sample {index} count out of range"))?;
            let accepted = Redaction::new(redacted, count).is_ok();
            ensure(accepted == valid).map_err(|_| {
                format!("sample {index} Redaction({redacted}, {count}) validity mismatch")
            })?;
        }
        return Ok(());
    }
    let json_text = input_field(case, "json")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.json")?
        .to_owned();
    let limits = ProtocolLimits::default();
    // The plan-byte case pins the presentation-only boundary on a batch-plan
    // record; the other cases decode the envelope.
    if expected_field(case, "original_hex").is_some() {
        let record = decode_json(json_text.as_bytes(), limits)
            .map_err(|error| format!("plan transport decode: {error}"))?;
        let plan = BatchPlanMessage::from_value(&record)
            .map_err(|error| format!("plan decode: {error}"))?;
        let entry = planned_entry(&plan)?;
        let patch = entry
            .source_patch()
            .ok_or("planned entry without source_patch")?;
        let replacement = patch
            .replacements()
            .first()
            .ok_or("no replacement in patch")?;
        if let Some(original_hex) = expected_string_field(case, "original_hex")? {
            ensure(hex(replacement.original()) == original_hex)
                .map_err(|_| "patch original bytes changed".to_owned())?;
        }
        if let Some(replacement_hex) = expected_string_field(case, "replacement_hex")? {
            ensure(hex(replacement.replacement()) == replacement_hex)
                .map_err(|_| "patch replacement bytes changed".to_owned())?;
        }
        let re_encoded = plan
            .to_value()
            .map_err(|error| format!("plan re-encode: {error}"))?;
        ensure(re_encoded == record)
            .map_err(|_| "plan bytes are not preserved through the record")?;
        let transport = encode_json(&record, limits)
            .map_err(|error| format!("plan transport re-encode: {error}"))?;
        ensure(transport == json_text.as_bytes())
            .map_err(|_| "plan record must re-encode to the exact input bytes")?;
        return Ok(());
    }
    let message = CliOutputMessage::from_json(json_text.as_bytes(), limits)
        .map_err(|error| format!("envelope decode: {error}"))?;
    assert_envelope_facts(&message, case)?;
    let re_encoded = message
        .to_json(limits)
        .map_err(|error| format!("envelope re-encode: {error}"))?;
    ensure(re_encoded == json_text.as_bytes())
        .map_err(|_| "envelope re-encode must reproduce the input bytes exactly")?;
    if let Some(placeholder) = expected_string_field(case, "placeholder")? {
        let payload = message.payload();
        ensure(payload_contains_string(payload, &placeholder)?)
            .map_err(|_| "placeholder value changed through the transport".to_owned())?;
    }
    Ok(())
}

/// Whether the exact string appears anywhere in the payload tree (the
/// placeholder contract of RFC 0015 §11.3: a literal `$REDACTED$` value is
/// indistinguishable and the transport never rewrites it).
fn payload_contains_string(value: &PortableValue, needle: &str) -> Result<bool, String> {
    if let Some(text) = value.as_string() {
        return Ok(text == needle);
    }
    if let Some(entries) = value.as_object() {
        return Ok(entries
            .iter()
            .map(|entry| payload_contains_string(entry.value(), needle))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|found| *found));
    }
    if let Some(items) = value.as_sequence() {
        return Ok(items
            .iter()
            .map(|item| payload_contains_string(item, needle))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|found| *found));
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Runs one `cli.limit@1` case.
///
/// The library-side limit contract: transport budgets (`input.json` under
/// `input.max_bytes`) and the source-patch replacement budget
/// (`input.record` under `SourcePatchLimits`), each raising
/// `core.protocol.resource-limit@1`, which classifies as `limit` (exit 3)
/// per RFC 0015 §5.2. CLI-layer budgets (file size, batch count, `--max-*`
/// overrides) are bin-level and covered by the process-level e2e tests.
fn run_limit(case: &PortableValue) -> Result<(), String> {
    let json_text = input_field(case, "json")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.json")?
        .to_owned();
    let limits = ProtocolLimits::default();
    let record = decode_json(json_text.as_bytes(), limits)
        .map_err(|error| format!("transport decode: {error}"))?;
    let classified = classify_error_code(ProtocolErrorKind::ResourceLimit.code());
    ensure(classified == ExitClass::Limit)
        .map_err(|_| "resource-limit must classify as limit".to_owned())?;
    // Transport-budget cases carry input.max_bytes; patch-budget cases decode
    // under the frozen replacement budget instead.
    if let Some(max_bytes_value) = input_field(case, "max_bytes") {
        let max_bytes = max_bytes_value
            .as_integer()
            .and_then(BigInteger::to_i64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or("input.max_bytes must be an integer")?;
        let budget = ProtocolLimits {
            max_bytes,
            ..ProtocolLimits::default()
        };
        let Err(error) = decode_json(json_text.as_bytes(), budget) else {
            return Err("payload must exceed the transport budget".to_owned());
        };
        ensure(error.kind() == ProtocolErrorKind::ResourceLimit).map_err(|_| {
            format!(
                "decode must fail with ResourceLimit, got {}",
                error.kind().code()
            )
        })?;
        return Ok(());
    }
    let patch_limits = SourcePatchLimits {
        max_replacements: 0,
        ..SourcePatchLimits::default()
    };
    let Err(error) =
        BatchPlanMessage::from_value_with_registry(&record, ErrorCodeRegistry::v7(), patch_limits)
    else {
        return Err("plan must exceed the patch replacement budget".to_owned());
    };
    ensure(error.kind() == ProtocolErrorKind::ResourceLimit).map_err(|_| {
        format!(
            "plan decode must fail with ResourceLimit, got {}",
            error.kind().code()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{ObjectBuilder, SequenceBuilder};
    use consema_protocol::{CliCommand, Redaction};

    /// The canonical RFC 0015 §4.4 inspect payload (the canonical form; the
    /// published §4.4 bytes contain a spurious `}` and are rejected).
    fn rfc_inspect_payload() -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("cli.inspect@1")),
            ("path", PortableValue::string("app.conf")),
            (
                "bytes",
                object(vec![
                    ("size", integer_u64(43)),
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
            ("markers", {
                let mut markers = SequenceBuilder::new();
                markers.push(PortableValue::string("[section]"));
                markers.build()
            }),
            ("candidates", {
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
                candidates.build()
            }),
            ("ambiguous", PortableValue::boolean(false)),
            ("ambiguity_reasons", {
                let reasons = SequenceBuilder::new();
                reasons.build()
            }),
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

    fn integer_u64(value: u64) -> PortableValue {
        PortableValue::integer(BigInteger::from(i64::try_from(value).expect("small value")))
    }

    fn rfc_envelope() -> CliOutputMessage {
        CliOutputMessage::new(
            CliCommand::Inspect,
            ExitClass::Success,
            "0.12.0",
            rfc_inspect_payload(),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn cli_v1_suite_passes_fully() {
        let report = run_cli_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 40);
    }

    #[test]
    fn cli_suite_identifier_is_checked() {
        let changed = CLI_V1_VECTORS_JSON.replace(
            "\"suite\": \"consema.cli.conformance@1\"",
            "\"suite\": \"unexpected.suite@1\"",
        );
        let report = run_cli_v1_json(&changed);
        assert!(
            report.failed.iter().any(|(id, _)| id == "suite.schema"),
            "{report:#?}"
        );
        assert!(report.passed.is_empty());
    }

    #[test]
    fn duplicate_case_ids_are_rejected() {
        // Rename the last case to the first case's id: a real duplicate.
        let duplicated = CLI_V1_VECTORS_JSON.replacen(
            "\"id\": \"cli.limit.patch-replacement-budget\"",
            "\"id\": \"cli.envelope.rfc-canonical-bytes\"",
            1,
        );
        let report = run_cli_v1_json(&duplicated);
        assert!(
            report.failed.iter().any(|(id, message)| {
                id == "cli.envelope.rfc-canonical-bytes" && message == "duplicate case id"
            }),
            "{report:#?}"
        );
    }

    #[test]
    fn vector_canonical_envelope_matches_the_protocol_canonical_form() {
        // The M9 vector pins the canonical RFC 0015 §4.4 bytes (the M2
        // finding: the published example carries one spurious `}` and must
        // never enter the corpus).
        let canonical = rfc_envelope()
            .to_json(ProtocolLimits::default())
            .expect("canonical encode");
        let vectors = parse_json(
            CLI_V1_VECTORS_JSON.as_bytes(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .expect("published vector JSON must form a document");
        let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
            .build()
            .expect("fixed projection request");
        let ProjectionResult::Complete(result) = vectors.project(&request) else {
            panic!("vector JSON projects");
        };
        let root = result.value.as_object().expect("vector root object");
        let cases = object_field(root, "cases")
            .and_then(PortableValue::as_sequence)
            .expect("cases field");
        let first = cases.first().expect("at least one case");
        assert_eq!(
            object_value_field(first, "id").and_then(PortableValue::as_string),
            Some("cli.envelope.rfc-canonical-bytes")
        );
        let embedded = object_value_field(first, "input")
            .and_then(|input| object_value_field(input, "json"))
            .and_then(PortableValue::as_string)
            .expect("input.json");
        let decoded = CliOutputMessage::from_json(embedded.as_bytes(), ProtocolLimits::default())
            .expect("embedded canonical envelope decodes");
        assert_eq!(
            decoded
                .to_json(ProtocolLimits::default())
                .expect("re-encode"),
            canonical,
            "vector envelope bytes must equal the protocol canonical form"
        );
    }

    #[test]
    fn vector_data_drives_expected_outputs() {
        // A changed expectation must fail its case: tamper the pinned PVCE
        // bytes of the canonical envelope case.
        let mutated = CLI_V1_VECTORS_JSON.replacen("\"pvce_hex\": \"", "\"pvce_hex\": \"00", 1);
        let report = run_cli_v1_json(&mutated);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "cli.envelope.rfc-canonical-bytes"),
            "{report:#?}"
        );

        // A changed input must fail its case: move one exit-code matrix row
        // from the limit family to the usage family.
        let mutated_input = CLI_V1_VECTORS_JSON.replacen(
            "\"cli.limit.batch-count@1\"",
            "\"cli.usage.missing-plan@1\"",
            1,
        );
        let report = run_cli_v1_json(&mutated_input);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "cli.exit-code.limit-family"),
            "{report:#?}"
        );
    }
}
