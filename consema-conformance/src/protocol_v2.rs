//! Language-neutral semantic-model v2 source protocol conformance runner.

use super::{ConformanceReport, VectorCase, ensure, object_field};
use consema_core::{BigInteger, ObjectBuilder, PortableValue};
use consema_document::{
    EncodingRequest, SourceEncoding, SourceLimits, SourcePatch, SourcePatchLimits,
    SourceReplacement, SourceSnapshot,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{
    ContractId, ContractRegistry, ErrorCodeRegistry, ProtocolLimits, ProtocolMessage,
    RegistryManifest, SourcePatchMessage, SourceSnapshotMessage, error_code_manifest_value_v2,
    validate_error_code_manifest_value,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// Embedded semantic-model v2 protocol suite bytes.
pub const PROTOCOL_V2_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/protocol-v2.json");

/// Runs the embedded `consema.protocol.conformance@2` suite.
#[must_use]
pub fn run_protocol_v2() -> ConformanceReport {
    run_protocol_v2_json(PROTOCOL_V2_VECTORS_JSON)
}

/// Runs one semantic-model v2 protocol suite from JSON text.
#[must_use]
pub fn run_protocol_v2_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published protocol v2 vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.protocol.conformance@2".to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("protocol v2 vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let fields = case.as_object().expect("protocol v2 case object");
        let id = object_field(fields, "id")
            .and_then(PortableValue::as_string)
            .expect("case id");
        let capability = object_field(fields, "capability")
            .and_then(PortableValue::as_string)
            .expect("case capability");
        let input = object_field(fields, "input").expect("case input");
        let expected = object_field(fields, "expected").expect("case expected");
        if !seen.insert(id) {
            report
                .failed
                .push((id.to_owned(), "duplicate case id".to_owned()));
            continue;
        }
        let vector = VectorCase {
            id,
            capability,
            input,
            expected,
        };
        match run_case(&vector) {
            Ok(()) => report.passed.push(id.to_owned()),
            Err(error) => report.failed.push((id.to_owned(), error)),
        }
    }
    report
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    match case.id {
        "protocol.v2.registry-manifest" => registry_case(case, false),
        "protocol.v2.registry-v1-frozen" => registry_case(case, true),
        "protocol.v2.error-code-manifest" => error_manifest_case(case),
        "protocol.v2.snapshot-dual-transport" => snapshot_transport(case),
        "protocol.v2.patch-dual-transport" => patch_transport(case),
        "protocol.v2.reject-source-under-v1" => reject_source_v1(case),
        "protocol.v2.reject-forged-digest" => reject_forged_digest(case),
        "protocol.v2.reject-forged-encoding" => reject_forged_encoding(case),
        "protocol.v2.snapshot-resource-limit" => snapshot_resource_limit(case),
        "protocol.v2.patch-resource-limit" => patch_resource_limit(case),
        "protocol.v2.patch-stale-after-wire" => patch_stale_after_wire(case),
        _ => Err("runner does not recognize published protocol v2 case".to_owned()),
    }
}

fn registry_case(case: &VectorCase<'_>, frozen_v1: bool) -> Result<(), String> {
    let manifest = if frozen_v1 {
        RegistryManifest::v1()
    } else {
        RegistryManifest::v2()
    };
    let decoded =
        RegistryManifest::from_value(&manifest.to_value()).map_err(|error| error.to_string())?;
    let source_contract = ContractId::new("core.source-snapshot", 1).unwrap();
    let registry = if frozen_v1 {
        ContractRegistry::v1()
    } else {
        ContractRegistry::v2()
    };
    ensure(
        decoded == manifest
            && decoded.semantic_model().schema() == expected_string(case, "semantic_model")?
            && decoded.contracts().len() == expected_usize(case, "contract_count")?
            && decoded.error_codes().len() == expected_usize(case, "error_code_count")?
            && registry.recognizes(&source_contract)
                == expected_bool(case, "recognizes_source_snapshot")?
            && decoded.is_current() == expected_bool(case, "is_current")?,
    )
}

fn error_manifest_case(case: &VectorCase<'_>) -> Result<(), String> {
    let manifest = error_code_manifest_value_v2();
    validate_error_code_manifest_value(&manifest).map_err(|error| error.to_string())?;
    let fields = manifest.as_object().ok_or("manifest must be Object")?;
    let count = object_field(fields, "error_codes")
        .and_then(PortableValue::as_sequence)
        .ok_or("error_codes must be Sequence")?
        .len();
    ensure(
        count == expected_usize(case, "error_code_count")?
            && ErrorCodeRegistry::v2().contains(expected_string(case, "required_code")?)
            && !ErrorCodeRegistry::v1().contains(expected_string(case, "required_code")?),
    )
}

fn snapshot_transport(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = source(case, "raw_hex")?;
    let payload = SourceSnapshotMessage::from_snapshot(&snapshot).to_value();
    let message = ProtocolMessage::new(
        ContractId::new("core.source-snapshot", 1).unwrap(),
        payload,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let limits = ProtocolLimits::default();
    let json = ProtocolMessage::from_json(
        &message.to_json(limits).map_err(|error| error.to_string())?,
        limits,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let pvce = ProtocolMessage::from_pvce(
        &message.to_pvce(limits).map_err(|error| error.to_string())?,
        limits,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let decoded = SourceSnapshotMessage::from_value(json.payload(), SourceLimits::default())
        .map_err(|error| error.to_string())?;
    ensure(
        (json == message) == expected_bool(case, "json_equal")?
            && (pvce == message) == expected_bool(case, "pvce_equal")?
            && decoded.snapshot() == &snapshot
            && snapshot.digest().to_hex() == expected_string(case, "digest")?,
    )
}

fn patch_transport(case: &VectorCase<'_>) -> Result<(), String> {
    let base = source(case, "base_hex")?;
    let patch = create_patch(case, &base)?;
    let message = ProtocolMessage::new(
        ContractId::new("core.source-patch", 1).unwrap(),
        SourcePatchMessage::from_patch(&patch)
            .to_value()
            .map_err(|error| error.to_string())?,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let limits = ProtocolLimits::default();
    let json = ProtocolMessage::from_json(
        &message.to_json(limits).map_err(|error| error.to_string())?,
        limits,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let pvce = ProtocolMessage::from_pvce(
        &message.to_pvce(limits).map_err(|error| error.to_string())?,
        limits,
        ContractRegistry::v2(),
    )
    .map_err(|error| error.to_string())?;
    let decoded = SourcePatchMessage::from_value(json.payload(), SourcePatchLimits::default())
        .map_err(|error| error.to_string())?;
    let target = decoded
        .patch()
        .apply(&base, SourcePatchLimits::default())
        .map_err(|error| error.to_string())?;
    ensure(
        (json == message) == expected_bool(case, "json_equal")?
            && (pvce == message) == expected_bool(case, "pvce_equal")?
            && hex(target.bytes()) == expected_string(case, "target_hex")?,
    )
}

fn reject_source_v1(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = source(case, "raw_hex")?;
    let error = ProtocolMessage::new(
        ContractId::new("core.source-snapshot", 1).unwrap(),
        SourceSnapshotMessage::from_snapshot(&snapshot).to_value(),
        ContractRegistry::v1(),
    )
    .unwrap_err();
    ensure(error.kind().code() == expected_string(case, "code")?)
}

fn reject_forged_digest(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = source(case, "raw_hex")?;
    let value = SourceSnapshotMessage::from_snapshot(&snapshot).to_value();
    let digest = ordered_object(&[
        ("algorithm", PortableValue::string("sha256")),
        ("hex", PortableValue::string("00".repeat(32))),
    ])?;
    let forged = replace_field(&value, "digest", digest)?;
    let error = SourceSnapshotMessage::from_value(&forged, SourceLimits::default()).unwrap_err();
    ensure(error.kind().code() == expected_string(case, "code")?)
}

fn reject_forged_encoding(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = source(case, "raw_hex")?;
    let value = SourceSnapshotMessage::from_snapshot(&snapshot).to_value();
    let encoding = value
        .as_object()
        .and_then(|fields| object_field(fields, "encoding"))
        .ok_or("encoding field missing")?;
    let forged_encoding = replace_field(
        encoding,
        "selected",
        PortableValue::string(input_string(case, "forged_selected")?),
    )?;
    let forged = replace_field(&value, "encoding", forged_encoding)?;
    let error = SourceSnapshotMessage::from_value(&forged, SourceLimits::default()).unwrap_err();
    ensure(error.kind().code() == expected_string(case, "code")?)
}

fn snapshot_resource_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = source(case, "raw_hex")?;
    let value = SourceSnapshotMessage::from_snapshot(&snapshot).to_value();
    let limits = SourceLimits {
        max_raw_bytes: input_usize(case, "max_raw_bytes")?,
        ..SourceLimits::default()
    };
    let error = SourceSnapshotMessage::from_value(&value, limits).unwrap_err();
    ensure(error.kind().code() == expected_string(case, "code")?)
}

fn patch_resource_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let base = source(case, "base_hex")?;
    let patch = create_patch(case, &base)?;
    let value = SourcePatchMessage::from_patch(&patch)
        .to_value()
        .map_err(|error| error.to_string())?;
    let limits = SourcePatchLimits {
        max_replacements: input_usize(case, "max_replacements")?,
        ..SourcePatchLimits::default()
    };
    let error = SourcePatchMessage::from_value(&value, limits).unwrap_err();
    ensure(error.kind().code() == expected_string(case, "code")?)
}

fn patch_stale_after_wire(case: &VectorCase<'_>) -> Result<(), String> {
    let base = source(case, "base_hex")?;
    let patch = create_patch(case, &base)?;
    let value = SourcePatchMessage::from_patch(&patch)
        .to_value()
        .map_err(|error| error.to_string())?;
    let limits = ProtocolLimits::default();
    let transported = consema_protocol::decode_pvce(
        &consema_protocol::encode_pvce(&value, limits).map_err(|error| error.to_string())?,
        limits,
    )
    .map_err(|error| error.to_string())?;
    let decoded = SourcePatchMessage::from_value(&transported, SourcePatchLimits::default())
        .map_err(|error| error.to_string())?;
    let stale = source(case, "stale_hex")?;
    let error = decoded
        .patch()
        .apply(&stale, SourcePatchLimits::default())
        .unwrap_err();
    ensure(error.code() == expected_string(case, "code")?)
}

fn source(case: &VectorCase<'_>, field: &str) -> Result<SourceSnapshot, String> {
    SourceSnapshot::from_raw(
        Arc::<[u8]>::from(input_hex(case, field)?),
        EncodingRequest::new(parse_encoding(input_string(case, "encoding")?)?),
        SourceLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))
}

fn create_patch(case: &VectorCase<'_>, base: &SourceSnapshot) -> Result<SourcePatch, String> {
    let replacements = input_field(case, "replacements")?
        .as_sequence()
        .ok_or("input.replacements must be Sequence")?
        .iter()
        .map(|value| {
            let fields = value.as_object().ok_or("replacement must be Object")?;
            Ok(SourceReplacement::new(
                object_usize(fields, "old_start")?,
                object_usize(fields, "old_end")?,
                object_hex(fields, "original_hex")?,
                object_hex(fields, "replacement_hex")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    SourcePatch::create(
        base,
        replacements,
        BTreeMap::from([("actor".to_owned(), "protocol-v2".to_owned())]),
        SourcePatchLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))
}

fn ordered_object(fields: &[(&str, PortableValue)]) -> Result<PortableValue, String> {
    let mut builder = ObjectBuilder::new();
    for (name, value) in fields {
        builder
            .insert(*name, value.clone())
            .map_err(|error| format!("{error:?}"))?;
    }
    Ok(builder.build())
}

fn replace_field(
    value: &PortableValue,
    target: &str,
    replacement: PortableValue,
) -> Result<PortableValue, String> {
    let fields = value.as_object().ok_or("value must be Object")?;
    let mut builder = ObjectBuilder::new();
    for field in fields {
        builder
            .insert(
                field.key(),
                if field.key() == target {
                    replacement.clone()
                } else {
                    field.value().clone()
                },
            )
            .map_err(|error| format!("{error:?}"))?;
    }
    Ok(builder.build())
}

fn parse_encoding(value: &str) -> Result<SourceEncoding, String> {
    match value {
        "utf-8" => Ok(SourceEncoding::Utf8),
        "utf-16le" => Ok(SourceEncoding::Utf16Le),
        "utf-16be" => Ok(SourceEncoding::Utf16Be),
        "latin-1" => Ok(SourceEncoding::Latin1),
        "binary" => Ok(SourceEncoding::Binary),
        other => Err(format!("unknown encoding {other}")),
    }
}

fn input_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.input
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing input.{name}"))
}

fn expected_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing expected.{name}"))
}

fn input_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    input_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("input.{name} must be String"))
}

fn expected_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    expected_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("expected.{name} must be String"))
}

fn expected_bool(case: &VectorCase<'_>, name: &str) -> Result<bool, String> {
    expected_field(case, name)?
        .as_boolean()
        .ok_or_else(|| format!("expected.{name} must be Boolean"))
}

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be host-size Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be host-size Integer"))
}

fn object_usize(fields: &[consema_core::ObjectEntry], name: &str) -> Result<usize, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("{name} must be host-size Integer"))
}

fn input_hex(case: &VectorCase<'_>, name: &str) -> Result<Vec<u8>, String> {
    decode_hex(input_string(case, name)?)
}

fn object_hex(fields: &[consema_core::ObjectEntry], name: &str) -> Result<Vec<u8>, String> {
    decode_hex(
        object_field(fields, name)
            .and_then(PortableValue::as_string)
            .ok_or_else(|| format!("{name} must be String"))?,
    )
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("String write cannot fail");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_protocol_v2_suite_is_conformant() {
        let report = run_protocol_v2();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 11);
    }

    #[test]
    fn protocol_v2_vectors_drive_input_and_expectations() {
        let changed = PROTOCOL_V2_VECTORS_JSON.replacen(
            "\"contract_count\": 18",
            "\"contract_count\": 17",
            1,
        );
        let report = run_protocol_v2_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "protocol.v2.registry-manifest"),
            "{report:#?}"
        );

        let changed = PROTOCOL_V2_VECTORS_JSON.replacen(
            "\"raw_hex\": \"616263\"",
            "\"raw_hex\": \"616264\"",
            1,
        );
        assert!(!run_protocol_v2_json(&changed).is_conformant());
    }
}
