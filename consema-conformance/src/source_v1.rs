//! Language-neutral raw-source and SourcePatch v1 conformance runner.

use super::{ConformanceReport, VectorCase, ensure, object_field};
use consema_core::{BigInteger, PortableValue};
use consema_document::{
    BinaryRegion, BinaryStructuralIndex, ContentDigest, DecodedOffset, DocumentAuthority,
    EncodingRequest, LocationError, NodeRole, SourceEncoding, SourceError, SourceLimits,
    SourcePatch, SourcePatchError, SourcePatchLimits, SourceReplacement, SourceSnapshot,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// Embedded language-neutral raw-source suite bytes.
pub const SOURCE_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/source-v1.json");

/// Runs the embedded `consema.source.conformance@1` suite.
#[must_use]
pub fn run_source_v1() -> ConformanceReport {
    run_source_v1_json(SOURCE_V1_VECTORS_JSON)
}

/// Runs one language-neutral raw-source suite from JSON text.
#[must_use]
pub fn run_source_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published source vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.source.conformance@1".to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("source vector root object");
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
        let fields = case.as_object().expect("source case object");
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
        "source.digest.sha256-empty" | "source.digest.sha256-abc" => digest_case(case),
        "source.identity.equal-bytes-distinct-snapshots" => identity_case(case),
        id if id.starts_with("source.encoding.") => encoding_case(case),
        id if id.starts_with("source.location.") => location_case(case),
        id if id.starts_with("source.binary.") => binary_case(case),
        id if id.starts_with("source.patch.") => patch_case(case),
        id if id.starts_with("source.resource.") => resource_case(case),
        _ => Err("runner does not recognize published source case".to_owned()),
    }
}

fn digest_case(case: &VectorCase<'_>) -> Result<(), String> {
    let raw = input_hex(case, "raw_hex")?;
    let expected = expected_string(case, "digest")?;
    ensure(ContentDigest::of(&raw).to_hex() == expected)
}

fn identity_case(case: &VectorCase<'_>) -> Result<(), String> {
    let raw = input_hex(case, "raw_hex")?;
    let first = parse(
        Arc::<[u8]>::from(raw.clone()),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let second = parse(
        Arc::<[u8]>::from(raw),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    ensure(
        (first.source().digest() == second.source().digest())
            == expected_bool(case, "equal_digest")?
            && (first.snapshot_identity() != second.snapshot_identity())
                == expected_bool(case, "distinct_snapshot")?,
    )
}

fn encoding_case(case: &VectorCase<'_>) -> Result<(), String> {
    let raw = input_hex(case, "raw_hex")?;
    let request = encoding_request(case)?;
    match SourceSnapshot::from_raw(
        Arc::<[u8]>::from(raw.clone()),
        request,
        SourceLimits::default(),
    ) {
        Ok(snapshot) => {
            let expected_raw = expected_string(case, "raw_hex")?;
            let expected_selected = expected_string(case, "selected")?;
            let expected_decoded = expected_field(case, "decoded_utf8_hex")?;
            let decoded_matches = if expected_decoded == &PortableValue::null() {
                snapshot.decoded_text().is_none()
            } else {
                hex(snapshot
                    .decoded_text()
                    .ok_or("decoded text unavailable")?
                    .as_bytes())
                    == expected_decoded
                        .as_string()
                        .ok_or("expected.decoded_utf8_hex must be String or Null")?
            };
            ensure(
                snapshot.bytes() == raw
                    && hex(snapshot.bytes()) == expected_raw
                    && snapshot.encoding_facts().selected().as_str() == expected_selected
                    && decoded_matches,
            )
        }
        Err(error) => ensure(source_error_code(&error) == expected_string(case, "code")?),
    }
}

fn location_case(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = SourceSnapshot::from_raw(
        Arc::<[u8]>::from(input_hex(case, "raw_hex")?),
        encoding_request(case)?,
        SourceLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    if snapshot.decoded_text().is_none() {
        return ensure(
            location_error_name(snapshot.decoded_position(0).unwrap_err())
                == expected_string(case, "code")?,
        );
    }
    let raw_byte = input_usize(case, "raw_byte")?;
    let position = snapshot
        .decoded_position(raw_byte)
        .map_err(|error| format!("{error:?}"))?;
    let reverse_utf8 = snapshot
        .raw_byte_at(DecodedOffset::Utf8Byte(position.decoded_utf8_byte))
        .map_err(|error| format!("{error:?}"))?;
    let reverse_scalar = snapshot
        .raw_byte_at(DecodedOffset::UnicodeScalar(position.unicode_scalar_offset))
        .map_err(|error| format!("{error:?}"))?;
    let reverse_utf16 = snapshot
        .raw_byte_at(DecodedOffset::Utf16CodeUnit(
            position.utf16_code_unit_offset,
        ))
        .map_err(|error| format!("{error:?}"))?;
    let invalid_raw = input_usize(case, "invalid_raw_byte")?;
    let invalid_utf16 = input_usize(case, "invalid_utf16_offset")?;
    ensure(
        position.decoded_utf8_byte == expected_usize(case, "decoded_utf8_byte")?
            && position.unicode_scalar_offset == expected_usize(case, "unicode_scalar_offset")?
            && position.utf16_code_unit_offset == expected_usize(case, "utf16_code_unit_offset")?
            && reverse_utf8 == raw_byte
            && reverse_scalar == raw_byte
            && reverse_utf16 == raw_byte
            && snapshot.decoded_position(invalid_raw) == Err(LocationError::NotDecodedBoundary)
            && snapshot.raw_byte_at(DecodedOffset::Utf16CodeUnit(invalid_utf16))
                == Err(LocationError::DecodedOffsetNotBoundary),
    )
}

fn binary_case(case: &VectorCase<'_>) -> Result<(), String> {
    let source_len = input_usize(case, "source_len")?;
    let authority = DocumentAuthority::fresh();
    let region_values = input_field(case, "regions")?
        .as_sequence()
        .ok_or("input.regions must be a Sequence")?;
    let mut regions = Vec::with_capacity(region_values.len());
    for (index, value) in region_values.iter().enumerate() {
        let fields = value.as_object().ok_or("region must be an Object")?;
        let start = object_usize(fields, "start")?;
        let end = object_usize(fields, "end")?;
        let kind = object_field(fields, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("region.kind must be String")?;
        regions.push(BinaryRegion::new(
            authority.node_ref(index as u64, NodeRole::BinaryRegion),
            authority
                .span(start, end)
                .map_err(|error| format!("{error:?}"))?,
            kind,
        ));
    }
    match BinaryStructuralIndex::new(authority.identity(), source_len, regions) {
        Ok(index) => ensure(
            index.regions().len() == expected_usize(case, "region_count")?
                && index
                    .regions()
                    .last()
                    .map_or(0, |region| region.span().end_byte())
                    == source_len,
        ),
        Err(error) => ensure(location_error_name(error) == expected_string(case, "code")?),
    }
}

fn patch_case(case: &VectorCase<'_>) -> Result<(), String> {
    let mode = input_string(case, "mode")?;
    let base = source_from_case(case)?;
    let replacements = replacement_values(case)?;
    let limits = patch_limits(case)?;
    match mode {
        "create-apply" => {
            let patch = SourcePatch::create(&base, replacements, metadata(), limits)
                .map_err(|error| format!("{error:?}"))?;
            let target = patch
                .apply(&base, limits)
                .map_err(|error| format!("{error:?}"))?;
            ensure(
                hex(target.bytes()) == expected_string(case, "target_hex")?
                    && target.digest() == patch.target_digest()
                    && patch.metadata().get("actor").map(String::as_str) == Some("conformance"),
            )
        }
        "stale-base" => {
            let patch = SourcePatch::create(&base, replacements, metadata(), limits)
                .map_err(|error| format!("{error:?}"))?;
            let stale = SourceSnapshot::from_raw(
                Arc::<[u8]>::from(input_hex(case, "stale_hex")?),
                encoding_request(case)?,
                SourceLimits::default(),
            )
            .map_err(|error| format!("{error:?}"))?;
            expect_patch_error(patch.apply(&stale, limits), case)
        }
        "wrong-original" => {
            let patch = SourcePatch::new(
                base.digest(),
                ContentDigest::of(&input_hex(case, "target_hex")?),
                base.encoding_facts(),
                replacements,
                metadata(),
                limits,
            )
            .map_err(|error| format!("{error:?}"))?;
            expect_patch_error(patch.apply(&base, limits), case)
        }
        "overlap" | "count-limit" => expect_patch_error(
            SourcePatch::create(&base, replacements, metadata(), limits),
            case,
        ),
        "wrong-target" => {
            let patch = SourcePatch::new(
                base.digest(),
                ContentDigest::of(b"deliberately-wrong-target"),
                base.encoding_facts(),
                replacements,
                metadata(),
                limits,
            )
            .map_err(|error| format!("{error:?}"))?;
            expect_patch_error(patch.apply(&base, limits), case)
        }
        "encoding-change" => {
            let target_bytes = input_hex(case, "target_hex")?;
            let patch = SourcePatch::new(
                base.digest(),
                ContentDigest::of(&target_bytes),
                base.encoding_facts(),
                replacements,
                metadata(),
                limits,
            )
            .map_err(|error| format!("{error:?}"))?;
            expect_patch_error(patch.apply(&base, limits), case)
        }
        other => Err(format!("unknown patch mode {other}")),
    }
}

fn resource_case(case: &VectorCase<'_>) -> Result<(), String> {
    if case.id == "source.resource.patch-count-limit" {
        return patch_case(case);
    }
    let raw = input_hex(case, "raw_hex")?;
    let mut limits = SourceLimits::default();
    if let Ok(value) = input_usize(case, "max_raw_bytes") {
        limits.max_raw_bytes = value;
    }
    if let Ok(value) = input_usize(case, "max_decoded_utf8_bytes") {
        limits.max_decoded_utf8_bytes = value;
    }
    if let Ok(value) = input_usize(case, "max_decoded_scalars") {
        limits.max_decoded_scalars = value;
    }
    let error = SourceSnapshot::from_raw(Arc::<[u8]>::from(raw), encoding_request(case)?, limits)
        .unwrap_err();
    ensure(source_error_code(&error) == expected_string(case, "code")?)
}

fn source_from_case(case: &VectorCase<'_>) -> Result<SourceSnapshot, String> {
    SourceSnapshot::from_raw(
        Arc::<[u8]>::from(input_hex(case, "base_hex")?),
        encoding_request(case)?,
        SourceLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))
}

fn replacement_values(case: &VectorCase<'_>) -> Result<Vec<SourceReplacement>, String> {
    input_field(case, "replacements")?
        .as_sequence()
        .ok_or("input.replacements must be a Sequence")?
        .iter()
        .map(|value| {
            let fields = value.as_object().ok_or("replacement must be an Object")?;
            Ok(SourceReplacement::new(
                object_usize(fields, "old_start")?,
                object_usize(fields, "old_end")?,
                object_hex(fields, "original_hex")?,
                object_hex(fields, "replacement_hex")?,
            ))
        })
        .collect()
}

fn patch_limits(case: &VectorCase<'_>) -> Result<SourcePatchLimits, String> {
    let mut limits = SourcePatchLimits::default();
    if let Some(value) = input_optional_usize(case, "max_replacements")? {
        limits.max_replacements = value;
    }
    if let Some(value) = input_optional_usize(case, "max_patch_bytes")? {
        limits.max_patch_bytes = value;
    }
    Ok(limits)
}

fn expect_patch_error<T>(
    result: Result<T, SourcePatchError>,
    case: &VectorCase<'_>,
) -> Result<(), String> {
    let error = result.map(|_| ()).unwrap_err();
    ensure(error.code() == expected_string(case, "code")?)
}

fn metadata() -> BTreeMap<String, String> {
    BTreeMap::from([("actor".to_owned(), "conformance".to_owned())])
}

fn encoding_request(case: &VectorCase<'_>) -> Result<EncodingRequest, String> {
    let mut request = EncodingRequest::new(parse_encoding(input_string(case, "encoding")?)?);
    if let Some(value) = input_optional_string(case, "declaration")? {
        request = request.with_declaration(parse_encoding(value)?);
    }
    if let Some(value) = input_optional_string(case, "caller_override")? {
        request = request.with_caller_override(parse_encoding(value)?);
    }
    Ok(request)
}

fn parse_encoding(value: &str) -> Result<SourceEncoding, String> {
    match value {
        "binary" => Ok(SourceEncoding::Binary),
        "utf-8" => Ok(SourceEncoding::Utf8),
        "utf-16le" => Ok(SourceEncoding::Utf16Le),
        "utf-16be" => Ok(SourceEncoding::Utf16Be),
        "latin-1" => Ok(SourceEncoding::Latin1),
        other => Err(format!("unknown encoding {other}")),
    }
}

const fn source_error_code(error: &SourceError) -> &'static str {
    match error {
        SourceError::InvalidUtf8 { .. } | SourceError::InvalidSequence { .. } => {
            "core.source.invalid-sequence@1"
        }
        SourceError::EncodingConflict { .. } => "core.source.encoding-conflict@1",
        SourceError::UnsupportedBom { .. } => "core.source.unsupported-bom@1",
        SourceError::ResourceLimit { .. } | SourceError::OffsetOverflow => {
            "core.source.resource-limit@1"
        }
    }
}

const fn location_error_name(error: LocationError) -> &'static str {
    match error {
        LocationError::IncompleteStructuralCoverage => "IncompleteStructuralCoverage",
        LocationError::NoDecodedText => "NoDecodedText",
        LocationError::NotDecodedBoundary => "NotDecodedBoundary",
        LocationError::DecodedOffsetNotBoundary => "DecodedOffsetNotBoundary",
        LocationError::InvertedSpan => "InvertedSpan",
        LocationError::WrongSnapshot => "WrongSnapshot",
        LocationError::OutOfBounds => "OutOfBounds",
        LocationError::WrongRole => "WrongRole",
        LocationError::InvalidBinaryRegionKind => "InvalidBinaryRegionKind",
        LocationError::DuplicateStructuralIdentity => "DuplicateStructuralIdentity",
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

fn input_optional_string<'a>(
    case: &'a VectorCase<'a>,
    name: &str,
) -> Result<Option<&'a str>, String> {
    let Some(value) = case
        .input
        .as_object()
        .and_then(|fields| object_field(fields, name))
    else {
        return Ok(None);
    };
    if value == &PortableValue::null() {
        Ok(None)
    } else {
        value
            .as_string()
            .map(Some)
            .ok_or_else(|| format!("input.{name} must be String or Null"))
    }
}

fn input_optional_usize(case: &VectorCase<'_>, name: &str) -> Result<Option<usize>, String> {
    let Some(value) = case
        .input
        .as_object()
        .and_then(|fields| object_field(fields, name))
    else {
        return Ok(None);
    };
    value
        .as_integer()
        .and_then(BigInteger::to_usize)
        .map(Some)
        .ok_or_else(|| format!("input.{name} must be a non-negative host-size Integer"))
}

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be a non-negative host-size Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be a non-negative host-size Integer"))
}

fn object_usize(fields: &[consema_core::ObjectEntry], name: &str) -> Result<usize, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("{name} must be a non-negative host-size Integer"))
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

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
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
    fn published_source_v1_suite_is_conformant() {
        let report = run_source_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 28);
    }

    #[test]
    fn vector_input_and_expectations_drive_source_cases() {
        let changed_digest = SOURCE_V1_VECTORS_JSON.replace(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        let report = run_source_v1_json(&changed_digest);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "source.digest.sha256-empty"),
            "{report:#?}"
        );

        let changed_input = SOURCE_V1_VECTORS_JSON.replacen(
            "\"raw_hex\": \"616263\"",
            "\"raw_hex\": \"616264\"",
            1,
        );
        let report = run_source_v1_json(&changed_input);
        assert!(!report.is_conformant(), "{report:#?}");
    }
}
