use consema::properties::{
    self, DuplicatePolicy, EditTransactionBuilder, JavaStringStatus, ProjectionRequest,
    ProjectionResult, PropertiesParseLimits,
};
use consema_core::PortableValue;
use consema_document::{ContentDigest, FormationStatus, ParseLimits, SourceEncoding};
use std::collections::{BTreeMap, HashSet};

use super::{ConformanceReport, object_field};

const SUITE: &str = "consema.java-properties.jdk25-differential@1";
const CASE_COUNT: usize = 11;
const PACKAGE_SHA256: &str = "54ba13f3ef80887fa74708b2a32daaae6262517ba68433d850bb4b426343172b";
const ADAPTER_SHA256: &str = "71cf3030b74ef264ad8e15f5633e653d70f3ec96b0bbd6944c9a6c4ffd4a94c6";

/// Embedded, authority-recorded Java SE 25 Properties differential manifest.
pub const PROPERTIES_JDK25_ORACLE_JSON: &str =
    include_str!("../../../conformance/oracles/java-properties-v1/manifest.json");

const READER_BASICS: &[u8] =
    include_bytes!("../../../conformance/oracles/java-properties-v1/reader-basics.properties");
const READER_CONTINUATION: &[u8] = include_bytes!(
    "../../../conformance/oracles/java-properties-v1/reader-continuation.properties"
);
const READER_DUPLICATES: &[u8] =
    include_bytes!("../../../conformance/oracles/java-properties-v1/reader-duplicates.properties");
const READER_ESCAPES: &[u8] =
    include_bytes!("../../../conformance/oracles/java-properties-v1/reader-escapes.properties");
const READER_FINAL_CONTINUATION: &[u8] = include_bytes!(
    "../../../conformance/oracles/java-properties-v1/reader-final-continuation.properties"
);
const READER_JAVA_UTF16: &[u8] =
    include_bytes!("../../../conformance/oracles/java-properties-v1/reader-java-utf16.properties");
const READER_MALFORMED_HEX: &[u8] = include_bytes!(
    "../../../conformance/oracles/java-properties-v1/reader-malformed-hex.properties"
);
const READER_MALFORMED_SHORT: &[u8] = include_bytes!(
    "../../../conformance/oracles/java-properties-v1/reader-malformed-short.properties"
);
const READER_MULTIPLE_U: &[u8] =
    include_bytes!("../../../conformance/oracles/java-properties-v1/reader-multiple-u.properties");
const READER_MESSAGES: &[u8] =
    include_bytes!("../../../conformance/fixtures/properties/messages.properties");
const LATIN1_RESOURCE_HEX: &str =
    include_str!("../../../conformance/fixtures/properties/latin1-resource.properties.hex");

/// Runs the embedded Java SE 25 Properties differential manifest.
#[must_use]
pub fn run_properties_jdk25_oracle() -> ConformanceReport {
    run_properties_jdk25_oracle_json(PROPERTIES_JDK25_ORACLE_JSON)
}

/// Runs one caller-supplied Java SE 25 Properties differential manifest.
#[must_use]
pub fn run_properties_jdk25_oracle_json(json: &str) -> ConformanceReport {
    let value = match parse_json_value(json) {
        Ok(value) => value,
        Err(error) => return failed_report("suite.parse", error),
    };
    let Some(root) = value.as_object() else {
        return failed_report("suite.schema", "manifest root must be Object");
    };
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .unwrap_or(SUITE)
        .to_owned();
    if let Err(error) = validate_metadata(root) {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![("suite.schema".to_owned(), error)],
        };
    }
    let Some(cases) = object_field(root, "cases").and_then(PortableValue::as_sequence) else {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "cases must be Sequence".to_owned(),
            )],
        };
    };
    if cases.len() != CASE_COUNT {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                format!("expected {CASE_COUNT} cases, got {}", cases.len()),
            )],
        };
    }

    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let Some(fields) = case.as_object() else {
            report
                .failed
                .push(("case.schema".to_owned(), "case must be Object".to_owned()));
            continue;
        };
        let id = match object_string(fields, "id") {
            Ok(id) => id,
            Err(error) => {
                report.failed.push(("case.schema".to_owned(), error));
                continue;
            }
        };
        if !seen.insert(id) {
            report
                .failed
                .push((id.to_owned(), "duplicate case id".to_owned()));
            continue;
        }
        match run_case(fields) {
            Ok(()) => report.passed.push(id.to_owned()),
            Err(error) => report.failed.push((id.to_owned(), error)),
        }
    }
    report
}

fn parse_json_value(json: &str) -> Result<PortableValue, String> {
    let document = consema_json::parse(
        json.as_bytes(),
        consema_json::JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("manifest JSON failed formation: {error:?}"))?;
    let request = consema_json::ProjectionRequestBuilder::new(
        consema_json::ProjectionTarget::BestExactCoreV1,
    )
    .build()
    .map_err(|error| format!("manifest projection request failed: {error:?}"))?;
    match document.project(&request) {
        consema_json::ProjectionResult::Complete(result) => Ok(result.value),
        consema_json::ProjectionResult::Failed(failed) => {
            Err(format!("manifest JSON projection failed: {failed:?}"))
        }
    }
}

fn validate_metadata(root: &[consema_core::ObjectEntry]) -> Result<(), String> {
    if object_string(root, "suite")? != SUITE {
        return Err("unexpected suite identifier".to_owned());
    }
    let authority = object_object(root, "authority")?;
    if object_string(authority, "package_sha256")? != PACKAGE_SHA256 {
        return Err("unexpected OpenJDK package digest".to_owned());
    }
    let adapter = object_object(root, "adapter")?;
    if object_string(adapter, "source_sha256")? != ADAPTER_SHA256 {
        return Err("unexpected Properties oracle adapter digest".to_owned());
    }
    let runtime = object_object(root, "runtime")?;
    if object_string(runtime, "java.runtime.version")? != "25.0.4+7-LTS"
        || object_string(runtime, "java.vendor")? != "Microsoft"
        || object_string(runtime, "os.name")? != "Windows 11"
        || object_string(runtime, "os.arch")? != "amd64"
        || object_string(runtime, "windows_build")? != "10.0.26200.0"
    {
        return Err("unexpected Properties oracle runtime facts".to_owned());
    }
    let exclusions = object_field(root, "exclusions")
        .and_then(PortableValue::as_sequence)
        .ok_or("exclusions must be Sequence")?;
    if exclusions.len() != 6 || exclusions.iter().any(|item| item.as_string().is_none()) {
        return Err("Properties oracle exclusions are incomplete".to_owned());
    }
    Ok(())
}

fn run_case(fields: &[consema_core::ObjectEntry]) -> Result<(), String> {
    let input = object_string(fields, "input")?;
    let profile = object_string(fields, "profile")?;
    let storage = object_string(fields, "storage")?;
    let source = fixture(input, storage)?;
    let expected_digest = object_string(fields, "input_sha256")?;
    if ContentDigest::of(&source).to_hex() != expected_digest {
        return Err("input digest differs from authority record".to_owned());
    }
    let document = match profile {
        "reader" => properties::parse_reader(
            source,
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        ),
        "latin1" => properties::parse_latin1(source, PropertiesParseLimits::default()),
        _ => return Err(format!("unknown oracle profile {profile}")),
    }
    .map_err(|error| format!("Consema formation failed fatally: {error:?}"))?;

    let expected = object_object(fields, "expected")?;
    match object_string(expected, "outcome")? {
        "complete" => compare_complete(&document, expected),
        "failed" => compare_failed(&document, expected),
        outcome => Err(format!("unknown oracle outcome {outcome}")),
    }
}

fn compare_complete(
    document: &properties::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    if document.formation_status() != FormationStatus::Complete {
        return Err(format!(
            "authority completed but Consema formed {:?}: {:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    let expected_table = expected_table(expected)?;
    let actual_table = native_last_wins_table(document);
    if actual_table != expected_table {
        return Err(format!(
            "JDK table differed: expected {expected_table:?}, got {actual_table:?}"
        ));
    }

    match object_field(expected, "projection").and_then(PortableValue::as_string) {
        Some("last-wins-jdk-table") => {
            if document.properties().len() <= expected_table.len() {
                return Err("duplicate oracle case lost native occurrences".to_owned());
            }
            let ProjectionResult::Complete(projected) = document.project(
                ProjectionRequest::require_object(DuplicatePolicy::LastWinsJdkTable),
            ) else {
                return Err("explicit LastWinsJdkTable projection failed".to_owned());
            };
            if portable_object_table(&projected.value)? != expected_table {
                return Err("LastWinsJdkTable projection differed from JDK".to_owned());
            }
            if projected.report.events().len() != document.properties().len() - expected_table.len()
            {
                return Err("LastWinsJdkTable collapse report count differed".to_owned());
            }
        }
        None => {
            let well_formed = document.properties().iter().all(|property| {
                property.key().status() == JavaStringStatus::WellFormedUnicode
                    && property.value().status() == JavaStringStatus::WellFormedUnicode
            });
            match document.project(ProjectionRequest::best_exact_entry_mapping()) {
                ProjectionResult::Complete(_) if well_formed => {}
                ProjectionResult::Failed(failed)
                    if !well_formed && failed.report.events().is_empty() => {}
                other => {
                    return Err(format!(
                        "scalar projection did not respect exact Java UTF-16 boundary: {other:?}"
                    ));
                }
            }
        }
        Some(other) => return Err(format!("unknown comparison projection {other}")),
    }
    Ok(())
}

fn compare_failed(
    document: &properties::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    if object_string(expected, "exception")? != "java.lang.IllegalArgumentException" {
        return Err("unknown JDK exception classification".to_owned());
    }
    if document.formation_status() != FormationStatus::Recovered
        || document.diagnostics().len() != 1
        || document.diagnostics()[0].code != "java-properties.parse.malformed-unicode-escape@1"
    {
        return Err(format!(
            "JDK rejected but Consema recovery differed: status={:?}, diagnostics={:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    let ProjectionResult::Failed(failed) =
        document.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("malformed JDK case published a Consema value".to_owned());
    };
    if !failed.report.events().is_empty()
        || document
            .commit(&EditTransactionBuilder::new(document).build())
            .is_ok()
    {
        return Err("malformed JDK case exposed a partial operation result".to_owned());
    }
    Ok(())
}

fn fixture(path: &str, storage: &str) -> Result<Vec<u8>, String> {
    let (bytes, expected_storage) = match path {
        "conformance/oracles/java-properties-v1/reader-basics.properties" => {
            (READER_BASICS.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-continuation.properties" => {
            (READER_CONTINUATION.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-duplicates.properties" => {
            (READER_DUPLICATES.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-escapes.properties" => {
            (READER_ESCAPES.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-final-continuation.properties" => {
            (READER_FINAL_CONTINUATION.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-java-utf16.properties" => {
            (READER_JAVA_UTF16.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-malformed-hex.properties" => {
            (READER_MALFORMED_HEX.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-malformed-short.properties" => {
            (READER_MALFORMED_SHORT.to_vec(), "bytes")
        }
        "conformance/oracles/java-properties-v1/reader-multiple-u.properties" => {
            (READER_MULTIPLE_U.to_vec(), "bytes")
        }
        "conformance/fixtures/properties/messages.properties" => {
            (READER_MESSAGES.to_vec(), "bytes")
        }
        "conformance/fixtures/properties/latin1-resource.properties.hex" => {
            (decode_byte_hex(LATIN1_RESOURCE_HEX)?, "hex")
        }
        _ => return Err(format!("unrecorded oracle input {path}")),
    };
    if storage != expected_storage {
        return Err(format!(
            "oracle storage mismatch for {path}: expected {expected_storage}, got {storage}"
        ));
    }
    Ok(bytes)
}

fn native_last_wins_table(document: &properties::Document) -> BTreeMap<Vec<u16>, Vec<u16>> {
    let mut table = BTreeMap::new();
    for property in document.properties() {
        table.insert(
            property.key().code_units().to_vec(),
            property.value().code_units().to_vec(),
        );
    }
    table
}

fn portable_object_table(value: &PortableValue) -> Result<BTreeMap<Vec<u16>, Vec<u16>>, String> {
    let object = value
        .as_object()
        .ok_or("LastWinsJdkTable result must be Object")?;
    let mut table = BTreeMap::new();
    for entry in object {
        let key = entry.key();
        let value = entry
            .value()
            .as_string()
            .ok_or("projected value must be String")?;
        if table
            .insert(key.encode_utf16().collect(), value.encode_utf16().collect())
            .is_some()
        {
            return Err("projected Object contains duplicate keys".to_owned());
        }
    }
    Ok(table)
}

fn expected_table(
    expected: &[consema_core::ObjectEntry],
) -> Result<BTreeMap<Vec<u16>, Vec<u16>>, String> {
    let entries = object_field(expected, "entries")
        .and_then(PortableValue::as_sequence)
        .ok_or("complete outcome entries must be Sequence")?;
    let mut table = BTreeMap::new();
    let mut previous: Option<Vec<u16>> = None;
    for entry in entries {
        let pair = entry
            .as_sequence()
            .ok_or("expected JDK entry must be Sequence")?;
        if pair.len() != 2 {
            return Err("expected JDK entry must contain key and value".to_owned());
        }
        let key = decode_utf16_hex(pair[0].as_string().ok_or("JDK key must be String")?)?;
        let value = decode_utf16_hex(pair[1].as_string().ok_or("JDK value must be String")?)?;
        if previous.as_ref().is_some_and(|item| item >= &key) {
            return Err("expected JDK entries are not in strict Java String order".to_owned());
        }
        previous = Some(key.clone());
        table.insert(key, value);
    }
    Ok(table)
}

fn decode_utf16_hex(value: &str) -> Result<Vec<u16>, String> {
    let bytes = decode_byte_hex(value)?;
    let mut chunks = bytes.chunks_exact(2);
    let units = chunks
        .by_ref()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    if !chunks.remainder().is_empty() {
        return Err("UTF-16 hex has a partial code unit".to_owned());
    }
    Ok(units)
}

fn decode_byte_hex(value: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let mut chunks = digits.chunks_exact(2);
    let decoded = chunks
        .by_ref()
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect::<Result<Vec<_>, String>>()?;
    if !chunks.remainder().is_empty() {
        return Err("hex has an odd digit count".to_owned());
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex must be canonical lowercase".to_owned()),
    }
}

fn object_object<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a [consema_core::ObjectEntry], String> {
    object_field(fields, name)
        .and_then(PortableValue::as_object)
        .ok_or_else(|| format!("{name} must be Object"))
}

fn object_string<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a str, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("{name} must be String"))
}

fn failed_report(id: &str, error: impl Into<String>) -> ConformanceReport {
    ConformanceReport {
        suite: SUITE.to_owned(),
        passed: Vec::new(),
        failed: vec![(id.to_owned(), error.into())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_jdk25_oracle_manifest_is_conformant() {
        let report = run_properties_jdk25_oracle();
        assert!(report.is_conformant(), "{:?}", report.failed);
        assert_eq!(report.passed.len(), CASE_COUNT);
    }

    #[test]
    fn jdk25_oracle_expectation_mutation_is_observed() {
        let mutated = PROPERTIES_JDK25_ORACLE_JSON.replacen("006f006e0065", "006f006e0066", 1);
        let report = run_properties_jdk25_oracle_json(&mutated);
        assert!(report.failed.iter().any(|(id, _)| id == "reader-basics"));
    }

    #[test]
    fn jdk25_oracle_digest_and_adapter_mutations_fail_closed() {
        let digest = PROPERTIES_JDK25_ORACLE_JSON.replacen(
            "3ca1a8f988f69ee8a0e448719106f6389b3362b09240dda8c93a03e0cdca61f9",
            "0ca1a8f988f69ee8a0e448719106f6389b3362b09240dda8c93a03e0cdca61f9",
            1,
        );
        let report = run_properties_jdk25_oracle_json(&digest);
        assert!(report.failed.iter().any(|(id, _)| id == "reader-basics"));

        let adapter = PROPERTIES_JDK25_ORACLE_JSON.replacen(ADAPTER_SHA256, PACKAGE_SHA256, 1);
        let report = run_properties_jdk25_oracle_json(&adapter);
        assert_eq!(report.failed[0].0, "suite.schema");
    }

    #[test]
    fn jdk25_oracle_unknown_input_outcome_and_duplicate_id_are_rejected() {
        let input = PROPERTIES_JDK25_ORACLE_JSON.replacen(
            "conformance/oracles/java-properties-v1/reader-basics.properties",
            "conformance/oracles/java-properties-v1/unrecorded.properties",
            1,
        );
        let report = run_properties_jdk25_oracle_json(&input);
        assert!(report.failed.iter().any(|(id, _)| id == "reader-basics"));

        let outcome = PROPERTIES_JDK25_ORACLE_JSON.replacen(
            "\"outcome\": \"complete\"",
            "\"outcome\": \"partial\"",
            1,
        );
        let report = run_properties_jdk25_oracle_json(&outcome);
        assert!(report.failed.iter().any(|(id, _)| id == "reader-basics"));

        let duplicate = PROPERTIES_JDK25_ORACLE_JSON.replacen(
            "\"id\": \"reader-continuation\"",
            "\"id\": \"reader-basics\"",
            1,
        );
        let report = run_properties_jdk25_oracle_json(&duplicate);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, error)| { id == "reader-basics" && error == "duplicate case id" })
        );
    }
}
