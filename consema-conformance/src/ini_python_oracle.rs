use consema::ini::{
    self, EditTransactionBuilder, IniEncodingSelection, IniParseLimits, IniProfile,
    ProjectionRequest, ProjectionResult,
};
use consema_core::PortableValue;
use consema_document::{ContentDigest, FormationStatus, ParseLimits};
use std::collections::HashSet;

use super::{ConformanceReport, object_field};

const SUITE: &str = "consema.ini.python-configparser314-differential@1";
const CASE_COUNT: usize = 9;
const PACKAGE_SHA256: &str = "c3a89aa7ead530bcac4729f3db7d000fbadb6ca7aa0461c2841867172aa0752a";
const ADAPTER_SHA256: &str = "2050a3317965006097e553574b95d19475440d44d7d9fbf73f35b33283cdd7bc";

/// Embedded CPython 3.14 ConfigParser differential manifest.
pub const INI_PYTHON_ORACLE_JSON: &str =
    include_str!("../../../conformance/oracles/python-configparser-v1/manifest.json");

const BASIC: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/basic.ini");
const CASEFOLD_COLLISION: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/casefold-collision.ini");
const CONTINUATION: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/continuation.ini");
const DEFAULT_OVERRIDE: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/default-override.ini");
const DEFAULTS_AND_RAW: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/defaults-and-raw.ini");
const DUPLICATE_OPTION: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/duplicate-option.ini");
const DUPLICATE_SECTION: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/duplicate-section.ini");
const MISSING_SECTION: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/missing-section.ini");
const UNICODE_OPTIONXFORM: &[u8] =
    include_bytes!("../../../conformance/oracles/python-configparser-v1/unicode-optionxform.ini");

#[derive(Debug, Eq, PartialEq)]
struct SectionView {
    name: String,
    entries: Vec<(String, String)>,
}

/// Runs the embedded CPython 3.14 ConfigParser differential manifest.
#[must_use]
pub fn run_ini_python_oracle() -> ConformanceReport {
    run_ini_python_oracle_json(INI_PYTHON_ORACLE_JSON)
}

/// Runs one caller-supplied CPython 3.14 ConfigParser differential manifest.
#[must_use]
pub fn run_ini_python_oracle_json(json: &str) -> ConformanceReport {
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
        return Err("unexpected CPython package digest".to_owned());
    }
    let adapter = object_object(root, "adapter")?;
    if object_string(adapter, "source_sha256")? != ADAPTER_SHA256 {
        return Err("unexpected ConfigParser adapter digest".to_owned());
    }
    let runtime = object_object(root, "runtime")?;
    if object_string(runtime, "python.implementation")? != "CPython"
        || object_string(runtime, "python.version")? != "3.14.6"
        || object_string(runtime, "os.name")? != "Windows"
        || object_string(runtime, "os.machine")? != "AMD64"
        || object_string(runtime, "windows_build")? != "10.0.26200.0"
    {
        return Err("unexpected ConfigParser runtime facts".to_owned());
    }
    let exclusions = object_field(root, "exclusions")
        .and_then(PortableValue::as_sequence)
        .ok_or("exclusions must be Sequence")?;
    if exclusions.len() != 6 || exclusions.iter().any(|item| item.as_string().is_none()) {
        return Err("ConfigParser oracle exclusions are incomplete".to_owned());
    }
    Ok(())
}

fn run_case(fields: &[consema_core::ObjectEntry]) -> Result<(), String> {
    let path = object_string(fields, "input")?;
    let source = fixture(path)?;
    if ContentDigest::of(source).to_hex() != object_string(fields, "input_sha256")? {
        return Err("input digest differs from authority record".to_owned());
    }
    let document = ini::parse(
        source,
        IniProfile::PythonConfigParserV1,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    )
    .map_err(|error| format!("Consema ConfigParser formation failed fatally: {error:?}"))?;
    let expected = object_object(fields, "expected")?;
    match object_string(expected, "outcome")? {
        "complete" => compare_complete(&document, expected),
        "failed" => compare_failed(&document, expected),
        outcome => Err(format!("unknown ConfigParser oracle outcome {outcome}")),
    }
}

fn compare_complete(
    document: &ini::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    if document.formation_status() != FormationStatus::Complete {
        return Err(format!(
            "ConfigParser completed but Consema formed {:?}: {:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    let expected_defaults = expected_pairs(expected, "defaults")?;
    let expected_sections = expected_sections(expected)?;
    let actual_defaults = python_defaults(document)?;
    let actual_sections = python_sections(document, &actual_defaults);
    if actual_defaults != expected_defaults || actual_sections != expected_sections {
        return Err(format!(
            "ConfigParser mapping view differed: expected defaults={expected_defaults:?}, sections={expected_sections:?}; got defaults={actual_defaults:?}, sections={actual_sections:?}"
        ));
    }
    if document
        .sections()
        .iter()
        .any(|section| section.duplicate_group().is_some())
        || document
            .entries()
            .iter()
            .any(|entry| entry.duplicate_group().is_some())
    {
        return Err("complete ConfigParser case contains a native collision".to_owned());
    }
    Ok(())
}

fn compare_failed(
    document: &ini::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    let exception = object_string(expected, "exception")?;
    let accepted_codes: &[&str] = match exception {
        "configparser.DuplicateOptionError" => &[
            "ini.formation.duplicate-entry@1",
            "ini.formation.case-collision@1",
        ],
        "configparser.DuplicateSectionError" => &["ini.formation.duplicate-section@1"],
        "configparser.MissingSectionHeaderError" => &["ini.parse.missing-section@1"],
        _ => {
            return Err(format!(
                "unknown ConfigParser exception classification {exception}"
            ));
        }
    };
    if document.formation_status() != FormationStatus::Recovered
        || !document
            .diagnostics()
            .iter()
            .any(|diagnostic| accepted_codes.contains(&diagnostic.code.as_str()))
    {
        return Err(format!(
            "ConfigParser rejected but Consema recovery differed: status={:?}, diagnostics={:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    if !matches!(
        document.project(ProjectionRequest::best_exact_entry_mapping()),
        ProjectionResult::Failed(_)
    ) {
        return Err("rejected ConfigParser case published a Consema value".to_owned());
    }
    let transaction = EditTransactionBuilder::new(document).build();
    if document.commit(&transaction).is_ok() {
        return Err("rejected ConfigParser case accepted an edit transaction".to_owned());
    }
    Ok(())
}

fn python_defaults(document: &ini::Document) -> Result<Vec<(String, String)>, String> {
    let defaults = document
        .sections()
        .iter()
        .filter(|section| section.is_default())
        .collect::<Vec<_>>();
    if defaults.len() > 1 {
        return Err("complete document contains multiple DEFAULT sections".to_owned());
    }
    let Some(defaults) = defaults.first() else {
        return Ok(Vec::new());
    };
    Ok(document
        .entries()
        .iter()
        .filter(|entry| entry.section() == defaults.node_ref())
        .map(|entry| (entry.comparison_key().to_owned(), entry.value().to_owned()))
        .collect())
}

fn python_sections(document: &ini::Document, defaults: &[(String, String)]) -> Vec<SectionView> {
    document
        .sections()
        .iter()
        .filter(|section| !section.is_default())
        .map(|section| {
            let mut entries = defaults.to_vec();
            for entry in document
                .entries()
                .iter()
                .filter(|entry| entry.section() == section.node_ref())
            {
                if let Some((_, value)) = entries
                    .iter_mut()
                    .find(|(key, _)| key == entry.comparison_key())
                {
                    entry.value().clone_into(value);
                } else {
                    entries.push((entry.comparison_key().to_owned(), entry.value().to_owned()));
                }
            }
            SectionView {
                name: section.name().to_owned(),
                entries,
            }
        })
        .collect()
}

fn expected_sections(expected: &[consema_core::ObjectEntry]) -> Result<Vec<SectionView>, String> {
    object_field(expected, "sections")
        .and_then(PortableValue::as_sequence)
        .ok_or("complete outcome sections must be Sequence")?
        .iter()
        .map(|section| {
            let section = section
                .as_object()
                .ok_or("expected ConfigParser section must be Object")?;
            Ok(SectionView {
                name: decode_utf8_hex(object_string(section, "name")?)?,
                entries: expected_pairs(section, "entries")?,
            })
        })
        .collect()
}

fn expected_pairs(
    fields: &[consema_core::ObjectEntry],
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("{name} must be Sequence"))?
        .iter()
        .map(|entry| {
            let pair = entry
                .as_sequence()
                .ok_or_else(|| format!("{name} entry must be Sequence"))?;
            if pair.len() != 2 {
                return Err(format!("{name} entry must contain key and value"));
            }
            Ok((
                decode_utf8_hex(pair[0].as_string().ok_or("key hex must be String")?)?,
                decode_utf8_hex(pair[1].as_string().ok_or("value hex must be String")?)?,
            ))
        })
        .collect()
}

fn fixture(path: &str) -> Result<&'static [u8], String> {
    match path {
        "conformance/oracles/python-configparser-v1/basic.ini" => Ok(BASIC),
        "conformance/oracles/python-configparser-v1/casefold-collision.ini" => {
            Ok(CASEFOLD_COLLISION)
        }
        "conformance/oracles/python-configparser-v1/continuation.ini" => Ok(CONTINUATION),
        "conformance/oracles/python-configparser-v1/default-override.ini" => Ok(DEFAULT_OVERRIDE),
        "conformance/oracles/python-configparser-v1/defaults-and-raw.ini" => Ok(DEFAULTS_AND_RAW),
        "conformance/oracles/python-configparser-v1/duplicate-option.ini" => Ok(DUPLICATE_OPTION),
        "conformance/oracles/python-configparser-v1/duplicate-section.ini" => Ok(DUPLICATE_SECTION),
        "conformance/oracles/python-configparser-v1/missing-section.ini" => Ok(MISSING_SECTION),
        "conformance/oracles/python-configparser-v1/unicode-optionxform.ini" => {
            Ok(UNICODE_OPTIONXFORM)
        }
        _ => Err(format!("unrecorded ConfigParser oracle input {path}")),
    }
}

fn decode_utf8_hex(value: &str) -> Result<String, String> {
    let bytes = decode_hex(value)?;
    String::from_utf8(bytes).map_err(|_| "UTF-8 hex is not well formed".to_owned())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = value.bytes().collect();
    let mut chunks = digits.chunks_exact(2);
    let bytes = chunks
        .by_ref()
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect::<Result<Vec<_>, String>>()?;
    if !chunks.remainder().is_empty() {
        return Err("hex has an odd digit count".to_owned());
    }
    Ok(bytes)
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
    fn published_python_oracle_manifest_is_conformant() {
        let report = run_ini_python_oracle();
        assert!(report.is_conformant(), "{:?}", report.failed);
        assert_eq!(report.passed.len(), CASE_COUNT);
    }

    #[test]
    fn python_oracle_expectation_and_digest_mutations_are_observed() {
        let expectation = INI_PYTHON_ORACLE_JSON.replacen("776f726b6572", "776f726b6573", 1);
        let report = run_ini_python_oracle_json(&expectation);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));

        let digest = INI_PYTHON_ORACLE_JSON.replacen(
            "bae47b1e454fe3f22604bf591ea6784bf904f2caa12748332339d3d05310b2ab",
            "0ae47b1e454fe3f22604bf591ea6784bf904f2caa12748332339d3d05310b2ab",
            1,
        );
        let report = run_ini_python_oracle_json(&digest);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));
    }

    #[test]
    fn python_oracle_metadata_unknown_input_and_outcome_fail_closed() {
        let metadata = INI_PYTHON_ORACLE_JSON.replacen(ADAPTER_SHA256, PACKAGE_SHA256, 1);
        assert_eq!(
            run_ini_python_oracle_json(&metadata).failed[0].0,
            "suite.schema"
        );

        let input = INI_PYTHON_ORACLE_JSON.replacen(
            "conformance/oracles/python-configparser-v1/basic.ini",
            "conformance/oracles/python-configparser-v1/unrecorded.ini",
            1,
        );
        assert!(
            run_ini_python_oracle_json(&input)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let outcome = INI_PYTHON_ORACLE_JSON.replacen(
            "\"outcome\": \"complete\"",
            "\"outcome\": \"partial\"",
            1,
        );
        assert!(
            run_ini_python_oracle_json(&outcome)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );
    }

    #[test]
    fn python_oracle_unknown_exception_and_duplicate_id_are_rejected() {
        let exception = INI_PYTHON_ORACLE_JSON.replacen(
            "configparser.DuplicateOptionError",
            "configparser.Error",
            1,
        );
        assert!(
            run_ini_python_oracle_json(&exception)
                .failed
                .iter()
                .any(|(id, _)| id == "casefold-collision")
        );

        let duplicate =
            INI_PYTHON_ORACLE_JSON.replacen("\"id\": \"continuation\"", "\"id\": \"basic\"", 1);
        assert!(
            run_ini_python_oracle_json(&duplicate)
                .failed
                .iter()
                .any(|(id, error)| id == "basic" && error == "duplicate case id")
        );
    }
}
