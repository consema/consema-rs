use consema::ini::{self, IniEncodingSelection, IniParseLimits, IniProfile, IniQuoteStyle};
use consema_core::{BigInteger, PortableValue};
use consema_document::{ContentDigest, FormationStatus, ParseLimits, SourceEncoding};
use std::collections::HashSet;

use super::{ConformanceReport, object_field};

const SUITE: &str = "consema.ini.windows-wide-api-differential@1";
const CASE_COUNT: usize = 5;
const MODULE_SHA256: &str = "b5ad8f395042f9599fd7cc5345281db9ec2ab73a90481320fc2c8ac742bf0280";
const ADAPTER_SHA256: &str = "74527cfca16d5197d82d30a9b8dc2805d9ff0a8d5b99e05da8d92f31ff7a2c82";

/// Embedded Windows wide INI API differential manifest.
pub const INI_WINDOWS_ORACLE_JSON: &str =
    include_str!("../../../conformance/oracles/windows-ini-v1/manifest.json");

const BASIC_HEX: &str = include_str!("../../../conformance/oracles/windows-ini-v1/basic.ini.hex");
const CASEFOLD_HEX: &str =
    include_str!("../../../conformance/oracles/windows-ini-v1/casefold.ini.hex");
const QUOTES_HEX: &str = include_str!("../../../conformance/oracles/windows-ini-v1/quotes.ini.hex");
const SECTIONS_HEX: &str =
    include_str!("../../../conformance/oracles/windows-ini-v1/sections.ini.hex");
const UNICODE_HEX: &str =
    include_str!("../../../conformance/oracles/windows-ini-v1/unicode.ini.hex");

/// Runs the embedded Windows wide INI API differential manifest.
#[must_use]
pub fn run_ini_windows_oracle() -> ConformanceReport {
    run_ini_windows_oracle_json(INI_WINDOWS_ORACLE_JSON)
}

/// Runs one caller-supplied Windows wide INI API differential manifest.
#[must_use]
pub fn run_ini_windows_oracle_json(json: &str) -> ConformanceReport {
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
    if object_string(authority, "windows_build")? != "10.0.26200.0"
        || object_string(authority, "module_file_version")?
            != "10.0.26100.8972 (WinBuild.160101.0800)"
        || object_string(authority, "module_sha256")? != MODULE_SHA256
    {
        return Err("unexpected Windows API authority facts".to_owned());
    }
    let adapter = object_object(root, "adapter")?;
    if object_string(adapter, "source_sha256")? != ADAPTER_SHA256 {
        return Err("unexpected Windows INI adapter digest".to_owned());
    }
    let exclusions = object_field(root, "exclusions")
        .and_then(PortableValue::as_sequence)
        .ok_or("exclusions must be Sequence")?;
    if exclusions.len() != 6 || exclusions.iter().any(|item| item.as_string().is_none()) {
        return Err("Windows INI exclusions are incomplete".to_owned());
    }
    Ok(())
}

fn run_case(fields: &[consema_core::ObjectEntry]) -> Result<(), String> {
    let path = object_string(fields, "input")?;
    let source = fixture(path)?;
    if ContentDigest::of(&source).to_hex() != object_string(fields, "input_sha256")? {
        return Err("input digest differs from authority record".to_owned());
    }
    let document = ini::parse(
        source,
        IniProfile::WindowsV1,
        IniEncodingSelection::Explicit(SourceEncoding::Utf16Le),
        IniParseLimits::default(),
    )
    .map_err(|error| format!("Consema Windows formation failed: {error:?}"))?;
    if document.formation_status() != FormationStatus::Complete
        || document.sections().len() != object_usize(fields, "native_sections")?
        || document.entries().len() != object_usize(fields, "native_entries")?
    {
        return Err(format!(
            "native Windows document differed: status={:?}, sections={}, entries={}, diagnostics={:?}",
            document.formation_status(),
            document.sections().len(),
            document.entries().len(),
            document.diagnostics()
        ));
    }
    let queries = object_field(fields, "queries")
        .and_then(PortableValue::as_sequence)
        .ok_or("queries must be Sequence")?;
    if queries.is_empty() {
        return Err("oracle case must contain at least one query".to_owned());
    }
    for query in queries {
        let query = query.as_object().ok_or("query must be Object")?;
        match object_string(query, "kind")? {
            "value" => {
                let actual = windows_value(
                    &document,
                    object_string(query, "section")?,
                    object_string(query, "key")?,
                    object_string(query, "default")?,
                );
                if utf16_hex(&actual) != object_string(query, "utf16be_hex")? {
                    return Err(format!("Windows value query differed: {actual:?}"));
                }
            }
            "sections" => {
                let actual: Vec<String> = document
                    .sections()
                    .iter()
                    .map(|section| utf16_hex(section.name()))
                    .collect();
                if actual != object_strings(query, "utf16be_hex")? {
                    return Err(format!("Windows section enumeration differed: {actual:?}"));
                }
            }
            "keys" => {
                let actual = windows_keys(&document, object_string(query, "section")?);
                if actual != object_strings(query, "utf16be_hex")? {
                    return Err(format!("Windows key enumeration differed: {actual:?}"));
                }
            }
            kind => return Err(format!("unknown Windows oracle query kind {kind}")),
        }
    }
    Ok(())
}

fn windows_value(document: &ini::Document, section: &str, key: &str, default: &str) -> String {
    let section = section.to_ascii_lowercase();
    let key = key.to_ascii_lowercase();
    let Some(section) = document
        .sections()
        .iter()
        .find(|item| item.comparison_name() == section)
    else {
        return default.to_owned();
    };
    document
        .entries()
        .iter()
        .find(|entry| entry.section() == section.node_ref() && entry.comparison_key() == key)
        .map_or_else(
            || default.to_owned(),
            |entry| {
                if entry.quote_style() == IniQuoteStyle::None {
                    entry
                        .value()
                        .trim_matches(|character| matches!(character, ' ' | '\t'))
                        .to_owned()
                } else {
                    entry.value().to_owned()
                }
            },
        )
}

fn windows_keys(document: &ini::Document, section: &str) -> Vec<String> {
    let section = section.to_ascii_lowercase();
    let Some(section) = document
        .sections()
        .iter()
        .find(|item| item.comparison_name() == section)
    else {
        return Vec::new();
    };
    document
        .entries()
        .iter()
        .filter(|entry| entry.section() == section.node_ref())
        .map(|entry| utf16_hex(entry.key()))
        .collect()
}

fn fixture(path: &str) -> Result<Vec<u8>, String> {
    let hex = match path {
        "conformance/oracles/windows-ini-v1/basic.ini.hex" => BASIC_HEX,
        "conformance/oracles/windows-ini-v1/casefold.ini.hex" => CASEFOLD_HEX,
        "conformance/oracles/windows-ini-v1/quotes.ini.hex" => QUOTES_HEX,
        "conformance/oracles/windows-ini-v1/sections.ini.hex" => SECTIONS_HEX,
        "conformance/oracles/windows-ini-v1/unicode.ini.hex" => UNICODE_HEX,
        _ => return Err(format!("unrecorded Windows oracle input {path}")),
    };
    decode_hex(hex)
}

fn utf16_hex(value: &str) -> String {
    let mut output = String::with_capacity(value.len() * 4);
    for unit in value.encode_utf16() {
        use std::fmt::Write as _;
        write!(output, "{unit:04x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
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

fn object_strings(fields: &[consema_core::ObjectEntry], name: &str) -> Result<Vec<String>, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} values must be String"))
        })
        .collect()
}

fn object_usize(fields: &[consema_core::ObjectEntry], name: &str) -> Result<usize, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_i64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("{name} must be non-negative usize"))
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
    fn published_windows_oracle_manifest_is_conformant() {
        let report = run_ini_windows_oracle();
        assert!(report.is_conformant(), "{:?}", report.failed);
        assert_eq!(report.passed.len(), CASE_COUNT);
    }

    #[test]
    fn windows_oracle_expectation_and_digest_mutations_are_observed() {
        let expectation = INI_WINDOWS_ORACLE_JSON.replacen(
            "0077006f0072006b00650072",
            "0077006f0072006b00650073",
            1,
        );
        let report = run_ini_windows_oracle_json(&expectation);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));

        let digest = INI_WINDOWS_ORACLE_JSON.replacen(
            "0c223635b3b52fff7c730c4d933309fdf5f582207e15b18ed1fa9a70e44d157e",
            "1c223635b3b52fff7c730c4d933309fdf5f582207e15b18ed1fa9a70e44d157e",
            1,
        );
        let report = run_ini_windows_oracle_json(&digest);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));
    }

    #[test]
    fn windows_oracle_metadata_unknown_query_and_input_fail_closed() {
        let metadata = INI_WINDOWS_ORACLE_JSON.replacen(ADAPTER_SHA256, MODULE_SHA256, 1);
        assert_eq!(
            run_ini_windows_oracle_json(&metadata).failed[0].0,
            "suite.schema"
        );

        let query =
            INI_WINDOWS_ORACLE_JSON.replacen("\"kind\": \"value\"", "\"kind\": \"write\"", 1);
        assert!(
            run_ini_windows_oracle_json(&query)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let input = INI_WINDOWS_ORACLE_JSON.replacen(
            "conformance/oracles/windows-ini-v1/basic.ini.hex",
            "conformance/oracles/windows-ini-v1/unrecorded.ini.hex",
            1,
        );
        assert!(
            run_ini_windows_oracle_json(&input)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );
    }
}
