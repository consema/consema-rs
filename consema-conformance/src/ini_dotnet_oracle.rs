use consema::ini::{
    self, EditTransactionBuilder, IniEncodingSelection, IniParseLimits, IniProfile,
    ProjectionRequest, ProjectionResult,
};
use consema_core::PortableValue;
use consema_document::{ContentDigest, FormationStatus, ParseLimits};
use std::collections::HashSet;

use super::{ConformanceReport, object_field};

const SUITE: &str = "consema.ini.dotnet10-provider-differential@1";
const CASE_COUNT: usize = 7;
const PACKAGE_SHA512: &str = "7d170ed75fa9af34c00646621d92011dbd71943952e2787cd15df9be78e6452b55dadef34d7eff77b802e6af4959e071a55855ac649afeac70901c3a2a258716";
const INI_ASSEMBLY_SHA256: &str =
    "3627e5553db01ffe29b13616da468763e43d2e5f291cafbdbbe3f28dad438416";
const ADAPTER_SHA256: &str = "c0303847b0ec79097802135b07f243e5d7f39923d5803280686384815feb955b";

/// Embedded .NET 10 IniConfigurationProvider differential manifest.
pub const INI_DOTNET_ORACLE_JSON: &str =
    include_str!("../../../conformance/oracles/dotnet-ini-v1/manifest.json");

const BASIC: &[u8] = include_bytes!("../../../conformance/oracles/dotnet-ini-v1/basic.ini");
const CASEFOLD_DUPLICATE: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/casefold-duplicate.ini");
const COMMENTS_WHITESPACE: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/comments-whitespace.ini");
const MALFORMED_LINE: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/malformed-line.ini");
const QUOTED_VALUE: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/quoted-value.ini");
const SECTION_CASEFOLD_DUPLICATE: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/section-casefold-duplicate.ini");
const SECTION_PATH: &[u8] =
    include_bytes!("../../../conformance/oracles/dotnet-ini-v1/section-path.ini");

/// Runs the embedded .NET 10 IniConfigurationProvider differential manifest.
#[must_use]
pub fn run_ini_dotnet_oracle() -> ConformanceReport {
    run_ini_dotnet_oracle_json(INI_DOTNET_ORACLE_JSON)
}

/// Runs one caller-supplied .NET 10 IniConfigurationProvider manifest.
#[must_use]
pub fn run_ini_dotnet_oracle_json(json: &str) -> ConformanceReport {
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
    if object_string(authority, "package_sha512")? != PACKAGE_SHA512
        || object_string(authority, "ini_assembly_sha256")? != INI_ASSEMBLY_SHA256
    {
        return Err("unexpected .NET authority digest".to_owned());
    }
    let adapter = object_object(root, "adapter")?;
    if object_string(adapter, "source_sha256")? != ADAPTER_SHA256
        || object_string(adapter, "project_sha256")?
            != "676085d4fc674143e0869726db6e61a17d1c44aa2b5a34f3d1bf306189ea6c31"
        || object_string(adapter, "nuget_config_sha256")?
            != "5256a7e3e07d2c5c94f7a1e6c45f39aab011c659c5e2d53e452dea525ce04575"
    {
        return Err("unexpected .NET adapter digest".to_owned());
    }
    let runtime = object_object(root, "runtime")?;
    if object_string(runtime, "sdk.version")? != "10.0.302"
        || object_string(runtime, "host.version")? != "10.0.10"
        || object_string(runtime, "dotnet.framework")? != ".NET 10.0.10"
        || object_string(runtime, "process.architecture")? != "X64"
        || object_string(runtime, "ini.assembly-version")? != "10.0.0.0"
        || object_string(runtime, "windows_build")? != "10.0.26200.0"
    {
        return Err("unexpected .NET runtime facts".to_owned());
    }
    let comparison = object_object(root, "comparison")?;
    if object_string(comparison, "profile")? != "ini.python-configparser@1 shared subset" {
        return Err(".NET comparison escaped the declared shared subset".to_owned());
    }
    let exclusions = object_field(root, "exclusions")
        .and_then(PortableValue::as_sequence)
        .ok_or("exclusions must be Sequence")?;
    if exclusions.len() != 6 || exclusions.iter().any(|item| item.as_string().is_none()) {
        return Err(".NET INI exclusions are incomplete".to_owned());
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
    .map_err(|error| format!("Consema shared-subset formation failed fatally: {error:?}"))?;
    let expected = object_object(fields, "expected")?;
    match object_string(expected, "outcome")? {
        "complete" => compare_complete(&document, expected),
        "failed" => compare_failed(&document, expected),
        outcome => Err(format!("unknown .NET INI oracle outcome {outcome}")),
    }
}

fn compare_complete(
    document: &ini::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    if document.formation_status() != FormationStatus::Complete {
        return Err(format!(
            ".NET completed but Consema formed {:?}: {:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    let expected_entries = expected_entries(expected)?;
    let actual_entries = dotnet_view(document)?;
    if actual_entries != expected_entries {
        return Err(format!(
            ".NET provider view differed: expected {expected_entries:?}, got {actual_entries:?}"
        ));
    }
    if document.entries().len() != expected_entries.len()
        || !matches!(
            document.project(ProjectionRequest::best_exact_entry_mapping()),
            ProjectionResult::Complete(_)
        )
    {
        return Err("complete .NET case lost native publication facts".to_owned());
    }
    Ok(())
}

fn compare_failed(
    document: &ini::Document,
    expected: &[consema_core::ObjectEntry],
) -> Result<(), String> {
    if object_string(expected, "exception")? != "System.FormatException" {
        return Err("unknown .NET INI exception classification".to_owned());
    }
    match object_string(expected, "failure_surface")? {
        "native-recovered" => {
            if document.formation_status() != FormationStatus::Recovered
                || !matches!(
                    document.project(ProjectionRequest::best_exact_entry_mapping()),
                    ProjectionResult::Failed(_)
                )
            {
                return Err(format!(
                    ".NET rejected but native recovery differed: status={:?}, diagnostics={:?}",
                    document.formation_status(),
                    document.diagnostics()
                ));
            }
            let transaction = EditTransactionBuilder::new(document).build();
            if document.commit(&transaction).is_ok() {
                return Err("recovered .NET case accepted an edit transaction".to_owned());
            }
        }
        "provider-view-collision" => {
            if document.formation_status() != FormationStatus::Complete
                || dotnet_view(document).is_ok()
                || !matches!(
                    document.project(ProjectionRequest::best_exact_entry_mapping()),
                    ProjectionResult::Complete(_)
                )
            {
                return Err(format!(
                    ".NET provider collision did not preserve a complete native document: status={:?}, diagnostics={:?}",
                    document.formation_status(),
                    document.diagnostics()
                ));
            }
        }
        surface => return Err(format!("unknown .NET failure surface {surface}")),
    }
    Ok(())
}

fn dotnet_view(document: &ini::Document) -> Result<Vec<(String, String)>, String> {
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(document.entries().len());
    for section in document.sections() {
        if section.is_default() {
            return Err("DEFAULT is outside the .NET shared subset".to_owned());
        }
        for entry in document
            .entries()
            .iter()
            .filter(|entry| entry.section() == section.node_ref())
        {
            let key = format!("{}:{}", section.name(), entry.key());
            if !key.is_ascii() {
                return Err("non-ASCII .NET provider key is outside the shared subset".to_owned());
            }
            if !seen.insert(key.to_ascii_lowercase()) {
                return Err(".NET provider key collision".to_owned());
            }
            output.push((key, dotnet_value(entry.value()).to_owned()));
        }
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

fn dotnet_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

fn expected_entries(
    expected: &[consema_core::ObjectEntry],
) -> Result<Vec<(String, String)>, String> {
    let entries = object_field(expected, "entries")
        .and_then(PortableValue::as_sequence)
        .ok_or("complete outcome entries must be Sequence")?;
    let mut output = Vec::with_capacity(entries.len());
    for entry in entries {
        let pair = entry
            .as_sequence()
            .ok_or("expected .NET entry must be Sequence")?;
        if pair.len() != 2 {
            return Err("expected .NET entry must contain key and value".to_owned());
        }
        let key = decode_utf8_hex(pair[0].as_string().ok_or(".NET key hex must be String")?)?;
        let value = decode_utf8_hex(pair[1].as_string().ok_or(".NET value hex must be String")?)?;
        if !key.is_ascii() || !key.contains(':') {
            return Err(".NET oracle key escapes the shared subset".to_owned());
        }
        if output.last().is_some_and(|(previous, _)| previous >= &key) {
            return Err("expected .NET entries are not in strict ordinal order".to_owned());
        }
        output.push((key, value));
    }
    Ok(output)
}

fn fixture(path: &str) -> Result<&'static [u8], String> {
    match path {
        "conformance/oracles/dotnet-ini-v1/basic.ini" => Ok(BASIC),
        "conformance/oracles/dotnet-ini-v1/casefold-duplicate.ini" => Ok(CASEFOLD_DUPLICATE),
        "conformance/oracles/dotnet-ini-v1/comments-whitespace.ini" => Ok(COMMENTS_WHITESPACE),
        "conformance/oracles/dotnet-ini-v1/malformed-line.ini" => Ok(MALFORMED_LINE),
        "conformance/oracles/dotnet-ini-v1/quoted-value.ini" => Ok(QUOTED_VALUE),
        "conformance/oracles/dotnet-ini-v1/section-casefold-duplicate.ini" => {
            Ok(SECTION_CASEFOLD_DUPLICATE)
        }
        "conformance/oracles/dotnet-ini-v1/section-path.ini" => Ok(SECTION_PATH),
        _ => Err(format!("unrecorded .NET INI oracle input {path}")),
    }
}

fn decode_utf8_hex(value: &str) -> Result<String, String> {
    let digits: Vec<u8> = value.bytes().collect();
    let mut chunks = digits.chunks_exact(2);
    let bytes = chunks
        .by_ref()
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect::<Result<Vec<_>, String>>()?;
    if !chunks.remainder().is_empty() {
        return Err("hex has an odd digit count".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "UTF-8 hex is not well formed".to_owned())
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
    fn published_dotnet_oracle_manifest_is_conformant() {
        let report = run_ini_dotnet_oracle();
        assert!(report.is_conformant(), "{:?}", report.failed);
        assert_eq!(report.passed.len(), CASE_COUNT);
    }

    #[test]
    fn dotnet_oracle_expectation_and_digest_mutations_are_observed() {
        let expectation = INI_DOTNET_ORACLE_JSON.replacen("776f726b6572", "776f726b6573", 1);
        let report = run_ini_dotnet_oracle_json(&expectation);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));

        let digest = INI_DOTNET_ORACLE_JSON.replacen(
            "08eb76e124a5cfa49037e4d7e2cd363899330f4478e21c554f66b5da91e9ba6c",
            "18eb76e124a5cfa49037e4d7e2cd363899330f4478e21c554f66b5da91e9ba6c",
            1,
        );
        let report = run_ini_dotnet_oracle_json(&digest);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));
    }

    #[test]
    fn dotnet_oracle_metadata_unknown_fields_and_duplicate_id_fail_closed() {
        let metadata = INI_DOTNET_ORACLE_JSON.replacen(ADAPTER_SHA256, INI_ASSEMBLY_SHA256, 1);
        assert_eq!(
            run_ini_dotnet_oracle_json(&metadata).failed[0].0,
            "suite.schema"
        );

        let input = INI_DOTNET_ORACLE_JSON.replacen(
            "conformance/oracles/dotnet-ini-v1/basic.ini",
            "conformance/oracles/dotnet-ini-v1/unrecorded.ini",
            1,
        );
        assert!(
            run_ini_dotnet_oracle_json(&input)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let surface = INI_DOTNET_ORACLE_JSON.replacen("native-recovered", "provider-partial", 1);
        assert!(
            run_ini_dotnet_oracle_json(&surface)
                .failed
                .iter()
                .any(|(id, _)| id == "casefold-duplicate")
        );

        let outcome = INI_DOTNET_ORACLE_JSON.replacen(
            "\"outcome\": \"complete\"",
            "\"outcome\": \"partial\"",
            1,
        );
        assert!(
            run_ini_dotnet_oracle_json(&outcome)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let duplicate = INI_DOTNET_ORACLE_JSON.replacen(
            "\"id\": \"casefold-duplicate\"",
            "\"id\": \"basic\"",
            1,
        );
        assert!(
            run_ini_dotnet_oracle_json(&duplicate)
                .failed
                .iter()
                .any(|(id, error)| id == "basic" && error == "duplicate case id")
        );
    }
}
