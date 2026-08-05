use consema::ini::{
    self, IniEncodingSelection, IniParseLimits, IniProfile, ProjectionRequest, ProjectionResult,
};
use consema_core::PortableValue;
use consema_document::{ContentDigest, FormationStatus, ParseLimits};
use std::collections::HashSet;

use super::{ConformanceReport, object_field};

const SUITE: &str = "consema.ini.qt610-portable-differential@1";
const CASE_COUNT: usize = 4;
const QT_PACKAGE_SHA256: &str = "511139353ebf960d16e8140eaae0c5424977152e7bc51d040d0279ca8d96a389";
const COMPILER_PACKAGE_SHA256: &str =
    "a7b502294a903b64fccd4a41ba39f48d3f6c9a5ece167f0cfaeac920d15b344f";
const ADAPTER_SHA256: &str = "68e46532e86a930f72c32e7ff42c05fe2e2b33720273eaffcaf5871a06164125";

/// Embedded Qt 6.10 QSettings portable-subset differential manifest.
pub const INI_QT_ORACLE_JSON: &str =
    include_str!("../../../conformance/oracles/qt-ini-v1/manifest.json");

const BASIC: &[u8] = include_bytes!("../../../conformance/oracles/qt-ini-v1/basic.ini");
const COMMENTS: &[u8] = include_bytes!("../../../conformance/oracles/qt-ini-v1/comments.ini");
const MULTI_SECTION: &[u8] =
    include_bytes!("../../../conformance/oracles/qt-ini-v1/multi-section.ini");
const ORDERING: &[u8] = include_bytes!("../../../conformance/oracles/qt-ini-v1/ordering.ini");

/// Runs the embedded Qt 6.10 QSettings portable-subset differential manifest.
#[must_use]
pub fn run_ini_qt_oracle() -> ConformanceReport {
    run_ini_qt_oracle_json(INI_QT_ORACLE_JSON)
}

/// Runs one caller-supplied Qt 6.10 QSettings differential manifest.
#[must_use]
pub fn run_ini_qt_oracle_json(json: &str) -> ConformanceReport {
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
    if object_string(authority, "package_sha256")? != QT_PACKAGE_SHA256
        || object_string(authority, "qt6core_sha256")?
            != "7e14027a0bb4017325db707c315c70ee008c8f2364f60bb2eb04d53c017ee762"
    {
        return Err("unexpected Qt authority digest".to_owned());
    }
    let compiler = object_object(root, "compiler")?;
    if object_string(compiler, "package_sha256")? != COMPILER_PACKAGE_SHA256
        || object_string(compiler, "executable_sha256")?
            != "cd65c087ad69a877e5a105c607cc910abfabcc52ba7e9448572f36567b51698c"
    {
        return Err("unexpected Qt compiler digest".to_owned());
    }
    let adapter = object_object(root, "adapter")?;
    if object_string(adapter, "source_sha256")? != ADAPTER_SHA256 {
        return Err("unexpected Qt adapter digest".to_owned());
    }
    let runtime = object_object(root, "runtime")?;
    if object_string(runtime, "qt.version")? != "6.10.2"
        || object_string(runtime, "qt.build-abi")? != "x86_64-little_endian-llp64"
        || object_string(runtime, "os.product-type")? != "windows"
        || object_string(runtime, "os.kernel-version")? != "10.0.26200"
        || object_string(runtime, "windows_build")? != "10.0.26200.0"
    {
        return Err("unexpected Qt runtime facts".to_owned());
    }
    let comparison = object_object(root, "comparison")?;
    if object_string(comparison, "profile")? != "ini.portable@1" {
        return Err("Qt comparison must remain on the portable profile".to_owned());
    }
    let exclusions = object_field(root, "exclusions")
        .and_then(PortableValue::as_sequence)
        .ok_or("exclusions must be Sequence")?;
    if exclusions.len() != 6 || exclusions.iter().any(|item| item.as_string().is_none()) {
        return Err("Qt oracle exclusions are incomplete".to_owned());
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
        IniProfile::PortableV1,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    )
    .map_err(|error| format!("Consema portable formation failed fatally: {error:?}"))?;
    if document.formation_status() != FormationStatus::Complete {
        return Err(format!(
            "Qt accepted but Consema formed {:?}: {:?}",
            document.formation_status(),
            document.diagnostics()
        ));
    }
    let expected = object_object(fields, "expected")?;
    if object_string(expected, "outcome")? != "complete" {
        return Err("unknown Qt oracle outcome".to_owned());
    }
    let expected_entries = expected_entries(expected)?;
    let actual_entries = qt_view(&document);
    if actual_entries != expected_entries {
        return Err(format!(
            "Qt public view differed: expected {expected_entries:?}, got {actual_entries:?}"
        ));
    }
    if document.entries().len() != expected_entries.len() {
        return Err("Qt portable comparison lost a native occurrence".to_owned());
    }
    if !matches!(
        document.project(ProjectionRequest::best_exact_entry_mapping()),
        ProjectionResult::Complete(_)
    ) {
        return Err("complete Qt portable case did not publish an exact projection".to_owned());
    }
    Ok(())
}

fn qt_view(document: &ini::Document) -> Vec<(String, String)> {
    let mut entries = Vec::with_capacity(document.entries().len());
    for section in document.sections() {
        for entry in document
            .entries()
            .iter()
            .filter(|entry| entry.section() == section.node_ref())
        {
            entries.push((
                format!("{}/{}", section.name(), entry.key()),
                entry.value().to_owned(),
            ));
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
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
            .ok_or("expected Qt entry must be Sequence")?;
        if pair.len() != 2 {
            return Err("expected Qt entry must contain key and value".to_owned());
        }
        let key = decode_utf8_hex(pair[0].as_string().ok_or("Qt key hex must be String")?)?;
        let value = decode_utf8_hex(pair[1].as_string().ok_or("Qt value hex must be String")?)?;
        if !key.is_ascii() || key.matches('/').count() != 1 {
            return Err("Qt oracle key escapes the portable subset".to_owned());
        }
        if output.last().is_some_and(|(previous, _)| previous >= &key) {
            return Err("expected Qt entries are not in strict lexical order".to_owned());
        }
        output.push((key, value));
    }
    Ok(output)
}

fn fixture(path: &str) -> Result<&'static [u8], String> {
    match path {
        "conformance/oracles/qt-ini-v1/basic.ini" => Ok(BASIC),
        "conformance/oracles/qt-ini-v1/comments.ini" => Ok(COMMENTS),
        "conformance/oracles/qt-ini-v1/multi-section.ini" => Ok(MULTI_SECTION),
        "conformance/oracles/qt-ini-v1/ordering.ini" => Ok(ORDERING),
        _ => Err(format!("unrecorded Qt oracle input {path}")),
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
    fn published_qt_oracle_manifest_is_conformant() {
        let report = run_ini_qt_oracle();
        assert!(report.is_conformant(), "{:?}", report.failed);
        assert_eq!(report.passed.len(), CASE_COUNT);
    }

    #[test]
    fn qt_oracle_expectation_and_digest_mutations_are_observed() {
        let expectation = INI_QT_ORACLE_JSON.replacen("6461726b", "6461726c", 1);
        let report = run_ini_qt_oracle_json(&expectation);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));

        let digest = INI_QT_ORACLE_JSON.replacen(
            "bc745d8a385b548d9c9962591dac7eaf7cf0dc663111595ddfc77972d68015ea",
            "0c745d8a385b548d9c9962591dac7eaf7cf0dc663111595ddfc77972d68015ea",
            1,
        );
        let report = run_ini_qt_oracle_json(&digest);
        assert!(report.failed.iter().any(|(id, _)| id == "basic"));
    }

    #[test]
    fn qt_oracle_metadata_unknown_input_outcome_and_duplicate_id_fail_closed() {
        let metadata = INI_QT_ORACLE_JSON.replacen(ADAPTER_SHA256, QT_PACKAGE_SHA256, 1);
        assert_eq!(
            run_ini_qt_oracle_json(&metadata).failed[0].0,
            "suite.schema"
        );

        let input = INI_QT_ORACLE_JSON.replacen(
            "conformance/oracles/qt-ini-v1/basic.ini",
            "conformance/oracles/qt-ini-v1/unrecorded.ini",
            1,
        );
        assert!(
            run_ini_qt_oracle_json(&input)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let outcome =
            INI_QT_ORACLE_JSON.replacen("\"outcome\": \"complete\"", "\"outcome\": \"partial\"", 1);
        assert!(
            run_ini_qt_oracle_json(&outcome)
                .failed
                .iter()
                .any(|(id, _)| id == "basic")
        );

        let duplicate = INI_QT_ORACLE_JSON.replacen("\"id\": \"comments\"", "\"id\": \"basic\"", 1);
        assert!(
            run_ini_qt_oracle_json(&duplicate)
                .failed
                .iter()
                .any(|(id, error)| id == "basic" && error == "duplicate case id")
        );
    }
}
