//! Shared language-neutral `consema.plist.conformance@1` runner.

use super::{ConformanceReport, ensure, object_field};
use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, Decimal, ObjectBuilder,
    OperatorCall, PortableValue, QueryDefinition, QueryDomain, QueryExecution, QueryExpression,
    QueryFailure, QueryLimits, QuerySelection, QueryTerminalState, StableFailure,
};
use consema_document::{
    CompleteMaterialization, FormationStatus, MaterializationFailure, MaterializationRequest,
    MaterializationResult, MaterializationStyleId, NewlinePolicy, ParseLimits, ProfileId,
    SourceEncoding, SourcePatchLimits,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult as JsonProjectionResult,
    ProjectionTarget, parse as parse_json,
};
use consema_plist::{
    CollisionPolicy, ConversionFailure, DictPlacement, Document, EditPath, EditPathStep,
    EditTransaction, EditTransactionBuilder, EditValue, PlistBinaryMatch, PlistBoolean, PlistData,
    PlistDate, PlistDict, PlistDictEntry, PlistDocument, PlistEncodingSelection, PlistInteger,
    PlistKey, PlistMatch, PlistParseLimits, PlistProfile, PlistReal, PlistString,
    PlistStringStatus, PlistUid, PlistValue, PlistValueKind, PlistValueRef, ProjectionEventKind,
    ProjectionRequest as PlistProjectionRequest, ProjectionResult as PlistProjectionResult,
    execute_plist_binary_query, execute_plist_native_query, materialize, parse as parse_plist,
    project as project_plist,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Frozen suite identifier expected in every plist vector file.
const SUITE: &str = "consema.plist.conformance@1";

/// Embedded shared plist suite bytes.
pub const PLIST_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/plist-v1.json");

/// Runs the embedded `consema.plist.conformance@1` suite.
#[must_use]
pub fn run_plist_v1() -> ConformanceReport {
    run_plist_v1_json(PLIST_V1_VECTORS_JSON)
}

/// Runs one plist suite from JSON text.
#[must_use]
pub fn run_plist_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse_json(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published plist vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        JsonProjectionResult::Complete(result) => result.value,
        JsonProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("plist vector root object");
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
        "plist.xml-formation@1" => run_xml_formation(case),
        "plist.binary-formation@1" => run_binary_formation(case),
        "plist.query@1" => run_query(case),
        "plist.projection@1" => run_projection(case),
        "plist.materialization@1" => run_materialization(case),
        "plist.conversion@1" => run_conversion(case),
        "plist.edit@1" => run_edit(case),
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

fn expected_string_field(expected: &PortableValue, name: &str) -> Option<String> {
    object_value_field(expected, name)
        .and_then(PortableValue::as_string)
        .map(str::to_owned)
}

fn expected_sequence<'v>(expected: &'v PortableValue, name: &str) -> Option<&'v [PortableValue]> {
    object_value_field(expected, name).and_then(PortableValue::as_sequence)
}

fn expected_integer_field(expected: &PortableValue, name: &str) -> Option<i64> {
    object_value_field(expected, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_i64)
}

fn expected_boolean_field(expected: &PortableValue, name: &str) -> Option<bool> {
    object_value_field(expected, name).and_then(PortableValue::as_boolean)
}

fn expected_f64_field(expected: &PortableValue, name: &str) -> Option<f64> {
    object_value_field(expected, name).and_then(expected_f64)
}

fn status_name(status: FormationStatus) -> &'static str {
    match status {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    }
}

fn terminal_name(terminal: QueryTerminalState) -> &'static str {
    match terminal {
        QueryTerminalState::Completed => "Completed",
        QueryTerminalState::Cancelled => "Cancelled",
        QueryTerminalState::Failed => "Failed",
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

/// Converts one exact decimal to its double value; `None` when the
/// coefficient or exponent exceeds the exact `i64` range.
#[allow(clippy::cast_precision_loss)]
fn decimal_to_f64(decimal: &Decimal) -> Option<f64> {
    let coefficient = decimal.coefficient().to_i64()?;
    let exponent = decimal.exponent().to_i64()?;
    let mut value = coefficient as f64;
    if exponent > 0 {
        value *= 10_f64.powi(exponent.min(308) as i32);
    } else if exponent < 0 {
        value /= 10_f64.powi(exponent.unsigned_abs().min(308) as i32);
    }
    Some(value)
}

/// Exact bit equality of two doubles; every published numeric fact is an
/// exactly representable value, so bit equality is the strict comparison.
fn bits_equal(left: f64, right: f64) -> bool {
    left.to_bits() == right.to_bits()
}

/// Exact double of one expected numeric fact (binary float or decimal).
fn expected_f64(value: &PortableValue) -> Option<f64> {
    if let Some(bits) = value.as_binary_float64() {
        Some(f64::from_bits(bits.bits()))
    } else if let Some(bits) = value.as_binary_float32() {
        Some(f64::from(f32::from_bits(bits.bits())))
    } else if let Some(decimal) = value.as_decimal() {
        decimal_to_f64(decimal)
    } else {
        None
    }
}

fn assert_strings(actual: &[String], expected: &[PortableValue], what: &str) -> Result<(), String> {
    ensure(actual.len() == expected.len())
        .map_err(|_| format!("{what} count {} != {}", actual.len(), expected.len()))?;
    for (actual_item, expected_item) in actual.iter().zip(expected.iter()) {
        let expected_item = expected_item
            .as_string()
            .ok_or_else(|| format!("{what} must be a string"))?;
        ensure(actual_item == expected_item)
            .map_err(|_| format!("{what} {actual_item} != {expected_item}"))?;
    }
    Ok(())
}

fn assert_u64_field(expected: &PortableValue, name: &str, actual: u64) -> Result<(), String> {
    if let Some(expected_value) = expected_integer_field(expected, name) {
        ensure(u64::try_from(expected_value).is_ok_and(|expected| actual == expected))
            .map_err(|_| format!("{name} {actual} != {expected_value}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Formation
// ---------------------------------------------------------------------------

/// One vector fact from a value or its `input` member: samples carry their
/// facts at the top level, case-level inputs wrap them under `input`.
fn vector_field<'v>(value: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    object_value_field(value, name).or_else(|| input_field(value, name))
}

fn profile_of(value: &PortableValue) -> Result<PlistProfile, String> {
    match vector_field(value, "profile").and_then(PortableValue::as_string) {
        Some("plist.xml@1") => Ok(PlistProfile::XmlV1),
        Some("plist.binary@1") => Ok(PlistProfile::BinaryV1),
        Some(other) => Err(format!("unknown profile {other}")),
        None => Err("missing profile".to_owned()),
    }
}

/// Raw source bytes of one vector input or sample: `source` (with an optional
/// `encoding`) for the XML profile, `hex` for the binary profile.
fn source_bytes(value: &PortableValue, profile: PlistProfile) -> Result<Arc<[u8]>, String> {
    match profile {
        PlistProfile::BinaryV1 => {
            let text = vector_field(value, "hex")
                .and_then(PortableValue::as_string)
                .ok_or("missing input.hex")?;
            Ok(Arc::from(decode_hex(text)?))
        }
        PlistProfile::XmlV1 => {
            let source = vector_field(value, "source")
                .and_then(PortableValue::as_string)
                .ok_or("missing input.source")?;
            match vector_field(value, "encoding").and_then(PortableValue::as_string) {
                Some("utf16le-bom") => {
                    let mut bytes = vec![0xFF, 0xFE];
                    for unit in source.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                    Ok(Arc::from(bytes))
                }
                _ => Ok(Arc::from(source.as_bytes().to_vec())),
            }
        }
    }
}

/// Forms one document from a case-level input or one sample descriptor.
fn form_value(value: &PortableValue) -> Result<Document, String> {
    let profile = profile_of(value)?;
    let bytes = source_bytes(value, profile)?;
    parse_plist(
        bytes,
        profile,
        PlistEncodingSelection::ProfileDefault,
        PlistParseLimits::default(),
    )
    .map_err(|failure| format!("{failure:?}"))
}

fn form_case(case: &PortableValue) -> Result<Document, String> {
    form_value(case)
}

/// One sample's profile: samples without their own `profile` fact inherit the
/// case-level input profile.
fn sample_profile(case: &PortableValue, sample: &PortableValue) -> Result<PlistProfile, String> {
    match object_value_field(sample, "profile").and_then(PortableValue::as_string) {
        Some("plist.xml@1") => Ok(PlistProfile::XmlV1),
        Some("plist.binary@1") => Ok(PlistProfile::BinaryV1),
        Some(other) => Err(format!("unknown profile {other}")),
        None => profile_of(case),
    }
}

fn form_sample(case: &PortableValue, sample: &PortableValue) -> Result<Document, String> {
    let profile = sample_profile(case, sample)?;
    let bytes = source_bytes(sample, profile)?;
    parse_plist(
        bytes,
        profile,
        PlistEncodingSelection::ProfileDefault,
        PlistParseLimits::default(),
    )
    .map_err(|failure| format!("{failure:?}"))
}

/// Asserts the `expected.status` and optional `expected.diagnostic` facts.
fn assert_expected_status(document: &Document, expected: &PortableValue) -> Result<(), String> {
    if let Some(status) = expected_string_field(expected, "status") {
        ensure(status_name(document.status()) == status)
            .map_err(|_| format!("status {} != {status}", status_name(document.status())))?;
    }
    if let Some(diagnostic) = expected_string_field(expected, "diagnostic") {
        ensure(document.diagnostics().iter().any(|d| d.code == diagnostic))
            .map_err(|_| format!("diagnostic {diagnostic} not found"))?;
    }
    Ok(())
}

fn native_document(document: &Document) -> Result<&PlistDocument, String> {
    document
        .document()
        .ok_or_else(|| "no native document".to_owned())
}

fn root_value(document: &Document) -> Result<&PlistValue, String> {
    Ok(native_document(document)?.root_value())
}

fn dict_entries(value: &PlistValue) -> Result<&[PlistDictEntry], String> {
    value
        .as_dict()
        .map(PlistDict::entries)
        .ok_or_else(|| "expected dict".to_owned())
}

fn entry_key_text(entry: &PlistDictEntry) -> Result<String, String> {
    entry
        .key()
        .to_unicode()
        .map_err(|_| "key not unicode".to_owned())
}

fn dict_keys_of(document: &Document, value: &PlistValue) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    for entry in dict_entries(value)? {
        keys.push(entry_key_text(entry)?);
    }
    let _ = document;
    Ok(keys)
}

fn entry_by_key<'d>(
    document: &'d Document,
    value: &'d PlistValue,
    name: &str,
) -> Result<&'d PlistValue, String> {
    let native = native_document(document)?;
    for entry in dict_entries(value)? {
        if entry_key_text(entry)? == name {
            return native
                .get(entry.value())
                .ok_or_else(|| "entry value missing".to_owned());
        }
    }
    Err(format!("dict entry {name} not found"))
}

fn duplicate_groups_of(entries: &[PlistDictEntry]) -> Result<usize, String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for entry in entries {
        *counts.entry(entry_key_text(entry)?).or_insert(0) += 1;
    }
    Ok(counts.values().filter(|count| **count > 1).count())
}

fn value_kind_name(value: &PlistValue) -> &'static str {
    value.kind().as_str()
}

fn value_text(value: &PlistValue) -> Option<String> {
    value
        .as_string()
        .and_then(|string| string.to_unicode().ok())
}

fn value_integer(value: &PlistValue) -> Option<i64> {
    value.as_integer().map(|integer| integer.value())
}

fn value_real(value: &PlistValue) -> Option<f64> {
    value.as_real().map(|real| real.as_f64())
}

fn value_boolean(value: &PlistValue) -> Option<bool> {
    value.as_boolean().map(|boolean| boolean.value())
}

fn value_data_hex(value: &PlistValue) -> Option<String> {
    value.as_data().map(|data| hex(data.bytes()))
}

fn value_seconds(value: &PlistValue) -> Option<f64> {
    value.as_date().map(|date| date.seconds())
}

/// Compares one native scalar against one expected portable scalar fact
/// (string, integer, or boolean).
fn compare_scalar_value(value: &PlistValue, expected: &PortableValue) -> Result<(), String> {
    if let Some(text) = expected.as_string() {
        ensure(value_text(value).as_deref() == Some(text))
            .map_err(|_| format!("value {:?} != {text:?}", value_text(value)))?;
    } else if let Some(integer) = expected.as_integer().and_then(BigInteger::to_i64) {
        ensure(value_integer(value) == Some(integer))
            .map_err(|_| "integer value mismatch".to_owned())?;
    } else if let Some(boolean) = expected.as_boolean() {
        ensure(value_boolean(value) == Some(boolean))
            .map_err(|_| "boolean value mismatch".to_owned())?;
    } else {
        return Err("unsupported expected scalar".to_owned());
    }
    Ok(())
}

fn run_xml_formation(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_xml_formation_samples(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let document = form_case(case)?;
    assert_expected_status(&document, expected)?;
    if document.status() == FormationStatus::Complete {
        if let Some(render) = expected_string_field(expected, "render") {
            let actual = std::str::from_utf8(document.render())
                .map_err(|_| "render is not UTF-8".to_owned())?;
            ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
        }
        if let Some(hex_expected) = expected_string_field(expected, "render_hex") {
            ensure(hex(document.render()) == hex_expected)
                .map_err(|_| "render_hex mismatch".to_owned())?;
        }
        run_xml_native_facts(&document, expected)?;
    }
    Ok(())
}

fn run_xml_formation_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let statuses = expected_sequence(expected, "statuses").ok_or("missing expected.statuses")?;
    let diagnostics =
        expected_sequence(expected, "diagnostics").ok_or("missing expected.diagnostics")?;
    ensure(samples.len() == statuses.len() && samples.len() == diagnostics.len())
        .map_err(|_| "status/diagnostic count mismatch".to_owned())?;
    let integers = expected_sequence(expected, "integers");
    let seconds = expected_sequence(expected, "seconds");
    let data_hexes = expected_sequence(expected, "data_hexes");
    let values = expected_sequence(expected, "values");
    for (index, sample) in samples.iter().enumerate() {
        let document = form_sample(case, sample)?;
        let status = statuses[index]
            .as_string()
            .ok_or("status must be a string")?;
        ensure(status_name(document.status()) == status).map_err(|_| {
            format!(
                "sample {index} status {} != {status}",
                status_name(document.status())
            )
        })?;
        if let Some(code) = diagnostics[index].as_string() {
            ensure(document.diagnostics().iter().any(|d| d.code == code))
                .map_err(|_| format!("sample {index} diagnostic {code} not found"))?;
        }
        if status == "Complete" {
            let root = root_value(&document)?;
            if let Some(integers) = integers {
                let expected_value = integers[index].as_integer().and_then(BigInteger::to_i64);
                ensure(value_integer(root) == expected_value)
                    .map_err(|_| format!("sample {index} integer mismatch"))?;
            }
            if let Some(seconds) = seconds {
                let expected_value = expected_f64(&seconds[index]);
                ensure(value_seconds(root) == expected_value)
                    .map_err(|_| format!("sample {index} seconds mismatch"))?;
            }
            if let Some(data_hexes) = data_hexes {
                let expected_value = data_hexes[index].as_string().map(str::to_owned);
                ensure(value_data_hex(root) == expected_value)
                    .map_err(|_| format!("sample {index} data hex mismatch"))?;
            }
            if let Some(values) = values {
                let expected_value = values[index].as_string().map(str::to_owned);
                match expected_value {
                    // An empty expectation admits both empty strings and
                    // empty data leaves (`<data></data>` and `<string/>`).
                    Some(text) if text.is_empty() => {
                        let empty = value_text(root).is_some_and(|value| value.is_empty())
                            || root.as_data().is_some_and(|data| data.bytes().is_empty());
                        ensure(empty).map_err(|_| format!("sample {index} value is not empty"))?;
                    }
                    Some(text) => ensure(value_text(root).as_deref() == Some(text.as_str()))
                        .map_err(|_| format!("sample {index} value mismatch"))?,
                    None => {}
                }
            }
        }
    }
    Ok(())
}

/// Asserts the native-model facts of one complete XML formation case.
fn run_xml_native_facts(document: &Document, expected: &PortableValue) -> Result<(), String> {
    let root = root_value(document)?;
    if let Some(value) = expected_string_field(expected, "root_value")
        .or_else(|| expected_string_field(expected, "string_value"))
    {
        ensure(value_text(root).as_deref() == Some(value.as_str()))
            .map_err(|_| format!("root value {:?} != {value:?}", value_text(root)))?;
    }
    if let Some(keys) = expected_sequence(expected, "keys") {
        let actual = dict_keys_of(document, root)?;
        assert_strings(&actual, keys, "key")?;
    }
    if let Some(associations) = expected_integer_field(expected, "associations") {
        let actual = dict_entries(root)?.len();
        ensure(actual as i64 == associations)
            .map_err(|_| format!("associations {actual} != {associations}"))?;
    }
    if let Some(groups) = expected_integer_field(expected, "duplicate_groups") {
        let actual = duplicate_groups_of(dict_entries(root)?)?;
        ensure(actual as i64 == groups)
            .map_err(|_| format!("duplicate_groups {actual} != {groups}"))?;
    }
    if let Some(values) = expected_sequence(expected, "values") {
        let entries = dict_entries(root)?;
        ensure(entries.len() == values.len())
            .map_err(|_| format!("value count {} != {}", entries.len(), values.len()))?;
        for (entry, expected_value) in entries.iter().zip(values.iter()) {
            let value = native_document(document)?
                .get(entry.value())
                .ok_or("entry value missing")?;
            compare_scalar_value(value, expected_value)?;
        }
    }
    if let Some(integer) = expected_integer_field(expected, "integer_value") {
        let value = entry_by_key(document, root, "count")?;
        ensure(value_integer(value) == Some(integer)).map_err(|_| {
            format!(
                "integer_value {} != {integer}",
                value_integer(value).unwrap_or_default()
            )
        })?;
    }
    if let Some(integer) = expected_integer_field(expected, "negative_integer") {
        let value = entry_by_key(document, root, "negative")?;
        ensure(value_integer(value) == Some(integer)).map_err(|_| {
            format!(
                "negative_integer {} != {integer}",
                value_integer(value).unwrap_or_default()
            )
        })?;
    }
    if let Some(real) = expected_f64_field(expected, "real_value") {
        let value = entry_by_key(document, root, "ratio")?;
        ensure(value_real(value) == Some(real)).map_err(|_| {
            format!(
                "real_value {} != {real}",
                value_real(value).unwrap_or_default()
            )
        })?;
    }
    if let Some(hex_expected) = expected_string_field(expected, "data_hex") {
        let value = entry_by_key(document, root, "payload")?;
        ensure(value_data_hex(value).as_deref() == Some(hex_expected.as_str()))
            .map_err(|_| "data_hex mismatch".to_owned())?;
    }
    if let Some(seconds) = expected_f64_field(expected, "date_seconds") {
        let value = entry_by_key(document, root, "born")?;
        ensure(value_seconds(value) == Some(seconds))
            .map_err(|_| "date_seconds mismatch".to_owned())?;
    }
    if let Some(booleans) = expected_sequence(expected, "bool_values") {
        let expected: Vec<bool> = booleans
            .iter()
            .filter_map(PortableValue::as_boolean)
            .collect();
        let actual: Vec<bool> = dict_entries(root)?
            .iter()
            .filter_map(|entry| {
                native_document(document)
                    .ok()
                    .and_then(|native| native.get(entry.value()))
                    .and_then(value_boolean)
            })
            .collect();
        ensure(actual == expected)
            .map_err(|_| format!("bool_values {actual:?} != {expected:?}"))?;
    }
    if let Some(nested) = expected_sequence(expected, "nested_array") {
        let array = entry_by_key(document, root, "tags")?;
        let elements = array.as_array().ok_or("tags must be an array")?;
        let elements: Vec<&PlistValue> = elements
            .elements()
            .iter()
            .map(|reference| {
                native_document(document)
                    .ok()
                    .and_then(|native| native.get(*reference))
                    .ok_or_else(|| "array element missing".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure(elements.len() == nested.len())
            .map_err(|_| format!("nested array count {} != {}", elements.len(), nested.len()))?;
        for (element, expected_element) in elements.iter().zip(nested.iter()) {
            if let Some(text) = expected_element.as_string() {
                ensure(value_text(element).as_deref() == Some(text))
                    .map_err(|_| "nested element text mismatch".to_owned())?;
            } else if expected_element.as_object().is_some() {
                ensure(element.as_dict().is_some_and(PlistDict::is_empty))
                    .map_err(|_| "nested element must be an empty dict".to_owned())?;
            } else {
                return Err("unsupported nested expectation".to_owned());
            }
        }
    }
    if let Some(string_values) = object_value_field(expected, "string_values") {
        let mapping = string_values
            .as_object()
            .ok_or("string_values must be an object")?;
        for entry in mapping {
            let value = entry_by_key(document, root, entry.key())?;
            let expected_text = entry.value().as_string().ok_or("expected string value")?;
            ensure(value_text(value).as_deref() == Some(expected_text))
                .map_err(|_| format!("string value {} mismatch", entry.key()))?;
        }
    }
    if let Some(normalized) = expected_boolean_field(expected, "line_end_normalized") {
        let value = entry_by_key(document, root, "lines")?;
        let text = value_text(value).ok_or("lines value missing")?;
        ensure(text.contains('\r') != normalized)
            .map_err(|_| "line-end normalization mismatch".to_owned())?;
    }
    let reals = if expected_integer_field(expected, "real_count").is_some()
        || expected_boolean_field(expected, "nan_admitted").is_some()
        || expected_boolean_field(expected, "infinities_admitted").is_some()
        || expected_f64_field(expected, "exponent_value").is_some()
    {
        let array = root.as_array().ok_or("root must be an array")?;
        let mut reals = Vec::new();
        for reference in array.elements() {
            let value = native_document(document)?
                .get(*reference)
                .ok_or("element missing")?;
            if value.as_real().is_some() {
                reals.push(value);
            }
        }
        Some(reals)
    } else {
        None
    };
    if let Some(count) = expected_integer_field(expected, "real_count") {
        ensure(reals.as_ref().expect("checked above").len() as i64 == count)
            .map_err(|_| "real_count mismatch".to_owned())?;
    }
    if let Some(admitted) = expected_boolean_field(expected, "nan_admitted") {
        let actual = reals
            .as_ref()
            .expect("checked above")
            .iter()
            .any(|real| real.as_real().is_some_and(|r| r.as_f64().is_nan()));
        ensure(actual == admitted).map_err(|_| "nan_admitted mismatch".to_owned())?;
    }
    if let Some(admitted) = expected_boolean_field(expected, "infinities_admitted") {
        let actual = reals
            .as_ref()
            .expect("checked above")
            .iter()
            .any(|real| real.as_real().is_some_and(|r| r.as_f64().is_infinite()));
        ensure(actual == admitted).map_err(|_| "infinities_admitted mismatch".to_owned())?;
    }
    if let Some(exponent) = expected_f64_field(expected, "exponent_value") {
        let actual = reals.as_ref().expect("checked above").iter().any(|real| {
            real.as_real()
                .is_some_and(|r| bits_equal(r.as_f64(), exponent))
        });
        ensure(actual).map_err(|_| "exponent_value mismatch".to_owned())?;
    }
    Ok(())
}

fn run_binary_formation(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_binary_formation_samples(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let document = form_case(case)?;
    assert_expected_status(&document, expected)?;
    if let Some(facts) = document.binary_facts() {
        let trailer = facts.trailer();
        assert_u64_field(expected, "num_objects", trailer.num_objects())?;
        assert_u64_field(expected, "top_object", trailer.top_object())?;
        assert_u64_field(
            expected,
            "offset_int_size",
            u64::from(trailer.offset_int_size()),
        )?;
        assert_u64_field(
            expected,
            "object_ref_size",
            u64::from(trailer.object_ref_size()),
        )?;
        assert_u64_field(expected, "sort_version", u64::from(trailer.sort_version()))?;
        assert_u64_field(
            expected,
            "offset_table_offset",
            trailer.offset_table_offset(),
        )?;
        if let Some(refs_of_top) = expected_sequence(expected, "refs_of_top") {
            let top = usize::try_from(trailer.top_object()).unwrap_or(usize::MAX);
            let mut refs: Vec<(usize, usize)> = facts
                .refs()
                .iter()
                .filter(|reference| reference.owner() == top)
                .map(|reference| (reference.position(), reference.target()))
                .collect();
            refs.sort_by_key(|(position, _)| *position);
            let actual: Vec<i64> = refs.iter().map(|(_, target)| *target as i64).collect();
            let expected_refs: Vec<i64> = refs_of_top
                .iter()
                .filter_map(|value| value.as_integer().and_then(BigInteger::to_i64))
                .collect();
            ensure(actual == expected_refs)
                .map_err(|_| format!("refs_of_top {actual:?} != {expected_refs:?}"))?;
        }
        if let Some(shared) = expected_integer_field(expected, "shared_ref_count") {
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for reference in facts.refs() {
                *counts.entry(reference.target()).or_insert(0) += 1;
            }
            let shared_count = counts.values().filter(|count| **count > 1).count() as i64;
            ensure(shared_count == shared)
                .map_err(|_| format!("shared_ref_count {shared_count} != {shared}"))?;
        }
    }
    if document.status() == FormationStatus::Complete {
        run_binary_native_facts(&document, expected)?;
    }
    Ok(())
}

/// Asserts the native-model facts of one complete binary formation case.
fn run_binary_native_facts(document: &Document, expected: &PortableValue) -> Result<(), String> {
    let root = root_value(document)?;
    if let Some(value) = expected_string_field(expected, "value") {
        ensure(value_text(root).as_deref() == Some(value.as_str()))
            .map_err(|_| format!("value {:?} != {value:?}", value_text(root)))?;
    }
    if let Some(kind) = expected_string_field(expected, "top_kind") {
        ensure(value_kind_name(root) == kind)
            .map_err(|_| format!("top_kind {} != {kind}", value_kind_name(root)))?;
    }
    if let Some(keys) = expected_sequence(expected, "keys") {
        let actual = dict_keys_of(document, root)?;
        assert_strings(&actual, keys, "key")?;
    }
    if let Some(values) = expected_sequence(expected, "values") {
        let entries = dict_entries(root)?;
        ensure(entries.len() == values.len())
            .map_err(|_| format!("value count {} != {}", entries.len(), values.len()))?;
        for (entry, expected_value) in entries.iter().zip(values.iter()) {
            let value = native_document(document)?
                .get(entry.value())
                .ok_or("entry value missing")?;
            compare_scalar_value(value, expected_value)?;
        }
    }
    if let Some(value) = expected_integer_field(expected, "int_value") {
        let entry = entry_by_key(document, root, "int")?;
        ensure(value_integer(entry) == Some(value)).map_err(|_| {
            format!(
                "int_value {} != {value}",
                value_integer(entry).unwrap_or_default()
            )
        })?;
    }
    if let Some(value) = expected_f64_field(expected, "real_value") {
        let entry = entry_by_key(document, root, "real")?;
        ensure(value_real(entry) == Some(value)).map_err(|_| {
            format!(
                "real_value {} != {value}",
                value_real(entry).unwrap_or_default()
            )
        })?;
    }
    if let Some(value) = expected_f64_field(expected, "f32_value") {
        let entry = entry_by_key(document, root, "f32")?;
        ensure(value_real(entry) == Some(value)).map_err(|_| {
            format!(
                "f32_value {} != {value}",
                value_real(entry).unwrap_or_default()
            )
        })?;
    }
    if let Some(value) = expected_string_field(expected, "data_hex") {
        let entry = entry_by_key(document, root, "data")?;
        ensure(value_data_hex(entry).as_deref() == Some(value.as_str()))
            .map_err(|_| "data_hex mismatch".to_owned())?;
    }
    if let Some(value) = expected_f64_field(expected, "date_seconds") {
        let entry = entry_by_key(document, root, "date")?;
        ensure(value_seconds(entry) == Some(value))
            .map_err(|_| "date_seconds mismatch".to_owned())?;
    }
    if let Some(value) = expected_f64_field(expected, "fractional_seconds") {
        let entry = entry_by_key(document, root, "fractional")?;
        ensure(value_seconds(entry) == Some(value))
            .map_err(|_| "fractional_seconds mismatch".to_owned())?;
    }
    if let Some(booleans) = expected_sequence(expected, "bool_values") {
        let entry = entry_by_key(document, root, "bool")?;
        let expected: Vec<bool> = booleans
            .iter()
            .filter_map(PortableValue::as_boolean)
            .collect();
        // The `bool` entry is either one boolean or an array of booleans.
        let actual: Vec<bool> = if let Some(array) = entry.as_array() {
            array
                .elements()
                .iter()
                .filter_map(|reference| {
                    native_document(document)
                        .ok()
                        .and_then(|native| native.get(*reference))
                        .and_then(value_boolean)
                })
                .collect()
        } else {
            value_boolean(entry).into_iter().collect()
        };
        ensure(actual == expected)
            .map_err(|_| format!("bool_values {actual:?} != {expected:?}"))?;
    }
    if let Some(elements) = expected_sequence(expected, "array_elements") {
        let entry = entry_by_key(document, root, "array")?;
        let array = entry.as_array().ok_or("array must be an array")?;
        ensure(array.len() == elements.len())
            .map_err(|_| format!("array count {} != {}", array.len(), elements.len()))?;
        for (reference, expected_element) in array.elements().iter().zip(elements.iter()) {
            let value = native_document(document)?
                .get(*reference)
                .ok_or("element missing")?;
            let expected_integer = expected_element
                .as_integer()
                .and_then(BigInteger::to_i64)
                .ok_or("expected element must be an integer")?;
            ensure(value_integer(value) == Some(expected_integer))
                .map_err(|_| "array element mismatch".to_owned())?;
        }
    }
    if let Some(value) = expected_string_field(expected, "str_value") {
        let entry = entry_by_key(document, root, "str")?;
        ensure(value_text(entry).as_deref() == Some(value.as_str()))
            .map_err(|_| "str_value mismatch".to_owned())?;
    }
    Ok(())
}

/// Whether the root scalar object of one binary document carries a
/// non-minimal width fact (integers and UIDs, RFC 0013 §5.3, §5.8).
fn width_non_minimal_observed(document: &Document, root: &PlistValue) -> Option<bool> {
    let marker = document.binary_facts()?.objects().first()?.marker();
    if let Some(integer) = value_integer(root) {
        let width = 1usize << usize::from(marker & 0x0F);
        let minimal = if integer < 0 {
            8
        } else if integer <= 0xFF {
            1
        } else if integer <= 0xFFFF {
            2
        } else if integer <= 0xFFFF_FFFF {
            4
        } else {
            8
        };
        Some(width > minimal)
    } else if let Some(uid) = root.as_uid() {
        let width = usize::from(marker & 0x0F) + 1;
        let value = uid.value();
        let minimal = if value <= 0xFF {
            1
        } else if value <= 0xFFFF {
            2
        } else if value <= 0xFF_FFFF {
            3
        } else {
            4
        };
        Some(width > minimal)
    } else {
        None
    }
}

fn string_status_name(status: PlistStringStatus) -> &'static str {
    match status {
        PlistStringStatus::WellFormedUnicode => "WellFormedUnicode",
        PlistStringStatus::UnpairedSurrogate => "UnpairedSurrogate",
    }
}

fn run_binary_formation_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let statuses = expected_sequence(expected, "statuses").ok_or("missing expected.statuses")?;
    let diagnostics =
        expected_sequence(expected, "diagnostics").ok_or("missing expected.diagnostics")?;
    ensure(samples.len() == statuses.len() && samples.len() == diagnostics.len())
        .map_err(|_| "status/diagnostic count mismatch".to_owned())?;
    let integers = expected_sequence(expected, "integers");
    let strings = expected_sequence(expected, "strings");
    let uids = expected_sequence(expected, "uids");
    let mut documents = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        let document = form_sample(case, sample)?;
        let status = statuses[index]
            .as_string()
            .ok_or("status must be a string")?;
        ensure(status_name(document.status()) == status).map_err(|_| {
            format!(
                "sample {index} status {} != {status}",
                status_name(document.status())
            )
        })?;
        if let Some(code) = diagnostics[index].as_string() {
            ensure(document.diagnostics().iter().any(|d| d.code == code))
                .map_err(|_| format!("sample {index} diagnostic {code} not found"))?;
        }
        if status == "Complete" {
            let root = root_value(&document)?;
            if let Some(integers) = integers {
                let expected_value = integers[index].as_integer().and_then(BigInteger::to_i64);
                ensure(value_integer(root) == expected_value)
                    .map_err(|_| format!("sample {index} integer mismatch"))?;
            }
            if let Some(strings) = strings {
                let expected_value = strings[index].as_string().map(str::to_owned);
                ensure(value_text(root) == expected_value)
                    .map_err(|_| format!("sample {index} string mismatch"))?;
            }
            if let Some(uids) = uids {
                let expected_value = uids[index].as_integer().and_then(BigInteger::to_i64);
                let actual_value = root.as_uid().map(|uid| i64::from(uid.value()));
                ensure(actual_value == expected_value)
                    .map_err(|_| format!("sample {index} uid mismatch"))?;
            }
        }
        documents.push(document);
    }
    if let Some(observed) = expected_boolean_field(expected, "non_minimal_width_observed") {
        let actual = documents.iter().any(|document| {
            root_value(document)
                .ok()
                .and_then(|root| width_non_minimal_observed(document, root))
                .unwrap_or(false)
        });
        ensure(actual == observed)
            .map_err(|_| format!("non_minimal_width_observed {actual} != {observed}"))?;
    }
    if expected_string_field(expected, "unpaired_utf16be_hex").is_some()
        || expected_string_field(expected, "unpaired_status").is_some()
    {
        let unpaired = documents
            .iter()
            .find(|document| {
                root_value(document)
                    .ok()
                    .and_then(|root| root.as_string())
                    .is_some_and(|string| string.status() == PlistStringStatus::UnpairedSurrogate)
            })
            .ok_or("no unpaired-surrogate sample")?;
        let root = root_value(unpaired)?;
        let string = root.as_string().ok_or("root is not a string")?;
        if let Some(unpaired_hex) = expected_string_field(expected, "unpaired_utf16be_hex") {
            ensure(hex(&string.utf16be_bytes()) == unpaired_hex)
                .map_err(|_| "unpaired_utf16be_hex mismatch".to_owned())?;
        }
        if let Some(unpaired_status) = expected_string_field(expected, "unpaired_status") {
            ensure(string_status_name(string.status()) == unpaired_status)
                .map_err(|_| "unpaired_status mismatch".to_owned())?;
        }
    }
    if let Some(accepted) = expected_boolean_field(expected, "sort_version_one_accepted") {
        let actual = documents.iter().any(|document| {
            document.status() == FormationStatus::Complete
                && document
                    .binary_facts()
                    .is_some_and(|facts| facts.trailer().sort_version() == 1)
        });
        ensure(actual == accepted)
            .map_err(|_| format!("sort_version_one_accepted {actual} != {accepted}"))?;
    }
    if expected_integer_field(expected, "extended_array_length").is_some()
        || expected_boolean_field(expected, "extended_count_is_object").is_some()
    {
        let document = documents
            .iter()
            .find(|document| document.status() == FormationStatus::Complete)
            .ok_or("no complete sample")?;
        let root = root_value(document)?;
        if let Some(length) = expected_integer_field(expected, "extended_array_length") {
            let array = root.as_array().ok_or("root must be an array")?;
            ensure(array.len() as i64 == length)
                .map_err(|_| format!("extended_array_length {} != {length}", array.len()))?;
        }
        if let Some(count_is_object) = expected_boolean_field(expected, "extended_count_is_object")
        {
            let facts = document.binary_facts().ok_or("missing binary facts")?;
            let marker = facts.objects().first().ok_or("missing object 0")?.marker();
            let extended = (marker & 0x0F) == 0x0F;
            ensure(extended == count_is_object)
                .map_err(|_| "extended_count_is_object mismatch".to_owned())?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

/// Builds the frozen operator vocabulary from one vector filter list.
///
/// The argument-less structure operators (`plist.document-root@1`,
/// `plist.dict-entries@1`, `plist.dict-entry-value@1`, `plist.value-as-*@1`,
/// `plist.object-table@1`, ...) carry no argument; `plist.dict-key-equals@1`
/// names its `key` argument and `plist.value-type-is@1` its `kind` argument.
fn build_filters(filters: &[PortableValue]) -> Result<Vec<OperatorCall>, String> {
    filters
        .iter()
        .map(|filter| {
            let operator = object_value_field(filter, "operator")
                .and_then(PortableValue::as_string)
                .ok_or("missing filter.operator")?;
            let (name, version) = operator
                .split_once('@')
                .ok_or_else(|| format!("operator lacks version: {operator}"))?;
            let version = version
                .parse::<u32>()
                .map_err(|_| format!("invalid operator version: {operator}"))?;
            let mut call = OperatorCall::new(name, version);
            if let Some(argument) =
                object_value_field(filter, "argument").and_then(PortableValue::as_string)
            {
                call = match name {
                    "plist.dict-key-equals" => {
                        call.with_argument("key", PortableValue::string(argument))
                    }
                    "plist.value-type-is" => {
                        call.with_argument("kind", PortableValue::string(argument))
                    }
                    _ => call.with_argument("argument", PortableValue::string(argument)),
                };
            }
            Ok(call)
        })
        .collect()
}

fn execute_native(
    document: &Document,
    calls: &[OperatorCall],
) -> Result<QueryExecution<PlistMatch>, QueryFailure> {
    let mut expression = QueryExpression::Input;
    for call in calls {
        expression = expression.then(call.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("plist.native-semantic-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()?;
    let executable = definition.bind(&capabilities())?;
    execute_plist_native_query(
        &executable,
        document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
}

/// Stable vector spelling of one `QueryFailure` variant.
fn query_failure_code(failure: &QueryFailure) -> &'static str {
    match failure {
        QueryFailure::DomainMismatch(_) => "plist.query.domain-mismatch@1",
        QueryFailure::UnknownOperator { .. } => "plist.query.unknown-operator@1",
        QueryFailure::WrongArgumentType { .. } => "plist.query.wrong-argument-type@1",
        QueryFailure::InvalidArgument { .. } => "plist.query.invalid-argument@1",
        QueryFailure::InvalidOperatorComposition { .. } => "plist.query.invalid-composition@1",
        QueryFailure::MissingRequiredCapability(_) => "plist.query.missing-capability@1",
        QueryFailure::RequiredTypeMismatch { .. } => "plist.query.type-mismatch@1",
        QueryFailure::CardinalityViolation { .. } => "plist.query.cardinality-violation@1",
        QueryFailure::ResourceLimitExceeded => "plist.query.resource-limit@1",
        QueryFailure::Cancelled => "plist.query.cancelled@1",
        QueryFailure::TargetUnavailable => "plist.query.target-unavailable@1",
    }
}

fn run_query(case: &PortableValue) -> Result<(), String> {
    let domain = input_field(case, "domain")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.domain")?;
    match domain {
        "plist.native-semantic-query@1" => run_native_query(case),
        "plist.binary-structure-query@1" => run_binary_structure_query(case),
        other => Err(format!("unknown query domain {other}")),
    }
}

fn dict_entry_keys(matches: &[PlistMatch]) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    for item in matches {
        if let PlistMatch::DictEntry { key, .. } = item {
            keys.push(key.to_unicode().map_err(|_| "key not unicode".to_owned())?);
        }
    }
    Ok(keys)
}

fn duplicate_key_groups(matches: &[PlistMatch]) -> Result<usize, String> {
    let mut counts = HashMap::new();
    for key in dict_entry_keys(matches)? {
        *counts.entry(key).or_insert(0usize) += 1;
    }
    Ok(counts.values().filter(|count| **count > 1).count())
}

/// The value payload of one native-domain match, when it carries one.
fn match_payload(m: &PlistMatch) -> Option<(PlistValueRef, PlistValueKind)> {
    match m {
        PlistMatch::Value { value, kind, .. } => Some((*value, *kind)),
        PlistMatch::DictEntry {
            value, value_kind, ..
        }
        | PlistMatch::ArrayElement {
            value, value_kind, ..
        } => Some((*value, *value_kind)),
        _ => None,
    }
}

fn assert_typed_matches(
    matches: &[PlistMatch],
    expected_matches: &[PortableValue],
    document: &Document,
) -> Result<(), String> {
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let expected_kind = object_value_field(expected_match, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected match kind")?;
        let (value, kind) = match_payload(actual).ok_or("match without value payload")?;
        ensure(kind.as_str() == expected_kind)
            .map_err(|_| format!("kind {} != {expected_kind}", kind.as_str()))?;
        let value = native_document(document)?
            .get(value)
            .ok_or("match value missing")?;
        if let Some(expected_value) = object_value_field(expected_match, "value")
            .and_then(PortableValue::as_integer)
            .and_then(BigInteger::to_i64)
        {
            ensure(value_integer(value) == Some(expected_value))
                .map_err(|_| "typed match integer mismatch".to_owned())?;
        }
        if let Some(expected_seconds) =
            object_value_field(expected_match, "seconds").and_then(expected_f64)
        {
            ensure(value_seconds(value) == Some(expected_seconds))
                .map_err(|_| "typed match date seconds mismatch".to_owned())?;
        }
    }
    Ok(())
}

fn run_native_query(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_native_query_samples(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let document = form_case(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("native-query input must form completely".to_owned());
    }
    let filters = input_field(case, "filters")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.filters")?;
    let calls = build_filters(filters)?;
    let execution =
        execute_native(&document, &calls).map_err(|failure| format!("execute: {failure:?}"))?;
    let terminal =
        expected_string_field(expected, "terminal").ok_or("missing expected.terminal")?;
    ensure(terminal_name(execution.terminal_state()) == terminal).map_err(|_| {
        format!(
            "terminal {} != {terminal}",
            terminal_name(execution.terminal_state())
        )
    })?;
    if let Some(keys) = expected_sequence(expected, "keys") {
        let actual = dict_entry_keys(execution.matches())?;
        assert_strings(&actual, keys, "key")?;
    }
    if let Some(value_types) = expected_sequence(expected, "value_types") {
        let actual: Vec<&str> = execution
            .matches()
            .iter()
            .filter_map(|m| match m {
                PlistMatch::DictEntry { value_kind, .. } => Some(value_kind.as_str()),
                _ => None,
            })
            .collect();
        let expected_types: Vec<&str> = value_types
            .iter()
            .filter_map(PortableValue::as_string)
            .collect();
        ensure(actual == expected_types)
            .map_err(|_| format!("value_types {actual:?} != {expected_types:?}"))?;
    }
    if let Some(groups) = expected_integer_field(expected, "duplicate_groups") {
        let actual = duplicate_key_groups(execution.matches())?;
        ensure(actual as i64 == groups)
            .map_err(|_| format!("duplicate_groups {actual} != {groups}"))?;
    }
    Ok(())
}

fn run_native_query_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let document = form_case(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("native-query input must form completely".to_owned());
    }
    let terminals = expected_sequence(expected, "terminals").ok_or("missing expected.terminals")?;
    ensure(samples.len() == terminals.len()).map_err(|_| "terminal count mismatch".to_owned())?;
    let mismatch_code = expected_string_field(expected, "mismatch_code");
    let integer_matches = expected_sequence(expected, "integer_matches");
    let date_matches = expected_sequence(expected, "date_matches");
    for (index, sample) in samples.iter().enumerate() {
        let filters = object_value_field(sample, "filters")
            .and_then(PortableValue::as_sequence)
            .ok_or("missing sample filters")?;
        let last_operator = filters
            .last()
            .and_then(|filter| object_value_field(filter, "operator"))
            .and_then(PortableValue::as_string)
            .unwrap_or("");
        let calls = build_filters(filters)?;
        let terminal = terminals[index]
            .as_string()
            .ok_or("terminal must be a string")?;
        match terminal {
            "Completed" => {
                let execution = execute_native(&document, &calls)
                    .map_err(|failure| format!("execute: {failure:?}"))?;
                if last_operator == "plist.value-as-integer@1" {
                    if let Some(expected_matches) = integer_matches {
                        assert_typed_matches(execution.matches(), expected_matches, &document)?;
                    }
                } else if last_operator == "plist.value-as-date@1" {
                    if let Some(expected_matches) = date_matches {
                        assert_typed_matches(execution.matches(), expected_matches, &document)?;
                    }
                }
            }
            "Failed" => {
                let Err(failure) = execute_native(&document, &calls) else {
                    return Err("execution must fail".to_owned());
                };
                let expected_code = mismatch_code.as_deref().ok_or("missing mismatch_code")?;
                ensure(query_failure_code(&failure) == expected_code).map_err(|_| {
                    format!(
                        "query failure {} != {expected_code}",
                        query_failure_code(&failure)
                    )
                })?;
            }
            other => return Err(format!("unknown terminal {other}")),
        }
    }
    Ok(())
}

/// Executes one validated binary-structure query against one document.
fn execute_binary_structure(
    calls: &[OperatorCall],
    document: &Document,
) -> Result<QueryExecution<PlistBinaryMatch>, String> {
    let mut expression = QueryExpression::Input;
    for call in calls {
        expression = expression.then(call.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("plist.binary-structure-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()
        .map_err(|failure| format!("definition: {failure:?}"))?;
    let executable = definition
        .bind(&capabilities())
        .map_err(|failure| format!("bind: {failure:?}"))?;
    execute_plist_binary_query(
        &executable,
        document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(|failure| format!("execute: {failure:?}"))
}

fn run_binary_structure_query(case: &PortableValue) -> Result<(), String> {
    let document = form_case(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("binary-structure-query input must form completely".to_owned());
    }
    let filters = input_field(case, "filters")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.filters")?;
    let calls = build_filters(filters)?;
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    let terminal =
        expected_string_field(expected, "terminal").ok_or("missing expected.terminal")?;
    // Composition: the full chain validates, binds, and executes (RFC 0013
    // §8.3) before any fact is asserted.
    let execution = execute_binary_structure(&calls, &document)?;
    ensure(terminal_name(execution.terminal_state()) == terminal).map_err(|_| {
        format!(
            "terminal {} != {terminal}",
            terminal_name(execution.terminal_state())
        )
    })?;
    // Facts: every structure operator projects its document-level fact set
    // once from any binary-structure input match, so each filter is also
    // executed standalone and its facts collected.
    let mut trailer = None;
    let mut objects: Vec<(usize, u8)> = Vec::new();
    let mut offsets: Vec<(usize, usize)> = Vec::new();
    let mut top_marker = None;
    let mut top_refs: Vec<usize> = Vec::new();
    for call in &calls {
        let execution = execute_binary_structure(std::slice::from_ref(call), &document)?;
        for item in execution.matches() {
            match item {
                PlistBinaryMatch::Trailer {
                    sort_version,
                    offset_int_size,
                    object_ref_size,
                    num_objects,
                    top_object,
                    offset_table_offset,
                    ..
                } => {
                    trailer = Some((
                        *sort_version,
                        *offset_int_size,
                        *object_ref_size,
                        *num_objects,
                        *top_object,
                        *offset_table_offset,
                    ));
                }
                PlistBinaryMatch::Object { index, marker, .. } => objects.push((*index, *marker)),
                PlistBinaryMatch::Offset { index, offset, .. } => offsets.push((*index, *offset)),
                PlistBinaryMatch::TopObject { marker, refs, .. } => {
                    top_marker = Some(*marker);
                    top_refs = refs.iter().map(|(_, target, _)| *target).collect();
                }
                _ => {}
            }
        }
    }
    let trailer = trailer.ok_or("missing trailer facts match")?;
    assert_u64_field(expected, "num_objects", trailer.3)?;
    assert_u64_field(expected, "top_object", trailer.4)?;
    assert_u64_field(expected, "offset_int_size", u64::from(trailer.1))?;
    assert_u64_field(expected, "object_ref_size", u64::from(trailer.2))?;
    assert_u64_field(expected, "sort_version", u64::from(trailer.0))?;
    assert_u64_field(expected, "offset_table_offset", trailer.5)?;
    objects.sort_by_key(|(index, _)| *index);
    offsets.sort_by_key(|(index, _)| *index);
    if let Some(object_offsets) = expected_sequence(expected, "object_offsets") {
        let expected_offsets: Vec<i64> = object_offsets
            .iter()
            .filter_map(|value| value.as_integer().and_then(BigInteger::to_i64))
            .collect();
        let actual: Vec<i64> = offsets.iter().map(|(_, offset)| *offset as i64).collect();
        ensure(actual == expected_offsets)
            .map_err(|_| format!("object_offsets {actual:?} != {expected_offsets:?}"))?;
    }
    if let Some(markers) = expected_sequence(expected, "markers") {
        let expected_markers: Vec<&str> = markers
            .iter()
            .filter_map(PortableValue::as_string)
            .collect();
        let actual: Vec<String> = objects
            .iter()
            .map(|(_, marker)| format!("{marker:02x}"))
            .collect();
        ensure(
            actual.len() == expected_markers.len()
                && actual
                    .iter()
                    .zip(expected_markers.iter())
                    .all(|(actual, expected)| actual == expected),
        )
        .map_err(|_| format!("markers {actual:?} != {expected_markers:?}"))?;
    }
    if let Some(marker) = expected_string_field(expected, "top_marker") {
        let actual = top_marker.ok_or("missing top-object match")?;
        ensure(format!("{actual:02x}") == marker)
            .map_err(|_| format!("top_marker {actual:02x} != {marker}"))?;
    }
    if let Some(refs) = expected_sequence(expected, "top_refs") {
        let expected_refs: Vec<i64> = refs
            .iter()
            .filter_map(|value| value.as_integer().and_then(BigInteger::to_i64))
            .collect();
        let actual: Vec<i64> = top_refs.iter().map(|target| *target as i64).collect();
        ensure(actual == expected_refs)
            .map_err(|_| format!("top_refs {actual:?} != {expected_refs:?}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/// Stable kind name of one projected portable value.
fn portable_kind_name(value: &PortableValue) -> Option<&'static str> {
    if value.as_entry_mapping().is_some() {
        Some("dict")
    } else if value.as_sequence().is_some() {
        Some("array")
    } else if value.as_string().is_some() {
        Some("string")
    } else if value.as_integer().is_some() {
        Some("integer")
    } else if value.as_binary_float64().is_some() || value.as_binary_float32().is_some() {
        Some("real")
    } else if value.as_boolean().is_some() {
        Some("boolean")
    } else if value.as_bytes().is_some() {
        Some("data")
    } else if value.as_object().is_some() {
        let object = value.as_object().expect("checked above");
        if object_field(object, "seconds").is_some() {
            Some("date")
        } else if object_field(object, "uid").is_some() {
            Some("uid")
        } else {
            None
        }
    } else {
        None
    }
}

/// Asserts one projected leaf against its `{kind, ...}` expectation.
fn assert_leaf(actual: &PortableValue, expected: &PortableValue) -> Result<(), String> {
    let kind = object_value_field(expected, "kind")
        .and_then(PortableValue::as_string)
        .ok_or("missing leaf kind")?;
    ensure(portable_kind_name(actual) == Some(kind))
        .map_err(|_| format!("leaf kind {:?} != {kind}", portable_kind_name(actual)))?;
    match kind {
        "string" => {
            let text = object_value_field(expected, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing leaf text")?;
            ensure(actual.as_string() == Some(text))
                .map_err(|_| "leaf text mismatch".to_owned())?;
        }
        "integer" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
                .ok_or("missing leaf integer")?;
            let actual_value = actual
                .as_integer()
                .and_then(BigInteger::to_i64)
                .ok_or("actual leaf integer missing")?;
            ensure(actual_value == expected_value)
                .map_err(|_| "leaf integer mismatch".to_owned())?;
        }
        "real" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(expected_f64)
                .ok_or("missing leaf real")?;
            let actual_value = expected_f64(actual).ok_or("actual leaf real missing")?;
            ensure(bits_equal(actual_value, expected_value))
                .map_err(|_| "leaf real mismatch".to_owned())?;
        }
        "boolean" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing leaf boolean")?;
            ensure(actual.as_boolean() == Some(expected_value))
                .map_err(|_| "leaf boolean mismatch".to_owned())?;
        }
        "data" => {
            let expected_hex = object_value_field(expected, "hex")
                .and_then(PortableValue::as_string)
                .ok_or("missing leaf hex")?;
            let actual_hex = actual
                .as_bytes()
                .map(hex)
                .ok_or("actual leaf data missing")?;
            ensure(actual_hex == expected_hex).map_err(|_| "leaf data hex mismatch".to_owned())?;
        }
        "date" => {
            let expected_seconds = object_value_field(expected, "seconds")
                .and_then(expected_f64)
                .ok_or("missing leaf seconds")?;
            let actual_seconds = object_value_field(actual, "seconds")
                .and_then(expected_f64)
                .ok_or("actual leaf date missing")?;
            ensure(bits_equal(actual_seconds, expected_seconds))
                .map_err(|_| "leaf date seconds mismatch".to_owned())?;
        }
        other => return Err(format!("unknown leaf kind {other}")),
    }
    Ok(())
}

fn run_projection(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_projection_samples(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let document = form_case(case)?;
    let result = project_plist(&document, PlistProjectionRequest::value_tree());
    let PlistProjectionResult::Complete(projection) = result else {
        return Err("projection must complete".to_owned());
    };
    if let Some(record) = expected_string_field(expected, "record") {
        let actual = object_value_field(&projection.value, "record")
            .and_then(PortableValue::as_string)
            .ok_or("missing record member")?;
        ensure(actual == record).map_err(|_| format!("record {actual} != {record}"))?;
    }
    let root = object_value_field(&projection.value, "root").ok_or("missing root member")?;
    if let Some(kind) = expected_string_field(expected, "root_kind") {
        ensure(portable_kind_name(root) == Some(kind.as_str()))
            .map_err(|_| format!("root_kind {:?} != {kind}", portable_kind_name(root)))?;
    }
    if let Some(keys) = expected_sequence(expected, "keys") {
        let mapping = root
            .as_entry_mapping()
            .ok_or("root must be an entry mapping")?;
        let actual: Vec<&str> = mapping
            .iter()
            .filter_map(|entry| entry.key().as_string())
            .collect();
        let expected_keys: Vec<&str> = keys.iter().filter_map(PortableValue::as_string).collect();
        ensure(actual == expected_keys)
            .map_err(|_| format!("keys {actual:?} != {expected_keys:?}"))?;
    }
    if let Some(leaves) = object_value_field(expected, "leaves") {
        let leaves = leaves.as_object().ok_or("leaves must be an object")?;
        let mapping = root
            .as_entry_mapping()
            .ok_or("root must be an entry mapping")?;
        for leaf in leaves {
            let entry = mapping
                .iter()
                .find(|entry| entry.key().as_string() == Some(leaf.key()))
                .ok_or_else(|| format!("leaf entry {} missing", leaf.key()))?;
            assert_leaf(entry.value(), leaf.value())?;
        }
    }
    if let Some(array_leaves) = object_value_field(expected, "array_leaves") {
        let array_leaves = array_leaves
            .as_object()
            .ok_or("array_leaves must be an object")?;
        let mapping = root
            .as_entry_mapping()
            .ok_or("root must be an entry mapping")?;
        for leaf in array_leaves {
            let entry = mapping
                .iter()
                .find(|entry| entry.key().as_string() == Some(leaf.key()))
                .ok_or_else(|| format!("array leaf entry {} missing", leaf.key()))?;
            let elements = entry
                .value()
                .as_sequence()
                .ok_or("array leaf must be a sequence")?;
            let expected_elements = leaf
                .value()
                .as_sequence()
                .ok_or("expected array leaf must be a sequence")?;
            ensure(elements.len() == expected_elements.len()).map_err(|_| {
                format!(
                    "array leaf count {} != {}",
                    elements.len(),
                    expected_elements.len()
                )
            })?;
            for (element, expected_element) in elements.iter().zip(expected_elements.iter()) {
                let expected_text = expected_element
                    .as_string()
                    .ok_or("array leaf element must be a string")?;
                ensure(element.as_string() == Some(expected_text))
                    .map_err(|_| "array leaf element mismatch".to_owned())?;
            }
        }
    }
    if let Some(preserved) = expected_boolean_field(expected, "association_order_preserved") {
        ensure(preserved).map_err(|_| "association order not preserved".to_owned())?;
    }
    Ok(())
}

fn run_projection_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let fidelities = expected_sequence(expected, "fidelities");
    let codes = expected_sequence(expected, "codes");
    let events_after_first = expected_integer_field(expected, "events_after_first").unwrap_or(0);
    let mut first_completed_checked = false;
    for (index, sample) in samples.iter().enumerate() {
        let document = form_sample(case, sample)?;
        let request = match object_value_field(sample, "collision_policy")
            .and_then(PortableValue::as_string)
        {
            Some("Reject") => PlistProjectionRequest::require_object(CollisionPolicy::Reject),
            Some("First") => PlistProjectionRequest::require_object(CollisionPolicy::First),
            Some("Last") => PlistProjectionRequest::require_object(CollisionPolicy::Last),
            _ => PlistProjectionRequest::value_tree(),
        };
        let result = project_plist(&document, request);
        if let Some(fidelities) = fidelities {
            let expected_fidelity = fidelities[index]
                .as_string()
                .ok_or("fidelity must be a string")?;
            let fidelity_ok = matches!(
                (&result, expected_fidelity),
                (PlistProjectionResult::Failed(_), "Failed")
                    | (PlistProjectionResult::Complete(_), "Transformed" | "Exact")
            );
            ensure(fidelity_ok)
                .map_err(|_| format!("projection fidelity != {expected_fidelity}"))?;
        }
        if let Some(codes) = codes {
            if let Some(expected_code) = codes[index].as_string() {
                let PlistProjectionResult::Failed(attempt) = &result else {
                    return Err("projection must fail".to_owned());
                };
                let code = attempt
                    .diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.code.as_str())
                    .ok_or("projection failure without diagnostics")?;
                ensure(code == expected_code)
                    .map_err(|_| format!("projection code {code} != {expected_code}"))?;
            }
        }
        if let PlistProjectionResult::Complete(projection) = &result {
            if !first_completed_checked {
                first_completed_checked = true;
                if let Some(first_sample) = object_value_field(expected, "first_sample") {
                    let keys = object_value_field(first_sample, "keys")
                        .and_then(PortableValue::as_sequence)
                        .ok_or("missing first_sample keys")?;
                    let values = object_value_field(first_sample, "values")
                        .and_then(PortableValue::as_sequence)
                        .ok_or("missing first_sample values")?;
                    let object = projection
                        .value
                        .as_object()
                        .ok_or("require-object projection must be an object")?;
                    ensure(object.len() == keys.len())
                        .map_err(|_| "first_sample key count mismatch".to_owned())?;
                    for (entry, (expected_key, expected_value)) in
                        object.iter().zip(keys.iter().zip(values.iter()))
                    {
                        let expected_key = expected_key
                            .as_string()
                            .ok_or("expected key must be a string")?;
                        let expected_value = expected_value
                            .as_string()
                            .ok_or("expected value must be a string")?;
                        ensure(entry.key() == expected_key)
                            .map_err(|_| format!("key {} != {expected_key}", entry.key()))?;
                        ensure(entry.value().as_string() == Some(expected_value))
                            .map_err(|_| format!("value of {expected_key} mismatch"))?;
                    }
                }
                if events_after_first > 0 {
                    let events = projection
                        .report
                        .events()
                        .iter()
                        .filter(|event| event.kind == ProjectionEventKind::AssociationDiscarded)
                        .count();
                    ensure(events as i64 == events_after_first)
                        .map_err(|_| format!("events {events} != {events_after_first}"))?;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Materialization
// ---------------------------------------------------------------------------

fn materialization_request(style: &str) -> Result<MaterializationRequest, String> {
    match style {
        "plist.xml-canonical@1" => Ok(MaterializationRequest::new(
            ProfileId::new("plist.xml", 1),
            MaterializationStyleId::new("plist.xml-canonical", 1),
        )),
        "plist.binary-canonical@1" => Ok(MaterializationRequest::new(
            ProfileId::new("plist.binary", 1),
            MaterializationStyleId::new("plist.binary-canonical", 1),
        )
        .with_encoding(SourceEncoding::Binary)
        .with_newline(NewlinePolicy::None)),
        other => Err(format!("unknown materialization style {other}")),
    }
}

/// Stable vector spelling of one `MaterializationFailure` variant.
fn materialization_failure_code(failure: &MaterializationFailure) -> &'static str {
    match failure {
        MaterializationFailure::Unrepresentable { kind, .. }
            if *kind == consema_core::PortableValueKind::Date =>
        {
            "plist.materialization.fractional-date@1"
        }
        MaterializationFailure::Unrepresentable { .. } => "plist.materialization.unrepresentable@1",
        MaterializationFailure::ResourceLimit(_) => "plist.materialization.resource-limit@1",
        MaterializationFailure::InvalidRequest(_) => "core.materialization.invalid-request@1",
        MaterializationFailure::UnsupportedProfile => "core.materialization.unsupported-profile@1",
        MaterializationFailure::UnsupportedStyle => "core.materialization.unsupported-style@1",
        MaterializationFailure::UnsupportedEncoding => {
            "core.materialization.unsupported-encoding@1"
        }
        MaterializationFailure::UnsupportedNewline => "core.materialization.unsupported-newline@1",
        MaterializationFailure::FormationFailed => "core.materialization.formation-failed@1",
    }
}

fn complete_materialization(
    record: &PortableValue,
    request: &MaterializationRequest,
) -> Result<CompleteMaterialization<Document>, String> {
    match materialize(record, request) {
        MaterializationResult::Complete(complete) => Ok(complete),
        MaterializationResult::Failed(attempt) => {
            Err(format!("materialization failed: {:?}", attempt.failure))
        }
    }
}

/// Counts the scalar (non-container) objects of one binary document.
fn scalar_objects(document: &Document) -> usize {
    let Some(facts) = document.binary_facts() else {
        return 0;
    };
    facts
        .objects()
        .iter()
        .filter(|object| {
            let marker = object.marker();
            !(0xA0..=0xAF).contains(&marker) && !(0xD0..=0xDF).contains(&marker)
        })
        .count()
}

fn run_materialization(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_materialization_samples(
            samples.as_sequence().ok_or("samples must be a sequence")?,
            case,
            expected,
        );
    }
    let style = input_field(case, "style")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.style")?;
    let record = input_field(case, "record").ok_or("missing input.record")?;
    let request = materialization_request(style)?;
    let complete = complete_materialization(record, &request)?;
    if expected_boolean_field(expected, "closure").unwrap_or(false) {
        ensure(complete.document.status() == FormationStatus::Complete)
            .map_err(|_| "materialized document must be complete".to_owned())?;
    }
    if let Some(render) = expected_string_field(expected, "render") {
        let actual = std::str::from_utf8(complete.document.render())
            .map_err(|_| "render is not UTF-8".to_owned())?;
        ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
    }
    if let Some(hex_expected) = expected_string_field(expected, "render_hex") {
        ensure(hex(complete.document.render()) == hex_expected)
            .map_err(|_| "render_hex mismatch".to_owned())?;
    }
    Ok(())
}

fn run_materialization_samples(
    samples: &[PortableValue],
    case: &PortableValue,
    expected: &PortableValue,
) -> Result<(), String> {
    let canonical_hex = expected_string_field(expected, "canonical_hex");
    let conversion_render = expected_string_field(expected, "conversion_render");
    let closure = expected_boolean_field(expected, "closure").unwrap_or(false);
    let representation_change =
        expected_boolean_field(expected, "representation_change_reported").unwrap_or(false);
    let mut deduplicated = expected_integer_field(expected, "deduplicated_scalars");
    let renders = expected_sequence(expected, "renders");
    let codes = expected_sequence(expected, "codes");
    let truncation_events = expected_integer_field(expected, "truncation_events").unwrap_or(0);
    for (index, sample) in samples.iter().enumerate() {
        let style = match object_value_field(sample, "style").and_then(PortableValue::as_string) {
            Some(style) => style,
            None => input_field(case, "style")
                .and_then(PortableValue::as_string)
                .ok_or("missing sample style")?,
        };
        if let Some(record) = object_value_field(sample, "record") {
            let record = match object_value_field(sample, "truncate_policy") {
                Some(policy) => {
                    let mut builder = ObjectBuilder::new();
                    let object = record.as_object().ok_or("record must be an object")?;
                    for entry in object {
                        builder
                            .insert(entry.key(), entry.value().clone())
                            .map_err(|_| "record insert".to_owned())?;
                    }
                    builder
                        .insert("truncate_policy", policy.clone())
                        .map_err(|_| "record insert".to_owned())?;
                    builder.build()
                }
                None => record.clone(),
            };
            let request = materialization_request(style)?;
            match materialize(&record, &request) {
                MaterializationResult::Complete(complete) => {
                    if let Some(renders) = renders {
                        let expected_render = renders[index]
                            .as_string()
                            .ok_or("expected render must be a string")?;
                        let actual = std::str::from_utf8(complete.document.render())
                            .map_err(|_| "render is not UTF-8".to_owned())?;
                        ensure(actual == expected_render)
                            .map_err(|_| format!("render {actual:?} != {expected_render:?}"))?;
                    }
                    if truncation_events > 0 {
                        let events = complete
                            .report
                            .events()
                            .iter()
                            .filter(|diagnostic| {
                                diagnostic.code == "plist.materialization.fractional-date@1"
                            })
                            .count();
                        ensure(events as i64 == truncation_events).map_err(|_| {
                            format!("truncation events {events} != {truncation_events}")
                        })?;
                    }
                    if closure {
                        ensure(complete.document.status() == FormationStatus::Complete)
                            .map_err(|_| "materialized document must be complete".to_owned())?;
                    }
                }
                MaterializationResult::Failed(attempt) => {
                    if let Some(codes) = codes {
                        let expected_code = codes[index]
                            .as_string()
                            .ok_or("expected code must be a string")?;
                        ensure(materialization_failure_code(&attempt.failure) == expected_code)
                            .map_err(|_| {
                                format!(
                                    "materialization failure {} != {expected_code}",
                                    materialization_failure_code(&attempt.failure)
                                )
                            })?;
                    } else {
                        return Err("materialization must complete".to_owned());
                    }
                }
            }
            continue;
        }
        // Source-document samples: normalization materializes the projected
        // record directly (the projected `plist.value-tree@1` record is the
        // materialization input, RFC 0013 §9, §10), conversion crosses the
        // representation boundary.
        let document = form_value(sample)?;
        if style == "plist.binary-canonical@1" {
            let projection = project_plist(&document, PlistProjectionRequest::value_tree());
            let PlistProjectionResult::Complete(projection) = projection else {
                return Err("projection must complete".to_owned());
            };
            let request = materialization_request(style)?;
            let complete = complete_materialization(&projection.value, &request)?;
            if let Some(canonical_hex) = &canonical_hex {
                ensure(hex(complete.document.render()) == *canonical_hex)
                    .map_err(|_| "canonical_hex mismatch".to_owned())?;
            }
            if let Some(deduplicated) = &mut deduplicated {
                let base_scalars = scalar_objects(&document);
                let committed_scalars = scalar_objects(&complete.document);
                let actual = base_scalars.saturating_sub(committed_scalars) as i64;
                ensure(actual == *deduplicated)
                    .map_err(|_| format!("deduplicated_scalars {actual} != {deduplicated}"))?;
            }
            if closure {
                ensure(complete.document.status() == FormationStatus::Complete)
                    .map_err(|_| "materialized document must be complete".to_owned())?;
            }
        } else {
            let converted = document
                .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
                .map_err(|failure| format!("{failure:?}"))?;
            if let Some(conversion_render) = &conversion_render {
                let actual = std::str::from_utf8(converted.document().render())
                    .map_err(|_| "render is not UTF-8".to_owned())?;
                ensure(actual == conversion_render)
                    .map_err(|_| format!("render {actual:?} != {conversion_render:?}"))?;
            }
            if representation_change {
                ensure(converted.report().representation_changed())
                    .map_err(|_| "representation change not reported".to_owned())?;
            }
            if closure {
                ensure(converted.document().status() == FormationStatus::Complete)
                    .map_err(|_| "converted document must be complete".to_owned())?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/// Stable vector spelling of one atomic `ConversionFailure`: the code of its
/// first ordered diagnostic (RFC 0013 §7, hard gate 3).
fn conversion_failure_code(failure: &ConversionFailure) -> &str {
    failure
        .diagnostics()
        .first()
        .map(|diagnostic| diagnostic.code.as_str())
        .unwrap_or_default()
}

fn run_conversion(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    let document = form_case(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("conversion input must form completely".to_owned());
    }
    let target = match expected_string_field(expected, "target").as_deref() {
        Some("plist.binary@1") => PlistProfile::BinaryV1,
        Some("plist.xml@1") => PlistProfile::XmlV1,
        Some(other) => return Err(format!("unknown target profile {other}")),
        None => return Err("missing expected.target".to_owned()),
    };
    match document.convert_to(target, PlistParseLimits::default()) {
        Ok(converted) => {
            if expected_string_field(expected, "code").is_some() {
                return Err("conversion must fail".to_owned());
            }
            if expected_boolean_field(expected, "representation_change_reported").unwrap_or(false) {
                ensure(converted.report().representation_changed())
                    .map_err(|_| "representation change not reported".to_owned())?;
            }
            if expected_boolean_field(expected, "closure").unwrap_or(false) {
                ensure(converted.document().status() == FormationStatus::Complete)
                    .map_err(|_| "converted document must be complete".to_owned())?;
            }
            if expected_boolean_field(expected, "round_trip").unwrap_or(false) {
                // Reparse closure across the boundary (RFC 0013 §7): the
                // target converted back under the source profile must carry
                // the exact source native model.
                let back = converted
                    .document()
                    .convert_to(profile_of(case)?, PlistParseLimits::default())
                    .map_err(|failure| format!("{failure:?}"))?;
                ensure(native_document(&document)? == native_document(back.document())?)
                    .map_err(|_| "round-trip native model mismatch".to_owned())?;
            }
            if let Some(keys) = expected_sequence(expected, "dict_keys") {
                let converted_document = converted.document();
                let actual = dict_keys_of(converted_document, root_value(converted_document)?)?;
                assert_strings(&actual, keys, "key")?;
            }
            Ok(())
        }
        Err(failure) => {
            let code = expected_string_field(expected, "code")
                .ok_or("conversion must complete".to_owned())?;
            let actual = conversion_failure_code(&failure);
            ensure(actual == code).map_err(|_| format!("conversion failure {actual} != {code}"))?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

fn edit_path(operation: &PortableValue) -> Result<EditPath, String> {
    let path = object_value_field(operation, "path")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing path")?;
    let mut steps = Vec::new();
    for element in path {
        if let Some(key) = element.as_string() {
            steps.push(EditPathStep::DictKey {
                key: PlistKey::from_unicode(key),
                occurrence: 0,
            });
        } else if let Some(index) = element.as_integer().and_then(BigInteger::to_usize) {
            steps.push(EditPathStep::ArrayIndex(index));
        } else {
            return Err("path step must be a string or integer".to_owned());
        }
    }
    Ok(EditPath::new(steps))
}

/// The operation target path: an explicit `path` sequence, or the `dict` /
/// `array` key name of one root-level container.
fn operation_path(operation: &PortableValue) -> Result<EditPath, String> {
    if object_value_field(operation, "path").is_some() {
        edit_path(operation)
    } else if let Some(name) =
        object_value_field(operation, "dict").and_then(PortableValue::as_string)
    {
        Ok(EditPath::new(vec![EditPathStep::DictKey {
            key: PlistKey::from_unicode(name),
            occurrence: 0,
        }]))
    } else if let Some(name) =
        object_value_field(operation, "array").and_then(PortableValue::as_string)
    {
        Ok(EditPath::new(vec![EditPathStep::DictKey {
            key: PlistKey::from_unicode(name),
            occurrence: 0,
        }]))
    } else {
        Err("missing operation path".to_owned())
    }
}

fn edit_value(value: &PortableValue) -> Result<EditValue, String> {
    let kind = object_value_field(value, "kind")
        .and_then(PortableValue::as_string)
        .ok_or("missing value kind")?;
    match kind {
        "string" => {
            let text = object_value_field(value, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing text")?;
            Ok(EditValue::String(PlistString::from_unicode(text)))
        }
        "integer" => {
            let payload = object_value_field(value, "value")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
                .ok_or("missing integer value")?;
            Ok(EditValue::Integer(PlistInteger::new(payload)))
        }
        "real" => {
            let payload = object_value_field(value, "value")
                .and_then(expected_f64)
                .ok_or("missing real value")?;
            Ok(EditValue::Real(PlistReal::double(payload)))
        }
        "boolean" => {
            let payload = object_value_field(value, "value")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing boolean value")?;
            Ok(EditValue::Boolean(PlistBoolean::new(payload)))
        }
        "date" => {
            let seconds = object_value_field(value, "seconds")
                .and_then(expected_f64)
                .ok_or("missing date seconds")?;
            let date = PlistDate::from_seconds(seconds).map_err(|error| format!("{error:?}"))?;
            Ok(EditValue::Date(date))
        }
        "data" => {
            let text = object_value_field(value, "hex")
                .and_then(PortableValue::as_string)
                .ok_or("missing data hex")?;
            Ok(EditValue::Data(PlistData::from_bytes(Arc::<[u8]>::from(
                decode_hex(text)?,
            ))))
        }
        "uid" => {
            let payload = object_value_field(value, "value")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
                .ok_or("missing uid value")?;
            let value = u32::try_from(payload).map_err(|_| "uid out of range".to_owned())?;
            Ok(EditValue::Uid(PlistUid::new(value)))
        }
        other => Err(format!("unknown value kind {other}")),
    }
}

fn dict_placement(operation: &PortableValue) -> Result<DictPlacement, String> {
    match object_value_field(operation, "placement")
        .and_then(PortableValue::as_string)
        .unwrap_or("End")
    {
        "End" => Ok(DictPlacement::End),
        other => Err(format!("unknown placement {other}")),
    }
}

fn build_transaction(
    document: &Document,
    operations: &[PortableValue],
) -> Result<EditTransaction, String> {
    let mut builder = EditTransactionBuilder::new(document);
    for operation in operations {
        let op = object_value_field(operation, "op")
            .and_then(PortableValue::as_string)
            .ok_or("missing op")?;
        match op {
            "plist.edit.set-value@1" => {
                let path = edit_path(operation)?;
                let value =
                    edit_value(object_value_field(operation, "value").ok_or("missing value")?)?;
                builder.set_value(path, value);
            }
            "plist.edit.insert-dict-entry@1" => {
                let path = operation_path(operation)?;
                let key = PlistKey::from_unicode(
                    object_value_field(operation, "key")
                        .and_then(PortableValue::as_string)
                        .ok_or("missing key")?,
                );
                let value =
                    edit_value(object_value_field(operation, "value").ok_or("missing value")?)?;
                let placement = dict_placement(operation)?;
                builder.insert_dict_entry(path, key, value, placement);
            }
            "plist.edit.remove-dict-entry@1" => {
                let path = operation_path(operation)?;
                let key = PlistKey::from_unicode(
                    object_value_field(operation, "key")
                        .and_then(PortableValue::as_string)
                        .ok_or("missing key")?,
                );
                builder.remove_dict_entry(path, key, 0);
            }
            "plist.edit.rename-dict-key@1" => {
                let path = operation_path(operation)?;
                let from = PlistKey::from_unicode(
                    object_value_field(operation, "from")
                        .and_then(PortableValue::as_string)
                        .ok_or("missing from")?,
                );
                let to = PlistKey::from_unicode(
                    object_value_field(operation, "to")
                        .and_then(PortableValue::as_string)
                        .ok_or("missing to")?,
                );
                builder.rename_dict_key(path, from, 0, to);
            }
            "plist.edit.insert-array-element@1" => {
                let path = operation_path(operation)?;
                let index = operation_usize(operation, "index")?;
                let value =
                    edit_value(object_value_field(operation, "value").ok_or("missing value")?)?;
                builder.insert_array_element(path, index, value);
            }
            "plist.edit.remove-array-element@1" => {
                let path = operation_path(operation)?;
                let index = operation_usize(operation, "index")?;
                builder.remove_array_element(path, index);
            }
            other => return Err(format!("unknown edit op {other}")),
        }
    }
    Ok(builder.build())
}

fn operation_usize(operation: &PortableValue, name: &str) -> Result<usize, String> {
    object_value_field(operation, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("missing {name}"))
}

/// Reparses one committed document under its own profile.
fn reparse(document: &Document) -> Result<Document, String> {
    let profile = if document.profile().id() == "plist.xml" {
        PlistProfile::XmlV1
    } else {
        PlistProfile::BinaryV1
    };
    parse_plist(
        Arc::from(document.render().to_vec()),
        profile,
        PlistEncodingSelection::ProfileDefault,
        PlistParseLimits::default(),
    )
    .map_err(|failure| format!("reparse: {failure:?}"))
}

/// Asserts the vector facts of one committed edit's native model.
fn assert_edit_native(expected: &PortableValue, committed: &Document) -> Result<(), String> {
    let root = root_value(committed)?;
    if let Some(kind) = expected_string_field(expected, "top_kind") {
        ensure(value_kind_name(root) == kind)
            .map_err(|_| format!("top_kind {} != {kind}", value_kind_name(root)))?;
    }
    if let Some(keys) = expected_sequence(expected, "dict_a_keys") {
        let dict_a = entry_by_key(committed, root, "a")?;
        let actual = dict_keys_of(committed, dict_a)?;
        assert_strings(&actual, keys, "key")?;
    }
    if let Some(values) = expected_sequence(expected, "dict_a_values") {
        let dict_a = entry_by_key(committed, root, "a")?;
        let entries = dict_entries(dict_a)?;
        ensure(entries.len() == values.len())
            .map_err(|_| format!("value count {} != {}", entries.len(), values.len()))?;
        for (entry, expected_value) in entries.iter().zip(values.iter()) {
            let value = native_document(committed)?
                .get(entry.value())
                .ok_or("entry value missing")?;
            compare_scalar_value(value, expected_value)?;
        }
    }
    if let Some(elements) = expected_sequence(expected, "arr_elements") {
        let array = entry_by_key(committed, root, "arr")?;
        let array = array.as_array().ok_or("arr must be an array")?;
        ensure(array.len() == elements.len())
            .map_err(|_| format!("array count {} != {}", array.len(), elements.len()))?;
        for (reference, expected_element) in array.elements().iter().zip(elements.iter()) {
            let value = native_document(committed)?
                .get(*reference)
                .ok_or("element missing")?;
            compare_scalar_value(value, expected_element)?;
        }
    }
    if let Some(elements) = expected_sequence(expected, "elements") {
        let array = root.as_array().ok_or("root must be an array")?;
        ensure(array.len() == elements.len())
            .map_err(|_| format!("array count {} != {}", array.len(), elements.len()))?;
        for (reference, expected_element) in array.elements().iter().zip(elements.iter()) {
            let value = native_document(committed)?
                .get(*reference)
                .ok_or("element missing")?;
            compare_scalar_value(value, expected_element)?;
        }
    }
    if let Some(kinds) = expected_sequence(expected, "element_kinds") {
        let array = root.as_array().ok_or("root must be an array")?;
        ensure(array.len() == kinds.len())
            .map_err(|_| format!("array count {} != {}", array.len(), kinds.len()))?;
        for (reference, expected_kind) in array.elements().iter().zip(kinds.iter()) {
            let value = native_document(committed)?
                .get(*reference)
                .ok_or("element missing")?;
            let expected_kind = expected_kind.as_string().ok_or("kind must be a string")?;
            ensure(value_kind_name(value) == expected_kind).map_err(|_| {
                format!("element kind {} != {expected_kind}", value_kind_name(value))
            })?;
        }
    }
    Ok(())
}

/// Verifies that every untouched-byte region of one commit is byte-exact
/// (untouched objects keep their exact bytes, RFC 0013 §11).
fn assert_untouched_object_bytes(
    document: &Document,
    commit: &consema_plist::EditCommit,
) -> Result<(), String> {
    for region in commit.untouched_proof.regions() {
        let base = &document.source().bytes()[region.old_start()..region.old_end()];
        let target = &commit.document.source().bytes()[region.new_start()..region.new_end()];
        ensure(base == target).map_err(|_| "untouched region content changed".to_owned())?;
    }
    Ok(())
}

fn run_edit(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_edit_conflicts(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let document = form_case(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("edit input must form completely".to_owned());
    }
    let operations = input_field(case, "operations")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.operations")?;
    let transaction = build_transaction(&document, operations)?;
    let commit = document
        .commit(&transaction)
        .map_err(|failure| format!("{failure:?}"))?;
    let committed = &commit.document;
    ensure(committed.status() == FormationStatus::Complete)
        .map_err(|_| "committed document must be complete".to_owned())?;
    if expected_boolean_field(expected, "reparse_closure").unwrap_or(false) {
        ensure(reparse(committed)?.status() == FormationStatus::Complete)
            .map_err(|_| "committed document must reparse completely".to_owned())?;
    }
    if expected_boolean_field(expected, "patch_replays").unwrap_or(false) {
        let replay = commit
            .source_patch
            .apply(document.source(), SourcePatchLimits::default())
            .map_err(|error| format!("patch apply: {error:?}"))?;
        ensure(replay.bytes() == committed.render())
            .map_err(|_| "patch does not replay".to_owned())?;
    }
    if expected_boolean_field(expected, "untouched_byte_proof").unwrap_or(false)
        || expected_boolean_field(expected, "untouched_object_bytes").unwrap_or(false)
    {
        commit
            .untouched_proof
            .verify(
                document.source(),
                committed.source(),
                commit.source_patch.replacements(),
            )
            .map_err(|error| format!("untouched proof: {error:?}"))?;
    }
    if expected_boolean_field(expected, "untouched_object_bytes").unwrap_or(false) {
        assert_untouched_object_bytes(&document, &commit)?;
    }
    assert_edit_native(expected, committed)?;
    Ok(())
}

fn run_edit_conflicts(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let codes = expected_sequence(expected, "codes").ok_or("missing expected.codes")?;
    let base_unchanged = expected_boolean_field(expected, "base_unchanged").unwrap_or(false);
    ensure(samples.len() == codes.len()).map_err(|_| "code count mismatch".to_owned())?;
    for (index, sample) in samples.iter().enumerate() {
        let document = form_sample(case, sample)?;
        let operations = object_value_field(sample, "operations")
            .and_then(PortableValue::as_sequence)
            .ok_or("missing operations")?;
        let transaction = if let Some(wrong) = object_value_field(sample, "wrong_source") {
            // The transaction is bound to another document's snapshot.
            let other = form_value(wrong)?;
            build_transaction(&other, operations)?
        } else {
            build_transaction(&document, operations)?
        };
        let Err(failure) = document.commit(&transaction) else {
            return Err("edit must fail".to_owned());
        };
        let expected_code = codes[index]
            .as_string()
            .ok_or("expected code must be a string")?;
        ensure(failure.diagnostic_code() == expected_code).map_err(|_| {
            format!(
                "edit failure {} != {expected_code}",
                failure.diagnostic_code()
            )
        })?;
        if base_unchanged {
            ensure(document.render() == document.source().bytes())
                .map_err(|_| "base document changed".to_owned())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_v1_suite_passes_fully() {
        let report = run_plist_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 45);
    }

    #[test]
    fn plist_suite_identifier_is_checked() {
        let changed = PLIST_V1_VECTORS_JSON.replace(
            "\"suite\": \"consema.plist.conformance@1\"",
            "\"suite\": \"unexpected.suite@1\"",
        );
        let report = run_plist_v1_json(&changed);
        assert!(
            report.failed.iter().any(|(id, _)| id == "suite.schema"),
            "{report:#?}"
        );
        assert!(report.passed.is_empty());
    }

    #[test]
    fn binary_structure_offset_table_offset_is_the_exact_trailer_field() {
        // The published expectation records the exact trailer field (0x0F);
        // a stale expectation must fail its case.
        let changed = PLIST_V1_VECTORS_JSON.replace(
            "\"offset_table_offset\": 15,",
            "\"offset_table_offset\": 16,",
        );
        let report = run_plist_v1_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "plist.query.binary-structure"),
            "{report:#?}"
        );
    }
}
