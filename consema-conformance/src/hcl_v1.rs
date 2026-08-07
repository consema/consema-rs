//! Shared language-neutral `consema.hcl.conformance@1` runner.
//!
//! The HCL family owns two profiles over one grammar and one native semantic
//! model (RFC 0014 §1, §6), so formation dispatches on `input.profile` —
//! `hcl.native@1` and `hcl.tfvars@1` — while query, projection,
//! materialization, edit, and limit share the `hcl.*` capability vocabulary
//! of the plan's §M9. Every expected fact is asserted against the frozen
//! vector data: the runner is the sole authority executing the vectors.

use super::{ConformanceReport, ensure, object_field};
use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, OperatorCall, PortableValue,
    PortableValueKind, QueryDefinition, QueryDomain, QueryExecution, QueryExpression, QueryFailure,
    QueryLimits, QuerySelection, StableFailure,
};
use consema_document::{
    EditPlanSourceId, FatalFormationFailure, FormationStatus, MaterializationFailure,
    MaterializationRequest, MaterializationResult, MaterializationStyleId, ParseLimits, ProfileId,
    SourcePatchLimits,
};
use consema_hcl::{
    BodyPath, BodyPlacement, Document, EditCommit, EditKey, EditTransactionBuilder, EditValue,
    ExpressionPolicy, HclAttribute, HclBlockLabel, HclBody, HclBodyItem, HclEncodingSelection,
    HclExpression, HclLiteralValue, HclMatch, HclParseLimits, HclProfile, HclSyntaxMatch, NodeRef,
    ProjectionEventKind, ProjectionRequest, ProjectionResult, execute_hcl_native_query,
    execute_hcl_syntax_query, is_literal_complete, literal_value, materialize, parse as parse_hcl,
    project as project_hcl,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult as JsonProjectionResult,
    ProjectionTarget, parse as parse_json,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Frozen suite identifier expected in every HCL vector file.
const SUITE: &str = "consema.hcl.conformance@1";

/// Embedded shared HCL suite bytes.
pub const HCL_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/hcl-v1.json");

/// Runs the embedded `consema.hcl.conformance@1` suite.
#[must_use]
pub fn run_hcl_v1() -> ConformanceReport {
    run_hcl_v1_json(HCL_V1_VECTORS_JSON)
}

/// Runs one HCL suite from JSON text.
#[must_use]
pub fn run_hcl_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse_json(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published HCL vector JSON must form a document");
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
    let root = value.as_object().expect("HCL vector root object");
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
        "hcl.native-formation@1" => run_native_formation(case),
        "hcl.tfvars-formation@1" => run_tfvars_formation(case),
        "hcl.query@1" => run_query(case),
        "hcl.projection@1" => run_projection(case),
        "hcl.materialization@1" => run_materialization(case),
        "hcl.edit@1" => run_edit(case),
        "hcl.limit@1" => run_limit(case),
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

/// Converts one exact decimal to its double value; `None` when the
/// coefficient or exponent exceeds the exact `i64` range.
#[allow(clippy::cast_precision_loss)]
fn decimal_to_f64(decimal: &consema_core::Decimal) -> Option<f64> {
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

fn status_name(status: FormationStatus) -> &'static str {
    match status {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    }
}

fn terminal_name(terminal: consema_core::QueryTerminalState) -> &'static str {
    match terminal {
        consema_core::QueryTerminalState::Completed => "Completed",
        consema_core::QueryTerminalState::Cancelled => "Cancelled",
        consema_core::QueryTerminalState::Failed => "Failed",
    }
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

// ---------------------------------------------------------------------------
// Formation
// ---------------------------------------------------------------------------

/// One vector fact from a value or its `input` member: samples carry their
/// facts at the top level, case-level inputs wrap them under `input`.
fn vector_field<'v>(value: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    object_value_field(value, name).or_else(|| input_field(value, name))
}

fn profile_of(value: &PortableValue) -> Result<HclProfile, String> {
    match vector_field(value, "profile").and_then(PortableValue::as_string) {
        Some("hcl.native@1") => Ok(HclProfile::NativeV1),
        Some("hcl.tfvars@1") => Ok(HclProfile::TfvarsV1),
        Some(other) => Err(format!("unknown profile {other}")),
        None => Err("missing profile".to_owned()),
    }
}

/// Raw source bytes of one vector input or sample: `source` UTF-8 text, or
/// `hex` raw bytes (the invalid-UTF-8 fatal sample of the source contract).
fn source_bytes(value: &PortableValue) -> Result<Arc<[u8]>, String> {
    if let Some(text) = vector_field(value, "hex").and_then(PortableValue::as_string) {
        return Ok(Arc::from(decode_hex(text)?));
    }
    let source = vector_field(value, "source")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.source")?;
    Ok(Arc::from(source.as_bytes().to_vec()))
}

/// Resolves the `input.limits` field overrides into the formation contract;
/// absent fields keep the frozen defaults.
fn parse_limits(case: &PortableValue) -> HclParseLimits {
    let mut limits = HclParseLimits::default();
    let Some(overrides) = input_field(case, "limits") else {
        return limits;
    };
    let Some(object) = overrides.as_object() else {
        return limits;
    };
    if let Some(common) = object_field(object, "common").and_then(PortableValue::as_object) {
        apply_usize(
            common,
            "max_source_bytes",
            &mut limits.common.max_source_bytes,
        );
        apply_usize(
            common,
            "max_nesting_depth",
            &mut limits.common.max_nesting_depth,
        );
        apply_usize(
            common,
            "max_token_count",
            &mut limits.common.max_token_count,
        );
        apply_usize(common, "max_node_count", &mut limits.common.max_node_count);
        apply_usize(
            common,
            "max_diagnostics",
            &mut limits.common.max_diagnostics,
        );
    }
    apply_usize(object, "max_body_depth", &mut limits.max_body_depth);
    apply_usize(
        object,
        "max_expression_depth",
        &mut limits.max_expression_depth,
    );
    apply_usize(object, "max_template_depth", &mut limits.max_template_depth);
    apply_usize(
        object,
        "max_attribute_count",
        &mut limits.max_attribute_count,
    );
    apply_usize(object, "max_block_count", &mut limits.max_block_count);
    apply_usize(object, "max_label_count", &mut limits.max_label_count);
    apply_usize(
        object,
        "max_body_item_count",
        &mut limits.max_body_item_count,
    );
    apply_usize(object, "max_identifier_len", &mut limits.max_identifier_len);
    apply_usize(object, "max_string_len", &mut limits.max_string_len);
    apply_usize(object, "max_number_digits", &mut limits.max_number_digits);
    apply_usize(object, "max_template_len", &mut limits.max_template_len);
    apply_usize(object, "max_heredoc_lines", &mut limits.max_heredoc_lines);
    apply_usize(object, "max_heredoc_bytes", &mut limits.max_heredoc_bytes);
    apply_usize(object, "max_tuple_elements", &mut limits.max_tuple_elements);
    apply_usize(object, "max_object_entries", &mut limits.max_object_entries);
    apply_usize(object, "max_for_extent", &mut limits.max_for_extent);
    apply_usize(
        object,
        "max_recovery_regions",
        &mut limits.max_recovery_regions,
    );
    apply_usize(object, "max_error_regions", &mut limits.max_error_regions);
    apply_usize(object, "max_syntax_pieces", &mut limits.max_syntax_pieces);
    limits
}

fn apply_usize(object: &[consema_core::ObjectEntry], name: &str, target: &mut usize) {
    if let Some(value) = object_field(object, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
    {
        *target = value;
    }
}

/// One formation outcome: a formed document or a fatal formation failure.
type Formed = Result<Document, FatalFormationFailure>;

fn form_value(value: &PortableValue) -> Result<Formed, String> {
    let profile = profile_of(value)?;
    let bytes = source_bytes(value)?;
    Ok(parse_hcl(
        bytes,
        profile,
        HclEncodingSelection::ProfileDefault,
        parse_limits(value),
    ))
}

/// Forms one case-level input document.
fn form_case(case: &PortableValue) -> Result<Formed, String> {
    form_value(case)
}

/// Forms one sample document; a sample without its own `source`/`profile`
/// facts inherits the case-level input facts.
fn form_sample(case: &PortableValue, sample: &PortableValue) -> Result<Formed, String> {
    form_value_merged(case, sample)
}

/// Forms one sample against case-level facts: the sample's own `source`/
/// `profile` facts win, case-level facts fill the rest.
fn form_value_merged(case: &PortableValue, sample: &PortableValue) -> Result<Formed, String> {
    let profile = match object_value_field(sample, "profile").and_then(PortableValue::as_string) {
        Some("hcl.native@1") => Ok(HclProfile::NativeV1),
        Some("hcl.tfvars@1") => Ok(HclProfile::TfvarsV1),
        Some(other) => Err(format!("unknown profile {other}")),
        None => profile_of(case),
    }?;
    let bytes =
        if let Some(text) = object_value_field(sample, "hex").and_then(PortableValue::as_string) {
            Arc::from(decode_hex(text)?)
        } else if let Some(source) =
            object_value_field(sample, "source").and_then(PortableValue::as_string)
        {
            Arc::from(source.as_bytes().to_vec())
        } else {
            source_bytes(case)?
        };
    Ok(parse_hcl(
        bytes,
        profile,
        HclEncodingSelection::ProfileDefault,
        parse_limits(case),
    ))
}

fn formed_status_name(formed: &Formed) -> &'static str {
    match formed {
        Ok(document) => status_name(document.status()),
        Err(_) => "FatalFormationFailure",
    }
}

fn formed_has_code(formed: &Formed, code: &str) -> bool {
    match formed {
        Ok(document) => document.diagnostics().iter().any(|d| d.code == code),
        Err(failure) => failure.diagnostics().iter().any(|d| d.code == code),
    }
}

fn formed_document(formed: &Formed) -> Result<&Document, String> {
    formed.as_ref().map_err(|_| "formation failed".to_owned())
}

/// Asserts the `expected.status` and optional `expected.diagnostic` facts.
fn assert_expected_status(formed: &Formed, expected: &PortableValue) -> Result<(), String> {
    if let Some(status) = expected_string_field(expected, "status") {
        ensure(formed_status_name(formed) == status)
            .map_err(|_| format!("status {} != {status}", formed_status_name(formed)))?;
    }
    if let Some(diagnostic) = expected_string_field(expected, "diagnostic") {
        ensure(formed_has_code(formed, &diagnostic))
            .map_err(|_| format!("diagnostic {diagnostic} not found"))?;
    }
    Ok(())
}

fn run_native_formation(case: &PortableValue) -> Result<(), String> {
    ensure(profile_of(case)? == HclProfile::NativeV1)
        .map_err(|_| "native-formation case must use the hcl.native@1 profile".to_owned())?;
    run_formation(case)
}

fn run_tfvars_formation(case: &PortableValue) -> Result<(), String> {
    ensure(profile_of(case)? == HclProfile::TfvarsV1)
        .map_err(|_| "tfvars-formation case must use the hcl.tfvars@1 profile".to_owned())?;
    run_formation(case)
}

fn run_formation(case: &PortableValue) -> Result<(), String> {
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(samples) = input_field(case, "samples") {
        return run_formation_samples(
            case,
            samples.as_sequence().ok_or("samples must be a sequence")?,
            expected,
        );
    }
    let formed = form_case(case)?;
    assert_expected_status(&formed, expected)?;
    if formed_status_name(&formed) == "Complete" {
        let document = formed_document(&formed)?;
        if let Some(render) = expected_string_field(expected, "render") {
            let actual = std::str::from_utf8(document.render())
                .map_err(|_| "render is not UTF-8".to_owned())?;
            ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
        }
    }
    Ok(())
}

fn run_formation_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let statuses = expected_sequence(expected, "statuses").ok_or("missing expected.statuses")?;
    let diagnostics =
        expected_sequence(expected, "diagnostics").ok_or("missing expected.diagnostics")?;
    ensure(samples.len() == statuses.len() && samples.len() == diagnostics.len())
        .map_err(|_| "status/diagnostic count mismatch".to_owned())?;
    let canonical_values = expected_sequence(expected, "canonical_values");
    let proven_attribute_names = expected_sequence(expected, "proven_attribute_names");
    for (index, sample) in samples.iter().enumerate() {
        let formed = form_sample(case, sample)?;
        let status = statuses[index]
            .as_string()
            .ok_or("status must be a string")?;
        ensure(formed_status_name(&formed) == status).map_err(|_| {
            format!(
                "sample {index} status {} != {status}",
                formed_status_name(&formed)
            )
        })?;
        if let Some(code) = diagnostics[index].as_string() {
            ensure(formed_has_code(&formed, code))
                .map_err(|_| format!("sample {index} diagnostic {code} not found"))?;
        }
        if status == "Complete" {
            if let Some(canonical_values) = canonical_values {
                if canonical_values[index].kind() != PortableValueKind::Null {
                    let document = formed_document(&formed)?;
                    assert_canonical_value(document, &canonical_values[index])
                        .map_err(|error| format!("sample {index}: {error}"))?;
                }
            }
        }
        if let Some(proven) = proven_attribute_names {
            if let Some(expected_names) = proven[index].as_sequence() {
                let document = formed_document(&formed)?;
                let actual: Vec<&str> = document
                    .document()
                    .body()
                    .items()
                    .iter()
                    .filter_map(HclBodyItem::as_attribute)
                    .map(HclAttribute::name)
                    .collect();
                let expected_names: Vec<&str> = expected_names
                    .iter()
                    .filter_map(PortableValue::as_string)
                    .collect();
                ensure(actual == expected_names).map_err(|_| {
                    format!("sample {index} attribute names {actual:?} != {expected_names:?}")
                })?;
            }
        }
    }
    Ok(())
}

/// Asserts the canonical decimal value of the first attribute expression
/// against one expected numeric fact (RFC 0014 §2.3, §6).
fn assert_canonical_value(document: &Document, expected: &PortableValue) -> Result<(), String> {
    let attribute = document
        .document()
        .body()
        .items()
        .first()
        .and_then(HclBodyItem::as_attribute)
        .ok_or("no attribute to canonicalize")?;
    let value = literal_value(attribute.expression())
        .map_err(|_| "expression is not literal-complete".to_owned())?;
    match value {
        HclLiteralValue::Integer(text) => {
            let actual = BigInteger::parse_decimal(&text).map_err(|error| format!("{error:?}"))?;
            let expected = expected
                .as_integer()
                .ok_or("expected an integer canonical value")?;
            ensure(actual == *expected).map_err(|_| "integer canonical value mismatch")?;
        }
        HclLiteralValue::Decimal(text) => {
            let actual = text
                .parse::<f64>()
                .map_err(|_| "canonical is not numeric")?;
            let expected = expected_f64(expected).ok_or("expected a real canonical value")?;
            ensure(bits_equal(actual, expected)).map_err(|_| "real canonical value mismatch")?;
        }
        _ => return Err("unexpected literal kind".to_owned()),
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
/// The argument-less structure operators (`hcl.document-body@1`,
/// `hcl.body-attributes@1`, `hcl.attribute-expression@1`, ...) carry no
/// argument; the equality and accessor operators name their own argument:
/// `hcl.attribute-name-equals@1` its `name`, `hcl.attribute-literal-value@1`
/// its `accessor`, `hcl.body-block-type-equals@1`/`hcl.block-type-equals@1`
/// their `type`, `hcl.block-label-equals@1` its `label`, the two kind
/// filters their `kind`, and `hcl.syntax-text-equals@1` its `text`.
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
                    "hcl.attribute-name-equals" => {
                        call.with_argument("name", PortableValue::string(argument))
                    }
                    "hcl.attribute-literal-value" => {
                        call.with_argument("accessor", PortableValue::string(argument))
                    }
                    "hcl.body-block-type-equals" | "hcl.block-type-equals" => {
                        call.with_argument("type", PortableValue::string(argument))
                    }
                    "hcl.block-label-equals" => {
                        call.with_argument("label", PortableValue::string(argument))
                    }
                    "hcl.expression-kind-is" | "hcl.syntax-kind-is" => {
                        call.with_argument("kind", PortableValue::string(argument))
                    }
                    "hcl.syntax-text-equals" => {
                        call.with_argument("text", PortableValue::string(argument))
                    }
                    _ => call.with_argument("argument", PortableValue::string(argument)),
                };
            }
            Ok(call)
        })
        .collect()
}

fn execute_native<'a>(
    document: &'a Document,
    calls: &[OperatorCall],
) -> Result<QueryExecution<HclMatch<'a>>, QueryFailure> {
    let mut expression = QueryExpression::Input;
    for call in calls {
        expression = expression.then(call.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("hcl.native-semantic-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()?;
    let executable = definition.bind(&capabilities())?;
    execute_hcl_native_query(
        &executable,
        document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
}

fn execute_syntax(
    document: &Document,
    calls: &[OperatorCall],
) -> Result<QueryExecution<HclSyntaxMatch>, QueryFailure> {
    let mut expression = QueryExpression::Input;
    for call in calls {
        expression = expression.then(call.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("hcl.lossless-syntax-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()?;
    let executable = definition.bind(&capabilities())?;
    execute_hcl_syntax_query(
        &executable,
        document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
}

/// Stable vector spelling of one `QueryFailure` variant.
fn query_failure_code(failure: &QueryFailure) -> &'static str {
    match failure {
        QueryFailure::DomainMismatch(_) => "hcl.query.domain-mismatch@1",
        QueryFailure::UnknownOperator { .. } => "hcl.query.unknown-operator@1",
        QueryFailure::WrongArgumentType { .. } => "hcl.query.wrong-argument-type@1",
        QueryFailure::InvalidArgument { .. } => "hcl.query.invalid-argument@1",
        QueryFailure::InvalidOperatorComposition { .. } => "hcl.query.invalid-composition@1",
        QueryFailure::MissingRequiredCapability(_) => "hcl.query.missing-capability@1",
        QueryFailure::RequiredTypeMismatch { .. } => "hcl.query.type-mismatch@1",
        QueryFailure::CardinalityViolation { .. } => "hcl.query.cardinality-violation@1",
        QueryFailure::ResourceLimitExceeded => "hcl.query.resource-limit@1",
        QueryFailure::Cancelled => "hcl.query.cancelled@1",
        QueryFailure::TargetUnavailable => "hcl.query.non-literal@1",
    }
}

fn run_query(case: &PortableValue) -> Result<(), String> {
    let domain = input_field(case, "domain")
        .and_then(PortableValue::as_string)
        .ok_or("missing input.domain")?;
    match domain {
        "hcl.native-semantic-query@1" => run_native_query(case),
        "hcl.lossless-syntax-query@1" => run_syntax_query(case),
        other => Err(format!("unknown query domain {other}")),
    }
}

/// The expression payload of one literal-capable native match.
fn expression_of<'m>(item: &'m HclMatch<'_>) -> Result<&'m HclExpression, String> {
    match item {
        HclMatch::Expression { expression, .. } => Ok(expression),
        _ => Err("match without expression payload".to_owned()),
    }
}

fn expression_facts(
    document: &Document,
    item: &HclMatch<'_>,
) -> Result<(String, String, bool), String> {
    let expression = expression_of(item)?;
    let kind = expression.kind().as_str().to_owned();
    let text = expression
        .text(document.source())
        .map_err(|error| format!("{error:?}"))?
        .to_owned();
    let literal = is_literal_complete(expression);
    Ok((kind, text, literal))
}

/// The typed literal payload of one expression match.
fn literal_of(expression: &HclExpression) -> Result<HclLiteralValue, String> {
    literal_value(expression).map_err(|_| "expression is not literal-complete".to_owned())
}

/// Compares one expression match against its `{kind, text, literal}`
/// expectation.
fn assert_expression_match(
    document: &Document,
    actual: &HclMatch<'_>,
    expected: &PortableValue,
) -> Result<(), String> {
    let (kind, text, literal) = expression_facts(document, actual)?;
    if let Some(expected_kind) =
        object_value_field(expected, "kind").and_then(PortableValue::as_string)
    {
        ensure(kind == expected_kind).map_err(|_| format!("kind {kind} != {expected_kind}"))?;
    }
    if let Some(expected_text) =
        object_value_field(expected, "text").and_then(PortableValue::as_string)
    {
        ensure(text == expected_text).map_err(|_| format!("text {text:?} != {expected_text:?}"))?;
    }
    if let Some(expected_literal) =
        object_value_field(expected, "literal").and_then(PortableValue::as_boolean)
    {
        ensure(literal == expected_literal)
            .map_err(|_| format!("literal {literal} != {expected_literal}"))?;
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
    let formed = form_case(case)?;
    let document = formed_document(&formed)?;
    // An `expected.error_regions` case queries a Recovered document: the
    // `hcl.error-regions@1` operator exposes its ordered error regions as
    // document-level facts (RFC 0014 §3, §7.1).
    let expects_error_regions = expected_sequence(expected, "error_regions").is_some();
    if document.status() != FormationStatus::Complete && !expects_error_regions {
        return Err("native-query input must form completely".to_owned());
    }
    let filters = input_field(case, "filters")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.filters")?;
    let calls = build_filters(filters)?;
    let execution =
        execute_native(document, &calls).map_err(|failure| format!("execute: {failure:?}"))?;
    let terminal =
        expected_string_field(expected, "terminal").ok_or("missing expected.terminal")?;
    ensure(terminal_name(execution.terminal_state()) == terminal).map_err(|_| {
        format!(
            "terminal {} != {terminal}",
            terminal_name(execution.terminal_state())
        )
    })?;
    if let Some(expected_matches) = expected_sequence(expected, "matches") {
        let matches = execution.matches();
        ensure(matches.len() == expected_matches.len()).map_err(|_| {
            format!(
                "match count {} != {}",
                matches.len(),
                expected_matches.len()
            )
        })?;
        for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
            assert_expression_match(document, actual, expected_match)?;
        }
    }
    if let Some(expected_regions) = expected_sequence(expected, "error_regions") {
        let regions: Vec<(&str, usize)> = execution
            .matches()
            .iter()
            .filter_map(|item| match item {
                HclMatch::ErrorRegion {
                    region, position, ..
                } => Some((region.code(), *position)),
                _ => None,
            })
            .collect();
        ensure(regions.len() == expected_regions.len()).map_err(|_| {
            format!(
                "error region count {} != {}",
                regions.len(),
                expected_regions.len()
            )
        })?;
        for (actual, expected_region) in regions.iter().zip(expected_regions.iter()) {
            let (code, position) = *actual;
            if let Some(expected_code) =
                object_value_field(expected_region, "code").and_then(PortableValue::as_string)
            {
                ensure(code == expected_code)
                    .map_err(|_| format!("error region code {code} != {expected_code}"))?;
            }
            if let Some(expected_position) = object_value_field(expected_region, "position")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
            {
                let actual_position = i64::try_from(position)
                    .map_err(|_| "error region position overflow".to_owned())?;
                ensure(actual_position == expected_position).map_err(|_| {
                    format!("error region position {actual_position} != {expected_position}")
                })?;
            }
        }
    }
    Ok(())
}

fn run_native_query_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let terminals = expected_sequence(expected, "terminals").ok_or("missing expected.terminals")?;
    ensure(samples.len() == terminals.len()).map_err(|_| "terminal count mismatch".to_owned())?;
    let codes = expected_sequence(expected, "codes");
    let integer_matches = expected_sequence(expected, "integer_matches");
    let boolean_matches = expected_sequence(expected, "boolean_matches");
    let label_matches = expected_sequence(expected, "label_matches");
    let nested_matches = expected_sequence(expected, "nested_matches");
    for (index, sample) in samples.iter().enumerate() {
        let formed = form_sample(case, sample)?;
        let document = formed_document(&formed)?;
        if document.status() != FormationStatus::Complete {
            return Err("native-query input must form completely".to_owned());
        }
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
                let execution = execute_native(document, &calls)
                    .map_err(|failure| format!("execute: {failure:?}"))?;
                match last_operator {
                    "hcl.attribute-literal-value" => {
                        let accessor = sample_accessor(sample);
                        if accessor == "as-integer" {
                            if let Some(expected_matches) = integer_matches {
                                assert_integer_matches(execution.matches(), expected_matches)?;
                            }
                        } else if accessor == "as-boolean-is" {
                            if let Some(expected_matches) = boolean_matches {
                                assert_boolean_matches(execution.matches(), expected_matches)?;
                            }
                        }
                    }
                    "hcl.block-label-equals" => {
                        if let Some(expected_matches) = label_matches {
                            assert_label_matches(execution.matches(), expected_matches)?;
                        }
                    }
                    "hcl.expression-text" => {
                        if let Some(expected_matches) = nested_matches {
                            assert_nested_matches(document, execution.matches(), expected_matches)?;
                        }
                    }
                    _ => {}
                }
            }
            "Failed" => {
                let Err(failure) = execute_native(document, &calls) else {
                    return Err("execution must fail".to_owned());
                };
                let codes = codes.ok_or("missing expected.codes")?;
                let expected_code = codes[index]
                    .as_string()
                    .ok_or("expected code must be a string")?;
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

fn sample_accessor(sample: &PortableValue) -> String {
    sample
        .as_object()
        .and_then(|object| {
            object_field(object, "filters")
                .and_then(PortableValue::as_sequence)
                .and_then(|filters| filters.last())
                .and_then(|filter| object_value_field(filter, "argument"))
                .and_then(PortableValue::as_string)
        })
        .unwrap_or("")
        .to_owned()
}

/// Asserts typed integer literal matches against `{kind, value}` facts.
fn assert_integer_matches(
    matches: &[HclMatch<'_>],
    expected_matches: &[PortableValue],
) -> Result<(), String> {
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "integer match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let expected_kind = object_value_field(expected_match, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected match kind")?;
        ensure(expected_kind == "integer")
            .map_err(|_| format!("expected kind {expected_kind} != integer"))?;
        let value = literal_of(expression_of(actual)?)?;
        let HclLiteralValue::Integer(text) = value else {
            return Err("match is not an integer literal".to_owned());
        };
        let actual_value =
            BigInteger::parse_decimal(&text).map_err(|error| format!("{error:?}"))?;
        let expected_value = object_value_field(expected_match, "value")
            .and_then(PortableValue::as_integer)
            .ok_or("missing expected integer value")?;
        ensure(actual_value == *expected_value)
            .map_err(|_| "integer literal value mismatch".to_owned())?;
    }
    Ok(())
}

/// Asserts typed boolean literal matches against `{kind, value}` facts.
fn assert_boolean_matches(
    matches: &[HclMatch<'_>],
    expected_matches: &[PortableValue],
) -> Result<(), String> {
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "boolean match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let expected_kind = object_value_field(expected_match, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected match kind")?;
        ensure(expected_kind == "boolean")
            .map_err(|_| format!("expected kind {expected_kind} != boolean"))?;
        let value = literal_of(expression_of(actual)?)?;
        let HclLiteralValue::Boolean(actual_value) = value else {
            return Err("match is not a boolean literal".to_owned());
        };
        let expected_value = object_value_field(expected_match, "value")
            .and_then(PortableValue::as_boolean)
            .ok_or("missing expected boolean value")?;
        ensure(actual_value == expected_value)
            .map_err(|_| "boolean literal value mismatch".to_owned())?;
    }
    Ok(())
}

/// Asserts block-label matches against `{text, quoted}` facts.
fn assert_label_matches(
    matches: &[HclMatch<'_>],
    expected_matches: &[PortableValue],
) -> Result<(), String> {
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "label match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let HclMatch::BlockLabel { label, .. } = actual else {
            return Err("match is not a block label".to_owned());
        };
        if let Some(expected_text) =
            object_value_field(expected_match, "text").and_then(PortableValue::as_string)
        {
            ensure(label.text() == expected_text)
                .map_err(|_| format!("label text {:?} != {expected_text:?}", label.text()))?;
        }
        if let Some(expected_quoted) =
            object_value_field(expected_match, "quoted").and_then(PortableValue::as_boolean)
        {
            ensure(label.quoted() == expected_quoted)
                .map_err(|_| format!("label quoted {} != {expected_quoted}", label.quoted()))?;
        }
    }
    Ok(())
}

/// Asserts expression matches against `{kind, text}` facts.
fn assert_nested_matches(
    document: &Document,
    matches: &[HclMatch<'_>],
    expected_matches: &[PortableValue],
) -> Result<(), String> {
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "nested match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let (kind, text, _) = expression_facts(document, actual)?;
        if let Some(expected_kind) =
            object_value_field(expected_match, "kind").and_then(PortableValue::as_string)
        {
            ensure(kind == expected_kind).map_err(|_| format!("kind {kind} != {expected_kind}"))?;
        }
        if let Some(expected_text) =
            object_value_field(expected_match, "text").and_then(PortableValue::as_string)
        {
            ensure(text == expected_text)
                .map_err(|_| format!("text {text:?} != {expected_text:?}"))?;
        }
    }
    Ok(())
}

fn run_syntax_query(case: &PortableValue) -> Result<(), String> {
    let formed = form_case(case)?;
    let document = formed_document(&formed)?;
    if document.status() != FormationStatus::Complete {
        return Err("syntax-query input must form completely".to_owned());
    }
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    let samples = input_field(case, "samples")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.samples")?;
    let terminals = expected_sequence(expected, "terminals").ok_or("missing expected.terminals")?;
    ensure(samples.len() == terminals.len()).map_err(|_| "terminal count mismatch".to_owned())?;
    let matches_sets = expected_sequence(expected, "matches").ok_or("missing expected.matches")?;
    ensure(samples.len() == matches_sets.len()).map_err(|_| "match count mismatch".to_owned())?;
    for (index, sample) in samples.iter().enumerate() {
        let filters = object_value_field(sample, "filters")
            .and_then(PortableValue::as_sequence)
            .ok_or("missing sample filters")?;
        let calls = build_filters(filters)?;
        let execution =
            execute_syntax(document, &calls).map_err(|failure| format!("execute: {failure:?}"))?;
        let terminal = terminals[index]
            .as_string()
            .ok_or("terminal must be a string")?;
        ensure(terminal_name(execution.terminal_state()) == terminal).map_err(|_| {
            format!(
                "terminal {} != {terminal}",
                terminal_name(execution.terminal_state())
            )
        })?;
        let matches = execution.matches();
        let expected_matches = matches_sets[index]
            .as_sequence()
            .ok_or("expected matches must be a sequence")?;
        ensure(matches.len() == expected_matches.len()).map_err(|_| {
            format!(
                "syntax match count {} != {}",
                matches.len(),
                expected_matches.len()
            )
        })?;
        for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
            let expected_kind = object_value_field(expected_match, "kind")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected match kind")?;
            ensure(actual.kind().as_str() == expected_kind)
                .map_err(|_| format!("kind {} != {expected_kind}", actual.kind().as_str()))?;
            if let Some(expected_text) =
                object_value_field(expected_match, "text").and_then(PortableValue::as_string)
            {
                let raw = &document.source().bytes()
                    [actual.span().start_byte()..actual.span().end_byte()];
                let actual_text =
                    std::str::from_utf8(raw).map_err(|_| "match text not UTF-8".to_owned())?;
                ensure(actual_text == expected_text)
                    .map_err(|_| format!("text {actual_text:?} != {expected_text:?}"))?;
            }
            if let Some(expected_ordinal) = object_value_field(expected_match, "ordinal")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
            {
                let actual_ordinal =
                    i64::try_from(actual.ordinal()).map_err(|_| "ordinal overflow".to_owned())?;
                ensure(actual_ordinal == expected_ordinal)
                    .map_err(|_| format!("ordinal {actual_ordinal} != {expected_ordinal}"))?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

fn projection_request(case: &PortableValue) -> Result<ProjectionRequest, String> {
    let target = input_field(case, "target")
        .and_then(PortableValue::as_string)
        .unwrap_or("hcl.projection.body@1");
    match target {
        "hcl.projection.body@1" => {
            match input_field(case, "policy").and_then(PortableValue::as_string) {
                Some("ProjectExpression") => Ok(ProjectionRequest::body_with_expression_policy(
                    ExpressionPolicy::ProjectExpression,
                )),
                None => Ok(ProjectionRequest::body()),
                Some(other) => Err(format!("unknown projection policy {other}")),
            }
        }
        other => Err(format!("unknown projection target {other}")),
    }
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
    let formed = form_case(case)?;
    let document = formed_document(&formed)?;
    let request = projection_request(case)?;
    let result = project_hcl(document, request);
    if let Some(failure) = expected_string_field(expected, "failure") {
        let ProjectionResult::Failed(attempt) = result else {
            return Err("projection must fail".to_owned());
        };
        let code = attempt
            .diagnostics
            .first()
            .map(|diagnostic| diagnostic.code.as_str())
            .ok_or("projection failure without diagnostics")?;
        ensure(code == failure).map_err(|_| format!("failure code {code} != {failure}"))?;
        return Ok(());
    }
    let ProjectionResult::Complete(projection) = result else {
        return Err("projection must complete".to_owned());
    };
    let record = expected_field(case, "record")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected.record")?;
    let actual = object_value_field(&projection.value, "record")
        .and_then(PortableValue::as_string)
        .ok_or("missing record member")?;
    ensure(actual == record).map_err(|_| format!("record {actual} != {record}"))?;
    if let Some(attributes) = expected_sequence(expected, "attributes") {
        assert_projected_attributes(&projection.value, attributes)?;
    }
    if let Some(blocks) = expected_sequence(expected, "blocks") {
        assert_projected_blocks(&projection.value, blocks)?;
    }
    if let Some(transformed) = expected_integer_field(expected, "transformed_events") {
        let events = projection
            .report
            .events()
            .iter()
            .filter(|event| event.kind == ProjectionEventKind::ExpressionSubstituted)
            .count();
        ensure(events as i64 == transformed)
            .map_err(|_| format!("transformed events {events} != {transformed}"))?;
    }
    if let Some(provenance) = expected_boolean_field(expected, "event_provenance") {
        ensure(provenance != projection.provenance.entries().is_empty())
            .map_err(|_| "event provenance mismatch".to_owned())?;
    }
    // Order, duplicate-key, and canonical-decimal preservation are verified
    // by the attribute assertions above; a declared flag must be true.
    for name in [
        "attribute_order_preserved",
        "duplicate_keys_preserved",
        "canonical_decimal",
    ] {
        if let Some(declared) = expected_boolean_field(expected, name) {
            ensure(declared).map_err(|_| format!("declared projection flag {name} is false"))?;
        }
    }
    Ok(())
}

/// The projected `hcl.body@1` record's ordered item sequence (RFC 0014
/// §8.2: one ordered body of `{kind, ...}` items, attributes and blocks
/// interleaved in source order).
fn projected_items(projected: &PortableValue) -> Result<&[PortableValue], String> {
    object_value_field(projected, "items")
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| "missing projected items".to_owned())
}

/// Asserts the attribute items of the projected `hcl.body@1` record against
/// the ordered expected attribute facts.
fn assert_projected_attributes(
    projected: &PortableValue,
    expected_attributes: &[PortableValue],
) -> Result<(), String> {
    let attributes: Vec<&PortableValue> = projected_items(projected)?
        .iter()
        .filter(|item| {
            object_value_field(item, "kind").and_then(PortableValue::as_string) == Some("attribute")
        })
        .collect();
    ensure(attributes.len() == expected_attributes.len()).map_err(|_| {
        format!(
            "attribute count {} != {}",
            attributes.len(),
            expected_attributes.len()
        )
    })?;
    for (actual, expected_attribute) in attributes.iter().zip(expected_attributes.iter()) {
        let expected_name = object_value_field(expected_attribute, "name")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected attribute name")?;
        let actual_name = object_value_field(actual, "name")
            .and_then(PortableValue::as_string)
            .ok_or("missing projected attribute name")?;
        ensure(actual_name == expected_name)
            .map_err(|_| format!("attribute name {actual_name} != {expected_name}"))?;
        // Expected attribute descriptors carry their value facts flat:
        // `{name, kind, text | value | elements | entries | expression}`.
        let value = object_value_field(actual, "value").ok_or("missing projected value")?;
        assert_projected_value(value, expected_attribute)?;
    }
    Ok(())
}

/// Asserts the block items of the projected `hcl.body@1` record.
fn assert_projected_blocks(
    projected: &PortableValue,
    expected_blocks: &[PortableValue],
) -> Result<(), String> {
    let blocks: Vec<&PortableValue> = projected_items(projected)?
        .iter()
        .filter(|item| {
            object_value_field(item, "kind").and_then(PortableValue::as_string) == Some("block")
        })
        .collect();
    ensure(blocks.len() == expected_blocks.len())
        .map_err(|_| format!("block count {} != {}", blocks.len(), expected_blocks.len()))?;
    for (actual, expected_block) in blocks.iter().zip(expected_blocks.iter()) {
        if let Some(expected_type) =
            object_value_field(expected_block, "type").and_then(PortableValue::as_string)
        {
            let actual_type = object_value_field(actual, "type")
                .and_then(PortableValue::as_string)
                .ok_or("missing projected block type")?;
            ensure(actual_type == expected_type)
                .map_err(|_| format!("block type {actual_type} != {expected_type}"))?;
        }
        if let Some(expected_labels) =
            object_value_field(expected_block, "labels").and_then(PortableValue::as_sequence)
        {
            let actual_labels = object_value_field(actual, "labels")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing projected block labels")?;
            ensure(actual_labels.len() == expected_labels.len()).map_err(|_| {
                format!(
                    "label count {} != {}",
                    actual_labels.len(),
                    expected_labels.len()
                )
            })?;
            for (actual_label, expected_label) in actual_labels.iter().zip(expected_labels.iter()) {
                let expected_text = expected_label
                    .as_string()
                    .ok_or("expected label must be a string")?;
                let actual_text = actual_label
                    .as_string()
                    .ok_or("projected label must be a string")?;
                ensure(actual_text == expected_text)
                    .map_err(|_| format!("label {actual_text} != {expected_text}"))?;
            }
        }
    }
    Ok(())
}

/// Asserts one projected value against its `{kind, ...}` expectation.
fn assert_projected_value(actual: &PortableValue, expected: &PortableValue) -> Result<(), String> {
    let kind = object_value_field(expected, "kind")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected value kind")?;
    match kind {
        "string" => {
            let text = object_value_field(expected, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected text")?;
            ensure(actual.as_string() == Some(text))
                .map_err(|_| "projected string mismatch".to_owned())?;
        }
        "integer" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_integer)
                .ok_or("missing expected integer")?;
            let actual_value = actual
                .as_integer()
                .ok_or("projected value is not an integer")?;
            ensure(actual_value == expected_value)
                .map_err(|_| "projected integer mismatch".to_owned())?;
        }
        "real" => {
            let expected_value =
                expected_f64_field(expected, "value").ok_or("missing expected real")?;
            let actual_value = expected_f64(actual).ok_or("projected value is not a real")?;
            ensure(bits_equal(actual_value, expected_value))
                .map_err(|_| "projected real mismatch".to_owned())?;
        }
        "boolean" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing expected boolean")?;
            ensure(actual.as_boolean() == Some(expected_value))
                .map_err(|_| "projected boolean mismatch".to_owned())?;
        }
        "null" => ensure(actual.kind() == PortableValueKind::Null)
            .map_err(|_| "projected value is not null".to_owned())?,
        "tuple" => {
            let elements = object_value_field(expected, "elements")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing expected elements")?;
            let actual_elements = actual
                .as_sequence()
                .ok_or("projected value is not a tuple")?;
            ensure(actual_elements.len() == elements.len()).map_err(|_| {
                format!(
                    "tuple count {} != {}",
                    actual_elements.len(),
                    elements.len()
                )
            })?;
            for (actual_element, expected_element) in actual_elements.iter().zip(elements.iter()) {
                assert_projected_element(actual_element, expected_element)?;
            }
        }
        "object" => {
            let entries = object_value_field(expected, "entries")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing expected entries")?;
            let actual_entries = actual
                .as_entry_mapping()
                .ok_or("projected value is not an object")?;
            ensure(actual_entries.len() == entries.len()).map_err(|_| {
                format!("object count {} != {}", actual_entries.len(), entries.len())
            })?;
            for (actual_entry, expected_entry) in actual_entries.iter().zip(entries.iter()) {
                let expected_pair = expected_entry
                    .as_sequence()
                    .ok_or("expected object entry must be a pair")?;
                let expected_key = expected_pair
                    .first()
                    .and_then(PortableValue::as_string)
                    .ok_or("expected object key must be a string")?;
                let actual_key = actual_entry
                    .key()
                    .as_string()
                    .ok_or("projected object key is not a string")?;
                ensure(actual_key == expected_key)
                    .map_err(|_| format!("object key {actual_key} != {expected_key}"))?;
                let expected_value = expected_pair
                    .get(1)
                    .ok_or("expected object entry value missing")?;
                assert_projected_element(actual_entry.value(), expected_value)?;
            }
        }
        "expression" => {
            let expected_expression = object_value_field(expected, "expression")
                .ok_or("missing expected expression record")?;
            let actual_record = object_value_field(actual, "record")
                .and_then(PortableValue::as_string)
                .ok_or("missing expression record member")?;
            let expected_record = object_value_field(expected_expression, "record")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected expression record id")?;
            ensure(actual_record == expected_record)
                .map_err(|_| format!("expression record {actual_record} != {expected_record}"))?;
            let actual_kind = object_value_field(actual, "kind")
                .and_then(PortableValue::as_string)
                .ok_or("missing expression kind member")?;
            let expected_kind = object_value_field(expected_expression, "kind")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected expression kind")?;
            ensure(actual_kind == expected_kind)
                .map_err(|_| format!("expression kind {actual_kind} != {expected_kind}"))?;
            let actual_text = object_value_field(actual, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing expression text member")?;
            let expected_text = object_value_field(expected_expression, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected expression text")?;
            ensure(actual_text == expected_text)
                .map_err(|_| format!("expression text {actual_text:?} != {expected_text:?}"))?;
        }
        other => return Err(format!("unknown projected value kind {other}")),
    }
    Ok(())
}

/// Asserts one tuple element or object value: a scalar, or a nested
/// `{kind, ...}` descriptor.
fn assert_projected_element(
    actual: &PortableValue,
    expected: &PortableValue,
) -> Result<(), String> {
    if let Some(text) = expected.as_string() {
        ensure(actual.as_string() == Some(text))
            .map_err(|_| "projected element string mismatch".to_owned())?;
        return Ok(());
    }
    if let Some(integer) = expected.as_integer() {
        ensure(actual.as_integer() == Some(integer))
            .map_err(|_| "projected element integer mismatch".to_owned())?;
        return Ok(());
    }
    if expected.as_boolean().is_some() {
        ensure(actual.as_boolean() == expected.as_boolean())
            .map_err(|_| "projected element boolean mismatch".to_owned())?;
        return Ok(());
    }
    if let Some(expected_real) = expected_f64(expected) {
        let actual_real = expected_f64(actual).ok_or("projected element is not a real")?;
        ensure(bits_equal(actual_real, expected_real))
            .map_err(|_| "projected element real mismatch".to_owned())?;
        return Ok(());
    }
    if object_value_field(expected, "kind").is_some() {
        return assert_projected_value_leaf(actual, expected);
    }
    Err("unsupported expected element".to_owned())
}

/// Leaf-level value assertion without the document parameter.
fn assert_projected_value_leaf(
    actual: &PortableValue,
    expected: &PortableValue,
) -> Result<(), String> {
    let kind = object_value_field(expected, "kind")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected value kind")?;
    match kind {
        "string" => {
            let text = object_value_field(expected, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing expected text")?;
            ensure(actual.as_string() == Some(text))
                .map_err(|_| "projected string mismatch".to_owned())?;
        }
        "integer" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_integer)
                .ok_or("missing expected integer")?;
            ensure(actual.as_integer() == Some(expected_value))
                .map_err(|_| "projected integer mismatch".to_owned())?;
        }
        "real" => {
            let expected_value =
                expected_f64_field(expected, "value").ok_or("missing expected real")?;
            let actual_value = expected_f64(actual).ok_or("projected value is not a real")?;
            ensure(bits_equal(actual_value, expected_value))
                .map_err(|_| "projected real mismatch".to_owned())?;
        }
        "boolean" => {
            let expected_value = object_value_field(expected, "value")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing expected boolean")?;
            ensure(actual.as_boolean() == Some(expected_value))
                .map_err(|_| "projected boolean mismatch".to_owned())?;
        }
        "null" => ensure(actual.kind() == PortableValueKind::Null)
            .map_err(|_| "projected value is not null".to_owned())?,
        "tuple" => {
            let elements = object_value_field(expected, "elements")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing expected elements")?;
            let actual_elements = actual
                .as_sequence()
                .ok_or("projected value is not a tuple")?;
            ensure(actual_elements.len() == elements.len()).map_err(|_| {
                format!(
                    "tuple count {} != {}",
                    actual_elements.len(),
                    elements.len()
                )
            })?;
            for (actual_element, expected_element) in actual_elements.iter().zip(elements.iter()) {
                assert_projected_element(actual_element, expected_element)?;
            }
        }
        "object" => {
            let entries = object_value_field(expected, "entries")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing expected entries")?;
            let actual_entries = actual
                .as_entry_mapping()
                .ok_or("projected value is not an object")?;
            ensure(actual_entries.len() == entries.len()).map_err(|_| {
                format!("object count {} != {}", actual_entries.len(), entries.len())
            })?;
            for (actual_entry, expected_entry) in actual_entries.iter().zip(entries.iter()) {
                let expected_pair = expected_entry
                    .as_sequence()
                    .ok_or("expected object entry must be a pair")?;
                let expected_key = expected_pair
                    .first()
                    .and_then(PortableValue::as_string)
                    .ok_or("expected object key must be a string")?;
                let actual_key = actual_entry
                    .key()
                    .as_string()
                    .ok_or("projected object key is not a string")?;
                ensure(actual_key == expected_key)
                    .map_err(|_| format!("object key {actual_key} != {expected_key}"))?;
                let expected_value = expected_pair
                    .get(1)
                    .ok_or("expected object entry value missing")?;
                assert_projected_element(actual_entry.value(), expected_value)?;
            }
        }
        other => return Err(format!("unknown projected value kind {other}")),
    }
    Ok(())
}

fn run_projection_samples(
    case: &PortableValue,
    samples: &[PortableValue],
    expected: &PortableValue,
) -> Result<(), String> {
    let codes = expected_sequence(expected, "codes");
    let literals = expected_sequence(expected, "literals");
    for (index, sample) in samples.iter().enumerate() {
        let formed = form_sample(case, sample)?;
        let document = formed_document(&formed)?;
        let request = projection_request(case)?;
        let result = project_hcl(document, request);
        if let Some(codes) = codes {
            if let Some(expected_code) = codes[index].as_string() {
                let ProjectionResult::Failed(attempt) = &result else {
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
        if let Some(literals) = literals {
            let expected_literal = literals[index]
                .as_boolean()
                .ok_or("expected literal must be a boolean")?;
            let completed = matches!(&result, ProjectionResult::Complete(_));
            ensure(completed == expected_literal).map_err(|_| {
                format!("sample {index} projection completion {completed} != {expected_literal}")
            })?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Materialization
// ---------------------------------------------------------------------------

fn materialization_request(
    style: &str,
    profile: &PortableValue,
) -> Result<MaterializationRequest, String> {
    let profile_id = match profile.as_string() {
        Some("hcl.native@1") => ProfileId::new("hcl.native", 1),
        Some("hcl.tfvars@1") => ProfileId::new("hcl.tfvars", 1),
        Some(other) => return Err(format!("unknown profile {other}")),
        None => return Err("missing profile".to_owned()),
    };
    match style {
        "hcl.canonical-document@1" => Ok(MaterializationRequest::new(
            profile_id,
            MaterializationStyleId::new("hcl.canonical-document", 1),
        )),
        other => Err(format!("unknown materialization style {other}")),
    }
}

/// Stable vector spelling of one `MaterializationFailure` variant.
///
/// `"invalid-record"` is the published spelling for `InvalidRequest`; the
/// remaining spellings let future vectors declare `"unsupported-profile"`,
/// `"unsupported-style"`, and friends.
fn materialization_failure_code(failure: &MaterializationFailure) -> &'static str {
    match failure {
        MaterializationFailure::InvalidRequest(_) => "invalid-record",
        MaterializationFailure::UnsupportedProfile => "unsupported-profile",
        MaterializationFailure::UnsupportedStyle => "unsupported-style",
        MaterializationFailure::UnsupportedEncoding => "unsupported-encoding",
        MaterializationFailure::UnsupportedNewline => "unsupported-newline",
        MaterializationFailure::Unrepresentable { .. } => "hcl.materialization.unrepresentable@1",
        MaterializationFailure::ResourceLimit(_) => "hcl.materialization.resource-limit@1",
        MaterializationFailure::FormationFailed => "formation-failed",
    }
}

fn complete_materialization(
    record: &PortableValue,
    request: &MaterializationRequest,
) -> Result<consema_document::CompleteMaterialization<Document>, String> {
    match materialize(record, request) {
        MaterializationResult::Complete(complete) => Ok(complete),
        MaterializationResult::Failed(attempt) => {
            Err(format!("materialization failed: {:?}", attempt.failure))
        }
    }
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
    let profile = input_field(case, "profile").ok_or("missing input.profile")?;
    let request = materialization_request(style, profile)?;
    let record = input_field(case, "record").ok_or("missing input.record")?;
    if let Some(failure) = expected_string_field(expected, "failure") {
        match materialize(record, &request) {
            MaterializationResult::Failed(attempt) => {
                ensure(materialization_failure_code(&attempt.failure) == failure).map_err(
                    |_| {
                        format!(
                            "failure {} != {failure}",
                            materialization_failure_code(&attempt.failure)
                        )
                    },
                )?;
            }
            MaterializationResult::Complete(_) => {
                return Err("materialization must fail".to_owned());
            }
        }
        return Ok(());
    }
    let complete = complete_materialization(record, &request)?;
    if let Some(render) = expected_string_field(expected, "render") {
        let actual = std::str::from_utf8(complete.document.render())
            .map_err(|_| "render is not UTF-8".to_owned())?;
        ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
    }
    if expected_boolean_field(expected, "closure").unwrap_or(false) {
        ensure(complete.document.status() == FormationStatus::Complete)
            .map_err(|_| "materialized document must be complete".to_owned())?;
    }
    if expected_boolean_field(expected, "fingerprint_match").unwrap_or(false) {
        assert_fingerprint_match(&complete, record)?;
    }
    Ok(())
}

/// Asserts that every `hcl.expression@1` record of the input record is
/// reproduced by the re-projection of the materialized document.
fn assert_fingerprint_match(
    complete: &consema_document::CompleteMaterialization<Document>,
    record: &PortableValue,
) -> Result<(), String> {
    let request =
        ProjectionRequest::body_with_expression_policy(ExpressionPolicy::ProjectExpression);
    let ProjectionResult::Complete(projection) = project_hcl(&complete.document, request) else {
        return Err("materialized document must re-project".to_owned());
    };
    let items = object_value_field(record, "items")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing record items")?;
    let attributes: Vec<&PortableValue> = projected_items(&projection.value)?
        .iter()
        .filter(|item| {
            object_value_field(item, "kind").and_then(PortableValue::as_string) == Some("attribute")
        })
        .collect();
    for item in items {
        let Some(kind) = object_value_field(item, "kind").and_then(PortableValue::as_string) else {
            continue;
        };
        if kind != "attribute" {
            continue;
        }
        let Some(value) = object_value_field(item, "value") else {
            continue;
        };
        let Some(value_kind) = object_value_field(value, "kind").and_then(PortableValue::as_string)
        else {
            continue;
        };
        if value_kind != "expression" {
            continue;
        }
        let name = object_value_field(item, "name")
            .and_then(PortableValue::as_string)
            .ok_or("missing attribute name")?;
        let expected_expression =
            object_value_field(value, "expression").ok_or("missing expression record")?;
        let projected = attributes
            .iter()
            .find(|attribute| {
                object_value_field(attribute, "name").and_then(PortableValue::as_string)
                    == Some(name)
            })
            .ok_or_else(|| format!("projected attribute {name} not found"))?;
        let projected_value =
            object_value_field(projected, "value").ok_or("missing projected value")?;
        let actual_kind = object_value_field(projected_value, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing projected expression kind")?;
        let expected_kind = object_value_field(expected_expression, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected expression kind")?;
        ensure(actual_kind == expected_kind)
            .map_err(|_| format!("expression kind {actual_kind} != {expected_kind}"))?;
        let actual_text = object_value_field(projected_value, "text")
            .and_then(PortableValue::as_string)
            .ok_or("missing projected expression text")?;
        let expected_text = object_value_field(expected_expression, "text")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected expression text")?;
        ensure(actual_text == expected_text)
            .map_err(|_| format!("expression text {actual_text:?} != {expected_text:?}"))?;
        let actual_record = object_value_field(projected_value, "record")
            .and_then(PortableValue::as_string)
            .ok_or("missing projected expression record")?;
        let expected_record = object_value_field(expected_expression, "record")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected expression record")?;
        ensure(actual_record == expected_record)
            .map_err(|_| format!("expression record {actual_record} != {expected_record}"))?;
    }
    Ok(())
}

fn run_materialization_samples(
    samples: &[PortableValue],
    case: &PortableValue,
    expected: &PortableValue,
) -> Result<(), String> {
    let renders = expected_sequence(expected, "renders");
    let codes = expected_sequence(expected, "codes");
    let closure = expected_boolean_field(expected, "closure").unwrap_or(false);
    ensure(
        samples.len()
            == renders
                .unwrap_or(codes.ok_or("missing expected.codes")?)
                .len(),
    )
    .map_err(|_| "render/code count mismatch".to_owned())?;
    for (index, sample) in samples.iter().enumerate() {
        let style = match object_value_field(sample, "style").and_then(PortableValue::as_string) {
            Some(style) => style,
            None => input_field(case, "style")
                .and_then(PortableValue::as_string)
                .ok_or("missing sample style")?,
        };
        let profile = match object_value_field(sample, "profile") {
            Some(profile) => profile.clone(),
            None => input_field(case, "profile")
                .cloned()
                .ok_or("missing sample profile")?,
        };
        let request = materialization_request(style, &profile)?;
        let record = object_value_field(sample, "record").ok_or("missing sample record")?;
        match materialize(record, &request) {
            MaterializationResult::Complete(complete) => {
                if let Some(renders) = renders {
                    let expected_render = renders[index]
                        .as_string()
                        .ok_or("expected render must be a string")?;
                    let actual = std::str::from_utf8(complete.document.render())
                        .map_err(|_| "render is not UTF-8".to_owned())?;
                    ensure(actual == expected_render)
                        .map_err(|_| format!("render {actual:?} != {expected_render:?}"))?;
                } else if let Some(codes) = codes {
                    if codes[index].as_string().is_some() {
                        return Err("materialization must fail".to_owned());
                    }
                }
                if closure {
                    ensure(complete.document.status() == FormationStatus::Complete)
                        .map_err(|_| "materialized document must be complete".to_owned())?;
                }
            }
            MaterializationResult::Failed(attempt) => {
                let codes = codes.ok_or("materialization must complete")?;
                let expected_code = codes[index]
                    .as_string()
                    .ok_or("expected code must be a string")?;
                ensure(materialization_failure_code(&attempt.failure) == expected_code).map_err(
                    |_| {
                        format!(
                            "materialization failure {} != {expected_code}",
                            materialization_failure_code(&attempt.failure)
                        )
                    },
                )?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

fn body_path(operation: &PortableValue) -> Result<BodyPath, String> {
    match object_value_field(operation, "body").and_then(PortableValue::as_string) {
        Some(other) if other != "root" => Err(format!("unknown body path {other}")),
        _ => Ok(BodyPath::root()),
    }
}

fn placement(operation: &PortableValue) -> Result<BodyPlacement, String> {
    match object_value_field(operation, "placement")
        .and_then(PortableValue::as_string)
        .unwrap_or("Last")
    {
        "First" => Ok(BodyPlacement::First),
        "Last" => Ok(BodyPlacement::Last),
        other => Err(format!("unknown placement {other}")),
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
            Ok(EditValue::String(text.to_owned()))
        }
        "integer" => {
            let payload = object_value_field(value, "value")
                .and_then(PortableValue::as_integer)
                .and_then(BigInteger::to_i64)
                .ok_or("missing integer value")?;
            Ok(EditValue::Integer(payload))
        }
        "real" => {
            let payload = expected_f64_field(value, "value").ok_or("missing real value")?;
            Ok(EditValue::Real(payload))
        }
        "boolean" => {
            let payload = object_value_field(value, "value")
                .and_then(PortableValue::as_boolean)
                .ok_or("missing boolean value")?;
            Ok(EditValue::Boolean(payload))
        }
        "null" => Ok(EditValue::Null),
        "tuple" => {
            let elements = object_value_field(value, "elements")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing tuple elements")?;
            let mut values = Vec::new();
            for element in elements {
                values.push(edit_value(element)?);
            }
            Ok(EditValue::Tuple(values))
        }
        "object" => {
            let entries = object_value_field(value, "entries")
                .and_then(PortableValue::as_sequence)
                .ok_or("missing object entries")?;
            let mut values = Vec::new();
            for entry in entries {
                let pair = entry.as_sequence().ok_or("entry must be a pair")?;
                let key_text = pair
                    .first()
                    .and_then(PortableValue::as_string)
                    .ok_or("entry key must be a string")?;
                let key = if let Ok(number) = key_text.parse::<i64>() {
                    EditKey::Number(number)
                } else {
                    EditKey::Identifier(key_text.to_owned())
                };
                let entry_value = pair.get(1).ok_or("entry value missing")?;
                values.push((key, edit_value(entry_value)?));
            }
            Ok(EditValue::Object(values))
        }
        "expression" => {
            let expression =
                object_value_field(value, "expression").ok_or("missing expression record")?;
            let kind = object_value_field(expression, "kind")
                .and_then(PortableValue::as_string)
                .ok_or("missing expression kind")?;
            let text = object_value_field(expression, "text")
                .and_then(PortableValue::as_string)
                .ok_or("missing expression text")?;
            Ok(EditValue::Expression {
                kind: kind.to_owned(),
                text: text.to_owned(),
            })
        }
        other => Err(format!("unknown value kind {other}")),
    }
}

fn block_node_ref(operation: &PortableValue) -> Result<NodeRef, String> {
    let node_ref = object_value_field(operation, "node_ref").ok_or("missing node_ref")?;
    let block_type = object_value_field(node_ref, "type")
        .and_then(PortableValue::as_string)
        .ok_or("missing node_ref type")?;
    let labels = object_value_field(node_ref, "labels")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing node_ref labels")?;
    let labels: Vec<String> = labels
        .iter()
        .map(|label| {
            label
                .as_string()
                .map(str::to_owned)
                .ok_or_else(|| "node_ref label must be a string".to_owned())
        })
        .collect::<Result<_, _>>()?;
    Ok(NodeRef::Block {
        body: BodyPath::root(),
        block_type: block_type.to_owned(),
        labels,
        occurrence: 0,
    })
}

fn build_transaction(
    document: &Document,
    operations: &[PortableValue],
) -> Result<EditTransactionBuilder, String> {
    let mut builder = EditTransactionBuilder::new(document);
    for operation in operations {
        let op = object_value_field(operation, "op")
            .and_then(PortableValue::as_string)
            .ok_or("missing op")?;
        match op {
            "hcl.edit.set-attribute-value@1" => {
                let body = body_path(operation)?;
                let attribute = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                let value =
                    edit_value(object_value_field(operation, "value").ok_or("missing value")?)?;
                builder.set_attribute_value(body, attribute, value);
            }
            "hcl.edit.insert-attribute@1" => {
                let body = body_path(operation)?;
                let name = object_value_field(operation, "name")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing name")?;
                let value =
                    edit_value(object_value_field(operation, "value").ok_or("missing value")?)?;
                let placement = placement(operation)?;
                builder.insert_attribute(body, name, value, placement);
            }
            "hcl.edit.remove-attribute@1" => {
                let body = body_path(operation)?;
                let attribute = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                builder.remove_attribute(body, attribute);
            }
            "hcl.edit.rename-attribute@1" => {
                let body = body_path(operation)?;
                let attribute = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                let name = object_value_field(operation, "name")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing name")?;
                builder.rename_attribute(body, attribute, name);
            }
            "hcl.edit.insert-block@1" => {
                let body = body_path(operation)?;
                let block_type = object_value_field(operation, "type")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing block type")?;
                let labels = object_value_field(operation, "labels")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("missing block labels")?;
                let labels: Vec<String> = labels
                    .iter()
                    .map(|label| {
                        label
                            .as_string()
                            .map(str::to_owned)
                            .ok_or_else(|| "block label must be a string".to_owned())
                    })
                    .collect::<Result<_, _>>()?;
                let attributes = object_value_field(operation, "attributes")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("missing block attributes")?;
                let mut typed = Vec::new();
                for attribute in attributes {
                    let name = object_value_field(attribute, "name")
                        .and_then(PortableValue::as_string)
                        .ok_or("missing block attribute name")?;
                    let value = edit_value(
                        object_value_field(attribute, "value").ok_or("missing attribute value")?,
                    )?;
                    typed.push((name.to_owned(), value));
                }
                let placement = placement(operation)?;
                builder.insert_block(body, block_type, labels, typed, placement);
            }
            "hcl.edit.remove-block@1" => {
                let node_ref = block_node_ref(operation)?;
                let NodeRef::Block {
                    block_type,
                    labels,
                    occurrence,
                    ..
                } = node_ref
                else {
                    return Err("node_ref must address a block".to_owned());
                };
                builder.remove_block(BodyPath::root(), &block_type, labels, occurrence);
            }
            other => return Err(format!("unknown edit op {other}")),
        }
    }
    Ok(builder)
}

/// Reparses one committed document under its own profile.
fn reparse(document: &Document) -> Result<Document, String> {
    let profile = if document.profile().id() == "hcl.tfvars" {
        HclProfile::TfvarsV1
    } else {
        HclProfile::NativeV1
    };
    parse_hcl(
        Arc::<[u8]>::from(document.render().to_vec()),
        profile,
        HclEncodingSelection::ProfileDefault,
        HclParseLimits::default(),
    )
    .map_err(|failure| format!("reparse: {failure:?}"))
}

/// Whether every block label of one native body tree is quoted.
fn all_labels_quoted(body: &HclBody) -> bool {
    body.items().iter().all(|item| match item {
        HclBodyItem::Attribute(_) => true,
        HclBodyItem::Block(block) => {
            block.labels().iter().all(HclBlockLabel::quoted) && all_labels_quoted(block.body())
        }
    })
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
    let formed = form_case(case)?;
    let document = formed_document(&formed)?;
    if document.status() != FormationStatus::Complete {
        return Err("edit input must form completely".to_owned());
    }
    let operations = input_field(case, "operations")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.operations")?;
    let transaction = build_transaction(document, operations)?.build();
    let commit = document
        .commit(&transaction)
        .map_err(|failure| format!("{failure:?}"))?;
    assert_edit_facts(document, &transaction, &commit, expected)?;
    Ok(())
}

/// Asserts the vector facts of one committed edit against its base document.
fn assert_edit_facts(
    base: &Document,
    transaction: &consema_hcl::EditTransaction,
    commit: &EditCommit,
    expected: &PortableValue,
) -> Result<(), String> {
    let committed = &commit.document;
    ensure(committed.status() == FormationStatus::Complete)
        .map_err(|_| "committed document must be complete".to_owned())?;
    if let Some(render) = expected_string_field(expected, "render") {
        let actual = std::str::from_utf8(committed.render())
            .map_err(|_| "render is not UTF-8".to_owned())?;
        ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
    }
    if expected_boolean_field(expected, "reparse_closure").unwrap_or(false) {
        ensure(reparse(committed)?.status() == FormationStatus::Complete)
            .map_err(|_| "committed document must reparse completely".to_owned())?;
    }
    if expected_boolean_field(expected, "untouched_byte_proof").unwrap_or(false) {
        commit
            .untouched_proof
            .verify(
                base.source(),
                committed.source(),
                commit.source_patch.replacements(),
            )
            .map_err(|error| format!("untouched proof: {error:?}"))?;
    }
    if expected_boolean_field(expected, "patch_replays").unwrap_or(false) {
        let replay = commit
            .source_patch
            .apply(base.source(), SourcePatchLimits::default())
            .map_err(|error| format!("patch apply: {error:?}"))?;
        ensure(replay.bytes() == committed.render())
            .map_err(|_| "patch does not replay".to_owned())?;
    }
    if expected_boolean_field(expected, "labels_always_quoted").unwrap_or(false) {
        ensure(all_labels_quoted(committed.document().body()))
            .map_err(|_| "a block label is not quoted".to_owned())?;
    }
    if expected_boolean_field(expected, "dry_run_equivalent").unwrap_or(false) {
        let source_id =
            EditPlanSourceId::new("hcl-conformance").map_err(|error| format!("{error:?}"))?;
        let plan = base
            .dry_run(transaction, source_id)
            .map_err(|failure| format!("dry run: {failure:?}"))?;
        ensure(plan.replacements() == commit.source_patch.replacements()).map_err(|_| {
            "dry-run replacement set differs from the committed replacement set".to_owned()
        })?;
    }
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
        let formed = form_sample(case, sample)?;
        let document = formed_document(&formed)?;
        let operations = object_value_field(sample, "operations")
            .and_then(PortableValue::as_sequence)
            .ok_or("missing operations")?;
        let transaction = if let Some(wrong) = object_value_field(sample, "wrong_source") {
            // The transaction is bound to another document's snapshot.
            let other = form_value(wrong)?;
            let other = formed_document(&other)?;
            build_transaction(other, operations)?.build()
        } else {
            build_transaction(document, operations)?.build()
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

// ---------------------------------------------------------------------------
// Limit
// ---------------------------------------------------------------------------

/// Runs one `hcl.limit@1` case.
///
/// Every published limit vector is formation-class today: the vocabulary
/// expresses `input.limits` field overrides resolved by [`parse_limits`]
/// into the formation contract, so this runner delegates to
/// [`run_formation`]. Non-formation limit scenarios — projection limits,
/// query result limits, edit resource limits — must branch here before
/// delegating, and the `hcl.limit@1` vector vocabulary grows to carry their
/// input and expectation facts alongside.
fn run_limit(case: &PortableValue) -> Result<(), String> {
    run_formation(case)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hcl_v1_suite_passes_fully() {
        let report = run_hcl_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 57);
    }

    #[test]
    fn hcl_suite_identifier_is_checked() {
        let changed = HCL_V1_VECTORS_JSON.replace(
            "\"suite\": \"consema.hcl.conformance@1\"",
            "\"suite\": \"unexpected.suite@1\"",
        );
        let report = run_hcl_v1_json(&changed);
        assert!(
            report.failed.iter().any(|(id, _)| id == "suite.schema"),
            "{report:#?}"
        );
        assert!(report.passed.is_empty());
    }

    #[test]
    fn hcl_vector_data_drives_expected_outputs() {
        // A changed expectation must fail its case.
        let changed = HCL_V1_VECTORS_JSON.replace(
            "\"status\": \"Recovered\",\n        \"diagnostic\": \"hcl.parse.duplicate-attribute@1\"",
            "\"status\": \"Recovered\",\n        \"diagnostic\": \"hcl.parse.unterminated-string@1\"",
        );
        let report = run_hcl_v1_json(&changed);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "hcl.native-formation.duplicate-attribute"),
            "{report:#?}"
        );
    }
}
