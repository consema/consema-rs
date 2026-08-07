//! Consema 0.6 JSON-family production conformance vectors.

use super::{ConformanceReport, VectorCase, capabilities, ensure, object_field};
use consema::{ConversionFailure, ConversionResult, convert_json};
use consema_core::{
    BigInteger, BinaryFloat64, CancellationToken, Decimal, OperatorCall, PortableValue,
    QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
};
use consema_document::{
    AssociationPlacement, ContentDigest, EditPlanSourceId, FormationStatus, MaterializationFailure,
    MaterializationRequest, MaterializationResult, MaterializationStyleId, NewlinePolicy,
    ParseLimits, ProfileId,
};
use consema_json::{
    Document, EditFailure, EditTransactionBuilder, JsonMatch, JsonObjectMember, JsonProfile,
    JsonValue, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, RepresentationPolicy,
    SemanticAvailability, execute_json_query, execute_json_syntax_query, parse,
};
use consema_protocol::{ContractRegistry, ErrorCodeRegistry, RegistryManifest};
use std::collections::HashSet;

/// Embedded language-neutral Consema 0.6 JSON-family suite.
pub const JSON_FAMILY_V2_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/json-family-v2.json");

/// JSON5 v2.2.3 reference parser corpus with pinned provenance and license.
pub const JSON5_REFERENCE_CORPUS_JSON: &str =
    include_str!("../../../conformance/corpora/json5-v2.2.3.json");

const JSON5_PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../../conformance/fixtures/json5/package-json5-v2.2.3.json5");

/// Runs the embedded JSON-family production suite.
#[must_use]
pub fn run_json_family_v2() -> ConformanceReport {
    run_json_family_v2_json(JSON_FAMILY_V2_VECTORS_JSON)
}

/// Runs caller-supplied JSON-family production vectors.
#[must_use]
pub fn run_json_family_v2_json(json: &str) -> ConformanceReport {
    let vectors = match parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    ) {
        Ok(document) => document,
        Err(error) => return failed_suite("suite.parse", format!("{error:?}")),
    };
    let projection = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed vector projection");
    let value = match vectors.project(&projection) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(error) => {
            return failed_suite("suite.project", format!("{error:?}"));
        }
    };
    let Some(root) = value.as_object() else {
        return failed_suite("suite.schema", "vector root is not Object".to_owned());
    };
    let Some(suite) = object_field(root, "suite").and_then(PortableValue::as_string) else {
        return failed_suite("suite.schema", "suite field is missing".to_owned());
    };
    if suite != "consema.json-family.conformance@2"
        || object_field(root, "semantic_model").and_then(PortableValue::as_string)
            != Some("core.semantic-model@4")
    {
        return failed_suite(
            "suite.schema",
            "suite or semantic model identity is invalid".to_owned(),
        );
    }
    let Some(cases) = object_field(root, "cases").and_then(PortableValue::as_sequence) else {
        return failed_suite("suite.schema", "cases field is missing".to_owned());
    };

    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite: suite.to_owned(),
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for value in cases {
        let Some(case) = vector_case(value) else {
            report.failed.push((
                "suite.schema".to_owned(),
                "case lacks id, capability, input, or expected".to_owned(),
            ));
            continue;
        };
        if !seen.insert(case.id) {
            report
                .failed
                .push((case.id.to_owned(), "duplicate case id".to_owned()));
            continue;
        }
        match run_case(&case) {
            Ok(()) => report.passed.push(case.id.to_owned()),
            Err(error) => report.failed.push((case.id.to_owned(), error)),
        }
    }
    report
}

/// Runs the pinned upstream JSON5 reference corpus and exact package fixture.
#[must_use]
pub fn run_json5_reference_corpus() -> ConformanceReport {
    run_json5_reference_corpus_json(JSON5_REFERENCE_CORPUS_JSON)
}

/// Runs caller-supplied JSON5 reference-corpus metadata plus the pinned fixture.
#[must_use]
pub fn run_json5_reference_corpus_json(json: &str) -> ConformanceReport {
    let value = match strict_core_value(json) {
        Ok(value) => value,
        Err(error) => return failed_reference_suite("suite.parse", error),
    };
    let Some(root) = value.as_object() else {
        return failed_reference_suite("suite.schema", "corpus root is not Object".to_owned());
    };
    if object_field(root, "suite").and_then(PortableValue::as_string)
        != Some("consema.json5.reference-corpus@1")
    {
        return failed_reference_suite("suite.schema", "corpus suite is invalid".to_owned());
    }
    let Some(upstream) = object_field(root, "upstream").and_then(PortableValue::as_object) else {
        return failed_reference_suite("suite.schema", "upstream metadata is missing".to_owned());
    };
    if object_field(upstream, "repository").and_then(PortableValue::as_string)
        != Some("https://github.com/json5/json5")
        || object_field(upstream, "tag").and_then(PortableValue::as_string) != Some("v2.2.3")
        || object_field(upstream, "commit").and_then(PortableValue::as_string)
            != Some("c3a75242772a5026a49c4017a16d9b3543b62776")
        || object_field(upstream, "upstream_fixture_blob_sha1").and_then(PortableValue::as_string)
            != Some("322bed5576031badba3383fe7343d39d21292942")
        || object_field(upstream, "stored_fixture_blob_sha1").and_then(PortableValue::as_string)
            != Some("d22ccc6cfbe4fec92c31d0512e311a7638a4ac4c")
        || object_field(upstream, "stored_fixture_sha256").and_then(PortableValue::as_string)
            != Some("ef3136abec4e0a19f610e39c7654dda5a06fee242ab8012df87d7ad9911411ad")
        || object_field(upstream, "license").and_then(PortableValue::as_string) != Some("MIT")
        || ContentDigest::of(JSON5_PACKAGE_FIXTURE).to_hex()
            != "ef3136abec4e0a19f610e39c7654dda5a06fee242ab8012df87d7ad9911411ad"
    {
        return failed_reference_suite(
            "suite.schema",
            "upstream provenance is not the frozen JSON5 reference".to_owned(),
        );
    }

    let mut report = ConformanceReport {
        suite: "consema.json5.reference-corpus@1".to_owned(),
        passed: Vec::new(),
        failed: Vec::new(),
    };
    let mut seen = HashSet::new();
    run_reference_cases(root, "valid", true, &mut seen, &mut report);
    run_reference_cases(root, "invalid", false, &mut seen, &mut report);

    let fixture_id = "fixture.package-json5-v2.2.3";
    match parse(
        JSON5_PACKAGE_FIXTURE,
        JsonProfile::Json5StandardV1,
        ParseLimits::default(),
    ) {
        Ok(document)
            if document.formation_status() == FormationStatus::Complete
                && document.render() == JSON5_PACKAGE_FIXTURE
                && matches!(
                    document.project(
                        &ProjectionRequestBuilder::new(ProjectionTarget::Json5BestExactCoreV1)
                            .build()
                            .expect("fixed fixture projection")
                    ),
                    ProjectionResult::Complete(_)
                ) =>
        {
            report.passed.push(fixture_id.to_owned());
        }
        Ok(document) => report.failed.push((
            fixture_id.to_owned(),
            format!(
                "fixture did not close exactly: status={:?}, diagnostics={:?}",
                document.formation_status(),
                document.diagnostics()
            ),
        )),
        Err(error) => report
            .failed
            .push((fixture_id.to_owned(), format!("{error:?}"))),
    }
    report
}

fn strict_core_value(json: &str) -> Result<PortableValue, String> {
    let document = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let projection = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed corpus projection");
    match document.project(&projection) {
        ProjectionResult::Complete(result) => Ok(result.value),
        ProjectionResult::Failed(error) => Err(format!("{error:?}")),
    }
}

fn failed_reference_suite(id: &str, error: String) -> ConformanceReport {
    ConformanceReport {
        suite: "consema.json5.reference-corpus@1".to_owned(),
        passed: Vec::new(),
        failed: vec![(id.to_owned(), error)],
    }
}

fn run_reference_cases(
    root: &[consema_core::ObjectEntry],
    field: &str,
    valid: bool,
    seen: &mut HashSet<String>,
    report: &mut ConformanceReport,
) {
    let Some(cases) = object_field(root, field).and_then(PortableValue::as_sequence) else {
        report.failed.push((
            "suite.schema".to_owned(),
            format!("{field} cases are missing"),
        ));
        return;
    };
    for case in cases {
        let Some(fields) = case.as_object() else {
            report.failed.push((
                "suite.schema".to_owned(),
                format!("{field} case is not Object"),
            ));
            continue;
        };
        let Some(id) = object_field(fields, "id").and_then(PortableValue::as_string) else {
            report
                .failed
                .push(("suite.schema".to_owned(), format!("{field} case lacks id")));
            continue;
        };
        let case_id = format!("{field}.{id}");
        if !seen.insert(case_id.clone()) {
            report
                .failed
                .push((case_id, "duplicate reference case id".to_owned()));
            continue;
        }
        let Some(source) = object_field(fields, "source").and_then(PortableValue::as_string) else {
            report
                .failed
                .push((case_id, "reference case lacks source".to_owned()));
            continue;
        };
        let result = if valid {
            validate_reference_acceptance(fields, source)
        } else {
            validate_reference_rejection(source)
        };
        match result {
            Ok(()) => report.passed.push(case_id),
            Err(error) => report.failed.push((case_id, error)),
        }
    }
}

fn validate_reference_acceptance(
    fields: &[consema_core::ObjectEntry],
    source: &str,
) -> Result<(), String> {
    let document = json5(source)?;
    ensure(document.render() == source.as_bytes())?;
    ensure(document.formation_status() == FormationStatus::Complete)?;
    if let Some(codes) =
        object_field(fields, "diagnostic_contains").and_then(PortableValue::as_sequence)
    {
        for code in codes {
            let code = code
                .as_string()
                .ok_or_else(|| "diagnostic_contains must contain strings".to_owned())?;
            ensure(document.diagnostics().iter().any(|item| item.code == code))?;
        }
    }
    Ok(())
}

fn validate_reference_rejection(source: &str) -> Result<(), String> {
    match parse(
        source.as_bytes(),
        JsonProfile::Json5StandardV1,
        ParseLimits::default(),
    ) {
        Err(_) => Ok(()),
        Ok(document) => ensure(
            document.render() == source.as_bytes()
                && document.formation_status() == FormationStatus::Recovered
                && !document.diagnostics().is_empty(),
        ),
    }
}

fn failed_suite(id: &str, error: String) -> ConformanceReport {
    ConformanceReport {
        suite: "consema.json-family.conformance@2".to_owned(),
        passed: Vec::new(),
        failed: vec![(id.to_owned(), error)],
    }
}

fn vector_case(value: &PortableValue) -> Option<VectorCase<'_>> {
    let fields = value.as_object()?;
    Some(VectorCase {
        id: object_field(fields, "id")?.as_string()?,
        capability: object_field(fields, "capability")?.as_string()?,
        input: object_field(fields, "input")?,
        expected: object_field(fields, "expected")?,
    })
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    if !case.capability.contains('@') {
        return Err("capability must be explicitly versioned".to_owned());
    }
    match input_string(case, "action")? {
        "parse" => parse_case(case),
        "syntax-query" => syntax_query_case(case),
        "native-query" => native_query_case(case),
        "project" => projection_case(case),
        "materialize" => materialization_case(case),
        "convert" => conversion_case(case),
        "move-member" => move_member_case(case),
        "edit-scalars" => edit_scalars_case(case),
        "registry-v4" => registry_v4_case(case),
        "parse-limit" => parse_limit_case(case),
        action => Err(format!("unknown input.action: {action}")),
    }
}

fn parse_case(case: &VectorCase<'_>) -> Result<(), String> {
    let source = input_string(case, "source")?;
    let document = parse(
        source.as_bytes(),
        profile(input_string(case, "profile")?)?,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    ensure(document.render() == source.as_bytes())?;

    if let Some(expected) = expected_string_optional(case, "formation") {
        ensure(formation_name(document.formation_status()) == expected)?;
    }
    for code in expected_strings_optional(case, "diagnostic_contains")? {
        ensure(document.diagnostics().iter().any(|item| item.code == code))?;
    }
    for kind in expected_strings_optional(case, "syntax_contains")? {
        ensure(
            document
                .lossless_syntax_kinds()
                .iter()
                .any(|item| format!("{item:?}") == kind),
        )?;
    }

    let root = document.root();
    if let Some(expected) = expected_string_optional(case, "root_kind") {
        ensure(value_kind_name(root)? == expected)?;
    }
    if let Some(expected) = expected_string_optional(case, "root_bits") {
        let bits = available(root.as_binary_float64())?
            .ok_or_else(|| "root is not BinaryFloat64".to_owned())?
            .bits();
        ensure(format!("{bits:016x}") == expected)?;
    }
    if let Some(expected) = expected_string_optional(case, "root_integer") {
        let integer =
            available(root.as_integer())?.ok_or_else(|| "root is not Integer".to_owned())?;
        ensure(integer.to_string() == expected)?;
    }

    if expected_field(case, "member_names").is_some()
        || expected_field(case, "member_kinds").is_some()
    {
        let members = object_members(root)?;
        if expected_field(case, "member_names").is_some() {
            let actual = members
                .iter()
                .map(|member| available(member.name()).map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?;
            ensure(actual == expected_strings(case, "member_names")?)?;
        }
        if expected_field(case, "member_kinds").is_some() {
            let actual = members
                .iter()
                .map(|member| value_kind_name(member.value()))
                .collect::<Result<Vec<_>, _>>()?;
            ensure(actual == expected_strings(case, "member_kinds")?)?;
        }
    }

    if expected_field(case, "element_kinds").is_some()
        || expected_field(case, "element_strings").is_some()
        || expected_field(case, "element_decimals").is_some()
    {
        let elements = array_values(root)?;
        if expected_field(case, "element_kinds").is_some() {
            let actual = elements
                .iter()
                .map(|value| value_kind_name(*value))
                .collect::<Result<Vec<_>, _>>()?;
            ensure(actual == expected_strings(case, "element_kinds")?)?;
        }
        if expected_field(case, "element_strings").is_some() {
            let actual = elements
                .iter()
                .map(|value| {
                    available(value.as_string())?
                        .map(str::to_owned)
                        .ok_or_else(|| "element is not String".to_owned())
                })
                .collect::<Result<Vec<_>, String>>()?;
            ensure(actual == expected_strings(case, "element_strings")?)?;
        }
        if expected_field(case, "element_decimals").is_some() {
            let actual = elements
                .iter()
                .map(|value| {
                    let decimal = available(value.as_decimal())?
                        .ok_or_else(|| "element is not Decimal".to_owned())?;
                    Ok((
                        decimal.coefficient().to_string(),
                        decimal.exponent().to_string(),
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            ensure(actual == expected_decimal_pairs(case)?)?;
        }
    }
    Ok(())
}

fn syntax_query_case(case: &VectorCase<'_>) -> Result<(), String> {
    let document = json5(input_string(case, "source")?)?;
    let kind = input_string(case, "kind")?;
    let query = QueryDefinition::new(QueryDomain::json_lossless_syntax_v2())
        .with_expression(
            QueryExpression::Input.then(
                OperatorCall::new("json.syntax-kind-is", 1)
                    .with_argument("kind", PortableValue::string(kind)),
            ),
        )
        .validate()
        .map_err(debug)?
        .bind(&capabilities())
        .map_err(debug)?;
    let result = execute_json_syntax_query(
        &query,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug)?;
    let actual = result
        .matches()
        .iter()
        .map(|item| {
            let span = item.span();
            std::str::from_utf8(&document.render()[span.start_byte()..span.end_byte()])
                .map(str::to_owned)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure(actual == expected_strings(case, "texts")?)?;

    if expected_bool(case, "v1_rejected")? {
        let v1 = QueryDefinition::new(QueryDomain::json_lossless_syntax_v1())
            .validate()
            .map_err(debug)?
            .bind(&capabilities())
            .map_err(debug)?;
        ensure(matches!(
            execute_json_syntax_query(
                &v1,
                &document,
                QueryLimits::default(),
                &CancellationToken::new()
            ),
            Err(QueryFailure::DomainMismatch(_))
        ))?;
    }
    Ok(())
}

fn native_query_case(case: &VectorCase<'_>) -> Result<(), String> {
    let document = json5(input_string(case, "source")?)?;
    let query = QueryDefinition::new(QueryDomain::json_native_v2())
        .validate()
        .map_err(debug)?
        .bind(&capabilities())
        .map_err(debug)?;
    let result = execute_json_query(
        &query,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug)?;
    let [
        JsonMatch::Value {
            kind: Some(kind), ..
        },
    ] = result.matches()
    else {
        return Err("native v2 root result is not one available value".to_owned());
    };
    ensure(format!("{kind:?}") == expected_string(case, "kind")?)?;

    if expected_bool(case, "v1_rejected")? {
        let v1 = QueryDefinition::new(QueryDomain::json_native_v1())
            .validate()
            .map_err(debug)?
            .bind(&capabilities())
            .map_err(debug)?;
        ensure(matches!(
            execute_json_query(
                &v1,
                &document,
                QueryLimits::default(),
                &CancellationToken::new()
            ),
            Err(QueryFailure::DomainMismatch(_))
        ))?;
    }
    Ok(())
}

fn projection_case(case: &VectorCase<'_>) -> Result<(), String> {
    let document = json5(input_string(case, "source")?)?;
    let target = match input_string(case, "target")? {
        "json5-best-exact" => ProjectionTarget::Json5BestExactCoreV1,
        "json-best-exact" => ProjectionTarget::BestExactCoreV1,
        value => return Err(format!("unknown projection target: {value}")),
    };
    let request = ProjectionRequestBuilder::new(target)
        .build()
        .map_err(debug)?;
    match document.project(&request) {
        ProjectionResult::Complete(result) => {
            ensure(expected_bool(case, "complete")?)?;
            ensure(format!("{:?}", result.value.kind()) == expected_string(case, "kind")?)?;
            if expected_field(case, "binary_bits").is_some() {
                let entries = result
                    .value
                    .as_entry_mapping()
                    .ok_or_else(|| "projection is not EntryMapping".to_owned())?;
                let actual = entries
                    .iter()
                    .map(|entry| {
                        entry
                            .value()
                            .as_binary_float64()
                            .map(|value| format!("{:016x}", value.bits()))
                            .ok_or_else(|| "entry is not BinaryFloat64".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ensure(actual == expected_strings(case, "binary_bits")?)?;
            }
        }
        ProjectionResult::Failed(attempt) => {
            ensure(!expected_bool(case, "complete")?)?;
            let code = expected_string(case, "code")?;
            ensure(attempt.diagnostics.iter().any(|item| item.code == code))?;
        }
    }
    Ok(())
}

fn materialization_case(case: &VectorCase<'_>) -> Result<(), String> {
    let values = input_field(case, "values")
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| "missing input.values".to_owned())?;
    let input = PortableValue::sequence(
        values
            .iter()
            .map(materialization_value)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let request =
        materialization_request(input_string(case, "profile")?, input_string(case, "style")?)?;
    match consema_json::materialize(&input, &request) {
        MaterializationResult::Complete(complete) => {
            ensure(complete.document.render() == expected_string(case, "output")?.as_bytes())
        }
        MaterializationResult::Failed(attempt) => ensure(
            materialization_failure_name(&attempt.failure) == expected_string(case, "failure")?,
        ),
    }
}

fn conversion_case(case: &VectorCase<'_>) -> Result<(), String> {
    let source_profile = profile(input_string(case, "source_profile")?)?;
    let document = parse(
        input_string(case, "source")?.as_bytes(),
        source_profile,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let target = if source_profile == JsonProfile::Json5StandardV1 {
        ProjectionTarget::Json5BestExactCoreV1
    } else {
        ProjectionTarget::BestExactCoreV1
    };
    let projection = ProjectionRequestBuilder::new(target)
        .build()
        .map_err(debug)?;
    let materialization = materialization_request(
        input_string(case, "target_profile")?,
        input_string(case, "style")?,
    )?;
    match convert_json(&document, &projection, &materialization) {
        ConversionResult::Complete(complete) => ensure(
            complete.document.render() == expected_string(case, "output")?.as_bytes()
                && format!("{:?}", complete.report.overall_fidelity())
                    == expected_string(case, "fidelity")?,
        ),
        ConversionResult::Failed(failure) => {
            let actual = match failure {
                ConversionFailure::MaterializationFailed { failure, .. } => {
                    materialization_failure_name(&failure)
                }
                ConversionFailure::ProjectionFailed { .. } => "ProjectionFailed",
                ConversionFailure::YamlProjectionFailed { .. } => "YamlProjectionFailed",
                ConversionFailure::UnauthorizedLoss => "UnauthorizedLoss",
            };
            ensure(actual == expected_string(case, "failure")?)
        }
    }
}

fn move_member_case(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse(
        input_string(case, "source")?.as_bytes(),
        profile(input_string(case, "profile")?)?,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let target = resolve_member(&document, &input_ordinals(case, "target_path")?)?;
    let placement = match input_string(case, "placement")? {
        "start" => AssociationPlacement::Start,
        "end" => AssociationPlacement::End,
        "before" | "after" => {
            let anchor = resolve_member(&document, &input_ordinals(case, "anchor_path")?)?;
            if input_string(case, "placement")? == "before" {
                AssociationPlacement::Before(anchor.node_ref())
            } else {
                AssociationPlacement::After(anchor.node_ref())
            }
        }
        value => return Err(format!("unknown placement: {value}")),
    };
    let mut builder = EditTransactionBuilder::new(&document);
    builder.move_member(target.node_ref(), placement);
    let transaction = builder.build();
    match document.commit(&transaction) {
        Ok(commit) => {
            ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())?;
            let plan = document
                .dry_run(
                    &transaction,
                    EditPlanSourceId::new("conformance.json5").map_err(debug)?,
                )
                .map_err(debug)?;
            ensure(
                (plan.replacements() == commit.source_patch.replacements()
                    && plan.target_digest() == commit.source_patch.target_digest())
                    == expected_bool(case, "patch_equal")?,
            )?;
            ensure(
                commit
                    .untouched_proof
                    .verify(
                        document.source(),
                        commit.document.source(),
                        commit.source_patch.replacements(),
                    )
                    .is_ok()
                    == expected_bool(case, "proof_valid")?,
            )
        }
        Err(failure) => ensure(edit_failure_name(&failure) == expected_string(case, "failure")?),
    }
}

fn edit_scalars_case(case: &VectorCase<'_>) -> Result<(), String> {
    let document = json5(input_string(case, "source")?)?;
    let members = object_members(document.root())?;
    let replacements = input_field(case, "replacements")
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| "missing input.replacements".to_owned())?;
    let mut builder = EditTransactionBuilder::new(&document);
    for replacement in replacements {
        let fields = replacement
            .as_object()
            .ok_or_else(|| "replacement is not Object".to_owned())?;
        let ordinal = object_field(fields, "ordinal")
            .and_then(PortableValue::as_integer)
            .and_then(BigInteger::to_usize)
            .ok_or_else(|| "replacement ordinal is invalid".to_owned())?;
        let value = scalar_replacement(fields)?;
        let member = members
            .get(ordinal)
            .ok_or_else(|| "replacement ordinal is out of range".to_owned())?;
        builder.semantic_scalar(
            member.value_node_ref(),
            value,
            RepresentationPolicy::PreserveCompatible,
        );
    }
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn registry_v4_case(case: &VectorCase<'_>) -> Result<(), String> {
    let contracts = ContractRegistry::v4();
    let v4 = ErrorCodeRegistry::v4();
    let v3 = ErrorCodeRegistry::v3();
    let manifest = RegistryManifest::v4();
    let restored = RegistryManifest::from_value(&manifest.to_value()).map_err(debug)?;
    ensure(
        contracts.contracts().len() == expected_usize(case, "contract_count")?
            && v4.codes().len() == expected_usize(case, "error_code_count")?
            && v3.codes().len() == expected_usize(case, "v3_error_code_count")?
            && v4.contains(expected_string(case, "new_code")?)
            && !v3.contains(expected_string(case, "new_code")?)
            && manifest.semantic_model().version() == 4
            && !manifest.is_current()
            && restored == manifest,
    )
}

fn parse_limit_case(case: &VectorCase<'_>) -> Result<(), String> {
    let result = parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::Json5StandardV1,
        ParseLimits {
            max_nesting_depth: input_usize(case, "max_depth")?,
            ..ParseLimits::default()
        },
    );
    ensure(result.is_err() == expected_bool(case, "fatal")?)
}

fn materialization_value(value: &PortableValue) -> Result<PortableValue, String> {
    let fields = value
        .as_object()
        .ok_or_else(|| "materialization value is not Object".to_owned())?;
    if let Some(bits) = object_field(fields, "bits").and_then(PortableValue::as_string) {
        return Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
            u64::from_str_radix(bits, 16).map_err(|error| error.to_string())?,
        )));
    }
    if let Some(string) = object_field(fields, "string").and_then(PortableValue::as_string) {
        return Ok(PortableValue::string(string));
    }
    if object_field(fields, "null").and_then(PortableValue::as_boolean) == Some(true) {
        return Ok(PortableValue::null());
    }
    Err("unknown materialization value".to_owned())
}

fn scalar_replacement(fields: &[consema_core::ObjectEntry]) -> Result<PortableValue, String> {
    if let Some(integer) = object_field(fields, "integer").and_then(PortableValue::as_string) {
        return BigInteger::parse_decimal(integer)
            .map(PortableValue::integer)
            .map_err(debug);
    }
    if let (Some(coefficient), Some(exponent)) = (
        object_field(fields, "decimal_coefficient").and_then(PortableValue::as_string),
        object_field(fields, "decimal_exponent").and_then(PortableValue::as_string),
    ) {
        return Ok(PortableValue::decimal(Decimal::new(
            BigInteger::parse_decimal(coefficient).map_err(debug)?,
            BigInteger::parse_decimal(exponent).map_err(debug)?,
        )));
    }
    if let Some(string) = object_field(fields, "string").and_then(PortableValue::as_string) {
        return Ok(PortableValue::string(string));
    }
    if let Some(bits) = object_field(fields, "bits").and_then(PortableValue::as_string) {
        return Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
            u64::from_str_radix(bits, 16).map_err(|error| error.to_string())?,
        )));
    }
    Err("replacement has no supported scalar value".to_owned())
}

fn resolve_member<'a>(
    document: &'a Document,
    path: &[usize],
) -> Result<JsonObjectMember<'a>, String> {
    if path.is_empty() {
        return Err("member path is empty".to_owned());
    }
    let mut value = document.root();
    for (depth, ordinal) in path.iter().copied().enumerate() {
        let members = object_members(value)?;
        let member = *members
            .get(ordinal)
            .ok_or_else(|| format!("member path ordinal {ordinal} is out of range"))?;
        if depth + 1 == path.len() {
            return Ok(member);
        }
        value = member.value();
    }
    unreachable!("non-empty member path returns inside the loop")
}

fn materialization_request(profile: &str, style: &str) -> Result<MaterializationRequest, String> {
    let target = profile_id(profile)?;
    Ok(
        MaterializationRequest::new(target, MaterializationStyleId::new(style, 1))
            .with_newline(NewlinePolicy::None),
    )
}

fn profile(value: &str) -> Result<JsonProfile, String> {
    match value {
        "json.strict@1" => Ok(JsonProfile::StrictV1),
        "jsonc.bounded@1" => Ok(JsonProfile::JsoncBoundedV1),
        "json5.standard@1" => Ok(JsonProfile::Json5StandardV1),
        value => Err(format!("unknown JSON profile: {value}")),
    }
}

fn profile_id(value: &str) -> Result<ProfileId, String> {
    Ok(profile(value)?.id())
}

fn json5(source: &str) -> Result<Document, String> {
    parse(
        source.as_bytes(),
        JsonProfile::Json5StandardV1,
        ParseLimits::default(),
    )
    .map_err(debug)
}

fn formation_name(value: FormationStatus) -> &'static str {
    match value {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    }
}

fn value_kind_name(value: JsonValue<'_>) -> Result<String, String> {
    available(value.kind()).map(|kind| format!("{kind:?}"))
}

fn object_members(value: JsonValue<'_>) -> Result<Vec<JsonObjectMember<'_>>, String> {
    available(value.object_members())?.ok_or_else(|| "value is not Object".to_owned())
}

fn array_values(value: JsonValue<'_>) -> Result<Vec<JsonValue<'_>>, String> {
    available(value.array_elements())?
        .ok_or_else(|| "value is not Array".to_owned())
        .map(|elements| {
            elements
                .into_iter()
                .map(consema_json::JsonArrayElement::value)
                .collect()
        })
}

fn available<T>(value: SemanticAvailability<T>) -> Result<T, String> {
    match value {
        SemanticAvailability::Available(value) => Ok(value),
        SemanticAvailability::Unavailable(reason) => {
            Err(format!("native semantics unavailable: {reason:?}"))
        }
    }
}

fn materialization_failure_name(failure: &MaterializationFailure) -> &'static str {
    match failure {
        MaterializationFailure::InvalidRequest(_) => "InvalidRequest",
        MaterializationFailure::UnsupportedProfile => "UnsupportedProfile",
        MaterializationFailure::UnsupportedStyle => "UnsupportedStyle",
        MaterializationFailure::UnsupportedEncoding => "UnsupportedEncoding",
        MaterializationFailure::UnsupportedNewline => "UnsupportedNewline",
        MaterializationFailure::Unrepresentable { .. } => "Unrepresentable",
        MaterializationFailure::ResourceLimit(_) => "ResourceLimit",
        MaterializationFailure::FormationFailed => "FormationFailed",
    }
}

fn edit_failure_name(failure: &EditFailure) -> &'static str {
    match failure {
        EditFailure::RecoveredDocument => "RecoveredDocument",
        EditFailure::WrongSnapshot => "WrongSnapshot",
        EditFailure::WrongRole => "WrongRole",
        EditFailure::IncompleteTarget => "IncompleteTarget",
        EditFailure::SemanticUnavailable => "SemanticUnavailable",
        EditFailure::UnsupportedSemanticValue(_) => "UnsupportedSemanticValue",
        EditFailure::InvalidLiteral => "InvalidLiteral",
        EditFailure::RepresentationIncompatible => "RepresentationIncompatible",
        EditFailure::ExactLiteralRequiresLiteralOperation => "ExactLiteralRequiresLiteralOperation",
        EditFailure::ConflictingEdits => "ConflictingEdits",
        EditFailure::DuplicateTarget => "DuplicateTarget",
        EditFailure::OverlappingOwnership => "OverlappingOwnership",
        EditFailure::AncestorDescendantConflict => "AncestorDescendantConflict",
        EditFailure::PlacementAnchorRemoved => "PlacementAnchorRemoved",
        EditFailure::PlacementAnchorModified => "PlacementAnchorModified",
        EditFailure::TargetNotFound => "TargetNotFound",
        EditFailure::UnrepresentableValue(_) => "UnrepresentableValue",
        EditFailure::ResourceLimit(_) => "ResourceLimit",
        EditFailure::NewDocumentFormationFailed => "NewDocumentFormationFailed",
    }
}

fn expected_decimal_pairs(case: &VectorCase<'_>) -> Result<Vec<(String, String)>, String> {
    expected_field(case, "element_decimals")
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| "missing expected.element_decimals".to_owned())?
        .iter()
        .map(|pair| {
            let pair = pair
                .as_sequence()
                .ok_or_else(|| "decimal pair is not Sequence".to_owned())?;
            if pair.len() != 2 {
                return Err("decimal pair must contain two strings".to_owned());
            }
            Ok((
                pair[0]
                    .as_string()
                    .ok_or_else(|| "decimal coefficient is not String".to_owned())?
                    .to_owned(),
                pair[1]
                    .as_string()
                    .ok_or_else(|| "decimal exponent is not String".to_owned())?
                    .to_owned(),
            ))
        })
        .collect()
}

fn input_ordinals(case: &VectorCase<'_>, key: &str) -> Result<Vec<usize>, String> {
    input_field(case, key)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("missing input.{key}"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_usize)
                .ok_or_else(|| format!("input.{key} contains a non-usize value"))
        })
        .collect()
}

fn input_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.input
        .as_object()
        .and_then(|fields| object_field(fields, key))
}

fn expected_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, key))
}

fn input_string<'a>(case: &VectorCase<'a>, key: &str) -> Result<&'a str, String> {
    input_field(case, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing input.{key}"))
}

fn expected_string<'a>(case: &VectorCase<'a>, key: &str) -> Result<&'a str, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing expected.{key}"))
}

fn expected_string_optional<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a str> {
    expected_field(case, key).and_then(PortableValue::as_string)
}

fn expected_strings(case: &VectorCase<'_>, key: &str) -> Result<Vec<String>, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_sequence)
        .ok_or_else(|| format!("missing expected.{key}"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(str::to_owned)
                .ok_or_else(|| format!("expected.{key} contains a non-string"))
        })
        .collect()
}

fn expected_strings_optional(case: &VectorCase<'_>, key: &str) -> Result<Vec<String>, String> {
    match expected_field(case, key) {
        Some(_) => expected_strings(case, key),
        None => Ok(Vec::new()),
    }
}

fn expected_bool(case: &VectorCase<'_>, key: &str) -> Result<bool, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_boolean)
        .ok_or_else(|| format!("missing expected.{key}"))
}

fn input_usize(case: &VectorCase<'_>, key: &str) -> Result<usize, String> {
    input_field(case, key)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("missing input.{key}"))
}

fn expected_usize(case: &VectorCase<'_>, key: &str) -> Result<usize, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("missing expected.{key}"))
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_json_family_v2_suite_is_conformant() {
        let report = run_json_family_v2();
        assert!(report.is_conformant(), "{:#?}", report.failed);
        assert_eq!(report.passed.len(), 33);
    }

    #[test]
    fn vector_expectations_drive_results() {
        let mutated = JSON_FAMILY_V2_VECTORS_JSON.replacen(
            "\"contract_count\": 25",
            "\"contract_count\": 24",
            1,
        );
        let report = run_json_family_v2_json(&mutated);
        assert_eq!(
            report.failed.first().map(|item| item.0.as_str()),
            Some("protocol.registry.semantic-model-v4")
        );
    }

    #[test]
    fn pinned_json5_reference_corpus_is_conformant() {
        let report = run_json5_reference_corpus();
        assert!(report.is_conformant(), "{:#?}", report.failed);
        assert_eq!(report.passed.len(), 83);
    }

    #[test]
    fn reference_corpus_classification_drives_results() {
        let mutated = JSON5_REFERENCE_CORPUS_JSON.replacen(
            "\"id\": \"object.empty\", \"source\": \"{}\"",
            "\"id\": \"object.empty\", \"source\": \"{\"",
            1,
        );
        let report = run_json5_reference_corpus_json(&mutated);
        assert_eq!(
            report.failed.first().map(|item| item.0.as_str()),
            Some("valid.object.empty")
        );
    }
}
