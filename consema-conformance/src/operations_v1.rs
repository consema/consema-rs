//! Consema 0.5 materialization, conversion, structural-edit, and v3 protocol vectors.

use crate::{ConformanceReport, VectorCase};
use consema::{ConversionResult, convert_json, convert_toml};
use consema_core::{BigInteger, BinaryFloat64, EntryMappingBuilder, PortableValue, StableFailure};
use consema_document::{
    AssociationPlacement, ContentDigest, EditPlanSourceId, MappingPolicy, MaterializationFidelity,
    MaterializationLimits, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, ParseLimits, ProfileId, SourcePatchLimits,
};
use consema_json::{
    EditTransactionBuilder as JsonEditBuilder, JsonProfile, ProjectionRequestBuilder,
    ProjectionResult as JsonProjectionResult, ProjectionTarget as JsonProjectionTarget,
    SemanticAvailability,
};
use consema_protocol::{
    ContractId, ContractRegistry, ConversionFidelityMessage, ConversionReportMessage,
    EditPlanMessage, FormatOperationRegistryMessage, MaterializationFailureMessage,
    MaterializationProvenanceMapMessage, MaterializationReportMessage,
    MaterializationRequestMessage, MaterializationResultMessage, ProjectionReportMessage,
    ProtocolLimits, ProtocolMessage, RegistryManifest,
};
use consema_toml::{
    EditTransactionBuilder as TomlEditBuilder, ProjectionRequest as TomlProjectionRequest,
    ProjectionResult as TomlProjectionResult, ProjectionTarget as TomlProjectionTarget,
    TomlProfile,
};
use std::collections::HashSet;

/// Embedded language-neutral Consema 0.5 operation suite.
pub const OPERATIONS_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/operations-v1.json");

/// Runs the embedded operation suite.
#[must_use]
pub fn run_operations_v1() -> ConformanceReport {
    run_operations_v1_json(OPERATIONS_V1_VECTORS_JSON)
}

/// Runs caller-supplied operation-suite JSON.
#[must_use]
pub fn run_operations_v1_json(json: &str) -> ConformanceReport {
    let vectors = match consema_json::parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    ) {
        Ok(document) => document,
        Err(error) => {
            return failed_suite("suite.parse", format!("{error:?}"));
        }
    };
    let request = ProjectionRequestBuilder::new(JsonProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        JsonProjectionResult::Complete(result) => result.value,
        JsonProjectionResult::Failed(error) => {
            return failed_suite("suite.project", format!("{error:?}"));
        }
    };
    let Some(root) = value.as_object() else {
        return failed_suite("suite.schema", "vector root is not Object".to_owned());
    };
    let Some(suite) = object_field(root, "suite").and_then(PortableValue::as_string) else {
        return failed_suite("suite.schema", "suite field is missing".to_owned());
    };
    if object_field(root, "semantic_model").and_then(PortableValue::as_string)
        != Some("core.semantic-model@3")
    {
        return failed_suite("suite.schema", "semantic model must be v3".to_owned());
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
            report
                .failed
                .push(("suite.schema".to_owned(), "invalid case schema".to_owned()));
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
    if cases.len() != 35 {
        report.failed.push((
            "suite.case-count".to_owned(),
            format!("expected 35 cases, found {}", cases.len()),
        ));
    }
    report
}

fn failed_suite(id: &str, error: String) -> ConformanceReport {
    ConformanceReport {
        suite: "consema.operations.conformance@1".to_owned(),
        passed: Vec::new(),
        failed: vec![(id.to_owned(), error)],
    }
}

fn vector_case(value: &PortableValue) -> Option<VectorCase<'_>> {
    let object = value.as_object()?;
    Some(VectorCase {
        id: object_field(object, "id")?.as_string()?,
        capability: object_field(object, "capability")?.as_string()?,
        input: object_field(object, "input")?,
        expected: object_field(object, "expected")?,
    })
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    match case.id {
        "operations.v1.registry-v3" => registry_v3(case),
        "operations.v1.protocol-v3-dual-transport" => protocol_v3(case),
        "operations.v1.operation-registry" => operation_registry(case),
        "operations.v1.materialize-json-compact"
        | "operations.v1.materialize-json-pretty-crlf"
        | "operations.v1.materialize-json-entry-mapping-duplicates" => {
            materialize_json_success(case)
        }
        "operations.v1.materialize-json-nonstring-key-rejected" => {
            materialize_json_nonstring_failure(case)
        }
        "operations.v1.materialize-json-float-rejected" => materialize_json_float_failure(case),
        "operations.v1.materialize-json-output-limit" => materialize_json_limit(case),
        "operations.v1.materialize-toml-native" => materialize_toml_native(case),
        "operations.v1.materialize-toml-explicit-mapping"
        | "operations.v1.materialize-toml-implicit-mapping-rejected" => {
            materialize_toml_mapping(case)
        }
        "operations.v1.materialize-toml-null-rejected" => {
            materialize_toml_failure(case, PortableValue::null())
        }
        "operations.v1.materialize-toml-output-limit" => materialize_toml_limit(case),
        "operations.v1.materialization-depth-limit" => materialization_depth_limit(case),
        "operations.v1.convert-json-to-toml-exact" => convert_json_toml(case),
        "operations.v1.convert-toml-to-json-exact" => convert_toml_json(case),
        "operations.v1.convert-duplicate-json-to-toml-fails" => convert_duplicate_failure(case),
        "operations.v1.convert-transformed-report" => convert_transformed(case),
        "operations.v1.json-object-insert" => json_object_insert(case),
        "operations.v1.json-object-remove-duplicate" => json_object_remove(case),
        "operations.v1.json-array-remove" => json_array_remove(case),
        "operations.v1.json-conflict-atomic" => json_conflict(case),
        "operations.v1.json-dry-run-proof-patch" => json_dry_run(case),
        "operations.v1.json-structural-matrix" => json_structural_matrix(case),
        "operations.v1.json-conflict-matrix" => json_conflict_matrix(case),
        "operations.v1.toml-root-insert" => toml_root_insert(case),
        "operations.v1.toml-inline-rename" => toml_inline_rename(case),
        "operations.v1.toml-array-remove" => toml_array_remove(case),
        "operations.v1.toml-conflict-atomic" => toml_conflict(case),
        "operations.v1.toml-dry-run-proof-patch" => toml_dry_run(case),
        "operations.v1.toml-structural-matrix" => toml_structural_matrix(case),
        "operations.v1.toml-conflict-matrix" => toml_conflict_matrix(case),
        "operations.v1.materialization-security-matrix" => materialization_security_matrix(case),
        "operations.v1.untouched-proof-tamper" => untouched_proof_tamper(case),
        _ => Err("runner does not recognize published operation case".to_owned()),
    }
}

fn registry_v3(case: &VectorCase<'_>) -> Result<(), String> {
    let v1 = RegistryManifest::v1();
    let v2 = RegistryManifest::v2();
    let v3 = RegistryManifest::v3();
    ensure(
        v3 == RegistryManifest::current()
            && v3.contracts().len() == expected_usize(case, "contract_count")?
            && v3.error_codes().len() == expected_usize(case, "error_code_count")?
            && v1.contracts().len() == expected_usize(case, "v1_contract_count")?
            && v1.error_codes().len() == expected_usize(case, "v1_error_code_count")?
            && v2.contracts().len() == expected_usize(case, "v2_contract_count")?
            && v2.error_codes().len() == expected_usize(case, "v2_error_code_count")?
            && RegistryManifest::from_value(&v3.to_value()).map_err(debug)? == v3,
    )
}

fn protocol_v3(case: &VectorCase<'_>) -> Result<(), String> {
    let target_profile = ProfileId::new("json.strict", 1);
    let digest = ContentDigest::of(b"unchanged");
    let conversion = ConversionReportMessage::new(
        ProfileId::new("toml.1.0", 1),
        target_profile.clone(),
        ConversionFidelityMessage::Exact,
        ProjectionReportMessage::default(),
        MaterializationFidelity::Exact,
        MaterializationReportMessage::default(),
        ConversionFidelityMessage::Exact,
    )
    .map_err(debug)?;
    let plan = EditPlanMessage::new(
        "source:one",
        digest,
        target_profile.clone(),
        Vec::new(),
        Vec::new(),
        digest,
        Vec::new(),
    )
    .map_err(debug)?;
    let operations = consema_json::format_operation_registry(JsonProfile::StrictV1);
    let request = json_request("json.canonical-compact", NewlinePolicy::None);
    let result = MaterializationResultMessage::failed(
        target_profile,
        MaterializationFailureMessage::UnsupportedStyle,
        MaterializationReportMessage::default(),
        Vec::new(),
    )
    .map_err(debug)?;
    let payloads = [
        ("core.conversion-report", conversion.to_value()),
        ("core.edit-plan", plan.to_value().map_err(debug)?),
        (
            "core.format-operation-registry",
            FormatOperationRegistryMessage::from_registry(&operations).to_value(),
        ),
        (
            "core.materialization-provenance-map",
            MaterializationProvenanceMapMessage::default().to_value(),
        ),
        (
            "core.materialization-report",
            MaterializationReportMessage::default().to_value(),
        ),
        (
            "core.materialization-request",
            MaterializationRequestMessage::from_request(&request)
                .to_value()
                .map_err(debug)?,
        ),
        ("core.materialization-result", result.to_value()),
    ];
    let limits = ProtocolLimits::default();
    let mut json_equal = true;
    let mut pvce_equal = true;
    for (id, payload) in &payloads {
        let message = ProtocolMessage::new(
            ContractId::new(*id, 1).map_err(debug)?,
            payload.clone(),
            ContractRegistry::v3(),
        )
        .map_err(debug)?;
        json_equal &= ProtocolMessage::from_json(
            &message.to_json(limits).map_err(debug)?,
            limits,
            ContractRegistry::v3(),
        )
        .map_err(debug)?
            == message;
        pvce_equal &= ProtocolMessage::from_pvce(
            &message.to_pvce(limits).map_err(debug)?,
            limits,
            ContractRegistry::v3(),
        )
        .map_err(debug)?
            == message;
    }
    ensure(
        payloads.len() == expected_usize(case, "new_payload_count")?
            && json_equal == expected_bool(case, "json_equal")?
            && pvce_equal == expected_bool(case, "pvce_equal")?,
    )
}

fn operation_registry(case: &VectorCase<'_>) -> Result<(), String> {
    let json = consema_json::format_operation_registry(JsonProfile::StrictV1);
    let toml = consema_toml::format_operation_registry(TomlProfile::Toml10V1);
    let required_json = expected_string(case, "required_json")?;
    let required_toml = expected_string(case, "required_toml")?;
    ensure(
        json.operations().len() == expected_usize(case, "json_operation_count")?
            && toml.operations().len() == expected_usize(case, "toml_operation_count")?
            && json
                .operations()
                .iter()
                .any(|operation| operation.id().to_string() == required_json)
            && toml
                .operations()
                .iter()
                .any(|operation| operation.id().to_string() == required_toml),
    )
}

fn materialize_json_success(case: &VectorCase<'_>) -> Result<(), String> {
    let source = input_string(case, "source")?;
    let document = consema_json::parse(
        source.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let target = match input_string_optional(case, "projection") {
        Some("BestExactCore") | None => JsonProjectionTarget::BestExactCoreV1,
        Some(other) => return Err(format!("unknown projection: {other}")),
    };
    let projected = json_project(&document, target)?;
    let style = input_string_optional(case, "style").unwrap_or("json.canonical-compact");
    let newline = parse_newline(input_string_optional(case, "newline").unwrap_or("None"))?;
    match consema_json::materialize(&projected, &json_request(style, newline)) {
        MaterializationResult::Complete(complete) => ensure(
            complete.document.render() == expected_string(case, "output")?.as_bytes()
                && fidelity_name(complete.fidelity) == expected_string(case, "fidelity")?
                && complete.provenance.entries().len()
                    >= expected_usize_optional(case, "minimum_provenance_entries").unwrap_or(0),
        ),
        MaterializationResult::Failed(failure) => Err(format!("unexpected failure: {failure:?}")),
    }
}

fn materialize_json_nonstring_failure(case: &VectorCase<'_>) -> Result<(), String> {
    let key = BigInteger::parse_decimal(input_string(case, "key_integer")?).map_err(debug)?;
    let mut mapping = EntryMappingBuilder::new();
    mapping.push(PortableValue::integer(key), PortableValue::boolean(true));
    materialize_json_failure(case, mapping.build(), MaterializationLimits::default())
}

fn materialize_json_float_failure(case: &VectorCase<'_>) -> Result<(), String> {
    let bits = u64::from_str_radix(input_string(case, "binary64_bits")?, 16)
        .map_err(|error| error.to_string())?;
    materialize_json_failure(
        case,
        PortableValue::binary_float64(BinaryFloat64::from_bits(bits)),
        MaterializationLimits::default(),
    )
}

fn materialize_json_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let value = json_project(&document, JsonProjectionTarget::BestExactCoreV1)?;
    materialize_json_failure(
        case,
        value,
        MaterializationLimits {
            max_output_bytes: input_usize(case, "max_output_bytes")?,
            ..MaterializationLimits::default()
        },
    )
}

fn materialize_json_failure(
    case: &VectorCase<'_>,
    value: PortableValue,
    limits: MaterializationLimits,
) -> Result<(), String> {
    let request = json_request("json.canonical-compact", NewlinePolicy::None).with_limits(limits);
    match consema_json::materialize(&value, &request) {
        MaterializationResult::Complete(_) => ensure(expected_bool(case, "has_document")?),
        MaterializationResult::Failed(failure) => ensure(
            failure.failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn materialize_toml_native(case: &VectorCase<'_>) -> Result<(), String> {
    let source = input_string(case, "source")?;
    let document = consema_toml::parse(
        source.as_bytes(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let value = toml_project(&document)?;
    match consema_toml::materialize(&value, &toml_request(MappingPolicy::RequireObject)) {
        MaterializationResult::Complete(complete) => {
            let reparsed = consema_toml::parse(
                complete.document.render(),
                TomlProfile::Toml10V1,
                ParseLimits::default(),
            )
            .map_err(debug)?;
            ensure(
                fidelity_name(complete.fidelity) == expected_string(case, "fidelity")?
                    && complete.provenance.entries().len()
                        >= expected_usize(case, "minimum_provenance_entries")?
                    && (toml_project(&reparsed)? == value)
                        == expected_bool(case, "reprojects_equal")?,
            )
        }
        MaterializationResult::Failed(failure) => Err(format!("unexpected failure: {failure:?}")),
    }
}

fn materialize_toml_mapping(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let value = json_project(&document, JsonProjectionTarget::ProjectAsEntryMappingV1)?;
    let policy = match input_string(case, "mapping_policy")? {
        "RequireObject" => MappingPolicy::RequireObject,
        "UniqueStringEntriesToObject" => MappingPolicy::UniqueStringEntriesToObject,
        other => return Err(format!("unknown mapping policy: {other}")),
    };
    match consema_toml::materialize(&value, &toml_request(policy)) {
        MaterializationResult::Complete(complete) => ensure(
            complete.document.render() == expected_string(case, "output")?.as_bytes()
                && fidelity_name(complete.fidelity) == expected_string(case, "fidelity")?
                && complete.report.events().iter().any(|event| {
                    event.code == expected_string(case, "event_code").unwrap_or_default()
                }),
        ),
        MaterializationResult::Failed(failure) => ensure(
            failure.failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn materialize_toml_failure(case: &VectorCase<'_>, value: PortableValue) -> Result<(), String> {
    match consema_toml::materialize(&value, &toml_request(MappingPolicy::RequireObject)) {
        MaterializationResult::Complete(_) => ensure(expected_bool(case, "has_document")?),
        MaterializationResult::Failed(failure) => ensure(
            failure.failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn materialize_toml_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_toml::parse(
        input_string(case, "source")?.as_bytes(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let value = toml_project(&document)?;
    let request = toml_request(MappingPolicy::RequireObject).with_limits(MaterializationLimits {
        max_output_bytes: input_usize(case, "max_output_bytes")?,
        ..MaterializationLimits::default()
    });
    match consema_toml::materialize(&value, &request) {
        MaterializationResult::Complete(_) => ensure(expected_bool(case, "has_document")?),
        MaterializationResult::Failed(failure) => ensure(
            failure.failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn materialization_depth_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let value = json_project(&document, JsonProjectionTarget::BestExactCoreV1)?;
    let request = json_request("json.canonical-compact", NewlinePolicy::None).with_limits(
        MaterializationLimits {
            max_depth: input_usize(case, "max_depth")?,
            ..MaterializationLimits::default()
        },
    );
    match consema_json::materialize(&value, &request) {
        MaterializationResult::Complete(_) => ensure(expected_bool(case, "has_document")?),
        MaterializationResult::Failed(failure) => ensure(
            failure.failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn convert_json_toml(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let projection = ProjectionRequestBuilder::new(JsonProjectionTarget::BestExactCoreV1)
        .build()
        .map_err(debug)?;
    match convert_json(
        &document,
        &projection,
        &toml_request(MappingPolicy::UniqueStringEntriesToObject),
    ) {
        ConversionResult::Complete(complete) => ensure(
            complete.document.render() == expected_string(case, "output")?.as_bytes()
                && conversion_fidelity_name(complete.report.overall_fidelity())
                    == expected_string(case, "overall_fidelity")?,
        ),
        ConversionResult::Failed(failure) => Err(format!("unexpected failure: {failure:?}")),
    }
}

fn convert_toml_json(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_toml::parse(
        input_string(case, "source")?.as_bytes(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    match convert_toml(
        &document,
        TomlProjectionRequest::new(TomlProjectionTarget::BestExactCoreV1),
        &json_request("json.canonical-compact", NewlinePolicy::None),
    ) {
        ConversionResult::Complete(complete) => ensure(
            complete.document.render() == expected_string(case, "output")?.as_bytes()
                && conversion_fidelity_name(complete.report.overall_fidelity())
                    == expected_string(case, "overall_fidelity")?,
        ),
        ConversionResult::Failed(failure) => Err(format!("unexpected failure: {failure:?}")),
    }
}

fn convert_duplicate_failure(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let projection = ProjectionRequestBuilder::new(JsonProjectionTarget::BestExactCoreV1)
        .build()
        .map_err(debug)?;
    match convert_json(
        &document,
        &projection,
        &toml_request(MappingPolicy::UniqueStringEntriesToObject),
    ) {
        ConversionResult::Complete(_) => ensure(expected_bool(case, "has_document")?),
        ConversionResult::Failed(failure) => ensure(
            failure.diagnostic_code() == expected_string(case, "code")?
                && !expected_bool(case, "has_document")?,
        ),
    }
}

fn convert_transformed(case: &VectorCase<'_>) -> Result<(), String> {
    let document = consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)?;
    let projection = ProjectionRequestBuilder::new(JsonProjectionTarget::ProjectAsEntryMappingV1)
        .build()
        .map_err(debug)?;
    match convert_json(
        &document,
        &projection,
        &toml_request(MappingPolicy::UniqueStringEntriesToObject),
    ) {
        ConversionResult::Complete(complete) => {
            let report = complete
                .protocol_report("source:json", "target:toml")
                .map_err(debug)?;
            ensure(
                conversion_message_fidelity_name(report.overall_fidelity())
                    == expected_string(case, "overall_fidelity")?
                    && report.projection_report().events().iter().any(|event| {
                        event.code == expected_string(case, "projection_event").unwrap_or_default()
                    })
                    && report
                        .materialization_report()
                        .events()
                        .iter()
                        .any(|event| {
                            event.code
                                == expected_string(case, "materialization_event")
                                    .unwrap_or_default()
                        }),
            )
        }
        ConversionResult::Failed(failure) => Err(format!("unexpected failure: {failure:?}")),
    }
}

fn json_object_insert(case: &VectorCase<'_>) -> Result<(), String> {
    let document = jsonc(case)?;
    let members = json_members(&document)?;
    let anchor = members[input_usize(case, "before_ordinal")?].node_ref();
    let mut builder = JsonEditBuilder::new(&document);
    builder.insert_member(
        document.root().node_ref(),
        input_string(case, "name")?,
        PortableValue::sequence(vec![PortableValue::boolean(true)]),
        AssociationPlacement::Before(anchor),
    );
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn json_object_remove(case: &VectorCase<'_>) -> Result<(), String> {
    let document = jsonc(case)?;
    let target = json_members(&document)?[input_usize(case, "target_ordinal")?].node_ref();
    let mut builder = JsonEditBuilder::new(&document);
    builder.remove_member(target);
    let commit = document.commit(&builder.build()).map_err(debug)?;
    verify_commit(
        case,
        document.source(),
        commit.document.source(),
        &commit.source_patch,
        &commit.untouched_proof,
        commit.document.render(),
    )
}

fn json_array_remove(case: &VectorCase<'_>) -> Result<(), String> {
    let document = jsonc(case)?;
    let elements = match document.root().array_elements() {
        SemanticAvailability::Available(Some(elements)) => elements,
        other => return Err(format!("expected array: {other:?}")),
    };
    let mut builder = JsonEditBuilder::new(&document);
    builder.remove_array_element(elements[input_usize(case, "target_ordinal")?].node_ref());
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn json_conflict(case: &VectorCase<'_>) -> Result<(), String> {
    let document = strict_json(case)?;
    let original = document.render().to_vec();
    let target = json_members(&document)?[input_usize(case, "target_ordinal")?].node_ref();
    let mut builder = JsonEditBuilder::new(&document);
    builder.rename_member(target, "x").remove_member(target);
    let failure = document.commit(&builder.build()).unwrap_err();
    ensure(
        failure.diagnostic_code() == expected_string(case, "code")?
            && (document.render() == original) == expected_bool(case, "base_unchanged")?,
    )
}

fn json_dry_run(case: &VectorCase<'_>) -> Result<(), String> {
    let document = strict_json(case)?;
    let secret_name = input_string(case, "name")?;
    let secret_value = input_string(case, "value")?;
    let mut builder = JsonEditBuilder::new(&document);
    builder.insert_member(
        document.root().node_ref(),
        secret_name,
        PortableValue::string(secret_value),
        AssociationPlacement::End,
    );
    let transaction = builder.build();
    let plan = document
        .dry_run(
            &transaction,
            EditPlanSourceId::new(input_string(case, "source_id")?).map_err(debug)?,
        )
        .map_err(debug)?;
    let commit = document.commit(&transaction).map_err(debug)?;
    let safe = plan
        .operations()
        .iter()
        .flat_map(|operation| operation.arguments().values())
        .all(|value| !value.contains("secret"));
    let redacted = plan
        .clone()
        .with_all_replacements_redacted(true, true)
        .map_err(debug)?;
    let verified = verify_commit(
        case,
        document.source(),
        commit.document.source(),
        &commit.source_patch,
        &commit.untouched_proof,
        commit.document.render(),
    )
    .is_ok();
    ensure(
        commit.document.render() == expected_string(case, "output")?.as_bytes()
            && (plan.replacements() == commit.source_patch.replacements())
                == expected_bool(case, "same_replacements")?
            && (plan.target_digest() == commit.source_patch.target_digest())
                == expected_bool(case, "same_target_digest")?
            && safe == expected_bool(case, "safe_summary")?
            && format!("{redacted:?}").contains("secret") != expected_bool(case, "redacted_debug")?
            && verified,
    )
}

fn json_structural_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.cases".to_owned())?;
    let mut completed = 0;
    for item in cases {
        let object = item
            .as_object()
            .ok_or("matrix item must be Object".to_owned())?;
        let operation = object_string(object, "operation")?;
        let document = consema_json::parse(
            object_string(object, "source")?.as_bytes(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .map_err(debug)?;
        let mut builder = JsonEditBuilder::new(&document);
        match operation {
            "insert-member-end" => {
                builder.insert_member(
                    document.root().node_ref(),
                    object_string(object, "name")?,
                    PortableValue::boolean(true),
                    AssociationPlacement::End,
                );
            }
            "remove-member" => {
                let target =
                    json_members(&document)?[object_usize(object, "target_ordinal")?].node_ref();
                builder.remove_member(target);
            }
            "rename-member" => {
                let target =
                    json_members(&document)?[object_usize(object, "target_ordinal")?].node_ref();
                builder.rename_member(target, object_string(object, "name")?);
            }
            "insert-array-start" => {
                builder.insert_array_element(
                    document.root().node_ref(),
                    PortableValue::integer(BigInteger::from(1_i64)),
                    AssociationPlacement::Start,
                );
            }
            "insert-array-after" => {
                let elements = match document.root().array_elements() {
                    SemanticAvailability::Available(Some(elements)) => elements,
                    other => return Err(format!("expected array: {other:?}")),
                };
                builder.insert_array_element(
                    document.root().node_ref(),
                    PortableValue::string("x"),
                    AssociationPlacement::After(
                        elements[object_usize(object, "anchor_ordinal")?].node_ref(),
                    ),
                );
            }
            other => return Err(format!("unknown JSON matrix operation: {other}")),
        }
        let commit = document.commit(&builder.build()).map_err(debug)?;
        if commit.document.render() != object_string(object, "expected")?.as_bytes() {
            return Err(format!("JSON matrix output mismatch for {operation}"));
        }
        completed += 1;
    }
    ensure(completed == expected_usize(case, "completed")?)
}

fn json_conflict_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.cases".to_owned())?;
    let mut failed_atomically = 0;
    for item in cases {
        let object = item
            .as_object()
            .ok_or("matrix item must be Object".to_owned())?;
        let mode = object_string(object, "mode")?;
        let document = consema_json::parse(
            object_string(object, "source")?.as_bytes(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .map_err(debug)?;
        let original = document.render().to_vec();
        let failure = match mode {
            "wrong-snapshot" => {
                let foreign = consema_json::parse(
                    object_string(object, "foreign")?.as_bytes(),
                    JsonProfile::StrictV1,
                    ParseLimits::default(),
                )
                .map_err(debug)?;
                let mut builder = JsonEditBuilder::new(&document);
                builder.literal_scalar(foreign.root().node_ref(), b"3".as_slice());
                document.commit(&builder.build()).unwrap_err()
            }
            "same-boundary" => {
                let mut builder = JsonEditBuilder::new(&document);
                builder
                    .insert_member(
                        document.root().node_ref(),
                        "x",
                        PortableValue::boolean(true),
                        AssociationPlacement::End,
                    )
                    .insert_member(
                        document.root().node_ref(),
                        "y",
                        PortableValue::boolean(false),
                        AssociationPlacement::End,
                    );
                document.commit(&builder.build()).unwrap_err()
            }
            "removed-anchor" => {
                let member = json_members(&document)?[0];
                let mut builder = JsonEditBuilder::new(&document);
                builder.remove_member(member.node_ref()).insert_member(
                    document.root().node_ref(),
                    "x",
                    PortableValue::boolean(true),
                    AssociationPlacement::Before(member.node_ref()),
                );
                document.commit(&builder.build()).unwrap_err()
            }
            "ancestor-descendant" => {
                let member = json_members(&document)?[0];
                let mut builder = JsonEditBuilder::new(&document);
                builder
                    .semantic_scalar(
                        member.value_node_ref(),
                        PortableValue::integer(BigInteger::from(3_i64)),
                        consema_json::RepresentationPolicy::PreserveCompatible,
                    )
                    .remove_member(member.node_ref());
                document.commit(&builder.build()).unwrap_err()
            }
            other => return Err(format!("unknown JSON conflict mode: {other}")),
        };
        if failure.diagnostic_code() != object_string(object, "code")?
            || document.render() != original
        {
            return Err(format!("JSON conflict mismatch for {mode}"));
        }
        failed_atomically += 1;
    }
    ensure(failed_atomically == expected_usize(case, "failed_atomically")?)
}

fn toml_root_insert(case: &VectorCase<'_>) -> Result<(), String> {
    let document = toml_document(case)?;
    let mut builder = TomlEditBuilder::new(&document);
    builder.insert_entry(
        document.root().node_ref(),
        input_string(case, "key")?,
        PortableValue::boolean(true),
        AssociationPlacement::End,
    );
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn toml_inline_rename(case: &VectorCase<'_>) -> Result<(), String> {
    let document = toml_document(case)?;
    let table = toml_root_entry(&document, input_string(case, "table")?)?.item();
    let entries = table
        .table_entries()
        .ok_or("expected inline table".to_owned())?;
    let mut builder = TomlEditBuilder::new(&document);
    builder.rename_entry(
        entries[input_usize(case, "target_ordinal")?].node_ref(),
        input_string(case, "key")?,
    );
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn toml_array_remove(case: &VectorCase<'_>) -> Result<(), String> {
    let document = toml_document(case)?;
    let array = toml_root_entry(&document, input_string(case, "array")?)?.item();
    let elements = array.array_elements().ok_or("expected array".to_owned())?;
    let mut builder = TomlEditBuilder::new(&document);
    builder.remove_array_element(elements[input_usize(case, "target_ordinal")?].node_ref());
    let commit = document.commit(&builder.build()).map_err(debug)?;
    ensure(commit.document.render() == expected_string(case, "output")?.as_bytes())
}

fn toml_conflict(case: &VectorCase<'_>) -> Result<(), String> {
    let document = toml_document(case)?;
    let original = document.render().to_vec();
    let mut builder = TomlEditBuilder::new(&document);
    builder.insert_entry(
        document.root().node_ref(),
        input_string(case, "key")?,
        PortableValue::boolean(true),
        AssociationPlacement::Start,
    );
    let failure = document.commit(&builder.build()).unwrap_err();
    ensure(
        failure.diagnostic_code() == expected_string(case, "code")?
            && (document.render() == original) == expected_bool(case, "base_unchanged")?,
    )
}

fn toml_dry_run(case: &VectorCase<'_>) -> Result<(), String> {
    let document = toml_document(case)?;
    let key = input_string(case, "key")?;
    let value = input_string(case, "value")?;
    let mut builder = TomlEditBuilder::new(&document);
    builder.insert_entry(
        document.root().node_ref(),
        key,
        PortableValue::string(value),
        AssociationPlacement::End,
    );
    let transaction = builder.build();
    let plan = document
        .dry_run(
            &transaction,
            EditPlanSourceId::new(input_string(case, "source_id")?).map_err(debug)?,
        )
        .map_err(debug)?;
    let commit = document.commit(&transaction).map_err(debug)?;
    let safe = plan
        .operations()
        .iter()
        .flat_map(|operation| operation.arguments().values())
        .all(|value| !value.contains("secret"));
    let redacted = plan
        .clone()
        .with_all_replacements_redacted(true, true)
        .map_err(debug)?;
    let verified = verify_commit(
        case,
        document.source(),
        commit.document.source(),
        &commit.source_patch,
        &commit.untouched_proof,
        commit.document.render(),
    )
    .is_ok();
    ensure(
        commit.document.render() == expected_string(case, "output")?.as_bytes()
            && (plan.replacements() == commit.source_patch.replacements())
                == expected_bool(case, "same_replacements")?
            && (plan.target_digest() == commit.source_patch.target_digest())
                == expected_bool(case, "same_target_digest")?
            && safe == expected_bool(case, "safe_summary")?
            && format!("{redacted:?}").contains("secret") != expected_bool(case, "redacted_debug")?
            && verified,
    )
}

fn toml_structural_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.cases".to_owned())?;
    let mut completed = 0;
    for item in cases {
        let object = item
            .as_object()
            .ok_or("matrix item must be Object".to_owned())?;
        let operation = object_string(object, "operation")?;
        let document = consema_toml::parse(
            object_string(object, "source")?.as_bytes(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .map_err(debug)?;
        let mut builder = TomlEditBuilder::new(&document);
        match operation {
            "insert-standard-table" => {
                let table = toml_root_entry(&document, object_string(object, "table")?)?.item();
                builder.insert_entry(
                    table.node_ref(),
                    object_string(object, "key")?,
                    PortableValue::string("localhost"),
                    AssociationPlacement::End,
                );
            }
            "insert-inline" => {
                let table = toml_root_entry(&document, object_string(object, "table")?)?.item();
                let entries = table
                    .table_entries()
                    .ok_or("expected inline table".to_owned())?;
                builder.insert_entry(
                    table.node_ref(),
                    object_string(object, "key")?,
                    PortableValue::sequence(vec![PortableValue::boolean(true)]),
                    AssociationPlacement::Before(
                        entries[object_usize(object, "before_ordinal")?].node_ref(),
                    ),
                );
            }
            "remove-inline" => {
                let table = toml_root_entry(&document, object_string(object, "table")?)?.item();
                let entries = table
                    .table_entries()
                    .ok_or("expected inline table".to_owned())?;
                builder.remove_entry(entries[object_usize(object, "target_ordinal")?].node_ref());
            }
            "insert-array-start" => {
                let array = toml_root_entry(&document, object_string(object, "array")?)?.item();
                builder.insert_array_element(
                    array.node_ref(),
                    PortableValue::integer(BigInteger::from(1_i64)),
                    AssociationPlacement::Start,
                );
            }
            other => return Err(format!("unknown TOML matrix operation: {other}")),
        }
        let commit = document.commit(&builder.build()).map_err(debug)?;
        if commit.document.render() != object_string(object, "expected")?.as_bytes() {
            return Err(format!("TOML matrix output mismatch for {operation}"));
        }
        completed += 1;
    }
    ensure(completed == expected_usize(case, "completed")?)
}

fn toml_conflict_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.cases".to_owned())?;
    let mut failed_atomically = 0;
    for item in cases {
        let object = item
            .as_object()
            .ok_or("matrix item must be Object".to_owned())?;
        let mode = object_string(object, "mode")?;
        let document = consema_toml::parse(
            object_string(object, "source")?.as_bytes(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .map_err(debug)?;
        let original = document.render().to_vec();
        let failure = match mode {
            "duplicate-target" => {
                let entry = toml_root_entry(&document, "a")?;
                let mut builder = TomlEditBuilder::new(&document);
                builder
                    .rename_entry(entry.node_ref(), "x")
                    .remove_entry(entry.node_ref());
                document.commit(&builder.build()).unwrap_err()
            }
            "removed-anchor" => {
                let entry = toml_root_entry(&document, "a")?;
                let mut builder = TomlEditBuilder::new(&document);
                builder.remove_entry(entry.node_ref()).insert_entry(
                    document.root().node_ref(),
                    "x",
                    PortableValue::boolean(true),
                    AssociationPlacement::Before(entry.node_ref()),
                );
                document.commit(&builder.build()).unwrap_err()
            }
            "ancestor-descendant" => {
                let entry = toml_root_entry(&document, "a")?;
                let mut builder = TomlEditBuilder::new(&document);
                builder
                    .semantic_scalar(
                        entry.item_node_ref(),
                        PortableValue::integer(BigInteger::from(3_i64)),
                        consema_toml::RepresentationPolicy::PreserveCompatible,
                    )
                    .remove_entry(entry.node_ref());
                document.commit(&builder.build()).unwrap_err()
            }
            "unsupported-table-remove" => {
                let entry = toml_root_entry(&document, "service")?;
                let mut builder = TomlEditBuilder::new(&document);
                builder.remove_entry(entry.node_ref());
                document.commit(&builder.build()).unwrap_err()
            }
            other => return Err(format!("unknown TOML conflict mode: {other}")),
        };
        if failure.diagnostic_code() != object_string(object, "code")?
            || document.render() != original
        {
            return Err(format!("TOML conflict mismatch for {mode}"));
        }
        failed_atomically += 1;
    }
    ensure(failed_atomically == expected_usize(case, "failed_atomically")?)
}

fn materialization_security_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.cases".to_owned())?;
    let mut completed = 0;
    for item in cases {
        let object = item
            .as_object()
            .ok_or("matrix item must be Object".to_owned())?;
        let mode = object_string(object, "mode")?;
        let document = consema_json::parse(
            object_string(object, "source")?.as_bytes(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .map_err(debug)?;
        let value = json_project(&document, JsonProjectionTarget::BestExactCoreV1)?;
        match mode {
            "node-limit" | "provenance-limit" => {
                let limit = object_usize(object, "limit")?;
                let limits = if mode == "node-limit" {
                    MaterializationLimits {
                        max_input_nodes: limit,
                        ..MaterializationLimits::default()
                    }
                } else {
                    MaterializationLimits {
                        max_provenance_entries: limit,
                        ..MaterializationLimits::default()
                    }
                };
                let request =
                    json_request("json.canonical-compact", NewlinePolicy::None).with_limits(limits);
                let MaterializationResult::Failed(failure) =
                    consema_json::materialize(&value, &request)
                else {
                    return Err(format!("security case {mode} unexpectedly completed"));
                };
                if failure.failure.diagnostic_code() != object_string(object, "code")? {
                    return Err(format!("security code mismatch for {mode}"));
                }
            }
            "escaping" => {
                let MaterializationResult::Complete(complete) = consema_json::materialize(
                    &value,
                    &json_request("json.canonical-compact", NewlinePolicy::None),
                ) else {
                    return Err("escaping case unexpectedly failed".to_owned());
                };
                if complete.document.render() != object_string(object, "expected")?.as_bytes() {
                    return Err("escaping output mismatch".to_owned());
                }
            }
            other => return Err(format!("unknown security mode: {other}")),
        }
        completed += 1;
    }
    ensure(completed == expected_usize(case, "completed")?)
}

fn untouched_proof_tamper(case: &VectorCase<'_>) -> Result<(), String> {
    let document = strict_json(case)?;
    let member = json_members(&document)?[0];
    let mut builder = JsonEditBuilder::new(&document);
    builder.semantic_scalar(
        member.value_node_ref(),
        PortableValue::integer(BigInteger::from(2_i64)),
        consema_json::RepresentationPolicy::PreserveCompatible,
    );
    let commit = document.commit(&builder.build()).map_err(debug)?;
    let tampered = consema_document::SourceSnapshot::from_utf8(
        input_string(case, "tampered_target")?.as_bytes(),
    )
    .map_err(debug)?;
    ensure(
        commit
            .untouched_proof
            .verify(
                document.source(),
                &tampered,
                commit.source_patch.replacements(),
            )
            .is_err()
            == expected_bool(case, "tamper_detected")?,
    )
}

fn verify_commit(
    case: &VectorCase<'_>,
    base: &consema_document::SourceSnapshot,
    target: &consema_document::SourceSnapshot,
    patch: &consema_document::SourcePatch,
    proof: &consema_document::UntouchedByteProof,
    output: &[u8],
) -> Result<(), String> {
    let replay = patch
        .apply(base, SourcePatchLimits::default())
        .map_err(debug)?;
    let patch_replays = replay.bytes() == output;
    let proof_verifies = proof.verify(base, target, patch.replacements()).is_ok();
    ensure(
        output == expected_string(case, "output")?.as_bytes()
            && patch_replays == expected_bool(case, "patch_replays")?
            && proof_verifies == expected_bool(case, "proof_verifies")?,
    )
}

fn json_request(style: &str, newline: NewlinePolicy) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new(style, 1),
    )
    .with_newline(newline)
}

fn toml_request(mapping_policy: MappingPolicy) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("toml.1.0", 1),
        MaterializationStyleId::new("toml.canonical-document", 1),
    )
    .with_newline(NewlinePolicy::Lf)
    .with_mapping_policy(mapping_policy)
}

fn json_project(
    document: &consema_json::Document,
    target: JsonProjectionTarget,
) -> Result<PortableValue, String> {
    let request = ProjectionRequestBuilder::new(target)
        .build()
        .map_err(debug)?;
    match document.project(&request) {
        JsonProjectionResult::Complete(complete) => Ok(complete.value),
        JsonProjectionResult::Failed(failure) => Err(format!("{failure:?}")),
    }
}

fn toml_project(document: &consema_toml::Document) -> Result<PortableValue, String> {
    match document.project(TomlProjectionRequest::new(
        TomlProjectionTarget::BestExactCoreV1,
    )) {
        TomlProjectionResult::Complete(complete) => Ok(complete.value),
        TomlProjectionResult::Failed(failure) => Err(format!("{failure:?}")),
    }
}

fn strict_json(case: &VectorCase<'_>) -> Result<consema_json::Document, String> {
    consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .map_err(debug)
}

fn jsonc(case: &VectorCase<'_>) -> Result<consema_json::Document, String> {
    consema_json::parse(
        input_string(case, "source")?.as_bytes(),
        JsonProfile::JsoncBoundedV1,
        ParseLimits::default(),
    )
    .map_err(debug)
}

fn toml_document(case: &VectorCase<'_>) -> Result<consema_toml::Document, String> {
    consema_toml::parse(
        input_string(case, "source")?.as_bytes(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .map_err(debug)
}

fn json_members(
    document: &consema_json::Document,
) -> Result<Vec<consema_json::JsonObjectMember<'_>>, String> {
    match document.root().object_members() {
        SemanticAvailability::Available(Some(members)) => Ok(members),
        other => Err(format!("expected object: {other:?}")),
    }
}

fn toml_root_entry<'a>(
    document: &'a consema_toml::Document,
    name: &str,
) -> Result<consema_toml::TomlEntry<'a>, String> {
    document
        .root()
        .table_entries()
        .expect("root table")
        .into_iter()
        .find(|entry| entry.name() == name)
        .ok_or_else(|| format!("missing root entry: {name}"))
}

const fn fidelity_name(fidelity: MaterializationFidelity) -> &'static str {
    match fidelity {
        MaterializationFidelity::Exact => "Exact",
        MaterializationFidelity::Transformed => "Transformed",
    }
}

const fn conversion_fidelity_name(fidelity: consema::ConversionFidelity) -> &'static str {
    match fidelity {
        consema::ConversionFidelity::Exact => "Exact",
        consema::ConversionFidelity::Transformed => "Transformed",
        consema::ConversionFidelity::Lossy => "Lossy",
    }
}

const fn conversion_message_fidelity_name(fidelity: ConversionFidelityMessage) -> &'static str {
    match fidelity {
        ConversionFidelityMessage::Exact => "Exact",
        ConversionFidelityMessage::Transformed => "Transformed",
        ConversionFidelityMessage::Lossy => "Lossy",
    }
}

fn parse_newline(value: &str) -> Result<NewlinePolicy, String> {
    match value {
        "None" => Ok(NewlinePolicy::None),
        "Lf" => Ok(NewlinePolicy::Lf),
        "CrLf" => Ok(NewlinePolicy::CrLf),
        _ => Err(format!("unknown newline: {value}")),
    }
}

fn object_field<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Option<&'a PortableValue> {
    entries
        .iter()
        .find(|entry| entry.key() == key)
        .map(consema_core::ObjectEntry::value)
}

fn object_string<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Result<&'a str, String> {
    object_field(entries, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing matrix field: {key}"))
}

fn object_usize(entries: &[consema_core::ObjectEntry], key: &str) -> Result<usize, String> {
    usize_value(object_field(entries, key), key)
}

fn input_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.input
        .as_object()
        .and_then(|entries| object_field(entries, key))
}

fn expected_field<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a PortableValue> {
    case.expected
        .as_object()
        .and_then(|entries| object_field(entries, key))
}

fn input_string<'a>(case: &VectorCase<'a>, key: &str) -> Result<&'a str, String> {
    input_field(case, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing input.{key}"))
}

fn input_string_optional<'a>(case: &VectorCase<'a>, key: &str) -> Option<&'a str> {
    input_field(case, key).and_then(PortableValue::as_string)
}

fn expected_string<'a>(case: &VectorCase<'a>, key: &str) -> Result<&'a str, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing expected.{key}"))
}

fn input_usize(case: &VectorCase<'_>, key: &str) -> Result<usize, String> {
    usize_value(input_field(case, key), &format!("input.{key}"))
}

fn expected_usize(case: &VectorCase<'_>, key: &str) -> Result<usize, String> {
    usize_value(expected_field(case, key), &format!("expected.{key}"))
}

fn expected_usize_optional(case: &VectorCase<'_>, key: &str) -> Option<usize> {
    usize_value(expected_field(case, key), key).ok()
}

fn usize_value(value: Option<&PortableValue>, path: &str) -> Result<usize, String> {
    value
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_i64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("missing or invalid {path}"))
}

fn expected_bool(case: &VectorCase<'_>, key: &str) -> Result<bool, String> {
    expected_field(case, key)
        .and_then(PortableValue::as_boolean)
        .ok_or_else(|| format!("missing expected.{key}"))
}

fn ensure(condition: bool) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err("expected behavior did not match".to_owned())
    }
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_operations_v1_suite_is_conformant() {
        let report = run_operations_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 35);
    }

    #[test]
    fn operation_vectors_drive_expected_output() {
        let changed = OPERATIONS_V1_VECTORS_JSON.replacen(
            "{\\\"a\\\":1,\\\"secret-name\\\":\\\"secret-value\\\"}",
            "{\\\"a\\\":1}",
            1,
        );
        assert!(!run_operations_v1_json(&changed).is_conformant());
    }
}
