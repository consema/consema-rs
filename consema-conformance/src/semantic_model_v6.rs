//! Language-neutral semantic-model v6 line-format protocol runner.

use std::collections::{BTreeMap, HashSet};

use consema_core::{
    BigInteger, MatchRole, ObjectBuilder, PortableValue, QueryDomain, SequenceBuilder,
};
use consema_document::{
    BomPolicy, ContentDigest, DecodedOffset, DocumentAuthority, EncodingRequest,
    MaterializationFidelity, MaterializationRequest, MaterializationStyleId, NewlinePolicy,
    NodeRole, ProfileId, SourceEncoding, SourceLimits, SourcePatch, SourcePatchLimits,
    SourceReplacement, SourceSnapshot, WindowsCodePage,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{
    Completion, CompletionStatus, ContractId, ContractRegistry, ErrorCodeRegistry, IniMatchLocator,
    IniQueryResultMessage, JavaPropertiesMatchLocator, JavaPropertiesQueryResultMessage,
    JavaUnicodeStatus, JavaUtf16String, MaterializationProvenanceMapMessage,
    MaterializationReportMessage, MaterializationRequestMessageV2, MaterializationResultMessageV2,
    ProtocolError, ProtocolLimits, ProtocolMessage, RegistryManifest, SourceEncodingMessage,
    SourcePatchMessageV2, SourceSnapshotMessage, SourceSnapshotMessageV2,
};

use super::{ConformanceReport, VectorCase, object_field};

const SUITE: &str = "consema.semantic-model-v6.conformance@1";

/// Embedded language-neutral semantic-model v6 suite bytes.
pub const SEMANTIC_MODEL_V6_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/semantic-model-v6.json");

const V5_VECTORS: &str = include_str!("../../../conformance/vectors/semantic-model-v5.json");
const PROTOCOL_V2_VECTORS: &str = include_str!("../../../conformance/vectors/protocol-v2.json");
const SOURCE_V1_VECTORS: &str = include_str!("../../../conformance/vectors/source-v1.json");

/// Runs the embedded semantic-model v6 suite.
#[must_use]
pub fn run_semantic_model_v6() -> ConformanceReport {
    run_semantic_model_v6_json(SEMANTIC_MODEL_V6_VECTORS_JSON)
}

/// Runs one semantic-model v6 suite from strict JSON text.
#[must_use]
pub fn run_semantic_model_v6_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published semantic-model v6 vectors must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("semantic-model v6 vector root");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let semantic_model = object_field(root, "semantic_model")
        .and_then(PortableValue::as_string)
        .unwrap_or_default();
    if suite != SUITE || semantic_model != "core.semantic-model@6" {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "unexpected suite or semantic-model identifier".to_owned(),
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
    for case in cases {
        let fields = case.as_object().expect("semantic-model v6 case object");
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
    let required = match case.id {
        id if id.starts_with("registry.") && id != "registry.v6-error-codes" => {
            "core.registry-manifest@1"
        }
        "registry.v6-error-codes" => "core.error-code-registry@1",
        id if id.starts_with("source-encoding.") => "core.source-encoding@1",
        id if id.starts_with("source.snapshot") || id == "source.bom-policy-distinct" => {
            "core.source-snapshot@2"
        }
        "source.patch-v2-atomic-apply" => "core.source-patch@2",
        "materialization.request-v2-roundtrip" => "core.materialization-request@2",
        "materialization.result-v2-version-closure" => "core.materialization-result@2",
        id if id.starts_with("java-utf16.") => "core.java-utf16-string@1",
        "ini-query.all-roles"
        | "line-query.reject-domain-role"
        | "line-query.reject-process-local" => "core.ini-query-result@1",
        "properties-query.all-roles" | "line-query.reject-ordinal-and-count" => {
            "core.java-properties-query-result@1"
        }
        id if id.starts_with("protocol.") => {
            if id == "protocol.new-payload-schema-and-limits" {
                "core.java-utf16-string@1"
            } else {
                "core.protocol-message@1"
            }
        }
        _ => return Err("runner does not recognize published v6 case".to_owned()),
    };
    if case.capability != required {
        return Err(format!("expected capability {required}"));
    }
    match case.id {
        "registry.v6-manifest" => registry_manifest(case),
        "registry.v1-v5-frozen" => registry_frozen(case),
        "registry.v6-additive-contracts" => registry_contracts(case),
        "registry.v6-error-codes" => registry_errors(case),
        "source-encoding.mandatory-code-pages" => source_code_pages(case),
        "source-encoding.reject-unsupported" => source_reject_code_page(case),
        "source.bom-policy-distinct" => source_bom_policy(case),
        "source.snapshot-v2-code-page-boundaries" => source_boundaries(case),
        "source.snapshot-v2-reject-digest" => source_digest(case),
        "source.patch-v2-atomic-apply" => source_patch(case),
        "materialization.request-v2-roundtrip" => materialization_request(case),
        "materialization.result-v2-version-closure" => materialization_result(case),
        "java-utf16.edge-matrix" => java_matrix(case),
        "java-utf16.reject-noncanonical-unit" | "java-utf16.reject-byte-mismatch" => {
            java_rejection(case)
        }
        "ini-query.all-roles" => ini_roles(case),
        "properties-query.all-roles" => properties_roles(case),
        "line-query.reject-domain-role" => line_domain_rejection(case),
        "line-query.reject-ordinal-and-count" => line_ordinal_rejection(case),
        "line-query.reject-process-local" => line_process_local(case),
        "protocol.v1-v5-reject-v6-contracts" => protocol_old_rejection(case),
        "protocol.exact-version-dispatch" => protocol_version_dispatch(case),
        "protocol.v6-nested-error-code" => protocol_nested_error(case),
        "protocol.new-contract-canonical-bytes" => protocol_canonical_bytes(case),
        "protocol.new-payload-schema-and-limits" => protocol_schema_limits(case),
        _ => Err("runner does not recognize published v6 case".to_owned()),
    }
}

fn registry_manifest(case: &VectorCase<'_>) -> Result<(), String> {
    let manifest = RegistryManifest::v6();
    let decoded = RegistryManifest::from_value(&manifest.to_value()).map_err(string_error)?;
    require(
        manifest.semantic_model().schema() == expected_string(case, "semantic_model")?
            && manifest.contracts().len() == expected_usize(case, "contract_count")?
            && manifest.error_codes().len() == expected_usize(case, "error_code_count")?
            && manifest.is_current()
            && decoded == manifest,
        "v6 manifest facts differ",
    )
}

fn registry_frozen(case: &VectorCase<'_>) -> Result<(), String> {
    let manifests = [
        RegistryManifest::v1(),
        RegistryManifest::v2(),
        RegistryManifest::v3(),
        RegistryManifest::v4(),
        RegistryManifest::v5(),
    ];
    let contracts = expected_usize_sequence(case, "contract_counts")?;
    let errors = expected_usize_sequence(case, "error_code_counts")?;
    let counts_match = manifests.iter().zip(contracts.iter().zip(&errors)).all(
        |(manifest, (contracts, errors))| {
            manifest.contracts().len() == *contracts
                && manifest.error_codes().len() == *errors
                && RegistryManifest::from_value(&manifest.to_value()).is_ok()
        },
    );
    let expected_vectors = input_field(case, "previous_vectors")?
        .as_sequence()
        .ok_or("input.previous_vectors must be Sequence")?;
    let previous = [
        ("semantic-model-v5", V5_VECTORS),
        ("protocol-v2", PROTOCOL_V2_VECTORS),
        ("source-v1", SOURCE_V1_VECTORS),
    ];
    let vectors_match = expected_vectors.len() == previous.len()
        && expected_vectors
            .iter()
            .zip(previous)
            .all(|(expected, actual)| {
                let Some(fields) = expected.as_object() else {
                    return false;
                };
                object_string(fields, "name").ok() == Some(actual.0)
                    && object_string(fields, "sha256").ok()
                        == Some(ContentDigest::of(actual.1.as_bytes()).to_hex().as_str())
            });
    require(
        counts_match && vectors_match,
        "a frozen registry or vector changed",
    )
}

fn registry_contracts(case: &VectorCase<'_>) -> Result<(), String> {
    let old = ContractRegistry::v5();
    let current = ContractRegistry::v6();
    let additions = expected_string_sequence(case, "contracts")?;
    require(
        additions.iter().all(|schema| {
            parse_contract(schema)
                .is_ok_and(|contract| !old.recognizes(&contract) && current.recognizes(&contract))
        }) && current.contracts().len() == old.contracts().len() + additions.len(),
        "v6 contract additions differ",
    )
}

fn registry_errors(case: &VectorCase<'_>) -> Result<(), String> {
    let old = ErrorCodeRegistry::v5();
    let current = ErrorCodeRegistry::v6();
    let additions = expected_string_sequence(case, "new_codes")?;
    require(
        current.codes().len() == expected_usize(case, "error_code_count")?
            && additions.len() == 34
            && additions.iter().all(|code| {
                !old.contains(code)
                    && current.descriptor(code).is_some_and(|descriptor| {
                        descriptor.introduced == "0.8.0" && !descriptor.description.is_empty()
                    })
            }),
        "v6 error-code additions differ",
    )
}

fn source_code_pages(case: &VectorCase<'_>) -> Result<(), String> {
    let pages = input_u16_sequence(case, "code_pages")?;
    let mut accepted = 0;
    for page in pages {
        let encoding = SourceEncoding::WindowsCodePage(
            WindowsCodePage::from_number(page).ok_or("published code page rejected")?,
        );
        let message = SourceEncodingMessage::from_encoding(encoding);
        if SourceEncodingMessage::from_value(&message.to_value())
            .map_err(string_error)?
            .encoding()
            == encoding
        {
            accepted += 1;
        }
    }
    require(
        accepted == expected_usize(case, "accepted_count")?,
        "mandatory code-page count differed",
    )
}

fn source_reject_code_page(case: &VectorCase<'_>) -> Result<(), String> {
    let value = object(vec![
        ("schema", PortableValue::string("core.source-encoding@1")),
        ("kind", PortableValue::string("WindowsCodePage")),
        (
            "windows_code_page",
            PortableValue::integer(BigInteger::from(i64::from(input_u16(case, "code_page")?))),
        ),
    ])?;
    expect_error(
        SourceEncodingMessage::from_value(&value),
        expected_string(case, "code")?,
        None,
    )
}

fn source_bom_policy(case: &VectorCase<'_>) -> Result<(), String> {
    let bytes = decode_hex(input_string(case, "hex")?)?;
    let detected = SourceSnapshot::from_raw(
        bytes.clone(),
        EncodingRequest::new(SourceEncoding::Latin1),
        SourceLimits::default(),
    )
    .map_err(string_error)?;
    let content = SourceSnapshot::from_raw(
        bytes,
        EncodingRequest::new(SourceEncoding::Latin1).with_bom_policy(BomPolicy::TreatAsContent),
        SourceLimits::default(),
    )
    .map_err(string_error)?;
    dual_roundtrip(
        ContractId::new("core.source-snapshot", 2).map_err(string_error)?,
        SourceSnapshotMessageV2::from_snapshot(&detected).to_value(),
    )?;
    dual_roundtrip(
        ContractId::new("core.source-snapshot", 2).map_err(string_error)?,
        SourceSnapshotMessageV2::from_snapshot(&content).to_value(),
    )?;
    require(
        detected.decoded_text() == Some(expected_string(case, "detect_text")?)
            && content.decoded_text() == Some(expected_string(case, "content_text")?)
            && detected.encoding_facts().bom_policy() == BomPolicy::DetectUnicode
            && content.encoding_facts().bom_policy() == BomPolicy::TreatAsContent,
        "BOM policies did not remain distinct",
    )
}

fn source_boundaries(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = code_page_snapshot(
        input_u16(case, "code_page")?,
        &decode_hex(input_string(case, "hex")?)?,
    )?;
    let payload = SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value();
    let decoded = SourceSnapshotMessageV2::from_value(&payload, SourceLimits::default())
        .map_err(string_error)?;
    let boundaries = expected_usize_sequence(case, "raw_boundaries")?;
    require(
        decoded.snapshot().decoded_text() == Some(expected_string(case, "text")?)
            && boundaries
                .iter()
                .all(|boundary| decoded.snapshot().decoded_position(*boundary).is_ok())
            && decoded
                .snapshot()
                .decoded_position(expected_usize(case, "invalid_raw_boundary")?)
                .is_err()
            && decoded
                .snapshot()
                .raw_byte_at(DecodedOffset::UnicodeScalar(1))
                == Ok(2),
        "code-page boundaries differed",
    )
}

fn source_digest(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = code_page_snapshot(
        input_u16(case, "code_page")?,
        &decode_hex(input_string(case, "hex")?)?,
    )?;
    let encoded = SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value();
    let digest = encoded
        .as_object()
        .and_then(|fields| object_field(fields, "digest"))
        .ok_or("missing digest")?;
    let value = replace_field(
        &encoded,
        "digest",
        replace_field(digest, "hex", PortableValue::string("0".repeat(64)))?,
    )?;
    expect_error(
        SourceSnapshotMessageV2::from_value(&value, SourceLimits::default()),
        expected_string(case, "code")?,
        Some("$.digest"),
    )
}

fn source_patch(case: &VectorCase<'_>) -> Result<(), String> {
    let base = code_page_snapshot(
        input_u16(case, "code_page")?,
        &decode_hex(input_string(case, "base_hex")?)?,
    )?;
    let replacement = SourceReplacement::new(
        input_usize(case, "start")?,
        input_usize(case, "end")?,
        base.bytes()[input_usize(case, "start")?..input_usize(case, "end")?].to_vec(),
        decode_hex(input_string(case, "replacement_hex")?)?,
    );
    let patch = SourcePatch::create(
        &base,
        vec![replacement],
        BTreeMap::new(),
        SourcePatchLimits::default(),
    )
    .map_err(string_error)?;
    let wire = SourcePatchMessageV2::from_patch(&patch)
        .to_value()
        .map_err(string_error)?;
    let decoded = SourcePatchMessageV2::from_value(&wire, SourcePatchLimits::default())
        .map_err(string_error)?;
    let target = decoded
        .patch()
        .apply(&base, SourcePatchLimits::default())
        .map_err(string_error)?;
    let wrong = code_page_snapshot(input_u16(case, "code_page")?, b"wrong")?;
    let failure = decoded
        .patch()
        .apply(&wrong, SourcePatchLimits::default())
        .unwrap_err();
    require(
        hex(target.bytes()) == expected_string(case, "target_hex")?
            && failure.code() == expected_string(case, "wrong_base_code")?,
        "source patch apply facts differed",
    )
}

fn materialization_request(case: &VectorCase<'_>) -> Result<(), String> {
    let encoding = code_page_encoding(input_u16(case, "code_page")?)?;
    let request = MaterializationRequest::new(
        ProfileId::new(input_string(case, "profile")?, 1),
        MaterializationStyleId::new(input_string(case, "style")?, 1),
    )
    .with_encoding(encoding)
    .with_newline(NewlinePolicy::CrLf);
    let payload = MaterializationRequestMessageV2::from_request(&request)
        .to_value()
        .map_err(string_error)?;
    let decoded = MaterializationRequestMessageV2::from_value(&payload).map_err(string_error)?;
    let fields = payload
        .as_object()
        .ok_or("request payload must be Object")?;
    let encoding_fields = object_field(fields, "encoding")
        .and_then(PortableValue::as_object)
        .ok_or("encoding must be Object")?;
    require(
        decoded.request() == &request
            && object_string(encoding_fields, "kind")? == expected_string(case, "encoding_kind")?,
        "materialization request v2 differed",
    )
}

fn materialization_result(case: &VectorCase<'_>) -> Result<(), String> {
    let snapshot = code_page_snapshot(
        input_u16(case, "code_page")?,
        &decode_hex(input_string(case, "hex")?)?,
    )?;
    let message = MaterializationResultMessageV2::complete(
        ProfileId::new("ini.windows", 1),
        "target:ini",
        SourceSnapshotMessageV2::from_snapshot(&snapshot),
        MaterializationFidelity::Exact,
        MaterializationReportMessage::default(),
        MaterializationProvenanceMapMessage::default(),
    )
    .map_err(string_error)?;
    dual_roundtrip(
        ContractId::new("core.materialization-result", 2).map_err(string_error)?,
        message.to_value(),
    )?;

    let utf8 = SourceSnapshot::from_utf8(b"k=v".as_slice()).map_err(string_error)?;
    let v2 = MaterializationResultMessageV2::complete(
        ProfileId::new("ini.portable", 1),
        "target:ini",
        SourceSnapshotMessageV2::from_snapshot(&utf8),
        MaterializationFidelity::Exact,
        MaterializationReportMessage::default(),
        MaterializationProvenanceMapMessage::default(),
    )
    .map_err(string_error)?;
    let mixed = replace_outcome_snapshot(
        &v2.to_value(),
        SourceSnapshotMessage::from_snapshot(&utf8)
            .map_err(string_error)?
            .to_value(),
    )?;
    expect_error(
        MaterializationResultMessageV2::from_value_with_registry(&mixed, ErrorCodeRegistry::v6()),
        expected_string(case, "mixed_version_code")?,
        None,
    )
}

fn java_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let cases = input_field(case, "cases")?
        .as_sequence()
        .ok_or("input.cases must be Sequence")?;
    let mut accepted = 0;
    for item in cases {
        let fields = item.as_object().ok_or("Java case must be Object")?;
        let units = object_field(fields, "units")
            .and_then(PortableValue::as_sequence)
            .ok_or("units must be Sequence")?
            .iter()
            .map(|unit| {
                unit.as_string()
                    .and_then(|value| u16::from_str_radix(value, 16).ok())
                    .ok_or_else(|| "invalid UTF-16 unit".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_status = match object_string(fields, "status")? {
            "WellFormedUnicode" => JavaUnicodeStatus::WellFormedUnicode,
            "UnpairedSurrogate" => JavaUnicodeStatus::UnpairedSurrogate,
            _ => return Err("unknown Java Unicode status".to_owned()),
        };
        let exact = JavaUtf16String::new(units, ProtocolLimits::default()).map_err(string_error)?;
        if exact.unicode_status() == expected_status
            && JavaUtf16String::from_value(&exact.to_value(), ProtocolLimits::default())
                .map_err(string_error)?
                == exact
        {
            accepted += 1;
        }
    }
    require(
        accepted == expected_usize(case, "accepted_count")?,
        "Java UTF-16 edge matrix differed",
    )
}

fn java_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let mut units = SequenceBuilder::new();
    units.push(PortableValue::string(input_string(case, "unit")?));
    let value = object(vec![
        ("schema", PortableValue::string("core.java-utf16-string@1")),
        ("encoding", PortableValue::string("UTF16BE/1")),
        ("code_units", units.build()),
        (
            "bytes",
            PortableValue::bytes(decode_hex(input_string(case, "bytes_hex")?)?),
        ),
        (
            "unicode_status",
            PortableValue::string(input_string(case, "status")?),
        ),
    ])?;
    expect_error(
        JavaUtf16String::from_value(&value, ProtocolLimits::default()),
        expected_string(case, "code")?,
        Some(expected_string(case, "path")?),
    )
}

fn ini_roles(case: &VectorCase<'_>) -> Result<(), String> {
    let roles = input_roles(case, "roles", parse_ini_role)?;
    for (ordinal, role) in roles.iter().copied().enumerate() {
        let domain = if role == MatchRole::IniSyntaxPiece {
            QueryDomain::ini_lossless_syntax_v1()
        } else {
            QueryDomain::ini_native_v1()
        };
        let result = IniQueryResultMessage::new(
            domain,
            role,
            vec![
                IniMatchLocator::new(
                    input_string(case, "source_id")?,
                    format!("ini:node:{ordinal}"),
                    role,
                    u64::try_from(ordinal).map_err(string_error)?,
                )
                .map_err(string_error)?,
            ],
            success(1)?,
            Vec::new(),
        )
        .map_err(string_error)?;
        dual_roundtrip(
            ContractId::new("core.ini-query-result", 1).map_err(string_error)?,
            result.to_value(),
        )?;
    }
    require(
        roles.len() == expected_usize(case, "role_count")?,
        "INI role count differed",
    )
}

fn properties_roles(case: &VectorCase<'_>) -> Result<(), String> {
    let roles = input_roles(case, "roles", parse_properties_role)?;
    for (ordinal, role) in roles.iter().copied().enumerate() {
        let domain = if role == MatchRole::PropertiesSyntaxPiece {
            QueryDomain::java_properties_lossless_syntax_v1()
        } else {
            QueryDomain::java_properties_native_v1()
        };
        let result = JavaPropertiesQueryResultMessage::new(
            domain,
            role,
            vec![
                JavaPropertiesMatchLocator::new(
                    input_string(case, "source_id")?,
                    format!("properties:node:{ordinal}"),
                    role,
                    u64::try_from(ordinal).map_err(string_error)?,
                )
                .map_err(string_error)?,
            ],
            success(1)?,
            Vec::new(),
        )
        .map_err(string_error)?;
        dual_roundtrip(
            ContractId::new("core.java-properties-query-result", 1).map_err(string_error)?,
            result.to_value(),
        )?;
    }
    require(
        roles.len() == expected_usize(case, "role_count")?,
        "Properties role count differed",
    )
}

fn line_domain_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let role = parse_ini_role(input_string(case, "role")?)?;
    expect_error(
        IniQueryResultMessage::new(
            QueryDomain::ini_native_v1(),
            role,
            Vec::new(),
            success(0)?,
            Vec::new(),
        ),
        expected_string(case, "code")?,
        None,
    )
}

fn line_ordinal_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let role = parse_properties_role(input_string(case, "role")?)?;
    let ordinals = input_u64_sequence(case, "ordinals")?;
    let matches = ordinals
        .iter()
        .enumerate()
        .map(|(index, ordinal)| {
            JavaPropertiesMatchLocator::new(
                "source:properties",
                format!("property:{index}"),
                role,
                *ordinal,
            )
            .map_err(string_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    expect_error(
        JavaPropertiesQueryResultMessage::new(
            QueryDomain::java_properties_native_v1(),
            role,
            matches,
            success(input_u64(case, "produced")?)?,
            Vec::new(),
        ),
        expected_string(case, "code")?,
        None,
    )
}

fn line_process_local(case: &VectorCase<'_>) -> Result<(), String> {
    let node = DocumentAuthority::fresh().node_ref(0, NodeRole::IniEntry);
    expect_error(
        IniMatchLocator::from_process_local(node),
        expected_string(case, "code")?,
        None,
    )
}

fn protocol_old_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let payloads = new_payloads()?;
    let old = [
        ContractRegistry::v1(),
        ContractRegistry::v2(),
        ContractRegistry::v3(),
        ContractRegistry::v4(),
        ContractRegistry::v5(),
    ];
    let expected_code = expected_string(case, "code")?;
    let rejected = payloads
        .iter()
        .filter(|(contract, payload)| {
            old.iter().all(|registry| {
                ProtocolMessage::new(contract.clone(), payload.clone(), *registry)
                    .is_err_and(|error| error.code() == expected_code)
            })
        })
        .count();
    require(
        rejected == expected_usize(case, "rejected_pairs")?,
        "an old registry accepted a v6 contract",
    )
}

fn protocol_version_dispatch(case: &VectorCase<'_>) -> Result<(), String> {
    let request = MaterializationRequest::new(
        ProfileId::new("ini.portable", 1),
        MaterializationStyleId::new("ini.portable-canonical", 1),
    );
    let v2 = MaterializationRequestMessageV2::from_request(&request)
        .to_value()
        .map_err(string_error)?;
    let disguised = replace_field(
        &v2,
        "schema",
        PortableValue::string("core.materialization-request@1"),
    )?;
    expect_error(
        ProtocolMessage::new(
            ContractId::new("core.materialization-request", 1).map_err(string_error)?,
            disguised,
            ContractRegistry::v6(),
        ),
        expected_string(case, "code")?,
        Some("$.encoding"),
    )
}

fn protocol_nested_error(case: &VectorCase<'_>) -> Result<(), String> {
    let code = input_string(case, "failure_code")?;
    let v5 = Completion::new_with_registry(
        CompletionStatus::Failed,
        1,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v5(),
    );
    let completion = Completion::new_with_registry(
        CompletionStatus::Failed,
        1,
        0,
        None,
        Some(code.to_owned()),
        ErrorCodeRegistry::v6(),
    )
    .map_err(string_error)?;
    dual_roundtrip(
        ContractId::new("core.completion", 1).map_err(string_error)?,
        completion.to_value(),
    )?;
    require(
        v5.is_err_and(|error| error.code() == expected_string(case, "v5_code").unwrap()),
        "v5 accepted a v6 diagnostic code",
    )
}

fn protocol_canonical_bytes(case: &VectorCase<'_>) -> Result<(), String> {
    let encoding = SourceEncodingMessage::from_encoding(code_page_encoding(1252)?).to_value();
    let java = JavaUtf16String::new(
        vec![0x0000, 0xD83D, 0xDE00, 0xD800],
        ProtocolLimits::default(),
    )
    .map_err(string_error)?
    .to_value();
    let encoding_message = ProtocolMessage::new(
        ContractId::new("core.source-encoding", 1).map_err(string_error)?,
        encoding,
        ContractRegistry::v6(),
    )
    .map_err(string_error)?;
    let java_message = ProtocolMessage::new(
        ContractId::new("core.java-utf16-string", 1).map_err(string_error)?,
        java,
        ContractRegistry::v6(),
    )
    .map_err(string_error)?;
    let limits = ProtocolLimits::default();
    let actual = [
        hex(&encoding_message.to_json(limits).map_err(string_error)?),
        hex(&encoding_message.to_pvce(limits).map_err(string_error)?),
        hex(&java_message.to_json(limits).map_err(string_error)?),
        hex(&java_message.to_pvce(limits).map_err(string_error)?),
    ];
    let expected = [
        expected_string(case, "source_encoding_json_hex")?,
        expected_string(case, "source_encoding_pvce_hex")?,
        expected_string(case, "java_utf16_json_hex")?,
        expected_string(case, "java_utf16_pvce_hex")?,
    ];
    require(
        actual.iter().map(String::as_str).eq(expected),
        format!("canonical hex differs: {actual:?}"),
    )
}

fn protocol_schema_limits(case: &VectorCase<'_>) -> Result<(), String> {
    let exact =
        JavaUtf16String::new(vec![0x0041], ProtocolLimits::default()).map_err(string_error)?;
    let unknown = append_field(&exact.to_value(), "unknown", PortableValue::null())?;
    let unknown_error =
        JavaUtf16String::from_value(&unknown, ProtocolLimits::default()).unwrap_err();
    let limited = ProtocolLimits {
        max_container_entries: input_usize(case, "max_units")?,
        ..ProtocolLimits::default()
    };
    let limit_error = JavaUtf16String::from_value(&exact.to_value(), limited).unwrap_err();
    require(
        unknown_error.code() == expected_string(case, "unknown_field_code")?
            && limit_error.code() == expected_string(case, "limit_code")?
            && unknown_error.path() == "$.unknown"
            && limit_error.path() == "$.code_units",
        "schema or limit rejection differed",
    )
}

fn new_payloads() -> Result<Vec<(ContractId, PortableValue)>, String> {
    let encoding = code_page_encoding(1252)?;
    let snapshot = code_page_snapshot(1252, b"k=1")?;
    let patch = SourcePatch::create(
        &snapshot,
        Vec::new(),
        BTreeMap::new(),
        SourcePatchLimits::default(),
    )
    .map_err(string_error)?;
    let request = MaterializationRequest::new(
        ProfileId::new("ini.windows", 1),
        MaterializationStyleId::new("ini.windows-canonical", 1),
    )
    .with_encoding(encoding)
    .with_newline(NewlinePolicy::CrLf);
    let result = MaterializationResultMessageV2::complete(
        ProfileId::new("ini.windows", 1),
        "target:ini",
        SourceSnapshotMessageV2::from_snapshot(&snapshot),
        MaterializationFidelity::Exact,
        MaterializationReportMessage::default(),
        MaterializationProvenanceMapMessage::default(),
    )
    .map_err(string_error)?;
    let ini = IniQueryResultMessage::new(
        QueryDomain::ini_native_v1(),
        MatchRole::IniDocument,
        Vec::new(),
        success(0)?,
        Vec::new(),
    )
    .map_err(string_error)?;
    let properties = JavaPropertiesQueryResultMessage::new(
        QueryDomain::java_properties_native_v1(),
        MatchRole::PropertiesDocument,
        Vec::new(),
        success(0)?,
        Vec::new(),
    )
    .map_err(string_error)?;
    let values = [
        ("core.ini-query-result", 1, ini.to_value()),
        (
            "core.java-properties-query-result",
            1,
            properties.to_value(),
        ),
        (
            "core.java-utf16-string",
            1,
            JavaUtf16String::new(vec![0xD800], ProtocolLimits::default())
                .map_err(string_error)?
                .to_value(),
        ),
        (
            "core.materialization-request",
            2,
            MaterializationRequestMessageV2::from_request(&request)
                .to_value()
                .map_err(string_error)?,
        ),
        ("core.materialization-result", 2, result.to_value()),
        (
            "core.source-encoding",
            1,
            SourceEncodingMessage::from_encoding(encoding).to_value(),
        ),
        (
            "core.source-patch",
            2,
            SourcePatchMessageV2::from_patch(&patch)
                .to_value()
                .map_err(string_error)?,
        ),
        (
            "core.source-snapshot",
            2,
            SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value(),
        ),
    ];
    values
        .into_iter()
        .map(|(id, version, payload)| {
            Ok((ContractId::new(id, version).map_err(string_error)?, payload))
        })
        .collect()
}

fn dual_roundtrip(contract: ContractId, payload: PortableValue) -> Result<(), String> {
    let message =
        ProtocolMessage::new(contract, payload, ContractRegistry::v6()).map_err(string_error)?;
    let limits = ProtocolLimits::default();
    require(
        ProtocolMessage::from_json(
            &message.to_json(limits).map_err(string_error)?,
            limits,
            ContractRegistry::v6(),
        )
        .map_err(string_error)?
            == message
            && ProtocolMessage::from_pvce(
                &message.to_pvce(limits).map_err(string_error)?,
                limits,
                ContractRegistry::v6(),
            )
            .map_err(string_error)?
                == message,
        "dual canonical transport did not close",
    )
}

fn code_page_encoding(number: u16) -> Result<SourceEncoding, String> {
    WindowsCodePage::from_number(number)
        .map(SourceEncoding::WindowsCodePage)
        .ok_or_else(|| format!("unsupported code page {number}"))
}

fn code_page_snapshot(number: u16, bytes: &[u8]) -> Result<SourceSnapshot, String> {
    SourceSnapshot::from_raw(
        bytes,
        EncodingRequest::new(code_page_encoding(number)?)
            .with_bom_policy(BomPolicy::TreatAsContent),
        SourceLimits::default(),
    )
    .map_err(string_error)
}

fn success(produced: u64) -> Result<Completion, String> {
    Completion::new(CompletionStatus::Success, produced, produced, None, None).map_err(string_error)
}

fn parse_contract(schema: &str) -> Result<ContractId, String> {
    let (id, version) = schema.rsplit_once('@').ok_or("contract lacks version")?;
    ContractId::new(
        id,
        version
            .parse::<u32>()
            .map_err(|_| "invalid contract version")?,
    )
    .map_err(string_error)
}

fn parse_ini_role(value: &str) -> Result<MatchRole, String> {
    match value {
        "IniDocument" => Ok(MatchRole::IniDocument),
        "IniPhysicalLine" => Ok(MatchRole::IniPhysicalLine),
        "IniLogicalLine" => Ok(MatchRole::IniLogicalLine),
        "IniSection" => Ok(MatchRole::IniSection),
        "IniDefaultSection" => Ok(MatchRole::IniDefaultSection),
        "IniEntry" => Ok(MatchRole::IniEntry),
        "IniErrorLine" => Ok(MatchRole::IniErrorLine),
        "IniSyntaxPiece" => Ok(MatchRole::IniSyntaxPiece),
        _ => Err(format!("unknown INI role {value}")),
    }
}

fn parse_properties_role(value: &str) -> Result<MatchRole, String> {
    match value {
        "PropertiesDocument" => Ok(MatchRole::PropertiesDocument),
        "PropertiesNaturalLine" => Ok(MatchRole::PropertiesNaturalLine),
        "PropertiesLogicalLine" => Ok(MatchRole::PropertiesLogicalLine),
        "PropertiesProperty" => Ok(MatchRole::PropertiesProperty),
        "PropertiesComment" => Ok(MatchRole::PropertiesComment),
        "PropertiesEscape" => Ok(MatchRole::PropertiesEscape),
        "PropertiesErrorLine" => Ok(MatchRole::PropertiesErrorLine),
        "PropertiesSyntaxPiece" => Ok(MatchRole::PropertiesSyntaxPiece),
        _ => Err(format!("unknown Properties role {value}")),
    }
}

fn input_roles(
    case: &VectorCase<'_>,
    name: &str,
    parser: fn(&str) -> Result<MatchRole, String>,
) -> Result<Vec<MatchRole>, String> {
    input_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("input.{name} must be Sequence"))?
        .iter()
        .map(|value| parser(value.as_string().ok_or("role must be String")?))
        .collect()
}

fn replace_outcome_snapshot(
    result: &PortableValue,
    snapshot: PortableValue,
) -> Result<PortableValue, String> {
    let fields = result.as_object().ok_or("result must be Object")?;
    let outcome = object_field(fields, "outcome").ok_or("missing outcome")?;
    replace_field(
        result,
        "outcome",
        replace_field(outcome, "snapshot", snapshot)?,
    )
}

fn replace_field(
    value: &PortableValue,
    target: &str,
    replacement: PortableValue,
) -> Result<PortableValue, String> {
    let fields = value.as_object().ok_or("value must be Object")?;
    if !fields.iter().any(|field| field.key() == target) {
        return Err(format!("field {target} is absent"));
    }
    let mut builder = ObjectBuilder::new();
    for field in fields {
        builder
            .insert(
                field.key(),
                if field.key() == target {
                    replacement.clone()
                } else {
                    field.value().clone()
                },
            )
            .map_err(string_error)?;
    }
    Ok(builder.build())
}

fn append_field(
    value: &PortableValue,
    name: &str,
    appended: PortableValue,
) -> Result<PortableValue, String> {
    let fields = value.as_object().ok_or("value must be Object")?;
    let mut builder = ObjectBuilder::new();
    for field in fields {
        builder
            .insert(field.key(), field.value().clone())
            .map_err(string_error)?;
    }
    builder.insert(name, appended).map_err(string_error)?;
    Ok(builder.build())
}

fn object(fields: Vec<(&str, PortableValue)>) -> Result<PortableValue, String> {
    let mut builder = ObjectBuilder::new();
    for (name, value) in fields {
        builder.insert(name, value).map_err(string_error)?;
    }
    Ok(builder.build())
}

fn expect_error<T>(
    result: Result<T, ProtocolError>,
    code: &str,
    path: Option<&str>,
) -> Result<(), String> {
    let error = result.map(|_| ()).unwrap_err();
    require(
        error.code() == code && path.is_none_or(|expected| error.path() == expected),
        error.to_string(),
    )
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

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be host-size Integer"))
}

fn input_u64(case: &VectorCase<'_>, name: &str) -> Result<u64, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| format!("input.{name} must be unsigned Integer"))
}

fn input_u16(case: &VectorCase<'_>, name: &str) -> Result<u16, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| format!("input.{name} must be unsigned 16-bit Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be host-size Integer"))
}

fn input_u16_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<u16>, String> {
    input_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("input.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_i64)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| format!("input.{name} item must be u16"))
        })
        .collect()
}

fn input_u64_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<u64>, String> {
    input_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("input.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_i64)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| format!("input.{name} item must be u64"))
        })
        .collect()
}

fn expected_usize_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<usize>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_usize)
                .ok_or_else(|| format!("expected.{name} item must be usize"))
        })
        .collect()
}

fn expected_string_sequence(case: &VectorCase<'_>, name: &str) -> Result<Vec<String>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("expected.{name} item must be String"))
        })
        .collect()
}

fn object_string<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a str, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("{name} must be String"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hexadecimal bytes".to_owned());
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hexadecimal bytes".to_owned())
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

fn require(condition: bool, detail: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_semantic_model_v6_suite_is_conformant() {
        let report = run_semantic_model_v6();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 25);
    }

    #[test]
    fn semantic_model_v6_vectors_drive_inputs_and_expectations() {
        let changed = SEMANTIC_MODEL_V6_VECTORS_JSON.replacen(
            "\"contract_count\": 38",
            "\"contract_count\": 37",
            1,
        );
        let report = run_semantic_model_v6_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "registry.v6-manifest"),
            "{report:#?}"
        );

        let changed = SEMANTIC_MODEL_V6_VECTORS_JSON.replacen(
            "\"accepted_count\": 15",
            "\"accepted_count\": 14",
            1,
        );
        let report = run_semantic_model_v6_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "source-encoding.mandatory-code-pages"),
            "{report:#?}"
        );
    }
}
