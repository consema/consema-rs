use super::{ConformanceReport, ensure, object_field};
use consema_core::{
    BigInteger, BinaryFloat32, BinaryFloat64, CancellationToken, CapabilityId, CapabilitySet, Date,
    Decimal, Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity,
    ImplementationSupport, LocalDateTime, MatchRole, OperatorCall, PortableValue,
    PortableValueKind, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QuerySelection, Time, ValuePath, VerificationStatus,
};
use consema_document::{DocumentAuthority, NodeRole, ParseLimits};
use consema_json::{
    EditTransactionBuilder, JsonProfile, ProjectionRequestBuilder as JsonProjectionRequestBuilder,
    ProjectionResult as JsonProjectionResult, ProjectionTarget as JsonProjectionTarget,
    RepresentationPolicy, parse as parse_json,
};
use consema_protocol::{
    CapabilityDeclaration, ChangeSetMessage, Completion, CompletionStatus, ContractId,
    ContractRegistry, DiagnosticMessage, ErrorCodeRegistry, NativeMatchLocator, ProfileDescriptor,
    ProjectedLocationMessage, ProjectionFidelity, ProjectionPolicy, ProjectionReportMessage,
    ProjectionRequestMessage, ProjectionResultMessage, ProjectionRule, ProjectionScope,
    ProtocolErrorKind, ProtocolLimits, ProtocolMessage, ProvenanceEntryMessage,
    ProvenanceMapMessage, ProvenanceRelation, QueryResultMessage, RegistryManifest,
    SourceOriginMessage, decode_json, decode_pvce, encode_json, encode_pvce,
    error_code_manifest_value, query_definition_from_message, query_definition_message,
    query_failure_code, validate_error_code_manifest_value,
};
use std::collections::BTreeMap;

/// Embedded language-neutral protocol suite bytes.
pub const PROTOCOL_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/protocol-v1.json");

/// Parses and runs every embedded `consema.protocol.conformance@1` case.
#[must_use]
pub fn run_protocol_v1() -> ConformanceReport {
    let vectors = parse_json(
        PROTOCOL_V1_VECTORS_JSON.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published protocol vector JSON must form a document");
    let request = JsonProjectionRequestBuilder::new(JsonProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        JsonProjectionResult::Complete(result) => result.value,
        JsonProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.protocol.conformance@1".to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let object = case.as_object().expect("case object");
        let id = object_field(object, "id")
            .and_then(PortableValue::as_string)
            .expect("case id");
        match run_case(id) {
            Ok(()) => report.passed.push(id.to_owned()),
            Err(error) => report.failed.push((id.to_owned(), error)),
        }
    }
    report
}

fn run_case(id: &str) -> Result<(), String> {
    match id {
        "protocol.json.null-vector" => json_null_vector(),
        "protocol.json.all-kinds-roundtrip" => json_all_kinds(),
        "protocol.json.reject-whitespace" => reject_whitespace(),
        "protocol.json.reject-alternate-escape" => reject_alternate_escape(),
        "protocol.json.reject-unknown-field" => reject_unknown_field(),
        "protocol.pvce.roundtrip-equivalent" => pvce_equivalent(),
        "protocol.resource.depth-limit" => depth_limit(),
        "protocol.envelope.dual-transport" => envelope_dual_transport(),
        "protocol.envelope.reject-unknown-contract" => reject_unknown_contract(),
        "protocol.envelope.reject-schema-mismatch" => reject_schema_mismatch(),
        "protocol.envelope.reject-schema-only-payload" => reject_schema_only_payload(),
        "protocol.envelope.reject-nested-envelope" => reject_nested_envelope(),
        "protocol.envelope.reject-semantic-model-identity" => reject_semantic_model_identity(),
        "protocol.profile.roundtrip" => profile_roundtrip(),
        "protocol.capability.conditional-roundtrip" => capability_roundtrip(),
        "protocol.capability.reject-contradiction" => capability_contradiction(),
        "protocol.diagnostic.require-source-binding" => diagnostic_source_binding(),
        "protocol.completion.reject-contradiction" => completion_contradiction(),
        "protocol.query.definition-envelope" => query_definition_envelope(),
        "protocol.query.portable-result" => query_portable_result(),
        "protocol.query.reject-native-handle" => reject_native_handle(),
        "protocol.projection.request-roundtrip" => projection_request_roundtrip(),
        "protocol.projection.no-partial-value" => projection_no_partial(),
        "protocol.provenance.externalized-roundtrip" => provenance_roundtrip(),
        "protocol.change-set.actual-edit-roundtrip" => change_set_roundtrip(),
        "protocol.registry.current-roundtrip" => registry_roundtrip(),
        "protocol.registry.error-code-schema" => error_code_schema(),
        "protocol.errors.query-codes-registered" => query_codes_registered(),
        _ => Err("runner does not recognize published protocol case".to_owned()),
    }
}

fn json_null_vector() -> Result<(), String> {
    ensure(
        encode_json(&PortableValue::null(), ProtocolLimits::default()).unwrap()
            == br#"{"schema":"core.portable-value-json@1","value":{"type":"Null"}}"#,
    )
}

fn all_kinds() -> PortableValue {
    let date = Date::new(BigInteger::from(2026), 8, 4).unwrap();
    let time = Time::new(
        1,
        2,
        3,
        Decimal::new(BigInteger::from(4), BigInteger::from(-1)),
    )
    .unwrap();
    let local = LocalDateTime::new(date.clone(), time.clone());
    let offset = consema_core::OffsetDateTime::new(local.clone(), 3600).unwrap();
    let mut object = consema_core::ObjectBuilder::new();
    object.insert("k", PortableValue::null()).unwrap();
    let mut mapping = consema_core::EntryMappingBuilder::new();
    mapping.push(
        PortableValue::integer(BigInteger::from(1)),
        PortableValue::string("v"),
    );
    PortableValue::sequence(vec![
        PortableValue::null(),
        PortableValue::boolean(true),
        PortableValue::integer(BigInteger::parse_decimal("12345678901234567890").unwrap()),
        PortableValue::decimal(Decimal::new(BigInteger::from(12), BigInteger::from(-1))),
        PortableValue::binary_float32(BinaryFloat32::from_bits(0x7fc0_0001)),
        PortableValue::binary_float64(BinaryFloat64::from_bits(1_u64 << 63)),
        PortableValue::string("文本"),
        PortableValue::bytes([0, 0xff].as_slice()),
        PortableValue::date(date),
        PortableValue::time(time),
        PortableValue::local_date_time(local),
        PortableValue::offset_date_time(offset),
        PortableValue::sequence(Vec::<PortableValue>::new()),
        object.build(),
        mapping.build(),
    ])
}

fn json_all_kinds() -> Result<(), String> {
    let value = all_kinds();
    let limits = ProtocolLimits::default();
    ensure(decode_json(&encode_json(&value, limits).unwrap(), limits).unwrap() == value)
}

fn reject_whitespace() -> Result<(), String> {
    ensure(
        decode_json(
            br#" {"schema":"core.portable-value-json@1","value":{"type":"Null"}}"#,
            ProtocolLimits::default(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::NonCanonicalJson),
    )
}

fn reject_alternate_escape() -> Result<(), String> {
    ensure(
        decode_json(
            br#"{"schema":"core.portable-value-json@1","value":{"type":"String","value":"\u0078"}}"#,
            ProtocolLimits::default(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::NonCanonicalJson),
    )
}

fn reject_unknown_field() -> Result<(), String> {
    ensure(
        decode_json(
            br#"{"schema":"core.portable-value-json@1","value":{"type":"Null","x":true}}"#,
            ProtocolLimits::default(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::UnknownField),
    )
}

fn pvce_equivalent() -> Result<(), String> {
    let value = all_kinds();
    let limits = ProtocolLimits::default();
    ensure(decode_pvce(&encode_pvce(&value, limits).unwrap(), limits).unwrap() == value)
}

fn depth_limit() -> Result<(), String> {
    let limits = ProtocolLimits {
        max_depth: 0,
        ..ProtocolLimits::default()
    };
    ensure(
        encode_json(
            &PortableValue::sequence(vec![PortableValue::null()]),
            limits,
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::ResourceLimit),
    )
}

fn completion_payload() -> PortableValue {
    Completion::new(CompletionStatus::Success, 1, 1, None, None)
        .unwrap()
        .to_value()
}

fn envelope_dual_transport() -> Result<(), String> {
    let registry = ContractRegistry::v1();
    let message = ProtocolMessage::new(
        ContractId::new("core.completion", 1).unwrap(),
        completion_payload(),
        registry,
    )
    .unwrap();
    let limits = ProtocolLimits::default();
    ensure(
        ProtocolMessage::from_json(&message.to_json(limits).unwrap(), limits, registry).unwrap()
            == message
            && ProtocolMessage::from_pvce(&message.to_pvce(limits).unwrap(), limits, registry)
                .unwrap()
                == message,
    )
}

fn reject_unknown_contract() -> Result<(), String> {
    let mut payload = consema_core::ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("example.unknown@1"))
        .unwrap();
    ensure(
        ProtocolMessage::new(
            ContractId::new("example.unknown", 1).unwrap(),
            payload.build(),
            ContractRegistry::v1(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::UnknownContract),
    )
}

fn reject_schema_mismatch() -> Result<(), String> {
    ensure(
        ProtocolMessage::new(
            ContractId::new("core.diagnostic", 1).unwrap(),
            completion_payload(),
            ContractRegistry::v1(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::SchemaMismatch),
    )
}

fn reject_schema_only_payload() -> Result<(), String> {
    let mut payload = consema_core::ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("core.diagnostic@1"))
        .unwrap();
    payload
        .insert("placeholder", PortableValue::null())
        .unwrap();
    ensure(
        ProtocolMessage::new(
            ContractId::new("core.diagnostic", 1).unwrap(),
            payload.build(),
            ContractRegistry::v1(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::UnknownField),
    )
}

fn reject_nested_envelope() -> Result<(), String> {
    let mut payload = consema_core::ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("core.protocol-message@1"))
        .unwrap();
    ensure(
        ProtocolMessage::new(
            ContractId::new("core.protocol-message", 1).unwrap(),
            payload.build(),
            ContractRegistry::v1(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::InvalidValue),
    )
}

fn reject_semantic_model_identity() -> Result<(), String> {
    let mut payload = consema_core::ObjectBuilder::new();
    payload
        .insert("schema", PortableValue::string("core.semantic-model@1"))
        .unwrap();
    ensure(
        ProtocolMessage::new(
            ContractId::new("core.semantic-model", 1).unwrap(),
            payload.build(),
            ContractRegistry::v1(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::UnknownContract),
    )
}

fn profile_roundtrip() -> Result<(), String> {
    let profile = ProfileDescriptor::new(
        "toml",
        1,
        "toml.1.0",
        1,
        None,
        vec!["toml.datetime".to_owned()],
        vec![CapabilityId::new("core.document.exact-roundtrip", 1)],
    )
    .unwrap();
    ensure(ProfileDescriptor::from_value(&profile.to_value()).unwrap() == profile)
}

fn capability_roundtrip() -> Result<(), String> {
    let declaration = CapabilityDeclaration::new(
        CapabilityId::new("toml.projection.best-exact-core", 1),
        ImplementationSupport::Conditional(vec![("profile".to_owned(), "toml.1.0@1".to_owned())]),
        VerificationStatus::Verified,
        Some("consema.protocol.conformance".to_owned()),
    )
    .unwrap();
    ensure(CapabilityDeclaration::from_value(&declaration.to_value()).unwrap() == declaration)
}

fn capability_contradiction() -> Result<(), String> {
    ensure(
        CapabilityDeclaration::new(
            CapabilityId::new("core.query.ordered-results", 1),
            ImplementationSupport::Conditional(Vec::new()),
            VerificationStatus::Unverified,
            None,
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::InvalidValue),
    )
}

fn diagnostic_source_binding() -> Result<(), String> {
    let diagnostic = Diagnostic::new(
        "json.syntax.expected-value@1",
        DiagnosticCategory::Syntax,
        DiagnosticSeverity::Error,
        Some(DiagnosticLocation {
            snapshot: Some(1),
            start_byte: 0,
            end_byte: 1,
        }),
        0,
    );
    ensure(
        DiagnosticMessage::from_core(&diagnostic, None)
            .is_err_and(|error| error.kind() == ProtocolErrorKind::ProcessLocalHandle),
    )
}

fn completion_contradiction() -> Result<(), String> {
    ensure(
        Completion::new(
            CompletionStatus::Success,
            1,
            1,
            Some("max_steps".to_owned()),
            None,
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::InvalidValue),
    )
}

fn query_definition_envelope() -> Result<(), String> {
    let definition = QueryDefinition::new(QueryDomain::portable_value_v1()).with_expression(
        QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
    );
    let before = consema_pvce::encode(&definition.to_protocol_value().unwrap());
    let message = query_definition_message(&definition).unwrap();
    let decoded = query_definition_from_message(&message).unwrap();
    let after = consema_pvce::encode(&decoded.to_protocol_value().unwrap());
    ensure(decoded == definition && before == after)
}

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

fn query_portable_result() -> Result<(), String> {
    let definition = QueryDefinition::new(QueryDomain::portable_value_v1());
    let execution = definition
        .validate()
        .unwrap()
        .bind(&capabilities())
        .unwrap()
        .execute_portable(
            &PortableValue::string("x"),
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
    let result = QueryResultMessage::from_portable_execution(
        QueryDomain::portable_value_v1(),
        MatchRole::Value,
        &execution,
    )
    .unwrap();
    ensure(QueryResultMessage::from_value(&result.to_value()).unwrap() == result)
}

fn reject_native_handle() -> Result<(), String> {
    let authority = DocumentAuthority::fresh();
    ensure(
        NativeMatchLocator::from_process_local(authority.node_ref(0, NodeRole::TomlItem))
            .is_err_and(|error| error.kind() == ProtocolErrorKind::ProcessLocalHandle),
    )
}

fn projection_request_roundtrip() -> Result<(), String> {
    let policy = ProjectionPolicy::new(
        ContractId::new("core.projection.exact-or-reject", 1).unwrap(),
        BTreeMap::new(),
    );
    let request = ProjectionRequestMessage::new(
        ContractId::new("json.projection.best-exact-core", 1).unwrap(),
        policy.clone(),
        vec![ProjectionRule {
            rule_id: "global".to_owned(),
            scope: ProjectionScope::Global,
            priority: 0,
            policy,
        }],
        BTreeMap::new(),
    )
    .unwrap();
    ensure(ProjectionRequestMessage::from_value(&request.to_value()).unwrap() == request)
}

fn projection_no_partial() -> Result<(), String> {
    let completion = Completion::new(
        CompletionStatus::Failed,
        1,
        0,
        None,
        Some("core.projection.target-not-applicable@1".to_owned()),
    )
    .unwrap();
    ensure(
        ProjectionResultMessage::new(
            completion,
            Some(PortableValue::null()),
            Some(ProjectionFidelity::Exact),
            ProjectionReportMessage::default(),
            ProvenanceMapMessage::default(),
            Vec::new(),
        )
        .is_err_and(|error| error.kind() == ProtocolErrorKind::InvalidValue),
    )
}

fn provenance_roundtrip() -> Result<(), String> {
    let map = ProvenanceMapMessage::new(vec![ProvenanceEntryMessage {
        projected: ProjectedLocationMessage::Value(ValuePath::root()),
        origins: vec![
            SourceOriginMessage::new(
                "source:one",
                Some("toml:root".to_owned()),
                0,
                1,
                ProvenanceRelation::Direct,
            )
            .unwrap(),
        ],
    }])
    .unwrap();
    ensure(ProvenanceMapMessage::from_value(&map.to_value()).unwrap() == map)
}

fn change_set_roundtrip() -> Result<(), String> {
    let document = parse_json(
        b"1".as_slice(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .unwrap();
    let mut transaction = EditTransactionBuilder::new(&document);
    transaction.semantic_scalar(
        document.root().node_ref(),
        PortableValue::integer(BigInteger::from(2)),
        RepresentationPolicy::CanonicalForProfile,
    );
    let commit = document.commit(&transaction.build()).unwrap();
    let old_snapshot = document.snapshot_identity();
    let message =
        ChangeSetMessage::from_document(&commit.change_set, "source:old", "source:new", |node| {
            Some(if node.snapshot() == old_snapshot {
                "json:root:old".to_owned()
            } else {
                "json:root:new".to_owned()
            })
        })
        .unwrap();
    ensure(
        message.source_edits()[0].replacement == b"2"
            && ChangeSetMessage::from_value(&message.to_value()).unwrap() == message,
    )
}

fn registry_roundtrip() -> Result<(), String> {
    let manifest = RegistryManifest::current();
    let decoded = RegistryManifest::from_value(&manifest.to_value()).unwrap();
    ensure(
        decoded.is_current()
            && decoded.contracts().windows(2).all(|pair| pair[0] < pair[1])
            && decoded
                .error_codes()
                .windows(2)
                .all(|pair| pair[0].code < pair[1].code),
    )
}

fn error_code_schema() -> Result<(), String> {
    validate_error_code_manifest_value(&error_code_manifest_value())
        .map_err(|error| error.to_string())
}

fn query_codes_registered() -> Result<(), String> {
    let failures = vec![
        QueryFailure::DomainMismatch(QueryDomain::new("example.domain", 1)),
        QueryFailure::UnknownOperator {
            id: "unknown".to_owned(),
            version: 1,
        },
        QueryFailure::WrongArgumentType {
            operator: "x".to_owned(),
            argument: "a".to_owned(),
            expected: PortableValueKind::String,
        },
        QueryFailure::InvalidArgument {
            operator: "x".to_owned(),
            argument: "a".to_owned(),
        },
        QueryFailure::InvalidOperatorComposition {
            operator: "x".to_owned(),
            expected: MatchRole::Value,
            actual: MatchRole::ObjectEntry,
        },
        QueryFailure::MissingRequiredCapability(CapabilityId::new("core.example", 1)),
        QueryFailure::RequiredTypeMismatch {
            expected: PortableValueKind::String,
            actual: PortableValueKind::Null,
        },
        QueryFailure::CardinalityViolation {
            selection: QuerySelection::RequireOne,
            actual: 0,
        },
        QueryFailure::ResourceLimitExceeded,
        QueryFailure::Cancelled,
        QueryFailure::TargetUnavailable,
    ];
    ensure(
        failures
            .iter()
            .all(|failure| ErrorCodeRegistry::v1().contains(query_failure_code(failure))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_protocol_v1_suite_is_conformant() {
        let report = run_protocol_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 28);
    }
}
