//! Contract identifiers, registry, and the common protocol envelope.

use crate::payload::validate_registered_payload;
use crate::schema::{object, schema_fields, string, unsigned_u32};
use crate::{
    ErrorCodeRegistry, ProtocolError, ProtocolErrorKind, ProtocolLimits, decode_json, decode_pvce,
    encode_json, encode_pvce,
};
use consema_core::{BigInteger, PortableValue};

/// Stable versioned protocol contract identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContractId {
    id: String,
    version: u32,
}

impl ContractId {
    /// Validates and creates an identifier.
    pub fn new(id: impl Into<String>, version: u32) -> Result<Self, ProtocolError> {
        let id = id.into();
        if version == 0 {
            return Err(crate::schema::invalid(
                "$.contract.version",
                "version must be non-zero",
            ));
        }
        validate_identifier(&id, "$.contract.id")?;
        Ok(Self { id, version })
    }

    /// Namespaced contract ID without the version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Canonical `id@version` schema discriminator.
    #[must_use]
    pub fn schema(&self) -> String {
        format!("{}@{}", self.id, self.version)
    }
}

/// Compatibility status of one frozen contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContractStability {
    /// Normative public contract for the current semantic model.
    Stable,
    /// Transport-only contract; still immutable within its version.
    Transport,
}

/// Static registry record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractDescriptor {
    /// Namespaced ID.
    pub id: &'static str,
    /// Contract version.
    pub version: u32,
    /// Compatibility classification.
    pub stability: ContractStability,
}

const CONTRACTS_V1: &[ContractDescriptor] = &[
    descriptor("core.cancellation-request", ContractStability::Stable),
    descriptor("core.capability-declaration", ContractStability::Stable),
    descriptor("core.change-set", ContractStability::Stable),
    descriptor("core.completion", ContractStability::Stable),
    descriptor("core.diagnostic", ContractStability::Stable),
    descriptor("core.error-code-registry", ContractStability::Stable),
    descriptor("core.execution-policy", ContractStability::Stable),
    descriptor("core.profile-descriptor", ContractStability::Stable),
    descriptor("core.projection-report", ContractStability::Stable),
    descriptor("core.projection-request", ContractStability::Stable),
    descriptor("core.projection-result", ContractStability::Stable),
    descriptor("core.protocol-message", ContractStability::Transport),
    descriptor("core.provenance-map", ContractStability::Stable),
    descriptor("core.query-definition", ContractStability::Stable),
    descriptor("core.query-result", ContractStability::Stable),
    descriptor("core.registry-manifest", ContractStability::Stable),
];

const CONTRACTS_V2: &[ContractDescriptor] = &[
    descriptor("core.cancellation-request", ContractStability::Stable),
    descriptor("core.capability-declaration", ContractStability::Stable),
    descriptor("core.change-set", ContractStability::Stable),
    descriptor("core.completion", ContractStability::Stable),
    descriptor("core.diagnostic", ContractStability::Stable),
    descriptor("core.error-code-registry", ContractStability::Stable),
    descriptor("core.execution-policy", ContractStability::Stable),
    descriptor("core.profile-descriptor", ContractStability::Stable),
    descriptor("core.projection-report", ContractStability::Stable),
    descriptor("core.projection-request", ContractStability::Stable),
    descriptor("core.projection-result", ContractStability::Stable),
    descriptor("core.protocol-message", ContractStability::Transport),
    descriptor("core.provenance-map", ContractStability::Stable),
    descriptor("core.query-definition", ContractStability::Stable),
    descriptor("core.query-result", ContractStability::Stable),
    descriptor("core.registry-manifest", ContractStability::Stable),
    descriptor("core.source-patch", ContractStability::Stable),
    descriptor("core.source-snapshot", ContractStability::Stable),
];

const CONTRACTS_V3: &[ContractDescriptor] = &[
    descriptor("core.cancellation-request", ContractStability::Stable),
    descriptor("core.capability-declaration", ContractStability::Stable),
    descriptor("core.change-set", ContractStability::Stable),
    descriptor("core.completion", ContractStability::Stable),
    descriptor("core.conversion-report", ContractStability::Stable),
    descriptor("core.diagnostic", ContractStability::Stable),
    descriptor("core.edit-plan", ContractStability::Stable),
    descriptor("core.error-code-registry", ContractStability::Stable),
    descriptor("core.execution-policy", ContractStability::Stable),
    descriptor("core.format-operation-registry", ContractStability::Stable),
    descriptor(
        "core.materialization-provenance-map",
        ContractStability::Stable,
    ),
    descriptor("core.materialization-report", ContractStability::Stable),
    descriptor("core.materialization-request", ContractStability::Stable),
    descriptor("core.materialization-result", ContractStability::Stable),
    descriptor("core.profile-descriptor", ContractStability::Stable),
    descriptor("core.projection-report", ContractStability::Stable),
    descriptor("core.projection-request", ContractStability::Stable),
    descriptor("core.projection-result", ContractStability::Stable),
    descriptor("core.protocol-message", ContractStability::Transport),
    descriptor("core.provenance-map", ContractStability::Stable),
    descriptor("core.query-definition", ContractStability::Stable),
    descriptor("core.query-result", ContractStability::Stable),
    descriptor("core.registry-manifest", ContractStability::Stable),
    descriptor("core.source-patch", ContractStability::Stable),
    descriptor("core.source-snapshot", ContractStability::Stable),
];

const CONTRACTS_V5: &[ContractDescriptor] = &[
    descriptor("core.cancellation-request", ContractStability::Stable),
    descriptor("core.capability-declaration", ContractStability::Stable),
    descriptor("core.change-set", ContractStability::Stable),
    descriptor("core.completion", ContractStability::Stable),
    descriptor("core.conversion-report", ContractStability::Stable),
    descriptor("core.diagnostic", ContractStability::Stable),
    descriptor("core.edit-plan", ContractStability::Stable),
    descriptor("core.error-code-registry", ContractStability::Stable),
    descriptor("core.execution-policy", ContractStability::Stable),
    descriptor("core.format-operation-registry", ContractStability::Stable),
    descriptor("core.graph-projection-result", ContractStability::Stable),
    descriptor("core.graph-provenance-map", ContractStability::Stable),
    descriptor("core.graph-query-result", ContractStability::Stable),
    descriptor(
        "core.materialization-provenance-map",
        ContractStability::Stable,
    ),
    descriptor("core.materialization-report", ContractStability::Stable),
    descriptor("core.materialization-request", ContractStability::Stable),
    descriptor("core.materialization-result", ContractStability::Stable),
    descriptor("core.portable-graph", ContractStability::Stable),
    descriptor("core.profile-descriptor", ContractStability::Stable),
    descriptor("core.projection-report", ContractStability::Stable),
    descriptor("core.projection-request", ContractStability::Stable),
    descriptor("core.projection-result", ContractStability::Stable),
    descriptor("core.protocol-message", ContractStability::Transport),
    descriptor("core.provenance-map", ContractStability::Stable),
    descriptor("core.query-definition", ContractStability::Stable),
    descriptor("core.query-result", ContractStability::Stable),
    descriptor("core.registry-manifest", ContractStability::Stable),
    descriptor("core.source-patch", ContractStability::Stable),
    descriptor("core.source-snapshot", ContractStability::Stable),
    descriptor("core.yaml-query-result", ContractStability::Stable),
];

const fn descriptor(id: &'static str, stability: ContractStability) -> ContractDescriptor {
    ContractDescriptor {
        id,
        version: 1,
        stability,
    }
}

/// Closed Consema 0.3 protocol contract registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractRegistry {
    version: RegistryVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
}

impl Default for ContractRegistry {
    fn default() -> Self {
        Self::v1()
    }
}

impl ContractRegistry {
    /// Frozen Consema 0.3 semantic-model v1 registry.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            version: RegistryVersion::V1,
        }
    }

    /// Consema 0.4 semantic-model v2 registry.
    #[must_use]
    pub const fn v2() -> Self {
        Self {
            version: RegistryVersion::V2,
        }
    }

    /// Consema 0.5 semantic-model v3 registry.
    #[must_use]
    pub const fn v3() -> Self {
        Self {
            version: RegistryVersion::V3,
        }
    }

    /// Consema 0.6 semantic-model v4 registry.
    #[must_use]
    pub const fn v4() -> Self {
        Self {
            version: RegistryVersion::V4,
        }
    }

    /// Consema 0.7 semantic-model v5 registry.
    #[must_use]
    pub const fn v5() -> Self {
        Self {
            version: RegistryVersion::V5,
        }
    }

    /// Sorted registered contracts.
    #[must_use]
    pub const fn contracts(self) -> &'static [ContractDescriptor] {
        match self.version {
            RegistryVersion::V1 => CONTRACTS_V1,
            RegistryVersion::V2 => CONTRACTS_V2,
            RegistryVersion::V3 | RegistryVersion::V4 => CONTRACTS_V3,
            RegistryVersion::V5 => CONTRACTS_V5,
        }
    }

    /// Whether an exact ID/version pair is registered.
    #[must_use]
    pub fn recognizes(self, contract: &ContractId) -> bool {
        self.descriptor(contract).is_some()
    }

    fn descriptor(self, contract: &ContractId) -> Option<&'static ContractDescriptor> {
        let contracts = self.contracts();
        contracts
            .binary_search_by(|candidate| {
                (candidate.id, candidate.version).cmp(&(contract.id(), contract.version()))
            })
            .ok()
            .map(|index| &contracts[index])
    }

    pub(crate) const fn error_code_registry(self) -> ErrorCodeRegistry {
        match self.version {
            RegistryVersion::V1 => ErrorCodeRegistry::v1(),
            RegistryVersion::V2 => ErrorCodeRegistry::v2(),
            RegistryVersion::V3 => ErrorCodeRegistry::v3(),
            RegistryVersion::V4 => ErrorCodeRegistry::v4(),
            RegistryVersion::V5 => ErrorCodeRegistry::v5(),
        }
    }
}

/// One validated protocol payload in the common envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolMessage {
    contract: ContractId,
    payload: PortableValue,
}

impl ProtocolMessage {
    /// Validates a recognized contract and matching payload schema.
    pub fn new(
        contract: ContractId,
        payload: PortableValue,
        registry: ContractRegistry,
    ) -> Result<Self, ProtocolError> {
        let descriptor = registry.descriptor(&contract).ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorKind::UnknownContract,
                "$.contract",
                contract.schema(),
            )
        })?;
        if descriptor.stability == ContractStability::Transport {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidValue,
                "$.contract",
                "transport envelopes cannot be nested as payload contracts",
            ));
        }
        validate_payload_schema(&payload, &contract)?;
        validate_registered_payload(&contract, &payload, registry)?;
        Ok(Self { contract, payload })
    }

    /// Exact contract.
    #[must_use]
    pub const fn contract(&self) -> &ContractId {
        &self.contract
    }

    /// Validated payload.
    #[must_use]
    pub const fn payload(&self) -> &PortableValue {
        &self.payload
    }

    /// Encodes the fixed `core.protocol-message@1` envelope as PortableValue.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("core.protocol-message@1")),
            ("contract_id", PortableValue::string(self.contract.id())),
            (
                "contract_version",
                PortableValue::integer(BigInteger::from(i64::from(self.contract.version()))),
            ),
            ("payload", self.payload.clone()),
        ])
    }

    /// Strictly decodes the envelope and validates the selected payload schema.
    pub fn from_value(
        value: &PortableValue,
        registry: ContractRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.protocol-message@1",
            &["schema", "contract_id", "contract_version", "payload"],
            "$",
        )?;
        let contract = ContractId::new(
            string(fields[1], "$.contract_id")?,
            unsigned_u32(fields[2], "$.contract_version")?,
        )?;
        Self::new(contract, fields[3].clone(), registry)
    }

    /// Encodes through canonical tagged JSON.
    pub fn to_json(&self, limits: ProtocolLimits) -> Result<Vec<u8>, ProtocolError> {
        encode_json(&self.to_value(), limits)
    }

    /// Decodes canonical tagged JSON and validates the registry contract.
    pub fn from_json(
        bytes: &[u8],
        limits: ProtocolLimits,
        registry: ContractRegistry,
    ) -> Result<Self, ProtocolError> {
        Self::from_value(&decode_json(bytes, limits)?, registry)
    }

    /// Encodes through canonical PVCE/1.
    pub fn to_pvce(&self, limits: ProtocolLimits) -> Result<Vec<u8>, ProtocolError> {
        encode_pvce(&self.to_value(), limits)
    }

    /// Decodes canonical PVCE/1 and validates the registry contract.
    pub fn from_pvce(
        bytes: &[u8],
        limits: ProtocolLimits,
        registry: ContractRegistry,
    ) -> Result<Self, ProtocolError> {
        Self::from_value(&decode_pvce(bytes, limits)?, registry)
    }
}

fn validate_payload_schema(
    payload: &PortableValue,
    contract: &ContractId,
) -> Result<(), ProtocolError> {
    let entries = payload.as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            "$.payload",
            "payload must be an Object",
        )
    })?;
    let first = entries.first().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::MissingField,
            "$.payload.schema",
            "payload schema is absent",
        )
    })?;
    if first.key() != "schema" {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.payload",
            "schema must be the first field",
        ));
    }
    let observed = string(first.value(), "$.payload.schema")?;
    if observed != contract.schema() {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.payload.schema",
            format!("expected {}", contract.schema()),
        ));
    }
    Ok(())
}

fn validate_identifier(identifier: &str, path: &str) -> Result<(), ProtocolError> {
    if identifier.len() > 255 || !identifier.contains('.') {
        return Err(crate::schema::invalid(
            path,
            "identifier must contain multiple segments and be at most 255 bytes",
        ));
    }
    for segment in identifier.split('.') {
        let mut bytes = segment.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(crate::schema::invalid(
                path,
                "identifier contains an invalid segment",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{
        ContentDigest, FormatOperationRegistry, MaterializationFailure, MaterializationFidelity,
        MaterializationRequest, MaterializationStyleId, NewlinePolicy, ProfileId, SourceLimits,
        SourcePatch, SourcePatchLimits, SourceSnapshot,
    };
    use consema_graph::{GraphBuilder, GraphLimits, PgceLimits};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn completion_payload() -> PortableValue {
        crate::Completion::new(crate::CompletionStatus::Success, 1, 1, None, None)
            .unwrap()
            .to_value()
    }

    #[test]
    fn envelope_round_trips_over_both_transports() {
        let registry = ContractRegistry::v1();
        let message = ProtocolMessage::new(
            ContractId::new("core.completion", 1).unwrap(),
            completion_payload(),
            registry,
        )
        .unwrap();
        let limits = ProtocolLimits::default();
        assert_eq!(
            ProtocolMessage::from_json(&message.to_json(limits).unwrap(), limits, registry)
                .unwrap(),
            message
        );
        assert_eq!(
            ProtocolMessage::from_pvce(&message.to_pvce(limits).unwrap(), limits, registry)
                .unwrap(),
            message
        );
    }

    #[test]
    fn unknown_contract_and_schema_mismatch_are_distinct() {
        let registry = ContractRegistry::v1();
        assert_eq!(
            ProtocolMessage::new(
                ContractId::new("example.unknown", 1).unwrap(),
                object(vec![
                    ("schema", PortableValue::string("example.unknown@1"),)
                ]),
                registry,
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::UnknownContract
        );
        assert_eq!(
            ProtocolMessage::new(
                ContractId::new("core.diagnostic", 1).unwrap(),
                object(vec![
                    ("schema", PortableValue::string("core.completion@1"),)
                ]),
                registry,
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::SchemaMismatch
        );
    }

    #[test]
    fn matching_schema_does_not_bypass_full_payload_validation() {
        let error = ProtocolMessage::new(
            ContractId::new("core.diagnostic", 1).unwrap(),
            object(vec![
                ("schema", PortableValue::string("core.diagnostic@1")),
                ("placeholder", PortableValue::null()),
            ]),
            ContractRegistry::v1(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::UnknownField);
    }

    #[test]
    fn transport_envelope_is_not_a_nested_payload_contract() {
        let error = ProtocolMessage::new(
            ContractId::new("core.protocol-message", 1).unwrap(),
            object(vec![(
                "schema",
                PortableValue::string("core.protocol-message@1"),
            )]),
            ContractRegistry::v1(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }

    #[test]
    fn registry_is_sorted_and_identifiers_are_strict() {
        for registry in [
            ContractRegistry::v1(),
            ContractRegistry::v2(),
            ContractRegistry::v3(),
            ContractRegistry::v4(),
            ContractRegistry::v5(),
        ] {
            assert!(
                registry
                    .contracts()
                    .windows(2)
                    .all(|pair| { (pair[0].id, pair[0].version) < (pair[1].id, pair[1].version) })
            );
        }
        assert_eq!(ContractRegistry::v1().contracts().len(), 16);
        assert_eq!(ContractRegistry::v2().contracts().len(), 18);
        assert_eq!(ContractRegistry::v3().contracts().len(), 25);
        assert_eq!(ContractRegistry::v4().contracts().len(), 25);
        assert_eq!(ContractRegistry::v5().contracts().len(), 30);
        assert_eq!(
            ContractRegistry::v4().contracts(),
            ContractRegistry::v3().contracts()
        );
        assert!(
            !ContractRegistry::v1()
                .recognizes(&ContractId::new("core.source-snapshot", 1).unwrap())
        );
        assert!(
            !ContractRegistry::v4().recognizes(&ContractId::new("core.portable-graph", 1).unwrap())
        );
        assert!(
            ContractRegistry::v5().recognizes(&ContractId::new("core.portable-graph", 1).unwrap())
        );
        assert!(
            ContractRegistry::v2().recognizes(&ContractId::new("core.source-snapshot", 1).unwrap())
        );
        assert!(ContractId::new("Core.Bad", 1).is_err());
        assert!(ContractId::new("core.bad", 0).is_err());
    }

    #[test]
    fn v2_envelopes_source_snapshots_and_patches_without_changing_v1() {
        let snapshot = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"source".as_slice())).unwrap();
        let patch = SourcePatch::create(
            &snapshot,
            Vec::new(),
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let payloads = [
            (
                ContractId::new("core.source-snapshot", 1).unwrap(),
                crate::SourceSnapshotMessage::from_snapshot(&snapshot)
                    .unwrap()
                    .to_value(),
            ),
            (
                ContractId::new("core.source-patch", 1).unwrap(),
                crate::SourcePatchMessage::from_patch(&patch)
                    .to_value()
                    .unwrap(),
            ),
        ];
        for (contract, payload) in payloads {
            assert_eq!(
                ProtocolMessage::new(contract.clone(), payload.clone(), ContractRegistry::v1())
                    .unwrap_err()
                    .kind(),
                ProtocolErrorKind::UnknownContract
            );
            let message = ProtocolMessage::new(contract, payload, ContractRegistry::v2()).unwrap();
            let limits = ProtocolLimits::default();
            assert_eq!(
                ProtocolMessage::from_json(
                    &message.to_json(limits).unwrap(),
                    limits,
                    ContractRegistry::v2(),
                )
                .unwrap(),
                message
            );
            assert_eq!(
                ProtocolMessage::from_pvce(
                    &message.to_pvce(limits).unwrap(),
                    limits,
                    ContractRegistry::v2(),
                )
                .unwrap(),
                message
            );
        }

        let decoded = crate::SourceSnapshotMessage::from_value(
            ProtocolMessage::new(
                ContractId::new("core.source-snapshot", 1).unwrap(),
                crate::SourceSnapshotMessage::from_snapshot(&snapshot)
                    .unwrap()
                    .to_value(),
                ContractRegistry::v2(),
            )
            .unwrap()
            .payload(),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(decoded.snapshot(), &snapshot);
    }

    #[test]
    fn v3_envelopes_every_new_contract_without_changing_v2() {
        let source_profile = ProfileId::new("toml.1.0", 1);
        let target_profile = ProfileId::new("json.strict", 1);
        let digest = ContentDigest::of(b"unchanged");
        let conversion = crate::ConversionReportMessage::new(
            source_profile.clone(),
            target_profile.clone(),
            crate::ConversionFidelityMessage::Exact,
            crate::ProjectionReportMessage::default(),
            MaterializationFidelity::Exact,
            crate::MaterializationReportMessage::default(),
            crate::ConversionFidelityMessage::Exact,
        )
        .unwrap();
        let edit_plan = crate::EditPlanMessage::new(
            "source:one",
            digest,
            target_profile.clone(),
            Vec::new(),
            Vec::new(),
            digest,
            Vec::new(),
        )
        .unwrap();
        let operations = FormatOperationRegistry::new(target_profile.clone(), Vec::new()).unwrap();
        let request = MaterializationRequest::new(
            target_profile.clone(),
            MaterializationStyleId::new("json.canonical-compact", 1),
        )
        .with_newline(NewlinePolicy::None);
        let result = crate::MaterializationResultMessage::failed(
            target_profile,
            crate::MaterializationFailureMessage::from_failure(
                &MaterializationFailure::UnsupportedStyle,
            ),
            crate::MaterializationReportMessage::default(),
            Vec::new(),
        )
        .unwrap();
        let payloads = [
            ("core.conversion-report", conversion.to_value()),
            ("core.edit-plan", edit_plan.to_value().unwrap()),
            (
                "core.format-operation-registry",
                crate::FormatOperationRegistryMessage::from_registry(&operations).to_value(),
            ),
            (
                "core.materialization-provenance-map",
                crate::MaterializationProvenanceMapMessage::default().to_value(),
            ),
            (
                "core.materialization-report",
                crate::MaterializationReportMessage::default().to_value(),
            ),
            (
                "core.materialization-request",
                crate::MaterializationRequestMessage::from_request(&request)
                    .to_value()
                    .unwrap(),
            ),
            ("core.materialization-result", result.to_value()),
        ];
        let limits = ProtocolLimits::default();
        for (id, payload) in payloads {
            let contract = ContractId::new(id, 1).unwrap();
            assert_eq!(
                ProtocolMessage::new(contract.clone(), payload.clone(), ContractRegistry::v2(),)
                    .unwrap_err()
                    .kind(),
                ProtocolErrorKind::UnknownContract
            );
            let message = ProtocolMessage::new(contract, payload, ContractRegistry::v3()).unwrap();
            assert_eq!(
                ProtocolMessage::from_json(
                    &message.to_json(limits).unwrap(),
                    limits,
                    ContractRegistry::v3(),
                )
                .unwrap(),
                message
            );
            assert_eq!(
                ProtocolMessage::from_pvce(
                    &message.to_pvce(limits).unwrap(),
                    limits,
                    ContractRegistry::v3(),
                )
                .unwrap(),
                message
            );
        }
    }

    #[test]
    fn v5_envelopes_every_new_contract_without_changing_v4() {
        let graph = crate::PortableGraphMessage::from_graph(
            GraphBuilder::new(GraphLimits::default()).build().unwrap(),
            PgceLimits::default(),
        )
        .unwrap();
        let graph_query = crate::GraphQueryResultMessage::new(
            consema_core::QueryDomain::portable_graph_v1(),
            consema_core::MatchRole::GraphNode,
            graph.clone(),
            Vec::new(),
            crate::Completion::new(crate::CompletionStatus::Success, 0, 0, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let provenance = crate::GraphProvenanceMapMessage::default();
        let projection = crate::GraphProjectionResultMessage::new(
            crate::Completion::new(crate::CompletionStatus::Success, 1, 1, None, None).unwrap(),
            Some(graph.clone()),
            provenance.clone(),
            Vec::new(),
        )
        .unwrap();
        let yaml_query = crate::YamlQueryResultMessage::new(
            consema_core::QueryDomain::yaml_native_v1(),
            consema_core::MatchRole::YamlStream,
            Vec::new(),
            crate::Completion::new(crate::CompletionStatus::Success, 0, 0, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let payloads = [
            ("core.graph-projection-result", projection.to_value()),
            ("core.graph-provenance-map", provenance.to_value()),
            ("core.graph-query-result", graph_query.to_value()),
            ("core.portable-graph", graph.to_value()),
            ("core.yaml-query-result", yaml_query.to_value()),
        ];
        let limits = ProtocolLimits::default();
        for (id, payload) in payloads {
            let contract = ContractId::new(id, 1).unwrap();
            assert_eq!(
                ProtocolMessage::new(contract.clone(), payload.clone(), ContractRegistry::v4())
                    .unwrap_err()
                    .kind(),
                ProtocolErrorKind::UnknownContract
            );
            let message = ProtocolMessage::new(contract, payload, ContractRegistry::v5()).unwrap();
            assert_eq!(
                ProtocolMessage::from_json(
                    &message.to_json(limits).unwrap(),
                    limits,
                    ContractRegistry::v5(),
                )
                .unwrap(),
                message
            );
            assert_eq!(
                ProtocolMessage::from_pvce(
                    &message.to_pvce(limits).unwrap(),
                    limits,
                    ContractRegistry::v5(),
                )
                .unwrap(),
                message
            );
        }
    }
}
