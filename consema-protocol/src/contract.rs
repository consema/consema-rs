//! Contract identifiers, registry, and the common protocol envelope.

use crate::schema::{object, schema_fields, string, unsigned_u32};
use crate::{
    ProtocolError, ProtocolErrorKind, ProtocolLimits, decode_json, decode_pvce, encode_json,
    encode_pvce,
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

const CONTRACTS: &[ContractDescriptor] = &[
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
    descriptor("core.semantic-model", ContractStability::Stable),
];

const fn descriptor(id: &'static str, stability: ContractStability) -> ContractDescriptor {
    ContractDescriptor {
        id,
        version: 1,
        stability,
    }
}

/// Closed Consema 0.3 protocol contract registry.
#[derive(Clone, Copy, Debug, Default)]
pub struct ContractRegistry;

impl ContractRegistry {
    /// Current immutable registry.
    #[must_use]
    pub const fn v1() -> Self {
        Self
    }

    /// Sorted registered contracts.
    #[must_use]
    pub const fn contracts(self) -> &'static [ContractDescriptor] {
        CONTRACTS
    }

    /// Whether an exact ID/version pair is registered.
    #[must_use]
    pub fn recognizes(self, contract: &ContractId) -> bool {
        CONTRACTS
            .binary_search_by(|candidate| {
                (candidate.id, candidate.version).cmp(&(contract.id(), contract.version()))
            })
            .is_ok()
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
        if !registry.recognizes(&contract) {
            return Err(ProtocolError::new(
                ProtocolErrorKind::UnknownContract,
                "$.contract",
                contract.schema(),
            ));
        }
        validate_payload_schema(&payload, &contract)?;
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

    fn diagnostic_payload() -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("core.diagnostic@1")),
            ("placeholder", PortableValue::null()),
        ])
    }

    #[test]
    fn envelope_round_trips_over_both_transports() {
        let registry = ContractRegistry::v1();
        let message = ProtocolMessage::new(
            ContractId::new("core.diagnostic", 1).unwrap(),
            diagnostic_payload(),
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
    fn registry_is_sorted_and_identifiers_are_strict() {
        let contracts = ContractRegistry::v1().contracts();
        assert!(
            contracts
                .windows(2)
                .all(|pair| { (pair[0].id, pair[0].version) < (pair[1].id, pair[1].version) })
        );
        assert!(ContractId::new("Core.Bad", 1).is_err());
        assert!(ContractId::new("core.bad", 0).is_err());
    }
}
