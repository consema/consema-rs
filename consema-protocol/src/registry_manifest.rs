//! Semantic-model contract and public error-code manifest.

use crate::error_registry::{category_name, parse_category};
use crate::schema::{exact_fields, object, schema_fields, sequence, string, unsigned_u32};
use crate::{ContractId, ContractRegistry, ContractStability, ErrorCodeRegistry, ProtocolError};
use consema_core::{BigInteger, DiagnosticCategory, PortableValue, SequenceBuilder};

/// Owned contract entry in a transferable registry manifest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContractManifestEntry {
    /// Contract identity.
    pub contract: ContractId,
    /// Compatibility classification.
    pub stability: ContractStability,
}

/// Owned error-code entry in a transferable registry manifest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErrorCodeManifestEntry {
    /// Full code including version.
    pub code: String,
    /// Semantic category.
    pub category: DiagnosticCategory,
    /// First release containing the code.
    pub introduced: String,
    /// Human-facing description.
    pub description: String,
}

/// `core.registry-manifest@1` for one semantic-model contract set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryManifest {
    semantic_model: ContractId,
    contracts: Vec<ContractManifestEntry>,
    error_codes: Vec<ErrorCodeManifestEntry>,
}

impl RegistryManifest {
    /// Builds the frozen Consema 0.3 `core.semantic-model@1` manifest.
    #[must_use]
    pub fn v1() -> Self {
        Self::from_registries(1, ContractRegistry::v1(), ErrorCodeRegistry::v1())
    }

    /// Builds the Consema 0.4 `core.semantic-model@2` manifest.
    #[must_use]
    pub fn v2() -> Self {
        Self::from_registries(2, ContractRegistry::v2(), ErrorCodeRegistry::v2())
    }

    /// Builds the Consema 0.5 `core.semantic-model@3` manifest.
    #[must_use]
    pub fn v3() -> Self {
        Self::from_registries(3, ContractRegistry::v3(), ErrorCodeRegistry::v3())
    }

    /// Builds the Consema 0.6 `core.semantic-model@4` manifest.
    #[must_use]
    pub fn v4() -> Self {
        Self::from_registries(4, ContractRegistry::v4(), ErrorCodeRegistry::v4())
    }

    /// Builds the Consema 0.7 `core.semantic-model@5` manifest.
    #[must_use]
    pub fn v5() -> Self {
        Self::from_registries(5, ContractRegistry::v5(), ErrorCodeRegistry::v5())
    }

    /// Builds the exact current Rust semantic-model manifest.
    #[must_use]
    pub fn current() -> Self {
        Self::v5()
    }

    fn from_registries(
        semantic_model_version: u32,
        contract_registry: ContractRegistry,
        error_code_registry: ErrorCodeRegistry,
    ) -> Self {
        let contracts = contract_registry
            .contracts()
            .iter()
            .map(|descriptor| ContractManifestEntry {
                contract: ContractId::new(descriptor.id, descriptor.version)
                    .expect("static contract descriptor is valid"),
                stability: descriptor.stability,
            })
            .collect();
        let error_codes = error_code_registry
            .codes()
            .iter()
            .map(|descriptor| ErrorCodeManifestEntry {
                code: descriptor.code.to_owned(),
                category: descriptor.category,
                introduced: descriptor.introduced.to_owned(),
                description: descriptor.description.to_owned(),
            })
            .collect();
        Self {
            semantic_model: ContractId::new("core.semantic-model", semantic_model_version)
                .expect("static semantic model is valid"),
            contracts,
            error_codes,
        }
    }

    /// Validates a manifest's sorted, unique, versioned records.
    pub fn new(
        semantic_model: ContractId,
        contracts: Vec<ContractManifestEntry>,
        error_codes: Vec<ErrorCodeManifestEntry>,
    ) -> Result<Self, ProtocolError> {
        if contracts
            .windows(2)
            .any(|pair| pair[0].contract >= pair[1].contract)
            || error_codes
                .windows(2)
                .any(|pair| pair[0].code >= pair[1].code)
        {
            return Err(crate::schema::invalid(
                "$",
                "manifest records must be sorted and unique",
            ));
        }
        for entry in &error_codes {
            parse_versioned_code(&entry.code)?;
            if entry.introduced.is_empty() || entry.description.is_empty() {
                return Err(crate::schema::invalid(
                    "$.error_codes",
                    "error-code metadata cannot be empty",
                ));
            }
        }
        Ok(Self {
            semantic_model,
            contracts,
            error_codes,
        })
    }

    /// Semantic model ID/version.
    #[must_use]
    pub const fn semantic_model(&self) -> &ContractId {
        &self.semantic_model
    }

    /// Sorted contract records.
    #[must_use]
    pub fn contracts(&self) -> &[ContractManifestEntry] {
        &self.contracts
    }

    /// Sorted error-code records.
    #[must_use]
    pub fn error_codes(&self) -> &[ErrorCodeManifestEntry] {
        &self.error_codes
    }

    /// Whether this manifest exactly equals the built-in current contract set.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self == &Self::current()
    }

    /// Encodes `core.registry-manifest@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut contracts = SequenceBuilder::new();
        for entry in &self.contracts {
            contracts.push(object(vec![
                ("id", PortableValue::string(entry.contract.id())),
                (
                    "version",
                    PortableValue::integer(BigInteger::from(i64::from(entry.contract.version()))),
                ),
                (
                    "stability",
                    PortableValue::string(stability_name(entry.stability)),
                ),
            ]));
        }
        let mut error_codes = SequenceBuilder::new();
        for entry in &self.error_codes {
            error_codes.push(object(vec![
                ("code", PortableValue::string(entry.code.as_str())),
                (
                    "category",
                    PortableValue::string(category_name(entry.category)),
                ),
                (
                    "introduced",
                    PortableValue::string(entry.introduced.as_str()),
                ),
                ("stability", PortableValue::string("Stable")),
                (
                    "description",
                    PortableValue::string(entry.description.as_str()),
                ),
            ]));
        }
        object(vec![
            ("schema", PortableValue::string("core.registry-manifest@1")),
            (
                "semantic_model",
                object(vec![
                    ("id", PortableValue::string(self.semantic_model.id())),
                    (
                        "version",
                        PortableValue::integer(BigInteger::from(i64::from(
                            self.semantic_model.version(),
                        ))),
                    ),
                ]),
            ),
            ("contracts", contracts.build()),
            ("error_codes", error_codes.build()),
        ])
    }

    /// Strictly decodes `core.registry-manifest@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.registry-manifest@1",
            &["schema", "semantic_model", "contracts", "error_codes"],
            "$",
        )?;
        let semantic_model = parse_contract(fields[1], "$.semantic_model")?;
        let contracts = sequence(fields[2], "$.contracts")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let path = format!("$.contracts[{index}]");
                let fields = exact_fields(item, &["id", "version", "stability"], &path)?;
                Ok(ContractManifestEntry {
                    contract: ContractId::new(
                        string(fields[0], &format!("{path}.id"))?,
                        unsigned_u32(fields[1], &format!("{path}.version"))?,
                    )?,
                    stability: parse_stability(string(fields[2], &format!("{path}.stability"))?)?,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let error_codes = sequence(fields[3], "$.error_codes")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let path = format!("$.error_codes[{index}]");
                let fields = exact_fields(
                    item,
                    &["code", "category", "introduced", "stability", "description"],
                    &path,
                )?;
                if string(fields[3], &format!("{path}.stability"))? != "Stable" {
                    return Err(crate::schema::invalid(
                        &format!("{path}.stability"),
                        "unknown error-code stability",
                    ));
                }
                Ok(ErrorCodeManifestEntry {
                    code: string(fields[0], &format!("{path}.code"))?.to_owned(),
                    category: parse_category(fields[1], &format!("{path}.category"))?,
                    introduced: string(fields[2], &format!("{path}.introduced"))?.to_owned(),
                    description: string(fields[4], &format!("{path}.description"))?.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        Self::new(semantic_model, contracts, error_codes)
    }
}

fn parse_contract(value: &PortableValue, path: &str) -> Result<ContractId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    ContractId::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )
}

fn parse_versioned_code(value: &str) -> Result<(), ProtocolError> {
    let (id, version) = value.rsplit_once('@').ok_or_else(|| {
        crate::schema::invalid("$.error_codes.code", "code lacks @version suffix")
    })?;
    let version = version
        .parse::<u32>()
        .map_err(|_| crate::schema::invalid("$.error_codes.code", "code version is invalid"))?;
    ContractId::new(id, version).map(|_| ())
}

const fn stability_name(stability: ContractStability) -> &'static str {
    match stability {
        ContractStability::Stable => "Stable",
        ContractStability::Transport => "Transport",
    }
}

fn parse_stability(value: &str) -> Result<ContractStability, ProtocolError> {
    match value {
        "Stable" => Ok(ContractStability::Stable),
        "Transport" => Ok(ContractStability::Transport),
        _ => Err(crate::schema::invalid(
            "$.stability",
            "unknown contract stability",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_registry_manifests_round_trip_and_are_self_consistent() {
        let versions = [
            (
                RegistryManifest::v1(),
                ContractRegistry::v1(),
                ErrorCodeRegistry::v1(),
                16,
                55,
                false,
            ),
            (
                RegistryManifest::v2(),
                ContractRegistry::v2(),
                ErrorCodeRegistry::v2(),
                18,
                62,
                false,
            ),
            (
                RegistryManifest::v3(),
                ContractRegistry::v3(),
                ErrorCodeRegistry::v3(),
                25,
                90,
                false,
            ),
            (
                RegistryManifest::v4(),
                ContractRegistry::v4(),
                ErrorCodeRegistry::v4(),
                25,
                92,
                false,
            ),
            (
                RegistryManifest::v5(),
                ContractRegistry::v5(),
                ErrorCodeRegistry::v5(),
                30,
                132,
                true,
            ),
        ];
        for (manifest, contracts, error_codes, contract_count, code_count, current) in versions {
            assert_eq!(manifest.contracts().len(), contract_count);
            assert_eq!(manifest.error_codes().len(), code_count);
            assert_eq!(manifest.is_current(), current);
            let decoded = RegistryManifest::from_value(&manifest.to_value()).unwrap();
            assert_eq!(decoded, manifest);
            assert_eq!(decoded.is_current(), current);
            assert!(
                decoded
                    .contracts()
                    .iter()
                    .all(|entry| contracts.recognizes(&entry.contract))
            );
            assert!(
                decoded
                    .error_codes()
                    .iter()
                    .all(|entry| error_codes.contains(&entry.code))
            );
        }
        assert_eq!(RegistryManifest::current(), RegistryManifest::v5());
    }
}
