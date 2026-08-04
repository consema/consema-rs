//! Transferable Profile and Capability registry records.

use crate::schema::{
    exact_fields, nullable_string, object, optional_string, schema_fields, sequence, string,
    unsigned_u32,
};
use crate::{ContractId, ProtocolError};
use consema_core::{
    BigInteger, CapabilityId, ImplementationSupport, ObjectBuilder, PortableValue, SequenceBuilder,
    VerificationStatus,
};
use std::collections::{BTreeMap, BTreeSet};

/// Versioned reference to a Profile, whose ID may contain numeric segments.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileReference {
    id: String,
    version: u32,
}

impl ProfileReference {
    /// Validates and creates a profile reference.
    pub fn new(id: impl Into<String>, version: u32) -> Result<Self, ProtocolError> {
        let id = id.into();
        validate_namespace(&id, true, "$.profile.id")?;
        if version == 0 {
            return Err(crate::schema::invalid(
                "$.profile.version",
                "version must be non-zero",
            ));
        }
        Ok(Self { id, version })
    }

    /// Profile namespace.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Immutable language profile registry descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    format_family_id: String,
    format_family_version: u32,
    profile_id: String,
    profile_version: u32,
    base_profile: Option<ProfileReference>,
    differences: Vec<String>,
    required_capabilities: Vec<CapabilityId>,
}

impl ProfileDescriptor {
    /// Creates a normalized descriptor and rejects malformed or duplicate facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_family_id: impl Into<String>,
        format_family_version: u32,
        profile_id: impl Into<String>,
        profile_version: u32,
        base_profile: Option<ProfileReference>,
        mut differences: Vec<String>,
        mut required_capabilities: Vec<CapabilityId>,
    ) -> Result<Self, ProtocolError> {
        let format_family_id = format_family_id.into();
        let profile_id = profile_id.into();
        validate_namespace(&format_family_id, false, "$.format_family_id")?;
        validate_namespace(&profile_id, true, "$.profile_id")?;
        if format_family_version == 0 || profile_version == 0 {
            return Err(crate::schema::invalid(
                "$",
                "family and profile versions must be non-zero",
            ));
        }
        for difference in &differences {
            validate_namespace(difference, true, "$.differences")?;
        }
        for capability in &required_capabilities {
            ContractId::new(capability.namespace(), capability.version())?;
        }
        differences.sort();
        if differences.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(crate::schema::invalid(
                "$.differences",
                "difference IDs must be unique",
            ));
        }
        required_capabilities.sort();
        if required_capabilities
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(crate::schema::invalid(
                "$.required_capabilities",
                "capability IDs must be unique",
            ));
        }
        Ok(Self {
            format_family_id,
            format_family_version,
            profile_id,
            profile_version,
            base_profile,
            differences,
            required_capabilities,
        })
    }

    /// Format-family namespace.
    #[must_use]
    pub fn format_family_id(&self) -> &str {
        &self.format_family_id
    }

    /// Format-family contract version.
    #[must_use]
    pub const fn format_family_version(&self) -> u32 {
        self.format_family_version
    }

    /// Profile namespace.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Profile version.
    #[must_use]
    pub const fn profile_version(&self) -> u32 {
        self.profile_version
    }

    /// Optional immutable base profile.
    #[must_use]
    pub const fn base_profile(&self) -> Option<&ProfileReference> {
        self.base_profile.as_ref()
    }

    /// Sorted stable difference identifiers.
    #[must_use]
    pub fn differences(&self) -> &[String] {
        &self.differences
    }

    /// Sorted required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityId] {
        &self.required_capabilities
    }

    /// Encodes `core.profile-descriptor@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut differences = SequenceBuilder::new();
        for difference in &self.differences {
            differences.push(PortableValue::string(difference.as_str()));
        }
        let mut capabilities = SequenceBuilder::new();
        for capability in &self.required_capabilities {
            capabilities.push(reference_value(
                capability.namespace(),
                capability.version(),
            ));
        }
        object(vec![
            ("schema", PortableValue::string("core.profile-descriptor@1")),
            (
                "format_family_id",
                PortableValue::string(self.format_family_id.as_str()),
            ),
            (
                "format_family_version",
                PortableValue::integer(BigInteger::from(i64::from(self.format_family_version))),
            ),
            (
                "profile_id",
                PortableValue::string(self.profile_id.as_str()),
            ),
            (
                "profile_version",
                PortableValue::integer(BigInteger::from(i64::from(self.profile_version))),
            ),
            (
                "base_profile",
                self.base_profile
                    .as_ref()
                    .map_or_else(PortableValue::null, |base| {
                        reference_value(base.id(), base.version())
                    }),
            ),
            ("differences", differences.build()),
            ("required_capabilities", capabilities.build()),
        ])
    }

    /// Strictly decodes `core.profile-descriptor@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.profile-descriptor@1",
            &[
                "schema",
                "format_family_id",
                "format_family_version",
                "profile_id",
                "profile_version",
                "base_profile",
                "differences",
                "required_capabilities",
            ],
            "$",
        )?;
        let base_profile = if fields[5] == &PortableValue::null() {
            None
        } else {
            Some(profile_reference(fields[5], "$.base_profile")?)
        };
        let differences = sequence(fields[6], "$.differences")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                string(item, &format!("$.differences[{index}]")).map(str::to_owned)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let required_capabilities = sequence(fields[7], "$.required_capabilities")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                contract_reference(item, &format!("$.required_capabilities[{index}]"))
                    .map(|id| CapabilityId::new(id.id(), id.version()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            string(fields[1], "$.format_family_id")?,
            unsigned_u32(fields[2], "$.format_family_version")?,
            string(fields[3], "$.profile_id")?,
            unsigned_u32(fields[4], "$.profile_version")?,
            base_profile,
            differences,
            required_capabilities,
        )
    }
}

/// One implementation's support and verification claim for a capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDeclaration {
    capability: CapabilityId,
    support: ImplementationSupport,
    verification: VerificationStatus,
    suite_id: Option<String>,
}

impl CapabilityDeclaration {
    /// Validates cross-field support and verification invariants.
    pub fn new(
        capability: CapabilityId,
        support: ImplementationSupport,
        verification: VerificationStatus,
        suite_id: Option<String>,
    ) -> Result<Self, ProtocolError> {
        ContractId::new(capability.namespace(), capability.version())?;
        match &support {
            ImplementationSupport::Conditional(preconditions) => {
                if preconditions.is_empty() {
                    return Err(crate::schema::invalid(
                        "$.preconditions",
                        "Conditional support requires preconditions",
                    ));
                }
                let keys = preconditions
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<BTreeSet<_>>();
                if keys.len() != preconditions.len() {
                    return Err(crate::schema::invalid(
                        "$.preconditions",
                        "precondition keys must be unique",
                    ));
                }
            }
            ImplementationSupport::Conformant | ImplementationSupport::Unsupported => {}
        }
        match (verification, suite_id.as_deref()) {
            (VerificationStatus::Verified, Some(id)) => {
                validate_namespace(id, true, "$.suite_id")?;
            }
            (VerificationStatus::Verified, None) => {
                return Err(crate::schema::invalid(
                    "$.suite_id",
                    "Verified requires a suite ID",
                ));
            }
            (VerificationStatus::SelfDeclared | VerificationStatus::Unverified, None) => {}
            (VerificationStatus::SelfDeclared | VerificationStatus::Unverified, Some(_)) => {
                return Err(crate::schema::invalid(
                    "$.suite_id",
                    "only Verified may name a suite",
                ));
            }
        }
        Ok(Self {
            capability,
            support,
            verification,
            suite_id,
        })
    }

    /// Capability contract.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// Declared implementation support.
    #[must_use]
    pub const fn support(&self) -> &ImplementationSupport {
        &self.support
    }

    /// Verification status.
    #[must_use]
    pub const fn verification(&self) -> VerificationStatus {
        self.verification
    }

    /// Conformance suite used for Verified status.
    #[must_use]
    pub fn suite_id(&self) -> Option<&str> {
        self.suite_id.as_deref()
    }

    /// Encodes `core.capability-declaration@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let (support, preconditions) = match &self.support {
            ImplementationSupport::Conformant => ("Conformant", Vec::new()),
            ImplementationSupport::Conditional(preconditions) => {
                ("Conditional", preconditions.clone())
            }
            ImplementationSupport::Unsupported => ("Unsupported", Vec::new()),
        };
        let sorted = preconditions.into_iter().collect::<BTreeMap<_, _>>();
        let mut precondition_object = ObjectBuilder::new();
        for (name, value) in sorted {
            precondition_object
                .insert(name, PortableValue::string(value))
                .expect("validated precondition keys are unique");
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.capability-declaration@1"),
            ),
            (
                "capability_id",
                PortableValue::string(self.capability.namespace()),
            ),
            (
                "capability_version",
                PortableValue::integer(BigInteger::from(i64::from(self.capability.version()))),
            ),
            ("support", PortableValue::string(support)),
            ("preconditions", precondition_object.build()),
            (
                "verification",
                PortableValue::string(verification_name(self.verification)),
            ),
            ("suite_id", nullable_string(self.suite_id.as_deref())),
        ])
    }

    /// Strictly decodes `core.capability-declaration@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.capability-declaration@1",
            &[
                "schema",
                "capability_id",
                "capability_version",
                "support",
                "preconditions",
                "verification",
                "suite_id",
            ],
            "$",
        )?;
        let precondition_entries = fields[4].as_object().ok_or_else(|| {
            crate::schema::invalid("$.preconditions", "expected Object<String, String>")
        })?;
        let mut preconditions = Vec::new();
        for entry in precondition_entries {
            preconditions.push((
                entry.key().to_owned(),
                string(entry.value(), &format!("$.preconditions.{}", entry.key()))?.to_owned(),
            ));
        }
        let support = match string(fields[3], "$.support")? {
            "Conformant" if preconditions.is_empty() => ImplementationSupport::Conformant,
            "Conditional" => ImplementationSupport::Conditional(preconditions),
            "Unsupported" if preconditions.is_empty() => ImplementationSupport::Unsupported,
            _ => {
                return Err(crate::schema::invalid(
                    "$.support",
                    "invalid support/preconditions combination",
                ));
            }
        };
        let verification = match string(fields[5], "$.verification")? {
            "Verified" => VerificationStatus::Verified,
            "SelfDeclared" => VerificationStatus::SelfDeclared,
            "Unverified" => VerificationStatus::Unverified,
            _ => {
                return Err(crate::schema::invalid(
                    "$.verification",
                    "unknown verification status",
                ));
            }
        };
        Self::new(
            CapabilityId::new(
                string(fields[1], "$.capability_id")?,
                unsigned_u32(fields[2], "$.capability_version")?,
            ),
            support,
            verification,
            optional_string(fields[6], "$.suite_id")?.map(str::to_owned),
        )
    }
}

fn reference_value(id: &str, version: u32) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(id)),
        (
            "version",
            PortableValue::integer(BigInteger::from(i64::from(version))),
        ),
    ])
}

fn contract_reference(value: &PortableValue, path: &str) -> Result<ContractId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    ContractId::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )
}

fn profile_reference(value: &PortableValue, path: &str) -> Result<ProfileReference, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    ProfileReference::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )
}

const fn verification_name(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Verified => "Verified",
        VerificationStatus::SelfDeclared => "SelfDeclared",
        VerificationStatus::Unverified => "Unverified",
    }
}

fn validate_namespace(
    identifier: &str,
    require_dot: bool,
    path: &str,
) -> Result<(), ProtocolError> {
    if identifier.is_empty() || identifier.len() > 255 || (require_dot && !identifier.contains('.'))
    {
        return Err(crate::schema::invalid(
            path,
            "invalid namespaced identifier",
        ));
    }
    for (index, segment) in identifier.split('.').enumerate() {
        let mut bytes = segment.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || (index != 0 && byte.is_ascii_digit()))
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(crate::schema::invalid(path, "invalid identifier segment"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_descriptor_is_normalized_and_strict() {
        let descriptor = ProfileDescriptor::new(
            "toml",
            1,
            "toml.1-0",
            1,
            None,
            vec!["toml.datetime".to_owned(), "toml.array-table".to_owned()],
            vec![CapabilityId::new("core.document.exact-roundtrip", 1)],
        )
        .unwrap();
        assert_eq!(
            ProfileDescriptor::from_value(&descriptor.to_value()).unwrap(),
            descriptor
        );
        assert_eq!(descriptor.differences()[0], "toml.array-table");
    }

    #[test]
    fn capability_cross_field_invariants_are_enforced() {
        let capability = CapabilityId::new("core.query.ordered-results", 1);
        assert!(
            CapabilityDeclaration::new(
                capability.clone(),
                ImplementationSupport::Conditional(Vec::new()),
                VerificationStatus::Unverified,
                None,
            )
            .is_err()
        );
        let declaration = CapabilityDeclaration::new(
            capability,
            ImplementationSupport::Conformant,
            VerificationStatus::Verified,
            Some("consema.conformance".to_owned()),
        )
        .unwrap();
        assert_eq!(
            CapabilityDeclaration::from_value(&declaration.to_value()).unwrap(),
            declaration
        );
    }
}
