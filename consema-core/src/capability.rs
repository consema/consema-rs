//! Versioned capability declarations.

use std::collections::BTreeSet;

/// A stable namespaced capability contract.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityId {
    namespace: String,
    version: u32,
}

impl CapabilityId {
    /// Creates a capability identifier.
    #[must_use]
    pub fn new(namespace: impl Into<String>, version: u32) -> Self {
        Self {
            namespace: namespace.into(),
            version,
        }
    }

    /// Namespaced identifier without the version suffix.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Immutable contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Implementation support state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImplementationSupport {
    /// The implementation promises the whole contract.
    Conformant,
    /// Support depends on machine-readable preconditions.
    Conditional(Vec<(String, String)>),
    /// The capability is unavailable.
    Unsupported,
}

/// How capability support was verified.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationStatus {
    /// Verified against the named conformance suite.
    Verified,
    /// Declared by the implementation.
    SelfDeclared,
    /// Not verified.
    Unverified,
}

/// A deterministic set of capabilities available to an operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet(BTreeSet<CapabilityId>);

impl CapabilitySet {
    /// Creates an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Adds a capability.
    pub fn insert(&mut self, capability: CapabilityId) -> bool {
        self.0.insert(capability)
    }

    /// Tests whether a capability is available.
    #[must_use]
    pub fn contains(&self, capability: &CapabilityId) -> bool {
        self.0.contains(capability)
    }

    /// Iterates in stable identifier order.
    pub fn iter(&self) -> impl Iterator<Item = &CapabilityId> {
        self.0.iter()
    }
}
