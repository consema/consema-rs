//! Versioned discovery contracts for format-owned edit operations.

use crate::ProfileId;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// Immutable namespaced operation identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FormatOperationId {
    id: Arc<str>,
    version: u32,
}

impl FormatOperationId {
    /// Creates an operation identifier. A registry validates its public spelling.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Namespaced identifier without its version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable operation version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

impl Display for FormatOperationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.id, self.version)
    }
}

/// Versioned semantic role required of an operation target or placement anchor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationTargetRoleId {
    id: Arc<str>,
    version: u32,
}

impl OperationTargetRoleId {
    /// Creates a target role identifier. A registry validates its public spelling.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Namespaced role identifier without its version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable role version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Closed v1 argument type vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationArgumentKind {
    /// Snapshot-bound structural identity.
    NodeRef,
    /// Unicode string interpreted under the operation contract.
    String,
    /// Complete portable semantic value.
    PortableValue,
    /// Start, end, before-anchor, or after-anchor placement.
    Placement,
    /// Exact source literal bytes.
    ExactBytes,
    /// Explicit representation policy owned by the format.
    RepresentationPolicy,
}

/// One named field in an operation's immutable argument schema.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationArgumentDescriptor {
    name: Arc<str>,
    kind: OperationArgumentKind,
    required: bool,
}

impl OperationArgumentDescriptor {
    /// Creates one argument descriptor. A registry validates name uniqueness and spelling.
    #[must_use]
    pub fn new(name: impl Into<Arc<str>>, kind: OperationArgumentKind, required: bool) -> Self {
        Self {
            name: name.into(),
            kind,
            required,
        }
    }

    /// Stable field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Closed argument kind.
    #[must_use]
    pub const fn kind(&self) -> OperationArgumentKind {
        self.kind
    }

    /// Whether the operation rejects omission of this argument.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// Truthful implementation support classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationSupport {
    /// Supported through the format's versioned structural operation surface.
    Supported,
    /// Supported by an existing format-specific typed Rust API.
    ExistingTypedCapability,
    /// Known to the registry vocabulary but not implemented for this profile.
    Unsupported,
}

/// One complete discoverable operation contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatOperationDescriptor {
    id: FormatOperationId,
    target_role: OperationTargetRoleId,
    arguments: Arc<[OperationArgumentDescriptor]>,
    support: OperationSupport,
}

impl FormatOperationDescriptor {
    /// Creates one descriptor. Its enclosing registry performs structural validation.
    #[must_use]
    pub fn new(
        id: FormatOperationId,
        target_role: OperationTargetRoleId,
        arguments: Vec<OperationArgumentDescriptor>,
        support: OperationSupport,
    ) -> Self {
        Self {
            id,
            target_role,
            arguments: Arc::from(arguments),
            support,
        }
    }

    /// Immutable operation identifier.
    #[must_use]
    pub const fn id(&self) -> &FormatOperationId {
        &self.id
    }

    /// Semantic role required of the primary target.
    #[must_use]
    pub const fn target_role(&self) -> &OperationTargetRoleId {
        &self.target_role
    }

    /// Fixed ordered argument schema.
    #[must_use]
    pub fn arguments(&self) -> &[OperationArgumentDescriptor] {
        &self.arguments
    }

    /// Truthful implementation support.
    #[must_use]
    pub const fn support(&self) -> OperationSupport {
        self.support
    }
}

/// Deterministically ordered operation contracts for one exact profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatOperationRegistry {
    profile: ProfileId,
    operations: Arc<[FormatOperationDescriptor]>,
}

impl FormatOperationRegistry {
    /// Validates and canonicalizes all descriptors before publishing the registry.
    pub fn new(
        profile: ProfileId,
        mut operations: Vec<FormatOperationDescriptor>,
    ) -> Result<Self, FormatOperationRegistryError> {
        if !valid_namespaced_id(profile.id()) || profile.version() == 0 {
            return Err(FormatOperationRegistryError::InvalidProfile);
        }

        for (operation_index, operation) in operations.iter().enumerate() {
            if !valid_namespaced_id(operation.id.id()) || operation.id.version() == 0 {
                return Err(FormatOperationRegistryError::InvalidOperationId { operation_index });
            }
            if !valid_namespaced_id(operation.target_role.id())
                || operation.target_role.version() == 0
            {
                return Err(FormatOperationRegistryError::InvalidTargetRole { operation_index });
            }
            let mut names = HashSet::with_capacity(operation.arguments.len());
            for (argument_index, argument) in operation.arguments.iter().enumerate() {
                if !valid_argument_name(argument.name()) {
                    return Err(FormatOperationRegistryError::InvalidArgumentName {
                        operation_index,
                        argument_index,
                    });
                }
                if !names.insert(argument.name()) {
                    return Err(FormatOperationRegistryError::DuplicateArgument {
                        operation_index,
                        argument_index,
                    });
                }
            }
        }

        operations.sort_by(|left, right| left.id.cmp(&right.id));
        for (operation_index, pair) in operations.windows(2).enumerate() {
            if pair[0].id == pair[1].id {
                return Err(FormatOperationRegistryError::DuplicateOperation {
                    operation_index: operation_index + 1,
                });
            }
        }

        Ok(Self {
            profile,
            operations: Arc::from(operations),
        })
    }

    /// Exact profile whose behavior the registry describes.
    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Canonically ordered operation descriptors.
    #[must_use]
    pub fn operations(&self) -> &[FormatOperationDescriptor] {
        &self.operations
    }

    /// Finds one exact operation ID/version.
    #[must_use]
    pub fn descriptor(&self, id: &FormatOperationId) -> Option<&FormatOperationDescriptor> {
        self.operations
            .binary_search_by(|candidate| candidate.id.cmp(id))
            .ok()
            .map(|index| &self.operations[index])
    }
}

/// Registry construction failure before an invalid discovery surface is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatOperationRegistryError {
    /// Profile ID or version is not a stable public identifier.
    InvalidProfile,
    /// Operation ID or version is invalid.
    InvalidOperationId {
        /// Operation position before canonical sorting.
        operation_index: usize,
    },
    /// Target role ID or version is invalid.
    InvalidTargetRole {
        /// Operation position before canonical sorting.
        operation_index: usize,
    },
    /// Argument name is not lower snake case.
    InvalidArgumentName {
        /// Operation position before canonical sorting.
        operation_index: usize,
        /// Argument position.
        argument_index: usize,
    },
    /// One operation schema repeats an argument name.
    DuplicateArgument {
        /// Operation position before canonical sorting.
        operation_index: usize,
        /// Position of the repeated argument.
        argument_index: usize,
    },
    /// More than one descriptor declares the same exact operation ID/version.
    DuplicateOperation {
        /// Position of the duplicate after canonical sorting.
        operation_index: usize,
    },
}

impl Display for FormatOperationRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FormatOperationRegistryError {}

fn valid_namespaced_id(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn valid_argument_name(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str, argument_names: &[&str]) -> FormatOperationDescriptor {
        FormatOperationDescriptor::new(
            FormatOperationId::new(id, 1),
            OperationTargetRoleId::new("json.object", 1),
            argument_names
                .iter()
                .map(|name| {
                    OperationArgumentDescriptor::new(
                        *name,
                        OperationArgumentKind::PortableValue,
                        true,
                    )
                })
                .collect(),
            OperationSupport::Supported,
        )
    }

    #[test]
    fn registry_canonicalizes_and_resolves_exact_versions() {
        let first = descriptor("json.edit.remove-member", &["target"]);
        let second = descriptor("json.edit.insert-member", &["name", "value"]);
        let registry = FormatOperationRegistry::new(
            ProfileId::new("json.strict", 1),
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        assert_eq!(registry.operations()[0], second);
        assert_eq!(registry.operations()[1], first);
        assert_eq!(
            registry.descriptor(&FormatOperationId::new("json.edit.remove-member", 1)),
            Some(&registry.operations()[1])
        );
        assert_eq!(
            registry.descriptor(&FormatOperationId::new("json.edit.remove-member", 2)),
            None
        );
        assert!(FormatOperationRegistry::new(ProfileId::new("toml.1.0", 1), vec![]).is_ok());
    }

    #[test]
    fn registry_rejects_ambiguous_or_unstable_schemas() {
        let duplicate = descriptor("json.edit.remove-member", &["target"]);
        assert!(matches!(
            FormatOperationRegistry::new(
                ProfileId::new("json.strict", 1),
                vec![duplicate.clone(), duplicate],
            ),
            Err(FormatOperationRegistryError::DuplicateOperation { .. })
        ));
        assert!(matches!(
            FormatOperationRegistry::new(
                ProfileId::new("json.strict", 1),
                vec![descriptor(
                    "json.edit.insert-member",
                    &["new_value", "new_value"]
                )],
            ),
            Err(FormatOperationRegistryError::DuplicateArgument { .. })
        ));
        assert!(matches!(
            FormatOperationRegistry::new(
                ProfileId::new("json.strict", 1),
                vec![descriptor("JSON.edit.insert-member", &["value"])],
            ),
            Err(FormatOperationRegistryError::InvalidOperationId { .. })
        ));
    }
}
