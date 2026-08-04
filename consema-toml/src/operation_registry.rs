//! TOML operation discovery.

use crate::TomlProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact TOML profile.
#[must_use]
pub fn format_operation_registry(profile: TomlProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in TOML operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "toml.edit.insert-entry",
            "toml.table-item",
            vec![
                argument("key", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "toml.edit.remove-entry",
            "toml.entry",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "toml.edit.rename-entry",
            "toml.entry",
            vec![argument("key", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "toml.edit.insert-array-element",
            "toml.array-item",
            vec![
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "toml.edit.remove-array-element",
            "toml.array-element",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "toml.edit.replace-scalar-semantic",
            "toml.scalar-item",
            vec![
                argument("value", OperationArgumentKind::PortableValue),
                argument(
                    "representation_policy",
                    OperationArgumentKind::RepresentationPolicy,
                ),
            ],
            OperationSupport::ExistingTypedCapability,
        ),
        descriptor(
            "toml.edit.replace-scalar-literal",
            "toml.scalar-item",
            vec![argument("literal", OperationArgumentKind::ExactBytes)],
            OperationSupport::ExistingTypedCapability,
        ),
    ]
}

fn descriptor(
    id: &'static str,
    target_role: &'static str,
    arguments: Vec<OperationArgumentDescriptor>,
    support: OperationSupport,
) -> FormatOperationDescriptor {
    FormatOperationDescriptor::new(
        FormatOperationId::new(id, 1),
        OperationTargetRoleId::new(target_role, 1),
        arguments,
        support,
    )
}

fn argument(name: &'static str, kind: OperationArgumentKind) -> OperationArgumentDescriptor {
    OperationArgumentDescriptor::new(name, kind, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_profile_publishes_the_frozen_structural_surface() {
        let registry = format_operation_registry(TomlProfile::Toml10V1);
        let structural: Vec<_> = registry
            .operations()
            .iter()
            .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
            .map(|descriptor| descriptor.id().to_string())
            .collect();
        assert_eq!(
            structural,
            [
                "toml.edit.insert-array-element@1",
                "toml.edit.insert-entry@1",
                "toml.edit.remove-array-element@1",
                "toml.edit.remove-entry@1",
                "toml.edit.rename-entry@1",
            ]
        );
        assert_eq!(registry.operations().len(), 7);
    }
}
