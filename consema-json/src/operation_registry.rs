//! JSON and JSONC operation discovery.

use crate::JsonProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact JSON-family profile.
#[must_use]
pub fn format_operation_registry(profile: JsonProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in JSON operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "json.edit.insert-member",
            "json.object",
            vec![
                argument("name", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "json.edit.remove-member",
            "json.object-member",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "json.edit.rename-member",
            "json.object-member",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "json.edit.insert-array-element",
            "json.array",
            vec![
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "json.edit.remove-array-element",
            "json.array-element",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "json.edit.replace-scalar-semantic",
            "json.scalar",
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
            "json.edit.replace-scalar-literal",
            "json.scalar",
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
    fn every_json_profile_publishes_the_frozen_structural_surface() {
        let expected = [
            "json.edit.insert-array-element@1",
            "json.edit.insert-member@1",
            "json.edit.remove-array-element@1",
            "json.edit.remove-member@1",
            "json.edit.rename-member@1",
        ];
        for profile in [JsonProfile::StrictV1, JsonProfile::JsoncBoundedV1] {
            let registry = format_operation_registry(profile);
            let structural: Vec<_> = registry
                .operations()
                .iter()
                .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
                .map(|descriptor| descriptor.id().to_string())
                .collect();
            assert_eq!(structural, expected);
            assert_eq!(registry.operations().len(), 7);
        }
    }
}
