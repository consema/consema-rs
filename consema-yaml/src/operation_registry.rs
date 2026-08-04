//! YAML operation discovery for both frozen language profiles.

use crate::YamlProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact YAML profile.
#[must_use]
pub fn format_operation_registry(profile: YamlProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in YAML operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "yaml.edit.insert-alias",
            "yaml.sequence",
            vec![
                argument("anchor", OperationArgumentKind::NodeRef),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.insert-mapping-entry",
            "yaml.mapping",
            vec![
                argument("key", OperationArgumentKind::PortableValue),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.insert-sequence-element",
            "yaml.sequence",
            vec![
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.remove-mapping-entry",
            "yaml.mapping-entry",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.remove-sequence-element",
            "yaml.sequence-element",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.rename-anchor",
            "yaml.anchor-definition",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "yaml.edit.replace-scalar-literal",
            "yaml.scalar",
            vec![argument("literal", OperationArgumentKind::ExactBytes)],
            OperationSupport::ExistingTypedCapability,
        ),
        descriptor(
            "yaml.edit.replace-scalar-semantic",
            "yaml.scalar",
            vec![
                argument("value", OperationArgumentKind::PortableValue),
                argument(
                    "representation_policy",
                    OperationArgumentKind::RepresentationPolicy,
                ),
            ],
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
    fn both_yaml_profiles_publish_only_the_frozen_implemented_surface() {
        let expected = [
            "yaml.edit.insert-alias@1",
            "yaml.edit.insert-mapping-entry@1",
            "yaml.edit.insert-sequence-element@1",
            "yaml.edit.remove-mapping-entry@1",
            "yaml.edit.remove-sequence-element@1",
            "yaml.edit.rename-anchor@1",
        ];
        for profile in [YamlProfile::Yaml12CoreV1, YamlProfile::Yaml11CompatV1] {
            let registry = format_operation_registry(profile);
            let structural: Vec<_> = registry
                .operations()
                .iter()
                .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
                .map(|descriptor| descriptor.id().to_string())
                .collect();
            assert_eq!(structural, expected);
            assert_eq!(registry.operations().len(), 8);

            let alias = registry
                .descriptor(&FormatOperationId::new("yaml.edit.insert-alias", 1))
                .unwrap();
            assert_eq!(alias.target_role().id(), "yaml.sequence");
            assert_eq!(alias.arguments()[0].name(), "anchor");
            assert_eq!(alias.arguments()[0].kind(), OperationArgumentKind::NodeRef);
        }
    }
}
