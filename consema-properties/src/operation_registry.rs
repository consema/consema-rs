//! Java Properties operation discovery for both exact source profiles.

use crate::PropertiesProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact Java Properties profile.
#[must_use]
pub fn format_operation_registry(profile: PropertiesProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in Java Properties operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "java-properties.edit.insert-property",
            "java-properties.document",
            vec![
                argument("key", OperationArgumentKind::PortableValue),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
        ),
        descriptor(
            "java-properties.edit.remove-property",
            "java-properties.property",
            vec![],
        ),
        descriptor(
            "java-properties.edit.rename-property",
            "java-properties.property",
            vec![argument("key", OperationArgumentKind::PortableValue)],
        ),
        descriptor(
            "java-properties.edit.replace-literal-value",
            "java-properties.property",
            vec![argument("literal", OperationArgumentKind::ExactBytes)],
        ),
        descriptor(
            "java-properties.edit.replace-semantic-value",
            "java-properties.property",
            vec![argument("value", OperationArgumentKind::PortableValue)],
        ),
    ]
}

fn descriptor(
    id: &'static str,
    target_role: &'static str,
    arguments: Vec<OperationArgumentDescriptor>,
) -> FormatOperationDescriptor {
    FormatOperationDescriptor::new(
        FormatOperationId::new(id, 1),
        OperationTargetRoleId::new(target_role, 1),
        arguments,
        OperationSupport::Supported,
    )
}

fn argument(name: &'static str, kind: OperationArgumentKind) -> OperationArgumentDescriptor {
    OperationArgumentDescriptor::new(name, kind, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_profiles_publish_the_same_frozen_five_operation_surface() {
        let expected = [
            "java-properties.edit.insert-property@1",
            "java-properties.edit.remove-property@1",
            "java-properties.edit.rename-property@1",
            "java-properties.edit.replace-literal-value@1",
            "java-properties.edit.replace-semantic-value@1",
        ];
        for profile in [PropertiesProfile::ReaderV1, PropertiesProfile::Latin1V1] {
            let registry = format_operation_registry(profile);
            let operations: Vec<_> = registry
                .operations()
                .iter()
                .map(|descriptor| descriptor.id().to_string())
                .collect();
            assert_eq!(operations, expected);
            assert!(
                registry
                    .operations()
                    .iter()
                    .all(|descriptor| { descriptor.support() == OperationSupport::Supported })
            );
        }
    }
}
