//! XML operation discovery for the frozen `xml.1.0-safe@1` profile.

use crate::XmlProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact XML profile.
#[must_use]
pub fn format_operation_registry(profile: XmlProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in XML operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "xml.edit.replace-text",
            "xml.text",
            vec![argument("text", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.insert-attribute",
            "xml.element",
            vec![
                argument("name", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::String),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.remove-attribute",
            "xml.attribute",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.rename-attribute",
            "xml.attribute",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.set-attribute-value",
            "xml.attribute",
            vec![argument("value", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.insert-element",
            "xml.element",
            vec![
                argument("name", OperationArgumentKind::String),
                argument("content", OperationArgumentKind::String),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.remove-element",
            "xml.element",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "xml.edit.rename-element",
            "xml.element",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
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
    fn every_xml_profile_publishes_the_frozen_eight_operation_surface() {
        let expected = [
            "xml.edit.insert-attribute@1",
            "xml.edit.insert-element@1",
            "xml.edit.remove-attribute@1",
            "xml.edit.remove-element@1",
            "xml.edit.rename-attribute@1",
            "xml.edit.rename-element@1",
            "xml.edit.replace-text@1",
            "xml.edit.set-attribute-value@1",
        ];
        let registry = format_operation_registry(XmlProfile::SafeV1);
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
                .all(|descriptor| descriptor.support() == OperationSupport::Supported)
        );
    }
}
