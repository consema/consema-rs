//! Plist operation discovery for the frozen `plist.xml@1` and `plist.binary@1`
//! profiles (RFC 0013 §11).

use crate::PlistProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact plist profile.
///
/// Both profiles publish the same six snapshot-bound structural operations,
/// independently typed per profile (RFC 0013 §11).
#[must_use]
pub fn format_operation_registry(profile: PlistProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in plist operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "plist.edit.set-value",
            "plist.value",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("value", OperationArgumentKind::PortableValue),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "plist.edit.insert-dict-entry",
            "plist.value",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("key", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "plist.edit.remove-dict-entry",
            "plist.dict-entry",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("key", OperationArgumentKind::String),
                argument("occurrence", OperationArgumentKind::NodeRef),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "plist.edit.rename-dict-key",
            "plist.dict-entry",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("from", OperationArgumentKind::String),
                argument("occurrence", OperationArgumentKind::NodeRef),
                argument("to", OperationArgumentKind::String),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "plist.edit.insert-array-element",
            "plist.value",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("index", OperationArgumentKind::NodeRef),
                argument("value", OperationArgumentKind::PortableValue),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "plist.edit.remove-array-element",
            "plist.array-element",
            vec![
                argument("path", OperationArgumentKind::NodeRef),
                argument("index", OperationArgumentKind::NodeRef),
            ],
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
    fn every_plist_profile_publishes_the_frozen_six_operation_surface() {
        let expected = [
            "plist.edit.insert-array-element@1",
            "plist.edit.insert-dict-entry@1",
            "plist.edit.remove-array-element@1",
            "plist.edit.remove-dict-entry@1",
            "plist.edit.rename-dict-key@1",
            "plist.edit.set-value@1",
        ];
        for profile in [PlistProfile::XmlV1, PlistProfile::BinaryV1] {
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
                    .all(|descriptor| descriptor.support() == OperationSupport::Supported)
            );
        }
    }
}
