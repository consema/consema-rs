//! INI operation discovery for every explicit family profile.

use crate::IniProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact INI profile.
#[must_use]
pub fn format_operation_registry(profile: IniProfile) -> FormatOperationRegistry {
    FormatOperationRegistry::new(profile.id(), descriptors())
        .expect("built-in INI operation descriptors are valid")
}

fn descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "ini.edit.insert-section",
            "ini.document",
            vec![
                argument("name", OperationArgumentKind::String),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.remove-section",
            "ini.section",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.rename-section",
            "ini.section",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.insert-entry",
            "ini.section",
            vec![
                argument("key", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::String),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.remove-entry",
            "ini.entry",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.rename-entry",
            "ini.entry",
            vec![argument("key", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "ini.edit.replace-semantic-value",
            "ini.entry",
            vec![
                argument("value", OperationArgumentKind::String),
                argument(
                    "representation_policy",
                    OperationArgumentKind::RepresentationPolicy,
                ),
            ],
            OperationSupport::ExistingTypedCapability,
        ),
        descriptor(
            "ini.edit.replace-literal-value",
            "ini.entry",
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
    fn every_ini_profile_publishes_the_same_frozen_eight_operation_surface() {
        let expected = [
            "ini.edit.insert-entry@1",
            "ini.edit.insert-section@1",
            "ini.edit.remove-entry@1",
            "ini.edit.remove-section@1",
            "ini.edit.rename-entry@1",
            "ini.edit.rename-section@1",
            "ini.edit.replace-literal-value@1",
            "ini.edit.replace-semantic-value@1",
        ];
        for profile in [
            IniProfile::PortableV1,
            IniProfile::WindowsV1,
            IniProfile::PythonConfigParserV1,
        ] {
            let registry = format_operation_registry(profile);
            let operations: Vec<_> = registry
                .operations()
                .iter()
                .map(|descriptor| descriptor.id().to_string())
                .collect();
            assert_eq!(operations, expected);
            assert_eq!(
                registry
                    .operations()
                    .iter()
                    .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
                    .count(),
                6
            );
        }
    }
}
