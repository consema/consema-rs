//! HCL operation discovery for the frozen `hcl.native@1` and `hcl.tfvars@1`
//! profiles (RFC 0014 §10).

use crate::HclProfile;
use consema_document::{
    FormatOperationDescriptor, FormatOperationId, FormatOperationRegistry,
    OperationArgumentDescriptor, OperationArgumentKind, OperationSupport, OperationTargetRoleId,
};

/// Returns the validated operation registry for one exact HCL profile.
///
/// `hcl.native@1` publishes all six structural operations; `hcl.tfvars@1`
/// publishes the four attribute operations only, because the tfvars
/// restriction admits no block (RFC 0014 §5, §10).
#[must_use]
pub fn format_operation_registry(profile: HclProfile) -> FormatOperationRegistry {
    let descriptors = match profile {
        HclProfile::NativeV1 => native_descriptors(),
        HclProfile::TfvarsV1 => tfvars_descriptors(),
    };
    FormatOperationRegistry::new(profile.id(), descriptors)
        .expect("built-in HCL operation descriptors are valid")
}

/// The full six-operation surface of `hcl.native@1`.
fn native_descriptors() -> Vec<FormatOperationDescriptor> {
    let mut descriptors = tfvars_descriptors();
    descriptors.push(descriptor(
        "hcl.edit.insert-block",
        "hcl.body",
        vec![
            argument("type", OperationArgumentKind::String),
            argument("labels", OperationArgumentKind::String),
            argument("attributes", OperationArgumentKind::PortableValue),
            argument("placement", OperationArgumentKind::Placement),
        ],
        OperationSupport::Supported,
    ));
    descriptors.push(descriptor(
        "hcl.edit.remove-block",
        "hcl.block",
        vec![],
        OperationSupport::Supported,
    ));
    descriptors
}

/// The attribute-only surface of `hcl.tfvars@1`.
fn tfvars_descriptors() -> Vec<FormatOperationDescriptor> {
    vec![
        descriptor(
            "hcl.edit.insert-attribute",
            "hcl.body",
            vec![
                argument("name", OperationArgumentKind::String),
                argument("value", OperationArgumentKind::PortableValue),
                argument("placement", OperationArgumentKind::Placement),
            ],
            OperationSupport::Supported,
        ),
        descriptor(
            "hcl.edit.remove-attribute",
            "hcl.attribute",
            vec![],
            OperationSupport::Supported,
        ),
        descriptor(
            "hcl.edit.rename-attribute",
            "hcl.attribute",
            vec![argument("name", OperationArgumentKind::String)],
            OperationSupport::Supported,
        ),
        descriptor(
            "hcl.edit.set-attribute-value",
            "hcl.attribute",
            vec![argument("value", OperationArgumentKind::PortableValue)],
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
    fn native_profile_publishes_the_frozen_six_operation_surface() {
        let expected = [
            "hcl.edit.insert-attribute@1",
            "hcl.edit.insert-block@1",
            "hcl.edit.remove-attribute@1",
            "hcl.edit.remove-block@1",
            "hcl.edit.rename-attribute@1",
            "hcl.edit.set-attribute-value@1",
        ];
        let registry = format_operation_registry(HclProfile::NativeV1);
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

    #[test]
    fn tfvars_profile_publishes_attribute_operations_only() {
        let expected = [
            "hcl.edit.insert-attribute@1",
            "hcl.edit.remove-attribute@1",
            "hcl.edit.rename-attribute@1",
            "hcl.edit.set-attribute-value@1",
        ];
        let registry = format_operation_registry(HclProfile::TfvarsV1);
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
        assert!(
            !registry
                .operations()
                .iter()
                .any(|descriptor| descriptor.id().to_string().contains("block"))
        );
    }
}
