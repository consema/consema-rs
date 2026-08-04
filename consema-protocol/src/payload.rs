//! Full validation dispatch for registered protocol payloads.

use crate::{
    CancellationRequest, CapabilityDeclaration, ChangeSetMessage, Completion, ContractId,
    ContractRegistry, ConversionReportMessage, DiagnosticMessage, EditPlanMessage, ExecutionPolicy,
    FormatOperationRegistryMessage, MaterializationProvenanceMapMessage,
    MaterializationReportMessage, MaterializationRequestMessage, MaterializationResultMessage,
    ProfileDescriptor, ProjectionReportMessage, ProjectionRequestMessage, ProjectionResultMessage,
    ProtocolError, ProtocolErrorKind, ProvenanceMapMessage, QueryResultMessage, RegistryManifest,
    SourcePatchMessage, SourceSnapshotMessage, validate_error_code_manifest_value,
};
use consema_core::{PortableValue, QueryDefinition};
use consema_document::{SourceLimits, SourcePatchLimits};

pub(crate) fn validate_registered_payload(
    contract: &ContractId,
    payload: &PortableValue,
    registry: ContractRegistry,
) -> Result<(), ProtocolError> {
    match contract.id() {
        "core.cancellation-request" => CancellationRequest::from_value(payload).map(drop),
        "core.capability-declaration" => CapabilityDeclaration::from_value(payload).map(drop),
        "core.change-set" => ChangeSetMessage::from_value(payload).map(drop),
        "core.completion" => Completion::from_value(payload).map(drop),
        "core.conversion-report" => ConversionReportMessage::from_value(payload).map(drop),
        "core.diagnostic" => {
            DiagnosticMessage::from_value_with_registry(payload, registry.error_code_registry())
                .map(drop)
        }
        "core.edit-plan" => EditPlanMessage::from_value(payload).map(drop),
        "core.error-code-registry" => validate_error_code_manifest_value(payload),
        "core.execution-policy" => ExecutionPolicy::from_value(payload).map(drop),
        "core.format-operation-registry" => {
            FormatOperationRegistryMessage::from_value(payload).map(drop)
        }
        "core.materialization-provenance-map" => {
            MaterializationProvenanceMapMessage::from_value(payload).map(drop)
        }
        "core.materialization-report" => {
            MaterializationReportMessage::from_value(payload).map(drop)
        }
        "core.materialization-request" => {
            MaterializationRequestMessage::from_value(payload).map(drop)
        }
        "core.materialization-result" => {
            MaterializationResultMessage::from_value(payload).map(drop)
        }
        "core.profile-descriptor" => ProfileDescriptor::from_value(payload).map(drop),
        "core.projection-report" => ProjectionReportMessage::from_value(payload).map(drop),
        "core.projection-request" => ProjectionRequestMessage::from_value(payload).map(drop),
        "core.projection-result" => ProjectionResultMessage::from_value(payload).map(drop),
        "core.provenance-map" => ProvenanceMapMessage::from_value(payload).map(drop),
        "core.query-definition" => QueryDefinition::from_protocol_value(payload)
            .map(drop)
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorKind::InvalidValue,
                    "$.payload",
                    format!("invalid query definition: {error:?}"),
                )
            }),
        "core.query-result" => QueryResultMessage::from_value(payload).map(drop),
        "core.registry-manifest" => RegistryManifest::from_value(payload).map(drop),
        "core.source-patch" => {
            SourcePatchMessage::from_value(payload, SourcePatchLimits::default()).map(drop)
        }
        "core.source-snapshot" => {
            SourceSnapshotMessage::from_value(payload, SourceLimits::default()).map(drop)
        }
        _ => Err(ProtocolError::new(
            ProtocolErrorKind::UnknownContract,
            "$.contract",
            contract.schema(),
        )),
    }
}
