//! Full validation dispatch for registered protocol payloads.

use crate::{
    CancellationRequest, CapabilityDeclaration, ChangeSetMessage, Completion, ContractId,
    DiagnosticMessage, ExecutionPolicy, ProfileDescriptor, ProjectionReportMessage,
    ProjectionRequestMessage, ProjectionResultMessage, ProtocolError, ProtocolErrorKind,
    ProvenanceMapMessage, QueryResultMessage, RegistryManifest, SourcePatchMessage,
    SourceSnapshotMessage, validate_error_code_manifest_value,
};
use consema_core::{PortableValue, QueryDefinition};
use consema_document::{SourceLimits, SourcePatchLimits};

pub(crate) fn validate_registered_payload(
    contract: &ContractId,
    payload: &PortableValue,
) -> Result<(), ProtocolError> {
    match contract.id() {
        "core.cancellation-request" => CancellationRequest::from_value(payload).map(drop),
        "core.capability-declaration" => CapabilityDeclaration::from_value(payload).map(drop),
        "core.change-set" => ChangeSetMessage::from_value(payload).map(drop),
        "core.completion" => Completion::from_value(payload).map(drop),
        "core.diagnostic" => DiagnosticMessage::from_value(payload).map(drop),
        "core.error-code-registry" => validate_error_code_manifest_value(payload),
        "core.execution-policy" => ExecutionPolicy::from_value(payload).map(drop),
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
