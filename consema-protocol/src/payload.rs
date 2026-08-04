//! Full validation dispatch for registered protocol payloads.

use crate::{
    CancellationRequest, CapabilityDeclaration, ChangeSetMessage, Completion, ContractId,
    ContractRegistry, ConversionReportMessage, DiagnosticMessage, EditPlanMessage, ExecutionPolicy,
    FormatOperationRegistryMessage, GraphProjectionResultMessage, GraphProvenanceMapMessage,
    GraphQueryResultMessage, IniQueryResultMessage, JavaPropertiesQueryResultMessage,
    JavaUtf16String, MaterializationProvenanceMapMessage, MaterializationReportMessage,
    MaterializationRequestMessage, MaterializationRequestMessageV2, MaterializationResultMessage,
    MaterializationResultMessageV2, PortableGraphMessage, ProfileDescriptor,
    ProjectionReportMessage, ProjectionRequestMessage, ProjectionResultMessage, ProtocolError,
    ProtocolErrorKind, ProtocolLimits, ProvenanceMapMessage, QueryResultMessage, RegistryManifest,
    SourceEncodingMessage, SourcePatchMessage, SourcePatchMessageV2, SourceSnapshotMessage,
    SourceSnapshotMessageV2, YamlQueryResultMessage, validate_error_code_manifest_value,
};
use consema_core::{PortableValue, QueryDefinition};
use consema_document::{SourceLimits, SourcePatchLimits};
use consema_graph::PgceLimits;

pub(crate) fn validate_registered_payload(
    contract: &ContractId,
    payload: &PortableValue,
    registry: ContractRegistry,
) -> Result<(), ProtocolError> {
    match (contract.id(), contract.version()) {
        ("core.cancellation-request", 1) => CancellationRequest::from_value(payload).map(drop),
        ("core.capability-declaration", 1) => CapabilityDeclaration::from_value(payload).map(drop),
        ("core.change-set", 1) => {
            ChangeSetMessage::from_value_with_registry(payload, registry.error_code_registry())
                .map(drop)
        }
        ("core.completion", 1) => {
            Completion::from_value_with_registry(payload, registry.error_code_registry()).map(drop)
        }
        ("core.conversion-report", 1) => ConversionReportMessage::from_value_with_registry(
            payload,
            registry.error_code_registry(),
        )
        .map(drop),
        ("core.diagnostic", 1) => {
            DiagnosticMessage::from_value_with_registry(payload, registry.error_code_registry())
                .map(drop)
        }
        ("core.edit-plan", 1) => {
            EditPlanMessage::from_value_with_registry(payload, registry.error_code_registry())
                .map(drop)
        }
        ("core.error-code-registry", 1) => validate_error_code_manifest_value(payload),
        ("core.execution-policy", 1) => ExecutionPolicy::from_value(payload).map(drop),
        ("core.format-operation-registry", 1) => {
            FormatOperationRegistryMessage::from_value(payload).map(drop)
        }
        ("core.graph-projection-result", 1) => {
            GraphProjectionResultMessage::from_value_with_registry(
                payload,
                PgceLimits::default(),
                registry.error_code_registry(),
            )
            .map(drop)
        }
        ("core.graph-provenance-map", 1) => {
            GraphProvenanceMapMessage::from_value(payload).map(drop)
        }
        ("core.graph-query-result", 1) => GraphQueryResultMessage::from_value_with_registry(
            payload,
            PgceLimits::default(),
            registry.error_code_registry(),
        )
        .map(drop),
        ("core.ini-query-result", 1) => IniQueryResultMessage::from_value_with_registry_and_limits(
            payload,
            registry.error_code_registry(),
            ProtocolLimits::default(),
        )
        .map(drop),
        ("core.java-properties-query-result", 1) => {
            JavaPropertiesQueryResultMessage::from_value_with_registry_and_limits(
                payload,
                registry.error_code_registry(),
                ProtocolLimits::default(),
            )
            .map(drop)
        }
        ("core.java-utf16-string", 1) => {
            JavaUtf16String::from_value(payload, ProtocolLimits::default()).map(drop)
        }
        ("core.materialization-provenance-map", 1) => {
            MaterializationProvenanceMapMessage::from_value(payload).map(drop)
        }
        ("core.materialization-report", 1) => {
            MaterializationReportMessage::from_value_with_registry(
                payload,
                registry.error_code_registry(),
            )
            .map(drop)
        }
        ("core.materialization-request", 1) => {
            MaterializationRequestMessage::from_value(payload).map(drop)
        }
        ("core.materialization-request", 2) => {
            MaterializationRequestMessageV2::from_value(payload).map(drop)
        }
        ("core.materialization-result", 1) => {
            MaterializationResultMessage::from_value_with_registry(
                payload,
                registry.error_code_registry(),
            )
            .map(drop)
        }
        ("core.materialization-result", 2) => {
            MaterializationResultMessageV2::from_value_with_registry(
                payload,
                registry.error_code_registry(),
            )
            .map(drop)
        }
        ("core.profile-descriptor", 1) => ProfileDescriptor::from_value(payload).map(drop),
        ("core.portable-graph", 1) => {
            PortableGraphMessage::from_value(payload, PgceLimits::default()).map(drop)
        }
        ("core.projection-report", 1) => ProjectionReportMessage::from_value_with_registry(
            payload,
            registry.error_code_registry(),
        )
        .map(drop),
        ("core.projection-request", 1) => ProjectionRequestMessage::from_value(payload).map(drop),
        ("core.projection-result", 1) => ProjectionResultMessage::from_value_with_registry(
            payload,
            registry.error_code_registry(),
        )
        .map(drop),
        ("core.provenance-map", 1) => ProvenanceMapMessage::from_value(payload).map(drop),
        ("core.query-definition", 1) => QueryDefinition::from_protocol_value(payload)
            .map(drop)
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorKind::InvalidValue,
                    "$.payload",
                    format!("invalid query definition: {error:?}"),
                )
            }),
        ("core.query-result", 1) => {
            QueryResultMessage::from_value_with_registry(payload, registry.error_code_registry())
                .map(drop)
        }
        ("core.registry-manifest", 1) => RegistryManifest::from_value(payload).map(drop),
        ("core.source-encoding", 1) => SourceEncodingMessage::from_value(payload).map(drop),
        ("core.source-patch", 1) => {
            SourcePatchMessage::from_value(payload, SourcePatchLimits::default()).map(drop)
        }
        ("core.source-patch", 2) => {
            SourcePatchMessageV2::from_value(payload, SourcePatchLimits::default()).map(drop)
        }
        ("core.source-snapshot", 1) => {
            SourceSnapshotMessage::from_value(payload, SourceLimits::default()).map(drop)
        }
        ("core.source-snapshot", 2) => {
            SourceSnapshotMessageV2::from_value(payload, SourceLimits::default()).map(drop)
        }
        ("core.yaml-query-result", 1) => YamlQueryResultMessage::from_value_with_registry(
            payload,
            registry.error_code_registry(),
        )
        .map(drop),
        _ => Err(ProtocolError::new(
            ProtocolErrorKind::UnknownContract,
            "$.contract",
            contract.schema(),
        )),
    }
}
