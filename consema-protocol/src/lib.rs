//! Consema cross-format protocol contracts and canonical transports.
//!
//! Protocol objects are fixed-field [`consema_core::PortableValue`] trees. The
//! same tree can be encoded as canonical PVCE/1 or as the fully tagged
//! `core.portable-value-json@1` representation without host-language object
//! serialization.

mod change;
mod contract;
mod conversion;
mod diagnostic;
mod error;
mod error_registry;
mod execution;
mod graph_projection;
mod graph_query;
mod limits;
mod materialization;
mod operation;
mod payload;
mod portable_graph;
mod projection;
mod query;
mod registry;
mod registry_manifest;
mod schema;
mod source;
mod value_transport;
mod yaml_query;

pub use contract::{
    ContractDescriptor, ContractId, ContractRegistry, ContractStability, ProtocolMessage,
};
pub use conversion::{ConversionFidelityMessage, ConversionReportMessage};
pub use diagnostic::{
    DiagnosticMessage, FixApplicability, FixProposal, RelatedSourceLocation, SourceLocation,
};
pub use error::{ProtocolError, ProtocolErrorKind};
pub use error_registry::{
    ErrorCodeDescriptor, ErrorCodeRegistry, error_code_manifest_value,
    error_code_manifest_value_v2, error_code_manifest_value_v3, error_code_manifest_value_v4,
    error_code_manifest_value_v5, query_failure_code, validate_error_code_manifest_value,
};
pub use execution::{CancellationRequest, Completion, CompletionStatus, ExecutionPolicy};
pub use graph_projection::{
    GraphProjectedLocationMessage, GraphProjectionResultMessage, GraphProvenanceEntryMessage,
    GraphProvenanceMapMessage, GraphProvenanceRelationMessage, GraphSourceOriginMessage,
};
pub use graph_query::{GraphQueryMatchMessage, GraphQueryResultMessage};
pub use limits::ProtocolLimits;
pub use materialization::{
    MaterializationFailureMessage, MaterializationInputLocationMessage,
    MaterializationOutcomeMessage, MaterializationProvenanceEntryMessage,
    MaterializationProvenanceMapMessage, MaterializationRelationMessage,
    MaterializationReportMessage, MaterializationRequestMessage, MaterializationRequestMessageV2,
    MaterializationResultMessage, MaterializedOriginMessage,
};
pub use operation::{EditOperationSummaryMessage, EditPlanMessage, FormatOperationRegistryMessage};
pub use portable_graph::PortableGraphMessage;
pub use projection::{
    LossClassification, ProjectedLocationMessage, ProjectionEventMessage, ProjectionFidelity,
    ProjectionPolicy, ProjectionReportMessage, ProjectionRequestMessage, ProjectionResultMessage,
    ProjectionRule, ProjectionScope, ProvenanceEntryMessage, ProvenanceMapMessage,
    ProvenanceRelation, SourceOriginMessage,
};
pub use query::{
    NativeMatchLocator, ProtocolQueryMatch, QueryResultMessage, query_definition_from_message,
    query_definition_message,
};
pub use registry::{CapabilityDeclaration, ProfileDescriptor, ProfileReference};
pub use registry_manifest::{ContractManifestEntry, ErrorCodeManifestEntry, RegistryManifest};
pub use source::{
    SourceEncodingMessage, SourcePatchMessage, SourcePatchMessageV2, SourceSnapshotMessage,
    SourceSnapshotMessageV2,
};
pub use value_transport::{decode_json, decode_pvce, encode_json, encode_pvce};
pub use yaml_query::{YamlMatchLocator, YamlQueryResultMessage};

/// Canonical tagged JSON transport schema.
pub const PORTABLE_VALUE_JSON_SCHEMA: &str = "core.portable-value-json@1";
pub use change::{ChangeSetMessage, NodeMappingMessage, SourceEditMessage};
