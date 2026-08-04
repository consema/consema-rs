//! Consema cross-format protocol contracts and canonical transports.
//!
//! Protocol objects are fixed-field [`consema_core::PortableValue`] trees. The
//! same tree can be encoded as canonical PVCE/1 or as the fully tagged
//! `core.portable-value-json@1` representation without host-language object
//! serialization.

mod change;
mod contract;
mod diagnostic;
mod error;
mod error_registry;
mod execution;
mod limits;
mod payload;
mod projection;
mod query;
mod registry;
mod registry_manifest;
mod schema;
mod value_transport;

pub use contract::{
    ContractDescriptor, ContractId, ContractRegistry, ContractStability, ProtocolMessage,
};
pub use diagnostic::{
    DiagnosticMessage, FixApplicability, FixProposal, RelatedSourceLocation, SourceLocation,
};
pub use error::{ProtocolError, ProtocolErrorKind};
pub use error_registry::{
    ErrorCodeDescriptor, ErrorCodeRegistry, error_code_manifest_value, query_failure_code,
    validate_error_code_manifest_value,
};
pub use execution::{CancellationRequest, Completion, CompletionStatus, ExecutionPolicy};
pub use limits::ProtocolLimits;
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
pub use value_transport::{decode_json, decode_pvce, encode_json, encode_pvce};

/// Canonical tagged JSON transport schema.
pub const PORTABLE_VALUE_JSON_SCHEMA: &str = "core.portable-value-json@1";
pub use change::{ChangeSetMessage, NodeMappingMessage, SourceEditMessage};
