//! Consema cross-format protocol contracts and canonical transports.
//!
//! Protocol objects are fixed-field [`consema_core::PortableValue`] trees. The
//! same tree can be encoded as canonical PVCE/1 or as the fully tagged
//! `core.portable-value-json@1` representation without host-language object
//! serialization.

mod contract;
mod diagnostic;
mod error;
mod execution;
mod limits;
mod registry;
mod schema;
mod value_transport;

pub use contract::{
    ContractDescriptor, ContractId, ContractRegistry, ContractStability, ProtocolMessage,
};
pub use diagnostic::{
    DiagnosticMessage, FixApplicability, FixProposal, RelatedSourceLocation, SourceLocation,
};
pub use error::{ProtocolError, ProtocolErrorKind};
pub use execution::{CancellationRequest, Completion, CompletionStatus, ExecutionPolicy};
pub use limits::ProtocolLimits;
pub use registry::{CapabilityDeclaration, ProfileDescriptor, ProfileReference};
pub use value_transport::{decode_json, decode_pvce, encode_json, encode_pvce};

/// Canonical tagged JSON transport schema.
pub const PORTABLE_VALUE_JSON_SCHEMA: &str = "core.portable-value-json@1";
