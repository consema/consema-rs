//! Consema cross-format protocol contracts and canonical transports.
//!
//! Protocol objects are fixed-field [`consema_core::PortableValue`] trees. The
//! same tree can be encoded as canonical PVCE/1 or as the fully tagged
//! `core.portable-value-json@1` representation without host-language object
//! serialization.

mod error;
mod limits;
mod value_transport;

pub use error::{ProtocolError, ProtocolErrorKind};
pub use limits::ProtocolLimits;
pub use value_transport::{decode_json, decode_pvce, encode_json, encode_pvce};

/// Canonical tagged JSON transport schema.
pub const PORTABLE_VALUE_JSON_SCHEMA: &str = "core.portable-value-json@1";
