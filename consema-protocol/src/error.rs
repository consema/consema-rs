//! Stable protocol rejection taxonomy.

use std::fmt::{self, Display, Formatter};

/// Stable protocol failure class and public diagnostic code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolErrorKind {
    /// Input is not accepted JSON for the canonical transport.
    InvalidJson,
    /// JSON represents a value but is not the one canonical byte form.
    NonCanonicalJson,
    /// Input is not canonical PVCE/1.
    InvalidPvce,
    /// The envelope selected an unknown contract ID or version.
    UnknownContract,
    /// Fixed fields, order, or schema discriminator do not match.
    SchemaMismatch,
    /// A fixed schema contains an undeclared field.
    UnknownField,
    /// A required field is absent.
    MissingField,
    /// A field has the wrong PortableValue or JSON kind.
    WrongType,
    /// A typed field violates its value invariant.
    InvalidValue,
    /// A declared protocol resource limit was reached.
    ResourceLimit,
    /// A process-local handle was presented for wire encoding.
    ProcessLocalHandle,
}

impl ProtocolErrorKind {
    /// Stable namespaced public error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidJson => "core.protocol.invalid-json@1",
            Self::NonCanonicalJson => "core.protocol.non-canonical-json@1",
            Self::InvalidPvce => "core.protocol.invalid-pvce@1",
            Self::UnknownContract => "core.protocol.unknown-contract@1",
            Self::SchemaMismatch => "core.protocol.schema-mismatch@1",
            Self::UnknownField => "core.protocol.unknown-field@1",
            Self::MissingField => "core.protocol.missing-field@1",
            Self::WrongType => "core.protocol.wrong-type@1",
            Self::InvalidValue => "core.protocol.invalid-value@1",
            Self::ResourceLimit => "core.protocol.resource-limit@1",
            Self::ProcessLocalHandle => "core.protocol.process-local-handle@1",
        }
    }
}

/// Structured failure from protocol validation or transport decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    kind: ProtocolErrorKind,
    path: String,
    detail: String,
}

impl ProtocolError {
    /// Creates a structured protocol error.
    #[must_use]
    pub fn new(
        kind: ProtocolErrorKind,
        path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            detail: detail.into(),
        }
    }

    /// Stable error class.
    #[must_use]
    pub const fn kind(&self) -> ProtocolErrorKind {
        self.kind
    }

    /// Stable namespaced public code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Root-relative schema path or transport phase.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Non-normative debugging detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.kind.code(),
            self.path,
            self.detail
        )
    }
}

impl std::error::Error for ProtocolError {}
