//! Stable operation result taxonomy.

use crate::Diagnostic;

/// High-level operation category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationKind {
    /// Parsing bytes into a document.
    Parse,
    /// Validating a query definition.
    QueryValidation,
    /// Binding or executing a query.
    QueryExecution,
    /// Projecting native semantics.
    Projection,
    /// Materializing a portable representation into a new document.
    Materialization,
    /// Composing projection and materialization across profiles.
    Conversion,
    /// Encoding a portable value.
    Encode,
    /// Decoding a portable value.
    Decode,
    /// Editing a document.
    Edit,
}

/// Stable failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FailureKind {
    /// Input violates a contract.
    InvalidInput,
    /// A domain or capability is unsupported.
    Unsupported,
    /// A target does not belong to the expected snapshot or role.
    TargetMismatch,
    /// A declared resource limit was reached.
    ResourceLimited,
    /// The caller cancelled execution.
    Cancelled,
    /// The requested operation is not applicable.
    NotApplicable,
    /// An internal invariant failed.
    Internal,
}

/// Language-neutral control-flow status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationStatus {
    /// The complete result is available.
    Success,
    /// The operation failed.
    Failed,
    /// The operation was cancelled.
    Cancelled,
    /// A resource limit stopped the operation.
    ResourceLimited,
    /// The implementation does not support the request.
    Unsupported,
    /// The request does not apply to the target.
    NotApplicable,
}

/// Stable public operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationFailure {
    /// Operation that failed.
    pub operation: OperationKind,
    /// Stable failure kind.
    pub kind: FailureKind,
    /// Ordered structured diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Stable operation/failure/diagnostic facts exposed by every public failure.
///
/// Detailed error enums remain the primary API; this projection guarantees
/// language-neutral control-flow facts without depending on display text.
pub trait StableFailure {
    /// Operation that failed.
    fn operation_kind(&self) -> OperationKind;
    /// Stable failure category.
    fn failure_kind(&self) -> FailureKind;
    /// Stable namespaced diagnostic code.
    fn diagnostic_code(&self) -> &str;
}
