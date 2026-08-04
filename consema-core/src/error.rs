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
