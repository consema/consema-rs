//! Language-neutral value and protocol primitives.

mod capability;
mod diagnostic;
mod error;
mod location;
mod query;
mod value;

pub use capability::{CapabilityId, CapabilitySet, ImplementationSupport, VerificationStatus};
pub use diagnostic::{
    Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity, RelatedLocation,
};
pub use error::{FailureKind, OperationFailure, OperationKind, OperationStatus, StableFailure};
pub use location::{AssociationLocation, AssociationRole, ValuePath, ValuePathSegment};
pub use query::{
    CancellationToken, ExecutableQuery, MatchRole, OperatorCall, OrderedQueryCursor, PortableMatch,
    PortableQueryCursor, QueryDefinition, QueryDefinitionBuilder, QueryDomain, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection, QueryTerminalState, ValidatedQuery,
};
pub use value::{
    BigInteger, BinaryFloat32, BinaryFloat64, Date, Decimal, EntryMappingBuilder,
    EntryMappingEntry, ExtendedValue, ExtensionContract, ExtensionValidationError, LocalDateTime,
    ObjectBuilder, ObjectEntry, OffsetDateTime, PortableValue, PortableValueKind, SequenceBuilder,
    Time, ValueBuildError,
};
