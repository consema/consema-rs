//! Immutable source snapshots, structural locations, and change facts.

use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

/// Opaque identity of exactly one immutable document snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnapshotIdentity(u64);

impl SnapshotIdentity {
    /// Stable process-local representation for protocol diagnostics.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Authority owned by one document implementation for issuing snapshot-bound handles.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct DocumentAuthority(SnapshotIdentity);

impl DocumentAuthority {
    /// Allocates a fresh snapshot identity.
    #[must_use]
    pub fn fresh() -> Self {
        let identity = NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
        assert_ne!(identity, 0, "snapshot identity space exhausted");
        Self(SnapshotIdentity(identity))
    }

    /// Snapshot identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotIdentity {
        self.0
    }

    /// Issues one opaque node handle.
    #[must_use]
    pub const fn node_ref(&self, index: u64, role: NodeRole) -> NodeRef {
        NodeRef {
            snapshot: self.0,
            index,
            role,
        }
    }

    /// Creates a snapshot-bound span after range validation.
    pub fn span(&self, start_byte: usize, end_byte: usize) -> Result<Span, LocationError> {
        if start_byte > end_byte {
            return Err(LocationError::InvertedSpan);
        }
        Ok(Span {
            snapshot: self.0,
            start_byte,
            end_byte,
        })
    }

    /// Verifies that a node handle belongs to this snapshot.
    pub fn verify(&self, node: NodeRef) -> Result<(), LocationError> {
        if node.snapshot == self.0 {
            Ok(())
        } else {
            Err(LocationError::WrongSnapshot)
        }
    }

    /// Resolves an index only for the authority that issued the handle.
    #[doc(hidden)]
    pub fn resolve_index(&self, node: NodeRef) -> Result<u64, LocationError> {
        self.verify(node)?;
        Ok(node.index)
    }
}

/// Semantic role of a document structural identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NodeRole {
    /// Format syntax node.
    SyntaxNode,
    /// Lexical token.
    Token,
    /// JSON object member association.
    ObjectMember,
    /// JSON object key.
    ObjectKey,
    /// JSON array element association.
    ArrayElement,
    /// Complete semantic value syntax.
    Value,
}

/// Opaque handle to one structural identity in exactly one snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeRef {
    snapshot: SnapshotIdentity,
    index: u64,
    role: NodeRole,
}

impl NodeRef {
    /// Owning snapshot.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Structural role.
    #[must_use]
    pub const fn role(self) -> NodeRole {
        self.role
    }
}

/// Half-open byte range bound to one snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    snapshot: SnapshotIdentity,
    start_byte: usize,
    end_byte: usize,
}

impl Span {
    /// Owning snapshot.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Inclusive start byte.
    #[must_use]
    pub const fn start_byte(self) -> usize {
        self.start_byte
    }

    /// Exclusive end byte.
    #[must_use]
    pub const fn end_byte(self) -> usize {
        self.end_byte
    }

    /// Byte length.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end_byte - self.start_byte
    }

    /// Whether the range is an insertion point.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start_byte == self.end_byte
    }

    /// Common diagnostic representation.
    #[must_use]
    pub fn diagnostic_location(self) -> DiagnosticLocation {
        DiagnosticLocation {
            snapshot: Some(self.snapshot.0),
            start_byte: self.start_byte as u64,
            end_byte: self.end_byte as u64,
        }
    }
}

/// Full immutable UTF-8 source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshot {
    bytes: Arc<[u8]>,
}

impl SourceSnapshot {
    /// Validates UTF-8 and stores all original bytes without normalization.
    pub fn from_utf8(bytes: impl Into<Arc<[u8]>>) -> Result<Self, SourceError> {
        let bytes = bytes.into();
        std::str::from_utf8(&bytes).map_err(|error| SourceError::InvalidUtf8 {
            valid_up_to: error.valid_up_to(),
        })?;
        Ok(Self { bytes })
    }

    /// Exact source bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validated source text.
    #[must_use]
    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("SourceSnapshot validates UTF-8")
    }

    /// Source byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the source is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Stable source construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// JSON v1 only accepts UTF-8.
    InvalidUtf8 {
        /// Prefix length that was valid UTF-8.
        valid_up_to: usize,
    },
}

impl Display for SourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourceError {}

/// Stable namespaced format family contract.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FormatFamilyId {
    id: Arc<str>,
    version: u32,
}

impl FormatFamilyId {
    /// Creates a format family ID.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Namespace.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Immutable named language profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProfileId {
    id: Arc<str>,
    version: u32,
}

impl ProfileId {
    /// Creates a profile ID.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Namespace.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Successful document formation state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FormationStatus {
    /// Entire syntax was formed without recovery.
    Complete,
    /// A complete snapshot with explicit recovery structure was formed.
    Recovered,
}

/// One exhaustive source-byte classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StructuralPieceKind {
    /// Lexical token.
    Token,
    /// Whitespace, newline, comment, or profile trivia.
    Trivia,
    /// Bytes not accepted as token or trivia.
    ErrorRegion,
}

/// One source byte interval and its lossless class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StructuralPiece {
    span: Span,
    kind: StructuralPieceKind,
}

impl StructuralPiece {
    /// Creates one piece.
    #[must_use]
    pub const fn new(span: Span, kind: StructuralPieceKind) -> Self {
        Self { span, kind }
    }

    /// Exact source range.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }

    /// Classification.
    #[must_use]
    pub const fn kind(self) -> StructuralPieceKind {
        self.kind
    }
}

/// Exhaustive ordered token/trivia/error-region coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LosslessStructuralIndex {
    pieces: Arc<[StructuralPiece]>,
}

impl LosslessStructuralIndex {
    /// Validates exact source coverage and stores pieces in structural order.
    pub fn new(
        identity: SnapshotIdentity,
        source_len: usize,
        pieces: Vec<StructuralPiece>,
    ) -> Result<Self, LocationError> {
        let mut next = 0;
        for piece in &pieces {
            if piece.span.snapshot != identity {
                return Err(LocationError::WrongSnapshot);
            }
            if piece.span.start_byte != next
                || piece.span.end_byte <= piece.span.start_byte
                || piece.span.end_byte > source_len
            {
                return Err(LocationError::IncompleteStructuralCoverage);
            }
            next = piece.span.end_byte;
        }
        if next != source_len {
            return Err(LocationError::IncompleteStructuralCoverage);
        }
        Ok(Self {
            pieces: Arc::from(pieces),
        })
    }

    /// Ordered exhaustive pieces.
    #[must_use]
    pub fn pieces(&self) -> &[StructuralPiece] {
        &self.pieces
    }
}

/// Span, identity, or coverage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocationError {
    /// Span start followed its end.
    InvertedSpan,
    /// Handle or span belongs to another snapshot.
    WrongSnapshot,
    /// Pieces had a gap, overlap, empty interval, or wrong final length.
    IncompleteStructuralCoverage,
}

impl Display for LocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LocationError {}

/// Parse resource limits; exceeding one is a fatal formation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum source bytes.
    pub max_source_bytes: usize,
    /// Maximum syntax nesting.
    pub max_nesting_depth: usize,
    /// Maximum tokens plus trivia/error regions.
    pub max_token_count: usize,
    /// Maximum format syntax nodes.
    pub max_node_count: usize,
    /// Maximum diagnostics before an explicit truncation marker.
    pub max_diagnostics: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024 * 1024,
            max_nesting_depth: 256,
            max_token_count: 2_000_000,
            max_node_count: 1_000_000,
            max_diagnostics: 10_000,
        }
    }
}

/// Failure before a complete immutable Document can be formed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatalFormationFailure {
    diagnostics: Vec<Diagnostic>,
}

impl FatalFormationFailure {
    /// UTF-8 failure.
    #[must_use]
    pub fn invalid_utf8(valid_up_to: usize) -> Self {
        Self {
            diagnostics: vec![Diagnostic::new(
                "core.source.invalid-utf8@1",
                DiagnosticCategory::Lexical,
                DiagnosticSeverity::Error,
                Some(DiagnosticLocation {
                    snapshot: None,
                    start_byte: valid_up_to as u64,
                    end_byte: valid_up_to as u64,
                }),
                0,
            )],
        }
    }

    /// Resource-limit failure.
    #[must_use]
    pub fn resource_limit(name: &str, observed: usize, limit: usize) -> Self {
        let mut diagnostic = Diagnostic::new(
            "core.parse.resource-limit@1",
            DiagnosticCategory::Resource,
            DiagnosticSeverity::Error,
            None,
            0,
        );
        diagnostic
            .arguments
            .insert("limit".to_owned(), limit.to_string());
        diagnostic
            .arguments
            .insert("name".to_owned(), name.to_owned());
        diagnostic
            .arguments
            .insert("observed".to_owned(), observed.to_string());
        Self {
            diagnostics: vec![diagnostic],
        }
    }

    /// Ordered diagnostics explaining why no Document exists.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// One ordered non-overlapping source replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEdit {
    /// Replaced old range.
    pub old_span: Span,
    /// Range occupied by replacement bytes in the new snapshot.
    pub new_span: Span,
    /// Exact replacement bytes.
    pub replacement: Arc<[u8]>,
}

/// Explicit node mapping status across immutable snapshots.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NodeMappingStatus {
    /// Exact structural entity survived.
    Preserved,
    /// Entity was replaced.
    Replaced,
    /// Entity was deleted.
    Deleted,
    /// One entity became several.
    Split,
    /// Several entities became one.
    Merged,
    /// No reliable mapping is known.
    Unmapped,
}

/// One explicit old-to-new node mapping fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeMapping {
    /// Old handle.
    pub old: NodeRef,
    /// New handle when a one-to-one mapping is known.
    pub new: Option<NodeRef>,
    /// Mapping status.
    pub status: NodeMappingStatus,
    /// Stable reason for missing or non-trivial mapping.
    pub reason: Option<String>,
}

/// Complete immutable description of one atomic document transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeSet {
    old_snapshot: SnapshotIdentity,
    new_snapshot: SnapshotIdentity,
    source_edits: Arc<[SourceEdit]>,
    node_mappings: Arc<[NodeMapping]>,
    diagnostics: Arc<[Diagnostic]>,
}

impl ChangeSet {
    /// Creates a complete change set from already ordered validated facts.
    #[doc(hidden)]
    #[must_use]
    pub fn new(
        old_snapshot: SnapshotIdentity,
        new_snapshot: SnapshotIdentity,
        source_edits: Vec<SourceEdit>,
        node_mappings: Vec<NodeMapping>,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            old_snapshot,
            new_snapshot,
            source_edits: Arc::from(source_edits),
            node_mappings: Arc::from(node_mappings),
            diagnostics: Arc::from(diagnostics),
        }
    }

    /// Base snapshot.
    #[must_use]
    pub const fn old_snapshot(&self) -> SnapshotIdentity {
        self.old_snapshot
    }

    /// Committed snapshot.
    #[must_use]
    pub const fn new_snapshot(&self) -> SnapshotIdentity {
        self.new_snapshot
    }

    /// Ordered non-overlapping source edits.
    #[must_use]
    pub fn source_edits(&self) -> &[SourceEdit] {
        &self.source_edits
    }

    /// Explicit node mappings.
    #[must_use]
    pub fn node_mappings(&self) -> &[NodeMapping] {
        &self.node_mappings
    }

    /// Operation diagnostics, never written into either Document.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_coverage_rejects_gaps() {
        let authority = DocumentAuthority::fresh();
        let first = StructuralPiece::new(authority.span(0, 1).unwrap(), StructuralPieceKind::Token);
        let last = StructuralPiece::new(authority.span(2, 3).unwrap(), StructuralPieceKind::Token);
        assert_eq!(
            LosslessStructuralIndex::new(authority.identity(), 3, vec![first, last]),
            Err(LocationError::IncompleteStructuralCoverage)
        );
    }

    #[test]
    fn node_refs_are_snapshot_bound() {
        let first = DocumentAuthority::fresh();
        let second = DocumentAuthority::fresh();
        let node = first.node_ref(0, NodeRole::Value);
        assert_eq!(second.verify(node), Err(LocationError::WrongSnapshot));
    }
}
