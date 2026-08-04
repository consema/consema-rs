//! Lossless Java Properties documents under exact Reader and Latin-1 profiles.

use consema_core::Diagnostic;
use consema_document::{
    FatalFormationFailure, FormationStatus, LosslessStructuralIndex, NodeRef, ParseLimits,
    ProfileId, SourceEncoding, SourceSnapshot, Span,
};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

mod parser;
mod projection;
mod query;

pub use projection::{
    CompleteProjection, DuplicatePolicy, FailedProjectionAttempt, Fidelity, ProjectedLocation,
    ProjectionEvent, ProjectionLimits, ProjectionReport, ProjectionRequest, ProjectionResult,
    ProjectionTarget, ProvenanceEntry, ProvenanceMap, ProvenanceRelation, SourceOrigin,
};
pub use query::{
    PropertiesMatch, PropertiesSyntaxMatch, execute_properties_query,
    execute_properties_query_cursor, execute_properties_syntax_query,
    execute_properties_syntax_query_cursor,
};

/// Frozen Java Properties formation profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertiesProfile {
    /// Character-source semantics corresponding to `Properties.load(Reader)`.
    ReaderV1,
    /// ISO-8859-1 byte semantics corresponding to `Properties.load(InputStream)`.
    Latin1V1,
}

impl PropertiesProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::ReaderV1 => ProfileId::new("java-properties.reader", 1),
            Self::Latin1V1 => ProfileId::new("java-properties.latin1", 1),
        }
    }
}

/// Explicit source contract; no extension, locale, or platform default is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertiesEncodingSelection {
    /// Reader input decoded through this exact published text encoding.
    Reader(SourceEncoding),
    /// InputStream-compatible one-byte ISO-8859-1 mapping with BOM bytes as content.
    Latin1,
}

/// Java Properties parse and recovery limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropertiesParseLimits {
    /// Common source, node, piece, and diagnostic limits.
    pub common: ParseLimits,
    /// Maximum decoded UTF-8 bytes in the source snapshot.
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalars and coordinate steps.
    pub max_decoded_scalars: usize,
    /// Maximum natural source lines.
    pub max_natural_lines: usize,
    /// Maximum raw bytes in one natural line.
    pub max_natural_line_bytes: usize,
    /// Maximum decoded scalars in one natural line.
    pub max_natural_line_scalars: usize,
    /// Maximum logical property or error lines.
    pub max_logical_lines: usize,
    /// Maximum natural-line constituents in one logical line.
    pub max_logical_line_natural_lines: usize,
    /// Maximum decoded source scalars assembled into one logical line.
    pub max_logical_line_scalars: usize,
    /// Maximum property occurrences.
    pub max_properties: usize,
    /// Maximum comment occurrences.
    pub max_comments: usize,
    /// Maximum escape occurrences.
    pub max_escapes: usize,
    /// Maximum Unicode escape occurrences.
    pub max_unicode_escapes: usize,
    /// Maximum Java UTF-16 code units in one key or value.
    pub max_java_code_units_per_string: usize,
    /// Maximum Java UTF-16 code units across the document.
    pub max_total_java_code_units: usize,
    /// Maximum members in one duplicate-key group.
    pub max_duplicate_group_members: usize,
    /// Maximum recovered error lines.
    pub max_recovery_regions: usize,
}

impl Default for PropertiesParseLimits {
    fn default() -> Self {
        Self {
            common: ParseLimits::default(),
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
            max_natural_lines: 2_000_000,
            max_natural_line_bytes: 4 * 1024 * 1024,
            max_natural_line_scalars: 2 * 1024 * 1024,
            max_logical_lines: 2_000_000,
            max_logical_line_natural_lines: 100_000,
            max_logical_line_scalars: 16 * 1024 * 1024,
            max_properties: 2_000_000,
            max_comments: 2_000_000,
            max_escapes: 8_000_000,
            max_unicode_escapes: 8_000_000,
            max_java_code_units_per_string: 16 * 1024 * 1024,
            max_total_java_code_units: 64 * 1024 * 1024,
            max_duplicate_group_members: 1_000_000,
            max_recovery_regions: 100_000,
        }
    }
}

/// Whether exact Java UTF-16 units form Unicode scalar text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JavaStringStatus {
    /// Every surrogate participates in one adjacent high/low pair.
    WellFormedUnicode,
    /// At least one surrogate is unpaired.
    UnpairedSurrogate,
}

/// Exact Java string content represented as immutable UTF-16 code units.
#[derive(Clone, Debug)]
pub struct JavaString {
    code_units: Arc<[u16]>,
    status: JavaStringStatus,
}

impl JavaString {
    /// Creates exact Java content and computes surrogate well-formedness.
    #[must_use]
    pub fn from_code_units(code_units: impl Into<Arc<[u16]>>) -> Self {
        let code_units = code_units.into();
        let status = classify_java_string(&code_units);
        Self { code_units, status }
    }

    /// Converts one valid Unicode scalar string to its exact UTF-16 units.
    #[must_use]
    pub fn from_unicode(value: &str) -> Self {
        Self::from_code_units(value.encode_utf16().collect::<Vec<_>>())
    }

    /// Exact ordered Java UTF-16 code units.
    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        &self.code_units
    }

    /// Canonical BOM-free big-endian `UTF16BE/1` bytes.
    #[must_use]
    pub fn utf16be_bytes(&self) -> Vec<u8> {
        self.code_units
            .iter()
            .flat_map(|unit| unit.to_be_bytes())
            .collect()
    }

    /// Exact surrogate pairing status.
    #[must_use]
    pub const fn status(&self) -> JavaStringStatus {
        self.status
    }

    /// Converts only well-formed Java content to a Rust Unicode string.
    pub fn to_unicode(&self) -> Result<String, JavaStringConversionError> {
        String::from_utf16(&self.code_units).map_err(|_| JavaStringConversionError)
    }
}

impl PartialEq for JavaString {
    fn eq(&self, other: &Self) -> bool {
        self.code_units == other.code_units
    }
}

impl Eq for JavaString {}

impl Hash for JavaString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.code_units.hash(state);
    }
}

/// An exact Java string cannot enter a Unicode-only host string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JavaStringConversionError;

impl std::fmt::Display for JavaStringConversionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Java UTF-16 string contains an unpaired surrogate")
    }
}

impl std::error::Error for JavaStringConversionError {}

/// One lossless Properties syntax category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertiesSyntaxKind {
    /// Unicode byte-order mark recognized by the Reader source contract.
    Bom,
    /// Space, tab, or form feed.
    Whitespace,
    /// LF, CR, or CRLF.
    LineBreak,
    /// `#` or `!` starting a comment natural line.
    CommentMarker,
    /// Comment payload.
    CommentText,
    /// Raw property key content.
    Key,
    /// Whitespace and optional `=` or `:` between key and value.
    Separator,
    /// Raw property element content.
    Value,
    /// Backslash beginning a normal escape.
    EscapeMarker,
    /// Named, Unicode, or dropped-backslash escape body.
    EscapeBody,
    /// Backslash consumed by natural-line continuation.
    ContinuationMarker,
    /// Malformed source retained through recovery.
    ErrorRegion,
}

impl PropertiesSyntaxKind {
    /// Stable query/protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "Bom",
            Self::Whitespace => "Whitespace",
            Self::LineBreak => "LineBreak",
            Self::CommentMarker => "CommentMarker",
            Self::CommentText => "CommentText",
            Self::Key => "Key",
            Self::Separator => "Separator",
            Self::Value => "Value",
            Self::EscapeMarker => "EscapeMarker",
            Self::EscapeBody => "EscapeBody",
            Self::ContinuationMarker => "ContinuationMarker",
            Self::ErrorRegion => "ErrorRegion",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "Bom" => Some(Self::Bom),
            "Whitespace" => Some(Self::Whitespace),
            "LineBreak" => Some(Self::LineBreak),
            "CommentMarker" => Some(Self::CommentMarker),
            "CommentText" => Some(Self::CommentText),
            "Key" => Some(Self::Key),
            "Separator" => Some(Self::Separator),
            "Value" => Some(Self::Value),
            "EscapeMarker" => Some(Self::EscapeMarker),
            "EscapeBody" => Some(Self::EscapeBody),
            "ContinuationMarker" => Some(Self::ContinuationMarker),
            "ErrorRegion" => Some(Self::ErrorRegion),
            _ => None,
        }
    }
}

/// Semantic empty/present state with exact separator provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertiesValueState {
    /// No separator followed the key.
    ImplicitEmpty,
    /// A whitespace, `=`, or `:` separator was present but the element is empty.
    ExplicitEmpty,
    /// The decoded element contains at least one UTF-16 code unit.
    Present,
}

/// Kind of one logical Properties record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertiesLogicalLineKind {
    /// One completely formed property occurrence.
    Property,
    /// One recovered malformed logical line.
    Error,
}

/// Kind of one retained escape occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertiesEscapeKind {
    /// `\t`, `\n`, `\r`, or `\f`.
    Named,
    /// `\\`.
    Backslash,
    /// Exact lowercase-`u` four-hex-digit escape.
    Unicode,
    /// Backslash removed before another source character.
    DroppedBackslash,
}

/// One exact natural source line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertiesNaturalLine {
    pub(crate) node: NodeRef,
    pub(crate) span: Span,
    pub(crate) content_span: Span,
    pub(crate) line_break_span: Option<Span>,
}

impl PropertiesNaturalLine {
    /// Snapshot-bound natural-line identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Complete source span including the terminator.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Content span excluding the terminator.
    #[must_use]
    pub const fn content_span(&self) -> Span {
        self.content_span
    }

    /// LF, CR, or CRLF span; absent for an EOF line.
    #[must_use]
    pub const fn line_break_span(&self) -> Option<Span> {
        self.line_break_span
    }
}

/// One property/error logical line and its natural-line constituents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertiesLogicalLine {
    pub(crate) node: NodeRef,
    pub(crate) kind: PropertiesLogicalLineKind,
    pub(crate) natural_lines: Arc<[NodeRef]>,
}

impl PropertiesLogicalLine {
    /// Snapshot-bound logical-line identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Property or recovered-error classification.
    #[must_use]
    pub const fn kind(&self) -> PropertiesLogicalLineKind {
        self.kind
    }

    /// Ordered natural-line constituents.
    #[must_use]
    pub fn natural_lines(&self) -> &[NodeRef] {
        &self.natural_lines
    }
}

/// One comment natural line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertiesComment {
    pub(crate) node: NodeRef,
    pub(crate) natural_line: NodeRef,
    pub(crate) span: Span,
    pub(crate) marker: char,
}

impl PropertiesComment {
    /// Snapshot-bound comment identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning natural line.
    #[must_use]
    pub const fn natural_line(&self) -> NodeRef {
        self.natural_line
    }

    /// Complete comment content span excluding its line break.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Exact comment marker.
    #[must_use]
    pub const fn marker(&self) -> char {
        self.marker
    }
}

/// One source escape and its exact Java-string output range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertiesEscape {
    pub(crate) node: NodeRef,
    pub(crate) property: NodeRef,
    pub(crate) in_key: bool,
    pub(crate) kind: PropertiesEscapeKind,
    pub(crate) span: Span,
    pub(crate) output_start: usize,
    pub(crate) output_end: usize,
}

impl PropertiesEscape {
    /// Snapshot-bound escape identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning property occurrence.
    #[must_use]
    pub const fn property(&self) -> NodeRef {
        self.property
    }

    /// Whether the output range belongs to the decoded key.
    #[must_use]
    pub const fn in_key(&self) -> bool {
        self.in_key
    }

    /// Exact escape kind.
    #[must_use]
    pub const fn kind(&self) -> PropertiesEscapeKind {
        self.kind
    }

    /// Complete raw escape spelling.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Half-open output code-unit range in the owning key or value.
    #[must_use]
    pub const fn output_range(&self) -> std::ops::Range<usize> {
        self.output_start..self.output_end
    }
}

/// One distinct source-ordered property association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Property {
    pub(crate) node: NodeRef,
    pub(crate) logical_line: NodeRef,
    pub(crate) span: Span,
    pub(crate) key_anchor: Span,
    pub(crate) value_anchor: Span,
    pub(crate) key_fragments: Arc<[Span]>,
    pub(crate) value_fragments: Arc<[Span]>,
    pub(crate) key: JavaString,
    pub(crate) value: JavaString,
    pub(crate) value_state: PropertiesValueState,
    pub(crate) escapes: Arc<[NodeRef]>,
    pub(crate) duplicate_group: Option<u32>,
}

impl Property {
    /// Snapshot-bound property association identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning logical line.
    #[must_use]
    pub const fn logical_line(&self) -> NodeRef {
        self.logical_line
    }

    /// Complete first-to-last property source range.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Zero-width source anchor at the start of the decoded key.
    #[must_use]
    pub const fn key_anchor(&self) -> Span {
        self.key_anchor
    }

    /// Zero-width source anchor at the start of the decoded value.
    #[must_use]
    pub const fn value_anchor(&self) -> Span {
        self.value_anchor
    }

    /// Ordered raw source fragments contributing to the key.
    #[must_use]
    pub fn key_fragments(&self) -> &[Span] {
        &self.key_fragments
    }

    /// Ordered raw source fragments contributing to the value.
    #[must_use]
    pub fn value_fragments(&self) -> &[Span] {
        &self.value_fragments
    }

    /// Exact decoded Java UTF-16 key.
    #[must_use]
    pub const fn key(&self) -> &JavaString {
        &self.key
    }

    /// Exact decoded Java UTF-16 element.
    #[must_use]
    pub const fn value(&self) -> &JavaString {
        &self.value
    }

    /// Implicit, explicit empty, or present source state.
    #[must_use]
    pub const fn value_state(&self) -> PropertiesValueState {
        self.value_state
    }

    /// Ordered escape identities in key-then-value decode order.
    #[must_use]
    pub fn escapes(&self) -> &[NodeRef] {
        &self.escapes
    }

    /// Deterministic exact-code-unit duplicate group.
    #[must_use]
    pub const fn duplicate_group(&self) -> Option<u32> {
        self.duplicate_group
    }
}

/// One recovered malformed logical line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertiesErrorLine {
    pub(crate) node: NodeRef,
    pub(crate) logical_line: NodeRef,
    pub(crate) natural_lines: Arc<[NodeRef]>,
    pub(crate) span: Span,
    pub(crate) code: Arc<str>,
}

impl PropertiesErrorLine {
    /// Snapshot-bound error identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning recovered logical line.
    #[must_use]
    pub const fn logical_line(&self) -> NodeRef {
        self.logical_line
    }

    /// Natural lines retained by this recovery record.
    #[must_use]
    pub fn natural_lines(&self) -> &[NodeRef] {
        &self.natural_lines
    }

    /// Complete recovered source range.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Stable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

/// Immutable, duplicate-preserving Java Properties document.
#[derive(Clone, Debug)]
pub struct Document {
    pub(crate) authority: consema_document::DocumentAuthority,
    pub(crate) source: SourceSnapshot,
    pub(crate) profile: PropertiesProfile,
    pub(crate) structural_index: LosslessStructuralIndex,
    pub(crate) syntax_kinds: Arc<[PropertiesSyntaxKind]>,
    pub(crate) formation_status: FormationStatus,
    pub(crate) diagnostics: Arc<[Diagnostic]>,
    pub(crate) natural_lines: Arc<[PropertiesNaturalLine]>,
    pub(crate) logical_lines: Arc<[PropertiesLogicalLine]>,
    pub(crate) properties: Arc<[Property]>,
    pub(crate) comments: Arc<[PropertiesComment]>,
    pub(crate) escapes: Arc<[PropertiesEscape]>,
    pub(crate) error_lines: Arc<[PropertiesErrorLine]>,
    pub(crate) parse_limits: PropertiesParseLimits,
    pub(crate) root_node: NodeRef,
}

impl Document {
    /// Snapshot identity to which every Properties handle and span belongs.
    #[must_use]
    pub fn snapshot_identity(&self) -> consema_document::SnapshotIdentity {
        self.authority.identity()
    }

    /// Exact immutable source snapshot.
    #[must_use]
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Default rendering is byte-for-byte source identity.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Stable Java Properties format family.
    #[must_use]
    pub fn format_family(&self) -> consema_document::FormatFamilyId {
        consema_document::FormatFamilyId::new("java-properties", 1)
    }

    /// Exact selected profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Concrete selected profile.
    #[must_use]
    pub const fn selected_profile(&self) -> PropertiesProfile {
        self.profile
    }

    /// Root Properties document identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.root_node
    }

    /// Complete or explicitly recovered formation state.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        self.formation_status
    }

    /// Stable ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Exhaustive ordered source coverage.
    #[must_use]
    pub const fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.structural_index
    }

    /// Format kind aligned with every structural piece.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[PropertiesSyntaxKind] {
        &self.syntax_kinds
    }

    /// Ordered natural source lines.
    #[must_use]
    pub fn natural_lines(&self) -> &[PropertiesNaturalLine] {
        &self.natural_lines
    }

    /// Ordered property/error logical lines.
    #[must_use]
    pub fn logical_lines(&self) -> &[PropertiesLogicalLine] {
        &self.logical_lines
    }

    /// Ordered duplicate-preserving property associations.
    #[must_use]
    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    /// Ordered comment occurrences.
    #[must_use]
    pub fn comments(&self) -> &[PropertiesComment] {
        &self.comments
    }

    /// Ordered escape occurrences.
    #[must_use]
    pub fn escapes(&self) -> &[PropertiesEscape] {
        &self.escapes
    }

    /// Ordered recovered error lines.
    #[must_use]
    pub fn error_lines(&self) -> &[PropertiesErrorLine] {
        &self.error_lines
    }

    /// Resource contract used to form this snapshot.
    #[must_use]
    pub const fn parse_limits(&self) -> PropertiesParseLimits {
        self.parse_limits
    }

    /// Resolves one property handle only within this snapshot.
    pub fn property(&self, node: NodeRef) -> Result<&Property, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::PropertiesProperty {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.properties
            .iter()
            .find(|property| property.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one natural-line handle only within this snapshot.
    pub fn natural_line(
        &self,
        node: NodeRef,
    ) -> Result<&PropertiesNaturalLine, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::PropertiesNaturalLine {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.natural_lines
            .iter()
            .find(|line| line.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one logical-line handle only within this snapshot.
    pub fn logical_line(
        &self,
        node: NodeRef,
    ) -> Result<&PropertiesLogicalLine, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::PropertiesLogicalLine {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.logical_lines
            .iter()
            .find(|line| line.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one escape handle only within this snapshot.
    pub fn escape(
        &self,
        node: NodeRef,
    ) -> Result<&PropertiesEscape, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::PropertiesEscape {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.escapes
            .iter()
            .find(|escape| escape.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }
}

/// Parses one immutable Properties snapshot under one exact profile/source contract.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: PropertiesProfile,
    encoding: PropertiesEncodingSelection,
    limits: PropertiesParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parser::parse(source.into(), profile, encoding, limits)
}

/// Parses Reader input using one explicit published text encoding.
pub fn parse_reader(
    source: impl Into<Arc<[u8]>>,
    encoding: SourceEncoding,
    limits: PropertiesParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parse(
        source,
        PropertiesProfile::ReaderV1,
        PropertiesEncodingSelection::Reader(encoding),
        limits,
    )
}

/// Parses InputStream-compatible Latin-1 bytes with marker bytes as content.
pub fn parse_latin1(
    source: impl Into<Arc<[u8]>>,
    limits: PropertiesParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parse(
        source,
        PropertiesProfile::Latin1V1,
        PropertiesEncodingSelection::Latin1,
        limits,
    )
}

fn classify_java_string(units: &[u16]) -> JavaStringStatus {
    let mut index = 0;
    while index < units.len() {
        match units[index] {
            0xD800..=0xDBFF
                if units
                    .get(index + 1)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(next)) =>
            {
                index += 2;
            }
            0xD800..=0xDFFF => return JavaStringStatus::UnpairedSurrogate,
            _ => index += 1,
        }
    }
    JavaStringStatus::WellFormedUnicode
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{BomKind, FormationStatus, StructuralPieceKind};

    #[test]
    fn java_string_preserves_exact_unpaired_code_units() {
        let exact = JavaString::from_code_units(vec![0x0041, 0xD800, 0x0042]);
        assert_eq!(exact.code_units(), &[0x0041, 0xD800, 0x0042]);
        assert_eq!(exact.utf16be_bytes(), [0x00, 0x41, 0xD8, 0x00, 0x00, 0x42]);
        assert_eq!(exact.status(), JavaStringStatus::UnpairedSurrogate);
        assert!(exact.to_unicode().is_err());

        let scalar = JavaString::from_unicode("😀");
        assert_eq!(scalar.code_units(), &[0xD83D, 0xDE00]);
        assert_eq!(scalar.to_unicode().unwrap(), "😀");
    }

    #[test]
    fn formation_preserves_lines_continuations_escapes_and_duplicates() {
        let source = b"  # retained comment\\\r\nkey\\ with\\ spaces : first\\\r\n \tsecond\\u0021\ndup=first\rdup:last\nempty\nexplicit=";
        let document = parse_reader(
            source.as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();

        assert_eq!(document.formation_status(), FormationStatus::Complete);
        assert_eq!(document.render(), source);
        assert_eq!(document.natural_lines().len(), 7);
        assert_eq!(document.logical_lines().len(), 5);
        assert_eq!(document.comments().len(), 1);
        assert_eq!(document.properties().len(), 5);
        assert_eq!(document.escapes().len(), 3);

        let first = &document.properties()[0];
        assert_eq!(first.key().to_unicode().unwrap(), "key with spaces");
        assert_eq!(first.value().to_unicode().unwrap(), "firstsecond!");
        assert_eq!(first.value_state(), PropertiesValueState::Present);
        assert_eq!(first.key_fragments().len(), 1);
        assert_eq!(first.value_fragments().len(), 2);
        assert_eq!(first.escapes().len(), 3);
        assert_eq!(document.properties()[1].duplicate_group(), Some(1));
        assert_eq!(document.properties()[2].duplicate_group(), Some(1));
        assert_eq!(
            document.properties()[3].value_state(),
            PropertiesValueState::ImplicitEmpty
        );
        assert_eq!(
            document.properties()[4].value_state(),
            PropertiesValueState::ExplicitEmpty
        );
        assert!(
            document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::ContinuationMarker)
        );
        assert!(
            document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::EscapeMarker)
        );

        let pieces = document.lossless_structural_index().pieces();
        assert_eq!(pieces.first().unwrap().span().start_byte(), 0);
        assert_eq!(pieces.last().unwrap().span().end_byte(), source.len());
        assert!(
            pieces
                .windows(2)
                .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
        );
    }

    #[test]
    fn malformed_unicode_escape_recovers_without_partial_property() {
        let source = br"good=ok
bad=\u12G4
after=yes";
        let document = parse_reader(
            source.as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();

        assert_eq!(document.formation_status(), FormationStatus::Recovered);
        assert_eq!(document.render(), source);
        assert_eq!(document.properties().len(), 2);
        assert_eq!(document.error_lines().len(), 1);
        assert_eq!(document.logical_lines().len(), 3);
        assert_eq!(
            document.error_lines()[0].code(),
            "java-properties.parse.malformed-unicode-escape@1"
        );
        assert_eq!(
            document.diagnostics()[0].code,
            "java-properties.parse.malformed-unicode-escape@1"
        );
        assert!(
            document
                .lossless_structural_index()
                .pieces()
                .iter()
                .any(|piece| piece.kind() == StructuralPieceKind::ErrorRegion)
        );
    }

    #[test]
    fn unicode_escape_preserves_an_unpaired_java_surrogate() {
        let document = parse_reader(
            br"key=\uD800".as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        let value = document.properties()[0].value();
        assert_eq!(value.code_units(), &[0xD800]);
        assert_eq!(value.status(), JavaStringStatus::UnpairedSurrogate);
        assert!(value.to_unicode().is_err());
    }

    #[test]
    fn latin1_treats_unicode_bom_bytes_as_content() {
        let source = [0xEF, 0xBB, 0xBF, b'k', b'=', b'v'];
        let document = parse_latin1(source, PropertiesParseLimits::default()).unwrap();
        assert_eq!(document.source().encoding_facts().bom(), None);
        assert_eq!(
            document.properties()[0].key().code_units(),
            &[0x00EF, 0x00BB, 0x00BF, 0x006B]
        );
        assert!(
            !document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::Bom)
        );
    }

    #[test]
    fn reader_honors_an_explicit_matching_utf16_bom() {
        let source = [0xFF, 0xFE, b'k', 0, b'=', 0, b'v', 0];
        let document = parse_reader(
            source,
            SourceEncoding::Utf16Le,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            document.source().encoding_facts().bom(),
            Some(BomKind::Utf16Le)
        );
        assert_eq!(document.properties()[0].key().to_unicode().unwrap(), "k");
        assert_eq!(document.render(), source);
        assert_eq!(
            document.lossless_syntax_kinds().first(),
            Some(&PropertiesSyntaxKind::Bom)
        );
    }

    #[test]
    fn profile_and_encoding_selection_must_match() {
        let failure = parse(
            b"k=v".as_slice(),
            PropertiesProfile::Latin1V1,
            PropertiesEncodingSelection::Reader(SourceEncoding::Utf8),
            PropertiesParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            failure.diagnostics()[0].code,
            "java-properties.source.profile-encoding@1"
        );
    }

    #[test]
    fn terminal_odd_backslash_matches_jdk_line_reader_eof_rule() {
        let mut source = b"key=value".to_vec();
        source.push(b'\\');
        let document = parse_reader(
            source.clone(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            document.properties()[0].value().to_unicode().unwrap(),
            "value"
        );
        assert_eq!(document.render(), source);
        assert_eq!(
            document.lossless_syntax_kinds().last(),
            Some(&PropertiesSyntaxKind::ContinuationMarker)
        );
    }

    #[test]
    fn unicode_escape_may_cross_a_continuation_without_stealing_its_syntax() {
        let source = b"key=\\u00\\\n 41";
        let document = parse_reader(
            source.as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();

        assert_eq!(document.properties()[0].value().code_units(), &[0x0041]);
        assert_eq!(document.properties()[0].value_fragments().len(), 2);
        assert_eq!(document.escapes().len(), 1);
        assert!(
            document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::ContinuationMarker)
        );
        assert!(
            document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::LineBreak)
        );
    }
}
