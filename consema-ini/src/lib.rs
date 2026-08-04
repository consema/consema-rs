//! Lossless INI documents under three explicit, incompatible profiles.

use consema_core::Diagnostic;
use consema_document::{
    FatalFormationFailure, FormationStatus, LosslessStructuralIndex, NodeRef, ParseLimits,
    ProfileId, SourceEncoding, SourceSnapshot, Span,
};
use std::sync::Arc;

mod parser;
mod query;

pub use query::{
    IniMatch, IniSyntaxMatch, execute_ini_query, execute_ini_query_cursor,
    execute_ini_syntax_query, execute_ini_syntax_query_cursor,
};

/// Frozen INI formation profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IniProfile {
    /// Conservative ASCII exchange subset.
    PortableV1,
    /// Deterministic Windows profile-string file surface.
    WindowsV1,
    /// Python 3.14 ConfigParser default formation surface without evaluation.
    PythonConfigParserV1,
}

impl IniProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::PortableV1 => ProfileId::new("ini.portable", 1),
            Self::WindowsV1 => ProfileId::new("ini.windows", 1),
            Self::PythonConfigParserV1 => ProfileId::new("ini.python-configparser", 1),
        }
    }
}

/// Explicit source-encoding selection; no host locale is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IniEncodingSelection {
    /// Apply only the selected profile's frozen default and BOM rules.
    ProfileDefault,
    /// Use one caller-selected source encoding.
    Explicit(SourceEncoding),
}

/// INI-specific parse and recovery limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IniParseLimits {
    /// Common source, node, piece, nesting, and diagnostic limits.
    pub common: ParseLimits,
    /// Maximum decoded UTF-8 bytes.
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalars and coordinate steps.
    pub max_decoded_scalars: usize,
    /// Maximum physical source lines.
    pub max_physical_lines: usize,
    /// Maximum raw bytes in one physical line.
    pub max_physical_line_bytes: usize,
    /// Maximum decoded scalars in one physical line.
    pub max_physical_line_scalars: usize,
    /// Maximum logical records.
    pub max_logical_lines: usize,
    /// Maximum raw bytes owned by one logical record.
    pub max_logical_line_bytes: usize,
    /// Maximum decoded scalars in one logical record.
    pub max_logical_line_scalars: usize,
    /// Maximum continuation physical lines per Python entry.
    pub max_continuation_lines: usize,
    /// Maximum section occurrences.
    pub max_sections: usize,
    /// Maximum entry occurrences.
    pub max_entries: usize,
    /// Maximum members in one duplicate or case-equivalence group.
    pub max_duplicate_group_members: usize,
    /// Maximum recovered error lines.
    pub max_recovery_regions: usize,
}

impl Default for IniParseLimits {
    fn default() -> Self {
        Self {
            common: ParseLimits::default(),
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
            max_physical_lines: 2_000_000,
            max_physical_line_bytes: 4 * 1024 * 1024,
            max_physical_line_scalars: 2 * 1024 * 1024,
            max_logical_lines: 2_000_000,
            max_logical_line_bytes: 16 * 1024 * 1024,
            max_logical_line_scalars: 8 * 1024 * 1024,
            max_continuation_lines: 100_000,
            max_sections: 1_000_000,
            max_entries: 1_000_000,
            max_duplicate_group_members: 100_000,
            max_recovery_regions: 100_000,
        }
    }
}

/// One lossless INI syntax category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IniSyntaxKind {
    /// Unicode byte-order mark.
    Bom,
    /// Horizontal whitespace.
    Whitespace,
    /// LF or CRLF.
    LineBreak,
    /// Prefix comment marker.
    CommentMarker,
    /// Comment payload.
    CommentText,
    /// Opening section bracket.
    SectionOpen,
    /// Section name text.
    SectionName,
    /// Closing section bracket.
    SectionClose,
    /// Entry key text.
    EntryKey,
    /// Entry delimiter.
    Delimiter,
    /// Value quote.
    Quote,
    /// Entry value text.
    EntryValue,
    /// Skipped indentation on a continuation line.
    ContinuationMarker,
    /// Profile-invalid or malformed source range.
    ErrorRegion,
}

impl IniSyntaxKind {
    /// Stable query/protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "Bom",
            Self::Whitespace => "Whitespace",
            Self::LineBreak => "LineBreak",
            Self::CommentMarker => "CommentMarker",
            Self::CommentText => "CommentText",
            Self::SectionOpen => "SectionOpen",
            Self::SectionName => "SectionName",
            Self::SectionClose => "SectionClose",
            Self::EntryKey => "EntryKey",
            Self::Delimiter => "Delimiter",
            Self::Quote => "Quote",
            Self::EntryValue => "EntryValue",
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
            "SectionOpen" => Some(Self::SectionOpen),
            "SectionName" => Some(Self::SectionName),
            "SectionClose" => Some(Self::SectionClose),
            "EntryKey" => Some(Self::EntryKey),
            "Delimiter" => Some(Self::Delimiter),
            "Quote" => Some(Self::Quote),
            "EntryValue" => Some(Self::EntryValue),
            "ContinuationMarker" => Some(Self::ContinuationMarker),
            "ErrorRegion" => Some(Self::ErrorRegion),
            _ => None,
        }
    }
}

/// Native value-presence fact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IniValueState {
    /// No delimiter/value was present; only recovered error records use this in v1.
    Missing,
    /// A delimiter was present with empty semantic content.
    Empty,
    /// Non-empty semantic string content.
    Present,
}

/// Profile-recognized outer quote style.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IniQuoteStyle {
    /// No semantic outer quotes.
    None,
    /// Exact single quotes under the Windows profile.
    Single,
    /// Exact double quotes under the Windows profile.
    Double,
}

/// Kind of one logical INI record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IniLogicalLineKind {
    /// Section header record.
    Section,
    /// Entry and any continuation lines.
    Entry,
    /// Recovered malformed record.
    Error,
}

/// One exact physical source line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniPhysicalLine {
    pub(crate) node: NodeRef,
    pub(crate) span: Span,
    pub(crate) content_span: Span,
    pub(crate) line_break_span: Option<Span>,
}

impl IniPhysicalLine {
    /// Snapshot-bound physical-line identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Complete raw line including its line break.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Raw line content excluding its line break.
    #[must_use]
    pub const fn content_span(&self) -> Span {
        self.content_span
    }

    /// Exact LF or CRLF range, absent at EOF.
    #[must_use]
    pub const fn line_break_span(&self) -> Option<Span> {
        self.line_break_span
    }
}

/// One logical record and its ordered physical constituents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniLogicalLine {
    pub(crate) node: NodeRef,
    pub(crate) kind: IniLogicalLineKind,
    pub(crate) physical_lines: Vec<NodeRef>,
}

impl IniLogicalLine {
    /// Snapshot-bound logical-line identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Logical record kind.
    #[must_use]
    pub const fn kind(&self) -> IniLogicalLineKind {
        self.kind
    }

    /// Ordered physical-line identities.
    #[must_use]
    pub fn physical_lines(&self) -> &[NodeRef] {
        &self.physical_lines
    }
}

/// One distinct section-header occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniSection {
    pub(crate) node: NodeRef,
    pub(crate) logical_line: NodeRef,
    pub(crate) span: Span,
    pub(crate) name_span: Span,
    pub(crate) name: Arc<str>,
    pub(crate) comparison_name: Arc<str>,
    pub(crate) is_default: bool,
    pub(crate) duplicate_group: Option<u32>,
}

impl IniSection {
    /// Snapshot-bound section occurrence identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning logical-line identity.
    #[must_use]
    pub const fn logical_line(&self) -> NodeRef {
        self.logical_line
    }

    /// Complete header content span, excluding the line break.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Exact section-name span.
    #[must_use]
    pub const fn name_span(&self) -> Span {
        self.name_span
    }

    /// Original decoded name spelling.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Profile-specific comparison name.
    #[must_use]
    pub fn comparison_name(&self) -> &str {
        &self.comparison_name
    }

    /// Whether this is Python's exact `DEFAULT` section.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.is_default
    }

    /// Deterministic duplicate/case-equivalence group identity.
    #[must_use]
    pub const fn duplicate_group(&self) -> Option<u32> {
        self.duplicate_group
    }
}

/// One distinct key/value occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniEntry {
    pub(crate) node: NodeRef,
    pub(crate) logical_line: NodeRef,
    pub(crate) section: NodeRef,
    pub(crate) span: Span,
    pub(crate) key_span: Span,
    pub(crate) value_span: Span,
    pub(crate) key: Arc<str>,
    pub(crate) comparison_key: Arc<str>,
    pub(crate) value: Arc<str>,
    pub(crate) state: IniValueState,
    pub(crate) quote_style: IniQuoteStyle,
    pub(crate) duplicate_group: Option<u32>,
}

impl IniEntry {
    /// Snapshot-bound entry occurrence identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning logical-line identity.
    #[must_use]
    pub const fn logical_line(&self) -> NodeRef {
        self.logical_line
    }

    /// Owning section occurrence.
    #[must_use]
    pub const fn section(&self) -> NodeRef {
        self.section
    }

    /// Complete first physical-line content span.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Exact original key span.
    #[must_use]
    pub const fn key_span(&self) -> Span {
        self.key_span
    }

    /// Exact first-line semantic value span.
    #[must_use]
    pub const fn value_span(&self) -> Span {
        self.value_span
    }

    /// Original decoded key spelling.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Profile-specific comparison key.
    #[must_use]
    pub fn comparison_key(&self) -> &str {
        &self.comparison_key
    }

    /// Stored semantic string, including deterministic continuation joins.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Missing, empty, or present value fact.
    #[must_use]
    pub const fn value_state(&self) -> IniValueState {
        self.state
    }

    /// Profile-recognized outer quote style.
    #[must_use]
    pub const fn quote_style(&self) -> IniQuoteStyle {
        self.quote_style
    }

    /// Deterministic duplicate/case-equivalence group identity.
    #[must_use]
    pub const fn duplicate_group(&self) -> Option<u32> {
        self.duplicate_group
    }
}

/// One recovered physical error record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniErrorLine {
    pub(crate) node: NodeRef,
    pub(crate) logical_line: NodeRef,
    pub(crate) physical_line: NodeRef,
    pub(crate) span: Span,
    pub(crate) code: Arc<str>,
}

impl IniErrorLine {
    /// Snapshot-bound error identity.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        self.node
    }

    /// Owning logical-line identity.
    #[must_use]
    pub const fn logical_line(&self) -> NodeRef {
        self.logical_line
    }

    /// Physical line retained by recovery.
    #[must_use]
    pub const fn physical_line(&self) -> NodeRef {
        self.physical_line
    }

    /// Exact malformed content span.
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

/// Immutable lossless INI document.
#[derive(Clone, Debug)]
pub struct Document {
    pub(crate) authority: consema_document::DocumentAuthority,
    pub(crate) source: SourceSnapshot,
    pub(crate) profile: IniProfile,
    pub(crate) structural_index: LosslessStructuralIndex,
    pub(crate) syntax_kinds: Arc<[IniSyntaxKind]>,
    pub(crate) formation_status: FormationStatus,
    pub(crate) diagnostics: Arc<[Diagnostic]>,
    pub(crate) physical_lines: Arc<[IniPhysicalLine]>,
    pub(crate) logical_lines: Arc<[IniLogicalLine]>,
    pub(crate) sections: Arc<[IniSection]>,
    pub(crate) entries: Arc<[IniEntry]>,
    pub(crate) error_lines: Arc<[IniErrorLine]>,
    pub(crate) parse_limits: IniParseLimits,
    pub(crate) root_node: NodeRef,
}

impl Document {
    /// Snapshot identity to which every INI handle and span belongs.
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

    /// Stable INI format family.
    #[must_use]
    pub fn format_family(&self) -> consema_document::FormatFamilyId {
        consema_document::FormatFamilyId::new("ini", 1)
    }

    /// Exact selected profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Root INI document identity.
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

    /// Format kind aligned with each structural piece.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[IniSyntaxKind] {
        &self.syntax_kinds
    }

    /// Ordered physical source lines.
    #[must_use]
    pub fn physical_lines(&self) -> &[IniPhysicalLine] {
        &self.physical_lines
    }

    /// Ordered logical records.
    #[must_use]
    pub fn logical_lines(&self) -> &[IniLogicalLine] {
        &self.logical_lines
    }

    /// Ordered distinct section occurrences.
    #[must_use]
    pub fn sections(&self) -> &[IniSection] {
        &self.sections
    }

    /// Ordered distinct entry occurrences.
    #[must_use]
    pub fn entries(&self) -> &[IniEntry] {
        &self.entries
    }

    /// Ordered recovered error records.
    #[must_use]
    pub fn error_lines(&self) -> &[IniErrorLine] {
        &self.error_lines
    }

    /// Resource contract used to form this snapshot.
    #[must_use]
    pub const fn parse_limits(&self) -> IniParseLimits {
        self.parse_limits
    }

    /// Resolves one physical-line handle only within this snapshot.
    pub fn physical_line(
        &self,
        node: NodeRef,
    ) -> Result<&IniPhysicalLine, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::IniPhysicalLine {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.physical_lines
            .iter()
            .find(|line| line.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one logical-line handle only within this snapshot.
    pub fn logical_line(
        &self,
        node: NodeRef,
    ) -> Result<&IniLogicalLine, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::IniLogicalLine {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.logical_lines
            .iter()
            .find(|line| line.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one section/default-section handle only within this snapshot.
    pub fn section(&self, node: NodeRef) -> Result<&IniSection, consema_document::LocationError> {
        self.authority.verify(node)?;
        if !matches!(
            node.role(),
            consema_document::NodeRole::IniSection | consema_document::NodeRole::IniDefaultSection
        ) {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.sections
            .iter()
            .find(|section| section.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }

    /// Resolves one entry handle only within this snapshot.
    pub fn entry(&self, node: NodeRef) -> Result<&IniEntry, consema_document::LocationError> {
        self.authority.verify(node)?;
        if node.role() != consema_document::NodeRole::IniEntry {
            return Err(consema_document::LocationError::WrongRole);
        }
        self.entries
            .iter()
            .find(|entry| entry.node == node)
            .ok_or(consema_document::LocationError::OutOfBounds)
    }
}

/// Parses one immutable INI snapshot under exactly one selected profile.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: IniProfile,
    encoding: IniEncodingSelection,
    limits: IniParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parser::parse(source.into(), profile, encoding, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{BomKind, BomPolicy, LocationError};

    fn parse_text(profile: IniProfile, text: &str) -> Document {
        parse(
            text.as_bytes(),
            profile,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap()
    }

    fn utf16le_bom(text: &str) -> Vec<u8> {
        let mut output = vec![0xff, 0xfe];
        output.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        output
    }

    fn assert_exact_coverage(document: &Document) {
        assert_eq!(
            document.lossless_structural_index().pieces().len(),
            document.lossless_syntax_kinds().len()
        );
        let pieces = document.lossless_structural_index().pieces();
        assert_eq!(
            pieces.first().map(|piece| piece.span().start_byte()),
            Some(0)
        );
        assert_eq!(
            pieces.last().map(|piece| piece.span().end_byte()),
            Some(document.source().len())
        );
        for pair in pieces.windows(2) {
            assert_eq!(pair[0].span().end_byte(), pair[1].span().start_byte());
        }
    }

    #[test]
    fn portable_profile_is_lossless_and_keeps_empty_distinct() {
        let source = "; heading\r\n[core]\r\nname=value\nempty=";
        let document = parse_text(IniProfile::PortableV1, source);
        assert_eq!(document.render(), source.as_bytes());
        assert_eq!(document.formation_status(), FormationStatus::Complete);
        assert_eq!(document.physical_lines().len(), 4);
        assert_eq!(document.logical_lines().len(), 3);
        assert_eq!(document.sections().len(), 1);
        assert_eq!(document.sections()[0].name(), "core");
        assert_eq!(document.entries().len(), 2);
        assert_eq!(document.entries()[0].value(), "value");
        assert_eq!(document.entries()[0].value_state(), IniValueState::Present);
        assert_eq!(document.entries()[1].value(), "");
        assert_eq!(document.entries()[1].value_state(), IniValueState::Empty);
        assert_exact_coverage(&document);
    }

    #[test]
    fn portable_profile_recovers_counterexamples_without_fabricating_entries() {
        for source in ["", "; only\n", "[s]\nkey:value\n", "[s]\nkey=é\n"] {
            let document = parse_text(IniProfile::PortableV1, source);
            assert_eq!(document.formation_status(), FormationStatus::Recovered);
            assert_exact_coverage_or_empty(&document);
        }
        let missing_delimiter = parse_text(IniProfile::PortableV1, "[s]\nkey:value\n");
        assert!(missing_delimiter.entries().is_empty());
        assert_eq!(missing_delimiter.error_lines().len(), 1);
        assert_eq!(
            missing_delimiter.error_lines()[0].code(),
            "ini.parse.missing-delimiter@1"
        );

        assert!(
            parse(
                [0xef, 0xbb, 0xbf, b'[', b's', b']', b'\n'],
                IniProfile::PortableV1,
                IniEncodingSelection::ProfileDefault,
                IniParseLimits::default(),
            )
            .is_err()
        );
    }

    fn assert_exact_coverage_or_empty(document: &Document) {
        if document.source().is_empty() {
            assert!(document.lossless_structural_index().pieces().is_empty());
        } else {
            assert_exact_coverage(document);
        }
    }

    #[test]
    fn windows_profile_accepts_utf16le_and_marks_case_ambiguity() {
        let source = utf16le_bom("[Main]\r\n Name =\" value \"\r\n[main]\r\nNAME=two");
        let document = parse(
            source.clone(),
            IniProfile::WindowsV1,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.render(), source);
        assert_eq!(document.formation_status(), FormationStatus::Complete);
        assert_eq!(
            document.source().encoding_facts().bom(),
            Some(BomKind::Utf16Le)
        );
        assert_eq!(document.sections().len(), 2);
        assert_eq!(document.sections()[0].comparison_name(), "main");
        assert_eq!(
            document.sections()[0].duplicate_group(),
            document.sections()[1].duplicate_group()
        );
        assert_eq!(document.entries()[0].key(), "Name");
        assert_eq!(document.entries()[0].value(), " value ");
        assert_eq!(document.entries()[0].quote_style(), IniQuoteStyle::Double);
        assert_eq!(
            document.entries()[0].duplicate_group(),
            document.entries()[1].duplicate_group()
        );
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|item| item.code == "ini.formation.case-collision@1")
        );
        assert_exact_coverage(&document);

        assert!(
            parse(
                [0xfe, 0xff, 0x00, b'[', 0x00, b's', 0x00, b']'],
                IniProfile::WindowsV1,
                IniEncodingSelection::ProfileDefault,
                IniParseLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn windows_profile_requires_explicit_code_page_for_non_ascii_bytes() {
        let code_page = consema_document::WindowsCodePage::from_number(1252).unwrap();
        let source = [b'[', b's', b']', b'\r', b'\n', b'k', b'=', 0x80];
        let document = parse(
            source,
            IniProfile::WindowsV1,
            IniEncodingSelection::Explicit(SourceEncoding::WindowsCodePage(code_page)),
            IniParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.entries()[0].value(), "€");
        assert_eq!(
            document.source().encoding_facts().bom_policy(),
            BomPolicy::TreatAsContent
        );
        assert_eq!(
            document.source().encoding_facts().caller_override(),
            Some(SourceEncoding::WindowsCodePage(code_page))
        );
        assert_exact_coverage(&document);

        assert!(
            parse(
                "[s]\nk=é".as_bytes(),
                IniProfile::WindowsV1,
                IniEncodingSelection::ProfileDefault,
                IniParseLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn python_profile_keeps_default_raw_values_and_multiline_identity() {
        let source = "[DEFAULT]\nRoot = raw%(x)s\n[Sec]\nKey: first\n    second\n\n    third\nOther = #literal ;literal";
        let document = parse_text(IniProfile::PythonConfigParserV1, source);
        assert_eq!(document.formation_status(), FormationStatus::Complete);
        assert_eq!(document.sections().len(), 2);
        assert!(document.sections()[0].is_default());
        assert_eq!(
            document.sections()[0].node_ref().role(),
            consema_document::NodeRole::IniDefaultSection
        );
        assert_eq!(document.entries()[0].value(), "raw%(x)s");
        assert_eq!(document.entries()[1].comparison_key(), "key");
        assert_eq!(document.entries()[1].value(), "first\nsecond\n\nthird");
        assert_eq!(
            document
                .logical_line(document.entries()[1].logical_line())
                .unwrap()
                .physical_lines()
                .len(),
            4
        );
        assert_eq!(document.entries()[2].value(), "#literal ;literal");
        assert_exact_coverage(&document);
    }

    #[test]
    fn python_duplicates_recover_and_handles_are_snapshot_bound() {
        let document = parse_text(IniProfile::PythonConfigParserV1, "[S]\nKey=1\nkey=2\n[S]\n");
        assert_eq!(document.formation_status(), FormationStatus::Recovered);
        assert!(document.entries()[0].duplicate_group().is_some());
        assert_eq!(
            document.entries()[0].duplicate_group(),
            document.entries()[1].duplicate_group()
        );
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|item| item.code == "ini.formation.case-collision@1")
        );
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|item| item.code == "ini.formation.duplicate-section@1")
        );

        let other = parse_text(IniProfile::PythonConfigParserV1, "[T]\nx=1\n");
        assert_eq!(
            other.entry(document.entries()[0].node_ref()),
            Err(LocationError::WrongSnapshot)
        );
    }

    #[test]
    fn every_formation_limit_fails_without_a_document() {
        let limits = IniParseLimits {
            max_physical_lines: 1,
            ..IniParseLimits::default()
        };
        assert!(
            parse(
                b"[s]\nk=1\n".as_slice(),
                IniProfile::PortableV1,
                IniEncodingSelection::ProfileDefault,
                limits,
            )
            .is_err()
        );

        let limits = IniParseLimits {
            max_continuation_lines: 0,
            ..IniParseLimits::default()
        };
        assert!(
            parse(
                b"[s]\nk=one\n  two\n".as_slice(),
                IniProfile::PythonConfigParserV1,
                IniEncodingSelection::ProfileDefault,
                limits,
            )
            .is_err()
        );

        let limits = IniParseLimits {
            max_logical_line_bytes: 8,
            ..IniParseLimits::default()
        };
        assert!(
            parse(
                b"[s]\nk=one\n  two\n".as_slice(),
                IniProfile::PythonConfigParserV1,
                IniEncodingSelection::ProfileDefault,
                limits,
            )
            .is_err()
        );
    }
}
