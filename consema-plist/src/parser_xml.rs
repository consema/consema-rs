//! `plist.xml@1` formation (RFC 0013 §2.1, §3, §4, §8.2, §12).
//!
//! The parser reuses the frozen RFC 0012 source contract — bounded
//! [`SourceSnapshot`] creation, half-open raw-byte spans, derived decoded
//! locations, and the UTF-8/UTF-16 document-entity table (RFC 0013 §2.1) —
//! and `xmlparser 0.13.6` tokenization (RFC 0013 §13). Consema owns every
//! plist rule the backend does not provide: the strict DOCTYPE contract, the
//! `<plist version="1.0">` root contract, the value grammar (integer, real,
//! date, base64, string references), dictionary association rules, recovery,
//! and every resource limit.
//!
//! Formation is one deterministic forward pass over the decoded text.
//! Recovery follows RFC 0013 §3: non-fatal deviations from the Profile's
//! grammar form a Recovered document that retains the immutable source,
//! exhaustive piece coverage, ordered diagnostics, and every independently
//! proven construct — the lossless syntax pieces and the value elements that
//! parsed cleanly. A value element either proves (its whole subtree proves)
//! or contributes no native value: containers keep their proven entries and
//! elements, scalars fail as a unit on grammar violations, and never is a
//! closing tag or value invented to fabricate a Complete tree. The native
//! document exists exactly when the root value is provable: a `<plist>` root
//! with exactly one proven value element.
//!
//! Resource limits are enforced at the point each claim is read, before any
//! allocation, and every size arithmetic is checked (hard gate 4, RFC 0013
//! §12); a limit failure is always fatal and never masquerades as a Recovered
//! or Complete tree. Source decoding failures and impossible coordinates are
//! fatal; malformed markup and value-grammar deviations are Recovered.
//!
//! The lossless syntax index partitions every raw byte into exactly one
//! [`PlistSyntaxKind`] piece (RFC 0013 §8.2). The root open tag
//! `<plist version="1.0">` partitions as `PlistOpen` on the name,
//! `Whitespace` on the separator, `PlistVersionName` on `version`,
//! `PlistVersionValue` on `="1.0"`, and a second `PlistOpen` on the closing
//! `>`; `PlistClose` covers `</plist>`.

use crate::PlistEncodingSelection;
use crate::PlistParseLimits;
use crate::native::{
    PlistArenaError, PlistArray, PlistBoolean, PlistData, PlistDate, PlistDict, PlistDictEntry,
    PlistDocument, PlistDocumentBuilder, PlistInteger, PlistKey, PlistReal, PlistString,
    PlistValue, PlistValueRef,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BomKind, BomPolicy, DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure,
    FormationStatus, LosslessStructuralIndex, SourceEncoding, SourceLimits, SourceSnapshot, Span,
    StructuralPiece, StructuralPieceKind,
};
use std::collections::HashMap;
use std::sync::Arc;
use xmlparser::{ElementEnd, ExternalId, StrSpan, Token, Tokenizer};

/// Byte length of `<!DOCTYPE`.
const DOCTYPE_OPEN_BYTES: usize = 9;
/// Byte length of `<?xml`.
const DECLARATION_OPEN_BYTES: usize = 5;
/// Byte length of `<![CDATA[`.
const CDATA_OPEN_BYTES: usize = 9;
/// Byte length of `<!--`.
const COMMENT_OPEN_BYTES: usize = 4;
/// Exact plist DOCTYPE identifiers (RFC 0013 §4.1).
const PLIST_DOCTYPE_PUBLIC: &str = "-//Apple//DTD PLIST 1.0//EN";
const PLIST_DOCTYPE_SYSTEM: &str = "http://www.apple.com/DTDs/PropertyList-1.0.dtd";
/// Exact root version value (RFC 0013 §4.2).
const PLIST_VERSION: &str = "1.0";
/// Exact seconds between the Unix epoch and the plist epoch (RFC 0013 §4.7,
/// §5.5); mirrors the frozen native constant.
const UNIX_TO_PLIST_EPOCH_SECONDS: f64 = crate::PLIST_EPOCH_OFFSET_UNIX;

/// Lossless plist XML syntax kinds (RFC 0013 §8.2).
///
/// Every non-empty raw byte of a `plist.xml@1` source belongs to exactly one
/// ordered structural piece with one of these kinds; the set is closed by
/// RFC 0013 §8.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlistSyntaxKind {
    /// Unicode byte-order mark.
    Bom,
    /// Horizontal whitespace trivia.
    Whitespace,
    /// Line break trivia.
    LineBreak,
    /// `<?xml` declaration opening.
    DeclarationOpen,
    /// Declaration pseudo-attribute name.
    DeclarationName,
    /// Declaration pseudo-attribute value.
    DeclarationValue,
    /// `?>` declaration closing.
    DeclarationClose,
    /// `<!DOCTYPE` opening.
    DoctypeOpen,
    /// DOCTYPE content between the opening and the closing `>`.
    DoctypeBody,
    /// Closing `>` of the DOCTYPE.
    DoctypeClose,
    /// Root element name `plist` and the `>` that closes the root open tag.
    PlistOpen,
    /// Root attribute name `version`.
    PlistVersionName,
    /// Root version attribute `="1.0"`, including the equals sign, quotes,
    /// and value.
    PlistVersionValue,
    /// `</plist>` root close tag and the root's `/>` when self-closing.
    PlistClose,
    /// `<dict` open-tag name and its closing `>`.
    DictOpen,
    /// `</dict>` close tag.
    DictClose,
    /// `<key` open-tag name and its closing `>`.
    KeyOpen,
    /// `</key>` close tag.
    KeyClose,
    /// `<array` open-tag name and its closing `>`.
    ArrayOpen,
    /// `</array>` close tag.
    ArrayClose,
    /// `<string` open-tag name and its closing `>`.
    StringOpen,
    /// `</string>` close tag.
    StringClose,
    /// `<integer` open-tag name and its closing `>`.
    IntegerOpen,
    /// `</integer>` close tag.
    IntegerClose,
    /// `<real` open-tag name and its closing `>`.
    RealOpen,
    /// `</real>` close tag.
    RealClose,
    /// `<date` open-tag name and its closing `>`.
    DateOpen,
    /// `</date>` close tag.
    DateClose,
    /// `<data` open-tag name and its closing `>`.
    DataOpen,
    /// `</data>` close tag.
    DataClose,
    /// `<true/>`, `<true>`, or `</true>`.
    True,
    /// `<false/>`, `<false>`, or `</false>`.
    False,
    /// Literal character data of string and key content.
    Text,
    /// One `&name;` entity reference in string or key content.
    EntityReference,
    /// One `&#...;` character reference in string or key content.
    CharacterReference,
    /// `<![CDATA[` opening.
    CdataOpen,
    /// CDATA character data.
    CdataText,
    /// `]]>` closing.
    CdataClose,
    /// `<!--` opening.
    CommentOpen,
    /// Comment character data.
    CommentText,
    /// `-->` closing.
    CommentClose,
    /// `<?` processing-instruction opening.
    ProcessingInstructionOpen,
    /// Processing-instruction target.
    ProcessingInstructionTarget,
    /// Processing-instruction content.
    ProcessingInstructionContent,
    /// `?>` processing-instruction closing.
    ProcessingInstructionClose,
    /// Bytes not admitted by the Profile's grammar.
    ErrorRegion,
}

impl PlistSyntaxKind {
    /// Stable query/protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "bom",
            Self::Whitespace => "whitespace",
            Self::LineBreak => "line-break",
            Self::DeclarationOpen => "declaration-open",
            Self::DeclarationName => "declaration-name",
            Self::DeclarationValue => "declaration-value",
            Self::DeclarationClose => "declaration-close",
            Self::DoctypeOpen => "doctype-open",
            Self::DoctypeBody => "doctype-body",
            Self::DoctypeClose => "doctype-close",
            Self::PlistOpen => "plist-open",
            Self::PlistVersionName => "plist-version-name",
            Self::PlistVersionValue => "plist-version-value",
            Self::PlistClose => "plist-close",
            Self::DictOpen => "dict-open",
            Self::DictClose => "dict-close",
            Self::KeyOpen => "key-open",
            Self::KeyClose => "key-close",
            Self::ArrayOpen => "array-open",
            Self::ArrayClose => "array-close",
            Self::StringOpen => "string-open",
            Self::StringClose => "string-close",
            Self::IntegerOpen => "integer-open",
            Self::IntegerClose => "integer-close",
            Self::RealOpen => "real-open",
            Self::RealClose => "real-close",
            Self::DateOpen => "date-open",
            Self::DateClose => "date-close",
            Self::DataOpen => "data-open",
            Self::DataClose => "data-close",
            Self::True => "true",
            Self::False => "false",
            Self::Text => "text",
            Self::EntityReference => "entity-reference",
            Self::CharacterReference => "character-reference",
            Self::CdataOpen => "cdata-open",
            Self::CdataText => "cdata-text",
            Self::CdataClose => "cdata-close",
            Self::CommentOpen => "comment-open",
            Self::CommentText => "comment-text",
            Self::CommentClose => "comment-close",
            Self::ProcessingInstructionOpen => "processing-instruction-open",
            Self::ProcessingInstructionTarget => "processing-instruction-target",
            Self::ProcessingInstructionContent => "processing-instruction-content",
            Self::ProcessingInstructionClose => "processing-instruction-close",
            Self::ErrorRegion => "error-region",
        }
    }

    /// Resolves a stable kind name from the lossless syntax query protocol.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "bom" => Self::Bom,
            "whitespace" => Self::Whitespace,
            "line-break" => Self::LineBreak,
            "declaration-open" => Self::DeclarationOpen,
            "declaration-name" => Self::DeclarationName,
            "declaration-value" => Self::DeclarationValue,
            "declaration-close" => Self::DeclarationClose,
            "doctype-open" => Self::DoctypeOpen,
            "doctype-body" => Self::DoctypeBody,
            "doctype-close" => Self::DoctypeClose,
            "plist-open" => Self::PlistOpen,
            "plist-version-name" => Self::PlistVersionName,
            "plist-version-value" => Self::PlistVersionValue,
            "plist-close" => Self::PlistClose,
            "dict-open" => Self::DictOpen,
            "dict-close" => Self::DictClose,
            "key-open" => Self::KeyOpen,
            "key-close" => Self::KeyClose,
            "array-open" => Self::ArrayOpen,
            "array-close" => Self::ArrayClose,
            "string-open" => Self::StringOpen,
            "string-close" => Self::StringClose,
            "integer-open" => Self::IntegerOpen,
            "integer-close" => Self::IntegerClose,
            "real-open" => Self::RealOpen,
            "real-close" => Self::RealClose,
            "date-open" => Self::DateOpen,
            "date-close" => Self::DateClose,
            "data-open" => Self::DataOpen,
            "data-close" => Self::DataClose,
            "true" => Self::True,
            "false" => Self::False,
            "text" => Self::Text,
            "entity-reference" => Self::EntityReference,
            "character-reference" => Self::CharacterReference,
            "cdata-open" => Self::CdataOpen,
            "cdata-text" => Self::CdataText,
            "cdata-close" => Self::CdataClose,
            "comment-open" => Self::CommentOpen,
            "comment-text" => Self::CommentText,
            "comment-close" => Self::CommentClose,
            "processing-instruction-open" => Self::ProcessingInstructionOpen,
            "processing-instruction-target" => Self::ProcessingInstructionTarget,
            "processing-instruction-content" => Self::ProcessingInstructionContent,
            "processing-instruction-close" => Self::ProcessingInstructionClose,
            "error-region" => Self::ErrorRegion,
            _ => return None,
        })
    }
}

/// One formed `plist.xml@1` document (RFC 0013 §3).
///
/// `Complete` requires exhaustive byte coverage under the Profile's grammar
/// and every configured limit. `Recovered` retains the immutable source,
/// exhaustive piece coverage, ordered diagnostics, and every independently
/// proven construct; `document()` is `Some` exactly when the root value is
/// provable — a `<plist>` root element with exactly one proven value element.
/// The lossless syntax index and its [`PlistSyntaxKind`] kinds always exist.
#[derive(Clone, Debug)]
pub struct PlistFormedXml {
    source: Arc<SourceSnapshot>,
    /// Consumed by the M4 lossless-syntax query domain (RFC 0013 §8.2).
    #[allow(dead_code)]
    authority: DocumentAuthority,
    status: FormationStatus,
    diagnostics: Vec<Diagnostic>,
    document: Option<PlistDocument>,
    syntax: LosslessStructuralIndex,
    syntax_kinds: Arc<[PlistSyntaxKind]>,
    /// Consumed by the M4 query and edit domains for limit enforcement.
    #[allow(dead_code)]
    limits: PlistParseLimits,
}

impl PlistFormedXml {
    /// Formation status.
    #[must_use]
    pub const fn status(&self) -> FormationStatus {
        self.status
    }

    /// Immutable raw source with encoding facts.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Exact original bytes; unmodified rendering is byte-exact.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Ordered diagnostics from formation.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Native value arena, when the root value is provable.
    #[must_use]
    pub fn document(&self) -> Option<&PlistDocument> {
        self.document.as_ref()
    }

    /// Exhaustive ordered lossless piece coverage of the raw bytes.
    #[must_use]
    pub fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.syntax
    }

    /// Ordered syntax kinds, parallel to the lossless structural pieces.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[PlistSyntaxKind] {
        &self.syntax_kinds
    }

    /// Snapshot-bound identity authority for issuing query handles (M4
    /// adaptation point).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        &self.authority
    }

    /// Limits applied during formation (M4 adaptation point).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn limits(&self) -> PlistParseLimits {
        self.limits
    }
}

/// Forms one `plist.xml@1` document from raw bytes (RFC 0013 §3).
///
/// The source contract follows RFC 0013 §2.1: no-BOM source defaults to
/// UTF-8, a BOM or an explicit caller choice is evidence that never
/// contradicts the other, and only the UTF-8/UTF-16 document-entity table is
/// admitted. Formation is side-effect free: it never fetches the Apple DTD or
/// any other URI and never processes an external or parameter entity.
pub(crate) fn parse_xml(
    bytes: Arc<[u8]>,
    selection: PlistEncodingSelection,
    limits: PlistParseLimits,
) -> Result<PlistFormedXml, FatalFormationFailure> {
    let request = encoding_request(selection)?;
    let source = Arc::new(
        SourceSnapshot::from_raw(
            bytes,
            request,
            SourceLimits {
                max_raw_bytes: limits.common.max_source_bytes,
                max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
                max_decoded_scalars: limits.max_decoded_scalars,
            },
        )
        .map_err(FatalFormationFailure::source_error)?,
    );
    validate_profile_encoding(&source, selection)?;
    let decoded = source.decoded_text().ok_or_else(encoding_failure)?;
    Parser::new(Arc::clone(&source), limits).parse(decoded)
}

/// Resolves the source encoding request under the RFC 0013 §2.1 table.
fn encoding_request(
    selection: PlistEncodingSelection,
) -> Result<EncodingRequest, FatalFormationFailure> {
    match selection {
        PlistEncodingSelection::ProfileDefault => {
            let mut request = EncodingRequest::new(SourceEncoding::Utf8);
            request = request.with_bom_policy(BomPolicy::DetectUnicode);
            Ok(request)
        }
        PlistEncodingSelection::Explicit(encoding) => {
            let admitted = matches!(
                encoding,
                SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be
            );
            if !admitted {
                // UTF-32, Latin-1, Windows code pages, and other IANA
                // encodings are explicit v1 Profile exclusions (RFC 0013
                // §2.1).
                return Err(encoding_failure());
            }
            let mut request = EncodingRequest::new(SourceEncoding::Utf8);
            request = request.with_caller_override(encoding);
            Ok(request)
        }
    }
}

fn validate_profile_encoding(
    source: &SourceSnapshot,
    selection: PlistEncodingSelection,
) -> Result<(), FatalFormationFailure> {
    let facts = source.encoding_facts();
    let valid = match selection {
        PlistEncodingSelection::ProfileDefault => matches!(
            facts.selected(),
            SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be
        ),
        PlistEncodingSelection::Explicit(SourceEncoding::Utf8) => {
            facts.selected() == SourceEncoding::Utf8
        }
        PlistEncodingSelection::Explicit(SourceEncoding::Utf16Le) => {
            facts.selected() == SourceEncoding::Utf16Le && facts.bom() == Some(BomKind::Utf16Le)
        }
        PlistEncodingSelection::Explicit(SourceEncoding::Utf16Be) => {
            facts.selected() == SourceEncoding::Utf16Be && facts.bom() == Some(BomKind::Utf16Be)
        }
        PlistEncodingSelection::Explicit(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(encoding_failure())
    }
}

/// Source-encoding conflict: a fatal condition (RFC 0013 §2.1, §3).
fn encoding_failure() -> FatalFormationFailure {
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        "plist.xml.encoding@1",
        DiagnosticCategory::Encoding,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

/// Bounded ordered diagnostic recording with the house truncation marker.
struct DiagnosticSink {
    diagnostics: Vec<Diagnostic>,
    max: usize,
    occurrence: u64,
    truncated: bool,
}

impl DiagnosticSink {
    const fn new(max: usize) -> Self {
        Self {
            diagnostics: Vec::new(),
            max,
            occurrence: 0,
            truncated: false,
        }
    }

    fn push(&mut self, mut diagnostic: Diagnostic) {
        diagnostic.occurrence = self.occurrence;
        self.occurrence = self.occurrence.saturating_add(1);
        if self.diagnostics.len() < self.max {
            self.diagnostics.push(diagnostic);
        } else if !self.truncated {
            self.truncated = true;
            self.diagnostics.push(Diagnostic::new(
                "core.diagnostic.truncated@1",
                DiagnosticCategory::Resource,
                DiagnosticSeverity::Warning,
                None,
                self.occurrence,
            ));
        }
    }

    fn finish(mut self) -> Vec<Diagnostic> {
        Diagnostic::sort_deterministically(&mut self.diagnostics);
        self.diagnostics
    }
}

/// The plist element vocabulary (RFC 0013 §4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ElementKind {
    Plist,
    Dict,
    Array,
    String,
    Key,
    Integer,
    Real,
    True,
    False,
    Data,
    Date,
}

impl ElementKind {
    const fn is_scalar(self) -> bool {
        matches!(
            self,
            Self::String
                | Self::Key
                | Self::Integer
                | Self::Real
                | Self::True
                | Self::False
                | Self::Data
                | Self::Date
        )
    }

    const fn open_kind(self) -> PlistSyntaxKind {
        match self {
            Self::Plist => PlistSyntaxKind::PlistOpen,
            Self::Dict => PlistSyntaxKind::DictOpen,
            Self::Array => PlistSyntaxKind::ArrayOpen,
            Self::String => PlistSyntaxKind::StringOpen,
            Self::Key => PlistSyntaxKind::KeyOpen,
            Self::Integer => PlistSyntaxKind::IntegerOpen,
            Self::Real => PlistSyntaxKind::RealOpen,
            Self::True => PlistSyntaxKind::True,
            Self::False => PlistSyntaxKind::False,
            Self::Data => PlistSyntaxKind::DataOpen,
            Self::Date => PlistSyntaxKind::DateOpen,
        }
    }

    const fn close_kind(self) -> PlistSyntaxKind {
        match self {
            Self::Plist => PlistSyntaxKind::PlistClose,
            Self::Dict => PlistSyntaxKind::DictClose,
            Self::Array => PlistSyntaxKind::ArrayClose,
            Self::String => PlistSyntaxKind::StringClose,
            Self::Key => PlistSyntaxKind::KeyClose,
            Self::Integer => PlistSyntaxKind::IntegerClose,
            Self::Real => PlistSyntaxKind::RealClose,
            Self::True => PlistSyntaxKind::True,
            Self::False => PlistSyntaxKind::False,
            Self::Data => PlistSyntaxKind::DataClose,
            Self::Date => PlistSyntaxKind::DateClose,
        }
    }
}

/// Classifies an unqualified element name; `None` is unknown or prefixed.
fn classify_element(prefix: StrSpan<'_>, local: StrSpan<'_>) -> Option<ElementKind> {
    if !prefix.is_empty() {
        return None;
    }
    match local.as_str() {
        "plist" => Some(ElementKind::Plist),
        "dict" => Some(ElementKind::Dict),
        "array" => Some(ElementKind::Array),
        "string" => Some(ElementKind::String),
        "key" => Some(ElementKind::Key),
        "integer" => Some(ElementKind::Integer),
        "real" => Some(ElementKind::Real),
        "true" => Some(ElementKind::True),
        "false" => Some(ElementKind::False),
        "data" => Some(ElementKind::Data),
        "date" => Some(ElementKind::Date),
        _ => None,
    }
}

/// Ordered association state of one open `<dict>` (RFC 0013 §4.4).
#[derive(Clone, Debug)]
struct DictState {
    entries: Vec<PlistDictEntry>,
    groups: HashMap<PlistKey, usize>,
    pending_key: Option<PlistKey>,
    expect_value: bool,
}

/// Native value accumulation of one open frame.
#[derive(Clone, Debug)]
enum FrameValue {
    /// No native value (unknown elements, keys, and unproven positions).
    None,
    /// The `<plist>` root element; root value counting is parser state.
    Root,
    /// An open `<dict>`.
    Dict(DictState),
    /// An open `<array>`.
    Array(Vec<PlistValueRef>),
}

/// One open element frame: XML tree facts and native value accumulation.
#[derive(Clone, Debug)]
struct Frame {
    kind: Option<ElementKind>,
    name: String,
    open_start: usize,
    open_end: usize,
    /// Decoded cursor for the open-tag trivia walk.
    tag_cursor: usize,
    /// Raw start of the outermost unknown subtree; the subtree is one error
    /// region from this byte through its close tag.
    unknown_subtree_start: Option<usize>,
    value_allowed: bool,
    value: FrameValue,
    content: String,
    scalar_unproven: bool,
    root_version: Option<String>,
    self_closing: bool,
}

/// Character-data position of one text or CDATA token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextPosition {
    Outside,
    Container,
    Boolean,
    Scalar,
}

/// Literal-text normalization for native content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Normalization {
    /// XML 1.0 line-end processing: raw CR and CRLF become LF.
    Text,
    /// Line-end processing then attribute whitespace becomes one space.
    Attribute,
}

/// Formation state for one XML source.
struct Parser {
    source: Arc<SourceSnapshot>,
    authority: DocumentAuthority,
    limits: PlistParseLimits,
    sink: DiagnosticSink,
    recovered: bool,
    pieces: Vec<StructuralPiece>,
    syntax_kinds: Vec<PlistSyntaxKind>,
    stack: Vec<Frame>,
    unknown_depth: usize,
    doctype_body_start: Option<usize>,
    any_top_level: bool,
    plist_root_seen: bool,
    root_value_count: usize,
    root_value_ref: Option<PlistValueRef>,
    arena: PlistDocumentBuilder,
}

impl Parser {
    fn new(source: Arc<SourceSnapshot>, limits: PlistParseLimits) -> Self {
        Self {
            source,
            authority: DocumentAuthority::fresh(),
            limits,
            sink: DiagnosticSink::new(limits.common.max_diagnostics),
            recovered: false,
            pieces: Vec::new(),
            syntax_kinds: Vec::new(),
            stack: Vec::new(),
            unknown_depth: 0,
            doctype_body_start: None,
            any_top_level: false,
            plist_root_seen: false,
            root_value_count: 0,
            root_value_ref: None,
            arena: PlistDocumentBuilder::with_limits(limits.arena_limits()),
        }
    }

    fn parse(mut self, decoded: &str) -> Result<PlistFormedXml, FatalFormationFailure> {
        self.cover_bom()?;
        let mut tokenizer = Tokenizer::from(decoded);
        loop {
            match tokenizer.next() {
                None => break,
                Some(Ok(token)) => {
                    self.token(token, decoded)?;
                }
                Some(Err(_)) => {
                    // xmlparser jumps its stream to the end on any error, so
                    // the deterministic error region is the last byte of the
                    // current stream; every byte before it stays covered by
                    // handler pieces and gap assembly.
                    let pos = tokenizer.stream().pos();
                    let end = pos.min(decoded.len());
                    let start = end.saturating_sub(1);
                    if end > 0 {
                        self.recover_error_region(start, end)?;
                    }
                    let next = Self::find_next_markup(decoded, end);
                    match next {
                        Some(markup) => {
                            tokenizer = Tokenizer::from_fragment(decoded, markup..decoded.len());
                        }
                        None => break,
                    }
                }
            }
        }
        self.finish()
    }

    fn find_next_markup(decoded: &str, from: usize) -> Option<usize> {
        decoded[from..].find('<').map(|at| from + at)
    }

    /// Covers a leading BOM as a trivia piece; the tokenizer skips the same
    /// bytes in decoded text.
    fn cover_bom(&mut self) -> Result<(), FatalFormationFailure> {
        if let Some(bom) = self.source.encoding_facts().bom() {
            let len = match bom {
                BomKind::Utf8 => 3,
                BomKind::Utf16Le | BomKind::Utf16Be => 2,
            };
            if len > 0 {
                let span = self.span(0, len)?;
                self.push_piece(span, PlistSyntaxKind::Bom, StructuralPieceKind::Trivia)?;
            }
        }
        Ok(())
    }

    fn token(&mut self, token: Token<'_>, decoded: &str) -> Result<(), FatalFormationFailure> {
        match token {
            Token::Declaration {
                version,
                encoding,
                standalone,
                span,
            } => self.declaration(version, encoding, standalone, span),
            Token::ProcessingInstruction {
                target,
                content,
                span,
            } => self.processing_instruction(target, content, span),
            Token::Comment { text, span } => self.comment(text, span),
            Token::DtdStart {
                name,
                external_id,
                span,
            } => self.doctype_start(name, external_id, span),
            Token::EmptyDtd {
                name,
                external_id,
                span,
            } => self.doctype_empty(name, external_id, span),
            Token::EntityDeclaration { .. } => {
                // Inside the DOCTYPE body, which is one DoctypeBody piece.
                Ok(())
            }
            Token::DtdEnd { span } => self.dtd_end(span),
            Token::ElementStart {
                prefix,
                local,
                span,
            } => self.element_start(prefix, local, span),
            Token::Attribute {
                prefix,
                local,
                value,
                span,
            } => self.attribute(prefix, local, value, span, decoded),
            Token::ElementEnd { end, span } => self.element_end(end, span),
            Token::Text { text } => self.text(text),
            Token::Cdata { text, span } => self.cdata(text, span),
        }
    }

    fn declaration(
        &mut self,
        version: StrSpan<'_>,
        encoding: Option<StrSpan<'_>>,
        _standalone: Option<bool>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        if self.unknown_depth > 0 {
            return Ok(());
        }
        let open = self.raw_span_offset(span.start(), span.start() + DECLARATION_OPEN_BYTES)?;
        self.push_piece(
            open,
            PlistSyntaxKind::DeclarationOpen,
            StructuralPieceKind::Token,
        )?;
        let text = span.as_str();
        let mut rel = DECLARATION_OPEN_BYTES;
        rel = skip_declaration_spaces(text, rel);
        if text[rel..].starts_with("version") {
            let name_raw = self.raw_span_offset(span.start() + rel, span.start() + rel + 7)?;
            self.push_piece(
                name_raw,
                PlistSyntaxKind::DeclarationName,
                StructuralPieceKind::Token,
            )?;
            let value_raw = self.raw_span(version)?;
            self.push_piece(
                value_raw,
                PlistSyntaxKind::DeclarationValue,
                StructuralPieceKind::Token,
            )?;
            rel = version.end() - span.start() + 1;
        }
        if version.as_str() != "1.0" {
            self.recover(
                "plist.parse.declaration-version@1",
                DiagnosticCategory::Syntax,
                Some(self.raw_span(version)?.diagnostic_location()),
                &[("version", version.as_str().to_owned())],
            );
        }
        if let Some(encoding) = encoding {
            rel = skip_declaration_spaces(text, rel);
            if text[rel..].starts_with("encoding") {
                let name_raw = self.raw_span_offset(span.start() + rel, span.start() + rel + 8)?;
                self.push_piece(
                    name_raw,
                    PlistSyntaxKind::DeclarationName,
                    StructuralPieceKind::Token,
                )?;
                let value_raw = self.raw_span(encoding)?;
                self.push_piece(
                    value_raw,
                    PlistSyntaxKind::DeclarationValue,
                    StructuralPieceKind::Token,
                )?;
                rel = encoding.end() - span.start() + 1;
            }
            let upper = encoding.as_str().to_ascii_uppercase();
            let selected = self.source.encoding_facts().selected();
            let agrees = match selected {
                SourceEncoding::Utf8 => upper == "UTF-8",
                SourceEncoding::Utf16Le => matches!(upper.as_str(), "UTF-16" | "UTF-16LE"),
                SourceEncoding::Utf16Be => matches!(upper.as_str(), "UTF-16" | "UTF-16BE"),
                _ => false,
            };
            if !agrees {
                self.recover(
                    "plist.parse.declaration-conflict@1",
                    DiagnosticCategory::Encoding,
                    Some(self.raw_span(encoding)?.diagnostic_location()),
                    &[
                        ("declared", encoding.as_str().to_owned()),
                        ("selected", selected.as_str().to_owned()),
                    ],
                );
            }
        }
        rel = skip_declaration_spaces(text, rel);
        if text[rel..].starts_with("standalone") {
            let name_raw = self.raw_span_offset(span.start() + rel, span.start() + rel + 10)?;
            self.push_piece(
                name_raw,
                PlistSyntaxKind::DeclarationName,
                StructuralPieceKind::Token,
            )?;
            let value_span = self.standalone_value_span(span, rel + 10)?;
            if !value_span.is_empty() {
                self.push_piece(
                    value_span,
                    PlistSyntaxKind::DeclarationValue,
                    StructuralPieceKind::Token,
                )?;
            }
        }
        if text.ends_with("?>") {
            let close = self.raw_span_offset(span.end() - 2, span.end())?;
            self.push_piece(
                close,
                PlistSyntaxKind::DeclarationClose,
                StructuralPieceKind::Token,
            )?;
        }
        Ok(())
    }

    /// Locates the `standalone` value span inside the declaration text.
    fn standalone_value_span(
        &self,
        span: StrSpan<'_>,
        name_end_rel: usize,
    ) -> Result<Span, FatalFormationFailure> {
        let text = span.as_str();
        let mut rel = name_end_rel;
        rel = skip_declaration_spaces(text, rel);
        let Some(eq) = text[rel..].find('=').map(|at| rel + at) else {
            return self.raw_span_offset(span.end(), span.end());
        };
        let value_start = skip_declaration_spaces(text, eq + 1);
        let Some(quote) = text
            .as_bytes()
            .get(value_start)
            .copied()
            .filter(|byte| *byte == b'"' || *byte == b'\'')
        else {
            return self.raw_span_offset(span.end(), span.end());
        };
        let Some(value_end) = text[value_start + 1..]
            .find(quote as char)
            .map(|at| value_start + 1 + at)
        else {
            return self.raw_span_offset(span.end(), span.end());
        };
        self.raw_span_offset(span.start() + value_start + 1, span.start() + value_end)
    }

    fn processing_instruction(
        &mut self,
        target: StrSpan<'_>,
        content: Option<StrSpan<'_>>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        if self.doctype_body_start.is_some() || self.unknown_depth > 0 {
            return Ok(());
        }
        let target_raw = self.raw_span(target)?;
        if target.as_str().eq_ignore_ascii_case("xml") {
            self.recover(
                "plist.parse.pi-target@1",
                DiagnosticCategory::Syntax,
                Some(target_raw.diagnostic_location()),
                &[],
            );
        }
        let open = self.raw_span_offset(span.start(), span.start() + 2)?;
        self.push_piece(
            open,
            PlistSyntaxKind::ProcessingInstructionOpen,
            StructuralPieceKind::Trivia,
        )?;
        self.push_piece(
            target_raw,
            PlistSyntaxKind::ProcessingInstructionTarget,
            StructuralPieceKind::Trivia,
        )?;
        if let Some(content) = content {
            let content_raw = self.raw_span(content)?;
            self.push_piece(
                content_raw,
                PlistSyntaxKind::ProcessingInstructionContent,
                StructuralPieceKind::Trivia,
            )?;
        }
        let close = self.raw_span_offset(span.end().saturating_sub(2), span.end())?;
        self.push_piece(
            close,
            PlistSyntaxKind::ProcessingInstructionClose,
            StructuralPieceKind::Trivia,
        )?;
        Ok(())
    }

    fn comment(
        &mut self,
        text: StrSpan<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        if self.doctype_body_start.is_some() || self.unknown_depth > 0 {
            return Ok(());
        }
        let open = self.raw_span_offset(span.start(), span.start() + COMMENT_OPEN_BYTES)?;
        let text_raw = self.raw_span(text)?;
        let close = self.raw_span_offset(text.end(), span.end())?;
        self.push_piece(
            open,
            PlistSyntaxKind::CommentOpen,
            StructuralPieceKind::Trivia,
        )?;
        self.push_piece(
            text_raw,
            PlistSyntaxKind::CommentText,
            StructuralPieceKind::Trivia,
        )?;
        self.push_piece(
            close,
            PlistSyntaxKind::CommentClose,
            StructuralPieceKind::Trivia,
        )?;
        Ok(())
    }

    fn doctype_start(
        &mut self,
        name: StrSpan<'_>,
        external_id: Option<ExternalId<'_>>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let open = self.span(raw.start_byte(), raw.start_byte() + DOCTYPE_OPEN_BYTES)?;
        self.push_piece(
            open,
            PlistSyntaxKind::DoctypeOpen,
            StructuralPieceKind::Token,
        )?;
        self.validate_doctype(name, external_id, raw);
        self.recover(
            "plist.parse.doctype-subset@1",
            DiagnosticCategory::Syntax,
            Some(raw.diagnostic_location()),
            &[],
        );
        self.doctype_body_start = Some(raw.start_byte() + DOCTYPE_OPEN_BYTES);
        Ok(())
    }

    fn doctype_empty(
        &mut self,
        name: StrSpan<'_>,
        external_id: Option<ExternalId<'_>>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let open = self.span(raw.start_byte(), raw.start_byte() + DOCTYPE_OPEN_BYTES)?;
        self.push_piece(
            open,
            PlistSyntaxKind::DoctypeOpen,
            StructuralPieceKind::Token,
        )?;
        self.validate_doctype(name, external_id, raw);
        let body_end = raw.end_byte() - 1;
        let body = self.span(raw.start_byte() + DOCTYPE_OPEN_BYTES, body_end)?;
        self.push_piece(
            body,
            PlistSyntaxKind::DoctypeBody,
            StructuralPieceKind::Token,
        )?;
        let close = self.span(body_end, raw.end_byte())?;
        self.push_piece(
            close,
            PlistSyntaxKind::DoctypeClose,
            StructuralPieceKind::Token,
        )?;
        Ok(())
    }

    /// Validates the exact Apple plist DOCTYPE identity (RFC 0013 §4.1).
    fn validate_doctype(
        &mut self,
        name: StrSpan<'_>,
        external_id: Option<ExternalId<'_>>,
        raw: Span,
    ) {
        let identifiers_ok = matches!(
            external_id,
            Some(ExternalId::Public(pub_id, sys_id))
                if pub_id.as_str() == PLIST_DOCTYPE_PUBLIC
                    && sys_id.as_str() == PLIST_DOCTYPE_SYSTEM
        );
        if name.as_str() != "plist" || !identifiers_ok {
            let mut arguments = vec![("name".to_owned(), name.as_str().to_owned())];
            match external_id {
                Some(ExternalId::Public(pub_id, sys_id)) => {
                    arguments.push(("public".to_owned(), pub_id.as_str().to_owned()));
                    arguments.push(("system".to_owned(), sys_id.as_str().to_owned()));
                }
                Some(ExternalId::System(sys_id)) => {
                    arguments.push(("system".to_owned(), sys_id.as_str().to_owned()));
                }
                None => {}
            }
            self.recover_owned(
                "plist.parse.doctype@1",
                DiagnosticCategory::Syntax,
                Some(raw.diagnostic_location()),
                arguments,
            );
        }
    }

    fn dtd_end(&mut self, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let body_end = raw.end_byte() - 1;
        if let Some(body_start) = self.doctype_body_start.take() {
            let body = self.span(body_start, body_end)?;
            self.push_piece(
                body,
                PlistSyntaxKind::DoctypeBody,
                StructuralPieceKind::Token,
            )?;
        }
        let close = self.span(body_end, raw.end_byte())?;
        self.push_piece(
            close,
            PlistSyntaxKind::DoctypeClose,
            StructuralPieceKind::Token,
        )?;
        Ok(())
    }

    fn element_start(
        &mut self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        if self.stack.len() >= self.limits.common.max_nesting_depth {
            return Err(fatal_limit(
                "nesting-depth",
                self.stack.len() + 1,
                self.limits.common.max_nesting_depth,
            ));
        }
        let open_raw = self.raw_span(span)?;
        let kind = classify_element(prefix, local);
        let name = String::from(&span.as_str()[1..]);
        let top_level = self.stack.is_empty();
        let admitted_root = top_level && !self.plist_root_seen && kind == Some(ElementKind::Plist);
        let is_unknown = if top_level {
            !admitted_root
        } else {
            kind.is_none() || kind == Some(ElementKind::Plist)
        };
        if top_level {
            self.any_top_level = true;
        }
        let frame_value = match kind {
            Some(ElementKind::Plist) => FrameValue::Root,
            Some(ElementKind::Dict) => FrameValue::Dict(DictState {
                entries: Vec::new(),
                groups: HashMap::new(),
                pending_key: None,
                expect_value: false,
            }),
            Some(ElementKind::Array) => FrameValue::Array(Vec::new()),
            _ => FrameValue::None,
        };
        let mut value_allowed = !is_unknown;
        let mut scalar_violation = false;
        if !is_unknown {
            let parent = self.stack.last();
            let parent_kind = parent.map(|frame| frame.kind);
            let parent_allowed = parent.is_none_or(|frame| frame.value_allowed);
            let parent_expect_value = matches!(
                parent.map(|frame| &frame.value),
                Some(FrameValue::Dict(state)) if state.expect_value
            );
            let parent_scalar =
                parent.is_some_and(|frame| frame.kind.is_some_and(ElementKind::is_scalar));
            value_allowed = parent_allowed;
            match kind {
                Some(ElementKind::Plist) | None => {}
                Some(ElementKind::Key) => match parent_kind {
                    Some(Some(ElementKind::Dict)) => {
                        if parent_allowed && parent_expect_value {
                            self.recover(
                                "plist.parse.dict-missing-value@1",
                                DiagnosticCategory::Syntax,
                                Some(open_raw.diagnostic_location()),
                                &[],
                            );
                        }
                    }
                    Some(Some(ElementKind::Plist | ElementKind::Array)) => {
                        self.recover(
                            "plist.parse.key-outside-dict@1",
                            DiagnosticCategory::Syntax,
                            Some(open_raw.diagnostic_location()),
                            &[("name", name.clone())],
                        );
                    }
                    Some(Some(_)) => {
                        scalar_violation = true;
                    }
                    _ => {}
                },
                Some(ElementKind::Dict | ElementKind::Array) => {
                    if parent_scalar {
                        scalar_violation = true;
                    }
                }
                Some(_) => match parent_kind {
                    Some(Some(ElementKind::Dict)) => {
                        if parent_allowed && !parent_expect_value {
                            self.recover(
                                "plist.parse.dict-key@1",
                                DiagnosticCategory::Syntax,
                                Some(open_raw.diagnostic_location()),
                                &[("element", name.clone())],
                            );
                        }
                    }
                    Some(Some(ElementKind::Plist | ElementKind::Array)) => {}
                    Some(Some(_)) => {
                        scalar_violation = true;
                    }
                    _ => {}
                },
            }
        }
        if scalar_violation {
            self.recover(
                "plist.parse.scalar-content@1",
                DiagnosticCategory::Syntax,
                Some(open_raw.diagnostic_location()),
                &[("element", name.clone())],
            );
            if let Some(parent) = self.stack.last_mut() {
                parent.scalar_unproven = true;
            }
            value_allowed = false;
        }
        if is_unknown && self.unknown_depth == 0 {
            self.recover(
                "plist.parse.element-name@1",
                DiagnosticCategory::Syntax,
                Some(open_raw.diagnostic_location()),
                &[("name", name.clone())],
            );
        }
        if self.unknown_depth == 0 && !is_unknown {
            let kind_piece = kind.expect("known element").open_kind();
            self.push_piece(open_raw, kind_piece, StructuralPieceKind::Token)?;
        }
        let unknown_marker = if is_unknown && self.unknown_depth == 0 {
            Some(open_raw.start_byte())
        } else {
            None
        };
        self.stack.push(Frame {
            kind,
            name,
            open_start: open_raw.start_byte(),
            open_end: open_raw.end_byte(),
            tag_cursor: span.end(),
            unknown_subtree_start: unknown_marker,
            value_allowed,
            value: frame_value,
            content: String::new(),
            scalar_unproven: false,
            root_version: None,
            self_closing: false,
        });
        if is_unknown {
            self.unknown_depth += 1;
        }
        if admitted_root {
            self.plist_root_seen = true;
        }
        Ok(())
    }

    fn attribute(
        &mut self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
        value: StrSpan<'_>,
        span: StrSpan<'_>,
        decoded: &str,
    ) -> Result<(), FatalFormationFailure> {
        if self.unknown_depth > 0 {
            return Ok(());
        }
        let (tag_cursor, is_root, version_unset) = {
            let Some(frame) = self.stack.last() else {
                return Ok(());
            };
            (
                frame.tag_cursor,
                frame.kind == Some(ElementKind::Plist) && self.stack.len() == 1,
                frame.root_version.is_none(),
            )
        };
        self.push_whitespace_pieces(tag_cursor, span.start())?;
        let is_version =
            is_root && version_unset && prefix.is_empty() && local.as_str() == "version";
        let mut root_version = None;
        if is_version {
            let name_raw = self.raw_span_offset(span.start(), local.end())?;
            self.push_piece(
                name_raw,
                PlistSyntaxKind::PlistVersionName,
                StructuralPieceKind::Token,
            )?;
            let eq_at = decoded[local.end()..value.start()]
                .find('=')
                .map_or(local.end(), |at| local.end() + at);
            let value_raw = self.raw_span_offset(eq_at, value.end() + 1)?;
            self.push_piece(
                value_raw,
                PlistSyntaxKind::PlistVersionValue,
                StructuralPieceKind::Token,
            )?;
            let normalized = self.normalize_attribute_value(value)?;
            if normalized != PLIST_VERSION {
                self.recover(
                    "plist.parse.root-version@1",
                    DiagnosticCategory::Syntax,
                    Some(value_raw.diagnostic_location()),
                    &[("version", normalized.clone())],
                );
            }
            root_version = Some(normalized);
        } else {
            let attr_raw = self.raw_span_offset(span.start(), value.end() + 1)?;
            self.push_piece(
                attr_raw,
                PlistSyntaxKind::ErrorRegion,
                StructuralPieceKind::ErrorRegion,
            )?;
            let code = if is_root {
                "plist.parse.root-attribute@1"
            } else {
                "plist.parse.element-attribute@1"
            };
            let name_text = if prefix.is_empty() {
                local.as_str().to_owned()
            } else {
                format!("{prefix}:{local}")
            };
            self.recover(
                code,
                DiagnosticCategory::Syntax,
                Some(attr_raw.diagnostic_location()),
                &[("name", name_text)],
            );
        }
        if let Some(frame) = self.stack.last_mut() {
            frame.tag_cursor = value.end() + 1;
            if root_version.is_some() {
                frame.root_version = root_version;
            }
        }
        Ok(())
    }

    /// Normalized root version value: references resolve and literal
    /// whitespace collapses to one space (XML attribute normalization).
    fn normalize_attribute_value(
        &mut self,
        value: StrSpan<'_>,
    ) -> Result<String, FatalFormationFailure> {
        self.resolve_fragments(value, Normalization::Attribute, false)
    }

    fn element_end(
        &mut self,
        end: ElementEnd<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        match end {
            ElementEnd::Open => self.open_tag_end(span),
            ElementEnd::Empty => self.empty_tag_end(span),
            ElementEnd::Close(_, _) => self.close_tag_end(span),
        }
    }

    /// `>` of an open tag: separator walk, tag-end piece, root finalize.
    fn open_tag_end(&mut self, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let (tag_cursor, is_plist, has_version) = {
            let Some(frame) = self.stack.last() else {
                return Ok(());
            };
            (
                frame.tag_cursor,
                frame.kind == Some(ElementKind::Plist) && self.stack.len() == 1,
                frame.root_version.is_some(),
            )
        };
        if self.unknown_depth == 0 {
            self.push_whitespace_pieces(tag_cursor, span.start())?;
            let raw = self.raw_span(span)?;
            if let Some(frame) = self.stack.last() {
                let kind_piece = frame
                    .kind
                    .map_or(PlistSyntaxKind::ErrorRegion, ElementKind::open_kind);
                self.push_piece(raw, kind_piece, StructuralPieceKind::Token)?;
            }
        }
        if is_plist && !has_version {
            let raw = self.raw_span(span)?;
            self.recover(
                "plist.parse.root-version@1",
                DiagnosticCategory::Syntax,
                Some(raw.diagnostic_location()),
                &[("version", String::from("<missing>"))],
            );
        }
        let raw_end = if self.unknown_depth == 0 {
            Some(self.raw_span(span)?.end_byte())
        } else {
            None
        };
        if let Some(frame) = self.stack.last_mut() {
            frame.tag_cursor = span.end();
            if let Some(raw_end) = raw_end {
                frame.open_end = raw_end;
            }
        }
        Ok(())
    }

    /// `/>` of a self-closing tag: separator walk, tag-end piece, root
    /// finalize, then the frame closes immediately.
    fn empty_tag_end(&mut self, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let (tag_cursor, is_plist, has_version) = {
            let Some(frame) = self.stack.last() else {
                return Ok(());
            };
            (
                frame.tag_cursor,
                frame.kind == Some(ElementKind::Plist) && self.stack.len() == 1,
                frame.root_version.is_some(),
            )
        };
        if self.unknown_depth == 0 {
            self.push_whitespace_pieces(tag_cursor, span.start())?;
            let raw = self.raw_span(span)?;
            if let Some(frame) = self.stack.last() {
                let kind_piece = frame
                    .kind
                    .map_or(PlistSyntaxKind::ErrorRegion, ElementKind::close_kind);
                self.push_piece(raw, kind_piece, StructuralPieceKind::Token)?;
            }
        }
        if is_plist && !has_version {
            let raw = self.raw_span(span)?;
            self.recover(
                "plist.parse.root-version@1",
                DiagnosticCategory::Syntax,
                Some(raw.diagnostic_location()),
                &[("version", String::from("<missing>"))],
            );
        }
        let raw = self.raw_span(span)?;
        if let Some(frame) = self.stack.last_mut() {
            frame.self_closing = true;
            if self.unknown_depth == 0 {
                frame.open_end = raw.end_byte();
            }
        }
        self.close_frame(raw)
    }

    /// `</name>`: name matching, one close-tag piece, then the frame closes.
    fn close_tag_end(&mut self, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let close_name = String::from(&span.as_str()[2..span.as_str().len() - 1]);
        if let Some(frame) = self.stack.last() {
            if frame.name != close_name {
                self.recover(
                    "plist.parse.mismatched-end-tag@1",
                    DiagnosticCategory::Syntax,
                    Some(raw.diagnostic_location()),
                    &[
                        ("expected", frame.name.clone()),
                        ("found", close_name.clone()),
                    ],
                );
            }
        }
        if self.unknown_depth == 0 {
            if let Some(frame) = self.stack.last() {
                let kind_piece = frame
                    .kind
                    .map_or(PlistSyntaxKind::ErrorRegion, ElementKind::close_kind);
                self.push_piece(raw, kind_piece, StructuralPieceKind::Token)?;
            }
        }
        self.close_frame(raw)
    }

    fn close_frame(&mut self, end_span: Span) -> Result<(), FatalFormationFailure> {
        let Some(mut frame) = self.stack.pop() else {
            self.recover(
                "plist.parse.extra-end-tag@1",
                DiagnosticCategory::Syntax,
                Some(end_span.diagnostic_location()),
                &[],
            );
            return Ok(());
        };
        if let Some(start) = frame.unknown_subtree_start {
            let span = self.span(start, end_span.end_byte())?;
            self.push_piece(
                span,
                PlistSyntaxKind::ErrorRegion,
                StructuralPieceKind::ErrorRegion,
            )?;
        }
        if frame.kind.is_none() {
            self.unknown_depth -= 1;
            return Ok(());
        }
        let limits = self.limits;
        let kind = frame.kind.expect("known frame");
        if kind == ElementKind::Key {
            let units: Vec<u16> = frame.content.encode_utf16().collect();
            if units.len() > limits.max_string_code_units {
                return Err(fatal_limit(
                    "string-code-units",
                    units.len(),
                    limits.max_string_code_units,
                ));
            }
            if frame.value_allowed {
                let pending = if frame.scalar_unproven {
                    None
                } else {
                    Some(PlistKey::from_string(PlistString::from_code_units(units)))
                };
                if let Some(parent) = self.stack.last_mut() {
                    if parent.value_allowed {
                        if let FrameValue::Dict(state) = &mut parent.value {
                            state.pending_key = pending;
                            state.expect_value = true;
                        }
                    }
                }
            }
            return Ok(());
        }
        let value_ref = if frame.value_allowed {
            self.build_value(&mut frame, end_span)?
        } else {
            None
        };
        let mut missing_value = false;
        {
            let Some(parent) = self.stack.last_mut() else {
                return Ok(());
            };
            match &mut parent.value {
                FrameValue::Root => {
                    self.root_value_count += 1;
                    if value_ref.is_some() && self.root_value_ref.is_none() {
                        self.root_value_ref = value_ref;
                    }
                }
                FrameValue::Dict(state) => {
                    if state.expect_value {
                        state.expect_value = false;
                        match state.pending_key.take() {
                            Some(key) => match value_ref {
                                Some(value_ref) => {
                                    let group = state.groups.entry(key.clone()).or_insert(0);
                                    *group = checked_add(*group, 1)?;
                                    if *group > limits.max_duplicate_key_group_members {
                                        return Err(fatal_limit(
                                            "duplicate-key-group",
                                            *group,
                                            limits.max_duplicate_key_group_members,
                                        ));
                                    }
                                    if state.entries.len() >= limits.max_dict_entries {
                                        return Err(fatal_limit(
                                            "dict-entries",
                                            state.entries.len() + 1,
                                            limits.max_dict_entries,
                                        ));
                                    }
                                    state.entries.push(PlistDictEntry::new(key, value_ref));
                                }
                                None => missing_value = true,
                            },
                            None => missing_value = true,
                        }
                    }
                }
                FrameValue::Array(elements) => {
                    if let Some(value_ref) = value_ref {
                        if elements.len() >= limits.max_array_elements {
                            return Err(fatal_limit(
                                "array-elements",
                                elements.len() + 1,
                                limits.max_array_elements,
                            ));
                        }
                        elements.push(value_ref);
                    }
                }
                FrameValue::None => {}
            }
        }
        if missing_value {
            self.recover(
                "plist.parse.dict-missing-value@1",
                DiagnosticCategory::Syntax,
                Some(end_span.diagnostic_location()),
                &[],
            );
        }
        Ok(())
    }

    /// Parses one closing element's native value and adds it to the arena.
    fn build_value(
        &mut self,
        frame: &mut Frame,
        close_span: Span,
    ) -> Result<Option<PlistValueRef>, FatalFormationFailure> {
        let limits = self.limits;
        let value = match frame.kind {
            Some(ElementKind::Dict) => {
                if let FrameValue::Dict(state) = &mut frame.value {
                    if state.expect_value {
                        self.recover(
                            "plist.parse.dict-missing-value@1",
                            DiagnosticCategory::Syntax,
                            Some(close_span.diagnostic_location()),
                            &[],
                        );
                    }
                    Some(PlistValue::Dict(PlistDict::from_entries(std::mem::take(
                        &mut state.entries,
                    ))))
                } else {
                    return Err(internal_failure());
                }
            }
            Some(ElementKind::Array) => {
                if let FrameValue::Array(elements) = &mut frame.value {
                    Some(PlistValue::Array(PlistArray::from_elements(
                        std::mem::take(elements),
                    )))
                } else {
                    return Err(internal_failure());
                }
            }
            Some(ElementKind::String | ElementKind::Key) => {
                if frame.scalar_unproven {
                    return Ok(None);
                }
                let units: Vec<u16> = frame.content.encode_utf16().collect();
                if units.len() > limits.max_string_code_units {
                    return Err(fatal_limit(
                        "string-code-units",
                        units.len(),
                        limits.max_string_code_units,
                    ));
                }
                Some(PlistValue::String(PlistString::from_code_units(units)))
            }
            Some(ElementKind::Integer) => {
                if frame.scalar_unproven {
                    return Ok(None);
                }
                if frame.content.is_empty() {
                    self.recover(
                        "plist.parse.empty-value@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[("element", String::from("integer"))],
                    );
                    return Ok(None);
                }
                if let Ok(value) = parse_integer(&frame.content) {
                    Some(PlistValue::Integer(PlistInteger::new(value)))
                } else {
                    self.recover(
                        "plist.parse.integer@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[],
                    );
                    None
                }
            }
            Some(ElementKind::Real) => {
                if frame.scalar_unproven {
                    return Ok(None);
                }
                if frame.content.is_empty() {
                    self.recover(
                        "plist.parse.empty-value@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[("element", String::from("real"))],
                    );
                    return Ok(None);
                }
                if let Ok(value) = parse_real(&frame.content) {
                    Some(PlistValue::Real(PlistReal::double(value)))
                } else {
                    self.recover(
                        "plist.parse.real@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[],
                    );
                    None
                }
            }
            Some(ElementKind::Date) => {
                if frame.scalar_unproven {
                    return Ok(None);
                }
                if frame.content.is_empty() {
                    self.recover(
                        "plist.parse.empty-value@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[("element", String::from("date"))],
                    );
                    return Ok(None);
                }
                if let Ok(seconds) = parse_date(&frame.content) {
                    match PlistDate::from_seconds(seconds) {
                        Ok(date) => Some(PlistValue::Date(date)),
                        Err(_) => return Err(internal_failure()),
                    }
                } else {
                    self.recover(
                        "plist.parse.date@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[],
                    );
                    None
                }
            }
            Some(ElementKind::Data) => {
                if frame.content.is_empty() {
                    if frame.self_closing {
                        self.recover(
                            "plist.parse.empty-value@1",
                            DiagnosticCategory::Syntax,
                            Some(close_span.diagnostic_location()),
                            &[("element", String::from("data"))],
                        );
                        return Ok(None);
                    }
                    return Ok(Some(
                        self.arena_add(PlistValue::Data(PlistData::from_bytes(Vec::new())))?,
                    ));
                }
                if frame.scalar_unproven {
                    return Ok(None);
                }
                if let Ok(bytes) = decode_base64(&frame.content) {
                    if bytes.len() > limits.max_data_bytes {
                        return Err(fatal_limit(
                            "data-bytes",
                            bytes.len(),
                            limits.max_data_bytes,
                        ));
                    }
                    Some(PlistValue::Data(PlistData::from_bytes(bytes)))
                } else {
                    self.recover(
                        "plist.parse.data@1",
                        DiagnosticCategory::Syntax,
                        Some(close_span.diagnostic_location()),
                        &[],
                    );
                    None
                }
            }
            Some(ElementKind::True | ElementKind::False) => {
                if frame.scalar_unproven {
                    return Ok(None);
                }
                Some(PlistValue::Boolean(PlistBoolean::new(
                    frame.kind == Some(ElementKind::True),
                )))
            }
            Some(ElementKind::Plist) | None => return Ok(None),
        };
        match value {
            Some(value) => Ok(Some(self.arena_add(value)?)),
            None => Ok(None),
        }
    }

    fn arena_add(&mut self, value: PlistValue) -> Result<PlistValueRef, FatalFormationFailure> {
        match self.arena.add(value) {
            Ok(reference) => Ok(reference),
            Err(PlistArenaError::ObjectLimitExceeded { limit }) => {
                Err(fatal_limit("object-count", self.arena.node_count(), limit))
            }
            Err(_) => Err(internal_failure()),
        }
    }

    fn text(&mut self, text: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        if self.unknown_depth > 0 {
            return Ok(());
        }
        let position = self.text_position();
        match position {
            TextPosition::Outside | TextPosition::Container => {
                if text.as_str().chars().all(is_ws_char) {
                    self.push_whitespace_pieces(text.start(), text.end())?;
                } else {
                    let raw = self.raw_span(text)?;
                    self.push_piece(
                        raw,
                        PlistSyntaxKind::ErrorRegion,
                        StructuralPieceKind::ErrorRegion,
                    )?;
                    self.recover(
                        "plist.parse.text-outside-value@1",
                        DiagnosticCategory::Syntax,
                        Some(raw.diagnostic_location()),
                        &[],
                    );
                }
            }
            TextPosition::Boolean => {
                if text.as_str().chars().all(is_ws_char) {
                    self.push_whitespace_pieces(text.start(), text.end())?;
                } else {
                    let raw = self.raw_span(text)?;
                    self.push_piece(
                        raw,
                        PlistSyntaxKind::ErrorRegion,
                        StructuralPieceKind::ErrorRegion,
                    )?;
                    self.recover(
                        "plist.parse.boolean-content@1",
                        DiagnosticCategory::Syntax,
                        Some(raw.diagnostic_location()),
                        &[],
                    );
                    if let Some(frame) = self.stack.last_mut() {
                        frame.scalar_unproven = true;
                    }
                }
            }
            TextPosition::Scalar => {
                let resolved = self.resolve_fragments(text, Normalization::Text, true)?;
                if let Some(frame) = self.stack.last_mut() {
                    frame.content.push_str(&resolved);
                }
            }
        }
        Ok(())
    }

    fn cdata(&mut self, text: StrSpan<'_>, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        if self.unknown_depth > 0 {
            return Ok(());
        }
        let position = self.text_position();
        match position {
            TextPosition::Outside | TextPosition::Container => {
                let raw = self.raw_span(span)?;
                self.push_piece(
                    raw,
                    PlistSyntaxKind::ErrorRegion,
                    StructuralPieceKind::ErrorRegion,
                )?;
                self.recover(
                    "plist.parse.text-outside-value@1",
                    DiagnosticCategory::Syntax,
                    Some(raw.diagnostic_location()),
                    &[],
                );
            }
            TextPosition::Boolean => {
                let raw = self.raw_span(span)?;
                self.push_piece(
                    raw,
                    PlistSyntaxKind::ErrorRegion,
                    StructuralPieceKind::ErrorRegion,
                )?;
                self.recover(
                    "plist.parse.boolean-content@1",
                    DiagnosticCategory::Syntax,
                    Some(raw.diagnostic_location()),
                    &[],
                );
                if let Some(frame) = self.stack.last_mut() {
                    frame.scalar_unproven = true;
                }
            }
            TextPosition::Scalar => {
                let open = self.raw_span_offset(span.start(), span.start() + CDATA_OPEN_BYTES)?;
                let text_raw = self.raw_span(text)?;
                let close = self.raw_span_offset(text.end(), span.end())?;
                self.push_piece(open, PlistSyntaxKind::CdataOpen, StructuralPieceKind::Token)?;
                self.push_piece(
                    text_raw,
                    PlistSyntaxKind::CdataText,
                    StructuralPieceKind::Token,
                )?;
                self.push_piece(
                    close,
                    PlistSyntaxKind::CdataClose,
                    StructuralPieceKind::Token,
                )?;
                let mut normalized = String::with_capacity(text.as_str().len());
                append_normalized(&mut normalized, text.as_str(), Normalization::Text);
                if let Some(frame) = self.stack.last_mut() {
                    frame.content.push_str(&normalized);
                }
            }
        }
        Ok(())
    }

    fn text_position(&self) -> TextPosition {
        match self.stack.last().map(|frame| frame.kind) {
            Some(Some(ElementKind::Plist | ElementKind::Dict | ElementKind::Array)) => {
                TextPosition::Container
            }
            Some(Some(ElementKind::True | ElementKind::False)) => TextPosition::Boolean,
            Some(Some(_)) => TextPosition::Scalar,
            _ => TextPosition::Outside,
        }
    }

    /// Splits one decoded whitespace run into Text/CharacterReference/
    /// EntityReference pieces and returns the resolved normalized content.
    ///
    /// Failing references resolve to nothing and publish a diagnostic; the
    /// remaining proven fragments still form the native text, following the
    /// RFC 0012 reference-recovery precedent.
    fn resolve_fragments(
        &mut self,
        span: StrSpan<'_>,
        mode: Normalization,
        emit_pieces: bool,
    ) -> Result<String, FatalFormationFailure> {
        let bytes = span.as_str();
        let mut content = String::with_capacity(bytes.len());
        if !bytes.contains('&') {
            if emit_pieces {
                let raw = self.raw_span(span)?;
                self.push_piece(raw, PlistSyntaxKind::Text, StructuralPieceKind::Token)?;
            }
            append_normalized(&mut content, bytes, mode);
            return Ok(content);
        }
        let mut cursor = 0usize;
        let mut index = 0usize;
        while index < bytes.len() {
            let Some(relative) = bytes[index..].find('&') else {
                break;
            };
            let at = index + relative;
            if at > cursor {
                if emit_pieces {
                    let raw = self.raw_span_offset(span.start() + cursor, span.start() + at)?;
                    self.push_piece(raw, PlistSyntaxKind::Text, StructuralPieceKind::Token)?;
                }
                append_normalized(&mut content, &bytes[cursor..at], mode);
            }
            let semi = bytes[at + 1..].find(';').map(|semi| at + 1 + semi);
            let Some(semi) = semi else {
                // Unterminated reference: recover and keep the rest literal.
                let raw = self.raw_span_offset(span.start() + at, span.end())?;
                self.recover(
                    "plist.parse.reference@1",
                    DiagnosticCategory::Syntax,
                    Some(raw.diagnostic_location()),
                    &[],
                );
                if emit_pieces {
                    self.push_piece(raw, PlistSyntaxKind::Text, StructuralPieceKind::Token)?;
                }
                append_normalized(&mut content, &bytes[at..], mode);
                return Ok(content);
            };
            let body = &bytes[at + 1..semi];
            let ref_raw = self.raw_span_offset(span.start() + at, span.start() + semi + 1)?;
            if let Some(resolved) = self.resolve_reference(body, ref_raw) {
                if emit_pieces {
                    let kind = if body.starts_with('#') {
                        PlistSyntaxKind::CharacterReference
                    } else {
                        PlistSyntaxKind::EntityReference
                    };
                    self.push_piece(ref_raw, kind, StructuralPieceKind::Token)?;
                }
                content.push(resolved);
            }
            cursor = semi + 1;
            index = semi + 1;
        }
        if cursor < bytes.len() {
            if emit_pieces {
                let raw = self.raw_span_offset(span.start() + cursor, span.end())?;
                self.push_piece(raw, PlistSyntaxKind::Text, StructuralPieceKind::Token)?;
            }
            append_normalized(&mut content, &bytes[cursor..], mode);
        }
        Ok(content)
    }

    /// Resolves one `&…;` reference body; `None` is a recovered failure that
    /// contributes nothing to the native text.
    fn resolve_reference(&mut self, body: &str, raw: Span) -> Option<char> {
        if let Some(digits) = body.strip_prefix('#') {
            let (is_hex, digits) = match digits
                .strip_prefix('x')
                .or_else(|| digits.strip_prefix('X'))
            {
                Some(hex) => (true, hex),
                None => (false, digits),
            };
            let valid = if is_hex {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            };
            let value = if valid {
                u32::from_str_radix(digits, if is_hex { 16 } else { 10 }).ok()
            } else {
                None
            };
            let resolved = value.and_then(char::from_u32).filter(|c| is_xml_char(*c));
            if let Some(resolved) = resolved {
                Some(resolved)
            } else {
                self.recover(
                    "plist.parse.reference@1",
                    DiagnosticCategory::Syntax,
                    Some(raw.diagnostic_location()),
                    &[],
                );
                None
            }
        } else if body.is_empty() {
            // `&;` has no entity name and is not a valid reference.
            self.recover(
                "plist.parse.reference@1",
                DiagnosticCategory::Syntax,
                Some(raw.diagnostic_location()),
                &[],
            );
            None
        } else {
            let value = match body {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "apos" => Some('\''),
                "quot" => Some('"'),
                _ => None,
            };
            if let Some(value) = value {
                Some(value)
            } else {
                self.recover(
                    "plist.parse.entity@1",
                    DiagnosticCategory::Conformance,
                    Some(raw.diagnostic_location()),
                    &[("name", body.to_owned())],
                );
                None
            }
        }
    }

    /// Splits one decoded whitespace-only run into Whitespace and LineBreak
    /// trivia pieces; defensive non-whitespace bytes become error regions.
    fn push_whitespace_pieces(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<(), FatalFormationFailure> {
        let decoded = self.source.decoded_text().ok_or_else(encoding_failure)?;
        let bytes = decoded.as_bytes();
        let mut runs: Vec<(usize, usize, PlistSyntaxKind, StructuralPieceKind)> = Vec::new();
        let mut cursor = start;
        while cursor < end {
            let byte = bytes[cursor];
            if !matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                // Defensive: the tokenizer guarantees whitespace in these
                // spans; an unproven byte becomes an error region.
                let run_start = cursor;
                while cursor < end && !matches!(bytes[cursor], b' ' | b'\t' | b'\n' | b'\r') {
                    cursor += 1;
                }
                runs.push((
                    run_start,
                    cursor,
                    PlistSyntaxKind::ErrorRegion,
                    StructuralPieceKind::ErrorRegion,
                ));
                continue;
            }
            let line_break = matches!(byte, b'\n' | b'\r');
            let run_start = cursor;
            cursor += if byte == b'\r' && cursor + 1 < end && bytes[cursor + 1] == b'\n' {
                2
            } else {
                1
            };
            while cursor < end && matches!(bytes[cursor], b'\n' | b'\r') == line_break {
                cursor += 1;
            }
            runs.push((
                run_start,
                cursor,
                if line_break {
                    PlistSyntaxKind::LineBreak
                } else {
                    PlistSyntaxKind::Whitespace
                },
                StructuralPieceKind::Trivia,
            ));
        }
        for (run_start, run_end, kind, structural) in runs {
            let raw = self.raw_span_offset(run_start, run_end)?;
            self.push_piece(raw, kind, structural)?;
        }
        Ok(())
    }

    fn recover_error_region(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.recovered = true;
        let raw_start = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(start))
            .map_err(|_| coordinates_failure())?;
        let raw_end = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(end))
            .map_err(|_| coordinates_failure())?;
        let span = self.span(raw_start, raw_end)?;
        if self.unknown_depth == 0 {
            self.push_piece(
                span,
                PlistSyntaxKind::ErrorRegion,
                StructuralPieceKind::ErrorRegion,
            )?;
        }
        self.recover(
            "plist.parse.well-formedness@1",
            DiagnosticCategory::Syntax,
            Some(span.diagnostic_location()),
            &[],
        );
        Ok(())
    }

    fn finish(mut self) -> Result<PlistFormedXml, FatalFormationFailure> {
        let unclosed = self.stack.last().map(|frame| {
            (
                frame.name.clone(),
                self.span(frame.open_start, frame.open_end).ok(),
            )
        });
        if let Some((unclosed_name, unclosed_span)) = unclosed {
            self.recover(
                "plist.parse.unclosed-element@1",
                DiagnosticCategory::Syntax,
                unclosed_span.map(Span::diagnostic_location),
                &[("element", unclosed_name)],
            );
        }
        let unknown_tail = self
            .stack
            .iter()
            .find_map(|frame| frame.unknown_subtree_start);
        if let Some(start) = unknown_tail {
            let span = self.span(start, self.source.len())?;
            self.push_piece(
                span,
                PlistSyntaxKind::ErrorRegion,
                StructuralPieceKind::ErrorRegion,
            )?;
        }
        if !self.any_top_level {
            self.recover(
                "plist.parse.missing-root@1",
                DiagnosticCategory::Syntax,
                None,
                &[],
            );
        }
        let document = if self.plist_root_seen {
            match self.root_value_count {
                0 => {
                    self.recover(
                        "plist.parse.root-value-count@1",
                        DiagnosticCategory::Syntax,
                        None,
                        &[("count", String::from("0"))],
                    );
                    None
                }
                1 => match self.root_value_ref {
                    Some(root) => {
                        let arena = std::mem::take(&mut self.arena);
                        match arena.build(root) {
                            Ok(document) => Some(document),
                            Err(PlistArenaError::ContainerDepthLimitExceeded { node, limit }) => {
                                return Err(fatal_limit("container-depth", node.index(), limit));
                            }
                            Err(_) => return Err(internal_failure()),
                        }
                    }
                    None => None,
                },
                count => {
                    self.recover(
                        "plist.parse.root-value-count@1",
                        DiagnosticCategory::Syntax,
                        None,
                        &[("count", count.to_string())],
                    );
                    None
                }
            }
        } else {
            None
        };
        let status = if self.recovered {
            FormationStatus::Recovered
        } else {
            FormationStatus::Complete
        };
        let source_len = self.source.len();
        // Pair every piece with its kind before any ordering, so sorting can
        // never desynchronize the two parallel arrays.
        let mut paired: Vec<(StructuralPiece, PlistSyntaxKind)> = std::mem::take(&mut self.pieces)
            .into_iter()
            .zip(std::mem::take(&mut self.syntax_kinds))
            .collect();
        paired.sort_by_key(|(piece, _)| piece.span().start_byte());
        let mut final_pieces = Vec::with_capacity(paired.len() + 8);
        let mut final_kinds = Vec::with_capacity(paired.len() + 8);
        let mut next = 0usize;
        for (piece, kind) in paired {
            let start = piece.span().start_byte();
            if start > next {
                let gap = self.span(next, start)?;
                if self.recovered {
                    self.push_piece(
                        gap,
                        PlistSyntaxKind::ErrorRegion,
                        StructuralPieceKind::ErrorRegion,
                    )?;
                } else {
                    self.push_piece(
                        gap,
                        PlistSyntaxKind::Whitespace,
                        StructuralPieceKind::Trivia,
                    )?;
                }
            }
            next = piece.span().end_byte();
            final_pieces.push(piece);
            final_kinds.push(kind);
        }
        if next < source_len {
            let gap = self.span(next, source_len)?;
            if self.recovered {
                self.push_piece(
                    gap,
                    PlistSyntaxKind::ErrorRegion,
                    StructuralPieceKind::ErrorRegion,
                )?;
            } else {
                self.push_piece(
                    gap,
                    PlistSyntaxKind::Whitespace,
                    StructuralPieceKind::Trivia,
                )?;
            }
        }
        // Gap pieces were pushed in increasing offset order; append them to
        // the final arrays, then pair and sort the complete set once.
        for (piece, kind) in std::mem::take(&mut self.pieces)
            .into_iter()
            .zip(std::mem::take(&mut self.syntax_kinds))
        {
            final_pieces.push(piece);
            final_kinds.push(kind);
        }
        let mut paired: Vec<(StructuralPiece, PlistSyntaxKind)> =
            final_pieces.into_iter().zip(final_kinds).collect();
        paired.sort_by_key(|(piece, _)| piece.span().start_byte());
        let mut structural = Vec::with_capacity(paired.len());
        let mut paired_kinds = Vec::with_capacity(paired.len());
        for (piece, kind) in &paired {
            structural.push(*piece);
            paired_kinds.push(*kind);
        }
        let error_regions = structural
            .iter()
            .filter(|piece| piece.kind() == StructuralPieceKind::ErrorRegion)
            .count();
        if error_regions > self.limits.max_recovery_regions {
            return Err(fatal_limit(
                "recovery-regions",
                error_regions,
                self.limits.max_recovery_regions,
            ));
        }
        let index = LosslessStructuralIndex::new(self.authority.identity(), source_len, structural)
            .map_err(|_| coverage_failure())?;
        Ok(PlistFormedXml {
            source: self.source,
            authority: self.authority,
            status,
            diagnostics: self.sink.finish(),
            document,
            syntax: index,
            syntax_kinds: Arc::from(paired_kinds),
            limits: self.limits,
        })
    }

    /// Records one recovery diagnostic and marks the parse Recovered.
    fn recover(
        &mut self,
        code: &'static str,
        category: DiagnosticCategory,
        location: Option<DiagnosticLocation>,
        arguments: &[(&'static str, String)],
    ) {
        self.recovered = true;
        let mut diagnostic =
            Diagnostic::new(code, category, DiagnosticSeverity::Error, location, 0);
        for (name, value) in arguments {
            diagnostic
                .arguments
                .insert((*name).to_owned(), value.clone());
        }
        self.sink.push(diagnostic);
    }

    /// Records a recovery diagnostic with owned argument pairs.
    fn recover_owned(
        &mut self,
        code: &'static str,
        category: DiagnosticCategory,
        location: Option<DiagnosticLocation>,
        arguments: Vec<(String, String)>,
    ) {
        self.recovered = true;
        let mut diagnostic =
            Diagnostic::new(code, category, DiagnosticSeverity::Error, location, 0);
        for (name, value) in arguments {
            diagnostic.arguments.insert(name, value);
        }
        self.sink.push(diagnostic);
    }

    fn raw_span_offset(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        let start_raw = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(start))
            .map_err(|_| coordinates_failure())?;
        let end_raw = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(end))
            .map_err(|_| coordinates_failure())?;
        self.span(start_raw, end_raw)
    }

    fn raw_span(&self, span: StrSpan<'_>) -> Result<Span, FatalFormationFailure> {
        self.raw_span_offset(span.start(), span.end())
    }

    fn span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        self.authority
            .span(start, end)
            .map_err(|_| coverage_failure())
    }

    fn push_piece(
        &mut self,
        span: Span,
        kind: PlistSyntaxKind,
        structural: StructuralPieceKind,
    ) -> Result<(), FatalFormationFailure> {
        if self.pieces.len() >= self.limits.max_syntax_pieces {
            return Err(fatal_limit(
                "syntax-pieces",
                self.pieces.len(),
                self.limits.max_syntax_pieces,
            ));
        }
        self.pieces.push(StructuralPiece::new(span, structural));
        self.syntax_kinds.push(kind);
        Ok(())
    }
}

/// Skips XML declaration spaces (ASCII ` `, `\t`, `\n`, `\r`) forward.
fn skip_declaration_spaces(text: &str, mut rel: usize) -> usize {
    while let Some(byte) = text.as_bytes().get(rel).copied() {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            rel += 1;
        } else {
            break;
        }
    }
    rel
}

const fn is_ws_char(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

const fn is_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Appends literal text with the requested normalization (RFC 0013 §4.9 and
/// XML 1.0 attribute normalization).
fn append_normalized(content: &mut String, text: &str, mode: Normalization) {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let c = if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            '\n'
        } else {
            c
        };
        content.push(match mode {
            Normalization::Text => c,
            Normalization::Attribute => {
                if matches!(c, ' ' | '\t' | '\n') {
                    ' '
                } else {
                    c
                }
            }
        });
    }
}

/// XML 1.0 `Char` production.
fn is_xml_char(c: char) -> bool {
    c == '\t'
        || c == '\n'
        || c == '\r'
        || ('\u{20}'..='\u{D7FF}').contains(&c)
        || ('\u{E000}'..='\u{FFFD}').contains(&c)
        || ('\u{10000}'..='\u{10FFFF}').contains(&c)
}

/// Signed 64-bit integer grammar (RFC 0013 §4.5):
/// `S*(-|+)?S*[0-9]+` and `S*(-|+)?S*0[xX][0-9a-fA-F]+`.
fn parse_integer(content: &str) -> Result<i64, ()> {
    let bytes = content.trim_matches(is_ws_char).as_bytes();
    let mut index = 0usize;
    let negative = match bytes.first() {
        Some(b'-') => {
            index = 1;
            true
        }
        Some(b'+') => {
            index = 1;
            false
        }
        _ => false,
    };
    while index < bytes.len() && is_ws_byte(bytes[index]) {
        index += 1;
    }
    let (hex, start) =
        if bytes.get(index) == Some(&b'0') && matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
            (true, index + 2)
        } else {
            (false, index)
        };
    let mut end = start;
    while end < bytes.len()
        && if hex {
            bytes[end].is_ascii_hexdigit()
        } else {
            bytes[end].is_ascii_digit()
        }
    {
        end += 1;
    }
    if end == start {
        return Err(());
    }
    while end < bytes.len() && is_ws_byte(bytes[end]) {
        end += 1;
    }
    if end != bytes.len() {
        return Err(());
    }
    let digits = std::str::from_utf8(&bytes[start..end]).map_err(|_| ())?;
    let magnitude = if hex {
        u64::from_str_radix(digits, 16)
    } else {
        digits.parse::<u64>()
    }
    .map_err(|_| ())?;
    if negative {
        if magnitude > (1_u64 << 63) {
            return Err(());
        }
        if magnitude == (1_u64 << 63) {
            return Ok(i64::MIN);
        }
        Ok(-(magnitude as i64))
    } else {
        if magnitude > i64::MAX as u64 {
            return Err(());
        }
        Ok(magnitude as i64)
    }
}

/// Real grammar (RFC 0013 §4.6): the special spellings `nan`, `inf`,
/// `±inf`, `infinity`, `±infinity` (case-insensitive) and otherwise
/// `sign? digits ('.' digits)? ([eE] sign? digits)?`.
fn parse_real(content: &str) -> Result<f64, ()> {
    let trimmed = content.trim_matches(is_ws_char);
    let lower = trimmed.to_ascii_lowercase();
    let special = match lower.as_str() {
        "nan" => Some(f64::NAN),
        "inf" | "+inf" | "infinity" | "+infinity" => Some(f64::INFINITY),
        "-inf" | "-infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    };
    if let Some(value) = special {
        return Ok(value);
    }
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        index += 1;
    }
    let digits_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == digits_start {
        return Err(());
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let fraction_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == fraction_start {
            return Err(());
        }
    }
    if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent_start {
            return Err(());
        }
    }
    if index != bytes.len() {
        return Err(());
    }
    trimmed.parse::<f64>().map_err(|_| ())
}

/// Date grammar (RFC 0013 §4.7): `[-]YYYY-MM-DDTHH:MM:SSZ` with calendar
/// validation; the value is the exact double seconds since the plist epoch.
///
/// The i64-to-f64 cast is the mandated native representation: the double is
/// the exact seconds value with deterministic rounding, never an error.
#[allow(clippy::cast_precision_loss)]
fn parse_date(content: &str) -> Result<f64, ()> {
    let bytes = content.as_bytes();
    let mut index = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        index = 1;
    }
    let year_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == year_start {
        return Err(());
    }
    let year: u64 = content[year_start..index].parse().map_err(|_| ())?;
    if year > u64::from(u32::MAX) {
        return Err(());
    }
    let month = expect_two_digits(bytes, &mut index, b'-')?;
    let day = expect_two_digits(bytes, &mut index, b'-')?;
    let hour = expect_two_digits(bytes, &mut index, b'T')?;
    let minute = expect_two_digits(bytes, &mut index, b':')?;
    let second = expect_two_digits(bytes, &mut index, b':')?;
    if index >= bytes.len() || bytes[index] != b'Z' {
        return Err(());
    }
    index += 1;
    if index != bytes.len() {
        return Err(());
    }
    let year_signed = if negative {
        -(year as i64)
    } else {
        year as i64
    };
    if !(1..=12).contains(&month) {
        return Err(());
    }
    let days_in_month = days_in_month(year_signed, month);
    if day == 0 || day > days_in_month {
        return Err(());
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(());
    }
    let days = days_from_civil(year_signed, i64::from(month), i64::from(day));
    let time = i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);
    let unix = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(time))
        .ok_or(())?;
    Ok(unix as f64 - UNIX_TO_PLIST_EPOCH_SECONDS)
}

/// Consumes `sep` then exactly two decimal digits.
fn expect_two_digits(bytes: &[u8], index: &mut usize, sep: u8) -> Result<u32, ()> {
    if bytes.get(*index) != Some(&sep) {
        return Err(());
    }
    *index += 1;
    if *index + 2 > bytes.len()
        || !bytes[*index].is_ascii_digit()
        || !bytes[*index + 1].is_ascii_digit()
    {
        return Err(());
    }
    let value = u32::from(bytes[*index] - b'0') * 10 + u32::from(bytes[*index + 1] - b'0');
    *index += 2;
    Ok(value)
}

/// Proleptic Gregorian calendar days since the Unix epoch
/// (Howard Hinnant's `days_from_civil`); exact for the 32-bit year bound.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Strict base64 decoding with the standard alphabet (RFC 0013 §4.8):
/// ASCII whitespace between characters, padding exactly as required for the
/// final incomplete group, and nothing else.
fn decode_base64(content: &str) -> Result<Vec<u8>, ()> {
    let mut compact = Vec::with_capacity(content.len());
    for &byte in content.as_bytes() {
        if is_ws_byte(byte) {
            continue;
        }
        compact.push(byte);
    }
    let len = compact.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len % 4 == 1 {
        return Err(());
    }
    let mut end = len;
    let mut padding = 0usize;
    while end > 0 && compact[end - 1] == b'=' {
        end -= 1;
        padding += 1;
    }
    if padding > 2 {
        return Err(());
    }
    if compact[..end].contains(&b'=') {
        return Err(());
    }
    let valid_padding = match padding {
        0 => end % 4 == 0,
        1 => end % 4 == 3,
        2 => end % 4 == 2,
        _ => false,
    };
    if !valid_padding {
        return Err(());
    }
    let out_len = end / 4 * 3
        + match padding {
            1 => 2,
            2 => 1,
            _ => 0,
        };
    let mut out = Vec::with_capacity(out_len);
    let mut at = 0usize;
    while at + 4 <= end {
        let s = [
            base64_value(compact[at])?,
            base64_value(compact[at + 1])?,
            base64_value(compact[at + 2])?,
            base64_value(compact[at + 3])?,
        ];
        out.push((s[0] << 2) | (s[1] >> 4));
        out.push(((s[1] & 0x0F) << 4) | (s[2] >> 2));
        out.push(((s[2] & 0x03) << 6) | s[3]);
        at += 4;
    }
    if at < end {
        let s = [
            base64_value(compact[at])?,
            base64_value(compact[at + 1])?,
            if at + 2 < end {
                base64_value(compact[at + 2])?
            } else {
                0
            },
        ];
        out.push((s[0] << 2) | (s[1] >> 4));
        if at + 2 < end {
            out.push(((s[1] & 0x0F) << 4) | (s[2] >> 2));
        }
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Result<u8, ()> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(()),
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, FatalFormationFailure> {
    left.checked_add(right).ok_or_else(overflow_failure)
}

/// Host-size or arithmetic overflow: a fatal condition (RFC 0013 §3, hard
/// gate 4).
fn overflow_failure() -> FatalFormationFailure {
    fatal(
        "plist.xml.overflow@1",
        DiagnosticCategory::Resource,
        None,
        &[],
    )
}

/// Unreachable internal state: defensive fatal with no panicking path.
fn internal_failure() -> FatalFormationFailure {
    fatal(
        "plist.xml.internal@1",
        DiagnosticCategory::Resource,
        None,
        &[],
    )
}

/// Exhaustive coverage could not be constructed: a fatal condition (RFC 0013
/// §3).
fn coverage_failure() -> FatalFormationFailure {
    fatal(
        "plist.xml.coverage@1",
        DiagnosticCategory::Syntax,
        None,
        &[],
    )
}

/// Impossible source coordinates: a fatal condition (RFC 0013 §3).
fn coordinates_failure() -> FatalFormationFailure {
    fatal(
        "plist.xml.coordinates@1",
        DiagnosticCategory::Syntax,
        None,
        &[],
    )
}

/// One fatal diagnostic.
fn fatal(
    code: &'static str,
    category: DiagnosticCategory,
    location: Option<DiagnosticLocation>,
    arguments: &[(&'static str, String)],
) -> FatalFormationFailure {
    let mut diagnostic = Diagnostic::new(code, category, DiagnosticSeverity::Error, location, 0);
    for (name, value) in arguments {
        diagnostic
            .arguments
            .insert((*name).to_owned(), value.clone());
    }
    FatalFormationFailure::from_diagnostic(diagnostic)
}

/// `plist.limit.<name>@1` resource-limit failure (RFC 0013 §12).
fn fatal_limit(name: &'static str, observed: usize, limit: usize) -> FatalFormationFailure {
    let mut diagnostic = Diagnostic::new(
        format!("plist.limit.{name}@1"),
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
        .insert("observed".to_owned(), observed.to_string());
    FatalFormationFailure::from_diagnostic(diagnostic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlistEncodingSelection;
    use crate::PlistParseLimits;
    use consema_document::{FormationStatus, SourceEncoding};

    fn parse(bytes: &[u8]) -> Result<PlistFormedXml, FatalFormationFailure> {
        parse_xml(
            Arc::<[u8]>::from(bytes),
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
    }

    fn parse_limited(
        bytes: &[u8],
        limits: PlistParseLimits,
    ) -> Result<PlistFormedXml, FatalFormationFailure> {
        parse_xml(
            Arc::<[u8]>::from(bytes),
            PlistEncodingSelection::ProfileDefault,
            limits,
        )
    }

    fn diagnostic_codes(formed: &PlistFormedXml) -> Vec<String> {
        formed
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    fn piece_kinds(formed: &PlistFormedXml) -> Vec<&str> {
        formed
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect()
    }

    fn piece_spans(formed: &PlistFormedXml) -> Vec<(usize, usize)> {
        formed
            .lossless_structural_index()
            .pieces()
            .iter()
            .map(|piece| (piece.span().start_byte(), piece.span().end_byte()))
            .collect()
    }

    fn minimal_document() -> &'static [u8] {
        b"<plist version=\"1.0\"><string>hi</string></plist>"
    }

    #[test]
    fn minimal_string_document_is_complete_and_byte_exact() {
        let formed = parse(minimal_document()).expect("minimal plist forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(formed.diagnostics().is_empty());
        assert_eq!(formed.render(), minimal_document());
        let document = formed.document().expect("native document");
        assert_eq!(document.node_count(), 1);
        assert_eq!(
            document
                .root_value()
                .as_string()
                .expect("string root")
                .to_unicode()
                .unwrap(),
            "hi"
        );
        assert_eq!(
            formed.source().encoding_facts().selected(),
            SourceEncoding::Utf8
        );
    }

    #[test]
    fn root_tag_pieces_partition_exactly() {
        let source = b"<plist version=\"1.0\"><string>x</string></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        // The open tag partitions as name, separator, version name,
        // `="1.0"`, and the closing `>`; the string element mirrors the same
        // name-plus-`>` partition with StringOpen.
        assert_eq!(
            piece_kinds(&formed),
            [
                "plist-open",
                "whitespace",
                "plist-version-name",
                "plist-version-value",
                "plist-open",
                "string-open",
                "string-open",
                "text",
                "string-close",
                "plist-close",
            ]
        );
        assert_eq!(
            piece_spans(&formed),
            [
                (0, 6),
                (6, 7),
                (7, 14),
                (14, 20),
                (20, 21),
                (21, 28),
                (28, 29),
                (29, 30),
                (30, 39),
                (39, 47),
            ]
        );
        // The PlistVersionValue span covers exactly `="1.0"`.
        let source_text = std::str::from_utf8(source).expect("utf-8");
        let spans = piece_spans(&formed);
        assert_eq!(&source_text[spans[3].0..spans[3].1], "=\"1.0\"");
    }

    #[test]
    fn all_value_kinds_parse_into_the_shared_native_model() {
        let source = br#"<plist version="1.0"><dict>
  <key>i</key><integer>256</integer>
  <key>r</key><real>0.5</real>
  <key>t</key><true/>
  <key>f</key><false/>
  <key>d</key><date>2001-01-01T00:00:00Z</date>
  <key>D</key><data>AAAA</data>
  <key>s</key><string>hi</string>
  <key>a</key><array><string>x</string></array>
  <key>e</key><dict/>
</dict></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(
            formed.diagnostics().is_empty(),
            "{:?}",
            formed.diagnostics()
        );
        let document = formed.document().expect("native document");
        let entries = document
            .get(document.root())
            .expect("root")
            .as_dict()
            .expect("dict root")
            .entries();
        assert_eq!(entries.len(), 9);
        assert_eq!(
            document
                .get(entries[0].value())
                .expect("value")
                .as_integer()
                .expect("integer")
                .value(),
            256
        );
        let real = document
            .get(entries[1].value())
            .expect("value")
            .as_real()
            .expect("real");
        assert_eq!(real.as_f64().to_bits(), 0.5_f64.to_bits());
        assert!(
            document
                .get(entries[2].value())
                .expect("value")
                .as_boolean()
                .expect("true")
                .value()
        );
        assert!(
            !document
                .get(entries[3].value())
                .expect("value")
                .as_boolean()
                .expect("false")
                .value()
        );
        assert_eq!(
            document
                .get(entries[4].value())
                .expect("value")
                .as_date()
                .expect("date")
                .seconds()
                .to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(
            document
                .get(entries[5].value())
                .expect("value")
                .as_data()
                .expect("data")
                .bytes(),
            &[0, 0, 0]
        );
        assert_eq!(
            document
                .get(entries[6].value())
                .expect("value")
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "hi"
        );
        let elements = document
            .get(entries[7].value())
            .expect("value")
            .as_array()
            .expect("array")
            .elements();
        assert_eq!(elements.len(), 1);
        assert_eq!(
            document
                .get(elements[0])
                .expect("element")
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "x"
        );
        assert!(
            document
                .get(entries[8].value())
                .expect("value")
                .as_dict()
                .expect("dict")
                .is_empty()
        );
    }

    #[test]
    fn doctype_is_optional_and_exact() {
        let with_doctype = br#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><string>x</string></plist>"#;
        let formed = parse(with_doctype).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let kinds = piece_kinds(&formed);
        assert_eq!(kinds[0], "doctype-open");
        assert_eq!(kinds[1], "doctype-body");
        assert_eq!(kinds[2], "doctype-close");

        let without = parse(minimal_document()).expect("forms without doctype");
        assert_eq!(without.status(), FormationStatus::Complete);
        assert!(
            !piece_kinds(&without).contains(&"doctype-open"),
            "no doctype pieces when absent"
        );
    }

    #[test]
    fn doctype_name_and_identifier_mismatches_are_recovered() {
        let variants: &[&[u8]] = &[
            br#"<!DOCTYPE plist><plist version="1.0"><string>x</string></plist>"#,
            br#"<!DOCTYPE plist SYSTEM "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><string>x</string></plist>"#,
            br#"<!DOCTYPE plist PUBLIC "wrong" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><string>x</string></plist>"#,
            br#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "wrong"><plist version="1.0"><string>x</string></plist>"#,
            br#"<!DOCTYPE other PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><string>x</string></plist>"#,
        ];
        for source in variants {
            let formed = parse(source).expect("recovered document forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{source:?}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.doctype@1".to_owned()),
                "{source:?}"
            );
            assert!(formed.document().is_some(), "{source:?}");
        }
    }

    #[test]
    fn doctype_internal_subset_is_recovered() {
        let source = br#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" [<!ENTITY x "y">]><plist version="1.0"><string>x</string></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.doctype-subset@1".to_owned()));
        let kinds = piece_kinds(&formed);
        assert!(kinds.starts_with(&["doctype-open", "doctype-body", "doctype-close"]));
    }

    #[test]
    fn integer_decimal_hex_and_sign_forms() {
        let cases: &[(&str, i64)] = &[
            ("42", 42),
            ("+42", 42),
            ("-42", -42),
            (" 42 ", 42),
            ("0x2A", 42),
            ("0X2a", 42),
            ("-0x2A", -42),
            ("- 42", -42),
            (" - 0x10 ", -16),
            ("00042", 42),
            ("-0", 0),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("0x7FFFFFFFFFFFFFFF", i64::MAX),
            ("-0x8000000000000000", i64::MIN),
        ];
        for (spelling, expected) in cases {
            let source = format!("<plist version=\"1.0\"><integer>{spelling}</integer></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Complete,
                "spelling {spelling}"
            );
            let value = formed
                .document()
                .expect("document")
                .root_value()
                .as_integer()
                .expect("integer")
                .value();
            assert_eq!(value, *expected, "spelling {spelling}");
        }
    }

    #[test]
    fn integer_range_and_grammar_violations_are_recovered() {
        let bad: &[&str] = &[
            "9223372036854775808",
            "-9223372036854775809",
            "0x8000000000000000",
            "-0x8000000000000001",
            "0x",
            "12x",
            "1 2",
            "++1",
            "--1",
            "- 0x",
            "0b101",
            "",
        ];
        for spelling in bad {
            let source = format!("<plist version=\"1.0\"><integer>{spelling}</integer></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "spelling {spelling:?}"
            );
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.integer@1".to_owned())
                    || diagnostic_codes(&formed).contains(&"plist.parse.empty-value@1".to_owned()),
                "spelling {spelling:?}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_none(), "spelling {spelling:?}");
        }
    }

    #[test]
    fn real_forms_and_special_spellings() {
        let cases: &[(&str, f64)] = &[
            ("1.5", 1.5),
            ("-0.5", -0.5),
            ("0", 0.0),
            ("42", 42.0),
            ("1e3", 1000.0),
            ("2.5e-2", 0.025),
            ("-1.5E+2", -150.0),
            ("+0.25", 0.25),
            (" 1.5 ", 1.5),
        ];
        for (spelling, expected) in cases {
            let source = format!("<plist version=\"1.0\"><real>{spelling}</real></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Complete, "{spelling}");
            let value = formed
                .document()
                .expect("document")
                .root_value()
                .as_real()
                .expect("real")
                .as_f64();
            assert_eq!(value.to_bits(), expected.to_bits(), "{spelling}");
        }
        let specials: &[(&str, f64)] = &[
            ("nan", f64::NAN),
            ("NAN", f64::NAN),
            ("inf", f64::INFINITY),
            ("+inf", f64::INFINITY),
            ("-inf", f64::NEG_INFINITY),
            ("Infinity", f64::INFINITY),
            ("+infinity", f64::INFINITY),
            ("-INFINITY", f64::NEG_INFINITY),
        ];
        for (spelling, expected) in specials {
            let source = format!("<plist version=\"1.0\"><real>{spelling}</real></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Complete, "{spelling}");
            let value = formed
                .document()
                .expect("document")
                .root_value()
                .as_real()
                .expect("real")
                .as_f64();
            assert_eq!(value.to_bits(), expected.to_bits(), "{spelling}");
        }
    }

    #[test]
    fn real_grammar_violations_are_recovered() {
        let bad: &[&str] = &[
            "5.", ".5", "abc", "1e", "1e+", "e5", "++1", "+", "-", "1.5.2", "0x1p2", "1 5",
        ];
        for spelling in bad {
            let source = format!("<plist version=\"1.0\"><real>{spelling}</real></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{spelling:?}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.real@1".to_owned()),
                "{spelling:?}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_none(), "{spelling:?}");
        }
    }

    #[test]
    fn date_forms_and_calendar_edges() {
        let cases: &[(&str, f64)] = &[
            ("2001-01-01T00:00:00Z", 0.0),
            ("1970-01-01T00:00:00Z", -978_307_200.0),
            ("2020-01-01T00:00:00Z", 1_577_836_800.0 - 978_307_200.0),
            (
                "2020-02-29T12:34:56Z",
                1_582_934_400.0 - 978_307_200.0 + 45_296.0,
            ),
            ("2000-02-29T00:00:00Z", 951_782_400.0 - 978_307_200.0),
            (
                "-0001-01-01T00:00:00Z",
                -719_893.0 * 86_400.0 - 978_307_200.0,
            ),
            (
                "0001-01-01T00:00:00Z",
                -719_162.0 * 86_400.0 - 978_307_200.0,
            ),
            ("2020-01-31T23:59:59Z", 1_580_515_199.0 - 978_307_200.0),
        ];
        for (spelling, expected) in cases {
            let source = format!("<plist version=\"1.0\"><date>{spelling}</date></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Complete, "{spelling}");
            let seconds = formed
                .document()
                .expect("document")
                .root_value()
                .as_date()
                .expect("date")
                .seconds();
            assert_eq!(seconds.to_bits(), expected.to_bits(), "{spelling}");
        }
        let bad: &[&str] = &[
            "1900-02-29T00:00:00Z",
            "2001-02-29T00:00:00Z",
            "2020-13-01T00:00:00Z",
            "2020-00-01T00:00:00Z",
            "2020-01-00T00:00:00Z",
            "2020-01-32T00:00:00Z",
            "2020-01-01T24:00:00Z",
            "2020-01-01T00:60:00Z",
            "2020-01-01T00:00:60Z",
            "2020-01-01T00:00:00",
            "2020-01-01T00:00:00Zx",
            "2020-01-01t00:00:00z",
            "2020-1-01T00:00:00Z",
            "2020-01-01T0:00:00Z",
            "2020-01-01T00:00:00.5Z",
            "2020-01-01T00:00:00+01:00",
            "2020-01-01 00:00:00Z",
            "4294967296-01-01T00:00:00Z",
        ];
        for spelling in bad {
            let source = format!("<plist version=\"1.0\"><date>{spelling}</date></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{spelling}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.date@1".to_owned()),
                "{spelling}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_none(), "{spelling}");
        }
    }

    #[test]
    fn data_base64_decodes_padding_and_whitespace() {
        let cases: &[(&str, &[u8])] = &[
            ("YWJj", b"abc"),
            ("YQ==", b"a"),
            ("YWI=", b"ab"),
            ("", b""),
            ("YW Jj", b"abc"),
            (" YQ== ", b"a"),
            ("YQ\n==", b"a"),
            ("YQ\r\n==", b"a"),
            ("YQ==\t", b"a"),
            ("YWJjZGVm", b"abcdef"),
        ];
        for (spelling, expected) in cases {
            let source = format!("<plist version=\"1.0\"><data>{spelling}</data></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Complete, "{spelling:?}");
            let bytes = formed
                .document()
                .expect("document")
                .root_value()
                .as_data()
                .expect("data")
                .bytes();
            assert_eq!(bytes, *expected, "{spelling:?}");
        }
    }

    #[test]
    fn data_base64_violations_are_recovered() {
        let bad: &[&str] = &[
            "YQ", "YQ=", "YQ===", "YW=j", "Y!!j", "A", "YWJjZQ", "Y W=j", "====", "YWJj=Q==",
        ];
        for spelling in bad {
            let source = format!("<plist version=\"1.0\"><data>{spelling}</data></plist>");
            let formed = parse(source.as_bytes()).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{spelling:?}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.data@1".to_owned()),
                "{spelling:?}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_none(), "{spelling:?}");
        }
    }

    #[test]
    fn data_empty_forms_distinguish_self_closing_and_explicit() {
        let self_closing = b"<plist version=\"1.0\"><data/></plist>";
        let formed = parse(self_closing).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.empty-value@1".to_owned()));
        assert!(formed.document().is_none());

        let explicit = b"<plist version=\"1.0\"><data></data></plist>";
        let formed = parse(explicit).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_data()
                .expect("data")
                .bytes()
                .is_empty()
        );
    }

    #[test]
    fn string_entities_and_character_references_resolve() {
        let source = br#"<plist version="1.0"><string>a &lt; b &amp; c &#65; &#x41; &apos;d&apos; &quot;e&quot;</string></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "a < b & c A A 'd' \"e\""
        );
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"entity-reference"));
        assert!(kinds.contains(&"character-reference"));
        assert!(kinds.contains(&"text"));
    }

    #[test]
    fn string_unknown_entity_is_recovered_without_partial_text() {
        let source = br#"<plist version="1.0"><string>before &bogus; after</string></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.entity@1".to_owned()));
        assert_eq!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "before  after"
        );
    }

    #[test]
    fn string_malformed_references_are_recovered() {
        let cases: &[&[u8]] = &[
            b"<plist version=\"1.0\"><string>a &#xZZ; b</string></plist>",
            b"<plist version=\"1.0\"><string>a &#xD800; b</string></plist>",
            b"<plist version=\"1.0\"><string>a &#xFFFE; b</string></plist>",
            b"<plist version=\"1.0\"><string>a &#x0; b</string></plist>",
            b"<plist version=\"1.0\"><string>a &b</string></plist>",
            b"<plist version=\"1.0\"><string>&;x</string></plist>",
        ];
        for source in cases {
            let formed = parse(source).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{source:?}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.reference@1".to_owned()),
                "{source:?}: {:?}",
                diagnostic_codes(&formed)
            );
        }
    }

    #[test]
    fn string_cdata_and_crlf_normalization() {
        let source = b"<plist version=\"1.0\"><string>a<![CDATA[b]]>c</string></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "abc"
        );
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"cdata-open"));
        assert!(kinds.contains(&"cdata-text"));
        assert!(kinds.contains(&"cdata-close"));

        let crlf = b"<plist version=\"1.0\"><string>line1\r\nline2</string></plist>";
        let formed = parse(crlf).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(formed.render(), crlf);
        assert_eq!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "line1\nline2"
        );

        // A character reference to CR is not line-end normalized (XML 1.0).
        let reference = b"<plist version=\"1.0\"><string>a&#13;b</string></plist>";
        let formed = parse(reference).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "a\rb"
        );
    }

    #[test]
    fn string_preserves_whitespace_and_unicode() {
        let source = "<plist version=\"1.0\"><string> A é 😀 </string></plist>";
        let formed = parse(source.as_bytes()).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let string = formed
            .document()
            .expect("document")
            .root_value()
            .as_string()
            .expect("string");
        assert_eq!(string.to_unicode().unwrap(), " A é 😀 ");
        assert_eq!(
            string.code_units(),
            &[0x20, 0x41, 0x20, 0xE9, 0x20, 0xD83D, 0xDE00, 0x20]
        );
    }

    #[test]
    fn duplicate_keys_are_preserved_in_source_order() {
        let source = br#"<plist version="1.0"><dict><key>k</key><string>v</string><key>k</key><string>w</string></dict></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().expect("document");
        let entries = document.root_value().as_dict().expect("dict").entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "k");
        assert_eq!(entries[1].key().to_unicode().unwrap(), "k");
        assert_eq!(
            document
                .get(entries[0].value())
                .expect("value")
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "v"
        );
        assert_eq!(
            document
                .get(entries[1].value())
                .expect("value")
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "w"
        );
    }

    #[test]
    fn empty_containers_and_strings_are_complete() {
        for source in [
            b"<plist version=\"1.0\"><dict/></plist>".as_slice(),
            b"<plist version=\"1.0\"><array/></plist>",
            b"<plist version=\"1.0\"><string/></plist>",
            b"<plist version=\"1.0\"><dict><key/><string>x</string></dict></plist>",
        ] {
            let formed = parse(source).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Complete,
                "{source:?}: {:?}",
                diagnostic_codes(&formed)
            );
        }
    }

    #[test]
    fn empty_scalars_are_recovered() {
        for element in ["integer", "real", "date", "data"] {
            let self_closing = format!("<plist version=\"1.0\"><{element}/></plist>");
            let formed = parse(self_closing.as_bytes()).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "{element} self-closing"
            );
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.empty-value@1".to_owned()),
                "{element}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_none(), "{element}");
        }
        // Explicitly closed empty integer/real/date elements are Recovered;
        // `<data></data>` is a valid zero-length value (RFC 0013 §4.8).
        for element in ["integer", "real", "date"] {
            let explicit = format!("<plist version=\"1.0\"><{element}></{element}></plist>");
            let formed = parse(explicit.as_bytes()).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "{element} explicit"
            );
        }
        let data = b"<plist version=\"1.0\"><data></data></plist>";
        assert_eq!(
            parse(data).expect("forms").status(),
            FormationStatus::Complete
        );
    }

    #[test]
    fn true_false_forms_and_content_recovery() {
        for source in [
            b"<plist version=\"1.0\"><true/></plist>".as_slice(),
            b"<plist version=\"1.0\"><true></true></plist>",
            b"<plist version=\"1.0\"><false/></plist>",
            b"<plist version=\"1.0\"><true> </true></plist>",
        ] {
            let formed = parse(source).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Complete,
                "{source:?}: {:?}",
                diagnostic_codes(&formed)
            );
            assert!(formed.document().is_some(), "{source:?}");
        }
        let content = b"<plist version=\"1.0\"><true>x</true></plist>";
        let formed = parse(content).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.boolean-content@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn dict_pairing_recovery_matrix() {
        // Value element in key position: unpaired, following pairs still work.
        let value_in_key = br#"<plist version="1.0"><dict><string>v</string><key>k</key><string>x</string></dict></plist>"#;
        let formed = parse(value_in_key).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.dict-key@1".to_owned()));
        let entries = formed
            .document()
            .expect("document")
            .root_value()
            .as_dict()
            .expect("dict")
            .entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "k");

        // Key while a value is expected: the pending key is dropped.
        let key_after_key = br#"<plist version="1.0"><dict><key>a</key><key>b</key><string>x</string></dict></plist>"#;
        let formed = parse(key_after_key).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.dict-missing-value@1".to_owned()));
        let entries = formed
            .document()
            .expect("document")
            .root_value()
            .as_dict()
            .expect("dict")
            .entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "b");

        // Pending key at `</dict>`: dropped with a diagnostic.
        let pending = br#"<plist version="1.0"><dict><key>a</key></dict></plist>"#;
        let formed = parse(pending).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.dict-missing-value@1".to_owned()));
        assert!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_dict()
                .expect("dict")
                .is_empty()
        );
    }

    #[test]
    fn key_outside_dict_is_recovered() {
        let source = br#"<plist version="1.0"><array><key>a</key></array></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.key-outside-dict@1".to_owned()));
        assert!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_array()
                .expect("array")
                .is_empty()
        );
    }

    #[test]
    fn scalar_child_elements_drop_the_scalar() {
        let source = br#"<plist version="1.0"><string>a<dict/>b</string></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.scalar-content@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn unknown_elements_cover_whole_subtrees_as_error_regions() {
        let source =
            br#"<plist version="1.0"><array><foo>text<bar/></foo><string>x</string></array></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.element-name@1".to_owned()));
        let elements = formed
            .document()
            .expect("document")
            .root_value()
            .as_array()
            .expect("array")
            .elements();
        assert_eq!(elements.len(), 1);
        assert_eq!(
            formed
                .document()
                .expect("document")
                .get(elements[0])
                .expect("element")
                .as_string()
                .expect("string")
                .to_unicode()
                .unwrap(),
            "x"
        );
        // The unknown subtree is one error region: from `<foo` through
        // `</foo>`, including its text and nested markup.
        let spans = piece_spans(&formed);
        let kinds = piece_kinds(&formed);
        let region_index = kinds
            .iter()
            .position(|kind| *kind == "error-region")
            .expect("error region");
        let foo_open = source
            .windows(4)
            .position(|window| window == b"<foo")
            .expect("foo open");
        let foo_close_end = source
            .windows(6)
            .rposition(|window| window == b"</foo>")
            .expect("foo close")
            + 6;
        assert_eq!(
            spans[region_index],
            (foo_open, foo_close_end),
            "spans: {spans:?}"
        );
    }

    #[test]
    fn nested_plist_elements_are_unknown_not_root() {
        let source = br#"<plist version="1.0"><array><plist/></array></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.element-name@1".to_owned()));
        assert!(
            !diagnostic_codes(&formed).contains(&"plist.parse.root-version@1".to_owned()),
            "a nested plist element must not trigger the root version check"
        );
        assert!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_array()
                .expect("array")
                .is_empty()
        );
    }

    #[test]
    fn prefixed_names_and_xmlns_are_recovered() {
        let prefixed = br#"<p:plist version="1.0"><dict/></p:plist>"#;
        let formed = parse(prefixed).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.element-name@1".to_owned()));
        assert!(formed.document().is_none());

        let xmlns = br#"<plist version="1.0" xmlns="urn:x"><dict xmlns:p="urn:y"/></plist>"#;
        let formed = parse(xmlns).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-attribute@1".to_owned()));
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.element-attribute@1".to_owned()));
        assert!(formed.document().is_some());
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"error-region"));
    }

    #[test]
    fn root_version_contract() {
        let missing = b"<plist><dict/></plist>";
        let formed = parse(missing).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-version@1".to_owned()));
        assert!(formed.document().is_some());

        let wrong = b"<plist version=\"2.0\"><dict/></plist>";
        let formed = parse(wrong).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-version@1".to_owned()));

        let extra = b"<plist version=\"1.0\" extra=\"x\"><dict/></plist>";
        let formed = parse(extra).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-attribute@1".to_owned()));

        let duplicate = b"<plist version=\"1.0\" version=\"1.0\"><dict/></plist>";
        let formed = parse(duplicate).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-attribute@1".to_owned()));

        let spaced = b"<plist  version = \"1.0\" ><dict/></plist>";
        let formed = parse(spaced).expect("forms");
        assert_eq!(
            formed.status(),
            FormationStatus::Complete,
            "{:?}",
            diagnostic_codes(&formed)
        );
    }

    #[test]
    fn root_value_count_zero_and_two_are_recovered() {
        let zero = b"<plist version=\"1.0\"></plist>";
        let formed = parse(zero).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-value-count@1".to_owned()));
        assert!(formed.document().is_none());

        let two = b"<plist version=\"1.0\"><string>a</string><string>b</string></plist>";
        let formed = parse(two).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.root-value-count@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn trailing_content_after_plist_is_recovered() {
        let junk = b"<plist version=\"1.0\"><string>a</string></plist>junk";
        let formed = parse(junk).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.well-formedness@1".to_owned()));
        assert!(formed.document().is_some());
        assert_eq!(formed.render(), junk);
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"error-region"));
    }

    #[test]
    fn missing_root_is_recovered() {
        for source in [
            b"".as_slice(),
            b"<?xml version=\"1.0\"?>".as_slice(),
            b"<!-- only a comment -->".as_slice(),
        ] {
            let formed = parse(source).expect("forms");
            assert_eq!(formed.status(), FormationStatus::Recovered, "{source:?}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.parse.missing-root@1".to_owned()),
                "{source:?}"
            );
            assert!(formed.document().is_none());
        }
    }

    #[test]
    fn mismatched_and_extra_end_tags_are_recovered() {
        let mismatched = b"<plist version=\"1.0\"><dict></array></plist>";
        let formed = parse(mismatched).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.mismatched-end-tag@1".to_owned()));

        // `</dict>` pops the plist frame (mismatch); the trailing `</plist>`
        // is then a tokenizer well-formedness error.
        let extra = b"<plist version=\"1.0\"><string>x</string></dict></plist>";
        let formed = parse(extra).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.mismatched-end-tag@1".to_owned()));
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.well-formedness@1".to_owned()));
    }

    #[test]
    fn unclosed_elements_are_recovered() {
        let source = b"<plist version=\"1.0\"><string>abc";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.unclosed-element@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn prolog_and_epilog_trivia_are_complete() {
        let source = b"<?xml version=\"1.0\"?><!-- c --><?pi x?><plist version=\"1.0\"><dict/><!-- inside --></plist><!-- tail -->";
        let formed = parse(source).expect("forms");
        assert_eq!(
            formed.status(),
            FormationStatus::Complete,
            "{:?}",
            diagnostic_codes(&formed)
        );
        assert!(formed.document().is_some());
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"comment-open"));
        assert!(kinds.contains(&"processing-instruction-target"));
        assert!(kinds.contains(&"processing-instruction-content"));
    }

    #[test]
    fn pi_target_xml_is_recovered() {
        let source = b"<?xml version=\"1.0\"?><?xml?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.pi-target@1".to_owned()));
    }

    #[test]
    fn declaration_rules_and_pieces() {
        let source = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let kinds = piece_kinds(&formed);
        assert!(kinds.starts_with(&["declaration-open", "whitespace", "declaration-name"]));
        assert!(kinds.contains(&"declaration-value"));
        assert!(kinds.contains(&"declaration-close"));

        let standalone =
            b"<?xml version=\"1.0\" standalone=\"no\"?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(standalone).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let spans = piece_spans(&formed);
        let kinds = piece_kinds(&formed);
        let value_index = kinds
            .iter()
            .rposition(|kind| *kind == "declaration-value")
            .expect("standalone value");
        assert_eq!(
            &std::str::from_utf8(standalone).expect("utf-8")
                [spans[value_index].0..spans[value_index].1],
            "no"
        );

        let bad_version = b"<?xml version=\"1.5\"?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(bad_version).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(
            diagnostic_codes(&formed).contains(&"plist.parse.declaration-version@1".to_owned())
        );

        // A version that does not start with `1.` is a tokenizer error.
        let other_version = b"<?xml version=\"2.0\"?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(other_version).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.well-formedness@1".to_owned()));
    }

    #[test]
    fn declaration_encoding_conflict_is_recovered() {
        let source =
            b"<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist version=\"1.0\"><dict/></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let diagnostic = formed
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "plist.parse.declaration-conflict@1")
            .expect("conflict diagnostic");
        assert_eq!(diagnostic.category, DiagnosticCategory::Encoding);
        assert_eq!(
            diagnostic.arguments.get("declared").map(String::as_str),
            Some("UTF-16")
        );
    }

    #[test]
    fn bom_sources_are_complete_and_byte_exact() {
        let source =
            b"\xEF\xBB\xBF<?xml version=\"1.0\"?><plist version=\"1.0\"><string>x</string></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(formed.render(), source);
        let kinds = piece_kinds(&formed);
        assert_eq!(kinds[0], "bom");
        assert_eq!(
            formed.source().encoding_facts().selected(),
            SourceEncoding::Utf8
        );
        assert!(formed.document().is_some());
    }

    #[test]
    fn utf16le_and_be_sources_round_trip() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist version=\"1.0\"><dict><key>s</key><string>aé😀</string></dict></plist>";
        let mut le = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        let mut be = vec![0xFE, 0xFF];
        for unit in text.encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        for (bytes, expected_encoding) in [
            (&le, SourceEncoding::Utf16Le),
            (&be, SourceEncoding::Utf16Be),
        ] {
            let formed = parse(bytes).expect("forms");
            assert_eq!(
                formed.status(),
                FormationStatus::Complete,
                "{expected_encoding:?}"
            );
            assert_eq!(formed.render(), bytes);
            assert_eq!(
                formed.source().encoding_facts().selected(),
                expected_encoding
            );
            let document = formed.document().expect("document");
            let entries = document.root_value().as_dict().expect("dict").entries();
            assert_eq!(
                document
                    .get(entries[0].value())
                    .expect("value")
                    .as_string()
                    .expect("string")
                    .to_unicode()
                    .unwrap(),
                "aé😀"
            );
        }
    }

    #[test]
    fn utf16_without_bom_is_fatal() {
        let text = "<plist version=\"1.0\"><dict/></plist>";
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let result = parse_xml(
            Arc::<[u8]>::from(bytes),
            PlistEncodingSelection::Explicit(SourceEncoding::Utf16Le),
            PlistParseLimits::default(),
        );
        let error = result.expect_err("UTF-16 without BOM must fail");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.xml.encoding@1")
        );
    }

    #[test]
    fn encoding_selection_conflicts_are_fatal() {
        for selection in [
            PlistEncodingSelection::Explicit(SourceEncoding::Latin1),
            PlistEncodingSelection::Explicit(SourceEncoding::Binary),
            PlistEncodingSelection::Explicit(SourceEncoding::WindowsCodePage(
                consema_document::WindowsCodePage::from_number(1252).expect("published"),
            )),
        ] {
            let result = parse_xml(
                Arc::<[u8]>::from(minimal_document()),
                selection,
                PlistParseLimits::default(),
            );
            let error = result.expect_err("selection must fail");
            assert!(
                error
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "plist.xml.encoding@1")
            );
        }
        // A BOM that contradicts the explicit caller choice is a source
        // conflict before any tokenization.
        let mut conflicting = vec![0xFF, 0xFE];
        conflicting.extend_from_slice(minimal_document());
        let result = parse_xml(
            Arc::<[u8]>::from(conflicting),
            PlistEncodingSelection::Explicit(SourceEncoding::Utf8),
            PlistParseLimits::default(),
        );
        let error = result.expect_err("BOM conflict must fail");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "core.source.encoding-conflict@1")
        );
    }

    #[test]
    fn invalid_utf8_is_fatal() {
        let result = parse(&[0x80, 0x81, 0x82]);
        let error = result.expect_err("invalid UTF-8 must fail");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "core.source.invalid-sequence@1")
        );
    }

    #[test]
    fn per_value_limits_are_fatal() {
        let string = b"<plist version=\"1.0\"><string>abc</string></plist>";
        let limits = PlistParseLimits {
            max_string_code_units: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(string, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.string-code-units@1")
        );

        let data = b"<plist version=\"1.0\"><data>AAAA</data></plist>";
        let limits = PlistParseLimits {
            max_data_bytes: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(data, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.data-bytes@1")
        );

        let array =
            b"<plist version=\"1.0\"><array><string>a</string><string>b</string></array></plist>";
        let limits = PlistParseLimits {
            max_array_elements: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(array, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.array-elements@1")
        );

        let dict = b"<plist version=\"1.0\"><dict><key>a</key><string>x</string><key>b</key><string>y</string></dict></plist>";
        let limits = PlistParseLimits {
            max_dict_entries: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(dict, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.dict-entries@1")
        );
    }

    #[test]
    fn duplicate_key_group_limit_is_fatal() {
        let source = b"<plist version=\"1.0\"><dict><key>k</key><string>a</string><key>k</key><string>b</string></dict></plist>";
        let limits = PlistParseLimits {
            max_duplicate_key_group_members: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(source, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.duplicate-key-group@1")
        );
    }

    #[test]
    fn nesting_and_container_depth_limits_are_fatal() {
        let deep = b"<plist version=\"1.0\"><array><array><array/></array></array></plist>";
        let limits = PlistParseLimits {
            common: consema_document::ParseLimits {
                max_nesting_depth: 2,
                ..consema_document::ParseLimits::default()
            },
            ..PlistParseLimits::default()
        };
        let error = parse_limited(deep, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.nesting-depth@1")
        );

        let limits = PlistParseLimits {
            max_container_depth: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(deep, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.container-depth@1")
        );
    }

    #[test]
    fn object_count_limit_is_fatal() {
        let source =
            b"<plist version=\"1.0\"><array><string>a</string><string>b</string></array></plist>";
        let limits = PlistParseLimits {
            max_object_count: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(source, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.object-count@1")
        );
    }

    #[test]
    fn syntax_pieces_limit_is_fatal() {
        let source = b"<plist version=\"1.0\"><dict/></plist>";
        let limits = PlistParseLimits {
            max_syntax_pieces: 3,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(source, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.syntax-pieces@1")
        );
    }

    #[test]
    fn source_bytes_limit_is_fatal() {
        let limits = PlistParseLimits {
            common: consema_document::ParseLimits {
                max_source_bytes: 10,
                ..consema_document::ParseLimits::default()
            },
            ..PlistParseLimits::default()
        };
        let error = parse_limited(minimal_document(), limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "core.source.resource-limit@1")
        );
    }

    #[test]
    fn recovery_regions_limit_is_fatal() {
        let source = b"<plist version=\"1.0\"><dict/></plist>junk";
        let limits = PlistParseLimits {
            max_recovery_regions: 0,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(source, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.recovery-regions@1")
        );
    }

    #[test]
    fn pieces_cover_every_byte_exhaustively() {
        let sources: &[&[u8]] = &[
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array><string>a &lt; b</string><data>YQ==</data><true/></array></plist>",
            b"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>k</key><date>2020-02-29T12:34:56Z</date></dict></plist>",
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string><key>d</key><date>BAD</date></dict></plist>",
            b"<plist version=\"1.0\"><array><foo/><string>x</string></array></plist>",
        ];
        for source in sources {
            let formed = parse(source).expect("forms");
            let mut next = 0;
            for piece in formed.lossless_structural_index().pieces() {
                assert_eq!(piece.span().start_byte(), next, "{source:?}");
                assert!(piece.span().end_byte() > piece.span().start_byte());
                next = piece.span().end_byte();
            }
            assert_eq!(next, source.len(), "{source:?}");
            assert_eq!(
                formed.lossless_syntax_kinds().len(),
                formed.lossless_structural_index().pieces().len(),
                "{source:?}"
            );
        }
    }

    #[test]
    fn fine_grained_kinds_cover_every_document_part() {
        let source = br#"<?xml version="1.0" standalone="yes"?>
<!-- prolog comment --><?pi x?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <string>a &lt; b &#65; <![CDATA[c]]></string>
  <integer>0x10</integer>
  <real>1.5e2</real>
  <date>2001-01-01T00:00:00Z</date>
  <data>YWJj</data>
  <true/>
  <false></false>
  <dict><key>k</key><string>v</string></dict>
</array>
<!-- inner comment -->
</plist>
<!-- epilog comment -->"#;
        let formed = parse(source).expect("forms");
        assert_eq!(
            formed.status(),
            FormationStatus::Complete,
            "{:?}",
            diagnostic_codes(&formed)
        );
        assert!(formed.document().is_some());
        let kinds = piece_kinds(&formed);
        for expected in [
            "declaration-open",
            "declaration-name",
            "declaration-value",
            "declaration-close",
            "comment-open",
            "comment-text",
            "comment-close",
            "processing-instruction-open",
            "processing-instruction-target",
            "processing-instruction-content",
            "processing-instruction-close",
            "doctype-open",
            "doctype-body",
            "doctype-close",
            "plist-open",
            "plist-version-name",
            "plist-version-value",
            "plist-close",
            "array-open",
            "array-close",
            "string-open",
            "string-close",
            "text",
            "entity-reference",
            "character-reference",
            "cdata-open",
            "cdata-text",
            "cdata-close",
            "integer-open",
            "integer-close",
            "real-open",
            "real-close",
            "date-open",
            "date-close",
            "data-open",
            "data-close",
            "true",
            "false",
            "dict-open",
            "dict-close",
            "key-open",
            "key-close",
            "whitespace",
            "line-break",
        ] {
            assert!(
                kinds.contains(&expected),
                "kind {expected} never emitted; kinds: {kinds:?}"
            );
        }
        assert!(!kinds.contains(&"bom"));
        assert!(!kinds.contains(&"error-region"));
    }

    #[test]
    fn whitespace_runs_split_into_trivia_kinds() {
        let source = b"<plist version=\"1.0\"><array>\n  <string>x</string>\r\n</array></plist>";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let kinds = piece_kinds(&formed);
        // `<array>` partitions into name and `>` pieces; the text runs
        // inside split into line-break and whitespace trivia.
        assert!(
            kinds
                .windows(3)
                .any(|window| window == ["array-open", "line-break", "whitespace"])
        );
        assert!(
            kinds
                .windows(3)
                .any(|window| window == ["string-close", "line-break", "array-close"])
        );
    }

    #[test]
    fn cdata_and_text_outside_values_are_error_regions() {
        let cdata = b"<plist version=\"1.0\"><array><![CDATA[x]]></array></plist>";
        let formed = parse(cdata).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.text-outside-value@1".to_owned()));
        let kinds = piece_kinds(&formed);
        assert!(kinds.contains(&"error-region"));

        let text = b"<plist version=\"1.0\"><array>junk</array></plist>";
        let formed = parse(text).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.text-outside-value@1".to_owned()));
        assert!(
            formed
                .document()
                .expect("document")
                .root_value()
                .as_array()
                .expect("array")
                .is_empty()
        );

        let under_root = b"<plist version=\"1.0\">junk<dict/></plist>";
        let formed = parse(under_root).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.text-outside-value@1".to_owned()));
        assert!(formed.document().is_some(), "the dict value stays proven");
    }

    #[test]
    fn recovered_document_keeps_proven_parts() {
        let source = br#"<plist version="1.0"><dict><key>a</key><string>x</string><key>d</key><date>BOGUS</date><key>z</key><integer>7</integer></dict></plist>"#;
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.parse.date@1".to_owned()));
        let entries = formed
            .document()
            .expect("document")
            .root_value()
            .as_dict()
            .expect("dict")
            .entries();
        assert_eq!(entries.len(), 2, "the failed date association is dropped");
        assert_eq!(entries[0].key().to_unicode().unwrap(), "a");
        assert_eq!(entries[1].key().to_unicode().unwrap(), "z");
    }

    #[test]
    fn diagnostics_are_deterministically_ordered() {
        let source =
            b"<plist version=\"2.0\"><dict><key>k</key><date>BAD</date></dict></plist>junk";
        let formed = parse(source).expect("forms");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let codes = diagnostic_codes(&formed);
        assert!(codes[0].starts_with("plist.parse.root-version"));
        let diagnostics = formed.diagnostics();
        for pair in diagnostics.windows(2) {
            let left = pair[0].primary.as_ref().expect("location").start_byte;
            let right = pair[1].primary.as_ref().expect("location").start_byte;
            assert!(left <= right);
        }
    }

    #[test]
    fn different_spellings_produce_equal_documents() {
        let hex = b"<plist version=\"1.0\"><integer>0x10</integer></plist>";
        let decimal = b"<plist version=\"1.0\"><integer>16</integer></plist>";
        assert_eq!(
            parse(hex).expect("hex").document().expect("document"),
            parse(decimal)
                .expect("decimal")
                .document()
                .expect("document")
        );
        let reference = b"<plist version=\"1.0\"><string>&#65;</string></plist>";
        let literal = b"<plist version=\"1.0\"><string>A</string></plist>";
        assert_eq!(
            parse(reference)
                .expect("reference")
                .document()
                .expect("document"),
            parse(literal)
                .expect("literal")
                .document()
                .expect("document")
        );
    }

    #[test]
    fn kind_names_round_trip_through_as_str_and_from_name() {
        for kind in [
            PlistSyntaxKind::Bom,
            PlistSyntaxKind::Whitespace,
            PlistSyntaxKind::LineBreak,
            PlistSyntaxKind::DeclarationOpen,
            PlistSyntaxKind::DeclarationName,
            PlistSyntaxKind::DeclarationValue,
            PlistSyntaxKind::DeclarationClose,
            PlistSyntaxKind::DoctypeOpen,
            PlistSyntaxKind::DoctypeBody,
            PlistSyntaxKind::DoctypeClose,
            PlistSyntaxKind::PlistOpen,
            PlistSyntaxKind::PlistVersionName,
            PlistSyntaxKind::PlistVersionValue,
            PlistSyntaxKind::PlistClose,
            PlistSyntaxKind::DictOpen,
            PlistSyntaxKind::DictClose,
            PlistSyntaxKind::KeyOpen,
            PlistSyntaxKind::KeyClose,
            PlistSyntaxKind::ArrayOpen,
            PlistSyntaxKind::ArrayClose,
            PlistSyntaxKind::StringOpen,
            PlistSyntaxKind::StringClose,
            PlistSyntaxKind::IntegerOpen,
            PlistSyntaxKind::IntegerClose,
            PlistSyntaxKind::RealOpen,
            PlistSyntaxKind::RealClose,
            PlistSyntaxKind::DateOpen,
            PlistSyntaxKind::DateClose,
            PlistSyntaxKind::DataOpen,
            PlistSyntaxKind::DataClose,
            PlistSyntaxKind::True,
            PlistSyntaxKind::False,
            PlistSyntaxKind::Text,
            PlistSyntaxKind::EntityReference,
            PlistSyntaxKind::CharacterReference,
            PlistSyntaxKind::CdataOpen,
            PlistSyntaxKind::CdataText,
            PlistSyntaxKind::CdataClose,
            PlistSyntaxKind::CommentOpen,
            PlistSyntaxKind::CommentText,
            PlistSyntaxKind::CommentClose,
            PlistSyntaxKind::ProcessingInstructionOpen,
            PlistSyntaxKind::ProcessingInstructionTarget,
            PlistSyntaxKind::ProcessingInstructionContent,
            PlistSyntaxKind::ProcessingInstructionClose,
            PlistSyntaxKind::ErrorRegion,
        ] {
            assert_eq!(PlistSyntaxKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(PlistSyntaxKind::from_name("nope"), None);
    }

    #[test]
    fn truncation_and_mutation_never_panic_or_fake_complete() {
        let source = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array><string>ab</string><data>AAAA</data></array></plist>";
        for len in 0..source.len() {
            if let Ok(formed) = parse(&source[..len]) {
                assert_ne!(formed.status(), FormationStatus::Complete, "len {len}");
                assert_eq!(formed.render(), &source[..len], "len {len}");
            }
        }
        // The version value and the close tag are integrity-critical: any
        // single-byte mutation there must never forge a Complete document.
        let version_start = source
            .windows(3)
            .position(|window| window == b"1.0")
            .expect("version value");
        let close_start = source.len() - b"</plist>".len();
        for position in 0..source.len() {
            for mutation in [0x00_u8, 0x3C, 0x80, 0xFF] {
                if source[position] == mutation {
                    continue;
                }
                let mut mutated = source.to_vec();
                mutated[position] = mutation;
                if let Ok(formed) = parse(&mutated) {
                    assert_eq!(formed.render(), mutated.as_slice(), "position {position}");
                    if (version_start..version_start + 3).contains(&position)
                        || position >= close_start
                    {
                        assert_ne!(
                            formed.status(),
                            FormationStatus::Complete,
                            "position {position} mutation {mutation:#04x}"
                        );
                    }
                }
            }
        }
    }
}
