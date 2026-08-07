//! Self-owned HCL tokenizer: the token stream, the 30-kind lossless piece
//! assembly, and the lexical half of the RFC 0014 §12 divergence inventory
//! (RFC 0014 §2, §4.1, §7.2).
//!
//! There is no third-party HCL tokenizer: the tokenizer, body/expression
//! grammar, recovery, and all downstream operations are Consema-owned
//! (RFC 0014 §12). [`lex`] is one deterministic forward pass over the decoded
//! UTF-8 text. Every non-empty raw byte of the source belongs to exactly one
//! ordered [`HclToken`], and the token stream maps one-to-one to the ordered
//! lossless pieces of the closed 30-kind [`HclSyntaxKind`] set — there is no
//! `Bom` kind because a BOM is excluded at formation (RFC 0014 §7.2).
//!
//! # Token face
//!
//! The token stream is richer than the piece kind set: it carries every
//! operator spelling, the trivia runs, and an explicit zero-length `Eof`
//! terminal (which has no piece). The exact source text of every token is
//! always derived from its half-open raw-byte span, never copied.
//!
//! - Identifiers follow UAX #31 via the `unicode-ident` tables:
//!   `ID_Start (ID_Continue | "-")*`. Underscore is excluded at the start
//!   position (RFC 0014 §4.1, §12 D-4) and admitted as a continuation
//!   (`foo_bar` is valid). Keyword spellings `true`/`false`/`null` are plain
//!   identifier tokens — their literal/traversal dual reading is a parser
//!   fact (RFC 0014 §4.1).
//! - Numbers follow the §4.1 decimal-only grammar. A number-shaped run that
//!   violates the grammar (hex, octal, binary, underscores, a bare exponent,
//!   a second fraction, or an identifier extension like `123abc`) is one
//!   `ErrorRegion` token with `hcl.parse.invalid-number@1`. `1-2` is
//!   `Number OpSubtract Number`; `1e-2` is one number.
//! - Quoted templates partition as `StringOpen` + ([`StringContent`] literal
//!   runs, interpolation and directive triples) + `StringClose`. The
//!   interpolation/directive interiors are one opaque `InterpolationContent`
//!   / `DirectiveContent` token each; the parser (M3) re-lexes the interior
//!   span through [`lex_region`] (RFC 0014 §3.2 of the implementation plan).
//! - Heredocs partition as `HeredocOpen` (the `<<`/`<<-` introducer and the
//!   bare-identifier marker), per-line literal runs kept as
//!   `HeredocContent`, the same interpolation/directive triples inside the
//!   content, and `HeredocClose` covering the closing marker line.
//! - Every operator and punctuation spelling is a token; `::` is never an
//!   operator — it is an `ErrorRegion` (RFC 0014 §12 D-6, namespaced calls
//!   have no spec form). `foo.0` lexes as the legal token sequence
//!   `Identifier Dot Number`; the §12 D-5 rejection is a grammar error of the
//!   parser (`GetAttr = "." Identifier`), not a lexical fact.
//!
//! # Recovery semantics
//!
//! Lexical deviations form Recovered output (ordered diagnostics + error
//! regions); limit violations and impossible coordinates are fatal. A
//! Recovered lex keeps exhaustive piece coverage — every byte still belongs
//! to exactly one piece. The deterministic boundaries follow RFC 0014 §3:
//!
//! - an unterminated quoted string is `StringOpen` + one `ErrorRegion` over
//!   its content to end of line (or end of file) with
//!   `hcl.parse.unterminated-string@1`; body scanning resumes at the next
//!   line;
//! - an unterminated interpolation or directive inside a template is an
//!   `ErrorRegion` covering the remainder of the template with
//!   `hcl.parse.unterminated-interpolation@1` / `...-directive@1`; when the
//!   enclosing template is also unterminated at end of file, the outermost
//!   construct owns the error region and the inner constructs publish
//!   diagnostics only;
//! - an unterminated heredoc is `HeredocOpen` + one `ErrorRegion` over its
//!   content to end of file, bounded by the heredoc size limits, with
//!   `hcl.parse.unterminated-heredoc@1`;
//! - a quoted string buffers its content tokens until the closing quote
//!   proves the template; a heredoc buffers its content tokens until the
//!   closing marker line proves it. An unterminated template discards the
//!   buffer — nothing unproven is ever asserted as a proven piece.
//!
//! # Divergence inventory (lexical half)
//!
//! - D-1 BOM: the source is decoded with `BomPolicy::TreatAsContent`, so the
//!   UTF-8 BOM bytes enter the decoded text and the lexer reports any
//!   `U+FEFF` outside template literal content as
//!   `hcl.parse.byte-order-mark@1` with an `ErrorRegion` piece (no `Bom`
//!   kind). A `U+FEFF` inside template literal content is literal text,
//!   matching the pinned oracle; UTF-16 BOMs are invalid UTF-8 and fatal.
//! - D-2 lone CR: a CR not followed by LF is `hcl.parse.lone-cr@1`, never a
//!   newline, everywhere in the source.
//! - D-3 invalid UTF-8: fatal `hcl.parse.invalid-utf8@1`.
//! - D-4 `_foo`: rejected at the lexer with `hcl.parse.identifier@1`.
//! - D-8 heredoc closing line: matched with the Go `bytes.TrimSpace`
//!   semantics (Unicode whitespace, tabs, and trailing whitespace admitted).
//!
//! # M3 adaptation points
//!
//! The parser consumes [`HclLexOutput::tokens`] in order; the `Eof` token is
//! the terminal. `InterpolationContent` / `DirectiveContent` spans are
//! re-lexed with [`lex_region`], which binds its spans to the same
//! [`DocumentAuthority`] so every native expression span shares one snapshot
//! identity. The lexer does not enforce the expression depth or number-digit
//! limits — those are parser-side facts of M3.

use crate::HclParseLimits;
use crate::native::{HclErrorRegion, HclSyntaxKind};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BomPolicy, DocumentAuthority, EncodingRequest, FatalFormationFailure, LosslessStructuralIndex,
    SourceEncoding, SourceError, SourceLimits, SourceSnapshot, Span, StructuralPiece,
    StructuralPieceKind,
};
use std::sync::Arc;

/// One lexical token with its exact half-open raw-byte span.
///
/// Every non-empty raw byte of a formed source belongs to exactly one token
/// (the zero-length [`HclTokenKind::Eof`] terminal has no piece). The exact
/// token text is always derived from the span against the frozen source —
/// never copied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HclToken {
    kind: HclTokenKind,
    span: Span,
}

impl HclToken {
    /// Creates one token.
    #[must_use]
    pub const fn new(kind: HclTokenKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Token kind.
    #[must_use]
    pub const fn kind(&self) -> HclTokenKind {
        self.kind
    }

    /// Exact half-open raw-byte span.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// Closed token kind set of the self-owned HCL tokenizer (RFC 0014 §2,
/// §4.1).
///
/// The set is richer than the 30-piece [`HclSyntaxKind`] closure: operator
/// spellings, the exact trivia runs, and the zero-length `Eof` terminal are
/// token facts. Keyword spellings are `Identifier` tokens — the literal
/// reading is a parser fact. The `~` strip markers of interpolations and
/// directives are span-internal facts of the open/close tokens.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HclTokenKind {
    /// Space or tab run.
    Whitespace,
    /// LF or CRLF newline sequence.
    LineBreak,
    /// `//` or `#` line comment, excluding the terminating newline.
    LineComment,
    /// `/* ... */` inline comment, which may span lines.
    InlineComment,
    /// UAX #31 identifier with hyphen continuation; keyword spellings
    /// included.
    Identifier,
    /// Valid §4.1 decimal number literal.
    Number,
    /// `=` equals sign.
    Equals,
    /// `"` quoted-template opening quote.
    StringOpen,
    /// Quoted-template literal content run (escapes and `$${`/`%%{` text
    /// included).
    StringContent,
    /// `"` quoted-template closing quote.
    StringClose,
    /// `${` or `${~` interpolation opening.
    InterpolationOpen,
    /// Interpolation interior between the opening and closing markers.
    InterpolationContent,
    /// `}` or `~}` interpolation closing.
    InterpolationClose,
    /// `%{` or `%{~` directive opening.
    DirectiveOpen,
    /// Directive interior between the opening and closing markers.
    DirectiveContent,
    /// `}` or `~}` directive closing.
    DirectiveClose,
    /// `<<`/`<<-` heredoc introducer and its bare-identifier marker.
    HeredocOpen,
    /// Heredoc literal content run of one content line.
    HeredocContent,
    /// Heredoc closing marker line.
    HeredocClose,
    /// `.` dot (traversal steps and splat starts).
    Dot,
    /// `,` comma.
    Comma,
    /// `:` colon.
    Colon,
    /// `?` question mark.
    QuestionMark,
    /// `=>` for-expression arrow.
    Arrow,
    /// `...` expansion or grouping marker.
    Ellipsis,
    /// `*` star (multiplication or splat marker).
    Star,
    /// `{` brace open.
    BraceOpen,
    /// `}` brace close.
    BraceClose,
    /// `[` bracket open.
    BracketOpen,
    /// `]` bracket close.
    BracketClose,
    /// `(` paren open.
    ParenOpen,
    /// `)` paren close.
    ParenClose,
    /// `==` operator.
    OpEqual,
    /// `!=` operator.
    OpNotEqual,
    /// `<` operator.
    OpLess,
    /// `>` operator.
    OpGreater,
    /// `<=` operator.
    OpLessEqual,
    /// `>=` operator.
    OpGreaterEqual,
    /// `+` operator.
    OpAdd,
    /// `-` operator.
    OpSubtract,
    /// `!` unary operator.
    OpNot,
    /// `/` operator.
    OpDivide,
    /// `%` operator.
    OpModulo,
    /// `&&` operator.
    OpAnd,
    /// `||` operator.
    OpOr,
    /// Bytes not admitted as any token: BOM, lone CR, invalid characters,
    /// invalid numbers, unterminated constructs, and other recovered
    /// regions.
    ErrorRegion,
    /// Zero-length end-of-source terminal; never a piece.
    Eof,
}

impl HclTokenKind {
    /// The closed lossless syntax kind of this token; `None` for the
    /// zero-length `Eof` terminal, which has no piece (RFC 0014 §7.2).
    #[must_use]
    pub const fn syntax_kind(self) -> Option<HclSyntaxKind> {
        Some(match self {
            Self::Whitespace => HclSyntaxKind::Whitespace,
            Self::LineBreak => HclSyntaxKind::LineBreak,
            Self::LineComment => HclSyntaxKind::LineComment,
            Self::InlineComment => HclSyntaxKind::InlineComment,
            Self::Identifier => HclSyntaxKind::Identifier,
            Self::Number => HclSyntaxKind::Number,
            Self::Equals => HclSyntaxKind::Equals,
            Self::StringOpen => HclSyntaxKind::StringOpen,
            Self::StringContent => HclSyntaxKind::StringContent,
            Self::StringClose => HclSyntaxKind::StringClose,
            Self::InterpolationOpen => HclSyntaxKind::InterpolationOpen,
            Self::InterpolationContent => HclSyntaxKind::InterpolationContent,
            Self::InterpolationClose => HclSyntaxKind::InterpolationClose,
            Self::DirectiveOpen => HclSyntaxKind::DirectiveOpen,
            Self::DirectiveContent => HclSyntaxKind::DirectiveContent,
            Self::DirectiveClose => HclSyntaxKind::DirectiveClose,
            Self::HeredocOpen => HclSyntaxKind::HeredocOpen,
            Self::HeredocContent => HclSyntaxKind::HeredocContent,
            Self::HeredocClose => HclSyntaxKind::HeredocClose,
            Self::BraceOpen => HclSyntaxKind::BraceOpen,
            Self::BraceClose => HclSyntaxKind::BraceClose,
            Self::BracketOpen => HclSyntaxKind::BracketOpen,
            Self::BracketClose => HclSyntaxKind::BracketClose,
            Self::ParenOpen => HclSyntaxKind::ParenOpen,
            Self::ParenClose => HclSyntaxKind::ParenClose,
            Self::Comma => HclSyntaxKind::Comma,
            Self::Colon => HclSyntaxKind::Colon,
            Self::QuestionMark => HclSyntaxKind::QuestionMark,
            Self::Dot
            | Self::Arrow
            | Self::Ellipsis
            | Self::Star
            | Self::OpEqual
            | Self::OpNotEqual
            | Self::OpLess
            | Self::OpGreater
            | Self::OpLessEqual
            | Self::OpGreaterEqual
            | Self::OpAdd
            | Self::OpSubtract
            | Self::OpNot
            | Self::OpDivide
            | Self::OpModulo
            | Self::OpAnd
            | Self::OpOr => HclSyntaxKind::Operator,
            Self::ErrorRegion => HclSyntaxKind::ErrorRegion,
            Self::Eof => return None,
        })
    }

    /// The structural classification of this token's piece.
    #[must_use]
    pub const fn structural_kind(self) -> StructuralPieceKind {
        match self {
            Self::Whitespace | Self::LineBreak | Self::LineComment | Self::InlineComment => {
                StructuralPieceKind::Trivia
            }
            Self::ErrorRegion => StructuralPieceKind::ErrorRegion,
            _ => StructuralPieceKind::Token,
        }
    }
}

/// Result of one lexer pass: the ordered token stream, the recovered error
/// regions, the ordered diagnostics, and the lossless 30-kind piece index
/// (RFC 0014 §2, §7.2).
///
/// `syntax` is `Some` for a whole-source lex and `None` for a region lex
/// (an interpolation interior), whose tokens still carry exact spans bound to
/// the same authority but do not form a source-covering index.
#[derive(Clone, Debug)]
pub struct HclLexOutput {
    source: Arc<SourceSnapshot>,
    tokens: Vec<HclToken>,
    error_regions: Vec<HclErrorRegion>,
    diagnostics: Vec<Diagnostic>,
    recovered: bool,
    syntax: Option<LosslessStructuralIndex>,
    syntax_kinds: Arc<[HclSyntaxKind]>,
    authority: DocumentAuthority,
}

impl HclLexOutput {
    /// Frozen source snapshot of the lexed bytes.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Ordered token stream, ending with the zero-length `Eof` terminal.
    #[must_use]
    pub fn tokens(&self) -> &[HclToken] {
        &self.tokens
    }

    /// Recovered error regions in source order, one per non-empty
    /// `ErrorRegion` token, each with its stable `hcl.parse.*@1` code.
    #[must_use]
    pub fn error_regions(&self) -> &[HclErrorRegion] {
        &self.error_regions
    }

    /// Ordered diagnostics from the pass, deterministically sorted.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Whether the pass formed any recovery.
    #[must_use]
    pub const fn is_recovered(&self) -> bool {
        self.recovered
    }

    /// Exhaustive ordered lossless piece coverage of the whole source; `None`
    /// for a region lex.
    #[must_use]
    pub fn syntax(&self) -> Option<&LosslessStructuralIndex> {
        self.syntax.as_ref()
    }

    /// Ordered syntax kinds, parallel to the lossless structural pieces.
    #[must_use]
    pub fn syntax_kinds(&self) -> &[HclSyntaxKind] {
        &self.syntax_kinds
    }

    /// Snapshot-bound identity authority shared by every emitted span (M3
    /// adaptation point).
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        &self.authority
    }
}

/// Lexes one whole HCL source under the frozen UTF-8 source contract
/// (RFC 0014 §2).
///
/// The source is decoded with `BomPolicy::TreatAsContent`: a UTF-8 BOM stays
/// in the decoded text where the lexer reports it as
/// `hcl.parse.byte-order-mark@1` instead of stripping it (RFC 0014 §12 D-1),
/// and UTF-16 BOMs fail as invalid UTF-8. Invalid UTF-8 is a fatal
/// formation failure with `hcl.parse.invalid-utf8@1` (RFC 0014 §2, §12 D-3).
pub fn lex(
    bytes: Arc<[u8]>,
    limits: HclParseLimits,
) -> Result<HclLexOutput, FatalFormationFailure> {
    let source = Arc::new(
        SourceSnapshot::from_raw(
            bytes,
            EncodingRequest::new(SourceEncoding::Utf8).with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits {
                max_raw_bytes: limits.common.max_source_bytes,
                max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
                max_decoded_scalars: limits.max_decoded_scalars,
            },
        )
        .map_err(invalid_utf8_failure)?,
    );
    let authority = DocumentAuthority::fresh();
    lex_source(source, authority, limits, None)
}

/// Lexes one expression region of an already-formed source (M3 adaptation
/// point).
///
/// The region's spans are bound to the caller's authority, so the parser can
/// re-lex `InterpolationContent` / `DirectiveContent` interiors and native
/// expression spans of the whole document share one snapshot identity. The
/// returned output carries no source-covering index.
pub(crate) fn lex_region(
    source: Arc<SourceSnapshot>,
    authority: DocumentAuthority,
    start: usize,
    end: usize,
    limits: HclParseLimits,
) -> Result<HclLexOutput, FatalFormationFailure> {
    lex_source(source, authority, limits, Some((start, end)))
}

fn lex_source(
    source: Arc<SourceSnapshot>,
    authority: DocumentAuthority,
    limits: HclParseLimits,
    region: Option<(usize, usize)>,
) -> Result<HclLexOutput, FatalFormationFailure> {
    let decoded = source.decoded_text().ok_or_else(encoding_failure)?;
    let (start, end) = region.unwrap_or((0, source.len()));
    if start > end || end > source.len() {
        return Err(coordinates_failure());
    }
    let mut lexer = Lexer::new(
        &source,
        decoded,
        authority,
        limits,
        start,
        end,
        region.is_none(),
    );
    lexer.scan()?;
    lexer.finish()
}

/// Stable `hcl.parse.*@1` diagnostic codes (RFC 0014 §2, §4.1, §4.4, §4.5,
/// §11).
mod codes {
    /// BOM anywhere outside template literal content (RFC 0014 §2, §12 D-1).
    pub const BYTE_ORDER_MARK: &str = "hcl.parse.byte-order-mark@1";
    /// Lone CR is not a newline (RFC 0014 §2, §12 D-2).
    pub const LONE_CR: &str = "hcl.parse.lone-cr@1";
    /// Invalid UTF-8 byte decoding, fatal (RFC 0014 §2, §12 D-3).
    pub const INVALID_UTF8: &str = "hcl.parse.invalid-utf8@1";
    /// Identifier start violation, such as a leading underscore (§12 D-4).
    pub const IDENTIFIER: &str = "hcl.parse.identifier@1";
    /// A number-shaped run that violates the §4.1 decimal grammar.
    pub const INVALID_NUMBER: &str = "hcl.parse.invalid-number@1";
    /// Character sequence admitted by no token, including `::` (§12 D-6).
    pub const INVALID_CHARACTER: &str = "hcl.parse.invalid-character@1";
    /// Invalid escape sequence in a quoted template (RFC 0014 §4.4).
    pub const INVALID_ESCAPE: &str = "hcl.parse.invalid-escape@1";
    /// Unterminated inline comment.
    pub const UNTERMINATED_COMMENT: &str = "hcl.parse.unterminated-comment@1";
    /// Unterminated quoted template (RFC 0014 §3).
    pub const UNTERMINATED_STRING: &str = "hcl.parse.unterminated-string@1";
    /// Unterminated interpolation (RFC 0014 §3).
    pub const UNTERMINATED_INTERPOLATION: &str = "hcl.parse.unterminated-interpolation@1";
    /// Unterminated directive (RFC 0014 §3).
    pub const UNTERMINATED_DIRECTIVE: &str = "hcl.parse.unterminated-directive@1";
    /// Unterminated heredoc (RFC 0014 §3, §4.5).
    pub const UNTERMINATED_HEREDOC: &str = "hcl.parse.unterminated-heredoc@1";
    /// `<<`/`<<-` that does not introduce a heredoc, including the quoted
    /// marker form (RFC 0014 §4.5).
    pub const HEREDOC_MARKER: &str = "hcl.parse.heredoc-marker@1";
}

/// One open template construct of the scanner stack.
///
/// The stack models the template nesting of RFC 0014 §4.4-§4.5: quoted
/// templates and heredocs contain interpolation and directive sequences whose
/// interiors are expressions, which may contain nested templates again.
/// Interpolation and directive interiors are scanned but not emitted — the
/// interior is one opaque content token — so the stack exists to find the
/// matching `}` at the right brace depth and to enforce the template nesting
/// limits.
#[derive(Clone, Debug)]
enum TemplateFrame {
    /// An open quoted template `"..."`.
    Quoted {
        /// Byte offset of the opening quote.
        open: usize,
        /// Buffered content tokens; flushed when the closing quote proves
        /// the template, discarded when the template is unterminated.
        buffer: Vec<HclToken>,
        /// Interpolation and directive count within this template.
        interpolations: usize,
    },
    /// An open heredoc `<<marker` ... `marker`.
    Heredoc {
        /// Bare identifier marker spelling.
        marker: Arc<str>,
        /// Byte offset where the heredoc content starts (after the
        /// introducer's newline).
        content_start: usize,
        /// Content bytes consumed so far, including content-line newlines.
        bytes: usize,
        /// Content lines consumed so far.
        lines: usize,
        /// Buffered content tokens; flushed at the closing marker line,
        /// discarded when the heredoc is unterminated.
        buffer: Vec<HclToken>,
        /// Interpolation and directive count within this template.
        interpolations: usize,
    },
    /// An open interpolation `${...}` or directive `%{...}` interior.
    Interp {
        /// Whether this is a directive (`%{`) rather than an interpolation.
        directive: bool,
        /// `{` nesting depth inside the interior; the sequence closes at the
        /// `}` at depth zero.
        depth: usize,
        /// Byte offset of the interior start (right after the open token).
        interior_start: usize,
    },
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

/// One deterministic lexer pass over a decoded UTF-8 source.
///
/// Byte offsets are decoded-text offsets; under the UTF-8-only source
/// contract they are identical to raw-byte offsets, so every span is issued
/// directly against the snapshot length. The scanner is total: every byte of
/// `[start, end)` is consumed by exactly one token or error region.
struct Lexer<'a> {
    source: &'a Arc<SourceSnapshot>,
    decoded: &'a str,
    bytes: &'a [u8],
    authority: DocumentAuthority,
    limits: HclParseLimits,
    pos: usize,
    end: usize,
    build_index: bool,
    tokens: Vec<HclToken>,
    error_regions: Vec<HclErrorRegion>,
    sink: DiagnosticSink,
    recovered: bool,
    /// Tokens currently buffered inside open quoted/heredoc frames.
    buffered: usize,
    stack: Vec<TemplateFrame>,
}

impl<'a> Lexer<'a> {
    fn new(
        source: &'a Arc<SourceSnapshot>,
        decoded: &'a str,
        authority: DocumentAuthority,
        limits: HclParseLimits,
        start: usize,
        end: usize,
        build_index: bool,
    ) -> Self {
        Self {
            source,
            decoded,
            bytes: decoded.as_bytes(),
            authority,
            limits,
            pos: start,
            end,
            build_index,
            tokens: Vec::new(),
            error_regions: Vec::new(),
            sink: DiagnosticSink::new(limits.common.max_diagnostics),
            recovered: false,
            buffered: 0,
            stack: Vec::new(),
        }
    }

    fn scan(&mut self) -> Result<(), FatalFormationFailure> {
        while self.pos < self.end {
            match self.stack.last() {
                None => self.scan_root()?,
                Some(TemplateFrame::Interp { .. }) => self.scan_absorb()?,
                Some(TemplateFrame::Quoted { .. }) => self.scan_quoted()?,
                Some(TemplateFrame::Heredoc { .. }) => self.scan_heredoc()?,
            }
        }
        self.finish_eof()?;
        Ok(())
    }

    /// Whether the current position is outside every interpolation/directive
    /// interior, i.e. whether tokens are emitted at all.
    fn emitting(&self) -> bool {
        self.stack
            .iter()
            .all(|frame| !matches!(frame, TemplateFrame::Interp { .. }))
    }

    /// Scans one root-level (body or expression) token.
    fn scan_root(&mut self) -> Result<(), FatalFormationFailure> {
        let byte = self.byte().expect("scan_root is called below the scan end");
        match byte {
            b' ' | b'\t' => {
                let start = self.pos;
                while matches!(self.byte(), Some(b' ' | b'\t')) {
                    self.pos += 1;
                }
                self.emit_kind(HclTokenKind::Whitespace, start, self.pos)?;
            }
            b'\n' => {
                self.emit_kind(HclTokenKind::LineBreak, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'\r' => {
                if self.byte_at(1) == Some(b'\n') {
                    self.emit_kind(HclTokenKind::LineBreak, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_error_region(
                        self.pos,
                        self.pos + 1,
                        codes::LONE_CR,
                        DiagnosticCategory::Lexical,
                    )?;
                    self.pos += 1;
                }
            }
            b'#' => {
                self.scan_line_comment(true)?;
            }
            b'/' => {
                if self.byte_at(1) == Some(b'/') {
                    self.scan_line_comment(true)?;
                } else if self.byte_at(1) == Some(b'*') {
                    self.scan_inline_comment(true)?;
                } else {
                    self.emit_kind(HclTokenKind::OpDivide, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'"' => {
                self.open_quoted(true)?;
            }
            b'<' => {
                if self.byte_at(1) == Some(b'<') {
                    self.open_heredoc(true)?;
                } else if self.byte_at(1) == Some(b'=') {
                    self.emit_kind(HclTokenKind::OpLessEqual, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_kind(HclTokenKind::OpLess, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'>' => {
                if self.byte_at(1) == Some(b'=') {
                    self.emit_kind(HclTokenKind::OpGreaterEqual, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_kind(HclTokenKind::OpGreater, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'=' => {
                if self.byte_at(1) == Some(b'=') {
                    self.emit_kind(HclTokenKind::OpEqual, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else if self.byte_at(1) == Some(b'>') {
                    self.emit_kind(HclTokenKind::Arrow, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_kind(HclTokenKind::Equals, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'!' => {
                if self.byte_at(1) == Some(b'=') {
                    self.emit_kind(HclTokenKind::OpNotEqual, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_kind(HclTokenKind::OpNot, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'-' => {
                self.emit_kind(HclTokenKind::OpSubtract, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'+' => {
                self.emit_kind(HclTokenKind::OpAdd, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'*' => {
                self.emit_kind(HclTokenKind::Star, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'%' => {
                self.emit_kind(HclTokenKind::OpModulo, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'&' => {
                if self.byte_at(1) == Some(b'&') {
                    self.emit_kind(HclTokenKind::OpAnd, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_error_region(
                        self.pos,
                        self.pos + 1,
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                    )?;
                    self.pos += 1;
                }
            }
            b'|' => {
                if self.byte_at(1) == Some(b'|') {
                    self.emit_kind(HclTokenKind::OpOr, self.pos, self.pos + 2)?;
                    self.pos += 2;
                } else {
                    self.emit_error_region(
                        self.pos,
                        self.pos + 1,
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                    )?;
                    self.pos += 1;
                }
            }
            b'?' => {
                self.emit_kind(HclTokenKind::QuestionMark, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b':' => {
                if self.byte_at(1) == Some(b':') {
                    // `::` is never an operator: the namespaced function form
                    // has no spec production (RFC 0014 §12 D-6).
                    self.emit_error_region(
                        self.pos,
                        self.pos + 2,
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                    )?;
                    self.pos += 2;
                } else {
                    self.emit_kind(HclTokenKind::Colon, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b',' => {
                self.emit_kind(HclTokenKind::Comma, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'.' => {
                if self.byte_at(1) == Some(b'.') && self.byte_at(2) == Some(b'.') {
                    self.emit_kind(HclTokenKind::Ellipsis, self.pos, self.pos + 3)?;
                    self.pos += 3;
                } else {
                    self.emit_kind(HclTokenKind::Dot, self.pos, self.pos + 1)?;
                    self.pos += 1;
                }
            }
            b'{' => {
                self.emit_kind(HclTokenKind::BraceOpen, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'}' => {
                self.emit_kind(HclTokenKind::BraceClose, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'[' => {
                self.emit_kind(HclTokenKind::BracketOpen, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b']' => {
                self.emit_kind(HclTokenKind::BracketClose, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'(' => {
                self.emit_kind(HclTokenKind::ParenOpen, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b')' => {
                self.emit_kind(HclTokenKind::ParenClose, self.pos, self.pos + 1)?;
                self.pos += 1;
            }
            b'~' | b'\\' | b'$' => {
                self.emit_error_region(
                    self.pos,
                    self.pos + 1,
                    codes::INVALID_CHARACTER,
                    DiagnosticCategory::Syntax,
                )?;
                self.pos += 1;
            }
            b'0'..=b'9' => {
                self.scan_number(true)?;
            }
            _ => {
                let ch = self
                    .char_at(self.pos)
                    .expect("scan positions are char boundaries");
                if ch == '\u{FEFF}' {
                    self.emit_error_region(
                        self.pos,
                        self.pos + 3,
                        codes::BYTE_ORDER_MARK,
                        DiagnosticCategory::Encoding,
                    )?;
                    self.pos += 3;
                } else if ch == '_' {
                    // `_` is not an ID_Start (RFC 0014 §4.1, §12 D-4).
                    self.emit_error_region(
                        self.pos,
                        self.pos + 1,
                        codes::IDENTIFIER,
                        DiagnosticCategory::Syntax,
                    )?;
                    self.pos += 1;
                } else if is_identifier_start(ch) {
                    self.scan_identifier(true)?;
                } else {
                    self.emit_error_region(
                        self.pos,
                        self.pos + ch.len_utf8(),
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                    )?;
                    self.pos += ch.len_utf8();
                }
            }
        }
        Ok(())
    }

    /// Scans one token inside an interpolation or directive interior: the
    /// interior is absorbed (no tokens), braces are balanced, and the
    /// sequence closes at the `}` (or `~}`) at depth zero.
    fn scan_absorb(&mut self) -> Result<(), FatalFormationFailure> {
        let byte = self
            .byte()
            .expect("scan_absorb is called below the scan end");
        match byte {
            b'{' => {
                let Some(TemplateFrame::Interp { depth, .. }) = self.stack.last_mut() else {
                    return Err(internal_failure());
                };
                *depth += 1;
                self.pos += 1;
            }
            b'}' | b'~' => {
                let (depth, directive, interior_start) = match self.stack.last() {
                    Some(TemplateFrame::Interp {
                        depth,
                        directive,
                        interior_start,
                        ..
                    }) => (*depth, *directive, *interior_start),
                    _ => return Err(internal_failure()),
                };
                let close_width = if byte == b'~' {
                    if depth == 0 && self.byte_at(1) == Some(b'}') {
                        Some(2)
                    } else {
                        None
                    }
                } else if depth == 0 {
                    Some(1)
                } else {
                    None
                };
                match close_width {
                    Some(width) => {
                        let close_start = self.pos;
                        self.pos += width;
                        let content_kind = if directive {
                            HclTokenKind::DirectiveContent
                        } else {
                            HclTokenKind::InterpolationContent
                        };
                        let close_kind = if directive {
                            HclTokenKind::DirectiveClose
                        } else {
                            HclTokenKind::InterpolationClose
                        };
                        let content =
                            HclToken::new(content_kind, self.span(interior_start, close_start)?);
                        let close_token =
                            HclToken::new(close_kind, self.span(close_start, self.pos)?);
                        self.stack.pop();
                        if self.emitting() {
                            self.emit(content)?;
                            self.emit(close_token)?;
                        }
                    }
                    None => {
                        if byte == b'}' {
                            let Some(TemplateFrame::Interp { depth, .. }) = self.stack.last_mut()
                            else {
                                return Err(internal_failure());
                            };
                            *depth -= 1;
                            self.pos += 1;
                        } else {
                            self.recover(
                                codes::INVALID_CHARACTER,
                                DiagnosticCategory::Syntax,
                                self.pos,
                                self.pos + 1,
                            )?;
                            self.pos += 1;
                        }
                    }
                }
            }
            b'"' => {
                let open = self.pos;
                self.pos += 1;
                self.check_template_depth()?;
                self.stack.push(TemplateFrame::Quoted {
                    open,
                    buffer: Vec::new(),
                    interpolations: 0,
                });
            }
            b'<' => {
                if self.byte_at(1) == Some(b'<') {
                    self.open_heredoc(false)?;
                } else if self.byte_at(1) == Some(b'=') {
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            }
            b'>' | b'!' => {
                if self.byte_at(1) == Some(b'=') {
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            }
            b'=' => {
                if matches!(self.byte_at(1), Some(b'=' | b'>')) {
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            }
            b'&' => {
                if self.byte_at(1) == Some(b'&') {
                    self.pos += 2;
                } else {
                    self.recover(
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                        self.pos,
                        self.pos + 1,
                    )?;
                    self.pos += 1;
                }
            }
            b'|' => {
                if self.byte_at(1) == Some(b'|') {
                    self.pos += 2;
                } else {
                    self.recover(
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                        self.pos,
                        self.pos + 1,
                    )?;
                    self.pos += 1;
                }
            }
            b':' => {
                if self.byte_at(1) == Some(b':') {
                    self.recover(
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                        self.pos,
                        self.pos + 2,
                    )?;
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            }
            b'.' => {
                if self.byte_at(1) == Some(b'.') && self.byte_at(2) == Some(b'.') {
                    self.pos += 3;
                } else {
                    self.pos += 1;
                }
            }
            b'+' | b'-' | b'*' | b'%' | b'?' | b',' | b'(' | b')' | b'[' | b']' | b' ' | b'\t' => {
                self.pos += 1;
            }
            b'\\' | b'$' => {
                self.recover(
                    codes::INVALID_CHARACTER,
                    DiagnosticCategory::Syntax,
                    self.pos,
                    self.pos + 1,
                )?;
                self.pos += 1;
            }
            b'\n' => {
                self.pos += 1;
                self.note_heredoc_line()?;
            }
            b'\r' => {
                if self.byte_at(1) == Some(b'\n') {
                    self.pos += 2;
                    self.note_heredoc_line()?;
                } else {
                    self.recover(
                        codes::LONE_CR,
                        DiagnosticCategory::Lexical,
                        self.pos,
                        self.pos + 1,
                    )?;
                    self.pos += 1;
                }
            }
            b'/' => {
                if self.byte_at(1) == Some(b'/') {
                    self.scan_line_comment(false)?;
                } else if self.byte_at(1) == Some(b'*') {
                    self.scan_inline_comment(false)?;
                } else {
                    self.pos += 1;
                }
            }
            b'#' => {
                self.scan_line_comment(false)?;
            }
            b'0'..=b'9' => {
                self.scan_number(false)?;
            }
            _ => {
                let ch = self
                    .char_at(self.pos)
                    .expect("scan positions are char boundaries");
                if ch == '\u{FEFF}' {
                    self.recover(
                        codes::BYTE_ORDER_MARK,
                        DiagnosticCategory::Encoding,
                        self.pos,
                        self.pos + 3,
                    )?;
                    self.pos += 3;
                } else if ch == '_' {
                    self.recover(
                        codes::IDENTIFIER,
                        DiagnosticCategory::Syntax,
                        self.pos,
                        self.pos + 1,
                    )?;
                    self.pos += 1;
                } else if is_identifier_start(ch) {
                    self.scan_identifier(false)?;
                } else {
                    self.recover(
                        codes::INVALID_CHARACTER,
                        DiagnosticCategory::Syntax,
                        self.pos,
                        self.pos + ch.len_utf8(),
                    )?;
                    self.pos += ch.len_utf8();
                }
            }
        }
        Ok(())
    }

    /// Scans quoted-template content up to the closing quote, an
    /// interpolation or directive opening, a raw newline, or end of source.
    fn scan_quoted(&mut self) -> Result<(), FatalFormationFailure> {
        let emit = self.emitting();
        let mut run_start = self.pos;
        while let Some(byte) = self.byte() {
            match byte {
                b'"' => {
                    self.end_run(run_start, emit, HclTokenKind::StringContent)?;
                    let close_start = self.pos;
                    self.pos += 1;
                    let Some(TemplateFrame::Quoted { open, .. }) = self.stack.last() else {
                        return Err(internal_failure());
                    };
                    let open = *open;
                    let span_len = self.pos - open;
                    if span_len > self.limits.max_string_len {
                        return Err(fatal_limit(
                            "string-len",
                            span_len,
                            self.limits.max_string_len,
                        ));
                    }
                    if span_len > self.limits.max_template_len {
                        return Err(fatal_limit(
                            "template-len",
                            span_len,
                            self.limits.max_template_len,
                        ));
                    }
                    if emit {
                        self.flush_buffer();
                        self.stack.pop();
                        self.emit_kind(HclTokenKind::StringClose, close_start, self.pos)?;
                    } else {
                        self.stack.pop();
                    }
                    return Ok(());
                }
                b'$' => {
                    if self.byte_at(1) == Some(b'$') && self.byte_at(2) == Some(b'{') {
                        self.pos += 3;
                    } else if self.byte_at(1) == Some(b'{') {
                        self.end_run(run_start, emit, HclTokenKind::StringContent)?;
                        self.open_interpolation(false, emit)?;
                        return Ok(());
                    } else {
                        self.pos += 1;
                    }
                }
                b'%' => {
                    if self.byte_at(1) == Some(b'%') && self.byte_at(2) == Some(b'{') {
                        self.pos += 3;
                    } else if self.byte_at(1) == Some(b'{') {
                        self.end_run(run_start, emit, HclTokenKind::StringContent)?;
                        self.open_interpolation(true, emit)?;
                        return Ok(());
                    } else {
                        self.pos += 1;
                    }
                }
                b'\\' => {
                    if self.byte_at(1) == Some(b'\n') {
                        // A backslash-newline is not an admitted escape and a
                        // raw newline is not permitted in a quoted template;
                        // the sequence is one invalid escape and the template
                        // continues.
                        self.recover(
                            codes::INVALID_ESCAPE,
                            DiagnosticCategory::Syntax,
                            self.pos,
                            self.pos + 2,
                        )?;
                        self.pos += 2;
                    } else if self.byte_at(1) == Some(b'\r') && self.byte_at(2) == Some(b'\n') {
                        self.recover(
                            codes::INVALID_ESCAPE,
                            DiagnosticCategory::Syntax,
                            self.pos,
                            self.pos + 3,
                        )?;
                        self.pos += 3;
                    } else {
                        self.scan_escape()?;
                    }
                }
                b'\n' => {
                    self.terminate_string(self.pos)?;
                    return Ok(());
                }
                b'\r' => {
                    if self.byte_at(1) == Some(b'\n') {
                        self.terminate_string(self.pos)?;
                        return Ok(());
                    }
                    self.end_run(run_start, emit, HclTokenKind::StringContent)?;
                    if emit {
                        self.emit_error_region(
                            self.pos,
                            self.pos + 1,
                            codes::LONE_CR,
                            DiagnosticCategory::Lexical,
                        )?;
                    } else {
                        self.recover(
                            codes::LONE_CR,
                            DiagnosticCategory::Lexical,
                            self.pos,
                            self.pos + 1,
                        )?;
                    }
                    self.pos += 1;
                    run_start = self.pos;
                }
                _ => {
                    let width = self
                        .char_at(self.pos)
                        .expect("scan positions are char boundaries")
                        .len_utf8();
                    self.pos += width;
                }
            }
        }
        self.terminate_string(self.end)?;
        Ok(())
    }

    /// Scans one heredoc content line or the closing marker line.
    fn scan_heredoc(&mut self) -> Result<(), FatalFormationFailure> {
        if self.pos >= self.end {
            return self.terminate_heredoc(self.end);
        }
        self.note_heredoc_content()?;
        let emit = self.emitting();
        let at_line_start = self.pos == 0 || self.bytes[self.pos - 1] == b'\n';
        let line_end = self.find_line_end();
        if at_line_start {
            let trimmed = self.decoded[self.pos..line_end].trim_matches(char::is_whitespace);
            let Some(TemplateFrame::Heredoc { marker, .. }) = self.stack.last() else {
                return Err(internal_failure());
            };
            let is_closing = trimmed == marker.as_ref();
            if is_closing {
                // The closing marker line; the whole line is HeredocClose.
                if emit {
                    self.flush_buffer();
                }
                self.stack.pop();
                if emit {
                    self.emit_kind(HclTokenKind::HeredocClose, self.pos, line_end)?;
                }
                if line_end < self.end {
                    if emit {
                        self.emit_kind(HclTokenKind::LineBreak, line_end, line_end + 1)?;
                    }
                    self.pos = line_end + 1;
                } else {
                    self.pos = line_end;
                }
                return Ok(());
            }
        }
        self.scan_heredoc_line(line_end)
    }

    /// Template-scans one heredoc content line: literal runs stay
    /// `HeredocContent`, and `${`/`%{` open interpolation/directive
    /// sequences (RFC 0014 §4.5).
    fn scan_heredoc_line(&mut self, line_end: usize) -> Result<(), FatalFormationFailure> {
        let emit = self.emitting();
        let mut run_start = self.pos;
        loop {
            if self.pos >= line_end {
                break;
            }
            let byte = self.bytes[self.pos];
            match byte {
                b'$' => {
                    if self.byte_at(1) == Some(b'$') && self.byte_at(2) == Some(b'{') {
                        self.pos += 3;
                    } else if self.byte_at(1) == Some(b'{') {
                        self.end_run(run_start, emit, HclTokenKind::HeredocContent)?;
                        self.open_interpolation(false, emit)?;
                        return Ok(());
                    } else {
                        self.pos += 1;
                    }
                }
                b'%' => {
                    if self.byte_at(1) == Some(b'%') && self.byte_at(2) == Some(b'{') {
                        self.pos += 3;
                    } else if self.byte_at(1) == Some(b'{') {
                        self.end_run(run_start, emit, HclTokenKind::HeredocContent)?;
                        self.open_interpolation(true, emit)?;
                        return Ok(());
                    } else {
                        self.pos += 1;
                    }
                }
                b'\r' => {
                    if self.pos + 1 == line_end && self.byte_at(1) == Some(b'\n') {
                        // The CR of a line-ending CRLF stays inside the
                        // content run; the newline after it is a LineBreak.
                        self.pos += 1;
                    } else {
                        self.end_run(run_start, emit, HclTokenKind::HeredocContent)?;
                        if emit {
                            self.emit_error_region(
                                self.pos,
                                self.pos + 1,
                                codes::LONE_CR,
                                DiagnosticCategory::Lexical,
                            )?;
                        } else {
                            self.recover(
                                codes::LONE_CR,
                                DiagnosticCategory::Lexical,
                                self.pos,
                                self.pos + 1,
                            )?;
                        }
                        self.pos += 1;
                        run_start = self.pos;
                    }
                }
                _ => {
                    let width = self
                        .char_at(self.pos)
                        .expect("scan positions are char boundaries")
                        .len_utf8();
                    self.pos += width;
                }
            }
        }
        self.end_run(run_start, emit, HclTokenKind::HeredocContent)?;
        if line_end < self.end {
            if emit {
                self.emit_kind(HclTokenKind::LineBreak, line_end, line_end + 1)?;
            }
            self.pos = line_end + 1;
        } else {
            self.pos = line_end;
        }
        self.note_heredoc_line()?;
        self.note_heredoc_content()?;
        Ok(())
    }

    /// Opens a quoted template at the current `"`.
    fn open_quoted(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let open = self.pos;
        self.pos += 1;
        self.check_template_depth()?;
        if emit {
            self.emit_kind(HclTokenKind::StringOpen, open, self.pos)?;
        }
        self.stack.push(TemplateFrame::Quoted {
            open,
            buffer: Vec::new(),
            interpolations: 0,
        });
        Ok(())
    }

    /// Opens a heredoc at the current `<<` or `<<-`, or reports a
    /// `hcl.parse.heredoc-marker@1` error region when the introducer does not
    /// form one (RFC 0014 §4.5).
    fn open_heredoc(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        self.pos += 2;
        if self.byte() == Some(b'-') {
            self.pos += 1;
        }
        if self.char_at(self.pos).is_some_and(is_identifier_start) {
            let marker_start = self.pos;
            while let Some(ch) = self.char_at(self.pos) {
                if is_identifier_continue(ch) || ch == '-' {
                    self.pos += ch.len_utf8();
                } else {
                    break;
                }
            }
            let marker_len = self.pos - marker_start;
            if marker_len > self.limits.max_identifier_len {
                return Err(fatal_limit(
                    "identifier-len",
                    marker_len,
                    self.limits.max_identifier_len,
                ));
            }
            let marker = Arc::from(&self.decoded[marker_start..self.pos]);
            // The introducer line ends with spaces or tabs and a newline (or
            // end of file); anything else is not a heredoc introduction.
            let mut line_cursor = self.pos;
            while matches!(self.bytes.get(line_cursor), Some(b' ' | b'\t')) {
                line_cursor += 1;
            }
            let newline_ok = line_cursor >= self.end
                || self.bytes[line_cursor] == b'\n'
                || (self.bytes[line_cursor] == b'\r'
                    && self.bytes.get(line_cursor + 1) == Some(&b'\n'));
            if newline_ok {
                if emit {
                    self.emit_kind(HclTokenKind::HeredocOpen, start, self.pos)?;
                    if line_cursor > self.pos {
                        self.emit_kind(HclTokenKind::Whitespace, self.pos, line_cursor)?;
                    }
                    if line_cursor < self.end {
                        let newline_end = if self.bytes[line_cursor] == b'\r' {
                            line_cursor + 2
                        } else {
                            line_cursor + 1
                        };
                        self.emit_kind(HclTokenKind::LineBreak, line_cursor, newline_end)?;
                        self.pos = newline_end;
                    } else {
                        self.pos = line_cursor;
                    }
                } else if line_cursor < self.end {
                    self.pos = if self.bytes[line_cursor] == b'\r' {
                        line_cursor + 2
                    } else {
                        line_cursor + 1
                    };
                } else {
                    self.pos = line_cursor;
                }
                self.check_template_depth()?;
                self.stack.push(TemplateFrame::Heredoc {
                    marker,
                    content_start: self.pos,
                    bytes: 0,
                    lines: 0,
                    buffer: Vec::new(),
                    interpolations: 0,
                });
                return Ok(());
            }
        }
        if emit {
            self.emit_error_region(
                start,
                self.pos,
                codes::HEREDOC_MARKER,
                DiagnosticCategory::Syntax,
            )?;
        } else {
            self.recover(
                codes::HEREDOC_MARKER,
                DiagnosticCategory::Syntax,
                start,
                self.pos,
            )?;
        }
        Ok(())
    }

    /// Opens an interpolation (`${`) or directive (`%{`) sequence inside a
    /// template, with the optional `~` strip marker included in the open
    /// token.
    fn open_interpolation(
        &mut self,
        directive: bool,
        emit: bool,
    ) -> Result<(), FatalFormationFailure> {
        let open_start = self.pos;
        self.pos += 2;
        if self.byte() == Some(b'~') {
            self.pos += 1;
        }
        if let Some(frame) = self.stack.last_mut() {
            let count = match frame {
                TemplateFrame::Quoted { interpolations, .. }
                | TemplateFrame::Heredoc { interpolations, .. } => {
                    *interpolations += 1;
                    *interpolations
                }
                TemplateFrame::Interp { .. } => return Err(internal_failure()),
            };
            if count > self.limits.max_template_interpolations {
                return Err(fatal_limit(
                    "template-interpolations",
                    count,
                    self.limits.max_template_interpolations,
                ));
            }
        }
        self.check_template_depth()?;
        if emit {
            let kind = if directive {
                HclTokenKind::DirectiveOpen
            } else {
                HclTokenKind::InterpolationOpen
            };
            self.emit_kind(kind, open_start, self.pos)?;
        }
        self.stack.push(TemplateFrame::Interp {
            directive,
            depth: 0,
            interior_start: self.pos,
        });
        Ok(())
    }

    /// Validates one escape sequence of a quoted template (RFC 0014 §4.4):
    /// `\n` `\r` `\t` `\"` `\\` `\uNNNN` `\UNNNNNNNN`.
    fn scan_escape(&mut self) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        self.pos += 1;
        let Some(ch) = self.char_at(self.pos) else {
            self.recover(
                codes::INVALID_ESCAPE,
                DiagnosticCategory::Syntax,
                start,
                self.pos,
            )?;
            return Ok(());
        };
        self.pos += ch.len_utf8();
        let valid = match ch {
            'n' | 'r' | 't' | '"' | '\\' => true,
            'u' => {
                let digits_start = self.pos;
                let consumed = self.consume_hex(4);
                let value = u32::from_str_radix(&self.decoded[digits_start..self.pos], 16).ok();
                consumed == 4 && value.is_some_and(|value| !(0xD800..=0xDFFF).contains(&value))
            }
            'U' => {
                let digits_start = self.pos;
                let consumed = self.consume_hex(8);
                let value = u32::from_str_radix(&self.decoded[digits_start..self.pos], 16).ok();
                consumed == 8
                    && value.is_some_and(|value| {
                        value <= 0x10_FFFF && !(0xD800..=0xDFFF).contains(&value)
                    })
            }
            _ => false,
        };
        if !valid {
            self.recover(
                codes::INVALID_ESCAPE,
                DiagnosticCategory::Syntax,
                start,
                self.pos,
            )?;
        }
        Ok(())
    }

    /// Consumes up to `count` ASCII hex digits; returns how many were found.
    fn consume_hex(&mut self, count: usize) -> usize {
        let mut consumed = 0;
        while consumed < count {
            match self.byte() {
                Some(byte) if byte.is_ascii_hexdigit() => {
                    self.pos += 1;
                    consumed += 1;
                }
                _ => break,
            }
        }
        consumed
    }

    /// Scans one identifier run; the start position is already validated.
    fn scan_identifier(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        while let Some(ch) = self.char_at(self.pos) {
            if is_identifier_continue(ch) || ch == '-' {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        let len = self.pos - start;
        if len > self.limits.max_identifier_len {
            return Err(fatal_limit(
                "identifier-len",
                len,
                self.limits.max_identifier_len,
            ));
        }
        if emit {
            self.emit_kind(HclTokenKind::Identifier, start, self.pos)?;
        }
        Ok(())
    }

    /// Scans one number-shaped run and validates the §4.1 decimal grammar
    /// (RFC 0014 §4.1).
    fn scan_number(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.byte() == Some(b'.') && self.byte_at(1).is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 2;
            while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            let sign = matches!(self.byte_at(1), Some(b'+' | b'-'));
            let digits_start = if sign { 2 } else { 1 };
            if self
                .byte_at(digits_start)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                self.pos += 1;
                if sign {
                    self.pos += 1;
                }
                while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
        }
        // A continuation that cannot start a fresh token makes the whole run
        // one invalid number: hex/octal/binary forms, underscores, a second
        // fraction, or an identifier extension.
        let mut end = self.pos;
        while let Some(ch) = self.char_at(end) {
            if is_identifier_continue(ch) {
                end += ch.len_utf8();
            } else if ch == '.'
                && self
                    .char_at(end + 1)
                    .is_some_and(|next| next.is_ascii_digit())
            {
                end += 2;
            } else {
                break;
            }
        }
        if end > self.pos {
            if emit {
                self.emit_error_region(
                    start,
                    end,
                    codes::INVALID_NUMBER,
                    DiagnosticCategory::Syntax,
                )?;
            } else {
                self.recover(
                    codes::INVALID_NUMBER,
                    DiagnosticCategory::Syntax,
                    start,
                    end,
                )?;
            }
            self.pos = end;
        } else if emit {
            self.emit_kind(HclTokenKind::Number, start, self.pos)?;
        }
        Ok(())
    }

    /// Scans a `//` or `#` line comment up to (not including) the newline.
    fn scan_line_comment(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        while self.pos < self.end && !matches!(self.byte(), Some(b'\n' | b'\r')) {
            self.pos += 1;
        }
        if emit {
            self.emit_kind(HclTokenKind::LineComment, start, self.pos)?;
        }
        Ok(())
    }

    /// Scans a `/* ... */` inline comment, which may span lines; an
    /// unterminated comment is one error region (RFC 0014 §4.1).
    fn scan_inline_comment(&mut self, emit: bool) -> Result<(), FatalFormationFailure> {
        let start = self.pos;
        self.pos += 2;
        while self.pos + 1 < self.end
            && !(self.bytes[self.pos] == b'*' && self.bytes[self.pos + 1] == b'/')
        {
            self.pos += 1;
        }
        if self.pos + 1 < self.end {
            self.pos += 2;
            if emit {
                self.emit_kind(HclTokenKind::InlineComment, start, self.pos)?;
            }
        } else {
            if emit {
                self.emit_error_region(
                    start,
                    self.end,
                    codes::UNTERMINATED_COMMENT,
                    DiagnosticCategory::Syntax,
                )?;
            } else {
                self.recover(
                    codes::UNTERMINATED_COMMENT,
                    DiagnosticCategory::Syntax,
                    start,
                    self.end,
                )?;
            }
            self.pos = self.end;
        }
        Ok(())
    }

    /// Terminates an unterminated quoted template: the buffered content is
    /// discarded and the content becomes one error region to `end` (the
    /// newline or end of file), with `hcl.parse.unterminated-string@1` (RFC
    /// 0014 §3).
    fn terminate_string(&mut self, end: usize) -> Result<(), FatalFormationFailure> {
        let (open, buffer_len) = match self.stack.last() {
            Some(TemplateFrame::Quoted { open, buffer, .. }) => (*open, buffer.len()),
            _ => return Err(internal_failure()),
        };
        let span_len = end - open;
        if span_len > self.limits.max_string_len {
            return Err(fatal_limit(
                "string-len",
                span_len,
                self.limits.max_string_len,
            ));
        }
        if span_len > self.limits.max_template_len {
            return Err(fatal_limit(
                "template-len",
                span_len,
                self.limits.max_template_len,
            ));
        }
        if self.emitting() {
            self.buffered = self.buffered.saturating_sub(buffer_len);
            self.stack.pop();
            self.emit_error_region(
                open + 1,
                end,
                codes::UNTERMINATED_STRING,
                DiagnosticCategory::Syntax,
            )?;
        } else {
            self.stack.pop();
            self.recover(
                codes::UNTERMINATED_STRING,
                DiagnosticCategory::Syntax,
                open + 1,
                end,
            )?;
        }
        Ok(())
    }

    /// Terminates an unterminated heredoc: the buffered content is discarded
    /// and the content becomes one error region to end of file (bounded by
    /// the heredoc size limits), with `hcl.parse.unterminated-heredoc@1`
    /// (RFC 0014 §3, §4.5).
    fn terminate_heredoc(&mut self, end: usize) -> Result<(), FatalFormationFailure> {
        let (content_start, buffer_len) = match self.stack.last() {
            Some(TemplateFrame::Heredoc {
                content_start,
                buffer,
                ..
            }) => (*content_start, buffer.len()),
            _ => return Err(internal_failure()),
        };
        if self.emitting() {
            self.buffered = self.buffered.saturating_sub(buffer_len);
            self.stack.pop();
            self.emit_error_region(
                content_start,
                end,
                codes::UNTERMINATED_HEREDOC,
                DiagnosticCategory::Syntax,
            )?;
        } else {
            self.stack.pop();
            self.recover(
                codes::UNTERMINATED_HEREDOC,
                DiagnosticCategory::Syntax,
                content_start,
                end,
            )?;
        }
        Ok(())
    }

    /// Ends the current literal run as one content token when non-empty.
    fn end_run(
        &mut self,
        run_start: usize,
        emit: bool,
        kind: HclTokenKind,
    ) -> Result<(), FatalFormationFailure> {
        if emit && self.pos > run_start {
            self.emit_kind(kind, run_start, self.pos)?;
        }
        Ok(())
    }

    /// Appends the top frame's buffered tokens to the stream.
    fn flush_buffer(&mut self) {
        if let Some(TemplateFrame::Quoted { buffer, .. } | TemplateFrame::Heredoc { buffer, .. }) =
            self.stack.last_mut()
        {
            let buffered = buffer.len();
            self.tokens.append(buffer);
            self.buffered = self.buffered.saturating_sub(buffered);
        }
    }

    /// Counts one completed content line of every open heredoc.
    fn note_heredoc_line(&mut self) -> Result<(), FatalFormationFailure> {
        for frame in &mut self.stack {
            if let TemplateFrame::Heredoc { lines, .. } = frame {
                *lines += 1;
                if *lines > self.limits.max_heredoc_lines {
                    return Err(fatal_limit(
                        "heredoc-lines",
                        *lines,
                        self.limits.max_heredoc_lines,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Re-accounts the content bytes of the open heredoc against the heredoc
    /// size limits.
    fn note_heredoc_content(&mut self) -> Result<(), FatalFormationFailure> {
        if let Some(TemplateFrame::Heredoc {
            bytes,
            content_start,
            ..
        }) = self.stack.last_mut()
        {
            *bytes = self.pos - *content_start;
            if *bytes > self.limits.max_heredoc_bytes {
                return Err(fatal_limit(
                    "heredoc-bytes",
                    *bytes,
                    self.limits.max_heredoc_bytes,
                ));
            }
            if *bytes > self.limits.max_template_len {
                return Err(fatal_limit(
                    "template-len",
                    *bytes,
                    self.limits.max_template_len,
                ));
            }
        }
        Ok(())
    }

    /// Checks the template nesting depth before a frame push.
    fn check_template_depth(&mut self) -> Result<(), FatalFormationFailure> {
        let depth = self.stack.len() + 1;
        if depth > self.limits.max_template_depth {
            return Err(fatal_limit(
                "template-depth",
                depth,
                self.limits.max_template_depth,
            ));
        }
        Ok(())
    }

    /// Emits one token, buffering it when an open quoted/heredoc template
    /// owns the current position.
    fn emit(&mut self, token: HclToken) -> Result<(), FatalFormationFailure> {
        let count = self.tokens.len() + self.buffered + 1;
        if count > self.limits.common.max_token_count {
            return Err(fatal_limit(
                "token-count",
                count,
                self.limits.common.max_token_count,
            ));
        }
        if count > self.limits.max_syntax_pieces {
            return Err(fatal_limit(
                "syntax-pieces",
                count,
                self.limits.max_syntax_pieces,
            ));
        }
        match self.stack.first_mut() {
            Some(TemplateFrame::Quoted { buffer, .. } | TemplateFrame::Heredoc { buffer, .. }) => {
                buffer.push(token);
                self.buffered += 1;
            }
            _ => self.tokens.push(token),
        }
        Ok(())
    }

    fn emit_kind(
        &mut self,
        kind: HclTokenKind,
        start: usize,
        end: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.emit(HclToken::new(kind, self.span(start, end)?))
    }

    /// Emits one error-region token and records its recovery fact.
    ///
    /// A zero-length region publishes the diagnostic but no token — no empty
    /// piece can exist in the lossless index.
    fn emit_error_region(
        &mut self,
        start: usize,
        end: usize,
        code: &'static str,
        category: DiagnosticCategory,
    ) -> Result<(), FatalFormationFailure> {
        self.recovered = true;
        let span = self.span(start, end)?;
        self.sink.push(Diagnostic::new(
            code,
            category,
            DiagnosticSeverity::Error,
            Some(span.diagnostic_location()),
            0,
        ));
        if end > start {
            self.emit(HclToken::new(HclTokenKind::ErrorRegion, span))?;
            self.error_regions.push(HclErrorRegion::new(span, code));
            if self.error_regions.len() > self.limits.max_recovery_regions {
                return Err(fatal_limit(
                    "recovery-regions",
                    self.error_regions.len(),
                    self.limits.max_recovery_regions,
                ));
            }
            if self.error_regions.len() > self.limits.max_error_regions {
                return Err(fatal_limit(
                    "error-regions",
                    self.error_regions.len(),
                    self.limits.max_error_regions,
                ));
            }
        }
        Ok(())
    }

    /// Records one recovery diagnostic without a piece (absorbed interiors
    /// and zero-length regions).
    fn recover(
        &mut self,
        code: &'static str,
        category: DiagnosticCategory,
        start: usize,
        end: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.recovered = true;
        let span = self.span(start, end)?;
        self.sink.push(Diagnostic::new(
            code,
            category,
            DiagnosticSeverity::Error,
            Some(span.diagnostic_location()),
            0,
        ));
        Ok(())
    }

    /// Pops the template stack at end of source with unterminated diagnostics.
    ///
    /// The outermost unterminated template owns the error region (when it is
    /// emitting); every unterminated construct in the chain publishes its
    /// diagnostic.
    fn finish_eof(&mut self) -> Result<(), FatalFormationFailure> {
        loop {
            match self.stack.last() {
                None => break,
                Some(TemplateFrame::Interp { directive, .. }) => {
                    let code = if *directive {
                        codes::UNTERMINATED_DIRECTIVE
                    } else {
                        codes::UNTERMINATED_INTERPOLATION
                    };
                    let interior_start = match self.stack.last() {
                        Some(TemplateFrame::Interp { interior_start, .. }) => *interior_start,
                        _ => return Err(internal_failure()),
                    };
                    self.stack.pop();
                    self.recover(code, DiagnosticCategory::Syntax, interior_start, self.end)?;
                }
                Some(TemplateFrame::Quoted { .. }) => {
                    self.terminate_string(self.end)?;
                }
                Some(TemplateFrame::Heredoc { .. }) => {
                    self.terminate_heredoc(self.end)?;
                }
            }
        }
        Ok(())
    }

    fn find_line_end(&self) -> usize {
        match self.bytes[self.pos..self.end]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            Some(at) => self.pos + at,
            None => self.end,
        }
    }

    fn byte(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn char_at(&self, pos: usize) -> Option<char> {
        self.decoded.get(pos..)?.chars().next()
    }

    /// Issues one snapshot-bound span; decoded byte offsets are raw byte
    /// offsets under the UTF-8-only source contract.
    fn span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        if start > end || end > self.source.len() {
            return Err(coordinates_failure());
        }
        self.authority
            .span(start, end)
            .map_err(|_| coordinates_failure())
    }

    fn finish(mut self) -> Result<HclLexOutput, FatalFormationFailure> {
        self.tokens.push(HclToken::new(
            HclTokenKind::Eof,
            self.span(self.end, self.end)?,
        ));
        let syntax = if self.build_index {
            let mut pieces = Vec::with_capacity(self.tokens.len());
            let mut kinds = Vec::with_capacity(self.tokens.len());
            for token in &self.tokens {
                let Some(kind) = token.kind().syntax_kind() else {
                    continue;
                };
                pieces.push(StructuralPiece::new(
                    token.span(),
                    token.kind().structural_kind(),
                ));
                kinds.push(kind);
            }
            let index =
                LosslessStructuralIndex::new(self.authority.identity(), self.source.len(), pieces)
                    .map_err(|_| coverage_failure())?;
            (Some(index), Arc::from(kinds))
        } else {
            (None, Arc::from([]))
        };
        Ok(HclLexOutput {
            source: Arc::clone(self.source),
            tokens: self.tokens,
            error_regions: self.error_regions,
            diagnostics: self.sink.finish(),
            recovered: self.recovered,
            syntax: syntax.0,
            syntax_kinds: syntax.1,
            authority: self.authority,
        })
    }
}

/// UAX #31 identifier start: `ID_Start` with underscore excluded (RFC 0014
/// §4.1, §12 D-4).
fn is_identifier_start(ch: char) -> bool {
    ch != '_' && unicode_ident::is_xid_start(ch)
}

/// UAX #31 identifier continuation: `ID_Continue` (underscore included); the
/// hyphen continuation is handled by the scan loops.
fn is_identifier_continue(ch: char) -> bool {
    unicode_ident::is_xid_continue(ch)
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

/// `hcl.limit.<name>@1` resource-limit failure (RFC 0014 §11).
fn fatal_limit(name: &'static str, observed: usize, limit: usize) -> FatalFormationFailure {
    let mut diagnostic = Diagnostic::new(
        format!("hcl.limit.{name}@1"),
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

/// Invalid UTF-8 or source-construction failure mapping (RFC 0014 §2, §11,
/// §12 D-3).
fn invalid_utf8_failure(error: SourceError) -> FatalFormationFailure {
    match error {
        SourceError::InvalidSequence { byte_offset, .. }
        | SourceError::InvalidUtf8 {
            valid_up_to: byte_offset,
        } => FatalFormationFailure::from_diagnostic(Diagnostic::new(
            codes::INVALID_UTF8,
            DiagnosticCategory::Encoding,
            DiagnosticSeverity::Error,
            Some(DiagnosticLocation {
                snapshot: None,
                start_byte: byte_offset as u64,
                end_byte: byte_offset as u64,
            }),
            0,
        )),
        SourceError::ResourceLimit {
            name,
            observed,
            limit,
        } => fatal_limit(name, observed, limit),
        SourceError::OffsetOverflow => fatal(
            "hcl.limit.offset-overflow@1",
            DiagnosticCategory::Resource,
            None,
            &[],
        ),
        SourceError::EncodingConflict { .. } | SourceError::UnsupportedBom { .. } => {
            internal_failure()
        }
    }
}

/// Unreachable encoding state: defensive fatal with no panicking path.
fn encoding_failure() -> FatalFormationFailure {
    fatal(codes::INVALID_UTF8, DiagnosticCategory::Encoding, None, &[])
}

/// Unreachable internal state: defensive fatal with no panicking path.
fn internal_failure() -> FatalFormationFailure {
    fatal(
        "hcl.parse.internal@1",
        DiagnosticCategory::Resource,
        None,
        &[],
    )
}

/// Exhaustive coverage could not be constructed: a fatal condition (RFC 0014
/// §3).
fn coverage_failure() -> FatalFormationFailure {
    fatal(
        "hcl.parse.coverage@1",
        DiagnosticCategory::Syntax,
        None,
        &[],
    )
}

/// Impossible source coordinates: a fatal condition (RFC 0014 §3).
fn coordinates_failure() -> FatalFormationFailure {
    fatal(
        "hcl.parse.coordinates@1",
        DiagnosticCategory::Syntax,
        None,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn lex_ok(bytes: &[u8]) -> HclLexOutput {
        lex(Arc::<[u8]>::from(bytes), HclParseLimits::default())
            .expect("lexer output for a valid UTF-8 source")
    }

    fn lex_with(
        bytes: &[u8],
        limits: HclParseLimits,
    ) -> Result<HclLexOutput, FatalFormationFailure> {
        lex(Arc::<[u8]>::from(bytes), limits)
    }

    /// Compact `(kind, start, end)` summary of the token stream without the
    /// zero-length Eof terminal.
    fn summary(bytes: &[u8]) -> Vec<(HclTokenKind, usize, usize)> {
        lex_ok(bytes)
            .tokens()
            .iter()
            .filter(|token| token.kind() != HclTokenKind::Eof)
            .map(|token| {
                (
                    token.kind(),
                    token.span().start_byte(),
                    token.span().end_byte(),
                )
            })
            .collect()
    }

    fn kinds_only(bytes: &[u8]) -> Vec<HclTokenKind> {
        summary(bytes)
            .into_iter()
            .map(|(kind, _, _)| kind)
            .collect()
    }

    fn codes(bytes: &[u8]) -> Vec<String> {
        lex_ok(bytes)
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    fn expected(codes: &[&str]) -> Vec<String> {
        codes.iter().map(|code| (*code).to_owned()).collect()
    }

    fn limit_code(bytes: &[u8], limits: HclParseLimits) -> String {
        lex_with(bytes, limits)
            .expect_err("limit must be fatal")
            .diagnostics()
            .first()
            .expect("one fatal diagnostic")
            .code
            .clone()
    }

    fn assert_exact_coverage(output: &HclLexOutput) {
        let index = output.syntax().expect("whole-source lex carries the index");
        let mut next = 0;
        for piece in index.pieces() {
            assert_eq!(piece.span().start_byte(), next, "pieces tile without gaps");
            assert!(
                piece.span().end_byte() > piece.span().start_byte(),
                "pieces are non-empty"
            );
            next = piece.span().end_byte();
        }
        assert_eq!(next, output.source().len(), "pieces cover every raw byte");
        assert_eq!(
            index.pieces().len(),
            output.syntax_kinds().len(),
            "kinds parallel pieces"
        );
    }

    fn limited(max: impl Fn(&mut HclParseLimits)) -> HclParseLimits {
        let mut limits = HclParseLimits::default();
        max(&mut limits);
        limits
    }

    #[test]
    fn empty_source_lexes_to_eof_only() {
        let output = lex_ok(b"");
        assert!(!output.is_recovered());
        assert!(output.diagnostics().is_empty());
        assert_eq!(output.tokens().len(), 1);
        assert_eq!(output.tokens()[0].kind(), HclTokenKind::Eof);
        assert_eq!(output.tokens()[0].span().len(), 0);
        assert_exact_coverage(&output);
    }

    #[test]
    fn whitespace_run_spans() {
        assert_eq!(
            summary(b"a \t b"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 4),
                (HclTokenKind::Identifier, 4, 5),
            ]
        );
    }

    #[test]
    fn linebreak_lf_and_crlf_spans() {
        assert_eq!(
            summary(b"a\r\nb\n"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::LineBreak, 1, 3),
                (HclTokenKind::Identifier, 3, 4),
                (HclTokenKind::LineBreak, 4, 5),
            ]
        );
    }

    #[test]
    fn lone_cr_is_recovered() {
        let output = lex_ok(b"a = 1\rb = 2");
        assert!(output.is_recovered());
        assert_eq!(codes(b"a = 1\rb = 2"), expected(&[codes::LONE_CR]));
        assert_eq!(
            summary(b"a = 1\rb = 2"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::Number, 4, 5),
                (HclTokenKind::ErrorRegion, 5, 6),
                (HclTokenKind::Identifier, 6, 7),
                (HclTokenKind::Whitespace, 7, 8),
                (HclTokenKind::Equals, 8, 9),
                (HclTokenKind::Whitespace, 9, 10),
                (HclTokenKind::Number, 10, 11),
            ]
        );
        assert_eq!(output.error_regions()[0].code(), codes::LONE_CR);
        assert_exact_coverage(&output);
    }

    #[test]
    fn hash_and_slash_line_comments() {
        assert_eq!(
            summary(b"# note\nx = 1 // tail\n"),
            vec![
                (HclTokenKind::LineComment, 0, 6),
                (HclTokenKind::LineBreak, 6, 7),
                (HclTokenKind::Identifier, 7, 8),
                (HclTokenKind::Whitespace, 8, 9),
                (HclTokenKind::Equals, 9, 10),
                (HclTokenKind::Whitespace, 10, 11),
                (HclTokenKind::Number, 11, 12),
                (HclTokenKind::Whitespace, 12, 13),
                (HclTokenKind::LineComment, 13, 20),
                (HclTokenKind::LineBreak, 20, 21),
            ]
        );
        // A line comment is trivia; the newline after it is a separate
        // LineBreak piece.
        let output = lex_ok(b"# c\n");
        assert!(!output.is_recovered());
        assert_eq!(
            output.syntax_kinds(),
            &[HclSyntaxKind::LineComment, HclSyntaxKind::LineBreak]
        );
    }

    #[test]
    fn inline_comment_spans_lines() {
        let output = lex_ok(b"a = 1 /* multi\nline */ b = 2");
        assert!(!output.is_recovered());
        assert_eq!(
            summary(b"a = 1 /* multi\nline */ b = 2"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::Number, 4, 5),
                (HclTokenKind::Whitespace, 5, 6),
                (HclTokenKind::InlineComment, 6, 22),
                (HclTokenKind::Whitespace, 22, 23),
                (HclTokenKind::Identifier, 23, 24),
                (HclTokenKind::Whitespace, 24, 25),
                (HclTokenKind::Equals, 25, 26),
                (HclTokenKind::Whitespace, 26, 27),
                (HclTokenKind::Number, 27, 28),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn unterminated_inline_comment_recovered() {
        let output = lex_ok(b"a = 1 /* never closed");
        assert!(output.is_recovered());
        assert_eq!(
            codes(b"a = 1 /* never closed"),
            expected(&[codes::UNTERMINATED_COMMENT])
        );
        assert_eq!(
            summary(b"a = 1 /* never closed"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::Number, 4, 5),
                (HclTokenKind::Whitespace, 5, 6),
                (HclTokenKind::ErrorRegion, 6, 21),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn operators_have_exact_spans() {
        let source = b"== != < > <= >= + - * / % && || !";
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::OpEqual, 0, 2),
                (HclTokenKind::Whitespace, 2, 3),
                (HclTokenKind::OpNotEqual, 3, 5),
                (HclTokenKind::Whitespace, 5, 6),
                (HclTokenKind::OpLess, 6, 7),
                (HclTokenKind::Whitespace, 7, 8),
                (HclTokenKind::OpGreater, 8, 9),
                (HclTokenKind::Whitespace, 9, 10),
                (HclTokenKind::OpLessEqual, 10, 12),
                (HclTokenKind::Whitespace, 12, 13),
                (HclTokenKind::OpGreaterEqual, 13, 15),
                (HclTokenKind::Whitespace, 15, 16),
                (HclTokenKind::OpAdd, 16, 17),
                (HclTokenKind::Whitespace, 17, 18),
                (HclTokenKind::OpSubtract, 18, 19),
                (HclTokenKind::Whitespace, 19, 20),
                (HclTokenKind::Star, 20, 21),
                (HclTokenKind::Whitespace, 21, 22),
                (HclTokenKind::OpDivide, 22, 23),
                (HclTokenKind::Whitespace, 23, 24),
                (HclTokenKind::OpModulo, 24, 25),
                (HclTokenKind::Whitespace, 25, 26),
                (HclTokenKind::OpAnd, 26, 28),
                (HclTokenKind::Whitespace, 28, 29),
                (HclTokenKind::OpOr, 29, 31),
                (HclTokenKind::Whitespace, 31, 32),
                (HclTokenKind::OpNot, 32, 33),
            ]
        );
        let output = lex_ok(source);
        for token in output.tokens() {
            if !matches!(token.kind(), HclTokenKind::Eof | HclTokenKind::Whitespace) {
                assert_eq!(token.kind().syntax_kind(), Some(HclSyntaxKind::Operator));
            }
        }
        assert_exact_coverage(&output);
    }

    #[test]
    fn punctuation_tokens() {
        assert_eq!(
            summary(b"= { } [ ] ( ) , : ? . => ..."),
            vec![
                (HclTokenKind::Equals, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::BraceOpen, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::BraceClose, 4, 5),
                (HclTokenKind::Whitespace, 5, 6),
                (HclTokenKind::BracketOpen, 6, 7),
                (HclTokenKind::Whitespace, 7, 8),
                (HclTokenKind::BracketClose, 8, 9),
                (HclTokenKind::Whitespace, 9, 10),
                (HclTokenKind::ParenOpen, 10, 11),
                (HclTokenKind::Whitespace, 11, 12),
                (HclTokenKind::ParenClose, 12, 13),
                (HclTokenKind::Whitespace, 13, 14),
                (HclTokenKind::Comma, 14, 15),
                (HclTokenKind::Whitespace, 15, 16),
                (HclTokenKind::Colon, 16, 17),
                (HclTokenKind::Whitespace, 17, 18),
                (HclTokenKind::QuestionMark, 18, 19),
                (HclTokenKind::Whitespace, 19, 20),
                (HclTokenKind::Dot, 20, 21),
                (HclTokenKind::Whitespace, 21, 22),
                (HclTokenKind::Arrow, 22, 24),
                (HclTokenKind::Whitespace, 24, 25),
                (HclTokenKind::Ellipsis, 25, 28),
            ]
        );
    }

    #[test]
    fn invalid_characters_recovered() {
        let source = b"a = ~$@;\\";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        let diagnostics = codes(source);
        assert_eq!(
            diagnostics,
            vec![
                codes::INVALID_CHARACTER,
                codes::INVALID_CHARACTER,
                codes::INVALID_CHARACTER,
                codes::INVALID_CHARACTER,
                codes::INVALID_CHARACTER,
            ]
        );
        assert_eq!(output.error_regions().len(), 5);
        assert_exact_coverage(&output);
    }

    #[test]
    fn double_colon_is_error_token() {
        // D-6: `::` is never an operator; the namespaced function form has no
        // spec production.
        let output = lex_ok(b"a = foo::bar()");
        assert!(output.is_recovered());
        assert_eq!(
            codes(b"a = foo::bar()"),
            expected(&[codes::INVALID_CHARACTER])
        );
        assert_eq!(
            summary(b"a = foo::bar()"),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::Identifier, 4, 7),
                (HclTokenKind::ErrorRegion, 7, 9),
                (HclTokenKind::Identifier, 9, 12),
                (HclTokenKind::ParenOpen, 12, 13),
                (HclTokenKind::ParenClose, 13, 14),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn identifiers_ascii_hyphen_and_underscore_continue() {
        assert_eq!(
            kinds_only(b"foo-bar foo_bar foo1 a-b-c"),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Identifier,
            ]
        );
        // A hyphen inside an identifier is a continuation, so `b-1` is one
        // identifier while `b - 1` is three tokens.
        assert_eq!(kinds_only(b"b-1"), vec![HclTokenKind::Identifier]);
        assert_eq!(
            kinds_only(b"b - 1"),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::OpSubtract,
                HclTokenKind::Whitespace,
                HclTokenKind::Number,
            ]
        );
    }

    #[test]
    fn identifiers_unicode_letters() {
        for name in ["caf\u{e9}", "\u{540d}\u{524d}", "\u{3bb}"] {
            let source = format!("{name} = 1");
            let tokens = kinds_only(source.as_bytes());
            assert_eq!(
                tokens,
                vec![
                    HclTokenKind::Identifier,
                    HclTokenKind::Whitespace,
                    HclTokenKind::Equals,
                    HclTokenKind::Whitespace,
                    HclTokenKind::Number,
                ]
            );
        }
        // An emoji is not an ID_Start: it is an invalid character.
        let source = "\u{1f600} = 1";
        assert!(lex_ok(source.as_bytes()).is_recovered());
        assert_eq!(
            codes(source.as_bytes()),
            expected(&[codes::INVALID_CHARACTER])
        );
    }

    #[test]
    fn leading_underscore_identifier_rejected() {
        // D-4: `_` is not an ID_Start, so `_foo` is Recovered while `foo_`
        // stays a valid identifier.
        let output = lex_ok(b"_foo = 1");
        assert!(output.is_recovered());
        assert_eq!(codes(b"_foo = 1"), expected(&[codes::IDENTIFIER]));
        assert_eq!(
            summary(b"_foo = 1"),
            vec![
                (HclTokenKind::ErrorRegion, 0, 1),
                (HclTokenKind::Identifier, 1, 4),
                (HclTokenKind::Whitespace, 4, 5),
                (HclTokenKind::Equals, 5, 6),
                (HclTokenKind::Whitespace, 6, 7),
                (HclTokenKind::Number, 7, 8),
            ]
        );
        assert!(!lex_ok(b"foo_ = 1").is_recovered());
        assert!(!lex_ok(b"foo_bar = 1").is_recovered());
        assert_exact_coverage(&output);
    }

    #[test]
    fn keyword_spellings_are_identifiers() {
        let output = lex_ok(b"true = 1\nfalse = 2\nnull = 3");
        assert!(!output.is_recovered());
        assert_eq!(
            kinds_only(b"true = 1\nfalse = 2\nnull = 3"),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Equals,
                HclTokenKind::Whitespace,
                HclTokenKind::Number,
                HclTokenKind::LineBreak,
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Equals,
                HclTokenKind::Whitespace,
                HclTokenKind::Number,
                HclTokenKind::LineBreak,
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Equals,
                HclTokenKind::Whitespace,
                HclTokenKind::Number,
            ]
        );
    }

    #[test]
    fn identifier_length_limit_fatal() {
        let limits = limited(|limits| limits.max_identifier_len = 4);
        assert_eq!(
            limit_code(b"longname = 1", limits),
            "hcl.limit.identifier-len@1"
        );
        // The limit applies inside interpolation interiors as well.
        assert_eq!(
            limit_code(b"a = \"${longname}\"", limits),
            "hcl.limit.identifier-len@1"
        );
    }

    #[test]
    fn number_token_spans_matrix() {
        let source = b"0 007 123 1.5 1e3 1E+3 1.5e-2 15e-1";
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Number, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Number, 2, 5),
                (HclTokenKind::Whitespace, 5, 6),
                (HclTokenKind::Number, 6, 9),
                (HclTokenKind::Whitespace, 9, 10),
                (HclTokenKind::Number, 10, 13),
                (HclTokenKind::Whitespace, 13, 14),
                (HclTokenKind::Number, 14, 17),
                (HclTokenKind::Whitespace, 17, 18),
                (HclTokenKind::Number, 18, 22),
                (HclTokenKind::Whitespace, 22, 23),
                (HclTokenKind::Number, 23, 29),
                (HclTokenKind::Whitespace, 29, 30),
                (HclTokenKind::Number, 30, 35),
            ]
        );
        assert!(!lex_ok(source).is_recovered());
    }

    #[test]
    fn invalid_number_forms_recovered() {
        // `5.` is excluded here: `5` is a valid number and `.` is a Dot
        // token, so the `5.` rejection is a parser-side grammar error.
        for spelling in [
            "0x10", "0b1", "0o7", "1_000", "1e", "1.2.3", "123abc", "1e3x", "0x",
        ] {
            let source = format!("a = {spelling}");
            let output = lex_ok(source.as_bytes());
            assert!(
                output.is_recovered(),
                "spelling {spelling:?} must be Recovered"
            );
            assert_eq!(
                codes(source.as_bytes()),
                vec![codes::INVALID_NUMBER],
                "spelling {spelling:?}"
            );
            let tokens = summary(source.as_bytes());
            let error = tokens
                .iter()
                .find(|(kind, _, _)| *kind == HclTokenKind::ErrorRegion)
                .expect("one error region token");
            assert_eq!(
                &source[error.1..error.2],
                spelling,
                "error region covers the run"
            );
            assert_exact_coverage(&output);
        }
        // `1e+`: the run covers `1e`; the `+` is a fresh operator token.
        let source = b"a = 1e+";
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::ErrorRegion, 4, 6),
                (HclTokenKind::OpAdd, 6, 7),
            ]
        );
        assert_eq!(codes(source), expected(&[codes::INVALID_NUMBER]));
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn number_following_operator_not_extended() {
        assert_eq!(
            kinds_only(b"1-2"),
            vec![
                HclTokenKind::Number,
                HclTokenKind::OpSubtract,
                HclTokenKind::Number,
            ]
        );
        assert_eq!(
            kinds_only(b"1 + 2"),
            vec![
                HclTokenKind::Number,
                HclTokenKind::Whitespace,
                HclTokenKind::OpAdd,
                HclTokenKind::Whitespace,
                HclTokenKind::Number,
            ]
        );
        assert!(!lex_ok(b"1-2").is_recovered());
    }

    #[test]
    fn dot_number_after_identifier_is_token_sequence() {
        // D-5: `foo.0` lexes as the legal token sequence Identifier Dot
        // Number; the rejection is the parser's grammar error
        // (`GetAttr = "." Identifier`), recorded at M3.
        assert_eq!(
            kinds_only(b"foo.0"),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Dot,
                HclTokenKind::Number,
            ]
        );
        assert!(!lex_ok(b"foo.0").is_recovered());
    }

    #[test]
    fn quoted_template_basic_pieces() {
        let source = b"a = \"hello\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::StringContent, 5, 10),
                (HclTokenKind::StringClose, 10, 11),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn empty_quoted_template() {
        assert_eq!(
            summary(b"\"\""),
            vec![
                (HclTokenKind::StringOpen, 0, 1),
                (HclTokenKind::StringClose, 1, 2),
            ]
        );
        assert!(!lex_ok(b"\"\"").is_recovered());
    }

    #[test]
    fn valid_escape_sequences() {
        let source = b"a = \"\\n\\r\\t\\\"\\\\\\u0041\\U0001F600\"";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            summary(source)
                .iter()
                .filter(|(kind, _, _)| *kind == HclTokenKind::StringContent)
                .count(),
            1
        );
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn invalid_escape_sequences_recovered() {
        for escape in ["\\q", "\\u12", "\\uD800", "\\U00110000", "\\U12"] {
            let source = format!("\"{escape}\"");
            let output = lex_ok(source.as_bytes());
            assert!(output.is_recovered(), "escape {escape:?} must be Recovered");
            assert_eq!(codes(source.as_bytes()), expected(&[codes::INVALID_ESCAPE]));
        }
        // A lone trailing backslash is an invalid escape; with no closing
        // quote the string is unterminated as well.
        let source = b"\"abc\\";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        let diagnostics = codes(source);
        assert!(diagnostics.contains(&codes::INVALID_ESCAPE.to_owned()));
        assert!(diagnostics.contains(&codes::UNTERMINATED_STRING.to_owned()));
        // The content stays a StringContent piece; only the diagnostic marks
        // the recovery.
        let source = b"\"\\q\"";
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::StringOpen, 0, 1),
                (HclTokenKind::StringContent, 1, 3),
                (HclTokenKind::StringClose, 3, 4),
            ]
        );
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn escaped_interpolation_markers_are_literal() {
        let source = b"a = \"$${x} %%{y}\"";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            kinds_only(source),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Equals,
                HclTokenKind::Whitespace,
                HclTokenKind::StringOpen,
                HclTokenKind::StringContent,
                HclTokenKind::StringClose,
            ]
        );
    }

    #[test]
    fn interpolation_piece_shapes() {
        let source = b"a = \"x${y + 1}z\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::StringContent, 5, 6),
                (HclTokenKind::InterpolationOpen, 6, 8),
                (HclTokenKind::InterpolationContent, 8, 13),
                (HclTokenKind::InterpolationClose, 13, 14),
                (HclTokenKind::StringContent, 14, 15),
                (HclTokenKind::StringClose, 15, 16),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn interpolation_strip_markers() {
        let source = b"a = \"${~ x ~}\"";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::InterpolationOpen, 5, 8),
                (HclTokenKind::InterpolationContent, 8, 11),
                (HclTokenKind::InterpolationClose, 11, 13),
                (HclTokenKind::StringClose, 13, 14),
            ]
        );
        // A bare `~` inside the interior is an invalid character.
        let source = b"\"${a ~ b}\"";
        assert!(lex_ok(source).is_recovered());
        assert_eq!(codes(source), expected(&[codes::INVALID_CHARACTER]));
    }

    #[test]
    fn interpolation_nested_braces() {
        let source = b"a = \"${ {b = 1} }\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::InterpolationOpen, 5, 7),
                (HclTokenKind::InterpolationContent, 7, 16),
                (HclTokenKind::InterpolationClose, 16, 17),
                (HclTokenKind::StringClose, 17, 18),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn interpolation_nested_quoted_template() {
        let source = b"a = \"${ \"x${y}\" }\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::InterpolationOpen, 5, 7),
                (HclTokenKind::InterpolationContent, 7, 16),
                (HclTokenKind::InterpolationClose, 16, 17),
                (HclTokenKind::StringClose, 17, 18),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn interpolation_multiline() {
        let source = b"a = \"${ 1 +\n2 }\"";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::InterpolationOpen, 5, 7),
                (HclTokenKind::InterpolationContent, 7, 14),
                (HclTokenKind::InterpolationClose, 14, 15),
                (HclTokenKind::StringClose, 15, 16),
            ]
        );
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn interpolation_containing_heredoc() {
        let source = b"a = \"${ <<EOT\nx\nEOT\n}\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        let tokens = summary(source);
        assert_eq!(tokens.first(), Some(&(HclTokenKind::Identifier, 0, 1)));
        assert_eq!(tokens.last(), Some(&(HclTokenKind::StringClose, 21, 22)));
        // The whole heredoc lives inside the one opaque interior token.
        assert!(tokens.iter().any(|(kind, start, end)| *kind
            == HclTokenKind::InterpolationContent
            && *start == 7
            && *end == 20));
        assert_exact_coverage(&output);
    }

    #[test]
    fn directive_piece_shapes() {
        let source = b"a = \"x%{ if y }z\"";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::StringContent, 5, 6),
                (HclTokenKind::DirectiveOpen, 6, 8),
                (HclTokenKind::DirectiveContent, 8, 14),
                (HclTokenKind::DirectiveClose, 14, 15),
                (HclTokenKind::StringContent, 15, 16),
                (HclTokenKind::StringClose, 16, 17),
            ]
        );
        // Directives admit the strip markers on either brace.
        let source = b"a = \"%{~ if y ~}\"";
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::DirectiveOpen, 5, 8),
                (HclTokenKind::DirectiveContent, 8, 14),
                (HclTokenKind::DirectiveClose, 14, 16),
                (HclTokenKind::StringClose, 16, 17),
            ]
        );
    }

    #[test]
    fn unterminated_string_ends_at_line() {
        let source = b"a = \"abc\nb = 2\n";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::UNTERMINATED_STRING]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::ErrorRegion, 5, 8),
                (HclTokenKind::LineBreak, 8, 9),
                (HclTokenKind::Identifier, 9, 10),
                (HclTokenKind::Whitespace, 10, 11),
                (HclTokenKind::Equals, 11, 12),
                (HclTokenKind::Whitespace, 12, 13),
                (HclTokenKind::Number, 13, 14),
                (HclTokenKind::LineBreak, 14, 15),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn unterminated_string_at_eof() {
        let source = b"a = \"abc";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::UNTERMINATED_STRING]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::ErrorRegion, 5, 8),
            ]
        );
        assert_exact_coverage(&output);
        // A quote alone at end of file has an empty region: the diagnostic
        // fires and the pieces still tile.
        let output = lex_ok(b"a = \"");
        assert!(output.is_recovered());
        assert_eq!(codes(b"a = \""), expected(&[codes::UNTERMINATED_STRING]));
        assert_exact_coverage(&output);
    }

    #[test]
    fn unterminated_interpolation_at_eof() {
        let source = b"a = \"abc${x";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(
            codes(source),
            vec![
                codes::UNTERMINATED_STRING,
                codes::UNTERMINATED_INTERPOLATION
            ]
        );
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::ErrorRegion, 5, 11),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn unterminated_directive_at_eof() {
        let source = b"a = \"x%{if";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(
            codes(source),
            vec![codes::UNTERMINATED_STRING, codes::UNTERMINATED_DIRECTIVE]
        );
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::ErrorRegion, 5, 10),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn string_length_limit_fatal() {
        let limits = limited(|limits| limits.max_string_len = 8);
        assert_eq!(
            limit_code(b"a = \"hello world\"", limits),
            "hcl.limit.string-len@1"
        );
        let limits = limited(|limits| limits.max_template_len = 8);
        assert_eq!(
            limit_code(b"a = \"hello world\"", limits),
            "hcl.limit.template-len@1"
        );
    }

    #[test]
    fn interpolation_count_limit_fatal() {
        let limits = limited(|limits| limits.max_template_interpolations = 2);
        assert_eq!(
            limit_code(b"a = \"${x}${y}${z}\"", limits),
            "hcl.limit.template-interpolations@1"
        );
    }

    #[test]
    fn template_depth_limit_fatal() {
        let limits = limited(|limits| limits.max_template_depth = 3);
        let source = b"a = \"${ \"${ \"${x}\" }\" }\"";
        assert_eq!(limit_code(source, limits), "hcl.limit.template-depth@1");
    }

    #[test]
    fn heredoc_basic_pieces() {
        let source = b"x = <<EOT\nhello\nEOT\ny = 2\n";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::HeredocOpen, 4, 9),
                (HclTokenKind::LineBreak, 9, 10),
                (HclTokenKind::HeredocContent, 10, 15),
                (HclTokenKind::LineBreak, 15, 16),
                (HclTokenKind::HeredocClose, 16, 19),
                (HclTokenKind::LineBreak, 19, 20),
                (HclTokenKind::Identifier, 20, 21),
                (HclTokenKind::Whitespace, 21, 22),
                (HclTokenKind::Equals, 22, 23),
                (HclTokenKind::Whitespace, 23, 24),
                (HclTokenKind::Number, 24, 25),
                (HclTokenKind::LineBreak, 25, 26),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_strip_indent_introducer() {
        let source = b"x = <<-EOT\n  a\n    b\nEOT\n";
        assert!(!lex_ok(source).is_recovered());
        assert_eq!(
            summary(source)
                .iter()
                .find(|(kind, _, _)| *kind == HclTokenKind::HeredocOpen),
            Some(&(HclTokenKind::HeredocOpen, 4, 10))
        );
        // The indentation facts are preserved exactly in the content spans;
        // the `<<-` stripping is a literal-value read, never destructive.
        let tokens = summary(source);
        assert!(tokens.contains(&(HclTokenKind::HeredocContent, 11, 14)));
        assert!(tokens.contains(&(HclTokenKind::HeredocContent, 15, 20)));
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn heredoc_closing_line_leading_spaces() {
        // D-8: the closing line may be preceded by spaces or tabs.
        assert!(!lex_ok(b"x = <<EOT\na\n\t EOT\n").is_recovered());
        let source = b"x = <<EOT\na\n\t EOT\n";
        let tokens = summary(source);
        assert!(tokens.contains(&(HclTokenKind::HeredocClose, 12, 17)));
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn heredoc_closing_line_trailing_whitespace() {
        // D-8: trailing whitespace after the marker is ignored.
        assert!(!lex_ok(b"x = <<EOT\na\nEOT  \t\n").is_recovered());
        let source = b"x = <<EOT\na\nEOT  \t\n";
        assert!(summary(source).contains(&(HclTokenKind::HeredocClose, 12, 18)));
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn heredoc_closing_line_crlf() {
        assert!(!lex_ok(b"x = <<EOT\r\na\r\nEOT\r\n").is_recovered());
        let source = b"x = <<EOT\r\na\r\nEOT\r\n";
        let tokens = summary(source);
        assert!(tokens.contains(&(HclTokenKind::HeredocOpen, 4, 9)));
        assert!(tokens.contains(&(HclTokenKind::HeredocClose, 14, 18)));
        assert_exact_coverage(&lex_ok(source));
    }

    #[test]
    fn heredoc_marker_line_with_content_is_content() {
        // A line containing the marker followed by any other content is not
        // a closing line.
        let source = b"x = <<EOT\nEOT x\nEOT\n";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        let tokens = summary(source);
        assert!(tokens.contains(&(HclTokenKind::HeredocContent, 10, 15)));
        assert!(tokens.contains(&(HclTokenKind::HeredocClose, 16, 19)));
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_content_interpolation_pieces() {
        let source = b"x = <<EOT\nhi ${name}\nEOT\n";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::HeredocOpen, 4, 9),
                (HclTokenKind::LineBreak, 9, 10),
                (HclTokenKind::HeredocContent, 10, 13),
                (HclTokenKind::InterpolationOpen, 13, 15),
                (HclTokenKind::InterpolationContent, 15, 19),
                (HclTokenKind::InterpolationClose, 19, 20),
                (HclTokenKind::LineBreak, 20, 21),
                (HclTokenKind::HeredocClose, 21, 24),
                (HclTokenKind::LineBreak, 24, 25),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_escaped_interpolation_literal() {
        let source = b"x = <<EOT\n$${a} %%{b}\nEOT\n";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            kinds_only(source),
            vec![
                HclTokenKind::Identifier,
                HclTokenKind::Whitespace,
                HclTokenKind::Equals,
                HclTokenKind::Whitespace,
                HclTokenKind::HeredocOpen,
                HclTokenKind::LineBreak,
                HclTokenKind::HeredocContent,
                HclTokenKind::LineBreak,
                HclTokenKind::HeredocClose,
                HclTokenKind::LineBreak,
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_quoted_marker_rejected() {
        // The quoted-marker form `<<"EOT"` does not exist in the current
        // specification (RFC 0014 §4.5).
        let source = b"x = <<\"EOT\"";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::HEREDOC_MARKER]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::ErrorRegion, 4, 6),
                (HclTokenKind::StringOpen, 6, 7),
                (HclTokenKind::StringContent, 7, 10),
                (HclTokenKind::StringClose, 10, 11),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_marker_followed_by_junk_rejected() {
        let source = b"x = <<EOT, y";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::HEREDOC_MARKER]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::ErrorRegion, 4, 9),
                (HclTokenKind::Comma, 9, 10),
                (HclTokenKind::Whitespace, 10, 11),
                (HclTokenKind::Identifier, 11, 12),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_unterminated_at_eof() {
        let source = b"x = <<EOT\nhello\n";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::UNTERMINATED_HEREDOC]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::HeredocOpen, 4, 9),
                (HclTokenKind::LineBreak, 9, 10),
                (HclTokenKind::ErrorRegion, 10, 16),
            ]
        );
        assert_exact_coverage(&output);
        // An introducer at end of file with no content at all is still an
        // unterminated heredoc.
        let output = lex_ok(b"x = <<EOT");
        assert!(output.is_recovered());
        assert_eq!(
            codes(b"x = <<EOT"),
            expected(&[codes::UNTERMINATED_HEREDOC])
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_unterminated_with_content_lines() {
        let source = b"x = <<EOT\na\nb\n";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::UNTERMINATED_HEREDOC]));
        // All content lines are one error region; nothing unproven is
        // asserted as HeredocContent.
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::HeredocOpen, 4, 9),
                (HclTokenKind::LineBreak, 9, 10),
                (HclTokenKind::ErrorRegion, 10, 14),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn heredoc_lines_limit_fatal() {
        let limits = limited(|limits| limits.max_heredoc_lines = 2);
        assert_eq!(
            limit_code(b"x = <<EOT\na\nb\nc\nEOT\n", limits),
            "hcl.limit.heredoc-lines@1"
        );
    }

    #[test]
    fn heredoc_bytes_limit_fatal() {
        let limits = limited(|limits| limits.max_heredoc_bytes = 4);
        assert_eq!(
            limit_code(b"x = <<EOT\nabcdef\nEOT\n", limits),
            "hcl.limit.heredoc-bytes@1"
        );
        let limits = limited(|limits| limits.max_template_len = 4);
        assert_eq!(
            limit_code(b"x = <<EOT\nabcdef\nEOT\n", limits),
            "hcl.limit.template-len@1"
        );
    }

    #[test]
    fn heredoc_inside_interpolation_absorbed() {
        let source = b"a = \"${ <<EOT\n}\nEOT\n}\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        let tokens = summary(source);
        // The `}` inside the heredoc content must not close the
        // interpolation: the content is absorbed and the interpolation closes
        // at the final `}`.
        assert!(tokens.contains(&(HclTokenKind::InterpolationOpen, 5, 7)));
        assert!(tokens.contains(&(HclTokenKind::InterpolationClose, 20, 21)));
        assert_exact_coverage(&output);
    }

    #[test]
    fn leading_bom_recovered() {
        // D-1: the oracle strips a leading BOM; Consema forms Recovered with
        // hcl.parse.byte-order-mark@1 and an ErrorRegion piece (no Bom kind).
        let source = b"\xEF\xBB\xBFa = 1\n";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_eq!(codes(source), expected(&[codes::BYTE_ORDER_MARK]));
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::ErrorRegion, 0, 3),
                (HclTokenKind::Identifier, 3, 4),
                (HclTokenKind::Whitespace, 4, 5),
                (HclTokenKind::Equals, 5, 6),
                (HclTokenKind::Whitespace, 6, 7),
                (HclTokenKind::Number, 7, 8),
                (HclTokenKind::LineBreak, 8, 9),
            ]
        );
        assert_eq!(output.error_regions()[0].code(), codes::BYTE_ORDER_MARK);
        assert_exact_coverage(&output);
    }

    #[test]
    fn bom_elsewhere_recovered() {
        // A U+FEFF outside template literal content is likewise Recovered.
        let source = "a = 1\n\u{FEFF}b = 2\n";
        let output = lex_ok(source.as_bytes());
        assert!(output.is_recovered());
        assert_eq!(
            codes(source.as_bytes()),
            expected(&[codes::BYTE_ORDER_MARK])
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn bom_inside_string_is_literal() {
        // A U+FEFF inside template literal content is literal text, matching
        // the pinned oracle — no untracked divergence.
        let source = "a = \"x\u{FEFF}y\"\n";
        let output = lex_ok(source.as_bytes());
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source.as_bytes())
                .iter()
                .find(|(kind, _, _)| *kind == HclTokenKind::StringContent),
            Some(&(HclTokenKind::StringContent, 5, 10))
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn invalid_utf8_fatal() {
        // D-3: invalid UTF-8 is a fatal formation failure with the HCL code.
        let error =
            lex_with(b"a = \xFF", HclParseLimits::default()).expect_err("invalid UTF-8 is fatal");
        assert_eq!(error.diagnostics()[0].code, "hcl.parse.invalid-utf8@1");
        assert_eq!(
            error.diagnostics()[0].category,
            DiagnosticCategory::Encoding
        );
        // A UTF-16 BOM is invalid UTF-8 under the UTF-8-only contract.
        let error = lex_with(b"\xFF\xFEa = 1", HclParseLimits::default())
            .expect_err("UTF-16 BOM is invalid UTF-8");
        assert_eq!(error.diagnostics()[0].code, "hcl.parse.invalid-utf8@1");
    }

    #[test]
    fn all_thirty_kinds_assembled() {
        let source = b"# c\na = [1, {x: 2}]\nb = \"s${v}%{if q}\"\nc = <<E\nh ${i}\nE\nd = (f ? 1 : 2) != 3\n/* block\ncomment */\ne = foo.bar\nf = @\n";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert_exact_coverage(&output);
        let kinds: HashSet<HclSyntaxKind> = output.syntax_kinds().iter().copied().collect();
        assert_eq!(kinds.len(), 30, "all thirty kinds appear in one document");
        for kind in [
            HclSyntaxKind::Whitespace,
            HclSyntaxKind::LineBreak,
            HclSyntaxKind::LineComment,
            HclSyntaxKind::InlineComment,
            HclSyntaxKind::Identifier,
            HclSyntaxKind::Equals,
            HclSyntaxKind::Number,
            HclSyntaxKind::StringOpen,
            HclSyntaxKind::StringContent,
            HclSyntaxKind::StringClose,
            HclSyntaxKind::InterpolationOpen,
            HclSyntaxKind::InterpolationContent,
            HclSyntaxKind::InterpolationClose,
            HclSyntaxKind::DirectiveOpen,
            HclSyntaxKind::DirectiveContent,
            HclSyntaxKind::DirectiveClose,
            HclSyntaxKind::HeredocOpen,
            HclSyntaxKind::HeredocContent,
            HclSyntaxKind::HeredocClose,
            HclSyntaxKind::BraceOpen,
            HclSyntaxKind::BraceClose,
            HclSyntaxKind::BracketOpen,
            HclSyntaxKind::BracketClose,
            HclSyntaxKind::ParenOpen,
            HclSyntaxKind::ParenClose,
            HclSyntaxKind::Comma,
            HclSyntaxKind::Colon,
            HclSyntaxKind::QuestionMark,
            HclSyntaxKind::Operator,
            HclSyntaxKind::ErrorRegion,
        ] {
            assert!(kinds.contains(&kind), "kind {kind:?} must appear");
        }
    }

    #[test]
    fn eof_token_is_zero_length_last() {
        let output = lex_ok(b"a = 1\n");
        let tokens = output.tokens();
        let last = tokens.last().expect("Eof terminal");
        assert_eq!(last.kind(), HclTokenKind::Eof);
        assert_eq!(last.span().len(), 0);
        assert_eq!(last.span().start_byte(), output.source().len());
        assert_eq!(last.span().end_byte(), output.source().len());
    }

    #[test]
    fn truncation_closure_keeps_coverage() {
        // Every truncation of every corpus source lexes without panic and
        // keeps exhaustive piece coverage.
        let corpus: [&[u8]; 6] = [
            b"a = 1\nb = 2\n",
            b"x = \"${y + 1}\"\n",
            b"h = <<E\nz ${q}\nE\n",
            b"a = [1, {x: 2}]\n",
            b"\xEF\xBB\xBFa = 1\n",
            b"a = \"unterminated",
        ];
        for source in corpus {
            for cut in 0..=source.len() {
                match lex_with(&source[..cut], HclParseLimits::default()) {
                    Ok(output) => assert_exact_coverage(&output),
                    Err(error) => {
                        assert!(
                            error
                                .diagnostics()
                                .iter()
                                .any(|d| d.code.starts_with("hcl.limit.")
                                    || d.code == "hcl.parse.invalid-utf8@1"),
                            "fatal truncation outcome: {:?}",
                            error.diagnostics().first().map(|d| d.code.as_str())
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn mutation_closure_never_panics() {
        let source = b"a = 1 + \"${x}\"\n# c\n";
        let mut mutations = 0;
        for index in 0..source.len() {
            for byte in *b"A\n\"0\x00\xFF\xEF$%<\\" {
                let mut mutated = source.to_vec();
                mutated[index] = byte;
                match lex_with(&mutated, HclParseLimits::default()) {
                    Ok(output) => assert_exact_coverage(&output),
                    Err(error) => {
                        assert!(
                            error
                                .diagnostics()
                                .iter()
                                .any(|d| d.code.starts_with("hcl.limit.")
                                    || d.code == "hcl.parse.invalid-utf8@1"),
                            "fatal mutation outcome: {:?}",
                            error.diagnostics().first().map(|d| d.code.as_str())
                        );
                    }
                }
                mutations += 1;
            }
        }
        assert_eq!(mutations, source.len() * 11);
    }

    #[test]
    fn token_count_limit_fatal() {
        let limits = limited(|limits| limits.common.max_token_count = 6);
        assert_eq!(
            limit_code(b"a = 1 + 2 + 3\n", limits),
            "hcl.limit.token-count@1"
        );
    }

    #[test]
    fn syntax_pieces_limit_fatal() {
        let limits = limited(|limits| limits.max_syntax_pieces = 6);
        assert_eq!(
            limit_code(b"a = 1 + 2 + 3\n", limits),
            "hcl.limit.syntax-pieces@1"
        );
    }

    #[test]
    fn recovery_regions_limit_fatal() {
        let limits = limited(|limits| limits.max_recovery_regions = 1);
        assert_eq!(
            limit_code(b"@ @ @\n", limits),
            "hcl.limit.recovery-regions@1"
        );
        let limits = limited(|limits| limits.max_error_regions = 1);
        assert_eq!(limit_code(b"@ @ @\n", limits), "hcl.limit.error-regions@1");
    }

    #[test]
    fn diagnostic_truncation_marker() {
        let limits = limited(|limits| limits.common.max_diagnostics = 2);
        let output = lex_with(b"@ @ @ @ @\n", limits).expect("recovered lex");
        let codes: Vec<&str> = output
            .diagnostics()
            .iter()
            .map(|d| d.code.as_str())
            .collect();
        assert!(codes.contains(&"core.diagnostic.truncated@1"));
        assert!(output.is_recovered());
        assert_exact_coverage(&output);
    }

    #[test]
    fn region_lex_binds_spans_to_authority() {
        let source =
            Arc::new(SourceSnapshot::from_utf8(b"a = \"${x + 1}\"\n".to_vec()).expect("utf-8"));
        let authority = DocumentAuthority::fresh();
        let output = lex_region(
            Arc::clone(&source),
            authority.clone(),
            7,
            12,
            HclParseLimits::default(),
        )
        .expect("region lex");
        assert!(output.syntax().is_none());
        assert!(!output.is_recovered());
        let tokens = output.tokens();
        assert_eq!(
            tokens.first().map(HclToken::kind),
            Some(HclTokenKind::Identifier)
        );
        assert_eq!(
            tokens.first().map(HclToken::span),
            Some(authority.span(7, 8).expect("span"))
        );
        assert_eq!(tokens.last().map(HclToken::kind), Some(HclTokenKind::Eof));
        assert_eq!(
            tokens.last().map(HclToken::span),
            Some(authority.span(12, 12).expect("span"))
        );
    }

    #[test]
    fn comments_inside_interpolation_are_scanned() {
        // Comments may appear inside interpolation sequences.
        let source = b"a = \"${x // c\n+ y}\"";
        let output = lex_ok(source);
        assert!(!output.is_recovered());
        assert_eq!(
            summary(source),
            vec![
                (HclTokenKind::Identifier, 0, 1),
                (HclTokenKind::Whitespace, 1, 2),
                (HclTokenKind::Equals, 2, 3),
                (HclTokenKind::Whitespace, 3, 4),
                (HclTokenKind::StringOpen, 4, 5),
                (HclTokenKind::InterpolationOpen, 5, 7),
                (HclTokenKind::InterpolationContent, 7, 17),
                (HclTokenKind::InterpolationClose, 17, 18),
                (HclTokenKind::StringClose, 18, 19),
            ]
        );
        assert_exact_coverage(&output);
    }

    #[test]
    fn comment_bytes_inside_interpolation_are_absorbed() {
        // An unterminated inline comment inside an interpolation interior is
        // a diagnostic without a piece: the interior stays one opaque token.
        let source = b"a = \"${x /* oops}";
        let output = lex_ok(source);
        assert!(output.is_recovered());
        assert!(
            codes(source)
                .iter()
                .any(|code| code == codes::UNTERMINATED_COMMENT)
        );
        assert_exact_coverage(&output);
    }
}
