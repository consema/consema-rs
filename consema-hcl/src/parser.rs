//! HCL body/expression parser: the native tree assembly and the grammar half
//! of the RFC 0014 §12 divergence inventory (RFC 0014 §3-§4).
//!
//! The parser consumes the frozen token stream of the M2 lexer in one
//! deterministic forward pass. It builds the native body tree — attributes
//! and blocks interleaved in source order, per-body duplicate-attribute
//! exclusion, quoted and naked labels, the full expression grammar of
//! §4.3-§4.6 with its precedence table, and quoted/heredoc template parts
//! with escape-decoded literal text and interpolation/directive expressions.
//! Interpolation and directive interiors are re-lexed through [`lex_region`],
//! which binds their spans to the same snapshot identity, so every native
//! span of the document shares one authority.
//!
//! # Recovery semantics (RFC 0014 §3)
//!
//! Lexical deviations were already recovered by the lexer. Parser-level
//! deviations form Recovered output with one `hcl.parse.*@1` diagnostic and
//! one [`HclErrorRegion`] per failed body item; the failed item never enters
//! the native model and never fabricates a closing delimiter, identifier,
//! equals sign, value, or attribute. Item-level recovery is deterministic:
//! an expression that fails to parse ends its error region at the end of its
//! line, except that an unterminated bracket/paren/brace extends the region
//! to the matching close if one exists and to end of line otherwise, and the
//! region never consumes a closing delimiter that belongs to the enclosing
//! body. After an error region ends, body parsing resumes at the next line
//! and every independently proven item survives. The missing-newline
//! terminator after an attribute or block is a diagnostic-only recovery: the
//! item survives and the following tokens to the end of the line are
//! consumed. A duplicate attribute in one body is a diagnostic-only
//! recovery: the first occurrence stays native and the duplicate stays an
//! inspectable syntax piece. End of file terminates the last attribute,
//! block, or one-line block without a trailing newline (RFC 0014 §12 D-9).
//!
//! # Divergence inventory (grammar half)
//!
//! - D-5 `foo.0`: the `GetAttr = "." Identifier` production admits
//!   identifiers only, so a dot followed by a number is an expression error;
//! - D-6 `foo::bar()`: `::` is already an error region at the lexer, so a
//!   namespaced call is an expression error at the parser;
//! - D-7 single-identifier for-directive: the key identifier is read only
//!   when a comma follows, so `%{ for x in list }` is valid;
//! - D-8 heredoc closing line: the lexer matched it with the Go
//!   `bytes.TrimSpace` semantics; the parser preserves the closing-line span
//!   as a representation fact;
//! - D-9 EOF-terminated body item: end of file terminates the last item
//!   without a newline.
//!
//! # Limits
//!
//! The parser enforces the expression-depth budget (shared by the binary and
//! unary chain lengths), the body nesting depth, the per-body attribute,
//! block, and item counts, the per-block label count, the canonical-decimal
//! digit count of one number, the tuple/object constructor extents, the
//! for-expression byte extent, and the merged recovery/error region counts.
//! Every limit failure is a fatal `hcl.limit.<name>@1` failure; a limit
//! failure never masquerades as a partial document (hard gate 4).

use crate::HclParseLimits;
use crate::expression::{
    BinaryOp, HclCallArg, HclDirectiveKind, HclExpression, HclExpressionKind, HclForIntro,
    HclNumber, HclObjectEntry, HclObjectKey, HclTemplateKey, HclTemplatePart, HclTraversalRoot,
    HclTraversalStep, HeredocFacts, HeredocMode, ObjectSeparator, UnaryOp, canonical_decimal,
};
use crate::lexer::{HclLexOutput, HclToken, HclTokenKind, lex, lex_region};
use crate::native::{
    HclAttribute, HclBlock, HclBlockLabel, HclBody, HclBodyItem, HclDocument, HclErrorRegion,
    HclSyntaxKind,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BomPolicy, DocumentAuthority, EncodingRequest, FatalFormationFailure, FormationStatus,
    LosslessStructuralIndex, SourceEncoding, SourceError, SourceLimits, SourceSnapshot, Span,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Stable `hcl.parse.*@1` parser diagnostic codes (RFC 0014 §3, §4, §11).
mod codes {
    /// A body item is neither an attribute nor a block.
    pub const ITEM: &str = "hcl.parse.item@1";
    /// An attribute is missing its `=` or its expression.
    pub const ATTRIBUTE: &str = "hcl.parse.attribute@1";
    /// A block header is invalid or the block is never closed.
    pub const BLOCK: &str = "hcl.parse.block@1";
    /// A quoted block label contains a template sequence.
    pub const LABEL: &str = "hcl.parse.label@1";
    /// An expression violates the §4.3-§4.6 grammar.
    pub const EXPRESSION: &str = "hcl.parse.expression@1";
    /// A template directive interior is malformed.
    pub const DIRECTIVE: &str = "hcl.parse.directive@1";
    /// An attribute or block is not terminated by a newline (RFC 0014 §2).
    pub const NEWLINE: &str = "hcl.parse.newline@1";
    /// A tuple or object element is not separated by a comma or newline.
    pub const SEPARATOR: &str = "hcl.parse.separator@1";
    /// A second attribute with the same name appears in one body (RFC 0014
    /// §3); the duplicate never enters the native model.
    pub const DUPLICATE_ATTRIBUTE: &str = "hcl.parse.duplicate-attribute@1";
}

/// One formed HCL document (RFC 0014 §3), parallel to `PlistFormedXml`.
///
/// `Complete` requires exhaustive byte coverage under the frozen grammar and
/// every configured limit. `Recovered` retains the immutable source,
/// exhaustive piece coverage, ordered diagnostics, the merged error regions,
/// and every independently proven construct; the native [`HclDocument`] is
/// always present — an empty body is a valid body — and its spans are bound
/// to the same snapshot identity as the lossless syntax index. The profile
/// layer that gates Complete formation (M4) consumes this type.
#[derive(Clone, Debug)]
pub struct HclFormed {
    source: Arc<SourceSnapshot>,
    /// Consumed by the M4 native-domain query surface (RFC 0014 §7.1).
    authority: DocumentAuthority,
    status: FormationStatus,
    diagnostics: Vec<Diagnostic>,
    document: HclDocument,
    error_regions: Vec<HclErrorRegion>,
    syntax: LosslessStructuralIndex,
    syntax_kinds: Arc<[HclSyntaxKind]>,
    /// Consumed by the M4 query and edit domains for limit enforcement.
    limits: HclParseLimits,
}

impl HclFormed {
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

    /// Ordered diagnostics from formation, deterministically sorted.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Native body tree bound to the frozen source.
    #[must_use]
    pub const fn document(&self) -> &HclDocument {
        &self.document
    }

    /// Recovered error regions in source order: one per non-empty
    /// `ErrorRegion` piece of the lexer and one per failed body item of the
    /// parser, each with its stable `hcl.parse.*@1` code.
    #[must_use]
    pub fn error_regions(&self) -> &[HclErrorRegion] {
        &self.error_regions
    }

    /// Exhaustive ordered lossless piece coverage of the raw bytes.
    #[must_use]
    pub fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.syntax
    }

    /// Ordered syntax kinds, parallel to the lossless structural pieces.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[HclSyntaxKind] {
        &self.syntax_kinds
    }

    /// Snapshot-bound identity authority for issuing query handles (M4
    /// adaptation point).
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        &self.authority
    }

    /// Limits applied during formation (M4 adaptation point).
    #[must_use]
    pub(crate) const fn limits(&self) -> HclParseLimits {
        self.limits
    }
}

/// Forms one HCL document from raw bytes under the frozen UTF-8 source
/// contract (RFC 0014 §2).
///
/// The source contract is enforced by the lexer: UTF-8 only, BOM as
/// content with `hcl.parse.byte-order-mark@1` recovery, lone CR never a
/// newline, invalid UTF-8 fatal. The parser then consumes the token stream
/// and assembles the native body tree with the §3 recovery semantics. The
/// whole formation is side-effect free: nothing is ever evaluated (hard
/// gate 1).
/// M3 formation entry point; consumed by the M4 profile layer
/// (crate::document::Document::parse) and by the materialization domain.
pub(crate) fn parse_hcl(
    bytes: Arc<[u8]>,
    limits: HclParseLimits,
) -> Result<HclFormed, FatalFormationFailure> {
    let lexed = lex(Arc::clone(&bytes), limits)?;
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
        .map_err(source_failure)?,
    );
    Parser::new(&lexed, source, limits, limits.common.max_diagnostics)?.parse()
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

/// Expression context: whether newline sequences are whitespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExprMode {
    /// Body-level expression: newlines and line comments end the expression.
    Top,
    /// Expression inside brackets, parens, calls, or template interiors:
    /// newlines are ignored as whitespace (RFC 0014 §2, §4.3).
    Nested,
}

/// The terminator of one body parse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyEnd {
    /// The root body ends at end of file only.
    Eof,
    /// A nested body ends at a closing brace or end of file.
    BraceClose,
}

/// One open bracket of the expression parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delim {
    Brace,
    Bracket,
    Paren,
}

impl Delim {
    const fn matches(self, kind: HclTokenKind) -> bool {
        match self {
            Self::Brace => matches!(kind, HclTokenKind::BraceClose),
            Self::Bracket => matches!(kind, HclTokenKind::BracketClose),
            Self::Paren => matches!(kind, HclTokenKind::ParenClose),
        }
    }
}

/// Why one attribute occurrence failed to form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttributeFailure {
    /// The `=` sign is missing or not on the same line as the name.
    MissingEquals,
    /// The expression after `=` is missing or invalid.
    MissingExpression,
}

/// The outcome of one attribute parse.
enum AttributeOutcome {
    Formed(HclAttribute),
    Failed(AttributeFailure),
}

/// One deterministic parser pass over the frozen lexer token stream.
struct Parser<'a> {
    lexed: &'a HclLexOutput,
    /// Rebuilt snapshot of the same bytes, bound to the native document.
    source: Arc<SourceSnapshot>,
    /// Decoded text of the lexer's snapshot; byte offsets are identical
    /// under the UTF-8-only source contract.
    decoded: &'a str,
    authority: DocumentAuthority,
    limits: HclParseLimits,
    tokens: &'a [HclToken],
    pos: usize,
    sink: DiagnosticSink,
    recovered: bool,
    error_regions: Vec<HclErrorRegion>,
    /// Brackets opened by the expression parser but never closed; taken by
    /// the recovery scan when the enclosing item fails (RFC 0014 §3).
    brackets: Vec<Delim>,
}

impl<'a> Parser<'a> {
    fn new(
        lexed: &'a HclLexOutput,
        source: Arc<SourceSnapshot>,
        limits: HclParseLimits,
        sink_cap: usize,
    ) -> Result<Self, FatalFormationFailure> {
        let decoded = lexed.source().decoded_text().ok_or_else(encoding_failure)?;
        Ok(Self {
            lexed,
            source,
            decoded,
            authority: lexed.authority().clone(),
            limits,
            tokens: lexed.tokens(),
            pos: 0,
            sink: DiagnosticSink::new(sink_cap),
            recovered: false,
            error_regions: Vec::new(),
            brackets: Vec::new(),
        })
    }

    fn parse(mut self) -> Result<HclFormed, FatalFormationFailure> {
        for diagnostic in self.lexed.diagnostics() {
            self.sink.push(diagnostic.clone());
        }
        for region in self.lexed.error_regions() {
            self.error_regions.push(region.clone());
        }
        self.recovered |= self.lexed.is_recovered();
        self.check_error_region_limits()?;
        let body = self.parse_body(1, BodyEnd::Eof)?;
        let status = if self.recovered {
            FormationStatus::Recovered
        } else {
            FormationStatus::Complete
        };
        let document = HclDocument::new(Arc::clone(&self.source), body);
        let syntax = self.lexed.syntax().cloned().ok_or_else(coverage_failure)?;
        let syntax_kinds = Arc::from(self.lexed.syntax_kinds());
        self.error_regions
            .sort_by_key(|region| region.span().start_byte());
        Ok(HclFormed {
            source: self.source,
            authority: self.authority,
            status,
            diagnostics: self.sink.finish(),
            document,
            error_regions: self.error_regions,
            syntax,
            syntax_kinds,
            limits: self.limits,
        })
    }

    // -- token cursor ------------------------------------------------------

    fn peek(&self) -> HclToken {
        self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn peek_kind(&self) -> HclTokenKind {
        self.peek().kind()
    }

    fn advance(&mut self) -> HclToken {
        let token = self.peek();
        if token.kind() != HclTokenKind::Eof {
            self.pos += 1;
        }
        token
    }

    fn at(&self, kind: HclTokenKind) -> bool {
        self.peek_kind() == kind
    }

    fn eat(&mut self, kind: HclTokenKind) -> Option<HclToken> {
        if self.at(kind) {
            Some(self.advance())
        } else {
            None
        }
    }

    /// Skips whitespace and inline comments (inline comments may span
    /// lines but count as whitespace; RFC 0014 §4.1).
    fn skip_trivia(&mut self) {
        while matches!(
            self.peek_kind(),
            HclTokenKind::Whitespace | HclTokenKind::InlineComment
        ) {
            self.pos += 1;
        }
    }

    /// Skips all trivia, including newlines and line comments.
    fn skip_structural(&mut self) {
        while matches!(
            self.peek_kind(),
            HclTokenKind::Whitespace
                | HclTokenKind::InlineComment
                | HclTokenKind::LineBreak
                | HclTokenKind::LineComment
        ) {
            self.pos += 1;
        }
    }

    fn skip_expression_trivia(&mut self, mode: ExprMode) {
        if mode == ExprMode::Top {
            self.skip_trivia();
        } else {
            self.skip_structural();
        }
    }

    /// Exact token text derived from the frozen decoded text; the result
    /// borrows the decoded text, not the parser, so the token stream stays
    /// mutable between calls.
    fn text(&self, token: HclToken) -> &'a str {
        &self.decoded[token.span().start_byte()..token.span().end_byte()]
    }

    fn span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        if start > end || end > self.source.len() {
            return Err(coordinates_failure());
        }
        self.authority
            .span(start, end)
            .map_err(|_| coordinates_failure())
    }

    // -- diagnostics and recovery ------------------------------------------

    /// Records one recovery diagnostic and marks the parse Recovered.
    fn diagnose(&mut self, code: &'static str, span: Span, category: DiagnosticCategory) {
        self.recovered = true;
        self.sink.push(Diagnostic::new(
            code,
            category,
            DiagnosticSeverity::Error,
            Some(span.diagnostic_location()),
            0,
        ));
    }

    /// Emits one error region with its diagnostic; a zero-length region
    /// publishes the diagnostic only, never an empty piece.
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
            self.error_regions.push(HclErrorRegion::new(span, code));
            self.check_error_region_limits()?;
        }
        Ok(())
    }

    fn check_error_region_limits(&self) -> Result<(), FatalFormationFailure> {
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
        Ok(())
    }

    /// Fails one body item: emits the error region from the item start to
    /// the deterministic recovery boundary and advances past the region.
    ///
    /// The boundary follows RFC 0014 §3: the end of the line when no
    /// bracket opened by the failed expression is still open; the matching
    /// close of the innermost open bracket when one exists; end of file
    /// otherwise. A closing delimiter that would close an enclosing body
    /// construct stops the region before it and is never consumed; a
    /// zero-length region publishes the diagnostic only.
    fn fail_item(&mut self, start: usize, code: &'static str) -> Result<(), FatalFormationFailure> {
        let brackets = std::mem::take(&mut self.brackets);
        let boundary = self.scan_recovery(brackets)?;
        self.emit_error_region(start, boundary, code, DiagnosticCategory::Syntax)
    }

    /// Scans forward from the current token to the recovery boundary and
    /// advances `pos` to the boundary token (the region end is returned).
    ///
    /// Whitespace and comments are consumed; a newline or line comment stops
    /// the scan when no bracket is open; end of file always stops it. An
    /// open bracket pushes; a close bracket that matches the innermost open
    /// bracket pops it and ends the region after the close when the stack
    /// empties; a close bracket with an empty stack ends the region before
    /// it; a mismatched close discards the innermost open bracket and the
    /// scan continues.
    fn scan_recovery(&mut self, mut stack: Vec<Delim>) -> Result<usize, FatalFormationFailure> {
        loop {
            let token = self.peek();
            match token.kind() {
                HclTokenKind::Eof => return Ok(self.source.len()),
                HclTokenKind::LineBreak | HclTokenKind::LineComment => {
                    if stack.is_empty() {
                        return Ok(token.span().start_byte());
                    }
                    self.pos += 1;
                }
                HclTokenKind::BraceOpen | HclTokenKind::BracketOpen | HclTokenKind::ParenOpen => {
                    if let Some(delim) = delim_of(token.kind()) {
                        stack.push(delim);
                    }
                    self.pos += 1;
                }
                HclTokenKind::BraceClose
                | HclTokenKind::BracketClose
                | HclTokenKind::ParenClose => {
                    if stack.is_empty() {
                        return Ok(token.span().start_byte());
                    }
                    if stack.last().is_some_and(|open| open.matches(token.kind())) {
                        stack.pop();
                        if stack.is_empty() {
                            self.pos += 1;
                            return Ok(token.span().end_byte());
                        }
                    } else {
                        stack.pop();
                    }
                    self.pos += 1;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    /// Consumes tokens through the next `}` at brace depth zero and returns
    /// its end byte; `None` at end of file. Used to close a one-line block
    /// whose content is invalid (the Go `recover(TokenCBrace)` shape).
    fn scan_to_close_brace(&mut self) -> Option<usize> {
        let mut braces = 0usize;
        loop {
            let token = self.peek();
            match token.kind() {
                HclTokenKind::Eof => return None,
                HclTokenKind::BraceOpen => {
                    braces += 1;
                    self.pos += 1;
                }
                HclTokenKind::BraceClose => {
                    if braces == 0 {
                        self.pos += 1;
                        return Some(token.span().end_byte());
                    }
                    braces -= 1;
                    self.pos += 1;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    // -- body grammar ------------------------------------------------------

    fn parse_body(&mut self, depth: usize, end: BodyEnd) -> Result<HclBody, FatalFormationFailure> {
        if depth > self.limits.max_body_depth {
            return Err(fatal_limit("body-depth", depth, self.limits.max_body_depth));
        }
        let mut items: Vec<HclBodyItem> = Vec::new();
        let mut attribute_count = 0usize;
        let mut block_count = 0usize;
        let mut item_count = 0usize;
        let mut names: HashSet<Arc<str>> = HashSet::new();
        loop {
            self.skip_structural();
            let token = self.peek();
            match token.kind() {
                HclTokenKind::Eof => break,
                HclTokenKind::BraceClose if end == BodyEnd::BraceClose => {
                    // The caller consumes the closing brace.
                    break;
                }
                HclTokenKind::Identifier => {
                    let token = self.advance();
                    let name = Arc::from(self.text(token));
                    self.skip_trivia();
                    match self.peek_kind() {
                        HclTokenKind::Equals => {
                            item_count += 1;
                            attribute_count += 1;
                            if item_count > self.limits.max_body_item_count {
                                return Err(fatal_limit(
                                    "body-item-count",
                                    item_count,
                                    self.limits.max_body_item_count,
                                ));
                            }
                            if attribute_count > self.limits.max_attribute_count {
                                return Err(fatal_limit(
                                    "attribute-count",
                                    attribute_count,
                                    self.limits.max_attribute_count,
                                ));
                            }
                            match self.parse_attribute(token, Arc::clone(&name), false)? {
                                AttributeOutcome::Formed(attribute) => {
                                    if names.insert(Arc::clone(&name)) {
                                        items.push(HclBodyItem::Attribute(attribute));
                                    } else {
                                        // The duplicate stays a proven
                                        // syntax piece but never a native
                                        // attribute (RFC 0014 §3).
                                        self.diagnose(
                                            codes::DUPLICATE_ATTRIBUTE,
                                            token.span(),
                                            DiagnosticCategory::Syntax,
                                        );
                                    }
                                }
                                AttributeOutcome::Failed(failure) => {
                                    self.fail_item(token.span().start_byte(), failure.code())?;
                                }
                            }
                        }
                        HclTokenKind::StringOpen
                        | HclTokenKind::BraceOpen
                        | HclTokenKind::Identifier => {
                            item_count += 1;
                            block_count += 1;
                            if item_count > self.limits.max_body_item_count {
                                return Err(fatal_limit(
                                    "body-item-count",
                                    item_count,
                                    self.limits.max_body_item_count,
                                ));
                            }
                            if block_count > self.limits.max_block_count {
                                return Err(fatal_limit(
                                    "block-count",
                                    block_count,
                                    self.limits.max_block_count,
                                ));
                            }
                            if let Some(block) = self.parse_block(token, depth)? {
                                items.push(HclBodyItem::Block(block));
                            }
                        }
                        _ => {
                            self.fail_item(token.span().start_byte(), codes::ITEM)?;
                        }
                    }
                }
                _ => {
                    if matches!(
                        token.kind(),
                        HclTokenKind::BraceClose
                            | HclTokenKind::BracketClose
                            | HclTokenKind::ParenClose
                    ) {
                        // An orphan closing delimiter at this body level:
                        // it closes no open construct, so it is consumed
                        // with a diagnostic instead of starting an item.
                        self.diagnose(codes::ITEM, token.span(), DiagnosticCategory::Syntax);
                        self.advance();
                    } else {
                        self.fail_item(token.span().start_byte(), codes::ITEM)?;
                    }
                }
            }
        }
        Ok(HclBody::from_items(items))
    }

    fn parse_attribute(
        &mut self,
        name_token: HclToken,
        name: Arc<str>,
        single_line: bool,
    ) -> Result<AttributeOutcome, FatalFormationFailure> {
        self.skip_trivia();
        let Some(equals) = self.eat(HclTokenKind::Equals) else {
            return Ok(AttributeOutcome::Failed(AttributeFailure::MissingEquals));
        };
        self.skip_trivia();
        let Some(expression) = self.parse_expression(ExprMode::Top, 0)? else {
            return Ok(AttributeOutcome::Failed(
                AttributeFailure::MissingExpression,
            ));
        };
        if !single_line {
            self.skip_trivia();
            match self.peek_kind() {
                HclTokenKind::LineBreak | HclTokenKind::LineComment | HclTokenKind::Eof => {}
                _ => {
                    // The attribute is proven; only its terminator is
                    // missing (RFC 0014 §2, §12 D-9).
                    self.diagnose(
                        codes::NEWLINE,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    self.scan_recovery(Vec::new())?;
                }
            }
        }
        Ok(AttributeOutcome::Formed(HclAttribute::new(
            name,
            name_token.span(),
            equals.span(),
            expression,
        )))
    }

    fn parse_block(
        &mut self,
        type_token: HclToken,
        depth: usize,
    ) -> Result<Option<HclBlock>, FatalFormationFailure> {
        let block_start = type_token.span().start_byte();
        let block_type = Arc::from(self.text(type_token));
        let mut labels: Vec<HclBlockLabel> = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek_kind() {
                HclTokenKind::Identifier => {
                    let token = self.advance();
                    labels.push(HclBlockLabel::new(
                        Arc::from(self.text(token)),
                        token.span(),
                        false,
                    ));
                    if labels.len() > self.limits.max_label_count {
                        return Err(fatal_limit(
                            "label-count",
                            labels.len(),
                            self.limits.max_label_count,
                        ));
                    }
                }
                HclTokenKind::StringOpen => {
                    let Some(label) = self.parse_quoted_label()? else {
                        self.fail_item(block_start, codes::LABEL)?;
                        return Ok(None);
                    };
                    labels.push(label);
                    if labels.len() > self.limits.max_label_count {
                        return Err(fatal_limit(
                            "label-count",
                            labels.len(),
                            self.limits.max_label_count,
                        ));
                    }
                }
                HclTokenKind::BraceOpen => break,
                _ => {
                    self.fail_item(block_start, codes::BLOCK)?;
                    return Ok(None);
                }
            }
        }
        self.advance(); // open brace
        self.skip_trivia();
        let body = match self.peek_kind() {
            HclTokenKind::LineBreak | HclTokenKind::LineComment => {
                self.skip_structural();
                let body = self.parse_body(depth + 1, BodyEnd::BraceClose)?;
                if self.at(HclTokenKind::BraceClose) {
                    let close = self.advance();
                    (body, close.span().end_byte())
                } else {
                    self.fail_item(block_start, codes::BLOCK)?;
                    return Ok(None);
                }
            }
            HclTokenKind::BraceClose => {
                let close = self.advance();
                (
                    HclBody::from_items(Vec::<HclBodyItem>::new()),
                    close.span().end_byte(),
                )
            }
            HclTokenKind::Eof => {
                self.fail_item(block_start, codes::BLOCK)?;
                return Ok(None);
            }
            _ => {
                let Some(formed) = self.parse_one_line_body(block_start)? else {
                    return Ok(None);
                };
                formed
            }
        };
        let close_end = body.1;
        let body = body.0;
        self.skip_trivia();
        match self.peek_kind() {
            HclTokenKind::LineBreak | HclTokenKind::LineComment | HclTokenKind::Eof => {}
            _ => {
                self.diagnose(
                    codes::NEWLINE,
                    self.peek().span(),
                    DiagnosticCategory::Syntax,
                );
                self.scan_recovery(Vec::new())?;
            }
        }
        let span = self.span(block_start, close_end)?;
        Ok(Some(HclBlock::new(block_type, labels.into(), body, span)))
    }

    /// Parses one quoted block label: a quoted literal string without any
    /// interpolation or directive sequence (RFC 0014 §4.2). `None` when the
    /// template is unterminated (already recovered at the lexer) or contains
    /// a template sequence.
    fn parse_quoted_label(&mut self) -> Result<Option<HclBlockLabel>, FatalFormationFailure> {
        let open = self.advance();
        let mut text = String::new();
        loop {
            let token = self.peek();
            match token.kind() {
                HclTokenKind::StringContent => {
                    self.advance();
                    text.push_str(&decode_quoted_literal(self.text(token)));
                }
                HclTokenKind::StringClose => {
                    let close = self.advance();
                    return Ok(Some(HclBlockLabel::new(
                        Arc::from(text),
                        self.span(open.span().start_byte(), close.span().end_byte())?,
                        true,
                    )));
                }
                HclTokenKind::ErrorRegion | HclTokenKind::Eof => {
                    // Unterminated at the lexer; the lexer already published
                    // its diagnostic.
                    return Ok(None);
                }
                _ => {
                    self.diagnose(codes::LABEL, token.span(), DiagnosticCategory::Syntax);
                    return Ok(None);
                }
            }
        }
    }

    /// Parses a one-line block body: at most one attribute, closed by `}`
    /// on the same line (RFC 0014 §4.2).
    ///
    /// Returns `None` when the block is never closed; the failure region is
    /// emitted by the caller through the block-start path only for the
    /// unclosed forms. A failing single attribute dies with its own region
    /// and the block still closes.
    fn parse_one_line_body(
        &mut self,
        block_start: usize,
    ) -> Result<Option<(HclBody, usize)>, FatalFormationFailure> {
        match self.peek_kind() {
            HclTokenKind::BraceClose => {
                let close = self.advance();
                Ok(Some((
                    HclBody::from_items(Vec::new()),
                    close.span().end_byte(),
                )))
            }
            HclTokenKind::Eof => {
                self.fail_item(block_start, codes::BLOCK)?;
                Ok(None)
            }
            HclTokenKind::Identifier => {
                let name_token = self.advance();
                let name = Arc::from(self.text(name_token));
                match self.parse_attribute(name_token, name, true)? {
                    AttributeOutcome::Formed(attribute) => {
                        self.skip_trivia();
                        match self.peek_kind() {
                            HclTokenKind::BraceClose => {
                                let close = self.advance();
                                Ok(Some((
                                    HclBody::from_items(vec![HclBodyItem::Attribute(attribute)]),
                                    close.span().end_byte(),
                                )))
                            }
                            HclTokenKind::Eof => {
                                self.fail_item(block_start, codes::BLOCK)?;
                                Ok(None)
                            }
                            _ => {
                                self.diagnose(
                                    codes::BLOCK,
                                    self.peek().span(),
                                    DiagnosticCategory::Syntax,
                                );
                                let Some(close_end) = self.scan_to_close_brace() else {
                                    self.fail_item(block_start, codes::BLOCK)?;
                                    return Ok(None);
                                };
                                Ok(Some((
                                    HclBody::from_items(vec![HclBodyItem::Attribute(attribute)]),
                                    close_end,
                                )))
                            }
                        }
                    }
                    AttributeOutcome::Failed(failure) => {
                        self.fail_item(name_token.span().start_byte(), failure.code())?;
                        let Some(close_end) = self.scan_to_close_brace() else {
                            self.fail_item(block_start, codes::BLOCK)?;
                            return Ok(None);
                        };
                        Ok(Some((HclBody::from_items(Vec::new()), close_end)))
                    }
                }
            }
            _ => {
                self.diagnose(codes::BLOCK, self.peek().span(), DiagnosticCategory::Syntax);
                let Some(close_end) = self.scan_to_close_brace() else {
                    self.fail_item(block_start, codes::BLOCK)?;
                    return Ok(None);
                };
                Ok(Some((HclBody::from_items(Vec::new()), close_end)))
            }
        }
    }

    // -- expression grammar ------------------------------------------------

    fn parse_expression(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        if depth >= self.limits.max_expression_depth {
            return Err(fatal_limit(
                "expression-depth",
                depth + 1,
                self.limits.max_expression_depth,
            ));
        }
        self.parse_conditional(mode, depth)
    }

    fn parse_conditional(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(condition) = self.parse_or(mode, depth)? else {
            return Ok(None);
        };
        self.skip_trivia();
        if !self.at(HclTokenKind::QuestionMark) {
            return Ok(Some(condition));
        }
        self.advance();
        let Some(then) = self.parse_conditional(mode, depth + 1)? else {
            return Ok(None);
        };
        self.skip_trivia();
        if self.eat(HclTokenKind::Colon).is_none() {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        let Some(else_) = self.parse_conditional(mode, depth + 1)? else {
            return Ok(None);
        };
        let span = self.span(condition.span().start_byte(), else_.span().end_byte())?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::Conditional {
                condition: Box::new(condition),
                then: Box::new(then),
                else_: Box::new(else_),
            },
            span,
        )))
    }

    /// One left-associative binary level; the precedence ladder is `||`,
    /// `&&`, `==`/`!=`, `<`/`>`/`<=`/`>=`, `+`/`-`, `*`/`/`/`%` (RFC 0014
    /// §4.3). The chain length is bounded by the expression depth so a
    /// left-deep chain can never overflow the structural-equality
    /// recursion.
    fn parse_or(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_and(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            if !self.at(HclTokenKind::OpOr) {
                break;
            }
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_and(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(BinaryOp::Or, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn parse_and(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_equality(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            if !self.at(HclTokenKind::OpAnd) {
                break;
            }
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_equality(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(BinaryOp::And, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn parse_equality(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_relational(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            let op = match self.peek_kind() {
                HclTokenKind::OpEqual => BinaryOp::Equal,
                HclTokenKind::OpNotEqual => BinaryOp::NotEqual,
                _ => break,
            };
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_relational(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn parse_relational(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_additive(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            let op = match self.peek_kind() {
                HclTokenKind::OpLess => BinaryOp::Less,
                HclTokenKind::OpGreater => BinaryOp::Greater,
                HclTokenKind::OpLessEqual => BinaryOp::LessEqual,
                HclTokenKind::OpGreaterEqual => BinaryOp::GreaterEqual,
                _ => break,
            };
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_additive(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn parse_additive(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_multiplicative(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            let op = match self.peek_kind() {
                HclTokenKind::OpAdd => BinaryOp::Add,
                HclTokenKind::OpSubtract => BinaryOp::Subtract,
                _ => break,
            };
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_multiplicative(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn parse_multiplicative(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(mut lhs) = self.parse_term(mode, depth)? else {
            return Ok(None);
        };
        let mut chain = 0usize;
        loop {
            self.skip_trivia();
            let op = match self.peek_kind() {
                HclTokenKind::Star => BinaryOp::Multiply,
                HclTokenKind::OpDivide => BinaryOp::Divide,
                HclTokenKind::OpModulo => BinaryOp::Modulo,
                _ => break,
            };
            chain += 1;
            if chain > self.limits.max_expression_depth {
                return Err(fatal_limit(
                    "expression-depth",
                    chain,
                    self.limits.max_expression_depth,
                ));
            }
            self.advance();
            self.skip_expression_trivia(mode);
            let Some(rhs) = self.parse_term(mode, depth)? else {
                return Ok(None);
            };
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(Some(lhs))
    }

    fn binary(
        &mut self,
        op: BinaryOp,
        lhs: HclExpression,
        rhs: HclExpression,
    ) -> Result<HclExpression, FatalFormationFailure> {
        let span = self.span(lhs.span().start_byte(), rhs.span().end_byte())?;
        Ok(HclExpression::new(
            HclExpressionKind::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
            span,
        ))
    }

    /// The term layer: unary chains over the base term and its postfix
    /// traversal steps (RFC 0014 §4.3).
    fn parse_term(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        if depth >= self.limits.max_expression_depth {
            return Err(fatal_limit(
                "expression-depth",
                depth + 1,
                self.limits.max_expression_depth,
            ));
        }
        self.skip_expression_trivia(mode);
        let token = self.peek();
        match token.kind() {
            HclTokenKind::OpSubtract | HclTokenKind::OpNot => {
                let op_token = self.advance();
                let op = if op_token.kind() == HclTokenKind::OpSubtract {
                    UnaryOp::Minus
                } else {
                    UnaryOp::Not
                };
                let Some(operand) = self.parse_term(mode, depth + 1)? else {
                    return Ok(None);
                };
                let span = self.span(op_token.span().start_byte(), operand.span().end_byte())?;
                Ok(Some(HclExpression::new(
                    HclExpressionKind::Unary {
                        op,
                        operand: Box::new(operand),
                    },
                    span,
                )))
            }
            HclTokenKind::Number => {
                let token = self.advance();
                let number = self.number(token)?;
                Ok(Some(HclExpression::new(
                    HclExpressionKind::Number(number),
                    token.span(),
                )))
            }
            HclTokenKind::StringOpen => {
                let Some((parts, span)) = self.parse_quoted_template(depth)? else {
                    return Ok(None);
                };
                Ok(Some(HclExpression::new(
                    HclExpressionKind::Template {
                        parts: parts.into(),
                        heredoc: None,
                    },
                    span,
                )))
            }
            HclTokenKind::HeredocOpen => self.parse_heredoc(depth),
            HclTokenKind::ParenOpen => self.parse_paren(depth),
            HclTokenKind::BracketOpen => self.parse_bracket(depth),
            HclTokenKind::BraceOpen => self.parse_brace(depth),
            HclTokenKind::Identifier => self.parse_identifier_term(mode, depth),
            _ => {
                self.diagnose(codes::EXPRESSION, token.span(), DiagnosticCategory::Syntax);
                Ok(None)
            }
        }
    }

    fn number(&self, token: HclToken) -> Result<HclNumber, FatalFormationFailure> {
        let spelling = self.text(token);
        let Some(canonical) = canonical_decimal(spelling) else {
            // A lexer-valid spelling whose exponent does not fit the
            // bounded canonical-decimal representation (RFC 0014 §11).
            return Err(fatal_limit(
                "number-digits",
                usize::MAX,
                self.limits.max_number_digits,
            ));
        };
        let digits = canonical.bytes().filter(u8::is_ascii_digit).count();
        if digits > self.limits.max_number_digits {
            return Err(fatal_limit(
                "number-digits",
                digits,
                self.limits.max_number_digits,
            ));
        }
        Ok(HclNumber::new(token.span(), canonical))
    }

    fn parse_identifier_term(
        &mut self,
        mode: ExprMode,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let name_token = self.peek();
        let name = self.text(name_token);
        self.advance();
        self.skip_expression_trivia(mode);
        if self.at(HclTokenKind::ParenOpen) {
            return self.parse_call(name_token, depth);
        }
        let base = match name {
            "true" => HclExpressionKind::Boolean(true),
            "false" => HclExpressionKind::Boolean(false),
            "null" => HclExpressionKind::Null,
            _ => HclExpressionKind::VariableRef {
                name: Arc::from(name),
            },
        };
        let mut steps: Vec<HclTraversalStep> = Vec::new();
        let mut end = name_token.span().end_byte();
        loop {
            self.skip_expression_trivia(mode);
            match self.peek_kind() {
                HclTokenKind::Dot => {
                    let dot = self.advance();
                    self.skip_expression_trivia(mode);
                    match self.peek_kind() {
                        HclTokenKind::Identifier => {
                            let ident = self.advance();
                            let step = HclTraversalStep::GetAttr {
                                name: Arc::from(self.text(ident)),
                                span: self
                                    .span(dot.span().start_byte(), ident.span().end_byte())?,
                            };
                            end = ident.span().end_byte();
                            steps.push(step);
                        }
                        HclTokenKind::Star => {
                            // Attribute splat `. * GetAttr*`.
                            let star = self.advance();
                            end = star.span().end_byte();
                            let mut nested = Vec::new();
                            loop {
                                self.skip_expression_trivia(mode);
                                if !self.at(HclTokenKind::Dot) {
                                    break;
                                }
                                let ndot = self.advance();
                                self.skip_expression_trivia(mode);
                                if !self.at(HclTokenKind::Identifier) {
                                    self.diagnose(
                                        codes::EXPRESSION,
                                        self.peek().span(),
                                        DiagnosticCategory::Syntax,
                                    );
                                    return Ok(None);
                                }
                                let nident = self.advance();
                                nested.push(HclTraversalStep::GetAttr {
                                    name: Arc::from(self.text(nident)),
                                    span: self
                                        .span(ndot.span().start_byte(), nident.span().end_byte())?,
                                });
                                end = nident.span().end_byte();
                            }
                            steps.push(HclTraversalStep::AttrSplat {
                                steps: nested.into(),
                            });
                        }
                        _ => {
                            // D-5: `foo.0` is rejected — `GetAttr = "."
                            // Identifier` admits identifiers only (RFC 0014
                            // §12).
                            self.diagnose(
                                codes::EXPRESSION,
                                self.peek().span(),
                                DiagnosticCategory::Syntax,
                            );
                            return Ok(None);
                        }
                    }
                }
                HclTokenKind::BracketOpen => {
                    self.brackets.push(Delim::Bracket);
                    let open = self.advance();
                    self.skip_structural();
                    if self.at(HclTokenKind::Star) {
                        // Full splat `[ * ] (GetAttr | Index)*`.
                        self.advance();
                        self.skip_structural();
                        if !self.at(HclTokenKind::BracketClose) {
                            self.diagnose(
                                codes::EXPRESSION,
                                self.peek().span(),
                                DiagnosticCategory::Syntax,
                            );
                            return Ok(None);
                        }
                        let close = self.advance();
                        end = close.span().end_byte();
                        let mut nested = Vec::new();
                        loop {
                            self.skip_expression_trivia(mode);
                            if self.at(HclTokenKind::Dot) {
                                let dot = self.advance();
                                self.skip_expression_trivia(mode);
                                if !self.at(HclTokenKind::Identifier) {
                                    self.diagnose(
                                        codes::EXPRESSION,
                                        self.peek().span(),
                                        DiagnosticCategory::Syntax,
                                    );
                                    return Ok(None);
                                }
                                let ident = self.advance();
                                nested.push(HclTraversalStep::GetAttr {
                                    name: Arc::from(self.text(ident)),
                                    span: self
                                        .span(dot.span().start_byte(), ident.span().end_byte())?,
                                });
                                end = ident.span().end_byte();
                            } else if self.at(HclTokenKind::BracketOpen) {
                                let index_open = self.advance();
                                self.brackets.push(Delim::Bracket);
                                self.skip_structural();
                                let Some(key) =
                                    self.parse_expression(ExprMode::Nested, depth + 1)?
                                else {
                                    return Ok(None);
                                };
                                self.skip_structural();
                                if !self.at(HclTokenKind::BracketClose) {
                                    self.diagnose(
                                        codes::EXPRESSION,
                                        self.peek().span(),
                                        DiagnosticCategory::Syntax,
                                    );
                                    return Ok(None);
                                }
                                let index_close = self.advance();
                                self.brackets.pop();
                                nested.push(HclTraversalStep::Index {
                                    key: Box::new(key),
                                    span: self.span(
                                        index_open.span().start_byte(),
                                        index_close.span().end_byte(),
                                    )?,
                                });
                                end = index_close.span().end_byte();
                            } else {
                                break;
                            }
                        }
                        steps.push(HclTraversalStep::FullSplat {
                            steps: nested.into(),
                        });
                        self.brackets.pop();
                    } else {
                        // Index step `[ Expression ]`.
                        let Some(key) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                            return Ok(None);
                        };
                        self.skip_structural();
                        if !self.at(HclTokenKind::BracketClose) {
                            self.diagnose(
                                codes::EXPRESSION,
                                self.peek().span(),
                                DiagnosticCategory::Syntax,
                            );
                            return Ok(None);
                        }
                        let close = self.advance();
                        self.brackets.pop();
                        steps.push(HclTraversalStep::Index {
                            key: Box::new(key),
                            span: self.span(open.span().start_byte(), close.span().end_byte())?,
                        });
                        end = close.span().end_byte();
                    }
                }
                _ => break,
            }
        }
        if steps.is_empty() {
            return Ok(Some(HclExpression::new(base, name_token.span())));
        }
        let root = match name {
            "true" => HclTraversalRoot::Boolean(true),
            "false" => HclTraversalRoot::Boolean(false),
            "null" => HclTraversalRoot::Null,
            _ => HclTraversalRoot::Variable(Arc::from(name)),
        };
        let span = self.span(name_token.span().start_byte(), end)?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::Traversal {
                root,
                steps: steps.into(),
            },
            span,
        )))
    }

    fn parse_call(
        &mut self,
        name_token: HclToken,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        self.brackets.push(Delim::Paren);
        self.advance(); // open paren
        let mut args: Vec<HclCallArg> = Vec::new();
        let close = loop {
            self.skip_structural();
            if self.at(HclTokenKind::ParenClose) {
                break self.advance();
            }
            let Some(expression) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                return Ok(None);
            };
            let mut expand = false;
            self.skip_structural();
            if self.at(HclTokenKind::Ellipsis) {
                // The expansion marker may only appear on the final
                // argument (a parser contract).
                self.advance();
                expand = true;
                self.skip_structural();
                if self.at(HclTokenKind::Comma) {
                    self.advance();
                    self.skip_structural();
                }
                if !self.at(HclTokenKind::ParenClose) {
                    self.diagnose(
                        codes::EXPRESSION,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
            }
            args.push(HclCallArg::new(expression, expand));
            if self.at(HclTokenKind::ParenClose) {
                break self.advance();
            }
            if self.at(HclTokenKind::Comma)
                || self.at(HclTokenKind::LineBreak)
                || self.at(HclTokenKind::LineComment)
            {
                self.advance();
                continue;
            }
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        };
        self.brackets.pop();
        let span = self.span(name_token.span().start_byte(), close.span().end_byte())?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::FunctionCall {
                name: Arc::from(self.text(name_token)),
                name_span: name_token.span(),
                args: args.into(),
            },
            span,
        )))
    }

    fn parse_paren(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        self.brackets.push(Delim::Paren);
        let open = self.advance();
        self.skip_structural();
        let Some(inner) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
            return Ok(None);
        };
        self.skip_structural();
        if !self.at(HclTokenKind::ParenClose) {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        let close = self.advance();
        self.brackets.pop();
        let span = self.span(open.span().start_byte(), close.span().end_byte())?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::Paren {
                inner: Box::new(inner),
            },
            span,
        )))
    }

    fn parse_bracket(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        self.brackets.push(Delim::Bracket);
        let open = self.advance();
        self.skip_structural();
        if self.at(HclTokenKind::Identifier) && self.text(self.peek()) == "for" {
            // The for-expression interpretation has priority over a first
            // element literally spelled `for` (RFC 0014 §4.6).
            return self.parse_for_tuple(open, depth);
        }
        let mut elements: Vec<HclExpression> = Vec::new();
        let close = loop {
            self.skip_structural();
            if self.at(HclTokenKind::BracketClose) {
                break self.advance();
            }
            let Some(element) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                return Ok(None);
            };
            if elements.len() >= self.limits.max_tuple_elements {
                return Err(fatal_limit(
                    "tuple-elements",
                    elements.len() + 1,
                    self.limits.max_tuple_elements,
                ));
            }
            elements.push(element);
            self.skip_trivia();
            match self.peek_kind() {
                HclTokenKind::Comma | HclTokenKind::LineBreak | HclTokenKind::LineComment => {
                    self.advance();
                }
                HclTokenKind::BracketClose => {}
                _ => {
                    self.diagnose(
                        codes::SEPARATOR,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                }
            }
        };
        self.brackets.pop();
        let span = self.span(open.span().start_byte(), close.span().end_byte())?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::Tuple {
                elements: elements.into(),
            },
            span,
        )))
    }

    fn parse_brace(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        self.brackets.push(Delim::Brace);
        let open = self.advance();
        self.skip_structural();
        if self.at(HclTokenKind::Identifier) && self.text(self.peek()) == "for" {
            // The for-expression interpretation has priority over a first
            // key literally spelled `for` (RFC 0014 §4.6).
            return self.parse_for_object(open, depth);
        }
        let mut entries: Vec<HclObjectEntry> = Vec::new();
        let close = loop {
            self.skip_structural();
            if self.at(HclTokenKind::BraceClose) {
                break self.advance();
            }
            let key = match self.peek_kind() {
                HclTokenKind::Identifier => {
                    let token = self.advance();
                    HclObjectKey::Identifier(Arc::from(self.text(token)))
                }
                HclTokenKind::Number => {
                    let token = self.advance();
                    HclObjectKey::Number(self.number(token)?)
                }
                HclTokenKind::StringOpen => {
                    let Some((parts, span)) = self.parse_quoted_template(depth)? else {
                        return Ok(None);
                    };
                    HclObjectKey::Template(HclTemplateKey::new(parts.into(), span))
                }
                HclTokenKind::ParenOpen => {
                    let Some(inner) = self.parse_paren(depth)? else {
                        return Ok(None);
                    };
                    HclObjectKey::Paren(Box::new(inner))
                }
                _ => {
                    self.diagnose(
                        codes::EXPRESSION,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
            };
            self.skip_structural();
            let separator = match self.peek_kind() {
                HclTokenKind::Equals => {
                    self.advance();
                    ObjectSeparator::Equals
                }
                HclTokenKind::Colon => {
                    self.advance();
                    ObjectSeparator::Colon
                }
                _ => {
                    self.diagnose(
                        codes::EXPRESSION,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
            };
            self.skip_structural();
            let Some(value) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                return Ok(None);
            };
            if entries.len() >= self.limits.max_object_entries {
                return Err(fatal_limit(
                    "object-entries",
                    entries.len() + 1,
                    self.limits.max_object_entries,
                ));
            }
            entries.push(HclObjectEntry::new(key, separator, value));
            self.skip_trivia();
            match self.peek_kind() {
                HclTokenKind::Comma | HclTokenKind::LineBreak | HclTokenKind::LineComment => {
                    self.advance();
                }
                HclTokenKind::BraceClose => {}
                _ => {
                    self.diagnose(
                        codes::SEPARATOR,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                }
            }
        };
        self.brackets.pop();
        let span = self.span(open.span().start_byte(), close.span().end_byte())?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::Object {
                entries: entries.into(),
            },
            span,
        )))
    }

    /// Parses the shared `for` introduction (RFC 0014 §4.6).
    ///
    /// The key identifier is read only when a comma follows (RFC 0014 §12
    /// D-7), so `for v in x` and `for k, v in x` are both admitted. With
    /// `expect_colon`, the introduction ends at the required `:` of a
    /// for-expression; without it, the introduction ends at the collection
    /// expression (a template directive).
    fn parse_for_intro(
        &mut self,
        for_start: usize,
        depth: usize,
        expect_colon: bool,
    ) -> Result<Option<HclForIntro>, FatalFormationFailure> {
        self.skip_structural();
        let first_token = if self.at(HclTokenKind::Identifier) {
            self.advance()
        } else {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        };
        let mut key = None;
        let value;
        self.skip_structural();
        if self.at(HclTokenKind::Comma) {
            self.advance();
            self.skip_structural();
            let value_token = if self.at(HclTokenKind::Identifier) {
                self.advance()
            } else {
                self.diagnose(
                    codes::EXPRESSION,
                    self.peek().span(),
                    DiagnosticCategory::Syntax,
                );
                return Ok(None);
            };
            // `for k, v in ...`: the first identifier is the key.
            key = Some(Arc::from(self.text(first_token)));
            value = Arc::from(self.text(value_token));
            self.skip_structural();
        } else {
            value = Arc::from(self.text(first_token));
        }
        if !(self.at(HclTokenKind::Identifier) && self.text(self.peek()) == "in") {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        self.advance();
        self.skip_structural();
        let Some(collection) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
            return Ok(None);
        };
        let mut end = collection.span().end_byte();
        if expect_colon {
            self.skip_structural();
            if !self.at(HclTokenKind::Colon) {
                self.diagnose(
                    codes::EXPRESSION,
                    self.peek().span(),
                    DiagnosticCategory::Syntax,
                );
                return Ok(None);
            }
            end = self.advance().span().end_byte();
        }
        let span = self.span(for_start, end)?;
        Ok(Some(HclForIntro::new(
            key,
            value,
            Box::new(collection),
            span,
        )))
    }

    fn parse_for_condition(
        &mut self,
        depth: usize,
    ) -> Result<Option<Box<HclExpression>>, FatalFormationFailure> {
        if self.at(HclTokenKind::Identifier) && self.text(self.peek()) == "if" {
            self.advance();
            self.skip_structural();
            let Some(condition) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                return Ok(None);
            };
            Ok(Some(Box::new(condition)))
        } else {
            Ok(None)
        }
    }

    fn parse_for_tuple(
        &mut self,
        open: HclToken,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let for_token = self.advance();
        let Some(intro) = self.parse_for_intro(for_token.span().start_byte(), depth, true)? else {
            return Ok(None);
        };
        self.skip_structural();
        let Some(value) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
            return Ok(None);
        };
        self.skip_structural();
        let condition = self.parse_for_condition(depth)?;
        self.skip_structural();
        if !self.at(HclTokenKind::BracketClose) {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        let close = self.advance();
        self.brackets.pop();
        let span = self.span(open.span().start_byte(), close.span().end_byte())?;
        self.check_for_extent(span)?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::ForTuple {
                intro,
                value: Box::new(value),
                condition,
            },
            span,
        )))
    }

    fn parse_for_object(
        &mut self,
        open: HclToken,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let for_token = self.advance();
        let Some(intro) = self.parse_for_intro(for_token.span().start_byte(), depth, true)? else {
            return Ok(None);
        };
        self.skip_structural();
        let Some(key) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
            return Ok(None);
        };
        self.skip_structural();
        if !self.at(HclTokenKind::Arrow) {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        self.advance();
        self.skip_structural();
        let Some(value) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
            return Ok(None);
        };
        let mut grouping = false;
        self.skip_structural();
        if self.at(HclTokenKind::Ellipsis) {
            self.advance();
            grouping = true;
        }
        self.skip_structural();
        let condition = self.parse_for_condition(depth)?;
        self.skip_structural();
        if !self.at(HclTokenKind::BraceClose) {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            return Ok(None);
        }
        let close = self.advance();
        self.brackets.pop();
        let span = self.span(open.span().start_byte(), close.span().end_byte())?;
        self.check_for_extent(span)?;
        Ok(Some(HclExpression::new(
            HclExpressionKind::ForObject {
                intro,
                key: Box::new(key),
                value: Box::new(value),
                grouping,
                condition,
            },
            span,
        )))
    }

    fn check_for_extent(&self, span: Span) -> Result<(), FatalFormationFailure> {
        let extent = span.len();
        if extent > self.limits.max_for_extent {
            return Err(fatal_limit(
                "for-extent",
                extent,
                self.limits.max_for_extent,
            ));
        }
        Ok(())
    }

    // -- templates and heredocs --------------------------------------------

    /// Parses one quoted template: literal runs with escape decoding,
    /// interpolation and directive parts, closed by the closing quote.
    /// Returns `None` when the template is unterminated (the lexer already
    /// recovered it) or any part fails; the caller recovers the item.
    fn parse_quoted_template(
        &mut self,
        depth: usize,
    ) -> Result<Option<(Vec<HclTemplatePart>, Span)>, FatalFormationFailure> {
        let open = self.advance();
        let mut parts: Vec<HclTemplatePart> = Vec::new();
        loop {
            let token = self.peek();
            match token.kind() {
                HclTokenKind::StringClose => {
                    let close = self.advance();
                    let span = self.span(open.span().start_byte(), close.span().end_byte())?;
                    return Ok(Some((parts, span)));
                }
                HclTokenKind::StringContent => {
                    self.advance();
                    let text = decode_quoted_literal(self.text(token));
                    parts.push(HclTemplatePart::Literal {
                        span: token.span(),
                        text: Arc::from(text),
                    });
                }
                HclTokenKind::InterpolationOpen | HclTokenKind::DirectiveOpen => {
                    let directive = token.kind() == HclTokenKind::DirectiveOpen;
                    let part_open = self.advance();
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
                    let Some(content) = self.eat(content_kind) else {
                        return Ok(None);
                    };
                    let Some(part_close) = self.eat(close_kind) else {
                        return Ok(None);
                    };
                    let part_span =
                        self.span(part_open.span().start_byte(), part_close.span().end_byte())?;
                    if directive {
                        let Some(kind) = self.parse_directive_region(content.span(), depth + 1)?
                        else {
                            return Ok(None);
                        };
                        parts.push(HclTemplatePart::Directive {
                            span: part_span,
                            kind,
                        });
                    } else {
                        let Some(expression) =
                            self.parse_region_expression(content.span(), depth + 1)?
                        else {
                            return Ok(None);
                        };
                        parts.push(HclTemplatePart::Interpolation {
                            span: part_span,
                            expression,
                        });
                    }
                }
                HclTokenKind::ErrorRegion | HclTokenKind::Eof => {
                    // Unterminated at the lexer; no extra diagnostic.
                    return Ok(None);
                }
                _ => {
                    self.diagnose(codes::EXPRESSION, token.span(), DiagnosticCategory::Syntax);
                    return Ok(None);
                }
            }
        }
    }

    /// Parses one heredoc template: literal content lines with `$${`/`%%{`
    /// decoding, interpolation and directive parts, and the closing marker
    /// line as a representation fact (RFC 0014 §4.5).
    fn parse_heredoc(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let open = self.advance();
        self.skip_trivia();
        if !self.at(HclTokenKind::LineBreak) {
            // Unterminated introducer or content; the lexer recovered it.
            return Ok(None);
        }
        self.advance();
        let mut parts: Vec<HclTemplatePart> = Vec::new();
        loop {
            let token = self.peek();
            match token.kind() {
                HclTokenKind::HeredocClose => {
                    let close = self.advance();
                    let heredoc_span =
                        self.span(open.span().start_byte(), close.span().end_byte())?;
                    let mode = if self.text(open).starts_with("<<-") {
                        HeredocMode::StripIndent
                    } else {
                        HeredocMode::Plain
                    };
                    let marker_start = open.span().start_byte()
                        + if mode == HeredocMode::StripIndent {
                            3
                        } else {
                            2
                        };
                    let marker = Arc::from(&self.decoded[marker_start..open.span().end_byte()]);
                    let facts = HeredocFacts::new(
                        mode,
                        marker,
                        self.span(marker_start, open.span().end_byte())?,
                        Some(close.span()),
                    );
                    return Ok(Some(HclExpression::new(
                        HclExpressionKind::Template {
                            parts: parts.into(),
                            heredoc: Some(facts),
                        },
                        heredoc_span,
                    )));
                }
                HclTokenKind::HeredocContent => {
                    self.advance();
                    let text = decode_heredoc_literal(self.text(token));
                    parts.push(HclTemplatePart::Literal {
                        span: token.span(),
                        text: Arc::from(text),
                    });
                }
                HclTokenKind::LineBreak => {
                    let token = self.advance();
                    parts.push(HclTemplatePart::Literal {
                        span: token.span(),
                        text: Arc::from("\n"),
                    });
                }
                HclTokenKind::InterpolationOpen | HclTokenKind::DirectiveOpen => {
                    let directive = token.kind() == HclTokenKind::DirectiveOpen;
                    let part_open = self.advance();
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
                    let Some(content) = self.eat(content_kind) else {
                        return Ok(None);
                    };
                    let Some(part_close) = self.eat(close_kind) else {
                        return Ok(None);
                    };
                    let part_span =
                        self.span(part_open.span().start_byte(), part_close.span().end_byte())?;
                    if directive {
                        let Some(kind) = self.parse_directive_region(content.span(), depth + 1)?
                        else {
                            return Ok(None);
                        };
                        parts.push(HclTemplatePart::Directive {
                            span: part_span,
                            kind,
                        });
                    } else {
                        let Some(expression) =
                            self.parse_region_expression(content.span(), depth + 1)?
                        else {
                            return Ok(None);
                        };
                        parts.push(HclTemplatePart::Interpolation {
                            span: part_span,
                            expression,
                        });
                    }
                }
                _ => {
                    // Unterminated at the lexer (error region or end of
                    // file); no extra diagnostic.
                    return Ok(None);
                }
            }
        }
    }

    /// Re-lexes one interpolation or directive interior and parses it as an
    /// expression on a sub-parser over the region tokens (RFC 0014 §3.2 of
    /// the implementation plan).
    fn parse_region_expression(
        &mut self,
        span: Span,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        self.with_region(span, |sub| sub.parse_expression_region(depth))
    }

    fn parse_directive_region(
        &mut self,
        span: Span,
        depth: usize,
    ) -> Result<Option<HclDirectiveKind>, FatalFormationFailure> {
        self.with_region(span, |sub| sub.parse_directive(depth))
    }

    /// Runs one parse on a fresh sub-parser over a re-lexed interior, then
    /// merges the sub-parser's recovery facts into this pass.
    fn with_region<T>(
        &mut self,
        span: Span,
        parse: impl FnOnce(&mut Parser<'_>) -> Result<Option<T>, FatalFormationFailure>,
    ) -> Result<Option<T>, FatalFormationFailure> {
        let output = lex_region(
            Arc::clone(&self.source),
            self.authority.clone(),
            span.start_byte(),
            span.end_byte(),
            self.limits,
        )?;
        self.recovered |= output.is_recovered();
        for diagnostic in output.diagnostics() {
            self.sink.push(diagnostic.clone());
        }
        for region in output.error_regions() {
            self.error_regions.push(region.clone());
        }
        self.check_error_region_limits()?;
        let source = Arc::clone(&self.source);
        let mut sub = Parser::new(&output, source, self.limits, usize::MAX)?;
        let result = parse(&mut sub);
        self.recovered |= sub.recovered;
        for diagnostic in sub.sink.finish() {
            self.sink.push(diagnostic);
        }
        for region in sub.error_regions {
            self.error_regions.push(region);
        }
        self.check_error_region_limits()?;
        result
    }

    /// One expression over the region token stream: a full expression
    /// followed by the region end, with newlines ignored as whitespace.
    fn parse_expression_region(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclExpression>, FatalFormationFailure> {
        let Some(expression) = self.parse_expression(ExprMode::Nested, depth)? else {
            return Ok(None);
        };
        self.skip_structural();
        if self.at(HclTokenKind::Eof) {
            Ok(Some(expression))
        } else {
            self.diagnose(
                codes::EXPRESSION,
                self.peek().span(),
                DiagnosticCategory::Syntax,
            );
            Ok(None)
        }
    }

    /// One template directive over the region token stream (RFC 0014 §4.4):
    /// `%{ if Expression }`, `%{ else }`, `%{ endif }`, `%{ for k, v in
    /// Expression }` (single-identifier form admitted, §12 D-7), and
    /// `%{ endfor }`.
    fn parse_directive(
        &mut self,
        depth: usize,
    ) -> Result<Option<HclDirectiveKind>, FatalFormationFailure> {
        self.skip_structural();
        let token = self.peek();
        if token.kind() != HclTokenKind::Identifier {
            self.diagnose(codes::DIRECTIVE, token.span(), DiagnosticCategory::Syntax);
            return Ok(None);
        }
        match self.text(token) {
            "if" => {
                self.advance();
                self.skip_structural();
                let Some(condition) = self.parse_expression(ExprMode::Nested, depth + 1)? else {
                    return Ok(None);
                };
                self.skip_structural();
                if !self.at(HclTokenKind::Eof) {
                    self.diagnose(
                        codes::DIRECTIVE,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
                Ok(Some(HclDirectiveKind::If {
                    condition: Box::new(condition),
                }))
            }
            "else" | "endif" | "endfor" => {
                self.advance();
                self.skip_structural();
                if !self.at(HclTokenKind::Eof) {
                    self.diagnose(
                        codes::DIRECTIVE,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
                let kind = match self.text(token) {
                    "else" => HclDirectiveKind::Else,
                    "endif" => HclDirectiveKind::EndIf,
                    _ => HclDirectiveKind::EndFor,
                };
                Ok(Some(kind))
            }
            "for" => {
                let for_token = self.advance();
                let Some(intro) =
                    self.parse_for_intro(for_token.span().start_byte(), depth, false)?
                else {
                    return Ok(None);
                };
                self.skip_structural();
                if !self.at(HclTokenKind::Eof) {
                    self.diagnose(
                        codes::DIRECTIVE,
                        self.peek().span(),
                        DiagnosticCategory::Syntax,
                    );
                    return Ok(None);
                }
                Ok(Some(HclDirectiveKind::For { intro }))
            }
            _ => {
                self.diagnose(codes::DIRECTIVE, token.span(), DiagnosticCategory::Syntax);
                Ok(None)
            }
        }
    }
}

impl AttributeFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::MissingEquals => codes::ATTRIBUTE,
            Self::MissingExpression => codes::EXPRESSION,
        }
    }
}

const fn delim_of(kind: HclTokenKind) -> Option<Delim> {
    match kind {
        HclTokenKind::BraceOpen => Some(Delim::Brace),
        HclTokenKind::BracketOpen => Some(Delim::Bracket),
        HclTokenKind::ParenOpen => Some(Delim::Paren),
        _ => None,
    }
}

/// Decodes one quoted-template literal run: the frozen escape sequences
/// `\n` `\r` `\t` `\"` `\\` `\uNNNN` `\UNNNNNNNN` and the escaped openers
/// `$${`/`%%{` (RFC 0014 §4.4). An invalid escape (already recovered by
/// the lexer) passes through unchanged.
fn decode_quoted_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                let Some(next) = bytes.get(index + 1) else {
                    out.push('\\');
                    index += 1;
                    continue;
                };
                match next {
                    b'n' => {
                        out.push('\n');
                        index += 2;
                    }
                    b'r' => {
                        out.push('\r');
                        index += 2;
                    }
                    b't' => {
                        out.push('\t');
                        index += 2;
                    }
                    b'"' => {
                        out.push('"');
                        index += 2;
                    }
                    b'\\' => {
                        out.push('\\');
                        index += 2;
                    }
                    b'u' => {
                        if let Some(hex) = text.get(index + 2..index + 6) {
                            if let Ok(value) = u32::from_str_radix(hex, 16) {
                                if let Some(ch) = char::from_u32(value) {
                                    out.push(ch);
                                    index += 6;
                                    continue;
                                }
                            }
                        }
                        out.push('\\');
                        index += 1;
                    }
                    b'U' => {
                        if let Some(hex) = text.get(index + 2..index + 10) {
                            if let Ok(value) = u32::from_str_radix(hex, 16) {
                                if let Some(ch) = char::from_u32(value) {
                                    out.push(ch);
                                    index += 10;
                                    continue;
                                }
                            }
                        }
                        out.push('\\');
                        index += 1;
                    }
                    _ => {
                        out.push('\\');
                        index += 1;
                    }
                }
            }
            b'$' => {
                if bytes.get(index + 1) == Some(&b'$') && bytes.get(index + 2) == Some(&b'{') {
                    out.push_str("${");
                    index += 3;
                } else {
                    out.push('$');
                    index += 1;
                }
            }
            b'%' => {
                if bytes.get(index + 1) == Some(&b'%') && bytes.get(index + 2) == Some(&b'{') {
                    out.push_str("%{");
                    index += 3;
                } else {
                    out.push('%');
                    index += 1;
                }
            }
            _ => {
                let width = char_width(bytes[index]);
                out.push_str(&text[index..index + width]);
                index += width;
            }
        }
    }
    out
}

/// Decodes one heredoc literal run: only the `$${`/`%%{` escapes apply;
/// heredoc text is otherwise raw (RFC 0014 §4.5).
fn decode_heredoc_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'$' => {
                if bytes.get(index + 1) == Some(&b'$') && bytes.get(index + 2) == Some(&b'{') {
                    out.push_str("${");
                    index += 3;
                } else {
                    out.push('$');
                    index += 1;
                }
            }
            b'%' => {
                if bytes.get(index + 1) == Some(&b'%') && bytes.get(index + 2) == Some(&b'{') {
                    out.push_str("%{");
                    index += 3;
                } else {
                    out.push('%');
                    index += 1;
                }
            }
            _ => {
                let width = char_width(bytes[index]);
                out.push_str(&text[index..index + width]);
                index += width;
            }
        }
    }
    out
}

/// UTF-8 width of one leading byte.
const fn char_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte < 0xE0 {
        2
    } else if byte < 0xF0 {
        3
    } else {
        4
    }
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

/// Source-construction failure mapping, mirroring the lexer (RFC 0014 §2,
/// §11, §12 D-3). Unreachable in practice: the lexer already constructed
/// the identical snapshot from the same bytes.
fn source_failure(error: SourceError) -> FatalFormationFailure {
    match error {
        SourceError::InvalidSequence { byte_offset, .. }
        | SourceError::InvalidUtf8 {
            valid_up_to: byte_offset,
        } => FatalFormationFailure::from_diagnostic(Diagnostic::new(
            "hcl.parse.invalid-utf8@1",
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

/// Unreachable decoding state: defensive fatal with no panicking path.
fn encoding_failure() -> FatalFormationFailure {
    fatal(
        "hcl.parse.invalid-utf8@1",
        DiagnosticCategory::Encoding,
        None,
        &[],
    )
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
    use crate::expression::{
        BinaryOp, HclExpressionKindName, HclTemplatePart, HclTraversalStep, HeredocMode,
        ObjectSeparator, UnaryOp, literal_value,
    };
    use consema_document::FormationStatus;

    fn parse(bytes: &[u8]) -> HclFormed {
        parse_hcl(Arc::<[u8]>::from(bytes), HclParseLimits::default())
            .expect("formation of a valid UTF-8 source")
    }

    fn parse_with(
        bytes: &[u8],
        limits: HclParseLimits,
    ) -> Result<HclFormed, FatalFormationFailure> {
        parse_hcl(Arc::<[u8]>::from(bytes), limits)
    }

    fn limited(adjust: impl FnOnce(&mut HclParseLimits)) -> HclParseLimits {
        let mut limits = HclParseLimits::default();
        adjust(&mut limits);
        limits
    }

    fn fatal_code(bytes: &[u8], limits: HclParseLimits) -> String {
        parse_with(bytes, limits)
            .expect_err("limit must be fatal")
            .diagnostics()
            .first()
            .expect("one fatal diagnostic")
            .code
            .clone()
    }

    fn codes(formed: &HclFormed) -> Vec<String> {
        formed
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    fn kind_names(formed: &HclFormed) -> Vec<&str> {
        formed
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect()
    }

    fn attributes(formed: &HclFormed) -> Vec<&HclAttribute> {
        formed
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_attribute)
            .collect()
    }

    fn blocks(formed: &HclFormed) -> Vec<&HclBlock> {
        formed
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_block)
            .collect()
    }

    fn attribute<'a>(formed: &'a HclFormed, name: &str) -> &'a HclAttribute {
        attributes(formed)
            .into_iter()
            .find(|attribute| attribute.name() == name)
            .expect("attribute exists")
    }

    fn expression_text(formed: &HclFormed, expression: &HclExpression) -> String {
        expression
            .text(formed.source())
            .expect("decoded source")
            .to_owned()
    }

    fn template_parts(expression: &HclExpression) -> Vec<&HclTemplatePart> {
        let HclExpressionKind::Template { parts, .. } = expression.kind() else {
            panic!("expected a template");
        };
        parts.iter().collect()
    }

    fn assert_regions(formed: &HclFormed, expected: &[(&str, usize, usize)]) {
        let actual: Vec<(&str, usize, usize)> = formed
            .error_regions()
            .iter()
            .map(|region| {
                (
                    region.code(),
                    region.span().start_byte(),
                    region.span().end_byte(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_source_is_complete_with_empty_body() {
        let formed = parse(b"");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(formed.document().body().is_empty());
        assert!(formed.diagnostics().is_empty());
        assert!(formed.error_regions().is_empty());
        assert!(formed.lossless_structural_index().pieces().is_empty());
        assert!(formed.lossless_syntax_kinds().is_empty());
        assert_eq!(formed.render(), b"");
    }

    #[test]
    fn trivia_only_source_is_complete_with_empty_body() {
        let formed = parse(b"  \n# comment\n/* inline */\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(formed.document().body().is_empty());
        assert!(formed.diagnostics().is_empty());
    }

    #[test]
    fn single_attribute_is_complete_with_exact_spans() {
        let formed = parse(b"a = 1\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let attributes = attributes(&formed);
        assert_eq!(attributes.len(), 1);
        let attribute = attributes[0];
        assert_eq!(attribute.name(), "a");
        assert_eq!(attribute.name_span().start_byte(), 0);
        assert_eq!(attribute.name_span().end_byte(), 1);
        assert_eq!(attribute.equals_span().start_byte(), 2);
        assert_eq!(attribute.equals_span().end_byte(), 3);
        assert_eq!(attribute.expression().kind().as_str(), "number");
        assert_eq!(expression_text(&formed, attribute.expression()), "1");
        assert_eq!(attribute.expression().span().start_byte(), 4);
        assert_eq!(attribute.expression().span().end_byte(), 5);
    }

    #[test]
    fn eof_terminates_the_last_attribute_without_newline() {
        // RFC 0014 §12 D-9.
        let formed = parse(b"a = 1");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(
            expression_text(&formed, attribute(&formed, "a").expression()),
            "1"
        );
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let formed = parse(b"a = 1\r\nb = 2\r\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(attributes(&formed).len(), 2);
        assert_eq!(attribute(&formed, "a").expression().span().end_byte(), 5);
        assert_eq!(attribute(&formed, "b").expression().span().start_byte(), 11);
    }

    #[test]
    fn line_comment_terminates_the_attribute() {
        let formed = parse(b"a = 1 # note\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(attributes(&formed).len(), 2);
        assert_eq!(
            expression_text(&formed, attribute(&formed, "a").expression()),
            "1"
        );
    }

    #[test]
    fn keyword_spellings_are_valid_attribute_names() {
        let formed = parse(b"true = 1\nfalse = 2\nnull = 3\nfor = 4\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(attributes(&formed).len(), 4);
        assert_eq!(attribute(&formed, "true").name(), "true");
        assert_eq!(attribute(&formed, "for").name(), "for");
    }

    #[test]
    fn body_preserves_interleaved_item_order() {
        let formed = parse(b"a = 1\nb {\n}\nc = 2\nd \"x\" {\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let items = formed.document().body().items();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].as_attribute().expect("attribute").name(), "a");
        assert_eq!(items[1].as_block().expect("block").block_type(), "b");
        assert_eq!(items[2].as_attribute().expect("attribute").name(), "c");
        assert_eq!(items[3].as_block().expect("block").block_type(), "d");
    }

    #[test]
    fn render_is_byte_exact() {
        let source = b"a = 1\nb \"web\" {\n  c = [1, 2]\n}\n";
        let formed = parse(source);
        assert_eq!(formed.render(), source);
        assert_eq!(formed.status(), FormationStatus::Complete);
    }

    #[test]
    fn block_with_naked_labels_and_nested_body() {
        let formed = parse(b"resource aws_instance web {\n  ami = \"ami-1\"\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 1);
        let block = blocks[0];
        assert_eq!(block.block_type(), "resource");
        assert_eq!(block.labels().len(), 2);
        assert!(!block.labels()[0].quoted());
        assert_eq!(block.labels()[0].text(), "aws_instance");
        assert!(!block.labels()[1].quoted());
        assert_eq!(block.labels()[1].text(), "web");
        assert_eq!(block.body().len(), 1);
        assert_eq!(
            block.body().items()[0]
                .as_attribute()
                .expect("attribute")
                .name(),
            "ami"
        );
        assert_eq!(block.span().start_byte(), 0);
        assert_eq!(block.span().end_byte(), 45);
    }

    #[test]
    fn block_with_quoted_labels_decodes_escapes() {
        let formed = parse(b"b \"web\" \"a\\n\" {\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let labels = blocks(&formed)[0].labels();
        assert_eq!(labels.len(), 2);
        assert!(labels[0].quoted());
        assert_eq!(labels[0].text(), "web");
        assert_eq!(labels[0].span().start_byte(), 2);
        assert_eq!(labels[0].span().end_byte(), 7);
        assert!(labels[1].quoted());
        assert_eq!(labels[1].text(), "a\n");
    }

    #[test]
    fn one_line_block_with_single_attribute() {
        let formed = parse(b"b { a = 1 }\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 1);
        let block = blocks[0];
        assert_eq!(block.block_type(), "b");
        assert_eq!(block.body().len(), 1);
        let inner = block.body().items()[0].as_attribute().expect("attribute");
        assert_eq!(inner.name(), "a");
        assert_eq!(expression_text(&formed, inner.expression()), "1");
        assert_eq!(block.span().start_byte(), 0);
        assert_eq!(block.span().end_byte(), 11);
    }

    #[test]
    fn empty_block_and_one_line_empty_block() {
        for source in [b"b {\n}\n".as_slice(), b"b { }\n".as_slice()] {
            let formed = parse(source);
            assert_eq!(formed.status(), FormationStatus::Complete);
            let blocks = blocks(&formed);
            assert_eq!(blocks.len(), 1);
            assert!(blocks[0].body().is_empty());
            assert_eq!(blocks[0].span().end_byte(), 5);
        }
    }

    #[test]
    fn block_span_covers_labels_through_closing_brace() {
        let formed = parse(b"b \"x\" \"y\" { a = 1 }\n");
        let block = blocks(&formed)[0];
        assert_eq!(block.span().start_byte(), 0);
        assert_eq!(block.span().end_byte(), 19);
        assert_eq!(
            expression_text(
                &formed,
                block.body().items()[0].as_attribute().unwrap().expression()
            ),
            "1"
        );
    }

    #[test]
    fn repeated_blocks_keep_per_occurrence_identity() {
        let formed = parse(b"b \"x\" {\n}\nb \"x\" {\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 2);
        assert_ne!(blocks[0].span(), blocks[1].span());
        assert_eq!(blocks[0].span().start_byte(), 0);
        assert_eq!(blocks[1].span().start_byte(), 10);
    }

    #[test]
    fn attribute_and_block_may_share_a_name() {
        let formed = parse(b"a = 1\na {\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let items = formed.document().body().items();
        assert_eq!(items.len(), 2);
        assert!(items[0].as_attribute().is_some());
        assert!(items[1].as_block().is_some());
        assert_eq!(items[0].as_attribute().unwrap().name(), "a");
        assert_eq!(items[1].as_block().unwrap().block_type(), "a");
    }

    #[test]
    fn quoted_label_with_interpolation_is_recovered() {
        let formed = parse(b"b \"x${y}\" {\n}\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::LABEL.to_owned()));
        assert!(formed.document().body().is_empty());
        assert_regions(&formed, &[("hcl.parse.label@1", 0, 13)]);
    }

    #[test]
    fn block_type_followed_by_newline_is_recovered() {
        let formed = parse(b"b\n{\n}\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(
            codes(&formed),
            vec![codes::ITEM.to_owned(), codes::ITEM.to_owned()]
        );
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn equals_after_block_label_is_recovered() {
        let formed = parse(b"b \"x\" = 1\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::BLOCK.to_owned()]);
        assert!(formed.document().body().is_empty());
        assert_regions(&formed, &[("hcl.parse.block@1", 0, 9)]);
    }

    #[test]
    fn duplicate_attribute_excludes_the_second_occurrence() {
        let formed = parse(b"a = 1\na = 2\nb = 3\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::DUPLICATE_ATTRIBUTE.to_owned()]);
        // The first occurrence stays native; the duplicate never enters the
        // model (RFC 0014 §3).
        let attributes = attributes(&formed);
        assert_eq!(attributes.len(), 2);
        assert_eq!(
            expression_text(&formed, attribute(&formed, "a").expression()),
            "1"
        );
        assert_eq!(
            expression_text(&formed, attribute(&formed, "b").expression()),
            "3"
        );
        // The duplicate remains an inspectable syntax piece.
        let kinds = kind_names(&formed);
        assert!(kinds.iter().filter(|kind| **kind == "Identifier").count() >= 3);
        // A duplicate publishes no error region.
        assert!(formed.error_regions().is_empty());
    }

    #[test]
    fn duplicate_attributes_in_nested_bodies_are_independent() {
        let formed = parse(b"b {\n  a = 1\n}\nc {\n  a = 2\n}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(blocks(&formed).len(), 2);
    }

    #[test]
    fn triple_duplicates_report_each_duplicate() {
        let formed = parse(b"a = 1\na = 2\na = 3\n");
        assert_eq!(
            codes(&formed),
            vec![
                codes::DUPLICATE_ATTRIBUTE.to_owned(),
                codes::DUPLICATE_ATTRIBUTE.to_owned(),
            ]
        );
        assert_eq!(attributes(&formed).len(), 1);
    }

    #[test]
    fn duplicate_attribute_inside_one_line_block() {
        let formed = parse(b"b { a = 1 }\nb { a = 2 }\n");
        // Each one-line block body is its own body scope.
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(blocks(&formed).len(), 2);
    }

    #[test]
    fn number_expression_keeps_canonical_decimal() {
        let formed = parse(b"a = 1.50\n");
        let HclExpressionKind::Number(number) = attribute(&formed, "a").expression().kind() else {
            panic!("expected number");
        };
        assert_eq!(number.canonical_decimal(), "1.5");
        assert_eq!(number.span().start_byte(), 4);
        assert_eq!(number.span().end_byte(), 8);
    }

    #[test]
    fn boolean_and_null_literals() {
        let formed = parse(b"a = true\nb = false\nc = null\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            attribute(&formed, "a").expression().kind().as_str(),
            "boolean"
        );
        assert_eq!(
            attribute(&formed, "b").expression().kind().as_str(),
            "boolean"
        );
        assert_eq!(attribute(&formed, "c").expression().kind().as_str(), "null");
        let HclExpressionKind::Boolean(value) = attribute(&formed, "a").expression().kind() else {
            panic!("expected boolean");
        };
        assert!(value);
    }

    #[test]
    fn keyword_spellings_are_traversal_roots() {
        let formed = parse(b"a = true.foo\nb = null.x.y\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Traversal { root, steps } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        assert_eq!(root, &crate::expression::HclTraversalRoot::Boolean(true));
        assert_eq!(steps.len(), 1);
        let HclExpressionKind::Traversal { root, steps } =
            attribute(&formed, "b").expression().kind()
        else {
            panic!("expected traversal");
        };
        assert_eq!(root, &crate::expression::HclTraversalRoot::Null);
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn variable_ref_without_steps() {
        let formed = parse(b"a = foo\n");
        let expression = attribute(&formed, "a").expression();
        assert_eq!(expression.kind().as_str(), "variable-ref");
        let HclExpressionKind::VariableRef { name } = expression.kind() else {
            panic!("expected variable");
        };
        assert_eq!(name.as_ref(), "foo");
        assert_eq!(expression.span().start_byte(), 4);
        assert_eq!(expression.span().end_byte(), 7);
    }

    #[test]
    fn traversal_getattr_and_index_steps() {
        let formed = parse(b"a = foo.bar[0]\n");
        let HclExpressionKind::Traversal { root, steps } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        assert_eq!(
            root,
            &crate::expression::HclTraversalRoot::Variable(Arc::from("foo"))
        );
        assert_eq!(steps.len(), 2);
        let HclTraversalStep::GetAttr { name, span } = &steps[0] else {
            panic!("expected get-attr");
        };
        assert_eq!(name.as_ref(), "bar");
        assert_eq!(span.start_byte(), 7);
        assert_eq!(span.end_byte(), 11);
        let HclTraversalStep::Index { key, span } = &steps[1] else {
            panic!("expected index");
        };
        assert_eq!(key.kind().as_str(), "number");
        assert_eq!(span.start_byte(), 11);
        assert_eq!(span.end_byte(), 14);
    }

    #[test]
    fn traversal_index_key_may_be_an_expression() {
        let formed = parse(b"a = foo[i + 1]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Traversal { steps, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        let HclTraversalStep::Index { key, .. } = &steps[0] else {
            panic!("expected index");
        };
        assert_eq!(key.kind().as_str(), "binary");
        assert_eq!(expression_text(&formed, key), "i + 1");
    }

    #[test]
    fn attribute_splat_nests_attribute_steps() {
        let formed = parse(b"a = foo.*.bar.baz\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Traversal { steps, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        assert_eq!(steps.len(), 1);
        let HclTraversalStep::AttrSplat { steps } = &steps[0] else {
            panic!("expected attr splat");
        };
        assert_eq!(steps.len(), 2);
        let HclTraversalStep::GetAttr { name, .. } = &steps[0] else {
            panic!("expected get-attr");
        };
        assert_eq!(name.as_ref(), "bar");
    }

    #[test]
    fn full_splat_nests_attribute_and_index_steps() {
        let formed = parse(b"a = foo[*].bar[0]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Traversal { steps, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        let HclTraversalStep::FullSplat { steps } = &steps[0] else {
            panic!("expected full splat");
        };
        assert_eq!(steps.len(), 2);
        assert!(matches!(steps[0], HclTraversalStep::GetAttr { .. }));
        assert!(matches!(steps[1], HclTraversalStep::Index { .. }));
    }

    #[test]
    fn steps_continue_after_a_splat() {
        let formed = parse(b"a = foo.*.bar[0]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Traversal { steps, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected traversal");
        };
        assert_eq!(steps.len(), 2);
        assert!(matches!(steps[0], HclTraversalStep::AttrSplat { .. }));
        assert!(matches!(steps[1], HclTraversalStep::Index { .. }));
    }

    #[test]
    fn numeric_attribute_access_is_rejected() {
        // RFC 0014 §12 D-5: `foo.0` is a grammar error.
        let formed = parse(b"a = foo.0\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "b").name(), "b");
        assert_regions(&formed, &[("hcl.parse.expression@1", 0, 9)]);
    }

    #[test]
    fn namespaced_function_call_is_rejected() {
        // RFC 0014 §12 D-6: `::` is an error region at the lexer, so
        // the namespaced call form never reaches the expression grammar.
        let formed = parse(b"a = foo::bar()\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&"hcl.parse.invalid-character@1".to_owned()));
    }

    #[test]
    fn function_call_with_trailing_comma_and_expansion() {
        let formed = parse(b"a = f(1, 2, 3...)\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::FunctionCall {
            name,
            name_span,
            args,
        } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected function call");
        };
        assert_eq!(name.as_ref(), "f");
        assert_eq!(name_span.start_byte(), 4);
        assert_eq!(name_span.end_byte(), 5);
        assert_eq!(args.len(), 3);
        assert!(!args[0].expand());
        assert!(!args[1].expand());
        assert!(args[2].expand());
        assert_eq!(attribute(&formed, "a").expression().span().end_byte(), 17);
    }

    #[test]
    fn function_call_trailing_comma_without_expansion() {
        let formed = parse(b"a = f(1, 2,)\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::FunctionCall { args, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected function call");
        };
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn function_call_ignores_newlines_between_arguments() {
        let formed = parse(b"a = f(1,\n2)\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::FunctionCall { args, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected function call");
        };
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn expansion_marker_on_non_final_argument_is_rejected() {
        let formed = parse(b"a = f(1..., 2)\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn parentheses_ignore_newlines() {
        let formed = parse(b"a = (1 +\n2)\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expression = attribute(&formed, "a").expression();
        assert_eq!(expression.kind().as_str(), "parenthesized");
        let HclExpressionKind::Paren { inner } = expression.kind() else {
            panic!("expected paren");
        };
        assert_eq!(inner.kind().as_str(), "binary");
    }

    #[test]
    fn unary_compound_matrix() {
        // RFC 0014 §13: `-1 + 2`, `2 * -1`, `-1 * 2`, `!!x`.
        let formed = parse(b"a = -1 + 2\nb = 2 * -1\nc = -1 * 2\nd = !!x\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let a = attribute(&formed, "a").expression();
        let HclExpressionKind::Binary { op, lhs, rhs } = a.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Add);
        assert_eq!(lhs.kind().as_str(), "unary");
        assert_eq!(rhs.kind().as_str(), "number");
        let b = attribute(&formed, "b").expression();
        let HclExpressionKind::Binary { op, lhs, .. } = b.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Multiply);
        assert_eq!(lhs.kind().as_str(), "number");
        let d = attribute(&formed, "d").expression();
        let HclExpressionKind::Unary { op, operand } = d.kind() else {
            panic!("expected unary");
        };
        assert_eq!(*op, UnaryOp::Not);
        assert_eq!(operand.kind().as_str(), "unary");
    }

    #[test]
    fn unary_minus_applies_to_the_full_term() {
        let formed = parse(b"a = -foo.bar\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Unary { op, operand } = expression.kind() else {
            panic!("expected unary");
        };
        assert_eq!(*op, UnaryOp::Minus);
        assert_eq!(operand.kind().as_str(), "traversal");
    }

    #[test]
    fn unary_plus_is_rejected() {
        let formed = parse(b"a = +1\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn multiplication_binds_tighter_than_addition() {
        let formed = parse(b"a = 1 + 2 * 3\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Binary { op, lhs, rhs } = expression.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Add);
        assert_eq!(lhs.kind().as_str(), "number");
        assert_eq!(rhs.kind().as_str(), "binary");
        let HclExpressionKind::Binary { op: inner, .. } = rhs.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*inner, BinaryOp::Multiply);
    }

    #[test]
    fn comparison_and_equality_levels() {
        let formed = parse(b"a = 1 < 2 == 3 != 4\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Binary { op, lhs, .. } = expression.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::NotEqual);
        let HclExpressionKind::Binary { op, .. } = lhs.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Equal);
    }

    #[test]
    fn logical_levels_bind_loosest() {
        let formed = parse(b"a = b || c && d\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Binary { op, rhs, .. } = expression.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Or);
        let HclExpressionKind::Binary { op, .. } = rhs.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::And);
    }

    #[test]
    fn binary_operators_are_left_associative() {
        let formed = parse(b"a = 1 - 2 - 3\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Binary { op, lhs, rhs } = expression.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Subtract);
        assert_eq!(rhs.kind().as_str(), "number");
        let HclExpressionKind::Binary { op, .. } = lhs.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Subtract);
    }

    #[test]
    fn doubled_star_is_rejected() {
        let formed = parse(b"a = 2 ** 3\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
    }

    #[test]
    fn conditional_never_binds_tighter_than_or() {
        let formed = parse(b"a = b || c ? d : e\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Conditional { condition, .. } = expression.kind() else {
            panic!("expected conditional");
        };
        let HclExpressionKind::Binary { op, .. } = condition.kind() else {
            panic!("expected binary");
        };
        assert_eq!(*op, BinaryOp::Or);
    }

    #[test]
    fn conditional_branches_are_right_associative() {
        let formed = parse(b"a = x ? y : z ? w : v\n");
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::Conditional { then, else_, .. } = expression.kind() else {
            panic!("expected conditional");
        };
        assert_eq!(then.kind().as_str(), "variable-ref");
        let HclExpressionKind::Conditional { .. } = else_.kind() else {
            panic!("expected nested conditional");
        };
        assert_eq!(attribute(&formed, "a").expression().span().end_byte(), 21);
    }

    #[test]
    fn conditional_missing_colon_is_rejected() {
        let formed = parse(b"a = x ? y z\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
    }

    #[test]
    fn tuple_constructor_with_separators_and_trailing_comma() {
        let formed = parse(b"a = [1, 2, 3,]\nb = [\n4\n5\n]\nc = []\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Tuple { elements } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected tuple");
        };
        assert_eq!(elements.len(), 3);
        let HclExpressionKind::Tuple { elements } = attribute(&formed, "b").expression().kind()
        else {
            panic!("expected tuple");
        };
        assert_eq!(elements.len(), 2);
        let HclExpressionKind::Tuple { elements } = attribute(&formed, "c").expression().kind()
        else {
            panic!("expected tuple");
        };
        assert!(elements.is_empty());
    }

    #[test]
    fn tuple_missing_separator_is_recovered_but_elements_survive() {
        let formed = parse(b"a = [1 2]\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::SEPARATOR.to_owned()]);
        let HclExpressionKind::Tuple { elements } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected tuple");
        };
        assert_eq!(elements.len(), 2);
    }

    #[test]
    fn object_constructor_key_forms_and_separators() {
        let formed = parse(b"a = { x = 1, \"y\": 2, (z): 3, 4: 5, }\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Object { entries } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected object");
        };
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[0].key(), HclObjectKey::Identifier(_)));
        assert_eq!(entries[0].separator(), ObjectSeparator::Equals);
        assert!(matches!(entries[1].key(), HclObjectKey::Template(_)));
        assert_eq!(entries[1].separator(), ObjectSeparator::Colon);
        assert!(matches!(entries[2].key(), HclObjectKey::Paren(_)));
        assert_eq!(entries[2].value().kind().as_str(), "number");
        assert!(matches!(entries[3].key(), HclObjectKey::Number(_)));
    }

    #[test]
    fn object_duplicate_keys_are_preserved_in_order() {
        let formed = parse(b"a = { x = 1, x = 2 }\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Object { entries } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected object");
        };
        assert_eq!(entries.len(), 2);
        let HclObjectKey::Identifier(first) = entries[0].key() else {
            panic!("expected identifier key");
        };
        let HclObjectKey::Identifier(second) = entries[1].key() else {
            panic!("expected identifier key");
        };
        assert_eq!(first.as_ref(), "x");
        assert_eq!(second.as_ref(), "x");
    }

    #[test]
    fn object_key_literally_spelled_for_has_for_priority() {
        let formed = parse(b"a = { for = 1 }\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn for_as_later_object_key_is_valid() {
        let formed = parse(b"a = { x = 1, for = 2 }\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Object { entries } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected object");
        };
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn for_as_first_tuple_element_has_for_priority() {
        let formed = parse(b"a = [for, 2]\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
    }

    #[test]
    fn for_tuple_expression_with_key_value_and_guard() {
        let formed = parse(b"a = [for k, v in list : v if v > 1]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expression = attribute(&formed, "a").expression();
        let HclExpressionKind::ForTuple {
            intro,
            value,
            condition,
        } = expression.kind()
        else {
            panic!("expected for-tuple");
        };
        assert_eq!(intro.key(), Some("k"));
        assert_eq!(intro.value(), "v");
        assert_eq!(intro.collection().kind().as_str(), "variable-ref");
        assert_eq!(value.kind().as_str(), "variable-ref");
        assert!(condition.is_some());
        assert_eq!(expression.span().start_byte(), 4);
        assert_eq!(expression.span().end_byte(), 35);
    }

    #[test]
    fn for_tuple_single_identifier_form() {
        let formed = parse(b"a = [for v in list : v]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::ForTuple { intro, .. } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected for-tuple");
        };
        assert_eq!(intro.key(), None);
        assert_eq!(intro.value(), "v");
    }

    #[test]
    fn for_object_expression_with_grouping_and_guard() {
        let formed = parse(b"a = {for k, v in list : k => v... if k}\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::ForObject {
            intro,
            key,
            value,
            grouping,
            condition,
        } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected for-object");
        };
        assert_eq!(intro.key(), Some("k"));
        assert_eq!(key.kind().as_str(), "variable-ref");
        assert_eq!(value.kind().as_str(), "variable-ref");
        assert!(grouping);
        assert!(condition.is_some());
    }

    #[test]
    fn for_expression_collection_parses_full_expression() {
        let formed = parse(b"a = [for v in a + b : v]\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::ForTuple { intro, .. } = attribute(&formed, "a").expression().kind()
        else {
            panic!("expected for-tuple");
        };
        assert_eq!(intro.collection().kind().as_str(), "binary");
    }

    #[test]
    fn expression_text_is_the_exact_source_slice() {
        let formed = parse(b"a = 1 + 2 * 3\n");
        let expression = attribute(&formed, "a").expression();
        assert_eq!(expression_text(&formed, expression), "1 + 2 * 3");
        assert_eq!(expression.span().start_byte(), 4);
        assert_eq!(expression.span().end_byte(), 13);
    }

    #[test]
    fn traversal_after_parenthesized_expression_is_rejected() {
        let formed = parse(b"a = (1 + 2).x\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::NEWLINE.to_owned()));
    }

    #[test]
    fn index_after_function_call_is_a_newline_recovery() {
        // Postfix steps admit variable roots only, so `f(x)[0]` ends the
        // expression at the call and the bracket is an unexpected
        // terminator.
        let formed = parse(b"a = f(x)[0]\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::NEWLINE.to_owned()));
        let HclExpressionKind::FunctionCall { args, .. } =
            attribute(&formed, "a").expression().kind()
        else {
            panic!("expected function call");
        };
        assert_eq!(args.len(), 1);
    }

    #[test]
    fn quoted_template_literal_decodes_escapes() {
        let formed = parse(b"a = \"a\\nb\\t\\\"c\\\\d\\u0041\\U0001F600\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        assert_eq!(parts.len(), 1);
        let HclTemplatePart::Literal { text, .. } = parts[0] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "a\nb\t\"c\\dA\u{1f600}");
    }

    #[test]
    fn escaped_openers_decode_to_literal_text() {
        let formed = parse(b"a = \"$${x}%%{y}\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        assert_eq!(parts.len(), 1);
        let HclTemplatePart::Literal { text, .. } = parts[0] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "${x}%{y}");
        // The template is literal-complete with the escaped openers.
        assert!(crate::expression::is_literal_complete(
            attribute(&formed, "a").expression()
        ));
    }

    #[test]
    fn interpolation_part_assembly_with_spans() {
        let formed = parse(b"a = \"x${b}c\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        assert_eq!(parts.len(), 3);
        assert!(parts[0].is_literal());
        let HclTemplatePart::Interpolation { span, expression } = parts[1] else {
            panic!("expected interpolation");
        };
        assert_eq!(expression.kind().as_str(), "variable-ref");
        assert_eq!(span.start_byte(), 6);
        assert_eq!(span.end_byte(), 10);
        assert_eq!(expression_text(&formed, expression), "b");
        let HclTemplatePart::Literal { text, .. } = parts[2] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "c");
    }

    #[test]
    fn nested_template_inside_interpolation() {
        let formed = parse(b"a = \"${ \"x\" }\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        let HclTemplatePart::Interpolation { expression, .. } = parts[0] else {
            panic!("expected interpolation");
        };
        assert_eq!(expression.kind().as_str(), "template");
    }

    #[test]
    fn strip_markers_are_span_internal_facts() {
        let formed = parse(b"a = \"${~ x ~}\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        assert_eq!(parts.len(), 1);
        let HclTemplatePart::Interpolation { span, expression } = parts[0] else {
            panic!("expected interpolation");
        };
        assert_eq!(span.start_byte(), 5);
        assert_eq!(span.end_byte(), 13);
        assert_eq!(expression.kind().as_str(), "variable-ref");
    }

    #[test]
    fn directives_parse_all_kinds() {
        let formed =
            parse(b"a = \"%{ if c }x%{ else }y%{ endif }%{ for k, v in list }z%{ endfor }\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        assert_eq!(parts.len(), 8);
        assert!(matches!(
            parts[0],
            HclTemplatePart::Directive {
                kind: HclDirectiveKind::If { .. },
                ..
            }
        ));
        assert!(matches!(
            parts[2],
            HclTemplatePart::Directive {
                kind: HclDirectiveKind::Else,
                ..
            }
        ));
        assert!(matches!(
            parts[5],
            HclTemplatePart::Directive {
                kind: HclDirectiveKind::For { .. },
                ..
            }
        ));
        assert!(matches!(
            parts[7],
            HclTemplatePart::Directive {
                kind: HclDirectiveKind::EndFor,
                ..
            }
        ));
    }

    #[test]
    fn single_identifier_for_directive_is_valid() {
        // RFC 0014 §12 D-7.
        let formed = parse(b"a = \"%{ for x in list }y%{ endfor }\"\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "a").expression());
        let HclTemplatePart::Directive {
            kind: HclDirectiveKind::For { intro },
            ..
        } = parts[0]
        else {
            panic!("expected for directive");
        };
        assert_eq!(intro.key(), None);
        assert_eq!(intro.value(), "x");
    }

    #[test]
    fn malformed_directive_is_recovered() {
        let formed = parse(b"a = \"x%{ bogus }y\"\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::DIRECTIVE.to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn directive_with_trailing_junk_is_recovered() {
        let formed = parse(b"a = \"%{ if x extra }\"\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::DIRECTIVE.to_owned()));
    }

    #[test]
    fn heredoc_plain_mode_facts_and_parts() {
        let formed = parse(b"x = <<EOT\nhello\nEOT\ny = 2\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expression = attribute(&formed, "x").expression();
        assert_eq!(expression.kind().as_str(), "template");
        let HclExpressionKind::Template { parts, heredoc } = expression.kind() else {
            panic!("expected template");
        };
        let facts = heredoc.as_ref().expect("heredoc facts");
        assert_eq!(facts.mode(), HeredocMode::Plain);
        assert_eq!(facts.marker(), "EOT");
        assert_eq!(facts.marker_span().start_byte(), 6);
        assert_eq!(facts.marker_span().end_byte(), 9);
        let closing = facts.closing_span().expect("closed heredoc");
        assert_eq!(closing.start_byte(), 16);
        assert_eq!(closing.end_byte(), 19);
        assert_eq!(expression.span().start_byte(), 4);
        assert_eq!(expression.span().end_byte(), 19);
        assert_eq!(parts.len(), 2);
        let HclTemplatePart::Literal { text, .. } = &parts[0] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "hello");
        let HclTemplatePart::Literal { text, .. } = &parts[1] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "\n");
        // The literal value is the concatenated content.
        let value = literal_value(expression).expect("literal");
        assert!(matches!(
            value,
            crate::expression::HclLiteralValue::String(ref s) if s == "hello\n"
        ));
    }

    #[test]
    fn heredoc_strip_indent_mode_is_a_preserved_fact() {
        let formed = parse(b"x = <<-EOT\n    a\n      b\nEOT\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Template { heredoc, .. } =
            attribute(&formed, "x").expression().kind()
        else {
            panic!("expected template");
        };
        let facts = heredoc.as_ref().expect("heredoc facts");
        assert_eq!(facts.mode(), HeredocMode::StripIndent);
        let value = literal_value(attribute(&formed, "x").expression()).expect("literal");
        assert!(matches!(
            value,
            crate::expression::HclLiteralValue::String(ref s) if s == "a\n  b\n"
        ));
    }

    #[test]
    fn heredoc_interpolation_and_escaped_opener() {
        let formed = parse(b"x = <<EOT\nhi $${name} ${other}\nEOT\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let HclExpressionKind::Template { parts, .. } = attribute(&formed, "x").expression().kind()
        else {
            panic!("expected template");
        };
        assert_eq!(parts.len(), 3);
        let HclTemplatePart::Literal { text, .. } = &parts[0] else {
            panic!("expected literal");
        };
        assert_eq!(text.as_ref(), "hi ${name} ");
        let HclTemplatePart::Interpolation { expression, .. } = &parts[1] else {
            panic!("expected interpolation");
        };
        assert_eq!(expression.kind().as_str(), "variable-ref");
    }

    #[test]
    fn heredoc_closing_line_allows_tabs_and_trailing_whitespace() {
        // RFC 0014 §12 D-8: the closing line matches with TrimSpace.
        for source in [
            b"x = <<EOT\na\n\tEOT\n".as_slice(),
            b"x = <<EOT\na\nEOT   \n".as_slice(),
        ] {
            let formed = parse(source);
            assert_eq!(formed.status(), FormationStatus::Complete);
            let HclExpressionKind::Template { heredoc, .. } =
                attribute(&formed, "x").expression().kind()
            else {
                panic!("expected template");
            };
            assert!(heredoc.as_ref().unwrap().closing_span().is_some());
        }
    }

    #[test]
    fn heredoc_marker_line_with_extra_content_is_literal() {
        let formed = parse(b"x = <<EOT\nEOT extra\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&"hcl.parse.unterminated-heredoc@1".to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn empty_heredoc_is_valid() {
        let formed = parse(b"x = <<EOT\nEOT\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let parts = template_parts(attribute(&formed, "x").expression());
        assert!(parts.is_empty());
    }

    #[test]
    fn heredoc_crlf_content_keeps_raw_bytes() {
        let formed = parse(b"x = <<EOT\na\r\nb\nEOT\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let value = literal_value(attribute(&formed, "x").expression()).expect("literal");
        assert!(matches!(
            value,
            crate::expression::HclLiteralValue::String(ref s) if s == "a\r\nb\n"
        ));
    }

    #[test]
    fn unterminated_quoted_string_kills_the_item_and_the_next_survives() {
        let formed = parse(b"a = \"open\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&"hcl.parse.unterminated-string@1".to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "b").name(), "b");
    }

    #[test]
    fn unterminated_heredoc_kills_the_item_and_the_next_survives() {
        let formed = parse(b"a = <<EOT\ncontent\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&"hcl.parse.unterminated-heredoc@1".to_owned()));
        // The heredoc error region extends to end of file, so the rest of
        // the source belongs to it (RFC 0014 §3).
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn missing_expression_is_an_attribute_failure() {
        let formed = parse(b"a =\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "b").name(), "b");
        assert_regions(&formed, &[("hcl.parse.expression@1", 0, 3)]);
    }

    #[test]
    fn bare_identifier_before_equals_is_an_item_error() {
        let formed = parse(
            b"a 1
b = 2
",
        );
        // `a 1` cannot start an attribute or a block header.
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::ITEM.to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
    }

    #[test]
    fn incomplete_expression_region_ends_at_end_of_line() {
        let formed = parse(b"a = 1 +\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::EXPRESSION.to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "b").name(), "b");
        assert_regions(&formed, &[("hcl.parse.expression@1", 0, 7)]);
    }

    #[test]
    fn unterminated_bracket_extends_to_the_matching_close() {
        // RFC 0014 §3: an unterminated bracket extends the region to
        // the matching close across line ends.
        let formed = parse(b"a = [1, 2\nb = 3]\nc = 4\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "c").name(), "c");
        assert_regions(&formed, &[("hcl.parse.expression@1", 0, 16)]);
    }

    #[test]
    fn unterminated_bracket_without_close_extends_to_end_of_file() {
        let formed = parse(b"a = [1, 2\nb = 3\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.document().body().is_empty());
        let regions = formed.error_regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].span().start_byte(), 0);
        assert_eq!(regions[0].span().end_byte(), 16);
    }

    #[test]
    fn missing_newline_after_attribute_survives_and_eats_the_line() {
        let formed = parse(b"a = 1 b = 2\nc = 3\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::NEWLINE.to_owned()]);
        // The attribute is proven and survives; the rest of the line is
        // consumed by the recovery.
        assert_eq!(attributes(&formed).len(), 2);
        assert_eq!(attribute(&formed, "a").name(), "a");
        assert_eq!(attribute(&formed, "c").name(), "c");
        assert!(formed.error_regions().is_empty());
    }

    #[test]
    fn missing_newline_inside_block_preserves_the_closing_brace() {
        let formed = parse(b"x {\n  a = 1 }\ny = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::NEWLINE.to_owned()]);
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].body().len(), 1);
        assert_eq!(attribute(&formed, "y").name(), "y");
    }

    #[test]
    fn missing_newline_after_block_is_recovered() {
        let formed = parse(b"b { } c = 2\nd = 3\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::NEWLINE.to_owned()]);
        assert_eq!(blocks(&formed).len(), 1);
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "d").name(), "d");
    }

    #[test]
    fn unclosed_block_is_recovered_with_region_to_eof() {
        let formed = parse(b"x {\n  a = 1\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(codes(&formed), vec![codes::BLOCK.to_owned()]);
        assert!(formed.document().body().is_empty());
        assert_regions(&formed, &[("hcl.parse.block@1", 0, 12)]);
    }

    #[test]
    fn invalid_body_item_becomes_an_error_region() {
        let formed = parse(b"= 1\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::ITEM.to_owned()));
        assert_eq!(attributes(&formed).len(), 1);
        assert_eq!(attribute(&formed, "b").name(), "b");
        assert_regions(&formed, &[("hcl.parse.item@1", 0, 3)]);
    }

    #[test]
    fn orphan_closing_delimiter_is_consumed_with_a_diagnostic() {
        let formed = parse(b"a = 1\n}\nb = 2\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::ITEM.to_owned()));
        assert_eq!(attributes(&formed).len(), 2);
        assert_eq!(attribute(&formed, "b").name(), "b");
    }

    #[test]
    fn one_line_block_with_broken_attribute_keeps_the_block() {
        let formed = parse(b"b { a }\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::ATTRIBUTE.to_owned()));
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].body().is_empty());
    }

    #[test]
    fn one_line_block_with_invalid_content_is_recovered() {
        let formed = parse(b"b { = 1 }\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::BLOCK.to_owned()));
        let blocks = blocks(&formed);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].body().is_empty());
    }

    #[test]
    fn one_line_block_missing_close_is_recovered() {
        let formed = parse(b"b { a = 1\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(codes(&formed).contains(&codes::BLOCK.to_owned()));
        assert!(formed.document().body().is_empty());
    }

    #[test]
    fn error_regions_merge_lexer_and_parser_regions_in_source_order() {
        let formed = parse(b"a = \"open\nb = [1, 2\nc = 3]\n");
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let regions = formed.error_regions();
        let starts: Vec<usize> = regions
            .iter()
            .map(|region| region.span().start_byte())
            .collect();
        let mut sorted = starts.clone();
        sorted.sort_unstable();
        assert_eq!(starts, sorted);
        assert!(regions.len() >= 2);
    }

    #[test]
    fn inline_comment_spanning_lines_stays_inside_the_expression() {
        let formed = parse(b"a = 1 /* c\nc */ + 2\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expression = attribute(&formed, "a").expression();
        assert_eq!(expression.kind().as_str(), "binary");
        assert_eq!(expression_text(&formed, expression), "1 /* c\nc */ + 2");
    }

    #[test]
    fn expression_depth_limit_is_fatal() {
        let limits = limited(|l| l.max_expression_depth = 3);
        assert_eq!(
            fatal_code(b"a = (((1)))\n", limits),
            "hcl.limit.expression-depth@1"
        );
        let limits = limited(|l| l.max_expression_depth = 4);
        assert_eq!(
            parse_with(b"a = (((1)))\n", limits).unwrap().status(),
            FormationStatus::Complete
        );
    }

    #[test]
    fn binary_chain_length_limit_is_fatal() {
        let limits = limited(|l| l.max_expression_depth = 3);
        assert_eq!(
            fatal_code(b"a = 1 + 1 + 1 + 1 + 1\n", limits),
            "hcl.limit.expression-depth@1"
        );
        assert_eq!(
            parse_with(b"a = 1 + 1 + 1\n", limits).unwrap().status(),
            FormationStatus::Complete
        );
    }

    #[test]
    fn body_depth_limit_is_fatal() {
        let limits = limited(|l| l.max_body_depth = 2);
        assert_eq!(
            fatal_code(b"a = 1\nb {\nc {\nd = 1\n}\n}\n", limits),
            "hcl.limit.body-depth@1"
        );
    }

    #[test]
    fn default_depth_budgets_keep_the_measured_stack_margin() {
        // The R-3 default-depth audit (plan §7.2, §11). Measured with
        // `cargo run -p consema-hcl --example depth_probe -- <dimension>
        // <levels>` on a 2 MB debug-build thread (Windows 11, x86_64,
        // 2026-08-07), the parse recursion dies of a stack overflow at:
        //
        //   dimension   overflow at   recursion shape
        //   call        63            ladder re-entry per argument
        //   template    64            ladder + region re-lex per level
        //   heredoc     64            ladder + region re-lex per level
        //   for         70            ladder re-entry per collection
        //   object      80            ladder re-entry per value
        //   parens      82            ladder re-entry per paren
        //   tuple       82            ladder re-entry per element
        //   blocks      340           body/block frames per level
        //   conditional 527          1-2 frames per level
        //   unary       586           parse_term frame per level
        //   chain       9,905         iterative parse; left-deep tree drop
        //
        // The frozen defaults truncate at 24 expression and 128 body
        // levels: at least a 2.5× margin below the binding overflow points.
        // The pins below fail if a future change erodes that margin.
        let limits = HclParseLimits::default();
        assert_eq!(limits.max_expression_depth, 24);
        assert_eq!(limits.max_body_depth, 128);
        // 2.5× below the worst measured expression overflow point
        // (call at 63): 5 × 24 = 120 ≤ 2 × 63.
        assert!(5 * limits.max_expression_depth <= 2 * 63);
        // 2.5× below the measured block-nesting overflow point (340):
        // 5 × 128 = 640 ≤ 2 × 340.
        assert!(5 * limits.max_body_depth <= 2 * 340);
    }

    #[test]
    fn deep_nesting_truncates_before_the_stack_on_a_small_thread() {
        use std::fmt::Write as _;
        // The R-3 defect: the frozen defaults must truncate deep recursion
        // before the stack explodes, even on a 2 MB thread. Each adversarial
        // input is 2,000 levels — beyond any production configuration — and
        // must fail with the documented budget code, never a panic and
        // never a stack overflow.
        let mut deep_parens = String::from("a = ");
        for _ in 0..2_000 {
            deep_parens.push('(');
        }
        deep_parens.push('1');
        for _ in 0..2_000 {
            deep_parens.push(')');
        }
        deep_parens.push('\n');

        let mut deep_chain = String::from("a = 1");
        for _ in 0..2_000 {
            deep_chain.push_str(" + 1");
        }
        deep_chain.push('\n');

        let mut deep_blocks = String::from("a = 1\n");
        for index in 0..2_000 {
            let _ = writeln!(deep_blocks, "b{index} {{");
        }
        deep_blocks.push_str("x = 1\n");
        for index in (0..2_000).rev() {
            let _ = writeln!(deep_blocks, "}}");
            let _ = writeln!(deep_blocks, "// close b{index}");
        }

        // True template nesting re-enters a quoted template inside each
        // interpolation; the lexer's template stack grows two frames per
        // level, so beyond ~127 levels the frozen lexical budget fires
        // first, while shallower nesting truncates in the parser.
        let mut deep_templates = String::from("a = \"");
        for _ in 0..2_000 {
            deep_templates.push_str("${\"");
        }
        deep_templates.push('1');
        for _ in 0..2_000 {
            deep_templates.push_str("\"}");
        }
        deep_templates.push('"');
        deep_templates.push('\n');

        let mut mid_templates = String::from("a = \"");
        for _ in 0..100 {
            mid_templates.push_str("${\"");
        }
        mid_templates.push('1');
        for _ in 0..100 {
            mid_templates.push_str("\"}");
        }
        mid_templates.push('"');
        mid_templates.push('\n');

        let thread = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let defaults = HclParseLimits::default();
                assert_eq!(
                    fatal_code(deep_parens.as_bytes(), defaults),
                    "hcl.limit.expression-depth@1"
                );
                assert_eq!(
                    fatal_code(deep_chain.as_bytes(), defaults),
                    "hcl.limit.expression-depth@1"
                );
                assert_eq!(
                    fatal_code(deep_blocks.as_bytes(), defaults),
                    "hcl.limit.body-depth@1"
                );
                assert_eq!(
                    fatal_code(deep_templates.as_bytes(), defaults),
                    "hcl.limit.template-depth@1"
                );
                // Shallower template nesting stays inside the lexical
                // budget and truncates in the parser recursion instead.
                assert_eq!(
                    fatal_code(mid_templates.as_bytes(), defaults),
                    "hcl.limit.expression-depth@1"
                );
            })
            .expect("spawning the small-stack thread");
        thread
            .join()
            .expect("the small-stack thread must not panic");
    }

    #[test]
    fn attribute_count_limit_is_fatal() {
        let limits = limited(|l| l.max_attribute_count = 2);
        assert_eq!(
            fatal_code(b"a = 1\nb = 2\nc = 3\n", limits),
            "hcl.limit.attribute-count@1"
        );
    }

    #[test]
    fn block_count_limit_is_fatal() {
        let limits = limited(|l| l.max_block_count = 1);
        assert_eq!(
            fatal_code(b"a {\n}\nb {\n}\n", limits),
            "hcl.limit.block-count@1"
        );
    }

    #[test]
    fn body_item_count_limit_is_fatal() {
        let limits = limited(|l| l.max_body_item_count = 2);
        assert_eq!(
            fatal_code(b"a = 1\nb = 2\nc = 3\n", limits),
            "hcl.limit.body-item-count@1"
        );
    }

    #[test]
    fn label_count_limit_is_fatal() {
        let limits = limited(|l| l.max_label_count = 1);
        assert_eq!(
            fatal_code(b"b \"x\" \"y\" {\n}\n", limits),
            "hcl.limit.label-count@1"
        );
    }

    #[test]
    fn number_digit_limit_is_fatal() {
        let limits = limited(|l| l.max_number_digits = 5);
        assert_eq!(
            fatal_code(b"a = 1e10\n", limits),
            "hcl.limit.number-digits@1"
        );
        assert_eq!(
            parse_with(b"a = 1.5\n", limits).unwrap().status(),
            FormationStatus::Complete
        );
    }

    #[test]
    fn unrepresentable_exponent_is_fatal() {
        assert_eq!(
            fatal_code(b"a = 1e99999999999999999999\n", HclParseLimits::default()),
            "hcl.limit.number-digits@1"
        );
    }

    #[test]
    fn tuple_element_limit_is_fatal() {
        let limits = limited(|l| l.max_tuple_elements = 2);
        assert_eq!(
            fatal_code(b"a = [1, 2, 3]\n", limits),
            "hcl.limit.tuple-elements@1"
        );
    }

    #[test]
    fn object_entry_limit_is_fatal() {
        let limits = limited(|l| l.max_object_entries = 2);
        assert_eq!(
            fatal_code(b"a = {x = 1, y = 2, z = 3}\n", limits),
            "hcl.limit.object-entries@1"
        );
    }

    #[test]
    fn for_extent_limit_is_fatal() {
        let limits = limited(|l| l.max_for_extent = 8);
        assert_eq!(
            fatal_code(b"a = [for v in x : v]\n", limits),
            "hcl.limit.for-extent@1"
        );
    }

    #[test]
    fn recovery_region_limit_is_fatal() {
        let limits = limited(|l| l.max_recovery_regions = 2);
        assert_eq!(
            fatal_code(b"a = 1 +\nb = 1 +\nc = 1 +\n", limits),
            "hcl.limit.recovery-regions@1"
        );
    }

    #[test]
    fn error_region_limit_is_fatal() {
        let limits = limited(|l| l.max_error_regions = 2);
        assert_eq!(
            fatal_code(b"a = 1 +\nb = 1 +\nc = 1 +\n", limits),
            "hcl.limit.error-regions@1"
        );
    }

    #[test]
    fn diagnostics_are_truncated_with_the_house_marker() {
        let limits = limited(|l| l.common.max_diagnostics = 3);
        let formed =
            parse_with(b"a = +\nb = +\nc = +\nd = +\n", limits).expect("truncation is not fatal");
        let codes = codes(&formed);
        assert!(codes.contains(&"core.diagnostic.truncated@1".to_owned()));
        assert!(formed.diagnostics().len() <= 4);
        assert_eq!(formed.status(), FormationStatus::Recovered);
    }

    #[test]
    fn formed_accessors_report_all_facts() {
        let formed = parse(b"a = 1\n");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(formed.render(), b"a = 1\n");
        assert!(formed.diagnostics().is_empty());
        assert!(formed.error_regions().is_empty());
        assert_eq!(formed.document().body().len(), 1);
        let index = formed.lossless_structural_index();
        assert_eq!(index.pieces().len(), formed.lossless_syntax_kinds().len());
        let mut next = 0usize;
        for piece in index.pieces() {
            assert_eq!(piece.span().start_byte(), next, "pieces tile without gaps");
            assert!(piece.span().end_byte() > piece.span().start_byte());
            next = piece.span().end_byte();
        }
        assert_eq!(next, formed.render().len(), "pieces cover every byte");
        // The native document spans are bound to the same snapshot bytes.
        assert_eq!(formed.document().snapshot().bytes(), formed.render());
    }

    #[test]
    fn all_thirty_syntax_kinds_appear_in_one_document() {
        let source = b"# comment\na = 1 + 2\nb = \"x${y}z%{ if c }w%{ endif }\"\nh = <<EOT\nline${x}\nEOT\nc = [1, 2]\nd = {x: 1}\ne = f(1)\ng = x ? 1 : 2\n/* inline */\ni = foo::bar\n";
        let formed = parse(source);
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let names: std::collections::HashSet<&str> = kind_names(&formed).into_iter().collect();
        for spelling in [
            "Whitespace",
            "LineBreak",
            "LineComment",
            "InlineComment",
            "Identifier",
            "Equals",
            "Number",
            "StringOpen",
            "StringContent",
            "StringClose",
            "InterpolationOpen",
            "InterpolationContent",
            "InterpolationClose",
            "DirectiveOpen",
            "DirectiveContent",
            "DirectiveClose",
            "HeredocOpen",
            "HeredocContent",
            "HeredocClose",
            "BraceOpen",
            "BraceClose",
            "BracketOpen",
            "BracketClose",
            "ParenOpen",
            "ParenClose",
            "Comma",
            "Colon",
            "QuestionMark",
            "Operator",
            "ErrorRegion",
        ] {
            assert!(names.contains(spelling), "missing kind {spelling}");
        }
    }

    #[test]
    fn truncation_and_mutation_never_panic() {
        let corpus: &[&[u8]] = &[
            b"a = 1\nb = [1, 2, 3]\n",
            b"resource \"aws_instance\" \"web\" {\n  ami = \"ami-123\"\n  tags = {\n    Name = \"web\"\n  }\n}\n",
            b"x = <<EOT\nhello ${name}\nEOT\n",
            b"a = foo.bar[0].*.baz ? 1 : 2\n",
            b"b \"l1\" \"l2\" {\n  c = f(1, 2...)\n}\n",
            b"a = \"%{ if x }y%{ endif }\"\n",
        ];
        for source in corpus {
            let _ = parse_hcl(Arc::<[u8]>::from(*source), HclParseLimits::default());
            for cut in 0..source.len() {
                let _ = parse_hcl(Arc::<[u8]>::from(&source[..cut]), HclParseLimits::default());
            }
            let mut mutated = source.to_vec();
            for index in 0..mutated.len() {
                mutated[index] = mutated[index].wrapping_add(1);
                let _ = parse_hcl(
                    Arc::<[u8]>::from(mutated.clone()),
                    HclParseLimits::default(),
                );
                mutated[index] = source[index];
            }
        }
    }

    #[test]
    fn expression_kind_names_cover_the_closed_set() {
        let formed = parse(
            b"a = f(1)\nb = foo[0]\nc = -x\nd = x ? 1 : 2\ne = [for v in x : v]\nf = {for k, v in x : k => v}\ng = [1]\nh = {a: 1}\ni = (1)\nj = \"t\"\n",
        );
        assert_eq!(formed.status(), FormationStatus::Complete);
        let expected = [
            "function-call",
            "traversal",
            "unary",
            "conditional",
            "for-tuple",
            "for-object",
            "tuple",
            "object",
            "parenthesized",
            "template",
        ];
        for (name, spelling) in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
            .iter()
            .zip(expected.iter())
        {
            let expression = attribute(&formed, name).expression();
            assert_eq!(expression.kind().as_str(), *spelling);
            assert_eq!(
                HclExpressionKindName::from_name(spelling),
                Some(expression.kind().name())
            );
        }
    }
}
