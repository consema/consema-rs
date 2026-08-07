//! Native HCL semantic model (RFC 0014 §6).
//!
//! The model is the schema-free HCL body tree — not a JSON Object tree, not
//! a Terraform typed object, and not an evaluated value. The root document
//! owns one body; body items preserve source order; attribute and block
//! identity are per-occurrence, never merged. Unlike the plist value model,
//! there is no shared-identity arena: every body item is an independent
//! ordered tree node with its own exact spans.
//!
//! Frozen semantics (RFC 0014 §6): duplicate attributes are excluded at
//! formation and never enter the native model (RFC 0014 §3); duplicate
//! object-constructor keys, duplicate block occurrences, and
//! attribute/block name sharing are preserved as ordered native facts with
//! independent spans; the model contains syntax, never computed values — no
//! variable binding, function table, template expansion, or iteration
//! exists; and no application types exist (no variable declaration,
//! resource, provider, schema, or type-checking role, hard gate 2).
//!
//! [`HclDocument`] is immutable and source-bound: every public span is a
//! half-open raw-byte range of its frozen [`SourceSnapshot`]. The profile
//! layer — which gates Complete formation and the operation surface — is
//! added at the document milestone (M4); this model is profile-independent.

use crate::expression::HclExpression;
use consema_document::{SourceSnapshot, Span};
use std::sync::Arc;

/// Immutable source-bound HCL document: one frozen source and its root body
/// (RFC 0014 §6).
///
/// All spans of the body tree are half-open raw-byte ranges of the bound
/// snapshot; the exact source text of every construct is derived from its
/// span. The profile layer (formation status, diagnostics, lossless
/// coverage, and the per-profile operation surface) is added at the
/// document milestone (M4); this model is profile-independent.
#[derive(Clone, Debug)]
pub struct HclDocument {
    snapshot: Arc<SourceSnapshot>,
    body: HclBody,
}

impl HclDocument {
    /// Binds one frozen source to its root body.
    ///
    /// The body's spans are the parser's contract: every span must be a
    /// half-open raw-byte range of `snapshot`; the native model does not
    /// re-validate duplicate attributes, which formation excludes before
    /// any native item exists (RFC 0014 §3).
    #[must_use]
    pub const fn new(snapshot: Arc<SourceSnapshot>, body: HclBody) -> Self {
        Self { snapshot, body }
    }

    /// Root body; the same body container serves nested block bodies.
    #[must_use]
    pub const fn body(&self) -> &HclBody {
        &self.body
    }

    /// Frozen source snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &Arc<SourceSnapshot> {
        &self.snapshot
    }
}

/// Ordered body item container (RFC 0014 §6).
///
/// A body holds attributes and blocks interleaved in source order; the root
/// body of a document and every nested block body share this container.
#[derive(Clone, Debug)]
pub struct HclBody {
    items: Arc<[HclBodyItem]>,
}

impl HclBody {
    /// Creates a body from its ordered items.
    #[must_use]
    pub fn from_items(items: impl Into<Arc<[HclBodyItem]>>) -> Self {
        Self {
            items: items.into(),
        }
    }

    /// Ordered body items, interleaving attributes and blocks in source
    /// order.
    #[must_use]
    pub fn items(&self) -> &[HclBodyItem] {
        &self.items
    }

    /// Number of body items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the body has no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// One body item: an attribute or a block occurrence (RFC 0014 §4.2, §6).
///
/// Identity is per-occurrence: an attribute and a block may share a name in
/// one body, blocks of the same type and labels may repeat, and every
/// occurrence keeps its own spans; nothing is merged or resolved.
#[derive(Clone, Debug)]
pub enum HclBodyItem {
    /// An attribute occurrence.
    Attribute(HclAttribute),
    /// A block occurrence, including one-line blocks.
    Block(HclBlock),
}

impl HclBodyItem {
    /// Attribute view.
    #[must_use]
    pub const fn as_attribute(&self) -> Option<&HclAttribute> {
        match self {
            Self::Attribute(attribute) => Some(attribute),
            Self::Block(_) => None,
        }
    }

    /// Block view.
    #[must_use]
    pub const fn as_block(&self) -> Option<&HclBlock> {
        match self {
            Self::Attribute(_) => None,
            Self::Block(block) => Some(block),
        }
    }
}

/// One attribute occurrence: name, equals sign, and expression (RFC 0014
/// §4.2, §6).
///
/// The expression is a first-class native role with its own exact span; the
/// attribute's full source range is the union of the name, equals, and
/// expression spans.
#[derive(Clone, Debug)]
pub struct HclAttribute {
    name: Arc<str>,
    name_span: Span,
    equals_span: Span,
    expression: HclExpression,
}

impl HclAttribute {
    /// Creates one attribute occurrence.
    #[must_use]
    pub const fn new(
        name: Arc<str>,
        name_span: Span,
        equals_span: Span,
        expression: HclExpression,
    ) -> Self {
        Self {
            name,
            name_span,
            equals_span,
            expression,
        }
    }

    /// Attribute name; keyword spellings such as `true` are valid names
    /// (RFC 0014 §4.1).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Exact span of the name identifier.
    #[must_use]
    pub const fn name_span(&self) -> Span {
        self.name_span
    }

    /// Exact span of the `=` equals sign.
    #[must_use]
    pub const fn equals_span(&self) -> Span {
        self.equals_span
    }

    /// Value expression, unevaluated (RFC 0014 §1).
    #[must_use]
    pub const fn expression(&self) -> &HclExpression {
        &self.expression
    }
}

/// One block occurrence: type, ordered labels, and nested body (RFC 0014
/// §4.2, §6).
///
/// A one-line block is the same native shape with at most one attribute and
/// no nested blocks. Keyword spellings are valid block types (RFC 0014
/// §4.1), and blocks of the same type and labels may repeat with
/// per-occurrence identity.
#[derive(Clone, Debug)]
pub struct HclBlock {
    block_type: Arc<str>,
    labels: Arc<[HclBlockLabel]>,
    body: HclBody,
    span: Span,
}

impl HclBlock {
    /// Creates one block occurrence.
    #[must_use]
    pub const fn new(
        block_type: Arc<str>,
        labels: Arc<[HclBlockLabel]>,
        body: HclBody,
        span: Span,
    ) -> Self {
        Self {
            block_type,
            labels,
            body,
            span,
        }
    }

    /// Block type identifier.
    #[must_use]
    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    /// Ordered labels; each carries its quote/naked fact.
    #[must_use]
    pub fn labels(&self) -> &[HclBlockLabel] {
        &self.labels
    }

    /// Nested body (empty for a one-line block or a block with no items).
    #[must_use]
    pub const fn body(&self) -> &HclBody {
        &self.body
    }

    /// Exact span of the whole block, from the type identifier through the
    /// closing brace.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// One block label with its quote/naked fact (RFC 0014 §4.2, §6).
///
/// A label is either a naked identifier or a quoted literal string without
/// interpolation; the `quoted` fact and the exact span preserve the source
/// form.
#[derive(Clone, Debug)]
pub struct HclBlockLabel {
    text: Arc<str>,
    span: Span,
    quoted: bool,
}

impl HclBlockLabel {
    /// Creates one label occurrence.
    #[must_use]
    pub const fn new(text: Arc<str>, span: Span, quoted: bool) -> Self {
        Self { text, span, quoted }
    }

    /// Label text; for a quoted label this is the content without the quote
    /// delimiters (escapes are decoded by the parser).
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Exact span, including the quote delimiters when quoted.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Whether the label is a quoted literal string; `false` for a naked
    /// identifier (RFC 0014 §6).
    #[must_use]
    pub const fn quoted(&self) -> bool {
        self.quoted
    }
}

/// One recovered HCL error region with its stable diagnostic code (RFC 0014
/// §3, §7.2).
///
/// Recovery regions are deterministic boundaries: an expression region ends
/// at end of line (extended by unterminated brackets/parens/braces to a
/// matching close or end of line, by unterminated strings to end of line,
/// and by unterminated heredocs to end of file within the heredoc size
/// limit). Every error region corresponds to a `hcl.parse.*@1` diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HclErrorRegion {
    span: Span,
    code: &'static str,
}

impl HclErrorRegion {
    /// Creates one error region.
    #[must_use]
    pub const fn new(span: Span, code: &'static str) -> Self {
        Self { span, code }
    }

    /// Exact recovered region span.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Stable `hcl.parse.*@1` diagnostic code of the region.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

/// Closed HCL lossless syntax kind set (RFC 0014 §7.2).
///
/// Exactly thirty kinds. Every non-empty raw byte of a formed document
/// belongs to exactly one ordered structural piece with one of these kinds;
/// there is no `Bom` kind because a BOM is excluded at formation (RFC 0014
/// §2). `HeredocOpen` covers the `<<`/`<<-` introducer and the marker
/// identifier; `HeredocClose` covers the closing marker line.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HclSyntaxKind {
    /// Space or tab trivia.
    Whitespace,
    /// LF or CRLF newline sequence.
    LineBreak,
    /// `//` or `#` line comment.
    LineComment,
    /// `/* ... */` inline comment.
    InlineComment,
    /// Identifier token.
    Identifier,
    /// `=` equals sign.
    Equals,
    /// Number literal token.
    Number,
    /// `"` quoted-template opening quote.
    StringOpen,
    /// Quoted-template literal content.
    StringContent,
    /// `"` quoted-template closing quote.
    StringClose,
    /// `${` interpolation opening (with optional `~` strip marker).
    InterpolationOpen,
    /// Interpolation content between the opening and closing markers.
    InterpolationContent,
    /// `}` interpolation closing (with optional `~` strip marker).
    InterpolationClose,
    /// `%{` directive opening (with optional `~` strip marker).
    DirectiveOpen,
    /// Directive content between the opening and closing markers.
    DirectiveContent,
    /// `}` directive closing (with optional `~` strip marker).
    DirectiveClose,
    /// `<<`/`<<-` heredoc introducer and marker identifier.
    HeredocOpen,
    /// Heredoc content line.
    HeredocContent,
    /// Heredoc closing marker line.
    HeredocClose,
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
    /// `,` comma.
    Comma,
    /// `:` colon.
    Colon,
    /// `?` question mark.
    QuestionMark,
    /// Operator token (`-`, `!`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `+`,
    /// `*`, `/`, `%`, `&&`, `||`).
    Operator,
    /// Recovered error region (BOM, lone CR, invalid character, or error
    /// token region).
    ErrorRegion,
}

impl HclSyntaxKind {
    /// Stable kind spelling (RFC 0014 §7.2).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Whitespace => "Whitespace",
            Self::LineBreak => "LineBreak",
            Self::LineComment => "LineComment",
            Self::InlineComment => "InlineComment",
            Self::Identifier => "Identifier",
            Self::Equals => "Equals",
            Self::Number => "Number",
            Self::StringOpen => "StringOpen",
            Self::StringContent => "StringContent",
            Self::StringClose => "StringClose",
            Self::InterpolationOpen => "InterpolationOpen",
            Self::InterpolationContent => "InterpolationContent",
            Self::InterpolationClose => "InterpolationClose",
            Self::DirectiveOpen => "DirectiveOpen",
            Self::DirectiveContent => "DirectiveContent",
            Self::DirectiveClose => "DirectiveClose",
            Self::HeredocOpen => "HeredocOpen",
            Self::HeredocContent => "HeredocContent",
            Self::HeredocClose => "HeredocClose",
            Self::BraceOpen => "BraceOpen",
            Self::BraceClose => "BraceClose",
            Self::BracketOpen => "BracketOpen",
            Self::BracketClose => "BracketClose",
            Self::ParenOpen => "ParenOpen",
            Self::ParenClose => "ParenClose",
            Self::Comma => "Comma",
            Self::Colon => "Colon",
            Self::QuestionMark => "QuestionMark",
            Self::Operator => "Operator",
            Self::ErrorRegion => "ErrorRegion",
        }
    }

    /// Resolves one kind spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "Whitespace" => Self::Whitespace,
            "LineBreak" => Self::LineBreak,
            "LineComment" => Self::LineComment,
            "InlineComment" => Self::InlineComment,
            "Identifier" => Self::Identifier,
            "Equals" => Self::Equals,
            "Number" => Self::Number,
            "StringOpen" => Self::StringOpen,
            "StringContent" => Self::StringContent,
            "StringClose" => Self::StringClose,
            "InterpolationOpen" => Self::InterpolationOpen,
            "InterpolationContent" => Self::InterpolationContent,
            "InterpolationClose" => Self::InterpolationClose,
            "DirectiveOpen" => Self::DirectiveOpen,
            "DirectiveContent" => Self::DirectiveContent,
            "DirectiveClose" => Self::DirectiveClose,
            "HeredocOpen" => Self::HeredocOpen,
            "HeredocContent" => Self::HeredocContent,
            "HeredocClose" => Self::HeredocClose,
            "BraceOpen" => Self::BraceOpen,
            "BraceClose" => Self::BraceClose,
            "BracketOpen" => Self::BracketOpen,
            "BracketClose" => Self::BracketClose,
            "ParenOpen" => Self::ParenOpen,
            "ParenClose" => Self::ParenClose,
            "Comma" => Self::Comma,
            "Colon" => Self::Colon,
            "QuestionMark" => Self::QuestionMark,
            "Operator" => Self::Operator,
            "ErrorRegion" => Self::ErrorRegion,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::{HclExpression, HclExpressionKind, HclNumber};
    use consema_document::DocumentAuthority;

    const ALL_KINDS: [HclSyntaxKind; 30] = [
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
    ];

    fn span(authority: &DocumentAuthority, start: usize, end: usize) -> Span {
        authority.span(start, end).expect("valid span")
    }

    fn number_expr(
        authority: &DocumentAuthority,
        start: usize,
        end: usize,
        spelling: &str,
    ) -> HclExpression {
        HclExpression::new(
            HclExpressionKind::Number(
                HclNumber::from_spelling(span(authority, start, end), spelling)
                    .expect("valid number spelling"),
            ),
            span(authority, start, end),
        )
    }

    fn attribute(
        authority: &DocumentAuthority,
        name: &str,
        name_span: (usize, usize),
        equals_span: (usize, usize),
        expression_span: (usize, usize),
    ) -> HclAttribute {
        HclAttribute::new(
            Arc::from(name),
            span(authority, name_span.0, name_span.1),
            span(authority, equals_span.0, equals_span.1),
            number_expr(authority, expression_span.0, expression_span.1, "1"),
        )
    }

    fn block(
        authority: &DocumentAuthority,
        block_type: &str,
        labels: Vec<HclBlockLabel>,
        body: HclBody,
        start: usize,
        end: usize,
    ) -> HclBlock {
        HclBlock::new(
            Arc::from(block_type),
            labels.into(),
            body,
            span(authority, start, end),
        )
    }

    #[test]
    fn body_preserves_interleaved_item_order() {
        let authority = DocumentAuthority::fresh();
        let body = HclBody::from_items(vec![
            HclBodyItem::Attribute(attribute(&authority, "a", (0, 1), (2, 3), (4, 5))),
            HclBodyItem::Block(block(
                &authority,
                "b",
                vec![],
                HclBody::from_items(vec![HclBodyItem::Attribute(attribute(
                    &authority,
                    "c",
                    (8, 9),
                    (10, 11),
                    (12, 13),
                ))]),
                6,
                16,
            )),
            HclBodyItem::Attribute(attribute(&authority, "d", (17, 18), (19, 20), (21, 22))),
        ]);
        assert_eq!(body.len(), 3);
        assert!(body.items()[0].as_attribute().is_some());
        assert!(body.items()[1].as_block().is_some());
        assert!(body.items()[2].as_attribute().is_some());
        assert_eq!(body.items()[0].as_attribute().unwrap().name(), "a");
        assert_eq!(body.items()[1].as_block().unwrap().block_type(), "b");
        assert_eq!(body.items()[2].as_attribute().unwrap().name(), "d");
    }

    #[test]
    fn body_len_and_empty() {
        let empty = HclBody::from_items(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.items().is_empty());
    }

    #[test]
    fn body_item_accessors_are_exclusive() {
        let authority = DocumentAuthority::fresh();
        let item = HclBodyItem::Attribute(attribute(&authority, "a", (0, 1), (2, 3), (4, 5)));
        assert!(item.as_attribute().is_some());
        assert!(item.as_block().is_none());
        let item = HclBodyItem::Block(block(
            &authority,
            "b",
            vec![],
            HclBody::from_items(vec![]),
            0,
            4,
        ));
        assert!(item.as_block().is_some());
        assert!(item.as_attribute().is_none());
    }

    #[test]
    fn attribute_accessors_report_name_equals_and_expression() {
        let authority = DocumentAuthority::fresh();
        let attribute = attribute(&authority, "true", (0, 4), (5, 6), (7, 8));
        assert_eq!(attribute.name(), "true");
        assert_eq!(attribute.name_span(), span(&authority, 0, 4));
        assert_eq!(attribute.equals_span(), span(&authority, 5, 6));
        assert_eq!(attribute.expression().span(), span(&authority, 7, 8));
        assert_eq!(attribute.expression().kind().as_str(), "number");
    }

    #[test]
    fn block_accessors_report_type_labels_body_and_span() {
        let authority = DocumentAuthority::fresh();
        let nested = HclBody::from_items(vec![HclBodyItem::Attribute(attribute(
            &authority,
            "c",
            (10, 11),
            (12, 13),
            (14, 15),
        ))]);
        let labels = vec![
            HclBlockLabel::new(Arc::from("web"), span(&authority, 4, 9), true),
            HclBlockLabel::new(Arc::from("prod"), span(&authority, 10, 14), false),
        ];
        let block = block(&authority, "resource", labels, nested, 0, 18);
        assert_eq!(block.block_type(), "resource");
        assert_eq!(block.labels().len(), 2);
        assert_eq!(block.labels()[0].text(), "web");
        assert_eq!(block.body().len(), 1);
        assert_eq!(block.body().items()[0].as_attribute().unwrap().name(), "c");
        assert_eq!(block.span(), span(&authority, 0, 18));
    }

    #[test]
    fn block_label_carries_quote_and_naked_facts() {
        let authority = DocumentAuthority::fresh();
        let quoted = HclBlockLabel::new(Arc::from("web"), span(&authority, 4, 9), true);
        assert_eq!(quoted.text(), "web");
        assert_eq!(quoted.span(), span(&authority, 4, 9));
        assert!(quoted.quoted());
        let naked = HclBlockLabel::new(Arc::from("prod"), span(&authority, 10, 14), false);
        assert!(!naked.quoted());
        assert_eq!(naked.text(), "prod");
    }

    #[test]
    fn document_binds_snapshot_and_body() {
        let authority = DocumentAuthority::fresh();
        let source = SourceSnapshot::from_utf8(b"a = 1".to_vec()).expect("utf-8");
        let body = HclBody::from_items(vec![HclBodyItem::Attribute(attribute(
            &authority,
            "a",
            (0, 1),
            (2, 3),
            (4, 5),
        ))]);
        let document = HclDocument::new(Arc::new(source), body);
        assert_eq!(document.body().len(), 1);
        assert_eq!(
            document.body().items()[0].as_attribute().unwrap().name(),
            "a"
        );
        assert_eq!(document.snapshot().bytes(), b"a = 1");
    }

    #[test]
    fn error_region_carries_span_and_code() {
        let authority = DocumentAuthority::fresh();
        let region = HclErrorRegion::new(span(&authority, 4, 11), "hcl.parse.invalid-number@1");
        assert_eq!(region.span(), span(&authority, 4, 11));
        assert_eq!(region.code(), "hcl.parse.invalid-number@1");
    }

    #[test]
    fn syntax_kind_closed_set_has_exactly_thirty_kinds() {
        assert_eq!(ALL_KINDS.len(), 30);
        let mut seen = std::collections::HashSet::new();
        for kind in ALL_KINDS {
            let spelling = kind.as_str();
            assert_eq!(HclSyntaxKind::from_name(spelling), Some(kind));
            assert!(seen.insert(kind), "kind set must not repeat {kind:?}");
        }
        assert_eq!(seen.len(), 30);
        assert_eq!(HclSyntaxKind::from_name("Bom"), None);
    }

    #[test]
    fn syntax_kind_spellings_match_the_rfc_721_list() {
        let spellings = [
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
        ];
        for (kind, spelling) in ALL_KINDS.iter().zip(spellings.iter()) {
            assert_eq!(kind.as_str(), *spelling);
        }
    }
}
