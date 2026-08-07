//! HCL expression AST (RFC 0014 §4.3-§4.6, §6, §8.1).
//!
//! An expression is a first-class native role: the AST retains the frozen
//! grammar as a kind with ordered children and exact half-open raw-byte
//! spans, and its exact source text is always derived from the span against
//! the immutable source — no re-encoding is needed and no information is
//! lost (RFC 0014 §6). Both representations are always available: the AST
//! for structure, the span-derived text for exactness.
//!
//! Structural equality (RFC 0014 §6) is recursive over kind and children:
//! number equality is canonical-decimal equality, template equality is
//! part-wise with exact literal text and structural interpolation/directive
//! comparison, constructor equality is element-wise, and node identity and
//! source spans are never part of value equality. This is the equality used
//! by query filters, projection comparison, and the `hcl.expression@1`
//! contract.
//!
//! The literal-complete boundary (RFC 0014 §8.1) is a purely syntactic
//! predicate: no evaluation, no arithmetic folding, no context. It is
//! decidable without any evaluator, and `literal_value` extracts the typed
//! literal projection that the `hcl.body@1` record consumes at projection
//! time. Numbers normalize to canonical decimal by pure decimal string
//! arithmetic — zero floating-point computation (hard gate 1) — so `1.50`,
//! `1.5`, and `15e-1` compare equal as values while remaining distinct
//! source facts.
//!
//! Templates cover both quoted templates and heredocs (RFC 0014 §4.4-§4.5):
//! a heredoc is a template whose ordered parts are the heredoc content, and
//! whose mode (`<<`/`<<-`), marker spelling, and closing-line facts are
//! representation facts carried by [`HeredocFacts`]. The indentation
//! stripping of `<<-` is performed only when the template's literal value is
//! read, never destructively.

use crate::HclParseLimits;
use consema_document::{LocationError, SourceSnapshot, Span};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Half-open raw-byte range of one expression AST node; the exact source
/// text is always derived from the span against the frozen source (RFC 0014
/// §6 double preservation).
#[derive(Clone, Debug)]
pub struct HclExpression {
    kind: HclExpressionKind,
    span: Span,
}

impl HclExpression {
    /// Creates one expression node from its kind and exact span.
    #[must_use]
    pub const fn new(kind: HclExpressionKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Closed native expression kind.
    #[must_use]
    pub const fn kind(&self) -> &HclExpressionKind {
        &self.kind
    }

    /// Exact source span, including all trivia, operators, and delimiters.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Exact source text derived from the span.
    ///
    /// HCL is UTF-8 only, so the span slice of the decoded text is the exact
    /// original spelling; this is the double-preserved raw text that no
    /// re-encoding can reproduce (RFC 0014 §6).
    pub fn text<'a>(&self, source: &'a SourceSnapshot) -> Result<&'a str, LocationError> {
        let start = source.decoded_position(self.span.start_byte())?;
        let end = source.decoded_position(self.span.end_byte())?;
        let decoded = source.decoded_text().ok_or(LocationError::NoDecodedText)?;
        Ok(&decoded[start.decoded_utf8_byte..end.decoded_utf8_byte])
    }

    /// Ordered direct child expressions in source order.
    ///
    /// The children are the expression nodes reachable from the variant
    /// fields without descending into nested expressions: binary operands,
    /// function-call arguments, interpolation and directive expressions,
    /// traversal index keys (including keys inside splat steps), constructor
    /// elements and object-entry keys and values, and for-expression
    /// collection/value/guard expressions.
    #[must_use]
    pub fn children(&self) -> Vec<&HclExpression> {
        let mut children = Vec::new();
        match self.kind() {
            HclExpressionKind::Number(_)
            | HclExpressionKind::Boolean(_)
            | HclExpressionKind::Null
            | HclExpressionKind::VariableRef { .. } => {}
            HclExpressionKind::Template { parts, .. } => {
                collect_template_part_children(parts.as_ref(), &mut children);
            }
            HclExpressionKind::FunctionCall { args, .. } => {
                children.extend(args.iter().map(HclCallArg::expression));
            }
            HclExpressionKind::Traversal { steps, .. } => {
                for step in steps.iter() {
                    match step {
                        HclTraversalStep::Index { key, .. } => children.push(key),
                        HclTraversalStep::AttrSplat { steps }
                        | HclTraversalStep::FullSplat { steps } => {
                            for inner in steps.iter() {
                                if let HclTraversalStep::Index { key, .. } = inner {
                                    children.push(key);
                                }
                            }
                        }
                        HclTraversalStep::GetAttr { .. } => {}
                    }
                }
            }
            HclExpressionKind::Unary { operand, .. } => children.push(operand),
            HclExpressionKind::Binary { lhs, rhs, .. } => {
                children.push(lhs);
                children.push(rhs);
            }
            HclExpressionKind::Conditional {
                condition,
                then,
                else_,
                ..
            } => {
                children.push(condition);
                children.push(then);
                children.push(else_);
            }
            HclExpressionKind::ForTuple {
                intro,
                value,
                condition,
                ..
            } => {
                children.push(intro.collection());
                children.push(value);
                if let Some(condition) = condition {
                    children.push(condition);
                }
            }
            HclExpressionKind::ForObject {
                intro,
                key,
                value,
                condition,
                ..
            } => {
                children.push(intro.collection());
                children.push(key);
                children.push(value);
                if let Some(condition) = condition {
                    children.push(condition);
                }
            }
            HclExpressionKind::Tuple { elements } => children.extend(elements.iter()),
            HclExpressionKind::Object { entries } => {
                for entry in entries.iter() {
                    match entry.key() {
                        HclObjectKey::Paren(inner) => children.push(inner),
                        HclObjectKey::Template(template) => {
                            collect_template_part_children(template.parts(), &mut children);
                        }
                        HclObjectKey::Identifier(_) | HclObjectKey::Number(_) => {}
                    }
                    children.push(entry.value());
                }
            }
            HclExpressionKind::Paren { inner } => children.push(inner),
        }
        children
    }
}

impl PartialEq for HclExpression {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Eq for HclExpression {}

impl Hash for HclExpression {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
    }
}

/// Closed native HCL expression kind (RFC 0014 §4.3-§4.6).
///
/// The variant set is closed by the frozen grammar. A quoted template and a
/// heredoc are one kind: a heredoc is a template whose [`HeredocFacts`] are
/// carried explicitly and whose content parts cover the heredoc body (RFC
/// 0014 §4.4-§4.5, §6). Structural equality is recursive over kind and
/// children and never includes source spans.
#[derive(Clone, Debug)]
pub enum HclExpressionKind {
    /// A decimal number literal with its exact spelling and canonical
    /// decimal value (RFC 0014 §4.1, §6).
    Number(HclNumber),
    /// The `true` or `false` keyword literal (RFC 0014 §4.3).
    Boolean(bool),
    /// The `null` literal (RFC 0014 §4.3).
    Null,
    /// A quoted template or heredoc with ordered parts (RFC 0014 §4.4-§4.5).
    Template {
        /// Ordered literal/interpolation/directive parts.
        parts: Arc<[HclTemplatePart]>,
        /// Heredoc representation facts; `None` for quoted templates.
        heredoc: Option<HeredocFacts>,
    },
    /// A function call `name(args)`; the name is a plain identifier only —
    /// the namespaced `foo::bar()` form is a grammar error (RFC 0014 §4.3,
    /// §12 D-6).
    FunctionCall {
        /// Function name.
        name: Arc<str>,
        /// Exact span of the name identifier.
        name_span: Span,
        /// Ordered arguments, each with its `...` expansion marker fact.
        args: Arc<[HclCallArg]>,
    },
    /// A variable reference: a traversal root with no steps (RFC 0014 §4.1,
    /// §4.3).
    VariableRef {
        /// Variable name.
        name: Arc<str>,
    },
    /// A static traversal: a root followed by attribute, index, and splat
    /// steps; `foo`, `foo.bar`, `foo[0]`, and `foo.*.bar` are traversal
    /// facts, never resolved (RFC 0014 §4.1, §4.3).
    Traversal {
        /// Traversal root; keyword spellings are dual-read roots (RFC 0014
        /// §4.1).
        root: HclTraversalRoot,
        /// Ordered traversal steps.
        steps: Arc<[HclTraversalStep]>,
    },
    /// A unary operation. Only `-` and `!` exist; unary `+` is a grammar
    /// error, and unary operators bind at the term layer above every binary
    /// operator (RFC 0014 §4.3).
    Unary {
        /// Unary operator.
        op: UnaryOp,
        /// Operand.
        operand: Box<HclExpression>,
    },
    /// A binary operation; left-associative within its precedence level
    /// (RFC 0014 §4.3).
    Binary {
        /// Binary operator.
        op: BinaryOp,
        /// Left operand.
        lhs: Box<HclExpression>,
        /// Right operand.
        rhs: Box<HclExpression>,
    },
    /// The conditional `condition ? then : else` production, which never
    /// binds tighter than `||` (RFC 0014 §4.3).
    Conditional {
        /// Condition expression.
        condition: Box<HclExpression>,
        /// Then-branch expression.
        then: Box<HclExpression>,
        /// Else-branch expression.
        else_: Box<HclExpression>,
    },
    /// A tuple for-expression `[for ... : value if cond]`; no iteration is
    /// ever performed (RFC 0014 §4.6, §6).
    ForTuple {
        /// The `for` introduction.
        intro: HclForIntro,
        /// Value expression.
        value: Box<HclExpression>,
        /// Optional `if` guard.
        condition: Option<Box<HclExpression>>,
    },
    /// An object for-expression `{for ... : key => value ... if cond}`;
    /// the `...` grouping marker is a source fact (RFC 0014 §4.6, §6).
    ForObject {
        /// The `for` introduction.
        intro: HclForIntro,
        /// Key expression.
        key: Box<HclExpression>,
        /// Value expression.
        value: Box<HclExpression>,
        /// `...` grouping marker fact.
        grouping: bool,
        /// Optional `if` guard.
        condition: Option<Box<HclExpression>>,
    },
    /// A tuple constructor; elements are ordered, separated by comma or
    /// newline, with a trailing comma admitted (RFC 0014 §4.6).
    Tuple {
        /// Ordered element expressions.
        elements: Arc<[HclExpression]>,
    },
    /// An object constructor; entries are ordered and duplicate keys are
    /// preserved, never collapsed (RFC 0014 §4.6, §6).
    Object {
        /// Ordered entries.
        entries: Arc<[HclObjectEntry]>,
    },
    /// A parenthesized expression `(expr)` (RFC 0014 §4.3).
    Paren {
        /// Inner expression.
        inner: Box<HclExpression>,
    },
}

impl HclExpressionKind {
    /// Closed payload-free kind name (RFC 0014 §7.1 `hcl.expression-kind-is@1`).
    #[must_use]
    pub const fn name(&self) -> HclExpressionKindName {
        match self {
            Self::Number(_) => HclExpressionKindName::Number,
            Self::Boolean(_) => HclExpressionKindName::Boolean,
            Self::Null => HclExpressionKindName::Null,
            Self::Template { .. } => HclExpressionKindName::Template,
            Self::FunctionCall { .. } => HclExpressionKindName::FunctionCall,
            Self::VariableRef { .. } => HclExpressionKindName::VariableRef,
            Self::Traversal { .. } => HclExpressionKindName::Traversal,
            Self::Unary { .. } => HclExpressionKindName::Unary,
            Self::Binary { .. } => HclExpressionKindName::Binary,
            Self::Conditional { .. } => HclExpressionKindName::Conditional,
            Self::ForTuple { .. } => HclExpressionKindName::ForTuple,
            Self::ForObject { .. } => HclExpressionKindName::ForObject,
            Self::Tuple { .. } => HclExpressionKindName::Tuple,
            Self::Object { .. } => HclExpressionKindName::Object,
            Self::Paren { .. } => HclExpressionKindName::Parenthesized,
        }
    }

    /// Stable kind spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.name().as_str()
    }
}

impl PartialEq for HclExpressionKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Null, Self::Null) => true,
            (
                Self::Template {
                    parts: left_parts,
                    heredoc: left_heredoc,
                },
                Self::Template {
                    parts: right_parts,
                    heredoc: right_heredoc,
                },
            ) => left_parts == right_parts && left_heredoc == right_heredoc,
            (
                Self::FunctionCall {
                    name: left_name,
                    args: left_args,
                    ..
                },
                Self::FunctionCall {
                    name: right_name,
                    args: right_args,
                    ..
                },
            ) => left_name == right_name && left_args == right_args,
            (Self::VariableRef { name: left }, Self::VariableRef { name: right }) => left == right,
            (
                Self::Traversal {
                    root: left_root,
                    steps: left_steps,
                },
                Self::Traversal {
                    root: right_root,
                    steps: right_steps,
                },
            ) => left_root == right_root && left_steps == right_steps,
            (
                Self::Unary {
                    op: left_op,
                    operand: left_operand,
                },
                Self::Unary {
                    op: right_op,
                    operand: right_operand,
                },
            ) => left_op == right_op && left_operand == right_operand,
            (
                Self::Binary {
                    op: left_op,
                    lhs: left_lhs,
                    rhs: left_rhs,
                },
                Self::Binary {
                    op: right_op,
                    lhs: right_lhs,
                    rhs: right_rhs,
                },
            ) => left_op == right_op && left_lhs == right_lhs && left_rhs == right_rhs,
            (
                Self::Conditional {
                    condition: left_condition,
                    then: left_then,
                    else_: left_else,
                },
                Self::Conditional {
                    condition: right_condition,
                    then: right_then,
                    else_: right_else,
                },
            ) => {
                left_condition == right_condition
                    && left_then == right_then
                    && left_else == right_else
            }
            (
                Self::ForTuple {
                    intro: left_intro,
                    value: left_value,
                    condition: left_condition,
                },
                Self::ForTuple {
                    intro: right_intro,
                    value: right_value,
                    condition: right_condition,
                },
            ) => {
                left_intro == right_intro
                    && left_value == right_value
                    && left_condition == right_condition
            }
            (
                Self::ForObject {
                    intro: left_intro,
                    key: left_key,
                    value: left_value,
                    grouping: left_grouping,
                    condition: left_condition,
                },
                Self::ForObject {
                    intro: right_intro,
                    key: right_key,
                    value: right_value,
                    grouping: right_grouping,
                    condition: right_condition,
                },
            ) => {
                left_intro == right_intro
                    && left_key == right_key
                    && left_value == right_value
                    && left_grouping == right_grouping
                    && left_condition == right_condition
            }
            (Self::Tuple { elements: left }, Self::Tuple { elements: right }) => left == right,
            (Self::Object { entries: left }, Self::Object { entries: right }) => left == right,
            (Self::Paren { inner: left }, Self::Paren { inner: right }) => left == right,
            _ => false,
        }
    }
}

impl Eq for HclExpressionKind {}

impl Hash for HclExpressionKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Number(number) => {
                0_u8.hash(state);
                number.hash(state);
            }
            Self::Boolean(value) => {
                1_u8.hash(state);
                value.hash(state);
            }
            Self::Null => 2_u8.hash(state),
            Self::Template { parts, heredoc } => {
                3_u8.hash(state);
                parts.hash(state);
                heredoc.hash(state);
            }
            Self::FunctionCall { name, args, .. } => {
                4_u8.hash(state);
                name.hash(state);
                args.hash(state);
            }
            Self::VariableRef { name } => {
                5_u8.hash(state);
                name.hash(state);
            }
            Self::Traversal { root, steps } => {
                6_u8.hash(state);
                root.hash(state);
                steps.hash(state);
            }
            Self::Unary { op, operand } => {
                7_u8.hash(state);
                op.hash(state);
                operand.hash(state);
            }
            Self::Binary { op, lhs, rhs } => {
                8_u8.hash(state);
                op.hash(state);
                lhs.hash(state);
                rhs.hash(state);
            }
            Self::Conditional {
                condition,
                then,
                else_,
            } => {
                9_u8.hash(state);
                condition.hash(state);
                then.hash(state);
                else_.hash(state);
            }
            Self::ForTuple {
                intro,
                value,
                condition,
            } => {
                10_u8.hash(state);
                intro.hash(state);
                value.hash(state);
                condition.hash(state);
            }
            Self::ForObject {
                intro,
                key,
                value,
                grouping,
                condition,
            } => {
                11_u8.hash(state);
                intro.hash(state);
                key.hash(state);
                value.hash(state);
                grouping.hash(state);
                condition.hash(state);
            }
            Self::Tuple { elements } => {
                12_u8.hash(state);
                elements.hash(state);
            }
            Self::Object { entries } => {
                13_u8.hash(state);
                entries.hash(state);
            }
            Self::Paren { inner } => {
                14_u8.hash(state);
                inner.hash(state);
            }
        }
    }
}

/// Closed payload-free expression kind name set (RFC 0014 §7.1
/// `hcl.expression-kind-is@1`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HclExpressionKindName {
    /// Decimal number literal.
    Number,
    /// `true`/`false` keyword literal.
    Boolean,
    /// `null` literal.
    Null,
    /// Quoted template or heredoc.
    Template,
    /// Function call.
    FunctionCall,
    /// Variable reference (bare traversal root).
    VariableRef,
    /// Static traversal with steps.
    Traversal,
    /// Unary operation (`-`, `!`).
    Unary,
    /// Binary operation.
    Binary,
    /// Conditional `? :`.
    Conditional,
    /// Tuple for-expression.
    ForTuple,
    /// Object for-expression.
    ForObject,
    /// Tuple constructor.
    Tuple,
    /// Object constructor.
    Object,
    /// Parenthesized expression.
    Parenthesized,
}

impl HclExpressionKindName {
    /// Stable kind spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Null => "null",
            Self::Template => "template",
            Self::FunctionCall => "function-call",
            Self::VariableRef => "variable-ref",
            Self::Traversal => "traversal",
            Self::Unary => "unary",
            Self::Binary => "binary",
            Self::Conditional => "conditional",
            Self::ForTuple => "for-tuple",
            Self::ForObject => "for-object",
            Self::Tuple => "tuple",
            Self::Object => "object",
            Self::Parenthesized => "parenthesized",
        }
    }

    /// Resolves one stable kind spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "number" => Self::Number,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            "template" => Self::Template,
            "function-call" => Self::FunctionCall,
            "variable-ref" => Self::VariableRef,
            "traversal" => Self::Traversal,
            "unary" => Self::Unary,
            "binary" => Self::Binary,
            "conditional" => Self::Conditional,
            "for-tuple" => Self::ForTuple,
            "for-object" => Self::ForObject,
            "tuple" => Self::Tuple,
            "object" => Self::Object,
            "parenthesized" => Self::Parenthesized,
            _ => return None,
        })
    }
}

/// Exact decimal number literal: source spelling plus canonical value
/// (RFC 0014 §4.1, §6, §8).
///
/// The grammar is decimal only — `decimal+ ("." decimal+)? (expmark
/// decimal+)?` with `expmark = ("e" | "E") ("+" | "-")?` — with no leading
/// sign (`-` is a unary operator, and unary `+` does not exist), no
/// hexadecimal/octal/binary form, and no underscore separators. The exact
/// source spelling is always derived from the span; the canonical decimal is
/// the normalized pure-decimal spelling with no leading zeros, no trailing
/// fraction zeros, and the exponent folded into the decimal point position
/// (`0` represents zero). Numeric equality is canonical-decimal equality, so
/// `1.50`, `1.5`, and `15e-1` compare equal as values while remaining
/// distinct source facts (RFC 0014 §6).
#[derive(Clone, Debug)]
pub struct HclNumber {
    span: Span,
    canonical_decimal: Arc<str>,
}

impl HclNumber {
    /// Creates a number from its exact span and canonical decimal spelling.
    ///
    /// The canonical spelling is the parser's contract: it must be the
    /// normalized form of the source spelling at `span`, with at most
    /// `max_number_digits` digits (RFC 0014 §11).
    #[must_use]
    pub fn new(span: Span, canonical_decimal: impl Into<Arc<str>>) -> Self {
        Self {
            span,
            canonical_decimal: canonical_decimal.into(),
        }
    }

    /// Creates a number from its exact source spelling, computing the
    /// canonical decimal.
    ///
    /// Returns `None` when the spelling is not a valid §4.1 number, its
    /// exponent does not fit the bounded canonical-decimal contract, or the
    /// canonical spelling would exceed the frozen `max_number_digits` digit
    /// budget (RFC 0014 §11) — the exponent folding is bounded before any
    /// zero-padding loop runs, never after.
    #[must_use]
    pub fn from_spelling(span: Span, spelling: &str) -> Option<Self> {
        canonical_decimal(spelling).map(|canonical| Self::new(span, canonical))
    }

    /// Exact source span of the number spelling.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Canonical decimal spelling: no leading zeros, no trailing fraction
    /// zeros, exponent folded into the decimal point position, `"0"` for
    /// zero (RFC 0014 §9).
    #[must_use]
    pub fn canonical_decimal(&self) -> &str {
        &self.canonical_decimal
    }
}

impl PartialEq for HclNumber {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_decimal == other.canonical_decimal
    }
}

impl Eq for HclNumber {}

impl Hash for HclNumber {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_decimal.hash(state);
    }
}

/// Normalizes one decimal number spelling to its canonical form by pure
/// decimal string arithmetic — zero floating-point computation (hard
/// gate 1).
///
/// The grammar is frozen by RFC 0014 §4.1: `decimal+ ("." decimal+)?
/// (expmark decimal+)?` with `expmark = ("e" | "E") ("+" | "-")?`, no
/// leading sign. The canonical form strips leading zeros, strips trailing
/// fraction zeros, and folds the exponent into the decimal point position,
/// so `"1.50"` and `"15e-1"` both normalize to `"1.5"`, `"1e3"` to
/// `"1000"`, and every zero spelling to `"0"` (RFC 0014 §6, §9). Returns
/// `None` for a grammar violation or an exponent that does not fit the
/// bounded representation.
///
/// The exponent folding is bounded by the frozen `max_number_digits` digit
/// budget of [`HclParseLimits::default`] (RFC 0014 §11): a spelling whose
/// canonical form would exceed the budget fails with `None` before any
/// zero-padding loop or allocation runs, never after.
#[must_use]
pub fn canonical_decimal(spelling: &str) -> Option<String> {
    canonical_decimal_bounded(spelling, HclParseLimits::default().max_number_digits)
}

/// Bounded canonical-decimal normalization: the same pure-decimal fold as
/// [`canonical_decimal`], but the exponent folding is checked against the
/// `max_digits` budget before any zero-padding loop or allocation runs
/// (RFC 0014 §11) — a canonical spelling with more than `max_digits` digits
/// fails with `None` up front, and the arithmetic never panics on any
/// target width.
#[must_use]
fn canonical_decimal_bounded(spelling: &str, max_digits: usize) -> Option<String> {
    let bytes = spelling.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let integer_len = index;
    if integer_len == 0 {
        return None;
    }
    let mut fraction_len = 0;
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let fraction_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        fraction_len = index - fraction_start;
        if fraction_len == 0 {
            return None;
        }
    }
    let mut exponent: i64 = 0;
    if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
        index += 1;
        let mut negative = false;
        if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
            negative = bytes[index] == b'-';
            index += 1;
        }
        let exponent_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent_start {
            return None;
        }
        let magnitude = spelling[exponent_start..index].parse::<i64>().ok()?;
        exponent = if negative { -magnitude } else { magnitude };
    }
    if index != bytes.len() {
        return None;
    }
    // The value is the concatenated digits with the decimal point after
    // `integer_len + exponent` digits.
    let mut digits = String::with_capacity(integer_len + fraction_len);
    digits.push_str(&spelling[..integer_len]);
    if fraction_len > 0 {
        digits.push_str(&spelling[integer_len + 1..integer_len + 1 + fraction_len]);
    }
    let stripped = digits.trim_start_matches('0');
    let point = (integer_len as i64)
        .checked_add(exponent)?
        .checked_sub((digits.len() - stripped.len()) as i64)?;
    if stripped.is_empty() {
        return Some("0".to_owned());
    }
    let mut out = String::with_capacity(stripped.len() + 2);
    if point <= 0 {
        // The canonical spelling is `0.` plus `zeros` zero digits plus the
        // significant digits, with trailing fraction zeros trimmed — its
        // digit count is exactly `1 + zeros + trimmed.len()`. That count is
        // checked against the budget before any padding loop runs (RFC 0014
        // §11), and the checked negation and width conversion fail
        // gracefully on a min-bound exponent instead of panicking on any
        // target width.
        let zeros = usize::try_from(point.checked_neg()?).ok()?;
        let trimmed = stripped.trim_end_matches('0');
        if zeros.saturating_add(trimmed.len()).saturating_add(1) > max_digits {
            return None;
        }
        out.push_str("0.");
        for _ in 0..zeros {
            out.push('0');
        }
        out.push_str(stripped);
        while out.len() > 2 && out.ends_with('0') {
            out.pop();
        }
    } else {
        let positive = usize::try_from(point).ok()?;
        if positive >= stripped.len() {
            // The canonical spelling is the significant digits followed by
            // `positive - stripped.len()` zeros — exactly `positive` digits
            // — checked against the budget before the padding loop runs
            // (RFC 0014 §11).
            if positive > max_digits {
                return None;
            }
            out.push_str(stripped);
            for _ in 0..positive - stripped.len() {
                out.push('0');
            }
        } else {
            out.push_str(&stripped[..positive]);
            let fraction = stripped[positive..].trim_end_matches('0');
            if !fraction.is_empty() {
                out.push('.');
                out.push_str(fraction);
            }
        }
    }
    Some(out)
}

/// Unary operator set; exactly `-` and `!` exist, and unary `+` is a
/// grammar error (RFC 0014 §4.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnaryOp {
    /// `-` negation.
    Minus,
    /// `!` logical not.
    Not,
}

impl UnaryOp {
    /// Stable operator spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minus => "-",
            Self::Not => "!",
        }
    }

    /// Resolves one operator spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "-" => Some(Self::Minus),
            "!" => Some(Self::Not),
            _ => None,
        }
    }
}

/// Binary operator set, frozen by the RFC 0014 §4.3 precedence table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BinaryOp {
    /// `==` equality.
    Equal,
    /// `!=` inequality.
    NotEqual,
    /// `<` less than.
    Less,
    /// `>` greater than.
    Greater,
    /// `<=` less than or equal.
    LessEqual,
    /// `>=` greater than or equal.
    GreaterEqual,
    /// `+` addition.
    Add,
    /// `-` subtraction.
    Subtract,
    /// `*` multiplication.
    Multiply,
    /// `/` division.
    Divide,
    /// `%` modulo.
    Modulo,
    /// `&&` logical and.
    And,
    /// `||` logical or.
    Or,
}

impl BinaryOp {
    /// Stable operator spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::Less => "<",
            Self::Greater => ">",
            Self::LessEqual => "<=",
            Self::GreaterEqual => ">=",
            Self::Add => "+",
            Self::Subtract => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Modulo => "%",
            Self::And => "&&",
            Self::Or => "||",
        }
    }

    /// Resolves one operator spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "==" => Self::Equal,
            "!=" => Self::NotEqual,
            "<" => Self::Less,
            ">" => Self::Greater,
            "<=" => Self::LessEqual,
            ">=" => Self::GreaterEqual,
            "+" => Self::Add,
            "-" => Self::Subtract,
            "*" => Self::Multiply,
            "/" => Self::Divide,
            "%" => Self::Modulo,
            "&&" => Self::And,
            "||" => Self::Or,
            _ => return None,
        })
    }
}

/// Traversal root; keyword spellings are dual-read roots, behaving as if
/// they were references to variables of those names without ever being
/// evaluated (RFC 0014 §4.1).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HclTraversalRoot {
    /// A variable-name root.
    Variable(Arc<str>),
    /// The `true`/`false` keyword as a static traversal root.
    Boolean(bool),
    /// The `null` keyword as a static traversal root.
    Null,
}

/// One static traversal step (RFC 0014 §4.3).
///
/// Attribute steps admit identifiers only: the numeric form `foo.0` is a
/// grammar error (RFC 0014 §12 D-5). Splat steps nest further steps: an
/// attribute splat admits attribute steps only, a full splat admits
/// attribute and index steps.
#[derive(Clone, Debug)]
pub enum HclTraversalStep {
    /// `.Identifier` attribute step.
    GetAttr {
        /// Attribute name.
        name: Arc<str>,
        /// Exact span of the step, including the dot.
        span: Span,
    },
    /// `[Expression]` index step.
    Index {
        /// Index key expression.
        key: Box<HclExpression>,
        /// Exact span of the step, including the brackets.
        span: Span,
    },
    /// `. * GetAttr*` attribute splat.
    AttrSplat {
        /// Nested attribute steps.
        steps: Arc<[HclTraversalStep]>,
    },
    /// `[ * ] (GetAttr | Index)*` full splat.
    FullSplat {
        /// Nested attribute and index steps.
        steps: Arc<[HclTraversalStep]>,
    },
}

impl PartialEq for HclTraversalStep {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GetAttr { name: left, .. }, Self::GetAttr { name: right, .. }) => left == right,
            (Self::Index { key: left, .. }, Self::Index { key: right, .. }) => left == right,
            (Self::AttrSplat { steps: left }, Self::AttrSplat { steps: right })
            | (Self::FullSplat { steps: left }, Self::FullSplat { steps: right }) => left == right,
            _ => false,
        }
    }
}

impl Eq for HclTraversalStep {}

impl Hash for HclTraversalStep {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::GetAttr { name, .. } => {
                0_u8.hash(state);
                name.hash(state);
            }
            Self::Index { key, .. } => {
                1_u8.hash(state);
                key.hash(state);
            }
            Self::AttrSplat { steps } => {
                2_u8.hash(state);
                steps.hash(state);
            }
            Self::FullSplat { steps } => {
                3_u8.hash(state);
                steps.hash(state);
            }
        }
    }
}

/// One ordered template part (RFC 0014 §6).
///
/// A literal part keeps its exact escape-decoded text; the raw escaped
/// spelling remains a source fact of the part's span (RFC 0014 §4.4). The
/// `~` strip markers of interpolations and directives are span-internal
/// source facts, never applied. A template consisting of a single
/// interpolation unwraps to the interpolation's value under evaluation only;
/// Consema never evaluates, so the unwrap is documented but never performed
/// (RFC 0014 §4.4).
#[derive(Clone, Debug)]
pub enum HclTemplatePart {
    /// Literal text; escaped `$${` and `%%{` sequences decode to literal
    /// `${`/`%{` text and count as literal text (RFC 0014 §4.4).
    Literal {
        /// Exact span of the literal run, including escapes.
        span: Span,
        /// Escape-decoded literal text.
        text: Arc<str>,
    },
    /// An interpolation `${ Expression }` with optional `~` strip markers.
    Interpolation {
        /// Exact span of the whole interpolation, including delimiters and
        /// strip markers.
        span: Span,
        /// Interpolated expression.
        expression: HclExpression,
    },
    /// A directive `%{ if }`/`%{ else }`/`%{ endif }`/`%{ for }`/`%{ endfor }`.
    Directive {
        /// Exact span of the whole directive, including delimiters and
        /// strip markers.
        span: Span,
        /// Directive kind.
        kind: HclDirectiveKind,
    },
}

impl HclTemplatePart {
    /// Exact span of the whole part, including delimiters and strip markers.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Literal { span, .. }
            | Self::Interpolation { span, .. }
            | Self::Directive { span, .. } => *span,
        }
    }
}

impl PartialEq for HclTemplatePart {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Literal { text: left, .. }, Self::Literal { text: right, .. }) => left == right,
            (
                Self::Interpolation {
                    expression: left, ..
                },
                Self::Interpolation {
                    expression: right, ..
                },
            ) => left == right,
            (Self::Directive { kind: left, .. }, Self::Directive { kind: right, .. }) => {
                left == right
            }
            _ => false,
        }
    }
}

impl Eq for HclTemplatePart {}

impl Hash for HclTemplatePart {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Literal { text, .. } => {
                0_u8.hash(state);
                text.hash(state);
            }
            Self::Interpolation { expression, .. } => {
                1_u8.hash(state);
                expression.hash(state);
            }
            Self::Directive { kind, .. } => {
                2_u8.hash(state);
                kind.hash(state);
            }
        }
    }
}

/// One template directive kind (RFC 0014 §4.4).
///
/// The single-identifier for-directive `%{ for x in list }` is valid —
/// Consema freezes the pinned Go parser's behavior of reading a key only
/// when a comma follows (RFC 0014 §4.4, §12 D-7).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HclDirectiveKind {
    /// `%{ if Expression }`.
    If {
        /// Condition expression.
        condition: Box<HclExpression>,
    },
    /// `%{ else }`.
    Else,
    /// `%{ endif }`.
    EndIf,
    /// `%{ for Identifier , Identifier in Expression }` (key optional).
    For {
        /// The `for` introduction.
        intro: HclForIntro,
    },
    /// `%{ endfor }`.
    EndFor,
}

/// Heredoc mode fact: `<<` or `<<-` (RFC 0014 §4.5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HeredocMode {
    /// `<<` plain heredoc: no indentation stripping.
    Plain,
    /// `<<-` strip-indent heredoc: the literal value removes the minimum
    /// number of leading spaces from each line's leading literal text.
    StripIndent,
}

impl HeredocMode {
    /// Stable mode spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "<<",
            Self::StripIndent => "<<-",
        }
    }
}

/// Heredoc representation facts of one template (RFC 0014 §4.5, §6).
///
/// The mode, marker spelling, marker span, and closing-line span are
/// preserved representation facts; the `<<-` indentation stripping is
/// performed only when the template's literal value is read, never
/// destructively. The ordered parts of the template cover the heredoc
/// content. Structural equality compares the mode and marker spelling only.
#[derive(Clone, Debug)]
pub struct HeredocFacts {
    mode: HeredocMode,
    marker: Arc<str>,
    marker_span: Span,
    closing_span: Option<Span>,
}

impl HeredocFacts {
    /// Creates heredoc facts for a formed heredoc.
    #[must_use]
    pub const fn new(
        mode: HeredocMode,
        marker: Arc<str>,
        marker_span: Span,
        closing_span: Option<Span>,
    ) -> Self {
        Self {
            mode,
            marker,
            marker_span,
            closing_span,
        }
    }

    /// Heredoc mode (`<<` or `<<-`).
    #[must_use]
    pub const fn mode(&self) -> HeredocMode {
        self.mode
    }

    /// Bare identifier marker spelling.
    #[must_use]
    pub fn marker(&self) -> &str {
        &self.marker
    }

    /// Exact span of the marker identifier.
    #[must_use]
    pub const fn marker_span(&self) -> Span {
        self.marker_span
    }

    /// Exact span of the closing marker line, or `None` for an unterminated
    /// heredoc (RFC 0014 §3).
    #[must_use]
    pub const fn closing_span(&self) -> Option<Span> {
        self.closing_span
    }
}

impl PartialEq for HeredocFacts {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.marker == other.marker
    }
}

impl Eq for HeredocFacts {}

impl Hash for HeredocFacts {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mode.hash(state);
        self.marker.hash(state);
    }
}

/// One function-call argument with its expansion marker fact (RFC 0014
/// §4.3).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HclCallArg {
    expression: HclExpression,
    expand: bool,
}

impl HclCallArg {
    /// Creates one argument.
    #[must_use]
    pub const fn new(expression: HclExpression, expand: bool) -> Self {
        Self { expression, expand }
    }

    /// Argument expression.
    #[must_use]
    pub const fn expression(&self) -> &HclExpression {
        &self.expression
    }

    /// `...` expansion marker fact; the marker may only appear on the final
    /// argument (a parser contract).
    #[must_use]
    pub const fn expand(&self) -> bool {
        self.expand
    }
}

/// The `for` introduction of a for-expression or for-directive (RFC 0014
/// §4.6).
#[derive(Clone, Debug)]
pub struct HclForIntro {
    key: Option<Arc<str>>,
    value: Arc<str>,
    collection: Box<HclExpression>,
    span: Span,
}

impl HclForIntro {
    /// Creates one introduction.
    #[must_use]
    pub const fn new(
        key: Option<Arc<str>>,
        value: Arc<str>,
        collection: Box<HclExpression>,
        span: Span,
    ) -> Self {
        Self {
            key,
            value,
            collection,
            span,
        }
    }

    /// Optional key identifier; `None` is the single-identifier form (RFC
    /// 0014 §12 D-7).
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Value identifier.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Collection expression.
    #[must_use]
    pub const fn collection(&self) -> &HclExpression {
        &self.collection
    }

    /// Exact span of the whole introduction, including `for ... in ...:`.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }
}

impl PartialEq for HclForIntro {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.value == other.value && self.collection == other.collection
    }
}

impl Eq for HclForIntro {}

impl Hash for HclForIntro {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
        self.value.hash(state);
        self.collection.hash(state);
    }
}

/// One object-constructor key (RFC 0014 §4.6).
///
/// The frozen key forms are an identifier (literal name), a number literal,
/// a quoted template, or a parenthesized expression; any other expression
/// key is a grammar error ("Invalid object key" in the pinned Go parser).
#[derive(Clone, Debug)]
pub enum HclObjectKey {
    /// Bare identifier key.
    Identifier(Arc<str>),
    /// Number-literal key.
    Number(HclNumber),
    /// Quoted-template key.
    Template(HclTemplateKey),
    /// Parenthesized-expression key.
    Paren(Box<HclExpression>),
}

impl PartialEq for HclObjectKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Identifier(left), Self::Identifier(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::Template(left), Self::Template(right)) => left == right,
            (Self::Paren(left), Self::Paren(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for HclObjectKey {}

impl Hash for HclObjectKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Identifier(name) => {
                0_u8.hash(state);
                name.hash(state);
            }
            Self::Number(number) => {
                1_u8.hash(state);
                number.hash(state);
            }
            Self::Template(template) => {
                2_u8.hash(state);
                template.hash(state);
            }
            Self::Paren(inner) => {
                3_u8.hash(state);
                inner.hash(state);
            }
        }
    }
}

/// A quoted-template object key (RFC 0014 §4.6).
#[derive(Clone, Debug)]
pub struct HclTemplateKey {
    parts: Arc<[HclTemplatePart]>,
    span: Span,
}

impl HclTemplateKey {
    /// Creates a quoted-template key from its ordered parts.
    #[must_use]
    pub const fn new(parts: Arc<[HclTemplatePart]>, span: Span) -> Self {
        Self { parts, span }
    }

    /// Ordered parts, including the quote delimiters' span facts.
    #[must_use]
    pub fn parts(&self) -> &[HclTemplatePart] {
        &self.parts
    }

    /// Exact span of the key, including the quotes.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }
}

impl PartialEq for HclTemplateKey {
    fn eq(&self, other: &Self) -> bool {
        self.parts == other.parts
    }
}

impl Eq for HclTemplateKey {}

impl Hash for HclTemplateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.parts.hash(state);
    }
}

/// One ordered object-constructor entry: key, separator, and value (RFC
/// 0014 §4.6).
///
/// Duplicate keys are preserved as ordered native facts with independent
/// spans and are never collapsed (RFC 0014 §4.6, §6).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HclObjectEntry {
    key: HclObjectKey,
    separator: ObjectSeparator,
    value: HclExpression,
}

impl HclObjectEntry {
    /// Creates one entry.
    #[must_use]
    pub const fn new(key: HclObjectKey, separator: ObjectSeparator, value: HclExpression) -> Self {
        Self {
            key,
            separator,
            value,
        }
    }

    /// Key identity.
    #[must_use]
    pub const fn key(&self) -> &HclObjectKey {
        &self.key
    }

    /// `=` or `:` separator source fact.
    #[must_use]
    pub const fn separator(&self) -> ObjectSeparator {
        self.separator
    }

    /// Value expression.
    #[must_use]
    pub const fn value(&self) -> &HclExpression {
        &self.value
    }
}

/// Object-constructor key/value separator source fact (RFC 0014 §4.6).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObjectSeparator {
    /// `=`.
    Equals,
    /// `:`.
    Colon,
}

impl ObjectSeparator {
    /// Stable separator spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "=",
            Self::Colon => ":",
        }
    }
}

/// Whether an expression is literal-complete: its value is uniquely
/// determined by the source text alone — no evaluation, no context (RFC
/// 0014 §8.1).
///
/// The boundary is deliberately purely syntactic: it is decidable without
/// any evaluator, and no arithmetic is ever computed (hard gate 1). Exactly
/// the following are literal-complete:
///
/// - a number literal (any decimal spelling);
/// - `true`, `false`, or `null`;
/// - a quoted or heredoc template containing zero interpolation and zero
///   directive sequences (escaped `$${`/`%%{` text counts as literal text);
/// - a tuple constructor whose elements are all literal-complete;
/// - an object constructor whose keys are identifiers, number literals,
///   quoted literal templates, or parenthesized literal-complete
///   expressions, and whose values are all literal-complete;
/// - a unary minus applied to a number literal;
/// - a parenthesized literal-complete expression.
///
/// Everything else — variable and traversal expressions, function calls,
/// binary operators (`1 + 2` included), the conditional operator, index and
/// splat operators, for-expressions, templates with any interpolation or
/// directive, and unary operators over anything but a number literal — is
/// derived.
#[must_use]
pub fn is_literal_complete(expression: &HclExpression) -> bool {
    match expression.kind() {
        HclExpressionKind::Number(_) | HclExpressionKind::Boolean(_) | HclExpressionKind::Null => {
            true
        }
        HclExpressionKind::Template { parts, .. } => parts.iter().all(HclTemplatePart::is_literal),
        HclExpressionKind::Tuple { elements } => elements.iter().all(is_literal_complete),
        HclExpressionKind::Object { entries } => entries
            .iter()
            .all(|entry| is_literal_complete(entry.value()) && literal_complete_key(entry.key())),
        HclExpressionKind::Unary {
            op: UnaryOp::Minus,
            operand,
        } => matches!(operand.kind(), HclExpressionKind::Number(_)),
        HclExpressionKind::Paren { inner } => is_literal_complete(inner),
        _ => false,
    }
}

fn literal_complete_key(key: &HclObjectKey) -> bool {
    match key {
        HclObjectKey::Identifier(_) | HclObjectKey::Number(_) => true,
        HclObjectKey::Template(template) => {
            template.parts().iter().all(HclTemplatePart::is_literal)
        }
        HclObjectKey::Paren(inner) => is_literal_complete(inner),
    }
}

impl HclTemplatePart {
    /// Whether this part is a literal run with no interpolation or directive.
    #[must_use]
    pub const fn is_literal(&self) -> bool {
        matches!(self, Self::Literal { .. })
    }
}

/// A literal-complete expression must be a typed literal value.
///
/// This is the explicit-failure path of RFC 0014 §8: projection of a derived
/// expression fails atomically with `hcl.projection.non-literal-expression@1`
/// at projection time; nothing here converts, folds, or guesses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NonLiteralExpression;

impl fmt::Display for NonLiteralExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expression is not literal-complete")
    }
}

impl std::error::Error for NonLiteralExpression {}

/// Extracts the typed literal value of a literal-complete expression (RFC
/// 0014 §8.1-§8.2).
///
/// The mapping freezes the `hcl.body@1` typed members: a canonical decimal
/// without a fraction projects as an integer, one with a fraction as a real
/// (`1e3` normalizes to `"1000"` and therefore projects as an integer);
/// zero-interpolation templates project as strings with the exact code
/// points, including the `<<-` indentation-stripped content; constructors
/// project element-wise with duplicate object keys preserved in order; and
/// a unary minus applies to a number literal only. A derived expression
/// fails with [`NonLiteralExpression`] — never a null, empty, or converted
/// result.
pub fn literal_value(expression: &HclExpression) -> Result<HclLiteralValue, NonLiteralExpression> {
    match expression.kind() {
        HclExpressionKind::Number(number) => Ok(number_literal(number.canonical_decimal())),
        HclExpressionKind::Boolean(value) => Ok(HclLiteralValue::Boolean(*value)),
        HclExpressionKind::Null => Ok(HclLiteralValue::Null),
        HclExpressionKind::Template { parts, heredoc } => {
            let mut text = String::new();
            for part in parts.iter() {
                match part {
                    HclTemplatePart::Literal { text: literal, .. } => text.push_str(literal),
                    HclTemplatePart::Interpolation { .. } | HclTemplatePart::Directive { .. } => {
                        return Err(NonLiteralExpression);
                    }
                }
            }
            if heredoc
                .as_ref()
                .is_some_and(|facts| facts.mode() == HeredocMode::StripIndent)
            {
                text = strip_heredoc_indentation(&text);
            }
            Ok(HclLiteralValue::String(text))
        }
        HclExpressionKind::Tuple { elements } => {
            let mut values = Vec::with_capacity(elements.len());
            for element in elements.iter() {
                values.push(literal_value(element)?);
            }
            Ok(HclLiteralValue::Tuple(values.into()))
        }
        HclExpressionKind::Object { entries } => {
            let mut projected = Vec::with_capacity(entries.len());
            for entry in entries.iter() {
                let key = match entry.key() {
                    HclObjectKey::Identifier(name) => HclLiteralKey::Identifier(name.to_string()),
                    HclObjectKey::Number(number) => {
                        HclLiteralKey::Number(number.canonical_decimal().to_owned())
                    }
                    HclObjectKey::Template(template) => {
                        let mut text = String::new();
                        for part in template.parts() {
                            match part {
                                HclTemplatePart::Literal { text: literal, .. } => {
                                    text.push_str(literal);
                                }
                                HclTemplatePart::Interpolation { .. }
                                | HclTemplatePart::Directive { .. } => {
                                    return Err(NonLiteralExpression);
                                }
                            }
                        }
                        HclLiteralKey::String(text)
                    }
                    HclObjectKey::Paren(inner) => HclLiteralKey::Value(literal_value(inner)?),
                };
                projected.push(HclLiteralObjectEntry::new(
                    key,
                    literal_value(entry.value())?,
                ));
            }
            Ok(HclLiteralValue::Object(projected.into()))
        }
        HclExpressionKind::Unary {
            op: UnaryOp::Minus,
            operand,
        } => match operand.kind() {
            HclExpressionKind::Number(number) => {
                let canonical = number.canonical_decimal();
                let value = if canonical == "0" {
                    canonical.to_owned()
                } else {
                    format!("-{canonical}")
                };
                Ok(number_literal(&value))
            }
            _ => Err(NonLiteralExpression),
        },
        HclExpressionKind::Paren { inner } => literal_value(inner),
        _ => Err(NonLiteralExpression),
    }
}

fn number_literal(canonical: &str) -> HclLiteralValue {
    if canonical.contains('.') {
        HclLiteralValue::Decimal(canonical.to_owned())
    } else {
        HclLiteralValue::Integer(canonical.to_owned())
    }
}

/// Applies the `<<-` indentation stripping: removes the minimum number of
/// leading spaces from each line's leading literal text (RFC 0014 §4.5).
///
/// The stripping is performed only when the template's literal value is
/// read, never destructively. For a literal-complete heredoc every part is
/// literal, so the analysis over the decoded text is exact.
fn strip_heredoc_indentation(text: &str) -> String {
    let mut minimum: Option<usize> = None;
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        minimum = Some(minimum.map_or(indent, |current| current.min(indent)));
    }
    let Some(minimum) = minimum else {
        return String::new();
    };
    let mut out = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&line[minimum.min(line.len())..]);
    }
    out
}

/// Typed literal projection of a literal-complete expression (RFC 0014
/// §8.2).
///
/// Integers and decimals carry the exact canonical decimal spelling with an
/// optional leading `-`; the `hcl.body@1` projection converts them to the
/// core `BigInteger`/`Decimal` members at projection time. Strings carry
/// exact decoded code points. Tuple and object projections preserve source
/// order, and duplicate object keys remain ordered entries.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HclLiteralValue {
    /// Integer value: canonical decimal without a fraction, optional leading
    /// `-` (for example `"1000"`, `"-42"`).
    Integer(String),
    /// Real value: canonical decimal with a fraction, optional leading `-`
    /// (for example `"1.5"`, `"-0.125"`).
    Decimal(String),
    /// String value with exact decoded code points, including the `<<-`
    /// indentation-stripped heredoc content.
    String(String),
    /// Boolean value.
    Boolean(bool),
    /// Null value.
    Null,
    /// Ordered tuple of literal values.
    Tuple(Arc<[HclLiteralValue]>),
    /// Ordered object entries; duplicate keys are preserved.
    Object(Arc<[HclLiteralObjectEntry]>),
}

/// One ordered object literal entry in a [`HclLiteralValue::Object`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HclLiteralObjectEntry {
    key: HclLiteralKey,
    value: HclLiteralValue,
}

impl HclLiteralObjectEntry {
    /// Creates one entry.
    #[must_use]
    pub const fn new(key: HclLiteralKey, value: HclLiteralValue) -> Self {
        Self { key, value }
    }

    /// Literal key.
    #[must_use]
    pub const fn key(&self) -> &HclLiteralKey {
        &self.key
    }

    /// Literal value.
    #[must_use]
    pub const fn value(&self) -> &HclLiteralValue {
        &self.value
    }
}

/// One object-literal key (RFC 0014 §8.1-§8.2).
///
/// The three bare forms are an identifier, a number literal, and a quoted
/// literal template; a parenthesized literal-complete expression reduces to
/// its inner value, so boolean, null, tuple, and object keys are reachable
/// through [`Self::Value`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HclLiteralKey {
    /// Bare identifier key.
    Identifier(String),
    /// Bare number-literal key with the exact canonical decimal spelling.
    Number(String),
    /// Bare quoted-literal-template key with exact decoded text.
    String(String),
    /// Parenthesized literal-complete expression key.
    Value(HclLiteralValue),
}

fn collect_template_part_children<'a>(
    parts: &'a [HclTemplatePart],
    children: &mut Vec<&'a HclExpression>,
) {
    for part in parts {
        match part {
            HclTemplatePart::Literal { .. } => {}
            HclTemplatePart::Interpolation { expression, .. } => children.push(expression),
            HclTemplatePart::Directive { kind, .. } => match kind {
                HclDirectiveKind::If { condition } => children.push(condition),
                HclDirectiveKind::For { intro } => children.push(intro.collection()),
                HclDirectiveKind::Else | HclDirectiveKind::EndIf | HclDirectiveKind::EndFor => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{DocumentAuthority, SourceSnapshot};
    use std::collections::hash_map::DefaultHasher;

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

    fn variable_expr(authority: &DocumentAuthority, name: &str) -> HclExpression {
        HclExpression::new(
            HclExpressionKind::VariableRef {
                name: Arc::from(name),
            },
            span(authority, 0, 1),
        )
    }

    fn literal_part(
        authority: &DocumentAuthority,
        start: usize,
        end: usize,
        text: &str,
    ) -> HclTemplatePart {
        HclTemplatePart::Literal {
            span: span(authority, start, end),
            text: Arc::from(text),
        }
    }

    fn template_expr(
        authority: &DocumentAuthority,
        parts: Vec<HclTemplatePart>,
        heredoc: Option<HeredocFacts>,
    ) -> HclExpression {
        HclExpression::new(
            HclExpressionKind::Template {
                parts: parts.into(),
                heredoc,
            },
            span(authority, 0, 30),
        )
    }

    fn object_expr(authority: &DocumentAuthority, entries: Vec<HclObjectEntry>) -> HclExpression {
        HclExpression::new(
            HclExpressionKind::Object {
                entries: entries.into(),
            },
            span(authority, 0, 30),
        )
    }

    fn entry(key: HclObjectKey, value: HclExpression) -> HclObjectEntry {
        HclObjectEntry::new(key, ObjectSeparator::Equals, value)
    }

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn canonical_decimal_folds_spellings_to_canonical_form() {
        for (spelling, canonical) in [
            ("1.50", "1.5"),
            ("1.5", "1.5"),
            ("15e-1", "1.5"),
            ("15E-1", "1.5"),
            ("15e+0", "15"),
            ("1e3", "1000"),
            ("1E+3", "1000"),
            ("007", "7"),
            ("0", "0"),
            ("0.0", "0"),
            ("1.0", "1"),
            ("0.5", "0.5"),
            ("1.2300", "1.23"),
            ("10.0", "10"),
            ("1e-3", "0.001"),
            ("1.5e2", "150"),
            ("0.00100", "0.001"),
            ("123.456e3", "123456"),
            ("1.23456e-3", "0.00123456"),
            ("100e-2", "1"),
            ("0e5", "0"),
            ("0.000", "0"),
            ("0.50", "0.5"),
            ("100e-1", "10"),
            ("1e-1", "0.1"),
            ("1.5e-2", "0.015"),
            ("2e0", "2"),
            ("10e2", "1000"),
            ("0.1e1", "1"),
            ("1.000e2", "100"),
        ] {
            assert_eq!(
                canonical_decimal(spelling).as_deref(),
                Some(canonical),
                "spelling {spelling:?}"
            );
        }
    }

    #[test]
    fn canonical_decimal_rejects_invalid_spellings() {
        for spelling in [
            "",
            "abc",
            "1.2.3",
            "1e",
            "1e+",
            "1e-",
            "e3",
            ".5",
            "5.",
            "+1",
            "-1",
            "1_000",
            "0x10",
            "0b10",
            "0o7",
            "1 ",
            " 1",
            "1..2",
            "1e1e1",
            "1e1.5",
            "0x",
            "-",
            "1,000",
            "1.5.6",
            "\u{0661}\u{0662}", // Arabic-Indic digits are not decimal+
        ] {
            assert_eq!(
                canonical_decimal(spelling),
                None,
                "spelling {spelling:?} must be rejected"
            );
        }
    }

    #[test]
    fn canonical_decimal_rejects_unrepresentable_exponents() {
        for spelling in [
            "1e99999999999999999999",
            "1e-99999999999999999999",
            "1e9223372036854775808",
        ] {
            assert_eq!(canonical_decimal(spelling), None);
        }
    }

    #[test]
    fn canonical_decimal_fails_fast_on_exponent_folding_overflow() {
        // A min-bound exponent used to run a ~9.2e18-iteration zero-padding
        // loop before the parser's digit check; the digit budget now fails
        // it before any padding starts, so the assertion here is the bounded
        // failure result, never a timing measurement.
        for spelling in [
            "1e-9223372036854775807",
            "1e9223372036854775807",
            "0.05e-9223372036854775807",
            "1e-100000",
            "1e100000",
        ] {
            assert_eq!(canonical_decimal(spelling), None, "spelling {spelling:?}");
        }
    }

    #[test]
    fn canonical_decimal_bounded_honors_an_explicit_digit_budget() {
        assert_eq!(canonical_decimal_bounded("1e-100000", 100), None);
        assert_eq!(canonical_decimal_bounded("1e-100000", 100_000), None);
        // The exact boundary: a canonical spelling of exactly `max_digits`
        // digits is accepted, one digit more is rejected.
        assert_eq!(
            canonical_decimal_bounded("1e-3", 4).as_deref(),
            Some("0.001")
        );
        assert_eq!(canonical_decimal_bounded("1e-4", 4), None);
        assert_eq!(
            canonical_decimal_bounded("1e4", 5).as_deref(),
            Some("10000")
        );
        assert_eq!(canonical_decimal_bounded("1e5", 5), None);
    }

    #[test]
    fn canonical_decimal_keeps_large_but_allowed_exponents() {
        // `1e30` normalizes to 31 digits, well inside the frozen default
        // budget of 100_000 digits.
        assert_eq!(
            canonical_decimal("1e30").as_deref(),
            Some("1000000000000000000000000000000")
        );
        assert_eq!(canonical_decimal("1.5e-2").as_deref(), Some("0.015"));
    }

    #[test]
    fn canonical_decimal_min_bound_exponent_fails_not_panics() {
        // `0.05e-9223372036854775807` folds to `point = i64::MIN`, whose
        // negation used to overflow in debug builds and wrap into a
        // panicking `usize::try_from` in release builds; on 32-bit targets
        // even `1e-9223372036854775807` used to panic in the width
        // conversion. Both now fail gracefully.
        assert_eq!(canonical_decimal("0.05e-9223372036854775807"), None);
        assert_eq!(canonical_decimal("1e-9223372036854775807"), None);
    }

    #[test]
    fn canonical_decimal_overflow_fails_parse_with_number_digits_limit() {
        // The parser maps a failed fold to the `hcl.limit.number-digits@1`
        // resource failure (parser.rs `number`), so the adversarial
        // exponent is a fast fatal formation failure, never a
        // ~9.2e18-iteration padding loop.
        let failure = crate::parse(
            &b"a = 1e-9223372036854775807\n"[..],
            crate::HclProfile::NativeV1,
            crate::HclEncodingSelection::ProfileDefault,
            crate::HclParseLimits::default(),
        )
        .expect_err("adversarial exponent must be a fatal formation failure");
        assert_eq!(
            failure.diagnostics().first().expect("one diagnostic").code,
            "hcl.limit.number-digits@1"
        );
    }

    #[test]
    fn number_equality_is_canonical_decimal_equality() {
        let authority = DocumentAuthority::fresh();
        let first = HclNumber::from_spelling(span(&authority, 0, 4), "1.50").unwrap();
        let second = HclNumber::from_spelling(span(&authority, 0, 3), "1.5").unwrap();
        let exponent = HclNumber::from_spelling(span(&authority, 0, 5), "15e-1").unwrap();
        let different = HclNumber::from_spelling(span(&authority, 0, 6), "1.5001").unwrap();
        assert_eq!(first, second);
        assert_eq!(first, exponent);
        assert_ne!(first, different);
        assert_eq!(hash_of(&first), hash_of(&second));
        assert_ne!(hash_of(&first), hash_of(&different));
    }

    #[test]
    fn number_accessors_and_from_spelling() {
        let authority = DocumentAuthority::fresh();
        let number = HclNumber::from_spelling(span(&authority, 3, 7), "1e3").unwrap();
        assert_eq!(number.span(), span(&authority, 3, 7));
        assert_eq!(number.canonical_decimal(), "1000");
        assert!(HclNumber::from_spelling(span(&authority, 0, 3), "1e").is_none());
    }

    #[test]
    fn expression_kind_names_round_trip() {
        let authority = DocumentAuthority::fresh();
        let expressions = [
            number_expr(&authority, 0, 1, "1"),
            HclExpression::new(HclExpressionKind::Boolean(true), span(&authority, 0, 4)),
            HclExpression::new(HclExpressionKind::Null, span(&authority, 0, 4)),
            template_expr(&authority, vec![literal_part(&authority, 1, 2, "a")], None),
            HclExpression::new(
                HclExpressionKind::FunctionCall {
                    name: Arc::from("f"),
                    name_span: span(&authority, 0, 1),
                    args: Arc::from([]),
                },
                span(&authority, 0, 3),
            ),
            variable_expr(&authority, "x"),
            HclExpression::new(
                HclExpressionKind::Traversal {
                    root: HclTraversalRoot::Variable(Arc::from("foo")),
                    steps: Arc::from([]),
                },
                span(&authority, 0, 3),
            ),
            HclExpression::new(
                HclExpressionKind::Unary {
                    op: UnaryOp::Minus,
                    operand: Box::new(number_expr(&authority, 1, 2, "1")),
                },
                span(&authority, 0, 2),
            ),
            HclExpression::new(
                HclExpressionKind::Binary {
                    op: BinaryOp::Add,
                    lhs: Box::new(number_expr(&authority, 0, 1, "1")),
                    rhs: Box::new(number_expr(&authority, 2, 3, "2")),
                },
                span(&authority, 0, 3),
            ),
            HclExpression::new(
                HclExpressionKind::Conditional {
                    condition: Box::new(number_expr(&authority, 0, 1, "1")),
                    then: Box::new(number_expr(&authority, 2, 3, "2")),
                    else_: Box::new(number_expr(&authority, 4, 5, "3")),
                },
                span(&authority, 0, 5),
            ),
            HclExpression::new(
                HclExpressionKind::ForTuple {
                    intro: HclForIntro::new(
                        None,
                        Arc::from("v"),
                        Box::new(variable_expr(&authority, "list")),
                        span(&authority, 0, 12),
                    ),
                    value: Box::new(number_expr(&authority, 13, 14, "1")),
                    condition: None,
                },
                span(&authority, 0, 15),
            ),
            HclExpression::new(
                HclExpressionKind::ForObject {
                    intro: HclForIntro::new(
                        None,
                        Arc::from("v"),
                        Box::new(variable_expr(&authority, "list")),
                        span(&authority, 0, 12),
                    ),
                    key: Box::new(number_expr(&authority, 13, 14, "1")),
                    value: Box::new(number_expr(&authority, 15, 16, "2")),
                    grouping: true,
                    condition: None,
                },
                span(&authority, 0, 17),
            ),
            HclExpression::new(
                HclExpressionKind::Tuple {
                    elements: Arc::from([]),
                },
                span(&authority, 0, 2),
            ),
            object_expr(&authority, vec![]),
            HclExpression::new(
                HclExpressionKind::Paren {
                    inner: Box::new(number_expr(&authority, 1, 2, "1")),
                },
                span(&authority, 0, 3),
            ),
        ];
        let names = [
            ("number", HclExpressionKindName::Number),
            ("boolean", HclExpressionKindName::Boolean),
            ("null", HclExpressionKindName::Null),
            ("template", HclExpressionKindName::Template),
            ("function-call", HclExpressionKindName::FunctionCall),
            ("variable-ref", HclExpressionKindName::VariableRef),
            ("traversal", HclExpressionKindName::Traversal),
            ("unary", HclExpressionKindName::Unary),
            ("binary", HclExpressionKindName::Binary),
            ("conditional", HclExpressionKindName::Conditional),
            ("for-tuple", HclExpressionKindName::ForTuple),
            ("for-object", HclExpressionKindName::ForObject),
            ("tuple", HclExpressionKindName::Tuple),
            ("object", HclExpressionKindName::Object),
            ("parenthesized", HclExpressionKindName::Parenthesized),
        ];
        for (expression, (spelling, name)) in expressions.iter().zip(names.iter()) {
            assert_eq!(expression.kind().name(), *name);
            assert_eq!(expression.kind().as_str(), *spelling);
            assert_eq!(HclExpressionKindName::from_name(spelling), Some(*name));
            assert_eq!(name.as_str(), *spelling);
        }
        assert_eq!(HclExpressionKindName::from_name("unknown"), None);
    }

    #[test]
    fn expression_text_derives_exact_source_slice() {
        let authority = DocumentAuthority::fresh();
        let source = SourceSnapshot::from_utf8(b"a = 1.5 + 2".to_vec()).expect("utf-8");
        let expression = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&authority, 4, 7, "1.5")),
                rhs: Box::new(number_expr(&authority, 10, 11, "2")),
            },
            span(&authority, 4, 11),
        );
        assert_eq!(expression.text(&source).expect("decoded"), "1.5 + 2");
    }

    #[test]
    fn expression_text_handles_multibyte_decoded_offsets() {
        let authority = DocumentAuthority::fresh();
        let source = SourceSnapshot::from_utf8(b"b = \"caf\xC3\xA9\"".to_vec()).expect("utf-8");
        let template = HclExpression::new(
            HclExpressionKind::Template {
                parts: Arc::from([literal_part(&authority, 5, 10, "caf\u{e9}")]),
                heredoc: None,
            },
            span(&authority, 4, 11),
        );
        assert_eq!(template.text(&source).expect("decoded"), "\"caf\u{e9}\"");
    }

    #[test]
    fn children_of_binary_and_conditional_follow_source_order() {
        let authority = DocumentAuthority::fresh();
        let one = number_expr(&authority, 0, 1, "1");
        let two = number_expr(&authority, 2, 3, "2");
        let three = number_expr(&authority, 4, 5, "3");
        let binary = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(one),
                rhs: Box::new(two),
            },
            span(&authority, 0, 3),
        );
        let children = binary.children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].kind().as_str(), "number");
        assert_eq!(children[1].kind().as_str(), "number");

        let conditional = HclExpression::new(
            HclExpressionKind::Conditional {
                condition: Box::new(number_expr(&authority, 0, 1, "1")),
                then: Box::new(number_expr(&authority, 2, 3, "2")),
                else_: Box::new(three),
            },
            span(&authority, 0, 5),
        );
        let children = conditional.children();
        assert_eq!(children.len(), 3);
        assert_eq!(
            children[2].kind(),
            &HclExpressionKind::Number(
                HclNumber::from_spelling(span(&authority, 4, 5), "3",).unwrap()
            )
        );
    }

    #[test]
    fn children_cover_template_call_traversal_for_and_object() {
        let authority = DocumentAuthority::fresh();
        let template = template_expr(
            &authority,
            vec![
                literal_part(&authority, 1, 2, "a"),
                HclTemplatePart::Interpolation {
                    span: span(&authority, 2, 9),
                    expression: number_expr(&authority, 4, 5, "1"),
                },
                HclTemplatePart::Directive {
                    span: span(&authority, 9, 25),
                    kind: HclDirectiveKind::If {
                        condition: Box::new(number_expr(&authority, 13, 14, "2")),
                    },
                },
            ],
            None,
        );
        let children = template.children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].kind().as_str(), "number");
        assert_eq!(children[1].kind().as_str(), "number");

        let call = HclExpression::new(
            HclExpressionKind::FunctionCall {
                name: Arc::from("f"),
                name_span: span(&authority, 0, 1),
                args: Arc::from([
                    HclCallArg::new(number_expr(&authority, 2, 3, "1"), false),
                    HclCallArg::new(number_expr(&authority, 5, 6, "2"), true),
                ]),
            },
            span(&authority, 0, 8),
        );
        let children = call.children();
        assert_eq!(children.len(), 2);
        assert_eq!(call.children()[0].span().len(), 1);

        let traversal = HclExpression::new(
            HclExpressionKind::Traversal {
                root: HclTraversalRoot::Variable(Arc::from("foo")),
                steps: Arc::from([
                    HclTraversalStep::GetAttr {
                        name: Arc::from("bar"),
                        span: span(&authority, 3, 7),
                    },
                    HclTraversalStep::Index {
                        key: Box::new(number_expr(&authority, 7, 8, "0")),
                        span: span(&authority, 7, 9),
                    },
                    HclTraversalStep::FullSplat {
                        steps: Arc::from([HclTraversalStep::Index {
                            key: Box::new(number_expr(&authority, 13, 14, "1")),
                            span: span(&authority, 13, 15),
                        }]),
                    },
                ]),
            },
            span(&authority, 0, 16),
        );
        let children = traversal.children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].span(), span(&authority, 7, 8));
        assert_eq!(children[1].span(), span(&authority, 13, 14));

        let for_tuple = HclExpression::new(
            HclExpressionKind::ForTuple {
                intro: HclForIntro::new(
                    None,
                    Arc::from("v"),
                    Box::new(variable_expr(&authority, "list")),
                    span(&authority, 0, 12),
                ),
                value: Box::new(number_expr(&authority, 13, 14, "1")),
                condition: Some(Box::new(number_expr(&authority, 15, 16, "2"))),
            },
            span(&authority, 0, 17),
        );
        let children = for_tuple.children();
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].kind().as_str(), "variable-ref");

        let object = object_expr(
            &authority,
            vec![
                entry(
                    HclObjectKey::Paren(Box::new(number_expr(&authority, 1, 2, "1"))),
                    number_expr(&authority, 3, 4, "2"),
                ),
                entry(
                    HclObjectKey::Template(HclTemplateKey::new(
                        Arc::from([HclTemplatePart::Interpolation {
                            span: span(&authority, 6, 13),
                            expression: number_expr(&authority, 8, 9, "3"),
                        }]),
                        span(&authority, 5, 14),
                    )),
                    number_expr(&authority, 15, 16, "4"),
                ),
            ],
        );
        let children = object.children();
        assert_eq!(children.len(), 4);
        for child in children {
            assert_eq!(child.kind().as_str(), "number");
        }
    }

    #[test]
    fn structural_equality_ignores_spans() {
        let first_authority = DocumentAuthority::fresh();
        let second_authority = DocumentAuthority::fresh();
        let first = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&first_authority, 0, 1, "1")),
                rhs: Box::new(number_expr(&first_authority, 2, 3, "2")),
            },
            span(&first_authority, 0, 3),
        );
        let second = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&second_authority, 10, 11, "1")),
                rhs: Box::new(number_expr(&second_authority, 12, 13, "2")),
            },
            span(&second_authority, 10, 13),
        );
        assert_eq!(first, second);
        assert_eq!(hash_of(&first), hash_of(&second));
        assert_eq!(first, first.clone());
    }

    #[test]
    fn structural_equality_is_canonical_for_numbers() {
        let authority = DocumentAuthority::fresh();
        let first = number_expr(&authority, 0, 4, "1.50");
        let second = number_expr(&authority, 0, 5, "15e-1");
        assert_eq!(first, second);
        assert_eq!(hash_of(&first), hash_of(&second));
    }

    #[test]
    fn template_equality_is_part_wise_with_exact_literal_text() {
        let authority = DocumentAuthority::fresh();
        let make = |text: &str, name: &str| {
            template_expr(
                &authority,
                vec![
                    literal_part(&authority, 1, 2, text),
                    HclTemplatePart::Interpolation {
                        span: span(&authority, 2, 9),
                        expression: variable_expr(&authority, name),
                    },
                    literal_part(&authority, 9, 10, "b"),
                ],
                None,
            )
        };
        let first = make("a", "x");
        let second = make("a", "x");
        assert_eq!(first, second);
        assert_ne!(first, make("c", "x"));
        assert_ne!(first, make("a", "y"));
        // A literal-text difference inside a part changes equality even when
        // the part spans align.
        let third = template_expr(
            &authority,
            vec![
                literal_part(&authority, 1, 2, "a"),
                HclTemplatePart::Interpolation {
                    span: span(&authority, 2, 9),
                    expression: variable_expr(&authority, "x"),
                },
                literal_part(&authority, 9, 10, "c"),
            ],
            None,
        );
        assert_ne!(first, third);
    }

    #[test]
    fn structural_inequality_across_kinds_and_children() {
        let authority = DocumentAuthority::fresh();
        let number = number_expr(&authority, 0, 1, "1");
        let boolean = HclExpression::new(HclExpressionKind::Boolean(true), span(&authority, 0, 4));
        assert_ne!(number, boolean);
        let add = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&authority, 0, 1, "1")),
                rhs: Box::new(number_expr(&authority, 2, 3, "2")),
            },
            span(&authority, 0, 3),
        );
        let subtract = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Subtract,
                lhs: Box::new(number_expr(&authority, 0, 1, "1")),
                rhs: Box::new(number_expr(&authority, 2, 3, "2")),
            },
            span(&authority, 0, 3),
        );
        assert_ne!(add, subtract);
        let unordered = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([
                    number_expr(&authority, 0, 1, "1"),
                    number_expr(&authority, 2, 3, "2"),
                ]),
            },
            span(&authority, 0, 4),
        );
        let reversed = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([
                    number_expr(&authority, 0, 1, "2"),
                    number_expr(&authority, 2, 3, "1"),
                ]),
            },
            span(&authority, 0, 4),
        );
        assert_ne!(unordered, reversed);
    }

    #[test]
    fn is_literal_complete_accepts_literal_terms() {
        let authority = DocumentAuthority::fresh();
        for expression in [
            number_expr(&authority, 0, 1, "1"),
            number_expr(&authority, 0, 4, "1.50"),
            HclExpression::new(HclExpressionKind::Boolean(true), span(&authority, 0, 4)),
            HclExpression::new(HclExpressionKind::Boolean(false), span(&authority, 0, 5)),
            HclExpression::new(HclExpressionKind::Null, span(&authority, 0, 4)),
        ] {
            assert!(is_literal_complete(&expression));
        }
    }

    #[test]
    fn is_literal_complete_accepts_templates_without_interpolation() {
        let authority = DocumentAuthority::fresh();
        let quoted = template_expr(
            &authority,
            vec![
                literal_part(&authority, 1, 5, "a${b"),
                literal_part(&authority, 5, 6, "c"),
            ],
            None,
        );
        assert!(is_literal_complete(&quoted));
        // Escaped `$${` decodes to literal `${` text and stays literal.
        let escaped = template_expr(&authority, vec![literal_part(&authority, 1, 4, "${")], None);
        assert!(is_literal_complete(&escaped));
        // Empty quoted template.
        let empty = template_expr(&authority, vec![], None);
        assert!(is_literal_complete(&empty));
        // Heredocs: plain and strip-indent modes are both literal when their
        // parts are literal.
        for mode in [HeredocMode::Plain, HeredocMode::StripIndent] {
            let heredoc = template_expr(
                &authority,
                vec![literal_part(&authority, 5, 12, "hello\n")],
                Some(HeredocFacts::new(
                    mode,
                    Arc::from("EOT"),
                    span(&authority, 4, 7),
                    Some(span(&authority, 20, 23)),
                )),
            );
            assert!(is_literal_complete(&heredoc));
        }
    }

    #[test]
    fn is_literal_complete_rejects_templates_with_interpolation_or_directive() {
        let authority = DocumentAuthority::fresh();
        let interpolated = template_expr(
            &authority,
            vec![
                literal_part(&authority, 1, 2, "a"),
                HclTemplatePart::Interpolation {
                    span: span(&authority, 2, 9),
                    expression: variable_expr(&authority, "x"),
                },
            ],
            None,
        );
        assert!(!is_literal_complete(&interpolated));
        let directive = template_expr(
            &authority,
            vec![HclTemplatePart::Directive {
                span: span(&authority, 1, 20),
                kind: HclDirectiveKind::Else,
            }],
            None,
        );
        assert!(!is_literal_complete(&directive));
    }

    #[test]
    fn is_literal_complete_accepts_constructors() {
        let authority = DocumentAuthority::fresh();
        let tuple = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([
                    number_expr(&authority, 1, 2, "1"),
                    HclExpression::new(HclExpressionKind::Null, span(&authority, 4, 8)),
                    HclExpression::new(
                        HclExpressionKind::Tuple {
                            elements: Arc::from([number_expr(&authority, 10, 11, "2")]),
                        },
                        span(&authority, 9, 12),
                    ),
                ]),
            },
            span(&authority, 0, 13),
        );
        assert!(is_literal_complete(&tuple));
        let empty_tuple = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([]),
            },
            span(&authority, 0, 2),
        );
        assert!(is_literal_complete(&empty_tuple));

        let object = object_expr(
            &authority,
            vec![
                entry(
                    HclObjectKey::Identifier(Arc::from("name")),
                    number_expr(&authority, 7, 8, "1"),
                ),
                entry(
                    HclObjectKey::Number(
                        HclNumber::from_spelling(span(&authority, 9, 12), "1.5").unwrap(),
                    ),
                    HclExpression::new(HclExpressionKind::Boolean(true), span(&authority, 13, 17)),
                ),
                entry(
                    HclObjectKey::Template(HclTemplateKey::new(
                        Arc::from([literal_part(&authority, 18, 21, "a")]),
                        span(&authority, 18, 21),
                    )),
                    HclExpression::new(HclExpressionKind::Null, span(&authority, 22, 26)),
                ),
                entry(
                    HclObjectKey::Paren(Box::new(number_expr(&authority, 27, 28, "3"))),
                    number_expr(&authority, 29, 30, "4"),
                ),
                // A parenthesized literal-complete expression key may itself
                // be a constructor: `{(["a"]) = 1}`.
                entry(
                    HclObjectKey::Paren(Box::new(HclExpression::new(
                        HclExpressionKind::Tuple {
                            elements: Arc::from([template_expr(
                                &authority,
                                vec![literal_part(&authority, 1, 2, "a")],
                                None,
                            )]),
                        },
                        span(&authority, 31, 36),
                    ))),
                    number_expr(&authority, 37, 38, "5"),
                ),
            ],
        );
        assert!(is_literal_complete(&object));
        let empty_object = object_expr(&authority, vec![]);
        assert!(is_literal_complete(&empty_object));
    }

    #[test]
    fn is_literal_complete_rejects_derived_constructors() {
        let authority = DocumentAuthority::fresh();
        let tuple = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([variable_expr(&authority, "x")]),
            },
            span(&authority, 0, 4),
        );
        assert!(!is_literal_complete(&tuple));
        let object = object_expr(
            &authority,
            vec![
                entry(
                    HclObjectKey::Identifier(Arc::from("k")),
                    variable_expr(&authority, "x"),
                ),
                entry(
                    HclObjectKey::Paren(Box::new(variable_expr(&authority, "x"))),
                    number_expr(&authority, 5, 6, "1"),
                ),
            ],
        );
        assert!(!is_literal_complete(&object));
    }

    #[test]
    fn is_literal_complete_unary_minus_boundary() {
        let authority = DocumentAuthority::fresh();
        let unary = |operand: HclExpression| {
            HclExpression::new(
                HclExpressionKind::Unary {
                    op: UnaryOp::Minus,
                    operand: Box::new(operand),
                },
                span(&authority, 0, 4),
            )
        };
        assert!(is_literal_complete(&unary(number_expr(
            &authority, 1, 4, "1.5"
        ))));
        assert!(is_literal_complete(&unary(number_expr(
            &authority, 1, 4, "1e3"
        ))));
        assert!(!is_literal_complete(&unary(HclExpression::new(
            HclExpressionKind::Boolean(true),
            span(&authority, 1, 5),
        ))));
        assert!(!is_literal_complete(&unary(variable_expr(&authority, "x"))));
        // `- -1` applies unary minus to a unary expression, not a number
        // literal.
        let nested = unary(unary(number_expr(&authority, 2, 3, "1")));
        assert!(!is_literal_complete(&nested));
        let not = HclExpression::new(
            HclExpressionKind::Unary {
                op: UnaryOp::Not,
                operand: Box::new(number_expr(&authority, 1, 2, "1")),
            },
            span(&authority, 0, 2),
        );
        assert!(!is_literal_complete(&not));
    }

    #[test]
    fn is_literal_complete_paren_preserves_boundary() {
        let authority = DocumentAuthority::fresh();
        let wrapped_literal = HclExpression::new(
            HclExpressionKind::Paren {
                inner: Box::new(number_expr(&authority, 1, 2, "1")),
            },
            span(&authority, 0, 3),
        );
        assert!(is_literal_complete(&wrapped_literal));
        let wrapped_derived = HclExpression::new(
            HclExpressionKind::Paren {
                inner: Box::new(HclExpression::new(
                    HclExpressionKind::Binary {
                        op: BinaryOp::Add,
                        lhs: Box::new(number_expr(&authority, 1, 2, "1")),
                        rhs: Box::new(number_expr(&authority, 3, 4, "2")),
                    },
                    span(&authority, 1, 4),
                )),
            },
            span(&authority, 0, 5),
        );
        assert!(!is_literal_complete(&wrapped_derived));
    }

    #[test]
    fn is_literal_complete_rejects_all_derived_forms() {
        let authority = DocumentAuthority::fresh();
        let binary = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&authority, 0, 1, "1")),
                rhs: Box::new(number_expr(&authority, 2, 3, "2")),
            },
            span(&authority, 0, 3),
        );
        let traversal = HclExpression::new(
            HclExpressionKind::Traversal {
                root: HclTraversalRoot::Variable(Arc::from("foo")),
                steps: Arc::from([HclTraversalStep::GetAttr {
                    name: Arc::from("bar"),
                    span: span(&authority, 3, 7),
                }]),
            },
            span(&authority, 0, 7),
        );
        let call = HclExpression::new(
            HclExpressionKind::FunctionCall {
                name: Arc::from("f"),
                name_span: span(&authority, 0, 1),
                args: Arc::from([HclCallArg::new(number_expr(&authority, 2, 3, "1"), false)]),
            },
            span(&authority, 0, 4),
        );
        let conditional = HclExpression::new(
            HclExpressionKind::Conditional {
                condition: Box::new(HclExpression::new(
                    HclExpressionKind::Boolean(true),
                    span(&authority, 0, 4),
                )),
                then: Box::new(number_expr(&authority, 5, 6, "1")),
                else_: Box::new(number_expr(&authority, 7, 8, "2")),
            },
            span(&authority, 0, 8),
        );
        let for_tuple = HclExpression::new(
            HclExpressionKind::ForTuple {
                intro: HclForIntro::new(
                    None,
                    Arc::from("v"),
                    Box::new(variable_expr(&authority, "list")),
                    span(&authority, 0, 12),
                ),
                value: Box::new(number_expr(&authority, 13, 14, "1")),
                condition: None,
            },
            span(&authority, 0, 15),
        );
        let for_object = HclExpression::new(
            HclExpressionKind::ForObject {
                intro: HclForIntro::new(
                    None,
                    Arc::from("v"),
                    Box::new(variable_expr(&authority, "list")),
                    span(&authority, 0, 12),
                ),
                key: Box::new(number_expr(&authority, 13, 14, "1")),
                value: Box::new(number_expr(&authority, 15, 16, "2")),
                grouping: false,
                condition: Some(Box::new(number_expr(&authority, 17, 18, "3"))),
            },
            span(&authority, 0, 19),
        );
        for derived in [
            variable_expr(&authority, "x"),
            traversal,
            call,
            binary,
            conditional,
            for_tuple,
            for_object,
        ] {
            assert!(!is_literal_complete(&derived));
        }
    }

    #[test]
    fn literal_value_projects_numbers_and_signs() {
        let authority = DocumentAuthority::fresh();
        assert_eq!(
            literal_value(&number_expr(&authority, 0, 4, "1000")).unwrap(),
            HclLiteralValue::Integer("1000".to_owned())
        );
        assert_eq!(
            literal_value(&number_expr(&authority, 0, 3, "1.5")).unwrap(),
            HclLiteralValue::Decimal("1.5".to_owned())
        );
        // `1e3` normalizes to `1000` and projects as an integer.
        assert_eq!(
            literal_value(&number_expr(&authority, 0, 3, "1e3")).unwrap(),
            HclLiteralValue::Integer("1000".to_owned())
        );
        let minus = |operand: HclExpression| {
            HclExpression::new(
                HclExpressionKind::Unary {
                    op: UnaryOp::Minus,
                    operand: Box::new(operand),
                },
                span(&authority, 0, 4),
            )
        };
        assert_eq!(
            literal_value(&minus(number_expr(&authority, 1, 2, "1"))).unwrap(),
            HclLiteralValue::Integer("-1".to_owned())
        );
        assert_eq!(
            literal_value(&minus(number_expr(&authority, 1, 4, "1.5"))).unwrap(),
            HclLiteralValue::Decimal("-1.5".to_owned())
        );
        assert_eq!(
            literal_value(&minus(number_expr(&authority, 1, 4, "1e3"))).unwrap(),
            HclLiteralValue::Integer("-1000".to_owned())
        );
        assert_eq!(
            literal_value(&minus(number_expr(&authority, 1, 4, "1.5e-2"))).unwrap(),
            HclLiteralValue::Decimal("-0.015".to_owned())
        );
        // `-0` stays canonical zero.
        assert_eq!(
            literal_value(&minus(number_expr(&authority, 1, 2, "0"))).unwrap(),
            HclLiteralValue::Integer("0".to_owned())
        );
    }

    #[test]
    fn literal_value_projects_booleans_and_null() {
        let authority = DocumentAuthority::fresh();
        assert_eq!(
            literal_value(&HclExpression::new(
                HclExpressionKind::Boolean(true),
                span(&authority, 0, 4),
            ))
            .unwrap(),
            HclLiteralValue::Boolean(true)
        );
        assert_eq!(
            literal_value(&HclExpression::new(
                HclExpressionKind::Boolean(false),
                span(&authority, 0, 5),
            ))
            .unwrap(),
            HclLiteralValue::Boolean(false)
        );
        assert_eq!(
            literal_value(&HclExpression::new(
                HclExpressionKind::Null,
                span(&authority, 0, 4),
            ))
            .unwrap(),
            HclLiteralValue::Null
        );
    }

    #[test]
    fn literal_value_projects_literal_templates() {
        let authority = DocumentAuthority::fresh();
        let quoted = template_expr(
            &authority,
            vec![literal_part(&authority, 1, 4, "a${b")],
            None,
        );
        assert_eq!(
            literal_value(&quoted).unwrap(),
            HclLiteralValue::String("a${b".to_owned())
        );
        let empty = template_expr(&authority, vec![], None);
        assert_eq!(
            literal_value(&empty).unwrap(),
            HclLiteralValue::String(String::new())
        );
        let heredoc = template_expr(
            &authority,
            vec![literal_part(&authority, 5, 12, "hello\n")],
            Some(HeredocFacts::new(
                HeredocMode::Plain,
                Arc::from("EOT"),
                span(&authority, 4, 7),
                Some(span(&authority, 20, 23)),
            )),
        );
        assert_eq!(
            literal_value(&heredoc).unwrap(),
            HclLiteralValue::String("hello\n".to_owned())
        );
        // `<<-` strips the minimum indentation only when the value is read.
        let strip = template_expr(
            &authority,
            vec![literal_part(&authority, 5, 14, "  a\n    b\n")],
            Some(HeredocFacts::new(
                HeredocMode::StripIndent,
                Arc::from("EOT"),
                span(&authority, 4, 7),
                Some(span(&authority, 30, 33)),
            )),
        );
        assert_eq!(
            literal_value(&strip).unwrap(),
            HclLiteralValue::String("a\n  b\n".to_owned())
        );
    }

    #[test]
    fn literal_value_projects_constructors() {
        let authority = DocumentAuthority::fresh();
        let tuple = HclExpression::new(
            HclExpressionKind::Tuple {
                elements: Arc::from([
                    number_expr(&authority, 1, 2, "1"),
                    HclExpression::new(HclExpressionKind::Boolean(true), span(&authority, 4, 8)),
                    HclExpression::new(
                        HclExpressionKind::Tuple {
                            elements: Arc::from([number_expr(&authority, 10, 11, "2")]),
                        },
                        span(&authority, 9, 12),
                    ),
                ]),
            },
            span(&authority, 0, 13),
        );
        let HclLiteralValue::Tuple(elements) = literal_value(&tuple).unwrap() else {
            panic!("expected tuple literal");
        };
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0], HclLiteralValue::Integer("1".to_owned()));
        assert_eq!(elements[1], HclLiteralValue::Boolean(true));
        assert_eq!(
            elements[2],
            HclLiteralValue::Tuple(Arc::from([HclLiteralValue::Integer("2".to_owned())]))
        );

        let object = object_expr(
            &authority,
            vec![
                entry(
                    HclObjectKey::Identifier(Arc::from("k")),
                    number_expr(&authority, 4, 5, "1"),
                ),
                entry(
                    HclObjectKey::Number(
                        HclNumber::from_spelling(span(&authority, 6, 9), "1.5").unwrap(),
                    ),
                    number_expr(&authority, 10, 11, "2"),
                ),
                entry(
                    HclObjectKey::Template(HclTemplateKey::new(
                        Arc::from([literal_part(&authority, 12, 15, "a")]),
                        span(&authority, 12, 15),
                    )),
                    number_expr(&authority, 16, 17, "3"),
                ),
                entry(
                    HclObjectKey::Paren(Box::new(number_expr(&authority, 18, 19, "4"))),
                    number_expr(&authority, 20, 21, "5"),
                ),
                // Duplicate keys remain ordered entries.
                entry(
                    HclObjectKey::Identifier(Arc::from("k")),
                    number_expr(&authority, 22, 23, "6"),
                ),
            ],
        );
        let HclLiteralValue::Object(entries) = literal_value(&object).unwrap() else {
            panic!("expected object literal");
        };
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].key(), &HclLiteralKey::Identifier("k".to_owned()));
        assert_eq!(
            entries[0].value(),
            &HclLiteralValue::Integer("1".to_owned())
        );
        assert_eq!(entries[1].key(), &HclLiteralKey::Number("1.5".to_owned()));
        assert_eq!(entries[2].key(), &HclLiteralKey::String("a".to_owned()));
        assert_eq!(
            entries[3].key(),
            &HclLiteralKey::Value(HclLiteralValue::Integer("4".to_owned()))
        );
        assert_eq!(entries[4].key(), &HclLiteralKey::Identifier("k".to_owned()));
    }

    #[test]
    fn literal_value_fails_for_derived_expressions() {
        let authority = DocumentAuthority::fresh();
        let binary = HclExpression::new(
            HclExpressionKind::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(number_expr(&authority, 0, 1, "1")),
                rhs: Box::new(number_expr(&authority, 2, 3, "2")),
            },
            span(&authority, 0, 3),
        );
        let interpolated = template_expr(
            &authority,
            vec![HclTemplatePart::Interpolation {
                span: span(&authority, 1, 8),
                expression: variable_expr(&authority, "x"),
            }],
            None,
        );
        let traversal = HclExpression::new(
            HclExpressionKind::Traversal {
                root: HclTraversalRoot::Variable(Arc::from("foo")),
                steps: Arc::from([HclTraversalStep::Index {
                    key: Box::new(number_expr(&authority, 4, 5, "0")),
                    span: span(&authority, 4, 6),
                }]),
            },
            span(&authority, 0, 6),
        );
        let unary_variable = HclExpression::new(
            HclExpressionKind::Unary {
                op: UnaryOp::Minus,
                operand: Box::new(variable_expr(&authority, "x")),
            },
            span(&authority, 0, 2),
        );
        for derived in [
            variable_expr(&authority, "x"),
            traversal,
            HclExpression::new(
                HclExpressionKind::FunctionCall {
                    name: Arc::from("f"),
                    name_span: span(&authority, 0, 1),
                    args: Arc::from([]),
                },
                span(&authority, 0, 3),
            ),
            binary,
            interpolated,
            unary_variable,
            HclExpression::new(
                HclExpressionKind::Unary {
                    op: UnaryOp::Not,
                    operand: Box::new(number_expr(&authority, 1, 2, "1")),
                },
                span(&authority, 0, 2),
            ),
        ] {
            assert_eq!(literal_value(&derived), Err(NonLiteralExpression));
        }
    }

    #[test]
    fn literal_value_equality_and_hash() {
        let authority = DocumentAuthority::fresh();
        let first = literal_value(&number_expr(&authority, 0, 1, "1")).unwrap();
        let second = literal_value(&number_expr(&authority, 0, 1, "1")).unwrap();
        let decimal = literal_value(&number_expr(&authority, 0, 3, "1.5")).unwrap();
        assert_eq!(first, second);
        assert_eq!(hash_of(&first), hash_of(&second));
        // A value that normalizes to an integer is an integer, never a
        // decimal with a trailing fraction.
        assert_eq!(
            literal_value(&number_expr(&authority, 0, 3, "1.0")).unwrap(),
            HclLiteralValue::Integer("1".to_owned())
        );
        assert_ne!(first, decimal);
        assert_eq!(decimal, HclLiteralValue::Decimal("1.5".to_owned()));
        assert_ne!(HclLiteralValue::Boolean(true), HclLiteralValue::Null);
    }

    #[test]
    fn heredoc_facts_carry_mode_marker_and_closing_facts() {
        let authority = DocumentAuthority::fresh();
        let facts = HeredocFacts::new(
            HeredocMode::StripIndent,
            Arc::from("EOT"),
            span(&authority, 4, 7),
            Some(span(&authority, 20, 23)),
        );
        assert_eq!(facts.mode(), HeredocMode::StripIndent);
        assert_eq!(facts.marker(), "EOT");
        assert_eq!(facts.marker_span(), span(&authority, 4, 7));
        assert_eq!(facts.closing_span(), Some(span(&authority, 20, 23)));
        let unterminated = HeredocFacts::new(
            HeredocMode::Plain,
            Arc::from("EOF"),
            span(&authority, 4, 7),
            None,
        );
        assert_eq!(unterminated.closing_span(), None);
        // Equality is mode and marker only; span positions do not matter.
        assert_ne!(facts, unterminated);
        let same = HeredocFacts::new(
            HeredocMode::StripIndent,
            Arc::from("EOT"),
            span(&authority, 40, 43),
            None,
        );
        assert_eq!(facts, same);
    }

    #[test]
    fn heredoc_mode_spellings_are_stable() {
        assert_eq!(HeredocMode::Plain.as_str(), "<<");
        assert_eq!(HeredocMode::StripIndent.as_str(), "<<-");
    }

    #[test]
    fn separator_and_operator_spellings_round_trip() {
        assert_eq!(ObjectSeparator::Equals.as_str(), "=");
        assert_eq!(ObjectSeparator::Colon.as_str(), ":");
        for spelling in ["-", "!"] {
            assert_eq!(
                UnaryOp::from_name(spelling).expect("known").as_str(),
                spelling
            );
        }
        assert_eq!(UnaryOp::from_name("+"), None);
        for spelling in [
            "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&&", "||",
        ] {
            assert_eq!(
                BinaryOp::from_name(spelling).expect("known").as_str(),
                spelling
            );
        }
        assert_eq!(BinaryOp::from_name("**"), None);
    }

    #[test]
    fn literal_entry_accessors_report_key_and_value() {
        let entry = HclLiteralObjectEntry::new(
            HclLiteralKey::Identifier("k".to_owned()),
            HclLiteralValue::Boolean(true),
        );
        assert_eq!(entry.key(), &HclLiteralKey::Identifier("k".to_owned()));
        assert_eq!(entry.value(), &HclLiteralValue::Boolean(true));
    }
}
