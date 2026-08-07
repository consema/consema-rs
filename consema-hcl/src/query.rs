//! HCL dual-domain query execution (RFC 0014 §7).
//!
//! The two query domains share the immutable-snapshot, ordered-selection,
//! limits, cancellation, and terminal-state rules of the common query
//! contract and differ only in what they see:
//!
//! - `hcl.native-semantic-query@1` (RFC 0014 §7.1) queries the native body
//!   tree of the document — the same model under both `hcl.native@1` and
//!   `hcl.tfvars@1`, so no representation guard exists here (unlike the
//!   plist family, RFC 0013). The domain root input is the root body;
//!   results preserve source order. The literal accessors
//!   (`hcl.attribute-literal-value@1`) validate that the expression is
//!   literal-complete and of the requested type before returning: a type
//!   mismatch is a `RequiredTypeMismatch` query failure, and a non-literal
//!   expression is reported as `TargetUnavailable` (the conformance layer
//!   maps these to `hcl.query.type-mismatch@1` and `hcl.query.non-literal@1`
//!   respectively) — never a null, empty, or converted result (RFC 0014
//!   §7.1). Nothing is ever evaluated, resolved, or executed (hard gate 1).
//!
//! - `hcl.lossless-syntax-query@1` (RFC 0014 §7.2) filters the ordered
//!   lossless pieces of the raw source by their closed 30-kind
//!   [`HclSyntaxKind`] set and by decoded text; every non-empty raw byte
//!   belongs to exactly one ordered structural piece, and the lossless index
//!   is always present under both profiles because both share the one syntax
//!   system.
//!
//! Domain/operator/role/profile validation occurs before the first result
//! (RFC 0014 §7.2): a definition validated for another domain is rejected
//! with `DomainMismatch`. A `Recovered` document remains queryable over its
//! proven parts and its error regions (RFC 0014 §3).
//!
//! The module is the crate's public query API, re-exported by `lib.rs`
//! (M9 conformance milestone).

use crate::document::Document;
use crate::expression::{
    HclDirectiveKind, HclExpression, HclExpressionKind, HclExpressionKindName, HclLiteralValue,
    HclTemplatePart, is_literal_complete, literal_value,
};
use crate::native::{
    HclAttribute, HclBlock, HclBlockLabel, HclBody, HclBodyItem, HclDocument, HclErrorRegion,
    HclSyntaxKind,
};
use consema_core::{
    BigInteger, CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor,
    PortableValueKind, QueryExecution, QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::{HashMap, HashSet};

/// Owned snapshot-bound HCL native semantic query match (RFC 0014 §7.1).
///
/// Every match carries a snapshot-bound handle and a reference into the
/// immutable native tree of the queried document: the same tree node reached
/// through different operators is one match identity, and no identity is
/// ever shared between distinct occurrences (RFC 0014 §6).
#[derive(Clone, Debug)]
pub enum HclMatch<'a> {
    /// One HCL body: the ordered container of attributes and blocks shared
    /// by the root and nested bodies; the domain root input is the root body
    /// (RFC 0014 §6, §7.1).
    Body {
        /// Body identity.
        node: NodeRef,
        /// Native body within the queried document.
        body: &'a HclBody,
    },
    /// One attribute occurrence.
    Attribute {
        /// Attribute identity.
        node: NodeRef,
        /// Native attribute within the queried document.
        attribute: &'a HclAttribute,
    },
    /// One block occurrence.
    Block {
        /// Block identity.
        node: NodeRef,
        /// Native block within the queried document.
        block: &'a HclBlock,
    },
    /// One block label with its quote/naked fact (RFC 0014 §6).
    BlockLabel {
        /// Label identity.
        node: NodeRef,
        /// Native label within the queried document.
        label: &'a HclBlockLabel,
    },
    /// One expression AST node.
    Expression {
        /// Expression identity.
        node: NodeRef,
        /// Native expression within the queried document.
        expression: &'a HclExpression,
    },
    /// One ordered template part: literal, interpolation, or directive.
    TemplatePart {
        /// Part identity.
        node: NodeRef,
        /// Native part within the queried document.
        part: &'a HclTemplatePart,
    },
    /// One recovered HCL error region with its stable code (RFC 0014 §3).
    ErrorRegion {
        /// Region identity.
        node: NodeRef,
        /// Recovered region fact.
        region: &'a HclErrorRegion,
        /// Zero-based position within the document's ordered error regions.
        position: usize,
    },
}

impl HclMatch<'_> {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Body { node, .. }
            | Self::Attribute { node, .. }
            | Self::Block { node, .. }
            | Self::BlockLabel { node, .. }
            | Self::Expression { node, .. }
            | Self::TemplatePart { node, .. }
            | Self::ErrorRegion { node, .. } => *node,
        }
    }
}

/// Owned snapshot-bound HCL lossless syntax query match (RFC 0014 §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HclSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: HclSyntaxKind,
    ordinal: usize,
}

impl HclSyntaxMatch {
    /// Process-local syntax-piece identity.
    #[must_use]
    pub const fn node_ref(self) -> NodeRef {
        self.node
    }

    /// Exact raw source span.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }

    /// Format-owned lossless kind.
    #[must_use]
    pub const fn kind(self) -> HclSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// One native tree node identity for the pre-order rank map.
///
/// The tree is immutable for the snapshot's lifetime, so the reference
/// addresses are stable for the whole execution; pointer identity is
/// process-local and never leaves the executor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RankKey {
    /// One body node.
    Body(*const HclBody),
    /// One attribute node.
    Attribute(*const HclAttribute),
    /// One block node.
    Block(*const HclBlock),
    /// One block label node.
    BlockLabel(*const HclBlockLabel),
    /// One expression node.
    Expression(*const HclExpression),
    /// One template part node.
    TemplatePart(*const HclTemplatePart),
}

/// Executes a validated HCL native semantic query against one immutable
/// snapshot (RFC 0014 §7.1).
///
/// The domain serves both profiles: the two profiles own the one native
/// model, so only the domain identity is guarded here.
pub fn execute_hcl_native_query<'a>(
    executable: &ExecutableQuery,
    document: &'a Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<HclMatch<'a>>, QueryFailure> {
    if executable.definition().domain().id() != "hcl.native-semantic-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let native = document.document();
    let (ranks, tree_nodes) = preorder_ranks(native);
    let mut context = NativeContext {
        document,
        native,
        limits,
        cancellation,
        steps: 0,
        ranks,
        tree_nodes,
    };
    context.step(1)?;
    let input = vec![HclMatch::Body {
        node: context.root_node(),
        body: native.body(),
    }];
    let matches =
        execute_native_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes the complete HCL native result through an ordered
/// cursor.
pub fn execute_hcl_native_query_cursor<'a>(
    executable: &ExecutableQuery,
    document: &'a Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<HclMatch<'a>>, QueryFailure> {
    let result = execute_hcl_native_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated HCL lossless syntax query in raw source order (RFC
/// 0014 §7.2).
///
/// The lossless index is always present under both profiles because both
/// share the one syntax system, so only the domain identity is guarded here.
pub fn execute_hcl_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<HclSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "hcl.lossless-syntax-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let mut context = SyntaxContext {
        document,
        limits,
        cancellation,
        steps: 0,
    };
    let pieces = document.lossless_structural_index().pieces();
    let kinds = document.lossless_syntax_kinds();
    context.step(pieces.len())?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(pieces.len())
        .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
    for (ordinal, (piece, kind)) in pieces.iter().zip(kinds).enumerate() {
        let identity = u64::try_from(ordinal).map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        input.push(HclSyntaxMatch {
            node: document
                .authority()
                .node_ref(identity, NodeRole::HclSyntaxPiece),
            span: piece.span(),
            kind: *kind,
            ordinal,
        });
    }
    let matches =
        execute_syntax_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes an HCL lossless syntax query and exposes its complete result as
/// a cancellable cursor.
pub fn execute_hcl_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<HclSyntaxMatch>, QueryFailure> {
    let result = execute_hcl_syntax_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Applies the validated cardinality selection to a complete standard result
/// sequence.
fn apply_selection<T>(
    mut values: Vec<T>,
    selection: QuerySelection,
) -> Result<Vec<T>, QueryFailure> {
    match selection {
        QuerySelection::All => Ok(values),
        QuerySelection::First => Ok(values.into_iter().take(1).collect()),
        QuerySelection::Last => Ok(values.pop().into_iter().collect()),
        QuerySelection::ZeroOrOne if values.len() <= 1 => Ok(values),
        QuerySelection::RequireOne if values.len() == 1 => Ok(values),
        QuerySelection::ZeroOrOne | QuerySelection::RequireOne => {
            Err(QueryFailure::CardinalityViolation {
                selection,
                actual: values.len(),
            })
        }
    }
}

/// Native-domain execution state: the document, its native tree, the
/// pre-order rank map, and the common accounting state.
struct NativeContext<'a, 'c> {
    document: &'a Document,
    native: &'a HclDocument,
    limits: QueryLimits,
    cancellation: &'c CancellationToken,
    steps: usize,
    /// Pre-order document rank of every tree node, computed once per
    /// execution for structure-order merging.
    ranks: HashMap<RankKey, usize>,
    /// Number of ranked tree nodes; the document-level error regions are
    /// ranked after them.
    tree_nodes: usize,
}

impl NativeContext<'_, '_> {
    fn step(&mut self, results: usize) -> Result<(), QueryFailure> {
        if self.cancellation.is_cancelled() {
            return Err(QueryFailure::Cancelled);
        }
        self.steps = self
            .steps
            .checked_add(1)
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if self.steps > self.limits.max_steps || results > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn push<T>(&self, output: &mut Vec<T>, value: T) -> Result<(), QueryFailure> {
        let observed = output
            .len()
            .checked_add(1)
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if observed > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        output
            .try_reserve(1)
            .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        output.push(value);
        Ok(())
    }

    fn append<T>(&self, output: &mut Vec<T>, mut values: Vec<T>) -> Result<(), QueryFailure> {
        let observed = output
            .len()
            .checked_add(values.len())
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if observed > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        output
            .try_reserve(values.len())
            .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        output.append(&mut values);
        Ok(())
    }

    fn node_ref(&self, index: usize, role: NodeRole) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(index).expect("parse limits keep tree nodes in u64"),
            role,
        )
    }

    fn rank(&self, key: RankKey) -> usize {
        self.ranks.get(&key).copied().unwrap_or(usize::MAX)
    }

    /// The root body handle: the root body is ranked first by the pre-order
    /// walk.
    fn root_node(&self) -> NodeRef {
        self.node_ref(0, NodeRole::HclBody)
    }

    /// Deterministic structure-order key: the pre-order document rank of the
    /// node, with the document-level error regions ranked after every tree
    /// node in their own source order (RFC 0014 §3).
    fn source_order(&self, item: &HclMatch<'_>) -> usize {
        match item {
            HclMatch::Body { body, .. } => self.rank(RankKey::Body(std::ptr::from_ref(*body))),
            HclMatch::Attribute { attribute, .. } => {
                self.rank(RankKey::Attribute(std::ptr::from_ref(*attribute)))
            }
            HclMatch::Block { block, .. } => self.rank(RankKey::Block(std::ptr::from_ref(*block))),
            HclMatch::BlockLabel { label, .. } => {
                self.rank(RankKey::BlockLabel(std::ptr::from_ref(*label)))
            }
            HclMatch::Expression { expression, .. } => {
                self.rank(RankKey::Expression(std::ptr::from_ref(*expression)))
            }
            HclMatch::TemplatePart { part, .. } => {
                self.rank(RankKey::TemplatePart(std::ptr::from_ref(*part)))
            }
            HclMatch::ErrorRegion { position, .. } => self.tree_nodes + position,
        }
    }
}

/// Syntax-domain execution state.
struct SyntaxContext<'a> {
    document: &'a Document,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
}

impl SyntaxContext<'_> {
    fn step(&mut self, results: usize) -> Result<(), QueryFailure> {
        if self.cancellation.is_cancelled() {
            return Err(QueryFailure::Cancelled);
        }
        self.steps = self
            .steps
            .checked_add(1)
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if self.steps > self.limits.max_steps || results > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn push<T>(&self, output: &mut Vec<T>, value: T) -> Result<(), QueryFailure> {
        let observed = output
            .len()
            .checked_add(1)
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if observed > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        output
            .try_reserve(1)
            .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        output.push(value);
        Ok(())
    }

    fn append<T>(&self, output: &mut Vec<T>, mut values: Vec<T>) -> Result<(), QueryFailure> {
        let observed = output
            .len()
            .checked_add(values.len())
            .ok_or(QueryFailure::ResourceLimitExceeded)?;
        if observed > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        output
            .try_reserve(values.len())
            .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        output.append(&mut values);
        Ok(())
    }
}

fn execute_native_expression<'a>(
    expression: &QueryExpression,
    input: &[HclMatch<'a>],
    context: &mut NativeContext<'a, '_>,
) -> Result<Vec<HclMatch<'a>>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let input = execute_native_expression(expression_input, input, context)?;
            apply_native_operator(operator, input, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_native_expression(branch, input, context)?;
                context.append(&mut output, values)?;
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_native_expression(branch, input, context)?;
                context.append(&mut output, values)?;
            }
            output.sort_by_key(|item| context.source_order(item));
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn execute_syntax_expression(
    expression: &QueryExpression,
    input: &[HclSyntaxMatch],
    context: &mut SyntaxContext<'_>,
) -> Result<Vec<HclSyntaxMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let input = execute_syntax_expression(expression_input, input, context)?;
            apply_syntax_operator(operator, input, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_syntax_expression(branch, input, context)?;
                context.append(&mut output, values)?;
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_syntax_expression(branch, input, context)?;
                context.append(&mut output, values)?;
            }
            output.sort_by_key(|item| item.ordinal);
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn apply_native_operator<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
) -> Result<Vec<HclMatch<'a>>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "hcl.document-body" => document_body(input, context, &mut output)?,
        "hcl.body-items" => body_items(input, context, &mut output)?,
        "hcl.body-attributes" => body_attributes(input, context, &mut output)?,
        "hcl.body-blocks" => body_blocks(input, context, &mut output)?,
        "hcl.body-block-type-equals" => {
            body_block_type_equals(operator, input, context, &mut output)?;
        }
        "hcl.attribute-name" => attribute_name(input, context, &mut output)?,
        "hcl.attribute-name-equals" => {
            attribute_name_equals(operator, input, context, &mut output)?;
        }
        "hcl.attribute-expression" => attribute_expression(input, context, &mut output)?,
        "hcl.attribute-literal-value" => {
            attribute_literal_value(operator, input, context, &mut output)?;
        }
        "hcl.block-type" => block_type(input, context, &mut output)?,
        "hcl.block-type-equals" => block_type_equals(operator, input, context, &mut output)?,
        "hcl.block-labels" => block_labels(input, context, &mut output)?,
        "hcl.block-label-equals" => block_label_equals(operator, input, context, &mut output)?,
        "hcl.block-nested-body" => block_nested_body(input, context, &mut output)?,
        "hcl.expression-kind-is" => expression_kind_is(operator, input, context, &mut output)?,
        "hcl.expression-is-literal" => expression_is_literal(input, context, &mut output)?,
        "hcl.expression-text" => expression_text(input, context, &mut output)?,
        "hcl.expression-children" => expression_children(input, context, &mut output)?,
        "hcl.template-parts" => template_parts(input, context, &mut output)?,
        "hcl.tuple-elements" => tuple_elements(input, context, &mut output)?,
        "hcl.object-entries" => object_entries(input, context, &mut output)?,
        "hcl.error-regions" => error_regions(input, context, &mut output)?,
        "core.take" => take(operator, input, context, &mut output)?,
        "core.distinct-by-identity" => distinct_by_identity(input, context, &mut output)?,
        _ => unreachable!("validated hcl native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// `hcl.document-body`: the document's root body, a document-level fact
/// emitted once from any non-empty input.
fn document_body<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    if input.is_empty() {
        return Ok(());
    }
    context.push(
        output,
        HclMatch::Body {
            node: context.root_node(),
            body: context.native.body(),
        },
    )
}

/// `hcl.body-items`: the ordered body items of every body match as attribute
/// and block matches, interleaved in source order.
fn body_items<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        let HclMatch::Body { body, .. } = item else {
            continue;
        };
        for body_item in body.items() {
            match body_item {
                HclBodyItem::Attribute(attribute) => {
                    let rank = context.rank(RankKey::Attribute(std::ptr::from_ref(attribute)));
                    context.push(
                        output,
                        HclMatch::Attribute {
                            node: context.node_ref(rank, NodeRole::HclAttribute),
                            attribute,
                        },
                    )?;
                }
                HclBodyItem::Block(block) => {
                    let rank = context.rank(RankKey::Block(std::ptr::from_ref(block)));
                    context.push(
                        output,
                        HclMatch::Block {
                            node: context.node_ref(rank, NodeRole::HclBlock),
                            block,
                        },
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// `hcl.body-attributes`: the attribute items of every body match, in source
/// order.
fn body_attributes<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        let HclMatch::Body { body, .. } = item else {
            continue;
        };
        for body_item in body.items() {
            if let HclBodyItem::Attribute(attribute) = body_item {
                let rank = context.rank(RankKey::Attribute(std::ptr::from_ref(attribute)));
                context.push(
                    output,
                    HclMatch::Attribute {
                        node: context.node_ref(rank, NodeRole::HclAttribute),
                        attribute,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.body-blocks`: the block items of every body match, in source order.
fn body_blocks<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        let HclMatch::Body { body, .. } = item else {
            continue;
        };
        for body_item in body.items() {
            if let HclBodyItem::Block(block) = body_item {
                let rank = context.rank(RankKey::Block(std::ptr::from_ref(block)));
                context.push(
                    output,
                    HclMatch::Block {
                        node: context.node_ref(rank, NodeRole::HclBlock),
                        block,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.body-block-type-equals`: the blocks of every body match whose type
/// equals the `type` argument.
fn body_block_type_equals<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["type"]
        .as_string()
        .expect("validated type argument");
    for item in input {
        let HclMatch::Body { body, .. } = item else {
            continue;
        };
        for body_item in body.items() {
            if let HclBodyItem::Block(block) = body_item {
                if block.block_type() == expected {
                    let rank = context.rank(RankKey::Block(std::ptr::from_ref(block)));
                    context.push(
                        output,
                        HclMatch::Block {
                            node: context.node_ref(rank, NodeRole::HclBlock),
                            block,
                        },
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// `hcl.attribute-name`: keeps every attribute match, selecting the name
/// fact; other body-item matches contribute nothing.
fn attribute_name<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(item, HclMatch::Attribute { .. }) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.attribute-name-equals`: exact attribute-name equality; case is never
/// folded.
fn attribute_name_equals<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["name"]
        .as_string()
        .expect("validated name argument");
    for item in input {
        if matches!(&item, HclMatch::Attribute { attribute, .. } if attribute.name() == expected) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.attribute-expression`: the value expression of every attribute
/// match, unevaluated (RFC 0014 §1).
fn attribute_expression<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Attribute { attribute, .. } = item {
            let expression = attribute.expression();
            let rank = context.rank(RankKey::Expression(std::ptr::from_ref(expression)));
            context.push(
                output,
                HclMatch::Expression {
                    node: context.node_ref(rank, NodeRole::HclExpression),
                    expression,
                },
            )?;
        }
    }
    Ok(())
}

/// `hcl.attribute-literal-value`: the typed literal accessor family (RFC
/// 0014 §7.1).
///
/// Each accessor (`as-string`, `as-integer`, `as-real`, `as-boolean-is`,
/// `as-null-is`) validates that the expression is literal-complete and of
/// the requested type before returning. A non-literal expression is reported
/// as `TargetUnavailable` (the conformance layer maps it to
/// `hcl.query.non-literal@1`); a type mismatch is reported as
/// `RequiredTypeMismatch` (`hcl.query.type-mismatch@1`). Neither is ever a
/// null, empty, or converted result.
fn attribute_literal_value<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let accessor = operator.arguments()["accessor"]
        .as_string()
        .expect("validated accessor argument");
    let expected = match accessor {
        "as-string" => PortableValueKind::String,
        "as-integer" => PortableValueKind::Integer,
        "as-real" => PortableValueKind::Decimal,
        "as-boolean-is" => PortableValueKind::Boolean,
        "as-null-is" => PortableValueKind::Null,
        _ => unreachable!("validated accessor name"),
    };
    for item in input {
        let Some(expression) = expression_payload(&item) else {
            continue;
        };
        let Ok(value) = literal_value(expression) else {
            return Err(QueryFailure::TargetUnavailable);
        };
        let actual = literal_kind(&value);
        if actual != expected {
            return Err(QueryFailure::RequiredTypeMismatch { expected, actual });
        }
        context.push(output, item)?;
    }
    Ok(())
}

/// The expression payload of one literal-capable match: a plain expression
/// or an attribute's value expression.
fn expression_payload<'a>(item: &HclMatch<'a>) -> Option<&'a HclExpression> {
    match item {
        HclMatch::Expression { expression, .. } => Some(expression),
        HclMatch::Attribute { attribute, .. } => Some(attribute.expression()),
        _ => None,
    }
}

/// Maps one typed literal value onto the closest portable value kind for
/// mismatch payloads.
fn literal_kind(value: &HclLiteralValue) -> PortableValueKind {
    match value {
        HclLiteralValue::Integer(_) => PortableValueKind::Integer,
        HclLiteralValue::Decimal(_) => PortableValueKind::Decimal,
        HclLiteralValue::String(_) => PortableValueKind::String,
        HclLiteralValue::Boolean(_) => PortableValueKind::Boolean,
        HclLiteralValue::Null => PortableValueKind::Null,
        HclLiteralValue::Tuple(_) => PortableValueKind::Sequence,
        HclLiteralValue::Object(_) => PortableValueKind::Object,
    }
}

/// `hcl.block-type`: keeps every block match, selecting the type fact; other
/// body-item matches contribute nothing.
fn block_type<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(item, HclMatch::Block { .. }) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.block-type-equals`: exact block-type equality.
fn block_type_equals<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["type"]
        .as_string()
        .expect("validated type argument");
    for item in input {
        if matches!(&item, HclMatch::Block { block, .. } if block.block_type() == expected) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.block-labels`: the ordered labels of every block match, each with
/// its quote/naked fact.
fn block_labels<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Block { block, .. } = item {
            for label in block.labels() {
                let rank = context.rank(RankKey::BlockLabel(std::ptr::from_ref(label)));
                context.push(
                    output,
                    HclMatch::BlockLabel {
                        node: context.node_ref(rank, NodeRole::HclBlockLabel),
                        label,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.block-label-equals`: exact label-text equality.
fn block_label_equals<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["label"]
        .as_string()
        .expect("validated label argument");
    for item in input {
        if let HclMatch::BlockLabel { label, .. } = &item {
            if label.text() == expected {
                context.push(output, item)?;
            }
        }
    }
    Ok(())
}

/// `hcl.block-nested-body`: the nested body of every block match (empty for
/// a one-line block or a block with no items).
fn block_nested_body<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Block { block, .. } = item {
            let body = block.body();
            let rank = context.rank(RankKey::Body(std::ptr::from_ref(body)));
            context.push(
                output,
                HclMatch::Body {
                    node: context.node_ref(rank, NodeRole::HclBody),
                    body,
                },
            )?;
        }
    }
    Ok(())
}

/// `hcl.expression-kind-is`: keeps expression matches of exactly the closed
/// kind named by the `kind` argument.
fn expression_kind_is<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let expected = HclExpressionKindName::from_name(
        operator.arguments()["kind"]
            .as_string()
            .expect("validated kind argument"),
    )
    .expect("kind name was validated before binding");
    for item in input {
        if matches!(&item, HclMatch::Expression { expression, .. } if expression.kind().name() == expected)
        {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.expression-is-literal`: keeps the literal-complete expression
/// matches, exactly as defined in RFC 0014 §8.1.
fn expression_is_literal<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(&item, HclMatch::Expression { expression, .. } if is_literal_complete(expression))
        {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.expression-text`: keeps every expression match, selecting the exact
/// source-text fact (RFC 0014 §6 double preservation).
fn expression_text<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(item, HclMatch::Expression { .. }) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `hcl.expression-children`: the ordered direct child expressions of every
/// expression match, in source order.
fn expression_children<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Expression { expression, .. } = item {
            for child in expression.children() {
                let rank = context.rank(RankKey::Expression(std::ptr::from_ref(child)));
                context.push(
                    output,
                    HclMatch::Expression {
                        node: context.node_ref(rank, NodeRole::HclExpression),
                        expression: child,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.template-parts`: the ordered literal/interpolation/directive parts
/// of every template expression match; non-template expressions contribute
/// nothing.
fn template_parts<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Expression { expression, .. } = item {
            let HclExpressionKind::Template { parts, .. } = expression.kind() else {
                continue;
            };
            for part in parts.iter() {
                let rank = context.rank(RankKey::TemplatePart(std::ptr::from_ref(part)));
                context.push(
                    output,
                    HclMatch::TemplatePart {
                        node: context.node_ref(rank, NodeRole::HclTemplatePart),
                        part,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.tuple-elements`: the ordered element expressions of every tuple
/// constructor match; non-tuple expressions contribute nothing.
fn tuple_elements<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Expression { expression, .. } = item {
            let HclExpressionKind::Tuple { elements } = expression.kind() else {
                continue;
            };
            for element in elements.iter() {
                let rank = context.rank(RankKey::Expression(std::ptr::from_ref(element)));
                context.push(
                    output,
                    HclMatch::Expression {
                        node: context.node_ref(rank, NodeRole::HclExpression),
                        expression: element,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.object-entries`: the ordered entry values of every object
/// constructor match; non-object expressions contribute nothing. The keys
/// remain source facts of the object expression; the entry values are the
/// queryable constructor content (RFC 0014 §7.1).
fn object_entries<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let HclMatch::Expression { expression, .. } = item {
            let HclExpressionKind::Object { entries } = expression.kind() else {
                continue;
            };
            for entry in entries.iter() {
                let value = entry.value();
                let rank = context.rank(RankKey::Expression(std::ptr::from_ref(value)));
                context.push(
                    output,
                    HclMatch::Expression {
                        node: context.node_ref(rank, NodeRole::HclExpression),
                        expression: value,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `hcl.error-regions`: the document's recovered error regions, a
/// document-level fact set emitted once from any non-empty input (RFC 0014
/// §3, §7).
fn error_regions<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    if input.is_empty() {
        return Ok(());
    }
    for (position, region) in context.document.error_regions().iter().enumerate() {
        let index = context.tree_nodes + position;
        context.push(
            output,
            HclMatch::ErrorRegion {
                node: context.node_ref(index, NodeRole::HclErrorRegion),
                region,
                position,
            },
        )?;
    }
    Ok(())
}

/// `core.take`: the first `count` input items.
fn take<'a>(
    operator: &OperatorCall,
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let count = operator.arguments()["count"]
        .as_integer()
        .and_then(BigInteger::to_usize)
        .expect("validated take count");
    for item in input.into_iter().take(count) {
        context.push(output, item)?;
    }
    Ok(())
}

/// `core.distinct-by-identity`: first occurrence of every identity.
fn distinct_by_identity<'a>(
    input: Vec<HclMatch<'a>>,
    context: &mut NativeContext<'a, '_>,
    output: &mut Vec<HclMatch<'a>>,
) -> Result<(), QueryFailure> {
    let mut seen = HashSet::new();
    for item in input {
        if seen.insert(item.identity()) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<HclSyntaxMatch>,
    context: &mut SyntaxContext<'_>,
) -> Result<Vec<HclSyntaxMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "hcl.syntax-kind-is" => {
            let expected = HclSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name was validated before binding");
            for item in input.into_iter().filter(|item| item.kind == expected) {
                context.push(&mut output, item)?;
            }
        }
        "hcl.syntax-text-equals" => {
            let expected = operator.arguments()["text"]
                .as_string()
                .expect("validated text argument");
            for item in input {
                if decoded_span_text(context.document, item.span) == expected {
                    context.push(&mut output, item)?;
                }
            }
        }
        "core.take" => {
            let count = operator.arguments()["count"]
                .as_integer()
                .and_then(BigInteger::to_usize)
                .expect("validated take count");
            for item in input.into_iter().take(count) {
                context.push(&mut output, item)?;
            }
        }
        "core.distinct-by-identity" => {
            let mut seen = HashSet::new();
            for item in input {
                if seen.insert(item.node) {
                    context.push(&mut output, item)?;
                }
            }
        }
        _ => unreachable!("validated hcl syntax operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// Exact decoded text of one raw span, resolved through the source's decoded
/// text; HCL is UTF-8 only, so the decoded text is always present (RFC 0014
/// §2).
fn decoded_span_text(document: &Document, span: Span) -> String {
    let source = document.source();
    let Some(decoded) = source.decoded_text() else {
        return String::new();
    };
    let start = source.decoded_position(span.start_byte());
    let end = source.decoded_position(span.end_byte());
    match (start, end) {
        (Ok(start), Ok(end)) => decoded[start.decoded_utf8_byte..end.decoded_utf8_byte].to_owned(),
        _ => String::from_utf8_lossy(&source.bytes()[span.start_byte()..span.end_byte()])
            .into_owned(),
    }
}

/// Pre-order document ranks of every native tree node, first visit winning;
/// the tree is acyclic, so the walk always terminates. Returns the rank map
/// and the total tree-node count (the base of the error-region identity
/// space).
fn preorder_ranks(document: &HclDocument) -> (HashMap<RankKey, usize>, usize) {
    let mut ranks = HashMap::new();
    let mut next = 0usize;
    visit_body(document.body(), &mut ranks, &mut next);
    (ranks, next)
}

fn visit_body(body: &HclBody, ranks: &mut HashMap<RankKey, usize>, next: &mut usize) {
    ranks.insert(RankKey::Body(std::ptr::from_ref(body)), *next);
    *next += 1;
    for item in body.items() {
        match item {
            HclBodyItem::Attribute(attribute) => {
                ranks.insert(RankKey::Attribute(std::ptr::from_ref(attribute)), *next);
                *next += 1;
                visit_expression(attribute.expression(), ranks, next);
            }
            HclBodyItem::Block(block) => {
                ranks.insert(RankKey::Block(std::ptr::from_ref(block)), *next);
                *next += 1;
                for label in block.labels() {
                    ranks.insert(RankKey::BlockLabel(std::ptr::from_ref(label)), *next);
                    *next += 1;
                }
                visit_body(block.body(), ranks, next);
            }
        }
    }
}

/// Ranks one expression and its subtree in source order: for a template, the
/// ordered parts with their interpolation/directive expressions; for every
/// other kind, the ordered direct children.
fn visit_expression(
    expression: &HclExpression,
    ranks: &mut HashMap<RankKey, usize>,
    next: &mut usize,
) {
    ranks.insert(RankKey::Expression(std::ptr::from_ref(expression)), *next);
    *next += 1;
    if let HclExpressionKind::Template { parts, .. } = expression.kind() {
        for part in parts.iter() {
            ranks.insert(RankKey::TemplatePart(std::ptr::from_ref(part)), *next);
            *next += 1;
            match part {
                HclTemplatePart::Interpolation { expression, .. } => {
                    visit_expression(expression, ranks, next);
                }
                HclTemplatePart::Directive { kind, .. } => match kind {
                    HclDirectiveKind::If { condition } => {
                        visit_expression(condition, ranks, next);
                    }
                    HclDirectiveKind::For { intro } => {
                        visit_expression(intro.collection(), ranks, next);
                    }
                    HclDirectiveKind::Else | HclDirectiveKind::EndIf | HclDirectiveKind::EndFor => {
                    }
                },
                HclTemplatePart::Literal { .. } => {}
            }
        }
    } else {
        for child in expression.children() {
            visit_expression(child, ranks, next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HclParseLimits, HclProfile};
    use consema_core::{
        CapabilityId, CapabilitySet, PortableValue, QueryDefinition, QueryDomain,
        QueryTerminalState,
    };
    use std::sync::Arc;

    fn parse(source: &[u8], profile: HclProfile) -> Document {
        Document::parse(
            Arc::<[u8]>::from(source),
            profile,
            HclParseLimits::default(),
        )
        .expect("formation of a valid UTF-8 source")
    }

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn native_executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::hcl_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn syntax_executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::hcl_lossless_syntax_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn run(expression: QueryExpression, document: &Document) -> Vec<HclMatch<'_>> {
        execute_hcl_native_query(
            &native_executable(expression),
            document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("query executes")
        .matches()
        .to_vec()
    }

    fn attribute_names(matches: &[HclMatch<'_>]) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::Attribute { attribute, .. } => attribute.name().to_owned(),
                _ => panic!("attribute match expected"),
            })
            .collect()
    }

    fn block_types(matches: &[HclMatch<'_>]) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::Block { block, .. } => block.block_type().to_owned(),
                _ => panic!("block match expected"),
            })
            .collect()
    }

    fn label_texts(matches: &[HclMatch<'_>]) -> Vec<(String, bool)> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::BlockLabel { label, .. } => (label.text().to_owned(), label.quoted()),
                _ => panic!("label match expected"),
            })
            .collect()
    }

    fn expression_texts(matches: &[HclMatch<'_>], document: &Document) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::Expression { expression, .. } => expression
                    .text(document.source())
                    .expect("decoded")
                    .to_owned(),
                _ => panic!("expression match expected"),
            })
            .collect()
    }

    fn expression_kinds(matches: &[HclMatch<'_>]) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::Expression { expression, .. } => expression.kind().as_str().to_owned(),
                _ => panic!("expression match expected"),
            })
            .collect()
    }

    fn literal_values(matches: &[HclMatch<'_>]) -> Vec<HclLiteralValue> {
        matches
            .iter()
            .map(|item| match item {
                HclMatch::Expression { expression, .. } => {
                    literal_value(expression).expect("literal-complete expression")
                }
                HclMatch::Attribute { attribute, .. } => literal_value(attribute.expression())
                    .expect("literal-complete attribute expression"),
                _ => panic!("literal-capable match expected"),
            })
            .collect()
    }

    #[test]
    fn document_body_emits_the_root_body_once() {
        let document = parse(b"a = 1\nb {\n  c = 2\n}\n", HclProfile::NativeV1);
        let matches = run(
            QueryExpression::Input.then(OperatorCall::new("hcl.document-body", 1)),
            &document,
        );
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0], HclMatch::Body { .. }));
        // The document body is a document-level fact: it is emitted once from
        // any non-empty input, including a chain through the nested body.
        let back_to_root = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-blocks", 1))
            .then(OperatorCall::new("hcl.block-nested-body", 1))
            .then(OperatorCall::new("hcl.document-body", 1));
        let matches = run(back_to_root, &document);
        assert_eq!(matches.len(), 1);
        let HclMatch::Body { body, .. } = &matches[0] else {
            panic!("body match");
        };
        assert_eq!(body.items().len(), 2, "the root body owns both items");
    }

    #[test]
    fn body_walk_filters_and_renders_the_vector_chain() {
        // The `hcl.query.native-body-walk` conformance vector chain (RFC
        // 0014 §14).
        let document = parse(
            b"region = \"us-east-1\"\nserver \"web\" {\n  port = 8080\n}\ncount = 3\n",
            HclProfile::NativeV1,
        );
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("count")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.expression-is-literal", 1))
            .then(
                OperatorCall::new("hcl.expression-kind-is", 1)
                    .with_argument("kind", PortableValue::string("number")),
            )
            .then(OperatorCall::new("hcl.expression-text", 1));
        let matches = run(chain, &document);
        assert_eq!(matches.len(), 1);
        assert_eq!(expression_kinds(&matches), vec!["number"]);
        assert_eq!(expression_texts(&matches, &document), vec!["3"]);
        let HclMatch::Expression { expression, .. } = &matches[0] else {
            panic!("expression match");
        };
        assert!(is_literal_complete(expression));
    }

    #[test]
    fn body_attributes_and_blocks_preserve_source_order() {
        let document = parse(
            b"region = \"us-east-1\"\nserver \"web\" {\n  port = 8080\n}\ncount = 3\n",
            HclProfile::NativeV1,
        );
        let attributes = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-attributes", 1)),
            &document,
        );
        assert_eq!(attribute_names(&attributes), vec!["region", "count"]);
        let blocks = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-blocks", 1)),
            &document,
        );
        assert_eq!(block_types(&blocks), vec!["server"]);
    }

    #[test]
    fn body_items_mix_attributes_and_blocks_in_source_order() {
        let document = parse(b"a = 1\nb \"x\" {\n}\nc = 2\n", HclProfile::NativeV1);
        let items = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-items", 1)),
            &document,
        );
        assert_eq!(items.len(), 3);
        let kinds: Vec<&str> = items
            .iter()
            .map(|item| match item {
                HclMatch::Attribute { .. } => "attribute",
                HclMatch::Block { .. } => "block",
                _ => panic!("body item match expected"),
            })
            .collect();
        assert_eq!(kinds, vec!["attribute", "block", "attribute"]);
        // A body-item chain into an attribute filter drops the block matches
        // (the plist value-operator union pattern).
        let filtered = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-items", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("c")),
            );
        assert_eq!(attribute_names(&run(filtered, &document)), vec!["c"]);
    }

    #[test]
    fn body_block_type_equals_filters_from_a_body() {
        let document = parse(
            b"a = 1\nserver \"web\" {\n}\ncount = 3\n",
            HclProfile::NativeV1,
        );
        let blocks = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(
                    OperatorCall::new("hcl.body-block-type-equals", 1)
                        .with_argument("type", PortableValue::string("server")),
                ),
            &document,
        );
        assert_eq!(block_types(&blocks), vec!["server"]);
    }

    #[test]
    fn attribute_name_and_block_type_select_facts() {
        let document = parse(b"a = 1\nb \"x\" {\n}\n", HclProfile::NativeV1);
        let names = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-items", 1))
                .then(OperatorCall::new("hcl.attribute-name", 1)),
            &document,
        );
        assert_eq!(attribute_names(&names), vec!["a"]);
        let types = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-items", 1))
                .then(OperatorCall::new("hcl.block-type", 1)),
            &document,
        );
        assert_eq!(block_types(&types), vec!["b"]);
    }

    #[test]
    fn attribute_name_equals_is_exact() {
        let document = parse(b"a = 1\nb = 2\n", HclProfile::NativeV1);
        let matches = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-attributes", 1))
                .then(
                    OperatorCall::new("hcl.attribute-name-equals", 1)
                        .with_argument("name", PortableValue::string("b")),
                ),
            &document,
        );
        assert_eq!(attribute_names(&matches), vec!["b"]);
    }

    #[test]
    fn blocks_and_labels_chain_matches_the_vector() {
        // The first sample of `hcl.query.blocks-and-labels` (RFC 0014 §14).
        let document = parse(
            b"region = \"us-east-1\"\nserver \"web\" {\n  port = 8080\n}\ncount = 3\n",
            HclProfile::NativeV1,
        );
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-blocks", 1))
            .then(
                OperatorCall::new("hcl.block-type-equals", 1)
                    .with_argument("type", PortableValue::string("server")),
            )
            .then(OperatorCall::new("hcl.block-labels", 1))
            .then(
                OperatorCall::new("hcl.block-label-equals", 1)
                    .with_argument("label", PortableValue::string("web")),
            );
        let matches = run(chain, &document);
        assert_eq!(label_texts(&matches), vec![("web".to_owned(), true)]);
    }

    #[test]
    fn block_nested_body_chain_matches_the_vector() {
        // The second sample of `hcl.query.blocks-and-labels` (RFC 0014 §14).
        let document = parse(
            b"region = \"us-east-1\"\nserver \"web\" {\n  port = 8080\n}\ncount = 3\n",
            HclProfile::NativeV1,
        );
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-blocks", 1))
            .then(
                OperatorCall::new("hcl.block-type-equals", 1)
                    .with_argument("type", PortableValue::string("server")),
            )
            .then(OperatorCall::new("hcl.block-nested-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("port")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.expression-text", 1));
        let matches = run(chain, &document);
        assert_eq!(expression_kinds(&matches), vec!["number"]);
        assert_eq!(expression_texts(&matches, &document), vec!["8080"]);
    }

    #[test]
    fn literal_accessors_return_typed_values() {
        // The completed samples of `hcl.query.literal-accessors` (RFC 0014
        // §14).
        let integer = parse(b"count = 42\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("count")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(
                OperatorCall::new("hcl.attribute-literal-value", 1)
                    .with_argument("accessor", PortableValue::string("as-integer")),
            );
        let matches = run(chain, &integer);
        assert_eq!(
            literal_values(&matches),
            vec![HclLiteralValue::Integer("42".to_owned())]
        );

        let boolean = parse(b"enabled = true\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("enabled")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(
                OperatorCall::new("hcl.attribute-literal-value", 1)
                    .with_argument("accessor", PortableValue::string("as-boolean-is")),
            );
        let matches = run(chain, &boolean);
        assert_eq!(
            literal_values(&matches),
            vec![HclLiteralValue::Boolean(true)]
        );
    }

    #[test]
    fn literal_accessor_type_mismatch_is_a_query_failure() {
        let document = parse(b"name = \"x\"\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("name")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(
                OperatorCall::new("hcl.attribute-literal-value", 1)
                    .with_argument("accessor", PortableValue::string("as-integer")),
            );
        let error = execute_hcl_native_query(
            &native_executable(chain),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("a string is not an integer");
        // The conformance layer maps this to `hcl.query.type-mismatch@1`.
        assert_eq!(
            error,
            QueryFailure::RequiredTypeMismatch {
                expected: PortableValueKind::Integer,
                actual: PortableValueKind::String,
            }
        );
    }

    #[test]
    fn literal_accessor_non_literal_expression_is_a_query_failure() {
        let document = parse(b"name = var.name\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("name")),
            )
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(
                OperatorCall::new("hcl.attribute-literal-value", 1)
                    .with_argument("accessor", PortableValue::string("as-string")),
            );
        let error = execute_hcl_native_query(
            &native_executable(chain),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("a traversal is not literal-complete");
        // The conformance layer maps this to `hcl.query.non-literal@1`; it is
        // never a null, empty, or converted result.
        assert_eq!(error, QueryFailure::TargetUnavailable);
    }

    #[test]
    fn literal_accessor_accepts_the_owning_attribute_directly() {
        let document = parse(b"count = 42\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(
                OperatorCall::new("hcl.attribute-name-equals", 1)
                    .with_argument("name", PortableValue::string("count")),
            )
            .then(
                OperatorCall::new("hcl.attribute-literal-value", 1)
                    .with_argument("accessor", PortableValue::string("as-integer")),
            );
        let matches = run(chain, &document);
        assert_eq!(attribute_names(&matches), vec!["count"]);
        assert_eq!(
            literal_values(&matches),
            vec![HclLiteralValue::Integer("42".to_owned())]
        );
    }

    #[test]
    fn expression_is_literal_filters_by_literal_completeness() {
        let document = parse(
            b"a = 1\nb = var.x\nc = [1, true]\nd = foo(1)\n",
            HclProfile::NativeV1,
        );
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.expression-is-literal", 1));
        let matches = run(chain, &document);
        // `a` (number), `c` (tuple of literals) survive; `b` (traversal) and
        // `d` (call) are derived.
        assert_eq!(
            expression_texts(&matches, &document),
            vec!["1", "[1, true]"]
        );
    }

    #[test]
    fn expression_kind_is_filters_by_closed_kind() {
        let document = parse(b"a = 1\nb = \"x\"\nc = foo(1)\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(
                OperatorCall::new("hcl.expression-kind-is", 1)
                    .with_argument("kind", PortableValue::string("template")),
            );
        let matches = run(chain, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["\"x\""]);
    }

    #[test]
    fn expression_children_navigate_in_source_order() {
        let document = parse(b"a = 1 + 2 * 3\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.expression-children", 1));
        let matches = run(chain.clone(), &document);
        // The binary tree is left-leaning: `1 + (2 * 3)`.
        assert_eq!(expression_texts(&matches, &document), vec!["1", "2 * 3"]);
        let grandchildren = chain.then(OperatorCall::new("hcl.expression-children", 1));
        let matches = run(grandchildren, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["2", "3"]);
    }

    #[test]
    fn template_parts_and_constructor_navigation() {
        let document = parse(
            b"m = \"hi ${name}!\"\nt = [1, 2]\no = { a = 1, b = 2 }\n",
            HclProfile::NativeV1,
        );
        let parts = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.template-parts", 1));
        let matches = run(parts, &document);
        assert_eq!(matches.len(), 3);
        let part_kinds: Vec<&str> = matches
            .iter()
            .map(|item| match item {
                HclMatch::TemplatePart { part, .. } => match part {
                    HclTemplatePart::Literal { .. } => "literal",
                    HclTemplatePart::Interpolation { .. } => "interpolation",
                    HclTemplatePart::Directive { .. } => "directive",
                },
                _ => panic!("template part match expected"),
            })
            .collect();
        assert_eq!(part_kinds, vec!["literal", "interpolation", "literal"]);

        let tuple_chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.tuple-elements", 1));
        let matches = run(tuple_chain, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["1", "2"]);

        let object_chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1))
            .then(OperatorCall::new("hcl.object-entries", 1));
        let matches = run(object_chain, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["1", "2"]);
    }

    #[test]
    fn error_regions_expose_recovered_regions() {
        // An unclosed block is parser recovery: one error region with
        // `hcl.parse.block@1` (RFC 0014 §3).
        let document = parse(b"a = 1\nb {\n", HclProfile::NativeV1);
        assert_eq!(
            document.status(),
            consema_document::FormationStatus::Recovered
        );
        assert_eq!(document.error_regions().len(), 1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.error-regions", 1));
        let matches = run(chain, &document);
        assert_eq!(matches.len(), 1);
        let HclMatch::ErrorRegion {
            region, position, ..
        } = &matches[0]
        else {
            panic!("error region match");
        };
        assert_eq!(region.code(), "hcl.parse.block@1");
        assert_eq!(*position, 0);
    }

    #[test]
    fn structure_order_merge_orders_branches_by_document_position() {
        let document = parse(b"b \"x\" {\n  e = 2\n}\na = 1\n", HclProfile::NativeV1);
        // Both branches output expression matches; the merge orders them by
        // pre-order document rank, so the block-nested `2` precedes the
        // trailing `1` in source order.
        let outer_attributes = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1));
        let nested_attributes = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-blocks", 1))
            .then(OperatorCall::new("hcl.block-nested-body", 1))
            .then(OperatorCall::new("hcl.body-attributes", 1))
            .then(OperatorCall::new("hcl.attribute-expression", 1));
        let merge = QueryExpression::StructureOrderMerge(vec![
            outer_attributes.clone(),
            nested_attributes.clone(),
        ]);
        let matches = run(merge, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["2", "1"]);

        let concat = QueryExpression::Concat(vec![outer_attributes, nested_attributes]);
        let matches = run(concat, &document);
        assert_eq!(expression_texts(&matches, &document), vec!["1", "2"]);
    }

    #[test]
    fn distinct_by_identity_keeps_first_occurrences() {
        let document = parse(b"b \"x\" {\n}\n", HclProfile::NativeV1);
        let chain = QueryExpression::Input
            .then(OperatorCall::new("hcl.document-body", 1))
            .then(OperatorCall::new("hcl.body-blocks", 1))
            .then(OperatorCall::new("hcl.block-labels", 1))
            .then(
                OperatorCall::new("core.take", 1)
                    .with_argument("count", PortableValue::integer(2.into())),
            )
            .then(OperatorCall::new("core.distinct-by-identity", 1));
        let matches = run(chain, &document);
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0], HclMatch::BlockLabel { .. }));
    }

    #[test]
    fn syntax_kind_filter_selects_pieces() {
        let document = parse(b"# c\nregion = \"us-east-1\"\n", HclProfile::NativeV1);
        let comments = QueryExpression::Input.then(
            OperatorCall::new("hcl.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("LineComment")),
        );
        let result = execute_hcl_syntax_query(
            &syntax_executable(comments),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        let piece = result.matches()[0];
        assert_eq!(piece.kind(), HclSyntaxKind::LineComment);
        assert_eq!(decoded_span_text(&document, piece.span()), "# c");
        // The ordinal is the piece's position in the ordered piece stream.
        let kinds = document.lossless_syntax_kinds();
        assert_eq!(
            kinds
                .iter()
                .position(|kind| *kind == HclSyntaxKind::LineComment),
            Some(piece.ordinal())
        );

        let content = QueryExpression::Input.then(
            OperatorCall::new("hcl.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("StringContent")),
        );
        let result = execute_hcl_syntax_query(
            &syntax_executable(content),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        assert_eq!(
            decoded_span_text(&document, result.matches()[0].span()),
            "us-east-1"
        );
    }

    #[test]
    fn syntax_text_equals_matches_decoded_text() {
        let document = parse(b"# c\nregion = \"us-east-1\"\n", HclProfile::NativeV1);
        let text = QueryExpression::Input.then(
            OperatorCall::new("hcl.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("us-east-1")),
        );
        let result = execute_hcl_syntax_query(
            &syntax_executable(text),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].kind(), HclSyntaxKind::StringContent);
    }

    #[test]
    fn syntax_pieces_are_source_ordered_with_ordinals() {
        let document = parse(b"# c\nregion = \"us-east-1\"\n", HclProfile::NativeV1);
        let result = execute_hcl_syntax_query(
            &syntax_executable(QueryExpression::Input),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        let pieces = document.lossless_structural_index().pieces().len();
        assert_eq!(result.matches().len(), pieces);
        let ordinals: Vec<usize> = result.matches().iter().map(|item| item.ordinal()).collect();
        let mut expected = ordinals.clone();
        expected.sort_unstable();
        assert_eq!(ordinals, expected, "ordinals are source ordered");
        assert_eq!(ordinals[0], 0);
        assert_eq!(result.matches()[0].kind(), HclSyntaxKind::LineComment);
    }

    #[test]
    fn syntax_take_limits_the_result() {
        let document = parse(b"# c\nregion = \"us-east-1\"\n", HclProfile::NativeV1);
        let take = QueryExpression::Input.then(
            OperatorCall::new("core.take", 1)
                .with_argument("count", PortableValue::integer(2.into())),
        );
        let result = execute_hcl_syntax_query(
            &syntax_executable(take),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 2);
        assert_eq!(result.matches()[0].ordinal(), 0);
    }

    #[test]
    fn foreign_domain_is_rejected() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let foreign = QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1));
        let executable = QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(foreign)
            .validate()
            .expect("valid ini query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_hcl_native_query(
                &executable,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::DomainMismatch(_))
        ));
    }

    #[test]
    fn each_executor_guards_its_own_domain() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let native = native_executable(QueryExpression::Input);
        let syntax = syntax_executable(QueryExpression::Input);
        // The syntax domain is foreign to the native executor and vice
        // versa.
        assert!(matches!(
            execute_hcl_native_query(
                &syntax,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::DomainMismatch(_))
        ));
        assert!(matches!(
            execute_hcl_syntax_query(
                &native,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::DomainMismatch(_))
        ));
    }

    #[test]
    fn tfvars_documents_query_through_the_shared_native_domain() {
        // Both profiles share the one native model and the one syntax
        // system, so both domains serve a tfvars document unchanged.
        let document = parse(b"region = \"us-east-1\"\ncount = 3\n", HclProfile::TfvarsV1);
        let attributes = run(
            QueryExpression::Input
                .then(OperatorCall::new("hcl.document-body", 1))
                .then(OperatorCall::new("hcl.body-attributes", 1)),
            &document,
        );
        assert_eq!(attribute_names(&attributes), vec!["region", "count"]);
        let result = execute_hcl_syntax_query(
            &syntax_executable(QueryExpression::Input),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(
            result.matches().len(),
            document.lossless_structural_index().pieces().len()
        );
    }

    #[test]
    fn cancellation_fails_before_results() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let token = CancellationToken::new();
        token.cancel();
        let error = execute_hcl_native_query(
            &native_executable(
                QueryExpression::Input.then(OperatorCall::new("hcl.document-body", 1)),
            ),
            &document,
            QueryLimits::default(),
            &token,
        )
        .expect_err("cancelled");
        assert_eq!(error, QueryFailure::Cancelled);
        let error = execute_hcl_syntax_query(
            &syntax_executable(QueryExpression::Input),
            &document,
            QueryLimits::default(),
            &token,
        )
        .expect_err("cancelled");
        assert_eq!(error, QueryFailure::Cancelled);
    }

    #[test]
    fn result_limit_is_fatal() {
        let document = parse(b"a = 1\nb = 2\nc = 3\n", HclProfile::NativeV1);
        let limits = QueryLimits {
            max_results: 2,
            ..QueryLimits::default()
        };
        let error = execute_hcl_native_query(
            &native_executable(
                QueryExpression::Input
                    .then(OperatorCall::new("hcl.document-body", 1))
                    .then(OperatorCall::new("hcl.body-attributes", 1)),
            ),
            &document,
            limits,
            &CancellationToken::new(),
        )
        .expect_err("result limit");
        assert_eq!(error, QueryFailure::ResourceLimitExceeded);
    }

    #[test]
    fn require_one_cardinality_is_enforced() {
        let document = parse(b"a = 1\nb = 2\n", HclProfile::NativeV1);
        let definition = QueryDefinition::new(QueryDomain::hcl_native_v1())
            .with_expression(
                QueryExpression::Input
                    .then(OperatorCall::new("hcl.document-body", 1))
                    .then(OperatorCall::new("hcl.body-attributes", 1)),
            )
            .with_selection(QuerySelection::RequireOne)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_hcl_native_query(
                &definition,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::CardinalityViolation { .. })
        ));
    }

    #[test]
    fn cursor_terminates_with_cancelled_when_token_is_cancelled() {
        let document = parse(b"a = 1\nb = 2\nc = 3\n", HclProfile::NativeV1);
        let cancellation = CancellationToken::new();
        let mut cursor = execute_hcl_native_query_cursor(
            &native_executable(
                QueryExpression::Input
                    .then(OperatorCall::new("hcl.document-body", 1))
                    .then(OperatorCall::new("hcl.body-attributes", 1)),
            ),
            &document,
            QueryLimits::default(),
            &cancellation,
        )
        .expect("cursor");
        assert!(cursor.next().is_some());
        assert_eq!(cursor.terminal_state(), None);
        cancellation.cancel();
        assert!(cursor.next().is_none());
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Cancelled));
    }
}
