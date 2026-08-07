//! Plist three-domain query execution (RFC 0013 §8).
//!
//! The three query domains share the immutable-snapshot, ordered-selection,
//! limits, cancellation, and terminal-state rules of the common query
//! contract and differ only in what they see:
//!
//! - `plist.native-semantic-query@1` (RFC 0013 §8.1) queries the
//!   representation-independent native value arena of both profiles. Results
//!   preserve source order: dictionary associations keep their physical
//!   order and duplicate occurrences, arrays keep element order, and
//!   `plist.duplicate-key-group@1` expands an association to every same-key
//!   association in source order. `plist.dict-key-equals@1` matches exact
//!   Unicode string keys and never folds case. The typed accessors validate
//!   the value type before returning; a type mismatch is a query failure,
//!   not a null or converted result (RFC 0013 §8.1).
//!
//! - `plist.lossless-syntax-query@1` (RFC 0013 §8.2) filters the ordered
//!   lossless pieces of a `plist.xml@1` source by their closed
//!   [`PlistSyntaxKind`] set and by decoded text; every non-empty raw byte
//!   belongs to exactly one ordered structural piece. The domain exists only
//!   for the XML representation: a binary document has no text, whitespace,
//!   or token fiction (RFC 0013 §7, hard gate 1).
//!
//! - `plist.binary-structure-query@1` (RFC 0013 §8.3) exposes the binary
//!   structure directly: object-table, offset-table, reference, and trailer
//!   facts with exact byte spans, without inventing text trivia. The domain
//!   exists only for the `plist.binary@1` representation (hard gate 1). The
//!   structure facts are document-level: every operator projects the same
//!   fact set once from any binary-structure input match, so chains of
//!   structure operators validate and execute without duplicating facts.
//!
//! Domain/operator/role/profile validation occurs before the first result
//! (RFC 0013 §8.3): a definition validated for another domain is rejected
//! with `DomainMismatch`, and a domain applied to a document of the wrong
//! representation is rejected the same way. A `Recovered` document remains
//! queryable over its proven parts (RFC 0013 §3).
//!
//! The whole public API is consumed by the M9 conformance runner
//! (`consema-conformance::plist_v1`) and re-exported by the M10 facade;
//! `lib.rs` does not re-export the query module yet, so the reachable
//! surface is `#[cfg(test)]`-only until then.
use crate::document::Document;
use crate::native::{PlistDocument, PlistKey, PlistValue, PlistValueKind, PlistValueRef};
use crate::parser_binary::BinaryFacts;
use crate::parser_xml::PlistSyntaxKind;
use consema_core::{
    BigInteger, CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor,
    PortableValueKind, QueryExecution, QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::HashSet;

/// Owned snapshot-bound plist native semantic query match (RFC 0013 §8.1).
///
/// Every match carries a snapshot-bound handle; value matches reference the
/// arena of the queried document, so shared identity from the binary object
/// table survives querying: one native node referenced by several containers
/// is one match identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlistMatch {
    /// Complete plist document; the native-domain root input.
    Document {
        /// Document identity.
        node: NodeRef,
    },
    /// One native value node of any of the nine closed kinds.
    Value {
        /// Value identity.
        node: NodeRef,
        /// Arena reference within the queried document.
        value: PlistValueRef,
        /// Closed native kind.
        kind: PlistValueKind,
    },
    /// One dictionary key/value association.
    DictEntry {
        /// Association identity.
        node: NodeRef,
        /// Owning dictionary arena reference.
        dict: PlistValueRef,
        /// Association position within the dictionary, in source order.
        position: usize,
        /// Exact string key identity of this physical occurrence.
        key: PlistKey,
        /// Associated value arena reference.
        value: PlistValueRef,
        /// Closed native kind of the associated value.
        value_kind: PlistValueKind,
    },
    /// One string key identity of one dictionary association.
    Key {
        /// Key identity.
        node: NodeRef,
        /// Owning dictionary arena reference.
        dict: PlistValueRef,
        /// Association position within the dictionary, in source order.
        position: usize,
        /// Exact key string.
        key: PlistKey,
    },
    /// One array element association.
    ArrayElement {
        /// Element identity.
        node: NodeRef,
        /// Owning array arena reference.
        array: PlistValueRef,
        /// Element position within the array, in source order.
        position: usize,
        /// Element value arena reference.
        value: PlistValueRef,
        /// Closed native kind of the element value.
        value_kind: PlistValueKind,
    },
}

impl PlistMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Document { node }
            | Self::Value { node, .. }
            | Self::DictEntry { node, .. }
            | Self::Key { node, .. }
            | Self::ArrayElement { node, .. } => *node,
        }
    }
}

/// Owned snapshot-bound plist XML lossless syntax query match (RFC 0013
/// §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlistSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: PlistSyntaxKind,
    ordinal: usize,
}

impl PlistSyntaxMatch {
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

    /// Format-specific lossless kind.
    #[must_use]
    pub const fn kind(self) -> PlistSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Owned snapshot-bound plist binary structure query match (RFC 0013 §8.3).
///
/// The binary structure facts are document-level: `Structure` is the domain
/// root, and every structure operator projects its fact set once from any
/// binary-structure match, so chains of structure operators never duplicate
/// facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlistBinaryMatch {
    /// Complete binary structure; the binary-structure-domain root input.
    Structure {
        /// Document identity.
        node: NodeRef,
    },
    /// One proven object-table entry fact.
    Object {
        /// Object identity.
        node: NodeRef,
        /// Object-table ordinal.
        index: usize,
        /// Marker byte offset (equals the offset-table entry value).
        offset: usize,
        /// Marker byte; the low nibble preserves non-minimal width facts.
        marker: u8,
        /// Exact marker-through-payload byte range.
        span: Span,
    },
    /// One validated offset-table entry fact.
    Offset {
        /// Entry identity.
        node: NodeRef,
        /// Object-table ordinal of this entry.
        index: usize,
        /// Decoded absolute file offset of the object's marker byte.
        offset: usize,
        /// Exact byte range of this entry inside the offset table.
        span: Span,
    },
    /// One decoded object reference of a proven container.
    Ref {
        /// Reference identity.
        node: NodeRef,
        /// Ordinal of this reference in the ordered reference fact list.
        index: usize,
        /// Referencing object index.
        owner: usize,
        /// Ordinal of this reference within the owner's reference block.
        position: usize,
        /// Decoded target object index.
        target: usize,
        /// Exact byte range of this reference inside the owner's payload.
        span: Span,
    },
    /// Trailer field facts of the complete 32-byte trailer.
    Trailer {
        /// Trailer identity.
        node: NodeRef,
        /// `sortVersion` byte (0 or 1; canonical materialization writes 0).
        sort_version: u8,
        /// `offsetIntSize` byte.
        offset_int_size: u8,
        /// `objectRefSize` byte.
        object_ref_size: u8,
        /// `numObjects` value.
        num_objects: u64,
        /// `topObject` value (the native document root when proven).
        top_object: u64,
        /// `offsetTableOffset` value.
        offset_table_offset: u64,
        /// Exact byte range of the 32-byte trailer.
        span: Span,
    },
    /// The trailer's top object with its ordered reference facts.
    TopObject {
        /// Top-object identity.
        node: NodeRef,
        /// Object-table ordinal of the top object.
        index: usize,
        /// Marker byte offset.
        offset: usize,
        /// Marker byte.
        marker: u8,
        /// Exact marker-through-payload byte range.
        span: Span,
        /// Ordered references of the top object as `(position, target,
        /// span)` triples.
        refs: Vec<(usize, usize, Span)>,
    },
}

impl PlistBinaryMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Structure { node }
            | Self::Object { node, .. }
            | Self::Offset { node, .. }
            | Self::Ref { node, .. }
            | Self::Trailer { node, .. }
            | Self::TopObject { node, .. } => *node,
        }
    }
}

/// Executes a validated plist native semantic query against one immutable
/// snapshot (RFC 0013 §8.1).
///
/// The native domain serves both representations; only the domain identity is
/// guarded here.
pub fn execute_plist_native_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<PlistMatch>, QueryFailure> {
    if executable.definition().domain().id() != "plist.native-semantic-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let native = document.document();
    let ranks = native.map(preorder_ranks).unwrap_or_default();
    let mut context = NativeContext {
        document,
        native,
        limits,
        cancellation,
        steps: 0,
        ranks,
    };
    context.step(1)?;
    let input = vec![PlistMatch::Document {
        node: document.authority().node_ref(0, NodeRole::PlistDocument),
    }];
    let matches =
        execute_native_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes the complete plist native result through an ordered
/// cursor.
pub fn execute_plist_native_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<PlistMatch>, QueryFailure> {
    let result = execute_plist_native_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated plist lossless syntax query in raw source order
/// (RFC 0013 §8.2).
///
/// The domain exists only for the `plist.xml@1` representation; a binary
/// document is rejected with `DomainMismatch` before the first result
/// (hard gate 1).
pub fn execute_plist_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<PlistSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "plist.lossless-syntax-query"
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
    let (pieces, kinds) = document
        .lossless_structural_index()
        .zip(document.lossless_syntax_kinds())
        .ok_or_else(|| QueryFailure::DomainMismatch(executable.definition().domain().clone()))?;
    let pieces = pieces.pieces();
    context.step(pieces.len())?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(pieces.len())
        .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
    for (ordinal, (piece, kind)) in pieces.iter().zip(kinds).enumerate() {
        let identity = u64::try_from(ordinal).map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        input.push(PlistSyntaxMatch {
            node: document
                .authority()
                .node_ref(identity, NodeRole::PlistSyntaxPiece),
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

/// Executes a plist lossless syntax query and exposes its complete result as
/// a cancellable cursor.
pub fn execute_plist_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<PlistSyntaxMatch>, QueryFailure> {
    let result = execute_plist_syntax_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated plist binary structure query (RFC 0013 §8.3).
///
/// The domain exists only for the `plist.binary@1` representation; an XML
/// document is rejected with `DomainMismatch` before the first result (hard
/// gate 1). The structure facts are document-level: every operator projects
/// its fact set once from any binary-structure input match.
pub fn execute_plist_binary_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<PlistBinaryMatch>, QueryFailure> {
    if executable.definition().domain().id() != "plist.binary-structure-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let facts = document
        .binary_facts()
        .ok_or_else(|| QueryFailure::DomainMismatch(executable.definition().domain().clone()))?;
    let mut context = BinaryContext {
        document,
        facts,
        limits,
        cancellation,
        steps: 0,
    };
    context.step(1)?;
    let input = vec![PlistBinaryMatch::Structure {
        node: document.authority().node_ref(0, NodeRole::PlistDocument),
    }];
    let matches =
        execute_binary_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes a plist binary structure query and exposes its complete result
/// as a cancellable cursor.
pub fn execute_plist_binary_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<PlistBinaryMatch>, QueryFailure> {
    let result = execute_plist_binary_query(executable, document, limits, cancellation)?;
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

/// Native-domain execution state: the document, its native arena when
/// provable, and the common accounting state.
struct NativeContext<'a> {
    document: &'a Document,
    native: Option<&'a PlistDocument>,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
    /// Pre-order document rank of every arena node, computed once per
    /// execution for structure-order merging.
    ranks: Vec<usize>,
}

impl NativeContext<'_> {
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
            u64::try_from(index).expect("parse limits keep arena in u64"),
            role,
        )
    }

    fn rank(&self, index: usize) -> usize {
        self.ranks.get(index).copied().unwrap_or(usize::MAX)
    }

    /// Deterministic structure-order key: the document rank of the owning
    /// node, with association position as the tiebreak.
    fn source_order(&self, item: &PlistMatch) -> (usize, usize) {
        match item {
            PlistMatch::Document { .. } => (0, 0),
            PlistMatch::Value { value, .. } => (self.rank(value.index()), 0),
            PlistMatch::DictEntry { dict, position, .. }
            | PlistMatch::Key { dict, position, .. } => (self.rank(dict.index()), position + 1),
            PlistMatch::ArrayElement {
                array, position, ..
            } => (self.rank(array.index()), position + 1),
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

/// Binary-structure-domain execution state.
struct BinaryContext<'a> {
    document: &'a Document,
    facts: &'a BinaryFacts,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
}

impl BinaryContext<'_> {
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

    /// Flat identity ordinal shared by the fact arrays, so every fact kind
    /// has a distinct identity space.
    fn object_node(&self, index: usize) -> NodeRef {
        self.fact_node(index)
    }

    fn offset_node(&self, index: usize) -> NodeRef {
        self.fact_node(self.facts.objects().len() + index)
    }

    fn ref_node(&self, index: usize) -> NodeRef {
        self.fact_node(self.facts.objects().len() + self.facts.offsets().len() + index)
    }

    fn trailer_node(&self) -> NodeRef {
        self.fact_node(
            self.facts.objects().len() + self.facts.offsets().len() + self.facts.refs().len(),
        )
    }

    fn top_object_node(&self) -> NodeRef {
        self.fact_node(
            self.facts.objects().len() + self.facts.offsets().len() + self.facts.refs().len() + 1,
        )
    }

    fn fact_node(&self, index: usize) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(index).expect("parse limits keep facts in u64"),
            NodeRole::BinaryRegion,
        )
    }

    /// Deterministic structure-order key over the flat fact identity space.
    fn source_order(&self, item: &PlistBinaryMatch) -> usize {
        let objects = self.facts.objects().len();
        let offsets = self.facts.offsets().len();
        let refs = self.facts.refs().len();
        match item {
            PlistBinaryMatch::Structure { .. } => 0,
            PlistBinaryMatch::Object { index, .. } => 1 + *index,
            PlistBinaryMatch::Offset { index, .. } => 1 + objects + *index,
            PlistBinaryMatch::Ref { index, .. } => 1 + objects + offsets + *index,
            PlistBinaryMatch::Trailer { .. } => 1 + objects + offsets + refs,
            PlistBinaryMatch::TopObject { .. } => 1 + objects + offsets + refs + 1,
        }
    }
}

fn execute_native_expression(
    expression: &QueryExpression,
    input: &[PlistMatch],
    context: &mut NativeContext<'_>,
) -> Result<Vec<PlistMatch>, QueryFailure> {
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
    input: &[PlistSyntaxMatch],
    context: &mut SyntaxContext<'_>,
) -> Result<Vec<PlistSyntaxMatch>, QueryFailure> {
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

fn execute_binary_expression(
    expression: &QueryExpression,
    input: &[PlistBinaryMatch],
    context: &mut BinaryContext<'_>,
) -> Result<Vec<PlistBinaryMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let input = execute_binary_expression(expression_input, input, context)?;
            apply_binary_operator(operator, input, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_binary_expression(branch, input, context)?;
                context.append(&mut output, values)?;
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_binary_expression(branch, input, context)?;
                context.append(&mut output, values)?;
            }
            output.sort_by_key(|item| context.source_order(item));
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn apply_native_operator(
    operator: &OperatorCall,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
) -> Result<Vec<PlistMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "plist.document-root" => document_root(input, context, &mut output)?,
        "plist.dict-entries" => dict_entries(input, context, &mut output)?,
        "plist.dict-entry-key" => dict_entry_key(input, context, &mut output)?,
        "plist.dict-entry-value" => dict_entry_value(input, context, &mut output)?,
        "plist.dict-key-equals" => dict_key_equals(operator, input, context, &mut output)?,
        "plist.duplicate-key-group" => duplicate_key_group(input, context, &mut output)?,
        "plist.array-elements" => array_elements(input, context, &mut output)?,
        "plist.value-type-is" => value_type_is(operator, input, context, &mut output)?,
        "plist.value-as-integer" => {
            value_as_typed(PlistValueKind::Integer, input, context, &mut output)?;
        }
        "plist.value-as-real" => {
            value_as_typed(PlistValueKind::Real, input, context, &mut output)?;
        }
        "plist.value-as-string" => {
            value_as_typed(PlistValueKind::String, input, context, &mut output)?;
        }
        "plist.value-as-data" => {
            value_as_typed(PlistValueKind::Data, input, context, &mut output)?;
        }
        "plist.value-as-date" => {
            value_as_typed(PlistValueKind::Date, input, context, &mut output)?;
        }
        "plist.value-as-uid" => {
            value_as_typed(PlistValueKind::Uid, input, context, &mut output)?;
        }
        "plist.value-as-boolean-is" => value_as_boolean_is(operator, input, context, &mut output)?,
        "core.take" => take(operator, input, context, &mut output)?,
        "core.distinct-by-identity" => distinct_by_identity(input, context, &mut output)?,
        _ => unreachable!("validated plist native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// `plist.document-root`: the root value, when formation proved it.
fn document_root(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        if matches!(item, PlistMatch::Document { .. }) {
            let root = native.root();
            let kind = native.get(root).expect("root resolves").kind();
            context.push(
                output,
                PlistMatch::Value {
                    node: context.node_ref(root.index(), NodeRole::PlistValue),
                    value: root,
                    kind,
                },
            )?;
        }
    }
    Ok(())
}

/// `plist.dict-entries`: the ordered associations of every dictionary value
/// match; non-dictionary values contribute nothing.
fn dict_entries(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        if let PlistMatch::Value { value, .. } = item {
            let Some(dict) = native.get(value).and_then(PlistValue::as_dict) else {
                continue;
            };
            for (position, entry) in dict.entries().iter().enumerate() {
                context.push(output, entry_match(context, value, position, entry))?;
            }
        }
    }
    Ok(())
}

/// `plist.dict-entry-key`: the string key identity of every entry match.
fn dict_entry_key(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let PlistMatch::DictEntry {
            dict,
            position,
            key,
            ..
        } = item
        {
            context.push(
                output,
                PlistMatch::Key {
                    node: context.node_ref(position, NodeRole::PlistKey),
                    dict,
                    position,
                    key,
                },
            )?;
        }
    }
    Ok(())
}

/// `plist.dict-entry-value`: the associated value of every entry match.
fn dict_entry_value(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        if let PlistMatch::DictEntry { value, .. } = item {
            let kind = native.get(value).expect("arena reference resolves").kind();
            context.push(
                output,
                PlistMatch::Value {
                    node: context.node_ref(value.index(), NodeRole::PlistValue),
                    value,
                    kind,
                },
            )?;
        }
    }
    Ok(())
}

/// `plist.dict-key-equals`: exact Unicode key equality; case is never
/// folded, and the comparison is over the exact UTF-16 code units.
fn dict_key_equals(
    operator: &OperatorCall,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["key"]
        .as_string()
        .expect("validated key argument");
    let expected_units: Vec<u16> = expected.encode_utf16().collect();
    for item in input {
        if matches!(&item, PlistMatch::DictEntry { key, .. } if key.code_units() == expected_units)
        {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `plist.duplicate-key-group`: expands one entry match to every same-key
/// association of its dictionary, in source order.
fn duplicate_key_group(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        if let PlistMatch::DictEntry { dict, key, .. } = &item {
            let Some(dict_value) = native.get(*dict).and_then(PlistValue::as_dict) else {
                continue;
            };
            for (position, entry) in dict_value.entries().iter().enumerate() {
                if entry.key() == key {
                    context.push(output, entry_match(context, *dict, position, entry))?;
                }
            }
        }
    }
    Ok(())
}

/// `plist.array-elements`: the ordered element associations of every array
/// value match; non-array values contribute nothing.
fn array_elements(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        if let PlistMatch::Value { value, .. } = item {
            let Some(array) = native.get(value).and_then(PlistValue::as_array) else {
                continue;
            };
            for (position, element) in array.elements().iter().enumerate() {
                let kind = native
                    .get(*element)
                    .expect("arena reference resolves")
                    .kind();
                context.push(
                    output,
                    PlistMatch::ArrayElement {
                        node: context.node_ref(position, NodeRole::PlistArrayElement),
                        array: value,
                        position,
                        value: *element,
                        value_kind: kind,
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// `plist.value-type-is`: keeps value-bearing matches of exactly the closed
/// kind named by the `kind` argument.
fn value_type_is(
    operator: &OperatorCall,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let expected = plist_kind_from_name(
        operator.arguments()["kind"]
            .as_string()
            .expect("validated kind argument"),
    )
    .expect("kind name was validated before binding");
    for item in input {
        if let Some((_, kind)) = value_payload(&item) {
            if kind == expected {
                context.push(output, item)?;
            }
        }
    }
    Ok(())
}

/// The typed accessors: the value type is validated before the match is
/// returned; a mismatch is a query failure, never a null or converted
/// result (RFC 0013 §8.1).
fn value_as_typed(
    target: PlistValueKind,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        let Some((_, kind)) = value_payload(&item) else {
            continue;
        };
        if kind != target {
            return Err(QueryFailure::RequiredTypeMismatch {
                expected: portable_kind(target),
                actual: portable_kind(kind),
            });
        }
        context.push(output, item)?;
    }
    Ok(())
}

/// `plist.value-as-boolean-is`: validates that every value-bearing match is
/// a boolean (a mismatch is a query failure), then keeps only the matches
/// equal to the `value` argument.
fn value_as_boolean_is(
    operator: &OperatorCall,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["value"]
        .as_boolean()
        .expect("validated boolean argument");
    let Some(native) = context.native else {
        return Ok(());
    };
    for item in input {
        let Some((value, kind)) = value_payload(&item) else {
            continue;
        };
        if kind != PlistValueKind::Boolean {
            return Err(QueryFailure::RequiredTypeMismatch {
                expected: PortableValueKind::Boolean,
                actual: portable_kind(kind),
            });
        }
        let observed = native
            .get(value)
            .and_then(PlistValue::as_boolean)
            .expect("boolean arena node")
            .value();
        if observed == expected {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// Value payload of one value-bearing match: a plain value or an array
/// element association.
fn value_payload(item: &PlistMatch) -> Option<(PlistValueRef, PlistValueKind)> {
    match item {
        PlistMatch::Value { value, kind, .. } => Some((*value, *kind)),
        PlistMatch::ArrayElement {
            value, value_kind, ..
        } => Some((*value, *value_kind)),
        _ => None,
    }
}

/// `core.take`: the first `count` input items.
fn take(
    operator: &OperatorCall,
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
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
fn distinct_by_identity(
    input: Vec<PlistMatch>,
    context: &mut NativeContext<'_>,
    output: &mut Vec<PlistMatch>,
) -> Result<(), QueryFailure> {
    let mut seen = HashSet::new();
    for item in input {
        if seen.insert(item.identity()) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// One dictionary association match in its owning dictionary.
fn entry_match(
    context: &NativeContext<'_>,
    dict: PlistValueRef,
    position: usize,
    entry: &crate::native::PlistDictEntry,
) -> PlistMatch {
    let kind = context
        .native
        .expect("native arena present")
        .get(entry.value())
        .expect("arena reference resolves")
        .kind();
    PlistMatch::DictEntry {
        node: context.node_ref(position, NodeRole::PlistDictEntry),
        dict,
        position,
        key: entry.key().clone(),
        value: entry.value(),
        value_kind: kind,
    }
}

/// Resolves the frozen closed kind name of `plist.value-type-is@1`.
fn plist_kind_from_name(name: &str) -> Option<PlistValueKind> {
    Some(match name {
        "dict" => PlistValueKind::Dict,
        "array" => PlistValueKind::Array,
        "string" => PlistValueKind::String,
        "integer" => PlistValueKind::Integer,
        "real" => PlistValueKind::Real,
        "boolean" => PlistValueKind::Boolean,
        "date" => PlistValueKind::Date,
        "data" => PlistValueKind::Data,
        "uid" => PlistValueKind::Uid,
        _ => return None,
    })
}

/// Maps one plist kind onto the closest portable value kind for mismatch
/// payloads. `PortableValueKind` has no UID variant; a UID maps to
/// `Integer`, and the plist conformance layer reports the plist-native kind
/// names.
fn portable_kind(kind: PlistValueKind) -> PortableValueKind {
    match kind {
        PlistValueKind::Dict => PortableValueKind::Object,
        PlistValueKind::Array => PortableValueKind::Sequence,
        PlistValueKind::String => PortableValueKind::String,
        PlistValueKind::Integer | PlistValueKind::Uid => PortableValueKind::Integer,
        PlistValueKind::Real => PortableValueKind::BinaryFloat64,
        PlistValueKind::Boolean => PortableValueKind::Boolean,
        PlistValueKind::Date => PortableValueKind::Date,
        PlistValueKind::Data => PortableValueKind::Bytes,
    }
}

/// Pre-order document ranks of the arena, first visit winning for shared
/// nodes; the arena is acyclic, so the traversal always terminates.
fn preorder_ranks(native: &PlistDocument) -> Vec<usize> {
    let node_count = native.node_count();
    let mut ranks = vec![usize::MAX; node_count];
    let mut visited = vec![false; node_count];
    let mut next = 0_usize;
    let mut stack = vec![native.root()];
    while let Some(node) = stack.pop() {
        if visited[node.index()] {
            continue;
        }
        visited[node.index()] = true;
        ranks[node.index()] = next;
        next += 1;
        match native.get(node) {
            Some(PlistValue::Dict(dict)) => {
                for entry in dict.entries().iter().rev() {
                    stack.push(entry.value());
                }
            }
            Some(PlistValue::Array(array)) => {
                for element in array.elements().iter().rev() {
                    stack.push(*element);
                }
            }
            _ => {}
        }
    }
    ranks
}

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<PlistSyntaxMatch>,
    context: &mut SyntaxContext<'_>,
) -> Result<Vec<PlistSyntaxMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "plist.syntax-kind-is" => {
            let expected = PlistSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name was validated before binding");
            for item in input.into_iter().filter(|item| item.kind == expected) {
                context.push(&mut output, item)?;
            }
        }
        "plist.syntax-text-equals" => {
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
        _ => unreachable!("validated plist syntax operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// Exact decoded text of one raw span, resolved through the source's decoded
/// text so that UTF-8, UTF-16LE, and UTF-16BE sources all decode correctly
/// (RFC 0013 §2.1).
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

fn apply_binary_operator(
    operator: &OperatorCall,
    input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
) -> Result<Vec<PlistBinaryMatch>, QueryFailure> {
    let mut output = Vec::new();
    // The binary structure facts are document-level (RFC 0013 §8.3): every
    // operator projects its fact set once, regardless of how many
    // binary-structure matches arrive, so chained structure operators never
    // duplicate facts.
    if input.is_empty() {
        return Ok(output);
    }
    match operator.id() {
        "plist.object-table" | "plist.top-object" => {
            object_table(operator.id(), input, context, &mut output)?;
        }
        "plist.object-offset" | "plist.offset-table" => {
            offset_table(input, context, &mut output)?;
        }
        "plist.object-refs" => object_refs(input, context, &mut output)?,
        "plist.trailer-facts" => trailer_facts(input, context, &mut output)?,
        "core.take" => take_binary(operator, input, context, &mut output)?,
        "core.distinct-by-identity" => distinct_binary(input, context, &mut output)?,
        _ => unreachable!("validated plist binary structure operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// `plist.object-table` / `plist.top-object`: the object facts, or only the
/// trailer's top object with its ordered references.
fn object_table(
    id: &str,
    _input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    if id == "plist.top-object" {
        return top_object(context, output);
    }
    for (index, fact) in context.facts.objects().iter().enumerate() {
        context.push(
            output,
            PlistBinaryMatch::Object {
                node: context.object_node(index),
                index: fact.index(),
                offset: fact.offset(),
                marker: fact.marker(),
                span: fact.span(),
            },
        )?;
    }
    Ok(())
}

/// `plist.top-object`: the trailer's top object with its ordered reference
/// facts; nothing when the top object is not a proven object fact.
fn top_object(
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    let top = context.facts.trailer().top_object();
    let top_index = usize::try_from(top).expect("trailer top object is in u64 range");
    let Some(fact) = context
        .facts
        .objects()
        .iter()
        .find(|fact| fact.index() == top_index)
    else {
        return Ok(());
    };
    let refs = context
        .facts
        .refs()
        .iter()
        .filter(|reference| reference.owner() == top_index)
        .map(|reference| (reference.position(), reference.target(), reference.span()))
        .collect();
    context.push(
        output,
        PlistBinaryMatch::TopObject {
            node: context.top_object_node(),
            index: fact.index(),
            offset: fact.offset(),
            marker: fact.marker(),
            span: fact.span(),
            refs,
        },
    )?;
    Ok(())
}

/// `plist.object-offset` / `plist.offset-table`: the validated offset-table
/// entry facts.
fn offset_table(
    _input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    for (index, fact) in context.facts.offsets().iter().enumerate() {
        context.push(
            output,
            PlistBinaryMatch::Offset {
                node: context.offset_node(index),
                index: fact.index(),
                offset: fact.offset(),
                span: fact.span(),
            },
        )?;
    }
    Ok(())
}

/// `plist.object-refs`: the ordered decoded reference facts of every proven
/// container, ordered by owner then position.
fn object_refs(
    _input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    for (index, fact) in context.facts.refs().iter().enumerate() {
        context.push(
            output,
            PlistBinaryMatch::Ref {
                node: context.ref_node(index),
                index,
                owner: fact.owner(),
                position: fact.position(),
                target: fact.target(),
                span: fact.span(),
            },
        )?;
    }
    Ok(())
}

/// `plist.trailer-facts`: the trailer field facts.
fn trailer_facts(
    _input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    let trailer = context.facts.trailer();
    context.push(
        output,
        PlistBinaryMatch::Trailer {
            node: context.trailer_node(),
            sort_version: trailer.sort_version(),
            offset_int_size: trailer.offset_int_size(),
            object_ref_size: trailer.object_ref_size(),
            num_objects: trailer.num_objects(),
            top_object: trailer.top_object(),
            offset_table_offset: trailer.offset_table_offset(),
            span: trailer.span(),
        },
    )?;
    Ok(())
}

/// `core.take`: the first `count` input items.
fn take_binary(
    operator: &OperatorCall,
    input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
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
fn distinct_binary(
    input: Vec<PlistBinaryMatch>,
    context: &mut BinaryContext<'_>,
    output: &mut Vec<PlistBinaryMatch>,
) -> Result<(), QueryFailure> {
    let mut seen = HashSet::new();
    for item in input {
        if seen.insert(item.identity()) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlistEncodingSelection, PlistParseLimits, PlistProfile};
    use consema_core::{
        CapabilityId, CapabilitySet, PortableValue, QueryDefinition, QueryDomain,
        QueryTerminalState,
    };
    use std::sync::Arc;

    /// Appends a big-endian value of `width` bytes.
    fn push_be(output: &mut Vec<u8>, value: u64, width: usize) {
        for shift in (0..width).rev() {
            output.push(((value >> (8 * shift)) & 0xFF) as u8);
        }
    }

    /// Hand-built `bplist00` fixture writer: header, objects, offset table,
    /// trailer.
    struct TestBinaryBuilder {
        bytes: Vec<u8>,
        offsets: Vec<u64>,
        offset_int_size: usize,
        ref_size: usize,
    }

    impl TestBinaryBuilder {
        fn new(offset_int_size: usize, ref_size: usize) -> Self {
            Self {
                bytes: b"bplist00".to_vec(),
                offsets: Vec::new(),
                offset_int_size,
                ref_size,
            }
        }

        fn object(&mut self, object: &[u8]) -> u64 {
            let offset = u64::try_from(self.bytes.len()).unwrap();
            self.offsets.push(offset);
            self.bytes.extend_from_slice(object);
            offset
        }

        fn finish(mut self, top_object: u64) -> Vec<u8> {
            let offset_table_offset = u64::try_from(self.bytes.len()).unwrap();
            for offset in &self.offsets {
                push_be(&mut self.bytes, *offset, self.offset_int_size);
            }
            self.bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            self.bytes.push(0); // sortVersion
            self.bytes.push(self.offset_int_size as u8);
            self.bytes.push(self.ref_size as u8);
            push_be(
                &mut self.bytes,
                u64::try_from(self.offsets.len()).unwrap(),
                8,
            );
            push_be(&mut self.bytes, top_object, 8);
            push_be(&mut self.bytes, offset_table_offset, 8);
            self.bytes
        }
    }

    /// Reference bytes of the given width.
    #[allow(dead_code)]
    fn reference(object_index: usize, ref_size: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_be(&mut bytes, u64::try_from(object_index).unwrap(), ref_size);
        bytes
    }

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::plist_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn syntax_executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::plist_lossless_syntax_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn binary_executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::plist_binary_structure_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn parse_xml(source: &[u8]) -> Document {
        Document::parse(
            Arc::from(source),
            PlistProfile::XmlV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("xml plist forms")
    }

    fn parse_binary(bytes: Vec<u8>) -> Document {
        Document::parse(
            Arc::from(bytes),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("binary plist forms")
    }

    /// The `plist.query.binary-structure` conformance vector source
    /// (RFC 0013 §14): 3 objects — a one-entry dict referencing the string
    /// `"a"` and the integer `1` — with 1-byte offsets and refs.
    const VECTOR_HEX: &str = "62706c6973743030d1010251611001080b0d000000000000010100000000000000030000000000000000000000000000000f";

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex ascii"), 16)
                    .expect("hex digit")
            })
            .collect()
    }

    fn binary_vector() -> Document {
        parse_binary(decode_hex(VECTOR_HEX))
    }

    fn run(expression: QueryExpression, document: &Document) -> Vec<PlistMatch> {
        execute_plist_native_query(
            &executable(expression),
            document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("query executes")
        .matches()
        .to_vec()
    }

    fn entry_keys(matches: &[PlistMatch]) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                PlistMatch::DictEntry { key, .. } => key.to_unicode().expect("well-formed key"),
                _ => panic!("entry match expected"),
            })
            .collect()
    }

    fn entry_value_kinds(matches: &[PlistMatch]) -> Vec<PlistValueKind> {
        matches
            .iter()
            .map(|item| match item {
                PlistMatch::DictEntry { value_kind, .. } => *value_kind,
                _ => panic!("entry match expected"),
            })
            .collect()
    }

    fn value_kinds(matches: &[PlistMatch]) -> Vec<PlistValueKind> {
        matches
            .iter()
            .map(|item| match item {
                PlistMatch::Value { kind, .. } => *kind,
                _ => panic!("value match expected"),
            })
            .collect()
    }

    fn binary_object_markers(matches: &[PlistBinaryMatch]) -> Vec<String> {
        matches
            .iter()
            .map(|item| match item {
                PlistBinaryMatch::Object { marker, .. } => format!("{marker:02x}"),
                _ => panic!("object match expected"),
            })
            .collect()
    }

    #[test]
    fn document_root_emits_the_root_value() {
        let document = parse_xml(b"<plist version=\"1.0\"><string>x</string></plist>");
        let matches = run(
            QueryExpression::Input.then(OperatorCall::new("plist.document-root", 1)),
            &document,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(value_kinds(&matches), vec![PlistValueKind::String]);
    }

    #[test]
    fn dict_entries_preserve_source_order_and_duplicates() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>b</key><array><string>x</string></array><key>a</key><integer>2</integer></dict></plist>",
        );
        let entries = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1));
        let matches = run(entries, &document);
        assert_eq!(entry_keys(&matches), vec!["a", "b", "a"]);
        assert_eq!(
            entry_value_kinds(&matches),
            vec![
                PlistValueKind::Integer,
                PlistValueKind::Array,
                PlistValueKind::Integer
            ]
        );
        // Positions are physical association ordinals.
        let positions: Vec<usize> = matches
            .iter()
            .map(|item| match item {
                PlistMatch::DictEntry { position, .. } => *position,
                _ => panic!("entry match"),
            })
            .collect();
        assert_eq!(positions, vec![0, 1, 2]);
    }

    #[test]
    fn dict_key_equals_is_exact_and_case_sensitive() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>A</key><integer>2</integer><key>ab</key><integer>3</integer></dict></plist>",
        );
        let by_a = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(
                OperatorCall::new("plist.dict-key-equals", 1)
                    .with_argument("key", PortableValue::string("a")),
            );
        let matches = run(by_a, &document);
        assert_eq!(entry_keys(&matches), vec!["a"]);
    }

    #[test]
    fn dict_entry_value_navigates_to_associated_values() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>n</key><integer>42</integer><key>s</key><string>x</string></dict></plist>",
        );
        let values = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(OperatorCall::new("plist.dict-entry-value", 1));
        let matches = run(values, &document);
        assert_eq!(
            value_kinds(&matches),
            vec![PlistValueKind::Integer, PlistValueKind::String]
        );
    }

    #[test]
    fn dict_entry_key_emits_key_matches() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>k</key><string>v</string></dict></plist>",
        );
        let keys = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(OperatorCall::new("plist.dict-entry-key", 1));
        let matches = run(keys, &document);
        assert_eq!(matches.len(), 1);
        let PlistMatch::Key { key, position, .. } = &matches[0] else {
            panic!("key match");
        };
        assert_eq!(key.to_unicode().expect("well-formed"), "k");
        assert_eq!(*position, 0);
    }

    #[test]
    fn duplicate_key_group_expands_every_same_key_association() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>b</key><integer>2</integer><key>a</key><integer>3</integer></dict></plist>",
        );
        let group = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(
                OperatorCall::new("plist.dict-key-equals", 1)
                    .with_argument("key", PortableValue::string("a")),
            )
            .then(
                OperatorCall::new("core.take", 1)
                    .with_argument("count", PortableValue::integer(1.into())),
            )
            .then(OperatorCall::new("plist.duplicate-key-group", 1));
        let matches = run(group, &document);
        assert_eq!(entry_keys(&matches), vec!["a", "a"]);
        let positions: Vec<usize> = matches
            .iter()
            .map(|item| match item {
                PlistMatch::DictEntry { position, .. } => *position,
                _ => panic!("entry match"),
            })
            .collect();
        assert_eq!(positions, vec![0, 2], "source order is preserved");
    }

    #[test]
    fn array_elements_preserve_element_order() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><array><integer>1</integer><string>x</string><true/></array></plist>",
        );
        let elements = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1));
        let matches = run(elements, &document);
        let kinds: Vec<PlistValueKind> = matches
            .iter()
            .map(|item| match item {
                PlistMatch::ArrayElement { value_kind, .. } => *value_kind,
                _ => panic!("array element match"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                PlistValueKind::Integer,
                PlistValueKind::String,
                PlistValueKind::Boolean
            ]
        );
    }

    #[test]
    fn value_type_is_filters_by_closed_kind() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>i</key><integer>1</integer><key>s</key><string>x</string><key>d</key><date>2023-01-01T00:00:00Z</date></dict></plist>",
        );
        let integers = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(OperatorCall::new("plist.dict-entry-value", 1))
            .then(
                OperatorCall::new("plist.value-type-is", 1)
                    .with_argument("kind", PortableValue::string("integer")),
            );
        let matches = run(integers, &document);
        assert_eq!(value_kinds(&matches), vec![PlistValueKind::Integer]);
    }

    #[test]
    fn typed_accessors_validate_before_returning() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>count</key><integer>42</integer><key>created</key><date>2023-01-01T00:00:00Z</date><key>name</key><string>x</string></dict></plist>",
        );
        let integer_chain = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(
                OperatorCall::new("plist.dict-key-equals", 1)
                    .with_argument("key", PortableValue::string("count")),
            )
            .then(OperatorCall::new("plist.dict-entry-value", 1))
            .then(
                OperatorCall::new("plist.value-type-is", 1)
                    .with_argument("kind", PortableValue::string("integer")),
            )
            .then(OperatorCall::new("plist.value-as-integer", 1));
        let matches = run(integer_chain, &document);
        assert_eq!(value_kinds(&matches), vec![PlistValueKind::Integer]);

        let date_chain = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(
                OperatorCall::new("plist.dict-key-equals", 1)
                    .with_argument("key", PortableValue::string("created")),
            )
            .then(OperatorCall::new("plist.dict-entry-value", 1))
            .then(OperatorCall::new("plist.value-as-date", 1));
        let matches = run(date_chain, &document);
        assert_eq!(value_kinds(&matches), vec![PlistValueKind::Date]);

        // A type mismatch is a query failure, never a null or converted
        // result (RFC 0013 §8.1).
        let string_chain = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(
                OperatorCall::new("plist.dict-key-equals", 1)
                    .with_argument("key", PortableValue::string("count")),
            )
            .then(OperatorCall::new("plist.dict-entry-value", 1))
            .then(OperatorCall::new("plist.value-as-string", 1));
        let error = execute_plist_native_query(
            &executable(string_chain),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("integer is not a string");
        assert_eq!(
            error,
            QueryFailure::RequiredTypeMismatch {
                expected: PortableValueKind::String,
                actual: PortableValueKind::Integer,
            }
        );
    }

    #[test]
    fn value_as_boolean_is_validates_and_filters() {
        let document =
            parse_xml(b"<plist version=\"1.0\"><array><true/><false/><true/></array></plist>");
        let trues = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1))
            .then(
                OperatorCall::new("plist.value-as-boolean-is", 1)
                    .with_argument("value", PortableValue::boolean(true)),
            );
        let matches = run(trues, &document);
        assert_eq!(matches.len(), 2);

        let falses = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1))
            .then(
                OperatorCall::new("plist.value-as-boolean-is", 1)
                    .with_argument("value", PortableValue::boolean(false)),
            );
        let matches = run(falses, &document);
        assert_eq!(matches.len(), 1);

        let mismatch = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1))
            .then(
                OperatorCall::new("plist.value-as-boolean-is", 1)
                    .with_argument("value", PortableValue::boolean(true)),
            );
        let document =
            parse_xml(b"<plist version=\"1.0\"><array><integer>1</integer></array></plist>");
        let error = execute_plist_native_query(
            &executable(mismatch),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("integer is not a boolean");
        assert_eq!(
            error,
            QueryFailure::RequiredTypeMismatch {
                expected: PortableValueKind::Boolean,
                actual: PortableValueKind::Integer,
            }
        );
    }

    #[test]
    fn nested_dicts_navigate_through_entry_values() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>outer</key><dict><key>inner</key><string>deep</string></dict></dict></plist>",
        );
        let inner_entries = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.dict-entries", 1))
            .then(OperatorCall::new("plist.dict-entry-value", 1))
            .then(OperatorCall::new("plist.dict-entries", 1));
        let matches = run(inner_entries, &document);
        assert_eq!(entry_keys(&matches), vec!["inner"]);
    }

    #[test]
    fn recovered_without_native_document_yields_no_root() {
        let document = parse_xml(b"<plist version=\"1.0\"><date>BAD</date></plist>");
        assert!(document.document().is_none());
        let matches = run(
            QueryExpression::Input.then(OperatorCall::new("plist.document-root", 1)),
            &document,
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn syntax_kind_filter_selects_pieces() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>k</key><string>hi</string></dict></plist>",
        );
        let opens = QueryExpression::Input.then(
            OperatorCall::new("plist.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("plist-open")),
        );
        let result = execute_plist_syntax_query(
            &syntax_executable(opens),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 2);

        let keys = QueryExpression::Input.then(
            OperatorCall::new("plist.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("key-open")),
        );
        let result = execute_plist_syntax_query(
            &syntax_executable(keys),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 2);
        assert!(
            result
                .matches()
                .iter()
                .all(|item| item.kind() == PlistSyntaxKind::KeyOpen)
        );
    }

    #[test]
    fn syntax_text_equals_matches_decoded_text() {
        let document =
            parse_xml(b"<plist version=\"1.0\"><string>hi</string><string>bye</string></plist>");
        let text = QueryExpression::Input.then(
            OperatorCall::new("plist.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("hi")),
        );
        let result = execute_plist_syntax_query(
            &syntax_executable(text),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].kind(), PlistSyntaxKind::Text);
    }

    #[test]
    fn syntax_pieces_are_source_ordered_with_ordinals() {
        let document = parse_xml(b"<plist version=\"1.0\"><true/></plist>");
        let result = execute_plist_syntax_query(
            &syntax_executable(QueryExpression::Input),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        let pieces = document
            .lossless_structural_index()
            .expect("xml index")
            .pieces()
            .len();
        assert_eq!(result.matches().len(), pieces);
        let ordinals: Vec<usize> = result.matches().iter().map(|item| item.ordinal()).collect();
        let mut expected = ordinals.clone();
        expected.sort_unstable();
        assert_eq!(ordinals, expected, "ordinals are source ordered");
        assert_eq!(ordinals[0], 0);
        assert_eq!(result.matches()[0].kind(), PlistSyntaxKind::PlistOpen);
    }

    #[test]
    fn syntax_utf16_source_decodes_span_text() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist version=\"1.0\"><string>hi</string></plist>";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let document = Document::parse(
            Arc::from(bytes),
            PlistProfile::XmlV1,
            PlistEncodingSelection::Explicit(consema_document::SourceEncoding::Utf16Le),
            PlistParseLimits::default(),
        )
        .expect("utf-16 xml forms");
        let text_filter = QueryExpression::Input.then(
            OperatorCall::new("plist.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("hi")),
        );
        let result = execute_plist_syntax_query(
            &syntax_executable(text_filter),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].kind(), PlistSyntaxKind::Text);
    }

    #[test]
    fn syntax_domain_rejects_binary_documents() {
        let document = binary_vector();
        let expression = QueryExpression::Input;
        let error = execute_plist_syntax_query(
            &syntax_executable(expression),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("binary documents have no syntax pieces");
        assert!(matches!(error, QueryFailure::DomainMismatch(_)));
    }

    #[test]
    fn syntax_take_limits_the_result() {
        let document = parse_xml(b"<plist version=\"1.0\"><string>x</string></plist>");
        let take = QueryExpression::Input.then(
            OperatorCall::new("core.take", 1)
                .with_argument("count", PortableValue::integer(3.into())),
        );
        let result = execute_plist_syntax_query(
            &syntax_executable(take),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].ordinal(), 0);
    }

    #[test]
    fn object_table_emits_object_facts() {
        let document = binary_vector();
        let result = execute_plist_binary_query(
            &binary_executable(
                QueryExpression::Input.then(OperatorCall::new("plist.object-table", 1)),
            ),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("binary query executes");
        assert_eq!(result.matches().len(), 3);
        assert_eq!(
            binary_object_markers(result.matches()),
            vec!["d1", "51", "10"]
        );
        let offsets: Vec<usize> = result
            .matches()
            .iter()
            .map(|item| match item {
                PlistBinaryMatch::Object { offset, .. } => *offset,
                _ => panic!("object match"),
            })
            .collect();
        assert_eq!(offsets, vec![8, 11, 13]);
        let indexes: Vec<usize> = result
            .matches()
            .iter()
            .map(|item| match item {
                PlistBinaryMatch::Object { index, .. } => *index,
                _ => panic!("object match"),
            })
            .collect();
        assert_eq!(indexes, vec![0, 1, 2]);
    }

    #[test]
    fn offset_table_emits_offset_facts() {
        let document = binary_vector();
        for operator in ["plist.offset-table", "plist.object-offset"] {
            let result = execute_plist_binary_query(
                &binary_executable(QueryExpression::Input.then(OperatorCall::new(operator, 1))),
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            )
            .expect("binary query executes");
            let offsets: Vec<usize> = result
                .matches()
                .iter()
                .map(|item| match item {
                    PlistBinaryMatch::Offset { offset, .. } => *offset,
                    _ => panic!("offset match"),
                })
                .collect();
            assert_eq!(offsets, vec![8, 11, 13]);
        }
    }

    #[test]
    fn object_refs_emit_reference_facts() {
        let document = binary_vector();
        let result = execute_plist_binary_query(
            &binary_executable(
                QueryExpression::Input.then(OperatorCall::new("plist.object-refs", 1)),
            ),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("binary query executes");
        assert_eq!(result.matches().len(), 2);
        let refs: Vec<(usize, usize, usize)> = result
            .matches()
            .iter()
            .map(|item| match item {
                PlistBinaryMatch::Ref {
                    owner,
                    position,
                    target,
                    ..
                } => (*owner, *position, *target),
                _ => panic!("ref match"),
            })
            .collect();
        assert_eq!(refs, vec![(0, 0, 1), (0, 1, 2)]);
    }

    #[test]
    fn trailer_facts_emit_all_fields() {
        let document = binary_vector();
        let result = execute_plist_binary_query(
            &binary_executable(
                QueryExpression::Input.then(OperatorCall::new("plist.trailer-facts", 1)),
            ),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("binary query executes");
        assert_eq!(result.matches().len(), 1);
        let PlistBinaryMatch::Trailer {
            sort_version,
            offset_int_size,
            object_ref_size,
            num_objects,
            top_object,
            offset_table_offset,
            span,
            ..
        } = &result.matches()[0]
        else {
            panic!("trailer match");
        };
        assert_eq!(*sort_version, 0);
        assert_eq!(*offset_int_size, 1);
        assert_eq!(*object_ref_size, 1);
        assert_eq!(*num_objects, 3);
        assert_eq!(*top_object, 0);
        assert_eq!(*offset_table_offset, 15);
        assert_eq!(span.len(), 32);
    }

    #[test]
    fn top_object_emits_marker_and_refs() {
        let document = binary_vector();
        let result = execute_plist_binary_query(
            &binary_executable(
                QueryExpression::Input.then(OperatorCall::new("plist.top-object", 1)),
            ),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("binary query executes");
        assert_eq!(result.matches().len(), 1);
        let PlistBinaryMatch::TopObject {
            index,
            marker,
            refs,
            ..
        } = &result.matches()[0]
        else {
            panic!("top-object match");
        };
        assert_eq!(*index, 0);
        assert_eq!(format!("{marker:02x}"), "d1");
        let targets: Vec<usize> = refs.iter().map(|(_, target, _)| *target).collect();
        assert_eq!(targets, vec![1, 2]);
    }

    #[test]
    fn binary_operators_emit_facts_once_through_a_chain() {
        let document = binary_vector();
        let chained = QueryExpression::Input
            .then(OperatorCall::new("plist.object-table", 1))
            .then(OperatorCall::new("plist.offset-table", 1))
            .then(OperatorCall::new("plist.trailer-facts", 1))
            .then(OperatorCall::new("plist.top-object", 1));
        let result = execute_plist_binary_query(
            &binary_executable(chained),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("binary query executes");
        assert_eq!(result.matches().len(), 1);
        assert!(matches!(
            result.matches()[0],
            PlistBinaryMatch::TopObject { .. }
        ));
    }

    #[test]
    fn binary_domain_rejects_xml_documents() {
        let document = parse_xml(b"<plist version=\"1.0\"><string>x</string></plist>");
        let error = execute_plist_binary_query(
            &binary_executable(QueryExpression::Input),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect_err("xml documents have no binary structure facts");
        assert!(matches!(error, QueryFailure::DomainMismatch(_)));
    }

    #[test]
    fn shared_identity_survives_native_querying() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'x']); // 0: "x"
        file.object(&[0xA2, 0x00, 0x00]); // 1: ["x", "x"]
        let bytes = file.finish(1);
        let document = parse_binary(bytes);
        let elements = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1));
        let matches = run(elements, &document);
        assert_eq!(matches.len(), 2);
        let values: Vec<PlistValueRef> = matches
            .iter()
            .map(|item| match item {
                PlistMatch::ArrayElement { value, .. } => *value,
                _ => panic!("array element match"),
            })
            .collect();
        assert_eq!(values[0], values[1], "shared identity is preserved");

        // Association identity stays per-occurrence: the two element matches
        // are distinct associations of one shared arena node.
        let distinct = QueryExpression::Input
            .then(OperatorCall::new("plist.document-root", 1))
            .then(OperatorCall::new("plist.array-elements", 1))
            .then(OperatorCall::new("core.distinct-by-identity", 1));
        let matches = run(distinct, &document);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn foreign_domain_is_rejected() {
        let document = parse_xml(b"<plist version=\"1.0\"><string>x</string></plist>");
        let foreign = QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1));
        let executable = QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(foreign)
            .validate()
            .expect("valid ini query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_plist_native_query(
                &executable,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::DomainMismatch(_))
        ));
    }

    #[test]
    fn cancellation_fails_before_results() {
        let document = parse_xml(b"<plist version=\"1.0\"><string>x</string></plist>");
        let token = CancellationToken::new();
        token.cancel();
        let error = execute_plist_native_query(
            &executable(QueryExpression::Input.then(OperatorCall::new("plist.document-root", 1))),
            &document,
            QueryLimits::default(),
            &token,
        )
        .expect_err("cancelled");
        assert_eq!(error, QueryFailure::Cancelled);
    }

    #[test]
    fn result_limit_is_fatal() {
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>b</key><integer>2</integer></dict></plist>",
        );
        let limits = QueryLimits {
            max_results: 1,
            ..QueryLimits::default()
        };
        let error = execute_plist_native_query(
            &executable(
                QueryExpression::Input
                    .then(OperatorCall::new("plist.document-root", 1))
                    .then(OperatorCall::new("plist.dict-entries", 1)),
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
        let document = parse_xml(
            b"<plist version=\"1.0\"><array><integer>1</integer><integer>2</integer></array></plist>",
        );
        let definition = QueryDefinition::new(QueryDomain::plist_native_v1())
            .with_expression(
                QueryExpression::Input
                    .then(OperatorCall::new("plist.document-root", 1))
                    .then(OperatorCall::new("plist.array-elements", 1)),
            )
            .with_selection(QuerySelection::RequireOne)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_plist_native_query(
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
        let document = parse_xml(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>b</key><integer>2</integer><key>c</key><integer>3</integer></dict></plist>",
        );
        let cancellation = CancellationToken::new();
        let mut cursor = execute_plist_native_query_cursor(
            &executable(
                QueryExpression::Input
                    .then(OperatorCall::new("plist.document-root", 1))
                    .then(OperatorCall::new("plist.dict-entries", 1)),
            ),
            &document,
            QueryLimits::default(),
            &cancellation,
        )
        .expect("cursor");
        assert!(cursor.next().is_some());
        assert_eq!(cursor.terminal_state(), None);
        cancellation.cancel();
        assert_eq!(cursor.next(), None);
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Cancelled));
    }
}
