//! XML native and lossless syntax query execution (RFC 0012 §8).
//!
//! Native order is document order. Element attributes and namespace
//! declarations preserve their respective source orders; child content
//! preserves mixed-content order. Descendant traversal is bounded pre-order.
//! No query resolves a URI, evaluates XPath, loads a schema, or expands
//! application data.

use crate::document::{
    Document, ReferenceFragment, XmlContent, XmlDeclarationData, XmlDoctypeData, XmlElementData,
    XmlNamespaceBindingData, XmlPrologItem, XmlSyntaxKind, text_semantic,
};
use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::HashSet;

/// One XML reference occurrence kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmlReferenceKind {
    /// Decimal or hexadecimal character reference.
    Character,
    /// One of the five predefined entity references.
    Predefined,
    /// An admitted internal general entity reference.
    General,
}

/// Owned snapshot-bound XML native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XmlMatch {
    /// Complete XML document.
    Document {
        /// Document identity.
        node: NodeRef,
    },
    /// The XML declaration.
    Declaration {
        /// Declaration identity.
        node: NodeRef,
        /// Declared version.
        version: String,
        /// Declared encoding, when present.
        encoding: Option<String>,
        /// Declared standalone, when present.
        standalone: Option<bool>,
    },
    /// DOCTYPE occurrence.
    Doctype {
        /// DOCTYPE identity.
        node: NodeRef,
        /// Root-name spelling.
        name: String,
    },
    /// One prolog or epilog occurrence.
    PrologItem {
        /// Occurrence identity.
        node: NodeRef,
        /// Kind: `processing-instruction` or `comment`.
        kind: String,
    },
    /// One element occurrence.
    Element {
        /// Element identity.
        node: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Original prefix spelling, when present.
        prefix: Option<String>,
        /// Local name.
        local: String,
        /// Resolved namespace URI, when provable.
        namespace: Option<String>,
        /// Whether a namespace error kept the name unprovable.
        namespace_error: bool,
    },
    /// One attribute association.
    Attribute {
        /// Attribute identity.
        node: NodeRef,
        /// Owning element.
        element: NodeRef,
        /// Original prefix spelling, when present.
        prefix: Option<String>,
        /// Local name.
        local: String,
        /// Resolved namespace URI, when provable.
        namespace: Option<String>,
        /// CDATA-normalized semantic value.
        value: String,
    },
    /// One namespace binding association.
    NamespaceBinding {
        /// Binding identity.
        node: NodeRef,
        /// Owning element.
        element: NodeRef,
        /// Bound prefix; `None` is the default namespace.
        prefix: Option<String>,
        /// Namespace URI.
        uri: String,
    },
    /// One text occurrence.
    Text {
        /// Text identity.
        node: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Line-end-normalized semantic content.
        semantic: String,
    },
    /// One CDATA occurrence.
    Cdata {
        /// CDATA identity.
        node: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Content text.
        text: String,
    },
    /// One comment occurrence.
    Comment {
        /// Comment identity.
        node: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Content text.
        text: String,
    },
    /// One processing instruction.
    ProcessingInstruction {
        /// PI identity.
        node: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Target.
        target: String,
        /// Content, when present.
        content: Option<String>,
    },
    /// One reference occurrence inside text.
    Reference {
        /// Reference identity.
        node: NodeRef,
        /// Owning text occurrence.
        text: NodeRef,
        /// Owning element, when present.
        parent: Option<NodeRef>,
        /// Reference kind.
        kind: XmlReferenceKind,
        /// Entity or reference name.
        name: String,
        /// Fully resolved character data.
        resolved: String,
    },
    /// One recovered error region.
    ErrorRegion {
        /// Error-region identity.
        node: NodeRef,
        /// Exact recovered span.
        span: Span,
    },
}

impl XmlMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Document { node }
            | Self::Declaration { node, .. }
            | Self::Doctype { node, .. }
            | Self::PrologItem { node, .. }
            | Self::Element { node, .. }
            | Self::Attribute { node, .. }
            | Self::NamespaceBinding { node, .. }
            | Self::Text { node, .. }
            | Self::Cdata { node, .. }
            | Self::Comment { node, .. }
            | Self::ProcessingInstruction { node, .. }
            | Self::Reference { node, .. }
            | Self::ErrorRegion { node, .. } => *node,
        }
    }
}

/// Owned snapshot-bound XML lossless syntax query match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmlSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: XmlSyntaxKind,
    ordinal: usize,
}

impl XmlSyntaxMatch {
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
    pub const fn kind(self) -> XmlSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Executes a validated XML native semantic query against one immutable snapshot.
pub fn execute_xml_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<XmlMatch>, QueryFailure> {
    if executable.definition().domain().id() != "xml.native-semantic-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let mut context = Context {
        document,
        limits,
        cancellation,
        steps: 0,
    };
    context.step(1)?;
    let input = vec![XmlMatch::Document {
        node: document.node_ref(),
    }];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Applies the validated cardinality selection.
fn apply_selection(
    mut values: Vec<XmlMatch>,
    selection: QuerySelection,
) -> Result<Vec<XmlMatch>, QueryFailure> {
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

/// Executes and exposes the complete native result through an ordered cursor.
pub fn execute_xml_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<XmlMatch>, QueryFailure> {
    let result = execute_xml_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated XML lossless syntax query in raw source order.
pub fn execute_xml_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<XmlSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "xml.lossless-syntax-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let mut context = Context {
        document,
        limits,
        cancellation,
        steps: 0,
    };
    let pieces = document
        .lossless_structural_index()
        .ok_or(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ))?
        .pieces();
    context.step(pieces.len())?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(pieces.len())
        .map_err(|_| QueryFailure::ResourceLimitExceeded)?;
    for (ordinal, (piece, kind)) in pieces
        .iter()
        .zip(document.lossless_syntax_kinds())
        .enumerate()
    {
        let identity = u64::try_from(ordinal).map_err(|_| QueryFailure::ResourceLimitExceeded)?;
        input.push(XmlSyntaxMatch {
            node: document
                .authority()
                .node_ref(identity, NodeRole::XmlSyntaxPiece),
            span: piece.span(),
            kind: *kind,
            ordinal,
        });
    }
    let matches =
        execute_syntax_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_syntax_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Applies the validated cardinality selection to syntax matches.
fn apply_syntax_selection(
    mut values: Vec<XmlSyntaxMatch>,
    selection: QuerySelection,
) -> Result<Vec<XmlSyntaxMatch>, QueryFailure> {
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

/// Executes an XML syntax query and exposes its complete result as a cancellable cursor.
pub fn execute_xml_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<XmlSyntaxMatch>, QueryFailure> {
    let result = execute_xml_syntax_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

struct Context<'a> {
    document: &'a Document,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
}

impl Context<'_> {
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

    fn element_data(&self, index: usize) -> &XmlElementData {
        let XmlContent::Element(data) = &self.document.nodes()[index] else {
            unreachable!("element handle always points at element arena data")
        };
        data
    }

    fn element_match(&self, index: usize) -> XmlMatch {
        let data = self.element_data(index);
        XmlMatch::Element {
            node: self.node_ref(index, NodeRole::XmlElement),
            parent: self.parent_of(index),
            prefix: data.qname.prefix.as_deref().map(str::to_owned),
            local: data.qname.local.to_string(),
            namespace: data
                .expanded
                .as_ref()
                .and_then(|expanded| expanded.namespace.as_deref())
                .map(str::to_owned),
            namespace_error: data.namespace_error.is_some(),
        }
    }

    fn parent_of(&self, index: usize) -> Option<NodeRef> {
        self.document
            .parent_of(index)
            .map(|parent| self.node_ref(parent, NodeRole::XmlElement))
    }

    fn node_ref(&self, index: usize, role: NodeRole) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(index).expect("parse limits keep arena in u64"),
            role,
        )
    }

    fn prolog_item(&self, item: &XmlPrologItem) -> Option<XmlMatch> {
        let (node, kind) = match item {
            XmlPrologItem::ProcessingInstruction(pi) => (
                self.node_ref(
                    usize::try_from(pi.ordinal).expect("ordinal in u64"),
                    NodeRole::XmlProcessingInstruction,
                ),
                "processing-instruction".to_owned(),
            ),
            XmlPrologItem::Comment(comment) => (
                self.node_ref(
                    usize::try_from(comment.ordinal).expect("ordinal in u64"),
                    NodeRole::XmlComment,
                ),
                "comment".to_owned(),
            ),
            XmlPrologItem::Declaration(_)
            | XmlPrologItem::Doctype(_)
            | XmlPrologItem::Bom(_)
            | XmlPrologItem::Whitespace(_) => return None,
        };
        Some(XmlMatch::PrologItem { node, kind })
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[XmlMatch],
    context: &mut Context<'_>,
) -> Result<Vec<XmlMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let input = execute_expression(expression_input, input, context)?;
            apply_operator(operator, input, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_expression(branch, input, context)?;
                context.append(&mut output, values)?;
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                let values = execute_expression(branch, input, context)?;
                context.append(&mut output, values)?;
            }
            output.sort_by_key(source_order);
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn execute_syntax_expression(
    expression: &QueryExpression,
    input: &[XmlSyntaxMatch],
    context: &mut Context<'_>,
) -> Result<Vec<XmlSyntaxMatch>, QueryFailure> {
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

fn source_order(item: &XmlMatch) -> usize {
    match item {
        XmlMatch::Document { .. } => 0,
        XmlMatch::Declaration { node, .. }
        | XmlMatch::Doctype { node, .. }
        | XmlMatch::PrologItem { node, .. }
        | XmlMatch::Element { node, .. }
        | XmlMatch::Attribute { node, .. }
        | XmlMatch::NamespaceBinding { node, .. }
        | XmlMatch::Text { node, .. }
        | XmlMatch::Cdata { node, .. }
        | XmlMatch::Comment { node, .. }
        | XmlMatch::ProcessingInstruction { node, .. }
        | XmlMatch::Reference { node, .. } => {
            // Ordinals are assigned in parse order, which is document order
            // for content; elements use their arena index.
            usize::try_from(node.index()).unwrap_or(usize::MAX)
        }
        XmlMatch::ErrorRegion { span, .. } => span.start_byte(),
    }
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<XmlMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "xml.document-root" => document_root(input, context, &mut output)?,
        "xml.document-declaration" => document_declaration(input, context, &mut output)?,
        "xml.document-doctype" => document_doctype(input, context, &mut output)?,
        "xml.document-prolog" | "xml.document-epilog" => {
            document_prolog_epilog(operator.id(), input, context, &mut output)?;
        }
        "xml.element-children" => element_children(input, context, &mut output)?,
        "xml.element-child-elements" => element_child_elements(input, context, &mut output)?,
        "xml.element-child-text" => element_child_text(input, context, &mut output)?,
        "xml.element-child-cdata" => element_child_cdata(input, context, &mut output)?,
        "xml.element-child-comments" => element_child_comments(input, context, &mut output)?,
        "xml.element-child-pi" => element_child_pi(input, context, &mut output)?,
        "xml.element-descendants" => element_descendants(input, context, &mut output)?,
        "xml.element-attributes" => element_attributes(input, context, &mut output)?,
        "xml.element-namespace-bindings" | "xml.element-in-scope-namespaces" => {
            namespace_bindings(operator.id(), input, context, &mut output)?;
        }
        "xml.content-parent" | "xml.attribute-element" | "xml.reference-text" => {
            content_parent(input, context, &mut output)?;
        }
        "xml.text-references" => text_references(input, context, &mut output)?,
        "xml.name-equals" => name_equals(operator, input, context, &mut output)?,
        "xml.attribute-value-equals" => {
            attribute_value_equals(operator, input, context, &mut output)?;
        }
        "xml.pi-target-equals" => pi_target_equals(operator, input, context, &mut output)?,
        "xml.reference-kind-is" => reference_kind_is(operator, input, context, &mut output)?,
        "xml.reference-name-equals" => {
            reference_name_equals(operator, input, context, &mut output)?;
        }
        "xml.node-kind-is" => node_kind_is(operator, input, context, &mut output)?,
        "core.take" => take(operator, input, context, &mut output)?,
        "core.distinct-by-identity" => distinct_by_identity(input, context, &mut output)?,
        _ => unreachable!("validated XML native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

/// `xml.document-root`: the one document element, when formation proved it.
fn document_root(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    if let Some(root) = context.document.root() {
        for item in input {
            if matches!(item, XmlMatch::Document { .. }) {
                context.push(output, context.element_match(root.data().index))?;
            }
        }
    }
    Ok(())
}

/// `xml.document-declaration`: the XML declaration, when present.
fn document_declaration(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(item, XmlMatch::Document { .. }) {
            if let Some(declared) = context.document.declaration() {
                context.push(output, declaration_match(declared, context))?;
            }
        }
    }
    Ok(())
}

/// `xml.document-doctype`: the DOCTYPE occurrence, when present.
fn document_doctype(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if matches!(item, XmlMatch::Document { .. }) {
            if let Some(doctype) = context.document.doctype() {
                context.push(output, doctype_match(doctype, context))?;
            }
        }
    }
    Ok(())
}

/// `xml.document-prolog` / `xml.document-epilog`: ordered prolog or epilog
/// occurrences that publish a match (processing instruction and comment).
fn document_prolog_epilog(
    id: &str,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let items = if id == "xml.document-prolog" {
        context.document.prolog()
    } else {
        context.document.epilog()
    };
    for item in input {
        if matches!(item, XmlMatch::Document { .. }) {
            for prolog in items {
                if let Some(match_item) = context.prolog_item(prolog) {
                    context.push(output, match_item)?;
                }
            }
        }
    }
    Ok(())
}
/// `xml.element-children`: every child content occurrence, mixed order.
fn element_children(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    let match_item = match &context.document.nodes()[child] {
                        XmlContent::Element(_) => context.element_match(child),
                        XmlContent::Text(_) => text_match(context, child, node),
                        XmlContent::Cdata(_) => cdata_match(context, child, node),
                        XmlContent::Comment(_) => comment_match(context, child, node),
                        XmlContent::ProcessingInstruction(_) => pi_match(context, child, node),
                        XmlContent::ErrorRegion(data) => XmlMatch::ErrorRegion {
                            node: context.node_ref(child, NodeRole::XmlErrorRegion),
                            span: data.span,
                        },
                    };
                    context.push(output, match_item)?;
                }
            }
        }
    }
    Ok(())
}

/// One child text occurrence match.
fn text_match(context: &Context<'_>, index: usize, parent: NodeRef) -> XmlMatch {
    let XmlContent::Text(data) = &context.document.nodes()[index] else {
        unreachable!("caller proved the child is a text occurrence");
    };
    XmlMatch::Text {
        node: context.node_ref(index, NodeRole::XmlText),
        parent: Some(parent),
        semantic: text_semantic(data),
    }
}

/// One child CDATA occurrence match.
fn cdata_match(context: &Context<'_>, index: usize, parent: NodeRef) -> XmlMatch {
    let XmlContent::Cdata(data) = &context.document.nodes()[index] else {
        unreachable!("caller proved the child is a CDATA occurrence");
    };
    XmlMatch::Cdata {
        node: context.node_ref(index, NodeRole::XmlCdata),
        parent: Some(parent),
        text: data.text.to_string(),
    }
}

/// One child comment occurrence match.
fn comment_match(context: &Context<'_>, index: usize, parent: NodeRef) -> XmlMatch {
    let XmlContent::Comment(data) = &context.document.nodes()[index] else {
        unreachable!("caller proved the child is a comment");
    };
    XmlMatch::Comment {
        node: context.node_ref(index, NodeRole::XmlComment),
        parent: Some(parent),
        text: data.text.to_string(),
    }
}

/// One child processing-instruction match.
fn pi_match(context: &Context<'_>, index: usize, parent: NodeRef) -> XmlMatch {
    let XmlContent::ProcessingInstruction(data) = &context.document.nodes()[index] else {
        unreachable!("caller proved the child is a processing instruction");
    };
    XmlMatch::ProcessingInstruction {
        node: context.node_ref(index, NodeRole::XmlProcessingInstruction),
        parent: Some(parent),
        target: data.target.to_string(),
        content: data.content.as_ref().map(|(_, text)| text.to_string()),
    }
}

/// `xml.element-child-elements`: child element occurrences only.
fn element_child_elements(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    if matches!(context.document.nodes()[child], XmlContent::Element(_)) {
                        context.push(output, context.element_match(child))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-child-text`: child text occurrences only.
fn element_child_text(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    if matches!(context.document.nodes()[child], XmlContent::Text(_)) {
                        context.push(output, text_match(context, child, node))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-child-cdata`: child CDATA occurrences only.
fn element_child_cdata(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    if matches!(context.document.nodes()[child], XmlContent::Cdata(_)) {
                        context.push(output, cdata_match(context, child, node))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-child-comments`: child comment occurrences only.
fn element_child_comments(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    if matches!(context.document.nodes()[child], XmlContent::Comment(_)) {
                        context.push(output, comment_match(context, child, node))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-child-pi`: child processing-instruction occurrences only.
fn element_child_pi(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for &child in &context.element_data(index).children {
                    if matches!(
                        context.document.nodes()[child],
                        XmlContent::ProcessingInstruction(_)
                    ) {
                        context.push(output, pi_match(context, child, node))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-descendants`: bounded pre-order traversal with an explicit
/// stack; the input element itself is never included.
fn element_descendants(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let mut stack = Vec::new();
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                stack.push(index);
                while let Some(current) = stack.pop() {
                    for &child in context.element_data(current).children.iter().rev() {
                        if matches!(context.document.nodes()[child], XmlContent::Element(_)) {
                            stack.push(child);
                        }
                    }
                    if current != index {
                        context.push(output, context.element_match(current))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-attributes`: ordered attributes, excluding declarations.
fn element_attributes(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                for attribute in &context.element_data(index).attributes {
                    context.push(output, attribute_match(attribute, node, context))?;
                }
            }
        }
    }
    Ok(())
}

/// `xml.element-namespace-bindings` / `xml.element-in-scope-namespaces`:
/// local declarations, or the full ancestry-derived chain oldest first.
fn namespace_bindings(
    id: &str,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Element { node, .. } = item {
            if let Some(index) = node_to_index(node) {
                if id == "xml.element-in-scope-namespaces" {
                    // Ancestry-derived in-scope bindings, oldest declaration
                    // first, each with its true origin.
                    let mut chain = Vec::new();
                    let mut current = Some(index);
                    while let Some(at) = current {
                        chain.push(at);
                        current = context.document.parent_of(at);
                    }
                    for at in chain.into_iter().rev() {
                        let element = context.node_ref(at, NodeRole::XmlElement);
                        for binding in &context.element_data(at).namespaces {
                            context
                                .push(output, namespace_binding_match(binding, element, context))?;
                        }
                    }
                } else {
                    for binding in &context.element_data(index).namespaces {
                        context.push(output, namespace_binding_match(binding, node, context))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// One namespace binding match on one owning element.
fn namespace_binding_match(
    binding: &XmlNamespaceBindingData,
    element: NodeRef,
    context: &Context<'_>,
) -> XmlMatch {
    XmlMatch::NamespaceBinding {
        node: context.node_ref(
            usize::try_from(binding.ordinal).expect("ordinal in u64"),
            NodeRole::XmlNamespaceBinding,
        ),
        element,
        prefix: binding.prefix.as_deref().map(str::to_owned),
        uri: binding.uri.to_string(),
    }
}

/// `xml.content-parent` / `xml.attribute-element` / `xml.reference-text`:
/// one step back to the owning element.
fn content_parent(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        match item {
            XmlMatch::Attribute { element, .. } | XmlMatch::NamespaceBinding { element, .. } => {
                context.push(output, element_from_node(context, element))?;
            }
            XmlMatch::Text { parent, .. }
            | XmlMatch::Cdata { parent, .. }
            | XmlMatch::Comment { parent, .. }
            | XmlMatch::ProcessingInstruction { parent, .. }
            | XmlMatch::Element { parent, .. }
            | XmlMatch::Reference { parent, .. } => {
                if let Some(parent) = parent {
                    context.push(output, element_from_node(context, parent))?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `xml.text-references`: the ordered reference occurrences of one text.
fn text_references(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    for item in input {
        if let XmlMatch::Text { node, parent, .. } = item {
            if let Some(index) = node_to_index(node) {
                let XmlContent::Text(data) = &context.document.nodes()[index] else {
                    continue;
                };
                for (ordinal, fragment) in data.fragments.iter().enumerate() {
                    let (kind, name, resolved) = match fragment {
                        ReferenceFragment::CharacterReference { resolved, .. } => (
                            XmlReferenceKind::Character,
                            format!("&#x{:X};", *resolved as u32),
                            resolved.to_string(),
                        ),
                        ReferenceFragment::PredefinedEntity { name, resolved, .. } => (
                            XmlReferenceKind::Predefined,
                            name.to_string(),
                            resolved.to_string(),
                        ),
                        ReferenceFragment::GeneralEntity { name, resolved, .. } => (
                            XmlReferenceKind::General,
                            name.to_string(),
                            resolved.to_string(),
                        ),
                        ReferenceFragment::Literal { .. } => continue,
                    };
                    context.push(
                        output,
                        XmlMatch::Reference {
                            node: context.node_ref(ordinal, NodeRole::XmlEntityReference),
                            text: node,
                            parent,
                            kind,
                            name,
                            resolved,
                        },
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// `xml.name-equals`: original-spelling or expanded-name comparison.
fn name_equals(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected_prefix = operator.arguments()["prefix"]
        .as_string()
        .expect("validated prefix argument");
    let expected_local = operator.arguments()["local"]
        .as_string()
        .expect("validated local argument");
    let expected_namespace = operator.arguments()["namespace"]
        .as_string()
        .expect("validated namespace argument");
    let comparison = operator.arguments()["comparison"]
        .as_string()
        .expect("validated comparison argument");
    for item in input {
        let matches = match &item {
            XmlMatch::Element {
                prefix,
                local,
                namespace,
                namespace_error,
                ..
            } => {
                if comparison == "OriginalExact" {
                    prefix.as_deref().unwrap_or("") == expected_prefix && local == expected_local
                } else if comparison == "Expanded" && !namespace_error {
                    namespace.as_deref().unwrap_or("") == expected_namespace
                        && local == expected_local
                } else {
                    false
                }
            }
            XmlMatch::Attribute {
                prefix,
                local,
                namespace,
                ..
            } => {
                if comparison == "OriginalExact" {
                    prefix.as_deref().unwrap_or("") == expected_prefix && local == expected_local
                } else if comparison == "Expanded" {
                    namespace.as_deref().unwrap_or("") == expected_namespace
                        && local == expected_local
                } else {
                    false
                }
            }
            _ => false,
        };
        if matches {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `xml.attribute-value-equals`: CDATA-normalized value equality.
fn attribute_value_equals(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["value"]
        .as_string()
        .expect("validated value argument");
    for item in input {
        if matches!(&item, XmlMatch::Attribute { value, .. } if value == expected) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `xml.pi-target-equals`: processing-instruction target equality.
fn pi_target_equals(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["target"]
        .as_string()
        .expect("validated target argument");
    for item in input {
        if matches!(
            &item,
            XmlMatch::ProcessingInstruction { target, .. } if target == expected
        ) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `xml.reference-kind-is`: reference kind equality.
fn reference_kind_is(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected = match operator.arguments()["kind"]
        .as_string()
        .expect("validated kind argument")
    {
        "Character" => XmlReferenceKind::Character,
        "Predefined" => XmlReferenceKind::Predefined,
        "General" => XmlReferenceKind::General,
        _ => unreachable!("kind was validated before binding"),
    };
    for item in input {
        if matches!(&item, XmlMatch::Reference { kind, .. } if *kind == expected) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `xml.reference-name-equals`: reference name equality.
fn reference_name_equals(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["name"]
        .as_string()
        .expect("validated name argument");
    for item in input {
        if matches!(&item, XmlMatch::Reference { name, .. } if name == expected) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `xml.node-kind-is`: match-kind filter over mixed output.
fn node_kind_is(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let expected = operator.arguments()["kind"]
        .as_string()
        .expect("validated kind argument");
    for item in input {
        let kind = match &item {
            XmlMatch::Document { .. } => "document",
            XmlMatch::Declaration { .. } => "declaration",
            XmlMatch::Doctype { .. } => "doctype",
            XmlMatch::PrologItem { .. } => "prolog-item",
            XmlMatch::Element { .. } => "element",
            XmlMatch::Attribute { .. } => "attribute",
            XmlMatch::NamespaceBinding { .. } => "namespace-binding",
            XmlMatch::Text { .. } => "text",
            XmlMatch::Cdata { .. } => "cdata",
            XmlMatch::Comment { .. } => "comment",
            XmlMatch::ProcessingInstruction { .. } => "processing-instruction",
            XmlMatch::Reference { .. } => "reference",
            XmlMatch::ErrorRegion { .. } => "error-region",
        };
        if kind == expected {
            context.push(output, item)?;
        }
    }
    Ok(())
}

/// `core.take`: the first `count` input items.
fn take(
    operator: &OperatorCall,
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let count = operator.arguments()["count"]
        .as_integer()
        .and_then(consema_core::BigInteger::to_usize)
        .expect("validated take count");
    for item in input.into_iter().take(count) {
        context.push(output, item)?;
    }
    Ok(())
}

/// `core.distinct-by-identity`: first occurrence of every identity.
fn distinct_by_identity(
    input: Vec<XmlMatch>,
    context: &mut Context<'_>,
    output: &mut Vec<XmlMatch>,
) -> Result<(), QueryFailure> {
    let mut seen = HashSet::new();
    for item in input {
        if seen.insert(item.identity()) {
            context.push(output, item)?;
        }
    }
    Ok(())
}

fn element_from_node(context: &Context<'_>, node: NodeRef) -> XmlMatch {
    if let Some(index) = node_to_index(node) {
        context.element_match(index)
    } else {
        // The root document element is addressed through the root handle.
        if let Some(root) = context.document.root() {
            return context.element_match(root.data().index);
        }
        XmlMatch::Document {
            node: context.document.node_ref(),
        }
    }
}

fn declaration_match(declared: &XmlDeclarationData, context: &Context<'_>) -> XmlMatch {
    XmlMatch::Declaration {
        node: context
            .document
            .authority()
            .node_ref(1, NodeRole::XmlDeclaration),
        version: declared.version.to_string(),
        encoding: declared
            .encoding
            .as_ref()
            .map(|(_, value)| value.to_string()),
        standalone: declared.standalone.map(|(_, value)| value),
    }
}

fn doctype_match(doctype: &XmlDoctypeData, context: &Context<'_>) -> XmlMatch {
    XmlMatch::Doctype {
        node: context
            .document
            .authority()
            .node_ref(2, NodeRole::XmlDoctype),
        name: doctype.name.qname().as_str(),
    }
}

fn attribute_match(
    attribute: &crate::document::XmlAttributeData,
    element: NodeRef,
    context: &Context<'_>,
) -> XmlMatch {
    XmlMatch::Attribute {
        node: context.node_ref(
            usize::try_from(attribute.ordinal).expect("ordinal in u64"),
            NodeRole::XmlAttribute,
        ),
        element,
        prefix: attribute.qname.prefix.as_deref().map(str::to_owned),
        local: attribute.qname.local.to_string(),
        namespace: attribute
            .expanded
            .as_ref()
            .and_then(|expanded| expanded.namespace.as_deref())
            .map(str::to_owned),
        value: attribute.normalized_value.to_string(),
    }
}

fn node_to_index(node: NodeRef) -> Option<usize> {
    usize::try_from(node.index()).ok()
}

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<XmlSyntaxMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<XmlSyntaxMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "xml.syntax-kind-is" => {
            let expected = XmlSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name was validated before binding");
            for item in input.into_iter().filter(|item| item.kind == expected) {
                context.push(&mut output, item)?;
            }
        }
        "xml.syntax-text-equals" => {
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
                .and_then(consema_core::BigInteger::to_usize)
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
        _ => unreachable!("validated XML syntax operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn decoded_span_text(document: &Document, span: Span) -> String {
    let bytes = &document.source().bytes()[span.start_byte()..span.end_byte()];
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile, parse};
    use consema_core::{
        CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
        QueryExpression,
    };

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::xml_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn syntax_executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::xml_lossless_syntax_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn document(source: &[u8]) -> Document {
        parse(
            std::sync::Arc::<[u8]>::from(source),
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("forms")
    }

    fn run(expression: QueryExpression, document: &Document) -> Vec<XmlMatch> {
        execute_xml_query(
            &executable(expression),
            document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("query executes")
        .matches()
        .to_vec()
    }

    #[test]
    fn root_and_children_preserve_mixed_content_order() {
        let document = document(br#"<root a="1">x<child/>y</root>"#);
        let children = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-children", 1));
        let matches = run(children, &document);
        let kinds: Vec<&str> = matches
            .iter()
            .map(|item| match item {
                XmlMatch::Text { .. } => "text",
                XmlMatch::Element { .. } => "element",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["text", "element", "text"]);
        let XmlMatch::Text { semantic, .. } = &matches[0] else {
            panic!("first child is text");
        };
        assert_eq!(semantic, "x");
    }

    #[test]
    fn descendants_are_bounded_pre_order() {
        let document = document(br"<a><b><c/></b><d/></a>");
        let descendants = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-descendants", 1));
        let matches = run(descendants, &document);
        let locals: Vec<&str> = matches
            .iter()
            .map(|item| match item {
                XmlMatch::Element { local, .. } => local.as_str(),
                _ => "?",
            })
            .collect();
        assert_eq!(locals, vec!["b", "c", "d"]);
    }

    #[test]
    fn name_equals_original_and_expanded() {
        let document = document(br#"<p:root xmlns:p="urn:x"><p:child q:a="1"/></p:root>"#);
        let original = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-elements", 1))
            .then(
                OperatorCall::new("xml.name-equals", 1)
                    .with_argument("prefix", PortableValue::string("p"))
                    .with_argument("local", PortableValue::string("child"))
                    .with_argument("namespace", PortableValue::string(""))
                    .with_argument("comparison", PortableValue::string("OriginalExact")),
            );
        let matches = run(original, &document);
        assert_eq!(matches.len(), 1);

        let expanded = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-elements", 1))
            .then(
                OperatorCall::new("xml.name-equals", 1)
                    .with_argument("prefix", PortableValue::string(""))
                    .with_argument("local", PortableValue::string("child"))
                    .with_argument("namespace", PortableValue::string("urn:x"))
                    .with_argument("comparison", PortableValue::string("Expanded")),
            );
        let matches = run(expanded, &document);
        assert_eq!(matches.len(), 1);
        let XmlMatch::Element {
            namespace,
            namespace_error,
            ..
        } = &matches[0]
        else {
            panic!("element match");
        };
        assert_eq!(namespace.as_deref(), Some("urn:x"));
        assert!(!namespace_error);
    }

    #[test]
    fn attributes_and_values_query() {
        let document = document(br#"<root a="1" b="2"/>  "#);
        let attributes = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-attributes", 1))
            .then(
                OperatorCall::new("xml.attribute-value-equals", 1)
                    .with_argument("value", PortableValue::string("2")),
            );
        let matches = run(attributes, &document);
        assert_eq!(matches.len(), 1);
        let XmlMatch::Attribute { local, .. } = &matches[0] else {
            panic!("attribute match");
        };
        assert_eq!(local, "b");
    }

    #[test]
    fn references_query_by_kind_and_name() {
        let source = br#"<!DOCTYPE root [<!ENTITY e "expanded">]>
<root>&lt; &e; &#65;</root>"#;
        let document = document(source);
        let references = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-text", 1))
            .then(OperatorCall::new("xml.text-references", 1));
        let matches = run(references, &document);
        assert_eq!(matches.len(), 3);
        let kinds: Vec<XmlReferenceKind> = matches
            .iter()
            .map(|item| match item {
                XmlMatch::Reference { kind, .. } => *kind,
                _ => panic!("reference match"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                XmlReferenceKind::Predefined,
                XmlReferenceKind::General,
                XmlReferenceKind::Character,
            ]
        );

        let general = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-text", 1))
            .then(OperatorCall::new("xml.text-references", 1))
            .then(
                OperatorCall::new("xml.reference-name-equals", 1)
                    .with_argument("name", PortableValue::string("e")),
            );
        let matches = run(general, &document);
        assert_eq!(matches.len(), 1);
        let XmlMatch::Reference { resolved, .. } = &matches[0] else {
            panic!("reference match");
        };
        assert_eq!(resolved, "expanded");
    }

    #[test]
    fn in_scope_namespaces_include_ancestors() {
        let document = document(br#"<a xmlns="urn:a"><b xmlns:p="urn:p"><c/></b></a>"#);
        let bindings = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-elements", 1))
            .then(OperatorCall::new("xml.element-child-elements", 1))
            .then(OperatorCall::new("xml.element-in-scope-namespaces", 1));
        let matches = run(bindings, &document);
        let uris: Vec<&str> = matches
            .iter()
            .map(|item| match item {
                XmlMatch::NamespaceBinding { uri, .. } => uri.as_str(),
                _ => panic!("binding match"),
            })
            .collect();
        assert_eq!(uris, vec!["urn:a", "urn:p"]);
    }

    #[test]
    fn content_parent_navigates_back() {
        let document = document(br"<root>text</root>");
        let parent = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-text", 1))
            .then(OperatorCall::new("xml.content-parent", 1));
        let matches = run(parent, &document);
        assert_eq!(matches.len(), 1);
        let XmlMatch::Element { local, .. } = &matches[0] else {
            panic!("element match");
        };
        assert_eq!(local, "root");
    }

    #[test]
    fn node_kind_is_filters_mixed_output() {
        let document = document(br"<root><!--c--><?pi x?></root>");
        let expression = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-children", 1))
            .then(
                OperatorCall::new("xml.node-kind-is", 1)
                    .with_argument("kind", PortableValue::string("comment")),
            );
        let matches = run(expression, &document);
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0], XmlMatch::Comment { .. }));
    }

    #[test]
    fn prolog_navigation_exposes_declaration_and_pi() {
        let document = document(br#"<?xml version="1.0"?><?style x?><root/><!--after-->"#);
        let prolog = QueryExpression::Input.then(OperatorCall::new("xml.document-prolog", 1));
        let matches = run(prolog, &document);
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0], XmlMatch::PrologItem { .. }));
        let declaration =
            QueryExpression::Input.then(OperatorCall::new("xml.document-declaration", 1));
        let matches = run(declaration, &document);
        let XmlMatch::Declaration { version, .. } = &matches[0] else {
            panic!("declaration match");
        };
        assert_eq!(version, "1.0");
        let epilog = QueryExpression::Input.then(OperatorCall::new("xml.document-epilog", 1));
        let matches = run(epilog, &document);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn syntax_query_filters_kind_text_and_take() {
        let document = document(br"<root>a<b/>c</root>");
        let kinds = QueryExpression::Input.then(
            OperatorCall::new("xml.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("tag-open")),
        );
        let result = execute_xml_syntax_query(
            &syntax_executable(kinds),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 2);

        let text = QueryExpression::Input.then(
            OperatorCall::new("xml.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("a")),
        );
        let result = execute_xml_syntax_query(
            &syntax_executable(text),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("syntax query executes");
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].kind(), XmlSyntaxKind::Text);

        let take = QueryExpression::Input.then(
            OperatorCall::new("core.take", 1)
                .with_argument("count", PortableValue::integer(3.into())),
        );
        let result = execute_xml_syntax_query(
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
    fn domain_mismatch_is_rejected() {
        let document = document(br"<root/>");
        let foreign = QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1));
        let executable = QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(foreign)
            .validate()
            .expect("valid ini query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_xml_query(
                &executable,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::DomainMismatch(_))
        ));
    }

    #[test]
    fn require_one_cardinality_is_enforced() {
        let document = document(br"<root><a/><b/></root>");
        let expression = QueryExpression::Input
            .then(OperatorCall::new("xml.document-root", 1))
            .then(OperatorCall::new("xml.element-child-elements", 1));
        let definition = QueryDefinition::new(QueryDomain::xml_native_v1())
            .with_expression(expression)
            .with_selection(QuerySelection::RequireOne)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities");
        assert!(matches!(
            execute_xml_query(
                &definition,
                &document,
                QueryLimits::default(),
                &CancellationToken::new(),
            ),
            Err(QueryFailure::CardinalityViolation { .. })
        ));
    }
}
