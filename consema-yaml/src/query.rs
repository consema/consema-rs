use std::collections::HashSet;

use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, SourceEncoding, Span};

use crate::{Document, NativeContent, YamlNodeKind, YamlScalarKind, YamlSyntaxKind};

/// Owned snapshot-bound YAML native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YamlMatch {
    /// Complete YAML serialization stream.
    Stream {
        /// Stream identity.
        stream: NodeRef,
        /// Exact raw source span.
        span: Span,
        /// Number of independent documents.
        document_count: usize,
    },
    /// One independent document.
    Document {
        /// Zero-based stream ordinal.
        ordinal: usize,
        /// Document identity.
        document: NodeRef,
        /// Representation root identity.
        root: NodeRef,
        /// Raw presentation span.
        span: Span,
    },
    /// One YAML representation node.
    Node {
        /// Representation identity.
        node: NodeRef,
        /// Scalar, sequence, or mapping.
        kind: YamlNodeKind,
        /// Resolved global tag URI.
        tag: String,
        /// Scalar category when the node is scalar.
        scalar_kind: Option<YamlScalarKind>,
        /// Canonical scalar content when the node is scalar.
        canonical: Option<String>,
        /// Defining anchor name, when present.
        anchor: Option<String>,
        /// Raw representation span.
        span: Span,
    },
    /// One ordered mapping association.
    MappingEntry {
        /// Zero-based direct association ordinal.
        ordinal: usize,
        /// Association identity.
        entry: NodeRef,
        /// Arbitrary key representation identity.
        key: NodeRef,
        /// Value representation identity.
        value: NodeRef,
        /// Raw association span.
        span: Span,
    },
    /// One ordered sequence association.
    SequenceElement {
        /// Zero-based direct association ordinal.
        ordinal: usize,
        /// Association identity.
        element: NodeRef,
        /// Referenced representation identity.
        node: NodeRef,
        /// Raw element occurrence span.
        span: Span,
    },
    /// One anchor definition occurrence.
    AnchorDefinition {
        /// Exact anchor name without `&`.
        name: String,
        /// Definition occurrence identity.
        definition: NodeRef,
        /// Anchored representation identity.
        node: NodeRef,
        /// Exact raw `&name` span.
        span: Span,
    },
    /// One alias serialization occurrence.
    AliasOccurrence {
        /// Zero-based serialization-order ordinal.
        ordinal: usize,
        /// Exact alias name without `*`.
        name: String,
        /// Alias occurrence identity.
        alias: NodeRef,
        /// Shared target representation identity.
        target: NodeRef,
        /// Exact raw `*name` span.
        span: Span,
    },
}

impl YamlMatch {
    /// Primary process-local identity for this match.
    #[must_use]
    pub const fn node_ref(&self) -> NodeRef {
        match self {
            Self::Stream { stream, .. } => *stream,
            Self::Document { document, .. } => *document,
            Self::Node { node, .. } => *node,
            Self::MappingEntry { entry, .. } => *entry,
            Self::SequenceElement { element, .. } => *element,
            Self::AnchorDefinition { definition, .. } => *definition,
            Self::AliasOccurrence { alias, .. } => *alias,
        }
    }

    /// Exact raw source span associated with the match.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Stream { span, .. }
            | Self::Document { span, .. }
            | Self::Node { span, .. }
            | Self::MappingEntry { span, .. }
            | Self::SequenceElement { span, .. }
            | Self::AnchorDefinition { span, .. }
            | Self::AliasOccurrence { span, .. } => *span,
        }
    }
}

/// Owned snapshot-bound YAML lossless syntax query match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YamlSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: YamlSyntaxKind,
    ordinal: usize,
}

impl YamlSyntaxMatch {
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
    pub const fn kind(self) -> YamlSyntaxKind {
        self.kind
    }

    /// Zero-based source-order ordinal.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Executes a validated YAML native semantic query against one immutable stream.
pub fn execute_yaml_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<YamlMatch>, QueryFailure> {
    if executable.definition().domain().id() != "yaml.native-semantic-query"
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
    let input = vec![YamlMatch::Stream {
        stream: document.stream_node_ref(),
        span: document.stream_span(),
        document_count: document.document_count(),
    }];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    Ok(QueryExecution::completed(apply_selection(
        matches,
        executable.definition().selection(),
    )?))
}

/// Executes and exposes a complete YAML native result through an ordered cursor.
pub fn execute_yaml_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<YamlMatch>, QueryFailure> {
    let result = execute_yaml_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated YAML lossless syntax query in exact raw source order.
pub fn execute_yaml_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<YamlSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "yaml.lossless-syntax-query"
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
    let pieces = document.lossless_structural_index().pieces();
    context.step(pieces.len())?;
    let input = pieces
        .iter()
        .zip(document.lossless_syntax_kinds())
        .enumerate()
        .map(|(ordinal, (piece, kind))| YamlSyntaxMatch {
            node: document.authority.node_ref(
                u64::try_from(ordinal).expect("parse limits keep syntax ordinals in u64"),
                NodeRole::YamlSyntaxPiece,
            ),
            span: piece.span(),
            kind: *kind,
            ordinal,
        })
        .collect::<Vec<_>>();
    let matches =
        execute_syntax_expression(executable.definition().expression(), &input, &mut context)?;
    Ok(QueryExecution::completed(apply_selection(
        matches,
        executable.definition().selection(),
    )?))
}

/// Executes a YAML syntax query and exposes its complete ordered result as a cursor.
pub fn execute_yaml_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<YamlSyntaxMatch>, QueryFailure> {
    let result = execute_yaml_syntax_query(executable, document, limits, cancellation)?;
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
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps || results > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn node_match(&self, index: usize) -> YamlMatch {
        let node = &self.document.native.nodes[index];
        let (kind, scalar_kind, canonical) = match &node.content {
            NativeContent::Scalar(scalar) => (
                YamlNodeKind::Scalar,
                Some(scalar.kind),
                Some(scalar.canonical.to_string()),
            ),
            NativeContent::Sequence(_) => (YamlNodeKind::Sequence, None, None),
            NativeContent::Mapping(_) => (YamlNodeKind::Mapping, None, None),
        };
        YamlMatch::Node {
            node: crate::node_ref(&self.document.authority, index),
            kind,
            tag: node.tag.to_string(),
            scalar_kind,
            canonical,
            anchor: node.anchor.as_ref().map(ToString::to_string),
            span: node.span,
        }
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[YamlMatch],
    context: &mut Context<'_>,
) -> Result<Vec<YamlMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let matches = execute_expression(expression_input, input, context)?;
            apply_operator(operator, matches, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_expression(branch, input, context)?);
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_expression(branch, input, context)?);
            }
            output.sort_by_key(|item| {
                let span = item.span();
                let identity = item.node_ref();
                (
                    span.start_byte(),
                    span.end_byte(),
                    role_order(identity.role()),
                    context
                        .document
                        .authority
                        .resolve_index(identity)
                        .expect("query match belongs to bound document"),
                )
            });
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn execute_syntax_expression(
    expression: &QueryExpression,
    input: &[YamlSyntaxMatch],
    context: &mut Context<'_>,
) -> Result<Vec<YamlSyntaxMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let matches = execute_syntax_expression(expression_input, input, context)?;
            apply_syntax_operator(operator, matches, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_syntax_expression(branch, input, context)?);
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_syntax_expression(branch, input, context)?);
            }
            output.sort_by_key(|item| item.ordinal);
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<YamlMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<YamlMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "yaml.documents" => {
            for item in input {
                if !matches!(item, YamlMatch::Stream { .. }) {
                    continue;
                }
                for (ordinal, document) in context.document.native.documents.iter().enumerate() {
                    output.push(YamlMatch::Document {
                        ordinal,
                        document: context.document.authority.node_ref(
                            u64::try_from(ordinal)
                                .expect("parse limits keep document ordinals in u64"),
                            NodeRole::YamlDocument,
                        ),
                        root: crate::node_ref(&context.document.authority, document.root),
                        span: document.span,
                    });
                }
            }
        }
        "yaml.document-root" => {
            for item in input {
                if let YamlMatch::Document { root, .. } = item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(root)
                        .expect("query match belongs to bound document")
                        as usize;
                    output.push(context.node_match(index));
                }
            }
        }
        "yaml.where-node-kind" => {
            let expected = operator.arguments()["kind"]
                .as_string()
                .expect("validated kind argument");
            output.extend(input.into_iter().filter(|item| {
                matches!(item, YamlMatch::Node { kind, .. } if node_kind_name(*kind) == expected)
            }));
        }
        "yaml.where-tag" => {
            let expected = operator.arguments()["tag"]
                .as_string()
                .expect("validated tag argument");
            output.extend(
                input
                    .into_iter()
                    .filter(|item| matches!(item, YamlMatch::Node { tag, .. } if tag == expected)),
            );
        }
        "yaml.scalar-canonical-equals" => {
            let expected = operator.arguments()["canonical"]
                .as_string()
                .expect("validated canonical argument");
            output.extend(input.into_iter().filter(|item| {
                matches!(item, YamlMatch::Node { canonical: Some(value), .. } if value == expected)
            }));
        }
        "yaml.try-sequence-elements" => {
            for item in input {
                let YamlMatch::Node { node, .. } = item else {
                    continue;
                };
                let index = resolve_node(context, node);
                let NativeContent::Sequence(items) = &context.document.native.nodes[index].content
                else {
                    continue;
                };
                for (ordinal, item) in items.iter().enumerate() {
                    output.push(YamlMatch::SequenceElement {
                        ordinal,
                        element: context
                            .document
                            .authority
                            .node_ref(item.identity, NodeRole::YamlSequenceElement),
                        node: crate::node_ref(&context.document.authority, item.node),
                        span: item.span,
                    });
                }
            }
        }
        "yaml.sequence-element-node" => {
            for item in input {
                if let YamlMatch::SequenceElement { node, .. } = item {
                    output.push(context.node_match(resolve_node(context, node)));
                }
            }
        }
        "yaml.try-mapping-entries" => {
            for item in input {
                let YamlMatch::Node { node, .. } = item else {
                    continue;
                };
                let index = resolve_node(context, node);
                let NativeContent::Mapping(entries) = &context.document.native.nodes[index].content
                else {
                    continue;
                };
                for (ordinal, entry) in entries.iter().enumerate() {
                    output.push(YamlMatch::MappingEntry {
                        ordinal,
                        entry: context
                            .document
                            .authority
                            .node_ref(entry.identity, NodeRole::YamlMappingEntry),
                        key: crate::node_ref(&context.document.authority, entry.key),
                        value: crate::node_ref(&context.document.authority, entry.value),
                        span: entry.span,
                    });
                }
            }
        }
        "yaml.mapping-entry-key" | "yaml.mapping-entry-value" => {
            let take_key = operator.id() == "yaml.mapping-entry-key";
            for item in input {
                if let YamlMatch::MappingEntry { key, value, .. } = item {
                    output.push(
                        context
                            .node_match(resolve_node(context, if take_key { key } else { value })),
                    );
                }
            }
        }
        "yaml.anchor-definition" => {
            for item in input {
                let YamlMatch::Node { node, .. } = item else {
                    continue;
                };
                let index = resolve_node(context, node);
                let native = &context.document.native.nodes[index];
                if let (Some(name), Some(span)) = (&native.anchor, native.anchor_span) {
                    output.push(YamlMatch::AnchorDefinition {
                        name: name.to_string(),
                        definition: context.document.authority.node_ref(
                            u64::try_from(index).expect("parse limits keep node indexes in u64"),
                            NodeRole::YamlAnchorDefinition,
                        ),
                        node,
                        span,
                    });
                }
            }
        }
        "yaml.anchor-node" => {
            for item in input {
                if let YamlMatch::AnchorDefinition { node, .. } = item {
                    output.push(context.node_match(resolve_node(context, node)));
                }
            }
        }
        "yaml.alias-occurrences" => {
            for item in input {
                if !matches!(item, YamlMatch::Stream { .. }) {
                    continue;
                }
                for (ordinal, alias) in context.document.native.aliases.iter().enumerate() {
                    output.push(YamlMatch::AliasOccurrence {
                        ordinal,
                        name: alias.name.to_string(),
                        alias: context
                            .document
                            .authority
                            .node_ref(alias.identity, NodeRole::YamlAlias),
                        target: crate::node_ref(&context.document.authority, alias.target),
                        span: alias.span,
                    });
                }
            }
        }
        "yaml.alias-target" => {
            for item in input {
                if let YamlMatch::AliasOccurrence { target, .. } = item {
                    output.push(context.node_match(resolve_node(context, target)));
                }
            }
        }
        "core.take" => {
            let count = operator.arguments()["count"]
                .as_integer()
                .and_then(consema_core::BigInteger::to_usize)
                .expect("validated take count");
            output.extend(input.into_iter().take(count));
        }
        "core.distinct-by-identity" => {
            let mut seen = HashSet::new();
            output.extend(
                input
                    .into_iter()
                    .filter(|item| seen.insert(item.node_ref())),
            );
        }
        _ => unreachable!("validated YAML native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<YamlSyntaxMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<YamlSyntaxMatch>, QueryFailure> {
    let output: Vec<YamlSyntaxMatch> = match operator.id() {
        "yaml.syntax-kind-is" => {
            let expected = YamlSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name validated before binding");
            input
                .into_iter()
                .filter(|item| item.kind == expected)
                .collect()
        }
        "yaml.syntax-text-equals" => {
            let expected = encoded_text(
                operator.arguments()["text"]
                    .as_string()
                    .expect("validated text argument"),
                context.document.source.encoding_facts().selected(),
            );
            input
                .into_iter()
                .filter(|item| {
                    context.document.source.bytes()[item.span.start_byte()..item.span.end_byte()]
                        == expected
                })
                .collect()
        }
        "core.take" => {
            let count = operator.arguments()["count"]
                .as_integer()
                .and_then(consema_core::BigInteger::to_usize)
                .expect("validated take count");
            input.into_iter().take(count).collect()
        }
        "core.distinct-by-identity" => {
            let mut seen = HashSet::new();
            input
                .into_iter()
                .filter(|item| seen.insert(item.node))
                .collect()
        }
        _ => unreachable!("validated YAML syntax operator"),
    };
    context.step(output.len())?;
    Ok(output)
}

fn encoded_text(value: &str, encoding: SourceEncoding) -> Vec<u8> {
    match encoding {
        SourceEncoding::Utf8 => value.as_bytes().to_vec(),
        SourceEncoding::Utf16Le => value.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        SourceEncoding::Utf16Be => value.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        SourceEncoding::Latin1 | SourceEncoding::Binary => Vec::new(),
    }
}

fn resolve_node(context: &Context<'_>, node: NodeRef) -> usize {
    context
        .document
        .authority
        .resolve_index(node)
        .expect("query match belongs to bound document") as usize
}

const fn node_kind_name(kind: YamlNodeKind) -> &'static str {
    match kind {
        YamlNodeKind::Scalar => "Scalar",
        YamlNodeKind::Sequence => "Sequence",
        YamlNodeKind::Mapping => "Mapping",
    }
}

const fn role_order(role: NodeRole) -> u8 {
    match role {
        NodeRole::YamlStream => 0,
        NodeRole::YamlDocument => 1,
        NodeRole::YamlMappingEntry | NodeRole::YamlSequenceElement => 2,
        NodeRole::YamlAnchorDefinition => 3,
        NodeRole::YamlAlias => 4,
        NodeRole::YamlNode => 5,
        _ => 6,
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{YamlProfile, parse};
    use consema_core::{
        CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
    };
    use consema_document::ParseLimits;

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::yaml_native_v1())
            .with_expression(expression)
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap()
    }

    #[test]
    fn native_query_keeps_arbitrary_entries_and_shared_alias_identity() {
        let document = parse(
            b"---\n? [a, b]\n: &x {k: v}\nalias: *x\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let entries = QueryExpression::Input
            .then(OperatorCall::new("yaml.documents", 1))
            .then(OperatorCall::new("yaml.document-root", 1))
            .then(OperatorCall::new("yaml.try-mapping-entries", 1));
        let result = execute_yaml_query(
            &executable(entries),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);

        let aliases = QueryExpression::Input
            .then(OperatorCall::new("yaml.alias-occurrences", 1))
            .then(OperatorCall::new("yaml.alias-target", 1));
        let alias_result = execute_yaml_query(
            &executable(aliases),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        let anchored = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        assert_eq!(alias_result.matches()[0].node_ref(), anchored.node_ref());
    }

    #[test]
    fn syntax_query_supports_utf16_text_and_source_order() {
        let utf16 = "a: 1 # note\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut source = vec![0xff, 0xfe];
        source.extend(utf16);
        let document = parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default()).unwrap();
        let expression = QueryExpression::Input.then(
            OperatorCall::new("yaml.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("# note")),
        );
        let executable = QueryDefinition::new(QueryDomain::yaml_lossless_syntax_v1())
            .with_expression(expression)
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = execute_yaml_syntax_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].kind(), YamlSyntaxKind::Comment);
        assert_eq!(
            result.matches()[0].node_ref().role(),
            NodeRole::YamlSyntaxPiece
        );
    }

    #[test]
    fn query_limits_and_cancellation_fail_without_completed_prefixes() {
        let document = parse(
            b"[a, b, c]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let elements = QueryExpression::Input
            .then(OperatorCall::new("yaml.documents", 1))
            .then(OperatorCall::new("yaml.document-root", 1))
            .then(OperatorCall::new("yaml.try-sequence-elements", 1));
        assert_eq!(
            execute_yaml_query(
                &executable(elements.clone()),
                &document,
                QueryLimits {
                    max_results: 2,
                    ..QueryLimits::default()
                },
                &CancellationToken::new(),
            ),
            Err(QueryFailure::ResourceLimitExceeded)
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            execute_yaml_query(
                &executable(elements),
                &document,
                QueryLimits::default(),
                &cancellation,
            ),
            Err(QueryFailure::Cancelled)
        );
    }

    #[test]
    fn definitions_reject_wrong_roles_and_unknown_yaml_kinds_before_binding() {
        let wrong_role = QueryDefinition::new(QueryDomain::yaml_native_v1()).with_expression(
            QueryExpression::Input.then(OperatorCall::new("yaml.document-root", 1)),
        );
        assert!(matches!(
            wrong_role.validate(),
            Err(QueryFailure::InvalidOperatorComposition {
                expected: consema_core::MatchRole::YamlDocument,
                actual: consema_core::MatchRole::YamlStream,
                ..
            })
        ));

        let unknown_kind = QueryDefinition::new(QueryDomain::yaml_lossless_syntax_v1())
            .with_expression(
                QueryExpression::Input.then(
                    OperatorCall::new("yaml.syntax-kind-is", 1)
                        .with_argument("kind", PortableValue::string("BackendToken")),
                ),
            );
        assert!(matches!(
            unknown_kind.validate(),
            Err(QueryFailure::InvalidArgument { .. })
        ));
    }
}
