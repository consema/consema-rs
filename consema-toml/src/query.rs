use crate::{Document, EntityKind, InternalItemKind, TomlItem, TomlItemKind, TomlSyntaxKind};
use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::HashSet;

/// Owned snapshot-bound TOML native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TomlMatch {
    /// TOML native item.
    Item {
        /// Exact item identity.
        node: NodeRef,
        /// Native item category.
        kind: TomlItemKind,
    },
    /// Ordered table or inline-table entry.
    Entry {
        /// Zero-based direct entry ordinal.
        ordinal: usize,
        /// Decoded direct key segment.
        name: String,
        /// Key identity.
        key: NodeRef,
        /// Associated item identity.
        item: NodeRef,
        /// Association identity.
        entry: NodeRef,
    },
    /// Ordered array or array-of-tables element.
    ArrayElement {
        /// Zero-based direct element ordinal.
        ordinal: usize,
        /// Association identity.
        element: NodeRef,
        /// Associated item identity.
        item: NodeRef,
    },
}

impl TomlMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Item { node, .. } => *node,
            Self::Entry { entry, .. } => *entry,
            Self::ArrayElement { element, .. } => *element,
        }
    }
}

/// Owned snapshot-bound TOML lossless syntax query match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TomlSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: TomlSyntaxKind,
    ordinal: usize,
}

impl TomlSyntaxMatch {
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
    pub const fn kind(self) -> TomlSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Executes a validated TOML native semantic query against one immutable snapshot.
pub fn execute_toml_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<TomlMatch>, QueryFailure> {
    if executable.definition().domain().id() != "toml.native-semantic-query"
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
    context.step(0)?;
    let input = vec![context.item_match(document.root().index)];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes the complete result through an ordered cursor.
pub fn execute_toml_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<TomlMatch>, QueryFailure> {
    let result = execute_toml_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated TOML lossless syntax query against every source piece in raw order.
pub fn execute_toml_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<TomlSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "toml.lossless-syntax-query"
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
        .map(|(ordinal, (piece, kind))| TomlSyntaxMatch {
            node: document.authority.node_ref(
                u64::try_from(ordinal).expect("parse limits keep syntax ordinals in u64"),
                NodeRole::TomlSyntaxPiece,
            ),
            span: piece.span(),
            kind: *kind,
            ordinal,
        })
        .collect::<Vec<_>>();
    let matches =
        execute_syntax_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes a TOML lossless syntax query and exposes its complete ordered result as a cursor.
pub fn execute_toml_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<TomlSyntaxMatch>, QueryFailure> {
    let result = execute_toml_syntax_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::new(result.matches().to_vec()))
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

    fn item_match(&self, index: usize) -> TomlMatch {
        let item = TomlItem {
            document: self.document,
            index,
        };
        TomlMatch::Item {
            node: item.node_ref(),
            kind: item.kind(),
        }
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[TomlMatch],
    context: &mut Context<'_>,
) -> Result<Vec<TomlMatch>, QueryFailure> {
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
                let index = context
                    .document
                    .authority
                    .resolve_index(item.identity())
                    .expect("query match belongs to bound document")
                    as usize;
                let span = context.document.entity(index).span;
                (span.start_byte(), span.end_byte(), index)
            });
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn execute_syntax_expression(
    expression: &QueryExpression,
    input: &[TomlSyntaxMatch],
    context: &mut Context<'_>,
) -> Result<Vec<TomlSyntaxMatch>, QueryFailure> {
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

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<TomlSyntaxMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<TomlSyntaxMatch>, QueryFailure> {
    let output: Vec<TomlSyntaxMatch> = match operator.id() {
        "toml.syntax-kind-is" => {
            let expected = TomlSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name was validated before binding");
            input
                .into_iter()
                .filter(|item| item.kind == expected)
                .collect()
        }
        "toml.syntax-text-equals" => {
            let expected = operator.arguments()["text"]
                .as_string()
                .expect("validated text argument")
                .as_bytes();
            input
                .into_iter()
                .filter(|item| {
                    &context.document.source.bytes()[item.span.start_byte()..item.span.end_byte()]
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
        _ => unreachable!("validated TOML syntax operator"),
    };
    context.step(output.len())?;
    Ok(output)
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<TomlMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<TomlMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "toml.try-table-entries" => {
            for match_item in input {
                if let TomlMatch::Item { node, .. } = match_item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(node)
                        .expect("query match belongs to bound document")
                        as usize;
                    let (InternalItemKind::Table { entries, .. }
                    | InternalItemKind::InlineTable(entries)) =
                        &context.document.item_entity(index).kind
                    else {
                        continue;
                    };
                    for entry_index in entries {
                        let entry = crate::TomlEntry {
                            document: context.document,
                            index: *entry_index,
                        };
                        output.push(TomlMatch::Entry {
                            ordinal: entry.ordinal(),
                            name: entry.name().to_owned(),
                            key: entry.key_node_ref(),
                            item: entry.item_node_ref(),
                            entry: entry.node_ref(),
                        });
                    }
                }
            }
        }
        "toml.entry-name-equals" => {
            let expected = operator.arguments()["name"]
                .as_string()
                .expect("validated name argument");
            output.extend(
                input.into_iter().filter(
                    |item| matches!(item, TomlMatch::Entry { name, .. } if name == expected),
                ),
            );
        }
        "toml.entry-item" => {
            for match_item in input {
                if let TomlMatch::Entry { item, .. } = match_item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(item)
                        .expect("query match belongs to bound document")
                        as usize;
                    output.push(context.item_match(index));
                }
            }
        }
        "toml.try-array-elements" => {
            for match_item in input {
                if let TomlMatch::Item { node, .. } = match_item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(node)
                        .expect("query match belongs to bound document")
                        as usize;
                    let (InternalItemKind::Array(elements)
                    | InternalItemKind::ArrayOfTables(elements)) =
                        &context.document.item_entity(index).kind
                    else {
                        continue;
                    };
                    for element_index in elements {
                        let EntityKind::Element(entity) =
                            &context.document.entity(*element_index).kind
                        else {
                            unreachable!("typed TOML element");
                        };
                        output.push(TomlMatch::ArrayElement {
                            ordinal: entity.ordinal,
                            element: context.document.node_ref(
                                *element_index,
                                consema_document::NodeRole::TomlArrayElement,
                            ),
                            item: context
                                .document
                                .node_ref(entity.item, consema_document::NodeRole::TomlItem),
                        });
                    }
                }
            }
        }
        "toml.array-element-item" => {
            for match_item in input {
                if let TomlMatch::ArrayElement { item, .. } = match_item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(item)
                        .expect("query match belongs to bound document")
                        as usize;
                    output.push(context.item_match(index));
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
            for item in input {
                if seen.insert(item.identity()) {
                    output.push(item);
                }
            }
        }
        _ => unreachable!("validated TOML operator"),
    }
    context.step(output.len())?;
    Ok(output)
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
    use crate::{TomlProfile, parse};
    use consema_core::{
        CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
        QueryExpression,
    };
    use consema_document::ParseLimits;

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::toml_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    #[test]
    fn nested_entry_query_retains_direct_toml_roles() {
        let document = parse(
            b"server.host = 'localhost'\nserver.ports = [80, 443]\n".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("valid TOML");
        let server = QueryExpression::Input
            .then(OperatorCall::new("toml.try-table-entries", 1))
            .then(
                OperatorCall::new("toml.entry-name-equals", 1)
                    .with_argument("name", PortableValue::string("server")),
            )
            .then(OperatorCall::new("toml.entry-item", 1))
            .then(OperatorCall::new("toml.try-table-entries", 1));
        let result = execute_toml_query(
            &executable(server),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("query");
        assert_eq!(result.matches().len(), 2);
        assert!(matches!(
            &result.matches()[0],
            TomlMatch::Entry { name, .. } if name == "host"
        ));
        assert!(matches!(
            &result.matches()[1],
            TomlMatch::Entry { name, .. } if name == "ports"
        ));
    }

    #[test]
    fn array_query_obeys_selection_and_cancellation() {
        let document = parse(
            b"values = [1, 2, 3]".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("valid TOML");
        let expression = QueryExpression::Input
            .then(OperatorCall::new("toml.try-table-entries", 1))
            .then(OperatorCall::new("toml.entry-item", 1))
            .then(OperatorCall::new("toml.try-array-elements", 1))
            .then(OperatorCall::new("toml.array-element-item", 1));
        let definition = QueryDefinition::new(QueryDomain::toml_native_v1())
            .with_expression(expression)
            .with_selection(QuerySelection::Last);
        let executable = definition
            .validate()
            .expect("valid")
            .bind(&capabilities())
            .expect("bind");
        let result = execute_toml_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .expect("query");
        assert!(matches!(
            result.matches(),
            [TomlMatch::Item {
                kind: TomlItemKind::Integer,
                ..
            }]
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            execute_toml_query(
                &executable,
                &document,
                QueryLimits::default(),
                &cancellation,
            ),
            Err(QueryFailure::Cancelled)
        );
    }

    #[test]
    fn lossless_syntax_query_preserves_piece_order_kind_and_text() {
        let document = parse(
            b"a = 1 # note\nb = 2\n".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .unwrap();
        let newlines = QueryExpression::Input.then(
            OperatorCall::new("toml.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("Newline")),
        );
        let comment = QueryExpression::Input.then(
            OperatorCall::new("toml.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("# note")),
        );
        let executable = QueryDefinition::new(QueryDomain::toml_lossless_syntax_v1())
            .with_expression(QueryExpression::StructureOrderMerge(vec![
                newlines, comment,
            ]))
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = execute_toml_syntax_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            result
                .matches()
                .iter()
                .map(|item| item.kind())
                .collect::<Vec<_>>(),
            vec![
                TomlSyntaxKind::Comment,
                TomlSyntaxKind::Newline,
                TomlSyntaxKind::Newline,
            ]
        );
        assert_eq!(
            result.matches()[0].node_ref().role(),
            NodeRole::TomlSyntaxPiece
        );
        assert!(result.matches()[0].ordinal() < result.matches()[1].ordinal());
        let span = result.matches()[0].span();
        assert_eq!(
            &document.source().bytes()[span.start_byte()..span.end_byte()],
            b"# note"
        );
    }
}
