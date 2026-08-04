use crate::{Document, InternalValueKind, JsonValueKind, SemanticAvailability};
use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::NodeRef;
use std::collections::HashSet;

/// Owned snapshot-bound JSON native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonMatch {
    /// JSON native value.
    Value {
        /// Exact value identity.
        node: NodeRef,
        /// Native category when locally available.
        kind: Option<JsonValueKind>,
    },
    /// Ordered object member with duplicate identity preserved.
    ObjectMember {
        /// Zero-based member ordinal.
        ordinal: usize,
        /// Decoded name when available.
        name: Option<String>,
        /// Key identity.
        key: NodeRef,
        /// Value identity.
        value: NodeRef,
        /// Association identity.
        member: NodeRef,
    },
    /// Ordered array element.
    ArrayElement {
        /// Zero-based element ordinal.
        ordinal: usize,
        /// Association identity.
        element: NodeRef,
        /// Value identity.
        value: NodeRef,
    },
}

impl JsonMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Value { node, .. } => *node,
            Self::ObjectMember { member, .. } => *member,
            Self::ArrayElement { element, .. } => *element,
        }
    }
}

/// Executes a validated JSON native semantic query against one immutable snapshot.
pub fn execute_json_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<JsonMatch>, QueryFailure> {
    if executable.definition().domain().id() != "json.native-semantic-query"
        || executable.definition().domain().version() != 1
    {
        return Err(QueryFailure::DomainMismatch(
            executable.definition().domain().clone(),
        ));
    }
    let root = document.root();
    let mut context = Context {
        document,
        limits,
        cancellation,
        steps: 0,
    };
    // The root is the first standard result; it must not bypass result limits.
    context.step(1)?;
    let input = vec![JsonMatch::Value {
        node: root.node_ref(),
        kind: match root.kind() {
            SemanticAvailability::Available(kind) => Some(kind),
            SemanticAvailability::Unavailable(_) => None,
        },
    }];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes the complete result through an ordered cursor.
pub fn execute_json_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<JsonMatch>, QueryFailure> {
    let result = execute_json_query(executable, document, limits, cancellation)?;
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

    fn value_match(&self, index: usize) -> JsonMatch {
        let value = crate::JsonValue {
            document: self.document,
            index,
        };
        JsonMatch::Value {
            node: value.node_ref(),
            kind: match value.kind() {
                SemanticAvailability::Available(kind) => Some(kind),
                SemanticAvailability::Unavailable(_) => None,
            },
        }
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[JsonMatch],
    context: &mut Context<'_>,
) -> Result<Vec<JsonMatch>, QueryFailure> {
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
                let span = context.document.span(index);
                (span.start_byte(), span.end_byte(), index)
            });
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<JsonMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<JsonMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "json.try-object-members" => {
            for item in input {
                if let JsonMatch::Value { node, .. } = item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(node)
                        .expect("query match belongs to bound document")
                        as usize;
                    if let InternalValueKind::Object(members) =
                        &context.document.value_entity(index).kind
                    {
                        for member_index in members {
                            let member = crate::JsonObjectMember {
                                document: context.document,
                                index: *member_index,
                            };
                            output.push(JsonMatch::ObjectMember {
                                ordinal: member.ordinal(),
                                name: match member.name() {
                                    SemanticAvailability::Available(name) => Some(name.to_owned()),
                                    SemanticAvailability::Unavailable(_) => None,
                                },
                                key: member.key_node_ref(),
                                value: member.value_node_ref(),
                                member: member.node_ref(),
                            });
                        }
                    }
                }
            }
        }
        "json.member-name-equals" => {
            let expected = operator.arguments()["name"]
                .as_string()
                .expect("validated name argument");
            output.extend(input.into_iter().filter(|item| {
                matches!(item, JsonMatch::ObjectMember { name: Some(name), .. } if name == expected)
            }));
        }
        "json.member-value" => {
            for item in input {
                if let JsonMatch::ObjectMember { value, .. } = item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(value)
                        .expect("query match belongs to bound document")
                        as usize;
                    output.push(context.value_match(index));
                }
            }
        }
        "json.try-array-elements" => {
            for item in input {
                if let JsonMatch::Value { node, .. } = item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(node)
                        .expect("query match belongs to bound document")
                        as usize;
                    if let InternalValueKind::Array(elements) =
                        &context.document.value_entity(index).kind
                    {
                        for element_index in elements {
                            let element = crate::JsonArrayElement {
                                document: context.document,
                                index: *element_index,
                            };
                            output.push(JsonMatch::ArrayElement {
                                ordinal: element.ordinal(),
                                element: element.node_ref(),
                                value: element.value_node_ref(),
                            });
                        }
                    }
                }
            }
        }
        "json.array-element-value" => {
            for item in input {
                if let JsonMatch::ArrayElement { value, .. } = item {
                    let index = context
                        .document
                        .authority
                        .resolve_index(value)
                        .expect("query match belongs to bound document")
                        as usize;
                    output.push(context.value_match(index));
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
        _ => unreachable!("validated JSON operator"),
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
    use crate::{JsonProfile, parse};
    use consema_core::{CapabilityId, CapabilitySet, OperatorCall, QueryDefinition, QueryDomain};
    use consema_document::ParseLimits;

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    #[test]
    fn operator_free_root_result_obeys_max_results() {
        let document = parse(
            br#"{"a":1}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let executable = QueryDefinition::new(QueryDomain::json_native_v1())
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let limits = QueryLimits {
            max_results: 0,
            ..QueryLimits::default()
        };
        assert!(matches!(
            execute_json_query(&executable, &document, limits, &CancellationToken::new()),
            Err(QueryFailure::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn duplicate_member_query_keeps_source_order_and_identity() {
        let document = parse(
            br#"{"a":1,"a":2,"b":3}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let expression = QueryExpression::Input
            .then(OperatorCall::new("json.try-object-members", 1))
            .then(
                OperatorCall::new("json.member-name-equals", 1)
                    .with_argument("name", consema_core::PortableValue::string("a")),
            );
        let executable = QueryDefinition::new(QueryDomain::json_native_v1())
            .with_expression(expression)
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = execute_json_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);
        assert_ne!(
            result.matches()[0].identity(),
            result.matches()[1].identity()
        );
    }
}
