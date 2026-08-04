use crate::{
    Document, JavaString, PropertiesEscapeKind, PropertiesLogicalLineKind, PropertiesSyntaxKind,
    PropertiesValueState,
};
use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::HashSet;

/// Owned snapshot-bound Java Properties native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertiesMatch {
    /// Complete Properties document.
    Document {
        /// Root document identity.
        node: NodeRef,
    },
    /// One duplicate-preserving property association.
    Property {
        /// Zero-based source-order property ordinal.
        ordinal: usize,
        /// Property identity.
        node: NodeRef,
        /// Owning logical line.
        logical_line: NodeRef,
        /// Exact Java UTF-16 key.
        key: JavaString,
        /// Exact Java UTF-16 value.
        value: JavaString,
        /// Implicit, explicit-empty, or present state.
        value_state: PropertiesValueState,
        /// Exact-key duplicate group, when present.
        duplicate_group: Option<u32>,
    },
    /// One exact natural source line.
    NaturalLine {
        /// Zero-based source-order natural-line ordinal.
        ordinal: usize,
        /// Natural-line identity.
        node: NodeRef,
        /// Complete raw line span including its terminator.
        span: Span,
    },
    /// One property or recovered-error logical line.
    LogicalLine {
        /// Zero-based logical-line ordinal.
        ordinal: usize,
        /// Logical-line identity.
        node: NodeRef,
        /// Logical record kind.
        kind: PropertiesLogicalLineKind,
    },
    /// One retained property escape.
    Escape {
        /// Zero-based source-order escape ordinal.
        ordinal: usize,
        /// Escape identity.
        node: NodeRef,
        /// Owning property identity.
        property: NodeRef,
        /// Whether the output belongs to the property key.
        in_key: bool,
        /// Escape behavior.
        kind: PropertiesEscapeKind,
        /// Complete raw escape range.
        span: Span,
        /// Half-open Java UTF-16 output range.
        output_start: usize,
        /// Exclusive Java UTF-16 output boundary.
        output_end: usize,
    },
}

impl PropertiesMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Document { node }
            | Self::Property { node, .. }
            | Self::NaturalLine { node, .. }
            | Self::LogicalLine { node, .. }
            | Self::Escape { node, .. } => *node,
        }
    }
}

/// Owned snapshot-bound Java Properties lossless syntax query match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropertiesSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: PropertiesSyntaxKind,
    ordinal: usize,
}

impl PropertiesSyntaxMatch {
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
    pub const fn kind(self) -> PropertiesSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Executes a validated Properties native semantic query against one snapshot.
pub fn execute_properties_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<PropertiesMatch>, QueryFailure> {
    if executable.definition().domain().id() != "java-properties.native-semantic-query"
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
    let input = vec![PropertiesMatch::Document {
        node: document.node_ref(),
    }];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes a complete Properties native result through an ordered cursor.
pub fn execute_properties_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<PropertiesMatch>, QueryFailure> {
    let result = execute_properties_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated Properties lossless syntax query in raw source order.
pub fn execute_properties_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<PropertiesSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "java-properties.lossless-syntax-query"
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
        input.push(PropertiesSyntaxMatch {
            node: document
                .authority
                .node_ref(identity, NodeRole::PropertiesSyntaxPiece),
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

/// Executes and exposes a complete Properties syntax result through an ordered cursor.
pub fn execute_properties_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<PropertiesSyntaxMatch>, QueryFailure> {
    let result = execute_properties_syntax_query(executable, document, limits, cancellation)?;
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

    fn property_match(&self, ordinal: usize) -> PropertiesMatch {
        let property = &self.document.properties()[ordinal];
        PropertiesMatch::Property {
            ordinal,
            node: property.node_ref(),
            logical_line: property.logical_line(),
            key: property.key().clone(),
            value: property.value().clone(),
            value_state: property.value_state(),
            duplicate_group: property.duplicate_group(),
        }
    }

    fn natural_line_match(&self, ordinal: usize) -> PropertiesMatch {
        let line = &self.document.natural_lines()[ordinal];
        PropertiesMatch::NaturalLine {
            ordinal,
            node: line.node_ref(),
            span: line.span(),
        }
    }

    fn logical_line_match(&self, ordinal: usize) -> PropertiesMatch {
        let line = &self.document.logical_lines()[ordinal];
        PropertiesMatch::LogicalLine {
            ordinal,
            node: line.node_ref(),
            kind: line.kind(),
        }
    }

    fn escape_match(&self, ordinal: usize) -> PropertiesMatch {
        let escape = &self.document.escapes()[ordinal];
        let output = escape.output_range();
        PropertiesMatch::Escape {
            ordinal,
            node: escape.node_ref(),
            property: escape.property(),
            in_key: escape.in_key(),
            kind: escape.kind(),
            span: escape.span(),
            output_start: output.start,
            output_end: output.end,
        }
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[PropertiesMatch],
    context: &mut Context<'_>,
) -> Result<Vec<PropertiesMatch>, QueryFailure> {
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
            output.sort_by_key(|item| source_order(context.document, item));
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn execute_syntax_expression(
    expression: &QueryExpression,
    input: &[PropertiesSyntaxMatch],
    context: &mut Context<'_>,
) -> Result<Vec<PropertiesSyntaxMatch>, QueryFailure> {
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

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<PropertiesMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<PropertiesMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "properties.document-properties" => {
            for item in input {
                if matches!(item, PropertiesMatch::Document { .. }) {
                    for ordinal in 0..context.document.properties().len() {
                        context.push(&mut output, context.property_match(ordinal))?;
                    }
                }
            }
        }
        "properties.natural-lines" => {
            for item in input {
                if matches!(item, PropertiesMatch::Document { .. }) {
                    for ordinal in 0..context.document.natural_lines().len() {
                        context.push(&mut output, context.natural_line_match(ordinal))?;
                    }
                }
            }
        }
        "properties.logical-lines" => {
            for item in input {
                if matches!(item, PropertiesMatch::Document { .. }) {
                    for ordinal in 0..context.document.logical_lines().len() {
                        context.push(&mut output, context.logical_line_match(ordinal))?;
                    }
                }
            }
        }
        "properties.logical-line-natural-lines" => {
            for item in input {
                if let PropertiesMatch::LogicalLine { node, .. } = item {
                    let logical = context
                        .document
                        .logical_line(node)
                        .expect("query logical line belongs to the bound document");
                    for natural in logical.natural_lines() {
                        let ordinal = context
                            .document
                            .natural_lines()
                            .iter()
                            .position(|candidate| candidate.node_ref() == *natural)
                            .expect("logical line owns a bound natural line");
                        context.push(&mut output, context.natural_line_match(ordinal))?;
                    }
                }
            }
        }
        "properties.property-key-equals" => {
            let expected = operator.arguments()["key"]
                .as_bytes()
                .expect("validated UTF16BE/1 bytes");
            for item in input {
                let matches = matches!(
                    &item,
                    PropertiesMatch::Property { key, .. }
                        if java_string_equals_utf16be(key, expected)
                );
                if matches {
                    context.push(&mut output, item)?;
                }
            }
        }
        "properties.property-value-state-is" => {
            let expected = match operator.arguments()["state"]
                .as_string()
                .expect("validated state")
            {
                "ImplicitEmpty" => PropertiesValueState::ImplicitEmpty,
                "ExplicitEmpty" => PropertiesValueState::ExplicitEmpty,
                "Present" => PropertiesValueState::Present,
                _ => unreachable!("state was validated before binding"),
            };
            for item in input {
                if matches!(
                    &item,
                    PropertiesMatch::Property { value_state, .. } if *value_state == expected
                ) {
                    context.push(&mut output, item)?;
                }
            }
        }
        "properties.property-escapes" => {
            for item in input {
                if let PropertiesMatch::Property { node, .. } = item {
                    for (ordinal, escape) in context.document.escapes().iter().enumerate() {
                        if escape.property() == node {
                            context.push(&mut output, context.escape_match(ordinal))?;
                        }
                    }
                }
            }
        }
        "properties.duplicate-group" => {
            for item in input {
                if let PropertiesMatch::Property {
                    duplicate_group: Some(group),
                    ..
                } = item
                {
                    for ordinal in 0..context.document.properties().len() {
                        if context.document.properties()[ordinal].duplicate_group() == Some(group) {
                            context.push(&mut output, context.property_match(ordinal))?;
                        }
                    }
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
                if seen.insert(item.identity()) {
                    context.push(&mut output, item)?;
                }
            }
        }
        _ => unreachable!("validated Properties native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<PropertiesSyntaxMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<PropertiesSyntaxMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "properties.syntax-kind-is" => {
            let expected = PropertiesSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind"),
            )
            .expect("kind name was validated before binding");
            for item in input.into_iter().filter(|item| item.kind == expected) {
                context.push(&mut output, item)?;
            }
        }
        "properties.syntax-text-equals" => {
            let expected = operator.arguments()["text"]
                .as_string()
                .expect("validated text");
            for item in input {
                if decoded_span_text(context.document, item.span) == expected {
                    context.push(&mut output, item)?;
                }
            }
        }
        "properties.syntax-raw-bytes-equals" => {
            let expected = operator.arguments()["bytes"]
                .as_bytes()
                .expect("validated bytes");
            for item in input {
                let span = item.span;
                if &context.document.render()[span.start_byte()..span.end_byte()] == expected {
                    context.push(&mut output, item)?;
                }
            }
        }
        "properties.syntax-utf16be-equals" => {
            let expected = operator.arguments()["code_units"]
                .as_bytes()
                .expect("validated UTF16BE/1 bytes");
            for item in input {
                if unicode_text_equals_utf16be(
                    decoded_span_text(context.document, item.span),
                    expected,
                ) {
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
        _ => unreachable!("validated Properties syntax operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn source_order(document: &Document, item: &PropertiesMatch) -> (usize, usize) {
    match item {
        PropertiesMatch::Document { .. } => (0, 0),
        PropertiesMatch::Property { ordinal, node, .. } => (
            document
                .property(*node)
                .expect("query property belongs to document")
                .span()
                .start_byte(),
            *ordinal,
        ),
        PropertiesMatch::NaturalLine { ordinal, span, .. }
        | PropertiesMatch::Escape { ordinal, span, .. } => (span.start_byte(), *ordinal),
        PropertiesMatch::LogicalLine { ordinal, node, .. } => {
            let logical = document
                .logical_line(*node)
                .expect("query logical line belongs to document");
            let start = logical
                .natural_lines()
                .first()
                .and_then(|natural| document.natural_line(*natural).ok())
                .map_or(0, |natural| natural.span().start_byte());
            (start, *ordinal)
        }
    }
}

fn decoded_span_text(document: &Document, span: Span) -> &str {
    let start = document
        .source()
        .decoded_position(span.start_byte())
        .expect("syntax span starts on a decoded boundary")
        .decoded_utf8_byte;
    let end = document
        .source()
        .decoded_position(span.end_byte())
        .expect("syntax span ends on a decoded boundary")
        .decoded_utf8_byte;
    &document
        .source()
        .decoded_text()
        .expect("Properties source is text")[start..end]
}

fn java_string_equals_utf16be(value: &JavaString, expected: &[u8]) -> bool {
    value.code_units().len().checked_mul(2) == Some(expected.len())
        && value
            .code_units()
            .iter()
            .zip(expected.chunks_exact(2))
            .all(|(unit, bytes)| unit.to_be_bytes() == bytes)
}

fn unicode_text_equals_utf16be(value: &str, expected: &[u8]) -> bool {
    let mut expected = expected.chunks_exact(2);
    for unit in value.encode_utf16() {
        if expected
            .next()
            .is_none_or(|bytes| unit.to_be_bytes() != bytes)
        {
            return false;
        }
    }
    expected.next().is_none()
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
    use crate::{PropertiesParseLimits, parse_reader};
    use consema_core::{
        CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
        QueryExpression, QueryTerminalState,
    };
    use consema_document::SourceEncoding;

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::java_properties_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    #[test]
    fn native_query_preserves_exact_keys_duplicates_and_escape_ownership() {
        let document = parse_reader(
            b"a\\ key=one\\u0021\na\\ key=two\nempty\n".as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        let matches = QueryExpression::Input
            .then(OperatorCall::new("properties.document-properties", 1))
            .then(
                OperatorCall::new("properties.property-key-equals", 1)
                    .with_argument("key", PortableValue::bytes(b"\0a\0 \0k\0e\0y".as_slice())),
            )
            .then(OperatorCall::new("core.take", 1).with_argument(
                "count",
                PortableValue::integer(consema_core::BigInteger::from(1_i64)),
            ))
            .then(OperatorCall::new("properties.duplicate-group", 1));
        let result = execute_properties_query(
            &executable(matches),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);

        let escapes = QueryExpression::Input
            .then(OperatorCall::new("properties.document-properties", 1))
            .then(OperatorCall::new("core.take", 1).with_argument(
                "count",
                PortableValue::integer(consema_core::BigInteger::from(1_i64)),
            ))
            .then(OperatorCall::new("properties.property-escapes", 1));
        let result = execute_properties_query(
            &executable(escapes),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);
        assert!(
            result
                .matches()
                .iter()
                .all(|item| matches!(item, PropertiesMatch::Escape { .. }))
        );
    }

    #[test]
    fn logical_query_returns_exact_natural_line_constituents() {
        let document = parse_reader(
            b"k=one\\\r\n two\n".as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        let expression = QueryExpression::Input
            .then(OperatorCall::new("properties.logical-lines", 1))
            .then(OperatorCall::new(
                "properties.logical-line-natural-lines",
                1,
            ));
        let result = execute_properties_query(
            &executable(expression),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);
        assert!(matches!(
            result.matches(),
            [
                PropertiesMatch::NaturalLine { ordinal: 0, .. },
                PropertiesMatch::NaturalLine { ordinal: 1, .. }
            ]
        ));
    }

    #[test]
    fn syntax_query_supports_text_raw_bytes_and_utf16be() {
        let document = parse_reader(
            "π=值\n".as_bytes(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        let text = QueryExpression::Input.then(
            OperatorCall::new("properties.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("值")),
        );
        let raw = QueryExpression::Input.then(
            OperatorCall::new("properties.syntax-raw-bytes-equals", 1)
                .with_argument("bytes", PortableValue::bytes("π".as_bytes())),
        );
        let utf16 = QueryExpression::Input.then(
            OperatorCall::new("properties.syntax-utf16be-equals", 1)
                .with_argument("code_units", PortableValue::bytes([0x50, 0x3C].as_slice())),
        );
        let executable = QueryDefinition::new(QueryDomain::java_properties_lossless_syntax_v1())
            .with_expression(QueryExpression::StructureOrderMerge(vec![text, raw, utf16]))
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = execute_properties_syntax_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].kind(), PropertiesSyntaxKind::Key);
        assert_eq!(
            result.matches()[0].node_ref().role(),
            NodeRole::PropertiesSyntaxPiece
        );
        assert_eq!(result.matches()[1].kind(), PropertiesSyntaxKind::Value);
        assert_eq!(result.matches()[2].kind(), PropertiesSyntaxKind::Value);
    }

    #[test]
    fn validation_limits_and_cursor_cancellation_are_explicit() {
        let invalid = QueryDefinition::new(QueryDomain::java_properties_native_v1())
            .with_expression(
                QueryExpression::Input
                    .then(OperatorCall::new("properties.document-properties", 1))
                    .then(
                        OperatorCall::new("properties.property-key-equals", 1)
                            .with_argument("key", PortableValue::bytes([0].as_slice())),
                    ),
            )
            .validate();
        assert!(matches!(
            invalid,
            Err(QueryFailure::InvalidArgument { argument, .. }) if argument == "key"
        ));

        let document = parse_reader(
            b"a=1\nb=2\n".as_slice(),
            SourceEncoding::Utf8,
            PropertiesParseLimits::default(),
        )
        .unwrap();
        let all = executable(
            QueryExpression::Input.then(OperatorCall::new("properties.document-properties", 1)),
        );
        assert_eq!(
            execute_properties_query(
                &all,
                &document,
                QueryLimits {
                    max_steps: 100,
                    max_results: 1,
                },
                &CancellationToken::new(),
            ),
            Err(QueryFailure::ResourceLimitExceeded)
        );
        let cancellation = CancellationToken::new();
        let mut cursor =
            execute_properties_query_cursor(&all, &document, QueryLimits::default(), &cancellation)
                .unwrap();
        assert!(cursor.next().is_some());
        cancellation.cancel();
        assert!(cursor.next().is_none());
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Cancelled));
    }
}
