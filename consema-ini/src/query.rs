use crate::{Document, IniLogicalLineKind, IniProfile, IniSyntaxKind, IniValueState};
use consema_core::{
    CancellationToken, ExecutableQuery, OperatorCall, OrderedQueryCursor, QueryExecution,
    QueryExpression, QueryFailure, QueryLimits, QuerySelection,
};
use consema_document::{NodeRef, NodeRole, Span};
use std::collections::HashSet;

/// Owned snapshot-bound INI native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IniMatch {
    /// Complete INI document.
    Document {
        /// Root document identity.
        node: NodeRef,
    },
    /// One distinct section occurrence.
    Section {
        /// Zero-based source-order section ordinal.
        ordinal: usize,
        /// Section occurrence identity.
        node: NodeRef,
        /// Original section name.
        name: String,
        /// Profile comparison name.
        comparison_name: String,
        /// Whether this is Python's exact default section.
        is_default: bool,
        /// Duplicate/case-equivalence group, when present.
        duplicate_group: Option<u32>,
    },
    /// One distinct entry occurrence.
    Entry {
        /// Zero-based source-order entry ordinal.
        ordinal: usize,
        /// Entry occurrence identity.
        node: NodeRef,
        /// Owning section occurrence.
        section: NodeRef,
        /// Original key spelling.
        key: String,
        /// Profile comparison key.
        comparison_key: String,
        /// Missing, empty, or present value fact.
        value_state: IniValueState,
        /// Duplicate/case-equivalence group, when present.
        duplicate_group: Option<u32>,
    },
    /// One exact physical source line.
    PhysicalLine {
        /// Zero-based source-order physical-line ordinal.
        ordinal: usize,
        /// Physical-line identity.
        node: NodeRef,
        /// Complete raw line span including its line break.
        span: Span,
    },
    /// One logical INI record.
    LogicalLine {
        /// Zero-based logical-record ordinal.
        ordinal: usize,
        /// Logical-line identity.
        node: NodeRef,
        /// Logical record kind.
        kind: IniLogicalLineKind,
    },
}

impl IniMatch {
    fn identity(&self) -> NodeRef {
        match self {
            Self::Document { node }
            | Self::Section { node, .. }
            | Self::Entry { node, .. }
            | Self::PhysicalLine { node, .. }
            | Self::LogicalLine { node, .. } => *node,
        }
    }
}

/// Owned snapshot-bound INI lossless syntax query match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IniSyntaxMatch {
    node: NodeRef,
    span: Span,
    kind: IniSyntaxKind,
    ordinal: usize,
}

impl IniSyntaxMatch {
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
    pub const fn kind(self) -> IniSyntaxKind {
        self.kind
    }

    /// Zero-based source-order position.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Executes a validated INI native semantic query against one immutable snapshot.
pub fn execute_ini_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<IniMatch>, QueryFailure> {
    if executable.definition().domain().id() != "ini.native-semantic-query"
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
    let input = vec![IniMatch::Document {
        node: document.node_ref(),
    }];
    let matches = execute_expression(executable.definition().expression(), &input, &mut context)?;
    let matches = apply_selection(matches, executable.definition().selection())?;
    Ok(QueryExecution::completed(matches))
}

/// Executes and exposes the complete native result through an ordered cursor.
pub fn execute_ini_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<IniMatch>, QueryFailure> {
    let result = execute_ini_query(executable, document, limits, cancellation)?;
    Ok(OrderedQueryCursor::with_cancellation(
        result.matches().to_vec(),
        cancellation,
    ))
}

/// Executes a validated INI lossless syntax query in raw source order.
pub fn execute_ini_syntax_query(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<QueryExecution<IniSyntaxMatch>, QueryFailure> {
    if executable.definition().domain().id() != "ini.lossless-syntax-query"
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
        input.push(IniSyntaxMatch {
            node: document
                .authority
                .node_ref(identity, NodeRole::IniSyntaxPiece),
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

/// Executes an INI syntax query and exposes its complete result as a cancellable cursor.
pub fn execute_ini_syntax_query_cursor(
    executable: &ExecutableQuery,
    document: &Document,
    limits: QueryLimits,
    cancellation: &CancellationToken,
) -> Result<OrderedQueryCursor<IniSyntaxMatch>, QueryFailure> {
    let result = execute_ini_syntax_query(executable, document, limits, cancellation)?;
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

    fn section_match(&self, ordinal: usize) -> IniMatch {
        let section = &self.document.sections()[ordinal];
        IniMatch::Section {
            ordinal,
            node: section.node_ref(),
            name: section.name().to_owned(),
            comparison_name: section.comparison_name().to_owned(),
            is_default: section.is_default(),
            duplicate_group: section.duplicate_group(),
        }
    }

    fn entry_match(&self, ordinal: usize) -> IniMatch {
        let entry = &self.document.entries()[ordinal];
        IniMatch::Entry {
            ordinal,
            node: entry.node_ref(),
            section: entry.section(),
            key: entry.key().to_owned(),
            comparison_key: entry.comparison_key().to_owned(),
            value_state: entry.value_state(),
            duplicate_group: entry.duplicate_group(),
        }
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[IniMatch],
    context: &mut Context<'_>,
) -> Result<Vec<IniMatch>, QueryFailure> {
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
    input: &[IniSyntaxMatch],
    context: &mut Context<'_>,
) -> Result<Vec<IniSyntaxMatch>, QueryFailure> {
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

fn apply_syntax_operator(
    operator: &OperatorCall,
    input: Vec<IniSyntaxMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<IniSyntaxMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "ini.syntax-kind-is" => {
            let expected = IniSyntaxKind::from_name(
                operator.arguments()["kind"]
                    .as_string()
                    .expect("validated kind argument"),
            )
            .expect("kind name was validated before binding");
            for item in input.into_iter().filter(|item| item.kind == expected) {
                context.push(&mut output, item)?;
            }
        }
        "ini.syntax-text-equals" => {
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
        _ => unreachable!("validated INI syntax operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn apply_operator(
    operator: &OperatorCall,
    input: Vec<IniMatch>,
    context: &mut Context<'_>,
) -> Result<Vec<IniMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "ini.document-sections" => {
            for item in input {
                if matches!(item, IniMatch::Document { .. }) {
                    for ordinal in 0..context.document.sections().len() {
                        context.push(&mut output, context.section_match(ordinal))?;
                    }
                }
            }
        }
        "ini.section-entries" => {
            for item in input {
                if let IniMatch::Section { node, .. } = item {
                    for (ordinal, entry) in context.document.entries().iter().enumerate() {
                        if entry.section() == node {
                            context.push(&mut output, context.entry_match(ordinal))?;
                        }
                    }
                }
            }
        }
        "ini.all-entries" => {
            for item in input {
                if matches!(item, IniMatch::Document { .. }) {
                    for ordinal in 0..context.document.entries().len() {
                        context.push(&mut output, context.entry_match(ordinal))?;
                    }
                }
            }
        }
        "ini.entry-section" => {
            for item in input {
                if let IniMatch::Entry { section, .. } = item {
                    let ordinal = context
                        .document
                        .sections()
                        .iter()
                        .position(|candidate| candidate.node_ref() == section)
                        .expect("entry section belongs to the bound document");
                    context.push(&mut output, context.section_match(ordinal))?;
                }
            }
        }
        "ini.section-name-equals" => {
            let expected = operator.arguments()["name"]
                .as_string()
                .expect("validated name argument");
            let comparison = operator.arguments()["comparison"]
                .as_string()
                .expect("validated comparison argument");
            let equivalent = section_comparison(context.document.profile, expected);
            for item in input {
                let matches = match &item {
                    IniMatch::Section {
                        name,
                        comparison_name,
                        ..
                    } => {
                        if comparison == "OriginalExact" {
                            name == expected
                        } else {
                            comparison_name == &equivalent
                        }
                    }
                    _ => false,
                };
                if matches {
                    context.push(&mut output, item)?;
                }
            }
        }
        "ini.entry-key-equals" => {
            let expected = operator.arguments()["key"]
                .as_string()
                .expect("validated key argument");
            let comparison = operator.arguments()["comparison"]
                .as_string()
                .expect("validated comparison argument");
            let equivalent = key_comparison(context.document.profile, expected);
            for item in input {
                let matches = match &item {
                    IniMatch::Entry {
                        key,
                        comparison_key,
                        ..
                    } => {
                        if comparison == "OriginalExact" {
                            key == expected
                        } else {
                            comparison_key == &equivalent
                        }
                    }
                    _ => false,
                };
                if matches {
                    context.push(&mut output, item)?;
                }
            }
        }
        "ini.entry-value-state-is" => {
            let expected = match operator.arguments()["state"]
                .as_string()
                .expect("validated state argument")
            {
                "Missing" => IniValueState::Missing,
                "Empty" => IniValueState::Empty,
                "Present" => IniValueState::Present,
                _ => unreachable!("state was validated before binding"),
            };
            for item in input {
                if matches!(&item, IniMatch::Entry { value_state, .. } if *value_state == expected)
                {
                    context.push(&mut output, item)?;
                }
            }
        }
        "ini.duplicate-group" => {
            for item in input {
                match item {
                    IniMatch::Section {
                        duplicate_group: Some(group),
                        ..
                    } => {
                        for ordinal in 0..context.document.sections().len() {
                            if context.document.sections()[ordinal].duplicate_group() == Some(group)
                            {
                                context.push(&mut output, context.section_match(ordinal))?;
                            }
                        }
                    }
                    IniMatch::Entry {
                        duplicate_group: Some(group),
                        ..
                    } => {
                        for ordinal in 0..context.document.entries().len() {
                            if context.document.entries()[ordinal].duplicate_group() == Some(group)
                            {
                                context.push(&mut output, context.entry_match(ordinal))?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "ini.physical-lines" => {
            for item in input {
                if matches!(item, IniMatch::Document { .. }) {
                    for (ordinal, line) in context.document.physical_lines().iter().enumerate() {
                        context.push(
                            &mut output,
                            IniMatch::PhysicalLine {
                                ordinal,
                                node: line.node_ref(),
                                span: line.span(),
                            },
                        )?;
                    }
                }
            }
        }
        "ini.logical-lines" => {
            for item in input {
                if matches!(item, IniMatch::Document { .. }) {
                    for (ordinal, line) in context.document.logical_lines().iter().enumerate() {
                        context.push(
                            &mut output,
                            IniMatch::LogicalLine {
                                ordinal,
                                node: line.node_ref(),
                                kind: line.kind(),
                            },
                        )?;
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
        _ => unreachable!("validated INI native operator"),
    }
    context.step(output.len())?;
    Ok(output)
}

fn source_order(document: &Document, item: &IniMatch) -> (usize, usize) {
    match item {
        IniMatch::Document { .. } => (0, 0),
        IniMatch::Section { ordinal, node, .. } => (
            document
                .section(*node)
                .expect("query section belongs to document")
                .span()
                .start_byte(),
            *ordinal,
        ),
        IniMatch::Entry { ordinal, node, .. } => (
            document
                .entry(*node)
                .expect("query entry belongs to document")
                .span()
                .start_byte(),
            *ordinal,
        ),
        IniMatch::PhysicalLine { ordinal, span, .. } => (span.start_byte(), *ordinal),
        IniMatch::LogicalLine { ordinal, node, .. } => {
            let logical = document
                .logical_line(*node)
                .expect("query logical line belongs to document");
            let start = logical
                .physical_lines()
                .first()
                .and_then(|physical| document.physical_line(*physical).ok())
                .map_or(0, |physical| physical.span().start_byte());
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
        .expect("INI source is text")[start..end]
}

fn section_comparison(profile: IniProfile, name: &str) -> String {
    match profile {
        IniProfile::WindowsV1 => name.to_ascii_lowercase(),
        IniProfile::PortableV1 | IniProfile::PythonConfigParserV1 => name.to_owned(),
    }
}

fn key_comparison(profile: IniProfile, key: &str) -> String {
    match profile {
        IniProfile::PortableV1 => key.to_owned(),
        IniProfile::WindowsV1 => key.to_ascii_lowercase(),
        IniProfile::PythonConfigParserV1 => crate::python_case::optionxform(key),
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
    use crate::{IniEncodingSelection, IniParseLimits, parse};
    use consema_core::{
        CapabilityId, CapabilitySet, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
        QueryExpression, QueryTerminalState,
    };

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    fn executable(expression: QueryExpression) -> ExecutableQuery {
        QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(expression)
            .validate()
            .expect("valid query")
            .bind(&capabilities())
            .expect("capabilities")
    }

    fn utf16le_bom(text: &str) -> Vec<u8> {
        let mut output = vec![0xff, 0xfe];
        output.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        output
    }

    #[test]
    fn native_query_keeps_profile_equivalence_duplicates_and_ownership() {
        let document = parse(
            b"[Main]\r\nName=one\r\nname=two\r\n[Other]\r\nempty=\r\n".as_slice(),
            IniProfile::WindowsV1,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap();
        let main_entries = QueryExpression::Input
            .then(OperatorCall::new("ini.document-sections", 1))
            .then(
                OperatorCall::new("ini.section-name-equals", 1)
                    .with_argument("name", PortableValue::string("MAIN"))
                    .with_argument("comparison", PortableValue::string("ProfileEquivalent")),
            )
            .then(OperatorCall::new("ini.section-entries", 1));
        let result = execute_ini_query(
            &executable(main_entries),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);
        assert!(result.matches().iter().all(|item| matches!(
            item,
            IniMatch::Entry {
                duplicate_group: Some(_),
                ..
            }
        )));

        let group = QueryExpression::Input
            .then(OperatorCall::new("ini.all-entries", 1))
            .then(
                OperatorCall::new("ini.entry-key-equals", 1)
                    .with_argument("key", PortableValue::string("Name"))
                    .with_argument("comparison", PortableValue::string("OriginalExact")),
            )
            .then(OperatorCall::new("ini.duplicate-group", 1));
        let result = execute_ini_query(
            &executable(group),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 2);
        assert!(matches!(
            &result.matches()[1],
            IniMatch::Entry { key, .. } if key == "name"
        ));

        let empty_section = QueryExpression::Input
            .then(OperatorCall::new("ini.all-entries", 1))
            .then(
                OperatorCall::new("ini.entry-value-state-is", 1)
                    .with_argument("state", PortableValue::string("Empty")),
            )
            .then(OperatorCall::new("ini.entry-section", 1));
        let result = execute_ini_query(
            &executable(empty_section),
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(matches!(
            result.matches(),
            [IniMatch::Section { name, .. }] if name == "Other"
        ));
    }

    #[test]
    fn syntax_query_matches_decoded_text_for_utf16_and_keeps_order() {
        let document = parse(
            utf16le_bom("[S]\r\nName=\" value \"\r\n"),
            IniProfile::WindowsV1,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap();
        let quote = QueryExpression::Input.then(
            OperatorCall::new("ini.syntax-kind-is", 1)
                .with_argument("kind", PortableValue::string("Quote")),
        );
        let name = QueryExpression::Input.then(
            OperatorCall::new("ini.syntax-text-equals", 1)
                .with_argument("text", PortableValue::string("Name")),
        );
        let executable = QueryDefinition::new(QueryDomain::ini_lossless_syntax_v1())
            .with_expression(QueryExpression::StructureOrderMerge(vec![quote, name]))
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = execute_ini_syntax_query(
            &executable,
            &document,
            QueryLimits::default(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(result.matches().len(), 3);
        assert_eq!(result.matches()[0].kind(), IniSyntaxKind::EntryKey);
        assert_eq!(
            result.matches()[0].node_ref().role(),
            NodeRole::IniSyntaxPiece
        );
        assert_eq!(result.matches()[1].kind(), IniSyntaxKind::Quote);
        assert!(result.matches()[0].ordinal() < result.matches()[1].ordinal());
    }

    #[test]
    fn query_validation_limits_and_cursor_cancellation_are_explicit() {
        let invalid = QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(
                QueryExpression::Input.then(
                    OperatorCall::new("ini.section-name-equals", 1)
                        .with_argument("name", PortableValue::string("S"))
                        .with_argument("comparison", PortableValue::string("Implicit")),
                ),
            )
            .validate();
        assert!(matches!(
            invalid,
            Err(QueryFailure::InvalidOperatorComposition { .. })
        ));
        let invalid_comparison = QueryDefinition::new(QueryDomain::ini_native_v1())
            .with_expression(
                QueryExpression::Input
                    .then(OperatorCall::new("ini.document-sections", 1))
                    .then(
                        OperatorCall::new("ini.section-name-equals", 1)
                            .with_argument("name", PortableValue::string("S"))
                            .with_argument("comparison", PortableValue::string("Implicit")),
                    ),
            )
            .validate();
        assert!(matches!(
            invalid_comparison,
            Err(QueryFailure::InvalidArgument { argument, .. }) if argument == "comparison"
        ));

        let document = parse(
            b"[s]\na=1\nb=2\n".as_slice(),
            IniProfile::PortableV1,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap();
        let all_entries =
            executable(QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1)));
        assert_eq!(
            execute_ini_query(
                &all_entries,
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
        let mut cursor = execute_ini_query_cursor(
            &all_entries,
            &document,
            QueryLimits::default(),
            &cancellation,
        )
        .unwrap();
        assert!(cursor.next().is_some());
        cancellation.cancel();
        assert!(cursor.next().is_none());
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Cancelled));
    }
}
