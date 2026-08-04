//! Shared language-neutral JSON/TOML lossless syntax-query conformance runner.

use super::{ConformanceReport, VectorCase, ensure, object_field};
use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, OperatorCall, OrderedQueryCursor,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QuerySelection, QueryTerminalState,
};
use consema_document::{NodeRole, ParseLimits};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget,
    execute_json_syntax_query, parse as parse_json,
};
use consema_protocol::query_failure_code;
use consema_toml::{TomlProfile, execute_toml_syntax_query, parse as parse_toml};
use std::collections::HashSet;

/// Embedded shared syntax-query suite bytes.
pub const SYNTAX_QUERY_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/syntax-query-v1.json");

/// Runs the embedded `consema.syntax-query.conformance@1` suite.
#[must_use]
pub fn run_syntax_query_v1() -> ConformanceReport {
    run_syntax_query_v1_json(SYNTAX_QUERY_V1_VECTORS_JSON)
}

/// Runs one shared syntax-query suite from JSON text.
#[must_use]
pub fn run_syntax_query_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse_json(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published syntax-query vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: "consema.syntax-query.conformance@1".to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("syntax-query vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for case in cases {
        let fields = case.as_object().expect("syntax-query case object");
        let id = object_field(fields, "id")
            .and_then(PortableValue::as_string)
            .expect("case id");
        let capability = object_field(fields, "capability")
            .and_then(PortableValue::as_string)
            .expect("case capability");
        let input = object_field(fields, "input").expect("case input");
        let expected = object_field(fields, "expected").expect("case expected");
        if !seen.insert(id) {
            report
                .failed
                .push((id.to_owned(), "duplicate case id".to_owned()));
            continue;
        }
        let vector = VectorCase {
            id,
            capability,
            input,
            expected,
        };
        match run_case(&vector) {
            Ok(()) => report.passed.push(id.to_owned()),
            Err(error) => report.failed.push((id.to_owned(), error)),
        }
    }
    report
}

fn run_case(case: &VectorCase<'_>) -> Result<(), String> {
    if case.id.starts_with("syntax.json.") {
        run_json(case)
    } else if case.id.starts_with("syntax.toml.") {
        run_toml(case)
    } else if case.id.starts_with("syntax.cursor.") {
        run_cursor(case)
    } else {
        Err("runner does not recognize published syntax-query case".to_owned())
    }
}

fn run_json(case: &VectorCase<'_>) -> Result<(), String> {
    let profile = match input_string(case, "profile")? {
        "json.strict@1" => JsonProfile::StrictV1,
        "jsonc.bounded@1" => JsonProfile::JsoncBoundedV1,
        other => return Err(format!("unknown JSON profile {other}")),
    };
    let document = parse_json(
        input_string(case, "source")?.as_bytes(),
        profile,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let executable = match definition(case, QueryDomain::json_lossless_syntax_v1(), "json") {
        Ok(definition) => definition,
        Err(error) => return expect_failure(case, &error),
    };
    let cancellation = cancellation(case)?;
    match execute_json_syntax_query(&executable, &document, limits(case)?, &cancellation) {
        Ok(result) => {
            let actual = result
                .matches()
                .iter()
                .map(|item| {
                    let span = item.span();
                    (
                        item.kind().as_str(),
                        std::str::from_utf8(
                            &document.source().bytes()[span.start_byte()..span.end_byte()],
                        )
                        .expect("JSON syntax source is UTF-8"),
                        item.ordinal(),
                        item.node_ref().role(),
                    )
                })
                .collect::<Vec<_>>();
            compare_matches(case, &actual, result.terminal_state())
        }
        Err(error) => expect_failure(case, &error),
    }
}

fn run_toml(case: &VectorCase<'_>) -> Result<(), String> {
    if input_string(case, "profile")? != "toml.1.0@1" {
        return Err("unknown TOML profile".to_owned());
    }
    let document = parse_toml(
        input_string(case, "source")?.as_bytes(),
        TomlProfile::Toml10V1,
        ParseLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let executable = match definition(case, QueryDomain::toml_lossless_syntax_v1(), "toml") {
        Ok(definition) => definition,
        Err(error) => return expect_failure(case, &error),
    };
    let cancellation = cancellation(case)?;
    match execute_toml_syntax_query(&executable, &document, limits(case)?, &cancellation) {
        Ok(result) => {
            let actual = result
                .matches()
                .iter()
                .map(|item| {
                    let span = item.span();
                    (
                        item.kind().as_str(),
                        std::str::from_utf8(
                            &document.source().bytes()[span.start_byte()..span.end_byte()],
                        )
                        .expect("TOML syntax source is UTF-8"),
                        item.ordinal(),
                        item.node_ref().role(),
                    )
                })
                .collect::<Vec<_>>();
            compare_matches(case, &actual, result.terminal_state())
        }
        Err(error) => expect_failure(case, &error),
    }
}

fn definition(
    case: &VectorCase<'_>,
    domain: QueryDomain,
    format: &str,
) -> Result<consema_core::ExecutableQuery, QueryFailure> {
    let filter_values = input_field(case, "filters")
        .and_then(|value| {
            value
                .as_sequence()
                .ok_or_else(|| "input.filters must be a Sequence".to_owned())
        })
        .map_err(|_| QueryFailure::InvalidArgument {
            operator: "vector".to_owned(),
            argument: "filters".to_owned(),
        })?;
    let mut branches = Vec::with_capacity(filter_values.len());
    for filter in filter_values {
        let fields = filter
            .as_object()
            .ok_or_else(|| QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: "filter".to_owned(),
            })?;
        let operator = object_field(fields, "operator")
            .and_then(PortableValue::as_string)
            .ok_or_else(|| QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: "operator".to_owned(),
            })?;
        let call = match operator {
            "kind-is" => OperatorCall::new(format!("{format}.syntax-kind-is"), 1).with_argument(
                "kind",
                object_field(fields, "argument").cloned().ok_or_else(|| {
                    QueryFailure::InvalidArgument {
                        operator: operator.to_owned(),
                        argument: "argument".to_owned(),
                    }
                })?,
            ),
            "text-equals" => OperatorCall::new(format!("{format}.syntax-text-equals"), 1)
                .with_argument(
                    "text",
                    object_field(fields, "argument").cloned().ok_or_else(|| {
                        QueryFailure::InvalidArgument {
                            operator: operator.to_owned(),
                            argument: "argument".to_owned(),
                        }
                    })?,
                ),
            "take" => OperatorCall::new("core.take", 1).with_argument(
                "count",
                object_field(fields, "argument").cloned().ok_or_else(|| {
                    QueryFailure::InvalidArgument {
                        operator: operator.to_owned(),
                        argument: "argument".to_owned(),
                    }
                })?,
            ),
            "distinct-by-identity" => OperatorCall::new("core.distinct-by-identity", 1),
            other => OperatorCall::new(other, 1),
        };
        branches.push(QueryExpression::Input.then(call));
    }
    let expression = match input_string(case, "combine").unwrap_or("Single") {
        "Single" if branches.is_empty() => QueryExpression::Input,
        "Single" if branches.len() == 1 => branches.pop().expect("one branch"),
        "StructureOrderMerge" => QueryExpression::StructureOrderMerge(branches),
        "Concat" => QueryExpression::Concat(branches),
        _ => {
            return Err(QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: "combine".to_owned(),
            });
        }
    };
    QueryDefinition::new(domain)
        .with_expression(expression)
        .with_selection(selection(case).map_err(|_| QueryFailure::InvalidArgument {
            operator: "vector".to_owned(),
            argument: "selection".to_owned(),
        })?)
        .validate()?
        .bind(&capabilities())
}

fn compare_matches(
    case: &VectorCase<'_>,
    actual: &[(&str, &str, usize, NodeRole)],
    terminal: QueryTerminalState,
) -> Result<(), String> {
    let expected = expected_field(case, "matches")?
        .as_sequence()
        .ok_or("expected.matches must be a Sequence")?;
    if actual.len() != expected.len() {
        return Err(format!(
            "match count differs: actual {}, expected {}",
            actual.len(),
            expected.len()
        ));
    }
    for ((kind, text, ordinal, role), expected) in actual.iter().zip(expected) {
        let fields = expected
            .as_object()
            .ok_or("expected match must be an Object")?;
        let expected_role = match role {
            NodeRole::JsonSyntaxPiece => "JsonSyntaxPiece",
            NodeRole::TomlSyntaxPiece => "TomlSyntaxPiece",
            _ => return Err("syntax match has the wrong NodeRole".to_owned()),
        };
        ensure(
            *kind
                == object_field(fields, "kind")
                    .and_then(PortableValue::as_string)
                    .ok_or("expected match.kind")?
                && *text
                    == object_field(fields, "text")
                        .and_then(PortableValue::as_string)
                        .ok_or("expected match.text")?
                && *ordinal == object_usize(fields, "ordinal")?
                && expected_role
                    == object_field(fields, "role")
                        .and_then(PortableValue::as_string)
                        .ok_or("expected match.role")?,
        )?;
    }
    ensure(terminal_name(terminal) == expected_string(case, "terminal")?)
}

fn expect_failure(case: &VectorCase<'_>, error: &QueryFailure) -> Result<(), String> {
    ensure(query_failure_code(error) == expected_string(case, "code")?)
}

fn run_cursor(case: &VectorCase<'_>) -> Result<(), String> {
    let values = input_field(case, "values")?
        .as_sequence()
        .ok_or("input.values must be a Sequence")?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_usize)
                .ok_or_else(|| "cursor value must be a host-size Integer".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mode = input_string(case, "mode")?;
    let mut yielded = Vec::new();
    let terminal = match mode {
        "Completed" => {
            let mut cursor = OrderedQueryCursor::new(values);
            while let Some(value) = cursor.next() {
                ensure(cursor.terminal_state().is_none())?;
                yielded.push(value);
            }
            cursor.terminal_state()
        }
        "Cancelled" => {
            let token = CancellationToken::new();
            let mut cursor = OrderedQueryCursor::with_cancellation(values, &token);
            if let Some(value) = cursor.next() {
                ensure(cursor.terminal_state().is_none())?;
                yielded.push(value);
            }
            token.cancel();
            ensure(cursor.next().is_none())?;
            cursor.terminal_state()
        }
        "Failed" => {
            let mut cursor = OrderedQueryCursor::with_terminal(values, QueryTerminalState::Failed);
            while let Some(value) = cursor.next() {
                ensure(cursor.terminal_state().is_none())?;
                yielded.push(value);
            }
            cursor.terminal_state()
        }
        other => return Err(format!("unknown cursor mode {other}")),
    };
    ensure(
        yielded.len() == expected_usize(case, "yielded")?
            && terminal.map(terminal_name) == Some(expected_string(case, "terminal")?),
    )
}

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

fn selection(case: &VectorCase<'_>) -> Result<QuerySelection, String> {
    match input_string(case, "selection").unwrap_or("All") {
        "All" => Ok(QuerySelection::All),
        "First" => Ok(QuerySelection::First),
        "Last" => Ok(QuerySelection::Last),
        "ZeroOrOne" => Ok(QuerySelection::ZeroOrOne),
        "RequireOne" => Ok(QuerySelection::RequireOne),
        other => Err(format!("unknown selection {other}")),
    }
}

fn limits(case: &VectorCase<'_>) -> Result<QueryLimits, String> {
    let mut limits = QueryLimits::default();
    if let Some(value) = input_optional_usize(case, "max_steps")? {
        limits.max_steps = value;
    }
    if let Some(value) = input_optional_usize(case, "max_results")? {
        limits.max_results = value;
    }
    Ok(limits)
}

fn cancellation(case: &VectorCase<'_>) -> Result<CancellationToken, String> {
    let cancellation = CancellationToken::new();
    if input_optional_bool(case, "cancelled")?.unwrap_or(false) {
        cancellation.cancel();
    }
    Ok(cancellation)
}

const fn terminal_name(terminal: QueryTerminalState) -> &'static str {
    match terminal {
        QueryTerminalState::Completed => "Completed",
        QueryTerminalState::Cancelled => "Cancelled",
        QueryTerminalState::Failed => "Failed",
    }
}

fn input_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.input
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing input.{name}"))
}

fn expected_field<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a PortableValue, String> {
    case.expected
        .as_object()
        .and_then(|fields| object_field(fields, name))
        .ok_or_else(|| format!("missing expected.{name}"))
}

fn input_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    input_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("input.{name} must be String"))
}

fn expected_string<'a>(case: &'a VectorCase<'a>, name: &str) -> Result<&'a str, String> {
    expected_field(case, name)?
        .as_string()
        .ok_or_else(|| format!("expected.{name} must be String"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be a host-size Integer"))
}

fn object_usize(fields: &[consema_core::ObjectEntry], name: &str) -> Result<usize, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("{name} must be a host-size Integer"))
}

fn input_optional_usize(case: &VectorCase<'_>, name: &str) -> Result<Option<usize>, String> {
    let Some(value) = case
        .input
        .as_object()
        .and_then(|fields| object_field(fields, name))
    else {
        return Ok(None);
    };
    value
        .as_integer()
        .and_then(BigInteger::to_usize)
        .map(Some)
        .ok_or_else(|| format!("input.{name} must be a host-size Integer"))
}

fn input_optional_bool(case: &VectorCase<'_>, name: &str) -> Result<Option<bool>, String> {
    let Some(value) = case
        .input
        .as_object()
        .and_then(|fields| object_field(fields, name))
    else {
        return Ok(None);
    };
    value
        .as_boolean()
        .map(Some)
        .ok_or_else(|| format!("input.{name} must be Boolean"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_syntax_query_v1_suite_is_conformant() {
        let report = run_syntax_query_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 19);
    }

    #[test]
    fn syntax_query_vectors_drive_input_and_expectations() {
        let changed = SYNTAX_QUERY_V1_VECTORS_JSON.replacen(
            "\"argument\": \"LineComment\"",
            "\"argument\": \"BlockComment\"",
            1,
        );
        let report = run_syntax_query_v1_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "syntax.json.kind-text-order"),
            "{report:#?}"
        );

        let changed = SYNTAX_QUERY_V1_VECTORS_JSON.replacen(
            "\"terminal\": \"Completed\"",
            "\"terminal\": \"Failed\"",
            1,
        );
        assert!(!run_syntax_query_v1_json(&changed).is_conformant());
    }
}
