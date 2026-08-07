//! Shared language-neutral `xml.1.0-safe@1` conformance runner.

use super::{ConformanceReport, ensure, object_field};
use consema_core::{
    CancellationToken, ObjectBuilder, OperatorCall, PortableValue, QueryDefinition, QueryDomain,
    QueryExpression, QueryLimits, QuerySelection,
};
use consema_document::{
    FormationStatus, MaterializationFailure, MaterializationRequest, MaterializationResult,
    NodeRole, SourceEncoding,
};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_xml::{
    AttributePlacement, ContentPlacement, EditTransactionBuilder, NameFacts, ProjectionRequest,
    XmlEncodingSelection, XmlParseLimits, XmlProfile, execute_xml_query, execute_xml_syntax_query,
    materialize, parse as parse_xml,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Frozen suite identifier expected in every XML vector file.
const SUITE: &str = "consema.xml-1-0-safe.conformance@1";

/// Embedded shared XML suite bytes.
pub const XML_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/xml-1-0-safe-v1.json");

/// Runs the embedded `consema.xml-1-0-safe.conformance@1` suite.
#[must_use]
pub fn run_xml_v1() -> ConformanceReport {
    run_xml_v1_json(XML_V1_VECTORS_JSON)
}

/// Runs one XML suite from JSON text.
#[must_use]
pub fn run_xml_v1_json(json: &str) -> ConformanceReport {
    let vectors = parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        consema_document::ParseLimits::default(),
    )
    .expect("published XML vector JSON must form a document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let value = match vectors.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value.as_object().expect("XML vector root object");
    let suite = object_field(root, "suite")
        .and_then(PortableValue::as_string)
        .expect("suite field")
        .to_owned();
    if suite != SUITE {
        return ConformanceReport {
            suite,
            passed: Vec::new(),
            failed: vec![(
                "suite.schema".to_owned(),
                "unexpected suite identifier".to_owned(),
            )],
        };
    }
    let cases = object_field(root, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");
    let mut seen = HashSet::new();
    let mut report = ConformanceReport {
        suite,
        passed: Vec::new(),
        failed: Vec::new(),
    };
    for (index, case) in cases.iter().enumerate() {
        let id = object_value_field(case, "id")
            .and_then(PortableValue::as_string)
            .unwrap_or(&format!("case.{index}"))
            .to_owned();
        if !seen.insert(id.clone()) {
            report.failed.push((id, "duplicate case id".to_owned()));
            continue;
        }
        let result = run_case(case);
        match result {
            Ok(()) => report.passed.push(id),
            Err(message) => report.failed.push((id, message)),
        }
    }
    report
}

fn run_case(case: &PortableValue) -> Result<(), String> {
    let capability = object_value_field(case, "capability")
        .and_then(PortableValue::as_string)
        .ok_or("missing capability")?;
    match capability {
        "xml.formation@1" => run_formation(case),
        "xml.syntax-query@1" => run_syntax_query(case),
        "xml.native-query@1" => run_native_query(case),
        "xml.projection@1" => run_projection(case),
        "xml.materialization@1" => run_materialization(case),
        "xml.edit@1" => run_edit(case),
        "xml.limit@1" => run_limit(case),
        _ => Err(format!("unknown capability {capability}")),
    }
}

fn object_value_field<'v>(value: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    value
        .as_object()
        .and_then(|object| object_field(object, name))
}

fn input_field<'v>(case: &'v PortableValue, name: &str) -> Option<&'v PortableValue> {
    object_value_field(case, "input").and_then(|input| object_value_field(input, name))
}

fn source_string(case: &PortableValue) -> Result<String, String> {
    input_field(case, "source")
        .and_then(PortableValue::as_string)
        .map(str::to_owned)
        .ok_or_else(|| "missing input.source".to_owned())
}

fn parse_limits(case: &PortableValue) -> XmlParseLimits {
    let mut limits = XmlParseLimits::default();
    if let Some(ratio) = input_field(case, "amplification_ratio")
        .and_then(PortableValue::as_integer)
        .and_then(consema_core::BigInteger::to_i64)
        .and_then(|value| u64::try_from(value).ok())
    {
        limits.max_entity_amplification_ratio = ratio;
    }
    if let Some(items) = input_field(case, "max_mixed_content_items")
        .and_then(PortableValue::as_integer)
        .and_then(consema_core::BigInteger::to_usize)
    {
        limits.max_mixed_content_items = items;
    }
    limits
}

fn form_document(case: &PortableValue) -> Result<consema_xml::Document, String> {
    let source = source_string(case)?;
    let bytes: Arc<[u8]> = match input_field(case, "encoding").and_then(PortableValue::as_string) {
        Some("utf16le-bom") => {
            let mut bytes = vec![0xFF, 0xFE];
            for unit in source.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            Arc::from(bytes)
        }
        _ => Arc::from(source.into_bytes()),
    };
    parse_xml(
        bytes,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        parse_limits(case),
    )
    .map_err(|failure| format!("{failure:?}"))
}

fn expected_string(case: &PortableValue, name: &str) -> Result<String, String> {
    object_value_field(case, "expected")
        .and_then(|expected| object_value_field(expected, name))
        .and_then(PortableValue::as_string)
        .map(str::to_owned)
        .ok_or(format!("missing expected.{name}"))
}

fn run_formation(case: &PortableValue) -> Result<(), String> {
    let document = form_document(case)?;
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    let status = object_value_field(expected, "status")
        .and_then(PortableValue::as_string)
        .ok_or("missing expected.status")?;
    let actual_status = match document.status() {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    };
    ensure(actual_status == status).map_err(|_| format!("status {actual_status} != {status}"))?;
    if status == "Complete" {
        if let Some(render) =
            object_value_field(expected, "render").and_then(PortableValue::as_string)
        {
            let actual = std::str::from_utf8(document.render())
                .map_err(|_| "render is not UTF-8".to_owned())?;
            ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
        }
        if let Some(hex) =
            object_value_field(expected, "render_hex").and_then(PortableValue::as_string)
        {
            let actual = document
                .render()
                .iter()
                .fold(String::new(), |mut out, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{byte:02x}");
                    out
                });
            ensure(actual == hex).map_err(|_| format!("render_hex {actual} != {hex}"))?;
        }
    }
    if let Some(diagnostic) =
        object_value_field(expected, "diagnostic").and_then(PortableValue::as_string)
    {
        ensure(document.diagnostics().iter().any(|d| d.code == diagnostic))
            .map_err(|_| format!("diagnostic {diagnostic} not found"))?;
    }
    Ok(())
}

fn capabilities() -> consema_core::CapabilitySet {
    let mut capabilities = consema_core::CapabilitySet::new();
    capabilities.insert(consema_core::CapabilityId::new(
        "core.query.ordered-results",
        1,
    ));
    capabilities
}

fn build_filters(case: &PortableValue) -> Result<Vec<OperatorCall>, String> {
    let filters = input_field(case, "filters")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.filters")?;
    filters
        .iter()
        .map(|filter| {
            let operator = object_value_field(filter, "operator")
                .and_then(PortableValue::as_string)
                .ok_or("missing filter.operator")?;
            let mut call = OperatorCall::new(operator, 1);
            if let Some(argument) =
                object_value_field(filter, "argument").and_then(PortableValue::as_string)
            {
                call = match operator {
                    "xml.syntax-kind-is" => {
                        call.with_argument("kind", PortableValue::string(argument))
                    }
                    "xml.syntax-text-equals" => {
                        call.with_argument("text", PortableValue::string(argument))
                    }
                    _ => call.with_argument("argument", PortableValue::string(argument)),
                };
            }
            Ok(call)
        })
        .collect()
}

fn run_syntax_query(case: &PortableValue) -> Result<(), String> {
    let document = form_document(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("syntax-query input must form completely".to_owned());
    }
    let filters = build_filters(case)?;
    let mut expression = QueryExpression::Input;
    for filter in &filters {
        expression = expression.then(filter.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("xml.lossless-syntax-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()
        .map_err(|failure| format!("definition: {failure:?}"))?;
    let executable = definition
        .bind(&capabilities())
        .map_err(|failure| format!("bind: {failure:?}"))?;
    let execution = execute_xml_syntax_query(
        &executable,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(|failure| format!("execute: {failure:?}"))?;
    let matches = execution.matches();
    let expected = object_value_field(case, "expected").ok_or("missing expected.matches")?;
    let expected_matches = object_value_field(expected, "matches")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing expected.matches")?;
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        let kind = object_value_field(expected_match, "kind")
            .and_then(PortableValue::as_string)
            .ok_or("missing expected match kind")?;
        ensure(actual.kind().as_str() == kind)
            .map_err(|_| format!("kind {} != {kind}", actual.kind().as_str()))?;
        if let Some(text) =
            object_value_field(expected_match, "text").and_then(PortableValue::as_string)
        {
            let raw =
                &document.source().bytes()[actual.span().start_byte()..actual.span().end_byte()];
            // Spans are raw-byte spans; UTF-16 sources therefore need an
            // endianness-aware decode instead of the UTF-8 path.
            let actual_text = match document.source().encoding_facts().selected() {
                SourceEncoding::Utf16Le => decode_utf16(raw, SourceEncoding::Utf16Le)?,
                SourceEncoding::Utf16Be => decode_utf16(raw, SourceEncoding::Utf16Be)?,
                SourceEncoding::Utf8 => std::str::from_utf8(raw)
                    .map_err(|_| "match text not UTF-8".to_owned())?
                    .to_owned(),
                other => {
                    return Err(format!(
                        "syntax-query text assertions do not support the {} source encoding",
                        other.as_str()
                    ));
                }
            };
            ensure(actual_text == text).map_err(|_| format!("text {actual_text:?} != {text:?}"))?;
        }
    }
    Ok(())
}

fn run_native_query(case: &PortableValue) -> Result<(), String> {
    let document = form_document(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("native-query input must form completely".to_owned());
    }
    let filters = build_filters(case)?;
    let mut expression = QueryExpression::Input;
    for filter in &filters {
        expression = expression.then(filter.clone());
    }
    let definition = QueryDefinition::new(QueryDomain::new("xml.native-semantic-query", 1))
        .with_expression(expression)
        .with_selection(QuerySelection::All)
        .validate()
        .map_err(|failure| format!("definition: {failure:?}"))?;
    let executable = definition
        .bind(&capabilities())
        .map_err(|failure| format!("bind: {failure:?}"))?;
    let execution = execute_xml_query(
        &executable,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(|failure| format!("execute: {failure:?}"))?;
    let matches = execution.matches();
    let expected_matches = object_value_field(case, "expected")
        .and_then(|expected| object_value_field(expected, "matches"))
        .and_then(PortableValue::as_sequence)
        .ok_or("missing expected.matches")?;
    ensure(matches.len() == expected_matches.len()).map_err(|_| {
        format!(
            "match count {} != {}",
            matches.len(),
            expected_matches.len()
        )
    })?;
    for (actual, expected_match) in matches.iter().zip(expected_matches.iter()) {
        if let Some(local) =
            object_value_field(expected_match, "local").and_then(PortableValue::as_string)
        {
            let actual_local = match actual {
                consema_xml::XmlMatch::Element { local, .. }
                | consema_xml::XmlMatch::Attribute { local, .. } => local.as_str(),
                _ => return Err("unexpected match kind".to_owned()),
            };
            ensure(actual_local == local)
                .map_err(|_| format!("local {actual_local} != {local}"))?;
        }
        if let Some(value) =
            object_value_field(expected_match, "value").and_then(PortableValue::as_string)
        {
            let consema_xml::XmlMatch::Attribute {
                value: actual_value,
                ..
            } = actual
            else {
                return Err("expected attribute match".to_owned());
            };
            ensure(actual_value == value)
                .map_err(|_| format!("value {actual_value} != {value}"))?;
        }
    }
    Ok(())
}

fn run_projection(case: &PortableValue) -> Result<(), String> {
    let document = form_document(case)?;
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(failure) =
        object_value_field(expected, "failure").and_then(PortableValue::as_string)
    {
        let consema_xml::ProjectionResult::Failed(attempt) =
            document.project(ProjectionRequest::element_tree())
        else {
            return Err("projection must fail".to_owned());
        };
        let code = attempt
            .diagnostics
            .first()
            .map(|diagnostic| diagnostic.code.as_str())
            .ok_or("projection failure without diagnostics")?;
        ensure(code == failure).map_err(|_| format!("failure code {code} != {failure}"))?;
        return Ok(());
    }
    let consema_xml::ProjectionResult::Complete(projection) =
        document.project(ProjectionRequest::element_tree())
    else {
        return Err("projection must complete".to_owned());
    };
    let record = expected.as_object().ok_or("expected must be an object")?;
    if let Some(record_id) = object_field(record, "record").and_then(PortableValue::as_string) {
        let actual = object_field(
            projection.value.as_object().ok_or("record object")?,
            "record",
        )
        .and_then(PortableValue::as_string)
        .ok_or("missing record field")?;
        ensure(actual == record_id).map_err(|_| format!("record {actual} != {record_id}"))?;
    }
    let root_value = projection
        .value
        .as_object()
        .and_then(|object| {
            object
                .iter()
                .find(|entry| entry.key() == "root")
                .map(consema_core::ObjectEntry::value)
        })
        .ok_or("missing root")?;
    if let Some(root_local) = object_field(record, "root_local").and_then(PortableValue::as_string)
    {
        let name = root_value
            .as_object()
            .and_then(|object| {
                object
                    .iter()
                    .find(|entry| entry.key() == "expanded-name")
                    .map(consema_core::ObjectEntry::value)
            })
            .and_then(|name| object_value_field(name, "local"))
            .and_then(PortableValue::as_string)
            .ok_or("missing expanded-name.local")?;
        ensure(name == root_local).map_err(|_| format!("root_local {name} != {root_local}"))?;
    }
    if let Some(root_namespace) =
        object_field(record, "root_namespace").and_then(PortableValue::as_string)
    {
        let namespace = root_value
            .as_object()
            .and_then(|object| {
                object
                    .iter()
                    .find(|entry| entry.key() == "expanded-name")
                    .map(consema_core::ObjectEntry::value)
            })
            .and_then(|name| object_value_field(name, "namespace"))
            .and_then(PortableValue::as_string)
            .ok_or("missing expanded-name.namespace")?;
        ensure(namespace == root_namespace)
            .map_err(|_| format!("root_namespace {namespace} != {root_namespace}"))?;
    }
    if let Some(attribute_value) =
        object_field(record, "root_attribute_value").and_then(PortableValue::as_string)
    {
        let attributes = root_value
            .as_object()
            .and_then(|object| {
                object
                    .iter()
                    .find(|entry| entry.key() == "attributes")
                    .map(consema_core::ObjectEntry::value)
            })
            .and_then(PortableValue::as_sequence)
            .ok_or("missing attributes")?;
        let value = attributes
            .first()
            .and_then(|attribute| object_value_field(attribute, "value"))
            .and_then(PortableValue::as_string)
            .ok_or("missing attribute value")?;
        ensure(value == attribute_value)
            .map_err(|_| format!("attribute value {value} != {attribute_value}"))?;
    }
    if let Some(content_kinds) =
        object_field(record, "content_kinds").and_then(PortableValue::as_sequence)
    {
        let content = root_value
            .as_object()
            .and_then(|object| {
                object
                    .iter()
                    .find(|entry| entry.key() == "content")
                    .map(consema_core::ObjectEntry::value)
            })
            .and_then(PortableValue::as_sequence)
            .ok_or("missing content")?;
        ensure(content.len() == content_kinds.len())
            .map_err(|_| format!("content count {} != {}", content.len(), content_kinds.len()))?;
        for (item, expected_kind) in content.iter().zip(content_kinds.iter()) {
            let expected_kind = expected_kind
                .as_string()
                .ok_or("content kind must be a string")?;
            let actual_kind = if object_value_field(item, "expanded-name").is_some() {
                "element"
            } else {
                object_value_field(item, "kind")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing content kind")?
            };
            ensure(actual_kind == expected_kind)
                .map_err(|_| format!("kind {actual_kind} != {expected_kind}"))?;
        }
    }
    Ok(())
}

/// Converts a vector record JSON value into a PortableValue record for
/// materialization.
fn record_value(case: &PortableValue) -> Result<PortableValue, String> {
    let record = input_field(case, "record").ok_or("missing input.record")?;
    let mut builder = ObjectBuilder::new();
    let object = record.as_object().ok_or("record must be an object")?;
    for entry in object {
        builder
            .insert(entry.key(), entry.value().clone())
            .map_err(|_| "record insert".to_owned())?;
    }
    Ok(builder.build())
}

fn run_materialization(case: &PortableValue) -> Result<(), String> {
    let record = record_value(case)?;
    let request = MaterializationRequest::new(
        consema_document::ProfileId::new("xml.1.0-safe", 1),
        consema_document::MaterializationStyleId::new("xml.safe-canonical-document", 1),
    );
    let result = materialize(&record, &request);
    let expected = object_value_field(case, "expected").ok_or("missing expected")?;
    if let Some(failure) =
        object_value_field(expected, "failure").and_then(PortableValue::as_string)
    {
        match result {
            MaterializationResult::Failed(attempt) => {
                let actual = materialization_failure_code(&attempt.failure);
                ensure(actual == failure).map_err(|_| format!("failure {actual} != {failure}"))?;
                // A failed attempt never claims to have analyzed more input
                // than the request's node budget (mirrors tests/hardening.rs).
                ensure(attempt.analyzed_input_paths.len() <= request.limits().max_input_nodes)
                    .map_err(|_| {
                        format!(
                            "analyzed_input_paths {} exceeds max_input_nodes {}",
                            attempt.analyzed_input_paths.len(),
                            request.limits().max_input_nodes
                        )
                    })?;
            }
            MaterializationResult::Complete(_) => {
                return Err("materialization must fail".to_owned());
            }
        }
        return Ok(());
    }
    let MaterializationResult::Complete(complete) = result else {
        return Err("materialization must complete".to_owned());
    };
    let render = expected_string(case, "render")?;
    let actual = std::str::from_utf8(complete.document.render())
        .map_err(|_| "render not UTF-8".to_owned())?;
    ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
    Ok(())
}

fn run_edit(case: &PortableValue) -> Result<(), String> {
    let document = form_document(case)?;
    if document.status() != FormationStatus::Complete {
        return Err("edit input must form completely".to_owned());
    }
    let operations = input_field(case, "operations")
        .and_then(PortableValue::as_sequence)
        .ok_or("missing input.operations")?;
    let mut builder = EditTransactionBuilder::new(&document);
    for operation in operations {
        let op = object_value_field(operation, "op")
            .and_then(PortableValue::as_string)
            .ok_or("missing op")?;
        match op {
            "replace-text" => {
                let text = occurrence_field(operation, "text")?;
                let value = object_value_field(operation, "value")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing value")?;
                let target = find_text(&document, text)?;
                builder.replace_text(target, value);
            }
            "insert-attribute" => {
                let element = object_value_field(operation, "element")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing element")?;
                let name = object_value_field(operation, "name")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing name")?;
                let value = object_value_field(operation, "value")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing value")?;
                let target = find_element(&document, element, operation_ordinal(operation)?)?;
                let placement = match object_value_field(operation, "placement")
                    .and_then(PortableValue::as_string)
                    .unwrap_or("End")
                {
                    "End" => AttributePlacement::End,
                    "Before" => AttributePlacement::Before(find_anchor_attribute(
                        &document,
                        target,
                        anchor_name(operation)?,
                    )?),
                    "After" => AttributePlacement::After(find_anchor_attribute(
                        &document,
                        target,
                        anchor_name(operation)?,
                    )?),
                    other => return Err(format!("unknown placement {other}")),
                };
                builder.insert_attribute(
                    target,
                    NameFacts::new(None, name.to_owned(), None),
                    value,
                    placement,
                );
            }
            "remove-attribute" => {
                let name = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                let attribute = find_attribute(&document, name, operation_ordinal(operation)?)?;
                builder.remove_attribute(attribute);
            }
            "rename-attribute" => {
                let from = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                let to = object_value_field(operation, "to")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing to")?;
                let attribute = find_attribute(&document, from, operation_ordinal(operation)?)?;
                builder.rename_attribute(attribute, NameFacts::new(None, to.to_owned(), None));
            }
            "set-attribute-value" => {
                let name = object_value_field(operation, "attribute")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing attribute")?;
                let value = object_value_field(operation, "value")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing value")?;
                let attribute = find_attribute(&document, name, operation_ordinal(operation)?)?;
                builder.set_attribute_value(attribute, value);
            }
            "insert-element" => {
                let root = document.root().ok_or("missing root")?.node_ref();
                let name = object_value_field(operation, "name")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing name")?;
                let content = object_value_field(operation, "content")
                    .and_then(PortableValue::as_string)
                    .map(str::to_owned);
                builder.insert_element(
                    root,
                    NameFacts::new(None, name.to_owned(), None),
                    content,
                    ContentPlacement::End,
                );
            }
            "remove-element" => {
                let name = object_value_field(operation, "name")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing name")?;
                let target = find_element(&document, name, operation_ordinal(operation)?)?;
                builder.remove_element(target);
            }
            "rename-element" => {
                let from = object_value_field(operation, "from")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing from")?;
                let to = object_value_field(operation, "to")
                    .and_then(PortableValue::as_string)
                    .ok_or("missing to")?;
                let target = find_element(&document, from, operation_ordinal(operation)?)?;
                builder.rename_element(target, NameFacts::new(None, to.to_owned(), None));
            }
            _ => return Err(format!("unknown edit op {op}")),
        }
    }
    let commit = document
        .commit(&builder.build())
        .map_err(|failure| format!("{failure:?}"))?;
    let render = expected_string(case, "render")?;
    let actual =
        std::str::from_utf8(commit.document.render()).map_err(|_| "render not UTF-8".to_owned())?;
    ensure(actual == render).map_err(|_| format!("render {actual:?} != {render:?}"))?;
    Ok(())
}

/// Reads an optional `"ordinal": N` occurrence selector on one edit
/// operation; absent means the first occurrence (0).
fn operation_ordinal(operation: &PortableValue) -> Result<u64, String> {
    occurrence_field(operation, "ordinal")
}

/// Reads an optional occurrence selector under `name`, where `N` selects the
/// Nth same-named occurrence in document order and absent means the first.
fn occurrence_field(operation: &PortableValue, name: &str) -> Result<u64, String> {
    match object_value_field(operation, name) {
        None => Ok(0),
        Some(value) => value
            .as_integer()
            .and_then(consema_core::BigInteger::to_i64)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| format!("{name} must be a non-negative integer")),
    }
}

/// The anchor attribute name for a Before/After insertion placement.
fn anchor_name(operation: &PortableValue) -> Result<&str, String> {
    object_value_field(operation, "anchor")
        .and_then(PortableValue::as_string)
        .ok_or_else(|| "missing anchor".to_owned())
}

/// Resolves the `ordinal`-th attribute with `name` in document order.
fn find_attribute(
    document: &consema_xml::Document,
    name: &str,
    ordinal: u64,
) -> Result<consema_document::NodeRef, String> {
    let mut occurrence = 0;
    for content in document.nodes() {
        if let consema_xml::XmlContent::Element(data) = content {
            for attribute in &data.attributes {
                if attribute.qname.local.as_ref() == name {
                    if occurrence == ordinal {
                        return Ok(
                            document.occurrence_node_ref(attribute.ordinal, NodeRole::XmlAttribute)
                        );
                    }
                    occurrence += 1;
                }
            }
        }
    }
    Err(format!("attribute {name} occurrence {ordinal} not found"))
}

/// Resolves the `ordinal`-th element with `name` in document order.
fn find_element(
    document: &consema_xml::Document,
    name: &str,
    ordinal: u64,
) -> Result<consema_document::NodeRef, String> {
    let mut occurrence = 0;
    for (index, content) in document.nodes().iter().enumerate() {
        if let consema_xml::XmlContent::Element(data) = content {
            if data.qname.local.as_ref() == name {
                if occurrence == ordinal {
                    return Ok(document.occurrence_node_ref(index as u64, NodeRole::XmlElement));
                }
                occurrence += 1;
            }
        }
    }
    Err(format!("element {name} occurrence {ordinal} not found"))
}

/// Resolves the `ordinal`-th text occurrence in document order.
fn find_text(
    document: &consema_xml::Document,
    ordinal: u64,
) -> Result<consema_document::NodeRef, String> {
    let mut occurrence = 0;
    for content in document.nodes() {
        if let consema_xml::XmlContent::Text(data) = content {
            if occurrence == ordinal {
                return Ok(document.occurrence_node_ref(data.ordinal, NodeRole::XmlText));
            }
            occurrence += 1;
        }
    }
    Err(format!("text occurrence {ordinal} not found"))
}

/// Resolves one attribute anchor on exactly one element.
fn find_anchor_attribute(
    document: &consema_xml::Document,
    element: consema_document::NodeRef,
    name: &str,
) -> Result<consema_document::NodeRef, String> {
    let index =
        usize::try_from(element.index()).map_err(|_| "element index overflow".to_owned())?;
    let consema_xml::XmlContent::Element(data) = &document.nodes()[index] else {
        return Err("anchor element is not an element".to_owned());
    };
    data.attributes
        .iter()
        .find(|attribute| attribute.qname.local.as_ref() == name)
        .map(|attribute| document.occurrence_node_ref(attribute.ordinal, NodeRole::XmlAttribute))
        .ok_or_else(|| format!("attribute {name} not found on element"))
}

/// Runs one `xml.limit@1` case.
///
/// Every published limit vector is formation-class today: the vocabulary
/// expresses `input.amplification_ratio` and `input.max_mixed_content_items`,
/// both resolved by [`parse_limits`] into the formation contract, so this
/// runner delegates to [`run_formation`]. Non-formation limit scenarios —
/// projection limits, query result limits, edit resource limits — must
/// branch here before delegating, and the `xml.limit@1` vector vocabulary
/// grows to carry their input and expectation facts alongside.
fn run_limit(case: &PortableValue) -> Result<(), String> {
    // Formation-class delegation keeps status and diagnostic semantics
    // identical to `xml.formation@1`; see the function comment for the
    // non-formation extension point.
    run_formation(case)
}

/// Decodes one raw-byte span under the selected UTF-16 endianness.
///
/// Syntax-query spans never include the leading BOM, but stripping it
/// defensively keeps this helper total for any caller-provided slice.
fn decode_utf16(bytes: &[u8], encoding: SourceEncoding) -> Result<String, String> {
    if bytes.len() % 2 != 0 {
        return Err(format!("{} span has odd byte length", encoding.as_str()));
    }
    let content = match encoding {
        SourceEncoding::Utf16Le => bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes),
        SourceEncoding::Utf16Be => bytes.strip_prefix(&[0xFE, 0xFF]).unwrap_or(bytes),
        _ => return Err(format!("{encoding:?} is not UTF-16")),
    };
    let units = content
        .chunks_exact(2)
        .map(|pair| match encoding {
            SourceEncoding::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
            SourceEncoding::Utf16Be => u16::from_be_bytes([pair[0], pair[1]]),
            _ => unreachable!("endianness checked above"),
        })
        .collect::<Vec<u16>>();
    String::from_utf16(&units).map_err(|_| "span is not valid UTF-16".to_owned())
}

/// Stable vector spelling for one `MaterializationFailure` variant.
///
/// `"invalid-record"` is the published spelling for `InvalidRequest`; the
/// remaining spellings let future vectors declare `"unsupported-profile"`,
/// `"unsupported-style"`, and friends.
fn materialization_failure_code(failure: &MaterializationFailure) -> &'static str {
    match failure {
        MaterializationFailure::InvalidRequest(_) => "invalid-record",
        MaterializationFailure::UnsupportedProfile => "unsupported-profile",
        MaterializationFailure::UnsupportedStyle => "unsupported-style",
        MaterializationFailure::UnsupportedEncoding => "unsupported-encoding",
        MaterializationFailure::UnsupportedNewline => "unsupported-newline",
        MaterializationFailure::Unrepresentable { .. } => "unrepresentable",
        MaterializationFailure::ResourceLimit(_) => "resource-limit",
        MaterializationFailure::FormationFailed => "formation-failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_v1_suite_passes_fully() {
        let report = run_xml_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 34);
    }

    #[test]
    fn xml_suite_identifier_is_checked() {
        let changed = XML_V1_VECTORS_JSON.replace(
            "\"suite\": \"consema.xml-1-0-safe.conformance@1\"",
            "\"suite\": \"unexpected.suite@1\"",
        );
        let report = run_xml_v1_json(&changed);
        assert!(
            report.failed.iter().any(|(id, _)| id == "suite.schema"),
            "{report:#?}"
        );
        assert!(report.passed.is_empty());
    }

    #[test]
    fn syntax_query_text_assertion_supports_utf16_sources() {
        // The published suite has no UTF-16 syntax-query input; the runner
        // must still decode UTF-16 spans instead of failing or panicking on
        // the UTF-8 path.
        let json = r#"{
            "id": "test.utf16le-text",
            "capability": "xml.syntax-query@1",
            "input": {
                "profile": "xml.1.0-safe@1",
                "encoding": "utf16le-bom",
                "source": "<root>中文</root>",
                "filters": [
                    { "operator": "xml.syntax-kind-is", "argument": "text" }
                ]
            },
            "expected": {
                "terminal": "Completed",
                "matches": [
                    { "kind": "text", "text": "中文" }
                ]
            }
        }"#;
        let vectors = parse(
            json.as_bytes(),
            JsonProfile::StrictV1,
            consema_document::ParseLimits::default(),
        )
        .expect("vector JSON forms");
        let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
            .build()
            .expect("fixed projection request");
        let ProjectionResult::Complete(result) = vectors.project(&request) else {
            panic!("vector JSON projects");
        };
        run_case(&result.value).expect("UTF-16 syntax-query case passes");
    }
}
