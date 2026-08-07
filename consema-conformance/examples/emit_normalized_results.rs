//! emit_normalized_results — cross-language normalized-result differential
//! harness support (milestone 0.15.0 G1.5; docs/go-implementation-plan.md
//! §4.4 and §2.2; roadmap §16.2 line 1488 and §11.2 lines 849-861).
//!
//! Reads the differential case file
//! (`go/conformance/differential/normalized/cases.json`) and executes every
//! case with the public Rust SDK, emitting the Rust side's normalized
//! results as one `<outdir>/<case-id>.txt` evidence file per case
//! (line-oriented `key=value` facts). Orchestration:
//! `scripts/go-verify-normalized-differential.ps1`; the Go test
//! (`go/conformance/differential/normalized/normalized_test.go`) computes
//! the same normalized facts with the Go SDK and compares them field by
//! field.
//!
//! The compared facts are exactly the language-neutral behavior surface of
//! roadmap §11.2: parse formation, diagnostic code/order (never text),
//! query count/identity/order, projection/materialization reports, edit
//! result bytes or failure codes, and resource-limit completion semantics.
//! The fact vocabulary is defined in the Go runner and mirrored verbatim
//! here; it contains no Rust internal type names. Error texts never
//! participate in the comparison.
//!
//! Why this example exists (justification): the differential harness needs
//! the Rust SDK's normalized results for a data-driven set of 40+ document
//! and source cases. No existing entry point executes arbitrary
//! parse/query/project/materialize/edit/source workflows and prints
//! normalized facts, so a minimal example is required. It reuses the
//! published crate APIs only — no new encoding or analysis logic — and adds
//! no dependency: the case file is parsed with the same consema-json strict
//! parser the conformance runner uses.
//!
//! Usage: `emit_normalized_results <cases.json> <out-dir>`
//! Exit code 0 = every case emitted; 1 = a case failed; 2 = usage error.

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

use consema_core::{
    BigInteger, BinaryFloat64, CancellationToken, CapabilityId, CapabilitySet, Decimal,
    EntryMappingBuilder, ExecutableQuery, OperatorCall, PortableValue, PortableValueKind,
    QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits, QuerySelection,
    StableFailure,
};
use consema_document::{
    AssociationPlacement, EncodingRequest, FatalFormationFailure, MaterializationLimits,
    MaterializationRequest, MaterializationStyleId, NewlinePolicy, NodeRef, ParseLimits, ProfileId,
    SourceEncoding, SourceError, SourceLimits, SourcePatch, SourcePatchLimits, SourceReplacement,
    SourceSnapshot,
};
use consema_json::{
    DuplicateKeyPolicy, EditFailure, Fidelity, JsonMatch, JsonProfile, JsonSyntaxMatch, JsonValue,
    JsonValueKind, ProjectionEventKind, ProjectionFailure, ProjectionRequestBuilder,
    ProjectionResult, ProjectionTarget, RepresentationPolicy, SemanticAvailability,
    SemanticUnavailable, execute_json_query, execute_json_syntax_query,
    materialize as json_materialize, parse as parse_json,
};
use consema_protocol::{ProtocolLimits, decode_json, query_failure_code};
use consema_toml::{
    EditFailure as TomlEditFailure, TomlItem, TomlItemKind, TomlMatch, TomlProfile,
    TomlSyntaxMatch, execute_toml_query, execute_toml_syntax_query,
    materialize as toml_materialize, parse as parse_toml,
};

// ---------------------------------------------------------------------------
// Case file reading (the emit_parity_bytes precedent)
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1);
    let (Some(cases_path), Some(out_dir)) = (args.next(), args.next()) else {
        eprintln!("usage: emit_normalized_results <cases.json> <out-dir>");
        std::process::exit(2);
    };
    let out_dir = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir).expect("create out-dir");
    let text = fs::read_to_string(&cases_path)
        .unwrap_or_else(|error| panic!("cannot read case file {cases_path:?}: {error}"));

    let document = parse_json(
        text.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("differential case file must form a strict JSON document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let root = match document.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            eprintln!("case file projection failed: {attempt:?}");
            std::process::exit(1);
        }
    };
    let root_object = root.as_object().expect("case file root object");
    let manifest = object_field(root_object, "manifest")
        .and_then(PortableValue::as_string)
        .expect("manifest field");
    if manifest != "consema.differential.normalized@1" {
        eprintln!("unexpected case file manifest {manifest:?}");
        std::process::exit(1);
    }
    let cases = object_field(root_object, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");

    let mut failures = Vec::new();
    let mut emitted = 0usize;
    for case in cases {
        let fields = case.as_object().expect("case object");
        let id = object_field(fields, "id")
            .and_then(PortableValue::as_string)
            .expect("case id")
            .to_owned();
        let kind = object_field(fields, "kind")
            .and_then(PortableValue::as_string)
            .expect("case kind")
            .to_owned();
        let facts = match kind.as_str() {
            "document" => match run_document_case(fields) {
                Ok(facts) => facts,
                Err(error) => {
                    eprintln!("case {id}: {error}");
                    failures.push(id);
                    continue;
                }
            },
            "source" => match run_source_case(fields) {
                Ok(facts) => facts,
                Err(error) => {
                    eprintln!("case {id}: {error}");
                    failures.push(id);
                    continue;
                }
            },
            other => {
                eprintln!("case {id}: unknown case kind {other:?}");
                failures.push(id);
                continue;
            }
        };
        let mut text = String::new();
        for (key, value) in &facts {
            writeln!(text, "{key}={value}").expect("String write");
        }
        fs::write(out_dir.join(format!("{id}.txt")), text)
            .unwrap_or_else(|error| panic!("case {id}: cannot write evidence file: {error}"));
        emitted += 1;
    }
    println!(
        "emit_normalized_results: {emitted} cases emitted into {:?}",
        out_dir
    );
    if !failures.is_empty() {
        eprintln!("failed cases: {failures:?}");
        std::process::exit(1);
    }
}

/// Reads one field of an object (the runner's `object_field`,
/// crates/consema-conformance/src/lib.rs:195-203).
fn object_field<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Option<&'a PortableValue> {
    entries
        .iter()
        .find(|entry| entry.key() == key)
        .map(consema_core::ObjectEntry::value)
}

/// Reads one string field of an object.
fn object_string<'a>(entries: &'a [consema_core::ObjectEntry], key: &str) -> Option<&'a str> {
    object_field(entries, key).and_then(PortableValue::as_string)
}

/// Reads one optional usize integer field.
fn object_usize(entries: &[consema_core::ObjectEntry], key: &str) -> Option<usize> {
    object_field(entries, key)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
}

/// Reads one optional boolean field.
fn object_bool(entries: &[consema_core::ObjectEntry], key: &str) -> Option<bool> {
    object_field(entries, key).and_then(PortableValue::as_boolean)
}

// ---------------------------------------------------------------------------
// Normalized fact emission (the vocabulary mirrored from the Go runner)
// ---------------------------------------------------------------------------

type Facts = Vec<(String, String)>;

fn set(facts: &mut Facts, key: impl Into<String>, value: impl Into<String>) {
    facts.push((key.into(), value.into()));
}

/// JSON string escaping (mirrors the Go runner's `escape`).
fn escape(text: &str) -> String {
    let mut output = String::new();
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                write!(output, "\\u{:04x}", other as u32).expect("String write");
            }
            other => output.push(other),
        }
    }
    output
}

/// `|`-joins one ordered list.
fn join(items: &[String]) -> String {
    items.join("|")
}

// ---------------------------------------------------------------------------
// Stable code mappings
// ---------------------------------------------------------------------------

/// Stable code of a fatal formation failure (the first diagnostic's code).
fn formation_code(failure: &FatalFormationFailure) -> String {
    failure
        .diagnostics()
        .first()
        .map(|diagnostic| diagnostic.code.clone())
        .unwrap_or_default()
}

/// Stable code of a source construction failure (the frozen mapping shared
/// with the Go `SourceError.Code()`).
fn source_error_code(error: &SourceError) -> &'static str {
    match error {
        SourceError::InvalidUtf8 { .. } | SourceError::InvalidSequence { .. } => {
            "core.source.invalid-sequence@1"
        }
        SourceError::EncodingConflict { .. } => "core.source.encoding-conflict@1",
        SourceError::UnsupportedBom { .. } => "core.source.unsupported-bom@1",
        SourceError::ResourceLimit { .. } | SourceError::OffsetOverflow => {
            "core.source.resource-limit@1"
        }
    }
}

/// Stable code of a JSON edit failure.
fn json_edit_failure_code(failure: &EditFailure) -> String {
    failure.diagnostic_code().to_owned()
}

/// Stable code of a TOML edit failure.
fn toml_edit_failure_code(failure: &TomlEditFailure) -> String {
    failure.diagnostic_code().to_owned()
}

/// Stable code of a JSON projection failure.
fn json_projection_failure_code(failure: &ProjectionFailure) -> String {
    failure.diagnostic_code().to_owned()
}

/// Stable code of a materialization failure (the consema-document mapping).
fn materialization_failure_code(failure: &consema_document::MaterializationFailure) -> String {
    failure.diagnostic_code().to_owned()
}

// ---------------------------------------------------------------------------
// Kind name vocabularies
// ---------------------------------------------------------------------------

fn json_value_kind_name(kind: JsonValueKind) -> &'static str {
    match kind {
        JsonValueKind::Null => "Null",
        JsonValueKind::Boolean => "Boolean",
        JsonValueKind::Integer => "Integer",
        JsonValueKind::Decimal => "Decimal",
        JsonValueKind::BinaryFloat64 => "BinaryFloat64",
        JsonValueKind::String => "String",
        JsonValueKind::Array => "Array",
        JsonValueKind::Object => "Object",
    }
}

fn semantic_unavailable_name(reason: SemanticUnavailable) -> &'static str {
    match reason {
        SemanticUnavailable::Missing => "Missing",
        SemanticUnavailable::ErrorRegion => "ErrorRegion",
        SemanticUnavailable::InvalidLiteral => "InvalidLiteral",
        SemanticUnavailable::ChildUnavailable => "ChildUnavailable",
    }
}

fn toml_item_kind_name(kind: TomlItemKind) -> &'static str {
    match kind {
        TomlItemKind::String => "String",
        TomlItemKind::Integer => "Integer",
        TomlItemKind::Float => "Float",
        TomlItemKind::Boolean => "Boolean",
        TomlItemKind::OffsetDateTime => "OffsetDateTime",
        TomlItemKind::LocalDateTime => "LocalDateTime",
        TomlItemKind::LocalDate => "LocalDate",
        TomlItemKind::LocalTime => "LocalTime",
        TomlItemKind::Array => "Array",
        TomlItemKind::InlineTable => "InlineTable",
        TomlItemKind::RootTable => "RootTable",
        TomlItemKind::StandardTable => "StandardTable",
        TomlItemKind::ImplicitTable => "ImplicitTable",
        TomlItemKind::DottedTable => "DottedTable",
        TomlItemKind::ArrayOfTables => "ArrayOfTables",
    }
}

fn portable_value_kind_name(kind: PortableValueKind) -> &'static str {
    match kind {
        PortableValueKind::Null => "Null",
        PortableValueKind::Boolean => "Boolean",
        PortableValueKind::Integer => "Integer",
        PortableValueKind::Decimal => "Decimal",
        PortableValueKind::BinaryFloat32 => "BinaryFloat32",
        PortableValueKind::BinaryFloat64 => "BinaryFloat64",
        PortableValueKind::String => "String",
        PortableValueKind::Bytes => "Bytes",
        PortableValueKind::Date => "Date",
        PortableValueKind::Time => "Time",
        PortableValueKind::LocalDateTime => "LocalDateTime",
        PortableValueKind::OffsetDateTime => "OffsetDateTime",
        PortableValueKind::Sequence => "Sequence",
        PortableValueKind::Object => "Object",
        PortableValueKind::EntryMapping => "EntryMapping",
    }
}

fn fidelity_name(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Exact => "Exact",
        Fidelity::Transformed => "Transformed",
        Fidelity::Lossy => "Lossy",
    }
}

fn projection_event_kind_name(kind: ProjectionEventKind) -> &'static str {
    match kind {
        ProjectionEventKind::StructureReencoded => "StructureReencoded",
        ProjectionEventKind::TypeMapped => "TypeMapped",
        ProjectionEventKind::DuplicateCollapsed => "DuplicateCollapsed",
        ProjectionEventKind::KeyStringified => "KeyStringified",
        ProjectionEventKind::ValueRounded => "ValueRounded",
        ProjectionEventKind::FieldDropped => "FieldDropped",
    }
}

fn toml_fidelity_name(fidelity: consema_toml::Fidelity) -> &'static str {
    match fidelity {
        consema_toml::Fidelity::Exact => "Exact",
        consema_toml::Fidelity::Transformed => "Transformed",
        consema_toml::Fidelity::Lossy => "Lossy",
    }
}

fn materialization_fidelity_name(
    fidelity: consema_document::MaterializationFidelity,
) -> &'static str {
    match fidelity {
        consema_document::MaterializationFidelity::Exact => "Exact",
        consema_document::MaterializationFidelity::Transformed => "Transformed",
    }
}

// ---------------------------------------------------------------------------
// Native summaries
// ---------------------------------------------------------------------------

/// Renders one JSON native value in the canonical summary vocabulary
/// (mirrors the Go `jsonNativeValue`).
fn json_native(value: JsonValue<'_>, depth: usize) -> String {
    if depth > 64 {
        return "...".to_owned();
    }
    match value.kind() {
        SemanticAvailability::Available(JsonValueKind::Null) => "null".to_owned(),
        SemanticAvailability::Available(JsonValueKind::Boolean) => match value.as_boolean() {
            SemanticAvailability::Available(Some(boolean)) => boolean.to_string(),
            _ => "?".to_owned(),
        },
        SemanticAvailability::Available(JsonValueKind::Integer) => match value.as_integer() {
            SemanticAvailability::Available(Some(integer)) => integer.to_string(),
            _ => "?".to_owned(),
        },
        SemanticAvailability::Available(JsonValueKind::Decimal) => match value.as_decimal() {
            SemanticAvailability::Available(Some(decimal)) => {
                format!("{}e{}", decimal.coefficient(), decimal.exponent())
            }
            _ => "?".to_owned(),
        },
        SemanticAvailability::Available(JsonValueKind::BinaryFloat64) => match value
            .as_binary_float64()
        {
            SemanticAvailability::Available(Some(number)) => format!("0x{:016x}", number.bits()),
            _ => "?".to_owned(),
        },
        SemanticAvailability::Available(JsonValueKind::String) => match value.as_string() {
            SemanticAvailability::Available(Some(text)) => format!("\"{}\"", escape(text)),
            _ => "?".to_owned(),
        },
        SemanticAvailability::Available(JsonValueKind::Array) => match value.array_elements() {
            SemanticAvailability::Available(None) => "?".to_owned(),
            SemanticAvailability::Available(Some(elements)) => {
                let parts = elements
                    .iter()
                    .map(|element| json_native(element.value(), depth + 1))
                    .collect::<Vec<_>>();
                format!("[{}]", parts.join(","))
            }
            SemanticAvailability::Unavailable(reason) => {
                format!("Unavailable:{}", semantic_unavailable_name(reason))
            }
        },
        SemanticAvailability::Available(JsonValueKind::Object) => match value.object_members() {
            SemanticAvailability::Available(None) => "?".to_owned(),
            SemanticAvailability::Available(Some(members)) => {
                let parts = members
                    .iter()
                    .map(|member| {
                        let name = match member.name() {
                            SemanticAvailability::Available(name) => escape(name),
                            SemanticAvailability::Unavailable(_) => "?".to_owned(),
                        };
                        format!("\"{name}\":{}", json_native(member.value(), depth + 1))
                    })
                    .collect::<Vec<_>>();
                format!("{{{}}}", parts.join(","))
            }
            SemanticAvailability::Unavailable(reason) => {
                format!("Unavailable:{}", semantic_unavailable_name(reason))
            }
        },
        SemanticAvailability::Unavailable(reason) => {
            format!("Unavailable:{}", semantic_unavailable_name(reason))
        }
    }
}

/// Renders one TOML native item in the canonical summary vocabulary
/// (mirrors the Go `tomlNativeItem`).
fn toml_native(item: TomlItem<'_>, depth: usize) -> String {
    if depth > 64 {
        return "...".to_owned();
    }
    match item.kind() {
        TomlItemKind::String => match item.as_string() {
            Some(text) => format!("\"{}\"", escape(text)),
            None => "?".to_owned(),
        },
        TomlItemKind::Integer => match item.as_integer() {
            Some(number) => number.to_string(),
            None => "?".to_owned(),
        },
        TomlItemKind::Float => match item.as_float() {
            Some(number) => format!("0x{:016x}", number.bits()),
            None => "?".to_owned(),
        },
        TomlItemKind::Boolean => match item.as_boolean() {
            Some(boolean) => boolean.to_string(),
            None => "?".to_owned(),
        },
        TomlItemKind::OffsetDateTime
        | TomlItemKind::LocalDateTime
        | TomlItemKind::LocalDate
        | TomlItemKind::LocalTime => match item.as_date_time() {
            Some(date_time) => toml_datetime_summary(date_time),
            None => "?".to_owned(),
        },
        TomlItemKind::Array => match item.array_elements() {
            Some(elements) => {
                let parts = elements
                    .iter()
                    .map(|element| toml_native(element.item(), depth + 1))
                    .collect::<Vec<_>>();
                format!("[{}]", parts.join(","))
            }
            None => "?".to_owned(),
        },
        TomlItemKind::InlineTable
        | TomlItemKind::RootTable
        | TomlItemKind::StandardTable
        | TomlItemKind::ImplicitTable
        | TomlItemKind::DottedTable => match item.table_entries() {
            Some(entries) => {
                let parts = entries
                    .iter()
                    .map(|entry| {
                        format!(
                            "\"{}\":{}",
                            escape(entry.name()),
                            toml_native(entry.item(), depth + 1)
                        )
                    })
                    .collect::<Vec<_>>();
                format!("{{{}}}", parts.join(","))
            }
            None => "?".to_owned(),
        },
        TomlItemKind::ArrayOfTables => match item.array_elements() {
            Some(elements) => {
                let parts = elements
                    .iter()
                    .map(|element| toml_native(element.item(), depth + 1))
                    .collect::<Vec<_>>();
                format!("[{}]", parts.join(","))
            }
            None => "?".to_owned(),
        },
    }
}

/// Renders one TOML date/time datum canonically (mirrors the Go
/// `tomlDateTimeSummary`).
fn toml_datetime_summary(date_time: &consema_toml::TomlDateTime) -> String {
    let mut parts = Vec::new();
    if let Some(date) = date_time.date {
        parts.push(format!(
            "date={:04}-{:02}-{:02}",
            date.year, date.month, date.day
        ));
    }
    if let Some(time) = date_time.time {
        let mut text = format!(
            "time={:02}:{:02}:{:02}",
            time.hour, time.minute, time.second
        );
        if time.nanosecond != 0 {
            write!(text, ".{:09}", time.nanosecond).expect("String write");
        }
        parts.push(text);
    }
    if let Some(offset) = date_time.offset {
        match offset {
            consema_toml::TomlOffset::Z => parts.push("offset=Z".to_owned()),
            consema_toml::TomlOffset::CustomMinutes(minutes) => {
                let (sign, magnitude) = if minutes < 0 {
                    ("-", -(minutes as i32))
                } else {
                    ("+", minutes as i32)
                };
                parts.push(format!(
                    "offset={}{:02}:{:02}",
                    sign,
                    magnitude / 60,
                    magnitude % 60
                ));
            }
        }
    }
    format!("datetime({})", parts.join(","))
}

// ---------------------------------------------------------------------------
// Query definitions
// ---------------------------------------------------------------------------

/// Builds the executable from the declarative filters (mirrors the Go
/// `buildQueryDefinition` and the runner's `definition()`).
fn build_query_definition(
    fields: &[consema_core::ObjectEntry],
    domain: QueryDomain,
) -> Result<ExecutableQuery, QueryFailure> {
    let format = if domain.id().starts_with("toml.") {
        "toml"
    } else {
        "json"
    };
    let filter_values = object_field(fields, "filters")
        .and_then(PortableValue::as_sequence)
        .unwrap_or(&[]);
    let mut calls = Vec::new();
    for filter in filter_values {
        let filter_fields = filter
            .as_object()
            .ok_or_else(|| QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: "filter".to_owned(),
            })?;
        let operator = object_string(filter_fields, "operator").unwrap_or("");
        let argument = object_field(filter_fields, "argument").cloned();
        let call = match operator {
            "kind-is" => OperatorCall::new(format!("{format}.syntax-kind-is"), 1).with_argument(
                "kind",
                argument.ok_or_else(|| QueryFailure::InvalidArgument {
                    operator: operator.to_owned(),
                    argument: "argument".to_owned(),
                })?,
            ),
            "text-equals" => OperatorCall::new(format!("{format}.syntax-text-equals"), 1)
                .with_argument(
                    "text",
                    argument.ok_or_else(|| QueryFailure::InvalidArgument {
                        operator: operator.to_owned(),
                        argument: "argument".to_owned(),
                    })?,
                ),
            "take" => OperatorCall::new("core.take", 1).with_argument(
                "count",
                argument.ok_or_else(|| QueryFailure::InvalidArgument {
                    operator: operator.to_owned(),
                    argument: "argument".to_owned(),
                })?,
            ),
            "json.member-name-equals" | "toml.entry-name-equals" => OperatorCall::new(operator, 1)
                .with_argument(
                    "name",
                    argument.ok_or_else(|| QueryFailure::InvalidArgument {
                        operator: operator.to_owned(),
                        argument: "argument".to_owned(),
                    })?,
                ),
            other => OperatorCall::new(other, 1),
        };
        calls.push(call);
    }
    let expression = match object_string(fields, "combine").unwrap_or("Single") {
        "Single" | "" => {
            let mut expression = QueryExpression::Input;
            for call in &calls {
                expression = expression.then(call.clone());
            }
            expression
        }
        "StructureOrderMerge" => {
            let branches = calls
                .iter()
                .map(|call| QueryExpression::Input.then(call.clone()))
                .collect();
            QueryExpression::StructureOrderMerge(branches)
        }
        "Concat" => {
            let branches = calls
                .iter()
                .map(|call| QueryExpression::Input.then(call.clone()))
                .collect();
            QueryExpression::Concat(branches)
        }
        other => {
            return Err(QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: other.to_owned(),
            });
        }
    };
    let selection = match object_string(fields, "selection").unwrap_or("All") {
        "All" | "" => QuerySelection::All,
        "First" => QuerySelection::First,
        "Last" => QuerySelection::Last,
        "ZeroOrOne" => QuerySelection::ZeroOrOne,
        "RequireOne" => QuerySelection::RequireOne,
        other => {
            return Err(QueryFailure::InvalidArgument {
                operator: "vector".to_owned(),
                argument: other.to_owned(),
            });
        }
    };
    QueryDefinition::new(domain)
        .with_expression(expression)
        .with_selection(selection)
        .validate()?
        .bind(&capabilities())
}

/// The capability set required by the shared query definitions.
fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

/// Applies the query-limit descriptor overrides.
fn apply_query_limits(fields: &[consema_core::ObjectEntry], limits: &mut QueryLimits) {
    let Some(desc) = object_field(fields, "query_limits") else {
        return;
    };
    let Some(desc) = desc.as_object() else {
        return;
    };
    if let Some(value) = object_usize(desc, "max_results") {
        limits.max_results = value;
    }
    if let Some(value) = object_usize(desc, "max_steps") {
        limits.max_steps = value;
    }
}

// ---------------------------------------------------------------------------
// Document face
// ---------------------------------------------------------------------------

/// Runs one document-face case and returns its ordered facts.
fn run_document_case(fields: &[consema_core::ObjectEntry]) -> Result<Facts, String> {
    let format = object_string(fields, "format").unwrap_or("");
    let profile_name = object_string(fields, "profile").unwrap_or("");
    let source = object_string(fields, "source").unwrap_or("");
    let foreign_source = object_string(fields, "foreign_source").unwrap_or("");
    let foreign_source_hex = object_string(fields, "foreign_source_hex").unwrap_or("");
    let parse_limits = parse_limits(fields);

    let mut facts = Facts::new();
    let mut state = DocState {
        format: format.to_owned(),
        profile_name: profile_name.to_owned(),
        foreign_source: foreign_source.to_owned(),
        foreign_source_hex: foreign_source_hex.to_owned(),
        parse_limits,
        ..DocState::default()
    };

    // --- parse ---
    let parse_outcome = parse_into_state(&mut state, source, profile_name, parse_limits);
    if let Err(failure) = parse_outcome {
        set(&mut facts, "parse.formation", "Fatal");
        set(&mut facts, "parse.fatal_code", formation_code(&failure));
        set(&mut facts, "parse.diagnostic_codes", "");
        set(&mut facts, "parse.root_kind", "");
        set(&mut facts, "parse.native", "");
        emit_step_facts(&mut facts, &mut state, None);
        return Ok(facts);
    }
    set(&mut facts, "parse.formation", &state.formation);
    set(&mut facts, "parse.fatal_code", "");
    set(
        &mut facts,
        "parse.diagnostic_codes",
        &state.diagnostic_codes,
    );
    set(&mut facts, "parse.root_kind", &state.root_kind);
    set(&mut facts, "parse.native", &state.native);

    let steps = object_field(fields, "steps")
        .and_then(PortableValue::as_sequence)
        .unwrap_or(&[]);
    for step in steps {
        let step_fields = step.as_object().ok_or("step must be an Object")?;
        let op = object_string(step_fields, "op").unwrap_or("");
        match op {
            "parse" => {}
            "query-native" | "query-syntax" | "project" | "materialize" | "edit" => {
                emit_step_facts(&mut facts, &mut state, Some(step_fields));
            }
            other => return Err(format!("unknown step op {other:?}")),
        }
    }
    // Every group's key set is emitted exactly once: groups whose step is
    // absent from the case report Blocked here, in the fixed order.
    emit_step_facts(&mut facts, &mut state, None);
    Ok(facts)
}

/// One document-face execution state.
#[derive(Default)]
struct DocState {
    format: String,
    profile_name: String,
    foreign_source: String,
    foreign_source_hex: String,
    parse_limits: ParseLimits,

    json_document: Option<consema_json::Document>,
    toml_document: Option<consema_toml::Document>,
    foreign_json: Option<consema_json::Document>,
    foreign_toml: Option<consema_toml::Document>,

    formation: String,
    diagnostic_codes: String,
    root_kind: String,
    native: String,

    query_native_run: bool,
    query_syntax_run: bool,
    project_run: bool,
    materialize_run: bool,
    edit_run: bool,

    value: Option<PortableValue>,
    projected: bool,
}

impl DocState {
    fn document_parsed(&self) -> bool {
        self.json_document.is_some() || self.toml_document.is_some()
    }
}

/// Reads the parse-limit descriptor overrides.
fn parse_limits(fields: &[consema_core::ObjectEntry]) -> ParseLimits {
    let mut limits = ParseLimits::default();
    let Some(desc) = object_field(fields, "parse_limits") else {
        return limits;
    };
    let Some(desc) = desc.as_object() else {
        return limits;
    };
    if let Some(value) = object_usize(desc, "max_source_bytes") {
        limits.max_source_bytes = value;
    }
    if let Some(value) = object_usize(desc, "max_nesting_depth") {
        limits.max_nesting_depth = value;
    }
    if let Some(value) = object_usize(desc, "max_token_count") {
        limits.max_token_count = value;
    }
    if let Some(value) = object_usize(desc, "max_node_count") {
        limits.max_node_count = value;
    }
    if let Some(value) = object_usize(desc, "max_diagnostics") {
        limits.max_diagnostics = value;
    }
    limits
}

/// Parses the case source and fills the parse facts; Err is the fatal
/// formation failure.
fn parse_into_state(
    state: &mut DocState,
    source: &str,
    profile_name: &str,
    limits: ParseLimits,
) -> Result<(), FatalFormationFailure> {
    match state.format.as_str() {
        "json" => {
            let profile = match profile_name {
                "json.strict@1" => JsonProfile::StrictV1,
                "jsonc.bounded@1" => JsonProfile::JsoncBoundedV1,
                "json5.standard@1" => JsonProfile::Json5StandardV1,
                other => panic!("unknown JSON profile {other:?}"),
            };
            let document = parse_json(source.as_bytes(), profile, limits)?;
            state.formation = formation_name(document.formation_status());
            state.diagnostic_codes = diagnostic_codes(document.diagnostics());
            let root = document.root();
            match root.kind() {
                SemanticAvailability::Available(kind) => {
                    state.root_kind = json_value_kind_name(kind).to_owned();
                }
                SemanticAvailability::Unavailable(reason) => {
                    state.root_kind = format!("Unavailable:{}", semantic_unavailable_name(reason));
                }
            }
            state.native = json_native(root, 0);
            state.json_document = Some(document);
            Ok(())
        }
        "toml" => {
            let document = parse_toml(source.as_bytes(), TomlProfile::Toml10V1, limits)?;
            state.formation = formation_name(document.formation_status());
            state.diagnostic_codes = diagnostic_codes(document.diagnostics());
            state.root_kind = toml_item_kind_name(document.root().kind()).to_owned();
            state.native = toml_native(document.root(), 0);
            state.toml_document = Some(document);
            Ok(())
        }
        other => panic!("unknown case format {other:?}"),
    }
}

/// Resolves one SemanticAvailability<Option<T>> into Option<T>.
fn availability_option<T>(availability: SemanticAvailability<Option<T>>) -> Option<T> {
    match availability {
        SemanticAvailability::Available(value) => value,
        SemanticAvailability::Unavailable(_) => None,
    }
}

fn formation_name(status: consema_document::FormationStatus) -> String {
    match status {
        consema_document::FormationStatus::Complete => "Complete".to_owned(),
        consema_document::FormationStatus::Recovered => "Recovered".to_owned(),
    }
}

fn diagnostic_codes(diagnostics: &[consema_core::Diagnostic]) -> String {
    join(
        &diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<Vec<_>>(),
    )
}

/// Dispatches one step (or the absence of a step) and emits exactly one
/// group's key set in the fixed order.
fn emit_step_facts(
    facts: &mut Facts,
    state: &mut DocState,
    step: Option<&[consema_core::ObjectEntry]>,
) {
    let op = step
        .map(|fields| object_string(fields, "op").unwrap_or(""))
        .unwrap_or("");
    match op {
        "query-native" => emit_native_query(facts, state, step),
        "query-syntax" => emit_syntax_query(facts, state, step),
        "project" => emit_project(facts, state, step),
        "materialize" => emit_materialize(facts, state, step),
        "edit" => emit_edit(facts, state, step),
        _ => {
            emit_native_query(facts, state, None);
            emit_syntax_query(facts, state, None);
            emit_project(facts, state, None);
            emit_materialize(facts, state, None);
            emit_edit(facts, state, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Query steps
// ---------------------------------------------------------------------------

fn emit_native_query(
    facts: &mut Facts,
    state: &mut DocState,
    step: Option<&[consema_core::ObjectEntry]>,
) {
    if state.query_native_run {
        return;
    }
    state.query_native_run = true;
    let mut blocked = || {
        set(facts, "query.native.status", "Blocked");
        set(facts, "query.native.failure", "");
        set(facts, "query.native.count", "");
        set(facts, "query.native.matches", "");
    };
    let Some(fields) = step else {
        blocked();
        return;
    };
    if object_string(fields, "op").unwrap_or("") != "query-native" || !state.document_parsed() {
        blocked();
        return;
    }
    let domain_id = object_string(fields, "domain").unwrap_or("");
    let domain_version = object_usize(fields, "domain_version").unwrap_or(1) as u32;
    let domain = match (domain_id, domain_version) {
        ("json.native-semantic-query", 1) => QueryDomain::json_native_v1(),
        ("json.native-semantic-query", 2) => QueryDomain::json_native_v2(),
        ("toml.native-semantic-query", 1) => QueryDomain::toml_native_v1(),
        _ => {
            set(facts, "query.native.status", "Failed");
            set(
                facts,
                "query.native.failure",
                "core.query.domain-mismatch@1",
            );
            set(facts, "query.native.count", "");
            set(facts, "query.native.matches", "");
            return;
        }
    };
    let executable = match build_query_definition(fields, domain) {
        Ok(executable) => executable,
        Err(failure) => {
            set(facts, "query.native.status", "Failed");
            set(facts, "query.native.failure", query_failure_code(&failure));
            set(facts, "query.native.count", "");
            set(facts, "query.native.matches", "");
            return;
        }
    };
    let mut limits = QueryLimits::default();
    apply_query_limits(fields, &mut limits);
    let cancellation = CancellationToken::new();
    if let Some(document) = &state.json_document {
        match execute_json_query(&executable, document, limits, &cancellation) {
            Ok(execution) => {
                let matches = execution.matches();
                let items = matches.iter().map(json_native_match).collect::<Vec<_>>();
                set(facts, "query.native.status", "Completed");
                set(facts, "query.native.failure", "");
                set(facts, "query.native.count", items.len().to_string());
                set(facts, "query.native.matches", join(&items));
            }
            Err(failure) => {
                set(facts, "query.native.status", "Failed");
                set(facts, "query.native.failure", query_failure_code(&failure));
                set(facts, "query.native.count", "");
                set(facts, "query.native.matches", "");
            }
        }
        return;
    }
    if let Some(document) = &state.toml_document {
        match execute_toml_query(&executable, document, limits, &cancellation) {
            Ok(execution) => {
                let matches = execution.matches();
                let items = matches.iter().map(toml_native_match).collect::<Vec<_>>();
                set(facts, "query.native.status", "Completed");
                set(facts, "query.native.failure", "");
                set(facts, "query.native.count", items.len().to_string());
                set(facts, "query.native.matches", join(&items));
            }
            Err(failure) => {
                set(facts, "query.native.status", "Failed");
                set(facts, "query.native.failure", query_failure_code(&failure));
                set(facts, "query.native.count", "");
                set(facts, "query.native.matches", "");
            }
        }
    }
}

/// Renders one JSON native match identity fact.
fn json_native_match(match_: &JsonMatch) -> String {
    match match_ {
        JsonMatch::Value { kind, .. } => {
            let name = kind.map(json_value_kind_name).unwrap_or("?");
            format!("V:{name}")
        }
        JsonMatch::ObjectMember { ordinal, name, .. } => {
            let name = name
                .as_deref()
                .map(escape)
                .unwrap_or_else(|| "?".to_owned());
            format!("M:{ordinal}:{name}")
        }
        JsonMatch::ArrayElement { ordinal, .. } => format!("E:{ordinal}"),
    }
}

/// Renders one TOML native match identity fact.
fn toml_native_match(match_: &TomlMatch) -> String {
    match match_ {
        TomlMatch::Item { kind, .. } => format!("I:{}", toml_item_kind_name(*kind)),
        TomlMatch::Entry { ordinal, name, .. } => {
            format!("M:{ordinal}:{}", escape(name))
        }
        TomlMatch::ArrayElement { ordinal, .. } => format!("E:{ordinal}"),
    }
}

fn emit_syntax_query(
    facts: &mut Facts,
    state: &mut DocState,
    step: Option<&[consema_core::ObjectEntry]>,
) {
    if state.query_syntax_run {
        return;
    }
    state.query_syntax_run = true;
    let mut blocked = || {
        set(facts, "query.syntax.status", "Blocked");
        set(facts, "query.syntax.failure", "");
        set(facts, "query.syntax.count", "");
        set(facts, "query.syntax.matches", "");
    };
    let Some(fields) = step else {
        blocked();
        return;
    };
    if object_string(fields, "op").unwrap_or("") != "query-syntax" || !state.document_parsed() {
        blocked();
        return;
    }
    let domain_id = object_string(fields, "domain").unwrap_or("");
    let domain_version = object_usize(fields, "domain_version").unwrap_or(1) as u32;
    let domain = match (domain_id, domain_version) {
        ("json.lossless-syntax-query", 1) => QueryDomain::json_lossless_syntax_v1(),
        ("json.lossless-syntax-query", 2) => QueryDomain::json_lossless_syntax_v2(),
        ("toml.lossless-syntax-query", 1) => QueryDomain::toml_lossless_syntax_v1(),
        _ => {
            set(facts, "query.syntax.status", "Failed");
            set(
                facts,
                "query.syntax.failure",
                "core.query.domain-mismatch@1",
            );
            set(facts, "query.syntax.count", "");
            set(facts, "query.syntax.matches", "");
            return;
        }
    };
    let executable = match build_query_definition(fields, domain) {
        Ok(executable) => executable,
        Err(failure) => {
            set(facts, "query.syntax.status", "Failed");
            set(facts, "query.syntax.failure", query_failure_code(&failure));
            set(facts, "query.syntax.count", "");
            set(facts, "query.syntax.matches", "");
            return;
        }
    };
    let mut limits = QueryLimits::default();
    apply_query_limits(fields, &mut limits);
    let cancellation = CancellationToken::new();
    if let Some(document) = &state.json_document {
        match execute_json_syntax_query(&executable, document, limits, &cancellation) {
            Ok(execution) => {
                let matches = execution.matches();
                let items = matches.iter().map(json_syntax_match).collect::<Vec<_>>();
                set(facts, "query.syntax.status", "Completed");
                set(facts, "query.syntax.failure", "");
                set(facts, "query.syntax.count", items.len().to_string());
                set(facts, "query.syntax.matches", join(&items));
            }
            Err(failure) => {
                set(facts, "query.syntax.status", "Failed");
                set(facts, "query.syntax.failure", query_failure_code(&failure));
                set(facts, "query.syntax.count", "");
                set(facts, "query.syntax.matches", "");
            }
        }
        return;
    }
    if let Some(document) = &state.toml_document {
        match execute_toml_syntax_query(&executable, document, limits, &cancellation) {
            Ok(execution) => {
                let matches = execution.matches();
                let items = matches.iter().map(toml_syntax_match).collect::<Vec<_>>();
                set(facts, "query.syntax.status", "Completed");
                set(facts, "query.syntax.failure", "");
                set(facts, "query.syntax.count", items.len().to_string());
                set(facts, "query.syntax.matches", join(&items));
            }
            Err(failure) => {
                set(facts, "query.syntax.status", "Failed");
                set(facts, "query.syntax.failure", query_failure_code(&failure));
                set(facts, "query.syntax.count", "");
                set(facts, "query.syntax.matches", "");
            }
        }
    }
}

fn json_syntax_match(match_: &JsonSyntaxMatch) -> String {
    format!("{}@{}", match_.kind().as_str(), match_.ordinal())
}

fn toml_syntax_match(match_: &TomlSyntaxMatch) -> String {
    format!("{}@{}", match_.kind().as_str(), match_.ordinal())
}

// ---------------------------------------------------------------------------
// Projection / materialization / edit steps
// ---------------------------------------------------------------------------

fn emit_project(
    facts: &mut Facts,
    state: &mut DocState,
    step: Option<&[consema_core::ObjectEntry]>,
) {
    if state.project_run {
        return;
    }
    state.project_run = true;
    let mut blocked = || {
        set(facts, "project.status", "Blocked");
        set(facts, "project.failure", "");
        set(facts, "project.fidelity", "");
        set(facts, "project.value_kind", "");
        set(facts, "project.report", "");
        set(facts, "project.provenance_entries", "");
    };
    let Some(fields) = step else {
        blocked();
        return;
    };
    if object_string(fields, "op").unwrap_or("") != "project" || !state.document_parsed() {
        blocked();
        return;
    }
    if let Some(document) = &state.json_document {
        let target = match object_string(fields, "target").unwrap_or("BestExactCore") {
            "ProjectAsObject" => ProjectionTarget::ProjectAsObjectV1,
            "ProjectAsEntryMapping" => ProjectionTarget::ProjectAsEntryMappingV1,
            "Json5BestExactCore" => ProjectionTarget::Json5BestExactCoreV1,
            _ => ProjectionTarget::BestExactCoreV1,
        };
        let mut builder = ProjectionRequestBuilder::new(target);
        match object_string(fields, "duplicate_policy").unwrap_or("Reject") {
            "FirstWins" => builder = builder.global_duplicate_policy(DuplicateKeyPolicy::FirstWins),
            "LastWins" => builder = builder.global_duplicate_policy(DuplicateKeyPolicy::LastWins),
            _ => {}
        }
        let request = match builder.build() {
            Ok(request) => request,
            Err(failure) => {
                set(facts, "project.status", "Failed");
                set(
                    facts,
                    "project.failure",
                    json_projection_failure_code(&failure),
                );
                set(facts, "project.fidelity", "");
                set(facts, "project.value_kind", "");
                set(facts, "project.report", "");
                set(facts, "project.provenance_entries", "");
                return;
            }
        };
        match document.project(&request) {
            ProjectionResult::Complete(complete) => {
                state.value = Some(complete.value.clone());
                state.projected = true;
                set(facts, "project.status", "Completed");
                set(facts, "project.failure", "");
                set(facts, "project.fidelity", fidelity_name(complete.fidelity));
                set(
                    facts,
                    "project.value_kind",
                    portable_value_kind_name(complete.value.kind()),
                );
                set(
                    facts,
                    "project.report",
                    json_event_summary(complete.report.events()),
                );
                set(
                    facts,
                    "project.provenance_entries",
                    complete.provenance.entries().len().to_string(),
                );
            }
            ProjectionResult::Failed(attempt) => {
                let code = attempt
                    .diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.code.clone())
                    .unwrap_or_default();
                set(facts, "project.status", "Failed");
                set(facts, "project.failure", code);
                set(facts, "project.fidelity", "");
                set(facts, "project.value_kind", "");
                set(
                    facts,
                    "project.report",
                    json_event_summary(attempt.report.events()),
                );
                set(facts, "project.provenance_entries", "");
            }
        }
        return;
    }
    if let Some(document) = &state.toml_document {
        let request =
            consema_toml::ProjectionRequest::new(consema_toml::ProjectionTarget::BestExactCoreV1);
        match document.project(request) {
            consema_toml::ProjectionResult::Complete(complete) => {
                state.value = Some(complete.value.clone());
                state.projected = true;
                set(facts, "project.status", "Completed");
                set(facts, "project.failure", "");
                set(
                    facts,
                    "project.fidelity",
                    toml_fidelity_name(complete.fidelity),
                );
                set(
                    facts,
                    "project.value_kind",
                    portable_value_kind_name(complete.value.kind()),
                );
                set(
                    facts,
                    "project.report",
                    toml_report_summary(complete.report.events()),
                );
                set(
                    facts,
                    "project.provenance_entries",
                    complete.provenance.entries().len().to_string(),
                );
            }
            consema_toml::ProjectionResult::Failed(attempt) => {
                let code = attempt
                    .diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.code.clone())
                    .unwrap_or_default();
                set(facts, "project.status", "Failed");
                set(facts, "project.failure", code);
                set(facts, "project.fidelity", "");
                set(facts, "project.value_kind", "");
                set(
                    facts,
                    "project.report",
                    toml_report_summary(attempt.report.events()),
                );
                set(facts, "project.provenance_entries", "");
            }
        }
    }
}

/// Renders the JSON projection report as ordered EventKind:count pairs.
fn json_event_summary(events: &[consema_json::ProjectionEvent]) -> String {
    let mut order = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for event in events {
        let name = projection_event_kind_name(event.kind).to_owned();
        if !counts.contains_key(&name) {
            order.push(name.clone());
        }
        *counts.entry(name).or_default() += 1;
    }
    let parts = order
        .iter()
        .map(|name| format!("{name}:{}", counts[name]))
        .collect::<Vec<_>>();
    join(&parts)
}

/// Renders the TOML projection report as ordered diagnostic codes.
fn toml_report_summary(events: &[consema_core::Diagnostic]) -> String {
    join(
        &events
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<Vec<_>>(),
    )
}

fn emit_materialize(
    facts: &mut Facts,
    state: &mut DocState,
    step: Option<&[consema_core::ObjectEntry]>,
) {
    if state.materialize_run {
        return;
    }
    state.materialize_run = true;
    let mut blocked = || {
        set(facts, "materialize.status", "Blocked");
        set(facts, "materialize.failure", "");
        set(facts, "materialize.output", "");
        set(facts, "materialize.fidelity", "");
    };
    let Some(fields) = step else {
        blocked();
        return;
    };
    if object_string(fields, "op").unwrap_or("") != "materialize" || !state.document_parsed() {
        blocked();
        return;
    }
    let value = match object_string(fields, "input").unwrap_or("project") {
        "project" | "" => match &state.value {
            Some(value) if state.projected => value.clone(),
            _ => {
                blocked();
                return;
            }
        },
        "value" => match decode_materialize_value(fields) {
            Some(value) => value,
            None => {
                set(facts, "materialize.status", "Failed");
                set(
                    facts,
                    "materialize.failure",
                    "core.protocol.invalid-value@1",
                );
                set(facts, "materialize.output", "");
                set(facts, "materialize.fidelity", "");
                return;
            }
        },
        _ => {
            set(facts, "materialize.status", "Failed");
            set(
                facts,
                "materialize.failure",
                "core.protocol.invalid-value@1",
            );
            set(facts, "materialize.output", "");
            set(facts, "materialize.fidelity", "");
            return;
        }
    };
    let Some(request) = build_materialization_request(fields) else {
        set(facts, "materialize.status", "Failed");
        set(
            facts,
            "materialize.failure",
            "core.materialization.invalid-request@1",
        );
        set(facts, "materialize.output", "");
        set(facts, "materialize.fidelity", "");
        return;
    };
    if state.json_document.is_some() {
        match json_materialize(&value, &request) {
            consema_document::MaterializationResult::Complete(complete) => {
                set(facts, "materialize.status", "Completed");
                set(facts, "materialize.failure", "");
                set(
                    facts,
                    "materialize.output",
                    escape(&String::from_utf8_lossy(complete.document.render())),
                );
                set(
                    facts,
                    "materialize.fidelity",
                    materialization_fidelity_name(complete.fidelity),
                );
            }
            consema_document::MaterializationResult::Failed(attempt) => {
                set(facts, "materialize.status", "Failed");
                set(
                    facts,
                    "materialize.failure",
                    materialization_failure_code(&attempt.failure),
                );
                set(facts, "materialize.output", "");
                set(facts, "materialize.fidelity", "");
            }
        }
        return;
    }
    match toml_materialize(&value, &request) {
        consema_document::MaterializationResult::Complete(complete) => {
            set(facts, "materialize.status", "Completed");
            set(facts, "materialize.failure", "");
            set(
                facts,
                "materialize.output",
                escape(&String::from_utf8_lossy(complete.document.render())),
            );
            set(
                facts,
                "materialize.fidelity",
                materialization_fidelity_name(complete.fidelity),
            );
        }
        consema_document::MaterializationResult::Failed(attempt) => {
            set(facts, "materialize.status", "Failed");
            set(
                facts,
                "materialize.failure",
                materialization_failure_code(&attempt.failure),
            );
            set(facts, "materialize.output", "");
            set(facts, "materialize.fidelity", "");
        }
    }
}

/// Decodes the materialize input descriptor through the canonical transport
/// JSON decoder (RFC 0015 §3.2).
fn decode_materialize_value(fields: &[consema_core::ObjectEntry]) -> Option<PortableValue> {
    if let Some(mapping) = object_field(fields, "entry_mapping").and_then(PortableValue::as_object)
    {
        let key_json = object_string(mapping, "key_json")?;
        let value_json = object_string(mapping, "value_json")?;
        let key = decode_json(key_json.as_bytes(), ProtocolLimits::default()).ok()?;
        let value = decode_json(value_json.as_bytes(), ProtocolLimits::default()).ok()?;
        let mut builder = EntryMappingBuilder::new();
        builder.push(key, value);
        return Some(builder.build());
    }
    let value_json = object_string(fields, "value_json").unwrap_or("");
    decode_json(value_json.as_bytes(), ProtocolLimits::default()).ok()
}

/// Builds the materialization request from the descriptor.
fn build_materialization_request(
    fields: &[consema_core::ObjectEntry],
) -> Option<MaterializationRequest> {
    let target_profile = object_string(fields, "target_profile").unwrap_or("");
    let style = object_string(fields, "style").unwrap_or("");
    if target_profile.is_empty() || style.is_empty() {
        return None;
    }
    let target_id = target_profile.split('@').next().unwrap_or(&target_profile);
    let style_id = style.split('@').next().unwrap_or(&style);
    let mut request = MaterializationRequest::new(
        ProfileId::new(target_id, 1),
        MaterializationStyleId::new(style_id, 1),
    );
    match object_string(fields, "newline").unwrap_or("Lf") {
        "None" => request = request.with_newline(NewlinePolicy::None),
        "CrLf" => request = request.with_newline(NewlinePolicy::CrLf),
        _ => request = request.with_newline(NewlinePolicy::Lf),
    }
    if let Some(desc) = object_field(fields, "limits").and_then(PortableValue::as_object) {
        let mut limits = MaterializationLimits::default();
        if let Some(value) = object_usize(desc, "max_output_bytes") {
            limits.max_output_bytes = value;
        }
        if let Some(value) = object_usize(desc, "max_input_nodes") {
            limits.max_input_nodes = value;
        }
        if let Some(value) = object_usize(desc, "max_depth") {
            limits.max_depth = value;
        }
        if let Some(value) = object_usize(desc, "max_provenance_entries") {
            limits.max_provenance_entries = value;
        }
        request = request.with_limits(limits);
    }
    Some(request)
}

fn emit_edit(facts: &mut Facts, state: &mut DocState, step: Option<&[consema_core::ObjectEntry]>) {
    if state.edit_run {
        return;
    }
    state.edit_run = true;
    let mut blocked = || {
        set(facts, "edit.status", "Blocked");
        set(facts, "edit.failure", "");
        set(facts, "edit.output", "");
        set(facts, "edit.source_edit_count", "");
    };
    let Some(fields) = step else {
        blocked();
        return;
    };
    if object_string(fields, "op").unwrap_or("") != "edit" || !state.document_parsed() {
        blocked();
        return;
    }
    // Go parity (emit_edit): a declared foreign source that fails to parse
    // reports edit.failure = core.source.invalid-sequence@1 (JSON face).
    if state.json_document.is_some() && !ensure_foreign(state) {
        set(facts, "edit.status", "Failed");
        set(facts, "edit.failure", "core.source.invalid-sequence@1");
        set(facts, "edit.output", "");
        set(facts, "edit.source_edit_count", "");
        return;
    }
    if let Some(document) = &state.json_document {
        let mut builder = consema_json::EditTransactionBuilder::new(document);
        if !apply_json_edit_operations(&mut builder, state, fields) {
            set(facts, "edit.status", "Failed");
            set(facts, "edit.failure", "core.edit.target-not-found@1");
            set(facts, "edit.output", "");
            set(facts, "edit.source_edit_count", "");
            return;
        }
        match document.commit(&builder.build()) {
            Ok(commit) => {
                set(facts, "edit.status", "Completed");
                set(facts, "edit.failure", "");
                set(
                    facts,
                    "edit.output",
                    escape(&String::from_utf8_lossy(commit.document.render())),
                );
                set(
                    facts,
                    "edit.source_edit_count",
                    commit.change_set.source_edits().len().to_string(),
                );
            }
            Err(failure) => {
                set(facts, "edit.status", "Failed");
                set(facts, "edit.failure", json_edit_failure_code(&failure));
                set(facts, "edit.output", "");
                set(facts, "edit.source_edit_count", "");
            }
        }
        return;
    }
    if let Some(document) = &state.toml_document {
        let mut builder = consema_toml::EditTransactionBuilder::new(document);
        if !apply_toml_edit_operations(&mut builder, state, fields) {
            set(facts, "edit.status", "Failed");
            set(facts, "edit.failure", "core.edit.target-not-found@1");
            set(facts, "edit.output", "");
            set(facts, "edit.source_edit_count", "");
            return;
        }
        match document.commit(&builder.build()) {
            Ok(commit) => {
                set(facts, "edit.status", "Completed");
                set(facts, "edit.failure", "");
                set(
                    facts,
                    "edit.output",
                    escape(&String::from_utf8_lossy(commit.document.render())),
                );
                set(
                    facts,
                    "edit.source_edit_count",
                    commit.change_set.source_edits().len().to_string(),
                );
            }
            Err(failure) => {
                set(facts, "edit.status", "Failed");
                set(facts, "edit.failure", toml_edit_failure_code(&failure));
                set(facts, "edit.output", "");
                set(facts, "edit.source_edit_count", "");
            }
        }
    }
}

/// Parses the foreign source when the case declares one (the wrong-snapshot
/// edit cases); false reports a declared source that failed to decode or
/// parse (edit.failure = core.source.invalid-sequence@1, Go parity).
fn ensure_foreign(state: &mut DocState) -> bool {
    if state.foreign_json.is_some()
        || state.foreign_toml.is_some()
        || (state.foreign_source.is_empty() && state.foreign_source_hex.is_empty())
    {
        return true;
    }
    let source_bytes = if state.foreign_source_hex.is_empty() {
        state.foreign_source.as_bytes().to_vec()
    } else {
        match decode_hex(&state.foreign_source_hex) {
            Some(bytes) => bytes,
            None => return false,
        }
    };
    let limits = state.parse_limits;
    match state.format.as_str() {
        "json" => {
            let profile = match state.profile_name.as_str() {
                "json.strict@1" => JsonProfile::StrictV1,
                "jsonc.bounded@1" => JsonProfile::JsoncBoundedV1,
                "json5.standard@1" => JsonProfile::Json5StandardV1,
                _ => JsonProfile::StrictV1,
            };
            match parse_json(source_bytes.as_slice(), profile, limits) {
                Ok(document) => {
                    state.foreign_json = Some(document);
                    true
                }
                Err(_) => false,
            }
        }
        "toml" => match parse_toml(source_bytes.as_slice(), TomlProfile::Toml10V1, limits) {
            Ok(document) => {
                state.foreign_toml = Some(document);
                true
            }
            Err(_) => false,
        },
        _ => false,
    }
}

/// Applies the declared JSON edit operations; false means a descriptor
/// could not be resolved.
fn apply_json_edit_operations(
    builder: &mut consema_json::EditTransactionBuilder,
    state: &DocState,
    fields: &[consema_core::ObjectEntry],
) -> bool {
    let Some(operations) = object_field(fields, "operations").and_then(PortableValue::as_sequence)
    else {
        return false;
    };
    for operation in operations {
        let Some(op) = operation.as_object() else {
            return false;
        };
        let name = object_string(op, "operation").unwrap_or("");
        let Some(target) = resolve_json_target(state, op) else {
            return false;
        };
        match name {
            "semantic-scalar" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(policy) = json_representation_policy(op) else {
                    return false;
                };
                builder.semantic_scalar(target, value, policy);
            }
            "literal-scalar" => {
                let Some(literal) = hex_field(op, "literal_hex") else {
                    return false;
                };
                builder.literal_scalar(target, literal);
            }
            "insert-member" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(placement) = resolve_json_placement(state, op) else {
                    return false;
                };
                let name = object_string(op, "name").unwrap_or("");
                builder.insert_member(target, name, value, placement);
            }
            "remove-member" => {
                builder.remove_member(target);
            }
            "rename-member" => {
                let name = object_string(op, "name").unwrap_or("");
                builder.rename_member(target, name);
            }
            "insert-array-element" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(placement) = resolve_json_placement(state, op) else {
                    return false;
                };
                builder.insert_array_element(target, value, placement);
            }
            "remove-array-element" => {
                builder.remove_array_element(target);
            }
            _ => return false,
        }
    }
    true
}

/// Applies the declared TOML edit operations.
fn apply_toml_edit_operations(
    builder: &mut consema_toml::EditTransactionBuilder,
    state: &DocState,
    fields: &[consema_core::ObjectEntry],
) -> bool {
    let Some(operations) = object_field(fields, "operations").and_then(PortableValue::as_sequence)
    else {
        return false;
    };
    for operation in operations {
        let Some(op) = operation.as_object() else {
            return false;
        };
        let name = object_string(op, "operation").unwrap_or("");
        let Some(target) = resolve_toml_target(state, op) else {
            return false;
        };
        match name {
            "semantic-scalar" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(policy) = toml_representation_policy(op) else {
                    return false;
                };
                builder.semantic_scalar(target, value, policy);
            }
            "literal-scalar" => {
                let Some(literal) = hex_field(op, "literal_hex") else {
                    return false;
                };
                builder.literal_scalar(target, literal);
            }
            "insert-entry" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(placement) = resolve_toml_placement(state, op) else {
                    return false;
                };
                let key = object_string(op, "name").unwrap_or("");
                builder.insert_entry(target, key, value, placement);
            }
            "remove-entry" => {
                builder.remove_entry(target);
            }
            "rename-entry" => {
                let key = object_string(op, "name").unwrap_or("");
                builder.rename_entry(target, key);
            }
            "insert-array-element" => {
                let Some(value) = value_from_desc(op) else {
                    return false;
                };
                let Some(placement) = resolve_toml_placement(state, op) else {
                    return false;
                };
                builder.insert_array_element(target, value, placement);
            }
            "remove-array-element" => {
                builder.remove_array_element(target);
            }
            _ => return false,
        }
    }
    true
}

/// Resolves one JSON target descriptor to a node handle.
fn resolve_json_target(state: &DocState, op: &[consema_core::ObjectEntry]) -> Option<NodeRef> {
    let target = object_field(op, "target")?.as_object()?;
    let kind = object_string(target, "kind").unwrap_or("");
    let ordinal = object_usize(target, "ordinal").unwrap_or(0);
    let foreign = object_bool(target, "foreign").unwrap_or(false);
    let document = if foreign {
        state.foreign_json.as_ref()?
    } else {
        state.json_document.as_ref()?
    };
    let root = document.root();
    match kind {
        "root" => Some(root.node_ref()),
        "member" | "member-value" | "member-key" => {
            let members = match root.object_members() {
                SemanticAvailability::Available(Some(members)) => members,
                _ => return None,
            };
            let member = members.get(ordinal)?;
            match kind {
                "member" => Some(member.node_ref()),
                "member-value" => Some(member.value_node_ref()),
                _ => Some(member.key_node_ref()),
            }
        }
        "array-element" | "array-element-value" => {
            let elements = match root.array_elements() {
                SemanticAvailability::Available(Some(elements)) => elements,
                _ => return None,
            };
            let element = elements.get(ordinal)?;
            match kind {
                "array-element" => Some(element.node_ref()),
                _ => Some(element.value_node_ref()),
            }
        }
        _ => None,
    }
}

/// Resolves one TOML target descriptor to a node handle.
fn resolve_toml_target(state: &DocState, op: &[consema_core::ObjectEntry]) -> Option<NodeRef> {
    let target = object_field(op, "target")?.as_object()?;
    let kind = object_string(target, "kind").unwrap_or("");
    let ordinal = object_usize(target, "ordinal").unwrap_or(0);
    let foreign = object_bool(target, "foreign").unwrap_or(false);
    let document = if foreign {
        state.foreign_toml.as_ref()?
    } else {
        state.toml_document.as_ref()?
    };
    let root = document.root();
    match kind {
        "root" => Some(root.node_ref()),
        "entry" | "entry-item" | "entry-key" => {
            let entries = root.table_entries()?;
            let entry = entries.get(ordinal)?;
            match kind {
                "entry" => Some(entry.node_ref()),
                "entry-item" => Some(entry.item_node_ref()),
                _ => Some(entry.key_node_ref()),
            }
        }
        "array-element" | "array-element-item" => {
            let elements = root.array_elements()?;
            let element = elements.get(ordinal)?;
            match kind {
                "array-element" => Some(element.node_ref()),
                _ => Some(element.item_node_ref()),
            }
        }
        _ => None,
    }
}

/// Resolves one JSON placement descriptor.
fn resolve_json_placement(
    state: &DocState,
    op: &[consema_core::ObjectEntry],
) -> Option<AssociationPlacement> {
    let placement = object_field(op, "placement").and_then(PortableValue::as_object);
    let Some(placement) = placement else {
        return Some(AssociationPlacement::End);
    };
    match object_string(placement, "at").unwrap_or("") {
        "start" => return Some(AssociationPlacement::Start),
        "end" => return Some(AssociationPlacement::End),
        _ => {}
    }
    if let Some(ordinal) = object_usize(placement, "before_ordinal") {
        let anchor = json_ordinal_anchor(state, ordinal)?;
        return Some(AssociationPlacement::Before(anchor));
    }
    if let Some(ordinal) = object_usize(placement, "after_ordinal") {
        let anchor = json_ordinal_anchor(state, ordinal)?;
        return Some(AssociationPlacement::After(anchor));
    }
    Some(AssociationPlacement::End)
}

/// Resolves one TOML placement descriptor.
fn resolve_toml_placement(
    state: &DocState,
    op: &[consema_core::ObjectEntry],
) -> Option<AssociationPlacement> {
    let placement = object_field(op, "placement").and_then(PortableValue::as_object);
    let Some(placement) = placement else {
        return Some(AssociationPlacement::End);
    };
    match object_string(placement, "at").unwrap_or("") {
        "start" => return Some(AssociationPlacement::Start),
        "end" => return Some(AssociationPlacement::End),
        _ => {}
    }
    if let Some(ordinal) = object_usize(placement, "before_ordinal") {
        let anchor = toml_ordinal_anchor(state, ordinal)?;
        return Some(AssociationPlacement::Before(anchor));
    }
    if let Some(ordinal) = object_usize(placement, "after_ordinal") {
        let anchor = toml_ordinal_anchor(state, ordinal)?;
        return Some(AssociationPlacement::After(anchor));
    }
    Some(AssociationPlacement::End)
}

/// Resolves the anchor of the current JSON container: the members for
/// insert-member, the elements for insert-array-element.
fn json_ordinal_anchor(state: &DocState, ordinal: usize) -> Option<NodeRef> {
    let document = state.json_document.as_ref()?;
    let root = document.root();
    if let Some(members) = availability_option(root.object_members()) {
        if let Some(member) = members.get(ordinal) {
            return Some(member.node_ref());
        }
    }
    if let Some(elements) = availability_option(root.array_elements()) {
        if let Some(element) = elements.get(ordinal) {
            return Some(element.node_ref());
        }
    }
    None
}

/// Resolves the anchor of the current TOML container.
fn toml_ordinal_anchor(state: &DocState, ordinal: usize) -> Option<NodeRef> {
    let document = state.toml_document.as_ref()?;
    let root = document.root();
    if let Some(entries) = root.table_entries() {
        if let Some(entry) = entries.get(ordinal) {
            return Some(entry.node_ref());
        }
    }
    if let Some(elements) = root.array_elements() {
        if let Some(element) = elements.get(ordinal) {
            return Some(element.node_ref());
        }
    }
    None
}

/// Builds one core value from a scalar descriptor.
fn value_from_desc(op: &[consema_core::ObjectEntry]) -> Option<PortableValue> {
    let desc = object_field(op, "value")?.as_object()?;
    if object_bool(desc, "null").is_some() {
        return Some(PortableValue::null());
    }
    if let Some(boolean) = object_bool(desc, "boolean") {
        return Some(PortableValue::boolean(boolean));
    }
    if let Some(integer) = object_string(desc, "integer") {
        let parsed = BigInteger::parse_decimal(integer).ok()?;
        return Some(PortableValue::integer(parsed));
    }
    if let Some(decimal) = object_string(desc, "decimal") {
        let parsed = Decimal::parse_json_number(decimal).ok()?;
        return Some(PortableValue::decimal(parsed));
    }
    if let Some(text) = object_string(desc, "string") {
        return Some(PortableValue::string(text));
    }
    if let Some(bits) = object_string(desc, "binary64") {
        let bits = u64::from_str_radix(bits.strip_prefix("0x").unwrap_or(bits), 16).ok()?;
        return Some(PortableValue::binary_float64(BinaryFloat64::from_bits(
            bits,
        )));
    }
    None
}

/// Decodes one hex field into bytes.
fn hex_field(op: &[consema_core::ObjectEntry], key: &str) -> Option<Vec<u8>> {
    let text = object_string(op, key)?;
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < text.len() {
        let octet = u8::from_str_radix(&text[index..index + 2], 16).ok()?;
        bytes.push(octet);
        index += 2;
    }
    Some(bytes)
}

fn json_representation_policy(op: &[consema_core::ObjectEntry]) -> Option<RepresentationPolicy> {
    match object_string(op, "policy").unwrap_or("") {
        "PreserveCompatible" => Some(RepresentationPolicy::PreserveCompatible),
        "CanonicalForProfile" => Some(RepresentationPolicy::CanonicalForProfile),
        "PreserveElseCanonical" => Some(RepresentationPolicy::PreserveElseCanonical),
        "ExactLiteral" => Some(RepresentationPolicy::ExactLiteral),
        _ => None,
    }
}

fn toml_representation_policy(
    op: &[consema_core::ObjectEntry],
) -> Option<consema_toml::RepresentationPolicy> {
    match object_string(op, "policy").unwrap_or("") {
        "PreserveCompatible" => Some(consema_toml::RepresentationPolicy::PreserveCompatible),
        "CanonicalForProfile" => Some(consema_toml::RepresentationPolicy::CanonicalForProfile),
        "PreserveElseCanonical" => Some(consema_toml::RepresentationPolicy::PreserveElseCanonical),
        "ExactLiteral" => Some(consema_toml::RepresentationPolicy::ExactLiteral),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Source face
// ---------------------------------------------------------------------------

/// Runs one source-face case and returns its ordered facts.
fn run_source_case(fields: &[consema_core::ObjectEntry]) -> Result<Facts, String> {
    let mut facts = Facts::new();
    let input = object_field(fields, "input")
        .and_then(PortableValue::as_object)
        .ok_or("source case without input")?;
    let raw = match object_string(input, "raw_hex").unwrap_or("") {
        "" => object_string(input, "source")
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        text => decode_hex(text).ok_or("invalid raw_hex")?,
    };
    let request = build_encoding_request(fields)?;
    let limits = SourceLimits::default();
    let snapshot = match SourceSnapshot::from_raw(raw.clone(), request, limits) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            set(&mut facts, "source.status", "Failed");
            set(&mut facts, "source.failure", source_error_code(&error));
            set(&mut facts, "source.encoding", "");
            set(&mut facts, "source.bom", "");
            set(&mut facts, "source.declared", "");
            set(&mut facts, "source.digest", "");
            set(&mut facts, "source.len", "");
            set(&mut facts, "source.text", "");
            emit_position_facts(&mut facts, fields, None);
            emit_patch_facts(&mut facts, fields, &raw, None, request);
            return Ok(facts);
        }
    };
    let encoding = snapshot.encoding_facts();
    set(&mut facts, "source.status", "Ok");
    set(&mut facts, "source.failure", "");
    set(&mut facts, "source.encoding", encoding.selected().as_str());
    set(
        &mut facts,
        "source.bom",
        encoding
            .bom()
            .map(|bom| bom.encoding().as_str())
            .unwrap_or(""),
    );
    set(
        &mut facts,
        "source.declared",
        encoding
            .declaration()
            .map(|encoding| encoding.as_str())
            .unwrap_or(""),
    );
    set(&mut facts, "source.digest", snapshot.digest().to_hex());
    set(&mut facts, "source.len", snapshot.len().to_string());
    match snapshot.decoded_text() {
        Some(text) => set(&mut facts, "source.text", escape(text)),
        None => set(&mut facts, "source.text", "binary"),
    }
    emit_position_facts(&mut facts, fields, Some(&snapshot));
    emit_patch_facts(&mut facts, fields, &raw, Some(&snapshot), request);
    Ok(facts)
}

/// Builds the encoding-resolution request from the descriptor.
fn build_encoding_request(fields: &[consema_core::ObjectEntry]) -> Result<EncodingRequest, String> {
    let request = object_field(fields, "request")
        .and_then(PortableValue::as_object)
        .ok_or("source case without request")?;
    let profile_default = object_string(request, "profile_default").unwrap_or("");
    let mut built =
        EncodingRequest::new(source_encoding(profile_default).ok_or("unknown profile_default")?);
    if let Some(declaration) = object_string(request, "declaration") {
        built = built.with_declaration(source_encoding(declaration).ok_or("unknown declaration")?);
    }
    if let Some(override_) = object_string(request, "caller_override") {
        built = built
            .with_caller_override(source_encoding(override_).ok_or("unknown caller_override")?);
    }
    match object_string(request, "bom_policy").unwrap_or("DetectUnicode") {
        "DetectUnicode" | "" => {}
        "TreatAsContent" => {
            built = built.with_bom_policy(consema_document::BomPolicy::TreatAsContent)
        }
        other => return Err(format!("unknown bom_policy {other:?}")),
    }
    Ok(built)
}

/// Resolves one stable encoding name.
fn source_encoding(name: &str) -> Option<SourceEncoding> {
    match name {
        "binary" => Some(SourceEncoding::Binary),
        "utf-8" => Some(SourceEncoding::Utf8),
        "utf-16le" => Some(SourceEncoding::Utf16Le),
        "utf-16be" => Some(SourceEncoding::Utf16Be),
        "latin-1" => Some(SourceEncoding::Latin1),
        "windows-1252" => Some(SourceEncoding::WindowsCodePage(
            consema_document::WindowsCodePage::from_number(1252)?,
        )),
        _ => None,
    }
}

/// Emits the byte-exact position conversions.
fn emit_position_facts(
    facts: &mut Facts,
    fields: &[consema_core::ObjectEntry],
    snapshot: Option<&SourceSnapshot>,
) {
    let positions = object_field(fields, "positions")
        .and_then(PortableValue::as_sequence)
        .unwrap_or(&[]);
    for (index, position) in positions.iter().enumerate() {
        let key = format!("source.position.{index}.");
        let Some(raw_byte) = position.as_integer().and_then(BigInteger::to_usize) else {
            continue;
        };
        match snapshot.map(|s| s.decoded_position(raw_byte)) {
            Some(Ok(position)) => {
                set(
                    facts,
                    format!("{key}raw_byte"),
                    position.raw_byte.to_string(),
                );
                set(
                    facts,
                    format!("{key}decoded_utf8"),
                    position.decoded_utf8_byte.to_string(),
                );
                set(
                    facts,
                    format!("{key}scalars"),
                    position.unicode_scalar_offset.to_string(),
                );
                set(
                    facts,
                    format!("{key}utf16"),
                    position.utf16_code_unit_offset.to_string(),
                );
            }
            _ => {
                set(facts, format!("{key}raw_byte"), raw_byte.to_string());
                set(facts, format!("{key}decoded_utf8"), "");
                set(facts, format!("{key}scalars"), "");
                set(facts, format!("{key}utf16"), "");
            }
        }
    }
}

/// Emits the optional SourcePatch application facts.
fn emit_patch_facts(
    facts: &mut Facts,
    fields: &[consema_core::ObjectEntry],
    raw: &[u8],
    snapshot: Option<&SourceSnapshot>,
    request: EncodingRequest,
) {
    let mut skipped = || {
        set(facts, "patch.status", "Skipped");
        set(facts, "patch.failure", "");
        set(facts, "patch.output", "");
        set(facts, "patch.replacement_count", "");
    };
    let Some(patch_desc) = object_field(fields, "patch").and_then(PortableValue::as_object) else {
        skipped();
        return;
    };
    let Some(snapshot) = snapshot else {
        skipped();
        return;
    };
    let Some(replacements) = build_source_replacements(snapshot, patch_desc) else {
        set(facts, "patch.status", "Failed");
        set(facts, "patch.failure", "core.protocol.invalid-value@1");
        set(facts, "patch.output", "");
        set(facts, "patch.replacement_count", "");
        return;
    };
    let limits = SourcePatchLimits::default();
    let patch = match SourcePatch::create(snapshot, replacements.clone(), BTreeMap::new(), limits) {
        Ok(patch) => patch,
        Err(error) => {
            set(facts, "patch.status", "Failed");
            set(facts, "patch.failure", error.code());
            set(facts, "patch.output", "");
            set(facts, "patch.replacement_count", "");
            return;
        }
    };
    let base = match object_string(patch_desc, "apply_to").unwrap_or("base") {
        "tampered" => {
            let mut tampered = raw.to_vec();
            if let Some(last) = tampered.last_mut() {
                *last ^= 0x01;
            }
            match SourceSnapshot::from_raw(tampered, request, SourceLimits::default()) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    set(facts, "patch.status", "Failed");
                    set(facts, "patch.failure", source_error_code(&error));
                    set(facts, "patch.output", "");
                    set(facts, "patch.replacement_count", "");
                    return;
                }
            }
        }
        _ => snapshot.clone(),
    };
    match patch.apply(&base, limits) {
        Ok(target) => {
            set(facts, "patch.status", "Applied");
            set(facts, "patch.failure", "");
            set(
                facts,
                "patch.output",
                escape(&String::from_utf8_lossy(target.bytes())),
            );
            set(
                facts,
                "patch.replacement_count",
                replacements.len().to_string(),
            );
        }
        Err(error) => {
            set(facts, "patch.status", "Failed");
            set(facts, "patch.failure", error.code());
            set(facts, "patch.output", "");
            set(facts, "patch.replacement_count", "");
        }
    }
}

/// Builds the replacements from the descriptor; the original bytes are
/// taken from the base snapshot (both sides do the same).
fn build_source_replacements(
    snapshot: &SourceSnapshot,
    patch_desc: &[consema_core::ObjectEntry],
) -> Option<Vec<SourceReplacement>> {
    let descriptions = object_field(patch_desc, "replacements")?.as_sequence()?;
    let base = snapshot.bytes();
    let mut replacements = Vec::with_capacity(descriptions.len());
    for description in descriptions {
        let desc = description.as_object()?;
        let old_start = object_usize(desc, "old_start")?;
        let old_end = object_usize(desc, "old_end")?;
        if old_end < old_start || old_end > base.len() {
            return None;
        }
        let replacement = decode_hex(object_string(desc, "replacement_hex").unwrap_or(""))?;
        let original = base[old_start..old_end].to_vec();
        replacements.push(SourceReplacement::new(
            old_start,
            old_end,
            original,
            replacement,
        ));
    }
    Some(replacements)
}

/// Decodes one lowercase hex text.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < text.len() {
        let octet = u8::from_str_radix(&text[index..index + 2], 16).ok()?;
        bytes.push(octet);
        index += 2;
    }
    Some(bytes)
}
