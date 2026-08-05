use consema::properties::{
    self, DuplicatePolicy, EditTransactionBuilder, Fidelity, JavaString, JavaStringStatus,
    ProjectedLocation, ProjectionLimits, ProjectionRequest, ProjectionResult, PropertiesEscapeKind,
    PropertiesMatch, PropertiesParseLimits, PropertiesProfile, PropertiesSyntaxKind,
    PropertiesValueState, ProvenanceRelation,
};
use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, EntryMappingBuilder, OperatorCall,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QueryTerminalState, StableFailure,
};
use consema_document::{
    AssociationPlacement, EditPlanSourceId, FormationStatus, MaterializationFidelity,
    MaterializationLimits, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, OperationSupport, ParseLimits, ProfileId, SourceEncoding, SourcePatchLimits,
    WindowsCodePage,
};
use std::collections::{HashMap, HashSet};

use super::{ConformanceReport, VectorCase, object_field};

const SUITE: &str = "consema.java-properties.conformance@1";

/// Embedded language-neutral Java Properties family suite bytes.
pub const PROPERTIES_V1_VECTORS_JSON: &str =
    include_str!("../../../conformance/vectors/java-properties-v1.json");

/// Runs the embedded `consema.java-properties.conformance@1` suite.
#[must_use]
pub fn run_properties_v1() -> ConformanceReport {
    run_properties_v1_json(PROPERTIES_V1_VECTORS_JSON)
}

/// Runs one Java Properties family suite from strict JSON text.
#[must_use]
pub fn run_properties_v1_json(json: &str) -> ConformanceReport {
    let vectors = consema_json::parse(
        json.as_bytes(),
        consema_json::JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published Java Properties vectors must form a document");
    let request = consema_json::ProjectionRequestBuilder::new(
        consema_json::ProjectionTarget::BestExactCoreV1,
    )
    .build()
    .expect("fixed projection request");
    let value = match vectors.project(&request) {
        consema_json::ProjectionResult::Complete(result) => result.value,
        consema_json::ProjectionResult::Failed(attempt) => {
            return ConformanceReport {
                suite: SUITE.to_owned(),
                passed: Vec::new(),
                failed: vec![("suite.parse".to_owned(), format!("{attempt:?}"))],
            };
        }
    };
    let root = value
        .as_object()
        .expect("Java Properties vector root object");
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
    for case in cases {
        let fields = case.as_object().expect("Java Properties case object");
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
    let required = match case.id {
        id if id.starts_with("formation.")
            && !matches!(
                id,
                "formation.malformed-unicode-recovery-matrix"
                    | "formation.recovery-never-publishes-partial-operation"
            ) =>
        {
            "java-properties.document@1"
        }
        id if id.starts_with("formation.") || id.starts_with("resource.formation-") => {
            "java-properties.formation@1"
        }
        id if id.starts_with("query.") => "java-properties.query@1",
        id if id.starts_with("projection.") || id.starts_with("resource.projection-") => {
            "java-properties.projection@1"
        }
        id if id.starts_with("materialization.") => "java-properties.materialization@1",
        id if id.starts_with("edit.") || id.starts_with("registry.") => "java-properties.edit@1",
        _ => return Err("runner does not recognize published Properties case".to_owned()),
    };
    if case.capability != required {
        return Err(format!("expected capability {required}"));
    }
    match case.id {
        "formation.reader-lines-escapes-duplicates" => formation_reader(case),
        "formation.empty-blank-comment-empty-key" => formation_basic_matrix(case),
        "formation.mixed-line-terminators" => formation_terminators(case),
        "formation.continuation-and-backslash-parity" => formation_continuations(case),
        "formation.escape-and-java-utf16-matrix" => formation_java_strings(case),
        "formation.malformed-unicode-recovery-matrix" => formation_recovery_matrix(case),
        "formation.reader-explicit-encodings" => formation_reader_encodings(case),
        "formation.latin1-byte-and-bom-content" => formation_latin1(case),
        "formation.recovery-never-publishes-partial-operation" => recovered_is_atomic(case),
        "query.native-duplicates-and-escape-ownership" => native_query(case),
        "query.logical-and-syntax-order" => logical_syntax_query(case),
        "query.validation-limit-cancellation" => query_failures(case),
        "projection.exact-duplicates-and-fragments" => projection_exact(case),
        "projection.unpaired-and-recovered-atomic-failure" => projection_failures(case),
        "projection.explicit-jdk-table-collapse" => projection_collapse(case),
        "materialization.canonical-styles-encodings-and-closure" => materialization_styles(case),
        "materialization.atomic-failures-and-limits" => materialization_limits(case),
        "edit.all-five-operations" => edit_all_operations(case),
        "edit.dry-run-patch-proof-conflict-atomicity" => edit_audit_artifacts(case),
        "resource.formation-limit-matrix" => formation_limits(case),
        "resource.projection-limit-matrix" => projection_limits(case),
        "registry.frozen-five-operation-surface" => operation_registry(case),
        _ => Err("runner does not recognize published Properties case".to_owned()),
    }
}

fn formation_reader(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && document.natural_lines().len() == expected_usize(case, "natural_lines")?
            && document.logical_lines().len() == expected_usize(case, "logical_lines")?
            && document.comments().len() == expected_usize(case, "comments")?
            && document.properties().len() == expected_usize(case, "properties")?
            && document.escapes().len() == expected_usize(case, "escapes")?
            && unicode_keys(&document)? == expected_strings(case, "keys")?
            && unicode_values(&document)? == expected_strings(case, "values")?
            && document
                .properties()
                .iter()
                .map(|property| value_state_name(property.value_state()).to_owned())
                .collect::<Vec<_>>()
                == expected_strings(case, "states")?
            && (document.properties()[1].duplicate_group()
                == document.properties()[2].duplicate_group()
                && document.properties()[1].duplicate_group().is_some())
                == expected_bool(case, "duplicate_group")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "Reader formation facts differed",
    )
}

fn formation_basic_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let samples = input_strings(case, "samples")?;
    let formations = expected_strings(case, "formations")?;
    let properties = expected_usizes(case, "properties")?;
    let comments = expected_usizes(case, "comments")?;
    if samples.len() != formations.len()
        || samples.len() != properties.len()
        || samples.len() != comments.len()
    {
        return Err("basic formation vector lengths differ".to_owned());
    }
    for (index, source) in samples.iter().enumerate() {
        let document = parse_reader_text(source)?;
        require(
            status_name(document.formation_status()) == formations[index]
                && document.properties().len() == properties[index]
                && document.comments().len() == comments[index]
                && exact_coverage(&document),
            format!("basic formation sample {index} differed"),
        )?;
    }
    Ok(())
}

fn formation_terminators(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let terminators = document
        .natural_lines()
        .iter()
        .map(|line| match line.line_break_span() {
            None => "Eof".to_owned(),
            Some(span) => match &document.render()[span.start_byte()..span.end_byte()] {
                b"\n" => "Lf".to_owned(),
                b"\r" => "Cr".to_owned(),
                b"\r\n" => "CrLf".to_owned(),
                _ => "Other".to_owned(),
            },
        })
        .collect::<Vec<_>>();
    require(
        document.natural_lines().len() == expected_usize(case, "natural_lines")?
            && document.logical_lines().len() == expected_usize(case, "logical_lines")?
            && document.properties().len() == expected_usize(case, "properties")?
            && terminators == expected_strings(case, "terminators")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        format!("line terminator facts differed: {terminators:?}"),
    )
}

fn formation_continuations(case: &VectorCase<'_>) -> Result<(), String> {
    let samples = input_field(case, "samples")?
        .as_sequence()
        .ok_or("input.samples must be Sequence")?;
    for (index, sample) in samples.iter().enumerate() {
        let fields = sample.as_object().ok_or("sample must be Object")?;
        let source = object_string(fields, "source")?;
        let expected_value = object_string(fields, "value_hex")?;
        let document = parse_reader_text(source)?;
        require(
            document.formation_status() == FormationStatus::Complete
                && hex(document.properties()[0].value().utf16be_bytes()) == expected_value
                && document.natural_lines().len() == object_usize(fields, "natural_lines")?
                && document.logical_lines().len() == object_usize(fields, "logical_lines")?
                && exact_coverage(&document),
            format!("continuation/backslash sample {index} differed"),
        )?;
    }
    require(
        expected_bool(case, "all_complete")? && expected_bool(case, "exact_coverage")?,
        "continuation suite expectation must require complete exact documents",
    )
}

fn formation_java_strings(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let values = document
        .properties()
        .iter()
        .map(|property| hex(property.value().utf16be_bytes()))
        .collect::<Vec<_>>();
    let statuses = document
        .properties()
        .iter()
        .map(|property| java_status_name(property.value().status()).to_owned())
        .collect::<Vec<_>>();
    let escapes = document
        .escapes()
        .iter()
        .map(|escape| escape_kind_name(escape.kind()).to_owned())
        .collect::<Vec<_>>();
    require(
        values == expected_strings(case, "value_utf16be_hex")?
            && statuses == expected_strings(case, "statuses")?
            && escapes == expected_strings(case, "escape_kinds")?,
        format!(
            "Java UTF-16/escape facts differed: values={values:?}, statuses={statuses:?}, escapes={escapes:?}"
        ),
    )
}

fn formation_recovery_matrix(case: &VectorCase<'_>) -> Result<(), String> {
    let samples = input_strings(case, "samples")?;
    let formations = expected_strings(case, "formations")?;
    let property_counts = expected_usizes(case, "property_counts")?;
    let error_counts = expected_usizes(case, "error_counts")?;
    if samples.len() != formations.len()
        || samples.len() != property_counts.len()
        || samples.len() != error_counts.len()
    {
        return Err("recovery matrix lengths differ".to_owned());
    }
    for (index, source) in samples.iter().enumerate() {
        let document = parse_reader_text(source)?;
        require(
            status_name(document.formation_status()) == formations[index]
                && document.properties().len() == property_counts[index]
                && document.error_lines().len() == error_counts[index]
                && (document.error_lines().is_empty()
                    || document.error_lines()[0].code() == expected_string(case, "code")?),
            format!("malformed Unicode sample {index} differed"),
        )?;
        if index + 1 == samples.len() {
            require(
                document.properties()[0]
                    .value()
                    .to_unicode()
                    .map_err(debug_error)?
                    == expected_string(case, "uppercase_u_value")?,
                "uppercase U behavior differed",
            )?;
        }
    }
    Ok(())
}

fn formation_reader_encodings(case: &VectorCase<'_>) -> Result<(), String> {
    let samples = input_field(case, "samples")?
        .as_sequence()
        .ok_or("input.samples must be Sequence")?;
    for (index, sample) in samples.iter().enumerate() {
        let fields = sample.as_object().ok_or("encoding sample must be Object")?;
        let encoding = source_encoding(object_string(fields, "encoding")?)?;
        let bytes = decode_hex(object_string(fields, "source_hex")?)?;
        let document =
            properties::parse_reader(bytes.clone(), encoding, PropertiesParseLimits::default())
                .map_err(debug_error)?;
        require(
            document.formation_status() == FormationStatus::Complete
                && document.render() == bytes
                && document.properties()[0]
                    .key()
                    .to_unicode()
                    .map_err(debug_error)?
                    == object_string(fields, "key")?
                && document.properties()[0]
                    .value()
                    .to_unicode()
                    .map_err(debug_error)?
                    == object_string(fields, "value")?
                && format!("{:?}", document.source().encoding_facts().bom())
                    == object_string(fields, "bom")?
                && exact_coverage(&document),
            format!("Reader encoding sample {index} differed"),
        )?;
    }
    require(
        expected_bool(case, "all_complete")?
            && expected_bool(case, "render_identity")?
            && expected_bool(case, "exact_coverage")?,
        "encoding vector expectations must require complete exact identity",
    )
}

fn formation_latin1(case: &VectorCase<'_>) -> Result<(), String> {
    let bytes = decode_hex(input_string(case, "source_hex")?)?;
    let document =
        properties::parse_latin1(bytes, PropertiesParseLimits::default()).map_err(debug_error)?;
    require(
        hex(document.properties()[0].key().utf16be_bytes())
            == expected_string(case, "key_utf16be_hex")?
            && hex(document.properties()[0].value().utf16be_bytes())
                == expected_string(case, "value_utf16be_hex")?
            && format!("{:?}", document.source().encoding_facts().bom())
                == expected_string(case, "bom")?
            && document
                .lossless_syntax_kinds()
                .contains(&PropertiesSyntaxKind::Bom)
                == expected_bool(case, "bom_syntax")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "Latin-1 byte/BOM-content facts differed",
    )
}

fn recovered_is_atomic(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let projection_code = match document.project(ProjectionRequest::best_exact_entry_mapping()) {
        ProjectionResult::Failed(failed) => failed
            .diagnostics
            .first()
            .map(|diagnostic| diagnostic.code.clone()),
        ProjectionResult::Complete(_) => None,
    };
    let edit_code = document
        .commit(&EditTransactionBuilder::new(&document).build())
        .err()
        .map(|failure| failure.diagnostic_code().to_owned());
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && unicode_keys(&document)? == expected_strings(case, "keys")?
            && document.error_lines().len() == expected_usize(case, "error_lines")?
            && document.error_lines()[0].code() == expected_string(case, "code")?
            && projection_code.as_deref() == Some(expected_string(case, "projection_code")?)
            && edit_code.as_deref() == Some(expected_string(case, "edit_code")?),
        "recovered Properties document exposed a partial operation result",
    )
}

fn native_query(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let key_bytes = decode_hex(input_string(case, "key_utf16be_hex")?)?;
    let duplicates = QueryExpression::Input
        .then(OperatorCall::new("properties.document-properties", 1))
        .then(
            OperatorCall::new("properties.property-key-equals", 1)
                .with_argument("key", PortableValue::bytes(key_bytes)),
        )
        .then(OperatorCall::new("core.take", 1).with_argument(
            "count",
            PortableValue::integer(BigInteger::from(
                i64::try_from(input_usize(case, "take")?).map_err(|_| "take too large")?,
            )),
        ))
        .then(OperatorCall::new("properties.duplicate-group", 1));
    let duplicate_result = properties::execute_properties_query(
        &native_executable(duplicates)?,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let escapes = QueryExpression::Input
        .then(OperatorCall::new("properties.document-properties", 1))
        .then(OperatorCall::new("core.take", 1).with_argument(
            "count",
            PortableValue::integer(BigInteger::from(
                i64::try_from(input_usize(case, "take")?).map_err(|_| "take too large")?,
            )),
        ))
        .then(OperatorCall::new("properties.property-escapes", 1));
    let escape_result = properties::execute_properties_query(
        &native_executable(escapes)?,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    require(
        duplicate_result.matches().len() == expected_usize(case, "duplicate_matches")?
            && escape_result.matches().len() == expected_usize(case, "escape_matches")?
            && duplicate_result.matches().iter().all(|item| {
                matches!(
                    item,
                    PropertiesMatch::Property {
                        duplicate_group: Some(_),
                        ..
                    }
                )
            }) == expected_bool(case, "duplicate_group")?
            && escape_result
                .matches()
                .iter()
                .all(|item| matches!(item, PropertiesMatch::Escape { .. }))
                == expected_bool(case, "escape_roles")?
            && terminal_name(duplicate_result.terminal_state())
                == expected_string(case, "terminal")?,
        "native duplicate/escape query facts differed",
    )
}

fn logical_syntax_query(case: &VectorCase<'_>) -> Result<(), String> {
    let logical = parse_reader_text(input_string(case, "logical_source")?)?;
    let expression = QueryExpression::Input
        .then(OperatorCall::new("properties.logical-lines", 1))
        .then(OperatorCall::new(
            "properties.logical-line-natural-lines",
            1,
        ));
    let logical_result = properties::execute_properties_query(
        &native_executable(expression)?,
        &logical,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let ordinals = logical_result
        .matches()
        .iter()
        .map(|item| match item {
            PropertiesMatch::NaturalLine { ordinal, .. } => Ok(*ordinal),
            _ => Err("logical query returned non-natural line".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let syntax = parse_reader_text(input_string(case, "syntax_source")?)?;
    let text = QueryExpression::Input.then(
        OperatorCall::new("properties.syntax-text-equals", 1)
            .with_argument("text", PortableValue::string(input_string(case, "text")?)),
    );
    let raw = QueryExpression::Input.then(
        OperatorCall::new("properties.syntax-raw-bytes-equals", 1).with_argument(
            "bytes",
            PortableValue::bytes(decode_hex(input_string(case, "raw_hex")?)?),
        ),
    );
    let utf16 = QueryExpression::Input.then(
        OperatorCall::new("properties.syntax-utf16be-equals", 1).with_argument(
            "code_units",
            PortableValue::bytes(decode_hex(input_string(case, "utf16be_hex")?)?),
        ),
    );
    let executable = QueryDefinition::new(QueryDomain::java_properties_lossless_syntax_v1())
        .with_expression(QueryExpression::StructureOrderMerge(vec![raw, text, utf16]))
        .validate()
        .map_err(debug_error)?
        .bind(&capabilities())
        .map_err(debug_error)?;
    let syntax_result = properties::execute_properties_syntax_query(
        &executable,
        &syntax,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let kinds = syntax_result
        .matches()
        .iter()
        .map(|item| item.kind().as_str().to_owned())
        .collect::<Vec<_>>();
    let increasing = syntax_result
        .matches()
        .windows(2)
        .all(|pair| pair[0].ordinal() < pair[1].ordinal());
    require(
        ordinals == expected_usizes(case, "natural_ordinals")?
            && kinds == expected_strings(case, "syntax_kinds")?
            && syntax_result.matches().iter().all(|item| {
                format!("{:?}", item.node_ref().role())
                    == expected_string(case, "syntax_role").unwrap_or("")
            })
            && increasing == expected_bool(case, "strictly_increasing_ordinals")?,
        format!("logical/syntax query facts differed: ordinals={ordinals:?}, kinds={kinds:?}"),
    )
}

fn query_failures(case: &VectorCase<'_>) -> Result<(), String> {
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
    let invalid_argument = match invalid {
        Err(QueryFailure::InvalidArgument { argument, .. }) => Some(argument),
        _ => None,
    };
    let document = parse_case(case)?;
    let all = native_executable(
        QueryExpression::Input.then(OperatorCall::new("properties.document-properties", 1)),
    )?;
    let failure = properties::execute_properties_query(
        &all,
        &document,
        QueryLimits {
            max_steps: 100,
            max_results: input_usize(case, "max_results")?,
        },
        &CancellationToken::new(),
    )
    .map_or_else(Ok, |_| {
        Err("vector requires a query result limit".to_owned())
    })?;
    let cancellation = CancellationToken::new();
    let mut cursor = properties::execute_properties_query_cursor(
        &all,
        &document,
        QueryLimits::default(),
        &cancellation,
    )
    .map_err(debug_error)?;
    let first = cursor.next().is_some();
    cancellation.cancel();
    let exhausted = cursor.next().is_none();
    require(
        invalid_argument.as_deref() == Some(expected_string(case, "invalid_argument")?)
            && failure.diagnostic_code() == expected_string(case, "limit_code")?
            && first == expected_bool(case, "first_yielded")?
            && exhausted
            && cursor.terminal_state().map(terminal_name)
                == Some(expected_string(case, "terminal")?),
        "query validation, limit, or cancellation differed",
    )
}

fn projection_exact(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let ProjectionResult::Complete(result) =
        document.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("exact Properties projection failed".to_owned());
    };
    let entries = result
        .value
        .as_entry_mapping()
        .ok_or("exact projection did not produce EntryMapping")?;
    let keys = entries
        .iter()
        .map(|entry| entry.key().as_string().map(ToOwned::to_owned).ok_or("key"))
        .collect::<Result<Vec<_>, _>>()?;
    let values = entries
        .iter()
        .map(|entry| {
            entry
                .value()
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or("value")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let escape = relation_present(&result, ProvenanceRelation::EscapeDerived);
    let fragments = result.provenance.entries().iter().any(|entry| {
        entry
            .origins
            .iter()
            .filter(|origin| origin.relation == ProvenanceRelation::ValueFragment)
            .count()
            == 2
    });
    let association = result
        .provenance
        .entries()
        .iter()
        .any(|entry| matches!(entry.projected, ProjectedLocation::Association(_)));
    require(
        fidelity_name(result.fidelity) == expected_string(case, "fidelity")?
            && keys == expected_strings(case, "keys")?
            && values == expected_strings(case, "values")?
            && result.report.events().len() == expected_usize(case, "events")?
            && escape == expected_bool(case, "escape_provenance")?
            && fragments == expected_bool(case, "two_value_fragments")?
            && association == expected_bool(case, "association_provenance")?,
        "exact Properties projection facts differed",
    )
}

fn projection_failures(case: &VectorCase<'_>) -> Result<(), String> {
    let unpaired = parse_reader_text(input_string(case, "unpaired_source")?)?;
    let recovered = parse_reader_text(input_string(case, "recovered_source")?)?;
    let ProjectionResult::Failed(unpaired_failure) =
        unpaired.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("unpaired surrogate projection completed".to_owned());
    };
    let ProjectionResult::Failed(recovered_failure) =
        recovered.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("recovered projection completed".to_owned());
    };
    require(
        unpaired_failure.diagnostics[0].code == expected_string(case, "unpaired_code")?
            && unpaired_failure.diagnostics[0]
                .primary
                .as_ref()
                .is_some_and(|location| {
                    location.start_byte
                        == expected_usize(case, "unpaired_start_byte").unwrap_or(usize::MAX) as u64
                })
            && recovered_failure.diagnostics[0].code == expected_string(case, "recovered_code")?
            && (unpaired_failure.report.events().is_empty()
                && recovered_failure.report.events().is_empty())
                == expected_bool(case, "empty_reports")?,
        "unpaired/recovered projection atomic failure differed",
    )
}

fn projection_collapse(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let unique_code = match document.project(ProjectionRequest::require_object(
        DuplicatePolicy::RequireUnique,
    )) {
        ProjectionResult::Failed(failed) => failed.diagnostics[0].code.clone(),
        ProjectionResult::Complete(_) => {
            return Err("unique projection accepted duplicates".to_owned());
        }
    };
    let ProjectionResult::Complete(first) = document.project(ProjectionRequest::require_object(
        DuplicatePolicy::FirstWins,
    )) else {
        return Err("FirstWins projection failed".to_owned());
    };
    let ProjectionResult::Complete(last) = document.project(ProjectionRequest::require_object(
        DuplicatePolicy::LastWinsJdkTable,
    )) else {
        return Err("LastWinsJdkTable projection failed".to_owned());
    };
    require(
        unique_code == expected_string(case, "unique_code")?
            && fidelity_name(first.fidelity) == expected_string(case, "first_fidelity")?
            && first.report.events().len() == expected_usize(case, "events")?
            && first.report.events()[0].code == expected_string(case, "event_code")?
            && object_pairs(&first.value)? == expected_pairs(case, "first_entries")?
            && object_pairs(&last.value)? == expected_pairs(case, "last_entries")?
            && relation_present(&first, ProvenanceRelation::Collapsed)
                == expected_bool(case, "collapsed_provenance")?,
        "explicit JDK table collapse differed",
    )
}

fn materialization_styles(case: &VectorCase<'_>) -> Result<(), String> {
    let reader_value = flat_mapping(input_field(case, "reader")?)?;
    let MaterializationResult::Complete(reader) = properties::materialize(
        &reader_value,
        &materialization_request(PropertiesProfile::ReaderV1),
    ) else {
        return Err("Reader materialization failed".to_owned());
    };
    let latin_value = flat_mapping(input_field(case, "latin1")?)?;
    let latin_request =
        materialization_request(PropertiesProfile::Latin1V1).with_newline(NewlinePolicy::CrLf);
    let MaterializationResult::Complete(latin) =
        properties::materialize(&latin_value, &latin_request)
    else {
        return Err("Latin-1 materialization failed".to_owned());
    };
    let utf16_value = flat_mapping(input_field(case, "utf16be")?)?;
    let utf16_request = materialization_request(PropertiesProfile::ReaderV1)
        .with_encoding(SourceEncoding::Utf16Be)
        .with_newline(NewlinePolicy::CrLf);
    let MaterializationResult::Complete(utf16) =
        properties::materialize(&utf16_value, &utf16_request)
    else {
        return Err("UTF-16BE Reader materialization failed".to_owned());
    };
    let cp_value = flat_mapping(input_field(case, "cp1252")?)?;
    let cp = WindowsCodePage::from_number(1252).ok_or("CP1252 unavailable")?;
    let cp_request = materialization_request(PropertiesProfile::ReaderV1)
        .with_encoding(SourceEncoding::WindowsCodePage(cp));
    let MaterializationResult::Complete(cp_result) =
        properties::materialize(&cp_value, &cp_request)
    else {
        return Err("CP1252 Reader materialization failed".to_owned());
    };
    let closure = [
        (&reader, &reader_value),
        (&latin, &latin_value),
        (&utf16, &utf16_value),
        (&cp_result, &cp_value),
    ]
    .iter()
    .all(|(result, value)| {
        matches!(
            result
                .document
                .project(ProjectionRequest::best_exact_entry_mapping()),
            ProjectionResult::Complete(ref projection) if projection.value == **value
        )
    });
    require(
        reader.document.render() == expected_string(case, "reader_source")?.as_bytes()
            && latin.document.render() == expected_string(case, "latin1_source")?.as_bytes()
            && utf16.document.source().decoded_text()
                == Some(expected_string(case, "utf16be_decoded")?)
            && hex(cp_result.document.render()) == expected_string(case, "cp1252_hex")?
            && [
                reader.fidelity,
                latin.fidelity,
                utf16.fidelity,
                cp_result.fidelity,
            ]
            .iter()
            .all(|fidelity| *fidelity == MaterializationFidelity::Exact)
                == expected_bool(case, "exact_fidelity")?
            && closure == expected_bool(case, "closure")?,
        format!(
            "canonical materialization differed: reader={:?}, latin={:?}, utf16={:?}, cp={}",
            String::from_utf8_lossy(reader.document.render()),
            String::from_utf8_lossy(latin.document.render()),
            utf16.document.source().decoded_text(),
            hex(cp_result.document.render()),
        ),
    )
}

fn materialization_limits(case: &VectorCase<'_>) -> Result<(), String> {
    let scalar_code = match properties::materialize(
        &PortableValue::string("scalar"),
        &materialization_request(PropertiesProfile::ReaderV1),
    ) {
        MaterializationResult::Failed(failed) => failed.failure.diagnostic_code().to_owned(),
        MaterializationResult::Complete(_) => return Err("scalar materialized".to_owned()),
    };
    let value = flat_mapping(input_field(case, "value")?)?;
    let encoding_code = match properties::materialize(
        &value,
        &materialization_request(PropertiesProfile::Latin1V1).with_encoding(SourceEncoding::Utf8),
    ) {
        MaterializationResult::Failed(failed) => failed.failure.diagnostic_code().to_owned(),
        MaterializationResult::Complete(_) => {
            return Err("Latin-1 accepted UTF-8 request".to_owned());
        }
    };
    let names = input_strings(case, "limit_names")?;
    let expected = expected_strings(case, "limit_outcomes")?;
    if names.len() != expected.len() {
        return Err("materialization limit vector lengths differ".to_owned());
    }
    let mut outcomes = Vec::new();
    for name in &names {
        let mut limits = MaterializationLimits::default();
        match name.as_str() {
            "max_input_nodes" => limits.max_input_nodes = 1,
            "max_output_bytes" => limits.max_output_bytes = 2,
            "max_depth" => limits.max_depth = 0,
            "max_report_entries" => limits.max_report_entries = 0,
            "max_provenance_entries" => limits.max_provenance_entries = 1,
            other => return Err(format!("unknown materialization limit {other}")),
        }
        match properties::materialize(
            &value,
            &materialization_request(PropertiesProfile::ReaderV1).with_limits(limits),
        ) {
            MaterializationResult::Complete(_) => outcomes.push("Complete".to_owned()),
            MaterializationResult::Failed(failed) => {
                if failed.failure.diagnostic_code() != expected_string(case, "limit_code")? {
                    return Err(format!(
                        "{name} returned wrong failure code {} ({:?})",
                        failed.failure.diagnostic_code(),
                        failed.failure,
                    ));
                }
                outcomes.push("Failed".to_owned());
            }
        }
    }
    require(
        scalar_code == expected_string(case, "scalar_code")?
            && encoding_code == expected_string(case, "encoding_code")?
            && outcomes == expected,
        format!("materialization failure outcomes differed: {outcomes:?}"),
    )
}

fn edit_all_operations(case: &VectorCase<'_>) -> Result<(), String> {
    let source = input_string(case, "source")?;
    let expected = expected_strings(case, "outputs")?;
    let mut outputs = Vec::new();
    let mut edit_counts = Vec::new();

    let document = parse_reader_text(source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.semantic_value(
        document.properties()[0].node_ref(),
        JavaString::from_unicode(input_string(case, "semantic_value")?),
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_reader_text(source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.literal_value(
        document.properties()[0].node_ref(),
        input_string(case, "literal_value")?.as_bytes(),
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_reader_text(source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.insert_property(
        document.node_ref(),
        JavaString::from_unicode(input_string(case, "new_key")?),
        JavaString::from_unicode(input_string(case, "new_value")?),
        AssociationPlacement::End,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_reader_text(source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.remove_property(document.properties()[0].node_ref());
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_reader_text(source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.rename_property(
        document.properties()[0].node_ref(),
        JavaString::from_unicode(input_string(case, "renamed_key")?),
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    require(
        outputs == expected
            && edit_counts.iter().all(|count| *count == 1)
                == expected_bool(case, "one_source_edit_each")?,
        format!("five edit outputs differed: {outputs:?}; edits={edit_counts:?}"),
    )
}

fn edit_audit_artifacts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let first = document.properties()[0].node_ref();
    let second = document.properties()[1].node_ref();
    let mut builder = EditTransactionBuilder::new(&document);
    builder
        .rename_property(
            first,
            JavaString::from_unicode(input_string(case, "rename")?),
        )
        .semantic_value(
            second,
            JavaString::from_unicode(input_string(case, "value")?),
        );
    let transaction = builder.build();
    let plan = document
        .dry_run(
            &transaction,
            EditPlanSourceId::new(input_string(case, "source_id")?).map_err(debug_error)?,
        )
        .map_err(debug_error)?;
    let commit = document.commit(&transaction).map_err(debug_error)?;
    let replay = commit
        .source_patch
        .apply(document.source(), SourcePatchLimits::default())
        .map_err(debug_error)?;
    let proof = commit.untouched_proof.verify(
        document.source(),
        commit.document.source(),
        commit.source_patch.replacements(),
    );

    let mut conflict = EditTransactionBuilder::new(&document);
    conflict
        .semantic_value(first, JavaString::from_unicode("x"))
        .rename_property(first, JavaString::from_unicode("renamed"));
    let conflict_code = document
        .commit(&conflict.build())
        .expect_err("duplicate target must fail")
        .diagnostic_code()
        .to_owned();
    require(
        commit.document.render() == expected_string(case, "source")?.as_bytes()
            && commit.change_set.source_edits().len() == expected_usize(case, "edit_count")?
            && plan.operations().len() == expected_usize(case, "dry_run_operations")?
            && (replay.bytes() == commit.document.render())
                == expected_bool(case, "patch_replays")?
            && proof.is_ok() == expected_bool(case, "proof_verifies")?
            && conflict_code == expected_string(case, "conflict_code")?
            && (document.render() == input_string(case, "source")?.as_bytes())
                == expected_bool(case, "base_unchanged")?,
        "edit patch/proof/conflict atomicity differed",
    )
}

fn formation_limits(case: &VectorCase<'_>) -> Result<(), String> {
    let descriptors = input_field(case, "limits")?
        .as_sequence()
        .ok_or("input.limits must be Sequence")?;
    let mut fatal = 0;
    let mut outcomes = HashMap::new();
    for descriptor in descriptors {
        let fields = descriptor
            .as_object()
            .ok_or("limit descriptor must be Object")?;
        let name = object_string(fields, "name")?;
        let source = object_string(fields, "source")?;
        let value = object_usize(fields, "value")?;
        let mut limits = PropertiesParseLimits::default();
        set_parse_limit(&mut limits, name, value)?;
        let failed =
            properties::parse_reader(source.as_bytes(), SourceEncoding::Utf8, limits).is_err();
        if failed {
            fatal += 1;
        }
        outcomes.insert(name.to_owned(), failed);
    }
    require(
        fatal == expected_usize(case, "fatal_count")?
            && outcomes.len() == descriptors.len()
            && expected_bool(case, "no_partial_documents")?,
        format!("formation limit outcomes differed: fatal={fatal}, outcomes={outcomes:?}"),
    )
}

fn projection_limits(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let names = input_strings(case, "limits")?;
    let mut failed_count = 0;
    for name in names {
        let mut limits = ProjectionLimits::default();
        match name.as_str() {
            "max_source_associations" => limits.max_source_associations = 0,
            "max_value_nodes" => limits.max_value_nodes = 1,
            "max_provenance_units" => limits.max_provenance_units = 1,
            other => return Err(format!("unknown projection limit {other}")),
        }
        let ProjectionResult::Failed(failed) =
            document.project(ProjectionRequest::best_exact_entry_mapping().with_limits(limits))
        else {
            return Err(format!("projection limit {name} did not fail"));
        };
        if failed.diagnostics[0].code == expected_string(case, "code")? {
            failed_count += 1;
        }
    }
    let duplicate = parse_reader_text(input_string(case, "duplicate_source")?)?;
    let ProjectionResult::Failed(failed) = duplicate.project(
        ProjectionRequest::require_object(DuplicatePolicy::FirstWins).with_limits(
            ProjectionLimits {
                max_report_entries: 0,
                ..ProjectionLimits::default()
            },
        ),
    ) else {
        return Err("report limit did not fail".to_owned());
    };
    if failed.diagnostics[0].code == expected_string(case, "code")? {
        failed_count += 1;
    }
    require(
        failed_count == expected_usize(case, "failed_count")?,
        format!("projection limit failed count was {failed_count}"),
    )
}

fn operation_registry(case: &VectorCase<'_>) -> Result<(), String> {
    let expected = expected_strings(case, "operations")?;
    for profile_name_value in input_strings(case, "profiles")? {
        let registry = properties::format_operation_registry(profile_name(&profile_name_value)?);
        let operations = registry
            .operations()
            .iter()
            .map(|descriptor| descriptor.id().to_string())
            .collect::<Vec<_>>();
        let supported = registry
            .operations()
            .iter()
            .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
            .count();
        require(
            operations == expected && supported == expected_usize(case, "supported")?,
            format!("operation registry differed for {profile_name_value}"),
        )?;
    }
    Ok(())
}

fn collect_edit(
    document: &properties::Document,
    builder: EditTransactionBuilder,
    outputs: &mut Vec<String>,
    edit_counts: &mut Vec<usize>,
) -> Result<(), String> {
    let commit = document.commit(&builder.build()).map_err(debug_error)?;
    outputs.push(
        String::from_utf8(commit.document.render().to_vec())
            .map_err(|_| "edited Reader Properties was not UTF-8")?,
    );
    edit_counts.push(commit.change_set.source_edits().len());
    Ok(())
}

fn relation_present(result: &properties::CompleteProjection, relation: ProvenanceRelation) -> bool {
    result.provenance.entries().iter().any(|entry| {
        entry
            .origins
            .iter()
            .any(|origin| origin.relation == relation)
    })
}

fn object_pairs(value: &PortableValue) -> Result<Vec<(String, String)>, String> {
    value
        .as_object()
        .ok_or("projected Object missing")?
        .iter()
        .map(|entry| {
            Ok((
                entry.key().to_owned(),
                entry
                    .value()
                    .as_string()
                    .ok_or("projected Object value not String")?
                    .to_owned(),
            ))
        })
        .collect()
}

fn expected_pairs(case: &VectorCase<'_>, name: &str) -> Result<Vec<(String, String)>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|pair| {
            let pair = pair
                .as_sequence()
                .ok_or_else(|| format!("expected.{name} item must be Sequence"))?;
            if pair.len() != 2 {
                return Err(format!("expected.{name} pair length must be 2"));
            }
            Ok((
                pair[0]
                    .as_string()
                    .ok_or("expected pair key must be String")?
                    .to_owned(),
                pair[1]
                    .as_string()
                    .ok_or("expected pair value must be String")?
                    .to_owned(),
            ))
        })
        .collect()
}

fn flat_mapping(descriptor: &PortableValue) -> Result<PortableValue, String> {
    let entries = descriptor
        .as_sequence()
        .ok_or("mapping descriptor must be Sequence")?;
    let mut mapping = EntryMappingBuilder::new();
    for entry in entries {
        let pair = entry
            .as_sequence()
            .ok_or("mapping entry must be Sequence")?;
        if pair.len() != 2 {
            return Err("mapping entry must contain key and value".to_owned());
        }
        mapping.push(
            PortableValue::string(pair[0].as_string().ok_or("mapping key must be String")?),
            PortableValue::string(pair[1].as_string().ok_or("mapping value must be String")?),
        );
    }
    Ok(mapping.build())
}

fn materialization_request(profile: PropertiesProfile) -> MaterializationRequest {
    match profile {
        PropertiesProfile::ReaderV1 => MaterializationRequest::new(
            ProfileId::new("java-properties.reader", 1),
            MaterializationStyleId::new("java-properties.reader-canonical", 1),
        ),
        PropertiesProfile::Latin1V1 => MaterializationRequest::new(
            ProfileId::new("java-properties.latin1", 1),
            MaterializationStyleId::new("java-properties.latin1-canonical", 1),
        )
        .with_encoding(SourceEncoding::Latin1),
    }
}

fn set_parse_limit(
    limits: &mut PropertiesParseLimits,
    name: &str,
    value: usize,
) -> Result<(), String> {
    match name {
        "max_source_bytes" => limits.common.max_source_bytes = value,
        "max_nesting_depth" => limits.common.max_nesting_depth = value,
        "max_token_count" => limits.common.max_token_count = value,
        "max_node_count" => limits.common.max_node_count = value,
        "max_diagnostics" => limits.common.max_diagnostics = value,
        "max_decoded_utf8_bytes" => limits.max_decoded_utf8_bytes = value,
        "max_decoded_scalars" => limits.max_decoded_scalars = value,
        "max_natural_lines" => limits.max_natural_lines = value,
        "max_natural_line_bytes" => limits.max_natural_line_bytes = value,
        "max_natural_line_scalars" => limits.max_natural_line_scalars = value,
        "max_logical_lines" => limits.max_logical_lines = value,
        "max_logical_line_natural_lines" => limits.max_logical_line_natural_lines = value,
        "max_logical_line_scalars" => limits.max_logical_line_scalars = value,
        "max_properties" => limits.max_properties = value,
        "max_comments" => limits.max_comments = value,
        "max_escapes" => limits.max_escapes = value,
        "max_unicode_escapes" => limits.max_unicode_escapes = value,
        "max_java_code_units_per_string" => limits.max_java_code_units_per_string = value,
        "max_total_java_code_units" => limits.max_total_java_code_units = value,
        "max_duplicate_group_members" => limits.max_duplicate_group_members = value,
        "max_recovery_regions" => limits.max_recovery_regions = value,
        other => return Err(format!("unknown Properties parse limit {other}")),
    }
    Ok(())
}

fn parse_case(case: &VectorCase<'_>) -> Result<properties::Document, String> {
    let profile = profile(case)?;
    let source = input_string(case, "source")?;
    match profile {
        PropertiesProfile::ReaderV1 => parse_reader_text(source),
        PropertiesProfile::Latin1V1 => {
            properties::parse_latin1(source.as_bytes(), PropertiesParseLimits::default())
                .map_err(debug_error)
        }
    }
}

fn parse_reader_text(source: &str) -> Result<properties::Document, String> {
    properties::parse_reader(
        source.as_bytes(),
        SourceEncoding::Utf8,
        PropertiesParseLimits::default(),
    )
    .map_err(debug_error)
}

fn profile(case: &VectorCase<'_>) -> Result<PropertiesProfile, String> {
    profile_name(input_string(case, "profile")?)
}

fn profile_name(name: &str) -> Result<PropertiesProfile, String> {
    match name {
        "java-properties.reader@1" => Ok(PropertiesProfile::ReaderV1),
        "java-properties.latin1@1" => Ok(PropertiesProfile::Latin1V1),
        other => Err(format!("unknown Java Properties profile {other}")),
    }
}

fn source_encoding(name: &str) -> Result<SourceEncoding, String> {
    match name {
        "Utf8" => Ok(SourceEncoding::Utf8),
        "Utf16Le" => Ok(SourceEncoding::Utf16Le),
        "Utf16Be" => Ok(SourceEncoding::Utf16Be),
        "Latin1" => Ok(SourceEncoding::Latin1),
        value if value.starts_with("WindowsCodePage(") && value.ends_with(')') => {
            let number = value[16..value.len() - 1]
                .parse::<u16>()
                .map_err(|_| "invalid Windows code page")?;
            WindowsCodePage::from_number(number)
                .map(SourceEncoding::WindowsCodePage)
                .ok_or_else(|| format!("unsupported Windows code page {number}"))
        }
        other => Err(format!("unknown source encoding {other}")),
    }
}

fn native_executable(expression: QueryExpression) -> Result<consema_core::ExecutableQuery, String> {
    QueryDefinition::new(QueryDomain::java_properties_native_v1())
        .with_expression(expression)
        .validate()
        .map_err(debug_error)?
        .bind(&capabilities())
        .map_err(debug_error)
}

fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    capabilities
}

fn unicode_keys(document: &properties::Document) -> Result<Vec<String>, String> {
    document
        .properties()
        .iter()
        .map(|property| property.key().to_unicode().map_err(debug_error))
        .collect()
}

fn unicode_values(document: &properties::Document) -> Result<Vec<String>, String> {
    document
        .properties()
        .iter()
        .map(|property| property.value().to_unicode().map_err(debug_error))
        .collect()
}

fn exact_coverage(document: &properties::Document) -> bool {
    let pieces = document.lossless_structural_index().pieces();
    if document.source().is_empty() {
        return pieces.is_empty();
    }
    pieces.len() == document.lossless_syntax_kinds().len()
        && pieces
            .first()
            .is_some_and(|piece| piece.span().start_byte() == 0)
        && pieces
            .last()
            .is_some_and(|piece| piece.span().end_byte() == document.source().len())
        && pieces
            .windows(2)
            .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
}

fn status_name(status: FormationStatus) -> &'static str {
    match status {
        FormationStatus::Complete => "Complete",
        FormationStatus::Recovered => "Recovered",
    }
}

fn value_state_name(state: PropertiesValueState) -> &'static str {
    match state {
        PropertiesValueState::ImplicitEmpty => "ImplicitEmpty",
        PropertiesValueState::ExplicitEmpty => "ExplicitEmpty",
        PropertiesValueState::Present => "Present",
    }
}

fn java_status_name(status: JavaStringStatus) -> &'static str {
    match status {
        JavaStringStatus::WellFormedUnicode => "WellFormedUnicode",
        JavaStringStatus::UnpairedSurrogate => "UnpairedSurrogate",
    }
}

fn escape_kind_name(kind: PropertiesEscapeKind) -> &'static str {
    match kind {
        PropertiesEscapeKind::Named => "Named",
        PropertiesEscapeKind::Backslash => "Backslash",
        PropertiesEscapeKind::Unicode => "Unicode",
        PropertiesEscapeKind::DroppedBackslash => "DroppedBackslash",
    }
}

fn fidelity_name(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Exact => "Exact",
        Fidelity::Transformed => "Transformed",
        Fidelity::Lossy => "Lossy",
    }
}

fn terminal_name(terminal: QueryTerminalState) -> &'static str {
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

fn input_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    input_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("input.{name} must be host-size Integer"))
}

fn expected_usize(case: &VectorCase<'_>, name: &str) -> Result<usize, String> {
    expected_field(case, name)?
        .as_integer()
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("expected.{name} must be host-size Integer"))
}

fn expected_bool(case: &VectorCase<'_>, name: &str) -> Result<bool, String> {
    expected_field(case, name)?
        .as_boolean()
        .ok_or_else(|| format!("expected.{name} must be Boolean"))
}

fn input_strings(case: &VectorCase<'_>, name: &str) -> Result<Vec<String>, String> {
    strings(input_field(case, name)?, &format!("input.{name}"))
}

fn expected_strings(case: &VectorCase<'_>, name: &str) -> Result<Vec<String>, String> {
    strings(expected_field(case, name)?, &format!("expected.{name}"))
}

fn expected_usizes(case: &VectorCase<'_>, name: &str) -> Result<Vec<usize>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_usize)
                .ok_or_else(|| format!("expected.{name} item must be host-size Integer"))
        })
        .collect()
}

fn strings(value: &PortableValue, path: &str) -> Result<Vec<String>, String> {
    value
        .as_sequence()
        .ok_or_else(|| format!("{path} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{path} item must be String"))
        })
        .collect()
}

fn object_string<'a>(
    fields: &'a [consema_core::ObjectEntry],
    name: &str,
) -> Result<&'a str, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("descriptor.{name} must be String"))
}

fn object_usize(fields: &[consema_core::ObjectEntry], name: &str) -> Result<usize, String> {
    object_field(fields, name)
        .and_then(PortableValue::as_integer)
        .and_then(BigInteger::to_usize)
        .ok_or_else(|| format!("descriptor.{name} must be host-size Integer"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    bytes
        .as_ref()
        .iter()
        .fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("String write");
            output
        })
}

fn require(condition: bool, failure: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| failure.into())
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_properties_v1_suite_is_conformant() {
        let report = run_properties_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 22);
    }

    #[test]
    fn vector_inputs_and_expectations_drive_the_runner() {
        let changed =
            PROPERTIES_V1_VECTORS_JSON.replace("\"natural_lines\": 7", "\"natural_lines\": 8");
        let report = run_properties_v1_json(&changed);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "formation.reader-lines-escapes-duplicates"),
            "{report:#?}"
        );

        let changed = PROPERTIES_V1_VECTORS_JSON.replace(
            "\"source\": \"a=1\\nb=2\\n\", \"max_results\": 1",
            "\"source\": \"a=1\\n\", \"max_results\": 1",
        );
        let report = run_properties_v1_json(&changed);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "query.validation-limit-cancellation"),
            "{report:#?}"
        );
    }

    #[test]
    fn suite_identity_unknown_cases_and_duplicate_ids_are_rejected() {
        let wrong_suite =
            PROPERTIES_V1_VECTORS_JSON.replace(SUITE, "consema.java-properties.conformance@2");
        assert!(!run_properties_v1_json(&wrong_suite).is_conformant());

        let unknown = PROPERTIES_V1_VECTORS_JSON.replace(
            "formation.reader-lines-escapes-duplicates",
            "formation.unknown",
        );
        assert!(!run_properties_v1_json(&unknown).is_conformant());

        let duplicate = PROPERTIES_V1_VECTORS_JSON.replace(
            "formation.empty-blank-comment-empty-key",
            "formation.reader-lines-escapes-duplicates",
        );
        assert!(!run_properties_v1_json(&duplicate).is_conformant());
    }
}
