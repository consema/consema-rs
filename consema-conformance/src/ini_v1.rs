use consema::ini::{
    self, CollisionPolicy, EditTransactionBuilder, Fidelity, IniEncodingSelection, IniMatch,
    IniParseLimits, IniProfile, IniQuoteStyle, IniValueState, NameComparison, ProjectedLocation,
    ProjectionLimits, ProjectionRequest, ProjectionResult, ProvenanceRelation,
    RepresentationPolicy,
};
use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, EntryMappingBuilder, OperatorCall,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryFailure, QueryLimits,
    QueryTerminalState, StableFailure,
};
use consema_document::{
    AssociationPlacement, EditPlanSourceId, FormationStatus, MappingPolicy,
    MaterializationFidelity, MaterializationLimits, MaterializationRequest, MaterializationResult,
    MaterializationStyleId, NewlinePolicy, OperationSupport, ParseLimits, ProfileId,
    SourceEncoding, SourcePatchLimits, WindowsCodePage,
};
use std::collections::{HashMap, HashSet};

use super::{ConformanceReport, VectorCase, object_field};

const SUITE: &str = "consema.ini.conformance@1";

/// Embedded language-neutral INI family suite bytes.
pub const INI_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/ini-v1.json");

/// Runs the embedded `consema.ini.conformance@1` suite.
#[must_use]
pub fn run_ini_v1() -> ConformanceReport {
    run_ini_v1_json(INI_V1_VECTORS_JSON)
}

/// Runs one INI family suite from strict JSON text.
#[must_use]
pub fn run_ini_v1_json(json: &str) -> ConformanceReport {
    let vectors = consema_json::parse(
        json.as_bytes(),
        consema_json::JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published INI vectors must form a document");
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
    let root = value.as_object().expect("INI vector root object");
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
        let fields = case.as_object().expect("INI case object");
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
        id if id.starts_with("formation.") && id != "formation.recovery-never-fabricates-entry" => {
            "ini.document@1"
        }
        id if id.starts_with("formation.") || id.starts_with("resource.formation-") => {
            "ini.formation@1"
        }
        id if id.starts_with("query.") => "ini.query@1",
        id if id.starts_with("projection.") || id.starts_with("resource.projection-") => {
            "ini.projection@1"
        }
        id if id.starts_with("materialization.") => "ini.materialization@1",
        id if id.starts_with("edit.") || id.starts_with("registry.") => "ini.edit@1",
        _ => return Err("runner does not recognize published INI case".to_owned()),
    };
    if case.capability != required {
        return Err(format!("expected capability {required}"));
    }
    match case.id {
        "formation.portable-lossless" => portable_lossless(case),
        "formation.profile-counterexample-matrix" => profile_counterexamples(case),
        "formation.windows-utf16-case-and-quote" => windows_utf16(case),
        "formation.windows-explicit-code-page" => windows_code_page(case),
        "formation.python-default-continuation-raw" => python_multiline(case),
        "formation.python-unicode16-optionxform" => python_optionxform(case),
        "formation.recovery-never-fabricates-entry" => recovered_is_atomic(case),
        "query.native-order-and-profile-equivalence" => native_query(case),
        "query.syntax-decoded-structure-order" => syntax_query(case),
        "query.validation-limit-cancellation" => query_failures(case),
        "projection.exact-duplicate-entry-mapping" => projection_exact(case),
        "projection.explicit-object-collapse" => projection_collapse(case),
        "projection.fragmented-value-provenance" => projection_fragments(case),
        "materialization.all-canonical-styles" => materialization_styles(case),
        "materialization.atomic-failures-and-limits" => materialization_limits(case),
        "edit.all-eight-operations" => edit_all_operations(case),
        "edit.dry-run-patch-proof-and-atomic-failure" => edit_audit_artifacts(case),
        "resource.formation-limit-matrix" => formation_limits(case),
        "resource.projection-limit-matrix" => projection_limits(case),
        "registry.frozen-eight-operation-surface" => operation_registry(case),
        _ => Err("runner does not recognize published INI case".to_owned()),
    }
}

fn portable_lossless(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && document.physical_lines().len() == expected_usize(case, "physical_lines")?
            && document.logical_lines().len() == expected_usize(case, "logical_lines")?
            && document
                .sections()
                .iter()
                .map(|section| section.name().to_owned())
                .collect::<Vec<_>>()
                == expected_strings(case, "section_names")?
            && document
                .entries()
                .iter()
                .map(|entry| entry.key().to_owned())
                .collect::<Vec<_>>()
                == expected_strings(case, "keys")?
            && document
                .entries()
                .iter()
                .map(|entry| entry.value().to_owned())
                .collect::<Vec<_>>()
                == expected_strings(case, "values")?
            && document
                .entries()
                .iter()
                .map(|entry| value_state_name(entry.value_state()).to_owned())
                .collect::<Vec<_>>()
                == expected_strings(case, "value_states")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "portable document facts differed",
    )
}

fn profile_counterexamples(case: &VectorCase<'_>) -> Result<(), String> {
    let samples = input_field(case, "samples")?
        .as_sequence()
        .ok_or("input.samples must be Sequence")?;
    let profiles = [
        (IniProfile::PortableV1, "portable"),
        (IniProfile::WindowsV1, "windows"),
        (IniProfile::PythonConfigParserV1, "python"),
    ];
    for (profile, expected_name) in profiles {
        let expected = expected_strings(case, expected_name)?;
        if expected.len() != samples.len() {
            return Err(format!("expected.{expected_name} length differed"));
        }
        let actual = samples
            .iter()
            .map(|sample| {
                let fields = sample.as_object().ok_or("sample must be Object")?;
                let source = object_field(fields, "source")
                    .and_then(PortableValue::as_string)
                    .ok_or("sample.source must be String")?;
                Ok(
                    match ini::parse(
                        source.as_bytes(),
                        profile,
                        IniEncodingSelection::ProfileDefault,
                        IniParseLimits::default(),
                    ) {
                        Ok(document) => status_name(document.formation_status()).to_owned(),
                        Err(_) => "Fatal".to_owned(),
                    },
                )
            })
            .collect::<Result<Vec<_>, String>>()?;
        require(
            actual == expected,
            format!("{expected_name} counterexample matrix differed: {actual:?}"),
        )?;
    }
    Ok(())
}

fn windows_utf16(case: &VectorCase<'_>) -> Result<(), String> {
    let bytes = decode_hex(input_string(case, "source_hex")?)?;
    let document = ini::parse(
        bytes,
        profile(case)?,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    )
    .map_err(debug_error)?;
    let sections = document
        .sections()
        .iter()
        .map(|section| section.name().to_owned())
        .collect::<Vec<_>>();
    let keys = document
        .entries()
        .iter()
        .map(|entry| entry.key().to_owned())
        .collect::<Vec<_>>();
    let values = document
        .entries()
        .iter()
        .map(|entry| entry.value().to_owned())
        .collect::<Vec<_>>();
    require(
        source_encoding_name(document.source().encoding_facts().selected())
            == expected_string(case, "encoding")?
            && sections == expected_strings(case, "section_names")?
            && document.sections()[0].comparison_name()
                == expected_string(case, "comparison_section")?
            && keys == expected_strings(case, "keys")?
            && document.entries()[0].comparison_key() == expected_string(case, "comparison_key")?
            && values == expected_strings(case, "values")?
            && quote_style_name(document.entries()[0].quote_style())
                == expected_string(case, "quote_style")?
            && document.sections()[0].duplicate_group() == document.sections()[1].duplicate_group()
            && document.entries()[0].duplicate_group() == document.entries()[1].duplicate_group()
            && document.diagnostics().iter().any(|item| {
                item.code == expected_string(case, "case_collision_code").unwrap_or("")
            })
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "Windows UTF-16 facts differed",
    )
}

fn windows_code_page(case: &VectorCase<'_>) -> Result<(), String> {
    let bytes = decode_hex(input_string(case, "source_hex")?)?;
    let number = input_usize(case, "code_page")?;
    let code_page =
        WindowsCodePage::from_number(u16::try_from(number).map_err(|_| "code page out of range")?)
            .ok_or("unsupported vector code page")?;
    let document = ini::parse(
        bytes,
        profile(case)?,
        IniEncodingSelection::Explicit(SourceEncoding::WindowsCodePage(code_page)),
        IniParseLimits::default(),
    )
    .map_err(debug_error)?;
    require(
        document.entries()[0].value() == expected_string(case, "value")?
            && source_encoding_name(document.source().encoding_facts().selected())
                == expected_string(case, "encoding")?
            && format!("{:?}", document.source().encoding_facts().bom_policy())
                == expected_string(case, "bom_policy")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "Windows code-page facts differed",
    )
}

fn python_multiline(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let comparison_keys = document
        .entries()
        .iter()
        .map(|entry| entry.comparison_key().to_owned())
        .collect::<Vec<_>>();
    let values = document
        .entries()
        .iter()
        .map(|entry| entry.value().to_owned())
        .collect::<Vec<_>>();
    let continued = document
        .logical_line(document.entries()[1].logical_line())
        .map_err(debug_error)?;
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && document.sections()[0].is_default() == expected_bool(case, "default_section")?
            && comparison_keys == expected_strings(case, "comparison_keys")?
            && values == expected_strings(case, "values")?
            && continued.physical_lines().len()
                == expected_usize(case, "continuation_physical_lines")?
            && exact_coverage(&document) == expected_bool(case, "exact_coverage")?,
        "Python raw/default/continuation facts differed",
    )
}

fn python_optionxform(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let comparisons = document
        .entries()
        .iter()
        .map(|entry| entry.comparison_key().to_owned())
        .collect::<Vec<_>>();
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && comparisons == expected_strings(case, "comparison_keys")?
            && document.entries()[0].duplicate_group().is_some()
                == expected_bool(case, "duplicate_group")?
            && document.entries()[0].duplicate_group() == document.entries()[1].duplicate_group()
            && document
                .diagnostics()
                .iter()
                .any(|item| item.code == expected_string(case, "code").unwrap_or("")),
        "Unicode 16 optionxform facts differed",
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
    let transaction = EditTransactionBuilder::new(&document).build();
    let edit_code = document
        .commit(&transaction)
        .err()
        .map(|failure| failure.diagnostic_code().to_owned());
    require(
        status_name(document.formation_status()) == expected_string(case, "formation")?
            && document.entries().len() == expected_usize(case, "entries")?
            && document.error_lines().len() == expected_usize(case, "error_lines")?
            && document.error_lines()[0].code() == expected_string(case, "code")?
            && projection_code.as_deref() == Some(expected_string(case, "projection_code")?)
            && edit_code.as_deref() == Some(expected_string(case, "edit_code")?),
        "recovered document exposed partial semantics",
    )
}

fn native_query(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let expression = QueryExpression::Input
        .then(OperatorCall::new("ini.document-sections", 1))
        .then(
            OperatorCall::new("ini.section-name-equals", 1)
                .with_argument(
                    "name",
                    PortableValue::string(input_string(case, "section_name")?),
                )
                .with_argument(
                    "comparison",
                    PortableValue::string(input_string(case, "comparison")?),
                ),
        )
        .then(OperatorCall::new("ini.section-entries", 1));
    let result = ini::execute_ini_query(
        &native_executable(expression)?,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let keys = result
        .matches()
        .iter()
        .map(|item| match item {
            IniMatch::Entry { key, .. } => Ok(key.clone()),
            _ => Err("native query returned non-entry".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let roles = result
        .matches()
        .iter()
        .map(|item| match item {
            IniMatch::Entry { .. } => "IniEntry".to_owned(),
            _ => "Other".to_owned(),
        })
        .collect::<Vec<_>>();
    let duplicate = result.matches().iter().all(|item| {
        matches!(
            item,
            IniMatch::Entry {
                duplicate_group: Some(_),
                ..
            }
        )
    });
    require(
        keys == expected_strings(case, "keys")?
            && roles == expected_strings(case, "roles")?
            && duplicate == expected_bool(case, "duplicate_group")?
            && terminal_name(result.terminal_state()) == expected_string(case, "terminal")?,
        "native query order or profile comparison differed",
    )
}

fn syntax_query(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let text = QueryExpression::Input.then(
        OperatorCall::new("ini.syntax-text-equals", 1)
            .with_argument("text", PortableValue::string(input_string(case, "text")?)),
    );
    let kind = QueryExpression::Input.then(
        OperatorCall::new("ini.syntax-kind-is", 1)
            .with_argument("kind", PortableValue::string(input_string(case, "kind")?)),
    );
    let executable = QueryDefinition::new(QueryDomain::ini_lossless_syntax_v1())
        .with_expression(QueryExpression::StructureOrderMerge(vec![text, kind]))
        .validate()
        .map_err(debug_error)?
        .bind(&capabilities())
        .map_err(debug_error)?;
    let result = ini::execute_ini_syntax_query(
        &executable,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let kinds = result
        .matches()
        .iter()
        .map(|item| item.kind().as_str().to_owned())
        .collect::<Vec<_>>();
    let increasing = result
        .matches()
        .windows(2)
        .all(|pair| pair[0].ordinal() < pair[1].ordinal());
    require(
        kinds == expected_strings(case, "kinds")?
            && increasing == expected_bool(case, "strictly_increasing_ordinals")?
            && result.matches().iter().all(|item| {
                format!("{:?}", item.node_ref().role())
                    == expected_string(case, "role").unwrap_or("")
            }),
        "syntax query decoded ordering differed",
    )
}

fn query_failures(case: &VectorCase<'_>) -> Result<(), String> {
    let invalid = QueryDefinition::new(QueryDomain::ini_native_v1())
        .with_expression(
            QueryExpression::Input.then(
                OperatorCall::new("ini.section-name-equals", 1)
                    .with_argument("name", PortableValue::string("S"))
                    .with_argument("comparison", PortableValue::string("OriginalExact")),
            ),
        )
        .validate();
    let document = parse_case(case)?;
    let all =
        native_executable(QueryExpression::Input.then(OperatorCall::new("ini.all-entries", 1)))?;
    let limit = ini::execute_ini_query(
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
    let mut cursor =
        ini::execute_ini_query_cursor(&all, &document, QueryLimits::default(), &cancellation)
            .map_err(debug_error)?;
    let first = cursor.next().is_some();
    cancellation.cancel();
    let exhausted = cursor.next().is_none();
    require(
        matches!(
            invalid,
            Err(QueryFailure::InvalidOperatorComposition { .. })
        ) == expected_bool(case, "invalid_composition")?
            && limit.diagnostic_code() == expected_string(case, "limit_code")?
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
        return Err("exact projection failed".to_owned());
    };
    let sections = result
        .value
        .as_entry_mapping()
        .ok_or("outer EntryMapping missing")?;
    let section_keys = sections
        .iter()
        .map(|entry| {
            entry
                .key()
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or("section key")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first_entries = sections[0]
        .value()
        .as_entry_mapping()
        .ok_or("inner EntryMapping missing")?;
    let first_keys = first_entries
        .iter()
        .map(|entry| {
            entry
                .key()
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or("entry key")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let association = result
        .provenance
        .entries()
        .iter()
        .any(|item| matches!(item.projected, ProjectedLocation::Association(_)));
    require(
        fidelity_name(result.fidelity) == expected_string(case, "fidelity")?
            && section_keys == expected_strings(case, "section_keys")?
            && first_keys == expected_strings(case, "first_entry_keys")?
            && result.report.events().len() == expected_usize(case, "events")?
            && association == expected_bool(case, "association_provenance")?,
        "exact projection facts differed",
    )
}

fn projection_collapse(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let comparison = comparison(input_string(case, "comparison")?)?;
    let rejected = matches!(
        document.project(ProjectionRequest::require_object(
            comparison,
            CollisionPolicy::Reject,
        )),
        ProjectionResult::Failed(_)
    );
    let ProjectionResult::Complete(first) = document.project(ProjectionRequest::require_object(
        comparison,
        CollisionPolicy::First,
    )) else {
        return Err("explicit first collapse failed".to_owned());
    };
    let ProjectionResult::Complete(last) = document.project(ProjectionRequest::require_object(
        comparison,
        CollisionPolicy::Last,
    )) else {
        return Err("explicit last collapse failed".to_owned());
    };
    let (first_section, first_key, first_value) = object_triplet(&first.value)?;
    let (last_section, last_key, last_value) = object_triplet(&last.value)?;
    let collapsed = first.provenance.entries().iter().any(|entry| {
        entry
            .origins
            .iter()
            .any(|origin| origin.relation == ProvenanceRelation::Collapsed)
    });
    require(
        rejected == expected_bool(case, "rejects")?
            && fidelity_name(first.fidelity) == expected_string(case, "first_fidelity")?
            && first.report.events().len() == expected_usize(case, "first_events")?
            && first_section == expected_string(case, "first_section")?
            && first_key == expected_string(case, "first_key")?
            && first_value == expected_string(case, "first_value")?
            && last_section == expected_string(case, "last_section")?
            && last_key == expected_string(case, "last_key")?
            && last_value == expected_string(case, "last_value")?
            && collapsed == expected_bool(case, "collapsed_provenance")?,
        "explicit Object collapse facts differed",
    )
}

fn projection_fragments(case: &VectorCase<'_>) -> Result<(), String> {
    let python = parse_text(
        IniProfile::PythonConfigParserV1,
        input_string(case, "python_source")?,
    )?;
    let windows = parse_text(IniProfile::WindowsV1, input_string(case, "windows_source")?)?;
    let ProjectionResult::Complete(python) =
        python.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("Python projection failed".to_owned());
    };
    let ProjectionResult::Complete(windows) =
        windows.project(ProjectionRequest::best_exact_entry_mapping())
    else {
        return Err("Windows projection failed".to_owned());
    };
    let continuation = relation_present(&python, ProvenanceRelation::ContinuationFragment);
    let quote = relation_present(&windows, ProvenanceRelation::QuoteDerived);
    require(
        continuation
            && quote
            && expected_string(case, "continuation_relation")? == "ContinuationFragment"
            && expected_string(case, "quote_relation")? == "QuoteDerived",
        "fragmented provenance was incomplete",
    )
}

fn materialization_styles(case: &VectorCase<'_>) -> Result<(), String> {
    let profiles = [
        (
            "portable",
            IniProfile::PortableV1,
            expected_string(case, "portable_source")?,
            SourceEncoding::Utf8,
        ),
        (
            "windows",
            IniProfile::WindowsV1,
            expected_string(case, "windows_decoded")?,
            SourceEncoding::Utf16Le,
        ),
        (
            "python",
            IniProfile::PythonConfigParserV1,
            expected_string(case, "python_decoded")?,
            SourceEncoding::Utf8,
        ),
    ];
    for (field, profile, expected_source, encoding) in profiles {
        let value = nested_mapping(input_field(case, field)?)?;
        let request = materialization_request(profile);
        let MaterializationResult::Complete(result) = ini::materialize(&value, &request) else {
            return Err(format!("{field} materialization failed"));
        };
        let decoded = result
            .document
            .source()
            .decoded_text()
            .ok_or("materialized source lacks decoded text")?;
        let closure = matches!(
            result
                .document
                .project(ProjectionRequest::best_exact_entry_mapping()),
            ProjectionResult::Complete(ref projected) if projected.value == value
        );
        require(
            decoded == expected_source
                && result.document.source().encoding_facts().selected() == encoding
                && (result.fidelity == MaterializationFidelity::Exact)
                    == expected_bool(case, "exact_fidelity")?
                && closure == expected_bool(case, "closure")?,
            format!(
                "{field} canonical materialization differed: decoded={decoded:?}, expected={expected_source:?}, encoding={:?}, fidelity={:?}, closure={closure}",
                result.document.source().encoding_facts().selected(),
                result.fidelity,
            ),
        )?;
    }
    require(
        expected_string(case, "windows_encoding")? == "Utf16Le",
        "Windows encoding expectation is not canonical",
    )
}

fn materialization_limits(case: &VectorCase<'_>) -> Result<(), String> {
    let scalar = PortableValue::string("x");
    let scalar_code =
        match ini::materialize(&scalar, &materialization_request(IniProfile::PortableV1)) {
            MaterializationResult::Failed(failed) => failed.failure.diagnostic_code().to_owned(),
            MaterializationResult::Complete(_) => return Err("scalar materialized".to_owned()),
        };
    let value = nested_mapping(input_field(case, "value")?)?;
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
        match ini::materialize(
            &value,
            &materialization_request(IniProfile::PortableV1).with_limits(limits),
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
        scalar_code == expected_string(case, "scalar_code")? && outcomes == expected,
        format!("materialization atomic limit outcomes differed: {outcomes:?}"),
    )
}

fn edit_all_operations(case: &VectorCase<'_>) -> Result<(), String> {
    let source = input_string(case, "source")?;
    let profile = profile(case)?;
    let expected = expected_strings(case, "outputs")?;
    let mut outputs = Vec::new();
    let mut edit_counts = Vec::new();

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.semantic_value(
        document.entries()[0].node_ref(),
        input_string(case, "semantic_value")?,
        RepresentationPolicy::CanonicalForProfile,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.literal_value(
        document.entries()[0].node_ref(),
        input_string(case, "literal_value")?.as_bytes(),
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.insert_section(
        document.node_ref(),
        input_string(case, "new_section")?,
        AssociationPlacement::End,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.remove_section(document.sections()[0].node_ref());
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.rename_section(
        document.sections()[0].node_ref(),
        input_string(case, "renamed_section")?,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.insert_entry(
        document.sections()[0].node_ref(),
        input_string(case, "new_key")?,
        input_string(case, "new_value")?,
        AssociationPlacement::End,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.remove_entry(document.entries()[0].node_ref());
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    let document = parse_text(profile, source)?;
    let mut edit = EditTransactionBuilder::new(&document);
    edit.rename_entry(
        document.entries()[0].node_ref(),
        input_string(case, "renamed_key")?,
    );
    collect_edit(&document, edit, &mut outputs, &mut edit_counts)?;

    require(
        outputs == expected
            && edit_counts.iter().all(|count| *count == 1)
                == expected_bool(case, "one_source_edit_each")?,
        format!("eight edit outputs differed: {outputs:?}; edits={edit_counts:?}"),
    )
}

fn edit_audit_artifacts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_value(
        document.entries()[0].node_ref(),
        input_string(case, "value")?,
        RepresentationPolicy::CanonicalForProfile,
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

    let other = parse_text(profile(case)?, input_string(case, "wrong_source")?)?;
    let mut wrong = EditTransactionBuilder::new(&document);
    wrong.literal_value(other.entries()[0].node_ref(), b"new".as_slice());
    let wrong_code = document
        .commit(&wrong.build())
        .expect_err("wrong snapshot must fail")
        .diagnostic_code()
        .to_owned();
    require(
        commit.document.render() == expected_string(case, "source")?.as_bytes()
            && (plan.source_patch() == &commit.source_patch)
                == expected_bool(case, "dry_run_equals_commit")?
            && (replay.bytes() == commit.document.render())
                == expected_bool(case, "patch_replays")?
            && proof.is_ok() == expected_bool(case, "proof_verifies")?
            && wrong_code == expected_string(case, "wrong_snapshot_code")?
            && (document.render() == input_string(case, "source")?.as_bytes())
                == expected_bool(case, "base_unchanged")?,
        "edit plan, patch, proof, or atomic failure differed",
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
        let profile = profile_name(object_string(fields, "profile")?)?;
        let source = object_string(fields, "source")?;
        let value = object_usize(fields, "value")?;
        let mut limits = IniParseLimits::default();
        set_parse_limit(&mut limits, name, value)?;
        let failed = ini::parse(
            source.as_bytes(),
            profile,
            IniEncodingSelection::ProfileDefault,
            limits,
        )
        .is_err();
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
            "max_source_associations" => limits.max_source_associations = 1,
            "max_value_nodes" => limits.max_value_nodes = 1,
            "max_provenance_units" => limits.max_provenance_units = 1,
            other => return Err(format!("unknown projection limit {other}")),
        }
        let ProjectionResult::Failed(failed) =
            document.project(ProjectionRequest::best_exact_entry_mapping().with_limits(limits))
        else {
            return Err(format!("projection limit {name} did not fail"));
        };
        if failed
            .diagnostics
            .first()
            .is_some_and(|item| item.code == expected_string(case, "code").unwrap_or(""))
        {
            failed_count += 1;
        }
    }
    require(
        failed_count == expected_usize(case, "failed_count")?,
        format!("projection failed count was {failed_count}"),
    )
}

fn operation_registry(case: &VectorCase<'_>) -> Result<(), String> {
    let expected = expected_strings(case, "operations")?;
    for profile_name_value in input_strings(case, "profiles")? {
        let registry = ini::format_operation_registry(profile_name(&profile_name_value)?);
        let operations = registry
            .operations()
            .iter()
            .map(|descriptor| descriptor.id().to_string())
            .collect::<Vec<_>>();
        let direct = registry
            .operations()
            .iter()
            .filter(|descriptor| descriptor.support() == OperationSupport::Supported)
            .count();
        require(
            operations == expected && direct == expected_usize(case, "direct_structural")?,
            format!("operation registry differed for {profile_name_value}"),
        )?;
    }
    Ok(())
}

fn collect_edit(
    document: &ini::Document,
    builder: EditTransactionBuilder,
    outputs: &mut Vec<String>,
    edit_counts: &mut Vec<usize>,
) -> Result<(), String> {
    let commit = document.commit(&builder.build()).map_err(debug_error)?;
    outputs.push(
        String::from_utf8(commit.document.render().to_vec())
            .map_err(|_| "edited Portable INI was not UTF-8")?,
    );
    edit_counts.push(commit.change_set.source_edits().len());
    Ok(())
}

fn relation_present(result: &ini::CompleteProjection, relation: ProvenanceRelation) -> bool {
    result.provenance.entries().iter().any(|entry| {
        entry
            .origins
            .iter()
            .any(|origin| origin.relation == relation)
    })
}

fn object_triplet(value: &PortableValue) -> Result<(&str, &str, &str), String> {
    let sections = value.as_object().ok_or("projected outer Object missing")?;
    let section = sections.first().ok_or("projected section missing")?;
    let entries = section
        .value()
        .as_object()
        .ok_or("projected inner Object missing")?;
    let entry = entries.first().ok_or("projected entry missing")?;
    Ok((
        section.key(),
        entry.key(),
        entry
            .value()
            .as_string()
            .ok_or("projected value not String")?,
    ))
}

fn nested_mapping(descriptor: &PortableValue) -> Result<PortableValue, String> {
    let sections = descriptor
        .as_sequence()
        .ok_or("mapping descriptor must be Sequence")?;
    let mut outer = EntryMappingBuilder::new();
    for section in sections {
        let fields = section
            .as_object()
            .ok_or("section descriptor must be Object")?;
        let name = object_string(fields, "section")?;
        let entries = object_field(fields, "entries")
            .and_then(PortableValue::as_sequence)
            .ok_or("section.entries must be Sequence")?;
        let mut inner = EntryMappingBuilder::new();
        for entry in entries {
            let pair = entry
                .as_sequence()
                .ok_or("entry descriptor must be Sequence")?;
            if pair.len() != 2 {
                return Err("entry descriptor must contain key and value".to_owned());
            }
            let key = pair[0].as_string().ok_or("entry key must be String")?;
            let value = pair[1].as_string().ok_or("entry value must be String")?;
            inner.push(PortableValue::string(key), PortableValue::string(value));
        }
        outer.push(PortableValue::string(name), inner.build());
    }
    Ok(outer.build())
}

fn materialization_request(profile: IniProfile) -> MaterializationRequest {
    match profile {
        IniProfile::PortableV1 => MaterializationRequest::new(
            ProfileId::new("ini.portable", 1),
            MaterializationStyleId::new("ini.portable-canonical", 1),
        )
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject),
        IniProfile::WindowsV1 => MaterializationRequest::new(
            ProfileId::new("ini.windows", 1),
            MaterializationStyleId::new("ini.windows-canonical", 1),
        )
        .with_encoding(SourceEncoding::Utf16Le)
        .with_newline(NewlinePolicy::CrLf)
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject),
        IniProfile::PythonConfigParserV1 => MaterializationRequest::new(
            ProfileId::new("ini.python-configparser", 1),
            MaterializationStyleId::new("ini.python-configparser-canonical", 1),
        )
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject),
    }
}

fn set_parse_limit(limits: &mut IniParseLimits, name: &str, value: usize) -> Result<(), String> {
    match name {
        "max_source_bytes" => limits.common.max_source_bytes = value,
        "max_nesting_depth" => limits.common.max_nesting_depth = value,
        "max_token_count" => limits.common.max_token_count = value,
        "max_node_count" => limits.common.max_node_count = value,
        "max_diagnostics" => limits.common.max_diagnostics = value,
        "max_decoded_utf8_bytes" => limits.max_decoded_utf8_bytes = value,
        "max_decoded_scalars" => limits.max_decoded_scalars = value,
        "max_physical_lines" => limits.max_physical_lines = value,
        "max_physical_line_bytes" => limits.max_physical_line_bytes = value,
        "max_physical_line_scalars" => limits.max_physical_line_scalars = value,
        "max_logical_lines" => limits.max_logical_lines = value,
        "max_logical_line_bytes" => limits.max_logical_line_bytes = value,
        "max_logical_line_scalars" => limits.max_logical_line_scalars = value,
        "max_continuation_lines" => limits.max_continuation_lines = value,
        "max_sections" => limits.max_sections = value,
        "max_entries" => limits.max_entries = value,
        "max_duplicate_group_members" => limits.max_duplicate_group_members = value,
        "max_recovery_regions" => limits.max_recovery_regions = value,
        other => return Err(format!("unknown INI parse limit {other}")),
    }
    Ok(())
}

fn parse_case(case: &VectorCase<'_>) -> Result<ini::Document, String> {
    parse_text(profile(case)?, input_string(case, "source")?)
}

fn parse_text(profile: IniProfile, source: &str) -> Result<ini::Document, String> {
    ini::parse(
        source.as_bytes(),
        profile,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    )
    .map_err(debug_error)
}

fn profile(case: &VectorCase<'_>) -> Result<IniProfile, String> {
    profile_name(input_string(case, "profile")?)
}

fn profile_name(name: &str) -> Result<IniProfile, String> {
    match name {
        "ini.portable@1" => Ok(IniProfile::PortableV1),
        "ini.windows@1" => Ok(IniProfile::WindowsV1),
        "ini.python-configparser@1" => Ok(IniProfile::PythonConfigParserV1),
        other => Err(format!("unknown INI profile {other}")),
    }
}

fn comparison(name: &str) -> Result<NameComparison, String> {
    match name {
        "OriginalExact" => Ok(NameComparison::OriginalExact),
        "ProfileEquivalent" => Ok(NameComparison::ProfileEquivalent),
        other => Err(format!("unknown comparison {other}")),
    }
}

fn native_executable(expression: QueryExpression) -> Result<consema_core::ExecutableQuery, String> {
    QueryDefinition::new(QueryDomain::ini_native_v1())
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

fn exact_coverage(document: &ini::Document) -> bool {
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

fn value_state_name(state: IniValueState) -> &'static str {
    match state {
        IniValueState::Missing => "Missing",
        IniValueState::Empty => "Empty",
        IniValueState::Present => "Present",
    }
}

fn quote_style_name(style: IniQuoteStyle) -> &'static str {
    match style {
        IniQuoteStyle::None => "None",
        IniQuoteStyle::Single => "Single",
        IniQuoteStyle::Double => "Double",
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

fn source_encoding_name(encoding: SourceEncoding) -> String {
    match encoding {
        SourceEncoding::Binary => "Binary".to_owned(),
        SourceEncoding::Utf8 => "Utf8".to_owned(),
        SourceEncoding::Utf16Le => "Utf16Le".to_owned(),
        SourceEncoding::Utf16Be => "Utf16Be".to_owned(),
        SourceEncoding::Latin1 => "Latin1".to_owned(),
        SourceEncoding::WindowsCodePage(code_page) => {
            format!("WindowsCodePage({})", code_page.number())
        }
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
    fn published_ini_v1_suite_is_conformant() {
        let report = run_ini_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 20);
    }

    #[test]
    fn vector_inputs_and_expectations_drive_the_runner() {
        let changed = INI_V1_VECTORS_JSON.replace("\"physical_lines\": 4", "\"physical_lines\": 5");
        let report = run_ini_v1_json(&changed);
        assert!(!report.is_conformant());
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "formation.portable-lossless"),
            "{report:#?}"
        );

        let changed = INI_V1_VECTORS_JSON.replace(
            "\"source\": \"[s]\\na=1\\nb=2\\n\", \"max_results\": 1",
            "\"source\": \"[s]\\na=1\\n\", \"max_results\": 1",
        );
        let report = run_ini_v1_json(&changed);
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
        let wrong_suite = INI_V1_VECTORS_JSON.replace(SUITE, "consema.ini.conformance@2");
        assert!(!run_ini_v1_json(&wrong_suite).is_conformant());

        let unknown =
            INI_V1_VECTORS_JSON.replace("formation.portable-lossless", "formation.unknown");
        assert!(!run_ini_v1_json(&unknown).is_conformant());

        let duplicate = INI_V1_VECTORS_JSON.replace(
            "formation.profile-counterexample-matrix",
            "formation.portable-lossless",
        );
        assert!(!run_ini_v1_json(&duplicate).is_conformant());
    }
}
