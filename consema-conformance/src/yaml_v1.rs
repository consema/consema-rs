//! Language-neutral YAML family conformance runner.

use std::collections::HashSet;

use consema_core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, MatchRole, OperatorCall,
    PortableValue, QueryDefinition, QueryDomain, QueryExpression, QueryLimits,
};
use consema_document::{
    AssociationPlacement, FormationStatus, MaterializationFidelity, MaterializationRequest,
    MaterializationResult, MaterializationStyleId, NewlinePolicy, ParseLimits, ProfileId,
    SourceEncoding,
};
use consema_graph::encode_pgce;
use consema_json::{JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget};
use consema_protocol::query_failure_code;
use consema_yaml::{
    EditTransactionBuilder, Fidelity, GraphMaterializationResult, GraphProjectedLocation,
    GraphProjectionLimits, GraphProjectionRequest, MappingPolicy, ProjectionEventKind,
    ProvenanceRelation, RepresentationPolicy, SharingPolicy, TagPolicy, ValueProjectionRequest,
    ValueProjectionResult, YamlMatch, YamlNodeKind, YamlProfile, YamlScalarKind, YamlSyntaxKind,
    edit_failure_code, execute_yaml_query, execute_yaml_syntax_query,
    graph_projection_failure_code, materialize_graph, materialize_value, parse,
    value_projection_failure_code,
};

use super::{ConformanceReport, VectorCase, object_field};

const SUITE: &str = "consema.yaml.conformance@1";

/// Embedded language-neutral YAML family suite bytes.
pub const YAML_V1_VECTORS_JSON: &str = include_str!("../../../conformance/vectors/yaml-v1.json");

/// Runs the embedded `consema.yaml.conformance@1` suite.
#[must_use]
pub fn run_yaml_v1() -> ConformanceReport {
    run_yaml_v1_json(YAML_V1_VECTORS_JSON)
}

/// Runs one YAML family suite from strict JSON text.
#[must_use]
pub fn run_yaml_v1_json(json: &str) -> ConformanceReport {
    let vectors = consema_json::parse(
        json.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("published YAML vectors must form a document");
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
    let root = value.as_object().expect("YAML vector root object");
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
        let fields = case.as_object().expect("YAML case object");
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
        id if id.starts_with("profile.") => "yaml.scalar-resolution@1",
        id if id.starts_with("source.") || id.starts_with("stream.") => "yaml.document@1",
        id if id.starts_with("syntax.") || id.starts_with("regression.") => {
            "yaml.lossless-syntax@1"
        }
        id if id.starts_with("native.") => "yaml.native-semantics@1",
        id if id.starts_with("formation.") => "yaml.formation@1",
        id if id.starts_with("graph.") => "yaml.projection.best-exact-graph@1",
        id if id.starts_with("query.") => "yaml.query@1",
        "projection.graph-provenance" => "yaml.projection.best-exact-graph@1",
        id if id.starts_with("projection.") => "yaml.projection.best-exact-value@1",
        id if id.starts_with("materialization.") => "yaml.materialization@1",
        id if id.starts_with("edit.") => "yaml.edit@1",
        id if id.starts_with("resource.parse-") => "yaml.formation@1",
        id if id.starts_with("resource.graph-") => "yaml.projection.best-exact-graph@1",
        _ => return Err("runner does not recognize published YAML case".to_owned()),
    };
    if case.capability != required {
        return Err(format!("expected capability {required}"));
    }
    match case.id {
        "profile.yaml12-scalars" | "profile.yaml11-scalars" => scalar_profile(case),
        "source.utf16le-bom" => source_encoding(case),
        "stream.empty" | "stream.multi-document" => stream_facts(case),
        "syntax.styles-and-trivia" => syntax_facts(case),
        "native.arbitrary-duplicate-mapping" => mapping_facts(case),
        "formation.undefined-alias" => formation_rejection(case),
        "graph.shared-cycle" => graph_facts(case),
        "query.mapping-entries" | "query.alias-target" => native_query(case),
        "query.syntax-comments" => syntax_query(case),
        "query.resource-limit" => query_limit(case),
        "projection.sharing-policy" => projection_sharing(case),
        "projection.cycle" => projection_failure(case, "cycle"),
        "projection.tag-policy" => projection_tag(case),
        "projection.mapping-policy" => projection_mapping(case),
        "projection.graph-provenance" => graph_provenance(case),
        "materialization.graph-cycle-flow" => graph_materialization(case),
        "materialization.value-flow" => value_materialization(case),
        "edit.scalar-atomic" => edit_scalar(case),
        "edit.anchor-rename" => edit_anchor(case),
        "edit.structural-insert" => edit_structural(case),
        "edit.anchor-dependency" => edit_anchor_dependency(case),
        "resource.parse-source-bytes" => parse_limit(case),
        "resource.graph-provenance" => graph_provenance_limit(case),
        "regression.plain-property-characters" => plain_property_regression(case),
        _ => Err("runner does not recognize published YAML case".to_owned()),
    }
}

fn scalar_profile(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let root = document.document(0).ok_or("document 0 missing")?.root();
    let count = root.sequence_len().ok_or("root must be Sequence")?;
    let mut kinds = Vec::with_capacity(count);
    let mut canonical = Vec::with_capacity(count);
    for ordinal in 0..count {
        let scalar = root
            .sequence_item(ordinal)
            .and_then(|item| item.node().scalar())
            .ok_or("sequence item must be Scalar")?;
        kinds.push(scalar_kind_name(scalar.kind()).to_owned());
        canonical.push(scalar.canonical().to_owned());
    }
    require(
        kinds == expected_strings(case, "kinds")?
            && canonical == expected_strings(case, "canonical")?,
        format!("scalar facts differed: kinds={kinds:?}, canonical={canonical:?}"),
    )
}

fn source_encoding(case: &VectorCase<'_>) -> Result<(), String> {
    let raw = decode_hex(input_string(case, "source_hex")?)?;
    let document =
        parse(raw.clone(), profile(case)?, ParseLimits::default()).map_err(debug_error)?;
    require(
        document.render() == raw
            && source_encoding_name(document.source().encoding_facts().selected())
                == expected_string(case, "encoding")?
            && document.document_count() == expected_usize(case, "document_count")?,
        "encoding or raw identity differed",
    )
}

fn stream_facts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    require(
        document.formation_status() == FormationStatus::Complete
            && document.document_count() == expected_usize(case, "document_count")?
            && document.alias_count() == expected_usize(case, "alias_count")?
            && document.render() == input_string(case, "source")?.as_bytes(),
        "stream facts differed",
    )
}

fn syntax_facts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let kinds = document
        .lossless_syntax_kinds()
        .iter()
        .map(|kind| kind.as_str().to_owned())
        .collect::<Vec<_>>();
    let required = expected_strings(case, "required_kinds")?;
    require(
        kinds.len() == expected_usize(case, "piece_count")?
            && required.iter().all(|kind| kinds.contains(kind))
            && document
                .lossless_structural_index()
                .pieces()
                .iter()
                .map(|piece| piece.span().len())
                .sum::<usize>()
                == document.render().len(),
        format!(
            "syntax facts differed: piece_count={}, kinds={kinds:?}",
            kinds.len()
        ),
    )
}

fn mapping_facts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let root = document.document(0).ok_or("document 0 missing")?.root();
    let count = root.mapping_len().ok_or("root must be Mapping")?;
    let mut key_kinds = Vec::new();
    let mut values = Vec::new();
    for ordinal in 0..count {
        let entry = root.mapping_entry(ordinal).ok_or("mapping entry missing")?;
        key_kinds.push(node_kind_name(entry.key().kind()).to_owned());
        values.push(
            entry
                .value()
                .scalar()
                .ok_or("value must be Scalar")?
                .canonical()
                .to_owned(),
        );
    }
    require(
        count == expected_usize(case, "entry_count")?
            && key_kinds == expected_strings(case, "key_kinds")?
            && values == expected_strings(case, "values")?,
        format!("mapping facts differed: keys={key_kinds:?}, values={values:?}"),
    )
}

fn formation_rejection(case: &VectorCase<'_>) -> Result<(), String> {
    let error = parse(
        input_string(case, "source")?.as_bytes(),
        profile(case)?,
        ParseLimits::default(),
    )
    .unwrap_err();
    require(
        error.diagnostics().first().map(|item| item.code.as_str())
            == Some(expected_string(case, "code")?),
        format!("formation code differed: {error:?}"),
    )
}

fn graph_facts(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let graph = document.project_graph().map_err(debug_error)?;
    let pgce = encode_pgce(&graph).map_err(debug_error)?;
    require(
        graph.node_count() == expected_usize(case, "node_count")?
            && graph.roots().len() == expected_usize(case, "root_count")?
            && hex(&pgce) == expected_string(case, "pgce_hex")?,
        format!(
            "graph facts differed: nodes={}, pgce={}",
            graph.node_count(),
            hex(&pgce)
        ),
    )
}

fn native_query(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let executable = query_from_pipeline(case, QueryDomain::yaml_native_v1())?;
    let result = execute_yaml_query(
        &executable,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let roles = result
        .matches()
        .iter()
        .map(yaml_match_role)
        .map(role_name)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    require(
        roles == expected_strings(case, "roles")?,
        format!("query roles differed: {roles:?}"),
    )
}

fn syntax_query(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let expression = QueryExpression::Input.then(
        OperatorCall::new("yaml.syntax-kind-is", 1)
            .with_argument("kind", PortableValue::string(input_string(case, "kind")?)),
    );
    let executable = QueryDefinition::new(QueryDomain::yaml_lossless_syntax_v1())
        .with_expression(expression)
        .validate()
        .map_err(debug_error)?
        .bind(&capabilities())
        .map_err(debug_error)?;
    let result = execute_yaml_syntax_query(
        &executable,
        &document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(debug_error)?;
    let ordinals = result
        .matches()
        .iter()
        .map(|item| u64::try_from(item.ordinal()).map_err(debug_error))
        .collect::<Result<Vec<_>, _>>()?;
    require(
        ordinals == expected_u64s(case, "ordinals")?,
        format!("syntax ordinals differed: {ordinals:?}"),
    )
}

fn query_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let executable = query_from_pipeline(case, QueryDomain::yaml_native_v1())?;
    let error = execute_yaml_query(
        &executable,
        &document,
        QueryLimits {
            max_results: input_usize(case, "max_results")?,
            ..QueryLimits::default()
        },
        &CancellationToken::new(),
    )
    .unwrap_err();
    require(
        query_failure_code(&error) == expected_string(case, "code")?,
        format!("query failure differed: {error:?}"),
    )
}

fn projection_sharing(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let default = document.project_value(ValueProjectionRequest::best_exact_v1());
    let ValueProjectionResult::Failed(failure) = default else {
        return Err("default sharing policy unexpectedly completed".to_owned());
    };
    let duplicated = document.project_value(
        ValueProjectionRequest::best_exact_v1().with_sharing(SharingPolicy::DuplicateAcyclic),
    );
    let ValueProjectionResult::Complete(duplicated) = duplicated else {
        return Err("explicit acyclic duplication failed".to_owned());
    };
    require(
        value_projection_failure_code(&failure) == expected_string(case, "default_code")?
            && duplicated.fidelity == Fidelity::Transformed
            && duplicated.report.events().len() == expected_usize(case, "event_count")?
            && duplicated
                .report
                .events()
                .iter()
                .all(|event| event.kind == ProjectionEventKind::SharingDuplicated),
        "sharing policy facts differed",
    )
}

fn projection_failure(case: &VectorCase<'_>, _kind: &str) -> Result<(), String> {
    let document = parse_case(case)?;
    let result = document.project_value(
        ValueProjectionRequest::best_exact_v1().with_sharing(SharingPolicy::DuplicateAcyclic),
    );
    let ValueProjectionResult::Failed(failure) = result else {
        return Err("projection unexpectedly completed".to_owned());
    };
    require(
        value_projection_failure_code(&failure) == expected_string(case, "code")?,
        format!("projection failure differed: {failure:?}"),
    )
}

fn projection_tag(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let ValueProjectionResult::Failed(failure) =
        document.project_value(ValueProjectionRequest::best_exact_v1())
    else {
        return Err("unknown tag unexpectedly projected exactly".to_owned());
    };
    let ValueProjectionResult::Complete(stripped) = document.project_value(
        ValueProjectionRequest::best_exact_v1().with_tags(TagPolicy::StripToNodeKind),
    ) else {
        return Err("explicit tag stripping failed".to_owned());
    };
    require(
        value_projection_failure_code(&failure) == expected_string(case, "default_code")?
            && stripped.fidelity == Fidelity::Lossy
            && stripped.value.as_string() == Some(expected_string(case, "value")?)
            && stripped.report.events().len() == 1,
        "tag policy facts differed",
    )
}

fn projection_mapping(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let ValueProjectionResult::Failed(failure) = document.project_value(
        ValueProjectionRequest::best_exact_v1().with_mapping(MappingPolicy::RequireObject),
    ) else {
        return Err("duplicate mapping unexpectedly became Object".to_owned());
    };
    let ValueProjectionResult::Complete(entries) = document.project_value(
        ValueProjectionRequest::best_exact_v1().with_mapping(MappingPolicy::RequireEntryMapping),
    ) else {
        return Err("explicit EntryMapping projection failed".to_owned());
    };
    let expected_entry_count = expected_usize(case, "entry_count")?;
    require(
        value_projection_failure_code(&failure) == expected_string(case, "object_code")?
            && entries
                .value
                .as_entry_mapping()
                .is_some_and(|items| items.len() == expected_entry_count),
        "mapping policy facts differed",
    )
}

fn graph_provenance(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let result = document
        .project_graph_with_provenance(GraphProjectionRequest::best_exact_v1())
        .map_err(debug_error)?;
    let references = result
        .provenance
        .entries()
        .iter()
        .flat_map(|entry| &entry.origins)
        .filter(|origin| origin.relation == ProvenanceRelation::Reference)
        .count();
    let association_entries = result
        .provenance
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                entry.projected,
                GraphProjectedLocation::SequenceElement { .. }
                    | GraphProjectedLocation::MappingKey { .. }
                    | GraphProjectedLocation::MappingValue { .. }
            )
        })
        .count();
    require(
        references == expected_usize(case, "reference_origins")?
            && association_entries == expected_usize(case, "association_entries")?,
        format!(
            "graph provenance differed: references={references}, associations={association_entries}"
        ),
    )
}

fn graph_materialization(case: &VectorCase<'_>) -> Result<(), String> {
    let source = parse_case(case)?;
    let graph = source.project_graph().map_err(debug_error)?;
    let result = materialize_graph(&graph, &materialization_request("yaml.canonical-flow"));
    let GraphMaterializationResult::Complete(complete) = result else {
        return Err(format!("graph materialization failed: {result:?}"));
    };
    require(
        complete.document.render() == expected_string(case, "source")?.as_bytes()
            && complete.document.project_graph().map_err(debug_error)? == graph
            && complete.fidelity == MaterializationFidelity::Exact,
        format!(
            "graph materialization differed: {}",
            String::from_utf8_lossy(complete.document.render())
        ),
    )
}

fn value_materialization(case: &VectorCase<'_>) -> Result<(), String> {
    let source = parse_case(case)?;
    let ValueProjectionResult::Complete(projected) =
        source.project_value(ValueProjectionRequest::best_exact_v1())
    else {
        return Err("input value projection failed".to_owned());
    };
    let result = materialize_value(
        &projected.value,
        &materialization_request("yaml.canonical-flow"),
    );
    let MaterializationResult::Complete(complete) = result else {
        return Err(format!("value materialization failed: {result:?}"));
    };
    let ValueProjectionResult::Complete(reprojected) = complete
        .document
        .project_value(ValueProjectionRequest::best_exact_v1())
    else {
        return Err("materialized value did not reproject".to_owned());
    };
    require(
        complete.document.render() == expected_string(case, "source")?.as_bytes()
            && reprojected.value == projected.value
            && complete.fidelity == MaterializationFidelity::Exact,
        format!(
            "value materialization differed: {}",
            String::from_utf8_lossy(complete.document.render())
        ),
    )
}

fn edit_scalar(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let entry = input_usize(case, "entry")?;
    let target = document
        .document(0)
        .and_then(|document| document.root().mapping_entry(entry))
        .map(consema_yaml::YamlMappingEntry::value)
        .ok_or("scalar edit target missing")?;
    let mut builder = EditTransactionBuilder::new(&document);
    builder.semantic_scalar(
        target.node_ref(),
        PortableValue::integer(
            BigInteger::parse_decimal(input_string(case, "integer")?).map_err(debug_error)?,
        ),
        RepresentationPolicy::PreserveCompatible,
    );
    let commit = document.commit(&builder.build()).map_err(debug_error)?;
    commit
        .untouched_proof
        .verify(
            document.source(),
            commit.document.source(),
            commit.source_patch.replacements(),
        )
        .map_err(debug_error)?;
    require(
        commit.document.render() == expected_string(case, "source")?.as_bytes()
            && commit.change_set.source_edits().len() == expected_usize(case, "edit_count")?,
        "scalar edit facts differed",
    )
}

fn edit_anchor(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let entry = input_usize(case, "entry")?;
    let target = document
        .document(0)
        .and_then(|document| document.root().mapping_entry(entry))
        .map(consema_yaml::YamlMappingEntry::value)
        .and_then(consema_yaml::YamlNode::anchor_node_ref)
        .ok_or("anchor target missing")?;
    let mut builder = EditTransactionBuilder::new(&document);
    builder.rename_anchor(target, input_string(case, "name")?);
    let commit = document.commit(&builder.build()).map_err(debug_error)?;
    require(
        commit.document.render() == expected_string(case, "source")?.as_bytes()
            && commit.document.alias(0).map(consema_yaml::YamlAlias::name)
                == Some(input_string(case, "name")?),
        "anchor rename facts differed",
    )
}

fn edit_structural(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let root = document.document(0).ok_or("document missing")?.root();
    let sequence = root
        .mapping_entry(0)
        .map(consema_yaml::YamlMappingEntry::value)
        .ok_or("sequence missing")?;
    let mapping = root
        .mapping_entry(1)
        .map(consema_yaml::YamlMappingEntry::value)
        .ok_or("mapping missing")?;
    let mut builder = EditTransactionBuilder::new(&document);
    builder
        .insert_sequence_element(
            sequence.node_ref(),
            PortableValue::boolean(true),
            AssociationPlacement::Before(
                sequence
                    .sequence_item(1)
                    .ok_or("second sequence item missing")?
                    .node_ref(),
            ),
        )
        .insert_mapping_entry(
            mapping.node_ref(),
            PortableValue::string("b"),
            PortableValue::integer(BigInteger::from(2)),
            AssociationPlacement::End,
        );
    let commit = document.commit(&builder.build()).map_err(debug_error)?;
    require(
        commit.document.render() == expected_string(case, "source")?.as_bytes(),
        format!(
            "structural edit differed: {}",
            String::from_utf8_lossy(commit.document.render())
        ),
    )
}

fn edit_anchor_dependency(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let target = document
        .document(0)
        .and_then(|document| document.root().mapping_entry(0))
        .and_then(|entry| entry.value().sequence_item(0))
        .ok_or("anchored sequence item missing")?;
    let mut builder = EditTransactionBuilder::new(&document);
    builder.remove_sequence_element(target.node_ref());
    let error = document.commit(&builder.build()).unwrap_err();
    require(
        edit_failure_code(&error) == expected_string(case, "code")?
            && document.render() == input_string(case, "source")?.as_bytes(),
        format!("anchor dependency differed: {error:?}"),
    )
}

fn parse_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let error = parse(
        input_string(case, "source")?.as_bytes(),
        profile(case)?,
        ParseLimits {
            max_source_bytes: input_usize(case, "max_source_bytes")?,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    require(
        error.diagnostics().first().map(|item| item.code.as_str())
            == Some(expected_string(case, "code")?),
        format!("parse limit differed: {error:?}"),
    )
}

fn graph_provenance_limit(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let error = document
        .project_graph_with_provenance(GraphProjectionRequest::best_exact_v1().with_limits(
            GraphProjectionLimits {
                max_provenance_entries: input_usize(case, "max_provenance_entries")?,
                ..GraphProjectionLimits::default()
            },
        ))
        .unwrap_err();
    require(
        graph_projection_failure_code(&error) == expected_string(case, "code")?,
        format!("graph provenance limit differed: {error:?}"),
    )
}

fn plain_property_regression(case: &VectorCase<'_>) -> Result<(), String> {
    let document = parse_case(case)?;
    let root = document.document(0).ok_or("document missing")?.root();
    let scalar = root.scalar().ok_or("root must be Scalar")?;
    require(
        scalar.canonical() == expected_string(case, "canonical")?
            && document.alias_count() == 0
            && !document
                .lossless_syntax_kinds()
                .contains(&YamlSyntaxKind::Anchor)
            && !document
                .lossless_syntax_kinds()
                .contains(&YamlSyntaxKind::Tag),
        "plain scalar fabricated YAML node properties",
    )
}

fn parse_case(case: &VectorCase<'_>) -> Result<consema_yaml::Document, String> {
    parse(
        input_string(case, "source")?.as_bytes(),
        profile(case)?,
        ParseLimits::default(),
    )
    .map_err(debug_error)
}

fn profile(case: &VectorCase<'_>) -> Result<YamlProfile, String> {
    match input_string(case, "profile")? {
        "yaml.1.2-core@1" => Ok(YamlProfile::Yaml12CoreV1),
        "yaml.1.1-compat@1" => Ok(YamlProfile::Yaml11CompatV1),
        other => Err(format!("unknown YAML profile {other}")),
    }
}

fn query_from_pipeline(
    case: &VectorCase<'_>,
    domain: QueryDomain,
) -> Result<consema_core::ExecutableQuery, String> {
    let pipeline = input_field(case, "pipeline")?
        .as_sequence()
        .ok_or("input.pipeline must be Sequence")?;
    let mut expression = QueryExpression::Input;
    for operator in pipeline {
        let operator = operator.as_string().ok_or("operator must be String")?;
        let (id, version) = operator.rsplit_once('@').ok_or("operator lacks version")?;
        expression = expression.then(OperatorCall::new(
            id,
            version.parse::<u32>().map_err(|_| "invalid version")?,
        ));
    }
    QueryDefinition::new(domain)
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

fn materialization_request(style: &str) -> MaterializationRequest {
    MaterializationRequest::new(
        ProfileId::new("yaml.1.2-core", 1),
        MaterializationStyleId::new(style, 1),
    )
    .with_newline(NewlinePolicy::Lf)
}

fn yaml_match_role(item: &YamlMatch) -> MatchRole {
    match item {
        YamlMatch::Stream { .. } => MatchRole::YamlStream,
        YamlMatch::Document { .. } => MatchRole::YamlDocument,
        YamlMatch::Node { .. } => MatchRole::YamlNode,
        YamlMatch::MappingEntry { .. } => MatchRole::YamlMappingEntry,
        YamlMatch::SequenceElement { .. } => MatchRole::YamlSequenceElement,
        YamlMatch::AnchorDefinition { .. } => MatchRole::YamlAnchorDefinition,
        YamlMatch::AliasOccurrence { .. } => MatchRole::YamlAliasOccurrence,
    }
}

fn role_name(role: MatchRole) -> &'static str {
    match role {
        MatchRole::YamlStream => "YamlStream",
        MatchRole::YamlDocument => "YamlDocument",
        MatchRole::YamlNode => "YamlNode",
        MatchRole::YamlMappingEntry => "YamlMappingEntry",
        MatchRole::YamlSequenceElement => "YamlSequenceElement",
        MatchRole::YamlAnchorDefinition => "YamlAnchorDefinition",
        MatchRole::YamlAliasOccurrence => "YamlAliasOccurrence",
        _ => "Other",
    }
}

fn scalar_kind_name(kind: YamlScalarKind) -> &'static str {
    match kind {
        YamlScalarKind::Null => "Null",
        YamlScalarKind::Boolean => "Boolean",
        YamlScalarKind::Integer => "Integer",
        YamlScalarKind::Float => "Float",
        YamlScalarKind::String => "String",
        YamlScalarKind::Timestamp => "Timestamp",
        YamlScalarKind::Binary => "Binary",
        YamlScalarKind::Custom => "Custom",
        YamlScalarKind::Tagged => "Tagged",
    }
}

fn node_kind_name(kind: YamlNodeKind) -> &'static str {
    match kind {
        YamlNodeKind::Scalar => "Scalar",
        YamlNodeKind::Sequence => "Sequence",
        YamlNodeKind::Mapping => "Mapping",
    }
}

fn source_encoding_name(encoding: SourceEncoding) -> &'static str {
    match encoding {
        SourceEncoding::Utf8 => "Utf8",
        SourceEncoding::Utf16Le => "Utf16Le",
        SourceEncoding::Utf16Be => "Utf16Be",
        SourceEncoding::Latin1 => "Latin1",
        SourceEncoding::Binary => "Binary",
        SourceEncoding::WindowsCodePage(_) => "WindowsCodePage",
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

fn expected_strings(case: &VectorCase<'_>, name: &str) -> Result<Vec<String>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("expected.{name} item must be String"))
        })
        .collect()
}

fn expected_u64s(case: &VectorCase<'_>, name: &str) -> Result<Vec<u64>, String> {
    expected_field(case, name)?
        .as_sequence()
        .ok_or_else(|| format!("expected.{name} must be Sequence"))?
        .iter()
        .map(|value| {
            value
                .as_integer()
                .and_then(BigInteger::to_i64)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| format!("expected.{name} item must be non-negative Integer"))
        })
        .collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hex".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| "invalid hex".to_owned())
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("String write cannot fail");
        output
    })
}

fn require(condition: bool, detail: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_yaml_v1_suite_is_conformant() {
        let report = run_yaml_v1();
        assert!(report.is_conformant(), "{report:#?}");
        assert_eq!(report.passed.len(), 27);
    }

    #[test]
    fn yaml_vectors_drive_inputs_and_expectations() {
        let changed = YAML_V1_VECTORS_JSON.replacen(
            "\"canonical\": [\"yes\", \"17\"",
            "\"canonical\": [\"true\", \"17\"",
            1,
        );
        let report = run_yaml_v1_json(&changed);
        assert!(
            report
                .failed
                .iter()
                .any(|(id, _)| id == "profile.yaml12-scalars"),
            "{report:#?}"
        );

        let changed = YAML_V1_VECTORS_JSON.replacen("k:#foo", "k: #foo", 1);
        assert!(!run_yaml_v1_json(&changed).is_conformant());
    }
}
