//! Consema SDK chain example (Rust): one JSON document through the full SDK
//! surface — parse, native semantic query, best-exact projection, structural
//! edit, canonical materialization, and cross-format conversion to TOML.
//!
//! Scenario: read `{"a":1,"b":{"c":2}}` under `json.strict`, query `b.c`
//! (`json.native-semantic-query@1`), project
//! `json.projection.best-exact-core@1`, edit `a` to `42` (semantic scalar
//! replacement, `CanonicalForProfile` representation), materialize the edited
//! value as canonical compact JSON, and convert the edited document to TOML
//! (`toml.canonical-document`).
//!
//! Run: `cargo run -p consema --example sdk_chain`
//! (CI check: `cargo check -p consema --example sdk_chain --locked`)
//!
//! Language-neutral contract reference (consema spec repository):
//! - https://github.com/consema/consema/blob/main/docs/cookbook.md — the CLI
//!   recipes for the same operations
//! - https://github.com/consema/consema/blob/main/docs/multi-language-implementation-plan.md
//!   — the five-language SDK design

use consema::core::{
    BigInteger, CancellationToken, CapabilityId, CapabilitySet, OperatorCall, PortableValue,
    QueryDefinition, QueryDomain, QueryExpression, QueryLimits, QuerySelection,
};
use consema::document::{
    FormationStatus, MappingPolicy, MaterializationRequest, MaterializationStyleId, NewlinePolicy,
    ProfileId,
};
use consema::json::{
    EditTransactionBuilder, JsonObjectMember, JsonValue, ProjectionRequestBuilder,
    ProjectionResult, ProjectionTarget, RepresentationPolicy, SemanticAvailability,
    execute_json_query, materialize,
};
use consema::registry::parse_document;
use consema::{ConversionResult, convert_json, document, json};
use std::sync::Arc;

/// Returns the value of one object member by decoded name, walking
/// `object_members()` with an explicit `SemanticAvailability` pattern match.
fn member_value_ref<'a>(value: JsonValue<'a>, name: &str) -> Result<JsonValue<'a>, String> {
    match value.object_members() {
        SemanticAvailability::Available(Some(members)) => members
            .into_iter()
            .find(|member| {
                matches!(member.name(), SemanticAvailability::Available(candidate) if candidate == name)
            })
            .map(JsonObjectMember::value)
            .ok_or_else(|| format!("member '{name}' not found")),
        SemanticAvailability::Available(None) => Err("value is not an object".to_owned()),
        SemanticAvailability::Unavailable(reason) => {
            Err(format!("semantics unavailable: {reason:?}"))
        }
    }
}

/// Projects one JSON document and renders its value as canonical compact JSON.
fn project_to_json(
    json_document: &json::Document,
    projection_request: &json::ProjectionRequest,
    compact_request: &MaterializationRequest,
) -> Result<Vec<u8>, String> {
    let projection = match json_document.project(projection_request) {
        ProjectionResult::Complete(projection) => projection,
        ProjectionResult::Failed(failure) => {
            return Err(format!("projection failed: {failure:?}"));
        }
    };
    match materialize(&projection.value, compact_request) {
        document::MaterializationResult::Complete(complete) => {
            Ok(complete.document.render().to_vec())
        }
        document::MaterializationResult::Failed(failure) => {
            Err(format!("materialization failed: {failure:?}"))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source: Arc<[u8]> = Arc::from(br#"{"a":1,"b":{"c":2}}"#.as_slice());
    let profile = ProfileId::new("json.strict", 1);

    // 1. Parse under the exact profile through the single facade parse entry.
    let document =
        parse_document(source, &profile).map_err(|failure| format!("parse failed: {failure:?}"))?;
    if document.formation_status() != FormationStatus::Complete {
        return Err(format!(
            "expected a Complete document, got {:?}",
            document.formation_status()
        )
        .into());
    }
    println!(
        "parse: profile={} status={:?} render={}",
        document.profile().id(),
        document.formation_status(),
        String::from_utf8_lossy(document.render())
    );
    let json_document = document
        .as_json()
        .map_err(|mismatch| format!("source is not a JSON document: {mismatch:?}"))?;

    // 2. Query `b.c` through the JSON native semantic domain.
    let definition = QueryDefinition::new(QueryDomain::json_native_v1())
        .with_expression(
            QueryExpression::Input
                .then(OperatorCall::new("json.try-object-members", 1))
                .then(
                    OperatorCall::new("json.member-name-equals", 1)
                        .with_argument("name", PortableValue::string("b")),
                )
                .then(OperatorCall::new("json.member-value", 1))
                .then(OperatorCall::new("json.try-object-members", 1))
                .then(
                    OperatorCall::new("json.member-name-equals", 1)
                        .with_argument("name", PortableValue::string("c")),
                )
                .then(OperatorCall::new("json.member-value", 1)),
        )
        .with_selection(QuerySelection::RequireOne);
    let mut capabilities = CapabilitySet::new();
    capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
    let executable = definition
        .validate()
        .map_err(|failure| format!("query validation failed: {failure:?}"))?
        .bind(&capabilities)
        .map_err(|failure| format!("query binding failed: {failure:?}"))?;
    let execution = execute_json_query(
        &executable,
        json_document,
        QueryLimits::default(),
        &CancellationToken::new(),
    )
    .map_err(|failure| format!("query execution failed: {failure:?}"))?;
    // Render the matched value through the semantic tree API (the same walk
    // the edit target below uses).
    let c_value = member_value_ref(member_value_ref(json_document.root(), "b")?, "c")?;
    let (kind, value) = match c_value.kind() {
        SemanticAvailability::Available(kind) => {
            let text = match c_value.as_integer() {
                SemanticAvailability::Available(Some(integer)) => integer.to_string(),
                _ => "?".to_owned(),
            };
            (format!("{kind:?}"), text)
        }
        SemanticAvailability::Unavailable(reason) => {
            return Err(format!("b.c has no semantic value: {reason:?}").into());
        }
    };
    println!(
        "query b.c: matches={} value={} kind={}",
        execution.matches().len(),
        value,
        kind
    );

    // 3. Project the document with the conservative best-exact core target.
    let projection_request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .map_err(|failure| format!("projection request failed: {failure:?}"))?;
    let compact_request = MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new("json.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None);
    let projected_bytes = project_to_json(json_document, &projection_request, &compact_request)?;
    println!(
        "project json.projection.best-exact-core@1: fidelity=Exact value={}",
        String::from_utf8_lossy(&projected_bytes)
    );

    // 4. Edit `a` to 42 with a semantic scalar replacement under the
    //    profile-canonical representation policy.
    let a_value = member_value_ref(json_document.root(), "a")?;
    let mut builder = EditTransactionBuilder::new(json_document);
    builder.semantic_scalar(
        a_value.node_ref(),
        PortableValue::integer(BigInteger::from(42)),
        RepresentationPolicy::CanonicalForProfile,
    );
    let commit = json_document
        .commit(&builder.build())
        .map_err(|failure| format!("edit commit failed: {failure:?}"))?;
    let edited = &commit.document;
    println!(
        "edit a->42 semantic_scalar CanonicalForProfile: render={}",
        String::from_utf8_lossy(edited.render())
    );

    // 5. Materialize the edited value as canonical compact JSON.
    let edited_bytes = project_to_json(edited, &projection_request, &compact_request)?;
    println!(
        "materialize json.canonical-compact: {}",
        String::from_utf8_lossy(&edited_bytes)
    );

    // 6. Convert the edited JSON document to TOML (two-stage composition).
    let toml_request = MaterializationRequest::new(
        ProfileId::new("toml.1.0", 1),
        MaterializationStyleId::new("toml.canonical-document", 1),
    )
    .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject);
    let conversion = match convert_json(edited, &projection_request, &toml_request) {
        ConversionResult::Complete(conversion) => conversion,
        ConversionResult::Failed(failure) => {
            return Err(format!("conversion failed: {failure:?}").into());
        }
    };
    println!("convert to toml.canonical-document:");
    print!("{}", String::from_utf8_lossy(conversion.document.render()));
    Ok(())
}
