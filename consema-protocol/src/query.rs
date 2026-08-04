//! Query definition and complete-result protocols.

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32, unsigned_u64,
};
use crate::{
    Completion, CompletionStatus, ContractId, ContractRegistry, DiagnosticMessage, ProtocolError,
    ProtocolErrorKind, ProtocolMessage,
};
use consema_core::{
    AssociationLocation, AssociationRole, MatchRole, PortableMatch, PortableValue, QueryDefinition,
    QueryDomain, QueryExecution, SequenceBuilder, ValuePath, ValuePathSegment,
};
use consema_document::NodeRef;

/// Wraps the frozen `core.query-definition@1` payload in the common envelope.
pub fn query_definition_message(
    definition: &QueryDefinition,
) -> Result<ProtocolMessage, ProtocolError> {
    let payload = definition.to_protocol_value().map_err(|error| {
        ProtocolError::new(
            ProtocolErrorKind::InvalidValue,
            "$.payload",
            format!("{error:?}"),
        )
    })?;
    ProtocolMessage::new(
        ContractId::new("core.query-definition", 1)?,
        payload,
        ContractRegistry::v1(),
    )
}

/// Strictly unwraps and decodes `core.query-definition@1`.
pub fn query_definition_from_message(
    message: &ProtocolMessage,
) -> Result<QueryDefinition, ProtocolError> {
    if message.contract().id() != "core.query-definition" || message.contract().version() != 1 {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.contract",
            "expected core.query-definition@1",
        ));
    }
    QueryDefinition::from_protocol_value(message.payload()).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorKind::InvalidValue,
            "$.payload",
            format!("{error:?}"),
        )
    })
}

/// Caller-externalized locator for a native semantic query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMatchLocator {
    source_id: String,
    node_locator: String,
    role: MatchRole,
    ordinal: u64,
}

impl NativeMatchLocator {
    /// Creates a transferable locator for one native match.
    pub fn new(
        source_id: impl Into<String>,
        node_locator: impl Into<String>,
        role: MatchRole,
        ordinal: u64,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        let node_locator = node_locator.into();
        if source_id.is_empty()
            || source_id.len() > 1024
            || node_locator.is_empty()
            || node_locator.len() > 4096
            || !is_native_role(role)
        {
            return Err(crate::schema::invalid(
                "$.native_match",
                "invalid source, locator, or native role",
            ));
        }
        Ok(Self {
            source_id,
            node_locator,
            role,
            ordinal,
        })
    }

    /// Explicit rejection adapter for raw process-local handles.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.native_match.node",
            "NodeRef must be externalized to a stable caller locator",
        ))
    }

    /// Stable source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Stable caller locator.
    #[must_use]
    pub fn node_locator(&self) -> &str {
        &self.node_locator
    }

    /// Native match role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Standard-order ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

/// One transferable query match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolQueryMatch {
    /// Complete portable-domain match.
    Portable(PortableMatch),
    /// Native match externalized by the caller.
    Native(NativeMatchLocator),
}

impl ProtocolQueryMatch {
    fn role(&self) -> MatchRole {
        match self {
            Self::Portable(PortableMatch::Value { .. }) => MatchRole::Value,
            Self::Portable(PortableMatch::ObjectEntry { .. }) => MatchRole::ObjectEntry,
            Self::Portable(PortableMatch::EntryMappingEntry { .. }) => MatchRole::EntryMappingEntry,
            Self::Native(locator) => locator.role,
        }
    }
}

/// Complete or explicitly non-complete `core.query-result@1` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResultMessage {
    domain: QueryDomain,
    role: MatchRole,
    matches: Vec<ProtocolQueryMatch>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

impl QueryResultMessage {
    /// Validates domain, match roles, ordering ordinals, and completion counts.
    pub fn new(
        domain: QueryDomain,
        role: MatchRole,
        matches: Vec<ProtocolQueryMatch>,
        completion: Completion,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        if !is_v1_role(role) {
            return Err(crate::schema::invalid(
                "$.role",
                "role is not published by core.query-result@1",
            ));
        }
        let produced = u64::try_from(matches.len()).map_err(|_| {
            crate::schema::invalid("$.matches", "match count exceeds protocol range")
        })?;
        if completion.produced() != produced || matches.iter().any(|item| item.role() != role) {
            return Err(crate::schema::invalid(
                "$",
                "completion count or match role is inconsistent",
            ));
        }
        let native_ordinals = matches
            .iter()
            .filter_map(|item| match item {
                ProtocolQueryMatch::Native(locator) => Some(locator.ordinal),
                ProtocolQueryMatch::Portable(_) => None,
            })
            .collect::<Vec<_>>();
        if native_ordinals.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(crate::schema::invalid(
                "$.matches",
                "native match ordinals must be strictly increasing",
            ));
        }
        Ok(Self {
            domain,
            role,
            matches,
            completion,
            diagnostics,
        })
    }

    /// Converts a completed portable query execution.
    pub fn from_portable_execution(
        domain: QueryDomain,
        role: MatchRole,
        execution: &QueryExecution<PortableMatch>,
    ) -> Result<Self, ProtocolError> {
        let count = u64::try_from(execution.matches().len()).map_err(|_| {
            crate::schema::invalid("$.matches", "match count exceeds protocol range")
        })?;
        Self::new(
            domain,
            role,
            execution
                .matches()
                .iter()
                .cloned()
                .map(ProtocolQueryMatch::Portable)
                .collect(),
            Completion::new(CompletionStatus::Success, count, count, None, None)?,
            Vec::new(),
        )
    }

    /// Query domain.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Uniform result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Ordered matches.
    #[must_use]
    pub fn matches(&self) -> &[ProtocolQueryMatch] {
        &self.matches
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Ordered operation diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.query-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut matches = SequenceBuilder::new();
        for item in &self.matches {
            matches.push(match_value(item));
        }
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.query-result@1")),
            ("domain_id", PortableValue::string(self.domain.id())),
            (
                "domain_version",
                PortableValue::integer(consema_core::BigInteger::from(i64::from(
                    self.domain.version(),
                ))),
            ),
            ("role", PortableValue::string(role_name(self.role))),
            ("matches", matches.build()),
            ("completion", self.completion.to_value()),
            ("diagnostics", diagnostics.build()),
        ])
    }

    /// Strictly decodes `core.query-result@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.query-result@1",
            &[
                "schema",
                "domain_id",
                "domain_version",
                "role",
                "matches",
                "completion",
                "diagnostics",
            ],
            "$",
        )?;
        let role = parse_role(string(fields[3], "$.role")?)?;
        let matches = sequence(fields[4], "$.matches")?
            .iter()
            .enumerate()
            .map(|(index, item)| parse_match(item, &format!("$.matches[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let diagnostics = sequence(fields[6], "$.diagnostics")?
            .iter()
            .map(DiagnosticMessage::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            QueryDomain::new(
                string(fields[1], "$.domain_id")?,
                unsigned_u32(fields[2], "$.domain_version")?,
            ),
            role,
            matches,
            Completion::from_value(fields[5])?,
            diagnostics,
        )
    }
}

fn match_value(item: &ProtocolQueryMatch) -> PortableValue {
    match item {
        ProtocolQueryMatch::Portable(PortableMatch::Value { path, value }) => object(vec![
            ("kind", PortableValue::string("Value")),
            ("path", path_value(path)),
            ("value", value.clone()),
        ]),
        ProtocolQueryMatch::Portable(PortableMatch::ObjectEntry {
            location,
            key,
            value_path,
            value,
        }) => object(vec![
            ("kind", PortableValue::string("ObjectEntry")),
            ("location", association_value(location)),
            ("key", PortableValue::string(key.as_str())),
            ("value_path", path_value(value_path)),
            ("value", value.clone()),
        ]),
        ProtocolQueryMatch::Portable(PortableMatch::EntryMappingEntry {
            location,
            key_path,
            key,
            value_path,
            value,
        }) => object(vec![
            ("kind", PortableValue::string("EntryMappingEntry")),
            ("location", association_value(location)),
            ("key_path", path_value(key_path)),
            ("key", key.clone()),
            ("value_path", path_value(value_path)),
            ("value", value.clone()),
        ]),
        ProtocolQueryMatch::Native(locator) => object(vec![
            ("kind", PortableValue::string("Native")),
            ("role", PortableValue::string(role_name(locator.role))),
            (
                "source_id",
                PortableValue::string(locator.source_id.as_str()),
            ),
            (
                "node_locator",
                PortableValue::string(locator.node_locator.as_str()),
            ),
            ("ordinal", integer_u64(locator.ordinal)),
        ]),
    }
}

fn parse_match(value: &PortableValue, path: &str) -> Result<ProtocolQueryMatch, ProtocolError> {
    let entries = value.as_object().ok_or_else(|| {
        ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected match Object")
    })?;
    let kind = entries
        .first()
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| crate::schema::invalid(path, "kind must be the first String field"))?;
    let portable = match kind {
        "Value" => {
            let fields = exact_fields(value, &["kind", "path", "value"], path)?;
            PortableMatch::Value {
                path: parse_path(fields[1], &format!("{path}.path"))?,
                value: fields[2].clone(),
            }
        }
        "ObjectEntry" => {
            let fields = exact_fields(
                value,
                &["kind", "location", "key", "value_path", "value"],
                path,
            )?;
            PortableMatch::ObjectEntry {
                location: parse_association(fields[1], &format!("{path}.location"))?,
                key: string(fields[2], &format!("{path}.key"))?.to_owned(),
                value_path: parse_path(fields[3], &format!("{path}.value_path"))?,
                value: fields[4].clone(),
            }
        }
        "EntryMappingEntry" => {
            let fields = exact_fields(
                value,
                &["kind", "location", "key_path", "key", "value_path", "value"],
                path,
            )?;
            PortableMatch::EntryMappingEntry {
                location: parse_association(fields[1], &format!("{path}.location"))?,
                key_path: parse_path(fields[2], &format!("{path}.key_path"))?,
                key: fields[3].clone(),
                value_path: parse_path(fields[4], &format!("{path}.value_path"))?,
                value: fields[5].clone(),
            }
        }
        "Native" => {
            let fields = exact_fields(
                value,
                &["kind", "role", "source_id", "node_locator", "ordinal"],
                path,
            )?;
            return NativeMatchLocator::new(
                string(fields[2], &format!("{path}.source_id"))?,
                string(fields[3], &format!("{path}.node_locator"))?,
                parse_role(string(fields[1], &format!("{path}.role"))?)?,
                unsigned_u64(fields[4], &format!("{path}.ordinal"))?,
            )
            .map(ProtocolQueryMatch::Native);
        }
        _ => return Err(crate::schema::invalid(path, "unknown query match kind")),
    };
    Ok(ProtocolQueryMatch::Portable(portable))
}

pub(crate) fn path_value(path: &ValuePath) -> PortableValue {
    let mut segments = SequenceBuilder::new();
    for segment in path.segments() {
        segments.push(match segment {
            ValuePathSegment::ObjectValue(key) => object(vec![
                ("kind", PortableValue::string("ObjectValue")),
                ("key", PortableValue::string(key.as_str())),
            ]),
            ValuePathSegment::SequenceElement(index) => object(vec![
                ("kind", PortableValue::string("SequenceElement")),
                ("index", integer_u64(*index)),
            ]),
            ValuePathSegment::EntryKey(index) => object(vec![
                ("kind", PortableValue::string("EntryKey")),
                ("index", integer_u64(*index)),
            ]),
            ValuePathSegment::EntryValue(index) => object(vec![
                ("kind", PortableValue::string("EntryValue")),
                ("index", integer_u64(*index)),
            ]),
        });
    }
    object(vec![("segments", segments.build())])
}

pub(crate) fn parse_path(value: &PortableValue, path: &str) -> Result<ValuePath, ProtocolError> {
    let fields = exact_fields(value, &["segments"], path)?;
    let mut result = ValuePath::root();
    for (index, segment) in sequence(fields[0], &format!("{path}.segments"))?
        .iter()
        .enumerate()
    {
        let segment_path = format!("{path}.segments[{index}]");
        let entries = segment.as_object().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorKind::WrongType,
                &segment_path,
                "expected path segment Object",
            )
        })?;
        let kind = entries
            .first()
            .filter(|entry| entry.key() == "kind")
            .and_then(|entry| entry.value().as_string())
            .ok_or_else(|| crate::schema::invalid(&segment_path, "missing segment kind"))?;
        let decoded = match kind {
            "ObjectValue" => {
                let fields = exact_fields(segment, &["kind", "key"], &segment_path)?;
                ValuePathSegment::ObjectValue(
                    string(fields[1], &format!("{segment_path}.key"))?.to_owned(),
                )
            }
            "SequenceElement" | "EntryKey" | "EntryValue" => {
                let fields = exact_fields(segment, &["kind", "index"], &segment_path)?;
                let index = unsigned_u64(fields[1], &format!("{segment_path}.index"))?;
                match kind {
                    "SequenceElement" => ValuePathSegment::SequenceElement(index),
                    "EntryKey" => ValuePathSegment::EntryKey(index),
                    _ => ValuePathSegment::EntryValue(index),
                }
            }
            _ => {
                return Err(crate::schema::invalid(
                    &segment_path,
                    "unknown path segment",
                ));
            }
        };
        result = result.child(decoded);
    }
    Ok(result)
}

pub(crate) fn association_value(location: &AssociationLocation) -> PortableValue {
    object(vec![
        ("container", path_value(location.container())),
        ("ordinal", integer_u64(location.ordinal())),
        (
            "role",
            PortableValue::string(association_role_name(location.role())),
        ),
    ])
}

pub(crate) fn parse_association(
    value: &PortableValue,
    path: &str,
) -> Result<AssociationLocation, ProtocolError> {
    let fields = exact_fields(value, &["container", "ordinal", "role"], path)?;
    Ok(AssociationLocation::new(
        parse_path(fields[0], &format!("{path}.container"))?,
        unsigned_u64(fields[1], &format!("{path}.ordinal"))?,
        match string(fields[2], &format!("{path}.role"))? {
            "ObjectEntry" => AssociationRole::ObjectEntry,
            "ObjectKey" => AssociationRole::ObjectKey,
            "EntryMappingEntry" => AssociationRole::EntryMappingEntry,
            _ => return Err(crate::schema::invalid(path, "unknown association role")),
        },
    ))
}

const fn association_role_name(role: AssociationRole) -> &'static str {
    match role {
        AssociationRole::ObjectEntry => "ObjectEntry",
        AssociationRole::ObjectKey => "ObjectKey",
        AssociationRole::EntryMappingEntry => "EntryMappingEntry",
    }
}

fn role_name(role: MatchRole) -> &'static str {
    match role {
        MatchRole::Value => "Value",
        MatchRole::ObjectEntry => "ObjectEntry",
        MatchRole::EntryMappingEntry => "EntryMappingEntry",
        MatchRole::JsonValue => "JsonValue",
        MatchRole::JsonObjectMember => "JsonObjectMember",
        MatchRole::JsonArrayElement => "JsonArrayElement",
        MatchRole::TomlItem => "TomlItem",
        MatchRole::TomlEntry => "TomlEntry",
        MatchRole::TomlArrayElement => "TomlArrayElement",
        MatchRole::JsonSyntaxPiece => "JsonSyntaxPiece",
        MatchRole::TomlSyntaxPiece => "TomlSyntaxPiece",
        MatchRole::GraphNode
        | MatchRole::GraphSequenceElement
        | MatchRole::GraphMappingEntry
        | MatchRole::YamlStream
        | MatchRole::YamlDocument
        | MatchRole::YamlNode
        | MatchRole::YamlMappingEntry
        | MatchRole::YamlSequenceElement
        | MatchRole::YamlAnchorDefinition
        | MatchRole::YamlAliasOccurrence
        | MatchRole::YamlSyntaxPiece => {
            unreachable!("core.query-result@1 construction rejects newer roles")
        }
    }
}

const fn is_v1_role(role: MatchRole) -> bool {
    !matches!(
        role,
        MatchRole::GraphNode
            | MatchRole::GraphSequenceElement
            | MatchRole::GraphMappingEntry
            | MatchRole::YamlStream
            | MatchRole::YamlDocument
            | MatchRole::YamlNode
            | MatchRole::YamlMappingEntry
            | MatchRole::YamlSequenceElement
            | MatchRole::YamlAnchorDefinition
            | MatchRole::YamlAliasOccurrence
            | MatchRole::YamlSyntaxPiece
    )
}

fn parse_role(value: &str) -> Result<MatchRole, ProtocolError> {
    match value {
        "Value" => Ok(MatchRole::Value),
        "ObjectEntry" => Ok(MatchRole::ObjectEntry),
        "EntryMappingEntry" => Ok(MatchRole::EntryMappingEntry),
        "JsonValue" => Ok(MatchRole::JsonValue),
        "JsonObjectMember" => Ok(MatchRole::JsonObjectMember),
        "JsonArrayElement" => Ok(MatchRole::JsonArrayElement),
        "TomlItem" => Ok(MatchRole::TomlItem),
        "TomlEntry" => Ok(MatchRole::TomlEntry),
        "TomlArrayElement" => Ok(MatchRole::TomlArrayElement),
        "JsonSyntaxPiece" => Ok(MatchRole::JsonSyntaxPiece),
        "TomlSyntaxPiece" => Ok(MatchRole::TomlSyntaxPiece),
        _ => Err(crate::schema::invalid("$.role", "unknown query match role")),
    }
}

const fn is_native_role(role: MatchRole) -> bool {
    matches!(
        role,
        MatchRole::JsonValue
            | MatchRole::JsonObjectMember
            | MatchRole::JsonArrayElement
            | MatchRole::TomlItem
            | MatchRole::TomlEntry
            | MatchRole::TomlArrayElement
            | MatchRole::JsonSyntaxPiece
            | MatchRole::TomlSyntaxPiece
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{CancellationToken, CapabilityId, CapabilitySet, OperatorCall, QueryLimits};
    use consema_document::DocumentAuthority;

    #[test]
    fn query_definition_envelope_preserves_existing_schema() {
        let definition = QueryDefinition::new(QueryDomain::portable_value_v1()).with_expression(
            consema_core::QueryExpression::Input
                .then(OperatorCall::new("core.try-sequence-elements", 1)),
        );
        let message = query_definition_message(&definition).unwrap();
        assert_eq!(query_definition_from_message(&message).unwrap(), definition);
    }

    #[test]
    fn portable_query_result_preserves_path_and_value() {
        let definition = QueryDefinition::new(QueryDomain::portable_value_v1());
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        let execution = definition
            .validate()
            .unwrap()
            .bind(&capabilities)
            .unwrap()
            .execute_portable(
                &PortableValue::string("x"),
                QueryLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        let result = QueryResultMessage::from_portable_execution(
            QueryDomain::portable_value_v1(),
            MatchRole::Value,
            &execution,
        )
        .unwrap();
        assert_eq!(
            QueryResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
    }

    #[test]
    fn native_results_require_external_locators() {
        let authority = DocumentAuthority::fresh();
        let node = authority.node_ref(0, consema_document::NodeRole::TomlItem);
        assert_eq!(
            NativeMatchLocator::from_process_local(node)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
        let locator =
            NativeMatchLocator::new("source:one", "toml:path:service", MatchRole::TomlItem, 0)
                .unwrap();
        let result = QueryResultMessage::new(
            QueryDomain::toml_native_v1(),
            MatchRole::TomlItem,
            vec![ProtocolQueryMatch::Native(locator)],
            Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            QueryResultMessage::from_value(&result.to_value()).unwrap(),
            result
        );
    }

    #[test]
    fn frozen_query_result_v1_rejects_graph_roles() {
        let error = QueryResultMessage::new(
            QueryDomain::portable_graph_v1(),
            MatchRole::GraphNode,
            Vec::new(),
            Completion::new(CompletionStatus::Success, 0, 0, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }
}
