//! Externally located INI and Java Properties query results.

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32, unsigned_u64,
};
use crate::{
    Completion, DiagnosticMessage, ErrorCodeRegistry, ProtocolError, ProtocolErrorKind,
    ProtocolLimits,
};
use consema_core::{BigInteger, MatchRole, PortableValue, QueryDomain, SequenceBuilder};
use consema_document::NodeRef;

const MAX_SOURCE_ID_BYTES: usize = 1024;
const MAX_NODE_LOCATOR_BYTES: usize = 4096;

/// One INI match after caller externalization of its process-local handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniMatchLocator(ExternalLineLocator);

impl IniMatchLocator {
    /// Validates stable identities, an exact INI role, and its result ordinal.
    pub fn new(
        source_id: impl Into<String>,
        node_locator: impl Into<String>,
        role: MatchRole,
        ordinal: u64,
    ) -> Result<Self, ProtocolError> {
        ExternalLineLocator::new(source_id, node_locator, role, ordinal, is_ini_role).map(Self)
    }

    /// Explicitly refuses a raw process-local INI node handle.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(process_local("INI"))
    }

    /// Stable source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.0.source_id
    }

    /// Stable caller-defined node locator.
    #[must_use]
    pub fn node_locator(&self) -> &str {
        &self.0.node_locator
    }

    /// Exact INI result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.0.role
    }

    /// Strictly increasing standard-result ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.0.ordinal
    }
}

/// Complete or explicitly non-complete `core.ini-query-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IniQueryResultMessage {
    domain: QueryDomain,
    role: MatchRole,
    matches: Vec<IniMatchLocator>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

impl IniQueryResultMessage {
    /// Validates the exact INI domain/role matrix, ordering, and produced count.
    pub fn new(
        domain: QueryDomain,
        role: MatchRole,
        matches: Vec<IniMatchLocator>,
        completion: Completion,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        validate_result(
            &domain,
            role,
            &matches,
            &completion,
            ini_domain_accepts_role,
        )?;
        Ok(Self {
            domain,
            role,
            matches,
            completion,
            diagnostics,
        })
    }

    /// Exact INI query domain.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Uniform result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Ordered external INI match locators.
    #[must_use]
    pub fn matches(&self) -> &[IniMatchLocator] {
        &self.matches
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.ini-query-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        encode_result(
            "core.ini-query-result@1",
            &self.domain,
            self.role,
            self.matches.iter().map(|item| &item.0),
            &self.completion,
            &self.diagnostics,
        )
    }

    /// Strictly decodes under current default transport limits.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry_and_limits(
            value,
            ErrorCodeRegistry::v1(),
            ProtocolLimits::default(),
        )
    }

    /// Strictly decodes diagnostics under an explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry_and_limits(value, registry, ProtocolLimits::default())
    }

    /// Strictly decodes with explicit registry and pre-allocation limits.
    pub fn from_value_with_registry_and_limits(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        let decoded = decode_result(
            value,
            "core.ini-query-result@1",
            registry,
            limits,
            parse_ini_role,
            is_ini_role,
        )?;
        Self::new(
            decoded.domain,
            decoded.role,
            decoded.matches.into_iter().map(IniMatchLocator).collect(),
            decoded.completion,
            decoded.diagnostics,
        )
    }
}

/// One Java Properties match after externalization of its process-local handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaPropertiesMatchLocator(ExternalLineLocator);

impl JavaPropertiesMatchLocator {
    /// Validates stable identities, an exact Properties role, and its result ordinal.
    pub fn new(
        source_id: impl Into<String>,
        node_locator: impl Into<String>,
        role: MatchRole,
        ordinal: u64,
    ) -> Result<Self, ProtocolError> {
        ExternalLineLocator::new(source_id, node_locator, role, ordinal, is_properties_role)
            .map(Self)
    }

    /// Explicitly refuses a raw process-local Properties node handle.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(process_local("Java Properties"))
    }

    /// Stable source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.0.source_id
    }

    /// Stable caller-defined node locator.
    #[must_use]
    pub fn node_locator(&self) -> &str {
        &self.0.node_locator
    }

    /// Exact Java Properties result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.0.role
    }

    /// Strictly increasing standard-result ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.0.ordinal
    }
}

/// Complete or explicitly non-complete `core.java-properties-query-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaPropertiesQueryResultMessage {
    domain: QueryDomain,
    role: MatchRole,
    matches: Vec<JavaPropertiesMatchLocator>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

impl JavaPropertiesQueryResultMessage {
    /// Validates the exact Properties domain/role matrix, ordering, and produced count.
    pub fn new(
        domain: QueryDomain,
        role: MatchRole,
        matches: Vec<JavaPropertiesMatchLocator>,
        completion: Completion,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        validate_result(
            &domain,
            role,
            &matches,
            &completion,
            properties_domain_accepts_role,
        )?;
        Ok(Self {
            domain,
            role,
            matches,
            completion,
            diagnostics,
        })
    }

    /// Exact Java Properties query domain.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Uniform result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Ordered external Java Properties match locators.
    #[must_use]
    pub fn matches(&self) -> &[JavaPropertiesMatchLocator] {
        &self.matches
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn completion(&self) -> &Completion {
        &self.completion
    }

    /// Ordered diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.java-properties-query-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        encode_result(
            "core.java-properties-query-result@1",
            &self.domain,
            self.role,
            self.matches.iter().map(|item| &item.0),
            &self.completion,
            &self.diagnostics,
        )
    }

    /// Strictly decodes under current default transport limits.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry_and_limits(
            value,
            ErrorCodeRegistry::v1(),
            ProtocolLimits::default(),
        )
    }

    /// Strictly decodes diagnostics under an explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry_and_limits(value, registry, ProtocolLimits::default())
    }

    /// Strictly decodes with explicit registry and pre-allocation limits.
    pub fn from_value_with_registry_and_limits(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        let decoded = decode_result(
            value,
            "core.java-properties-query-result@1",
            registry,
            limits,
            parse_properties_role,
            is_properties_role,
        )?;
        Self::new(
            decoded.domain,
            decoded.role,
            decoded
                .matches
                .into_iter()
                .map(JavaPropertiesMatchLocator)
                .collect(),
            decoded.completion,
            decoded.diagnostics,
        )
    }
}

trait LocatedMatch {
    fn locator(&self) -> &ExternalLineLocator;
}

impl LocatedMatch for IniMatchLocator {
    fn locator(&self) -> &ExternalLineLocator {
        &self.0
    }
}

impl LocatedMatch for JavaPropertiesMatchLocator {
    fn locator(&self) -> &ExternalLineLocator {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExternalLineLocator {
    source_id: String,
    node_locator: String,
    role: MatchRole,
    ordinal: u64,
}

impl ExternalLineLocator {
    fn new(
        source_id: impl Into<String>,
        node_locator: impl Into<String>,
        role: MatchRole,
        ordinal: u64,
        accepts_role: fn(MatchRole) -> bool,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        let node_locator = node_locator.into();
        if !valid_identifier(&source_id, MAX_SOURCE_ID_BYTES)
            || !valid_identifier(&node_locator, MAX_NODE_LOCATOR_BYTES)
            || !accepts_role(role)
        {
            return Err(invalid(
                "$.matches",
                "invalid source, locator, or line-format role",
            ));
        }
        Ok(Self {
            source_id,
            node_locator,
            role,
            ordinal,
        })
    }
}

struct DecodedResult {
    domain: QueryDomain,
    role: MatchRole,
    matches: Vec<ExternalLineLocator>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

fn validate_result<T: LocatedMatch>(
    domain: &QueryDomain,
    role: MatchRole,
    matches: &[T],
    completion: &Completion,
    domain_accepts_role: fn(&QueryDomain, MatchRole) -> bool,
) -> Result<(), ProtocolError> {
    if !domain_accepts_role(domain, role) {
        return Err(invalid(
            "$",
            "line-format query domain and result role are inconsistent",
        ));
    }
    let produced = u64::try_from(matches.len())
        .map_err(|_| resource("$.matches", "match count exceeds protocol range"))?;
    if completion.produced() != produced
        || matches.iter().any(|item| item.locator().role != role)
        || matches
            .windows(2)
            .any(|pair| pair[0].locator().ordinal >= pair[1].locator().ordinal)
    {
        return Err(invalid(
            "$",
            "completion count, role, or match ordinals are inconsistent",
        ));
    }
    Ok(())
}

fn encode_result<'a>(
    schema: &str,
    domain: &QueryDomain,
    role: MatchRole,
    matches: impl Iterator<Item = &'a ExternalLineLocator>,
    completion: &Completion,
    diagnostics: &[DiagnosticMessage],
) -> PortableValue {
    let mut encoded_matches = SequenceBuilder::new();
    for item in matches {
        encoded_matches.push(object(vec![
            ("source_id", PortableValue::string(item.source_id.as_str())),
            (
                "node_locator",
                PortableValue::string(item.node_locator.as_str()),
            ),
            ("role", PortableValue::string(role_name(item.role))),
            ("ordinal", integer_u64(item.ordinal)),
        ]));
    }
    let mut encoded_diagnostics = SequenceBuilder::new();
    for diagnostic in diagnostics {
        encoded_diagnostics.push(diagnostic.to_value());
    }
    object(vec![
        ("schema", PortableValue::string(schema)),
        ("domain_id", PortableValue::string(domain.id())),
        (
            "domain_version",
            PortableValue::integer(BigInteger::from(i64::from(domain.version()))),
        ),
        ("role", PortableValue::string(role_name(role))),
        ("matches", encoded_matches.build()),
        ("completion", completion.to_value()),
        ("diagnostics", encoded_diagnostics.build()),
    ])
}

fn decode_result(
    value: &PortableValue,
    expected_schema: &str,
    registry: ErrorCodeRegistry,
    limits: ProtocolLimits,
    parse_role: fn(&str) -> Result<MatchRole, ProtocolError>,
    accepts_role: fn(MatchRole) -> bool,
) -> Result<DecodedResult, ProtocolError> {
    let fields = schema_fields(
        value,
        expected_schema,
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
    let match_values = sequence(fields[4], "$.matches")?;
    let diagnostic_values = sequence(fields[6], "$.diagnostics")?;
    check_container_limit("$.matches", match_values.len(), limits)?;
    check_container_limit("$.diagnostics", diagnostic_values.len(), limits)?;
    let aggregate = match_values
        .len()
        .checked_add(diagnostic_values.len())
        .and_then(|count| count.checked_add(8))
        .ok_or_else(|| resource("$", "query-result node count overflows usize"))?;
    if aggregate > limits.max_nodes {
        return Err(resource(
            "$",
            "query-result structure exceeds the configured node limit",
        ));
    }

    let mut matches = Vec::new();
    matches
        .try_reserve_exact(match_values.len())
        .map_err(|_| resource("$.matches", "cannot allocate bounded match list"))?;
    for (index, value) in match_values.iter().enumerate() {
        let path = format!("$.matches[{index}]");
        let fields = exact_fields(
            value,
            &["source_id", "node_locator", "role", "ordinal"],
            &path,
        )?;
        let source_id = bounded_copy(
            string(fields[0], &format!("{path}.source_id"))?,
            MAX_SOURCE_ID_BYTES,
            limits,
            &format!("{path}.source_id"),
        )?;
        let node_locator = bounded_copy(
            string(fields[1], &format!("{path}.node_locator"))?,
            MAX_NODE_LOCATOR_BYTES,
            limits,
            &format!("{path}.node_locator"),
        )?;
        let role = parse_role(string(fields[2], &format!("{path}.role"))?)?;
        matches.push(ExternalLineLocator::new(
            source_id,
            node_locator,
            role,
            unsigned_u64(fields[3], &format!("{path}.ordinal"))?,
            accepts_role,
        )?);
    }

    let mut diagnostics = Vec::new();
    diagnostics
        .try_reserve_exact(diagnostic_values.len())
        .map_err(|_| resource("$.diagnostics", "cannot allocate bounded diagnostic list"))?;
    for value in diagnostic_values {
        diagnostics.push(DiagnosticMessage::from_value_with_registry(
            value, registry,
        )?);
    }
    Ok(DecodedResult {
        domain: QueryDomain::new(
            string(fields[1], "$.domain_id")?,
            unsigned_u32(fields[2], "$.domain_version")?,
        ),
        role: parse_role(string(fields[3], "$.role")?)?,
        matches,
        completion: Completion::from_value_with_registry(fields[5], registry)?,
        diagnostics,
    })
}

fn bounded_copy(
    value: &str,
    format_limit: usize,
    limits: ProtocolLimits,
    path: &str,
) -> Result<String, ProtocolError> {
    if !valid_identifier(value, format_limit) {
        return Err(invalid(
            path,
            "identifier is empty or exceeds its format limit",
        ));
    }
    if value.len() > limits.max_blob_bytes {
        return Err(resource(
            path,
            "identifier exceeds the configured blob limit",
        ));
    }
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| resource(path, "cannot allocate bounded identifier"))?;
    owned.push_str(value);
    Ok(owned)
}

fn check_container_limit(
    path: &str,
    count: usize,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    if count > limits.max_container_entries {
        return Err(resource(
            path,
            "container exceeds the configured entry limit",
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn ini_domain_accepts_role(domain: &QueryDomain, role: MatchRole) -> bool {
    match (domain.id(), domain.version()) {
        ("ini.native-semantic-query", 1) => is_ini_native_role(role),
        ("ini.lossless-syntax-query", 1) => role == MatchRole::IniSyntaxPiece,
        _ => false,
    }
}

fn properties_domain_accepts_role(domain: &QueryDomain, role: MatchRole) -> bool {
    match (domain.id(), domain.version()) {
        ("java-properties.native-semantic-query", 1) => is_properties_native_role(role),
        ("java-properties.lossless-syntax-query", 1) => role == MatchRole::PropertiesSyntaxPiece,
        _ => false,
    }
}

fn is_ini_role(role: MatchRole) -> bool {
    is_ini_native_role(role) || role == MatchRole::IniSyntaxPiece
}

const fn is_ini_native_role(role: MatchRole) -> bool {
    matches!(
        role,
        MatchRole::IniDocument
            | MatchRole::IniPhysicalLine
            | MatchRole::IniLogicalLine
            | MatchRole::IniSection
            | MatchRole::IniDefaultSection
            | MatchRole::IniEntry
            | MatchRole::IniErrorLine
    )
}

fn is_properties_role(role: MatchRole) -> bool {
    is_properties_native_role(role) || role == MatchRole::PropertiesSyntaxPiece
}

const fn is_properties_native_role(role: MatchRole) -> bool {
    matches!(
        role,
        MatchRole::PropertiesDocument
            | MatchRole::PropertiesNaturalLine
            | MatchRole::PropertiesLogicalLine
            | MatchRole::PropertiesProperty
            | MatchRole::PropertiesComment
            | MatchRole::PropertiesEscape
            | MatchRole::PropertiesErrorLine
    )
}

fn role_name(role: MatchRole) -> &'static str {
    match role {
        MatchRole::IniDocument => "IniDocument",
        MatchRole::IniPhysicalLine => "IniPhysicalLine",
        MatchRole::IniLogicalLine => "IniLogicalLine",
        MatchRole::IniSection => "IniSection",
        MatchRole::IniDefaultSection => "IniDefaultSection",
        MatchRole::IniEntry => "IniEntry",
        MatchRole::IniErrorLine => "IniErrorLine",
        MatchRole::IniSyntaxPiece => "IniSyntaxPiece",
        MatchRole::PropertiesDocument => "PropertiesDocument",
        MatchRole::PropertiesNaturalLine => "PropertiesNaturalLine",
        MatchRole::PropertiesLogicalLine => "PropertiesLogicalLine",
        MatchRole::PropertiesProperty => "PropertiesProperty",
        MatchRole::PropertiesComment => "PropertiesComment",
        MatchRole::PropertiesEscape => "PropertiesEscape",
        MatchRole::PropertiesErrorLine => "PropertiesErrorLine",
        MatchRole::PropertiesSyntaxPiece => "PropertiesSyntaxPiece",
        _ => unreachable!("line-query construction validates the role"),
    }
}

fn parse_ini_role(value: &str) -> Result<MatchRole, ProtocolError> {
    match value {
        "IniDocument" => Ok(MatchRole::IniDocument),
        "IniPhysicalLine" => Ok(MatchRole::IniPhysicalLine),
        "IniLogicalLine" => Ok(MatchRole::IniLogicalLine),
        "IniSection" => Ok(MatchRole::IniSection),
        "IniDefaultSection" => Ok(MatchRole::IniDefaultSection),
        "IniEntry" => Ok(MatchRole::IniEntry),
        "IniErrorLine" => Ok(MatchRole::IniErrorLine),
        "IniSyntaxPiece" => Ok(MatchRole::IniSyntaxPiece),
        _ => Err(invalid("$.role", "unknown INI query match role")),
    }
}

fn parse_properties_role(value: &str) -> Result<MatchRole, ProtocolError> {
    match value {
        "PropertiesDocument" => Ok(MatchRole::PropertiesDocument),
        "PropertiesNaturalLine" => Ok(MatchRole::PropertiesNaturalLine),
        "PropertiesLogicalLine" => Ok(MatchRole::PropertiesLogicalLine),
        "PropertiesProperty" => Ok(MatchRole::PropertiesProperty),
        "PropertiesComment" => Ok(MatchRole::PropertiesComment),
        "PropertiesEscape" => Ok(MatchRole::PropertiesEscape),
        "PropertiesErrorLine" => Ok(MatchRole::PropertiesErrorLine),
        "PropertiesSyntaxPiece" => Ok(MatchRole::PropertiesSyntaxPiece),
        _ => Err(invalid(
            "$.role",
            "unknown Java Properties query match role",
        )),
    }
}

fn process_local(format: &str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorKind::ProcessLocalHandle,
        "$.matches.node",
        format!("{format} NodeRef requires a stable caller locator"),
    )
}

fn invalid(path: impl Into<String>, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, detail)
}

fn resource(path: impl Into<String>, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::ResourceLimit, path, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompletionStatus;
    use consema_document::{DocumentAuthority, NodeRole};

    #[test]
    fn every_ini_role_round_trips_in_its_exact_domain() {
        let roles = [
            MatchRole::IniDocument,
            MatchRole::IniPhysicalLine,
            MatchRole::IniLogicalLine,
            MatchRole::IniSection,
            MatchRole::IniDefaultSection,
            MatchRole::IniEntry,
            MatchRole::IniErrorLine,
            MatchRole::IniSyntaxPiece,
        ];
        for role in roles {
            let domain = if role == MatchRole::IniSyntaxPiece {
                QueryDomain::ini_lossless_syntax_v1()
            } else {
                QueryDomain::ini_native_v1()
            };
            let result = IniQueryResultMessage::new(
                domain,
                role,
                vec![IniMatchLocator::new("source:ini", "ini:node:0", role, 0).unwrap()],
                success(1),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                IniQueryResultMessage::from_value(&result.to_value()).unwrap(),
                result
            );
        }
    }

    #[test]
    fn every_properties_role_round_trips_in_its_exact_domain() {
        let roles = [
            MatchRole::PropertiesDocument,
            MatchRole::PropertiesNaturalLine,
            MatchRole::PropertiesLogicalLine,
            MatchRole::PropertiesProperty,
            MatchRole::PropertiesComment,
            MatchRole::PropertiesEscape,
            MatchRole::PropertiesErrorLine,
            MatchRole::PropertiesSyntaxPiece,
        ];
        for role in roles {
            let domain = if role == MatchRole::PropertiesSyntaxPiece {
                QueryDomain::java_properties_lossless_syntax_v1()
            } else {
                QueryDomain::java_properties_native_v1()
            };
            let result = JavaPropertiesQueryResultMessage::new(
                domain,
                role,
                vec![
                    JavaPropertiesMatchLocator::new(
                        "source:properties",
                        "properties:node:0",
                        role,
                        0,
                    )
                    .unwrap(),
                ],
                success(1),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                JavaPropertiesQueryResultMessage::from_value(&result.to_value()).unwrap(),
                result
            );
        }
    }

    #[test]
    fn domain_role_ordinals_completion_and_limits_are_strict() {
        let mismatch = IniQueryResultMessage::new(
            QueryDomain::ini_native_v1(),
            MatchRole::IniSyntaxPiece,
            Vec::new(),
            success(0),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(mismatch.kind(), ProtocolErrorKind::InvalidValue);

        let duplicate = JavaPropertiesQueryResultMessage::new(
            QueryDomain::java_properties_native_v1(),
            MatchRole::PropertiesProperty,
            vec![
                JavaPropertiesMatchLocator::new(
                    "source:p",
                    "property:0",
                    MatchRole::PropertiesProperty,
                    1,
                )
                .unwrap(),
                JavaPropertiesMatchLocator::new(
                    "source:p",
                    "property:1",
                    MatchRole::PropertiesProperty,
                    1,
                )
                .unwrap(),
            ],
            success(2),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(duplicate.kind(), ProtocolErrorKind::InvalidValue);

        let result = IniQueryResultMessage::new(
            QueryDomain::ini_native_v1(),
            MatchRole::IniEntry,
            vec![IniMatchLocator::new("source:ini", "entry:0", MatchRole::IniEntry, 0).unwrap()],
            success(1),
            Vec::new(),
        )
        .unwrap();
        let limits = ProtocolLimits {
            max_container_entries: 0,
            ..ProtocolLimits::default()
        };
        assert_eq!(
            IniQueryResultMessage::from_value_with_registry_and_limits(
                &result.to_value(),
                ErrorCodeRegistry::v5(),
                limits,
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::ResourceLimit
        );
    }

    #[test]
    fn raw_line_format_nodes_never_cross_the_wire() {
        let authority = DocumentAuthority::fresh();
        assert_eq!(
            IniMatchLocator::from_process_local(authority.node_ref(0, NodeRole::IniEntry))
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
        assert_eq!(
            JavaPropertiesMatchLocator::from_process_local(
                authority.node_ref(1, NodeRole::SyntaxNode),
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
    }

    fn success(produced: u64) -> Completion {
        Completion::new(CompletionStatus::Success, produced, produced, None, None).unwrap()
    }
}
