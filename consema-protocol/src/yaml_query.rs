//! Externally located YAML native and lossless query results.

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32, unsigned_u64,
};
use crate::{Completion, DiagnosticMessage, ProtocolError, ProtocolErrorKind};
use consema_core::{BigInteger, MatchRole, PortableValue, QueryDomain, SequenceBuilder};
use consema_document::NodeRef;

/// One YAML match after caller externalization of its process-local handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamlMatchLocator {
    source_id: String,
    node_locator: String,
    role: MatchRole,
    ordinal: u64,
}

impl YamlMatchLocator {
    /// Validates stable identities, a YAML role, and its result ordinal.
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
            || !is_yaml_role(role)
        {
            return Err(invalid(
                "$.yaml_match",
                "invalid source, locator, or YAML role",
            ));
        }
        Ok(Self {
            source_id,
            node_locator,
            role,
            ordinal,
        })
    }

    /// Explicitly refuses a raw process-local YAML node handle.
    pub fn from_process_local(_node: NodeRef) -> Result<Self, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.yaml_match.node",
            "NodeRef requires a stable caller locator",
        ))
    }

    /// Stable source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Stable caller-defined node locator.
    #[must_use]
    pub fn node_locator(&self) -> &str {
        &self.node_locator
    }

    /// Exact YAML result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Strictly increasing standard-result ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

/// Complete or explicitly non-complete `core.yaml-query-result@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamlQueryResultMessage {
    domain: QueryDomain,
    role: MatchRole,
    matches: Vec<YamlMatchLocator>,
    completion: Completion,
    diagnostics: Vec<DiagnosticMessage>,
}

impl YamlQueryResultMessage {
    /// Validates domain/role binding, match ordering, and produced count.
    pub fn new(
        domain: QueryDomain,
        role: MatchRole,
        matches: Vec<YamlMatchLocator>,
        completion: Completion,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        if !domain_accepts_role(&domain, role) {
            return Err(invalid(
                "$",
                "YAML query domain and result role are inconsistent",
            ));
        }
        let produced = u64::try_from(matches.len())
            .map_err(|_| resource("$.matches", "match count exceeds protocol range"))?;
        if completion.produced() != produced
            || matches.iter().any(|item| item.role != role)
            || matches
                .windows(2)
                .any(|pair| pair[0].ordinal >= pair[1].ordinal)
        {
            return Err(invalid(
                "$",
                "completion count, role, or YAML match ordinals are inconsistent",
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

    /// Exact YAML query domain.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Uniform result role.
    #[must_use]
    pub const fn role(&self) -> MatchRole {
        self.role
    }

    /// Ordered external match locators.
    #[must_use]
    pub fn matches(&self) -> &[YamlMatchLocator] {
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

    /// Encodes `core.yaml-query-result@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut matches = SequenceBuilder::new();
        for item in &self.matches {
            matches.push(object(vec![
                ("source_id", PortableValue::string(item.source_id.as_str())),
                (
                    "node_locator",
                    PortableValue::string(item.node_locator.as_str()),
                ),
                ("role", PortableValue::string(role_name(item.role))),
                ("ordinal", integer_u64(item.ordinal)),
            ]));
        }
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.yaml-query-result@1")),
            ("domain_id", PortableValue::string(self.domain.id())),
            (
                "domain_version",
                PortableValue::integer(BigInteger::from(i64::from(self.domain.version()))),
            ),
            ("role", PortableValue::string(role_name(self.role))),
            ("matches", matches.build()),
            ("completion", self.completion.to_value()),
            ("diagnostics", diagnostics.build()),
        ])
    }

    /// Strictly decodes one externalized YAML query result.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.yaml-query-result@1",
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
        let matches = sequence(fields[4], "$.matches")?
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let path = format!("$.matches[{index}]");
                let fields = exact_fields(
                    value,
                    &["source_id", "node_locator", "role", "ordinal"],
                    &path,
                )?;
                YamlMatchLocator::new(
                    string(fields[0], &format!("{path}.source_id"))?,
                    string(fields[1], &format!("{path}.node_locator"))?,
                    parse_role(string(fields[2], &format!("{path}.role"))?)?,
                    unsigned_u64(fields[3], &format!("{path}.ordinal"))?,
                )
            })
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
            parse_role(string(fields[3], "$.role")?)?,
            matches,
            Completion::from_value(fields[5])?,
            diagnostics,
        )
    }
}

fn domain_accepts_role(domain: &QueryDomain, role: MatchRole) -> bool {
    match (domain.id(), domain.version()) {
        ("yaml.native-semantic-query", 1) => is_yaml_native_role(role),
        ("yaml.lossless-syntax-query", 1) => role == MatchRole::YamlSyntaxPiece,
        _ => false,
    }
}

fn is_yaml_role(role: MatchRole) -> bool {
    is_yaml_native_role(role) || role == MatchRole::YamlSyntaxPiece
}

const fn is_yaml_native_role(role: MatchRole) -> bool {
    matches!(
        role,
        MatchRole::YamlStream
            | MatchRole::YamlDocument
            | MatchRole::YamlNode
            | MatchRole::YamlMappingEntry
            | MatchRole::YamlSequenceElement
            | MatchRole::YamlAnchorDefinition
            | MatchRole::YamlAliasOccurrence
    )
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
        MatchRole::YamlSyntaxPiece => "YamlSyntaxPiece",
        _ => unreachable!("YamlQueryResultMessage construction validates the role"),
    }
}

fn parse_role(value: &str) -> Result<MatchRole, ProtocolError> {
    match value {
        "YamlStream" => Ok(MatchRole::YamlStream),
        "YamlDocument" => Ok(MatchRole::YamlDocument),
        "YamlNode" => Ok(MatchRole::YamlNode),
        "YamlMappingEntry" => Ok(MatchRole::YamlMappingEntry),
        "YamlSequenceElement" => Ok(MatchRole::YamlSequenceElement),
        "YamlAnchorDefinition" => Ok(MatchRole::YamlAnchorDefinition),
        "YamlAliasOccurrence" => Ok(MatchRole::YamlAliasOccurrence),
        "YamlSyntaxPiece" => Ok(MatchRole::YamlSyntaxPiece),
        _ => Err(invalid("$.role", "unknown YAML query match role")),
    }
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, message)
}

fn resource(path: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::ResourceLimit, path, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompletionStatus;
    use consema_document::DocumentAuthority;

    #[test]
    fn every_yaml_role_round_trips_in_its_exact_domain() {
        let roles = [
            MatchRole::YamlStream,
            MatchRole::YamlDocument,
            MatchRole::YamlNode,
            MatchRole::YamlMappingEntry,
            MatchRole::YamlSequenceElement,
            MatchRole::YamlAnchorDefinition,
            MatchRole::YamlAliasOccurrence,
            MatchRole::YamlSyntaxPiece,
        ];
        for role in roles {
            let domain = if role == MatchRole::YamlSyntaxPiece {
                QueryDomain::yaml_lossless_syntax_v1()
            } else {
                QueryDomain::yaml_native_v1()
            };
            let result = YamlQueryResultMessage::new(
                domain,
                role,
                vec![YamlMatchLocator::new("source:yaml", "yaml:node:0", role, 0).unwrap()],
                Completion::new(CompletionStatus::Success, 1, 1, None, None).unwrap(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                YamlQueryResultMessage::from_value(&result.to_value()).unwrap(),
                result
            );
        }
    }

    #[test]
    fn domain_role_mismatch_and_nonincreasing_ordinals_fail() {
        let syntax_as_native = YamlQueryResultMessage::new(
            QueryDomain::yaml_native_v1(),
            MatchRole::YamlSyntaxPiece,
            Vec::new(),
            Completion::new(CompletionStatus::Success, 0, 0, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(syntax_as_native.kind(), ProtocolErrorKind::InvalidValue);

        let duplicate = YamlQueryResultMessage::new(
            QueryDomain::yaml_native_v1(),
            MatchRole::YamlNode,
            vec![
                YamlMatchLocator::new("source:yaml", "yaml:node:0", MatchRole::YamlNode, 0)
                    .unwrap(),
                YamlMatchLocator::new("source:yaml", "yaml:node:1", MatchRole::YamlNode, 0)
                    .unwrap(),
            ],
            Completion::new(CompletionStatus::Success, 2, 2, None, None).unwrap(),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(duplicate.kind(), ProtocolErrorKind::InvalidValue);
    }

    #[test]
    fn raw_yaml_node_never_crosses_the_wire() {
        let node = DocumentAuthority::fresh().node_ref(0, consema_document::NodeRole::YamlNode);
        assert_eq!(
            YamlMatchLocator::from_process_local(node)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
    }
}
