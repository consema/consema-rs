//! Versioned typed query definitions and portable-value execution.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    AssociationLocation, AssociationRole, BigInteger, CapabilityId, CapabilitySet, ObjectBuilder,
    PortableValue, PortableValueKind, SequenceBuilder, ValuePath, ValuePathSegment,
};

/// A versioned query domain.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QueryDomain {
    id: String,
    version: u32,
}

impl QueryDomain {
    /// Creates a domain identifier.
    #[must_use]
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// `core.portable-value-query@1`.
    #[must_use]
    pub fn portable_value_v1() -> Self {
        Self::new("core.portable-value-query", 1)
    }

    /// `core.portable-graph-query@1`.
    #[must_use]
    pub fn portable_graph_v1() -> Self {
        Self::new("core.portable-graph-query", 1)
    }

    /// `json.native-semantic-query@1`.
    #[must_use]
    pub fn json_native_v1() -> Self {
        Self::new("json.native-semantic-query", 1)
    }

    /// `json.native-semantic-query@2` with JSON5 `BinaryFloat64` support.
    #[must_use]
    pub fn json_native_v2() -> Self {
        Self::new("json.native-semantic-query", 2)
    }

    /// `toml.native-semantic-query@1`.
    #[must_use]
    pub fn toml_native_v1() -> Self {
        Self::new("toml.native-semantic-query", 1)
    }

    /// `yaml.native-semantic-query@1`.
    #[must_use]
    pub fn yaml_native_v1() -> Self {
        Self::new("yaml.native-semantic-query", 1)
    }

    /// `ini.native-semantic-query@1`.
    #[must_use]
    pub fn ini_native_v1() -> Self {
        Self::new("ini.native-semantic-query", 1)
    }

    /// `json.lossless-syntax-query@1`.
    #[must_use]
    pub fn json_lossless_syntax_v1() -> Self {
        Self::new("json.lossless-syntax-query", 1)
    }

    /// `json.lossless-syntax-query@2` with JSON5 Identifier support.
    #[must_use]
    pub fn json_lossless_syntax_v2() -> Self {
        Self::new("json.lossless-syntax-query", 2)
    }

    /// `toml.lossless-syntax-query@1`.
    #[must_use]
    pub fn toml_lossless_syntax_v1() -> Self {
        Self::new("toml.lossless-syntax-query", 1)
    }

    /// `yaml.lossless-syntax-query@1`.
    #[must_use]
    pub fn yaml_lossless_syntax_v1() -> Self {
        Self::new("yaml.lossless-syntax-query", 1)
    }

    /// `ini.lossless-syntax-query@1`.
    #[must_use]
    pub fn ini_lossless_syntax_v1() -> Self {
        Self::new("ini.lossless-syntax-query", 1)
    }

    /// Domain namespace.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Domain version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Typed match role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MatchRole {
    /// Portable value and root-relative path.
    Value,
    /// Portable Object association.
    ObjectEntry,
    /// Portable EntryMapping association.
    EntryMappingEntry,
    /// JSON native semantic value.
    JsonValue,
    /// JSON object member preserving duplicate identity.
    JsonObjectMember,
    /// JSON array element.
    JsonArrayElement,
    /// TOML native semantic item.
    TomlItem,
    /// TOML table or inline-table entry.
    TomlEntry,
    /// TOML array or array-of-tables element.
    TomlArrayElement,
    /// Complete YAML serialization stream.
    YamlStream,
    /// One independent YAML document.
    YamlDocument,
    /// YAML representation node.
    YamlNode,
    /// YAML ordered mapping association.
    YamlMappingEntry,
    /// YAML ordered sequence association.
    YamlSequenceElement,
    /// YAML anchor definition occurrence.
    YamlAnchorDefinition,
    /// YAML alias serialization occurrence.
    YamlAliasOccurrence,
    /// JSON lossless syntax piece.
    JsonSyntaxPiece,
    /// TOML lossless syntax piece.
    TomlSyntaxPiece,
    /// YAML lossless syntax piece.
    YamlSyntaxPiece,
    /// Complete INI document.
    IniDocument,
    /// One INI section occurrence.
    IniSection,
    /// One INI entry occurrence.
    IniEntry,
    /// One physical INI source line.
    IniPhysicalLine,
    /// One logical INI record.
    IniLogicalLine,
    /// INI lossless syntax piece.
    IniSyntaxPiece,
    /// PortableGraph node.
    GraphNode,
    /// PortableGraph sequence element association.
    GraphSequenceElement,
    /// PortableGraph mapping association.
    GraphMappingEntry,
}

/// One versioned operator call with deterministic arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorCall {
    id: String,
    version: u32,
    arguments: BTreeMap<String, PortableValue>,
}

impl OperatorCall {
    /// Creates an operator call without arguments.
    #[must_use]
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
            arguments: BTreeMap::new(),
        }
    }

    /// Adds or replaces a named argument.
    #[must_use]
    pub fn with_argument(mut self, name: impl Into<String>, value: PortableValue) -> Self {
        self.arguments.insert(name.into(), value);
        self
    }

    /// Stable operator identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Operator contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Deterministically ordered arguments.
    #[must_use]
    pub const fn arguments(&self) -> &BTreeMap<String, PortableValue> {
        &self.arguments
    }
}

/// Declarative operator tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryExpression {
    /// Domain root input.
    Input,
    /// Applies an operator to an input expression.
    Apply {
        /// Input expression.
        input: Box<Self>,
        /// Operator call.
        operator: OperatorCall,
    },
    /// Appends complete branch results in branch order.
    Concat(Vec<Self>),
    /// Merges branches by structural identity order.
    StructureOrderMerge(Vec<Self>),
}

impl QueryExpression {
    /// Applies one operator.
    #[must_use]
    pub fn then(self, operator: OperatorCall) -> Self {
        Self::Apply {
            input: Box::new(self),
            operator,
        }
    }
}

/// Builder that is not yet a completed query definition.
#[derive(Clone, Debug)]
pub struct QueryDefinitionBuilder {
    domain: QueryDomain,
    expression: QueryExpression,
    selection: QuerySelection,
}

impl QueryDefinitionBuilder {
    /// Starts a definition rooted at the domain input.
    #[must_use]
    pub fn new(domain: QueryDomain) -> Self {
        Self {
            domain,
            expression: QueryExpression::Input,
            selection: QuerySelection::All,
        }
    }

    /// Replaces the expression.
    pub fn expression(&mut self, expression: QueryExpression) -> &mut Self {
        self.expression = expression;
        self
    }

    /// Sets cardinality selection.
    pub fn selection(&mut self, selection: QuerySelection) -> &mut Self {
        self.selection = selection;
        self
    }

    /// Completes the immutable definition. The builder itself is never a valid query.
    #[must_use]
    pub fn build(self) -> QueryDefinition {
        QueryDefinition {
            domain: self.domain,
            expression: self.expression,
            selection: self.selection,
        }
    }
}

/// Cardinality selection applied to the complete standard result sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuerySelection {
    /// Keep every match.
    All,
    /// Keep the first match.
    First,
    /// Keep the last match.
    Last,
    /// Require at most one match.
    ZeroOrOne,
    /// Require exactly one match.
    RequireOne,
}

/// Transferable, not-yet-validated query definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryDefinition {
    domain: QueryDomain,
    expression: QueryExpression,
    selection: QuerySelection,
}

impl QueryDefinition {
    /// Creates a definition rooted at the domain input.
    #[must_use]
    pub fn new(domain: QueryDomain) -> Self {
        Self {
            domain,
            expression: QueryExpression::Input,
            selection: QuerySelection::All,
        }
    }

    /// Replaces the expression.
    #[must_use]
    pub fn with_expression(mut self, expression: QueryExpression) -> Self {
        self.expression = expression;
        self
    }

    /// Sets cardinality selection.
    #[must_use]
    pub const fn with_selection(mut self, selection: QuerySelection) -> Self {
        self.selection = selection;
        self
    }

    /// Domain contract.
    #[must_use]
    pub const fn domain(&self) -> &QueryDomain {
        &self.domain
    }

    /// Operator expression.
    #[must_use]
    pub const fn expression(&self) -> &QueryExpression {
        &self.expression
    }

    /// Cardinality selector.
    #[must_use]
    pub const fn selection(&self) -> QuerySelection {
        self.selection
    }

    /// Validates domain, argument schemas, composition and role typing.
    pub fn validate(self) -> Result<ValidatedQuery, QueryFailure> {
        let input_role = match (self.domain.id(), self.domain.version()) {
            ("core.portable-value-query", 1) => MatchRole::Value,
            ("core.portable-graph-query", 1) => MatchRole::GraphNode,
            ("json.native-semantic-query", 1 | 2) => MatchRole::JsonValue,
            ("toml.native-semantic-query", 1) => MatchRole::TomlItem,
            ("yaml.native-semantic-query", 1) => MatchRole::YamlStream,
            ("ini.native-semantic-query", 1) => MatchRole::IniDocument,
            ("json.lossless-syntax-query", 1 | 2) => MatchRole::JsonSyntaxPiece,
            ("toml.lossless-syntax-query", 1) => MatchRole::TomlSyntaxPiece,
            ("yaml.lossless-syntax-query", 1) => MatchRole::YamlSyntaxPiece,
            ("ini.lossless-syntax-query", 1) => MatchRole::IniSyntaxPiece,
            _ => return Err(QueryFailure::DomainMismatch(self.domain.clone())),
        };
        let output_role = validate_expression(&self.domain, &self.expression, input_role)?;
        Ok(ValidatedQuery {
            definition: self,
            output_role,
            required_capabilities: vec![CapabilityId::new("core.query.ordered-results", 1)],
        })
    }

    /// Encodes `core.query-definition@1` through the fixed-field PortableValue schema.
    ///
    /// The result can be passed to PVCE/1; no host-language object serialization is used.
    pub fn to_protocol_value(&self) -> Result<PortableValue, QueryFailure> {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("schema", PortableValue::string("core.query-definition@1"))
            .expect("fixed unique field");
        builder
            .insert("domain_id", PortableValue::string(self.domain.id()))
            .expect("fixed unique field");
        builder
            .insert(
                "domain_version",
                PortableValue::integer(BigInteger::from(i64::from(self.domain.version()))),
            )
            .expect("fixed unique field");
        builder
            .insert(
                "selection",
                PortableValue::string(selection_name(self.selection)),
            )
            .expect("fixed unique field");
        builder
            .insert("expression", encode_expression(&self.expression, 0)?)
            .expect("fixed unique field");
        Ok(builder.build())
    }

    /// Strictly decodes `core.query-definition@1`.
    ///
    /// Unknown, reordered, or missing fields are rejected. Structural/operator validation
    /// remains the explicit next lifecycle step.
    pub fn from_protocol_value(value: &PortableValue) -> Result<Self, QueryFailure> {
        let fields = exact_object_fields(
            value,
            &[
                "schema",
                "domain_id",
                "domain_version",
                "selection",
                "expression",
            ],
            "core.query-definition@1",
        )?;
        if fields[0].as_string() != Some("core.query-definition@1") {
            return Err(protocol_error("schema"));
        }
        let domain_id = fields[1]
            .as_string()
            .ok_or_else(|| protocol_error("domain_id"))?;
        let domain_version = integer_u32(fields[2], "domain_version")?;
        let selection = match fields[3].as_string() {
            Some("All") => QuerySelection::All,
            Some("First") => QuerySelection::First,
            Some("Last") => QuerySelection::Last,
            Some("ZeroOrOne") => QuerySelection::ZeroOrOne,
            Some("RequireOne") => QuerySelection::RequireOne,
            _ => return Err(protocol_error("selection")),
        };
        Ok(Self {
            domain: QueryDomain::new(domain_id, domain_version),
            expression: decode_expression(fields[4], 0)?,
            selection,
        })
    }
}

const fn selection_name(selection: QuerySelection) -> &'static str {
    match selection {
        QuerySelection::All => "All",
        QuerySelection::First => "First",
        QuerySelection::Last => "Last",
        QuerySelection::ZeroOrOne => "ZeroOrOne",
        QuerySelection::RequireOne => "RequireOne",
    }
}

fn encode_expression(
    expression: &QueryExpression,
    depth: usize,
) -> Result<PortableValue, QueryFailure> {
    if depth > 256 {
        return Err(QueryFailure::ResourceLimitExceeded);
    }
    let mut builder = ObjectBuilder::new();
    match expression {
        QueryExpression::Input => {
            builder
                .insert("kind", PortableValue::string("Input"))
                .expect("fixed unique field");
        }
        QueryExpression::Apply { input, operator } => {
            builder
                .insert("kind", PortableValue::string("Apply"))
                .expect("fixed unique field");
            builder
                .insert("input", encode_expression(input, depth + 1)?)
                .expect("fixed unique field");
            builder
                .insert("operator", encode_operator(operator))
                .expect("fixed unique field");
        }
        QueryExpression::Concat(branches) | QueryExpression::StructureOrderMerge(branches) => {
            builder
                .insert(
                    "kind",
                    PortableValue::string(if matches!(expression, QueryExpression::Concat(_)) {
                        "Concat"
                    } else {
                        "StructureOrderMerge"
                    }),
                )
                .expect("fixed unique field");
            let mut sequence = SequenceBuilder::new();
            for branch in branches {
                sequence.push(encode_expression(branch, depth + 1)?);
            }
            builder
                .insert("branches", sequence.build())
                .expect("fixed unique field");
        }
    }
    Ok(builder.build())
}

fn encode_operator(operator: &OperatorCall) -> PortableValue {
    let mut builder = ObjectBuilder::new();
    builder
        .insert("id", PortableValue::string(operator.id()))
        .expect("fixed unique field");
    builder
        .insert(
            "version",
            PortableValue::integer(BigInteger::from(i64::from(operator.version()))),
        )
        .expect("fixed unique field");
    let mut arguments = ObjectBuilder::new();
    for (name, value) in operator.arguments() {
        arguments
            .insert(name, value.clone())
            .expect("BTreeMap has unique names");
    }
    builder
        .insert("arguments", arguments.build())
        .expect("fixed unique field");
    builder.build()
}

fn decode_expression(value: &PortableValue, depth: usize) -> Result<QueryExpression, QueryFailure> {
    if depth > 256 {
        return Err(QueryFailure::ResourceLimitExceeded);
    }
    let entries = value
        .as_object()
        .ok_or_else(|| protocol_error("expression"))?;
    let kind = entries
        .first()
        .filter(|entry| entry.key() == "kind")
        .and_then(|entry| entry.value().as_string())
        .ok_or_else(|| protocol_error("expression.kind"))?;
    match kind {
        "Input" if entries.len() == 1 => Ok(QueryExpression::Input),
        "Apply" => {
            let fields = exact_object_fields(value, &["kind", "input", "operator"], "Apply")?;
            Ok(QueryExpression::Apply {
                input: Box::new(decode_expression(fields[1], depth + 1)?),
                operator: decode_operator(fields[2])?,
            })
        }
        "Concat" | "StructureOrderMerge" => {
            let fields = exact_object_fields(value, &["kind", "branches"], kind)?;
            let branches = fields[1]
                .as_sequence()
                .ok_or_else(|| protocol_error("expression.branches"))?
                .iter()
                .map(|branch| decode_expression(branch, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            if kind == "Concat" {
                Ok(QueryExpression::Concat(branches))
            } else {
                Ok(QueryExpression::StructureOrderMerge(branches))
            }
        }
        _ => Err(protocol_error("expression.kind")),
    }
}

fn decode_operator(value: &PortableValue) -> Result<OperatorCall, QueryFailure> {
    let fields = exact_object_fields(value, &["id", "version", "arguments"], "operator")?;
    let id = fields[0]
        .as_string()
        .ok_or_else(|| protocol_error("operator.id"))?;
    let version = integer_u32(fields[1], "operator.version")?;
    let entries = fields[2]
        .as_object()
        .ok_or_else(|| protocol_error("operator.arguments"))?;
    let mut operator = OperatorCall::new(id, version);
    for entry in entries {
        operator = operator.with_argument(entry.key(), entry.value().clone());
    }
    Ok(operator)
}

fn exact_object_fields<'a>(
    value: &'a PortableValue,
    names: &[&str],
    context: &str,
) -> Result<Vec<&'a PortableValue>, QueryFailure> {
    let entries = value.as_object().ok_or_else(|| protocol_error(context))?;
    if entries.len() != names.len()
        || entries
            .iter()
            .zip(names)
            .any(|(entry, name)| entry.key() != *name)
    {
        return Err(protocol_error(context));
    }
    Ok(entries.iter().map(crate::ObjectEntry::value).collect())
}

fn integer_u32(value: &PortableValue, name: &str) -> Result<u32, QueryFailure> {
    value
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| protocol_error(name))
}

fn protocol_error(field: &str) -> QueryFailure {
    QueryFailure::InvalidArgument {
        operator: "core.query-definition@1".to_owned(),
        argument: field.to_owned(),
    }
}

/// Definition proven structurally valid for its domain.
#[derive(Clone, Debug)]
pub struct ValidatedQuery {
    definition: QueryDefinition,
    output_role: MatchRole,
    required_capabilities: Vec<CapabilityId>,
}

impl ValidatedQuery {
    /// Final match role.
    #[must_use]
    pub const fn output_role(&self) -> MatchRole {
        self.output_role
    }

    /// Required capability contracts.
    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityId] {
        &self.required_capabilities
    }

    /// Binds the validated definition to implementation capabilities.
    pub fn bind(self, capabilities: &CapabilitySet) -> Result<ExecutableQuery, QueryFailure> {
        for capability in &self.required_capabilities {
            if !capabilities.contains(capability) {
                return Err(QueryFailure::MissingRequiredCapability(capability.clone()));
            }
        }
        Ok(ExecutableQuery { validated: self })
    }
}

/// A fully validated and capability-bound query.
#[derive(Clone, Debug)]
pub struct ExecutableQuery {
    validated: ValidatedQuery,
}

impl ExecutableQuery {
    /// Validated definition.
    #[must_use]
    pub const fn definition(&self) -> &QueryDefinition {
        &self.validated.definition
    }

    /// Final match role.
    #[must_use]
    pub const fn output_role(&self) -> MatchRole {
        self.validated.output_role
    }

    /// Executes against an immutable PortableValue.
    pub fn execute_portable(
        &self,
        target: &PortableValue,
        limits: QueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<QueryExecution<PortableMatch>, QueryFailure> {
        let mut cursor = self.build_portable_cursor(target, limits, cancellation)?;
        let mut matches = Vec::new();
        while let Some(item) = cursor.next_match() {
            matches.push(item?);
        }
        Ok(QueryExecution::completed(matches))
    }

    /// Returns a lazy ordered pull cursor.
    ///
    /// Definition and capability errors still fail before the first match.
    /// Mid-stream failures surface through [`PortableQueryCursor::next_match`]
    /// with a `Failed` terminal; cancellation surfaces `Cancelled`.
    pub fn execute_portable_cursor<'a>(
        &self,
        target: &PortableValue,
        limits: QueryLimits,
        cancellation: &'a CancellationToken,
    ) -> Result<PortableQueryCursor<'a>, QueryFailure> {
        self.build_portable_cursor(target, limits, cancellation)
    }

    fn build_portable_cursor<'a>(
        &self,
        target: &PortableValue,
        limits: QueryLimits,
        cancellation: &'a CancellationToken,
    ) -> Result<PortableQueryCursor<'a>, QueryFailure> {
        if self.definition().domain != QueryDomain::portable_value_v1() {
            return Err(QueryFailure::DomainMismatch(
                self.definition().domain.clone(),
            ));
        }
        let root = PortableMatch::Value {
            path: ValuePath::root(),
            value: target.clone(),
        };
        build_portable_cursor_pipeline(self.definition(), root, limits, cancellation)
    }
}

fn validate_expression(
    domain: &QueryDomain,
    expression: &QueryExpression,
    input_role: MatchRole,
) -> Result<MatchRole, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input_role),
        QueryExpression::Apply { input, operator } => {
            let actual_input = validate_expression(domain, input, input_role)?;
            validate_operator(domain, operator, actual_input)
        }
        QueryExpression::Concat(branches) | QueryExpression::StructureOrderMerge(branches) => {
            let mut output = None;
            for branch in branches {
                let branch_output = validate_expression(domain, branch, input_role)?;
                if output.is_some_and(|expected| expected != branch_output) {
                    return Err(QueryFailure::InvalidOperatorComposition {
                        operator: "composition.concat".to_owned(),
                        expected: output.expect("checked Some"),
                        actual: branch_output,
                    });
                }
                output = Some(branch_output);
            }
            output.ok_or_else(|| QueryFailure::InvalidArgument {
                operator: "composition.concat".to_owned(),
                argument: "branches".to_owned(),
            })
        }
    }
}

fn validate_operator(
    domain: &QueryDomain,
    operator: &OperatorCall,
    input: MatchRole,
) -> Result<MatchRole, QueryFailure> {
    if operator.version != 1 {
        return Err(QueryFailure::UnknownOperator {
            id: operator.id.clone(),
            version: operator.version,
        });
    }
    let (expected, output, arguments): (MatchRole, MatchRole, &[(&str, PortableValueKind)]) =
        match (domain.id(), operator.id()) {
            ("core.portable-value-query", "core.try-object-entries") => {
                (MatchRole::Value, MatchRole::ObjectEntry, &[])
            }
            ("core.portable-value-query", "core.object-entry-value") => {
                (MatchRole::ObjectEntry, MatchRole::Value, &[])
            }
            ("core.portable-value-query", "core.object-entry-name-equals") => (
                MatchRole::ObjectEntry,
                MatchRole::ObjectEntry,
                &[("name", PortableValueKind::String)],
            ),
            ("core.portable-value-query", "core.try-entry-mapping-entries") => {
                (MatchRole::Value, MatchRole::EntryMappingEntry, &[])
            }
            ("core.portable-value-query", "core.entry-key" | "core.entry-value") => {
                (MatchRole::EntryMappingEntry, MatchRole::Value, &[])
            }
            (
                "core.portable-value-query",
                "core.try-sequence-elements" | "core.where-type" | "core.require-type",
            ) => (
                MatchRole::Value,
                MatchRole::Value,
                if matches!(operator.id(), "core.where-type" | "core.require-type") {
                    &[("kind", PortableValueKind::String)]
                } else {
                    &[]
                },
            ),
            ("json.native-semantic-query", "json.try-object-members") => {
                (MatchRole::JsonValue, MatchRole::JsonObjectMember, &[])
            }
            ("json.native-semantic-query", "json.member-name-equals") => (
                MatchRole::JsonObjectMember,
                MatchRole::JsonObjectMember,
                &[("name", PortableValueKind::String)],
            ),
            ("json.native-semantic-query", "json.member-value") => {
                (MatchRole::JsonObjectMember, MatchRole::JsonValue, &[])
            }
            ("json.native-semantic-query", "json.try-array-elements") => {
                (MatchRole::JsonValue, MatchRole::JsonArrayElement, &[])
            }
            ("json.native-semantic-query", "json.array-element-value") => {
                (MatchRole::JsonArrayElement, MatchRole::JsonValue, &[])
            }
            ("toml.native-semantic-query", "toml.try-table-entries") => {
                (MatchRole::TomlItem, MatchRole::TomlEntry, &[])
            }
            ("toml.native-semantic-query", "toml.entry-name-equals") => (
                MatchRole::TomlEntry,
                MatchRole::TomlEntry,
                &[("name", PortableValueKind::String)],
            ),
            ("toml.native-semantic-query", "toml.entry-item") => {
                (MatchRole::TomlEntry, MatchRole::TomlItem, &[])
            }
            ("toml.native-semantic-query", "toml.try-array-elements") => {
                (MatchRole::TomlItem, MatchRole::TomlArrayElement, &[])
            }
            ("toml.native-semantic-query", "toml.array-element-item") => {
                (MatchRole::TomlArrayElement, MatchRole::TomlItem, &[])
            }
            ("yaml.native-semantic-query", "yaml.documents") => {
                (MatchRole::YamlStream, MatchRole::YamlDocument, &[])
            }
            ("yaml.native-semantic-query", "yaml.document-root") => {
                (MatchRole::YamlDocument, MatchRole::YamlNode, &[])
            }
            (
                "yaml.native-semantic-query",
                "yaml.where-node-kind" | "yaml.where-tag" | "yaml.scalar-canonical-equals",
            ) => (
                MatchRole::YamlNode,
                MatchRole::YamlNode,
                &[(
                    (if operator.id() == "yaml.where-node-kind" {
                        "kind"
                    } else if operator.id() == "yaml.where-tag" {
                        "tag"
                    } else {
                        "canonical"
                    }),
                    PortableValueKind::String,
                )],
            ),
            ("yaml.native-semantic-query", "yaml.try-sequence-elements") => {
                (MatchRole::YamlNode, MatchRole::YamlSequenceElement, &[])
            }
            ("yaml.native-semantic-query", "yaml.sequence-element-node") => {
                (MatchRole::YamlSequenceElement, MatchRole::YamlNode, &[])
            }
            ("yaml.native-semantic-query", "yaml.try-mapping-entries") => {
                (MatchRole::YamlNode, MatchRole::YamlMappingEntry, &[])
            }
            (
                "yaml.native-semantic-query",
                "yaml.mapping-entry-key" | "yaml.mapping-entry-value",
            ) => (MatchRole::YamlMappingEntry, MatchRole::YamlNode, &[]),
            ("yaml.native-semantic-query", "yaml.anchor-definition") => {
                (MatchRole::YamlNode, MatchRole::YamlAnchorDefinition, &[])
            }
            ("yaml.native-semantic-query", "yaml.anchor-node") => {
                (MatchRole::YamlAnchorDefinition, MatchRole::YamlNode, &[])
            }
            ("yaml.native-semantic-query", "yaml.alias-occurrences") => {
                (MatchRole::YamlStream, MatchRole::YamlAliasOccurrence, &[])
            }
            ("yaml.native-semantic-query", "yaml.alias-target") => {
                (MatchRole::YamlAliasOccurrence, MatchRole::YamlNode, &[])
            }
            ("ini.native-semantic-query", "ini.document-sections") => {
                (MatchRole::IniDocument, MatchRole::IniSection, &[])
            }
            ("ini.native-semantic-query", "ini.section-entries") => {
                (MatchRole::IniSection, MatchRole::IniEntry, &[])
            }
            ("ini.native-semantic-query", "ini.all-entries") => {
                (MatchRole::IniDocument, MatchRole::IniEntry, &[])
            }
            ("ini.native-semantic-query", "ini.entry-section") => {
                (MatchRole::IniEntry, MatchRole::IniSection, &[])
            }
            ("ini.native-semantic-query", "ini.section-name-equals") => (
                MatchRole::IniSection,
                MatchRole::IniSection,
                &[
                    ("name", PortableValueKind::String),
                    ("comparison", PortableValueKind::String),
                ],
            ),
            ("ini.native-semantic-query", "ini.entry-key-equals") => (
                MatchRole::IniEntry,
                MatchRole::IniEntry,
                &[
                    ("key", PortableValueKind::String),
                    ("comparison", PortableValueKind::String),
                ],
            ),
            ("ini.native-semantic-query", "ini.entry-value-state-is") => (
                MatchRole::IniEntry,
                MatchRole::IniEntry,
                &[("state", PortableValueKind::String)],
            ),
            ("ini.native-semantic-query", "ini.duplicate-group") => {
                if !matches!(input, MatchRole::IniSection | MatchRole::IniEntry) {
                    return Err(QueryFailure::InvalidOperatorComposition {
                        operator: operator.id.clone(),
                        expected: MatchRole::IniSection,
                        actual: input,
                    });
                }
                (input, input, &[])
            }
            ("ini.native-semantic-query", "ini.physical-lines") => {
                (MatchRole::IniDocument, MatchRole::IniPhysicalLine, &[])
            }
            ("ini.native-semantic-query", "ini.logical-lines") => {
                (MatchRole::IniDocument, MatchRole::IniLogicalLine, &[])
            }
            ("json.lossless-syntax-query", "json.syntax-kind-is") => (
                MatchRole::JsonSyntaxPiece,
                MatchRole::JsonSyntaxPiece,
                &[("kind", PortableValueKind::String)],
            ),
            ("json.lossless-syntax-query", "json.syntax-text-equals") => (
                MatchRole::JsonSyntaxPiece,
                MatchRole::JsonSyntaxPiece,
                &[("text", PortableValueKind::String)],
            ),
            ("toml.lossless-syntax-query", "toml.syntax-kind-is") => (
                MatchRole::TomlSyntaxPiece,
                MatchRole::TomlSyntaxPiece,
                &[("kind", PortableValueKind::String)],
            ),
            ("toml.lossless-syntax-query", "toml.syntax-text-equals") => (
                MatchRole::TomlSyntaxPiece,
                MatchRole::TomlSyntaxPiece,
                &[("text", PortableValueKind::String)],
            ),
            ("yaml.lossless-syntax-query", "yaml.syntax-kind-is") => (
                MatchRole::YamlSyntaxPiece,
                MatchRole::YamlSyntaxPiece,
                &[("kind", PortableValueKind::String)],
            ),
            ("yaml.lossless-syntax-query", "yaml.syntax-text-equals") => (
                MatchRole::YamlSyntaxPiece,
                MatchRole::YamlSyntaxPiece,
                &[("text", PortableValueKind::String)],
            ),
            ("ini.lossless-syntax-query", "ini.syntax-kind-is") => (
                MatchRole::IniSyntaxPiece,
                MatchRole::IniSyntaxPiece,
                &[("kind", PortableValueKind::String)],
            ),
            ("ini.lossless-syntax-query", "ini.syntax-text-equals") => (
                MatchRole::IniSyntaxPiece,
                MatchRole::IniSyntaxPiece,
                &[("text", PortableValueKind::String)],
            ),
            ("core.portable-graph-query", "graph.reachable-nodes") => {
                (MatchRole::GraphNode, MatchRole::GraphNode, &[])
            }
            ("core.portable-graph-query", "graph.where-kind") => (
                MatchRole::GraphNode,
                MatchRole::GraphNode,
                &[("kind", PortableValueKind::String)],
            ),
            ("core.portable-graph-query", "graph.where-tag") => (
                MatchRole::GraphNode,
                MatchRole::GraphNode,
                &[("tag", PortableValueKind::String)],
            ),
            ("core.portable-graph-query", "graph.try-sequence-elements") => {
                (MatchRole::GraphNode, MatchRole::GraphSequenceElement, &[])
            }
            ("core.portable-graph-query", "graph.sequence-element-node") => {
                (MatchRole::GraphSequenceElement, MatchRole::GraphNode, &[])
            }
            ("core.portable-graph-query", "graph.try-mapping-entries") => {
                (MatchRole::GraphNode, MatchRole::GraphMappingEntry, &[])
            }
            (
                "core.portable-graph-query",
                "graph.mapping-entry-key" | "graph.mapping-entry-value",
            ) => (MatchRole::GraphMappingEntry, MatchRole::GraphNode, &[]),
            (_, "core.take" | "core.distinct-by-identity") => (
                input,
                input,
                if operator.id() == "core.take" {
                    &[("count", PortableValueKind::Integer)]
                } else {
                    &[]
                },
            ),
            _ => {
                return Err(QueryFailure::UnknownOperator {
                    id: operator.id.clone(),
                    version: operator.version,
                });
            }
        };
    if input != expected {
        return Err(QueryFailure::InvalidOperatorComposition {
            operator: operator.id.clone(),
            expected,
            actual: input,
        });
    }
    if operator.arguments.len() != arguments.len() {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "argument-set".to_owned(),
        });
    }
    for (name, kind) in arguments {
        if operator.arguments.get(*name).map(PortableValue::kind) != Some(*kind) {
            return Err(QueryFailure::WrongArgumentType {
                operator: operator.id.clone(),
                argument: (*name).to_owned(),
                expected: *kind,
            });
        }
    }
    if operator.id == "core.take"
        && operator.arguments["count"]
            .as_integer()
            .and_then(crate::BigInteger::to_usize)
            .is_none()
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "count".to_owned(),
        });
    }
    if matches!(operator.id(), "core.where-type" | "core.require-type") {
        parse_kind(
            operator.arguments["kind"]
                .as_string()
                .expect("validated string"),
        )?;
    }
    if operator.id() == "json.syntax-kind-is"
        && !is_json_syntax_kind(
            domain.version(),
            operator.arguments["kind"]
                .as_string()
                .expect("validated string"),
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if operator.id() == "toml.syntax-kind-is"
        && !is_toml_syntax_kind(
            operator.arguments["kind"]
                .as_string()
                .expect("validated string"),
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if operator.id() == "yaml.syntax-kind-is"
        && !is_yaml_syntax_kind(
            operator.arguments()["kind"]
                .as_string()
                .expect("validated string"),
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if operator.id() == "ini.syntax-kind-is"
        && !is_ini_syntax_kind(
            operator.arguments()["kind"]
                .as_string()
                .expect("validated string"),
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if matches!(
        operator.id(),
        "ini.section-name-equals" | "ini.entry-key-equals"
    ) && !matches!(
        operator.arguments()["comparison"]
            .as_string()
            .expect("validated string"),
        "OriginalExact" | "ProfileEquivalent"
    ) {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "comparison".to_owned(),
        });
    }
    if operator.id() == "ini.entry-value-state-is"
        && !matches!(
            operator.arguments()["state"]
                .as_string()
                .expect("validated string"),
            "Missing" | "Empty" | "Present"
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "state".to_owned(),
        });
    }
    if operator.id() == "yaml.where-node-kind"
        && !matches!(
            operator.arguments()["kind"]
                .as_string()
                .expect("validated string"),
            "Scalar" | "Sequence" | "Mapping"
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if operator.id() == "yaml.where-tag"
        && operator.arguments()["tag"]
            .as_string()
            .expect("validated string")
            .is_empty()
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "tag".to_owned(),
        });
    }
    if operator.id() == "graph.where-kind"
        && !matches!(
            operator.arguments["kind"]
                .as_string()
                .expect("validated string"),
            "Scalar" | "Sequence" | "Mapping"
        )
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "kind".to_owned(),
        });
    }
    if operator.id() == "graph.where-tag"
        && operator.arguments["tag"]
            .as_string()
            .expect("validated string")
            .is_empty()
    {
        return Err(QueryFailure::InvalidArgument {
            operator: operator.id.clone(),
            argument: "tag".to_owned(),
        });
    }
    Ok(output)
}

fn is_json_syntax_kind(domain_version: u32, kind: &str) -> bool {
    matches!(
        kind,
        "Bom"
            | "Whitespace"
            | "LineComment"
            | "BlockComment"
            | "LeftBrace"
            | "RightBrace"
            | "LeftBracket"
            | "RightBracket"
            | "Colon"
            | "Comma"
            | "String"
            | "Number"
            | "True"
            | "False"
            | "Null"
            | "ErrorRegion"
    ) || (domain_version == 2 && kind == "Identifier")
}

fn is_toml_syntax_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Whitespace"
            | "Newline"
            | "Comment"
            | "String"
            | "Bare"
            | "Equals"
            | "LeftBracket"
            | "RightBracket"
            | "LeftBrace"
            | "RightBrace"
            | "Comma"
            | "Dot"
    )
}

fn is_yaml_syntax_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Bom"
            | "Whitespace"
            | "Newline"
            | "Comment"
            | "Directive"
            | "DocumentStart"
            | "DocumentEnd"
            | "FlowSequenceStart"
            | "FlowSequenceEnd"
            | "FlowMappingStart"
            | "FlowMappingEnd"
            | "FlowEntry"
            | "SequenceEntry"
            | "ExplicitKey"
            | "MappingValue"
            | "Anchor"
            | "Alias"
            | "Tag"
            | "PlainScalar"
            | "SingleQuotedScalar"
            | "DoubleQuotedScalar"
            | "LiteralBlockHeader"
            | "FoldedBlockHeader"
            | "BlockScalarContent"
            | "ErrorRegion"
    )
}

fn is_ini_syntax_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Bom"
            | "Whitespace"
            | "LineBreak"
            | "CommentMarker"
            | "CommentText"
            | "SectionOpen"
            | "SectionName"
            | "SectionClose"
            | "EntryKey"
            | "Delimiter"
            | "Quote"
            | "EntryValue"
            | "ContinuationMarker"
            | "ErrorRegion"
    )
}

fn parse_kind(text: &str) -> Result<PortableValueKind, QueryFailure> {
    match text {
        "Null" => Ok(PortableValueKind::Null),
        "Boolean" => Ok(PortableValueKind::Boolean),
        "Integer" => Ok(PortableValueKind::Integer),
        "Decimal" => Ok(PortableValueKind::Decimal),
        "BinaryFloat32" => Ok(PortableValueKind::BinaryFloat32),
        "BinaryFloat64" => Ok(PortableValueKind::BinaryFloat64),
        "String" => Ok(PortableValueKind::String),
        "Bytes" => Ok(PortableValueKind::Bytes),
        "Date" => Ok(PortableValueKind::Date),
        "Time" => Ok(PortableValueKind::Time),
        "LocalDateTime" => Ok(PortableValueKind::LocalDateTime),
        "OffsetDateTime" => Ok(PortableValueKind::OffsetDateTime),
        "Sequence" => Ok(PortableValueKind::Sequence),
        "Object" => Ok(PortableValueKind::Object),
        "EntryMapping" => Ok(PortableValueKind::EntryMapping),
        _ => Err(QueryFailure::InvalidArgument {
            operator: "value-kind".to_owned(),
            argument: text.to_owned(),
        }),
    }
}

/// Portable query match preserving path or association identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableMatch {
    /// A value match.
    Value {
        /// Root-relative value path.
        path: ValuePath,
        /// Observed immutable value.
        value: PortableValue,
    },
    /// An Object association.
    ObjectEntry {
        /// Association location, separate from the value path.
        location: AssociationLocation,
        /// Unique object key.
        key: String,
        /// Path of the entry value.
        value_path: ValuePath,
        /// Observed entry value.
        value: PortableValue,
    },
    /// An EntryMapping association.
    EntryMappingEntry {
        /// Association location.
        location: AssociationLocation,
        /// Path of the key value.
        key_path: ValuePath,
        /// Observed key value.
        key: PortableValue,
        /// Path of the associated value.
        value_path: ValuePath,
        /// Observed associated value.
        value: PortableValue,
    },
}

impl PortableMatch {
    fn identity(&self) -> PortableIdentity {
        match self {
            Self::Value { path, .. } => PortableIdentity::Value(path.clone()),
            Self::ObjectEntry { location, .. } | Self::EntryMappingEntry { location, .. } => {
                PortableIdentity::Association(location.clone())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum PortableIdentity {
    Value(ValuePath),
    Association(AssociationLocation),
}

struct LazyContext<'a> {
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
}

impl LazyContext<'_> {
    fn step(&mut self) -> Result<(), QueryFailure> {
        if self.cancellation.is_cancelled() {
            return Err(QueryFailure::Cancelled);
        }
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }
}

/// One pull step of the lazy ordered execution.
trait Producer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure>;
}

struct InputProducer {
    root: Option<PortableMatch>,
}

impl Producer for InputProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        context.step()?;
        Ok(self.root.take())
    }
}

struct VecProducer {
    items: std::vec::IntoIter<PortableMatch>,
}

impl VecProducer {
    fn new(items: Vec<PortableMatch>) -> Self {
        Self {
            items: items.into_iter(),
        }
    }
}

impl Producer for VecProducer {
    fn next(
        &mut self,
        _context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        Ok(self.items.next())
    }
}

fn materialize(
    producer: &mut Box<dyn Producer>,
    context: &mut LazyContext<'_>,
) -> Result<Vec<PortableMatch>, QueryFailure> {
    let mut values = Vec::new();
    while let Some(item) = producer.next(context)? {
        values.push(item);
        if values.len() > context.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
    }
    Ok(values)
}

fn build_producer(
    expression: &QueryExpression,
    input: Box<dyn Producer>,
    context: &mut LazyContext<'_>,
) -> Result<Box<dyn Producer>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input),
        QueryExpression::Apply {
            input: inner,
            operator,
        } => Ok(Box::new(ApplyProducer::new(
            build_producer(inner, input, context)?,
            operator.clone(),
        ))),
        QueryExpression::Concat(branches) | QueryExpression::StructureOrderMerge(branches) => {
            let mut input = input;
            let input_values = materialize(&mut input, context)?;
            let cloned_inputs = input_values
                .len()
                .checked_mul(branches.len())
                .ok_or(QueryFailure::ResourceLimitExceeded)?;
            if cloned_inputs > context.limits.max_results {
                return Err(QueryFailure::ResourceLimitExceeded);
            }
            let mut producers = Vec::with_capacity(branches.len());
            for branch in branches {
                context.step()?;
                producers.push(build_producer(
                    branch,
                    Box::new(VecProducer::new(input_values.clone())),
                    context,
                )?);
            }
            if matches!(expression, QueryExpression::Concat(_)) {
                Ok(Box::new(ConcatProducer::new(producers)))
            } else {
                Ok(Box::new(MergeProducer::new(producers)))
            }
        }
    }
}

struct ApplyProducer {
    input: Box<dyn Producer>,
    operator: OperatorCall,
    pending: Option<std::vec::IntoIter<PortableMatch>>,
    seen: Option<HashSet<PortableIdentity>>,
    remaining: Option<usize>,
    results: usize,
    done: bool,
}

impl ApplyProducer {
    fn new(input: Box<dyn Producer>, operator: OperatorCall) -> Self {
        Self {
            input,
            operator,
            pending: None,
            seen: None,
            remaining: None,
            results: 0,
            done: false,
        }
    }

    fn count(&mut self, context: &LazyContext<'_>) -> Result<(), QueryFailure> {
        self.results = self.results.saturating_add(1);
        if self.results > context.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }
}

impl Producer for ApplyProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        loop {
            if self.done {
                return Ok(None);
            }
            if let Some(iter) = &mut self.pending {
                if let Some(item) = iter.next() {
                    self.count(context)?;
                    return Ok(Some(item));
                }
            }
            self.pending = None;
            let Some(item) = self.input.next(context)? else {
                self.done = true;
                return Ok(None);
            };
            context.step()?;
            match self.operator.id() {
                "core.take" => {
                    let count = self.remaining.get_or_insert_with(|| {
                        self.operator.arguments()["count"]
                            .as_integer()
                            .and_then(crate::BigInteger::to_usize)
                            .expect("query validation checked count")
                    });
                    if *count == 0 {
                        self.done = true;
                        return Ok(None);
                    }
                    *count -= 1;
                    self.count(context)?;
                    return Ok(Some(item));
                }
                "core.distinct-by-identity" => {
                    let seen = self.seen.get_or_insert_with(HashSet::new);
                    if seen.insert(item.identity()) {
                        self.count(context)?;
                        return Ok(Some(item));
                    }
                }
                _ => {
                    let output = apply_portable_operator_items(
                        &self.operator,
                        vec![item],
                        context.limits.max_results,
                    )?;
                    if !output.is_empty() {
                        self.pending = Some(output.into_iter());
                    }
                }
            }
        }
    }
}

struct ConcatProducer {
    producers: Vec<Box<dyn Producer>>,
    index: usize,
}

impl ConcatProducer {
    fn new(producers: Vec<Box<dyn Producer>>) -> Self {
        Self {
            producers,
            index: 0,
        }
    }
}

impl Producer for ConcatProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        loop {
            if self.index >= self.producers.len() {
                return Ok(None);
            }
            if let Some(item) = self.producers[self.index].next(context)? {
                return Ok(Some(item));
            }
            self.index += 1;
            context.step()?;
        }
    }
}

struct MergeProducer {
    producers: Vec<Box<dyn Producer>>,
    remaining: Option<std::vec::IntoIter<PortableMatch>>,
}

impl MergeProducer {
    fn new(producers: Vec<Box<dyn Producer>>) -> Self {
        Self {
            producers,
            remaining: None,
        }
    }
}

impl Producer for MergeProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        if let Some(remaining) = &mut self.remaining {
            return Ok(remaining.next());
        }
        let mut merged = Vec::new();
        for producer in &mut self.producers {
            merged.extend(materialize(producer, context)?);
            if merged.len() > context.limits.max_results {
                return Err(QueryFailure::ResourceLimitExceeded);
            }
        }
        merged.sort_by_key(PortableMatch::identity);
        self.remaining = Some(merged.into_iter());
        Ok(self.remaining.as_mut().expect("just set").next())
    }
}

fn selection_producer(selection: QuerySelection, child: Box<dyn Producer>) -> Box<dyn Producer> {
    match selection {
        QuerySelection::All => child,
        QuerySelection::First => Box::new(FirstProducer { child, done: false }),
        QuerySelection::Last => Box::new(LastProducer {
            child,
            state: LastState::Buffering,
            buffer: Vec::new(),
        }),
        QuerySelection::ZeroOrOne => Box::new(ZeroOrOneProducer { child, count: 0 }),
        QuerySelection::RequireOne => Box::new(RequireOneProducer {
            child,
            count: 0,
            buffer: Vec::new(),
            yielded: false,
        }),
    }
}

struct FirstProducer {
    child: Box<dyn Producer>,
    done: bool,
}

impl Producer for FirstProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        self.child.next(context)
    }
}

enum LastState {
    Buffering,
    Yielding(std::vec::IntoIter<PortableMatch>),
}

struct LastProducer {
    child: Box<dyn Producer>,
    state: LastState,
    buffer: Vec<PortableMatch>,
}

impl Producer for LastProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        loop {
            if let LastState::Yielding(iter) = &mut self.state {
                return Ok(iter.next());
            }
            if let Some(item) = self.child.next(context)? {
                self.buffer = vec![item];
                continue;
            }
            let iter = std::mem::take(&mut self.buffer).into_iter();
            self.state = LastState::Yielding(iter);
        }
    }
}

struct ZeroOrOneProducer {
    child: Box<dyn Producer>,
    count: usize,
}

impl Producer for ZeroOrOneProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        let Some(item) = self.child.next(context)? else {
            return Ok(None);
        };
        if self.count == 1 {
            return Err(QueryFailure::CardinalityViolation {
                selection: QuerySelection::ZeroOrOne,
                actual: 2,
            });
        }
        self.count += 1;
        Ok(Some(item))
    }
}

struct RequireOneProducer {
    child: Box<dyn Producer>,
    count: usize,
    buffer: Vec<PortableMatch>,
    yielded: bool,
}

impl Producer for RequireOneProducer {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        if self.yielded {
            return Ok(None);
        }
        loop {
            if let Some(item) = self.child.next(context)? {
                self.count += 1;
                if self.count > 1 {
                    return Err(QueryFailure::CardinalityViolation {
                        selection: QuerySelection::RequireOne,
                        actual: 2,
                    });
                }
                self.buffer.push(item);
            } else {
                if self.count == 0 {
                    return Err(QueryFailure::CardinalityViolation {
                        selection: QuerySelection::RequireOne,
                        actual: 0,
                    });
                }
                self.yielded = true;
                return Ok(self.buffer.pop());
            }
        }
    }
}

/// Root result accounting: the root is the first standard result and may not
/// bypass `max_results`; every later yielded result is counted the same way.
struct RootCounter {
    child: Box<dyn Producer>,
    limits: QueryLimits,
    root_checked: bool,
    count: usize,
}

impl Producer for RootCounter {
    fn next(
        &mut self,
        context: &mut LazyContext<'_>,
    ) -> Result<Option<PortableMatch>, QueryFailure> {
        if !self.root_checked {
            self.root_checked = true;
            if 1 > self.limits.max_results {
                return Err(QueryFailure::ResourceLimitExceeded);
            }
        }
        let Some(item) = self.child.next(context)? else {
            return Ok(None);
        };
        self.count = self.count.saturating_add(1);
        if self.count > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(Some(item))
    }
}

fn apply_portable_operator_items(
    operator: &OperatorCall,
    input: Vec<PortableMatch>,
    max_results: usize,
) -> Result<Vec<PortableMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "core.try-object-entries" => {
            for item in input {
                if let PortableMatch::Value { path, value } = item {
                    if let Some(entries) = value.as_object() {
                        for (ordinal, entry) in entries
                            .iter()
                            .take(max_results.saturating_add(1))
                            .enumerate()
                        {
                            let value_path =
                                path.child(ValuePathSegment::ObjectValue(entry.key().to_owned()));
                            output.push(PortableMatch::ObjectEntry {
                                location: AssociationLocation::new(
                                    path.clone(),
                                    ordinal as u64,
                                    AssociationRole::ObjectEntry,
                                ),
                                key: entry.key().to_owned(),
                                value_path,
                                value: entry.value().clone(),
                            });
                        }
                    }
                }
            }
        }
        "core.object-entry-name-equals" => {
            let name = operator.arguments["name"]
                .as_string()
                .expect("query validation checked name");
            output.extend(input.into_iter().filter(
                |item| matches!(item, PortableMatch::ObjectEntry { key, .. } if key == name),
            ));
        }
        "core.object-entry-value" => {
            for item in input {
                if let PortableMatch::ObjectEntry {
                    value_path, value, ..
                } = item
                {
                    output.push(PortableMatch::Value {
                        path: value_path,
                        value,
                    });
                }
            }
        }
        "core.try-entry-mapping-entries" => {
            for item in input {
                if let PortableMatch::Value { path, value } = item {
                    if let Some(entries) = value.as_entry_mapping() {
                        for (ordinal, entry) in entries
                            .iter()
                            .take(max_results.saturating_add(1))
                            .enumerate()
                        {
                            output.push(PortableMatch::EntryMappingEntry {
                                location: AssociationLocation::new(
                                    path.clone(),
                                    ordinal as u64,
                                    AssociationRole::EntryMappingEntry,
                                ),
                                key_path: path.child(ValuePathSegment::EntryKey(ordinal as u64)),
                                key: entry.key().clone(),
                                value_path: path
                                    .child(ValuePathSegment::EntryValue(ordinal as u64)),
                                value: entry.value().clone(),
                            });
                        }
                    }
                }
            }
        }
        "core.entry-key" => {
            for item in input {
                if let PortableMatch::EntryMappingEntry { key_path, key, .. } = item {
                    output.push(PortableMatch::Value {
                        path: key_path,
                        value: key,
                    });
                }
            }
        }
        "core.entry-value" => {
            for item in input {
                if let PortableMatch::EntryMappingEntry {
                    value_path, value, ..
                } = item
                {
                    output.push(PortableMatch::Value {
                        path: value_path,
                        value,
                    });
                }
            }
        }
        "core.try-sequence-elements" => {
            for item in input {
                if let PortableMatch::Value { path, value } = item {
                    if let Some(elements) = value.as_sequence() {
                        for (index, element) in elements
                            .iter()
                            .take(max_results.saturating_add(1))
                            .enumerate()
                        {
                            output.push(PortableMatch::Value {
                                path: path.child(ValuePathSegment::SequenceElement(index as u64)),
                                value: element.clone(),
                            });
                        }
                    }
                }
            }
        }
        "core.where-type" | "core.require-type" => {
            let expected = parse_kind(
                operator.arguments["kind"]
                    .as_string()
                    .expect("query validation checked kind"),
            )?;
            let require = operator.id() == "core.require-type";
            for item in input {
                let PortableMatch::Value { value, .. } = &item else {
                    unreachable!("role validation guarantees Value input")
                };
                if value.kind() == expected {
                    output.push(item);
                } else if require {
                    return Err(QueryFailure::RequiredTypeMismatch {
                        expected,
                        actual: value.kind(),
                    });
                }
            }
        }
        "core.take" => {
            let count = operator.arguments["count"]
                .as_integer()
                .and_then(crate::BigInteger::to_usize)
                .expect("query validation checked count");
            output.extend(input.into_iter().take(count));
        }
        "core.distinct-by-identity" => {
            let mut seen = HashSet::new();
            for item in input {
                if seen.insert(item.identity()) {
                    output.push(item);
                }
            }
        }
        _ => unreachable!("validated portable operator"),
    }
    Ok(output)
}

/// Lazy pull cursor over a validated portable-value query.
///
/// The stream terminates with `Completed` only after every standard result
/// was yielded, `Cancelled` when the token is cancelled before the stream is
/// exhausted, and `Failed` when a resource limit or runtime error stops the
/// stream. Matches yielded before a failure remain real local discoveries.
pub struct PortableQueryCursor<'a> {
    root: Box<dyn Producer>,
    context: LazyContext<'a>,
    terminal: Option<QueryTerminalState>,
}

impl<'a> PortableQueryCursor<'a> {
    fn new(
        root: Box<dyn Producer>,
        limits: QueryLimits,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            root,
            context: LazyContext {
                limits,
                cancellation,
                steps: 0,
            },
            terminal: None,
        }
    }

    /// Pulls the next match; `Ok(None)` means the stream completed.
    pub fn next_match(&mut self) -> Option<Result<PortableMatch, QueryFailure>> {
        if self.terminal.is_some() {
            return None;
        }
        if self.context.cancellation.is_cancelled() {
            self.terminal = Some(QueryTerminalState::Cancelled);
            return Some(Err(QueryFailure::Cancelled));
        }
        match self.root.next(&mut self.context) {
            Ok(Some(item)) => Some(Ok(item)),
            Ok(None) => {
                self.terminal = Some(QueryTerminalState::Completed);
                None
            }
            Err(failure) => {
                self.terminal = Some(if matches!(failure, QueryFailure::Cancelled) {
                    QueryTerminalState::Cancelled
                } else {
                    QueryTerminalState::Failed
                });
                Some(Err(failure))
            }
        }
    }

    /// Terminal state; `None` while the stream is still open.
    #[must_use]
    pub const fn terminal_state(&self) -> Option<QueryTerminalState> {
        self.terminal
    }
}

impl std::fmt::Debug for PortableQueryCursor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortableQueryCursor")
            .field("steps", &self.context.steps)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

fn build_portable_cursor_pipeline<'a>(
    definition: &QueryDefinition,
    root: PortableMatch,
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
) -> Result<PortableQueryCursor<'a>, QueryFailure> {
    let mut context = LazyContext {
        limits,
        cancellation,
        steps: 0,
    };
    let input = Box::new(InputProducer { root: Some(root) });
    let expression = build_producer(definition.expression(), input, &mut context)?;
    let expression = selection_producer(definition.selection(), expression);
    let expression = Box::new(RootCounter {
        child: expression,
        limits,
        root_checked: false,
        count: 0,
    });
    Ok(PortableQueryCursor::new(expression, limits, cancellation))
}

impl Iterator for PortableQueryCursor<'_> {
    type Item = Result<PortableMatch, QueryFailure>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_match()
    }
}
/// Immutable query execution limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryLimits {
    /// Maximum operator steps.
    pub max_steps: usize,
    /// Maximum complete results buffered by an operator.
    pub max_results: usize,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_steps: 100_000,
            max_results: 100_000,
        }
    }
}

/// Cooperative cancellation signal.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates a non-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Tests cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Complete materialized query result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryExecution<T> {
    matches: Vec<T>,
    terminal: QueryTerminalState,
}

impl<T> QueryExecution<T> {
    /// Complete ordered matches.
    #[must_use]
    pub fn matches(&self) -> &[T] {
        &self.matches
    }

    /// Explicit terminal state.
    #[must_use]
    pub const fn terminal_state(&self) -> QueryTerminalState {
        self.terminal
    }

    /// Creates a complete execution for another domain implementation.
    #[must_use]
    pub fn completed(matches: Vec<T>) -> Self {
        Self {
            matches,
            terminal: QueryTerminalState::Completed,
        }
    }
}

/// Ordered cursor terminal state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QueryTerminalState {
    /// The entire standard sequence was produced.
    Completed,
    /// Execution was cancelled.
    Cancelled,
    /// Execution failed after zero or more local discoveries.
    Failed,
}

/// Ordered cursor over already validated execution output.
#[derive(Debug)]
pub struct OrderedQueryCursor<T> {
    remaining: std::vec::IntoIter<T>,
    declared_terminal: QueryTerminalState,
    terminal: Option<QueryTerminalState>,
    cancellation: Option<CancellationToken>,
}

impl<T> OrderedQueryCursor<T> {
    /// Creates a cursor over a complete standard-order result.
    #[must_use]
    pub fn new(values: Vec<T>) -> Self {
        Self::with_terminal(values, QueryTerminalState::Completed)
    }

    /// Creates a cursor with an explicit terminal state that remains hidden until exhaustion.
    #[must_use]
    pub fn with_terminal(values: Vec<T>, terminal: QueryTerminalState) -> Self {
        Self {
            remaining: values.into_iter(),
            declared_terminal: terminal,
            terminal: None,
            cancellation: None,
        }
    }

    /// Creates a cursor that stops with `Cancelled` when the token is set.
    #[must_use]
    pub fn with_cancellation(values: Vec<T>, cancellation: &CancellationToken) -> Self {
        Self {
            remaining: values.into_iter(),
            declared_terminal: QueryTerminalState::Completed,
            terminal: None,
            cancellation: Some(cancellation.clone()),
        }
    }

    /// Terminal state; `None` while the cursor is still open.
    #[must_use]
    pub const fn terminal_state(&self) -> Option<QueryTerminalState> {
        self.terminal
    }
}

impl<T> Iterator for OrderedQueryCursor<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.terminal = Some(QueryTerminalState::Cancelled);
            return None;
        }
        let next = self.remaining.next();
        if next.is_none() {
            self.terminal = Some(self.declared_terminal);
        }
        next
    }
}

/// Stable query definition or execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryFailure {
    /// Domain ID or version is unavailable or mismatched.
    DomainMismatch(QueryDomain),
    /// Operator ID/version is unknown.
    UnknownOperator {
        /// Operator ID.
        id: String,
        /// Operator version.
        version: u32,
    },
    /// An argument has the wrong value kind.
    WrongArgumentType {
        /// Operator ID.
        operator: String,
        /// Argument name.
        argument: String,
        /// Required value kind.
        expected: PortableValueKind,
    },
    /// An argument is malformed or missing.
    InvalidArgument {
        /// Operator ID.
        operator: String,
        /// Argument name or value.
        argument: String,
    },
    /// Operator role composition is invalid.
    InvalidOperatorComposition {
        /// Operator ID.
        operator: String,
        /// Required input role.
        expected: MatchRole,
        /// Actual input role.
        actual: MatchRole,
    },
    /// Capability binding failed.
    MissingRequiredCapability(CapabilityId),
    /// `RequireType` observed another type.
    RequiredTypeMismatch {
        /// Required kind.
        expected: PortableValueKind,
        /// Actual kind.
        actual: PortableValueKind,
    },
    /// Cardinality selector rejected the final result count.
    CardinalityViolation {
        /// Selector.
        selection: QuerySelection,
        /// Actual count.
        actual: usize,
    },
    /// A declared resource limit was reached; no complete result exists.
    ResourceLimitExceeded,
    /// Execution was cancelled; no complete result exists.
    Cancelled,
    /// Target semantics were unavailable.
    TargetUnavailable,
}

impl crate::StableFailure for QueryFailure {
    fn operation_kind(&self) -> crate::OperationKind {
        match self {
            Self::DomainMismatch(_)
            | Self::UnknownOperator { .. }
            | Self::WrongArgumentType { .. }
            | Self::InvalidArgument { .. }
            | Self::InvalidOperatorComposition { .. } => crate::OperationKind::QueryValidation,
            Self::MissingRequiredCapability(_)
            | Self::RequiredTypeMismatch { .. }
            | Self::CardinalityViolation { .. }
            | Self::ResourceLimitExceeded
            | Self::Cancelled
            | Self::TargetUnavailable => crate::OperationKind::QueryExecution,
        }
    }

    fn failure_kind(&self) -> crate::FailureKind {
        match self {
            Self::DomainMismatch(_)
            | Self::UnknownOperator { .. }
            | Self::WrongArgumentType { .. }
            | Self::InvalidArgument { .. }
            | Self::InvalidOperatorComposition { .. }
            | Self::RequiredTypeMismatch { .. }
            | Self::CardinalityViolation { .. }
            | Self::TargetUnavailable => crate::FailureKind::InvalidInput,
            Self::MissingRequiredCapability(_) => crate::FailureKind::Unsupported,
            Self::ResourceLimitExceeded => crate::FailureKind::ResourceLimited,
            Self::Cancelled => crate::FailureKind::Cancelled,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::DomainMismatch(_) => "core.query.domain-mismatch@1",
            Self::UnknownOperator { .. } => "core.query.unknown-operator@1",
            Self::WrongArgumentType { .. } => "core.query.wrong-argument-type@1",
            Self::InvalidArgument { .. } => "core.query.invalid-argument@1",
            Self::InvalidOperatorComposition { .. } => "core.query.invalid-composition@1",
            Self::MissingRequiredCapability(_) => "core.query.missing-capability@1",
            Self::RequiredTypeMismatch { .. } => "core.query.required-type-mismatch@1",
            Self::CardinalityViolation { .. } => "core.query.cardinality-violation@1",
            Self::ResourceLimitExceeded => "core.query.resource-limit@1",
            Self::Cancelled => "core.query.cancelled@1",
            Self::TargetUnavailable => "core.query.target-unavailable@1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BigInteger, ObjectBuilder, SequenceBuilder};

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
    }

    #[test]
    fn cursor_and_materialized_execution_share_identity_and_order() {
        let mut object = ObjectBuilder::new();
        object
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        object
            .insert("b", PortableValue::integer(BigInteger::from(2_i64)))
            .unwrap();
        let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(
                QueryExpression::Input
                    .then(OperatorCall::new("core.try-object-entries", 1))
                    .then(OperatorCall::new("core.object-entry-value", 1)),
            )
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let target = object.build();
        let materialized = executable
            .execute_portable(&target, QueryLimits::default(), &CancellationToken::new())
            .unwrap();
        let cancellation = CancellationToken::new();
        let mut cursor = executable
            .execute_portable_cursor(&target, QueryLimits::default(), &cancellation)
            .unwrap();
        let mut from_cursor = Vec::new();
        while let Some(item) = cursor.next_match() {
            from_cursor.push(item.unwrap());
        }
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Completed));
        assert_eq!(materialized.matches().to_vec(), from_cursor);
    }

    #[test]
    fn cursor_cancellation_stops_stream_with_cancelled_terminal() {
        let mut sequence = SequenceBuilder::new();
        for value in [1, 2, 3] {
            sequence.push(PortableValue::integer(BigInteger::from(value)));
        }
        let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(
                QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
            )
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let token = CancellationToken::new();
        let mut cursor = executable
            .execute_portable_cursor(&sequence.build(), QueryLimits::default(), &token)
            .unwrap();
        assert!(cursor.next_match().is_some());
        token.cancel();
        assert!(matches!(
            cursor.next_match(),
            Some(Err(QueryFailure::Cancelled))
        ));
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Cancelled));
        assert_eq!(cursor.next_match(), None);
    }

    #[test]
    fn cursor_reports_resource_failure_with_failed_terminal() {
        let mut sequence = SequenceBuilder::new();
        for value in [1, 2, 3, 4, 5] {
            sequence.push(PortableValue::integer(BigInteger::from(value)));
        }
        let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(
                QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
            )
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let limits = QueryLimits {
            max_results: 3,
            ..QueryLimits::default()
        };
        let cancellation = CancellationToken::new();
        let mut cursor = executable
            .execute_portable_cursor(&sequence.build(), limits, &cancellation)
            .unwrap();
        let mut yielded = 0;
        while let Some(item) = cursor.next_match() {
            match item {
                Ok(_) => yielded += 1,
                Err(QueryFailure::ResourceLimitExceeded) => {
                    assert_eq!(yielded, 3);
                    assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Failed));
                    return;
                }
                Err(other) => panic!("unexpected failure: {other:?}"),
            }
        }
        panic!("stream should have failed");
    }

    #[test]
    fn cursor_require_one_enforces_cardinality_at_exhaustion() {
        let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(QueryExpression::Input)
            .with_selection(QuerySelection::RequireOne)
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let cancellation = CancellationToken::new();
        let mut cursor = executable
            .execute_portable_cursor(
                &PortableValue::null(),
                QueryLimits::default(),
                &cancellation,
            )
            .unwrap();
        assert!(matches!(
            cursor.next_match(),
            Some(Ok(PortableMatch::Value { .. }))
        ));
        assert_eq!(cursor.next_match(), None);
        assert_eq!(cursor.terminal_state(), Some(QueryTerminalState::Completed));
    }

    #[test]
    fn stable_failure_metadata_is_language_neutral() {
        use crate::{FailureKind, OperationKind, StableFailure};
        assert_eq!(
            QueryFailure::ResourceLimitExceeded.operation_kind(),
            OperationKind::QueryExecution
        );
        assert_eq!(
            QueryFailure::ResourceLimitExceeded.failure_kind(),
            FailureKind::ResourceLimited
        );
        assert_eq!(
            QueryFailure::DomainMismatch(QueryDomain::new("unknown", 1)).diagnostic_code(),
            "core.query.domain-mismatch@1"
        );
        assert_eq!(
            QueryFailure::Cancelled.failure_kind(),
            FailureKind::Cancelled
        );
    }

    #[test]
    fn builder_produces_the_same_immutable_definition() {
        let fluent = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(
                QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
            )
            .with_selection(QuerySelection::First);
        let mut builder = QueryDefinitionBuilder::new(QueryDomain::portable_value_v1());
        builder.expression(
            QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
        );
        builder.selection(QuerySelection::First);
        let built = builder.build();
        assert_eq!(built, fluent);
        assert_eq!(
            QueryDefinition::from_protocol_value(&built.to_protocol_value().unwrap()).unwrap(),
            built
        );
    }

    #[test]
    fn operator_free_root_result_obeys_max_results() {
        let executable = QueryDefinition::new(QueryDomain::portable_value_v1())
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let limits = QueryLimits {
            max_results: 0,
            ..QueryLimits::default()
        };
        assert!(matches!(
            executable.execute_portable(&PortableValue::null(), limits, &CancellationToken::new()),
            Err(QueryFailure::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn invalid_role_composition_is_rejected_before_execution() {
        let definition = QueryDefinition::new(QueryDomain::portable_value_v1()).with_expression(
            QueryExpression::Input.then(OperatorCall::new("core.object-entry-value", 1)),
        );
        assert!(matches!(
            definition.validate(),
            Err(QueryFailure::InvalidOperatorComposition { .. })
        ));
    }

    #[test]
    fn duplicate_value_results_keep_object_order() {
        let mut object = ObjectBuilder::new();
        object
            .insert("b", PortableValue::integer(BigInteger::from(2_i64)))
            .unwrap();
        object
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        let definition = QueryDefinition::new(QueryDomain::portable_value_v1()).with_expression(
            QueryExpression::Input
                .then(OperatorCall::new("core.try-object-entries", 1))
                .then(OperatorCall::new("core.object-entry-value", 1)),
        );
        let executable = definition
            .validate()
            .unwrap()
            .bind(&capabilities())
            .unwrap();
        let result = executable
            .execute_portable(
                &object.build(),
                QueryLimits::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        let paths: Vec<_> = result
            .matches()
            .iter()
            .map(|item| match item {
                PortableMatch::Value { path, .. } => path.clone(),
                _ => panic!("unexpected role"),
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                ValuePath::root().child(ValuePathSegment::ObjectValue("b".to_owned())),
                ValuePath::root().child(ValuePathSegment::ObjectValue("a".to_owned()))
            ]
        );
    }

    #[test]
    fn protocol_schema_round_trips_and_rejects_unknown_fields() {
        let definition = QueryDefinition::new(QueryDomain::portable_value_v1())
            .with_expression(
                QueryExpression::Input.then(OperatorCall::new("core.try-sequence-elements", 1)),
            )
            .with_selection(QuerySelection::First);
        let encoded = definition.to_protocol_value().unwrap();
        assert_eq!(
            QueryDefinition::from_protocol_value(&encoded).unwrap(),
            definition
        );

        let mut invalid = ObjectBuilder::new();
        for entry in encoded.as_object().unwrap() {
            invalid.insert(entry.key(), entry.value().clone()).unwrap();
        }
        invalid.insert("unknown", PortableValue::null()).unwrap();
        assert!(QueryDefinition::from_protocol_value(&invalid.build()).is_err());
    }

    #[test]
    fn syntax_kind_names_are_validated_before_binding() {
        let definition = QueryDefinition::new(QueryDomain::json_lossless_syntax_v1())
            .with_expression(
                QueryExpression::Input.then(
                    OperatorCall::new("json.syntax-kind-is", 1)
                        .with_argument("kind", PortableValue::string("NotAJsonKind")),
                ),
            );
        assert!(matches!(
            definition.validate(),
            Err(QueryFailure::InvalidArgument { argument, .. }) if argument == "kind"
        ));

        let identifier_filter = |domain| {
            QueryDefinition::new(domain).with_expression(
                QueryExpression::Input.then(
                    OperatorCall::new("json.syntax-kind-is", 1)
                        .with_argument("kind", PortableValue::string("Identifier")),
                ),
            )
        };
        assert!(matches!(
            identifier_filter(QueryDomain::json_lossless_syntax_v1()).validate(),
            Err(QueryFailure::InvalidArgument { argument, .. }) if argument == "kind"
        ));
        identifier_filter(QueryDomain::json_lossless_syntax_v2())
            .validate()
            .unwrap();

        QueryDefinition::new(QueryDomain::toml_lossless_syntax_v1())
            .with_expression(
                QueryExpression::Input.then(
                    OperatorCall::new("toml.syntax-kind-is", 1)
                        .with_argument("kind", PortableValue::string("Newline")),
                ),
            )
            .validate()
            .unwrap();
    }

    #[test]
    fn cursor_declared_terminal_is_hidden_until_exhaustion() {
        for terminal in [
            QueryTerminalState::Completed,
            QueryTerminalState::Cancelled,
            QueryTerminalState::Failed,
        ] {
            let mut cursor = OrderedQueryCursor::with_terminal(vec![1, 2], terminal);
            assert_eq!(cursor.terminal_state(), None);
            assert_eq!(cursor.next(), Some(1));
            assert_eq!(cursor.terminal_state(), None);
            assert_eq!(cursor.next(), Some(2));
            assert_eq!(cursor.terminal_state(), None);
            assert_eq!(cursor.next(), None);
            assert_eq!(cursor.terminal_state(), Some(terminal));
            assert_eq!(cursor.next(), None);
            assert_eq!(cursor.terminal_state(), Some(terminal));
        }
    }
}
