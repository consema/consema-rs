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

    /// `json.native-semantic-query@1`.
    #[must_use]
    pub fn json_native_v1() -> Self {
        Self::new("json.native-semantic-query", 1)
    }

    /// `toml.native-semantic-query@1`.
    #[must_use]
    pub fn toml_native_v1() -> Self {
        Self::new("toml.native-semantic-query", 1)
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
            ("json.native-semantic-query", 1) => MatchRole::JsonValue,
            ("toml.native-semantic-query", 1) => MatchRole::TomlItem,
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
        if self.definition().domain != QueryDomain::portable_value_v1() {
            return Err(QueryFailure::DomainMismatch(
                self.definition().domain.clone(),
            ));
        }
        let mut context = PortableExecutionContext {
            limits,
            cancellation,
            steps: 0,
        };
        // The root is the first standard result; it must not bypass result limits.
        context.step(1)?;
        let root = PortableMatch::Value {
            path: ValuePath::root(),
            value: target.clone(),
        };
        let matches = execute_expression(self.definition().expression(), &[root], &mut context)?;
        let matches = apply_selection(matches, self.definition().selection())?;
        Ok(QueryExecution {
            matches,
            terminal: QueryTerminalState::Completed,
        })
    }

    /// Returns an ordered cursor. Validation and capability errors have already
    /// happened before this method can expose its first item.
    pub fn execute_portable_cursor(
        &self,
        target: &PortableValue,
        limits: QueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<OrderedQueryCursor<PortableMatch>, QueryFailure> {
        let execution = self.execute_portable(target, limits, cancellation)?;
        Ok(OrderedQueryCursor::new(execution.matches))
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
    Ok(output)
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

struct PortableExecutionContext<'a> {
    limits: QueryLimits,
    cancellation: &'a CancellationToken,
    steps: usize,
}

impl PortableExecutionContext<'_> {
    fn step(&mut self, produced: usize) -> Result<(), QueryFailure> {
        if self.cancellation.is_cancelled() {
            return Err(QueryFailure::Cancelled);
        }
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps || produced > self.limits.max_results {
            return Err(QueryFailure::ResourceLimitExceeded);
        }
        Ok(())
    }
}

fn execute_expression(
    expression: &QueryExpression,
    input: &[PortableMatch],
    context: &mut PortableExecutionContext<'_>,
) -> Result<Vec<PortableMatch>, QueryFailure> {
    match expression {
        QueryExpression::Input => Ok(input.to_vec()),
        QueryExpression::Apply {
            input: expression_input,
            operator,
        } => {
            let matches = execute_expression(expression_input, input, context)?;
            apply_portable_operator(operator, matches, context)
        }
        QueryExpression::Concat(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_expression(branch, input, context)?);
                context.step(output.len())?;
            }
            Ok(output)
        }
        QueryExpression::StructureOrderMerge(branches) => {
            let mut output = Vec::new();
            for branch in branches {
                output.extend(execute_expression(branch, input, context)?);
            }
            output.sort_by_key(PortableMatch::identity);
            context.step(output.len())?;
            Ok(output)
        }
    }
}

fn apply_portable_operator(
    operator: &OperatorCall,
    input: Vec<PortableMatch>,
    context: &mut PortableExecutionContext<'_>,
) -> Result<Vec<PortableMatch>, QueryFailure> {
    let mut output = Vec::new();
    match operator.id() {
        "core.try-object-entries" => {
            for item in input {
                if let PortableMatch::Value { path, value } = item
                    && let Some(entries) = value.as_object()
                {
                    for (ordinal, entry) in entries.iter().enumerate() {
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
                if let PortableMatch::Value { path, value } = item
                    && let Some(entries) = value.as_entry_mapping()
                {
                    for (ordinal, entry) in entries.iter().enumerate() {
                        output.push(PortableMatch::EntryMappingEntry {
                            location: AssociationLocation::new(
                                path.clone(),
                                ordinal as u64,
                                AssociationRole::EntryMappingEntry,
                            ),
                            key_path: path.child(ValuePathSegment::EntryKey(ordinal as u64)),
                            key: entry.key().clone(),
                            value_path: path.child(ValuePathSegment::EntryValue(ordinal as u64)),
                            value: entry.value().clone(),
                        });
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
                if let PortableMatch::Value { path, value } = item
                    && let Some(elements) = value.as_sequence()
                {
                    for (index, element) in elements.iter().enumerate() {
                        output.push(PortableMatch::Value {
                            path: path.child(ValuePathSegment::SequenceElement(index as u64)),
                            value: element.clone(),
                        });
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
    context.step(output.len())?;
    Ok(output)
}

fn apply_selection<T>(
    mut values: Vec<T>,
    selection: QuerySelection,
) -> Result<Vec<T>, QueryFailure> {
    match selection {
        QuerySelection::All => Ok(values),
        QuerySelection::First => Ok(values.into_iter().take(1).collect()),
        QuerySelection::Last => Ok(values.pop().into_iter().collect()),
        QuerySelection::ZeroOrOne if values.len() <= 1 => Ok(values),
        QuerySelection::RequireOne if values.len() == 1 => Ok(values),
        QuerySelection::ZeroOrOne | QuerySelection::RequireOne => {
            Err(QueryFailure::CardinalityViolation {
                selection,
                actual: values.len(),
            })
        }
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
    terminal: Option<QueryTerminalState>,
}

impl<T> OrderedQueryCursor<T> {
    /// Creates a cursor over a complete standard-order result.
    #[must_use]
    pub fn new(values: Vec<T>) -> Self {
        Self {
            remaining: values.into_iter(),
            terminal: None,
        }
    }

    /// Becomes `Some(Completed)` only after the cursor is exhausted.
    #[must_use]
    pub const fn terminal_state(&self) -> Option<QueryTerminalState> {
        self.terminal
    }
}

impl<T> Iterator for OrderedQueryCursor<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.remaining.next();
        if next.is_none() {
            self.terminal = Some(QueryTerminalState::Completed);
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
    use crate::{BigInteger, ObjectBuilder};

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.insert(CapabilityId::new("core.query.ordered-results", 1));
        capabilities
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
}
