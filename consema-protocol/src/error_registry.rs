//! Stable public diagnostic and failure code registry.

use crate::schema::{exact_fields, object, schema_fields, sequence, string};
use crate::{ContractId, ProtocolError, ProtocolErrorKind};
use consema_core::{DiagnosticCategory, PortableValue, QueryFailure, SequenceBuilder};

/// One stable public code registry record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ErrorCodeDescriptor {
    /// Full namespaced code including `@version`.
    pub code: &'static str,
    /// Semantic category.
    pub category: DiagnosticCategory,
    /// First Consema release containing the code.
    pub introduced: &'static str,
    /// Human-facing summary; not part of control flow.
    pub description: &'static str,
}

macro_rules! code {
    ($code:literal, $category:ident, $introduced:literal, $description:literal) => {
        ErrorCodeDescriptor {
            code: $code,
            category: DiagnosticCategory::$category,
            introduced: $introduced,
            description: $description,
        }
    };
}

const ERROR_CODES_V1: &[ErrorCodeDescriptor] = &[
    code!(
        "core.diagnostic.truncated@1",
        Resource,
        "0.1.0",
        "Diagnostic limit truncated a sequence"
    ),
    code!(
        "core.parse.resource-limit@1",
        Resource,
        "0.1.0",
        "Parser resource limit was reached"
    ),
    code!(
        "core.projection.conflicting-policy@1",
        Projection,
        "0.1.0",
        "Projection policy rules conflict"
    ),
    code!(
        "core.projection.invalid-policy-target@1",
        Projection,
        "0.1.0",
        "Projection policy target is invalid"
    ),
    code!(
        "core.projection.resource-limit@1",
        Resource,
        "0.1.0",
        "Projection resource limit was reached"
    ),
    code!(
        "core.projection.target-not-applicable@1",
        Projection,
        "0.1.0",
        "Projection target does not apply"
    ),
    code!(
        "core.projection.wrong-snapshot-policy@1",
        Projection,
        "0.1.0",
        "Projection policy uses another snapshot"
    ),
    code!(
        "core.protocol.invalid-json@1",
        Encoding,
        "0.3.0",
        "Protocol JSON is invalid"
    ),
    code!(
        "core.protocol.invalid-pvce@1",
        Encoding,
        "0.3.0",
        "Protocol PVCE is invalid"
    ),
    code!(
        "core.protocol.invalid-value@1",
        Encoding,
        "0.3.0",
        "Protocol field value violates its invariant"
    ),
    code!(
        "core.protocol.missing-field@1",
        Encoding,
        "0.3.0",
        "Required protocol field is absent"
    ),
    code!(
        "core.protocol.non-canonical-json@1",
        Encoding,
        "0.3.0",
        "Protocol JSON is not canonical"
    ),
    code!(
        "core.protocol.process-local-handle@1",
        Encoding,
        "0.3.0",
        "Process-local handle cannot cross the wire"
    ),
    code!(
        "core.protocol.resource-limit@1",
        Resource,
        "0.3.0",
        "Protocol resource limit was reached"
    ),
    code!(
        "core.protocol.schema-mismatch@1",
        Encoding,
        "0.3.0",
        "Protocol schema or field order does not match"
    ),
    code!(
        "core.protocol.unknown-contract@1",
        Encoding,
        "0.3.0",
        "Protocol contract ID or version is unknown"
    ),
    code!(
        "core.protocol.unknown-field@1",
        Encoding,
        "0.3.0",
        "Fixed protocol schema contains an unknown field"
    ),
    code!(
        "core.protocol.wrong-type@1",
        Encoding,
        "0.3.0",
        "Protocol field has the wrong value type"
    ),
    code!(
        "core.query.cancelled@1",
        Query,
        "0.3.0",
        "Query execution was cancelled"
    ),
    code!(
        "core.query.cardinality-violation@1",
        Query,
        "0.3.0",
        "Query selection cardinality was violated"
    ),
    code!(
        "core.query.domain-mismatch@1",
        Query,
        "0.3.0",
        "Query domain is unknown or mismatched"
    ),
    code!(
        "core.query.invalid-argument@1",
        Query,
        "0.3.0",
        "Query operator argument is invalid"
    ),
    code!(
        "core.query.invalid-composition@1",
        Query,
        "0.3.0",
        "Query operator roles cannot be composed"
    ),
    code!(
        "core.query.missing-capability@1",
        Query,
        "0.3.0",
        "Query implementation lacks a required capability"
    ),
    code!(
        "core.query.required-type-mismatch@1",
        Query,
        "0.3.0",
        "Required query value type did not match"
    ),
    code!(
        "core.query.resource-limit@1",
        Resource,
        "0.3.0",
        "Query resource limit was reached"
    ),
    code!(
        "core.query.target-unavailable@1",
        Query,
        "0.3.0",
        "Target native semantics are unavailable"
    ),
    code!(
        "core.query.unknown-operator@1",
        Query,
        "0.3.0",
        "Query operator ID or version is unknown"
    ),
    code!(
        "core.query.wrong-argument-type@1",
        Query,
        "0.3.0",
        "Query operator argument has the wrong type"
    ),
    code!(
        "core.source.invalid-utf8@1",
        Lexical,
        "0.1.0",
        "Source bytes are not valid UTF-8"
    ),
    code!(
        "json.edit.representation-fallback@1",
        Edit,
        "0.1.0",
        "JSON edit used an authorized canonical fallback"
    ),
    code!(
        "json.object.duplicate-member@1",
        Semantic,
        "0.1.0",
        "JSON object contains duplicate member names"
    ),
    code!(
        "json.projection.duplicate-keys@1",
        Projection,
        "0.1.0",
        "JSON projection encountered duplicate keys"
    ),
    code!(
        "json.projection.semantic-unavailable@1",
        Projection,
        "0.1.0",
        "Recovered JSON region lacks native semantics"
    ),
    code!(
        "json.strict.comment-not-allowed@1",
        Conformance,
        "0.1.0",
        "Strict JSON profile rejects comments"
    ),
    code!(
        "json.strict.leading-bom@1",
        Conformance,
        "0.1.0",
        "Strict JSON source has a leading BOM"
    ),
    code!(
        "json.strict.trailing-comma@1",
        Conformance,
        "0.1.0",
        "Strict JSON profile rejects trailing commas"
    ),
    code!(
        "json.syntax.expected-object-key@1",
        Syntax,
        "0.1.0",
        "JSON object key was expected"
    ),
    code!(
        "json.syntax.expected-value@1",
        Syntax,
        "0.1.0",
        "JSON value was expected"
    ),
    code!(
        "json.syntax.invalid-number@1",
        Syntax,
        "0.1.0",
        "JSON number syntax is invalid"
    ),
    code!(
        "json.syntax.invalid-string-escape@1",
        Syntax,
        "0.1.0",
        "JSON string escape is invalid"
    ),
    code!(
        "json.syntax.missing-array-close@1",
        Syntax,
        "0.1.0",
        "JSON array close delimiter is missing"
    ),
    code!(
        "json.syntax.missing-colon@1",
        Syntax,
        "0.1.0",
        "JSON member colon is missing"
    ),
    code!(
        "json.syntax.missing-comma@1",
        Syntax,
        "0.1.0",
        "JSON container comma is missing"
    ),
    code!(
        "json.syntax.missing-object-close@1",
        Syntax,
        "0.1.0",
        "JSON object close delimiter is missing"
    ),
    code!(
        "json.syntax.missing-value@1",
        Syntax,
        "0.1.0",
        "JSON value is missing"
    ),
    code!(
        "json.syntax.trailing-content@1",
        Syntax,
        "0.1.0",
        "JSON has trailing content"
    ),
    code!(
        "json.syntax.unexpected-character@1",
        Syntax,
        "0.1.0",
        "JSON has an unexpected character"
    ),
    code!(
        "json.syntax.unexpected-word@1",
        Syntax,
        "0.1.0",
        "JSON has an unexpected word"
    ),
    code!(
        "json.syntax.unterminated-block-comment@1",
        Syntax,
        "0.1.0",
        "JSONC block comment is unterminated"
    ),
    code!(
        "json.syntax.unterminated-string@1",
        Syntax,
        "0.1.0",
        "JSON string is unterminated"
    ),
    code!(
        "toml.edit.representation-fallback@1",
        Edit,
        "0.2.0",
        "TOML edit used an authorized canonical fallback"
    ),
    code!(
        "toml.parse.syntax@1",
        Syntax,
        "0.2.0",
        "TOML syntax is invalid"
    ),
    code!(
        "toml.projection.core-invariant@1",
        Projection,
        "0.2.0",
        "TOML projection hit a core invariant"
    ),
    code!(
        "toml.projection.unrepresentable-datetime@1",
        Projection,
        "0.2.0",
        "TOML temporal value is not exactly representable"
    ),
];

const SOURCE_CODES_V2_BEFORE_UTF8: &[ErrorCodeDescriptor] = &[
    code!(
        "core.source.encoding-conflict@1",
        Encoding,
        "0.4.0",
        "Source encoding facts conflict"
    ),
    code!(
        "core.source.invalid-sequence@1",
        Lexical,
        "0.4.0",
        "Source bytes are invalid for the selected encoding"
    ),
];

const SOURCE_CODES_V2_AFTER_UTF8: &[ErrorCodeDescriptor] = &[
    code!(
        "core.source.patch-base-mismatch@1",
        Edit,
        "0.4.0",
        "SourcePatch base digest does not match"
    ),
    code!(
        "core.source.patch-original-mismatch@1",
        Edit,
        "0.4.0",
        "SourcePatch original-byte precondition does not match"
    ),
    code!(
        "core.source.patch-target-mismatch@1",
        Edit,
        "0.4.0",
        "SourcePatch target digest does not match"
    ),
    code!(
        "core.source.resource-limit@1",
        Resource,
        "0.4.0",
        "Source construction or patch limit was reached"
    ),
    code!(
        "core.source.unsupported-bom@1",
        Encoding,
        "0.4.0",
        "Source begins with an unsupported byte-order mark"
    ),
];

const ERROR_CODES_V2: [ErrorCodeDescriptor; 62] = build_v2_codes();

const fn build_v2_codes() -> [ErrorCodeDescriptor; 62] {
    let mut output = [ERROR_CODES_V1[0]; 62];
    let mut source = 0;
    let mut target = 0;
    while source < 29 {
        output[target] = ERROR_CODES_V1[source];
        source += 1;
        target += 1;
    }
    let mut extra = 0;
    while extra < SOURCE_CODES_V2_BEFORE_UTF8.len() {
        output[target] = SOURCE_CODES_V2_BEFORE_UTF8[extra];
        extra += 1;
        target += 1;
    }
    output[target] = ERROR_CODES_V1[29];
    source = 30;
    target += 1;
    extra = 0;
    while extra < SOURCE_CODES_V2_AFTER_UTF8.len() {
        output[target] = SOURCE_CODES_V2_AFTER_UTF8[extra];
        extra += 1;
        target += 1;
    }
    while source < ERROR_CODES_V1.len() {
        output[target] = ERROR_CODES_V1[source];
        source += 1;
        target += 1;
    }
    output
}

const NEW_CODES_V3: &[ErrorCodeDescriptor] = &[
    code!(
        "core.conversion.materialization-failed@1",
        Conversion,
        "0.5.0",
        "Conversion target materialization failed"
    ),
    code!(
        "core.conversion.projection-failed@1",
        Conversion,
        "0.5.0",
        "Conversion source projection failed"
    ),
    code!(
        "core.conversion.unauthorized-loss@1",
        Conversion,
        "0.5.0",
        "Conversion encountered loss without explicit authorization"
    ),
    code!(
        "core.edit.conflicting-edits@1",
        Edit,
        "0.5.0",
        "Edit operations have conflicting source ownership"
    ),
    code!(
        "core.edit.duplicate-key@1",
        Edit,
        "0.5.0",
        "Edit would create a duplicate key"
    ),
    code!(
        "core.edit.exact-literal-requires-literal@1",
        Edit,
        "0.5.0",
        "Exact literal policy requires a literal operation"
    ),
    code!(
        "core.edit.formation-failed@1",
        Edit,
        "0.5.0",
        "Edited bytes did not form the required target document"
    ),
    code!(
        "core.edit.incomplete-target@1",
        Edit,
        "0.5.0",
        "Edit target is not a complete syntax node"
    ),
    code!(
        "core.edit.invalid-literal@1",
        Edit,
        "0.5.0",
        "Edit literal is invalid for the target profile"
    ),
    code!(
        "core.edit.operation-unsupported@1",
        Edit,
        "0.5.0",
        "Edit operation is not supported for the target"
    ),
    code!(
        "core.edit.precondition-failed@1",
        Edit,
        "0.5.0",
        "Edit original-byte or digest precondition failed"
    ),
    code!(
        "core.edit.representation-incompatible@1",
        Edit,
        "0.5.0",
        "Edit representation policy cannot preserve the target category"
    ),
    code!(
        "core.edit.resource-limit@1",
        Resource,
        "0.5.0",
        "Edit planning or commit resource limit was reached"
    ),
    code!(
        "core.edit.semantic-unavailable@1",
        Edit,
        "0.5.0",
        "Edit target native semantics are unavailable"
    ),
    code!(
        "core.edit.target-not-found@1",
        Edit,
        "0.5.0",
        "Edit target or placement anchor was not found"
    ),
    code!(
        "core.edit.unsupported-value@1",
        Edit,
        "0.5.0",
        "Edit value is not representable by the target profile"
    ),
    code!(
        "core.edit.wrong-role@1",
        Edit,
        "0.5.0",
        "Edit target has the wrong structural role"
    ),
    code!(
        "core.edit.wrong-snapshot@1",
        Edit,
        "0.5.0",
        "Edit target belongs to another snapshot"
    ),
    code!(
        "core.materialization.formation-failed@1",
        Materialization,
        "0.5.0",
        "Generated bytes did not form the target profile"
    ),
    code!(
        "core.materialization.invalid-request@1",
        Materialization,
        "0.5.0",
        "Materialization request fields are contradictory"
    ),
    code!(
        "core.materialization.mapping-transformed@1",
        Materialization,
        "0.5.0",
        "Ordered mapping was explicitly transformed into an object"
    ),
    code!(
        "core.materialization.resource-limit@1",
        Resource,
        "0.5.0",
        "Materialization resource limit was reached"
    ),
    code!(
        "core.materialization.unrepresentable@1",
        Materialization,
        "0.5.0",
        "Portable input cannot be represented by the target profile"
    ),
    code!(
        "core.materialization.unsupported-encoding@1",
        Encoding,
        "0.5.0",
        "Target profile does not support the requested encoding"
    ),
    code!(
        "core.materialization.unsupported-newline@1",
        Materialization,
        "0.5.0",
        "Target style does not support the requested newline policy"
    ),
    code!(
        "core.materialization.unsupported-profile@1",
        Materialization,
        "0.5.0",
        "Requested materialization profile is unavailable"
    ),
    code!(
        "core.materialization.unsupported-style@1",
        Materialization,
        "0.5.0",
        "Requested materialization style is unavailable"
    ),
    code!(
        "json.projection.structure-reencoded@1",
        Projection,
        "0.5.0",
        "JSON object structure was reversibly represented as an entry mapping"
    ),
];

const ERROR_CODES_V3: [ErrorCodeDescriptor; 90] = build_v3_codes();

const fn build_v3_codes() -> [ErrorCodeDescriptor; 90] {
    let mut output = [ERROR_CODES_V2[0]; 90];
    let mut old = 0;
    let mut new = 0;
    let mut target = 0;
    while old < ERROR_CODES_V2.len() && new < NEW_CODES_V3.len() {
        if const_str_less(ERROR_CODES_V2[old].code, NEW_CODES_V3[new].code) {
            output[target] = ERROR_CODES_V2[old];
            old += 1;
        } else {
            output[target] = NEW_CODES_V3[new];
            new += 1;
        }
        target += 1;
    }
    while old < ERROR_CODES_V2.len() {
        output[target] = ERROR_CODES_V2[old];
        old += 1;
        target += 1;
    }
    while new < NEW_CODES_V3.len() {
        output[target] = NEW_CODES_V3[new];
        new += 1;
        target += 1;
    }
    output
}

const NEW_CODES_V4: &[ErrorCodeDescriptor] = &[
    code!(
        "json5.string.unescaped-line-separator@1",
        Conformance,
        "0.6.0",
        "JSON5 string contains an unescaped Unicode line separator"
    ),
    code!(
        "json5.syntax.invalid-identifier@1",
        Syntax,
        "0.6.0",
        "JSON5 IdentifierName syntax is invalid"
    ),
];

const ERROR_CODES_V4: [ErrorCodeDescriptor; 92] = build_v4_codes();

const fn build_v4_codes() -> [ErrorCodeDescriptor; 92] {
    let mut output = [ERROR_CODES_V3[0]; 92];
    let mut old = 0;
    let mut new = 0;
    let mut target = 0;
    while old < ERROR_CODES_V3.len() && new < NEW_CODES_V4.len() {
        if const_str_less(ERROR_CODES_V3[old].code, NEW_CODES_V4[new].code) {
            output[target] = ERROR_CODES_V3[old];
            old += 1;
        } else {
            output[target] = NEW_CODES_V4[new];
            new += 1;
        }
        target += 1;
    }
    while old < ERROR_CODES_V3.len() {
        output[target] = ERROR_CODES_V3[old];
        old += 1;
        target += 1;
    }
    while new < NEW_CODES_V4.len() {
        output[target] = NEW_CODES_V4[new];
        new += 1;
        target += 1;
    }
    output
}

const fn const_str_less(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut index = 0;
    while index < left.len() && index < right.len() {
        if left[index] < right[index] {
            return true;
        }
        if left[index] > right[index] {
            return false;
        }
        index += 1;
    }
    left.len() < right.len()
}

/// Closed, explicitly versioned error-code registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorCodeRegistry {
    version: RegistryVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryVersion {
    V1,
    V2,
    V3,
    V4,
}

impl Default for ErrorCodeRegistry {
    fn default() -> Self {
        Self::v1()
    }
}

impl ErrorCodeRegistry {
    /// Frozen Consema 0.3 semantic-model v1 registry.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            version: RegistryVersion::V1,
        }
    }

    /// Consema 0.4 semantic-model v2 error registry.
    #[must_use]
    pub const fn v2() -> Self {
        Self {
            version: RegistryVersion::V2,
        }
    }

    /// Consema 0.5 semantic-model v3 error registry.
    #[must_use]
    pub const fn v3() -> Self {
        Self {
            version: RegistryVersion::V3,
        }
    }

    /// Consema 0.6 semantic-model v4 error registry.
    #[must_use]
    pub const fn v4() -> Self {
        Self {
            version: RegistryVersion::V4,
        }
    }

    /// Sorted immutable descriptors.
    #[must_use]
    pub const fn codes(self) -> &'static [ErrorCodeDescriptor] {
        match self.version {
            RegistryVersion::V1 => ERROR_CODES_V1,
            RegistryVersion::V2 => &ERROR_CODES_V2,
            RegistryVersion::V3 => &ERROR_CODES_V3,
            RegistryVersion::V4 => &ERROR_CODES_V4,
        }
    }

    /// Whether a full exact code is registered.
    #[must_use]
    pub fn contains(self, candidate: &str) -> bool {
        self.descriptor(candidate).is_some()
    }

    /// Returns the exact registered descriptor.
    #[must_use]
    pub fn descriptor(self, candidate: &str) -> Option<&'static ErrorCodeDescriptor> {
        let codes = self.codes();
        codes
            .binary_search_by_key(&candidate, |descriptor| descriptor.code)
            .ok()
            .map(|index| &codes[index])
    }

    /// Validates an exact registered code.
    pub fn validate(self, candidate: &str) -> Result<(), ProtocolError> {
        self.validate_at(candidate, "$.code")
    }

    pub(crate) fn validate_at(self, candidate: &str, path: &str) -> Result<(), ProtocolError> {
        if self.contains(candidate) {
            Ok(())
        } else {
            Err(ProtocolError::new(
                ProtocolErrorKind::InvalidValue,
                path,
                format!("unregistered public code: {candidate}"),
            ))
        }
    }
}

/// Stable public code for every current QueryFailure variant.
#[must_use]
pub const fn query_failure_code(failure: &QueryFailure) -> &'static str {
    match failure {
        QueryFailure::DomainMismatch(_) => "core.query.domain-mismatch@1",
        QueryFailure::UnknownOperator { .. } => "core.query.unknown-operator@1",
        QueryFailure::WrongArgumentType { .. } => "core.query.wrong-argument-type@1",
        QueryFailure::InvalidArgument { .. } => "core.query.invalid-argument@1",
        QueryFailure::InvalidOperatorComposition { .. } => "core.query.invalid-composition@1",
        QueryFailure::MissingRequiredCapability(_) => "core.query.missing-capability@1",
        QueryFailure::RequiredTypeMismatch { .. } => "core.query.required-type-mismatch@1",
        QueryFailure::CardinalityViolation { .. } => "core.query.cardinality-violation@1",
        QueryFailure::ResourceLimitExceeded => "core.query.resource-limit@1",
        QueryFailure::Cancelled => "core.query.cancelled@1",
        QueryFailure::TargetUnavailable => "core.query.target-unavailable@1",
    }
}

/// Encodes `core.error-code-registry@1`.
#[must_use]
pub fn error_code_manifest_value() -> PortableValue {
    error_code_manifest_value_for(ErrorCodeRegistry::v1())
}

/// Encodes the semantic-model v2 `core.error-code-registry@1` payload.
#[must_use]
pub fn error_code_manifest_value_v2() -> PortableValue {
    error_code_manifest_value_for(ErrorCodeRegistry::v2())
}

/// Encodes the semantic-model v3 `core.error-code-registry@1` payload.
#[must_use]
pub fn error_code_manifest_value_v3() -> PortableValue {
    error_code_manifest_value_for(ErrorCodeRegistry::v3())
}

/// Encodes the semantic-model v4 `core.error-code-registry@1` payload.
#[must_use]
pub fn error_code_manifest_value_v4() -> PortableValue {
    error_code_manifest_value_for(ErrorCodeRegistry::v4())
}

fn error_code_manifest_value_for(registry: ErrorCodeRegistry) -> PortableValue {
    let mut codes = SequenceBuilder::new();
    for descriptor in registry.codes() {
        codes.push(object(vec![
            ("code", PortableValue::string(descriptor.code)),
            (
                "category",
                PortableValue::string(category_name(descriptor.category)),
            ),
            ("introduced", PortableValue::string(descriptor.introduced)),
            ("stability", PortableValue::string("Stable")),
            ("description", PortableValue::string(descriptor.description)),
        ]));
    }
    object(vec![
        (
            "schema",
            PortableValue::string("core.error-code-registry@1"),
        ),
        ("error_codes", codes.build()),
    ])
}

/// Strictly validates one transferable `core.error-code-registry@1` value.
///
/// Registry descriptions are presentation metadata, so a conforming peer may
/// publish different non-empty wording. Identity, ordering, category and
/// stability remain normative.
pub fn validate_error_code_manifest_value(value: &PortableValue) -> Result<(), ProtocolError> {
    let fields = schema_fields(
        value,
        "core.error-code-registry@1",
        &["schema", "error_codes"],
        "$",
    )?;
    let mut previous = None::<String>;
    for (index, item) in sequence(fields[1], "$.error_codes")?.iter().enumerate() {
        let path = format!("$.error_codes[{index}]");
        let fields = exact_fields(
            item,
            &["code", "category", "introduced", "stability", "description"],
            &path,
        )?;
        let code = string(fields[0], &format!("{path}.code"))?;
        validate_versioned_code(code, &format!("{path}.code"))?;
        parse_category(fields[1], &format!("{path}.category"))?;
        if string(fields[2], &format!("{path}.introduced"))?.is_empty()
            || string(fields[4], &format!("{path}.description"))?.is_empty()
        {
            return Err(crate::schema::invalid(
                &path,
                "introduced and description must be non-empty",
            ));
        }
        if string(fields[3], &format!("{path}.stability"))? != "Stable" {
            return Err(crate::schema::invalid(
                &format!("{path}.stability"),
                "unknown error-code stability",
            ));
        }
        if previous
            .as_deref()
            .is_some_and(|candidate| candidate >= code)
        {
            return Err(crate::schema::invalid(
                "$.error_codes",
                "error codes must be sorted and unique",
            ));
        }
        previous = Some(code.to_owned());
    }
    Ok(())
}

fn validate_versioned_code(code: &str, path: &str) -> Result<(), ProtocolError> {
    let (id, version) = code
        .rsplit_once('@')
        .ok_or_else(|| crate::schema::invalid(path, "code lacks @version suffix"))?;
    let version = version
        .parse::<u32>()
        .map_err(|_| crate::schema::invalid(path, "code version is invalid"))?;
    ContractId::new(id, version).map(|_| ())
}

pub(crate) const fn category_name(category: DiagnosticCategory) -> &'static str {
    match category {
        DiagnosticCategory::Lexical => "Lexical",
        DiagnosticCategory::Syntax => "Syntax",
        DiagnosticCategory::Conformance => "Conformance",
        DiagnosticCategory::Semantic => "Semantic",
        DiagnosticCategory::Query => "Query",
        DiagnosticCategory::Projection => "Projection",
        DiagnosticCategory::Materialization => "Materialization",
        DiagnosticCategory::Conversion => "Conversion",
        DiagnosticCategory::Edit => "Edit",
        DiagnosticCategory::Resource => "Resource",
        DiagnosticCategory::Encoding => "Encoding",
    }
}

pub(crate) fn parse_category(
    value: &PortableValue,
    path: &str,
) -> Result<DiagnosticCategory, ProtocolError> {
    match string(value, path)? {
        "Lexical" => Ok(DiagnosticCategory::Lexical),
        "Syntax" => Ok(DiagnosticCategory::Syntax),
        "Conformance" => Ok(DiagnosticCategory::Conformance),
        "Semantic" => Ok(DiagnosticCategory::Semantic),
        "Query" => Ok(DiagnosticCategory::Query),
        "Projection" => Ok(DiagnosticCategory::Projection),
        "Materialization" => Ok(DiagnosticCategory::Materialization),
        "Conversion" => Ok(DiagnosticCategory::Conversion),
        "Edit" => Ok(DiagnosticCategory::Edit),
        "Resource" => Ok(DiagnosticCategory::Resource),
        "Encoding" => Ok(DiagnosticCategory::Encoding),
        _ => Err(crate::schema::invalid(path, "unknown error-code category")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolErrorKind;
    use consema_core::QueryDomain;

    #[test]
    fn registry_is_sorted_unique_and_contains_every_protocol_code() {
        for registry in [
            ErrorCodeRegistry::v1(),
            ErrorCodeRegistry::v2(),
            ErrorCodeRegistry::v3(),
            ErrorCodeRegistry::v4(),
        ] {
            assert!(
                registry
                    .codes()
                    .windows(2)
                    .all(|pair| pair[0].code < pair[1].code)
            );
        }
        assert_eq!(ErrorCodeRegistry::v1().codes().len(), 55);
        assert_eq!(ErrorCodeRegistry::v2().codes().len(), 62);
        assert_eq!(ErrorCodeRegistry::v3().codes().len(), 90);
        assert_eq!(ErrorCodeRegistry::v4().codes().len(), 92);
        assert!(!ErrorCodeRegistry::v1().contains("core.source.patch-base-mismatch@1"));
        assert!(ErrorCodeRegistry::v2().contains("core.source.patch-base-mismatch@1"));
        assert!(!ErrorCodeRegistry::v2().contains("core.materialization.unrepresentable@1"));
        assert!(ErrorCodeRegistry::v3().contains("core.materialization.unrepresentable@1"));
        assert!(!ErrorCodeRegistry::v3().contains("json5.syntax.invalid-identifier@1"));
        assert!(ErrorCodeRegistry::v4().contains("json5.syntax.invalid-identifier@1"));
        assert!(ErrorCodeRegistry::v4().contains("json5.string.unescaped-line-separator@1"));
        let protocol_kinds = [
            ProtocolErrorKind::InvalidJson,
            ProtocolErrorKind::NonCanonicalJson,
            ProtocolErrorKind::InvalidPvce,
            ProtocolErrorKind::UnknownContract,
            ProtocolErrorKind::SchemaMismatch,
            ProtocolErrorKind::UnknownField,
            ProtocolErrorKind::MissingField,
            ProtocolErrorKind::WrongType,
            ProtocolErrorKind::InvalidValue,
            ProtocolErrorKind::ResourceLimit,
            ProtocolErrorKind::ProcessLocalHandle,
        ];
        assert!(
            protocol_kinds
                .iter()
                .all(|kind| ErrorCodeRegistry::v1().contains(kind.code()))
        );
    }

    #[test]
    fn every_query_failure_has_a_registered_code() {
        let failures = [
            QueryFailure::DomainMismatch(QueryDomain::new("example.domain", 1)),
            QueryFailure::UnknownOperator {
                id: "x".to_owned(),
                version: 1,
            },
            QueryFailure::ResourceLimitExceeded,
            QueryFailure::Cancelled,
            QueryFailure::TargetUnavailable,
        ];
        assert!(
            failures
                .iter()
                .all(|failure| { ErrorCodeRegistry::v1().contains(query_failure_code(failure)) })
        );
    }

    #[test]
    fn published_error_code_manifest_is_strictly_valid() {
        validate_error_code_manifest_value(&error_code_manifest_value()).unwrap();
        validate_error_code_manifest_value(&error_code_manifest_value_v2()).unwrap();
        validate_error_code_manifest_value(&error_code_manifest_value_v3()).unwrap();
        validate_error_code_manifest_value(&error_code_manifest_value_v4()).unwrap();
    }
}
