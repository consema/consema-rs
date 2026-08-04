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

const ERROR_CODES: &[ErrorCodeDescriptor] = &[
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

/// Closed error-code registry for the current semantic model.
#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorCodeRegistry;

impl ErrorCodeRegistry {
    /// Current registry.
    #[must_use]
    pub const fn v1() -> Self {
        Self
    }

    /// Sorted immutable descriptors.
    #[must_use]
    pub const fn codes(self) -> &'static [ErrorCodeDescriptor] {
        ERROR_CODES
    }

    /// Whether a full exact code is registered.
    #[must_use]
    pub fn contains(self, candidate: &str) -> bool {
        self.descriptor(candidate).is_some()
    }

    /// Returns the exact registered descriptor.
    #[must_use]
    pub fn descriptor(self, candidate: &str) -> Option<&'static ErrorCodeDescriptor> {
        ERROR_CODES
            .binary_search_by_key(&candidate, |descriptor| descriptor.code)
            .ok()
            .map(|index| &ERROR_CODES[index])
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
    let mut codes = SequenceBuilder::new();
    for descriptor in ERROR_CODES {
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
        let codes = ErrorCodeRegistry::v1().codes();
        assert!(codes.windows(2).all(|pair| pair[0].code < pair[1].code));
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
    }
}
