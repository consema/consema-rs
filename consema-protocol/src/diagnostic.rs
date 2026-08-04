//! Transferable diagnostic protocol.

use crate::schema::{
    exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u64,
};
use crate::{ErrorCodeRegistry, ProtocolError, ProtocolErrorKind};
use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity, ObjectBuilder,
    PortableValue, RelatedLocation, SequenceBuilder,
};
use std::collections::BTreeMap;

/// Transferable source location bound to a caller-assigned stable source ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SourceLocation {
    source_id: String,
    start_byte: u64,
    end_byte: u64,
}

impl SourceLocation {
    /// Validates one half-open source range.
    pub fn new(
        source_id: impl Into<String>,
        start_byte: u64,
        end_byte: u64,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        if source_id.is_empty() || source_id.len() > 1024 || start_byte > end_byte {
            return Err(crate::schema::invalid(
                "$.location",
                "source ID or half-open byte range is invalid",
            ));
        }
        Ok(Self {
            source_id,
            start_byte,
            end_byte,
        })
    }

    /// Caller-assigned stable source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Inclusive start byte.
    #[must_use]
    pub const fn start_byte(&self) -> u64 {
        self.start_byte
    }

    /// Exclusive end byte.
    #[must_use]
    pub const fn end_byte(&self) -> u64 {
        self.end_byte
    }
}

/// Related transferable source location and stable relationship role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedSourceLocation {
    /// Stable role.
    pub role: String,
    /// Related source range.
    pub location: SourceLocation,
}

/// Whether a fix can be applied without additional judgment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FixApplicability {
    /// Preconditions make the exact replacement safe to apply.
    MachineApplicable,
    /// The caller should validate surrounding context.
    MaybeApplicable,
    /// The proposal is informational and needs human judgment.
    Manual,
}

/// Explicit source replacement proposal; never an implicit write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixProposal {
    /// Stable namespaced fix ID.
    pub id: String,
    /// Applicability classification.
    pub applicability: FixApplicability,
    /// Optional target source range.
    pub location: Option<SourceLocation>,
    /// Exact replacement bytes.
    pub replacement: Vec<u8>,
}

/// Full `core.diagnostic@1` message independent from control-flow status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticMessage {
    /// Stable namespaced code.
    pub code: String,
    /// Diagnostic category.
    pub category: DiagnosticCategory,
    /// Presentation severity.
    pub severity: DiagnosticSeverity,
    /// Primary source location.
    pub primary: Option<SourceLocation>,
    /// Related locations in semantic order.
    pub related: Vec<RelatedSourceLocation>,
    /// Deterministically sorted arguments.
    pub arguments: BTreeMap<String, String>,
    /// Stable note IDs or localized fallback text.
    pub notes: Vec<String>,
    /// Explicit optional fixes.
    pub fixes: Vec<FixProposal>,
    /// Final deterministic occurrence ordinal.
    pub occurrence: u64,
}

impl DiagnosticMessage {
    /// Converts a core diagnostic with an explicit wire source binding.
    ///
    /// A diagnostic carrying any process-local snapshot location requires a
    /// caller-supplied `source_id`; the adapter never serializes snapshot integers.
    pub fn from_core(
        diagnostic: &Diagnostic,
        source_id: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        Self::from_core_with_registry(diagnostic, source_id, ErrorCodeRegistry::v1())
    }

    /// Converts a core diagnostic under one explicit semantic-model error registry.
    pub fn from_core_with_registry(
        diagnostic: &Diagnostic,
        source_id: Option<&str>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let primary = diagnostic
            .primary
            .as_ref()
            .map(|location| bind_location(location, source_id))
            .transpose()?;
        let related = diagnostic
            .related
            .iter()
            .map(|related| {
                Ok(RelatedSourceLocation {
                    role: related.role.clone(),
                    location: bind_location(&related.location, source_id)?,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let result = Self {
            code: diagnostic.code.clone(),
            category: diagnostic.category,
            severity: diagnostic.severity,
            primary,
            related,
            arguments: diagnostic.arguments.clone(),
            notes: diagnostic.notes.clone(),
            fixes: Vec::new(),
            occurrence: diagnostic.occurrence,
        };
        validate_diagnostic_code(&result.code, result.category, registry)?;
        Ok(result)
    }

    /// Converts portable diagnostic facts back to a snapshot-neutral core value.
    #[must_use]
    pub fn to_core(&self) -> Diagnostic {
        Diagnostic {
            code: self.code.clone(),
            category: self.category,
            severity: self.severity,
            primary: self.primary.as_ref().map(core_location),
            related: self
                .related
                .iter()
                .map(|related| RelatedLocation {
                    role: related.role.clone(),
                    location: core_location(&related.location),
                })
                .collect(),
            arguments: self.arguments.clone(),
            notes: self.notes.clone(),
            occurrence: self.occurrence,
        }
    }

    /// Encodes `core.diagnostic@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut related = SequenceBuilder::new();
        for item in &self.related {
            related.push(object(vec![
                ("role", PortableValue::string(item.role.as_str())),
                ("location", location_value(&item.location)),
            ]));
        }
        let mut arguments = ObjectBuilder::new();
        for (name, value) in &self.arguments {
            arguments
                .insert(name, PortableValue::string(value.as_str()))
                .expect("BTreeMap keys are unique");
        }
        let mut notes = SequenceBuilder::new();
        for note in &self.notes {
            notes.push(PortableValue::string(note.as_str()));
        }
        let mut fixes = SequenceBuilder::new();
        for fix in &self.fixes {
            fixes.push(object(vec![
                ("id", PortableValue::string(fix.id.as_str())),
                (
                    "applicability",
                    PortableValue::string(fix_applicability_name(fix.applicability)),
                ),
                (
                    "location",
                    fix.location
                        .as_ref()
                        .map_or_else(PortableValue::null, location_value),
                ),
                (
                    "replacement",
                    PortableValue::bytes(fix.replacement.as_slice()),
                ),
            ]));
        }
        object(vec![
            ("schema", PortableValue::string("core.diagnostic@1")),
            ("code", PortableValue::string(self.code.as_str())),
            (
                "category",
                PortableValue::string(category_name(self.category)),
            ),
            (
                "severity",
                PortableValue::string(severity_name(self.severity)),
            ),
            (
                "primary",
                self.primary
                    .as_ref()
                    .map_or_else(PortableValue::null, location_value),
            ),
            ("related", related.build()),
            ("arguments", arguments.build()),
            ("notes", notes.build()),
            ("fixes", fixes.build()),
            ("occurrence", integer_u64(self.occurrence)),
        ])
    }

    /// Strictly decodes `core.diagnostic@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v1())
    }

    /// Strictly decodes `core.diagnostic@1` under an explicit error registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.diagnostic@1",
            &[
                "schema",
                "code",
                "category",
                "severity",
                "primary",
                "related",
                "arguments",
                "notes",
                "fixes",
                "occurrence",
            ],
            "$",
        )?;
        let primary = if fields[4] == &PortableValue::null() {
            None
        } else {
            Some(location(fields[4], "$.primary")?)
        };
        let related = sequence(fields[5], "$.related")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let path = format!("$.related[{index}]");
                let fields = exact_fields(item, &["role", "location"], &path)?;
                Ok(RelatedSourceLocation {
                    role: string(fields[0], &format!("{path}.role"))?.to_owned(),
                    location: location(fields[1], &format!("{path}.location"))?,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let argument_entries = fields[6].as_object().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorKind::WrongType,
                "$.arguments",
                "expected Object<String, String>",
            )
        })?;
        let mut arguments = BTreeMap::new();
        for entry in argument_entries {
            arguments.insert(
                entry.key().to_owned(),
                string(entry.value(), &format!("$.arguments.{}", entry.key()))?.to_owned(),
            );
        }
        let notes = sequence(fields[7], "$.notes")?
            .iter()
            .enumerate()
            .map(|(index, note)| string(note, &format!("$.notes[{index}]")).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let fixes = sequence(fields[8], "$.fixes")?
            .iter()
            .enumerate()
            .map(|(index, fix)| decode_fix(fix, &format!("$.fixes[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let result = Self {
            code: string(fields[1], "$.code")?.to_owned(),
            category: parse_category(string(fields[2], "$.category")?)?,
            severity: parse_severity(string(fields[3], "$.severity")?)?,
            primary,
            related,
            arguments,
            notes,
            fixes,
            occurrence: unsigned_u64(fields[9], "$.occurrence")?,
        };
        validate_diagnostic_code(&result.code, result.category, registry)?;
        Ok(result)
    }
}

fn validate_diagnostic_code(
    code: &str,
    category: DiagnosticCategory,
    registry: ErrorCodeRegistry,
) -> Result<(), ProtocolError> {
    let descriptor = registry.descriptor(code).ok_or_else(|| {
        crate::schema::invalid("$.code", format!("unregistered public code: {code}"))
    })?;
    if descriptor.category != category {
        return Err(crate::schema::invalid(
            "$.category",
            "diagnostic category contradicts the error-code registry",
        ));
    }
    Ok(())
}

fn bind_location(
    location: &DiagnosticLocation,
    source_id: Option<&str>,
) -> Result<SourceLocation, ProtocolError> {
    let source_id = source_id.ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::ProcessLocalHandle,
            "$.location.snapshot",
            "a stable source binding is required for wire encoding",
        )
    })?;
    SourceLocation::new(source_id, location.start_byte, location.end_byte)
}

fn core_location(location: &SourceLocation) -> DiagnosticLocation {
    DiagnosticLocation {
        snapshot: None,
        start_byte: location.start_byte,
        end_byte: location.end_byte,
    }
}

fn location_value(location: &SourceLocation) -> PortableValue {
    object(vec![
        (
            "source_id",
            PortableValue::string(location.source_id.as_str()),
        ),
        ("start_byte", integer_u64(location.start_byte)),
        ("end_byte", integer_u64(location.end_byte)),
    ])
}

fn location(value: &PortableValue, path: &str) -> Result<SourceLocation, ProtocolError> {
    let fields = exact_fields(value, &["source_id", "start_byte", "end_byte"], path)?;
    SourceLocation::new(
        string(fields[0], &format!("{path}.source_id"))?,
        unsigned_u64(fields[1], &format!("{path}.start_byte"))?,
        unsigned_u64(fields[2], &format!("{path}.end_byte"))?,
    )
}

fn decode_fix(value: &PortableValue, path: &str) -> Result<FixProposal, ProtocolError> {
    let fields = exact_fields(
        value,
        &["id", "applicability", "location", "replacement"],
        path,
    )?;
    let id = string(fields[0], &format!("{path}.id"))?.to_owned();
    if id.is_empty() || id.len() > 255 {
        return Err(crate::schema::invalid(
            &format!("{path}.id"),
            "invalid fix ID",
        ));
    }
    let applicability = match string(fields[1], &format!("{path}.applicability"))? {
        "MachineApplicable" => FixApplicability::MachineApplicable,
        "MaybeApplicable" => FixApplicability::MaybeApplicable,
        "Manual" => FixApplicability::Manual,
        _ => {
            return Err(crate::schema::invalid(
                &format!("{path}.applicability"),
                "unknown fix applicability",
            ));
        }
    };
    let location = if fields[2] == &PortableValue::null() {
        None
    } else {
        Some(self::location(fields[2], &format!("{path}.location"))?)
    };
    let replacement = fields[3].as_bytes().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.replacement"),
            "expected Bytes",
        )
    })?;
    Ok(FixProposal {
        id,
        applicability,
        location,
        replacement: replacement.to_vec(),
    })
}

const fn category_name(category: DiagnosticCategory) -> &'static str {
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

fn parse_category(value: &str) -> Result<DiagnosticCategory, ProtocolError> {
    match value {
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
        _ => Err(crate::schema::invalid(
            "$.category",
            "unknown diagnostic category",
        )),
    }
}

const fn severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "Info",
        DiagnosticSeverity::Warning => "Warning",
        DiagnosticSeverity::Error => "Error",
    }
}

fn parse_severity(value: &str) -> Result<DiagnosticSeverity, ProtocolError> {
    match value {
        "Info" => Ok(DiagnosticSeverity::Info),
        "Warning" => Ok(DiagnosticSeverity::Warning),
        "Error" => Ok(DiagnosticSeverity::Error),
        _ => Err(crate::schema::invalid(
            "$.severity",
            "unknown diagnostic severity",
        )),
    }
}

const fn fix_applicability_name(value: FixApplicability) -> &'static str {
    match value {
        FixApplicability::MachineApplicable => "MachineApplicable",
        FixApplicability::MaybeApplicable => "MaybeApplicable",
        FixApplicability::Manual => "Manual",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_round_trip_preserves_fixes_and_locations() {
        let message = DiagnosticMessage {
            code: "json.object.duplicate-member@1".to_owned(),
            category: DiagnosticCategory::Semantic,
            severity: DiagnosticSeverity::Warning,
            primary: Some(SourceLocation::new("sha256:abc", 2, 4).unwrap()),
            related: Vec::new(),
            arguments: BTreeMap::from([("name".to_owned(), "x".to_owned())]),
            notes: vec!["example.note@1".to_owned()],
            fixes: vec![FixProposal {
                id: "example.fix@1".to_owned(),
                applicability: FixApplicability::MachineApplicable,
                location: Some(SourceLocation::new("sha256:abc", 2, 4).unwrap()),
                replacement: b"ok".to_vec(),
            }],
            occurrence: 7,
        };
        assert_eq!(
            DiagnosticMessage::from_value(&message.to_value()).unwrap(),
            message
        );
    }

    #[test]
    fn core_snapshot_location_requires_explicit_binding() {
        let diagnostic = Diagnostic::new(
            "json.syntax.expected-value@1",
            DiagnosticCategory::Syntax,
            DiagnosticSeverity::Error,
            Some(DiagnosticLocation {
                snapshot: Some(42),
                start_byte: 0,
                end_byte: 1,
            }),
            0,
        );
        assert_eq!(
            DiagnosticMessage::from_core(&diagnostic, None)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
        let portable = DiagnosticMessage::from_core(&diagnostic, Some("source:one")).unwrap();
        assert_eq!(portable.primary.unwrap().source_id(), "source:one");
    }

    #[test]
    fn diagnostic_code_and_category_are_registry_bound() {
        let mut message = DiagnosticMessage {
            code: "example.problem@1".to_owned(),
            category: DiagnosticCategory::Semantic,
            severity: DiagnosticSeverity::Warning,
            primary: None,
            related: Vec::new(),
            arguments: BTreeMap::new(),
            notes: Vec::new(),
            fixes: Vec::new(),
            occurrence: 0,
        };
        assert!(DiagnosticMessage::from_value(&message.to_value()).is_err());
        message.code = "json.object.duplicate-member@1".to_owned();
        message.category = DiagnosticCategory::Syntax;
        assert!(DiagnosticMessage::from_value(&message.to_value()).is_err());
    }

    #[test]
    fn json5_diagnostics_require_semantic_model_v4() {
        let diagnostic = Diagnostic::new(
            "json5.syntax.invalid-identifier@1",
            DiagnosticCategory::Syntax,
            DiagnosticSeverity::Error,
            None,
            0,
        );
        assert!(
            DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v3())
                .is_err()
        );
        let message =
            DiagnosticMessage::from_core_with_registry(&diagnostic, None, ErrorCodeRegistry::v4())
                .unwrap();
        assert_eq!(message.code, diagnostic.code);
        let contract = crate::ContractId::new("core.diagnostic", 1).unwrap();
        assert!(
            crate::ProtocolMessage::new(
                contract.clone(),
                message.to_value(),
                crate::ContractRegistry::v3(),
            )
            .is_err()
        );
        let envelope = crate::ProtocolMessage::new(
            contract,
            message.to_value(),
            crate::ContractRegistry::v4(),
        )
        .unwrap();
        let limits = crate::ProtocolLimits::default();
        assert_eq!(
            crate::ProtocolMessage::from_json(
                &envelope.to_json(limits).unwrap(),
                limits,
                crate::ContractRegistry::v4(),
            )
            .unwrap(),
            envelope
        );
        assert_eq!(
            crate::ProtocolMessage::from_pvce(
                &envelope.to_pvce(limits).unwrap(),
                limits,
                crate::ContractRegistry::v4(),
            )
            .unwrap(),
            envelope
        );
    }
}
