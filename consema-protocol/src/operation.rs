//! Format operation discovery and dry-run edit-plan wire contracts.

use crate::schema::{
    boolean, exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32,
    unsigned_u64,
};
use crate::{ContractId, DiagnosticMessage, ErrorCodeRegistry, ProtocolError, ProtocolErrorKind};
use consema_core::{ObjectBuilder, PortableValue, SequenceBuilder};
use consema_document::{
    ContentDigest, EditOperationSummary, EditPlan, FormatOperationDescriptor, FormatOperationId,
    FormatOperationRegistry, OperationArgumentDescriptor, OperationArgumentKind, OperationSupport,
    OperationTargetRoleId, ProfileId, SourceReplacement,
};
use std::collections::BTreeMap;

/// Transferable `core.format-operation-registry@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatOperationRegistryMessage {
    registry: FormatOperationRegistry,
}

impl FormatOperationRegistryMessage {
    /// Copies one already validated registry.
    #[must_use]
    pub fn from_registry(registry: &FormatOperationRegistry) -> Self {
        Self {
            registry: registry.clone(),
        }
    }

    /// Validated operation registry.
    #[must_use]
    pub const fn registry(&self) -> &FormatOperationRegistry {
        &self.registry
    }

    /// Encodes the fixed discovery schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut operations = SequenceBuilder::new();
        for operation in self.registry.operations() {
            let mut arguments = SequenceBuilder::new();
            for argument in operation.arguments() {
                arguments.push(object(vec![
                    ("name", PortableValue::string(argument.name())),
                    (
                        "kind",
                        PortableValue::string(argument_kind_name(argument.kind())),
                    ),
                    ("required", PortableValue::boolean(argument.required())),
                ]));
            }
            operations.push(object(vec![
                (
                    "operation",
                    reference_value(operation.id().id(), operation.id().version()),
                ),
                (
                    "target_role",
                    reference_value(
                        operation.target_role().id(),
                        operation.target_role().version(),
                    ),
                ),
                ("arguments", arguments.build()),
                (
                    "support",
                    PortableValue::string(support_name(operation.support())),
                ),
            ]));
        }
        object(vec![
            (
                "schema",
                PortableValue::string("core.format-operation-registry@1"),
            ),
            ("profile", profile_value(self.registry.profile())),
            ("operations", operations.build()),
        ])
    }

    /// Strictly decodes and revalidates IDs, schemas, order, and uniqueness.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.format-operation-registry@1",
            &["schema", "profile", "operations"],
            "$",
        )?;
        let profile = parse_profile(fields[1], "$.profile")?;
        let operations = sequence(fields[2], "$.operations")?
            .iter()
            .enumerate()
            .map(|(index, operation)| parse_operation(operation, &format!("$.operations[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let registry = FormatOperationRegistry::new(profile, operations)
            .map_err(|error| crate::schema::invalid("$.operations", format!("{error:?}")))?;
        Ok(Self { registry })
    }
}

/// One transferable content-free edit operation summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditOperationSummaryMessage {
    /// Exact operation ID/version.
    pub operation: FormatOperationId,
    /// Stable sorted safe summary values.
    pub summary: BTreeMap<String, String>,
}

/// Transferable `core.edit-plan@1` dry-run facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditPlanMessage {
    source_id: String,
    base_digest: ContentDigest,
    profile: ProfileId,
    operations: Vec<EditOperationSummaryMessage>,
    replacements: Vec<SourceReplacement>,
    target_digest: ContentDigest,
    report: Vec<DiagnosticMessage>,
}

impl EditPlanMessage {
    /// Externalizes a complete local plan without serializing process-local identities.
    pub fn from_plan(plan: &EditPlan) -> Result<Self, ProtocolError> {
        let report = plan
            .report()
            .iter()
            .map(|diagnostic| {
                DiagnosticMessage::from_core_with_registry(
                    diagnostic,
                    Some(plan.source_id().as_str()),
                    ErrorCodeRegistry::v3(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            plan.source_id().as_str(),
            plan.base_digest(),
            plan.profile().clone(),
            plan.operations()
                .iter()
                .map(|operation| EditOperationSummaryMessage {
                    operation: operation.operation().clone(),
                    summary: operation.arguments().clone(),
                })
                .collect(),
            plan.replacements().to_vec(),
            plan.target_digest(),
            report,
        )
    }

    /// Validates all external dry-run fields and replacement preconditions.
    pub fn new(
        source_id: impl Into<String>,
        base_digest: ContentDigest,
        profile: ProfileId,
        operations: Vec<EditOperationSummaryMessage>,
        replacements: Vec<SourceReplacement>,
        target_digest: ContentDigest,
        report: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        let source_id = source_id.into();
        if source_id.is_empty() || source_id.len() > 1024 {
            return Err(crate::schema::invalid("$.source_id", "invalid source ID"));
        }
        for (index, operation) in operations.iter().enumerate() {
            ContractId::new(operation.operation.id(), operation.operation.version())?;
            EditOperationSummary::new(operation.operation.clone(), operation.summary.clone())
                .map_err(|error| {
                    crate::schema::invalid(&format!("$.operations[{index}]"), format!("{error:?}"))
                })?;
        }
        validate_replacements(&replacements)?;
        if replacements.is_empty() && base_digest != target_digest {
            return Err(crate::schema::invalid(
                "$.target_digest",
                "an empty replacement set cannot change the content digest",
            ));
        }
        for event in &report {
            DiagnosticMessage::from_value_with_registry(
                &event.to_value(),
                ErrorCodeRegistry::v3(),
            )?;
            if event
                .primary
                .as_ref()
                .is_some_and(|location| location.source_id() != source_id)
                || event
                    .related
                    .iter()
                    .any(|related| related.location.source_id() != source_id)
                || event
                    .fixes
                    .iter()
                    .filter_map(|fix| fix.location.as_ref())
                    .any(|location| location.source_id() != source_id)
            {
                return Err(crate::schema::invalid(
                    "$.report.location.source_id",
                    "all edit report locations must bind the plan source",
                ));
            }
        }
        Ok(Self {
            source_id,
            base_digest,
            profile,
            operations,
            replacements,
            target_digest,
            report,
        })
    }

    /// Caller-stable source ID.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Required base digest.
    #[must_use]
    pub const fn base_digest(&self) -> ContentDigest {
        self.base_digest
    }

    /// Exact edit profile.
    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Ordered operation summaries.
    #[must_use]
    pub fn operations(&self) -> &[EditOperationSummaryMessage] {
        &self.operations
    }

    /// Exact replacement facts.
    #[must_use]
    pub fn replacements(&self) -> &[SourceReplacement] {
        &self.replacements
    }

    /// Precomputed target digest.
    #[must_use]
    pub const fn target_digest(&self) -> ContentDigest {
        self.target_digest
    }

    /// Ordered edit report.
    #[must_use]
    pub fn report(&self) -> &[DiagnosticMessage] {
        &self.report
    }

    /// Encodes the fixed dry-run plan schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        let mut operations = SequenceBuilder::new();
        for operation in &self.operations {
            let mut summary = ObjectBuilder::new();
            for (name, value) in &operation.summary {
                summary
                    .insert(name, PortableValue::string(value.as_str()))
                    .expect("summary keys are unique");
            }
            operations.push(object(vec![
                (
                    "operation",
                    reference_value(operation.operation.id(), operation.operation.version()),
                ),
                ("summary", summary.build()),
            ]));
        }
        let mut replacements = SequenceBuilder::new();
        for (index, replacement) in self.replacements.iter().enumerate() {
            replacements.push(replacement_value(replacement, index)?);
        }
        let mut report = SequenceBuilder::new();
        for diagnostic in &self.report {
            report.push(diagnostic.to_value());
        }
        Ok(object(vec![
            ("schema", PortableValue::string("core.edit-plan@1")),
            ("source_id", PortableValue::string(self.source_id.as_str())),
            ("base_digest", digest_value(self.base_digest)),
            ("profile", profile_value(&self.profile)),
            ("operations", operations.build()),
            ("replacements", replacements.build()),
            ("target_digest", digest_value(self.target_digest)),
            ("report", report.build()),
        ]))
    }

    /// Strictly decodes and revalidates a dry-run plan.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.edit-plan@1",
            &[
                "schema",
                "source_id",
                "base_digest",
                "profile",
                "operations",
                "replacements",
                "target_digest",
                "report",
            ],
            "$",
        )?;
        let operations = sequence(fields[4], "$.operations")?
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                parse_operation_summary(operation, &format!("$.operations[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let replacements = sequence(fields[5], "$.replacements")?
            .iter()
            .enumerate()
            .map(|(index, replacement)| {
                parse_replacement(replacement, &format!("$.replacements[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let report = sequence(fields[7], "$.report")?
            .iter()
            .map(|event| {
                DiagnosticMessage::from_value_with_registry(event, ErrorCodeRegistry::v3())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            string(fields[1], "$.source_id")?,
            parse_digest(fields[2], "$.base_digest")?,
            parse_profile(fields[3], "$.profile")?,
            operations,
            replacements,
            parse_digest(fields[6], "$.target_digest")?,
            report,
        )
    }
}

fn parse_operation(
    value: &PortableValue,
    path: &str,
) -> Result<FormatOperationDescriptor, ProtocolError> {
    let fields = exact_fields(
        value,
        &["operation", "target_role", "arguments", "support"],
        path,
    )?;
    let (operation_id, operation_version) =
        parse_reference(fields[0], &format!("{path}.operation"))?;
    let (role_id, role_version) = parse_reference(fields[1], &format!("{path}.target_role"))?;
    let arguments = sequence(fields[2], &format!("{path}.arguments"))?
        .iter()
        .enumerate()
        .map(|(index, argument)| parse_argument(argument, &format!("{path}.arguments[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FormatOperationDescriptor::new(
        FormatOperationId::new(operation_id, operation_version),
        OperationTargetRoleId::new(role_id, role_version),
        arguments,
        parse_support(string(fields[3], &format!("{path}.support"))?, path)?,
    ))
}

fn parse_argument(
    value: &PortableValue,
    path: &str,
) -> Result<OperationArgumentDescriptor, ProtocolError> {
    let fields = exact_fields(value, &["name", "kind", "required"], path)?;
    Ok(OperationArgumentDescriptor::new(
        string(fields[0], &format!("{path}.name"))?,
        parse_argument_kind(string(fields[1], &format!("{path}.kind"))?, path)?,
        boolean(fields[2], &format!("{path}.required"))?,
    ))
}

fn parse_operation_summary(
    value: &PortableValue,
    path: &str,
) -> Result<EditOperationSummaryMessage, ProtocolError> {
    let fields = exact_fields(value, &["operation", "summary"], path)?;
    let (id, version) = parse_reference(fields[0], &format!("{path}.operation"))?;
    let entries = fields[1].as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.summary"),
            "expected Object",
        )
    })?;
    let summary = entries
        .iter()
        .map(|entry| {
            Ok((
                entry.key().to_owned(),
                string(entry.value(), &format!("{path}.summary.{}", entry.key()))?.to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
    Ok(EditOperationSummaryMessage {
        operation: FormatOperationId::new(id, version),
        summary,
    })
}

fn replacement_value(
    replacement: &SourceReplacement,
    index: usize,
) -> Result<PortableValue, ProtocolError> {
    let path = format!("$.replacements[{index}]");
    let old_start = u64::try_from(replacement.old_start())
        .map_err(|_| crate::schema::invalid(&path, "old_start exceeds u64"))?;
    let old_end = u64::try_from(replacement.old_end())
        .map_err(|_| crate::schema::invalid(&path, "old_end exceeds u64"))?;
    Ok(object(vec![
        ("old_start", integer_u64(old_start)),
        ("old_end", integer_u64(old_end)),
        ("original", PortableValue::bytes(replacement.original())),
        (
            "replacement",
            PortableValue::bytes(replacement.replacement()),
        ),
        (
            "redact_original",
            PortableValue::boolean(replacement.redact_original()),
        ),
        (
            "redact_replacement",
            PortableValue::boolean(replacement.redact_replacement()),
        ),
    ]))
}

fn parse_replacement(
    value: &PortableValue,
    path: &str,
) -> Result<SourceReplacement, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "old_start",
            "old_end",
            "original",
            "replacement",
            "redact_original",
            "redact_replacement",
        ],
        path,
    )?;
    Ok(SourceReplacement::new(
        usize::try_from(unsigned_u64(fields[0], &format!("{path}.old_start"))?)
            .map_err(|_| crate::schema::invalid(path, "old_start exceeds usize"))?,
        usize::try_from(unsigned_u64(fields[1], &format!("{path}.old_end"))?)
            .map_err(|_| crate::schema::invalid(path, "old_end exceeds usize"))?,
        bytes(fields[2], &format!("{path}.original"))?,
        bytes(fields[3], &format!("{path}.replacement"))?,
    )
    .with_original_redacted(boolean(fields[4], &format!("{path}.redact_original"))?)
    .with_replacement_redacted(boolean(fields[5], &format!("{path}.redact_replacement"))?))
}

fn validate_replacements(replacements: &[SourceReplacement]) -> Result<(), ProtocolError> {
    let mut previous = None::<&SourceReplacement>;
    for (index, replacement) in replacements.iter().enumerate() {
        if replacement.old_start() > replacement.old_end()
            || replacement.original().len() != replacement.old_end() - replacement.old_start()
        {
            return Err(crate::schema::invalid(
                &format!("$.replacements[{index}]"),
                "replacement range and original bytes disagree",
            ));
        }
        if let Some(previous) = previous {
            let duplicate_insertion = replacement.old_start() == replacement.old_end()
                && previous.old_start() == previous.old_end()
                && replacement.old_start() == previous.old_start();
            if duplicate_insertion
                || (replacement.old_start(), replacement.old_end())
                    <= (previous.old_start(), previous.old_end())
                || replacement.old_start() < previous.old_end()
            {
                return Err(crate::schema::invalid(
                    "$.replacements",
                    "replacements are not canonically ordered and non-overlapping",
                ));
            }
        }
        previous = Some(replacement);
    }
    Ok(())
}

fn reference_value(id: &str, version: u32) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(id)),
        (
            "version",
            PortableValue::integer(consema_core::BigInteger::from(i64::from(version))),
        ),
    ])
}

fn profile_value(profile: &ProfileId) -> PortableValue {
    reference_value(profile.id(), profile.version())
}

fn parse_reference(value: &PortableValue, path: &str) -> Result<(String, u32), ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    let reference = ContractId::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )?;
    Ok((reference.id().to_owned(), reference.version()))
}

fn parse_profile(value: &PortableValue, path: &str) -> Result<ProfileId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    let reference = crate::ProfileReference::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )?;
    Ok(ProfileId::new(reference.id(), reference.version()))
}

fn digest_value(digest: ContentDigest) -> PortableValue {
    object(vec![
        ("algorithm", PortableValue::string(digest.algorithm())),
        ("hex", PortableValue::string(digest.to_hex())),
    ])
}

fn parse_digest(value: &PortableValue, path: &str) -> Result<ContentDigest, ProtocolError> {
    let fields = exact_fields(value, &["algorithm", "hex"], path)?;
    if string(fields[0], &format!("{path}.algorithm"))? != "sha256" {
        return Err(crate::schema::invalid(path, "expected sha256"));
    }
    let hex = string(fields[1], &format!("{path}.hex"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::schema::invalid(path, "invalid lowercase sha256"));
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| crate::schema::invalid(path, "invalid sha256"))?;
    }
    Ok(ContentDigest::from_bytes(bytes))
}

fn bytes(value: &PortableValue, path: &str) -> Result<Vec<u8>, ProtocolError> {
    value
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Bytes"))
}

const fn argument_kind_name(kind: OperationArgumentKind) -> &'static str {
    match kind {
        OperationArgumentKind::NodeRef => "NodeRef",
        OperationArgumentKind::String => "String",
        OperationArgumentKind::PortableValue => "PortableValue",
        OperationArgumentKind::Placement => "Placement",
        OperationArgumentKind::ExactBytes => "ExactBytes",
        OperationArgumentKind::RepresentationPolicy => "RepresentationPolicy",
    }
}

fn parse_argument_kind(value: &str, path: &str) -> Result<OperationArgumentKind, ProtocolError> {
    match value {
        "NodeRef" => Ok(OperationArgumentKind::NodeRef),
        "String" => Ok(OperationArgumentKind::String),
        "PortableValue" => Ok(OperationArgumentKind::PortableValue),
        "Placement" => Ok(OperationArgumentKind::Placement),
        "ExactBytes" => Ok(OperationArgumentKind::ExactBytes),
        "RepresentationPolicy" => Ok(OperationArgumentKind::RepresentationPolicy),
        _ => Err(crate::schema::invalid(
            path,
            "unknown operation argument kind",
        )),
    }
}

const fn support_name(support: OperationSupport) -> &'static str {
    match support {
        OperationSupport::Supported => "Supported",
        OperationSupport::ExistingTypedCapability => "ExistingTypedCapability",
        OperationSupport::Unsupported => "Unsupported",
    }
}

fn parse_support(value: &str, path: &str) -> Result<OperationSupport, ProtocolError> {
    match value {
        "Supported" => Ok(OperationSupport::Supported),
        "ExistingTypedCapability" => Ok(OperationSupport::ExistingTypedCapability),
        "Unsupported" => Ok(OperationSupport::Unsupported),
        _ => Err(crate::schema::invalid(path, "unknown operation support")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{
        FormatOperationRegistry, OperationArgumentDescriptor, OperationArgumentKind,
    };

    #[test]
    fn operation_registry_round_trip_revalidates_sorted_contracts() {
        let registry = FormatOperationRegistry::new(
            ProfileId::new("json.strict", 1),
            vec![FormatOperationDescriptor::new(
                FormatOperationId::new("json.edit.remove-member", 1),
                OperationTargetRoleId::new("json.object-member", 1),
                vec![OperationArgumentDescriptor::new(
                    "target",
                    OperationArgumentKind::NodeRef,
                    true,
                )],
                OperationSupport::Supported,
            )],
        )
        .unwrap();
        let message = FormatOperationRegistryMessage::from_registry(&registry);
        assert_eq!(
            FormatOperationRegistryMessage::from_value(&message.to_value()).unwrap(),
            message
        );
    }

    #[test]
    fn empty_edit_plan_round_trip_preserves_exact_digests() {
        let digest = ContentDigest::of(b"unchanged");
        let message = EditPlanMessage::new(
            "source:one",
            digest,
            ProfileId::new("json.strict", 1),
            Vec::new(),
            Vec::new(),
            digest,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            EditPlanMessage::from_value(&message.to_value().unwrap()).unwrap(),
            message
        );
    }
}
