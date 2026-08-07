//! CLI machine-protocol payloads: envelope, batch plan, and batch result.
//!
//! RFC 0015 §4/§8/§9 freeze `core.cli-output@1`, `core.batch-plan@1`, and
//! `core.batch-result@1` as fixed-field [`consema_core::PortableValue`]
//! records. Every decoder re-validates the cross constraints (closed command
//! and exit-class sets, payload-schema/command consistency, redaction
//! consistency, digest equality, per-status presence rules) instead of
//! trusting the `schema` discriminator, and applies the crate's protocol
//! limits at the transport layer.

use crate::schema::{
    boolean, exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32,
    unsigned_u64,
};
use crate::{
    DiagnosticMessage, EditOperationSummaryMessage, ErrorCodeRegistry, ExitClass, ProtocolError,
    ProtocolErrorKind, ProtocolLimits, SourcePatchMessageV2, decode_json, decode_pvce, encode_json,
    encode_pvce,
};
use consema_core::{BigInteger, ObjectBuilder, PortableValue, SequenceBuilder};
use consema_document::{
    ContentDigest, EditOperationSummary, FormatOperationId, ProfileId, SourcePatch,
    SourcePatchLimits,
};
use std::collections::BTreeMap;

/// One of the eleven formal CLI commands (RFC 0015 §6.1).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CliCommand {
    /// `consema inspect`: file facts and optional parse facts.
    Inspect,
    /// `consema capabilities`: facade capability inventory.
    Capabilities,
    /// `consema query`: native/lossless query results.
    Query,
    /// `consema project`: explicit projection results.
    Project,
    /// `consema materialize`: explicit materialization results.
    Materialize,
    /// `consema convert`: two-phase cross-format conversion.
    Convert,
    /// `consema edit`: single-file structural edit (dry-run by default).
    Edit,
    /// `consema plan`: batch plan manifest.
    Plan,
    /// `consema apply`: batch apply result manifest.
    Apply,
    /// `consema conformance`: embedded self-check suite report.
    Conformance,
    /// `consema explain`: contract/error-code/profile/capability record.
    Explain,
}

impl CliCommand {
    /// Canonical `command` envelope name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Capabilities => "capabilities",
            Self::Query => "query",
            Self::Project => "project",
            Self::Materialize => "materialize",
            Self::Convert => "convert",
            Self::Edit => "edit",
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Conformance => "conformance",
            Self::Explain => "explain",
        }
    }

    /// Parses one canonical command name into the closed command set.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "inspect" => Some(Self::Inspect),
            "capabilities" => Some(Self::Capabilities),
            "query" => Some(Self::Query),
            "project" => Some(Self::Project),
            "materialize" => Some(Self::Materialize),
            "convert" => Some(Self::Convert),
            "edit" => Some(Self::Edit),
            "plan" => Some(Self::Plan),
            "apply" => Some(Self::Apply),
            "conformance" => Some(Self::Conformance),
            "explain" => Some(Self::Explain),
            _ => None,
        }
    }

    /// Payload schemas the command may carry (RFC 0015 §6.1 table).
    #[must_use]
    pub const fn payload_schemas(self) -> &'static [&'static str] {
        match self {
            Self::Inspect => &["cli.inspect@1"],
            Self::Capabilities => &["cli.capabilities@1"],
            Self::Query => &[
                "core.query-result@1",
                "core.ini-query-result@1",
                "core.java-properties-query-result@1",
                "core.yaml-query-result@1",
                "core.graph-query-result@1",
            ],
            Self::Project => &["core.projection-result@1"],
            Self::Materialize => &["core.materialization-result@2"],
            Self::Convert => &["cli.convert@1"],
            Self::Edit => &["cli.edit@1"],
            Self::Plan => &["core.batch-plan@1"],
            Self::Apply => &["core.batch-result@1"],
            Self::Conformance => &["cli.conformance@1"],
            Self::Explain => &["cli.explain@1"],
        }
    }
}

/// Envelope redaction facts (RFC 0015 §11.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redaction {
    redacted: bool,
    count: u64,
}

impl Redaction {
    /// Validates the `redacted == (count > 0)` invariant.
    pub fn new(redacted: bool, count: u64) -> Result<Self, ProtocolError> {
        if redacted != (count > 0) {
            return Err(crate::schema::invalid(
                "$.redaction",
                "redacted must equal (count > 0)",
            ));
        }
        Ok(Self { redacted, count })
    }

    /// Whether any value was replaced by the `$REDACTED$` placeholder.
    #[must_use]
    pub const fn redacted(self) -> bool {
        self.redacted
    }

    /// Number of values replaced in this output.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }
}

/// Full `core.cli-output@1` machine envelope (RFC 0015 §4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOutputMessage {
    command: CliCommand,
    exit_class: ExitClass,
    product_version: String,
    payload: PortableValue,
    diagnostics: Vec<DiagnosticMessage>,
    redaction: Redaction,
}

impl CliOutputMessage {
    /// Validates command/exit-class closure, product-version shape, payload
    /// schema consistency, diagnostic registry binding, and redaction facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: CliCommand,
        exit_class: ExitClass,
        product_version: impl Into<String>,
        payload: PortableValue,
        diagnostics: Vec<DiagnosticMessage>,
        redaction: Redaction,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_registry(
            command,
            exit_class,
            product_version,
            payload,
            diagnostics,
            redaction,
            ErrorCodeRegistry::v7(),
        )
    }

    /// Validates the envelope under one explicit semantic-model registry.
    pub fn new_with_registry(
        command: CliCommand,
        exit_class: ExitClass,
        product_version: impl Into<String>,
        payload: PortableValue,
        diagnostics: Vec<DiagnosticMessage>,
        redaction: Redaction,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let product_version = product_version.into();
        if !is_semantic_version(&product_version) {
            return Err(crate::schema::invalid(
                "$.product_version",
                "expected MAJOR.MINOR.PATCH without leading zeros",
            ));
        }
        validate_payload_schema(&payload, command)?;
        for (index, diagnostic) in diagnostics.iter().enumerate() {
            DiagnosticMessage::from_value_with_registry(&diagnostic.to_value(), registry).map_err(
                |error| {
                    ProtocolError::new(
                        error.kind(),
                        format!("$.diagnostics[{index}]"),
                        error.to_string(),
                    )
                },
            )?;
        }
        Ok(Self {
            command,
            exit_class,
            product_version,
            payload,
            diagnostics,
            redaction,
        })
    }

    /// Command that produced the envelope.
    #[must_use]
    pub const fn command(&self) -> CliCommand {
        self.command
    }

    /// Frozen exit class of the operation.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        self.exit_class
    }

    /// Release version string of the producing CLI.
    #[must_use]
    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    /// Validated command payload.
    #[must_use]
    pub const fn payload(&self) -> &PortableValue {
        &self.payload
    }

    /// Ordered operation diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Redaction facts of this output.
    #[must_use]
    pub const fn redaction(&self) -> Redaction {
        self.redaction
    }

    /// Encodes the fixed `core.cli-output@1` envelope.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.cli-output@1")),
            ("command", PortableValue::string(self.command.name())),
            ("exit_class", PortableValue::string(self.exit_class.name())),
            (
                "product_version",
                PortableValue::string(self.product_version.as_str()),
            ),
            ("payload", self.payload.clone()),
            ("diagnostics", diagnostics.build()),
            (
                "redaction",
                object(vec![
                    (
                        "redacted",
                        PortableValue::boolean(self.redaction.redacted()),
                    ),
                    ("count", integer_u64(self.redaction.count())),
                ]),
            ),
        ])
    }

    /// Strictly decodes `core.cli-output@1` under the semantic-model v7 error
    /// registry.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v7())
    }

    /// Strictly decodes the envelope under one explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.cli-output@1",
            &[
                "schema",
                "command",
                "exit_class",
                "product_version",
                "payload",
                "diagnostics",
                "redaction",
            ],
            "$",
        )?;
        let command = CliCommand::parse(string(fields[1], "$.command")?)
            .ok_or_else(|| crate::schema::invalid("$.command", "unknown command"))?;
        let exit_class = ExitClass::parse(string(fields[2], "$.exit_class")?)
            .ok_or_else(|| crate::schema::invalid("$.exit_class", "unknown exit class"))?;
        let product_version = string(fields[3], "$.product_version")?.to_owned();
        if !is_semantic_version(&product_version) {
            return Err(crate::schema::invalid(
                "$.product_version",
                "expected MAJOR.MINOR.PATCH without leading zeros",
            ));
        }
        validate_payload_schema(fields[4], command)?;
        let diagnostics = sequence(fields[5], "$.diagnostics")?
            .iter()
            .map(|value| DiagnosticMessage::from_value_with_registry(value, registry))
            .collect::<Result<Vec<_>, _>>()?;
        let redaction_fields = exact_fields(fields[6], &["redacted", "count"], "$.redaction")?;
        let redaction = Redaction::new(
            boolean(redaction_fields[0], "$.redaction.redacted")?,
            unsigned_u64(redaction_fields[1], "$.redaction.count")?,
        )?;
        Self::new_with_registry(
            command,
            exit_class,
            product_version,
            fields[4].clone(),
            diagnostics,
            redaction,
            registry,
        )
    }

    /// Encodes the envelope through canonical tagged JSON.
    pub fn to_json(&self, limits: ProtocolLimits) -> Result<Vec<u8>, ProtocolError> {
        encode_json(&self.to_value(), limits)
    }

    /// Decodes canonical tagged JSON and re-validates the envelope.
    pub fn from_json(bytes: &[u8], limits: ProtocolLimits) -> Result<Self, ProtocolError> {
        Self::from_value(&decode_json(bytes, limits)?)
    }

    /// Encodes the envelope through canonical PVCE/1.
    pub fn to_pvce(&self, limits: ProtocolLimits) -> Result<Vec<u8>, ProtocolError> {
        encode_pvce(&self.to_value(), limits)
    }

    /// Decodes canonical PVCE/1 and re-validates the envelope.
    pub fn from_pvce(bytes: &[u8], limits: ProtocolLimits) -> Result<Self, ProtocolError> {
        Self::from_value(&decode_pvce(bytes, limits)?)
    }
}

/// One file-level status in a `core.batch-plan@1` manifest (RFC 0015 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchPlanFileStatus {
    /// The file planned successfully; profile/source_digest/operations/
    /// source_patch are present.
    Planned,
    /// The file failed to plan; failure_code/diagnostics are present.
    Failed,
}

/// One file entry of a `core.batch-plan@1` manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPlanFileEntry {
    path: String,
    status: BatchPlanFileStatus,
    profile: Option<ProfileId>,
    source_digest: Option<ContentDigest>,
    operations: Option<Vec<EditOperationSummaryMessage>>,
    source_patch: Option<SourcePatch>,
    failure_code: Option<String>,
    diagnostics: Option<Vec<DiagnosticMessage>>,
}

impl BatchPlanFileEntry {
    /// Validates the per-status presence rules and the
    /// `source_digest == source_patch.base_digest` cross constraint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl Into<String>,
        status: BatchPlanFileStatus,
        profile: Option<ProfileId>,
        source_digest: Option<ContentDigest>,
        operations: Option<Vec<EditOperationSummaryMessage>>,
        source_patch: Option<SourcePatch>,
        failure_code: Option<String>,
        diagnostics: Option<Vec<DiagnosticMessage>>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let path = path.into();
        if path.is_empty() || path.len() > 1024 {
            return Err(crate::schema::invalid("$.files[].path", "invalid path"));
        }
        if let Some(operations) = &operations {
            for (index, operation) in operations.iter().enumerate() {
                EditOperationSummary::new(operation.operation.clone(), operation.summary.clone())
                    .map_err(|error| {
                    crate::schema::invalid(
                        &format!("$.files[].operations[{index}]"),
                        format!("{error:?}"),
                    )
                })?;
            }
        }
        match status {
            BatchPlanFileStatus::Planned => {
                let (Some(_), Some(source_digest), Some(_), Some(source_patch)) = (
                    profile.as_ref(),
                    source_digest,
                    operations.as_ref(),
                    source_patch.as_ref(),
                ) else {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "planned entries require profile, source_digest, operations, and source_patch",
                    ));
                };
                if failure_code.is_some() || diagnostics.is_some() {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "planned entries cannot carry failure_code or diagnostics",
                    ));
                }
                if source_digest != source_patch.base_digest() {
                    return Err(crate::schema::invalid(
                        "$.files[].source_digest",
                        "source_digest must equal source_patch.base_digest",
                    ));
                }
            }
            BatchPlanFileStatus::Failed => {
                if profile.is_some()
                    || source_digest.is_some()
                    || operations.is_some()
                    || source_patch.is_some()
                {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "failed entries cannot carry planning facts",
                    ));
                }
                if failure_code.as_deref().is_none_or(str::is_empty) {
                    return Err(crate::schema::invalid(
                        "$.files[].failure_code",
                        "failed entries require a failure_code",
                    ));
                }
                if diagnostics.is_none() {
                    return Err(crate::schema::invalid(
                        "$.files[].diagnostics",
                        "failed entries require a diagnostics sequence",
                    ));
                }
            }
        }
        if let Some(diagnostics) = &diagnostics {
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                DiagnosticMessage::from_value_with_registry(&diagnostic.to_value(), registry)
                    .map_err(|error| {
                        ProtocolError::new(
                            error.kind(),
                            format!("$.files[].diagnostics[{index}]"),
                            error.to_string(),
                        )
                    })?;
            }
        }
        Ok(Self {
            path,
            status,
            profile,
            source_digest,
            operations,
            source_patch,
            failure_code,
            diagnostics,
        })
    }

    /// User-given path spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Per-file plan status.
    #[must_use]
    pub const fn status(&self) -> BatchPlanFileStatus {
        self.status
    }

    /// Profile of a planned file.
    #[must_use]
    pub const fn profile(&self) -> Option<&ProfileId> {
        self.profile.as_ref()
    }

    /// Base digest of a planned file; equals `source_patch.base_digest`.
    #[must_use]
    pub const fn source_digest(&self) -> Option<ContentDigest> {
        self.source_digest
    }

    /// Ordered operation summaries of a planned file.
    #[must_use]
    pub fn operations(&self) -> Option<&[EditOperationSummaryMessage]> {
        self.operations.as_deref()
    }

    /// Verifiable source patch of a planned file.
    #[must_use]
    pub const fn source_patch(&self) -> Option<&SourcePatch> {
        self.source_patch.as_ref()
    }

    /// Failure code of a failed file.
    #[must_use]
    pub fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }

    /// Diagnostics of a failed file.
    #[must_use]
    pub fn diagnostics(&self) -> Option<&[DiagnosticMessage]> {
        self.diagnostics.as_deref()
    }
}

/// Full `core.batch-plan@1` manifest (RFC 0015 §8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPlanMessage {
    product_version: String,
    files: Vec<BatchPlanFileEntry>,
}

impl BatchPlanMessage {
    /// Validates the manifest fields and every file entry.
    pub fn new(
        product_version: impl Into<String>,
        files: Vec<BatchPlanFileEntry>,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_registry(product_version, files, ErrorCodeRegistry::v7())
    }

    /// Validates the manifest under one explicit semantic-model registry.
    pub fn new_with_registry(
        product_version: impl Into<String>,
        files: Vec<BatchPlanFileEntry>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let product_version = product_version.into();
        if product_version.is_empty() {
            return Err(crate::schema::invalid(
                "$.product_version",
                "product_version cannot be empty",
            ));
        }
        for (index, entry) in files.iter().enumerate() {
            revalidate_plan_entry(entry, index, registry)?;
        }
        Ok(Self {
            product_version,
            files,
        })
    }

    /// Release version string of the producing CLI.
    #[must_use]
    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    /// File entries in command-line argument order.
    #[must_use]
    pub fn files(&self) -> &[BatchPlanFileEntry] {
        &self.files
    }

    /// Encodes the fixed `core.batch-plan@1` schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        let mut files = SequenceBuilder::new();
        for (index, entry) in self.files.iter().enumerate() {
            files.push(plan_entry_value(entry, index)?);
        }
        Ok(object(vec![
            ("schema", PortableValue::string("core.batch-plan@1")),
            (
                "product_version",
                PortableValue::string(self.product_version.as_str()),
            ),
            ("command", PortableValue::string("plan")),
            ("files", files.build()),
        ]))
    }

    /// Strictly decodes `core.batch-plan@1` under the semantic-model v7 error
    /// registry and default source-patch limits.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v7(), SourcePatchLimits::default())
    }

    /// Strictly decodes the manifest and re-verifies every cross constraint.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
        patch_limits: SourcePatchLimits,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.batch-plan@1",
            &["schema", "product_version", "command", "files"],
            "$",
        )?;
        if string(fields[2], "$.command")? != "plan" {
            return Err(crate::schema::invalid(
                "$.command",
                "expected command \"plan\"",
            ));
        }
        let files = sequence(fields[3], "$.files")?
            .iter()
            .enumerate()
            .map(|(index, item)| parse_plan_entry(item, index, registry, patch_limits))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new_with_registry(string(fields[1], "$.product_version")?, files, registry)
    }
}

/// One file-level status in a `core.batch-result@1` manifest (RFC 0015 §9.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchResultFileStatus {
    /// The file was rewritten and its target digest was verified.
    Completed,
    /// The file failed; failure_code is present.
    Failed,
    /// The file was pending when the manifest was written (interruption).
    Pending,
    /// The current bytes no longer match the planned base digest.
    SkippedStale,
}

/// One result entry of a `core.batch-result@1` manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchResultFileEntry {
    path: String,
    status: BatchResultFileStatus,
    failure_code: Option<String>,
    target_digest: Option<ContentDigest>,
    redacted: bool,
}

impl BatchResultFileEntry {
    /// Validates the per-status presence rules and the closed status set.
    pub fn new(
        path: impl Into<String>,
        status: BatchResultFileStatus,
        failure_code: Option<String>,
        target_digest: Option<ContentDigest>,
        redacted: bool,
    ) -> Result<Self, ProtocolError> {
        let path = path.into();
        if path.is_empty() || path.len() > 1024 {
            return Err(crate::schema::invalid("$.files[].path", "invalid path"));
        }
        match status {
            BatchResultFileStatus::Completed => {
                if failure_code.is_some() || target_digest.is_none() {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "completed entries require a target_digest and no failure_code",
                    ));
                }
            }
            BatchResultFileStatus::Failed | BatchResultFileStatus::SkippedStale => {
                if failure_code.as_deref().is_none_or(str::is_empty) || target_digest.is_some() {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "failed or skipped-stale entries require a failure_code and no target_digest",
                    ));
                }
            }
            BatchResultFileStatus::Pending => {
                if failure_code.is_some() || target_digest.is_some() {
                    return Err(crate::schema::invalid(
                        "$.files[]",
                        "pending entries cannot carry failure_code or target_digest",
                    ));
                }
            }
        }
        Ok(Self {
            path,
            status,
            failure_code,
            target_digest,
            redacted,
        })
    }

    /// User-given path spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Per-file result status.
    #[must_use]
    pub const fn status(&self) -> BatchResultFileStatus {
        self.status
    }

    /// Failure code of failed or skipped-stale files.
    #[must_use]
    pub fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }

    /// Verified target digest of completed files.
    #[must_use]
    pub const fn target_digest(&self) -> Option<ContentDigest> {
        self.target_digest
    }

    /// Whether the file's edit operations matched a redaction key pattern.
    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.redacted
    }
}

/// Full `core.batch-result@1` manifest (RFC 0015 §9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchResultMessage {
    product_version: String,
    files: Vec<BatchResultFileEntry>,
}

impl BatchResultMessage {
    /// Validates the manifest fields and every result entry.
    pub fn new(
        product_version: impl Into<String>,
        files: Vec<BatchResultFileEntry>,
    ) -> Result<Self, ProtocolError> {
        let product_version = product_version.into();
        if product_version.is_empty() {
            return Err(crate::schema::invalid(
                "$.product_version",
                "product_version cannot be empty",
            ));
        }
        Ok(Self {
            product_version,
            files,
        })
    }

    /// Release version string of the producing CLI.
    #[must_use]
    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    /// Result entries in input plan order.
    #[must_use]
    pub fn files(&self) -> &[BatchResultFileEntry] {
        &self.files
    }

    /// Encodes the fixed `core.batch-result@1` schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut files = SequenceBuilder::new();
        for entry in &self.files {
            files.push(result_entry_value(entry));
        }
        object(vec![
            ("schema", PortableValue::string("core.batch-result@1")),
            (
                "product_version",
                PortableValue::string(self.product_version.as_str()),
            ),
            ("command", PortableValue::string("apply")),
            ("files", files.build()),
        ])
    }

    /// Strictly decodes `core.batch-result@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.batch-result@1",
            &["schema", "product_version", "command", "files"],
            "$",
        )?;
        if string(fields[2], "$.command")? != "apply" {
            return Err(crate::schema::invalid(
                "$.command",
                "expected command \"apply\"",
            ));
        }
        let files = sequence(fields[3], "$.files")?
            .iter()
            .enumerate()
            .map(|(index, item)| parse_result_entry(item, &format!("$.files[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(string(fields[1], "$.product_version")?, files)
    }
}

fn validate_payload_schema(
    payload: &PortableValue,
    command: CliCommand,
) -> Result<(), ProtocolError> {
    let entries = payload.as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            "$.payload",
            "payload must be an Object",
        )
    })?;
    let first = entries.first().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::MissingField,
            "$.payload.schema",
            "payload schema is absent",
        )
    })?;
    if first.key() != "schema" {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.payload",
            "schema must be the first field",
        ));
    }
    let schema = string(first.value(), "$.payload.schema")?;
    // `contains` cannot express the short-lived schema borrow against the
    // static schema list, so the equal closure stays explicit.
    #[allow(clippy::manual_contains)]
    if !command
        .payload_schemas()
        .iter()
        .any(|allowed| *allowed == schema)
    {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.payload.schema",
            format!(
                "payload schema {schema} is not published by {}",
                command.name()
            ),
        ));
    }
    Ok(())
}

fn is_semantic_version(version: &str) -> bool {
    let mut segments = version.split('.');
    let (Some(major), Some(minor), Some(patch), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    [major, minor, patch].iter().all(|segment| {
        !segment.is_empty()
            && segment.bytes().all(|byte| byte.is_ascii_digit())
            && (segment.len() == 1 || !segment.starts_with('0'))
    })
}

fn revalidate_plan_entry(
    entry: &BatchPlanFileEntry,
    index: usize,
    registry: ErrorCodeRegistry,
) -> Result<(), ProtocolError> {
    let path = format!("$.files[{index}]");
    match entry.status {
        BatchPlanFileStatus::Planned => {
            let (Some(_), Some(source_digest), Some(_), Some(source_patch)) = (
                entry.profile.as_ref(),
                entry.source_digest,
                entry.operations.as_ref(),
                entry.source_patch.as_ref(),
            ) else {
                return Err(crate::schema::invalid(
                    &path,
                    "planned entries require all planning facts",
                ));
            };
            if source_digest != source_patch.base_digest() {
                return Err(crate::schema::invalid(
                    &format!("{path}.source_digest"),
                    "source_digest must equal source_patch.base_digest",
                ));
            }
        }
        BatchPlanFileStatus::Failed => {
            if entry.failure_code.as_deref().is_none_or(str::is_empty)
                || entry.diagnostics.is_none()
            {
                return Err(crate::schema::invalid(
                    &path,
                    "failed entries require failure_code and diagnostics",
                ));
            }
        }
    }
    if let Some(diagnostics) = &entry.diagnostics {
        for (diagnostic_index, diagnostic) in diagnostics.iter().enumerate() {
            DiagnosticMessage::from_value_with_registry(&diagnostic.to_value(), registry).map_err(
                |error| {
                    ProtocolError::new(
                        error.kind(),
                        format!("{path}.diagnostics[{diagnostic_index}]"),
                        error.to_string(),
                    )
                },
            )?;
        }
    }
    Ok(())
}

fn plan_entry_value(
    entry: &BatchPlanFileEntry,
    index: usize,
) -> Result<PortableValue, ProtocolError> {
    let path = format!("$.files[{index}]");
    let profile = entry
        .profile
        .as_ref()
        .map_or_else(PortableValue::null, |profile| {
            reference_value(profile.id(), profile.version())
        });
    let source_digest = entry
        .source_digest
        .map_or_else(PortableValue::null, digest_value);
    let operations = entry
        .operations
        .as_ref()
        .map_or_else(PortableValue::null, |operations| {
            let mut builder = SequenceBuilder::new();
            for operation in operations {
                let mut summary = ObjectBuilder::new();
                for (name, value) in &operation.summary {
                    summary
                        .insert(name, PortableValue::string(value.as_str()))
                        .expect("summary keys are unique");
                }
                builder.push(object(vec![
                    (
                        "operation",
                        reference_value(operation.operation.id(), operation.operation.version()),
                    ),
                    ("summary", summary.build()),
                ]));
            }
            builder.build()
        });
    let source_patch = entry
        .source_patch
        .as_ref()
        .map_or(Ok(PortableValue::null()), |patch| {
            SourcePatchMessageV2::from_patch(patch)
                .to_value()
                .map_err(|error| {
                    ProtocolError::new(
                        error.kind(),
                        format!("{path}.source_patch"),
                        error.to_string(),
                    )
                })
        })?;
    let failure_code = entry
        .failure_code
        .as_deref()
        .map_or_else(PortableValue::null, PortableValue::string);
    let diagnostics = entry
        .diagnostics
        .as_ref()
        .map_or_else(PortableValue::null, |diagnostics| {
            let mut builder = SequenceBuilder::new();
            for diagnostic in diagnostics {
                builder.push(diagnostic.to_value());
            }
            builder.build()
        });
    Ok(object(vec![
        ("path", PortableValue::string(entry.path.as_str())),
        (
            "status",
            PortableValue::string(match entry.status {
                BatchPlanFileStatus::Planned => "planned",
                BatchPlanFileStatus::Failed => "failed",
            }),
        ),
        ("profile", profile),
        ("source_digest", source_digest),
        ("operations", operations),
        ("source_patch", source_patch),
        ("failure_code", failure_code),
        ("diagnostics", diagnostics),
    ]))
}

fn parse_plan_entry(
    value: &PortableValue,
    index: usize,
    registry: ErrorCodeRegistry,
    patch_limits: SourcePatchLimits,
) -> Result<BatchPlanFileEntry, ProtocolError> {
    let path = format!("$.files[{index}]");
    let fields = exact_fields(
        value,
        &[
            "path",
            "status",
            "profile",
            "source_digest",
            "operations",
            "source_patch",
            "failure_code",
            "diagnostics",
        ],
        &path,
    )?;
    let status = match string(fields[1], &format!("{path}.status"))? {
        "planned" => BatchPlanFileStatus::Planned,
        "failed" => BatchPlanFileStatus::Failed,
        _ => {
            return Err(crate::schema::invalid(
                &format!("{path}.status"),
                "unknown plan file status",
            ));
        }
    };
    let (profile, source_digest, operations, source_patch, failure_code, diagnostics) = match status
    {
        BatchPlanFileStatus::Planned => {
            let profile = parse_profile(fields[2], &format!("{path}.profile"))?;
            let source_digest = parse_digest(fields[3], &format!("{path}.source_digest"))?;
            let operations = sequence(fields[4], &format!("{path}.operations"))?
                .iter()
                .enumerate()
                .map(|(operation_index, operation)| {
                    parse_operation_summary(
                        operation,
                        &format!("{path}.operations[{operation_index}]"),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let decoded_patch = SourcePatchMessageV2::from_value(fields[5], patch_limits)
                .map_err(|error| {
                    ProtocolError::new(
                        error.kind(),
                        format!("{path}.source_patch"),
                        error.to_string(),
                    )
                })?
                .into_patch();
            if fields[6] != &PortableValue::null() || fields[7] != &PortableValue::null() {
                return Err(crate::schema::invalid(
                    &path,
                    "planned entries cannot carry failure_code or diagnostics",
                ));
            }
            (
                Some(profile),
                Some(source_digest),
                Some(operations),
                Some(decoded_patch),
                None,
                None,
            )
        }
        BatchPlanFileStatus::Failed => {
            if fields[2] != &PortableValue::null()
                || fields[3] != &PortableValue::null()
                || fields[4] != &PortableValue::null()
                || fields[5] != &PortableValue::null()
            {
                return Err(crate::schema::invalid(
                    &path,
                    "failed entries cannot carry planning facts",
                ));
            }
            let failure_code = string(fields[6], &format!("{path}.failure_code"))?;
            if failure_code.is_empty() {
                return Err(crate::schema::invalid(
                    &format!("{path}.failure_code"),
                    "failure_code cannot be empty",
                ));
            }
            let diagnostics = sequence(fields[7], &format!("{path}.diagnostics"))?
                .iter()
                .map(|item| DiagnosticMessage::from_value_with_registry(item, registry))
                .collect::<Result<Vec<_>, _>>()?;
            (
                None,
                None,
                None,
                None,
                Some(failure_code.to_owned()),
                Some(diagnostics),
            )
        }
    };
    BatchPlanFileEntry::new(
        string(fields[0], &format!("{path}.path"))?,
        status,
        profile,
        source_digest,
        operations,
        source_patch,
        failure_code,
        diagnostics,
        registry,
    )
}

fn result_entry_value(entry: &BatchResultFileEntry) -> PortableValue {
    object(vec![
        ("path", PortableValue::string(entry.path.as_str())),
        (
            "status",
            PortableValue::string(match entry.status {
                BatchResultFileStatus::Completed => "completed",
                BatchResultFileStatus::Failed => "failed",
                BatchResultFileStatus::Pending => "pending",
                BatchResultFileStatus::SkippedStale => "skipped-stale",
            }),
        ),
        (
            "failure_code",
            entry
                .failure_code
                .as_deref()
                .map_or_else(PortableValue::null, PortableValue::string),
        ),
        (
            "target_digest",
            entry
                .target_digest
                .map_or_else(PortableValue::null, digest_value),
        ),
        ("redacted", PortableValue::boolean(entry.redacted)),
    ])
}

fn parse_result_entry(
    value: &PortableValue,
    path: &str,
) -> Result<BatchResultFileEntry, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "path",
            "status",
            "failure_code",
            "target_digest",
            "redacted",
        ],
        path,
    )?;
    let status = match string(fields[1], &format!("{path}.status"))? {
        "completed" => BatchResultFileStatus::Completed,
        "failed" => BatchResultFileStatus::Failed,
        "pending" => BatchResultFileStatus::Pending,
        "skipped-stale" => BatchResultFileStatus::SkippedStale,
        _ => {
            return Err(crate::schema::invalid(
                &format!("{path}.status"),
                "unknown result file status",
            ));
        }
    };
    let failure_code = if fields[2] == &PortableValue::null() {
        None
    } else {
        Some(string(fields[2], &format!("{path}.failure_code"))?.to_owned())
    };
    let target_digest = if fields[3] == &PortableValue::null() {
        None
    } else {
        Some(parse_digest(fields[3], &format!("{path}.target_digest"))?)
    };
    BatchResultFileEntry::new(
        string(fields[0], &format!("{path}.path"))?,
        status,
        failure_code,
        target_digest,
        boolean(fields[4], &format!("{path}.redacted"))?,
    )
}

fn reference_value(id: &str, version: u32) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(id)),
        (
            "version",
            PortableValue::integer(BigInteger::from(i64::from(version))),
        ),
    ])
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

fn parse_profile(value: &PortableValue, path: &str) -> Result<ProfileId, ProtocolError> {
    let fields = exact_fields(value, &["id", "version"], path)?;
    let reference = crate::ProfileReference::new(
        string(fields[0], &format!("{path}.id"))?,
        unsigned_u32(fields[1], &format!("{path}.version"))?,
    )?;
    Ok(ProfileId::new(reference.id(), reference.version()))
}

fn parse_operation_summary(
    value: &PortableValue,
    path: &str,
) -> Result<EditOperationSummaryMessage, ProtocolError> {
    let fields = exact_fields(value, &["operation", "summary"], path)?;
    let reference = exact_fields(fields[0], &["id", "version"], &format!("{path}.operation"))?;
    let operation = FormatOperationId::new(
        string(reference[0], &format!("{path}.operation.id"))?.to_owned(),
        unsigned_u32(reference[1], &format!("{path}.operation.version"))?,
    );
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
    Ok(EditOperationSummaryMessage { operation, summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContractId, ContractRegistry, ProtocolMessage};
    use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
    use consema_document::{SourceReplacement, SourceSnapshot};
    use std::collections::BTreeMap;

    const RFC_ENVELOPE_JSON: &str = concat!(
        r#"{"schema":"core.portable-value-json@1","value":{"type":"Object","entries":["#,
        r#"{"key":"schema","value":{"type":"String","value":"core.cli-output@1"}},"#,
        r#"{"key":"command","value":{"type":"String","value":"inspect"}},"#,
        r#"{"key":"exit_class","value":{"type":"String","value":"success"}},"#,
        r#"{"key":"product_version","value":{"type":"String","value":"0.12.0"}},"#,
        r#"{"key":"payload","value":{"type":"Object","entries":["#,
        r#"{"key":"schema","value":{"type":"String","value":"cli.inspect@1"}},"#,
        r#"{"key":"path","value":{"type":"String","value":"app.conf"}},"#,
        r#"{"key":"bytes","value":{"type":"Object","entries":["#,
        r#"{"key":"size","value":{"type":"Integer","value":"43"}},"#,
        r#"{"key":"digest","value":{"type":"Object","entries":["#,
        r#"{"key":"algorithm","value":{"type":"String","value":"sha256"}},"#,
        r#"{"key":"hex","value":{"type":"String","value":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}}]}}]}},"#,
        r#"{"key":"bom","value":{"type":"Null"}},"#,
        r#"{"key":"symlink","value":{"type":"Boolean","value":false}},"#,
        r#"{"key":"markers","value":{"type":"Sequence","items":[{"type":"String","value":"[section]"}]}},"#,
        r#"{"key":"candidates","value":{"type":"Sequence","items":[{"type":"Object","entries":["#,
        r#"{"key":"profile","value":{"type":"Object","entries":[{"key":"id","value":{"type":"String","value":"ini.portable"}},{"key":"version","value":{"type":"Integer","value":"1"}}]}},"#,
        r#"{"key":"reason","value":{"type":"String","value":"leading [section] line"}}]}]}},"#,
        r#"{"key":"ambiguous","value":{"type":"Boolean","value":false}},"#,
        r#"{"key":"ambiguity_reasons","value":{"type":"Sequence","items":[]}},"#,
        r#"{"key":"parse","value":{"type":"Null"}}]}},"#,
        r#"{"key":"diagnostics","value":{"type":"Sequence","items":[]}},"#,
        r#"{"key":"redaction","value":{"type":"Object","entries":[{"key":"redacted","value":{"type":"Boolean","value":false}},{"key":"count","value":{"type":"Integer","value":"0"}}]}}]}}"#
    );

    fn rfc_inspect_payload() -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("cli.inspect@1")),
            ("path", PortableValue::string("app.conf")),
            (
                "bytes",
                object(vec![
                    ("size", integer_u64(43)),
                    (
                        "digest",
                        object(vec![
                            ("algorithm", PortableValue::string("sha256")),
                            (
                                "hex",
                                PortableValue::string(
                                    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                                ),
                            ),
                        ]),
                    ),
                ]),
            ),
            ("bom", PortableValue::null()),
            ("symlink", PortableValue::boolean(false)),
            ("markers", {
                let mut markers = SequenceBuilder::new();
                markers.push(PortableValue::string("[section]"));
                markers.build()
            }),
            ("candidates", {
                let mut candidates = SequenceBuilder::new();
                candidates.push(object(vec![
                    (
                        "profile",
                        object(vec![
                            ("id", PortableValue::string("ini.portable")),
                            ("version", PortableValue::integer(BigInteger::from(1))),
                        ]),
                    ),
                    ("reason", PortableValue::string("leading [section] line")),
                ]));
                candidates.build()
            }),
            ("ambiguous", PortableValue::boolean(false)),
            ("ambiguity_reasons", {
                let reasons = SequenceBuilder::new();
                reasons.build()
            }),
            ("parse", PortableValue::null()),
        ])
    }

    fn envelope() -> CliOutputMessage {
        CliOutputMessage::new(
            CliCommand::Inspect,
            ExitClass::Success,
            "0.12.0",
            rfc_inspect_payload(),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap()
    }

    fn base_snapshot() -> SourceSnapshot {
        let mut bytes = vec![b'a'; 16];
        bytes.extend_from_slice(b"oldzzz");
        SourceSnapshot::from_utf8(bytes).unwrap()
    }

    fn planned_entry() -> BatchPlanFileEntry {
        let snapshot = base_snapshot();
        let patch = SourcePatch::create(
            &snapshot,
            vec![SourceReplacement::new(
                16,
                19,
                b"old".to_vec(),
                b"new".to_vec(),
            )],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let mut summary = BTreeMap::new();
        summary.insert("name".to_owned(), "password".to_owned());
        BatchPlanFileEntry::new(
            "app.conf",
            BatchPlanFileStatus::Planned,
            Some(ProfileId::new("ini.portable", 1)),
            Some(patch.base_digest()),
            Some(vec![EditOperationSummaryMessage {
                operation: FormatOperationId::new("ini.edit.set-entry-value", 1),
                summary,
            }]),
            Some(patch),
            None,
            None,
            ErrorCodeRegistry::v7(),
        )
        .unwrap()
    }

    fn failed_entry() -> BatchPlanFileEntry {
        BatchPlanFileEntry::new(
            "broken.conf",
            BatchPlanFileStatus::Failed,
            None,
            None,
            None,
            None,
            Some("ini.parse.malformed-section@1".to_owned()),
            Some(Vec::new()),
            ErrorCodeRegistry::v7(),
        )
        .unwrap()
    }

    fn rfc_target_digest() -> ContentDigest {
        let hex = "9cf4e2b5d1f0c6a3b8e7d2f0a4c6b8e1f3a5c7d9b0e2f4a6c8d0b1e3f5a7c9d2";
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        ContentDigest::from_bytes(bytes)
    }

    #[test]
    fn rfc_envelope_canonical_json_bytes_match_exactly() {
        let limits = ProtocolLimits::default();
        let encoded = envelope().to_json(limits).unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            RFC_ENVELOPE_JSON,
            "RFC 0015 §4.4 envelope bytes drifted"
        );
        let decoded = CliOutputMessage::from_json(&encoded, limits).unwrap();
        assert_eq!(decoded, envelope());
        assert_eq!(decoded.command(), CliCommand::Inspect);
        assert_eq!(decoded.exit_class(), ExitClass::Success);
        assert_eq!(decoded.product_version(), "0.12.0");
        assert!(!decoded.redaction().redacted());
        assert_eq!(decoded.redaction().count(), 0);
        // The same value round-trips through PVCE/1 byte-exactly.
        let pvce = envelope().to_pvce(limits).unwrap();
        assert_eq!(
            CliOutputMessage::from_pvce(&pvce, limits).unwrap(),
            envelope()
        );
        // Canonical JSON and PVCE decode to the same envelope.
        assert_eq!(CliOutputMessage::from_pvce(&pvce, limits).unwrap(), decoded);
    }

    #[test]
    fn rfc_envelope_example_typo_is_strictly_rejected() {
        // The §4.4 example as published contains one spurious `}` inside the
        // candidates sequence close (`"}}]}}]}}` instead of the canonical
        // `"}}]}]}}`), which is not valid JSON. The strict decoder must reject
        // the published literal; the M9 vector pins the canonical bytes.
        let typo = RFC_ENVELOPE_JSON.replacen(
            r#""leading [section] line"}}]}]}}"#,
            r#""leading [section] line"}}]}}]}}"#,
            1,
        );
        assert_ne!(typo, RFC_ENVELOPE_JSON);
        let error =
            CliOutputMessage::from_json(typo.as_bytes(), ProtocolLimits::default()).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidJson);
    }

    #[test]
    fn envelope_command_payload_schema_must_match() {
        // A mismatched payload schema is rejected for the command.
        let error = CliOutputMessage::new(
            CliCommand::Inspect,
            ExitClass::Success,
            "0.12.0",
            object(vec![("schema", PortableValue::string("cli.explain@1"))]),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);

        let error = CliOutputMessage::new(
            CliCommand::Query,
            ExitClass::Success,
            "0.12.0",
            object(vec![("schema", PortableValue::string("cli.inspect@1"))]),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);

        // Every query-result schema listed in RFC 0015 §6.1 is accepted.
        for schema in [
            "core.query-result@1",
            "core.ini-query-result@1",
            "core.java-properties-query-result@1",
            "core.yaml-query-result@1",
            "core.graph-query-result@1",
        ] {
            CliOutputMessage::new(
                CliCommand::Query,
                ExitClass::Success,
                "0.12.0",
                object(vec![("schema", PortableValue::string(schema))]),
                Vec::new(),
                Redaction::new(false, 0).unwrap(),
            )
            .unwrap();
        }

        // A non-object payload is rejected.
        let error = CliOutputMessage::new(
            CliCommand::Query,
            ExitClass::Success,
            "0.12.0",
            PortableValue::string("core.query-result@1"),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::WrongType);

        // The schema must be the first payload field.
        let mut entries = ObjectBuilder::new();
        entries.insert("path", PortableValue::string("x")).unwrap();
        entries
            .insert("schema", PortableValue::string("cli.inspect@1"))
            .unwrap();
        let error = CliOutputMessage::new(
            CliCommand::Inspect,
            ExitClass::Success,
            "0.12.0",
            entries.build(),
            Vec::new(),
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::SchemaMismatch);
    }

    #[test]
    fn envelope_rejects_invalid_product_version_and_redaction() {
        for version in ["0.12", "0.12.0.1", "0.12.01", "00.1.0", "0.12.a", "0..0"] {
            let error = CliOutputMessage::new(
                CliCommand::Inspect,
                ExitClass::Success,
                version,
                rfc_inspect_payload(),
                Vec::new(),
                Redaction::new(false, 0).unwrap(),
            )
            .unwrap_err();
            assert_eq!(error.path(), "$.product_version", "version {version}");
        }
        let error = Redaction::new(true, 0).unwrap_err();
        assert_eq!(error.path(), "$.redaction");
        let error = Redaction::new(false, 3).unwrap_err();
        assert_eq!(error.path(), "$.redaction");
        assert_eq!(Redaction::new(true, 3).unwrap().count(), 3);
    }

    #[test]
    fn envelope_diagnostics_are_bound_to_the_v7_registry() {
        let diagnostic = DiagnosticMessage::from_core_with_registry(
            &Diagnostic::new(
                "cli.limit.file-size@1",
                DiagnosticCategory::Resource,
                DiagnosticSeverity::Error,
                None,
                0,
            ),
            None,
            ErrorCodeRegistry::v7(),
        )
        .unwrap();
        let message = CliOutputMessage::new(
            CliCommand::Inspect,
            ExitClass::Limit,
            "0.12.0",
            rfc_inspect_payload(),
            vec![diagnostic],
            Redaction::new(false, 0).unwrap(),
        )
        .unwrap();
        let decoded = CliOutputMessage::from_value(&message.to_value()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.diagnostics()[0].code, "cli.limit.file-size@1");
    }

    #[test]
    fn envelope_registered_contract_can_be_wrapped_as_protocol_message() {
        // core.cli-output@1 is registered in v7 and must be envelopeable.
        let message = ProtocolMessage::new(
            ContractId::new("core.cli-output", 1).unwrap(),
            envelope().to_value(),
            ContractRegistry::v7(),
        )
        .unwrap();
        let limits = ProtocolLimits::default();
        assert_eq!(
            ProtocolMessage::from_json(
                &message.to_json(limits).unwrap(),
                limits,
                ContractRegistry::v7(),
            )
            .unwrap(),
            message
        );
        assert_eq!(
            ProtocolMessage::from_pvce(
                &message.to_pvce(limits).unwrap(),
                limits,
                ContractRegistry::v7(),
            )
            .unwrap(),
            message
        );
    }

    #[test]
    fn batch_plan_notation_round_trips_on_both_transports() {
        let plan = BatchPlanMessage::new("0.12.0", vec![planned_entry(), failed_entry()]).unwrap();
        let value = plan.to_value().unwrap();
        let decoded = BatchPlanMessage::from_value(&value).unwrap();
        assert_eq!(decoded, plan);
        let limits = ProtocolLimits::default();
        let json = encode_json(&value, limits).unwrap();
        let decoded_json =
            BatchPlanMessage::from_value(&decode_json(&json, limits).unwrap()).unwrap();
        assert_eq!(decoded_json, plan);
        let pvce = encode_pvce(&value, limits).unwrap();
        let decoded_pvce =
            BatchPlanMessage::from_value(&decode_pvce(&pvce, limits).unwrap()).unwrap();
        assert_eq!(decoded_pvce, plan);
        // RFC 0015 §8.2: command is fixed to "plan".
        let fields = value.as_object().unwrap();
        let command = fields
            .iter()
            .find(|entry| entry.key() == "command")
            .unwrap()
            .value();
        assert_eq!(command.as_string(), Some("plan"));
    }

    #[test]
    fn batch_plan_cross_constraints_are_enforced() {
        let snapshot = base_snapshot();
        let patch = SourcePatch::create(
            &snapshot,
            vec![SourceReplacement::new(
                16,
                19,
                b"old".to_vec(),
                b"new".to_vec(),
            )],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        // source_digest != base_digest is rejected.
        let error = BatchPlanFileEntry::new(
            "app.conf",
            BatchPlanFileStatus::Planned,
            Some(ProfileId::new("ini.portable", 1)),
            Some(patch.target_digest()),
            Some(Vec::new()),
            Some(patch.clone()),
            None,
            None,
            ErrorCodeRegistry::v7(),
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[].source_digest");

        // A planned entry cannot carry failure facts.
        let error = BatchPlanFileEntry::new(
            "app.conf",
            BatchPlanFileStatus::Planned,
            Some(ProfileId::new("ini.portable", 1)),
            Some(patch.base_digest()),
            Some(Vec::new()),
            Some(patch),
            Some("ini.parse.malformed-line@1".to_owned()),
            None,
            ErrorCodeRegistry::v7(),
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[]");

        // A failed entry needs failure_code and diagnostics.
        let error = BatchPlanFileEntry::new(
            "broken.conf",
            BatchPlanFileStatus::Failed,
            None,
            None,
            None,
            None,
            None,
            Some(Vec::new()),
            ErrorCodeRegistry::v7(),
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[].failure_code");

        // Failed entries cannot carry planning facts.
        let error = BatchPlanFileEntry::new(
            "broken.conf",
            BatchPlanFileStatus::Failed,
            Some(ProfileId::new("ini.portable", 1)),
            None,
            None,
            None,
            Some("ini.parse.malformed-section@1".to_owned()),
            Some(Vec::new()),
            ErrorCodeRegistry::v7(),
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[]");

        // The manifest rejects a non-plan command.
        let mut value = BatchPlanMessage::new("0.12.0", Vec::new())
            .unwrap()
            .to_value()
            .unwrap();
        let entries = value.as_object().unwrap();
        let mut builder = ObjectBuilder::new();
        for field in entries {
            let replacement = if field.key() == "command" {
                PortableValue::string("apply")
            } else {
                field.value().clone()
            };
            builder.insert(field.key(), replacement).unwrap();
        }
        value = builder.build();
        let error = BatchPlanMessage::from_value(&value).unwrap_err();
        assert_eq!(error.path(), "$.command");
    }

    #[test]
    fn batch_result_notation_round_trips_with_all_statuses() {
        let completed = BatchResultFileEntry::new(
            "app.conf",
            BatchResultFileStatus::Completed,
            None,
            Some(rfc_target_digest()),
            true,
        )
        .unwrap();
        let failed = BatchResultFileEntry::new(
            "broken.conf",
            BatchResultFileStatus::Failed,
            Some("core.source.patch-original-mismatch@1".to_owned()),
            None,
            false,
        )
        .unwrap();
        let stale = BatchResultFileEntry::new(
            "stale.conf",
            BatchResultFileStatus::SkippedStale,
            Some("core.source.patch-base-mismatch@1".to_owned()),
            None,
            false,
        )
        .unwrap();
        let pending = BatchResultFileEntry::new(
            "pending.conf",
            BatchResultFileStatus::Pending,
            None,
            None,
            false,
        )
        .unwrap();
        let result =
            BatchResultMessage::new("0.12.0", vec![completed, failed, stale, pending]).unwrap();
        let value = result.to_value();
        let decoded = BatchResultMessage::from_value(&value).unwrap();
        assert_eq!(decoded, result);
        let limits = ProtocolLimits::default();
        let json = encode_json(&value, limits).unwrap();
        assert_eq!(
            BatchResultMessage::from_value(&decode_json(&json, limits).unwrap()).unwrap(),
            result
        );
        let pvce = encode_pvce(&value, limits).unwrap();
        assert_eq!(
            BatchResultMessage::from_value(&decode_pvce(&pvce, limits).unwrap()).unwrap(),
            result
        );
        let fields = value.as_object().unwrap();
        let command = fields
            .iter()
            .find(|entry| entry.key() == "command")
            .unwrap()
            .value();
        assert_eq!(command.as_string(), Some("apply"));
        // RFC 0015 §9.5 completed entry facts.
        let entry = &decoded.files()[0];
        assert_eq!(entry.path(), "app.conf");
        assert_eq!(entry.status(), BatchResultFileStatus::Completed);
        assert_eq!(entry.failure_code(), None);
        assert_eq!(entry.target_digest(), Some(rfc_target_digest()));
        assert!(entry.redacted());
    }

    #[test]
    fn batch_result_status_presence_rules_are_enforced() {
        // completed requires a target digest and no failure code.
        let error = BatchResultFileEntry::new(
            "app.conf",
            BatchResultFileStatus::Completed,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[]");
        let error = BatchResultFileEntry::new(
            "app.conf",
            BatchResultFileStatus::Completed,
            Some("cli.write.io@1".to_owned()),
            Some(rfc_target_digest()),
            false,
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[]");

        // failed/skipped-stale require a failure code and no target digest.
        for status in [
            BatchResultFileStatus::Failed,
            BatchResultFileStatus::SkippedStale,
        ] {
            let error = BatchResultFileEntry::new("x.conf", status, None, None, false).unwrap_err();
            assert_eq!(error.path(), "$.files[]");
            let error = BatchResultFileEntry::new(
                "x.conf",
                status,
                Some("cli.write.io@1".to_owned()),
                Some(rfc_target_digest()),
                false,
            )
            .unwrap_err();
            assert_eq!(error.path(), "$.files[]");
        }

        // pending carries neither field.
        let error = BatchResultFileEntry::new(
            "p.conf",
            BatchResultFileStatus::Pending,
            Some("cli.write.io@1".to_owned()),
            None,
            false,
        )
        .unwrap_err();
        assert_eq!(error.path(), "$.files[]");

        // An unknown status is rejected by the decoder.
        let value = object(vec![
            ("path", PortableValue::string("x.conf")),
            ("status", PortableValue::string("committed")),
            ("failure_code", PortableValue::null()),
            ("target_digest", PortableValue::null()),
            ("redacted", PortableValue::boolean(false)),
        ]);
        let error = parse_result_entry(&value, "$.files[0]").unwrap_err();
        assert_eq!(error.path(), "$.files[0].status");
    }
}
