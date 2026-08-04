use crate::{
    Document, IniEncodingSelection, IniEntry, IniParseLimits, IniProfile, IniQuoteStyle,
    IniSyntaxKind, materialization, parse,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId, FormatOperationId,
    FormationStatus, MaterializationFailure, NodeMapping, NodeMappingStatus, NodeRef, NodeRole,
    SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits, Span,
    UntouchedByteProof,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// Explicit semantic value representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must use an exact literal operation instead.
    ExactLiteral,
    /// Retain the target's compatible quote or multiline representation.
    PreserveCompatible,
    /// Use the selected INI profile's frozen canonical value representation.
    CanonicalForProfile,
    /// Preserve when compatible, otherwise use canonical representation and report fallback.
    PreserveElseCanonical,
}

/// One INI value replacement bound to a transaction base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueReplacement {
    /// Replaces the stored string under an explicit representation policy.
    Semantic {
        /// Exact INI entry target.
        target: NodeRef,
        /// New stored string value.
        value: String,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replaces the exact profile-specific value representation bytes.
    Literal {
        /// Exact INI entry target.
        target: NodeRef,
        /// Raw bytes in the base document's selected source encoding.
        literal: Arc<[u8]>,
    },
}

impl ValueReplacement {
    const fn target(&self) -> NodeRef {
        match self {
            Self::Semantic { target, .. } | Self::Literal { target, .. } => *target,
        }
    }
}

/// One typed INI edit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Replaces one exact entry's value.
    ReplaceValue(ValueReplacement),
}

/// Immutable edit transaction; every operation resolves against one base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditTransaction {
    base: SnapshotIdentity,
    operations: Arc<[EditOperation]>,
}

impl EditTransaction {
    /// Base snapshot identity.
    #[must_use]
    pub const fn base_snapshot(&self) -> SnapshotIdentity {
        self.base
    }

    /// Ordered declared operations.
    #[must_use]
    pub fn operations(&self) -> &[EditOperation] {
        &self.operations
    }
}

/// Builder for one immutable edit transaction.
#[derive(Debug)]
pub struct EditTransactionBuilder {
    base: SnapshotIdentity,
    operations: Vec<EditOperation>,
}

impl EditTransactionBuilder {
    /// Binds a new transaction to one immutable INI document.
    #[must_use]
    pub fn new(document: &Document) -> Self {
        Self {
            base: document.snapshot_identity(),
            operations: Vec::new(),
        }
    }

    /// Adds one semantic stored-value replacement.
    pub fn semantic_value(
        &mut self,
        target: NodeRef,
        value: impl Into<String>,
        policy: RepresentationPolicy,
    ) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceValue(ValueReplacement::Semantic {
                target,
                value: value.into(),
                policy,
            }));
        self
    }

    /// Adds one exact raw value-representation replacement.
    pub fn literal_value(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceValue(ValueReplacement::Literal {
                target,
                literal: literal.into(),
            }));
        self
    }

    /// Completes the request; validation occurs atomically at commit or dry-run.
    #[must_use]
    pub fn build(self) -> EditTransaction {
        EditTransaction {
            base: self.base,
            operations: Arc::from(self.operations),
        }
    }
}

/// Atomic edit success.
#[derive(Clone, Debug)]
pub struct EditCommit {
    /// New immutable document.
    pub document: Document,
    /// Complete old-to-new change facts.
    pub change_set: ChangeSet,
    /// Replayable exact raw-byte patch.
    pub source_patch: SourcePatch,
    /// Verifiable evidence for every byte outside the replacement set.
    pub untouched_proof: UntouchedByteProof,
}

/// Stable edit validation or commit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditFailure {
    /// Edits are forbidden on a recovered document.
    RecoveredDocument,
    /// Transaction or target belongs to another snapshot.
    WrongSnapshot,
    /// Target is not an INI entry.
    WrongRole,
    /// More than one operation names the same exact target.
    DuplicateTarget,
    /// Prepared value ownership intervals overlap.
    OverlappingOwnership,
    /// `PreserveCompatible` cannot retain the target representation.
    RepresentationIncompatible,
    /// `ExactLiteral` was requested without literal bytes.
    ExactLiteralRequiresLiteralOperation,
    /// The semantic string cannot be represented by the selected profile.
    UnrepresentableValue,
    /// The replacement cannot be encoded exactly in the source encoding.
    EncodingUnrepresentable,
    /// Literal bytes do not form exactly one value at the target.
    InvalidLiteral,
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement bytes could not form one complete document under the original contract.
    NewDocumentFormationFailed,
}

impl Document {
    /// Atomically commits all declared value replacements.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if self.formation_status() != FormationStatus::Complete {
            return Err(EditFailure::RecoveredDocument);
        }
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        let mut targets = HashSet::new();
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for operation in transaction.operations.iter() {
            let EditOperation::ReplaceValue(replacement) = operation;
            if !targets.insert(replacement.target()) {
                return Err(EditFailure::DuplicateTarget);
            }
            prepared.push(self.prepare_value(replacement, &mut diagnostics)?);
        }
        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        for pair in prepared.windows(2) {
            if pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
                || pair[0].old_span == pair[1].old_span
            {
                return Err(EditFailure::OverlappingOwnership);
            }
        }
        let contains_literal = prepared.iter().any(|edit| edit.literal);

        let target_len = prepared
            .iter()
            .try_fold(self.source().len(), |length, edit| {
                length
                    .checked_sub(edit.old_span.len())
                    .and_then(|length| length.checked_add(edit.replacement.len()))
                    .ok_or(EditFailure::ResourceLimit("target-bytes"))
            })?;
        if target_len > self.parse_limits.common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("target-bytes"));
        }
        let mut rendered = Vec::new();
        rendered
            .try_reserve_exact(target_len)
            .map_err(|_| EditFailure::ResourceLimit("target-allocation"))?;
        let mut cursor = 0usize;
        for edit in &prepared {
            append_bytes(
                &mut rendered,
                &self.source().bytes()[cursor..edit.old_span.start_byte()],
                target_len,
            )?;
            append_bytes(&mut rendered, &edit.replacement, target_len)?;
            cursor = edit.old_span.end_byte();
        }
        append_bytes(&mut rendered, &self.source().bytes()[cursor..], target_len)?;

        let new_document = parse(
            rendered,
            self.profile,
            original_encoding_selection(self),
            self.parse_limits,
        )
        .map_err(|_| {
            if contains_literal {
                EditFailure::InvalidLiteral
            } else {
                EditFailure::NewDocumentFormationFailed
            }
        })?;
        if new_document.formation_status() != FormationStatus::Complete
            || new_document.entries().len() != self.entries().len()
            || new_document.sections().len() != self.sections().len()
        {
            return Err(if contains_literal {
                EditFailure::InvalidLiteral
            } else {
                EditFailure::NewDocumentFormationFailed
            });
        }

        let mut delta = 0isize;
        let mut source_edits = Vec::new();
        let mut mappings = Vec::new();
        source_edits
            .try_reserve_exact(prepared.len())
            .map_err(|_| EditFailure::ResourceLimit("source-edits"))?;
        mappings
            .try_reserve_exact(prepared.len())
            .map_err(|_| EditFailure::ResourceLimit("node-mappings"))?;
        for edit in prepared {
            let new_start = edit
                .old_span
                .start_byte()
                .checked_add_signed(delta)
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
            let new_end = new_start
                .checked_add(edit.replacement.len())
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
            let new_span = new_document
                .authority
                .span(new_start, new_end)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            let new_entry = new_document
                .entries()
                .get(edit.entry_ordinal)
                .ok_or(EditFailure::NewDocumentFormationFailed)?;
            let new_owned = new_document.value_ownership(new_entry)?;
            if new_owned != new_span
                || new_entry.key() != self.entries()[edit.entry_ordinal].key()
                || new_entry.section() != new_document.sections()[edit.section_ordinal].node_ref()
            {
                return Err(if edit.literal {
                    EditFailure::InvalidLiteral
                } else {
                    EditFailure::NewDocumentFormationFailed
                });
            }
            source_edits.push(SourceEdit {
                old_span: edit.old_span,
                new_span,
                replacement: Arc::from(edit.replacement.clone()),
            });
            mappings.push(NodeMapping {
                old: edit.target,
                new: Some(new_entry.node_ref()),
                status: NodeMappingStatus::Replaced,
                reason: None,
            });
            let replacement_len = isize::try_from(edit.replacement.len())
                .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
            let old_len = isize::try_from(edit.old_span.len())
                .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
            delta = delta
                .checked_add(replacement_len - old_len)
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
        }
        let change_set = ChangeSet::new(
            self.snapshot_identity(),
            new_document.snapshot_identity(),
            source_edits,
            mappings,
            diagnostics,
        );
        let patch_limits = source_patch_limits(self.parse_limits, change_set.source_edits().len());
        let source_patch = SourcePatch::derive(
            self.source(),
            new_document.source(),
            &change_set,
            operation_metadata(transaction),
            patch_limits,
        )
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        let untouched_proof = UntouchedByteProof::create(
            self.source(),
            new_document.source(),
            source_patch.replacements(),
        )
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        Ok(EditCommit {
            document: new_document,
            change_set,
            source_patch,
            untouched_proof,
        })
    }

    /// Fully validates and plans an edit without publishing a new document.
    pub fn dry_run(
        &self,
        transaction: &EditTransaction,
        source_id: EditPlanSourceId,
    ) -> Result<EditPlan, EditFailure> {
        let commit = self.commit(transaction)?;
        EditPlan::new(
            source_id,
            self.profile(),
            operation_summaries(transaction)?,
            commit.source_patch,
            commit.change_set.diagnostics().to_vec(),
        )
        .map_err(|_| EditFailure::NewDocumentFormationFailed)
    }

    fn prepare_value(
        &self,
        operation: &ValueReplacement,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<PreparedEdit, EditFailure> {
        let target = operation.target();
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::IniEntry {
            return Err(EditFailure::WrongRole);
        }
        let entry_ordinal = self
            .entries()
            .iter()
            .position(|entry| entry.node_ref() == target)
            .ok_or(EditFailure::WrongRole)?;
        let entry = &self.entries()[entry_ordinal];
        let section_ordinal = self
            .sections()
            .iter()
            .position(|section| section.node_ref() == entry.section())
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let old_span = self.value_ownership(entry)?;
        let (replacement, literal) = match operation {
            ValueReplacement::Literal { literal, .. } => {
                if literal.len() > self.parse_limits.common.max_source_bytes {
                    return Err(EditFailure::ResourceLimit("replacement-bytes"));
                }
                (literal.to_vec(), true)
            }
            ValueReplacement::Semantic { value, policy, .. } => (
                self.semantic_value(entry, value, *policy, diagnostics)?,
                false,
            ),
        };
        Ok(PreparedEdit {
            old_span,
            replacement,
            target,
            entry_ordinal,
            section_ordinal,
            literal,
        })
    }

    fn semantic_value(
        &self,
        entry: &IniEntry,
        value: &str,
        policy: RepresentationPolicy,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<u8>, EditFailure> {
        if policy == RepresentationPolicy::ExactLiteral {
            return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
        }
        validate_semantic_value(self.profile, value)?;
        let preserve = || self.preserved_value(entry, value);
        match policy {
            RepresentationPolicy::PreserveCompatible => preserve(),
            RepresentationPolicy::PreserveElseCanonical => match preserve() {
                Ok(bytes) => Ok(bytes),
                Err(EditFailure::RepresentationIncompatible) => {
                    diagnostics.push(Diagnostic::new(
                        "ini.edit.canonical-fallback@1",
                        DiagnosticCategory::Edit,
                        DiagnosticSeverity::Warning,
                        Some(entry.value_span().diagnostic_location()),
                        diagnostics.len() as u64,
                    ));
                    self.canonical_value(entry, value)
                }
                Err(failure) => Err(failure),
            },
            RepresentationPolicy::CanonicalForProfile => self.canonical_value(entry, value),
            RepresentationPolicy::ExactLiteral => unreachable!("handled above"),
        }
    }

    fn preserved_value(&self, entry: &IniEntry, value: &str) -> Result<Vec<u8>, EditFailure> {
        match self.profile {
            IniProfile::PortableV1 => self.encode_value(value),
            IniProfile::WindowsV1 => match entry.quote_style() {
                IniQuoteStyle::Single | IniQuoteStyle::Double => {
                    let quote = if entry.quote_style() == IniQuoteStyle::Single {
                        '\''
                    } else {
                        '"'
                    };
                    let mut literal = String::new();
                    literal.push(quote);
                    literal.push_str(value);
                    literal.push(quote);
                    self.encode_value(&literal)
                }
                IniQuoteStyle::None if !materialization::windows_value_needs_quotes(value) => {
                    self.encode_value(value)
                }
                IniQuoteStyle::None => Err(EditFailure::RepresentationIncompatible),
            },
            IniProfile::PythonConfigParserV1 => self.preserved_python_value(entry, value),
        }
    }

    fn canonical_value(&self, entry: &IniEntry, value: &str) -> Result<Vec<u8>, EditFailure> {
        match self.profile {
            IniProfile::PortableV1 => self.encode_value(value),
            IniProfile::WindowsV1 => {
                if materialization::windows_value_needs_quotes(value) {
                    let quote = if value.starts_with('"') && value.ends_with('"') {
                        '\''
                    } else {
                        '"'
                    };
                    self.encode_value(&format!("{quote}{value}{quote}"))
                } else {
                    self.encode_value(value)
                }
            }
            IniProfile::PythonConfigParserV1 => self.canonical_python_value(entry, value),
        }
    }

    fn preserved_python_value(
        &self,
        entry: &IniEntry,
        value: &str,
    ) -> Result<Vec<u8>, EditFailure> {
        let logical = self
            .logical_line(entry.logical_line())
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        let physical = logical.physical_lines();
        let new_lines: Vec<_> = value.split('\n').collect();
        let old_lines: Vec<_> = entry.value().split('\n').collect();
        if physical.len() != new_lines.len() || old_lines.len() != new_lines.len() {
            return Err(EditFailure::RepresentationIncompatible);
        }
        let mut output = Vec::new();
        append_bytes(
            &mut output,
            &self.encode_value(new_lines[0])?,
            self.parse_limits.common.max_source_bytes,
        )?;
        let first = self
            .physical_line(physical[0])
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        append_bytes(
            &mut output,
            self.raw(
                entry.value_span().end_byte(),
                first.content_span().end_byte(),
            )?,
            self.parse_limits.common.max_source_bytes,
        )?;
        for index in 1..physical.len() {
            let previous = self
                .physical_line(physical[index - 1])
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            let line_break = previous
                .line_break_span()
                .ok_or(EditFailure::RepresentationIncompatible)?;
            append_bytes(
                &mut output,
                self.raw(line_break.start_byte(), line_break.end_byte())?,
                self.parse_limits.common.max_source_bytes,
            )?;
            let line = self
                .physical_line(physical[index])
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            if old_lines[index].is_empty() != new_lines[index].is_empty() {
                return Err(EditFailure::RepresentationIncompatible);
            }
            if new_lines[index].is_empty() {
                append_bytes(
                    &mut output,
                    self.raw(
                        line.content_span().start_byte(),
                        line.content_span().end_byte(),
                    )?,
                    self.parse_limits.common.max_source_bytes,
                )?;
                continue;
            }
            let value_piece = self
                .syntax_span(IniSyntaxKind::EntryValue, line.content_span())
                .ok_or(EditFailure::RepresentationIncompatible)?;
            append_bytes(
                &mut output,
                self.raw(line.content_span().start_byte(), value_piece.start_byte())?,
                self.parse_limits.common.max_source_bytes,
            )?;
            append_bytes(
                &mut output,
                &self.encode_value(new_lines[index])?,
                self.parse_limits.common.max_source_bytes,
            )?;
            append_bytes(
                &mut output,
                self.raw(value_piece.end_byte(), line.content_span().end_byte())?,
                self.parse_limits.common.max_source_bytes,
            )?;
        }
        Ok(output)
    }

    fn canonical_python_value(
        &self,
        entry: &IniEntry,
        value: &str,
    ) -> Result<Vec<u8>, EditFailure> {
        let first = self
            .logical_line(entry.logical_line())
            .ok()
            .and_then(|line| line.physical_lines().first().copied())
            .and_then(|line| self.physical_line(line).ok())
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let base_indent = self.raw(
            first.content_span().start_byte(),
            entry.key_span().start_byte(),
        )?;
        let mut output = Vec::new();
        for (index, line) in value.split('\n').enumerate() {
            if index > 0 {
                append_bytes(
                    &mut output,
                    &self.encode_value("\n")?,
                    self.parse_limits.common.max_source_bytes,
                )?;
                append_bytes(
                    &mut output,
                    base_indent,
                    self.parse_limits.common.max_source_bytes,
                )?;
                if !line.is_empty() {
                    append_bytes(
                        &mut output,
                        &self.encode_value("    ")?,
                        self.parse_limits.common.max_source_bytes,
                    )?;
                }
            }
            append_bytes(
                &mut output,
                &self.encode_value(line)?,
                self.parse_limits.common.max_source_bytes,
            )?;
        }
        Ok(output)
    }

    fn encode_value(&self, value: &str) -> Result<Vec<u8>, EditFailure> {
        materialization::encode_fragment(
            value,
            self.source().encoding_facts().selected(),
            self.parse_limits.common.max_source_bytes,
        )
        .map_err(|failure| match failure {
            MaterializationFailure::ResourceLimit(name) => EditFailure::ResourceLimit(name),
            MaterializationFailure::UnsupportedEncoding => EditFailure::EncodingUnrepresentable,
            _ => EditFailure::UnrepresentableValue,
        })
    }

    fn value_ownership(&self, entry: &IniEntry) -> Result<Span, EditFailure> {
        let (start, end) = match self.profile {
            IniProfile::PortableV1 => (
                entry.value_span().start_byte(),
                entry.value_span().end_byte(),
            ),
            IniProfile::WindowsV1 => {
                let delimiter = self
                    .syntax_span(IniSyntaxKind::Delimiter, entry.span())
                    .ok_or(EditFailure::NewDocumentFormationFailed)?;
                (delimiter.end_byte(), entry.span().end_byte())
            }
            IniProfile::PythonConfigParserV1 => {
                let logical = self
                    .logical_line(entry.logical_line())
                    .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
                let last = logical
                    .physical_lines()
                    .last()
                    .and_then(|line| self.physical_line(*line).ok())
                    .ok_or(EditFailure::NewDocumentFormationFailed)?;
                (
                    entry.value_span().start_byte(),
                    last.content_span().end_byte(),
                )
            }
        };
        self.authority
            .span(start, end)
            .map_err(|_| EditFailure::NewDocumentFormationFailed)
    }

    fn syntax_span(&self, kind: IniSyntaxKind, within: Span) -> Option<Span> {
        self.lossless_structural_index()
            .pieces()
            .iter()
            .zip(self.lossless_syntax_kinds())
            .find_map(|(piece, candidate)| {
                let span = piece.span();
                (*candidate == kind
                    && span.start_byte() >= within.start_byte()
                    && span.end_byte() <= within.end_byte())
                .then_some(span)
            })
    }

    fn raw(&self, start: usize, end: usize) -> Result<&[u8], EditFailure> {
        self.source()
            .bytes()
            .get(start..end)
            .ok_or(EditFailure::NewDocumentFormationFailed)
    }
}

fn validate_semantic_value(profile: IniProfile, value: &str) -> Result<(), EditFailure> {
    let valid = match profile {
        IniProfile::PortableV1 => value.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'\'' | b'"' | b'\\' | b':' | b'#' | b';')
                || byte == b' '
        }),
        IniProfile::WindowsV1 => !value.contains(['\0', '\r', '\n']),
        IniProfile::PythonConfigParserV1 => {
            !value.contains(['\0', '\r'])
                && !value.ends_with('\n')
                && value.split('\n').enumerate().all(|(index, line)| {
                    line.trim_matches([' ', '\t']) == line
                        && (index == 0 || !matches!(line.as_bytes().first(), Some(b'#' | b';')))
                })
        }
    };
    valid.then_some(()).ok_or(EditFailure::UnrepresentableValue)
}

fn original_encoding_selection(document: &Document) -> IniEncodingSelection {
    document.source().encoding_facts().caller_override().map_or(
        IniEncodingSelection::ProfileDefault,
        IniEncodingSelection::Explicit,
    )
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), EditFailure> {
    let length = output
        .len()
        .checked_add(bytes.len())
        .ok_or(EditFailure::ResourceLimit("replacement-bytes"))?;
    if length > max {
        return Err(EditFailure::ResourceLimit("replacement-bytes"));
    }
    output
        .try_reserve(bytes.len())
        .map_err(|_| EditFailure::ResourceLimit("replacement-bytes"))?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn source_patch_limits(limits: IniParseLimits, operation_count: usize) -> SourcePatchLimits {
    SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: limits.common.max_source_bytes,
            max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
            max_decoded_scalars: limits.max_decoded_scalars,
        },
        max_replacements: operation_count,
        max_patch_bytes: limits.common.max_source_bytes.saturating_mul(2),
    }
}

fn operation_metadata(transaction: &EditTransaction) -> BTreeMap<String, String> {
    transaction
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let id = match operation {
                EditOperation::ReplaceValue(ValueReplacement::Semantic { .. }) => {
                    "ini.edit.replace-semantic-value@1"
                }
                EditOperation::ReplaceValue(ValueReplacement::Literal { .. }) => {
                    "ini.edit.replace-literal-value@1"
                }
            };
            (format!("operation.{index}"), id.to_owned())
        })
        .collect()
}

fn operation_summaries(
    transaction: &EditTransaction,
) -> Result<Vec<EditOperationSummary>, EditFailure> {
    transaction
        .operations
        .iter()
        .map(|operation| {
            let (id, arguments) = match operation {
                EditOperation::ReplaceValue(ValueReplacement::Semantic {
                    value, policy, ..
                }) => (
                    "ini.edit.replace-semantic-value",
                    BTreeMap::from([
                        (
                            "representation_policy".to_owned(),
                            policy_name(*policy).to_owned(),
                        ),
                        (
                            "value_scalars".to_owned(),
                            value.chars().count().to_string(),
                        ),
                    ]),
                ),
                EditOperation::ReplaceValue(ValueReplacement::Literal { literal, .. }) => (
                    "ini.edit.replace-literal-value",
                    BTreeMap::from([("literal_bytes".to_owned(), literal.len().to_string())]),
                ),
            };
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

const fn policy_name(policy: RepresentationPolicy) -> &'static str {
    match policy {
        RepresentationPolicy::ExactLiteral => "exact-literal",
        RepresentationPolicy::PreserveCompatible => "preserve-compatible",
        RepresentationPolicy::CanonicalForProfile => "canonical-for-profile",
        RepresentationPolicy::PreserveElseCanonical => "preserve-else-canonical",
    }
}

impl consema_core::StableFailure for EditFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Edit
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::WrongSnapshot => consema_core::FailureKind::TargetMismatch,
            Self::WrongRole | Self::DuplicateTarget | Self::OverlappingOwnership => {
                consema_core::FailureKind::InvalidInput
            }
            Self::RecoveredDocument
            | Self::RepresentationIncompatible
            | Self::ExactLiteralRequiresLiteralOperation
            | Self::InvalidLiteral => consema_core::FailureKind::NotApplicable,
            Self::UnrepresentableValue | Self::EncodingUnrepresentable => {
                consema_core::FailureKind::Unsupported
            }
            Self::ResourceLimit(_) => consema_core::FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::RecoveredDocument => "ini.edit.recovered-document@1",
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::DuplicateTarget | Self::OverlappingOwnership => "core.edit.conflicting-edits@1",
            Self::RepresentationIncompatible => "core.edit.representation-incompatible@1",
            Self::ExactLiteralRequiresLiteralOperation => {
                "core.edit.exact-literal-requires-literal@1"
            }
            Self::UnrepresentableValue => "ini.edit.unrepresentable-value@1",
            Self::EncodingUnrepresentable => "ini.edit.encoding-unrepresentable@1",
            Self::InvalidLiteral => "ini.edit.invalid-literal@1",
            Self::ResourceLimit(_) => "core.edit.resource-limit@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

struct PreparedEdit {
    old_span: Span,
    replacement: Vec<u8>,
    target: NodeRef,
    entry_ordinal: usize,
    section_ordinal: usize,
    literal: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::StableFailure;
    use consema_document::{EditPlanSourceId, SourceEncoding, WindowsCodePage};

    fn parsed(profile: IniProfile, source: &str) -> Document {
        parse(
            source.as_bytes(),
            profile,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn portable_semantic_edit_is_atomic_and_replayable() {
        let document = parsed(IniProfile::PortableV1, "; before\n[s]\nk=old\n; after\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_value(
            document.entries()[0].node_ref(),
            "new value",
            RepresentationPolicy::CanonicalForProfile,
        );
        let transaction = builder.build();
        let source_id = EditPlanSourceId::new("memory:portable").unwrap();
        let plan = document.dry_run(&transaction, source_id).unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(
            commit.document.render(),
            b"; before\n[s]\nk=new value\n; after\n"
        );
        assert_eq!(plan.source_patch(), &commit.source_patch);
        let replay = commit
            .source_patch
            .apply(
                document.source(),
                source_patch_limits(document.parse_limits(), 1),
            )
            .unwrap();
        assert_eq!(replay.bytes(), commit.document.render());
        commit
            .untouched_proof
            .verify(
                document.source(),
                commit.document.source(),
                commit.source_patch.replacements(),
            )
            .unwrap();
    }

    #[test]
    fn windows_preserves_quotes_and_falls_back_for_unquoted_whitespace() {
        let document = parsed(IniProfile::WindowsV1, "[S]\r\na='old'\r\nb=plain\r\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .semantic_value(
                document.entries()[0].node_ref(),
                " new ",
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_value(
                document.entries()[1].node_ref(),
                " spaced ",
                RepresentationPolicy::PreserveElseCanonical,
            );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[S]\r\na=' new '\r\nb=\" spaced \"\r\n"
        );
        assert_eq!(
            commit.change_set.diagnostics()[0].code,
            "ini.edit.canonical-fallback@1"
        );
    }

    #[test]
    fn python_preserves_multiline_trivia_and_canonicalizes_shape_changes() {
        let source = "[S]\nkey : first  \n\tsecond\t\n\n\tthird\nnext=x\n";
        let document = parsed(IniProfile::PythonConfigParserV1, source);
        let mut preserve = EditTransactionBuilder::new(&document);
        preserve.semantic_value(
            document.entries()[0].node_ref(),
            "one\ntwo\n\nthree",
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&preserve.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[S]\nkey : one  \n\ttwo\t\n\n\tthree\nnext=x\n"
        );
        assert_eq!(commit.document.entries()[0].value(), "one\ntwo\n\nthree");

        let mut fallback = EditTransactionBuilder::new(&document);
        fallback.semantic_value(
            document.entries()[0].node_ref(),
            "single",
            RepresentationPolicy::PreserveElseCanonical,
        );
        let commit = document.commit(&fallback.build()).unwrap();
        assert_eq!(commit.document.entries()[0].value(), "single");
        assert_eq!(commit.change_set.diagnostics().len(), 1);
    }

    #[test]
    fn literal_and_snapshot_failures_are_explicit() {
        let document = parsed(IniProfile::PortableV1, "[s]\nk=old\n");
        let other = parsed(IniProfile::PortableV1, "[s]\nk=x\n");
        let mut wrong = EditTransactionBuilder::new(&document);
        wrong.literal_value(other.entries()[0].node_ref(), b"new".as_slice());
        assert!(matches!(
            document.commit(&wrong.build()),
            Err(EditFailure::WrongSnapshot)
        ));

        let mut invalid = EditTransactionBuilder::new(&document);
        invalid.literal_value(document.entries()[0].node_ref(), b"x\n[y]\nq=z".as_slice());
        assert!(matches!(
            document.commit(&invalid.build()),
            Err(EditFailure::InvalidLiteral)
        ));

        let recovered = parsed(IniProfile::PortableV1, "[s]\nbroken\n");
        let transaction = EditTransactionBuilder::new(&recovered).build();
        assert!(matches!(
            recovered.commit(&transaction),
            Err(EditFailure::RecoveredDocument)
        ));
        assert_eq!(
            EditFailure::RecoveredDocument.diagnostic_code(),
            "ini.edit.recovered-document@1"
        );
    }

    #[test]
    fn policy_conflicts_and_duplicate_targets_fail_before_a_patch_exists() {
        let document = parsed(IniProfile::WindowsV1, "[S]\r\nk=plain\r\n");
        let target = document.entries()[0].node_ref();

        let mut incompatible = EditTransactionBuilder::new(&document);
        incompatible.semantic_value(target, " spaced ", RepresentationPolicy::PreserveCompatible);
        assert!(matches!(
            document.commit(&incompatible.build()),
            Err(EditFailure::RepresentationIncompatible)
        ));

        let mut exact = EditTransactionBuilder::new(&document);
        exact.semantic_value(target, "value", RepresentationPolicy::ExactLiteral);
        assert!(matches!(
            document.commit(&exact.build()),
            Err(EditFailure::ExactLiteralRequiresLiteralOperation)
        ));

        let mut duplicate = EditTransactionBuilder::new(&document);
        duplicate
            .semantic_value(target, "one", RepresentationPolicy::CanonicalForProfile)
            .literal_value(target, b"two".as_slice());
        assert!(matches!(
            document.commit(&duplicate.build()),
            Err(EditFailure::DuplicateTarget)
        ));
    }

    #[test]
    fn python_first_line_comment_markers_remain_literal_content() {
        let document = parsed(IniProfile::PythonConfigParserV1, "[S]\nk=old\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_value(
            document.entries()[0].node_ref(),
            "#literal ;literal",
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.entries()[0].value(), "#literal ;literal");
    }

    #[test]
    fn selected_utf16_and_code_page_encodings_are_preserved() {
        let text = "[S]\r\nk=old\r\n";
        let mut utf16 = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            utf16.extend(unit.to_le_bytes());
        }
        let document = parse(
            utf16,
            IniProfile::WindowsV1,
            IniEncodingSelection::ProfileDefault,
            IniParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_value(
            document.entries()[0].node_ref(),
            "wide",
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.entries()[0].value(), "wide");
        assert_eq!(
            commit.document.source().encoding_facts(),
            document.source().encoding_facts()
        );

        let code_page = WindowsCodePage::from_number(1252).unwrap();
        let document = parse(
            b"[S]\r\nk=old\r\n".as_slice(),
            IniProfile::WindowsV1,
            IniEncodingSelection::Explicit(SourceEncoding::WindowsCodePage(code_page)),
            IniParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_value(
            document.entries()[0].node_ref(),
            "\u{20ac}",
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.entries()[0].value(), "\u{20ac}");
        assert!(commit.document.render().contains(&0x80));
    }
}
