use crate::{
    Document, IniEncodingSelection, IniEntry, IniParseLimits, IniProfile, IniQuoteStyle,
    IniSyntaxKind, materialization, parse,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    AssociationPlacement, ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId,
    FormatOperationId, FormationStatus, MaterializationFailure, NodeMapping, NodeMappingStatus,
    NodeRef, NodeRole, SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits,
    Span, UntouchedByteProof,
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
    /// Inserts one new section occurrence.
    InsertSection {
        /// Exact INI document target.
        document: NodeRef,
        /// Decoded section name.
        name: String,
        /// Placement among section occurrences.
        placement: AssociationPlacement,
    },
    /// Removes one exact section and all entries owned by that occurrence.
    RemoveSection {
        /// Exact ordinary or default-section target.
        target: NodeRef,
    },
    /// Replaces one exact section name.
    RenameSection {
        /// Exact ordinary or default-section target.
        target: NodeRef,
        /// New decoded section name.
        name: String,
    },
    /// Inserts one new entry into an exact section occurrence.
    InsertEntry {
        /// Exact ordinary or default-section container.
        section: NodeRef,
        /// Decoded entry key.
        key: String,
        /// Stored string value.
        value: String,
        /// Placement among direct entry occurrences.
        placement: AssociationPlacement,
    },
    /// Removes one exact entry occurrence.
    RemoveEntry {
        /// Exact INI entry target.
        target: NodeRef,
    },
    /// Replaces one exact entry key.
    RenameEntry {
        /// Exact INI entry target.
        target: NodeRef,
        /// New decoded key.
        key: String,
    },
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

    /// Adds one canonical section insertion.
    pub fn insert_section(
        &mut self,
        document: NodeRef,
        name: impl Into<String>,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertSection {
            document,
            name: name.into(),
            placement,
        });
        self
    }

    /// Adds one exact section removal, including that occurrence's owned entries.
    pub fn remove_section(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveSection { target });
        self
    }

    /// Adds one exact section-name replacement.
    pub fn rename_section(&mut self, target: NodeRef, name: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::RenameSection {
            target,
            name: name.into(),
        });
        self
    }

    /// Adds one canonical entry insertion.
    pub fn insert_entry(
        &mut self,
        section: NodeRef,
        key: impl Into<String>,
        value: impl Into<String>,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertEntry {
            section,
            key: key.into(),
            value: value.into(),
            placement,
        });
        self
    }

    /// Adds one exact entry removal.
    pub fn remove_entry(&mut self, target: NodeRef) -> &mut Self {
        self.operations.push(EditOperation::RemoveEntry { target });
        self
    }

    /// Adds one exact entry-key replacement.
    pub fn rename_entry(&mut self, target: NodeRef, key: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::RenameEntry {
            target,
            key: key.into(),
        });
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
    /// One operation removes a section while another edits its owned entry.
    AncestorDescendantConflict,
    /// An insertion anchor is removed by the same transaction.
    PlacementAnchorRemoved,
    /// A target or placement anchor does not exist in its declared container.
    TargetNotFound,
    /// A section name is invalid under the selected profile.
    InvalidName,
    /// A strict profile would become ambiguous after insertion or rename.
    NameCollision,
    /// An entry key is invalid under the selected profile.
    InvalidKey,
    /// A strict profile would contain a duplicate or comparison-equivalent key.
    KeyCollision,
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
        if transaction.operations().len() > self.parse_limits.common.max_node_count {
            return Err(EditFailure::ResourceLimit("edit-operations"));
        }
        self.validate_dependencies(transaction)?;
        let mut targets = HashSet::new();
        targets
            .try_reserve(transaction.operations().len())
            .map_err(|_| EditFailure::ResourceLimit("edit-targets"))?;
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for operation in transaction.operations.iter() {
            if let Some(target) = destructive_target(operation) {
                if !targets.insert(target) {
                    return Err(EditFailure::DuplicateTarget);
                }
            }
            let edits = self.prepare_operation(operation, &mut diagnostics)?;
            prepared
                .try_reserve(edits.len())
                .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
            prepared.extend(edits);
        }
        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        prepared = self.coalesce_adjacent_deletions(prepared)?;
        for pair in prepared.windows(2) {
            if pair[0].old_span == pair[1].old_span {
                return Err(EditFailure::OverlappingOwnership);
            }
            if pair[0].old_span.end_byte() > pair[1].old_span.start_byte() {
                return Err(EditFailure::AncestorDescendantConflict);
            }
        }
        let literal_only = !transaction.operations().is_empty()
            && transaction.operations().iter().all(|operation| {
                matches!(
                    operation,
                    EditOperation::ReplaceValue(ValueReplacement::Literal { .. })
                )
            });

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
            if literal_only {
                EditFailure::InvalidLiteral
            } else {
                EditFailure::NewDocumentFormationFailed
            }
        })?;
        if new_document.formation_status() != FormationStatus::Complete {
            return Err(if literal_only {
                EditFailure::InvalidLiteral
            } else {
                EditFailure::NewDocumentFormationFailed
            });
        }

        let mut delta = 0isize;
        let mut source_edits = Vec::new();
        let mut mappings = Vec::new();
        let mapping_count = prepared.iter().try_fold(0usize, |count, edit| {
            count
                .checked_add(edit.mappings.len())
                .ok_or(EditFailure::ResourceLimit("node-mappings"))
        })?;
        if mapping_count > self.parse_limits.common.max_node_count {
            return Err(EditFailure::ResourceLimit("node-mappings"));
        }
        source_edits
            .try_reserve_exact(prepared.len())
            .map_err(|_| EditFailure::ResourceLimit("source-edits"))?;
        mappings
            .try_reserve_exact(mapping_count)
            .map_err(|_| EditFailure::ResourceLimit("node-mappings"))?;
        let mut mapped_old = HashSet::new();
        mapped_old
            .try_reserve(mapping_count)
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
            source_edits.push(SourceEdit {
                old_span: edit.old_span,
                new_span,
                replacement: Arc::from(edit.replacement.clone()),
            });
            for mapping in edit.mappings {
                let publish_mapping = mapped_old.insert(mapping.old);
                let (new, status, reason) = match mapping.plan {
                    MappingPlan::ReplacedValue {
                        ref expected_key,
                        literal,
                    } => {
                        let new = new_document.entries().iter().find(|entry| {
                            entry.key() == expected_key
                                && new_document.value_ownership(entry) == Ok(new_span)
                        });
                        let Some(new) = new else {
                            return Err(if literal {
                                EditFailure::InvalidLiteral
                            } else {
                                EditFailure::NewDocumentFormationFailed
                            });
                        };
                        (Some(new.node_ref()), NodeMappingStatus::Replaced, None)
                    }
                    MappingPlan::ReplacedSection { ref expected_name } => {
                        let new = new_document.sections().iter().find(|section| {
                            section.name() == expected_name && section.name_span() == new_span
                        });
                        let Some(new) = new else {
                            return Err(EditFailure::NewDocumentFormationFailed);
                        };
                        (Some(new.node_ref()), NodeMappingStatus::Replaced, None)
                    }
                    MappingPlan::ReplacedEntry { ref expected_key } => {
                        let new = new_document.entries().iter().find(|entry| {
                            entry.key() == expected_key && entry.key_span() == new_span
                        });
                        let Some(new) = new else {
                            return Err(EditFailure::NewDocumentFormationFailed);
                        };
                        (Some(new.node_ref()), NodeMappingStatus::Replaced, None)
                    }
                    MappingPlan::SectionAfterEntryInsertion {
                        ref expected_key,
                        ref expected_value,
                    } => {
                        let inserted = new_document.entries().iter().any(|entry| {
                            entry.key() == expected_key
                                && entry.value() == expected_value
                                && new_document.entry_record_span(entry).is_ok_and(|span| {
                                    span.start_byte() >= new_span.start_byte()
                                        && span.end_byte() == new_span.end_byte()
                                })
                        });
                        if !inserted {
                            return Err(EditFailure::NewDocumentFormationFailed);
                        }
                        (
                            None,
                            NodeMappingStatus::Unmapped,
                            Some("section-reparsed-after-entry-insertion".to_owned()),
                        )
                    }
                    MappingPlan::Deleted => (None, NodeMappingStatus::Deleted, None),
                    MappingPlan::Unmapped(reason) => {
                        (None, NodeMappingStatus::Unmapped, Some(reason.to_owned()))
                    }
                };
                if publish_mapping {
                    mappings.push(NodeMapping {
                        old: mapping.old,
                        new,
                        status,
                        reason,
                    });
                }
            }
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
            mappings: vec![PlannedMapping {
                old: target,
                plan: MappingPlan::ReplacedValue {
                    expected_key: entry.key().to_owned(),
                    literal,
                },
            }],
            mergeable_deletion: false,
        })
    }

    fn prepare_operation(
        &self,
        operation: &EditOperation,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        match operation {
            EditOperation::ReplaceValue(replacement) => {
                Ok(vec![self.prepare_value(replacement, diagnostics)?])
            }
            EditOperation::InsertSection {
                document,
                name,
                placement,
            } => Ok(vec![
                self.prepare_insert_section(*document, name, *placement)?,
            ]),
            EditOperation::RemoveSection { target } => self.prepare_remove_section(*target),
            EditOperation::RenameSection { target, name } => {
                Ok(vec![self.prepare_rename_section(*target, name)?])
            }
            EditOperation::InsertEntry {
                section,
                key,
                value,
                placement,
            } => Ok(vec![
                self.prepare_insert_entry(*section, key, value, *placement)?,
            ]),
            EditOperation::RemoveEntry { target } => self.prepare_remove_entry(*target),
            EditOperation::RenameEntry { target, key } => {
                Ok(vec![self.prepare_rename_entry(*target, key)?])
            }
        }
    }

    fn prepare_insert_section(
        &self,
        document: NodeRef,
        name: &str,
        placement: AssociationPlacement,
    ) -> Result<PreparedEdit, EditFailure> {
        self.resolve_document(document)?;
        self.validate_section_name(name)?;
        self.validate_section_collision(name, None)?;
        let position = match placement {
            AssociationPlacement::Start => self.section_line_start(&self.sections()[0])?,
            AssociationPlacement::End => self.source().len(),
            AssociationPlacement::Before(anchor) => {
                self.section_line_start(self.resolve_section(anchor)?)?
            }
            AssociationPlacement::After(anchor) => {
                self.resolve_section(anchor)?;
                let ordinal = self
                    .sections()
                    .iter()
                    .position(|section| section.node_ref() == anchor)
                    .ok_or(EditFailure::TargetNotFound)?;
                self.sections().get(ordinal + 1).map_or_else(
                    || Ok(self.source().len()),
                    |section| self.section_line_start(section),
                )?
            }
        };
        let mut text = String::new();
        if position == self.source().len()
            && !self
                .source()
                .decoded_text()
                .is_some_and(|source| source.ends_with(['\n', '\r']))
        {
            text.push_str(profile_newline(self.profile));
        }
        text.push('[');
        text.push_str(name);
        text.push(']');
        text.push_str(profile_newline(self.profile));
        Ok(PreparedEdit {
            old_span: self
                .authority
                .span(position, position)
                .map_err(|_| EditFailure::TargetNotFound)?,
            replacement: self.encode_value(&text)?,
            mappings: vec![PlannedMapping {
                old: document,
                plan: MappingPlan::Unmapped("document-reparsed-after-section-insertion"),
            }],
            mergeable_deletion: false,
        })
    }

    fn prepare_remove_section(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let section = self.resolve_section(target)?;
        let header = self.logical_physical_spans(section.logical_line())?;
        let entry_count = self
            .entries()
            .iter()
            .filter(|entry| entry.section() == target)
            .count();
        let mut edits = Vec::new();
        edits
            .try_reserve_exact(header.len().saturating_add(entry_count))
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for (index, span) in header.into_iter().enumerate() {
            edits.push(deletion_edit(span, (index == 0).then_some(target)));
        }
        for entry in self
            .entries()
            .iter()
            .filter(|entry| entry.section() == target)
        {
            for (index, span) in self
                .logical_physical_spans(entry.logical_line())?
                .into_iter()
                .enumerate()
            {
                edits.push(deletion_edit(
                    span,
                    (index == 0).then_some(entry.node_ref()),
                ));
            }
        }
        Ok(edits)
    }

    fn prepare_rename_section(
        &self,
        target: NodeRef,
        name: &str,
    ) -> Result<PreparedEdit, EditFailure> {
        let section = self.resolve_section(target)?;
        self.validate_section_name(name)?;
        self.validate_section_collision(name, Some(target))?;
        Ok(PreparedEdit {
            old_span: section.name_span(),
            replacement: self.encode_value(name)?,
            mappings: vec![PlannedMapping {
                old: target,
                plan: MappingPlan::ReplacedSection {
                    expected_name: name.to_owned(),
                },
            }],
            mergeable_deletion: false,
        })
    }

    fn prepare_insert_entry(
        &self,
        section: NodeRef,
        key: &str,
        value: &str,
        placement: AssociationPlacement,
    ) -> Result<PreparedEdit, EditFailure> {
        self.resolve_section(section)?;
        self.validate_entry_key(key)?;
        self.validate_entry_collision(section, key, None)?;
        validate_semantic_value(self.profile, value)?;
        let direct_count = self
            .entries()
            .iter()
            .filter(|entry| entry.section() == section)
            .count();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(direct_count)
            .map_err(|_| EditFailure::ResourceLimit("section-entries"))?;
        entries.extend(
            self.entries()
                .iter()
                .filter(|entry| entry.section() == section),
        );
        let position = match placement {
            AssociationPlacement::Start => entries.first().map_or_else(
                || self.section_content_end(section),
                |entry| self.entry_line_start(entry),
            ),
            AssociationPlacement::End => self.section_content_end(section),
            AssociationPlacement::Before(anchor) => {
                let entry = self.resolve_entry_in_section(anchor, section, &entries)?;
                self.entry_line_start(entry)
            }
            AssociationPlacement::After(anchor) => {
                let entry = self.resolve_entry_in_section(anchor, section, &entries)?;
                self.entry_line_end(entry)
            }
        }?;
        let mut text = String::new();
        if position == self.source().len()
            && !self
                .source()
                .decoded_text()
                .is_some_and(|source| source.ends_with(['\n', '\r']))
        {
            text.push_str(profile_newline(self.profile));
        }
        text.push_str(&self.canonical_entry_text(key, value)?);
        Ok(PreparedEdit {
            old_span: self
                .authority
                .span(position, position)
                .map_err(|_| EditFailure::TargetNotFound)?,
            replacement: self.encode_value(&text)?,
            mappings: vec![PlannedMapping {
                old: section,
                plan: MappingPlan::SectionAfterEntryInsertion {
                    expected_key: key.to_owned(),
                    expected_value: value.to_owned(),
                },
            }],
            mergeable_deletion: false,
        })
    }

    fn prepare_remove_entry(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let entry = self.resolve_entry(target)?;
        let mut edits = Vec::new();
        let spans = self.logical_physical_spans(entry.logical_line())?;
        edits
            .try_reserve_exact(spans.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for (index, span) in spans.into_iter().enumerate() {
            edits.push(deletion_edit(span, (index == 0).then_some(target)));
        }
        Ok(edits)
    }

    fn prepare_rename_entry(
        &self,
        target: NodeRef,
        key: &str,
    ) -> Result<PreparedEdit, EditFailure> {
        let entry = self.resolve_entry(target)?;
        self.validate_entry_key(key)?;
        self.validate_entry_collision(entry.section(), key, Some(target))?;
        Ok(PreparedEdit {
            old_span: entry.key_span(),
            replacement: self.encode_value(key)?,
            mappings: vec![PlannedMapping {
                old: target,
                plan: MappingPlan::ReplacedEntry {
                    expected_key: key.to_owned(),
                },
            }],
            mergeable_deletion: false,
        })
    }

    fn validate_dependencies(&self, transaction: &EditTransaction) -> Result<(), EditFailure> {
        let mut removed_sections = HashSet::new();
        let mut removed_entries = HashSet::new();
        removed_sections
            .try_reserve(transaction.operations().len())
            .map_err(|_| EditFailure::ResourceLimit("edit-dependencies"))?;
        removed_entries
            .try_reserve(transaction.operations().len())
            .map_err(|_| EditFailure::ResourceLimit("edit-dependencies"))?;
        for operation in transaction.operations() {
            if let EditOperation::RemoveSection { target } = operation {
                removed_sections.insert(*target);
            }
            if let EditOperation::RemoveEntry { target } = operation {
                removed_entries.insert(*target);
            }
        }
        for operation in transaction.operations() {
            match operation {
                EditOperation::InsertSection {
                    placement:
                        AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor),
                    ..
                } if removed_sections.contains(anchor) => {
                    return Err(EditFailure::PlacementAnchorRemoved);
                }
                EditOperation::InsertEntry {
                    placement:
                        AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor),
                    ..
                } if removed_entries.contains(anchor) => {
                    return Err(EditFailure::PlacementAnchorRemoved);
                }
                EditOperation::InsertEntry { section, .. }
                    if removed_sections.contains(section) =>
                {
                    return Err(EditFailure::AncestorDescendantConflict);
                }
                EditOperation::ReplaceValue(replacement)
                    if self
                        .entry(replacement.target())
                        .is_ok_and(|entry| removed_sections.contains(&entry.section())) =>
                {
                    return Err(EditFailure::AncestorDescendantConflict);
                }
                EditOperation::RemoveEntry { target }
                | EditOperation::RenameEntry { target, .. }
                    if self
                        .entry(*target)
                        .is_ok_and(|entry| removed_sections.contains(&entry.section())) =>
                {
                    return Err(EditFailure::AncestorDescendantConflict);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resolve_document(&self, target: NodeRef) -> Result<(), EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::IniDocument {
            return Err(EditFailure::WrongRole);
        }
        (target == self.node_ref())
            .then_some(())
            .ok_or(EditFailure::TargetNotFound)
    }

    fn resolve_section(&self, target: NodeRef) -> Result<&crate::IniSection, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if !matches!(
            target.role(),
            NodeRole::IniSection | NodeRole::IniDefaultSection
        ) {
            return Err(EditFailure::WrongRole);
        }
        self.sections()
            .iter()
            .find(|section| section.node_ref() == target)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn validate_section_name(&self, name: &str) -> Result<(), EditFailure> {
        let valid = match self.profile {
            IniProfile::PortableV1 => {
                !name.is_empty()
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
            }
            IniProfile::WindowsV1 => {
                !name.is_empty()
                    && name.bytes().all(|byte| {
                        (byte.is_ascii_graphic() || byte == b' ')
                            && !matches!(byte, b'[' | b']' | b'=' | b'\0' | b'\r' | b'\n')
                    })
            }
            IniProfile::PythonConfigParserV1 => {
                !name.is_empty() && !name.contains(['\0', '\r', '\n'])
            }
        };
        valid.then_some(()).ok_or(EditFailure::InvalidName)
    }

    fn validate_section_collision(
        &self,
        name: &str,
        except: Option<NodeRef>,
    ) -> Result<(), EditFailure> {
        if self.profile != IniProfile::WindowsV1
            && self
                .sections()
                .iter()
                .any(|section| Some(section.node_ref()) != except && section.name() == name)
        {
            Err(EditFailure::NameCollision)
        } else {
            Ok(())
        }
    }

    fn resolve_entry(&self, target: NodeRef) -> Result<&IniEntry, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::IniEntry {
            return Err(EditFailure::WrongRole);
        }
        self.entries()
            .iter()
            .find(|entry| entry.node_ref() == target)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn resolve_entry_in_section<'a>(
        &self,
        target: NodeRef,
        section: NodeRef,
        entries: &[&'a IniEntry],
    ) -> Result<&'a IniEntry, EditFailure> {
        self.resolve_entry(target)?;
        entries
            .iter()
            .copied()
            .find(|entry| entry.node_ref() == target && entry.section() == section)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn validate_entry_key(&self, key: &str) -> Result<(), EditFailure> {
        let valid = match self.profile {
            IniProfile::PortableV1 => {
                !key.is_empty()
                    && key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
            }
            IniProfile::WindowsV1 => {
                !key.is_empty()
                    && key.trim_matches([' ', '\t']) == key
                    && key.bytes().all(|byte| {
                        (byte.is_ascii_graphic() || byte == b' ')
                            && !matches!(byte, b'[' | b']' | b'=' | b'\0' | b'\r' | b'\n')
                    })
            }
            IniProfile::PythonConfigParserV1 => {
                !key.is_empty()
                    && key.trim_matches([' ', '\t']) == key
                    && !key.contains(['\0', '\r', '\n', '=', ':'])
                    && !matches!(key.as_bytes().first(), Some(b'#' | b';'))
            }
        };
        valid.then_some(()).ok_or(EditFailure::InvalidKey)
    }

    fn validate_entry_collision(
        &self,
        section: NodeRef,
        key: &str,
        except: Option<NodeRef>,
    ) -> Result<(), EditFailure> {
        if self.profile == IniProfile::WindowsV1 {
            return Ok(());
        }
        let comparison = if self.profile == IniProfile::PythonConfigParserV1 {
            crate::python_case::optionxform(key)
        } else {
            key.to_owned()
        };
        if self.entries().iter().any(|entry| {
            entry.section() == section
                && Some(entry.node_ref()) != except
                && entry.comparison_key() == comparison
        }) {
            Err(EditFailure::KeyCollision)
        } else {
            Ok(())
        }
    }

    fn entry_line_start(&self, entry: &IniEntry) -> Result<usize, EditFailure> {
        self.logical_line(entry.logical_line())
            .ok()
            .and_then(|logical| logical.physical_lines().first().copied())
            .and_then(|line| self.physical_line(line).ok())
            .map(|line| line.span().start_byte())
            .ok_or(EditFailure::TargetNotFound)
    }

    fn entry_line_end(&self, entry: &IniEntry) -> Result<usize, EditFailure> {
        self.logical_line(entry.logical_line())
            .ok()
            .and_then(|logical| logical.physical_lines().last().copied())
            .and_then(|line| self.physical_line(line).ok())
            .map(|line| line.span().end_byte())
            .ok_or(EditFailure::TargetNotFound)
    }

    fn section_content_end(&self, target: NodeRef) -> Result<usize, EditFailure> {
        let ordinal = self
            .sections()
            .iter()
            .position(|section| section.node_ref() == target)
            .ok_or(EditFailure::TargetNotFound)?;
        self.sections().get(ordinal + 1).map_or_else(
            || Ok(self.source().len()),
            |section| self.section_line_start(section),
        )
    }

    fn canonical_entry_text(&self, key: &str, value: &str) -> Result<String, EditFailure> {
        let continuation_overhead = if self.profile == IniProfile::PythonConfigParserV1 {
            value
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                .checked_mul(4)
                .ok_or(EditFailure::ResourceLimit("replacement-bytes"))?
        } else {
            0
        };
        let estimated = key
            .len()
            .checked_add(value.len())
            .and_then(|length| length.checked_add(continuation_overhead))
            .and_then(|length| length.checked_add(8))
            .ok_or(EditFailure::ResourceLimit("replacement-bytes"))?;
        if estimated > self.parse_limits.common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("replacement-bytes"));
        }
        let mut text = String::new();
        text.try_reserve_exact(estimated)
            .map_err(|_| EditFailure::ResourceLimit("replacement-bytes"))?;
        text.push_str(key);
        match self.profile {
            IniProfile::PortableV1 => {
                text.push('=');
                text.push_str(value);
            }
            IniProfile::WindowsV1 => {
                text.push('=');
                if materialization::windows_value_needs_quotes(value) {
                    let quote = if value.starts_with('"') && value.ends_with('"') {
                        '\''
                    } else {
                        '"'
                    };
                    text.push(quote);
                    text.push_str(value);
                    text.push(quote);
                } else {
                    text.push_str(value);
                }
            }
            IniProfile::PythonConfigParserV1 => {
                text.push_str(" =");
                for (index, line) in value.split('\n').enumerate() {
                    if index == 0 {
                        if !line.is_empty() {
                            text.push(' ');
                        }
                    } else {
                        text.push('\n');
                        if !line.is_empty() {
                            text.push_str("    ");
                        }
                    }
                    text.push_str(line);
                }
            }
        }
        text.push_str(profile_newline(self.profile));
        if text.len() > self.parse_limits.common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("replacement-bytes"));
        }
        Ok(text)
    }

    fn section_line_start(&self, section: &crate::IniSection) -> Result<usize, EditFailure> {
        self.logical_line(section.logical_line())
            .ok()
            .and_then(|logical| logical.physical_lines().first().copied())
            .and_then(|line| self.physical_line(line).ok())
            .map(|line| line.span().start_byte())
            .ok_or(EditFailure::TargetNotFound)
    }

    fn logical_physical_spans(&self, logical: NodeRef) -> Result<Vec<Span>, EditFailure> {
        let logical = self
            .logical_line(logical)
            .map_err(|_| EditFailure::TargetNotFound)?;
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(logical.physical_lines().len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for line in logical.physical_lines() {
            spans.push(
                self.physical_line(*line)
                    .map_err(|_| EditFailure::TargetNotFound)?
                    .span(),
            );
        }
        Ok(spans)
    }

    fn coalesce_adjacent_deletions(
        &self,
        edits: Vec<PreparedEdit>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let mut merged: Vec<PreparedEdit> = Vec::new();
        merged
            .try_reserve_exact(edits.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for edit in edits {
            let merge = merged.last().is_some_and(|previous| {
                previous.mergeable_deletion
                    && edit.mergeable_deletion
                    && previous.old_span.end_byte() == edit.old_span.start_byte()
            });
            if merge {
                let previous = merged.last_mut().expect("merge requires previous edit");
                previous.old_span = self
                    .authority
                    .span(previous.old_span.start_byte(), edit.old_span.end_byte())
                    .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
                previous
                    .mappings
                    .try_reserve(edit.mappings.len())
                    .map_err(|_| EditFailure::ResourceLimit("node-mappings"))?;
                previous.mappings.extend(edit.mappings);
            } else {
                merged.push(edit);
            }
        }
        Ok(merged)
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

    fn entry_record_span(&self, entry: &IniEntry) -> Result<Span, EditFailure> {
        let logical = self
            .logical_line(entry.logical_line())
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        let first = logical
            .physical_lines()
            .first()
            .and_then(|line| self.physical_line(*line).ok())
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let last = logical
            .physical_lines()
            .last()
            .and_then(|line| self.physical_line(*line).ok())
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        self.authority
            .span(first.span().start_byte(), last.span().end_byte())
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

const fn destructive_target(operation: &EditOperation) -> Option<NodeRef> {
    match operation {
        EditOperation::ReplaceValue(replacement) => Some(replacement.target()),
        EditOperation::RemoveSection { target }
        | EditOperation::RenameSection { target, .. }
        | EditOperation::RemoveEntry { target }
        | EditOperation::RenameEntry { target, .. } => Some(*target),
        EditOperation::InsertSection { .. } | EditOperation::InsertEntry { .. } => None,
    }
}

fn deletion_edit(span: Span, target: Option<NodeRef>) -> PreparedEdit {
    PreparedEdit {
        old_span: span,
        replacement: Vec::new(),
        mappings: target
            .map(|old| PlannedMapping {
                old,
                plan: MappingPlan::Deleted,
            })
            .into_iter()
            .collect(),
        mergeable_deletion: true,
    }
}

const fn profile_newline(profile: IniProfile) -> &'static str {
    match profile {
        IniProfile::WindowsV1 => "\r\n",
        IniProfile::PortableV1 | IniProfile::PythonConfigParserV1 => "\n",
    }
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
                EditOperation::InsertSection { .. } => "ini.edit.insert-section@1",
                EditOperation::RemoveSection { .. } => "ini.edit.remove-section@1",
                EditOperation::RenameSection { .. } => "ini.edit.rename-section@1",
                EditOperation::InsertEntry { .. } => "ini.edit.insert-entry@1",
                EditOperation::RemoveEntry { .. } => "ini.edit.remove-entry@1",
                EditOperation::RenameEntry { .. } => "ini.edit.rename-entry@1",
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
                EditOperation::InsertSection {
                    name, placement, ..
                } => (
                    "ini.edit.insert-section",
                    BTreeMap::from([
                        ("name_scalars".to_owned(), name.chars().count().to_string()),
                        (
                            "placement".to_owned(),
                            placement_name(*placement).to_owned(),
                        ),
                    ]),
                ),
                EditOperation::RemoveSection { .. } => ("ini.edit.remove-section", BTreeMap::new()),
                EditOperation::RenameSection { name, .. } => (
                    "ini.edit.rename-section",
                    BTreeMap::from([("name_scalars".to_owned(), name.chars().count().to_string())]),
                ),
                EditOperation::InsertEntry {
                    key,
                    value,
                    placement,
                    ..
                } => (
                    "ini.edit.insert-entry",
                    BTreeMap::from([
                        ("key_scalars".to_owned(), key.chars().count().to_string()),
                        (
                            "placement".to_owned(),
                            placement_name(*placement).to_owned(),
                        ),
                        (
                            "value_scalars".to_owned(),
                            value.chars().count().to_string(),
                        ),
                    ]),
                ),
                EditOperation::RemoveEntry { .. } => ("ini.edit.remove-entry", BTreeMap::new()),
                EditOperation::RenameEntry { key, .. } => (
                    "ini.edit.rename-entry",
                    BTreeMap::from([("key_scalars".to_owned(), key.chars().count().to_string())]),
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

const fn placement_name(placement: AssociationPlacement) -> &'static str {
    match placement {
        AssociationPlacement::Start => "start",
        AssociationPlacement::End => "end",
        AssociationPlacement::Before(_) => "before",
        AssociationPlacement::After(_) => "after",
    }
}

impl consema_core::StableFailure for EditFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Edit
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::WrongSnapshot => consema_core::FailureKind::TargetMismatch,
            Self::WrongRole
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorRemoved
            | Self::InvalidName
            | Self::NameCollision
            | Self::InvalidKey
            | Self::KeyCollision => consema_core::FailureKind::InvalidInput,
            Self::RecoveredDocument
            | Self::RepresentationIncompatible
            | Self::ExactLiteralRequiresLiteralOperation
            | Self::InvalidLiteral
            | Self::TargetNotFound => consema_core::FailureKind::NotApplicable,
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
            Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorRemoved => "core.edit.conflicting-edits@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
            Self::InvalidName => "ini.edit.invalid-name@1",
            Self::NameCollision => "ini.edit.name-collision@1",
            Self::InvalidKey => "ini.edit.invalid-key@1",
            Self::KeyCollision => "ini.edit.key-collision@1",
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
    mappings: Vec<PlannedMapping>,
    mergeable_deletion: bool,
}

struct PlannedMapping {
    old: NodeRef,
    plan: MappingPlan,
}

enum MappingPlan {
    ReplacedValue {
        expected_key: String,
        literal: bool,
    },
    ReplacedSection {
        expected_name: String,
    },
    ReplacedEntry {
        expected_key: String,
    },
    SectionAfterEntryInsertion {
        expected_key: String,
        expected_value: String,
    },
    Deleted,
    Unmapped(&'static str),
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

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_section(document.node_ref(), "Next", AssociationPlacement::End);
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.sections().len(), 2);
        assert_eq!(commit.document.sections()[1].name(), "Next");
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

    #[test]
    fn section_insert_rename_and_remove_have_exact_ownership() {
        let source = "[one]\na=1\n; independent\n[two]\nb=2\n";
        let document = parsed(IniProfile::PortableV1, source);

        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_section(
            document.node_ref(),
            "middle",
            AssociationPlacement::After(document.sections()[0].node_ref()),
        );
        let commit = document.commit(&insert.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[one]\na=1\n; independent\n[middle]\n[two]\nb=2\n"
        );
        assert_eq!(commit.document.sections()[1].name(), "middle");

        let mut rename = EditTransactionBuilder::new(&document);
        rename.rename_section(document.sections()[1].node_ref(), "renamed");
        let commit = document.commit(&rename.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[one]\na=1\n; independent\n[renamed]\nb=2\n"
        );
        assert_eq!(
            commit.change_set.node_mappings()[0].status,
            NodeMappingStatus::Replaced
        );

        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_section(document.sections()[0].node_ref());
        let commit = document.commit(&remove.build()).unwrap();
        assert_eq!(commit.document.render(), b"; independent\n[two]\nb=2\n");
        assert_eq!(commit.change_set.node_mappings().len(), 2);
        assert!(
            commit
                .change_set
                .node_mappings()
                .iter()
                .all(|mapping| mapping.status == NodeMappingStatus::Deleted)
        );
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
    fn section_removal_owns_python_continuations_but_not_comments() {
        let document = parsed(
            IniProfile::PythonConfigParserV1,
            "[one]\nk=first\n  second\n\n  fourth\n# keep\n[two]\nx=y\n",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_section(document.sections()[0].node_ref());
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), b"# keep\n[two]\nx=y\n");
        assert_eq!(commit.document.entries().len(), 1);
    }

    #[test]
    fn appending_after_an_eof_entry_introduces_one_profile_newline() {
        let document = parsed(IniProfile::PortableV1, "[one]\na=1");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_section(document.node_ref(), "two", AssociationPlacement::End);
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), b"[one]\na=1\n[two]\n");
    }

    #[test]
    fn multiple_section_insertions_map_the_old_document_once() {
        let document = parsed(IniProfile::PortableV1, "[one]\na=1\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_section(document.node_ref(), "zero", AssociationPlacement::Start)
            .insert_section(document.node_ref(), "last", AssociationPlacement::End);
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), b"[zero]\n[one]\na=1\n[last]\n");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        assert_eq!(
            commit.change_set.node_mappings()[0].status,
            NodeMappingStatus::Unmapped
        );
    }

    #[test]
    fn section_dependencies_names_and_collisions_fail_atomically() {
        let document = parsed(IniProfile::PortableV1, "[one]\na=1\n[two]\nb=2\n");
        let first = document.sections()[0].node_ref();
        let mut conflict = EditTransactionBuilder::new(&document);
        conflict.remove_section(first).semantic_value(
            document.entries()[0].node_ref(),
            "new",
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&conflict.build()),
            Err(EditFailure::AncestorDescendantConflict)
        ));

        let mut removed_anchor = EditTransactionBuilder::new(&document);
        removed_anchor.remove_section(first).insert_section(
            document.node_ref(),
            "three",
            AssociationPlacement::After(first),
        );
        assert!(matches!(
            document.commit(&removed_anchor.build()),
            Err(EditFailure::PlacementAnchorRemoved)
        ));

        let mut invalid = EditTransactionBuilder::new(&document);
        invalid.rename_section(first, "bad name");
        assert!(matches!(
            document.commit(&invalid.build()),
            Err(EditFailure::InvalidName)
        ));

        let mut collision = EditTransactionBuilder::new(&document);
        collision.rename_section(first, "two");
        assert!(matches!(
            document.commit(&collision.build()),
            Err(EditFailure::NameCollision)
        ));

        let mut same_position = EditTransactionBuilder::new(&document);
        same_position
            .insert_section(document.node_ref(), "three", AssociationPlacement::End)
            .insert_section(document.node_ref(), "four", AssociationPlacement::End);
        assert!(matches!(
            document.commit(&same_position.build()),
            Err(EditFailure::OverlappingOwnership)
        ));

        let only = parsed(IniProfile::PortableV1, "[only]\nk=v\n");
        let mut remove_only = EditTransactionBuilder::new(&only);
        remove_only.remove_section(only.sections()[0].node_ref());
        assert!(matches!(
            only.commit(&remove_only.build()),
            Err(EditFailure::NewDocumentFormationFailed)
        ));
    }

    #[test]
    fn entry_insert_rename_and_remove_preserve_unowned_comments() {
        let source = "[s]\na=1\n; independent\nc=3\n[next]\nx=y\n";
        let document = parsed(IniProfile::PortableV1, source);
        let section = document.sections()[0].node_ref();

        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_entry(
            section,
            "b",
            "2",
            AssociationPlacement::After(document.entries()[0].node_ref()),
        );
        let commit = document.commit(&insert.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[s]\na=1\nb=2\n; independent\nc=3\n[next]\nx=y\n"
        );

        let mut rename = EditTransactionBuilder::new(&document);
        rename.rename_entry(document.entries()[1].node_ref(), "renamed");
        let commit = document.commit(&rename.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[s]\na=1\n; independent\nrenamed=3\n[next]\nx=y\n"
        );
        assert_eq!(
            commit.change_set.node_mappings()[0].status,
            NodeMappingStatus::Replaced
        );

        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_entry(document.entries()[0].node_ref());
        let commit = document.commit(&remove.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[s]\n; independent\nc=3\n[next]\nx=y\n"
        );
        assert_eq!(
            commit.change_set.node_mappings()[0].status,
            NodeMappingStatus::Deleted
        );
    }

    #[test]
    fn inserted_values_use_each_profiles_canonical_entry_representation() {
        let windows = parsed(IniProfile::WindowsV1, "[S]\r\na=1\r\n");
        let mut builder = EditTransactionBuilder::new(&windows);
        builder.insert_entry(
            windows.sections()[0].node_ref(),
            "quoted",
            " spaced ",
            AssociationPlacement::End,
        );
        let transaction = builder.build();
        let plan = windows
            .dry_run(
                &transaction,
                EditPlanSourceId::new("memory:windows-entry").unwrap(),
            )
            .unwrap();
        let commit = windows.commit(&transaction).unwrap();
        assert_eq!(plan.source_patch(), &commit.source_patch);
        assert_eq!(
            commit.document.render(),
            b"[S]\r\na=1\r\nquoted=\" spaced \"\r\n"
        );
        assert_eq!(commit.document.entries()[1].value(), " spaced ");

        let python = parsed(IniProfile::PythonConfigParserV1, "[S]\na=1\n");
        let mut builder = EditTransactionBuilder::new(&python);
        builder.insert_entry(
            python.sections()[0].node_ref(),
            "multi",
            "first\n\nthird",
            AssociationPlacement::End,
        );
        let commit = python.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"[S]\na=1\nmulti = first\n\n    third\n"
        );
        assert_eq!(commit.document.entries()[1].value(), "first\n\nthird");
    }

    #[test]
    fn removing_a_python_multiline_entry_owns_its_continuations_only() {
        let document = parsed(
            IniProfile::PythonConfigParserV1,
            "[S]\nmulti=first\n  second\n\n  fourth\n# keep\nnext=value\n",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_entry(document.entries()[0].node_ref());
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), b"[S]\n# keep\nnext=value\n");
    }

    #[test]
    fn entry_keys_placements_and_dependencies_are_validated_before_rendering() {
        let document = parsed(
            IniProfile::PythonConfigParserV1,
            "[S]\nKey=1\nother=2\n[T]\nx=3\n",
        );
        let section = document.sections()[0].node_ref();
        let mut collision = EditTransactionBuilder::new(&document);
        collision.rename_entry(document.entries()[1].node_ref(), "KEY");
        assert!(matches!(
            document.commit(&collision.build()),
            Err(EditFailure::KeyCollision)
        ));

        let mut invalid = EditTransactionBuilder::new(&document);
        invalid.insert_entry(section, "bad:key", "v", AssociationPlacement::End);
        assert!(matches!(
            document.commit(&invalid.build()),
            Err(EditFailure::InvalidKey)
        ));

        let mut cross_section = EditTransactionBuilder::new(&document);
        cross_section.insert_entry(
            section,
            "new",
            "v",
            AssociationPlacement::Before(document.entries()[2].node_ref()),
        );
        assert!(matches!(
            document.commit(&cross_section.build()),
            Err(EditFailure::TargetNotFound)
        ));

        let mut removed_anchor = EditTransactionBuilder::new(&document);
        removed_anchor
            .remove_entry(document.entries()[0].node_ref())
            .insert_entry(
                section,
                "new",
                "v",
                AssociationPlacement::After(document.entries()[0].node_ref()),
            );
        assert!(matches!(
            document.commit(&removed_anchor.build()),
            Err(EditFailure::PlacementAnchorRemoved)
        ));

        let mut removed_section = EditTransactionBuilder::new(&document);
        removed_section.remove_section(section).insert_entry(
            section,
            "new",
            "v",
            AssociationPlacement::End,
        );
        assert!(matches!(
            document.commit(&removed_section.build()),
            Err(EditFailure::AncestorDescendantConflict)
        ));
    }

    #[test]
    fn windows_entry_edits_keep_ordered_case_equivalent_occurrences() {
        let document = parsed(IniProfile::WindowsV1, "[S]\r\nKey=1\r\nother=2\r\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_entry(document.entries()[1].node_ref(), "KEY");
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.entries()[0].comparison_key(), "key");
        assert_eq!(commit.document.entries()[1].comparison_key(), "key");
        assert_eq!(
            commit.document.entries()[0].duplicate_group(),
            commit.document.entries()[1].duplicate_group()
        );
    }
}
