use crate::{Document, EntityKind, InternalItemKind, TomlItemKind, TomlSyntaxKind, parse};
use consema_core::{
    BinaryFloat64, Date, Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    LocalDateTime, OffsetDateTime, PortableValue, PortableValueKind, Time,
};
use consema_document::{
    AssociationPlacement, ChangeSet, MaterializationLimits, NodeMapping, NodeMappingStatus,
    NodeRef, NodeRole, SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits,
    UntouchedByteProof,
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

/// Explicit semantic scalar representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must use an exact literal operation instead.
    ExactLiteral,
    /// New public value must retain the target native scalar category.
    PreserveCompatible,
    /// Use the frozen deterministic TOML 1.0 scalar representation.
    CanonicalForProfile,
    /// Preserve the category when compatible, otherwise report canonical fallback.
    PreserveElseCanonical,
}

/// One scalar operation bound to a transaction base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarReplacement {
    /// Replace by public semantic value under an explicit policy.
    Semantic {
        /// Exact TOML item target.
        target: NodeRef,
        /// New complete core scalar.
        value: PortableValue,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replace by exact candidate literal bytes after full profile validation.
    Literal {
        /// Exact TOML item target.
        target: NodeRef,
        /// Exact candidate scalar bytes.
        literal: Arc<[u8]>,
    },
}

impl ScalarReplacement {
    const fn target(&self) -> NodeRef {
        match self {
            Self::Semantic { target, .. } | Self::Literal { target, .. } => *target,
        }
    }
}

/// One typed TOML edit operation bound to an immutable base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Existing scalar semantic or literal replacement.
    ReplaceScalar(ScalarReplacement),
    /// Inserts one direct entry into a root, standard, or inline table.
    InsertEntry {
        /// Exact table item target.
        table: NodeRef,
        /// Decoded direct key segment.
        key: String,
        /// Complete inserted value.
        value: PortableValue,
        /// Explicit association placement.
        placement: AssociationPlacement,
    },
    /// Removes one exact direct entry identity.
    RemoveEntry {
        /// Exact `TomlEntry` target.
        target: NodeRef,
    },
    /// Replaces only one exact entry's direct key segment.
    RenameEntry {
        /// Exact `TomlEntry` target.
        target: NodeRef,
        /// New decoded direct key segment.
        key: String,
    },
    /// Inserts one complete element into a TOML array value.
    InsertArrayElement {
        /// Exact Array item target.
        array: NodeRef,
        /// Complete inserted value.
        value: PortableValue,
        /// Explicit association placement.
        placement: AssociationPlacement,
    },
    /// Removes one exact TOML array element identity.
    RemoveArrayElement {
        /// Exact `TomlArrayElement` target.
        target: NodeRef,
    },
}

/// Immutable transaction; every operation resolves against one base snapshot.
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

/// Builder that is not a committed edit.
#[derive(Debug)]
pub struct EditTransactionBuilder {
    base: SnapshotIdentity,
    operations: Vec<EditOperation>,
}

impl EditTransactionBuilder {
    /// Binds a new transaction to one immutable base document.
    #[must_use]
    pub fn new(document: &Document) -> Self {
        Self {
            base: document.snapshot_identity(),
            operations: Vec::new(),
        }
    }

    /// Adds a semantic scalar replacement.
    pub fn semantic_scalar(
        &mut self,
        target: NodeRef,
        value: PortableValue,
        policy: RepresentationPolicy,
    ) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceScalar(ScalarReplacement::Semantic {
                target,
                value,
                policy,
            }));
        self
    }

    /// Adds an exact TOML scalar literal replacement.
    pub fn literal_scalar(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceScalar(ScalarReplacement::Literal {
                target,
                literal: literal.into(),
            }));
        self
    }

    /// Adds one direct TOML table entry insertion.
    pub fn insert_entry(
        &mut self,
        table: NodeRef,
        key: impl Into<String>,
        value: PortableValue,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertEntry {
            table,
            key: key.into(),
            value,
            placement,
        });
        self
    }

    /// Adds one exact TOML table entry removal.
    pub fn remove_entry(&mut self, target: NodeRef) -> &mut Self {
        self.operations.push(EditOperation::RemoveEntry { target });
        self
    }

    /// Adds one exact TOML direct key rename.
    pub fn rename_entry(&mut self, target: NodeRef, key: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::RenameEntry {
            target,
            key: key.into(),
        });
        self
    }

    /// Adds one TOML array element insertion.
    pub fn insert_array_element(
        &mut self,
        array: NodeRef,
        value: PortableValue,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertArrayElement {
            array,
            value,
            placement,
        });
        self
    }

    /// Adds one exact TOML array element removal.
    pub fn remove_array_element(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveArrayElement { target });
        self
    }

    /// Completes the immutable request; target validation occurs atomically at commit.
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
    /// Portable exact raw-byte application fact.
    pub source_patch: SourcePatch,
    /// Verifiable evidence for every byte outside the replacement set.
    pub untouched_proof: UntouchedByteProof,
}

/// Stable edit validation or commit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditFailure {
    /// Transaction or target belongs to another snapshot.
    WrongSnapshot,
    /// Target is not a TOML scalar item.
    WrongRole,
    /// Public value cannot be represented as a TOML 1.0 scalar without semantic loss.
    UnsupportedSemanticValue(PortableValueKind),
    /// Candidate bytes are not exactly one complete TOML 1.0 scalar literal.
    InvalidLiteral,
    /// `PreserveCompatible` could not retain the scalar category.
    RepresentationIncompatible,
    /// `ExactLiteral` was requested without literal bytes.
    ExactLiteralRequiresLiteralOperation,
    /// Two source edits overlap or target the same scalar.
    ConflictingEdits,
    /// More than one operation names the same exact destructive target.
    DuplicateTarget,
    /// Prepared source ownership intervals overlap or reuse one insertion point.
    OverlappingOwnership,
    /// An insertion anchor is removed by the same transaction.
    PlacementAnchorRemoved,
    /// A target or placement anchor is not present in its declared container.
    TargetNotFound,
    /// The requested key already exists in the target table.
    DuplicateKey,
    /// The requested structural operation is outside the frozen TOML v1 edit surface.
    UnsupportedOperation,
    /// A structural value cannot be represented by TOML 1.0.
    UnrepresentableValue(PortableValueKind),
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement document could not be formed under the original limits.
    NewDocumentFormationFailed,
}

impl Document {
    /// Atomically commits scalar and structural operations. A failure never changes this snapshot.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        validate_dependencies(transaction)?;
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::new();
        prepared
            .try_reserve(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for operation in transaction.operations.iter() {
            prepared.extend(self.prepare_operation(operation, &mut diagnostics)?);
        }

        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        for pair in prepared.windows(2) {
            if pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
                || pair[0].old_span == pair[1].old_span
                || (pair[0].old_span.is_empty()
                    && pair[1].old_span.is_empty()
                    && pair[0].old_span.start_byte() == pair[1].old_span.start_byte())
            {
                return Err(EditFailure::OverlappingOwnership);
            }
        }

        let target_len = prepared
            .iter()
            .try_fold(self.source.len(), |length, edit| {
                length
                    .checked_sub(edit.old_span.len())
                    .and_then(|length| length.checked_add(edit.replacement.len()))
                    .ok_or(EditFailure::ResourceLimit("target-bytes"))
            })?;
        if target_len > self.parse_limits.max_source_bytes {
            return Err(EditFailure::ResourceLimit("target-bytes"));
        }
        let mut rendered = Vec::new();
        rendered
            .try_reserve_exact(target_len)
            .map_err(|_| EditFailure::ResourceLimit("target-allocation"))?;
        let mut cursor = 0;
        for edit in &prepared {
            rendered.extend_from_slice(&self.source.bytes()[cursor..edit.old_span.start_byte()]);
            rendered.extend_from_slice(&edit.replacement);
            cursor = edit.old_span.end_byte();
        }
        rendered.extend_from_slice(&self.source.bytes()[cursor..]);
        let new_document = parse(rendered, self.profile, self.parse_limits)
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;

        let mut delta = 0_isize;
        let mut source_edits = Vec::new();
        source_edits
            .try_reserve(prepared.len())
            .map_err(|_| EditFailure::ResourceLimit("source-edits"))?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("node-mappings"))?;
        let mut mapped_old = HashSet::new();
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
            if let Some((old, plan)) = edit.mapping {
                if mapped_old.insert(old) {
                    let (new, status, reason) = match plan {
                        MappingPlan::ReplacedLiteral => {
                            let new = find_item_by_span(&new_document, new_start, new_end)
                                .map(|index| new_document.node_ref(index, NodeRole::TomlItem));
                            (
                                new,
                                NodeMappingStatus::Replaced,
                                new.is_none()
                                    .then(|| "reparsed-item-not-uniquely-located".to_owned()),
                            )
                        }
                        MappingPlan::Deleted => (None, NodeMappingStatus::Deleted, None),
                        MappingPlan::Unmapped(reason) => {
                            (None, NodeMappingStatus::Unmapped, Some(reason.to_owned()))
                        }
                    };
                    mappings.push(NodeMapping {
                        old,
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
            &self.source,
            new_document.source(),
            &change_set,
            operation_metadata(transaction),
            patch_limits,
        )
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        let untouched_proof = UntouchedByteProof::create(
            &self.source,
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

    fn prepare_operation(
        &self,
        operation: &EditOperation,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        match operation {
            EditOperation::ReplaceScalar(operation) => {
                Ok(vec![self.prepare_scalar(operation, diagnostics)?])
            }
            EditOperation::InsertEntry {
                table,
                key,
                value,
                placement,
            } => self.prepare_insert_entry(*table, key, value, *placement),
            EditOperation::RemoveEntry { target } => self.prepare_remove_entry(*target),
            EditOperation::RenameEntry { target, key } => {
                Ok(vec![self.prepare_rename_entry(*target, key)?])
            }
            EditOperation::InsertArrayElement {
                array,
                value,
                placement,
            } => self.prepare_insert_array_element(*array, value, *placement),
            EditOperation::RemoveArrayElement { target } => {
                self.prepare_remove_array_element(*target)
            }
        }
    }

    fn prepare_scalar(
        &self,
        operation: &ScalarReplacement,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<PreparedEdit, EditFailure> {
        let target = operation.target();
        let index = self.resolve_target(target, NodeRole::TomlItem)?;
        let old_kind = self.item_entity(index).kind.public_kind();
        if !is_scalar_kind(old_kind) {
            return Err(EditFailure::WrongRole);
        }
        let replacement = match operation {
            ScalarReplacement::Literal { literal, .. } => {
                validate_exact_scalar(literal)?;
                literal.to_vec()
            }
            ScalarReplacement::Semantic { value, policy, .. } => {
                semantic_literal(value, old_kind, *policy, target, diagnostics)?
            }
        };
        Ok(PreparedEdit {
            old_span: self.entity(index).span,
            replacement,
            mapping: Some((target, MappingPlan::ReplacedLiteral)),
        })
    }

    fn prepare_insert_entry(
        &self,
        table: NodeRef,
        key: &str,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let table_index = self.resolve_target(table, NodeRole::TomlItem)?;
        let item = &self.item_entity(table_index).kind;
        let entries = match item {
            InternalItemKind::Table { entries, .. } | InternalItemKind::InlineTable(entries) => {
                entries.as_slice()
            }
            _ => return Err(EditFailure::WrongRole),
        };
        let kind = item.public_kind();
        if !matches!(
            kind,
            TomlItemKind::RootTable | TomlItemKind::StandardTable | TomlItemKind::InlineTable
        ) {
            return Err(EditFailure::UnsupportedOperation);
        }
        if entries.iter().any(|index| self.entry_name(*index) == key) {
            return Err(EditFailure::DuplicateKey);
        }
        let mut fragment = canonical_string(key).into_bytes();
        append_fragment(&mut fragment, b" = ", self.parse_limits.max_source_bytes)?;
        append_fragment(
            &mut fragment,
            &self.fragment(value)?,
            self.parse_limits.max_source_bytes,
        )?;
        let prepared = if kind == TomlItemKind::InlineTable {
            self.prepare_delimited_insertion(
                table,
                self.entity(table_index).span,
                entries,
                DelimitedSyntax {
                    anchor_role: NodeRole::TomlEntry,
                    open: TomlSyntaxKind::LeftBrace,
                    close: TomlSyntaxKind::RightBrace,
                },
                placement,
                fragment,
            )?
        } else {
            self.prepare_table_line_insertion(table, table_index, entries, placement, fragment)?
        };
        Ok(vec![prepared])
    }

    fn prepare_insert_array_element(
        &self,
        array: NodeRef,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(array, NodeRole::TomlItem)?;
        let InternalItemKind::Array(elements) = &self.item_entity(index).kind else {
            return Err(EditFailure::WrongRole);
        };
        Ok(vec![self.prepare_delimited_insertion(
            array,
            self.entity(index).span,
            elements,
            DelimitedSyntax {
                anchor_role: NodeRole::TomlArrayElement,
                open: TomlSyntaxKind::LeftBracket,
                close: TomlSyntaxKind::RightBracket,
            },
            placement,
            self.fragment(value)?,
        )?])
    }

    fn prepare_delimited_insertion(
        &self,
        container: NodeRef,
        container_span: consema_document::Span,
        associations: &[usize],
        syntax: DelimitedSyntax,
        placement: AssociationPlacement,
        fragment: Vec<u8>,
    ) -> Result<PreparedEdit, EditFailure> {
        let (position, prefix_comma, suffix_comma) = if associations.is_empty() {
            match placement {
                AssociationPlacement::Start => (
                    self.delimiter(syntax.open, container_span, false)?
                        .end_byte(),
                    false,
                    false,
                ),
                AssociationPlacement::End => (
                    self.delimiter(syntax.close, container_span, true)?
                        .start_byte(),
                    false,
                    false,
                ),
                AssociationPlacement::Before(_) | AssociationPlacement::After(_) => {
                    return Err(EditFailure::TargetNotFound);
                }
            }
        } else {
            match placement {
                AssociationPlacement::Start => {
                    (self.entity(associations[0]).span.start_byte(), false, true)
                }
                AssociationPlacement::End => (
                    self.entity(*associations.last().expect("non-empty"))
                        .span
                        .end_byte(),
                    true,
                    false,
                ),
                AssociationPlacement::Before(anchor) => {
                    let anchor = self.resolve_anchor(anchor, syntax.anchor_role, associations)?;
                    (self.entity(anchor).span.start_byte(), false, true)
                }
                AssociationPlacement::After(anchor) => {
                    let anchor = self.resolve_anchor(anchor, syntax.anchor_role, associations)?;
                    (self.entity(anchor).span.end_byte(), true, false)
                }
            }
        };
        let mut replacement = Vec::new();
        replacement
            .try_reserve(fragment.len().saturating_add(2))
            .map_err(|_| EditFailure::ResourceLimit("insert-fragment"))?;
        if prefix_comma {
            replacement.push(b',');
        }
        replacement.extend_from_slice(&fragment);
        if suffix_comma {
            replacement.push(b',');
        }
        Ok(PreparedEdit {
            old_span: self
                .authority
                .span(position, position)
                .map_err(|_| EditFailure::TargetNotFound)?,
            replacement,
            mapping: Some((
                container,
                MappingPlan::Unmapped("container-reparsed-after-structural-insertion"),
            )),
        })
    }

    fn prepare_table_line_insertion(
        &self,
        table: NodeRef,
        table_index: usize,
        entries: &[usize],
        placement: AssociationPlacement,
        fragment: Vec<u8>,
    ) -> Result<PreparedEdit, EditFailure> {
        let kind = self.item_entity(table_index).kind.public_kind();
        let position = match placement {
            AssociationPlacement::Start => {
                if kind == TomlItemKind::RootTable {
                    0
                } else {
                    self.first_line_after_header(self.entity(table_index).span)
                }
            }
            AssociationPlacement::End => self.table_end_insertion(entries, table_index),
            AssociationPlacement::Before(anchor) => {
                let anchor = self.resolve_anchor(anchor, NodeRole::TomlEntry, entries)?;
                self.line_start(self.entity(anchor).span.start_byte())
            }
            AssociationPlacement::After(anchor) => {
                let anchor = self.resolve_anchor(anchor, NodeRole::TomlEntry, entries)?;
                if is_table_kind(self.entry_item_kind(anchor)) {
                    return Err(EditFailure::UnsupportedOperation);
                }
                self.line_after(self.entity(anchor).span.end_byte())
            }
        };
        Ok(PreparedEdit {
            old_span: self
                .authority
                .span(position, position)
                .map_err(|_| EditFailure::TargetNotFound)?,
            replacement: self.line_fragment(position, fragment)?,
            mapping: Some((
                table,
                MappingPlan::Unmapped("table-reparsed-after-entry-insertion"),
            )),
        })
    }

    fn prepare_remove_entry(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(target, NodeRole::TomlEntry)?;
        if is_table_kind(self.entry_item_kind(index)) {
            return Err(EditFailure::UnsupportedOperation);
        }
        let (container, entries, ordinal) = self
            .parent_table(index)
            .ok_or(EditFailure::TargetNotFound)?;
        match self.item_entity(container).kind.public_kind() {
            TomlItemKind::InlineTable => self.prepare_delimited_removal(
                target,
                index,
                entries,
                ordinal,
                self.entity(container).span.end_byte(),
            ),
            TomlItemKind::RootTable | TomlItemKind::StandardTable => Ok(vec![PreparedEdit {
                old_span: self.entity(index).span,
                replacement: Vec::new(),
                mapping: Some((target, MappingPlan::Deleted)),
            }]),
            _ => Err(EditFailure::UnsupportedOperation),
        }
    }

    fn prepare_remove_array_element(
        &self,
        target: NodeRef,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(target, NodeRole::TomlArrayElement)?;
        let (container, elements, ordinal) = self
            .parent_array(index)
            .ok_or(EditFailure::TargetNotFound)?;
        self.prepare_delimited_removal(
            target,
            index,
            elements,
            ordinal,
            self.entity(container).span.end_byte(),
        )
    }

    fn prepare_delimited_removal(
        &self,
        target: NodeRef,
        index: usize,
        associations: &[usize],
        ordinal: usize,
        container_end: usize,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let target_span = self.entity(index).span;
        let mut edits = Vec::new();
        edits
            .try_reserve(2)
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        if let Some(comma) = self.removal_comma(associations, ordinal, container_end)? {
            if comma.end_byte() == target_span.start_byte()
                || comma.start_byte() == target_span.end_byte()
            {
                edits.push(PreparedEdit {
                    old_span: self
                        .authority
                        .span(
                            comma.start_byte().min(target_span.start_byte()),
                            comma.end_byte().max(target_span.end_byte()),
                        )
                        .map_err(|_| EditFailure::TargetNotFound)?,
                    replacement: Vec::new(),
                    mapping: Some((target, MappingPlan::Deleted)),
                });
                return Ok(edits);
            }
            edits.push(PreparedEdit {
                old_span: target_span,
                replacement: Vec::new(),
                mapping: Some((target, MappingPlan::Deleted)),
            });
            edits.push(PreparedEdit {
                old_span: comma,
                replacement: Vec::new(),
                mapping: None,
            });
        } else {
            edits.push(PreparedEdit {
                old_span: target_span,
                replacement: Vec::new(),
                mapping: Some((target, MappingPlan::Deleted)),
            });
        }
        Ok(edits)
    }

    fn prepare_rename_entry(
        &self,
        target: NodeRef,
        key: &str,
    ) -> Result<PreparedEdit, EditFailure> {
        let index = self.resolve_target(target, NodeRole::TomlEntry)?;
        if is_table_kind(self.entry_item_kind(index)) {
            return Err(EditFailure::UnsupportedOperation);
        }
        let (container, entries, _) = self
            .parent_table(index)
            .ok_or(EditFailure::TargetNotFound)?;
        if !matches!(
            self.item_entity(container).kind.public_kind(),
            TomlItemKind::RootTable | TomlItemKind::StandardTable | TomlItemKind::InlineTable
        ) {
            return Err(EditFailure::UnsupportedOperation);
        }
        if entries
            .iter()
            .any(|candidate| *candidate != index && self.entry_name(*candidate) == key)
        {
            return Err(EditFailure::DuplicateKey);
        }
        let EntityKind::Entry(entry) = &self.entity(index).kind else {
            return Err(EditFailure::WrongRole);
        };
        Ok(PreparedEdit {
            old_span: self.entity(entry.key).span,
            replacement: canonical_string(key).into_bytes(),
            mapping: Some((
                target,
                MappingPlan::Unmapped("entry-reparsed-after-key-rename"),
            )),
        })
    }

    fn resolve_target(&self, target: NodeRef, role: NodeRole) -> Result<usize, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != role {
            return Err(EditFailure::WrongRole);
        }
        self.validate_ref(target, role)
            .map_err(|failure| match failure {
                crate::TomlAccessError::WrongSnapshot => EditFailure::WrongSnapshot,
                crate::TomlAccessError::WrongRole => EditFailure::WrongRole,
                crate::TomlAccessError::UnknownNode => EditFailure::TargetNotFound,
            })
    }

    fn resolve_anchor(
        &self,
        anchor: NodeRef,
        role: NodeRole,
        associations: &[usize],
    ) -> Result<usize, EditFailure> {
        let index = self.resolve_target(anchor, role)?;
        associations
            .contains(&index)
            .then_some(index)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn fragment(&self, value: &PortableValue) -> Result<Vec<u8>, EditFailure> {
        crate::materialization::canonical_fragment(
            value,
            MaterializationLimits {
                max_input_nodes: self.parse_limits.max_node_count,
                max_output_bytes: self.parse_limits.max_source_bytes,
                max_depth: self.parse_limits.max_nesting_depth,
                max_report_entries: self.parse_limits.max_diagnostics,
                max_provenance_entries: self.parse_limits.max_node_count.saturating_mul(4),
            },
        )
        .map_err(|failure| match failure {
            consema_document::MaterializationFailure::Unrepresentable { kind, .. } => {
                EditFailure::UnrepresentableValue(kind)
            }
            consema_document::MaterializationFailure::ResourceLimit(name) => {
                EditFailure::ResourceLimit(name)
            }
            _ => EditFailure::NewDocumentFormationFailed,
        })
    }

    fn parent_table(&self, entry: usize) -> Option<(usize, &[usize], usize)> {
        self.entities
            .iter()
            .enumerate()
            .find_map(|(index, entity)| match &entity.kind {
                EntityKind::Item(item) => match &item.kind {
                    InternalItemKind::Table { entries, .. }
                    | InternalItemKind::InlineTable(entries) => entries
                        .iter()
                        .position(|candidate| *candidate == entry)
                        .map(|ordinal| (index, entries.as_slice(), ordinal)),
                    _ => None,
                },
                _ => None,
            })
    }

    fn parent_array(&self, element: usize) -> Option<(usize, &[usize], usize)> {
        self.entities
            .iter()
            .enumerate()
            .find_map(|(index, entity)| match &entity.kind {
                EntityKind::Item(item) => match &item.kind {
                    InternalItemKind::Array(elements) => elements
                        .iter()
                        .position(|candidate| *candidate == element)
                        .map(|ordinal| (index, elements.as_slice(), ordinal)),
                    _ => None,
                },
                _ => None,
            })
    }

    fn entry_name(&self, entry: usize) -> &str {
        let EntityKind::Entry(entry) = &self.entity(entry).kind else {
            unreachable!("typed TOML entry")
        };
        let EntityKind::Key(key) = &self.entity(entry.key).kind else {
            unreachable!("typed TOML key")
        };
        &key.name
    }

    fn entry_item_kind(&self, entry: usize) -> TomlItemKind {
        let EntityKind::Entry(entry) = &self.entity(entry).kind else {
            unreachable!("typed TOML entry")
        };
        self.item_entity(entry.item).kind.public_kind()
    }

    fn table_end_insertion(&self, entries: &[usize], table_index: usize) -> usize {
        if let Some(entry) = entries
            .iter()
            .find(|entry| is_table_kind(self.entry_item_kind(**entry)))
        {
            return self.line_start(self.entity(*entry).span.start_byte());
        }
        if let Some(entry) = entries.last() {
            return self.line_after(self.entity(*entry).span.end_byte());
        }
        if self.item_entity(table_index).kind.public_kind() == TomlItemKind::StandardTable {
            return self.first_line_after_header(self.entity(table_index).span);
        }
        self.entity(table_index).span.end_byte()
    }

    fn first_line_after_header(&self, table_span: consema_document::Span) -> usize {
        self.line_after(table_span.start_byte())
    }

    fn line_start(&self, position: usize) -> usize {
        self.source.bytes()[..position]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1)
    }

    fn line_after(&self, position: usize) -> usize {
        self.source.bytes()[position..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(self.source.len(), |index| position + index + 1)
    }

    fn line_fragment(&self, position: usize, fragment: Vec<u8>) -> Result<Vec<u8>, EditFailure> {
        let newline = self.newline_bytes();
        let needs_prefix = position > 0 && self.source.bytes()[position - 1] != b'\n';
        let needs_suffix = position < self.source.len();
        let extra = newline
            .len()
            .saturating_mul(usize::from(needs_prefix) + usize::from(needs_suffix));
        let mut replacement = Vec::new();
        replacement
            .try_reserve(fragment.len().saturating_add(extra))
            .map_err(|_| EditFailure::ResourceLimit("insert-fragment"))?;
        if needs_prefix {
            replacement.extend_from_slice(newline);
        }
        replacement.extend_from_slice(&fragment);
        if needs_suffix {
            replacement.extend_from_slice(newline);
        }
        Ok(replacement)
    }

    fn newline_bytes(&self) -> &[u8] {
        self.structural_index
            .pieces()
            .iter()
            .zip(self.syntax_kinds.iter())
            .find(|(_, kind)| **kind == TomlSyntaxKind::Newline)
            .map_or(b"\n", |(piece, _)| {
                &self.source.bytes()[piece.span().start_byte()..piece.span().end_byte()]
            })
    }

    fn removal_comma(
        &self,
        associations: &[usize],
        ordinal: usize,
        container_end: usize,
    ) -> Result<Option<consema_document::Span>, EditFailure> {
        let current = self.entity(associations[ordinal]).span;
        let following_end = associations
            .get(ordinal + 1)
            .map_or(container_end, |index| self.entity(*index).span.start_byte());
        if let Some(comma) = self.syntax_between(
            TomlSyntaxKind::Comma,
            current.end_byte(),
            following_end,
            false,
        ) {
            return Ok(Some(comma));
        }
        if ordinal == 0 {
            return Ok(None);
        }
        let previous = self.entity(associations[ordinal - 1]).span;
        self.syntax_between(
            TomlSyntaxKind::Comma,
            previous.end_byte(),
            current.start_byte(),
            true,
        )
        .map(Some)
        .ok_or(EditFailure::TargetNotFound)
    }

    fn delimiter(
        &self,
        kind: TomlSyntaxKind,
        container: consema_document::Span,
        last: bool,
    ) -> Result<consema_document::Span, EditFailure> {
        self.syntax_between(kind, container.start_byte(), container.end_byte(), last)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn syntax_between(
        &self,
        kind: TomlSyntaxKind,
        start: usize,
        end: usize,
        last: bool,
    ) -> Option<consema_document::Span> {
        let mut matches = self
            .structural_index
            .pieces()
            .iter()
            .zip(self.syntax_kinds.iter())
            .filter(|(piece, candidate)| {
                **candidate == kind
                    && piece.span().start_byte() >= start
                    && piece.span().end_byte() <= end
            })
            .map(|(piece, _)| piece.span());
        if last {
            matches.next_back()
        } else {
            matches.next()
        }
    }
}

fn validate_dependencies(transaction: &EditTransaction) -> Result<(), EditFailure> {
    let mut destructive = HashSet::new();
    let mut removed = HashSet::new();
    let mut anchors = Vec::new();
    for operation in transaction.operations.iter() {
        let target = match operation {
            EditOperation::ReplaceScalar(operation) => Some(operation.target()),
            EditOperation::RemoveEntry { target }
            | EditOperation::RenameEntry { target, .. }
            | EditOperation::RemoveArrayElement { target } => Some(*target),
            EditOperation::InsertEntry { .. } | EditOperation::InsertArrayElement { .. } => None,
        };
        if let Some(target) = target {
            if !destructive.insert(target) {
                return Err(EditFailure::DuplicateTarget);
            }
        }
        match operation {
            EditOperation::RemoveEntry { target }
            | EditOperation::RemoveArrayElement { target } => {
                removed.insert(*target);
            }
            EditOperation::InsertEntry { placement, .. }
            | EditOperation::InsertArrayElement { placement, .. } => match placement {
                AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor) => {
                    anchors.push(*anchor);
                }
                AssociationPlacement::Start | AssociationPlacement::End => {}
            },
            EditOperation::ReplaceScalar(_) | EditOperation::RenameEntry { .. } => {}
        }
    }
    if anchors.iter().any(|anchor| removed.contains(anchor)) {
        return Err(EditFailure::PlacementAnchorRemoved);
    }
    Ok(())
}

fn append_fragment(output: &mut Vec<u8>, fragment: &[u8], max: usize) -> Result<(), EditFailure> {
    let new_len = output
        .len()
        .checked_add(fragment.len())
        .ok_or(EditFailure::ResourceLimit("insert-fragment"))?;
    if new_len > max {
        return Err(EditFailure::ResourceLimit("insert-fragment"));
    }
    output
        .try_reserve(fragment.len())
        .map_err(|_| EditFailure::ResourceLimit("insert-fragment"))?;
    output.extend_from_slice(fragment);
    Ok(())
}

fn source_patch_limits(
    parse_limits: consema_document::ParseLimits,
    operation_count: usize,
) -> SourcePatchLimits {
    SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: parse_limits.max_source_bytes,
            max_decoded_utf8_bytes: parse_limits.max_source_bytes,
            max_decoded_scalars: parse_limits.max_source_bytes,
        },
        max_replacements: operation_count,
        max_patch_bytes: parse_limits.max_source_bytes.saturating_mul(2),
    }
}

fn operation_metadata(transaction: &EditTransaction) -> BTreeMap<String, String> {
    transaction
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let id = match operation {
                EditOperation::ReplaceScalar(ScalarReplacement::Semantic { .. }) => {
                    "toml.edit.replace-scalar-semantic@1"
                }
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { .. }) => {
                    "toml.edit.replace-scalar-literal@1"
                }
                EditOperation::InsertEntry { .. } => "toml.edit.insert-entry@1",
                EditOperation::RemoveEntry { .. } => "toml.edit.remove-entry@1",
                EditOperation::RenameEntry { .. } => "toml.edit.rename-entry@1",
                EditOperation::InsertArrayElement { .. } => "toml.edit.insert-array-element@1",
                EditOperation::RemoveArrayElement { .. } => "toml.edit.remove-array-element@1",
            };
            (format!("operation.{index}"), id.to_owned())
        })
        .collect()
}

impl consema_core::StableFailure for EditFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Edit
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::WrongSnapshot => consema_core::FailureKind::TargetMismatch,
            Self::WrongRole
            | Self::InvalidLiteral
            | Self::ExactLiteralRequiresLiteralOperation
            | Self::ConflictingEdits
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::PlacementAnchorRemoved
            | Self::DuplicateKey => consema_core::FailureKind::InvalidInput,
            Self::TargetNotFound | Self::RepresentationIncompatible => {
                consema_core::FailureKind::NotApplicable
            }
            Self::UnsupportedSemanticValue(_)
            | Self::UnsupportedOperation
            | Self::UnrepresentableValue(_) => consema_core::FailureKind::Unsupported,
            Self::ResourceLimit(_) => consema_core::FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::UnsupportedSemanticValue(_) | Self::UnrepresentableValue(_) => {
                "core.edit.unsupported-value@1"
            }
            Self::InvalidLiteral => "core.edit.invalid-literal@1",
            Self::RepresentationIncompatible => "core.edit.representation-incompatible@1",
            Self::ExactLiteralRequiresLiteralOperation => {
                "core.edit.exact-literal-requires-literal@1"
            }
            Self::ConflictingEdits
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::PlacementAnchorRemoved => "core.edit.conflicting-edits@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
            Self::DuplicateKey => "core.edit.duplicate-key@1",
            Self::UnsupportedOperation => "core.edit.operation-unsupported@1",
            Self::ResourceLimit(_) => "core.edit.resource-limit@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

struct PreparedEdit {
    old_span: consema_document::Span,
    replacement: Vec<u8>,
    mapping: Option<(NodeRef, MappingPlan)>,
}

#[derive(Clone, Copy)]
struct DelimitedSyntax {
    anchor_role: NodeRole,
    open: TomlSyntaxKind,
    close: TomlSyntaxKind,
}

#[derive(Clone, Copy)]
enum MappingPlan {
    ReplacedLiteral,
    Deleted,
    Unmapped(&'static str),
}

fn is_scalar_kind(kind: TomlItemKind) -> bool {
    matches!(
        kind,
        TomlItemKind::String
            | TomlItemKind::Integer
            | TomlItemKind::Float
            | TomlItemKind::Boolean
            | TomlItemKind::OffsetDateTime
            | TomlItemKind::LocalDateTime
            | TomlItemKind::LocalDate
            | TomlItemKind::LocalTime
    )
}

fn is_table_kind(kind: TomlItemKind) -> bool {
    matches!(
        kind,
        TomlItemKind::RootTable
            | TomlItemKind::StandardTable
            | TomlItemKind::ImplicitTable
            | TomlItemKind::DottedTable
            | TomlItemKind::ArrayOfTables
    )
}

fn validate_exact_scalar(literal: &[u8]) -> Result<TomlItemKind, EditFailure> {
    let literal = std::str::from_utf8(literal).map_err(|_| EditFailure::InvalidLiteral)?;
    let prefix = "_ = ";
    let source = format!("{prefix}{literal}");
    let parsed = toml_edit::ImDocument::parse(source).map_err(|_| EditFailure::InvalidLiteral)?;
    if parsed.iter().count() != 1 {
        return Err(EditFailure::InvalidLiteral);
    }
    let value = parsed
        .get("_")
        .and_then(toml_edit::Item::as_value)
        .ok_or(EditFailure::InvalidLiteral)?;
    if value.span() != Some(prefix.len()..prefix.len() + literal.len()) {
        return Err(EditFailure::InvalidLiteral);
    }
    match value {
        toml_edit::Value::String(_) => Ok(TomlItemKind::String),
        toml_edit::Value::Integer(_) => Ok(TomlItemKind::Integer),
        toml_edit::Value::Float(_) => Ok(TomlItemKind::Float),
        toml_edit::Value::Boolean(_) => Ok(TomlItemKind::Boolean),
        toml_edit::Value::Datetime(value) => {
            let value = value.value();
            match (value.date, value.time, value.offset) {
                (Some(_), Some(_), Some(_)) => Ok(TomlItemKind::OffsetDateTime),
                (Some(_), Some(_), None) => Ok(TomlItemKind::LocalDateTime),
                (Some(_), None, None) => Ok(TomlItemKind::LocalDate),
                (None, Some(_), None) => Ok(TomlItemKind::LocalTime),
                _ => Err(EditFailure::InvalidLiteral),
            }
        }
        toml_edit::Value::Array(_) | toml_edit::Value::InlineTable(_) => {
            Err(EditFailure::InvalidLiteral)
        }
    }
}

fn semantic_literal(
    value: &PortableValue,
    old_kind: TomlItemKind,
    policy: RepresentationPolicy,
    target: NodeRef,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<u8>, EditFailure> {
    if policy == RepresentationPolicy::ExactLiteral {
        return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
    }
    let new_kind = portable_toml_kind(value)
        .ok_or_else(|| EditFailure::UnsupportedSemanticValue(value.kind()))?;
    let compatible = old_kind == new_kind;
    match policy {
        RepresentationPolicy::PreserveCompatible if !compatible => {
            return Err(EditFailure::RepresentationIncompatible);
        }
        RepresentationPolicy::PreserveElseCanonical if !compatible => {
            let mut diagnostic = Diagnostic::new(
                "toml.edit.representation-fallback@1",
                DiagnosticCategory::Edit,
                DiagnosticSeverity::Warning,
                None,
                diagnostics.len() as u64,
            );
            diagnostic
                .arguments
                .insert("target".to_owned(), format!("{target:?}"));
            diagnostic
                .arguments
                .insert("old_kind".to_owned(), format!("{old_kind:?}"));
            diagnostic
                .arguments
                .insert("new_kind".to_owned(), format!("{new_kind:?}"));
            diagnostics.push(diagnostic);
        }
        _ => {}
    }
    let literal = canonical_literal(value)?;
    let validated_kind = validate_exact_scalar(literal.as_bytes())?;
    if validated_kind != new_kind {
        return Err(EditFailure::UnsupportedSemanticValue(value.kind()));
    }
    Ok(literal.into_bytes())
}

fn portable_toml_kind(value: &PortableValue) -> Option<TomlItemKind> {
    match value.kind() {
        PortableValueKind::String => Some(TomlItemKind::String),
        PortableValueKind::Integer => Some(TomlItemKind::Integer),
        PortableValueKind::BinaryFloat64 => Some(TomlItemKind::Float),
        PortableValueKind::Boolean => Some(TomlItemKind::Boolean),
        PortableValueKind::Date => Some(TomlItemKind::LocalDate),
        PortableValueKind::Time => Some(TomlItemKind::LocalTime),
        PortableValueKind::LocalDateTime => Some(TomlItemKind::LocalDateTime),
        PortableValueKind::OffsetDateTime => Some(TomlItemKind::OffsetDateTime),
        _ => None,
    }
}

fn canonical_literal(value: &PortableValue) -> Result<String, EditFailure> {
    match value.kind() {
        PortableValueKind::String => Ok(canonical_string(
            value.as_string().expect("kind checked string"),
        )),
        PortableValueKind::Integer => {
            let integer = value.as_integer().expect("kind checked integer");
            integer
                .to_i64()
                .map(|_| integer.to_string())
                .ok_or(EditFailure::UnsupportedSemanticValue(value.kind()))
        }
        PortableValueKind::BinaryFloat64 => {
            canonical_float(value.as_binary_float64().expect("kind checked binary64"))
                .ok_or(EditFailure::UnsupportedSemanticValue(value.kind()))
        }
        PortableValueKind::Boolean => Ok(value
            .as_boolean()
            .expect("kind checked boolean")
            .to_string()),
        PortableValueKind::Date => canonical_date(value.as_date().expect("kind checked date"))
            .ok_or(EditFailure::UnsupportedSemanticValue(value.kind())),
        PortableValueKind::Time => canonical_time(value.as_time().expect("kind checked time"))
            .ok_or(EditFailure::UnsupportedSemanticValue(value.kind())),
        PortableValueKind::LocalDateTime => {
            let value = value
                .as_local_date_time()
                .expect("kind checked local datetime");
            canonical_local_datetime(value).ok_or(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::LocalDateTime,
            ))
        }
        PortableValueKind::OffsetDateTime => {
            let value = value
                .as_offset_date_time()
                .expect("kind checked offset datetime");
            canonical_offset_datetime(value).ok_or(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::OffsetDateTime,
            ))
        }
        _ => Err(EditFailure::UnsupportedSemanticValue(value.kind())),
    }
}

fn canonical_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len().saturating_add(2));
    output.push('"');
    for character in value.chars() {
        match character {
            '\u{08}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character if character <= '\u{1f}' || character == '\u{7f}' => {
                write!(output, "\\u{:04X}", u32::from(character))
                    .expect("write to String is infallible");
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn canonical_float(value: BinaryFloat64) -> Option<String> {
    let bits = value.bits();
    let float = f64::from_bits(bits);
    if float.is_nan() {
        return match bits {
            0x7ff8_0000_0000_0000 => Some("nan".to_owned()),
            0xfff8_0000_0000_0000 => Some("-nan".to_owned()),
            _ => None,
        };
    }
    if float == f64::INFINITY {
        return Some("inf".to_owned());
    }
    if float == f64::NEG_INFINITY {
        return Some("-inf".to_owned());
    }
    let mut output = float.to_string();
    if !output.contains(['.', 'e', 'E']) {
        output.push_str(".0");
    }
    Some(output)
}

fn canonical_date(value: &Date) -> Option<String> {
    let year = value.year().to_i64()?;
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!("{year:04}-{:02}-{:02}", value.month(), value.day()))
}

fn canonical_time(value: &Time) -> Option<String> {
    let nanoseconds = exact_nanoseconds(value.fractional_second())?;
    let mut output = format!(
        "{:02}:{:02}:{:02}",
        value.hour(),
        value.minute(),
        value.second()
    );
    if nanoseconds != 0 {
        let mut fraction = format!("{nanoseconds:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        output.push('.');
        output.push_str(&fraction);
    }
    Some(output)
}

fn canonical_local_datetime(value: &LocalDateTime) -> Option<String> {
    Some(format!(
        "{}T{}",
        canonical_date(value.date())?,
        canonical_time(value.time())?
    ))
}

fn canonical_offset_datetime(value: &OffsetDateTime) -> Option<String> {
    let mut output = canonical_local_datetime(value.local())?;
    let seconds = value.offset_seconds();
    if seconds == 0 {
        output.push('Z');
        return Some(output);
    }
    if seconds % 60 != 0 {
        return None;
    }
    let minutes = seconds / 60;
    if minutes.unsigned_abs() >= 24 * 60 {
        return None;
    }
    let sign = if minutes < 0 { '-' } else { '+' };
    let magnitude = minutes.unsigned_abs();
    write!(output, "{sign}{:02}:{:02}", magnitude / 60, magnitude % 60)
        .expect("write to String is infallible");
    Some(output)
}

fn exact_nanoseconds(value: &Decimal) -> Option<u32> {
    if value.coefficient().to_i64()? == 0 {
        return Some(0);
    }
    let exponent = value.exponent().to_i64()?;
    if !(-9..0).contains(&exponent) {
        return None;
    }
    let mut nanoseconds = value.coefficient().to_i64()?;
    if nanoseconds < 0 {
        return None;
    }
    for _ in 0..(exponent + 9) {
        nanoseconds = nanoseconds.checked_mul(10)?;
    }
    u32::try_from(nanoseconds)
        .ok()
        .filter(|value| *value < 1_000_000_000)
}

fn find_item_by_span(document: &Document, start: usize, end: usize) -> Option<usize> {
    let mut matches = document
        .entities
        .iter()
        .enumerate()
        .filter(|(_, entity)| {
            matches!(entity.kind, EntityKind::Item(_))
                && entity.span.start_byte() == start
                && entity.span.end_byte() == end
        })
        .map(|(index, _)| index);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TomlProfile, parse};
    use consema_core::{BigInteger, Date, LocalDateTime, OffsetDateTime, PortableValue, Time};
    use consema_document::ParseLimits;

    fn document(source: &[u8]) -> Document {
        parse(source, TomlProfile::Toml10V1, ParseLimits::default()).expect("valid TOML")
    }

    fn root_item(document: &Document, name: &str) -> NodeRef {
        document
            .root()
            .table_entries()
            .expect("root")
            .into_iter()
            .find(|entry| entry.name() == name)
            .expect("entry")
            .item_node_ref()
    }

    fn root_entry<'a>(document: &'a Document, name: &str) -> crate::TomlEntry<'a> {
        document
            .root()
            .table_entries()
            .expect("root")
            .into_iter()
            .find(|entry| entry.name() == name)
            .expect("entry")
    }

    #[test]
    fn literal_and_semantic_edits_change_only_scalar_spans() {
        let document = document(b"hex = 0x2A # keep\nname = 'old'\nfloat = 1.0\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .literal_scalar(root_item(&document, "hex"), b"0x2B".as_slice())
            .semantic_scalar(
                root_item(&document, "name"),
                PortableValue::string("new\nvalue"),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                root_item(&document, "float"),
                PortableValue::binary_float64(BinaryFloat64::from_bits((-0.0_f64).to_bits())),
                RepresentationPolicy::PreserveCompatible,
            );
        let commit = document.commit(&builder.build()).expect("atomic commit");
        assert_eq!(
            commit.document.render(),
            b"hex = 0x2B # keep\nname = \"new\\nvalue\"\nfloat = -0.0\n"
        );
        assert_eq!(commit.change_set.source_edits().len(), 3);
        let patch_limits = source_patch_limits(document.parse_limits, 3);
        assert_eq!(
            commit
                .source_patch
                .apply(document.source(), patch_limits)
                .unwrap()
                .bytes(),
            commit.document.render()
        );
        assert_eq!(
            commit.untouched_proof.verify(
                document.source(),
                commit.document.source(),
                commit.source_patch.replacements(),
            ),
            Ok(())
        );
        assert_eq!(commit.change_set.node_mappings().len(), 3);
        assert!(
            commit
                .change_set
                .node_mappings()
                .iter()
                .all(|mapping| mapping.new.is_some())
        );
    }

    #[test]
    fn invalid_or_conflicting_transactions_leave_the_base_unchanged() {
        let document = document(b"value = 1\narray = [1, 2]\n");
        let mut incompatible = EditTransactionBuilder::new(&document);
        incompatible.semantic_scalar(
            root_item(&document, "value"),
            PortableValue::string("one"),
            RepresentationPolicy::PreserveCompatible,
        );
        assert_eq!(
            document.commit(&incompatible.build()).unwrap_err(),
            EditFailure::RepresentationIncompatible
        );

        let mut container = EditTransactionBuilder::new(&document);
        container.literal_scalar(root_item(&document, "array"), b"3".as_slice());
        assert_eq!(
            document.commit(&container.build()).unwrap_err(),
            EditFailure::WrongRole
        );

        let target = root_item(&document, "value");
        let mut duplicate = EditTransactionBuilder::new(&document);
        duplicate
            .literal_scalar(target, b"2".as_slice())
            .literal_scalar(target, b"3".as_slice());
        assert_eq!(
            document.commit(&duplicate.build()).unwrap_err(),
            EditFailure::DuplicateTarget
        );
        assert_eq!(document.render(), b"value = 1\narray = [1, 2]\n");
    }

    #[test]
    fn semantic_boundaries_are_rejected_instead_of_rounded() {
        let document = document(b"float = 1.0\ntime = 00:00:00\noffset = 1979-05-27T00:00:00Z\n");
        let mut nan_payload = EditTransactionBuilder::new(&document);
        nan_payload.semantic_scalar(
            root_item(&document, "float"),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0001)),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&nan_payload.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::BinaryFloat64
            ))
        ));

        let date = Date::new(BigInteger::from(1979_i64), 5, 27).expect("date");
        let time = Time::new(
            0,
            0,
            0,
            Decimal::new(BigInteger::from(1_i64), BigInteger::from(-10_i64)),
        )
        .expect("core time");
        let mut precision = EditTransactionBuilder::new(&document);
        precision.semantic_scalar(
            root_item(&document, "time"),
            PortableValue::time(time.clone()),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&precision.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::Time
            ))
        ));

        let offset = OffsetDateTime::new(LocalDateTime::new(date, time), 1).expect("core offset");
        let mut offset_edit = EditTransactionBuilder::new(&document);
        offset_edit.semantic_scalar(
            root_item(&document, "offset"),
            PortableValue::offset_date_time(offset),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&offset_edit.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::OffsetDateTime
            ))
        ));
    }

    #[test]
    fn exact_literal_rejects_trivia_containers_and_extra_assignments() {
        for literal in [
            b" 2".as_slice(),
            b"2 # comment".as_slice(),
            b"[1, 2]".as_slice(),
            b"2\nother = 3".as_slice(),
        ] {
            assert_eq!(
                validate_exact_scalar(literal),
                Err(EditFailure::InvalidLiteral)
            );
        }
        assert_eq!(validate_exact_scalar(b"0x2A"), Ok(TomlItemKind::Integer));
        assert_eq!(
            validate_exact_scalar(br#""multi\nline""#),
            Ok(TomlItemKind::String)
        );
    }

    #[test]
    fn root_and_standard_table_insertions_preserve_ownership() {
        let document = document(b"root = 1\n\n[service]\nport = 80\n");
        let service = root_entry(&document, "service").item();

        let mut root_insert = EditTransactionBuilder::new(&document);
        root_insert.insert_entry(
            document.root().node_ref(),
            "enabled",
            PortableValue::boolean(true),
            AssociationPlacement::End,
        );
        let root_commit = document.commit(&root_insert.build()).expect("root insert");
        assert_eq!(
            root_commit.document.render(),
            b"root = 1\n\n\"enabled\" = true\n[service]\nport = 80\n"
        );
        assert_eq!(
            root_commit
                .document
                .root()
                .table_entries()
                .expect("root")
                .into_iter()
                .find(|entry| entry.name() == "enabled")
                .expect("root-owned insertion")
                .item()
                .as_boolean(),
            Some(true)
        );

        let mut table_insert = EditTransactionBuilder::new(&document);
        table_insert.insert_entry(
            service.node_ref(),
            "host",
            PortableValue::string("localhost"),
            AssociationPlacement::End,
        );
        let table_commit = document
            .commit(&table_insert.build())
            .expect("standard table insert");
        assert_eq!(
            table_commit.document.render(),
            b"root = 1\n\n[service]\nport = 80\n\"host\" = \"localhost\""
        );
        let reparsed_service = root_entry(&table_commit.document, "service").item();
        assert!(
            reparsed_service
                .table_entries()
                .expect("service")
                .iter()
                .any(|entry| entry.name() == "host")
        );
    }

    #[test]
    fn inline_table_operations_preserve_exact_association_identity() {
        let document = document(b"point = { a = 1, b = 2 }\n");
        let point = root_entry(&document, "point").item();
        let entries = point.table_entries().expect("inline table");

        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_entry(
            point.node_ref(),
            "axis",
            PortableValue::sequence(vec![PortableValue::boolean(true)]),
            AssociationPlacement::Before(entries[1].node_ref()),
        );
        assert_eq!(
            document.commit(&insert.build()).unwrap().document.render(),
            b"point = { a = 1, \"axis\" = [true],b = 2 }\n"
        );

        let mut rename = EditTransactionBuilder::new(&document);
        rename.rename_entry(entries[1].node_ref(), "beta");
        assert_eq!(
            document.commit(&rename.build()).unwrap().document.render(),
            b"point = { a = 1, \"beta\" = 2 }\n"
        );

        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_entry(entries[0].node_ref());
        let removed = document.commit(&remove.build()).unwrap();
        assert_eq!(removed.document.render(), b"point = {  b = 2 }\n");
        let limits = source_patch_limits(document.parse_limits, 1);
        assert_eq!(
            removed
                .source_patch
                .apply(document.source(), limits)
                .unwrap()
                .bytes(),
            removed.document.render()
        );
        assert_eq!(
            removed.untouched_proof.verify(
                document.source(),
                removed.document.source(),
                removed.source_patch.replacements(),
            ),
            Ok(())
        );
    }

    #[test]
    fn array_insert_and_remove_cover_empty_and_commented_arrays() {
        let empty = document(b"items = [ ]\n");
        let array = root_entry(&empty, "items").item();
        let mut start = EditTransactionBuilder::new(&empty);
        start.insert_array_element(
            array.node_ref(),
            PortableValue::integer(BigInteger::from(1_i64)),
            AssociationPlacement::Start,
        );
        assert_eq!(
            empty.commit(&start.build()).unwrap().document.render(),
            b"items = [1 ]\n"
        );

        let document = document(b"items = [1, # keep\n 2, 3,]\n");
        let array = root_entry(&document, "items").item();
        let elements = array.array_elements().expect("array");
        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_array_element(
            array.node_ref(),
            PortableValue::string("end"),
            AssociationPlacement::After(elements[2].node_ref()),
        );
        assert_eq!(
            document.commit(&insert.build()).unwrap().document.render(),
            b"items = [1, # keep\n 2, 3,\"end\",]\n"
        );

        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_array_element(elements[1].node_ref());
        assert_eq!(
            document.commit(&remove.build()).unwrap().document.render(),
            b"items = [1, # keep\n  3,]\n"
        );
    }

    #[test]
    fn structural_dependencies_and_table_rules_fail_atomically() {
        let document = document(b"a = 1\nb = 2\n\n[service]\nport = 80\n");
        let entries = document.root().table_entries().expect("root");
        let a = entries.iter().find(|entry| entry.name() == "a").unwrap();
        let service = entries
            .iter()
            .find(|entry| entry.name() == "service")
            .unwrap();

        let mut duplicate_key = EditTransactionBuilder::new(&document);
        duplicate_key.insert_entry(
            document.root().node_ref(),
            "a",
            PortableValue::boolean(true),
            AssociationPlacement::Start,
        );
        assert_eq!(
            document.commit(&duplicate_key.build()).unwrap_err(),
            EditFailure::DuplicateKey
        );

        let b = entries.iter().find(|entry| entry.name() == "b").unwrap();
        let mut duplicate_rename = EditTransactionBuilder::new(&document);
        duplicate_rename.rename_entry(b.node_ref(), "a");
        assert_eq!(
            document.commit(&duplicate_rename.build()).unwrap_err(),
            EditFailure::DuplicateKey
        );

        let mut removed_anchor = EditTransactionBuilder::new(&document);
        removed_anchor.remove_entry(a.node_ref()).insert_entry(
            document.root().node_ref(),
            "x",
            PortableValue::boolean(true),
            AssociationPlacement::Before(a.node_ref()),
        );
        assert_eq!(
            document.commit(&removed_anchor.build()).unwrap_err(),
            EditFailure::PlacementAnchorRemoved
        );

        let mut duplicate_target = EditTransactionBuilder::new(&document);
        duplicate_target
            .rename_entry(a.node_ref(), "x")
            .remove_entry(a.node_ref());
        assert_eq!(
            document.commit(&duplicate_target.build()).unwrap_err(),
            EditFailure::DuplicateTarget
        );

        let mut remove_table = EditTransactionBuilder::new(&document);
        remove_table.remove_entry(service.node_ref());
        assert_eq!(
            document.commit(&remove_table.build()).unwrap_err(),
            EditFailure::UnsupportedOperation
        );

        let mut cross_container = EditTransactionBuilder::new(&document);
        cross_container.insert_entry(
            service.item().node_ref(),
            "x",
            PortableValue::boolean(true),
            AssociationPlacement::Before(a.node_ref()),
        );
        assert_eq!(
            document.commit(&cross_container.build()).unwrap_err(),
            EditFailure::TargetNotFound
        );

        let mut same_boundary = EditTransactionBuilder::new(&document);
        same_boundary
            .insert_entry(
                document.root().node_ref(),
                "x",
                PortableValue::boolean(true),
                AssociationPlacement::End,
            )
            .insert_entry(
                document.root().node_ref(),
                "y",
                PortableValue::boolean(false),
                AssociationPlacement::End,
            );
        assert_eq!(
            document.commit(&same_boundary.build()).unwrap_err(),
            EditFailure::OverlappingOwnership
        );

        let mut null_value = EditTransactionBuilder::new(&document);
        null_value.insert_entry(
            document.root().node_ref(),
            "null",
            PortableValue::null(),
            AssociationPlacement::Start,
        );
        assert_eq!(
            document.commit(&null_value.build()).unwrap_err(),
            EditFailure::UnrepresentableValue(PortableValueKind::Null)
        );
        assert_eq!(document.render(), b"a = 1\nb = 2\n\n[service]\nport = 80\n");
    }

    #[test]
    fn empty_standard_table_insertion_uses_its_header_newline_and_crlf() {
        let document = document(b"[empty]\r\n[next]\r\nx = 1\r\n");
        let empty = root_entry(&document, "empty").item();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_entry(
            empty.node_ref(),
            "enabled",
            PortableValue::boolean(true),
            AssociationPlacement::End,
        );
        let commit = document
            .commit(&builder.build())
            .expect("empty table insert");
        assert_eq!(
            commit.document.render(),
            b"[empty]\r\n\"enabled\" = true\r\n[next]\r\nx = 1\r\n"
        );
        let empty = root_entry(&commit.document, "empty").item();
        assert_eq!(
            empty.table_entries().expect("populated table")[0]
                .item()
                .as_boolean(),
            Some(true)
        );
    }
}
