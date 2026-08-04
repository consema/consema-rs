use crate::{
    Document, InternalValueKind, JsonProfile, JsonSyntaxKind, JsonValueKind, SemanticAvailability,
    parse,
};
use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, PortableValue, PortableValueKind,
};
use consema_document::{
    AssociationPlacement, ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId,
    FormatOperationId, MaterializationLimits, NodeMapping, NodeMappingStatus, NodeRef, NodeRole,
    SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits, UntouchedByteProof,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// Explicit semantic scalar representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must instead use `LiteralScalarReplacement`; semantic replacement rejects this.
    ExactLiteral,
    /// Preserve the target's compatible native scalar category or fail.
    PreserveCompatible,
    /// Use deterministic profile-canonical JSON literal syntax.
    CanonicalForProfile,
    /// Try category preservation, then explicitly report canonical fallback.
    PreserveElseCanonical,
}

/// One scalar operation bound to the transaction's base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarReplacement {
    /// Replace by public semantic value under an explicit representation policy.
    Semantic {
        /// Exact target NodeRef.
        target: NodeRef,
        /// New complete core scalar.
        value: PortableValue,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replace by exact candidate literal bytes after full profile validation.
    Literal {
        /// Exact target NodeRef.
        target: NodeRef,
        /// Exact candidate bytes.
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

/// One typed JSON edit operation bound to an immutable base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Existing scalar semantic or literal replacement.
    ReplaceScalar(ScalarReplacement),
    /// Inserts one complete member into an Object value.
    InsertMember {
        /// Exact Object value target.
        object: NodeRef,
        /// Decoded member name.
        name: String,
        /// Complete inserted value.
        value: PortableValue,
        /// Explicit association placement.
        placement: AssociationPlacement,
    },
    /// Removes one exact member identity.
    RemoveMember {
        /// Exact ObjectMember target.
        target: NodeRef,
    },
    /// Moves one exact member within its current Object.
    MoveMember {
        /// Exact ObjectMember target.
        target: NodeRef,
        /// Placement within the same Object after removing the target.
        placement: AssociationPlacement,
    },
    /// Replaces only one exact member's key literal.
    RenameMember {
        /// Exact ObjectMember target.
        target: NodeRef,
        /// New decoded name.
        name: String,
    },
    /// Inserts one complete element into an Array value.
    InsertArrayElement {
        /// Exact Array value target.
        array: NodeRef,
        /// Complete inserted value.
        value: PortableValue,
        /// Explicit association placement.
        placement: AssociationPlacement,
    },
    /// Removes one exact array element identity.
    RemoveArrayElement {
        /// Exact ArrayElement target.
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

    /// Adds semantic scalar replacement.
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

    /// Adds exact literal scalar replacement.
    pub fn literal_scalar(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceScalar(ScalarReplacement::Literal {
                target,
                literal: literal.into(),
            }));
        self
    }

    /// Adds one JSON Object member insertion.
    pub fn insert_member(
        &mut self,
        object: NodeRef,
        name: impl Into<String>,
        value: PortableValue,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertMember {
            object,
            name: name.into(),
            value,
            placement,
        });
        self
    }

    /// Adds one exact JSON Object member removal.
    pub fn remove_member(&mut self, target: NodeRef) -> &mut Self {
        self.operations.push(EditOperation::RemoveMember { target });
        self
    }

    /// Adds one exact same-Object member move.
    pub fn move_member(&mut self, target: NodeRef, placement: AssociationPlacement) -> &mut Self {
        self.operations
            .push(EditOperation::MoveMember { target, placement });
        self
    }

    /// Adds one exact JSON Object member rename.
    pub fn rename_member(&mut self, target: NodeRef, name: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::RenameMember {
            target,
            name: name.into(),
        });
        self
    }

    /// Adds one JSON Array element insertion.
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

    /// Adds one exact JSON Array element removal.
    pub fn remove_array_element(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveArrayElement { target });
        self
    }

    /// Completes the immutable request; target validation happens atomically at commit.
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
    /// Target role is not a scalar value or object key.
    WrongRole,
    /// Target is not a complete literal syntax node.
    IncompleteTarget,
    /// Target native semantics are unavailable.
    SemanticUnavailable,
    /// Public value cannot be represented as a JSON scalar.
    UnsupportedSemanticValue(PortableValueKind),
    /// Exact candidate is not one complete legal scalar literal for the profile.
    InvalidLiteral,
    /// PreserveCompatible could not retain the scalar category.
    RepresentationIncompatible,
    /// ExactLiteral was incorrectly requested without literal bytes.
    ExactLiteralRequiresLiteralOperation,
    /// Two source edits overlap or target the same scalar.
    ConflictingEdits,
    /// More than one operation names the same exact destructive target.
    DuplicateTarget,
    /// Prepared source ownership intervals overlap or reuse one insertion point.
    OverlappingOwnership,
    /// One transaction edits an association and one of its owned descendants.
    AncestorDescendantConflict,
    /// An insertion anchor is removed by the same transaction.
    PlacementAnchorRemoved,
    /// A move target or anchor is modified by another operation in the transaction.
    PlacementAnchorModified,
    /// A target or placement anchor is not present in its declared container.
    TargetNotFound,
    /// A structural value cannot be represented by the JSON target profile.
    UnrepresentableValue(PortableValueKind),
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement document could not be formed under the original limits.
    NewDocumentFormationFailed,
}

impl Document {
    /// Atomically commits scalar and structural operations. On failure `self` remains unchanged.
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
            if !pair[0].old_span.is_empty()
                && !pair[1].old_span.is_empty()
                && (pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
                    || pair[0].old_span == pair[1].old_span)
            {
                return Err(EditFailure::AncestorDescendantConflict);
            }
            if pair[0].old_span == pair[1].old_span
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
                        MappingPlan::ReplacedLiteral(role) => {
                            let new = find_value_by_literal_span(&new_document, new_start, new_end)
                                .map(|index| new_document.node_ref(index, role));
                            (
                                new,
                                NodeMappingStatus::Replaced,
                                new.is_none()
                                    .then(|| "reparsed-node-not-uniquely-located".to_owned()),
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

    /// Fully validates and plans an edit without returning a new Document.
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
}

impl Document {
    fn prepare_operation(
        &self,
        operation: &EditOperation,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        match operation {
            EditOperation::ReplaceScalar(operation) => {
                Ok(vec![self.prepare_scalar(operation, diagnostics)?])
            }
            EditOperation::InsertMember {
                object,
                name,
                value,
                placement,
            } => self.prepare_insert_member(*object, name, value, *placement),
            EditOperation::RemoveMember { target } => self.prepare_remove_member(*target),
            EditOperation::MoveMember { target, placement } => {
                self.prepare_move_member(*target, *placement)
            }
            EditOperation::RenameMember { target, name } => {
                Ok(vec![self.prepare_rename_member(*target, name)?])
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
        let index = self.resolve_target(target, &[NodeRole::Value, NodeRole::ObjectKey])?;
        let entity = self.value_entity(index);
        if !entity.complete || entity.literal_span.is_none() {
            return Err(EditFailure::IncompleteTarget);
        }
        if matches!(entity.kind, InternalValueKind::Unavailable(_)) {
            return Err(EditFailure::SemanticUnavailable);
        }
        if matches!(
            entity.kind,
            InternalValueKind::Array(_) | InternalValueKind::Object(_)
        ) {
            return Err(EditFailure::WrongRole);
        }
        let replacement = match operation {
            ScalarReplacement::Literal { literal, .. } => {
                let literal_kind = validate_literal(literal, self.profile, self.parse_limits)?;
                if target.role() == NodeRole::ObjectKey && literal_kind != JsonValueKind::String {
                    return Err(EditFailure::InvalidLiteral);
                }
                literal.to_vec()
            }
            ScalarReplacement::Semantic { value, policy, .. } => {
                if target.role() == NodeRole::ObjectKey && value.kind() != PortableValueKind::String
                {
                    return Err(EditFailure::UnsupportedSemanticValue(value.kind()));
                }
                let old_span = entity.literal_span.expect("checked literal span");
                let old_literal = &self.source.bytes()[old_span.start_byte()..old_span.end_byte()];
                semantic_literal(
                    value,
                    &entity.kind,
                    old_literal,
                    self.profile,
                    *policy,
                    old_span,
                    diagnostics,
                )?
            }
        };
        Ok(PreparedEdit {
            old_span: entity.literal_span.expect("checked literal span"),
            replacement,
            mapping: Some((target, MappingPlan::ReplacedLiteral(target.role()))),
        })
    }

    fn prepare_insert_member(
        &self,
        object: NodeRef,
        name: &str,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(object, &[NodeRole::Value])?;
        let entity = self.value_entity(index);
        if !entity.complete {
            return Err(EditFailure::IncompleteTarget);
        }
        let InternalValueKind::Object(members) = &entity.kind else {
            return Err(EditFailure::WrongRole);
        };
        let mut fragment = self.fragment(&PortableValue::string(name))?;
        fragment
            .try_reserve(1)
            .map_err(|_| EditFailure::ResourceLimit("insert-fragment"))?;
        fragment.push(b':');
        append_fragment(
            &mut fragment,
            &self.fragment(value)?,
            self.parse_limits.max_source_bytes,
        )?;
        Ok(vec![self.prepare_insertion(
            object,
            entity.span,
            members,
            InsertionSyntax {
                anchor_role: NodeRole::ObjectMember,
                open: JsonSyntaxKind::LeftBrace,
                close: JsonSyntaxKind::RightBrace,
            },
            placement,
            fragment,
        )?])
    }

    fn prepare_insert_array_element(
        &self,
        array: NodeRef,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(array, &[NodeRole::Value])?;
        let entity = self.value_entity(index);
        if !entity.complete {
            return Err(EditFailure::IncompleteTarget);
        }
        let InternalValueKind::Array(elements) = &entity.kind else {
            return Err(EditFailure::WrongRole);
        };
        Ok(vec![self.prepare_insertion(
            array,
            entity.span,
            elements,
            InsertionSyntax {
                anchor_role: NodeRole::ArrayElement,
                open: JsonSyntaxKind::LeftBracket,
                close: JsonSyntaxKind::RightBracket,
            },
            placement,
            self.fragment(value)?,
        )?])
    }

    fn prepare_insertion(
        &self,
        container: NodeRef,
        container_span: consema_document::Span,
        associations: &[usize],
        syntax: InsertionSyntax,
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
                    (self.span(associations[0]).start_byte(), false, true)
                }
                AssociationPlacement::End => (
                    self.span(*associations.last().expect("non-empty"))
                        .end_byte(),
                    true,
                    false,
                ),
                AssociationPlacement::Before(anchor) => {
                    let anchor = self.resolve_anchor(anchor, syntax.anchor_role, associations)?;
                    (self.span(anchor).start_byte(), false, true)
                }
                AssociationPlacement::After(anchor) => {
                    let anchor = self.resolve_anchor(anchor, syntax.anchor_role, associations)?;
                    (self.span(anchor).end_byte(), true, false)
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
                .map_err(|_| EditFailure::IncompleteTarget)?,
            replacement,
            mapping: Some((
                container,
                MappingPlan::Unmapped("container-reparsed-after-structural-insertion"),
            )),
        })
    }

    fn prepare_remove_member(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(target, &[NodeRole::ObjectMember])?;
        let (container, members, ordinal) = self
            .parent_object(index)
            .ok_or(EditFailure::TargetNotFound)?;
        self.prepare_removal(
            target,
            index,
            members,
            ordinal,
            self.span(container).end_byte(),
        )
    }

    fn prepare_move_member(
        &self,
        target: NodeRef,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(target, &[NodeRole::ObjectMember])?;
        let (container, members, ordinal) = self
            .parent_object(index)
            .ok_or(EditFailure::TargetNotFound)?;
        let mut remaining = Vec::new();
        remaining
            .try_reserve(members.len().saturating_sub(1))
            .map_err(|_| EditFailure::ResourceLimit("move-members"))?;
        remaining.extend(members.iter().copied().filter(|member| *member != index));
        let destination = match placement {
            AssociationPlacement::Start => 0,
            AssociationPlacement::End => remaining.len(),
            AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor) => {
                if anchor == target {
                    return Err(EditFailure::PlacementAnchorModified);
                }
                let anchor = self.resolve_anchor(anchor, NodeRole::ObjectMember, &remaining)?;
                let position = remaining
                    .iter()
                    .position(|candidate| *candidate == anchor)
                    .expect("resolved anchor is in remaining members");
                if matches!(placement, AssociationPlacement::After(_)) {
                    position.saturating_add(1)
                } else {
                    position
                }
            }
        };
        if destination == ordinal {
            return Ok(Vec::new());
        }

        let target_span = self.span(index);
        let source_fragment =
            &self.source.bytes()[target_span.start_byte()..target_span.end_byte()];
        let mut fragment = Vec::new();
        fragment
            .try_reserve_exact(source_fragment.len())
            .map_err(|_| EditFailure::ResourceLimit("move-fragment"))?;
        fragment.extend_from_slice(source_fragment);
        let container_ref = self.node_ref(container, NodeRole::Value);
        let mut edits = self.prepare_removal(
            target,
            index,
            members,
            ordinal,
            self.span(container).end_byte(),
        )?;
        for edit in &mut edits {
            if edit.mapping.is_some_and(|(old, _)| old == target) {
                edit.mapping = Some((target, MappingPlan::Unmapped("member-reparsed-after-move")));
            }
        }
        edits.push(self.prepare_insertion(
            container_ref,
            self.span(container),
            &remaining,
            InsertionSyntax {
                anchor_role: NodeRole::ObjectMember,
                open: JsonSyntaxKind::LeftBrace,
                close: JsonSyntaxKind::RightBrace,
            },
            placement,
            fragment,
        )?);
        Ok(edits)
    }

    fn prepare_remove_array_element(
        &self,
        target: NodeRef,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_target(target, &[NodeRole::ArrayElement])?;
        let (container, elements, ordinal) = self
            .parent_array(index)
            .ok_or(EditFailure::TargetNotFound)?;
        self.prepare_removal(
            target,
            index,
            elements,
            ordinal,
            self.span(container).end_byte(),
        )
    }

    fn prepare_removal(
        &self,
        target: NodeRef,
        index: usize,
        associations: &[usize],
        ordinal: usize,
        container_end: usize,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let target_span = self.span(index);
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
                        .map_err(|_| EditFailure::IncompleteTarget)?,
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

    fn prepare_rename_member(
        &self,
        target: NodeRef,
        name: &str,
    ) -> Result<PreparedEdit, EditFailure> {
        let index = self.resolve_target(target, &[NodeRole::ObjectMember])?;
        self.parent_object(index)
            .ok_or(EditFailure::TargetNotFound)?;
        let crate::Entity::Member(member) = self.entity(index) else {
            return Err(EditFailure::WrongRole);
        };
        let key = self.value_entity(member.key);
        let old_span = key.literal_span.ok_or(EditFailure::IncompleteTarget)?;
        Ok(PreparedEdit {
            old_span,
            replacement: self.fragment(&PortableValue::string(name))?,
            mapping: Some((
                target,
                MappingPlan::Unmapped("member-reparsed-after-key-rename"),
            )),
        })
    }

    fn resolve_target(&self, target: NodeRef, roles: &[NodeRole]) -> Result<usize, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if !roles.contains(&target.role()) {
            return Err(EditFailure::WrongRole);
        }
        self.validate_ref(target, roles)
            .map_err(|failure| match failure {
                crate::JsonAccessError::WrongSnapshot => EditFailure::WrongSnapshot,
                crate::JsonAccessError::WrongRole => EditFailure::WrongRole,
                crate::JsonAccessError::UnknownNode => EditFailure::TargetNotFound,
            })
    }

    fn resolve_anchor(
        &self,
        anchor: NodeRef,
        role: NodeRole,
        associations: &[usize],
    ) -> Result<usize, EditFailure> {
        let index = self.resolve_target(anchor, &[role])?;
        associations
            .contains(&index)
            .then_some(index)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn fragment(&self, value: &PortableValue) -> Result<Vec<u8>, EditFailure> {
        crate::materialization::canonical_fragment(
            value,
            self.profile,
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

    fn parent_object(&self, member: usize) -> Option<(usize, &[usize], usize)> {
        self.entities
            .iter()
            .enumerate()
            .find_map(|(index, entity)| match entity {
                crate::Entity::Value(crate::ValueEntity {
                    kind: InternalValueKind::Object(members),
                    ..
                }) => members
                    .iter()
                    .position(|candidate| *candidate == member)
                    .map(|ordinal| (index, members.as_slice(), ordinal)),
                _ => None,
            })
    }

    fn parent_array(&self, element: usize) -> Option<(usize, &[usize], usize)> {
        self.entities
            .iter()
            .enumerate()
            .find_map(|(index, entity)| match entity {
                crate::Entity::Value(crate::ValueEntity {
                    kind: InternalValueKind::Array(elements),
                    ..
                }) => elements
                    .iter()
                    .position(|candidate| *candidate == element)
                    .map(|ordinal| (index, elements.as_slice(), ordinal)),
                _ => None,
            })
    }

    fn removal_comma(
        &self,
        associations: &[usize],
        ordinal: usize,
        container_end: usize,
    ) -> Result<Option<consema_document::Span>, EditFailure> {
        let current = self.span(associations[ordinal]);
        let following_end = associations
            .get(ordinal + 1)
            .map_or(container_end, |index| self.span(*index).start_byte());
        if let Some(comma) = self.syntax_between(
            JsonSyntaxKind::Comma,
            current.end_byte(),
            following_end,
            false,
        ) {
            return Ok(Some(comma));
        }
        if ordinal == 0 {
            return Ok(None);
        }
        let previous = self.span(associations[ordinal - 1]);
        self.syntax_between(
            JsonSyntaxKind::Comma,
            previous.end_byte(),
            current.start_byte(),
            true,
        )
        .map(Some)
        .ok_or(EditFailure::IncompleteTarget)
    }

    fn delimiter(
        &self,
        kind: JsonSyntaxKind,
        container: consema_document::Span,
        last: bool,
    ) -> Result<consema_document::Span, EditFailure> {
        self.syntax_between(kind, container.start_byte(), container.end_byte(), last)
            .ok_or(EditFailure::IncompleteTarget)
    }

    fn syntax_between(
        &self,
        kind: JsonSyntaxKind,
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
    let mut moved = HashSet::new();
    let mut move_anchors = Vec::new();
    for operation in transaction.operations.iter() {
        let target = match operation {
            EditOperation::ReplaceScalar(operation) => Some(operation.target()),
            EditOperation::RemoveMember { target }
            | EditOperation::MoveMember { target, .. }
            | EditOperation::RenameMember { target, .. }
            | EditOperation::RemoveArrayElement { target } => Some(*target),
            EditOperation::InsertMember { .. } | EditOperation::InsertArrayElement { .. } => None,
        };
        if let Some(target) = target {
            if !destructive.insert(target) {
                return Err(EditFailure::DuplicateTarget);
            }
        }
        match operation {
            EditOperation::RemoveMember { target }
            | EditOperation::RemoveArrayElement { target } => {
                removed.insert(*target);
            }
            EditOperation::InsertMember { placement, .. }
            | EditOperation::InsertArrayElement { placement, .. }
            | EditOperation::MoveMember { placement, .. } => match placement {
                AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor) => {
                    anchors.push(*anchor);
                    if matches!(operation, EditOperation::MoveMember { .. }) {
                        move_anchors.push(*anchor);
                    }
                }
                AssociationPlacement::Start | AssociationPlacement::End => {}
            },
            EditOperation::ReplaceScalar(_) | EditOperation::RenameMember { .. } => {}
        }
        if let EditOperation::MoveMember { target, .. } = operation {
            moved.insert(*target);
        }
    }
    if anchors.iter().any(|anchor| removed.contains(anchor)) {
        return Err(EditFailure::PlacementAnchorRemoved);
    }
    if anchors.iter().any(|anchor| moved.contains(anchor))
        || move_anchors
            .iter()
            .any(|anchor| destructive.contains(anchor))
    {
        return Err(EditFailure::PlacementAnchorModified);
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
                    "json.edit.replace-scalar-semantic@1"
                }
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { .. }) => {
                    "json.edit.replace-scalar-literal@1"
                }
                EditOperation::InsertMember { .. } => "json.edit.insert-member@1",
                EditOperation::RemoveMember { .. } => "json.edit.remove-member@1",
                EditOperation::MoveMember { .. } => "json.edit.move-member@1",
                EditOperation::RenameMember { .. } => "json.edit.rename-member@1",
                EditOperation::InsertArrayElement { .. } => "json.edit.insert-array-element@1",
                EditOperation::RemoveArrayElement { .. } => "json.edit.remove-array-element@1",
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
            let (id, target_role, mut arguments) = match operation {
                EditOperation::ReplaceScalar(ScalarReplacement::Semantic {
                    value, policy, ..
                }) => (
                    "json.edit.replace-scalar-semantic",
                    "json.scalar@1",
                    BTreeMap::from([
                        (
                            "representation_policy".to_owned(),
                            json_policy_name(*policy).to_owned(),
                        ),
                        (
                            "value_kind".to_owned(),
                            value_kind_name(value.kind()).to_owned(),
                        ),
                    ]),
                ),
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { literal, .. }) => (
                    "json.edit.replace-scalar-literal",
                    "json.scalar@1",
                    BTreeMap::from([("literal_bytes".to_owned(), literal.len().to_string())]),
                ),
                EditOperation::InsertMember {
                    name,
                    value,
                    placement,
                    ..
                } => (
                    "json.edit.insert-member",
                    "json.object@1",
                    BTreeMap::from([
                        ("name_bytes".to_owned(), name.len().to_string()),
                        (
                            "placement".to_owned(),
                            placement_name(*placement).to_owned(),
                        ),
                        (
                            "value_kind".to_owned(),
                            value_kind_name(value.kind()).to_owned(),
                        ),
                    ]),
                ),
                EditOperation::RemoveMember { .. } => (
                    "json.edit.remove-member",
                    "json.object-member@1",
                    BTreeMap::new(),
                ),
                EditOperation::MoveMember { placement, .. } => (
                    "json.edit.move-member",
                    "json.object-member@1",
                    BTreeMap::from([(
                        "placement".to_owned(),
                        placement_name(*placement).to_owned(),
                    )]),
                ),
                EditOperation::RenameMember { name, .. } => (
                    "json.edit.rename-member",
                    "json.object-member@1",
                    BTreeMap::from([("name_bytes".to_owned(), name.len().to_string())]),
                ),
                EditOperation::InsertArrayElement {
                    value, placement, ..
                } => (
                    "json.edit.insert-array-element",
                    "json.array@1",
                    BTreeMap::from([
                        (
                            "placement".to_owned(),
                            placement_name(*placement).to_owned(),
                        ),
                        (
                            "value_kind".to_owned(),
                            value_kind_name(value.kind()).to_owned(),
                        ),
                    ]),
                ),
                EditOperation::RemoveArrayElement { .. } => (
                    "json.edit.remove-array-element",
                    "json.array-element@1",
                    BTreeMap::new(),
                ),
            };
            arguments.insert("target_role".to_owned(), target_role.to_owned());
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

const fn placement_name(placement: AssociationPlacement) -> &'static str {
    match placement {
        AssociationPlacement::Start => "start",
        AssociationPlacement::End => "end",
        AssociationPlacement::Before(_) => "before",
        AssociationPlacement::After(_) => "after",
    }
}

const fn json_policy_name(policy: RepresentationPolicy) -> &'static str {
    match policy {
        RepresentationPolicy::ExactLiteral => "exact-literal",
        RepresentationPolicy::PreserveCompatible => "preserve-compatible",
        RepresentationPolicy::CanonicalForProfile => "canonical-for-profile",
        RepresentationPolicy::PreserveElseCanonical => "preserve-else-canonical",
    }
}

const fn value_kind_name(kind: PortableValueKind) -> &'static str {
    match kind {
        PortableValueKind::Null => "null",
        PortableValueKind::Boolean => "boolean",
        PortableValueKind::Integer => "integer",
        PortableValueKind::Decimal => "decimal",
        PortableValueKind::BinaryFloat32 => "binary-float32",
        PortableValueKind::BinaryFloat64 => "binary-float64",
        PortableValueKind::String => "string",
        PortableValueKind::Bytes => "bytes",
        PortableValueKind::Date => "date",
        PortableValueKind::Time => "time",
        PortableValueKind::LocalDateTime => "local-date-time",
        PortableValueKind::OffsetDateTime => "offset-date-time",
        PortableValueKind::Sequence => "sequence",
        PortableValueKind::Object => "object",
        PortableValueKind::EntryMapping => "entry-mapping",
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
            | Self::IncompleteTarget
            | Self::SemanticUnavailable
            | Self::InvalidLiteral
            | Self::ExactLiteralRequiresLiteralOperation
            | Self::ConflictingEdits
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorRemoved
            | Self::PlacementAnchorModified => consema_core::FailureKind::InvalidInput,
            Self::TargetNotFound | Self::RepresentationIncompatible => {
                consema_core::FailureKind::NotApplicable
            }
            Self::UnsupportedSemanticValue(_) | Self::UnrepresentableValue(_) => {
                consema_core::FailureKind::Unsupported
            }
            Self::ResourceLimit(_) => consema_core::FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::IncompleteTarget => "core.edit.incomplete-target@1",
            Self::SemanticUnavailable => "core.edit.semantic-unavailable@1",
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
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorRemoved
            | Self::PlacementAnchorModified => "core.edit.conflicting-edits@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
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
struct InsertionSyntax {
    anchor_role: NodeRole,
    open: JsonSyntaxKind,
    close: JsonSyntaxKind,
}

#[derive(Clone, Copy)]
enum MappingPlan {
    ReplacedLiteral(NodeRole),
    Deleted,
    Unmapped(&'static str),
}

fn semantic_literal(
    value: &PortableValue,
    old: &InternalValueKind,
    old_literal: &[u8],
    profile: JsonProfile,
    policy: RepresentationPolicy,
    target_span: consema_document::Span,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<u8>, EditFailure> {
    if policy == RepresentationPolicy::ExactLiteral {
        return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
    }
    portable_json_kind(value, profile)
        .ok_or_else(|| EditFailure::UnsupportedSemanticValue(value.kind()))?;
    let preserved = analyze_lexical_style(old_literal, old)
        .and_then(|style| render_preserving_style(value, &style));
    match policy {
        RepresentationPolicy::PreserveCompatible => {
            preserved.ok_or(EditFailure::RepresentationIncompatible)
        }
        RepresentationPolicy::CanonicalForProfile => canonical_literal(value, profile),
        RepresentationPolicy::PreserveElseCanonical => {
            if let Some(bytes) = preserved {
                Ok(bytes)
            } else {
                let diagnostic = Diagnostic::new(
                    "json.edit.representation-fallback@1",
                    DiagnosticCategory::Edit,
                    DiagnosticSeverity::Warning,
                    Some(target_span.diagnostic_location()),
                    diagnostics.len() as u64,
                );
                diagnostics.push(diagnostic);
                canonical_literal(value, profile)
            }
        }
        RepresentationPolicy::ExactLiteral => {
            unreachable!("ExactLiteral is rejected before matching")
        }
    }
}

/// Maximum digits a preserved fixed-fraction rendering may produce.
const MAX_PRESERVED_FRACTION_DIGITS: usize = 1_000_000;

/// Bounded lexical style retained by `PreserveCompatible` edits.
///
/// v1 preserves: integer digit form; decimal fraction digit count and
/// exponent marker case / explicit plus sign; per-character string escape
/// choices. A decimal literal that mixes a fraction and an exponent keeps
/// the fraction scale and absorbs the exponent into the fixed form.
#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonScalarLexicalStyle {
    Null,
    Boolean,
    Integer(IntegerLexicalStyle),
    Decimal(DecimalLexicalStyle),
    NonFinite(NonFiniteLexicalStyle),
    String(StringLexicalStyle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegerRadix {
    Decimal,
    Hex {
        uppercase_prefix: bool,
        uppercase_digits: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IntegerLexicalStyle {
    radix: IntegerRadix,
    explicit_plus: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecimalLexicalStyle {
    fraction_scale: Option<usize>,
    exponent_marker: Option<u8>,
    exponent_plus: bool,
    leading_plus: bool,
    leading_point: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NonFiniteLexicalStyle {
    explicit_plus: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StringLexicalStyle {
    quote: char,
    escapes: HashMap<char, String>,
}

fn analyze_lexical_style(
    literal: &[u8],
    old: &InternalValueKind,
) -> Option<JsonScalarLexicalStyle> {
    match old {
        InternalValueKind::Null => Some(JsonScalarLexicalStyle::Null),
        InternalValueKind::Boolean(_) => Some(JsonScalarLexicalStyle::Boolean),
        InternalValueKind::Integer(_) => {
            let text = std::str::from_utf8(literal).ok()?;
            let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
            let radix = if let Some(hex) = unsigned
                .strip_prefix("0x")
                .or_else(|| unsigned.strip_prefix("0X"))
            {
                IntegerRadix::Hex {
                    uppercase_prefix: unsigned.starts_with("0X"),
                    uppercase_digits: hex.bytes().any(|byte| byte.is_ascii_uppercase()),
                }
            } else {
                IntegerRadix::Decimal
            };
            Some(JsonScalarLexicalStyle::Integer(IntegerLexicalStyle {
                radix,
                explicit_plus: text.starts_with('+'),
            }))
        }
        InternalValueKind::Decimal(_) => {
            let text = std::str::from_utf8(literal).ok()?;
            let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
            let exponent_index = unsigned.find(['e', 'E']);
            let mantissa = &unsigned[..exponent_index.unwrap_or(unsigned.len())];
            let fraction_scale = mantissa
                .find('.')
                .map(|index| mantissa.len().saturating_sub(index + 1));
            let (exponent_marker, exponent_plus) = match exponent_index {
                Some(index) => {
                    let plus = unsigned.as_bytes().get(index + 1) == Some(&b'+');
                    (Some(unsigned.as_bytes()[index]), plus)
                }
                None => (None, false),
            };
            Some(JsonScalarLexicalStyle::Decimal(DecimalLexicalStyle {
                fraction_scale,
                exponent_marker,
                exponent_plus,
                leading_plus: text.starts_with('+'),
                leading_point: mantissa.starts_with('.'),
            }))
        }
        InternalValueKind::BinaryFloat64(_) => {
            let text = std::str::from_utf8(literal).ok()?;
            Some(JsonScalarLexicalStyle::NonFinite(NonFiniteLexicalStyle {
                explicit_plus: text.starts_with('+'),
            }))
        }
        InternalValueKind::String(_) => {
            analyze_string_style(literal).map(JsonScalarLexicalStyle::String)
        }
        InternalValueKind::Array(_)
        | InternalValueKind::Object(_)
        | InternalValueKind::Unavailable(_) => None,
    }
}

fn analyze_string_style(literal: &[u8]) -> Option<StringLexicalStyle> {
    let text = std::str::from_utf8(literal).ok()?;
    let quote = text.chars().next()?;
    if !matches!(quote, '\'' | '"') || !text.ends_with(quote) {
        return None;
    }
    let mut style = StringLexicalStyle {
        quote,
        escapes: HashMap::new(),
    };
    let end = text.len().checked_sub(quote.len_utf8())?;
    let mut offset = quote.len_utf8();
    while offset < end {
        let character = text[offset..].chars().next()?;
        if character != '\\' {
            offset += character.len_utf8();
            continue;
        }
        let escape_start = offset;
        offset += 1;
        let escaped = text[offset..].chars().next()?;
        offset += escaped.len_utf8();
        let decoded = match escaped {
            '"' => Some('"'),
            '\'' => Some('\''),
            '\\' => Some('\\'),
            '/' => Some('/'),
            'b' => Some('\u{0008}'),
            'f' => Some('\u{000c}'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'v' => Some('\u{000b}'),
            '0' => Some('\0'),
            'x' => {
                let value = u8::from_str_radix(text.get(offset..offset + 2)?, 16).ok()?;
                offset += 2;
                Some(char::from(value))
            }
            'u' => {
                let first = u16::from_str_radix(text.get(offset..offset + 4)?, 16).ok()?;
                offset += 4;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if text.get(offset..offset + 2)? != "\\u" {
                        return None;
                    }
                    let second = u16::from_str_radix(text.get(offset + 2..offset + 6)?, 16).ok()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return None;
                    }
                    offset += 6;
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else {
                    u32::from(first)
                };
                Some(char::from_u32(scalar)?)
            }
            '\r' => {
                if text[offset..].starts_with('\n') {
                    offset += 1;
                }
                None
            }
            '\n' | '\u{2028}' | '\u{2029}' => None,
            other => Some(other),
        };
        if let Some(decoded) = decoded {
            style
                .escapes
                .insert(decoded, text[escape_start..offset].to_owned());
        }
    }
    Some(style)
}

fn render_preserving_style(
    value: &PortableValue,
    style: &JsonScalarLexicalStyle,
) -> Option<Vec<u8>> {
    match style {
        JsonScalarLexicalStyle::Null if value.kind() == PortableValueKind::Null => {
            Some(b"null".to_vec())
        }
        JsonScalarLexicalStyle::Boolean if value.kind() == PortableValueKind::Boolean => {
            Some(value.as_boolean()?.to_string().into_bytes())
        }
        JsonScalarLexicalStyle::Integer(style) if value.kind() == PortableValueKind::Integer => {
            render_integer_style(value.as_integer()?, *style)
        }
        JsonScalarLexicalStyle::Decimal(style)
            if matches!(
                value.kind(),
                PortableValueKind::Decimal | PortableValueKind::Integer
            ) =>
        {
            render_decimal_style(value, style)
        }
        JsonScalarLexicalStyle::NonFinite(style)
            if value.kind() == PortableValueKind::BinaryFloat64 =>
        {
            render_non_finite_style(value.as_binary_float64()?, *style)
        }
        JsonScalarLexicalStyle::String(style) if value.kind() == PortableValueKind::String => {
            Some(render_string_style(value.as_string()?, style).into_bytes())
        }
        _ => None,
    }
}

fn render_integer_style(
    value: &consema_core::BigInteger,
    style: IntegerLexicalStyle,
) -> Option<Vec<u8>> {
    let mut output = String::new();
    if value.signum() < 0 {
        output.push('-');
    } else if style.explicit_plus {
        output.push('+');
    }
    match style.radix {
        IntegerRadix::Decimal => output.push_str(value.to_string().trim_start_matches('-')),
        IntegerRadix::Hex {
            uppercase_prefix,
            uppercase_digits,
        } => {
            output.push_str(if uppercase_prefix { "0X" } else { "0x" });
            if value.magnitude().is_empty() {
                output.push('0');
            } else {
                use std::fmt::Write as _;
                for (index, octet) in value.magnitude().iter().enumerate() {
                    if uppercase_digits && index == 0 {
                        write!(output, "{octet:X}").ok()?;
                    } else if uppercase_digits {
                        write!(output, "{octet:02X}").ok()?;
                    } else if index == 0 {
                        write!(output, "{octet:x}").ok()?;
                    } else {
                        write!(output, "{octet:02x}").ok()?;
                    }
                }
            }
        }
    }
    Some(output.into_bytes())
}

fn render_decimal_style(value: &PortableValue, style: &DecimalLexicalStyle) -> Option<Vec<u8>> {
    let coefficient = match value.kind() {
        PortableValueKind::Decimal => value.as_decimal()?.coefficient(),
        PortableValueKind::Integer => value.as_integer()?,
        _ => return None,
    };
    let exponent = match value.kind() {
        PortableValueKind::Decimal => value.as_decimal()?.exponent(),
        PortableValueKind::Integer => &consema_core::BigInteger::zero(),
        _ => return None,
    };
    let mut output = if let Some(marker) = style.exponent_marker {
        let scale = style.fraction_scale.unwrap_or(0);
        let mut mantissa = if style.fraction_scale.is_some() {
            decimal_fixed_text(coefficient, scale)
        } else {
            coefficient.to_string()
        };
        if style.leading_point {
            remove_leading_zero(&mut mantissa)?;
        }
        let exponent = exponent.to_i64()?.checked_add(i64::try_from(scale).ok()?)?;
        mantissa.push(marker as char);
        if exponent >= 0 && style.exponent_plus {
            mantissa.push('+');
        }
        mantissa.push_str(&exponent.to_string());
        mantissa
    } else {
        let scale = style.fraction_scale?;
        let shift = match exponent.to_i64() {
            Some(shift) if shift >= 0 => usize::try_from(shift).ok()?.checked_add(scale)?,
            Some(negative) => scale.checked_sub(usize::try_from(negative.unsigned_abs()).ok()?)?,
            None => return None,
        };
        if shift > MAX_PRESERVED_FRACTION_DIGITS {
            return None;
        }
        let mantissa = coefficient.mul_pow10(shift);
        let mut output = decimal_fixed_text(&mantissa, scale);
        if style.leading_point {
            remove_leading_zero(&mut output)?;
        }
        output
    };
    if style.leading_plus && !output.starts_with('-') {
        output.insert(0, '+');
    }
    Some(output.into_bytes())
}

fn remove_leading_zero(text: &mut String) -> Option<()> {
    let zero = usize::from(text.starts_with("-0."));
    (text.as_bytes().get(zero..zero + 2) == Some(b"0.")).then_some(())?;
    text.remove(zero);
    Some(())
}

fn render_non_finite_style(
    value: consema_core::BinaryFloat64,
    style: NonFiniteLexicalStyle,
) -> Option<Vec<u8>> {
    let text = match value.bits() {
        0x7ff0_0000_0000_0000 if style.explicit_plus => "+Infinity",
        0x7ff0_0000_0000_0000 => "Infinity",
        0xfff0_0000_0000_0000 => "-Infinity",
        0x7ff8_0000_0000_0000 if style.explicit_plus => "+NaN",
        0x7ff8_0000_0000_0000 => "NaN",
        0xfff8_0000_0000_0000 => "-NaN",
        _ => return None,
    };
    Some(text.as_bytes().to_vec())
}

fn decimal_fixed_text(mantissa: &consema_core::BigInteger, scale: usize) -> String {
    let text = mantissa.to_string();
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text.as_str()),
    };
    if digits.len() <= scale {
        format!("{sign}0.{}{}", "0".repeat(scale - digits.len()), digits)
    } else {
        let split = digits.len() - scale;
        format!("{sign}{}.{}", &digits[..split], &digits[split..])
    }
}

fn render_string_style(value: &str, style: &StringLexicalStyle) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push(style.quote);
    for character in value.chars() {
        if let Some(escape) = style.escapes.get(&character) {
            output.push_str(escape);
        } else {
            push_json_string_char(&mut output, character, style.quote, false);
        }
    }
    output.push(style.quote);
    output
}

fn portable_json_kind(value: &PortableValue, profile: JsonProfile) -> Option<JsonValueKind> {
    match value.kind() {
        PortableValueKind::Null => Some(JsonValueKind::Null),
        PortableValueKind::Boolean => Some(JsonValueKind::Boolean),
        PortableValueKind::Integer => Some(JsonValueKind::Integer),
        PortableValueKind::Decimal => Some(JsonValueKind::Decimal),
        PortableValueKind::BinaryFloat64 if profile.is_json5() => {
            Some(JsonValueKind::BinaryFloat64)
        }
        PortableValueKind::String => Some(JsonValueKind::String),
        _ => None,
    }
}

fn canonical_literal(value: &PortableValue, profile: JsonProfile) -> Result<Vec<u8>, EditFailure> {
    let text = match value.kind() {
        PortableValueKind::Null => "null".to_owned(),
        PortableValueKind::Boolean => value.as_boolean().expect("boolean kind").to_string(),
        PortableValueKind::Integer => value.as_integer().expect("integer kind").to_string(),
        PortableValueKind::Decimal => {
            let value = value.as_decimal().expect("decimal kind");
            format!("{}e{}", value.coefficient(), value.exponent())
        }
        PortableValueKind::BinaryFloat64 if profile.is_json5() => {
            return render_non_finite_style(
                value.as_binary_float64().expect("binary64 kind"),
                NonFiniteLexicalStyle {
                    explicit_plus: false,
                },
            )
            .ok_or(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::BinaryFloat64,
            ));
        }
        PortableValueKind::String => {
            encode_json_string(value.as_string().expect("string kind"), profile.is_json5())
        }
        kind => return Err(EditFailure::UnsupportedSemanticValue(kind)),
    };
    Ok(text.into_bytes())
}

fn encode_json_string(value: &str, json5: bool) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        push_json_string_char(&mut output, character, '"', json5);
    }
    output.push('"');
    output
}

fn push_json_string_char(output: &mut String, character: char, quote: char, canonical_json5: bool) {
    match character {
        character if character == quote => {
            output.push('\\');
            output.push(character);
        }
        '\\' => output.push_str("\\\\"),
        '\u{0008}' => output.push_str("\\b"),
        '\u{000c}' => output.push_str("\\f"),
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        '\u{0000}'..='\u{001f}' => {
            use std::fmt::Write;
            write!(output, "\\u{:04X}", u32::from(character)).expect("String write");
        }
        '\u{2028}' | '\u{2029}' if canonical_json5 => {
            use std::fmt::Write;
            write!(output, "\\u{:04X}", u32::from(character)).expect("String write");
        }
        _ => output.push(character),
    }
}

fn validate_literal(
    literal: &[u8],
    profile: JsonProfile,
    limits: consema_document::ParseLimits,
) -> Result<JsonValueKind, EditFailure> {
    if literal.is_empty() || std::str::from_utf8(literal).is_err() {
        return Err(EditFailure::InvalidLiteral);
    }
    let document = parse(literal, profile, limits).map_err(|_| EditFailure::InvalidLiteral)?;
    let kind = document.root().kind();
    if document.formation_status() != consema_document::FormationStatus::Complete
        || document.root().span().start_byte() != 0
        || document.root().span().end_byte() != literal.len()
        || !matches!(
            kind,
            SemanticAvailability::Available(
                JsonValueKind::Null
                    | JsonValueKind::Boolean
                    | JsonValueKind::Integer
                    | JsonValueKind::Decimal
                    | JsonValueKind::BinaryFloat64
                    | JsonValueKind::String
            )
        )
    {
        return Err(EditFailure::InvalidLiteral);
    }
    match kind {
        SemanticAvailability::Available(kind) => Ok(kind),
        SemanticAvailability::Unavailable(_) => Err(EditFailure::InvalidLiteral),
    }
}

fn find_value_by_literal_span(document: &Document, start: usize, end: usize) -> Option<usize> {
    let mut matches =
        document
            .entities
            .iter()
            .enumerate()
            .filter_map(|(index, entity)| match entity {
                crate::Entity::Value(value)
                    if value.literal_span.is_some_and(|span| {
                        span.start_byte() == start && span.end_byte() == end
                    }) =>
                {
                    Some(index)
                }
                _ => None,
            });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsonProfile, parse};
    use consema_core::{BigInteger, BinaryFloat64, Decimal, PortableValue};
    use consema_document::ParseLimits;

    fn object_members(document: &Document) -> Vec<crate::JsonObjectMember<'_>> {
        match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members,
            other => panic!("expected object: {other:?}"),
        }
    }

    fn array_elements(document: &Document) -> Vec<crate::JsonArrayElement<'_>> {
        match document.root().array_elements() {
            SemanticAvailability::Available(Some(elements)) => elements,
            other => panic!("expected array: {other:?}"),
        }
    }

    #[test]
    fn semantic_edit_changes_only_literal_and_keeps_trivia() {
        let document = parse(
            b"{ /* lead */ \"a\" : 1 // tail\n}".as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let member = match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0],
            _ => panic!("missing member"),
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member.value_node_ref(),
            PortableValue::integer(BigInteger::from(200_i64)),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"{ /* lead */ \"a\" : 200 // tail\n}"
        );
        assert_eq!(commit.change_set.source_edits().len(), 1);
        let patch_limits = source_patch_limits(document.parse_limits, 1);
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
        assert_ne!(
            document.snapshot_identity(),
            commit.document.snapshot_identity()
        );
    }

    #[test]
    fn object_structural_edits_preserve_duplicate_identity_comments_and_trailing_comma() {
        let document = parse(
            br#"{ /*lead*/ "a":1, /*keep*/ "a":2, "z":3, }"#.as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let members = object_members(&document);

        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_member(
            document.root().node_ref(),
            "x",
            PortableValue::sequence(vec![PortableValue::boolean(true)]),
            AssociationPlacement::Before(members[1].node_ref()),
        );
        let inserted = document.commit(&insert.build()).unwrap();
        assert_eq!(
            inserted.document.render(),
            br#"{ /*lead*/ "a":1, /*keep*/ "x":[true],"a":2, "z":3, }"#
        );

        let mut rename = EditTransactionBuilder::new(&document);
        rename.rename_member(members[1].node_ref(), "b");
        let renamed = document.commit(&rename.build()).unwrap();
        assert_eq!(
            renamed.document.render(),
            br#"{ /*lead*/ "a":1, /*keep*/ "b":2, "z":3, }"#
        );

        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_member(members[0].node_ref());
        let removed = document.commit(&remove.build()).unwrap();
        assert_eq!(
            removed.document.render(),
            br#"{ /*lead*/  /*keep*/ "a":2, "z":3, }"#
        );
        let limits = source_patch_limits(document.parse_limits, 2);
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
    fn array_insert_and_remove_cover_empty_singleton_and_end_placements() {
        let empty = parse(
            b"[ /*inside*/ ]".as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut at_start = EditTransactionBuilder::new(&empty);
        at_start.insert_array_element(
            empty.root().node_ref(),
            PortableValue::integer(BigInteger::from(1_i64)),
            AssociationPlacement::Start,
        );
        assert_eq!(
            empty.commit(&at_start.build()).unwrap().document.render(),
            b"[1 /*inside*/ ]"
        );
        let mut at_end = EditTransactionBuilder::new(&empty);
        at_end.insert_array_element(
            empty.root().node_ref(),
            PortableValue::integer(BigInteger::from(1_i64)),
            AssociationPlacement::End,
        );
        assert_eq!(
            empty.commit(&at_end.build()).unwrap().document.render(),
            b"[ /*inside*/ 1]"
        );

        let document = parse(
            b"[1, /*keep*/ 2, 3,]".as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let elements = array_elements(&document);
        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_array_element(
            document.root().node_ref(),
            PortableValue::string("end"),
            AssociationPlacement::After(elements[2].node_ref()),
        );
        assert_eq!(
            document.commit(&insert.build()).unwrap().document.render(),
            b"[1, /*keep*/ 2, 3,\"end\",]"
        );
        let mut remove = EditTransactionBuilder::new(&document);
        remove.remove_array_element(elements[1].node_ref());
        assert_eq!(
            document.commit(&remove.build()).unwrap().document.render(),
            b"[1, /*keep*/  3,]"
        );
    }

    #[test]
    fn structural_conflicts_fail_before_a_document_exists() {
        let document = parse(
            b"{\"a\":1,\"b\":2}".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let members = object_members(&document);

        let mut removed_anchor = EditTransactionBuilder::new(&document);
        removed_anchor
            .remove_member(members[0].node_ref())
            .insert_member(
                document.root().node_ref(),
                "x",
                PortableValue::boolean(true),
                AssociationPlacement::Before(members[0].node_ref()),
            );
        assert_eq!(
            document.commit(&removed_anchor.build()).unwrap_err(),
            EditFailure::PlacementAnchorRemoved
        );

        let mut duplicate = EditTransactionBuilder::new(&document);
        duplicate
            .rename_member(members[0].node_ref(), "x")
            .remove_member(members[0].node_ref());
        assert_eq!(
            document.commit(&duplicate.build()).unwrap_err(),
            EditFailure::DuplicateTarget
        );

        let mut same_boundary = EditTransactionBuilder::new(&document);
        same_boundary
            .insert_member(
                document.root().node_ref(),
                "x",
                PortableValue::boolean(true),
                AssociationPlacement::End,
            )
            .insert_member(
                document.root().node_ref(),
                "y",
                PortableValue::boolean(false),
                AssociationPlacement::End,
            );
        assert_eq!(
            document.commit(&same_boundary.build()).unwrap_err(),
            EditFailure::OverlappingOwnership
        );

        let mut ancestor_descendant = EditTransactionBuilder::new(&document);
        ancestor_descendant
            .semantic_scalar(
                members[0].value_node_ref(),
                PortableValue::integer(BigInteger::from(3_i64)),
                RepresentationPolicy::PreserveCompatible,
            )
            .remove_member(members[0].node_ref());
        assert_eq!(
            document.commit(&ancestor_descendant.build()).unwrap_err(),
            EditFailure::AncestorDescendantConflict
        );
        assert_eq!(document.render(), b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn move_member_keeps_trivia_in_place_and_publishes_exact_artifacts() {
        let document = parse(
            b"{ /*before-a*/ a:1, /*between*/ b:2, c:3, }".as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        )
        .unwrap();
        let members = object_members(&document);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.move_member(members[1].node_ref(), AssociationPlacement::Start);
        let transaction = builder.build();
        let plan = document
            .dry_run(&transaction, EditPlanSourceId::new("config.json5").unwrap())
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(
            commit.document.render(),
            b"{ /*before-a*/ b:2,a:1, /*between*/  c:3, }"
        );
        assert_eq!(plan.replacements(), commit.source_patch.replacements());
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(
            commit
                .source_patch
                .apply(
                    document.source(),
                    source_patch_limits(
                        document.parse_limits,
                        commit.source_patch.replacements().len(),
                    ),
                )
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
        assert!(commit.change_set.node_mappings().iter().any(|mapping| {
            mapping.old == members[1].node_ref()
                && mapping.status == NodeMappingStatus::Unmapped
                && mapping.reason.as_deref() == Some("member-reparsed-after-move")
        }));

        let mut to_end = EditTransactionBuilder::new(&document);
        to_end.move_member(members[0].node_ref(), AssociationPlacement::End);
        assert_eq!(
            document.commit(&to_end.build()).unwrap().document.render(),
            b"{ /*before-a*/  /*between*/ b:2, c:3,a:1, }"
        );

        let mut no_op = EditTransactionBuilder::new(&document);
        no_op.move_member(
            members[1].node_ref(),
            AssociationPlacement::Before(members[2].node_ref()),
        );
        let no_op = document.commit(&no_op.build()).unwrap();
        assert_eq!(no_op.document.render(), document.render());
        assert!(no_op.change_set.source_edits().is_empty());
    }

    #[test]
    fn move_member_rejects_cross_object_self_and_concurrent_conflicts() {
        let document = parse(
            br#"{"left":{"a":1,"x":2},"right":{"b":3}}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let roots = object_members(&document);
        let left = match roots[0].value().object_members() {
            SemanticAvailability::Available(Some(members)) => members,
            other => panic!("expected left object: {other:?}"),
        };
        let right = match roots[1].value().object_members() {
            SemanticAvailability::Available(Some(members)) => members,
            other => panic!("expected right object: {other:?}"),
        };

        let mut cross = EditTransactionBuilder::new(&document);
        cross.move_member(
            left[0].node_ref(),
            AssociationPlacement::Before(right[0].node_ref()),
        );
        assert_eq!(
            document.commit(&cross.build()).unwrap_err(),
            EditFailure::TargetNotFound
        );

        let mut self_anchor = EditTransactionBuilder::new(&document);
        self_anchor.move_member(
            left[0].node_ref(),
            AssociationPlacement::After(left[0].node_ref()),
        );
        assert_eq!(
            document.commit(&self_anchor.build()).unwrap_err(),
            EditFailure::PlacementAnchorModified
        );

        let mut anchor_renamed = EditTransactionBuilder::new(&document);
        anchor_renamed
            .move_member(
                left[0].node_ref(),
                AssociationPlacement::After(left[1].node_ref()),
            )
            .rename_member(left[1].node_ref(), "renamed");
        assert_eq!(
            document.commit(&anchor_renamed.build()).unwrap_err(),
            EditFailure::PlacementAnchorModified
        );

        let mut descendant = EditTransactionBuilder::new(&document);
        descendant
            .move_member(left[0].node_ref(), AssociationPlacement::End)
            .semantic_scalar(
                left[0].value_node_ref(),
                PortableValue::integer(BigInteger::from(9_i64)),
                RepresentationPolicy::PreserveCompatible,
            );
        assert_eq!(
            document.commit(&descendant.build()).unwrap_err(),
            EditFailure::AncestorDescendantConflict
        );

        let mut target_as_anchor = EditTransactionBuilder::new(&document);
        target_as_anchor
            .move_member(left[0].node_ref(), AssociationPlacement::End)
            .insert_member(
                roots[0].value_node_ref(),
                "new",
                PortableValue::null(),
                AssociationPlacement::Before(left[0].node_ref()),
            );
        assert_eq!(
            document.commit(&target_as_anchor.build()).unwrap_err(),
            EditFailure::PlacementAnchorModified
        );
        assert_eq!(
            document.render(),
            br#"{"left":{"a":1,"x":2},"right":{"b":3}}"#
        );
    }

    #[test]
    fn dry_run_and_commit_have_identical_patch_and_target_digest() {
        let document = parse(
            b"{\"a\":1}".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_member(
            document.root().node_ref(),
            "secret-name",
            PortableValue::string("secret-value"),
            AssociationPlacement::End,
        );
        let transaction = builder.build();
        let plan = document
            .dry_run(&transaction, EditPlanSourceId::new("config.json").unwrap())
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(plan.replacements(), commit.source_patch.replacements());
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(plan.operations().len(), 1);
        assert!(
            plan.operations()[0]
                .arguments()
                .values()
                .all(|value| !value.contains("secret"))
        );
        assert_eq!(
            plan.source_patch()
                .apply(
                    document.source(),
                    source_patch_limits(document.parse_limits, 1)
                )
                .unwrap()
                .bytes(),
            commit.document.render()
        );
        let redacted = plan
            .clone()
            .with_all_replacements_redacted(true, true)
            .unwrap();
        assert!(!format!("{redacted:?}").contains("secret"));
        assert!(
            redacted.replacements()[0]
                .replacement()
                .windows(b"secret-value".len())
                .any(|window| window == b"secret-value")
        );
        assert_eq!(
            redacted
                .source_patch()
                .apply(
                    document.source(),
                    source_patch_limits(document.parse_limits, 1)
                )
                .unwrap()
                .bytes(),
            commit.document.render()
        );
    }

    #[test]
    fn wrong_snapshot_is_rejected_atomically() {
        let first = parse(
            b"1".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let second = parse(
            b"2".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&second);
        builder.literal_scalar(first.root().node_ref(), b"3".as_slice());
        assert!(matches!(
            second.commit(&builder.build()),
            Err(EditFailure::WrongSnapshot)
        ));
        assert_eq!(second.render(), b"2");
    }

    #[test]
    fn object_key_replacement_must_remain_a_string() {
        let document = parse(
            br#"{"a":1}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let member = match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0],
            _ => panic!("missing member"),
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.literal_scalar(member.key_node_ref(), b"2".as_slice());
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::InvalidLiteral)
        ));
        assert_eq!(document.render(), br#"{"a":1}"#);
    }

    fn member_value_ref(document: &Document) -> NodeRef {
        match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0].value_node_ref(),
            _ => panic!("missing member"),
        }
    }

    #[test]
    fn preserve_compatible_keeps_decimal_fraction_scale() {
        let document = parse(
            br#"{"a": 1.00}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(25_i64),
                BigInteger::from(-1_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 2.50}"#);
    }

    #[test]
    fn preserve_compatible_keeps_exponent_marker_and_sign() {
        let document = parse(
            br#"{"a": 1E+02}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::integer(BigInteger::from(2_i64)),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 2E+0}"#);
    }

    #[test]
    fn preserve_compatible_rejects_unrepresentable_fraction_scale() {
        let document = parse(
            br#"{"a": 1.000}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(-4_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::RepresentationIncompatible)
        ));
        assert_eq!(document.render(), br#"{"a": 1.000}"#);
    }

    #[test]
    fn preserve_compatible_keeps_string_escape_style() {
        let document = parse(
            br#"{"a": "a\u0041"}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::string("xA"),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": "x\u0041"}"#);
    }

    #[test]
    fn canonical_for_profile_is_independent_of_old_spelling() {
        let document = parse(
            br#"{"a": 1.00}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(25_i64),
                BigInteger::from(-1_i64),
            )),
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 25e-1}"#);
    }

    #[test]
    fn preserve_else_canonical_reports_actual_fallback() {
        let document = parse(
            br#"{"a": 1.000}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(-4_i64),
            )),
            RepresentationPolicy::PreserveElseCanonical,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 1e-4}"#);
        assert_eq!(
            commit
                .change_set
                .diagnostics()
                .iter()
                .filter(|item| item.code == "json.edit.representation-fallback@1")
                .count(),
            1
        );
    }

    #[test]
    fn preserve_compatible_rejects_category_change() {
        let document = parse(
            br#"{"a": 1}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(0_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::RepresentationIncompatible)
        ));
    }

    #[test]
    fn json5_scalar_edits_preserve_compatible_lexical_categories() {
        let document = parse(
            br"{hex:+0X0f,lead:+.50,trail:1.,exp:1.0E+2,single:'a\x20\v\0\q',nf:+Infinity,}"
                .as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        )
        .unwrap();
        let members = object_members(&document);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .semantic_scalar(
                members[0].value_node_ref(),
                PortableValue::integer(BigInteger::from(16_i64)),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                members[1].value_node_ref(),
                PortableValue::decimal(Decimal::new(
                    BigInteger::from(75_i64),
                    BigInteger::from(-2_i64),
                )),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                members[2].value_node_ref(),
                PortableValue::integer(BigInteger::from(2_i64)),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                members[3].value_node_ref(),
                PortableValue::decimal(Decimal::new(
                    BigInteger::from(34_i64),
                    BigInteger::from(-1_i64),
                )),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                members[4].value_node_ref(),
                PortableValue::string("a \u{000b}\0q"),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                members[5].value_node_ref(),
                PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0000)),
                RepresentationPolicy::PreserveCompatible,
            );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            br"{hex:+0X10,lead:+.75,trail:2.,exp:3.4E+0,single:'a\x20\v\0\q',nf:+NaN,}"
        );
    }

    #[test]
    fn json5_structural_edits_quote_names_and_allow_frozen_non_finite_values() {
        let document = parse(
            b"{a:1, /*keep*/ b:2,}".as_slice(),
            JsonProfile::Json5StandardV1,
            ParseLimits::default(),
        )
        .unwrap();
        let members = object_members(&document);
        let mut insert = EditTransactionBuilder::new(&document);
        insert.insert_member(
            document.root().node_ref(),
            "x\"",
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff0_0000_0000_0000)),
            AssociationPlacement::Before(members[1].node_ref()),
        );
        assert_eq!(
            document.commit(&insert.build()).unwrap().document.render(),
            br#"{a:1, /*keep*/ "x\"":Infinity,b:2,}"#
        );

        let mut rename = EditTransactionBuilder::new(&document);
        rename.rename_member(members[0].node_ref(), "renamed");
        assert_eq!(
            document.commit(&rename.build()).unwrap().document.render(),
            br#"{"renamed":1, /*keep*/ b:2,}"#
        );

        let strict = parse(
            b"0".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut unsupported = EditTransactionBuilder::new(&strict);
        unsupported.semantic_scalar(
            strict.root().node_ref(),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff0_0000_0000_0000)),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            strict.commit(&unsupported.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::BinaryFloat64
            ))
        ));
    }
}
