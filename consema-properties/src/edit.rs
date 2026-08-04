use crate::{
    Document, JavaString, PropertiesEncodingSelection, PropertiesProfile, Property, parse,
};
use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, FailureKind, OperationKind, StableFailure,
};
use consema_document::{
    AssociationPlacement, BomPolicy, ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId,
    EncodingRequest, FormatOperationId, FormationStatus, NodeMapping, NodeMappingStatus, NodeRef,
    NodeRole, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits, SourceSnapshot, Span,
    UntouchedByteProof,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

/// One typed Java Properties structural edit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Replaces one property's semantic Java UTF-16 value.
    ReplaceSemanticValue {
        /// Exact property target.
        target: NodeRef,
        /// Exact replacement Java string.
        value: JavaString,
    },
    /// Replaces one property's exact raw value literal.
    ReplaceLiteralValue {
        /// Exact property target.
        target: NodeRef,
        /// Raw bytes in the base document's selected source encoding.
        literal: Arc<[u8]>,
    },
    /// Inserts one canonical property occurrence.
    InsertProperty {
        /// Exact Properties document target.
        document: NodeRef,
        /// Exact Java UTF-16 key.
        key: JavaString,
        /// Exact Java UTF-16 value.
        value: JavaString,
        /// Placement among property occurrences.
        placement: AssociationPlacement,
    },
    /// Removes one exact property occurrence and all its natural lines.
    RemoveProperty {
        /// Exact property target.
        target: NodeRef,
    },
    /// Replaces one exact property's semantic Java UTF-16 key.
    RenameProperty {
        /// Exact property target.
        target: NodeRef,
        /// Exact replacement key.
        key: JavaString,
    },
}

impl EditOperation {
    fn destructive_target(&self) -> Option<NodeRef> {
        match self {
            Self::ReplaceSemanticValue { target, .. }
            | Self::ReplaceLiteralValue { target, .. }
            | Self::RemoveProperty { target }
            | Self::RenameProperty { target, .. } => Some(*target),
            Self::InsertProperty { .. } => None,
        }
    }
}

/// Immutable edit transaction; every operation resolves against one base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditTransaction {
    base: consema_document::SnapshotIdentity,
    operations: Arc<[EditOperation]>,
}

impl EditTransaction {
    /// Base snapshot identity.
    #[must_use]
    pub const fn base_snapshot(&self) -> consema_document::SnapshotIdentity {
        self.base
    }

    /// Ordered declared operations.
    #[must_use]
    pub fn operations(&self) -> &[EditOperation] {
        &self.operations
    }
}

/// Builder for one immutable Properties edit transaction.
#[derive(Debug)]
pub struct EditTransactionBuilder {
    base: consema_document::SnapshotIdentity,
    operations: Vec<EditOperation>,
}

impl EditTransactionBuilder {
    /// Binds a new transaction to one immutable Properties document.
    #[must_use]
    pub fn new(document: &Document) -> Self {
        Self {
            base: document.snapshot_identity(),
            operations: Vec::new(),
        }
    }

    /// Adds one semantic Java-string value replacement.
    pub fn semantic_value(&mut self, target: NodeRef, value: JavaString) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceSemanticValue { target, value });
        self
    }

    /// Adds one exact raw value-literal replacement.
    pub fn literal_value(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations.push(EditOperation::ReplaceLiteralValue {
            target,
            literal: literal.into(),
        });
        self
    }

    /// Adds one canonical property insertion.
    pub fn insert_property(
        &mut self,
        document: NodeRef,
        key: JavaString,
        value: JavaString,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertProperty {
            document,
            key,
            value,
            placement,
        });
        self
    }

    /// Adds one exact property removal.
    pub fn remove_property(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveProperty { target });
        self
    }

    /// Adds one semantic Java-string property rename.
    pub fn rename_property(&mut self, target: NodeRef, key: JavaString) -> &mut Self {
        self.operations
            .push(EditOperation::RenameProperty { target, key });
        self
    }

    /// Completes the request; validation remains atomic at dry-run or commit.
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
    /// Evidence for every byte outside the replacement set.
    pub untouched_proof: UntouchedByteProof,
}

/// Stable edit validation or commit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditFailure {
    /// Edits are forbidden on a recovered document.
    RecoveredDocument,
    /// Transaction or target belongs to another snapshot.
    WrongSnapshot,
    /// Target has the wrong structural role.
    WrongRole,
    /// More than one operation names the same exact property.
    DuplicateTarget,
    /// Prepared source ownership intervals overlap or share an insertion point.
    OverlappingOwnership,
    /// Placement is invalid or names an unavailable anchor.
    InvalidPlacement,
    /// An insertion anchor is removed by this transaction.
    PlacementAnchorRemoved,
    /// A target no longer exists in the base snapshot.
    TargetNotFound,
    /// A semantic Java string cannot be represented by the selected source encoding.
    EncodingUnrepresentable,
    /// Literal bytes do not form exactly one raw value element.
    InvalidLiteral,
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement bytes did not close through exact reparse and semantic verification.
    NewDocumentFormationFailed,
}

impl std::fmt::Display for EditFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for EditFailure {}

impl StableFailure for EditFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Edit
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::WrongSnapshot => FailureKind::TargetMismatch,
            Self::WrongRole
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::InvalidPlacement
            | Self::PlacementAnchorRemoved => FailureKind::InvalidInput,
            Self::RecoveredDocument | Self::TargetNotFound | Self::InvalidLiteral => {
                FailureKind::NotApplicable
            }
            Self::EncodingUnrepresentable => FailureKind::Unsupported,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::RecoveredDocument => "core.edit.incomplete-target@1",
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::DuplicateTarget | Self::OverlappingOwnership | Self::PlacementAnchorRemoved => {
                "core.edit.conflicting-edits@1"
            }
            Self::InvalidPlacement => "java-properties.edit.invalid-placement@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
            Self::EncodingUnrepresentable => "core.edit.representation-incompatible@1",
            Self::InvalidLiteral => "core.edit.invalid-literal@1",
            Self::ResourceLimit(_) => "core.edit.resource-limit@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

#[derive(Clone)]
struct ExpectedProperty {
    old: Option<NodeRef>,
    key: JavaString,
    value: Option<JavaString>,
    literal: bool,
    literal_old_span: Option<Span>,
    removed: bool,
}

struct PreparedEdit {
    old_span: Span,
    replacement: Vec<u8>,
}

impl Document {
    /// Atomically commits every declared Properties operation.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if self.formation_status() != FormationStatus::Complete {
            return Err(EditFailure::RecoveredDocument);
        }
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if transaction.operations.len() > self.parse_limits.common.max_node_count {
            return Err(EditFailure::ResourceLimit("edit-operations"));
        }
        Self::validate_removed_anchors(transaction)?;

        let mut targets = HashSet::new();
        targets
            .try_reserve(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("edit-targets"))?;
        let mut insert_boundaries = BTreeSet::new();
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::new();
        let mut expected = self
            .properties()
            .iter()
            .map(|property| ExpectedProperty {
                old: Some(property.node_ref()),
                key: property.key().clone(),
                value: Some(property.value().clone()),
                literal: false,
                literal_old_span: None,
                removed: false,
            })
            .collect::<Vec<_>>();
        let mut insertions = BTreeMap::<usize, ExpectedProperty>::new();

        for operation in transaction.operations.iter() {
            if let Some(target) = operation.destructive_target() {
                if !targets.insert(target) {
                    return Err(EditFailure::DuplicateTarget);
                }
            }
            match operation {
                EditOperation::ReplaceSemanticValue { target, value } => {
                    let ordinal = self.property_ordinal(*target)?;
                    let property = &self.properties()[ordinal];
                    let old_span = self.value_ownership(property)?;
                    let replacement =
                        if let Some(bytes) = self.preserve_direct_value(property, value) {
                            bytes
                        } else {
                            diagnostics.push(Self::canonical_fallback_diagnostic(property.span()));
                            self.canonical_fragment(value, false)?
                        };
                    expected[ordinal].value = Some(value.clone());
                    prepared.push(PreparedEdit {
                        old_span,
                        replacement,
                    });
                }
                EditOperation::ReplaceLiteralValue { target, literal } => {
                    let ordinal = self.property_ordinal(*target)?;
                    self.validate_literal(literal)?;
                    let property = &self.properties()[ordinal];
                    let old_span = self.value_ownership(property)?;
                    expected[ordinal].value = None;
                    expected[ordinal].literal = true;
                    expected[ordinal].literal_old_span = Some(old_span);
                    prepared.push(PreparedEdit {
                        old_span,
                        replacement: literal.to_vec(),
                    });
                }
                EditOperation::InsertProperty {
                    document,
                    key,
                    value,
                    placement,
                } => {
                    self.validate_document_target(*document)?;
                    let (boundary, position) = self.insertion_location(*placement)?;
                    if !insert_boundaries.insert(boundary) {
                        return Err(EditFailure::OverlappingOwnership);
                    }
                    insertions.insert(
                        boundary,
                        ExpectedProperty {
                            old: None,
                            key: key.clone(),
                            value: Some(value.clone()),
                            literal: false,
                            literal_old_span: None,
                            removed: false,
                        },
                    );
                    prepared.push(PreparedEdit {
                        old_span: self
                            .authority
                            .span(position, position)
                            .map_err(|_| EditFailure::InvalidPlacement)?,
                        replacement: self.canonical_record(position, key, value)?,
                    });
                }
                EditOperation::RemoveProperty { target } => {
                    let ordinal = self.property_ordinal(*target)?;
                    expected[ordinal].removed = true;
                    prepared.push(PreparedEdit {
                        old_span: self.record_ownership(&self.properties()[ordinal])?,
                        replacement: Vec::new(),
                    });
                }
                EditOperation::RenameProperty { target, key } => {
                    let ordinal = self.property_ordinal(*target)?;
                    expected[ordinal].key = key.clone();
                    prepared.push(PreparedEdit {
                        old_span: self.key_ownership(&self.properties()[ordinal])?,
                        replacement: self.canonical_fragment(key, true)?,
                    });
                }
            }
        }
        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        validate_non_overlapping(&prepared)?;
        let final_expected = assemble_expected(expected, insertions);
        let closure_failure = if final_expected.iter().any(|property| property.literal) {
            EditFailure::InvalidLiteral
        } else {
            EditFailure::NewDocumentFormationFailed
        };
        let rendered = self.apply_prepared(&prepared)?;
        let new_document = parse(
            rendered,
            self.profile,
            original_encoding_selection(self),
            self.parse_limits,
        )
        .map_err(|_| closure_failure.clone())?;
        if new_document.formation_status() != FormationStatus::Complete {
            return Err(closure_failure);
        }
        verify_expected(&new_document, &final_expected)?;

        let source_edits = build_source_edits(&new_document, &prepared)?;
        verify_literal_ownership(&new_document, &final_expected, &source_edits)?;
        let mappings = build_node_mappings(&new_document, &final_expected, transaction);
        let change_set = ChangeSet::new(
            self.snapshot_identity(),
            new_document.snapshot_identity(),
            source_edits,
            mappings,
            diagnostics,
        );
        let patch_limits = source_patch_limits(self.parse_limits, prepared.len());
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

    fn property_ordinal(&self, target: NodeRef) -> Result<usize, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::PropertiesProperty {
            return Err(EditFailure::WrongRole);
        }
        self.properties()
            .iter()
            .position(|property| property.node_ref() == target)
            .ok_or(EditFailure::TargetNotFound)
    }

    fn validate_document_target(&self, target: NodeRef) -> Result<(), EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::PropertiesDocument {
            return Err(EditFailure::WrongRole);
        }
        if target != self.node_ref() {
            return Err(EditFailure::TargetNotFound);
        }
        Ok(())
    }

    fn validate_removed_anchors(transaction: &EditTransaction) -> Result<(), EditFailure> {
        let removed: HashSet<_> = transaction
            .operations
            .iter()
            .filter_map(|operation| match operation {
                EditOperation::RemoveProperty { target } => Some(*target),
                _ => None,
            })
            .collect();
        for operation in transaction.operations.iter() {
            if let EditOperation::InsertProperty { placement, .. } = operation {
                if matches!(placement, AssociationPlacement::Before(anchor) | AssociationPlacement::After(anchor) if removed.contains(anchor))
                {
                    return Err(EditFailure::PlacementAnchorRemoved);
                }
            }
        }
        Ok(())
    }

    fn insertion_location(
        &self,
        placement: AssociationPlacement,
    ) -> Result<(usize, usize), EditFailure> {
        let count = self.properties().len();
        match placement {
            AssociationPlacement::Start => Ok((
                0,
                self.properties()
                    .first()
                    .map_or(self.source().len(), |property| {
                        self.record_ownership(property)
                            .expect("formed property owns a record")
                            .start_byte()
                    }),
            )),
            AssociationPlacement::End => Ok((count, self.source().len())),
            AssociationPlacement::Before(anchor) => {
                let ordinal = self.property_ordinal(anchor)?;
                Ok((
                    ordinal,
                    self.record_ownership(&self.properties()[ordinal])?
                        .start_byte(),
                ))
            }
            AssociationPlacement::After(anchor) => {
                let ordinal = self.property_ordinal(anchor)?;
                Ok((
                    ordinal + 1,
                    self.record_ownership(&self.properties()[ordinal])?
                        .end_byte(),
                ))
            }
        }
    }

    fn record_ownership(&self, property: &Property) -> Result<Span, EditFailure> {
        let logical = self
            .logical_line(property.logical_line())
            .map_err(|_| EditFailure::TargetNotFound)?;
        let first = logical
            .natural_lines()
            .first()
            .and_then(|node| self.natural_line(*node).ok())
            .ok_or(EditFailure::TargetNotFound)?;
        let last = logical
            .natural_lines()
            .last()
            .and_then(|node| self.natural_line(*node).ok())
            .ok_or(EditFailure::TargetNotFound)?;
        self.authority
            .span(first.span().start_byte(), last.span().end_byte())
            .map_err(|_| EditFailure::TargetNotFound)
    }

    fn key_ownership(&self, property: &Property) -> Result<Span, EditFailure> {
        fragment_ownership(
            &self.authority,
            property.key_fragments(),
            property.key_anchor(),
        )
    }

    fn value_ownership(&self, property: &Property) -> Result<Span, EditFailure> {
        fragment_ownership(
            &self.authority,
            property.value_fragments(),
            property.value_anchor(),
        )
    }

    fn preserve_direct_value(&self, property: &Property, value: &JavaString) -> Option<Vec<u8>> {
        let logical = self.logical_line(property.logical_line()).ok()?;
        if logical.natural_lines().len() != 1
            || property
                .escapes()
                .iter()
                .filter_map(|node| self.escape(*node).ok())
                .any(|escape| !escape.in_key())
        {
            return None;
        }
        let text = value.to_unicode().ok()?;
        if text.starts_with([' ', '\t', '\u{000c}']) || text.contains(['\\', '\r', '\n']) {
            return None;
        }
        crate::materialization::encode_fragment(
            &text,
            self.source().encoding_facts().selected(),
            self.parse_limits.common.max_source_bytes,
        )
        .ok()
    }

    fn canonical_fragment(&self, value: &JavaString, is_key: bool) -> Result<Vec<u8>, EditFailure> {
        let text = canonical_java_string(
            value,
            self.profile,
            is_key,
            self.parse_limits.common.max_source_bytes,
        )?;
        crate::materialization::encode_fragment(
            &text,
            self.source().encoding_facts().selected(),
            self.parse_limits.common.max_source_bytes,
        )
        .map_err(map_encoding_failure)
    }

    fn canonical_record(
        &self,
        position: usize,
        key: &JavaString,
        value: &JavaString,
    ) -> Result<Vec<u8>, EditFailure> {
        let newline = self.newline_convention();
        let mut text = String::new();
        if position > 0 && !self.is_line_boundary(position)? {
            push_bounded(
                &mut text,
                newline,
                self.parse_limits.common.max_source_bytes,
            )?;
        }
        push_bounded(
            &mut text,
            &canonical_java_string(
                key,
                self.profile,
                true,
                self.parse_limits.common.max_source_bytes,
            )?,
            self.parse_limits.common.max_source_bytes,
        )?;
        push_bounded(&mut text, "=", self.parse_limits.common.max_source_bytes)?;
        push_bounded(
            &mut text,
            &canonical_java_string(
                value,
                self.profile,
                false,
                self.parse_limits.common.max_source_bytes,
            )?,
            self.parse_limits.common.max_source_bytes,
        )?;
        push_bounded(
            &mut text,
            newline,
            self.parse_limits.common.max_source_bytes,
        )?;
        crate::materialization::encode_fragment(
            &text,
            self.source().encoding_facts().selected(),
            self.parse_limits.common.max_source_bytes,
        )
        .map_err(map_encoding_failure)
    }

    fn newline_convention(&self) -> &'static str {
        let text = self
            .source()
            .decoded_text()
            .expect("Properties source is text");
        for (index, character) in text.char_indices() {
            if character == '\r' {
                return if text[index + 1..].starts_with('\n') {
                    "\r\n"
                } else {
                    "\r"
                };
            }
            if character == '\n' {
                return "\n";
            }
        }
        "\n"
    }

    fn is_line_boundary(&self, raw: usize) -> Result<bool, EditFailure> {
        let decoded = self
            .source()
            .decoded_position(raw)
            .map_err(|_| EditFailure::InvalidPlacement)?
            .decoded_utf8_byte;
        Ok(self.source().decoded_text().expect("text")[..decoded].ends_with(['\r', '\n']))
    }

    fn validate_literal(&self, literal: &[u8]) -> Result<(), EditFailure> {
        if literal.len() > self.parse_limits.common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("replacement-bytes"));
        }
        let encoding = self.source().encoding_facts().selected();
        let request = EncodingRequest::new(encoding)
            .with_caller_override(encoding)
            .with_bom_policy(BomPolicy::TreatAsContent);
        let snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(literal),
            request,
            SourceLimits {
                max_raw_bytes: self.parse_limits.common.max_source_bytes,
                max_decoded_utf8_bytes: self.parse_limits.max_decoded_utf8_bytes,
                max_decoded_scalars: self.parse_limits.max_decoded_scalars,
            },
        )
        .map_err(|_| EditFailure::InvalidLiteral)?;
        if snapshot
            .decoded_text()
            .expect("literal uses a text encoding")
            .contains(['\r', '\n'])
        {
            return Err(EditFailure::InvalidLiteral);
        }
        Ok(())
    }

    fn canonical_fallback_diagnostic(span: Span) -> Diagnostic {
        Diagnostic::new(
            "java-properties.edit.canonical-fallback@1",
            DiagnosticCategory::Edit,
            DiagnosticSeverity::Warning,
            Some(span.diagnostic_location()),
            0,
        )
    }

    fn apply_prepared(&self, prepared: &[PreparedEdit]) -> Result<Vec<u8>, EditFailure> {
        let target_len = prepared
            .iter()
            .try_fold(self.source().len(), |length, edit| {
                length
                    .checked_sub(edit.old_span.len())
                    .and_then(|value| value.checked_add(edit.replacement.len()))
                    .ok_or(EditFailure::ResourceLimit("target-bytes"))
            })?;
        if target_len > self.parse_limits.common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("target-bytes"));
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(target_len)
            .map_err(|_| EditFailure::ResourceLimit("target-allocation"))?;
        let mut cursor = 0;
        for edit in prepared {
            append_bytes(
                &mut output,
                &self.source().bytes()[cursor..edit.old_span.start_byte()],
                target_len,
            )?;
            append_bytes(&mut output, &edit.replacement, target_len)?;
            cursor = edit.old_span.end_byte();
        }
        append_bytes(&mut output, &self.source().bytes()[cursor..], target_len)?;
        Ok(output)
    }
}

fn fragment_ownership(
    authority: &consema_document::DocumentAuthority,
    fragments: &[Span],
    anchor: Span,
) -> Result<Span, EditFailure> {
    if fragments.is_empty() {
        return Ok(anchor);
    }
    authority
        .span(
            fragments[0].start_byte(),
            fragments[fragments.len() - 1].end_byte(),
        )
        .map_err(|_| EditFailure::TargetNotFound)
}

fn validate_non_overlapping(prepared: &[PreparedEdit]) -> Result<(), EditFailure> {
    for pair in prepared.windows(2) {
        let left = pair[0].old_span;
        let right = pair[1].old_span;
        if left == right
            || left.end_byte() > right.start_byte()
            || (left.is_empty() && left.start_byte() == right.start_byte())
            || (right.is_empty() && left.end_byte() == right.start_byte())
        {
            return Err(EditFailure::OverlappingOwnership);
        }
    }
    Ok(())
}

fn assemble_expected(
    old: Vec<ExpectedProperty>,
    mut insertions: BTreeMap<usize, ExpectedProperty>,
) -> Vec<ExpectedProperty> {
    let mut output = Vec::with_capacity(old.len().saturating_add(insertions.len()));
    for boundary in 0..=old.len() {
        if let Some(inserted) = insertions.remove(&boundary) {
            output.push(inserted);
        }
        if let Some(property) = old.get(boundary).filter(|property| !property.removed) {
            output.push(property.clone());
        }
    }
    output
}

fn verify_expected(document: &Document, expected: &[ExpectedProperty]) -> Result<(), EditFailure> {
    if document.properties().len() != expected.len() {
        return Err(if expected.iter().any(|property| property.literal) {
            EditFailure::InvalidLiteral
        } else {
            EditFailure::NewDocumentFormationFailed
        });
    }
    for (actual, expected) in document.properties().iter().zip(expected) {
        if actual.key() != &expected.key
            || expected
                .value
                .as_ref()
                .is_some_and(|value| actual.value() != value)
        {
            return Err(if expected.literal {
                EditFailure::InvalidLiteral
            } else {
                EditFailure::NewDocumentFormationFailed
            });
        }
    }
    Ok(())
}

fn build_source_edits(
    new_document: &Document,
    prepared: &[PreparedEdit],
) -> Result<Vec<SourceEdit>, EditFailure> {
    let mut delta = 0_isize;
    let mut source_edits = Vec::new();
    source_edits
        .try_reserve_exact(prepared.len())
        .map_err(|_| EditFailure::ResourceLimit("source-edits"))?;
    for edit in prepared {
        let new_start = edit
            .old_span
            .start_byte()
            .checked_add_signed(delta)
            .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
        let new_end = new_start
            .checked_add(edit.replacement.len())
            .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
        source_edits.push(SourceEdit {
            old_span: edit.old_span,
            new_span: new_document
                .authority
                .span(new_start, new_end)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?,
            replacement: Arc::from(edit.replacement.clone()),
        });
        let replacement_len = isize::try_from(edit.replacement.len())
            .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
        let old_len = isize::try_from(edit.old_span.len())
            .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
        delta = delta
            .checked_add(replacement_len - old_len)
            .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
    }
    Ok(source_edits)
}

fn verify_literal_ownership(
    document: &Document,
    expected: &[ExpectedProperty],
    source_edits: &[SourceEdit],
) -> Result<(), EditFailure> {
    for (ordinal, expected) in expected.iter().enumerate().filter(|(_, item)| item.literal) {
        let old_span = expected
            .literal_old_span
            .ok_or(EditFailure::InvalidLiteral)?;
        let source_edit = source_edits
            .iter()
            .find(|edit| edit.old_span == old_span)
            .ok_or(EditFailure::InvalidLiteral)?;
        let actual = &document.properties()[ordinal];
        let ownership = document.value_ownership(actual)?;
        if source_edit.new_span != ownership {
            return Err(EditFailure::InvalidLiteral);
        }
    }
    Ok(())
}

fn build_node_mappings(
    document: &Document,
    expected: &[ExpectedProperty],
    transaction: &EditTransaction,
) -> Vec<NodeMapping> {
    transaction
        .operations
        .iter()
        .filter_map(|operation| match operation {
            EditOperation::RemoveProperty { target } => Some(NodeMapping {
                old: *target,
                new: None,
                status: NodeMappingStatus::Deleted,
                reason: None,
            }),
            EditOperation::ReplaceSemanticValue { target, .. }
            | EditOperation::ReplaceLiteralValue { target, .. }
            | EditOperation::RenameProperty { target, .. } => {
                let ordinal = expected.iter().position(|item| item.old == Some(*target))?;
                Some(NodeMapping {
                    old: *target,
                    new: Some(document.properties()[ordinal].node_ref()),
                    status: NodeMappingStatus::Replaced,
                    reason: None,
                })
            }
            EditOperation::InsertProperty { .. } => None,
        })
        .collect()
}

fn canonical_java_string(
    value: &JavaString,
    profile: PropertiesProfile,
    is_key: bool,
    limit: usize,
) -> Result<String, EditFailure> {
    let mut output = String::new();
    let mut index = 0;
    let mut leading_value_space = !is_key;
    while index < value.code_units().len() {
        let unit = value.code_units()[index];
        let scalar = if (0xD800..=0xDBFF).contains(&unit)
            && value
                .code_units()
                .get(index + 1)
                .is_some_and(|next| (0xDC00..=0xDFFF).contains(next))
        {
            let high = u32::from(unit - 0xD800);
            let low = u32::from(value.code_units()[index + 1] - 0xDC00);
            index += 2;
            char::from_u32(0x10000 + (high << 10) + low)
        } else if (0xD800..=0xDFFF).contains(&unit) {
            index += 1;
            push_unicode_escape(&mut output, unit, limit)?;
            leading_value_space = false;
            continue;
        } else {
            index += 1;
            char::from_u32(u32::from(unit))
        }
        .expect("formed UTF-16 scalar");

        match scalar {
            ' ' if is_key || leading_value_space => push_bounded(&mut output, "\\ ", limit)?,
            '\t' => push_bounded(&mut output, "\\t", limit)?,
            '\n' => push_bounded(&mut output, "\\n", limit)?,
            '\r' => push_bounded(&mut output, "\\r", limit)?,
            '\u{000c}' => push_bounded(&mut output, "\\f", limit)?,
            '\\' => push_bounded(&mut output, "\\\\", limit)?,
            '#' | '!' | '=' | ':' => {
                push_bounded(&mut output, "\\", limit)?;
                push_char_bounded(&mut output, scalar, limit)?;
            }
            control if control.is_control() => {
                let mut units = [0_u16; 2];
                for unit in control.encode_utf16(&mut units) {
                    push_unicode_escape(&mut output, *unit, limit)?;
                }
            }
            non_ascii
                if profile == PropertiesProfile::Latin1V1
                    && !(0x20..=0x7E).contains(&u32::from(non_ascii)) =>
            {
                let mut units = [0_u16; 2];
                for unit in non_ascii.encode_utf16(&mut units) {
                    push_unicode_escape(&mut output, *unit, limit)?;
                }
            }
            printable => push_char_bounded(&mut output, printable, limit)?,
        }
        if scalar != ' ' {
            leading_value_space = false;
        }
    }
    Ok(output)
}

fn push_unicode_escape(output: &mut String, value: u16, limit: usize) -> Result<(), EditFailure> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let text = [
        b'\\',
        b'u',
        HEX[usize::from((value >> 12) & 0xF)],
        HEX[usize::from((value >> 8) & 0xF)],
        HEX[usize::from((value >> 4) & 0xF)],
        HEX[usize::from(value & 0xF)],
    ];
    push_bounded(
        output,
        std::str::from_utf8(&text).expect("ASCII escape"),
        limit,
    )
}

fn push_bounded(output: &mut String, text: &str, limit: usize) -> Result<(), EditFailure> {
    let length = output
        .len()
        .checked_add(text.len())
        .ok_or(EditFailure::ResourceLimit("replacement-bytes"))?;
    if length > limit {
        return Err(EditFailure::ResourceLimit("replacement-bytes"));
    }
    output
        .try_reserve(text.len())
        .map_err(|_| EditFailure::ResourceLimit("replacement-bytes"))?;
    output.push_str(text);
    Ok(())
}

fn push_char_bounded(output: &mut String, value: char, limit: usize) -> Result<(), EditFailure> {
    let mut encoded = [0_u8; 4];
    push_bounded(output, value.encode_utf8(&mut encoded), limit)
}

fn map_encoding_failure(failure: consema_document::MaterializationFailure) -> EditFailure {
    match failure {
        consema_document::MaterializationFailure::ResourceLimit(name) => {
            EditFailure::ResourceLimit(name)
        }
        _ => EditFailure::EncodingUnrepresentable,
    }
}

fn original_encoding_selection(document: &Document) -> PropertiesEncodingSelection {
    match document.selected_profile() {
        PropertiesProfile::ReaderV1 => {
            PropertiesEncodingSelection::Reader(document.source().encoding_facts().selected())
        }
        PropertiesProfile::Latin1V1 => PropertiesEncodingSelection::Latin1,
    }
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

fn source_patch_limits(
    limits: crate::PropertiesParseLimits,
    operation_count: usize,
) -> SourcePatchLimits {
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
            (
                format!("operation.{index}"),
                format!("{}@1", operation_id(operation)),
            )
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
            let arguments = match operation {
                EditOperation::ReplaceSemanticValue { value, .. } => BTreeMap::from([(
                    "value_code_units".to_owned(),
                    value.code_units().len().to_string(),
                )]),
                EditOperation::ReplaceLiteralValue { literal, .. } => {
                    BTreeMap::from([("literal_bytes".to_owned(), literal.len().to_string())])
                }
                EditOperation::InsertProperty {
                    key,
                    value,
                    placement,
                    ..
                } => BTreeMap::from([
                    (
                        "key_code_units".to_owned(),
                        key.code_units().len().to_string(),
                    ),
                    (
                        "value_code_units".to_owned(),
                        value.code_units().len().to_string(),
                    ),
                    (
                        "placement".to_owned(),
                        placement_name(*placement).to_owned(),
                    ),
                ]),
                EditOperation::RemoveProperty { .. } => BTreeMap::new(),
                EditOperation::RenameProperty { key, .. } => BTreeMap::from([(
                    "key_code_units".to_owned(),
                    key.code_units().len().to_string(),
                )]),
            };
            EditOperationSummary::new(
                FormatOperationId::new(operation_id(operation), 1),
                arguments,
            )
            .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

const fn operation_id(operation: &EditOperation) -> &'static str {
    match operation {
        EditOperation::ReplaceSemanticValue { .. } => "java-properties.edit.replace-semantic-value",
        EditOperation::ReplaceLiteralValue { .. } => "java-properties.edit.replace-literal-value",
        EditOperation::InsertProperty { .. } => "java-properties.edit.insert-property",
        EditOperation::RemoveProperty { .. } => "java-properties.edit.remove-property",
        EditOperation::RenameProperty { .. } => "java-properties.edit.rename-property",
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

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{EditPlanSourceId, SourceEncoding, WindowsCodePage};

    fn reader(source: &[u8]) -> Document {
        crate::parse_reader(
            source,
            SourceEncoding::Utf8,
            crate::PropertiesParseLimits::default(),
        )
        .unwrap()
    }

    fn text(document: &Document) -> &str {
        std::str::from_utf8(document.render()).unwrap()
    }

    fn commit_one(
        document: &Document,
        operation: impl FnOnce(&mut EditTransactionBuilder),
    ) -> EditCommit {
        let mut builder = EditTransactionBuilder::new(document);
        operation(&mut builder);
        document.commit(&builder.build()).unwrap()
    }

    #[test]
    fn semantic_value_preserves_direct_style_and_falls_back_only_when_required() {
        let direct = reader(b"a=one\n");
        let direct_commit = commit_one(&direct, |builder| {
            builder.semantic_value(
                direct.properties()[0].node_ref(),
                JavaString::from_unicode("two words"),
            );
        });
        assert_eq!(text(&direct_commit.document), "a=two words\n");
        assert!(direct_commit.change_set.diagnostics().is_empty());

        let escaped = reader(
            br"a=one\ value
",
        );
        let fallback_commit = commit_one(&escaped, |builder| {
            builder.semantic_value(
                escaped.properties()[0].node_ref(),
                JavaString::from_unicode("next value"),
            );
        });
        assert_eq!(text(&fallback_commit.document), "a=next value\n");
        assert_eq!(
            fallback_commit.change_set.diagnostics()[0].code,
            "java-properties.edit.canonical-fallback@1"
        );
    }

    #[test]
    fn semantic_value_preserves_exact_unpaired_java_units_with_unicode_escapes() {
        let document = reader(b"a=x\n");
        let exact = JavaString::from_code_units(vec![0xD800]);
        let commit = commit_one(&document, |builder| {
            builder.semantic_value(document.properties()[0].node_ref(), exact.clone());
        });
        assert_eq!(text(&commit.document), "a=\\uD800\n");
        assert_eq!(commit.document.properties()[0].value(), &exact);
    }

    #[test]
    fn literal_value_requires_one_exact_value_ownership_interval() {
        let document = reader(b"a=one\nb=two\n");
        let commit = commit_one(&document, |builder| {
            builder.literal_value(
                document.properties()[0].node_ref(),
                b"raw\\ value".as_slice(),
            );
        });
        assert_eq!(text(&commit.document), "a=raw\\ value\nb=two\n");
        assert_eq!(
            commit.document.properties()[0]
                .value()
                .to_unicode()
                .unwrap(),
            "raw value"
        );

        for invalid in [
            b" leading".as_slice(),
            b"line\nbreak".as_slice(),
            b"tail\\".as_slice(),
        ] {
            let mut builder = EditTransactionBuilder::new(&document);
            builder.literal_value(document.properties()[0].node_ref(), invalid);
            assert_eq!(
                document.commit(&builder.build()).unwrap_err(),
                EditFailure::InvalidLiteral
            );
        }
    }

    #[test]
    fn insertions_honor_all_property_relative_placements_and_duplicates() {
        let source = b"# head\na=1\n# middle\nb=2";
        let cases = [
            (
                AssociationPlacement::Start,
                "# head\nx=0\na=1\n# middle\nb=2",
            ),
            (
                AssociationPlacement::Before(reader(source).properties()[1].node_ref()),
                "# head\na=1\n# middle\nx=0\nb=2",
            ),
            (
                AssociationPlacement::After(reader(source).properties()[0].node_ref()),
                "# head\na=1\nx=0\n# middle\nb=2",
            ),
            (
                AssociationPlacement::End,
                "# head\na=1\n# middle\nb=2\nx=0\n",
            ),
        ];
        for (placement, expected) in cases {
            let document = reader(source);
            let placement = match placement {
                AssociationPlacement::Before(_) => {
                    AssociationPlacement::Before(document.properties()[1].node_ref())
                }
                AssociationPlacement::After(_) => {
                    AssociationPlacement::After(document.properties()[0].node_ref())
                }
                other => other,
            };
            let commit = commit_one(&document, |builder| {
                builder.insert_property(
                    document.node_ref(),
                    JavaString::from_unicode("x"),
                    JavaString::from_unicode("0"),
                    placement,
                );
            });
            assert_eq!(text(&commit.document), expected);
        }

        let duplicate = reader(b"a=1\na=2\n");
        let commit = commit_one(&duplicate, |builder| {
            builder.insert_property(
                duplicate.node_ref(),
                JavaString::from_unicode("a"),
                JavaString::from_unicode("3"),
                AssociationPlacement::End,
            );
        });
        assert_eq!(commit.document.properties().len(), 3);
        assert!(
            commit.document.properties().iter().all(|property| property
                .key()
                .to_unicode()
                .unwrap()
                == "a")
        );
    }

    #[test]
    fn removal_owns_all_continuation_lines_but_not_adjacent_comments() {
        let document = reader(b"# before\nkey=first\\\n  second\n# after\nnext=v\n");
        let commit = commit_one(&document, |builder| {
            builder.remove_property(document.properties()[0].node_ref());
        });
        assert_eq!(text(&commit.document), "# before\n# after\nnext=v\n");
        assert_eq!(commit.document.comments().len(), 2);
        assert_eq!(commit.document.properties().len(), 1);
    }

    #[test]
    fn rename_replaces_the_complete_continued_key_ownership() {
        let document = reader(b"old\\\n key=value\n");
        let commit = commit_one(&document, |builder| {
            builder.rename_property(
                document.properties()[0].node_ref(),
                JavaString::from_unicode("new key"),
            );
        });
        assert_eq!(text(&commit.document), "new\\ key=value\n");
        assert_eq!(
            commit.document.properties()[0].key().to_unicode().unwrap(),
            "new key"
        );
    }

    #[test]
    fn transaction_conflicts_fail_before_any_document_is_published() {
        let document = reader(b"a=1\nb=2\n");
        let first = document.properties()[0].node_ref();

        let mut duplicate = EditTransactionBuilder::new(&document);
        duplicate
            .semantic_value(first, JavaString::from_unicode("x"))
            .rename_property(first, JavaString::from_unicode("renamed"));
        assert_eq!(
            document.commit(&duplicate.build()).unwrap_err(),
            EditFailure::DuplicateTarget
        );

        let mut removed_anchor = EditTransactionBuilder::new(&document);
        removed_anchor.remove_property(first).insert_property(
            document.node_ref(),
            JavaString::from_unicode("x"),
            JavaString::from_unicode("0"),
            AssociationPlacement::After(first),
        );
        assert_eq!(
            document.commit(&removed_anchor.build()).unwrap_err(),
            EditFailure::PlacementAnchorRemoved
        );

        let mut shared_boundary = EditTransactionBuilder::new(&document);
        shared_boundary
            .insert_property(
                document.node_ref(),
                JavaString::from_unicode("x"),
                JavaString::from_unicode("0"),
                AssociationPlacement::Start,
            )
            .insert_property(
                document.node_ref(),
                JavaString::from_unicode("y"),
                JavaString::from_unicode("0"),
                AssociationPlacement::Before(first),
            );
        assert_eq!(
            document.commit(&shared_boundary.build()).unwrap_err(),
            EditFailure::OverlappingOwnership
        );
        assert_eq!(document.render(), b"a=1\nb=2\n");
    }

    #[test]
    fn snapshot_role_recovery_and_resource_contracts_are_enforced() {
        let document = reader(b"a=1\n");
        let other = reader(b"a=1\n");
        let mut wrong_snapshot = EditTransactionBuilder::new(&document);
        wrong_snapshot.semantic_value(
            other.properties()[0].node_ref(),
            JavaString::from_unicode("x"),
        );
        assert_eq!(
            document.commit(&wrong_snapshot.build()).unwrap_err(),
            EditFailure::WrongSnapshot
        );

        let mut wrong_role = EditTransactionBuilder::new(&document);
        wrong_role.semantic_value(document.node_ref(), JavaString::from_unicode("x"));
        assert_eq!(
            document.commit(&wrong_role.build()).unwrap_err(),
            EditFailure::WrongRole
        );

        let recovered = reader(
            br"bad=\u12G4
",
        );
        let transaction = EditTransactionBuilder::new(&recovered).build();
        assert_eq!(
            recovered.commit(&transaction).unwrap_err(),
            EditFailure::RecoveredDocument
        );

        let mut limits = crate::PropertiesParseLimits::default();
        limits.common.max_source_bytes = 5;
        let bounded =
            crate::parse_reader(b"a=x\n".as_slice(), SourceEncoding::Utf8, limits).unwrap();
        let mut oversized = EditTransactionBuilder::new(&bounded);
        oversized.semantic_value(
            bounded.properties()[0].node_ref(),
            JavaString::from_unicode("abcdef"),
        );
        assert!(matches!(
            bounded.commit(&oversized.build()),
            Err(EditFailure::ResourceLimit(_))
        ));
    }

    #[test]
    fn selected_encoding_is_preserved_and_unrepresentable_reader_text_fails() {
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in "a=one\r\n".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let document = crate::parse_reader(
            utf16,
            SourceEncoding::Utf16Le,
            crate::PropertiesParseLimits::default(),
        )
        .unwrap();
        let commit = commit_one(&document, |builder| {
            builder.semantic_value(
                document.properties()[0].node_ref(),
                JavaString::from_unicode("\u{65B0}"),
            );
        });
        assert_eq!(
            commit.document.source().encoding_facts(),
            document.source().encoding_facts()
        );
        assert_eq!(
            commit.document.properties()[0]
                .value()
                .to_unicode()
                .unwrap(),
            "\u{65B0}"
        );

        let windows = crate::parse_reader(
            b"a=x\n".as_slice(),
            SourceEncoding::WindowsCodePage(WindowsCodePage::from_number(1252).unwrap()),
            crate::PropertiesParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&windows);
        builder.semantic_value(
            windows.properties()[0].node_ref(),
            JavaString::from_unicode("\u{4E2D}"),
        );
        assert_eq!(
            windows.commit(&builder.build()).unwrap_err(),
            EditFailure::EncodingUnrepresentable
        );
    }

    #[test]
    fn patch_proof_and_dry_run_close_over_the_exact_committed_bytes() {
        let document = reader(b"a=one\nb=two\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .rename_property(
                document.properties()[0].node_ref(),
                JavaString::from_unicode("first"),
            )
            .semantic_value(
                document.properties()[1].node_ref(),
                JavaString::from_unicode("changed"),
            );
        let transaction = builder.build();
        let commit = document.commit(&transaction).unwrap();
        let limits = source_patch_limits(document.parse_limits(), transaction.operations().len());
        let replayed = commit
            .source_patch
            .apply(document.source(), limits)
            .unwrap();
        assert_eq!(replayed.bytes(), commit.document.render());
        commit
            .untouched_proof
            .verify(
                document.source(),
                commit.document.source(),
                commit.source_patch.replacements(),
            )
            .unwrap();

        let plan = document
            .dry_run(
                &transaction,
                EditPlanSourceId::new("fixture.properties").unwrap(),
            )
            .unwrap();
        assert_eq!(plan.source_patch(), &commit.source_patch);
        assert_eq!(plan.operations().len(), 2);
        assert_eq!(
            plan.operations()[0].operation().to_string(),
            "java-properties.edit.rename-property@1"
        );
    }

    #[test]
    fn empty_transaction_is_a_verified_identity_transition() {
        let document = reader(b"a=1\n");
        let transaction = EditTransactionBuilder::new(&document).build();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(commit.document.render(), document.render());
        assert!(commit.source_patch.replacements().is_empty());
        assert!(commit.change_set.source_edits().is_empty());
    }
}
