//! Snapshot-bound plist structural edit (RFC 0013 §11).
//!
//! Both profiles publish the same six versioned operations:
//!
//! ```text
//! plist.edit.set-value@1
//! plist.edit.insert-dict-entry@1
//! plist.edit.remove-dict-entry@1
//! plist.edit.rename-dict-key@1
//! plist.edit.insert-array-element@1
//! plist.edit.remove-array-element@1
//! ```
//!
//! Targets are addressed by root-relative [`EditPath`] steps: dictionary keys
//! with an occurrence selector for duplicate keys, and array indices. Values
//! are supplied as typed native facts ([`EditValue`]) — integer, real,
//! boolean, date, data, string, UID — never raw markup or raw bytes.
//!
//! XML edits are byte-level like RFC 0012: each operation replaces only
//! operation-owned spans of the raw source, keeps every untouched byte,
//! reparses the target, and verifies the promised plist semantics. Binary
//! edits are structural (RFC 0013 §11): `set-value` rewrites the target
//! object's marker and payload, `insert`/`remove` rewrite the owning
//! container's reference block, and the offset table and trailer are
//! regenerated whenever sizes change. Untouched objects keep their exact
//! bytes; shared references are preserved — removing a dictionary entry
//! removes that entry's reference but never an object that remains referenced
//! elsewhere, and a key rename binds a fresh key object so other dictionaries
//! sharing the old key object keep it byte-exact. All offset, size, and
//! reference arithmetic is checked before any output exists (hard gate 4).
//!
//! Operations apply sequentially against the evolving document state: an
//! index or occurrence refers to the state as of the operation's own
//! application, so a removal by index may target an element an earlier
//! insertion shifted, and a later operation may edit content an earlier
//! operation of the same transaction inserted. Every splice is recorded
//! against the base snapshot; an operation whose span lies inside a
//! replacement an earlier operation wrote folds into that replacement, and
//! commit merges the recorded base spans into maximal non-overlapping runs
//! whose replacements are the exact committed bytes, so the ChangeSet, the
//! `SourcePatch`, and the `UntouchedByteProof` are always self-consistent.
//! The target reparses after every operation, and any failure returns no
//! document and leaves the base byte-exact (atomicity, hard gate 4).
//! Conflict validation covers wrong profile/role/snapshot, incomplete bases,
//! missing or duplicate targets, stale anchors, UID insertion into an XML
//! document, unrepresentable values, limit failure, and reparse failure.
//!
//! Commit returns the new `Document`, a complete `ChangeSet`, an
//! `UntouchedByteProof`, and a replayable `SourcePatch`; dry-run returns an
//! `EditPlan` with the identical replacement set and target digest. No
//! operation writes a filesystem path.

// The edit API is published with the milestone that wires it into the
// protocol layer; until then the crate-internal module keeps the public
// surface lint-clean.
use crate::native::{
    PLIST_EPOCH_OFFSET_UNIX, PlistBoolean, PlistData, PlistDate, PlistDictEntry, PlistDocument,
    PlistInteger, PlistKey, PlistReal, PlistString, PlistStringStatus, PlistUid, PlistValue,
    PlistValueKind, PlistValueRef, RealWidth,
};
use crate::parser_binary::{BinaryFacts, PlistFormedBinary};
use crate::parser_xml::{PlistFormedXml, PlistSyntaxKind};
use crate::{
    Document, PlistEncodingSelection, PlistParseLimits, PlistProfile, PlistRepresentation,
};
use consema_core::{FailureKind, OperationKind, StableFailure};
use consema_document::{
    ChangeSet, DocumentAuthority, EditOperationSummary, EditPlan, EditPlanSourceId,
    FatalFormationFailure, FormatOperationId, FormationStatus, NodeMapping, NodeMappingStatus,
    NodeRole, SnapshotIdentity, SourceEdit, SourceEncoding, SourceLimits, SourcePatch,
    SourcePatchLimits, SourceSnapshot, UntouchedByteProof,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// One root-relative path step (RFC 0013 §11).
///
/// A `DictKey` step selects one physical dictionary association by exact key
/// content and occurrence: with duplicate keys, `occurrence` is the 0-based
/// source position among the equal keys. An `ArrayIndex` step selects one
/// array element by its 0-based position.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EditPathStep {
    /// One dictionary association with the given key; the occurrence selects
    /// the N-th physical association among duplicate keys.
    DictKey {
        /// Exact key content.
        key: PlistKey,
        /// 0-based source position among associations with this key.
        occurrence: usize,
    },
    /// One array element at the given 0-based position.
    ArrayIndex(usize),
}

/// A root-relative path to one value or container (RFC 0013 §11).
///
/// The empty path denotes the root value. A path step that meets a container
/// of the wrong kind is a role failure; a step that does not exist in the
/// current document state is a missing-target failure.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct EditPath(Vec<EditPathStep>);

impl EditPath {
    /// Root path.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Creates a path from ordered steps.
    #[must_use]
    pub const fn new(steps: Vec<EditPathStep>) -> Self {
        Self(steps)
    }

    /// Ordered path steps.
    #[must_use]
    pub fn segments(&self) -> &[EditPathStep] {
        &self.0
    }

    /// Creates a child path without modifying this path.
    #[must_use]
    pub fn child(&self, step: EditPathStep) -> Self {
        let mut steps = self.0.clone();
        steps.push(step);
        Self(steps)
    }
}

/// Dictionary entry insertion placement inside one dictionary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DictPlacement {
    /// Append before the closing `</dict>` (or wrap a self-closing `<dict/>`).
    End,
    /// Insert immediately before the entry at the given 0-based source
    /// position of the current dictionary state.
    Before(usize),
    /// Insert immediately after the entry at the given 0-based source
    /// position of the current dictionary state.
    After(usize),
}

/// One typed native plist value supplied to an edit (RFC 0013 §11).
///
/// Values are typed native facts, never raw markup or raw bytes. All seven
/// kinds are expressible in the binary representation; UID values, `Float32`
/// width facts, unpaired-surrogate strings, fractional-second dates, dates
/// outside the XML calendar's year range, non-XML characters, and
/// non-canonical NaN payloads are binary-only and fail XML edits with
/// `plist.edit.uid-in-xml@1` or `plist.edit.unrepresentable@1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditValue {
    /// Exact UTF-16 string content.
    String(PlistString),
    /// Signed 64-bit integer.
    Integer(PlistInteger),
    /// IEEE 754 real with its exact width fact.
    Real(PlistReal),
    /// Boolean.
    Boolean(PlistBoolean),
    /// Double seconds since the plist epoch.
    Date(PlistDate),
    /// Exact bytes.
    Data(PlistData),
    /// Unsigned 32-bit UID (binary profile only).
    Uid(PlistUid),
}

impl EditValue {
    /// Closed native kind of this value.
    #[must_use]
    pub const fn kind(&self) -> PlistValueKind {
        match self {
            Self::String(_) => PlistValueKind::String,
            Self::Integer(_) => PlistValueKind::Integer,
            Self::Real(_) => PlistValueKind::Real,
            Self::Boolean(_) => PlistValueKind::Boolean,
            Self::Date(_) => PlistValueKind::Date,
            Self::Data(_) => PlistValueKind::Data,
            Self::Uid(_) => PlistValueKind::Uid,
        }
    }
}

/// One snapshot-bound plist structural operation (RFC 0013 §11).
///
/// The path, key, occurrence, index, and placement of every operation refer
/// to the document state as of the operation's own application: operations
/// of one transaction apply sequentially, so a later removal by index may
/// target an element an earlier insertion shifted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Replaces the value at the path with one typed native value.
    SetValue {
        /// Path to the value to replace; the empty path is the root value.
        path: EditPath,
        /// New typed value.
        value: EditValue,
    },
    /// Inserts one dictionary association.
    InsertDictEntry {
        /// Path to the owning dictionary.
        path: EditPath,
        /// New key content.
        key: PlistKey,
        /// New entry value.
        value: EditValue,
        /// Explicit placement inside the dictionary.
        placement: DictPlacement,
    },
    /// Removes one dictionary association by key and occurrence.
    RemoveDictEntry {
        /// Path to the owning dictionary.
        path: EditPath,
        /// Key content of the association to remove.
        key: PlistKey,
        /// 0-based position among the associations with this key.
        occurrence: usize,
    },
    /// Renames one dictionary key, preserving its association value.
    RenameDictKey {
        /// Path to the owning dictionary.
        path: EditPath,
        /// Key content to rename.
        from: PlistKey,
        /// 0-based position among the associations with this key.
        occurrence: usize,
        /// New key content.
        to: PlistKey,
    },
    /// Inserts one array element before the current element at the index;
    /// an index equal to the current length appends before the closing tag.
    InsertArrayElement {
        /// Path to the owning array.
        path: EditPath,
        /// 0-based insertion position in the current array state.
        index: usize,
        /// New element value.
        value: EditValue,
    },
    /// Removes the array element at the given 0-based position of the
    /// current array state.
    RemoveArrayElement {
        /// Path to the owning array.
        path: EditPath,
        /// 0-based position of the element to remove.
        index: usize,
    },
}

/// Immutable snapshot-bound transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditTransaction {
    base: SnapshotIdentity,
    operations: Vec<EditOperation>,
}

impl EditTransaction {
    /// Base snapshot identity.
    #[must_use]
    pub const fn base_snapshot(&self) -> SnapshotIdentity {
        self.base
    }

    /// Ordered operations.
    #[must_use]
    pub fn operations(&self) -> &[EditOperation] {
        &self.operations
    }
}

/// Builds one transaction against one immutable snapshot.
#[derive(Clone, Debug)]
pub struct EditTransactionBuilder {
    base: SnapshotIdentity,
    operations: Vec<EditOperation>,
}

impl EditTransactionBuilder {
    /// Creates a builder bound to one snapshot.
    #[must_use]
    pub fn new(document: &Document) -> Self {
        Self {
            base: document.snapshot_identity(),
            operations: Vec::new(),
        }
    }

    /// Replaces one value.
    pub fn set_value(&mut self, path: EditPath, value: EditValue) -> &mut Self {
        self.operations
            .push(EditOperation::SetValue { path, value });
        self
    }

    /// Inserts one dictionary association.
    pub fn insert_dict_entry(
        &mut self,
        path: EditPath,
        key: PlistKey,
        value: EditValue,
        placement: DictPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertDictEntry {
            path,
            key,
            value,
            placement,
        });
        self
    }

    /// Removes one dictionary association.
    pub fn remove_dict_entry(
        &mut self,
        path: EditPath,
        key: PlistKey,
        occurrence: usize,
    ) -> &mut Self {
        self.operations.push(EditOperation::RemoveDictEntry {
            path,
            key,
            occurrence,
        });
        self
    }

    /// Renames one dictionary key.
    pub fn rename_dict_key(
        &mut self,
        path: EditPath,
        from: PlistKey,
        occurrence: usize,
        to: PlistKey,
    ) -> &mut Self {
        self.operations.push(EditOperation::RenameDictKey {
            path,
            from,
            occurrence,
            to,
        });
        self
    }

    /// Inserts one array element.
    pub fn insert_array_element(
        &mut self,
        path: EditPath,
        index: usize,
        value: EditValue,
    ) -> &mut Self {
        self.operations
            .push(EditOperation::InsertArrayElement { path, index, value });
        self
    }

    /// Removes one array element.
    pub fn remove_array_element(&mut self, path: EditPath, index: usize) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveArrayElement { path, index });
        self
    }

    /// Closes the transaction.
    #[must_use]
    pub fn build(self) -> EditTransaction {
        EditTransaction {
            base: self.base,
            operations: self.operations,
        }
    }
}

/// One complete committed edit.
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
    /// A path step meets a container of the wrong kind.
    WrongRole,
    /// A path step, key occurrence, index, or placement anchor does not
    /// exist in the current document state.
    TargetNotFound,
    /// The base document is not `Complete` with a provable native value
    /// graph, so no target can be edited.
    IncompleteTarget,
    /// Two operations target the same exact source position or occurrence.
    ConflictingEdits,
    /// One operation's source span contains bytes an earlier operation of
    /// the same transaction replaced. The sequential model folds operations
    /// whose spans lie inside earlier replacements and merges overlapping
    /// base spans at commit, so this variant has no emission path in this
    /// crate; it remains part of the stable failure surface.
    OverlappingOwnership,
    /// A UID value was inserted into or set on an XML document.
    UidInXml,
    /// A typed value or key cannot be expressed in the target
    /// representation; the payload names the blocking native fact.
    UnrepresentableValue(&'static str),
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// The replacement document could not be formed under the original
    /// limits.
    NewDocumentFormationFailed,
}

impl StableFailure for EditFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Edit
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::WrongSnapshot => FailureKind::TargetMismatch,
            Self::WrongRole | Self::TargetNotFound | Self::IncompleteTarget => {
                FailureKind::NotApplicable
            }
            Self::ConflictingEdits
            | Self::OverlappingOwnership
            | Self::UidInXml
            | Self::UnrepresentableValue(_) => FailureKind::InvalidInput,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
            Self::IncompleteTarget => "core.edit.incomplete-target@1",
            Self::ConflictingEdits | Self::OverlappingOwnership => "core.edit.conflicting-edits@1",
            Self::UidInXml => "plist.edit.uid-in-xml@1",
            Self::UnrepresentableValue(_) => "plist.edit.unrepresentable@1",
            Self::ResourceLimit(_) => "core.edit.resource-limit@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

impl Document {
    /// Atomically commits structural operations. On failure `self` remains
    /// unchanged.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        self.commit_impl(transaction, self.limits())
    }

    /// Fully validates and plans a transaction without returning a new
    /// Document.
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

    /// Commits under explicit limits (the test and limit paths share one
    /// implementation).
    fn commit_impl(
        &self,
        transaction: &EditTransaction,
        limits: PlistParseLimits,
    ) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if self.status() != FormationStatus::Complete || self.document().is_none() {
            return Err(EditFailure::IncompleteTarget);
        }
        if transaction.operations.len() > limits.max_report_events {
            return Err(EditFailure::ResourceLimit("report-events"));
        }
        match self.representation() {
            PlistRepresentation::Xml => self.commit_xml(transaction, limits),
            PlistRepresentation::Binary => self.commit_binary(transaction, limits),
        }
    }

    /// XML byte-level commit: each operation resolves against the current
    /// reparse, replaces only operation-owned spans of the raw source, and
    /// reparses after every operation.
    fn commit_xml(
        &self,
        transaction: &EditTransaction,
        limits: PlistParseLimits,
    ) -> Result<EditCommit, EditFailure> {
        // Reparse under the exact request the base was formed with, so the
        // committed snapshot reproduces the base encoding facts (the patch
        // and proof machinery requires identical facts).
        let selection = match self.source().encoding_facts().caller_override() {
            Some(encoding) => PlistEncodingSelection::Explicit(encoding),
            None => PlistEncodingSelection::ProfileDefault,
        };
        let mut bytes = self.render().to_vec();
        let mut edits: Vec<AppliedEdit> = Vec::new();
        for operation in &transaction.operations {
            let formed = crate::parse_xml(Arc::from(bytes.clone()), selection, limits)
                .map_err(|fatal| map_fatal(&fatal))?;
            if formed.status() != FormationStatus::Complete || formed.document().is_none() {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            let layout = xml_layout(&formed)?;
            let encoding = formed.source().encoding_facts().selected();
            let splices = prepare_xml_operation(&formed, &layout, operation, encoding)?;
            apply_step(&mut edits, &mut bytes, limits, &splices)?;
        }
        let final_document =
            Document::parse(Arc::from(bytes), PlistProfile::XmlV1, selection, limits)
                .map_err(|fatal| map_fatal(&fatal))?;
        if final_document.status() != FormationStatus::Complete {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        build_commit(self, transaction, final_document, edits)
    }

    /// Binary structural commit: each operation rewrites the owning object
    /// bytes, appends fresh objects for new values, regenerates the offset
    /// table and trailer, and reparses after every operation.
    fn commit_binary(
        &self,
        transaction: &EditTransaction,
        limits: PlistParseLimits,
    ) -> Result<EditCommit, EditFailure> {
        let mut bytes = self.render().to_vec();
        let mut edits: Vec<AppliedEdit> = Vec::new();
        for operation in &transaction.operations {
            let formed = crate::parse_binary(
                Arc::from(bytes.clone()),
                PlistEncodingSelection::ProfileDefault,
                limits,
            )
            .map_err(|fatal| map_fatal(&fatal))?;
            if formed.status() != FormationStatus::Complete || formed.document().is_none() {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            let splices = binary_step(&formed, operation, limits)?;
            apply_step(&mut edits, &mut bytes, limits, &splices)?;
        }
        let final_document = Document::parse(
            Arc::from(bytes),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            limits,
        )
        .map_err(|fatal| map_fatal(&fatal))?;
        if final_document.status() != FormationStatus::Complete {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        build_commit(self, transaction, final_document, edits)
    }
}

/// Applies one step's splices: validates the target length against the
/// source bound first (hard gate 4), records every splice against the base
/// coordinates, then builds the new bytes in one pass.
fn apply_step(
    edits: &mut Vec<AppliedEdit>,
    bytes: &mut Vec<u8>,
    limits: PlistParseLimits,
    splices: &[AppliedEdit],
) -> Result<(), EditFailure> {
    let target_len = splices.iter().try_fold(bytes.len(), |length, splice| {
        length
            .checked_sub(splice.pre_len)
            .and_then(|length| length.checked_add(splice.replacement.len()))
            .ok_or(EditFailure::ResourceLimit("target-bytes"))
    })?;
    if target_len > limits.common.max_source_bytes {
        return Err(EditFailure::ResourceLimit("target-bytes"));
    }
    for splice in splices {
        record_edit(
            edits,
            splice.pre_start,
            splice.pre_len,
            splice.replacement.to_vec(),
            splice.structural,
        )?;
    }
    *bytes = apply_splices(bytes, splices)?;
    Ok(())
}

/// One applied raw-byte splice, recorded for base-coordinate translation.
#[derive(Clone, Debug)]
struct AppliedEdit {
    /// Start of the replaced span in the state immediately before this
    /// splice was applied.
    pre_start: usize,
    /// Length of the replaced span in that pre-state.
    pre_len: usize,
    /// Replacement bytes.
    replacement: Arc<[u8]>,
    /// Implementation-owned structural region (binary offset table and
    /// trailer): the fold scan never merges operation content into one.
    structural: bool,
}

/// Maps one position from the final state back to the base snapshot through
/// the applied edits in reverse application order; a position inside an
/// earlier replacement is an ownership overlap.
fn unmap_in(edits: &[AppliedEdit], mut pos: usize) -> Result<usize, EditFailure> {
    for (index, edit) in edits.iter().enumerate().rev() {
        // A position at or before the replacement start is the untouched
        // boundary and maps unchanged.
        if pos <= edit.pre_start {
            continue;
        }
        if pos < edit.pre_start + edit.replacement.len() {
            // A position inside an earlier replacement maps through that
            // replacement's base span; the enclosing operation owns the whole
            // span, so the exact sub-byte mapping is the linear one.
            let base_start = unmap_in(&edits[..index], edit.pre_start)?;
            return Ok(base_start + (pos - edit.pre_start));
        }
        pos = pos - edit.replacement.len() + edit.pre_len;
    }
    Ok(pos)
}

/// Maps one position from one pre-state to the final state through the
/// applied edits in application order.
fn map_in(edits: &[AppliedEdit], mut pos: usize) -> Result<usize, EditFailure> {
    for edit in edits {
        if pos <= edit.pre_start {
            continue;
        }
        if pos < edit.pre_start + edit.pre_len {
            return Err(EditFailure::OverlappingOwnership);
        }
        pos = pos + edit.replacement.len() - edit.pre_len;
    }
    Ok(pos)
}

/// Records one splice and rejects two insertions that map to the same base
/// position (a duplicate target).
///
/// An operation whose span lies inside a replacement an earlier operation of
/// this transaction wrote (including the exact boundaries) folds into that
/// replacement: the sequential result is one combined splice. This is how a
/// later operation edits content an earlier insertion created.
fn record_edit(
    edits: &mut Vec<AppliedEdit>,
    pre_start: usize,
    pre_len: usize,
    replacement: Vec<u8>,
    structural: bool,
) -> Result<(), EditFailure> {
    if pre_len == 0 && replacement.is_empty() {
        return Ok(());
    }
    for index in (0..edits.len()).rev() {
        if edits[index].structural {
            continue;
        }
        let region_start = map_in(&edits[index + 1..], edits[index].pre_start)?;
        let region_end = region_start + edits[index].replacement.len();
        // A zero-width insertion exactly at the region end (for example the
        // binary append at the object-area end) is not operation content of
        // the region's owner and is recorded on its own.
        if pre_start >= region_start
            && pre_start + pre_len <= region_end
            && !(pre_len == 0 && pre_start == region_end)
        {
            let offset = pre_start - region_start;
            let mut merged = Vec::with_capacity(edits[index].replacement.len() + replacement.len());
            merged.extend_from_slice(&edits[index].replacement[..offset]);
            merged.extend_from_slice(&replacement);
            merged.extend_from_slice(&edits[index].replacement[offset + pre_len..]);
            let delta = merged.len() as isize - edits[index].replacement.len() as isize;
            let target_start = edits[index].pre_start;
            // Only the later records whose own spans lie at or after the fold
            // target's span move in the folded coordinate system; records
            // before it keep their exact positions.
            for later in edits.iter_mut().skip(index + 1) {
                if later.pre_start > target_start {
                    later.pre_start = shifted(later.pre_start, delta)?;
                }
            }
            edits[index].replacement = Arc::from(merged);
            return Ok(());
        }
    }
    let base_start = unmap_in(edits, pre_start)?;
    let base_end = unmap_in(edits, pre_start + pre_len)?;
    for (index, previous) in edits.iter().enumerate() {
        if previous.pre_len == 0 && base_start == base_end {
            let previous_base = unmap_in(&edits[..index], previous.pre_start)?;
            if previous_base == base_start {
                return Err(EditFailure::ConflictingEdits);
            }
        }
    }
    edits.push(AppliedEdit {
        pre_start,
        pre_len,
        replacement: Arc::from(replacement),
        structural,
    });
    debug_assert!(base_end >= base_start);
    Ok(())
}

/// Builds the new bytes by applying the splices sequentially against a
/// working buffer; every splice's pre-span is expressed in its own pre-state,
/// so each application position is exact in the evolving bytes.
fn apply_splices(bytes: &[u8], splices: &[AppliedEdit]) -> Result<Vec<u8>, EditFailure> {
    let mut working = bytes.to_vec();
    for splice in splices {
        let end = splice
            .pre_start
            .checked_add(splice.pre_len)
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        if end > working.len() {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        working.splice(splice.pre_start..end, splice.replacement.iter().copied());
    }
    Ok(working)
}

/// Resolves one path against one native arena; the empty path is the root.
fn resolve_path(document: &PlistDocument, path: &EditPath) -> Result<PlistValueRef, EditFailure> {
    let mut current = document.root();
    for step in path.segments() {
        let node = document.get(current).ok_or(EditFailure::TargetNotFound)?;
        match step {
            EditPathStep::DictKey { key, occurrence } => {
                let dict = node.as_dict().ok_or(EditFailure::WrongRole)?;
                let position = nth_key_position(dict.entries(), key, *occurrence)?;
                current = dict.entries()[position].value();
            }
            EditPathStep::ArrayIndex(index) => {
                let array = node.as_array().ok_or(EditFailure::WrongRole)?;
                if *index >= array.elements().len() {
                    return Err(EditFailure::TargetNotFound);
                }
                current = array.elements()[*index];
            }
        }
    }
    Ok(current)
}

/// Source position of the occurrence-th association with the given key.
fn nth_key_position(
    entries: &[PlistDictEntry],
    key: &PlistKey,
    occurrence: usize,
) -> Result<usize, EditFailure> {
    let mut seen = 0;
    for (position, entry) in entries.iter().enumerate() {
        if entry.key() == key {
            if seen == occurrence {
                return Ok(position);
            }
            seen += 1;
        }
    }
    Err(EditFailure::TargetNotFound)
}

// ---------------------------------------------------------------------------
// XML byte-level layout and operations
// ---------------------------------------------------------------------------

/// One value element's byte facts, indexed by native arena ordinal (the XML
/// parser assigns arena ordinals in close-tag order, so the ordinal of the
/// k-th closed value element is `k`).
#[derive(Clone, Debug)]
struct XmlNodeLayout {
    /// Full element span `[open tag start, close tag end)`.
    span: (usize, usize),
    /// Whether the element is written as one self-closing tag.
    self_closing: bool,
    /// End of the open tag (containers; the first child's removal start).
    open_end: usize,
    /// Start of the close tag (containers; the `End` insertion point).
    close_start: usize,
    /// Child value ordinals: dictionary entry values and array elements.
    children: Vec<usize>,
    /// Per-entry key element facts of a dictionary.
    key_text: Vec<XmlKeyLayout>,
    /// Per-entry full span start including leading whitespace.
    entry_starts: Vec<usize>,
}

/// One key element's byte facts of a dictionary entry.
#[derive(Clone, Debug)]
struct XmlKeyLayout {
    /// Text span between `<key>` and `</key>`; for a self-closing `<key/>`
    /// this is the whole tag.
    text: (usize, usize),
    /// Full key element span.
    element: (usize, usize),
    /// Whether the key element is one self-closing tag.
    self_closing: bool,
}

/// Open stack frame of the layout walk.
struct XmlFrame {
    kind: PlistSyntaxKind,
    open_start: usize,
    open_end: usize,
    children: Vec<usize>,
    key_text: Vec<XmlKeyLayout>,
    entry_starts: Vec<usize>,
    prev_value_end: usize,
    pending_key: Option<XmlKeyLayout>,
}

/// Walks the lossless pieces and assigns every value element its byte span
/// in arena ordinal order.
fn xml_layout(formed: &PlistFormedXml) -> Result<Vec<XmlNodeLayout>, EditFailure> {
    let source = formed.source();
    let pieces = formed.lossless_structural_index().pieces();
    let kinds = formed.lossless_syntax_kinds();
    let mut layouts: Vec<XmlNodeLayout> = Vec::new();
    let mut stack: Vec<XmlFrame> = Vec::new();
    let mut pending_key_open: Option<(usize, usize)> = None;
    for (piece, kind) in pieces.iter().zip(kinds.iter().copied()) {
        let start = piece.span().start_byte();
        let end = piece.span().end_byte();
        match kind {
            PlistSyntaxKind::KeyOpen => {
                if piece_text(source, start, end)? == ">" {
                    // The tag-closing `>` continuation of the same open tag.
                    if let Some((open_start, _)) = pending_key_open.take() {
                        pending_key_open = Some((open_start, end));
                    }
                } else {
                    pending_key_open = Some((start, end));
                }
            }
            PlistSyntaxKind::KeyClose => {
                let key = if piece_text(source, start, end)?.ends_with("/>") {
                    // A self-closing `<key/>`: the whole tag is replaced on
                    // rename.
                    match pending_key_open.take() {
                        Some((open_start, _)) => XmlKeyLayout {
                            text: (open_start, end),
                            element: (open_start, end),
                            self_closing: true,
                        },
                        None => XmlKeyLayout {
                            text: (start, end),
                            element: (start, end),
                            self_closing: true,
                        },
                    }
                } else {
                    match pending_key_open.take() {
                        Some((open_start, open_end)) => XmlKeyLayout {
                            text: (open_end, start),
                            element: (open_start, end),
                            self_closing: false,
                        },
                        None => XmlKeyLayout {
                            text: (start, end),
                            element: (start, end),
                            self_closing: true,
                        },
                    }
                };
                if let Some(frame) = stack.last_mut() {
                    frame.pending_key = Some(key);
                }
            }
            PlistSyntaxKind::DictOpen
            | PlistSyntaxKind::ArrayOpen
            | PlistSyntaxKind::StringOpen
            | PlistSyntaxKind::IntegerOpen
            | PlistSyntaxKind::RealOpen
            | PlistSyntaxKind::DateOpen
            | PlistSyntaxKind::DataOpen => {
                if piece_text(source, start, end)? == ">" {
                    // The tag-closing `>` continuation of the open tag on the
                    // stack top: the open tag ends here.
                    if let Some(frame) = stack.last_mut() {
                        frame.open_end = end;
                        frame.prev_value_end = end;
                    }
                } else {
                    stack.push(XmlFrame {
                        kind,
                        open_start: start,
                        open_end: end,
                        children: Vec::new(),
                        key_text: Vec::new(),
                        entry_starts: Vec::new(),
                        prev_value_end: end,
                        pending_key: None,
                    });
                }
            }
            PlistSyntaxKind::DictClose
            | PlistSyntaxKind::ArrayClose
            | PlistSyntaxKind::StringClose
            | PlistSyntaxKind::IntegerClose
            | PlistSyntaxKind::RealClose
            | PlistSyntaxKind::DateClose
            | PlistSyntaxKind::DataClose => {
                if piece_text(source, start, end)?.ends_with("/>") {
                    // The `/>` of a self-closing tag: the name piece opened
                    // the frame and this piece closes it.
                    let frame = stack.pop().ok_or(EditFailure::NewDocumentFormationFailed)?;
                    finalize_xml_frame(&mut stack, &mut layouts, frame, end, end, true);
                } else if stack
                    .last()
                    .is_some_and(|frame| frame.kind == open_kind_for(kind))
                {
                    let frame = stack.pop().expect("matching open frame");
                    finalize_xml_frame(&mut stack, &mut layouts, frame, start, end, false);
                } else {
                    return Err(EditFailure::NewDocumentFormationFailed);
                }
            }
            PlistSyntaxKind::True | PlistSyntaxKind::False => {
                let text = piece_text(source, start, end)?;
                if text == ">" {
                    // The tag-closing `>` continuation of the open tag on the
                    // stack top.
                    if let Some(frame) = stack.last_mut() {
                        frame.open_end = end;
                        frame.prev_value_end = end;
                    }
                } else if text.starts_with("</") {
                    let frame = stack.pop().ok_or(EditFailure::NewDocumentFormationFailed)?;
                    finalize_xml_frame(&mut stack, &mut layouts, frame, start, end, false);
                } else if text.ends_with("/>") {
                    // The `/>` of a self-closing tag closes the name-piece
                    // frame.
                    let frame = stack.pop().ok_or(EditFailure::NewDocumentFormationFailed)?;
                    finalize_xml_frame(&mut stack, &mut layouts, frame, end, end, true);
                } else {
                    stack.push(XmlFrame {
                        kind,
                        open_start: start,
                        open_end: end,
                        children: Vec::new(),
                        key_text: Vec::new(),
                        entry_starts: Vec::new(),
                        prev_value_end: end,
                        pending_key: None,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(layouts)
}

/// The open-kind piece that pairs with one close-kind piece.
const fn open_kind_for(close: PlistSyntaxKind) -> PlistSyntaxKind {
    match close {
        PlistSyntaxKind::DictClose => PlistSyntaxKind::DictOpen,
        PlistSyntaxKind::ArrayClose => PlistSyntaxKind::ArrayOpen,
        PlistSyntaxKind::StringClose => PlistSyntaxKind::StringOpen,
        PlistSyntaxKind::IntegerClose => PlistSyntaxKind::IntegerOpen,
        PlistSyntaxKind::RealClose => PlistSyntaxKind::RealOpen,
        PlistSyntaxKind::DateClose => PlistSyntaxKind::DateOpen,
        PlistSyntaxKind::DataClose => PlistSyntaxKind::DataOpen,
        _ => PlistSyntaxKind::ErrorRegion,
    }
}

/// Assigns the next arena ordinal to one closed frame and updates its parent
/// dictionary's pending entry.
fn finalize_xml_frame(
    stack: &mut [XmlFrame],
    layouts: &mut Vec<XmlNodeLayout>,
    frame: XmlFrame,
    close_start: usize,
    close_end: usize,
    self_closing: bool,
) {
    let ordinal = layouts.len();
    if let Some(parent) = stack.last_mut() {
        if parent.kind == PlistSyntaxKind::DictOpen {
            if let Some(key) = parent.pending_key.take() {
                parent.key_text.push(key);
                parent.entry_starts.push(parent.prev_value_end);
            }
        }
        parent.children.push(ordinal);
        parent.prev_value_end = close_end;
    }
    layouts.push(XmlNodeLayout {
        span: (frame.open_start, close_end),
        self_closing,
        open_end: frame.open_end,
        close_start,
        children: frame.children,
        key_text: frame.key_text,
        entry_starts: frame.entry_starts,
    });
}

/// Decoded text of one piece span.
fn piece_text(source: &SourceSnapshot, start: usize, end: usize) -> Result<&str, EditFailure> {
    let text = source
        .decoded_text()
        .ok_or(EditFailure::NewDocumentFormationFailed)?;
    let start_decoded = source
        .decoded_position(start)
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?
        .decoded_utf8_byte;
    let end_decoded = source
        .decoded_position(end)
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?
        .decoded_utf8_byte;
    Ok(&text[start_decoded..end_decoded])
}

/// Prepares one XML operation's splices against the current formed state.
fn prepare_xml_operation(
    formed: &PlistFormedXml,
    layout: &[XmlNodeLayout],
    operation: &EditOperation,
    encoding: SourceEncoding,
) -> Result<Vec<AppliedEdit>, EditFailure> {
    let document = formed
        .document()
        .ok_or(EditFailure::NewDocumentFormationFailed)?;
    match operation {
        EditOperation::SetValue { path, value } => {
            check_xml_value(value)?;
            let node = resolve_path(document, path)?;
            let node_layout = &layout[node.index()];
            Ok(vec![splice(
                node_layout.span.0,
                node_layout.span.1 - node_layout.span.0,
                encode_xml_element(value, encoding)?,
            )])
        }
        EditOperation::InsertDictEntry {
            path,
            key,
            value,
            placement,
        } => {
            check_xml_key(key)?;
            check_xml_value(value)?;
            let dict = resolve_path(document, path)?;
            if document.get(dict).and_then(PlistValue::as_dict).is_none() {
                return Err(EditFailure::WrongRole);
            }
            let dict_layout = &layout[dict.index()];
            let count = dict_layout.children.len();
            let (insert_at, old_len, markup) = match placement {
                DictPlacement::End => {
                    if dict_layout.self_closing {
                        let mut markup = b"<dict>".to_vec();
                        markup.extend(entry_markup(key, value, encoding)?);
                        markup.extend_from_slice(b"</dict>");
                        (
                            dict_layout.span.0,
                            dict_layout.span.1 - dict_layout.span.0,
                            markup,
                        )
                    } else {
                        (
                            dict_layout.close_start,
                            0,
                            entry_markup(key, value, encoding)?,
                        )
                    }
                }
                DictPlacement::Before(position) => {
                    if *position >= count {
                        return Err(EditFailure::TargetNotFound);
                    }
                    (
                        dict_layout.entry_starts[*position],
                        0,
                        entry_markup(key, value, encoding)?,
                    )
                }
                DictPlacement::After(position) => {
                    if *position >= count {
                        return Err(EditFailure::TargetNotFound);
                    }
                    (
                        layout[dict_layout.children[*position]].span.1,
                        0,
                        entry_markup(key, value, encoding)?,
                    )
                }
            };
            Ok(vec![splice(insert_at, old_len, markup)])
        }
        EditOperation::RemoveDictEntry {
            path,
            key,
            occurrence,
        } => {
            let dict = resolve_path(document, path)?;
            let dict_layout = &layout[dict.index()];
            let entries = document
                .get(dict)
                .and_then(PlistValue::as_dict)
                .ok_or(EditFailure::WrongRole)?
                .entries();
            let position = nth_key_position(entries, key, *occurrence)?;
            let span_start = dict_layout.entry_starts[position];
            let span_end = layout[dict_layout.children[position]].span.1;
            Ok(vec![splice(span_start, span_end - span_start, Vec::new())])
        }
        EditOperation::RenameDictKey {
            path,
            from,
            occurrence,
            to,
        } => {
            check_xml_key(to)?;
            let dict = resolve_path(document, path)?;
            let dict_layout = &layout[dict.index()];
            let entries = document
                .get(dict)
                .and_then(PlistValue::as_dict)
                .ok_or(EditFailure::WrongRole)?
                .entries();
            let position = nth_key_position(entries, from, *occurrence)?;
            let key_layout = &dict_layout.key_text[position];
            let (old_start, old_len, replacement) = if key_layout.self_closing {
                (
                    key_layout.element.0,
                    key_layout.element.1 - key_layout.element.0,
                    encode_xml_key(to, encoding)?,
                )
            } else {
                (
                    key_layout.text.0,
                    key_layout.text.1 - key_layout.text.0,
                    encode_key_text(to, encoding)?,
                )
            };
            Ok(vec![splice(old_start, old_len, replacement)])
        }
        EditOperation::InsertArrayElement { path, index, value } => {
            check_xml_value(value)?;
            let array = resolve_path(document, path)?;
            if document.get(array).and_then(PlistValue::as_array).is_none() {
                return Err(EditFailure::WrongRole);
            }
            let array_layout = &layout[array.index()];
            let count = array_layout.children.len();
            if *index > count {
                return Err(EditFailure::TargetNotFound);
            }
            let markup = encode_xml_element(value, encoding)?;
            let (insert_at, old_len, replacement) = if *index == count {
                if array_layout.self_closing {
                    let mut replacement = b"<array>".to_vec();
                    replacement.extend(markup);
                    replacement.extend_from_slice(b"</array>");
                    (
                        array_layout.span.0,
                        array_layout.span.1 - array_layout.span.0,
                        replacement,
                    )
                } else {
                    (array_layout.close_start, 0, markup)
                }
            } else if *index == 0 {
                (array_layout.open_end, 0, markup)
            } else {
                (layout[array_layout.children[*index]].span.0, 0, markup)
            };
            Ok(vec![splice(insert_at, old_len, replacement)])
        }
        EditOperation::RemoveArrayElement { path, index } => {
            let array = resolve_path(document, path)?;
            if document.get(array).and_then(PlistValue::as_array).is_none() {
                return Err(EditFailure::WrongRole);
            }
            let array_layout = &layout[array.index()];
            let count = array_layout.children.len();
            if *index >= count {
                return Err(EditFailure::TargetNotFound);
            }
            let (span_start, span_end) = if *index == 0 {
                (
                    array_layout.open_end,
                    layout[array_layout.children[0]].span.1,
                )
            } else {
                (
                    layout[array_layout.children[*index - 1]].span.1,
                    layout[array_layout.children[*index]].span.1,
                )
            };
            Ok(vec![splice(span_start, span_end - span_start, Vec::new())])
        }
    }
}

/// One zero-width or full replacement splice.
fn splice(pre_start: usize, pre_len: usize, replacement: Vec<u8>) -> AppliedEdit {
    AppliedEdit {
        pre_start,
        pre_len,
        replacement: Arc::from(replacement),
        structural: false,
    }
}

/// One implementation-owned structural splice (binary offset table and
/// trailer).
fn structural_splice(pre_start: usize, pre_len: usize, replacement: Vec<u8>) -> AppliedEdit {
    AppliedEdit {
        pre_start,
        pre_len,
        replacement: Arc::from(replacement),
        structural: true,
    }
}

/// `<key>..</key>` plus one value element.
fn entry_markup(
    key: &PlistKey,
    value: &EditValue,
    encoding: SourceEncoding,
) -> Result<Vec<u8>, EditFailure> {
    let mut markup = encode_xml_key(key, encoding)?;
    markup.extend(encode_xml_element(value, encoding)?);
    Ok(markup)
}

/// One value element written as markup.
fn encode_xml_element(value: &EditValue, encoding: SourceEncoding) -> Result<Vec<u8>, EditFailure> {
    let mut text = String::new();
    match value {
        EditValue::String(string) => {
            let unicode = string
                .to_unicode()
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            text.push_str("<string>");
            escape_xml_text(&mut text, &unicode);
            text.push_str("</string>");
        }
        EditValue::Integer(integer) => {
            text.push_str("<integer>");
            text.push_str(&integer.value().to_string());
            text.push_str("</integer>");
        }
        EditValue::Real(real) => {
            text.push_str("<real>");
            text.push_str(&render_real(*real));
            text.push_str("</real>");
        }
        EditValue::Boolean(boolean) => {
            text.push_str(if boolean.value() {
                "<true/>"
            } else {
                "<false/>"
            });
        }
        EditValue::Date(date) => {
            let (year, month, day, hour, minute, second) = whole_second_date(date.seconds())
                .map_err(|error| {
                    EditFailure::UnrepresentableValue(match error {
                        DateRangeError::FractionalSeconds => "fractional-seconds",
                        DateRangeError::YearOutOfRange => "date-year-range",
                    })
                })?;
            text.push_str("<date>");
            text.push_str(&render_date(year, month, day, hour, minute, second));
            text.push_str("</date>");
        }
        EditValue::Data(data) => {
            text.push_str("<data>");
            text.push_str(&encode_base64(data.bytes()));
            text.push_str("</data>");
        }
        EditValue::Uid(_) => return Err(EditFailure::UidInXml),
    }
    let mut bytes = Vec::new();
    encode_text(&mut bytes, &text, encoding);
    Ok(bytes)
}

/// One key element written as markup.
fn encode_xml_key(key: &PlistKey, encoding: SourceEncoding) -> Result<Vec<u8>, EditFailure> {
    let unicode = key
        .to_unicode()
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
    let mut text = String::from("<key>");
    escape_xml_text(&mut text, &unicode);
    text.push_str("</key>");
    let mut bytes = Vec::new();
    encode_text(&mut bytes, &text, encoding);
    Ok(bytes)
}

/// Escaped key content only.
fn encode_key_text(key: &PlistKey, encoding: SourceEncoding) -> Result<Vec<u8>, EditFailure> {
    let unicode = key
        .to_unicode()
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
    let mut escaped = String::new();
    escape_xml_text(&mut escaped, &unicode);
    let mut bytes = Vec::new();
    encode_text(&mut bytes, &escaped, encoding);
    Ok(bytes)
}

/// Appends one decoded string under the source encoding.
fn encode_text(out: &mut Vec<u8>, text: &str, encoding: SourceEncoding) {
    match encoding {
        SourceEncoding::Utf16Le => {
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
        }
        SourceEncoding::Utf16Be => {
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
        }
        _ => out.extend_from_slice(text.as_bytes()),
    }
}

/// Validates one typed value for the XML representation.
fn check_xml_value(value: &EditValue) -> Result<(), EditFailure> {
    match value {
        EditValue::String(string) => check_xml_string(string),
        EditValue::Real(real) => {
            if real.width() == RealWidth::Float32 {
                return Err(EditFailure::UnrepresentableValue("float32-width"));
            }
            if !real_expressible(*real) {
                return Err(EditFailure::UnrepresentableValue("real-nan-payload"));
            }
            Ok(())
        }
        EditValue::Date(date) => match whole_second_date(date.seconds()) {
            Ok(_) => Ok(()),
            Err(DateRangeError::FractionalSeconds) => {
                Err(EditFailure::UnrepresentableValue("fractional-seconds"))
            }
            Err(DateRangeError::YearOutOfRange) => {
                Err(EditFailure::UnrepresentableValue("date-year-range"))
            }
        },
        EditValue::Uid(_) => Err(EditFailure::UidInXml),
        _ => Ok(()),
    }
}

/// Validates one key content for the XML representation.
fn check_xml_key(key: &PlistKey) -> Result<(), EditFailure> {
    if key.status() == PlistStringStatus::UnpairedSurrogate {
        return Err(EditFailure::UnrepresentableValue("unpaired-surrogate"));
    }
    if !is_xml_text(key.code_units()) {
        return Err(EditFailure::UnrepresentableValue("non-xml-character"));
    }
    Ok(())
}

/// Validates one string content for the XML representation.
fn check_xml_string(string: &PlistString) -> Result<(), EditFailure> {
    if string.status() == PlistStringStatus::UnpairedSurrogate {
        return Err(EditFailure::UnrepresentableValue("unpaired-surrogate"));
    }
    if !is_xml_text(string.code_units()) {
        return Err(EditFailure::UnrepresentableValue("non-xml-character"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary structural operations
// ---------------------------------------------------------------------------

/// One binary operation's structural changes.
struct BinaryPlan {
    /// Final flattened reference lists per object: for a dictionary the key
    /// references followed by the value references, for an array the element
    /// references.
    refs: Vec<Vec<usize>>,
    /// Fresh object bytes appended after the existing object table, in
    /// object-index order.
    appended: Vec<Vec<u8>>,
    /// Direct scalar rewrites (set-value): object index to new object bytes.
    scalar_replaces: BTreeMap<usize, Vec<u8>>,
    /// Container objects whose reference blocks the operation rewrites.
    container_touched: Vec<usize>,
}

/// Computes one binary operation's structural changes against the current
/// formed state. All arithmetic is checked before any splice exists.
fn binary_step(
    formed: &PlistFormedBinary,
    operation: &EditOperation,
    limits: PlistParseLimits,
) -> Result<Vec<AppliedEdit>, EditFailure> {
    let document = formed
        .document()
        .ok_or(EditFailure::NewDocumentFormationFailed)?;
    let facts = formed.facts();
    let plan = binary_plan(document, facts, operation)?;
    let node_count = document.node_count();
    let new_object_count = node_count
        .checked_add(plan.appended.len())
        .ok_or(EditFailure::ResourceLimit("object-count"))?;
    if new_object_count > limits.max_object_count {
        return Err(EditFailure::ResourceLimit("object-count"));
    }
    let current_ref_size = usize::from(facts.trailer().object_ref_size());
    let new_ref_size = ref_width_for(new_object_count);
    if new_ref_size > limits.max_object_ref_size {
        return Err(EditFailure::ResourceLimit("object-ref-size"));
    }
    let mut replacements: BTreeMap<usize, Vec<u8>> = plan.scalar_replaces;
    for &index in &plan.container_touched {
        replacements.insert(
            index,
            encode_container(
                &plan.refs[index],
                container_is_dict(document, index),
                new_ref_size,
            )?,
        );
    }
    if new_ref_size != current_ref_size {
        for index in 0..node_count {
            if container_is_dict(document, index)
                || matches!(
                    document.get(PlistValueRef::from_index(index)),
                    Some(PlistValue::Array(_))
                )
            {
                replacements.insert(
                    index,
                    encode_container(
                        &plan.refs[index],
                        container_is_dict(document, index),
                        new_ref_size,
                    )?,
                );
            }
        }
    }

    // Object spans and lengths in the current state. Every splice's pre-span
    // is expressed in its own pre-state: each later splice position shifts by
    // the length deltas of the earlier splices of this step.
    let mut new_lens: Vec<usize> = (0..node_count)
        .map(|index| facts.objects()[index].span().len())
        .collect();
    let mut splices: Vec<AppliedEdit> = Vec::new();
    let mut delta = 0_isize;
    for (index, bytes) in &replacements {
        let span = facts.objects()[*index].span();
        new_lens[*index] = bytes.len();
        let pre_start = shifted(span.start_byte(), delta)?;
        splices.push(splice(pre_start, span.len(), bytes.clone()));
        delta = add_length_delta(delta, bytes.len(), span.len())?;
    }
    // Fresh objects append after the last object.
    let object_area_end = usize::try_from(facts.trailer().offset_table_offset())
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
    let mut appended_bytes = Vec::new();
    for bytes in &plan.appended {
        appended_bytes.extend_from_slice(bytes);
    }
    if !appended_bytes.is_empty() {
        let pre_start = shifted(object_area_end, delta)?;
        let appended_len = appended_bytes.len();
        splices.push(splice(pre_start, 0, appended_bytes));
        delta = add_length_delta(delta, appended_len, 0)?;
    }

    // New object offsets and layout.
    let mut new_offsets: Vec<usize> = Vec::with_capacity(new_object_count);
    let mut cursor = 8_usize;
    for length in &new_lens {
        new_offsets.push(cursor);
        cursor = cursor
            .checked_add(*length)
            .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
    }
    for bytes in &plan.appended {
        new_offsets.push(cursor);
        cursor = cursor
            .checked_add(bytes.len())
            .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
    }
    let new_table_offset = cursor;

    // Offset table.
    let old_table_start = shifted(object_area_end, delta)?;
    let old_table_bytes = usize::try_from(facts.trailer().num_objects())
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?
        .checked_mul(usize::from(facts.trailer().offset_int_size()))
        .ok_or(EditFailure::ResourceLimit("offset-table-bytes"))?;
    let offset_int_size = ref_width_for(new_table_offset);
    if offset_int_size > limits.max_offset_int_size {
        return Err(EditFailure::ResourceLimit("offset-int-size"));
    }
    let table_bytes = new_object_count
        .checked_mul(offset_int_size)
        .ok_or(EditFailure::ResourceLimit("offset-table-bytes"))?;
    if table_bytes > limits.max_offset_table_bytes {
        return Err(EditFailure::ResourceLimit("offset-table-bytes"));
    }
    let target_len = new_table_offset
        .checked_add(table_bytes)
        .and_then(|length| length.checked_add(32))
        .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
    if target_len > limits.common.max_source_bytes {
        return Err(EditFailure::ResourceLimit("target-bytes"));
    }
    let mut table = Vec::with_capacity(table_bytes);
    for offset in new_offsets {
        write_be(&mut table, offset as u64, offset_int_size)?;
    }
    let table_len = table.len();
    splices.push(structural_splice(old_table_start, old_table_bytes, table));
    delta = add_length_delta(delta, table_len, old_table_bytes)?;

    // Trailer: 5 unused bytes, sortVersion 0, offsetIntSize, objectRefSize,
    // numObjects, topObject, offsetTableOffset (RFC 0013 §5.10).
    let old_len = formed.render().len();
    let mut trailer = Vec::with_capacity(32);
    trailer.extend_from_slice(&[0, 0, 0, 0, 0]);
    trailer.push(0); // sortVersion
    trailer.push(offset_int_size as u8);
    trailer.push(new_ref_size as u8);
    write_be(&mut trailer, new_object_count as u64, 8)?;
    write_be(&mut trailer, document.root().index() as u64, 8)?;
    write_be(&mut trailer, new_table_offset as u64, 8)?;
    let trailer_start = shifted(old_len, delta)?
        .checked_sub(32)
        .ok_or(EditFailure::NewDocumentFormationFailed)?;
    splices.push(structural_splice(trailer_start, 32, trailer));
    Ok(splices)
}

/// Shifts one base position by the accumulated length delta of earlier
/// splices.
fn shifted(base: usize, delta: isize) -> Result<usize, EditFailure> {
    let magnitude = delta.unsigned_abs();
    if delta >= 0 {
        base.checked_add(magnitude)
            .ok_or(EditFailure::ResourceLimit("target-bytes"))
    } else {
        base.checked_sub(magnitude)
            .ok_or(EditFailure::ResourceLimit("target-bytes"))
    }
}

/// Accumulates one splice's length delta.
fn add_length_delta(delta: isize, new_len: usize, old_len: usize) -> Result<isize, EditFailure> {
    let change = isize::try_from(new_len)
        .ok()
        .and_then(|new| isize::try_from(old_len).ok().map(|old| new - old))
        .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
    delta
        .checked_add(change)
        .ok_or(EditFailure::ResourceLimit("target-bytes"))
}

/// Computes one operation's structural changes over the current arena.
fn binary_plan(
    document: &PlistDocument,
    facts: &BinaryFacts,
    operation: &EditOperation,
) -> Result<BinaryPlan, EditFailure> {
    let node_count = document.node_count();
    let dict_counts: Vec<usize> = (0..node_count)
        .map(|index| {
            document
                .get(PlistValueRef::from_index(index))
                .and_then(PlistValue::as_dict)
                .map_or(0, |dict| dict.entries().len())
        })
        .collect();
    let mut key_refs: Vec<Vec<usize>> = vec![Vec::new(); node_count];
    for reference in facts.refs() {
        if reference.position() < dict_counts[reference.owner()] {
            key_refs[reference.owner()].push(reference.target());
        }
    }
    let mut refs: Vec<Vec<usize>> = vec![Vec::new(); node_count];
    for index in 0..node_count {
        match document.get(PlistValueRef::from_index(index)) {
            Some(PlistValue::Dict(dict)) => {
                refs[index].clone_from(&key_refs[index]);
                refs[index].extend(dict.entries().iter().map(|entry| entry.value().index()));
            }
            Some(PlistValue::Array(array)) => {
                refs[index] = array
                    .elements()
                    .iter()
                    .map(|element| element.index())
                    .collect();
            }
            _ => {}
        }
    }
    match operation {
        EditOperation::SetValue { path, value } => {
            let target = resolve_path(document, path)?;
            let mut scalar_replaces = BTreeMap::new();
            scalar_replaces.insert(target.index(), encode_binary_value(value)?);
            Ok(BinaryPlan {
                refs,
                appended: Vec::new(),
                scalar_replaces,
                container_touched: Vec::new(),
            })
        }
        EditOperation::InsertDictEntry {
            path,
            key,
            value,
            placement,
        } => {
            let dict = resolve_path(document, path)?;
            let count = document
                .get(dict)
                .and_then(PlistValue::as_dict)
                .ok_or(EditFailure::WrongRole)?
                .entries()
                .len();
            let position = match placement {
                DictPlacement::End => count,
                DictPlacement::Before(position) if *position < count => *position,
                DictPlacement::After(position) if *position < count => position + 1,
                _ => return Err(EditFailure::TargetNotFound),
            };
            let key_bytes = encode_binary_string(key.string())?;
            let value_bytes = encode_binary_value(value)?;
            let key_index = node_count;
            let value_index = node_count + 1;
            let dict_refs = &mut refs[dict.index()];
            dict_refs.insert(position, key_index);
            dict_refs.insert(count + 1 + position, value_index);
            Ok(BinaryPlan {
                refs,
                appended: vec![key_bytes, value_bytes],
                scalar_replaces: BTreeMap::new(),
                container_touched: vec![dict.index()],
            })
        }
        EditOperation::RemoveDictEntry {
            path,
            key,
            occurrence,
        } => {
            let dict = resolve_path(document, path)?;
            let entries = document
                .get(dict)
                .and_then(PlistValue::as_dict)
                .ok_or(EditFailure::WrongRole)?
                .entries();
            let position = nth_key_position(entries, key, *occurrence)?;
            let count = entries.len();
            let dict_refs = &mut refs[dict.index()];
            dict_refs.remove(position);
            dict_refs.remove(count - 1 + position);
            Ok(BinaryPlan {
                refs,
                appended: Vec::new(),
                scalar_replaces: BTreeMap::new(),
                container_touched: vec![dict.index()],
            })
        }
        EditOperation::RenameDictKey {
            path,
            from,
            occurrence,
            to,
        } => {
            let dict = resolve_path(document, path)?;
            let entries = document
                .get(dict)
                .and_then(PlistValue::as_dict)
                .ok_or(EditFailure::WrongRole)?
                .entries();
            let position = nth_key_position(entries, from, *occurrence)?;
            let new_key_index = node_count;
            refs[dict.index()][position] = new_key_index;
            Ok(BinaryPlan {
                refs,
                appended: vec![encode_binary_string(to.string())?],
                scalar_replaces: BTreeMap::new(),
                container_touched: vec![dict.index()],
            })
        }
        EditOperation::InsertArrayElement { path, index, value } => {
            let array = resolve_path(document, path)?;
            let count = document
                .get(array)
                .and_then(PlistValue::as_array)
                .ok_or(EditFailure::WrongRole)?
                .elements()
                .len();
            if *index > count {
                return Err(EditFailure::TargetNotFound);
            }
            let value_index = node_count;
            refs[array.index()].insert(*index, value_index);
            Ok(BinaryPlan {
                refs,
                appended: vec![encode_binary_value(value)?],
                scalar_replaces: BTreeMap::new(),
                container_touched: vec![array.index()],
            })
        }
        EditOperation::RemoveArrayElement { path, index } => {
            let array = resolve_path(document, path)?;
            let count = document
                .get(array)
                .and_then(PlistValue::as_array)
                .ok_or(EditFailure::WrongRole)?
                .elements()
                .len();
            if *index >= count {
                return Err(EditFailure::TargetNotFound);
            }
            refs[array.index()].remove(*index);
            Ok(BinaryPlan {
                refs,
                appended: Vec::new(),
                scalar_replaces: BTreeMap::new(),
                container_touched: vec![array.index()],
            })
        }
    }
}

/// Whether one object is a dictionary.
fn container_is_dict(document: &PlistDocument, index: usize) -> bool {
    matches!(
        document.get(PlistValueRef::from_index(index)),
        Some(PlistValue::Dict(_))
    )
}

/// Encodes one container object: the sized marker and every reference at the
/// given width; a dictionary writes its key references followed by its value
/// references (RFC 0013 §5.9).
fn encode_container(
    refs: &[usize],
    is_dict: bool,
    ref_size: usize,
) -> Result<Vec<u8>, EditFailure> {
    let count = if is_dict { refs.len() / 2 } else { refs.len() };
    let mut out = Vec::new();
    write_sized_marker(&mut out, if is_dict { 0xD0 } else { 0xA0 }, count)?;
    for &target in refs {
        write_be(&mut out, target as u64, ref_size)?;
    }
    Ok(out)
}

/// Encodes one typed value as a binary object (RFC 0013 §5).
fn encode_binary_value(value: &EditValue) -> Result<Vec<u8>, EditFailure> {
    let mut out = Vec::new();
    match value {
        EditValue::String(string) => return encode_binary_string(string),
        EditValue::Integer(integer) => {
            let value = integer.value();
            let width = integer_width(value);
            out.push(0x10 | width.trailing_zeros() as u8);
            // The two's-complement bit pattern of the signed value, written
            // at exactly `width` bytes (RFC 0013 §5.3).
            #[allow(clippy::cast_sign_loss)]
            write_be(&mut out, value as u64, width)?;
        }
        EditValue::Real(real) => match real.width() {
            RealWidth::Float64 => {
                out.push(0x23);
                write_be(&mut out, real.bits(), 8)?;
            }
            RealWidth::Float32 => {
                out.push(0x22);
                write_be(&mut out, real.bits(), 4)?;
            }
        },
        EditValue::Boolean(boolean) => {
            out.push(if boolean.value() { 0x09 } else { 0x08 });
        }
        EditValue::Date(date) => {
            out.push(0x33);
            write_be(&mut out, date.seconds().to_bits(), 8)?;
        }
        EditValue::Data(data) => {
            write_sized_marker(&mut out, 0x40, data.bytes().len())?;
            out.extend_from_slice(data.bytes());
        }
        EditValue::Uid(uid) => {
            let value = u64::from(uid.value());
            let width = uid_width(value);
            out.push(0x80 | (width as u8 - 1));
            write_be(&mut out, value, width)?;
        }
    }
    Ok(out)
}

/// Encodes one string object: the ASCII marker when every code unit is below
/// `0x80`, else the UTF-16BE marker (RFC 0013 §5.6).
fn encode_binary_string(string: &PlistString) -> Result<Vec<u8>, EditFailure> {
    let units = string.code_units();
    let mut out = Vec::new();
    if units.iter().all(|unit| *unit < 0x80) {
        write_sized_marker(&mut out, 0x50, units.len())?;
        for unit in units {
            out.push(*unit as u8);
        }
    } else {
        write_sized_marker(&mut out, 0x60, units.len())?;
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    }
    Ok(out)
}

/// Writes one sized marker: counts below `0x0F` fit the low nibble, while the
/// nibble `0x0F` itself is the extended-size sentinel (RFC 0013 §5.4), so
/// every count of 15 or more follows the marker with a `0x10`-style size
/// marker and count object. The parser always reads nibble `0xF` as the
/// sentinel, so the plain `marker | 0x0F` spelling would consume the first
/// payload byte as a size object.
fn write_sized_marker(out: &mut Vec<u8>, marker: u8, count: usize) -> Result<(), EditFailure> {
    if count < 0x0F {
        out.push(marker | count as u8);
        return Ok(());
    }
    out.push(marker | 0x0F);
    let count = u64::try_from(count).map_err(|_| EditFailure::ResourceLimit("object-count"))?;
    let width = unsigned_width(count);
    out.push(0x10 | width.trailing_zeros() as u8);
    write_be(out, count, width)
}

/// Appends one big-endian unsigned value of exactly `width` bytes.
fn write_be(out: &mut Vec<u8>, value: u64, width: usize) -> Result<(), EditFailure> {
    if width > 8 {
        return Err(EditFailure::ResourceLimit("object-width"));
    }
    for shift in (0..width).rev() {
        out.push(((value >> (8 * shift)) & 0xFF) as u8);
    }
    Ok(())
}

/// Smallest width in bytes whose capacity (`2^(8 * width)`) exceeds
/// `max_index`, satisfying the trailer sufficiency checks of RFC 0013 §5.11.
fn ref_width_for(max_index: usize) -> usize {
    let mut size = 1;
    let mut capacity = 256_usize;
    while max_index >= capacity && size < 8 {
        size += 1;
        capacity = capacity.saturating_mul(256);
    }
    size
}

/// Minimal marker width for one signed 64-bit integer: negatives always use
/// the signed 8-byte form (RFC 0013 §5.3, §10.2).
fn integer_width(value: i64) -> usize {
    match u64::try_from(value) {
        Ok(value) => unsigned_width(value),
        Err(_) => 8,
    }
}

/// Minimal marker width for one unsigned count: 1, 2, 4, or 8 bytes.
fn unsigned_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFFFF_FFFF {
        4
    } else {
        8
    }
}

/// Minimal byte width of one unsigned 32-bit UID value (RFC 0013 §5.8).
fn uid_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFF_FFFF {
        3
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// Commit assembly
// ---------------------------------------------------------------------------

/// Builds the commit facts: ChangeSet, replayable SourcePatch, and the
/// untouched-byte proof.
fn build_commit(
    base: &Document,
    transaction: &EditTransaction,
    final_document: Document,
    edits: Vec<AppliedEdit>,
) -> Result<EditCommit, EditFailure> {
    let limits = base.limits();
    if edits.len() > limits.max_report_events {
        return Err(EditFailure::ResourceLimit("report-events"));
    }
    let old_authority = base.authority();
    let new_authority = final_document.authority();
    // The recorded edits are merged into maximal non-overlapping base runs
    // (spans that overlap or touch, including the binary structural regions
    // every step rewrites). Each run's replacement is the exact target bytes
    // at its new span, so the change set, patch, and proof are always
    // self-consistent with the committed bytes.
    let mut spans: Vec<(usize, usize, isize)> = Vec::with_capacity(edits.len());
    for (index, edit) in edits.iter().enumerate() {
        let old_start = unmap_in(&edits[..index], edit.pre_start)?;
        let old_end = unmap_in(&edits[..index], edit.pre_start + edit.pre_len)?;
        let delta = isize::try_from(edit.replacement.len())
            .ok()
            .and_then(|replacement| {
                isize::try_from(edit.pre_len)
                    .ok()
                    .map(|pre| replacement - pre)
            })
            .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
        spans.push((old_start, old_end, delta));
    }
    spans.sort_by_key(|(start, end, _)| (*start, *end));
    let mut runs: Vec<(usize, usize, isize)> = Vec::with_capacity(spans.len());
    for (start, end, delta) in spans {
        if let Some((_, run_end, run_delta)) = runs.last_mut() {
            if start <= *run_end {
                *run_end = (*run_end).max(end);
                *run_delta = run_delta
                    .checked_add(delta)
                    .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
                continue;
            }
        }
        runs.push((start, end, delta));
    }
    let mut before_delta = 0_isize;
    let target_bytes = final_document.render();
    let mut source_edits = Vec::with_capacity(runs.len());
    for (start, end, run_delta) in runs {
        let target_start = shifted(start, before_delta)?;
        let run_len = usize::try_from((end - start) as isize + run_delta)
            .map_err(|_| EditFailure::ResourceLimit("target-bytes"))?;
        let target_end = target_start
            .checked_add(run_len)
            .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
        if target_end > target_bytes.len() {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        source_edits.push(SourceEdit {
            old_span: old_authority
                .span(start, end)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?,
            new_span: new_authority
                .span(target_start, target_end)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?,
            replacement: Arc::from(&target_bytes[target_start..target_end]),
        });
        before_delta = before_delta
            .checked_add(run_delta)
            .ok_or(EditFailure::ResourceLimit("target-bytes"))?;
    }
    let change_set = ChangeSet::new(
        base.snapshot_identity(),
        final_document.snapshot_identity(),
        source_edits,
        build_mappings(base, transaction, &final_document),
        Vec::new(),
    );
    let source_patch = SourcePatch::derive(
        base.source(),
        final_document.source(),
        &change_set,
        operation_metadata(transaction),
        source_patch_limits(limits),
    )
    .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
    let untouched_proof = UntouchedByteProof::create(
        base.source(),
        final_document.source(),
        source_patch.replacements(),
    )
    .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
    Ok(EditCommit {
        document: final_document,
        change_set,
        source_patch,
        untouched_proof,
    })
}

/// One old-to-new mapping per operation whose target resolves in the base
/// snapshot; insertions carry no mapping.
fn build_mappings(
    base: &Document,
    transaction: &EditTransaction,
    final_document: &Document,
) -> Vec<NodeMapping> {
    let Some(base_document) = base.document() else {
        return Vec::new();
    };
    let Some(final_doc) = final_document.document() else {
        return Vec::new();
    };
    let old_authority = base.authority();
    let new_authority = final_document.authority();
    transaction
        .operations
        .iter()
        .filter_map(|operation| {
            mapping_for(
                operation,
                base_document,
                final_doc,
                old_authority,
                new_authority,
            )
        })
        .collect()
}

/// One mapping fact for one operation, when its target resolves in the base.
fn mapping_for(
    operation: &EditOperation,
    base_document: &PlistDocument,
    final_document: &PlistDocument,
    old_authority: &DocumentAuthority,
    new_authority: &DocumentAuthority,
) -> Option<NodeMapping> {
    let (old, new, status) = match operation {
        EditOperation::SetValue { path, .. } | EditOperation::RenameDictKey { path, .. } => {
            let old = resolve_path(base_document, path).ok()?;
            match resolve_path(final_document, path).ok() {
                Some(new) => (old, Some(new), NodeMappingStatus::Replaced),
                None => (old, None, NodeMappingStatus::Unmapped),
            }
        }
        EditOperation::RemoveDictEntry {
            path,
            key,
            occurrence,
        } => {
            let container = resolve_path(base_document, path).ok()?;
            let entries = base_document.get(container)?.as_dict()?.entries();
            let position = nth_key_position(entries, key, *occurrence).ok()?;
            (entries[position].value(), None, NodeMappingStatus::Deleted)
        }
        EditOperation::RemoveArrayElement { path, index } => {
            let container = resolve_path(base_document, path).ok()?;
            let elements = base_document.get(container)?.as_array()?.elements();
            let element = *elements.get(*index)?;
            (element, None, NodeMappingStatus::Deleted)
        }
        EditOperation::InsertDictEntry { .. } | EditOperation::InsertArrayElement { .. } => {
            return None;
        }
    };
    Some(NodeMapping {
        old: old_authority.node_ref(old.index() as u64, NodeRole::PlistValue),
        new: new.map(|new| new_authority.node_ref(new.index() as u64, NodeRole::PlistValue)),
        status,
        reason: (status == NodeMappingStatus::Unmapped)
            .then(|| "reparsed-node-not-uniquely-located".to_owned()),
    })
}

/// Patch construction bounds derived from the parse limits.
fn source_patch_limits(limits: PlistParseLimits) -> SourcePatchLimits {
    SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: limits.common.max_source_bytes,
            max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
            max_decoded_scalars: limits.max_decoded_scalars,
        },
        max_replacements: limits.max_report_events.max(1),
        max_patch_bytes: limits.common.max_source_bytes.saturating_mul(2),
    }
}

/// Maps one fatal target formation failure to a stable edit failure.
fn map_fatal(fatal: &FatalFormationFailure) -> EditFailure {
    if fatal.diagnostics().iter().any(|diagnostic| {
        diagnostic.code.starts_with("plist.limit.")
            || diagnostic.code == "core.source.resource-limit@1"
    }) {
        EditFailure::ResourceLimit("formation")
    } else {
        EditFailure::NewDocumentFormationFailed
    }
}

/// Deterministic patch metadata: one operation id per declared operation.
fn operation_metadata(transaction: &EditTransaction) -> BTreeMap<String, String> {
    transaction
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            (
                format!("operation.{index}"),
                operation_id(operation).to_owned(),
            )
        })
        .collect()
}

/// Stable operation identifier.
fn operation_id(operation: &EditOperation) -> &'static str {
    match operation {
        EditOperation::SetValue { .. } => "plist.edit.set-value@1",
        EditOperation::InsertDictEntry { .. } => "plist.edit.insert-dict-entry@1",
        EditOperation::RemoveDictEntry { .. } => "plist.edit.remove-dict-entry@1",
        EditOperation::RenameDictKey { .. } => "plist.edit.rename-dict-key@1",
        EditOperation::InsertArrayElement { .. } => "plist.edit.insert-array-element@1",
        EditOperation::RemoveArrayElement { .. } => "plist.edit.remove-array-element@1",
    }
}

/// Content-free operation summaries for the dry-run plan.
fn operation_summaries(
    transaction: &EditTransaction,
) -> Result<Vec<EditOperationSummary>, EditFailure> {
    transaction
        .operations
        .iter()
        .map(|operation| {
            let (id, arguments) = match operation {
                EditOperation::SetValue { value, .. } => (
                    "plist.edit.set-value",
                    BTreeMap::from([("value_kind".to_owned(), value.kind().as_str().to_owned())]),
                ),
                EditOperation::InsertDictEntry {
                    key,
                    value,
                    placement,
                    ..
                } => (
                    "plist.edit.insert-dict-entry",
                    BTreeMap::from([
                        ("key_units".to_owned(), key.code_units().len().to_string()),
                        ("value_kind".to_owned(), value.kind().as_str().to_owned()),
                        ("placement".to_owned(), placement_name(placement).to_owned()),
                    ]),
                ),
                EditOperation::RemoveDictEntry {
                    key, occurrence, ..
                } => (
                    "plist.edit.remove-dict-entry",
                    BTreeMap::from([
                        ("key_units".to_owned(), key.code_units().len().to_string()),
                        ("occurrence".to_owned(), occurrence.to_string()),
                    ]),
                ),
                EditOperation::RenameDictKey {
                    from,
                    to,
                    occurrence,
                    ..
                } => (
                    "plist.edit.rename-dict-key",
                    BTreeMap::from([
                        ("from_units".to_owned(), from.code_units().len().to_string()),
                        ("to_units".to_owned(), to.code_units().len().to_string()),
                        ("occurrence".to_owned(), occurrence.to_string()),
                    ]),
                ),
                EditOperation::InsertArrayElement { index, value, .. } => (
                    "plist.edit.insert-array-element",
                    BTreeMap::from([
                        ("index".to_owned(), index.to_string()),
                        ("value_kind".to_owned(), value.kind().as_str().to_owned()),
                    ]),
                ),
                EditOperation::RemoveArrayElement { index, .. } => (
                    "plist.edit.remove-array-element",
                    BTreeMap::from([("index".to_owned(), index.to_string())]),
                ),
            };
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

/// Stable placement name for summaries.
fn placement_name(placement: &DictPlacement) -> &'static str {
    match placement {
        DictPlacement::End => "end",
        DictPlacement::Before(_) => "before",
        DictPlacement::After(_) => "after",
    }
}

// ---------------------------------------------------------------------------
// XML value spelling helpers (RFC 0013 §4, §10.1)
// ---------------------------------------------------------------------------

/// Escapes XML text content (RFC 0013 §4.9, §10.1): `&`, `<`, `>`, and a
/// literal CR, which XML line-end normalization would otherwise turn into LF
/// (a character reference is not normalized).
fn escape_xml_text(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(character),
        }
    }
}

/// Deterministic shortest-round-trip decimal spelling of one real (RFC 0013
/// §4.6, §10.1); the special spellings match the frozen grammar.
fn render_real(real: PlistReal) -> String {
    let value = real.as_f64();
    if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        value.to_string()
    }
}

/// Whether the exact bits of one real survive the XML spelling: Rust's
/// shortest-round-trip decimal is exact for every finite double, and the
/// special spellings resolve to the canonical NaN bit pattern only.
fn real_expressible(real: PlistReal) -> bool {
    let value = real.as_f64();
    if value.is_nan() {
        value.to_bits() == f64::NAN.to_bits()
    } else if value.is_infinite() {
        true
    } else {
        value
            .to_string()
            .parse::<f64>()
            .is_ok_and(|parsed| parsed.to_bits() == value.to_bits())
    }
}

/// `2^53`: the largest magnitude at which every integral double is exactly
/// representable, so the day/second decomposition below it is exact.
const EXACT_UNIX_SECONDS_BOUND: f64 = 9_007_199_254_740_992.0;

/// Decomposition failure of one date value under the XML calendar grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DateRangeError {
    /// The seconds value carries a fractional part (RFC 0013 §4.7).
    FractionalSeconds,
    /// The calendar year exceeds the exact whole-second range expressible by
    /// the XML grammar: the 32-bit year magnitude, or a Unix-seconds value
    /// whose exact double decomposition would round (hard gate 3).
    YearOutOfRange,
}

/// Whole-second XML date spelling of one exact plist-epoch seconds value
/// (RFC 0013 §4.7).
fn render_date(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> String {
    let sign = if year < 0 { "-" } else { "" };
    format!(
        "{sign}{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        year = year.unsigned_abs()
    )
}

/// Decomposes exact plist-epoch seconds into XML calendar fields (RFC 0013
/// §4.7, §5.5). The value must be whole-second, and the day/second
/// decomposition must be exact: the Unix-seconds value must stay below `2^53`
/// and the calendar year within the grammar's 32-bit magnitude.
fn whole_second_date(seconds: f64) -> Result<(i64, i64, i64, i64, i64, i64), DateRangeError> {
    if seconds.fract() != 0.0 {
        return Err(DateRangeError::FractionalSeconds);
    }
    // The sum of an integral seconds value and the exact epoch offset is
    // exactly representable; the pre-bound keeps every later cast exact.
    let unix = seconds + PLIST_EPOCH_OFFSET_UNIX;
    if unix.abs() >= EXACT_UNIX_SECONDS_BOUND {
        return Err(DateRangeError::YearOutOfRange);
    }
    let unix_int = unix as i64;
    let days = unix_int.div_euclid(86_400);
    let seconds_of_day = unix_int.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if year.unsigned_abs() > u64::from(u32::MAX) {
        return Err(DateRangeError::YearOutOfRange);
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok((year, month, day, hour, minute, second))
}

/// Proleptic Gregorian calendar date of `days` since the Unix epoch (the
/// inverse of the parser's `days_from_civil`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// Standard-alphabet base64 with exact `=` padding (RFC 0013 §4.8, §10.1).
fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(char::from(ALPHABET[(first >> 2) as usize]));
        out.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(((second & 0x0F) << 2) | (third >> 6)) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(third & 0x3F) as usize])
        } else {
            '='
        });
    }
    out
}

/// XML 1.0 `Char` production (RFC 0013 §4.9).
const fn is_xml_char(character: char) -> bool {
    character == '\t'
        || character == '\n'
        || character == '\r'
        || (character >= '\u{20}' && character <= '\u{D7FF}')
        || (character >= '\u{E000}' && character <= '\u{FFFD}')
        || (character >= '\u{10000}' && character <= '\u{10FFFF}')
}

/// Whether every scalar of one well-formed UTF-16 sequence is an XML 1.0
/// character; an unpaired surrogate is not.
fn is_xml_text(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let scalar = if (0xD800..=0xDBFF).contains(&unit) {
            match units.get(index + 1).copied() {
                Some(low) if (0xDC00..=0xDFFF).contains(&low) => {
                    index += 2;
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00)
                }
                _ => return false,
            }
        } else {
            index += 1;
            u32::from(unit)
        };
        let Some(character) = char::from_u32(scalar) else {
            return false;
        };
        if !is_xml_char(character) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::PlistDict;
    use consema_document::{ParseLimits, SourceEncoding, UntouchedByteRegion};

    /// Appends a big-endian value of `width` bytes.
    fn push_be(output: &mut Vec<u8>, value: u64, width: usize) {
        for shift in (0..width).rev() {
            output.push(((value >> (8 * shift)) & 0xFF) as u8);
        }
    }

    /// Hand-built `bplist00` fixture writer: header, objects, offset table,
    /// trailer.
    struct TestBinaryBuilder {
        bytes: Vec<u8>,
        offsets: Vec<u64>,
        offset_int_size: usize,
        ref_size: usize,
    }

    impl TestBinaryBuilder {
        fn new(offset_int_size: usize, ref_size: usize) -> Self {
            Self {
                bytes: b"bplist00".to_vec(),
                offsets: Vec::new(),
                offset_int_size,
                ref_size,
            }
        }

        fn object(&mut self, object: &[u8]) -> u64 {
            let offset = u64::try_from(self.bytes.len()).unwrap();
            self.offsets.push(offset);
            self.bytes.extend_from_slice(object);
            offset
        }

        fn finish(mut self, top_object: u64) -> Vec<u8> {
            let offset_table_offset = u64::try_from(self.bytes.len()).unwrap();
            for offset in &self.offsets {
                push_be(&mut self.bytes, *offset, self.offset_int_size);
            }
            self.bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            self.bytes.push(0); // sortVersion
            self.bytes.push(self.offset_int_size as u8);
            self.bytes.push(self.ref_size as u8);
            push_be(
                &mut self.bytes,
                u64::try_from(self.offsets.len()).unwrap(),
                8,
            );
            push_be(&mut self.bytes, top_object, 8);
            push_be(&mut self.bytes, offset_table_offset, 8);
            self.bytes
        }
    }

    fn parse_xml_document(source: &[u8]) -> Document {
        Document::parse(
            Arc::from(source),
            PlistProfile::XmlV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("xml plist forms")
    }

    fn parse_binary_document(bytes: Vec<u8>) -> Document {
        Document::parse(
            Arc::from(bytes),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("binary plist forms")
    }

    /// The conformance binary fixture: a root array `[1, "b"]`.
    fn binary_fixture() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0xA2, 0x01, 0x02]); // 0: array [1, 2]
        file.object(&[0x10, 0x01]); // 1: integer 1
        file.object(&[0x51, b'b']); // 2: "b"
        file.finish(0)
    }

    fn key(step: &str) -> PlistKey {
        PlistKey::from_unicode(step)
    }

    fn key_step(name: &str) -> EditPathStep {
        EditPathStep::DictKey {
            key: key(name),
            occurrence: 0,
        }
    }

    fn patch_limits() -> SourcePatchLimits {
        SourcePatchLimits {
            source: SourceLimits {
                max_raw_bytes: 1024 * 1024,
                max_decoded_utf8_bytes: 1024 * 1024,
                max_decoded_scalars: 1024 * 1024,
            },
            max_replacements: 64,
            max_patch_bytes: 1024 * 1024,
        }
    }

    /// Commits and verifies the full contract: patch replay, untouched proof,
    /// and a Complete target.
    fn commit(document: &Document, transaction: EditTransaction) -> Document {
        let commit = document.commit(&transaction).expect("commit succeeds");
        let replay = commit
            .source_patch
            .apply(document.source(), patch_limits())
            .expect("patch replays");
        assert_eq!(replay.bytes(), commit.document.render());
        commit
            .untouched_proof
            .verify(
                document.source(),
                commit.document.source(),
                commit.source_patch.replacements(),
            )
            .expect("untouched bytes proven");
        assert_eq!(
            commit.document.status(),
            FormationStatus::Complete,
            "committed document is complete"
        );
        commit.document
    }

    fn string_value(text: &str) -> EditValue {
        EditValue::String(PlistString::from_unicode(text))
    }

    fn integer_value(value: i64) -> EditValue {
        EditValue::Integer(PlistInteger::new(value))
    }

    fn boolean_value(value: bool) -> EditValue {
        EditValue::Boolean(PlistBoolean::new(value))
    }

    /// The root dictionary of one document.
    fn root_dict(document: &Document) -> &PlistDict {
        document
            .document()
            .expect("document")
            .root_value()
            .as_dict()
            .expect("root dict")
    }

    /// Entry value of one root-level key (first occurrence).
    fn root_entry<'a>(document: &'a Document, name: &str) -> &'a PlistValue {
        let entries = root_dict(document).entries();
        let position = entries
            .iter()
            .position(|entry| entry.key() == &key(name))
            .expect("entry exists");
        let reference = entries[position].value();
        document
            .document()
            .expect("document")
            .get(reference)
            .expect("entry value")
    }

    /// An XML or binary fixture for representation-parallel tests.
    enum EditSource<'a> {
        Xml(&'a [u8]),
        Binary(Vec<u8>),
    }

    /// A binary fixture with a nested dict and array under a root dict.
    fn binary_fixture_with_dict_and_array() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'v']); // 0: "v"
        file.object(&[0x52, b'k', b'x']); // 1: "kx"
        file.object(&[0x10, 0x01]); // 2: integer 1
        file.object(&[0x10, 0x02]); // 3: integer 2
        file.object(&[0xA2, 0x02, 0x03]); // 4: array [2, 3]
        file.object(&[0x51, b'k']); // 5: "k"
        file.object(&[0x51, b'd']); // 6: "d"
        file.object(&[0x51, b'a']); // 7: "a"
        file.object(&[0xD1, 0x05, 0x00]); // 8: dict {k: v}
        file.object(&[0xD2, 0x06, 0x07, 0x08, 0x04]); // 9: dict {d: 8, a: 4}
        file.finish(9)
    }

    #[test]
    fn xml_six_operations_match_the_conformance_vector() {
        let source = b"<plist version=\"1.0\"><dict><key>a</key><dict><key>b</key><string>old</string></dict><key>arr</key><array><integer>1</integer><integer>2</integer></array></dict></plist>";
        let document = parse_xml_document(source);
        let path_a = EditPath::new(vec![key_step("a")]);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(
                path_a.child(EditPathStep::DictKey {
                    key: key("b"),
                    occurrence: 0,
                }),
                string_value("new"),
            )
            .insert_dict_entry(
                path_a.clone(),
                key("c"),
                integer_value(3),
                DictPlacement::End,
            )
            .insert_array_element(EditPath::new(vec![key_step("arr")]), 0, string_value("z"))
            .remove_array_element(EditPath::new(vec![key_step("arr")]), 2)
            .rename_dict_key(path_a.clone(), key("c"), 0, key("c2"))
            .remove_dict_entry(path_a, key("b"), 0);
        let after = commit(&document, builder.build());
        let entries_a = root_entry(&after, "a").as_dict().expect("dict a");
        let keys = entries_a
            .entries()
            .iter()
            .map(|entry| entry.key().to_unicode().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["c2"]);
        let values = entries_a
            .entries()
            .iter()
            .map(|entry| {
                after
                    .document()
                    .unwrap()
                    .get(entry.value())
                    .unwrap()
                    .as_integer()
                    .unwrap()
                    .value()
            })
            .collect::<Vec<_>>();
        assert_eq!(values, vec![3]);
        let array = root_entry(&after, "arr").as_array().expect("array");
        let elements = array
            .elements()
            .iter()
            .map(
                |reference| match after.document().unwrap().get(*reference).unwrap() {
                    PlistValue::String(string) => string.to_unicode().unwrap(),
                    PlistValue::Integer(integer) => integer.value().to_string(),
                    other => panic!("unexpected element {other:?}"),
                },
            )
            .collect::<Vec<_>>();
        assert_eq!(elements, vec!["z", "1"]);
    }

    #[test]
    fn binary_structural_edits_match_the_conformance_vector() {
        let document = parse_binary_document(binary_fixture());
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(
                EditPath::new(vec![EditPathStep::ArrayIndex(1)]),
                integer_value(42),
            )
            .insert_array_element(EditPath::root(), 0, boolean_value(true));
        let transaction = builder.build();
        let commit = document.commit(&transaction).expect("commit succeeds");
        let replay = commit
            .source_patch
            .apply(document.source(), patch_limits())
            .expect("patch replays");
        assert_eq!(replay.bytes(), commit.document.render());
        commit
            .untouched_proof
            .verify(
                document.source(),
                commit.document.source(),
                commit.source_patch.replacements(),
            )
            .expect("untouched bytes proven");
        let after = commit.document;
        let elements = after
            .document()
            .unwrap()
            .root_value()
            .as_array()
            .unwrap()
            .elements();
        let values = elements
            .iter()
            .map(
                |reference| match after.document().unwrap().get(*reference).unwrap() {
                    PlistValue::Boolean(boolean) => boolean.value().to_string(),
                    PlistValue::Integer(integer) => integer.value().to_string(),
                    other => panic!("unexpected element {other:?}"),
                },
            )
            .collect::<Vec<_>>();
        assert_eq!(values, vec!["true", "1", "42"]);
        // The untouched integer object keeps its exact bytes at the shifted
        // position: object 1 moves from 11..13 to 12..14.
        let rendered = after.render();
        assert_eq!(&rendered[12..14], &[0x10, 0x01]);
        // The untouched-byte proof covers exactly the untouched object.
        assert!(
            commit
                .untouched_proof
                .regions()
                .contains(&UntouchedByteRegion::new(11, 13, 12, 14))
        );
    }

    #[test]
    fn conflict_vector_codes_and_atomicity() {
        // UID insertion into an XML document.
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string></dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(
            EditPath::new(vec![key_step("a")]),
            EditValue::Uid(PlistUid::new(5)),
        );
        let error = document.commit(&builder.build()).expect_err("uid blocked");
        assert_eq!(error, EditFailure::UidInXml);
        assert_eq!(error.diagnostic_code(), "plist.edit.uid-in-xml@1");
        assert_eq!(
            document.render(),
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string></dict></plist>",
            "base_unchanged"
        );

        // An incomplete base (a dictionary key without a value) cannot be
        // edited.
        let document =
            parse_xml_document(b"<plist version=\"1.0\"><dict><key>a</key></dict></plist>");
        assert_eq!(document.status(), FormationStatus::Recovered);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(EditPath::new(vec![key_step("a")]), integer_value(1));
        let error = document.commit(&builder.build()).expect_err("incomplete");
        assert_eq!(error, EditFailure::IncompleteTarget);
        assert_eq!(error.diagnostic_code(), "core.edit.incomplete-target@1");
        assert_eq!(
            document.render(),
            b"<plist version=\"1.0\"><dict><key>a</key></dict></plist>",
            "base_unchanged"
        );

        // A transaction built against another snapshot is rejected.
        let document = parse_binary_document(binary_fixture());
        let wrong_bytes = [
            0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x30, 0x50, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        ];
        let wrong_source = parse_binary_document(wrong_bytes.to_vec());
        let original = wrong_source.render().to_vec();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(
            EditPath::new(vec![EditPathStep::ArrayIndex(1)]),
            integer_value(42),
        );
        let transaction = builder.build();
        let error = wrong_source
            .commit(&transaction)
            .expect_err("wrong snapshot");
        assert_eq!(error, EditFailure::WrongSnapshot);
        assert_eq!(error.diagnostic_code(), "core.edit.wrong-snapshot@1");
        assert_eq!(wrong_source.render(), original.as_slice(), "base_unchanged");
    }

    #[test]
    fn every_operation_works_on_both_representations() {
        let xml_source = b"<plist version=\"1.0\"><dict><key>d</key><dict><key>k</key><string>v</string></dict><key>a</key><array><integer>1</integer><integer>2</integer></array></dict></plist>";
        for source in [
            EditSource::Xml(xml_source),
            EditSource::Binary(binary_fixture_with_dict_and_array()),
        ] {
            let document = match source {
                EditSource::Xml(bytes) => parse_xml_document(bytes),
                EditSource::Binary(bytes) => parse_binary_document(bytes),
            };
            let path_d = EditPath::new(vec![key_step("d")]);
            let path_a = EditPath::new(vec![key_step("a")]);

            // set-value.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_value(
                path_d.clone().child(EditPathStep::DictKey {
                    key: key("k"),
                    occurrence: 0,
                }),
                string_value("changed"),
            );
            let after = commit(&document, builder.build());
            let value = after
                .document()
                .unwrap()
                .get(root_entry(&after, "d").as_dict().unwrap().entries()[0].value())
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap();
            assert_eq!(value, "changed");

            // insert-dict-entry with every placement.
            for placement in [
                DictPlacement::End,
                DictPlacement::Before(0),
                DictPlacement::After(0),
            ] {
                let mut builder = EditTransactionBuilder::new(&document);
                builder.insert_dict_entry(path_d.clone(), key("x"), integer_value(9), placement);
                let after = commit(&document, builder.build());
                let entries_d = root_entry(&after, "d").as_dict().unwrap().entries();
                assert_eq!(entries_d.len(), 2);
                let inserted_position = match placement {
                    DictPlacement::Before(0) => 0,
                    DictPlacement::End | DictPlacement::After(0) => 1,
                    _ => unreachable!(),
                };
                assert_eq!(
                    entries_d[inserted_position].key().to_unicode().unwrap(),
                    "x"
                );
            }

            // remove-dict-entry.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.remove_dict_entry(path_d.clone(), key("k"), 0);
            let after = commit(&document, builder.build());
            assert!(
                root_entry(&after, "d")
                    .as_dict()
                    .unwrap()
                    .entries()
                    .is_empty()
            );

            // rename-dict-key.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.rename_dict_key(path_d.clone(), key("k"), 0, key("renamed"));
            let after = commit(&document, builder.build());
            let entries_d = root_entry(&after, "d").as_dict().unwrap().entries();
            assert_eq!(entries_d[0].key().to_unicode().unwrap(), "renamed");

            // insert-array-element at the start, middle, and end.
            for index in [0_usize, 1, 2] {
                let mut builder = EditTransactionBuilder::new(&document);
                builder.insert_array_element(path_a.clone(), index, string_value("z"));
                let after = commit(&document, builder.build());
                let elements = root_entry(&after, "a").as_array().unwrap().elements();
                assert_eq!(elements.len(), 3);
            }

            // remove-array-element.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.remove_array_element(path_a.clone(), 1);
            let after = commit(&document, builder.build());
            let elements = root_entry(&after, "a").as_array().unwrap().elements();
            assert_eq!(elements.len(), 1);

            // Path roles: an array step into a dict fails; a dict step into
            // an array fails.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_value(
                path_d.clone().child(EditPathStep::ArrayIndex(0)),
                integer_value(1),
            );
            assert!(matches!(
                document.commit(&builder.build()),
                Err(EditFailure::WrongRole)
            ));
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_value(path_a.clone().child(key_step("k")), integer_value(1));
            assert!(matches!(
                document.commit(&builder.build()),
                Err(EditFailure::WrongRole)
            ));
        }
    }

    #[test]
    fn duplicate_key_occurrence_selects_the_nth_association() {
        let xml_source = b"<plist version=\"1.0\"><dict><key>k</key><integer>1</integer><key>k</key><integer>2</integer></dict></plist>";
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'k']); // 0: "k"
        file.object(&[0x51, b'k']); // 1: "k"
        file.object(&[0x10, 0x01]); // 2: integer 1
        file.object(&[0x10, 0x02]); // 3: integer 2
        file.object(&[0xD2, 0x00, 0x01, 0x02, 0x03]); // 4: dict {k:1, k:2}
        let binary_source = file.finish(4);

        for source in [
            EditSource::Xml(xml_source),
            EditSource::Binary(binary_source),
        ] {
            let document = match source {
                EditSource::Xml(bytes) => parse_xml_document(bytes),
                EditSource::Binary(bytes) => parse_binary_document(bytes),
            };
            let root = EditPath::root();

            // set-value with occurrence 1 targets the second association.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_value(
                EditPath::new(vec![EditPathStep::DictKey {
                    key: key("k"),
                    occurrence: 1,
                }]),
                integer_value(3),
            );
            let after = commit(&document, builder.build());
            let values = root_dict(&after)
                .entries()
                .iter()
                .map(|entry| {
                    after
                        .document()
                        .unwrap()
                        .get(entry.value())
                        .unwrap()
                        .as_integer()
                        .unwrap()
                        .value()
                })
                .collect::<Vec<_>>();
            assert_eq!(values, vec![1, 3]);

            // remove with occurrence 0 removes the first association.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.remove_dict_entry(root.clone(), key("k"), 0);
            let after = commit(&document, builder.build());
            let entries = root_dict(&after).entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(
                after
                    .document()
                    .unwrap()
                    .get(entries[0].value())
                    .unwrap()
                    .as_integer()
                    .unwrap()
                    .value(),
                2
            );

            // rename with occurrence 1 renames the second association.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.rename_dict_key(root.clone(), key("k"), 1, key("k2"));
            let after = commit(&document, builder.build());
            let keys = root_dict(&after)
                .entries()
                .iter()
                .map(|entry| entry.key().to_unicode().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(keys, vec!["k", "k2"]);

            // An occurrence past the group is a missing target.
            let mut builder = EditTransactionBuilder::new(&document);
            builder.remove_dict_entry(root.clone(), key("k"), 2);
            assert!(matches!(
                document.commit(&builder.build()),
                Err(EditFailure::TargetNotFound)
            ));
        }
    }

    #[test]
    fn failed_transactions_leave_the_base_byte_exact() {
        let source = b"<plist version=\"1.0\"><dict><key>a</key><dict><key>i</key><integer>1</integer></dict><key>b</key><array><integer>1</integer></array></dict></plist>";
        let document = parse_xml_document(source);
        let original = document.render().to_vec();
        let path_a = EditPath::new(vec![key_step("a")]);
        let path_b = EditPath::new(vec![key_step("b")]);

        // Missing key.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_dict_entry(EditPath::root(), key("missing"), 0);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::TargetNotFound)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Stale array index.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_array_element(path_b.clone(), 5);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::TargetNotFound)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Stale placement anchor.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            path_a.clone(),
            key("z"),
            integer_value(1),
            DictPlacement::Before(7),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::TargetNotFound)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Two insertions at the same End position map to the same base
        // position: a duplicate target.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_dict_entry(
                path_a.clone(),
                key("z"),
                integer_value(1),
                DictPlacement::End,
            )
            .insert_dict_entry(
                path_a.clone(),
                key("y"),
                integer_value(2),
                DictPlacement::End,
            );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::ConflictingEdits)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Removing exactly the entry an earlier operation inserted folds to
        // a no-op: the transaction succeeds and the base stays byte-exact.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_dict_entry(
                path_a.clone(),
                key("z"),
                integer_value(1),
                DictPlacement::End,
            )
            .remove_dict_entry(path_a.clone(), key("z"), 0);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), original.as_slice(), "net no-op");

        // An operation whose source span contains an earlier operation's
        // ownership merges into one combined splice: inserting into a
        // dictionary and then removing the owning entry removes both.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_dict_entry(
                path_a.clone(),
                key("z"),
                integer_value(1),
                DictPlacement::End,
            )
            .remove_dict_entry(EditPath::root(), key("a"), 0);
        let after = commit(&document, builder.build());
        assert!(
            root_dict(&after)
                .entries()
                .iter()
                .all(|entry| entry.key().to_unicode().unwrap() != "a"),
            "the owning entry is gone"
        );

        // A path that meets a container of the wrong kind is a role failure.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            path_b.clone(),
            key("z"),
            integer_value(1),
            DictPlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::WrongRole)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");
    }

    #[test]
    fn unrepresentable_values_fail_on_xml_and_succeed_on_binary() {
        let xml = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        let binary = parse_binary_document(binary_fixture_with_dict_and_array());
        let cases: Vec<(&str, EditValue)> = vec![
            ("float32-width", EditValue::Real(PlistReal::single(0.1_f32))),
            (
                "unpaired-surrogate",
                EditValue::String(PlistString::from_code_units(vec![0xD800, 0x0061])),
            ),
            (
                "non-xml-character",
                EditValue::String(PlistString::from_unicode("\u{0001}")),
            ),
            (
                "fractional-seconds",
                EditValue::Date(PlistDate::from_seconds(0.5).unwrap()),
            ),
            (
                "real-nan-payload",
                EditValue::Real(PlistReal::from_bits(
                    RealWidth::Float64,
                    0x7FF8_0000_0000_0001,
                )),
            ),
        ];
        for (fact, value) in &cases {
            let mut builder = EditTransactionBuilder::new(&xml);
            builder.set_value(EditPath::root(), value.clone());
            let error = xml.commit(&builder.build()).expect_err("unrepresentable");
            assert_eq!(
                error,
                EditFailure::UnrepresentableValue(fact),
                "fact {fact}"
            );
            assert_eq!(error.diagnostic_code(), "plist.edit.unrepresentable@1");
        }
        let binary_path = EditPath::new(vec![key_step("a"), EditPathStep::ArrayIndex(0)]);
        for (_, value) in cases {
            let mut builder = EditTransactionBuilder::new(&binary);
            builder.set_value(binary_path.clone(), value);
            commit(&binary, builder.build());
        }
    }

    #[test]
    fn binary_shared_reference_edits_preserve_identity() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0xD0]); // 0: empty dict
        file.object(&[0xA2, 0x00, 0x00]); // 1: array [0, 0]
        let bytes = file.finish(1);
        let document = parse_binary_document(bytes);

        // set-value on the shared object updates every owner.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(
            EditPath::new(vec![EditPathStep::ArrayIndex(0)]),
            integer_value(5),
        );
        let after = commit(&document, builder.build());
        let elements = after
            .document()
            .unwrap()
            .root_value()
            .as_array()
            .unwrap()
            .elements();
        let values = elements
            .iter()
            .map(|reference| {
                after
                    .document()
                    .unwrap()
                    .get(*reference)
                    .unwrap()
                    .as_integer()
                    .unwrap()
                    .value()
            })
            .collect::<Vec<_>>();
        assert_eq!(values, vec![5, 5]);

        // Removing one array element never removes the shared object.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_array_element(EditPath::root(), 1);
        let after = commit(&document, builder.build());
        let elements = after
            .document()
            .unwrap()
            .root_value()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(elements.len(), 1);
        assert!(
            after
                .document()
                .unwrap()
                .get(elements[0])
                .unwrap()
                .as_dict()
                .is_some()
        );
        assert_eq!(
            after.document().unwrap().node_count(),
            2,
            "orphans stay in the table"
        );
    }

    #[test]
    fn binary_rename_dict_key_binds_a_fresh_key_object() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'k']); // 0: "k"
        file.object(&[0x10, 0x07]); // 1: integer 7
        file.object(&[0xD1, 0x00, 0x01]); // 2: dict {k: 7}
        file.object(&[0xD1, 0x00, 0x01]); // 3: dict {k: 7}
        file.object(&[0xA2, 0x02, 0x03]); // 4: array [2, 3]
        let bytes = file.finish(4);
        let document = parse_binary_document(bytes);

        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_dict_key(
            EditPath::new(vec![EditPathStep::ArrayIndex(0)]),
            key("k"),
            0,
            key("k2"),
        );
        let after = commit(&document, builder.build());
        let root = after.document().unwrap().root_value().as_array().unwrap();
        let first = after
            .document()
            .unwrap()
            .get(root.elements()[0])
            .unwrap()
            .as_dict()
            .unwrap();
        let second = after
            .document()
            .unwrap()
            .get(root.elements()[1])
            .unwrap()
            .as_dict()
            .unwrap();
        assert_eq!(first.entries()[0].key().to_unicode().unwrap(), "k2");
        assert_eq!(second.entries()[0].key().to_unicode().unwrap(), "k");
        // The old key object keeps its bytes; the new key object is appended.
        let rendered = after.render();
        let old_key = after
            .binary_facts()
            .expect("binary facts")
            .objects()
            .iter()
            .find(|fact| fact.index() == 0)
            .expect("old key object");
        assert_eq!(
            &rendered[old_key.span().start_byte()..old_key.span().end_byte()],
            &[0x51, b'k']
        );
        let facts = after.binary_facts().unwrap();
        assert_eq!(facts.trailer().num_objects(), 6);
    }

    /// Reparses the exact committed bytes and requires Complete plus
    /// native-model equality (the edit closure, RFC 0013 §10.3).
    fn assert_binary_closure(document: &Document) {
        let reparsed = Document::parse(
            Arc::from(document.render().to_vec()),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("the committed bytes reparse");
        assert_eq!(reparsed.status(), FormationStatus::Complete);
        assert_eq!(reparsed.document(), document.document());
    }

    #[test]
    fn insert_operations_write_the_fifteen_count_boundary_extended() {
        // Low nibble `0x0F` is the extended-size sentinel (RFC 0013 §5.4):
        // the binary writer reads a nibble-`0xF` marker as "a size object
        // follows", so a count of exactly 15 must never be spelled as the
        // plain `marker | 0x0F` byte. Each leg commits one structural
        // operation: the binary commit maps every appended-object splice of a
        // transaction to the object-area end, so two append-generating
        // operations of one transaction conflict by design.
        // (a) A 15-char key: the inserted association's key object emits the
        // sentinel nibble plus the `0x10`-style count object (`0x10 0x0F`).
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0xD0]); // 0: empty dict (root)
        let document = parse_binary_document(file.finish(0));
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            EditPath::root(),
            key("123456789012345"),
            string_value("v"),
            DictPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert!(
            after
                .render()
                .windows(3)
                .any(|window| window == [0x5F, 0x10, 0x0F]),
            "the 15-char key marker: {:02x?}",
            after.render()
        );
        assert_binary_closure(&after);
        // (b) A 15-byte data value.
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0xD0]); // 0: empty dict (root)
        let document = parse_binary_document(file.finish(0));
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            EditPath::root(),
            key("payload"),
            EditValue::Data(PlistData::from_bytes(vec![0u8; 15])),
            DictPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert!(
            after
                .render()
                .windows(3)
                .any(|window| window == [0x4F, 0x10, 0x0F]),
            "the 15-byte data marker: {:02x?}",
            after.render()
        );
        assert_binary_closure(&after);
        // (c) A 15-element array: inserting the 15th element rewrites the
        // array container at count 15.
        let mut file = TestBinaryBuilder::new(1, 1);
        let mut refs = Vec::new();
        for index in 0..14 {
            let offset = file.object(&[0x10, index as u8]);
            assert_eq!(offset as usize, 8 + index * 2);
            refs.push(index as u8);
        }
        let mut array = vec![0xAE];
        array.extend_from_slice(&refs);
        file.object(&array);
        let document = parse_binary_document(file.finish(14));
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_array_element(EditPath::root(), 14, integer_value(14));
        let after = commit(&document, builder.build());
        assert!(
            after
                .render()
                .windows(3)
                .any(|window| window == [0xAF, 0x10, 0x0F]),
            "the 15-element array marker: {:02x?}",
            after.render()
        );
        assert_binary_closure(&after);
    }

    #[test]
    fn binary_ref_size_growth_rewrites_container_refs() {
        let mut file = TestBinaryBuilder::new(2, 1);
        // 254 boolean objects plus one array referencing them: 255 objects.
        let mut refs = Vec::new();
        for index in 0..254 {
            let offset = file.object(&[0x08]);
            assert_eq!(offset as usize, 8 + index);
            refs.push(u8::try_from(index).unwrap());
        }
        let mut array = vec![0xAF, 0x10, 0xFE];
        for reference in &refs {
            array.push(*reference);
        }
        file.object(&array);
        let bytes = file.finish(254);
        let document = parse_binary_document(bytes);
        assert_eq!(
            document.binary_facts().unwrap().trailer().object_ref_size(),
            1
        );

        // One more element crosses the 256-object capacity: every container
        // reference block is rewritten at width 2.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_array_element(EditPath::root(), 0, boolean_value(true));
        let after = commit(&document, builder.build());
        let facts = after.binary_facts().expect("facts");
        assert_eq!(facts.trailer().object_ref_size(), 2);
        assert_eq!(facts.trailer().num_objects(), 256);
        let elements = after
            .document()
            .unwrap()
            .root_value()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(elements.len(), 255);
        assert!(
            after
                .document()
                .unwrap()
                .get(elements[0])
                .unwrap()
                .as_boolean()
                .is_some()
        );
        // Untouched scalar objects keep their exact marker bytes.
        assert!(
            after.render()[8..]
                .windows(2)
                .any(|window| window == [0x08, 0x08])
        );
    }

    #[test]
    fn xml_inserts_into_self_closing_containers() {
        let document = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            EditPath::root(),
            key("k"),
            integer_value(1),
            DictPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            b"<plist version=\"1.0\"><dict><key>k</key><integer>1</integer></dict></plist>"
        );

        let document = parse_xml_document(b"<plist version=\"1.0\"><array/></plist>");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_array_element(EditPath::root(), 0, string_value("x"));
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            b"<plist version=\"1.0\"><array><string>x</string></array></plist>"
        );

        // A self-closing scalar value is replaced wholesale.
        let document = parse_xml_document(b"<plist version=\"1.0\"><string/></plist>");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(EditPath::root(), string_value("content"));
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            b"<plist version=\"1.0\"><string>content</string></plist>"
        );
    }

    #[test]
    fn xml_utf16_sources_edit_correctly() {
        for little_endian in [true, false] {
            let text = "<plist version=\"1.0\"><dict><key>k</key><string>a</string></dict></plist>";
            let mut bytes = if little_endian {
                vec![0xFF, 0xFE]
            } else {
                vec![0xFE, 0xFF]
            };
            for unit in text.encode_utf16() {
                if little_endian {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                } else {
                    bytes.extend_from_slice(&unit.to_be_bytes());
                }
            }
            let bom = bytes[..2].to_vec();
            let document = Document::parse(
                Arc::from(bytes),
                PlistProfile::XmlV1,
                PlistEncodingSelection::Explicit(if little_endian {
                    SourceEncoding::Utf16Le
                } else {
                    SourceEncoding::Utf16Be
                }),
                PlistParseLimits::default(),
            )
            .expect("utf-16 xml forms");
            let mut builder = EditTransactionBuilder::new(&document);
            builder
                .set_value(
                    EditPath::new(vec![key_step("k")]),
                    string_value("x & y 中文"),
                )
                .insert_dict_entry(
                    EditPath::root(),
                    key("z"),
                    integer_value(3),
                    DictPlacement::End,
                );
            let after = commit(&document, builder.build());
            let decoded = after.source().decoded_text().expect("decoded");
            assert!(
                decoded.contains("<string>x &amp; y 中文</string>"),
                "{decoded}"
            );
            assert!(
                decoded.contains("<key>z</key><integer>3</integer>"),
                "{decoded}"
            );
            // The BOM stays exactly once.
            assert_eq!(&after.render()[..2], bom.as_slice());
            let entries = root_dict(&after).entries();
            assert_eq!(entries.len(), 2);
        }
    }

    #[test]
    fn dry_run_matches_commit() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(EditPath::new(vec![key_step("a")]), integer_value(2))
            .insert_dict_entry(
                EditPath::root(),
                key("b"),
                string_value("x"),
                DictPlacement::End,
            );
        let transaction = builder.build();
        let commit = document.commit(&transaction).expect("commit");
        let plan = document
            .dry_run(&transaction, EditPlanSourceId::new("test").expect("id"))
            .expect("plan");
        assert_eq!(plan.operations().len(), 2);
        assert_eq!(
            plan.replacements().len(),
            commit.source_patch.replacements().len()
        );
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(
            plan.base_digest(),
            document.source().digest(),
            "dry-run and commit share the base"
        );
    }

    #[test]
    fn limits_are_enforced_atomically() {
        // Target source bound.
        let document = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        let limits = PlistParseLimits {
            common: ParseLimits {
                max_source_bytes: 48,
                ..ParseLimits::default()
            },
            ..PlistParseLimits::default()
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            EditPath::root(),
            key("a"),
            string_value("a"),
            DictPlacement::End,
        );
        let error = document
            .commit_impl(&builder.build(), limits)
            .expect_err("source bound");
        assert_eq!(error, EditFailure::ResourceLimit("target-bytes"));

        // Binary object count bound.
        let document = parse_binary_document(binary_fixture());
        let limits = PlistParseLimits {
            max_object_count: 3,
            ..PlistParseLimits::default()
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_array_element(EditPath::root(), 0, boolean_value(true));
        let error = document
            .commit_impl(&builder.build(), limits)
            .expect_err("object bound");
        assert_eq!(error, EditFailure::ResourceLimit("object-count"));
        assert_eq!(document.render(), binary_fixture().as_slice(), "atomicity");

        // Report event bound.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(
                EditPath::new(vec![EditPathStep::ArrayIndex(0)]),
                integer_value(1),
            )
            .set_value(
                EditPath::new(vec![EditPathStep::ArrayIndex(1)]),
                integer_value(2),
            );
        let limits = PlistParseLimits {
            max_report_events: 1,
            ..PlistParseLimits::default()
        };
        let error = document
            .commit_impl(&builder.build(), limits)
            .expect_err("report bound");
        assert_eq!(error, EditFailure::ResourceLimit("report-events"));
    }

    #[test]
    fn change_set_maps_replaced_deleted_and_unmapped() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string></dict></plist>",
        );
        let path_a = EditPath::new(vec![key_step("a")]);

        // set-value maps the target Replaced.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(path_a.clone(), string_value("y"));
        let commit = document.commit(&builder.build()).expect("commit");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Replaced);
        assert!(mapping.new.is_some());
        assert_eq!(mapping.old.role(), NodeRole::PlistValue);

        // remove maps the removed value Deleted.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_dict_entry(EditPath::root(), key("a"), 0);
        let commit = document.commit(&builder.build()).expect("commit");
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Deleted);
        assert!(mapping.new.is_none());

        // rename maps the dictionary Replaced.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_dict_key(EditPath::root(), key("a"), 0, key("b"));
        let commit = document.commit(&builder.build()).expect("commit");
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Replaced);

        // A set-value whose path a later rename invalidates maps Unmapped
        // with the stable reason.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(path_a.clone(), string_value("z"))
            .rename_dict_key(EditPath::root(), key("a"), 0, key("b"));
        let commit = document.commit(&builder.build()).expect("commit");
        let mappings = commit.change_set.node_mappings();
        assert_eq!(mappings.len(), 2);
        let set_value_mapping = mappings
            .iter()
            .find(|mapping| mapping.status == NodeMappingStatus::Unmapped)
            .expect("unmapped mapping");
        assert_eq!(
            set_value_mapping.reason.as_deref(),
            Some("reparsed-node-not-uniquely-located")
        );
    }

    #[test]
    fn xml_layout_walk_assigns_ordinals_and_spans() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string><key>b</key><array><true/></array></dict></plist>",
        );
        let formed = crate::parse_xml(
            Arc::from(document.render()),
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("forms");
        let layout = xml_layout(&formed).expect("layout");
        assert_eq!(layout.len(), 4);
        // Ordinals follow close-tag order: string, true, array, dict.
        let rendered = document.render();
        let dict_start = rendered
            .windows(5)
            .position(|window| window == b"<dict")
            .expect("dict open");
        let string_start = rendered
            .windows(7)
            .position(|window| window == b"<string")
            .expect("string open");
        let true_start = rendered
            .windows(6)
            .position(|window| window == b"<true/")
            .expect("true tag");
        assert_eq!(layout[0].span.0, string_start);
        assert!(layout[1].self_closing);
        assert_eq!(layout[1].span.0, true_start);
        assert_eq!(layout[2].children, vec![1]);
        assert_eq!(layout[3].children, vec![0, 2]);
        assert_eq!(layout[3].key_text.len(), 2);
        assert_eq!(layout[3].entry_starts.len(), 2);
        assert_eq!(layout[3].span.0, dict_start);
        // The array's close-tag start is the insertion point for End.
        let array_close = rendered
            .windows(7)
            .position(|window| window == b"</array")
            .expect("array close");
        assert_eq!(layout[2].close_start, array_close);
    }

    #[test]
    fn binary_appends_keep_orphans_and_reparse_closure_holds() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'k']); // 0: "k"
        file.object(&[0x10, 0x01]); // 1: integer 1
        file.object(&[0x51, b'm']); // 2: "m"
        file.object(&[0x10, 0x02]); // 3: integer 2
        file.object(&[0xD2, 0x00, 0x02, 0x01, 0x03]); // 4: dict {k:1, m:2}
        let bytes = file.finish(4);
        let document = parse_binary_document(bytes);

        // Remove one entry: the removed key and value objects stay in the
        // object table as orphans while the reachable graph shrinks.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_dict_entry(EditPath::root(), key("m"), 0);
        let after = commit(&document, builder.build());
        let facts = after.binary_facts().expect("facts");
        assert_eq!(facts.trailer().num_objects(), 5);
        let entries = after
            .document()
            .unwrap()
            .root_value()
            .as_dict()
            .unwrap()
            .entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "k");
        assert_eq!(
            after
                .document()
                .unwrap()
                .get(entries[0].value())
                .unwrap()
                .as_integer()
                .unwrap()
                .value(),
            1
        );
    }

    #[test]
    fn empty_transaction_commits_an_unchanged_document() {
        let document = parse_xml_document(b"<plist version=\"1.0\"><string>x</string></plist>");
        let builder = EditTransactionBuilder::new(&document);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), document.render());
    }

    #[test]
    fn root_set_value_replaces_the_root_value() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_value(EditPath::root(), string_value("root"));
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            b"<plist version=\"1.0\"><string>root</string></plist>"
        );
    }

    #[test]
    fn remove_consumes_leading_whitespace_only() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict>\n  <key>a</key>\n  <integer>1</integer>\n  <key>b</key>\n  <integer>2</integer>\n  <key>c</key>\n  <integer>3</integer>\n</dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_dict_entry(EditPath::root(), key("b"), 0);
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            b"<plist version=\"1.0\"><dict>\n  <key>a</key>\n  <integer>1</integer>\n  <key>c</key>\n  <integer>3</integer>\n</dict></plist>"
        );
    }

    #[test]
    fn insert_dict_entry_duplicate_keys_are_preserved() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>k</key><integer>1</integer></dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_dict_entry(
            EditPath::root(),
            key("k"),
            integer_value(2),
            DictPlacement::End,
        );
        let after = commit(&document, builder.build());
        let entries = root_dict(&after).entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key(), &key("k"));
        assert_eq!(entries[1].key(), &key("k"));
    }

    #[test]
    fn binary_uid_and_special_values_round_trip_through_edits() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x80, 0x2A]); // 0: uid 42
        file.object(&[0x22]); // 1: float32 0.1
        push_be(&mut file.bytes, u64::from(0.1_f32.to_bits()), 4);
        file.object(&[0xA2, 0x00, 0x01]); // 2: array [0, 1]
        let bytes = file.finish(2);
        let document = parse_binary_document(bytes);

        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_value(
                EditPath::new(vec![EditPathStep::ArrayIndex(0)]),
                EditValue::Uid(PlistUid::new(7)),
            )
            .set_value(
                EditPath::new(vec![EditPathStep::ArrayIndex(1)]),
                EditValue::Real(PlistReal::single(0.5_f32)),
            );
        let after = commit(&document, builder.build());
        let elements = after
            .document()
            .unwrap()
            .root_value()
            .as_array()
            .unwrap()
            .elements();
        let first = after
            .document()
            .unwrap()
            .get(elements[0])
            .unwrap()
            .as_uid()
            .unwrap();
        assert_eq!(first.value(), 7);
        let second = after
            .document()
            .unwrap()
            .get(elements[1])
            .unwrap()
            .as_real()
            .unwrap();
        assert_eq!(second.width(), RealWidth::Float32);
        assert_eq!(second.bits(), u64::from(0.5_f32.to_bits()));
    }

    #[test]
    fn escaped_key_content_round_trips_through_rename() {
        let document = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a&amp;b</key><integer>1</integer></dict></plist>",
        );
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_dict_key(EditPath::root(), key("a&b"), 0, key("x<y"));
        let after = commit(&document, builder.build());
        let entries = root_dict(&after).entries();
        assert_eq!(entries[0].key().to_unicode().unwrap(), "x<y");
        assert!(
            std::str::from_utf8(after.render())
                .unwrap()
                .contains("<key>x&lt;y</key>")
        );
    }
}
