//! Snapshot-bound HCL structural edit (RFC 0014 §10).
//!
//! Both profiles publish the same six versioned operations:
//!
//! ```text
//! hcl.edit.set-attribute-value@1
//! hcl.edit.insert-attribute@1
//! hcl.edit.remove-attribute@1
//! hcl.edit.rename-attribute@1
//! hcl.edit.insert-block@1
//! hcl.edit.remove-block@1
//! ```
//!
//! The `hcl.tfvars@1` profile does not publish the block operations (RFC 0014
//! §10): an `insert-block` on a tfvars document fails with
//! `hcl.edit.block-in-tfvars@1`, and no block can exist in a Complete tfvars
//! document, so `remove-block` has no target there.
//!
//! Targets are addressed by a root-relative [`BodyPath`] (block type, exact
//! label sequence, and occurrence select one nested body) plus an attribute
//! name or a block [`NodeRef`]. Attributes are unique per body in a Complete
//! document (RFC 0014 §3 excludes duplicates at formation), so an attribute
//! is addressed by name alone; blocks may repeat with identical type and
//! labels, so a block occurrence is part of the address. Insertion placement
//! is first, last, or after an exact [`NodeRef`] (RFC 0014 §10).
//!
//! Values are supplied as typed native facts ([`EditValue`]) — integer, real,
//! boolean, string, null, tuple, and object — never as raw markup and never
//! as unevaluated expression text. Expression-AST editing and inserting
//! derived expressions are explicit v1 non-goals (RFC 0014 §14); the
//! [`EditValue::Expression`] variant exists so that the refusal is explicit
//! and stable: every commit rejects it with `hcl.edit.unrepresentable@1`.
//! String values render with minimal deterministic escapes (`\n`, `\r`,
//! `\t`, `\"`, `\\`, `\uNNNN` for control characters, and `$${`/`%%{` so the
//! reparse keeps `${`/`%{` as literal text), numbers render their canonical
//! decimal spelling, and tuple/object constructors render one item per line
//! with `=` keys at the target indentation, following the canonical style of
//! RFC 0014 §9.
//!
//! Edits are byte-level like the plist XML side of RFC 0013: each operation
//! resolves against the current reparse, replaces only operation-owned spans
//! of the raw source, keeps every untouched byte, reparses the target after
//! every operation, and verifies the promised HCL semantics per operation —
//! the reparse must be Complete under the base profile, the target must
//! resolve, and the target's reparsed literal value must equal the supplied
//! typed value (numbers by canonical-decimal equality). `remove-attribute`
//! and `remove-block` remove the item's whole line: its leading indentation,
//! the item itself, and the owned trivia through the end of the terminating
//! newline (a trailing line comment is owned trivia). Inserted items render
//! at the indentation of the anchor item (or the canonical
//! two-space-per-depth indentation of an empty body), and an insertion after
//! an end-of-file-terminated item separates itself with a newline.
//!
//! Operations apply sequentially against the evolving document state: a
//! later operation may edit content an earlier operation of the same
//! transaction inserted. Every splice is recorded against the base snapshot;
//! an operation whose span lies inside a replacement an earlier operation
//! wrote folds into that replacement, and commit merges the recorded base
//! spans into maximal non-overlapping runs whose replacements are the exact
//! committed bytes, so the ChangeSet, the `SourcePatch`, and the
//! `UntouchedByteProof` are always self-consistent. The target reparses
//! after every operation, and any failure returns no document and leaves the
//! base byte-exact (atomicity, hard gate 4). Conflict validation covers
//! wrong profile/role/snapshot, incomplete bases, missing or duplicate
//! targets, stale anchors, duplicate-attribute creation, `hcl.tfvars@1`
//! block insertion, unrepresentable values, limit failure, and reparse
//! failure.
//!
//! Commit returns the new `Document`, a complete `ChangeSet`, an
//! `UntouchedByteProof`, and a replayable `SourcePatch`; dry-run returns an
//! `EditPlan` with the identical replacement set and target digest. No
//! operation writes a filesystem path, and none evaluates anything (hard
//! gate 1).

use crate::expression::{
    HclExpressionKind, HclLiteralKey, HclLiteralValue, canonical_decimal, literal_value,
};
use crate::native::{
    HclAttribute, HclBlock, HclBlockLabel, HclBody, HclBodyItem, HclDocument, HclSyntaxKind,
};
use crate::{Document, HclParseLimits, HclProfile};
use consema_core::{FailureKind, OperationKind, StableFailure};
use consema_document::{
    ChangeSet, DocumentAuthority, EditOperationSummary, EditPlan, EditPlanSourceId,
    FatalFormationFailure, FormatOperationId, FormationStatus, NodeMapping, NodeMappingStatus,
    NodeRole, SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch, SourcePatchLimits,
    UntouchedByteProof,
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

/// One root-relative body path step (RFC 0014 §4.2, §10).
///
/// A step selects one block occurrence by exact type, exact label sequence,
/// and 0-based source position among the blocks with the same type and
/// labels; the selected block's nested body is the next level.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BodyPathStep {
    block_type: String,
    labels: Vec<String>,
    occurrence: usize,
}

impl BodyPathStep {
    /// Creates one block step.
    #[must_use]
    pub fn new(
        block_type: impl Into<String>,
        labels: impl Into<Vec<String>>,
        occurrence: usize,
    ) -> Self {
        Self {
            block_type: block_type.into(),
            labels: labels.into(),
            occurrence,
        }
    }

    /// Exact block type of the step.
    #[must_use]
    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    /// Exact label sequence of the step.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// 0-based source position among the blocks with the same type and
    /// labels.
    #[must_use]
    pub const fn occurrence(&self) -> usize {
        self.occurrence
    }
}

/// A root-relative path to one body (RFC 0014 §10).
///
/// The empty path denotes the root body. A step that meets an attribute
/// instead of a block is a role failure; a step that does not exist in the
/// current document state is a missing-target failure.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct BodyPath(Vec<BodyPathStep>);

impl BodyPath {
    /// Root body path.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Creates a path from ordered steps.
    #[must_use]
    pub const fn new(steps: Vec<BodyPathStep>) -> Self {
        Self(steps)
    }

    /// Ordered path steps.
    #[must_use]
    pub fn segments(&self) -> &[BodyPathStep] {
        &self.0
    }

    /// Creates a child path without modifying this path.
    #[must_use]
    pub fn child(&self, step: BodyPathStep) -> Self {
        let mut steps = self.0.clone();
        steps.push(step);
        Self(steps)
    }
}

/// One exact body item address (RFC 0014 §10).
///
/// An attribute is addressed by owning body and name — unique per body in a
/// Complete document (RFC 0014 §3). A block is addressed by owning body,
/// type, exact label sequence, and occurrence, because blocks with the same
/// type and labels may repeat (RFC 0014 §6).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NodeRef {
    /// One attribute occurrence.
    Attribute {
        /// Owning body.
        body: BodyPath,
        /// Exact attribute name.
        name: String,
    },
    /// One block occurrence.
    Block {
        /// Owning body.
        body: BodyPath,
        /// Exact block type.
        block_type: String,
        /// Exact label sequence.
        labels: Vec<String>,
        /// 0-based source position among the equal-type-and-labels blocks.
        occurrence: usize,
    },
}

impl NodeRef {
    /// Owning body path of the addressed item.
    #[must_use]
    pub const fn body_path(&self) -> &BodyPath {
        match self {
            Self::Attribute { body, .. } | Self::Block { body, .. } => body,
        }
    }
}

/// Attribute insertion placement inside one body (RFC 0014 §10).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BodyPlacement {
    /// Insert before the body's first item (or at the body content start of
    /// an empty body).
    First,
    /// Insert after the body's last item's terminating line (or at the body
    /// content end of an empty body).
    Last,
    /// Insert immediately after the item addressed by one exact NodeRef of
    /// the same body.
    After(NodeRef),
}

/// One typed literal-complete HCL value supplied to an edit (RFC 0014 §10).
///
/// Values are typed native facts, never raw markup and never unevaluated
/// expression text. Numbers are canonical-decimal facts: an integer renders
/// its exact decimal spelling, a real renders the canonical decimal of its
/// shortest-round-trip spelling (non-finite reals are refused with
/// `hcl.edit.unrepresentable@1`). Strings render with minimal deterministic
/// escapes. Tuples and objects are ordered with duplicate object keys
/// preserved, never collapsed (RFC 0014 §4.6). The [`Self::Expression`]
/// variant exists so that derived-expression insertion is refused explicitly
/// with `hcl.edit.unrepresentable@1`; no commit ever renders it (RFC 0014
/// §10, §14).
#[derive(Clone, Debug)]
pub enum EditValue {
    /// Signed 64-bit integer.
    Integer(i64),
    /// IEEE 754 real; must be finite.
    Real(f64),
    /// Exact string content.
    String(String),
    /// Boolean.
    Boolean(bool),
    /// Null.
    Null,
    /// Ordered tuple of literal values.
    Tuple(Vec<EditValue>),
    /// Ordered object entries; duplicate keys are preserved.
    Object(Vec<(EditKey, EditValue)>),
    /// A derived expression: refused by every commit with
    /// `hcl.edit.unrepresentable@1`.
    Expression {
        /// Expression kind spelling (for example `"binary"`).
        kind: String,
        /// Expression source text.
        text: String,
    },
}

impl EditValue {
    /// Stable value-kind spelling for summaries.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::String(_) => "string",
            Self::Boolean(_) => "boolean",
            Self::Null => "null",
            Self::Tuple(_) => "tuple",
            Self::Object(_) => "object",
            Self::Expression { .. } => "expression",
        }
    }
}

impl PartialEq for EditValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(left), Self::Integer(right)) => left == right,
            // Total equality over the exact bit pattern; NaN payloads are
            // refused at commit anyway (hard gate 4).
            (Self::Real(left), Self::Real(right)) => left.to_bits() == right.to_bits(),
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Null, Self::Null) => true,
            (Self::Tuple(left), Self::Tuple(right)) => left == right,
            (Self::Object(left), Self::Object(right)) => left == right,
            (
                Self::Expression {
                    kind: left_kind,
                    text: left_text,
                },
                Self::Expression {
                    kind: right_kind,
                    text: right_text,
                },
            ) => left_kind == right_kind && left_text == right_text,
            _ => false,
        }
    }
}

/// One object-constructor literal key (RFC 0014 §4.6, §8.1).
///
/// The bare forms are an identifier, a number literal, and a quoted literal
/// string; the parenthesized-expression key form is not part of the edit
/// surface. An identifier key spelled `for` is refused, because the
/// for-expression interpretation has priority in an object constructor
/// (RFC 0014 §4.6).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EditKey {
    /// Bare identifier key.
    Identifier(String),
    /// Bare number-literal key.
    Number(i64),
    /// Bare quoted-literal-string key.
    String(String),
}

/// One snapshot-bound HCL structural operation (RFC 0014 §10).
///
/// Every body path, name, and occurrence refers to the document state as of
/// the operation's own application: operations of one transaction apply
/// sequentially, so a later operation may target content an earlier
/// insertion created.
#[derive(Clone, Debug, PartialEq)]
pub enum EditOperation {
    /// Replaces the target attribute's expression span with the canonical
    /// rendering of one typed literal-complete value.
    SetAttributeValue {
        /// Owning body of the target attribute.
        body: BodyPath,
        /// Exact target attribute name.
        attribute: String,
        /// New typed literal value.
        value: EditValue,
    },
    /// Adds one attribute to a target body at a position anchor.
    InsertAttribute {
        /// Target body.
        body: BodyPath,
        /// New attribute name.
        name: String,
        /// New typed literal value.
        value: EditValue,
        /// Explicit placement inside the body.
        placement: BodyPlacement,
    },
    /// Removes one attribute's name, equals, expression, and owned trivia.
    RemoveAttribute {
        /// Owning body of the target attribute.
        body: BodyPath,
        /// Exact target attribute name.
        attribute: String,
    },
    /// Changes one attribute name, preserving its expression.
    RenameAttribute {
        /// Owning body of the target attribute.
        body: BodyPath,
        /// Exact target attribute name.
        attribute: String,
        /// New attribute name.
        name: String,
    },
    /// Adds one block (type, labels, and a nested body whose attributes are
    /// typed literal-complete values) to a target body.
    InsertBlock {
        /// Target body.
        body: BodyPath,
        /// New block type.
        block_type: String,
        /// New label sequence; labels always render quoted.
        labels: Vec<String>,
        /// Ordered nested attributes of the new block.
        attributes: Vec<(String, EditValue)>,
        /// Explicit placement inside the body.
        placement: BodyPlacement,
    },
    /// Removes one block by exact type, labels, and occurrence.
    RemoveBlock {
        /// Owning body of the target block.
        body: BodyPath,
        /// Exact target block type.
        block_type: String,
        /// Exact target label sequence.
        labels: Vec<String>,
        /// 0-based source position among the equal-type-and-labels blocks.
        occurrence: usize,
    },
}

/// Immutable snapshot-bound transaction.
#[derive(Clone, Debug, PartialEq)]
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

    /// Replaces one attribute value.
    pub fn set_attribute_value(
        &mut self,
        body: BodyPath,
        attribute: &str,
        value: EditValue,
    ) -> &mut Self {
        self.operations.push(EditOperation::SetAttributeValue {
            body,
            attribute: attribute.to_owned(),
            value,
        });
        self
    }

    /// Inserts one attribute into a body.
    pub fn insert_attribute(
        &mut self,
        body: BodyPath,
        name: &str,
        value: EditValue,
        placement: BodyPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertAttribute {
            body,
            name: name.to_owned(),
            value,
            placement,
        });
        self
    }

    /// Removes one attribute.
    pub fn remove_attribute(&mut self, body: BodyPath, attribute: &str) -> &mut Self {
        self.operations.push(EditOperation::RemoveAttribute {
            body,
            attribute: attribute.to_owned(),
        });
        self
    }

    /// Renames one attribute.
    pub fn rename_attribute(&mut self, body: BodyPath, attribute: &str, name: &str) -> &mut Self {
        self.operations.push(EditOperation::RenameAttribute {
            body,
            attribute: attribute.to_owned(),
            name: name.to_owned(),
        });
        self
    }

    /// Inserts one block into a body.
    pub fn insert_block(
        &mut self,
        body: BodyPath,
        block_type: &str,
        labels: Vec<String>,
        attributes: Vec<(String, EditValue)>,
        placement: BodyPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertBlock {
            body,
            block_type: block_type.to_owned(),
            labels,
            attributes,
            placement,
        });
        self
    }

    /// Removes one block.
    pub fn remove_block(
        &mut self,
        body: BodyPath,
        block_type: &str,
        labels: Vec<String>,
        occurrence: usize,
    ) -> &mut Self {
        self.operations.push(EditOperation::RemoveBlock {
            body,
            block_type: block_type.to_owned(),
            labels,
            occurrence,
        });
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
    /// A body path step meets an attribute instead of a block.
    WrongRole,
    /// The base document is not `Complete`, or a target, occurrence, or
    /// placement anchor does not exist in the current document state.
    IncompleteTarget,
    /// An insertion or rename would create a second attribute with the same
    /// name in one body.
    DuplicateAttribute,
    /// A block operation was declared under the `hcl.tfvars@1` profile.
    BlockInTfvars,
    /// Two operations map to the same exact base position.
    ConflictingEdits,
    /// One operation's source span contains bytes an earlier operation of
    /// the same transaction replaced. The sequential model folds operations
    /// whose spans lie inside earlier replacements and merges overlapping
    /// base spans at commit, so this variant has no emission path in this
    /// crate; it remains part of the stable failure surface.
    OverlappingOwnership,
    /// A typed value or name cannot be expressed as literal-complete HCL;
    /// the payload names the blocking native fact.
    UnrepresentableValue(&'static str),
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// The replacement document could not be formed under the original
    /// limits, or the reparsed target does not carry the promised semantics.
    NewDocumentFormationFailed,
}

impl StableFailure for EditFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Edit
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::WrongSnapshot => FailureKind::TargetMismatch,
            Self::WrongRole | Self::IncompleteTarget => FailureKind::NotApplicable,
            Self::DuplicateAttribute
            | Self::BlockInTfvars
            | Self::ConflictingEdits
            | Self::OverlappingOwnership
            | Self::UnrepresentableValue(_) => FailureKind::InvalidInput,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::IncompleteTarget => "core.edit.incomplete-target@1",
            Self::DuplicateAttribute => "hcl.edit.duplicate-attribute@1",
            Self::BlockInTfvars => "hcl.edit.block-in-tfvars@1",
            Self::ConflictingEdits | Self::OverlappingOwnership => "core.edit.conflicting-edits@1",
            Self::UnrepresentableValue(_) => "hcl.edit.unrepresentable@1",
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
        limits: HclParseLimits,
    ) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if self.status() != FormationStatus::Complete {
            return Err(EditFailure::IncompleteTarget);
        }
        if transaction.operations.len() > limits.max_report_events {
            return Err(EditFailure::ResourceLimit("report-events"));
        }
        let profile = self.selector();
        let mut bytes = self.render().to_vec();
        let mut edits: Vec<AppliedEdit> = Vec::new();
        let mut current = self.clone();
        for operation in &transaction.operations {
            let (splices, verify) = prepare_operation(&current, operation)?;
            apply_step(&mut edits, &mut bytes, limits, &splices)?;
            let formed = Document::parse(Arc::from(bytes.clone()), profile, limits)
                .map_err(|fatal| map_fatal(&fatal))?;
            if formed.status() != FormationStatus::Complete {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            verify_operation(&formed, operation, &verify)?;
            current = formed;
        }
        let final_document = if transaction.operations.is_empty() {
            let formed = Document::parse(Arc::from(bytes), profile, limits)
                .map_err(|fatal| map_fatal(&fatal))?;
            if formed.status() != FormationStatus::Complete {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            formed
        } else {
            current
        };
        build_commit(self, transaction, final_document, edits)
    }
}

/// Per-operation data the post-application verification needs beyond the
/// operation itself.
enum VerifyData {
    /// No extra facts.
    None,
    /// The pre-operation expression kind a rename must preserve.
    RenameKind(HclExpressionKind),
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
    /// Implementation-owned structural region: HCL has no structural regions
    /// (unlike the plist binary offset table), so this flag is always
    /// `false`; it remains part of the shared fold machinery.
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
        // A zero-width insertion exactly at the region end is not operation
        // content of the region's owner and is recorded on its own.
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

/// Applies one step's splices: validates the target length against the
/// source bound first (hard gate 4), records every splice against the base
/// coordinates, then builds the new bytes in one pass.
fn apply_step(
    edits: &mut Vec<AppliedEdit>,
    bytes: &mut Vec<u8>,
    limits: HclParseLimits,
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

/// One zero-width or full replacement splice.
fn splice(pre_start: usize, pre_len: usize, replacement: Vec<u8>) -> AppliedEdit {
    AppliedEdit {
        pre_start,
        pre_len,
        replacement: Arc::from(replacement),
        structural: false,
    }
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

// ---------------------------------------------------------------------------
// Byte-level layout and resolution
// ---------------------------------------------------------------------------

/// Lossless piece facts of one formed document, indexed for boundary walks.
struct PieceIndex {
    starts: Vec<usize>,
    ends: Vec<usize>,
    kinds: Vec<HclSyntaxKind>,
}

impl PieceIndex {
    /// Builds the parallel piece facts of one document.
    fn new(document: &Document) -> Self {
        let pieces = document.lossless_structural_index().pieces();
        let kinds = document.lossless_syntax_kinds();
        let mut starts = Vec::with_capacity(pieces.len());
        let mut ends = Vec::with_capacity(pieces.len());
        let mut kinds_out = Vec::with_capacity(pieces.len());
        for (piece, kind) in pieces.iter().zip(kinds.iter().copied()) {
            starts.push(piece.span().start_byte());
            ends.push(piece.span().end_byte());
            kinds_out.push(kind);
        }
        Self {
            starts,
            ends,
            kinds: kinds_out,
        }
    }

    /// Index of the piece starting exactly at `pos`; `None` at end of file.
    fn piece_starting_at(&self, pos: usize) -> Option<usize> {
        let index = self.starts.partition_point(|start| *start < pos);
        (index < self.starts.len() && self.starts[index] == pos).then_some(index)
    }

    /// Index of the piece ending exactly at `pos`; `None` at position zero.
    fn piece_ending_at(&self, pos: usize) -> Option<usize> {
        if pos == 0 {
            return None;
        }
        let index = self.starts.partition_point(|start| *start < pos);
        if index == 0 {
            return None;
        }
        let previous = index - 1;
        (self.ends[previous] == pos).then_some(previous)
    }
}

/// Resolves one body path against one native document; the empty path is the
/// root body. Returns the target body and, for a nested target, the owning
/// block of the last path step.
fn resolve_body<'a>(
    document: &'a HclDocument,
    path: &BodyPath,
) -> Result<(&'a HclBody, Option<&'a HclBlock>), EditFailure> {
    let mut body = document.body();
    let mut parent = None;
    for step in path.segments() {
        let Some(block) = find_block(body, &step.block_type, &step.labels, step.occurrence) else {
            if body.items().iter().any(|item| {
                item.as_attribute()
                    .is_some_and(|a| a.name() == step.block_type)
            }) {
                return Err(EditFailure::WrongRole);
            }
            return Err(EditFailure::IncompleteTarget);
        };
        parent = Some(block);
        body = block.body();
    }
    Ok((body, parent))
}

/// One attribute occurrence by exact name; attributes are unique per body in
/// a Complete document (RFC 0014 §3).
fn find_attribute<'a>(body: &'a HclBody, name: &str) -> Option<&'a HclAttribute> {
    body.items()
        .iter()
        .filter_map(HclBodyItem::as_attribute)
        .find(|attribute| attribute.name() == name)
}

/// One block occurrence by exact type, label sequence, and occurrence.
fn find_block<'a>(
    body: &'a HclBody,
    block_type: &str,
    labels: &[String],
    occurrence: usize,
) -> Option<&'a HclBlock> {
    let mut seen = 0;
    for item in body.items() {
        if let Some(block) = item.as_block() {
            if block.block_type() == block_type
                && block
                    .labels()
                    .iter()
                    .map(HclBlockLabel::text)
                    .eq(labels.iter().map(String::as_str))
            {
                if seen == occurrence {
                    return Some(block);
                }
                seen += 1;
            }
        }
    }
    None
}

/// Items-index position of one block occurrence.
fn block_position(
    body: &HclBody,
    block_type: &str,
    labels: &[String],
    occurrence: usize,
) -> Option<usize> {
    let mut seen = 0;
    for (position, item) in body.items().iter().enumerate() {
        if let Some(block) = item.as_block() {
            if block.block_type() == block_type
                && block
                    .labels()
                    .iter()
                    .map(HclBlockLabel::text)
                    .eq(labels.iter().map(String::as_str))
            {
                if seen == occurrence {
                    return Some(position);
                }
                seen += 1;
            }
        }
    }
    None
}

/// Resolves one exact item address against one native document.
fn resolve_node<'a>(
    document: &'a HclDocument,
    node_ref: &NodeRef,
) -> Result<&'a HclBodyItem, EditFailure> {
    match node_ref {
        NodeRef::Attribute { body, name } => {
            let (target_body, _) = resolve_body(document, body)?;
            let position = target_body
                .items()
                .iter()
                .position(|item| item.as_attribute().is_some_and(|a| a.name() == name))
                .ok_or(EditFailure::IncompleteTarget)?;
            Ok(&target_body.items()[position])
        }
        NodeRef::Block {
            body,
            block_type,
            labels,
            occurrence,
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            let position = block_position(target_body, block_type, labels, *occurrence)
                .ok_or(EditFailure::IncompleteTarget)?;
            Ok(&target_body.items()[position])
        }
    }
}

/// Start byte of one item's own span (the name or block-type identifier).
fn item_span_start(item: &HclBodyItem) -> usize {
    match item {
        HclBodyItem::Attribute(attribute) => attribute.name_span().start_byte(),
        HclBodyItem::Block(block) => block.span().start_byte(),
    }
}

/// End byte of one item's own span (the expression end or the closing
/// brace).
fn item_span_end(item: &HclBodyItem) -> usize {
    match item {
        HclBodyItem::Attribute(attribute) => attribute.expression().span().end_byte(),
        HclBodyItem::Block(block) => block.span().end_byte(),
    }
}

/// End of the line that terminates the item ending at `from`: the end of the
/// first `LineBreak` piece at or after `from` that is not inside an inline
/// comment (inline-comment pieces span their internal newlines), or `from`
/// itself when the item is end-of-file-terminated. Everything between `from`
/// and the returned position is owned trivia: whitespace, line comments, and
/// inline comments.
///
/// A non-trivia piece before any terminator is impossible in a Complete
/// document and fails defensively.
fn item_line_end(index: &PieceIndex, from: usize) -> Result<usize, EditFailure> {
    let mut pos = from;
    loop {
        let Some(piece) = index.piece_starting_at(pos) else {
            return Ok(pos);
        };
        // `piece` is in-bounds by construction (piece_starting_at), but
        // matching the index expression directly trips the 1.85-only
        // clippy::match_on_vec_items noise lint; bind the kind first.
        let kind = index.kinds[piece];
        match kind {
            HclSyntaxKind::Whitespace
            | HclSyntaxKind::LineComment
            | HclSyntaxKind::InlineComment => pos = index.ends[piece],
            HclSyntaxKind::LineBreak => return Ok(index.ends[piece]),
            _ => return Err(EditFailure::NewDocumentFormationFailed),
        }
    }
}

/// Start of the line that begins at `item_start`: the beginning of the
/// whitespace run that indents the item, so a first-position insertion lands
/// before the item's indentation instead of after it.
fn item_line_start(index: &PieceIndex, item_start: usize) -> usize {
    let mut pos = item_start;
    while let Some(piece) = index.piece_ending_at(pos) {
        if index.kinds[piece] != HclSyntaxKind::Whitespace {
            break;
        }
        pos = index.starts[piece];
    }
    pos
}

/// Leading whitespace run of the line that starts an item, used as the
/// indentation of inserted markup so continuation lines and new items align
/// with their anchor.
fn item_indent(index: &PieceIndex, document: &HclDocument, item_start: usize) -> String {
    let source = document.snapshot().bytes();
    let mut pos = item_start;
    let mut indent = String::new();
    while let Some(piece) = index.piece_ending_at(pos) {
        if index.kinds[piece] != HclSyntaxKind::Whitespace {
            break;
        }
        let start = index.starts[piece];
        let end = index.ends[piece];
        // Whitespace pieces are space or tab only (RFC 0014 §4.1).
        indent.insert_str(
            0,
            &source[start..end]
                .iter()
                .map(|byte| char::from(*byte))
                .collect::<String>(),
        );
        pos = start;
    }
    indent
}

/// Byte positions of one block's own braces: the end of its opening `{` and
/// the start of its closing `}`. The first `BraceOpen` piece in the block
/// span is the block's own opener (a block header contains no braces), and
/// the last `BraceClose` piece is its own closer.
fn block_brace_positions(
    index: &PieceIndex,
    block_span: (usize, usize),
) -> Result<(usize, usize), EditFailure> {
    let mut open_end: Option<usize> = None;
    let mut close_start: Option<usize> = None;
    for (position, &start) in index.starts.iter().enumerate() {
        if start >= block_span.1 {
            break;
        }
        if start < block_span.0 {
            continue;
        }
        // `position` is in-bounds (enumerated from the parallel starts
        // vector), but matching the index expression directly trips the
        // 1.85-only clippy::match_on_vec_items noise lint; bind first.
        let kind = index.kinds[position];
        match kind {
            HclSyntaxKind::BraceOpen if open_end.is_none() => open_end = Some(index.ends[position]),
            HclSyntaxKind::BraceClose => close_start = Some(start),
            _ => {}
        }
    }
    Ok((
        open_end.ok_or(EditFailure::NewDocumentFormationFailed)?,
        close_start.ok_or(EditFailure::NewDocumentFormationFailed)?,
    ))
}

/// Insertion point facts of an empty target body: the content-end position
/// (the owning block's closing brace, or the source length for the root
/// body) and the canonical two-space-per-depth indentation.
fn empty_body_point(
    index: &PieceIndex,
    document: &HclDocument,
    body_path: &BodyPath,
    parent: Option<&HclBlock>,
) -> Result<(usize, String), EditFailure> {
    match parent {
        None => Ok((document.snapshot().bytes().len(), String::new())),
        Some(block) => {
            let (_, close_start) =
                block_brace_positions(index, (block.span().start_byte(), block.span().end_byte()))?;
            Ok((close_start, "  ".repeat(body_path.segments().len())))
        }
    }
}

/// Computes the insertion point, markup indentation, and whether the markup
/// needs a separating leading newline (the anchor item is end-of-file
/// terminated) for one insertion placement.
fn insertion_point(
    index: &PieceIndex,
    document: &HclDocument,
    body_path: &BodyPath,
    body: &HclBody,
    parent: Option<&HclBlock>,
    placement: &BodyPlacement,
) -> Result<(usize, String, bool), EditFailure> {
    let items = body.items();
    match placement {
        BodyPlacement::First => {
            if let Some(item) = items.first() {
                let start = item_span_start(item);
                Ok((
                    item_line_start(index, start),
                    item_indent(index, document, start),
                    false,
                ))
            } else {
                let (point, indent) = empty_body_point(index, document, body_path, parent)?;
                Ok((point, indent, false))
            }
        }
        BodyPlacement::Last => {
            if let Some(item) = items.last() {
                let end = item_span_end(item);
                let line_end = item_line_end(index, end)?;
                let eof_terminated = line_end == end;
                Ok((
                    line_end,
                    item_indent(index, document, item_span_start(item)),
                    eof_terminated,
                ))
            } else {
                let (point, indent) = empty_body_point(index, document, body_path, parent)?;
                Ok((point, indent, false))
            }
        }
        BodyPlacement::After(node_ref) => {
            if node_ref.body_path() != body_path {
                return Err(EditFailure::IncompleteTarget);
            }
            let anchor = resolve_node(document, node_ref)?;
            let end = item_span_end(anchor);
            let line_end = item_line_end(index, end)?;
            let eof_terminated = line_end == end;
            Ok((
                line_end,
                item_indent(index, document, item_span_start(anchor)),
                eof_terminated,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Operation preparation
// ---------------------------------------------------------------------------

/// Resolves one operation against the current state and computes its splices
/// in the current state's coordinates, plus the data its post-application
/// verification needs.
fn prepare_operation(
    current: &Document,
    operation: &EditOperation,
) -> Result<(Vec<AppliedEdit>, VerifyData), EditFailure> {
    let index = PieceIndex::new(current);
    let document = current.document();
    match operation {
        EditOperation::SetAttributeValue {
            body,
            attribute,
            value,
        } => {
            check_value(value)?;
            let (target_body, _) = resolve_body(document, body)?;
            let attribute_ref =
                find_attribute(target_body, attribute).ok_or(EditFailure::IncompleteTarget)?;
            let indent = item_indent(&index, document, attribute_ref.name_span().start_byte());
            let rendered = render_value(value, &indent)?;
            let start = attribute_ref.expression().span().start_byte();
            let end = attribute_ref.expression().span().end_byte();
            Ok((
                vec![splice(start, end - start, rendered.into_bytes())],
                VerifyData::None,
            ))
        }
        EditOperation::InsertAttribute {
            body,
            name,
            value,
            placement,
        } => {
            let (target_body, parent) = resolve_body(document, body)?;
            if !is_valid_identifier(name) {
                return Err(EditFailure::UnrepresentableValue("identifier"));
            }
            if find_attribute(target_body, name).is_some() {
                return Err(EditFailure::DuplicateAttribute);
            }
            check_value(value)?;
            let (point, indent, leading_newline) =
                insertion_point(&index, document, body, target_body, parent, placement)?;
            let mut markup = if leading_newline {
                "\n".to_owned()
            } else {
                String::new()
            };
            markup.push_str(&indent);
            markup.push_str(name);
            markup.push_str(" = ");
            markup.push_str(&render_value(value, &indent)?);
            markup.push('\n');
            Ok((
                vec![splice(point, 0, markup.into_bytes())],
                VerifyData::None,
            ))
        }
        EditOperation::RemoveAttribute { body, attribute } => {
            let (target_body, _) = resolve_body(document, body)?;
            let attribute_ref =
                find_attribute(target_body, attribute).ok_or(EditFailure::IncompleteTarget)?;
            // The removal owns the item's line: its leading indentation, the
            // name, equals, and expression, and the owned trivia through the
            // terminating newline.
            let start = item_line_start(&index, attribute_ref.name_span().start_byte());
            let end = item_line_end(&index, attribute_ref.expression().span().end_byte())?;
            Ok((
                vec![splice(start, end - start, Vec::new())],
                VerifyData::None,
            ))
        }
        EditOperation::RenameAttribute {
            body,
            attribute,
            name,
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            let attribute_ref =
                find_attribute(target_body, attribute).ok_or(EditFailure::IncompleteTarget)?;
            if !is_valid_identifier(name) {
                return Err(EditFailure::UnrepresentableValue("identifier"));
            }
            let kind = attribute_ref.expression().kind().clone();
            if attribute == name {
                return Ok((Vec::new(), VerifyData::RenameKind(kind)));
            }
            if find_attribute(target_body, name).is_some() {
                return Err(EditFailure::DuplicateAttribute);
            }
            let start = attribute_ref.name_span().start_byte();
            let end = attribute_ref.name_span().end_byte();
            Ok((
                vec![splice(start, end - start, name.as_bytes().to_vec())],
                VerifyData::RenameKind(kind),
            ))
        }
        EditOperation::InsertBlock {
            body,
            block_type,
            labels,
            attributes,
            placement,
        } => {
            // The profile gate precedes every target check: a block
            // operation can never succeed under the tfvars profile.
            if current.selector() == HclProfile::TfvarsV1 {
                return Err(EditFailure::BlockInTfvars);
            }
            if !is_valid_identifier(block_type) {
                return Err(EditFailure::UnrepresentableValue("identifier"));
            }
            let mut seen = HashSet::new();
            for (name, value) in attributes {
                if !is_valid_identifier(name) {
                    return Err(EditFailure::UnrepresentableValue("identifier"));
                }
                if !seen.insert(name) {
                    return Err(EditFailure::DuplicateAttribute);
                }
                check_value(value)?;
            }
            let (target_body, parent) = resolve_body(document, body)?;
            let (point, indent, leading_newline) =
                insertion_point(&index, document, body, target_body, parent, placement)?;
            let mut markup = if leading_newline {
                "\n".to_owned()
            } else {
                String::new()
            };
            markup.push_str(&block_markup(&indent, block_type, labels, attributes)?);
            Ok((
                vec![splice(point, 0, markup.into_bytes())],
                VerifyData::None,
            ))
        }
        EditOperation::RemoveBlock {
            body,
            block_type,
            labels,
            occurrence,
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            let Some(block_ref) = find_block(target_body, block_type, labels, *occurrence) else {
                if target_body
                    .items()
                    .iter()
                    .any(|item| item.as_attribute().is_some_and(|a| a.name() == block_type))
                {
                    return Err(EditFailure::WrongRole);
                }
                return Err(EditFailure::IncompleteTarget);
            };
            let start = item_line_start(&index, block_ref.span().start_byte());
            let end = item_line_end(&index, block_ref.span().end_byte())?;
            Ok((
                vec![splice(start, end - start, Vec::new())],
                VerifyData::None,
            ))
        }
    }
}

/// Rejects one typed value that cannot be expressed as literal-complete HCL:
/// a non-finite real, an object key that is not a bare
/// identifier/number/string (including the reserved `for` spelling), or any
/// expression value (RFC 0014 §8.1, §10, §14).
fn check_value(value: &EditValue) -> Result<(), EditFailure> {
    match value {
        EditValue::Real(real) if !real.is_finite() => {
            Err(EditFailure::UnrepresentableValue("real"))
        }
        EditValue::Integer(_)
        | EditValue::Boolean(_)
        | EditValue::Null
        | EditValue::String(_)
        | EditValue::Real(_) => Ok(()),
        EditValue::Tuple(elements) => elements.iter().try_for_each(check_value),
        EditValue::Object(entries) => entries.iter().try_for_each(|(key, entry_value)| {
            check_key(key)?;
            check_value(entry_value)
        }),
        EditValue::Expression { .. } => Err(EditFailure::UnrepresentableValue("expression")),
    }
}

/// Rejects one object key that cannot be expressed as a bare literal key.
fn check_key(key: &EditKey) -> Result<(), EditFailure> {
    match key {
        EditKey::Identifier(name) if is_valid_identifier(name) && name != "for" => Ok(()),
        EditKey::Identifier(_) => Err(EditFailure::UnrepresentableValue("object-key")),
        EditKey::Number(_) | EditKey::String(_) => Ok(()),
    }
}

/// Whether one spelling is a valid UAX #31 identifier without a leading
/// underscore, matching the frozen lexer rule (RFC 0014 §4.1, §12 D-4).
fn is_valid_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first != '_'
        && unicode_ident::is_xid_start(first)
        && characters.all(|c| c == '-' || unicode_ident::is_xid_continue(c))
}

/// Minimal deterministic quoted-template spelling of one string (RFC 0014
/// §9): `\n`, `\r`, `\t`, `\"`, `\\`, `\uNNNN` for other control characters,
/// and `$${`/`%%{` so the reparse keeps `${`/`%{` as literal text.
fn quote_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if characters.peek() == Some(&'{') => {
                out.push_str("$${");
                characters.next();
            }
            '%' if characters.peek() == Some(&'{') => {
                out.push_str("%%{");
                characters.next();
            }
            character if character < '\u{20}' || character == '\u{7F}' => {
                let _ = write!(out, "\\u{:04X}", u32::from(character));
            }
            _ => out.push(character),
        }
    }
    out.push('"');
    out
}

/// Canonical decimal spelling of one finite real, by pure decimal string
/// arithmetic over its shortest-round-trip spelling (hard gate 1): the sign
/// is reattached to the canonical magnitude, and `-0` normalizes to `0`.
fn canonical_real(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    let text = value.to_string();
    match text.strip_prefix('-') {
        Some(magnitude) => canonical_decimal(magnitude).map(|canonical| {
            if canonical == "0" {
                canonical
            } else {
                format!("-{canonical}")
            }
        }),
        None => canonical_decimal(&text),
    }
}

/// Canonical expression text of one typed literal value at one base
/// indentation; constructor continuation lines render one item per line at
/// the base indentation plus two spaces (RFC 0014 §9).
fn render_value(value: &EditValue, indent: &str) -> Result<String, EditFailure> {
    match value {
        EditValue::Integer(integer) => Ok(integer.to_string()),
        EditValue::Real(real) => {
            canonical_real(*real).ok_or(EditFailure::UnrepresentableValue("real"))
        }
        EditValue::String(text) => Ok(quote_escape(text)),
        EditValue::Boolean(boolean) => Ok(if *boolean {
            "true".to_owned()
        } else {
            "false".to_owned()
        }),
        EditValue::Null => Ok("null".to_owned()),
        EditValue::Tuple(elements) => {
            if elements.is_empty() {
                return Ok("[]".to_owned());
            }
            let inner = format!("{indent}  ");
            let mut out = String::from("[\n");
            for (position, element) in elements.iter().enumerate() {
                if position > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner);
                out.push_str(&render_value(element, &inner)?);
            }
            out.push('\n');
            out.push_str(indent);
            out.push(']');
            Ok(out)
        }
        EditValue::Object(entries) => {
            if entries.is_empty() {
                return Ok("{}".to_owned());
            }
            let inner = format!("{indent}  ");
            let mut out = String::from("{\n");
            for (position, (key, entry_value)) in entries.iter().enumerate() {
                if position > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner);
                out.push_str(&render_key(key));
                out.push_str(" = ");
                out.push_str(&render_value(entry_value, &inner)?);
            }
            out.push('\n');
            out.push_str(indent);
            out.push('}');
            Ok(out)
        }
        EditValue::Expression { .. } => Err(EditFailure::UnrepresentableValue("expression")),
    }
}

/// Bare spelling of one object key; validity is pre-checked by
/// [`check_key`].
fn render_key(key: &EditKey) -> String {
    match key {
        EditKey::Identifier(name) => name.clone(),
        EditKey::Number(number) => number.to_string(),
        EditKey::String(text) => quote_escape(text),
    }
}

/// Canonical block text at one base indentation: `type "label" {` header,
/// two-space-indented nested attributes, closing brace, and a trailing
/// newline; labels always render quoted (RFC 0014 §9).
fn block_markup(
    indent: &str,
    block_type: &str,
    labels: &[String],
    attributes: &[(String, EditValue)],
) -> Result<String, EditFailure> {
    let mut out = String::new();
    out.push_str(indent);
    out.push_str(block_type);
    for label in labels {
        out.push(' ');
        out.push_str(&quote_escape(label));
    }
    out.push_str(" {\n");
    let inner = format!("{indent}  ");
    for (name, value) in attributes {
        out.push_str(&inner);
        out.push_str(name);
        out.push_str(" = ");
        out.push_str(&render_value(value, &inner)?);
        out.push('\n');
    }
    out.push_str(indent);
    out.push_str("}\n");
    Ok(out)
}

/// Verifies the promised HCL semantics of one operation against the
/// reparse of the state immediately after its application: the target
/// resolves, a rename preserves its expression kind, a removal is gone, and
/// every promised literal value equals the reparsed literal (numbers by
/// canonical-decimal equality, RFC 0014 §6, §9).
fn verify_operation(
    formed: &Document,
    operation: &EditOperation,
    data: &VerifyData,
) -> Result<(), EditFailure> {
    let document = formed.document();
    match operation {
        EditOperation::SetAttributeValue {
            body,
            attribute,
            value,
        }
        | EditOperation::InsertAttribute {
            body,
            name: attribute,
            value,
            ..
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            let attribute_ref = find_attribute(target_body, attribute)
                .ok_or(EditFailure::NewDocumentFormationFailed)?;
            let literal = literal_value(attribute_ref.expression())
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            if !edit_value_matches_literal(value, &literal) {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            Ok(())
        }
        EditOperation::RemoveAttribute { body, attribute } => {
            let (target_body, _) = resolve_body(document, body)?;
            if find_attribute(target_body, attribute).is_some() {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            Ok(())
        }
        EditOperation::RenameAttribute { body, name, .. } => {
            let VerifyData::RenameKind(expected) = data else {
                return Err(EditFailure::NewDocumentFormationFailed);
            };
            let (target_body, _) = resolve_body(document, body)?;
            let attribute_ref =
                find_attribute(target_body, name).ok_or(EditFailure::NewDocumentFormationFailed)?;
            if attribute_ref.expression().kind() != expected {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            Ok(())
        }
        EditOperation::InsertBlock {
            body,
            block_type,
            labels,
            attributes,
            ..
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            for item in target_body.items() {
                if let Some(block) = item.as_block() {
                    if block.block_type() == block_type
                        && block
                            .labels()
                            .iter()
                            .map(HclBlockLabel::text)
                            .eq(labels.iter().map(String::as_str))
                        && block_body_matches(block, attributes)?
                    {
                        return Ok(());
                    }
                }
            }
            Err(EditFailure::NewDocumentFormationFailed)
        }
        EditOperation::RemoveBlock {
            body,
            block_type,
            labels,
            occurrence,
        } => {
            let (target_body, _) = resolve_body(document, body)?;
            if find_block(target_body, block_type, labels, *occurrence).is_some() {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
            Ok(())
        }
    }
}

/// Whether one block's nested body carries exactly the promised attributes
/// with the promised literal values.
fn block_body_matches(
    block: &HclBlock,
    attributes: &[(String, EditValue)],
) -> Result<bool, EditFailure> {
    let items = block.body().items();
    if items
        .iter()
        .filter(|item| item.as_attribute().is_some())
        .count()
        != attributes.len()
    {
        return Ok(false);
    }
    for (name, value) in attributes {
        let Some(attribute_ref) = find_attribute(block.body(), name) else {
            return Ok(false);
        };
        let literal = literal_value(attribute_ref.expression())
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        if !edit_value_matches_literal(value, &literal) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether one typed edit value equals one reparsed literal; numbers compare
/// by canonical-decimal value equality across the integer/real kind boundary
/// (RFC 0014 §6), strings and constructor content compare exactly.
fn edit_value_matches_literal(value: &EditValue, literal: &HclLiteralValue) -> bool {
    match (value, literal) {
        (EditValue::Integer(integer), HclLiteralValue::Integer(canonical)) => {
            integer.to_string() == *canonical
        }
        (
            EditValue::Real(real),
            HclLiteralValue::Integer(canonical) | HclLiteralValue::Decimal(canonical),
        ) => canonical_real(*real).as_deref() == Some(canonical.as_str()),
        (EditValue::String(text), HclLiteralValue::String(decoded)) => text == decoded,
        (EditValue::Boolean(boolean), HclLiteralValue::Boolean(decoded)) => *boolean == *decoded,
        (EditValue::Null, HclLiteralValue::Null) => true,
        (EditValue::Tuple(elements), HclLiteralValue::Tuple(decoded)) => {
            elements.len() == decoded.len()
                && elements
                    .iter()
                    .zip(decoded.iter())
                    .all(|(element, decoded)| edit_value_matches_literal(element, decoded))
        }
        (EditValue::Object(entries), HclLiteralValue::Object(decoded)) => {
            entries.len() == decoded.len()
                && entries
                    .iter()
                    .zip(decoded.iter())
                    .all(|((key, value), entry)| {
                        edit_key_matches_literal(key, entry.key())
                            && edit_value_matches_literal(value, entry.value())
                    })
        }
        _ => false,
    }
}

/// Whether one typed object key equals one reparsed literal key.
fn edit_key_matches_literal(key: &EditKey, literal: &HclLiteralKey) -> bool {
    match (key, literal) {
        (EditKey::Identifier(name), HclLiteralKey::Identifier(decoded)) => name == decoded,
        (EditKey::Number(number), HclLiteralKey::Number(canonical)) => {
            number.to_string() == *canonical
        }
        (EditKey::String(text), HclLiteralKey::String(decoded)) => text == decoded,
        _ => false,
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
    // (spans that overlap or touch). Each run's replacement is the exact
    // target bytes at its new span, so the change set, patch, and proof are
    // always self-consistent with the committed bytes.
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
    transaction
        .operations
        .iter()
        .filter_map(|operation| {
            mapping_for(
                operation,
                base.document(),
                final_document.document(),
                base.authority(),
                final_document.authority(),
            )
        })
        .collect()
}

/// One mapping fact for one operation, when its target resolves in the base.
fn mapping_for(
    operation: &EditOperation,
    base_document: &HclDocument,
    final_document: &HclDocument,
    old_authority: &DocumentAuthority,
    new_authority: &DocumentAuthority,
) -> Option<NodeMapping> {
    let (old, new, status) = match operation {
        EditOperation::SetAttributeValue {
            body, attribute, ..
        } => {
            let old = resolve_attribute_mapping(base_document, body, attribute)?;
            let new = resolve_attribute_mapping(final_document, body, attribute);
            match new {
                Some(new) => (old, Some(new), NodeMappingStatus::Replaced),
                None => (old, None, NodeMappingStatus::Unmapped),
            }
        }
        EditOperation::RenameAttribute {
            body,
            attribute,
            name,
            ..
        } => {
            let old = resolve_attribute_mapping(base_document, body, attribute)?;
            let new = resolve_attribute_mapping(final_document, body, name);
            match new {
                Some(new) => (old, Some(new), NodeMappingStatus::Replaced),
                None => (old, None, NodeMappingStatus::Unmapped),
            }
        }
        EditOperation::RemoveAttribute {
            body, attribute, ..
        } => (
            resolve_attribute_mapping(base_document, body, attribute)?,
            None,
            NodeMappingStatus::Deleted,
        ),
        EditOperation::RemoveBlock {
            body,
            block_type,
            labels,
            occurrence,
        } => (
            resolve_block_mapping(base_document, body, block_type, labels, *occurrence)?,
            None,
            NodeMappingStatus::Deleted,
        ),
        EditOperation::InsertAttribute { .. } | EditOperation::InsertBlock { .. } => return None,
    };
    Some(NodeMapping {
        old: old_authority.node_ref(old.0, old.1),
        new: new.map(|(index, role)| new_authority.node_ref(index, role)),
        status,
        reason: (status == NodeMappingStatus::Unmapped)
            .then(|| "reparsed-node-not-uniquely-located".to_owned()),
    })
}

/// One attribute's node index (its name's start byte) and role in one
/// document.
fn resolve_attribute_mapping(
    document: &HclDocument,
    body: &BodyPath,
    attribute: &str,
) -> Option<(u64, NodeRole)> {
    let (target_body, _) = resolve_body(document, body).ok()?;
    let attribute_ref = find_attribute(target_body, attribute)?;
    Some((
        attribute_ref.name_span().start_byte() as u64,
        NodeRole::HclAttribute,
    ))
}

/// One block's node index (its span's start byte) and role in one document.
fn resolve_block_mapping(
    document: &HclDocument,
    body: &BodyPath,
    block_type: &str,
    labels: &[String],
    occurrence: usize,
) -> Option<(u64, NodeRole)> {
    let (target_body, _) = resolve_body(document, body).ok()?;
    let block = find_block(target_body, block_type, labels, occurrence)?;
    Some((block.span().start_byte() as u64, NodeRole::HclBlock))
}

/// Patch construction bounds derived from the parse limits.
fn source_patch_limits(limits: HclParseLimits) -> SourcePatchLimits {
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
        diagnostic.code.starts_with("hcl.limit.")
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
        EditOperation::SetAttributeValue { .. } => "hcl.edit.set-attribute-value@1",
        EditOperation::InsertAttribute { .. } => "hcl.edit.insert-attribute@1",
        EditOperation::RemoveAttribute { .. } => "hcl.edit.remove-attribute@1",
        EditOperation::RenameAttribute { .. } => "hcl.edit.rename-attribute@1",
        EditOperation::InsertBlock { .. } => "hcl.edit.insert-block@1",
        EditOperation::RemoveBlock { .. } => "hcl.edit.remove-block@1",
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
                EditOperation::SetAttributeValue {
                    body,
                    attribute,
                    value,
                } => (
                    "hcl.edit.set-attribute-value",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("attribute_len".to_owned(), attribute.len().to_string()),
                        ("value_kind".to_owned(), value.kind_name().to_owned()),
                    ]),
                ),
                EditOperation::InsertAttribute {
                    body,
                    name,
                    value,
                    placement,
                } => (
                    "hcl.edit.insert-attribute",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("name_len".to_owned(), name.len().to_string()),
                        ("value_kind".to_owned(), value.kind_name().to_owned()),
                        ("placement".to_owned(), placement_name(placement).to_owned()),
                    ]),
                ),
                EditOperation::RemoveAttribute { body, attribute } => (
                    "hcl.edit.remove-attribute",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("attribute_len".to_owned(), attribute.len().to_string()),
                    ]),
                ),
                EditOperation::RenameAttribute {
                    body,
                    attribute,
                    name,
                } => (
                    "hcl.edit.rename-attribute",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("attribute_len".to_owned(), attribute.len().to_string()),
                        ("name_len".to_owned(), name.len().to_string()),
                    ]),
                ),
                EditOperation::InsertBlock {
                    body,
                    block_type,
                    labels,
                    attributes,
                    placement,
                } => (
                    "hcl.edit.insert-block",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("type_len".to_owned(), block_type.len().to_string()),
                        ("labels".to_owned(), labels.len().to_string()),
                        ("attribute_count".to_owned(), attributes.len().to_string()),
                        ("placement".to_owned(), placement_name(placement).to_owned()),
                    ]),
                ),
                EditOperation::RemoveBlock {
                    body,
                    block_type,
                    labels,
                    occurrence,
                } => (
                    "hcl.edit.remove-block",
                    BTreeMap::from([
                        ("body_depth".to_owned(), body.segments().len().to_string()),
                        ("type_len".to_owned(), block_type.len().to_string()),
                        ("labels".to_owned(), labels.len().to_string()),
                        ("occurrence".to_owned(), occurrence.to_string()),
                    ]),
                ),
            };
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

/// Stable placement name for summaries.
fn placement_name(placement: &BodyPlacement) -> &'static str {
    match placement {
        BodyPlacement::First => "first",
        BodyPlacement::Last => "last",
        BodyPlacement::After(_) => "after",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::HclLiteralObjectEntry;
    use consema_document::ParseLimits;

    fn parse(source: &[u8], profile: HclProfile) -> Document {
        Document::parse(Arc::from(source), profile, HclParseLimits::default()).expect("hcl forms")
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

    fn integer_value(value: i64) -> EditValue {
        EditValue::Integer(value)
    }

    fn string_value(text: &str) -> EditValue {
        EditValue::String(text.to_owned())
    }

    fn boolean_value(value: bool) -> EditValue {
        EditValue::Boolean(value)
    }

    /// The reparsed literal value of one root attribute.
    fn root_attribute_value(document: &Document, name: &str) -> HclLiteralValue {
        let attribute = document
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_attribute)
            .find(|attribute| attribute.name() == name)
            .expect("attribute exists");
        literal_value(attribute.expression()).expect("literal value")
    }

    #[test]
    fn attribute_operations_match_the_conformance_vector() {
        let source = b"region = \"us-east-1\"\ncount = 2\nenabled = true\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_attribute(
                BodyPath::root(),
                "zone",
                string_value("a"),
                BodyPlacement::First,
            )
            .set_attribute_value(BodyPath::root(), "count", integer_value(3))
            .rename_attribute(BodyPath::root(), "enabled", "active")
            .remove_attribute(BodyPath::root(), "region");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"zone = \"a\"\ncount = 3\nactive = true\n");
        assert_eq!(
            root_attribute_value(&after, "zone"),
            HclLiteralValue::String("a".to_owned())
        );
        assert_eq!(
            root_attribute_value(&after, "count"),
            HclLiteralValue::Integer("3".to_owned())
        );
        assert_eq!(
            root_attribute_value(&after, "active"),
            HclLiteralValue::Boolean(true)
        );
    }

    #[test]
    fn block_operations_match_the_conformance_vector() {
        let source = b"server \"web\" {\n  port = 8080\n}\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_block(
                BodyPath::root(),
                "server",
                vec!["db".to_owned()],
                vec![("port".to_owned(), integer_value(5432))],
                BodyPlacement::Last,
            )
            .remove_block(BodyPath::root(), "server", vec!["web".to_owned()], 0);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"server \"db\" {\n  port = 5432\n}\n");
        let block = after
            .document()
            .body()
            .items()
            .iter()
            .find_map(HclBodyItem::as_block)
            .expect("block");
        assert_eq!(block.block_type(), "server");
        assert_eq!(block.labels()[0].text(), "db");
        assert!(block.labels()[0].quoted(), "labels always render quoted");
    }

    #[test]
    fn conflict_vector_codes_and_atomicity() {
        // Inserting an attribute whose name already exists in the body.
        let document = parse(b"count = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "count",
            integer_value(3),
            BodyPlacement::Last,
        );
        let error = document.commit(&builder.build()).expect_err("duplicate");
        assert_eq!(error, EditFailure::DuplicateAttribute);
        assert_eq!(error.diagnostic_code(), "hcl.edit.duplicate-attribute@1");
        assert_eq!(document.render(), b"count = 2\n", "base unchanged");

        // A block insertion under the tfvars profile.
        let document = parse(b"region = \"x\"\n", HclProfile::TfvarsV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_block(
            BodyPath::root(),
            "server",
            vec!["db".to_owned()],
            Vec::new(),
            BodyPlacement::Last,
        );
        let error = document.commit(&builder.build()).expect_err("tfvars gate");
        assert_eq!(error, EditFailure::BlockInTfvars);
        assert_eq!(error.diagnostic_code(), "hcl.edit.block-in-tfvars@1");
        assert_eq!(document.render(), b"region = \"x\"\n", "base unchanged");

        // A derived expression value is refused, never rendered.
        let document = parse(b"count = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(
            BodyPath::root(),
            "count",
            EditValue::Expression {
                kind: "binary".to_owned(),
                text: "1 + 2".to_owned(),
            },
        );
        let error = document.commit(&builder.build()).expect_err("expression");
        assert_eq!(error, EditFailure::UnrepresentableValue("expression"));
        assert_eq!(error.diagnostic_code(), "hcl.edit.unrepresentable@1");
        assert_eq!(document.render(), b"count = 2\n", "base unchanged");

        // A missing target is an incomplete target.
        let document = parse(b"count = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "missing", integer_value(1));
        let error = document.commit(&builder.build()).expect_err("missing");
        assert_eq!(error, EditFailure::IncompleteTarget);
        assert_eq!(error.diagnostic_code(), "core.edit.incomplete-target@1");
        assert_eq!(document.render(), b"count = 2\n", "base unchanged");

        // A transaction built against another snapshot is rejected.
        let document = parse(b"count = 2\n", HclProfile::NativeV1);
        let wrong = parse(b"other = 1\n", HclProfile::NativeV1);
        let original = wrong.render().to_vec();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "count", integer_value(9));
        let error = wrong.commit(&builder.build()).expect_err("wrong snapshot");
        assert_eq!(error, EditFailure::WrongSnapshot);
        assert_eq!(error.diagnostic_code(), "core.edit.wrong-snapshot@1");
        assert_eq!(wrong.render(), original.as_slice(), "base unchanged");
    }

    #[test]
    fn tfvars_gate_refuses_block_operations_atomically() {
        // A transaction whose second operation is a block insertion fails
        // atomically: the base stays byte-exact.
        let document = parse(b"a = 1\n", HclProfile::TfvarsV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(BodyPath::root(), "a", integer_value(2))
            .insert_block(
                BodyPath::root(),
                "b",
                Vec::new(),
                Vec::new(),
                BodyPlacement::Last,
            );
        let error = document.commit(&builder.build()).expect_err("tfvars gate");
        assert_eq!(error, EditFailure::BlockInTfvars);
        assert_eq!(document.render(), b"a = 1\n", "base unchanged");

        // No block can exist in a Complete tfvars document, so a block
        // removal has no target.
        let document = parse(b"a = 1\n", HclProfile::TfvarsV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_block(BodyPath::root(), "b", Vec::new(), 0);
        let error = document.commit(&builder.build()).expect_err("no block");
        assert_eq!(error, EditFailure::IncompleteTarget);
        assert_eq!(document.render(), b"a = 1\n", "base unchanged");
    }

    #[test]
    fn every_attribute_operation_works_under_both_profiles() {
        for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
            let document = parse(
                b"region = \"us-east-1\"\ncount = 2\nenabled = true\n",
                profile,
            );
            let mut builder = EditTransactionBuilder::new(&document);
            builder
                .set_attribute_value(BodyPath::root(), "count", integer_value(3))
                .insert_attribute(
                    BodyPath::root(),
                    "zone",
                    string_value("a"),
                    BodyPlacement::Last,
                )
                .rename_attribute(BodyPath::root(), "enabled", "active")
                .remove_attribute(BodyPath::root(), "region");
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                b"count = 3\nactive = true\nzone = \"a\"\n",
                "profile {profile:?}"
            );
            assert_eq!(after.profile(), document.profile());
        }
    }

    #[test]
    fn nested_body_operations_resolve_through_body_paths() {
        let source = b"server \"web\" {\n  port = 8080\n}\n";
        let document = parse(source, HclProfile::NativeV1);
        let path = BodyPath::new(vec![BodyPathStep::new("server", vec!["web".to_owned()], 0)]);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(path.clone(), "port", integer_value(9090))
            .insert_attribute(
                path.clone(),
                "zone",
                string_value("a"),
                BodyPlacement::First,
            )
            .rename_attribute(path.clone(), "zone", "region")
            .remove_attribute(path.clone(), "region");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"server \"web\" {\n  port = 9090\n}\n");

        // Inserting and removing a nested block round-trips byte-exactly.
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_block(
                path.clone(),
                "server",
                vec!["db".to_owned()],
                vec![("port".to_owned(), integer_value(5432))],
                BodyPlacement::Last,
            )
            .remove_block(path.clone(), "server", vec!["db".to_owned()], 0);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), source, "nested insert and remove cancel");

        // A path step that meets an attribute is a role failure.
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(
            BodyPath::new(vec![BodyPathStep::new("a", Vec::new(), 0)]),
            "x",
            integer_value(1),
        );
        let error = document.commit(&builder.build()).expect_err("wrong role");
        assert_eq!(error, EditFailure::WrongRole);
        assert_eq!(error.diagnostic_code(), "core.edit.wrong-role@1");

        // A path step that does not exist is an incomplete target.
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(
            BodyPath::new(vec![BodyPathStep::new("missing", Vec::new(), 0)]),
            "x",
            integer_value(1),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::IncompleteTarget)
        ));
    }

    #[test]
    fn insert_placements_first_last_and_after() {
        let source = b"a = 1\nb = 2\n";
        let document = parse(source, HclProfile::NativeV1);

        // After an attribute anchor.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::After(NodeRef::Attribute {
                body: BodyPath::root(),
                name: "b".to_owned(),
            }),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\nb = 2\nz = \"x\"\n");

        // After a block anchor.
        let document = parse(b"a = 1\nb {\n}\nc = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::After(NodeRef::Block {
                body: BodyPath::root(),
                block_type: "b".to_owned(),
                labels: Vec::new(),
                occurrence: 0,
            }),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\nb {\n}\nz = \"x\"\nc = 2\n");

        // An anchor in another body is an incomplete target.
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::After(NodeRef::Attribute {
                body: BodyPath::new(vec![BodyPathStep::new("missing", Vec::new(), 0)]),
                name: "a".to_owned(),
            }),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::IncompleteTarget)
        ));

        // A stale anchor is an incomplete target.
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::After(NodeRef::Attribute {
                body: BodyPath::root(),
                name: "missing".to_owned(),
            }),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::IncompleteTarget)
        ));
    }

    #[test]
    fn remove_consumes_owned_trivia() {
        // A trailing line comment is owned trivia of the attribute.
        let document = parse(b"a = 1 // comment\nb = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_attribute(BodyPath::root(), "a");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"b = 2\n");

        // An end-of-file-terminated item removes without its absent newline.
        let document = parse(b"a = 1\nb = 2", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_attribute(BodyPath::root(), "b");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\n");

        // A blank line before the removed item is body trivia, not owned.
        let document = parse(b"a = 1\n\nb = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_attribute(BodyPath::root(), "a");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"\nb = 2\n");

        // A block removal consumes its terminating newline.
        let document = parse(b"b {\n  x = 1\n}\n# trailing\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_block(BodyPath::root(), "b", Vec::new(), 0);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"# trailing\n");
    }

    #[test]
    fn eof_terminated_inserts_add_a_separating_newline() {
        let document = parse(b"a = 1", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::Last,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\nz = \"x\"\n");

        // The same applies to an after-anchor on the final item.
        let document = parse(b"a = 1", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "z",
            string_value("x"),
            BodyPlacement::After(NodeRef::Attribute {
                body: BodyPath::root(),
                name: "a".to_owned(),
            }),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\nz = \"x\"\n");
    }

    #[test]
    fn rename_preserves_expression_semantics() {
        // The post-application verification proves the derived expression
        // kind is preserved byte-for-byte.
        let document = parse(b"x = 1 + 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_attribute(BodyPath::root(), "x", "y");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"y = 1 + 2\n");

        // Renaming to the same name is a no-op.
        let source = b"x = 1 + 2\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_attribute(BodyPath::root(), "x", "x");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), source);
    }

    #[test]
    fn duplicate_attribute_creation_is_rejected() {
        // Renaming onto an existing name creates a duplicate.
        let document = parse(b"a = 1\nb = 2\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_attribute(BodyPath::root(), "a", "b");
        let error = document.commit(&builder.build()).expect_err("duplicate");
        assert_eq!(error, EditFailure::DuplicateAttribute);
        assert_eq!(error.diagnostic_code(), "hcl.edit.duplicate-attribute@1");

        // Duplicate names among an inserted block's nested attributes.
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_block(
            BodyPath::root(),
            "b",
            Vec::new(),
            vec![
                ("port".to_owned(), integer_value(1)),
                ("port".to_owned(), integer_value(2)),
            ],
            BodyPlacement::Last,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::DuplicateAttribute)
        ));
    }

    #[test]
    fn unrepresentable_values_fail_atomically() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let cases: Vec<(&str, EditValue)> = vec![
            ("real", EditValue::Real(f64::NAN)),
            ("real", EditValue::Real(f64::INFINITY)),
            (
                "expression",
                EditValue::Tuple(vec![EditValue::Expression {
                    kind: "variable-ref".to_owned(),
                    text: "x".to_owned(),
                }]),
            ),
            (
                "object-key",
                EditValue::Object(vec![(
                    EditKey::Identifier("for".to_owned()),
                    integer_value(1),
                )]),
            ),
        ];
        for (fact, value) in &cases {
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_attribute_value(BodyPath::root(), "a", value.clone());
            let error = document
                .commit(&builder.build())
                .expect_err("unrepresentable");
            assert_eq!(
                error,
                EditFailure::UnrepresentableValue(fact),
                "fact {fact}"
            );
            assert_eq!(error.diagnostic_code(), "hcl.edit.unrepresentable@1");
            assert_eq!(document.render(), b"a = 1\n", "base unchanged");
        }

        // An invalid attribute name is an unrepresentable identifier.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "_bad",
            integer_value(1),
            BodyPlacement::Last,
        );
        let error = document.commit(&builder.build()).expect_err("identifier");
        assert_eq!(error, EditFailure::UnrepresentableValue("identifier"));
    }

    #[test]
    fn string_escaping_round_trips_through_edits() {
        let value = "line\nbreak\t\"quote\"\\backslash ${interp} %{if} \u{1F600} \u{0001}";
        let document = parse(b"a = \"old\"\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "a", string_value(value));
        let after = commit(&document, builder.build());
        assert_eq!(
            root_attribute_value(&after, "a"),
            HclLiteralValue::String(value.to_owned()),
            "the reparsed literal equals the promised string"
        );
        let rendered = std::str::from_utf8(after.render()).expect("utf-8");
        assert!(rendered.contains("$${interp}"), "{rendered}");
        assert!(rendered.contains("%%{if}"), "{rendered}");
        assert!(rendered.contains("\\u0001"), "{rendered}");
        // The literal survives a later removal and reinsertion.
        let mut builder = EditTransactionBuilder::new(&after);
        builder
            .remove_attribute(BodyPath::root(), "a")
            .insert_attribute(
                BodyPath::root(),
                "b",
                string_value(value),
                BodyPlacement::Last,
            );
        let after = commit(&after, builder.build());
        assert_eq!(
            root_attribute_value(&after, "b"),
            HclLiteralValue::String(value.to_owned())
        );
    }

    #[test]
    fn constructor_values_render_and_verify() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(
                BodyPath::root(),
                "a",
                EditValue::Tuple(vec![
                    integer_value(1),
                    string_value("two"),
                    boolean_value(true),
                    EditValue::Null,
                ]),
            )
            .insert_attribute(
                BodyPath::root(),
                "obj",
                EditValue::Object(vec![
                    (EditKey::Identifier("env".to_owned()), string_value("prod")),
                    (EditKey::Number(1), string_value("one")),
                    (EditKey::String("dup".to_owned()), string_value("dup")),
                    (EditKey::String("dup".to_owned()), integer_value(2)),
                ]),
                BodyPlacement::First,
            )
            .set_attribute_value(BodyPath::root(), "a", EditValue::Real(1.5))
            .insert_attribute(
                BodyPath::root(),
                "empty",
                EditValue::Tuple(Vec::new()),
                BodyPlacement::First,
            );
        let after = commit(&document, builder.build());
        let rendered = std::str::from_utf8(after.render()).expect("utf-8");
        assert!(
            rendered.contains(
                "obj = {\n  env = \"prod\",\n  1 = \"one\",\n  \"dup\" = \"dup\",\n  \"dup\" = 2\n}"
            ),
            "{rendered}"
        );
        assert!(rendered.contains("a = 1.5"), "{rendered}");
        assert!(rendered.contains("empty = []"), "{rendered}");
        assert_eq!(
            root_attribute_value(&after, "obj"),
            HclLiteralValue::Object(
                vec![
                    HclLiteralObjectEntry::new(
                        HclLiteralKey::Identifier("env".to_owned()),
                        HclLiteralValue::String("prod".to_owned())
                    ),
                    HclLiteralObjectEntry::new(
                        HclLiteralKey::Number("1".to_owned()),
                        HclLiteralValue::String("one".to_owned())
                    ),
                    HclLiteralObjectEntry::new(
                        HclLiteralKey::String("dup".to_owned()),
                        HclLiteralValue::String("dup".to_owned())
                    ),
                    HclLiteralObjectEntry::new(
                        HclLiteralKey::String("dup".to_owned()),
                        HclLiteralValue::Integer("2".to_owned())
                    ),
                ]
                .into()
            )
        );
        // A real with an integer spelling compares canonically.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "a", EditValue::Real(1000.0));
        let after = commit(&document, builder.build());
        assert_eq!(
            root_attribute_value(&after, "a"),
            HclLiteralValue::Integer("1000".to_owned())
        );
    }

    #[test]
    fn dry_run_matches_commit() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(BodyPath::root(), "a", integer_value(2))
            .insert_attribute(
                BodyPath::root(),
                "b",
                string_value("x"),
                BodyPlacement::Last,
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
        assert_eq!(
            plan.operations()[0].operation().to_string(),
            "hcl.edit.set-attribute-value@1"
        );
        assert_eq!(
            plan.operations()[1].operation().to_string(),
            "hcl.edit.insert-attribute@1"
        );
    }

    #[test]
    fn failed_transactions_leave_the_base_byte_exact() {
        let source = b"a = 1\nb {\n  x = 1\n}\n";
        let document = parse(source, HclProfile::NativeV1);
        let original = document.render().to_vec();
        let path = BodyPath::new(vec![BodyPathStep::new("b", Vec::new(), 0)]);

        // A later operation failing leaves every earlier byte unchanged.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(path.clone(), "x", integer_value(2))
            .set_attribute_value(BodyPath::root(), "missing", integer_value(1));
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::IncompleteTarget)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Two append insertions map to the same base position: a duplicate
        // target (the plist `End`-anchor precedent, RFC 0013 §11).
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_attribute(BodyPath::root(), "z", integer_value(1), BodyPlacement::Last)
            .insert_attribute(BodyPath::root(), "y", integer_value(2), BodyPlacement::Last);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::ConflictingEdits)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // An out-of-range occurrence is a missing target.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_block(BodyPath::root(), "b", Vec::new(), 1);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::IncompleteTarget)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");
    }

    #[test]
    fn sequential_edits_fold_and_verify() {
        // Insert then set the inserted attribute: one combined replacement.
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_attribute(BodyPath::root(), "z", integer_value(1), BodyPlacement::Last)
            .set_attribute_value(BodyPath::root(), "z", integer_value(2));
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\nz = 2\n");

        // Insert then remove the inserted attribute: a net no-op.
        let source = b"a = 1\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_attribute(BodyPath::root(), "z", integer_value(1), BodyPlacement::Last)
            .remove_attribute(BodyPath::root(), "z");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), source, "net no-op");

        // Insert into a block then remove the block: the removal swallows
        // the insertion.
        let document = parse(b"b {\n  x = 1\n}\n", HclProfile::NativeV1);
        let path = BodyPath::new(vec![BodyPathStep::new("b", Vec::new(), 0)]);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_attribute(path.clone(), "y", integer_value(2), BodyPlacement::Last)
            .remove_block(BodyPath::root(), "b", Vec::new(), 0);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"", "the owning block is gone");
    }

    #[test]
    fn limits_are_enforced_atomically() {
        // Target source bound.
        let document = parse(
            b"region = \"us-east-1\"\ncount = 2\nenabled = true\n",
            HclProfile::NativeV1,
        );
        let limits = HclParseLimits {
            common: ParseLimits {
                max_source_bytes: 46,
                ..ParseLimits::default()
            },
            ..HclParseLimits::default()
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "zone",
            string_value("a"),
            BodyPlacement::First,
        );
        let error = document
            .commit_impl(&builder.build(), limits)
            .expect_err("source bound");
        assert_eq!(error, EditFailure::ResourceLimit("target-bytes"));
        assert_eq!(
            document.render(),
            b"region = \"us-east-1\"\ncount = 2\nenabled = true\n"
        );

        // Report event bound.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(BodyPath::root(), "count", integer_value(1))
            .set_attribute_value(BodyPath::root(), "count", integer_value(2));
        let limits = HclParseLimits {
            max_report_events: 1,
            ..HclParseLimits::default()
        };
        let error = document
            .commit_impl(&builder.build(), limits)
            .expect_err("report bound");
        assert_eq!(error, EditFailure::ResourceLimit("report-events"));
    }

    #[test]
    fn change_set_maps_replaced_deleted_and_unmapped() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);

        // set-attribute-value maps the target Replaced.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "a", integer_value(2));
        let commit = document.commit(&builder.build()).expect("commit");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Replaced);
        assert!(mapping.new.is_some());
        assert_eq!(mapping.old.role(), NodeRole::HclAttribute);

        // remove-attribute maps the removed attribute Deleted.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_attribute(BodyPath::root(), "a");
        let commit = document.commit(&builder.build()).expect("commit");
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Deleted);
        assert!(mapping.new.is_none());

        // rename-attribute maps the attribute Replaced under its new name.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_attribute(BodyPath::root(), "a", "b");
        let commit = document.commit(&builder.build()).expect("commit");
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Replaced);

        // A set-value whose path a later removal invalidates maps Unmapped
        // with the stable reason.
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(BodyPath::root(), "a", integer_value(3))
            .remove_attribute(BodyPath::root(), "a");
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
    fn empty_transaction_commits_an_unchanged_document() {
        let document = parse(b"a = 1\n", HclProfile::NativeV1);
        let builder = EditTransactionBuilder::new(&document);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), document.render());
    }

    #[test]
    fn remove_block_by_occurrence_selects_the_nth() {
        let source = b"b {\n  x = 1\n}\nb {\n  y = 2\n}\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_block(BodyPath::root(), "b", Vec::new(), 1);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"b {\n  x = 1\n}\n");
    }

    #[test]
    fn empty_documents_and_empty_bodies_accept_inserts() {
        let document = parse(b"", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            BodyPath::root(),
            "a",
            integer_value(1),
            BodyPlacement::First,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\n");
        // A second transaction appends after the first's content.
        let mut builder = EditTransactionBuilder::new(&after);
        builder.insert_attribute(BodyPath::root(), "b", integer_value(2), BodyPlacement::Last);
        let after = commit(&after, builder.build());
        assert_eq!(after.render(), b"a = 1\nb = 2\n");

        let document = parse(b"server \"web\" {\n}\n", HclProfile::NativeV1);
        let path = BodyPath::new(vec![BodyPathStep::new("server", vec!["web".to_owned()], 0)]);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(path, "port", integer_value(80), BodyPlacement::First);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"server \"web\" {\n  port = 80\n}\n");
    }

    #[test]
    fn heredocs_and_multiline_sources_edit_correctly() {
        let source = b"script = <<EOT\n#!/bin/sh\necho hi\nEOT\ncount = 1\n";
        let document = parse(source, HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(BodyPath::root(), "script", string_value("hello"));
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"script = \"hello\"\ncount = 1\n");

        // CRLF sources keep their untouched line endings.
        let document = parse(b"a = 1\r\nb = 2\r\n", HclProfile::NativeV1);
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(BodyPath::root(), "b", integer_value(3))
            .insert_attribute(BodyPath::root(), "c", integer_value(4), BodyPlacement::Last);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), b"a = 1\r\nb = 3\r\nc = 4\n");
    }

    #[test]
    fn operation_ids_match_the_frozen_surface() {
        let operations = [
            EditOperation::SetAttributeValue {
                body: BodyPath::root(),
                attribute: "a".to_owned(),
                value: integer_value(1),
            },
            EditOperation::InsertAttribute {
                body: BodyPath::root(),
                name: "a".to_owned(),
                value: integer_value(1),
                placement: BodyPlacement::Last,
            },
            EditOperation::RemoveAttribute {
                body: BodyPath::root(),
                attribute: "a".to_owned(),
            },
            EditOperation::RenameAttribute {
                body: BodyPath::root(),
                attribute: "a".to_owned(),
                name: "b".to_owned(),
            },
            EditOperation::InsertBlock {
                body: BodyPath::root(),
                block_type: "b".to_owned(),
                labels: Vec::new(),
                attributes: Vec::new(),
                placement: BodyPlacement::Last,
            },
            EditOperation::RemoveBlock {
                body: BodyPath::root(),
                block_type: "b".to_owned(),
                labels: Vec::new(),
                occurrence: 0,
            },
        ];
        let ids: Vec<_> = operations
            .iter()
            .map(|operation| operation_id(operation))
            .collect();
        assert_eq!(
            ids,
            [
                "hcl.edit.set-attribute-value@1",
                "hcl.edit.insert-attribute@1",
                "hcl.edit.remove-attribute@1",
                "hcl.edit.rename-attribute@1",
                "hcl.edit.insert-block@1",
                "hcl.edit.remove-block@1",
            ]
        );
    }

    #[test]
    fn piece_index_walk_finds_line_ends_indents_and_braces() {
        let document = parse(b"a = 1 // c\nb {\n  x = 1\n}\n", HclProfile::NativeV1);
        let index = PieceIndex::new(&document);
        // The first attribute's expression spans bytes 4..5; the terminator
        // walk consumes the trailing comment and its newline.
        assert_eq!(item_line_end(&index, 5).expect("line end"), 11);
        // The first-position insertion point of the nested body lies before
        // the first item's indentation.
        let path = BodyPath::new(vec![BodyPathStep::new("b", Vec::new(), 0)]);
        let (body, parent) = resolve_body(document.document(), &path).expect("body");
        let first = body.items().first().expect("first item");
        assert_eq!(item_line_start(&index, item_span_start(first)), 15);
        let attribute = find_attribute(body, "x").expect("attribute");
        assert_eq!(
            item_indent(
                &index,
                document.document(),
                attribute.name_span().start_byte()
            ),
            "  "
        );
        let block = parent.expect("owning block");
        let (open_end, close_start) =
            block_brace_positions(&index, (block.span().start_byte(), block.span().end_byte()))
                .expect("braces");
        assert_eq!(open_end, 14);
        assert_eq!(close_start, 23);

        // An empty root body has no pieces.
        let empty = parse(b"", HclProfile::NativeV1);
        let empty_index = PieceIndex::new(&empty);
        assert!(empty_index.piece_starting_at(0).is_none());
        assert!(empty_index.piece_ending_at(0).is_none());
    }
}
