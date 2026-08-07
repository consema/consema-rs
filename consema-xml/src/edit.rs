//! Snapshot-bound XML structural edit (RFC 0012 §11).
//!
//! V1 publishes eight versioned operations:
//!
//! ```text
//! xml.edit.replace-text@1
//! xml.edit.insert-attribute@1
//! xml.edit.remove-attribute@1
//! xml.edit.rename-attribute@1
//! xml.edit.set-attribute-value@1
//! xml.edit.insert-element@1
//! xml.edit.remove-element@1
//! xml.edit.rename-element@1
//! ```
//!
//! Each operation targets one exact `NodeRef`. Placement uses one exact
//! parent and an optional sibling/attribute anchor. Duplicate expanded
//! attributes, invalid namespace bindings, unbound prefixes, reserved-prefix
//! misuse, ancestor/self placement, stale snapshots, overlapping
//! replacements, and operations that would break mixed-content or
//! document-root invariants fail before commit.
//!
//! Semantic replacement accepts text or validated QName facts, never raw
//! untrusted markup. New literal content is XML-escaped under the existing
//! encoding. Commit preserves every byte outside operation-owned spans,
//! reparses the target, verifies promised XML/namespace semantics, produces
//! a complete ChangeSet, derives an `UntouchedByteProof`, and emits a
//! replayable `SourcePatch`. Dry-run and commit have identical replacement
//! sets and target digest. No operation writes a filesystem path.

use crate::document::{
    Document, QNameFacts, XmlAttributeData, XmlContent, XmlElementData, XmlTextData,
};
use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile, parse};
use consema_document::SourceEncoding;
use consema_document::{
    ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId, FormatOperationId, NodeMapping,
    NodeMappingStatus, NodeRef, NodeRole, SnapshotIdentity, SourceEdit, SourceLimits, SourcePatch,
    SourcePatchLimits, UntouchedByteProof,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// One prepared raw-byte edit owned by the transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedEdit {
    old_span: consema_document::Span,
    replacement: Vec<u8>,
    mapping: Option<(NodeRef, MappingPlan)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappingPlan {
    Replaced,
    Deleted,
}

/// A validated element or attribute name for structural operations.
///
/// The prefix must already be bound to `namespace` in the target's in-scope
/// scope; the edit never guesses or fabricates namespace declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameFacts {
    /// Prefix spelling; `None` is an unprefixed name.
    pub prefix: Option<String>,
    /// Local name.
    pub local: String,
    /// Namespace URI the prefix must resolve to; `None` forbids a prefix.
    pub namespace: Option<String>,
}

impl NameFacts {
    /// Creates name facts from an already validated prefix/local pair.
    #[must_use]
    pub fn new(prefix: Option<String>, local: String, namespace: Option<String>) -> Self {
        Self {
            prefix,
            local,
            namespace,
        }
    }

    fn spelling(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}:{}", self.local),
            None => self.local.clone(),
        }
    }
}

/// Attribute insertion placement inside one start tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributePlacement {
    /// Insert immediately before one anchor attribute.
    Before(NodeRef),
    /// Insert immediately after one anchor attribute.
    After(NodeRef),
    /// Append before the closing `>` or `/>`.
    End,
}

/// Content insertion placement inside one element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentPlacement {
    /// Insert immediately before one anchor content item.
    Before(NodeRef),
    /// Insert immediately after one anchor content item.
    After(NodeRef),
    /// Append before the end tag (or after the empty-element tag).
    End,
}

/// One snapshot-bound XML structural operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Replaces one text occurrence with new escaped literal content.
    ReplaceText {
        /// Text occurrence.
        target: NodeRef,
        /// New literal character data.
        text: String,
    },
    /// Inserts one attribute association into an element start tag.
    InsertAttribute {
        /// Owning element.
        target: NodeRef,
        /// Validated name facts.
        name: NameFacts,
        /// Semantic attribute value.
        value: String,
        /// Explicit placement.
        placement: AttributePlacement,
    },
    /// Removes one attribute association including its leading whitespace.
    RemoveAttribute {
        /// Attribute association.
        target: NodeRef,
    },
    /// Renames one attribute name, preserving its value.
    RenameAttribute {
        /// Attribute association.
        target: NodeRef,
        /// New validated name facts.
        name: NameFacts,
    },
    /// Replaces one attribute value with new escaped content.
    SetAttributeValue {
        /// Attribute association.
        target: NodeRef,
        /// New semantic value.
        value: String,
    },
    /// Inserts one element into a parent's mixed content.
    InsertElement {
        /// Owning element.
        target: NodeRef,
        /// Validated element name facts.
        name: NameFacts,
        /// Optional literal text content; `None` writes an empty element.
        content: Option<String>,
        /// Explicit placement.
        placement: ContentPlacement,
    },
    /// Removes one element subtree including its leading whitespace.
    RemoveElement {
        /// Element occurrence.
        target: NodeRef,
    },
    /// Renames one element in both its start and end tags.
    RenameElement {
        /// Element occurrence.
        target: NodeRef,
        /// New validated name facts.
        name: NameFacts,
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

    /// Replaces one text occurrence with new literal content.
    pub fn replace_text(&mut self, target: NodeRef, text: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::ReplaceText {
            target,
            text: text.into(),
        });
        self
    }

    /// Inserts one attribute with explicit placement.
    pub fn insert_attribute(
        &mut self,
        target: NodeRef,
        name: NameFacts,
        value: impl Into<String>,
        placement: AttributePlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertAttribute {
            target,
            name,
            value: value.into(),
            placement,
        });
        self
    }

    /// Removes one attribute association.
    pub fn remove_attribute(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveAttribute { target });
        self
    }

    /// Renames one attribute.
    pub fn rename_attribute(&mut self, target: NodeRef, name: NameFacts) -> &mut Self {
        self.operations
            .push(EditOperation::RenameAttribute { target, name });
        self
    }

    /// Replaces one attribute value.
    pub fn set_attribute_value(&mut self, target: NodeRef, value: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::SetAttributeValue {
            target,
            value: value.into(),
        });
        self
    }

    /// Inserts one element into a parent's mixed content.
    pub fn insert_element(
        &mut self,
        target: NodeRef,
        name: NameFacts,
        content: Option<String>,
        placement: ContentPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertElement {
            target,
            name,
            content,
            placement,
        });
        self
    }

    /// Removes one element subtree.
    pub fn remove_element(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveElement { target });
        self
    }

    /// Renames one element.
    pub fn rename_element(&mut self, target: NodeRef, name: NameFacts) -> &mut Self {
        self.operations
            .push(EditOperation::RenameElement { target, name });
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
    /// Target role is not the operation's expected XML role.
    WrongRole,
    /// The target or anchor NodeRef does not exist in this snapshot.
    TargetNotFound,
    /// The base document is not `Complete`, so no target can be edited.
    IncompleteTarget,
    /// Name facts violate XML QName grammar.
    InvalidQName,
    /// A prefixed name has no in-scope binding to its promised namespace.
    UnboundPrefix {
        /// The unbound prefix spelling.
        prefix: String,
    },
    /// A reserved prefix or namespace was used as an ordinary name.
    ReservedPrefix {
        /// The reserved prefix spelling.
        prefix: String,
    },
    /// The renamed or inserted attribute duplicates an expanded name.
    DuplicateExpandedAttribute,
    /// The document element cannot be removed.
    CannotRemoveRoot,
    /// An insertion targets the element itself or one of its descendants.
    AncestorPlacement,
    /// Two operations target the same exact occurrence.
    ConflictingEdits,
    /// Two operations own the same exact source interval.
    OverlappingOwnership,
    /// One operation edits an element and another edits an owned descendant.
    AncestorDescendantConflict,
    /// An insertion anchor is modified by another operation in the transaction.
    PlacementAnchorModified,
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement document could not be formed under the original limits.
    NewDocumentFormationFailed,
}

impl consema_core::StableFailure for EditFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Edit
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::WrongSnapshot => consema_core::FailureKind::TargetMismatch,
            Self::InvalidQName
            | Self::UnboundPrefix { .. }
            | Self::ReservedPrefix { .. }
            | Self::DuplicateExpandedAttribute
            | Self::CannotRemoveRoot
            | Self::AncestorPlacement
            | Self::ConflictingEdits
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorModified => consema_core::FailureKind::InvalidInput,
            Self::TargetNotFound | Self::WrongRole | Self::IncompleteTarget => {
                consema_core::FailureKind::NotApplicable
            }
            Self::ResourceLimit(_) => consema_core::FailureKind::ResourceLimited,
            Self::NewDocumentFormationFailed => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::TargetNotFound => "core.edit.target-not-found@1",
            Self::IncompleteTarget => "core.edit.incomplete-target@1",
            Self::InvalidQName => "core.edit.invalid-qname@1",
            Self::UnboundPrefix { .. } => "core.edit.unbound-prefix@1",
            Self::ReservedPrefix { .. } => "core.edit.reserved-prefix@1",
            Self::DuplicateExpandedAttribute => "core.edit.duplicate-expanded-attribute@1",
            Self::CannotRemoveRoot => "core.edit.cannot-remove-root@1",
            Self::AncestorPlacement => "core.edit.ancestor-placement@1",
            Self::ConflictingEdits
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::PlacementAnchorModified => "core.edit.conflicting-edits@1",
            Self::ResourceLimit(_) => "core.edit.resource-limit@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

impl Document {
    /// Atomically commits structural operations. On failure `self` remains
    /// unchanged.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if self.status() != consema_document::FormationStatus::Complete {
            return Err(EditFailure::IncompleteTarget);
        }
        validate_dependencies(transaction)?;
        let mut prepared = Vec::new();
        prepared
            .try_reserve(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for operation in &transaction.operations {
            prepared.extend(self.prepare_operation(operation)?);
        }
        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        for pair in prepared.windows(2) {
            if pair[0].old_span == pair[1].old_span
                || (pair[0].old_span.is_empty()
                    && pair[1].old_span.is_empty()
                    && pair[0].old_span.start_byte() == pair[1].old_span.start_byte())
            {
                return Err(EditFailure::OverlappingOwnership);
            }
            if !pair[0].old_span.is_empty()
                && !pair[1].old_span.is_empty()
                && pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
            {
                return Err(EditFailure::OverlappingOwnership);
            }
        }
        let target_len = prepared
            .iter()
            .try_fold(self.source().len(), |length, edit| {
                length
                    .checked_sub(edit.old_span.len())
                    .and_then(|length| length.checked_add(edit.replacement.len()))
                    .ok_or(EditFailure::ResourceLimit("target-bytes"))
            })?;
        if target_len > self.parse_limits().common.max_source_bytes {
            return Err(EditFailure::ResourceLimit("target-bytes"));
        }
        let mut rendered = Vec::new();
        rendered
            .try_reserve_exact(target_len)
            .map_err(|_| EditFailure::ResourceLimit("target-allocation"))?;
        let mut cursor = 0;
        for edit in &prepared {
            rendered.extend_from_slice(&self.source().bytes()[cursor..edit.old_span.start_byte()]);
            rendered.extend_from_slice(&edit.replacement);
            cursor = edit.old_span.end_byte();
        }
        rendered.extend_from_slice(&self.source().bytes()[cursor..]);
        let bytes: Arc<[u8]> = Arc::from(rendered);
        let new_document = parse(
            Arc::clone(&bytes),
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            self.parse_limits(),
        )
        .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        if new_document.status() != consema_document::FormationStatus::Complete {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
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
            let replacement_len = edit.replacement.len();
            let new_start = edit
                .old_span
                .start_byte()
                .checked_add_signed(delta)
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
            let new_end = new_start
                .checked_add(replacement_len)
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
            let new_span = new_document
                .authority()
                .span(new_start, new_end)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
            source_edits.push(SourceEdit {
                old_span: edit.old_span,
                new_span,
                replacement: Arc::from(edit.replacement),
            });
            if let Some((old, plan)) = edit.mapping {
                if mapped_old.insert(old) {
                    let (new, status, reason) = match plan {
                        MappingPlan::Replaced => {
                            let found = find_node_by_span(&new_document, new_start, new_end);
                            (
                                found,
                                if found.is_some() {
                                    NodeMappingStatus::Replaced
                                } else {
                                    NodeMappingStatus::Unmapped
                                },
                                found
                                    .is_none()
                                    .then(|| "reparsed-node-not-uniquely-located".to_owned()),
                            )
                        }
                        MappingPlan::Deleted => (None, NodeMappingStatus::Deleted, None),
                    };
                    mappings.push(NodeMapping {
                        old,
                        new,
                        status,
                        reason,
                    });
                }
            }
            let delta_len = isize::try_from(replacement_len)
                .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
            let old_len = isize::try_from(edit.old_span.len())
                .map_err(|_| EditFailure::ResourceLimit("target-coordinate"))?;
            delta = delta
                .checked_add(delta_len - old_len)
                .ok_or(EditFailure::ResourceLimit("target-coordinate"))?;
        }
        let change_set = ChangeSet::new(
            self.snapshot_identity(),
            new_document.snapshot_identity(),
            source_edits,
            mappings,
            Vec::new(),
        );
        let patch_limits =
            source_patch_limits(self.parse_limits(), change_set.source_edits().len());
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

    /// The parse limits this document was formed under.
    #[must_use]
    pub const fn parse_limits(&self) -> XmlParseLimits {
        self.parse_limits
    }
}

/// Cross-operation dependency checks before any span is computed.
fn validate_dependencies(transaction: &EditTransaction) -> Result<(), EditFailure> {
    let mut targets: HashSet<NodeRef> = HashSet::new();
    for operation in &transaction.operations {
        let (target, anchor) = match operation {
            EditOperation::ReplaceText { target, .. }
            | EditOperation::RemoveAttribute { target }
            | EditOperation::SetAttributeValue { target, .. }
            | EditOperation::RemoveElement { target }
            | EditOperation::RenameAttribute { target, .. }
            | EditOperation::RenameElement { target, .. } => (*target, None),
            EditOperation::InsertAttribute {
                target, placement, ..
            } => (
                *target,
                match placement {
                    AttributePlacement::Before(anchor) | AttributePlacement::After(anchor) => {
                        Some(*anchor)
                    }
                    AttributePlacement::End => None,
                },
            ),
            EditOperation::InsertElement {
                target, placement, ..
            } => (
                *target,
                match placement {
                    ContentPlacement::Before(anchor) | ContentPlacement::After(anchor) => {
                        Some(*anchor)
                    }
                    ContentPlacement::End => None,
                },
            ),
        };
        if !targets.insert(target) {
            return Err(EditFailure::ConflictingEdits);
        }
        if let Some(anchor) = anchor {
            if targets.contains(&anchor) {
                return Err(EditFailure::PlacementAnchorModified);
            }
        }
    }
    Ok(())
}

/// Raw bytes per decoded character under the source encoding.
const fn char_width(encoding: SourceEncoding) -> usize {
    match encoding {
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => 2,
        _ => 1,
    }
}

/// Whether the element tag ending at `span_end` is written with a `/>`
/// close, probed in raw bytes. The slash is the byte directly before the
/// close for UTF-8 and UTF-16LE, and the byte after the leading zero for
/// UTF-16BE.
fn empty_element_tag_close(source: &[u8], span_end: usize, encoding: SourceEncoding) -> bool {
    let Some(offset) = span_end.checked_sub(2 * char_width(encoding)) else {
        return false;
    };
    let slash = match encoding {
        SourceEncoding::Utf16Be => offset + 1,
        _ => offset,
    };
    source.get(slash).copied() == Some(b'/')
}

/// Appends literal text to a replacement buffer under the source encoding.
///
/// Every replacement byte is written in the encoding the source stream uses,
/// so spliced edits never misalign a UTF-16 stream. ASCII occupies one byte
/// per character in UTF-8 and two bytes per decoded code unit in UTF-16. The
/// BOM is never repeated here: replacements land inside the existing stream,
/// whose leading BOM stays untouched.
fn push_encoded_text(out: &mut Vec<u8>, text: &str, encoding: SourceEncoding) {
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

/// Encodes one scalar under the source encoding.
fn push_encoded_char(out: &mut Vec<u8>, c: char, encoding: SourceEncoding) {
    let mut buffer = [0u8; 4];
    push_encoded_text(out, c.encode_utf8(&mut buffer), encoding);
}

/// Encodes one name spelling under the source encoding.
fn spelling_bytes(name: &NameFacts, encoding: SourceEncoding) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(prefix) = &name.prefix {
        push_encoded_text(&mut out, prefix, encoding);
        push_encoded_text(&mut out, ":", encoding);
    }
    push_encoded_text(&mut out, &name.local, encoding);
    out
}

/// Encodes one source QName spelling under the source encoding.
fn qname_spelling_bytes(qname: &QNameFacts, encoding: SourceEncoding) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(prefix) = &qname.prefix {
        push_encoded_text(&mut out, prefix, encoding);
        push_encoded_text(&mut out, ":", encoding);
    }
    push_encoded_text(&mut out, &qname.local, encoding);
    out
}

/// Escapes literal character data for text content under the source encoding.
fn escape_text(text: &str, encoding: SourceEncoding) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => push_encoded_text(&mut out, "&amp;", encoding),
            '<' => push_encoded_text(&mut out, "&lt;", encoding),
            _ => push_encoded_char(&mut out, c, encoding),
        }
    }
    out
}

/// Escapes literal text for double-quoted attribute values under the source
/// encoding.
fn escape_attribute(text: &str, encoding: SourceEncoding) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => push_encoded_text(&mut out, "&amp;", encoding),
            '<' => push_encoded_text(&mut out, "&lt;", encoding),
            '"' => push_encoded_text(&mut out, "&quot;", encoding),
            _ => push_encoded_char(&mut out, c, encoding),
        }
    }
    out
}

impl Document {
    fn prepare_operation(
        &self,
        operation: &EditOperation,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        match operation {
            EditOperation::ReplaceText { target, text } => self.prepare_replace_text(*target, text),
            EditOperation::InsertAttribute {
                target,
                name,
                value,
                placement,
            } => self.prepare_insert_attribute(*target, name, value, *placement),
            EditOperation::RemoveAttribute { target } => self.prepare_remove_attribute(*target),
            EditOperation::RenameAttribute { target, name } => {
                self.prepare_rename_attribute(*target, name)
            }
            EditOperation::SetAttributeValue { target, value } => {
                self.prepare_set_attribute_value(*target, value)
            }
            EditOperation::InsertElement {
                target,
                name,
                content,
                placement,
            } => self.prepare_insert_element(*target, name, content.as_deref(), *placement),
            EditOperation::RemoveElement { target } => self.prepare_remove_element(*target),
            EditOperation::RenameElement { target, name } => {
                self.prepare_rename_element(*target, name)
            }
        }
    }

    fn prepare_replace_text(
        &self,
        target: NodeRef,
        text: &str,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let text_data = self.text_for(target)?;
        let encoding = self.source().encoding_facts().selected();
        Ok(vec![PreparedEdit {
            old_span: text_data.span,
            replacement: escape_text(text, encoding),
            mapping: Some((target, MappingPlan::Replaced)),
        }])
    }

    fn prepare_insert_attribute(
        &self,
        target: NodeRef,
        name: &NameFacts,
        value: &str,
        placement: AttributePlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let element = self.element_for(target)?;
        Self::validate_name_facts(name, element, true)?;
        Self::reject_duplicate_attribute(element, name)?;
        let encoding = self.source().encoding_facts().selected();
        let (insert_at, replacement) = match placement {
            AttributePlacement::Before(anchor) => {
                let anchor_data = self.attribute_for(anchor)?;
                (anchor_data.span.start_byte(), {
                    let mut bytes = spelling_bytes(name, encoding);
                    push_encoded_text(&mut bytes, "=", encoding);
                    push_encoded_text(&mut bytes, "\"", encoding);
                    bytes.extend(escape_attribute(value, encoding));
                    push_encoded_text(&mut bytes, "\"", encoding);
                    push_encoded_text(&mut bytes, " ", encoding);
                    bytes
                })
            }
            AttributePlacement::After(anchor) => {
                let anchor_data = self.attribute_for(anchor)?;
                (anchor_data.span.end_byte(), {
                    let mut bytes = Vec::new();
                    push_encoded_text(&mut bytes, " ", encoding);
                    bytes.extend(spelling_bytes(name, encoding));
                    push_encoded_text(&mut bytes, "=", encoding);
                    push_encoded_text(&mut bytes, "\"", encoding);
                    bytes.extend(escape_attribute(value, encoding));
                    push_encoded_text(&mut bytes, "\"", encoding);
                    bytes
                })
            }
            AttributePlacement::End => {
                let empty_element = empty_element_tag_close(
                    self.source().bytes(),
                    element.span.end_byte(),
                    encoding,
                );
                let width = char_width(encoding);
                let insert_at = element.span.end_byte().saturating_sub(if empty_element {
                    2 * width
                } else {
                    width
                });
                (insert_at, {
                    let mut bytes = Vec::new();
                    push_encoded_text(&mut bytes, " ", encoding);
                    bytes.extend(spelling_bytes(name, encoding));
                    push_encoded_text(&mut bytes, "=", encoding);
                    push_encoded_text(&mut bytes, "\"", encoding);
                    bytes.extend(escape_attribute(value, encoding));
                    push_encoded_text(&mut bytes, "\"", encoding);
                    bytes
                })
            }
        };
        let span = self
            .authority()
            .span(insert_at, insert_at)
            .map_err(|_| EditFailure::TargetNotFound)?;
        Ok(vec![PreparedEdit {
            old_span: span,
            replacement,
            mapping: None,
        }])
    }

    fn prepare_remove_attribute(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let attribute = self.attribute_for(target)?;
        let start = leading_whitespace_start(self.source().bytes(), attribute.span.start_byte());
        let span = self
            .authority()
            .span(start, attribute.span.end_byte())
            .map_err(|_| EditFailure::TargetNotFound)?;
        Ok(vec![PreparedEdit {
            old_span: span,
            replacement: Vec::new(),
            mapping: Some((target, MappingPlan::Deleted)),
        }])
    }

    fn prepare_rename_attribute(
        &self,
        target: NodeRef,
        name: &NameFacts,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let attribute = self.attribute_for(target)?;
        let element = self
            .elements()
            .find(|(_, data)| {
                data.attributes
                    .iter()
                    .any(|a| a.ordinal == attribute.ordinal)
            })
            .map(|(_, data)| data)
            .ok_or(EditFailure::TargetNotFound)?;
        Self::validate_name_facts(name, element, true)?;
        let remaining: Vec<&XmlAttributeData> = element
            .attributes
            .iter()
            .filter(|a| a.ordinal != attribute.ordinal)
            .collect();
        if let Some(new_expanded) = Self::expanded_name_for_facts(name, element)? {
            if remaining.iter().any(|a| {
                a.expanded
                    .as_ref()
                    .is_some_and(|existing| existing == &new_expanded)
            }) {
                return Err(EditFailure::DuplicateExpandedAttribute);
            }
        }
        let encoding = self.source().encoding_facts().selected();
        Ok(vec![PreparedEdit {
            old_span: attribute.qname.span,
            replacement: spelling_bytes(name, encoding),
            mapping: Some((target, MappingPlan::Replaced)),
        }])
    }

    fn prepare_set_attribute_value(
        &self,
        target: NodeRef,
        value: &str,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let attribute = self.attribute_for(target)?;
        let encoding = self.source().encoding_facts().selected();
        Ok(vec![PreparedEdit {
            old_span: attribute.value_span,
            replacement: escape_attribute(value, encoding),
            mapping: Some((target, MappingPlan::Replaced)),
        }])
    }

    fn prepare_insert_element(
        &self,
        target: NodeRef,
        name: &NameFacts,
        content: Option<&str>,
        placement: ContentPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let element = self.element_for(target)?;
        Self::validate_name_facts(name, element, false)?;
        let encoding = self.source().encoding_facts().selected();
        let spelling = spelling_bytes(name, encoding);
        let mut markup = Vec::new();
        push_encoded_text(&mut markup, "<", encoding);
        markup.extend_from_slice(&spelling);
        if let Some(content) = content {
            push_encoded_text(&mut markup, ">", encoding);
            markup.extend(escape_text(content, encoding));
            push_encoded_text(&mut markup, "</", encoding);
            markup.extend_from_slice(&spelling);
            push_encoded_text(&mut markup, ">", encoding);
        } else {
            push_encoded_text(&mut markup, "/>", encoding);
        }
        let (start, end, replacement) = match placement {
            ContentPlacement::Before(anchor) => {
                let (role, span) = self.content_span_for(anchor)?;
                if !element.children.iter().any(|&child| {
                    self.nodes()[child].span() == span && self.node_role(child) == role
                }) {
                    return Err(EditFailure::TargetNotFound);
                }
                (span.start_byte(), span.start_byte(), markup)
            }
            ContentPlacement::After(anchor) => {
                let (role, span) = self.content_span_for(anchor)?;
                if !element.children.iter().any(|&child| {
                    self.nodes()[child].span() == span && self.node_role(child) == role
                }) {
                    return Err(EditFailure::TargetNotFound);
                }
                (span.end_byte(), span.end_byte(), markup)
            }
            ContentPlacement::End => {
                if let Some(&last_child) = element.children.last() {
                    let at = self.content_extent_end(last_child);
                    (at, at, markup)
                } else {
                    let end = element.span.end_byte();
                    if empty_element_tag_close(self.source().bytes(), end, encoding) {
                        // `<root/>`: the element's own span ends after the
                        // `/>`, so a zero-width insertion there would create
                        // a second root. Replace the `/>` close with `>` plus
                        // the new element plus a fresh `</parent-name>` close.
                        let mut wrapped = Vec::new();
                        push_encoded_text(&mut wrapped, ">", encoding);
                        wrapped.extend_from_slice(&markup);
                        push_encoded_text(&mut wrapped, "</", encoding);
                        wrapped.extend(qname_spelling_bytes(&element.qname, encoding));
                        push_encoded_text(&mut wrapped, ">", encoding);
                        (end - 2 * char_width(encoding), end, wrapped)
                    } else {
                        // `<root></root>`: insert directly before the
                        // explicit end tag.
                        (end, end, markup)
                    }
                }
            }
        };
        let span = self
            .authority()
            .span(start, end)
            .map_err(|_| EditFailure::TargetNotFound)?;
        Ok(vec![PreparedEdit {
            old_span: span,
            replacement,
            mapping: None,
        }])
    }

    fn prepare_remove_element(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let element = self.element_for(target)?;
        if self
            .root()
            .is_some_and(|root| root.data().index == element.index)
        {
            return Err(EditFailure::CannotRemoveRoot);
        }
        let start = leading_whitespace_start(self.source().bytes(), element.span.start_byte());
        // The element's span covers only its start tag; the removal must
        // consume the whole subtree including the closing `</name>`.
        let end = self.content_extent_end(element.index);
        let span = self
            .authority()
            .span(start, end)
            .map_err(|_| EditFailure::TargetNotFound)?;
        Ok(vec![PreparedEdit {
            old_span: span,
            replacement: Vec::new(),
            mapping: Some((target, MappingPlan::Deleted)),
        }])
    }

    fn prepare_rename_element(
        &self,
        target: NodeRef,
        name: &NameFacts,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let element = self.element_for(target)?;
        Self::validate_name_facts(name, element, false)?;
        let encoding = self.source().encoding_facts().selected();
        let spelling = spelling_bytes(name, encoding);
        let mut edits = vec![PreparedEdit {
            old_span: element.qname.span,
            replacement: spelling.clone(),
            mapping: Some((target, MappingPlan::Replaced)),
        }];
        // The end-tag name span: `</name>` after the last child, or directly
        // after the start tag for an element without content.
        let empty_element =
            empty_element_tag_close(self.source().bytes(), element.span.end_byte(), encoding);
        if !empty_element {
            let last_child_end = element
                .children
                .last()
                .map_or(element.span.end_byte(), |&index| {
                    self.content_extent_end(index)
                });
            let char_width = char_width(encoding);
            let name_start = last_child_end + 2 * char_width;
            let end_name = self
                .authority()
                .span(name_start, name_start + element.qname.span.len())
                .map_err(|_| EditFailure::TargetNotFound)?;
            edits.push(PreparedEdit {
                old_span: end_name,
                replacement: spelling,
                mapping: None,
            });
        }
        Ok(edits)
    }

    /// Resolves one element occurrence by arena index.
    fn element_for(&self, target: NodeRef) -> Result<&XmlElementData, EditFailure> {
        if target.snapshot() != self.snapshot_identity() || target.role() != NodeRole::XmlElement {
            return Err(EditFailure::WrongSnapshot);
        }
        let index = usize::try_from(target.index()).map_err(|_| EditFailure::TargetNotFound)?;
        let XmlContent::Element(data) =
            self.nodes().get(index).ok_or(EditFailure::TargetNotFound)?
        else {
            return Err(EditFailure::WrongRole);
        };
        if data.index != index {
            return Err(EditFailure::WrongRole);
        }
        Ok(data)
    }

    /// Resolves one attribute association by ordinal.
    fn attribute_for(&self, target: NodeRef) -> Result<&XmlAttributeData, EditFailure> {
        if target.snapshot() != self.snapshot_identity() || target.role() != NodeRole::XmlAttribute
        {
            return Err(EditFailure::WrongSnapshot);
        }
        self.attributes()
            .find(|data| data.ordinal == target.index())
            .ok_or(EditFailure::TargetNotFound)
    }

    /// Resolves one text occurrence by ordinal.
    fn text_for(&self, target: NodeRef) -> Result<&XmlTextData, EditFailure> {
        if target.snapshot() != self.snapshot_identity() || target.role() != NodeRole::XmlText {
            return Err(EditFailure::WrongSnapshot);
        }
        self.texts()
            .find(|data| data.ordinal == target.index())
            .ok_or(EditFailure::TargetNotFound)
    }

    /// The exact end of one content item's full extent: for an element
    /// child this is its closing end tag, not its start-tag end.
    fn content_extent_end(&self, index: usize) -> usize {
        match &self.nodes()[index] {
            XmlContent::Element(data) => {
                let encoding = self.source().encoding_facts().selected();
                let char_width = char_width(encoding);
                let Some(&last_child) = data.children.last() else {
                    // The element's own span covers only the start tag. An
                    // empty-element tag already ends at `/>`; an explicit
                    // `</name>` pair continues past the start tag.
                    if empty_element_tag_close(
                        self.source().bytes(),
                        data.span.end_byte(),
                        encoding,
                    ) {
                        return data.span.end_byte();
                    }
                    return data
                        .span
                        .end_byte()
                        .checked_add(2 * char_width)
                        .and_then(|end| end.checked_add(data.qname.span.len()))
                        .and_then(|end| end.checked_add(char_width))
                        .unwrap_or(data.span.end_byte());
                };
                self.content_extent_end(last_child)
                    .checked_add(2 * char_width)
                    .and_then(|end| end.checked_add(data.qname.span.len()))
                    .and_then(|end| end.checked_add(char_width))
                    .unwrap_or(data.span.end_byte())
            }
            content => content.span().end_byte(),
        }
    }

    /// Resolves one content item span by role.
    fn content_span_for(
        &self,
        target: NodeRef,
    ) -> Result<(NodeRole, consema_document::Span), EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        match target.role() {
            NodeRole::XmlElement => {
                let data = self.element_for(target)?;
                Ok((NodeRole::XmlElement, data.span))
            }
            NodeRole::XmlText => {
                let data = self.text_for(target)?;
                Ok((NodeRole::XmlText, data.span))
            }
            NodeRole::XmlCdata => {
                let data = self
                    .cdatas()
                    .find(|data| data.ordinal == target.index())
                    .ok_or(EditFailure::TargetNotFound)?;
                Ok((NodeRole::XmlCdata, data.span))
            }
            NodeRole::XmlComment => {
                let data = self
                    .comments()
                    .find(|data| data.ordinal == target.index())
                    .ok_or(EditFailure::TargetNotFound)?;
                Ok((NodeRole::XmlComment, data.span))
            }
            NodeRole::XmlProcessingInstruction => {
                let data = self
                    .pis()
                    .find(|data| data.ordinal == target.index())
                    .ok_or(EditFailure::TargetNotFound)?;
                Ok((NodeRole::XmlProcessingInstruction, data.span))
            }
            _ => Err(EditFailure::WrongRole),
        }
    }

    /// Validates name facts against one element's in-scope scope.
    fn validate_name_facts(
        name: &NameFacts,
        element: &XmlElementData,
        attribute: bool,
    ) -> Result<(), EditFailure> {
        if name.local.is_empty()
            || name.local.contains(':')
            || name.local.as_bytes()[0].is_ascii_digit()
            || name.local.as_bytes()[0] == b'-'
        {
            return Err(EditFailure::InvalidQName);
        }
        match (&name.prefix, &name.namespace) {
            (None, Some(uri)) => {
                if attribute {
                    // An unprefixed attribute never carries a namespace.
                    return Err(EditFailure::UnboundPrefix {
                        prefix: String::new(),
                    });
                }
                // An unprefixed element name resolves through the default
                // namespace; it must equal the promised URI.
                let default = element
                    .scope
                    .bindings()
                    .iter()
                    .rev()
                    .find(|binding| binding.prefix.is_none())
                    .map(|binding| binding.uri.as_ref());
                if default != Some(uri.as_str()) {
                    return Err(EditFailure::UnboundPrefix {
                        prefix: String::new(),
                    });
                }
                Ok(())
            }
            (Some(prefix), None) => Err(EditFailure::UnboundPrefix {
                prefix: prefix.clone(),
            }),
            (None, None) => Ok(()),
            (Some(prefix), Some(uri)) => {
                if prefix == "xmlns" {
                    return Err(EditFailure::ReservedPrefix {
                        prefix: prefix.clone(),
                    });
                }
                if prefix == "xml" && uri != crate::namespace::XML_NAMESPACE_URI {
                    return Err(EditFailure::UnboundPrefix {
                        prefix: prefix.clone(),
                    });
                }
                let bound = element
                    .scope
                    .bindings()
                    .iter()
                    .rev()
                    .find(|binding| binding.prefix.as_deref() == Some(prefix.as_str()))
                    .map_or("", |binding| binding.uri.as_ref());
                if bound != uri {
                    return Err(EditFailure::UnboundPrefix {
                        prefix: prefix.clone(),
                    });
                }
                Ok(())
            }
        }
    }

    /// The expanded name promised by name facts, when resolvable.
    fn expanded_name_for_facts(
        name: &NameFacts,
        element: &XmlElementData,
    ) -> Result<Option<crate::namespace::ExpandedName>, EditFailure> {
        let Some(uri) = &name.namespace else {
            return Ok(None);
        };
        if name.prefix.as_deref() == Some("xml") {
            return Ok(Some(crate::namespace::ExpandedName {
                namespace: Some(Arc::from(crate::namespace::XML_NAMESPACE_URI)),
                local: Arc::from(name.local.as_str()),
            }));
        }
        let bound = element
            .scope
            .bindings()
            .iter()
            .rev()
            .find(|binding| binding.prefix.as_deref() == Some(name.prefix.as_deref().unwrap_or("")))
            .map(|binding| binding.uri.as_ref());
        if bound != Some(uri.as_str()) {
            return Err(EditFailure::UnboundPrefix {
                prefix: name.prefix.clone().unwrap_or_default(),
            });
        }
        Ok(Some(crate::namespace::ExpandedName {
            namespace: Some(Arc::from(uri.as_str())),
            local: Arc::from(name.local.as_str()),
        }))
    }

    /// Rejects an attribute whose expanded name already exists on the element.
    fn reject_duplicate_attribute(
        element: &XmlElementData,
        name: &NameFacts,
    ) -> Result<(), EditFailure> {
        let Some(promised) = Self::expanded_name_for_facts(name, element)? else {
            return Ok(());
        };
        if element
            .attributes
            .iter()
            .filter_map(|attribute| attribute.expanded.as_ref())
            .any(|existing| existing == &promised)
        {
            return Err(EditFailure::DuplicateExpandedAttribute);
        }
        Ok(())
    }
}

/// One element and its arena index in document order.
fn find_node_by_span(document: &Document, start: usize, end: usize) -> Option<NodeRef> {
    let mut found = None;
    for content in document.nodes() {
        let span = content.span();
        if span.start_byte() == start && span.end_byte() == end {
            let role = match content {
                XmlContent::Element(_) => NodeRole::XmlElement,
                XmlContent::Text(_) => NodeRole::XmlText,
                XmlContent::Cdata(_) => NodeRole::XmlCdata,
                XmlContent::Comment(_) => NodeRole::XmlComment,
                XmlContent::ProcessingInstruction(_) => NodeRole::XmlProcessingInstruction,
                XmlContent::ErrorRegion(_) => NodeRole::XmlErrorRegion,
            };
            let ordinal = match content {
                XmlContent::Element(data) => data.index as u64,
                XmlContent::Text(data) => data.ordinal,
                XmlContent::Cdata(data) => data.ordinal,
                XmlContent::Comment(data) => data.ordinal,
                XmlContent::ProcessingInstruction(data) => data.ordinal,
                XmlContent::ErrorRegion(data) => data.ordinal,
            };
            found = Some(document.authority().node_ref(ordinal, role));
            break;
        }
    }
    found
}

fn leading_whitespace_start(source: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor > 0 && matches!(source[cursor - 1], b' ' | b'\t' | b'\r' | b'\n') {
        cursor -= 1;
    }
    cursor
}

fn source_patch_limits(limits: XmlParseLimits, operation_count: usize) -> SourcePatchLimits {
    SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: limits.common.max_source_bytes,
            max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
            max_decoded_scalars: limits.max_decoded_scalars,
        },
        max_replacements: operation_count.max(1),
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
                operation_id(operation).to_owned(),
            )
        })
        .collect()
}

fn operation_id(operation: &EditOperation) -> &'static str {
    match operation {
        EditOperation::ReplaceText { .. } => "xml.edit.replace-text@1",
        EditOperation::InsertAttribute { .. } => "xml.edit.insert-attribute@1",
        EditOperation::RemoveAttribute { .. } => "xml.edit.remove-attribute@1",
        EditOperation::RenameAttribute { .. } => "xml.edit.rename-attribute@1",
        EditOperation::SetAttributeValue { .. } => "xml.edit.set-attribute-value@1",
        EditOperation::InsertElement { .. } => "xml.edit.insert-element@1",
        EditOperation::RemoveElement { .. } => "xml.edit.remove-element@1",
        EditOperation::RenameElement { .. } => "xml.edit.rename-element@1",
    }
}

fn operation_summaries(
    transaction: &EditTransaction,
) -> Result<Vec<EditOperationSummary>, EditFailure> {
    transaction
        .operations
        .iter()
        .map(|operation| {
            let (id, arguments) = match operation {
                EditOperation::ReplaceText { text, .. } => (
                    "xml.edit.replace-text",
                    BTreeMap::from([("text_bytes".to_owned(), text.len().to_string())]),
                ),
                EditOperation::InsertAttribute { name, value, .. } => (
                    "xml.edit.insert-attribute",
                    BTreeMap::from([
                        ("name_bytes".to_owned(), name.spelling().len().to_string()),
                        ("value_bytes".to_owned(), value.len().to_string()),
                    ]),
                ),
                EditOperation::RemoveAttribute { .. } => {
                    ("xml.edit.remove-attribute", BTreeMap::new())
                }
                EditOperation::RenameAttribute { name, .. } => (
                    "xml.edit.rename-attribute",
                    BTreeMap::from([("name_bytes".to_owned(), name.spelling().len().to_string())]),
                ),
                EditOperation::SetAttributeValue { value, .. } => (
                    "xml.edit.set-attribute-value",
                    BTreeMap::from([("value_bytes".to_owned(), value.len().to_string())]),
                ),
                EditOperation::InsertElement { name, content, .. } => (
                    "xml.edit.insert-element",
                    BTreeMap::from([
                        ("name_bytes".to_owned(), name.spelling().len().to_string()),
                        (
                            "content_bytes".to_owned(),
                            content.as_deref().unwrap_or("").len().to_string(),
                        ),
                    ]),
                ),
                EditOperation::RemoveElement { .. } => ("xml.edit.remove-element", BTreeMap::new()),
                EditOperation::RenameElement { name, .. } => (
                    "xml.edit.rename-element",
                    BTreeMap::from([("name_bytes".to_owned(), name.spelling().len().to_string())]),
                ),
            };
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::InvalidQName)
        })
        .collect()
}

/// Iterators over the document's occurrence families.
impl Document {
    fn attributes(&self) -> impl Iterator<Item = &XmlAttributeData> {
        self.nodes()
            .iter()
            .filter_map(|content| match content {
                XmlContent::Element(data) => Some(data.attributes.iter()),
                _ => None,
            })
            .flatten()
    }

    fn texts(&self) -> impl Iterator<Item = &XmlTextData> {
        self.nodes().iter().filter_map(|content| match content {
            XmlContent::Text(data) => Some(data),
            _ => None,
        })
    }

    fn cdatas(&self) -> impl Iterator<Item = &crate::document::XmlCdataData> {
        self.nodes().iter().filter_map(|content| match content {
            XmlContent::Cdata(data) => Some(data),
            _ => None,
        })
    }

    fn comments(&self) -> impl Iterator<Item = &crate::document::XmlCommentData> {
        self.nodes().iter().filter_map(|content| match content {
            XmlContent::Comment(data) => Some(data),
            _ => None,
        })
    }

    fn pis(&self) -> impl Iterator<Item = &crate::document::XmlPiData> {
        self.nodes().iter().filter_map(|content| match content {
            XmlContent::ProcessingInstruction(data) => Some(data),
            _ => None,
        })
    }

    fn elements(&self) -> impl Iterator<Item = (usize, &XmlElementData)> {
        self.nodes()
            .iter()
            .enumerate()
            .filter_map(|(index, content)| match content {
                XmlContent::Element(data) => Some((index, data)),
                _ => None,
            })
    }

    fn node_role(&self, index: usize) -> NodeRole {
        match &self.nodes()[index] {
            XmlContent::Element(_) => NodeRole::XmlElement,
            XmlContent::Text(_) => NodeRole::XmlText,
            XmlContent::Cdata(_) => NodeRole::XmlCdata,
            XmlContent::Comment(_) => NodeRole::XmlComment,
            XmlContent::ProcessingInstruction(_) => NodeRole::XmlProcessingInstruction,
            XmlContent::ErrorRegion(_) => NodeRole::XmlErrorRegion,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::text_semantic;
    use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile};
    use consema_core::StableFailure;
    use consema_document::FormationStatus;
    use std::sync::Arc;

    fn parse_utf8(source: &[u8]) -> Document {
        let bytes: Arc<[u8]> = Arc::from(source);
        parse(
            bytes,
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("forms")
    }

    /// Encodes text as BOM-prefixed UTF-16 in the requested endianness.
    fn utf16_bytes(source: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for unit in source.encode_utf16() {
            if little_endian {
                bytes.extend_from_slice(&unit.to_le_bytes());
            } else {
                bytes.extend_from_slice(&unit.to_be_bytes());
            }
        }
        bytes
    }

    fn parse_utf16(source: &str, little_endian: bool) -> Document {
        let bytes: Arc<[u8]> = Arc::from(utf16_bytes(source, little_endian));
        parse(
            bytes,
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("UTF-16 forms")
    }

    fn root_element(document: &Document) -> XmlElementData {
        let index = document.root().expect("root").data().index;
        let XmlContent::Element(data) = &document.nodes()[index] else {
            panic!("root is element");
        };
        data.clone()
    }

    fn element_index(document: &Document, name: &str) -> usize {
        document
            .elements()
            .find(|(_, data)| data.qname.local.as_ref() == name)
            .map(|(index, _)| index)
            .expect("element exists")
    }

    fn element_ref(document: &Document, name: &str) -> NodeRef {
        document
            .authority()
            .node_ref(element_index(document, name) as u64, NodeRole::XmlElement)
    }

    fn attribute_ref(document: &Document, name: &str) -> NodeRef {
        let (_, element) = document
            .elements()
            .find(|(_, data)| {
                data.attributes
                    .iter()
                    .any(|a| a.qname.local.as_ref() == name)
            })
            .expect("attribute exists");
        let attribute = element
            .attributes
            .iter()
            .find(|a| a.qname.local.as_ref() == name)
            .expect("attribute");
        document
            .authority()
            .node_ref(attribute.ordinal, NodeRole::XmlAttribute)
    }

    fn text_ref(document: &Document) -> NodeRef {
        let (_, element) = document
            .elements()
            .find(|(_, data)| {
                data.children
                    .iter()
                    .any(|&i| matches!(document.nodes()[i], XmlContent::Text(_)))
            })
            .expect("element with text");
        let index = *element
            .children
            .iter()
            .find(|&&i| matches!(document.nodes()[i], XmlContent::Text(_)))
            .expect("text child");
        let XmlContent::Text(data) = &document.nodes()[index] else {
            unreachable!()
        };
        document
            .authority()
            .node_ref(data.ordinal, NodeRole::XmlText)
    }

    fn patch_limits() -> consema_document::SourcePatchLimits {
        consema_document::SourcePatchLimits {
            source: consema_document::SourceLimits {
                max_raw_bytes: 1024 * 1024,
                max_decoded_utf8_bytes: 1024 * 1024,
                max_decoded_scalars: 1024 * 1024,
            },
            max_replacements: 64,
            max_patch_bytes: 1024 * 1024,
        }
    }

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

    #[test]
    fn replace_text_escapes_and_replaces_whole_occurrence() {
        let document = parse_utf8(br"<root>a &lt; b</root>");
        let target = text_ref(&document);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.replace_text(target, "x < y & z");
        let new = commit(&document, builder.build());
        assert_eq!(new.render(), br"<root>x &lt; y &amp; z</root>");
    }

    #[test]
    fn insert_remove_attribute_with_placement() {
        let document = parse_utf8(br#"<root a="1" b="2"/>"#);
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let b_ref = attribute_ref(&document, "b");

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(None, "c".to_owned(), None),
            "3",
            AttributePlacement::Before(b_ref),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br#"<root a="1" c="3" b="2"/>"#.as_slice());

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(None, "d".to_owned(), None),
            "4",
            AttributePlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br#"<root a="1" b="2" d="4"/>"#.as_slice());

        let b_ref_after = attribute_ref(&after, "b");
        let mut builder = EditTransactionBuilder::new(&after);
        builder.remove_attribute(b_ref_after);
        let after = commit(&after, builder.build());
        assert_eq!(after.render(), br#"<root a="1" d="4"/>"#.as_slice());
    }

    #[test]
    fn set_and_rename_attribute() {
        let document = parse_utf8(br#"<root a="1"/>"#);
        let a_ref = attribute_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(a_ref, "v & w");
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br#"<root a="v &amp; w"/>"#.as_slice());

        let a_ref = attribute_ref(&after, "a");
        let mut builder = EditTransactionBuilder::new(&after);
        builder.rename_attribute(a_ref, NameFacts::new(None, "renamed".to_owned(), None));
        let after = commit(&after, builder.build());
        assert_eq!(after.render(), br#"<root renamed="v &amp; w"/>"#.as_slice());
    }

    #[test]
    fn prefixed_attribute_operations_validate_bindings() {
        let document = parse_utf8(br#"<root xmlns:p="urn:p" p:a="1"/>"#);
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(
                Some("p".to_owned()),
                "b".to_owned(),
                Some("urn:p".to_owned()),
            ),
            "2",
            AttributePlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            br#"<root xmlns:p="urn:p" p:a="1" p:b="2"/>"#.as_slice()
        );

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(
                Some("q".to_owned()),
                "b".to_owned(),
                Some("urn:q".to_owned()),
            ),
            "2",
            AttributePlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::UnboundPrefix { .. })
        ));
        assert_eq!(
            document.render(),
            br#"<root xmlns:p="urn:p" p:a="1"/>"#.as_slice(),
            "atomicity"
        );

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(
                Some("p".to_owned()),
                "a".to_owned(),
                Some("urn:p".to_owned()),
            ),
            "2",
            AttributePlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::DuplicateExpandedAttribute)
        ));
        assert_eq!(
            document.render(),
            br#"<root xmlns:p="urn:p" p:a="1"/>"#.as_slice(),
            "atomicity"
        );
    }

    #[test]
    fn insert_remove_element_with_anchors() {
        let document = parse_utf8(br"<root><a/></root>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let a_ref = element_ref(&document, "a");

        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            Some("content".to_owned()),
            ContentPlacement::Before(a_ref),
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            br"<root><x>content</x><a/></root>".as_slice()
        );

        let root = root_element(&after);
        let root_ref = after
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&after);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "y".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        let after = commit(&after, builder.build());
        assert_eq!(
            after.render(),
            br"<root><x>content</x><a/><y/></root>".as_slice()
        );

        let a_ref = element_ref(&after, "a");
        let mut builder = EditTransactionBuilder::new(&after);
        builder.remove_element(a_ref);
        let after = commit(&after, builder.build());
        assert_eq!(
            after.render(),
            br"<root><x>content</x><y/></root>".as_slice()
        );
    }

    #[test]
    fn remove_root_is_rejected() {
        let document = parse_utf8(br"<root/>");
        let root = document.root().expect("root").node_ref();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(root);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::CannotRemoveRoot)
        ));
        assert_eq!(document.render(), br"<root/>".as_slice(), "atomicity");
    }

    #[test]
    fn recovered_base_documents_are_rejected_before_any_edit() {
        // RFC 0012 §4: edit commit requires a Complete Document. A Recovered
        // base (here an unbound-prefix namespace error) must be rejected
        // even when the edit itself would repair it — removing the
        // `p:child` element would render a Complete `<root></root>` — so
        // the gate is what fails, not reparse of the target.
        let source = br"<root><p:child/></root>";
        let document = parse_utf8(source);
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.namespace.unbound-prefix@1")
        );
        let child_ref = element_ref(&document, "child");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(child_ref);
        let error = document
            .commit(&builder.build())
            .expect_err("recovered base must be rejected");
        assert_eq!(error, EditFailure::IncompleteTarget);
        assert_eq!(error.diagnostic_code(), "core.edit.incomplete-target@1");
        assert_eq!(document.render(), source, "atomicity");
    }

    #[test]
    fn rename_element_rewrites_both_tags() {
        let document = parse_utf8(br"<old><child>t</child></old>");
        let old_ref = element_ref(&document, "old");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(old_ref, NameFacts::new(None, "new".to_owned(), None));
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<new><child>t</child></new>".as_slice());

        let document = parse_utf8(br"<old/>");
        let old_ref = element_ref(&document, "old");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(old_ref, NameFacts::new(None, "new".to_owned(), None));
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<new/>".as_slice());
    }

    #[test]
    fn prefixed_rename_respects_scope() {
        let document = parse_utf8(br#"<root xmlns:p="urn:p"><p:old/></root>"#);
        let old_ref = element_ref(&document, "old");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(
            old_ref,
            NameFacts::new(
                Some("p".to_owned()),
                "new".to_owned(),
                Some("urn:p".to_owned()),
            ),
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            br#"<root xmlns:p="urn:p"><p:new/></root>"#.as_slice()
        );
    }

    #[test]
    fn multi_operation_transaction_is_atomic() {
        let document = parse_utf8(br#"<root a="1">t</root>"#);
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let a_ref = attribute_ref(&document, "a");
        let text = text_ref(&document);

        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(a_ref, "2")
            .replace_text(text, "u")
            .insert_attribute(
                root_ref,
                NameFacts::new(None, "b".to_owned(), None),
                "3",
                AttributePlacement::End,
            );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br#"<root a="2" b="3">u</root>"#.as_slice());
    }

    #[test]
    fn conflicting_targets_and_stale_snapshots_fail() {
        let document = parse_utf8(br#"<root a="1">t</root>"#);
        let a_ref = attribute_ref(&document, "a");

        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(a_ref, "2")
            .set_attribute_value(a_ref, "3");
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::ConflictingEdits)
        ));
        assert_eq!(
            document.render(),
            br#"<root a="1">t</root>"#.as_slice(),
            "atomicity"
        );

        let other = parse_utf8(br"<other/>");
        let mut builder = EditTransactionBuilder::new(&other);
        builder.set_attribute_value(a_ref, "2");
        assert!(matches!(
            other.commit(&builder.build()),
            Err(EditFailure::WrongSnapshot)
        ));
        assert_eq!(other.render(), br"<other/>".as_slice(), "atomicity");
    }

    #[test]
    fn dry_run_matches_commit() {
        let document = parse_utf8(br#"<root a="1"/>"#);
        let a_ref = attribute_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.set_attribute_value(a_ref, "changed");
        let transaction = builder.build();
        let commit = document.commit(&transaction).expect("commit");
        let plan = document
            .dry_run(
                &transaction,
                EditPlanSourceId::new("test").expect("valid id"),
            )
            .expect("plan");
        assert_eq!(
            plan.replacements().len(),
            commit.source_patch.replacements().len()
        );
        assert_eq!(
            plan.replacements().len(),
            commit.source_patch.replacements().len()
        );
        assert_eq!(plan.operations().len(), 1);
    }

    #[test]
    fn edit_failure_matrix_never_renders_partial_targets() {
        // Every rejected transaction must leave the snapshot byte-exact; the
        // assertions below also pin the exact variant each scenario produces.
        let document = parse_utf8(br#"<root><a x="1">t</a></root>"#);
        let original = document.render().to_vec();
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let a_ref = element_ref(&document, "a");
        let x_ref = attribute_ref(&document, "x");

        // The audit's ancestor/descendant scenario — an attribute edit plus
        // removal of the attribute's owning element in one transaction — is
        // proven by exact span overlap in the prepare pass. The element's
        // owned span (its start tag) contains the attribute value span, so
        // the conflict surfaces as OverlappingOwnership.
        // (EditFailure::AncestorDescendantConflict has no emission path in
        // this crate; the same overlap proof would be its trigger.)
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .set_attribute_value(x_ref, "2")
            .remove_element(a_ref);
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::OverlappingOwnership)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // Two insertions at the same End position share one target, so the
        // target-level dependency check fires ConflictingEdits before any
        // span is computed (the identical empty spans would also overlap).
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_element(
                root_ref,
                NameFacts::new(None, "x".to_owned(), None),
                None,
                ContentPlacement::End,
            )
            .insert_element(
                root_ref,
                NameFacts::new(None, "y".to_owned(), None),
                None,
                ContentPlacement::End,
            );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::ConflictingEdits)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // The insertion anchor is itself renamed by the same transaction
        // when the anchor operation is declared after the modification.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(a_ref, NameFacts::new(None, "renamed".to_owned(), None));
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::Before(a_ref),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::PlacementAnchorModified)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // A NodeRef whose role cannot be a content anchor fails as WrongRole.
        // (A text-role NodeRef actually surfaces WrongSnapshot: element_for
        // classifies a role mismatch with the snapshot gate, so the anchor
        // role gate is exercised with a namespace-binding ref instead.)
        let binding_ref = document
            .authority()
            .node_ref(0, NodeRole::XmlNamespaceBinding);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::Before(binding_ref),
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::WrongRole)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // A same-snapshot NodeRef pointing past the arena fails as
        // TargetNotFound. (A ref from another snapshot is rejected earlier as
        // WrongSnapshot, covered by conflicting_targets_and_stale_snapshots_fail.)
        let dangling = document
            .authority()
            .node_ref(u64::MAX, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(dangling, NameFacts::new(None, "x".to_owned(), None));
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::TargetNotFound)
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");
    }

    #[test]
    fn name_facts_failure_matrix_never_renders_partial_targets() {
        let document = parse_utf8(br"<root/>");
        let original = document.render().to_vec();
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);

        // InvalidQName: empty local, digit-leading local, colon inside local.
        for local in ["", "1x", "a:b"] {
            let mut builder = EditTransactionBuilder::new(&document);
            builder.insert_element(
                root_ref,
                NameFacts::new(None, local.to_owned(), None),
                None,
                ContentPlacement::End,
            );
            assert!(matches!(
                document.commit(&builder.build()),
                Err(EditFailure::InvalidQName)
            ));
            assert_eq!(document.render(), original.as_slice(), "atomicity");
        }

        // ReservedPrefix: the `xmlns` prefix cannot be an ordinary name.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(
                Some("xmlns".to_owned()),
                "x".to_owned(),
                Some("urn:x".to_owned()),
            ),
            None,
            ContentPlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::ReservedPrefix { .. })
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // The reserved `xml` prefix promised to a foreign namespace is
        // rejected as UnboundPrefix by validate_name_facts (the audit listed
        // it under ReservedPrefix, but the emission site maps it there).
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(
                Some("xml".to_owned()),
                "x".to_owned(),
                Some("urn:not-xml".to_owned()),
            ),
            None,
            ContentPlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::UnboundPrefix { prefix }) if prefix == "xml"
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // UnboundPrefix (None, Some(uri)): an unprefixed element name
        // promising a namespace the default namespace does not bind.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), Some("urn:x".to_owned())),
            None,
            ContentPlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::UnboundPrefix { .. })
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");

        // UnboundPrefix (Some(prefix), None): a prefixed name must always
        // promise the URI its prefix resolves to.
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(Some("p".to_owned()), "x".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::UnboundPrefix { prefix }) if prefix == "p"
        ));
        assert_eq!(document.render(), original.as_slice(), "atomicity");
    }

    #[test]
    fn attribute_and_content_after_placement_succeed() {
        let document = parse_utf8(br#"<root a="1"/>"#);
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let a_ref = attribute_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_attribute(
            root_ref,
            NameFacts::new(None, "b".to_owned(), None),
            "2",
            AttributePlacement::After(a_ref),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br#"<root a="1" b="2"/>"#.as_slice());

        let document = parse_utf8(br"<root><a/>t</root>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let a_ref = element_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            Some("v".to_owned()),
            ContentPlacement::After(a_ref),
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><a/><x>v</x>t</root>".as_slice());
    }

    #[test]
    fn inserted_content_is_xml_escaped() {
        let document = parse_utf8(br"<root><a/></root>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            Some("a & b < c".to_owned()),
            ContentPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            br"<root><a/><x>a &amp; b &lt; c</x></root>".as_slice()
        );
    }

    #[test]
    fn rename_element_on_utf16_sources_succeeds() {
        // Both tags are rewritten with replacement bytes encoded in the
        // source encoding; the committed render is a fresh, reparseable
        // UTF-16 stream with its BOM retained exactly once.
        for little_endian in [true, false] {
            let document = parse_utf16("<old><child>t</child></old>", little_endian);
            let old_ref = element_ref(&document, "old");
            let mut builder = EditTransactionBuilder::new(&document);
            builder.rename_element(old_ref, NameFacts::new(None, "new".to_owned(), None));
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<new><child>t</child></new>", little_endian).as_slice()
            );
        }
    }

    #[test]
    fn change_set_maps_renamed_unmapped_and_removed_deleted() {
        let document = parse_utf8(br"<root><a/></root>");
        let a_ref = element_ref(&document, "a");

        // The rename replaces only the QName span, but node-mapping lookup
        // matches whole node spans, so the renamed element cannot be located
        // by span and the mapping stays Unmapped with its stable reason
        // (the ini baseline's rename -> Replaced does not hold here).
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_element(a_ref, NameFacts::new(None, "renamed".to_owned(), None));
        let commit = document.commit(&builder.build()).expect("commit succeeds");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Unmapped);
        assert!(mapping.new.is_none());
        assert_eq!(
            mapping.reason.as_deref(),
            Some("reparsed-node-not-uniquely-located")
        );

        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(a_ref);
        let commit = document.commit(&builder.build()).expect("commit succeeds");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Deleted);
        assert!(mapping.new.is_none(), "a removed element maps to nothing");
    }

    #[test]
    fn replace_text_maps_to_replaced() {
        // A text occurrence is the only whole-node span a replacement can
        // cover exactly, so ReplaceText maps Replaced.
        let document = parse_utf8(br"<root>old</root>");
        let text = text_ref(&document);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.replace_text(text, "new");
        let commit = document.commit(&builder.build()).expect("commit succeeds");
        assert_eq!(commit.change_set.node_mappings().len(), 1);
        let mapping = &commit.change_set.node_mappings()[0];
        assert_eq!(mapping.status, NodeMappingStatus::Replaced);
        assert!(
            mapping.new.is_some(),
            "the replaced text occurrence must be located in the new snapshot"
        );
    }

    #[test]
    fn replace_text_on_utf16_sources_encodes_replacement() {
        // Escaped literal content is written in the source encoding; the
        // committed render is byte-exact UTF-16 (even byte count, one BOM)
        // and the reparse yields the promised text semantics.
        for little_endian in [true, false] {
            let document = parse_utf16("<root>a &amp; b</root>", little_endian);
            let target = text_ref(&document);
            let mut builder = EditTransactionBuilder::new(&document);
            builder.replace_text(target, "x < y & z 中文");
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root>x &lt; y &amp; z 中文</root>", little_endian).as_slice()
            );
            let index = after
                .nodes()
                .iter()
                .position(|content| matches!(content, XmlContent::Text(_)))
                .expect("text node");
            let XmlContent::Text(data) = &after.nodes()[index] else {
                unreachable!()
            };
            assert_eq!(text_semantic(data), "x < y & z 中文");
        }
    }

    #[test]
    fn set_attribute_value_on_utf16_sources_encodes_value() {
        for little_endian in [true, false] {
            let document = parse_utf16("<root a=\"1\"/>", little_endian);
            let a_ref = attribute_ref(&document, "a");
            let mut builder = EditTransactionBuilder::new(&document);
            builder.set_attribute_value(a_ref, "v & w \"q\" 中文");
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root a=\"v &amp; w &quot;q&quot; 中文\"/>", little_endian).as_slice()
            );
        }
    }

    #[test]
    fn insert_attribute_on_utf16_sources_encodes_value() {
        for little_endian in [true, false] {
            let document = parse_utf16("<root a=\"1\"/>", little_endian);
            let root = root_element(&document);
            let root_ref = document
                .authority()
                .node_ref(root.index as u64, NodeRole::XmlElement);
            let mut builder = EditTransactionBuilder::new(&document);
            builder.insert_attribute(
                root_ref,
                NameFacts::new(None, "b".to_owned(), None),
                "2 & 3",
                AttributePlacement::End,
            );
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root a=\"1\" b=\"2 &amp; 3\"/>", little_endian).as_slice()
            );
        }
    }

    #[test]
    fn insert_element_on_utf16_sources_encodes_markup() {
        for little_endian in [true, false] {
            let document = parse_utf16("<root><a/></root>", little_endian);
            let root = root_element(&document);
            let root_ref = document
                .authority()
                .node_ref(root.index as u64, NodeRole::XmlElement);
            let mut builder = EditTransactionBuilder::new(&document);
            builder.insert_element(
                root_ref,
                NameFacts::new(None, "x".to_owned(), None),
                Some("t & u 中文".to_owned()),
                ContentPlacement::End,
            );
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root><a/><x>t &amp; u 中文</x></root>", little_endian).as_slice()
            );
        }
    }

    #[test]
    fn remove_element_removes_full_extent_including_end_tag() {
        // A non-empty element's span covers only its start tag; the removal
        // must consume the whole subtree and the closing `</name>`.
        let document = parse_utf8(br"<root><a><b>t</b></a><c/></root>");
        let a_ref = element_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(a_ref);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><c/></root>".as_slice());

        // Mixed content: text children and nested elements are removed too.
        let document = parse_utf8(br"<root><a>x<b>y</b>z</a><c/></root>");
        let a_ref = element_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(a_ref);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><c/></root>".as_slice());

        // An explicit empty pair completes the extent even though the element
        // has no children.
        let document = parse_utf8(br"<root><a></a><c/></root>");
        let a_ref = element_ref(&document, "a");
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_element(a_ref);
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><c/></root>".as_slice());
    }

    #[test]
    fn remove_element_on_utf16_source_removes_end_tag() {
        // The extent math counts raw bytes (two per decoded unit), so a
        // removal on UTF-16 leaves no stray end-tag bytes behind.
        for little_endian in [true, false] {
            let document = parse_utf16("<root><a><b>t</b></a><c/></root>", little_endian);
            let a_ref = element_ref(&document, "a");
            let mut builder = EditTransactionBuilder::new(&document);
            builder.remove_element(a_ref);
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root><c/></root>", little_endian).as_slice()
            );
        }
    }

    #[test]
    fn insert_element_end_into_empty_element_places_before_slash_close() {
        // `<root/>`: the insert point must fall before the `/>`, not after
        // the whole empty-element tag (which would create a second root).
        let document = parse_utf8(br"<root/>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><x/></root>".as_slice());

        // `<root></root>`: the insert point lies before the explicit end tag.
        let document = parse_utf8(br"<root></root>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><x/></root>".as_slice());

        // The `/>`-close replacement also works on UTF-16 sources, where the
        // close pair occupies four bytes.
        for little_endian in [true, false] {
            let document = parse_utf16("<root/>", little_endian);
            let root = root_element(&document);
            let root_ref = document
                .authority()
                .node_ref(root.index as u64, NodeRole::XmlElement);
            let mut builder = EditTransactionBuilder::new(&document);
            builder.insert_element(
                root_ref,
                NameFacts::new(None, "x".to_owned(), None),
                None,
                ContentPlacement::End,
            );
            let after = commit(&document, builder.build());
            assert_eq!(
                after.render(),
                utf16_bytes("<root><x/></root>", little_endian).as_slice()
            );
        }

        // A prefixed parent re-closes with its own QName spelling.
        let document = parse_utf8(br#"<p:root xmlns:p="urn:p"/>"#);
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(
            after.render(),
            br#"<p:root xmlns:p="urn:p"><x/></p:root>"#.as_slice()
        );

        // A non-empty parent appends after the last child's full extent,
        // including a nested element's end tag.
        let document = parse_utf8(br"<root><a/></root>");
        let root = root_element(&document);
        let root_ref = document
            .authority()
            .node_ref(root.index as u64, NodeRole::XmlElement);
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_element(
            root_ref,
            NameFacts::new(None, "x".to_owned(), None),
            None,
            ContentPlacement::End,
        );
        let after = commit(&document, builder.build());
        assert_eq!(after.render(), br"<root><a/><x/></root>".as_slice());
    }
}
