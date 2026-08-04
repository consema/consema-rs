//! Snapshot-bound atomic YAML structural editing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity, FailureKind,
    OperationKind, PortableValue, PortableValueKind, StableFailure,
};
pub use consema_document::AssociationPlacement;
use consema_document::{
    ChangeSet, DecodedOffset, EditOperationSummary, EditPlan, EditPlanSourceId, FormatOperationId,
    MaterializationLimits, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NodeMapping, NodeMappingStatus, NodeRef, NodeRole, SnapshotIdentity, SourceEdit,
    SourceEncoding, SourceLimits, SourcePatch, SourcePatchLimits, Span, UntouchedByteProof,
};

use crate::native::NativeContent;
use crate::{Document, YamlNodeKind, YamlProfile, YamlScalarKind, YamlScalarStyle, YamlSyntaxKind};

/// Explicit semantic scalar representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must use an exact literal operation instead.
    ExactLiteral,
    /// Retain the target scalar category and presentation style or fail.
    PreserveCompatible,
    /// Use the frozen canonical YAML scalar representation.
    CanonicalForProfile,
    /// Preserve when compatible, otherwise report canonical fallback.
    PreserveElseCanonical,
}

/// One scalar operation bound to the transaction's base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarReplacement {
    /// Replace by a complete core scalar under an explicit policy.
    Semantic {
        /// Exact YAML representation-node target.
        target: NodeRef,
        /// New complete core scalar.
        value: PortableValue,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replace only the exact scalar literal bytes after profile validation.
    Literal {
        /// Exact YAML representation-node target.
        target: NodeRef,
        /// Candidate bytes in the base document's selected encoding.
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

/// One typed YAML edit operation bound to an immutable base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditOperation {
    /// Existing scalar semantic or literal replacement.
    ReplaceScalar(ScalarReplacement),
    /// Rename one anchor definition and all aliases that resolve to it.
    RenameAnchor {
        /// Exact YAML anchor-definition target.
        target: NodeRef,
        /// New decoded anchor name.
        name: String,
    },
    /// Insert one arbitrary-key mapping association using canonical flow fragments.
    InsertMappingEntry {
        /// Mapping representation node to mutate.
        mapping: NodeRef,
        /// Complete portable key.
        key: PortableValue,
        /// Complete portable value.
        value: PortableValue,
        /// Snapshot-bound association placement.
        placement: AssociationPlacement,
    },
    /// Remove one exact mapping association.
    RemoveMappingEntry {
        /// Mapping-association identity to remove.
        target: NodeRef,
    },
    /// Insert one sequence association using a canonical flow fragment.
    InsertSequenceElement {
        /// Sequence representation node to mutate.
        sequence: NodeRef,
        /// Complete portable element value.
        value: PortableValue,
        /// Snapshot-bound association placement.
        placement: AssociationPlacement,
    },
    /// Remove one exact sequence association.
    RemoveSequenceElement {
        /// Sequence-association identity to remove.
        target: NodeRef,
    },
    /// Insert an alias edge into a sequence without expanding its target.
    InsertAlias {
        /// Sequence representation node to mutate.
        sequence: NodeRef,
        /// Earlier visible anchor definition to reference.
        anchor: NodeRef,
        /// Snapshot-bound association placement.
        placement: AssociationPlacement,
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

/// Builder that does not mutate or commit a document.
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

    /// Adds one semantic scalar replacement.
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

    /// Adds one exact scalar-literal replacement.
    pub fn literal_scalar(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations
            .push(EditOperation::ReplaceScalar(ScalarReplacement::Literal {
                target,
                literal: literal.into(),
            }));
        self
    }

    /// Adds one anchor rename that also updates every dependent alias.
    pub fn rename_anchor(&mut self, target: NodeRef, name: impl Into<String>) -> &mut Self {
        self.operations.push(EditOperation::RenameAnchor {
            target,
            name: name.into(),
        });
        self
    }

    /// Adds one arbitrary-key mapping association insertion.
    pub fn insert_mapping_entry(
        &mut self,
        mapping: NodeRef,
        key: PortableValue,
        value: PortableValue,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertMappingEntry {
            mapping,
            key,
            value,
            placement,
        });
        self
    }

    /// Adds one exact mapping-association removal.
    pub fn remove_mapping_entry(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveMappingEntry { target });
        self
    }

    /// Adds one sequence value insertion.
    pub fn insert_sequence_element(
        &mut self,
        sequence: NodeRef,
        value: PortableValue,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertSequenceElement {
            sequence,
            value,
            placement,
        });
        self
    }

    /// Adds one exact sequence-association removal.
    pub fn remove_sequence_element(&mut self, target: NodeRef) -> &mut Self {
        self.operations
            .push(EditOperation::RemoveSequenceElement { target });
        self
    }

    /// Adds one sequence alias insertion to an earlier visible anchor.
    pub fn insert_alias(
        &mut self,
        sequence: NodeRef,
        anchor: NodeRef,
        placement: AssociationPlacement,
    ) -> &mut Self {
        self.operations.push(EditOperation::InsertAlias {
            sequence,
            anchor,
            placement,
        });
        self
    }

    /// Completes the immutable request; validation happens atomically at commit.
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
    /// New immutable YAML document.
    pub document: Document,
    /// Complete old-to-new change facts.
    pub change_set: ChangeSet,
    /// Portable exact raw-byte application fact.
    pub source_patch: SourcePatch,
    /// Evidence that every byte outside the replacement set is unchanged.
    pub untouched_proof: UntouchedByteProof,
}

/// Stable YAML edit validation or commit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditFailure {
    /// Transaction or target belongs to another snapshot.
    WrongSnapshot,
    /// Target role does not match the selected operation.
    WrongRole,
    /// Target identity is not present in the base document.
    TargetNotFound,
    /// Target is not one complete editable scalar or anchor occurrence.
    IncompleteTarget,
    /// Public value cannot be represented as a YAML scalar.
    UnsupportedSemanticValue(PortableValueKind),
    /// Exact candidate is not one complete scalar literal.
    InvalidLiteral,
    /// PreserveCompatible could not retain category and presentation style.
    RepresentationIncompatible,
    /// ExactLiteral was requested without an exact literal operation.
    ExactLiteralRequiresLiteralOperation,
    /// New anchor name is not accepted as one exact anchor property.
    InvalidAnchorName,
    /// Placement anchor is from another container or has the wrong association role.
    InvalidPlacement,
    /// Inserted alias target is not the last visible definition of its name.
    AnchorNotVisible,
    /// Removal would leave an alias whose anchor definition no longer exists.
    AnchorDependency,
    /// Portable input cannot be represented exactly by the YAML value materializer.
    UnsupportedInsertedValue(PortableValueKind),
    /// More than one structural mutation targets the same base container.
    StructuralContainerConflict,
    /// More than one operation names the same destructive target.
    DuplicateTarget,
    /// Prepared source ownership intervals overlap or reuse an insertion point.
    OverlappingOwnership,
    /// One operation edits an ancestor/descendant region of another operation.
    AncestorDescendantConflict,
    /// A configured edit or output bound was exceeded.
    ResourceLimit(&'static str),
    /// Replacement bytes did not form the promised YAML document and topology.
    NewDocumentFormationFailed,
}

/// Stable semantic-model v5 diagnostic code for YAML editing.
#[must_use]
pub const fn edit_failure_code(error: &EditFailure) -> &'static str {
    match error {
        EditFailure::WrongSnapshot => "core.edit.wrong-snapshot@1",
        EditFailure::WrongRole => "core.edit.wrong-role@1",
        EditFailure::TargetNotFound => "core.edit.target-not-found@1",
        EditFailure::IncompleteTarget => "core.edit.incomplete-target@1",
        EditFailure::UnsupportedSemanticValue(_) | EditFailure::UnsupportedInsertedValue(_) => {
            "core.edit.unsupported-value@1"
        }
        EditFailure::InvalidLiteral => "core.edit.invalid-literal@1",
        EditFailure::RepresentationIncompatible => "core.edit.representation-incompatible@1",
        EditFailure::ExactLiteralRequiresLiteralOperation => {
            "core.edit.exact-literal-requires-literal@1"
        }
        EditFailure::InvalidAnchorName => "yaml.edit.invalid-anchor-name@1",
        EditFailure::InvalidPlacement => "yaml.edit.invalid-placement@1",
        EditFailure::AnchorNotVisible => "yaml.edit.anchor-not-visible@1",
        EditFailure::AnchorDependency => "yaml.edit.anchor-dependency@1",
        EditFailure::StructuralContainerConflict => "yaml.edit.structural-container-conflict@1",
        EditFailure::DuplicateTarget
        | EditFailure::OverlappingOwnership
        | EditFailure::AncestorDescendantConflict => "core.edit.conflicting-edits@1",
        EditFailure::ResourceLimit(_) => "core.edit.resource-limit@1",
        EditFailure::NewDocumentFormationFailed => "core.edit.formation-failed@1",
    }
}

impl StableFailure for EditFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Edit
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::WrongSnapshot | Self::WrongRole | Self::TargetNotFound => {
                FailureKind::TargetMismatch
            }
            Self::UnsupportedSemanticValue(_) | Self::UnsupportedInsertedValue(_) => {
                FailureKind::Unsupported
            }
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::IncompleteTarget
            | Self::InvalidLiteral
            | Self::RepresentationIncompatible
            | Self::ExactLiteralRequiresLiteralOperation
            | Self::InvalidAnchorName
            | Self::InvalidPlacement
            | Self::AnchorNotVisible
            | Self::AnchorDependency
            | Self::StructuralContainerConflict
            | Self::DuplicateTarget
            | Self::OverlappingOwnership
            | Self::AncestorDescendantConflict
            | Self::NewDocumentFormationFailed => FailureKind::InvalidInput,
        }
    }

    fn diagnostic_code(&self) -> &str {
        edit_failure_code(self)
    }
}

#[derive(Clone, Debug)]
struct PreparedEdit {
    old_span: Span,
    replacement: Vec<u8>,
    mapping: Option<(NodeRef, MappingPlan)>,
}

#[derive(Debug, Default)]
struct CandidateMap {
    nodes: HashMap<usize, usize>,
    aliases: HashMap<usize, usize>,
}

#[derive(Clone, Copy, Debug)]
enum MappingPlan {
    Node(usize),
    Anchor(usize),
    Alias(usize),
    Removed,
}

impl Document {
    /// Atomically commits validated YAML scalar, collection, anchor, and alias operations.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        self.validate_dependencies(transaction)?;
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::new();
        prepared
            .try_reserve(transaction.operations.len())
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        for operation in transaction.operations.iter() {
            prepared.extend(self.prepare_operation(operation, &mut diagnostics)?);
        }
        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        validate_prepared_ownership(&prepared)?;
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
        let new_document = crate::parse(rendered, self.profile, self.parse_limits)
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;
        let candidate_map = self.validate_candidate(&new_document, transaction)?;

        let mut delta = 0_isize;
        let mut source_edits = Vec::new();
        source_edits
            .try_reserve(prepared.len())
            .map_err(|_| EditFailure::ResourceLimit("source-edits"))?;
        let mut mappings = Vec::new();
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
                    let new = match plan {
                        MappingPlan::Node(index) => candidate_map
                            .nodes
                            .get(&index)
                            .map(|index| crate::node_ref(&new_document.authority, *index)),
                        MappingPlan::Anchor(index) => {
                            candidate_map.nodes.get(&index).and_then(|index| {
                                new_document
                                    .native
                                    .nodes
                                    .get(*index)
                                    .filter(|node| node.anchor.is_some())
                                    .map(|_| {
                                        new_document.authority.node_ref(
                                            u64::try_from(*index).expect("parse indexes fit u64"),
                                            NodeRole::YamlAnchorDefinition,
                                        )
                                    })
                            })
                        }
                        MappingPlan::Alias(index) => candidate_map
                            .aliases
                            .get(&index)
                            .and_then(|index| new_document.alias(*index))
                            .map(crate::YamlAlias::node_ref),
                        MappingPlan::Removed => None,
                    };
                    mappings.push(NodeMapping {
                        old,
                        new,
                        status: if matches!(plan, MappingPlan::Removed) {
                            NodeMappingStatus::Deleted
                        } else {
                            NodeMappingStatus::Replaced
                        },
                        reason: match (plan, new) {
                            (MappingPlan::Removed, _) => {
                                Some("association-removed-by-declared-operation".to_owned())
                            }
                            (_, None) => Some("reparsed-node-not-uniquely-located".to_owned()),
                            (_, Some(_)) => None,
                        },
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
        let source_patch = SourcePatch::derive(
            &self.source,
            new_document.source(),
            &change_set,
            operation_metadata(transaction),
            source_patch_limits(self.parse_limits, change_set.source_edits().len()),
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

    fn prepare_operation(
        &self,
        operation: &EditOperation,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        match operation {
            EditOperation::ReplaceScalar(operation) => self.prepare_scalar(operation, diagnostics),
            EditOperation::RenameAnchor { target, name } => {
                self.prepare_anchor_rename(*target, name)
            }
            EditOperation::InsertMappingEntry {
                mapping,
                key,
                value,
                placement,
            } => self.prepare_mapping_insertion(*mapping, key, value, *placement),
            EditOperation::RemoveMappingEntry { target } => self.prepare_mapping_removal(*target),
            EditOperation::InsertSequenceElement {
                sequence,
                value,
                placement,
            } => self.prepare_sequence_insertion(*sequence, value, *placement),
            EditOperation::RemoveSequenceElement { target } => {
                self.prepare_sequence_removal(*target)
            }
            EditOperation::InsertAlias {
                sequence,
                anchor,
                placement,
            } => self.prepare_alias_insertion(*sequence, *anchor, *placement),
        }
    }

    fn prepare_scalar(
        &self,
        operation: &ScalarReplacement,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let target = operation.target();
        let index = self.resolve_node(target, NodeRole::YamlNode)?;
        let node = &self.native.nodes[index];
        let NativeContent::Scalar(scalar) = &node.content else {
            return Err(EditFailure::WrongRole);
        };
        let literal_span = self
            .scalar_literal_span(index)
            .ok_or(EditFailure::IncompleteTarget)?;
        match operation {
            ScalarReplacement::Literal { literal, .. } => {
                self.validate_literal(literal)?;
                Ok(vec![PreparedEdit {
                    old_span: literal_span,
                    replacement: literal.to_vec(),
                    mapping: Some((target, MappingPlan::Node(index))),
                }])
            }
            ScalarReplacement::Semantic { value, policy, .. } => {
                if !is_scalar_value(value.kind()) {
                    return Err(EditFailure::UnsupportedSemanticValue(value.kind()));
                }
                if *policy == RepresentationPolicy::ExactLiteral {
                    return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
                }
                let canonical = self.canonical_scalar_fragment(value)?;
                let preserve = || {
                    preserved_literal(
                        scalar.kind,
                        scalar.style,
                        node.tag.as_ref(),
                        self.tag_span(index).is_some(),
                        &canonical,
                        value.kind(),
                        self.profile,
                    )
                };
                match policy {
                    RepresentationPolicy::PreserveCompatible => {
                        let replacement = preserve()
                            .ok_or(EditFailure::RepresentationIncompatible)
                            .and_then(|text| self.encode_fragment(&text))?;
                        Ok(vec![PreparedEdit {
                            old_span: literal_span,
                            replacement,
                            mapping: Some((target, MappingPlan::Node(index))),
                        }])
                    }
                    RepresentationPolicy::CanonicalForProfile => {
                        self.canonical_scalar_edits(index, target, literal_span, &canonical)
                    }
                    RepresentationPolicy::PreserveElseCanonical => {
                        if let Some(text) = preserve() {
                            Ok(vec![PreparedEdit {
                                old_span: literal_span,
                                replacement: self.encode_fragment(&text)?,
                                mapping: Some((target, MappingPlan::Node(index))),
                            }])
                        } else {
                            push_fallback_diagnostic(diagnostics, literal_span)?;
                            self.canonical_scalar_edits(index, target, literal_span, &canonical)
                        }
                    }
                    RepresentationPolicy::ExactLiteral => unreachable!("handled above"),
                }
            }
        }
    }

    fn canonical_scalar_edits(
        &self,
        index: usize,
        target: NodeRef,
        literal_span: Span,
        canonical: &CanonicalScalar,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let mut edits = Vec::new();
        let encoded_literal = self.encode_fragment(&canonical.literal)?;
        if let Some(tag_span) = self.tag_span(index) {
            edits.push(PreparedEdit {
                old_span: tag_span,
                replacement: self.encode_fragment(&canonical.tag)?,
                mapping: None,
            });
            edits.push(PreparedEdit {
                old_span: literal_span,
                replacement: encoded_literal,
                mapping: Some((target, MappingPlan::Node(index))),
            });
        } else {
            edits.push(PreparedEdit {
                old_span: literal_span,
                replacement: self
                    .encode_fragment(&format!("{} {}", canonical.tag, canonical.literal))?,
                mapping: Some((target, MappingPlan::Node(index))),
            });
        }
        Ok(edits)
    }

    fn prepare_anchor_rename(
        &self,
        target: NodeRef,
        name: &str,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_node(target, NodeRole::YamlAnchorDefinition)?;
        self.validate_anchor_name(name)?;
        let node = &self.native.nodes[index];
        let old_name = node.anchor.as_deref().ok_or(EditFailure::WrongRole)?;
        let definition = node.anchor_span.ok_or(EditFailure::IncompleteTarget)?;
        let mut edits = Vec::new();
        edits
            .try_reserve(self.native.aliases.len().saturating_add(1))
            .map_err(|_| EditFailure::ResourceLimit("prepared-edits"))?;
        edits.push(PreparedEdit {
            old_span: definition,
            replacement: self.encode_fragment(&format!("&{name}"))?,
            mapping: Some((target, MappingPlan::Anchor(index))),
        });
        for (ordinal, alias) in self.native.aliases.iter().enumerate() {
            if alias.target == index && alias.name.as_ref() == old_name {
                edits.push(PreparedEdit {
                    old_span: alias.span,
                    replacement: self.encode_fragment(&format!("*{name}"))?,
                    mapping: Some((
                        self.authority.node_ref(alias.identity, NodeRole::YamlAlias),
                        MappingPlan::Alias(ordinal),
                    )),
                });
            }
        }
        Ok(edits)
    }

    fn prepare_mapping_insertion(
        &self,
        mapping: NodeRef,
        key: &PortableValue,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_node(mapping, NodeRole::YamlNode)?;
        let NativeContent::Mapping(entries) = &self.native.nodes[index].content else {
            return Err(EditFailure::WrongRole);
        };
        let ordinal = self.mapping_placement(index, entries, placement)?;
        let key = self.canonical_value_fragment(key)?;
        let value = self.canonical_value_fragment(value)?;
        let fragment = format!("? {key} : {value}");
        let block_lines = [format!("? {key}"), format!(": {value}")];
        let (old_span, replacement) = self.prepare_collection_insertion(
            index,
            entries
                .iter()
                .map(|entry| self.association_span(entry.span))
                .collect::<Result<Vec<_>, _>>()?,
            ordinal,
            &fragment,
            &block_lines,
            YamlSyntaxKind::FlowMappingStart,
            YamlSyntaxKind::FlowMappingEnd,
        )?;
        Ok(vec![PreparedEdit {
            old_span,
            replacement,
            mapping: Some((mapping, MappingPlan::Node(index))),
        }])
    }

    fn prepare_sequence_insertion(
        &self,
        sequence: NodeRef,
        value: &PortableValue,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let index = self.resolve_node(sequence, NodeRole::YamlNode)?;
        let NativeContent::Sequence(items) = &self.native.nodes[index].content else {
            return Err(EditFailure::WrongRole);
        };
        let ordinal = self.sequence_placement(index, items, placement)?;
        let fragment = self.canonical_value_fragment(value)?;
        let block_lines = [format!("- {fragment}")];
        let (old_span, replacement) = self.prepare_collection_insertion(
            index,
            items
                .iter()
                .map(|item| self.association_span(item.span))
                .collect::<Result<Vec<_>, _>>()?,
            ordinal,
            &fragment,
            &block_lines,
            YamlSyntaxKind::FlowSequenceStart,
            YamlSyntaxKind::FlowSequenceEnd,
        )?;
        Ok(vec![PreparedEdit {
            old_span,
            replacement,
            mapping: Some((sequence, MappingPlan::Node(index))),
        }])
    }

    fn prepare_alias_insertion(
        &self,
        sequence: NodeRef,
        anchor: NodeRef,
        placement: AssociationPlacement,
    ) -> Result<Vec<PreparedEdit>, EditFailure> {
        let sequence_index = self.resolve_node(sequence, NodeRole::YamlNode)?;
        let anchor_index = self.resolve_node(anchor, NodeRole::YamlAnchorDefinition)?;
        let NativeContent::Sequence(items) = &self.native.nodes[sequence_index].content else {
            return Err(EditFailure::WrongRole);
        };
        let ordinal = self.sequence_placement(sequence_index, items, placement)?;
        let spans = items
            .iter()
            .map(|item| self.association_span(item.span))
            .collect::<Result<Vec<_>, _>>()?;
        let insertion = self.collection_insertion_point(
            sequence_index,
            &spans,
            ordinal,
            YamlSyntaxKind::FlowSequenceStart,
            YamlSyntaxKind::FlowSequenceEnd,
        )?;
        self.validate_visible_anchor(sequence_index, anchor_index, insertion)?;
        let name = self.native.nodes[anchor_index]
            .anchor
            .as_deref()
            .ok_or(EditFailure::WrongRole)?;
        let (old_span, replacement) = self.prepare_collection_insertion_at(
            sequence_index,
            &spans,
            ordinal,
            &format!("*{name}"),
            &[format!("- *{name}")],
            YamlSyntaxKind::FlowSequenceStart,
            YamlSyntaxKind::FlowSequenceEnd,
            insertion,
        )?;
        Ok(vec![PreparedEdit {
            old_span,
            replacement,
            mapping: Some((sequence, MappingPlan::Node(sequence_index))),
        }])
    }

    fn prepare_mapping_removal(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let (container, ordinal) = self.resolve_mapping_entry(target)?;
        let NativeContent::Mapping(entries) = &self.native.nodes[container].content else {
            unreachable!("resolver only returns mapping containers");
        };
        let spans = entries
            .iter()
            .map(|entry| self.association_span(entry.span))
            .collect::<Result<Vec<_>, _>>()?;
        let owned = self.collection_removal_span(
            container,
            &spans,
            ordinal,
            YamlSyntaxKind::FlowMappingStart,
            YamlSyntaxKind::FlowMappingEnd,
        )?;
        self.validate_removal_dependencies(
            owned,
            [
                (entries[ordinal].key, entries[ordinal].key_alias),
                (entries[ordinal].value, entries[ordinal].value_alias),
            ],
        )?;
        let replacement = if entries.len() == 1
            && !self.collection_is_flow(container, YamlSyntaxKind::FlowMappingStart)
        {
            self.empty_block_replacement(owned, spans[ordinal], "{}")?
        } else {
            Vec::new()
        };
        Ok(vec![PreparedEdit {
            old_span: owned,
            replacement,
            mapping: Some((target, MappingPlan::Removed)),
        }])
    }

    fn prepare_sequence_removal(&self, target: NodeRef) -> Result<Vec<PreparedEdit>, EditFailure> {
        let (container, ordinal) = self.resolve_sequence_item(target)?;
        let NativeContent::Sequence(items) = &self.native.nodes[container].content else {
            unreachable!("resolver only returns sequence containers");
        };
        let spans = items
            .iter()
            .map(|item| self.association_span(item.span))
            .collect::<Result<Vec<_>, _>>()?;
        let owned = self.collection_removal_span(
            container,
            &spans,
            ordinal,
            YamlSyntaxKind::FlowSequenceStart,
            YamlSyntaxKind::FlowSequenceEnd,
        )?;
        self.validate_removal_dependencies(owned, [(items[ordinal].node, items[ordinal].alias)])?;
        let replacement = if items.len() == 1
            && !self.collection_is_flow(container, YamlSyntaxKind::FlowSequenceStart)
        {
            self.empty_block_replacement(owned, spans[ordinal], "[]")?
        } else {
            Vec::new()
        };
        Ok(vec![PreparedEdit {
            old_span: owned,
            replacement,
            mapping: Some((target, MappingPlan::Removed)),
        }])
    }

    fn mapping_placement(
        &self,
        expected: usize,
        entries: &[crate::native::NativeMappingEntry],
        placement: AssociationPlacement,
    ) -> Result<usize, EditFailure> {
        match placement {
            AssociationPlacement::Start => Ok(0),
            AssociationPlacement::End => Ok(entries.len()),
            AssociationPlacement::Before(target) | AssociationPlacement::After(target) => {
                let (container, ordinal) = self.resolve_mapping_entry(target)?;
                if container != expected {
                    return Err(EditFailure::InvalidPlacement);
                }
                Ok(if matches!(placement, AssociationPlacement::After(_)) {
                    ordinal + 1
                } else {
                    ordinal
                })
            }
        }
    }

    fn sequence_placement(
        &self,
        expected: usize,
        items: &[crate::native::NativeSequenceItem],
        placement: AssociationPlacement,
    ) -> Result<usize, EditFailure> {
        match placement {
            AssociationPlacement::Start => Ok(0),
            AssociationPlacement::End => Ok(items.len()),
            AssociationPlacement::Before(target) | AssociationPlacement::After(target) => {
                let (container, ordinal) = self.resolve_sequence_item(target)?;
                if container != expected {
                    return Err(EditFailure::InvalidPlacement);
                }
                Ok(if matches!(placement, AssociationPlacement::After(_)) {
                    ordinal + 1
                } else {
                    ordinal
                })
            }
        }
    }

    fn resolve_mapping_entry(&self, target: NodeRef) -> Result<(usize, usize), EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::YamlMappingEntry {
            return Err(EditFailure::WrongRole);
        }
        let identity = self
            .authority
            .resolve_index(target)
            .map_err(|_| EditFailure::WrongSnapshot)?;
        self.native
            .nodes
            .iter()
            .enumerate()
            .find_map(|(container, node)| match &node.content {
                NativeContent::Mapping(entries) => entries
                    .iter()
                    .position(|entry| entry.identity == identity)
                    .map(|ordinal| (container, ordinal)),
                NativeContent::Scalar(_) | NativeContent::Sequence(_) => None,
            })
            .ok_or(EditFailure::TargetNotFound)
    }

    fn resolve_sequence_item(&self, target: NodeRef) -> Result<(usize, usize), EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != NodeRole::YamlSequenceElement {
            return Err(EditFailure::WrongRole);
        }
        let identity = self
            .authority
            .resolve_index(target)
            .map_err(|_| EditFailure::WrongSnapshot)?;
        self.native
            .nodes
            .iter()
            .enumerate()
            .find_map(|(container, node)| match &node.content {
                NativeContent::Sequence(items) => items
                    .iter()
                    .position(|item| item.identity == identity)
                    .map(|ordinal| (container, ordinal)),
                NativeContent::Scalar(_) | NativeContent::Mapping(_) => None,
            })
            .ok_or(EditFailure::TargetNotFound)
    }

    fn association_span(&self, span: Span) -> Result<Span, EditFailure> {
        let pieces = self.structural_index.pieces();
        let mut start = span.start_byte();
        while let Some(index) = pieces
            .iter()
            .rposition(|piece| piece.span().end_byte() == start)
        {
            let kind = self.syntax_kinds[index];
            if matches!(
                kind,
                YamlSyntaxKind::Tag | YamlSyntaxKind::Anchor | YamlSyntaxKind::ExplicitKey
            ) {
                start = pieces[index].span().start_byte();
                continue;
            }
            if kind != YamlSyntaxKind::Whitespace || index == 0 {
                break;
            }
            let property = index - 1;
            if pieces[property].span().end_byte() == pieces[index].span().start_byte()
                && matches!(
                    self.syntax_kinds[property],
                    YamlSyntaxKind::Tag | YamlSyntaxKind::Anchor | YamlSyntaxKind::ExplicitKey
                )
            {
                start = pieces[property].span().start_byte();
                continue;
            }
            break;
        }
        self.authority
            .span(start, span.end_byte())
            .map_err(|_| EditFailure::IncompleteTarget)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_collection_insertion(
        &self,
        container: usize,
        spans: Vec<Span>,
        ordinal: usize,
        flow_fragment: &str,
        block_lines: &[String],
        flow_start: YamlSyntaxKind,
        flow_end: YamlSyntaxKind,
    ) -> Result<(Span, Vec<u8>), EditFailure> {
        let insertion =
            self.collection_insertion_point(container, &spans, ordinal, flow_start, flow_end)?;
        self.prepare_collection_insertion_at(
            container,
            &spans,
            ordinal,
            flow_fragment,
            block_lines,
            flow_start,
            flow_end,
            insertion,
        )
    }

    fn collection_insertion_point(
        &self,
        container: usize,
        spans: &[Span],
        ordinal: usize,
        flow_start: YamlSyntaxKind,
        flow_end: YamlSyntaxKind,
    ) -> Result<usize, EditFailure> {
        if ordinal > spans.len() {
            return Err(EditFailure::InvalidPlacement);
        }
        if self.collection_is_flow(container, flow_start) {
            if let Some(span) = spans.get(ordinal) {
                Ok(span.start_byte())
            } else if let Some(span) = spans.last() {
                Ok(span.end_byte())
            } else {
                self.syntax_within(self.native.nodes[container].span, flow_end, true)
                    .map(Span::start_byte)
                    .ok_or(EditFailure::IncompleteTarget)
            }
        } else if let Some(span) = spans.get(ordinal) {
            Ok(self.block_owned_span(*span)?.start_byte())
        } else if let Some(span) = spans.last() {
            Ok(self.block_owned_span(*span)?.end_byte())
        } else {
            Err(EditFailure::IncompleteTarget)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_collection_insertion_at(
        &self,
        container: usize,
        spans: &[Span],
        ordinal: usize,
        flow_fragment: &str,
        block_lines: &[String],
        flow_start: YamlSyntaxKind,
        _flow_end: YamlSyntaxKind,
        insertion: usize,
    ) -> Result<(Span, Vec<u8>), EditFailure> {
        let span = self
            .authority
            .span(insertion, insertion)
            .map_err(|_| EditFailure::IncompleteTarget)?;
        if self.collection_is_flow(container, flow_start) {
            let text = if spans.is_empty() {
                flow_fragment.to_owned()
            } else if ordinal < spans.len() {
                format!("{flow_fragment}, ")
            } else {
                format!(", {flow_fragment}")
            };
            return Ok((span, self.encode_fragment(&text)?));
        }
        let reference = spans
            .get(ordinal)
            .or_else(|| spans.last())
            .copied()
            .ok_or(EditFailure::IncompleteTarget)?;
        let owned = self.block_owned_span(reference)?;
        let indent = self.line_indent(owned.start_byte())?;
        let newline = self.nearest_newline(insertion);
        let suffix_newline = ordinal < spans.len()
            || self
                .raw_decoded(owned.start_byte(), owned.end_byte())?
                .ends_with(['\r', '\n']);
        let mut text = String::new();
        if ordinal == spans.len() && !suffix_newline {
            text.push_str(&newline);
        }
        for (index, line) in block_lines.iter().enumerate() {
            text.push_str(&indent);
            text.push_str(line);
            if index + 1 < block_lines.len() || suffix_newline {
                text.push_str(&newline);
            }
        }
        Ok((span, self.encode_fragment(&text)?))
    }

    fn collection_removal_span(
        &self,
        container: usize,
        spans: &[Span],
        ordinal: usize,
        flow_start: YamlSyntaxKind,
        _flow_end: YamlSyntaxKind,
    ) -> Result<Span, EditFailure> {
        let target = *spans.get(ordinal).ok_or(EditFailure::TargetNotFound)?;
        if !self.collection_is_flow(container, flow_start) {
            return self.block_owned_span(target);
        }
        if spans.len() == 1 {
            return Ok(target);
        }
        if ordinal + 1 < spans.len() {
            let _comma = self
                .syntax_between(
                    YamlSyntaxKind::FlowEntry,
                    target.end_byte(),
                    spans[ordinal + 1].start_byte(),
                    false,
                )
                .ok_or(EditFailure::IncompleteTarget)?;
            self.authority
                .span(target.start_byte(), spans[ordinal + 1].start_byte())
                .map_err(|_| EditFailure::IncompleteTarget)
        } else {
            let comma = self
                .syntax_between(
                    YamlSyntaxKind::FlowEntry,
                    spans[ordinal - 1].end_byte(),
                    target.start_byte(),
                    true,
                )
                .ok_or(EditFailure::IncompleteTarget)?;
            self.authority
                .span(comma.start_byte(), target.end_byte())
                .map_err(|_| EditFailure::IncompleteTarget)
        }
    }

    fn collection_is_flow(&self, container: usize, flow_start: YamlSyntaxKind) -> bool {
        let node = &self.native.nodes[container];
        self.structural_index
            .pieces()
            .iter()
            .zip(self.syntax_kinds.iter())
            .filter(|(piece, _)| {
                piece.span().start_byte() >= node.span.start_byte()
                    && piece.span().end_byte() <= node.span.end_byte()
            })
            .find_map(|(_, kind)| {
                (!matches!(
                    kind,
                    YamlSyntaxKind::Whitespace
                        | YamlSyntaxKind::Newline
                        | YamlSyntaxKind::Comment
                        | YamlSyntaxKind::Tag
                        | YamlSyntaxKind::Anchor
                ))
                .then_some(*kind)
            })
            == Some(flow_start)
    }

    fn block_owned_span(&self, occurrence: Span) -> Result<Span, EditFailure> {
        let start = self.line_start(occurrence.start_byte())?;
        let end = if self.line_start(occurrence.end_byte())? == occurrence.end_byte()
            && occurrence.end_byte() > start
        {
            occurrence.end_byte()
        } else {
            self.line_end(occurrence.end_byte())?
        };
        self.authority
            .span(start, end)
            .map_err(|_| EditFailure::IncompleteTarget)
    }

    fn line_start(&self, raw: usize) -> Result<usize, EditFailure> {
        let position = self
            .source
            .decoded_position(raw)
            .map_err(|_| EditFailure::IncompleteTarget)?;
        let text = self
            .source
            .decoded_text()
            .ok_or(EditFailure::IncompleteTarget)?;
        let prefix = &text[..position.decoded_utf8_byte];
        let start = prefix
            .rfind(['\r', '\n'])
            .map_or(0, |offset| offset.saturating_add(1));
        self.source
            .raw_byte_at(DecodedOffset::Utf8Byte(start))
            .map_err(|_| EditFailure::IncompleteTarget)
    }

    fn line_end(&self, raw: usize) -> Result<usize, EditFailure> {
        let position = self
            .source
            .decoded_position(raw)
            .map_err(|_| EditFailure::IncompleteTarget)?;
        let text = self
            .source
            .decoded_text()
            .ok_or(EditFailure::IncompleteTarget)?;
        let suffix = &text[position.decoded_utf8_byte..];
        let mut end = suffix
            .find(['\r', '\n'])
            .map_or(text.len(), |offset| position.decoded_utf8_byte + offset);
        if end < text.len() {
            if text.as_bytes()[end] == b'\r' && text.as_bytes().get(end + 1) == Some(&b'\n') {
                end += 2;
            } else {
                end += 1;
            }
        }
        self.source
            .raw_byte_at(DecodedOffset::Utf8Byte(end))
            .map_err(|_| EditFailure::IncompleteTarget)
    }

    fn line_indent(&self, raw_line_start: usize) -> Result<String, EditFailure> {
        let end = self.line_end(raw_line_start)?;
        Ok(self
            .raw_decoded(raw_line_start, end)?
            .chars()
            .take_while(|character| *character == ' ')
            .collect())
    }

    fn raw_decoded(&self, start: usize, end: usize) -> Result<&str, EditFailure> {
        let start = self
            .source
            .decoded_position(start)
            .map_err(|_| EditFailure::IncompleteTarget)?
            .decoded_utf8_byte;
        let end = self
            .source
            .decoded_position(end)
            .map_err(|_| EditFailure::IncompleteTarget)?
            .decoded_utf8_byte;
        self.source
            .decoded_text()
            .and_then(|text| text.get(start..end))
            .ok_or(EditFailure::IncompleteTarget)
    }

    fn nearest_newline(&self, raw: usize) -> String {
        self.structural_index
            .pieces()
            .iter()
            .zip(self.syntax_kinds.iter())
            .filter(|(_, kind)| **kind == YamlSyntaxKind::Newline)
            .min_by_key(|(piece, _)| piece.span().start_byte().abs_diff(raw))
            .and_then(|(piece, _)| {
                self.raw_decoded(piece.span().start_byte(), piece.span().end_byte())
                    .ok()
            })
            .unwrap_or("\n")
            .to_owned()
    }

    fn empty_block_replacement(
        &self,
        owned: Span,
        occurrence: Span,
        empty: &str,
    ) -> Result<Vec<u8>, EditFailure> {
        let indent = self.line_indent(owned.start_byte())?;
        let whole = self.raw_decoded(owned.start_byte(), owned.end_byte())?;
        let tail = if occurrence.end_byte() < owned.end_byte() {
            self.raw_decoded(occurrence.end_byte(), owned.end_byte())?
        } else if whole.ends_with("\r\n") {
            "\r\n"
        } else if whole.ends_with('\n') {
            "\n"
        } else if whole.ends_with('\r') {
            "\r"
        } else {
            ""
        };
        self.encode_fragment(&format!("{indent}{empty}{tail}"))
    }

    fn validate_visible_anchor(
        &self,
        sequence: usize,
        anchor: usize,
        insertion: usize,
    ) -> Result<(), EditFailure> {
        let anchor_span = self.native.nodes[anchor]
            .anchor_span
            .ok_or(EditFailure::WrongRole)?;
        let sequence_span = self.native.nodes[sequence].span;
        let document = self
            .native
            .documents
            .iter()
            .find(|document| {
                document.span.start_byte() <= sequence_span.start_byte()
                    && sequence_span.end_byte() <= document.span.end_byte()
            })
            .ok_or(EditFailure::AnchorNotVisible)?;
        if anchor_span.end_byte() > insertion
            || anchor_span.start_byte() < document.span.start_byte()
            || anchor_span.end_byte() > document.span.end_byte()
        {
            return Err(EditFailure::AnchorNotVisible);
        }
        let name = self.native.nodes[anchor]
            .anchor
            .as_deref()
            .ok_or(EditFailure::WrongRole)?;
        let visible = self
            .native
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| {
                node.anchor_span
                    .filter(|span| {
                        node.anchor.as_deref() == Some(name)
                            && span.start_byte() >= document.span.start_byte()
                            && span.end_byte() <= insertion
                    })
                    .map(|span| (span.end_byte(), index))
            })
            .max_by_key(|(end, _)| *end)
            .map(|(_, index)| index);
        if visible == Some(anchor) {
            Ok(())
        } else {
            Err(EditFailure::AnchorNotVisible)
        }
    }

    fn validate_removal_dependencies(
        &self,
        owned: Span,
        roots: impl IntoIterator<Item = (usize, Option<usize>)>,
    ) -> Result<(), EditFailure> {
        let mut removed = HashSet::new();
        for (node, alias) in roots {
            if alias.is_none() {
                self.collect_owned_nodes(node, &mut removed);
            }
        }
        if self.native.aliases.iter().any(|alias| {
            removed.contains(&alias.target)
                && !(alias.span.start_byte() >= owned.start_byte()
                    && alias.span.end_byte() <= owned.end_byte())
        }) {
            Err(EditFailure::AnchorDependency)
        } else {
            Ok(())
        }
    }

    fn collect_owned_nodes(&self, node: usize, output: &mut HashSet<usize>) {
        if !output.insert(node) {
            return;
        }
        match &self.native.nodes[node].content {
            NativeContent::Scalar(_) => {}
            NativeContent::Sequence(items) => {
                for item in items.iter().filter(|item| item.alias.is_none()) {
                    self.collect_owned_nodes(item.node, output);
                }
            }
            NativeContent::Mapping(entries) => {
                for entry in entries.iter() {
                    if entry.key_alias.is_none() {
                        self.collect_owned_nodes(entry.key, output);
                    }
                    if entry.value_alias.is_none() {
                        self.collect_owned_nodes(entry.value, output);
                    }
                }
            }
        }
    }

    fn resolve_node(&self, target: NodeRef, role: NodeRole) -> Result<usize, EditFailure> {
        if target.snapshot() != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        if target.role() != role {
            return Err(EditFailure::WrongRole);
        }
        let index = usize::try_from(
            self.authority
                .resolve_index(target)
                .map_err(|_| EditFailure::WrongSnapshot)?,
        )
        .map_err(|_| EditFailure::TargetNotFound)?;
        if index >= self.native.nodes.len() {
            return Err(EditFailure::TargetNotFound);
        }
        match role {
            NodeRole::YamlNode => {}
            NodeRole::YamlAnchorDefinition if self.native.nodes[index].anchor.is_some() => {}
            _ => return Err(EditFailure::WrongRole),
        }
        Ok(index)
    }

    fn scalar_literal_span(&self, index: usize) -> Option<Span> {
        let node = self.native.nodes.get(index)?;
        let NativeContent::Scalar(scalar) = &node.content else {
            return None;
        };
        let expected = match scalar.style {
            YamlScalarStyle::Plain => YamlSyntaxKind::PlainScalar,
            YamlScalarStyle::SingleQuoted => YamlSyntaxKind::SingleQuotedScalar,
            YamlScalarStyle::DoubleQuoted => YamlSyntaxKind::DoubleQuotedScalar,
            YamlScalarStyle::Literal => YamlSyntaxKind::LiteralBlockHeader,
            YamlScalarStyle::Folded => YamlSyntaxKind::FoldedBlockHeader,
        };
        let header = self.syntax_within(node.span, expected, false)?;
        if matches!(
            scalar.style,
            YamlScalarStyle::Literal | YamlScalarStyle::Folded
        ) {
            let end = self
                .syntax_between(
                    YamlSyntaxKind::BlockScalarContent,
                    header.end_byte(),
                    node.span.end_byte(),
                    true,
                )
                .map_or(header.end_byte(), Span::end_byte);
            self.authority.span(header.start_byte(), end).ok()
        } else {
            Some(header)
        }
    }

    fn tag_span(&self, index: usize) -> Option<Span> {
        self.syntax_within(
            self.native.nodes.get(index)?.span,
            YamlSyntaxKind::Tag,
            false,
        )
    }

    fn syntax_within(&self, span: Span, kind: YamlSyntaxKind, last: bool) -> Option<Span> {
        self.syntax_between(kind, span.start_byte(), span.end_byte(), last)
    }

    fn syntax_between(
        &self,
        kind: YamlSyntaxKind,
        start: usize,
        end: usize,
        last: bool,
    ) -> Option<Span> {
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

    fn validate_literal(&self, literal: &[u8]) -> Result<(), EditFailure> {
        if literal.is_empty() {
            return Err(EditFailure::InvalidLiteral);
        }
        let source = standalone_source(literal, self.source.encoding_facts().selected())?;
        let candidate = crate::parse(source, self.profile, self.parse_limits)
            .map_err(|_| EditFailure::InvalidLiteral)?;
        let root = candidate
            .document(0)
            .filter(|_| candidate.document_count() == 1)
            .map(crate::YamlDocument::root)
            .filter(|root| root.kind() == YamlNodeKind::Scalar)
            .ok_or(EditFailure::InvalidLiteral)?;
        if root.anchor().is_some()
            || candidate.lossless_syntax_kinds().iter().any(|kind| {
                matches!(
                    kind,
                    YamlSyntaxKind::Tag
                        | YamlSyntaxKind::Anchor
                        | YamlSyntaxKind::Alias
                        | YamlSyntaxKind::Directive
                        | YamlSyntaxKind::DocumentStart
                        | YamlSyntaxKind::DocumentEnd
                        | YamlSyntaxKind::Comment
                        | YamlSyntaxKind::ErrorRegion
                )
            })
        {
            return Err(EditFailure::InvalidLiteral);
        }
        Ok(())
    }

    fn canonical_scalar_fragment(
        &self,
        value: &PortableValue,
    ) -> Result<CanonicalScalar, EditFailure> {
        let request = MaterializationRequest::new(
            self.profile.id(),
            MaterializationStyleId::new("yaml.canonical-flow", 1),
        )
        .with_limits(edit_materialization_limits(self.parse_limits));
        let complete = match crate::materialize_value(value, &request) {
            MaterializationResult::Complete(complete) => complete,
            MaterializationResult::Failed(failed) => {
                return Err(match failed.failure {
                    consema_document::MaterializationFailure::Unrepresentable { kind, .. } => {
                        EditFailure::UnsupportedSemanticValue(kind)
                    }
                    consema_document::MaterializationFailure::ResourceLimit(name) => {
                        EditFailure::ResourceLimit(name)
                    }
                    _ => EditFailure::NewDocumentFormationFailed,
                });
            }
        };
        let text = complete
            .document
            .source()
            .decoded_text()
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let fragment = text
            .strip_prefix("--- ")
            .and_then(|text| text.strip_suffix('\n'))
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let (tag, literal) = fragment
            .split_once(' ')
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let scalar = complete
            .document
            .document(0)
            .and_then(|document| document.root().scalar())
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        Ok(CanonicalScalar {
            tag: tag.to_owned(),
            literal: literal.to_owned(),
            canonical: scalar.canonical().to_owned(),
        })
    }

    fn canonical_value_fragment(&self, value: &PortableValue) -> Result<String, EditFailure> {
        let request = MaterializationRequest::new(
            self.profile.id(),
            MaterializationStyleId::new("yaml.canonical-flow", 1),
        )
        .with_limits(edit_materialization_limits(self.parse_limits));
        let complete = match crate::materialize_value(value, &request) {
            MaterializationResult::Complete(complete) => complete,
            MaterializationResult::Failed(failed) => {
                return Err(match failed.failure {
                    consema_document::MaterializationFailure::Unrepresentable { kind, .. } => {
                        EditFailure::UnsupportedInsertedValue(kind)
                    }
                    consema_document::MaterializationFailure::ResourceLimit(name) => {
                        EditFailure::ResourceLimit(name)
                    }
                    _ => EditFailure::NewDocumentFormationFailed,
                });
            }
        };
        complete
            .document
            .source()
            .decoded_text()
            .and_then(|text| text.strip_prefix("--- "))
            .and_then(|text| text.strip_suffix('\n'))
            .map(str::to_owned)
            .ok_or(EditFailure::NewDocumentFormationFailed)
    }

    fn validate_anchor_name(&self, name: &str) -> Result<(), EditFailure> {
        if name.is_empty() || name.len() > self.parse_limits.max_source_bytes {
            return Err(EditFailure::InvalidAnchorName);
        }
        let source = format!("--- &{name} !!str \"x\"\n");
        let candidate = crate::parse(
            source.into_bytes(),
            self.profile,
            consema_document::ParseLimits {
                max_source_bytes: self.parse_limits.max_source_bytes,
                max_nesting_depth: 2,
                max_token_count: 32,
                max_node_count: 8,
                max_diagnostics: self.parse_limits.max_diagnostics,
            },
        )
        .map_err(|_| EditFailure::InvalidAnchorName)?;
        if candidate
            .document(0)
            .and_then(|document| document.root().anchor())
            == Some(name)
        {
            Ok(())
        } else {
            Err(EditFailure::InvalidAnchorName)
        }
    }

    fn encode_fragment(&self, text: &str) -> Result<Vec<u8>, EditFailure> {
        encode_fragment(
            text,
            self.source.encoding_facts().selected(),
            self.parse_limits.max_source_bytes,
        )
    }

    fn validate_candidate(
        &self,
        candidate: &Document,
        transaction: &EditTransaction,
    ) -> Result<CandidateMap, EditFailure> {
        if transaction.operations.iter().any(is_structural_operation) {
            return self.validate_structural_candidate(candidate, transaction);
        }
        let mut scalar_targets = HashSet::new();
        let mut renames = HashMap::new();
        for operation in transaction.operations.iter() {
            match operation {
                EditOperation::ReplaceScalar(replacement) => {
                    scalar_targets
                        .insert(self.resolve_node(replacement.target(), NodeRole::YamlNode)?);
                }
                EditOperation::RenameAnchor { target, name } => {
                    renames.insert(
                        self.resolve_node(*target, NodeRole::YamlAnchorDefinition)?,
                        name.as_str(),
                    );
                }
                EditOperation::InsertMappingEntry { .. }
                | EditOperation::RemoveMappingEntry { .. }
                | EditOperation::InsertSequenceElement { .. }
                | EditOperation::RemoveSequenceElement { .. }
                | EditOperation::InsertAlias { .. } => {
                    unreachable!("structural transactions use structural validation")
                }
            }
        }
        if self.native.documents.len() != candidate.native.documents.len()
            || self.native.nodes.len() != candidate.native.nodes.len()
            || self.native.aliases.len() != candidate.native.aliases.len()
        {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        for (old, new) in self
            .native
            .documents
            .iter()
            .zip(candidate.native.documents.iter())
        {
            if old.root != new.root {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
        }
        for (index, (old, new)) in self
            .native
            .nodes
            .iter()
            .zip(candidate.native.nodes.iter())
            .enumerate()
        {
            let expected_anchor = renames.get(&index).copied().or(old.anchor.as_deref());
            if new.anchor.as_deref() != expected_anchor
                || !same_topology(&old.content, &new.content)
                || (!scalar_targets.contains(&index)
                    && (old.tag != new.tag || !same_scalar_semantics(&old.content, &new.content)))
            {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
        }
        for (old, new) in self
            .native
            .aliases
            .iter()
            .zip(candidate.native.aliases.iter())
        {
            let expected_name = renames.get(&old.target).copied().unwrap_or(&old.name);
            if old.target != new.target || new.name.as_ref() != expected_name {
                return Err(EditFailure::NewDocumentFormationFailed);
            }
        }
        Ok(CandidateMap {
            nodes: (0..self.native.nodes.len())
                .map(|index| (index, index))
                .collect(),
            aliases: (0..self.native.aliases.len())
                .map(|index| (index, index))
                .collect(),
        })
    }

    fn validate_structural_candidate(
        &self,
        candidate: &Document,
        transaction: &EditTransaction,
    ) -> Result<CandidateMap, EditFailure> {
        if self.native.documents.len() != candidate.native.documents.len() {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        let mut expected = ValidationModel::from_document(self, true);
        for operation in transaction.operations.iter() {
            match operation {
                EditOperation::ReplaceScalar(ScalarReplacement::Semantic {
                    target, value, ..
                }) => {
                    let target = self.resolve_node(*target, NodeRole::YamlNode)?;
                    if !matches!(
                        expected.nodes[target].content,
                        ValidationContent::Scalar { .. }
                    ) {
                        return Err(EditFailure::WrongRole);
                    }
                    let imported = expected.append_root(self.validation_model_for_value(value)?)?;
                    let replacement = expected.nodes[imported].clone();
                    expected.nodes[target].tag = replacement.tag;
                    expected.nodes[target].content = replacement.content;
                    expected.nodes[target].scalar_wildcard = false;
                }
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { target, .. }) => {
                    let target = self.resolve_node(*target, NodeRole::YamlNode)?;
                    if !matches!(
                        expected.nodes[target].content,
                        ValidationContent::Scalar { .. }
                    ) {
                        return Err(EditFailure::WrongRole);
                    }
                    expected.nodes[target].scalar_wildcard = true;
                }
                EditOperation::RenameAnchor { target, name } => {
                    let target = self.resolve_node(*target, NodeRole::YamlAnchorDefinition)?;
                    let old_name = expected.nodes[target]
                        .anchor
                        .replace(name.clone())
                        .ok_or(EditFailure::WrongRole)?;
                    for node in &mut expected.nodes {
                        match &mut node.content {
                            ValidationContent::Scalar { .. } => {}
                            ValidationContent::Sequence(items) => {
                                for edge in items.iter_mut().filter(|edge| edge.target == target) {
                                    match &mut edge.alias {
                                        Some(alias) if alias.name == old_name => {
                                            alias.name.clone_from(name);
                                        }
                                        Some(_) | None => {}
                                    }
                                }
                            }
                            ValidationContent::Mapping(entries) => {
                                for edge in entries
                                    .iter_mut()
                                    .flat_map(|entry| [&mut entry.key, &mut entry.value])
                                    .filter(|edge| edge.target == target)
                                {
                                    match &mut edge.alias {
                                        Some(alias) if alias.name == old_name => {
                                            alias.name.clone_from(name);
                                        }
                                        Some(_) | None => {}
                                    }
                                }
                            }
                        }
                    }
                }
                EditOperation::InsertMappingEntry {
                    mapping,
                    key,
                    value,
                    placement,
                } => {
                    let container = self.resolve_node(*mapping, NodeRole::YamlNode)?;
                    let NativeContent::Mapping(base) = &self.native.nodes[container].content else {
                        return Err(EditFailure::WrongRole);
                    };
                    let ordinal = self.mapping_placement(container, base, *placement)?;
                    let key = expected.append_root(self.validation_model_for_value(key)?)?;
                    let value = expected.append_root(self.validation_model_for_value(value)?)?;
                    let ValidationContent::Mapping(entries) =
                        &mut expected.nodes[container].content
                    else {
                        return Err(EditFailure::NewDocumentFormationFailed);
                    };
                    entries.insert(
                        ordinal,
                        ValidationMappingEntry {
                            key: ValidationEdge {
                                target: key,
                                alias: None,
                            },
                            value: ValidationEdge {
                                target: value,
                                alias: None,
                            },
                        },
                    );
                }
                EditOperation::RemoveMappingEntry { target } => {
                    let (container, ordinal) = self.resolve_mapping_entry(*target)?;
                    let ValidationContent::Mapping(entries) =
                        &mut expected.nodes[container].content
                    else {
                        return Err(EditFailure::NewDocumentFormationFailed);
                    };
                    entries.remove(ordinal);
                }
                EditOperation::InsertSequenceElement {
                    sequence,
                    value,
                    placement,
                } => {
                    let container = self.resolve_node(*sequence, NodeRole::YamlNode)?;
                    let NativeContent::Sequence(base) = &self.native.nodes[container].content
                    else {
                        return Err(EditFailure::WrongRole);
                    };
                    let ordinal = self.sequence_placement(container, base, *placement)?;
                    let target = expected.append_root(self.validation_model_for_value(value)?)?;
                    let ValidationContent::Sequence(items) = &mut expected.nodes[container].content
                    else {
                        return Err(EditFailure::NewDocumentFormationFailed);
                    };
                    items.insert(
                        ordinal,
                        ValidationEdge {
                            target,
                            alias: None,
                        },
                    );
                }
                EditOperation::RemoveSequenceElement { target } => {
                    let (container, ordinal) = self.resolve_sequence_item(*target)?;
                    let ValidationContent::Sequence(items) = &mut expected.nodes[container].content
                    else {
                        return Err(EditFailure::NewDocumentFormationFailed);
                    };
                    items.remove(ordinal);
                }
                EditOperation::InsertAlias {
                    sequence,
                    anchor,
                    placement,
                } => {
                    let container = self.resolve_node(*sequence, NodeRole::YamlNode)?;
                    let target = self.resolve_node(*anchor, NodeRole::YamlAnchorDefinition)?;
                    let NativeContent::Sequence(base) = &self.native.nodes[container].content
                    else {
                        return Err(EditFailure::WrongRole);
                    };
                    let ordinal = self.sequence_placement(container, base, *placement)?;
                    let name = self.native.nodes[target]
                        .anchor
                        .as_deref()
                        .ok_or(EditFailure::WrongRole)?
                        .to_owned();
                    let ValidationContent::Sequence(items) = &mut expected.nodes[container].content
                    else {
                        return Err(EditFailure::NewDocumentFormationFailed);
                    };
                    items.insert(
                        ordinal,
                        ValidationEdge {
                            target,
                            alias: Some(ValidationAlias {
                                name,
                                source_alias: None,
                            }),
                        },
                    );
                }
            }
        }
        expected.compare(&ValidationModel::from_document(candidate, true))
    }

    fn validation_model_for_value(
        &self,
        value: &PortableValue,
    ) -> Result<ValidationModel, EditFailure> {
        let request = MaterializationRequest::new(
            self.profile.id(),
            MaterializationStyleId::new("yaml.canonical-flow", 1),
        )
        .with_limits(edit_materialization_limits(self.parse_limits));
        match crate::materialize_value(value, &request) {
            MaterializationResult::Complete(complete) => {
                Ok(ValidationModel::from_document(&complete.document, false))
            }
            MaterializationResult::Failed(failed) => Err(match failed.failure {
                consema_document::MaterializationFailure::Unrepresentable { kind, .. } => {
                    EditFailure::UnsupportedInsertedValue(kind)
                }
                consema_document::MaterializationFailure::ResourceLimit(name) => {
                    EditFailure::ResourceLimit(name)
                }
                _ => EditFailure::NewDocumentFormationFailed,
            }),
        }
    }

    fn validate_dependencies(&self, transaction: &EditTransaction) -> Result<(), EditFailure> {
        let mut targets = HashSet::new();
        let mut structural_containers = HashSet::new();
        for operation in transaction.operations.iter() {
            let target = match operation {
                EditOperation::ReplaceScalar(replacement) => replacement.target(),
                EditOperation::RenameAnchor { target, .. }
                | EditOperation::RemoveMappingEntry { target }
                | EditOperation::RemoveSequenceElement { target } => *target,
                EditOperation::InsertMappingEntry { mapping, .. } => *mapping,
                EditOperation::InsertSequenceElement { sequence, .. }
                | EditOperation::InsertAlias { sequence, .. } => *sequence,
            };
            if !targets.insert(target) {
                return Err(EditFailure::DuplicateTarget);
            }
            let structural_container = match operation {
                EditOperation::InsertMappingEntry { mapping, .. } => {
                    Some(self.resolve_node(*mapping, NodeRole::YamlNode)?)
                }
                EditOperation::RemoveMappingEntry { target } => {
                    Some(self.resolve_mapping_entry(*target)?.0)
                }
                EditOperation::InsertSequenceElement { sequence, .. }
                | EditOperation::InsertAlias { sequence, .. } => {
                    Some(self.resolve_node(*sequence, NodeRole::YamlNode)?)
                }
                EditOperation::RemoveSequenceElement { target } => {
                    Some(self.resolve_sequence_item(*target)?.0)
                }
                EditOperation::ReplaceScalar(_) | EditOperation::RenameAnchor { .. } => None,
            };
            match structural_container {
                Some(container) if !structural_containers.insert(container) => {
                    return Err(EditFailure::StructuralContainerConflict);
                }
                Some(_) | None => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CanonicalScalar {
    tag: String,
    literal: String,
    canonical: String,
}

#[derive(Clone, Debug)]
struct ValidationModel {
    roots: Vec<usize>,
    nodes: Vec<ValidationNode>,
}

#[derive(Clone, Debug)]
struct ValidationNode {
    tag: String,
    anchor: Option<String>,
    content: ValidationContent,
    source_node: Option<usize>,
    scalar_wildcard: bool,
}

#[derive(Clone, Debug)]
enum ValidationContent {
    Scalar {
        kind: YamlScalarKind,
        canonical: String,
    },
    Sequence(Vec<ValidationEdge>),
    Mapping(Vec<ValidationMappingEntry>),
}

#[derive(Clone, Debug)]
struct ValidationEdge {
    target: usize,
    alias: Option<ValidationAlias>,
}

#[derive(Clone, Debug)]
struct ValidationAlias {
    name: String,
    source_alias: Option<usize>,
}

#[derive(Clone, Debug)]
struct ValidationMappingEntry {
    key: ValidationEdge,
    value: ValidationEdge,
}

impl ValidationModel {
    fn from_document(document: &Document, retain_source: bool) -> Self {
        let nodes = document
            .native
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| ValidationNode {
                tag: node.tag.to_string(),
                anchor: node.anchor.as_deref().map(str::to_owned),
                content: match &node.content {
                    NativeContent::Scalar(scalar) => ValidationContent::Scalar {
                        kind: scalar.kind,
                        canonical: scalar.canonical.to_string(),
                    },
                    NativeContent::Sequence(items) => ValidationContent::Sequence(
                        items
                            .iter()
                            .map(|item| ValidationEdge {
                                target: item.node,
                                alias: item.alias.map(|ordinal| ValidationAlias {
                                    name: document.native.aliases[ordinal].name.to_string(),
                                    source_alias: retain_source.then_some(ordinal),
                                }),
                            })
                            .collect(),
                    ),
                    NativeContent::Mapping(entries) => ValidationContent::Mapping(
                        entries
                            .iter()
                            .map(|entry| ValidationMappingEntry {
                                key: ValidationEdge {
                                    target: entry.key,
                                    alias: entry.key_alias.map(|ordinal| ValidationAlias {
                                        name: document.native.aliases[ordinal].name.to_string(),
                                        source_alias: retain_source.then_some(ordinal),
                                    }),
                                },
                                value: ValidationEdge {
                                    target: entry.value,
                                    alias: entry.value_alias.map(|ordinal| ValidationAlias {
                                        name: document.native.aliases[ordinal].name.to_string(),
                                        source_alias: retain_source.then_some(ordinal),
                                    }),
                                },
                            })
                            .collect(),
                    ),
                },
                source_node: retain_source.then_some(index),
                scalar_wildcard: false,
            })
            .collect();
        Self {
            roots: document
                .native
                .documents
                .iter()
                .map(|document| document.root)
                .collect(),
            nodes,
        }
    }

    fn append_root(&mut self, mut imported: Self) -> Result<usize, EditFailure> {
        if imported.roots.len() != 1 {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        let offset = self.nodes.len();
        for node in &mut imported.nodes {
            node.source_node = None;
            match &mut node.content {
                ValidationContent::Scalar { .. } => {}
                ValidationContent::Sequence(items) => {
                    for item in items {
                        item.target = item
                            .target
                            .checked_add(offset)
                            .ok_or(EditFailure::ResourceLimit("validation-nodes"))?;
                        if let Some(alias) = &mut item.alias {
                            alias.source_alias = None;
                        }
                    }
                }
                ValidationContent::Mapping(entries) => {
                    for entry in entries {
                        for edge in [&mut entry.key, &mut entry.value] {
                            edge.target = edge
                                .target
                                .checked_add(offset)
                                .ok_or(EditFailure::ResourceLimit("validation-nodes"))?;
                            if let Some(alias) = &mut edge.alias {
                                alias.source_alias = None;
                            }
                        }
                    }
                }
            }
        }
        let root = imported.roots[0]
            .checked_add(offset)
            .ok_or(EditFailure::ResourceLimit("validation-nodes"))?;
        self.nodes
            .try_reserve(imported.nodes.len())
            .map_err(|_| EditFailure::ResourceLimit("validation-nodes"))?;
        self.nodes.extend(imported.nodes);
        Ok(root)
    }

    fn compare(&self, candidate: &Self) -> Result<CandidateMap, EditFailure> {
        if self.roots.len() != candidate.roots.len() {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        let mut state = ValidationComparison::default();
        for (&expected, &actual) in self.roots.iter().zip(candidate.roots.iter()) {
            self.compare_node(candidate, expected, actual, &mut state)?;
        }
        if state.node_pairs.len() != self.reachable_count()
            || state.actual_nodes.len() != candidate.reachable_count()
        {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        Ok(state.output)
    }

    fn compare_node(
        &self,
        candidate: &Self,
        expected: usize,
        actual: usize,
        state: &mut ValidationComparison,
    ) -> Result<(), EditFailure> {
        if let Some(mapped) = state.node_pairs.get(&expected) {
            return if *mapped == actual {
                Ok(())
            } else {
                Err(EditFailure::NewDocumentFormationFailed)
            };
        }
        if !state.actual_nodes.insert(actual) {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        let expected_node = self
            .nodes
            .get(expected)
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        let actual_node = candidate
            .nodes
            .get(actual)
            .ok_or(EditFailure::NewDocumentFormationFailed)?;
        state.node_pairs.insert(expected, actual);
        if let Some(source) = expected_node.source_node {
            state.output.nodes.insert(source, actual);
        }
        if expected_node.anchor != actual_node.anchor {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        if expected_node.scalar_wildcard {
            return if matches!(
                (&expected_node.content, &actual_node.content),
                (
                    ValidationContent::Scalar { .. },
                    ValidationContent::Scalar { .. }
                )
            ) {
                Ok(())
            } else {
                Err(EditFailure::NewDocumentFormationFailed)
            };
        }
        if expected_node.tag != actual_node.tag {
            return Err(EditFailure::NewDocumentFormationFailed);
        }
        match (&expected_node.content, &actual_node.content) {
            (
                ValidationContent::Scalar {
                    kind: expected_kind,
                    canonical: expected_canonical,
                },
                ValidationContent::Scalar {
                    kind: actual_kind,
                    canonical: actual_canonical,
                },
            ) if expected_kind == actual_kind && expected_canonical == actual_canonical => Ok(()),
            (ValidationContent::Sequence(expected), ValidationContent::Sequence(actual))
                if expected.len() == actual.len() =>
            {
                for (expected, actual) in expected.iter().zip(actual.iter()) {
                    self.compare_edge(candidate, expected, actual, state)?;
                }
                Ok(())
            }
            (ValidationContent::Mapping(expected), ValidationContent::Mapping(actual))
                if expected.len() == actual.len() =>
            {
                for (expected, actual) in expected.iter().zip(actual.iter()) {
                    self.compare_edge(candidate, &expected.key, &actual.key, state)?;
                    self.compare_edge(candidate, &expected.value, &actual.value, state)?;
                }
                Ok(())
            }
            _ => Err(EditFailure::NewDocumentFormationFailed),
        }
    }

    fn compare_edge(
        &self,
        candidate: &Self,
        expected: &ValidationEdge,
        actual: &ValidationEdge,
        state: &mut ValidationComparison,
    ) -> Result<(), EditFailure> {
        match (&expected.alias, &actual.alias) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected.name == actual.name => {
                if let (Some(old), Some(new)) = (expected.source_alias, actual.source_alias) {
                    state.output.aliases.insert(old, new);
                }
            }
            _ => return Err(EditFailure::NewDocumentFormationFailed),
        }
        self.compare_node(candidate, expected.target, actual.target, state)
    }

    fn reachable_count(&self) -> usize {
        let mut reached = HashSet::new();
        let mut pending = self.roots.clone();
        while let Some(index) = pending.pop() {
            if !reached.insert(index) {
                continue;
            }
            let Some(node) = self.nodes.get(index) else {
                continue;
            };
            match &node.content {
                ValidationContent::Scalar { .. } => {}
                ValidationContent::Sequence(items) => {
                    pending.extend(items.iter().map(|item| item.target));
                }
                ValidationContent::Mapping(entries) => {
                    pending.extend(
                        entries
                            .iter()
                            .flat_map(|entry| [entry.key.target, entry.value.target]),
                    );
                }
            }
        }
        reached.len()
    }
}

#[derive(Debug, Default)]
struct ValidationComparison {
    node_pairs: HashMap<usize, usize>,
    actual_nodes: HashSet<usize>,
    output: CandidateMap,
}

fn preserved_literal(
    old_kind: YamlScalarKind,
    old_style: YamlScalarStyle,
    old_tag: &str,
    explicit_tag: bool,
    canonical: &CanonicalScalar,
    value_kind: PortableValueKind,
    profile: YamlProfile,
) -> Option<String> {
    if old_kind != yaml_kind(value_kind) || old_tag != shorthand_tag_uri(&canonical.tag)? {
        return None;
    }
    let decoded = decode_canonical_literal(&canonical.literal)?;
    match old_style {
        YamlScalarStyle::DoubleQuoted => Some(canonical.literal.clone()),
        YamlScalarStyle::SingleQuoted if !decoded.contains(['\n', '\r']) => {
            Some(format!("'{}'", decoded.replace('\'', "''")))
        }
        YamlScalarStyle::Plain => {
            let source = if explicit_tag {
                format!("{} {decoded}", canonical.tag)
            } else {
                decoded.clone()
            };
            let candidate = crate::parse(
                source.as_bytes(),
                profile,
                consema_document::ParseLimits::default(),
            )
            .ok()?;
            let scalar = candidate.document(0)?.root().scalar()?;
            (scalar.kind() == old_kind && scalar.canonical() == canonical.canonical)
                .then_some(decoded)
        }
        YamlScalarStyle::SingleQuoted | YamlScalarStyle::Literal | YamlScalarStyle::Folded => None,
    }
}

fn shorthand_tag_uri(tag: &str) -> Option<&str> {
    match tag {
        "!!null" => Some("tag:yaml.org,2002:null"),
        "!!bool" => Some("tag:yaml.org,2002:bool"),
        "!!int" => Some("tag:yaml.org,2002:int"),
        "!!float" => Some("tag:yaml.org,2002:float"),
        "!!str" => Some("tag:yaml.org,2002:str"),
        "!!timestamp" => Some("tag:yaml.org,2002:timestamp"),
        "!!binary" => Some("tag:yaml.org,2002:binary"),
        _ => None,
    }
}

fn decode_canonical_literal(literal: &str) -> Option<String> {
    let candidate = crate::parse(
        literal.as_bytes(),
        YamlProfile::Yaml12CoreV1,
        consema_document::ParseLimits::default(),
    )
    .ok()?;
    Some(candidate.document(0)?.root().scalar()?.decoded().to_owned())
}

const fn yaml_kind(kind: PortableValueKind) -> YamlScalarKind {
    match kind {
        PortableValueKind::Null => YamlScalarKind::Null,
        PortableValueKind::Boolean => YamlScalarKind::Boolean,
        PortableValueKind::Integer => YamlScalarKind::Integer,
        PortableValueKind::Decimal | PortableValueKind::BinaryFloat64 => YamlScalarKind::Float,
        PortableValueKind::String => YamlScalarKind::String,
        PortableValueKind::Bytes => YamlScalarKind::Binary,
        PortableValueKind::Date | PortableValueKind::OffsetDateTime => YamlScalarKind::Timestamp,
        PortableValueKind::BinaryFloat32
        | PortableValueKind::Time
        | PortableValueKind::LocalDateTime
        | PortableValueKind::Sequence
        | PortableValueKind::Object
        | PortableValueKind::EntryMapping => YamlScalarKind::Custom,
    }
}

const fn is_scalar_value(kind: PortableValueKind) -> bool {
    !matches!(
        kind,
        PortableValueKind::Sequence | PortableValueKind::Object | PortableValueKind::EntryMapping
    )
}

fn same_topology(old: &NativeContent, new: &NativeContent) -> bool {
    match (old, new) {
        (NativeContent::Scalar(_), NativeContent::Scalar(_)) => true,
        (NativeContent::Sequence(old), NativeContent::Sequence(new)) => {
            old.len() == new.len()
                && old.iter().zip(new.iter()).all(|(old, new)| {
                    old.node == new.node && old.alias.is_some() == new.alias.is_some()
                })
        }
        (NativeContent::Mapping(old), NativeContent::Mapping(new)) => {
            old.len() == new.len()
                && old.iter().zip(new.iter()).all(|(old, new)| {
                    old.key == new.key
                        && old.value == new.value
                        && old.key_alias.is_some() == new.key_alias.is_some()
                        && old.value_alias.is_some() == new.value_alias.is_some()
                })
        }
        _ => false,
    }
}

fn same_scalar_semantics(old: &NativeContent, new: &NativeContent) -> bool {
    match (old, new) {
        (NativeContent::Scalar(old), NativeContent::Scalar(new)) => {
            old.canonical == new.canonical && old.kind == new.kind
        }
        _ => true,
    }
}

const fn is_structural_operation(operation: &EditOperation) -> bool {
    matches!(
        operation,
        EditOperation::InsertMappingEntry { .. }
            | EditOperation::RemoveMappingEntry { .. }
            | EditOperation::InsertSequenceElement { .. }
            | EditOperation::RemoveSequenceElement { .. }
            | EditOperation::InsertAlias { .. }
    )
}

fn validate_prepared_ownership(prepared: &[PreparedEdit]) -> Result<(), EditFailure> {
    for pair in prepared.windows(2) {
        if !pair[0].old_span.is_empty()
            && !pair[1].old_span.is_empty()
            && pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
        {
            return Err(EditFailure::AncestorDescendantConflict);
        }
        if pair[0].old_span == pair[1].old_span {
            return Err(EditFailure::OverlappingOwnership);
        }
    }
    Ok(())
}

fn push_fallback_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    span: Span,
) -> Result<(), EditFailure> {
    let occurrence =
        u64::try_from(diagnostics.len()).map_err(|_| EditFailure::ResourceLimit("diagnostics"))?;
    diagnostics.push(Diagnostic::new(
        "yaml.edit.canonical-fallback@1",
        DiagnosticCategory::Edit,
        DiagnosticSeverity::Info,
        Some(DiagnosticLocation {
            snapshot: Some(span.snapshot().as_u64()),
            start_byte: u64::try_from(span.start_byte())
                .map_err(|_| EditFailure::ResourceLimit("diagnostics"))?,
            end_byte: u64::try_from(span.end_byte())
                .map_err(|_| EditFailure::ResourceLimit("diagnostics"))?,
        }),
        occurrence,
    ));
    Ok(())
}

fn standalone_source(fragment: &[u8], encoding: SourceEncoding) -> Result<Vec<u8>, EditFailure> {
    let mut output = Vec::new();
    let bom: &[u8] = match encoding {
        SourceEncoding::Utf8 => &[],
        SourceEncoding::Utf16Le => &[0xff, 0xfe],
        SourceEncoding::Utf16Be => &[0xfe, 0xff],
        SourceEncoding::Binary | SourceEncoding::Latin1 | SourceEncoding::WindowsCodePage(_) => {
            return Err(EditFailure::InvalidLiteral);
        }
    };
    output
        .try_reserve(bom.len().saturating_add(fragment.len()))
        .map_err(|_| EditFailure::ResourceLimit("literal-allocation"))?;
    output.extend_from_slice(bom);
    output.extend_from_slice(fragment);
    Ok(output)
}

fn encode_fragment(
    text: &str,
    encoding: SourceEncoding,
    max: usize,
) -> Result<Vec<u8>, EditFailure> {
    match encoding {
        SourceEncoding::Utf8 => {
            if text.len() > max {
                return Err(EditFailure::ResourceLimit("replacement-bytes"));
            }
            Ok(text.as_bytes().to_vec())
        }
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => {
            let length = text
                .encode_utf16()
                .count()
                .checked_mul(2)
                .ok_or(EditFailure::ResourceLimit("replacement-bytes"))?;
            if length > max {
                return Err(EditFailure::ResourceLimit("replacement-bytes"));
            }
            let mut output = Vec::new();
            output
                .try_reserve(length)
                .map_err(|_| EditFailure::ResourceLimit("replacement-allocation"))?;
            for unit in text.encode_utf16() {
                let bytes = if encoding == SourceEncoding::Utf16Le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                };
                output.extend_from_slice(&bytes);
            }
            Ok(output)
        }
        SourceEncoding::Binary | SourceEncoding::Latin1 | SourceEncoding::WindowsCodePage(_) => {
            Err(EditFailure::InvalidLiteral)
        }
    }
}

const fn edit_materialization_limits(
    limits: consema_document::ParseLimits,
) -> MaterializationLimits {
    MaterializationLimits {
        max_input_nodes: limits.max_node_count,
        max_output_bytes: limits.max_source_bytes,
        max_depth: limits.max_nesting_depth,
        max_report_entries: limits.max_diagnostics,
        max_provenance_entries: limits.max_node_count.saturating_mul(4),
    }
}

fn source_patch_limits(
    limits: consema_document::ParseLimits,
    operation_count: usize,
) -> SourcePatchLimits {
    SourcePatchLimits {
        source: SourceLimits {
            max_raw_bytes: limits.max_source_bytes,
            max_decoded_utf8_bytes: limits.max_source_bytes.saturating_mul(2),
            max_decoded_scalars: limits.max_source_bytes,
        },
        max_replacements: operation_count,
        max_patch_bytes: limits.max_source_bytes.saturating_mul(2),
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
                    "yaml.edit.replace-scalar-semantic@1"
                }
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { .. }) => {
                    "yaml.edit.replace-scalar-literal@1"
                }
                EditOperation::RenameAnchor { .. } => "yaml.edit.rename-anchor@1",
                EditOperation::InsertMappingEntry { .. } => "yaml.edit.insert-mapping-entry@1",
                EditOperation::RemoveMappingEntry { .. } => "yaml.edit.remove-mapping-entry@1",
                EditOperation::InsertSequenceElement { .. } => {
                    "yaml.edit.insert-sequence-element@1"
                }
                EditOperation::RemoveSequenceElement { .. } => {
                    "yaml.edit.remove-sequence-element@1"
                }
                EditOperation::InsertAlias { .. } => "yaml.edit.insert-alias@1",
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
            let (id, role, mut arguments) = match operation {
                EditOperation::ReplaceScalar(ScalarReplacement::Semantic {
                    value, policy, ..
                }) => (
                    "yaml.edit.replace-scalar-semantic",
                    "yaml.scalar@1",
                    BTreeMap::from([
                        ("policy".to_owned(), policy_name(*policy).to_owned()),
                        ("value_kind".to_owned(), format!("{:?}", value.kind())),
                    ]),
                ),
                EditOperation::ReplaceScalar(ScalarReplacement::Literal { literal, .. }) => (
                    "yaml.edit.replace-scalar-literal",
                    "yaml.scalar@1",
                    BTreeMap::from([("literal_bytes".to_owned(), literal.len().to_string())]),
                ),
                EditOperation::RenameAnchor { name, .. } => (
                    "yaml.edit.rename-anchor",
                    "yaml.anchor-definition@1",
                    BTreeMap::from([("name_bytes".to_owned(), name.len().to_string())]),
                ),
                EditOperation::InsertMappingEntry {
                    key,
                    value,
                    placement,
                    ..
                } => (
                    "yaml.edit.insert-mapping-entry",
                    "yaml.mapping@1",
                    BTreeMap::from([
                        ("key_kind".to_owned(), format!("{:?}", key.kind())),
                        ("value_kind".to_owned(), format!("{:?}", value.kind())),
                        ("placement".to_owned(), placement_name(*placement)),
                    ]),
                ),
                EditOperation::RemoveMappingEntry { .. } => (
                    "yaml.edit.remove-mapping-entry",
                    "yaml.mapping-entry@1",
                    BTreeMap::new(),
                ),
                EditOperation::InsertSequenceElement {
                    value, placement, ..
                } => (
                    "yaml.edit.insert-sequence-element",
                    "yaml.sequence@1",
                    BTreeMap::from([
                        ("value_kind".to_owned(), format!("{:?}", value.kind())),
                        ("placement".to_owned(), placement_name(*placement)),
                    ]),
                ),
                EditOperation::RemoveSequenceElement { .. } => (
                    "yaml.edit.remove-sequence-element",
                    "yaml.sequence-element@1",
                    BTreeMap::new(),
                ),
                EditOperation::InsertAlias { placement, .. } => (
                    "yaml.edit.insert-alias",
                    "yaml.sequence@1",
                    BTreeMap::from([("placement".to_owned(), placement_name(*placement))]),
                ),
            };
            arguments.insert("target_role".to_owned(), role.to_owned());
            EditOperationSummary::new(FormatOperationId::new(id, 1), arguments)
                .map_err(|_| EditFailure::NewDocumentFormationFailed)
        })
        .collect()
}

fn placement_name(placement: AssociationPlacement) -> String {
    match placement {
        AssociationPlacement::Start => "start".to_owned(),
        AssociationPlacement::End => "end".to_owned(),
        AssociationPlacement::Before(_) => "before".to_owned(),
        AssociationPlacement::After(_) => "after".to_owned(),
    }
}

const fn policy_name(policy: RepresentationPolicy) -> &'static str {
    match policy {
        RepresentationPolicy::ExactLiteral => "exact-literal",
        RepresentationPolicy::PreserveCompatible => "preserve-compatible",
        RepresentationPolicy::CanonicalForProfile => "canonical-for-profile",
        RepresentationPolicy::PreserveElseCanonical => "preserve-else-canonical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::BigInteger;
    use consema_document::{EditPlanSourceId, ParseLimits};

    #[test]
    fn semantic_and_literal_scalar_edits_are_atomic_and_style_aware() {
        let document = crate::parse(
            b"# keep\na: 1\nb: \"old\"\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        let integer = root.mapping_entry(0).unwrap().value();
        let string = root.mapping_entry(1).unwrap().value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .semantic_scalar(
                integer.node_ref(),
                PortableValue::integer(BigInteger::from(2)),
                RepresentationPolicy::PreserveCompatible,
            )
            .literal_scalar(string.node_ref(), b"'new'".as_slice());
        let transaction = builder.build();
        let plan = document
            .dry_run(&transaction, EditPlanSourceId::new("scalar.yaml").unwrap())
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(commit.document.render(), b"# keep\na: 2\nb: 'new'\n");
        assert_eq!(commit.change_set.source_edits().len(), 2);
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
    fn canonical_fallback_is_explicit_and_keeps_anchor_properties() {
        let document = crate::parse(
            b"value: &x plain\ncopy: *x\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let target = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            target.node_ref(),
            PortableValue::boolean(true),
            RepresentationPolicy::PreserveElseCanonical,
        );
        let transaction = builder.build();
        let plan = document
            .dry_run(
                &transaction,
                EditPlanSourceId::new("fallback.yaml").unwrap(),
            )
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(commit.change_set.diagnostics().len(), 1);
        assert!(
            std::str::from_utf8(commit.document.render())
                .unwrap()
                .contains("&x !!bool \"true\"")
        );
        assert_eq!(
            commit
                .document
                .alias(0)
                .unwrap()
                .target()
                .scalar()
                .unwrap()
                .canonical(),
            "true"
        );
    }

    #[test]
    fn anchor_rename_updates_only_dependent_aliases_and_dry_run_matches() {
        let document = crate::parse(
            b"first: &x [one]\ncopy: *x\nother: &x [two]\ncopy2: *x\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let first = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.rename_anchor(first.anchor_node_ref().unwrap(), "renamed");
        let transaction = builder.build();
        let plan = document
            .dry_run(&transaction, EditPlanSourceId::new("config.yaml").unwrap())
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(
            commit.document.render(),
            b"first: &renamed [one]\ncopy: *renamed\nother: &x [two]\ncopy2: *x\n"
        );
        assert_eq!(commit.document.alias(0).unwrap().name(), "renamed");
        assert_eq!(commit.document.alias(1).unwrap().name(), "x");
    }

    #[test]
    fn wrong_snapshots_invalid_literals_and_duplicate_targets_fail_without_documents() {
        let first = crate::parse(
            b"a: 1\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let second = crate::parse(
            b"a: 2\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let target = second
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut wrong = EditTransactionBuilder::new(&first);
        wrong.literal_scalar(target.node_ref(), b"3".as_slice());
        assert_eq!(
            first.commit(&wrong.build()).unwrap_err(),
            EditFailure::WrongSnapshot
        );

        let own = first
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut invalid = EditTransactionBuilder::new(&first);
        invalid.literal_scalar(own.node_ref(), b"[not, scalar]".as_slice());
        assert_eq!(
            first.commit(&invalid.build()).unwrap_err(),
            EditFailure::InvalidLiteral
        );

        let mut duplicate = EditTransactionBuilder::new(&first);
        duplicate
            .literal_scalar(own.node_ref(), b"3".as_slice())
            .literal_scalar(own.node_ref(), b"4".as_slice());
        assert_eq!(
            first.commit(&duplicate.build()).unwrap_err(),
            EditFailure::DuplicateTarget
        );
    }

    #[test]
    fn utf16_edits_keep_encoding_and_explicit_tag_anchor_boundaries() {
        let text = "value: &x !!int '1'\ncopy: *x\n";
        let mut source = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            source.extend_from_slice(&unit.to_le_bytes());
        }
        let document =
            crate::parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default()).unwrap();
        let target = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .semantic_scalar(
                target.node_ref(),
                PortableValue::integer(BigInteger::from(2)),
                RepresentationPolicy::PreserveCompatible,
            )
            .rename_anchor(target.anchor_node_ref().unwrap(), "renamed");
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Le
        );
        assert_eq!(
            commit.document.source().decoded_text().unwrap(),
            "\u{feff}value: &renamed !!int '2'\ncopy: *renamed\n"
        );
        assert_eq!(
            commit
                .document
                .alias(0)
                .unwrap()
                .target()
                .scalar()
                .unwrap()
                .canonical(),
            "2"
        );
    }

    #[test]
    fn flow_insertions_and_removals_preserve_order_and_arbitrary_keys() {
        let document = crate::parse(
            b"root: [one, two]\nmap: {a: one}\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        let sequence = root.mapping_entry(0).unwrap().value();
        let mapping = root.mapping_entry(1).unwrap().value();
        let before_two = sequence.sequence_item(1).unwrap().node_ref();
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_sequence_element(
                sequence.node_ref(),
                PortableValue::boolean(true),
                AssociationPlacement::Before(before_two),
            )
            .insert_mapping_entry(
                mapping.node_ref(),
                PortableValue::sequence(vec![
                    PortableValue::string("x"),
                    PortableValue::string("y"),
                ]),
                PortableValue::integer(BigInteger::from(2)),
                AssociationPlacement::End,
            );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"root: [one, !!bool \"true\", two]\nmap: {a: one, ? !!seq [!!str \"x\", !!str \"y\"] : !!int \"2\"}\n"
        );
        let root = commit.document.document(0).unwrap().root();
        assert_eq!(
            root.mapping_entry(0).unwrap().value().sequence_len(),
            Some(3)
        );
        assert_eq!(
            root.mapping_entry(1).unwrap().value().mapping_len(),
            Some(2)
        );

        let sequence = root.mapping_entry(0).unwrap().value();
        let mapping = root.mapping_entry(1).unwrap().value();
        let mut remove = EditTransactionBuilder::new(&commit.document);
        remove
            .remove_sequence_element(sequence.sequence_item(1).unwrap().node_ref())
            .remove_mapping_entry(mapping.mapping_entry(1).unwrap().node_ref());
        let restored = commit.document.commit(&remove.build()).unwrap();
        assert_eq!(restored.document.render(), document.render());
    }

    #[test]
    fn block_insertions_are_style_aware_and_reversible_with_crlf_comments() {
        let source =
            b"root:\r\n  - one # keep-one\r\n  - two\r\nmap:\r\n  a: one # keep-a\r\n  b: two\r\n";
        let document = crate::parse(
            source.as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        let sequence = root.mapping_entry(0).unwrap().value();
        let mapping = root.mapping_entry(1).unwrap().value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .insert_sequence_element(
                sequence.node_ref(),
                PortableValue::string("inserted"),
                AssociationPlacement::After(sequence.sequence_item(0).unwrap().node_ref()),
            )
            .insert_mapping_entry(
                mapping.node_ref(),
                PortableValue::string("inserted-key"),
                PortableValue::boolean(false),
                AssociationPlacement::Before(mapping.mapping_entry(1).unwrap().node_ref()),
            );
        let transaction = builder.build();
        let plan = document
            .dry_run(
                &transaction,
                EditPlanSourceId::new("structural.yaml").unwrap(),
            )
            .unwrap();
        let commit = document.commit(&transaction).unwrap();
        assert_eq!(plan.target_digest(), commit.source_patch.target_digest());
        assert_eq!(
            commit.document.render(),
            b"root:\r\n  - one # keep-one\r\n  - !!str \"inserted\"\r\n  - two\r\nmap:\r\n  a: one # keep-a\r\n  ? !!str \"inserted-key\"\r\n  : !!bool \"false\"\r\n  b: two\r\n"
        );
        let root = commit.document.document(0).unwrap().root();
        let sequence = root.mapping_entry(0).unwrap().value();
        let mapping = root.mapping_entry(1).unwrap().value();
        let mut remove = EditTransactionBuilder::new(&commit.document);
        remove
            .remove_sequence_element(sequence.sequence_item(1).unwrap().node_ref())
            .remove_mapping_entry(mapping.mapping_entry(1).unwrap().node_ref());
        let restored = commit.document.commit(&remove.build()).unwrap();
        assert_eq!(restored.document.render(), source);
    }

    #[test]
    fn last_block_removal_retains_collection_kind_and_rejects_live_aliases() {
        let document = crate::parse(
            b"seq:\n  - one # keep\nnext: yes\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let item = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value()
            .sequence_item(0)
            .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.remove_sequence_element(item.node_ref());
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), b"seq:\n  [] # keep\nnext: yes\n");
        assert_eq!(
            commit
                .document
                .document(0)
                .unwrap()
                .root()
                .mapping_entry(0)
                .unwrap()
                .value()
                .sequence_len(),
            Some(0)
        );

        let anchored = crate::parse(
            b"seq:\n  - &x one\ncopy: *x\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let item = anchored
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value()
            .sequence_item(0)
            .unwrap();
        let mut removal = EditTransactionBuilder::new(&anchored);
        removal.remove_sequence_element(item.node_ref());
        assert_eq!(
            anchored.commit(&removal.build()).unwrap_err(),
            EditFailure::AnchorDependency
        );
    }

    #[test]
    fn alias_insertion_requires_the_exact_latest_visible_definition() {
        let document = crate::parse(
            b"first: &x [one]\nseq:\n  - two\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        let anchor = root
            .mapping_entry(0)
            .unwrap()
            .value()
            .anchor_node_ref()
            .unwrap();
        let sequence = root.mapping_entry(1).unwrap().value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_alias(sequence.node_ref(), anchor, AssociationPlacement::End);
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"first: &x [one]\nseq:\n  - two\n  - *x\n"
        );
        let inserted = commit
            .document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(1)
            .unwrap()
            .value()
            .sequence_item(1)
            .unwrap();
        assert_eq!(inserted.alias().unwrap().name(), "x");
        assert_eq!(inserted.node().sequence_len(), Some(1));

        let cyclic = crate::parse(
            b"&self [one]\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let sequence = cyclic.document(0).unwrap().root();
        let mut cycle = EditTransactionBuilder::new(&cyclic);
        cycle.insert_alias(
            sequence.node_ref(),
            sequence.anchor_node_ref().unwrap(),
            AssociationPlacement::End,
        );
        let committed_cycle = cyclic.commit(&cycle.build()).unwrap();
        assert_eq!(committed_cycle.document.render(), b"&self [one, *self]\n");
        let root = committed_cycle.document.document(0).unwrap().root();
        assert_eq!(
            root.sequence_item(1)
                .unwrap()
                .alias()
                .unwrap()
                .target()
                .node_ref(),
            root.node_ref()
        );
        let mut remove_alias = EditTransactionBuilder::new(&committed_cycle.document);
        remove_alias.remove_sequence_element(root.sequence_item(1).unwrap().node_ref());
        let without_alias = committed_cycle
            .document
            .commit(&remove_alias.build())
            .unwrap();
        assert_eq!(without_alias.document.render(), cyclic.render());

        let shadowed = crate::parse(
            b"first: &x [one]\nsecond: &x [two]\nseq: [three]\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = shadowed.document(0).unwrap().root();
        let first = root
            .mapping_entry(0)
            .unwrap()
            .value()
            .anchor_node_ref()
            .unwrap();
        let sequence = root.mapping_entry(2).unwrap().value();
        let mut invalid = EditTransactionBuilder::new(&shadowed);
        invalid.insert_alias(sequence.node_ref(), first, AssociationPlacement::End);
        assert_eq!(
            shadowed.commit(&invalid.build()).unwrap_err(),
            EditFailure::AnchorNotVisible
        );
    }

    #[test]
    fn structural_edits_keep_utf16_and_reject_ambiguous_same_container_transactions() {
        let text = "seq:\n  - one\n";
        let mut source = vec![0xfe, 0xff];
        for unit in text.encode_utf16() {
            source.extend_from_slice(&unit.to_be_bytes());
        }
        let document =
            crate::parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default()).unwrap();
        let sequence = document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.insert_sequence_element(
            sequence.node_ref(),
            PortableValue::string("two"),
            AssociationPlacement::End,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Be
        );
        assert_eq!(
            commit.document.source().decoded_text().unwrap(),
            "\u{feff}seq:\n  - one\n  - !!str \"two\"\n"
        );

        let sequence = commit
            .document
            .document(0)
            .unwrap()
            .root()
            .mapping_entry(0)
            .unwrap()
            .value();
        let mut ambiguous = EditTransactionBuilder::new(&commit.document);
        ambiguous
            .remove_sequence_element(sequence.sequence_item(0).unwrap().node_ref())
            .remove_sequence_element(sequence.sequence_item(1).unwrap().node_ref());
        assert_eq!(
            commit.document.commit(&ambiguous.build()).unwrap_err(),
            EditFailure::StructuralContainerConflict
        );
    }

    #[test]
    fn edit_failures_publish_stable_v5_codes() {
        let cases = [
            (EditFailure::WrongSnapshot, "core.edit.wrong-snapshot@1"),
            (EditFailure::WrongRole, "core.edit.wrong-role@1"),
            (EditFailure::TargetNotFound, "core.edit.target-not-found@1"),
            (
                EditFailure::IncompleteTarget,
                "core.edit.incomplete-target@1",
            ),
            (
                EditFailure::UnsupportedSemanticValue(PortableValueKind::Object),
                "core.edit.unsupported-value@1",
            ),
            (EditFailure::InvalidLiteral, "core.edit.invalid-literal@1"),
            (
                EditFailure::RepresentationIncompatible,
                "core.edit.representation-incompatible@1",
            ),
            (
                EditFailure::ExactLiteralRequiresLiteralOperation,
                "core.edit.exact-literal-requires-literal@1",
            ),
            (
                EditFailure::InvalidAnchorName,
                "yaml.edit.invalid-anchor-name@1",
            ),
            (
                EditFailure::InvalidPlacement,
                "yaml.edit.invalid-placement@1",
            ),
            (
                EditFailure::AnchorNotVisible,
                "yaml.edit.anchor-not-visible@1",
            ),
            (
                EditFailure::AnchorDependency,
                "yaml.edit.anchor-dependency@1",
            ),
            (
                EditFailure::UnsupportedInsertedValue(PortableValueKind::Object),
                "core.edit.unsupported-value@1",
            ),
            (
                EditFailure::StructuralContainerConflict,
                "yaml.edit.structural-container-conflict@1",
            ),
            (
                EditFailure::DuplicateTarget,
                "core.edit.conflicting-edits@1",
            ),
            (
                EditFailure::OverlappingOwnership,
                "core.edit.conflicting-edits@1",
            ),
            (
                EditFailure::AncestorDescendantConflict,
                "core.edit.conflicting-edits@1",
            ),
            (
                EditFailure::ResourceLimit("target-bytes"),
                "core.edit.resource-limit@1",
            ),
            (
                EditFailure::NewDocumentFormationFailed,
                "core.edit.formation-failed@1",
            ),
        ];
        for (failure, code) in cases {
            assert_eq!(edit_failure_code(&failure), code);
            assert_eq!(failure.diagnostic_code(), code);
        }
    }
}
