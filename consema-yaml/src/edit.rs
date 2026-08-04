//! Snapshot-bound atomic YAML structural editing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity, PortableValue,
    PortableValueKind,
};
use consema_document::{
    ChangeSet, EditOperationSummary, EditPlan, EditPlanSourceId, FormatOperationId,
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

#[derive(Clone, Debug)]
struct PreparedEdit {
    old_span: Span,
    replacement: Vec<u8>,
    mapping: Option<(NodeRef, MappingPlan)>,
}

#[derive(Clone, Copy, Debug)]
enum MappingPlan {
    Node(usize),
    Anchor(usize),
    Alias(usize),
}

impl Document {
    /// Atomically commits YAML scalar and anchor operations.
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
        self.validate_candidate(&new_document, transaction)?;

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
                        MappingPlan::Node(index) => new_document
                            .native
                            .nodes
                            .get(index)
                            .map(|_| crate::node_ref(&new_document.authority, index)),
                        MappingPlan::Anchor(index) => new_document
                            .native
                            .nodes
                            .get(index)
                            .filter(|node| node.anchor.is_some())
                            .map(|_| {
                                new_document.authority.node_ref(
                                    u64::try_from(index).expect("parse indexes fit u64"),
                                    NodeRole::YamlAnchorDefinition,
                                )
                            }),
                        MappingPlan::Alias(index) => {
                            new_document.alias(index).map(crate::YamlAlias::node_ref)
                        }
                    };
                    mappings.push(NodeMapping {
                        old,
                        new,
                        status: NodeMappingStatus::Replaced,
                        reason: new
                            .is_none()
                            .then(|| "reparsed-node-not-uniquely-located".to_owned()),
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
    ) -> Result<(), EditFailure> {
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
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CanonicalScalar {
    tag: String,
    literal: String,
    canonical: String,
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

fn validate_dependencies(transaction: &EditTransaction) -> Result<(), EditFailure> {
    let mut targets = HashSet::new();
    for operation in transaction.operations.iter() {
        let target = match operation {
            EditOperation::ReplaceScalar(replacement) => replacement.target(),
            EditOperation::RenameAnchor { target, .. } => *target,
        };
        if !targets.insert(target) {
            return Err(EditFailure::DuplicateTarget);
        }
    }
    Ok(())
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
        SourceEncoding::Binary | SourceEncoding::Latin1 => return Err(EditFailure::InvalidLiteral),
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
        SourceEncoding::Binary | SourceEncoding::Latin1 => Err(EditFailure::InvalidLiteral),
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
            };
            arguments.insert("target_role".to_owned(), role.to_owned());
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
        let commit = document.commit(&builder.build()).unwrap();
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
        let commit = document.commit(&builder.build()).unwrap();
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
}
