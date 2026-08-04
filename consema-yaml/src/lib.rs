//! Lossless YAML 1.2 Core and YAML 1.1 compatibility documents.
//!
//! The parser backend is intentionally private: Consema owns profile decisions,
//! source identity, diagnostics, resource limits, native semantics, and graph
//! composition. No third-party parser type is part of the public contract.

use std::sync::Arc;

use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure, FormatFamilyId,
    FormationStatus, LosslessStructuralIndex, ParseLimits, ProfileId, SnapshotIdentity,
    SourceEncoding, SourceLimits, SourceSnapshot,
};

mod backend;
mod edit;
mod materialization;
mod native;
mod operation_registry;
mod projection;
mod query;
mod syntax;

use backend::{BackendError, BackendEventKind, parse_events};
pub use edit::{
    AssociationPlacement, EditCommit, EditFailure, EditOperation, EditTransaction,
    EditTransactionBuilder, RepresentationPolicy, ScalarReplacement,
};
pub use materialization::{
    CompleteGraphMaterialization, FailedGraphMaterializationAttempt, GraphMaterializationFailure,
    GraphMaterializationInputLocation, GraphMaterializationProvenanceEntry,
    GraphMaterializationProvenanceMap, GraphMaterializationResult, materialize_graph,
    materialize_value,
};
pub use native::GraphProjectionError;
use native::{NativeContent, NativeStream, node_ref};
pub use operation_registry::format_operation_registry;
pub use projection::{
    CompleteGraphProjection, CompleteValueProjection, Fidelity, GraphProjectedLocation,
    GraphProjectionFailure, GraphProjectionLimits, GraphProjectionRequest, GraphProvenanceEntry,
    GraphProvenanceMap, MappingPolicy, ProjectedLocation, ProjectionEvent, ProjectionEventKind,
    ProjectionReport, ProvenanceEntry, ProvenanceMap, ProvenanceRelation, SharingPolicy,
    SourceOrigin, TagPolicy, ValueProjectionFailure, ValueProjectionLimits, ValueProjectionRequest,
    ValueProjectionResult,
};
pub use query::{
    YamlMatch, YamlSyntaxMatch, execute_yaml_query, execute_yaml_query_cursor,
    execute_yaml_syntax_query, execute_yaml_syntax_query_cursor,
};
use syntax::{Tokenized, tokenize};

/// Frozen YAML language profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlProfile {
    /// YAML 1.2.2 presentation grammar with the Core schema.
    Yaml12CoreV1,
    /// Safe YAML 1.2-compatible presentation with frozen YAML 1.1 scalar resolution.
    Yaml11CompatV1,
}

/// Closed YAML lossless presentation-piece classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlSyntaxKind {
    /// Unicode byte-order mark retained in the decoded stream.
    Bom,
    /// Horizontal separation.
    Whitespace,
    /// LF, CRLF, or bare CR line break.
    Newline,
    /// Comment excluding its line break.
    Comment,
    /// `%YAML`, `%TAG`, or reserved directive line.
    Directive,
    /// `---` document start.
    DocumentStart,
    /// `...` document end.
    DocumentEnd,
    /// Block sequence `-` indicator.
    SequenceEntry,
    /// Explicit mapping key `?` indicator.
    ExplicitKey,
    /// Mapping value `:` indicator.
    MappingValue,
    /// `[`.
    FlowSequenceStart,
    /// `]`.
    FlowSequenceEnd,
    /// `{`.
    FlowMappingStart,
    /// `}`.
    FlowMappingEnd,
    /// Flow `,` separator.
    FlowEntry,
    /// Anchor spelling beginning with `&`.
    Anchor,
    /// Alias spelling beginning with `*`.
    Alias,
    /// Tag spelling beginning with `!`.
    Tag,
    /// Plain scalar presentation fragment.
    PlainScalar,
    /// Complete single-quoted scalar presentation.
    SingleQuotedScalar,
    /// Complete double-quoted scalar presentation.
    DoubleQuotedScalar,
    /// Literal block-scalar header beginning with `|`.
    LiteralBlockHeader,
    /// Folded block-scalar header beginning with `>`.
    FoldedBlockHeader,
    /// Exact indented block-scalar content region.
    BlockScalarContent,
    /// Bytes retained after bounded syntax recovery.
    ErrorRegion,
}

/// YAML native representation node kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlNodeKind {
    /// Tagged scalar.
    Scalar,
    /// Ordered sequence associations.
    Sequence,
    /// Ordered arbitrary key/value associations.
    Mapping,
}

/// Exact scalar presentation style.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlScalarStyle {
    /// Plain style.
    Plain,
    /// Single-quoted style.
    SingleQuoted,
    /// Double-quoted style.
    DoubleQuoted,
    /// Literal block style.
    Literal,
    /// Folded block style.
    Folded,
}

/// Resolved native scalar semantic category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlScalarKind {
    /// Null.
    Null,
    /// Boolean.
    Boolean,
    /// Arbitrary-precision integer.
    Integer,
    /// Exact decimal or frozen non-finite float spelling.
    Float,
    /// String.
    String,
    /// YAML 1.1-compatible timestamp.
    Timestamp,
    /// Validated YAML binary scalar.
    Binary,
    /// Scalar carrying an uninterpreted custom tag.
    Custom,
    /// Scalar carrying a retained standard tag without a core tree lowering.
    Tagged,
}

impl YamlSyntaxKind {
    /// Stable query/protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "Bom",
            Self::Whitespace => "Whitespace",
            Self::Newline => "Newline",
            Self::Comment => "Comment",
            Self::Directive => "Directive",
            Self::DocumentStart => "DocumentStart",
            Self::DocumentEnd => "DocumentEnd",
            Self::SequenceEntry => "SequenceEntry",
            Self::ExplicitKey => "ExplicitKey",
            Self::MappingValue => "MappingValue",
            Self::FlowSequenceStart => "FlowSequenceStart",
            Self::FlowSequenceEnd => "FlowSequenceEnd",
            Self::FlowMappingStart => "FlowMappingStart",
            Self::FlowMappingEnd => "FlowMappingEnd",
            Self::FlowEntry => "FlowEntry",
            Self::Anchor => "Anchor",
            Self::Alias => "Alias",
            Self::Tag => "Tag",
            Self::PlainScalar => "PlainScalar",
            Self::SingleQuotedScalar => "SingleQuotedScalar",
            Self::DoubleQuotedScalar => "DoubleQuotedScalar",
            Self::LiteralBlockHeader => "LiteralBlockHeader",
            Self::FoldedBlockHeader => "FoldedBlockHeader",
            Self::BlockScalarContent => "BlockScalarContent",
            Self::ErrorRegion => "ErrorRegion",
        }
    }

    /// Resolves one exact stable kind name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Bom" => Some(Self::Bom),
            "Whitespace" => Some(Self::Whitespace),
            "Newline" => Some(Self::Newline),
            "Comment" => Some(Self::Comment),
            "Directive" => Some(Self::Directive),
            "DocumentStart" => Some(Self::DocumentStart),
            "DocumentEnd" => Some(Self::DocumentEnd),
            "SequenceEntry" => Some(Self::SequenceEntry),
            "ExplicitKey" => Some(Self::ExplicitKey),
            "MappingValue" => Some(Self::MappingValue),
            "FlowSequenceStart" => Some(Self::FlowSequenceStart),
            "FlowSequenceEnd" => Some(Self::FlowSequenceEnd),
            "FlowMappingStart" => Some(Self::FlowMappingStart),
            "FlowMappingEnd" => Some(Self::FlowMappingEnd),
            "FlowEntry" => Some(Self::FlowEntry),
            "Anchor" => Some(Self::Anchor),
            "Alias" => Some(Self::Alias),
            "Tag" => Some(Self::Tag),
            "PlainScalar" => Some(Self::PlainScalar),
            "SingleQuotedScalar" => Some(Self::SingleQuotedScalar),
            "DoubleQuotedScalar" => Some(Self::DoubleQuotedScalar),
            "LiteralBlockHeader" => Some(Self::LiteralBlockHeader),
            "FoldedBlockHeader" => Some(Self::FoldedBlockHeader),
            "BlockScalarContent" => Some(Self::BlockScalarContent),
            "ErrorRegion" => Some(Self::ErrorRegion),
            _ => None,
        }
    }

    const fn is_trivia(self) -> bool {
        matches!(
            self,
            Self::Bom | Self::Whitespace | Self::Newline | Self::Comment
        )
    }
}

impl YamlProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::Yaml12CoreV1 => ProfileId::new("yaml.1.2-core", 1),
            Self::Yaml11CompatV1 => ProfileId::new("yaml.1.1-compat", 1),
        }
    }

    const fn accepted_version(self) -> &'static str {
        match self {
            Self::Yaml12CoreV1 => "1.2",
            Self::Yaml11CompatV1 => "1.1",
        }
    }
}

/// Parses one exact YAML stream using BOM-detected UTF-8/UTF-16 source rules.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: YamlProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    let bytes = source.into();
    if bytes.len() > limits.max_source_bytes {
        return Err(FatalFormationFailure::resource_limit(
            "source-bytes",
            bytes.len(),
            limits.max_source_bytes,
        ));
    }
    let source = SourceSnapshot::from_raw(
        bytes,
        EncodingRequest::new(SourceEncoding::Utf8),
        SourceLimits {
            max_raw_bytes: limits.max_source_bytes,
            ..SourceLimits::default()
        },
    )
    .map_err(FatalFormationFailure::source_error)?;
    let text = source
        .decoded_text()
        .expect("YAML profiles always request decoded text");
    let (backend_text, scalar_offset_base) = text
        .strip_prefix('\u{feff}')
        .map_or((text, 0), |without_bom| (without_bom, 1));
    validate_version_directives(backend_text, profile)?;
    let events = parse_events(
        backend_text,
        limits.max_token_count,
        limits.max_nesting_depth,
        scalar_offset_base,
    )
    .map_err(|error| backend_failure(error, &source))?;
    let document_count = events
        .iter()
        .filter(|event| matches!(event.kind, BackendEventKind::DocumentStart { .. }))
        .count();
    let authority = DocumentAuthority::fresh();
    let Tokenized {
        index: structural_index,
        kinds: syntax_kinds,
        anchors,
        aliases,
    } = tokenize(&source, &authority, limits.max_token_count)?;
    let native = native::compose(
        &events, &source, &authority, profile, anchors, aliases, limits,
    )?;
    Ok(Document {
        authority,
        source,
        profile,
        structural_index,
        syntax_kinds: Arc::from(syntax_kinds),
        native,
        stream_documents: document_count,
        parse_limits: limits,
    })
}

/// Immutable exact-source YAML stream snapshot.
#[derive(Clone, Debug)]
pub struct Document {
    authority: DocumentAuthority,
    source: SourceSnapshot,
    profile: YamlProfile,
    structural_index: LosslessStructuralIndex,
    syntax_kinds: Arc<[YamlSyntaxKind]>,
    native: NativeStream,
    stream_documents: usize,
    parse_limits: ParseLimits,
}

impl Document {
    /// Snapshot-bound identity of the complete serialization stream.
    #[must_use]
    pub fn stream_node_ref(&self) -> consema_document::NodeRef {
        self.authority
            .node_ref(0, consema_document::NodeRole::YamlStream)
    }

    /// Exact raw span of the complete serialization stream.
    #[must_use]
    pub fn stream_span(&self) -> consema_document::Span {
        self.authority
            .span(0, self.source.len())
            .expect("source length is an ordered span")
    }

    /// Snapshot identity to which future native handles and spans are bound.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.authority.identity()
    }

    /// Exact immutable raw source and decoded-location facts.
    #[must_use]
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Default rendering is byte-for-byte identical to the input.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// YAML format-family contract.
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("yaml", 1)
    }

    /// Exact selected YAML profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Complete valid streams require no recovered semantic claims.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        FormationStatus::Complete
    }

    /// Exhaustive token/trivia byte coverage.
    #[must_use]
    pub const fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.structural_index
    }

    /// Format-specific kind for each structural piece in source order.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[YamlSyntaxKind] {
        &self.syntax_kinds
    }

    /// Returns one independent YAML document by stream ordinal.
    #[must_use]
    pub fn document(&self, ordinal: usize) -> Option<YamlDocument<'_>> {
        self.native
            .documents
            .get(ordinal)
            .map(|document| YamlDocument {
                owner: self,
                ordinal,
                document,
            })
    }

    /// Number of alias serialization occurrences; aliases are never expanded.
    #[must_use]
    pub fn alias_count(&self) -> usize {
        self.native.aliases.len()
    }

    /// Returns one alias occurrence in serialization order.
    #[must_use]
    pub fn alias(&self, ordinal: usize) -> Option<YamlAlias<'_>> {
        self.native
            .aliases
            .get(ordinal)
            .map(|alias| YamlAlias { owner: self, alias })
    }

    /// Projects all document roots to one exact PortableGraph.
    ///
    /// Unknown/custom tags fail instead of being treated as application
    /// constructors or untyped strings; frozen standard repository tags remain
    /// exact tagged graph nodes.
    pub fn project_graph(&self) -> Result<consema_graph::PortableGraph, GraphProjectionError> {
        self.project_graph_bounded(consema_graph::GraphLimits::default())
    }

    /// Projects all document roots with caller-supplied graph resource limits.
    pub fn project_graph_bounded(
        &self,
        limits: consema_graph::GraphLimits,
    ) -> Result<consema_graph::PortableGraph, GraphProjectionError> {
        self.native.project_graph(limits)
    }

    /// Number of independent YAML documents in this stream.
    #[must_use]
    pub const fn document_count(&self) -> usize {
        self.stream_documents
    }

    /// Resource contract used to form this stream.
    #[must_use]
    pub const fn parse_limits(&self) -> ParseLimits {
        self.parse_limits
    }
}

/// One independent document in a YAML stream.
#[derive(Clone, Copy, Debug)]
pub struct YamlDocument<'a> {
    owner: &'a Document,
    ordinal: usize,
    document: &'a native::NativeDocument,
}

impl<'a> YamlDocument<'a> {
    /// Zero-based stream ordinal.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }

    /// Snapshot-bound document identity.
    #[must_use]
    pub fn node_ref(self) -> consema_document::NodeRef {
        self.owner.authority.node_ref(
            u64::try_from(self.ordinal).expect("parse limits keep document ordinals in u64"),
            consema_document::NodeRole::YamlDocument,
        )
    }

    /// Backend-validated raw document presentation span.
    #[must_use]
    pub const fn span(self) -> consema_document::Span {
        self.document.span
    }

    /// Representation root. Alias occurrences already share target identity.
    #[must_use]
    pub const fn root(self) -> YamlNode<'a> {
        YamlNode {
            owner: self.owner,
            index: self.document.root,
        }
    }
}

/// Snapshot-bound YAML representation node.
#[derive(Clone, Copy, Debug)]
pub struct YamlNode<'a> {
    owner: &'a Document,
    index: usize,
}

impl<'a> YamlNode<'a> {
    /// Process-local stable identity within this snapshot.
    #[must_use]
    pub fn node_ref(self) -> consema_document::NodeRef {
        node_ref(&self.owner.authority, self.index)
    }

    /// Exact raw representation occurrence span.
    #[must_use]
    pub fn span(self) -> consema_document::Span {
        self.owner.native.nodes[self.index].span
    }

    /// Resolved tag identifier.
    #[must_use]
    pub fn tag(self) -> &'a str {
        &self.owner.native.nodes[self.index].tag
    }

    /// Exact anchor name on the defining occurrence, if present.
    #[must_use]
    pub fn anchor(self) -> Option<&'a str> {
        self.owner.native.nodes[self.index].anchor.as_deref()
    }

    /// Snapshot-bound anchor-definition identity, when this node defines one.
    #[must_use]
    pub fn anchor_node_ref(self) -> Option<consema_document::NodeRef> {
        self.owner.native.nodes[self.index]
            .anchor
            .as_ref()
            .map(|_| {
                self.owner.authority.node_ref(
                    u64::try_from(self.index).expect("parse limits keep node indexes in u64"),
                    consema_document::NodeRole::YamlAnchorDefinition,
                )
            })
    }

    /// Exact raw `&name` span, when this node defines an anchor.
    #[must_use]
    pub fn anchor_span(self) -> Option<consema_document::Span> {
        self.owner.native.nodes[self.index].anchor_span
    }

    /// Native node kind.
    #[must_use]
    pub fn kind(self) -> YamlNodeKind {
        match self.owner.native.nodes[self.index].content {
            NativeContent::Scalar(_) => YamlNodeKind::Scalar,
            NativeContent::Sequence(_) => YamlNodeKind::Sequence,
            NativeContent::Mapping(_) => YamlNodeKind::Mapping,
        }
    }

    /// Scalar facts, when this is a scalar node.
    #[must_use]
    pub fn scalar(self) -> Option<YamlScalar<'a>> {
        match &self.owner.native.nodes[self.index].content {
            NativeContent::Scalar(scalar) => Some(YamlScalar { scalar }),
            NativeContent::Sequence(_) | NativeContent::Mapping(_) => None,
        }
    }

    /// Ordered sequence association count.
    #[must_use]
    pub fn sequence_len(self) -> Option<usize> {
        match &self.owner.native.nodes[self.index].content {
            NativeContent::Sequence(items) => Some(items.len()),
            NativeContent::Scalar(_) | NativeContent::Mapping(_) => None,
        }
    }

    /// One exact sequence association.
    #[must_use]
    pub fn sequence_item(self, ordinal: usize) -> Option<YamlSequenceItem<'a>> {
        match &self.owner.native.nodes[self.index].content {
            NativeContent::Sequence(items) => items.get(ordinal).map(|item| YamlSequenceItem {
                owner: self.owner,
                item,
            }),
            NativeContent::Scalar(_) | NativeContent::Mapping(_) => None,
        }
    }

    /// Ordered mapping association count.
    #[must_use]
    pub fn mapping_len(self) -> Option<usize> {
        match &self.owner.native.nodes[self.index].content {
            NativeContent::Mapping(entries) => Some(entries.len()),
            NativeContent::Scalar(_) | NativeContent::Sequence(_) => None,
        }
    }

    /// One exact arbitrary key/value association.
    #[must_use]
    pub fn mapping_entry(self, ordinal: usize) -> Option<YamlMappingEntry<'a>> {
        match &self.owner.native.nodes[self.index].content {
            NativeContent::Mapping(entries) => entries.get(ordinal).map(|entry| YamlMappingEntry {
                owner: self.owner,
                entry,
            }),
            NativeContent::Scalar(_) | NativeContent::Sequence(_) => None,
        }
    }
}

/// Native scalar facts with exact decoded and canonical content.
#[derive(Clone, Copy, Debug)]
pub struct YamlScalar<'a> {
    scalar: &'a native::NativeScalar,
}

impl<'a> YamlScalar<'a> {
    /// Decoded YAML scalar content before schema canonicalization.
    #[must_use]
    pub fn decoded(self) -> &'a str {
        &self.scalar.decoded
    }

    /// Profile-defined canonical scalar content.
    #[must_use]
    pub fn canonical(self) -> &'a str {
        &self.scalar.canonical
    }

    /// Resolved scalar category.
    #[must_use]
    pub const fn kind(self) -> YamlScalarKind {
        self.scalar.kind
    }

    /// Source presentation style.
    #[must_use]
    pub const fn style(self) -> YamlScalarStyle {
        self.scalar.style
    }
}

/// One ordered sequence association.
#[derive(Clone, Copy, Debug)]
pub struct YamlSequenceItem<'a> {
    owner: &'a Document,
    item: &'a native::NativeSequenceItem,
}

impl<'a> YamlSequenceItem<'a> {
    /// Snapshot-bound association identity.
    #[must_use]
    pub fn node_ref(self) -> consema_document::NodeRef {
        self.owner.authority.node_ref(
            self.item.identity,
            consema_document::NodeRole::YamlSequenceElement,
        )
    }

    /// Exact raw element occurrence span, including an alias spelling when used.
    #[must_use]
    pub const fn span(self) -> consema_document::Span {
        self.item.span
    }

    /// Referenced representation node.
    #[must_use]
    pub const fn node(self) -> YamlNode<'a> {
        YamlNode {
            owner: self.owner,
            index: self.item.node,
        }
    }

    /// Alias occurrence that supplied this element edge, when present.
    #[must_use]
    pub fn alias(self) -> Option<YamlAlias<'a>> {
        self.item.alias.map(|ordinal| YamlAlias {
            owner: self.owner,
            alias: &self.owner.native.aliases[ordinal],
        })
    }
}

/// One ordered YAML mapping association with an arbitrary key node.
#[derive(Clone, Copy, Debug)]
pub struct YamlMappingEntry<'a> {
    owner: &'a Document,
    entry: &'a native::NativeMappingEntry,
}

impl<'a> YamlMappingEntry<'a> {
    /// Snapshot-bound association identity.
    #[must_use]
    pub fn node_ref(self) -> consema_document::NodeRef {
        self.owner.authority.node_ref(
            self.entry.identity,
            consema_document::NodeRole::YamlMappingEntry,
        )
    }

    /// Raw span from the key occurrence through the value occurrence.
    #[must_use]
    pub const fn span(self) -> consema_document::Span {
        self.entry.span
    }

    /// Arbitrary key node.
    #[must_use]
    pub const fn key(self) -> YamlNode<'a> {
        YamlNode {
            owner: self.owner,
            index: self.entry.key,
        }
    }

    /// Value node.
    #[must_use]
    pub const fn value(self) -> YamlNode<'a> {
        YamlNode {
            owner: self.owner,
            index: self.entry.value,
        }
    }

    /// Alias occurrence that supplied the key edge, when present.
    #[must_use]
    pub fn key_alias(self) -> Option<YamlAlias<'a>> {
        self.entry.key_alias.map(|ordinal| YamlAlias {
            owner: self.owner,
            alias: &self.owner.native.aliases[ordinal],
        })
    }

    /// Alias occurrence that supplied the value edge, when present.
    #[must_use]
    pub fn value_alias(self) -> Option<YamlAlias<'a>> {
        self.entry.value_alias.map(|ordinal| YamlAlias {
            owner: self.owner,
            alias: &self.owner.native.aliases[ordinal],
        })
    }
}

/// One alias serialization occurrence pointing at an existing representation node.
#[derive(Clone, Copy, Debug)]
pub struct YamlAlias<'a> {
    owner: &'a Document,
    alias: &'a native::NativeAlias,
}

impl<'a> YamlAlias<'a> {
    /// Snapshot-bound occurrence identity.
    #[must_use]
    pub fn node_ref(self) -> consema_document::NodeRef {
        self.owner
            .authority
            .node_ref(self.alias.identity, consema_document::NodeRole::YamlAlias)
    }

    /// Exact raw `*name` occurrence span.
    #[must_use]
    pub const fn span(self) -> consema_document::Span {
        self.alias.span
    }

    /// Exact alias name without `*`.
    #[must_use]
    pub fn name(self) -> &'a str {
        &self.alias.name
    }

    /// Shared target representation node; no expansion occurs.
    #[must_use]
    pub const fn target(self) -> YamlNode<'a> {
        YamlNode {
            owner: self.owner,
            index: self.alias.target,
        }
    }
}

fn validate_version_directives(
    text: &str,
    profile: YamlProfile,
) -> Result<(), FatalFormationFailure> {
    for (line_index, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        let Some(rest) = line.strip_prefix("%YAML") else {
            continue;
        };
        let Some(separator) = rest.chars().next() else {
            continue;
        };
        if !matches!(separator, ' ' | '\t') {
            continue;
        }
        let version = rest
            .trim_start_matches([' ', '\t'])
            .split([' ', '\t', '#'])
            .next()
            .unwrap_or_default();
        if version != profile.accepted_version() {
            let mut diagnostic = Diagnostic::new(
                "yaml.profile.version-directive@1",
                DiagnosticCategory::Conformance,
                DiagnosticSeverity::Error,
                None,
                0,
            );
            diagnostic
                .arguments
                .insert("selected_profile".to_owned(), profile.id().id().to_owned());
            diagnostic
                .arguments
                .insert("declared_version".to_owned(), version.to_owned());
            diagnostic
                .arguments
                .insert("line".to_owned(), (line_index + 1).to_string());
            return Err(FatalFormationFailure::from_diagnostic(diagnostic));
        }
    }
    Ok(())
}

fn backend_failure(error: BackendError, source: &SourceSnapshot) -> FatalFormationFailure {
    match error {
        BackendError::ResourceLimit {
            name,
            observed,
            limit,
        } => FatalFormationFailure::resource_limit(name, observed, limit),
        BackendError::Syntax { scalar_offset } => {
            let location = source
                .raw_byte_at(DecodedOffset::UnicodeScalar(scalar_offset))
                .ok()
                .map(|byte| DiagnosticLocation {
                    snapshot: None,
                    start_byte: byte as u64,
                    end_byte: byte as u64,
                });
            FatalFormationFailure::from_diagnostic(Diagnostic::new(
                "yaml.parse.syntax@1",
                DiagnosticCategory::Syntax,
                DiagnosticSeverity::Error,
                location,
                0,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multidocument_stream_is_profile_bound() {
        let source = b"%YAML 1.2\n---\na: &x [1, *x]\n---\nb: |\n  text\n";
        let document = parse(
            source.as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.render(), source);
        assert_eq!(document.profile().id(), "yaml.1.2-core");
        assert_eq!(document.document_count(), 2);
    }

    #[test]
    fn utf16_bom_source_is_retained_and_location_aware() {
        let source = [0xff, 0xfe, b'a', 0, b':', 0, b' ', 0, b'1', 0];
        let document = parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default()).unwrap();
        assert_eq!(document.render(), &source);
        assert_eq!(document.source().decoded_text(), Some("\u{feff}a: 1"));
        assert_eq!(document.document_count(), 1);
        assert_eq!(
            document.lossless_structural_index().pieces()[0]
                .span()
                .end_byte(),
            2
        );
        assert_eq!(document.lossless_syntax_kinds()[0], YamlSyntaxKind::Bom);
    }

    #[test]
    fn profile_directives_are_not_silently_cross_loaded() {
        let error = parse(
            b"%YAML 1.1\n---\nyes\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            error.diagnostics()[0].code,
            "yaml.profile.version-directive@1"
        );

        let document = parse(
            b"%YAML 1.1\n---\nyes\n".as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.profile().id(), "yaml.1.1-compat");

        let commented = parse(
            b"%YAML\t1.2 # profile\n---\nx\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(commented.document_count(), 1);
    }

    #[test]
    fn syntax_and_resource_failures_form_no_document() {
        let syntax = parse(
            b"[unterminated".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(syntax.diagnostics()[0].code, "yaml.parse.syntax@1");

        let limited = parse(
            b"[[x]]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits {
                max_nesting_depth: 1,
                ..ParseLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(limited.diagnostics()[0].code, "core.parse.resource-limit@1");
    }

    #[test]
    fn aliases_compose_to_shared_cycles_without_expansion() {
        let document = parse(
            b"&self [*self]\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        assert_eq!(root.anchor(), Some("self"));
        assert_eq!(root.sequence_len(), Some(1));
        assert_eq!(
            root.sequence_item(0).unwrap().node().node_ref(),
            root.node_ref()
        );
        assert_eq!(document.alias_count(), 1);
        assert_eq!(document.alias(0).unwrap().name(), "self");
        assert_eq!(
            document.alias(0).unwrap().target().node_ref(),
            root.node_ref()
        );

        let graph = document.project_graph().unwrap();
        let graph_root = graph.roots()[0];
        assert_eq!(
            graph.node(graph_root).unwrap().sequence_items(),
            Some([graph_root].as_slice())
        );
    }

    #[test]
    fn native_handles_retain_exact_anchor_alias_and_association_spans() {
        let source = b"---\nroot: &node [one, *node]\n";
        let document = parse(
            source.as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            document.stream_node_ref().role(),
            consema_document::NodeRole::YamlStream
        );
        assert_eq!(document.stream_span().end_byte(), source.len());
        let yaml_document = document.document(0).unwrap();
        assert_eq!(
            yaml_document.node_ref().role(),
            consema_document::NodeRole::YamlDocument
        );
        let entry = yaml_document.root().mapping_entry(0).unwrap();
        let sequence = entry.value();
        let anchor_span = sequence.anchor_span().unwrap();
        assert_eq!(
            &source[anchor_span.start_byte()..anchor_span.end_byte()],
            b"&node"
        );
        assert_eq!(
            sequence.anchor_node_ref().unwrap().role(),
            consema_document::NodeRole::YamlAnchorDefinition
        );
        let alias = document.alias(0).unwrap();
        assert_eq!(
            &source[alias.span().start_byte()..alias.span().end_byte()],
            b"*node"
        );
        assert_eq!(alias.target().node_ref(), sequence.node_ref());
        let element = sequence.sequence_item(1).unwrap();
        assert_eq!(element.span(), alias.span());
        assert_eq!(element.alias().unwrap().node_ref(), alias.node_ref());
        assert_eq!(
            element.node_ref().role(),
            consema_document::NodeRole::YamlSequenceElement
        );
    }

    #[test]
    fn mappings_keep_arbitrary_keys_duplicates_and_order() {
        let document = parse(
            b"? [a, b]\n: one\n? [a, b]\n: two\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        assert_eq!(root.mapping_len(), Some(2));
        assert_eq!(
            root.mapping_entry(0).unwrap().key().kind(),
            YamlNodeKind::Sequence
        );
        assert_ne!(
            root.mapping_entry(0).unwrap().key().node_ref(),
            root.mapping_entry(1).unwrap().key().node_ref()
        );
        assert_eq!(
            root.mapping_entry(0)
                .unwrap()
                .value()
                .scalar()
                .unwrap()
                .decoded(),
            "one"
        );
        assert_eq!(document.project_graph().unwrap().node_count(), 9);
    }

    #[test]
    fn profiles_resolve_plain_scalars_but_never_construct_custom_tags() {
        let source = b"flag: yes\nnumber: 017\n";
        let core = parse(
            source.as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let compat = parse(
            source.as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        let core_root = core.document(0).unwrap().root();
        let compat_root = compat.document(0).unwrap().root();
        assert_eq!(
            core_root
                .mapping_entry(0)
                .unwrap()
                .value()
                .scalar()
                .unwrap()
                .kind(),
            YamlScalarKind::String
        );
        assert_eq!(
            compat_root
                .mapping_entry(0)
                .unwrap()
                .value()
                .scalar()
                .unwrap()
                .canonical(),
            "true"
        );
        assert_eq!(
            compat_root
                .mapping_entry(1)
                .unwrap()
                .value()
                .scalar()
                .unwrap()
                .canonical(),
            "15"
        );

        let custom = parse(
            b"!application/object payload\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = custom.document(0).unwrap().root();
        assert_eq!(root.tag(), "!application/object");
        assert_eq!(root.scalar().unwrap().kind(), YamlScalarKind::Custom);
        assert!(matches!(
            custom.project_graph(),
            Err(GraphProjectionError::UnsupportedTag(tag)) if tag == "!application/object"
        ));
    }

    #[test]
    fn explicit_standard_tags_are_kind_and_grammar_checked() {
        let invalid_scalar = parse(
            b"!!int nope\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            invalid_scalar.diagnostics()[0].code,
            "yaml.scalar.invalid-explicit-tag@1"
        );

        let invalid_kind = parse(
            b"!!seq {a: b}\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            invalid_kind.diagnostics()[0].code,
            "yaml.tag.kind-mismatch@1"
        );
    }

    #[test]
    fn standard_repository_tags_survive_graph_projection_without_constructors() {
        let document = parse(
            b"set: !!set {a: null}\nbinary: !!binary SGVsbG8=\ntime: !!timestamp 2001-12-15\n"
                .as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        let root = document.document(0).unwrap().root();
        assert_eq!(
            root.mapping_entry(0).unwrap().value().tag(),
            "tag:yaml.org,2002:set"
        );
        assert_eq!(
            root.mapping_entry(1)
                .unwrap()
                .value()
                .scalar()
                .unwrap()
                .canonical(),
            "SGVsbG8="
        );
        let graph = document.project_graph().unwrap();
        assert!(
            graph
                .nodes()
                .any(|(_, node)| node.tag() == "tag:yaml.org,2002:set")
        );
        assert!(
            graph
                .nodes()
                .any(|(_, node)| node.tag() == "tag:yaml.org,2002:binary")
        );

        assert!(
            parse(
                b"!!set [a]".as_slice(),
                YamlProfile::Yaml11CompatV1,
                ParseLimits::default(),
            )
            .is_err()
        );
    }
}
