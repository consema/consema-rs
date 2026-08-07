//! Immutable namespace-aware native XML tree (RFC 0012 §4-7).
//!
//! The Document retains prolog order, one document element, epilog order,
//! and every exact source span. An XML element is not a JSON Object:
//! attributes and child elements are never merged into one map, mixed
//! content keeps its source order, and namespace prefixes stay source
//! spelling rather than expanded names.

use crate::namespace::{ExpandedName, NamespaceError, NamespaceScope, QName};
use consema_core::Diagnostic;
use consema_document::{
    DocumentAuthority, FormatFamilyId, FormationStatus, LosslessStructuralIndex, NodeRef, NodeRole,
    ProfileId, SnapshotIdentity, SourceSnapshot, Span,
};
use std::sync::Arc;

/// One lossless XML syntax category (RFC 0012 §7).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum XmlSyntaxKind {
    /// Unicode byte-order mark.
    Bom,
    /// Horizontal whitespace.
    Whitespace,
    /// Line break.
    LineBreak,
    /// `<?xml` declaration opening.
    DeclarationOpen,
    /// Declaration pseudo-attribute name.
    DeclarationName,
    /// Declaration pseudo-attribute value.
    DeclarationValue,
    /// `?>` declaration closing.
    DeclarationClose,
    /// `<!DOCTYPE` opening.
    DoctypeOpen,
    /// DOCTYPE name.
    DoctypeName,
    /// Admitted internal DTD subset markup.
    DtdMarkup,
    /// `>` DOCTYPE closing.
    DoctypeClose,
    /// `<` or `</` tag opening.
    TagOpen,
    /// `>` tag closing.
    TagClose,
    /// `/>` empty-element closing.
    EmptyElementClose,
    /// `</` end-tag opening.
    EndTagOpen,
    /// QName prefix spelling.
    Prefix,
    /// QName local-name spelling.
    LocalName,
    /// QName colon.
    Colon,
    /// Attribute name.
    AttributeName,
    /// `=` assignment.
    Equals,
    /// Attribute value quote.
    Quote,
    /// Attribute value content.
    AttributeValue,
    /// `xmlns` or `xmlns:p` declaration.
    NamespaceDeclaration,
    /// Character data without markup.
    Text,
    /// General or predefined entity reference.
    EntityReference,
    /// Decimal or hexadecimal character reference.
    CharacterReference,
    /// `<![CDATA[` opening.
    CdataOpen,
    /// CDATA content.
    CdataText,
    /// `]]>` CDATA closing.
    CdataClose,
    /// `<!--` comment opening.
    CommentOpen,
    /// Comment content.
    CommentText,
    /// `-->` comment closing.
    CommentClose,
    /// `<?` PI opening.
    ProcessingInstructionOpen,
    /// PI target.
    ProcessingInstructionTarget,
    /// PI content.
    ProcessingInstructionContent,
    /// `?>` PI closing.
    ProcessingInstructionClose,
    /// Recovered error region.
    ErrorRegion,
}

/// One lexical QName with its source-derived facts (RFC 0012 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QNameFacts {
    /// Original prefix spelling, when present.
    pub prefix: Option<Arc<str>>,
    /// Local name.
    pub local: Arc<str>,
    /// Complete QName span.
    pub span: Span,
    /// Prefix span, when present.
    pub prefix_span: Option<Span>,
    /// Local-name span.
    pub local_span: Span,
}

impl QNameFacts {
    /// Resolves this QName against an element's in-scope scope.
    #[must_use]
    pub fn qname(&self) -> QName {
        QName {
            prefix: self.prefix.clone(),
            local: Arc::clone(&self.local),
        }
    }
}

impl ReferenceFragment {
    /// Exact source span of this fragment.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Literal { span, .. }
            | Self::CharacterReference { span, .. }
            | Self::PredefinedEntity { span, .. }
            | Self::GeneralEntity { span, .. } => *span,
        }
    }
}

/// One ordered text or attribute-value fragment (RFC 0012 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceFragment {
    /// Literal character data.
    Literal {
        /// Exact source span.
        span: Span,
        /// Decoded literal text.
        text: Arc<str>,
    },
    /// Decimal or hexadecimal character reference.
    CharacterReference {
        /// Exact source span of `&#…;`.
        span: Span,
        /// Resolved legal XML character.
        resolved: char,
    },
    /// One of the five predefined entity references.
    PredefinedEntity {
        /// Exact source span of `&…;`.
        span: Span,
        /// Entity name.
        name: Arc<str>,
        /// Replacement character data.
        resolved: Arc<str>,
    },
    /// An admitted internal general entity reference.
    GeneralEntity {
        /// Exact source span of `&…;`.
        span: Span,
        /// Entity name.
        name: Arc<str>,
        /// Fully resolved replacement text.
        resolved: Arc<str>,
        /// Span of the declaring `<!ENTITY …>`.
        declaration_span: Span,
    },
}

/// One XML namespace declaration association (RFC 0012 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlNamespaceBindingData {
    /// Document-wide binding ordinal for stable identity.
    pub ordinal: u64,
    /// `xmlns="…"` or `xmlns:p="…"` span.
    pub span: Span,
    /// Bound prefix; `None` is the default namespace.
    pub prefix: Option<Arc<str>>,
    /// Namespace URI value span.
    pub uri_span: Span,
    /// Namespace URI.
    pub uri: Arc<str>,
}

/// One XML attribute association (RFC 0012 §5-6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlAttributeData {
    /// Document-wide attribute ordinal for stable identity.
    pub ordinal: u64,
    /// Whole attribute span.
    pub span: Span,
    /// Lexical QName facts.
    pub qname: QNameFacts,
    /// Resolved expanded name; `None` when a namespace error kept the name
    /// unprovable.
    pub expanded: Option<ExpandedName>,
    /// The namespace resolution failure, when the name could not be proven.
    pub namespace_error: Option<NamespaceError>,
    /// Whether the value used single or double quotes.
    pub single_quote: bool,
    /// Exact value span between the quotes; empty for an empty value.
    pub value_span: Span,
    /// Ordered raw value fragments.
    pub fragments: Arc<[ReferenceFragment]>,
    /// XML 1.0 CDATA-normalized semantic value.
    pub normalized_value: Arc<str>,
}

/// One text occurrence with ordered fragments (RFC 0012 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlTextData {
    /// Document-wide text ordinal for stable identity.
    pub ordinal: u64,
    /// Exact source span.
    pub span: Span,
    /// Ordered fragments; adjacent literals are not merged across markup.
    pub fragments: Arc<[ReferenceFragment]>,
}

/// One CDATA occurrence (RFC 0012 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlCdataData {
    /// Document-wide ordinal for stable identity.
    pub ordinal: u64,
    /// `![CDATA[…]]>` span.
    pub span: Span,
    /// Content text span.
    pub text_span: Span,
    /// Content text; never entity-expanded.
    pub text: Arc<str>,
}

/// One comment occurrence (RFC 0012 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlCommentData {
    /// Document-wide ordinal for stable identity.
    pub ordinal: u64,
    /// `<!--…-->` span.
    pub span: Span,
    /// Content text span.
    pub text_span: Span,
    /// Content text; never entity-expanded.
    pub text: Arc<str>,
}

/// One processing instruction (RFC 0012 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlPiData {
    /// Document-wide ordinal for stable identity.
    pub ordinal: u64,
    /// `<?…?>` span.
    pub span: Span,
    /// Target span.
    pub target_span: Span,
    /// Target; cannot compare case-insensitively equal to `xml`.
    pub target: Arc<str>,
    /// Content span and text, when present; never entity-expanded.
    pub content: Option<(Span, Arc<str>)>,
}

/// One recovered error region (RFC 0012 §4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlErrorRegionData {
    /// Document-wide ordinal for stable identity.
    pub ordinal: u64,
    /// Recovered error span.
    pub span: Span,
}

/// One element occurrence (RFC 0012 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlElementData {
    /// Arena index for stable identity.
    pub index: usize,
    /// Full start-tag span, or the whole empty-element span.
    pub span: Span,
    /// Lexical QName facts.
    pub qname: QNameFacts,
    /// Resolved expanded name; `None` when a namespace error kept the name
    /// unprovable.
    pub expanded: Option<ExpandedName>,
    /// The namespace resolution failure, when the name could not be proven.
    pub namespace_error: Option<NamespaceError>,
    /// Immutable ancestry-derived in-scope namespace chain.
    pub scope: NamespaceScope,
    /// Ordered namespace declarations on this element.
    pub namespaces: Vec<XmlNamespaceBindingData>,
    /// Ordered attributes, excluding namespace declarations.
    pub attributes: Vec<XmlAttributeData>,
    /// Ordered child content arena indices; never sorted by type.
    pub children: Vec<usize>,
}

/// One child content occurrence (RFC 0012 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XmlContent {
    /// Child element.
    Element(XmlElementData),
    /// Text occurrence.
    Text(XmlTextData),
    /// CDATA occurrence.
    Cdata(XmlCdataData),
    /// Comment occurrence.
    Comment(XmlCommentData),
    /// Processing instruction.
    ProcessingInstruction(XmlPiData),
    /// Recovered error region.
    ErrorRegion(XmlErrorRegionData),
}

impl XmlContent {
    /// Exact source span of this occurrence.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Element(data) => data.span,
            Self::Text(data) => data.span,
            Self::Cdata(data) => data.span,
            Self::Comment(data) => data.span,
            Self::ProcessingInstruction(data) => data.span,
            Self::ErrorRegion(data) => data.span,
        }
    }
}

/// One prolog or epilog occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XmlPrologItem {
    /// The XML declaration, only in the prolog.
    Declaration(XmlDeclarationData),
    /// DOCTYPE occurrence, only in the prolog.
    Doctype(XmlDoctypeData),
    /// Processing instruction.
    ProcessingInstruction(XmlPiData),
    /// Comment.
    Comment(XmlCommentData),
    /// Byte-order mark trivia.
    Bom(Span),
    /// Whitespace trivia.
    Whitespace(Span),
}

/// XML declaration facts (RFC 0012 §2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlDeclarationData {
    /// `<?xml …?>` span.
    pub span: Span,
    /// Version pseudo-attribute span.
    pub version_span: Span,
    /// Version; exactly `1.0`.
    pub version: Arc<str>,
    /// Optional encoding pseudo-attribute span and value.
    pub encoding: Option<(Span, Arc<str>)>,
    /// Optional standalone pseudo-attribute span and value.
    pub standalone: Option<(Span, bool)>,
}

/// One admitted internal general entity declaration (RFC 0012 §3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityDeclarationData {
    /// `<!ENTITY …>` span.
    pub span: Span,
    /// Entity name.
    pub name: Arc<str>,
    /// Replacement value span.
    pub replacement_span: Span,
    /// Raw replacement text.
    pub replacement: Arc<str>,
}

/// DOCTYPE facts (RFC 0012 §3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlDoctypeData {
    /// `<!DOCTYPE …>` span.
    pub span: Span,
    /// Root-name QName facts.
    pub name: QNameFacts,
    /// Ordered admitted internal general entity declarations.
    pub entities: Arc<[EntityDeclarationData]>,
    /// Whether an excluded external/validation construct forced recovery.
    pub recovered: bool,
}

/// The immutable XML document (RFC 0012 §4).
#[derive(Clone, Debug)]
pub struct Document {
    source: Arc<SourceSnapshot>,
    authority: DocumentAuthority,
    status: FormationStatus,
    declaration: Option<XmlDeclarationData>,
    doctype: Option<XmlDoctypeData>,
    prolog: Vec<XmlPrologItem>,
    root: Option<usize>,
    epilog: Vec<XmlPrologItem>,
    syntax: Option<LosslessStructuralIndex>,
    syntax_kinds: Vec<XmlSyntaxKind>,
    diagnostics: Vec<Diagnostic>,
    nodes: Vec<XmlContent>,
    /// Arena index → parent element arena index; `None` for the root element
    /// and for orphaned content (dropped or recovered nodes).
    parent_of: Vec<Option<usize>>,
    pub(crate) parse_limits: crate::XmlParseLimits,
}

/// Completed formation facts handed to [`Document::from_formed`].
pub(crate) struct Formed {
    pub(crate) source: Arc<SourceSnapshot>,
    pub(crate) status: FormationStatus,
    pub(crate) declaration: Option<XmlDeclarationData>,
    pub(crate) doctype: Option<XmlDoctypeData>,
    pub(crate) prolog: Vec<XmlPrologItem>,
    pub(crate) root: Option<usize>,
    pub(crate) epilog: Vec<XmlPrologItem>,
    pub(crate) syntax: Option<LosslessStructuralIndex>,
    pub(crate) syntax_kinds: Vec<XmlSyntaxKind>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) nodes: Vec<XmlContent>,
    pub(crate) parent_of: Vec<Option<usize>>,
    pub(crate) parse_limits: crate::XmlParseLimits,
}

impl Document {
    /// Creates a document from completed formation facts.
    #[must_use]
    pub(crate) fn from_formed(authority: DocumentAuthority, formed: Formed) -> Self {
        Self {
            authority,
            source: formed.source,
            status: formed.status,
            declaration: formed.declaration,
            doctype: formed.doctype,
            prolog: formed.prolog,
            root: formed.root,
            epilog: formed.epilog,
            syntax: formed.syntax,
            syntax_kinds: formed.syntax_kinds,
            diagnostics: formed.diagnostics,
            nodes: formed.nodes,
            parent_of: formed.parent_of,
            parse_limits: formed.parse_limits,
        }
    }

    /// Formation status.
    #[must_use]
    pub const fn status(&self) -> FormationStatus {
        self.status
    }

    /// Complete or explicitly recovered formation state.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        self.status()
    }

    /// Immutable raw source.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Exact original bytes; unmodified rendering is byte-exact.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Exhaustive ordered lossless syntax coverage.
    #[must_use]
    pub fn lossless_structural_index(&self) -> Option<&LosslessStructuralIndex> {
        self.syntax.as_ref()
    }

    /// Parallel format-owned syntax kind for every structural piece.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[XmlSyntaxKind] {
        &self.syntax_kinds
    }

    /// Snapshot-bound identity authority for issuing query handles.
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        &self.authority
    }

    /// Ordered diagnostics from formation.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The XML declaration, when present.
    #[must_use]
    pub fn declaration(&self) -> Option<&XmlDeclarationData> {
        self.declaration.as_ref()
    }

    /// The DOCTYPE occurrence, when present.
    #[must_use]
    pub fn doctype(&self) -> Option<&XmlDoctypeData> {
        self.doctype.as_ref()
    }

    /// Ordered prolog items before the document element.
    #[must_use]
    pub fn prolog(&self) -> &[XmlPrologItem] {
        &self.prolog
    }

    /// Ordered epilog items after the document element.
    #[must_use]
    pub fn epilog(&self) -> &[XmlPrologItem] {
        &self.epilog
    }

    /// The one document element, when formation proved it.
    #[must_use]
    pub fn root(&self) -> Option<XmlElement<'_>> {
        self.root.map(|index| XmlElement { owner: self, index })
    }

    /// All arena nodes; child content of every element is reachable here.
    #[must_use]
    pub fn nodes(&self) -> &[XmlContent] {
        &self.nodes
    }

    /// Snapshot identity.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.authority.identity()
    }

    /// Parent element arena index of one arena node; `None` for the root
    /// element and for orphaned content.
    #[must_use]
    pub(crate) fn parent_of(&self, index: usize) -> Option<usize> {
        self.parent_of.get(index).copied().flatten()
    }

    /// XML format family contract.
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("xml", 1)
    }

    /// Stable profile identifier under the common facade name.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        ProfileId::new("xml.1.0-safe", 1)
    }

    /// Snapshot-bound document handle.
    #[must_use]
    pub fn node_ref(&self) -> NodeRef {
        self.authority.node_ref(0, NodeRole::XmlDocument)
    }

    /// Snapshot-bound identity of one ordinal-scoped occurrence.
    #[must_use]
    pub fn occurrence_node_ref(&self, ordinal: u64, role: NodeRole) -> NodeRef {
        self.authority.node_ref(ordinal, role)
    }
}

/// Snapshot-bound view of the whole document.
#[derive(Clone, Copy, Debug)]
pub struct XmlDocument<'a> {
    owner: &'a Document,
}

impl<'a> XmlDocument<'a> {
    /// Creates a view from the owned document.
    #[must_use]
    pub const fn new(owner: &'a Document) -> Self {
        Self { owner }
    }

    /// Snapshot-bound document identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.owner.node_ref()
    }

    /// Exact raw document span.
    #[must_use]
    pub fn span(self) -> Span {
        self.owner
            .authority
            .span(0, self.owner.source.len())
            .expect("document span is always valid")
    }

    /// The document element.
    #[must_use]
    pub fn root(self) -> Option<XmlElement<'a>> {
        self.owner.root()
    }

    /// Formation status.
    #[must_use]
    pub const fn status(self) -> FormationStatus {
        self.owner.status
    }
}

/// Snapshot-bound element handle.
#[derive(Clone, Copy, Debug)]
pub struct XmlElement<'a> {
    owner: &'a Document,
    index: usize,
}

impl<'a> XmlElement<'a> {
    /// Snapshot-bound stable identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.owner
            .authority
            .node_ref(self.index as u64, NodeRole::XmlElement)
    }

    /// Full start-tag or empty-element span.
    #[must_use]
    pub fn span(self) -> Span {
        self.data().span
    }

    /// Lexical QName facts.
    #[must_use]
    pub fn qname(self) -> &'a QNameFacts {
        &self.data().qname
    }

    /// Resolved expanded name, when the namespace binding could be proven.
    #[must_use]
    pub fn expanded(self) -> Option<&'a ExpandedName> {
        self.data().expanded.as_ref()
    }

    /// Ordered namespace declarations on this element.
    #[must_use]
    pub fn namespace_bindings(self) -> &'a [XmlNamespaceBindingData] {
        &self.data().namespaces
    }

    /// Ordered attributes, excluding namespace declarations.
    #[must_use]
    pub fn attributes(self) -> &'a [XmlAttributeData] {
        &self.data().attributes
    }

    /// Ordered child content occurrences; mixed-content order is retained.
    #[must_use = "child content occurrences must be consumed or dropped explicitly"]
    pub fn children(self) -> impl Iterator<Item = XmlContentItem<'a>> + 'a {
        let owner = self.owner;
        self.data()
            .children
            .iter()
            .map(move |&index| XmlContentItem { owner, index })
    }

    /// Whether the element has no child content.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.data().children.is_empty()
    }

    pub(crate) fn data(self) -> &'a XmlElementData {
        let XmlContent::Element(data) = &self.owner.nodes[self.index] else {
            unreachable!("element handle always points at element arena data")
        };
        data
    }
}

/// One borrowed child content occurrence.
#[derive(Clone, Copy, Debug)]
pub struct XmlContentItem<'a> {
    owner: &'a Document,
    index: usize,
}

impl<'a> XmlContentItem<'a> {
    /// Snapshot-bound stable identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        let role = match &self.owner.nodes[self.index] {
            XmlContent::Element(_) => NodeRole::XmlElement,
            XmlContent::Text(_) => NodeRole::XmlText,
            XmlContent::Cdata(_) => NodeRole::XmlCdata,
            XmlContent::Comment(_) => NodeRole::XmlComment,
            XmlContent::ProcessingInstruction(_) => NodeRole::XmlProcessingInstruction,
            XmlContent::ErrorRegion(_) => NodeRole::XmlErrorRegion,
        };
        self.owner.authority.node_ref(self.index as u64, role)
    }

    /// Exact source span.
    #[must_use]
    pub fn span(self) -> Span {
        match &self.owner.nodes[self.index] {
            XmlContent::Element(data) => data.span,
            XmlContent::Text(data) => data.span,
            XmlContent::Cdata(data) => data.span,
            XmlContent::Comment(data) => data.span,
            XmlContent::ProcessingInstruction(data) => data.span,
            XmlContent::ErrorRegion(data) => data.span,
        }
    }

    /// Element content, when this is an element occurrence.
    #[must_use]
    pub fn element(self) -> Option<XmlElement<'a>> {
        match &self.owner.nodes[self.index] {
            XmlContent::Element(_) => Some(XmlElement {
                owner: self.owner,
                index: self.index,
            }),
            _ => None,
        }
    }

    /// Text occurrence data, when this is a text occurrence.
    #[must_use]
    pub fn text(self) -> Option<&'a XmlTextData> {
        match &self.owner.nodes[self.index] {
            XmlContent::Text(data) => Some(data),
            _ => None,
        }
    }

    /// CDATA occurrence data, when present.
    #[must_use]
    pub fn cdata(self) -> Option<&'a XmlCdataData> {
        match &self.owner.nodes[self.index] {
            XmlContent::Cdata(data) => Some(data),
            _ => None,
        }
    }

    /// Comment occurrence data, when present.
    #[must_use]
    pub fn comment(self) -> Option<&'a XmlCommentData> {
        match &self.owner.nodes[self.index] {
            XmlContent::Comment(data) => Some(data),
            _ => None,
        }
    }

    /// Processing-instruction data, when present.
    #[must_use]
    pub fn processing_instruction(self) -> Option<&'a XmlPiData> {
        match &self.owner.nodes[self.index] {
            XmlContent::ProcessingInstruction(data) => Some(data),
            _ => None,
        }
    }
}

/// Semantic concatenation of one text occurrence after XML line-end
/// normalization to LF (RFC 0012 §6).
#[must_use]
pub fn text_semantic(text: &XmlTextData) -> String {
    let mut out = String::new();
    for fragment in text.fragments.iter() {
        match fragment {
            ReferenceFragment::Literal { text, .. } => {
                push_normalized(&mut out, text);
            }
            ReferenceFragment::CharacterReference { resolved, .. } => out.push(*resolved),
            ReferenceFragment::PredefinedEntity { resolved, .. }
            | ReferenceFragment::GeneralEntity { resolved, .. } => {
                push_normalized(&mut out, resolved);
            }
        }
    }
    out
}

fn push_normalized(out: &mut String, text: &str) {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // XML 1.0 line-end normalization: CRLF and CR become LF.
            '\r' => {
                out.push('\n');
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
}

impl XmlSyntaxKind {
    /// Stable kind name used by the lossless syntax query protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "bom",
            Self::Whitespace => "whitespace",
            Self::LineBreak => "line-break",
            Self::DeclarationOpen => "declaration-open",
            Self::DeclarationName => "declaration-name",
            Self::DeclarationValue => "declaration-value",
            Self::DeclarationClose => "declaration-close",
            Self::DoctypeOpen => "doctype-open",
            Self::DoctypeName => "doctype-name",
            Self::DtdMarkup => "dtd-markup",
            Self::DoctypeClose => "doctype-close",
            Self::TagOpen => "tag-open",
            Self::TagClose => "tag-close",
            Self::EmptyElementClose => "empty-element-close",
            Self::EndTagOpen => "end-tag-open",
            Self::Prefix => "prefix",
            Self::LocalName => "local-name",
            Self::Colon => "colon",
            Self::AttributeName => "attribute-name",
            Self::Equals => "equals",
            Self::Quote => "quote",
            Self::AttributeValue => "attribute-value",
            Self::NamespaceDeclaration => "namespace-declaration",
            Self::Text => "text",
            Self::EntityReference => "entity-reference",
            Self::CharacterReference => "character-reference",
            Self::CdataOpen => "cdata-open",
            Self::CdataText => "cdata-text",
            Self::CdataClose => "cdata-close",
            Self::CommentOpen => "comment-open",
            Self::CommentText => "comment-text",
            Self::CommentClose => "comment-close",
            Self::ProcessingInstructionOpen => "processing-instruction-open",
            Self::ProcessingInstructionTarget => "processing-instruction-target",
            Self::ProcessingInstructionContent => "processing-instruction-content",
            Self::ProcessingInstructionClose => "processing-instruction-close",
            Self::ErrorRegion => "error-region",
        }
    }

    /// Resolves a stable kind name from the lossless syntax query protocol.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "bom" => Self::Bom,
            "whitespace" => Self::Whitespace,
            "line-break" => Self::LineBreak,
            "declaration-open" => Self::DeclarationOpen,
            "declaration-name" => Self::DeclarationName,
            "declaration-value" => Self::DeclarationValue,
            "declaration-close" => Self::DeclarationClose,
            "doctype-open" => Self::DoctypeOpen,
            "doctype-name" => Self::DoctypeName,
            "dtd-markup" => Self::DtdMarkup,
            "doctype-close" => Self::DoctypeClose,
            "tag-open" => Self::TagOpen,
            "tag-close" => Self::TagClose,
            "empty-element-close" => Self::EmptyElementClose,
            "end-tag-open" => Self::EndTagOpen,
            "prefix" => Self::Prefix,
            "local-name" => Self::LocalName,
            "colon" => Self::Colon,
            "attribute-name" => Self::AttributeName,
            "equals" => Self::Equals,
            "quote" => Self::Quote,
            "attribute-value" => Self::AttributeValue,
            "namespace-declaration" => Self::NamespaceDeclaration,
            "text" => Self::Text,
            "entity-reference" => Self::EntityReference,
            "character-reference" => Self::CharacterReference,
            "cdata-open" => Self::CdataOpen,
            "cdata-text" => Self::CdataText,
            "cdata-close" => Self::CdataClose,
            "comment-open" => Self::CommentOpen,
            "comment-text" => Self::CommentText,
            "comment-close" => Self::CommentClose,
            "processing-instruction-open" => Self::ProcessingInstructionOpen,
            "processing-instruction-target" => Self::ProcessingInstructionTarget,
            "processing-instruction-content" => Self::ProcessingInstructionContent,
            "processing-instruction-close" => Self::ProcessingInstructionClose,
            "error-region" => Self::ErrorRegion,
            _ => return None,
        })
    }
}
