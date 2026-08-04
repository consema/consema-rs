//! Lossless `json.strict@1` and `jsonc.bounded@1` documents.

mod edit;
mod materialization;
mod operation_registry;
mod parser;
mod projection;
mod query;

use consema_core::{BigInteger, Decimal, Diagnostic};
use consema_document::{
    DocumentAuthority, FatalFormationFailure, FormatFamilyId, FormationStatus,
    LosslessStructuralIndex, NodeRef, NodeRole, ParseLimits, ProfileId, SnapshotIdentity,
    SourceSnapshot, Span,
};
use std::sync::Arc;

pub use edit::{
    EditCommit, EditFailure, EditTransaction, EditTransactionBuilder, RepresentationPolicy,
    ScalarReplacement,
};
pub use materialization::materialize;
pub use operation_registry::format_operation_registry;
pub use projection::{
    CompleteProjection, DuplicateKeyPolicy, FailedProjectionAttempt, Fidelity, ProjectedLocation,
    ProjectionEvent, ProjectionEventKind, ProjectionFailure, ProjectionLimits,
    ProjectionPolicyScope, ProjectionReport, ProjectionRequest, ProjectionRequestBuilder,
    ProjectionResult, ProjectionTarget, ProvenanceEntry, ProvenanceMap, ProvenanceRelation,
    SourceOrigin,
};
pub use query::{
    JsonMatch, JsonSyntaxMatch, execute_json_query, execute_json_query_cursor,
    execute_json_syntax_query, execute_json_syntax_query_cursor,
};

/// Frozen JSON language profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonProfile {
    /// RFC-style strict JSON plus the baseline duplicate/BOM diagnostics.
    StrictV1,
    /// Strict JSON plus comments, trailing commas, and optional leading BOM.
    JsoncBoundedV1,
}

/// Closed JSON/JSONC v1 lossless syntax-piece classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonSyntaxKind {
    /// Leading UTF-8 byte-order mark.
    Bom,
    /// JSON whitespace.
    Whitespace,
    /// `//` comment.
    LineComment,
    /// Closed `/* ... */` comment.
    BlockComment,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// `[`.
    LeftBracket,
    /// `]`.
    RightBracket,
    /// `:`.
    Colon,
    /// `,`.
    Comma,
    /// Complete string token.
    String,
    /// Valid JSON number token.
    Number,
    /// `true`.
    True,
    /// `false`.
    False,
    /// `null`.
    Null,
    /// Bytes retained after bounded lexical recovery.
    ErrorRegion,
}

impl JsonSyntaxKind {
    /// Stable query and protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "Bom",
            Self::Whitespace => "Whitespace",
            Self::LineComment => "LineComment",
            Self::BlockComment => "BlockComment",
            Self::LeftBrace => "LeftBrace",
            Self::RightBrace => "RightBrace",
            Self::LeftBracket => "LeftBracket",
            Self::RightBracket => "RightBracket",
            Self::Colon => "Colon",
            Self::Comma => "Comma",
            Self::String => "String",
            Self::Number => "Number",
            Self::True => "True",
            Self::False => "False",
            Self::Null => "Null",
            Self::ErrorRegion => "ErrorRegion",
        }
    }

    /// Resolves one exact stable kind name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Bom" => Some(Self::Bom),
            "Whitespace" => Some(Self::Whitespace),
            "LineComment" => Some(Self::LineComment),
            "BlockComment" => Some(Self::BlockComment),
            "LeftBrace" => Some(Self::LeftBrace),
            "RightBrace" => Some(Self::RightBrace),
            "LeftBracket" => Some(Self::LeftBracket),
            "RightBracket" => Some(Self::RightBracket),
            "Colon" => Some(Self::Colon),
            "Comma" => Some(Self::Comma),
            "String" => Some(Self::String),
            "Number" => Some(Self::Number),
            "True" => Some(Self::True),
            "False" => Some(Self::False),
            "Null" => Some(Self::Null),
            "ErrorRegion" => Some(Self::ErrorRegion),
            _ => None,
        }
    }
}

impl JsonProfile {
    /// Immutable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::StrictV1 => ProfileId::new("json.strict", 1),
            Self::JsoncBoundedV1 => ProfileId::new("jsonc.bounded", 1),
        }
    }

    /// Whether bounded comments and trailing commas are accepted.
    #[must_use]
    const fn permits_jsonc_extensions(self) -> bool {
        matches!(self, Self::JsoncBoundedV1)
    }
}

/// Parses a complete immutable JSON/JSONC document snapshot.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: JsonProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parser::parse(source.into(), profile, limits)
}

/// Opaque immutable document snapshot.
#[derive(Clone, Debug)]
pub struct Document {
    authority: DocumentAuthority,
    source: SourceSnapshot,
    profile: JsonProfile,
    structural_index: LosslessStructuralIndex,
    syntax_kinds: Arc<[JsonSyntaxKind]>,
    formation_status: FormationStatus,
    diagnostics: Arc<[Diagnostic]>,
    entities: Arc<[Entity]>,
    root: usize,
    parse_limits: ParseLimits,
}

impl Document {
    /// Snapshot identity to which every NodeRef and Span belongs.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.authority.identity()
    }

    /// Exact immutable source.
    #[must_use]
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Default rendering is the exact current source bytes.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// JSON format family contract.
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("json", 1)
    }

    /// Exact language profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Whether recovery structure was required.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        self.formation_status
    }

    /// Deterministically ordered document diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Exhaustive token/trivia/error-region byte coverage.
    #[must_use]
    pub const fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.structural_index
    }

    /// Format-specific kind for every structural piece, in the same source order.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[JsonSyntaxKind] {
        &self.syntax_kinds
    }

    /// Root native semantic value. Recovered roots can report local semantic unavailability.
    #[must_use]
    pub const fn root(&self) -> JsonValue<'_> {
        JsonValue {
            document: self,
            index: self.root,
        }
    }

    fn entity(&self, index: usize) -> &Entity {
        &self.entities[index]
    }

    fn value_entity(&self, index: usize) -> &ValueEntity {
        match self.entity(index) {
            Entity::Value(value) => value,
            _ => unreachable!("typed value handle"),
        }
    }

    fn node_ref(&self, index: usize, role: NodeRole) -> NodeRef {
        self.authority.node_ref(index as u64, role)
    }

    fn span(&self, index: usize) -> Span {
        self.entity(index).span()
    }

    fn validate_ref(&self, node: NodeRef, roles: &[NodeRole]) -> Result<usize, JsonAccessError> {
        self.authority
            .verify(node)
            .map_err(|_| JsonAccessError::WrongSnapshot)?;
        if !roles.contains(&node.role()) {
            return Err(JsonAccessError::WrongRole);
        }
        let index = usize::try_from(
            self.authority
                .resolve_index(node)
                .map_err(|_| JsonAccessError::WrongSnapshot)?,
        )
        .map_err(|_| JsonAccessError::UnknownNode)?;
        if index >= self.entities.len() {
            return Err(JsonAccessError::UnknownNode);
        }
        Ok(index)
    }
}

/// Regional semantic availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticAvailability<T> {
    /// Complete native meaning.
    Available(T),
    /// Recovery or an invalid literal prevented native meaning.
    Unavailable(SemanticUnavailable),
}

impl<T> SemanticAvailability<T> {
    /// Maps an available value while preserving unavailability.
    #[must_use]
    pub fn map<U>(self, function: impl FnOnce(T) -> U) -> SemanticAvailability<U> {
        match self {
            Self::Available(value) => SemanticAvailability::Available(function(value)),
            Self::Unavailable(reason) => SemanticAvailability::Unavailable(reason),
        }
    }
}

/// Stable reason that a region has no native semantic value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticUnavailable {
    /// Parser inserted a zero-width missing value.
    Missing,
    /// Source bytes occupy an explicit error region.
    ErrorRegion,
    /// Literal syntax was complete but its decoded meaning was invalid.
    InvalidLiteral,
    /// A child prevents complete container semantics.
    ChildUnavailable,
}

/// Native JSON value category, preserving integer-form versus decimal-form numbers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonValueKind {
    /// JSON null.
    Null,
    /// Boolean.
    Boolean,
    /// Number without decimal point or exponent.
    Integer,
    /// Number with decimal point or exponent.
    Decimal,
    /// Decoded string.
    String,
    /// Ordered array.
    Array,
    /// Ordered object with duplicate member preservation.
    Object,
}

/// Borrowed typed native semantic value bound to one Document snapshot.
#[derive(Clone, Copy, Debug)]
pub struct JsonValue<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> JsonValue<'a> {
    /// Exact value node handle.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document.node_ref(self.index, NodeRole::Value)
    }

    /// Exact syntax span, possibly zero-width for a missing recovered node.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.span(self.index)
    }

    /// Native semantic category when available.
    #[must_use]
    pub fn kind(self) -> SemanticAvailability<JsonValueKind> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Null => SemanticAvailability::Available(JsonValueKind::Null),
            InternalValueKind::Boolean(_) => {
                SemanticAvailability::Available(JsonValueKind::Boolean)
            }
            InternalValueKind::Integer(_) => {
                SemanticAvailability::Available(JsonValueKind::Integer)
            }
            InternalValueKind::Decimal(_) => {
                SemanticAvailability::Available(JsonValueKind::Decimal)
            }
            InternalValueKind::String(_) => SemanticAvailability::Available(JsonValueKind::String),
            InternalValueKind::Array(_) => SemanticAvailability::Available(JsonValueKind::Array),
            InternalValueKind::Object(_) => SemanticAvailability::Available(JsonValueKind::Object),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
        }
    }

    /// Boolean value.
    #[must_use]
    pub fn as_boolean(self) -> SemanticAvailability<Option<bool>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Boolean(value) => SemanticAvailability::Available(Some(*value)),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    /// Exact arbitrary-precision integer.
    #[must_use]
    pub fn as_integer(self) -> SemanticAvailability<Option<&'a BigInteger>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Integer(value) => SemanticAvailability::Available(Some(value)),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    /// Exact normalized decimal.
    #[must_use]
    pub fn as_decimal(self) -> SemanticAvailability<Option<&'a Decimal>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Decimal(value) => SemanticAvailability::Available(Some(value)),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    /// Decoded Unicode string without normalization.
    #[must_use]
    pub fn as_string(self) -> SemanticAvailability<Option<&'a str>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::String(value) => SemanticAvailability::Available(Some(value)),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    /// Ordered array elements.
    #[must_use]
    pub fn array_elements(self) -> SemanticAvailability<Option<Vec<JsonArrayElement<'a>>>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Array(elements) => SemanticAvailability::Available(Some(
                elements
                    .iter()
                    .map(|index| JsonArrayElement {
                        document: self.document,
                        index: *index,
                    })
                    .collect(),
            )),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    /// Ordered object members without duplicate collapse.
    #[must_use]
    pub fn object_members(self) -> SemanticAvailability<Option<Vec<JsonObjectMember<'a>>>> {
        match &self.document.value_entity(self.index).kind {
            InternalValueKind::Object(members) => SemanticAvailability::Available(Some(
                members
                    .iter()
                    .map(|index| JsonObjectMember {
                        document: self.document,
                        index: *index,
                    })
                    .collect(),
            )),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Available(None),
        }
    }

    fn raw_index(self) -> usize {
        self.index
    }
}

/// Borrowed JSON object member association.
#[derive(Clone, Copy, Debug)]
pub struct JsonObjectMember<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> JsonObjectMember<'a> {
    fn entity(self) -> &'a MemberEntity {
        match self.document.entity(self.index) {
            Entity::Member(member) => member,
            _ => unreachable!("typed member handle"),
        }
    }

    /// Zero-based structural member ordinal.
    #[must_use]
    pub fn ordinal(self) -> usize {
        self.entity().ordinal
    }

    /// Member association identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document.node_ref(self.index, NodeRole::ObjectMember)
    }

    /// Key node identity.
    #[must_use]
    pub fn key_node_ref(self) -> NodeRef {
        self.document
            .node_ref(self.entity().key, NodeRole::ObjectKey)
    }

    /// Value node identity.
    #[must_use]
    pub fn value_node_ref(self) -> NodeRef {
        self.document.node_ref(self.entity().value, NodeRole::Value)
    }

    /// Whole member source span.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.span(self.index)
    }

    /// Decoded member name.
    #[must_use]
    pub fn name(self) -> SemanticAvailability<&'a str> {
        match &self.document.value_entity(self.entity().key).kind {
            InternalValueKind::String(name) => SemanticAvailability::Available(name),
            InternalValueKind::Unavailable(reason) => {
                SemanticAvailability::Unavailable(reason.clone())
            }
            _ => SemanticAvailability::Unavailable(SemanticUnavailable::InvalidLiteral),
        }
    }

    /// Associated value.
    #[must_use]
    pub fn value(self) -> JsonValue<'a> {
        JsonValue {
            document: self.document,
            index: self.entity().value,
        }
    }
}

/// Borrowed JSON array element association.
#[derive(Clone, Copy, Debug)]
pub struct JsonArrayElement<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> JsonArrayElement<'a> {
    fn entity(self) -> &'a ElementEntity {
        match self.document.entity(self.index) {
            Entity::Element(element) => element,
            _ => unreachable!("typed element handle"),
        }
    }

    /// Zero-based structural index.
    #[must_use]
    pub fn ordinal(self) -> usize {
        self.entity().ordinal
    }

    /// Element association identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document.node_ref(self.index, NodeRole::ArrayElement)
    }

    /// Associated value identity.
    #[must_use]
    pub fn value_node_ref(self) -> NodeRef {
        self.document.node_ref(self.entity().value, NodeRole::Value)
    }

    /// Whole element span.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.span(self.index)
    }

    /// Element value.
    #[must_use]
    pub fn value(self) -> JsonValue<'a> {
        JsonValue {
            document: self.document,
            index: self.entity().value,
        }
    }
}

/// Stable typed JSON access failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonAccessError {
    /// NodeRef belongs to another snapshot.
    WrongSnapshot,
    /// NodeRef role cannot be used by this operation.
    WrongRole,
    /// Index is not present in this snapshot.
    UnknownNode,
}

#[derive(Clone, Debug)]
pub(crate) enum Entity {
    Value(ValueEntity),
    Member(MemberEntity),
    Element(ElementEntity),
}

impl Entity {
    fn span(&self) -> Span {
        match self {
            Self::Value(value) => value.span,
            Self::Member(member) => member.span,
            Self::Element(element) => element.span,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ValueEntity {
    pub(crate) span: Span,
    pub(crate) literal_span: Option<Span>,
    pub(crate) complete: bool,
    pub(crate) kind: InternalValueKind,
}

#[derive(Clone, Debug)]
pub(crate) enum InternalValueKind {
    Null,
    Boolean(bool),
    Integer(BigInteger),
    Decimal(Decimal),
    String(String),
    Array(Vec<usize>),
    Object(Vec<usize>),
    Unavailable(SemanticUnavailable),
}

#[derive(Clone, Debug)]
pub(crate) struct MemberEntity {
    pub(crate) span: Span,
    pub(crate) key: usize,
    pub(crate) value: usize,
    pub(crate) ordinal: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ElementEntity {
    pub(crate) span: Span,
    pub(crate) value: usize,
    pub(crate) ordinal: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_document_round_trips_and_preserves_duplicates() {
        let source = br#" { "a": 1, "a": 2 } "#;
        let document = parse(
            source.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.render(), source);
        let members = match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members,
            other => panic!("unexpected semantics: {other:?}"),
        };
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(), SemanticAvailability::Available("a"));
        assert_ne!(members[0].node_ref(), members[1].node_ref());
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|item| item.code == "json.object.duplicate-member@1")
        );
    }

    #[test]
    fn jsonc_lossless_syntax_kinds_align_with_exact_coverage() {
        let source = b"\xef\xbb\xbf // line\n{\"x\":true,/* block */\"y\":null}";
        let document = parse(
            source.as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let kinds = document.lossless_syntax_kinds();
        assert_eq!(
            kinds,
            &[
                JsonSyntaxKind::Bom,
                JsonSyntaxKind::Whitespace,
                JsonSyntaxKind::LineComment,
                JsonSyntaxKind::Whitespace,
                JsonSyntaxKind::LeftBrace,
                JsonSyntaxKind::String,
                JsonSyntaxKind::Colon,
                JsonSyntaxKind::True,
                JsonSyntaxKind::Comma,
                JsonSyntaxKind::BlockComment,
                JsonSyntaxKind::String,
                JsonSyntaxKind::Colon,
                JsonSyntaxKind::Null,
                JsonSyntaxKind::RightBrace,
            ]
        );
        assert_eq!(
            kinds.len(),
            document.lossless_structural_index().pieces().len()
        );
    }
}
