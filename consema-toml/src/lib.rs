//! Lossless `toml.1.0@1` documents and native semantics.

mod edit;
mod materialization;
mod operation_registry;
mod parser;
mod projection;
mod query;

use consema_core::{BinaryFloat64, Diagnostic};
use consema_document::{
    DocumentAuthority, FatalFormationFailure, FormatFamilyId, FormationStatus,
    LosslessStructuralIndex, NodeRef, NodeRole, ParseLimits, ProfileId, SnapshotIdentity,
    SourceSnapshot, Span,
};
use std::sync::Arc;

pub use edit::{
    EditCommit, EditFailure, EditOperation, EditTransaction, EditTransactionBuilder,
    RepresentationPolicy, ScalarReplacement,
};
pub use materialization::materialize;
pub use operation_registry::format_operation_registry;
pub use projection::{
    CompleteProjection, FailedProjectionAttempt, Fidelity, ProjectedLocation, ProjectionFailure,
    ProjectionLimits, ProjectionReport, ProjectionRequest, ProjectionResult, ProjectionTarget,
    ProvenanceEntry, ProvenanceMap, ProvenanceRelation, SourceOrigin,
};
pub use query::{
    TomlMatch, TomlSyntaxMatch, execute_toml_query, execute_toml_query_cursor,
    execute_toml_syntax_query, execute_toml_syntax_query_cursor,
};

/// Frozen TOML language profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TomlProfile {
    /// TOML 1.0.0 without implementation extensions.
    Toml10V1,
}

/// Closed TOML v1 lossless syntax-piece classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TomlSyntaxKind {
    /// Horizontal whitespace.
    Whitespace,
    /// LF, CRLF, or invalid bare CR retained for formation diagnostics.
    Newline,
    /// `#` comment excluding its newline.
    Comment,
    /// Basic or literal string token, including multiline forms.
    String,
    /// Bare key or value fragment.
    Bare,
    /// `=`.
    Equals,
    /// `[`.
    LeftBracket,
    /// `]`.
    RightBracket,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// `,`.
    Comma,
    /// `.`.
    Dot,
}

impl TomlSyntaxKind {
    /// Stable query and protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Whitespace => "Whitespace",
            Self::Newline => "Newline",
            Self::Comment => "Comment",
            Self::String => "String",
            Self::Bare => "Bare",
            Self::Equals => "Equals",
            Self::LeftBracket => "LeftBracket",
            Self::RightBracket => "RightBracket",
            Self::LeftBrace => "LeftBrace",
            Self::RightBrace => "RightBrace",
            Self::Comma => "Comma",
            Self::Dot => "Dot",
        }
    }

    /// Resolves one exact stable kind name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Whitespace" => Some(Self::Whitespace),
            "Newline" => Some(Self::Newline),
            "Comment" => Some(Self::Comment),
            "String" => Some(Self::String),
            "Bare" => Some(Self::Bare),
            "Equals" => Some(Self::Equals),
            "LeftBracket" => Some(Self::LeftBracket),
            "RightBracket" => Some(Self::RightBracket),
            "LeftBrace" => Some(Self::LeftBrace),
            "RightBrace" => Some(Self::RightBrace),
            "Comma" => Some(Self::Comma),
            "Dot" => Some(Self::Dot),
            _ => None,
        }
    }
}

impl TomlProfile {
    /// Immutable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::Toml10V1 => ProfileId::new("toml.1.0", 1),
        }
    }
}

/// Parses one complete immutable TOML 1.0 document snapshot.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: TomlProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parser::parse(source.into(), profile, limits)
}

/// Opaque immutable TOML document snapshot.
#[derive(Clone, Debug)]
pub struct Document {
    authority: DocumentAuthority,
    source: SourceSnapshot,
    profile: TomlProfile,
    structural_index: LosslessStructuralIndex,
    syntax_kinds: Arc<[TomlSyntaxKind]>,
    diagnostics: Arc<[Diagnostic]>,
    entities: Arc<[Entity]>,
    root: usize,
    parse_limits: ParseLimits,
}

impl Document {
    /// Snapshot identity to which every native handle and span belongs.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.authority.identity()
    }

    /// Exact immutable UTF-8 source.
    #[must_use]
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Default rendering is byte-for-byte identical to the source.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// TOML format family contract.
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("toml", 1)
    }

    /// Exact language profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// TOML 0.2 forms only complete valid documents.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        FormationStatus::Complete
    }

    /// Deterministically ordered non-fatal diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Exhaustive token/trivia byte coverage.
    #[must_use]
    pub const fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        &self.structural_index
    }

    /// Format-specific kind for every structural piece, in the same source order.
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[TomlSyntaxKind] {
        &self.syntax_kinds
    }

    /// Resource contract used to form this snapshot and any edit successor.
    #[must_use]
    pub const fn parse_limits(&self) -> ParseLimits {
        self.parse_limits
    }

    /// Root native item, which is always `RootTable`.
    #[must_use]
    pub const fn root(&self) -> TomlItem<'_> {
        TomlItem {
            document: self,
            index: self.root,
        }
    }

    /// Resolves a snapshot-bound TOML item handle.
    pub fn item(&self, node: NodeRef) -> Result<TomlItem<'_>, TomlAccessError> {
        let index = self.validate_ref(node, NodeRole::TomlItem)?;
        if !matches!(self.entities[index].kind, EntityKind::Item(_)) {
            return Err(TomlAccessError::WrongRole);
        }
        Ok(TomlItem {
            document: self,
            index,
        })
    }

    fn entity(&self, index: usize) -> &Entity {
        &self.entities[index]
    }

    fn item_entity(&self, index: usize) -> &ItemEntity {
        match &self.entity(index).kind {
            EntityKind::Item(item) => item,
            _ => unreachable!("typed TOML item handle"),
        }
    }

    fn node_ref(&self, index: usize, role: NodeRole) -> NodeRef {
        self.authority.node_ref(index as u64, role)
    }

    fn validate_ref(&self, node: NodeRef, role: NodeRole) -> Result<usize, TomlAccessError> {
        self.authority
            .verify(node)
            .map_err(|_| TomlAccessError::WrongSnapshot)?;
        if node.role() != role {
            return Err(TomlAccessError::WrongRole);
        }
        let index = usize::try_from(
            self.authority
                .resolve_index(node)
                .map_err(|_| TomlAccessError::WrongSnapshot)?,
        )
        .map_err(|_| TomlAccessError::UnknownNode)?;
        if index >= self.entities.len() {
            return Err(TomlAccessError::UnknownNode);
        }
        Ok(index)
    }
}

/// Stable TOML native handle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TomlAccessError {
    /// Handle belongs to another immutable snapshot.
    WrongSnapshot,
    /// Handle role does not match the requested native entity.
    WrongRole,
    /// Handle index is not present in this document.
    UnknownNode,
}

/// Native TOML item category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TomlItemKind {
    /// Decoded TOML string.
    String,
    /// Signed 64-bit TOML integer.
    Integer,
    /// IEEE-754 binary64 TOML float.
    Float,
    /// Boolean.
    Boolean,
    /// Date-time with a fixed offset.
    OffsetDateTime,
    /// Date-time without an offset.
    LocalDateTime,
    /// Date without time or offset.
    LocalDate,
    /// Time without date or offset.
    LocalTime,
    /// Inline value array.
    Array,
    /// Inline table value.
    InlineTable,
    /// Document root table.
    RootTable,
    /// Explicit standard table.
    StandardTable,
    /// Logical table created by a table path.
    ImplicitTable,
    /// Logical table created by dotted-key syntax.
    DottedTable,
    /// Ordered array of explicit tables.
    ArrayOfTables,
}

/// Parsed TOML date fields.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TomlDate {
    /// Four-digit year.
    pub year: u16,
    /// Month in `1..=12`.
    pub month: u8,
    /// Day in the selected month.
    pub day: u8,
}

/// Parsed TOML time fields.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TomlTime {
    /// Hour in `0..=23`.
    pub hour: u8,
    /// Minute in `0..=59`.
    pub minute: u8,
    /// Parsed second.
    pub second: u8,
    /// Fractional second truncated to nanoseconds by the profile backend.
    pub nanosecond: u32,
}

/// Parsed TOML UTC offset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TomlOffset {
    /// Literal UTC `Z`.
    Z,
    /// Signed offset in minutes.
    CustomMinutes(i16),
}

/// Complete native TOML date/time datum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TomlDateTime {
    /// Optional date component.
    pub date: Option<TomlDate>,
    /// Optional time component.
    pub time: Option<TomlTime>,
    /// Optional UTC offset.
    pub offset: Option<TomlOffset>,
}

/// Borrowed native TOML item bound to one document snapshot.
#[derive(Clone, Copy, Debug)]
pub struct TomlItem<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> TomlItem<'a> {
    /// Exact item identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document.node_ref(self.index, NodeRole::TomlItem)
    }

    /// Exact or contract-authorized logical source span.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.entity(self.index).span
    }

    /// Native item category.
    #[must_use]
    pub fn kind(self) -> TomlItemKind {
        self.document.item_entity(self.index).kind.public_kind()
    }

    /// Decoded string when this item is a string.
    #[must_use]
    pub fn as_string(self) -> Option<&'a str> {
        match &self.document.item_entity(self.index).kind {
            InternalItemKind::String(value) => Some(value),
            _ => None,
        }
    }

    /// Signed integer when this item is an integer.
    #[must_use]
    pub fn as_integer(self) -> Option<i64> {
        match self.document.item_entity(self.index).kind {
            InternalItemKind::Integer(value) => Some(value),
            _ => None,
        }
    }

    /// Exact IEEE-754 datum when this item is a float.
    #[must_use]
    pub fn as_float(self) -> Option<BinaryFloat64> {
        match self.document.item_entity(self.index).kind {
            InternalItemKind::Float(value) => Some(value),
            _ => None,
        }
    }

    /// Boolean when this item is a boolean.
    #[must_use]
    pub fn as_boolean(self) -> Option<bool> {
        match self.document.item_entity(self.index).kind {
            InternalItemKind::Boolean(value) => Some(value),
            _ => None,
        }
    }

    /// Native temporal datum when this item is any TOML date/time category.
    #[must_use]
    pub fn as_date_time(self) -> Option<&'a TomlDateTime> {
        match &self.document.item_entity(self.index).kind {
            InternalItemKind::DateTime(value) => Some(value),
            _ => None,
        }
    }

    /// Direct ordered entries for any table category or inline table.
    #[must_use]
    pub fn table_entries(self) -> Option<Vec<TomlEntry<'a>>> {
        let (InternalItemKind::Table { entries, .. } | InternalItemKind::InlineTable(entries)) =
            &self.document.item_entity(self.index).kind
        else {
            return None;
        };
        Some(
            entries
                .iter()
                .map(|index| TomlEntry {
                    document: self.document,
                    index: *index,
                })
                .collect(),
        )
    }

    /// Direct ordered elements for arrays and arrays-of-tables.
    #[must_use]
    pub fn array_elements(self) -> Option<Vec<TomlArrayElement<'a>>> {
        let (InternalItemKind::Array(elements) | InternalItemKind::ArrayOfTables(elements)) =
            &self.document.item_entity(self.index).kind
        else {
            return None;
        };
        Some(
            elements
                .iter()
                .map(|index| TomlArrayElement {
                    document: self.document,
                    index: *index,
                })
                .collect(),
        )
    }
}

/// Borrowed direct table entry association.
#[derive(Clone, Copy, Debug)]
pub struct TomlEntry<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> TomlEntry<'a> {
    fn entity(self) -> &'a EntryEntity {
        match &self.document.entity(self.index).kind {
            EntityKind::Entry(entry) => entry,
            _ => unreachable!("typed TOML entry handle"),
        }
    }

    /// Zero-based direct entry ordinal.
    #[must_use]
    pub fn ordinal(self) -> usize {
        self.entity().ordinal
    }

    /// Association identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document.node_ref(self.index, NodeRole::TomlEntry)
    }

    /// Direct key segment identity.
    #[must_use]
    pub fn key_node_ref(self) -> NodeRef {
        self.document.node_ref(self.entity().key, NodeRole::TomlKey)
    }

    /// Associated item identity.
    #[must_use]
    pub fn item_node_ref(self) -> NodeRef {
        self.document
            .node_ref(self.entity().item, NodeRole::TomlItem)
    }

    /// Association source span.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.entity(self.index).span
    }

    /// Decoded direct key segment without normalization.
    #[must_use]
    pub fn name(self) -> &'a str {
        match &self.document.entity(self.entity().key).kind {
            EntityKind::Key(key) => &key.name,
            _ => unreachable!("typed TOML key handle"),
        }
    }

    /// Associated native item.
    #[must_use]
    pub fn item(self) -> TomlItem<'a> {
        TomlItem {
            document: self.document,
            index: self.entity().item,
        }
    }
}

/// Borrowed array or array-of-tables element association.
#[derive(Clone, Copy, Debug)]
pub struct TomlArrayElement<'a> {
    document: &'a Document,
    index: usize,
}

impl<'a> TomlArrayElement<'a> {
    fn entity(self) -> &'a ElementEntity {
        match &self.document.entity(self.index).kind {
            EntityKind::Element(element) => element,
            _ => unreachable!("typed TOML element handle"),
        }
    }

    /// Zero-based direct element ordinal.
    #[must_use]
    pub fn ordinal(self) -> usize {
        self.entity().ordinal
    }

    /// Association identity.
    #[must_use]
    pub fn node_ref(self) -> NodeRef {
        self.document
            .node_ref(self.index, NodeRole::TomlArrayElement)
    }

    /// Associated item identity.
    #[must_use]
    pub fn item_node_ref(self) -> NodeRef {
        self.document
            .node_ref(self.entity().item, NodeRole::TomlItem)
    }

    /// Association source span.
    #[must_use]
    pub fn span(self) -> Span {
        self.document.entity(self.index).span
    }

    /// Associated native item.
    #[must_use]
    pub fn item(self) -> TomlItem<'a> {
        TomlItem {
            document: self.document,
            index: self.entity().item,
        }
    }
}

#[derive(Clone, Debug)]
struct Entity {
    span: Span,
    kind: EntityKind,
}

#[derive(Clone, Debug)]
enum EntityKind {
    Item(ItemEntity),
    Entry(EntryEntity),
    Key(KeyEntity),
    Element(ElementEntity),
}

#[derive(Clone, Debug)]
struct ItemEntity {
    kind: InternalItemKind,
}

#[derive(Clone, Debug)]
enum InternalItemKind {
    String(Arc<str>),
    Integer(i64),
    Float(BinaryFloat64),
    Boolean(bool),
    DateTime(TomlDateTime),
    Array(Vec<usize>),
    InlineTable(Vec<usize>),
    Table {
        flavor: TableFlavor,
        entries: Vec<usize>,
    },
    ArrayOfTables(Vec<usize>),
}

impl InternalItemKind {
    fn public_kind(&self) -> TomlItemKind {
        match self {
            Self::String(_) => TomlItemKind::String,
            Self::Integer(_) => TomlItemKind::Integer,
            Self::Float(_) => TomlItemKind::Float,
            Self::Boolean(_) => TomlItemKind::Boolean,
            Self::DateTime(value) => match (value.date, value.time, value.offset) {
                (Some(_), Some(_), Some(_)) => TomlItemKind::OffsetDateTime,
                (Some(_), Some(_), None) => TomlItemKind::LocalDateTime,
                (Some(_), None, None) => TomlItemKind::LocalDate,
                (None, Some(_), None) => TomlItemKind::LocalTime,
                _ => unreachable!("TOML parser returns one defined datetime shape"),
            },
            Self::Array(_) => TomlItemKind::Array,
            Self::InlineTable(_) => TomlItemKind::InlineTable,
            Self::Table { flavor, .. } => match flavor {
                TableFlavor::Root => TomlItemKind::RootTable,
                TableFlavor::Standard => TomlItemKind::StandardTable,
                TableFlavor::Implicit => TomlItemKind::ImplicitTable,
                TableFlavor::Dotted => TomlItemKind::DottedTable,
            },
            Self::ArrayOfTables(_) => TomlItemKind::ArrayOfTables,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum TableFlavor {
    Root,
    Standard,
    Implicit,
    Dotted,
}

#[derive(Clone, Debug)]
struct EntryEntity {
    ordinal: usize,
    key: usize,
    item: usize,
}

#[derive(Clone, Debug)]
struct KeyEntity {
    name: Arc<str>,
}

#[derive(Clone, Debug)]
struct ElementEntity {
    ordinal: usize,
    item: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{ParseLimits, StructuralPieceKind};

    #[test]
    fn complete_document_preserves_source_and_native_categories() {
        let source = br#"title = "TOML"
hex = 0x2A
float = -0.0
when = 1979-05-27T07:32:00Z
point = { x = 1, y = 2 }
items = [1, 2]

[owner.profile]
active = true

[[products]]
name = "one"

[[products]]
name = "two"
"#;
        let document = parse(
            source.as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("valid TOML");
        assert_eq!(document.render(), source);
        assert_eq!(document.root().kind(), TomlItemKind::RootTable);
        assert_eq!(document.formation_status(), FormationStatus::Complete);

        let entries = document.root().table_entries().expect("root table");
        let float = entries
            .iter()
            .find(|entry| entry.name() == "float")
            .expect("float entry")
            .item();
        assert_eq!(float.kind(), TomlItemKind::Float);
        assert_eq!(
            float.as_float().expect("float").bits(),
            (-0.0_f64).to_bits()
        );

        let owner = entries
            .iter()
            .find(|entry| entry.name() == "owner")
            .expect("implicit owner")
            .item();
        assert_eq!(owner.kind(), TomlItemKind::ImplicitTable);
        let products = entries
            .iter()
            .find(|entry| entry.name() == "products")
            .expect("products")
            .item();
        assert_eq!(products.kind(), TomlItemKind::ArrayOfTables);
        assert_eq!(products.array_elements().expect("AOT").len(), 2);

        let pieces = document.lossless_structural_index().pieces();
        assert!(!pieces.is_empty());
        assert!(
            pieces
                .iter()
                .any(|piece| piece.kind() == StructuralPieceKind::Trivia)
        );
        assert_eq!(pieces.first().expect("piece").span().start_byte(), 0);
        assert_eq!(
            pieces.last().expect("piece").span().end_byte(),
            source.len()
        );
    }

    #[test]
    fn dotted_keys_retain_each_logical_segment() {
        let document = parse(
            b"alpha.beta.gamma = 1\n".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("valid dotted key");
        let alpha = document.root().table_entries().expect("root")[0];
        assert_eq!(alpha.name(), "alpha");
        assert_eq!(alpha.item().kind(), TomlItemKind::DottedTable);
        let beta = alpha.item().table_entries().expect("alpha table")[0];
        assert_eq!(beta.name(), "beta");
        let gamma = beta.item().table_entries().expect("beta table")[0];
        assert_eq!(gamma.name(), "gamma");
        assert_eq!(gamma.item().as_integer(), Some(1));
    }

    #[test]
    fn syntax_and_resource_failures_never_form_documents() {
        let syntax = parse(
            b"value = [1,,2]".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect_err("invalid TOML");
        assert_eq!(syntax.diagnostics()[0].code, "toml.parse.syntax@1");

        let limits = ParseLimits {
            max_source_bytes: 3,
            ..ParseLimits::default()
        };
        let limited =
            parse(b"x = 1".as_slice(), TomlProfile::Toml10V1, limits).expect_err("source limit");
        assert_eq!(limited.diagnostics()[0].code, "core.parse.resource-limit@1");

        let limits = ParseLimits {
            max_nesting_depth: 2,
            ..ParseLimits::default()
        };
        let nested = parse(b"value = [[[[[".as_slice(), TomlProfile::Toml10V1, limits)
            .expect_err("preflight nesting limit");
        assert_eq!(nested.diagnostics()[0].code, "core.parse.resource-limit@1");
        assert_eq!(nested.diagnostics()[0].arguments["name"], "nesting_depth");
    }

    #[test]
    fn item_handles_are_snapshot_and_role_bound() {
        let first = parse(
            b"x = 1".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("first");
        let second = parse(
            b"x = 2".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("second");
        assert!(matches!(
            second.item(first.root().node_ref()),
            Err(TomlAccessError::WrongSnapshot)
        ));
        let entry = first.root().table_entries().expect("entries")[0];
        assert!(matches!(
            first.item(entry.node_ref()),
            Err(TomlAccessError::WrongRole)
        ));
    }

    #[test]
    fn toml_lossless_syntax_kinds_distinguish_newlines_and_punctuation() {
        let source = b"a.b = \"x\" # c\r\nlist = [1, 2]\ninline = {x=1}\n";
        let document = parse(
            source.as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .unwrap();
        let kinds = document.lossless_syntax_kinds();
        assert_eq!(
            &kinds[..10],
            &[
                TomlSyntaxKind::Bare,
                TomlSyntaxKind::Dot,
                TomlSyntaxKind::Bare,
                TomlSyntaxKind::Whitespace,
                TomlSyntaxKind::Equals,
                TomlSyntaxKind::Whitespace,
                TomlSyntaxKind::String,
                TomlSyntaxKind::Whitespace,
                TomlSyntaxKind::Comment,
                TomlSyntaxKind::Newline,
            ]
        );
        assert!(kinds.contains(&TomlSyntaxKind::LeftBracket));
        assert!(kinds.contains(&TomlSyntaxKind::RightBracket));
        assert!(kinds.contains(&TomlSyntaxKind::LeftBrace));
        assert!(kinds.contains(&TomlSyntaxKind::RightBrace));
        assert!(kinds.contains(&TomlSyntaxKind::Comma));
        assert_eq!(
            kinds.len(),
            document.lossless_structural_index().pieces().len()
        );
    }
}
