use crate::{Document, EntityKind, TomlItemKind, parse};
use consema_core::{
    BinaryFloat64, Date, Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    LocalDateTime, OffsetDateTime, PortableValue, PortableValueKind, Time,
};
use consema_document::{
    ChangeSet, NodeMapping, NodeMappingStatus, NodeRef, NodeRole, SnapshotIdentity, SourceEdit,
};
use std::fmt::Write as _;
use std::sync::Arc;

/// Explicit semantic scalar representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must use an exact literal operation instead.
    ExactLiteral,
    /// New public value must retain the target native scalar category.
    PreserveCompatible,
    /// Use the frozen deterministic TOML 1.0 scalar representation.
    CanonicalForProfile,
    /// Preserve the category when compatible, otherwise report canonical fallback.
    PreserveElseCanonical,
}

/// One scalar operation bound to a transaction base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarReplacement {
    /// Replace by public semantic value under an explicit policy.
    Semantic {
        /// Exact TOML item target.
        target: NodeRef,
        /// New complete core scalar.
        value: PortableValue,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replace by exact candidate literal bytes after full profile validation.
    Literal {
        /// Exact TOML item target.
        target: NodeRef,
        /// Exact candidate scalar bytes.
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

/// Immutable transaction; every operation resolves against one base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditTransaction {
    base: SnapshotIdentity,
    operations: Arc<[ScalarReplacement]>,
}

impl EditTransaction {
    /// Base snapshot identity.
    #[must_use]
    pub const fn base_snapshot(&self) -> SnapshotIdentity {
        self.base
    }

    /// Ordered declared operations.
    #[must_use]
    pub fn operations(&self) -> &[ScalarReplacement] {
        &self.operations
    }
}

/// Builder that is not a committed edit.
#[derive(Debug)]
pub struct EditTransactionBuilder {
    base: SnapshotIdentity,
    operations: Vec<ScalarReplacement>,
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

    /// Adds a semantic scalar replacement.
    pub fn semantic_scalar(
        &mut self,
        target: NodeRef,
        value: PortableValue,
        policy: RepresentationPolicy,
    ) -> &mut Self {
        self.operations.push(ScalarReplacement::Semantic {
            target,
            value,
            policy,
        });
        self
    }

    /// Adds an exact TOML scalar literal replacement.
    pub fn literal_scalar(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations.push(ScalarReplacement::Literal {
            target,
            literal: literal.into(),
        });
        self
    }

    /// Completes the immutable request; target validation occurs atomically at commit.
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
}

/// Stable edit validation or commit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditFailure {
    /// Transaction or target belongs to another snapshot.
    WrongSnapshot,
    /// Target is not a TOML scalar item.
    WrongRole,
    /// Public value cannot be represented as a TOML 1.0 scalar without semantic loss.
    UnsupportedSemanticValue(PortableValueKind),
    /// Candidate bytes are not exactly one complete TOML 1.0 scalar literal.
    InvalidLiteral,
    /// `PreserveCompatible` could not retain the scalar category.
    RepresentationIncompatible,
    /// `ExactLiteral` was requested without literal bytes.
    ExactLiteralRequiresLiteralOperation,
    /// Two source edits overlap or target the same scalar.
    ConflictingEdits,
    /// Replacement document could not be formed under the original limits.
    NewDocumentFormationFailed,
}

impl Document {
    /// Atomically commits scalar replacements. A failure never changes this snapshot.
    pub fn commit(&self, transaction: &EditTransaction) -> Result<EditCommit, EditFailure> {
        if transaction.base != self.snapshot_identity() {
            return Err(EditFailure::WrongSnapshot);
        }
        let mut diagnostics = Vec::new();
        let mut prepared = Vec::with_capacity(transaction.operations.len());
        for operation in transaction.operations.iter() {
            let target = operation.target();
            if target.snapshot() != self.snapshot_identity() {
                return Err(EditFailure::WrongSnapshot);
            }
            let index = self
                .validate_ref(target, NodeRole::TomlItem)
                .map_err(|failure| match failure {
                    crate::TomlAccessError::WrongSnapshot => EditFailure::WrongSnapshot,
                    crate::TomlAccessError::WrongRole | crate::TomlAccessError::UnknownNode => {
                        EditFailure::WrongRole
                    }
                })?;
            let old_kind = self.item_entity(index).kind.public_kind();
            if !is_scalar_kind(old_kind) {
                return Err(EditFailure::WrongRole);
            }
            let replacement = match operation {
                ScalarReplacement::Literal { literal, .. } => {
                    validate_exact_scalar(literal)?;
                    literal.to_vec()
                }
                ScalarReplacement::Semantic { value, policy, .. } => {
                    semantic_literal(value, old_kind, *policy, target, &mut diagnostics)?
                }
            };
            prepared.push(PreparedEdit {
                target,
                old_span: self.entity(index).span,
                replacement,
            });
        }

        prepared.sort_by_key(|edit| (edit.old_span.start_byte(), edit.old_span.end_byte()));
        for pair in prepared.windows(2) {
            if pair[0].old_span.end_byte() > pair[1].old_span.start_byte()
                || pair[0].old_span == pair[1].old_span
            {
                return Err(EditFailure::ConflictingEdits);
            }
        }

        let mut rendered = Vec::with_capacity(self.source.len());
        let mut cursor = 0;
        for edit in &prepared {
            rendered.extend_from_slice(&self.source.bytes()[cursor..edit.old_span.start_byte()]);
            rendered.extend_from_slice(&edit.replacement);
            cursor = edit.old_span.end_byte();
        }
        rendered.extend_from_slice(&self.source.bytes()[cursor..]);
        let new_document = parse(rendered, self.profile, self.parse_limits)
            .map_err(|_| EditFailure::NewDocumentFormationFailed)?;

        let mut delta = 0_isize;
        let mut source_edits = Vec::with_capacity(prepared.len());
        let mut mappings = Vec::with_capacity(prepared.len());
        for edit in prepared {
            let new_start = edit
                .old_span
                .start_byte()
                .checked_add_signed(delta)
                .expect("validated edit delta");
            let new_end = new_start + edit.replacement.len();
            let new_span = new_document
                .authority
                .span(new_start, new_end)
                .expect("replacement span");
            let new_ref = find_item_by_span(&new_document, new_start, new_end)
                .map(|index| new_document.node_ref(index, NodeRole::TomlItem));
            source_edits.push(SourceEdit {
                old_span: edit.old_span,
                new_span,
                replacement: Arc::from(edit.replacement.clone()),
            });
            mappings.push(NodeMapping {
                old: edit.target,
                new: new_ref,
                status: NodeMappingStatus::Replaced,
                reason: new_ref
                    .is_none()
                    .then(|| "reparsed-item-not-uniquely-located".to_owned()),
            });
            delta += edit.replacement.len() as isize - edit.old_span.len() as isize;
        }
        let change_set = ChangeSet::new(
            self.snapshot_identity(),
            new_document.snapshot_identity(),
            source_edits,
            mappings,
            diagnostics,
        );
        Ok(EditCommit {
            document: new_document,
            change_set,
        })
    }
}

struct PreparedEdit {
    target: NodeRef,
    old_span: consema_document::Span,
    replacement: Vec<u8>,
}

fn is_scalar_kind(kind: TomlItemKind) -> bool {
    matches!(
        kind,
        TomlItemKind::String
            | TomlItemKind::Integer
            | TomlItemKind::Float
            | TomlItemKind::Boolean
            | TomlItemKind::OffsetDateTime
            | TomlItemKind::LocalDateTime
            | TomlItemKind::LocalDate
            | TomlItemKind::LocalTime
    )
}

fn validate_exact_scalar(literal: &[u8]) -> Result<TomlItemKind, EditFailure> {
    let literal = std::str::from_utf8(literal).map_err(|_| EditFailure::InvalidLiteral)?;
    let prefix = "_ = ";
    let source = format!("{prefix}{literal}");
    let parsed = toml_edit::ImDocument::parse(source).map_err(|_| EditFailure::InvalidLiteral)?;
    if parsed.iter().count() != 1 {
        return Err(EditFailure::InvalidLiteral);
    }
    let value = parsed
        .get("_")
        .and_then(toml_edit::Item::as_value)
        .ok_or(EditFailure::InvalidLiteral)?;
    if value.span() != Some(prefix.len()..prefix.len() + literal.len()) {
        return Err(EditFailure::InvalidLiteral);
    }
    match value {
        toml_edit::Value::String(_) => Ok(TomlItemKind::String),
        toml_edit::Value::Integer(_) => Ok(TomlItemKind::Integer),
        toml_edit::Value::Float(_) => Ok(TomlItemKind::Float),
        toml_edit::Value::Boolean(_) => Ok(TomlItemKind::Boolean),
        toml_edit::Value::Datetime(value) => {
            let value = value.value();
            match (value.date, value.time, value.offset) {
                (Some(_), Some(_), Some(_)) => Ok(TomlItemKind::OffsetDateTime),
                (Some(_), Some(_), None) => Ok(TomlItemKind::LocalDateTime),
                (Some(_), None, None) => Ok(TomlItemKind::LocalDate),
                (None, Some(_), None) => Ok(TomlItemKind::LocalTime),
                _ => Err(EditFailure::InvalidLiteral),
            }
        }
        toml_edit::Value::Array(_) | toml_edit::Value::InlineTable(_) => {
            Err(EditFailure::InvalidLiteral)
        }
    }
}

fn semantic_literal(
    value: &PortableValue,
    old_kind: TomlItemKind,
    policy: RepresentationPolicy,
    target: NodeRef,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<u8>, EditFailure> {
    if policy == RepresentationPolicy::ExactLiteral {
        return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
    }
    let new_kind = portable_toml_kind(value)
        .ok_or_else(|| EditFailure::UnsupportedSemanticValue(value.kind()))?;
    let compatible = old_kind == new_kind;
    match policy {
        RepresentationPolicy::PreserveCompatible if !compatible => {
            return Err(EditFailure::RepresentationIncompatible);
        }
        RepresentationPolicy::PreserveElseCanonical if !compatible => {
            let mut diagnostic = Diagnostic::new(
                "toml.edit.representation-fallback@1",
                DiagnosticCategory::Edit,
                DiagnosticSeverity::Warning,
                None,
                diagnostics.len() as u64,
            );
            diagnostic
                .arguments
                .insert("target".to_owned(), format!("{target:?}"));
            diagnostic
                .arguments
                .insert("old_kind".to_owned(), format!("{old_kind:?}"));
            diagnostic
                .arguments
                .insert("new_kind".to_owned(), format!("{new_kind:?}"));
            diagnostics.push(diagnostic);
        }
        _ => {}
    }
    let literal = canonical_literal(value)?;
    let validated_kind = validate_exact_scalar(literal.as_bytes())?;
    if validated_kind != new_kind {
        return Err(EditFailure::UnsupportedSemanticValue(value.kind()));
    }
    Ok(literal.into_bytes())
}

fn portable_toml_kind(value: &PortableValue) -> Option<TomlItemKind> {
    match value.kind() {
        PortableValueKind::String => Some(TomlItemKind::String),
        PortableValueKind::Integer => Some(TomlItemKind::Integer),
        PortableValueKind::BinaryFloat64 => Some(TomlItemKind::Float),
        PortableValueKind::Boolean => Some(TomlItemKind::Boolean),
        PortableValueKind::Date => Some(TomlItemKind::LocalDate),
        PortableValueKind::Time => Some(TomlItemKind::LocalTime),
        PortableValueKind::LocalDateTime => Some(TomlItemKind::LocalDateTime),
        PortableValueKind::OffsetDateTime => Some(TomlItemKind::OffsetDateTime),
        _ => None,
    }
}

fn canonical_literal(value: &PortableValue) -> Result<String, EditFailure> {
    match value.kind() {
        PortableValueKind::String => Ok(canonical_string(
            value.as_string().expect("kind checked string"),
        )),
        PortableValueKind::Integer => {
            let integer = value.as_integer().expect("kind checked integer");
            integer
                .to_i64()
                .map(|_| integer.to_string())
                .ok_or(EditFailure::UnsupportedSemanticValue(value.kind()))
        }
        PortableValueKind::BinaryFloat64 => {
            canonical_float(value.as_binary_float64().expect("kind checked binary64"))
                .ok_or(EditFailure::UnsupportedSemanticValue(value.kind()))
        }
        PortableValueKind::Boolean => Ok(value
            .as_boolean()
            .expect("kind checked boolean")
            .to_string()),
        PortableValueKind::Date => canonical_date(value.as_date().expect("kind checked date"))
            .ok_or(EditFailure::UnsupportedSemanticValue(value.kind())),
        PortableValueKind::Time => canonical_time(value.as_time().expect("kind checked time"))
            .ok_or(EditFailure::UnsupportedSemanticValue(value.kind())),
        PortableValueKind::LocalDateTime => {
            let value = value
                .as_local_date_time()
                .expect("kind checked local datetime");
            canonical_local_datetime(value).ok_or(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::LocalDateTime,
            ))
        }
        PortableValueKind::OffsetDateTime => {
            let value = value
                .as_offset_date_time()
                .expect("kind checked offset datetime");
            canonical_offset_datetime(value).ok_or(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::OffsetDateTime,
            ))
        }
        _ => Err(EditFailure::UnsupportedSemanticValue(value.kind())),
    }
}

fn canonical_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len().saturating_add(2));
    output.push('"');
    for character in value.chars() {
        match character {
            '\u{08}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character if character <= '\u{1f}' || character == '\u{7f}' => {
                write!(output, "\\u{:04X}", u32::from(character))
                    .expect("write to String is infallible");
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn canonical_float(value: BinaryFloat64) -> Option<String> {
    let bits = value.bits();
    let float = f64::from_bits(bits);
    if float.is_nan() {
        return match bits {
            0x7ff8_0000_0000_0000 => Some("nan".to_owned()),
            0xfff8_0000_0000_0000 => Some("-nan".to_owned()),
            _ => None,
        };
    }
    if float == f64::INFINITY {
        return Some("inf".to_owned());
    }
    if float == f64::NEG_INFINITY {
        return Some("-inf".to_owned());
    }
    let mut output = float.to_string();
    if !output.contains(['.', 'e', 'E']) {
        output.push_str(".0");
    }
    Some(output)
}

fn canonical_date(value: &Date) -> Option<String> {
    let year = value.year().to_i64()?;
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!("{year:04}-{:02}-{:02}", value.month(), value.day()))
}

fn canonical_time(value: &Time) -> Option<String> {
    let nanoseconds = exact_nanoseconds(value.fractional_second())?;
    let mut output = format!(
        "{:02}:{:02}:{:02}",
        value.hour(),
        value.minute(),
        value.second()
    );
    if nanoseconds != 0 {
        let mut fraction = format!("{nanoseconds:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        output.push('.');
        output.push_str(&fraction);
    }
    Some(output)
}

fn canonical_local_datetime(value: &LocalDateTime) -> Option<String> {
    Some(format!(
        "{}T{}",
        canonical_date(value.date())?,
        canonical_time(value.time())?
    ))
}

fn canonical_offset_datetime(value: &OffsetDateTime) -> Option<String> {
    let mut output = canonical_local_datetime(value.local())?;
    let seconds = value.offset_seconds();
    if seconds == 0 {
        output.push('Z');
        return Some(output);
    }
    if seconds % 60 != 0 {
        return None;
    }
    let minutes = seconds / 60;
    if minutes.unsigned_abs() >= 24 * 60 {
        return None;
    }
    let sign = if minutes < 0 { '-' } else { '+' };
    let magnitude = minutes.unsigned_abs();
    write!(output, "{sign}{:02}:{:02}", magnitude / 60, magnitude % 60)
        .expect("write to String is infallible");
    Some(output)
}

fn exact_nanoseconds(value: &Decimal) -> Option<u32> {
    if value.coefficient().to_i64()? == 0 {
        return Some(0);
    }
    let exponent = value.exponent().to_i64()?;
    if !(-9..0).contains(&exponent) {
        return None;
    }
    let mut nanoseconds = value.coefficient().to_i64()?;
    if nanoseconds < 0 {
        return None;
    }
    for _ in 0..(exponent + 9) {
        nanoseconds = nanoseconds.checked_mul(10)?;
    }
    u32::try_from(nanoseconds)
        .ok()
        .filter(|value| *value < 1_000_000_000)
}

fn find_item_by_span(document: &Document, start: usize, end: usize) -> Option<usize> {
    let mut matches = document
        .entities
        .iter()
        .enumerate()
        .filter(|(_, entity)| {
            matches!(entity.kind, EntityKind::Item(_))
                && entity.span.start_byte() == start
                && entity.span.end_byte() == end
        })
        .map(|(index, _)| index);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TomlProfile, parse};
    use consema_core::{BigInteger, Date, LocalDateTime, OffsetDateTime, PortableValue, Time};
    use consema_document::ParseLimits;

    fn document(source: &[u8]) -> Document {
        parse(source, TomlProfile::Toml10V1, ParseLimits::default()).expect("valid TOML")
    }

    fn root_item(document: &Document, name: &str) -> NodeRef {
        document
            .root()
            .table_entries()
            .expect("root")
            .into_iter()
            .find(|entry| entry.name() == name)
            .expect("entry")
            .item_node_ref()
    }

    #[test]
    fn literal_and_semantic_edits_change_only_scalar_spans() {
        let document = document(b"hex = 0x2A # keep\nname = 'old'\nfloat = 1.0\n");
        let mut builder = EditTransactionBuilder::new(&document);
        builder
            .literal_scalar(root_item(&document, "hex"), b"0x2B".as_slice())
            .semantic_scalar(
                root_item(&document, "name"),
                PortableValue::string("new\nvalue"),
                RepresentationPolicy::PreserveCompatible,
            )
            .semantic_scalar(
                root_item(&document, "float"),
                PortableValue::binary_float64(BinaryFloat64::from_bits((-0.0_f64).to_bits())),
                RepresentationPolicy::PreserveCompatible,
            );
        let commit = document.commit(&builder.build()).expect("atomic commit");
        assert_eq!(
            commit.document.render(),
            b"hex = 0x2B # keep\nname = \"new\\nvalue\"\nfloat = -0.0\n"
        );
        assert_eq!(commit.change_set.source_edits().len(), 3);
        assert_eq!(commit.change_set.node_mappings().len(), 3);
        assert!(
            commit
                .change_set
                .node_mappings()
                .iter()
                .all(|mapping| mapping.new.is_some())
        );
    }

    #[test]
    fn invalid_or_conflicting_transactions_leave_the_base_unchanged() {
        let document = document(b"value = 1\narray = [1, 2]\n");
        let mut incompatible = EditTransactionBuilder::new(&document);
        incompatible.semantic_scalar(
            root_item(&document, "value"),
            PortableValue::string("one"),
            RepresentationPolicy::PreserveCompatible,
        );
        assert_eq!(
            document.commit(&incompatible.build()).unwrap_err(),
            EditFailure::RepresentationIncompatible
        );

        let mut container = EditTransactionBuilder::new(&document);
        container.literal_scalar(root_item(&document, "array"), b"3".as_slice());
        assert_eq!(
            document.commit(&container.build()).unwrap_err(),
            EditFailure::WrongRole
        );

        let target = root_item(&document, "value");
        let mut duplicate = EditTransactionBuilder::new(&document);
        duplicate
            .literal_scalar(target, b"2".as_slice())
            .literal_scalar(target, b"3".as_slice());
        assert_eq!(
            document.commit(&duplicate.build()).unwrap_err(),
            EditFailure::ConflictingEdits
        );
        assert_eq!(document.render(), b"value = 1\narray = [1, 2]\n");
    }

    #[test]
    fn semantic_boundaries_are_rejected_instead_of_rounded() {
        let document = document(b"float = 1.0\ntime = 00:00:00\noffset = 1979-05-27T00:00:00Z\n");
        let mut nan_payload = EditTransactionBuilder::new(&document);
        nan_payload.semantic_scalar(
            root_item(&document, "float"),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0001)),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&nan_payload.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::BinaryFloat64
            ))
        ));

        let date = Date::new(BigInteger::from(1979_i64), 5, 27).expect("date");
        let time = Time::new(
            0,
            0,
            0,
            Decimal::new(BigInteger::from(1_i64), BigInteger::from(-10_i64)),
        )
        .expect("core time");
        let mut precision = EditTransactionBuilder::new(&document);
        precision.semantic_scalar(
            root_item(&document, "time"),
            PortableValue::time(time.clone()),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&precision.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::Time
            ))
        ));

        let offset = OffsetDateTime::new(LocalDateTime::new(date, time), 1).expect("core offset");
        let mut offset_edit = EditTransactionBuilder::new(&document);
        offset_edit.semantic_scalar(
            root_item(&document, "offset"),
            PortableValue::offset_date_time(offset),
            RepresentationPolicy::CanonicalForProfile,
        );
        assert!(matches!(
            document.commit(&offset_edit.build()),
            Err(EditFailure::UnsupportedSemanticValue(
                PortableValueKind::OffsetDateTime
            ))
        ));
    }

    #[test]
    fn exact_literal_rejects_trivia_containers_and_extra_assignments() {
        for literal in [
            b" 2".as_slice(),
            b"2 # comment".as_slice(),
            b"[1, 2]".as_slice(),
            b"2\nother = 3".as_slice(),
        ] {
            assert_eq!(
                validate_exact_scalar(literal),
                Err(EditFailure::InvalidLiteral)
            );
        }
        assert_eq!(validate_exact_scalar(b"0x2A"), Ok(TomlItemKind::Integer));
        assert_eq!(
            validate_exact_scalar(br#""multi\nline""#),
            Ok(TomlItemKind::String)
        );
    }
}
