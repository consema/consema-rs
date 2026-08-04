use crate::{Document, InternalValueKind, JsonProfile, JsonValueKind, SemanticAvailability, parse};
use consema_core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, PortableValue, PortableValueKind,
};
use consema_document::{
    ChangeSet, NodeMapping, NodeMappingStatus, NodeRef, NodeRole, SnapshotIdentity, SourceEdit,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Explicit semantic scalar representation policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentationPolicy {
    /// Caller must instead use `LiteralScalarReplacement`; semantic replacement rejects this.
    ExactLiteral,
    /// Preserve the target's compatible native scalar category or fail.
    PreserveCompatible,
    /// Use deterministic profile-canonical JSON literal syntax.
    CanonicalForProfile,
    /// Try category preservation, then explicitly report canonical fallback.
    PreserveElseCanonical,
}

/// One scalar operation bound to the transaction's base snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarReplacement {
    /// Replace by public semantic value under an explicit representation policy.
    Semantic {
        /// Exact target NodeRef.
        target: NodeRef,
        /// New complete core scalar.
        value: PortableValue,
        /// Representation contract.
        policy: RepresentationPolicy,
    },
    /// Replace by exact candidate literal bytes after full profile validation.
    Literal {
        /// Exact target NodeRef.
        target: NodeRef,
        /// Exact candidate bytes.
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

    /// Adds semantic scalar replacement.
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

    /// Adds exact literal scalar replacement.
    pub fn literal_scalar(&mut self, target: NodeRef, literal: impl Into<Arc<[u8]>>) -> &mut Self {
        self.operations.push(ScalarReplacement::Literal {
            target,
            literal: literal.into(),
        });
        self
    }

    /// Completes the immutable request; target validation happens atomically at commit.
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
    /// Target role is not a scalar value or object key.
    WrongRole,
    /// Target is not a complete literal syntax node.
    IncompleteTarget,
    /// Target native semantics are unavailable.
    SemanticUnavailable,
    /// Public value cannot be represented as a JSON scalar.
    UnsupportedSemanticValue(PortableValueKind),
    /// Exact candidate is not one complete legal scalar literal for the profile.
    InvalidLiteral,
    /// PreserveCompatible could not retain the scalar category.
    RepresentationIncompatible,
    /// ExactLiteral was incorrectly requested without literal bytes.
    ExactLiteralRequiresLiteralOperation,
    /// Two source edits overlap or target the same scalar.
    ConflictingEdits,
    /// Replacement document could not be formed under the original limits.
    NewDocumentFormationFailed,
}

impl Document {
    /// Atomically commits scalar replacements. On failure `self` remains the only snapshot.
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
            if !matches!(target.role(), NodeRole::Value | NodeRole::ObjectKey) {
                return Err(EditFailure::WrongRole);
            }
            let index = self
                .validate_ref(target, &[NodeRole::Value, NodeRole::ObjectKey])
                .map_err(|error| match error {
                    crate::JsonAccessError::WrongSnapshot => EditFailure::WrongSnapshot,
                    crate::JsonAccessError::WrongRole | crate::JsonAccessError::UnknownNode => {
                        EditFailure::WrongRole
                    }
                })?;
            let entity = self.value_entity(index);
            if !entity.complete || entity.literal_span.is_none() {
                return Err(EditFailure::IncompleteTarget);
            }
            if matches!(entity.kind, InternalValueKind::Unavailable(_)) {
                return Err(EditFailure::SemanticUnavailable);
            }
            if matches!(
                entity.kind,
                InternalValueKind::Array(_) | InternalValueKind::Object(_)
            ) {
                return Err(EditFailure::WrongRole);
            }
            let replacement = match operation {
                ScalarReplacement::Literal { literal, .. } => {
                    let literal_kind = validate_literal(literal, self.profile, self.parse_limits)?;
                    if target.role() == NodeRole::ObjectKey && literal_kind != JsonValueKind::String
                    {
                        return Err(EditFailure::InvalidLiteral);
                    }
                    literal.to_vec()
                }
                ScalarReplacement::Semantic { value, policy, .. } => {
                    if target.role() == NodeRole::ObjectKey
                        && value.kind() != PortableValueKind::String
                    {
                        return Err(EditFailure::UnsupportedSemanticValue(value.kind()));
                    }
                    let old_span = entity.literal_span.expect("checked literal span");
                    let old_literal =
                        &self.source.bytes()[old_span.start_byte()..old_span.end_byte()];
                    semantic_literal(
                        value,
                        &entity.kind,
                        old_literal,
                        *policy,
                        target,
                        &mut diagnostics,
                    )?
                }
            };
            prepared.push(PreparedEdit {
                target,
                old_span: entity.literal_span.expect("checked literal span"),
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
            let new_ref = find_value_by_literal_span(&new_document, new_start, new_end)
                .map(|index| new_document.node_ref(index, edit.target.role()));
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
                    .then(|| "reparsed-node-not-uniquely-located".to_owned()),
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

impl consema_core::StableFailure for EditFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Edit
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::WrongSnapshot => consema_core::FailureKind::TargetMismatch,
            Self::WrongRole
            | Self::IncompleteTarget
            | Self::SemanticUnavailable
            | Self::InvalidLiteral
            | Self::ExactLiteralRequiresLiteralOperation => consema_core::FailureKind::InvalidInput,
            Self::UnsupportedSemanticValue(_) => consema_core::FailureKind::Unsupported,
            Self::RepresentationIncompatible => consema_core::FailureKind::NotApplicable,
            Self::ConflictingEdits => consema_core::FailureKind::InvalidInput,
            Self::NewDocumentFormationFailed => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::WrongSnapshot => "core.edit.wrong-snapshot@1",
            Self::WrongRole => "core.edit.wrong-role@1",
            Self::IncompleteTarget => "core.edit.incomplete-target@1",
            Self::SemanticUnavailable => "core.edit.semantic-unavailable@1",
            Self::UnsupportedSemanticValue(_) => "core.edit.unsupported-value@1",
            Self::InvalidLiteral => "core.edit.invalid-literal@1",
            Self::RepresentationIncompatible => "core.edit.representation-incompatible@1",
            Self::ExactLiteralRequiresLiteralOperation => {
                "core.edit.exact-literal-requires-literal@1"
            }
            Self::ConflictingEdits => "core.edit.conflicting-edits@1",
            Self::NewDocumentFormationFailed => "core.edit.formation-failed@1",
        }
    }
}

struct PreparedEdit {
    target: NodeRef,
    old_span: consema_document::Span,
    replacement: Vec<u8>,
}

fn semantic_literal(
    value: &PortableValue,
    old: &InternalValueKind,
    old_literal: &[u8],
    policy: RepresentationPolicy,
    target: NodeRef,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<u8>, EditFailure> {
    if policy == RepresentationPolicy::ExactLiteral {
        return Err(EditFailure::ExactLiteralRequiresLiteralOperation);
    }
    portable_json_kind(value).ok_or_else(|| EditFailure::UnsupportedSemanticValue(value.kind()))?;
    let preserved = analyze_lexical_style(old_literal, old)
        .and_then(|style| render_preserving_style(value, &style));
    match policy {
        RepresentationPolicy::PreserveCompatible => {
            preserved.ok_or(EditFailure::RepresentationIncompatible)
        }
        RepresentationPolicy::CanonicalForProfile => canonical_literal(value),
        RepresentationPolicy::PreserveElseCanonical => match preserved {
            Some(bytes) => Ok(bytes),
            None => {
                let mut diagnostic = Diagnostic::new(
                    "json.edit.representation-fallback@1",
                    DiagnosticCategory::Edit,
                    DiagnosticSeverity::Warning,
                    None,
                    diagnostics.len() as u64,
                );
                diagnostic
                    .arguments
                    .insert("target".to_owned(), format!("{target:?}"));
                diagnostics.push(diagnostic);
                canonical_literal(value)
            }
        },
        RepresentationPolicy::ExactLiteral => {
            unreachable!("ExactLiteral is rejected before matching")
        }
    }
}

/// Maximum digits a preserved fixed-fraction rendering may produce.
const MAX_PRESERVED_FRACTION_DIGITS: usize = 1_000_000;

/// Bounded lexical style retained by `PreserveCompatible` edits.
///
/// v1 preserves: integer digit form; decimal fraction digit count and
/// exponent marker case / explicit plus sign; per-character string escape
/// choices. A decimal literal that mixes a fraction and an exponent keeps
/// the fraction scale and absorbs the exponent into the fixed form.
#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonScalarLexicalStyle {
    Null,
    Boolean,
    Integer,
    Decimal(DecimalLexicalStyle),
    String(StringLexicalStyle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecimalLexicalStyle {
    fraction_scale: Option<usize>,
    exponent_marker: Option<u8>,
    explicit_plus: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct StringLexicalStyle {
    escapes: HashMap<char, String>,
}

fn analyze_lexical_style(
    literal: &[u8],
    old: &InternalValueKind,
) -> Option<JsonScalarLexicalStyle> {
    match old {
        InternalValueKind::Null => Some(JsonScalarLexicalStyle::Null),
        InternalValueKind::Boolean(_) => Some(JsonScalarLexicalStyle::Boolean),
        InternalValueKind::Integer(_) => Some(JsonScalarLexicalStyle::Integer),
        InternalValueKind::Decimal(_) => {
            let text = std::str::from_utf8(literal).ok()?;
            let fraction_scale = text
                .find('.')
                .map(|index| text.len().saturating_sub(index + 1));
            let exponent_index = text.find(['e', 'E']);
            let (exponent_marker, explicit_plus) = match exponent_index {
                Some(index) => {
                    let plus = text.as_bytes().get(index + 1) == Some(&b'+');
                    (Some(text.as_bytes()[index]), plus)
                }
                None => (None, false),
            };
            Some(JsonScalarLexicalStyle::Decimal(DecimalLexicalStyle {
                fraction_scale,
                exponent_marker,
                explicit_plus,
            }))
        }
        InternalValueKind::String(_) => {
            let mut style = StringLexicalStyle::default();
            let bytes = literal;
            let mut index = 1;
            while index + 1 < bytes.len() {
                if bytes[index] != b'\\' {
                    index += 1;
                    continue;
                }
                let escape_start = index;
                index += 1;
                let Some(&kind_byte) = bytes.get(index) else {
                    break;
                };
                index += 1;
                match kind_byte {
                    b'"' => {
                        style.escapes.insert('"', "\\\"".to_owned());
                    }
                    b'\\' => {
                        style.escapes.insert('\\', "\\\\".to_owned());
                    }
                    b'/' => {
                        style.escapes.insert('/', "\\/".to_owned());
                    }
                    b'b' => {
                        style.escapes.insert('\u{0008}', "\\b".to_owned());
                    }
                    b'f' => {
                        style.escapes.insert('\u{000c}', "\\f".to_owned());
                    }
                    b'n' => {
                        style.escapes.insert('\n', "\\n".to_owned());
                    }
                    b'r' => {
                        style.escapes.insert('\r', "\\r".to_owned());
                    }
                    b't' => {
                        style.escapes.insert('\t', "\\t".to_owned());
                    }
                    b'u' => {
                        let Some(hex) = bytes.get(index..index + 4) else {
                            break;
                        };
                        let Some(value) =
                            u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
                        else {
                            break;
                        };
                        index += 4;
                        let text = std::str::from_utf8(&bytes[escape_start..index])
                            .ok()?
                            .to_owned();
                        if (0xd800..=0xdbff).contains(&value)
                            && bytes.get(index) == Some(&b'\\')
                            && bytes.get(index + 1) == Some(&b'u')
                        {
                            let low_start = index + 2;
                            if let Some(low_value) = bytes
                                .get(low_start..low_start + 4)
                                .and_then(|low| std::str::from_utf8(low).ok())
                                .and_then(|low| u32::from_str_radix(low, 16).ok())
                            {
                                if (0xdc00..=0xdfff).contains(&low_value) {
                                    let combined =
                                        0x1_0000 + ((value - 0xd800) << 10) + (low_value - 0xdc00);
                                    if let Some(character) = char::from_u32(combined) {
                                        index += 6;
                                        let pair = std::str::from_utf8(&bytes[escape_start..index])
                                            .ok()?
                                            .to_owned();
                                        style.escapes.insert(character, pair);
                                        continue;
                                    }
                                }
                            }
                        }
                        if let Some(character) = char::from_u32(value) {
                            style.escapes.insert(character, text);
                        }
                    }
                    _ => break,
                }
            }
            Some(JsonScalarLexicalStyle::String(style))
        }
        InternalValueKind::Array(_)
        | InternalValueKind::Object(_)
        | InternalValueKind::Unavailable(_) => None,
    }
}

fn render_preserving_style(
    value: &PortableValue,
    style: &JsonScalarLexicalStyle,
) -> Option<Vec<u8>> {
    match style {
        JsonScalarLexicalStyle::Null if value.kind() == PortableValueKind::Null => {
            Some(b"null".to_vec())
        }
        JsonScalarLexicalStyle::Boolean if value.kind() == PortableValueKind::Boolean => {
            Some(value.as_boolean()?.to_string().into_bytes())
        }
        JsonScalarLexicalStyle::Integer if value.kind() == PortableValueKind::Integer => {
            Some(value.as_integer()?.to_string().into_bytes())
        }
        JsonScalarLexicalStyle::Decimal(style)
            if matches!(
                value.kind(),
                PortableValueKind::Decimal | PortableValueKind::Integer
            ) =>
        {
            render_decimal_style(value, style)
        }
        JsonScalarLexicalStyle::String(style) if value.kind() == PortableValueKind::String => {
            Some(render_string_style(value.as_string()?, style).into_bytes())
        }
        _ => None,
    }
}

fn render_decimal_style(value: &PortableValue, style: &DecimalLexicalStyle) -> Option<Vec<u8>> {
    let coefficient = match value.kind() {
        PortableValueKind::Decimal => value.as_decimal()?.coefficient(),
        PortableValueKind::Integer => value.as_integer()?,
        _ => return None,
    };
    let exponent = match value.kind() {
        PortableValueKind::Decimal => value.as_decimal()?.exponent(),
        PortableValueKind::Integer => &consema_core::BigInteger::zero(),
        _ => return None,
    };
    if let Some(scale) = style.fraction_scale {
        let shift = match exponent.to_i64() {
            Some(shift) if shift >= 0 => (shift as usize).checked_add(scale)?,
            Some(negative) => scale.checked_sub(negative.unsigned_abs() as usize)?,
            None => return None,
        };
        if shift > MAX_PRESERVED_FRACTION_DIGITS {
            return None;
        }
        let mantissa = coefficient.mul_pow10(shift);
        return Some(decimal_fixed_text(&mantissa, scale).into_bytes());
    }
    if let Some(marker) = style.exponent_marker {
        let mut output = coefficient.to_string();
        output.push(marker as char);
        let exponent = exponent.to_string();
        if !exponent.starts_with('-') && style.explicit_plus {
            output.push('+');
        }
        output.push_str(&exponent);
        return Some(output.into_bytes());
    }
    None
}

fn decimal_fixed_text(mantissa: &consema_core::BigInteger, scale: usize) -> String {
    let text = mantissa.to_string();
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text.as_str()),
    };
    if digits.len() <= scale {
        format!("{sign}0.{}{}", "0".repeat(scale - digits.len()), digits)
    } else {
        let split = digits.len() - scale;
        format!("{sign}{}.{}", &digits[..split], &digits[split..])
    }
}

fn render_string_style(value: &str, style: &StringLexicalStyle) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        if let Some(escape) = style.escapes.get(&character) {
            output.push_str(escape);
        } else {
            push_json_char(&mut output, character);
        }
    }
    output.push('"');
    output
}

fn portable_json_kind(value: &PortableValue) -> Option<JsonValueKind> {
    match value.kind() {
        PortableValueKind::Null => Some(JsonValueKind::Null),
        PortableValueKind::Boolean => Some(JsonValueKind::Boolean),
        PortableValueKind::Integer => Some(JsonValueKind::Integer),
        PortableValueKind::Decimal => Some(JsonValueKind::Decimal),
        PortableValueKind::String => Some(JsonValueKind::String),
        _ => None,
    }
}

fn canonical_literal(value: &PortableValue) -> Result<Vec<u8>, EditFailure> {
    let text = match value.kind() {
        PortableValueKind::Null => "null".to_owned(),
        PortableValueKind::Boolean => value.as_boolean().expect("boolean kind").to_string(),
        PortableValueKind::Integer => value.as_integer().expect("integer kind").to_string(),
        PortableValueKind::Decimal => {
            let value = value.as_decimal().expect("decimal kind");
            format!("{}e{}", value.coefficient(), value.exponent())
        }
        PortableValueKind::String => encode_json_string(value.as_string().expect("string kind")),
        kind => return Err(EditFailure::UnsupportedSemanticValue(kind)),
    };
    Ok(text.into_bytes())
}

fn encode_json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        push_json_char(&mut output, character);
    }
    output.push('"');
    output
}

fn push_json_char(output: &mut String, character: char) {
    match character {
        '"' => output.push_str("\\\""),
        '\\' => output.push_str("\\\\"),
        '\u{0008}' => output.push_str("\\b"),
        '\u{000c}' => output.push_str("\\f"),
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        '\u{0000}'..='\u{001f}' => {
            use std::fmt::Write;
            write!(output, "\\u{:04X}", u32::from(character)).expect("String write");
        }
        _ => output.push(character),
    }
}

fn validate_literal(
    literal: &[u8],
    profile: JsonProfile,
    limits: consema_document::ParseLimits,
) -> Result<JsonValueKind, EditFailure> {
    if literal.is_empty() || std::str::from_utf8(literal).is_err() {
        return Err(EditFailure::InvalidLiteral);
    }
    let document = parse(literal, profile, limits).map_err(|_| EditFailure::InvalidLiteral)?;
    let kind = document.root().kind();
    if document.formation_status() != consema_document::FormationStatus::Complete
        || document.root().span().start_byte() != 0
        || document.root().span().end_byte() != literal.len()
        || !matches!(
            kind,
            SemanticAvailability::Available(
                JsonValueKind::Null
                    | JsonValueKind::Boolean
                    | JsonValueKind::Integer
                    | JsonValueKind::Decimal
                    | JsonValueKind::String
            )
        )
    {
        return Err(EditFailure::InvalidLiteral);
    }
    match kind {
        SemanticAvailability::Available(kind) => Ok(kind),
        SemanticAvailability::Unavailable(_) => Err(EditFailure::InvalidLiteral),
    }
}

fn find_value_by_literal_span(document: &Document, start: usize, end: usize) -> Option<usize> {
    let mut matches =
        document
            .entities
            .iter()
            .enumerate()
            .filter_map(|(index, entity)| match entity {
                crate::Entity::Value(value)
                    if value.literal_span.is_some_and(|span| {
                        span.start_byte() == start && span.end_byte() == end
                    }) =>
                {
                    Some(index)
                }
                _ => None,
            });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsonProfile, parse};
    use consema_core::{BigInteger, Decimal, PortableValue};
    use consema_document::ParseLimits;

    #[test]
    fn semantic_edit_changes_only_literal_and_keeps_trivia() {
        let document = parse(
            b"{ /* lead */ \"a\" : 1 // tail\n}".as_slice(),
            JsonProfile::JsoncBoundedV1,
            ParseLimits::default(),
        )
        .unwrap();
        let member = match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0],
            _ => panic!("missing member"),
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member.value_node_ref(),
            PortableValue::integer(BigInteger::from(200_i64)),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(
            commit.document.render(),
            b"{ /* lead */ \"a\" : 200 // tail\n}"
        );
        assert_eq!(commit.change_set.source_edits().len(), 1);
        assert_ne!(
            document.snapshot_identity(),
            commit.document.snapshot_identity()
        );
    }

    #[test]
    fn wrong_snapshot_is_rejected_atomically() {
        let first = parse(
            b"1".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let second = parse(
            b"2".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&second);
        builder.literal_scalar(first.root().node_ref(), b"3".as_slice());
        assert!(matches!(
            second.commit(&builder.build()),
            Err(EditFailure::WrongSnapshot)
        ));
        assert_eq!(second.render(), b"2");
    }

    #[test]
    fn object_key_replacement_must_remain_a_string() {
        let document = parse(
            br#"{"a":1}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let member = match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0],
            _ => panic!("missing member"),
        };
        let mut builder = EditTransactionBuilder::new(&document);
        builder.literal_scalar(member.key_node_ref(), b"2".as_slice());
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::InvalidLiteral)
        ));
        assert_eq!(document.render(), br#"{"a":1}"#);
    }

    fn member_value_ref(document: &Document) -> NodeRef {
        match document.root().object_members() {
            SemanticAvailability::Available(Some(members)) => members[0].value_node_ref(),
            _ => panic!("missing member"),
        }
    }

    #[test]
    fn preserve_compatible_keeps_decimal_fraction_scale() {
        let document = parse(
            br#"{"a": 1.00}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(25_i64),
                BigInteger::from(-1_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 2.50}"#);
    }

    #[test]
    fn preserve_compatible_keeps_exponent_marker_and_sign() {
        let document = parse(
            br#"{"a": 1E+02}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::integer(BigInteger::from(2_i64)),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 2E+0}"#);
    }

    #[test]
    fn preserve_compatible_rejects_unrepresentable_fraction_scale() {
        let document = parse(
            br#"{"a": 1.000}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(-4_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::RepresentationIncompatible)
        ));
        assert_eq!(document.render(), br#"{"a": 1.000}"#);
    }

    #[test]
    fn preserve_compatible_keeps_string_escape_style() {
        let document = parse(
            br#"{"a": "a\u0041"}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::string("xA"),
            RepresentationPolicy::PreserveCompatible,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": "x\u0041"}"#);
    }

    #[test]
    fn canonical_for_profile_is_independent_of_old_spelling() {
        let document = parse(
            br#"{"a": 1.00}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(25_i64),
                BigInteger::from(-1_i64),
            )),
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 25e-1}"#);
    }

    #[test]
    fn preserve_else_canonical_reports_actual_fallback() {
        let document = parse(
            br#"{"a": 1.000}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(-4_i64),
            )),
            RepresentationPolicy::PreserveElseCanonical,
        );
        let commit = document.commit(&builder.build()).unwrap();
        assert_eq!(commit.document.render(), br#"{"a": 1e-4}"#);
        assert_eq!(
            commit
                .change_set
                .diagnostics()
                .iter()
                .filter(|item| item.code == "json.edit.representation-fallback@1")
                .count(),
            1
        );
    }

    #[test]
    fn preserve_compatible_rejects_category_change() {
        let document = parse(
            br#"{"a": 1}"#.as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut builder = EditTransactionBuilder::new(&document);
        builder.semantic_scalar(
            member_value_ref(&document),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(0_i64),
            )),
            RepresentationPolicy::PreserveCompatible,
        );
        assert!(matches!(
            document.commit(&builder.build()),
            Err(EditFailure::RepresentationIncompatible)
        ));
    }
}
