//! Canonical `hcl.canonical-document@1` materialization (RFC 0014 §9).
//!
//! Materialization consumes one validated `hcl.body@1` record and creates a
//! new `hcl.native@1` or `hcl.tfvars@1` Document. It is not a formatter for
//! an existing source: the input is the projected body record, the output is
//! a new snapshot whose complete native model equals the promised input
//! semantics (RFC 0014 §9).
//!
//! # Record contract
//!
//! The input must be an Object record:
//!
//! ```text
//! { "record": "hcl.body@1",
//!   "items": [ <item>, ... ] }
//! ```
//!
//! An item is an Object with a string `kind`:
//!
//! ```text
//! attribute  { "kind": "attribute", "name": <String>, "value": <value> }
//! block      { "kind": "block", "type": <String>,
//!              "labels": [ <String>, ... ], "body": <hcl.body@1> }
//! ```
//!
//! Attribute names and block types must be valid UAX #31 identifiers (the
//! frozen `Identifier = ID_Start (ID_Continue | "-")*` rule of RFC 0014
//! §4.1); anything else is unrepresentable. A body with two attributes of
//! the same name is unrepresentable, because the per-body
//! duplicate-attribute rule of RFC 0014 §3 admits no Complete document with
//! duplicates.
//!
//! A value record is an Object with a string `kind`:
//!
//! ```text
//! string      { "kind": "string",  "text": <String> }
//! integer     { "kind": "integer", "value": <Integer> }
//! real        { "kind": "real",    "value": <Decimal|BinaryFloat64|BinaryFloat32> }
//! boolean     { "kind": "boolean", "value": <Boolean> }
//! null        { "kind": "null" }
//! tuple       { "kind": "tuple",   "elements": [ <value>, ... ] }
//! object      { "kind": "object",  "entries": [ [<String>, <value>], ... ] }
//! expression  { "kind": "expression",
//!               "expression": <hcl.expression@1 record> }
//! ```
//!
//! The RFC 0014 §8.2 typed member itself is also accepted as the attribute
//! `value`: a raw string, integer, real (decimal or binary float), boolean,
//! null, tuple, or object PortableValue exactly as the body projection
//! publishes it, and the `hcl.expression@1` record object of a derived
//! expression:
//!
//! ```text
//! string      <String>
//! integer     <Integer>
//! real        <Decimal|BinaryFloat64|BinaryFloat32>
//! boolean     <Boolean>
//! null        null
//! tuple       [ <value>, ... ]
//! object      <EntryMapping>        keys as strings, duplicates preserved
//! expression  { "record": "hcl.expression@1",
//!               "kind": <String>, "text": <String>,
//!               "fingerprint"?: <String> }
//! ```
//!
//! Integers are arbitrary precision and emit their exact decimal digits;
//! reals are the exact canonical decimal of the payload (a `Decimal` emits
//! its plain normalized spelling, a binary float its exact decimal
//! expansion), so `1.50` and `15e-1` both materialize as `1.5` (RFC 0014
//! §9). A non-finite binary float is unrepresentable.
//!
//! The `hcl.expression@1` record is the authorized ExtendedValue of a
//! derived expression (RFC 0014 §8.2):
//!
//! ```text
//! { "record": "hcl.expression@1",
//!   "kind": <String>, "text": <String>,
//!   "fingerprint"?: <String> }
//! ```
//!
//! The `text` is the exact source text of the expression and is emitted
//! verbatim. Validation parses it standalone and requires the parse to form
//! one complete expression whose structural kind spelling matches the
//! record's `kind`; a malformed or mismatched record is invalid. The
//! optional `fingerprint` field, when present, must equal the structural
//! fingerprint of that parsed expression. The fingerprint is the hex of a
//! 64-bit FNV-1a hash over the canonical structural serialization of the
//! expression (kind, children, canonical decimals, exact literal texts,
//! operator spellings, heredoc mode and marker); it is the shared
//! M6/M7 adaptation point of the `hcl.expression@1` codec and is stable
//! across snapshots because spans and identities are never part of it.
//!
//! # Request contract
//!
//! - `hcl.canonical-document@1` targets profile `hcl.native@1` or
//!   `hcl.tfvars@1`; the target profile selects the reparse profile and the
//!   tfvars structural rule: a record containing a block fails
//!   `hcl.materialization.unrepresentable@1` for the tfvars target (RFC
//!   0014 §5, §9).
//! - The style emits UTF-8 without BOM, so the encoding must be `Utf8`;
//!   the style emits LF line endings, so the newline policy must be `Lf`.
//!
//! Any other profile, style, encoding, or newline is an unsupported failure.
//!
//! # Canonical layout (RFC 0014 §9)
//!
//! The emitted document uses two-space indentation per body nesting level,
//! `name = value` attributes, block headers as `type "label" {`, and a
//! trailing newline after the final item. Strings re-quote with double
//! quotes and minimal deterministic escapes (`\n`, `\r`, `\t`, `\"`, `\\`,
//! `\uNNNN` for control characters, and `$${`/`%%{` for the template
//! openers so the decoded text is exact); numbers emit their canonical
//! decimal spelling; booleans and null emit `true`, `false`, and `null`;
//! tuples and objects emit with a deterministic one-item-per-line layout at
//! the chosen indentation — tuples with a trailing comma per element, objects
//! with newline-separated `key = value` entries, both closing on a line of
//! their own — and empty constructors stay single-line (`[]`/`{}`); object
//! keys emit bare when the key is a plain identifier other than the
//! contextual `for`, else quoted with the same escaping; block labels are
//! always quoted; `hcl.expression@1` values emit their canonical text
//! verbatim.
//!
//! # Failure mapping (contract for the conformance runner)
//!
//! Every failure is a shared `MaterializationFailure`; the HCL suite maps it
//! to an `hcl.materialization.*@1` code:
//!
//! ```text
//! Unrepresentable { .. }          -> hcl.materialization.unrepresentable@1
//! ResourceLimit(name)             -> hcl.materialization.resource-limit@1
//! InvalidRequest / Unsupported* / FormationFailed
//!                                  -> core.materialization.*@1 (shared codes)
//! ```
//!
//! Unrepresentable inputs are the tfvars block restriction, invalid
//! attribute names and block types, duplicate attributes in one body,
//! non-finite real payloads, and record shapes that cannot be expressed.
//!
//! # Provenance
//!
//! One provenance entry maps every input item, attribute value, block label,
//! and the root record to its exact output origin: the whole document span
//! for the root (`NodeRole::HclDocument`), the attribute's name-through-
//! expression span (`NodeRole::HclAttribute`), the value expression span
//! (`NodeRole::HclExpression`), the block span (`NodeRole::HclBlock`), and
//! each label span (`NodeRole::HclBlockLabel`), in pre-order with arena
//! ordinals assigned in the same order. Relations are `Direct`.
//!
//! # Closure
//!
//! Every materialization validates the complete input before proportional
//! allocation, encodes, reparses the exact generated bytes under the
//! promised Profile, and walks the reparsed native model in lockstep with
//! the record — numbers by canonical-decimal value equality, strings and
//! object keys by exact decoded text, constructors element-wise,
//! `hcl.expression@1` values by structural equality plus fingerprint
//! equality (RFC 0014 §6, §9). Failure returns no target Document, partial
//! bytes, or partial provenance. The reparse uses limits derived from the
//! request so a bounded input cannot fail its own closure.
//!
//! The module is not yet re-exported from the crate root (the M5-M8 parallel
//! milestones land their `pub use` wiring together); this attribute is the
//! shared adaptation-point pattern of the parallel milestone files and is
//! removed when the crate root exports land.
use crate::expression::{
    HclDirectiveKind, HclExpression, HclExpressionKind, HclForIntro, HclObjectKey, HclTemplatePart,
    HclTraversalRoot, HclTraversalStep, UnaryOp, canonical_decimal,
};
use crate::native::HclBody;
use crate::{Document, HclBodyItem, HclParseLimits, HclProfile};
use consema_core::{Decimal, PortableValue, PortableValueKind, ValuePath, ValuePathSegment};
use consema_document::{
    CompleteMaterialization, FailedMaterializationAttempt, FormationStatus, MaterializationFailure,
    MaterializationFidelity, MaterializationInputLocation, MaterializationLimits,
    MaterializationProvenanceEntry, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationResult, MaterializedOrigin,
    NewlinePolicy, NodeRole, ParseLimits, ProfileId, SourceEncoding, Span,
};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::Arc;

/// Style identifier `hcl.canonical-document` (RFC 0014 §9).
const STYLE_CANONICAL: &str = "hcl.canonical-document";
/// Versioned body record name (RFC 0014 §8.2).
const BODY_RECORD: &str = "hcl.body@1";
/// Versioned expression record name (RFC 0014 §8.2).
const EXPRESSION_RECORD: &str = "hcl.expression@1";
/// Sentinel attribute name of the standalone expression parse; any text
/// that would parse into an additional body item is not one expression.
const SENTINEL_ATTRIBUTE: &str = "expr";

/// The canonical materialization style (RFC 0014 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    /// `hcl.native@1`: any body is representable.
    Native,
    /// `hcl.tfvars@1`: attribute-only records only (RFC 0014 §5, §9).
    Tfvars,
}

/// Materializes one `hcl.body@1` record into a new canonical HCL document
/// (RFC 0014 §9).
///
/// The requested profile selects the output semantics: `hcl.tfvars@1`
/// rejects any record containing a block with
/// `hcl.materialization.unrepresentable@1`. The generated bytes are reparsed
/// under the promised Profile and the reparsed native model is compared to
/// the promised input semantics; failure returns no target Document, no
/// partial bytes, and no partial provenance.
#[must_use]
pub fn materialize(
    value: &PortableValue,
    request: &MaterializationRequest,
) -> MaterializationResult<Document> {
    let mut analyzed = Vec::new();
    match materialize_complete(value, request, &mut analyzed) {
        Ok(complete) => MaterializationResult::Complete(complete),
        Err(failure) => MaterializationResult::Failed(FailedMaterializationAttempt {
            failure,
            report: MaterializationReport::default(),
            analyzed_input_paths: analyzed,
        }),
    }
}

fn materialize_complete(
    value: &PortableValue,
    request: &MaterializationRequest,
    analyzed: &mut Vec<ValuePath>,
) -> Result<CompleteMaterialization<Document>, MaterializationFailure> {
    let target = validate_request(request)?;
    let limits = request.limits();
    let record = Record::validate(value, request, analyzed)?;
    let mut writer = Writer {
        out: String::new(),
        limits,
    };
    write_body(&mut writer, &record.body, 0)?;
    let bytes = writer.out.into_bytes();
    let profile = match target {
        Target::Native => HclProfile::NativeV1,
        Target::Tfvars => HclProfile::TfvarsV1,
    };
    let document = crate::parse(
        Arc::<[u8]>::from(bytes),
        profile,
        crate::HclEncodingSelection::ProfileDefault,
        parse_limits(limits),
    )
    .map_err(|_| MaterializationFailure::FormationFailed)?;
    if document.status() != FormationStatus::Complete {
        return Err(MaterializationFailure::FormationFailed);
    }
    let provenance = verify_closure(&record, &document, limits)?;
    let report = MaterializationReport::new(Vec::new(), limits)?;
    Ok(CompleteMaterialization {
        document,
        fidelity: MaterializationFidelity::Exact,
        report,
        provenance,
    })
}

/// Validates the request against the frozen style contract (RFC 0014 §9).
fn validate_request(request: &MaterializationRequest) -> Result<Target, MaterializationFailure> {
    let profile = request.target_profile();
    let style = request.style();
    let target = match (profile.id(), profile.version(), style.id(), style.version()) {
        ("hcl.native", 1, STYLE_CANONICAL, 1) => Target::Native,
        ("hcl.tfvars", 1, STYLE_CANONICAL, 1) => Target::Tfvars,
        (id, version, _, _) if (id != "hcl.native" && id != "hcl.tfvars") || version != 1 => {
            return Err(MaterializationFailure::UnsupportedProfile);
        }
        _ => return Err(MaterializationFailure::UnsupportedStyle),
    };
    if request.encoding() != SourceEncoding::Utf8 {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    if request.newline() != NewlinePolicy::Lf {
        return Err(MaterializationFailure::UnsupportedNewline);
    }
    Ok(target)
}

/// Parse limits for the closure reparse, derived from the request so a
/// bounded input cannot fail its own closure.
///
/// The emitted document provably satisfies every bound: the source is the
/// output byte budget, body and expression nesting stay within the record's
/// container depth budget plus two (the root body and the unary-minus
/// wrapper of a negative number), item and label counts stay within the
/// input node budget, and every other bound derives from the output bytes.
const fn parse_limits(limits: MaterializationLimits) -> HclParseLimits {
    HclParseLimits {
        common: ParseLimits {
            max_source_bytes: limits.max_output_bytes,
            max_nesting_depth: limits.max_depth.saturating_add(2),
            max_token_count: limits.max_output_bytes,
            max_node_count: limits.max_output_bytes,
            max_diagnostics: limits.max_report_entries,
        },
        max_decoded_utf8_bytes: limits.max_output_bytes.saturating_mul(3),
        max_decoded_scalars: limits.max_output_bytes,
        max_body_depth: limits.max_depth.saturating_add(2),
        max_expression_depth: limits.max_depth.saturating_add(2),
        max_template_depth: limits.max_depth.saturating_add(2),
        max_attribute_count: limits.max_input_nodes,
        max_block_count: limits.max_input_nodes,
        max_label_count: limits.max_input_nodes,
        max_body_item_count: limits.max_input_nodes.saturating_mul(2),
        max_identifier_len: limits.max_output_bytes,
        max_string_len: limits.max_output_bytes,
        max_number_digits: limits.max_output_bytes,
        max_template_len: limits.max_output_bytes,
        max_template_interpolations: limits.max_input_nodes,
        max_heredoc_lines: limits.max_output_bytes,
        max_heredoc_bytes: limits.max_output_bytes,
        max_tuple_elements: limits.max_input_nodes,
        max_object_entries: limits.max_input_nodes,
        max_for_extent: limits.max_input_nodes,
        max_recovery_regions: limits.max_report_entries,
        max_error_regions: limits.max_report_entries,
        max_syntax_pieces: limits.max_output_bytes,
        max_report_events: limits.max_report_entries,
    }
}

/// Parse limits for one standalone expression-text parse, derived from the
/// text length so a bounded text cannot fail its own parse.
///
/// The wrapper source is exactly `text.len() + 8` bytes. The expression
/// depth is the record's container depth budget plus two, so an accepted
/// text can never overflow the closure reparse of the emitted document; the
/// canonical-decimal digit budget is the output byte budget, matching the
/// closure reparse. Every other bound derives from the wrapper size.
fn promised_expression_limits(text_len: usize, limits: MaterializationLimits) -> HclParseLimits {
    let source = text_len.saturating_add(8);
    HclParseLimits {
        common: ParseLimits {
            max_source_bytes: source,
            max_nesting_depth: limits.max_depth.saturating_add(2),
            max_token_count: source.saturating_mul(2),
            max_node_count: source.saturating_mul(2),
            max_diagnostics: limits.max_report_entries,
        },
        max_decoded_utf8_bytes: source.saturating_mul(3),
        max_decoded_scalars: source,
        max_body_depth: 4,
        max_expression_depth: limits.max_depth.saturating_add(2),
        max_template_depth: limits.max_depth.saturating_add(2),
        max_attribute_count: 8,
        max_block_count: 8,
        max_label_count: 8,
        max_body_item_count: 16,
        max_identifier_len: source,
        max_string_len: source,
        max_number_digits: limits.max_output_bytes,
        max_template_len: source,
        max_template_interpolations: source,
        max_heredoc_lines: source,
        max_heredoc_bytes: source,
        max_tuple_elements: source,
        max_object_entries: source,
        max_for_extent: source,
        max_recovery_regions: limits.max_report_entries,
        max_error_regions: limits.max_report_entries,
        max_syntax_pieces: source.saturating_mul(2),
        max_report_events: limits.max_report_entries,
    }
}

/// One validated `hcl.body@1` record.
struct Record {
    /// Root body.
    body: Body,
}

impl Record {
    /// Validates the record name, the tfvars block restriction, the body
    /// tree, the input node budget, and the container depth budget; every
    /// visited path is recorded in `analyzed`.
    fn validate(
        value: &PortableValue,
        request: &MaterializationRequest,
        analyzed: &mut Vec<ValuePath>,
    ) -> Result<Self, MaterializationFailure> {
        analyzed.push(ValuePath::root());
        let record_path =
            ValuePath::root().child(ValuePathSegment::ObjectValue("record".to_owned()));
        let record = expect_string_field(
            value,
            "record",
            &record_path,
            "input record is missing the record member",
        )?;
        if record != BODY_RECORD {
            return Err(MaterializationFailure::InvalidRequest(
                "input record is not hcl.body@1",
            ));
        }
        let tfvars = request.target_profile() == &ProfileId::new("hcl.tfvars", 1);
        let mut validator = Validator::new(request.limits());
        let body = Body::validate(
            value,
            &ValuePath::root(),
            &mut validator,
            analyzed,
            tfvars,
            0,
        )?;
        Ok(Self { body })
    }
}

/// One validated body: ordered attributes and blocks.
struct Body {
    /// Ordered body items.
    items: Vec<BodyItem>,
}

/// One validated body item.
enum BodyItem {
    /// An attribute occurrence.
    Attribute {
        /// Input path of the item inside the record.
        path: ValuePath,
        /// Validated identifier name.
        name: Arc<str>,
        /// Validated value.
        value: ValueNode,
    },
    /// A block occurrence.
    Block {
        /// Input path of the item inside the record.
        path: ValuePath,
        /// Validated identifier block type.
        block_type: Arc<str>,
        /// Ordered labels.
        labels: Vec<Label>,
        /// Nested body.
        body: Body,
    },
}

/// One validated block label.
struct Label {
    /// Exact label text; the canonical output always quotes it.
    text: Arc<str>,
}

/// One validated value record with its kind semantics.
struct ValueNode {
    /// Validated value.
    kind: ValueKind,
}

/// Closed validated value kinds.
enum ValueKind {
    /// Exact decoded string text.
    String(Arc<str>),
    /// Exact canonical decimal spelling of an integer (RFC 0014 §9).
    Integer(Arc<str>),
    /// Exact canonical decimal spelling of a real (RFC 0014 §9).
    Real(Arc<str>),
    /// Boolean value.
    Boolean(bool),
    /// Null value.
    Null,
    /// Ordered tuple elements.
    Tuple(Vec<ValueNode>),
    /// Ordered object entries; duplicate keys are preserved.
    Object(Vec<ObjectEntry>),
    /// A derived expression as the authorized `hcl.expression@1`
    /// ExtendedValue (RFC 0014 §8.2).
    Expression(PromisedExpression),
}

/// One validated object-constructor entry.
struct ObjectEntry {
    /// Exact key text; the canonical output emits it bare when it is a
    /// plain identifier other than `for`, else quoted.
    key: Arc<str>,
    /// Associated value.
    value: ValueNode,
}

/// One validated `hcl.expression@1` record.
struct PromisedExpression {
    /// Exact source text, emitted verbatim.
    text: Arc<str>,
    /// Parsed promised AST for the closure comparison.
    ast: HclExpression,
}

/// Input node budget accounting during validation.
struct Validator {
    /// Value and item nodes visited so far.
    nodes: usize,
    /// Requested limits.
    limits: MaterializationLimits,
}

impl Validator {
    const fn new(limits: MaterializationLimits) -> Self {
        Self { nodes: 0, limits }
    }

    fn step(&mut self) -> Result<(), MaterializationFailure> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(MaterializationFailure::ResourceLimit("input-nodes"))?;
        if self.nodes > self.limits.max_input_nodes {
            return Err(MaterializationFailure::ResourceLimit("input-nodes"));
        }
        Ok(())
    }
}

impl Body {
    /// Validates one body record and its items; `depth` is the block nesting
    /// level, bounded by the container depth budget.
    fn validate(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        tfvars: bool,
        depth: usize,
    ) -> Result<Self, MaterializationFailure> {
        let items_path = path.child(ValuePathSegment::ObjectValue("items".to_owned()));
        let items_value = expect_object_field(
            value,
            "items",
            &items_path,
            "input body record is missing the items member",
        )?;
        let items = items_value
            .as_sequence()
            .ok_or_else(|| unrepresentable(&items_path, items_value.kind()))?;
        let mut out = Vec::with_capacity(items.len());
        let mut names = HashSet::new();
        for (index, item) in items.iter().enumerate() {
            let item_path = items_path.child(ValuePathSegment::SequenceElement(index as u64));
            validator.step()?;
            analyzed.push(item_path.clone());
            let kind_path = item_path.child(ValuePathSegment::ObjectValue("kind".to_owned()));
            let kind = expect_string_field(
                item,
                "kind",
                &kind_path,
                "body item is missing the kind member",
            )?;
            match kind {
                "attribute" => {
                    let name_path =
                        item_path.child(ValuePathSegment::ObjectValue("name".to_owned()));
                    let name = expect_string_field(
                        item,
                        "name",
                        &name_path,
                        "attribute item is missing the name member",
                    )?;
                    if !is_plain_identifier(name) {
                        return Err(unrepresentable(&name_path, PortableValueKind::String));
                    }
                    // RFC 0014 §3: a second attribute with the same name in
                    // one body never forms a Complete document.
                    if !names.insert(name.to_owned()) {
                        return Err(unrepresentable(&item_path, PortableValueKind::String));
                    }
                    let value_path =
                        item_path.child(ValuePathSegment::ObjectValue("value".to_owned()));
                    let value_value = expect_object_field(
                        item,
                        "value",
                        &value_path,
                        "attribute item is missing the value member",
                    )?;
                    let value =
                        ValueNode::validate(value_value, &value_path, validator, analyzed, 0)?;
                    out.push(BodyItem::Attribute {
                        path: item_path,
                        name: Arc::from(name),
                        value,
                    });
                }
                "block" => {
                    // RFC 0014 §5, §9: the tfvars target admits attribute-
                    // only records; the block restriction is checked before
                    // the block shape so the record's presence alone fails.
                    if tfvars {
                        return Err(unrepresentable(&item_path, PortableValueKind::Object));
                    }
                    if depth + 1 > validator.limits.max_depth {
                        return Err(MaterializationFailure::ResourceLimit("input-depth"));
                    }
                    let type_path =
                        item_path.child(ValuePathSegment::ObjectValue("type".to_owned()));
                    let block_type = expect_string_field(
                        item,
                        "type",
                        &type_path,
                        "block item is missing the type member",
                    )?;
                    if !is_plain_identifier(block_type) {
                        return Err(unrepresentable(&type_path, PortableValueKind::String));
                    }
                    let labels_path =
                        item_path.child(ValuePathSegment::ObjectValue("labels".to_owned()));
                    let labels_value = expect_object_field(
                        item,
                        "labels",
                        &labels_path,
                        "block item is missing the labels member",
                    )?;
                    let labels_sequence = labels_value
                        .as_sequence()
                        .ok_or_else(|| unrepresentable(&labels_path, labels_value.kind()))?;
                    let mut labels = Vec::with_capacity(labels_sequence.len());
                    for (label_index, label) in labels_sequence.iter().enumerate() {
                        let label_path = labels_path
                            .child(ValuePathSegment::SequenceElement(label_index as u64));
                        validator.step()?;
                        analyzed.push(label_path.clone());
                        let text = label
                            .as_string()
                            .ok_or_else(|| unrepresentable(&label_path, label.kind()))?;
                        if quoted_len(text) > validator.limits.max_output_bytes {
                            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                        }
                        labels.push(Label {
                            text: Arc::from(text),
                        });
                    }
                    let body_path =
                        item_path.child(ValuePathSegment::ObjectValue("body".to_owned()));
                    let body_value = expect_object_field(
                        item,
                        "body",
                        &body_path,
                        "block item is missing the body member",
                    )?;
                    let body = Body::validate(
                        body_value,
                        &body_path,
                        validator,
                        analyzed,
                        tfvars,
                        depth + 1,
                    )?;
                    out.push(BodyItem::Block {
                        path: item_path,
                        block_type: Arc::from(block_type),
                        labels,
                        body,
                    });
                }
                _ => return Err(unrepresentable(&kind_path, PortableValueKind::String)),
            }
        }
        Ok(Self { items: out })
    }
}

impl ValueNode {
    /// Validates one attribute value and its descendants: either the RFC
    /// 0014 §8.2 typed member itself — a raw string, integer, real, boolean,
    /// null, tuple, or object PortableValue, or the `hcl.expression@1`
    /// record object of a derived expression — or the equivalent value
    /// record with a string `kind` member. `depth` is the tuple/object
    /// container nesting level, bounded by the container depth budget.
    fn validate(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        depth: usize,
    ) -> Result<Self, MaterializationFailure> {
        validator.step()?;
        analyzed.push(path.clone());
        if value.as_object().is_some() {
            return Self::validate_object(value, path, validator, analyzed, depth);
        }
        Self::validate_typed_member(value, path, validator, analyzed, depth)
    }

    /// Validates one object-form value: the raw `hcl.expression@1` record
    /// object of a derived expression (RFC 0014 §8.2), or the value record
    /// with a string `kind` member.
    fn validate_object(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        depth: usize,
    ) -> Result<Self, MaterializationFailure> {
        let object = value.as_object().expect("object form");
        if object_field(object, "record").and_then(PortableValue::as_string)
            == Some(EXPRESSION_RECORD)
        {
            let expression =
                PromisedExpression::validate(value, path, validator, analyzed, validator.limits)?;
            return Ok(Self {
                kind: ValueKind::Expression(expression),
            });
        }
        let kind_path = path.child(ValuePathSegment::ObjectValue("kind".to_owned()));
        let kind = expect_string_field(
            value,
            "kind",
            &kind_path,
            "value record is missing the kind member",
        )?;
        let limits = validator.limits;
        let kind = match kind {
            "string" => {
                let text_path = path.child(ValuePathSegment::ObjectValue("text".to_owned()));
                let text = expect_string_field(
                    value,
                    "text",
                    &text_path,
                    "string value record is missing the text member",
                )?;
                if quoted_len(text) > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                ValueKind::String(Arc::from(text))
            }
            "integer" => {
                let payload_path = path.child(ValuePathSegment::ObjectValue("value".to_owned()));
                let payload = expect_object_field(
                    value,
                    "value",
                    &payload_path,
                    "integer value record is missing the value member",
                )?;
                let integer = payload
                    .as_integer()
                    .ok_or_else(|| unrepresentable(&payload_path, payload.kind()))?;
                if integer.magnitude().len().saturating_mul(3) > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                let spelling = integer.to_string();
                if spelling.len() > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                ValueKind::Integer(Arc::from(spelling))
            }
            "real" => {
                let payload_path = path.child(ValuePathSegment::ObjectValue("value".to_owned()));
                let payload = expect_object_field(
                    value,
                    "value",
                    &payload_path,
                    "real value record is missing the value member",
                )?;
                let spelling = match (
                    payload.as_binary_float64(),
                    payload.as_decimal(),
                    payload.as_binary_float32(),
                ) {
                    (Some(bits), _, _) => double_to_canonical_decimal(bits.bits())
                        .ok_or_else(|| unrepresentable(path, PortableValueKind::BinaryFloat64))?,
                    (None, Some(decimal), _) => render_decimal(decimal, limits)?,
                    (None, None, Some(bits)) => double_to_canonical_decimal(
                        f64::from(f32::from_bits(bits.bits())).to_bits(),
                    )
                    .ok_or_else(|| unrepresentable(path, PortableValueKind::BinaryFloat32))?,
                    _ => return Err(unrepresentable(&payload_path, payload.kind())),
                };
                if spelling.len() > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                ValueKind::Real(Arc::from(spelling))
            }
            "boolean" => {
                let payload_path = path.child(ValuePathSegment::ObjectValue("value".to_owned()));
                let payload = expect_object_field(
                    value,
                    "value",
                    &payload_path,
                    "boolean value record is missing the value member",
                )?;
                let flag = payload
                    .as_boolean()
                    .ok_or_else(|| unrepresentable(&payload_path, payload.kind()))?;
                ValueKind::Boolean(flag)
            }
            "null" => ValueKind::Null,
            "tuple" => {
                if depth + 1 > limits.max_depth {
                    return Err(MaterializationFailure::ResourceLimit("input-depth"));
                }
                let elements_path =
                    path.child(ValuePathSegment::ObjectValue("elements".to_owned()));
                let elements_value = expect_object_field(
                    value,
                    "elements",
                    &elements_path,
                    "tuple value record is missing the elements member",
                )?;
                let elements = elements_value
                    .as_sequence()
                    .ok_or_else(|| unrepresentable(&elements_path, elements_value.kind()))?;
                let mut out = Vec::with_capacity(elements.len());
                for (index, element) in elements.iter().enumerate() {
                    let element_path =
                        elements_path.child(ValuePathSegment::SequenceElement(index as u64));
                    out.push(ValueNode::validate(
                        element,
                        &element_path,
                        validator,
                        analyzed,
                        depth + 1,
                    )?);
                }
                ValueKind::Tuple(out)
            }
            "object" => {
                if depth + 1 > limits.max_depth {
                    return Err(MaterializationFailure::ResourceLimit("input-depth"));
                }
                let entries_path = path.child(ValuePathSegment::ObjectValue("entries".to_owned()));
                let entries_value = expect_object_field(
                    value,
                    "entries",
                    &entries_path,
                    "object value record is missing the entries member",
                )?;
                let entries = entries_value
                    .as_sequence()
                    .ok_or_else(|| unrepresentable(&entries_path, entries_value.kind()))?;
                let mut out = Vec::with_capacity(entries.len());
                for (index, entry) in entries.iter().enumerate() {
                    let entry_path =
                        entries_path.child(ValuePathSegment::SequenceElement(index as u64));
                    let pair = entry
                        .as_sequence()
                        .ok_or_else(|| unrepresentable(&entry_path, entry.kind()))?;
                    if pair.len() != 2 {
                        return Err(unrepresentable(&entry_path, entry.kind()));
                    }
                    let key_path = entry_path.child(ValuePathSegment::SequenceElement(0));
                    let key = pair[0]
                        .as_string()
                        .ok_or_else(|| unrepresentable(&key_path, pair[0].kind()))?;
                    let value_path = entry_path.child(ValuePathSegment::SequenceElement(1));
                    let value =
                        ValueNode::validate(&pair[1], &value_path, validator, analyzed, depth + 1)?;
                    out.push(ObjectEntry {
                        key: Arc::from(key),
                        value,
                    });
                }
                ValueKind::Object(out)
            }
            "expression" => {
                let expression_path =
                    path.child(ValuePathSegment::ObjectValue("expression".to_owned()));
                let expression_value = expect_object_field(
                    value,
                    "expression",
                    &expression_path,
                    "expression value record is missing the expression member",
                )?;
                let expression = PromisedExpression::validate(
                    expression_value,
                    &expression_path,
                    validator,
                    analyzed,
                    limits,
                )?;
                ValueKind::Expression(expression)
            }
            _ => return Err(unrepresentable(&kind_path, PortableValueKind::String)),
        };
        Ok(Self { kind })
    }

    /// Validates one raw RFC 0014 §8.2 typed member: a string, integer,
    /// real, boolean, null, tuple, or object PortableValue without any
    /// record wrapper, exactly as the body projection publishes attribute
    /// values. `depth` is the tuple/object container nesting level, bounded
    /// by the container depth budget.
    fn validate_typed_member(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        depth: usize,
    ) -> Result<Self, MaterializationFailure> {
        let limits = validator.limits;
        match value.kind() {
            PortableValueKind::String => {
                let text = value.as_string().expect("string kind");
                if quoted_len(text) > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                Ok(Self {
                    kind: ValueKind::String(Arc::from(text)),
                })
            }
            PortableValueKind::Integer => {
                let integer = value.as_integer().expect("integer kind");
                if integer.magnitude().len().saturating_mul(3) > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                let spelling = integer.to_string();
                if spelling.len() > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                Ok(Self {
                    kind: ValueKind::Integer(Arc::from(spelling)),
                })
            }
            PortableValueKind::Decimal
            | PortableValueKind::BinaryFloat32
            | PortableValueKind::BinaryFloat64 => {
                let spelling = match (
                    value.as_binary_float64(),
                    value.as_decimal(),
                    value.as_binary_float32(),
                ) {
                    (Some(bits), _, _) => double_to_canonical_decimal(bits.bits())
                        .ok_or_else(|| unrepresentable(path, PortableValueKind::BinaryFloat64))?,
                    (None, Some(decimal), _) => render_decimal(decimal, limits)?,
                    (None, None, Some(bits)) => double_to_canonical_decimal(
                        f64::from(f32::from_bits(bits.bits())).to_bits(),
                    )
                    .ok_or_else(|| unrepresentable(path, PortableValueKind::BinaryFloat32))?,
                    _ => return Err(unrepresentable(path, value.kind())),
                };
                if spelling.len() > limits.max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                Ok(Self {
                    kind: ValueKind::Real(Arc::from(spelling)),
                })
            }
            PortableValueKind::Boolean => {
                let flag = value.as_boolean().expect("boolean kind");
                Ok(Self {
                    kind: ValueKind::Boolean(flag),
                })
            }
            PortableValueKind::Null => Ok(Self {
                kind: ValueKind::Null,
            }),
            PortableValueKind::Sequence => {
                if depth + 1 > limits.max_depth {
                    return Err(MaterializationFailure::ResourceLimit("input-depth"));
                }
                let elements = value.as_sequence().expect("sequence kind");
                let mut out = Vec::with_capacity(elements.len());
                for (index, element) in elements.iter().enumerate() {
                    let element_path = path.child(ValuePathSegment::SequenceElement(index as u64));
                    out.push(Self::validate(
                        element,
                        &element_path,
                        validator,
                        analyzed,
                        depth + 1,
                    )?);
                }
                Ok(Self {
                    kind: ValueKind::Tuple(out),
                })
            }
            PortableValueKind::EntryMapping => {
                if depth + 1 > limits.max_depth {
                    return Err(MaterializationFailure::ResourceLimit("input-depth"));
                }
                let entries = value.as_entry_mapping().expect("entry mapping kind");
                let mut out = Vec::with_capacity(entries.len());
                for (index, entry) in entries.iter().enumerate() {
                    let entry_path = path.child(ValuePathSegment::SequenceElement(index as u64));
                    let key = entry
                        .key()
                        .as_string()
                        .ok_or_else(|| unrepresentable(&entry_path, entry.key().kind()))?;
                    let value_path = entry_path.child(ValuePathSegment::SequenceElement(1));
                    let value =
                        Self::validate(entry.value(), &value_path, validator, analyzed, depth + 1)?;
                    out.push(ObjectEntry {
                        key: Arc::from(key),
                        value,
                    });
                }
                Ok(Self {
                    kind: ValueKind::Object(out),
                })
            }
            // Bytes, date, and time datums have no HCL spelling (RFC 0014
            // §8.2).
            _ => Err(unrepresentable(path, value.kind())),
        }
    }
}

impl PromisedExpression {
    /// Validates one `hcl.expression@1` record: the text must parse
    /// standalone as one complete expression whose structural kind spelling
    /// matches the record's `kind`, and an optional `fingerprint` field must
    /// equal the parsed expression's structural fingerprint (RFC 0014 §8.2,
    /// §9).
    fn validate(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        limits: MaterializationLimits,
    ) -> Result<Self, MaterializationFailure> {
        validator.step()?;
        analyzed.push(path.clone());
        let record_path = path.child(ValuePathSegment::ObjectValue("record".to_owned()));
        let record = expect_string_field(
            value,
            "record",
            &record_path,
            "expression record is missing the record member",
        )?;
        if record != EXPRESSION_RECORD {
            return Err(MaterializationFailure::InvalidRequest(
                "input expression is not hcl.expression@1",
            ));
        }
        let kind_path = path.child(ValuePathSegment::ObjectValue("kind".to_owned()));
        let kind = expect_string_field(
            value,
            "kind",
            &kind_path,
            "expression record is missing the kind member",
        )?;
        let text_path = path.child(ValuePathSegment::ObjectValue("text".to_owned()));
        let text = expect_string_field(
            value,
            "text",
            &text_path,
            "expression record is missing the text member",
        )?;
        if text.len() > limits.max_output_bytes {
            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
        }
        let ast = promised_expression_parse(text, limits)?;
        if expression_kind_spelling(&ast) != kind {
            return Err(MaterializationFailure::InvalidRequest(
                "expression kind does not match text",
            ));
        }
        let Some(object) = value.as_object() else {
            return Err(unrepresentable(path, value.kind()));
        };
        if let Some(fingerprint_value) = object_field(object, "fingerprint") {
            let fingerprint_path =
                path.child(ValuePathSegment::ObjectValue("fingerprint".to_owned()));
            let fingerprint = fingerprint_value
                .as_string()
                .ok_or_else(|| unrepresentable(&fingerprint_path, fingerprint_value.kind()))?;
            if fingerprint != expression_fingerprint(&ast) {
                return Err(MaterializationFailure::InvalidRequest(
                    "expression fingerprint mismatch",
                ));
            }
        }
        Ok(Self {
            text: Arc::from(text),
            ast,
        })
    }
}

/// Parses one expression text standalone by wrapping it in one sentinel
/// attribute and requiring the parse to yield exactly that attribute (RFC
/// 0014 §8.2 reparse discipline).
///
/// A text that would parse into additional body items, a block, or a
/// duplicate of the sentinel is not one expression. A fatal limit failure of
/// the standalone parse is an input-depth limit failure: the text's
/// structural depth is bounded by the same budget as the closure reparse, so
/// an accepted text can never overflow it.
fn promised_expression_parse(
    text: &str,
    limits: MaterializationLimits,
) -> Result<HclExpression, MaterializationFailure> {
    let mut source = String::with_capacity(text.len() + 8);
    source.push_str(SENTINEL_ATTRIBUTE);
    source.push_str(" = ");
    source.push_str(text);
    source.push('\n');
    let formed = crate::parser::parse_hcl(
        Arc::from(source.into_bytes()),
        promised_expression_limits(text.len(), limits),
    )
    .map_err(|_| MaterializationFailure::ResourceLimit("input-depth"))?;
    if formed.status() != FormationStatus::Complete {
        return Err(MaterializationFailure::InvalidRequest(
            "expression text does not parse",
        ));
    }
    let items = formed.document().body().items();
    if items.len() != 1 {
        return Err(MaterializationFailure::InvalidRequest(
            "expression text does not parse",
        ));
    }
    let HclBodyItem::Attribute(attribute) = &items[0] else {
        return Err(MaterializationFailure::InvalidRequest(
            "expression text does not parse",
        ));
    };
    if attribute.name() != SENTINEL_ATTRIBUTE {
        return Err(MaterializationFailure::InvalidRequest(
            "expression text does not parse",
        ));
    }
    Ok(attribute.expression().clone())
}

/// Stable structural kind spelling of the `hcl.expression@1` record (RFC
/// 0014 §8.2); the shared M6/M7 adaptation point of the ExtendedValue
/// codec. The one spelling authority is the projection's [`kind_family`]
/// mapping over the closed RFC 0014 §8.2 kind table — variable references
/// and traversals share the `variable` spelling, and both for-expression
/// forms are one `for` family (RFC 0014 §4.6) — so the materialization
/// accepts exactly the kind the projection writes.
fn expression_kind_spelling(expression: &HclExpression) -> &'static str {
    crate::projection::kind_family(expression.kind().name())
}

/// The canonical emitter: a bounded output String with checked appends.
struct Writer {
    /// Emitted canonical bytes as UTF-8 text.
    out: String,
    /// Requested limits.
    limits: MaterializationLimits,
}

impl Writer {
    /// Appends one chunk after bounding the total output.
    fn push(&mut self, text: &str) -> Result<(), MaterializationFailure> {
        let planned = self
            .out
            .len()
            .checked_add(text.len())
            .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
        if planned > self.limits.max_output_bytes {
            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
        }
        self.out.push_str(text);
        Ok(())
    }

    /// Appends one body-nesting indentation level of two spaces.
    fn indent(&mut self, depth: usize) -> Result<(), MaterializationFailure> {
        for _ in 0..depth {
            self.push("  ")?;
        }
        Ok(())
    }

    /// Appends one double-quoted string with minimal deterministic escapes
    /// (RFC 0014 §9).
    fn push_quoted(&mut self, text: &str) -> Result<(), MaterializationFailure> {
        self.push("\"")?;
        self.push(&escape_text(text))?;
        self.push("\"")
    }
}

/// Emits one body at the given block-nesting depth.
fn write_body(
    writer: &mut Writer,
    body: &Body,
    depth: usize,
) -> Result<(), MaterializationFailure> {
    for item in &body.items {
        match item {
            BodyItem::Attribute { name, value, .. } => {
                writer.indent(depth)?;
                writer.push(name)?;
                writer.push(" = ")?;
                write_value(writer, value, depth)?;
                writer.push("\n")?;
            }
            BodyItem::Block {
                block_type,
                labels,
                body,
                ..
            } => {
                writer.indent(depth)?;
                writer.push(block_type)?;
                for label in labels {
                    writer.push(" ")?;
                    writer.push_quoted(&label.text)?;
                }
                writer.push(" {\n")?;
                write_body(writer, body, depth + 1)?;
                writer.indent(depth)?;
                writer.push("}\n")?;
            }
        }
    }
    Ok(())
}

/// Emits one attribute value at the given indentation depth.
fn write_value(
    writer: &mut Writer,
    value: &ValueNode,
    depth: usize,
) -> Result<(), MaterializationFailure> {
    match &value.kind {
        ValueKind::String(text) => writer.push_quoted(text),
        ValueKind::Integer(spelling) | ValueKind::Real(spelling) => writer.push(spelling),
        ValueKind::Boolean(flag) => writer.push(if *flag { "true" } else { "false" }),
        ValueKind::Null => writer.push("null"),
        ValueKind::Tuple(elements) => {
            if elements.is_empty() {
                return writer.push("[]");
            }
            writer.push("[\n")?;
            let last = elements.len() - 1;
            for (index, element) in elements.iter().enumerate() {
                writer.indent(depth + 1)?;
                write_value(writer, element, depth + 1)?;
                writer.push(if index == last { "\n" } else { ",\n" })?;
            }
            writer.indent(depth)?;
            writer.push("]")
        }
        ValueKind::Object(entries) => {
            if entries.is_empty() {
                return writer.push("{}");
            }
            writer.push("{\n")?;
            let last = entries.len() - 1;
            for (index, entry) in entries.iter().enumerate() {
                writer.indent(depth + 1)?;
                write_object_key(writer, &entry.key)?;
                writer.push(" = ")?;
                write_value(writer, &entry.value, depth + 1)?;
                writer.push(if index == last { "\n" } else { ",\n" })?;
            }
            writer.indent(depth)?;
            writer.push("}")
        }
        ValueKind::Expression(expression) => writer.push(&expression.text),
    }
}

/// Emits one object key: bare for a plain identifier other than the
/// contextual `for` (which would trigger the for-expression reading, RFC
/// 0014 §4.6), else quoted.
fn write_object_key(writer: &mut Writer, key: &str) -> Result<(), MaterializationFailure> {
    if is_plain_identifier(key) && key != "for" {
        writer.push(key)
    } else {
        writer.push_quoted(key)
    }
}

/// Whether one text is a valid UAX #31 identifier with the frozen hyphen
/// continuation and the underscore exclusion at the start (RFC 0014 §4.1,
/// §12 D-4), matching the lexer's own rule.
fn is_plain_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if first == '_' || !unicode_ident::is_xid_start(first) {
        return false;
    }
    characters.all(|character| unicode_ident::is_xid_continue(character) || character == '-')
}

/// Whether one character is escaped as `\uNNNN` in canonical output: the
/// C0 controls other than the three named escapes, DEL, and the C1
/// controls (RFC 0014 §9 "control characters").
const fn is_escaped_control(character: char) -> bool {
    let value = character as u32;
    value < 0x20 || (value >= 0x7F && value <= 0x9F)
}

/// Escapes one string with the minimal deterministic escape set (RFC 0014
/// §9): `\n`, `\r`, `\t`, `\"`, `\\`, `\uNNNN` for control characters, and
/// the `$${`/`%%{` doubling for the template openers.
///
/// The `$`/`%` rule inverts the template-literal decoding exactly: a run of
/// `k` dollars followed by `{` decodes to `k` dollars followed by `{`, so a
/// run of `k` dollars followed by `{` is emitted with `k + 1` dollars, and
/// any other run is emitted verbatim.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'$' || byte == b'%' {
            let mut run = 1;
            while bytes.get(index + run) == Some(&byte) {
                run += 1;
            }
            let doubled = bytes.get(index + run) == Some(&b'{');
            for _ in 0..run + usize::from(doubled) {
                out.push(char::from(byte));
            }
            index += run;
        } else {
            let character = text[index..]
                .chars()
                .next()
                .expect("scan positions are char boundaries");
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if is_escaped_control(c) => {
                    write!(out, "\\u{:04x}", u32::from(c))
                        .expect("writing into a String cannot fail");
                }
                _ => out.push(character),
            }
            index += character.len_utf8();
        }
    }
    out
}

/// Byte length of the double-quoted, minimally escaped spelling of one
/// text.
fn quoted_len(text: &str) -> usize {
    escape_text(text).len() + 2
}

/// Renders one normalized decimal as its plain canonical spelling: the
/// coefficient digits with the exponent folded into the decimal point
/// position, `"0"` for zero (RFC 0014 §9).
fn render_decimal(
    decimal: &Decimal,
    limits: MaterializationLimits,
) -> Result<String, MaterializationFailure> {
    let coefficient = decimal.coefficient();
    if coefficient.signum() == 0 {
        return Ok("0".to_owned());
    }
    if coefficient.magnitude().len().saturating_mul(3) > limits.max_output_bytes {
        return Err(MaterializationFailure::ResourceLimit("output-bytes"));
    }
    let Some(exponent) = decimal.exponent().to_i64() else {
        // An exponent beyond i64 forces a spelling far beyond any output
        // budget.
        return Err(MaterializationFailure::ResourceLimit("output-bytes"));
    };
    let digits = coefficient.to_string();
    let planned = planned_decimal_len(&digits, exponent);
    if planned > limits.max_output_bytes {
        return Err(MaterializationFailure::ResourceLimit("output-bytes"));
    }
    Ok(place_decimal_point(digits, exponent))
}

/// Exact planned byte length of `digits × 10^exponent` under the canonical
/// spelling.
fn planned_decimal_len(digits: &str, exponent: i64) -> usize {
    let signed = digits.starts_with('-');
    let magnitude = digits.len() - usize::from(signed);
    match exponent.cmp(&0) {
        Ordering::Greater => digits.len() + exponent.unsigned_abs() as usize,
        Ordering::Less => {
            let fraction = exponent.unsigned_abs() as usize;
            if fraction < magnitude {
                digits.len() + 1
            } else {
                fraction + 2 + usize::from(signed)
            }
        }
        Ordering::Equal => digits.len(),
    }
}

/// Places the decimal point of `digits × 10^exponent` into the canonical
/// spelling.
fn place_decimal_point(digits: String, exponent: i64) -> String {
    if exponent == 0 {
        return digits;
    }
    if exponent > 0 {
        let mut out = digits;
        out.extend(std::iter::repeat_n('0', exponent.unsigned_abs() as usize));
        return out;
    }
    let fraction = exponent.unsigned_abs() as usize;
    let signed = digits.starts_with('-');
    let magnitude = if signed {
        &digits[1..]
    } else {
        digits.as_str()
    };
    if fraction < magnitude.len() {
        let point = magnitude.len() - fraction;
        let mut out = String::with_capacity(digits.len() + 1);
        if signed {
            out.push('-');
        }
        out.push_str(&magnitude[..point]);
        out.push('.');
        out.push_str(&magnitude[point..]);
        out
    } else {
        let zeros = fraction - magnitude.len();
        let mut out = String::with_capacity(fraction + 2 + usize::from(signed));
        if signed {
            out.push('-');
        }
        out.push_str("0.");
        for _ in 0..zeros {
            out.push('0');
        }
        out.push_str(magnitude);
        out
    }
}

/// Multiplies one decimal digit string (no sign) by one u64 multiplier
/// with u128 carry arithmetic; the multiplier is a bounded power of two or
/// five.
fn decimal_mul_u64(digits: &mut String, multiplier: u64) {
    let bytes = digits.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() + 20);
    let mut carry = 0_u128;
    for byte in bytes.iter().rev() {
        let value = u128::from(*byte - b'0') * u128::from(multiplier) + carry;
        result.push(char::from(b'0' + (value % 10) as u8));
        carry = value / 10;
    }
    while carry > 0 {
        result.push(char::from(b'0' + (carry % 10) as u8));
        carry /= 10;
    }
    result.reverse();
    *digits = result.into_iter().collect();
}

/// Exact canonical decimal spelling of one binary64 datum; `None` for NaN
/// and infinity, which the HCL number grammar cannot express.
///
/// The exact value `mantissa × 2^exponent` is expanded by pure decimal
/// arithmetic (`× 5^k / 10^k` for a negative exponent), and the result is
/// normalized through the shared canonical-decimal fold, so the spelling
/// round-trips through the reparse closure by canonical-decimal equality.
fn double_to_canonical_decimal(bits: u64) -> Option<String> {
    let sign = bits >> 63;
    let exponent_bits = ((bits >> 52) & 0x7FF) as i64;
    let fraction = bits & 0xF_FFFF_FFFF_FFFF;
    let (mantissa, exponent) = if exponent_bits == 0 {
        if fraction == 0 {
            return Some("0".to_owned());
        }
        (fraction, -1074)
    } else if exponent_bits == 0x7FF {
        return None;
    } else {
        (fraction | 0x10_0000_0000_0000, exponent_bits - 1075)
    };
    let mut digits = mantissa.to_string();
    if exponent >= 0 {
        let mut remaining = exponent.unsigned_abs() as u32;
        while remaining > 0 {
            let chunk = remaining.min(32);
            decimal_mul_u64(&mut digits, 1_u64 << chunk);
            remaining -= chunk;
        }
    } else {
        let magnitude = exponent.unsigned_abs() as u32;
        let mut remaining = magnitude;
        while remaining > 0 {
            let chunk = remaining.min(27);
            decimal_mul_u64(&mut digits, 5_u64.pow(chunk));
            remaining -= chunk;
        }
        digits = place_decimal_point(digits, -i64::from(magnitude));
    }
    let mut canonical = canonical_decimal(&digits)?;
    if sign != 0 && canonical != "0" {
        canonical.insert(0, '-');
    }
    Some(canonical)
}

/// Structural fingerprint value of one expression: a 64-bit FNV-1a hash
/// over the canonical structural serialization (RFC 0014 §8.2).
///
/// The serialization covers the frozen structural equality of RFC 0014 §6 —
/// kind, ordered children, canonical decimals, exact literal texts,
/// operator spellings, heredoc mode and marker — and never source spans or
/// identities, so structurally equal expressions always carry the same
/// fingerprint. This is the fingerprint written by the M6 projection codec
/// (its `structural_fingerprint` delegates here) and verified by the
/// materialization closure: the shared M6/M7 adaptation point of the
/// `hcl.expression@1` payload.
pub(crate) fn expression_fingerprint_value(expression: &HclExpression) -> u64 {
    let mut bytes = Vec::new();
    write_expression_structure(expression, &mut bytes);
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Structural fingerprint of one expression: the hex of the shared
/// [`expression_fingerprint_value`] (RFC 0014 §8.2).
fn expression_fingerprint(expression: &HclExpression) -> String {
    format!("{:016x}", expression_fingerprint_value(expression))
}

/// Appends the canonical structural serialization of one expression.
fn write_expression_structure(expression: &HclExpression, out: &mut Vec<u8>) {
    match expression.kind() {
        HclExpressionKind::Number(number) => {
            out.push(b'N');
            push_text(out, number.canonical_decimal().as_bytes());
        }
        HclExpressionKind::Boolean(value) => {
            out.push(b'B');
            out.push(u8::from(*value));
        }
        HclExpressionKind::Null => out.push(b'Z'),
        HclExpressionKind::Template { parts, heredoc } => {
            out.push(b'T');
            match heredoc {
                Some(facts) => {
                    out.push(b'H');
                    push_text(out, facts.mode().as_str().as_bytes());
                    push_text(out, facts.marker().as_bytes());
                }
                None => out.push(b'Q'),
            }
            for part in parts.iter() {
                match part {
                    HclTemplatePart::Literal { text, .. } => {
                        out.push(b'L');
                        push_text(out, text.as_bytes());
                    }
                    HclTemplatePart::Interpolation { expression, .. } => {
                        out.push(b'I');
                        write_expression_structure(expression, out);
                    }
                    HclTemplatePart::Directive { kind, .. } => {
                        out.push(b'D');
                        write_directive_structure(kind, out);
                    }
                }
            }
        }
        HclExpressionKind::FunctionCall { name, args, .. } => {
            out.push(b'F');
            push_text(out, name.as_bytes());
            for argument in args.iter() {
                out.push(if argument.expand() { b'X' } else { b'x' });
                write_expression_structure(argument.expression(), out);
            }
        }
        HclExpressionKind::VariableRef { name } => {
            out.push(b'V');
            push_text(out, name.as_bytes());
        }
        HclExpressionKind::Traversal { root, steps } => {
            out.push(b'R');
            match root {
                HclTraversalRoot::Variable(name) => {
                    out.push(b'v');
                    push_text(out, name.as_bytes());
                }
                HclTraversalRoot::Boolean(value) => {
                    out.push(b'b');
                    out.push(u8::from(*value));
                }
                HclTraversalRoot::Null => out.push(b'n'),
            }
            for step in steps.iter() {
                write_traversal_step(step, out);
            }
        }
        HclExpressionKind::Unary { op, operand } => {
            out.push(b'U');
            push_text(out, op.as_str().as_bytes());
            write_expression_structure(operand, out);
        }
        HclExpressionKind::Binary { op, lhs, rhs } => {
            out.push(b'W');
            push_text(out, op.as_str().as_bytes());
            write_expression_structure(lhs, out);
            write_expression_structure(rhs, out);
        }
        HclExpressionKind::Conditional {
            condition,
            then,
            else_,
        } => {
            out.push(b'C');
            write_expression_structure(condition, out);
            write_expression_structure(then, out);
            write_expression_structure(else_, out);
        }
        HclExpressionKind::ForTuple {
            intro,
            value,
            condition,
        } => {
            out.push(b'P');
            write_for_intro(intro, out);
            write_expression_structure(value, out);
            match condition {
                Some(condition) => {
                    out.push(b'c');
                    write_expression_structure(condition, out);
                }
                None => out.push(b'n'),
            }
        }
        HclExpressionKind::ForObject {
            intro,
            key,
            value,
            grouping,
            condition,
        } => {
            out.push(b'O');
            write_for_intro(intro, out);
            write_expression_structure(key, out);
            write_expression_structure(value, out);
            out.push(if *grouping { b'g' } else { b'n' });
            match condition {
                Some(condition) => {
                    out.push(b'c');
                    write_expression_structure(condition, out);
                }
                None => out.push(b'n'),
            }
        }
        HclExpressionKind::Tuple { elements } => {
            out.push(b'L');
            for element in elements.iter() {
                write_expression_structure(element, out);
            }
        }
        HclExpressionKind::Object { entries } => {
            out.push(b'M');
            for entry in entries.iter() {
                write_object_key_structure(entry.key(), out);
                write_expression_structure(entry.value(), out);
            }
        }
        HclExpressionKind::Paren { inner } => {
            out.push(b'(');
            write_expression_structure(inner, out);
        }
    }
}

/// Appends the canonical structural serialization of one template
/// directive.
fn write_directive_structure(kind: &HclDirectiveKind, out: &mut Vec<u8>) {
    match kind {
        HclDirectiveKind::If { condition } => {
            out.push(b'f');
            write_expression_structure(condition, out);
        }
        HclDirectiveKind::Else => out.push(b'e'),
        HclDirectiveKind::EndIf => out.push(b'E'),
        HclDirectiveKind::For { intro } => {
            out.push(b'o');
            write_for_intro(intro, out);
        }
        HclDirectiveKind::EndFor => out.push(b'g'),
    }
}

/// Appends the canonical structural serialization of one `for`
/// introduction.
fn write_for_intro(intro: &HclForIntro, out: &mut Vec<u8>) {
    match intro.key() {
        Some(key) => {
            out.push(b'k');
            push_text(out, key.as_bytes());
        }
        None => out.push(b'n'),
    }
    push_text(out, intro.value().as_bytes());
    write_expression_structure(intro.collection(), out);
}

/// Appends the canonical structural serialization of one traversal step.
fn write_traversal_step(step: &HclTraversalStep, out: &mut Vec<u8>) {
    match step {
        HclTraversalStep::GetAttr { name, .. } => {
            out.push(b'a');
            push_text(out, name.as_bytes());
        }
        HclTraversalStep::Index { key, .. } => {
            out.push(b'i');
            write_expression_structure(key, out);
        }
        HclTraversalStep::AttrSplat { steps } => {
            out.push(b's');
            for inner in steps.iter() {
                write_traversal_step(inner, out);
            }
        }
        HclTraversalStep::FullSplat { steps } => {
            out.push(b'S');
            for inner in steps.iter() {
                write_traversal_step(inner, out);
            }
        }
    }
}

/// Appends the canonical structural serialization of one object key.
fn write_object_key_structure(key: &HclObjectKey, out: &mut Vec<u8>) {
    match key {
        HclObjectKey::Identifier(name) => {
            out.push(b'K');
            push_text(out, name.as_bytes());
        }
        HclObjectKey::Number(number) => {
            out.push(b'k');
            push_text(out, number.canonical_decimal().as_bytes());
        }
        HclObjectKey::Template(template) => {
            out.push(b't');
            for part in template.parts() {
                match part {
                    HclTemplatePart::Literal { text, .. } => {
                        out.push(b'l');
                        push_text(out, text.as_bytes());
                    }
                    HclTemplatePart::Interpolation { expression, .. } => {
                        out.push(b'i');
                        write_expression_structure(expression, out);
                    }
                    HclTemplatePart::Directive { kind, .. } => {
                        out.push(b'd');
                        write_directive_structure(kind, out);
                    }
                }
            }
        }
        HclObjectKey::Paren(inner) => {
            out.push(b'p');
            write_expression_structure(inner, out);
        }
    }
}

/// Appends one length-prefixed byte run.
fn push_text(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(&(text.len() as u64).to_le_bytes());
    out.extend_from_slice(text);
}

/// Walks the input record and the reparsed document in lockstep, compares
/// the promised semantics, and pairs every recorded input location with its
/// exact output origin. Any mismatch fails the whole materialization.
fn verify_closure(
    record: &Record,
    document: &Document,
    limits: MaterializationLimits,
) -> Result<MaterializationProvenanceMap, MaterializationFailure> {
    let authority = document.authority();
    let snapshot = document.snapshot_identity();
    let root_span = authority
        .span(0, document.source().len())
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    let mut context = ClosureContext {
        authority,
        snapshot,
        outputs: Vec::new(),
        limits,
    };
    context.push(&ValuePath::root(), root_span, NodeRole::HclDocument)?;
    context.body(&record.body, document.document().body())?;
    let entries = context
        .outputs
        .into_iter()
        .map(|(input, origin)| MaterializationProvenanceEntry {
            input: MaterializationInputLocation::Value(input),
            outputs: vec![origin],
        })
        .collect();
    MaterializationProvenanceMap::new(entries, snapshot, limits)
}

/// Closure walk state: the reparsed snapshot and the ordered input-to-output
/// pairs.
struct ClosureContext<'a> {
    /// Reparsed document authority.
    authority: &'a consema_document::DocumentAuthority,
    /// Reparsed snapshot identity.
    snapshot: consema_document::SnapshotIdentity,
    /// Ordered input paths with their output origins.
    outputs: Vec<(ValuePath, MaterializedOrigin)>,
    /// Requested limits.
    limits: MaterializationLimits,
}

impl ClosureContext<'_> {
    /// Records one input path paired with its output origin.
    fn push(
        &mut self,
        input: &ValuePath,
        span: Span,
        role: NodeRole,
    ) -> Result<(), MaterializationFailure> {
        if self.outputs.len() >= self.limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries"));
        }
        self.outputs.push((
            input.clone(),
            MaterializedOrigin {
                snapshot: self.snapshot,
                node: self.authority.node_ref(self.outputs.len() as u64, role),
                span,
                relation: MaterializationRelation::Direct,
            },
        ));
        Ok(())
    }

    /// Compares one body in lockstep and records its item provenance.
    fn body(&mut self, record: &Body, reparsed: &HclBody) -> Result<(), MaterializationFailure> {
        let items = reparsed.items();
        if items.len() != record.items.len() {
            return Err(MaterializationFailure::FormationFailed);
        }
        for (record_item, native_item) in record.items.iter().zip(items) {
            match (record_item, native_item) {
                (BodyItem::Attribute { path, name, value }, HclBodyItem::Attribute(attribute)) => {
                    if attribute.name() != name.as_ref() {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    if !check_value(value, attribute.expression()) {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    let item_span = self
                        .authority
                        .span(
                            attribute.name_span().start_byte(),
                            attribute.expression().span().end_byte(),
                        )
                        .map_err(|_| MaterializationFailure::FormationFailed)?;
                    self.push(path, item_span, NodeRole::HclAttribute)?;
                    let value_path = path.child(ValuePathSegment::ObjectValue("value".to_owned()));
                    self.push(
                        &value_path,
                        attribute.expression().span(),
                        NodeRole::HclExpression,
                    )?;
                }
                (
                    BodyItem::Block {
                        path,
                        block_type,
                        labels,
                        body,
                    },
                    HclBodyItem::Block(block),
                ) => {
                    if block.block_type() != block_type.as_ref() {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    if block.labels().len() != labels.len() {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    self.push(path, block.span(), NodeRole::HclBlock)?;
                    let labels_path =
                        path.child(ValuePathSegment::ObjectValue("labels".to_owned()));
                    for (index, (record_label, native_label)) in
                        labels.iter().zip(block.labels()).enumerate()
                    {
                        if native_label.text() != record_label.text.as_ref() {
                            return Err(MaterializationFailure::FormationFailed);
                        }
                        let label_path =
                            labels_path.child(ValuePathSegment::SequenceElement(index as u64));
                        self.push(&label_path, native_label.span(), NodeRole::HclBlockLabel)?;
                    }
                    self.body(body, block.body())?;
                }
                _ => return Err(MaterializationFailure::FormationFailed),
            }
        }
        Ok(())
    }
}

/// Whether one reparsed expression carries the promised value semantics
/// (RFC 0014 §9 closure): numbers by canonical-decimal value equality,
/// strings and object keys by exact decoded text, constructors
/// element-wise, and `hcl.expression@1` values by structural equality plus
/// fingerprint equality (RFC 0014 §6).
fn check_value(record: &ValueNode, expression: &HclExpression) -> bool {
    match &record.kind {
        ValueKind::String(text) => {
            quoted_template_text(expression).as_deref() == Some(text.as_ref())
        }
        ValueKind::Integer(spelling) | ValueKind::Real(spelling) => {
            number_spelling_matches(expression, spelling)
        }
        ValueKind::Boolean(flag) => {
            matches!(expression.kind(), HclExpressionKind::Boolean(value) if *value == *flag)
        }
        ValueKind::Null => matches!(expression.kind(), HclExpressionKind::Null),
        ValueKind::Tuple(elements) => {
            let HclExpressionKind::Tuple { elements: reparsed } = expression.kind() else {
                return false;
            };
            elements.len() == reparsed.len()
                && elements
                    .iter()
                    .zip(reparsed.iter())
                    .all(|(record, native)| check_value(record, native))
        }
        ValueKind::Object(entries) => {
            let HclExpressionKind::Object { entries: reparsed } = expression.kind() else {
                return false;
            };
            entries.len() == reparsed.len()
                && entries.iter().zip(reparsed.iter()).all(|(record, native)| {
                    object_key_matches(native.key(), &record.key)
                        && check_value(&record.value, native.value())
                })
        }
        ValueKind::Expression(promised) => {
            expression == &promised.ast
                && expression_fingerprint(expression) == expression_fingerprint(&promised.ast)
        }
    }
}

/// Exact decoded text of one quoted template; `None` for a heredoc, an
/// interpolation, or a directive.
fn quoted_template_text(expression: &HclExpression) -> Option<String> {
    let HclExpressionKind::Template { parts, heredoc } = expression.kind() else {
        return None;
    };
    if heredoc.is_some() {
        return None;
    }
    let mut text = String::new();
    for part in parts.iter() {
        let HclTemplatePart::Literal { text: literal, .. } = part else {
            return None;
        };
        text.push_str(literal);
    }
    Some(text)
}

/// Whether one reparsed expression is the canonical spelling of one
/// promised number, including the unary-minus form of a negative value.
fn number_spelling_matches(expression: &HclExpression, spelling: &str) -> bool {
    if let Some(magnitude) = spelling.strip_prefix('-') {
        matches!(
            expression.kind(),
            HclExpressionKind::Unary {
                op: UnaryOp::Minus,
                operand,
            } if number_canonical_matches(operand, magnitude)
        )
    } else {
        number_canonical_matches(expression, spelling)
    }
}

/// Whether one reparsed expression is one number with the exact canonical
/// decimal spelling.
fn number_canonical_matches(expression: &HclExpression, canonical: &str) -> bool {
    matches!(
        expression.kind(),
        HclExpressionKind::Number(number) if number.canonical_decimal() == canonical
    )
}

/// Whether one reparsed object key is the promised key text: a bare
/// identifier or a quoted literal template with the exact decoded text.
fn object_key_matches(key: &HclObjectKey, promised: &str) -> bool {
    match key {
        HclObjectKey::Identifier(name) => name.as_ref() == promised,
        HclObjectKey::Template(template) => {
            let mut text = String::new();
            for part in template.parts() {
                let HclTemplatePart::Literal { text: literal, .. } = part else {
                    return false;
                };
                text.push_str(literal);
            }
            text == promised
        }
        HclObjectKey::Number(_) | HclObjectKey::Paren(_) => false,
    }
}

/// Looks up one object entry by exact key.
fn object_field<'v>(
    object: &'v [consema_core::ObjectEntry],
    name: &str,
) -> Option<&'v PortableValue> {
    object
        .iter()
        .find(|entry| entry.key() == name)
        .map(consema_core::ObjectEntry::value)
}

/// Reads one required object member of one record; a missing member is an
/// invalid request whose detail names the missing member exactly, so a
/// malformed record never surfaces as a generic shape error.
fn expect_object_field<'v>(
    value: &'v PortableValue,
    name: &str,
    path: &ValuePath,
    missing: &'static str,
) -> Result<&'v PortableValue, MaterializationFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| unrepresentable(path, value.kind()))?;
    let Some(field) = object_field(object, name) else {
        return Err(MaterializationFailure::InvalidRequest(missing));
    };
    Ok(field)
}

/// Reads one required string member of one record; a missing member is an
/// invalid request whose detail names the missing member exactly, and a
/// non-string member is unrepresentable at the member's path.
fn expect_string_field<'v>(
    value: &'v PortableValue,
    name: &str,
    path: &ValuePath,
    missing: &'static str,
) -> Result<&'v str, MaterializationFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| unrepresentable(path, value.kind()))?;
    let Some(field) = object_field(object, name) else {
        return Err(MaterializationFailure::InvalidRequest(missing));
    };
    field.as_string().ok_or_else(|| {
        unrepresentable(
            &path.child(ValuePathSegment::ObjectValue(name.to_owned())),
            field.kind(),
        )
    })
}

/// One input value that the target profile cannot represent; the runner maps
/// this variant to `hcl.materialization.unrepresentable@1`.
fn unrepresentable(path: &ValuePath, kind: PortableValueKind) -> MaterializationFailure {
    MaterializationFailure::Unrepresentable {
        path: path.clone(),
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HclBlockLabel;
    use crate::expression::{HclLiteralKey, HclLiteralObjectEntry, HclLiteralValue, literal_value};
    use consema_core::{BigInteger, BinaryFloat32, BinaryFloat64, Decimal, ObjectBuilder};
    use consema_document::{MaterializationStyleId, ProfileId};

    fn request(profile: &str) -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new(profile, 1),
            MaterializationStyleId::new(STYLE_CANONICAL, 1),
        )
    }

    fn native_request() -> MaterializationRequest {
        request("hcl.native")
    }

    fn tfvars_request() -> MaterializationRequest {
        request("hcl.tfvars")
    }

    fn body_record(items: Vec<PortableValue>) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string(BODY_RECORD))
            .expect("insert");
        builder
            .insert("items", PortableValue::sequence(items))
            .expect("insert");
        builder.build()
    }

    fn attribute_record(name: &str, value: PortableValue) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("kind", PortableValue::string("attribute"))
            .expect("insert");
        builder
            .insert("name", PortableValue::string(name))
            .expect("insert");
        builder.insert("value", value).expect("insert");
        builder.build()
    }

    fn block_record(block_type: &str, labels: Vec<&str>, body: PortableValue) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("kind", PortableValue::string("block"))
            .expect("insert");
        builder
            .insert("type", PortableValue::string(block_type))
            .expect("insert");
        builder
            .insert(
                "labels",
                PortableValue::sequence(
                    labels
                        .into_iter()
                        .map(PortableValue::string)
                        .collect::<Vec<_>>(),
                ),
            )
            .expect("insert");
        builder.insert("body", body).expect("insert");
        builder.build()
    }

    fn value_record(kind: &str, fields: Vec<(&str, PortableValue)>) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("kind", PortableValue::string(kind))
            .expect("insert");
        for (name, value) in fields {
            builder.insert(name, value).expect("insert");
        }
        builder.build()
    }

    fn string_record(text: &str) -> PortableValue {
        value_record("string", vec![("text", PortableValue::string(text))])
    }

    fn integer_record(value: i64) -> PortableValue {
        value_record(
            "integer",
            vec![("value", PortableValue::integer(BigInteger::from(value)))],
        )
    }

    fn decimal_record(value: &str) -> PortableValue {
        value_record(
            "real",
            vec![(
                "value",
                PortableValue::decimal(Decimal::parse_json_number(value).expect("decimal")),
            )],
        )
    }

    fn float64_record(value: f64) -> PortableValue {
        value_record(
            "real",
            vec![(
                "value",
                PortableValue::binary_float64(BinaryFloat64::from_bits(value.to_bits())),
            )],
        )
    }

    fn boolean_record(value: bool) -> PortableValue {
        value_record("boolean", vec![("value", PortableValue::boolean(value))])
    }

    fn null_record() -> PortableValue {
        value_record("null", vec![])
    }

    fn tuple_record(elements: Vec<PortableValue>) -> PortableValue {
        value_record(
            "tuple",
            vec![("elements", PortableValue::sequence(elements))],
        )
    }

    fn object_record(entries: Vec<(&str, PortableValue)>) -> PortableValue {
        object_record_owned(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn object_record_owned(entries: Vec<(String, PortableValue)>) -> PortableValue {
        value_record(
            "object",
            vec![(
                "entries",
                PortableValue::sequence(
                    entries
                        .into_iter()
                        .map(|(key, value)| {
                            PortableValue::sequence(vec![PortableValue::string(key), value])
                        })
                        .collect::<Vec<_>>(),
                ),
            )],
        )
    }

    fn expression_record(kind: &str, text: &str) -> PortableValue {
        expression_record_with_fingerprint(kind, text, None)
    }

    fn expression_record_with_fingerprint(
        kind: &str,
        text: &str,
        fingerprint: Option<&str>,
    ) -> PortableValue {
        let mut expression = ObjectBuilder::new();
        expression
            .insert("record", PortableValue::string(EXPRESSION_RECORD))
            .expect("insert");
        expression
            .insert("kind", PortableValue::string(kind))
            .expect("insert");
        expression
            .insert("text", PortableValue::string(text))
            .expect("insert");
        if let Some(fingerprint) = fingerprint {
            expression
                .insert("fingerprint", PortableValue::string(fingerprint))
                .expect("insert");
        }
        value_record("expression", vec![("expression", expression.build())])
    }

    fn render(document: &Document) -> String {
        String::from_utf8(document.render().to_vec()).expect("utf-8")
    }

    fn complete_document(value: &PortableValue, request: &MaterializationRequest) -> Document {
        match materialize(value, request) {
            MaterializationResult::Complete(complete) => {
                assert_eq!(complete.fidelity, MaterializationFidelity::Exact);
                assert!(
                    !complete.provenance.entries().is_empty(),
                    "every materialization maps its root record"
                );
                assert!(
                    complete.report.events().is_empty(),
                    "the canonical style reports no events"
                );
                complete.document
            }
            MaterializationResult::Failed(attempt) => {
                panic!("materialization must complete: {:?}", attempt.failure);
            }
        }
    }

    fn assert_failure(
        value: &PortableValue,
        request: &MaterializationRequest,
        expected: MaterializationFailure,
    ) {
        match materialize(value, request) {
            MaterializationResult::Failed(attempt) => {
                assert_eq!(
                    attempt.failure, expected,
                    "the exact failure variant must surface"
                );
            }
            MaterializationResult::Complete(complete) => panic!(
                "expected {expected:?} but materialization completed: {}",
                render(&complete.document)
            ),
        }
    }

    #[test]
    fn canonical_document_matches_the_published_vector_render() {
        let value = body_record(vec![
            attribute_record("name", string_record("hello")),
            attribute_record("escaped", string_record("a\nb\t\"c\\d")),
            attribute_record("count", integer_record(42)),
            attribute_record("ratio", decimal_record("1.5")),
            attribute_record("enabled", boolean_record(true)),
            attribute_record("nothing", null_record()),
            attribute_record(
                "tags",
                tuple_record(vec![string_record("a"), string_record("b")]),
            ),
            attribute_record(
                "labels",
                object_record(vec![("env", string_record("prod"))]),
            ),
            attribute_record("empty_tuple", tuple_record(vec![])),
            attribute_record("empty_obj", object_record(vec![])),
            block_record(
                "server",
                vec!["web", "1"],
                body_record(vec![attribute_record("port", integer_record(8080))]),
            ),
        ]);
        let document = complete_document(&value, &native_request());
        let expected = "name = \"hello\"\nescaped = \"a\\nb\\t\\\"c\\\\d\"\ncount = 42\nratio = 1.5\nenabled = true\nnothing = null\ntags = [\n  \"a\",\n  \"b\"\n]\nlabels = {\n  env = \"prod\"\n}\nempty_tuple = []\nempty_obj = {}\nserver \"web\" \"1\" {\n  port = 8080\n}\n";
        assert_eq!(render(&document), expected);
    }

    #[test]
    fn reparse_closure_matches_the_published_vector_render_and_fingerprint() {
        let value = body_record(vec![
            attribute_record("derived", expression_record("binary", "1 + 2")),
            attribute_record("big", integer_record(1000)),
            attribute_record("small", decimal_record("1.5")),
        ]);
        let document = complete_document(&value, &native_request());
        let expected = "derived = 1 + 2\nbig = 1000\nsmall = 1.5\n";
        assert_eq!(render(&document), expected);
        // The reparsed expression carries the promised structural
        // fingerprint: the vector's `fingerprint_match` expectation.
        let derived = document.document().body().items()[0]
            .as_attribute()
            .expect("attribute");
        let promised = promised_expression_parse("1 + 2", MaterializationLimits::default())
            .expect("promised parse");
        assert_eq!(
            expression_fingerprint(derived.expression()),
            expression_fingerprint(&promised),
            "the reparse closure compares structural fingerprints"
        );
    }

    #[test]
    fn tfvars_target_rejects_block_records() {
        let value = body_record(vec![block_record(
            "server",
            vec!["x"],
            body_record(vec![attribute_record("a", integer_record(1))]),
        )]);
        assert_failure(
            &value,
            &tfvars_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("items".to_owned()))
                    .child(ValuePathSegment::SequenceElement(0)),
                kind: PortableValueKind::Object,
            },
        );
    }

    #[test]
    fn wrong_record_name_is_invalid_request() {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string("hcl.something-else@1"))
            .expect("insert");
        builder
            .insert("items", PortableValue::sequence(vec![]))
            .expect("insert");
        assert_failure(
            &builder.build(),
            &native_request(),
            MaterializationFailure::InvalidRequest("input record is not hcl.body@1"),
        );
    }

    #[test]
    fn native_target_materializes_block_records() {
        let value = body_record(vec![block_record(
            "server",
            vec!["x"],
            body_record(vec![attribute_record("a", integer_record(1))]),
        )]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "server \"x\" {\n  a = 1\n}\n");
    }

    #[test]
    fn tfvars_target_materializes_attribute_only_records() {
        let value = body_record(vec![attribute_record("region", string_record("us-east-1"))]);
        let document = complete_document(&value, &tfvars_request());
        assert_eq!(render(&document), "region = \"us-east-1\"\n");
        assert_eq!(document.profile(), ProfileId::new("hcl.tfvars", 1));
        assert_eq!(document.status(), FormationStatus::Complete);
    }

    #[test]
    fn request_validation_matrix_fails_exactly() {
        let value = body_record(vec![attribute_record("a", integer_record(1))]);
        let wrong_profile = MaterializationRequest::new(
            ProfileId::new("hcl.json", 1),
            MaterializationStyleId::new(STYLE_CANONICAL, 1),
        );
        assert_failure(
            &value,
            &wrong_profile,
            MaterializationFailure::UnsupportedProfile,
        );
        let wrong_version = MaterializationRequest::new(
            ProfileId::new("hcl.native", 2),
            MaterializationStyleId::new(STYLE_CANONICAL, 1),
        );
        assert_failure(
            &value,
            &wrong_version,
            MaterializationFailure::UnsupportedProfile,
        );
        let wrong_style = MaterializationRequest::new(
            ProfileId::new("hcl.native", 1),
            MaterializationStyleId::new("hcl.fancy", 1),
        );
        assert_failure(
            &value,
            &wrong_style,
            MaterializationFailure::UnsupportedStyle,
        );
        assert_failure(
            &value,
            &native_request().with_encoding(SourceEncoding::Utf16Le),
            MaterializationFailure::UnsupportedEncoding,
        );
        assert_failure(
            &value,
            &native_request().with_newline(NewlinePolicy::CrLf),
            MaterializationFailure::UnsupportedNewline,
        );
        assert_failure(
            &value,
            &native_request().with_newline(NewlinePolicy::None),
            MaterializationFailure::UnsupportedNewline,
        );
    }

    #[test]
    fn minimal_string_escaping_round_trips_exact_text() {
        let cases = [
            ("a\nb\t\"c\\d", "a\\nb\\t\\\"c\\\\d"),
            ("", ""),
            ("plain", "plain"),
            ("${x}", "$${x}"),
            ("%{x}", "%%{x}"),
            ("$${x}", "$$${x}"),
            ("$$$$", "$$$$"),
            ("$$", "$$"),
            ("$", "$"),
            ("a${b}c", "a$${b}c"),
            ("%%{", "%%%{"),
            ("%", "%"),
            ("\u{1}", "\\u0001"),
            ("\u{7f}", "\\u007f"),
            ("\u{80}", "\\u0080"),
            ("\u{9f}", "\\u009f"),
            ("caf\u{e9} \u{1f600}", "caf\u{e9} \u{1f600}"),
            ("\u{2028}", "\u{2028}"),
            ("\u{10ffff}", "\u{10ffff}"),
        ];
        for (text, escaped) in cases {
            let value = body_record(vec![attribute_record("s", string_record(text))]);
            let document = complete_document(&value, &native_request());
            assert_eq!(
                render(&document),
                format!("s = \"{escaped}\"\n"),
                "text {text:?}"
            );
            let attribute = document.document().body().items()[0]
                .as_attribute()
                .expect("attribute");
            assert_eq!(
                quoted_template_text(attribute.expression()).as_deref(),
                Some(text),
                "the closure decodes the exact text of {text:?}"
            );
        }
    }

    #[test]
    fn escaped_lengths_are_exact() {
        for text in [
            "",
            "a",
            "\n",
            "\u{1}",
            "${",
            "$${",
            "a$$$${b}",
            "é\u{1f600}",
        ] {
            assert_eq!(
                quoted_len(text),
                escape_text(text).len() + 2,
                "text {text:?}"
            );
        }
    }

    #[test]
    fn canonical_number_spellings_fold_and_round_trip() {
        let cases = [
            (integer_record(0), "0"),
            (integer_record(-42), "-42"),
            (integer_record(1000), "1000"),
            (decimal_record("1.5"), "1.5"),
            (decimal_record("15e-1"), "1.5"),
            (decimal_record("1.50"), "1.5"),
            (decimal_record("-0.125"), "-0.125"),
            (decimal_record("1e3"), "1000"),
            (decimal_record("0.001"), "0.001"),
            (decimal_record("100e-2"), "1"),
            (float64_record(1.5), "1.5"),
            (
                float64_record(0.1),
                "0.1000000000000000055511151231257827021181583404541015625",
            ),
            (float64_record(-0.0), "0"),
        ];
        for (value, spelling) in cases {
            let record = body_record(vec![attribute_record("n", value)]);
            let document = complete_document(&record, &native_request());
            assert_eq!(
                render(&document),
                format!("n = {spelling}\n"),
                "spelling {spelling:?}"
            );
        }
        // The exact decimal expansion of the double nearest to 1e300: the
        // nearest double to 10^300 is 10^300 + 5.25...e283, and the exact
        // expansion must survive the closure by canonical-decimal equality.
        let huge = body_record(vec![attribute_record("n", float64_record(1.0e300))]);
        let document = complete_document(&huge, &native_request());
        assert_eq!(
            render(&document),
            "n = 1000000000000000052504760255204420248704468581108159154915854115511802457988908195786371375080447864043704443832883878176942523235360430575644792184786706982848387200926575803737830233794788090059368953234970799945081119038967640880074652742780142494579258788820056842838115669472196386865459400540160\n"
        );
    }

    #[test]
    fn non_finite_real_payloads_are_unrepresentable() {
        let root_value_path = ValuePath::root()
            .child(ValuePathSegment::ObjectValue("items".to_owned()))
            .child(ValuePathSegment::SequenceElement(0))
            .child(ValuePathSegment::ObjectValue("value".to_owned()));
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let record = body_record(vec![attribute_record("n", float64_record(value))]);
            assert_failure(
                &record,
                &native_request(),
                MaterializationFailure::Unrepresentable {
                    path: root_value_path.clone(),
                    kind: PortableValueKind::BinaryFloat64,
                },
            );
        }
    }

    #[test]
    fn binary_float32_payloads_convert_exactly() {
        let value = body_record(vec![attribute_record(
            "f",
            value_record(
                "real",
                vec![(
                    "value",
                    PortableValue::binary_float32(BinaryFloat32::from_bits(0.1_f32.to_bits())),
                )],
            ),
        )]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "f = 0.100000001490116119384765625\n");
    }

    #[test]
    fn huge_integers_round_trip_exactly() {
        let value = body_record(vec![attribute_record(
            "big",
            value_record(
                "integer",
                vec![(
                    "value",
                    PortableValue::integer(
                        BigInteger::parse_decimal("123456789012345678901234567890")
                            .expect("integer"),
                    ),
                )],
            ),
        )]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "big = 123456789012345678901234567890\n");
    }

    #[test]
    fn empty_constructors_render_single_line_at_any_depth() {
        let value = body_record(vec![
            attribute_record("a", tuple_record(vec![])),
            attribute_record("b", object_record(vec![])),
            block_record(
                "b",
                vec![],
                body_record(vec![attribute_record("c", tuple_record(vec![]))]),
            ),
        ]);
        let document = complete_document(&value, &native_request());
        let rendered = render(&document);
        assert_eq!(rendered, "a = []\nb = {}\nb {\n  c = []\n}\n", "{rendered}");
    }

    #[test]
    fn constructors_layout_one_item_per_line_at_indentation() {
        let value = body_record(vec![attribute_record(
            "t",
            tuple_record(vec![
                tuple_record(vec![integer_record(1), integer_record(2)]),
                object_record(vec![("k", tuple_record(vec![string_record("x")]))]),
            ]),
        )]);
        let document = complete_document(&value, &native_request());
        let expected =
            "t = [\n  [\n    1,\n    2\n  ],\n  {\n    k = [\n      \"x\"\n    ]\n  }\n]\n";
        assert_eq!(render(&document), expected);
    }

    #[test]
    fn object_keys_emit_bare_identifiers_and_quoted_others() {
        let value = body_record(vec![attribute_record(
            "o",
            object_record(vec![
                ("env", string_record("prod")),
                ("a-b", string_record("hyphen")),
                ("for", string_record("keyword")),
                ("1", string_record("number")),
                ("", string_record("empty")),
                ("true", string_record("keyword2")),
                ("a b", string_record("space")),
                ("caf\u{e9}", string_record("unicode")),
            ]),
        )]);
        let document = complete_document(&value, &native_request());
        let expected = "o = {\n  env = \"prod\",\n  a-b = \"hyphen\",\n  \"for\" = \"keyword\",\n  \"1\" = \"number\",\n  \"\" = \"empty\",\n  true = \"keyword2\",\n  \"a b\" = \"space\",\n  caf\u{e9} = \"unicode\"\n}\n";
        assert_eq!(render(&document), expected);
    }

    #[test]
    fn labels_are_always_quoted_and_escaped() {
        let value = body_record(vec![block_record(
            "b",
            vec!["x", "a b", "${}", ""],
            body_record(vec![]),
        )]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "b \"x\" \"a b\" \"$${}\" \"\" {\n}\n");
    }

    #[test]
    fn negative_numbers_reparse_as_unary_minus_and_match() {
        let value = body_record(vec![
            attribute_record("i", integer_record(-42)),
            attribute_record("r", decimal_record("-1.5")),
        ]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "i = -42\nr = -1.5\n");
    }

    #[test]
    fn duplicate_attribute_in_a_body_is_unrepresentable() {
        let value = body_record(vec![
            attribute_record("a", integer_record(1)),
            attribute_record("a", integer_record(2)),
        ]);
        assert_failure(
            &value,
            &native_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("items".to_owned()))
                    .child(ValuePathSegment::SequenceElement(1)),
                kind: PortableValueKind::String,
            },
        );
    }

    #[test]
    fn invalid_names_and_types_are_unrepresentable() {
        let name_path = ValuePath::root()
            .child(ValuePathSegment::ObjectValue("items".to_owned()))
            .child(ValuePathSegment::SequenceElement(0))
            .child(ValuePathSegment::ObjectValue("name".to_owned()));
        for name in ["a b", "1a", "a.b", "", "_x", "-x", "a\u{1f600}"] {
            let value = body_record(vec![attribute_record(name, integer_record(1))]);
            assert_failure(
                &value,
                &native_request(),
                MaterializationFailure::Unrepresentable {
                    path: name_path.clone(),
                    kind: PortableValueKind::String,
                },
            );
        }
        let type_path = ValuePath::root()
            .child(ValuePathSegment::ObjectValue("items".to_owned()))
            .child(ValuePathSegment::SequenceElement(0))
            .child(ValuePathSegment::ObjectValue("type".to_owned()));
        let value = body_record(vec![block_record("1b", vec![], body_record(vec![]))]);
        assert_failure(
            &value,
            &native_request(),
            MaterializationFailure::Unrepresentable {
                path: type_path,
                kind: PortableValueKind::String,
            },
        );
    }

    #[test]
    fn expression_kind_mismatch_is_invalid_request() {
        let value = body_record(vec![attribute_record(
            "d",
            expression_record("number", "1 + 2"),
        )]);
        assert_failure(
            &value,
            &native_request(),
            MaterializationFailure::InvalidRequest("expression kind does not match text"),
        );
    }

    #[test]
    fn unparseable_expression_text_is_invalid_request() {
        for text in [
            "",
            "1 +",
            "expr = 5",
            "1\nx = 2",
            ")",
            "\"unterminated",
            "a ? b",
        ] {
            let value = body_record(vec![attribute_record(
                "d",
                expression_record("variable", text),
            )]);
            assert_failure(
                &value,
                &native_request(),
                MaterializationFailure::InvalidRequest("expression text does not parse"),
            );
        }
    }

    #[test]
    fn expression_fingerprint_field_validates() {
        let ast = promised_expression_parse("1 + 2", MaterializationLimits::default())
            .expect("promised parse");
        let fingerprint = expression_fingerprint(&ast);
        let value = body_record(vec![attribute_record(
            "d",
            expression_record_with_fingerprint("binary", "1 + 2", Some(&fingerprint)),
        )]);
        let document = complete_document(&value, &native_request());
        assert_eq!(render(&document), "d = 1 + 2\n");
        let wrong = body_record(vec![attribute_record(
            "d",
            expression_record_with_fingerprint("binary", "1 + 2", Some("deadbeef")),
        )]);
        assert_failure(
            &wrong,
            &native_request(),
            MaterializationFailure::InvalidRequest("expression fingerprint mismatch"),
        );
    }

    #[test]
    fn expression_text_may_carry_trailing_trivia() {
        let value = body_record(vec![
            attribute_record("a", expression_record("binary", "1 + 2 // note")),
            attribute_record("b", expression_record("tuple", "[\n  1,\n  2\n]")),
            attribute_record("c", expression_record("binary", "1 + 2\n")),
        ]);
        let document = complete_document(&value, &native_request());
        let expected = "a = 1 + 2 // note\nb = [\n  1,\n  2\n]\nc = 1 + 2\n\n";
        assert_eq!(render(&document), expected);
    }

    #[test]
    fn over_deep_expression_text_hits_the_depth_limit() {
        // The small depth budget keeps the parser's bounded recursion far
        // below any thread stack, while the text still exceeds the budget.
        let text = format!("{}1{}", "(".repeat(40), ")".repeat(40));
        let value = body_record(vec![attribute_record(
            "d",
            expression_record("parenthesized", &text),
        )]);
        assert_failure(
            &value,
            &native_request().with_limits(MaterializationLimits {
                max_depth: 16,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-depth"),
        );
    }

    #[test]
    fn fingerprint_is_stable_and_distinguishes_structure() {
        let first =
            promised_expression_parse("1 + 2", MaterializationLimits::default()).expect("parses");
        let second =
            promised_expression_parse("1+2", MaterializationLimits::default()).expect("parses");
        assert_eq!(
            expression_fingerprint(&first),
            expression_fingerprint(&second),
            "spelling trivia does not change structure"
        );
        let other =
            promised_expression_parse("1 - 2", MaterializationLimits::default()).expect("parses");
        assert_ne!(
            expression_fingerprint(&first),
            expression_fingerprint(&other)
        );
        let number =
            promised_expression_parse("1.50", MaterializationLimits::default()).expect("parses");
        let folded =
            promised_expression_parse("15e-1", MaterializationLimits::default()).expect("parses");
        assert_eq!(
            expression_fingerprint(&number),
            expression_fingerprint(&folded),
            "canonical-decimal equality is structural"
        );
    }

    #[test]
    fn closure_catches_reparsed_model_mismatch() {
        let document = crate::parse(
            Arc::<[u8]>::from(b"a = 1\n".as_slice()),
            HclProfile::NativeV1,
            crate::HclEncodingSelection::ProfileDefault,
            HclParseLimits::default(),
        )
        .expect("forms");
        let item_path = ValuePath::root()
            .child(ValuePathSegment::ObjectValue("items".to_owned()))
            .child(ValuePathSegment::SequenceElement(0));
        let wrong_value = Record {
            body: Body {
                items: vec![BodyItem::Attribute {
                    path: item_path,
                    name: Arc::from("a"),
                    value: ValueNode {
                        kind: ValueKind::String(Arc::from("b")),
                    },
                }],
            },
        };
        assert_eq!(
            verify_closure(&wrong_value, &document, MaterializationLimits::default()),
            Err(MaterializationFailure::FormationFailed),
            "a promised string that reparses as a number must fail the closure"
        );
        let empty_record = Record {
            body: Body { items: Vec::new() },
        };
        assert_eq!(
            verify_closure(&empty_record, &document, MaterializationLimits::default()),
            Err(MaterializationFailure::FormationFailed),
            "an item-count mismatch must fail the closure"
        );
    }

    #[test]
    fn resource_limits_fail_with_exact_names() {
        let wide = body_record(vec![
            attribute_record("a", integer_record(1)),
            attribute_record("b", integer_record(2)),
        ]);
        assert_failure(
            &wide,
            &native_request().with_limits(MaterializationLimits {
                max_input_nodes: 1,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-nodes"),
        );
        let deep = body_record(vec![attribute_record(
            "t",
            tuple_record(vec![tuple_record(vec![tuple_record(vec![
                integer_record(1),
            ])])]),
        )]);
        assert_failure(
            &deep,
            &native_request().with_limits(MaterializationLimits {
                max_depth: 2,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-depth"),
        );
        let deep_block = body_record(vec![block_record(
            "a",
            vec![],
            body_record(vec![block_record("b", vec![], body_record(vec![]))]),
        )]);
        assert_failure(
            &deep_block,
            &native_request().with_limits(MaterializationLimits {
                max_depth: 1,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-depth"),
        );
        let big_string = body_record(vec![attribute_record(
            "s",
            string_record("0123456789abcdef"),
        )]);
        assert_failure(
            &big_string,
            &native_request().with_limits(MaterializationLimits {
                max_output_bytes: 16,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("output-bytes"),
        );
        let single = body_record(vec![attribute_record("a", integer_record(1))]);
        assert_failure(
            &single,
            &native_request().with_limits(MaterializationLimits {
                max_provenance_entries: 1,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("provenance-entries"),
        );
    }

    #[test]
    fn provenance_covers_every_input_node_and_is_target_bound() {
        let value = body_record(vec![
            attribute_record("a", integer_record(1)),
            block_record(
                "b",
                vec!["x"],
                body_record(vec![attribute_record("c", string_record("y"))]),
            ),
        ]);
        match materialize(&value, &native_request()) {
            MaterializationResult::Complete(complete) => {
                // Root, attribute a, value 1, block b, label x, attribute c,
                // value y: seven entries.
                assert_eq!(complete.provenance.entries().len(), 7);
                let target = complete.document.snapshot_identity();
                for entry in complete.provenance.entries() {
                    assert_eq!(entry.outputs.len(), 1);
                    let origin = &entry.outputs[0];
                    assert_eq!(origin.snapshot, target);
                    assert_eq!(origin.node.snapshot(), target);
                    assert_eq!(origin.span.snapshot(), target);
                    assert_eq!(origin.relation, MaterializationRelation::Direct);
                }
            }
            MaterializationResult::Failed(attempt) => {
                panic!("must complete: {:?}", attempt.failure);
            }
        }
    }

    #[test]
    fn provenance_spans_are_exact() {
        let value = body_record(vec![
            attribute_record("a", integer_record(1)),
            block_record("b", vec!["x"], body_record(vec![])),
        ]);
        let MaterializationResult::Complete(complete) = materialize(&value, &native_request())
        else {
            panic!("must complete");
        };
        let source = complete.document.render();
        let entries = complete.provenance.entries();
        let root_origin = &entries[0].outputs[0];
        assert_eq!(
            &source[root_origin.span.start_byte()..root_origin.span.end_byte()],
            b"a = 1\nb \"x\" {\n}\n",
            "the root record maps to the whole document"
        );
        assert_eq!(root_origin.node.role(), NodeRole::HclDocument);
        let attribute_origin = &entries[1].outputs[0];
        assert_eq!(
            &source[attribute_origin.span.start_byte()..attribute_origin.span.end_byte()],
            b"a = 1"
        );
        assert_eq!(attribute_origin.node.role(), NodeRole::HclAttribute);
        let value_origin = &entries[2].outputs[0];
        assert_eq!(
            &source[value_origin.span.start_byte()..value_origin.span.end_byte()],
            b"1"
        );
        assert_eq!(value_origin.node.role(), NodeRole::HclExpression);
        let block_origin = &entries[3].outputs[0];
        assert_eq!(
            &source[block_origin.span.start_byte()..block_origin.span.end_byte()],
            b"b \"x\" {\n}"
        );
        assert_eq!(block_origin.node.role(), NodeRole::HclBlock);
        let label_origin = &entries[4].outputs[0];
        assert_eq!(
            &source[label_origin.span.start_byte()..label_origin.span.end_byte()],
            b"\"x\""
        );
        assert_eq!(label_origin.node.role(), NodeRole::HclBlockLabel);
    }

    #[test]
    fn materialize_parse_materialize_is_a_fixed_point() {
        let value = body_record(vec![
            attribute_record("name", string_record("hello")),
            attribute_record("escaped", string_record("a\nb\t\"c\\d")),
            attribute_record("count", integer_record(42)),
            attribute_record("ratio", decimal_record("1.5")),
            attribute_record("negative", decimal_record("-0.125")),
            attribute_record("enabled", boolean_record(true)),
            attribute_record("nothing", null_record()),
            attribute_record(
                "tags",
                tuple_record(vec![string_record("a"), string_record("b")]),
            ),
            attribute_record(
                "labels",
                object_record(vec![
                    ("env", string_record("prod")),
                    ("for", string_record("x")),
                ]),
            ),
            attribute_record("empty_tuple", tuple_record(vec![])),
            attribute_record("empty_obj", object_record(vec![])),
            attribute_record("derived", expression_record("binary", "1 + 2")),
            block_record(
                "server",
                vec!["web", "1"],
                body_record(vec![attribute_record("port", integer_record(8080))]),
            ),
        ]);
        let first = complete_document(&value, &native_request());
        let first_render = first.render().to_vec();
        // Rebuild the record from the reparsed native model through the
        // literal-value extraction; the fixed point must reproduce the input
        // record exactly.
        let rebuilt = record_from_document(&first);
        assert_eq!(
            rebuilt, value,
            "the reparsed native model projects back to the same record"
        );
        let second = complete_document(&rebuilt, &native_request());
        assert_eq!(
            second.render(),
            first_render,
            "the canonical render is a fixed point"
        );
    }

    #[test]
    fn projection_to_materialization_loop_closes_with_reparse_equality() {
        // The M9 fixture gate: parse a Complete document, project it to the
        // `hcl.body@1` record, materialize the record canonically, and
        // reparse the generated bytes; the reparsed native model must equal
        // the source model (RFC 0014 §9 closure). The sources exercise
        // nested blocks (native only — tfvars admits attribute-only top
        // levels, RFC 0014 §5), repeated object keys, canonical number
        // folding (`1.50` and `15e-1` both become `1.5`), and the
        // `hcl.expression@1` ExtendedValue of the explicit ProjectExpression
        // policy with its structural fingerprint verified by the closure.
        let native_source: &[u8] = b"region = \"us-east-1\"\nratio = 1.50\nsmall = 15e-1\ncount = 42\ndups = { a = 1, a = 2 }\nserver \"web\" \"prod\" {\n  name = \"x\"\n  port = 8080\n  child {\n    deep = true\n  }\n}\nderived = var.name + 1\n";
        let tfvars_source: &[u8] = b"region = \"us-east-1\"\nratio = 1.50\nsmall = 15e-1\ncount = 42\ndups = { a = 1, a = 2 }\nderived = var.name + 1\n";
        let request = crate::projection::ProjectionRequest::body_with_expression_policy(
            crate::projection::ExpressionPolicy::ProjectExpression,
        );
        let cases: [(HclProfile, &[u8], &str); 2] = [
            (
                HclProfile::NativeV1,
                native_source,
                "region = \"us-east-1\"\nratio = 1.5\nsmall = 1.5\ncount = 42\ndups = {\n  a = 1,\n  a = 2\n}\nserver \"web\" \"prod\" {\n  name = \"x\"\n  port = 8080\n  child {\n    deep = true\n  }\n}\nderived = var.name + 1\n",
            ),
            (
                HclProfile::TfvarsV1,
                tfvars_source,
                "region = \"us-east-1\"\nratio = 1.5\nsmall = 1.5\ncount = 42\ndups = {\n  a = 1,\n  a = 2\n}\nderived = var.name + 1\n",
            ),
        ];
        for (profile, source, expected_render) in cases {
            let document = crate::parse(
                Arc::<[u8]>::from(source),
                profile,
                crate::HclEncodingSelection::ProfileDefault,
                HclParseLimits::default(),
            )
            .expect("complete formation");
            assert_eq!(document.status(), FormationStatus::Complete);
            let crate::projection::ProjectionResult::Complete(projection) =
                crate::projection::project(&document, request)
            else {
                panic!("projection must complete");
            };
            let target = match profile {
                HclProfile::NativeV1 => native_request(),
                HclProfile::TfvarsV1 => tfvars_request(),
            };
            let materialized = complete_document(&projection.value, &target);
            assert_eq!(render(&materialized), expected_render);
            assert!(
                native_body_eq(materialized.document().body(), document.document().body()),
                "the reparsed native model must equal the source model under {profile:?}"
            );
            // The projected `hcl.expression@1` fingerprint is exactly the
            // fingerprint the closure computes over the reparsed expression
            // (the shared M6/M7 adaptation point of the codec).
            let derived = materialized
                .document()
                .body()
                .items()
                .iter()
                .find_map(|item| match item {
                    HclBodyItem::Attribute(attribute) if attribute.name() == "derived" => {
                        Some(attribute)
                    }
                    _ => None,
                })
                .expect("derived attribute");
            assert_eq!(
                expression_fingerprint(derived.expression()),
                projected_fingerprint(&projection.value, "derived"),
                "the reparse closure fingerprint must equal the projected fingerprint"
            );
        }
    }

    #[test]
    fn old_split_record_shape_is_rejected_with_a_precise_diagnostic() {
        // The pre-RFC 0014 §8.2 split record (separate `attributes` and
        // `blocks` members) is not the published `hcl.body@1` shape: the
        // record must carry one ordered `items` sequence (RFC 0014 §8.2).
        // The diagnostic must name the missing member instead of masking
        // the mismatch behind a generic shape error.
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string(BODY_RECORD))
            .expect("insert");
        builder
            .insert("attributes", PortableValue::sequence(vec![]))
            .expect("insert");
        builder
            .insert("blocks", PortableValue::sequence(vec![]))
            .expect("insert");
        assert_failure(
            &builder.build(),
            &native_request(),
            MaterializationFailure::InvalidRequest("input body record is missing the items member"),
        );

        // An `items` sequence whose item lacks the `kind` member (the old
        // attribute item shape) fails with the item-level diagnostic.
        let mut item = ObjectBuilder::new();
        item.insert("name", PortableValue::string("a"))
            .expect("insert");
        item.insert("value", PortableValue::string("x"))
            .expect("insert");
        let items_record = body_record(vec![item.build()]);
        assert_failure(
            &items_record,
            &native_request(),
            MaterializationFailure::InvalidRequest("body item is missing the kind member"),
        );
    }

    /// Structural equality of two native body trees: attribute names and
    /// expressions (RFC 0014 §6 structural equality), block types, label
    /// texts, and nested bodies.
    fn native_body_eq(left: &HclBody, right: &HclBody) -> bool {
        let left = left.items();
        let right = right.items();
        left.len() == right.len()
            && left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| match (left, right) {
                    (HclBodyItem::Attribute(left), HclBodyItem::Attribute(right)) => {
                        left.name() == right.name() && left.expression() == right.expression()
                    }
                    (HclBodyItem::Block(left), HclBodyItem::Block(right)) => {
                        left.block_type() == right.block_type()
                            && left.labels().len() == right.labels().len()
                            && left
                                .labels()
                                .iter()
                                .zip(right.labels())
                                .all(|(left, right)| left.text() == right.text())
                            && native_body_eq(left.body(), right.body())
                    }
                    _ => false,
                })
    }

    /// The `fingerprint` member of one projected `hcl.expression@1` record
    /// inside the projected `hcl.body@1` record.
    fn projected_fingerprint(record: &PortableValue, name: &str) -> String {
        for item in record
            .as_object()
            .expect("record object")
            .iter()
            .find(|entry| entry.key() == "items")
            .expect("items member")
            .value()
            .as_sequence()
            .expect("items sequence")
        {
            let object = item.as_object().expect("item object");
            let kind = object
                .iter()
                .find(|entry| entry.key() == "kind")
                .expect("kind member")
                .value()
                .as_string();
            if kind != Some("attribute") {
                continue;
            }
            let item_name = object
                .iter()
                .find(|entry| entry.key() == "name")
                .expect("name member")
                .value()
                .as_string();
            if item_name == Some(name) {
                return object
                    .iter()
                    .find(|entry| entry.key() == "value")
                    .expect("value member")
                    .value()
                    .as_object()
                    .expect("expression record")
                    .iter()
                    .find(|entry| entry.key() == "fingerprint")
                    .expect("fingerprint member")
                    .value()
                    .as_string()
                    .expect("fingerprint string")
                    .to_owned();
            }
        }
        panic!("attribute {name:?} not found");
    }

    #[test]
    fn empty_body_materializes_to_an_empty_document() {
        let value = body_record(vec![]);
        let document = complete_document(&value, &native_request());
        assert_eq!(document.render(), b"");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.profile(), ProfileId::new("hcl.native", 1));
    }

    #[test]
    fn analyzed_paths_are_recorded_before_failure() {
        let value = body_record(vec![
            attribute_record("a", integer_record(1)),
            attribute_record("bad", value_record("blob", vec![])),
        ]);
        match materialize(&value, &native_request()) {
            MaterializationResult::Failed(attempt) => {
                assert!(
                    attempt.analyzed_input_paths.len() >= 5,
                    "the root, the items, and the values are analyzed before the failure"
                );
            }
            MaterializationResult::Complete(_) => panic!("must fail"),
        }
    }

    /// Rebuilds the `hcl.body@1` record of one reparsed document from its
    /// native model: literal values through [`literal_value`], derived
    /// expressions as `hcl.expression@1` with their span-derived exact text.
    fn record_from_document(document: &Document) -> PortableValue {
        fn body_from(body: &HclBody, document: &Document) -> PortableValue {
            let items = body
                .items()
                .iter()
                .map(|item| match item {
                    HclBodyItem::Attribute(attribute) => attribute_record(
                        attribute.name(),
                        value_from_expression(attribute.expression(), document),
                    ),
                    HclBodyItem::Block(block) => block_record(
                        block.block_type(),
                        block.labels().iter().map(HclBlockLabel::text).collect(),
                        body_from(block.body(), document),
                    ),
                })
                .collect();
            body_record(items)
        }
        fn value_from_expression(expression: &HclExpression, document: &Document) -> PortableValue {
            if let Ok(literal) = literal_value(expression) {
                return value_from_literal(&literal);
            }
            let text = expression
                .text(document.source())
                .expect("decoded expression text");
            expression_record(expression_kind_spelling(expression), text)
        }
        fn value_from_literal(literal: &HclLiteralValue) -> PortableValue {
            match literal {
                HclLiteralValue::Integer(spelling) => value_record(
                    "integer",
                    vec![(
                        "value",
                        PortableValue::integer(
                            BigInteger::parse_decimal(spelling).expect("canonical integer"),
                        ),
                    )],
                ),
                HclLiteralValue::Decimal(spelling) => value_record(
                    "real",
                    vec![(
                        "value",
                        PortableValue::decimal(
                            Decimal::parse_json_number(spelling).expect("canonical decimal"),
                        ),
                    )],
                ),
                HclLiteralValue::String(text) => string_record(text),
                HclLiteralValue::Boolean(flag) => boolean_record(*flag),
                HclLiteralValue::Null => null_record(),
                HclLiteralValue::Tuple(elements) => {
                    tuple_record(elements.iter().map(value_from_literal).collect())
                }
                HclLiteralValue::Object(entries) => object_record_owned(
                    entries
                        .iter()
                        .map(|entry| (literal_key(entry), value_from_literal(entry.value())))
                        .collect(),
                ),
            }
        }
        fn literal_key(entry: &HclLiteralObjectEntry) -> String {
            match entry.key() {
                HclLiteralKey::Identifier(name) | HclLiteralKey::String(name) => name.clone(),
                HclLiteralKey::Number(spelling) => spelling.clone(),
                // A parenthesized key reduces to its value; the canonical
                // output always quotes keys, so a round-tripped record only
                // ever carries string spellings.
                HclLiteralKey::Value(value) => match value {
                    HclLiteralValue::Integer(spelling) | HclLiteralValue::Decimal(spelling) => {
                        spelling.clone()
                    }
                    _ => String::new(),
                },
            }
        }
        body_from(document.document().body(), document)
    }
}
