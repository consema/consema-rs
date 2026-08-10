//! Canonical `plist.xml-canonical@1` / `plist.binary-canonical@1`
//! materialization (RFC 0013 §10).
//!
//! Materialization consumes one `plist.value-tree@1` record and creates a new
//! `plist.xml@1` or `plist.binary@1` Document. It is not a formatter for an
//! existing source: the input is the projected value tree, the output is a new
//! snapshot whose complete native model equals the promised input semantics
//! (RFC 0013 §10.3).
//!
//! # Record contract
//!
//! The input is the exact `plist.value-tree@1` record the projection
//! publishes (RFC 0013 §9, §10): an Object with:
//!
//! ```text
//! { "record": "plist.value-tree@1",
//!   "root": <value>,
//!   "truncate_policy": "TruncateWithReport" | absent }
//! ```
//!
//! A value is one of the typed PortableValue members of the value-tree
//! record:
//!
//! ```text
//! dict    EntryMapping of [key string, value] associations
//!         or an Object of ordered members (the JSON vector spelling)
//! array   Sequence of values
//! string  String
//! integer Integer                                        signed 64-bit
//! real    BinaryFloat64 | BinaryFloat32 | Decimal
//! boolean Boolean
//! date    Object { "epoch": "2001-01-01T00:00:00Z",      exact double
//!                   "seconds": <BinaryFloat64|Decimal> } seconds since the
//!                                                        2001 epoch
//! data    Bytes
//!         or an Object { "hex": <String> }                strict lowercase or
//!                                                        uppercase hex
//! uid     Object { "uid": <Integer> }                    unsigned 32-bit
//! ```
//!
//! Dict associations are ordered and duplicate keys are preserved (RFC 0013
//! §4.4, §5.9). The numeric payloads are accepted as the exact binary float
//! kinds (the `plist.projection.value-tree@1` emission) or as `Decimal` (the
//! consema-json projection of the conformance vectors); a Decimal is
//! converted to its double value.
//!
//! The JSON vector spelling maps a unique-key object to an `Object` and a
//! duplicate-key object to an `EntryMapping`; both are ordered association
//! containers, so both are admitted. An Object whose members are exactly
//! `epoch` + `seconds`, `uid`, or `hex` is the corresponding typed leaf, and
//! any other Object is a dictionary. An Object carrying a `kind` member is
//! rejected: the explicit `{kind, ...}` record spelling is not the
//! `plist.value-tree@1` record.
//!
//! # Request contract
//!
//! - `plist.xml-canonical@1` targets profile `plist.xml@1`: encoding must be
//!   `Utf8` (the style emits UTF-8 without BOM, RFC 0013 §10.1) and the
//!   newline policy must be `Lf`.
//! - `plist.binary-canonical@1` targets profile `plist.binary@1`: encoding
//!   must be `Binary` and the newline policy must be `None` (binary output has
//!   no newline).
//!
//! Any other profile, style, encoding, or newline is an unsupported failure.
//!
//! # Fractional-second dates and `TruncateWithReport`
//!
//! The XML grammar is whole-second only (RFC 0013 §4.7). A fractional-second
//! date leaf under `plist.xml-canonical@1` fails atomically unless the record
//! carries `"truncate_policy": "TruncateWithReport"`, which discards the
//! fraction (truncation toward zero), emits one
//! `plist.materialization.fractional-date@1` report event per truncated date
//! with the input value path and the original seconds, and marks the whole
//! operation `Transformed` (RFC 0013 §10.1, hard gate 3). Truncation is never
//! silent. The binary style preserves fractional seconds exactly and never
//! consults the policy.
//!
//! # Failure mapping (contract for the conformance runner)
//!
//! Every failure is a shared `MaterializationFailure`; the plist suite maps it
//! to a `plist.materialization.*@1` code:
//!
//! ```text
//! Unrepresentable { kind: Date }           -> plist.materialization.fractional-date@1
//! Unrepresentable { .. } (other kinds)     -> plist.materialization.unrepresentable@1
//! ResourceLimit(name)                      -> plist.materialization.resource-limit@1
//! InvalidRequest / Unsupported* / FormationFailed
//!                                           -> core.materialization.*@1 (shared codes)
//! ```
//!
//! A `Date` kind marks a plist value-tree date leaf that cannot be expressed
//! by the XML whole-second calendar grammar: the fraction policy is absent,
//! the calendar year is out of the grammar's range, the value is non-finite,
//! or the exact bits (negative zero) do not survive the spelling.
//!
//! # Provenance
//!
//! One provenance entry maps every input value path to its exact output
//! origin: for binary, the object-table object (`NodeRole::PlistValue`,
//! marker-through-payload span); for XML, the value element (`NodeRole::PlistValue`,
//! open-tag-through-close-tag span, arena ordinals assigned in close-tag
//! order). Relations are `Direct`.
//!
//! # Closure
//!
//! Every style validates the complete input before proportional allocation,
//! encodes, reparses the exact generated bytes under the promised Profile, and
//! compares the reparsed native model to the promised input semantics (RFC
//! 0013 §10.3). Failure returns no target Document, partial bytes, or partial
//! provenance. The reparse uses limits derived from the request so a bounded
//! input cannot fail its own closure.
//!
//! The module is not yet re-exported from the crate root (the M5-M8 parallel
//! milestones land their `pub use` wiring together); this attribute is the
//! shared adaptation-point pattern of the parallel milestone files and is
//! removed when the crate root exports land.
use crate::native::{
    PLIST_EPOCH_OFFSET_UNIX, PlistArray, PlistBoolean, PlistData, PlistDate, PlistDict,
    PlistDictEntry, PlistDocument, PlistDocumentBuilder, PlistInteger, PlistKey, PlistReal,
    PlistString, PlistStringStatus, PlistUid, PlistValue, PlistValueRef, RealWidth,
};
use crate::{Document, PlistEncodingSelection, PlistParseLimits, PlistProfile, PlistSyntaxKind};
use consema_core::{
    Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity, ObjectEntry, PortableValue,
    PortableValueKind, ValuePath, ValuePathSegment,
};
use consema_document::{
    CompleteMaterialization, FailedMaterializationAttempt, FormationStatus, MaterializationFailure,
    MaterializationFidelity, MaterializationInputLocation, MaterializationLimits,
    MaterializationProvenanceEntry, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationResult, MaterializedOrigin,
    NewlinePolicy, NodeRole, ParseLimits, SourceEncoding, Span,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Style identifier `plist.xml-canonical` (RFC 0013 §10.1).
const STYLE_XML: &str = "plist.xml-canonical";
/// Style identifier `plist.binary-canonical` (RFC 0013 §10.2).
const STYLE_BINARY: &str = "plist.binary-canonical";
/// Versioned value-tree record name (RFC 0013 §9).
const VALUE_TREE_RECORD: &str = "plist.value-tree@1";
/// The only admitted truncation policy (RFC 0013 §10.1).
const TRUNCATE_POLICY: &str = "TruncateWithReport";
/// Fixed XML spelling of the plist epoch carried by every date leaf of the
/// value-tree record (RFC 0013 §9).
const PLIST_EPOCH_SPELLING: &str = "2001-01-01T00:00:00Z";
/// Stable truncation report/failure code (RFC 0013 §10.1, §12).
const FRACTIONAL_DATE_CODE: &str = "plist.materialization.fractional-date@1";
/// Exact bits of `-0.0`; the XML date spelling cannot distinguish signed
/// zeros, so a negative-zero date does not survive the closure.
const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;
/// `2^53`: the largest magnitude at which every integral double is exactly
/// representable, so the day/second decomposition below it is exact.
const EXACT_UNIX_SECONDS_BOUND: f64 = 9_007_199_254_740_992.0;

/// The two canonical materialization styles (RFC 0013 §10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Style {
    /// `plist.xml-canonical@1`: the Apple header spelling, four-space
    /// indentation, LF line endings, whole-second dates (RFC 0013 §10.1).
    Xml,
    /// `plist.binary-canonical@1`: minimal widths, deduplicated scalars,
    /// `sortVersion = 0x00` (RFC 0013 §10.2).
    Binary,
}

/// Materializes one `plist.value-tree@1` record into a new canonical plist
/// document (RFC 0013 §10).
///
/// The requested style selects the target profile and representation:
/// `plist.xml-canonical@1` produces a `plist.xml@1` Document and
/// `plist.binary-canonical@1` a `plist.binary@1` Document. The generated bytes
/// are reparsed under the promised Profile and the reparsed native model is
/// compared to the promised input semantics; failure returns no target
/// Document, no partial bytes, and no partial provenance.
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
    let style = validate_request(request)?;
    let limits = request.limits();
    let mut record = Record::validate(value, request, analyzed)?;
    let (native, events, transformed) = build_native(&mut record, style, request)?;
    let (bytes, items) = match style {
        Style::Xml => serialize_xml(&record, limits)?,
        Style::Binary => serialize_binary(&record, limits)?,
    };
    let profile = match style {
        Style::Xml => PlistProfile::XmlV1,
        Style::Binary => PlistProfile::BinaryV1,
    };
    let document = crate::parse(
        Arc::from(bytes),
        profile,
        PlistEncodingSelection::ProfileDefault,
        parse_limits(limits),
    )
    .map_err(|_| MaterializationFailure::FormationFailed)?;
    if document.status() != FormationStatus::Complete || document.document() != Some(&native) {
        return Err(MaterializationFailure::FormationFailed);
    }
    let report = MaterializationReport::new(events, limits)?;
    let provenance = build_provenance(items, &document, style, limits)?;
    let fidelity = if transformed {
        MaterializationFidelity::Transformed
    } else {
        MaterializationFidelity::Exact
    };
    Ok(CompleteMaterialization {
        document,
        fidelity,
        report,
        provenance,
    })
}

/// Validates the request against the frozen style contracts (RFC 0013 §10).
fn validate_request(request: &MaterializationRequest) -> Result<Style, MaterializationFailure> {
    let profile = request.target_profile();
    let style = request.style();
    let selected = match (profile.id(), profile.version(), style.id(), style.version()) {
        ("plist.xml", 1, STYLE_XML, 1) => Style::Xml,
        ("plist.binary", 1, STYLE_BINARY, 1) => Style::Binary,
        (id, version, _, _) if (id != "plist.xml" && id != "plist.binary") || version != 1 => {
            return Err(MaterializationFailure::UnsupportedProfile);
        }
        _ => return Err(MaterializationFailure::UnsupportedStyle),
    };
    match selected {
        Style::Xml => {
            if request.encoding() != SourceEncoding::Utf8 {
                return Err(MaterializationFailure::UnsupportedEncoding);
            }
            if request.newline() != NewlinePolicy::Lf {
                return Err(MaterializationFailure::UnsupportedNewline);
            }
        }
        Style::Binary => {
            if request.encoding() != SourceEncoding::Binary {
                return Err(MaterializationFailure::UnsupportedEncoding);
            }
            if request.newline() != NewlinePolicy::None {
                return Err(MaterializationFailure::UnsupportedNewline);
            }
        }
    }
    Ok(selected)
}

/// Parse limits for the closure reparse, derived from the request so a
/// bounded input cannot fail its own closure. The output object table may
/// hold one key object per dictionary entry in addition to the value nodes,
/// so the object bound doubles the input node budget; every other bound is
/// derived from the output byte budget, which the generated bytes provably
/// satisfy.
const fn parse_limits(limits: MaterializationLimits) -> PlistParseLimits {
    PlistParseLimits {
        common: ParseLimits {
            max_source_bytes: limits.max_output_bytes,
            max_nesting_depth: limits.max_depth.saturating_add(2),
            max_token_count: limits.max_output_bytes,
            max_node_count: limits.max_input_nodes,
            max_diagnostics: limits.max_report_entries,
        },
        max_decoded_utf8_bytes: limits.max_output_bytes.saturating_mul(3),
        max_decoded_scalars: limits.max_output_bytes,
        max_object_count: limits.max_input_nodes.saturating_mul(2),
        max_container_depth: limits.max_depth,
        max_dict_entries: limits.max_input_nodes,
        max_array_elements: limits.max_input_nodes,
        max_duplicate_key_group_members: limits.max_input_nodes,
        max_string_code_units: limits.max_output_bytes,
        max_data_bytes: limits.max_output_bytes,
        max_uid_count: limits.max_input_nodes,
        max_extended_size_integers: limits.max_input_nodes.saturating_mul(2),
        max_extended_size_value: limits.max_input_nodes,
        max_offset_int_size: 8,
        max_object_ref_size: 8,
        max_offset_table_bytes: limits.max_output_bytes.saturating_mul(8),
        max_syntax_pieces: limits.max_output_bytes,
        max_binary_facts: limits.max_output_bytes.saturating_mul(16),
        max_conversion_nodes: limits.max_input_nodes,
        max_report_events: limits.max_report_entries,
        max_recovery_regions: limits.max_report_entries,
    }
}

/// One validated `plist.value-tree@1` record.
struct Record {
    /// Root value record.
    root: ValueNode,
    /// Whether the record authorized `TruncateWithReport`.
    policy: bool,
}

/// One validated value record with its input path.
struct ValueNode {
    /// Input path inside the record.
    path: ValuePath,
    /// Validated value.
    kind: ValueKind,
}

/// One validated dictionary association.
struct DictEntry {
    /// Exact key string content.
    key: PlistString,
    /// Input path of the key element inside the record.
    key_path: ValuePath,
    /// Associated value.
    value: ValueNode,
}

/// Closed validated value kinds.
enum ValueKind {
    /// Ordered dictionary.
    Dict {
        /// Ordered associations.
        entries: Vec<DictEntry>,
    },
    /// Ordered array.
    Array {
        /// Ordered elements.
        elements: Vec<ValueNode>,
    },
    /// Exact UTF-16 string.
    String(PlistString),
    /// Signed 64-bit integer.
    Integer(i64),
    /// IEEE 754 real with its width fact.
    Real(PlistReal),
    /// Boolean.
    Boolean(bool),
    /// Exact double seconds since the plist epoch; the policy may truncate
    /// the fraction in place under the XML style.
    Date {
        /// Seconds, possibly truncated by an authorized policy.
        seconds: f64,
    },
    /// Exact bytes.
    Data(Arc<[u8]>),
    /// Unsigned 32-bit UID.
    Uid(u32),
}

/// Input node budget and depth accounting during validation.
struct Validator {
    /// Value nodes visited so far.
    nodes: usize,
    /// Requested limits.
    limits: MaterializationLimits,
}

impl Validator {
    fn new(limits: MaterializationLimits) -> Self {
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

impl Record {
    /// Validates the record shape, the truncation policy, the value tree, the
    /// input node budget, and the container depth budget; every visited value
    /// path is recorded in `analyzed`.
    fn validate(
        value: &PortableValue,
        request: &MaterializationRequest,
        analyzed: &mut Vec<ValuePath>,
    ) -> Result<Self, MaterializationFailure> {
        analyzed.push(ValuePath::root());
        let record_path =
            ValuePath::root().child(ValuePathSegment::ObjectValue("record".to_owned()));
        let record = expect_string_field(value, "record", &record_path)?;
        if record != VALUE_TREE_RECORD {
            return Err(MaterializationFailure::InvalidRequest(
                "input record is not plist.value-tree@1",
            ));
        }
        let policy = match value
            .as_object()
            .and_then(|object| object_field(object, "truncate_policy"))
        {
            None => false,
            Some(policy) => {
                let policy_path = ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("truncate_policy".to_owned()));
                let policy =
                    policy
                        .as_string()
                        .ok_or_else(|| MaterializationFailure::Unrepresentable {
                            path: policy_path.clone(),
                            kind: policy.kind(),
                        })?;
                if policy != TRUNCATE_POLICY {
                    return Err(MaterializationFailure::InvalidRequest(
                        "unsupported truncate policy",
                    ));
                }
                true
            }
        };
        let root_path = ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned()));
        let root_value = expect_object_field(value, "root", &root_path)?;
        let mut validator = Validator::new(request.limits());
        let root = ValueNode::validate(root_value, &root_path, &mut validator, analyzed, 0)?;
        Ok(Self { root, policy })
    }
}

impl ValueNode {
    /// Validates one value of the `plist.value-tree@1` record and its
    /// descendants (RFC 0013 §9).
    fn validate(
        value: &PortableValue,
        path: &ValuePath,
        validator: &mut Validator,
        analyzed: &mut Vec<ValuePath>,
        depth: usize,
    ) -> Result<Self, MaterializationFailure> {
        validator.step()?;
        analyzed.push(path.clone());
        let max_output_bytes = validator.limits.max_output_bytes;
        let kind = if let Some(entries) = value.as_entry_mapping() {
            // Ordered dictionary associations (RFC 0013 §9); the projection
            // emission keeps duplicate keys and association order.
            if depth + 1 > validator.limits.max_depth {
                return Err(MaterializationFailure::ResourceLimit("input-depth"));
            }
            let mut out = Vec::with_capacity(entries.len());
            for (ordinal, entry) in entries.iter().enumerate() {
                let key_path = path.child(ValuePathSegment::EntryKey(ordinal as u64));
                let key = entry.key().as_string().ok_or_else(|| {
                    MaterializationFailure::Unrepresentable {
                        path: key_path.clone(),
                        kind: entry.key().kind(),
                    }
                })?;
                let value_path = path.child(ValuePathSegment::EntryValue(ordinal as u64));
                let value_node = ValueNode::validate(
                    entry.value(),
                    &value_path,
                    validator,
                    analyzed,
                    depth + 1,
                )?;
                out.push(DictEntry {
                    key: PlistString::from_unicode(key),
                    key_path,
                    value: value_node,
                });
            }
            ValueKind::Dict { entries: out }
        } else if let Some(elements) = value.as_sequence() {
            // Ordered array elements (RFC 0013 §9).
            if depth + 1 > validator.limits.max_depth {
                return Err(MaterializationFailure::ResourceLimit("input-depth"));
            }
            let mut out = Vec::with_capacity(elements.len());
            for (index, element) in elements.iter().enumerate() {
                let element_path = path.child(ValuePathSegment::SequenceElement(index as u64));
                out.push(ValueNode::validate(
                    element,
                    &element_path,
                    validator,
                    analyzed,
                    depth + 1,
                )?);
            }
            ValueKind::Array { elements: out }
        } else if let Some(text) = value.as_string() {
            if text.len() > max_output_bytes {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            ValueKind::String(PlistString::from_unicode(text))
        } else if let Some(integer) = value.as_integer() {
            let value = integer
                .to_i64()
                .ok_or(MaterializationFailure::Unrepresentable {
                    path: path.clone(),
                    kind: PortableValueKind::Integer,
                })?;
            ValueKind::Integer(value)
        } else if let Some(real) = match (
            value.as_binary_float32(),
            value.as_binary_float64(),
            value.as_decimal(),
        ) {
            (Some(bits), _, _) => Some(PlistReal::single(f32::from_bits(bits.bits()))),
            (None, Some(bits), _) => Some(PlistReal::double(f64::from_bits(bits.bits()))),
            (None, None, Some(decimal)) => decimal_to_f64(decimal).map(PlistReal::double),
            _ => None,
        } {
            ValueKind::Real(real)
        } else if let Some(boolean) = value.as_boolean() {
            ValueKind::Boolean(boolean)
        } else if let Some(bytes) = value.as_bytes() {
            if bytes.len() > max_output_bytes {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            ValueKind::Data(Arc::from(bytes.to_vec()))
        } else if let Some(object) = value.as_object() {
            // The JSON vector spelling maps containers and leaf records to
            // Objects; the member set dispatches them.
            if object_field(object, "kind").is_some() {
                // The explicit `{kind, ...}` record spelling is not the
                // `plist.value-tree@1` record (RFC 0013 §9).
                return Err(MaterializationFailure::Unrepresentable {
                    path: path.clone(),
                    kind: PortableValueKind::Object,
                });
            }
            if let (Some(epoch), Some(seconds)) = (
                object_field(object, "epoch"),
                object_field(object, "seconds"),
            ) {
                // Date leaf: exact double seconds plus the fixed epoch
                // constant (RFC 0013 §9).
                let epoch_path = path.child(ValuePathSegment::ObjectValue("epoch".to_owned()));
                let epoch =
                    epoch
                        .as_string()
                        .ok_or_else(|| MaterializationFailure::Unrepresentable {
                            path: epoch_path,
                            kind: epoch.kind(),
                        })?;
                if epoch != PLIST_EPOCH_SPELLING {
                    return Err(MaterializationFailure::InvalidRequest(
                        "date epoch is not 2001-01-01T00:00:00Z",
                    ));
                }
                let seconds = match (seconds.as_binary_float64(), seconds.as_decimal()) {
                    (Some(bits), _) => f64::from_bits(bits.bits()),
                    (None, Some(decimal)) => decimal_to_f64(decimal).ok_or_else(|| {
                        MaterializationFailure::Unrepresentable {
                            path: path.clone(),
                            kind: PortableValueKind::Date,
                        }
                    })?,
                    _ => {
                        return Err(MaterializationFailure::Unrepresentable {
                            path: path.clone(),
                            kind: PortableValueKind::Date,
                        });
                    }
                };
                if !seconds.is_finite() {
                    return Err(MaterializationFailure::Unrepresentable {
                        path: path.clone(),
                        kind: PortableValueKind::Date,
                    });
                }
                ValueKind::Date { seconds }
            } else if let Some(uid) = object_field(object, "uid") {
                // Typed UID member (RFC 0013 §9).
                let uid_path = path.child(ValuePathSegment::ObjectValue("uid".to_owned()));
                let integer =
                    uid.as_integer()
                        .ok_or_else(|| MaterializationFailure::Unrepresentable {
                            path: uid_path.clone(),
                            kind: uid.kind(),
                        })?;
                let value =
                    integer
                        .to_i64()
                        .ok_or_else(|| MaterializationFailure::Unrepresentable {
                            path: uid_path.clone(),
                            kind: PortableValueKind::Integer,
                        })?;
                let value =
                    u32::try_from(value).map_err(|_| MaterializationFailure::Unrepresentable {
                        path: uid_path,
                        kind: PortableValueKind::Integer,
                    })?;
                ValueKind::Uid(value)
            } else if let Some(hex) = object_field(object, "hex") {
                // The JSON vector spelling of a data leaf.
                let hex_path = path.child(ValuePathSegment::ObjectValue("hex".to_owned()));
                let hex =
                    hex.as_string()
                        .ok_or_else(|| MaterializationFailure::Unrepresentable {
                            path: hex_path.clone(),
                            kind: hex.kind(),
                        })?;
                if hex.len() / 2 > max_output_bytes {
                    return Err(MaterializationFailure::ResourceLimit("output-bytes"));
                }
                let bytes = decode_hex(hex).ok_or(MaterializationFailure::Unrepresentable {
                    path: hex_path,
                    kind: PortableValueKind::String,
                })?;
                ValueKind::Data(Arc::from(bytes))
            } else {
                // A dictionary spelled as an ordered JSON object.
                if depth + 1 > validator.limits.max_depth {
                    return Err(MaterializationFailure::ResourceLimit("input-depth"));
                }
                let mut out = Vec::with_capacity(object.len());
                for (ordinal, entry) in object.iter().enumerate() {
                    let key_path = path.child(ValuePathSegment::EntryKey(ordinal as u64));
                    let value_path = path.child(ValuePathSegment::EntryValue(ordinal as u64));
                    let value_node = ValueNode::validate(
                        entry.value(),
                        &value_path,
                        validator,
                        analyzed,
                        depth + 1,
                    )?;
                    out.push(DictEntry {
                        key: PlistString::from_unicode(entry.key()),
                        key_path,
                        value: value_node,
                    });
                }
                ValueKind::Dict { entries: out }
            }
        } else {
            return Err(MaterializationFailure::Unrepresentable {
                path: path.clone(),
                kind: value.kind(),
            });
        };
        Ok(Self {
            path: path.clone(),
            kind,
        })
    }
}

/// Converts one exact decimal to its double value; `None` when the
/// coefficient or exponent exceeds the exact `i64` range (the decimal is then
/// far outside double precision).
///
/// The conversion intentionally rounds to the nearest double: the plist
/// native value is the exact IEEE 754 double, and the decimal is a spelling
/// of it (RFC 0013 §6).
#[allow(clippy::cast_precision_loss)]
fn decimal_to_f64(decimal: &Decimal) -> Option<f64> {
    let coefficient = decimal.coefficient().to_i64()?;
    let exponent = decimal.exponent().to_i64()?;
    let mut value = coefficient as f64;
    // The if/else-if chain trips the 1.85-only clippy::comparison_chain
    // (removed or reconfigured in later clippy); the allow carries
    // unknown_lints so the attribute stays valid under both toolchains.
    #[allow(unknown_lints, clippy::comparison_chain)]
    if exponent > 0 {
        value *= 10_f64.powi(exponent.min(308) as i32);
    } else if exponent < 0 {
        value /= 10_f64.powi(exponent.unsigned_abs().min(308) as i32);
    }
    Some(value)
}

/// Strictly decodes one even-length hex string (RFC 0013 §9 data spelling).
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]);
        let low = hex_digit(pair[1]);
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}

/// Builds the promised native document from the validated record, applying
/// the XML expressibility boundary (RFC 0013 §7, hard gate 3) and the
/// authorized date truncation policy.
///
/// Under the XML style, UID values, `Float32` width facts, non-canonical NaN
/// payloads, unpaired-surrogate or non-XML-character strings and keys, and
/// date leaves the whole-second calendar grammar cannot express fail the
/// whole operation atomically. Truncation happens in place on the record so
/// the serializer and the closure see the same promised semantics.
fn build_native(
    record: &mut Record,
    style: Style,
    request: &MaterializationRequest,
) -> Result<(PlistDocument, Vec<Diagnostic>, bool), MaterializationFailure> {
    let limits = request.limits();
    let mut builder = PlistDocumentBuilder::with_limits(crate::PlistArenaLimits {
        max_objects: limits.max_input_nodes,
        max_container_depth: limits.max_depth,
    });
    let mut events = Vec::new();
    let mut transformed = false;
    let root = build_value(
        &mut builder,
        &mut record.root,
        style,
        record.policy,
        &mut events,
        &mut transformed,
    )?;
    let document = builder.build(root).map_err(|_| internal_failure())?;
    Ok((document, events, transformed))
}

fn build_value(
    builder: &mut PlistDocumentBuilder,
    node: &mut ValueNode,
    style: Style,
    policy: bool,
    events: &mut Vec<Diagnostic>,
    transformed: &mut bool,
) -> Result<PlistValueRef, MaterializationFailure> {
    match &mut node.kind {
        ValueKind::Dict { entries } => {
            let mut dict_entries = Vec::with_capacity(entries.len());
            for entry in entries {
                if style == Style::Xml && !is_xml_text(entry.key.code_units()) {
                    return Err(unrepresentable(&entry.key_path, PortableValueKind::String));
                }
                let value = build_value(
                    builder,
                    &mut entry.value,
                    style,
                    policy,
                    events,
                    transformed,
                )?;
                dict_entries.push(PlistDictEntry::new(
                    PlistKey::from_string(entry.key.clone()),
                    value,
                ));
            }
            builder
                .add(PlistValue::Dict(PlistDict::from_entries(dict_entries)))
                .map_err(|_| internal_failure())
        }
        ValueKind::Array { elements } => {
            let mut refs = Vec::with_capacity(elements.len());
            for element in elements {
                refs.push(build_value(
                    builder,
                    element,
                    style,
                    policy,
                    events,
                    transformed,
                )?);
            }
            builder
                .add(PlistValue::Array(PlistArray::from_elements(refs)))
                .map_err(|_| internal_failure())
        }
        ValueKind::String(string) => {
            if style == Style::Xml
                && (string.status() == PlistStringStatus::UnpairedSurrogate
                    || !is_xml_text(string.code_units()))
            {
                return Err(unrepresentable(&node.path, PortableValueKind::String));
            }
            builder
                .add(PlistValue::String(string.clone()))
                .map_err(|_| internal_failure())
        }
        ValueKind::Integer(value) => builder
            .add(PlistValue::Integer(PlistInteger::new(*value)))
            .map_err(|_| internal_failure()),
        ValueKind::Real(real) => {
            if style == Style::Xml {
                if real.width() == RealWidth::Float32 {
                    return Err(unrepresentable(
                        &node.path,
                        PortableValueKind::BinaryFloat32,
                    ));
                }
                if !real_expressible(*real) {
                    return Err(unrepresentable(
                        &node.path,
                        PortableValueKind::BinaryFloat64,
                    ));
                }
            }
            builder
                .add(PlistValue::Real(*real))
                .map_err(|_| internal_failure())
        }
        ValueKind::Boolean(value) => builder
            .add(PlistValue::Boolean(PlistBoolean::new(*value)))
            .map_err(|_| internal_failure()),
        ValueKind::Date { seconds } => {
            if style == Style::Xml {
                if seconds.to_bits() == NEGATIVE_ZERO_BITS {
                    return Err(unrepresentable(&node.path, PortableValueKind::Date));
                }
                match whole_second_date(*seconds) {
                    Ok(_) => {}
                    Err(DateRangeError::FractionalSeconds) => {
                        if !policy {
                            return Err(unrepresentable(&node.path, PortableValueKind::Date));
                        }
                        let original = *seconds;
                        let truncated = original.trunc();
                        *seconds = truncated;
                        if truncated.to_bits() == NEGATIVE_ZERO_BITS
                            || whole_second_date(truncated).is_err()
                        {
                            return Err(unrepresentable(&node.path, PortableValueKind::Date));
                        }
                        events.push(fractional_date_event(
                            &node.path,
                            original,
                            events.len() as u64,
                        ));
                        *transformed = true;
                    }
                    Err(DateRangeError::YearOutOfRange) => {
                        return Err(unrepresentable(&node.path, PortableValueKind::Date));
                    }
                }
            }
            let date = PlistDate::from_seconds(*seconds).map_err(|_| internal_failure())?;
            builder
                .add(PlistValue::Date(date))
                .map_err(|_| internal_failure())
        }
        ValueKind::Data(bytes) => builder
            .add(PlistValue::Data(PlistData::from_bytes(Arc::clone(bytes))))
            .map_err(|_| internal_failure()),
        ValueKind::Uid(value) => {
            if style == Style::Xml {
                return Err(unrepresentable(&node.path, PortableValueKind::Integer));
            }
            builder
                .add(PlistValue::Uid(PlistUid::new(*value)))
                .map_err(|_| internal_failure())
        }
    }
}

/// One authorized truncation report event (RFC 0013 §10.1): the code is the
/// stable `plist.materialization.fractional-date@1`, and the arguments carry
/// the input value path and the original exact seconds.
fn fractional_date_event(path: &ValuePath, seconds: f64, occurrence: u64) -> Diagnostic {
    let mut diagnostic = Diagnostic::new(
        FRACTIONAL_DATE_CODE,
        DiagnosticCategory::Materialization,
        DiagnosticSeverity::Warning,
        None,
        occurrence,
    );
    diagnostic
        .arguments
        .insert("path".to_owned(), render_path(path));
    diagnostic
        .arguments
        .insert("seconds".to_owned(), seconds.to_string());
    diagnostic
}

/// Stable path rendering for diagnostic arguments.
fn render_path(path: &ValuePath) -> String {
    let mut out = String::new();
    for segment in path.segments() {
        match segment {
            ValuePathSegment::ObjectValue(name) => {
                out.push('/');
                out.push_str(name);
            }
            ValuePathSegment::SequenceElement(index) => {
                out.push('[');
                out.push_str(&index.to_string());
                out.push(']');
            }
            ValuePathSegment::EntryKey(index) => {
                out.push_str("[key ");
                out.push_str(&index.to_string());
                out.push(']');
            }
            ValuePathSegment::EntryValue(index) => {
                out.push_str("[value ");
                out.push_str(&index.to_string());
                out.push(']');
            }
        }
    }
    out
}

/// One input value location paired with its exact target ordinal.
struct InputItem {
    /// Input value path.
    path: ValuePath,
    /// Target ordinal: the binary object-table index or the XML arena
    /// ordinal (assigned in close-tag order).
    target: usize,
}

/// One planned binary object in object-table order.
enum PlannedObject {
    /// Dictionary with planned key and value reference targets.
    Dict {
        /// Key reference targets in entry order.
        keys: Vec<usize>,
        /// Value reference targets in entry order.
        values: Vec<usize>,
    },
    /// Array with planned element reference targets.
    Array {
        /// Element reference targets in element order.
        elements: Vec<usize>,
    },
    /// One scalar object.
    Scalar(ScalarKey),
}

/// Content key of one scalar object; `String`, `Integer`, `Real`, `Date`, and
/// `Data` participate in first-occurrence deduplication (RFC 0013 §5.12,
/// §10.2). Booleans and UIDs are always written fresh.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ScalarKey {
    /// Exact string content.
    String(PlistString),
    /// Signed 64-bit value.
    Integer(i64),
    /// Real with exact bits and width fact.
    Real(PlistReal),
    /// Boolean value.
    Boolean(bool),
    /// Exact bits of finite double seconds since the plist epoch.
    Date(u64),
    /// Exact bytes.
    Data(Arc<[u8]>),
    /// Unsigned 32-bit UID value.
    Uid(u32),
}

impl ScalarKey {
    /// Content key of one non-container value node.
    fn from_node(node: &ValueNode) -> Self {
        match &node.kind {
            ValueKind::String(value) => Self::String(value.clone()),
            ValueKind::Integer(value) => Self::Integer(*value),
            ValueKind::Real(value) => Self::Real(*value),
            ValueKind::Boolean(value) => Self::Boolean(*value),
            ValueKind::Date { seconds, .. } => Self::Date(seconds.to_bits()),
            ValueKind::Data(value) => Self::Data(Arc::clone(value)),
            ValueKind::Uid(value) => Self::Uid(*value),
            ValueKind::Dict { .. } | ValueKind::Array { .. } => {
                unreachable!("containers are planned before their children")
            }
        }
    }

    /// Whether this scalar participates in first-occurrence deduplication
    /// (RFC 0013 §5.12: string, integer, real, date, data).
    fn deduplicates(&self) -> bool {
        matches!(
            self,
            Self::String(_) | Self::Integer(_) | Self::Real(_) | Self::Date(_) | Self::Data(_)
        )
    }
}

/// The planned binary object table and the input items of one binary
/// materialization.
struct BinaryPlan {
    /// Planned objects in object-table order.
    objects: Vec<PlannedObject>,
    /// Input items with their target object indices.
    items: Vec<InputItem>,
}

/// Plans the document-ordered binary object table (RFC 0013 §10.2).
///
/// The order is a pre-order of the value tree where a dictionary is written
/// first, then its key objects, then its values recursively: the root value
/// is always object 0, identical deduplicable scalars share one object at
/// first occurrence, and containers are always written fresh. Reference
/// targets are computed before any byte is emitted, so the planned refs may
/// point forward.
fn plan_binary(root: &ValueNode) -> BinaryPlan {
    fn plan_node(
        node: &ValueNode,
        plan: &mut BinaryPlan,
        cache: &mut HashMap<ScalarKey, usize>,
    ) -> usize {
        match &node.kind {
            ValueKind::Dict { entries } => {
                let index = plan.objects.len();
                plan.objects.push(PlannedObject::Dict {
                    keys: Vec::new(),
                    values: Vec::new(),
                });
                plan.items.push(InputItem {
                    path: node.path.clone(),
                    target: index,
                });
                let mut key_refs = Vec::with_capacity(entries.len());
                for entry in entries {
                    let key = ScalarKey::String(entry.key.clone());
                    let key_index = *cache.entry(key.clone()).or_insert_with(|| {
                        let index = plan.objects.len();
                        plan.objects.push(PlannedObject::Scalar(key));
                        index
                    });
                    key_refs.push(key_index);
                }
                let mut value_refs = Vec::with_capacity(entries.len());
                for entry in entries {
                    value_refs.push(plan_node(&entry.value, plan, cache));
                }
                if let PlannedObject::Dict { keys, values } = &mut plan.objects[index] {
                    *keys = key_refs;
                    *values = value_refs;
                }
                index
            }
            ValueKind::Array { elements } => {
                let index = plan.objects.len();
                plan.objects.push(PlannedObject::Array {
                    elements: Vec::new(),
                });
                plan.items.push(InputItem {
                    path: node.path.clone(),
                    target: index,
                });
                let refs = elements
                    .iter()
                    .map(|element| plan_node(element, plan, cache))
                    .collect();
                if let PlannedObject::Array { elements } = &mut plan.objects[index] {
                    *elements = refs;
                }
                index
            }
            _ => {
                let key = ScalarKey::from_node(node);
                if key.deduplicates() {
                    if let Some(&index) = cache.get(&key) {
                        plan.items.push(InputItem {
                            path: node.path.clone(),
                            target: index,
                        });
                        return index;
                    }
                }
                let index = plan.objects.len();
                plan.objects.push(PlannedObject::Scalar(key.clone()));
                if key.deduplicates() {
                    cache.insert(key, index);
                }
                plan.items.push(InputItem {
                    path: node.path.clone(),
                    target: index,
                });
                index
            }
        }
    }
    let mut plan = BinaryPlan {
        objects: Vec::new(),
        items: Vec::new(),
    };
    plan_node(root, &mut plan, &mut HashMap::new());
    plan
}

/// Serializes one record as a `plist.xml@1` source (RFC 0013 §4, §10.1).
///
/// The output uses the exact Apple header spelling, deterministic four-space
/// indentation (the root value element at depth 1), LF line endings, keys in
/// input association order, decimal integers, shortest-round-trip reals,
/// whole-second dates, and base64 wrapped at `76 - 8 * depth` characters per
/// line. The emitted bytes reparse `Complete` with native-model equality.
fn serialize_xml(
    record: &Record,
    limits: MaterializationLimits,
) -> Result<(Vec<u8>, Vec<InputItem>), MaterializationFailure> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    out.push_str("<plist version=\"1.0\">\n");
    let mut items = Vec::new();
    let mut rank = 0;
    emit_value(&mut out, &record.root, 1, &mut items, &mut rank, limits)?;
    out.push_str("</plist>\n");
    Ok((out.into_bytes(), items))
}

/// Emits one value element at the given depth; the node's target ordinal is
/// its post-order rank, mirroring the arena ordinals the parser assigns in
/// close-tag order.
fn emit_value(
    out: &mut String,
    node: &ValueNode,
    depth: usize,
    items: &mut Vec<InputItem>,
    rank: &mut usize,
    limits: MaterializationLimits,
) -> Result<(), MaterializationFailure> {
    match &node.kind {
        ValueKind::Dict { entries } => {
            write_indent(out, depth);
            if entries.is_empty() {
                out.push_str("<dict></dict>\n");
            } else {
                out.push_str("<dict>\n");
                for entry in entries {
                    write_indent(out, depth + 1);
                    out.push_str("<key>");
                    escape_xml_text(out, &string_to_unicode(&entry.key)?);
                    out.push_str("</key>\n");
                    emit_value(out, &entry.value, depth + 1, items, rank, limits)?;
                }
                write_indent(out, depth);
                out.push_str("</dict>\n");
            }
        }
        ValueKind::Array { elements } => {
            write_indent(out, depth);
            if elements.is_empty() {
                out.push_str("<array></array>\n");
            } else {
                out.push_str("<array>\n");
                for element in elements {
                    emit_value(out, element, depth + 1, items, rank, limits)?;
                }
                write_indent(out, depth);
                out.push_str("</array>\n");
            }
        }
        ValueKind::String(string) => {
            write_indent(out, depth);
            out.push_str("<string>");
            escape_xml_text(out, &string_to_unicode(string)?);
            out.push_str("</string>\n");
        }
        ValueKind::Integer(value) => {
            write_indent(out, depth);
            out.push_str("<integer>");
            out.push_str(&value.to_string());
            out.push_str("</integer>\n");
        }
        ValueKind::Real(real) => {
            write_indent(out, depth);
            out.push_str("<real>");
            out.push_str(&render_real(*real));
            out.push_str("</real>\n");
        }
        ValueKind::Boolean(value) => {
            write_indent(out, depth);
            out.push_str(if *value { "<true/>\n" } else { "<false/>\n" });
        }
        ValueKind::Date { seconds } => {
            write_indent(out, depth);
            out.push_str("<date>");
            let (year, month, day, hour, minute, second) =
                whole_second_date(*seconds).map_err(|_| internal_failure())?;
            out.push_str(&render_date(year, month, day, hour, minute, second));
            out.push_str("</date>\n");
        }
        ValueKind::Data(bytes) => {
            write_indent(out, depth);
            out.push_str("<data>");
            out.push_str(&encode_base64_wrapped(bytes, depth));
            out.push_str("</data>\n");
        }
        ValueKind::Uid(_) => return Err(internal_failure()),
    }
    items.push(InputItem {
        path: node.path.clone(),
        target: *rank,
    });
    *rank += 1;
    if out.len() > limits.max_output_bytes {
        return Err(MaterializationFailure::ResourceLimit("output-bytes"));
    }
    Ok(())
}

/// Appends one indentation level of four spaces.
fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// Escapes XML text content (RFC 0013 §4.9, §10.1): `&`, `<`, `>`, and a
/// literal CR, which XML line-end normalization would otherwise turn into LF
/// (a character reference is not normalized).
fn escape_xml_text(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(character),
        }
    }
}

/// Deterministic shortest-round-trip decimal spelling of one real (RFC 0013
/// §4.6, §10.1); the special spellings match the frozen grammar.
fn render_real(real: PlistReal) -> String {
    let value = real.as_f64();
    if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        value.to_string()
    }
}

/// Whether the exact bits of one real survive the XML spelling: Rust's
/// shortest-round-trip decimal is exact for every finite double, and the
/// special spellings resolve to the canonical NaN bit pattern only.
fn real_expressible(real: PlistReal) -> bool {
    let value = real.as_f64();
    if value.is_nan() {
        value.to_bits() == f64::NAN.to_bits()
    } else if value.is_infinite() {
        true
    } else {
        value
            .to_string()
            .parse::<f64>()
            .is_ok_and(|parsed| parsed.to_bits() == value.to_bits())
    }
}

/// Whole-second XML date spelling of one exact plist-epoch seconds value
/// (RFC 0013 §4.7).
fn render_date(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> String {
    let sign = if year < 0 { "-" } else { "" };
    format!(
        "{sign}{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        year = year.unsigned_abs()
    )
}

/// Decomposition failure of one date value under the XML calendar grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DateRangeError {
    /// The seconds value carries a fractional part (RFC 0013 §4.7).
    FractionalSeconds,
    /// The calendar year exceeds the exact whole-second range expressible by
    /// the XML grammar: the 32-bit year magnitude, or a Unix-seconds value
    /// whose exact double decomposition would round (hard gate 3).
    YearOutOfRange,
}

/// Decomposes exact plist-epoch seconds into XML calendar fields (RFC 0013
/// §4.7, §5.5). The value must be whole-second, and the day/second
/// decomposition must be exact: the Unix-seconds value must stay below `2^53`
/// and the calendar year within the grammar's 32-bit magnitude.
fn whole_second_date(seconds: f64) -> Result<(i64, i64, i64, i64, i64, i64), DateRangeError> {
    if seconds.fract() != 0.0 {
        return Err(DateRangeError::FractionalSeconds);
    }
    // The sum of an integral seconds value and the exact epoch offset is
    // exactly representable; the pre-bound keeps every later cast exact.
    let unix = seconds + PLIST_EPOCH_OFFSET_UNIX;
    if unix.abs() >= EXACT_UNIX_SECONDS_BOUND {
        return Err(DateRangeError::YearOutOfRange);
    }
    let unix_int = unix as i64;
    let days = unix_int.div_euclid(86_400);
    let seconds_of_day = unix_int.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if year.unsigned_abs() > u64::from(u32::MAX) {
        return Err(DateRangeError::YearOutOfRange);
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok((year, month, day, hour, minute, second))
}

/// Proleptic Gregorian calendar date of `days` since the Unix epoch (the
/// inverse of the parser's `days_from_civil`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// Canonical standard-alphabet base64 with exact `=` padding, wrapped so
/// every line carries at most `76 - 8 * depth` characters (RFC 0013 §4.8,
/// §10.1; Apple's `MAXLINELEN` counts the indentation against the budget, so
/// the wrap point is `76 - 8 * depth` and the line length is exactly 76 only
/// at depth 0). The first chunk follows the `<data>` tag inline; continuation
/// chunks start on a new indented line.
fn encode_base64_wrapped(bytes: &[u8], depth: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let budget = (76_usize.saturating_sub(8 * depth)).max(1);
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    let mut line = 0_usize;
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        if line + 4 > budget && line > 0 {
            out.push('\n');
            write_indent(&mut out, depth);
            line = 0;
        }
        out.push(char::from(ALPHABET[(first >> 2) as usize]));
        out.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(((second & 0x0F) << 2) | (third >> 6)) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(third & 0x3F) as usize])
        } else {
            '='
        });
        line += 4;
    }
    out
}

/// XML 1.0 `Char` production (RFC 0013 §4.9).
const fn is_xml_char(character: char) -> bool {
    character == '\t'
        || character == '\n'
        || character == '\r'
        || (character >= '\u{20}' && character <= '\u{D7FF}')
        || (character >= '\u{E000}' && character <= '\u{FFFD}')
        || (character >= '\u{10000}' && character <= '\u{10FFFF}')
}

/// Whether every scalar of one well-formed UTF-16 sequence is an XML 1.0
/// character; an unpaired surrogate is not.
fn is_xml_text(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let scalar = if (0xD800..=0xDBFF).contains(&unit) {
            match units.get(index + 1).copied() {
                Some(low) if (0xDC00..=0xDFFF).contains(&low) => {
                    index += 2;
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00)
                }
                _ => return false,
            }
        } else {
            index += 1;
            u32::from(unit)
        };
        let Some(character) = char::from_u32(scalar) else {
            return false;
        };
        if !is_xml_char(character) {
            return false;
        }
    }
    true
}

/// Exact Unicode text of one validated string.
fn string_to_unicode(string: &PlistString) -> Result<String, MaterializationFailure> {
    string.to_unicode().map_err(|_| internal_failure())
}

/// Serializes one record as a `plist.binary@1` source (RFC 0013 §5, §10.2).
///
/// The object table is document-ordered (the root value is object 0, every
/// dictionary is followed by its key objects and then its values), integers
/// use the minimal width with negatives always 8 bytes, `Float32` width facts
/// are preserved, identical deduplicable scalars share one object at first
/// occurrence, UIDs use the minimal width, and the offset/ref sizes are the
/// minimal widths satisfying the trailer sufficiency checks. The emitted
/// bytes reparse `Complete` with native-model equality.
fn serialize_binary(
    record: &Record,
    limits: MaterializationLimits,
) -> Result<(Vec<u8>, Vec<InputItem>), MaterializationFailure> {
    let plan = plan_binary(&record.root);
    let num_objects = plan.objects.len();
    let ref_size = ref_size_for(num_objects);
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::with_capacity(num_objects);
    for object in &plan.objects {
        offsets.push(out.len());
        write_planned_object(&mut out, object, ref_size)?;
        if out.len() > limits.max_output_bytes {
            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
        }
    }
    let offset_table_offset = out.len();
    let offset_int_size = ref_size_for(offset_table_offset);
    for &offset in &offsets {
        write_be(&mut out, offset as u64, offset_int_size)?;
    }
    out.extend_from_slice(&[0, 0, 0, 0, 0]);
    out.push(0); // sortVersion
    out.push(offset_int_size as u8);
    out.push(ref_size as u8);
    write_be(&mut out, num_objects as u64, 8)?; // numObjects
    write_be(&mut out, 0, 8)?; // topObject: the root value is always object 0
    write_be(&mut out, offset_table_offset as u64, 8)?; // offsetTableOffset
    Ok((out, plan.items))
}

/// Writes one planned object: marker, size, payload, and references
/// (RFC 0013 §5).
fn write_planned_object(
    out: &mut Vec<u8>,
    object: &PlannedObject,
    ref_size: usize,
) -> Result<(), MaterializationFailure> {
    match object {
        PlannedObject::Dict { keys, values } => {
            let count = keys.len();
            write_sized(out, 0xD0, count)?;
            for &key in keys {
                write_be(out, key as u64, ref_size)?;
            }
            for &value in values {
                write_be(out, value as u64, ref_size)?;
            }
        }
        PlannedObject::Array { elements } => {
            let count = elements.len();
            write_sized(out, 0xA0, count)?;
            for &element in elements {
                write_be(out, element as u64, ref_size)?;
            }
        }
        PlannedObject::Scalar(key) => match key {
            ScalarKey::String(string) => write_string_object(out, string)?,
            ScalarKey::Integer(value) => {
                let width = integer_width(*value);
                out.push(0x10 | width.trailing_zeros() as u8);
                // The two's-complement bit pattern of the signed value,
                // written at exactly `width` bytes (RFC 0013 §5.3).
                #[allow(clippy::cast_sign_loss)]
                let bits = *value as u64;
                write_be(out, bits, width)?;
            }
            ScalarKey::Real(real) => match real.width() {
                RealWidth::Float64 => {
                    out.push(0x23);
                    write_be(out, real.bits(), 8)?;
                }
                RealWidth::Float32 => {
                    out.push(0x22);
                    write_be(out, real.bits(), 4)?;
                }
            },
            ScalarKey::Boolean(value) => {
                out.push(if *value { 0x09 } else { 0x08 });
            }
            ScalarKey::Date(bits) => {
                out.push(0x33);
                write_be(out, *bits, 8)?;
            }
            ScalarKey::Data(bytes) => {
                write_sized(out, 0x40, bytes.len())?;
                out.extend_from_slice(bytes);
            }
            ScalarKey::Uid(value) => {
                let value = u64::from(*value);
                let width = uid_width(value);
                out.push(0x80 | (width as u8 - 1));
                write_be(out, value, width)?;
            }
        },
    }
    Ok(())
}

/// Writes one string object: the ASCII marker when every code unit is below
/// `0x80`, else the UTF-16BE marker (RFC 0013 §5.6).
fn write_string_object(
    out: &mut Vec<u8>,
    string: &PlistString,
) -> Result<(), MaterializationFailure> {
    let units = string.code_units();
    if units.iter().all(|unit| *unit < 0x80) {
        write_sized(out, 0x50, units.len())?;
        for unit in units {
            out.push(*unit as u8);
        }
    } else {
        write_sized(out, 0x60, units.len())?;
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    }
    Ok(())
}

/// Writes one sized marker: counts below `0x0F` fit the low nibble, while the
/// nibble `0x0F` itself is the extended-size sentinel (RFC 0013 §5.4), so
/// every count of 15 or more follows the marker with a `0x10`-style size
/// marker and count object. The parser always reads nibble `0xF` as the
/// sentinel, so the plain `marker | 0x0F` spelling would consume the first
/// payload byte as a size object.
fn write_sized(out: &mut Vec<u8>, marker: u8, count: usize) -> Result<(), MaterializationFailure> {
    if count < 0x0F {
        out.push(marker | count as u8);
        return Ok(());
    }
    out.push(marker | 0x0F);
    let count = u64::try_from(count).map_err(|_| internal_failure())?;
    let width = unsigned_width(count);
    out.push(0x10 | width.trailing_zeros() as u8);
    write_be(out, count, width)
}

/// Appends one big-endian unsigned value of exactly `width` bytes.
fn write_be(out: &mut Vec<u8>, value: u64, width: usize) -> Result<(), MaterializationFailure> {
    if width > 8 {
        return Err(internal_failure());
    }
    for shift in (0..width).rev() {
        out.push(((value >> (8 * shift)) & 0xFF) as u8);
    }
    Ok(())
}

/// Smallest width in bytes whose capacity (`2^(8 * width)`) exceeds
/// `max_index`, satisfying the trailer sufficiency checks of RFC 0013 §5.11.
fn ref_size_for(max_index: usize) -> usize {
    let mut size = 1;
    let mut capacity = 256_usize;
    while max_index >= capacity && size < 8 {
        size += 1;
        capacity = capacity.saturating_mul(256);
    }
    size
}

/// Minimal marker width for one signed 64-bit integer: negatives always use
/// the signed 8-byte form (RFC 0013 §5.3, §10.2).
fn integer_width(value: i64) -> usize {
    match u64::try_from(value) {
        Ok(value) => unsigned_width(value),
        Err(_) => 8,
    }
}

/// Minimal marker width for one unsigned count: 1, 2, 4, or 8 bytes.
fn unsigned_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFFFF_FFFF {
        4
    } else {
        8
    }
}

/// Minimal byte width of one unsigned 32-bit UID value (RFC 0013 §5.8).
fn uid_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFF_FFFF {
        3
    } else {
        4
    }
}

/// Pairs every recorded input item with its exact output origin in the
/// reparsed document and builds the provenance map.
///
/// For binary the target ordinal is the object-table index and the origin
/// span is the object's marker-through-payload range. For XML the target
/// ordinal is the arena ordinal (close-tag order) and the origin span is the
/// value element's open-tag-through-close-tag range, reconstructed from the
/// lossless syntax pieces.
fn build_provenance(
    items: Vec<InputItem>,
    document: &Document,
    style: Style,
    limits: MaterializationLimits,
) -> Result<MaterializationProvenanceMap, MaterializationFailure> {
    let authority = document.authority();
    let identity = document.snapshot_identity();
    let origins: Vec<MaterializedOrigin> = match style {
        Style::Binary => {
            let facts = document
                .binary_facts()
                .ok_or(MaterializationFailure::FormationFailed)?;
            let objects = facts.objects();
            items
                .iter()
                .map(|item| {
                    let fact = objects
                        .get(item.target)
                        .ok_or(MaterializationFailure::FormationFailed)?;
                    Ok(MaterializedOrigin {
                        snapshot: identity,
                        node: authority.node_ref(fact.index() as u64, NodeRole::PlistValue),
                        span: fact.span(),
                        relation: MaterializationRelation::Direct,
                    })
                })
                .collect::<Result<Vec<_>, MaterializationFailure>>()?
        }
        Style::Xml => {
            let spans = xml_value_spans(document)?;
            items
                .iter()
                .map(|item| {
                    let span = spans
                        .get(item.target)
                        .copied()
                        .ok_or(MaterializationFailure::FormationFailed)?;
                    Ok(MaterializedOrigin {
                        snapshot: identity,
                        node: authority.node_ref(item.target as u64, NodeRole::PlistValue),
                        span,
                        relation: MaterializationRelation::Direct,
                    })
                })
                .collect::<Result<Vec<_>, MaterializationFailure>>()?
        }
    };
    let entries = items
        .into_iter()
        .zip(origins)
        .map(|(item, origin)| MaterializationProvenanceEntry {
            input: MaterializationInputLocation::Value(item.path),
            outputs: vec![origin],
        })
        .collect();
    MaterializationProvenanceMap::new(entries, identity, limits)
}

/// Reconstructs the value element spans of one reparsed XML document, in
/// arena (close-tag) order.
///
/// The walk tracks open value elements on a stack, completes each element at
/// its close tag (the parser assigns arena ordinals in the same order), and
/// treats `<true/>`/`<false/>` as self-closing by inspecting the raw bytes.
fn xml_value_spans(document: &Document) -> Result<Vec<Span>, MaterializationFailure> {
    let pieces = document
        .lossless_structural_index()
        .ok_or(MaterializationFailure::FormationFailed)?
        .pieces();
    let kinds = document
        .lossless_syntax_kinds()
        .ok_or(MaterializationFailure::FormationFailed)?;
    let source = document.source().bytes();
    let authority = document.authority();
    let mut spans = Vec::new();
    let mut stack: Vec<(usize, PlistSyntaxKind)> = Vec::new();
    for (piece, kind) in pieces.iter().zip(kinds.iter()) {
        let span = piece.span();
        match kind {
            PlistSyntaxKind::DictOpen
            | PlistSyntaxKind::ArrayOpen
            | PlistSyntaxKind::StringOpen
            | PlistSyntaxKind::IntegerOpen
            | PlistSyntaxKind::RealOpen
            | PlistSyntaxKind::DateOpen
            | PlistSyntaxKind::DataOpen => {
                // An open tag partitions into two pieces of the same kind:
                // the element name and the closing `>`. Only the name piece
                // opens the element.
                let raw = &source[span.start_byte()..span.end_byte()];
                if raw.len() != 1 || raw[0] != b'>' {
                    stack.push((span.start_byte(), *kind));
                }
            }
            PlistSyntaxKind::DictClose
            | PlistSyntaxKind::ArrayClose
            | PlistSyntaxKind::StringClose
            | PlistSyntaxKind::IntegerClose
            | PlistSyntaxKind::RealClose
            | PlistSyntaxKind::DateClose
            | PlistSyntaxKind::DataClose => {
                let (start, _) = stack.pop().ok_or(MaterializationFailure::FormationFailed)?;
                spans.push(
                    authority
                        .span(start, span.end_byte())
                        .map_err(|_| MaterializationFailure::FormationFailed)?,
                );
            }
            PlistSyntaxKind::True | PlistSyntaxKind::False => {
                // The boolean elements partition like every other tag: a
                // self-closing `<true/>` is a name piece plus a `/>` piece,
                // an explicit close is a `</true>` piece, and a separate
                // `<true>` open keeps its `>` as its own piece.
                let raw = &source[span.start_byte()..span.end_byte()];
                if raw.starts_with(b"</") || raw == b"/>" {
                    let (start, open_kind) =
                        stack.pop().ok_or(MaterializationFailure::FormationFailed)?;
                    if open_kind != *kind {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    spans.push(
                        authority
                            .span(start, span.end_byte())
                            .map_err(|_| MaterializationFailure::FormationFailed)?,
                    );
                } else if raw != b">" {
                    stack.push((span.start_byte(), *kind));
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(MaterializationFailure::FormationFailed);
    }
    Ok(spans)
}

/// Looks up one object entry by exact key.
fn object_field<'v>(object: &'v [ObjectEntry], name: &str) -> Option<&'v PortableValue> {
    object
        .iter()
        .find(|entry| entry.key() == name)
        .map(ObjectEntry::value)
}

/// Static precise spelling of one absent record member (RFC 0013 §9): the
/// failure names the missing field instead of masking it.
fn missing_record_field(name: &str) -> &'static str {
    match name {
        "record" => "missing record field: record",
        "root" => "missing record field: root",
        "kind" => "missing record field: kind",
        "entries" => "missing record field: entries",
        "elements" => "missing record field: elements",
        "text" => "missing record field: text",
        "value" => "missing record field: value",
        "seconds" => "missing record field: seconds",
        "epoch" => "missing record field: epoch",
        "hex" => "missing record field: hex",
        "uid" => "missing record field: uid",
        _ => "missing record field",
    }
}

fn expect_object_field<'v>(
    value: &'v PortableValue,
    name: &str,
    path: &ValuePath,
) -> Result<&'v PortableValue, MaterializationFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| MaterializationFailure::Unrepresentable {
            path: path.clone(),
            kind: value.kind(),
        })?;
    let Some(field) = object_field(object, name) else {
        return Err(MaterializationFailure::InvalidRequest(
            missing_record_field(name),
        ));
    };
    Ok(field)
}

fn expect_string_field<'v>(
    value: &'v PortableValue,
    name: &str,
    path: &ValuePath,
) -> Result<&'v str, MaterializationFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| MaterializationFailure::Unrepresentable {
            path: path.clone(),
            kind: value.kind(),
        })?;
    let Some(field) = object_field(object, name) else {
        return Err(MaterializationFailure::InvalidRequest(
            missing_record_field(name),
        ));
    };
    field
        .as_string()
        .ok_or_else(|| MaterializationFailure::Unrepresentable {
            path: path.child(ValuePathSegment::ObjectValue(name.to_owned())),
            kind: field.kind(),
        })
}

/// One plist date leaf failure: the whole-second XML calendar grammar cannot
/// express this exact date (RFC 0013 §4.7, §10.1). The runner maps this
/// variant to `plist.materialization.fractional-date@1`.
fn unrepresentable(path: &ValuePath, kind: PortableValueKind) -> MaterializationFailure {
    MaterializationFailure::Unrepresentable {
        path: path.clone(),
        kind,
    }
}

/// Unreachable internal state of the materialization layer: validated input
/// and emitted bytes can never reach it.
fn internal_failure() -> MaterializationFailure {
    MaterializationFailure::FormationFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{
        BigInteger, BinaryFloat32, BinaryFloat64, EntryMappingBuilder, ObjectBuilder,
    };
    use consema_document::{MaterializationStyleId, ProfileId};

    /// Appends a big-endian value of `width` bytes.
    #[allow(dead_code)]
    fn push_be(output: &mut Vec<u8>, value: u64, width: usize) {
        for shift in (0..width).rev() {
            output.push(((value >> (8 * shift)) & 0xFF) as u8);
        }
    }

    /// Hand-built `bplist00` fixture writer: header, objects, offset table,
    /// trailer.
    #[allow(dead_code)]
    struct TestBinaryBuilder {
        bytes: Vec<u8>,
        offsets: Vec<u64>,
        offset_int_size: usize,
        ref_size: usize,
    }

    #[allow(dead_code)]
    impl TestBinaryBuilder {
        fn new(offset_int_size: usize, ref_size: usize) -> Self {
            Self {
                bytes: b"bplist00".to_vec(),
                offsets: Vec::new(),
                offset_int_size,
                ref_size,
            }
        }

        fn object(&mut self, object: &[u8]) -> u64 {
            let offset = u64::try_from(self.bytes.len()).unwrap();
            self.offsets.push(offset);
            self.bytes.extend_from_slice(object);
            offset
        }

        fn finish(mut self, top_object: u64) -> Vec<u8> {
            let offset_table_offset = u64::try_from(self.bytes.len()).unwrap();
            for offset in &self.offsets {
                push_be(&mut self.bytes, *offset, self.offset_int_size);
            }
            self.bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            self.bytes.push(0); // sortVersion
            self.bytes.push(self.offset_int_size as u8);
            self.bytes.push(self.ref_size as u8);
            push_be(
                &mut self.bytes,
                u64::try_from(self.offsets.len()).unwrap(),
                8,
            );
            push_be(&mut self.bytes, top_object, 8);
            push_be(&mut self.bytes, offset_table_offset, 8);
            self.bytes
        }
    }

    fn xml_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("plist.xml", 1),
            MaterializationStyleId::new(STYLE_XML, 1),
        )
    }

    fn binary_request() -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("plist.binary", 1),
            MaterializationStyleId::new(STYLE_BINARY, 1),
        )
        .with_encoding(SourceEncoding::Binary)
        .with_newline(NewlinePolicy::None)
    }

    /// One dictionary value: an EntryMapping of ordered key/value
    /// associations, the projection emission (RFC 0013 §9).
    fn dict_record(entries: Vec<(&str, PortableValue)>) -> PortableValue {
        let mut builder = EntryMappingBuilder::new();
        for (key, value) in entries {
            builder.push(PortableValue::string(key), value);
        }
        builder.build()
    }

    fn dict_record_entries(entries: Vec<(PortableValue, PortableValue)>) -> PortableValue {
        let mut builder = EntryMappingBuilder::new();
        for (key, value) in entries {
            builder.push(key, value);
        }
        builder.build()
    }

    /// One dictionary value spelled as an ordered JSON object (the conformance
    /// vector spelling of the record).
    fn dict_object(entries: Vec<(&str, PortableValue)>) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        for (key, value) in entries {
            builder.insert(key, value).expect("insert");
        }
        builder.build()
    }

    fn array_record(elements: Vec<PortableValue>) -> PortableValue {
        PortableValue::sequence(elements)
    }

    fn string_record(text: &str) -> PortableValue {
        PortableValue::string(text)
    }

    fn integer_record(value: i64) -> PortableValue {
        PortableValue::integer(BigInteger::parse_decimal(&value.to_string()).unwrap())
    }

    fn real64_record(value: f64) -> PortableValue {
        PortableValue::binary_float64(BinaryFloat64::from_bits(value.to_bits()))
    }

    fn real32_record(bits: u32) -> PortableValue {
        PortableValue::binary_float32(BinaryFloat32::from_bits(bits))
    }

    fn boolean_record(value: bool) -> PortableValue {
        PortableValue::boolean(value)
    }

    /// One date leaf: exact double seconds plus the fixed epoch constant
    /// (RFC 0013 §9).
    fn date_record(seconds: f64) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("epoch", PortableValue::string(PLIST_EPOCH_SPELLING))
            .and_then(|builder| {
                builder.insert(
                    "seconds",
                    PortableValue::binary_float64(BinaryFloat64::from_bits(seconds.to_bits())),
                )
            })
            .expect("insert");
        builder.build()
    }

    fn data_record(bytes: &[u8]) -> PortableValue {
        PortableValue::bytes(bytes.to_vec())
    }

    /// One data leaf spelled as the JSON vector `{ "hex": ... }` record.
    fn data_hex_record(hex: &str) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("hex", PortableValue::string(hex))
            .expect("insert");
        builder.build()
    }

    /// One typed UID member (RFC 0013 §9).
    fn uid_record(value: u32) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert(
                "uid",
                PortableValue::integer(BigInteger::parse_decimal(&value.to_string()).unwrap()),
            )
            .expect("insert");
        builder.build()
    }

    /// The full `plist.value-tree@1` record wrapper (RFC 0013 §9).
    fn record(root: PortableValue) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string(VALUE_TREE_RECORD))
            .expect("insert");
        builder.insert("root", root).expect("insert");
        builder.build()
    }

    /// The record wrapper with the authorized truncation policy.
    fn record_with_policy(root: PortableValue) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string(VALUE_TREE_RECORD))
            .expect("insert");
        builder.insert("root", root).expect("insert");
        builder
            .insert("truncate_policy", PortableValue::string(TRUNCATE_POLICY))
            .expect("insert");
        builder.build()
    }

    /// The value tree of the published xml-canonical-text and
    /// binary-canonical-hex materialization vectors.
    fn conformance_value_tree() -> PortableValue {
        dict_record(vec![
            ("name", string_record("value")),
            ("count", integer_record(42)),
            ("ratio", real64_record(1.5)),
            ("enabled", boolean_record(true)),
            ("disabled", boolean_record(false)),
            ("payload", data_record(&[1, 2, 3])),
            ("created", date_record(694_224_000.0)),
            ("title", string_record("a & b < c")),
            (
                "tags",
                array_record(vec![string_record("a"), string_record("b")]),
            ),
        ])
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(out, "{byte:02x}").expect("writing into a String cannot fail");
        }
        out
    }

    fn complete_document(value: &PortableValue, request: &MaterializationRequest) -> Document {
        match materialize(value, request) {
            MaterializationResult::Complete(complete) => {
                assert_eq!(complete.fidelity, MaterializationFidelity::Exact);
                assert!(
                    !complete.provenance.entries().is_empty(),
                    "every materialization maps its root value"
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
                String::from_utf8_lossy(complete.document.render())
            ),
        }
    }

    #[test]
    fn xml_canonical_matches_the_published_vector_render() {
        let document = complete_document(&record(conformance_value_tree()), &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n    <dict>\n        <key>name</key>\n        <string>value</string>\n        <key>count</key>\n        <integer>42</integer>\n        <key>ratio</key>\n        <real>1.5</real>\n        <key>enabled</key>\n        <true/>\n        <key>disabled</key>\n        <false/>\n        <key>payload</key>\n        <data>AQID</data>\n        <key>created</key>\n        <date>2023-01-01T00:00:00Z</date>\n        <key>title</key>\n        <string>a &amp; b &lt; c</string>\n        <key>tags</key>\n        <array>\n            <string>a</string>\n            <string>b</string>\n        </array>\n    </dict>\n</plist>\n";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn binary_canonical_matches_the_published_vector_hex() {
        let document = complete_document(&record(conformance_value_tree()), &binary_request());
        let expected = "62706c6973743030d90102030405060708090a0b0c0d0e0f101112546e616d6555636f756e7455726174696f57656e61626c65645864697361626c6564577061796c6f61645763726561746564557469746c6554746167735576616c7565102a233ff80000000000000908430102033341c4b08240000000596120262062203c2063a2131451615162081b20262c343d454d53585e60696a6b6f788285870000000000000101000000000000001500000000000000000000000000000089";
        assert_eq!(to_hex(document.render()), expected);
    }

    #[test]
    fn binary_canonical_normalizes_widths_and_deduplicates() {
        // The published normalization vector: array [5, 5, 5] collapses the
        // three identical integers into one minimal-width object with three
        // references.
        let value = record(array_record(vec![
            integer_record(5),
            integer_record(5),
            integer_record(5),
        ]));
        let document = complete_document(&value, &binary_request());
        let expected = "62706c6973743030a30101011005080c000000000000010100000000000000020000000000000000000000000000000e";
        assert_eq!(to_hex(document.render()), expected);
        assert_eq!(
            document.binary_facts().expect("facts").objects().len(),
            2,
            "three identical scalars deduplicate to one object"
        );
    }

    #[test]
    fn xml_conversion_of_a_binary_document_renders_canonically() {
        // The published conversion_render expectation for { "a": 1 }.
        let value = record(dict_record(vec![("a", integer_record(1))]));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n    <dict>\n        <key>a</key>\n        <integer>1</integer>\n    </dict>\n</plist>\n";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn fractional_date_fails_without_the_policy() {
        let value = record(dict_record(vec![("t", date_record(1.5))]));
        assert_failure(
            &value,
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("root".to_owned()))
                    .child(ValuePathSegment::EntryValue(0)),
                kind: PortableValueKind::Date,
            },
        );
    }

    #[test]
    fn fractional_date_truncates_and_reports_under_the_policy() {
        let value = record_with_policy(dict_record(vec![("t", date_record(1.5))]));
        match materialize(&value, &xml_request()) {
            MaterializationResult::Complete(complete) => {
                assert_eq!(complete.fidelity, MaterializationFidelity::Transformed);
                let rendered = std::str::from_utf8(complete.document.render()).expect("utf-8");
                assert!(
                    rendered.contains("<date>2001-01-01T00:00:01Z</date>"),
                    "{rendered}"
                );
                let events = complete.report.events();
                assert_eq!(events.len(), 1, "exactly one truncation event");
                assert_eq!(events[0].code, FRACTIONAL_DATE_CODE);
                assert_eq!(events[0].severity, DiagnosticSeverity::Warning);
                assert!(
                    events[0]
                        .arguments
                        .get("seconds")
                        .is_some_and(|seconds| seconds == "1.5"),
                    "the original exact seconds survive in the event"
                );
                // The closure compared against the truncated semantics: the
                // reparsed document holds the whole-second value.
                let reparsed = complete.document.document().expect("native");
                let entry = &reparsed.root_value().as_dict().expect("dict").entries()[0];
                let date = reparsed
                    .get(entry.value())
                    .and_then(PlistValue::as_date)
                    .expect("date");
                assert_eq!(date.seconds().to_bits(), 1.0_f64.to_bits());
            }
            MaterializationResult::Failed(attempt) => {
                panic!("authorized truncation must complete: {:?}", attempt.failure);
            }
        }
    }

    #[test]
    fn binary_style_preserves_fractional_seconds_exactly() {
        let value = record(dict_record(vec![("t", date_record(1.5))]));
        let document = complete_document(&value, &binary_request());
        let native = document.document().expect("native");
        let entry = &native.root_value().as_dict().expect("dict").entries()[0];
        let date = native
            .get(entry.value())
            .and_then(PlistValue::as_date)
            .expect("date");
        assert_eq!(date.seconds().to_bits(), 1.5_f64.to_bits());
        assert!(
            to_hex(document.render()).starts_with("62706c6973743030d10102"),
            "the dict leads the file with its key and value references"
        );
    }

    #[test]
    fn request_validation_matrix_fails_exactly() {
        let value = record(string_record("x"));
        let wrong_profile = MaterializationRequest::new(
            ProfileId::new("plist.json", 1),
            MaterializationStyleId::new(STYLE_XML, 1),
        );
        assert_failure(
            &value,
            &wrong_profile,
            MaterializationFailure::UnsupportedProfile,
        );
        let wrong_style = MaterializationRequest::new(
            ProfileId::new("plist.xml", 1),
            MaterializationStyleId::new("plist.fancy", 1),
        );
        assert_failure(
            &value,
            &wrong_style,
            MaterializationFailure::UnsupportedStyle,
        );
        let cross_style = MaterializationRequest::new(
            ProfileId::new("plist.xml", 1),
            MaterializationStyleId::new(STYLE_BINARY, 1),
        );
        assert_failure(
            &value,
            &cross_style,
            MaterializationFailure::UnsupportedStyle,
        );
        assert_failure(
            &value,
            &xml_request().with_encoding(SourceEncoding::Utf16Le),
            MaterializationFailure::UnsupportedEncoding,
        );
        assert_failure(
            &value,
            &xml_request().with_newline(NewlinePolicy::CrLf),
            MaterializationFailure::UnsupportedNewline,
        );
        assert_failure(
            &value,
            &binary_request().with_encoding(SourceEncoding::Utf8),
            MaterializationFailure::UnsupportedEncoding,
        );
        assert_failure(
            &value,
            &binary_request().with_newline(NewlinePolicy::Lf),
            MaterializationFailure::UnsupportedNewline,
        );
    }

    #[test]
    fn record_validation_matrix_fails_exactly() {
        let mut not_a_record = ObjectBuilder::new();
        not_a_record
            .insert("record", PortableValue::string("plist.other@1"))
            .expect("insert");
        assert_failure(
            &not_a_record.build(),
            &xml_request(),
            MaterializationFailure::InvalidRequest("input record is not plist.value-tree@1"),
        );

        let mut bad_policy = ObjectBuilder::new();
        bad_policy
            .insert("record", PortableValue::string(VALUE_TREE_RECORD))
            .expect("insert");
        bad_policy
            .insert("root", string_record("x"))
            .expect("insert");
        bad_policy
            .insert("truncate_policy", PortableValue::string("Drop"))
            .expect("insert");
        assert_failure(
            &bad_policy.build(),
            &xml_request(),
            MaterializationFailure::InvalidRequest("unsupported truncate policy"),
        );

        // The explicit `{kind, ...}` record spelling is not the value-tree
        // record (RFC 0013 §9).
        let mut kind_record = ObjectBuilder::new();
        kind_record
            .insert("kind", PortableValue::string("blob"))
            .expect("insert");
        assert_failure(
            &record(kind_record.build()),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned())),
                kind: PortableValueKind::Object,
            },
        );

        let bad_hex = record(data_hex_record("xyz"));
        assert_failure(
            &bad_hex,
            &binary_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("root".to_owned()))
                    .child(ValuePathSegment::ObjectValue("hex".to_owned())),
                kind: PortableValueKind::String,
            },
        );
    }

    #[test]
    fn the_old_record_shape_is_rejected_with_a_precise_diagnostic() {
        // The former materialization contract wrapped the value in a `value`
        // member and spelled every value as an explicit `{kind, ...}` record;
        // the RFC 0013 §9 record carries the `root` member instead, and the
        // rejection names it.
        let mut old_shape = ObjectBuilder::new();
        old_shape
            .insert("record", PortableValue::string(VALUE_TREE_RECORD))
            .expect("insert");
        let mut kind_string = ObjectBuilder::new();
        kind_string
            .insert("kind", PortableValue::string("string"))
            .expect("insert");
        kind_string
            .insert("text", PortableValue::string("x"))
            .expect("insert");
        old_shape
            .insert("value", kind_string.build())
            .expect("insert");
        let old_shape = old_shape.build();
        assert_failure(
            &old_shape,
            &xml_request(),
            MaterializationFailure::InvalidRequest("missing record field: root"),
        );
        assert_failure(
            &old_shape,
            &binary_request(),
            MaterializationFailure::InvalidRequest("missing record field: root"),
        );
    }

    #[test]
    fn xml_inexpressible_facts_fail_atomically() {
        // The failing leaf is the root value itself in every case, so its
        // input path is /root.
        let root_value_path =
            ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned()));
        assert_failure(
            &record(uid_record(42)),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path.clone(),
                kind: PortableValueKind::Integer,
            },
        );
        assert_failure(
            &record(real32_record(0.1_f32.to_bits())),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path.clone(),
                kind: PortableValueKind::BinaryFloat32,
            },
        );
        assert_failure(
            &record(real64_record(f64::from_bits(0x7FF8_0000_0000_0001))),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path.clone(),
                kind: PortableValueKind::BinaryFloat64,
            },
        );
        assert_failure(
            &record(string_record("a\u{1}b")),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path.clone(),
                kind: PortableValueKind::String,
            },
        );
        assert_failure(
            &record(date_record(1e20)),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path.clone(),
                kind: PortableValueKind::Date,
            },
        );
        assert_failure(
            &record(date_record(f64::NAN)),
            &xml_request(),
            MaterializationFailure::Unrepresentable {
                path: root_value_path,
                kind: PortableValueKind::Date,
            },
        );
    }

    #[test]
    fn every_value_kind_round_trips_both_styles() {
        let tree = dict_record(vec![
            ("string", string_record("héllo 😀")),
            ("integer", integer_record(i64::MIN)),
            ("negative", integer_record(-1)),
            ("real", real64_record(-0.0)),
            ("real2", real64_record(1.5e300)),
            ("bool", boolean_record(true)),
            ("date", date_record(-978_307_200.0)),
            ("empty-data", data_record(&[])),
            ("data", data_record(&[0, 1, 2, 0xFE, 0xFF])),
            (
                "nested",
                dict_record_entries(vec![
                    (PortableValue::string("dup"), string_record("first")),
                    (PortableValue::string("dup"), string_record("second")),
                    (
                        PortableValue::string("arr"),
                        array_record(vec![string_record("x"), string_record("x")]),
                    ),
                ]),
            ),
            ("empty-dict", dict_record(vec![])),
            ("empty-array", array_record(vec![])),
        ]);
        let value = record(tree);
        let xml = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(xml.render()).expect("utf-8");
        for spelling in [
            "<integer>-9223372036854775808</integer>",
            "<integer>-1</integer>",
            "<real>-0</real>",
            "<data></data>",
            "<dict></dict>",
            "<array></array>",
            "<key>dup</key>",
        ] {
            assert!(rendered.contains(spelling), "{spelling} not in {rendered}");
        }
        let xml_native = xml.document().expect("native").clone();
        let binary = complete_document(&value, &binary_request());
        assert_eq!(binary.document().expect("native"), &xml_native);
        let binary_native = binary.document().expect("native").clone();
        let xml_again = complete_document(&value, &xml_request());
        assert_eq!(xml_again.document().expect("native"), &binary_native);
    }

    #[test]
    fn binary_style_preserves_binary_only_facts() {
        // Float32 width, UID, and fractional-second dates are exact in binary
        // canonical output.
        let value = record(dict_record_entries(vec![
            (
                PortableValue::string("f32"),
                real32_record(0.1_f32.to_bits()),
            ),
            (PortableValue::string("uid"), uid_record(300)),
            (PortableValue::string("fractional"), date_record(0.5)),
        ]));
        let document = complete_document(&value, &binary_request());
        let hex = to_hex(document.render());
        assert!(
            hex.contains("223dcccccd"),
            "Float32 marker 0x22 with the exact 0.1f32 bits"
        );
        assert!(
            hex.contains("81012c"),
            "UID 300 uses the 2-byte minimal width (marker 0x81, payload 0x012C)"
        );
        // The closure equality holds for the binary-only facts: the native
        // model round-trips the Float32 width and the exact seconds.
        let native = document.document().expect("native");
        let dict = native.root_value().as_dict().expect("dict");
        let real = native
            .get(dict.entries()[0].value())
            .and_then(PlistValue::as_real)
            .expect("real");
        assert_eq!(real.width(), RealWidth::Float32);
        assert_eq!(real.bits(), u64::from(0.1_f32.to_bits()));
        let date = native
            .get(dict.entries()[2].value())
            .and_then(PlistValue::as_date)
            .expect("date");
        assert_eq!(date.seconds().to_bits(), 0.5_f64.to_bits());
    }

    #[test]
    fn binary_style_writes_minimal_integer_widths() {
        let value = record(array_record(vec![
            integer_record(0),
            integer_record(255),
            integer_record(256),
            integer_record(65_535),
            integer_record(65_536),
            integer_record(-1),
            integer_record(i64::MAX),
            integer_record(i64::MIN),
        ]));
        let document = complete_document(&value, &binary_request());
        let hex = to_hex(document.render());
        assert!(hex.contains("1000"), "0 as 1-byte");
        assert!(hex.contains("10ff"), "255 as 1-byte");
        assert!(hex.contains("110100"), "256 as 2-byte");
        assert!(hex.contains("11ffff"), "65535 as 2-byte");
        assert!(hex.contains("1200010000"), "65536 as 4-byte");
        assert!(
            hex.contains("13ffffffffffffffff"),
            "-1 always uses the signed 8-byte form"
        );
        assert!(
            hex.contains("137fffffffffffffff"),
            "i64::MAX uses the signed 8-byte form"
        );
    }

    #[test]
    fn identical_scalars_deduplicate_at_first_occurrence() {
        let value = record(dict_record(vec![
            ("same", string_record("x")),
            ("same2", string_record("x")),
            ("key-same", integer_record(7)),
            ("key-same2", integer_record(7)),
        ]));
        let document = complete_document(&value, &binary_request());
        let objects = document.binary_facts().expect("facts").objects();
        // The dict, its four distinct key objects, and one deduplicated "x"
        // and one deduplicated 7: seven objects.
        assert_eq!(objects.len(), 7);
        let native = document.document().expect("native");
        let root = native.root_value().as_dict().expect("dict");
        let first = native
            .get(root.entries()[0].value())
            .and_then(PlistValue::as_string)
            .expect("string");
        let second = native
            .get(root.entries()[1].value())
            .and_then(PlistValue::as_string)
            .expect("string");
        assert_eq!(first.code_units(), second.code_units());
    }

    #[test]
    fn keys_keep_input_order_and_duplicates() {
        let value = record(dict_record(vec![
            ("z", integer_record(1)),
            ("a", integer_record(2)),
            ("z", integer_record(3)),
        ]));
        let xml = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(xml.render()).expect("utf-8");
        let first_z = rendered.find("<key>z</key>").expect("first z");
        let a = rendered.find("<key>a</key>").expect("a");
        let second_z = rendered.rfind("<key>z</key>").expect("second z");
        assert!(first_z < a && a < second_z, "{rendered}");
        let binary = complete_document(&value, &binary_request());
        let native = binary.document().expect("native");
        let entries = native.root_value().as_dict().expect("dict").entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "z");
        assert_eq!(entries[1].key().to_unicode().unwrap(), "a");
        assert_eq!(entries[2].key().to_unicode().unwrap(), "z");
    }

    #[test]
    fn base64_wraps_against_the_indented_budget() {
        // 100 bytes produce 136 base64 characters; at depth 2 the budget is
        // 76 - 16 = 60 characters per line.
        let bytes = (0..100)
            .map(|index| u8::try_from(index).expect("byte in range"))
            .collect::<Vec<_>>();
        let value = record(dict_record(vec![("big", data_record(&bytes))]));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        let start = rendered.find("<data>").expect("data element");
        let end = rendered.find("</data>").expect("data close");
        let body = &rendered[start + 6..end];
        let lines = body.split('\n').collect::<Vec<_>>();
        assert!(lines.len() >= 3, "100 bytes must wrap: {body}");
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                // The line carries the 8-space element indent plus the
                // 60-character base64 budget (76 - 8 * depth at depth 2);
                // only the final line may be shorter.
                assert!(
                    line.starts_with("        "),
                    "continuation lines are indented like the element"
                );
                assert!(line.trim_start().len() <= 60);
                if index < lines.len() - 1 {
                    assert_eq!(line.len(), 68, "continuation lines use the budget");
                    assert_eq!(line.trim_start().len(), 60);
                }
            }
        }
        // The wrapped base64 still reparses: the closure passed, and the
        // native bytes are exact.
        let native = document.document().expect("native");
        let entry = &native.root_value().as_dict().expect("dict").entries()[0];
        let bytes = native
            .get(entry.value())
            .and_then(PlistValue::as_data)
            .expect("data")
            .bytes();
        assert_eq!(bytes, &(0..100).collect::<Vec<_>>());
    }

    #[test]
    fn provenance_covers_every_value_node_and_is_target_bound() {
        let value = record(dict_record(vec![
            ("a", integer_record(1)),
            (
                "b",
                array_record(vec![string_record("x"), string_record("y")]),
            ),
        ]));
        for request in [xml_request(), binary_request()] {
            match materialize(&value, &request) {
                MaterializationResult::Complete(complete) => {
                    // Root dict, integer, array, "x", "y": five value nodes.
                    assert_eq!(complete.provenance.entries().len(), 5);
                    let target = complete.document.snapshot_identity();
                    for entry in complete.provenance.entries() {
                        assert_eq!(entry.outputs.len(), 1);
                        let origin = &entry.outputs[0];
                        assert_eq!(origin.snapshot, target);
                        assert_eq!(origin.node.snapshot(), target);
                        assert_eq!(origin.span.snapshot(), target);
                        assert_eq!(origin.node.role(), NodeRole::PlistValue);
                        assert_eq!(origin.relation, MaterializationRelation::Direct);
                    }
                }
                MaterializationResult::Failed(attempt) => {
                    panic!("must complete: {:?}", attempt.failure);
                }
            }
        }
    }

    #[test]
    fn provenance_spans_are_exact_for_both_styles() {
        let value = record(dict_record(vec![("a", integer_record(1))]));
        let MaterializationResult::Complete(xml) = materialize(&value, &xml_request()) else {
            panic!("must complete");
        };
        // Items are recorded in post-order (children first), so the root
        // dict is the last entry; the span covers the element from its open
        // tag through its close tag, without the surrounding trivia.
        let xml_root = &xml.provenance.entries()[1].outputs[0];
        let xml_source = xml.document.render();
        assert_eq!(
            &xml_source[xml_root.span.start_byte()..xml_root.span.end_byte()],
            b"<dict>\n        <key>a</key>\n        <integer>1</integer>\n    </dict>"
        );
        let MaterializationResult::Complete(binary) = materialize(&value, &binary_request()) else {
            panic!("must complete");
        };
        let binary_root = &binary.provenance.entries()[0].outputs[0];
        let binary_source = binary.document.render();
        assert_eq!(
            &binary_source[binary_root.span.start_byte()..binary_root.span.end_byte()],
            &[0xD1, 0x01, 0x02],
            "the root dict origin spans marker through references"
        );
    }

    #[test]
    fn input_node_and_depth_limits_fail_with_exact_names() {
        let wide = record(array_record(vec![string_record("x"); 3]));
        assert_failure(
            &wide,
            &xml_request().with_limits(MaterializationLimits {
                max_input_nodes: 2,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-nodes"),
        );
        let deep = record(dict_record(vec![(
            "a",
            dict_record(vec![("b", dict_record(vec![("c", string_record("x"))]))]),
        )]));
        assert_failure(
            &deep,
            &xml_request().with_limits(MaterializationLimits {
                max_depth: 2,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("input-depth"),
        );
        assert_failure(
            &record(string_record("longer than sixteen bytes")),
            &binary_request().with_limits(MaterializationLimits {
                max_output_bytes: 16,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("output-bytes"),
        );
    }

    #[test]
    fn provenance_limits_fail_atomically() {
        let value = record(dict_record(vec![("a", integer_record(1))]));
        assert_failure(
            &value,
            &xml_request().with_limits(MaterializationLimits {
                max_provenance_entries: 1,
                ..MaterializationLimits::default()
            }),
            MaterializationFailure::ResourceLimit("provenance-entries"),
        );
    }

    #[test]
    fn decimal_payloads_are_admitted() {
        // The conformance runner feeds the vectors through the consema-json
        // projection, which renders JSON numbers as Decimal; the exact double
        // semantics follow.
        let mut date = ObjectBuilder::new();
        date.insert("epoch", PortableValue::string(PLIST_EPOCH_SPELLING))
            .expect("insert");
        date.insert(
            "seconds",
            PortableValue::decimal(Decimal::parse_json_number("694224000.0").unwrap()),
        )
        .expect("insert");
        // The dictionary is spelled as an ordered JSON object, exactly as the
        // conformance vectors spell the record.
        let value = record(dict_object(vec![
            (
                "ratio",
                PortableValue::decimal(Decimal::parse_json_number("1.5").unwrap()),
            ),
            ("created", date.build()),
        ]));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        assert!(rendered.contains("<real>1.5</real>"), "{rendered}");
        assert!(
            rendered.contains("<date>2023-01-01T00:00:00Z</date>"),
            "{rendered}"
        );
    }

    #[test]
    fn huge_integers_and_uids_fail_with_exact_kinds() {
        assert_failure(
            &record(PortableValue::integer(
                BigInteger::parse_decimal("9223372036854775808").unwrap(),
            )),
            &binary_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned())),
                kind: PortableValueKind::Integer,
            },
        );
        let mut wide_uid = ObjectBuilder::new();
        wide_uid
            .insert(
                "uid",
                PortableValue::integer(BigInteger::parse_decimal("4294967296").unwrap()),
            )
            .expect("insert");
        assert_failure(
            &record(wide_uid.build()),
            &binary_request(),
            MaterializationFailure::Unrepresentable {
                path: ValuePath::root()
                    .child(ValuePathSegment::ObjectValue("root".to_owned()))
                    .child(ValuePathSegment::ObjectValue("uid".to_owned())),
                kind: PortableValueKind::Integer,
            },
        );
    }

    #[test]
    fn scalar_root_values_round_trip() {
        let cases: Vec<(PortableValue, &str)> = vec![
            (string_record(""), "<string></string>"),
            (string_record("x"), "<string>x</string>"),
            (integer_record(0), "<integer>0</integer>"),
            (real64_record(f64::NAN), "<real>nan</real>"),
            (real64_record(f64::INFINITY), "<real>inf</real>"),
            (real64_record(f64::NEG_INFINITY), "<real>-inf</real>"),
            (boolean_record(false), "<false/>"),
            (boolean_record(true), "<true/>"),
            (date_record(0.0), "<date>2001-01-01T00:00:00Z</date>"),
            (data_record(&[]), "<data></data>"),
        ];
        for (root, spelling) in cases {
            let value = record(root);
            let xml = complete_document(&value, &xml_request());
            let rendered = std::str::from_utf8(xml.render()).expect("utf-8");
            assert!(rendered.contains(spelling), "{spelling} not in {rendered}");
            let binary = complete_document(&value, &binary_request());
            assert_eq!(
                binary.document().expect("native"),
                xml.document().expect("native")
            );
        }
    }

    #[test]
    fn the_apple_header_spelling_is_exact() {
        let value = record(dict_record(vec![]));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        assert!(rendered.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n"
        ));
        assert!(rendered.ends_with("</plist>\n"));
    }

    #[test]
    fn empty_dict_and_array_use_the_empty_spelling() {
        let value = record(dict_record(vec![
            ("d", dict_record(vec![])),
            ("a", array_record(vec![])),
        ]));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        assert!(rendered.contains("        <dict></dict>\n"), "{rendered}");
        assert!(rendered.contains("        <array></array>\n"), "{rendered}");
    }

    #[test]
    fn cr_in_strings_escapes_as_a_character_reference() {
        let value = record(string_record("a\rb"));
        let document = complete_document(&value, &xml_request());
        let rendered = std::str::from_utf8(document.render()).expect("utf-8");
        assert!(rendered.contains("<string>a&#13;b</string>"), "{rendered}");
        let binary = complete_document(&value, &binary_request());
        let native = binary.document().expect("native");
        let text = native
            .root_value()
            .as_string()
            .expect("string")
            .code_units();
        assert_eq!(text, &[0x61, 0x0D, 0x62]);
    }

    #[test]
    fn negative_zero_real_survives_the_xml_closure() {
        // Reals render "-0" and the grammar parses it back to -0.0 bits.
        let value = record(real64_record(-0.0));
        let document = complete_document(&value, &xml_request());
        let native = document.document().expect("native");
        let real = native.root_value().as_real().expect("real");
        assert_eq!(real.bits(), (-0.0_f64).to_bits());
    }

    #[test]
    fn large_binary_outputs_grow_the_offset_width() {
        // 300 distinct scalars force objectRefSize 2 (256 < 300 <= 65536);
        // the emitted file still reparses Complete with native equality.
        let elements = (0..300).map(integer_record).collect();
        let value = record(array_record(elements));
        let document = complete_document(&value, &binary_request());
        let trailer = &document.render()[document.render().len() - 32..];
        assert_eq!(trailer[7], 2, "objectRefSize grows to 2 bytes");
        assert_eq!(document.status(), FormationStatus::Complete);
    }

    #[test]
    fn extended_sizes_cover_large_containers() {
        // 20 entries exceed the 15-entry low-nibble limit and force the
        // extended-size spelling (0xDF marker plus a 1-byte count object).
        let entries = (0..20)
            .map(|index| {
                (
                    PortableValue::string(format!("k{index}")),
                    integer_record(index),
                )
            })
            .collect::<Vec<_>>();
        let value = record(dict_record_entries(entries));
        let document = complete_document(&value, &binary_request());
        let hex = to_hex(document.render());
        assert!(hex.starts_with("62706c6973743030df1014"), "{hex}");
    }

    #[test]
    fn the_fifteen_count_boundary_uses_the_extended_size_spelling() {
        // Low nibble `0x0F` is the extended-size sentinel (RFC 0013 §5.4):
        // the parser always reads a nibble-`0xF` marker as "a size object
        // follows", so a count of exactly 15 must never be spelled as the
        // plain `marker | 0x0F` byte — that would consume the first payload
        // byte as the size marker. Every count-15 object emits the sentinel
        // nibble plus the `0x10`-style count object (`0x10 0x0F`), and the
        // closure reparse (materialize -> reparse -> native equality) stays
        // Complete over the exact generated bytes.
        let value = record(dict_record_entries(vec![
            (PortableValue::string("123456789012345"), string_record("v")),
            (PortableValue::string("d"), data_record(&[0u8; 15])),
            (
                PortableValue::string("a"),
                array_record((0..15).map(integer_record).collect()),
            ),
        ]));
        let document = complete_document(&value, &binary_request());
        let hex = to_hex(document.render());
        assert!(hex.contains("5f100f"), "15-char key marker: {hex}");
        assert!(hex.contains("4f100f"), "15-byte data marker: {hex}");
        assert!(hex.contains("af100f"), "15-element array marker: {hex}");
        let reparsed = crate::parse(
            Arc::from(document.render().to_vec()),
            crate::PlistProfile::BinaryV1,
            crate::PlistEncodingSelection::ProfileDefault,
            crate::PlistParseLimits::default(),
        )
        .expect("the canonical bytes reparse");
        assert_eq!(reparsed.status(), FormationStatus::Complete);
        assert_eq!(reparsed.document(), document.document());
    }

    #[test]
    fn the_sixteen_count_neighbor_keeps_the_extended_spelling() {
        // 16 is the first count above the sentinel value and already takes
        // the extended path (`0x5F 0x10 0x10`); the boundary neighbor must
        // stay Complete.
        let value = record(dict_record(vec![("1234567890123456", string_record("v"))]));
        let document = complete_document(&value, &binary_request());
        let hex = to_hex(document.render());
        assert!(hex.contains("5f1010"), "16-char key marker: {hex}");
    }

    #[test]
    fn plan_binary_orders_keys_before_values() {
        let value = record(dict_record(vec![
            ("name", string_record("value")),
            ("count", integer_record(42)),
        ]));
        let MaterializationResult::Complete(complete) = materialize(&value, &binary_request())
        else {
            panic!("must complete");
        };
        // Object 0: dict; 1-2: keys; 3-4: values.
        let facts = complete.document.binary_facts().expect("facts");
        assert_eq!(facts.objects()[0].offset(), 8);
        assert_eq!(facts.objects()[1].offset(), 8 + 1 + 2 + 2);
        let native = complete.document.document().expect("native");
        let dict = native.root_value().as_dict().expect("dict");
        let key = native
            .get(dict.entries()[0].value())
            .and_then(PlistValue::as_string)
            .expect("string");
        assert_eq!(key.to_unicode().unwrap(), "value");
    }

    #[test]
    fn analyzed_paths_are_recorded_before_failure() {
        let value = record(dict_record(vec![("t", date_record(1.5))]));
        match materialize(&value, &xml_request()) {
            MaterializationResult::Failed(attempt) => {
                assert!(
                    attempt.analyzed_input_paths.len() >= 3,
                    "the record, the value, and the dict are analyzed before the date fails"
                );
            }
            MaterializationResult::Complete(_) => panic!("must fail"),
        }
    }

    #[test]
    fn a_projected_xml_record_closes_the_loop_both_styles() {
        // The M9 loop gate: parse Complete -> project -> materialize ->
        // reparse generated bytes -> native-model equality, consuming the
        // projected record directly with no shape translation (RFC 0013 §9,
        // §10.3). The source carries a nested dict/array, repeated dict keys,
        // a date, and data.
        let source = crate::parse(
            Arc::from(
                b"<plist version=\"1.0\"><dict>\
                  <key>name</key><string>text</string>\
                  <key>count</key><integer>42</integer>\
                  <key>nested</key><dict><key>inner</key>\
                  <array><string>a</string><string>b</string></array></dict>\
                  <key>dup</key><string>first</string>\
                  <key>dup</key><string>second</string>\
                  <key>created</key><date>2023-01-01T00:00:00Z</date>\
                  <key>payload</key><data>AQID</data>\
                  </dict></plist>"
                    .as_slice(),
            ),
            crate::PlistProfile::XmlV1,
            crate::PlistEncodingSelection::ProfileDefault,
            crate::PlistParseLimits::default(),
        )
        .expect("the xml source forms complete");
        assert_eq!(source.status(), FormationStatus::Complete);
        let crate::ProjectionResult::Complete(projection) =
            crate::project(&source, crate::ProjectionRequest::value_tree())
        else {
            panic!("projection must complete");
        };
        // The projected record is the materialization record: it carries the
        // `root` member and never the old `value` member.
        let object = projection.value.as_object().expect("record object");
        assert!(object.iter().any(|entry| entry.key() == "root"));
        assert!(!object.iter().any(|entry| entry.key() == "value"));
        let expected = source.document().expect("native").clone();
        for request in [xml_request(), binary_request()] {
            let MaterializationResult::Complete(complete) =
                materialize(&projection.value, &request)
            else {
                panic!("the projected record must materialize");
            };
            assert_eq!(complete.fidelity, MaterializationFidelity::Exact);
            assert_eq!(complete.document.document(), Some(&expected));
        }
    }

    #[test]
    fn a_projected_binary_record_closes_the_loop_both_styles() {
        // The same loop over a binary source: a dict with a string, a
        // whole-second date, and data, each object referenced once so the
        // canonical reparse yields native equality.
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x54, b'n', b'a', b'm', b'e']); // 0: "name"
        file.object(&[0x57, b'c', b'r', b'e', b'a', b't', b'e', b'd']); // 1: "created"
        file.object(&[0x57, b'p', b'a', b'y', b'l', b'o', b'a', b'd']); // 2: "payload"
        file.object(&[0x54, b't', b'e', b'x', b't']); // 3: "text"
        file.object(&[0x33, 0x41, 0xC4, 0xB0, 0x82, 0x40, 0x00, 0x00, 0x00]); // 4: date
        file.object(&[0x43, 0x01, 0x02, 0x03]); // 5: data [1, 2, 3]
        file.object(&[0xD3, 0, 1, 2, 3, 4, 5]); // 6: dict, keys 0-2, values 3-5
        let bytes = file.finish(6);
        let source = crate::parse(
            Arc::from(bytes),
            crate::PlistProfile::BinaryV1,
            crate::PlistEncodingSelection::ProfileDefault,
            crate::PlistParseLimits::default(),
        )
        .expect("the binary source forms complete");
        assert_eq!(source.status(), FormationStatus::Complete);
        let crate::ProjectionResult::Complete(projection) =
            crate::project(&source, crate::ProjectionRequest::value_tree())
        else {
            panic!("projection must complete");
        };
        let expected = source.document().expect("native").clone();
        for request in [xml_request(), binary_request()] {
            let MaterializationResult::Complete(complete) =
                materialize(&projection.value, &request)
            else {
                panic!("the projected record must materialize");
            };
            assert_eq!(complete.fidelity, MaterializationFidelity::Exact);
            assert_eq!(complete.document.document(), Some(&expected));
        }
    }
}
