//! Native plist value model (RFC 0013 §6).
//!
//! The value model is representation-independent: `plist.xml@1` and
//! `plist.binary@1` share one native model, and cross-representation
//! conversion is exact whenever every native fact is expressible in the
//! target representation. The model is not a JSON Object tree and not an XML
//! element tree.
//!
//! Values live in an arena. [`PlistDocument`] owns the ordered node array and
//! the root reference; containers refer to their children by
//! [`PlistValueRef`], so shared identity from the binary object table is
//! preserved: one source object referenced by several arrays or dictionaries
//! is one native node with multiple owners (RFC 0013 §6, §5.9). The arena is
//! acyclic — cycles are rejected at formation (RFC 0013 §5.11) and again by
//! [`PlistDocumentBuilder::build`].
//!
//! Equality is strict and content-based. Scalar values compare exactly: a
//! real compares its exact bit pattern, so NaN payloads and signed zero are
//! distinct. Two documents compare equal when their reachable value graphs
//! are equal, independent of arena indices, sharing patterns, or unreachable
//! objects; this mirrors the "duplicated scalar objects share native value
//! equality" rule of RFC 0013 §5.12 and is the equality the materialization
//! reparse closure (RFC 0013 §10.3) and the cross-representation round trip
//! (RFC 0013 §7) use.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Seconds between the Unix epoch (`1970-01-01T00:00:00Z`) and the plist
/// epoch (`2001-01-01T00:00:00Z`), the origin of every [`PlistDate`] value.
/// The Unix epoch is exactly this many seconds after the plist epoch
/// (RFC 0013 §5.5).
pub const PLIST_EPOCH_OFFSET_UNIX: f64 = 978_307_200.0;

/// Whether exact UTF-16 code units form Unicode scalar text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlistStringStatus {
    /// Every surrogate participates in one adjacent high/low pair.
    WellFormedUnicode,
    /// At least one surrogate is unpaired.
    UnpairedSurrogate,
}

/// Exact plist string content as immutable UTF-16 code units.
///
/// A string holds exact UTF-16 code units with a bounded validation result
/// (`WellFormedUnicode | UnpairedSurrogate`), following the
/// `core.java-utf16-string@1` wire pattern (RFC 0011 §7) as a format-native
/// role. XML sources can only produce well-formed Unicode; binary sources may
/// produce unpaired surrogates, which are preserved exactly and block
/// conversion to the XML representation and to ordinary Unicode projection
/// (RFC 0013 §5.6, §7).
#[derive(Clone, Debug)]
pub struct PlistString {
    code_units: Arc<[u16]>,
    status: PlistStringStatus,
}

impl PlistString {
    /// Creates exact string content and computes surrogate well-formedness.
    #[must_use]
    pub fn from_code_units(code_units: impl Into<Arc<[u16]>>) -> Self {
        let code_units = code_units.into();
        let status = classify_string(&code_units);
        Self { code_units, status }
    }

    /// Converts one valid Unicode scalar string to its exact UTF-16 units.
    #[must_use]
    pub fn from_unicode(value: &str) -> Self {
        Self::from_code_units(value.encode_utf16().collect::<Vec<_>>())
    }

    /// Exact ordered UTF-16 code units.
    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        &self.code_units
    }

    /// Canonical BOM-free big-endian UTF-16BE bytes.
    #[must_use]
    pub fn utf16be_bytes(&self) -> Vec<u8> {
        self.code_units
            .iter()
            .flat_map(|unit| unit.to_be_bytes())
            .collect()
    }

    /// Exact surrogate pairing status.
    #[must_use]
    pub const fn status(&self) -> PlistStringStatus {
        self.status
    }

    /// Converts only well-formed content to a Rust Unicode string.
    pub fn to_unicode(&self) -> Result<String, PlistStringConversionError> {
        String::from_utf16(&self.code_units).map_err(|_| PlistStringConversionError)
    }
}

impl PartialEq for PlistString {
    fn eq(&self, other: &Self) -> bool {
        self.code_units == other.code_units
    }
}

impl Eq for PlistString {}

impl Hash for PlistString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.code_units.hash(state);
    }
}

/// An exact plist string cannot enter a Unicode-only host string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlistStringConversionError;

impl fmt::Display for PlistStringConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plist string contains an unpaired surrogate")
    }
}

impl std::error::Error for PlistStringConversionError {}

/// String key identity of one dictionary association.
///
/// Keys are strings in both profiles (RFC 0013 §4.4, §5.9); each physical
/// association keeps its own key identity, and duplicate keys are preserved
/// as ordered native facts rather than collapsed.
#[derive(Clone, Debug)]
pub struct PlistKey {
    string: PlistString,
}

impl PlistKey {
    /// Creates a key from exact plist string content.
    #[must_use]
    pub fn from_string(string: PlistString) -> Self {
        Self { string }
    }

    /// Creates a key from exact UTF-16 code units.
    #[must_use]
    pub fn from_code_units(code_units: impl Into<Arc<[u16]>>) -> Self {
        Self::from_string(PlistString::from_code_units(code_units))
    }

    /// Creates a key from one valid Unicode scalar string.
    #[must_use]
    pub fn from_unicode(value: &str) -> Self {
        Self::from_string(PlistString::from_unicode(value))
    }

    /// Exact key string content.
    #[must_use]
    pub const fn string(&self) -> &PlistString {
        &self.string
    }

    /// Exact ordered UTF-16 code units.
    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        self.string.code_units()
    }

    /// Exact surrogate pairing status.
    #[must_use]
    pub const fn status(&self) -> PlistStringStatus {
        self.string.status
    }

    /// Converts only well-formed keys to a Rust Unicode string.
    pub fn to_unicode(&self) -> Result<String, PlistStringConversionError> {
        self.string.to_unicode()
    }
}

impl PartialEq for PlistKey {
    fn eq(&self, other: &Self) -> bool {
        self.string == other.string
    }
}

impl Eq for PlistKey {}

impl Hash for PlistKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.string.hash(state);
    }
}

/// Exact signed 64-bit plist integer.
///
/// Both profiles freeze the signed 64-bit range (RFC 0013 §4.5, §5.3, §6);
/// wider source inputs are Recovered rather than widening this type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlistInteger(i64);

impl PlistInteger {
    /// Wraps an exact signed 64-bit value.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Exact value.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

/// Width fact of one exact IEEE 754 real payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealWidth {
    /// 8-byte IEEE 754 binary64.
    Float64,
    /// 4-byte IEEE 754 binary32 (only `plist.binary@1` marker `0x22`).
    Float32,
}

/// Exact IEEE 754 real with its source width fact.
///
/// The value is the exact bit pattern of the source width; NaN and the
/// infinities are admitted values (RFC 0013 §4.6, §5.5). Equality and hashing
/// follow the bit pattern, so distinct NaN payloads and signed zero are
/// distinct values, matching the PortableValue `binary_float` strict-equality
/// philosophy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlistReal {
    bits: u64,
    width: RealWidth,
}

impl PlistReal {
    /// Creates a `Float64` real from an exact double.
    #[must_use]
    pub const fn double(value: f64) -> Self {
        Self {
            bits: value.to_bits(),
            width: RealWidth::Float64,
        }
    }

    /// Creates a `Float32` real from an exact single.
    #[must_use]
    pub fn single(value: f32) -> Self {
        Self {
            bits: u64::from(value.to_bits()),
            width: RealWidth::Float32,
        }
    }

    /// Creates a real from the exact source-width bit pattern.
    ///
    /// This is the parser path (`0x22`/`0x23` payloads). For `Float32` only
    /// the low 32 bits are retained.
    #[must_use]
    pub const fn from_bits(width: RealWidth, bits: u64) -> Self {
        match width {
            RealWidth::Float64 => Self { bits, width },
            RealWidth::Float32 => Self {
                bits: bits & 0xFFFF_FFFF,
                width,
            },
        }
    }

    /// Exact source-width bit pattern.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Source width fact.
    #[must_use]
    pub const fn width(self) -> RealWidth {
        self.width
    }

    /// Exact double-converted value (RFC 0013 §5.5).
    #[must_use]
    pub const fn as_f64(self) -> f64 {
        match self.width {
            RealWidth::Float64 => f64::from_bits(self.bits),
            RealWidth::Float32 => f32::from_bits(self.bits as u32) as f64,
        }
    }
}

/// One plist boolean value (`<true/>`/`<false/>`, markers `0x09`/`0x08`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlistBoolean(bool);

impl PlistBoolean {
    /// Creates a boolean value.
    #[must_use]
    pub const fn new(value: bool) -> Self {
        Self(value)
    }

    /// Exact value.
    #[must_use]
    pub const fn value(self) -> bool {
        self.0
    }
}

/// Exact double seconds since the plist epoch.
///
/// The value is the exact double number of seconds since
/// `2001-01-01T00:00:00Z` (RFC 0013 §4.7, §5.5); the original text spelling
/// of an XML source remains an observable representation fact at the document
/// layer. Construction rejects non-finite payloads: `plist.binary@1` marks
/// them Recovered (RFC 0013 §5.5) and XML calendar validation always yields a
/// finite value. Equality is bit-exact, so signed zero is distinct from zero.
#[derive(Clone, Copy, Debug)]
pub struct PlistDate {
    seconds: f64,
}

impl PlistDate {
    /// Creates a date from exact seconds since the plist epoch.
    pub fn from_seconds(seconds: f64) -> Result<Self, PlistDateError> {
        if seconds.is_finite() {
            Ok(Self { seconds })
        } else {
            Err(PlistDateError)
        }
    }

    /// Exact double seconds since `2001-01-01T00:00:00Z`.
    #[must_use]
    pub const fn seconds(self) -> f64 {
        self.seconds
    }
}

impl PartialEq for PlistDate {
    fn eq(&self, other: &Self) -> bool {
        self.seconds.to_bits() == other.seconds.to_bits()
    }
}

impl Eq for PlistDate {}

impl Hash for PlistDate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.seconds.to_bits().hash(state);
    }
}

/// A plist date value must be a finite double.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlistDateError;

impl fmt::Display for PlistDateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plist date seconds must be finite")
    }
}

impl std::error::Error for PlistDateError {}

/// Exact plist data bytes.
///
/// Data is exact bytes in the native layer; base64 exists only as
/// `plist.xml@1` representation text (RFC 0013 §6).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PlistData {
    bytes: Arc<[u8]>,
}

impl PlistData {
    /// Creates data from exact bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Exact bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Unsigned 32-bit UID value (binary profile only).
///
/// A UID is a value whose reference meaning belongs to an application layer
/// such as NSKeyedArchiver; Consema preserves the value but never resolves it
/// to an object, class name, or archive entry (RFC 0013 §5.8, §6).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlistUid(u32);

impl PlistUid {
    /// Wraps an exact unsigned 32-bit value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Exact value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Arena reference to one native value node.
///
/// A reference is valid only within the arena that issued it, and the arena
/// is bound to one document snapshot at the document layer. The same source
/// object referenced several times is the same reference (shared identity);
/// [`PlistDocumentBuilder::build`] validates every reference before an
/// immutable document exists.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlistValueRef(usize);

impl PlistValueRef {
    /// Creates a reference from an arena-relative ordinal.
    ///
    /// References to not-yet-added nodes are permitted so that the binary
    /// parser can build containers with forward object-table references;
    /// `build` rejects any reference outside the final arena.
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Arena-relative ordinal.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// One ordered dictionary association: key identity and value reference.
///
/// Each physical occurrence keeps its own association identity; duplicate
/// keys are preserved in source order and never collapsed (RFC 0013 §4.4,
/// §5.9).
#[derive(Clone, Debug)]
pub struct PlistDictEntry {
    key: PlistKey,
    value: PlistValueRef,
}

impl PlistDictEntry {
    /// Creates one association.
    #[must_use]
    pub const fn new(key: PlistKey, value: PlistValueRef) -> Self {
        Self { key, value }
    }

    /// String key identity.
    #[must_use]
    pub const fn key(&self) -> &PlistKey {
        &self.key
    }

    /// Value reference within the owning arena.
    #[must_use]
    pub const fn value(&self) -> PlistValueRef {
        self.value
    }
}

/// Ordered plist dictionary value.
///
/// A dictionary preserves physical key/value association order and duplicate
/// occurrences; there is no implicit first-wins or last-wins lookup (RFC 0013
/// §6).
#[derive(Clone, Debug)]
pub struct PlistDict {
    entries: Arc<[PlistDictEntry]>,
}

impl PlistDict {
    /// Creates a dictionary from its ordered associations.
    #[must_use]
    pub fn from_entries(entries: impl Into<Arc<[PlistDictEntry]>>) -> Self {
        Self {
            entries: entries.into(),
        }
    }

    /// Ordered associations.
    #[must_use]
    pub fn entries(&self) -> &[PlistDictEntry] {
        &self.entries
    }

    /// Number of associations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dictionary has no associations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Source-ordered positions of every association whose key equals `key`.
    pub fn positions_of_key<'a>(&'a self, key: &'a PlistKey) -> impl Iterator<Item = usize> + 'a {
        self.entries
            .iter()
            .enumerate()
            .filter_map(move |(position, entry)| (entry.key == *key).then_some(position))
    }
}

/// Ordered plist array value.
#[derive(Clone, Debug)]
pub struct PlistArray {
    elements: Arc<[PlistValueRef]>,
}

impl PlistArray {
    /// Creates an array from its ordered element references.
    #[must_use]
    pub fn from_elements(elements: impl Into<Arc<[PlistValueRef]>>) -> Self {
        Self {
            elements: elements.into(),
        }
    }

    /// Ordered element references.
    #[must_use]
    pub fn elements(&self) -> &[PlistValueRef] {
        &self.elements
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Whether the array has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

/// Closed native plist value kind.
///
/// The kind set is closed by RFC 0013 §6: both profiles share exactly these
/// nine kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlistValueKind {
    /// Ordered dictionary.
    Dict,
    /// Ordered array.
    Array,
    /// Exact UTF-16 string.
    String,
    /// Signed 64-bit integer.
    Integer,
    /// IEEE 754 real with a width fact.
    Real,
    /// Boolean.
    Boolean,
    /// Double seconds since the plist epoch.
    Date,
    /// Exact bytes.
    Data,
    /// Unsigned 32-bit UID.
    Uid,
}

impl PlistValueKind {
    /// Stable query/protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dict => "dict",
            Self::Array => "array",
            Self::String => "string",
            Self::Integer => "integer",
            Self::Real => "real",
            Self::Boolean => "boolean",
            Self::Date => "date",
            Self::Data => "data",
            Self::Uid => "uid",
        }
    }
}

/// One native plist value node.
///
/// The variant set is closed by RFC 0013 §6. `Uid` values are binary-only and
/// are never reachable from an XML document. Structural equality of the
/// complete value graph is provided by [`PlistDocument`], which owns the
/// arena the references in this node point into.
#[derive(Clone, Debug)]
pub enum PlistValue {
    /// Ordered dictionary.
    Dict(PlistDict),
    /// Ordered array.
    Array(PlistArray),
    /// Exact UTF-16 string.
    String(PlistString),
    /// Signed 64-bit integer.
    Integer(PlistInteger),
    /// IEEE 754 real with its width fact.
    Real(PlistReal),
    /// Boolean.
    Boolean(PlistBoolean),
    /// Double seconds since `2001-01-01T00:00:00Z`.
    Date(PlistDate),
    /// Exact bytes.
    Data(PlistData),
    /// Unsigned 32-bit UID.
    Uid(PlistUid),
}

impl PlistValue {
    /// Closed native kind.
    #[must_use]
    pub const fn kind(&self) -> PlistValueKind {
        match self {
            Self::Dict(_) => PlistValueKind::Dict,
            Self::Array(_) => PlistValueKind::Array,
            Self::String(_) => PlistValueKind::String,
            Self::Integer(_) => PlistValueKind::Integer,
            Self::Real(_) => PlistValueKind::Real,
            Self::Boolean(_) => PlistValueKind::Boolean,
            Self::Date(_) => PlistValueKind::Date,
            Self::Data(_) => PlistValueKind::Data,
            Self::Uid(_) => PlistValueKind::Uid,
        }
    }

    /// Dictionary view.
    #[must_use]
    pub const fn as_dict(&self) -> Option<&PlistDict> {
        match self {
            Self::Dict(value) => Some(value),
            _ => None,
        }
    }

    /// Array view.
    #[must_use]
    pub const fn as_array(&self) -> Option<&PlistArray> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    /// String view.
    #[must_use]
    pub const fn as_string(&self) -> Option<&PlistString> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Integer view.
    #[must_use]
    pub const fn as_integer(&self) -> Option<&PlistInteger> {
        match self {
            Self::Integer(value) => Some(value),
            _ => None,
        }
    }

    /// Real view.
    #[must_use]
    pub const fn as_real(&self) -> Option<&PlistReal> {
        match self {
            Self::Real(value) => Some(value),
            _ => None,
        }
    }

    /// Boolean view.
    #[must_use]
    pub const fn as_boolean(&self) -> Option<&PlistBoolean> {
        match self {
            Self::Boolean(value) => Some(value),
            _ => None,
        }
    }

    /// Date view.
    #[must_use]
    pub const fn as_date(&self) -> Option<&PlistDate> {
        match self {
            Self::Date(value) => Some(value),
            _ => None,
        }
    }

    /// Data view.
    #[must_use]
    pub const fn as_data(&self) -> Option<&PlistData> {
        match self {
            Self::Data(value) => Some(value),
            _ => None,
        }
    }

    /// UID view.
    #[must_use]
    pub const fn as_uid(&self) -> Option<&PlistUid> {
        match self {
            Self::Uid(value) => Some(value),
            _ => None,
        }
    }

    /// Ordered direct child references of this node (dictionary values, then
    /// array elements).
    fn references(&self) -> Vec<PlistValueRef> {
        match self {
            Self::Dict(dict) => dict.entries.iter().map(|entry| entry.value).collect(),
            Self::Array(array) => array.elements.to_vec(),
            _ => Vec::new(),
        }
    }
}

/// Resource bounds for one native arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlistArenaLimits {
    /// Maximum native value nodes in one arena.
    pub max_objects: usize,
    /// Maximum container nesting depth of any node in the arena.
    pub max_container_depth: usize,
}

impl Default for PlistArenaLimits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_container_depth: 256,
        }
    }
}

/// Native arena validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlistArenaError {
    /// The node limit was reached before the value could be added.
    ObjectLimitExceeded {
        /// Configured maximum node count.
        limit: usize,
    },
    /// A reference does not index a node in the arena.
    ReferenceOutOfBounds {
        /// The invalid reference.
        reference: PlistValueRef,
        /// Node count of the arena being built.
        node_count: usize,
    },
    /// The arena contains a reference cycle; the reported node is part of or
    /// feeds the cyclic structure.
    CycleDetected {
        /// A node in or feeding the cyclic structure.
        node: PlistValueRef,
    },
    /// A container is nested deeper than the configured limit.
    ContainerDepthLimitExceeded {
        /// The container exceeding the limit.
        node: PlistValueRef,
        /// Configured maximum container depth.
        limit: usize,
    },
}

impl fmt::Display for PlistArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectLimitExceeded { limit } => {
                write!(formatter, "plist arena object limit of {limit} exceeded")
            }
            Self::ReferenceOutOfBounds {
                reference,
                node_count,
            } => write!(
                formatter,
                "plist arena reference {reference:?} is out of bounds for {node_count} nodes"
            ),
            Self::CycleDetected { node } => {
                write!(
                    formatter,
                    "plist arena contains a reference cycle at or feeding {node:?}"
                )
            }
            Self::ContainerDepthLimitExceeded { node, limit } => write!(
                formatter,
                "plist arena container depth exceeds {limit} at node {node:?}"
            ),
        }
    }
}

impl std::error::Error for PlistArenaError {}

/// Immutable native plist value arena.
///
/// The arena owns every native value node of one document (in binary
/// object-table order) and the root reference. Nodes may be referenced by
/// several containers, preserving shared identity from the binary object
/// table. Objects not reachable from the root may exist in the arena (binary
/// object-table orphans); they remain structural facts of the binary
/// representation and are excluded from structural equality.
///
/// Structural equality compares only the reachable value graphs and is
/// content-based: sharing patterns, arena indices, and unreachable objects do
/// not matter. This is the equality the round-trip contract of RFC 0013
/// §10.3 and the cross-representation native-model equality of RFC 0013 §7
/// use.
#[derive(Clone, Debug)]
pub struct PlistDocument {
    nodes: Arc<[PlistValue]>,
    root: PlistValueRef,
    arena_limits: PlistArenaLimits,
}

impl PlistDocument {
    /// Root value reference.
    #[must_use]
    pub const fn root(&self) -> PlistValueRef {
        self.root
    }

    /// Root value; always in bounds because `build` validated the arena.
    #[must_use]
    pub fn root_value(&self) -> &PlistValue {
        &self.nodes[self.root.0]
    }

    /// Resolves one reference within this arena.
    #[must_use]
    pub fn get(&self, reference: PlistValueRef) -> Option<&PlistValue> {
        self.nodes.get(reference.0)
    }

    /// Number of nodes in the arena, including unreachable objects.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Arena limits used when the document was built.
    #[must_use]
    pub const fn arena_limits(&self) -> PlistArenaLimits {
        self.arena_limits
    }
}

impl PartialEq for PlistDocument {
    fn eq(&self, other: &Self) -> bool {
        if self.root == other.root && Arc::ptr_eq(&self.nodes, &other.nodes) {
            return true;
        }
        // Iterative structural comparison of the reachable graphs with a
        // memo of already-proven-equal node pairs. The arenas are acyclic,
        // so each pair is compared at most once even under heavy sharing.
        let mut memo = HashSet::new();
        let mut stack = vec![(self.root.0, other.root.0)];
        while let Some((left, right)) = stack.pop() {
            if !memo.insert((left, right)) {
                continue;
            }
            match (&self.nodes[left], &other.nodes[right]) {
                (PlistValue::Dict(left_dict), PlistValue::Dict(right_dict)) => {
                    let left_entries = left_dict.entries();
                    let right_entries = right_dict.entries();
                    if left_entries.len() != right_entries.len() {
                        return false;
                    }
                    for (left_entry, right_entry) in left_entries.iter().zip(right_entries.iter()) {
                        if left_entry.key() != right_entry.key() {
                            return false;
                        }
                        stack.push((left_entry.value().0, right_entry.value().0));
                    }
                }
                (PlistValue::Array(left_array), PlistValue::Array(right_array)) => {
                    let left_elements = left_array.elements();
                    let right_elements = right_array.elements();
                    if left_elements.len() != right_elements.len() {
                        return false;
                    }
                    stack.extend(
                        left_elements
                            .iter()
                            .zip(right_elements.iter())
                            .map(|(left_ref, right_ref)| (left_ref.0, right_ref.0)),
                    );
                }
                (PlistValue::String(left), PlistValue::String(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Integer(left), PlistValue::Integer(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Real(left), PlistValue::Real(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Boolean(left), PlistValue::Boolean(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Date(left), PlistValue::Date(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Data(left), PlistValue::Data(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (PlistValue::Uid(left), PlistValue::Uid(right)) => {
                    if left != right {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

impl Eq for PlistDocument {}

impl Hash for PlistDocument {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Content-based structural hash. Shared nodes are hashed per
        // occurrence (no memoization): content-equal documents with different
        // sharing patterns must hash identically, and per-occurrence hashing
        // is what makes the traversal sequences match exactly.
        let mut stack = vec![self.root.0];
        while let Some(index) = stack.pop() {
            match &self.nodes[index] {
                PlistValue::Dict(dict) => {
                    PlistValueKind::Dict.hash(state);
                    dict.entries().len().hash(state);
                    for entry in dict.entries() {
                        entry.key().hash(state);
                        stack.push(entry.value().0);
                    }
                }
                PlistValue::Array(array) => {
                    PlistValueKind::Array.hash(state);
                    array.elements().len().hash(state);
                    stack.extend(array.elements().iter().map(|reference| reference.0));
                }
                PlistValue::String(value) => {
                    PlistValueKind::String.hash(state);
                    value.hash(state);
                }
                PlistValue::Integer(value) => {
                    PlistValueKind::Integer.hash(state);
                    value.hash(state);
                }
                PlistValue::Real(value) => {
                    PlistValueKind::Real.hash(state);
                    value.hash(state);
                }
                PlistValue::Boolean(value) => {
                    PlistValueKind::Boolean.hash(state);
                    value.hash(state);
                }
                PlistValue::Date(value) => {
                    PlistValueKind::Date.hash(state);
                    value.hash(state);
                }
                PlistValue::Data(value) => {
                    PlistValueKind::Data.hash(state);
                    value.hash(state);
                }
                PlistValue::Uid(value) => {
                    PlistValueKind::Uid.hash(state);
                    value.hash(state);
                }
            }
        }
    }
}

/// Builds one immutable [`PlistDocument`] arena.
///
/// The binary parser adds nodes in object-table order so that arena indices
/// equal object indices; the same source object is added once and referenced
/// many times, which yields shared identity. References may point forward
/// (containers referencing not-yet-added objects). [`PlistDocumentBuilder::build`]
/// validates the complete arena: reference bounds, acyclicity, and the
/// container depth limit.
#[derive(Clone, Debug)]
pub struct PlistDocumentBuilder {
    nodes: Vec<PlistValue>,
    limits: PlistArenaLimits,
}

impl PlistDocumentBuilder {
    /// Starts a builder with the default arena limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(PlistArenaLimits::default())
    }

    /// Starts a builder with explicit arena limits.
    #[must_use]
    pub fn with_limits(limits: PlistArenaLimits) -> Self {
        Self {
            nodes: Vec::new(),
            limits,
        }
    }

    /// Arena limits applied by this builder.
    #[must_use]
    pub const fn limits(&self) -> PlistArenaLimits {
        self.limits
    }

    /// Number of nodes added so far.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Adds one node and returns its arena reference.
    pub fn add(&mut self, value: PlistValue) -> Result<PlistValueRef, PlistArenaError> {
        if self.nodes.len() >= self.limits.max_objects {
            return Err(PlistArenaError::ObjectLimitExceeded {
                limit: self.limits.max_objects,
            });
        }
        self.nodes.push(value);
        Ok(PlistValueRef(self.nodes.len() - 1))
    }

    /// Validates the arena and freezes it into one immutable document.
    ///
    /// The root must be in bounds, every reference must index an existing
    /// node, the reference graph must be acyclic, and no container may be
    /// nested deeper than `max_container_depth`. Validation is iterative
    /// (Kahn's algorithm plus a reversed-topological depth pass) and performs
    /// no recursion.
    pub fn build(self, root: PlistValueRef) -> Result<PlistDocument, PlistArenaError> {
        let node_count = self.nodes.len();
        if root.0 >= node_count {
            return Err(PlistArenaError::ReferenceOutOfBounds {
                reference: root,
                node_count,
            });
        }
        // Reference bounds and indegrees.
        let mut indegree = vec![0_usize; node_count];
        for node in &self.nodes {
            for reference in node.references() {
                if reference.0 >= node_count {
                    return Err(PlistArenaError::ReferenceOutOfBounds {
                        reference,
                        node_count,
                    });
                }
                indegree[reference.0] += 1;
            }
        }
        // Kahn's algorithm: parents before children, leaving cyclic nodes
        // unprocessed.
        let mut queue = VecDeque::new();
        for (index, degree) in indegree.iter().enumerate() {
            if *degree == 0 {
                queue.push_back(index);
            }
        }
        let mut order = Vec::with_capacity(node_count);
        while let Some(index) = queue.pop_front() {
            order.push(index);
            for reference in self.nodes[index].references() {
                indegree[reference.0] -= 1;
                if indegree[reference.0] == 0 {
                    queue.push_back(reference.0);
                }
            }
        }
        if order.len() != node_count {
            let mut processed = vec![false; node_count];
            for index in &order {
                processed[*index] = true;
            }
            let mut node = 0;
            while node < node_count && processed[node] {
                node += 1;
            }
            return Err(PlistArenaError::CycleDetected {
                node: PlistValueRef(node),
            });
        }
        // Container depth over the reversed topological order, so every
        // child's depth is known before its parent.
        let mut depth = vec![0_usize; node_count];
        for &index in order.iter().rev() {
            if matches!(
                &self.nodes[index],
                PlistValue::Dict(_) | PlistValue::Array(_)
            ) {
                let mut child_depth = 0;
                for reference in self.nodes[index].references() {
                    child_depth = child_depth.max(depth[reference.0]);
                }
                let container_depth = child_depth + 1;
                if container_depth > self.limits.max_container_depth {
                    return Err(PlistArenaError::ContainerDepthLimitExceeded {
                        node: PlistValueRef(index),
                        limit: self.limits.max_container_depth,
                    });
                }
                depth[index] = container_depth;
            }
        }
        Ok(PlistDocument {
            nodes: Arc::from(self.nodes),
            root,
            arena_limits: self.limits,
        })
    }
}

impl Default for PlistDocumentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn classify_string(units: &[u16]) -> PlistStringStatus {
    let mut index = 0;
    while index < units.len() {
        match units[index] {
            0xD800..=0xDBFF
                if units
                    .get(index + 1)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(next)) =>
            {
                index += 2;
            }
            0xD800..=0xDFFF => return PlistStringStatus::UnpairedSurrogate,
            _ => index += 1,
        }
    }
    PlistStringStatus::WellFormedUnicode
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash_of(document: &PlistDocument) -> u64 {
        let mut hasher = DefaultHasher::new();
        document.hash(&mut hasher);
        hasher.finish()
    }

    fn key_hash(key: &PlistKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn integer_document(value: i64) -> PlistDocument {
        let mut builder = PlistDocumentBuilder::new();
        let root = builder
            .add(PlistValue::Integer(PlistInteger::new(value)))
            .unwrap();
        builder.build(root).unwrap()
    }

    #[test]
    fn string_preserves_exact_code_units_and_status() {
        let string = PlistString::from_unicode("A😀B");
        assert_eq!(string.code_units(), &[0x0041, 0xD83D, 0xDE00, 0x0042]);
        assert_eq!(string.status(), PlistStringStatus::WellFormedUnicode);
        assert_eq!(
            string.utf16be_bytes(),
            [0x00, 0x41, 0xD8, 0x3D, 0xDE, 0x00, 0x00, 0x42]
        );
        assert_eq!(string.to_unicode().unwrap(), "A😀B");
    }

    #[test]
    fn string_keeps_unpaired_surrogates_exact() {
        let string = PlistString::from_code_units(vec![0x0041, 0xD800, 0x0042]);
        assert_eq!(string.code_units(), &[0x0041, 0xD800, 0x0042]);
        assert_eq!(string.status(), PlistStringStatus::UnpairedSurrogate);
        assert_eq!(string.utf16be_bytes(), [0x00, 0x41, 0xD8, 0x00, 0x00, 0x42]);
        assert!(string.to_unicode().is_err());
    }

    #[test]
    fn string_equality_and_hash_follow_code_units() {
        let first = PlistString::from_unicode("key");
        let second = PlistString::from_code_units("key".encode_utf16().collect::<Vec<_>>());
        assert_eq!(first, second);
        assert_ne!(first, PlistString::from_unicode("Key"));
        let empty = PlistString::from_code_units(vec![]);
        assert!(empty.code_units().is_empty());
        assert_eq!(empty.status(), PlistStringStatus::WellFormedUnicode);
    }

    #[test]
    fn key_identity_compares_by_exact_code_units() {
        let first = PlistKey::from_unicode("key");
        let second = PlistKey::from_string(PlistString::from_code_units(
            "key".encode_utf16().collect::<Vec<_>>(),
        ));
        assert_eq!(first, second);
        assert_ne!(first, PlistKey::from_unicode("Key"));
        assert_eq!(key_hash(&first), key_hash(&second));
    }

    #[test]
    fn key_delegates_string_facts() {
        let key = PlistKey::from_code_units(vec![0x0041, 0xD800]);
        assert_eq!(key.code_units(), &[0x0041, 0xD800]);
        assert_eq!(key.status(), PlistStringStatus::UnpairedSurrogate);
        assert_eq!(key.string().code_units(), &[0x0041, 0xD800]);
        assert!(key.to_unicode().is_err());
        assert_eq!(PlistKey::from_unicode("k").to_unicode().unwrap(), "k");
    }

    #[test]
    fn integer_wraps_exact_i64_range() {
        assert_eq!(PlistInteger::new(i64::MIN).value(), i64::MIN);
        assert_eq!(PlistInteger::new(i64::MAX).value(), i64::MAX);
        assert_eq!(PlistInteger::new(0).value(), 0);
        assert_eq!(PlistInteger::new(-1).value(), -1);
    }

    #[test]
    fn integer_equality_is_exact() {
        assert_eq!(PlistInteger::new(1), PlistInteger::new(1));
        assert_ne!(PlistInteger::new(1), PlistInteger::new(2));
    }

    #[test]
    fn real_double_keeps_exact_bits() {
        let real = PlistReal::double(1.5);
        assert_eq!(real.width(), RealWidth::Float64);
        assert_eq!(real.bits(), 1.5_f64.to_bits());
        assert_eq!(real.as_f64().to_bits(), 1.5_f64.to_bits());
        assert_ne!(PlistReal::double(0.0), PlistReal::double(-0.0));
    }

    #[test]
    fn real_single_keeps_float32_width_fact() {
        let real = PlistReal::single(0.1_f32);
        assert_eq!(real.width(), RealWidth::Float32);
        assert_eq!(real.bits(), u64::from(0.1_f32.to_bits()));
        assert_eq!(real.as_f64().to_bits(), f64::from(0.1_f32).to_bits());
    }

    #[test]
    fn real_nan_and_infinity_are_admitted_and_bit_exact() {
        let nan = PlistReal::double(f64::NAN);
        let other_nan = PlistReal::from_bits(RealWidth::Float64, 0x7FF8_0000_0000_0001);
        assert_eq!(nan, PlistReal::double(f64::NAN));
        assert_ne!(nan, other_nan);
        assert_eq!(
            PlistReal::double(f64::INFINITY),
            PlistReal::double(f64::INFINITY)
        );
        assert_ne!(
            PlistReal::double(f64::INFINITY),
            PlistReal::double(f64::NEG_INFINITY)
        );
        assert!(nan.as_f64().is_nan());
    }

    #[test]
    fn real_from_bits_is_the_parser_path_and_masks_float32() {
        let real = PlistReal::from_bits(RealWidth::Float32, 0xFFFF_FFFF_3DCC_CCCD);
        assert_eq!(real.bits(), 0x3DCC_CCCD);
        assert_eq!(
            real.as_f64().to_bits(),
            f64::from(f32::from_bits(0x3DCC_CCCD)).to_bits()
        );
    }

    #[test]
    fn boolean_wraps_true_and_false() {
        assert!(PlistBoolean::new(true).value());
        assert!(!PlistBoolean::new(false).value());
    }

    #[test]
    fn boolean_equality_is_exact() {
        assert_eq!(PlistBoolean::new(true), PlistBoolean::new(true));
        assert_ne!(PlistBoolean::new(true), PlistBoolean::new(false));
    }

    #[test]
    fn date_rejects_non_finite_seconds() {
        assert!(PlistDate::from_seconds(f64::NAN).is_err());
        assert!(PlistDate::from_seconds(f64::INFINITY).is_err());
        assert!(PlistDate::from_seconds(f64::NEG_INFINITY).is_err());
        assert!(PlistDate::from_seconds(0.0).is_ok());
    }

    #[test]
    fn date_holds_exact_seconds_since_plist_epoch() {
        assert_eq!(
            PlistDate::from_seconds(0.0).unwrap().seconds().to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(
            PlistDate::from_seconds(-1.5).unwrap().seconds().to_bits(),
            (-1.5_f64).to_bits()
        );
        assert_eq!(
            PlistDate::from_seconds(PLIST_EPOCH_OFFSET_UNIX)
                .unwrap()
                .seconds()
                .to_bits(),
            978_307_200.0_f64.to_bits()
        );
    }

    #[test]
    fn date_equality_is_bit_exact_including_signed_zero() {
        assert_eq!(
            PlistDate::from_seconds(1.25).unwrap(),
            PlistDate::from_seconds(1.25).unwrap()
        );
        assert_ne!(
            PlistDate::from_seconds(1.25).unwrap(),
            PlistDate::from_seconds(1.5).unwrap()
        );
        assert_ne!(
            PlistDate::from_seconds(0.0).unwrap(),
            PlistDate::from_seconds(-0.0).unwrap()
        );
    }

    #[test]
    fn epoch_offset_constant_is_exact() {
        // RFC 0013 §5.5: `1970-01-01T00:00:00Z` is exactly `978307200`
        // seconds earlier than `2001-01-01T00:00:00Z` — 11,323 days × 86,400.
        assert_eq!(
            PLIST_EPOCH_OFFSET_UNIX.to_bits(),
            978_307_200.0_f64.to_bits()
        );
        assert_eq!(
            PLIST_EPOCH_OFFSET_UNIX.to_bits(),
            (11_323.0_f64 * 86_400.0).to_bits()
        );
    }

    #[test]
    fn data_accepts_empty_and_keeps_exact_bytes() {
        let empty = PlistData::from_bytes(vec![]);
        assert!(empty.bytes().is_empty());
        let data = PlistData::from_bytes(vec![0x00, 0x01, 0xFF]);
        assert_eq!(data.bytes(), &[0x00, 0x01, 0xFF]);
    }

    #[test]
    fn data_equality_and_hash() {
        assert_eq!(
            PlistData::from_bytes(vec![1, 2]),
            PlistData::from_bytes(vec![1, 2])
        );
        assert_ne!(
            PlistData::from_bytes(vec![1, 2]),
            PlistData::from_bytes(vec![1, 3])
        );
    }

    #[test]
    fn uid_wraps_zero_and_max() {
        assert_eq!(PlistUid::new(0).value(), 0);
        assert_eq!(PlistUid::new(u32::MAX).value(), u32::MAX);
        assert_eq!(PlistUid::new(u32::MAX), PlistUid::new(u32::MAX));
        assert_ne!(PlistUid::new(0), PlistUid::new(1));
    }

    #[test]
    fn value_ref_identity_compares_by_index() {
        assert_eq!(PlistValueRef::from_index(0), PlistValueRef::from_index(0));
        assert_ne!(PlistValueRef::from_index(0), PlistValueRef::from_index(1));
        assert_eq!(PlistValueRef::from_index(3).index(), 3);
    }

    #[test]
    fn dict_accepts_empty() {
        let dict = PlistDict::from_entries(vec![]);
        assert!(dict.is_empty());
        assert_eq!(dict.len(), 0);
        assert!(dict.entries().is_empty());
    }

    #[test]
    fn dict_preserves_association_order_and_duplicates() {
        let dict = PlistDict::from_entries(vec![
            PlistDictEntry::new(PlistKey::from_unicode("b"), PlistValueRef::from_index(10)),
            PlistDictEntry::new(PlistKey::from_unicode("a"), PlistValueRef::from_index(11)),
            PlistDictEntry::new(PlistKey::from_unicode("b"), PlistValueRef::from_index(12)),
        ]);
        assert_eq!(dict.len(), 3);
        assert_eq!(dict.entries()[0].key().to_unicode().unwrap(), "b");
        assert_eq!(dict.entries()[0].value(), PlistValueRef::from_index(10));
        assert_eq!(dict.entries()[2].key().to_unicode().unwrap(), "b");
        assert_eq!(dict.entries()[2].value(), PlistValueRef::from_index(12));
    }

    #[test]
    fn dict_positions_of_key_are_source_ordered() {
        let dict = PlistDict::from_entries(vec![
            PlistDictEntry::new(PlistKey::from_unicode("a"), PlistValueRef::from_index(0)),
            PlistDictEntry::new(PlistKey::from_unicode("b"), PlistValueRef::from_index(1)),
            PlistDictEntry::new(PlistKey::from_unicode("a"), PlistValueRef::from_index(2)),
        ]);
        let positions = dict
            .positions_of_key(&PlistKey::from_unicode("a"))
            .collect::<Vec<_>>();
        assert_eq!(positions, vec![0, 2]);
        assert!(
            dict.positions_of_key(&PlistKey::from_unicode("z"))
                .next()
                .is_none()
        );
    }

    #[test]
    fn array_accepts_empty() {
        let array = PlistArray::from_elements(vec![]);
        assert!(array.is_empty());
        assert_eq!(array.len(), 0);
        assert!(array.elements().is_empty());
    }

    #[test]
    fn array_preserves_element_order() {
        let array = PlistArray::from_elements(vec![
            PlistValueRef::from_index(0),
            PlistValueRef::from_index(1),
            PlistValueRef::from_index(2),
        ]);
        assert_eq!(array.len(), 3);
        assert_eq!(array.elements()[0], PlistValueRef::from_index(0));
        assert_eq!(array.elements()[2], PlistValueRef::from_index(2));
    }

    #[test]
    fn value_kind_reports_closed_type_set_and_accessors() {
        let values = [
            PlistValue::Dict(PlistDict::from_entries(vec![])),
            PlistValue::Array(PlistArray::from_elements(vec![])),
            PlistValue::String(PlistString::from_unicode("")),
            PlistValue::Integer(PlistInteger::new(0)),
            PlistValue::Real(PlistReal::double(0.0)),
            PlistValue::Boolean(PlistBoolean::new(false)),
            PlistValue::Date(PlistDate::from_seconds(0.0).unwrap()),
            PlistValue::Data(PlistData::from_bytes(vec![])),
            PlistValue::Uid(PlistUid::new(0)),
        ];
        let kinds = [
            PlistValueKind::Dict,
            PlistValueKind::Array,
            PlistValueKind::String,
            PlistValueKind::Integer,
            PlistValueKind::Real,
            PlistValueKind::Boolean,
            PlistValueKind::Date,
            PlistValueKind::Data,
            PlistValueKind::Uid,
        ];
        for (value, kind) in values.iter().zip(kinds.iter()) {
            assert_eq!(value.kind(), *kind);
        }
        assert!(values[0].as_dict().is_some());
        assert!(values[0].as_integer().is_none());
        assert!(values[3].as_integer().is_some());
        assert!(values[3].as_uid().is_none());
        assert!(values[8].as_uid().is_some());
        assert!(values[8].as_boolean().is_none());
    }

    #[test]
    fn value_kind_has_stable_wire_spellings() {
        assert_eq!(PlistValueKind::Dict.as_str(), "dict");
        assert_eq!(PlistValueKind::Array.as_str(), "array");
        assert_eq!(PlistValueKind::String.as_str(), "string");
        assert_eq!(PlistValueKind::Integer.as_str(), "integer");
        assert_eq!(PlistValueKind::Real.as_str(), "real");
        assert_eq!(PlistValueKind::Boolean.as_str(), "boolean");
        assert_eq!(PlistValueKind::Date.as_str(), "date");
        assert_eq!(PlistValueKind::Data.as_str(), "data");
        assert_eq!(PlistValueKind::Uid.as_str(), "uid");
    }

    #[test]
    fn builder_builds_document_with_resolvable_root() {
        let mut builder = PlistDocumentBuilder::new();
        let root = builder
            .add(PlistValue::Integer(PlistInteger::new(7)))
            .unwrap();
        let document = builder.build(root).unwrap();
        assert_eq!(document.root(), root);
        assert_eq!(document.node_count(), 1);
        assert_eq!(document.get(root).unwrap().kind(), PlistValueKind::Integer);
        assert_eq!(
            document
                .get(root)
                .and_then(PlistValue::as_integer)
                .map(|integer| integer.value()),
            Some(7)
        );
        assert_eq!(document.root_value().kind(), PlistValueKind::Integer);
        assert_eq!(document.arena_limits(), PlistArenaLimits::default());
        assert!(document.get(PlistValueRef::from_index(5)).is_none());
    }

    #[test]
    fn shared_identity_is_one_node_with_multiple_owners() {
        let mut builder = PlistDocumentBuilder::new();
        let shared = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![])))
            .unwrap();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![
                shared, shared,
            ])))
            .unwrap();
        let document = builder.build(root).unwrap();
        let elements = document.get(root).unwrap().as_array().unwrap().elements();
        assert_eq!(elements, &[shared, shared]);
        assert_eq!(elements[0], elements[1]);
    }

    #[test]
    fn structural_equality_ignores_arena_indices_and_sharing() {
        let mut builder = PlistDocumentBuilder::new();
        let one = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let shared = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("k"), one),
            ])))
            .unwrap();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![
                shared, shared,
            ])))
            .unwrap();
        let shared_document = builder.build(root).unwrap();

        let mut builder = PlistDocumentBuilder::new();
        let one_first = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let first = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("k"), one_first),
            ])))
            .unwrap();
        let one_second = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let second = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("k"), one_second),
            ])))
            .unwrap();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![
                first, second,
            ])))
            .unwrap();
        let distinct_document = builder.build(root).unwrap();

        assert_eq!(shared_document, distinct_document);
        assert_eq!(hash_of(&shared_document), hash_of(&distinct_document));
    }

    #[test]
    fn structural_equality_requires_content_and_order_equality() {
        let mut builder = PlistDocumentBuilder::new();
        let value = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let root = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("a"), value),
            ])))
            .unwrap();
        let document = builder.build(root).unwrap();

        assert_ne!(document, integer_document(1));
        assert_ne!(document, integer_document(2));

        let mut builder = PlistDocumentBuilder::new();
        let value = builder
            .add(PlistValue::Integer(PlistInteger::new(2)))
            .unwrap();
        let root = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("a"), value),
            ])))
            .unwrap();
        assert_ne!(document, builder.build(root).unwrap());

        let mut builder = PlistDocumentBuilder::new();
        let value = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let root = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("b"), value),
            ])))
            .unwrap();
        assert_ne!(document, builder.build(root).unwrap());

        let mut builder = PlistDocumentBuilder::new();
        let value = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![value])))
            .unwrap();
        assert_ne!(document, builder.build(root).unwrap());
    }

    #[test]
    fn unreachable_nodes_do_not_affect_structural_equality() {
        let mut builder = PlistDocumentBuilder::new();
        builder
            .add(PlistValue::String(PlistString::from_unicode("orphan")))
            .unwrap();
        let root = builder
            .add(PlistValue::Boolean(PlistBoolean::new(true)))
            .unwrap();
        let with_orphan = builder.build(root).unwrap();

        let mut builder = PlistDocumentBuilder::new();
        let root = builder
            .add(PlistValue::Boolean(PlistBoolean::new(true)))
            .unwrap();
        let without_orphan = builder.build(root).unwrap();

        assert_eq!(with_orphan, without_orphan);
        assert_eq!(hash_of(&with_orphan), hash_of(&without_orphan));
    }

    #[test]
    fn equal_documents_hash_equally() {
        let mut builder = PlistDocumentBuilder::new();
        let one = builder
            .add(PlistValue::Integer(PlistInteger::new(1)))
            .unwrap();
        let two = builder
            .add(PlistValue::Integer(PlistInteger::new(2)))
            .unwrap();
        let root = builder
            .add(PlistValue::Dict(PlistDict::from_entries(vec![
                PlistDictEntry::new(PlistKey::from_unicode("a"), one),
                PlistDictEntry::new(PlistKey::from_unicode("b"), two),
            ])))
            .unwrap();
        let document = builder.build(root).unwrap();
        assert_eq!(hash_of(&document), hash_of(&document.clone()));
        assert_eq!(document, document.clone());
    }

    #[test]
    fn out_of_bounds_references_are_rejected() {
        let mut builder = PlistDocumentBuilder::new();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![
                PlistValueRef::from_index(5),
            ])))
            .unwrap();
        let error = builder.build(root).unwrap_err();
        assert_eq!(
            error,
            PlistArenaError::ReferenceOutOfBounds {
                reference: PlistValueRef::from_index(5),
                node_count: 1,
            }
        );

        let mut builder = PlistDocumentBuilder::new();
        builder
            .add(PlistValue::Boolean(PlistBoolean::new(true)))
            .unwrap();
        let error = builder.build(PlistValueRef::from_index(7)).unwrap_err();
        assert_eq!(
            error,
            PlistArenaError::ReferenceOutOfBounds {
                reference: PlistValueRef::from_index(7),
                node_count: 1,
            }
        );
    }

    #[test]
    fn cycles_are_rejected() {
        let mut builder = PlistDocumentBuilder::new();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![
                PlistValueRef::from_index(1),
            ])))
            .unwrap();
        builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![root])))
            .unwrap();
        let error = builder.build(root).unwrap_err();
        assert_eq!(
            error,
            PlistArenaError::CycleDetected {
                node: PlistValueRef::from_index(0),
            }
        );
    }

    #[test]
    fn object_limit_is_enforced() {
        let limits = PlistArenaLimits {
            max_objects: 1,
            ..PlistArenaLimits::default()
        };
        let mut builder = PlistDocumentBuilder::with_limits(limits);
        builder
            .add(PlistValue::Boolean(PlistBoolean::new(true)))
            .unwrap();
        let error = builder
            .add(PlistValue::Boolean(PlistBoolean::new(false)))
            .unwrap_err();
        assert_eq!(error, PlistArenaError::ObjectLimitExceeded { limit: 1 });
    }

    #[test]
    fn container_depth_limit_is_enforced() {
        let limits = PlistArenaLimits {
            max_container_depth: 1,
            ..PlistArenaLimits::default()
        };
        let mut builder = PlistDocumentBuilder::with_limits(limits);
        let inner = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![])))
            .unwrap();
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![inner])))
            .unwrap();
        let error = builder.build(root).unwrap_err();
        assert_eq!(
            error,
            PlistArenaError::ContainerDepthLimitExceeded {
                node: root,
                limit: 1,
            }
        );

        let mut builder = PlistDocumentBuilder::with_limits(limits);
        let root = builder
            .add(PlistValue::Array(PlistArray::from_elements(vec![])))
            .unwrap();
        assert!(builder.build(root).is_ok());
    }
}
