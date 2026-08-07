//! `plist.binary@1` formation (RFC 0013 §2.2, §3, §5, §12).
//!
//! The parser reads the raw `bplist00` byte layout in one deterministic
//! forward pass: header, trailer, offset table, then the object table. The
//! mandatory integrity checks of RFC 0013 §5.11 run before any object is
//! decoded; a violated check makes the affected construct Recovered rather
//! than inventing facts. Object-table recovery is prefix-based: the first
//! object that fails any structural or value check cuts the proven prefix,
//! every proven object keeps its facts and native value, and all bytes from
//! the end of the last proven object to the offset table form one error
//! region. The native arena adds nodes in object-table order so arena indices
//! equal object indices; shared references and forward references resolve
//! through [`PlistValueRef`], and [`PlistDocumentBuilder::build`] rejects
//! cycles (Recovered, RFC 0013 §5.11) and container-depth violations (fatal,
//! RFC 0013 §12).
//!
//! Resource limits are enforced at the point each claim is read, before any
//! allocation, and every size arithmetic is checked (hard gate 4, RFC 0013
//! §12); a limit failure is always fatal and never masquerades as a Recovered
//! or Complete tree.
//!
//! The [`BinaryStructuralIndex`] partitions the source into the four
//! positional structures (header, object table, offset table, trailer) with
//! `error-region` covering unproven bytes and `padding` covering format-admitted
//! gaps between proven constructs; fine-grained per-object spans are
//! [`BinaryObjectFact`] facts, never region boundaries (RFC 0013 §2.2, §8.3).

use crate::PlistParseLimits;
use crate::native::{
    PlistArenaError, PlistArray, PlistBoolean, PlistData, PlistDate, PlistDict, PlistDictEntry,
    PlistDocument, PlistDocumentBuilder, PlistInteger, PlistKey, PlistReal, PlistString, PlistUid,
    PlistValue, PlistValueRef, RealWidth,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BinaryRegion, BinaryStructuralIndex, DocumentAuthority, FatalFormationFailure, FormationStatus,
    NodeRole, SourceLimits, SourceSnapshot, Span,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Exact `bplist00` header bytes (RFC 0013 §5.1).
const HEADER: [u8; 8] = *b"bplist00";
/// Minimum admissible source length: 8-byte header, at least one 1-byte
/// object, at least one 1-byte offset entry, and the 32-byte trailer
/// (RFC 0013 §2.2).
const MIN_SOURCE_BYTES: usize = 42;
/// Trailer byte length (RFC 0013 §5.10).
const TRAILER_BYTES: usize = 32;
/// Largest legal integer/offset/ref payload width in bytes (RFC 0013 §5.11).
const MAX_FIELD_WIDTH: u8 = 8;

/// One proven object-table entry fact (RFC 0013 §8.3 `plist.object-table@1`).
///
/// `index` is the object-table ordinal, `offset` the marker byte offset, and
/// `span` the exact half-open byte range of marker and payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryObjectFact {
    index: usize,
    offset: usize,
    marker: u8,
    span: Span,
}

impl BinaryObjectFact {
    /// Object-table ordinal.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Marker byte offset (equals the offset-table entry value).
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Marker byte; the low nibble preserves non-minimal width facts.
    #[must_use]
    pub const fn marker(self) -> u8 {
        self.marker
    }

    /// Exact marker-through-payload byte range.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }
}

/// One validated offset-table entry fact (RFC 0013 §8.3 `plist.object-offset@1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryOffsetFact {
    index: usize,
    offset: usize,
    span: Span,
}

impl BinaryOffsetFact {
    /// Object-table ordinal of this entry.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Decoded absolute file offset of the object's marker byte.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Exact byte range of this entry inside the offset table.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }
}

/// One decoded object reference of a proven container (RFC 0013 §8.3
/// `plist.object-refs@1`).
///
/// For dictionaries, keys occupy positions `0..count` and values
/// `count..2*count`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryObjectRefFact {
    owner: usize,
    position: usize,
    target: usize,
    span: Span,
}

impl BinaryObjectRefFact {
    /// Referencing object index.
    #[must_use]
    pub const fn owner(self) -> usize {
        self.owner
    }

    /// Ordinal of this reference within the owner's reference block.
    #[must_use]
    pub const fn position(self) -> usize {
        self.position
    }

    /// Decoded target object index.
    #[must_use]
    pub const fn target(self) -> usize {
        self.target
    }

    /// Exact byte range of this reference inside the owner's payload.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }
}

/// Trailer field facts (RFC 0013 §5.10, §8.3 `plist.trailer-facts@1` and
/// `plist.top-object@1`).
///
/// The raw field values are always recorded — they are bytes of the source —
/// while validity is carried by formation diagnostics and status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryTrailerFacts {
    sort_version: u8,
    offset_int_size: u8,
    object_ref_size: u8,
    num_objects: u64,
    top_object: u64,
    offset_table_offset: u64,
    span: Span,
}

impl BinaryTrailerFacts {
    /// `sortVersion` byte (0 or 1; canonical materialization writes 0).
    #[must_use]
    pub const fn sort_version(self) -> u8 {
        self.sort_version
    }

    /// `offsetIntSize` byte.
    #[must_use]
    pub const fn offset_int_size(self) -> u8 {
        self.offset_int_size
    }

    /// `objectRefSize` byte.
    #[must_use]
    pub const fn object_ref_size(self) -> u8 {
        self.object_ref_size
    }

    /// `numObjects` value.
    #[must_use]
    pub const fn num_objects(self) -> u64 {
        self.num_objects
    }

    /// `topObject` value (the native document root when proven).
    #[must_use]
    pub const fn top_object(self) -> u64 {
        self.top_object
    }

    /// `offsetTableOffset` value.
    #[must_use]
    pub const fn offset_table_offset(self) -> u64 {
        self.offset_table_offset
    }

    /// Exact byte range of the 32-byte trailer.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }
}

/// Complete binary structure facts of one parse (RFC 0013 §8.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryFacts {
    objects: Arc<[BinaryObjectFact]>,
    offsets: Arc<[BinaryOffsetFact]>,
    refs: Arc<[BinaryObjectRefFact]>,
    trailer: BinaryTrailerFacts,
}

impl BinaryFacts {
    /// Proven object facts in object-table order.
    #[must_use]
    pub fn objects(&self) -> &[BinaryObjectFact] {
        &self.objects
    }

    /// Validated offset-table entry facts in object-table order.
    #[must_use]
    pub fn offsets(&self) -> &[BinaryOffsetFact] {
        &self.offsets
    }

    /// Proven reference facts ordered by owner then position.
    #[must_use]
    pub fn refs(&self) -> &[BinaryObjectRefFact] {
        &self.refs
    }

    /// Trailer field facts.
    #[must_use]
    pub const fn trailer(&self) -> BinaryTrailerFacts {
        self.trailer
    }
}

/// One formed `plist.binary@1` document (RFC 0013 §3).
///
/// `Complete` requires exhaustive byte coverage under the Profile's grammar
/// and every configured limit. `Recovered` retains the immutable source,
/// exhaustive region coverage, ordered diagnostics, every independently
/// proven construct, and — when the native value graph is provable — the
/// native document; `document()` is `None` when the top object or a proven
/// reference reaches an unproven object, when the object table cannot be
/// located, or when the arena contains a reference cycle.
#[derive(Clone, Debug)]
pub struct PlistFormedBinary {
    source: Arc<SourceSnapshot>,
    /// Consumed by the M4 binary-structure query domain (RFC 0013 §8.3).
    #[allow(dead_code)]
    authority: DocumentAuthority,
    status: FormationStatus,
    diagnostics: Vec<Diagnostic>,
    document: Option<PlistDocument>,
    facts: BinaryFacts,
    structural: BinaryStructuralIndex,
    /// Consumed by the M4 query and edit domains for limit enforcement.
    #[allow(dead_code)]
    limits: PlistParseLimits,
}

impl PlistFormedBinary {
    /// Formation status.
    #[must_use]
    pub const fn status(&self) -> FormationStatus {
        self.status
    }

    /// Immutable raw binary source.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Exact original bytes; unmodified rendering is byte-exact.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Ordered diagnostics from formation.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Native value arena, when every value is provable.
    #[must_use]
    pub fn document(&self) -> Option<&PlistDocument> {
        self.document.as_ref()
    }

    /// Binary object/offset/reference/trailer facts.
    #[must_use]
    pub const fn facts(&self) -> &BinaryFacts {
        &self.facts
    }

    /// Exhaustive ordered region coverage of the raw bytes.
    #[must_use]
    pub fn structural_index(&self) -> &BinaryStructuralIndex {
        &self.structural
    }

    /// Snapshot-bound identity authority for issuing query handles (M4
    /// adaptation point).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        &self.authority
    }

    /// Limits applied during formation (M4 adaptation point).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn limits(&self) -> PlistParseLimits {
        self.limits
    }
}

/// Bounded ordered diagnostic recording with the house truncation marker.
struct DiagnosticSink {
    diagnostics: Vec<Diagnostic>,
    max: usize,
    occurrence: u64,
    truncated: bool,
}

impl DiagnosticSink {
    const fn new(max: usize) -> Self {
        Self {
            diagnostics: Vec::new(),
            max,
            occurrence: 0,
            truncated: false,
        }
    }

    fn push(&mut self, mut diagnostic: Diagnostic) {
        diagnostic.occurrence = self.occurrence;
        self.occurrence = self.occurrence.saturating_add(1);
        if self.diagnostics.len() < self.max {
            self.diagnostics.push(diagnostic);
        } else if !self.truncated {
            self.truncated = true;
            self.diagnostics.push(Diagnostic::new(
                "core.diagnostic.truncated@1",
                DiagnosticCategory::Resource,
                DiagnosticSeverity::Warning,
                None,
                self.occurrence,
            ));
        }
    }

    fn finish(mut self) -> Vec<Diagnostic> {
        Diagnostic::sort_deterministically(&mut self.diagnostics);
        self.diagnostics
    }
}

/// Decoded kind of one object, without its payload value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShapeKind {
    False,
    True,
    Integer { width: usize },
    Real { width: usize },
    Date,
    Data,
    AsciiString,
    Utf16String,
    Uid,
    Array,
    Dict,
}

impl ShapeKind {
    const fn is_string(self) -> bool {
        matches!(self, Self::AsciiString | Self::Utf16String)
    }
}

/// One decoded object-table reference with its exact byte span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RefTarget {
    target: usize,
    span: Span,
}

/// Structural facts of one object: kind, marker, byte extent, and refs.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectShape {
    kind: ShapeKind,
    marker: u8,
    offset: usize,
    extent: usize,
    count: usize,
    key_count: usize,
    payload_start: usize,
    refs: Vec<RefTarget>,
}

/// Raw trailer field values (RFC 0013 §5.10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawTrailer {
    unused: [u8; 5],
    sort_version: u8,
    offset_int_size: u8,
    object_ref_size: u8,
    num_objects: u64,
    top_object: u64,
    offset_table_offset: u64,
}

impl RawTrailer {
    fn read(bytes: &[u8]) -> Self {
        let start = bytes.len() - TRAILER_BYTES;
        Self {
            unused: [
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
                bytes[start + 4],
            ],
            sort_version: bytes[start + 5],
            offset_int_size: bytes[start + 6],
            object_ref_size: bytes[start + 7],
            num_objects: u64::from_be_bytes([
                bytes[start + 8],
                bytes[start + 9],
                bytes[start + 10],
                bytes[start + 11],
                bytes[start + 12],
                bytes[start + 13],
                bytes[start + 14],
                bytes[start + 15],
            ]),
            top_object: u64::from_be_bytes([
                bytes[start + 16],
                bytes[start + 17],
                bytes[start + 18],
                bytes[start + 19],
                bytes[start + 20],
                bytes[start + 21],
                bytes[start + 22],
                bytes[start + 23],
            ]),
            offset_table_offset: u64::from_be_bytes([
                bytes[start + 24],
                bytes[start + 25],
                bytes[start + 26],
                bytes[start + 27],
                bytes[start + 28],
                bytes[start + 29],
                bytes[start + 30],
                bytes[start + 31],
            ]),
        }
    }
}

/// Formation state for one binary source.
struct Parser {
    source: Arc<SourceSnapshot>,
    limits: PlistParseLimits,
    authority: DocumentAuthority,
    sink: DiagnosticSink,
    recovered: bool,
    uid_count: usize,
    extended_integers: usize,
    facts: usize,
}

/// Forms one `plist.binary@1` document from raw bytes (RFC 0013 §3).
///
/// The source is created as an opaque `Binary` snapshot; formation is
/// side-effect free and never resolves a UID, path, or external reference.
pub(crate) fn parse_binary(
    bytes: Arc<[u8]>,
    limits: PlistParseLimits,
) -> Result<PlistFormedBinary, FatalFormationFailure> {
    let source = Arc::new(
        SourceSnapshot::from_binary(
            bytes,
            SourceLimits {
                max_raw_bytes: limits.common.max_source_bytes,
                max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
                max_decoded_scalars: limits.max_decoded_scalars,
            },
        )
        .map_err(FatalFormationFailure::source_error)?,
    );
    let parser = Parser {
        source,
        limits,
        authority: DocumentAuthority::fresh(),
        sink: DiagnosticSink::new(limits.common.max_diagnostics),
        recovered: false,
        uid_count: 0,
        extended_integers: 0,
        facts: 0,
    };
    parser.parse()
}

impl Parser {
    fn parse(mut self) -> Result<PlistFormedBinary, FatalFormationFailure> {
        let source = Arc::clone(&self.source);
        let bytes = source.bytes();
        let len = bytes.len();
        if len < MIN_SOURCE_BYTES {
            return Err(fatal(
                "plist.binary.minimum-size@1",
                DiagnosticCategory::Syntax,
                Some(DiagnosticLocation {
                    snapshot: Some(self.authority.identity().as_u64()),
                    start_byte: 0,
                    end_byte: len as u64,
                }),
                &[],
            ));
        }
        let trailer_start = len - TRAILER_BYTES;

        // Header (RFC 0013 §5.1): any other version string is Recovered, and
        // formation continues so the remaining constructs are still judged.
        let header_ok = bytes[..HEADER.len()] == HEADER;
        if !header_ok {
            self.recover(
                "plist.binary.header@1",
                Some(self.loc(0, 8)?),
                &[("expected", String::from("bplist00"))],
            );
        }

        // Trailer facts are bytes of the source and are always recorded.
        let raw = RawTrailer::read(bytes);
        self.record_fact()?;
        let trailer_facts = BinaryTrailerFacts {
            sort_version: raw.sort_version,
            offset_int_size: raw.offset_int_size,
            object_ref_size: raw.object_ref_size,
            num_objects: raw.num_objects,
            top_object: raw.top_object,
            offset_table_offset: raw.offset_table_offset,
            span: self.span(trailer_start, len)?,
        };

        // Mandatory integrity checks run before any object is decoded
        // (RFC 0013 §5.11).
        let trailer_ok = self.validate_trailer(&raw)?;
        if !trailer_ok {
            // The object table cannot be located; the middle bytes are one
            // error region and no native document exists.
            let regions = vec![
                self.region(0, if header_ok { "header" } else { "error-region" }, 0, 8)?,
                self.region(1, "error-region", 8, trailer_start)?,
                self.region(2, "error-region", trailer_start, len)?,
            ];
            return self.finish(
                None,
                BinaryFacts {
                    objects: Arc::new([]),
                    offsets: Arc::new([]),
                    refs: Arc::new([]),
                    trailer: trailer_facts,
                },
                regions,
            );
        }

        let offset_table_offset = to_usize(raw.offset_table_offset)?;
        let num_objects = to_usize(raw.num_objects)?;
        let offset_int_size = usize::from(raw.offset_int_size);
        let object_ref_size = usize::from(raw.object_ref_size);
        let table_bytes = checked_mul(num_objects, offset_int_size)?;
        if table_bytes > self.limits.max_offset_table_bytes {
            return Err(fatal_limit(
                "offset-table-bytes",
                table_bytes,
                self.limits.max_offset_table_bytes,
            ));
        }

        let (offset_facts, object_offsets, entry_cut) =
            self.read_offset_table(offset_table_offset, num_objects, offset_int_size)?;
        let (shapes, shape_cut) = self.scan_objects(
            &object_offsets,
            entry_cut,
            offset_table_offset,
            object_ref_size,
            num_objects,
        )?;
        let cut = self.verify_dict_keys(&shapes, shape_cut);

        // Native document eligibility: the top object and every reference of
        // a proven object must stay inside the proven prefix.
        let top_object = to_usize(raw.top_object)?;
        let mut native_unproven = false;
        if top_object >= cut {
            self.recover(
                "plist.binary.unproven-top-object@1",
                Some(self.loc(trailer_start + 16, trailer_start + 24)?),
                &[("top-object", top_object.to_string())],
            );
            native_unproven = true;
        }
        if let Some((owner, bad)) = shapes[..cut].iter().enumerate().find_map(|(owner, shape)| {
            shape
                .refs
                .iter()
                .find(|reference| reference.target >= cut)
                .map(|reference| (owner, reference))
        }) {
            self.recover(
                "plist.binary.unproven-reference@1",
                Some(bad.span.diagnostic_location()),
                &[
                    ("owner", owner.to_string()),
                    ("target", bad.target.to_string()),
                ],
            );
            native_unproven = true;
        }

        let document = if native_unproven {
            None
        } else {
            let values = self.build_values(&shapes, cut)?;
            let mut builder = PlistDocumentBuilder::with_limits(self.limits.arena_limits());
            for value in values {
                builder.add(value).map_err(|error| match error {
                    PlistArenaError::ObjectLimitExceeded { limit } => {
                        fatal_limit("object-count", cut, limit)
                    }
                    _ => internal_failure(),
                })?;
            }
            match builder.build(PlistValueRef::from_index(top_object)) {
                Ok(document) => Some(document),
                Err(PlistArenaError::CycleDetected { .. }) => {
                    self.recover("plist.binary.cycle@1", None, &[]);
                    None
                }
                Err(PlistArenaError::ContainerDepthLimitExceeded { node, limit }) => {
                    return Err(fatal_limit("container-depth", node.index(), limit));
                }
                Err(PlistArenaError::ObjectLimitExceeded { .. }) => return Err(internal_failure()),
                Err(PlistArenaError::ReferenceOutOfBounds { .. }) => {
                    return Err(internal_failure());
                }
            }
        };

        // Facts of the proven prefix (RFC 0013 §8.3).
        let mut objects = Vec::with_capacity(cut);
        for (index, shape) in shapes[..cut].iter().enumerate() {
            self.record_fact()?;
            objects.push(BinaryObjectFact {
                index,
                offset: shape.offset,
                marker: shape.marker,
                span: self.span(shape.offset, checked_add(shape.offset, shape.extent)?)?,
            });
        }
        let mut refs = Vec::new();
        for (owner, shape) in shapes[..cut].iter().enumerate() {
            for (position, reference) in shape.refs.iter().enumerate() {
                self.record_fact()?;
                refs.push(BinaryObjectRefFact {
                    owner,
                    position,
                    target: reference.target,
                    span: reference.span,
                });
            }
        }
        let facts = BinaryFacts {
            objects: Arc::from(objects),
            offsets: Arc::from(offset_facts),
            refs: Arc::from(refs),
            trailer: trailer_facts,
        };

        // Exhaustive region coverage: positional structures, proven parts of
        // the object table, error regions for unproven bytes, and padding for
        // format-admitted gaps.
        let mut regions = Vec::new();
        regions.push(self.region(0, if header_ok { "header" } else { "error-region" }, 0, 8)?);
        if cut > 0 {
            let last_end = checked_add(shapes[cut - 1].offset, shapes[cut - 1].extent)?;
            regions.push(self.region(1, "object-table", 8, last_end)?);
            if cut < num_objects {
                if last_end < offset_table_offset {
                    regions.push(self.region(2, "error-region", last_end, offset_table_offset)?);
                }
            } else if last_end < offset_table_offset {
                regions.push(self.region(2, "padding", last_end, offset_table_offset)?);
            }
        } else if 8 < offset_table_offset {
            regions.push(self.region(1, "error-region", 8, offset_table_offset)?);
        }
        regions.push(self.region(
            regions.len(),
            "offset-table",
            offset_table_offset,
            checked_add(offset_table_offset, table_bytes)?,
        )?);
        regions.push(self.region(regions.len(), "trailer", trailer_start, len)?);

        self.finish(document, facts, regions)
    }

    fn finish(
        self,
        document: Option<PlistDocument>,
        facts: BinaryFacts,
        regions: Vec<BinaryRegion>,
    ) -> Result<PlistFormedBinary, FatalFormationFailure> {
        let error_regions = regions
            .iter()
            .filter(|region| region.kind() == "error-region")
            .count();
        if error_regions > self.limits.max_recovery_regions {
            return Err(fatal_limit(
                "recovery-regions",
                error_regions,
                self.limits.max_recovery_regions,
            ));
        }
        let structural =
            BinaryStructuralIndex::new(self.authority.identity(), self.source.len(), regions)
                .map_err(|_| {
                    fatal(
                        "plist.binary.coverage@1",
                        DiagnosticCategory::Syntax,
                        None,
                        &[],
                    )
                })?;
        let status = if self.recovered {
            FormationStatus::Recovered
        } else {
            FormationStatus::Complete
        };
        Ok(PlistFormedBinary {
            source: self.source,
            authority: self.authority,
            status,
            diagnostics: self.sink.finish(),
            document,
            facts,
            structural,
            limits: self.limits,
        })
    }

    /// Validates the mandatory trailer checks (RFC 0013 §5.11) and records a
    /// `plist.binary.trailer@1` diagnostic per violated check.
    fn validate_trailer(&mut self, raw: &RawTrailer) -> Result<bool, FatalFormationFailure> {
        let mut ok = true;
        let len = self.source.len();
        let start = len - TRAILER_BYTES;

        if raw.unused != [0; 5] {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start, start + 5)?),
                &[("check", String::from("unused-bytes"))],
            );
            ok = false;
        }
        if !matches!(raw.sort_version, 0 | 1) {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 5, start + 6)?),
                &[
                    ("check", String::from("sort-version")),
                    ("sort-version", format!("{:#04x}", raw.sort_version)),
                ],
            );
            ok = false;
        }
        if !(1..=MAX_FIELD_WIDTH).contains(&raw.offset_int_size) {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 6, start + 7)?),
                &[
                    ("check", String::from("offset-int-size")),
                    ("offset-int-size", raw.offset_int_size.to_string()),
                ],
            );
            ok = false;
        } else if usize::from(raw.offset_int_size) > self.limits.max_offset_int_size {
            return Err(fatal_limit(
                "offset-int-size",
                usize::from(raw.offset_int_size),
                self.limits.max_offset_int_size,
            ));
        }
        if !(1..=MAX_FIELD_WIDTH).contains(&raw.object_ref_size) {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 7, start + 8)?),
                &[
                    ("check", String::from("object-ref-size")),
                    ("object-ref-size", raw.object_ref_size.to_string()),
                ],
            );
            ok = false;
        } else if usize::from(raw.object_ref_size) > self.limits.max_object_ref_size {
            return Err(fatal_limit(
                "object-ref-size",
                usize::from(raw.object_ref_size),
                self.limits.max_object_ref_size,
            ));
        }
        if raw.num_objects == 0 {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 8, start + 16)?),
                &[("check", String::from("num-objects"))],
            );
            ok = false;
        } else if raw.num_objects > u64::try_from(self.limits.max_object_count).unwrap_or(u64::MAX)
        {
            let observed = usize::try_from(raw.num_objects).unwrap_or(usize::MAX);
            return Err(fatal_limit(
                "object-count",
                observed,
                self.limits.max_object_count,
            ));
        }
        if raw.top_object >= raw.num_objects {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 16, start + 24)?),
                &[
                    ("check", String::from("top-object")),
                    ("top-object", raw.top_object.to_string()),
                ],
            );
            ok = false;
        }
        let max_table_offset = u64::try_from(len - TRAILER_BYTES).unwrap_or(u64::MAX);
        if !(9..max_table_offset).contains(&raw.offset_table_offset) {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start + 24, start + 32)?),
                &[
                    ("check", String::from("offset-table-offset")),
                    ("offset-table-offset", raw.offset_table_offset.to_string()),
                ],
            );
            ok = false;
        }
        if (1..=MAX_FIELD_WIDTH).contains(&raw.offset_int_size)
            && raw.offset_int_size < MAX_FIELD_WIDTH
        {
            let capacity = 1_u64 << (8 * raw.offset_int_size);
            if capacity <= raw.offset_table_offset {
                self.recover(
                    "plist.binary.trailer@1",
                    Some(self.loc(start + 24, start + 32)?),
                    &[("check", String::from("offset-int-size-sufficiency"))],
                );
                ok = false;
            }
        }
        if (1..=MAX_FIELD_WIDTH).contains(&raw.object_ref_size)
            && raw.object_ref_size < MAX_FIELD_WIDTH
        {
            let capacity = 1_u64 << (8 * raw.object_ref_size);
            if capacity <= raw.num_objects {
                self.recover(
                    "plist.binary.trailer@1",
                    Some(self.loc(start + 7, start + 8)?),
                    &[("check", String::from("object-ref-size-sufficiency"))],
                );
                ok = false;
            }
        }
        let table_bytes = checked_mul_u64(raw.num_objects, u64::from(raw.offset_int_size))?;
        let expected = checked_add_u64(raw.offset_table_offset, table_bytes)?;
        let expected = checked_add_u64(expected, TRAILER_BYTES as u64)?;
        if expected != u64::try_from(len).unwrap_or(u64::MAX) {
            self.recover(
                "plist.binary.trailer@1",
                Some(self.loc(start, len)?),
                &[
                    ("check", String::from("total-length")),
                    ("expected", expected.to_string()),
                    ("observed", len.to_string()),
                ],
            );
            ok = false;
        }
        Ok(ok)
    }

    /// Reads and validates the offset table in entry order (RFC 0013 §5.10,
    /// §5.11). The first invalid entry cuts the proven prefix.
    fn read_offset_table(
        &mut self,
        offset_table_offset: usize,
        num_objects: usize,
        offset_int_size: usize,
    ) -> Result<(Vec<BinaryOffsetFact>, Vec<usize>, usize), FatalFormationFailure> {
        let source = Arc::clone(&self.source);
        let bytes = source.bytes();
        let mut facts = Vec::with_capacity(num_objects);
        let mut offsets = Vec::with_capacity(num_objects);
        let mut cut = num_objects;
        for index in 0..num_objects {
            let start = checked_add(offset_table_offset, checked_mul(index, offset_int_size)?)?;
            let end = checked_add(start, offset_int_size)?;
            if end > bytes.len() {
                // Defensive: the entry window must stay inside the source.
                // The trailer's total-length check already bounds the table
                // before the trailer window; this check keeps the read
                // locally safe without that chain and cuts the proven prefix
                // exactly like a malformed entry value (RFC 0013 §5.11).
                self.recover(
                    "plist.binary.offset-table@1",
                    Some(self.loc(start.min(bytes.len() - 1), bytes.len())?),
                    &[("index", index.to_string()), ("end", end.to_string())],
                );
                cut = index;
                break;
            }
            let value = read_be_u64(bytes, start, offset_int_size)?;
            let value_usize = to_usize(value)?;
            if value_usize < 8 || value_usize >= offset_table_offset {
                self.recover(
                    "plist.binary.offset-table@1",
                    Some(self.loc(start, end)?),
                    &[
                        ("index", index.to_string()),
                        ("value", format!("{value:#x}")),
                    ],
                );
                cut = index;
                break;
            }
            self.record_fact()?;
            facts.push(BinaryOffsetFact {
                index,
                offset: value_usize,
                span: self.span(start, end)?,
            });
            offsets.push(value_usize);
        }
        Ok((facts, offsets, cut))
    }

    /// Scans objects in index order and returns the proven shapes plus the
    /// prefix cut (RFC 0013 §5.2-5.9).
    fn scan_objects(
        &mut self,
        object_offsets: &[usize],
        mut cut: usize,
        offset_table_offset: usize,
        object_ref_size: usize,
        num_objects: usize,
    ) -> Result<(Vec<ObjectShape>, usize), FatalFormationFailure> {
        let mut shapes = Vec::with_capacity(cut);
        for (index, offset) in object_offsets.iter().take(cut).copied().enumerate() {
            let Some(shape) = self.scan_object(
                index,
                offset,
                offset_table_offset,
                object_ref_size,
                num_objects,
            )?
            else {
                cut = index;
                break;
            };
            shapes.push(shape);
        }
        Ok((shapes, cut))
    }

    /// Decodes one object's marker, size, extent, and references; `None` is a
    /// fault that cuts the proven prefix at `index`.
    fn scan_object(
        &mut self,
        index: usize,
        offset: usize,
        table_end: usize,
        object_ref_size: usize,
        num_objects: usize,
    ) -> Result<Option<ObjectShape>, FatalFormationFailure> {
        let source = Arc::clone(&self.source);
        let bytes = source.bytes();
        if offset >= bytes.len() {
            // Defensive: the marker byte must exist inside the source. The
            // offset-table validation already bounds entry values below the
            // offset table and the trailer bounds that below the trailer
            // window; this check keeps the marker read locally safe without
            // that chain and cuts the proven prefix exactly like a malformed
            // offset entry (RFC 0013 §5.11).
            self.recover(
                "plist.binary.offset-table@1",
                Some(self.loc(bytes.len() - 1, bytes.len())?),
                &[
                    ("index", index.to_string()),
                    ("value", format!("{offset:#x}")),
                ],
            );
            return Ok(None);
        }
        let marker = bytes[offset];
        let marker_span = self.span(offset, offset + 1)?;
        let (kind, count, ext_bytes) = match marker {
            0x08 => (ShapeKind::False, 0, 0),
            0x09 => (ShapeKind::True, 0, 0),
            0x10..=0x13 => (
                ShapeKind::Integer {
                    width: 1 << (marker & 0x0F),
                },
                0,
                0,
            ),
            0x22 => (ShapeKind::Real { width: 4 }, 0, 0),
            0x23 => (ShapeKind::Real { width: 8 }, 0, 0),
            0x33 => (ShapeKind::Date, 0, 0),
            0x40..=0x4F => {
                let Some((count, ext)) = self.sized_count(marker, offset, index)? else {
                    return Ok(None);
                };
                if count > self.limits.max_data_bytes {
                    return Err(fatal_limit("data-bytes", count, self.limits.max_data_bytes));
                }
                (ShapeKind::Data, count, ext)
            }
            0x50..=0x5F => {
                let Some((count, ext)) = self.sized_count(marker, offset, index)? else {
                    return Ok(None);
                };
                if count > self.limits.max_string_code_units {
                    return Err(fatal_limit(
                        "string-code-units",
                        count,
                        self.limits.max_string_code_units,
                    ));
                }
                (ShapeKind::AsciiString, count, ext)
            }
            0x60..=0x6F => {
                let Some((count, ext)) = self.sized_count(marker, offset, index)? else {
                    return Ok(None);
                };
                if count > self.limits.max_string_code_units {
                    return Err(fatal_limit(
                        "string-code-units",
                        count,
                        self.limits.max_string_code_units,
                    ));
                }
                (ShapeKind::Utf16String, count, ext)
            }
            0x80..=0x8F => (ShapeKind::Uid, usize::from(marker & 0x0F) + 1, 0),
            0xA0..=0xAF => {
                let Some((count, ext)) = self.sized_count(marker, offset, index)? else {
                    return Ok(None);
                };
                if count > self.limits.max_array_elements {
                    return Err(fatal_limit(
                        "array-elements",
                        count,
                        self.limits.max_array_elements,
                    ));
                }
                (ShapeKind::Array, count, ext)
            }
            0xD0..=0xDF => {
                let Some((count, ext)) = self.sized_count(marker, offset, index)? else {
                    return Ok(None);
                };
                if count > self.limits.max_dict_entries {
                    return Err(fatal_limit(
                        "dict-entries",
                        count,
                        self.limits.max_dict_entries,
                    ));
                }
                (ShapeKind::Dict, count, ext)
            }
            _ => {
                self.recover(
                    "plist.binary.marker@1",
                    Some(marker_span.diagnostic_location()),
                    &[
                        ("marker", format!("{marker:#04x}")),
                        ("object", index.to_string()),
                    ],
                );
                return Ok(None);
            }
        };
        let payload_start = checked_add(checked_add(offset, 1)?, ext_bytes)?;
        let payload_len = match kind {
            ShapeKind::Uid
            | ShapeKind::Data
            | ShapeKind::AsciiString
            | ShapeKind::False
            | ShapeKind::True => count,
            ShapeKind::Integer { width } | ShapeKind::Real { width } => width,
            ShapeKind::Date => 8,
            ShapeKind::Utf16String => checked_mul(count, 2)?,
            ShapeKind::Array => checked_mul(count, object_ref_size)?,
            ShapeKind::Dict => checked_mul(checked_mul(count, 2)?, object_ref_size)?,
        };
        let extent = checked_add(checked_add(1, ext_bytes)?, payload_len)?;
        let end = checked_add(offset, extent)?;
        if end > table_end {
            self.recover(
                "plist.binary.extent@1",
                Some(marker_span.diagnostic_location()),
                &[
                    ("object", index.to_string()),
                    ("end", end.to_string()),
                    ("table-end", table_end.to_string()),
                ],
            );
            return Ok(None);
        }

        // Value-validity checks that cut the prefix here (RFC 0013 §5.5-5.8).
        match kind {
            ShapeKind::AsciiString => {
                if let Some(at) = bytes[payload_start..end]
                    .iter()
                    .position(|byte| *byte >= 0x80)
                {
                    self.recover(
                        "plist.binary.string@1",
                        Some(self.loc(payload_start + at, payload_start + at + 1)?),
                        &[
                            ("byte", format!("{:#04x}", bytes[payload_start + at])),
                            ("object", index.to_string()),
                        ],
                    );
                    return Ok(None);
                }
            }
            ShapeKind::Date => {
                let seconds = f64::from_bits(read_be_u64(bytes, payload_start, 8)?);
                if !seconds.is_finite() {
                    self.recover(
                        "plist.binary.date@1",
                        Some(self.loc(payload_start, checked_add(payload_start, 8)?)?),
                        &[("object", index.to_string())],
                    );
                    return Ok(None);
                }
            }
            ShapeKind::Uid => {
                let value = read_be_u64(bytes, payload_start, count)?;
                if value > u64::from(u32::MAX) {
                    self.recover(
                        "plist.binary.uid@1",
                        Some(self.loc(payload_start, checked_add(payload_start, count)?)?),
                        &[
                            ("value", format!("{value:#x}")),
                            ("object", index.to_string()),
                        ],
                    );
                    return Ok(None);
                }
                self.uid_count = checked_add(self.uid_count, 1)?;
                if self.uid_count > self.limits.max_uid_count {
                    return Err(fatal_limit(
                        "uid-count",
                        self.uid_count,
                        self.limits.max_uid_count,
                    ));
                }
            }
            _ => {}
        }

        // Container references (RFC 0013 §5.9).
        let mut refs = Vec::new();
        if matches!(kind, ShapeKind::Array | ShapeKind::Dict) {
            let total = if matches!(kind, ShapeKind::Dict) {
                checked_mul(count, 2)?
            } else {
                count
            };
            for position in 0..total {
                let ref_start =
                    checked_add(payload_start, checked_mul(position, object_ref_size)?)?;
                let ref_end = checked_add(ref_start, object_ref_size)?;
                let ref_span = self.span(ref_start, ref_end)?;
                let target = to_usize(read_be_u64(bytes, ref_start, object_ref_size)?)?;
                if target >= num_objects {
                    self.recover(
                        "plist.binary.reference@1",
                        Some(ref_span.diagnostic_location()),
                        &[("owner", index.to_string()), ("target", target.to_string())],
                    );
                    return Ok(None);
                }
                refs.push(RefTarget {
                    target,
                    span: ref_span,
                });
            }
            self.facts = checked_add(self.facts, total)?;
            if self.facts > self.limits.max_binary_facts {
                return Err(fatal_limit(
                    "binary-facts",
                    self.facts,
                    self.limits.max_binary_facts,
                ));
            }
        }
        Ok(Some(ObjectShape {
            kind,
            marker,
            offset,
            extent,
            count,
            key_count: if matches!(kind, ShapeKind::Dict) {
                count
            } else {
                0
            },
            payload_start,
            refs,
        }))
    }

    /// Reads a sized construct's count, honoring the extended-size integer
    /// rule (RFC 0013 §5.4); `None` is a fault.
    fn sized_count(
        &mut self,
        marker: u8,
        object_offset: usize,
        index: usize,
    ) -> Result<Option<(usize, usize)>, FatalFormationFailure> {
        let nibble = usize::from(marker & 0x0F);
        if nibble != 0x0F {
            return Ok(Some((nibble, 0)));
        }
        self.read_count(object_offset, index)
    }

    /// Reads one extended-size integer and enforces its limits (RFC 0013
    /// §5.4, §12); `None` is a fault.
    fn read_count(
        &mut self,
        object_offset: usize,
        index: usize,
    ) -> Result<Option<(usize, usize)>, FatalFormationFailure> {
        let source = Arc::clone(&self.source);
        let bytes = source.bytes();
        if object_offset + 1 >= bytes.len() {
            // Defensive: the extended-size marker must exist inside the
            // source; the same local bounds reasoning as the object-marker
            // read applies, and the recovery cuts the proven prefix exactly
            // like a malformed offset entry (RFC 0013 §5.11).
            self.recover(
                "plist.binary.offset-table@1",
                Some(self.loc(bytes.len() - 1, bytes.len())?),
                &[
                    ("index", index.to_string()),
                    ("value", format!("{object_offset:#x}")),
                ],
            );
            return Ok(None);
        }
        let marker = bytes[object_offset + 1];
        if !(0x10..=0x13).contains(&marker) {
            self.recover(
                "plist.binary.extended-size@1",
                Some(self.loc(object_offset + 1, object_offset + 2)?),
                &[
                    ("marker", format!("{marker:#04x}")),
                    ("object", index.to_string()),
                ],
            );
            return Ok(None);
        }
        let width = 1usize << (marker & 0x0F);
        let value = read_be_u64(bytes, object_offset + 2, width)?;
        if value > u64::try_from(self.limits.max_extended_size_value).unwrap_or(u64::MAX) {
            let observed = usize::try_from(value).unwrap_or(usize::MAX);
            return Err(fatal_limit(
                "extended-size-value",
                observed,
                self.limits.max_extended_size_value,
            ));
        }
        self.extended_integers = checked_add(self.extended_integers, 1)?;
        if self.extended_integers > self.limits.max_extended_size_integers {
            return Err(fatal_limit(
                "extended-size-integers",
                self.extended_integers,
                self.limits.max_extended_size_integers,
            ));
        }
        Ok(Some((to_usize(value)?, checked_add(1, width)?)))
    }

    /// Verifies that every dictionary key target is a string object (RFC 0013
    /// §5.9); the first violating dictionary cuts the proven prefix.
    fn verify_dict_keys(&mut self, shapes: &[ObjectShape], cut: usize) -> usize {
        for index in 0..cut {
            let shape = &shapes[index];
            if shape.kind != ShapeKind::Dict {
                continue;
            }
            for key_ref in &shape.refs[..shape.key_count] {
                if key_ref.target >= cut {
                    // The target is unproven; the unproven-reference rule
                    // decides native-document eligibility.
                    continue;
                }
                if !shapes[key_ref.target].kind.is_string() {
                    self.recover(
                        "plist.binary.non-string-key@1",
                        Some(key_ref.span.diagnostic_location()),
                        &[
                            ("key-object", key_ref.target.to_string()),
                            ("object", index.to_string()),
                        ],
                    );
                    return index;
                }
            }
        }
        cut
    }

    /// Builds native values in object-table order so arena indices equal
    /// object indices; the caller guarantees every reference stays inside the
    /// proven prefix and every key target is a string.
    fn build_values(
        &mut self,
        shapes: &[ObjectShape],
        cut: usize,
    ) -> Result<Vec<PlistValue>, FatalFormationFailure> {
        let bytes = self.source.bytes();
        let mut values = Vec::with_capacity(cut);
        for shape in shapes.iter().take(cut) {
            let value = match shape.kind {
                ShapeKind::False => PlistValue::Boolean(PlistBoolean::new(false)),
                ShapeKind::True => PlistValue::Boolean(PlistBoolean::new(true)),
                ShapeKind::Integer { width } => PlistValue::Integer(PlistInteger::new(
                    self.read_integer(shape.payload_start, width)?,
                )),
                ShapeKind::Real { width } => {
                    PlistValue::Real(self.read_real(shape.payload_start, width))
                }
                ShapeKind::Date => {
                    let seconds = f64::from_bits(read_be_u64(bytes, shape.payload_start, 8)?);
                    match PlistDate::from_seconds(seconds) {
                        Ok(date) => PlistValue::Date(date),
                        Err(_) => return Err(internal_failure()),
                    }
                }
                ShapeKind::Data => PlistValue::Data(PlistData::from_bytes(Arc::<[u8]>::from(
                    &bytes[shape.payload_start..shape.payload_start + shape.count],
                ))),
                ShapeKind::AsciiString => PlistValue::String(PlistString::from_code_units(
                    bytes[shape.payload_start..shape.payload_start + shape.count]
                        .iter()
                        .map(|byte| u16::from(*byte))
                        .collect::<Vec<_>>(),
                )),
                ShapeKind::Utf16String => {
                    let mut units = Vec::with_capacity(shape.count);
                    let mut at = shape.payload_start;
                    for _ in 0..shape.count {
                        units.push(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
                        at += 2;
                    }
                    PlistValue::String(PlistString::from_code_units(units))
                }
                ShapeKind::Uid => PlistValue::Uid(PlistUid::new(read_be_u64(
                    bytes,
                    shape.payload_start,
                    shape.count,
                )? as u32)),
                ShapeKind::Array => PlistValue::Array(PlistArray::from_elements(
                    shape
                        .refs
                        .iter()
                        .map(|reference| PlistValueRef::from_index(reference.target))
                        .collect::<Vec<_>>(),
                )),
                ShapeKind::Dict => PlistValue::Dict(PlistDict::from_entries(vec![])),
            };
            values.push(value);
        }

        // Dictionary entries need the key target's string content, which is
        // only complete after every node exists; forward key references are
        // therefore materialized in a second pass.
        for index in 0..cut {
            let shape = &shapes[index];
            if shape.kind != ShapeKind::Dict {
                continue;
            }
            let mut entries = Vec::with_capacity(shape.key_count);
            let mut groups: HashMap<PlistKey, usize> = HashMap::new();
            for (position, key_ref) in shape.refs[..shape.key_count].iter().enumerate() {
                let key_string = match values[key_ref.target].as_string() {
                    Some(string) => string.clone(),
                    None => return Err(internal_failure()),
                };
                let key = PlistKey::from_string(key_string);
                let group = groups.entry(key.clone()).or_insert(0);
                *group = checked_add(*group, 1)?;
                if *group > self.limits.max_duplicate_key_group_members {
                    return Err(fatal_limit(
                        "duplicate-key-group",
                        *group,
                        self.limits.max_duplicate_key_group_members,
                    ));
                }
                entries.push(PlistDictEntry::new(
                    key,
                    PlistValueRef::from_index(shape.refs[shape.key_count + position].target),
                ));
            }
            values[index] = PlistValue::Dict(PlistDict::from_entries(entries));
        }
        Ok(values)
    }

    fn read_integer(
        &self,
        payload_start: usize,
        width: usize,
    ) -> Result<i64, FatalFormationFailure> {
        let bytes = self.source.bytes();
        if width < 8 {
            // 1-, 2-, and 4-byte integers are unsigned (RFC 0013 §5.3).
            let value = read_be_u64(bytes, payload_start, width)?;
            i64::try_from(value).map_err(|_| internal_failure())
        } else {
            // 8-byte integers are signed two's complement (RFC 0013 §5.3).
            let mut raw = [0_u8; 8];
            raw.copy_from_slice(&bytes[payload_start..payload_start + 8]);
            Ok(i64::from_be_bytes(raw))
        }
    }

    fn read_real(&self, payload_start: usize, width: usize) -> PlistReal {
        let bytes = self.source.bytes();
        match width {
            4 => PlistReal::from_bits(
                RealWidth::Float32,
                u64::from(u32::from_be_bytes([
                    bytes[payload_start],
                    bytes[payload_start + 1],
                    bytes[payload_start + 2],
                    bytes[payload_start + 3],
                ])),
            ),
            _ => PlistReal::from_bits(
                RealWidth::Float64,
                u64::from_be_bytes([
                    bytes[payload_start],
                    bytes[payload_start + 1],
                    bytes[payload_start + 2],
                    bytes[payload_start + 3],
                    bytes[payload_start + 4],
                    bytes[payload_start + 5],
                    bytes[payload_start + 6],
                    bytes[payload_start + 7],
                ]),
            ),
        }
    }

    /// Records one structural fact against the binary-facts limit.
    fn record_fact(&mut self) -> Result<(), FatalFormationFailure> {
        self.facts = checked_add(self.facts, 1)?;
        if self.facts > self.limits.max_binary_facts {
            return Err(fatal_limit(
                "binary-facts",
                self.facts,
                self.limits.max_binary_facts,
            ));
        }
        Ok(())
    }

    /// Records one recovery diagnostic and marks the parse Recovered.
    fn recover(
        &mut self,
        code: &'static str,
        location: Option<DiagnosticLocation>,
        arguments: &[(&'static str, String)],
    ) {
        self.recovered = true;
        let mut diagnostic = Diagnostic::new(
            code,
            DiagnosticCategory::Syntax,
            DiagnosticSeverity::Error,
            location,
            0,
        );
        for (name, value) in arguments {
            diagnostic
                .arguments
                .insert((*name).to_owned(), value.clone());
        }
        self.sink.push(diagnostic);
    }

    fn span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        self.authority
            .span(start, end)
            .map_err(|_| coverage_failure())
    }

    fn loc(&self, start: usize, end: usize) -> Result<DiagnosticLocation, FatalFormationFailure> {
        Ok(self.span(start, end)?.diagnostic_location())
    }

    fn region(
        &self,
        index: usize,
        kind: &'static str,
        start: usize,
        end: usize,
    ) -> Result<BinaryRegion, FatalFormationFailure> {
        Ok(BinaryRegion::new(
            self.authority
                .node_ref(index as u64, NodeRole::BinaryRegion),
            self.span(start, end)?,
            kind,
        ))
    }
}

fn read_be_u64(bytes: &[u8], start: usize, width: usize) -> Result<u64, FatalFormationFailure> {
    // The read window must stay inside the source. Callers pre-validate
    // their windows (offset-table entries against the trailer total-length
    // check, payloads against the object extent check); this check keeps
    // every read locally safe without relying on those chains and fails
    // fatally like any other size-arithmetic violation (RFC 0013 §12, hard
    // gate 4).
    let end = start.checked_add(width).ok_or_else(overflow_failure)?;
    if end > bytes.len() {
        return Err(overflow_failure());
    }
    let mut value = 0_u64;
    for index in 0..width {
        value =
            value.checked_shl(8).ok_or_else(overflow_failure)? | u64::from(bytes[start + index]);
    }
    Ok(value)
}

fn to_usize(value: u64) -> Result<usize, FatalFormationFailure> {
    usize::try_from(value).map_err(|_| overflow_failure())
}

fn checked_add(left: usize, right: usize) -> Result<usize, FatalFormationFailure> {
    left.checked_add(right).ok_or_else(overflow_failure)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, FatalFormationFailure> {
    left.checked_mul(right).ok_or_else(overflow_failure)
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, FatalFormationFailure> {
    left.checked_add(right).ok_or_else(overflow_failure)
}

fn checked_mul_u64(left: u64, right: u64) -> Result<u64, FatalFormationFailure> {
    left.checked_mul(right).ok_or_else(overflow_failure)
}

/// Host-size or arithmetic overflow: a fatal condition (RFC 0013 §3, hard
/// gate 4).
fn overflow_failure() -> FatalFormationFailure {
    fatal(
        "plist.binary.overflow@1",
        DiagnosticCategory::Resource,
        None,
        &[],
    )
}

/// Unreachable internal state: defensive fatal with no panicking path.
fn internal_failure() -> FatalFormationFailure {
    fatal(
        "plist.binary.internal@1",
        DiagnosticCategory::Resource,
        None,
        &[],
    )
}

/// Exhaustive coverage could not be constructed: a fatal condition (RFC 0013
/// §3).
fn coverage_failure() -> FatalFormationFailure {
    fatal(
        "plist.binary.coverage@1",
        DiagnosticCategory::Syntax,
        None,
        &[],
    )
}

/// One fatal diagnostic.
fn fatal(
    code: &'static str,
    category: DiagnosticCategory,
    location: Option<DiagnosticLocation>,
    arguments: &[(&'static str, String)],
) -> FatalFormationFailure {
    let mut diagnostic = Diagnostic::new(code, category, DiagnosticSeverity::Error, location, 0);
    for (name, value) in arguments {
        diagnostic
            .arguments
            .insert((*name).to_owned(), value.clone());
    }
    FatalFormationFailure::from_diagnostic(diagnostic)
}

/// `plist.limit.<name>@1` resource-limit failure (RFC 0013 §12).
fn fatal_limit(name: &'static str, observed: usize, limit: usize) -> FatalFormationFailure {
    let mut diagnostic = Diagnostic::new(
        format!("plist.limit.{name}@1"),
        DiagnosticCategory::Resource,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("limit".to_owned(), limit.to_string());
    diagnostic
        .arguments
        .insert("observed".to_owned(), observed.to_string());
    FatalFormationFailure::from_diagnostic(diagnostic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlistValueKind;

    /// Appends a big-endian value of `width` bytes.
    fn push_be(output: &mut Vec<u8>, value: u64, width: usize) {
        for shift in (0..width).rev() {
            output.push(((value >> (8 * shift)) & 0xFF) as u8);
        }
    }

    /// Hand-built `bplist00` fixture writer: header, objects, offset table,
    /// trailer.
    struct TestFile {
        bytes: Vec<u8>,
        offsets: Vec<u64>,
        offset_int_size: usize,
        object_ref_size: usize,
    }

    impl TestFile {
        fn new(offset_int_size: usize, object_ref_size: usize) -> Self {
            Self {
                bytes: b"bplist00".to_vec(),
                offsets: Vec::new(),
                offset_int_size,
                object_ref_size,
            }
        }

        fn object(&mut self, object: &[u8]) -> u64 {
            let offset = u64::try_from(self.bytes.len()).unwrap();
            self.offsets.push(offset);
            self.bytes.extend_from_slice(object);
            offset
        }

        fn pad(&mut self, count: usize) {
            self.bytes.extend(std::iter::repeat_n(0xAA, count));
        }

        fn finish(mut self, top_object: u64) -> Vec<u8> {
            let offset_table_offset = u64::try_from(self.bytes.len()).unwrap();
            for offset in &self.offsets {
                push_be(&mut self.bytes, *offset, self.offset_int_size);
            }
            self.bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            self.bytes.push(0); // sortVersion
            self.bytes.push(self.offset_int_size as u8);
            self.bytes.push(self.object_ref_size as u8);
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

    /// Reference bytes of the given width.
    fn reference(object_index: usize, ref_size: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_be(&mut bytes, u64::try_from(object_index).unwrap(), ref_size);
        bytes
    }

    fn parse(bytes: &[u8]) -> Result<PlistFormedBinary, FatalFormationFailure> {
        parse_binary(Arc::from(bytes), PlistParseLimits::default())
    }

    fn parse_limited(
        bytes: &[u8],
        limits: PlistParseLimits,
    ) -> Result<PlistFormedBinary, FatalFormationFailure> {
        parse_binary(Arc::from(bytes), limits)
    }

    /// Direct-parser harness mirroring `parse_binary`'s preamble, so tests
    /// can exercise the defensive bounds guards that the trailer integrity
    /// checks make unreachable through the public entry point.
    fn parser_for(bytes: &[u8]) -> Parser {
        let limits = PlistParseLimits::default();
        let source = Arc::new(
            SourceSnapshot::from_binary(
                Arc::<[u8]>::from(bytes),
                SourceLimits {
                    max_raw_bytes: limits.common.max_source_bytes,
                    max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
                    max_decoded_scalars: limits.max_decoded_scalars,
                },
            )
            .expect("source snapshot"),
        );
        Parser {
            source,
            limits,
            authority: DocumentAuthority::fresh(),
            sink: DiagnosticSink::new(limits.common.max_diagnostics),
            recovered: false,
            uid_count: 0,
            extended_integers: 0,
            facts: 0,
        }
    }

    fn diagnostic_codes(formed: &PlistFormedBinary) -> Vec<String> {
        formed
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    fn region_kinds(formed: &PlistFormedBinary) -> Vec<&str> {
        formed
            .structural_index()
            .regions()
            .iter()
            .map(BinaryRegion::kind)
            .collect()
    }

    fn region_spans(formed: &PlistFormedBinary) -> Vec<(usize, usize)> {
        formed
            .structural_index()
            .regions()
            .iter()
            .map(|region| (region.span().start_byte(), region.span().end_byte()))
            .collect()
    }

    fn minimal_file() -> Vec<u8> {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]);
        file.finish(0)
    }

    /// Patches trailer bytes: `field_offset` is relative to the trailer start.
    fn patch_trailer(bytes: &mut [u8], field_offset: usize, value: u64, width: usize) {
        let start = bytes.len() - 32 + field_offset;
        let mut encoded = Vec::new();
        push_be(&mut encoded, value, width);
        bytes[start..start + width].copy_from_slice(&encoded);
    }

    #[test]
    fn minimal_42_byte_file_forms_complete_document() {
        let bytes = minimal_file();
        assert_eq!(bytes.len(), 42);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert!(formed.diagnostics().is_empty());
        let document = formed.document().unwrap();
        assert_eq!(document.node_count(), 1);
        assert_eq!(document.root_value().kind(), PlistValueKind::Boolean);
        assert!(
            !document
                .get(document.root())
                .unwrap()
                .as_boolean()
                .unwrap()
                .value()
        );
        assert_eq!(formed.render(), bytes);
    }

    #[test]
    fn minimal_facts_and_regions_are_exact() {
        let formed = parse(&minimal_file()).unwrap();
        let facts = formed.facts();
        assert_eq!(facts.objects().len(), 1);
        assert_eq!(facts.objects()[0].index(), 0);
        assert_eq!(facts.objects()[0].offset(), 8);
        assert_eq!(facts.objects()[0].marker(), 0x08);
        assert_eq!(facts.offsets().len(), 1);
        assert_eq!(facts.offsets()[0].index(), 0);
        assert_eq!(facts.offsets()[0].offset(), 8);
        assert!(facts.refs().is_empty());
        assert_eq!(facts.trailer().sort_version(), 0);
        assert_eq!(facts.trailer().offset_int_size(), 1);
        assert_eq!(facts.trailer().object_ref_size(), 1);
        assert_eq!(facts.trailer().num_objects(), 1);
        assert_eq!(facts.trailer().top_object(), 0);
        assert_eq!(facts.trailer().offset_table_offset(), 9);
        assert_eq!(
            region_kinds(&formed),
            ["header", "object-table", "offset-table", "trailer"]
        );
        assert_eq!(region_spans(&formed), [(0, 8), (8, 9), (9, 10), (10, 42)]);
    }

    /// Builds the all-value-kinds fixture: 25 objects, root dict with 12
    /// entries whose keys are shared string objects.
    fn all_types_fixture() -> Vec<u8> {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x11, 0x01, 0x00]); // 0: integer 256 (2-byte)
        file.object(&[0x23]); // 1: real 0.5 (8-byte)
        push_be(&mut file.bytes, 0.5_f64.to_bits(), 8);
        file.object(&[0x09]); // 2: true
        file.object(&[0x33]); // 3: date 0.0
        push_be(&mut file.bytes, 0.0_f64.to_bits(), 8);
        file.object(&[0x80, 0x2A]); // 4: uid 42
        file.object(&[0xA1, 0x06]); // 5: array [6]
        file.object(&[0x52, 0x68, 0x69]); // 6: ascii "hi"
        file.object(&[0x61, 0x00, 0x41]); // 7: utf16 "A"
        file.object(&[0x42, 0xDE, 0xAD]); // 8: data [DE AD]
        file.object(&[0x08]); // 9: false
        file.object(&[0xD0]); // 10: empty dict
        file.object(&[0xA0]); // 11: empty array
        for key in *b"irtduaswDfeE" {
            file.object(&[0x51, key]); // 12..23: key strings
        }
        let mut dict = vec![0xDC]; // 24: dict with 12 entries
        for key_object in 12..24 {
            dict.extend(reference(key_object, 1));
        }
        for value_object in 0..12 {
            dict.extend(reference(value_object, 1));
        }
        file.object(&dict);
        file.finish(24)
    }

    #[test]
    fn all_value_kinds_parse_into_the_shared_native_model() {
        let bytes = all_types_fixture();
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        assert_eq!(document.node_count(), 25);
        let entries = document
            .get(document.root())
            .unwrap()
            .as_dict()
            .unwrap()
            .entries();
        assert_eq!(entries.len(), 12);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "i");
        assert_eq!(
            document
                .get(entries[0].value())
                .unwrap()
                .as_integer()
                .unwrap()
                .value(),
            256
        );
        assert_eq!(entries[1].key().to_unicode().unwrap(), "r");
        let real = document.get(entries[1].value()).unwrap().as_real().unwrap();
        assert_eq!(real.width(), RealWidth::Float64);
        assert_eq!(real.as_f64().to_bits(), 0.5_f64.to_bits());
        assert_eq!(entries[2].key().to_unicode().unwrap(), "t");
        assert!(
            document
                .get(entries[2].value())
                .unwrap()
                .as_boolean()
                .unwrap()
                .value()
        );
        assert_eq!(entries[3].key().to_unicode().unwrap(), "d");
        assert_eq!(
            document
                .get(entries[3].value())
                .unwrap()
                .as_date()
                .unwrap()
                .seconds()
                .to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(entries[4].key().to_unicode().unwrap(), "u");
        assert_eq!(
            document
                .get(entries[4].value())
                .unwrap()
                .as_uid()
                .unwrap()
                .value(),
            42
        );
        assert_eq!(entries[5].key().to_unicode().unwrap(), "a");
        let elements = document
            .get(entries[5].value())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(elements.len(), 1);
        assert_eq!(
            document
                .get(elements[0])
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "hi"
        );
        assert_eq!(entries[6].key().to_unicode().unwrap(), "s");
        assert_eq!(
            document
                .get(entries[6].value())
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "hi"
        );
        assert_eq!(entries[7].key().to_unicode().unwrap(), "w");
        assert_eq!(
            document
                .get(entries[7].value())
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "A"
        );
        assert_eq!(entries[8].key().to_unicode().unwrap(), "D");
        assert_eq!(
            document
                .get(entries[8].value())
                .unwrap()
                .as_data()
                .unwrap()
                .bytes(),
            &[0xDE, 0xAD]
        );
        assert_eq!(entries[9].key().to_unicode().unwrap(), "f");
        assert!(
            !document
                .get(entries[9].value())
                .unwrap()
                .as_boolean()
                .unwrap()
                .value()
        );
        assert_eq!(entries[10].key().to_unicode().unwrap(), "e");
        assert!(
            document
                .get(entries[10].value())
                .unwrap()
                .as_dict()
                .unwrap()
                .is_empty()
        );
        assert_eq!(entries[11].key().to_unicode().unwrap(), "E");
        assert!(
            document
                .get(entries[11].value())
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn all_types_facts_expose_the_binary_structure() {
        let bytes = all_types_fixture();
        let formed = parse(&bytes).unwrap();
        let facts = formed.facts();
        assert_eq!(facts.objects().len(), 25);
        assert_eq!(facts.objects()[0].marker(), 0x11);
        assert_eq!(facts.objects()[4].marker(), 0x80);
        assert_eq!(facts.objects()[5].marker(), 0xA1);
        assert_eq!(facts.objects()[24].marker(), 0xDC);
        assert_eq!(facts.offsets().len(), 25);
        assert_eq!(facts.refs().len(), 25); // 1 array element + 24 dict refs
        assert_eq!(facts.refs()[0].owner(), 5);
        assert_eq!(facts.refs()[0].position(), 0);
        assert_eq!(facts.refs()[0].target(), 6);
        assert_eq!(facts.trailer().num_objects(), 25);
        assert_eq!(facts.trailer().top_object(), 24);
    }

    #[test]
    fn integer_widths_follow_the_rfc_513_sign_rules() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x10, 0xFF]); // 255
        file.object(&[0x11, 0x00, 0xFF]); // 255
        file.object(&[0x12, 0xFF, 0xFF, 0xFF, 0xFF]); // 4294967295
        file.object(&[0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // -1
        file.object(&[0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]); // 5, non-minimal
        file.object(&[0x13, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // i64::MIN
        file.object(&[0xA6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let bytes = file.finish(6);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        let values = elements
            .iter()
            .map(|reference| {
                document
                    .get(*reference)
                    .unwrap()
                    .as_integer()
                    .unwrap()
                    .value()
            })
            .collect::<Vec<_>>();
        assert_eq!(values, [255, 255, 4_294_967_295, -1, 5, i64::MIN]);
        // Non-minimal width facts are preserved on the object facts.
        assert_eq!(formed.facts().objects()[4].marker(), 0x13);
        assert_eq!(formed.facts().objects()[0].marker(), 0x10);
    }

    #[test]
    fn float32_width_fact_survives_parsing() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x22]);
        push_be(&mut file.bytes, u64::from(0.1_f32.to_bits()), 4);
        file.object(&[0x23]);
        push_be(&mut file.bytes, f64::NAN.to_bits(), 8);
        file.object(&[0xA2, 0x00, 0x01]);
        let bytes = file.finish(2);
        let formed = parse(&bytes).unwrap();
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        let single = document.get(elements[0]).unwrap().as_real().unwrap();
        assert_eq!(single.width(), RealWidth::Float32);
        assert_eq!(single.as_f64().to_bits(), f64::from(0.1_f32).to_bits());
        let double = document.get(elements[1]).unwrap().as_real().unwrap();
        assert_eq!(double.width(), RealWidth::Float64);
        assert!(double.as_f64().is_nan());
    }

    #[test]
    fn date_holds_exact_seconds_since_the_plist_epoch() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x33]);
        push_be(&mut file.bytes, (-1.5_f64).to_bits(), 8);
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            formed
                .document()
                .unwrap()
                .root_value()
                .as_date()
                .unwrap()
                .seconds()
                .to_bits(),
            (-1.5_f64).to_bits()
        );
    }

    #[test]
    fn non_finite_date_payload_is_recovered() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x33]);
        push_be(&mut file.bytes, f64::INFINITY.to_bits(), 8);
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.date@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn ascii_string_high_bit_bytes_are_rejected() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x52, b'a', 0x80]);
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.string@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn utf16be_strings_preserve_code_units_and_surrogates() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x63, 0x00, 0x41, 0xD8, 0x3D, 0xDE, 0x00]); // "A😀"
        file.object(&[0x62, 0x00, 0x41, 0xD8, 0x00]); // 'A' + unpaired high surrogate
        file.object(&[0xA2, 0x00, 0x01]);
        let bytes = file.finish(2);
        let formed = parse(&bytes).unwrap();
        let document = formed.document().unwrap();
        let well_formed = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        let first = document.get(well_formed[0]).unwrap().as_string().unwrap();
        assert_eq!(first.code_units(), &[0x0041, 0xD83D, 0xDE00]);
        assert_eq!(first.status(), crate::PlistStringStatus::WellFormedUnicode);
        assert_eq!(first.to_unicode().unwrap(), "A😀");
        let unpaired = document.get(well_formed[1]).unwrap().as_string().unwrap();
        assert_eq!(unpaired.code_units(), &[0x0041, 0xD800]);
        assert_eq!(
            unpaired.status(),
            crate::PlistStringStatus::UnpairedSurrogate
        );
        assert!(unpaired.to_unicode().is_err());
    }

    #[test]
    fn uid_widths_leading_zeros_and_32_bit_bound() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x80, 0x00]); // 1 byte: 0
        file.object(&[0x81, 0x01, 0x02]); // 2 bytes: 258
        file.object(&[0x82, 0x00, 0x00, 0x2A]); // 3 bytes: 42
        file.object(&[0x83, 0xFF, 0xFF, 0xFF, 0xFF]); // 4 bytes: u32::MAX
        file.object(&[0x84, 0x00, 0x00, 0x00, 0x00, 0x00]); // 5 bytes, leading zeros: 0
        file.object(&[0xA5, 0x00, 0x01, 0x02, 0x03, 0x04]);
        let bytes = file.finish(5);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        let values = elements
            .iter()
            .map(|reference| document.get(*reference).unwrap().as_uid().unwrap().value())
            .collect::<Vec<_>>();
        assert_eq!(values, [0, 258, 42, u32::MAX, 0]);
        assert_eq!(formed.facts().objects()[3].marker(), 0x83);
    }

    #[test]
    fn uid_values_above_32_bits_are_recovered() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x84, 0x01, 0x00, 0x00, 0x00, 0x00]); // 2^32
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.uid@1".to_owned()));
        assert!(formed.document().is_none());
    }

    #[test]
    fn shared_references_preserve_arena_identity() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x51, b'x']); // 0: "x"
        file.object(&[0xA2, 0x00, 0x00]); // 1: ["x", "x"]
        let bytes = file.finish(1);
        let formed = parse(&bytes).unwrap();
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(
            elements,
            &[PlistValueRef::from_index(0), PlistValueRef::from_index(0)]
        );
        assert_eq!(elements[0], elements[1]);
        assert_eq!(document.node_count(), 2);
        assert_eq!(formed.facts().refs().len(), 2);
        assert_eq!(formed.facts().refs()[0].target(), 0);
        assert_eq!(formed.facts().refs()[1].target(), 0);
    }

    #[test]
    fn forward_references_are_valid() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA1, 0x01]); // 0: array [1] (forward)
        file.object(&[0x51, b'z']); // 1: "z"
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(
            document
                .get(elements[0])
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "z"
        );
    }

    #[test]
    fn duplicate_offset_entries_are_distinct_objects_with_equal_values() {
        // Two offset entries pointing at the same bytes are two distinct
        // source objects sharing native value equality (RFC 0013 §5.12).
        let mut bytes = b"bplist00".to_vec();
        bytes.push(0x51);
        bytes.push(b'x');
        bytes.push(0x08); // entry 0 -> 8
        bytes.push(0x08); // entry 1 -> 8
        bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
        bytes.push(0); // sortVersion
        bytes.push(1); // offsetIntSize
        bytes.push(1); // objectRefSize
        push_be(&mut bytes, 2, 8); // numObjects
        push_be(&mut bytes, 0, 8); // topObject
        push_be(&mut bytes, 10, 8); // offsetTableOffset
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        assert_eq!(document.node_count(), 2);
        assert_eq!(formed.facts().objects().len(), 2);
        assert_eq!(formed.facts().objects()[0].offset(), 8);
        assert_eq!(formed.facts().objects()[1].offset(), 8);
        let first = document
            .get(PlistValueRef::from_index(0))
            .unwrap()
            .as_string()
            .unwrap()
            .to_unicode()
            .unwrap();
        let second = document
            .get(PlistValueRef::from_index(1))
            .unwrap()
            .as_string()
            .unwrap()
            .to_unicode()
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn non_string_dict_keys_are_recovered() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x12, 0x00, 0x00, 0x00, 0x05]); // 0: integer 5
        let mut dict = vec![0xD1, 0x00, 0x00]; // 1: dict { 0: 0 }
        dict.extend(reference(0, 1));
        file.object(&dict);
        let bytes = file.finish(1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.non-string-key@1".to_owned()));
        assert!(formed.document().is_none());
        assert_eq!(formed.facts().objects().len(), 1);
    }

    #[test]
    fn duplicate_keys_are_preserved_in_source_order() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x51, b'k']); // 0: "k"
        file.object(&[0x51, b'k']); // 1: "k"
        file.object(&[0x51, b'v']); // 2: "v"
        file.object(&[0x51, b'w']); // 3: "w"
        let mut dict = vec![0xD2];
        dict.extend(reference(0, 1));
        dict.extend(reference(1, 1));
        dict.extend(reference(2, 1));
        dict.extend(reference(3, 1));
        file.object(&dict); // 4: { "k": "v", "k": "w" }
        let bytes = file.finish(4);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        let entries = document
            .get(document.root())
            .unwrap()
            .as_dict()
            .unwrap()
            .entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key().to_unicode().unwrap(), "k");
        assert_eq!(entries[1].key().to_unicode().unwrap(), "k");
        assert_eq!(
            document
                .get(entries[0].value())
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "v"
        );
        assert_eq!(
            document
                .get(entries[1].value())
                .unwrap()
                .as_string()
                .unwrap()
                .to_unicode()
                .unwrap(),
            "w"
        );
    }

    #[test]
    fn extended_sizes_are_read_as_unsigned_integer_objects() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x4F, 0x10, 0x01, 0xAB]); // data of 1 byte via extended size
        file.object(&[0xAF, 0x11, 0x00, 0x01, 0x02]); // array of 1 element via 2-byte size
        file.object(&[0x08]);
        let bytes = file.finish(1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        let document = formed.document().unwrap();
        assert_eq!(
            document
                .get(PlistValueRef::from_index(0))
                .unwrap()
                .as_data()
                .unwrap()
                .bytes(),
            &[0xAB]
        );
        let elements = document
            .get(PlistValueRef::from_index(1))
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(elements, &[PlistValueRef::from_index(2)]);
    }

    #[test]
    fn extended_size_marker_must_be_an_integer_marker() {
        for bad_marker in [0x08_u8, 0x14, 0x0F, 0x22] {
            let mut file = TestFile::new(1, 1);
            file.object(&[0x4F, bad_marker, 0x00]);
            let bytes = file.finish(0);
            let formed = parse(&bytes).unwrap();
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "marker {bad_marker:#04x}"
            );
            assert!(
                diagnostic_codes(&formed).contains(&"plist.binary.extended-size@1".to_owned()),
                "marker {bad_marker:#04x}"
            );
        }
    }

    #[test]
    fn excluded_markers_are_recovered_with_a_stable_diagnostic() {
        for marker in [
            0x00_u8, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x14, 0x20, 0x21, 0x70, 0x90, 0xB0, 0xC0,
            0xE0, 0xFF,
        ] {
            let mut file = TestFile::new(1, 1);
            file.object(&[marker]);
            let bytes = file.finish(0);
            let formed = parse(&bytes).unwrap();
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "marker {marker:#04x}"
            );
            assert!(
                diagnostic_codes(&formed).contains(&"plist.binary.marker@1".to_owned()),
                "marker {marker:#04x}"
            );
            assert!(formed.document().is_none(), "marker {marker:#04x}");
        }
    }

    #[test]
    fn header_version_strings_other_than_00_are_recovered_but_parsed() {
        let mut bytes = minimal_file();
        bytes[7] = b'1';
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.header@1".to_owned()));
        assert!(formed.document().is_some());

        let mut bytes = minimal_file();
        bytes[0] = b'x';
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert_eq!(
            region_kinds(&formed),
            ["error-region", "object-table", "offset-table", "trailer"]
        );
        assert!(formed.document().is_some());
    }

    #[test]
    fn undersized_sources_are_fatal() {
        for len in 0..MIN_SOURCE_BYTES {
            let bytes = vec![0_u8; len];
            let error = parse(&bytes).unwrap_err();
            assert!(
                error
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "plist.binary.minimum-size@1"),
                "len {len}"
            );
        }
        // 42 bytes of zeros form a Recovered document (bad header, bad trailer).
        let formed = parse(&[0_u8; MIN_SOURCE_BYTES]).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.document().is_none());
    }

    #[test]
    fn trailer_unused_bytes_must_be_zero() {
        let mut bytes = minimal_file();
        let unused = bytes.len() - 32;
        bytes[unused] = 1;
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let trailer = formed
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "plist.binary.trailer@1")
            .unwrap();
        assert_eq!(
            trailer.arguments.get("check").map(String::as_str),
            Some("unused-bytes")
        );
        assert!(formed.document().is_none());
        assert!(formed.facts().objects().is_empty());
        assert!(formed.facts().offsets().is_empty());
        assert_eq!(
            region_kinds(&formed),
            ["header", "error-region", "error-region"]
        );
    }

    #[test]
    fn trailer_sort_version_accepts_zero_and_one() {
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 5, 1, 1);
        assert_eq!(parse(&bytes).unwrap().status(), FormationStatus::Complete);

        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 5, 2, 1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str) == Some("sort-version")
        }));
    }

    #[test]
    fn trailer_width_fields_are_bounded() {
        for (field, check) in [(6_usize, "offset-int-size"), (7_usize, "object-ref-size")] {
            for width in [0_u8, 9] {
                let mut bytes = minimal_file();
                patch_trailer(&mut bytes, field, u64::from(width), 1);
                let formed = parse(&bytes).unwrap();
                assert_eq!(
                    formed.status(),
                    FormationStatus::Recovered,
                    "field {field} width {width}"
                );
                assert!(formed.diagnostics().iter().any(|diagnostic| {
                    diagnostic.code == "plist.binary.trailer@1"
                        && diagnostic.arguments.get("check").map(String::as_str) == Some(check)
                }));
            }
        }
    }

    #[test]
    fn trailer_num_objects_zero_is_rejected() {
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 8, 0, 8);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str) == Some("num-objects")
        }));
        assert!(formed.document().is_none());
    }

    #[test]
    fn trailer_top_object_out_of_range_is_rejected() {
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 16, 1, 8);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str) == Some("top-object")
        }));
    }

    #[test]
    fn trailer_offset_table_offset_range_is_rejected() {
        let len = minimal_file().len();
        for value in [0_u64, 7, 8] {
            let mut bytes = minimal_file();
            patch_trailer(&mut bytes, 24, value, 8);
            let formed = parse(&bytes).unwrap();
            assert_eq!(
                formed.status(),
                FormationStatus::Recovered,
                "offset {value}"
            );
            assert!(formed.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == "plist.binary.trailer@1"
                    && diagnostic.arguments.get("check").map(String::as_str)
                        == Some("offset-table-offset")
            }));
        }
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 24, u64::try_from(len - 32).unwrap(), 8);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 24, u64::try_from(len - 31).unwrap(), 8);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
    }

    #[test]
    fn trailer_total_length_mismatch_is_recovered() {
        let mut bytes = minimal_file();
        bytes.insert(bytes.len() - 32, 0xAB);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str) == Some("total-length")
        }));
        assert!(formed.document().is_none());
        assert_eq!(
            region_kinds(&formed),
            ["header", "error-region", "error-region"]
        );
    }

    #[test]
    fn trailer_sufficiency_checks_are_enforced() {
        // offsetIntSize 1 cannot address an offset table at or beyond byte 256.
        let mut file = TestFile::new(2, 1);
        let mut payload = vec![0x4F, 0x10, 0xFA];
        payload.extend(std::iter::repeat_n(0x00, 250));
        file.object(&payload);
        let mut bytes = file.finish(0);
        patch_trailer(&mut bytes, 6, 1, 1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str)
                    == Some("offset-int-size-sufficiency")
        }));

        // objectRefSize 1 cannot address 256 objects.
        let mut file = TestFile::new(1, 2);
        for _ in 0..256 {
            file.object(&[0x08]);
        }
        let mut bytes = file.finish(255);
        patch_trailer(&mut bytes, 7, 1, 1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str)
                    == Some("object-ref-size-sufficiency")
        }));
    }

    #[test]
    fn offset_table_entries_out_of_range_cut_the_prefix() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]); // 0 at offset 8
        file.object(&[0x08]); // 1 at offset 9
        let bytes = file.finish(0);
        assert_eq!(bytes.len(), 44);
        for bad in [7_u8, 10, 255] {
            let mut mutated = bytes.clone();
            mutated[11] = bad; // entry 1
            let formed = parse(&mutated).unwrap();
            assert_eq!(formed.status(), FormationStatus::Recovered, "entry {bad}");
            assert!(
                diagnostic_codes(&formed).contains(&"plist.binary.offset-table@1".to_owned()),
                "entry {bad}"
            );
            assert!(formed.document().is_some());
            assert_eq!(formed.facts().objects().len(), 1);
            assert_eq!(formed.facts().offsets().len(), 1);
            assert_eq!(
                region_kinds(&formed),
                [
                    "header",
                    "object-table",
                    "error-region",
                    "offset-table",
                    "trailer"
                ]
            );
            assert_eq!(
                region_spans(&formed),
                [(0, 8), (8, 9), (9, 10), (10, 12), (12, 44)]
            );
        }
    }

    #[test]
    fn table_windows_past_end_of_source_follow_the_trailer_recovery() {
        // The trailer's total-length check is the parser's existing defense
        // for a table window that runs past end-of-source: it recovers with
        // `plist.binary.trailer@1` before any table entry is read. Entry 0
        // here would claim the window [40, 48) inside a 42-byte source.
        let mut bytes = minimal_file();
        patch_trailer(&mut bytes, 6, 8, 1); // offsetIntSize 8
        patch_trailer(&mut bytes, 24, 40, 8); // offsetTableOffset 40
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(formed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "plist.binary.trailer@1"
                && diagnostic.arguments.get("check").map(String::as_str) == Some("total-length")
        }));
        assert!(!diagnostic_codes(&formed).contains(&"plist.binary.offset-table@1".to_owned()));
    }

    #[test]
    fn offset_table_entry_windows_past_end_of_source_recover() {
        // A 41-byte source with a valid first entry at byte 40 (value 10) and
        // a second entry whose window [41, 42) runs past the end: the
        // defensive guard cuts the proven prefix exactly like a malformed
        // entry value instead of panicking.
        let mut bytes = b"bplist00".to_vec();
        bytes.resize(41, 0x00);
        bytes[40] = 0x0A;
        let mut parser = parser_for(&bytes);
        let (facts, offsets, cut) = parser.read_offset_table(40, 2, 1).unwrap();
        assert_eq!(cut, 1);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].offset(), 10);
        assert_eq!(offsets, [10]);
        assert!(parser.recovered);
        let diagnostics = parser.sink.finish();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "plist.binary.offset-table@1");
        assert_eq!(
            diagnostics[0].arguments.get("end").map(String::as_str),
            Some("42")
        );
    }

    #[test]
    fn read_be_u64_rejects_windows_past_end_of_source() {
        let bytes = [0_u8; 8];
        assert!(read_be_u64(&bytes, 0, 8).is_ok());
        assert!(read_be_u64(&bytes, 0, 1).is_ok());
        let error = read_be_u64(&bytes, 1, 8).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.binary.overflow@1")
        );
        assert!(read_be_u64(&bytes, 8, 1).is_err());
    }

    #[test]
    fn object_marker_past_end_of_source_recovers_like_a_bad_offset_entry() {
        let bytes = minimal_file();
        let mut parser = parser_for(&bytes);
        let shape = parser
            .scan_object(0, bytes.len(), bytes.len(), 1, 1)
            .unwrap();
        assert!(shape.is_none());
        assert!(parser.recovered);
        assert!(
            parser
                .sink
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.binary.offset-table@1")
        );
    }

    #[test]
    fn extended_size_marker_past_end_of_source_recovers() {
        let bytes = minimal_file();
        let mut parser = parser_for(&bytes);
        let count = parser.read_count(bytes.len() - 1, 0).unwrap();
        assert!(count.is_none());
        assert!(parser.recovered);
        assert!(
            parser
                .sink
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.binary.offset-table@1")
        );
    }

    #[test]
    fn object_extent_beyond_the_table_is_recovered() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x45, 0x01, 0x02, 0x03]); // claims 5 payload bytes, has 3
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.extent@1".to_owned()));
        assert!(formed.document().is_none());
        assert!(formed.facts().objects().is_empty());
        assert_eq!(
            region_kinds(&formed),
            ["header", "error-region", "offset-table", "trailer"]
        );
    }

    #[test]
    fn prefix_recovery_keeps_proven_objects_and_facts() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA2, 0x01, 0x02]); // 0: [1, 2]
        file.object(&[0x08]); // 1: false
        file.object(&[0x09]); // 2: true
        file.object(&[0x14]); // 3: excluded marker
        file.object(&[0x08]); // 4: unproven
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.marker@1".to_owned()));
        let document = formed.document().unwrap();
        let elements = document
            .get(document.root())
            .unwrap()
            .as_array()
            .unwrap()
            .elements();
        assert_eq!(elements.len(), 2);
        assert_eq!(formed.facts().objects().len(), 3);
        assert_eq!(formed.facts().objects()[0].marker(), 0xA2);
        assert_eq!(formed.facts().offsets().len(), 5);
        assert_eq!(formed.facts().refs().len(), 2);
        assert_eq!(
            region_kinds(&formed),
            [
                "header",
                "object-table",
                "error-region",
                "offset-table",
                "trailer"
            ]
        );
        assert_eq!(
            region_spans(&formed),
            [(0, 8), (8, 13), (13, 15), (15, 20), (20, 52)]
        );
    }

    #[test]
    fn reference_to_an_unproven_object_drops_the_native_document() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA1, 0x02]); // 0: [2]
        file.object(&[0x08]); // 1: false
        file.object(&[0x14]); // 2: excluded marker
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(
            diagnostic_codes(&formed).contains(&"plist.binary.unproven-reference@1".to_owned())
        );
        assert!(formed.document().is_none());
        assert_eq!(formed.facts().objects().len(), 2);
        assert_eq!(formed.facts().refs().len(), 1);
    }

    #[test]
    fn unproven_top_object_drops_the_native_document() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]); // 0: false
        file.object(&[0x14]); // 1: excluded marker
        let bytes = file.finish(1);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(
            diagnostic_codes(&formed).contains(&"plist.binary.unproven-top-object@1".to_owned())
        );
        assert!(formed.document().is_none());
        assert_eq!(formed.facts().objects().len(), 1);
    }

    #[test]
    fn cross_object_cycles_are_recovered() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA1, 0x01]); // 0: [1]
        file.object(&[0xA1, 0x00]); // 1: [0]
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        assert!(diagnostic_codes(&formed).contains(&"plist.binary.cycle@1".to_owned()));
        assert!(formed.document().is_none());
        assert_eq!(formed.facts().objects().len(), 2);
        assert_eq!(formed.facts().refs().len(), 2);
        // Every byte remains proven: no error region.
        assert!(!region_kinds(&formed).contains(&"error-region"));
    }

    #[test]
    fn container_depth_limit_is_fatal() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA1, 0x01]); // 0: [1]
        file.object(&[0xA1, 0x02]); // 1: [2]
        file.object(&[0xA1, 0x03]); // 2: [3]
        file.object(&[0x08]); // 3
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_container_depth: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.container-depth@1")
        );
    }

    #[test]
    fn object_count_limit_is_fatal() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]);
        file.object(&[0x08]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_object_count: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.object-count@1")
        );
    }

    #[test]
    fn per_value_limits_are_fatal() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x53, b'a', b'b', b'c']);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_string_code_units: 2,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.string-code-units@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0x42, 0x01, 0x02]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_data_bytes: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.data-bytes@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0xA2, 0x00, 0x01]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_array_elements: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.array-elements@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0xD2, 0x00, 0x00, 0x00, 0x00]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_dict_entries: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.dict-entries@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0x80, 0x01]);
        file.object(&[0x80, 0x02]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_uid_count: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.uid-count@1")
        );
    }

    #[test]
    fn extended_size_limits_are_fatal() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x4F, 0x10, 0x05]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_extended_size_value: 4,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.extended-size-value@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0x4F, 0x10, 0x01, 0x00]);
        file.object(&[0x4F, 0x10, 0x01, 0x00]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_extended_size_integers: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.extended-size-integers@1")
        );
    }

    #[test]
    fn width_and_table_limits_are_fatal() {
        let mut file = TestFile::new(2, 1);
        file.object(&[0x08]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_offset_int_size: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.offset-int-size@1")
        );

        let mut file = TestFile::new(1, 2);
        file.object(&[0x08]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_object_ref_size: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.object-ref-size@1")
        );

        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]);
        file.object(&[0x08]);
        let bytes = file.finish(0);
        let limits = PlistParseLimits {
            max_offset_table_bytes: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.offset-table-bytes@1")
        );
    }

    #[test]
    fn binary_facts_limit_is_fatal() {
        let limits = PlistParseLimits {
            max_binary_facts: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&minimal_file(), limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.binary-facts@1")
        );
    }

    #[test]
    fn duplicate_key_group_limit_is_fatal() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x51, b'k']);
        file.object(&[0x51, b'k']);
        file.object(&[0x51, b'v']);
        file.object(&[0x51, b'w']);
        let mut dict = vec![0xD2];
        dict.extend(reference(0, 1));
        dict.extend(reference(1, 1));
        dict.extend(reference(2, 1));
        dict.extend(reference(3, 1));
        file.object(&dict);
        let bytes = file.finish(4);
        let limits = PlistParseLimits {
            max_duplicate_key_group_members: 1,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.duplicate-key-group@1")
        );
    }

    #[test]
    fn source_bytes_limit_is_fatal() {
        let limits = PlistParseLimits {
            common: consema_document::ParseLimits {
                max_source_bytes: 10,
                ..consema_document::ParseLimits::default()
            },
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&minimal_file(), limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "core.source.resource-limit@1")
        );
    }

    #[test]
    fn recovery_regions_limit_is_fatal() {
        let mut bytes = minimal_file();
        bytes[0] = b'x';
        let limits = PlistParseLimits {
            max_recovery_regions: 0,
            ..PlistParseLimits::default()
        };
        let error = parse_limited(&bytes, limits).unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.recovery-regions@1")
        );
    }

    #[test]
    fn empty_containers_are_complete() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0xA0]);
        let bytes = file.finish(0);
        assert_eq!(parse(&bytes).unwrap().status(), FormationStatus::Complete);

        let mut file = TestFile::new(1, 1);
        file.object(&[0xD0]);
        let bytes = file.finish(0);
        assert_eq!(parse(&bytes).unwrap().status(), FormationStatus::Complete);
    }

    #[test]
    fn gap_between_objects_and_offset_table_is_padding() {
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]);
        file.pad(3);
        let bytes = file.finish(0);
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(
            region_kinds(&formed),
            [
                "header",
                "object-table",
                "padding",
                "offset-table",
                "trailer"
            ]
        );
        assert_eq!(
            region_spans(&formed),
            [(0, 8), (8, 9), (9, 12), (12, 13), (13, 45)]
        );
    }

    #[test]
    fn structural_regions_cover_the_source_exactly() {
        for bytes in [minimal_file(), all_types_fixture()] {
            let formed = parse(&bytes).unwrap();
            let mut next = 0;
            for region in formed.structural_index().regions() {
                assert_eq!(region.span().start_byte(), next);
                assert!(region.span().end_byte() > region.span().start_byte());
                next = region.span().end_byte();
            }
            assert_eq!(next, bytes.len());
        }
        let mut file = TestFile::new(1, 1);
        file.object(&[0x14]);
        let broken = file.finish(0);
        let formed = parse(&broken).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let mut next = 0;
        for region in formed.structural_index().regions() {
            assert_eq!(region.span().start_byte(), next);
            next = region.span().end_byte();
        }
        assert_eq!(next, broken.len());
    }

    #[test]
    fn diagnostics_are_deterministically_ordered() {
        let mut bytes = minimal_file();
        bytes[0] = b'x'; // bad header
        let unused = bytes.len() - 32;
        bytes[unused] = 1; // bad unused bytes
        let formed = parse(&bytes).unwrap();
        assert_eq!(formed.status(), FormationStatus::Recovered);
        let codes = diagnostic_codes(&formed);
        assert!(codes[0].starts_with("plist.binary.header"));
        assert!(codes.iter().any(|code| code == "plist.binary.trailer@1"));
        let diagnostics = formed.diagnostics();
        for pair in diagnostics.windows(2) {
            let left = pair[0].primary.as_ref().unwrap().start_byte;
            let right = pair[1].primary.as_ref().unwrap().start_byte;
            assert!(left <= right);
        }
    }

    #[test]
    fn truncation_and_mutation_never_panic_or_fake_complete() {
        let bytes = minimal_file();
        for len in 0..bytes.len() {
            if let Ok(formed) = parse(&bytes[..len]) {
                assert_ne!(formed.status(), FormationStatus::Complete, "len {len}");
            }
        }
        // A longer file exercises truncations above the minimum: the outcome
        // is Recovered (trailer integrity faults) or a fatal limit (garbage
        // trailer claims), never Complete and never a panic.
        let mut file = TestFile::new(1, 1);
        file.object(&[0x08]);
        file.object(&[0x09]);
        file.object(&[0x08]);
        let longer = file.finish(0);
        for len in MIN_SOURCE_BYTES..longer.len() {
            if let Ok(formed) = parse(&longer[..len]) {
                assert_eq!(formed.status(), FormationStatus::Recovered, "len {len}");
                assert_eq!(formed.render(), &longer[..len]);
            }
        }
        // Byte mutations never panic; header and trailer positions can never
        // forge a Complete document.
        for position in 0..bytes.len() {
            for mutation in [0x00_u8, 0x80, 0xFF, 0x13] {
                if bytes[position] == mutation {
                    continue;
                }
                let mut mutated = bytes.clone();
                mutated[position] = mutation;
                if let Ok(formed) = parse(&mutated) {
                    assert_eq!(formed.render(), mutated.as_slice());
                    if position < 8 || position >= bytes.len() - 32 {
                        assert_ne!(
                            formed.status(),
                            FormationStatus::Complete,
                            "position {position} mutation {mutation:#04x}"
                        );
                    }
                }
            }
        }
    }
}
