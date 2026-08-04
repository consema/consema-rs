//! Raw source ownership, encoding facts, content identity, and decoded locations.

use super::LocationError;
use encoding_rs::{
    BIG5, DecoderResult, EUC_KR, Encoding, GBK, SHIFT_JIS, UTF_8, WINDOWS_874, WINDOWS_1250,
    WINDOWS_1251, WINDOWS_1252, WINDOWS_1253, WINDOWS_1254, WINDOWS_1255, WINDOWS_1256,
    WINDOWS_1257, WINDOWS_1258,
};
use sha2::{Digest, Sha256};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

const CHECKPOINT_STRIDE: usize = 256;

/// Stable SHA-256 identity of exact raw source bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Computes the digest of exact raw bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Digest algorithm identifier frozen by the v1 source contract.
    #[must_use]
    pub const fn algorithm(self) -> &'static str {
        "sha256"
    }

    /// Exact 32 digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    /// Constructs a digest value from an already decoded 32-byte record.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}

/// One deterministic Windows code page admitted by source contract v2.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowsCodePage(u16);

impl WindowsCodePage {
    /// Resolves one numeric code page only when source v2 publishes it.
    #[must_use]
    pub const fn from_number(number: u16) -> Option<Self> {
        match number {
            874 | 932 | 936 | 949 | 950 | 1250..=1258 | 65001 => Some(Self(number)),
            _ => None,
        }
    }

    /// Canonical numeric code-page identity.
    #[must_use]
    pub const fn number(self) -> u16 {
        self.0
    }

    const fn name(self) -> &'static str {
        match self.0 {
            874 => "windows-874",
            932 => "windows-932",
            936 => "windows-936",
            949 => "windows-949",
            950 => "windows-950",
            1250 => "windows-1250",
            1251 => "windows-1251",
            1252 => "windows-1252",
            1253 => "windows-1253",
            1254 => "windows-1254",
            1255 => "windows-1255",
            1256 => "windows-1256",
            1257 => "windows-1257",
            1258 => "windows-1258",
            65001 => "windows-65001",
            _ => unreachable!(),
        }
    }

    const fn encoding(self) -> &'static Encoding {
        match self.0 {
            874 => WINDOWS_874,
            932 => SHIFT_JIS,
            936 => GBK,
            949 => EUC_KR,
            950 => BIG5,
            1250 => WINDOWS_1250,
            1251 => WINDOWS_1251,
            1252 => WINDOWS_1252,
            1253 => WINDOWS_1253,
            1254 => WINDOWS_1254,
            1255 => WINDOWS_1255,
            1256 => WINDOWS_1256,
            1257 => WINDOWS_1257,
            1258 => WINDOWS_1258,
            65001 => UTF_8,
            _ => unreachable!(),
        }
    }
}

/// Closed source encoding set supported by source contracts v1 and v2.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceEncoding {
    /// Opaque bytes without a decoded-text view.
    Binary,
    /// Unicode UTF-8.
    Utf8,
    /// Unicode UTF-16 with little-endian code units.
    Utf16Le,
    /// Unicode UTF-16 with big-endian code units.
    Utf16Be,
    /// ISO-8859-1 byte-to-scalar mapping.
    Latin1,
    /// Explicit Windows code page; never resolved from the host locale.
    WindowsCodePage(WindowsCodePage),
}

impl SourceEncoding {
    /// Stable wire identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Latin1 => "latin-1",
            Self::WindowsCodePage(code_page) => code_page.name(),
        }
    }

    const fn is_text(self) -> bool {
        !matches!(self, Self::Binary)
    }
}

/// Whether marker-shaped leading bytes participate in Unicode BOM resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BomPolicy {
    /// Detect UTF-8/UTF-16 BOMs using the frozen source-v1 rule.
    DetectUnicode,
    /// Decode all bytes as content under the explicitly selected encoding.
    TreatAsContent,
}

/// Recognized Unicode byte-order mark.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BomKind {
    /// EF BB BF.
    Utf8,
    /// FF FE.
    Utf16Le,
    /// FE FF.
    Utf16Be,
}

impl BomKind {
    /// Encoding asserted by this marker.
    #[must_use]
    pub const fn encoding(self) -> SourceEncoding {
        match self {
            Self::Utf8 => SourceEncoding::Utf8,
            Self::Utf16Le => SourceEncoding::Utf16Le,
            Self::Utf16Be => SourceEncoding::Utf16Be,
        }
    }
}

/// Caller inputs to deterministic encoding resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingRequest {
    profile_default: SourceEncoding,
    bom_policy: BomPolicy,
    declaration: Option<SourceEncoding>,
    caller_override: Option<SourceEncoding>,
}

impl EncodingRequest {
    /// Starts with the required profile default and no higher-priority facts.
    #[must_use]
    pub const fn new(profile_default: SourceEncoding) -> Self {
        Self {
            profile_default,
            bom_policy: BomPolicy::DetectUnicode,
            declaration: None,
            caller_override: None,
        }
    }

    /// Opaque-binary request.
    #[must_use]
    pub const fn binary() -> Self {
        Self::new(SourceEncoding::Binary)
    }

    /// Adds a normalized declaration supplied by the format layer.
    #[must_use]
    pub const fn with_declaration(mut self, declaration: SourceEncoding) -> Self {
        self.declaration = Some(declaration);
        self
    }

    /// Adds an explicit caller override.
    #[must_use]
    pub const fn with_caller_override(mut self, caller_override: SourceEncoding) -> Self {
        self.caller_override = Some(caller_override);
        self
    }

    /// Selects whether leading marker-shaped bytes are BOM evidence or content.
    #[must_use]
    pub const fn with_bom_policy(mut self, bom_policy: BomPolicy) -> Self {
        self.bom_policy = bom_policy;
        self
    }

    /// Profile fallback.
    #[must_use]
    pub const fn profile_default(self) -> SourceEncoding {
        self.profile_default
    }

    /// BOM interpretation policy.
    #[must_use]
    pub const fn bom_policy(self) -> BomPolicy {
        self.bom_policy
    }

    /// Normalized in-source declaration, when one exists.
    #[must_use]
    pub const fn declaration(self) -> Option<SourceEncoding> {
        self.declaration
    }

    /// Explicit caller choice, when one exists.
    #[must_use]
    pub const fn caller_override(self) -> Option<SourceEncoding> {
        self.caller_override
    }
}

/// Complete, auditable result of encoding resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingFacts {
    profile_default: SourceEncoding,
    bom_policy: BomPolicy,
    bom: Option<BomKind>,
    declaration: Option<SourceEncoding>,
    caller_override: Option<SourceEncoding>,
    selected: SourceEncoding,
}

impl EncodingFacts {
    /// Validates a structurally complete encoding-facts claim.
    ///
    /// This proves resolution consistency only. A source decoder must still
    /// verify that the claimed BOM is present in the supplied raw bytes.
    pub fn from_claim(
        profile_default: SourceEncoding,
        bom: Option<BomKind>,
        declaration: Option<SourceEncoding>,
        caller_override: Option<SourceEncoding>,
        selected: SourceEncoding,
    ) -> Result<Self, SourceError> {
        let request = EncodingRequest {
            profile_default,
            bom_policy: BomPolicy::DetectUnicode,
            declaration,
            caller_override,
        };
        let resolved = resolve_assertions(request, bom)?;
        if resolved.selected != selected {
            return Err(SourceError::EncodingConflict {
                bom: bom.map(BomKind::encoding),
                declaration,
                caller_override,
            });
        }
        Ok(resolved)
    }

    /// Validates a source-v2 claim including explicit BOM interpretation.
    pub fn from_claim_with_bom_policy(
        profile_default: SourceEncoding,
        bom_policy: BomPolicy,
        bom: Option<BomKind>,
        declaration: Option<SourceEncoding>,
        caller_override: Option<SourceEncoding>,
        selected: SourceEncoding,
    ) -> Result<Self, SourceError> {
        if bom_policy == BomPolicy::TreatAsContent && bom.is_some() {
            return Err(SourceError::EncodingConflict {
                bom: bom.map(BomKind::encoding),
                declaration,
                caller_override,
            });
        }
        let request = EncodingRequest {
            profile_default,
            bom_policy,
            declaration,
            caller_override,
        };
        let resolved = resolve_assertions(request, bom)?;
        if resolved.selected != selected {
            return Err(SourceError::EncodingConflict {
                bom: bom.map(BomKind::encoding),
                declaration,
                caller_override,
            });
        }
        Ok(resolved)
    }

    /// Profile fallback that participated in resolution.
    #[must_use]
    pub const fn profile_default(self) -> SourceEncoding {
        self.profile_default
    }

    /// BOM interpretation policy used for this source.
    #[must_use]
    pub const fn bom_policy(self) -> BomPolicy {
        self.bom_policy
    }

    /// Recognized byte-order mark.
    #[must_use]
    pub const fn bom(self) -> Option<BomKind> {
        self.bom
    }

    /// Normalized in-source declaration.
    #[must_use]
    pub const fn declaration(self) -> Option<SourceEncoding> {
        self.declaration
    }

    /// Explicit caller override.
    #[must_use]
    pub const fn caller_override(self) -> Option<SourceEncoding> {
        self.caller_override
    }

    /// Encoding selected by the frozen priority rule.
    #[must_use]
    pub const fn selected(self) -> SourceEncoding {
        self.selected
    }

    pub(crate) const fn resolution_request(self) -> EncodingRequest {
        EncodingRequest {
            profile_default: self.profile_default,
            bom_policy: self.bom_policy,
            declaration: self.declaration,
            caller_override: self.caller_override,
        }
    }
}

/// Resource bounds applied while a source snapshot is constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLimits {
    /// Maximum retained raw bytes.
    pub max_raw_bytes: usize,
    /// Maximum decoded UTF-8 bytes.
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalar values.
    pub max_decoded_scalars: usize,
}

impl SourceLimits {
    /// Compatibility limits for already-bounded format parsers.
    pub const UNBOUNDED: Self = Self {
        max_raw_bytes: usize::MAX,
        max_decoded_utf8_bytes: usize::MAX,
        max_decoded_scalars: usize::MAX,
    };
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self {
            max_raw_bytes: 64 * 1024 * 1024,
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
        }
    }
}

/// One exact boundary expressed in every supported coordinate system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedPosition {
    /// Offset in retained raw source bytes.
    pub raw_byte: usize,
    /// Offset in the UTF-8 representation of decoded text.
    pub decoded_utf8_byte: usize,
    /// Number of decoded Unicode scalar values.
    pub unicode_scalar_offset: usize,
    /// Number of UTF-16 code units in decoded text.
    pub utf16_code_unit_offset: usize,
}

/// A decoded coordinate to resolve back to an exact raw-byte boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedOffset {
    /// UTF-8 byte offset in decoded text.
    Utf8Byte(usize),
    /// Unicode scalar offset in decoded text.
    UnicodeScalar(usize),
    /// UTF-16 code-unit offset in decoded text.
    Utf16CodeUnit(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundaryCheckpoint(DecodedPosition);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawBoundaryStep(u8);

impl RawBoundaryStep {
    const EXACT_MASK: u8 = 1 << 7;

    const fn new(raw_advance: u8, exact_after: bool) -> Self {
        debug_assert!(raw_advance < Self::EXACT_MASK);
        Self(raw_advance | if exact_after { Self::EXACT_MASK } else { 0 })
    }

    const fn raw_advance(self) -> u8 {
        self.0 & !Self::EXACT_MASK
    }

    const fn exact_after(self) -> bool {
        self.0 & Self::EXACT_MASK != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedIndex {
    checkpoints: Arc<[BoundaryCheckpoint]>,
    terminal: DecodedPosition,
    variable_steps: Option<Arc<[RawBoundaryStep]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedStorage {
    RawUtf8,
    Owned(Arc<str>),
    None,
}

/// Immutable ownership of exact raw bytes plus explicitly derived text facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshot {
    bytes: Arc<[u8]>,
    digest: ContentDigest,
    encoding: EncodingFacts,
    decoded: DecodedStorage,
    decoded_index: Option<DecodedIndex>,
}

impl SourceSnapshot {
    /// Constructs a source from raw bytes using explicit resolution inputs and limits.
    pub fn from_raw(
        bytes: impl Into<Arc<[u8]>>,
        request: EncodingRequest,
        limits: SourceLimits,
    ) -> Result<Self, SourceError> {
        let bytes = bytes.into();
        check_limit("raw-bytes", bytes.len(), limits.max_raw_bytes)?;
        let encoding = resolve_encoding(&bytes, request)?;
        let digest = ContentDigest::of(&bytes);

        let (decoded, variable_steps) = match encoding.selected {
            SourceEncoding::Binary => (DecodedStorage::None, None),
            SourceEncoding::Utf8 => {
                std::str::from_utf8(&bytes).map_err(|error| SourceError::InvalidSequence {
                    encoding: SourceEncoding::Utf8,
                    byte_offset: error.valid_up_to(),
                })?;
                (DecodedStorage::RawUtf8, None)
            }
            SourceEncoding::Utf16Le => (
                DecodedStorage::Owned(decode_utf16(&bytes, true, limits)?),
                None,
            ),
            SourceEncoding::Utf16Be => (
                DecodedStorage::Owned(decode_utf16(&bytes, false, limits)?),
                None,
            ),
            SourceEncoding::Latin1 => (DecodedStorage::Owned(decode_latin1(&bytes, limits)?), None),
            SourceEncoding::WindowsCodePage(code_page) => {
                let decoded = decode_windows_code_page(&bytes, code_page, limits)?;
                (DecodedStorage::Owned(decoded.text), Some(decoded.steps))
            }
        };
        let decoded_index = match &decoded {
            DecodedStorage::None => None,
            DecodedStorage::RawUtf8 => Some(build_index(
                std::str::from_utf8(&bytes).expect("UTF-8 was validated"),
                encoding.selected,
                bytes.len(),
                limits,
                variable_steps.clone(),
            )?),
            DecodedStorage::Owned(text) => Some(build_index(
                text,
                encoding.selected,
                bytes.len(),
                limits,
                variable_steps,
            )?),
        };

        Ok(Self {
            bytes,
            digest,
            encoding,
            decoded,
            decoded_index,
        })
    }

    /// Compatibility constructor for exact UTF-8 sources.
    pub fn from_utf8(bytes: impl Into<Arc<[u8]>>) -> Result<Self, SourceError> {
        Self::from_raw(
            bytes,
            EncodingRequest::new(SourceEncoding::Utf8).with_caller_override(SourceEncoding::Utf8),
            SourceLimits::UNBOUNDED,
        )
        .map_err(|error| match error {
            SourceError::InvalidSequence {
                encoding: SourceEncoding::Utf8,
                byte_offset,
            } => SourceError::InvalidUtf8 {
                valid_up_to: byte_offset,
            },
            other => other,
        })
    }

    /// Constructs an opaque binary source without decoding or BOM interpretation.
    pub fn from_binary(
        bytes: impl Into<Arc<[u8]>>,
        limits: SourceLimits,
    ) -> Result<Self, SourceError> {
        Self::from_raw(bytes, EncodingRequest::binary(), limits)
    }

    /// Exact retained source bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Stable SHA-256 identity of exact retained bytes.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Complete encoding-resolution facts.
    #[must_use]
    pub const fn encoding_facts(&self) -> EncodingFacts {
        self.encoding
    }

    /// Decoded text, or `None` for an opaque binary source.
    #[must_use]
    pub fn decoded_text(&self) -> Option<&str> {
        match &self.decoded {
            DecodedStorage::RawUtf8 => {
                Some(std::str::from_utf8(&self.bytes).expect("UTF-8 was validated"))
            }
            DecodedStorage::Owned(text) => Some(text),
            DecodedStorage::None => None,
        }
    }

    /// Source byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the source is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Resolves one raw byte offset only when it is a decoded scalar boundary.
    pub fn decoded_position(&self, raw_byte: usize) -> Result<DecodedPosition, LocationError> {
        if raw_byte > self.bytes.len() {
            return Err(LocationError::OutOfBounds);
        }
        let text = self.decoded_text().ok_or(LocationError::NoDecodedText)?;
        let index = self
            .decoded_index
            .as_ref()
            .expect("decoded text always has an index");
        let checkpoint =
            last_checkpoint(&index.checkpoints, |position| position.raw_byte <= raw_byte);
        scan_to_raw(
            text,
            self.encoding.selected,
            index.variable_steps.as_deref(),
            checkpoint.0,
            raw_byte,
        )
    }

    /// Resolves one decoded offset only when it denotes a scalar boundary.
    pub fn raw_byte_at(&self, offset: DecodedOffset) -> Result<usize, LocationError> {
        let text = self.decoded_text().ok_or(LocationError::NoDecodedText)?;
        let index = self
            .decoded_index
            .as_ref()
            .expect("decoded text always has an index");
        let requested = offset_value(index.terminal, offset);
        if requested.0 > requested.1 {
            return Err(LocationError::OutOfBounds);
        }
        let checkpoint = last_checkpoint(&index.checkpoints, |position| {
            offset_component(position, offset) <= requested.0
        });
        let position = scan_to_decoded(
            text,
            self.encoding.selected,
            index.variable_steps.as_deref(),
            checkpoint.0,
            offset,
        )?;
        Ok(position.raw_byte)
    }
}

/// Stable source construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// Compatibility error returned by `SourceSnapshot::from_utf8`.
    InvalidUtf8 {
        /// Prefix length that was valid UTF-8.
        valid_up_to: usize,
    },
    /// Raw bytes are not a valid sequence in the selected encoding.
    InvalidSequence {
        /// Selected encoding.
        encoding: SourceEncoding,
        /// First byte at which a valid sequence could not be formed.
        byte_offset: usize,
    },
    /// BOM, declaration, and caller inputs made contradictory assertions.
    EncodingConflict {
        /// BOM-derived encoding.
        bom: Option<SourceEncoding>,
        /// Declaration-derived encoding.
        declaration: Option<SourceEncoding>,
        /// Caller-selected encoding.
        caller_override: Option<SourceEncoding>,
    },
    /// A UTF-32 byte-order mark is recognized but unsupported by v1.
    UnsupportedBom {
        /// Stable unsupported marker identifier.
        kind: UnsupportedBomKind,
    },
    /// A configured construction bound was exceeded.
    ResourceLimit {
        /// Stable limit name.
        name: &'static str,
        /// Observed amount.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Coordinate arithmetic exceeded the host representation.
    OffsetOverflow,
}

impl Display for SourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourceError {}

/// Recognized but unsupported Unicode marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedBomKind {
    /// FF FE 00 00.
    Utf32Le,
    /// 00 00 FE FF.
    Utf32Be,
}

fn resolve_encoding(bytes: &[u8], request: EncodingRequest) -> Result<EncodingFacts, SourceError> {
    let has_explicit_text = request.declaration.is_some_and(SourceEncoding::is_text)
        || request.caller_override.is_some_and(SourceEncoding::is_text);
    let interpret_bom = request.bom_policy == BomPolicy::DetectUnicode
        && (request.profile_default.is_text() || has_explicit_text);
    let bom = if interpret_bom {
        detect_bom(bytes)?
    } else {
        None
    };
    resolve_assertions(request, bom)
}

fn resolve_assertions(
    request: EncodingRequest,
    bom: Option<BomKind>,
) -> Result<EncodingFacts, SourceError> {
    if request.profile_default == SourceEncoding::Binary
        && (request.declaration.is_some_and(SourceEncoding::is_text)
            || request.caller_override.is_some_and(SourceEncoding::is_text))
    {
        return Err(SourceError::EncodingConflict {
            bom: bom.map(BomKind::encoding),
            declaration: request.declaration,
            caller_override: request.caller_override,
        });
    }
    let bom_encoding = bom.map(BomKind::encoding);
    let assertions = [bom_encoding, request.declaration, request.caller_override];
    let expected = assertions.into_iter().flatten().next();
    if expected.is_some_and(|expected| {
        assertions
            .into_iter()
            .flatten()
            .any(|encoding| encoding != expected)
    }) {
        return Err(SourceError::EncodingConflict {
            bom: bom_encoding,
            declaration: request.declaration,
            caller_override: request.caller_override,
        });
    }
    let selected = request
        .caller_override
        .or(request.declaration)
        .or(bom_encoding)
        .unwrap_or(request.profile_default);
    Ok(EncodingFacts {
        profile_default: request.profile_default,
        bom_policy: request.bom_policy,
        bom,
        declaration: request.declaration,
        caller_override: request.caller_override,
        selected,
    })
}

fn detect_bom(bytes: &[u8]) -> Result<Option<BomKind>, SourceError> {
    if bytes.starts_with(&[0xff, 0xfe, 0x00, 0x00]) {
        return Err(SourceError::UnsupportedBom {
            kind: UnsupportedBomKind::Utf32Le,
        });
    }
    if bytes.starts_with(&[0x00, 0x00, 0xfe, 0xff]) {
        return Err(SourceError::UnsupportedBom {
            kind: UnsupportedBomKind::Utf32Be,
        });
    }
    Ok(if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        Some(BomKind::Utf8)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        Some(BomKind::Utf16Le)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Some(BomKind::Utf16Be)
    } else {
        None
    })
}

fn decode_utf16(
    bytes: &[u8],
    little_endian: bool,
    limits: SourceLimits,
) -> Result<Arc<str>, SourceError> {
    if bytes.len() % 2 != 0 {
        return Err(SourceError::InvalidSequence {
            encoding: if little_endian {
                SourceEncoding::Utf16Le
            } else {
                SourceEncoding::Utf16Be
            },
            byte_offset: bytes.len() - 1,
        });
    }
    let encoding = if little_endian {
        SourceEncoding::Utf16Le
    } else {
        SourceEncoding::Utf16Be
    };
    let mut output = String::new();
    let mut offset = 0;
    let mut scalars = 0;
    while offset < bytes.len() {
        let first = read_u16(bytes, offset, little_endian);
        let (scalar, consumed) = if (0xd800..=0xdbff).contains(&first) {
            if offset + 3 >= bytes.len() {
                return Err(SourceError::InvalidSequence {
                    encoding,
                    byte_offset: offset,
                });
            }
            let second = read_u16(bytes, offset + 2, little_endian);
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(SourceError::InvalidSequence {
                    encoding,
                    byte_offset: offset,
                });
            }
            let high = u32::from(first) - 0xd800;
            let low = u32::from(second) - 0xdc00;
            (0x1_0000 + (high << 10) + low, 4)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(SourceError::InvalidSequence {
                encoding,
                byte_offset: offset,
            });
        } else {
            (u32::from(first), 2)
        };
        let character = char::from_u32(scalar).expect("validated UTF-16 forms Unicode scalars");
        scalars = checked_add(scalars, 1)?;
        check_limit("decoded-scalars", scalars, limits.max_decoded_scalars)?;
        let decoded_bytes = checked_add(output.len(), character.len_utf8())?;
        check_limit(
            "decoded-utf8-bytes",
            decoded_bytes,
            limits.max_decoded_utf8_bytes,
        )?;
        output.push(character);
        offset += consumed;
    }
    Ok(Arc::from(output))
}

fn read_u16(bytes: &[u8], offset: usize, little_endian: bool) -> u16 {
    let pair = [bytes[offset], bytes[offset + 1]];
    if little_endian {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    }
}

fn decode_latin1(bytes: &[u8], limits: SourceLimits) -> Result<Arc<str>, SourceError> {
    check_limit("decoded-scalars", bytes.len(), limits.max_decoded_scalars)?;
    let mut output = String::new();
    for &byte in bytes {
        let character = char::from(byte);
        let decoded_bytes = checked_add(output.len(), character.len_utf8())?;
        check_limit(
            "decoded-utf8-bytes",
            decoded_bytes,
            limits.max_decoded_utf8_bytes,
        )?;
        output.push(character);
    }
    Ok(Arc::from(output))
}

struct DecodedWindowsCodePage {
    text: Arc<str>,
    steps: Arc<[RawBoundaryStep]>,
}

fn decode_windows_code_page(
    bytes: &[u8],
    code_page: WindowsCodePage,
    limits: SourceLimits,
) -> Result<DecodedWindowsCodePage, SourceError> {
    let source_encoding = SourceEncoding::WindowsCodePage(code_page);
    let mut decoder = code_page.encoding().new_decoder_without_bom_handling();
    let mut output = String::new();
    let mut steps = Vec::new();
    let mut pending_bytes = 0usize;
    let mut pending_start = 0usize;

    for (offset, byte) in bytes.iter().enumerate() {
        if pending_bytes == 0 {
            pending_start = offset;
        }
        let previous_len = output.len();
        output
            .try_reserve(16)
            .map_err(|_| SourceError::OffsetOverflow)?;
        let (result, read) = decoder.decode_to_string_without_replacement(
            std::slice::from_ref(byte),
            &mut output,
            false,
        );
        check_limit(
            "decoded-utf8-bytes",
            output.len(),
            limits.max_decoded_utf8_bytes,
        )?;
        pending_bytes = checked_add(pending_bytes, read)?;
        append_variable_steps(
            &output[previous_len..],
            &mut steps,
            &mut pending_bytes,
            limits,
        )?;
        match result {
            DecoderResult::InputEmpty if read == 1 => {}
            DecoderResult::Malformed(_, _) => {
                return Err(SourceError::InvalidSequence {
                    encoding: source_encoding,
                    byte_offset: pending_start,
                });
            }
            DecoderResult::OutputFull | DecoderResult::InputEmpty => {
                return Err(SourceError::OffsetOverflow);
            }
        }
    }

    let previous_len = output.len();
    output
        .try_reserve(16)
        .map_err(|_| SourceError::OffsetOverflow)?;
    let (result, read) = decoder.decode_to_string_without_replacement(&[], &mut output, true);
    debug_assert_eq!(read, 0);
    append_variable_steps(
        &output[previous_len..],
        &mut steps,
        &mut pending_bytes,
        limits,
    )?;
    match result {
        DecoderResult::InputEmpty if pending_bytes == 0 => {}
        DecoderResult::Malformed(_, _) => {
            return Err(SourceError::InvalidSequence {
                encoding: source_encoding,
                byte_offset: pending_start,
            });
        }
        DecoderResult::OutputFull | DecoderResult::InputEmpty => {
            return Err(SourceError::OffsetOverflow);
        }
    }
    check_limit(
        "decoded-utf8-bytes",
        output.len(),
        limits.max_decoded_utf8_bytes,
    )?;
    debug_assert_eq!(
        steps
            .iter()
            .map(|step| usize::from(step.raw_advance()))
            .sum::<usize>(),
        bytes.len()
    );
    Ok(DecodedWindowsCodePage {
        text: Arc::from(output),
        steps: Arc::from(steps),
    })
}

fn append_variable_steps(
    decoded: &str,
    steps: &mut Vec<RawBoundaryStep>,
    pending_bytes: &mut usize,
    limits: SourceLimits,
) -> Result<(), SourceError> {
    let emitted = decoded.chars().count();
    if emitted == 0 {
        return Ok(());
    }
    let raw_advance = u8::try_from(*pending_bytes).map_err(|_| SourceError::OffsetOverflow)?;
    if raw_advance == 0 {
        return Err(SourceError::OffsetOverflow);
    }
    for _ in 1..emitted {
        steps.push(RawBoundaryStep::new(0, false));
    }
    steps.push(RawBoundaryStep::new(raw_advance, true));
    *pending_bytes = 0;
    check_limit("decoded-scalars", steps.len(), limits.max_decoded_scalars)
}

fn build_index(
    text: &str,
    encoding: SourceEncoding,
    raw_len: usize,
    limits: SourceLimits,
    variable_steps: Option<Arc<[RawBoundaryStep]>>,
) -> Result<DecodedIndex, SourceError> {
    check_limit(
        "decoded-utf8-bytes",
        text.len(),
        limits.max_decoded_utf8_bytes,
    )?;
    let mut current = DecodedPosition {
        raw_byte: 0,
        decoded_utf8_byte: 0,
        unicode_scalar_offset: 0,
        utf16_code_unit_offset: 0,
    };
    let mut checkpoints = vec![BoundaryCheckpoint(current)];
    if let Some(steps) = &variable_steps {
        if steps.len() != text.chars().count() {
            return Err(SourceError::OffsetOverflow);
        }
    }
    for character in text.chars() {
        let step = raw_step(
            encoding,
            variable_steps.as_deref(),
            current.unicode_scalar_offset,
            character,
        );
        advance(&mut current, character, step.raw_advance())?;
        check_limit(
            "decoded-scalars",
            current.unicode_scalar_offset,
            limits.max_decoded_scalars,
        )?;
        if step.exact_after() && current.unicode_scalar_offset % CHECKPOINT_STRIDE == 0 {
            checkpoints.push(BoundaryCheckpoint(current));
        }
    }
    debug_assert_eq!(current.decoded_utf8_byte, text.len());
    debug_assert_eq!(current.raw_byte, raw_len);
    if checkpoints.last().map(|item| item.0) != Some(current) {
        checkpoints.push(BoundaryCheckpoint(current));
    }
    Ok(DecodedIndex {
        checkpoints: Arc::from(checkpoints),
        terminal: current,
        variable_steps,
    })
}

fn advance(
    position: &mut DecodedPosition,
    character: char,
    raw_width: u8,
) -> Result<(), SourceError> {
    position.raw_byte = checked_add(position.raw_byte, usize::from(raw_width))?;
    position.decoded_utf8_byte = checked_add(position.decoded_utf8_byte, character.len_utf8())?;
    position.unicode_scalar_offset = checked_add(position.unicode_scalar_offset, 1)?;
    position.utf16_code_unit_offset =
        checked_add(position.utf16_code_unit_offset, character.len_utf16())?;
    Ok(())
}

fn last_checkpoint(
    checkpoints: &[BoundaryCheckpoint],
    predicate: impl Fn(DecodedPosition) -> bool,
) -> BoundaryCheckpoint {
    let index = checkpoints.partition_point(|checkpoint| predicate(checkpoint.0));
    checkpoints[index.saturating_sub(1)]
}

fn scan_to_raw(
    text: &str,
    encoding: SourceEncoding,
    variable_steps: Option<&[RawBoundaryStep]>,
    mut position: DecodedPosition,
    requested: usize,
) -> Result<DecodedPosition, LocationError> {
    if position.raw_byte == requested {
        return Ok(position);
    }
    for character in text[position.decoded_utf8_byte..].chars() {
        let step = raw_step(
            encoding,
            variable_steps,
            position.unicode_scalar_offset,
            character,
        );
        advance_location(&mut position, character, step.raw_advance());
        if step.exact_after() && position.raw_byte == requested {
            return Ok(position);
        }
        if position.raw_byte > requested {
            return Err(LocationError::NotDecodedBoundary);
        }
    }
    Err(LocationError::OutOfBounds)
}

fn scan_to_decoded(
    text: &str,
    encoding: SourceEncoding,
    variable_steps: Option<&[RawBoundaryStep]>,
    mut position: DecodedPosition,
    requested: DecodedOffset,
) -> Result<DecodedPosition, LocationError> {
    let target = offset_component_from_request(requested);
    if offset_component(position, requested) == target {
        return Ok(position);
    }
    for character in text[position.decoded_utf8_byte..].chars() {
        let step = raw_step(
            encoding,
            variable_steps,
            position.unicode_scalar_offset,
            character,
        );
        advance_location(&mut position, character, step.raw_advance());
        let observed = offset_component(position, requested);
        if observed == target {
            return if step.exact_after() {
                Ok(position)
            } else {
                Err(LocationError::DecodedOffsetNotBoundary)
            };
        }
        if observed > target {
            return Err(LocationError::DecodedOffsetNotBoundary);
        }
    }
    Err(LocationError::OutOfBounds)
}

fn advance_location(position: &mut DecodedPosition, character: char, raw_width: u8) {
    position.raw_byte += usize::from(raw_width);
    position.decoded_utf8_byte += character.len_utf8();
    position.unicode_scalar_offset += 1;
    position.utf16_code_unit_offset += character.len_utf16();
}

fn raw_step(
    encoding: SourceEncoding,
    variable_steps: Option<&[RawBoundaryStep]>,
    scalar_offset: usize,
    character: char,
) -> RawBoundaryStep {
    if let Some(steps) = variable_steps {
        return steps[scalar_offset];
    }
    let raw_advance = match encoding {
        SourceEncoding::Utf8 => character.len_utf8(),
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => character.len_utf16() * 2,
        SourceEncoding::Latin1 => 1,
        SourceEncoding::WindowsCodePage(_) => {
            unreachable!("Windows code-page sources carry exact variable boundary steps")
        }
        SourceEncoding::Binary => unreachable!("binary source has no decoded locations"),
    };
    RawBoundaryStep::new(
        u8::try_from(raw_advance).expect("fixed source scalar width fits u8"),
        true,
    )
}

fn offset_value(terminal: DecodedPosition, offset: DecodedOffset) -> (usize, usize) {
    (
        offset_component_from_request(offset),
        offset_component(terminal, offset),
    )
}

const fn offset_component(position: DecodedPosition, offset: DecodedOffset) -> usize {
    match offset {
        DecodedOffset::Utf8Byte(_) => position.decoded_utf8_byte,
        DecodedOffset::UnicodeScalar(_) => position.unicode_scalar_offset,
        DecodedOffset::Utf16CodeUnit(_) => position.utf16_code_unit_offset,
    }
}

const fn offset_component_from_request(offset: DecodedOffset) -> usize {
    match offset {
        DecodedOffset::Utf8Byte(value)
        | DecodedOffset::UnicodeScalar(value)
        | DecodedOffset::Utf16CodeUnit(value) => value,
    }
}

fn check_limit(name: &'static str, observed: usize, limit: usize) -> Result<(), SourceError> {
    if observed > limit {
        Err(SourceError::ResourceLimit {
            name,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, SourceError> {
    left.checked_add(right).ok_or(SourceError::OffsetOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(bytes: &[u8], encoding: SourceEncoding) -> SourceSnapshot {
        SourceSnapshot::from_raw(
            Arc::<[u8]>::from(bytes),
            EncodingRequest::new(encoding),
            SourceLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn sha256_content_identity_uses_exact_raw_bytes() {
        assert_eq!(
            ContentDigest::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ContentDigest::of(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(ContentDigest::of(b"abc").algorithm(), "sha256");
        assert_eq!(
            source(b"same", SourceEncoding::Utf8).digest(),
            source(b"same", SourceEncoding::Utf8).digest()
        );
    }

    #[test]
    fn decodes_all_v1_text_encodings_without_losing_raw_bytes() {
        let cases: &[(&[u8], SourceEncoding, &str)] = &[
            (b"A\xc3\xa9", SourceEncoding::Utf8, "Aé"),
            (&[0x41, 0x00, 0xe9, 0x00], SourceEncoding::Utf16Le, "Aé"),
            (&[0x00, 0x41, 0x00, 0xe9], SourceEncoding::Utf16Be, "Aé"),
            (&[0x41, 0xe9], SourceEncoding::Latin1, "Aé"),
        ];
        for &(bytes, encoding, expected) in cases {
            let snapshot = source(bytes, encoding);
            assert_eq!(snapshot.bytes(), bytes);
            assert_eq!(snapshot.decoded_text(), Some(expected));
            assert_eq!(snapshot.encoding_facts().selected(), encoding);
        }
    }

    #[test]
    fn bom_is_retained_as_decoded_scalar_and_recorded() {
        let snapshot = source(&[0xff, 0xfe, 0x41, 0x00], SourceEncoding::Utf16Le);
        assert_eq!(snapshot.decoded_text(), Some("\u{feff}A"));
        assert_eq!(snapshot.encoding_facts().bom(), Some(BomKind::Utf16Le));
        assert_eq!(
            snapshot.decoded_position(2).unwrap().unicode_scalar_offset,
            1
        );
    }

    #[test]
    fn rejects_conflicts_unsupported_boms_and_invalid_sequences() {
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0xff, 0xfe, 0x41, 0x00]),
                EncodingRequest::new(SourceEncoding::Utf8)
                    .with_caller_override(SourceEncoding::Utf8),
                SourceLimits::default()
            ),
            Err(SourceError::EncodingConflict { .. })
        ));
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0xff, 0xfe, 0x00, 0x00]),
                EncodingRequest::new(SourceEncoding::Utf8),
                SourceLimits::default()
            ),
            Err(SourceError::UnsupportedBom { .. })
        ));
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0x00, 0xd8]),
                EncodingRequest::new(SourceEncoding::Utf16Le),
                SourceLimits::default()
            ),
            Err(SourceError::InvalidSequence { byte_offset: 0, .. })
        ));
    }

    #[test]
    fn location_conversion_requires_exact_scalar_boundaries() {
        let snapshot = source("A😀é".as_bytes(), SourceEncoding::Utf8);
        assert_eq!(
            snapshot.decoded_position(5).unwrap(),
            DecodedPosition {
                raw_byte: 5,
                decoded_utf8_byte: 5,
                unicode_scalar_offset: 2,
                utf16_code_unit_offset: 3,
            }
        );
        assert_eq!(
            snapshot.decoded_position(2),
            Err(LocationError::NotDecodedBoundary)
        );
        assert_eq!(snapshot.raw_byte_at(DecodedOffset::UnicodeScalar(2)), Ok(5));
        assert_eq!(
            snapshot.raw_byte_at(DecodedOffset::Utf16CodeUnit(2)),
            Err(LocationError::DecodedOffsetNotBoundary)
        );
        assert_eq!(
            snapshot.raw_byte_at(DecodedOffset::Utf8Byte(2)),
            Err(LocationError::DecodedOffsetNotBoundary)
        );
    }

    #[test]
    fn utf16_locations_account_for_surrogate_pairs() {
        let snapshot = source(
            &[0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0xe9, 0x00],
            SourceEncoding::Utf16Le,
        );
        assert_eq!(snapshot.decoded_text(), Some("A😀é"));
        assert_eq!(
            snapshot.decoded_position(6).unwrap(),
            DecodedPosition {
                raw_byte: 6,
                decoded_utf8_byte: 5,
                unicode_scalar_offset: 2,
                utf16_code_unit_offset: 3,
            }
        );
        assert_eq!(
            snapshot.decoded_position(4),
            Err(LocationError::NotDecodedBoundary)
        );
        assert_eq!(snapshot.raw_byte_at(DecodedOffset::Utf16CodeUnit(3)), Ok(6));
    }

    #[test]
    fn checkpointed_locations_remain_exact_beyond_one_stride() {
        let text = format!("{}😀tail", "a".repeat(CHECKPOINT_STRIDE + 7));
        let snapshot = source(text.as_bytes(), SourceEncoding::Utf8);
        let raw = CHECKPOINT_STRIDE + 7 + 4;
        assert_eq!(
            snapshot
                .decoded_position(raw)
                .unwrap()
                .unicode_scalar_offset,
            CHECKPOINT_STRIDE + 8
        );
        assert_eq!(
            snapshot.raw_byte_at(DecodedOffset::UnicodeScalar(CHECKPOINT_STRIDE + 8)),
            Ok(raw)
        );
    }

    #[test]
    fn binary_source_has_no_decoded_claims() {
        let snapshot = SourceSnapshot::from_binary(
            Arc::<[u8]>::from([0xff, 0xfe, 0x00, 0x00]),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.bytes(), &[0xff, 0xfe, 0x00, 0x00]);
        assert_eq!(snapshot.decoded_text(), None);
        assert_eq!(
            snapshot.decoded_position(0),
            Err(LocationError::NoDecodedText)
        );
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from(b"text".as_slice()),
                EncodingRequest::binary().with_caller_override(SourceEncoding::Utf8),
                SourceLimits::default(),
            ),
            Err(SourceError::EncodingConflict { .. })
        ));
    }

    #[test]
    fn source_limits_are_enforced_before_decoding_expands_data() {
        let limits = SourceLimits {
            max_raw_bytes: 2,
            max_decoded_utf8_bytes: 1,
            max_decoded_scalars: 2,
        };
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0x80]),
                EncodingRequest::new(SourceEncoding::Latin1),
                limits
            ),
            Err(SourceError::ResourceLimit {
                name: "decoded-utf8-bytes",
                ..
            })
        ));
    }

    #[test]
    fn source_v2_publishes_only_the_frozen_windows_code_pages() {
        assert_eq!(std::mem::size_of::<RawBoundaryStep>(), 1);
        let expected = [
            874, 932, 936, 949, 950, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 65001,
        ];
        for number in expected {
            let code_page = WindowsCodePage::from_number(number).expect("published code page");
            assert_eq!(code_page.number(), number);
            assert_eq!(
                SourceEncoding::WindowsCodePage(code_page).as_str(),
                format!("windows-{number}")
            );
        }
        for number in [0, 873, 875, 931, 951, 1249, 1259, 65_000, u16::MAX] {
            assert_eq!(WindowsCodePage::from_number(number), None);
        }
    }

    #[test]
    fn windows_code_pages_decode_strictly_with_exact_boundaries() {
        let cp1252 = WindowsCodePage::from_number(1252).unwrap();
        let snapshot = source(&[0x80, b'A'], SourceEncoding::WindowsCodePage(cp1252));
        assert_eq!(snapshot.decoded_text(), Some("€A"));
        assert_eq!(
            snapshot.decoded_position(1).unwrap(),
            DecodedPosition {
                raw_byte: 1,
                decoded_utf8_byte: 3,
                unicode_scalar_offset: 1,
                utf16_code_unit_offset: 1,
            }
        );

        let cp932 = SourceEncoding::WindowsCodePage(WindowsCodePage::from_number(932).unwrap());
        assert_eq!(source(&[0x82, 0xa0], cp932).decoded_text(), Some("あ"));
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0x82]),
                EncodingRequest::new(cp932).with_bom_policy(BomPolicy::TreatAsContent),
                SourceLimits::default(),
            ),
            Err(SourceError::InvalidSequence { byte_offset: 0, .. })
        ));

        let cp65001 = SourceEncoding::WindowsCodePage(WindowsCodePage::from_number(65001).unwrap());
        assert!(matches!(
            SourceSnapshot::from_raw(
                Arc::<[u8]>::from([0xff]),
                EncodingRequest::new(cp65001).with_bom_policy(BomPolicy::TreatAsContent),
                SourceLimits::default(),
            ),
            Err(SourceError::InvalidSequence { byte_offset: 0, .. })
        ));
    }

    #[test]
    fn multiscalar_big5_mapping_exposes_only_real_raw_boundaries() {
        let big5 = SourceEncoding::WindowsCodePage(WindowsCodePage::from_number(950).unwrap());
        let snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from([0x88, 0x62]),
            EncodingRequest::new(big5).with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.decoded_text(), Some("Ê\u{0304}"));
        assert_eq!(
            snapshot.raw_byte_at(DecodedOffset::UnicodeScalar(1)),
            Err(LocationError::DecodedOffsetNotBoundary)
        );
        assert_eq!(
            snapshot.decoded_position(1),
            Err(LocationError::NotDecodedBoundary)
        );
        assert_eq!(snapshot.raw_byte_at(DecodedOffset::UnicodeScalar(2)), Ok(2));
        assert_eq!(
            snapshot.decoded_position(2).unwrap().unicode_scalar_offset,
            2
        );
    }

    #[test]
    fn bom_policy_keeps_legacy_marker_bytes_as_content() {
        let bytes = Arc::<[u8]>::from([0xef, 0xbb, 0xbf]);
        let detected = SourceSnapshot::from_raw(
            bytes.clone(),
            EncodingRequest::new(SourceEncoding::Latin1),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(detected.encoding_facts().selected(), SourceEncoding::Utf8);
        assert_eq!(detected.encoding_facts().bom(), Some(BomKind::Utf8));
        assert_eq!(detected.decoded_text(), Some("\u{feff}"));
        let latin1 = SourceSnapshot::from_raw(
            bytes,
            EncodingRequest::new(SourceEncoding::Latin1).with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(latin1.decoded_text(), Some("ï»¿"));
        assert_eq!(latin1.encoding_facts().bom(), None);
        assert_eq!(
            latin1.encoding_facts().bom_policy(),
            BomPolicy::TreatAsContent
        );

        assert!(
            EncodingFacts::from_claim_with_bom_policy(
                SourceEncoding::Latin1,
                BomPolicy::TreatAsContent,
                Some(BomKind::Utf8),
                None,
                None,
                SourceEncoding::Latin1,
            )
            .is_err()
        );
    }
}
