//! Transferable raw source snapshots and verifiable source patches.

use crate::schema::{
    boolean, exact_fields, integer_u64, object, schema_fields, sequence, string, unsigned_u32,
    unsigned_u64,
};
use crate::{ProtocolError, ProtocolErrorKind};
use consema_core::{ObjectBuilder, PortableValue, SequenceBuilder};
use consema_document::{
    BomKind, BomPolicy, ContentDigest, EncodingFacts, EncodingRequest, SourceEncoding, SourceError,
    SourceLimits, SourcePatch, SourcePatchError, SourcePatchLimits, SourceReplacement,
    SourceSnapshot,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Transferable `core.source-encoding@1` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceEncodingMessage {
    encoding: SourceEncoding,
}

impl SourceEncodingMessage {
    /// Wraps one normalized source encoding.
    #[must_use]
    pub const fn from_encoding(encoding: SourceEncoding) -> Self {
        Self { encoding }
    }

    /// Normalized source encoding.
    #[must_use]
    pub const fn encoding(self) -> SourceEncoding {
        self.encoding
    }

    /// Encodes the exact standalone source-encoding schema.
    #[must_use]
    pub fn to_value(self) -> PortableValue {
        source_encoding_value(self.encoding)
    }

    /// Strictly decodes one canonical source-encoding value.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        source_encoding_from_value(value, "$").map(Self::from_encoding)
    }
}

/// Transferable `core.source-snapshot@1` content fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshotMessage {
    snapshot: SourceSnapshot,
}

impl SourceSnapshotMessage {
    /// Copies one immutable snapshot into a transferable content message.
    pub fn from_snapshot(snapshot: &SourceSnapshot) -> Result<Self, ProtocolError> {
        ensure_v1_encoding_facts(snapshot.encoding_facts(), "$.encoding")?;
        Ok(Self {
            snapshot: snapshot.clone(),
        })
    }

    /// Verified immutable source snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &SourceSnapshot {
        &self.snapshot
    }

    /// Consumes the message and returns its verified snapshot.
    #[must_use]
    pub fn into_snapshot(self) -> SourceSnapshot {
        self.snapshot
    }

    /// Encodes the fixed-field PortableValue schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        source_snapshot_value(
            &self.snapshot,
            "core.source-snapshot@1",
            encoding_value(self.snapshot.encoding_facts()),
        )
    }

    /// Strictly decodes and re-verifies raw bytes, digest, encoding, and decoded status.
    pub fn from_value(value: &PortableValue, limits: SourceLimits) -> Result<Self, ProtocolError> {
        source_snapshot_from_value(
            value,
            "core.source-snapshot@1",
            encoding_from_value,
            request_from_facts,
            limits,
        )
        .map(|snapshot| Self { snapshot })
    }
}

/// Transferable `core.source-snapshot@2` content fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshotMessageV2 {
    snapshot: SourceSnapshot,
}

impl SourceSnapshotMessageV2 {
    /// Copies one immutable snapshot into a source-v2 message.
    #[must_use]
    pub fn from_snapshot(snapshot: &SourceSnapshot) -> Self {
        Self {
            snapshot: snapshot.clone(),
        }
    }

    /// Verified immutable source snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &SourceSnapshot {
        &self.snapshot
    }

    /// Consumes the message and returns its verified snapshot.
    #[must_use]
    pub fn into_snapshot(self) -> SourceSnapshot {
        self.snapshot
    }

    /// Encodes the exact source-snapshot v2 schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        source_snapshot_value(
            &self.snapshot,
            "core.source-snapshot@2",
            encoding_value_v2(self.snapshot.encoding_facts()),
        )
    }

    /// Strictly decodes and re-verifies every source-v2 fact.
    pub fn from_value(value: &PortableValue, limits: SourceLimits) -> Result<Self, ProtocolError> {
        source_snapshot_from_value(
            value,
            "core.source-snapshot@2",
            encoding_from_value_v2,
            request_from_facts_v2,
            limits,
        )
        .map(|snapshot| Self { snapshot })
    }
}

/// Transferable `core.source-patch@1` verification facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePatchMessage {
    patch: SourcePatch,
}

impl SourcePatchMessage {
    /// Copies one validated source patch into a transferable message.
    #[must_use]
    pub fn from_patch(patch: &SourcePatch) -> Self {
        Self {
            patch: patch.clone(),
        }
    }

    /// Validated source patch.
    #[must_use]
    pub const fn patch(&self) -> &SourcePatch {
        &self.patch
    }

    /// Consumes the message and returns its validated patch.
    #[must_use]
    pub fn into_patch(self) -> SourcePatch {
        self.patch
    }

    /// Encodes the fixed-field PortableValue schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        ensure_v1_encoding_facts(self.patch.encoding_facts(), "$.encoding")?;
        source_patch_value(
            &self.patch,
            "core.source-patch@1",
            encoding_value(self.patch.encoding_facts()),
        )
    }

    /// Strictly decodes structural patch facts without applying them to a base snapshot.
    pub fn from_value(
        value: &PortableValue,
        limits: SourcePatchLimits,
    ) -> Result<Self, ProtocolError> {
        source_patch_from_value(value, "core.source-patch@1", encoding_from_value, limits)
            .map(|patch| Self { patch })
    }
}

/// Transferable `core.source-patch@2` verification facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePatchMessageV2 {
    patch: SourcePatch,
}

impl SourcePatchMessageV2 {
    /// Copies one validated source patch into a source-v2 message.
    #[must_use]
    pub fn from_patch(patch: &SourcePatch) -> Self {
        Self {
            patch: patch.clone(),
        }
    }

    /// Validated source patch.
    #[must_use]
    pub const fn patch(&self) -> &SourcePatch {
        &self.patch
    }

    /// Consumes the message and returns its validated patch.
    #[must_use]
    pub fn into_patch(self) -> SourcePatch {
        self.patch
    }

    /// Encodes the exact source-patch v2 schema.
    pub fn to_value(&self) -> Result<PortableValue, ProtocolError> {
        source_patch_value(
            &self.patch,
            "core.source-patch@2",
            encoding_value_v2(self.patch.encoding_facts()),
        )
    }

    /// Strictly decodes structural source-patch v2 facts.
    pub fn from_value(
        value: &PortableValue,
        limits: SourcePatchLimits,
    ) -> Result<Self, ProtocolError> {
        source_patch_from_value(value, "core.source-patch@2", encoding_from_value_v2, limits)
            .map(|patch| Self { patch })
    }
}

fn source_snapshot_value(
    snapshot: &SourceSnapshot,
    schema: &'static str,
    encoding: PortableValue,
) -> PortableValue {
    object(vec![
        ("schema", PortableValue::string(schema)),
        ("raw_bytes", PortableValue::bytes(snapshot.bytes().to_vec())),
        ("digest", digest_value(snapshot.digest())),
        ("encoding", encoding),
        (
            "decoded_status",
            PortableValue::string(if snapshot.decoded_text().is_some() {
                "Available"
            } else {
                "NotText"
            }),
        ),
    ])
}

fn source_snapshot_from_value(
    value: &PortableValue,
    schema: &'static str,
    parse_encoding: fn(&PortableValue, &str) -> Result<EncodingFacts, ProtocolError>,
    request_from_encoding: fn(EncodingFacts) -> EncodingRequest,
    limits: SourceLimits,
) -> Result<SourceSnapshot, ProtocolError> {
    let fields = schema_fields(
        value,
        schema,
        &[
            "schema",
            "raw_bytes",
            "digest",
            "encoding",
            "decoded_status",
        ],
        "$",
    )?;
    let raw = bytes(fields[1], "$.raw_bytes")?;
    let claimed_digest = digest_from_value(fields[2], "$.digest")?;
    let claimed_encoding = parse_encoding(fields[3], "$.encoding")?;
    let decoded_status = string(fields[4], "$.decoded_status")?;
    if !matches!(decoded_status, "Available" | "NotText") {
        return Err(crate::schema::invalid(
            "$.decoded_status",
            "expected Available or NotText",
        ));
    }
    let snapshot = SourceSnapshot::from_raw(
        Arc::<[u8]>::from(raw),
        request_from_encoding(claimed_encoding),
        limits,
    )
    .map_err(|error| source_error("$.raw_bytes", error))?;
    if snapshot.digest() != claimed_digest {
        return Err(crate::schema::invalid(
            "$.digest",
            "digest does not match raw_bytes",
        ));
    }
    if snapshot.encoding_facts() != claimed_encoding {
        return Err(crate::schema::invalid(
            "$.encoding",
            "encoding facts do not match raw_bytes resolution",
        ));
    }
    let actual_status = if snapshot.decoded_text().is_some() {
        "Available"
    } else {
        "NotText"
    };
    if decoded_status != actual_status {
        return Err(crate::schema::invalid(
            "$.decoded_status",
            "decoded status contradicts selected encoding",
        ));
    }
    Ok(snapshot)
}

fn source_patch_value(
    patch: &SourcePatch,
    schema: &'static str,
    encoding: PortableValue,
) -> Result<PortableValue, ProtocolError> {
    let mut replacements = SequenceBuilder::new();
    for replacement in patch.replacements() {
        let old_start = u64::try_from(replacement.old_start()).map_err(|_| {
            crate::schema::invalid("$.replacements.old_start", "offset exceeds u64")
        })?;
        let old_end = u64::try_from(replacement.old_end())
            .map_err(|_| crate::schema::invalid("$.replacements.old_end", "offset exceeds u64"))?;
        replacements.push(object(vec![
            ("old_start", integer_u64(old_start)),
            ("old_end", integer_u64(old_end)),
            (
                "original",
                PortableValue::bytes(replacement.original().to_vec()),
            ),
            (
                "replacement",
                PortableValue::bytes(replacement.replacement().to_vec()),
            ),
            (
                "redact_original",
                PortableValue::boolean(replacement.redact_original()),
            ),
            (
                "redact_replacement",
                PortableValue::boolean(replacement.redact_replacement()),
            ),
        ]));
    }
    let mut metadata = ObjectBuilder::new();
    for (name, value) in patch.metadata() {
        metadata
            .insert(name, PortableValue::string(value.as_str()))
            .expect("BTreeMap metadata names are unique");
    }
    Ok(object(vec![
        ("schema", PortableValue::string(schema)),
        ("base_digest", digest_value(patch.base_digest())),
        ("target_digest", digest_value(patch.target_digest())),
        ("encoding", encoding),
        ("replacements", replacements.build()),
        ("metadata", metadata.build()),
    ]))
}

fn source_patch_from_value(
    value: &PortableValue,
    schema: &'static str,
    parse_encoding: fn(&PortableValue, &str) -> Result<EncodingFacts, ProtocolError>,
    limits: SourcePatchLimits,
) -> Result<SourcePatch, ProtocolError> {
    let fields = schema_fields(
        value,
        schema,
        &[
            "schema",
            "base_digest",
            "target_digest",
            "encoding",
            "replacements",
            "metadata",
        ],
        "$",
    )?;
    let base_digest = digest_from_value(fields[1], "$.base_digest")?;
    let target_digest = digest_from_value(fields[2], "$.target_digest")?;
    let encoding = parse_encoding(fields[3], "$.encoding")?;
    let replacement_values = sequence(fields[4], "$.replacements")?;
    if replacement_values.len() > limits.max_replacements {
        return Err(ProtocolError::new(
            ProtocolErrorKind::ResourceLimit,
            "$.replacements",
            "replacement count exceeds configured limit",
        ));
    }
    let replacements = replacement_values
        .iter()
        .enumerate()
        .map(|(index, value)| replacement_from_value(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata_entries = fields[5].as_object().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            "$.metadata",
            "expected Object<String, String>",
        )
    })?;
    let mut metadata = BTreeMap::new();
    for entry in metadata_entries {
        metadata.insert(
            entry.key().to_owned(),
            string(entry.value(), &format!("$.metadata.{}", entry.key()))?.to_owned(),
        );
    }
    SourcePatch::new(
        base_digest,
        target_digest,
        encoding,
        replacements,
        metadata,
        limits,
    )
    .map_err(patch_error)
}

fn replacement_from_value(
    value: &PortableValue,
    index: usize,
) -> Result<SourceReplacement, ProtocolError> {
    let path = format!("$.replacements[{index}]");
    let fields = exact_fields(
        value,
        &[
            "old_start",
            "old_end",
            "original",
            "replacement",
            "redact_original",
            "redact_replacement",
        ],
        &path,
    )?;
    let old_start = usize::try_from(unsigned_u64(fields[0], &format!("{path}.old_start"))?)
        .map_err(|_| crate::schema::invalid(&format!("{path}.old_start"), "exceeds usize"))?;
    let old_end = usize::try_from(unsigned_u64(fields[1], &format!("{path}.old_end"))?)
        .map_err(|_| crate::schema::invalid(&format!("{path}.old_end"), "exceeds usize"))?;
    Ok(SourceReplacement::new(
        old_start,
        old_end,
        bytes(fields[2], &format!("{path}.original"))?,
        bytes(fields[3], &format!("{path}.replacement"))?,
    )
    .with_original_redacted(boolean(fields[4], &format!("{path}.redact_original"))?)
    .with_replacement_redacted(boolean(fields[5], &format!("{path}.redact_replacement"))?))
}

fn digest_value(digest: ContentDigest) -> PortableValue {
    object(vec![
        ("algorithm", PortableValue::string(digest.algorithm())),
        ("hex", PortableValue::string(digest.to_hex())),
    ])
}

fn digest_from_value(value: &PortableValue, path: &str) -> Result<ContentDigest, ProtocolError> {
    let fields = exact_fields(value, &["algorithm", "hex"], path)?;
    if string(fields[0], &format!("{path}.algorithm"))? != "sha256" {
        return Err(crate::schema::invalid(
            &format!("{path}.algorithm"),
            "expected sha256",
        ));
    }
    let hex = string(fields[1], &format!("{path}.hex"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::schema::invalid(
            &format!("{path}.hex"),
            "expected 64 lowercase hexadecimal characters",
        ));
    }
    let mut decoded = [0_u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        let pair = &hex[index * 2..index * 2 + 2];
        *output = u8::from_str_radix(pair, 16).expect("validated hexadecimal pair");
    }
    Ok(ContentDigest::from_bytes(decoded))
}

fn source_encoding_value(encoding: SourceEncoding) -> PortableValue {
    let (kind, windows_code_page) = match encoding {
        SourceEncoding::Binary => ("Binary", PortableValue::null()),
        SourceEncoding::Utf8 => ("Utf8", PortableValue::null()),
        SourceEncoding::Utf16Le => ("Utf16Le", PortableValue::null()),
        SourceEncoding::Utf16Be => ("Utf16Be", PortableValue::null()),
        SourceEncoding::Latin1 => ("Latin1", PortableValue::null()),
        SourceEncoding::WindowsCodePage(code_page) => (
            "WindowsCodePage",
            integer_u64(u64::from(code_page.number())),
        ),
    };
    object(vec![
        ("schema", PortableValue::string("core.source-encoding@1")),
        ("kind", PortableValue::string(kind)),
        ("windows_code_page", windows_code_page),
    ])
}

pub(crate) fn source_encoding_from_value(
    value: &PortableValue,
    path: &str,
) -> Result<SourceEncoding, ProtocolError> {
    let fields = schema_fields(
        value,
        "core.source-encoding@1",
        &["schema", "kind", "windows_code_page"],
        path,
    )?;
    let kind = string(fields[1], &format!("{path}.kind"))?;
    let code_page_path = format!("{path}.windows_code_page");
    match kind {
        "Binary" | "Utf8" | "Utf16Le" | "Utf16Be" | "Latin1" => {
            if fields[2] != &PortableValue::null() {
                return Err(crate::schema::invalid(
                    &code_page_path,
                    "non-Windows encoding requires null",
                ));
            }
            Ok(match kind {
                "Binary" => SourceEncoding::Binary,
                "Utf8" => SourceEncoding::Utf8,
                "Utf16Le" => SourceEncoding::Utf16Le,
                "Utf16Be" => SourceEncoding::Utf16Be,
                "Latin1" => SourceEncoding::Latin1,
                _ => unreachable!("matched closed source encoding kind"),
            })
        }
        "WindowsCodePage" => {
            let number = unsigned_u32(fields[2], &code_page_path)?;
            let number = u16::try_from(number).map_err(|_| {
                crate::schema::invalid(&code_page_path, "unsupported Windows code page")
            })?;
            consema_document::WindowsCodePage::from_number(number)
                .map(SourceEncoding::WindowsCodePage)
                .ok_or_else(|| {
                    crate::schema::invalid(&code_page_path, "unsupported Windows code page")
                })
        }
        _ => Err(crate::schema::invalid(
            &format!("{path}.kind"),
            "unknown source encoding kind",
        )),
    }
}

fn encoding_value(facts: EncodingFacts) -> PortableValue {
    object(vec![
        (
            "profile_default",
            PortableValue::string(encoding_name(facts.profile_default())),
        ),
        (
            "bom",
            facts.bom().map_or_else(PortableValue::null, |bom| {
                PortableValue::string(bom_name(bom))
            }),
        ),
        (
            "declaration",
            facts
                .declaration()
                .map_or_else(PortableValue::null, |encoding| {
                    PortableValue::string(encoding_name(encoding))
                }),
        ),
        (
            "caller_override",
            facts
                .caller_override()
                .map_or_else(PortableValue::null, |encoding| {
                    PortableValue::string(encoding_name(encoding))
                }),
        ),
        (
            "selected",
            PortableValue::string(encoding_name(facts.selected())),
        ),
    ])
}

fn encoding_value_v2(facts: EncodingFacts) -> PortableValue {
    object(vec![
        (
            "profile_default",
            source_encoding_value(facts.profile_default()),
        ),
        (
            "bom_policy",
            PortableValue::string(match facts.bom_policy() {
                BomPolicy::DetectUnicode => "DetectUnicode",
                BomPolicy::TreatAsContent => "TreatAsContent",
            }),
        ),
        (
            "bom",
            facts.bom().map_or_else(PortableValue::null, |bom| {
                PortableValue::string(bom_name(bom))
            }),
        ),
        (
            "declaration",
            facts
                .declaration()
                .map_or_else(PortableValue::null, source_encoding_value),
        ),
        (
            "caller_override",
            facts
                .caller_override()
                .map_or_else(PortableValue::null, source_encoding_value),
        ),
        ("selected", source_encoding_value(facts.selected())),
    ])
}

fn ensure_v1_encoding_facts(facts: EncodingFacts, path: &str) -> Result<(), ProtocolError> {
    if facts.bom_policy() != BomPolicy::DetectUnicode {
        return Err(crate::schema::invalid(
            path,
            "core source v1 requires DetectUnicode BOM policy",
        ));
    }
    for encoding in [
        Some(facts.profile_default()),
        facts.declaration(),
        facts.caller_override(),
        Some(facts.selected()),
    ]
    .into_iter()
    .flatten()
    {
        if matches!(encoding, SourceEncoding::WindowsCodePage(_)) {
            return Err(crate::schema::invalid(
                path,
                "core source v1 does not support Windows code pages",
            ));
        }
    }
    Ok(())
}

fn encoding_from_value(value: &PortableValue, path: &str) -> Result<EncodingFacts, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "profile_default",
            "bom",
            "declaration",
            "caller_override",
            "selected",
        ],
        path,
    )?;
    let profile_default =
        encoding_from_name(string(fields[0], &format!("{path}.profile_default"))?)?;
    let bom = optional_bom(fields[1], &format!("{path}.bom"))?;
    let declaration = optional_encoding(fields[2], &format!("{path}.declaration"))?;
    let caller_override = optional_encoding(fields[3], &format!("{path}.caller_override"))?;
    let selected = encoding_from_name(string(fields[4], &format!("{path}.selected"))?)?;
    EncodingFacts::from_claim(profile_default, bom, declaration, caller_override, selected)
        .map_err(|error| source_error(path, error))
}

fn encoding_from_value_v2(
    value: &PortableValue,
    path: &str,
) -> Result<EncodingFacts, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "profile_default",
            "bom_policy",
            "bom",
            "declaration",
            "caller_override",
            "selected",
        ],
        path,
    )?;
    let profile_default =
        source_encoding_from_value(fields[0], &format!("{path}.profile_default"))?;
    let bom_policy = match string(fields[1], &format!("{path}.bom_policy"))? {
        "DetectUnicode" => BomPolicy::DetectUnicode,
        "TreatAsContent" => BomPolicy::TreatAsContent,
        _ => {
            return Err(crate::schema::invalid(
                &format!("{path}.bom_policy"),
                "unknown BOM policy",
            ));
        }
    };
    let bom = optional_bom(fields[2], &format!("{path}.bom"))?;
    let declaration = optional_source_encoding_v2(fields[3], &format!("{path}.declaration"))?;
    let caller_override =
        optional_source_encoding_v2(fields[4], &format!("{path}.caller_override"))?;
    let selected = source_encoding_from_value(fields[5], &format!("{path}.selected"))?;
    EncodingFacts::from_claim_with_bom_policy(
        profile_default,
        bom_policy,
        bom,
        declaration,
        caller_override,
        selected,
    )
    .map_err(|error| source_error(path, error))
}

fn encoding_name(encoding: SourceEncoding) -> &'static str {
    match encoding {
        SourceEncoding::Binary => "Binary",
        SourceEncoding::Utf8 => "Utf8",
        SourceEncoding::Utf16Le => "Utf16Le",
        SourceEncoding::Utf16Be => "Utf16Be",
        SourceEncoding::Latin1 => "Latin1",
        SourceEncoding::WindowsCodePage(_) => {
            unreachable!("core source v1 validation rejects Windows code pages")
        }
    }
}

fn encoding_from_name(name: &str) -> Result<SourceEncoding, ProtocolError> {
    match name {
        "Binary" => Ok(SourceEncoding::Binary),
        "Utf8" => Ok(SourceEncoding::Utf8),
        "Utf16Le" => Ok(SourceEncoding::Utf16Le),
        "Utf16Be" => Ok(SourceEncoding::Utf16Be),
        "Latin1" => Ok(SourceEncoding::Latin1),
        _ => Err(crate::schema::invalid("$.encoding", "unknown encoding ID")),
    }
}

const fn bom_name(bom: BomKind) -> &'static str {
    match bom {
        BomKind::Utf8 => "Utf8",
        BomKind::Utf16Le => "Utf16Le",
        BomKind::Utf16Be => "Utf16Be",
    }
}

fn optional_bom(value: &PortableValue, path: &str) -> Result<Option<BomKind>, ProtocolError> {
    if value == &PortableValue::null() {
        return Ok(None);
    }
    match string(value, path)? {
        "Utf8" => Ok(Some(BomKind::Utf8)),
        "Utf16Le" => Ok(Some(BomKind::Utf16Le)),
        "Utf16Be" => Ok(Some(BomKind::Utf16Be)),
        _ => Err(crate::schema::invalid(path, "unknown BOM ID")),
    }
}

fn optional_encoding(
    value: &PortableValue,
    path: &str,
) -> Result<Option<SourceEncoding>, ProtocolError> {
    if value == &PortableValue::null() {
        Ok(None)
    } else {
        encoding_from_name(string(value, path)?).map(Some)
    }
}

fn optional_source_encoding_v2(
    value: &PortableValue,
    path: &str,
) -> Result<Option<SourceEncoding>, ProtocolError> {
    if value == &PortableValue::null() {
        Ok(None)
    } else {
        source_encoding_from_value(value, path).map(Some)
    }
}

fn request_from_facts(facts: EncodingFacts) -> EncodingRequest {
    let mut request = EncodingRequest::new(facts.profile_default());
    if let Some(declaration) = facts.declaration() {
        request = request.with_declaration(declaration);
    }
    if let Some(caller_override) = facts.caller_override() {
        request = request.with_caller_override(caller_override);
    }
    request
}

fn request_from_facts_v2(facts: EncodingFacts) -> EncodingRequest {
    let mut request =
        EncodingRequest::new(facts.profile_default()).with_bom_policy(facts.bom_policy());
    if let Some(declaration) = facts.declaration() {
        request = request.with_declaration(declaration);
    }
    if let Some(caller_override) = facts.caller_override() {
        request = request.with_caller_override(caller_override);
    }
    request
}

fn bytes(value: &PortableValue, path: &str) -> Result<Vec<u8>, ProtocolError> {
    value
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Bytes"))
}

fn source_error(path: &str, error: SourceError) -> ProtocolError {
    let kind = if matches!(
        error,
        SourceError::ResourceLimit { .. } | SourceError::OffsetOverflow
    ) {
        ProtocolErrorKind::ResourceLimit
    } else {
        ProtocolErrorKind::InvalidValue
    };
    ProtocolError::new(kind, path, error.to_string())
}

fn patch_error(error: SourcePatchError) -> ProtocolError {
    let kind = if matches!(
        error,
        SourcePatchError::ResourceLimit { .. }
            | SourcePatchError::Source(
                SourceError::ResourceLimit { .. } | SourceError::OffsetOverflow
            )
    ) {
        ProtocolErrorKind::ResourceLimit
    } else {
        ProtocolErrorKind::InvalidValue
    };
    ProtocolError::new(kind, "$.replacements", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProtocolLimits, decode_json, decode_pvce, encode_json, encode_pvce};

    #[test]
    fn source_encoding_contract_is_exact_and_canonical() {
        let mut encodings = vec![
            SourceEncoding::Binary,
            SourceEncoding::Utf8,
            SourceEncoding::Utf16Le,
            SourceEncoding::Utf16Be,
            SourceEncoding::Latin1,
        ];
        encodings.extend(
            [
                874, 932, 936, 949, 950, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
                65001,
            ]
            .into_iter()
            .map(|number| {
                SourceEncoding::WindowsCodePage(
                    consema_document::WindowsCodePage::from_number(number).unwrap(),
                )
            }),
        );
        for encoding in encodings {
            let value = SourceEncodingMessage::from_encoding(encoding).to_value();
            for transported in [
                decode_json(
                    &encode_json(&value, ProtocolLimits::default()).unwrap(),
                    ProtocolLimits::default(),
                )
                .unwrap(),
                decode_pvce(
                    &encode_pvce(&value, ProtocolLimits::default()).unwrap(),
                    ProtocolLimits::default(),
                )
                .unwrap(),
            ] {
                let decoded = SourceEncodingMessage::from_value(&transported).unwrap();
                assert_eq!(decoded.encoding(), encoding);
                assert_eq!(decoded.to_value(), value);
            }
        }

        for invalid in [
            object(vec![
                ("schema", PortableValue::string("core.source-encoding@1")),
                ("kind", PortableValue::string("Utf8")),
                ("windows_code_page", integer_u64(65001)),
            ]),
            object(vec![
                ("schema", PortableValue::string("core.source-encoding@1")),
                ("kind", PortableValue::string("WindowsCodePage")),
                ("windows_code_page", PortableValue::null()),
            ]),
            object(vec![
                ("schema", PortableValue::string("core.source-encoding@1")),
                ("kind", PortableValue::string("WindowsCodePage")),
                ("windows_code_page", integer_u64(437)),
            ]),
            object(vec![
                ("schema", PortableValue::string("core.source-encoding@1")),
                ("kind", PortableValue::string("WindowsCodePage")),
                ("windows_code_page", integer_u64(u64::from(u32::MAX) + 1)),
            ]),
            object(vec![
                ("schema", PortableValue::string("core.source-encoding@1")),
                ("kind", PortableValue::string("GBK")),
                ("windows_code_page", integer_u64(936)),
            ]),
        ] {
            assert!(SourceEncodingMessage::from_value(&invalid).is_err());
        }
    }

    #[test]
    fn source_snapshot_round_trips_all_facts_through_both_transports() {
        let snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from([0xff, 0xfe, 0x41, 0x00]),
            EncodingRequest::new(SourceEncoding::Utf16Le),
            SourceLimits::default(),
        )
        .unwrap();
        let message = SourceSnapshotMessage::from_snapshot(&snapshot).unwrap();
        let value = message.to_value();
        for transported in [
            decode_json(
                &encode_json(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
            decode_pvce(
                &encode_pvce(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
        ] {
            let decoded =
                SourceSnapshotMessage::from_value(&transported, SourceLimits::default()).unwrap();
            assert_eq!(decoded.snapshot(), &snapshot);
        }
    }

    #[test]
    fn source_v1_rejects_v2_code_pages_and_bom_policy() {
        let code_page = consema_document::WindowsCodePage::from_number(1252).unwrap();
        let code_page_snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from([0x80]),
            EncodingRequest::new(SourceEncoding::WindowsCodePage(code_page))
                .with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        let error = SourceSnapshotMessage::from_snapshot(&code_page_snapshot).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);

        let patch = SourcePatch::create(
            &code_page_snapshot,
            Vec::new(),
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let error = SourcePatchMessage::from_patch(&patch)
            .to_value()
            .unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);

        let content_bom_snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(b"plain".as_slice()),
            EncodingRequest::new(SourceEncoding::Utf8).with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        let error = SourceSnapshotMessage::from_snapshot(&content_bom_snapshot).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }

    #[test]
    fn source_snapshot_v2_round_trips_code_page_and_bom_policy() {
        let code_page = consema_document::WindowsCodePage::from_number(1252).unwrap();
        let snapshot = SourceSnapshot::from_raw(
            Arc::<[u8]>::from([0xef, 0xbb, 0xbf, b'A']),
            EncodingRequest::new(SourceEncoding::WindowsCodePage(code_page))
                .with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.decoded_text(), Some("ï»¿A"));
        let value = SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value();
        for transported in [
            decode_json(
                &encode_json(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
            decode_pvce(
                &encode_pvce(&value, ProtocolLimits::default()).unwrap(),
                ProtocolLimits::default(),
            )
            .unwrap(),
        ] {
            let decoded =
                SourceSnapshotMessageV2::from_value(&transported, SourceLimits::default()).unwrap();
            assert_eq!(decoded.snapshot(), &snapshot);
            assert_eq!(decoded.to_value(), value);
        }
        assert!(SourceSnapshotMessage::from_value(&value, SourceLimits::default()).is_err());
    }

    #[test]
    fn source_patch_v2_round_trips_and_applies_code_page_bytes() {
        let code_page = consema_document::WindowsCodePage::from_number(1252).unwrap();
        let base = SourceSnapshot::from_raw(
            Arc::<[u8]>::from([0x80, b'A']),
            EncodingRequest::new(SourceEncoding::WindowsCodePage(code_page))
                .with_bom_policy(BomPolicy::TreatAsContent),
            SourceLimits::default(),
        )
        .unwrap();
        let patch = SourcePatch::create(
            &base,
            vec![SourceReplacement::new(
                1,
                2,
                b"A".as_slice(),
                b"B".as_slice(),
            )],
            BTreeMap::from([("actor".to_owned(), "source-v2-test".to_owned())]),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let value = SourcePatchMessageV2::from_patch(&patch).to_value().unwrap();
        let decoded =
            SourcePatchMessageV2::from_value(&value, SourcePatchLimits::default()).unwrap();
        assert_eq!(decoded.patch(), &patch);
        let target = decoded
            .patch()
            .apply(&base, SourcePatchLimits::default())
            .unwrap();
        assert_eq!(target.bytes(), &[0x80, b'B']);
        assert_eq!(target.decoded_text(), Some("€B"));
        assert!(SourcePatchMessage::from_value(&value, SourcePatchLimits::default()).is_err());
    }

    #[test]
    fn source_snapshot_v2_rejects_contradictory_bom_policy() {
        let snapshot = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"plain".as_slice())).unwrap();
        let value = SourceSnapshotMessageV2::from_snapshot(&snapshot).to_value();
        let fields = value.as_object().unwrap();
        let encoding = fields[3].value().as_object().unwrap();
        let forged_encoding = object(vec![
            ("profile_default", encoding[0].value().clone()),
            ("bom_policy", PortableValue::string("TreatAsContent")),
            ("bom", PortableValue::string("Utf8")),
            ("declaration", encoding[3].value().clone()),
            ("caller_override", encoding[4].value().clone()),
            ("selected", encoding[5].value().clone()),
        ]);
        let forged = object(vec![
            ("schema", fields[0].value().clone()),
            ("raw_bytes", fields[1].value().clone()),
            ("digest", fields[2].value().clone()),
            ("encoding", forged_encoding),
            ("decoded_status", fields[4].value().clone()),
        ]);
        let error =
            SourceSnapshotMessageV2::from_value(&forged, SourceLimits::default()).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::InvalidValue);
    }

    #[test]
    fn snapshot_decoder_rejects_forged_digest_and_encoding() {
        let snapshot = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"abc".as_slice())).unwrap();
        let value = SourceSnapshotMessage::from_snapshot(&snapshot)
            .unwrap()
            .to_value();
        let entries = value.as_object().unwrap();
        let forged_digest = object(vec![
            ("algorithm", PortableValue::string("sha256")),
            ("hex", PortableValue::string("00".repeat(32))),
        ]);
        let forged = object(vec![
            ("schema", entries[0].value().clone()),
            ("raw_bytes", entries[1].value().clone()),
            ("digest", forged_digest),
            ("encoding", entries[3].value().clone()),
            ("decoded_status", entries[4].value().clone()),
        ]);
        assert!(SourceSnapshotMessage::from_value(&forged, SourceLimits::default()).is_err());

        let forged_bom_facts = EncodingFacts::from_claim(
            SourceEncoding::Utf8,
            Some(BomKind::Utf8),
            None,
            None,
            SourceEncoding::Utf8,
        )
        .unwrap();
        let forged = object(vec![
            ("schema", entries[0].value().clone()),
            ("raw_bytes", entries[1].value().clone()),
            ("digest", entries[2].value().clone()),
            ("encoding", encoding_value(forged_bom_facts)),
            ("decoded_status", PortableValue::string("Available")),
        ]);
        assert!(SourceSnapshotMessage::from_value(&forged, SourceLimits::default()).is_err());
    }

    #[test]
    fn source_patch_round_trips_and_remains_applicable() {
        let base = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"old".as_slice())).unwrap();
        let patch = SourcePatch::create(
            &base,
            vec![
                SourceReplacement::new(0, 3, b"old".as_slice(), b"new".as_slice())
                    .with_original_redacted(true),
            ],
            BTreeMap::from([("actor".to_owned(), "test".to_owned())]),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let value = SourcePatchMessage::from_patch(&patch).to_value().unwrap();
        let decoded = SourcePatchMessage::from_value(&value, SourcePatchLimits::default()).unwrap();
        assert_eq!(decoded.patch(), &patch);
        assert_eq!(
            decoded
                .patch()
                .apply(&base, SourcePatchLimits::default())
                .unwrap()
                .bytes(),
            b"new"
        );
    }

    #[test]
    fn patch_decoder_rejects_noncanonical_order_and_uppercase_digest() {
        let base = SourceSnapshot::from_utf8(Arc::<[u8]>::from(b"abc".as_slice())).unwrap();
        let patch = SourcePatch::create(
            &base,
            Vec::new(),
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let value = SourcePatchMessage::from_patch(&patch).to_value().unwrap();
        let fields = value.as_object().unwrap();
        let uppercase = object(vec![
            ("algorithm", PortableValue::string("sha256")),
            ("hex", PortableValue::string("AA".repeat(32))),
        ]);
        let invalid = object(vec![
            ("schema", fields[0].value().clone()),
            ("base_digest", uppercase),
            ("target_digest", fields[2].value().clone()),
            ("encoding", fields[3].value().clone()),
            ("replacements", fields[4].value().clone()),
            ("metadata", fields[5].value().clone()),
        ]);
        assert!(SourcePatchMessage::from_value(&invalid, SourcePatchLimits::default()).is_err());
    }
}
