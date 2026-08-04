//! Verifiable raw-byte patches between immutable source snapshots.

use crate::{ChangeSet, ContentDigest, EncodingFacts, SourceError, SourceLimits, SourceSnapshot};
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

/// Resource bounds for constructing or applying one source patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePatchLimits {
    /// Limits for the resulting source snapshot.
    pub source: SourceLimits,
    /// Maximum number of ordered replacements.
    pub max_replacements: usize,
    /// Maximum sum of original and replacement payload bytes.
    pub max_patch_bytes: usize,
}

impl Default for SourcePatchLimits {
    fn default() -> Self {
        Self {
            source: SourceLimits::default(),
            max_replacements: 100_000,
            max_patch_bytes: 128 * 1024 * 1024,
        }
    }
}

/// One raw-byte precondition and replacement in a source patch.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceReplacement {
    old_start: usize,
    old_end: usize,
    original: Arc<[u8]>,
    replacement: Arc<[u8]>,
    redact_original: bool,
    redact_replacement: bool,
}

impl SourceReplacement {
    /// Creates one half-open raw-byte replacement.
    #[must_use]
    pub fn new(
        old_start: usize,
        old_end: usize,
        original: impl Into<Arc<[u8]>>,
        replacement: impl Into<Arc<[u8]>>,
    ) -> Self {
        Self {
            old_start,
            old_end,
            original: original.into(),
            replacement: replacement.into(),
            redact_original: false,
            redact_replacement: false,
        }
    }

    /// Controls whether the original bytes are hidden in review/debug presentation.
    #[must_use]
    pub const fn with_original_redacted(mut self, redacted: bool) -> Self {
        self.redact_original = redacted;
        self
    }

    /// Controls whether replacement bytes are hidden in review/debug presentation.
    #[must_use]
    pub const fn with_replacement_redacted(mut self, redacted: bool) -> Self {
        self.redact_replacement = redacted;
        self
    }

    /// Inclusive start raw byte.
    #[must_use]
    pub const fn old_start(&self) -> usize {
        self.old_start
    }

    /// Exclusive end raw byte.
    #[must_use]
    pub const fn old_end(&self) -> usize {
        self.old_end
    }

    /// Exact bytes required at the old range.
    #[must_use]
    pub fn original(&self) -> &[u8] {
        &self.original
    }

    /// Exact bytes written in place of the old range.
    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    /// Whether review/debug presentation hides the original bytes.
    #[must_use]
    pub const fn redact_original(&self) -> bool {
        self.redact_original
    }

    /// Whether review/debug presentation hides the replacement bytes.
    #[must_use]
    pub const fn redact_replacement(&self) -> bool {
        self.redact_replacement
    }
}

impl Debug for SourceReplacement {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SourceReplacement");
        debug
            .field("old_start", &self.old_start)
            .field("old_end", &self.old_end);
        if self.redact_original {
            debug.field("original", &"<redacted>");
        } else {
            debug.field("original", &self.original);
        }
        if self.redact_replacement {
            debug.field("replacement", &"<redacted>");
        } else {
            debug.field("replacement", &self.replacement);
        }
        debug
            .field("redact_original", &self.redact_original)
            .field("redact_replacement", &self.redact_replacement)
            .finish()
    }
}

/// Immutable, transferable facts needed to verify one raw source transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePatch {
    base_digest: ContentDigest,
    target_digest: ContentDigest,
    encoding: EncodingFacts,
    replacements: Arc<[SourceReplacement]>,
    metadata: BTreeMap<String, String>,
}

impl SourcePatch {
    /// Derives and verifies a portable patch from one complete document-level change fact.
    pub fn derive(
        base: &SourceSnapshot,
        target: &SourceSnapshot,
        change_set: &ChangeSet,
        metadata: BTreeMap<String, String>,
        limits: SourcePatchLimits,
    ) -> Result<Self, SourcePatchError> {
        if base.encoding_facts() != target.encoding_facts() {
            return Err(SourcePatchError::EncodingMismatch);
        }
        let edits = change_set.source_edits();
        let mut replacements = Vec::new();
        replacements
            .try_reserve(edits.len())
            .map_err(|_| SourcePatchError::ResourceLimit {
                name: "patch-allocation",
                observed: edits.len(),
                limit: limits.max_replacements,
            })?;
        let mut previous_new: Option<(usize, usize)> = None;
        for (index, edit) in edits.iter().enumerate() {
            if edit.old_span.snapshot() != change_set.old_snapshot()
                || edit.new_span.snapshot() != change_set.new_snapshot()
                || edit.old_span.end_byte() > base.bytes().len()
                || edit.new_span.end_byte() > target.bytes().len()
                || edit.replacement.as_ref()
                    != &target.bytes()[edit.new_span.start_byte()..edit.new_span.end_byte()]
            {
                return Err(SourcePatchError::ChangeSetMismatch { index });
            }
            let new_range = (edit.new_span.start_byte(), edit.new_span.end_byte());
            if let Some(previous) = previous_new {
                if new_range <= previous || new_range.0 < previous.1 {
                    return Err(SourcePatchError::ChangeSetMismatch { index });
                }
            }
            let original = Arc::<[u8]>::from(
                &base.bytes()[edit.old_span.start_byte()..edit.old_span.end_byte()],
            );
            replacements.push(SourceReplacement::new(
                edit.old_span.start_byte(),
                edit.old_span.end_byte(),
                original,
                edit.replacement.clone(),
            ));
            previous_new = Some(new_range);
        }
        let patch = Self::new(
            base.digest(),
            target.digest(),
            base.encoding_facts(),
            replacements,
            metadata,
            limits,
        )?;
        let reapplied = patch.apply(base, limits)?;
        if reapplied.bytes() != target.bytes() {
            return Err(SourcePatchError::TargetMismatch);
        }
        Ok(patch)
    }

    /// Creates a patch from externally supplied facts after structural and resource validation.
    pub fn new(
        base_digest: ContentDigest,
        target_digest: ContentDigest,
        encoding: EncodingFacts,
        replacements: Vec<SourceReplacement>,
        metadata: BTreeMap<String, String>,
        limits: SourcePatchLimits,
    ) -> Result<Self, SourcePatchError> {
        validate_replacements(&replacements, limits)?;
        Ok(Self {
            base_digest,
            target_digest,
            encoding,
            replacements: Arc::from(replacements),
            metadata,
        })
    }

    /// Builds a self-consistent patch against one immutable base snapshot.
    pub fn create(
        base: &SourceSnapshot,
        replacements: Vec<SourceReplacement>,
        metadata: BTreeMap<String, String>,
        limits: SourcePatchLimits,
    ) -> Result<Self, SourcePatchError> {
        validate_replacements(&replacements, limits)?;
        let target_bytes = apply_replacements(base.bytes(), &replacements, limits)?;
        let target = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(target_bytes),
            base.encoding_facts().resolution_request(),
            limits.source,
        )
        .map_err(SourcePatchError::Source)?;
        if target.encoding_facts() != base.encoding_facts() {
            return Err(SourcePatchError::EncodingMismatch);
        }
        Ok(Self {
            base_digest: base.digest(),
            target_digest: target.digest(),
            encoding: base.encoding_facts(),
            replacements: Arc::from(replacements),
            metadata,
        })
    }

    /// Applies all facts atomically and returns a new immutable snapshot only on complete success.
    pub fn apply(
        &self,
        base: &SourceSnapshot,
        limits: SourcePatchLimits,
    ) -> Result<SourceSnapshot, SourcePatchError> {
        validate_replacements(&self.replacements, limits)?;
        if base.digest() != self.base_digest {
            return Err(SourcePatchError::BaseMismatch);
        }
        if base.encoding_facts() != self.encoding {
            return Err(SourcePatchError::EncodingMismatch);
        }
        let target_bytes = apply_replacements(base.bytes(), &self.replacements, limits)?;
        let target = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(target_bytes),
            self.encoding.resolution_request(),
            limits.source,
        )
        .map_err(SourcePatchError::Source)?;
        if target.encoding_facts() != self.encoding {
            return Err(SourcePatchError::EncodingMismatch);
        }
        if target.digest() != self.target_digest {
            return Err(SourcePatchError::TargetMismatch);
        }
        Ok(target)
    }

    /// Required base content identity.
    #[must_use]
    pub const fn base_digest(&self) -> ContentDigest {
        self.base_digest
    }

    /// Required result content identity.
    #[must_use]
    pub const fn target_digest(&self) -> ContentDigest {
        self.target_digest
    }

    /// Encoding facts that both base and result must reproduce.
    #[must_use]
    pub const fn encoding_facts(&self) -> EncodingFacts {
        self.encoding
    }

    /// Ordered non-overlapping replacements.
    #[must_use]
    pub fn replacements(&self) -> &[SourceReplacement] {
        &self.replacements
    }

    /// Deterministically ordered audit metadata, which never affects application.
    #[must_use]
    pub const fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// Marks every replacement payload for redacted review/debug presentation.
    ///
    /// Exact bytes remain present for digest and original-byte precondition checks.
    pub fn with_all_replacements_redacted(
        self,
        redact_original: bool,
        redact_replacement: bool,
    ) -> Result<Self, SourcePatchRedactionError> {
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(self.replacements.len())
            .map_err(|_| SourcePatchRedactionError::AllocationFailed)?;
        replacements.extend(self.replacements.iter().cloned().map(|replacement| {
            replacement
                .with_original_redacted(redact_original)
                .with_replacement_redacted(redact_replacement)
        }));
        Ok(Self {
            base_digest: self.base_digest,
            target_digest: self.target_digest,
            encoding: self.encoding,
            replacements: Arc::from(replacements),
            metadata: self.metadata,
        })
    }

    /// Marks one exact replacement payload for redacted review/debug presentation.
    pub fn with_replacement_redacted(
        self,
        index: usize,
        redact_original: bool,
        redact_replacement: bool,
    ) -> Result<Self, SourcePatchRedactionError> {
        if index >= self.replacements.len() {
            return Err(SourcePatchRedactionError::UnknownReplacement { index });
        }
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(self.replacements.len())
            .map_err(|_| SourcePatchRedactionError::AllocationFailed)?;
        replacements.extend(self.replacements.iter().cloned());
        replacements[index] = replacements[index]
            .clone()
            .with_original_redacted(redact_original)
            .with_replacement_redacted(redact_replacement);
        Ok(Self {
            base_digest: self.base_digest,
            target_digest: self.target_digest,
            encoding: self.encoding,
            replacements: Arc::from(replacements),
            metadata: self.metadata,
        })
    }
}

/// Review-redaction selection failure; patch bytes and application facts are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePatchRedactionError {
    /// Redacted review view could not allocate its replacement index.
    AllocationFailed,
    /// Requested replacement index does not exist.
    UnknownReplacement {
        /// Requested zero-based replacement index.
        index: usize,
    },
}

impl std::fmt::Display for SourcePatchRedactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourcePatchRedactionError {}

/// Stable source patch construction or application failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourcePatchError {
    /// A document-level source edit disagrees with its snapshots or replacement bytes.
    ChangeSetMismatch {
        /// Zero-based source edit position.
        index: usize,
    },
    /// Replacement start followed its end or its original byte count disagreed with its range.
    InvalidReplacement {
        /// Zero-based replacement position.
        index: usize,
    },
    /// Replacement order was not canonical or two old ranges overlapped.
    ReplacementOrder {
        /// Zero-based replacement position at which order failed.
        index: usize,
    },
    /// Two replacements targeted the same zero-width insertion point.
    DuplicateInsertion {
        /// Zero-based position of the second insertion.
        index: usize,
    },
    /// Base raw bytes do not have the declared digest.
    BaseMismatch,
    /// Base bytes in one range do not equal the declared precondition.
    OriginalMismatch {
        /// Zero-based replacement position.
        index: usize,
    },
    /// Computed result bytes do not have the declared digest.
    TargetMismatch,
    /// Base or resulting encoding facts disagree with the patch.
    EncodingMismatch,
    /// A patch count, byte, output, or allocation bound was exceeded.
    ResourceLimit {
        /// Stable limit name.
        name: &'static str,
        /// Observed amount.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Resulting bytes could not form a valid source snapshot.
    Source(SourceError),
}

impl SourcePatchError {
    /// Stable public operation code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BaseMismatch => "core.source.patch-base-mismatch@1",
            Self::OriginalMismatch { .. } => "core.source.patch-original-mismatch@1",
            Self::TargetMismatch => "core.source.patch-target-mismatch@1",
            Self::EncodingMismatch | Self::Source(SourceError::EncodingConflict { .. }) => {
                "core.source.encoding-conflict@1"
            }
            Self::ResourceLimit { .. }
            | Self::Source(SourceError::ResourceLimit { .. } | SourceError::OffsetOverflow) => {
                "core.source.resource-limit@1"
            }
            Self::Source(SourceError::UnsupportedBom { .. }) => "core.source.unsupported-bom@1",
            Self::Source(SourceError::InvalidUtf8 { .. } | SourceError::InvalidSequence { .. }) => {
                "core.source.invalid-sequence@1"
            }
            Self::InvalidReplacement { .. }
            | Self::ReplacementOrder { .. }
            | Self::DuplicateInsertion { .. }
            | Self::ChangeSetMismatch { .. } => "core.protocol.invalid-value@1",
        }
    }
}

impl std::fmt::Display for SourcePatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourcePatchError {}

fn validate_replacements(
    replacements: &[SourceReplacement],
    limits: SourcePatchLimits,
) -> Result<(), SourcePatchError> {
    check_limit(
        "patch-replacements",
        replacements.len(),
        limits.max_replacements,
    )?;
    let mut patch_bytes = 0usize;
    let mut previous: Option<&SourceReplacement> = None;
    for (index, replacement) in replacements.iter().enumerate() {
        if replacement.old_start > replacement.old_end
            || replacement.original.len() != replacement.old_end - replacement.old_start
        {
            return Err(SourcePatchError::InvalidReplacement { index });
        }
        if let Some(previous) = previous {
            if replacement.old_start == replacement.old_end
                && previous.old_start == previous.old_end
                && replacement.old_start == previous.old_start
            {
                return Err(SourcePatchError::DuplicateInsertion { index });
            }
            if (replacement.old_start, replacement.old_end)
                <= (previous.old_start, previous.old_end)
                || replacement.old_start < previous.old_end
            {
                return Err(SourcePatchError::ReplacementOrder { index });
            }
        }
        patch_bytes = patch_bytes
            .checked_add(replacement.original.len())
            .and_then(|value| value.checked_add(replacement.replacement.len()))
            .ok_or(SourcePatchError::ResourceLimit {
                name: "patch-bytes",
                observed: usize::MAX,
                limit: limits.max_patch_bytes,
            })?;
        check_limit("patch-bytes", patch_bytes, limits.max_patch_bytes)?;
        previous = Some(replacement);
    }
    Ok(())
}

fn apply_replacements(
    base: &[u8],
    replacements: &[SourceReplacement],
    limits: SourcePatchLimits,
) -> Result<Vec<u8>, SourcePatchError> {
    let mut target_len = base.len();
    for (index, replacement) in replacements.iter().enumerate() {
        if replacement.old_end > base.len()
            || base.get(replacement.old_start..replacement.old_end) != Some(replacement.original())
        {
            return Err(SourcePatchError::OriginalMismatch { index });
        }
        target_len = target_len
            .checked_sub(replacement.original.len())
            .and_then(|value| value.checked_add(replacement.replacement.len()))
            .ok_or(SourcePatchError::ResourceLimit {
                name: "target-raw-bytes",
                observed: usize::MAX,
                limit: limits.source.max_raw_bytes,
            })?;
        check_limit("target-raw-bytes", target_len, limits.source.max_raw_bytes)?;
    }

    let mut target = Vec::new();
    target
        .try_reserve_exact(target_len)
        .map_err(|_| SourcePatchError::ResourceLimit {
            name: "target-allocation",
            observed: target_len,
            limit: limits.source.max_raw_bytes,
        })?;
    let mut cursor = 0;
    for replacement in replacements {
        target.extend_from_slice(&base[cursor..replacement.old_start]);
        target.extend_from_slice(&replacement.replacement);
        cursor = replacement.old_end;
    }
    target.extend_from_slice(&base[cursor..]);
    debug_assert_eq!(target.len(), target_len);
    Ok(target)
}

fn check_limit(name: &'static str, observed: usize, limit: usize) -> Result<(), SourcePatchError> {
    if observed > limit {
        Err(SourcePatchError::ResourceLimit {
            name,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChangeSet, DocumentAuthority, EncodingRequest, SourceEdit, SourceEncoding};

    fn utf8(bytes: &[u8]) -> SourceSnapshot {
        SourceSnapshot::from_utf8(Arc::<[u8]>::from(bytes)).unwrap()
    }

    #[test]
    fn patch_creation_and_application_are_exact_and_repeatable() {
        let base = utf8(b"name = old\n");
        let replacements = vec![
            SourceReplacement::new(0, 0, [], b"# ".as_slice()),
            SourceReplacement::new(7, 10, b"old".as_slice(), b"new".as_slice()),
        ];
        let mut metadata = BTreeMap::new();
        metadata.insert("actor".to_owned(), "test".to_owned());
        let patch =
            SourcePatch::create(&base, replacements, metadata, SourcePatchLimits::default())
                .unwrap();
        let first = patch.apply(&base, SourcePatchLimits::default()).unwrap();
        let second = patch.apply(&base, SourcePatchLimits::default()).unwrap();
        assert_eq!(first.bytes(), b"# name = new\n");
        assert_eq!(first.digest(), patch.target_digest());
        assert_eq!(first, second);
        assert_eq!(
            patch.metadata().get("actor").map(String::as_str),
            Some("test")
        );
    }

    #[test]
    fn derives_exact_patch_from_document_change_facts() {
        let base = utf8(b"abc");
        let target = utf8(b"aXYc");
        let old = DocumentAuthority::fresh();
        let new = DocumentAuthority::fresh();
        let change_set = ChangeSet::new(
            old.identity(),
            new.identity(),
            vec![SourceEdit {
                old_span: old.span(1, 2).unwrap(),
                new_span: new.span(1, 3).unwrap(),
                replacement: Arc::from(b"XY".as_slice()),
            }],
            Vec::new(),
            Vec::new(),
        );
        let patch = SourcePatch::derive(
            &base,
            &target,
            &change_set,
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        assert_eq!(
            patch
                .apply(&base, SourcePatchLimits::default())
                .unwrap()
                .bytes(),
            target.bytes()
        );

        let inconsistent = ChangeSet::new(
            old.identity(),
            new.identity(),
            vec![SourceEdit {
                old_span: old.span(1, 2).unwrap(),
                new_span: new.span(1, 3).unwrap(),
                replacement: Arc::from(b"ZZ".as_slice()),
            }],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            SourcePatch::derive(
                &base,
                &target,
                &inconsistent,
                BTreeMap::new(),
                SourcePatchLimits::default(),
            ),
            Err(SourcePatchError::ChangeSetMismatch { index: 0 })
        );
    }

    #[test]
    fn stale_base_and_original_mismatch_fail_before_a_result_exists() {
        let base = utf8(b"abc");
        let patch = SourcePatch::create(
            &base,
            vec![SourceReplacement::new(
                1,
                2,
                b"b".as_slice(),
                b"B".as_slice(),
            )],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        assert_eq!(
            patch.apply(&utf8(b"abd"), SourcePatchLimits::default()),
            Err(SourcePatchError::BaseMismatch)
        );

        let wrong_original = SourcePatch::new(
            base.digest(),
            patch.target_digest(),
            base.encoding_facts(),
            vec![SourceReplacement::new(
                1,
                2,
                b"x".as_slice(),
                b"B".as_slice(),
            )],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        assert_eq!(
            wrong_original.apply(&base, SourcePatchLimits::default()),
            Err(SourcePatchError::OriginalMismatch { index: 0 })
        );
    }

    #[test]
    fn target_digest_and_encoding_drift_are_rejected() {
        let base = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(b"ab".as_slice()),
            EncodingRequest::new(SourceEncoding::Latin1),
            SourceLimits::default(),
        )
        .unwrap();
        let replacement = SourceReplacement::new(0, 2, b"ab".as_slice(), b"cd".as_slice());
        let wrong_target = SourcePatch::new(
            base.digest(),
            ContentDigest::of(b"not cd"),
            base.encoding_facts(),
            vec![replacement],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        assert_eq!(
            wrong_target.apply(&base, SourcePatchLimits::default()),
            Err(SourcePatchError::TargetMismatch)
        );

        let utf16_bytes = [0xff, 0xfe, 0x41, 0x00];
        let encoding_drift = SourcePatch::new(
            base.digest(),
            ContentDigest::of(&utf16_bytes),
            base.encoding_facts(),
            vec![SourceReplacement::new(
                0,
                2,
                b"ab".as_slice(),
                utf16_bytes.as_slice(),
            )],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .unwrap();
        assert_eq!(
            encoding_drift.apply(&base, SourcePatchLimits::default()),
            Err(SourcePatchError::EncodingMismatch)
        );
    }

    #[test]
    fn overlapping_and_duplicate_insertions_are_not_valid_patches() {
        let base = utf8(b"abcdef");
        assert_eq!(
            SourcePatch::create(
                &base,
                vec![
                    SourceReplacement::new(1, 4, b"bcd".as_slice(), []),
                    SourceReplacement::new(3, 5, b"de".as_slice(), []),
                ],
                BTreeMap::new(),
                SourcePatchLimits::default(),
            ),
            Err(SourcePatchError::ReplacementOrder { index: 1 })
        );
        assert_eq!(
            SourcePatch::create(
                &base,
                vec![
                    SourceReplacement::new(2, 2, [], b"x".as_slice()),
                    SourceReplacement::new(2, 2, [], b"y".as_slice()),
                ],
                BTreeMap::new(),
                SourcePatchLimits::default(),
            ),
            Err(SourcePatchError::DuplicateInsertion { index: 1 })
        );
    }

    #[test]
    fn limits_are_checked_before_target_allocation() {
        let base = utf8(b"a");
        let limits = SourcePatchLimits {
            source: SourceLimits {
                max_raw_bytes: 2,
                ..SourceLimits::default()
            },
            max_replacements: 1,
            max_patch_bytes: 2,
        };
        assert!(matches!(
            SourcePatch::create(
                &base,
                vec![SourceReplacement::new(1, 1, [], b"large".as_slice())],
                BTreeMap::new(),
                limits,
            ),
            Err(SourcePatchError::ResourceLimit { .. })
        ));
    }

    #[test]
    fn redacted_bytes_are_required_for_application_but_hidden_from_debug() {
        let replacement = SourceReplacement::new(0, 6, b"secret".as_slice(), b"hidden".as_slice())
            .with_original_redacted(true)
            .with_replacement_redacted(true);
        assert_eq!(replacement.original(), b"secret");
        assert_eq!(replacement.replacement(), b"hidden");
        let rendered = format!("{replacement:?}");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("hidden"));
        assert!(rendered.contains("<redacted>"));
    }
}
