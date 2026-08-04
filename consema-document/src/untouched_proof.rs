//! Verifiable proof that planned replacements did not alter surrounding bytes.

use crate::{ContentDigest, SourceReplacement, SourceSnapshot};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// One maximal unchanged raw-byte interval mapped across two source snapshots.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UntouchedByteRegion {
    old_start: usize,
    old_end: usize,
    new_start: usize,
    new_end: usize,
}

impl UntouchedByteRegion {
    /// Creates one region fact. The enclosing proof validates length and ordering.
    #[must_use]
    pub const fn new(old_start: usize, old_end: usize, new_start: usize, new_end: usize) -> Self {
        Self {
            old_start,
            old_end,
            new_start,
            new_end,
        }
    }

    /// Inclusive start in the base snapshot.
    #[must_use]
    pub const fn old_start(self) -> usize {
        self.old_start
    }

    /// Exclusive end in the base snapshot.
    #[must_use]
    pub const fn old_end(self) -> usize {
        self.old_end
    }

    /// Inclusive start in the target snapshot.
    #[must_use]
    pub const fn new_start(self) -> usize {
        self.new_start
    }

    /// Exclusive end in the target snapshot.
    #[must_use]
    pub const fn new_end(self) -> usize {
        self.new_end
    }

    const fn old_len(self) -> usize {
        self.old_end - self.old_start
    }

    const fn new_len(self) -> usize {
        self.new_end - self.new_start
    }
}

/// Immutable evidence for every byte outside one exact replacement plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntouchedByteProof {
    base_digest: ContentDigest,
    target_digest: ContentDigest,
    regions: Arc<[UntouchedByteRegion]>,
}

impl UntouchedByteProof {
    /// Creates a proof only when the replacements exactly produce the supplied target snapshot.
    pub fn create(
        base: &SourceSnapshot,
        target: &SourceSnapshot,
        replacements: &[SourceReplacement],
    ) -> Result<Self, UntouchedByteProofError> {
        let regions = expected_regions(base, target, replacements)?;
        Ok(Self {
            base_digest: base.digest(),
            target_digest: target.digest(),
            regions: Arc::from(regions),
        })
    }

    /// Constructs transferable proof facts after validating their canonical structure.
    pub fn from_facts(
        base_digest: ContentDigest,
        target_digest: ContentDigest,
        regions: Vec<UntouchedByteRegion>,
    ) -> Result<Self, UntouchedByteProofError> {
        validate_regions(&regions)?;
        Ok(Self {
            base_digest,
            target_digest,
            regions: Arc::from(regions),
        })
    }

    /// Rechecks digests, replacement preconditions, exact target bytes, and every region fact.
    pub fn verify(
        &self,
        base: &SourceSnapshot,
        target: &SourceSnapshot,
        replacements: &[SourceReplacement],
    ) -> Result<(), UntouchedByteProofError> {
        if base.digest() != self.base_digest || target.digest() != self.target_digest {
            return Err(UntouchedByteProofError::DigestMismatch);
        }
        let expected = expected_regions(base, target, replacements)?;
        if expected.as_slice() != self.regions.as_ref() {
            return Err(UntouchedByteProofError::ProofMismatch);
        }
        Ok(())
    }

    /// Required base digest.
    #[must_use]
    pub const fn base_digest(&self) -> ContentDigest {
        self.base_digest
    }

    /// Required target digest.
    #[must_use]
    pub const fn target_digest(&self) -> ContentDigest {
        self.target_digest
    }

    /// Canonical maximal unchanged regions.
    #[must_use]
    pub fn regions(&self) -> &[UntouchedByteRegion] {
        &self.regions
    }
}

/// Proof construction or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UntouchedByteProofError {
    /// Base and target encoding facts differ.
    EncodingMismatch,
    /// A replacement has an inverted or out-of-bounds old interval.
    InvalidReplacement {
        /// Zero-based replacement position.
        index: usize,
    },
    /// Replacements are not in canonical non-overlapping order.
    ReplacementOrder {
        /// Zero-based replacement position at which ordering failed.
        index: usize,
    },
    /// Two replacements target the same insertion point.
    DuplicateInsertion {
        /// Zero-based position of the second insertion.
        index: usize,
    },
    /// Base bytes do not satisfy an original-byte precondition.
    OriginalMismatch {
        /// Zero-based replacement position.
        index: usize,
    },
    /// Supplied target bytes are not the exact result of the replacement set.
    TargetMismatch,
    /// A target coordinate calculation overflowed.
    CoordinateOverflow,
    /// A transferred region has an invalid range, unequal lengths, order, or canonicality.
    InvalidRegion {
        /// Zero-based region position.
        index: usize,
    },
    /// Supplied snapshots do not have the proof's declared digests.
    DigestMismatch,
    /// Region facts differ from the canonical proof of the supplied replacement set.
    ProofMismatch,
}

impl Display for UntouchedByteProofError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for UntouchedByteProofError {}

fn expected_regions(
    base: &SourceSnapshot,
    target: &SourceSnapshot,
    replacements: &[SourceReplacement],
) -> Result<Vec<UntouchedByteRegion>, UntouchedByteProofError> {
    if base.encoding_facts() != target.encoding_facts() {
        return Err(UntouchedByteProofError::EncodingMismatch);
    }

    let mut regions = Vec::with_capacity(replacements.len().saturating_add(1));
    let mut old_cursor = 0usize;
    let mut new_cursor = 0usize;
    let mut previous: Option<&SourceReplacement> = None;

    for (index, replacement) in replacements.iter().enumerate() {
        validate_replacement(base, previous, replacement, index)?;

        let unchanged_len = replacement.old_start() - old_cursor;
        let new_unchanged_end = new_cursor
            .checked_add(unchanged_len)
            .ok_or(UntouchedByteProofError::CoordinateOverflow)?;
        if target.bytes().get(new_cursor..new_unchanged_end)
            != base.bytes().get(old_cursor..replacement.old_start())
        {
            return Err(UntouchedByteProofError::TargetMismatch);
        }
        push_region(
            &mut regions,
            UntouchedByteRegion::new(
                old_cursor,
                replacement.old_start(),
                new_cursor,
                new_unchanged_end,
            ),
        );

        let replacement_end = new_unchanged_end
            .checked_add(replacement.replacement().len())
            .ok_or(UntouchedByteProofError::CoordinateOverflow)?;
        if target.bytes().get(new_unchanged_end..replacement_end) != Some(replacement.replacement())
        {
            return Err(UntouchedByteProofError::TargetMismatch);
        }
        old_cursor = replacement.old_end();
        new_cursor = replacement_end;
        previous = Some(replacement);
    }

    let tail_len = base.bytes().len() - old_cursor;
    let new_end = new_cursor
        .checked_add(tail_len)
        .ok_or(UntouchedByteProofError::CoordinateOverflow)?;
    if new_end != target.bytes().len()
        || target.bytes().get(new_cursor..new_end) != base.bytes().get(old_cursor..)
    {
        return Err(UntouchedByteProofError::TargetMismatch);
    }
    push_region(
        &mut regions,
        UntouchedByteRegion::new(old_cursor, base.bytes().len(), new_cursor, new_end),
    );
    validate_regions(&regions)?;
    Ok(regions)
}

fn validate_replacement(
    base: &SourceSnapshot,
    previous: Option<&SourceReplacement>,
    replacement: &SourceReplacement,
    index: usize,
) -> Result<(), UntouchedByteProofError> {
    if replacement.old_start() > replacement.old_end()
        || replacement.old_end() > base.bytes().len()
        || replacement.original().len() != replacement.old_end() - replacement.old_start()
    {
        return Err(UntouchedByteProofError::InvalidReplacement { index });
    }
    if let Some(previous) = previous {
        if replacement.old_start() == replacement.old_end()
            && previous.old_start() == previous.old_end()
            && replacement.old_start() == previous.old_start()
        {
            return Err(UntouchedByteProofError::DuplicateInsertion { index });
        }
        if (replacement.old_start(), replacement.old_end())
            <= (previous.old_start(), previous.old_end())
            || replacement.old_start() < previous.old_end()
        {
            return Err(UntouchedByteProofError::ReplacementOrder { index });
        }
    }
    if base
        .bytes()
        .get(replacement.old_start()..replacement.old_end())
        != Some(replacement.original())
    {
        return Err(UntouchedByteProofError::OriginalMismatch { index });
    }
    Ok(())
}

fn push_region(regions: &mut Vec<UntouchedByteRegion>, region: UntouchedByteRegion) {
    if region.old_start == region.old_end {
        return;
    }
    if let Some(previous) = regions.last_mut() {
        if previous.old_end == region.old_start && previous.new_end == region.new_start {
            previous.old_end = region.old_end;
            previous.new_end = region.new_end;
            return;
        }
    }
    regions.push(region);
}

fn validate_regions(regions: &[UntouchedByteRegion]) -> Result<(), UntouchedByteProofError> {
    let mut previous: Option<UntouchedByteRegion> = None;
    for (index, region) in regions.iter().copied().enumerate() {
        if region.old_start >= region.old_end
            || region.new_start >= region.new_end
            || region.old_len() != region.new_len()
        {
            return Err(UntouchedByteProofError::InvalidRegion { index });
        }
        if let Some(previous) = previous {
            if region.old_start < previous.old_end
                || region.new_start < previous.new_end
                || (region.old_start == previous.old_end && region.new_start == previous.new_end)
            {
                return Err(UntouchedByteProofError::InvalidRegion { index });
            }
        }
        previous = Some(region);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf8(bytes: &[u8]) -> SourceSnapshot {
        SourceSnapshot::from_utf8(Arc::<[u8]>::from(bytes)).unwrap()
    }

    fn replacements() -> Vec<SourceReplacement> {
        vec![
            SourceReplacement::new(0, 0, [], b">".as_slice()),
            SourceReplacement::new(2, 4, b"XX".as_slice(), b"YYY".as_slice()),
            SourceReplacement::new(6, 7, b"!".as_slice(), []),
        ]
    }

    #[test]
    fn proof_covers_every_and_only_untouched_byte() {
        let base = utf8(b"abXXcd!");
        let target = utf8(b">abYYYcd");
        let replacements = replacements();
        let proof = UntouchedByteProof::create(&base, &target, &replacements).unwrap();
        assert_eq!(
            proof.regions(),
            &[
                UntouchedByteRegion::new(0, 2, 1, 3),
                UntouchedByteRegion::new(4, 6, 6, 8),
            ]
        );
        assert_eq!(proof.verify(&base, &target, &replacements), Ok(()));
    }

    #[test]
    fn proof_detects_region_digest_and_target_tampering() {
        let base = utf8(b"abXXcd!");
        let target = utf8(b">abYYYcd");
        let replacements = replacements();
        let proof = UntouchedByteProof::from_facts(
            base.digest(),
            target.digest(),
            vec![
                UntouchedByteRegion::new(0, 2, 0, 2),
                UntouchedByteRegion::new(4, 6, 6, 8),
            ],
        )
        .unwrap();
        assert_eq!(
            proof.verify(&base, &target, &replacements),
            Err(UntouchedByteProofError::ProofMismatch)
        );
        assert_eq!(
            proof.verify(&base, &utf8(b">abYYYcD"), &replacements),
            Err(UntouchedByteProofError::DigestMismatch)
        );
        assert_eq!(
            UntouchedByteProof::create(&base, &utf8(b">aBYYYcd"), &replacements),
            Err(UntouchedByteProofError::TargetMismatch)
        );
    }

    #[test]
    fn no_replacements_prove_the_complete_snapshot() {
        let source = utf8(b"same");
        let proof = UntouchedByteProof::create(&source, &source, &[]).unwrap();
        assert_eq!(proof.regions(), &[UntouchedByteRegion::new(0, 4, 0, 4)]);
        assert_eq!(proof.verify(&source, &source, &[]), Ok(()));
    }

    #[test]
    fn transferred_proof_rejects_noncanonical_regions() {
        let digest = ContentDigest::of(b"abc");
        assert!(matches!(
            UntouchedByteProof::from_facts(
                digest,
                digest,
                vec![
                    UntouchedByteRegion::new(0, 1, 0, 1),
                    UntouchedByteRegion::new(1, 3, 1, 3),
                ],
            ),
            Err(UntouchedByteProofError::InvalidRegion { index: 1 })
        ));
    }
}
