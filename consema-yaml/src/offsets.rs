//! One-pass decoded-scalar to raw-byte offset resolution.
//!
//! `SourceSnapshot::raw_byte_at` re-validates the complete decoded text on
//! every call (the UTF-8 storage branch runs a full `str::from_utf8`
//! validation), so calling it per lexeme or per node is O(source) per call
//! and O(source × pieces) overall. The YAML parse resolves every lexeme and
//! node boundary in non-decreasing order, so a single forward walk with
//! constant-width per-scalar raw advances reproduces the exact same offsets
//! in O(source + lookups) total. This resolver is snapshot-local and
//! encoding-aware (UTF-8 and BOM-detected UTF-16 are the only encodings the
//! YAML parse can select); lookups may be repeated and need not be sorted.

use consema_document::{SourceEncoding, SourceSnapshot};

/// Resolves decoded Unicode scalar offsets to exact raw byte offsets.
pub(crate) struct RawByteResolver<'a> {
    text: &'a str,
    encoding: SourceEncoding,
    scalar: usize,
    raw_byte: usize,
    utf8_byte: usize,
}

impl<'a> RawByteResolver<'a> {
    /// Starts a resolver over one snapshot's decoded text.
    pub(crate) fn new(source: &'a SourceSnapshot) -> Self {
        Self {
            text: source
                .decoded_text()
                .expect("YAML sources always decode to text"),
            encoding: source.encoding_facts().selected(),
            scalar: 0,
            raw_byte: 0,
            utf8_byte: 0,
        }
    }

    /// Exact raw byte offset of one decoded scalar boundary.
    ///
    /// Walking from the current position keeps every call amortized O(1);
    /// a lookup behind the cursor restarts the walk so any query order is
    /// correct (only the total walk cost can grow).
    pub(crate) fn resolve(&mut self, scalar: usize) -> usize {
        self.advance_to(scalar);
        self.raw_byte
    }

    /// Decoded-text byte offset of one decoded scalar boundary.
    ///
    /// Same single-pass walk as [`resolve`](Self::resolve), but in decoded
    /// text coordinates, for slicing the decoded text directly.
    pub(crate) fn decoded_byte_at(&mut self, scalar: usize) -> usize {
        self.advance_to(scalar);
        self.utf8_byte
    }

    fn advance_to(&mut self, scalar: usize) {
        if scalar < self.scalar {
            self.scalar = 0;
            self.raw_byte = 0;
            self.utf8_byte = 0;
        }
        for character in self.text[self.utf8_byte..]
            .chars()
            .take(scalar - self.scalar)
        {
            self.raw_byte += match self.encoding {
                SourceEncoding::Utf8 => character.len_utf8(),
                SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => character.len_utf16() * 2,
                SourceEncoding::Binary
                | SourceEncoding::Latin1
                | SourceEncoding::WindowsCodePage(_) => {
                    unreachable!("YAML parse selects only UTF-8 and BOM-detected UTF-16")
                }
            };
            self.utf8_byte += character.len_utf8();
            self.scalar += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use consema_document::{DecodedOffset, EncodingRequest, SourceLimits};

    use super::*;

    #[test]
    fn utf8_resolution_matches_raw_byte_at_exactly() {
        let bytes = "\u{feff}鍵: \"值\"\nmore: text".as_bytes();
        let source = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(bytes),
            EncodingRequest::new(SourceEncoding::Utf8),
            SourceLimits::default(),
        )
        .unwrap();
        let mut resolver = RawByteResolver::new(&source);
        let scalars = source
            .decoded_text()
            .expect("decoded")
            .char_indices()
            .map(|(byte, _)| byte)
            .collect::<Vec<_>>();
        for (index, byte) in scalars.iter().enumerate() {
            let expected = source
                .raw_byte_at(DecodedOffset::UnicodeScalar(index))
                .unwrap();
            assert_eq!(resolver.resolve(index), expected);
            assert_eq!(&resolver.resolve(index), byte);
        }
        assert_eq!(resolver.resolve(scalars.len()), bytes.len());
    }

    #[test]
    fn utf16_bom_resolution_matches_raw_byte_at_exactly() {
        let bytes = [0xff, 0xfe, b'a', 0, b':', 0, b' ', 0, b'1', 0];
        let source = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(bytes),
            EncodingRequest::new(SourceEncoding::Utf8),
            SourceLimits::default(),
        )
        .unwrap();
        let mut resolver = RawByteResolver::new(&source);
        let text = source.decoded_text().expect("decoded");
        let scalar_count = text.chars().count();
        for index in 0..=scalar_count {
            let expected = source
                .raw_byte_at(DecodedOffset::UnicodeScalar(index))
                .unwrap();
            assert_eq!(resolver.resolve(index), expected);
        }
    }

    #[test]
    fn unsorted_lookups_restart_and_stay_correct() {
        let bytes = "a: 1\nb: 2\nc: 3\n".as_bytes();
        let source = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(bytes),
            EncodingRequest::new(SourceEncoding::Utf8),
            SourceLimits::default(),
        )
        .unwrap();
        let mut resolver = RawByteResolver::new(&source);
        assert_eq!(resolver.resolve(4), 4);
        assert_eq!(resolver.resolve(1), 1);
        assert_eq!(resolver.resolve(6), 6);
        assert_eq!(
            resolver.resolve(11),
            source
                .raw_byte_at(DecodedOffset::UnicodeScalar(11))
                .unwrap()
        );
    }
}
