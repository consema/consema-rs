//! Property tests for the plist binary offset-table/object-ref decoders
//! (0.13.0 gate plan M2, 路线图 §15.3: high-risk offset logic).
//!
//! A property-generated minimal bplist file is built by hand (marker bytes,
//! object table, offset table, trailer) and decoded with the production
//! decoder; the decoded `BinaryOffsetFact` offsets and object counts must
//! match the built layout exactly, every offset must stay in bounds, and
//! every object ref must resolve. This exercises the `offsetIntSize` /
//! `objectRefSize` width decoders and the trailer positions at every legal
//! width.

use consema_document::FormationStatus;
use consema_plist::{
    BinaryOffsetFact, PlistEncodingSelection, PlistParseLimits, PlistProfile, parse, parse_binary,
};
use proptest::prelude::*;
use std::sync::Arc;

/// One generated object seed; refs are resolved deterministically to
/// earlier object ordinals during layout.
#[derive(Clone, Debug)]
enum ObjectSeed {
    Integer { width_exp: u8, value: Vec<u8> },
    AsciiString { bytes: Vec<u8> },
    Array { count: usize },
    Dict { count: usize },
}

fn int_seed() -> impl Strategy<Value = ObjectSeed> {
    (0u8..=3, prop::collection::vec(any::<u8>(), 1..=8))
        .prop_map(|(width_exp, value)| ObjectSeed::Integer { width_exp, value })
}

fn string_seed() -> impl Strategy<Value = ObjectSeed> {
    prop::collection::vec(proptest::char::range('\u{20}', '\u{7e}'), 0..=24).prop_map(|chars| {
        ObjectSeed::AsciiString {
            bytes: chars.into_iter().map(|c| c as u8).collect(),
        }
    })
}

fn object_seed() -> impl Strategy<Value = ObjectSeed> {
    prop_oneof![
        int_seed(),
        string_seed(),
        (0usize..=6).prop_map(|count| ObjectSeed::Array { count }),
        (0usize..=6).prop_map(|count| ObjectSeed::Dict { count }),
    ]
}

/// A complete generated file: the byte layout plus the expected facts.
#[derive(Clone, Debug)]
struct GeneratedFile {
    bytes: Vec<u8>,
    object_count: u64,
    /// Every decoded offset fact must equal the builder's offset table.
    expected_offsets: Vec<u64>,
    /// Offset-table entry width in bytes (`offsetIntSize`).
    offset_width: usize,
}

fn build_file(
    seeds: &[ObjectSeed],
    offset_int_size_exp: u8,
    object_ref_size_exp: u8,
) -> GeneratedFile {
    let ref_width = 1usize << object_ref_size_exp;
    let offset_width = 1usize << offset_int_size_exp;
    let mut bytes = b"bplist00".to_vec();
    let mut offsets = Vec::with_capacity(seeds.len());
    // String object ordinals seen so far: dictionary keys must target
    // string objects (RFC 0013 §5.9).
    let mut string_ordinals: Vec<u64> = Vec::new();
    for (index, seed) in seeds.iter().enumerate() {
        offsets.push(bytes.len() as u64);
        // Value refs resolve to an earlier object ordinal.
        let value_refs = |count: usize| -> Vec<u64> {
            if index == 0 {
                return Vec::new();
            }
            (0..count).map(|offset| (offset % index) as u64).collect()
        };
        match seed {
            ObjectSeed::Integer { width_exp, value } => {
                bytes.push(0x10 | width_exp);
                let width = 1usize << width_exp;
                let padded: Vec<u8> = {
                    let mut padded = vec![0u8; width];
                    let start = width.saturating_sub(value.len());
                    padded[start..].copy_from_slice(&value[..value.len().min(width)]);
                    padded
                };
                bytes.extend(padded);
            }
            ObjectSeed::AsciiString { bytes: content } => {
                push_sized(&mut bytes, 0x50, content.len());
                bytes.extend(content);
                string_ordinals.push(index as u64);
            }
            ObjectSeed::Array { count } => {
                let refs = value_refs(*count);
                push_sized(&mut bytes, 0xA0, refs.len());
                for reference in refs {
                    bytes.extend(reference.to_be_bytes()[8 - ref_width..].to_vec());
                }
            }
            ObjectSeed::Dict { count } => {
                let refs = value_refs(*count);
                // Keys must be string ordinals; fall back to an empty dict
                // when no string object precedes this one.
                let keys: Vec<u64> = if string_ordinals.is_empty() {
                    Vec::new()
                } else {
                    refs.iter()
                        .map(|offset| {
                            string_ordinals[(offset % string_ordinals.len() as u64) as usize]
                        })
                        .collect()
                };
                push_sized(&mut bytes, 0xD0, keys.len());
                for reference in keys.iter().chain(refs.iter()) {
                    bytes.extend(reference.to_be_bytes()[8 - ref_width..].to_vec());
                }
            }
        }
    }
    // The offset table precedes the trailer: one entry per object,
    // big-endian, `offsetIntSize` bytes wide (RFC 0013 §5.8). The trailer
    // field points at the START of the table.
    let offset_table_start = bytes.len() as u64;
    for offset in &offsets {
        bytes.extend(offset.to_be_bytes()[8 - offset_width..].to_vec());
    }
    bytes.extend([0u8; 6]);
    // The trailer holds the byte widths directly (1, 2, 4, 8), not
    // exponents (RFC 0013 §5.7).
    bytes.push(1 << offset_int_size_exp);
    bytes.push(1 << object_ref_size_exp);
    bytes.extend((seeds.len() as u64).to_be_bytes());
    bytes.extend(0u64.to_be_bytes()); // top object
    bytes.extend(offset_table_start.to_be_bytes());
    GeneratedFile {
        bytes,
        object_count: seeds.len() as u64,
        expected_offsets: offsets,
        offset_width,
    }
}

/// Writes the sized marker: a nibble count for small lengths, otherwise an
/// inline integer object (RFC 0013 §5.4: the extended size is itself a
/// 0x10-prefixed integer object).
fn push_sized(bytes: &mut Vec<u8>, marker_base: u8, count: usize) {
    if count < 0x0F {
        bytes.push(marker_base | count as u8);
    } else {
        bytes.push(marker_base | 0x0F);
        bytes.push(0x11); // 2-byte integer object
        bytes.extend((count as u16).to_be_bytes());
    }
}

fn object_seeds() -> impl Strategy<Value = Vec<ObjectSeed>> {
    prop::collection::vec(object_seed(), 1..=12)
}

fn generated_file() -> impl Strategy<Value = GeneratedFile> {
    (object_seeds(), 0u8..=3, 0u8..=3)
        .prop_map(|(seeds, offset_int_size_exp, object_ref_size_exp)| {
            build_file(&seeds, offset_int_size_exp, object_ref_size_exp)
        })
        .prop_filter(
            "the offset table width must hold every offset and the file must reach the binary minimum",
            |file| {
                let max_fit = 1u64
                    .checked_shl(u32::try_from(file.offset_width * 8).unwrap_or(64))
                    .unwrap_or(u64::MAX);
                // Every object offset AND the offset-table start itself
                // must be representable in `offsetIntSize` bytes (the
                // parser's offset-int-size-sufficiency check). The table
                // starts at `len - 32 (trailer) - table_bytes`.
                let table_start = file.bytes.len() as u64
                    - 32
                    - file.object_count * file.offset_width as u64;
                file.expected_offsets.iter().all(|offset| *offset < max_fit)
                    && table_start < max_fit
                    && file.bytes.len() >= 42
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    /// Decoded offset facts must exactly match the builder's offset table,
    /// in object-table order, every ref must resolve, and a formed binary
    /// document must be Complete and render byte-exactly.
    #[test]
    fn binary_offset_table_decodes_exactly(file in generated_file()) {
        let formed = parse_binary(
            Arc::<[u8]>::from(file.bytes.clone()),
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("the builder's file must form");
        prop_assert_eq!(
            formed.facts().objects().len() as u64,
            file.object_count,
            "object count comes from the trailer"
        );
        let decoded_offsets: Vec<u64> = formed
            .facts()
            .offsets()
            .iter()
            .map(|fact: &BinaryOffsetFact| fact.offset() as u64)
            .collect();
        prop_assert_eq!(
            decoded_offsets,
            file.expected_offsets.as_slice(),
            "decoded offsets must equal the builder's offset table"
        );
        // Offsets are strictly increasing (objects are laid out in order).
        prop_assert!(
            file.expected_offsets.windows(2).all(|pair| pair[0] < pair[1]),
            "object offsets are strictly increasing"
        );
        // Every object marker sits inside the file.
        for fact in formed.facts().objects() {
            prop_assert!(
                fact.offset() < file.bytes.len(),
                "object marker offset stays inside the file"
            );
        }
        // A fully formed binary document is Complete and byte-exact.
        let document = parse(
            Arc::<[u8]>::from(file.bytes.clone()),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("the builder's file forms a document");
        prop_assert_eq!(
            document.formation_status(),
            FormationStatus::Complete,
            "a hand-built binary plist forms completely"
        );
        prop_assert_eq!(document.render(), file.bytes.as_slice());
    }
}
