//! Adversarial plist closure properties for the 0.10.0 release gate.

use consema_document::FormationStatus;
use consema_plist::{Document, PlistEncodingSelection, PlistParseLimits, PlistProfile, parse};
use std::sync::Arc;

fn parse_xml(source: &[u8], limits: PlistParseLimits) -> Result<Document, String> {
    parse(
        Arc::from(source.to_vec()),
        PlistProfile::XmlV1,
        PlistEncodingSelection::ProfileDefault,
        limits,
    )
    .map_err(|error| format!("{error:?}"))
}

fn parse_binary(source: &[u8], limits: PlistParseLimits) -> Result<Document, String> {
    parse(
        Arc::from(source.to_vec()),
        PlistProfile::BinaryV1,
        PlistEncodingSelection::ProfileDefault,
        limits,
    )
    .map_err(|error| format!("{error:?}"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// Every formed XML document, complete or recovered, must render byte-exactly,
/// cover its source exhaustively, and keep kinds parallel to pieces; nothing
/// may panic.
fn assert_parse_closure_xml(source: &[u8], limits: PlistParseLimits) {
    if let Ok(document) = parse_xml(source, limits) {
        assert_eq!(document.render(), source);
        if let Some(index) = document.lossless_structural_index() {
            let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
            assert_eq!(covered, source.len());
            assert_eq!(
                document
                    .lossless_syntax_kinds()
                    .map_or(0, <[consema_plist::PlistSyntaxKind]>::len),
                index.pieces().len(),
                "kinds stay parallel to pieces"
            );
        }
    }
}

/// Every formed binary document, complete or recovered, must render
/// byte-exactly; nothing may panic.
fn assert_parse_closure_binary(source: &[u8], limits: PlistParseLimits) {
    if let Ok(document) = parse_binary(source, limits) {
        assert_eq!(document.render(), source);
    }
}

#[test]
fn malformed_xml_never_forms_partial_documents() {
    let malformed: &[&[u8]] = &[
        b"",
        b"<",
        b"<plist",
        b"<plist>",
        b"<plist version=\"1.0\">",
        b"<plist version=\"1.0\"><string>x</plist>",
        b"<plist version=\"1.0\"><string>",
        b"<plist version=\"1.0\"><string>x</string></plist></plist>",
        b"<plist version=\"1.0\"><dict><key>a</key></dict></plist>",
        b"<plist version=\"1.0\"><dict><string>x</string></dict></plist>",
        b"<plist version=\"2.0\"><string>x</string></plist>",
        b"<plist version=\"1.0\" extra=\"1\"><string>x</string></plist>",
        b"<plist version=\"1.0\"><unknown/></plist>",
        b"<plist version=\"1.0\"><integer>12a</integer></plist>",
        b"<plist version=\"1.0\"><date>2024-02-30T00:00:00Z</date></plist>",
        b"<plist version=\"1.0\"><data>AB$C</data></plist>",
        b"<plist version=\"1.0\"><string>&unknown;</string></plist>",
        b"<plist version=\"1.0\"><string>a</string> trailing",
        b"<plist version=\"1.0\"><![CDATA[x]]></plist>",
        b"<plist version=\"1.0\"><!-- unterminated</plist>",
        b"<plist version=\"1.0\"><string>a</string><?pi unterminated",
        b"<!DOCTYPE plist SYSTEM \"http://x/\"><plist version=\"1.0\"/>",
        b"<!DOCTYPE wrong PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"/>",
        b"\xff",
        b"\xff\xfe",
        b"<plist version=\"1.0\">\xff</plist>",
    ];
    for source in malformed {
        if let Ok(document) = parse_xml(source, PlistParseLimits::default()) {
            assert_eq!(
                document.status(),
                FormationStatus::Recovered,
                "malformed input must recover, never complete: {source:?}"
            );
            assert!(
                !document.diagnostics().is_empty(),
                "recovered document must publish diagnostics: {source:?}"
            );
        }
    }
}

#[test]
fn xml_mutation_and_truncation_never_panic_or_fabricate() {
    let seeds: &[&[u8]] = &[
        b"<plist version=\"1.0\"><string>ok</string></plist>",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><string>ok</string></plist>\n",
        b"<plist version=\"1.0\"><dict><key>name</key><string>Consema</string><key>count</key><integer>0x2A</integer><key>payload</key><data>AQID</data><key>tags</key><array><string>a</string><dict/></array></dict></plist>",
        "<plist version=\"1.0\"><string>中文 &amp; 文</string></plist>".as_bytes(),
        b"<plist version=\"1.0\"><dict><key>text</key><string>a &lt; b &amp; c &#65; <![CDATA[raw]]></string></dict></plist>",
    ];
    for seed in seeds {
        for length in 0..seed.len() {
            assert_parse_closure_xml(&seed[..length], PlistParseLimits::default());
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                assert_parse_closure_xml(&mutated, PlistParseLimits::default());
            }
        }
    }
}

#[test]
fn binary_mutation_and_truncation_never_panic_or_fabricate() {
    let seeds: &[&str] = &[
        "62706c697374303050080000000000000101000000000000000100000000000000000000000000000009",
        "62706c6973743030d1010251611001080b0d000000000000010100000000000000030000000000000000000000000000000f",
        "62706c6973743030a3010102d103045178516b5176080c0f11130000000000000101000000000000000500000000000000000000000000000015",
        "62706c6973743030d201010203516b10011002080d0f110000000000000101000000000000000400000000000000000000000000000013",
        "62706c6973743030a2010210015162080b0d000000000000010100000000000000030000000000000000000000000000000f",
    ];
    for seed in seeds {
        let seed = decode_hex(seed);
        for length in 0..seed.len() {
            assert_parse_closure_binary(&seed[..length], PlistParseLimits::default());
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.clone();
                mutated[index] ^= mask;
                assert_parse_closure_binary(&mutated, PlistParseLimits::default());
            }
        }
    }
}

#[test]
fn plist_parse_limits_reject_before_publishing_a_document() {
    let xml_limits: Vec<(Vec<u8>, PlistParseLimits)> = vec![
        (
            b"<plist version=\"1.0\"><string>ok</string></plist>".to_vec(),
            PlistParseLimits {
                common: consema_document::ParseLimits {
                    max_source_bytes: 16,
                    ..consema_document::ParseLimits::default()
                },
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><dict><key>a</key><dict><key>b</key><dict><key>c</key><string>x</string></dict></dict></dict></plist>".to_vec(),
            PlistParseLimits {
                common: consema_document::ParseLimits {
                    max_nesting_depth: 2,
                    ..consema_document::ParseLimits::default()
                },
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string></dict></plist>".to_vec(),
            PlistParseLimits {
                max_object_count: 1,
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><dict><key>a</key><dict><key>b</key><dict><key>c</key><string>x</string></dict></dict></dict></plist>".to_vec(),
            PlistParseLimits {
                max_container_depth: 2,
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><string>abcde</string></plist>".to_vec(),
            PlistParseLimits {
                max_string_code_units: 4,
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><data>QUJDRA==</data></plist>".to_vec(),
            PlistParseLimits {
                max_data_bytes: 3,
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><dict><key>a</key><integer>1</integer><key>b</key><integer>2</integer></dict></plist>".to_vec(),
            PlistParseLimits {
                max_dict_entries: 1,
                ..PlistParseLimits::default()
            },
        ),
        (
            b"<plist version=\"1.0\"><array><integer>1</integer><integer>2</integer></array></plist>".to_vec(),
            PlistParseLimits {
                max_array_elements: 1,
                ..PlistParseLimits::default()
            },
        ),
    ];
    for (source, limits) in xml_limits {
        assert!(
            parse_xml(&source, limits).is_err(),
            "bounded XML parse unexpectedly formed a document: {:?}",
            String::from_utf8_lossy(&source)
        );
    }

    let binary_limits: Vec<(Vec<u8>, PlistParseLimits)> = vec![
        (
            decode_hex(
                "62706c697374303050080000000000000101000000000000000100000000000000000000000000000009",
            ),
            PlistParseLimits {
                common: consema_document::ParseLimits {
                    max_source_bytes: 20,
                    ..consema_document::ParseLimits::default()
                },
                ..PlistParseLimits::default()
            },
        ),
        (
            decode_hex(
                "62706c6973743030d1010251611001080b0d000000000000010100000000000000030000000000000000000000000000000f",
            ),
            PlistParseLimits {
                max_object_count: 2,
                ..PlistParseLimits::default()
            },
        ),
        (
            decode_hex(
                "62706c6973743030d1010251611001080b0d000000000000010100000000000000030000000000000000000000000000000f",
            ),
            PlistParseLimits {
                max_offset_table_bytes: 1,
                ..PlistParseLimits::default()
            },
        ),
        (
            decode_hex(
                "62706c6973743030d1010251611001080b0d000000000000010100000000000000030000000000000000000000000000000f",
            ),
            PlistParseLimits {
                max_binary_facts: 1,
                ..PlistParseLimits::default()
            },
        ),
    ];
    for (source, limits) in binary_limits {
        assert!(
            parse_binary(&source, limits).is_err(),
            "bounded binary parse unexpectedly formed a document: {}",
            source.iter().fold(String::new(), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
                out
            })
        );
    }
}

#[test]
fn recovered_documents_keep_exhaustive_coverage_and_diagnostics() {
    let xml_seeds: &[&[u8]] = &[
        b"<plist version=\"1.0\"><string>ok</string></plist> trailing",
        b"<!DOCTYPE wrong PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><string>ok</string></plist>",
        b"<plist><string>ok</string></plist>",
        b"<plist version=\"1.0\"><dict><key>a</key></dict></plist>",
        b"<plist version=\"1.0\"><string>&unknown;</string></plist>",
    ];
    for seed in xml_seeds {
        let document = parse_xml(seed, PlistParseLimits::default()).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert_eq!(document.render(), *seed);
        assert!(
            !document.diagnostics().is_empty(),
            "recovery always publishes diagnostics: {:?}",
            String::from_utf8_lossy(seed)
        );
        let index = document.lossless_structural_index().expect("index");
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, seed.len());
    }

    let binary_seeds: &[&str] = &[
        "62706c697374303000080000000000000101000000000000000100000000000000000000000000000009",
        "62706c697374303050500805000000000000010100000000000000020000000000000000000000000000000a",
        "62706c69737430305150080000000000000101000000000000000100000000000000000000000000000009",
    ];
    for seed in binary_seeds {
        let seed = decode_hex(seed);
        let document = parse_binary(&seed, PlistParseLimits::default()).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert_eq!(document.render(), seed);
        assert!(
            !document.diagnostics().is_empty(),
            "recovery always publishes diagnostics: {seed:?}"
        );
    }
}

#[test]
fn published_plist_vector_suite_is_conformant() {
    let report = consema_conformance::run_plist_v1();
    assert!(report.is_conformant(), "{report:#?}");
    assert_eq!(report.passed.len(), 45);
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn published_types_are_send_and_sync() {
    assert_send_sync::<Document>();
    assert_send_sync::<consema_plist::PlistDocument>();
    assert_send_sync::<consema_plist::EditTransaction>();
    assert_send_sync::<consema_plist::EditCommit>();
    assert_send_sync::<consema_plist::ProjectionRequest>();
    assert_send_sync::<consema_plist::PlistParseLimits>();
}
