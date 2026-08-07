//! XML encoding corpus: BOM/declaration conflicts, UTF-16LE/BE, non-BMP
//! names and content, invalid sequences, and raw/decoded span closure.

use consema_document::{FatalFormationFailure, FormationStatus};
use consema_xml::{XmlEncodingSelection, XmlParseLimits, XmlProfile, parse};
use std::sync::Arc;

fn parse_bytes(
    bytes: &[u8],
    selection: XmlEncodingSelection,
) -> Result<consema_xml::Document, FatalFormationFailure> {
    let bytes: Arc<[u8]> = Arc::from(bytes);
    parse(
        bytes,
        XmlProfile::SafeV1,
        selection,
        XmlParseLimits::default(),
    )
}

fn utf16_bytes(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend_from_slice(if big_endian {
            &[0xFE, 0xFF]
        } else {
            &[0xFF, 0xFE]
        });
    }
    for unit in text.encode_utf16() {
        let encoded = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

#[test]
fn utf8_bom_is_retained_and_span_closed() {
    let source = "\u{FEFF}<root>\u{6587}</root>".as_bytes();
    let document = parse_bytes(source, XmlEncodingSelection::ProfileDefault).expect("forms");
    assert_eq!(document.status(), FormationStatus::Complete);
    assert_eq!(document.render(), source, "UTF-8 BOM bytes are preserved");
    let index = document.lossless_structural_index().expect("index");
    let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
    assert_eq!(covered, source.len(), "raw/decoded span closure");
    assert_eq!(
        index.pieces()[0].kind(),
        consema_document::StructuralPieceKind::Trivia,
        "BOM is trivia"
    );
}

#[test]
fn utf16le_and_be_bom_documents_round_trip() {
    let text = "<root>中文</root>";
    for big_endian in [false, true] {
        let bytes = utf16_bytes(text, big_endian, true);
        let document = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault).expect("forms");
        assert_eq!(
            document.status(),
            FormationStatus::Complete,
            "UTF-16{} with BOM forms",
            if big_endian { "BE" } else { "LE" }
        );
        assert_eq!(document.render(), bytes.as_slice());
    }
}

#[test]
fn utf16_without_bom_never_guesses_endianness() {
    for big_endian in [false, true] {
        let bytes = utf16_bytes("<root/>", big_endian, false);
        // Without a BOM the frozen contract defaults to UTF-8; the NUL code
        // units make the bytes invalid XML, which must recover or fail, and
        // can never fabricate a Complete document by guessing endianness.
        if let Ok(document) = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault) {
            assert_eq!(
                document.status(),
                FormationStatus::Recovered,
                "BOM-less UTF-16 must not form completely"
            );
            assert!(
                !document.diagnostics().is_empty(),
                "recovery always publishes diagnostics: {bytes:?}"
            );
        }
        assert!(
            parse_bytes(
                &bytes,
                XmlEncodingSelection::Explicit(if big_endian {
                    consema_document::SourceEncoding::Utf16Be
                } else {
                    consema_document::SourceEncoding::Utf16Le
                }),
            )
            .is_err(),
            "even an explicit endianness cannot rescue a BOM-less UTF-16 entity"
        );
    }
}

#[test]
fn declaration_encoding_conflicts_are_recovered() {
    // UTF-16LE bytes with a UTF-8 declaration: explicit conflict.
    let text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
    let bytes = utf16_bytes(text, false, true);
    let document = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.declaration.conflict@1"),
        "declaration/encoding conflict must publish its stable diagnostic"
    );

    // Agreeing declaration stays complete.
    let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>";
    let bytes = utf16_bytes(text, false, true);
    let document = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault).expect("forms");
    assert_eq!(document.status(), FormationStatus::Complete);
}

#[test]
fn non_bmp_content_and_names_round_trip_in_both_encodings() {
    let text = "<root>\u{1F980} crab</root>";
    for big_endian in [false, true] {
        let bytes = utf16_bytes(text, big_endian, true);
        let document = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.render(), bytes.as_slice());
    }

    // Non-BMP characters are legal XML Name characters in both encodings.
    let name_document = "<\u{1F980}root/>";
    for big_endian in [false, true] {
        let bytes = utf16_bytes(name_document, big_endian, true);
        let document = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault).expect("forms");
        assert_eq!(
            document.status(),
            FormationStatus::Complete,
            "non-BMP element name must form in UTF-16{}",
            if big_endian { "BE" } else { "LE" }
        );
        assert_eq!(document.render(), bytes.as_slice());
    }
}

#[test]
fn invalid_sequences_never_fabricate_complete_documents() {
    let invalid: Vec<Vec<u8>> = vec![
        // Odd UTF-16 byte count.
        {
            let mut bytes = utf16_bytes("<root/>", false, true);
            bytes.pop();
            bytes
        },
        // Truncated surrogate pair (high surrogate alone at the end).
        {
            let mut bytes = vec![0xFF, 0xFE];
            bytes.extend_from_slice(&0xD83Eu16.to_le_bytes());
            bytes
        },
        // Invalid UTF-8 continuation.
        b"<root>\xC3</root>".to_vec(),
        // Overlong UTF-8 encoding.
        b"<root>\xC0\xAF</root>".to_vec(),
        // UTF-16 bytes interpreted as UTF-8 without a BOM.
        utf16_bytes("<root/>", false, false),
    ];
    for bytes in invalid {
        if let Ok(document) = parse_bytes(&bytes, XmlEncodingSelection::ProfileDefault) {
            assert_eq!(
                document.status(),
                FormationStatus::Recovered,
                "invalid sequences must not fabricate a Complete document: {bytes:?}"
            );
            assert!(
                !document.diagnostics().is_empty(),
                "recovered document must publish diagnostics: {bytes:?}"
            );
        }
    }
}

#[test]
fn explicit_encoding_selection_must_agree_with_bom() {
    let le_bytes = utf16_bytes("<root/>", false, true);
    let be_bytes = utf16_bytes("<root/>", true, true);
    let error = parse_bytes(
        &be_bytes,
        XmlEncodingSelection::Explicit(consema_document::SourceEncoding::Utf16Le),
    )
    .expect_err("BE BOM contradicts explicit LE selection");
    assert!(
        error
            .diagnostics()
            .iter()
            .any(|d| d.code == "core.source.encoding-conflict@1"),
        "BOM/selection contradiction must publish its stable diagnostic"
    );
    let error = parse_bytes(
        &le_bytes,
        XmlEncodingSelection::Explicit(consema_document::SourceEncoding::Utf16Be),
    )
    .expect_err("LE BOM contradicts explicit BE selection");
    assert!(
        error
            .diagnostics()
            .iter()
            .any(|d| d.code == "core.source.encoding-conflict@1"),
        "BOM/selection contradiction must publish its stable diagnostic"
    );
    let document = parse_bytes(
        &le_bytes,
        XmlEncodingSelection::Explicit(consema_document::SourceEncoding::Utf16Le),
    )
    .expect("matching BOM and selection forms");
    assert_eq!(document.status(), FormationStatus::Complete);
    assert_eq!(
        document.render(),
        le_bytes.as_slice(),
        "explicit selection keeps render byte-exact"
    );
    let index = document.lossless_structural_index().expect("index");
    let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
    assert_eq!(
        covered,
        le_bytes.len(),
        "explicit selection keeps exhaustive coverage"
    );
}
