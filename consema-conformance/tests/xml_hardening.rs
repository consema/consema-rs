//! Adversarial XML closure properties for the 0.9.0 release gate.

use consema_document::FormationStatus;
use consema_xml::{XmlEncodingSelection, XmlParseLimits, XmlProfile, parse};
use std::sync::Arc;

fn parse_xml(source: &[u8], limits: XmlParseLimits) -> Result<consema_xml::Document, String> {
    let bytes: Arc<[u8]> = Arc::from(source);
    parse(
        bytes,
        XmlProfile::SafeV1,
        XmlEncodingSelection::ProfileDefault,
        limits,
    )
    .map_err(|error| format!("{error:?}"))
}

/// Every formed document, complete or recovered, must render byte-exactly
/// and cover its source exhaustively; nothing may panic.
fn assert_parse_closure(source: &[u8], limits: XmlParseLimits) {
    if let Ok(document) = parse_xml(source, limits) {
        assert_eq!(document.render(), source);
        let index = document.lossless_structural_index().expect("index");
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, source.len());
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            index.pieces().len(),
            "kinds stay parallel to pieces"
        );
    }
}

#[test]
fn malformed_xml_never_forms_partial_documents() {
    let malformed: &[&[u8]] = &[
        b"",
        b"<",
        b"<root",
        b"<root>",
        b"</root>",
        b"<root>a</root></root>",
        b"<root><a></root>",
        b"<root a=>x</root>",
        b"<root a=\"unterminated>",
        b"<root><!-- unterminated</root>",
        b"<root><![CDATA[unterminated</root>",
        b"<root><?pi unterminated</root>",
        b"<?xml version=\"2.0\"?><root/>",
        b"<root>&#0;</root>",
        b"<root>&#xD800;</root>",
        b"<root>&unknown;</root>",
        b"<!DOCTYPE root [<!ELEMENT root EMPTY>]><root/>",
        b"<!DOCTYPE root [<!ATTLIST root a CDATA \"1\">]><root/>",
        b"<!DOCTYPE root [<!NOTATION n SYSTEM \"x\">]><root/>",
        b"<!DOCTYPE root [<![INCLUDE[<!ENTITY e \"x\">]]>]><root/>",
        b"<!DOCTYPE root SYSTEM \"http://x/\"><root/>",
        b"<!DOCTYPE root [<!ENTITY % p \"x\">]><root/>",
        b"<!DOCTYPE root [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><root/&e;>",
        b"\xff",
        b"\xff\xfe",
        b"\xfe\xff",
        b"<root>\xff</root>",
    ];
    for source in malformed {
        if let Ok(document) = parse_xml(source, XmlParseLimits::default()) {
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
fn mutation_and_truncation_never_panic_or_fabricate() {
    let seeds: &[&[u8]] = &[
        br#"<?xml version="1.0"?><root a="1"><child>t</child></root>"#,
        br#"<!DOCTYPE root [<!ENTITY e "hello">]><root>&e;</root>"#,
        "<root>中文 &amp; 文</root>".as_bytes(),
        br#"<p:root xmlns:p="urn:p"><p:child q:attr="x" xmlns:q="urn:q"/></p:root>"#,
        br"<root>a<child/>b<![CDATA[c]]><!--d--><?pi e?>f</root>",
    ];
    for seed in seeds {
        for length in 0..seed.len() {
            assert_parse_closure(&seed[..length], XmlParseLimits::default());
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                assert_parse_closure(&mutated, XmlParseLimits::default());
            }
        }
    }
}

#[test]
fn truncation_and_mutation_of_utf16_never_panic() {
    let text = "<root>中文</root>";
    let mut seed = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        seed.extend_from_slice(&unit.to_le_bytes());
    }
    for length in 0..seed.len() {
        assert_parse_closure(&seed[..length], XmlParseLimits::default());
    }
    for index in (2..seed.len()).step_by(2) {
        for mask in [0x01, 0x80, 0xff] {
            let mut mutated = seed.clone();
            mutated[index] ^= mask;
            assert_parse_closure(&mutated, XmlParseLimits::default());
        }
    }
}

#[test]
fn xml_parse_limits_reject_before_publishing_a_document() {
    let cases: Vec<(Vec<u8>, XmlParseLimits)> = vec![
        (
            b"<root/>".to_vec(),
            XmlParseLimits {
                common: consema_document::ParseLimits {
                    max_source_bytes: 4,
                    ..consema_document::ParseLimits::default()
                },
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<a><b><c><d/></c></b></a>".to_vec(),
            XmlParseLimits {
                common: consema_document::ParseLimits {
                    max_nesting_depth: 2,
                    ..consema_document::ParseLimits::default()
                },
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root a=\"1234567890\"/>".to_vec(),
            XmlParseLimits {
                max_attribute_value_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root><!-- 1234567890 --></root>".to_vec(),
            XmlParseLimits {
                max_comment_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root>1234567890</root>".to_vec(),
            XmlParseLimits {
                max_text_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root><![CDATA[1234567890]]></root>".to_vec(),
            XmlParseLimits {
                max_cdata_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root><?pi 1234567890?></root>".to_vec(),
            XmlParseLimits {
                max_pi_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root xmlns:p=\"urn:verylongnamespace\"><p:x/></root>".to_vec(),
            XmlParseLimits {
                max_namespace_uri_length: 4,
                ..XmlParseLimits::default()
            },
        ),
        (
            b"<root a=\"1\" b=\"2\" c=\"3\"/>".to_vec(),
            XmlParseLimits {
                max_attribute_count: 2,
                ..XmlParseLimits::default()
            },
        ),
    ];
    for (source, limits) in cases {
        assert!(
            parse_xml(&source, limits).is_err(),
            "bounded parse unexpectedly formed a document: {:?}",
            String::from_utf8_lossy(&source)
        );
    }
}

#[test]
fn billion_laughs_variants_are_bounded_by_document_wide_accounting() {
    // Classic billion laughs: exponential nesting across ten levels.
    use std::fmt::Write as _;
    let mut dtd = String::from("<!DOCTYPE root [<!ENTITY e0 \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\">");
    for index in 1..10 {
        let _ = write!(
            dtd,
            "<!ENTITY e{index} \"&e{};&e{};&e{};&e{};&e{};&e{};&e{};&e{};\">",
            index - 1,
            index - 1,
            index - 1,
            index - 1,
            index - 1,
            index - 1,
            index - 1,
            index - 1
        );
    }
    dtd.push_str("]><root>&e9;</root>");
    let source = dtd;
    let document = parse_xml(source.as_bytes(), XmlParseLimits::default()).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.entity.amplification@1"),
        "billion laughs must hit the document-wide amplification limit"
    );

    // Linear amplification with a tight ratio.
    let limits = XmlParseLimits {
        max_entity_amplification_ratio: 2,
        ..XmlParseLimits::default()
    };
    let source =
        br#"<!DOCTYPE root [<!ENTITY a "xxxxxxxxxxxxxxxxxxxx">]><root>&a;&a;&a;&a;&a;&a;</root>"#;
    let document = parse_xml(source, limits).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.entity.amplification@1")
    );
}

#[test]
fn cyclic_entities_are_bounded_and_recovered() {
    let source = br#"<!DOCTYPE root [<!ENTITY a "&b;"><!ENTITY b "&a;">]><root>&a;</root>"#;
    let document = parse_xml(source, XmlParseLimits::default()).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.entity.cyclic@1"),
        "cyclic references must publish the cycle diagnostic"
    );
}

#[test]
fn deep_reference_nesting_hits_the_depth_limit() {
    use std::fmt::Write as _;
    let mut dtd = String::from("<!DOCTYPE root [");
    let mut references = String::new();
    for index in 0..200 {
        let _ = write!(dtd, "<!ENTITY e{index} \"&e{};\">", index + 1);
        let _ = write!(references, "&e{index};");
    }
    dtd.push_str("]><root>");
    dtd.push_str(&references);
    dtd.push_str("</root>");
    let document = parse_xml(dtd.as_bytes(), XmlParseLimits::default()).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.entity.limit@1"),
        "reference nesting must hit the entity expansion depth limit"
    );
    assert!(
        document
            .diagnostics()
            .iter()
            .any(|d| d.code == "xml.entity.cyclic@1"),
        "each breached chain unwinds through the cycle diagnostic"
    );
}

#[test]
fn namespace_attacks_never_fabricate_expanded_names() {
    let cases: &[&[u8]] = &[
        br"<p:root/>",
        br#"<root xmlns="http://www.w3.org/2000/xmlns/"/>"#,
        br#"<root xmlns:xml="urn:wrong"/>"#,
        br#"<root xmlns:xmlns="urn:x"/>"#,
        br#"<root xmlns:p="urn:u" xmlns:q="urn:u" p:a="1" q:a="2"/>"#,
        br#"<root xmlns:p="urn:u" xmlns:q="urn:u" p:a="1" q:a="2">t</root>"#,
        br#"<root xmlns:p="urn:u" p:a="1" p:a="2"/>"#,
    ];
    for source in cases {
        let document = parse_xml(source, XmlParseLimits::default()).expect("forms");
        assert_eq!(
            document.status(),
            FormationStatus::Recovered,
            "namespace violation must recover: {:?}",
            String::from_utf8_lossy(source)
        );
        assert!(
            !document.diagnostics().is_empty(),
            "recovery always publishes diagnostics: {:?}",
            String::from_utf8_lossy(source)
        );
    }
}

#[test]
fn recovered_documents_keep_exhaustive_coverage() {
    let seeds: &[&[u8]] = &[
        br"<root><a></root>",
        br"<root>&unknown; &another;</root>",
        br#"<!DOCTYPE root [<!ENTITY e SYSTEM "x">]><root/>"#,
        br#"<root a="1"><![CDATA[unterminated"#,
    ];
    for seed in seeds {
        let document = parse_xml(seed, XmlParseLimits::default()).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert_eq!(document.render(), *seed);
        let index = document.lossless_structural_index().expect("index");
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, seed.len());
    }
}

#[test]
fn mixed_content_limit_publishes_diagnostics_for_every_drop() {
    let limits = XmlParseLimits {
        max_mixed_content_items: 1,
        ..XmlParseLimits::default()
    };
    let source = br"<root>a<child/>b<child2/>c</root>";
    let document = parse_xml(source, limits).expect("forms");
    assert_eq!(document.status(), FormationStatus::Recovered);
    let drops = document
        .diagnostics()
        .iter()
        .filter(|d| d.code == "xml.limit.mixed-content@1")
        .count();
    assert_eq!(
        drops, 4,
        "each of the four dropped content items is diagnosed exactly once"
    );
    assert_eq!(document.render(), source);
}
