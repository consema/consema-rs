//! Reproducible wall-clock baseline for the frozen plist production corpus.

use consema::document::{
    MaterializationRequest, MaterializationResult, MaterializationStyleId, NewlinePolicy,
    ProfileId, SourceEncoding,
};
use consema::plist::{
    PlistEncodingSelection, PlistParseLimits, PlistProfile, ProjectionRequest, ProjectionResult,
    materialize, parse, project,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Production-shaped preference-style plist XML corpus (original, MIT).
const PREFERENCE_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ServiceName</key>
	<string>catalog</string>
	<key>Port</key>
	<integer>8080</integer>
	<key>Enabled</key>
	<true/>
	<key>RetryCount</key>
	<integer>3</integer>
	<key>Endpoints</key>
	<array>
		<string>primary</string>
		<string>backup</string>
	</array>
</dict>
</plist>
"#;

/// Byte-for-byte pinned `bplist00` equivalent of `PREFERENCE_XML`; the
/// example asserts it forms a Complete document at startup, so an invalid
/// corpus fails the run before any measurement.
const PREFERENCE_BINARY_HEX: &str = "\
62706C6973743030\
D50103050709020406080A\
5B536572766963654E616D65\
57636174616C6F67\
54706F7274\
111F90\
57456E61626C6564\
09\
5A5265747279436F756E74\
1003\
59456E64706F696E7473\
A20B0C\
577072696D617279\
566261636B7570\
08131F272C2F373843454F525A\
0000000000000101000000000000000D00000000000000000000000000000061";

fn main() {
    let iterations = std::env::args().nth(1).map_or(20_000, |value| {
        value.parse::<u64>().expect("iterations must be u64")
    });
    assert!(iterations > 0, "iterations must be non-zero");

    let preference_binary = decode_hex(PREFERENCE_BINARY_HEX);
    let xml_document = parse_document(PREFERENCE_XML, PlistProfile::XmlV1);
    let binary_document = parse_document(&preference_binary, PlistProfile::BinaryV1);
    let xml_record = project_value(&xml_document);
    let binary_record = project_value(&binary_document);
    let xml_materialization_request = MaterializationRequest::new(
        ProfileId::new("plist.xml", 1),
        MaterializationStyleId::new("plist.xml-canonical", 1),
    );
    let binary_materialization_request = MaterializationRequest::new(
        ProfileId::new("plist.binary", 1),
        MaterializationStyleId::new("plist.binary-canonical", 1),
    )
    .with_encoding(SourceEncoding::Binary)
    .with_newline(NewlinePolicy::None);

    let xml_parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(PREFERENCE_XML, PlistProfile::XmlV1));
    }
    let xml_parse_elapsed = xml_parse_start.elapsed();

    let binary_parse_start = Instant::now();
    for _ in 0..iterations {
        black_box(parse_document(&preference_binary, PlistProfile::BinaryV1));
    }
    let binary_parse_elapsed = binary_parse_start.elapsed();

    let projection_start = Instant::now();
    for _ in 0..iterations {
        black_box(project_value(&xml_document));
    }
    let projection_elapsed = projection_start.elapsed();

    let xml_materialization_start = Instant::now();
    for _ in 0..iterations {
        black_box(materialize(&xml_record, &xml_materialization_request));
    }
    let xml_materialization_elapsed = xml_materialization_start.elapsed();

    let binary_materialization_start = Instant::now();
    for _ in 0..iterations {
        black_box(materialize(&binary_record, &binary_materialization_request));
    }
    let binary_materialization_elapsed = binary_materialization_start.elapsed();

    println!(
        "fixture preference-plist.xml bytes={}",
        PREFERENCE_XML.len()
    );
    println!(
        "parse plist.xml {iterations} iterations in {:?} ({:.1} ns/op)",
        xml_parse_elapsed,
        ns_per_op(xml_parse_elapsed, iterations)
    );
    println!(
        "fixture preference.bplist bytes={}",
        preference_binary.len()
    );
    println!(
        "parse plist.binary {iterations} iterations in {:?} ({:.1} ns/op)",
        binary_parse_elapsed,
        ns_per_op(binary_parse_elapsed, iterations)
    );
    println!(
        "projection value-tree {iterations} iterations in {:?} ({:.1} ns/op)",
        projection_elapsed,
        ns_per_op(projection_elapsed, iterations)
    );
    println!(
        "materialization plist.xml-canonical {iterations} iterations in {:?} ({:.1} ns/op)",
        xml_materialization_elapsed,
        ns_per_op(xml_materialization_elapsed, iterations)
    );
    println!(
        "materialization plist.binary-canonical {iterations} iterations in {:?} ({:.1} ns/op)",
        binary_materialization_elapsed,
        ns_per_op(binary_materialization_elapsed, iterations)
    );

    // The closure contract: materializing the pinned record always succeeds,
    // in both representations, with exact fidelity.
    let MaterializationResult::Complete(xml_complete) =
        materialize(&xml_record, &xml_materialization_request)
    else {
        panic!("pinned plist XML fixture must materialize");
    };
    let MaterializationResult::Complete(binary_complete) =
        materialize(&binary_record, &binary_materialization_request)
    else {
        panic!("pinned plist binary fixture must materialize");
    };
    assert_eq!(
        xml_complete.fidelity,
        consema::document::MaterializationFidelity::Exact
    );
    assert_eq!(
        binary_complete.fidelity,
        consema::document::MaterializationFidelity::Exact
    );
}

#[allow(clippy::cast_precision_loss)]
fn ns_per_op(elapsed: Duration, iterations: u64) -> f64 {
    // Microseconds keep both operands far below f64's 52-bit mantissa.
    elapsed.as_micros() as f64 * 1_000.0 / iterations as f64
}

fn parse_document(source: &[u8], profile: PlistProfile) -> consema::plist::Document {
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(source);
    let document = parse(
        bytes,
        profile,
        PlistEncodingSelection::ProfileDefault,
        PlistParseLimits::default(),
    )
    .expect("pinned fixture must form");
    assert_eq!(
        document.status(),
        consema::document::FormationStatus::Complete
    );
    document
}

fn project_value(document: &consema::plist::Document) -> consema::core::PortableValue {
    let ProjectionResult::Complete(projected) = project(document, ProjectionRequest::value_tree())
    else {
        panic!("pinned fixture must project exactly");
    };
    projected.value
}

fn decode_hex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    assert!(bytes.len() % 2 == 0, "hex must have even length");
    bytes
        .chunks(2)
        .map(|pair| hex_value(pair[0]) << 4 | hex_value(pair[1]))
        .collect()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}
