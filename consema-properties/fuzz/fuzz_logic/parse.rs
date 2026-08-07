// Fuzz-target logic: consema-properties parser entry point
// (0.13.0 gate plan M2).
//
// Single source of truth for both harnesses: the in-process engine
// (`crates/consema-conformance/tests/parse_fuzz.rs`) and the libFuzzer
// wrapper (`crates/consema-properties/fuzz/fuzz_targets/parse.rs`).
// Resource limits are the production profile defaults; a limit failure is a
// fatal formation error and therefore a pass, never a crash.

use consema_document::{FormationStatus, SourceEncoding};
use consema_properties::{PropertiesParseLimits, parse_latin1, parse_reader};

#[allow(dead_code)] // used by the parse_fuzz driver and the cargo-fuzz wrapper
/// Drives the production Properties profiles over one input.
pub fn fuzz_parse(data: &[u8]) {
    let limits = PropertiesParseLimits::default();
    assert_parse_closure_reader(data, limits);
    assert_parse_closure_latin1(data, limits);
}

/// ReaderV1 parse closure (UTF-8 reader contract).
pub fn assert_parse_closure_reader(data: &[u8], limits: PropertiesParseLimits) {
    let Ok(document) = parse_reader(data, SourceEncoding::Utf8, limits) else {
        return; // fatal formation (including resource-limit truncation): pass
    };
    assert_formed_closure(data, limits, document);
}

/// Latin1V1 parse closure (ISO-8859-1 byte contract).
pub fn assert_parse_closure_latin1(data: &[u8], limits: PropertiesParseLimits) {
    let Ok(document) = parse_latin1(data, limits) else {
        return; // fatal formation (including resource-limit truncation): pass
    };
    assert_formed_closure(data, limits, document);
}

/// Shared formed-document closure.
pub fn assert_formed_closure(
    data: &[u8],
    limits: PropertiesParseLimits,
    document: consema_properties::Document,
) {
    assert_eq!(document.render(), data, "formed documents render byte-exactly");
    let index = document.lossless_structural_index();
    let covered: usize = index
        .pieces()
        .iter()
        .map(|piece| piece.span().len())
        .sum();
    assert_eq!(covered, data.len(), "formation covers the source exhaustively");
    assert_eq!(
        document.lossless_syntax_kinds().len(),
        index.pieces().len(),
        "syntax kinds stay parallel to structural pieces"
    );
    assert!(
        document.diagnostics().len() <= limits.common.max_diagnostics,
        "diagnostics stay within the resource contract"
    );
    if document.formation_status() == FormationStatus::Recovered {
        assert!(
            !document.diagnostics().is_empty(),
            "recovered documents always publish diagnostics"
        );
    }
}
