// Fuzz-target logic: consema-toml parser entry point (0.13.0 gate plan M2).
//
// Single source of truth for both harnesses: the in-process engine
// (`crates/consema-conformance/tests/parse_fuzz.rs`) and the libFuzzer
// wrapper (`crates/consema-toml/fuzz/fuzz_targets/parse.rs`). Resource
// limits are the production profile defaults; a limit failure is a fatal
// formation error and therefore a pass, never a crash.

use consema_document::{FormationStatus, ParseLimits};
use consema_toml::{TomlProfile, parse};

#[allow(dead_code)] // used by the parse_fuzz driver and the cargo-fuzz wrapper
/// Drives the production TOML profile over one input.
pub fn fuzz_parse(data: &[u8]) {
    assert_parse_closure(data, TomlProfile::Toml10V1, ParseLimits::default());
}

/// One parse closure: formed documents render byte-exactly, cover the source
/// exhaustively, keep kinds parallel to pieces, stay inside the diagnostic
/// budget, and publish diagnostics when recovered.
pub fn assert_parse_closure(data: &[u8], profile: TomlProfile, limits: ParseLimits) {
    let Ok(document) = parse(data, profile, limits) else {
        return; // fatal formation (including resource-limit truncation): pass
    };
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
        document.diagnostics().len() <= limits.max_diagnostics,
        "diagnostics stay within the resource contract"
    );
    if document.formation_status() == FormationStatus::Recovered {
        assert!(
            !document.diagnostics().is_empty(),
            "recovered documents always publish diagnostics"
        );
    }
}
