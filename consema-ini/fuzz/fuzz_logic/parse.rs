// Fuzz-target logic: consema-ini parser entry point (0.13.0 gate plan M2).
//
// Single source of truth for both harnesses: the in-process engine
// (`crates/consema-conformance/tests/parse_fuzz.rs`) and the libFuzzer
// wrapper (`crates/consema-ini/fuzz/fuzz_targets/parse.rs`). Resource
// limits are the production profile defaults; a limit failure is a fatal
// formation error and therefore a pass, never a crash.

use consema_document::FormationStatus;
use consema_ini::{IniEncodingSelection, IniParseLimits, IniProfile, parse};

#[allow(dead_code)] // used by the parse_fuzz driver and the cargo-fuzz wrapper
/// Drives the production INI profiles over one input.
pub fn fuzz_parse(data: &[u8]) {
    for profile in [
        IniProfile::PortableV1,
        IniProfile::WindowsV1,
        IniProfile::PythonConfigParserV1,
    ] {
        assert_parse_closure(data, profile, IniParseLimits::default());
    }
}

#[allow(dead_code)] // used by the parse_fuzz driver and the cargo-fuzz wrapper
/// One parse closure under the profile's frozen default encoding.
pub fn assert_parse_closure(data: &[u8], profile: IniProfile, limits: IniParseLimits) {
    let Ok(document) = parse(data, profile, IniEncodingSelection::ProfileDefault, limits) else {
        return; // fatal formation (including resource-limit truncation): pass
    };
    assert_formed_closure(data, limits, document);
}

/// Shared formed-document closure: render byte-exact, exhaustive coverage,
/// kinds parallel to pieces, diagnostics within budget, recovered documents
/// publish diagnostics.
pub fn assert_formed_closure(data: &[u8], limits: IniParseLimits, document: consema_ini::Document) {
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
