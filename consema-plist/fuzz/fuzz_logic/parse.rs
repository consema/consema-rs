// Fuzz-target logic: consema-plist parser entry point (0.13.0 gate plan M2).
//
// Single source of truth for both harnesses: the in-process engine
// (`crates/consema-conformance/tests/parse_fuzz.rs`) and the libFuzzer
// wrapper (`crates/consema-plist/fuzz/fuzz_targets/parse.rs`). Resource
// limits are the production profile defaults; a limit failure is a fatal
// formation error and therefore a pass, never a crash. Both profiles
// (`plist.xml@1` and `plist.binary@1`) run: the binary profile drives the
// offset-table/object-ref decoders, the XML profile drives the XML decoder.

use consema_document::FormationStatus;
use consema_plist::{PlistEncodingSelection, PlistParseLimits, PlistProfile, parse};
use std::sync::Arc;

#[allow(dead_code)] // used by the parse_fuzz driver and the cargo-fuzz wrapper
/// Drives the production plist profiles over one input.
pub fn fuzz_parse(data: &[u8]) {
    for profile in [PlistProfile::XmlV1, PlistProfile::BinaryV1] {
        assert_parse_closure(data, profile, PlistParseLimits::default());
    }
}

/// One parse closure: formed documents render byte-exactly, cover the source
/// exhaustively, keep kinds parallel to pieces, stay inside the diagnostic
/// budget, and publish diagnostics when recovered.
pub fn assert_parse_closure(data: &[u8], profile: PlistProfile, limits: PlistParseLimits) {
    let Ok(document) = parse(
        Arc::<[u8]>::from(data),
        profile,
        PlistEncodingSelection::ProfileDefault,
        limits,
    ) else {
        return; // fatal formation (including resource-limit truncation): pass
    };
    assert_eq!(
        document.render(),
        data,
        "formed documents render byte-exactly"
    );
    // The lossless structural index and syntax kinds are `plist.xml@1` only
    // (RFC 0013 §8.2, hard gate 1); the binary profile covers its bytes
    // through the offset/object facts instead.
    if let Some(index) = document.lossless_structural_index() {
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(
            covered,
            data.len(),
            "formation covers the source exhaustively"
        );
        assert_eq!(
            document
                .lossless_syntax_kinds()
                .expect("syntax kinds")
                .len(),
            index.pieces().len(),
            "syntax kinds stay parallel to structural pieces"
        );
    }
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
