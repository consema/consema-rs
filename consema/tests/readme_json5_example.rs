//! JSON5 (json5.standard@1) → strict-JSON conversion chain example:
//! parse → best-exact projection → canonical-compact materialization,
//! with byte-exact assertions (finite JSON5 is exactly representable
//! as strict JSON).
//!
//! Attribution truth (wave-4 R10; wave-5 P2 anchor fix): the README
//! quick-start fence (the single ```rust code fence in the README's
//! "快速开始" section — located by content, not by line number; line
//! numbers drift, per the repository's anchor discipline) is a
//! strict-JSON parse → query → edit → render example — the only JSON5
//! mention in the README is the `json5.standard@1` entry in the profile
//! list — so the earlier claim that "the README quick-start example keeps
//! finite JSON5 exactly representable as strict JSON" was a leftover from
//! the 0.8.0-era README that did carry a JSON5 example. This test is the
//! JSON5 conversion gate itself; the README fence is compile-gated by
//! consema/examples/quickstart.rs (same parse → project → convert shape
//! for the JSON5 profile).

use consema::document::{
    MaterializationRequest, MaterializationStyleId, NewlinePolicy, ParseLimits, ProfileId,
};
use consema::json::{JsonProfile, ProjectionRequestBuilder, ProjectionTarget, parse};
use consema::{ConversionResult, convert_json};

#[test]
fn json5_to_strict_conversion_is_exact() {
    let source = br"{service:'catalog',limit:0x100,retry:.25,enabled:true,}";
    let document = parse(
        source.as_slice(),
        JsonProfile::Json5StandardV1,
        ParseLimits::default(),
    )
    .expect("valid JSON5");
    assert_eq!(document.render(), source);

    let projection = ProjectionRequestBuilder::new(ProjectionTarget::Json5BestExactCoreV1)
        .build()
        .unwrap();
    let target = MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new("json.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None);

    let ConversionResult::Complete(converted) = convert_json(&document, &projection, &target)
    else {
        panic!("finite JSON5 is exactly representable as strict JSON");
    };
    assert_eq!(
        converted.document.render(),
        br#"{"service":"catalog","limit":256,"retry":25e-2,"enabled":true}"#,
    );
}
