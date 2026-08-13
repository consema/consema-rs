//! JSON5 (json5.standard@1) → strict-JSON conversion chain example:
//! parse → best-exact projection → canonical-compact materialization,
//! with byte-exact assertions (the README quick-start example keeps
//! finite JSON5 exactly representable as strict JSON).
//!
//! (The README.md quick-start code fence is compile-gated by
//! consema/examples/quickstart.rs; this test covers the same
//! parse → project → convert shape for the JSON5 profile.)

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
