#![no_main]
//! libFuzzer target: consema-properties parser (0.13.0 gate plan M2).
//! See crates/consema-json/fuzz/fuzz_targets/parse.rs for the harness
//! equivalence statement.

use libfuzzer_sys::fuzz_target;

mod logic {
    include!("../fuzz_logic/parse.rs");
}

fuzz_target!(|data: &[u8]| {
    logic::fuzz_parse(data);
});
