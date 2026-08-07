#![no_main]
//! libFuzzer target: consema-json parser (0.13.0 gate plan M2).
//!
//! The logic is the single source shared with the in-process harness:
//! crates/consema-conformance/tests/parse_fuzz.rs includes
//! fuzz_logic/parse.rs and runs the same assertions under `cargo test`
//! (this Windows/MSVC machine cannot link libFuzzer — no clang — so the
//! in-process harness is the verified equivalent).

use libfuzzer_sys::fuzz_target;

mod logic {
    include!("../fuzz_logic/parse.rs");
}

fuzz_target!(|data: &[u8]| {
    logic::fuzz_parse(data);
});
