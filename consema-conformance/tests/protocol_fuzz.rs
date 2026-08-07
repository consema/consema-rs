//! Deterministic in-process fuzz for the protocol/PVCE/PGCE decoders
//! (0.13.0 gate plan M2).
//!
//! Drives the high-risk decoder entry points (canonical JSON transport,
//! PVCE varint transport, PGCE graph transport) with mutated bytes under
//! the production default limits. Target logic is
//! `crates/consema-protocol/fuzz/fuzz_logic/decode.rs`, included verbatim
//! here and wrapped by the cargo-fuzz target; see
//! `crates/consema-conformance/src/fuzz.rs` for the harness equivalence
//! statement.

use consema_conformance::fuzz;

mod protocol_logic {
    include!("../../consema-protocol/fuzz/fuzz_logic/decode.rs");
}

/// Committed seed (evidence: unseeded runs do not count).
const PROTOCOL_SEED: u64 = 0x7072_6F74_0000_0201; // "prot"
/// Iterations per base input in the bounded CI run.
const BOUNDED_ITERATIONS: u64 = 2_000;
/// Iterations per base input in the `#[ignore]`d evidence run.
const LONG_RUN_ITERATIONS: u64 = 100_000;

/// Base inputs: a canonical JSON envelope, a PVCE encoding, a PGCE
/// encoding, and adversarial byte soup.
const DECODE_BASES: &[&[u8]] = &[
    br#"{"schema":"https://consema.dev/schemas/portable-value/v1","value":{"type":"object","members":[{"name":"a","value":{"type":"integer","magnitude":"1"}}]}}"#,
    b"\x01\x01\x00",
    b"bplist00",
    b"\xff\xfe\x00\x01",
];

fn run_target(iterations: u64, target: impl Fn(&[u8])) -> Result<(), fuzz::FuzzFinding> {
    for base in DECODE_BASES {
        fuzz::run(PROTOCOL_SEED, iterations, base, &target)?;
        fuzz::run(PROTOCOL_SEED ^ 0xA5, iterations, base, &target)?;
    }
    Ok(())
}

#[test]
fn protocol_decode_fuzz_bounded() {
    let result = run_target(BOUNDED_ITERATIONS, protocol_logic::fuzz_decode);
    if let Err(finding) = result {
        panic!(
            "protocol decode fuzz found a violation:\n{}",
            finding.render()
        );
    }
}

#[test]
#[ignore = "manual evidence run: several minutes"]
fn protocol_decode_fuzz_long_run() {
    let result = run_target(LONG_RUN_ITERATIONS, protocol_logic::fuzz_decode);
    if let Err(finding) = result {
        panic!(
            "protocol decode fuzz (long) found a violation:\n{}",
            finding.render()
        );
    }
}
