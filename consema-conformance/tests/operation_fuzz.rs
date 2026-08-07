//! Deterministic in-process formation-to-operation fuzz for every format
//! crate (0.13.0 gate plan M2).
//!
//! Drives formation → operation with mutated inputs: parse with the
//! production default limits, then exercise query, projection,
//! materialization and edit. The gate under test: recovered documents must
//! never reach project/materialize/edit (the gate rejects them), while
//! query stays legitimate over recovered documents (the CLI inspect path).
//!
//! Target logic is the single-source files under
//! `crates/<format>/fuzz/fuzz_logic/operations.rs`, included verbatim here
//! and wrapped by the cargo-fuzz targets; see
//! `crates/consema-conformance/src/fuzz.rs` for the harness equivalence
//! statement.

use consema_conformance::fuzz;

mod json_logic {
    include!("../../consema-json/fuzz/fuzz_logic/operations.rs");
}
mod toml_logic {
    include!("../../consema-toml/fuzz/fuzz_logic/operations.rs");
}
mod yaml_logic {
    include!("../../consema-yaml/fuzz/fuzz_logic/operations.rs");
}
mod ini_logic {
    include!("../../consema-ini/fuzz/fuzz_logic/operations.rs");
}
mod properties_logic {
    include!("../../consema-properties/fuzz/fuzz_logic/operations.rs");
}
mod xml_logic {
    include!("../../consema-xml/fuzz/fuzz_logic/operations.rs");
}
mod plist_logic {
    include!("../../consema-plist/fuzz/fuzz_logic/operations.rs");
}
mod hcl_logic {
    include!("../../consema-hcl/fuzz/fuzz_logic/operations.rs");
}

/// Committed seeds (evidence: unseeded runs do not count).
const JSON_SEED: u64 = 0x6F70_6A73_0000_0101; // "opjs"
const TOML_SEED: u64 = 0x6F70_746D_0000_0102;
const YAML_SEED: u64 = 0x6F70_7961_0000_0103;
const INI_SEED: u64 = 0x6F70_696E_0000_0104;
const PROPERTIES_SEED: u64 = 0x6F70_7072_0000_0105;
const XML_SEED: u64 = 0x6F70_786D_0000_0106;
const PLIST_SEED: u64 = 0x6F70_706C_0000_0107;
const HCL_SEED: u64 = 0x6F70_6863_0000_0108;

/// Iterations per base input in the bounded CI runs (the operations targets
/// are heavier than parse, so the bound is lower).
const BOUNDED_ITERATIONS: u64 = 400;
/// Iterations per base input in the `#[ignore]`d evidence runs.
const LONG_RUN_ITERATIONS: u64 = 25_000;

/// Production-shaped and adversarial base inputs (each run mixes complete
/// and recovered seeds).
const JSON_BASES: &[&[u8]] = &[
    br#"{"a":1,"b":[true,null,"x"],"c":{"d":1.5}}"#,
    b"{a:",
    b"[1,2,3]",
];
const TOML_BASES: &[&[u8]] = &[
    b"a = 1\nb = \"x\"\n[c]\nd = [1, 2]\n",
    b"a = 1\na = 2\n",
    b"[",
];
const YAML_BASES: &[&[u8]] = &[
    b"a: 1\nb:\n  - x\n  - 2\nc: {d: e}\n",
    b"anchor: &a {x: 1}\nalias: *a\n",
    b"a: [1, 2\n",
];
const INI_BASES: &[&[u8]] = &[
    b"[section]\nkey = value\ncomment ; x\n",
    b"[unterminated\nkey = \n",
    b"",
];
const PROPERTIES_BASES: &[&[u8]] = &[b"a=1\nb.c = x\n", b"a = 1\\\nb = 2\n", b"\xff"];
const XML_BASES: &[&[u8]] = &[
    b"<?xml version=\"1.0\"?><root a=\"1\"><x>text</x></root>",
    b"<root><a></root>",
    b"<root/>",
];
const PLIST_BASES: &[&[u8]] = &[
    b"<?xml version=\"1.0\"?><dict><key>a</key><string>x</string></dict>",
    b"bplist00",
    b"<dict><key>a</dict>",
];
const HCL_BASES: &[&[u8]] = &[
    b"a = 1\nserver \"web\" {\n  port = 8080\n}\n",
    b"a = \"${x}\"\n",
    b"a = \"unterminated\n",
];

fn run_target(
    seeds: &[u64],
    iterations: u64,
    bases: &[&[u8]],
    target: impl Fn(&[u8]),
) -> Result<(), fuzz::FuzzFinding> {
    for base in bases {
        for seed in seeds {
            fuzz::run(*seed, iterations, base, &target)?;
        }
    }
    Ok(())
}

fn assert_clean(result: Result<(), fuzz::FuzzFinding>, target: &str) {
    if let Err(finding) = result {
        panic!(
            "operation fuzz target {target} found a violation:\n{}",
            finding.render()
        );
    }
}

#[test]
fn json_operation_fuzz_bounded() {
    // Finding M2-F1 fixed: consema-json rejects recovered documents at
    // project and commit with typed failures, so the strict assertions in
    // crates/consema-json/fuzz/fuzz_logic/operations.rs are the gate.
    assert_clean(
        run_target(
            &[JSON_SEED, JSON_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            JSON_BASES,
            |data| {
                json_logic::fuzz_operations(data);
            },
        ),
        "json",
    );
}

#[test]
fn toml_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[TOML_SEED, TOML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            TOML_BASES,
            |data| {
                toml_logic::fuzz_operations(data);
            },
        ),
        "toml",
    );
}

#[test]
fn yaml_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[YAML_SEED, YAML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            YAML_BASES,
            |data| {
                yaml_logic::fuzz_operations(data);
            },
        ),
        "yaml",
    );
}

#[test]
fn ini_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[INI_SEED, INI_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            INI_BASES,
            |data| {
                ini_logic::fuzz_operations(data);
            },
        ),
        "ini",
    );
}

#[test]
fn properties_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[PROPERTIES_SEED, PROPERTIES_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            PROPERTIES_BASES,
            properties_logic::fuzz_operations,
        ),
        "properties",
    );
}

#[test]
fn xml_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[XML_SEED, XML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            XML_BASES,
            |data| {
                xml_logic::fuzz_operations(data);
            },
        ),
        "xml",
    );
}

#[test]
fn plist_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[PLIST_SEED, PLIST_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            PLIST_BASES,
            |data| {
                plist_logic::fuzz_operations(data);
            },
        ),
        "plist",
    );
}

#[test]
fn hcl_operation_fuzz_bounded() {
    assert_clean(
        run_target(
            &[HCL_SEED, HCL_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            HCL_BASES,
            |data| {
                hcl_logic::fuzz_operations(data);
            },
        ),
        "hcl",
    );
}

// ---------------------------------------------------------------------------
// Long runs (manual evidence; `cargo test -p consema-conformance --test
// operation_fuzz -- --ignored`).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn json_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[JSON_SEED], LONG_RUN_ITERATIONS, JSON_BASES, |data| {
            json_logic::fuzz_operations(data);
        }),
        "json (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn toml_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[TOML_SEED], LONG_RUN_ITERATIONS, TOML_BASES, |data| {
            toml_logic::fuzz_operations(data);
        }),
        "toml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn yaml_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[YAML_SEED], LONG_RUN_ITERATIONS, YAML_BASES, |data| {
            yaml_logic::fuzz_operations(data);
        }),
        "yaml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn ini_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[INI_SEED], LONG_RUN_ITERATIONS, INI_BASES, |data| {
            ini_logic::fuzz_operations(data);
        }),
        "ini (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn properties_operation_fuzz_long_run() {
    assert_clean(
        run_target(
            &[PROPERTIES_SEED],
            LONG_RUN_ITERATIONS,
            PROPERTIES_BASES,
            |data| {
                properties_logic::fuzz_operations(data);
            },
        ),
        "properties (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn xml_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[XML_SEED], LONG_RUN_ITERATIONS, XML_BASES, |data| {
            xml_logic::fuzz_operations(data);
        }),
        "xml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn plist_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[PLIST_SEED], LONG_RUN_ITERATIONS, PLIST_BASES, |data| {
            plist_logic::fuzz_operations(data);
        }),
        "plist (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn hcl_operation_fuzz_long_run() {
    assert_clean(
        run_target(&[HCL_SEED], LONG_RUN_ITERATIONS, HCL_BASES, |data| {
            hcl_logic::fuzz_operations(data);
        }),
        "hcl (long)",
    );
}
