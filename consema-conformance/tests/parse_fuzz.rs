//! Deterministic in-process parse fuzz for every format crate
//! (0.13.0 gate plan M2).
//!
//! The per-format targets are the single-source files under
//! `crates/<format>/fuzz/fuzz_logic/`, included here verbatim and wrapped by
//! the cargo-fuzz targets in the same directories; see
//! `crates/consema-conformance/src/fuzz.rs` for the harness equivalence
//! statement and `crates/consema-json/fuzz/README.md` for the target
//! contract.
//!
//! Bounded runs (this file, default `cargo test`) keep CI fast; the
//! `#[ignore]`d long runs are the manual fuzz evidence runs
//! (`cargo test -p consema-conformance --test parse_fuzz -- --ignored`).

use consema_conformance::fuzz;

mod json_logic {
    include!("../../consema-json/fuzz/fuzz_logic/parse.rs");
}
mod toml_logic {
    include!("../../consema-toml/fuzz/fuzz_logic/parse.rs");
}
mod yaml_logic {
    include!("../../consema-yaml/fuzz/fuzz_logic/parse.rs");
}
mod ini_logic {
    include!("../../consema-ini/fuzz/fuzz_logic/parse.rs");
}
mod properties_logic {
    include!("../../consema-properties/fuzz/fuzz_logic/parse.rs");
}
mod xml_logic {
    include!("../../consema-xml/fuzz/fuzz_logic/parse.rs");
}
mod plist_logic {
    include!("../../consema-plist/fuzz/fuzz_logic/parse.rs");
}
mod hcl_logic {
    include!("../../consema-hcl/fuzz/fuzz_logic/parse.rs");
}

/// Committed seeds (evidence: unseeded runs do not count). Each seed is a
/// fixed constant; the engine derives one mutation per iteration from
/// `seed ^ iteration`.
const JSON_SEED: u64 = 0x6A73_6F6E_0000_0001; // "json"
const TOML_SEED: u64 = 0x746F_6D6C_0000_0002; // "toml"
const YAML_SEED: u64 = 0x7961_6D6C_0000_0003; // "yaml"
const INI_SEED: u64 = 0x696E_6900_0000_0004; // "ini\0"
const PROPERTIES_SEED: u64 = 0x7072_6F70_0000_0005; // "prop"
const XML_SEED: u64 = 0x786D_6C00_0000_0006; // "xml\0"
const PLIST_SEED: u64 = 0x706C_6973_7400_0007; // "plist"
const HCL_SEED: u64 = 0x6863_6C00_0000_0008; // "hcl\0"

/// Iterations per base input in the bounded CI runs.
const BOUNDED_ITERATIONS: u64 = 1_000;
/// Iterations per base input in the `#[ignore]`d evidence runs (a few
/// minutes per target on this machine).
const LONG_RUN_ITERATIONS: u64 = 100_000;

/// Production-shaped and adversarial base inputs per format.
const JSON_BASES: &[&[u8]] = &[
    br#"{"a":1,"b":[true,null,"x"],"c":{"d":1.5}}"#,
    b"{a:[[1,2,],[3,]],}'unterminated",
    b"\xff\xfe",
    br#"["a","b"],[1,2"#,
];
const TOML_BASES: &[&[u8]] = &[
    b"a = 1\nb = \"x\"\n[c]\nd = [1, 2]\n",
    b"a = 1\na = 2\n",
    b"a = \"unterminated\n",
    b"\xff",
];
const YAML_BASES: &[&[u8]] = &[
    b"a: 1\nb:\n  - x\n  - 2\nc: {d: e}\n",
    b"anchor: &a {x: 1}\nalias: *a\n",
    b"a: [1, 2\n",
    b"---\n# comment\nx: |\n  text\n",
];
const INI_BASES: &[&[u8]] = &[
    b"[section]\nkey = value\ncomment ; x\n",
    b"[unterminated\nkey = \n",
    b"\xef\xbb\xbf[section]\nkey = \xff\n",
    b"",
];
const PROPERTIES_BASES: &[&[u8]] = &[
    b"a=1\nb.c = x\\ny\\u0041\n",
    b"key\\ with\\ spaces = value\n",
    b"a = 1\\\nb = 2\n",
    b"\xef\xbb\xbfk = v\n",
];
const XML_BASES: &[&[u8]] = &[
    b"<?xml version=\"1.0\"?><root a=\"1\"><x>text</x></root>",
    b"<root><a></root>",
    b"<root>&#0;&unknown;</root>",
    b"\xff\xfe<root/>",
];
const PLIST_BASES: &[&[u8]] = &[
    b"<?xml version=\"1.0\"?><dict><key>a</key><string>x</string></dict>",
    b"bplist00",
    b"<dict><key>a</dict>",
    b"\xff\xfe",
];
const HCL_BASES: &[&[u8]] = &[
    b"a = 1\nserver \"web\" {\n  port = 8080\n}\n",
    b"a = \"${x}\"\nb = <<EOT\ncontent\nEOT\n",
    b"a = \"unterminated\n",
    b"\xef\xbb\xbfa = 1\n",
];

/// Runs the target over every committed seed and base input.
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
            "parse fuzz target {target} found a violation:\n{}",
            finding.render()
        );
    }
}

#[test]
fn json_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[JSON_SEED, JSON_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            JSON_BASES,
            |data| {
                json_logic::fuzz_parse(data);
            },
        ),
        "json",
    );
}

#[test]
fn toml_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[TOML_SEED, TOML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            TOML_BASES,
            |data| {
                toml_logic::fuzz_parse(data);
            },
        ),
        "toml",
    );
}

#[test]
fn yaml_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[YAML_SEED, YAML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            YAML_BASES,
            |data| {
                yaml_logic::fuzz_parse(data);
            },
        ),
        "yaml",
    );
}

#[test]
fn ini_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[INI_SEED, INI_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            INI_BASES,
            |data| {
                ini_logic::fuzz_parse(data);
            },
        ),
        "ini",
    );
}

#[test]
fn properties_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[PROPERTIES_SEED, PROPERTIES_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            PROPERTIES_BASES,
            properties_logic::fuzz_parse,
        ),
        "properties",
    );
}

#[test]
fn xml_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[XML_SEED, XML_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            XML_BASES,
            |data| {
                xml_logic::fuzz_parse(data);
            },
        ),
        "xml",
    );
}

#[test]
fn plist_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[PLIST_SEED, PLIST_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            PLIST_BASES,
            |data| {
                plist_logic::fuzz_parse(data);
            },
        ),
        "plist",
    );
}

#[test]
fn hcl_parse_fuzz_bounded() {
    assert_clean(
        run_target(
            &[HCL_SEED, HCL_SEED ^ 0x51],
            BOUNDED_ITERATIONS,
            HCL_BASES,
            |data| {
                hcl_logic::fuzz_parse(data);
            },
        ),
        "hcl",
    );
}

// ---------------------------------------------------------------------------
// Long runs: the manual fuzz evidence (`cargo test -p consema-conformance
// --test parse_fuzz -- --ignored`); each target runs several minutes.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn json_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[JSON_SEED], LONG_RUN_ITERATIONS, JSON_BASES, |data| {
            json_logic::fuzz_parse(data);
        }),
        "json (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn toml_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[TOML_SEED], LONG_RUN_ITERATIONS, TOML_BASES, |data| {
            toml_logic::fuzz_parse(data);
        }),
        "toml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn yaml_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[YAML_SEED], LONG_RUN_ITERATIONS, YAML_BASES, |data| {
            yaml_logic::fuzz_parse(data);
        }),
        "yaml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn ini_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[INI_SEED], LONG_RUN_ITERATIONS, INI_BASES, |data| {
            ini_logic::fuzz_parse(data);
        }),
        "ini (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn properties_parse_fuzz_long_run() {
    assert_clean(
        run_target(
            &[PROPERTIES_SEED],
            LONG_RUN_ITERATIONS,
            PROPERTIES_BASES,
            |data| {
                properties_logic::fuzz_parse(data);
            },
        ),
        "properties (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn xml_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[XML_SEED], LONG_RUN_ITERATIONS, XML_BASES, |data| {
            xml_logic::fuzz_parse(data);
        }),
        "xml (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn plist_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[PLIST_SEED], LONG_RUN_ITERATIONS, PLIST_BASES, |data| {
            plist_logic::fuzz_parse(data);
        }),
        "plist (long)",
    );
}

#[test]
#[ignore = "manual evidence run: several minutes per target"]
fn hcl_parse_fuzz_long_run() {
    assert_clean(
        run_target(&[HCL_SEED], LONG_RUN_ITERATIONS, HCL_BASES, |data| {
            hcl_logic::fuzz_parse(data);
        }),
        "hcl (long)",
    );
}
