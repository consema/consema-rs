//! Deterministic mutation-corpus generator (0.13.0 gate plan M2).
//!
//! Reads the committed fixtures under `conformance/fixtures/`, applies the
//! deterministic mutation schedule (flip/truncate/insert/delete/repeat/
//! splice — the same operator classes as the fuzz engine in
//! `consema_conformance::fuzz`), and writes
//! `conformance/corpora/mutation-v1.json`. The corpus is regression input,
//! not a runtime generator: the replay test
//! (`crates/consema-conformance/tests/mutation_corpus.rs`) reads the
//! committed file and never regenerates.
//!
//! Usage:
//!
//! ```sh
//! cargo run -p consema-conformance --example gen_mutation_corpus        # (re)generate
//! cargo run -p consema-conformance --example gen_mutation_corpus -- --check  # verify committed corpus is current
//! ```
//!
//! The schedule is fully deterministic: every offset, length, byte, and
//! count is drawn from the committed base seed plus the fixture index, so
//! regenerating on any machine produces byte-identical output. The
//! committed `regressions` array (hand-added fuzz findings, see
//! conformance/corpora/README.md) is round-tripped verbatim from the
//! committed file, so regeneration never wipes regression entries.

use consema_conformance::fuzz::{FLIP_MASKS, INSERT_BYTES, Rng};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Committed base seed of the whole corpus (evidence: unseeded mutation
/// runs do not count).
const BASE_SEED: u64 = 0x5EED_13C0_5EED_13C0;

/// Per-fixture fixed counts of the structural operators.
const INSERTS_PER_FIXTURE: usize = 16;
const DELETES_PER_FIXTURE: usize = 12;
const REPEATS_PER_FIXTURE: usize = 8;
const SPLICES_PER_FIXTURE: usize = 8;

#[derive(Clone, Copy)]
enum Source {
    Bytes(&'static [u8]),
    Hex(&'static str),
}

impl Source {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => bytes.to_vec(),
            Self::Hex(hex) => decode_hex(hex),
        }
    }
}

struct Fixture {
    id: &'static str,
    format: &'static str,
    profile: &'static str,
    encoding: &'static str,
    path: &'static str,
    source: Source,
}

macro_rules! fixture {
    ($id:literal, $format:literal, $profile:literal, $encoding:literal, $path:literal) => {
        Fixture {
            id: $id,
            format: $format,
            profile: $profile,
            encoding: $encoding,
            path: $path,
            source: Source::Bytes(include_bytes!(concat!(
                "../../../conformance/fixtures/",
                $path
            ))),
        }
    };
    ($id:literal, $format:literal, $profile:literal, $encoding:literal, $path:literal, hex) => {
        Fixture {
            id: $id,
            format: $format,
            profile: $profile,
            encoding: $encoding,
            path: $path,
            source: Source::Hex(include_str!(concat!(
                "../../../conformance/fixtures/",
                $path
            ))),
        }
    };
}

/// The complete fixture table: every committed fixture under
/// `conformance/fixtures/` is mutated. `profile`/`encoding` are the exact
/// production profile and source-contract selection the replay test must
/// parse the mutated bytes with.
const FIXTURES: &[Fixture] = &[
    // JSON family.
    fixture!(
        "json5.package-json5",
        "json",
        "json5.standard@1",
        "default",
        "json5/package-json5-v2.2.3.json5"
    ),
    fixture!(
        "json5.application-json5",
        "json",
        "json5.standard@1",
        "default",
        "real-world/application.json5"
    ),
    fixture!(
        "json.package-json",
        "json",
        "json.strict@1",
        "default",
        "real-world/package.json"
    ),
    fixture!(
        "json.tsconfig-jsonc",
        "json",
        "jsonc.bounded@1",
        "default",
        "real-world/tsconfig.jsonc"
    ),
    fixture!(
        "json.vscode-settings-jsonc",
        "json",
        "jsonc.bounded@1",
        "default",
        "real-world/vscode-settings.jsonc"
    ),
    // TOML.
    fixture!(
        "toml.all-values",
        "toml",
        "toml.1.0@1",
        "default",
        "toml/all-values.toml"
    ),
    fixture!(
        "toml.application",
        "toml",
        "toml.1.0@1",
        "default",
        "toml/application.toml"
    ),
    fixture!(
        "toml.invalid-duplicate",
        "toml",
        "toml.1.0@1",
        "default",
        "toml/invalid-duplicate.toml"
    ),
    fixture!(
        "toml.pyproject",
        "toml",
        "toml.1.0@1",
        "default",
        "toml/pyproject.toml"
    ),
    fixture!(
        "toml.trivia-and-strings",
        "toml",
        "toml.1.0@1",
        "default",
        "toml/trivia-and-strings.toml"
    ),
    // YAML.
    fixture!(
        "yaml.anchor-heavy",
        "yaml",
        "yaml.1.2-core@1",
        "default",
        "yaml/anchor-heavy.yaml"
    ),
    fixture!(
        "yaml.compose-services",
        "yaml",
        "yaml.1.2-core@1",
        "default",
        "yaml/compose-services.yaml"
    ),
    fixture!(
        "yaml.github-actions-ci",
        "yaml",
        "yaml.1.2-core@1",
        "default",
        "yaml/github-actions-ci.yaml"
    ),
    fixture!(
        "yaml.kubernetes-workload",
        "yaml",
        "yaml.1.2-core@1",
        "default",
        "yaml/kubernetes-workload.yaml"
    ),
    // INI.
    fixture!(
        "ini.desktop-settings",
        "ini",
        "ini.portable@1",
        "default",
        "ini/desktop-settings.ini"
    ),
    fixture!(
        "ini.dotnet-service",
        "ini",
        "ini.windows@1",
        "default",
        "ini/dotnet-service.ini"
    ),
    fixture!(
        "ini.python-tool",
        "ini",
        "ini.python-configparser@1",
        "default",
        "ini/python-tool.ini"
    ),
    fixture!(
        "ini.legacy-mixed-newline",
        "ini",
        "ini.portable@1",
        "default",
        "ini/legacy-mixed-newline.ini.hex",
        hex
    ),
    fixture!(
        "ini.windows-cp1252",
        "ini",
        "ini.windows@1",
        "windows-1252",
        "ini/windows-cp1252.ini.hex",
        hex
    ),
    // Java Properties.
    fixture!(
        "properties.logging",
        "properties",
        "java-properties.reader@1",
        "utf8",
        "properties/logging.properties"
    ),
    fixture!(
        "properties.messages",
        "properties",
        "java-properties.reader@1",
        "utf8",
        "properties/messages.properties"
    ),
    fixture!(
        "properties.build-tool",
        "properties",
        "java-properties.reader@1",
        "utf8",
        "properties/build-tool.properties"
    ),
    fixture!(
        "properties.windows-paths",
        "properties",
        "java-properties.reader@1",
        "utf8",
        "properties/windows-paths.properties"
    ),
    fixture!(
        "properties.continuation-heavy",
        "properties",
        "java-properties.reader@1",
        "utf8",
        "properties/continuation-heavy.properties"
    ),
    fixture!(
        "properties.utf16-edge",
        "properties",
        "java-properties.reader@1",
        "utf16le",
        "properties/utf16-edge.properties"
    ),
    fixture!(
        "properties.latin1-resource",
        "properties",
        "java-properties.latin1@1",
        "latin1",
        "properties/latin1-resource.properties.hex",
        hex
    ),
    // XML.
    fixture!(
        "xml.app-server-config",
        "xml",
        "xml.1.0-safe@1",
        "default",
        "xml/app-server-config.xml"
    ),
    fixture!(
        "xml.logback",
        "xml",
        "xml.1.0-safe@1",
        "default",
        "xml/logback.xml"
    ),
    fixture!(
        "xml.maven-pom",
        "xml",
        "xml.1.0-safe@1",
        "default",
        "xml/maven-pom.xml"
    ),
    fixture!(
        "xml.namespaced-service",
        "xml",
        "xml.1.0-safe@1",
        "default",
        "xml/namespaced-service.xml"
    ),
    fixture!(
        "xml.spring-application",
        "xml",
        "xml.1.0-safe@1",
        "default",
        "xml/spring-application.xml"
    ),
    // plist XML.
    fixture!(
        "plist.xml.Info",
        "plist",
        "plist.xml@1",
        "default",
        "plist/xml/Info.plist"
    ),
    fixture!(
        "plist.xml.archiver-sample",
        "plist",
        "plist.xml@1",
        "default",
        "plist/xml/com.example.archiver-sample.plist"
    ),
    fixture!(
        "plist.xml.preferences",
        "plist",
        "plist.xml@1",
        "default",
        "plist/xml/com.example.preferences.plist"
    ),
    fixture!(
        "plist.xml.repeated-keys",
        "plist",
        "plist.xml@1",
        "default",
        "plist/xml/com.example.repeated-keys.plist"
    ),
    // plist binary (the offset-table/object-ref decoder).
    fixture!(
        "plist.binary.archiver-sample",
        "plist",
        "plist.binary@1",
        "default",
        "plist/binary/com.example.archiver-sample.binary.plist"
    ),
    fixture!(
        "plist.binary.preferences",
        "plist",
        "plist.binary@1",
        "default",
        "plist/binary/com.example.preferences.binary.plist"
    ),
    fixture!(
        "plist.binary.shared-refs",
        "plist",
        "plist.binary@1",
        "default",
        "plist/binary/com.example.shared-refs.binary.plist"
    ),
    // HCL.
    fixture!(
        "hcl.main-tf",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/main.tf"
    ),
    fixture!(
        "hcl.network-tf",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/network.tf"
    ),
    fixture!(
        "hcl.nomad-hcl",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/nomad.hcl"
    ),
    fixture!(
        "hcl.packer-pkr",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/packer.pkr.hcl"
    ),
    fixture!(
        "hcl.variables-tf",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/variables.tf"
    ),
    fixture!(
        "hcl.vault-hcl",
        "hcl",
        "hcl.native@1",
        "default",
        "hcl/tf/vault.hcl"
    ),
    fixture!(
        "hcl.prod-tfvars",
        "hcl",
        "hcl.tfvars@1",
        "default",
        "hcl/tfvars/prod.tfvars"
    ),
    fixture!(
        "hcl.terraform-tfvars",
        "hcl",
        "hcl.tfvars@1",
        "default",
        "hcl/tfvars/terraform.tfvars"
    ),
];

struct MutationCase {
    class: &'static str,
    offset: usize,
    extra1: usize,
    extra2: usize,
    byte: u8,
}

fn main() {
    let check = std::env::args().any(|argument| argument == "--check");
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/corpora/mutation-v1.json");
    // Regression entries are committed by hand (conformance/corpora/README.md,
    // "Adding a fuzz finding"). Read the committed array once at startup and
    // round-trip it verbatim into the regenerated output: regeneration is
    // idempotent with respect to regressions (a new entry survives, and an
    // unchanged array leaves the output byte-identical). There is no merge —
    // the committed file is the only source of entries.
    let existing = std::fs::read_to_string(&target);
    let regressions = match &existing {
        Ok(content) => extract_regressions(content, &target),
        Err(_) => String::new(), // first generation: no committed corpus yet
    };
    let generated = generate(&regressions);
    if check {
        let content = existing.unwrap_or_else(|error| {
            panic!("cannot read committed corpus {}: {error}", target.display())
        });
        assert!(
            content == generated,
            "committed corpus {} is stale: re-run `cargo run -p consema-conformance --example gen_mutation_corpus`",
            target.display()
        );
        println!(
            "mutation corpus {} is current ({} bytes)",
            target.display(),
            generated.len()
        );
    } else {
        std::fs::write(&target, &generated)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", target.display()));
        println!(
            "wrote {} ({} bytes, {} cases)",
            target.display(),
            generated.len(),
            case_count()
        );
    }
}

fn case_count() -> usize {
    FIXTURES
        .iter()
        .map(|fixture| schedule_for(fixture).len())
        .sum()
}

/// The deterministic per-fixture mutation schedule (flip/truncate/insert/
/// delete/repeat/splice).
fn schedule_for(fixture: &Fixture) -> Vec<MutationCase> {
    let bytes = fixture.source.bytes();
    let len = bytes.len();
    let mut rng = Rng::new(BASE_SEED ^ (FIXTURES.len() as u64) ^ ordinal(fixture.id) as u64);
    let mut cases = Vec::new();
    // Truncate at every length (a truncated document must recover or fail
    // fatally, never panic and never claim full coverage).
    for length in 0..=len {
        cases.push(MutationCase {
            class: "truncate",
            offset: length,
            extra1: 0,
            extra2: 0,
            byte: 0,
        });
    }
    // Flip every byte with every production flip mask.
    for (offset, mask) in
        (0..len).flat_map(|offset| FLIP_MASKS.iter().map(move |mask| (offset, *mask)))
    {
        cases.push(MutationCase {
            class: "flip",
            offset,
            extra1: usize::from(mask),
            extra2: 0,
            byte: 0,
        });
    }
    // Structural operators with seeded offsets.
    for _ in 0..INSERTS_PER_FIXTURE {
        cases.push(MutationCase {
            class: "insert",
            offset: rng.next_usize(len + 1),
            extra1: 0,
            extra2: 0,
            byte: INSERT_BYTES[rng.next_usize(INSERT_BYTES.len())],
        });
    }
    for _ in 0..DELETES_PER_FIXTURE {
        cases.push(MutationCase {
            class: "delete",
            offset: rng.next_usize(len),
            extra1: 1 + rng.next_usize(4).min(len.saturating_sub(1).max(1)),
            extra2: 0,
            byte: 0,
        });
    }
    for _ in 0..REPEATS_PER_FIXTURE {
        cases.push(MutationCase {
            class: "repeat",
            offset: rng.next_usize(len),
            extra1: 1 + rng.next_usize(6).min(len.max(1)),
            extra2: 2 + rng.next_usize(3),
            byte: 0,
        });
    }
    for _ in 0..SPLICES_PER_FIXTURE {
        cases.push(MutationCase {
            class: "splice",
            offset: rng.next_usize(len + 1),
            extra1: rng.next_usize(len),
            extra2: 1 + rng.next_usize(8).min(len.max(1)),
            byte: 0,
        });
    }
    cases
}

fn ordinal(id: &str) -> usize {
    FIXTURES
        .iter()
        .position(|fixture| fixture.id == id)
        .expect("fixture id is in the table")
}

fn generate(regressions: &str) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str("  \"suite\": \"consema.mutation-corpus@1\",\n");
    output.push_str("  \"generator\": {\n");
    output.push_str(
        "    \"tool\": \"crates/consema-conformance/examples/gen_mutation_corpus.rs\",\n",
    );
    let _ = writeln!(output, "    \"seed\": {BASE_SEED},");
    output.push_str("    \"classes\": [\"flip\", \"truncate\", \"insert\", \"delete\", \"repeat\", \"splice\"],\n");
    output.push_str(
        "    \"regenerate\": \"cargo run -p consema-conformance --example gen_mutation_corpus\"\n",
    );
    output.push_str("  },\n");
    output.push_str("  \"fixtures\": [\n");
    for (index, fixture) in FIXTURES.iter().enumerate() {
        let size = fixture.source.bytes().len();
        let _ = writeln!(
            output,
            "    {{\"id\":\"{}\",\"format\":\"{}\",\"profile\":\"{}\",\"encoding\":\"{}\",\"path\":\"{}\",\"bytes\":{size}}}{}",
            fixture.id,
            fixture.format,
            fixture.profile,
            fixture.encoding,
            fixture.path,
            if index + 1 == FIXTURES.len() { "" } else { "," }
        );
    }
    output.push_str("  ],\n");
    output.push_str("  \"cases\": {\n");
    for (fixture_index, fixture) in FIXTURES.iter().enumerate() {
        let cases = schedule_for(fixture);
        let _ = writeln!(output, "    \"{}\": [", fixture.id);
        for (case_index, case) in cases.iter().enumerate() {
            let comma = if case_index + 1 == cases.len() {
                ""
            } else {
                ","
            };
            let fields = match case.class {
                "truncate" => format!("\"l\":{}", case.offset),
                "flip" => format!("\"o\":{},\"m\":{}", case.offset, case.extra1),
                "insert" => format!("\"o\":{},\"b\":{}", case.offset, case.byte),
                "delete" => format!("\"o\":{},\"n\":{}", case.offset, case.extra1),
                "repeat" => format!(
                    "\"o\":{},\"s\":{},\"t\":{}",
                    case.offset, case.extra1, case.extra2
                ),
                "splice" => format!(
                    "\"o\":{},\"f\":{},\"s\":{}",
                    case.offset, case.extra1, case.extra2
                ),
                other => panic!("unknown mutation class {other}"),
            };
            let _ = writeln!(output, "      {{\"c\":\"{}\",{fields}}}{comma}", case.class);
        }
        let _ = writeln!(
            output,
            "    ]{}",
            if fixture_index + 1 == FIXTURES.len() {
                ""
            } else {
                ","
            }
        );
    }
    output.push_str("  },\n");
    // Fuzz findings are committed here (exact minimal inputs) per
    // conformance/corpora/README.md; the committed array is round-tripped
    // verbatim by `extract_regressions`, so it is empty only when the
    // committed file itself has an empty array.
    output.push_str("  \"regressions\": [");
    output.push_str(regressions);
    output.push_str("]\n");
    output.push_str("}\n");
    output
}

/// Extracts the raw text of the committed `regressions` array (the bytes
/// between its brackets) for verbatim round-tripping, so contributor entries
/// survive regeneration byte-for-byte regardless of how they are formatted.
/// The scan is string-aware: `[`/`]` inside quoted strings (e.g. a note
/// mentioning brackets) do not affect bracket matching. The `regressions`
/// field is always the last field of the corpus object, so the first
/// `"regressions":` occurrence is the field itself, never content inside it.
fn extract_regressions(content: &str, target: &Path) -> String {
    let marker = "\"regressions\":";
    let marker_pos = content.find(marker).unwrap_or_else(|| {
        panic!(
            "committed corpus {} lacks a regressions field",
            target.display()
        )
    });
    let after = &content[marker_pos + marker.len()..];
    let open = after.find('[').unwrap_or_else(|| {
        panic!(
            "committed corpus {} regressions is not an array",
            target.display()
        )
    });
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in after[open..].bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return after[open + 1..open + offset].to_string();
                    }
                }
                _ => {}
            }
        }
    }
    panic!(
        "committed corpus {} has an unterminated regressions array",
        target.display()
    )
}

fn decode_hex(source: &str) -> Vec<u8> {
    let digits: Vec<u8> = source
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(digits.len() % 2 == 0, "hex fixture has an odd digit count");
    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        decoded.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
    }
    decoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        other => panic!("invalid hex digit {other:#x}"),
    }
}
