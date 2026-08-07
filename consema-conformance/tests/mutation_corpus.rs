//! Mutation-corpus replay (0.13.0 gate plan M2).
//!
//! Replays the committed mutation corpus `conformance/corpora/mutation-v1.json`
//! (regression input, not a runtime generator — see
//! `conformance/corpora/README.md`): every derived case is rebuilt from its
//! fixture plus mutation operator and run through the fixture's production
//! parse closure with the profile's default limits; every regression entry
//! is replayed byte-exactly. A violated closure property or a panic fails
//! the test with the exact input.
//!
//! The full replay is the `#[ignore]`d long run; the bounded default run
//! replays a deterministic stride sample (≤256 cases per fixture) to keep
//! CI fast.

use consema_document::ParseLimits;
use consema_json::{JsonProfile, JsonValue, SemanticAvailability, parse};

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

/// Bounded default: deterministic stride sample per fixture (the full
/// 175k-case replay is the `#[ignore]`d long run).
const BOUNDED_CASES_PER_FIXTURE: usize = 96;

/// Fixture sources keyed by corpus fixture id (must stay in sync with the
/// generator's fixture table; a mismatch fails the replay).
enum FixtureSource {
    Bytes(&'static [u8]),
    Hex(&'static str),
}

impl FixtureSource {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => bytes.to_vec(),
            Self::Hex(hex) => decode_hex(hex),
        }
    }
}

fn fixture_source(id: &str) -> FixtureSource {
    use FixtureSource::{Bytes, Hex};
    match id {
        "json5.package-json5" => Bytes(include_bytes!(
            "../../../conformance/fixtures/json5/package-json5-v2.2.3.json5"
        )),
        "json5.application-json5" => Bytes(include_bytes!(
            "../../../conformance/fixtures/real-world/application.json5"
        )),
        "json.package-json" => Bytes(include_bytes!(
            "../../../conformance/fixtures/real-world/package.json"
        )),
        "json.tsconfig-jsonc" => Bytes(include_bytes!(
            "../../../conformance/fixtures/real-world/tsconfig.jsonc"
        )),
        "json.vscode-settings-jsonc" => Bytes(include_bytes!(
            "../../../conformance/fixtures/real-world/vscode-settings.jsonc"
        )),
        "toml.all-values" => Bytes(include_bytes!(
            "../../../conformance/fixtures/toml/all-values.toml"
        )),
        "toml.application" => Bytes(include_bytes!(
            "../../../conformance/fixtures/toml/application.toml"
        )),
        "toml.invalid-duplicate" => Bytes(include_bytes!(
            "../../../conformance/fixtures/toml/invalid-duplicate.toml"
        )),
        "toml.pyproject" => Bytes(include_bytes!(
            "../../../conformance/fixtures/toml/pyproject.toml"
        )),
        "toml.trivia-and-strings" => Bytes(include_bytes!(
            "../../../conformance/fixtures/toml/trivia-and-strings.toml"
        )),
        "yaml.anchor-heavy" => Bytes(include_bytes!(
            "../../../conformance/fixtures/yaml/anchor-heavy.yaml"
        )),
        "yaml.compose-services" => Bytes(include_bytes!(
            "../../../conformance/fixtures/yaml/compose-services.yaml"
        )),
        "yaml.github-actions-ci" => Bytes(include_bytes!(
            "../../../conformance/fixtures/yaml/github-actions-ci.yaml"
        )),
        "yaml.kubernetes-workload" => Bytes(include_bytes!(
            "../../../conformance/fixtures/yaml/kubernetes-workload.yaml"
        )),
        "ini.desktop-settings" => Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/desktop-settings.ini"
        )),
        "ini.dotnet-service" => Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/dotnet-service.ini"
        )),
        "ini.python-tool" => Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/python-tool.ini"
        )),
        "ini.legacy-mixed-newline" => Hex(include_str!(
            "../../../conformance/fixtures/ini/legacy-mixed-newline.ini.hex"
        )),
        "ini.windows-cp1252" => Hex(include_str!(
            "../../../conformance/fixtures/ini/windows-cp1252.ini.hex"
        )),
        "properties.logging" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/logging.properties"
        )),
        "properties.messages" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/messages.properties"
        )),
        "properties.build-tool" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/build-tool.properties"
        )),
        "properties.windows-paths" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/windows-paths.properties"
        )),
        "properties.continuation-heavy" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/continuation-heavy.properties"
        )),
        "properties.utf16-edge" => Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/utf16-edge.properties"
        )),
        "properties.latin1-resource" => Hex(include_str!(
            "../../../conformance/fixtures/properties/latin1-resource.properties.hex"
        )),
        "xml.app-server-config" => Bytes(include_bytes!(
            "../../../conformance/fixtures/xml/app-server-config.xml"
        )),
        "xml.logback" => Bytes(include_bytes!(
            "../../../conformance/fixtures/xml/logback.xml"
        )),
        "xml.maven-pom" => Bytes(include_bytes!(
            "../../../conformance/fixtures/xml/maven-pom.xml"
        )),
        "xml.namespaced-service" => Bytes(include_bytes!(
            "../../../conformance/fixtures/xml/namespaced-service.xml"
        )),
        "xml.spring-application" => Bytes(include_bytes!(
            "../../../conformance/fixtures/xml/spring-application.xml"
        )),
        "plist.xml.Info" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/xml/Info.plist"
        )),
        "plist.xml.archiver-sample" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/xml/com.example.archiver-sample.plist"
        )),
        "plist.xml.preferences" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/xml/com.example.preferences.plist"
        )),
        "plist.xml.repeated-keys" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/xml/com.example.repeated-keys.plist"
        )),
        "plist.binary.archiver-sample" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/binary/com.example.archiver-sample.binary.plist"
        )),
        "plist.binary.preferences" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/binary/com.example.preferences.binary.plist"
        )),
        "plist.binary.shared-refs" => Bytes(include_bytes!(
            "../../../conformance/fixtures/plist/binary/com.example.shared-refs.binary.plist"
        )),
        "hcl.main-tf" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/main.tf"
        )),
        "hcl.network-tf" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/network.tf"
        )),
        "hcl.nomad-hcl" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/nomad.hcl"
        )),
        "hcl.packer-pkr" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/packer.pkr.hcl"
        )),
        "hcl.variables-tf" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/variables.tf"
        )),
        "hcl.vault-hcl" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tf/vault.hcl"
        )),
        "hcl.prod-tfvars" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tfvars/prod.tfvars"
        )),
        "hcl.terraform-tfvars" => Bytes(include_bytes!(
            "../../../conformance/fixtures/hcl/tfvars/terraform.tfvars"
        )),
        other => panic!("corpus fixture table is stale: unknown fixture id {other:?}"),
    }
}

/// Applies one corpus mutation operator to the fixture bytes (clamped like
/// the fuzz engine's operators).
fn apply_op(fixture: &[u8], class: &str, case: &JsonValue<'_>) -> Vec<u8> {
    let mut output = fixture.to_vec();
    match class {
        "truncate" => {
            let len = integer_field(case, "l") as usize;
            output.truncate(len.min(output.len()));
        }
        "flip" => {
            let offset = integer_field(case, "o") as usize;
            let mask = integer_field(case, "m") as u8;
            if let Some(byte) = output.get_mut(offset) {
                *byte ^= mask;
            }
        }
        "insert" => {
            let offset = integer_field(case, "o") as usize;
            let byte = integer_field(case, "b") as u8;
            output.insert(offset.min(output.len()), byte);
        }
        "delete" => {
            let offset = integer_field(case, "o") as usize;
            let count = integer_field(case, "n") as usize;
            let start = offset.min(output.len());
            let end = (start + count).min(output.len());
            output.drain(start..end);
        }
        "repeat" => {
            let offset = integer_field(case, "o") as usize;
            let span = integer_field(case, "s") as usize;
            let times = integer_field(case, "t") as usize;
            let start = offset.min(output.len());
            let chunk: Vec<u8> = output
                .iter()
                .skip(start)
                .take(span.min(output.len().saturating_sub(start)))
                .copied()
                .collect();
            if !chunk.is_empty() {
                for _ in 0..(times.saturating_sub(1)) {
                    output.splice(start..start, chunk.iter().copied());
                }
            }
        }
        "splice" => {
            let offset_to = integer_field(case, "o") as usize;
            let offset_from = integer_field(case, "f") as usize;
            let span = integer_field(case, "s") as usize;
            let from = offset_from.min(output.len());
            let chunk: Vec<u8> = output
                .iter()
                .skip(from)
                .take(span.min(output.len().saturating_sub(from)))
                .copied()
                .collect();
            if !chunk.is_empty() {
                let to = offset_to.min(output.len());
                output.splice(to..to, chunk);
            }
        }
        other => panic!("unknown corpus mutation class {other:?}"),
    }
    output
}

/// Runs one mutated fixture through its production parse closure.
fn replay_case(format: &str, profile: &str, encoding: &str, bytes: &[u8]) {
    match format {
        "json" => {
            let profile = match profile {
                "json.strict@1" => JsonProfile::StrictV1,
                "jsonc.bounded@1" => JsonProfile::JsoncBoundedV1,
                "json5.standard@1" => JsonProfile::Json5StandardV1,
                other => panic!("unknown json profile {other:?}"),
            };
            json_logic::assert_parse_closure(bytes, profile, ParseLimits::default());
        }
        "toml" => {
            assert_eq!(profile, "toml.1.0@1", "unknown toml profile");
            toml_logic::assert_parse_closure(
                bytes,
                consema_toml::TomlProfile::Toml10V1,
                ParseLimits::default(),
            );
        }
        "yaml" => {
            let profile = match profile {
                "yaml.1.2-core@1" => consema_yaml::YamlProfile::Yaml12CoreV1,
                "yaml.1.1-compat@1" => consema_yaml::YamlProfile::Yaml11CompatV1,
                other => panic!("unknown yaml profile {other:?}"),
            };
            yaml_logic::assert_parse_closure(bytes, profile, ParseLimits::default());
        }
        "ini" => {
            let profile = match profile {
                "ini.portable@1" => consema_ini::IniProfile::PortableV1,
                "ini.windows@1" => consema_ini::IniProfile::WindowsV1,
                "ini.python-configparser@1" => consema_ini::IniProfile::PythonConfigParserV1,
                other => panic!("unknown ini profile {other:?}"),
            };
            let selection = match encoding {
                "default" => consema_ini::IniEncodingSelection::ProfileDefault,
                "windows-1252" => consema_ini::IniEncodingSelection::Explicit(
                    consema_document::SourceEncoding::WindowsCodePage(
                        consema_document::WindowsCodePage::from_number(1252)
                            .expect("Windows-1252 is published"),
                    ),
                ),
                other => panic!("unknown ini encoding {other:?}"),
            };
            let document = consema_ini::parse(
                bytes,
                profile,
                selection,
                consema_ini::IniParseLimits::default(),
            );
            if let Ok(document) = document {
                ini_logic::assert_formed_closure(
                    bytes,
                    consema_ini::IniParseLimits::default(),
                    document,
                );
            }
        }
        "properties" => {
            let limits = consema_properties::PropertiesParseLimits::default();
            match encoding {
                "utf8" => {
                    assert_eq!(profile, "java-properties.reader@1");
                    properties_logic::assert_parse_closure_reader(bytes, limits);
                }
                "utf16le" => {
                    assert_eq!(profile, "java-properties.reader@1");
                    let document = consema_properties::parse_reader(
                        bytes,
                        consema_document::SourceEncoding::Utf16Le,
                        limits,
                    );
                    if let Ok(document) = document {
                        properties_logic::assert_formed_closure(bytes, limits, document);
                    }
                }
                "latin1" => {
                    assert_eq!(profile, "java-properties.latin1@1");
                    properties_logic::assert_parse_closure_latin1(bytes, limits);
                }
                other => panic!("unknown properties encoding {other:?}"),
            }
        }
        "xml" => {
            assert_eq!(profile, "xml.1.0-safe@1", "unknown xml profile");
            xml_logic::assert_parse_closure(
                bytes,
                consema_xml::XmlProfile::SafeV1,
                consema_xml::XmlParseLimits::default(),
            );
        }
        "plist" => {
            let profile = match profile {
                "plist.xml@1" => consema_plist::PlistProfile::XmlV1,
                "plist.binary@1" => consema_plist::PlistProfile::BinaryV1,
                other => panic!("unknown plist profile {other:?}"),
            };
            plist_logic::assert_parse_closure(
                bytes,
                profile,
                consema_plist::PlistParseLimits::default(),
            );
        }
        "hcl" => {
            let profile = match profile {
                "hcl.native@1" => consema_hcl::HclProfile::NativeV1,
                "hcl.tfvars@1" => consema_hcl::HclProfile::TfvarsV1,
                other => panic!("unknown hcl profile {other:?}"),
            };
            hcl_logic::assert_parse_closure(bytes, profile, consema_hcl::HclParseLimits::default());
        }
        other => panic!("unknown corpus format {other:?}"),
    }
}

/// Replays every derived case of one fixture (optionally stride-sampled).
fn replay_fixture(fixture: &JsonValue<'_>, cases: &[JsonValue<'_>], bounded: bool) {
    let id = string_field(fixture, "id");
    let format = string_field(fixture, "format");
    let profile = string_field(fixture, "profile");
    let encoding = string_field(fixture, "encoding");
    let base = fixture_source(id).bytes();
    assert_eq!(
        base.len(),
        integer_field(fixture, "bytes") as usize,
        "corpus fixture table is stale: byte count mismatch for {id}"
    );
    let sampled: Vec<usize> = if bounded && cases.len() > BOUNDED_CASES_PER_FIXTURE {
        let stride = cases.len() / BOUNDED_CASES_PER_FIXTURE;
        (0..BOUNDED_CASES_PER_FIXTURE)
            .map(|index| index * stride)
            .collect()
    } else {
        (0..cases.len()).collect()
    };
    for index in sampled {
        let case = &cases[index];
        let class = string_field(case, "c");
        let mutated = apply_op(&base, class, case);
        replay_case(format, profile, encoding, &mutated);
    }
}

/// Replays every committed regression byte-exactly.
fn replay_regressions(root: &JsonValue<'_>) {
    let regressions = array_field(root, "regressions");
    for case in &regressions {
        let format = string_field(case, "format");
        let profile = string_field(case, "profile");
        let bytes = decode_hex(string_field(case, "bytes"));
        if bytes.is_empty() {
            continue; // the workflow is in conformance/corpora/README.md
        }
        // The encoding field is optional and defaults to the production
        // profile default for that format.
        let encoding = match object_field(case, "encoding").as_string() {
            SemanticAvailability::Available(Some(encoding)) => encoding,
            _ => "default",
        };
        replay_case(format, profile, encoding, &bytes);
    }
}

fn load_corpus() -> (consema_json::Document, usize) {
    let json = include_str!("../../../conformance/corpora/mutation-v1.json");
    // The corpus is our own generated artifact (6 MB, ~175k cases); parse it
    // with explicit generous limits, never the production defaults.
    let limits = ParseLimits {
        max_source_bytes: 64 * 1024 * 1024,
        max_nesting_depth: 64,
        max_token_count: 20_000_000,
        max_node_count: 10_000_000,
        max_diagnostics: 10_000,
    };
    let document = parse(json.as_bytes(), JsonProfile::StrictV1, limits)
        .expect("committed mutation corpus must form a strict JSON document");
    let root = document.root();
    let fixtures = array_field(&root, "fixtures");
    let cases_object = object_field(&root, "cases");
    let mut total = 0usize;
    for fixture in &fixtures {
        let id = string_field(fixture, "id");
        let cases = array_field(&cases_object, id);
        total += cases.len();
    }
    (document, total)
}

fn replay_bounded_or_full(bounded: bool) {
    let (document, total) = load_corpus();
    let root = document.root();
    let fixtures = array_field(&root, "fixtures");
    let cases_object = object_field(&root, "cases");
    for fixture in &fixtures {
        let id = string_field(fixture, "id");
        let cases = array_field(&cases_object, id);
        replay_fixture(fixture, &cases, bounded);
    }
    replay_regressions(&root);
    eprintln!("mutation corpus replay complete: {total} committed cases (bounded={bounded})");
}

#[test]
fn mutation_corpus_replay_bounded() {
    replay_bounded_or_full(true);
}

#[test]
#[ignore = "manual evidence run: full 175k-case replay, tens of seconds"]
fn mutation_corpus_replay_full() {
    replay_bounded_or_full(false);
}

// ---------------------------------------------------------------------------
// Minimal strict-JSON navigation helpers (the corpus is our own file, so the
// shape is fixed and checked here).
// ---------------------------------------------------------------------------

fn available<T>(value: SemanticAvailability<T>, what: &str) -> T {
    match value {
        SemanticAvailability::Available(value) => value,
        SemanticAvailability::Unavailable(reason) => {
            panic!("corpus {what} has unavailable native semantics: {reason:?}")
        }
    }
}

fn object_field<'a>(object: &JsonValue<'a>, name: &str) -> JsonValue<'a> {
    let members =
        available(object.object_members(), "member access").expect("corpus value is an object");
    members
        .iter()
        .find(|member| available(member.name(), "member name") == name)
        .map_or_else(
            || panic!("corpus member {name:?} is missing"),
            |member| member.value(),
        )
}

fn array_field<'a>(object: &JsonValue<'a>, name: &str) -> Vec<JsonValue<'a>> {
    available(object_field(object, name).array_elements(), "array access")
        .expect("corpus member is an array")
        .into_iter()
        .map(consema_json::JsonArrayElement::value)
        .collect()
}

fn string_field<'a>(object: &JsonValue<'a>, name: &str) -> &'a str {
    available(object_field(object, name).as_string(), "string access")
        .expect("corpus member is a string")
}

fn integer_field(object: &JsonValue<'_>, name: &str) -> u64 {
    available(object_field(object, name).as_integer(), "integer access")
        .and_then(consema_core::BigInteger::to_i64)
        .and_then(|value| u64::try_from(value).ok())
        .expect("corpus member is a non-negative integer")
}

fn decode_hex(source: &str) -> Vec<u8> {
    let digits: Vec<u8> = source
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(digits.len() % 2 == 0, "hex has an odd digit count");
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
