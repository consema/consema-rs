//! Production-shaped INI and Java Properties fixture acceptance gates.

use consema::ini::{
    self, EditTransactionBuilder as IniEditBuilder, IniEncodingSelection, IniParseLimits,
    IniProfile, ProjectionRequest as IniProjectionRequest, ProjectionResult as IniProjectionResult,
    RepresentationPolicy,
};
use consema::properties::{
    self, EditTransactionBuilder as PropertiesEditBuilder, JavaString, JavaStringStatus,
    ProjectionRequest as PropertiesProjectionRequest,
    ProjectionResult as PropertiesProjectionResult, PropertiesParseLimits,
};
use consema_document::{
    FormationStatus, MappingPolicy, MaterializationFidelity, MaterializationRequest,
    MaterializationResult, MaterializationStyleId, NewlinePolicy, ProfileId, SourceEncoding,
    SourcePatchLimits, WindowsCodePage,
};

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

#[derive(Clone, Copy)]
enum IniEncoding {
    Default,
    Windows1252,
}

struct IniFixture {
    name: &'static str,
    source: FixtureSource,
    profile: IniProfile,
    encoding: IniEncoding,
    sections: usize,
    entries: usize,
}

const INI_FIXTURES: &[IniFixture] = &[
    IniFixture {
        name: "desktop-settings",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/desktop-settings.ini"
        )),
        profile: IniProfile::PortableV1,
        encoding: IniEncoding::Default,
        sections: 3,
        entries: 7,
    },
    IniFixture {
        name: "dotnet-service",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/dotnet-service.ini"
        )),
        profile: IniProfile::WindowsV1,
        encoding: IniEncoding::Default,
        sections: 3,
        entries: 7,
    },
    IniFixture {
        name: "python-tool",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/ini/python-tool.ini"
        )),
        profile: IniProfile::PythonConfigParserV1,
        encoding: IniEncoding::Default,
        sections: 3,
        entries: 6,
    },
    IniFixture {
        name: "legacy-mixed-newline",
        source: FixtureSource::Hex(include_str!(
            "../../../conformance/fixtures/ini/legacy-mixed-newline.ini.hex"
        )),
        profile: IniProfile::PortableV1,
        encoding: IniEncoding::Default,
        sections: 2,
        entries: 3,
    },
    IniFixture {
        name: "windows-cp1252",
        source: FixtureSource::Hex(include_str!(
            "../../../conformance/fixtures/ini/windows-cp1252.ini.hex"
        )),
        profile: IniProfile::WindowsV1,
        encoding: IniEncoding::Windows1252,
        sections: 1,
        entries: 3,
    },
];

#[derive(Clone, Copy)]
enum PropertiesEncoding {
    ReaderUtf8,
    Latin1,
}

struct PropertiesFixture {
    name: &'static str,
    source: FixtureSource,
    encoding: PropertiesEncoding,
    properties: usize,
    scalar_projectable: bool,
}

const PROPERTIES_FIXTURES: &[PropertiesFixture] = &[
    PropertiesFixture {
        name: "logging",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/logging.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 7,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "messages",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/messages.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 4,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "build-tool",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/build-tool.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 6,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "windows-paths",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/windows-paths.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 4,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "continuation-heavy",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/continuation-heavy.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 3,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "latin1-resource",
        source: FixtureSource::Hex(include_str!(
            "../../../conformance/fixtures/properties/latin1-resource.properties.hex"
        )),
        encoding: PropertiesEncoding::Latin1,
        properties: 3,
        scalar_projectable: true,
    },
    PropertiesFixture {
        name: "utf16-edge",
        source: FixtureSource::Bytes(include_bytes!(
            "../../../conformance/fixtures/properties/utf16-edge.properties"
        )),
        encoding: PropertiesEncoding::ReaderUtf8,
        properties: 3,
        scalar_projectable: false,
    },
];

#[test]
fn production_ini_fixtures_close_without_normalizing_source_bytes() {
    for fixture in INI_FIXTURES {
        let source = fixture.source.bytes();
        let document = ini::parse(
            source.as_slice(),
            fixture.profile,
            ini_encoding(fixture.encoding),
            IniParseLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{} did not parse: {error:?}", fixture.name));
        assert_eq!(
            document.formation_status(),
            FormationStatus::Complete,
            "{}: {:?}",
            fixture.name,
            document.diagnostics()
        );
        assert!(
            document.diagnostics().is_empty(),
            "{}: {:?}",
            fixture.name,
            document.diagnostics()
        );
        assert_eq!(document.render(), source, "{}", fixture.name);
        assert_exact_ini_coverage(&document, source.len(), fixture.name);
        assert_eq!(
            document.sections().len(),
            fixture.sections,
            "{}",
            fixture.name
        );
        assert_eq!(
            document.entries().len(),
            fixture.entries,
            "{}",
            fixture.name
        );

        let IniProjectionResult::Complete(projected) =
            document.project(IniProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("{} exact projection failed", fixture.name);
        };
        let MaterializationResult::Complete(materialized) = ini::materialize(
            &projected.value,
            &ini_materialization_request(fixture.profile, fixture.encoding),
        ) else {
            panic!("{} materialization failed", fixture.name);
        };
        assert_eq!(
            materialized.fidelity,
            MaterializationFidelity::Exact,
            "{}",
            fixture.name
        );
        assert!(
            matches!(
                materialized
                    .document
                    .project(IniProjectionRequest::best_exact_entry_mapping()),
                IniProjectionResult::Complete(ref result) if result.value == projected.value
            ),
            "{}",
            fixture.name
        );

        let mut edit = IniEditBuilder::new(&document);
        edit.semantic_value(
            document.entries()[0].node_ref(),
            "fixture-edited",
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document
            .commit(&edit.build())
            .unwrap_or_else(|error| panic!("{} edit failed: {error:?}", fixture.name));
        assert_patch_replay(
            document.source(),
            commit.document.source(),
            &commit.source_patch,
            &commit.untouched_proof,
        );
    }
}

#[test]
fn ini_byte_container_fixtures_retain_their_declared_transport_facts() {
    let mixed = INI_FIXTURES[3].source.bytes();
    let mut lines = mixed.split_inclusive(|byte| *byte == b'\n');
    assert!(lines.clone().any(|line| line.ends_with(b"\r\n")));
    assert!(lines.any(|line| line.ends_with(b"\n") && !line.ends_with(b"\r\n")));

    let cp1252 = INI_FIXTURES[4].source.bytes();
    assert!(String::from_utf8(cp1252.clone()).is_err());
    assert!(cp1252.contains(&0xe9));
    assert!(cp1252.contains(&0x80));
}

#[test]
fn production_properties_fixtures_close_or_reject_scalar_projection_explicitly() {
    for fixture in PROPERTIES_FIXTURES {
        let source = fixture.source.bytes();
        let document = match fixture.encoding {
            PropertiesEncoding::ReaderUtf8 => properties::parse_reader(
                source.as_slice(),
                SourceEncoding::Utf8,
                PropertiesParseLimits::default(),
            ),
            PropertiesEncoding::Latin1 => {
                properties::parse_latin1(source.as_slice(), PropertiesParseLimits::default())
            }
        }
        .unwrap_or_else(|error| panic!("{} did not parse: {error:?}", fixture.name));
        assert_eq!(
            document.formation_status(),
            FormationStatus::Complete,
            "{}",
            fixture.name
        );
        assert!(
            document.diagnostics().is_empty(),
            "{}: {:?}",
            fixture.name,
            document.diagnostics()
        );
        assert_eq!(document.render(), source, "{}", fixture.name);
        assert_exact_properties_coverage(&document, source.len(), fixture.name);
        assert_eq!(
            document.properties().len(),
            fixture.properties,
            "{}",
            fixture.name
        );

        match document.project(PropertiesProjectionRequest::best_exact_entry_mapping()) {
            PropertiesProjectionResult::Complete(projected) => {
                assert!(fixture.scalar_projectable, "{}", fixture.name);
                let MaterializationResult::Complete(materialized) = properties::materialize(
                    &projected.value,
                    &properties_materialization_request(fixture.encoding),
                ) else {
                    panic!("{} materialization failed", fixture.name);
                };
                assert_eq!(
                    materialized.fidelity,
                    MaterializationFidelity::Exact,
                    "{}",
                    fixture.name
                );
                assert!(
                    matches!(
                        materialized
                            .document
                            .project(PropertiesProjectionRequest::best_exact_entry_mapping()),
                        PropertiesProjectionResult::Complete(ref result) if result.value == projected.value
                    ),
                    "{}",
                    fixture.name
                );
            }
            PropertiesProjectionResult::Failed(failed) => {
                assert!(!fixture.scalar_projectable, "{}", fixture.name);
                assert!(failed.report.events().is_empty(), "{}", fixture.name);
                assert!(
                    document.properties().iter().any(|property| {
                        property.key().status() == JavaStringStatus::UnpairedSurrogate
                            || property.value().status() == JavaStringStatus::UnpairedSurrogate
                    }),
                    "{}",
                    fixture.name
                );
            }
        }

        let mut edit = PropertiesEditBuilder::new(&document);
        edit.semantic_value(
            document.properties()[0].node_ref(),
            JavaString::from_unicode("fixture-edited"),
        );
        let commit = document
            .commit(&edit.build())
            .unwrap_or_else(|error| panic!("{} edit failed: {error:?}", fixture.name));
        assert_patch_replay(
            document.source(),
            commit.document.source(),
            &commit.source_patch,
            &commit.untouched_proof,
        );
    }
}

#[test]
fn properties_latin1_container_is_not_accidentally_utf8() {
    let source = PROPERTIES_FIXTURES[5].source.bytes();
    assert!(String::from_utf8(source.clone()).is_err());
    assert!(source.contains(&0xe9));
    assert!(source.contains(&0xa3));
    assert!(source.contains(&0xef));
}

fn ini_encoding(encoding: IniEncoding) -> IniEncodingSelection {
    match encoding {
        IniEncoding::Default => IniEncodingSelection::ProfileDefault,
        IniEncoding::Windows1252 => {
            IniEncodingSelection::Explicit(SourceEncoding::WindowsCodePage(
                WindowsCodePage::from_number(1252).expect("Windows-1252 must be published"),
            ))
        }
    }
}

fn ini_materialization_request(
    profile: IniProfile,
    source_encoding: IniEncoding,
) -> MaterializationRequest {
    let request = match profile {
        IniProfile::PortableV1 => MaterializationRequest::new(
            ProfileId::new("ini.portable", 1),
            MaterializationStyleId::new("ini.portable-canonical", 1),
        ),
        IniProfile::WindowsV1 => MaterializationRequest::new(
            ProfileId::new("ini.windows", 1),
            MaterializationStyleId::new("ini.windows-canonical", 1),
        )
        .with_encoding(SourceEncoding::Utf16Le)
        .with_newline(NewlinePolicy::CrLf),
        IniProfile::PythonConfigParserV1 => MaterializationRequest::new(
            ProfileId::new("ini.python-configparser", 1),
            MaterializationStyleId::new("ini.python-configparser-canonical", 1),
        ),
    }
    .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject);
    match source_encoding {
        IniEncoding::Default => request,
        IniEncoding::Windows1252 => request.with_encoding(SourceEncoding::WindowsCodePage(
            WindowsCodePage::from_number(1252).expect("Windows-1252 must be published"),
        )),
    }
}

fn properties_materialization_request(encoding: PropertiesEncoding) -> MaterializationRequest {
    match encoding {
        PropertiesEncoding::ReaderUtf8 => MaterializationRequest::new(
            ProfileId::new("java-properties.reader", 1),
            MaterializationStyleId::new("java-properties.reader-canonical", 1),
        ),
        PropertiesEncoding::Latin1 => MaterializationRequest::new(
            ProfileId::new("java-properties.latin1", 1),
            MaterializationStyleId::new("java-properties.latin1-canonical", 1),
        )
        .with_encoding(SourceEncoding::Latin1),
    }
}

fn assert_exact_ini_coverage(document: &ini::Document, source_len: usize, name: &str) {
    let pieces = document.lossless_structural_index().pieces();
    assert_eq!(
        pieces.len(),
        document.lossless_syntax_kinds().len(),
        "{name}"
    );
    assert_eq!(
        pieces.iter().map(|piece| piece.span().len()).sum::<usize>(),
        source_len,
        "{name}"
    );
    assert!(
        pieces
            .windows(2)
            .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte()),
        "{name}"
    );
}

fn assert_exact_properties_coverage(
    document: &properties::Document,
    source_len: usize,
    name: &str,
) {
    let pieces = document.lossless_structural_index().pieces();
    assert_eq!(
        pieces.len(),
        document.lossless_syntax_kinds().len(),
        "{name}"
    );
    assert_eq!(
        pieces.iter().map(|piece| piece.span().len()).sum::<usize>(),
        source_len,
        "{name}"
    );
    assert!(
        pieces
            .windows(2)
            .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte()),
        "{name}"
    );
}

fn assert_patch_replay(
    before: &consema_document::SourceSnapshot,
    after: &consema_document::SourceSnapshot,
    patch: &consema_document::SourcePatch,
    proof: &consema_document::UntouchedByteProof,
) {
    let replay = patch
        .apply(before, SourcePatchLimits::default())
        .expect("fixture patch must replay");
    assert_eq!(replay.bytes(), after.bytes());
    proof
        .verify(before, after, patch.replacements())
        .expect("fixture untouched-region proof must verify");
}

fn decode_hex(source: &str) -> Vec<u8> {
    let digits: Vec<u8> = source
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let mut chunks = digits.chunks_exact(2);
    let decoded = chunks
        .by_ref()
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect();
    assert!(
        chunks.remainder().is_empty(),
        "hex fixture has an odd digit count"
    );
    decoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("hex fixture contains a non-lowercase-hex byte"),
    }
}
