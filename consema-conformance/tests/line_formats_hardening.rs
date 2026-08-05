//! Adversarial publication-property checks for INI and Java Properties.

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
use consema_core::{EntryMappingBuilder, PortableValue};
use consema_document::{
    AssociationPlacement, FormationStatus, MaterializationLimits, MaterializationRequest,
    MaterializationResult, MaterializationStyleId, NewlinePolicy, ProfileId, SourceEncoding,
    SourcePatchLimits,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn line_format_publication_objects_are_send_and_sync() {
    assert_send_sync::<ini::Document>();
    assert_send_sync::<ini::ProjectionResult>();
    assert_send_sync::<ini::EditTransaction>();
    assert_send_sync::<ini::EditCommit>();
    assert_send_sync::<properties::Document>();
    assert_send_sync::<properties::JavaString>();
    assert_send_sync::<properties::ProjectionResult>();
    assert_send_sync::<properties::EditTransaction>();
    assert_send_sync::<properties::EditCommit>();
}

#[test]
fn bounded_ini_mutation_corpus_never_panics_or_publishes_partial_semantics() {
    let seeds = [
        (
            IniProfile::PortableV1,
            b"[core]\nname=value\nempty=\n".as_slice(),
        ),
        (
            IniProfile::WindowsV1,
            b"[Main]\r\nName=\" value \"\r\nname=two\r\n".as_slice(),
        ),
        (
            IniProfile::PythonConfigParserV1,
            b"[DEFAULT]\nroot=raw%(x)s\n[s]\nkey=one\n  two\n".as_slice(),
        ),
    ];
    for (profile, seed) in seeds {
        for end in 0..=seed.len() {
            check_ini_candidate(profile, &seed[..end]);
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x20, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                check_ini_candidate(profile, &mutated);
            }
        }
    }

    for malformed in [
        b"".as_slice(),
        b"[".as_slice(),
        b"[]\n".as_slice(),
        b"[s\nkey=value\n".as_slice(),
        b"[s]\nbare\n".as_slice(),
        b"[s]\nkey:value\n".as_slice(),
        b"[s]\nkey=\0value\n".as_slice(),
        b"[s]\nkey=one\n  two\n  three\n".as_slice(),
    ] {
        for profile in [
            IniProfile::PortableV1,
            IniProfile::WindowsV1,
            IniProfile::PythonConfigParserV1,
        ] {
            check_ini_candidate(profile, malformed);
        }
    }
}

fn check_ini_candidate(profile: IniProfile, bytes: &[u8]) {
    if let Ok(document) = ini::parse(
        bytes,
        profile,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    ) {
        assert_eq!(document.render(), bytes);
        assert_exact_ini_coverage(&document);
        assert!(document.diagnostics().len() <= document.parse_limits().common.max_diagnostics);
        if document.formation_status() == FormationStatus::Complete {
            assert!(matches!(
                document.project(IniProjectionRequest::best_exact_entry_mapping()),
                IniProjectionResult::Complete(_)
            ));
        } else {
            let IniProjectionResult::Failed(failed) =
                document.project(IniProjectionRequest::best_exact_entry_mapping())
            else {
                panic!("recovered INI published a value")
            };
            assert!(failed.report.events().is_empty());
            assert!(
                document
                    .commit(&IniEditBuilder::new(&document).build())
                    .is_err()
            );
        }
    }
}

#[test]
fn bounded_properties_mutation_corpus_never_panics_or_publishes_partial_semantics() {
    let reader = b"# comment\na\\ key=one\\\n two\\u0021\na\\ key=last\n";
    for end in 0..=reader.len() {
        check_reader_candidate(&reader[..end]);
    }
    for index in 0..reader.len() {
        for mask in [0x01, 0x20, 0x80, 0xff] {
            let mut mutated = reader.to_vec();
            mutated[index] ^= mask;
            check_reader_candidate(&mutated);
        }
    }

    let latin1 = b"name=caf\xe9\nemoji=\\uD83D\\uDE00\n";
    for end in 0..=latin1.len() {
        check_latin1_candidate(&latin1[..end]);
    }
    for index in 0..latin1.len() {
        for mask in [0x01, 0x20, 0x80, 0xff] {
            let mut mutated = latin1.to_vec();
            mutated[index] ^= mask;
            check_latin1_candidate(&mutated);
        }
    }

    for malformed in [
        b"a=\\u".as_slice(),
        b"a=\\u1".as_slice(),
        b"a=\\u12G4\nafter=ok".as_slice(),
        b"a=one\\\n".as_slice(),
        b"a=one\\\\".as_slice(),
        b"a=\\uD800".as_slice(),
        b"a=\\uDC00".as_slice(),
        b"a=\\uD800A".as_slice(),
        b"a=A\\uDC00".as_slice(),
        b"\0=\xff".as_slice(),
    ] {
        check_reader_candidate(malformed);
        check_latin1_candidate(malformed);
    }
}

fn check_reader_candidate(bytes: &[u8]) {
    if let Ok(document) = properties::parse_reader(
        bytes,
        SourceEncoding::Utf8,
        PropertiesParseLimits::default(),
    ) {
        check_properties_document(&document, bytes);
    }
}

fn check_latin1_candidate(bytes: &[u8]) {
    if let Ok(document) = properties::parse_latin1(bytes, PropertiesParseLimits::default()) {
        check_properties_document(&document, bytes);
    }
}

fn check_properties_document(document: &properties::Document, bytes: &[u8]) {
    assert_eq!(document.render(), bytes);
    assert_exact_properties_coverage(document);
    assert!(document.diagnostics().len() <= document.parse_limits().common.max_diagnostics);
    if document.formation_status() == FormationStatus::Recovered {
        let PropertiesProjectionResult::Failed(failed) =
            document.project(PropertiesProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("recovered Properties published a value")
        };
        assert!(failed.report.events().is_empty());
        assert!(
            document
                .commit(&PropertiesEditBuilder::new(document).build())
                .is_err()
        );
        return;
    }
    let well_formed = document.properties().iter().all(|property| {
        property.key().status() == JavaStringStatus::WellFormedUnicode
            && property.value().status() == JavaStringStatus::WellFormedUnicode
    });
    match document.project(PropertiesProjectionRequest::best_exact_entry_mapping()) {
        PropertiesProjectionResult::Complete(_) => assert!(well_formed),
        PropertiesProjectionResult::Failed(failed) => {
            assert!(!well_formed);
            assert!(failed.report.events().is_empty());
        }
    }
}

#[test]
fn line_format_transactions_are_snapshot_bound_conflict_atomic_and_replayable() {
    let ini_base = parse_ini(b"[s]\na=1\nb=2\n");
    let ini_other = parse_ini(b"[s]\na=1\nb=2\n");
    let mut stale_ini = IniEditBuilder::new(&ini_base);
    stale_ini.semantic_value(
        ini_base.entries()[0].node_ref(),
        "changed",
        RepresentationPolicy::CanonicalForProfile,
    );
    assert!(ini_other.commit(&stale_ini.build()).is_err());
    assert_eq!(ini_other.render(), b"[s]\na=1\nb=2\n");

    let target = ini_base.entries()[0].node_ref();
    let mut conflicting_ini = IniEditBuilder::new(&ini_base);
    conflicting_ini
        .semantic_value(target, "first", RepresentationPolicy::CanonicalForProfile)
        .literal_value(target, b"second".as_slice());
    assert!(ini_base.commit(&conflicting_ini.build()).is_err());
    assert_eq!(ini_base.render(), b"[s]\na=1\nb=2\n");

    let mut successful_ini = IniEditBuilder::new(&ini_base);
    successful_ini.insert_entry(
        ini_base.sections()[0].node_ref(),
        "c",
        "3",
        AssociationPlacement::End,
    );
    let ini_commit = ini_base.commit(&successful_ini.build()).unwrap();
    let ini_replay = ini_commit
        .source_patch
        .apply(ini_base.source(), SourcePatchLimits::default())
        .unwrap();
    assert_eq!(ini_replay.bytes(), ini_commit.document.render());
    ini_commit
        .untouched_proof
        .verify(
            ini_base.source(),
            ini_commit.document.source(),
            ini_commit.source_patch.replacements(),
        )
        .unwrap();

    let properties_base = parse_properties(b"a=1\nb=2\n");
    let properties_other = parse_properties(b"a=1\nb=2\n");
    let mut stale_properties = PropertiesEditBuilder::new(&properties_base);
    stale_properties.semantic_value(
        properties_base.properties()[0].node_ref(),
        JavaString::from_unicode("changed"),
    );
    assert!(properties_other.commit(&stale_properties.build()).is_err());
    assert_eq!(properties_other.render(), b"a=1\nb=2\n");

    let target = properties_base.properties()[0].node_ref();
    let mut conflicting_properties = PropertiesEditBuilder::new(&properties_base);
    conflicting_properties
        .semantic_value(target, JavaString::from_unicode("first"))
        .rename_property(target, JavaString::from_unicode("renamed"));
    assert!(
        properties_base
            .commit(&conflicting_properties.build())
            .is_err()
    );
    assert_eq!(properties_base.render(), b"a=1\nb=2\n");

    let mut successful_properties = PropertiesEditBuilder::new(&properties_base);
    successful_properties.insert_property(
        properties_base.node_ref(),
        JavaString::from_unicode("c"),
        JavaString::from_unicode("3"),
        AssociationPlacement::End,
    );
    let properties_commit = properties_base
        .commit(&successful_properties.build())
        .unwrap();
    let properties_replay = properties_commit
        .source_patch
        .apply(properties_base.source(), SourcePatchLimits::default())
        .unwrap();
    assert_eq!(
        properties_replay.bytes(),
        properties_commit.document.render()
    );
    properties_commit
        .untouched_proof
        .verify(
            properties_base.source(),
            properties_commit.document.source(),
            properties_commit.source_patch.replacements(),
        )
        .unwrap();
}

#[test]
fn line_format_materialization_limits_never_publish_partial_documents() {
    let value = string_mapping(&[("section", "value")]);
    for limits in [
        MaterializationLimits {
            max_input_nodes: 1,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_output_bytes: 2,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_depth: 0,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_provenance_entries: 0,
            ..MaterializationLimits::default()
        },
    ] {
        assert!(matches!(
            properties::materialize(
                &value,
                &MaterializationRequest::new(
                    ProfileId::new("java-properties.reader", 1),
                    MaterializationStyleId::new("java-properties.reader-canonical", 1),
                )
                .with_limits(limits),
            ),
            MaterializationResult::Failed(_)
        ));
    }

    let nested = nested_string_mapping(&[("s", &[("key", "value")])]);
    for limits in [
        MaterializationLimits {
            max_input_nodes: 1,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_output_bytes: 2,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_depth: 0,
            ..MaterializationLimits::default()
        },
        MaterializationLimits {
            max_provenance_entries: 0,
            ..MaterializationLimits::default()
        },
    ] {
        assert!(matches!(
            ini::materialize(
                &nested,
                &MaterializationRequest::new(
                    ProfileId::new("ini.portable", 1),
                    MaterializationStyleId::new("ini.portable-canonical", 1),
                )
                .with_newline(NewlinePolicy::Lf)
                .with_limits(limits),
            ),
            MaterializationResult::Failed(_)
        ));
    }
}

#[test]
fn line_format_length_and_continuation_bombs_fail_before_document_publication() {
    let long_ini = format!("[s]\nkey={}\n", "x".repeat(4096));
    let ini_limits = IniParseLimits {
        max_physical_line_bytes: 64,
        max_logical_line_bytes: 64,
        ..IniParseLimits::default()
    };
    assert!(
        ini::parse(
            long_ini.as_bytes(),
            IniProfile::PortableV1,
            IniEncodingSelection::ProfileDefault,
            ini_limits,
        )
        .is_err()
    );
    let python_bomb = format!("[s]\nkey=one\n{}", "  next\n".repeat(32));
    let python_limits = IniParseLimits {
        max_continuation_lines: 4,
        ..IniParseLimits::default()
    };
    assert!(
        ini::parse(
            python_bomb.as_bytes(),
            IniProfile::PythonConfigParserV1,
            IniEncodingSelection::ProfileDefault,
            python_limits,
        )
        .is_err()
    );

    let long_properties = format!("key={}\n", "x".repeat(4096));
    let properties_limits = PropertiesParseLimits {
        max_natural_line_bytes: 64,
        max_logical_line_scalars: 64,
        ..PropertiesParseLimits::default()
    };
    assert!(
        properties::parse_reader(
            long_properties.as_bytes(),
            SourceEncoding::Utf8,
            properties_limits,
        )
        .is_err()
    );
    let continuation_bomb = format!("key=one\\\n{}", " next\\\n".repeat(32));
    let continuation_limits = PropertiesParseLimits {
        max_logical_line_natural_lines: 4,
        ..PropertiesParseLimits::default()
    };
    assert!(
        properties::parse_reader(
            continuation_bomb.as_bytes(),
            SourceEncoding::Utf8,
            continuation_limits,
        )
        .is_err()
    );
}

fn parse_ini(source: &[u8]) -> ini::Document {
    ini::parse(
        source,
        IniProfile::PortableV1,
        IniEncodingSelection::ProfileDefault,
        IniParseLimits::default(),
    )
    .unwrap()
}

fn parse_properties(source: &[u8]) -> properties::Document {
    properties::parse_reader(
        source,
        SourceEncoding::Utf8,
        PropertiesParseLimits::default(),
    )
    .unwrap()
}

fn assert_exact_ini_coverage(document: &ini::Document) {
    let pieces = document.lossless_structural_index().pieces();
    assert_eq!(pieces.len(), document.lossless_syntax_kinds().len());
    if document.source().is_empty() {
        assert!(pieces.is_empty());
        return;
    }
    assert_eq!(pieces.first().unwrap().span().start_byte(), 0);
    assert_eq!(
        pieces.last().unwrap().span().end_byte(),
        document.source().len()
    );
    assert!(
        pieces
            .windows(2)
            .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
    );
}

fn assert_exact_properties_coverage(document: &properties::Document) {
    let pieces = document.lossless_structural_index().pieces();
    assert_eq!(pieces.len(), document.lossless_syntax_kinds().len());
    if document.source().is_empty() {
        assert!(pieces.is_empty());
        return;
    }
    assert_eq!(pieces.first().unwrap().span().start_byte(), 0);
    assert_eq!(
        pieces.last().unwrap().span().end_byte(),
        document.source().len()
    );
    assert!(
        pieces
            .windows(2)
            .all(|pair| pair[0].span().end_byte() == pair[1].span().start_byte())
    );
}

fn string_mapping(entries: &[(&str, &str)]) -> PortableValue {
    let mut mapping = EntryMappingBuilder::new();
    for (key, value) in entries {
        mapping.push(PortableValue::string(*key), PortableValue::string(*value));
    }
    mapping.build()
}

fn nested_string_mapping(sections: &[(&str, &[(&str, &str)])]) -> PortableValue {
    let mut outer = EntryMappingBuilder::new();
    for (section, entries) in sections {
        outer.push(PortableValue::string(*section), string_mapping(entries));
    }
    outer.build()
}
