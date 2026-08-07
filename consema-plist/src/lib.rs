//! Lossless `plist.xml@1` and `plist.binary@1` documents under the RFC 0013
//! boundary.
//!
//! The two profiles share one native value model and the immutable-snapshot,
//! recovery, transaction, proof, and patch infrastructure. They do not share
//! syntax: the XML profile is a text tree of tags, while the binary profile
//! is an object table with offset-table and trailer facts and has no text,
//! whitespace, or token fiction.
//!
//! The profile is selected by the caller before formation. The `bplist00`
//! magic number does not silently choose a profile, and a `.plist` extension
//! alone never determines which representation, encoding, or profile applies.
//! The two profiles are format identities, not dialects of one format: Apple
//! serializes the same value space to both representations, and Consema
//! preserves that value identity.
//!
//! Formation is side-effect free: it never fetches the Apple DTD or any other
//! URI, resolves a UID or archive key path, evaluates an expression, reads
//! environment or locale state, writes files, or invokes application code.

use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{FatalFormationFailure, ParseLimits, ProfileId, SourceEncoding};
use std::sync::Arc;

mod document;
mod edit;
mod materialization;
mod native;
mod operation_registry;
mod parser_binary;
mod parser_xml;
mod projection;
mod query;

pub use document::{
    ConversionEventKind, ConversionFailure, ConversionReport, ConversionReportEvent,
    ConvertedDocument, Document, PlistRepresentation,
};
pub use edit::{
    DictPlacement, EditCommit, EditFailure, EditOperation, EditPath, EditPathStep, EditTransaction,
    EditTransactionBuilder, EditValue,
};
pub use materialization::materialize;
pub use native::{
    PLIST_EPOCH_OFFSET_UNIX, PlistArenaError, PlistArenaLimits, PlistArray, PlistBoolean,
    PlistData, PlistDate, PlistDateError, PlistDict, PlistDictEntry, PlistDocument,
    PlistDocumentBuilder, PlistInteger, PlistKey, PlistReal, PlistString,
    PlistStringConversionError, PlistStringStatus, PlistUid, PlistValue, PlistValueKind,
    PlistValueRef, RealWidth,
};
pub use operation_registry::format_operation_registry;
pub use parser_binary::{
    BinaryFacts, BinaryObjectFact, BinaryObjectRefFact, BinaryOffsetFact, BinaryTrailerFacts,
    PlistFormedBinary,
};
pub use parser_xml::{PlistFormedXml, PlistSyntaxKind};
pub use projection::{
    CollisionPolicy, CompleteProjection, FailedProjectionAttempt, Fidelity, ProjectedLocation,
    ProjectionEvent, ProjectionEventKind, ProjectionFailure, ProjectionLimits, ProjectionReport,
    ProjectionRequest, ProjectionResult, ProjectionTarget, ProvenanceEntry, ProvenanceMap,
    ProvenanceRelation, SourceOrigin, UidPolicy, project,
};
pub use query::{
    PlistBinaryMatch, PlistMatch, PlistSyntaxMatch, execute_plist_binary_query,
    execute_plist_binary_query_cursor, execute_plist_native_query,
    execute_plist_native_query_cursor, execute_plist_syntax_query,
    execute_plist_syntax_query_cursor,
};

/// Frozen plist formation profiles.
///
/// The profile is selected by the caller before formation; neither the
/// `bplist00` magic number nor a `.plist` extension selects semantics (RFC
/// 0013 §1).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlistProfile {
    /// The plist value vocabulary expressed as XML 1.0 (RFC 0013 §4).
    XmlV1,
    /// The binary object-table representation (RFC 0013 §5).
    BinaryV1,
}

impl PlistProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::XmlV1 => ProfileId::new("plist.xml", 1),
            Self::BinaryV1 => ProfileId::new("plist.binary", 1),
        }
    }
}

/// Explicit source-encoding selection.
///
/// For the XML profile the selection follows the RFC 0012 source contract:
/// no-BOM source defaults to UTF-8, and an explicit caller choice is
/// evidence, not permission to contradict a BOM or a declaration. The binary
/// profile has no text encoding and no BOM; only `ProfileDefault` and
/// `Explicit(SourceEncoding::Binary)` are consistent with it. A selection
/// inconsistent with the chosen profile is a source-contract conflict at
/// formation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlistEncodingSelection {
    /// Apply only the frozen profile default and BOM rules.
    ProfileDefault,
    /// Use one caller-selected document-entity encoding (XML profile), or
    /// `SourceEncoding::Binary` (binary profile).
    Explicit(SourceEncoding),
}

/// Plist-specific formation, structure, recovery, and conversion limits
/// (RFC 0013 §12).
///
/// Every limit failure is a fatal formation failure or an atomic operation
/// failure; a limit failure never masquerades as an empty tree, truncated
/// data, a shortened query, a partial target, or a successful edit (hard
/// gate 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlistParseLimits {
    /// Common source, node, nesting, token, and diagnostic limits; includes
    /// `max_source_bytes` (the 42-byte binary minimum is far below the
    /// default).
    pub common: ParseLimits,
    /// Maximum decoded UTF-8 bytes (XML profile).
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalars and coordinate steps (XML profile).
    pub max_decoded_scalars: usize,
    /// Maximum native objects: binary object-table entries and native arena
    /// nodes.
    pub max_object_count: usize,
    /// Maximum container nesting depth of the native value graph.
    pub max_container_depth: usize,
    /// Maximum dictionary entries in one dictionary.
    pub max_dict_entries: usize,
    /// Maximum array elements in one array.
    pub max_array_elements: usize,
    /// Maximum members in one duplicate-key group.
    pub max_duplicate_key_group_members: usize,
    /// Maximum UTF-16 code units in one string or key.
    pub max_string_code_units: usize,
    /// Maximum bytes in one data value.
    pub max_data_bytes: usize,
    /// Maximum UID values in one document.
    pub max_uid_count: usize,
    /// Maximum extended-size integer objects (binary profile).
    pub max_extended_size_integers: usize,
    /// Maximum magnitude claimed by one extended size (binary profile).
    pub max_extended_size_value: usize,
    /// Maximum `offsetIntSize` width in bytes (binary profile).
    pub max_offset_int_size: usize,
    /// Maximum `objectRefSize` width in bytes (binary profile).
    pub max_object_ref_size: usize,
    /// Maximum offset-table bytes (binary profile).
    pub max_offset_table_bytes: usize,
    /// Maximum XML lossless syntax pieces.
    pub max_syntax_pieces: usize,
    /// Maximum binary object/offset/trailer structural facts.
    pub max_binary_facts: usize,
    /// Maximum cross-representation conversion nodes.
    pub max_conversion_nodes: usize,
    /// Maximum conversion, projection, or edit report events.
    pub max_report_events: usize,
    /// Maximum recovery regions.
    pub max_recovery_regions: usize,
}

impl Default for PlistParseLimits {
    fn default() -> Self {
        Self {
            common: ParseLimits::default(),
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
            max_object_count: 1_000_000,
            max_container_depth: 256,
            max_dict_entries: 1_000_000,
            max_array_elements: 1_000_000,
            max_duplicate_key_group_members: 1_000_000,
            max_string_code_units: 16 * 1024 * 1024,
            max_data_bytes: 16 * 1024 * 1024,
            max_uid_count: 100_000,
            max_extended_size_integers: 10_000,
            max_extended_size_value: 1_000_000,
            max_offset_int_size: 8,
            max_object_ref_size: 8,
            max_offset_table_bytes: 8 * 1024 * 1024,
            max_syntax_pieces: 2_000_000,
            max_binary_facts: 2_000_000,
            max_conversion_nodes: 1_000_000,
            max_report_events: 100_000,
            max_recovery_regions: 100_000,
        }
    }
}

impl PlistParseLimits {
    /// Native arena limits derived from these parse limits.
    #[must_use]
    pub const fn arena_limits(self) -> PlistArenaLimits {
        PlistArenaLimits {
            max_objects: self.max_object_count,
            max_container_depth: self.max_container_depth,
        }
    }
}

/// Forms one `plist.xml@1` or `plist.binary@1` document from raw bytes
/// (RFC 0013 §1, §3).
///
/// Thin dispatch over [`Document::parse`]: the profile selects the
/// representation, the encoding selection follows the RFC 0013 §2 source
/// contract, and the limits bound formation. Neither the `bplist00` magic
/// number nor a `.plist` extension selects a profile.
pub fn parse(
    source: Arc<[u8]>,
    profile: PlistProfile,
    selection: PlistEncodingSelection,
    limits: PlistParseLimits,
) -> Result<Document, FatalFormationFailure> {
    Document::parse(source, profile, selection, limits)
}

/// Forms a `plist.binary@1` document from raw bytes (RFC 0013 §2.2, §3, §5).
///
/// The source is an opaque [`SourceEncoding::Binary`] snapshot; only
/// [`PlistEncodingSelection::ProfileDefault`] and
/// [`PlistEncodingSelection::Explicit`] with [`SourceEncoding::Binary`] are
/// consistent with the profile. Any other selection is a source-contract
/// conflict at formation and returns a fatal `plist.binary.encoding@1`
/// failure.
///
/// The entry point is the M4 adaptation point for the complete binary
/// formation pipeline (query and structure domains); the parser itself is
/// `parser_binary::parse_binary`.
///
/// Conformance/tooling entry point: returns the intermediate
/// [`PlistFormedBinary`] formation shape (source, structural regions,
/// binary facts, and the recovery outcome) before the [`Document`] wrap;
/// [`parse`] is the typed entry point for the shared document shape, and
/// the conformance runner exercises the formed shape through [`Document`].
pub fn parse_binary(
    bytes: Arc<[u8]>,
    selection: PlistEncodingSelection,
    limits: PlistParseLimits,
) -> Result<PlistFormedBinary, FatalFormationFailure> {
    match selection {
        PlistEncodingSelection::ProfileDefault
        | PlistEncodingSelection::Explicit(SourceEncoding::Binary) => {}
        PlistEncodingSelection::Explicit(_) => {
            return Err(FatalFormationFailure::from_diagnostic(Diagnostic::new(
                "plist.binary.encoding@1",
                DiagnosticCategory::Encoding,
                DiagnosticSeverity::Error,
                None,
                0,
            )));
        }
    }
    parser_binary::parse_binary(bytes, limits)
}

/// Forms a `plist.xml@1` document from raw bytes (RFC 0013 §2.1, §3, §4).
///
/// The source contract follows RFC 0013 §2.1: no-BOM source defaults to
/// UTF-8, a BOM or an explicit caller choice is evidence that never
/// contradicts the other, and only the UTF-8/UTF-16 document-entity table is
/// admitted. Any other selection is a source-contract conflict at formation
/// and returns a fatal `plist.xml.encoding@1` failure.
///
/// The entry point is the M4 adaptation point for the complete XML formation
/// pipeline (lossless-syntax and native query domains); the parser itself is
/// `parser_xml::parse_xml`.
///
/// Conformance/tooling entry point: returns the intermediate
/// [`PlistFormedXml`] formation shape (source, lossless syntax pieces, and
/// the recovery outcome) before the [`Document`] wrap; [`parse`] is the
/// typed entry point for the shared document shape, and the conformance
/// runner exercises the formed shape through [`Document`].
pub fn parse_xml(
    bytes: Arc<[u8]>,
    selection: PlistEncodingSelection,
    limits: PlistParseLimits,
) -> Result<PlistFormedXml, FatalFormationFailure> {
    match selection {
        PlistEncodingSelection::ProfileDefault
        | PlistEncodingSelection::Explicit(
            SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be,
        ) => {}
        PlistEncodingSelection::Explicit(_) => {
            return Err(FatalFormationFailure::from_diagnostic(Diagnostic::new(
                "plist.xml.encoding@1",
                DiagnosticCategory::Encoding,
                DiagnosticSeverity::Error,
                None,
                0,
            )));
        }
    }
    parser_xml::parse_xml(bytes, selection, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::FormationStatus;

    #[test]
    fn profile_ids_are_stable() {
        assert_eq!(PlistProfile::XmlV1.id(), ProfileId::new("plist.xml", 1));
        assert_eq!(
            PlistProfile::BinaryV1.id(),
            ProfileId::new("plist.binary", 1)
        );
    }

    #[test]
    fn parse_limits_defaults_derive_arena_limits() {
        let limits = PlistParseLimits::default();
        assert_eq!(limits.arena_limits().max_objects, limits.max_object_count);
        assert_eq!(
            limits.arena_limits().max_container_depth,
            limits.max_container_depth
        );
    }

    #[test]
    fn parse_xml_entry_forms_a_complete_document() {
        let source: &[u8] = b"<plist version=\"1.0\"><string>x</string></plist>";
        let formed = parse_xml(
            Arc::<[u8]>::from(source),
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("xml plist forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
        assert_eq!(formed.render(), source);
        assert!(formed.document().is_some());
        assert_eq!(
            formed.document().unwrap().root_value().kind(),
            PlistValueKind::String
        );
    }

    #[test]
    fn parse_xml_entry_rejects_incompatible_selections() {
        for selection in [
            PlistEncodingSelection::Explicit(SourceEncoding::Binary),
            PlistEncodingSelection::Explicit(SourceEncoding::Latin1),
        ] {
            let error = parse_xml(
                Arc::<[u8]>::from(b"<plist version=\"1.0\"/>".as_slice()),
                selection,
                PlistParseLimits::default(),
            )
            .expect_err("incompatible selection must fail");
            assert!(
                error
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "plist.xml.encoding@1")
            );
        }
    }

    #[test]
    fn parse_entry_dispatches_by_profile() {
        let xml_source: &[u8] = b"<plist version=\"1.0\"><string>x</string></plist>";
        let xml = parse(
            Arc::<[u8]>::from(xml_source),
            PlistProfile::XmlV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("xml forms");
        assert_eq!(xml.representation(), PlistRepresentation::Xml);
        assert_eq!(xml.status(), FormationStatus::Complete);
        assert_eq!(xml.render(), xml_source);
        assert_eq!(xml.profile(), ProfileId::new("plist.xml", 1));

        let mut binary = b"bplist00".to_vec();
        binary.push(0x08); // object 0: false
        binary.push(0x08); // offset entry 0 -> 8
        binary.extend_from_slice(&[0, 0, 0, 0, 0]); // unused
        binary.push(0); // sortVersion
        binary.push(1); // offsetIntSize
        binary.push(1); // objectRefSize
        binary.extend_from_slice(&1_u64.to_be_bytes()); // numObjects
        binary.extend_from_slice(&0_u64.to_be_bytes()); // topObject
        binary.extend_from_slice(&9_u64.to_be_bytes()); // offsetTableOffset
        assert_eq!(binary.len(), 42);
        let binary = parse(
            Arc::<[u8]>::from(binary),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("binary forms");
        assert_eq!(binary.representation(), PlistRepresentation::Binary);
        assert_eq!(binary.status(), FormationStatus::Complete);
        assert_eq!(binary.profile(), ProfileId::new("plist.binary", 1));
    }

    #[test]
    fn parse_xml_entry_accepts_explicit_text_encodings() {
        let text = "<plist version=\"1.0\"><dict/></plist>";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let formed = parse_xml(
            Arc::<[u8]>::from(bytes),
            PlistEncodingSelection::Explicit(SourceEncoding::Utf16Le),
            PlistParseLimits::default(),
        )
        .expect("explicit UTF-16LE forms");
        assert_eq!(formed.status(), FormationStatus::Complete);
    }
}
