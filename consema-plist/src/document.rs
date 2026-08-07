//! Unified `plist.xml@1` / `plist.binary@1` document layer (RFC 0013 §3, §7).
//!
//! The two profiles share one native value model but have disjoint syntax
//! systems (RFC 0013 §7): [`Document`] is an enum over the two formed
//! representations, so representation-specific facts are only reachable
//! through representation-specific accessors. Parsing never invents facts of
//! the other representation (hard gate 1): the XML lossless index and syntax
//! kinds exist only for `Xml` documents, and the binary object/offset/ref/
//! trailer facts and structural regions exist only for `Binary` documents.
//!
//! Cross-representation conversion ([`Document::convert_to`]) is a
//! first-class transform (RFC 0013 §7): it serializes the reachable native
//! value graph under the target profile, reparses the exact emitted bytes,
//! verifies native-model equality (the reparse closure), and reports the
//! representation change plus one value-mapped event per reachable node.
//! Conversion is atomic: a native fact the target representation cannot
//! express fails the whole conversion with a `plist.conversion.inexpressible@1`
//! diagnostic and returns no target document (hard gate 3). UID values,
//! `Float32` width facts, unpaired-surrogate strings, fractional-second
//! dates, dates outside the XML calendar's year range, non-XML characters,
//! non-canonical NaN payloads, and shared object identity are binary-only and
//! block conversion to XML; no XML-sourced document ever contains any of
//! them, so conversion to binary is always expressible.

use crate::native::{
    PlistDocument, PlistReal, PlistString, PlistStringStatus, PlistValue, PlistValueRef, RealWidth,
};
use crate::parser_binary::{BinaryFacts, PlistFormedBinary};
use crate::parser_xml::{PlistFormedXml, PlistSyntaxKind};
use crate::{PLIST_EPOCH_OFFSET_UNIX, PlistEncodingSelection, PlistParseLimits, PlistProfile};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    BinaryStructuralIndex, DocumentAuthority, FatalFormationFailure, FormatFamilyId,
    FormationStatus, LosslessStructuralIndex, ProfileId, SnapshotIdentity, SourceSnapshot,
};
use std::sync::Arc;

/// The two plist representations (RFC 0013 §1, §7).
///
/// The representations share one native value model and are format
/// identities, not dialects of one format; a `.plist` extension never selects
/// one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlistRepresentation {
    /// The `plist.xml@1` text representation: a tree of tags over raw text.
    Xml,
    /// The `plist.binary@1` object-table representation.
    Binary,
}

/// One formed plist document under either representation (RFC 0013 §3, §7).
///
/// The concrete representation is private; representation-specific facts are
/// reachable only through the representation-specific accessors, so an XML
/// document can never expose binary structure facts and vice versa (hard
/// gate 1). Every returned fact is an immutable snapshot fact.
#[derive(Clone, Debug)]
pub struct Document {
    inner: PlistDocumentInner,
}

#[derive(Clone, Debug)]
enum PlistDocumentInner {
    Xml(PlistFormedXml),
    Binary(PlistFormedBinary),
}

impl Document {
    /// Forms one document from raw bytes under one exact profile (RFC 0013
    /// §1, §3).
    ///
    /// The profile is selected by the caller before formation; neither the
    /// `bplist00` magic number nor a `.plist` extension selects semantics.
    /// The source and encoding contract follows RFC 0013 §2: the binary
    /// profile admits only the opaque binary source, and the XML profile
    /// follows the RFC 0012 UTF-8/UTF-16 document-entity table. An encoding
    /// selection inconsistent with the profile is a fatal source-contract
    /// conflict at formation.
    pub fn parse(
        source: Arc<[u8]>,
        profile: PlistProfile,
        selection: PlistEncodingSelection,
        limits: PlistParseLimits,
    ) -> Result<Self, FatalFormationFailure> {
        match profile {
            PlistProfile::XmlV1 => Ok(Self {
                inner: PlistDocumentInner::Xml(crate::parse_xml(source, selection, limits)?),
            }),
            PlistProfile::BinaryV1 => Ok(Self {
                inner: PlistDocumentInner::Binary(crate::parse_binary(source, selection, limits)?),
            }),
        }
    }

    /// Representation of the formed document.
    #[must_use]
    pub const fn representation(&self) -> PlistRepresentation {
        match &self.inner {
            PlistDocumentInner::Xml(_) => PlistRepresentation::Xml,
            PlistDocumentInner::Binary(_) => PlistRepresentation::Binary,
        }
    }

    /// Formation status (RFC 0013 §3).
    #[must_use]
    pub const fn status(&self) -> FormationStatus {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.status(),
            PlistDocumentInner::Binary(formed) => formed.status(),
        }
    }

    /// Complete or explicitly recovered formation state.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        self.status()
    }

    /// Immutable raw source with encoding facts.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.source(),
            PlistDocumentInner::Binary(formed) => formed.source(),
        }
    }

    /// Exact original bytes; unmodified rendering is byte-exact.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.render(),
            PlistDocumentInner::Binary(formed) => formed.render(),
        }
    }

    /// Ordered diagnostics from formation.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.diagnostics(),
            PlistDocumentInner::Binary(formed) => formed.diagnostics(),
        }
    }

    /// Snapshot identity to which every handle and span of this document
    /// belongs.
    #[must_use]
    pub fn snapshot_identity(&self) -> SnapshotIdentity {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.authority().identity(),
            PlistDocumentInner::Binary(formed) => formed.authority().identity(),
        }
    }

    /// Exact source profile of the formed document.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        match self.representation() {
            PlistRepresentation::Xml => PlistProfile::XmlV1.id(),
            PlistRepresentation::Binary => PlistProfile::BinaryV1.id(),
        }
    }

    /// Stable format family identity of the plist family (RFC 0013 §7).
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("plist", 1)
    }

    /// Native value arena, when the root value is provable (RFC 0013 §6).
    ///
    /// Both representations share the same native value model; `Some` exactly
    /// when formation proved the complete root value. A `Recovered` document
    /// may or may not carry one.
    #[must_use]
    pub fn document(&self) -> Option<&PlistDocument> {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.document(),
            PlistDocumentInner::Binary(formed) => formed.document(),
        }
    }

    /// Exhaustive ordered lossless piece coverage of the raw bytes;
    /// `plist.xml@1` only (RFC 0013 §8.2, hard gate 1).
    #[must_use]
    pub fn lossless_structural_index(&self) -> Option<&LosslessStructuralIndex> {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => Some(formed.lossless_structural_index()),
            PlistDocumentInner::Binary(_) => None,
        }
    }

    /// Ordered XML syntax kinds, parallel to the lossless structural pieces;
    /// `plist.xml@1` only (RFC 0013 §8.2, hard gate 1).
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> Option<&[PlistSyntaxKind]> {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => Some(formed.lossless_syntax_kinds()),
            PlistDocumentInner::Binary(_) => None,
        }
    }

    /// Binary object/offset/reference/trailer facts; `plist.binary@1` only
    /// (RFC 0013 §8.3, hard gate 1).
    #[must_use]
    pub fn binary_facts(&self) -> Option<&BinaryFacts> {
        match &self.inner {
            PlistDocumentInner::Xml(_) => None,
            PlistDocumentInner::Binary(formed) => Some(formed.facts()),
        }
    }

    /// Exhaustive ordered binary region coverage of the raw bytes;
    /// `plist.binary@1` only (RFC 0013 §2.2, §8.3, hard gate 1).
    #[must_use]
    pub fn binary_structural_index(&self) -> Option<&BinaryStructuralIndex> {
        match &self.inner {
            PlistDocumentInner::Xml(_) => None,
            PlistDocumentInner::Binary(formed) => Some(formed.structural_index()),
        }
    }

    /// Converts the document to the other representation (RFC 0013 §7).
    ///
    /// Conversion serializes the reachable native value graph under the
    /// target profile, reparses the exact emitted bytes under the same
    /// limits, and verifies that the target native model equals the source
    /// native model (reparse closure, RFC 0013 §7, §10.3). Every conversion
    /// is a transform: the report carries one `RepresentationChange` event
    /// followed by one `ValueMapped` event per reachable native node, in
    /// source arena order.
    ///
    /// Conversion is atomic (hard gate 3). A native fact the target
    /// representation cannot express fails the whole conversion with a
    /// `plist.conversion.inexpressible@1` diagnostic and returns no target
    /// document: UID values, `Float32` width facts, unpaired-surrogate
    /// strings, fractional-second dates, dates whose calendar year exceeds
    /// the XML grammar's 32-bit magnitude, strings or keys containing
    /// characters outside the XML 1.0 `Char` production, reals whose exact
    /// bits do not survive the XML spelling, and shared object identity are
    /// binary-only and fail conversion to XML. XML-sourced documents never
    /// contain any of them, so conversion to binary is always expressible.
    ///
    /// A source that is not `Complete` with a provable native document cannot
    /// be converted (RFC 0013 §3), and a target equal to the source
    /// representation is not a conversion: canonical same-representation
    /// materialization is a materialization concern (RFC 0013 §10).
    ///
    /// The limits bound the reachable conversion node count, the report event
    /// count, the target object count, and the target formation itself.
    pub fn convert_to(
        &self,
        target: PlistProfile,
        limits: PlistParseLimits,
    ) -> Result<ConvertedDocument, ConversionFailure> {
        let source_representation = self.representation();
        let target_representation = match target {
            PlistProfile::XmlV1 => PlistRepresentation::Xml,
            PlistProfile::BinaryV1 => PlistRepresentation::Binary,
        };
        if source_representation == target_representation {
            return Err(conversion_failure_with_args(
                "plist.conversion.same-representation@1",
                &[],
            ));
        }
        if self.status() != FormationStatus::Complete {
            return Err(conversion_failure_with_args(
                "plist.conversion.formation@1",
                &[("status", String::from("recovered"))],
            ));
        }
        let Some(native) = self.document() else {
            return Err(conversion_failure_with_args(
                "plist.conversion.formation@1",
                &[("status", String::from("no-native-document"))],
            ));
        };
        match (source_representation, target_representation) {
            (PlistRepresentation::Xml, PlistRepresentation::Binary) => {
                convert_xml_to_binary(native, limits)
            }
            (PlistRepresentation::Binary, PlistRepresentation::Xml) => {
                convert_binary_to_xml(native, limits)
            }
            _ => unreachable!("same-representation targets are rejected above"),
        }
    }

    /// Snapshot-bound identity authority for issuing query handles (M4
    /// adaptation point for the query and edit domains).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.authority(),
            PlistDocumentInner::Binary(formed) => formed.authority(),
        }
    }

    /// Limits applied during formation (M4 adaptation point for the query
    /// and edit domains).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn limits(&self) -> PlistParseLimits {
        match &self.inner {
            PlistDocumentInner::Xml(formed) => formed.limits(),
            PlistDocumentInner::Binary(formed) => formed.limits(),
        }
    }
}

/// One successful cross-representation conversion (RFC 0013 §7).
///
/// The target document and the conversion report are immutable snapshot
/// facts; the target is a new snapshot whose native model equals the source
/// native model.
#[derive(Clone, Debug)]
pub struct ConvertedDocument {
    document: Document,
    report: ConversionReport,
}

impl ConvertedDocument {
    /// Target document in the converted representation.
    #[must_use]
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// Conversion report events.
    #[must_use]
    pub fn report(&self) -> &ConversionReport {
        &self.report
    }

    /// Consumes the conversion, returning the target document.
    #[must_use]
    pub fn into_document(self) -> Document {
        self.document
    }
}

/// Conversion report of one cross-representation conversion (RFC 0013 §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionReport {
    events: Arc<[ConversionReportEvent]>,
}

impl ConversionReport {
    /// Creates a report from ordered validated events.
    #[doc(hidden)]
    #[must_use]
    pub fn new(events: Vec<ConversionReportEvent>) -> Self {
        Self {
            events: Arc::from(events),
        }
    }

    /// Ordered report events: one `RepresentationChange` event followed by
    /// one `ValueMapped` event per reachable native node, in source arena
    /// order.
    #[must_use]
    pub fn events(&self) -> &[ConversionReportEvent] {
        &self.events
    }

    /// Whether the conversion changed representation (always true for a
    /// successful cross-representation conversion).
    #[must_use]
    pub fn representation_changed(&self) -> bool {
        self.events
            .iter()
            .any(|event| event.kind() == ConversionEventKind::RepresentationChange)
    }
}

/// One conversion report event (RFC 0013 §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionReportEvent {
    kind: ConversionEventKind,
    source: Option<PlistValueRef>,
    target: Option<usize>,
}

impl ConversionReportEvent {
    /// Creates the single representation-change event of one conversion.
    fn representation_change() -> Self {
        Self {
            kind: ConversionEventKind::RepresentationChange,
            source: None,
            target: None,
        }
    }

    /// Creates one value-mapped event for one reachable source node.
    fn value_mapped(source: PlistValueRef, target: usize) -> Self {
        Self {
            kind: ConversionEventKind::ValueMapped,
            source: Some(source),
            target: Some(target),
        }
    }

    /// Event kind.
    #[must_use]
    pub const fn kind(&self) -> ConversionEventKind {
        self.kind
    }

    /// Source arena node this event concerns, when one exists.
    #[must_use]
    pub const fn source(&self) -> Option<PlistValueRef> {
        self.source
    }

    /// Target arena ordinal this event maps to, when one exists.
    #[must_use]
    pub const fn target(&self) -> Option<usize> {
        self.target
    }
}

/// Event kinds of one conversion report (RFC 0013 §7).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConversionEventKind {
    /// The document changed representation: `plist.xml@1` to `plist.binary@1`
    /// or vice versa (hard gate 2).
    RepresentationChange,
    /// One reachable native value node of the source document was carried
    /// into the target document at the mapped target arena ordinal.
    ValueMapped,
}

/// Atomic conversion failure (RFC 0013 §7, hard gate 3).
///
/// A failed conversion returns no target document, no partial bytes, and no
/// partial report; the ordered diagnostics explain which facts blocked the
/// conversion and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionFailure {
    diagnostics: Vec<Diagnostic>,
}

impl ConversionFailure {
    /// Creates a failure from ordered validated diagnostics.
    #[doc(hidden)]
    #[must_use]
    pub fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self { diagnostics }
    }

    /// Ordered diagnostics explaining why no target document exists.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// Reachable-graph facts of one native document (RFC 0013 §7).
struct ReachableGraph {
    /// Ordered value children of every arena node.
    children: Vec<Vec<PlistValueRef>>,
    /// Post-order rank of every reachable node, indexed by source arena
    /// ordinal. The XML parser assigns arena ordinals in close-tag order, so
    /// this is the target arena ordinal of each node in an XML conversion.
    ranks: Vec<usize>,
    /// Source ordinals of the reachable nodes in source arena order.
    reachable: Vec<usize>,
}

/// Decomposition failure of one date value under the XML calendar grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DateRangeError {
    /// The seconds value carries a fractional part (RFC 0013 §4.7).
    FractionalSeconds,
    /// The calendar year exceeds the exact whole-second range expressible by
    /// the XML grammar: the 32-bit year magnitude, or a Unix-seconds value
    /// whose exact double decomposition would round (hard gate 3).
    YearOutOfRange,
}

/// `2^53`: the largest magnitude at which every integral double is exactly
/// representable, so the day/second decomposition below it is exact.
const EXACT_UNIX_SECONDS_BOUND: f64 = 9_007_199_254_740_992.0;

/// Converts one `plist.xml@1` document to `plist.binary@1` (RFC 0013 §7).
///
/// Every arena node of an XML-sourced document is reachable and expressible
/// in binary; the target object table writes one string object per
/// dictionary entry key, in entry order, immediately before its dictionary,
/// and every other object exactly once in source arena order.
fn convert_xml_to_binary(
    native: &PlistDocument,
    limits: PlistParseLimits,
) -> Result<ConvertedDocument, ConversionFailure> {
    let node_count = native.node_count();
    if node_count > limits.max_conversion_nodes {
        return Err(conversion_limit(
            "conversion-nodes",
            node_count,
            limits.max_conversion_nodes,
        ));
    }
    let total_keys = arena_key_count(native);
    let target_object_count = node_count + total_keys;
    if target_object_count > limits.max_object_count {
        return Err(conversion_limit(
            "object-count",
            target_object_count,
            limits.max_object_count,
        ));
    }
    let event_count = 1 + node_count;
    if event_count > limits.max_report_events {
        return Err(conversion_limit(
            "report-events",
            event_count,
            limits.max_report_events,
        ));
    }
    let bytes = serialize_binary(native)?;
    let formed = parser_binary_parse(bytes, limits)?;
    if formed.status() != FormationStatus::Complete || formed.document() != Some(native) {
        return Err(reparse_failure());
    }
    // Mapping: node `i` lands after the key objects of every earlier
    // dictionary and its own.
    let mut keys_before = 0_usize;
    let mut events = Vec::with_capacity(event_count);
    events.push(ConversionReportEvent::representation_change());
    for index in 0..node_count {
        let dict_keys = match native.get(PlistValueRef::from_index(index)) {
            Some(PlistValue::Dict(dict)) => dict.entries().len(),
            _ => 0,
        };
        events.push(ConversionReportEvent::value_mapped(
            PlistValueRef::from_index(index),
            index + keys_before + dict_keys,
        ));
        keys_before += dict_keys;
    }
    let document = Document {
        inner: PlistDocumentInner::Binary(formed),
    };
    Ok(ConvertedDocument {
        document,
        report: ConversionReport::new(events),
    })
}

/// Converts one `plist.binary@1` document to `plist.xml@1` (RFC 0013 §7).
///
/// The reachable value graph is validated for XML expressibility first; any
/// binary-only fact fails the whole conversion atomically. The XML parser
/// assigns target arena ordinals in close-tag (post) order, so the report
/// maps each source node to its post-order rank.
fn convert_binary_to_xml(
    native: &PlistDocument,
    limits: PlistParseLimits,
) -> Result<ConvertedDocument, ConversionFailure> {
    let graph = analyze(native, limits)?;
    let reachable_count = graph.reachable.len();
    let event_count = 1 + reachable_count;
    if event_count > limits.max_report_events {
        return Err(conversion_limit(
            "report-events",
            event_count,
            limits.max_report_events,
        ));
    }
    let bytes = serialize_xml(native, &graph)?;
    let formed = parse_xml_source(bytes, limits)?;
    if formed.status() != FormationStatus::Complete || formed.document() != Some(native) {
        return Err(reparse_failure());
    }
    let mut events = Vec::with_capacity(event_count);
    events.push(ConversionReportEvent::representation_change());
    for &index in &graph.reachable {
        events.push(ConversionReportEvent::value_mapped(
            PlistValueRef::from_index(index),
            graph.ranks[index],
        ));
    }
    let document = Document {
        inner: PlistDocumentInner::Xml(formed),
    };
    Ok(ConvertedDocument {
        document,
        report: ConversionReport::new(events),
    })
}

/// Parses one serialized binary target; a fatal target parse is a limit or
/// source failure of the conversion and carries its diagnostics.
fn parser_binary_parse(
    bytes: Vec<u8>,
    limits: PlistParseLimits,
) -> Result<PlistFormedBinary, ConversionFailure> {
    crate::parser_binary::parse_binary(Arc::from(bytes), limits)
        .map_err(|fatal| ConversionFailure::new(fatal.diagnostics().to_vec()))
}

/// Parses one serialized XML target; a fatal target parse is a limit or
/// source failure of the conversion and carries its diagnostics.
fn parse_xml_source(
    bytes: Vec<u8>,
    limits: PlistParseLimits,
) -> Result<PlistFormedXml, ConversionFailure> {
    crate::parse_xml(
        Arc::from(bytes),
        PlistEncodingSelection::ProfileDefault,
        limits,
    )
    .map_err(|fatal| ConversionFailure::new(fatal.diagnostics().to_vec()))
}

/// Validates one native document against the XML expressibility boundary
/// (RFC 0013 §7, hard gate 3) and computes the reachable-graph facts.
///
/// The traversal is iterative, counts every incoming reference of every
/// reachable node (so shared identity is detected exactly), and reports one
/// `plist.conversion.inexpressible@1` diagnostic per violating node, in
/// source arena order, bounded by the common diagnostic limit.
fn analyze(
    native: &PlistDocument,
    limits: PlistParseLimits,
) -> Result<ReachableGraph, ConversionFailure> {
    let node_count = native.node_count();
    if node_count > limits.max_conversion_nodes {
        return Err(conversion_limit(
            "conversion-nodes",
            node_count,
            limits.max_conversion_nodes,
        ));
    }
    let children: Vec<Vec<PlistValueRef>> = (0..node_count)
        .map(|index| children_of(native, PlistValueRef::from_index(index)))
        .collect();
    let mut visited = vec![false; node_count];
    let mut indegree = vec![0_usize; node_count];
    let mut postorder: Vec<usize> = Vec::with_capacity(node_count);
    let root = native.root();
    visited[root.index()] = true;
    let mut stack = vec![(root, 0_usize)];
    while let Some((node, next_child)) = stack.pop() {
        let node_children = &children[node.index()];
        if next_child < node_children.len() {
            stack.push((node, next_child + 1));
            let child = node_children[next_child];
            indegree[child.index()] += 1;
            if !visited[child.index()] {
                visited[child.index()] = true;
                stack.push((child, 0));
            }
        } else {
            postorder.push(node.index());
        }
    }
    let mut ranks = vec![usize::MAX; node_count];
    for (rank, &index) in postorder.iter().enumerate() {
        ranks[index] = rank;
    }
    let mut violations: Vec<(usize, &'static str)> = Vec::new();
    for index in 0..node_count {
        if !visited[index] {
            continue;
        }
        if indegree[index] > 1 {
            violations.push((index, "shared-identity"));
        }
        match native.get(PlistValueRef::from_index(index)) {
            Some(PlistValue::Uid(_)) => violations.push((index, "uid")),
            Some(PlistValue::Real(real)) => {
                if real.width() == RealWidth::Float32 {
                    violations.push((index, "float32-width"));
                } else if !real_expressible(*real) {
                    violations.push((index, "real-nan-payload"));
                }
            }
            Some(PlistValue::String(string)) => {
                if string.status() == PlistStringStatus::UnpairedSurrogate {
                    violations.push((index, "unpaired-surrogate"));
                } else if !is_xml_text(string.code_units()) {
                    violations.push((index, "non-xml-character"));
                }
            }
            Some(PlistValue::Date(date)) => match whole_second_date(date.seconds()) {
                Ok(_) => {}
                Err(DateRangeError::FractionalSeconds) => {
                    violations.push((index, "fractional-seconds"));
                }
                Err(DateRangeError::YearOutOfRange) => {
                    violations.push((index, "date-year-range"));
                }
            },
            Some(PlistValue::Dict(dict)) => {
                for entry in dict.entries() {
                    let key = entry.key();
                    if key.status() == PlistStringStatus::UnpairedSurrogate {
                        violations.push((index, "unpaired-surrogate"));
                    } else if !is_xml_text(key.code_units()) {
                        violations.push((index, "non-xml-character"));
                    }
                }
            }
            _ => {}
        }
    }
    if !violations.is_empty() {
        let count = violations.len().min(limits.common.max_diagnostics);
        let diagnostics = violations
            .into_iter()
            .take(count)
            .map(|(node, fact)| {
                let mut diagnostic = Diagnostic::new(
                    "plist.conversion.inexpressible@1",
                    DiagnosticCategory::Conversion,
                    DiagnosticSeverity::Error,
                    None,
                    0,
                );
                diagnostic
                    .arguments
                    .insert("fact".to_owned(), fact.to_owned());
                diagnostic
                    .arguments
                    .insert("node".to_owned(), node.to_string());
                diagnostic
            })
            .collect();
        return Err(ConversionFailure::new(diagnostics));
    }
    let reachable = (0..node_count).filter(|index| visited[*index]).collect();
    Ok(ReachableGraph {
        children,
        ranks,
        reachable,
    })
}

/// Ordered direct value children of one node (RFC 0013 §6).
fn children_of(native: &PlistDocument, node: PlistValueRef) -> Vec<PlistValueRef> {
    match native.get(node) {
        Some(PlistValue::Dict(dict)) => dict
            .entries()
            .iter()
            .map(crate::native::PlistDictEntry::value)
            .collect(),
        Some(PlistValue::Array(array)) => array.elements().to_vec(),
        _ => Vec::new(),
    }
}

/// Number of dictionary entry keys of the whole arena (one binary string
/// object per key).
fn arena_key_count(native: &PlistDocument) -> usize {
    (0..native.node_count())
        .filter_map(|index| match native.get(PlistValueRef::from_index(index)) {
            Some(PlistValue::Dict(dict)) => Some(dict.entries().len()),
            _ => None,
        })
        .sum()
}

/// Serializes one native value graph as a `plist.xml@1` source (RFC 0013 §4,
/// §7).
///
/// The caller guarantees expressibility; the emitted bytes reparse `Complete`
/// with native-model equality. The document uses the Apple header spelling,
/// four-space indentation, LF line endings, and a trailing newline.
fn serialize_xml(
    native: &PlistDocument,
    graph: &ReachableGraph,
) -> Result<Vec<u8>, ConversionFailure> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    out.push_str("<plist version=\"1.0\">\n");
    let root = native.root();
    match native.get(root) {
        Some(PlistValue::Dict(_) | PlistValue::Array(_)) => {
            let mut frames = vec![(root, 0_usize, 0_usize)];
            while let Some((node, depth, next_child)) = frames.pop() {
                let value = native.get(node).ok_or_else(internal_failure)?;
                let children = &graph.children[node.index()];
                if next_child == 0 {
                    write_indent(&mut out, depth);
                    match value {
                        PlistValue::Dict(_) => {
                            if children.is_empty() {
                                out.push_str("<dict></dict>\n");
                                continue;
                            }
                            out.push_str("<dict>\n");
                        }
                        PlistValue::Array(_) => {
                            if children.is_empty() {
                                out.push_str("<array></array>\n");
                                continue;
                            }
                            out.push_str("<array>\n");
                        }
                        _ => return Err(internal_failure()),
                    }
                }
                if next_child < children.len() {
                    frames.push((node, depth, next_child + 1));
                    let child = children[next_child];
                    if let PlistValue::Dict(dict) = value {
                        let key_text = dict.entries()[next_child]
                            .key()
                            .to_unicode()
                            .map_err(|_| internal_failure())?;
                        write_indent(&mut out, depth + 1);
                        out.push_str("<key>");
                        escape_xml_text(&mut out, &key_text);
                        out.push_str("</key>\n");
                    }
                    match native.get(child) {
                        Some(PlistValue::Dict(_) | PlistValue::Array(_)) => {
                            frames.push((child, depth + 1, 0));
                        }
                        _ => emit_scalar_xml(&mut out, native, child, depth + 1)?,
                    }
                } else {
                    write_indent(&mut out, depth);
                    match value {
                        PlistValue::Dict(_) => out.push_str("</dict>\n"),
                        PlistValue::Array(_) => out.push_str("</array>\n"),
                        _ => return Err(internal_failure()),
                    }
                }
            }
        }
        _ => emit_scalar_xml(&mut out, native, root, 0)?,
    }
    out.push_str("</plist>\n");
    Ok(out.into_bytes())
}

/// Emits one scalar value element at the given depth.
fn emit_scalar_xml(
    out: &mut String,
    native: &PlistDocument,
    node: PlistValueRef,
    depth: usize,
) -> Result<(), ConversionFailure> {
    write_indent(out, depth);
    let value = native.get(node).ok_or_else(internal_failure)?;
    match value {
        PlistValue::String(string) => {
            out.push_str("<string>");
            escape_xml_text(out, &string_to_unicode(string)?);
            out.push_str("</string>\n");
        }
        PlistValue::Integer(integer) => {
            out.push_str("<integer>");
            out.push_str(&integer.value().to_string());
            out.push_str("</integer>\n");
        }
        PlistValue::Real(real) => {
            out.push_str("<real>");
            out.push_str(&render_real(*real));
            out.push_str("</real>\n");
        }
        PlistValue::Boolean(boolean) => {
            out.push_str(if boolean.value() {
                "<true/>\n"
            } else {
                "<false/>\n"
            });
        }
        PlistValue::Date(date) => {
            out.push_str("<date>");
            let (year, month, day, hour, minute, second) =
                whole_second_date(date.seconds()).map_err(|_| internal_failure())?;
            out.push_str(&render_date(year, month, day, hour, minute, second));
            out.push_str("</date>\n");
        }
        PlistValue::Data(data) => {
            out.push_str("<data>");
            out.push_str(&encode_base64(data.bytes()));
            out.push_str("</data>\n");
        }
        _ => return Err(internal_failure()),
    }
    Ok(())
}

/// Appends one indentation level of four spaces.
fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// Escapes XML text content (RFC 0013 §4.9, §10.1): `&`, `<`, `>`, and a
/// literal CR, which XML line-end normalization would otherwise turn into LF
/// (a character reference is not normalized).
fn escape_xml_text(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(character),
        }
    }
}

/// Deterministic shortest-round-trip decimal spelling of one real (RFC 0013
/// §4.6, §10.1); the special spellings match the frozen grammar.
fn render_real(real: PlistReal) -> String {
    let value = real.as_f64();
    if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        value.to_string()
    }
}

/// Whether the exact bits of one real survive the XML spelling: Rust's
/// shortest-round-trip decimal is exact for every finite double, and the
/// special spellings resolve to the canonical NaN bit pattern only.
fn real_expressible(real: PlistReal) -> bool {
    let value = real.as_f64();
    if value.is_nan() {
        value.to_bits() == f64::NAN.to_bits()
    } else if value.is_infinite() {
        true
    } else {
        value
            .to_string()
            .parse::<f64>()
            .is_ok_and(|parsed| parsed.to_bits() == value.to_bits())
    }
}

/// Whole-second XML date spelling of one exact plist-epoch seconds value
/// (RFC 0013 §4.7).
fn render_date(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> String {
    let sign = if year < 0 { "-" } else { "" };
    format!(
        "{sign}{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        year = year.unsigned_abs()
    )
}

/// Decomposes exact plist-epoch seconds into XML calendar fields (RFC 0013
/// §4.7, §5.5). The value must be whole-second, and the day/second
/// decomposition must be exact: the Unix-seconds value must stay below `2^53`
/// and the calendar year within the grammar's 32-bit magnitude.
fn whole_second_date(seconds: f64) -> Result<(i64, i64, i64, i64, i64, i64), DateRangeError> {
    if seconds.fract() != 0.0 {
        return Err(DateRangeError::FractionalSeconds);
    }
    // The sum of an integral seconds value and the exact epoch offset is
    // exactly representable; the pre-bound keeps every later cast exact.
    let unix = seconds + PLIST_EPOCH_OFFSET_UNIX;
    if unix.abs() >= EXACT_UNIX_SECONDS_BOUND {
        return Err(DateRangeError::YearOutOfRange);
    }
    let unix_int = unix as i64;
    let days = unix_int.div_euclid(86_400);
    let seconds_of_day = unix_int.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if year.unsigned_abs() > u64::from(u32::MAX) {
        return Err(DateRangeError::YearOutOfRange);
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok((year, month, day, hour, minute, second))
}

/// Proleptic Gregorian calendar date of `days` since the Unix epoch (the
/// inverse of the parser's `days_from_civil`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// Standard-alphabet base64 with exact `=` padding (RFC 0013 §4.8, §10.1).
fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(char::from(ALPHABET[(first >> 2) as usize]));
        out.push(char::from(
            ALPHABET[((first & 0x03) << 4 | second >> 4) as usize],
        ));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[((second & 0x0F) << 2 | third >> 6) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(third & 0x3F) as usize])
        } else {
            '='
        });
    }
    out
}

/// XML 1.0 `Char` production (RFC 0013 §4.9).
const fn is_xml_char(character: char) -> bool {
    character == '\t'
        || character == '\n'
        || character == '\r'
        || (character >= '\u{20}' && character <= '\u{D7FF}')
        || (character >= '\u{E000}' && character <= '\u{FFFD}')
        || (character >= '\u{10000}' && character <= '\u{10FFFF}')
}

/// Whether every scalar of one well-formed UTF-16 sequence is an XML 1.0
/// character; an unpaired surrogate is not.
fn is_xml_text(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let scalar = if (0xD800..=0xDBFF).contains(&unit) {
            match units.get(index + 1).copied() {
                Some(low) if (0xDC00..=0xDFFF).contains(&low) => {
                    index += 2;
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00)
                }
                _ => return false,
            }
        } else {
            index += 1;
            u32::from(unit)
        };
        let Some(character) = char::from_u32(scalar) else {
            return false;
        };
        if !is_xml_char(character) {
            return false;
        }
    }
    true
}

/// Exact Unicode text of one expressible string.
fn string_to_unicode(string: &PlistString) -> Result<String, ConversionFailure> {
    string.to_unicode().map_err(|_| internal_failure())
}

/// Serializes one native value graph as a `plist.binary@1` source (RFC 0013
/// §5, §7).
///
/// Objects are written once each in source arena order — dictionary keys as
/// fresh string objects immediately before their dictionary — with minimal
/// integer widths (negatives always 8 bytes), `Float32` width preserved,
/// UID minimal widths, and offset/ref sizes chosen minimally to satisfy the
/// trailer sufficiency checks. The emitted bytes reparse `Complete` with
/// native-model equality.
fn serialize_binary(native: &PlistDocument) -> Result<Vec<u8>, ConversionFailure> {
    let node_count = native.node_count();
    let mut target_index = vec![0_usize; node_count];
    let mut keys_before = 0_usize;
    for (index, target) in target_index.iter_mut().enumerate() {
        let dict_keys = match native.get(PlistValueRef::from_index(index)) {
            Some(PlistValue::Dict(dict)) => dict.entries().len(),
            _ => 0,
        };
        *target = index + keys_before + dict_keys;
        keys_before += dict_keys;
    }
    let target_object_count = node_count + keys_before;
    // References must address every object, key objects included.
    let ref_size = ref_size_for(target_object_count);
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::with_capacity(target_object_count);
    for index in 0..node_count {
        let node = native
            .get(PlistValueRef::from_index(index))
            .ok_or_else(internal_failure)?;
        if let PlistValue::Dict(dict) = node {
            for entry in dict.entries() {
                offsets.push(out.len());
                write_string_object(&mut out, entry.key().string())?;
            }
        }
        offsets.push(out.len());
        write_binary_object(&mut out, index, node, ref_size, &target_index)?;
    }
    let offset_table_offset = out.len();
    let offset_int_size = ref_size_for(offset_table_offset);
    for &offset in &offsets {
        write_be(&mut out, offset as u64, offset_int_size)?;
    }
    out.extend_from_slice(&[0, 0, 0, 0, 0]);
    out.push(0); // sortVersion
    out.push(offset_int_size as u8);
    out.push(ref_size as u8);
    write_be(&mut out, target_object_count as u64, 8)?; // numObjects
    write_be(&mut out, target_index[native.root().index()] as u64, 8)?; // topObject
    write_be(&mut out, offset_table_offset as u64, 8)?; // offsetTableOffset
    Ok(out)
}

/// Writes one object: marker, size, payload, and references (RFC 0013 §5).
fn write_binary_object(
    out: &mut Vec<u8>,
    source_index: usize,
    node: &PlistValue,
    ref_size: usize,
    target_index: &[usize],
) -> Result<(), ConversionFailure> {
    match node {
        PlistValue::Dict(dict) => {
            let count = dict.entries().len();
            write_sized(out, 0xD0, count)?;
            let key_start = target_index[source_index] - count;
            for position in 0..count {
                write_be(out, (key_start + position) as u64, ref_size)?;
            }
            for entry in dict.entries() {
                write_be(out, target_index[entry.value().index()] as u64, ref_size)?;
            }
        }
        PlistValue::Array(array) => {
            let count = array.elements().len();
            write_sized(out, 0xA0, count)?;
            for element in array.elements() {
                write_be(out, target_index[element.index()] as u64, ref_size)?;
            }
        }
        PlistValue::String(string) => write_string_object(out, string)?,
        PlistValue::Integer(integer) => {
            let value = integer.value();
            let width = integer_width(value);
            out.push(0x10 | width.trailing_zeros() as u8);
            // The two's-complement bit pattern of the signed value, written
            // at exactly `width` bytes (RFC 0013 §5.3).
            #[allow(clippy::cast_sign_loss)]
            let bits = value as u64;
            write_be(out, bits, width)?;
        }
        PlistValue::Real(real) => match real.width() {
            RealWidth::Float64 => {
                out.push(0x23);
                write_be(out, real.bits(), 8)?;
            }
            RealWidth::Float32 => {
                out.push(0x22);
                write_be(out, real.bits(), 4)?;
            }
        },
        PlistValue::Boolean(boolean) => {
            out.push(if boolean.value() { 0x09 } else { 0x08 });
        }
        PlistValue::Date(date) => {
            out.push(0x33);
            write_be(out, date.seconds().to_bits(), 8)?;
        }
        PlistValue::Data(data) => {
            let bytes = data.bytes();
            write_sized(out, 0x40, bytes.len())?;
            out.extend_from_slice(bytes);
        }
        PlistValue::Uid(uid) => {
            let value = u64::from(uid.value());
            let width = uid_width(value);
            out.push(0x80 | (width as u8 - 1));
            write_be(out, value, width)?;
        }
    }
    Ok(())
}

/// Writes one string object: the ASCII marker when every code unit is below
/// `0x80`, else the UTF-16BE marker (RFC 0013 §5.6).
fn write_string_object(out: &mut Vec<u8>, string: &PlistString) -> Result<(), ConversionFailure> {
    let units = string.code_units();
    if units.iter().all(|unit| *unit < 0x80) {
        write_sized(out, 0x50, units.len())?;
        for unit in units {
            out.push(*unit as u8);
        }
    } else {
        write_sized(out, 0x60, units.len())?;
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    }
    Ok(())
}

/// Writes one sized marker: counts below `0x0F` fit the low nibble, while the
/// nibble `0x0F` itself is the extended-size sentinel (RFC 0013 §5.4), so
/// every count of 15 or more follows the marker with a `0x10`-style size
/// marker and count object. The parser always reads nibble `0xF` as the
/// sentinel, so the plain `marker | 0x0F` spelling would consume the first
/// payload byte as a size object.
fn write_sized(out: &mut Vec<u8>, marker: u8, count: usize) -> Result<(), ConversionFailure> {
    if count < 0x0F {
        out.push(marker | count as u8);
        return Ok(());
    }
    out.push(marker | 0x0F);
    let count = u64::try_from(count).map_err(|_| overflow_failure())?;
    let width = unsigned_width(count);
    out.push(0x10 | width.trailing_zeros() as u8);
    write_be(out, count, width)
}

/// Appends one big-endian unsigned value of exactly `width` bytes.
fn write_be(out: &mut Vec<u8>, value: u64, width: usize) -> Result<(), ConversionFailure> {
    if width > 8 {
        return Err(overflow_failure());
    }
    for shift in (0..width).rev() {
        out.push(((value >> (8 * shift)) & 0xFF) as u8);
    }
    Ok(())
}

/// Smallest width in bytes whose capacity (`2^(8 * width)`) exceeds
/// `max_index`, satisfying the trailer sufficiency checks of RFC 0013 §5.11.
fn ref_size_for(max_index: usize) -> usize {
    let mut size = 1;
    let mut capacity = 256_usize;
    while max_index >= capacity && size < 8 {
        size += 1;
        capacity = capacity.saturating_mul(256);
    }
    size
}

/// Minimal marker width for one signed 64-bit integer: negatives always use
/// the signed 8-byte form (RFC 0013 §5.3, §10.2).
fn integer_width(value: i64) -> usize {
    match u64::try_from(value) {
        Ok(value) => unsigned_width(value),
        Err(_) => 8,
    }
}

/// Minimal marker width for one unsigned count: 1, 2, 4, or 8 bytes.
fn unsigned_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFFFF_FFFF {
        4
    } else {
        8
    }
}

/// Minimal byte width of one unsigned 32-bit UID value (RFC 0013 §5.8).
fn uid_width(value: u64) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFF_FFFF {
        3
    } else {
        4
    }
}

/// Host-size overflow of the conversion layer: unreachable for bounded
/// native documents.
fn overflow_failure() -> ConversionFailure {
    conversion_failure("plist.conversion.internal@1")
}

/// Unreachable internal state of the conversion layer.
fn internal_failure() -> ConversionFailure {
    conversion_failure("plist.conversion.internal@1")
}

/// The serializer produced bytes that did not reparse `Complete` with
/// native-model equality: an internal invariant violation.
fn reparse_failure() -> ConversionFailure {
    conversion_failure("plist.conversion.reparse@1")
}

/// One conversion failure diagnostic with stable arguments.
fn conversion_failure_with_args(
    code: &'static str,
    arguments: &[(&'static str, String)],
) -> ConversionFailure {
    let mut diagnostic = Diagnostic::new(
        code,
        DiagnosticCategory::Conversion,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    for (name, value) in arguments {
        diagnostic.arguments.insert(name.to_string(), value.clone());
    }
    ConversionFailure::new(vec![diagnostic])
}

/// One conversion failure diagnostic without arguments.
fn conversion_failure(code: &'static str) -> ConversionFailure {
    conversion_failure_with_args(code, &[])
}

/// `plist.limit.<name>@1` conversion limit failure (RFC 0013 §12).
fn conversion_limit(name: &'static str, observed: usize, limit: usize) -> ConversionFailure {
    let mut diagnostic = Diagnostic::new(
        format!("plist.limit.{name}@1"),
        DiagnosticCategory::Resource,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("limit".to_owned(), limit.to_string());
    diagnostic
        .arguments
        .insert("observed".to_owned(), observed.to_string());
    ConversionFailure::new(vec![diagnostic])
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::ParseLimits;

    /// Appends a big-endian value of `width` bytes.
    fn push_be(output: &mut Vec<u8>, value: u64, width: usize) {
        for shift in (0..width).rev() {
            output.push(((value >> (8 * shift)) & 0xFF) as u8);
        }
    }

    /// Hand-built `bplist00` fixture writer: header, objects, offset table,
    /// trailer.
    struct TestBinaryBuilder {
        bytes: Vec<u8>,
        offsets: Vec<u64>,
        offset_int_size: usize,
        ref_size: usize,
    }

    impl TestBinaryBuilder {
        fn new(offset_int_size: usize, ref_size: usize) -> Self {
            Self {
                bytes: b"bplist00".to_vec(),
                offsets: Vec::new(),
                offset_int_size,
                ref_size,
            }
        }

        fn object(&mut self, object: &[u8]) -> u64 {
            let offset = u64::try_from(self.bytes.len()).unwrap();
            self.offsets.push(offset);
            self.bytes.extend_from_slice(object);
            offset
        }

        fn finish(mut self, top_object: u64) -> Vec<u8> {
            let offset_table_offset = u64::try_from(self.bytes.len()).unwrap();
            for offset in &self.offsets {
                push_be(&mut self.bytes, *offset, self.offset_int_size);
            }
            self.bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            self.bytes.push(0); // sortVersion
            self.bytes.push(self.offset_int_size as u8);
            self.bytes.push(self.ref_size as u8);
            push_be(
                &mut self.bytes,
                u64::try_from(self.offsets.len()).unwrap(),
                8,
            );
            push_be(&mut self.bytes, top_object, 8);
            push_be(&mut self.bytes, offset_table_offset, 8);
            self.bytes
        }
    }

    /// Reference bytes of the given width.
    fn reference(object_index: usize, ref_size: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_be(&mut bytes, u64::try_from(object_index).unwrap(), ref_size);
        bytes
    }

    fn parse_xml_document(source: &[u8]) -> Document {
        Document::parse(
            Arc::from(source),
            PlistProfile::XmlV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("xml plist forms")
    }

    fn parse_binary_document(bytes: Vec<u8>) -> Document {
        Document::parse(
            Arc::from(bytes),
            PlistProfile::BinaryV1,
            PlistEncodingSelection::ProfileDefault,
            PlistParseLimits::default(),
        )
        .expect("binary plist forms")
    }

    fn binary_minimal() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x08]);
        file.finish(0)
    }

    /// All-value-kinds binary fixture, every fact expressible in XML:
    /// 21 objects, root dict with 9 entries including one duplicate key.
    /// Every value object is referenced exactly once, so no shared identity
    /// exists.
    fn binary_expressible() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x11, 0x01, 0x00]); // 0: integer 256 (2-byte)
        file.object(&[0x23]); // 1: real 0.5 (8-byte)
        push_be(&mut file.bytes, 0.5_f64.to_bits(), 8);
        file.object(&[0x09]); // 2: true
        file.object(&[0x33]); // 3: date 0.0
        push_be(&mut file.bytes, 0.0_f64.to_bits(), 8);
        file.object(&[0x42, 0xDE, 0xAD]); // 4: data [DE AD]
        file.object(&[0x52, 0x68, 0x69]); // 5: "hi"
        file.object(&[0x52, 0x68, 0x78]); // 6: "hx" (array element, distinct)
        file.object(&[0xA1, 0x06]); // 7: array [6]
        file.object(&[0xD0]); // 8: empty dict
        for key in *b"krtdDsae" {
            file.object(&[0x51, key]); // 9..16: entry keys
        }
        file.object(&[0x51, b'k']); // 17: duplicate "k" key
        file.object(&[0x51, b'v']); // 18: "v"
        file.object(&[0x51, b'w']); // 19: "w" (unreachable orphan)
        let mut dict = vec![0xD9];
        for key_object in 9..=17 {
            dict.extend(reference(key_object, 1));
        }
        for value_object in [0_u8, 1, 2, 3, 4, 5, 7, 8, 18] {
            dict.extend(reference(usize::from(value_object), 1));
        }
        file.object(&dict); // 20: dict with 9 entries
        file.finish(20)
    }

    fn binary_with_uid() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x80, 0x2A]);
        file.finish(0)
    }

    fn binary_with_float32() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x22]);
        push_be(&mut file.bytes, u64::from(0.1_f32.to_bits()), 4);
        file.finish(0)
    }

    fn binary_with_unpaired_surrogate() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x62, 0x00, 0x41, 0xD8, 0x00]);
        file.finish(0)
    }

    fn binary_with_fractional_date() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x33]);
        push_be(&mut file.bytes, 0.5_f64.to_bits(), 8);
        file.finish(0)
    }

    fn binary_with_shared_identity() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'x']); // 0: "x"
        file.object(&[0xA2, 0x00, 0x00]); // 1: ["x", "x"]
        file.finish(1)
    }

    fn binary_with_non_xml_character() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x52, b'a', 0x01]); // "a" + U+0001
        file.finish(0)
    }

    fn binary_with_non_canonical_nan() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x23]);
        push_be(&mut file.bytes, 0x7FF8_0000_0000_0001, 8);
        file.finish(0)
    }

    fn binary_with_huge_date() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x33]);
        push_be(&mut file.bytes, 1e20_f64.to_bits(), 8);
        file.finish(0)
    }

    fn binary_with_cr_string() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x53, b'a', 0x0D, b'b']);
        file.finish(0)
    }

    fn binary_with_real_spellings() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x23]);
        push_be(&mut file.bytes, 1.5_f64.to_bits(), 8);
        file.object(&[0x23]);
        push_be(&mut file.bytes, (-0.5_f64).to_bits(), 8);
        file.object(&[0x23]);
        push_be(&mut file.bytes, f64::NAN.to_bits(), 8);
        file.object(&[0x23]);
        push_be(&mut file.bytes, f64::INFINITY.to_bits(), 8);
        file.object(&[0x23]);
        push_be(&mut file.bytes, f64::NEG_INFINITY.to_bits(), 8);
        file.object(&[0xA5, 0x00, 0x01, 0x02, 0x03, 0x04]);
        file.finish(5)
    }

    fn binary_with_integer_edges() -> Vec<u8> {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // -1
        file.object(&[0x10, 0x00]); // 0
        file.object(&[0x11, 0x01, 0x2C]); // 300
        file.object(&[0x12, 0x00, 0x01, 0x00, 0x00]); // 65536
        file.object(&[0x13, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // i64::MAX
        file.object(&[0x13, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // i64::MIN
        file.object(&[0xA6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        file.finish(6)
    }

    fn conversion_fact_failure(bytes: &[u8], expected: &str) {
        let source = parse_binary_document(bytes.to_vec());
        let error = source
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect_err("inexpressible conversion must fail");
        let diagnostic = error
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "plist.conversion.inexpressible@1")
            .expect("inexpressible diagnostic");
        assert_eq!(
            diagnostic.arguments.get("fact").map(String::as_str),
            Some(expected)
        );
    }

    #[test]
    fn parse_dispatches_by_profile() {
        let source: &[u8] = b"<plist version=\"1.0\"><string>x</string></plist>";
        let xml = parse_xml_document(source);
        assert_eq!(xml.representation(), PlistRepresentation::Xml);
        assert_eq!(xml.status(), FormationStatus::Complete);
        assert_eq!(xml.render(), source);

        let binary = parse_binary_document(binary_minimal());
        assert_eq!(binary.representation(), PlistRepresentation::Binary);
        assert_eq!(binary.status(), FormationStatus::Complete);
        assert_eq!(binary.render(), binary_minimal().as_slice());
    }

    #[test]
    fn accessors_delegate_per_representation() {
        let xml = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        assert_eq!(xml.profile(), ProfileId::new("plist.xml", 1));
        assert_eq!(xml.format_family(), FormatFamilyId::new("plist", 1));
        assert!(!xml.source().bytes().is_empty());
        assert!(xml.lossless_structural_index().is_some());
        assert!(xml.lossless_syntax_kinds().is_some());
        assert!(xml.binary_facts().is_none());
        assert!(xml.binary_structural_index().is_none());
        assert!(xml.document().is_some());
        assert_eq!(
            xml.lossless_syntax_kinds().unwrap().len(),
            xml.lossless_structural_index().unwrap().pieces().len()
        );

        let binary = parse_binary_document(binary_minimal());
        assert_eq!(binary.profile(), ProfileId::new("plist.binary", 1));
        assert_eq!(binary.format_family(), FormatFamilyId::new("plist", 1));
        assert!(binary.binary_facts().is_some());
        assert!(binary.binary_structural_index().is_some());
        assert!(binary.lossless_structural_index().is_none());
        assert!(binary.lossless_syntax_kinds().is_none());
        assert!(binary.document().is_some());

        // Every snapshot owns a fresh identity.
        let xml_identity = xml.snapshot_identity();
        let binary_identity = binary.snapshot_identity();
        assert_ne!(xml_identity, binary_identity);
        assert_eq!(
            xml.snapshot_identity(),
            xml_identity,
            "identity is stable per snapshot"
        );
    }

    #[test]
    fn xml_to_binary_conversion_reports_representation_change() {
        let source = b"<plist version=\"1.0\"><dict><key>k</key><integer>256</integer><key>k</key><string>v</string><key>a</key><array><string>x</string></array></dict></plist>";
        let xml = parse_xml_document(source);
        let converted = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("xml converts to binary");
        let report = converted.report();
        assert!(report.representation_changed());
        assert_eq!(
            report.events()[0].kind(),
            ConversionEventKind::RepresentationChange
        );
        assert_eq!(report.events()[0].source(), None);
        assert_eq!(report.events()[0].target(), None);
        // Arena: int 256, "v", "x", array, dict(3 entries) — 5 nodes; the
        // dict's 3 key objects shift it to target ordinal 7.
        assert_eq!(report.events().len(), 6);
        let targets = report.events()[1..]
            .iter()
            .map(|event| {
                assert_eq!(event.kind(), ConversionEventKind::ValueMapped);
                event.target().expect("mapped target")
            })
            .collect::<Vec<_>>();
        assert_eq!(targets, vec![0, 1, 2, 3, 7]);

        let target = converted.document();
        assert_eq!(target.representation(), PlistRepresentation::Binary);
        assert_eq!(target.status(), FormationStatus::Complete);
        assert_eq!(target.document(), xml.document());
    }

    #[test]
    fn binary_to_xml_conversion_reports_representation_change() {
        let binary = parse_binary_document(binary_expressible());
        let converted = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("binary converts to xml");
        let report = converted.report();
        assert!(report.representation_changed());
        assert_eq!(
            report.events()[0].kind(),
            ConversionEventKind::RepresentationChange
        );
        // 11 reachable nodes: 9 entry values, the array element, and the root
        // dict; the root is the last node of the target arena (post-order).
        assert_eq!(report.events().len(), 12);
        let last = report.events().last().expect("root event");
        assert_eq!(last.kind(), ConversionEventKind::ValueMapped);
        assert_eq!(last.source().expect("source").index(), 20);
        assert_eq!(last.target(), Some(10));

        let target = converted.document();
        assert_eq!(target.representation(), PlistRepresentation::Xml);
        assert_eq!(target.status(), FormationStatus::Complete);
        assert_eq!(target.document(), binary.document());
        assert!(target.lossless_structural_index().is_some());
        assert!(target.binary_facts().is_none());
    }

    #[test]
    fn xml_binary_xml_round_trip_keeps_native_model() {
        let source = b"<plist version=\"1.0\"><dict><key>k</key><integer>256</integer><key>k</key><string>v</string><key>a</key><array><string>x</string><string>x</string></array><key>D</key><data>AAAA</data></dict></plist>";
        let xml = parse_xml_document(source);
        let binary = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("xml to binary")
            .into_document();
        let back = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("binary to xml")
            .into_document();
        assert_eq!(back.document(), xml.document());
    }

    #[test]
    fn xml_to_binary_conversion_writes_the_count_fifteen_key_extended() {
        // Low nibble `0x0F` is the extended-size sentinel (RFC 0013 §5.4): a
        // 15-character key must convert with the sentinel nibble plus the
        // `0x10`-style count object (`0x10 0x0F`), never the plain `0x5F`
        // marker that would consume the first key byte as a size object and
        // fail the conversion reparse.
        let source = b"<plist version=\"1.0\"><dict><key>123456789012345</key><string>v</string></dict></plist>";
        let xml = parse_xml_document(source);
        let converted = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("the count-15 key converts to binary");
        let target = converted.document();
        assert_eq!(target.status(), FormationStatus::Complete);
        assert_eq!(target.document(), xml.document());
        assert!(
            target
                .render()
                .windows(3)
                .any(|window| window == [0x5F, 0x10, 0x0F]),
            "the 15-char key uses the extended-size spelling: {:02x?}",
            target.render()
        );
    }

    #[test]
    fn binary_xml_binary_round_trip_keeps_native_model() {
        let binary = parse_binary_document(binary_expressible());
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("binary to xml")
            .into_document();
        let back = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("xml to binary")
            .into_document();
        assert_eq!(back.document(), binary.document());
        // The XML conversion drops the unreachable orphan (object 18), so the
        // target arena differs while the reachable native model is equal.
        assert_eq!(back.document().unwrap(), binary.document().unwrap());
        assert!(xml.document().is_some());
    }

    #[test]
    fn duplicate_keys_and_equal_scalars_round_trip() {
        // Two distinct equal scalar objects are expressible (no shared
        // identity); duplicate keys stay ordered native facts.
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x51, b'a']); // 0: "a"
        file.object(&[0x51, b'a']); // 1: "a"
        file.object(&[0xA2, 0x00, 0x01]); // 2: ["a", "a"]
        let bytes = file.finish(2);
        let binary = parse_binary_document(bytes);
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("expressible")
            .into_document();
        assert_eq!(xml.document(), binary.document());
    }

    #[test]
    fn inexpressible_facts_fail_atomically() {
        conversion_fact_failure(&binary_with_uid(), "uid");
        conversion_fact_failure(&binary_with_float32(), "float32-width");
        conversion_fact_failure(&binary_with_unpaired_surrogate(), "unpaired-surrogate");
        conversion_fact_failure(&binary_with_fractional_date(), "fractional-seconds");
        conversion_fact_failure(&binary_with_shared_identity(), "shared-identity");
        conversion_fact_failure(&binary_with_non_xml_character(), "non-xml-character");
        conversion_fact_failure(&binary_with_non_canonical_nan(), "real-nan-payload");
        conversion_fact_failure(&binary_with_huge_date(), "date-year-range");
    }

    #[test]
    fn inexpressible_failure_reports_the_offending_node() {
        let source = parse_binary_document(binary_with_uid());
        let error = source
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect_err("uid blocks xml");
        let diagnostic = error
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "plist.conversion.inexpressible@1")
            .expect("diagnostic");
        assert_eq!(
            diagnostic.arguments.get("node").map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn recovered_documents_cannot_be_converted() {
        let recovered_with_document =
            parse_xml_document(b"<plist version=\"2.0\"><string>x</string></plist>");
        assert_eq!(recovered_with_document.status(), FormationStatus::Recovered);
        assert!(recovered_with_document.document().is_some());
        let error = recovered_with_document
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect_err("recovered cannot convert");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.conversion.formation@1")
        );

        let without_document =
            parse_xml_document(b"<plist version=\"1.0\"><date>BAD</date></plist>");
        assert!(without_document.document().is_none());
        let error = without_document
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect_err("no native document cannot convert");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.conversion.formation@1")
        );
    }

    #[test]
    fn same_representation_target_is_not_a_conversion() {
        let xml = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        let error = xml
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect_err("same representation rejected");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.conversion.same-representation@1")
        );
        let binary = parse_binary_document(binary_minimal());
        let error = binary
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect_err("same representation rejected");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.conversion.same-representation@1")
        );
    }

    #[test]
    fn conversion_node_and_report_event_limits_are_fatal() {
        let source =
            b"<plist version=\"1.0\"><array><string>a</string><string>b</string></array></plist>";
        let xml = parse_xml_document(source);
        let limits = PlistParseLimits {
            max_conversion_nodes: 2,
            ..PlistParseLimits::default()
        };
        let error = xml
            .convert_to(PlistProfile::BinaryV1, limits)
            .expect_err("node limit");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.conversion-nodes@1")
        );

        let limits = PlistParseLimits {
            max_report_events: 2,
            ..PlistParseLimits::default()
        };
        let error = xml
            .convert_to(PlistProfile::BinaryV1, limits)
            .expect_err("report event limit");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.report-events@1")
        );
    }

    #[test]
    fn conversion_target_formation_limits_apply() {
        // The source (35 bytes) fits the source bound; the emitted binary
        // (42 bytes minimum) does not.
        let xml = parse_xml_document(b"<plist version=\"1.0\"><dict/></plist>");
        let limits = PlistParseLimits {
            common: ParseLimits {
                max_source_bytes: 40,
                ..ParseLimits::default()
            },
            ..PlistParseLimits::default()
        };
        let error = xml
            .convert_to(PlistProfile::BinaryV1, limits)
            .expect_err("target source bound");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "core.source.resource-limit@1")
        );

        // 4 native nodes plus 3 key objects exceed the target object count.
        let xml = parse_xml_document(
            b"<plist version=\"1.0\"><dict><key>a</key><string>x</string><key>b</key><string>y</string><key>c</key><string>z</string></dict></plist>",
        );
        let limits = PlistParseLimits {
            max_object_count: 6,
            ..PlistParseLimits::default()
        };
        let error = xml
            .convert_to(PlistProfile::BinaryV1, limits)
            .expect_err("target object count");
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "plist.limit.object-count@1")
        );
    }

    #[test]
    fn epoch_offset_round_trips_between_representations() {
        // 1970-01-01T00:00:00Z is exactly PLIST_EPOCH_OFFSET_UNIX seconds
        // before the plist epoch (RFC 0013 §5.5), so its plist-epoch seconds
        // value is the negated offset.
        let source = b"<plist version=\"1.0\"><date>1970-01-01T00:00:00Z</date></plist>";
        let xml = parse_xml_document(source);
        let seconds = xml
            .document()
            .expect("document")
            .root_value()
            .as_date()
            .expect("date")
            .seconds();
        assert_eq!(seconds.to_bits(), (-PLIST_EPOCH_OFFSET_UNIX).to_bits());
        let binary = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts")
            .into_document();
        let seconds = binary
            .document()
            .expect("document")
            .root_value()
            .as_date()
            .expect("date")
            .seconds();
        assert_eq!(seconds.to_bits(), (-PLIST_EPOCH_OFFSET_UNIX).to_bits());
        let back = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts")
            .into_document();
        assert_eq!(back.document(), xml.document());
    }

    #[test]
    fn date_spellings_round_trip_through_conversion() {
        let cases: &[(f64, &str)] = &[
            (0.0, "2001-01-01T00:00:00Z"),
            (-978_307_200.0, "1970-01-01T00:00:00Z"),
            (
                -719_893.0 * 86_400.0 - 978_307_200.0,
                "-0001-01-01T00:00:00Z",
            ),
            (1_577_836_800.0 - 978_307_200.0, "2020-01-01T00:00:00Z"),
            (
                1_582_934_400.0 - 978_307_200.0 + 45_296.0,
                "2020-02-29T12:34:56Z",
            ),
        ];
        for (seconds, spelling) in cases {
            let mut file = TestBinaryBuilder::new(1, 1);
            file.object(&[0x33]);
            push_be(&mut file.bytes, seconds.to_bits(), 8);
            let bytes = file.finish(0);
            let binary = parse_binary_document(bytes);
            let xml = binary
                .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
                .expect("converts");
            let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
            assert!(
                rendered.contains(spelling),
                "spelling {spelling} not in {rendered}"
            );
            let back = xml
                .document()
                .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
                .expect("converts back");
            assert_eq!(back.document().document(), binary.document());
        }
    }

    #[test]
    fn real_spellings_round_trip_through_conversion() {
        let binary = parse_binary_document(binary_with_real_spellings());
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        for spelling in [
            "<real>1.5</real>",
            "<real>-0.5</real>",
            "<real>nan</real>",
            "<real>inf</real>",
            "<real>-inf</real>",
        ] {
            assert!(rendered.contains(spelling), "{spelling} not in {rendered}");
        }
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());
    }

    #[test]
    fn integer_edges_round_trip_through_conversion() {
        let binary = parse_binary_document(binary_with_integer_edges());
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        for spelling in [
            "<integer>-1</integer>",
            "<integer>0</integer>",
            "<integer>300</integer>",
            "<integer>65536</integer>",
            "<integer>9223372036854775807</integer>",
            "<integer>-9223372036854775808</integer>",
        ] {
            assert!(rendered.contains(spelling), "{spelling} not in {rendered}");
        }
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());
    }

    #[test]
    fn cr_strings_use_character_references_and_round_trip() {
        let binary = parse_binary_document(binary_with_cr_string());
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(
            rendered.contains("<string>a&#13;b</string>"),
            "CR must escape as a character reference: {rendered}"
        );
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());

        // The XML side of the same fact: a character reference stays CR in
        // the native text and survives the binary conversion.
        let xml_source =
            parse_xml_document(b"<plist version=\"1.0\"><string>a&#13;b</string></plist>");
        let binary_target = xml_source
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts");
        assert_eq!(binary_target.document().document(), xml_source.document());
    }

    #[test]
    fn base64_padding_and_bytes_round_trip() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x44, 0x00, 0x01, 0xFE, 0xFF]);
        let bytes = file.finish(0);
        let binary = parse_binary_document(bytes);
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(rendered.contains("<data>AAH+/w==</data>"), "{rendered}");
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());

        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x41, 0x61]); // 1 byte: needs `==` padding
        let bytes = file.finish(0);
        let binary = parse_binary_document(bytes);
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(rendered.contains("<data>YQ==</data>"), "{rendered}");
    }

    #[test]
    fn empty_values_round_trip() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0xD0]); // empty dict
        file.object(&[0xA0]); // empty array
        file.object(&[0x50]); // empty string
        file.object(&[0x40]); // empty data
        file.object(&[0xA4, 0x00, 0x01, 0x02, 0x03]);
        let bytes = file.finish(4);
        let binary = parse_binary_document(bytes);
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(rendered.contains("<dict></dict>"), "{rendered}");
        assert!(rendered.contains("<array></array>"), "{rendered}");
        assert!(rendered.contains("<string></string>"), "{rendered}");
        assert!(rendered.contains("<data></data>"), "{rendered}");
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());
    }

    #[test]
    fn string_escaping_round_trips() {
        let mut file = TestBinaryBuilder::new(1, 1);
        file.object(&[0x55, b'a', b'&', b'<', b'>', b'b']);
        let bytes = file.finish(0);
        let binary = parse_binary_document(bytes);
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(
            rendered.contains("<string>a&amp;&lt;&gt;b</string>"),
            "{rendered}"
        );
        let back = xml
            .document()
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts back");
        assert_eq!(back.document().document(), binary.document());
    }

    #[test]
    fn xml_with_utf16_source_converts_to_binary() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist version=\"1.0\"><string>aé😀</string></plist>";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let xml = Document::parse(
            Arc::from(bytes),
            PlistProfile::XmlV1,
            PlistEncodingSelection::Explicit(consema_document::SourceEncoding::Utf16Le),
            PlistParseLimits::default(),
        )
        .expect("utf-16 xml forms");
        let binary = xml
            .convert_to(PlistProfile::BinaryV1, PlistParseLimits::default())
            .expect("converts");
        assert_eq!(binary.document().document(), xml.document());
    }

    #[test]
    fn emitted_xml_has_the_apple_header_spelling() {
        let binary = parse_binary_document(binary_expressible());
        let xml = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let rendered = std::str::from_utf8(xml.document().render()).expect("utf-8");
        assert!(
            rendered.starts_with(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n"
            ),
            "{rendered}"
        );
        assert!(rendered.ends_with("</plist>\n"), "{rendered}");
        assert!(rendered.contains("    <key>k</key>\n    <integer>256</integer>\n"));
    }

    #[test]
    fn civil_date_round_trips_against_the_parser_calendar() {
        // Known whole-second dates convert exactly.
        let cases: &[(f64, i64, i64, &str)] = &[
            (0.0, 11_323, 0, "2001-01-01T00:00:00Z"),
            (-978_307_200.0, 0, 0, "1970-01-01T00:00:00Z"),
            (
                -719_893.0 * 86_400.0 - 978_307_200.0,
                -719_893,
                0,
                "-0001-01-01T00:00:00Z",
            ),
            (
                -719_528.0 * 86_400.0 - 978_307_200.0,
                -719_528,
                0,
                "0000-01-01T00:00:00Z",
            ),
            (
                18_321.0 * 86_400.0 - 978_307_200.0 + 45_296.0,
                18_321,
                45_296,
                "2020-02-29T12:34:56Z",
            ),
        ];
        for (seconds, days, seconds_of_day, spelling) in cases {
            let (year, month, day, hour, minute, second) =
                whole_second_date(*seconds).expect("whole second");
            assert_eq!(civil_from_days(*days), (year, month, day));
            assert_eq!(*seconds_of_day, hour * 3_600 + minute * 60 + second);
            assert_eq!(
                render_date(year, month, day, hour, minute, second),
                *spelling
            );
            // The decomposition is the exact inverse of the seconds value.
            let unix = *seconds + PLIST_EPOCH_OFFSET_UNIX;
            let unix_int = unix as i64;
            assert_eq!(
                (unix_int.div_euclid(86_400), unix_int.rem_euclid(86_400)),
                (*days, *seconds_of_day)
            );
        }
        // Dense round trip hour by hour across several years, spanning a leap
        // day and the epoch.
        let start = -978_307_200.0 - 100.0 * 86_400.0;
        let mut seconds = start;
        for _ in 0..10_000 {
            let (year, month, day, hour, minute, second) =
                whole_second_date(seconds).expect("whole second");
            let unix = seconds + PLIST_EPOCH_OFFSET_UNIX;
            let unix_int = unix as i64;
            let days = unix_int.div_euclid(86_400);
            let seconds_of_day = unix_int.rem_euclid(86_400);
            assert_eq!(civil_from_days(days), (year, month, day));
            assert_eq!(seconds_of_day, hour * 3_600 + minute * 60 + second);
            seconds += 3_600.0;
        }
    }

    #[test]
    fn report_events_are_deterministic_and_complete() {
        let binary = parse_binary_document(binary_expressible());
        let converted = binary
            .convert_to(PlistProfile::XmlV1, PlistParseLimits::default())
            .expect("converts");
        let report = converted.report();
        let sources = report.events()[1..]
            .iter()
            .map(|event| event.source().expect("source").index())
            .collect::<Vec<_>>();
        let mut expected = sources.clone();
        expected.sort_unstable();
        assert_eq!(
            sources, expected,
            "value-mapped events are in source arena order"
        );
        // Every reachable source node maps to a distinct target ordinal.
        let mut targets = report.events()[1..]
            .iter()
            .map(|event| event.target().expect("target"))
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        assert_eq!(targets.len(), sources.len(), "mappings are injective");
    }
}
