//! Lossless `xml.1.0-safe@1` documents under the RFC 0012 boundary.
//!
//! The Profile is selected before formation. A `.xml` extension does not
//! authorize external I/O, schema lookup, DTD validation, or application
//! mapping. Formation consumes one complete document entity supplied as
//! bytes and never opens another entity, file, URI, network connection,
//! registry, classpath, or catalog.

use consema_document::{FatalFormationFailure, ParseLimits, ProfileId, SourceEncoding};
use std::sync::Arc;

mod document;
mod edit;
mod entity;
mod materialization;
mod namespace;
mod operation_registry;
mod parser;
mod projection;
mod query;

pub use document::{
    Document, EntityDeclarationData, QNameFacts, ReferenceFragment, XmlAttributeData, XmlCdataData,
    XmlCommentData, XmlContent, XmlContentItem, XmlDeclarationData, XmlDoctypeData, XmlDocument,
    XmlElement, XmlElementData, XmlErrorRegionData, XmlNamespaceBindingData, XmlPiData,
    XmlPrologItem, XmlSyntaxKind, XmlTextData, text_semantic,
};
pub use edit::{
    AttributePlacement, ContentPlacement, EditCommit, EditFailure, EditOperation, EditTransaction,
    EditTransactionBuilder, NameFacts,
};
pub use entity::{
    EntityExpansionLimits, EntityExpansionState, ExpansionBreach, PREDEFINED_ENTITIES,
    PredefinedEntity, ReplacementError, validate_replacement_text,
};
pub use materialization::materialize;
pub use namespace::{
    Binding, ExpandedName, NamespaceError, NamespaceScope, QName, XML_NAMESPACE_URI,
    XMLNS_NAMESPACE_URI,
};
pub use operation_registry::format_operation_registry;
pub use projection::{
    AttributePolicy, CollisionPolicy, CompleteProjection, ExpandedNameKeyPolicy,
    FailedProjectionAttempt, Fidelity, ProjectedLocation, ProjectionEvent, ProjectionEventKind,
    ProjectionFailure, ProjectionLimits, ProjectionReport, ProjectionRequest, ProjectionResult,
    ProjectionTarget, ProvenanceEntry, ProvenanceMap, ProvenanceRelation, RepeatedChildPolicy,
    SourceOrigin, TextContentInclude, TextKeyPolicy,
};
pub use query::{
    XmlMatch, XmlReferenceKind, XmlSyntaxMatch, execute_xml_query, execute_xml_query_cursor,
    execute_xml_syntax_query, execute_xml_syntax_query_cursor,
};

/// Frozen XML formation profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum XmlProfile {
    /// Namespace-aware, side-effect-free XML 1.0 with the safe DTD subset.
    SafeV1,
}

impl XmlProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        ProfileId::new("xml.1.0-safe", 1)
    }
}

/// Explicit document-entity encoding selection.
///
/// No-BOM source defaults to UTF-8. An explicit caller choice is evidence,
/// not permission to contradict a BOM or a declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmlEncodingSelection {
    /// Apply only the frozen profile default and BOM rules.
    ProfileDefault,
    /// Use one caller-selected document-entity encoding.
    Explicit(SourceEncoding),
}

/// XML-specific formation, entity, and recovery limits (RFC 0012 §12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmlParseLimits {
    /// Common source, node, piece, nesting, and diagnostic limits.
    pub common: ParseLimits,
    /// Maximum decoded UTF-8 bytes.
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalars and coordinate steps.
    pub max_decoded_scalars: usize,
    /// Maximum elements in the native tree.
    pub max_element_count: usize,
    /// Maximum attributes per element.
    pub max_attribute_count: usize,
    /// Maximum namespace declarations per element.
    pub max_namespace_declaration_count: usize,
    /// Maximum child content items per element.
    pub max_mixed_content_items: usize,
    /// Maximum QName bytes (prefix, local, and full spelling).
    pub max_qname_length: usize,
    /// Maximum namespace URI bytes.
    pub max_namespace_uri_length: usize,
    /// Maximum attribute-value decoded bytes.
    pub max_attribute_value_length: usize,
    /// Maximum comment decoded bytes.
    pub max_comment_length: usize,
    /// Maximum processing-instruction content decoded bytes.
    pub max_pi_length: usize,
    /// Maximum CDATA content decoded bytes.
    pub max_cdata_length: usize,
    /// Maximum text content decoded bytes.
    pub max_text_length: usize,
    /// Maximum DTD subset raw bytes.
    pub max_dtd_bytes: usize,
    /// Maximum entity declarations.
    pub max_entity_declarations: usize,
    /// Maximum entity references.
    pub max_entity_references: usize,
    /// Maximum reference expansion depth.
    pub max_entity_expansion_depth: usize,
    /// Maximum expanded bytes across the whole document.
    pub max_expanded_entity_bytes: usize,
    /// Maximum expanded scalars across the whole document.
    pub max_expanded_entity_scalars: usize,
    /// Maximum expanded/declared byte amplification ratio.
    pub max_entity_amplification_ratio: u64,
    /// Maximum recovery error regions.
    pub max_recovery_regions: usize,
}

impl Default for XmlParseLimits {
    fn default() -> Self {
        Self {
            common: ParseLimits::default(),
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
            max_element_count: 1_000_000,
            max_attribute_count: 100_000,
            max_namespace_declaration_count: 100_000,
            max_mixed_content_items: 2_000_000,
            max_qname_length: 4 * 1024,
            max_namespace_uri_length: 8 * 1024,
            max_attribute_value_length: 4 * 1024 * 1024,
            max_comment_length: 4 * 1024 * 1024,
            max_pi_length: 4 * 1024 * 1024,
            max_cdata_length: 4 * 1024 * 1024,
            max_text_length: 4 * 1024 * 1024,
            max_dtd_bytes: 4 * 1024 * 1024,
            max_entity_declarations: 10_000,
            max_entity_references: 1_000_000,
            max_entity_expansion_depth: 100,
            max_expanded_entity_bytes: 32 * 1024 * 1024,
            max_expanded_entity_scalars: 16 * 1024 * 1024,
            max_entity_amplification_ratio: 1_000,
            max_recovery_regions: 100_000,
        }
    }
}

impl XmlParseLimits {
    /// Entity expansion limits derived from these parse limits.
    #[must_use]
    pub fn entity_limits(self) -> EntityExpansionLimits {
        EntityExpansionLimits {
            max_declarations: self.max_entity_declarations,
            max_references: self.max_entity_references,
            max_expansion_depth: self.max_entity_expansion_depth,
            max_expanded_bytes: self.max_expanded_entity_bytes,
            max_expanded_scalars: self.max_expanded_entity_scalars,
            max_amplification_ratio: self.max_entity_amplification_ratio,
        }
    }
}

/// Forms one `xml.1.0-safe@1` document from a complete document entity.
///
/// The Profile is selected before formation and never by extension. The
/// parser consumes the supplied bytes and opens no other entity, file, URI,
/// network connection, registry, classpath, or catalog.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: XmlProfile,
    selection: XmlEncodingSelection,
    limits: XmlParseLimits,
) -> Result<Document, FatalFormationFailure> {
    parser::parse(source.into(), profile, selection, limits)
}
