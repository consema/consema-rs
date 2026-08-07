//! XML projection targets and explicit mapping policies (RFC 0012 §9).
//!
//! The exact default target is the versioned `xml.element-tree@1` record.
//! There is no `xml-to-json-default`, automatic attribute `@` prefix,
//! automatic text `#text` key, singular/plural heuristic, namespace
//! stripping, or child grouping. Any authorized transformation emits report
//! events and provenance.

use crate::document::{
    Document, ReferenceFragment, XmlContent, XmlDeclarationData, XmlElementData, text_semantic,
};
use crate::namespace::ExpandedName;
use consema_core::{
    AssociationLocation, AssociationRole, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
    EntryMappingBuilder, ObjectBuilder, PortableValue, StableFailure, ValuePath, ValuePathSegment,
};
use consema_document::{FormationStatus, NodeRef, SnapshotIdentity, Span};
use std::collections::HashMap;

/// Versioned XML projection target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Exact `xml.element-tree@1` record projection.
    ElementTreeV1,
    /// Always-transformed descendant text content.
    TextContentV1,
    /// Explicit-policy entry mapping of a selected subtree.
    SimpleEntryMappingV1,
}

/// Descendant text inclusion for `TextContentV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TextContentInclude {
    /// Include descendant text and CDATA occurrences.
    TextAndCdata,
    /// Include descendant text only; CDATA is reported as discarded.
    TextOnly,
}

/// Attribute handling for `SimpleEntryMappingV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AttributePolicy {
    /// Reject the projection when any attribute is present.
    RejectAttributes,
    /// Ignore every attribute and report each as discarded.
    IgnoreAttributes,
    /// Prefix attribute keys with `@`.
    PrefixAttributeKeys,
}

/// Text child handling for `SimpleEntryMappingV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TextKeyPolicy {
    /// Reject the projection when any non-whitespace text is present.
    RejectText,
    /// Discard text and report it as discarded.
    IgnoreText,
}

/// Repeated expanded-child-name handling for `SimpleEntryMappingV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepeatedChildPolicy {
    /// Reject every repeated expanded child name.
    Reject,
    /// Retain the first occurrence in document order.
    First,
    /// Retain the last occurrence.
    Last,
}

/// Entry-key spelling for `SimpleEntryMappingV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpandedNameKeyPolicy {
    /// Key is the local name; namespace collisions must be resolved by
    /// another policy or the projection fails.
    LocalOnly,
    /// Key is the lexical `prefix:local` spelling.
    PrefixedSpelling,
    /// Key is the `{uri}local` spelling; absent namespace is `{}local`.
    UriBracketed,
}

/// Collision resolution direction shared by both entry policies.
#[derive(Clone, Copy)]
enum KeepPolicy {
    Reject,
    First,
    Last,
}

/// Ordered mapping entries with their expanded-name identities.
///
/// The `seen` map keeps the expanded name of the retained occurrence so the
/// projection can distinguish a repeated expanded name (governed by the
/// repeated-child policy) from a key-spelling collision (governed by the
/// collision policy).
struct EntrySet {
    ordered: Vec<(String, PortableValue)>,
    seen: HashMap<String, (usize, Option<ExpandedName>)>,
}

impl EntrySet {
    fn new() -> Self {
        Self {
            ordered: Vec::new(),
            seen: HashMap::new(),
        }
    }

    fn into_ordered(self) -> Vec<(String, PortableValue)> {
        self.ordered
    }
}

/// Explicit mapping behavior for `SimpleEntryMappingV1`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CollisionPolicy {
    /// Reject every collision.
    Reject,
    /// Retain the first occurrence in document order.
    First,
    /// Retain the last occurrence.
    Last,
}

/// Explicit XML projection request; every policy is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    subtree: Option<u64>,
    include: TextContentInclude,
    attributes: AttributePolicy,
    text_key: TextKeyPolicy,
    repeated_child: RepeatedChildPolicy,
    key_spelling: ExpandedNameKeyPolicy,
    collision: CollisionPolicy,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Exact `xml.element-tree@1` record request for the document root.
    #[must_use]
    pub fn element_tree() -> Self {
        Self {
            target: ProjectionTarget::ElementTreeV1,
            subtree: None,
            include: TextContentInclude::TextAndCdata,
            attributes: AttributePolicy::RejectAttributes,
            text_key: TextKeyPolicy::RejectText,
            repeated_child: RepeatedChildPolicy::Reject,
            key_spelling: ExpandedNameKeyPolicy::LocalOnly,
            collision: CollisionPolicy::Reject,
            limits: ProjectionLimits::default(),
        }
    }

    /// Explicit `SimpleEntryMappingV1` request over one subtree.
    #[must_use]
    pub fn simple_entry_mapping(
        subtree: NodeRef,
        attributes: AttributePolicy,
        text_key: TextKeyPolicy,
        repeated_child: RepeatedChildPolicy,
        key_spelling: ExpandedNameKeyPolicy,
        collision: CollisionPolicy,
    ) -> Self {
        Self {
            target: ProjectionTarget::SimpleEntryMappingV1,
            subtree: Some(subtree.index()),
            include: TextContentInclude::TextAndCdata,
            attributes,
            text_key,
            repeated_child,
            key_spelling,
            collision,
            limits: ProjectionLimits::default(),
        }
    }

    /// Explicit `TextContentV1` request over one subtree.
    #[must_use]
    pub fn text_content(subtree: NodeRef, include: TextContentInclude) -> Self {
        Self {
            target: ProjectionTarget::TextContentV1,
            subtree: Some(subtree.index()),
            include,
            attributes: AttributePolicy::RejectAttributes,
            text_key: TextKeyPolicy::RejectText,
            repeated_child: RepeatedChildPolicy::Reject,
            key_spelling: ExpandedNameKeyPolicy::LocalOnly,
            collision: CollisionPolicy::Reject,
            limits: ProjectionLimits::default(),
        }
    }

    /// Projection target.
    #[must_use]
    pub const fn target(&self) -> ProjectionTarget {
        self.target
    }

    /// Selected subtree identity, when the request targets a subtree.
    #[must_use]
    pub const fn subtree(&self) -> Option<u64> {
        self.subtree
    }

    /// Resource limits.
    #[must_use]
    pub const fn limits(&self) -> ProjectionLimits {
        self.limits
    }
}

/// XML projection resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum inspected source nodes.
    pub max_source_nodes: usize,
    /// Maximum produced PortableValue nodes.
    pub max_value_nodes: usize,
    /// Maximum report events.
    pub max_report_entries: usize,
    /// Maximum projected locations plus source origins.
    pub max_provenance_units: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_source_nodes: 2_000_000,
            max_value_nodes: 2_000_000,
            max_report_entries: 100_000,
            max_provenance_units: 4_000_000,
        }
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target directly represents every native association.
    Exact,
    /// An explicit reported policy transformed associations.
    Transformed,
    /// Source facts were irreversibly omitted without a retained source relation.
    Lossy,
}

/// Projected value or association location.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ProjectedLocation {
    /// Portable value location.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// Source-to-projection relation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProvenanceRelation {
    /// Direct native semantic origin.
    Direct,
    /// Container value derived from a source record.
    Derived,
    /// Discarded occurrence related to the retained projected occurrence.
    Collapsed,
    /// Semantic content derived from reference resolution.
    ReferenceDerived,
}

/// One exact source origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOrigin {
    /// Source document snapshot.
    pub snapshot: SnapshotIdentity,
    /// Exact structural identity.
    pub node: NodeRef,
    /// Exact raw source range.
    pub span: Span,
    /// Source relation.
    pub relation: ProvenanceRelation,
}

/// One many-valued provenance entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected value or association.
    pub projected: ProjectedLocation,
    /// Ordered source origins.
    pub origins: Vec<SourceOrigin>,
}

/// Immutable many-valued provenance mapping.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMap {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceMap {
    /// Deterministically ordered projected locations and origins.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }

    fn push(
        &mut self,
        entry: ProvenanceEntry,
        limits: ProjectionLimits,
    ) -> Result<(), ProjectionFailure> {
        let observed = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_provenance_units"))?;
        if observed > limits.max_provenance_units {
            return Err(ProjectionFailure::ResourceLimit("max_provenance_units"));
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// Projection report category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionEventKind {
    /// Element discarded by policy.
    ElementDiscarded,
    /// Attribute discarded by policy.
    AttributeDiscarded,
    /// Text discarded by policy.
    TextDiscarded,
    /// CDATA discarded by policy.
    CdataDiscarded,
    /// Comment discarded by policy.
    CommentDiscarded,
    /// Processing instruction discarded by policy.
    ProcessingInstructionDiscarded,
    /// Reference distinction collapsed into resolved text.
    ReferenceCollapsed,
    /// Repeated expanded child name collapsed under policy.
    ChildCollapsed,
    /// Expanded-name namespace difference collapsed by key spelling.
    NamespaceCollapsed,
}

/// One explicit transformation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event kind.
    pub kind: ProjectionEventKind,
    /// Discarded source occurrence.
    pub discarded: NodeRef,
    /// Fidelity impact.
    pub impact: Fidelity,
}

/// Complete ordered projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in deterministic document order.
    #[must_use]
    pub fn events(&self) -> &[ProjectionEvent] {
        &self.events
    }

    fn push(
        &mut self,
        event: ProjectionEvent,
        limits: ProjectionLimits,
    ) -> Result<(), ProjectionFailure> {
        let observed = self
            .events
            .len()
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_report_entries"))?;
        if observed > limits.max_report_entries {
            return Err(ProjectionFailure::ResourceLimit("max_report_entries"));
        }
        self.events.push(event);
        Ok(())
    }
}

/// Complete successful projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable projected value.
    pub value: PortableValue,
    /// Worst operation fidelity.
    pub fidelity: Fidelity,
    /// Structured transformation report.
    pub report: ProjectionReport,
    /// Value and association provenance.
    pub provenance: ProvenanceMap,
}

/// Failed projection attempt without a partial value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedProjectionAttempt {
    /// Stable ordered diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Empty report: failed projections publish no partial transformation result.
    pub report: ProjectionReport,
}

/// Projection completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionResult {
    /// Complete success.
    Complete(CompleteProjection),
    /// Failure with no value or provenance map.
    Failed(FailedProjectionAttempt),
}

/// Stable XML projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// Recovered documents cannot publish partial semantic values.
    RecoveredDocument,
    /// The selected subtree is not an element.
    SubtreeNotElement,
    /// Simple-entry-mapping admission precondition failed.
    MappingAdmission(&'static str),
    /// Object collision under `Reject`.
    Collision {
        /// Colliding child element.
        child: NodeRef,
        /// Entry key that collided.
        key: String,
    },
    /// Declared projection resource limit was reached.
    ResourceLimit(&'static str),
    /// PortableValue construction invariant failed.
    CoreInvariant,
}

impl consema_core::StableFailure for ProjectionFailure {
    fn operation_kind(&self) -> consema_core::OperationKind {
        consema_core::OperationKind::Projection
    }

    fn failure_kind(&self) -> consema_core::FailureKind {
        match self {
            Self::RecoveredDocument
            | Self::SubtreeNotElement
            | Self::MappingAdmission(_)
            | Self::Collision { .. } => consema_core::FailureKind::InvalidInput,
            Self::ResourceLimit(_) => consema_core::FailureKind::ResourceLimited,
            Self::CoreInvariant => consema_core::FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::RecoveredDocument => "xml.projection.recovered-document@1",
            Self::SubtreeNotElement => "xml.projection.subtree@1",
            Self::MappingAdmission(_) => "xml.projection.admission@1",
            Self::Collision { .. } => "xml.projection.collision@1",
            Self::ResourceLimit(_) => "xml.projection.resource-limit@1",
            Self::CoreInvariant => "xml.projection.core-invariant@1",
        }
    }
}

impl Document {
    /// Projects this snapshot under one explicit target and policy contract.
    #[must_use]
    pub fn project(&self, request: ProjectionRequest) -> ProjectionResult {
        if self.status() != FormationStatus::Complete {
            return failed(ProjectionFailure::RecoveredDocument);
        }
        let mut context = Context {
            document: self,
            limits: request.limits,
            report: ProjectionReport::default(),
            provenance: ProvenanceMap::default(),
            value_nodes: 0,
            source_nodes: 0,
        };
        let result = match request.target {
            ProjectionTarget::ElementTreeV1 => context.project_element_tree(),
            ProjectionTarget::TextContentV1 => {
                context.project_text_content(request.subtree, request.include)
            }
            ProjectionTarget::SimpleEntryMappingV1 => context.project_entry_mapping(request),
        };
        match result {
            Ok((value, fidelity)) => ProjectionResult::Complete(CompleteProjection {
                value,
                fidelity,
                report: context.report,
                provenance: context.provenance,
            }),
            Err(failure) => failed(failure),
        }
    }
}

struct Context<'a> {
    document: &'a Document,
    limits: ProjectionLimits,
    report: ProjectionReport,
    provenance: ProvenanceMap,
    value_nodes: usize,
    source_nodes: usize,
}

impl Context<'_> {
    fn step(&mut self) -> Result<(), ProjectionFailure> {
        self.source_nodes = self
            .source_nodes
            .checked_add(1)
            .ok_or(ProjectionFailure::ResourceLimit("max_source_nodes"))?;
        if self.source_nodes > self.limits.max_source_nodes {
            return Err(ProjectionFailure::ResourceLimit("max_source_nodes"));
        }
        Ok(())
    }

    fn reserve_value(&mut self, count: usize) -> Result<(), ProjectionFailure> {
        self.value_nodes = self
            .value_nodes
            .checked_add(count)
            .ok_or(ProjectionFailure::ResourceLimit("max_value_nodes"))?;
        if self.value_nodes > self.limits.max_value_nodes {
            return Err(ProjectionFailure::ResourceLimit("max_value_nodes"));
        }
        Ok(())
    }

    fn event(
        &mut self,
        kind: ProjectionEventKind,
        discarded: NodeRef,
        impact: Fidelity,
    ) -> Result<(), ProjectionFailure> {
        self.report.push(
            ProjectionEvent {
                kind,
                discarded,
                impact,
            },
            self.limits,
        )
    }

    fn origin(
        &mut self,
        projected: ProjectedLocation,
        node: NodeRef,
        span: Span,
        relation: ProvenanceRelation,
    ) -> Result<(), ProjectionFailure> {
        self.provenance.push(
            ProvenanceEntry {
                projected,
                origins: vec![SourceOrigin {
                    snapshot: self.document.snapshot_identity(),
                    node,
                    span,
                    relation,
                }],
            },
            self.limits,
        )
    }

    fn element_data(&self, index: usize) -> &XmlElementData {
        let XmlContent::Element(data) = &self.document.nodes()[index] else {
            unreachable!("element index always points at element arena data")
        };
        data
    }

    fn element_node_ref(&self, index: usize) -> NodeRef {
        self.document.authority().node_ref(
            u64::try_from(index).expect("parse limits keep arena in u64"),
            consema_document::NodeRole::XmlElement,
        )
    }

    /// Snapshot-bound identity of one ordinal-scoped content occurrence.
    fn occurrence_node_ref(&self, ordinal: u64, role: consema_document::NodeRole) -> NodeRef {
        self.document.authority().node_ref(ordinal, role)
    }

    /// Value path of one item inside an ordered record array.
    fn item_path(container: &ValuePath, field: &str, index: usize) -> ValuePath {
        container
            .child(ValuePathSegment::ObjectValue(field.to_owned()))
            .child(ValuePathSegment::SequenceElement(index as u64))
    }

    /// Exact `xml.element-tree@1` record for the document root.
    fn project_element_tree(&mut self) -> Result<(PortableValue, Fidelity), ProjectionFailure> {
        let root = self
            .document
            .root()
            .ok_or(ProjectionFailure::MappingAdmission("missing root"))?
            .data()
            .index;
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string("xml.element-tree@1"))
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        if let Some(declared) = self.document.declaration() {
            builder
                .insert("declaration", Self::declaration_value(declared)?)
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        if let Some(doctype) = self.document.doctype() {
            if !doctype.entities.is_empty() {
                let mut entity_list = Vec::new();
                for entity in doctype.entities.iter() {
                    let mut entry = ObjectBuilder::new();
                    entry
                        .insert("name", PortableValue::string(entity.name.to_string()))
                        .map_err(|_| ProjectionFailure::CoreInvariant)?
                        .insert(
                            "replacement",
                            PortableValue::string(entity.replacement.to_string()),
                        )
                        .map_err(|_| ProjectionFailure::CoreInvariant)?;
                    entity_list.push(entry.build());
                }
                builder
                    .insert("entities", PortableValue::sequence(entity_list))
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
            }
        }
        let root_path = ValuePath::root().child(ValuePathSegment::ObjectValue("root".to_owned()));
        let (root_value, _) = self.element_value(root, root_path)?;
        builder
            .insert("root", root_value)
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        let value = builder.build();
        Ok((value, Fidelity::Exact))
    }

    fn declaration_value(
        declared: &XmlDeclarationData,
    ) -> Result<PortableValue, ProjectionFailure> {
        let mut builder = ObjectBuilder::new();
        builder
            .insert(
                "version",
                PortableValue::string(declared.version.to_string()),
            )
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        if let Some((_, encoding)) = &declared.encoding {
            builder
                .insert("encoding", PortableValue::string(encoding.to_string()))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        if let Some((_, standalone)) = declared.standalone {
            builder
                .insert("standalone", PortableValue::boolean(standalone))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        Ok(builder.build())
    }

    /// Recursive element record; `path` is the location of this element
    /// record inside the projected value.
    fn element_value(
        &mut self,
        index: usize,
        path: ValuePath,
    ) -> Result<(PortableValue, usize), ProjectionFailure> {
        self.step()?;
        let data = self.element_data(index);
        let span = data.span;
        let namespaces = data.namespaces.clone();
        let attributes = data.attributes.clone();
        let children = data.children.clone();
        let mut builder = ObjectBuilder::new();
        let (namespace, local) = match &data.expanded {
            Some(expanded) => (
                expanded.namespace.as_deref().map(str::to_owned),
                expanded.local.to_string(),
            ),
            None => (None, data.qname.local.to_string()),
        };
        let mut name = ObjectBuilder::new();
        name.insert(
            "namespace",
            namespace.map_or_else(PortableValue::null, PortableValue::string),
        )
        .and_then(|name| name.insert("local", PortableValue::string(local)))
        .map_err(|_| ProjectionFailure::CoreInvariant)?;
        builder
            .insert("expanded-name", name.build())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        if !namespaces.is_empty() {
            let mut list = Vec::new();
            for (item, binding) in namespaces.iter().enumerate() {
                let mut binding_value = ObjectBuilder::new();
                binding_value
                    .insert(
                        "prefix",
                        binding
                            .prefix
                            .as_deref()
                            .map_or_else(PortableValue::null, PortableValue::string),
                    )
                    .and_then(|binding_value| {
                        binding_value.insert("uri", PortableValue::string(binding.uri.to_string()))
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                self.origin(
                    ProjectedLocation::Value(Self::item_path(&path, "namespaces", item)),
                    self.occurrence_node_ref(
                        binding.ordinal,
                        consema_document::NodeRole::XmlNamespaceBinding,
                    ),
                    binding.span,
                    ProvenanceRelation::Direct,
                )?;
                list.push(binding_value.build());
            }
            builder
                .insert("namespaces", PortableValue::sequence(list))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        if !attributes.is_empty() {
            let mut list = Vec::new();
            for (item, attribute) in attributes.iter().enumerate() {
                let mut attribute_value = ObjectBuilder::new();
                let (attr_namespace, attr_local) = match &attribute.expanded {
                    Some(expanded) => (
                        expanded.namespace.as_deref().map(str::to_owned),
                        expanded.local.to_string(),
                    ),
                    None => (None, attribute.qname.local.to_string()),
                };
                let mut attr_name = ObjectBuilder::new();
                attr_name
                    .insert(
                        "namespace",
                        attr_namespace.map_or_else(PortableValue::null, PortableValue::string),
                    )
                    .and_then(|attr_name| {
                        attr_name.insert("local", PortableValue::string(attr_local))
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                attribute_value
                    .insert("expanded-name", attr_name.build())
                    .and_then(|attribute_value| {
                        attribute_value.insert(
                            "value",
                            PortableValue::string(attribute.normalized_value.to_string()),
                        )
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                self.origin(
                    ProjectedLocation::Value(Self::item_path(&path, "attributes", item)),
                    self.occurrence_node_ref(
                        attribute.ordinal,
                        consema_document::NodeRole::XmlAttribute,
                    ),
                    attribute.span,
                    ProvenanceRelation::Direct,
                )?;
                list.push(attribute_value.build());
            }
            builder
                .insert("attributes", PortableValue::sequence(list))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        if !children.is_empty() {
            let mut list = Vec::new();
            for (item, &child) in children.iter().enumerate() {
                let (value, _) =
                    self.content_value(child, Self::item_path(&path, "content", item))?;
                list.push(value);
            }
            builder
                .insert("content", PortableValue::sequence(list))
                .map_err(|_| ProjectionFailure::CoreInvariant)?;
        }
        let value = builder.build();
        self.reserve_value(1)?;
        let node = self.element_node_ref(index);
        self.origin(
            ProjectedLocation::Value(path),
            node,
            span,
            ProvenanceRelation::Direct,
        )?;
        Ok((value, index))
    }

    /// One ordered content item record; `path` is the item's location.
    fn content_value(
        &mut self,
        index: usize,
        path: ValuePath,
    ) -> Result<(PortableValue, usize), ProjectionFailure> {
        self.step()?;
        match &self.document.nodes()[index] {
            XmlContent::Element(_) => self.element_value(index, path),
            XmlContent::Text(data) => {
                let mut builder = ObjectBuilder::new();
                builder
                    .insert("kind", PortableValue::string("text"))
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                let mut fragments = Vec::new();
                for (item, fragment) in data.fragments.iter().enumerate() {
                    let mut fragment_value = ObjectBuilder::new();
                    match fragment {
                        ReferenceFragment::Literal { text, .. } => {
                            fragment_value
                                .insert("kind", PortableValue::string("literal"))
                                .and_then(|fragment_value| {
                                    fragment_value
                                        .insert("text", PortableValue::string(text.to_string()))
                                })
                                .map_err(|_| ProjectionFailure::CoreInvariant)?;
                        }
                        ReferenceFragment::CharacterReference { resolved, .. } => {
                            fragment_value
                                .insert("kind", PortableValue::string("character-reference"))
                                .and_then(|fragment_value| {
                                    fragment_value.insert(
                                        "resolved",
                                        PortableValue::string(resolved.to_string()),
                                    )
                                })
                                .map_err(|_| ProjectionFailure::CoreInvariant)?;
                        }
                        ReferenceFragment::PredefinedEntity { name, resolved, .. } => {
                            fragment_value
                                .insert("kind", PortableValue::string("predefined-entity"))
                                .and_then(|fragment_value| {
                                    fragment_value
                                        .insert("name", PortableValue::string(name.to_string()))
                                })
                                .and_then(|fragment_value| {
                                    fragment_value.insert(
                                        "resolved",
                                        PortableValue::string(resolved.to_string()),
                                    )
                                })
                                .map_err(|_| ProjectionFailure::CoreInvariant)?;
                        }
                        ReferenceFragment::GeneralEntity { name, resolved, .. } => {
                            fragment_value
                                .insert("kind", PortableValue::string("general-entity"))
                                .and_then(|fragment_value| {
                                    fragment_value
                                        .insert("name", PortableValue::string(name.to_string()))
                                })
                                .and_then(|fragment_value| {
                                    fragment_value.insert(
                                        "resolved",
                                        PortableValue::string(resolved.to_string()),
                                    )
                                })
                                .map_err(|_| ProjectionFailure::CoreInvariant)?;
                        }
                    }
                    self.origin(
                        ProjectedLocation::Value(Self::item_path(&path, "fragments", item)),
                        self.occurrence_node_ref(
                            data.ordinal,
                            consema_document::NodeRole::XmlEntityReference,
                        ),
                        fragment.span(),
                        ProvenanceRelation::ReferenceDerived,
                    )?;
                    fragments.push(fragment_value.build());
                }
                builder
                    .insert("fragments", PortableValue::sequence(fragments))
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                let value = builder.build();
                self.reserve_value(1)?;
                self.origin(
                    ProjectedLocation::Value(path),
                    self.occurrence_node_ref(data.ordinal, consema_document::NodeRole::XmlText),
                    data.span,
                    ProvenanceRelation::Direct,
                )?;
                Ok((value, index))
            }
            XmlContent::Cdata(data) => {
                let mut builder = ObjectBuilder::new();
                builder
                    .insert("kind", PortableValue::string("cdata"))
                    .and_then(|builder| {
                        builder.insert("text", PortableValue::string(data.text.to_string()))
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                let value = builder.build();
                self.reserve_value(1)?;
                self.origin(
                    ProjectedLocation::Value(path),
                    self.occurrence_node_ref(data.ordinal, consema_document::NodeRole::XmlCdata),
                    data.span,
                    ProvenanceRelation::Direct,
                )?;
                Ok((value, index))
            }
            XmlContent::Comment(data) => {
                let mut builder = ObjectBuilder::new();
                builder
                    .insert("kind", PortableValue::string("comment"))
                    .and_then(|builder| {
                        builder.insert("text", PortableValue::string(data.text.to_string()))
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                let value = builder.build();
                self.reserve_value(1)?;
                self.origin(
                    ProjectedLocation::Value(path),
                    self.occurrence_node_ref(data.ordinal, consema_document::NodeRole::XmlComment),
                    data.span,
                    ProvenanceRelation::Direct,
                )?;
                Ok((value, index))
            }
            XmlContent::ProcessingInstruction(data) => {
                let mut builder = ObjectBuilder::new();
                builder
                    .insert("kind", PortableValue::string("processing-instruction"))
                    .and_then(|builder| {
                        builder.insert("target", PortableValue::string(data.target.to_string()))
                    })
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                if let Some((_, content)) = &data.content {
                    builder
                        .insert("content", PortableValue::string(content.to_string()))
                        .map_err(|_| ProjectionFailure::CoreInvariant)?;
                }
                let value = builder.build();
                self.reserve_value(1)?;
                self.origin(
                    ProjectedLocation::Value(path),
                    self.occurrence_node_ref(
                        data.ordinal,
                        consema_document::NodeRole::XmlProcessingInstruction,
                    ),
                    data.span,
                    ProvenanceRelation::Direct,
                )?;
                Ok((value, index))
            }
            XmlContent::ErrorRegion(data) => {
                let mut builder = ObjectBuilder::new();
                builder
                    .insert("kind", PortableValue::string("error-region"))
                    .map_err(|_| ProjectionFailure::CoreInvariant)?;
                let value = builder.build();
                self.reserve_value(1)?;
                self.origin(
                    ProjectedLocation::Value(path),
                    self.occurrence_node_ref(
                        data.ordinal,
                        consema_document::NodeRole::XmlErrorRegion,
                    ),
                    data.span,
                    ProvenanceRelation::Direct,
                )?;
                Ok((value, index))
            }
        }
    }

    /// Always-transformed descendant text content.
    fn project_text_content(
        &mut self,
        subtree: Option<u64>,
        include: TextContentInclude,
    ) -> Result<(PortableValue, Fidelity), ProjectionFailure> {
        let root_index = self
            .document
            .root()
            .ok_or(ProjectionFailure::MappingAdmission("missing root"))?
            .data()
            .index;
        let start = match subtree {
            Some(index) => {
                usize::try_from(index).map_err(|_| ProjectionFailure::SubtreeNotElement)?
            }
            None => root_index,
        };
        if !matches!(self.document.nodes()[start], XmlContent::Element(_)) {
            return Err(ProjectionFailure::SubtreeNotElement);
        }
        let mut out = String::new();
        self.collect_text(start, include, &mut out)?;
        let value = PortableValue::string(out);
        self.reserve_value(1)?;
        self.origin(
            ProjectedLocation::Value(ValuePath::root()),
            self.element_node_ref(start),
            self.element_data(start).span,
            ProvenanceRelation::Derived,
        )?;
        Ok((value, Fidelity::Transformed))
    }

    fn collect_text(
        &mut self,
        index: usize,
        include: TextContentInclude,
        out: &mut String,
    ) -> Result<(), ProjectionFailure> {
        let data = self.element_data(index);
        let children = data.children.clone();
        for &child in &children {
            match &self.document.nodes()[child] {
                XmlContent::Element(child_data) => {
                    self.event(
                        ProjectionEventKind::ElementDiscarded,
                        self.element_node_ref(child),
                        Fidelity::Transformed,
                    )?;
                    for attribute in &child_data.attributes {
                        self.event(
                            ProjectionEventKind::AttributeDiscarded,
                            self.document.authority().node_ref(
                                attribute.ordinal,
                                consema_document::NodeRole::XmlAttribute,
                            ),
                            Fidelity::Transformed,
                        )?;
                    }
                    self.collect_text(child, include, out)?;
                }
                XmlContent::Text(data) => {
                    for fragment in data.fragments.iter() {
                        if matches!(
                            fragment,
                            ReferenceFragment::CharacterReference { .. }
                                | ReferenceFragment::PredefinedEntity { .. }
                                | ReferenceFragment::GeneralEntity { .. }
                        ) {
                            self.event(
                                ProjectionEventKind::ReferenceCollapsed,
                                self.occurrence_node_ref(
                                    data.ordinal,
                                    consema_document::NodeRole::XmlEntityReference,
                                ),
                                Fidelity::Transformed,
                            )?;
                        }
                    }
                    // Semantic text: line ends are normalized to LF, matching
                    // every other text observation in the crate.
                    out.push_str(&text_semantic(data));
                }
                XmlContent::Cdata(data) => {
                    if matches!(include, TextContentInclude::TextAndCdata) {
                        out.push_str(&data.text);
                    } else {
                        self.event(
                            ProjectionEventKind::CdataDiscarded,
                            self.document
                                .authority()
                                .node_ref(data.ordinal, consema_document::NodeRole::XmlCdata),
                            Fidelity::Transformed,
                        )?;
                    }
                }
                XmlContent::Comment(data) => {
                    self.event(
                        ProjectionEventKind::CommentDiscarded,
                        self.document
                            .authority()
                            .node_ref(data.ordinal, consema_document::NodeRole::XmlComment),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::ProcessingInstruction(data) => {
                    self.event(
                        ProjectionEventKind::ProcessingInstructionDiscarded,
                        self.document.authority().node_ref(
                            data.ordinal,
                            consema_document::NodeRole::XmlProcessingInstruction,
                        ),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::ErrorRegion(_) => {}
            }
        }
        Ok(())
    }

    /// Explicit-policy entry mapping of one selected subtree.
    fn project_entry_mapping(
        &mut self,
        request: ProjectionRequest,
    ) -> Result<(PortableValue, Fidelity), ProjectionFailure> {
        let root_index = self
            .document
            .root()
            .ok_or(ProjectionFailure::MappingAdmission("missing root"))?
            .data()
            .index;
        let start = match request.subtree {
            Some(index) => {
                usize::try_from(index).map_err(|_| ProjectionFailure::SubtreeNotElement)?
            }
            None => root_index,
        };
        if !matches!(self.document.nodes()[start], XmlContent::Element(_)) {
            return Err(ProjectionFailure::SubtreeNotElement);
        }
        let mut entries = EntrySet::new();
        self.map_children(start, ValuePath::root(), &mut entries, &request)?;
        let mut builder = EntryMappingBuilder::new();
        for (key, value) in entries.into_ordered() {
            builder.push(PortableValue::string(key), value);
        }
        let value = builder.build();
        self.reserve_value(1)?;
        Ok((value, Fidelity::Transformed))
    }

    fn keep_from_repeated(policy: RepeatedChildPolicy) -> KeepPolicy {
        match policy {
            RepeatedChildPolicy::Reject => KeepPolicy::Reject,
            RepeatedChildPolicy::First => KeepPolicy::First,
            RepeatedChildPolicy::Last => KeepPolicy::Last,
        }
    }

    fn keep_from_collision(policy: CollisionPolicy) -> KeepPolicy {
        match policy {
            CollisionPolicy::Reject => KeepPolicy::Reject,
            CollisionPolicy::First => KeepPolicy::First,
            CollisionPolicy::Last => KeepPolicy::Last,
        }
    }

    /// Resolves the entry ordinal under the explicit request policies.
    ///
    /// A repeated *expanded name* is governed by `repeated_child`; a key
    /// collision after key-spelling (distinct expanded names folding to one
    /// key, or an attribute key meeting an existing key) is governed by
    /// `collision`.
    fn entry_ordinal(
        &mut self,
        entries: &mut EntrySet,
        key: &str,
        candidate: Option<&ExpandedName>,
        request: &ProjectionRequest,
        origin: NodeRef,
        collapse: ProjectionEventKind,
    ) -> Result<usize, ProjectionFailure> {
        let keep_repeated = Self::keep_from_repeated(request.repeated_child);
        let keep_collision = Self::keep_from_collision(request.collision);
        match entries.seen.get(key) {
            None => {
                let ordinal = entries.ordered.len();
                entries
                    .seen
                    .insert(key.to_owned(), (ordinal, candidate.cloned()));
                Ok(ordinal)
            }
            Some((position, existing)) => {
                let repeated = match (existing, candidate) {
                    (Some(earlier), Some(candidate)) => earlier == candidate,
                    _ => false,
                };
                let keep = if repeated {
                    keep_repeated
                } else {
                    keep_collision
                };
                match keep {
                    KeepPolicy::Reject => Err(ProjectionFailure::Collision {
                        child: origin,
                        key: key.to_owned(),
                    }),
                    KeepPolicy::First | KeepPolicy::Last => {
                        // A repeated expanded name collapses under the
                        // repeated-child policy; a key-spelling collision of
                        // distinct expanded names collapses the namespace
                        // difference under the collision policy.
                        let event_kind = if repeated {
                            collapse
                        } else {
                            ProjectionEventKind::NamespaceCollapsed
                        };
                        self.event(event_kind, origin, Fidelity::Transformed)?;
                        Ok(*position)
                    }
                }
            }
        }
    }

    /// Records one committed entry and its value/association provenance.
    fn commit_entry(
        &mut self,
        entries: &mut EntrySet,
        key: String,
        value: PortableValue,
        ordinal: usize,
        source: (NodeRef, Span),
        container: &ValuePath,
    ) -> Result<(), ProjectionFailure> {
        if entries.ordered.get(ordinal).is_some() {
            entries.ordered[ordinal] = (key, value);
        } else {
            entries.ordered.push((key, value));
        }
        self.reserve_value(1)?;
        let association = AssociationLocation::new(
            container.clone(),
            ordinal as u64,
            AssociationRole::EntryMappingEntry,
        );
        self.origin(
            ProjectedLocation::Association(association),
            source.0,
            source.1,
            ProvenanceRelation::Direct,
        )?;
        self.origin(
            ProjectedLocation::Value(container.child(ValuePathSegment::EntryValue(ordinal as u64))),
            source.0,
            source.1,
            ProvenanceRelation::Direct,
        )?;
        Ok(())
    }

    fn map_children(
        &mut self,
        element: usize,
        container: ValuePath,
        entries: &mut EntrySet,
        request: &ProjectionRequest,
    ) -> Result<(), ProjectionFailure> {
        let data = self.element_data(element);
        if !data.namespaces.is_empty() {
            return Err(ProjectionFailure::MappingAdmission(
                "namespace declarations on the mapped element",
            ));
        }
        let attributes = data.attributes.clone();
        let children = data.children.clone();
        for attribute in &attributes {
            let origin = self
                .occurrence_node_ref(attribute.ordinal, consema_document::NodeRole::XmlAttribute);
            match request.attributes {
                AttributePolicy::RejectAttributes => {
                    return Err(ProjectionFailure::MappingAdmission(
                        "attributes present under RejectAttributes",
                    ));
                }
                AttributePolicy::IgnoreAttributes => {
                    self.event(
                        ProjectionEventKind::AttributeDiscarded,
                        origin,
                        Fidelity::Transformed,
                    )?;
                }
                AttributePolicy::PrefixAttributeKeys => {
                    let key = format!("@{}", attribute.qname.local);
                    let ordinal = self.entry_ordinal(
                        entries,
                        &key,
                        None,
                        request,
                        origin,
                        ProjectionEventKind::AttributeDiscarded,
                    )?;
                    let value = PortableValue::string(attribute.normalized_value.to_string());
                    self.commit_entry(
                        entries,
                        key,
                        value,
                        ordinal,
                        (origin, attribute.span),
                        &container,
                    )?;
                }
            }
        }
        for &child in &children {
            match &self.document.nodes()[child] {
                XmlContent::Element(child_data) => {
                    let (namespace, local) = match &child_data.expanded {
                        Some(expanded) => (
                            expanded.namespace.as_deref().unwrap_or("").to_owned(),
                            expanded.local.to_string(),
                        ),
                        None => (String::new(), child_data.qname.local.to_string()),
                    };
                    let key = match request.key_spelling {
                        ExpandedNameKeyPolicy::LocalOnly => local.clone(),
                        ExpandedNameKeyPolicy::PrefixedSpelling => {
                            child_data.qname.qname().as_str()
                        }
                        ExpandedNameKeyPolicy::UriBracketed => format!("{{{namespace}}}{local}"),
                    };
                    let origin = self.element_node_ref(child);
                    let ordinal = self.entry_ordinal(
                        entries,
                        &key,
                        child_data.expanded.as_ref(),
                        request,
                        origin,
                        ProjectionEventKind::ChildCollapsed,
                    )?;
                    let has_element_children = child_data.children.iter().any(|&grandchild| {
                        matches!(self.document.nodes()[grandchild], XmlContent::Element(_))
                    });
                    let child_value = if has_element_children {
                        let nested_container =
                            container.child(ValuePathSegment::EntryValue(ordinal as u64));
                        let mut nested = EntrySet::new();
                        self.map_children(child, nested_container, &mut nested, request)?;
                        let mut nested_builder = EntryMappingBuilder::new();
                        for (nested_key, nested_value) in nested.into_ordered() {
                            nested_builder.push(PortableValue::string(nested_key), nested_value);
                        }
                        nested_builder.build()
                    } else {
                        self.leaf_value(child, request)?
                    };
                    self.commit_entry(
                        entries,
                        key,
                        child_value,
                        ordinal,
                        (origin, child_data.span),
                        &container,
                    )?;
                }
                XmlContent::Text(data) => match request.text_key {
                    TextKeyPolicy::RejectText => {
                        if !text_semantic(data).trim().is_empty() {
                            return Err(ProjectionFailure::MappingAdmission(
                                "text content under RejectText",
                            ));
                        }
                    }
                    TextKeyPolicy::IgnoreText => {
                        self.event(
                            ProjectionEventKind::TextDiscarded,
                            self.occurrence_node_ref(
                                data.ordinal,
                                consema_document::NodeRole::XmlText,
                            ),
                            Fidelity::Transformed,
                        )?;
                    }
                },
                XmlContent::Cdata(data) => match request.text_key {
                    TextKeyPolicy::RejectText => {
                        return Err(ProjectionFailure::MappingAdmission(
                            "CDATA content under RejectText",
                        ));
                    }
                    TextKeyPolicy::IgnoreText => {
                        self.event(
                            ProjectionEventKind::CdataDiscarded,
                            self.occurrence_node_ref(
                                data.ordinal,
                                consema_document::NodeRole::XmlCdata,
                            ),
                            Fidelity::Transformed,
                        )?;
                    }
                },
                XmlContent::Comment(data) => {
                    self.event(
                        ProjectionEventKind::CommentDiscarded,
                        self.occurrence_node_ref(
                            data.ordinal,
                            consema_document::NodeRole::XmlComment,
                        ),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::ProcessingInstruction(data) => {
                    self.event(
                        ProjectionEventKind::ProcessingInstructionDiscarded,
                        self.occurrence_node_ref(
                            data.ordinal,
                            consema_document::NodeRole::XmlProcessingInstruction,
                        ),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::ErrorRegion(_) => {}
            }
        }
        Ok(())
    }

    /// The leaf value of one element without element children.
    fn leaf_value(
        &mut self,
        element: usize,
        request: &ProjectionRequest,
    ) -> Result<PortableValue, ProjectionFailure> {
        let data = self.element_data(element);
        let children = data.children.clone();
        let mut text = String::new();
        for &child in &children {
            match &self.document.nodes()[child] {
                XmlContent::Text(text_data) => {
                    text.push_str(&text_semantic(text_data));
                }
                XmlContent::Cdata(cdata_data) => match request.text_key {
                    TextKeyPolicy::RejectText => {
                        return Err(ProjectionFailure::MappingAdmission(
                            "CDATA content under RejectText",
                        ));
                    }
                    TextKeyPolicy::IgnoreText => {
                        self.event(
                            ProjectionEventKind::CdataDiscarded,
                            self.document
                                .authority()
                                .node_ref(cdata_data.ordinal, consema_document::NodeRole::XmlCdata),
                            Fidelity::Transformed,
                        )?;
                    }
                },
                XmlContent::Comment(comment_data) => {
                    self.event(
                        ProjectionEventKind::CommentDiscarded,
                        self.document
                            .authority()
                            .node_ref(comment_data.ordinal, consema_document::NodeRole::XmlComment),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::ProcessingInstruction(pi_data) => {
                    self.event(
                        ProjectionEventKind::ProcessingInstructionDiscarded,
                        self.document.authority().node_ref(
                            pi_data.ordinal,
                            consema_document::NodeRole::XmlProcessingInstruction,
                        ),
                        Fidelity::Transformed,
                    )?;
                }
                XmlContent::Element(_) | XmlContent::ErrorRegion(_) => {}
            }
        }
        Ok(PortableValue::string(text))
    }
}

fn failed(failure: ProjectionFailure) -> ProjectionResult {
    let mut diagnostic = Diagnostic::new(
        failure.diagnostic_code(),
        DiagnosticCategory::Projection,
        DiagnosticSeverity::Error,
        None,
        0,
    );
    diagnostic
        .arguments
        .insert("failure".to_owned(), format!("{failure:?}"));
    ProjectionResult::Failed(FailedProjectionAttempt {
        diagnostics: vec![diagnostic],
        report: ProjectionReport::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile};
    use consema_core::ValuePathSegment;
    use std::sync::Arc;

    fn parse_utf8(source: &[u8]) -> Document {
        let bytes: Arc<[u8]> = Arc::from(source);
        crate::parse(
            bytes,
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("forms")
    }

    fn entry_mapping(
        document: &Document,
        subtree: NodeRef,
        attributes: AttributePolicy,
        text_key: TextKeyPolicy,
        repeated: RepeatedChildPolicy,
        spelling: ExpandedNameKeyPolicy,
        collision: CollisionPolicy,
    ) -> ProjectionResult {
        document.project(ProjectionRequest::simple_entry_mapping(
            subtree, attributes, text_key, repeated, spelling, collision,
        ))
    }

    #[test]
    fn element_tree_provenance_uses_nested_value_paths() {
        let document = parse_utf8(br#"<root a="1"><child>t</child></root>"#);
        let ProjectionResult::Complete(projection) =
            document.project(ProjectionRequest::element_tree())
        else {
            panic!("exact projection");
        };
        let paths: Vec<Vec<ValuePathSegment>> = projection
            .provenance
            .entries()
            .iter()
            .filter_map(|entry| match &entry.projected {
                ProjectedLocation::Value(path) => Some(path.segments().to_vec()),
                ProjectedLocation::Association(_) => None,
            })
            .collect();
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [ValuePathSegment::ObjectValue(root), ValuePathSegment::ObjectValue(content), ValuePathSegment::SequenceElement(0)]
                    if root == "root" && content == "content"
                )
            }),
            "child content path must descend through root/content/0: {paths:?}"
        );
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(root),
                        ValuePathSegment::ObjectValue(attributes),
                        ValuePathSegment::SequenceElement(0),
                    ] if root == "root" && attributes == "attributes"
                )
            }),
            "attribute path must descend through root/attributes/0: {paths:?}"
        );
        assert!(
            paths.iter().all(|segments| !segments.is_empty()),
            "no provenance entry may point at the bare root"
        );
    }

    #[test]
    fn key_spelling_collision_uses_collision_policy() {
        // Two distinct expanded names fold to one `x` key under LocalOnly.
        let document = parse_utf8(br#"<root><a:x xmlns:a="urn:a"/><b:x xmlns:b="urn:b"/></root>"#);
        let root = document.root().expect("root").node_ref();
        let rejected = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        );
        assert!(
            matches!(rejected, ProjectionResult::Failed(_)),
            "spelling collision must fail under CollisionPolicy::Reject"
        );

        let first = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::First,
        );
        let ProjectionResult::Complete(first) = first else {
            panic!("First policy must complete");
        };
        assert_eq!(first.value.as_entry_mapping().unwrap().len(), 1);
        assert!(
            first
                .report
                .events()
                .iter()
                .any(|event| event.kind == ProjectionEventKind::NamespaceCollapsed),
            "distinct expanded names folding to one key collapse the namespace difference"
        );
        assert!(
            first
                .provenance
                .entries()
                .iter()
                .any(|entry| matches!(&entry.projected, ProjectedLocation::Association(_))),
            "entry mapping publishes association provenance"
        );

        // The same expanded name repeated twice is a repeated-child case:
        // RepeatedChildPolicy::First keeps one entry, never CollisionPolicy.
        let repeated = parse_utf8(br"<root><x/><x/></root>");
        let repeated_root = repeated.root().expect("root").node_ref();
        let kept = entry_mapping(
            &repeated,
            repeated_root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::First,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        );
        assert!(
            matches!(kept, ProjectionResult::Complete(_)),
            "repeated expanded names are governed by RepeatedChildPolicy, not CollisionPolicy"
        );
    }

    #[test]
    fn text_content_normalizes_line_endings() {
        let document = parse_utf8(b"<root>line1\r\nline2</root>");
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = document.project(
            ProjectionRequest::text_content(root, TextContentInclude::TextAndCdata),
        ) else {
            panic!("text content projection");
        };
        assert_eq!(
            projection.value.as_string().unwrap(),
            "line1\nline2",
            "text content is the normalized semantic text"
        );
        assert_eq!(projection.fidelity, Fidelity::Transformed);
    }

    #[test]
    fn recovered_documents_never_project() {
        let document = parse_utf8(br"<p:root/>");
        assert_eq!(
            document.status(),
            consema_document::FormationStatus::Recovered
        );
        let ProjectionResult::Failed(failed) = document.project(ProjectionRequest::element_tree())
        else {
            panic!("recovered document must fail projection");
        };
        assert_eq!(
            failed.diagnostics[0].code,
            "xml.projection.recovered-document@1"
        );
    }

    #[test]
    fn simple_entry_mapping_attribute_policy_matrix() {
        let document = parse_utf8(br#"<root a="1" b="2"><x/></root>"#);
        let root = document.root().expect("root").node_ref();

        let rejected = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        );
        let ProjectionResult::Failed(failed) = rejected else {
            panic!("RejectAttributes must reject");
        };
        assert_eq!(failed.diagnostics[0].code, "xml.projection.admission@1");

        let ProjectionResult::Complete(ignored) = entry_mapping(
            &document,
            root,
            AttributePolicy::IgnoreAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        ) else {
            panic!("IgnoreAttributes must complete");
        };
        assert_eq!(ignored.value.as_entry_mapping().unwrap().len(), 1);
        assert_eq!(
            ignored
                .report
                .events()
                .iter()
                .filter(|event| event.kind == ProjectionEventKind::AttributeDiscarded)
                .count(),
            2,
            "every attribute publishes an AttributeDiscarded event"
        );

        let ProjectionResult::Complete(prefixed) = entry_mapping(
            &document,
            root,
            AttributePolicy::PrefixAttributeKeys,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        ) else {
            panic!("PrefixAttributeKeys must complete");
        };
        let entries = prefixed.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 3, "two @ attributes and one child entry");
        let value = |key: &str| {
            entries
                .iter()
                .find(|entry| entry.key().as_string() == Some(key))
                .expect("entry exists")
                .value()
                .as_string()
                .expect("string value")
        };
        assert_eq!(value("@a"), "1");
        assert_eq!(value("@b"), "2");
        assert_eq!(value("x"), "");
    }

    #[test]
    fn simple_entry_mapping_text_key_policy_matrix() {
        let document = parse_utf8(br"<root>t<child/></root>");
        let root = document.root().expect("root").node_ref();

        let rejected = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        );
        let ProjectionResult::Failed(failed) = rejected else {
            panic!("non-whitespace text must fail under RejectText");
        };
        assert_eq!(failed.diagnostics[0].code, "xml.projection.admission@1");

        let ProjectionResult::Complete(ignored) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::IgnoreText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        ) else {
            panic!("IgnoreText must complete");
        };
        assert_eq!(ignored.value.as_entry_mapping().unwrap().len(), 1);
        assert!(
            ignored
                .report
                .events()
                .iter()
                .any(|event| event.kind == ProjectionEventKind::TextDiscarded),
            "ignored text must publish a TextDiscarded event"
        );
    }

    #[test]
    fn simple_entry_mapping_key_spelling_and_keep_policies() {
        // PrefixedSpelling uses the lexical prefix:local key.
        let document = parse_utf8(br#"<root><p:a xmlns:p="urn:p">v</p:a></root>"#);
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::PrefixedSpelling,
            CollisionPolicy::Reject,
        ) else {
            panic!("PrefixedSpelling must complete");
        };
        let entries = projection.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().as_string(), Some("p:a"));
        assert_eq!(entries[0].value().as_string(), Some("v"));

        // UriBracketed uses the {uri}local key.
        let ProjectionResult::Complete(projection) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::UriBracketed,
            CollisionPolicy::Reject,
        ) else {
            panic!("UriBracketed must complete");
        };
        let entries = projection.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().as_string(), Some("{urn:p}a"));
        assert_eq!(entries[0].value().as_string(), Some("v"));

        // RepeatedChildPolicy::Last keeps the later occurrence's value and
        // reports a ChildCollapsed collapse.
        let document = parse_utf8(br"<root><x>one</x><x>two</x></root>");
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Last,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        ) else {
            panic!("RepeatedChildPolicy::Last must complete");
        };
        let entries = projection.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value().as_string(), Some("two"));
        assert!(
            projection
                .report
                .events()
                .iter()
                .any(|event| event.kind == ProjectionEventKind::ChildCollapsed),
            "repeated expanded names collapse as ChildCollapsed"
        );

        // CollisionPolicy::Last keeps the later occurrence when distinct
        // expanded names fold to one key under LocalOnly, and the collapse is
        // reported as NamespaceCollapsed.
        let document =
            parse_utf8(br#"<root><a:x xmlns:a="urn:a">A</a:x><b:x xmlns:b="urn:b">B</b:x></root>"#);
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Last,
        ) else {
            panic!("CollisionPolicy::Last must complete");
        };
        let entries = projection.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value().as_string(), Some("B"));
        assert!(
            projection
                .report
                .events()
                .iter()
                .any(|event| event.kind == ProjectionEventKind::NamespaceCollapsed),
            "distinct expanded names folding to one key collapse the namespace difference"
        );
    }

    #[test]
    fn simple_entry_mapping_admission_and_recursion() {
        // A mapped element carrying namespace declarations fails admission.
        let document = parse_utf8(br#"<root xmlns:p="urn:p"><x/></root>"#);
        let root = document.root().expect("root").node_ref();
        let rejected = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        );
        let ProjectionResult::Failed(failed) = rejected else {
            panic!("namespace declarations on the mapped element must fail admission");
        };
        assert_eq!(failed.diagnostics[0].code, "xml.projection.admission@1");

        // Child elements with element children recurse into a nested mapping.
        let document = parse_utf8(br"<root><a><b>t</b></a></root>");
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = entry_mapping(
            &document,
            root,
            AttributePolicy::RejectAttributes,
            TextKeyPolicy::RejectText,
            RepeatedChildPolicy::Reject,
            ExpandedNameKeyPolicy::LocalOnly,
            CollisionPolicy::Reject,
        ) else {
            panic!("nested mapping must complete");
        };
        let entries = projection.value.as_entry_mapping().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key().as_string(), Some("a"));
        let nested = entries[0]
            .value()
            .as_entry_mapping()
            .expect("nested mapping");
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].key().as_string(), Some("b"));
        assert_eq!(nested[0].value().as_string(), Some("t"));
    }

    #[test]
    fn text_content_text_only_discards_cdata_and_reports() {
        let document = parse_utf8(br"<root>t<![CDATA[c]]></root>");
        let root = document.root().expect("root").node_ref();
        let ProjectionResult::Complete(projection) = document.project(
            ProjectionRequest::text_content(root, TextContentInclude::TextOnly),
        ) else {
            panic!("TextOnly must complete");
        };
        assert_eq!(projection.value.as_string().unwrap(), "t");
        assert!(
            projection
                .report
                .events()
                .iter()
                .any(|event| event.kind == ProjectionEventKind::CdataDiscarded),
            "dropped CDATA must publish a CdataDiscarded event"
        );
    }

    #[test]
    fn text_content_subtree_must_be_an_element() {
        let document = parse_utf8(br"<root>t</root>");
        let root_data = document.root().expect("root").data();
        let XmlContent::Text(text) = &document.nodes()[root_data.children[0]] else {
            panic!("child is text");
        };
        let text_ref = document
            .authority()
            .node_ref(text.ordinal, consema_document::NodeRole::XmlText);
        let ProjectionResult::Failed(failed) = document.project(ProjectionRequest::text_content(
            text_ref,
            TextContentInclude::TextOnly,
        )) else {
            panic!("a text subtree is not an element");
        };
        assert_eq!(failed.diagnostics[0].code, "xml.projection.subtree@1");
    }
}
