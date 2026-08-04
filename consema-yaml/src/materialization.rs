//! Canonical PortableGraph and PortableValue materialization for YAML.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter, Write as _};

use consema_core::{FailureKind, OperationKind, StableFailure};
use consema_document::{
    MaterializationFailure, MaterializationFidelity, MaterializationLimits, MaterializationReport,
    MaterializationRequest, MaterializedOrigin, NewlinePolicy, ParseLimits, SourceEncoding,
};
use consema_graph::{GraphNodeId, GraphNodeKind, PortableGraph};

use crate::native::{
    TAG_BINARY, TAG_BOOL, TAG_FLOAT, TAG_INT, TAG_MAP, TAG_MERGE, TAG_NULL, TAG_OMAP, TAG_PAIRS,
    TAG_SEQ, TAG_SET, TAG_STR, TAG_TIMESTAMP, TAG_VALUE, TAG_YAML,
};
use crate::{Document, YamlNode, YamlNodeKind, YamlProfile, parse};

/// A PortableGraph location consumed by YAML materialization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GraphMaterializationInputLocation {
    /// Ordered graph root occurrence.
    Root(u64),
    /// One graph node identity.
    Node(GraphNodeId),
    /// One ordered sequence edge.
    SequenceElement {
        /// Parent sequence node.
        parent: GraphNodeId,
        /// Direct element ordinal.
        ordinal: u64,
    },
    /// One ordered mapping-key edge.
    MappingKey {
        /// Parent mapping node.
        parent: GraphNodeId,
        /// Direct association ordinal.
        ordinal: u64,
    },
    /// One ordered mapping-value edge.
    MappingValue {
        /// Parent mapping node.
        parent: GraphNodeId,
        /// Direct association ordinal.
        ordinal: u64,
    },
}

/// One graph-input location mapped to one or more generated YAML origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphMaterializationProvenanceEntry {
    /// Exact input location.
    pub input: GraphMaterializationInputLocation,
    /// One or more exact output origins.
    pub outputs: Vec<MaterializedOrigin>,
}

/// Complete deterministic graph-to-YAML provenance multimap.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphMaterializationProvenanceMap {
    entries: Vec<GraphMaterializationProvenanceEntry>,
}

impl GraphMaterializationProvenanceMap {
    /// Entries in root, canonical-node, and association traversal order.
    #[must_use]
    pub fn entries(&self) -> &[GraphMaterializationProvenanceEntry] {
        &self.entries
    }
}

/// Stable PortableGraph-to-YAML materialization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphMaterializationFailure {
    /// A common request, formation, or resource contract failed.
    Materialization(MaterializationFailure),
    /// A custom tag has no published YAML constructor contract.
    UnsupportedTag {
        /// Graph node carrying the tag.
        node: GraphNodeId,
        /// Exact unsupported tag.
        tag: String,
    },
    /// A standard repository tag was attached to the wrong graph-node kind.
    TagKindMismatch {
        /// Invalid graph node.
        node: GraphNodeId,
        /// Exact standard tag.
        tag: String,
    },
    /// YAML document-scoped anchors cannot preserve sharing across graph roots.
    CrossDocumentSharing {
        /// Node reachable from more than one root document.
        node: GraphNodeId,
    },
    /// Reparse did not reproduce the complete input graph exactly.
    RoundTripMismatch,
}

impl From<MaterializationFailure> for GraphMaterializationFailure {
    fn from(value: MaterializationFailure) -> Self {
        Self::Materialization(value)
    }
}

impl Display for GraphMaterializationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GraphMaterializationFailure {}

impl StableFailure for GraphMaterializationFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Materialization
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::Materialization(failure) => failure.failure_kind(),
            Self::UnsupportedTag { .. } | Self::CrossDocumentSharing { .. } => {
                FailureKind::NotApplicable
            }
            Self::TagKindMismatch { .. } => FailureKind::InvalidInput,
            Self::RoundTripMismatch => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::Materialization(failure) => failure.diagnostic_code(),
            Self::UnsupportedTag { .. } => "yaml.materialization.unsupported-tag@1",
            Self::TagKindMismatch { .. } => "yaml.materialization.tag-kind-mismatch@1",
            Self::CrossDocumentSharing { .. } => "yaml.materialization.cross-document-sharing@1",
            Self::RoundTripMismatch => "yaml.materialization.round-trip-mismatch@1",
        }
    }
}

/// Failed graph attempt without a Document or partial output bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedGraphMaterializationAttempt {
    /// Stable failure.
    pub failure: GraphMaterializationFailure,
    /// Canonical input nodes analyzed before failure.
    pub analyzed_input_nodes: Vec<GraphNodeId>,
}

/// Complete exact PortableGraph-to-YAML materialization.
#[derive(Clone, Debug)]
pub struct CompleteGraphMaterialization {
    /// Newly formed immutable YAML stream.
    pub document: Document,
    /// Always Exact for the published graph contract.
    pub fidelity: MaterializationFidelity,
    /// Complete structured report.
    pub report: MaterializationReport,
    /// Complete graph-input-to-YAML provenance.
    pub provenance: GraphMaterializationProvenanceMap,
}

/// Closed graph materialization completion algebra.
#[derive(Clone, Debug)]
pub enum GraphMaterializationResult {
    /// Complete success with every required artifact.
    Complete(Box<CompleteGraphMaterialization>),
    /// Atomic failure without a candidate document.
    Failed(FailedGraphMaterializationAttempt),
}

/// Materializes one complete PortableGraph as a canonical YAML stream.
#[must_use]
pub fn materialize_graph(
    graph: &PortableGraph,
    request: &MaterializationRequest,
) -> GraphMaterializationResult {
    let mut analyzed = Vec::new();
    match materialize_graph_complete(graph, request, &mut analyzed) {
        Ok(complete) => GraphMaterializationResult::Complete(Box::new(complete)),
        Err(failure) => GraphMaterializationResult::Failed(FailedGraphMaterializationAttempt {
            failure,
            analyzed_input_nodes: analyzed,
        }),
    }
}

fn materialize_graph_complete(
    graph: &PortableGraph,
    request: &MaterializationRequest,
    analyzed: &mut Vec<GraphNodeId>,
) -> Result<CompleteGraphMaterialization, GraphMaterializationFailure> {
    let profile = requested_profile(request)?;
    let style = requested_style(request)?;
    requested_output_contract(request)?;
    let layout = GraphLayout::analyze(graph, request.limits())?;
    let mut writer = GraphWriter::new(graph, &layout, style, request, analyzed);
    writer.stream()?;
    let raw = encode_output(
        writer.output.finish(),
        request.encoding(),
        request.limits().max_output_bytes,
    )?;
    let document = parse(raw, profile, parse_limits(request.limits()))
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    let reparsed = document
        .project_graph()
        .map_err(|_| GraphMaterializationFailure::RoundTripMismatch)?;
    if &reparsed != graph {
        return Err(GraphMaterializationFailure::RoundTripMismatch);
    }
    let provenance = collect_graph_provenance(graph, &document, request.limits())?;
    Ok(CompleteGraphMaterialization {
        document,
        fidelity: MaterializationFidelity::Exact,
        report: MaterializationReport::default(),
        provenance,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YamlStyle {
    Block,
    Flow,
}

fn requested_profile(
    request: &MaterializationRequest,
) -> Result<YamlProfile, MaterializationFailure> {
    match (
        request.target_profile().id(),
        request.target_profile().version(),
    ) {
        ("yaml.1.2-core", 1) => Ok(YamlProfile::Yaml12CoreV1),
        ("yaml.1.1-compat", 1) => Ok(YamlProfile::Yaml11CompatV1),
        _ => Err(MaterializationFailure::UnsupportedProfile),
    }
}

fn requested_style(request: &MaterializationRequest) -> Result<YamlStyle, MaterializationFailure> {
    match (request.style().id(), request.style().version()) {
        ("yaml.canonical-block", 1) => Ok(YamlStyle::Block),
        ("yaml.canonical-flow", 1) => Ok(YamlStyle::Flow),
        _ => Err(MaterializationFailure::UnsupportedStyle),
    }
}

fn requested_output_contract(
    request: &MaterializationRequest,
) -> Result<(), MaterializationFailure> {
    if !matches!(
        request.encoding(),
        SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be
    ) {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    if request.newline() == NewlinePolicy::None {
        return Err(MaterializationFailure::UnsupportedNewline);
    }
    Ok(())
}

const fn parse_limits(limits: MaterializationLimits) -> ParseLimits {
    ParseLimits {
        max_source_bytes: limits.max_output_bytes,
        max_nesting_depth: limits.max_depth,
        max_token_count: limits.max_output_bytes,
        max_node_count: limits.max_input_nodes.saturating_mul(4),
        max_diagnostics: limits.max_report_entries,
    }
}

struct GraphLayout {
    anchor_names: HashMap<GraphNodeId, usize>,
}

impl GraphLayout {
    fn analyze(
        graph: &PortableGraph,
        limits: MaterializationLimits,
    ) -> Result<Self, GraphMaterializationFailure> {
        let mut canonical = Vec::with_capacity(graph.node_count());
        let mut canonical_ids = HashMap::with_capacity(graph.node_count());
        let mut stack = graph
            .roots()
            .iter()
            .rev()
            .copied()
            .map(|root| (root, 0_usize))
            .collect::<Vec<_>>();
        while let Some((id, depth)) = stack.pop() {
            if canonical_ids.contains_key(&id) {
                continue;
            }
            if depth > limits.max_depth {
                return Err(MaterializationFailure::ResourceLimit("input-depth").into());
            }
            if canonical.len() >= limits.max_input_nodes {
                return Err(MaterializationFailure::ResourceLimit("input-nodes").into());
            }
            let node = graph
                .node(id)
                .ok_or(MaterializationFailure::InvalidRequest("foreign graph node"))?;
            validate_tag_kind(id, node.tag(), node.kind())?;
            canonical_ids.insert(id, canonical.len());
            canonical.push(id);
            let child_depth = depth
                .checked_add(1)
                .ok_or(MaterializationFailure::ResourceLimit("input-depth"))?;
            match node.kind() {
                GraphNodeKind::Scalar => {}
                GraphNodeKind::Sequence => stack.extend(
                    node.sequence_items()
                        .expect("graph kind and view agree")
                        .iter()
                        .rev()
                        .copied()
                        .map(|child| (child, child_depth)),
                ),
                GraphNodeKind::Mapping => {
                    for entry in node
                        .mapping_entries()
                        .expect("graph kind and view agree")
                        .iter()
                        .rev()
                    {
                        stack.push((entry.value(), child_depth));
                        stack.push((entry.key(), child_depth));
                    }
                }
            }
        }

        let mut document_owner = HashMap::with_capacity(graph.node_count());
        let mut occurrences = HashMap::<GraphNodeId, usize>::with_capacity(graph.node_count());
        for (root_ordinal, root) in graph.roots().iter().copied().enumerate() {
            let mut seen = HashSet::new();
            let mut pending = vec![root];
            *occurrences.entry(root).or_default() = occurrences
                .get(&root)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            while let Some(id) = pending.pop() {
                if !seen.insert(id) {
                    continue;
                }
                if document_owner.insert(id, root_ordinal).is_some() {
                    return Err(GraphMaterializationFailure::CrossDocumentSharing { node: id });
                }
                let node = graph.node(id).expect("completed graph IDs resolve");
                match node.kind() {
                    GraphNodeKind::Scalar => {}
                    GraphNodeKind::Sequence => {
                        for child in node.sequence_items().expect("kind agrees") {
                            let count = occurrences.entry(*child).or_default();
                            *count = count.saturating_add(1);
                            pending.push(*child);
                        }
                    }
                    GraphNodeKind::Mapping => {
                        for entry in node.mapping_entries().expect("kind agrees") {
                            for child in [entry.key(), entry.value()] {
                                let count = occurrences.entry(child).or_default();
                                *count = count.saturating_add(1);
                                pending.push(child);
                            }
                        }
                    }
                }
            }
        }
        let anchor_names = canonical
            .iter()
            .copied()
            .filter(|id| occurrences.get(id).copied().unwrap_or(0) > 1)
            .enumerate()
            .map(|(anchor, id)| (id, anchor))
            .collect();
        Ok(Self { anchor_names })
    }
}

fn validate_tag_kind(
    node: GraphNodeId,
    tag: &str,
    kind: GraphNodeKind,
) -> Result<(), GraphMaterializationFailure> {
    let compatible = match tag {
        TAG_NULL | TAG_BOOL | TAG_INT | TAG_FLOAT | TAG_STR | TAG_TIMESTAMP | TAG_BINARY
        | TAG_MERGE | TAG_VALUE | TAG_YAML => kind == GraphNodeKind::Scalar,
        TAG_SEQ | TAG_OMAP | TAG_PAIRS => kind == GraphNodeKind::Sequence,
        TAG_MAP | TAG_SET => kind == GraphNodeKind::Mapping,
        _ => {
            return Err(GraphMaterializationFailure::UnsupportedTag {
                node,
                tag: tag.to_owned(),
            });
        }
    };
    if compatible {
        Ok(())
    } else {
        Err(GraphMaterializationFailure::TagKindMismatch {
            node,
            tag: tag.to_owned(),
        })
    }
}

struct GraphWriter<'a> {
    graph: &'a PortableGraph,
    layout: &'a GraphLayout,
    style: YamlStyle,
    newline: &'static str,
    limits: MaterializationLimits,
    output: BoundedText,
    emitted: HashSet<GraphNodeId>,
    analyzed: &'a mut Vec<GraphNodeId>,
}

impl<'a> GraphWriter<'a> {
    fn new(
        graph: &'a PortableGraph,
        layout: &'a GraphLayout,
        style: YamlStyle,
        request: &MaterializationRequest,
        analyzed: &'a mut Vec<GraphNodeId>,
    ) -> Self {
        Self {
            graph,
            layout,
            style,
            newline: match request.newline() {
                NewlinePolicy::Lf => "\n",
                NewlinePolicy::CrLf => "\r\n",
                NewlinePolicy::None => unreachable!("validated request"),
            },
            limits: request.limits(),
            output: BoundedText::new(request.limits().max_output_bytes),
            emitted: HashSet::new(),
            analyzed,
        }
    }

    fn stream(&mut self) -> Result<(), GraphMaterializationFailure> {
        for (ordinal, root) in self.graph.roots().iter().copied().enumerate() {
            if ordinal != 0 {
                self.output.push_str(self.newline)?;
            }
            self.emitted.clear();
            self.output.push_str("---")?;
            match self.style {
                YamlStyle::Block => self.block_after_indicator(root, 0, 0)?,
                YamlStyle::Flow => {
                    self.output.push_char(' ')?;
                    self.flow_node(root, 0)?;
                }
            }
            self.output.push_str(self.newline)?;
        }
        Ok(())
    }

    fn flow_node(
        &mut self,
        id: GraphNodeId,
        depth: usize,
    ) -> Result<(), GraphMaterializationFailure> {
        if self.write_alias_if_emitted(id)? {
            return Ok(());
        }
        self.begin_definition(id, depth)?;
        self.write_properties(id)?;
        let node = self.graph.node(id).expect("completed graph IDs resolve");
        match node.kind() {
            GraphNodeKind::Scalar => {
                self.output.push_char(' ')?;
                self.write_quoted(node.scalar_content().expect("kind agrees"))
            }
            GraphNodeKind::Sequence => {
                self.output.push_str(" [")?;
                for (index, child) in node
                    .sequence_items()
                    .expect("kind agrees")
                    .iter()
                    .copied()
                    .enumerate()
                {
                    if index != 0 {
                        self.output.push_str(", ")?;
                    }
                    self.flow_node(child, depth.saturating_add(1))?;
                }
                self.output.push_char(']')
            }
            GraphNodeKind::Mapping => {
                self.output.push_str(" {")?;
                for (index, entry) in node
                    .mapping_entries()
                    .expect("kind agrees")
                    .iter()
                    .enumerate()
                {
                    if index != 0 {
                        self.output.push_str(", ")?;
                    }
                    self.output.push_str("? ")?;
                    self.flow_node(entry.key(), depth.saturating_add(1))?;
                    self.output.push_str(" : ")?;
                    self.flow_node(entry.value(), depth.saturating_add(1))?;
                }
                self.output.push_char('}')
            }
        }
    }

    fn block_after_indicator(
        &mut self,
        id: GraphNodeId,
        child_indent: usize,
        depth: usize,
    ) -> Result<(), GraphMaterializationFailure> {
        if self.emitted.contains(&id) {
            self.output.push_char(' ')?;
            return self.write_alias(id);
        }
        let node = self.graph.node(id).expect("completed graph IDs resolve");
        let block = match node.kind() {
            GraphNodeKind::Scalar => false,
            GraphNodeKind::Sequence => !node.sequence_items().expect("kind agrees").is_empty(),
            GraphNodeKind::Mapping => !node.mapping_entries().expect("kind agrees").is_empty(),
        };
        self.begin_definition(id, depth)?;
        self.output.push_char(' ')?;
        self.write_properties(id)?;
        if block {
            self.output.push_str(self.newline)?;
            self.block_content(id, child_indent, depth)
        } else {
            match node.kind() {
                GraphNodeKind::Scalar => {
                    self.output.push_char(' ')?;
                    self.write_quoted(node.scalar_content().expect("kind agrees"))
                }
                GraphNodeKind::Sequence => self.output.push_str(" []"),
                GraphNodeKind::Mapping => self.output.push_str(" {}"),
            }
        }
    }

    fn block_content(
        &mut self,
        id: GraphNodeId,
        indent: usize,
        depth: usize,
    ) -> Result<(), GraphMaterializationFailure> {
        let node = self.graph.node(id).expect("completed graph IDs resolve");
        match node.kind() {
            GraphNodeKind::Scalar => Err(GraphMaterializationFailure::RoundTripMismatch),
            GraphNodeKind::Sequence => {
                let items = node.sequence_items().expect("kind agrees");
                for (index, child) in items.iter().copied().enumerate() {
                    if index != 0 {
                        self.output.push_str(self.newline)?;
                    }
                    self.indent(indent)?;
                    self.output.push_char('-')?;
                    self.block_after_indicator(
                        child,
                        indent.saturating_add(2),
                        depth.saturating_add(1),
                    )?;
                }
                Ok(())
            }
            GraphNodeKind::Mapping => {
                let entries = node.mapping_entries().expect("kind agrees");
                for (index, entry) in entries.iter().enumerate() {
                    if index != 0 {
                        self.output.push_str(self.newline)?;
                    }
                    self.indent(indent)?;
                    self.output.push_char('?')?;
                    self.block_after_indicator(
                        entry.key(),
                        indent.saturating_add(2),
                        depth.saturating_add(1),
                    )?;
                    self.output.push_str(self.newline)?;
                    self.indent(indent)?;
                    self.output.push_char(':')?;
                    self.block_after_indicator(
                        entry.value(),
                        indent.saturating_add(2),
                        depth.saturating_add(1),
                    )?;
                }
                Ok(())
            }
        }
    }

    fn begin_definition(
        &mut self,
        id: GraphNodeId,
        depth: usize,
    ) -> Result<(), GraphMaterializationFailure> {
        if depth > self.limits.max_depth {
            return Err(MaterializationFailure::ResourceLimit("input-depth").into());
        }
        if !self.emitted.insert(id) {
            return Err(GraphMaterializationFailure::RoundTripMismatch);
        }
        if self.analyzed.len() >= self.limits.max_input_nodes {
            return Err(MaterializationFailure::ResourceLimit("input-nodes").into());
        }
        self.analyzed.push(id);
        Ok(())
    }

    fn write_alias_if_emitted(
        &mut self,
        id: GraphNodeId,
    ) -> Result<bool, GraphMaterializationFailure> {
        if self.emitted.contains(&id) {
            self.write_alias(id)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn write_alias(&mut self, id: GraphNodeId) -> Result<(), GraphMaterializationFailure> {
        let anchor = self
            .layout
            .anchor_names
            .get(&id)
            .ok_or(GraphMaterializationFailure::RoundTripMismatch)?;
        write!(&mut self.output, "*g{anchor}")
            .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes").into())
    }

    fn write_properties(&mut self, id: GraphNodeId) -> Result<(), GraphMaterializationFailure> {
        if let Some(anchor) = self.layout.anchor_names.get(&id) {
            write!(&mut self.output, "&g{anchor} ")
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
        }
        let tag = self
            .graph
            .node(id)
            .expect("completed graph IDs resolve")
            .tag();
        let suffix = tag.strip_prefix("tag:yaml.org,2002:").ok_or_else(|| {
            GraphMaterializationFailure::UnsupportedTag {
                node: id,
                tag: tag.to_owned(),
            }
        })?;
        write!(&mut self.output, "!!{suffix}")
            .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes").into())
    }

    fn write_quoted(&mut self, value: &str) -> Result<(), GraphMaterializationFailure> {
        self.output.push_char('"')?;
        for character in value.chars() {
            match character {
                '"' => self.output.push_str("\\\"")?,
                '\\' => self.output.push_str("\\\\")?,
                '\u{0008}' => self.output.push_str("\\b")?,
                '\u{0009}' => self.output.push_str("\\t")?,
                '\n' => self.output.push_str("\\n")?,
                '\u{000c}' => self.output.push_str("\\f")?,
                '\r' => self.output.push_str("\\r")?,
                '\u{0000}'..='\u{001f}' | '\u{007f}' => {
                    write!(&mut self.output, "\\u{:04x}", u32::from(character))
                        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
                }
                _ => self.output.push_char(character)?,
            }
        }
        self.output.push_char('"')?;
        Ok(())
    }

    fn indent(&mut self, spaces: usize) -> Result<(), GraphMaterializationFailure> {
        for _ in 0..spaces {
            self.output.push_char(' ')?;
        }
        Ok(())
    }
}

struct BoundedText {
    text: String,
    max: usize,
}

impl BoundedText {
    const fn new(max: usize) -> Self {
        Self {
            text: String::new(),
            max,
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), GraphMaterializationFailure> {
        let length = self
            .text
            .len()
            .checked_add(value.len())
            .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
        if length > self.max {
            return Err(MaterializationFailure::ResourceLimit("output-bytes").into());
        }
        self.text
            .try_reserve(value.len())
            .map_err(|_| MaterializationFailure::ResourceLimit("output-allocation"))?;
        self.text.push_str(value);
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), GraphMaterializationFailure> {
        let mut encoded = [0_u8; 4];
        self.push_str(value.encode_utf8(&mut encoded))
    }

    fn finish(self) -> String {
        self.text
    }
}

impl fmt::Write for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_str(value).map_err(|_| fmt::Error)
    }
}

fn encode_output(
    text: String,
    encoding: SourceEncoding,
    max: usize,
) -> Result<Vec<u8>, MaterializationFailure> {
    match encoding {
        SourceEncoding::Utf8 => {
            if text.len() > max {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            Ok(text.into_bytes())
        }
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => {
            let units = text.encode_utf16().count();
            let length = units
                .checked_mul(2)
                .and_then(|length| length.checked_add(2))
                .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
            if length > max {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            let mut output = Vec::new();
            output
                .try_reserve(length)
                .map_err(|_| MaterializationFailure::ResourceLimit("output-allocation"))?;
            output.extend_from_slice(if encoding == SourceEncoding::Utf16Le {
                &[0xff, 0xfe]
            } else {
                &[0xfe, 0xff]
            });
            for unit in text.encode_utf16() {
                let bytes = if encoding == SourceEncoding::Utf16Le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                };
                output.extend_from_slice(&bytes);
            }
            Ok(output)
        }
        SourceEncoding::Binary | SourceEncoding::Latin1 => {
            Err(MaterializationFailure::UnsupportedEncoding)
        }
    }
}

fn collect_graph_provenance(
    graph: &PortableGraph,
    document: &Document,
    limits: MaterializationLimits,
) -> Result<GraphMaterializationProvenanceMap, GraphMaterializationFailure> {
    if graph.roots().len() != document.document_count() {
        return Err(GraphMaterializationFailure::RoundTripMismatch);
    }
    let mut builder = GraphProvenanceBuilder {
        document,
        limits,
        units: 0,
        entries: Vec::new(),
        seen: HashSet::new(),
    };
    for (index, input_root) in graph.roots().iter().copied().enumerate() {
        let output_document = document
            .document(index)
            .ok_or(GraphMaterializationFailure::RoundTripMismatch)?;
        builder.push(
            GraphMaterializationInputLocation::Root(
                u64::try_from(index)
                    .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?,
            ),
            MaterializedOrigin {
                snapshot: document.snapshot_identity(),
                node: output_document.node_ref(),
                span: output_document.span(),
                relation: consema_document::MaterializationRelation::Generated,
            },
        )?;
        builder.collect_node(graph, input_root, output_document.root())?;
    }
    Ok(GraphMaterializationProvenanceMap {
        entries: builder.entries,
    })
}

struct GraphProvenanceBuilder<'a> {
    document: &'a Document,
    limits: MaterializationLimits,
    units: usize,
    entries: Vec<GraphMaterializationProvenanceEntry>,
    seen: HashSet<GraphNodeId>,
}

impl GraphProvenanceBuilder<'_> {
    fn collect_node(
        &mut self,
        graph: &PortableGraph,
        input: GraphNodeId,
        output: YamlNode<'_>,
    ) -> Result<(), GraphMaterializationFailure> {
        if !self.seen.insert(input) {
            return Ok(());
        }
        let node = graph
            .node(input)
            .ok_or(GraphMaterializationFailure::RoundTripMismatch)?;
        let expected_kind = match node.kind() {
            GraphNodeKind::Scalar => YamlNodeKind::Scalar,
            GraphNodeKind::Sequence => YamlNodeKind::Sequence,
            GraphNodeKind::Mapping => YamlNodeKind::Mapping,
        };
        if output.kind() != expected_kind || output.tag() != node.tag() {
            return Err(GraphMaterializationFailure::RoundTripMismatch);
        }
        if node.kind() == GraphNodeKind::Scalar
            && output.scalar().map(super::YamlScalar::canonical) != node.scalar_content()
        {
            return Err(GraphMaterializationFailure::RoundTripMismatch);
        }
        self.push(
            GraphMaterializationInputLocation::Node(input),
            self.origin(
                output.node_ref(),
                output.span(),
                consema_document::MaterializationRelation::Direct,
            ),
        )?;
        match node.kind() {
            GraphNodeKind::Scalar => Ok(()),
            GraphNodeKind::Sequence => {
                let children = node.sequence_items().expect("kind agrees");
                if output.sequence_len() != Some(children.len()) {
                    return Err(GraphMaterializationFailure::RoundTripMismatch);
                }
                for (index, child) in children.iter().copied().enumerate() {
                    let edge = output
                        .sequence_item(index)
                        .ok_or(GraphMaterializationFailure::RoundTripMismatch)?;
                    let location = GraphMaterializationInputLocation::SequenceElement {
                        parent: input,
                        ordinal: u64::try_from(index).map_err(|_| {
                            MaterializationFailure::ResourceLimit("provenance-entries")
                        })?,
                    };
                    self.push(
                        location,
                        self.origin(
                            edge.node_ref(),
                            edge.span(),
                            consema_document::MaterializationRelation::Direct,
                        ),
                    )?;
                    if let Some(alias) = edge.alias() {
                        self.add(
                            location,
                            self.origin(
                                alias.node_ref(),
                                alias.span(),
                                consema_document::MaterializationRelation::Reencoded,
                            ),
                        )?;
                    }
                    self.collect_node(graph, child, edge.node())?;
                }
                Ok(())
            }
            GraphNodeKind::Mapping => {
                let entries = node.mapping_entries().expect("kind agrees");
                if output.mapping_len() != Some(entries.len()) {
                    return Err(GraphMaterializationFailure::RoundTripMismatch);
                }
                for (index, entry) in entries.iter().enumerate() {
                    let output_entry = output
                        .mapping_entry(index)
                        .ok_or(GraphMaterializationFailure::RoundTripMismatch)?;
                    let ordinal = u64::try_from(index)
                        .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
                    for (location, alias) in [
                        (
                            GraphMaterializationInputLocation::MappingKey {
                                parent: input,
                                ordinal,
                            },
                            output_entry.key_alias(),
                        ),
                        (
                            GraphMaterializationInputLocation::MappingValue {
                                parent: input,
                                ordinal,
                            },
                            output_entry.value_alias(),
                        ),
                    ] {
                        self.push(
                            location,
                            self.origin(
                                output_entry.node_ref(),
                                output_entry.span(),
                                consema_document::MaterializationRelation::Direct,
                            ),
                        )?;
                        if let Some(alias) = alias {
                            self.add(
                                location,
                                self.origin(
                                    alias.node_ref(),
                                    alias.span(),
                                    consema_document::MaterializationRelation::Reencoded,
                                ),
                            )?;
                        }
                    }
                    self.collect_node(graph, entry.key(), output_entry.key())?;
                    self.collect_node(graph, entry.value(), output_entry.value())?;
                }
                Ok(())
            }
        }
    }

    fn origin(
        &self,
        node: consema_document::NodeRef,
        span: consema_document::Span,
        relation: consema_document::MaterializationRelation,
    ) -> MaterializedOrigin {
        MaterializedOrigin {
            snapshot: self.document.snapshot_identity(),
            node,
            span,
            relation,
        }
    }

    fn push(
        &mut self,
        input: GraphMaterializationInputLocation,
        output: MaterializedOrigin,
    ) -> Result<(), GraphMaterializationFailure> {
        self.units = self
            .units
            .checked_add(2)
            .ok_or(MaterializationFailure::ResourceLimit("provenance-entries"))?;
        if self.units > self.limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries").into());
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("provenance-allocation"))?;
        self.entries.push(GraphMaterializationProvenanceEntry {
            input,
            outputs: vec![output],
        });
        Ok(())
    }

    fn add(
        &mut self,
        input: GraphMaterializationInputLocation,
        output: MaterializedOrigin,
    ) -> Result<(), GraphMaterializationFailure> {
        self.units = self
            .units
            .checked_add(1)
            .ok_or(MaterializationFailure::ResourceLimit("provenance-entries"))?;
        if self.units > self.limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries").into());
        }
        self.entries
            .iter_mut()
            .find(|entry| entry.input == input)
            .ok_or(GraphMaterializationFailure::RoundTripMismatch)?
            .outputs
            .push(output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{MaterializationStyleId, ProfileId};
    use consema_graph::{GraphBuilder, GraphLimits, GraphMappingEntry};

    fn request(style: &str) -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("yaml.1.2-core", 1),
            MaterializationStyleId::new(style, 1),
        )
    }

    fn complete(result: GraphMaterializationResult) -> CompleteGraphMaterialization {
        match result {
            GraphMaterializationResult::Complete(complete) => *complete,
            GraphMaterializationResult::Failed(failed) => {
                panic!("graph materialization failed: {failed:?}")
            }
        }
    }

    #[test]
    fn flow_materialization_anchors_a_cycle_and_round_trips() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        builder.define_sequence(root, TAG_SEQ, vec![root]).unwrap();
        builder.push_root(root).unwrap();
        let graph = builder.build().unwrap();

        let complete = complete(materialize_graph(&graph, &request("yaml.canonical-flow")));
        assert_eq!(
            std::str::from_utf8(complete.document.render()).unwrap(),
            "--- &g0 !!seq [*g0]\n"
        );
        assert_eq!(complete.document.project_graph().unwrap(), graph);
        assert!(complete.provenance.entries().iter().any(|entry| {
            matches!(
                entry.input,
                GraphMaterializationInputLocation::SequenceElement { .. }
            ) && entry.outputs.len() == 2
        }));
    }

    #[test]
    fn block_materialization_preserves_arbitrary_mapping_order() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        let key = builder.reserve_node().unwrap();
        let key_item = builder.reserve_node().unwrap();
        let value = builder.reserve_node().unwrap();
        builder.define_scalar(key_item, TAG_STR, "k").unwrap();
        builder
            .define_sequence(key, TAG_SEQ, vec![key_item])
            .unwrap();
        builder.define_scalar(value, TAG_INT, "7").unwrap();
        builder
            .define_mapping(root, TAG_MAP, vec![GraphMappingEntry::new(key, value)])
            .unwrap();
        builder.push_root(root).unwrap();
        let graph = builder.build().unwrap();

        let complete = complete(materialize_graph(&graph, &request("yaml.canonical-block")));
        let text = std::str::from_utf8(complete.document.render()).unwrap();
        assert!(text.contains("? !!seq\n  - !!str \"k\"\n: !!int \"7\""));
        assert_eq!(complete.document.project_graph().unwrap(), graph);
    }

    #[test]
    fn document_scoped_anchors_reject_cross_root_sharing() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let shared = builder.reserve_node().unwrap();
        builder.define_scalar(shared, TAG_STR, "x").unwrap();
        builder
            .push_root(shared)
            .unwrap()
            .push_root(shared)
            .unwrap();
        let graph = builder.build().unwrap();
        assert!(matches!(
            materialize_graph(&graph, &request("yaml.canonical-flow")),
            GraphMaterializationResult::Failed(FailedGraphMaterializationAttempt {
                failure: GraphMaterializationFailure::CrossDocumentSharing { node },
                ..
            }) if node == shared
        ));
    }

    #[test]
    fn utf16_and_crlf_are_explicit_and_reparsed() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        builder.define_scalar(root, TAG_STR, "é").unwrap();
        builder.push_root(root).unwrap();
        let graph = builder.build().unwrap();
        let complete = complete(materialize_graph(
            &graph,
            &request("yaml.canonical-flow")
                .with_encoding(SourceEncoding::Utf16Be)
                .with_newline(NewlinePolicy::CrLf),
        ));
        assert_eq!(&complete.document.render()[..2], &[0xfe, 0xff]);
        assert_eq!(
            complete.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Be
        );
        assert_eq!(complete.document.project_graph().unwrap(), graph);
    }
}
