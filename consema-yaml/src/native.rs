use std::collections::HashMap;
use std::sync::Arc;

use consema_core::{BigInteger, Decimal};
use consema_document::{
    DecodedOffset, DocumentAuthority, FatalFormationFailure, NodeRef, NodeRole, ParseLimits,
    SourceSnapshot, Span,
};
use consema_graph::{
    GraphBuildError, GraphBuilder, GraphLimits, GraphMappingEntry, GraphNodeId, PortableGraph,
};

use crate::backend::{BackendEvent, BackendEventKind, BackendScalarStyle, BackendSpan, BackendTag};
use crate::syntax::NamedOccurrence;
use crate::{YamlProfile, YamlScalarKind, YamlScalarStyle};

pub(crate) const TAG_NULL: &str = "tag:yaml.org,2002:null";
pub(crate) const TAG_BOOL: &str = "tag:yaml.org,2002:bool";
pub(crate) const TAG_INT: &str = "tag:yaml.org,2002:int";
pub(crate) const TAG_FLOAT: &str = "tag:yaml.org,2002:float";
pub(crate) const TAG_STR: &str = "tag:yaml.org,2002:str";
pub(crate) const TAG_SEQ: &str = "tag:yaml.org,2002:seq";
pub(crate) const TAG_MAP: &str = "tag:yaml.org,2002:map";
pub(crate) const TAG_TIMESTAMP: &str = "tag:yaml.org,2002:timestamp";
pub(crate) const TAG_BINARY: &str = "tag:yaml.org,2002:binary";
pub(crate) const TAG_MERGE: &str = "tag:yaml.org,2002:merge";
pub(crate) const TAG_OMAP: &str = "tag:yaml.org,2002:omap";
pub(crate) const TAG_PAIRS: &str = "tag:yaml.org,2002:pairs";
pub(crate) const TAG_SET: &str = "tag:yaml.org,2002:set";
pub(crate) const TAG_VALUE: &str = "tag:yaml.org,2002:value";
pub(crate) const TAG_YAML: &str = "tag:yaml.org,2002:yaml";

#[derive(Clone, Debug)]
pub(crate) struct NativeStream {
    pub(crate) nodes: Arc<[NativeNode]>,
    pub(crate) documents: Arc<[NativeDocument]>,
    pub(crate) aliases: Arc<[NativeAlias]>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeDocument {
    pub(crate) root: usize,
    pub(crate) span: Span,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeNode {
    pub(crate) tag: Arc<str>,
    pub(crate) anchor: Option<Arc<str>>,
    pub(crate) anchor_span: Option<Span>,
    pub(crate) span: Span,
    pub(crate) content: NativeContent,
}

#[derive(Clone, Debug)]
pub(crate) enum NativeContent {
    Scalar(NativeScalar),
    Sequence(Arc<[NativeSequenceItem]>),
    Mapping(Arc<[NativeMappingEntry]>),
}

#[derive(Clone, Debug)]
pub(crate) struct NativeScalar {
    pub(crate) decoded: Arc<str>,
    pub(crate) canonical: Arc<str>,
    pub(crate) kind: YamlScalarKind,
    pub(crate) style: YamlScalarStyle,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSequenceItem {
    pub(crate) identity: u64,
    pub(crate) node: usize,
    pub(crate) span: Span,
    pub(crate) alias: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeMappingEntry {
    pub(crate) identity: u64,
    pub(crate) key: usize,
    pub(crate) value: usize,
    pub(crate) span: Span,
    pub(crate) key_alias: Option<usize>,
    pub(crate) value_alias: Option<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeAlias {
    pub(crate) identity: u64,
    pub(crate) name: Arc<str>,
    pub(crate) target: usize,
    pub(crate) span: Span,
}

/// Exact YAML-to-PortableGraph projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphProjectionError {
    /// A custom tag has no frozen graph canonicalization.
    UnsupportedTag(String),
    /// Graph construction rejected a resource or topology fact.
    Graph(GraphBuildError),
}

impl From<GraphBuildError> for GraphProjectionError {
    fn from(error: GraphBuildError) -> Self {
        Self::Graph(error)
    }
}

pub(crate) fn compose(
    events: &[BackendEvent],
    source: &SourceSnapshot,
    authority: &DocumentAuthority,
    profile: YamlProfile,
    anchors: Vec<NamedOccurrence>,
    aliases: Vec<NamedOccurrence>,
    limits: ParseLimits,
) -> Result<NativeStream, FatalFormationFailure> {
    Composer {
        events,
        source,
        authority,
        position: 0,
        profile,
        limits,
        nodes: Vec::new(),
        documents: Vec::new(),
        anchors: HashMap::new(),
        anchor_occurrences: anchors.into_iter(),
        anchor_name_by_id: HashMap::new(),
        alias_occurrences: aliases.into_iter(),
        composed_aliases: Vec::new(),
        next_association: 0,
    }
    .compose()
}

impl NativeStream {
    pub(crate) fn project_graph(
        &self,
        limits: GraphLimits,
    ) -> Result<PortableGraph, GraphProjectionError> {
        self.project_graph_with_ids(limits).map(|(graph, _)| graph)
    }

    pub(crate) fn project_graph_with_ids(
        &self,
        limits: GraphLimits,
    ) -> Result<(PortableGraph, Vec<GraphNodeId>), GraphProjectionError> {
        let mut builder = GraphBuilder::new(limits);
        let ids = (0..self.nodes.len())
            .map(|_| builder.reserve_node())
            .collect::<Result<Vec<_>, _>>()?;
        for (index, node) in self.nodes.iter().enumerate() {
            if !is_standard_graph_tag(&node.tag) {
                return Err(GraphProjectionError::UnsupportedTag(node.tag.to_string()));
            }
            match &node.content {
                NativeContent::Scalar(scalar) => {
                    builder.define_scalar(
                        ids[index],
                        node.tag.clone(),
                        scalar.canonical.clone(),
                    )?;
                }
                NativeContent::Sequence(items) => {
                    builder.define_sequence(
                        ids[index],
                        node.tag.clone(),
                        items.iter().map(|item| ids[item.node]).collect(),
                    )?;
                }
                NativeContent::Mapping(entries) => {
                    builder.define_mapping(
                        ids[index],
                        node.tag.clone(),
                        entries
                            .iter()
                            .map(|entry| GraphMappingEntry::new(ids[entry.key], ids[entry.value]))
                            .collect(),
                    )?;
                }
            }
        }
        for document in self.documents.iter() {
            builder.push_root(ids[document.root])?;
        }
        let graph = builder.build()?;
        Ok((graph, ids))
    }
}

struct Composer<'a> {
    events: &'a [BackendEvent],
    source: &'a SourceSnapshot,
    authority: &'a DocumentAuthority,
    position: usize,
    profile: YamlProfile,
    limits: ParseLimits,
    nodes: Vec<Option<NativeNode>>,
    documents: Vec<NativeDocument>,
    anchors: HashMap<usize, usize>,
    anchor_occurrences: std::vec::IntoIter<NamedOccurrence>,
    anchor_name_by_id: HashMap<usize, Arc<str>>,
    alias_occurrences: std::vec::IntoIter<NamedOccurrence>,
    composed_aliases: Vec<NativeAlias>,
    next_association: u64,
}

#[derive(Clone, Copy)]
struct ComposedOccurrence {
    node: usize,
    span: Span,
    alias: Option<usize>,
}

impl Composer<'_> {
    fn compose(mut self) -> Result<NativeStream, FatalFormationFailure> {
        self.expect_simple(|kind| matches!(kind, BackendEventKind::StreamStart))?;
        while !self.peek_is(|kind| matches!(kind, BackendEventKind::StreamEnd)) {
            let document_start =
                self.take_simple(|kind| matches!(kind, BackendEventKind::DocumentStart { .. }))?;
            self.anchors.clear();
            self.anchor_name_by_id.clear();
            let root = self.node()?;
            let document_end =
                self.take_simple(|kind| matches!(kind, BackendEventKind::DocumentEnd))?;
            self.documents.push(NativeDocument {
                root: root.node,
                span: self.covering_span(document_start, document_end)?,
            });
        }
        self.expect_simple(|kind| matches!(kind, BackendEventKind::StreamEnd))?;
        if self.position != self.events.len() {
            return Err(native_failure("yaml.native.trailing-events@1"));
        }
        if self.anchor_occurrences.next().is_some() || self.alias_occurrences.next().is_some() {
            return Err(native_failure("yaml.native.trailing-named-occurrence@1"));
        }
        let nodes = self
            .nodes
            .into_iter()
            .map(|node| node.expect("every reserved YAML node is defined"))
            .collect::<Vec<_>>();
        Ok(NativeStream {
            nodes: Arc::from(nodes),
            documents: Arc::from(self.documents),
            aliases: Arc::from(self.composed_aliases),
        })
    }

    fn node(&mut self) -> Result<ComposedOccurrence, FatalFormationFailure> {
        let event = self
            .events
            .get(self.position)
            .cloned()
            .ok_or_else(|| native_failure("yaml.native.unexpected-end@1"))?;
        self.position += 1;
        match event.kind {
            BackendEventKind::Alias { anchor_id } => {
                let target = self
                    .anchors
                    .get(&anchor_id)
                    .copied()
                    .ok_or_else(|| native_failure("yaml.anchor.unknown@1"))?;
                let occurrence = self
                    .alias_occurrences
                    .next()
                    .ok_or_else(|| native_failure("yaml.alias.name-unavailable@1"))?;
                let name = Arc::<str>::from(occurrence.name);
                if self.anchor_name_by_id.get(&anchor_id).map(AsRef::as_ref) != Some(name.as_ref())
                {
                    return Err(native_failure("yaml.alias.name-mismatch@1"));
                }
                let identity = self.association_identity()?;
                let alias = self.composed_aliases.len();
                self.composed_aliases.push(NativeAlias {
                    identity,
                    name,
                    target,
                    span: occurrence.span,
                });
                Ok(ComposedOccurrence {
                    node: target,
                    span: occurrence.span,
                    alias: Some(alias),
                })
            }
            BackendEventKind::Scalar {
                decoded,
                style,
                anchor_id,
                tag,
            } => {
                let index = self.reserve_node()?;
                let (anchor, anchor_span) = self.register_anchor(anchor_id, index)?;
                let decoded = exact_empty_scalar(
                    decoded,
                    event.span,
                    self.source
                        .decoded_text()
                        .expect("YAML source is always decoded text"),
                );
                let (tag, scalar) = resolve_scalar(&decoded, style, tag.as_ref(), self.profile)?;
                let span = self.raw_span(event.span)?;
                self.nodes[index] = Some(NativeNode {
                    tag: Arc::from(tag),
                    anchor,
                    anchor_span,
                    span,
                    content: NativeContent::Scalar(scalar),
                });
                Ok(ComposedOccurrence {
                    node: index,
                    span,
                    alias: None,
                })
            }
            BackendEventKind::SequenceStart { anchor_id, tag } => {
                let index = self.reserve_node()?;
                let (anchor, anchor_span) = self.register_anchor(anchor_id, index)?;
                let tag = resolve_collection_tag(tag.as_ref(), TAG_SEQ)?;
                let mut items = Vec::new();
                while !self.peek_is(|kind| matches!(kind, BackendEventKind::SequenceEnd)) {
                    let occurrence = self.node()?;
                    items.push(NativeSequenceItem {
                        identity: self.association_identity()?,
                        node: occurrence.node,
                        span: occurrence.span,
                        alias: occurrence.alias,
                    });
                }
                let end = self.take_simple(|kind| matches!(kind, BackendEventKind::SequenceEnd))?;
                let span = self.covering_span(event.span, end)?;
                self.nodes[index] = Some(NativeNode {
                    tag: Arc::from(tag),
                    anchor,
                    anchor_span,
                    span,
                    content: NativeContent::Sequence(Arc::from(items)),
                });
                Ok(ComposedOccurrence {
                    node: index,
                    span,
                    alias: None,
                })
            }
            BackendEventKind::MappingStart { anchor_id, tag } => {
                let index = self.reserve_node()?;
                let (anchor, anchor_span) = self.register_anchor(anchor_id, index)?;
                let tag = resolve_collection_tag(tag.as_ref(), TAG_MAP)?;
                let mut entries = Vec::new();
                while !self.peek_is(|kind| matches!(kind, BackendEventKind::MappingEnd)) {
                    let key = self.node()?;
                    if self.peek_is(|kind| matches!(kind, BackendEventKind::MappingEnd)) {
                        return Err(native_failure("yaml.mapping.missing-value@1"));
                    }
                    let value = self.node()?;
                    entries.push(NativeMappingEntry {
                        identity: self.association_identity()?,
                        key: key.node,
                        value: value.node,
                        span: self.covering_raw_spans(key.span, value.span)?,
                        key_alias: key.alias,
                        value_alias: value.alias,
                    });
                }
                let end = self.take_simple(|kind| matches!(kind, BackendEventKind::MappingEnd))?;
                let span = self.covering_span(event.span, end)?;
                self.nodes[index] = Some(NativeNode {
                    tag: Arc::from(tag),
                    anchor,
                    anchor_span,
                    span,
                    content: NativeContent::Mapping(Arc::from(entries)),
                });
                Ok(ComposedOccurrence {
                    node: index,
                    span,
                    alias: None,
                })
            }
            _ => Err(native_failure("yaml.native.unexpected-event@1")),
        }
    }

    fn reserve_node(&mut self) -> Result<usize, FatalFormationFailure> {
        let observed = self.nodes.len().saturating_add(1);
        if observed > self.limits.max_node_count {
            return Err(FatalFormationFailure::resource_limit(
                "native-nodes",
                observed,
                self.limits.max_node_count,
            ));
        }
        let index = self.nodes.len();
        self.nodes.push(None);
        Ok(index)
    }

    fn register_anchor(
        &mut self,
        anchor_id: Option<usize>,
        node: usize,
    ) -> Result<(Option<Arc<str>>, Option<Span>), FatalFormationFailure> {
        let Some(anchor_id) = anchor_id else {
            return Ok((None, None));
        };
        let occurrence = self
            .anchor_occurrences
            .next()
            .ok_or_else(|| native_failure("yaml.anchor.name-unavailable@1"))?;
        let name = Arc::<str>::from(occurrence.name);
        self.anchors.insert(anchor_id, node);
        self.anchor_name_by_id.insert(anchor_id, name.clone());
        Ok((Some(name), Some(occurrence.span)))
    }

    fn association_identity(&mut self) -> Result<u64, FatalFormationFailure> {
        let identity = self.next_association;
        self.next_association = self.next_association.checked_add(1).ok_or_else(|| {
            FatalFormationFailure::resource_limit(
                "association-identity",
                usize::MAX,
                usize::MAX - 1,
            )
        })?;
        Ok(identity)
    }

    fn peek_is(&self, predicate: impl FnOnce(&BackendEventKind) -> bool) -> bool {
        self.events
            .get(self.position)
            .is_some_and(|event| predicate(&event.kind))
    }

    fn expect_simple(
        &mut self,
        predicate: impl FnOnce(&BackendEventKind) -> bool,
    ) -> Result<(), FatalFormationFailure> {
        self.take_simple(predicate).map(|_| ())
    }

    fn take_simple(
        &mut self,
        predicate: impl FnOnce(&BackendEventKind) -> bool,
    ) -> Result<BackendSpan, FatalFormationFailure> {
        if !self.peek_is(predicate) {
            return Err(native_failure("yaml.native.unexpected-event@1"));
        }
        let span = self.events[self.position].span;
        self.position += 1;
        Ok(span)
    }

    fn raw_span(&self, span: BackendSpan) -> Result<Span, FatalFormationFailure> {
        let start = self
            .source
            .raw_byte_at(DecodedOffset::UnicodeScalar(span.start_scalar))
            .map_err(|_| native_failure("yaml.native.invalid-source-span@1"))?;
        let end = self
            .source
            .raw_byte_at(DecodedOffset::UnicodeScalar(span.end_scalar))
            .map_err(|_| native_failure("yaml.native.invalid-source-span@1"))?;
        self.authority
            .span(start, end)
            .map_err(|_| native_failure("yaml.native.invalid-source-span@1"))
    }

    fn covering_span(
        &self,
        start: BackendSpan,
        end: BackendSpan,
    ) -> Result<Span, FatalFormationFailure> {
        self.raw_span(BackendSpan {
            start_scalar: start.start_scalar,
            end_scalar: end.end_scalar,
        })
    }

    fn covering_raw_spans(&self, start: Span, end: Span) -> Result<Span, FatalFormationFailure> {
        self.authority
            .span(start.start_byte(), end.end_byte())
            .map_err(|_| native_failure("yaml.native.invalid-source-span@1"))
    }
}

fn exact_empty_scalar(decoded: String, span: BackendSpan, text: &str) -> String {
    let presentation = text
        .chars()
        .skip(span.start_scalar)
        .take(span.end_scalar.saturating_sub(span.start_scalar))
        .collect::<String>();
    if decoded == "~" && presentation != "~" {
        String::new()
    } else {
        decoded
    }
}

fn resolve_collection_tag(
    explicit: Option<&BackendTag>,
    expected: &'static str,
) -> Result<String, FatalFormationFailure> {
    let Some(tag) = explicit else {
        return Ok(expected.to_owned());
    };
    let resolved = resolved_tag(tag);
    if resolved == "!" {
        return Ok(expected.to_owned());
    }
    let valid_collection = match expected {
        TAG_SEQ => matches!(resolved.as_str(), TAG_SEQ | TAG_OMAP | TAG_PAIRS),
        TAG_MAP => matches!(resolved.as_str(), TAG_MAP | TAG_SET),
        _ => false,
    };
    if (is_standard_collection_tag(&resolved) && !valid_collection)
        || is_standard_scalar_tag(&resolved)
    {
        return Err(native_failure("yaml.tag.kind-mismatch@1"));
    }
    Ok(resolved)
}

fn resolve_scalar(
    decoded: &str,
    style: BackendScalarStyle,
    explicit: Option<&BackendTag>,
    profile: YamlProfile,
) -> Result<(String, NativeScalar), FatalFormationFailure> {
    let public_style = public_style(style);
    if let Some(explicit) = explicit {
        let tag = resolved_tag(explicit);
        if is_standard_collection_tag(&tag) {
            return Err(native_failure("yaml.tag.kind-mismatch@1"));
        }
        if tag == "!" || tag == TAG_STR {
            return Ok((
                TAG_STR.to_owned(),
                scalar(decoded, decoded, YamlScalarKind::String, public_style),
            ));
        }
        if tag == TAG_NULL {
            return resolve_explicit(
                decoded,
                public_style,
                TAG_NULL,
                YamlScalarKind::Null,
                profile,
            );
        }
        if tag == TAG_BOOL {
            return resolve_explicit(
                decoded,
                public_style,
                TAG_BOOL,
                YamlScalarKind::Boolean,
                profile,
            );
        }
        if tag == TAG_INT {
            return resolve_explicit(
                decoded,
                public_style,
                TAG_INT,
                YamlScalarKind::Integer,
                profile,
            );
        }
        if tag == TAG_FLOAT {
            return resolve_explicit(
                decoded,
                public_style,
                TAG_FLOAT,
                YamlScalarKind::Float,
                profile,
            );
        }
        if tag == TAG_TIMESTAMP {
            let canonical = parse_timestamp(decoded)
                .ok_or_else(|| native_failure("yaml.scalar.invalid-explicit-tag@1"))?;
            return Ok((
                tag,
                scalar(decoded, &canonical, YamlScalarKind::Timestamp, public_style),
            ));
        }
        if tag == TAG_BINARY {
            let canonical = canonical_base64(decoded)
                .ok_or_else(|| native_failure("yaml.scalar.invalid-explicit-tag@1"))?;
            return Ok((
                tag,
                scalar(decoded, &canonical, YamlScalarKind::Binary, public_style),
            ));
        }
        if matches!(tag.as_str(), TAG_MERGE | TAG_VALUE | TAG_YAML) {
            return Ok((
                tag,
                scalar(decoded, decoded, YamlScalarKind::Tagged, public_style),
            ));
        }
        return Ok((
            tag,
            scalar(decoded, decoded, YamlScalarKind::Custom, public_style),
        ));
    }
    if style != BackendScalarStyle::Plain {
        return Ok((
            TAG_STR.to_owned(),
            scalar(decoded, decoded, YamlScalarKind::String, public_style),
        ));
    }
    Ok(resolve_implicit(decoded, public_style, profile))
}

fn resolve_explicit(
    decoded: &str,
    style: YamlScalarStyle,
    tag: &'static str,
    kind: YamlScalarKind,
    profile: YamlProfile,
) -> Result<(String, NativeScalar), FatalFormationFailure> {
    let canonical = match kind {
        YamlScalarKind::Null => parse_null(decoded).map(str::to_owned),
        YamlScalarKind::Boolean => parse_bool(decoded, profile).map(str::to_owned),
        YamlScalarKind::Integer => parse_integer(decoded, profile),
        YamlScalarKind::Float => parse_float(decoded, profile),
        _ => unreachable!(
            "remaining scalar kinds are handled by the caller before explicit-tag formation"
        ),
    }
    .ok_or_else(|| native_failure("yaml.scalar.invalid-explicit-tag@1"))?;
    Ok((tag.to_owned(), scalar(decoded, &canonical, kind, style)))
}

fn resolve_implicit(
    decoded: &str,
    style: YamlScalarStyle,
    profile: YamlProfile,
) -> (String, NativeScalar) {
    if let Some(value) = parse_null(decoded) {
        return (
            TAG_NULL.to_owned(),
            scalar(decoded, value, YamlScalarKind::Null, style),
        );
    }
    if let Some(value) = parse_bool(decoded, profile) {
        return (
            TAG_BOOL.to_owned(),
            scalar(decoded, value, YamlScalarKind::Boolean, style),
        );
    }
    if let Some(value) = parse_integer(decoded, profile) {
        return (
            TAG_INT.to_owned(),
            scalar(decoded, &value, YamlScalarKind::Integer, style),
        );
    }
    if let Some(value) = parse_float(decoded, profile) {
        return (
            TAG_FLOAT.to_owned(),
            scalar(decoded, &value, YamlScalarKind::Float, style),
        );
    }
    if profile == YamlProfile::Yaml11CompatV1 {
        if let Some(value) = parse_timestamp(decoded) {
            return (
                TAG_TIMESTAMP.to_owned(),
                scalar(decoded, &value, YamlScalarKind::Timestamp, style),
            );
        }
    }
    (
        TAG_STR.to_owned(),
        scalar(decoded, decoded, YamlScalarKind::String, style),
    )
}

fn scalar(
    decoded: &str,
    canonical: &str,
    kind: YamlScalarKind,
    style: YamlScalarStyle,
) -> NativeScalar {
    NativeScalar {
        decoded: Arc::from(decoded),
        canonical: Arc::from(canonical),
        kind,
        style,
    }
}

const fn public_style(style: BackendScalarStyle) -> YamlScalarStyle {
    match style {
        BackendScalarStyle::Plain => YamlScalarStyle::Plain,
        BackendScalarStyle::SingleQuoted => YamlScalarStyle::SingleQuoted,
        BackendScalarStyle::DoubleQuoted => YamlScalarStyle::DoubleQuoted,
        BackendScalarStyle::Literal => YamlScalarStyle::Literal,
        BackendScalarStyle::Folded => YamlScalarStyle::Folded,
    }
}

fn resolved_tag(tag: &BackendTag) -> String {
    format!("{}{}", tag.prefix, tag.suffix)
}

fn parse_null(value: &str) -> Option<&'static str> {
    matches!(value, "" | "~" | "null" | "Null" | "NULL").then_some("")
}

fn parse_bool(value: &str, profile: YamlProfile) -> Option<&'static str> {
    match value {
        "true" | "True" | "TRUE" => Some("true"),
        "false" | "False" | "FALSE" => Some("false"),
        "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON"
            if profile == YamlProfile::Yaml11CompatV1 =>
        {
            Some("true")
        }
        "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF"
            if profile == YamlProfile::Yaml11CompatV1 =>
        {
            Some("false")
        }
        _ => None,
    }
}

fn parse_integer(value: &str, profile: YamlProfile) -> Option<String> {
    let (sign, unsigned) = split_sign(value)?;
    let allow_underscores = profile == YamlProfile::Yaml11CompatV1;
    let cleaned = if allow_underscores {
        valid_underscored(unsigned)?.replace('_', "")
    } else if unsigned.contains('_') {
        return None;
    } else {
        unsigned.to_owned()
    };
    let (base, digits) = if let Some(digits) = cleaned.strip_prefix("0b") {
        (2, digits)
    } else if let Some(digits) = cleaned.strip_prefix("0o") {
        if profile == YamlProfile::Yaml11CompatV1 {
            return None;
        }
        (8, digits)
    } else if let Some(digits) = cleaned.strip_prefix("0x") {
        (16, digits)
    } else if profile == YamlProfile::Yaml11CompatV1
        && cleaned.len() > 1
        && cleaned.starts_with('0')
    {
        (8, cleaned.as_str())
    } else if profile == YamlProfile::Yaml11CompatV1 && cleaned.contains(':') {
        return parse_sexagesimal_integer(sign, &cleaned);
    } else {
        (10, cleaned.as_str())
    };
    let magnitude = parse_base_magnitude(digits, base)?;
    BigInteger::from_sign_and_magnitude(sign, &magnitude)
        .ok()
        .map(|value| value.to_string())
}

fn parse_float(value: &str, profile: YamlProfile) -> Option<String> {
    match value {
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
            return Some(".inf".to_owned());
        }
        "-.inf" | "-.Inf" | "-.INF" => return Some("-.inf".to_owned()),
        ".nan" | ".NaN" | ".NAN" => return Some(".nan".to_owned()),
        _ => {}
    }
    let cleaned = if profile == YamlProfile::Yaml11CompatV1 {
        valid_underscored(value)?.replace('_', "")
    } else if value.contains('_') {
        return None;
    } else {
        value.to_owned()
    };
    if profile == YamlProfile::Yaml11CompatV1 && cleaned.contains(':') {
        return parse_sexagesimal_float(&cleaned);
    }
    if !cleaned.contains(['.', 'e', 'E']) {
        return None;
    }
    let normalized = normalize_decimal_lexeme(&cleaned);
    Decimal::parse_json_number(&normalized)
        .ok()
        .map(|value| decimal_canonical(&value))
}

fn normalize_decimal_lexeme(value: &str) -> String {
    let mut value = value.to_owned();
    if value.starts_with('+') {
        value.remove(0);
    }
    if value.starts_with("-.") {
        value.insert(1, '0');
    } else if value.starts_with('.') {
        value.insert(0, '0');
    }
    let exponent = value.find(['e', 'E']).unwrap_or(value.len());
    if value[..exponent].ends_with('.') {
        value.insert(exponent, '0');
    }
    value
}

fn parse_sexagesimal_integer(sign: i8, value: &str) -> Option<String> {
    let mut parts = value.split(':');
    let first = parts.next()?;
    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut magnitude = parse_base_magnitude(first, 10)?;
    let mut count = 0usize;
    for part in parts {
        let component = part.parse::<u8>().ok()?;
        if component > 59 || part.is_empty() || part.len() > 2 {
            return None;
        }
        multiply_add(&mut magnitude, 60, component);
        count += 1;
    }
    if count == 0 {
        return None;
    }
    BigInteger::from_sign_and_magnitude(sign, &magnitude)
        .ok()
        .map(|value| value.to_string())
}

fn parse_sexagesimal_float(value: &str) -> Option<String> {
    let (sign, unsigned) = split_sign(value)?;
    let mut parts = unsigned.split(':').collect::<Vec<_>>();
    let last = parts.pop()?;
    let (whole, fraction) = last.split_once('.')?;
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut magnitude = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let component = part.parse::<u64>().ok()?;
        if index > 0 && component > 59 {
            return None;
        }
        if index == 0 {
            magnitude = parse_base_magnitude(part, 10)?;
        } else {
            multiply_add(&mut magnitude, 60, u8::try_from(component).ok()?);
        }
    }
    if parts.is_empty() {
        return None;
    }
    let whole = whole.parse::<u8>().ok()?;
    if whole > 59 {
        return None;
    }
    multiply_add(&mut magnitude, 60, whole);
    let whole = BigInteger::from_sign_and_magnitude(1, &magnitude)
        .ok()?
        .to_string();
    let coefficient = BigInteger::parse_decimal(&format!(
        "{}{whole}{fraction}",
        if sign < 0 { "-" } else { "" }
    ))
    .ok()?;
    Some(decimal_canonical(&Decimal::new(
        coefficient,
        BigInteger::from(-(fraction.len() as i64)),
    )))
}

fn decimal_canonical(value: &Decimal) -> String {
    if value.exponent().signum() == 0 {
        value.coefficient().to_string()
    } else {
        format!("{}e{}", value.coefficient(), value.exponent())
    }
}

fn split_sign(value: &str) -> Option<(i8, &str)> {
    match value.as_bytes().first()? {
        b'-' => Some((-1, &value[1..])),
        b'+' => Some((1, &value[1..])),
        _ => Some((1, value)),
    }
}

fn valid_underscored(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    for (index, item) in bytes.iter().copied().enumerate() {
        if item == b'_'
            && (index == 0
                || index + 1 == bytes.len()
                || !bytes[index - 1].is_ascii_alphanumeric()
                || !bytes[index + 1].is_ascii_alphanumeric())
        {
            return None;
        }
    }
    Some(value)
}

fn parse_base_magnitude(value: &str, base: u8) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let mut magnitude = Vec::new();
    for digit in value.chars().map(|item| item.to_digit(u32::from(base))) {
        multiply_add(&mut magnitude, base, u8::try_from(digit?).ok()?);
    }
    Some(magnitude)
}

fn multiply_add(magnitude: &mut Vec<u8>, multiplier: u8, addend: u8) {
    let mut carry = u16::from(addend);
    for octet in magnitude.iter_mut().rev() {
        let value = u16::from(*octet) * u16::from(multiplier) + carry;
        *octet = value as u8;
        carry = value >> 8;
    }
    while carry > 0 {
        magnitude.insert(0, carry as u8);
        carry >>= 8;
    }
}

fn parse_timestamp(value: &str) -> Option<String> {
    if value.is_ascii() && value.len() >= 10 && valid_date(&value[..10]) {
        if value.len() == 10 {
            return Some(value.to_owned());
        }
        return canonical_timestamp(value);
    }
    None
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let year = value[..4].parse::<i32>().ok();
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day != 0 && day <= max_day
}

fn canonical_timestamp(value: &str) -> Option<String> {
    let mut rest = &value[10..];
    rest = rest.trim_start_matches([' ', '\t', 'T', 't']);
    let (hour, tail) = take_one_or_two_digits(rest)?;
    let tail = tail.strip_prefix(':')?;
    let (minute, tail) = take_two_digits(tail)?;
    let tail = tail.strip_prefix(':')?;
    let (second, mut tail) = take_two_digits(tail)?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut fraction = "";
    if let Some(after_dot) = tail.strip_prefix('.') {
        let length = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return None;
        }
        fraction = &after_dot[..length];
        tail = &after_dot[length..];
    }
    tail = tail.trim_start_matches([' ', '\t']);
    let zone = if tail.is_empty() || matches!(tail, "Z" | "z") {
        "Z".to_owned()
    } else {
        canonical_zone(tail)?
    };
    Some(format!(
        "{}T{hour:02}:{minute:02}:{second:02}{}{zone}",
        &value[..10],
        if fraction.is_empty() {
            String::new()
        } else {
            format!(".{fraction}")
        }
    ))
}

fn canonical_zone(value: &str) -> Option<String> {
    let sign = match value.as_bytes().first()? {
        b'+' => '+',
        b'-' => '-',
        _ => return None,
    };
    let rest = &value[1..];
    let (hour, tail) = take_one_or_two_digits(rest)?;
    let tail = tail.strip_prefix(':').unwrap_or(tail);
    let minute = if tail.is_empty() {
        0
    } else {
        let (minute, remaining) = take_two_digits(tail)?;
        if !remaining.is_empty() {
            return None;
        }
        minute
    };
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(format!("{sign}{hour:02}:{minute:02}"))
}

fn take_two_digits(value: &str) -> Option<(u8, &str)> {
    if value.len() < 2 || !value.as_bytes()[..2].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((value[..2].parse().ok()?, &value[2..]))
}

fn take_one_or_two_digits(value: &str) -> Option<(u8, &str)> {
    let count = value.bytes().take(2).take_while(u8::is_ascii_digit).count();
    if count == 0 {
        return None;
    }
    Some((value[..count].parse().ok()?, &value[count..]))
}

fn canonical_base64(value: &str) -> Option<String> {
    let cleaned = value
        .chars()
        .filter(|item| !item.is_ascii_whitespace())
        .collect::<String>();
    let padding = cleaned
        .bytes()
        .rev()
        .take_while(|item| *item == b'=')
        .count();
    if cleaned.len() % 4 != 0
        || !cleaned
            .bytes()
            .all(|item| item.is_ascii_alphanumeric() || matches!(item, b'+' | b'/' | b'='))
        || cleaned
            .bytes()
            .take(cleaned.len().saturating_sub(2))
            .any(|item| item == b'=')
        || padding > 2
    {
        return None;
    }
    if padding > 0 {
        let last_significant = base64_value(cleaned.as_bytes()[cleaned.len() - padding - 1])?;
        let unused_mask = if padding == 1 {
            0b0000_0011
        } else {
            0b0000_1111
        };
        if last_significant & unused_mask != 0 {
            return None;
        }
    }
    Some(cleaned)
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn is_standard_collection_tag(tag: &str) -> bool {
    matches!(tag, TAG_SEQ | TAG_MAP | TAG_OMAP | TAG_PAIRS | TAG_SET)
}

fn is_standard_scalar_tag(tag: &str) -> bool {
    matches!(
        tag,
        TAG_NULL
            | TAG_BOOL
            | TAG_INT
            | TAG_FLOAT
            | TAG_STR
            | TAG_TIMESTAMP
            | TAG_BINARY
            | TAG_MERGE
            | TAG_VALUE
            | TAG_YAML
    )
}

fn is_standard_graph_tag(tag: &str) -> bool {
    is_standard_collection_tag(tag) || is_standard_scalar_tag(tag)
}

fn native_failure(code: &'static str) -> FatalFormationFailure {
    use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        code,
        DiagnosticCategory::Semantic,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

pub(crate) fn node_ref(authority: &DocumentAuthority, index: usize) -> NodeRef {
    authority.node_ref(index as u64, NodeRole::YamlNode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_profiles_are_intentionally_different() {
        assert_eq!(
            resolve_implicit("yes", YamlScalarStyle::Plain, YamlProfile::Yaml12CoreV1).0,
            TAG_STR
        );
        assert_eq!(
            resolve_implicit("yes", YamlScalarStyle::Plain, YamlProfile::Yaml11CompatV1)
                .1
                .canonical
                .as_ref(),
            "true"
        );
        assert_eq!(
            parse_integer("0o17", YamlProfile::Yaml12CoreV1).as_deref(),
            Some("15")
        );
        assert_eq!(
            parse_integer("017", YamlProfile::Yaml11CompatV1).as_deref(),
            Some("15")
        );
        assert_eq!(
            parse_integer("1:02:03", YamlProfile::Yaml11CompatV1).as_deref(),
            Some("3723")
        );
        assert_eq!(parse_float("-.nan", YamlProfile::Yaml12CoreV1), None);
    }

    #[test]
    fn timestamp_and_binary_validation_are_bounded_data_only() {
        assert_eq!(
            parse_timestamp("2001-12-15 2:59:43.10 -5"),
            Some("2001-12-15T02:59:43.10-05:00".to_owned())
        );
        assert_eq!(canonical_base64("SGVs\n bG8="), Some("SGVsbG8=".to_owned()));
        assert_eq!(canonical_base64("SGVsbG9="), None);
        assert_eq!(canonical_base64("=bad"), None);
    }
}
