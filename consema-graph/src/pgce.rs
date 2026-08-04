use std::fmt::{self, Display, Formatter};
use std::str;

use crate::{
    GraphBuildError, GraphBuilder, GraphLimits, GraphMappingEntry, GraphNodeContent, PortableGraph,
    canonical_order,
};

/// Portable Graph Canonical Encoding / 1 magic.
pub const PGCE_MAGIC: [u8; 4] = *b"PGCE";
/// PGCE wire version.
pub const PGCE_VERSION: u64 = 1;

const NODE_SCALAR: u8 = 0x20;
const NODE_SEQUENCE: u8 = 0x40;
const NODE_MAPPING: u8 = 0x41;

/// Bounded PGCE encode/decode limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgceLimits {
    /// Maximum complete PGCE stream bytes.
    pub max_stream_bytes: usize,
    /// Maximum ordered roots.
    pub max_roots: usize,
    /// Maximum graph nodes.
    pub max_nodes: usize,
    /// Maximum sequence-item plus mapping key/value edges.
    pub max_edges: usize,
    /// Maximum items or associations in one container.
    pub max_container_entries: usize,
    /// Maximum UTF-8 bytes in one tag identifier.
    pub max_tag_bytes: usize,
    /// Maximum UTF-8 bytes in one scalar's canonical content.
    pub max_scalar_bytes: usize,
    /// Maximum canonical first-visit traversal depth.
    pub max_traversal_depth: usize,
}

impl Default for PgceLimits {
    fn default() -> Self {
        Self {
            max_stream_bytes: 64 * 1024 * 1024,
            max_roots: 1_000_000,
            max_nodes: 1_000_000,
            max_edges: 2_000_000,
            max_container_entries: 1_000_000,
            max_tag_bytes: 1024 * 1024,
            max_scalar_bytes: 64 * 1024 * 1024,
            max_traversal_depth: 256,
        }
    }
}

impl PgceLimits {
    const fn graph_limits(self) -> GraphLimits {
        GraphLimits {
            max_roots: self.max_roots,
            max_nodes: self.max_nodes,
            max_edges: self.max_edges,
            max_container_entries: self.max_container_entries,
            max_tag_bytes: self.max_tag_bytes,
            max_scalar_bytes: self.max_scalar_bytes,
            max_traversal_depth: self.max_traversal_depth,
        }
    }
}

/// Stable PGCE encoding failure. No variant carries partial output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PgceEncodeError {
    /// A configured resource bound was exceeded.
    ResourceLimit {
        /// Stable limit name.
        name: &'static str,
        /// Observed amount.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Size arithmetic exceeded the host representation.
    SizeOverflow,
}

impl Display for PgceEncodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PgceEncodeError {}

/// Stable strict PGCE decoding failure. No variant carries a partial graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PgceDecodeError {
    /// Complete input exceeded the configured stream bound.
    ResourceLimit {
        /// Stable limit name.
        name: &'static str,
        /// Observed amount.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Stream magic was not `PGCE`.
    InvalidMagic,
    /// The version is not PGCE/1.
    UnsupportedVersion(u64),
    /// Input ended inside a required field.
    UnexpectedEof,
    /// A varint was not the shortest representation of its value.
    NonMinimalVarint,
    /// A varint or host-size conversion overflowed.
    VarintOverflow,
    /// A node kind octet is not assigned by PGCE/1.
    UnknownNodeKind(u8),
    /// A length-delimited string was not UTF-8.
    InvalidUtf8,
    /// A tag was empty or contained ASCII control/whitespace.
    InvalidTag,
    /// A root or edge referenced a node outside `node_count`.
    ReferenceOutOfRange(u64),
    /// Wire IDs were not assigned in canonical first-discovery order.
    NonCanonicalNodeOrder,
    /// Bytes followed the one complete graph.
    TrailingBytes,
    /// A structurally decoded graph violated graph construction invariants.
    InvalidGraph(GraphBuildError),
    /// Re-encoding produced different bytes.
    NonCanonicalEncoding,
}

impl Display for PgceDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PgceDecodeError {}

/// Encodes one graph with the default bounded PGCE/1 policy.
pub fn encode_pgce(graph: &PortableGraph) -> Result<Vec<u8>, PgceEncodeError> {
    encode_pgce_bounded(graph, PgceLimits::default())
}

/// Encodes one complete canonical PGCE/1 stream after exact size measurement.
pub fn encode_pgce_bounded(
    graph: &PortableGraph,
    limits: PgceLimits,
) -> Result<Vec<u8>, PgceEncodeError> {
    validate_graph_limits(graph, limits)?;
    let layout = graph.canonical_layout();
    let size = measure(graph, &layout.canonical_ids, &layout.order, limits)?;
    check_encode_limit("stream-bytes", size, limits.max_stream_bytes)?;
    let mut output = Vec::with_capacity(size);
    output.extend_from_slice(&PGCE_MAGIC);
    write_varint(PGCE_VERSION, &mut output);
    write_varint(usize_u64(graph.roots.len())?, &mut output);
    write_varint(usize_u64(graph.nodes.len())?, &mut output);
    for root in graph.roots.iter().copied() {
        write_varint(canonical_id(&layout.canonical_ids, root)?, &mut output);
    }
    for index in layout.order.iter().copied() {
        let node = &graph.nodes[index];
        match &node.content {
            GraphNodeContent::Scalar(content) => {
                output.push(NODE_SCALAR);
                write_blob(node.tag.as_bytes(), &mut output)?;
                write_blob(content.as_bytes(), &mut output)?;
            }
            GraphNodeContent::Sequence(items) => {
                output.push(NODE_SEQUENCE);
                write_blob(node.tag.as_bytes(), &mut output)?;
                write_varint(usize_u64(items.len())?, &mut output);
                for item in items.iter().copied() {
                    write_varint(canonical_id(&layout.canonical_ids, item)?, &mut output);
                }
            }
            GraphNodeContent::Mapping(entries) => {
                output.push(NODE_MAPPING);
                write_blob(node.tag.as_bytes(), &mut output)?;
                write_varint(usize_u64(entries.len())?, &mut output);
                for entry in entries.iter().copied() {
                    write_varint(
                        canonical_id(&layout.canonical_ids, entry.key())?,
                        &mut output,
                    );
                    write_varint(
                        canonical_id(&layout.canonical_ids, entry.value())?,
                        &mut output,
                    );
                }
            }
        }
    }
    debug_assert_eq!(output.len(), size);
    Ok(output)
}

fn validate_graph_limits(graph: &PortableGraph, limits: PgceLimits) -> Result<(), PgceEncodeError> {
    check_encode_limit("graph-roots", graph.roots.len(), limits.max_roots)?;
    check_encode_limit("graph-nodes", graph.nodes.len(), limits.max_nodes)?;
    check_encode_limit("graph-edges", graph.edge_count, limits.max_edges)?;
    canonical_order(&graph.nodes, &graph.roots, Some(limits.max_traversal_depth))
        .map_err(map_build_to_encode)?;
    Ok(())
}

fn measure(
    graph: &PortableGraph,
    canonical_ids: &[u64],
    order: &[usize],
    limits: PgceLimits,
) -> Result<usize, PgceEncodeError> {
    let mut size = PGCE_MAGIC.len();
    size = checked_add(size, varint_size(PGCE_VERSION))?;
    size = checked_add(size, varint_size(usize_u64(graph.roots.len())?))?;
    size = checked_add(size, varint_size(usize_u64(graph.nodes.len())?))?;
    for root in graph.roots.iter().copied() {
        size = checked_add(size, varint_size(canonical_id(canonical_ids, root)?))?;
    }
    for index in order.iter().copied() {
        let node = &graph.nodes[index];
        check_encode_limit("tag-bytes", node.tag.len(), limits.max_tag_bytes)?;
        size = checked_add(size, 1)?;
        size = checked_add(size, blob_size(node.tag.len())?)?;
        match &node.content {
            GraphNodeContent::Scalar(content) => {
                check_encode_limit("scalar-bytes", content.len(), limits.max_scalar_bytes)?;
                size = checked_add(size, blob_size(content.len())?)?;
            }
            GraphNodeContent::Sequence(items) => {
                check_encode_limit(
                    "container-entries",
                    items.len(),
                    limits.max_container_entries,
                )?;
                size = checked_add(size, varint_size(usize_u64(items.len())?))?;
                for item in items.iter().copied() {
                    size = checked_add(size, varint_size(canonical_id(canonical_ids, item)?))?;
                }
            }
            GraphNodeContent::Mapping(entries) => {
                check_encode_limit(
                    "container-entries",
                    entries.len(),
                    limits.max_container_entries,
                )?;
                size = checked_add(size, varint_size(usize_u64(entries.len())?))?;
                for entry in entries.iter().copied() {
                    size =
                        checked_add(size, varint_size(canonical_id(canonical_ids, entry.key())?))?;
                    size = checked_add(
                        size,
                        varint_size(canonical_id(canonical_ids, entry.value())?),
                    )?;
                }
            }
        }
    }
    Ok(size)
}

fn canonical_id(canonical_ids: &[u64], id: crate::GraphNodeId) -> Result<u64, PgceEncodeError> {
    canonical_ids
        .get(id.index().ok_or(PgceEncodeError::SizeOverflow)?)
        .copied()
        .ok_or(PgceEncodeError::SizeOverflow)
}

fn blob_size(length: usize) -> Result<usize, PgceEncodeError> {
    checked_add(varint_size(usize_u64(length)?), length)
}

fn checked_add(left: usize, right: usize) -> Result<usize, PgceEncodeError> {
    left.checked_add(right).ok_or(PgceEncodeError::SizeOverflow)
}

fn usize_u64(value: usize) -> Result<u64, PgceEncodeError> {
    u64::try_from(value).map_err(|_| PgceEncodeError::SizeOverflow)
}

fn check_encode_limit(
    name: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), PgceEncodeError> {
    if observed > limit {
        Err(PgceEncodeError::ResourceLimit {
            name,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn map_build_to_encode(error: GraphBuildError) -> PgceEncodeError {
    match error {
        GraphBuildError::ResourceLimit {
            name,
            observed,
            limit,
        } => PgceEncodeError::ResourceLimit {
            name,
            observed,
            limit,
        },
        GraphBuildError::SizeOverflow => PgceEncodeError::SizeOverflow,
        _ => unreachable!("completed graph traversal has no structural errors"),
    }
}

fn write_blob(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), PgceEncodeError> {
    write_varint(usize_u64(bytes.len())?, output);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut octet = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            octet |= 0x80;
        }
        output.push(octet);
        if value == 0 {
            break;
        }
    }
}

const fn varint_size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        size += 1;
        value >>= 7;
    }
    size
}

/// Strictly decodes one canonical PGCE/1 stream.
pub fn decode_pgce(bytes: &[u8], limits: PgceLimits) -> Result<PortableGraph, PgceDecodeError> {
    check_decode_limit("stream-bytes", bytes.len(), limits.max_stream_bytes)?;
    let mut decoder = Decoder {
        bytes,
        offset: 0,
        limits,
        edges: 0,
    };
    if decoder.take(PGCE_MAGIC.len())? != PGCE_MAGIC {
        return Err(PgceDecodeError::InvalidMagic);
    }
    let version = decoder.varint()?;
    if version != PGCE_VERSION {
        return Err(PgceDecodeError::UnsupportedVersion(version));
    }
    let root_count = decoder.count("graph-roots", limits.max_roots)?;
    let node_count = decoder.count("graph-nodes", limits.max_nodes)?;

    let mut builder = GraphBuilder::new(limits.graph_limits());
    let mut ids = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        ids.push(builder.reserve_node().map_err(map_build_to_decode)?);
    }

    let mut root_indices = Vec::with_capacity(root_count);
    for _ in 0..root_count {
        root_indices.push(decoder.reference(node_count)?);
    }
    for index in root_indices {
        builder.push_root(ids[index]).map_err(map_build_to_decode)?;
    }

    for index in 0..node_count {
        let kind = decoder.byte()?;
        let tag = decoder.string("tag-bytes", limits.max_tag_bytes)?;
        match kind {
            NODE_SCALAR => {
                let content = decoder.string("scalar-bytes", limits.max_scalar_bytes)?;
                builder
                    .define_scalar(ids[index], tag, content)
                    .map_err(map_build_to_decode)?;
            }
            NODE_SEQUENCE => {
                let count = decoder.count("container-entries", limits.max_container_entries)?;
                decoder.add_edges(count)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(ids[decoder.reference(node_count)?]);
                }
                builder
                    .define_sequence(ids[index], tag, items)
                    .map_err(map_build_to_decode)?;
            }
            NODE_MAPPING => {
                let count = decoder.count("container-entries", limits.max_container_entries)?;
                let edges = count
                    .checked_mul(2)
                    .ok_or(PgceDecodeError::VarintOverflow)?;
                decoder.add_edges(edges)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = ids[decoder.reference(node_count)?];
                    let value = ids[decoder.reference(node_count)?];
                    entries.push(GraphMappingEntry::new(key, value));
                }
                builder
                    .define_mapping(ids[index], tag, entries)
                    .map_err(map_build_to_decode)?;
            }
            unknown => return Err(PgceDecodeError::UnknownNodeKind(unknown)),
        }
    }
    if decoder.offset != bytes.len() {
        return Err(PgceDecodeError::TrailingBytes);
    }
    let graph = builder.build().map_err(map_build_to_decode)?;
    let layout = graph.canonical_layout();
    if !layout.order.iter().copied().eq(0..node_count) {
        return Err(PgceDecodeError::NonCanonicalNodeOrder);
    }
    let encoded = encode_pgce_bounded(&graph, limits).map_err(map_encode_to_decode)?;
    if encoded != bytes {
        return Err(PgceDecodeError::NonCanonicalEncoding);
    }
    Ok(graph)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: PgceLimits,
    edges: usize,
}

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, PgceDecodeError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(PgceDecodeError::UnexpectedEof)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PgceDecodeError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PgceDecodeError::VarintOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PgceDecodeError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    fn varint(&mut self) -> Result<u64, PgceDecodeError> {
        let start = self.offset;
        let mut value = 0_u64;
        for shift in (0..=63).step_by(7) {
            let octet = self.byte()?;
            let payload = u64::from(octet & 0x7f);
            if shift == 63 && payload > 1 {
                return Err(PgceDecodeError::VarintOverflow);
            }
            value |= payload << shift;
            if octet & 0x80 == 0 {
                if self.offset - start != varint_size(value) {
                    return Err(PgceDecodeError::NonMinimalVarint);
                }
                return Ok(value);
            }
        }
        Err(PgceDecodeError::VarintOverflow)
    }

    fn count(&mut self, name: &'static str, limit: usize) -> Result<usize, PgceDecodeError> {
        let value = self.varint()?;
        let value = usize::try_from(value).map_err(|_| PgceDecodeError::VarintOverflow)?;
        check_decode_limit(name, value, limit)?;
        Ok(value)
    }

    fn reference(&mut self, node_count: usize) -> Result<usize, PgceDecodeError> {
        let value = self.varint()?;
        let index =
            usize::try_from(value).map_err(|_| PgceDecodeError::ReferenceOutOfRange(value))?;
        if index >= node_count {
            return Err(PgceDecodeError::ReferenceOutOfRange(value));
        }
        Ok(index)
    }

    fn string(
        &mut self,
        limit_name: &'static str,
        limit: usize,
    ) -> Result<String, PgceDecodeError> {
        let length = self.count(limit_name, limit)?;
        let bytes = self.take(length)?;
        str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| PgceDecodeError::InvalidUtf8)
    }

    fn add_edges(&mut self, count: usize) -> Result<(), PgceDecodeError> {
        self.edges = self
            .edges
            .checked_add(count)
            .ok_or(PgceDecodeError::VarintOverflow)?;
        check_decode_limit("graph-edges", self.edges, self.limits.max_edges)
    }
}

fn check_decode_limit(
    name: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), PgceDecodeError> {
    if observed > limit {
        Err(PgceDecodeError::ResourceLimit {
            name,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn map_build_to_decode(error: GraphBuildError) -> PgceDecodeError {
    match error {
        GraphBuildError::ResourceLimit {
            name,
            observed,
            limit,
        } => PgceDecodeError::ResourceLimit {
            name,
            observed,
            limit,
        },
        GraphBuildError::InvalidTag => PgceDecodeError::InvalidTag,
        other => PgceDecodeError::InvalidGraph(other),
    }
}

fn map_encode_to_decode(error: PgceEncodeError) -> PgceDecodeError {
    match error {
        PgceEncodeError::ResourceLimit {
            name,
            observed,
            limit,
        } => PgceDecodeError::ResourceLimit {
            name,
            observed,
            limit,
        },
        PgceEncodeError::SizeOverflow => PgceDecodeError::VarintOverflow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GraphMappingEntry, GraphNodeKind};
    use std::fmt::Write;

    const STR: &str = "tag:yaml.org,2002:str";
    const SEQ: &str = "tag:yaml.org,2002:seq";
    const MAP: &str = "tag:yaml.org,2002:map";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(
            String::with_capacity(bytes.len() * 2),
            |mut output, byte| {
                write!(output, "{byte:02x}").expect("writing to a String cannot fail");
                output
            },
        )
    }

    #[test]
    fn scalar_byte_vector_is_frozen() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        builder
            .define_scalar(root, STR, "x")
            .unwrap()
            .push_root(root)
            .unwrap();
        let encoded = encode_pgce(&builder.build().unwrap()).unwrap();
        assert_eq!(
            hex(&encoded),
            "504743450101010020157461673a79616d6c2e6f72672c323030323a7374720178"
        );
    }

    #[test]
    fn empty_graph_byte_vector_is_frozen() {
        let graph = GraphBuilder::new(GraphLimits::default()).build().unwrap();
        let encoded = encode_pgce(&graph).unwrap();
        assert_eq!(hex(&encoded), "50474345010000");
        assert_eq!(decode_pgce(&encoded, PgceLimits::default()).unwrap(), graph);
    }

    #[test]
    fn isomorphic_builder_numbering_has_identical_pgce() {
        let build = |shared_first: bool| {
            let mut builder = GraphBuilder::new(GraphLimits::default());
            let (root, shared) = if shared_first {
                let shared = builder.reserve_node().unwrap();
                let root = builder.reserve_node().unwrap();
                (root, shared)
            } else {
                let root = builder.reserve_node().unwrap();
                let shared = builder.reserve_node().unwrap();
                (root, shared)
            };
            builder.define_scalar(shared, STR, "x").unwrap();
            builder
                .define_sequence(root, SEQ, vec![shared, shared])
                .unwrap()
                .push_root(root)
                .unwrap();
            builder.build().unwrap()
        };
        let first = build(false);
        let second = build(true);
        assert_eq!(first, second);
        assert_eq!(encode_pgce(&first).unwrap(), encode_pgce(&second).unwrap());
    }

    #[test]
    fn shared_cycles_and_arbitrary_mapping_keys_round_trip() {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let mapping = builder.reserve_node().unwrap();
        let key = builder.reserve_node().unwrap();
        let sequence = builder.reserve_node().unwrap();
        builder.define_scalar(key, STR, "k").unwrap();
        builder
            .define_sequence(sequence, SEQ, vec![mapping, key])
            .unwrap();
        builder
            .define_mapping(
                mapping,
                MAP,
                vec![
                    GraphMappingEntry::new(sequence, key),
                    GraphMappingEntry::new(key, mapping),
                ],
            )
            .unwrap()
            .push_root(mapping)
            .unwrap();
        let graph = builder.build().unwrap();
        let encoded = encode_pgce(&graph).unwrap();
        let decoded = decode_pgce(&encoded, PgceLimits::default()).unwrap();
        assert_eq!(decoded, graph);
        assert_eq!(
            decoded.node(decoded.roots()[0]).unwrap().kind(),
            GraphNodeKind::Mapping
        );
        assert_eq!(encode_pgce(&decoded).unwrap(), encoded);
    }

    #[test]
    fn decoder_rejects_nonminimal_varint_trailing_and_invalid_reference() {
        let scalar = hex_scalar();
        let mut nonminimal = scalar.clone();
        nonminimal.splice(4..5, [0x81, 0x00]);
        assert_eq!(
            decode_pgce(&nonminimal, PgceLimits::default()).unwrap_err(),
            PgceDecodeError::NonMinimalVarint
        );

        let mut trailing = scalar.clone();
        trailing.push(0);
        assert_eq!(
            decode_pgce(&trailing, PgceLimits::default()).unwrap_err(),
            PgceDecodeError::TrailingBytes
        );

        let mut invalid_reference = scalar;
        invalid_reference[7] = 1;
        assert_eq!(
            decode_pgce(&invalid_reference, PgceLimits::default()).unwrap_err(),
            PgceDecodeError::ReferenceOutOfRange(1)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_node_numbering() {
        let mut bytes = Vec::from(PGCE_MAGIC);
        bytes.extend_from_slice(&[
            1, // version
            1, // roots
            2, // nodes
            1, // root is node 1, violating canonical first discovery
            NODE_SCALAR,
            21,
        ]);
        bytes.extend_from_slice(STR.as_bytes());
        bytes.extend_from_slice(&[1, b'x', NODE_SEQUENCE, 21]);
        bytes.extend_from_slice(SEQ.as_bytes());
        bytes.extend_from_slice(&[1, 0]);
        assert_eq!(
            decode_pgce(&bytes, PgceLimits::default()).unwrap_err(),
            PgceDecodeError::NonCanonicalNodeOrder
        );
    }

    #[test]
    fn encode_and_decode_limits_fail_atomically() {
        let scalar = hex_scalar();
        let limits = PgceLimits {
            max_stream_bytes: scalar.len() - 1,
            ..PgceLimits::default()
        };
        assert!(matches!(
            decode_pgce(&scalar, limits),
            Err(PgceDecodeError::ResourceLimit {
                name: "stream-bytes",
                ..
            })
        ));

        let graph = decode_pgce(&scalar, PgceLimits::default()).unwrap();
        assert!(matches!(
            encode_pgce_bounded(&graph, limits),
            Err(PgceEncodeError::ResourceLimit {
                name: "stream-bytes",
                ..
            })
        ));
    }

    fn hex_scalar() -> Vec<u8> {
        let mut builder = GraphBuilder::new(GraphLimits::default());
        let root = builder.reserve_node().unwrap();
        builder
            .define_scalar(root, STR, "x")
            .unwrap()
            .push_root(root)
            .unwrap();
        encode_pgce(&builder.build().unwrap()).unwrap()
    }
}
