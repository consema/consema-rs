//! Bounded protocol transport policy.

/// Resource limits shared by canonical JSON and PVCE protocol transports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    /// Maximum encoded transport bytes.
    pub max_bytes: usize,
    /// Maximum nested PortableValue depth.
    pub max_depth: usize,
    /// Maximum total PortableValue nodes.
    pub max_nodes: usize,
    /// Maximum entries in one container.
    pub max_container_entries: usize,
    /// Maximum one String, Bytes, key, or identifier payload.
    pub max_blob_bytes: usize,
    /// Maximum magnitude bytes for an arbitrary integer.
    pub max_integer_bytes: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_depth: 256,
            max_nodes: 1_000_000,
            max_container_entries: 1_000_000,
            max_blob_bytes: 64 * 1024 * 1024,
            max_integer_bytes: 1024 * 1024,
        }
    }
}
