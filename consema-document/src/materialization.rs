//! Common immutable contracts for creating a new format document.

use crate::{NodeRef, ProfileId, SnapshotIdentity, SourceEncoding, Span};
use consema_core::{
    AssociationLocation, Diagnostic, FailureKind, OperationKind, PortableValueKind, StableFailure,
    ValuePath,
};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// Versioned format-owned materialization style identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaterializationStyleId {
    id: Arc<str>,
    version: u32,
}

impl MaterializationStyleId {
    /// Creates a versioned style identifier.
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Namespaced style ID without version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable style version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// Explicit output newline policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NewlinePolicy {
    /// Emit no final or layout newline; only supported by compact profiles.
    None,
    /// ASCII LF.
    Lf,
    /// ASCII CR followed by LF.
    CrLf,
}

impl NewlinePolicy {
    /// Exact selected newline bytes.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::None => b"",
            Self::Lf => b"\n",
            Self::CrLf => b"\r\n",
        }
    }
}

/// Explicit treatment of ordered mappings at object-only targets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MappingPolicy {
    /// Require a native PortableValue Object.
    RequireObject,
    /// Permit a unique String-key EntryMapping to become an Object and report transformation.
    UniqueStringEntriesToObject,
}

/// Closed v1 representability policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepresentabilityPolicy {
    /// Reject every value that cannot round-trip through the target's exact projection contract.
    ExactOnly,
}

/// Resource limits for one complete materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializationLimits {
    /// Maximum input PortableValue nodes visited.
    pub max_input_nodes: usize,
    /// Maximum raw output bytes.
    pub max_output_bytes: usize,
    /// Maximum recursive container depth.
    pub max_depth: usize,
    /// Maximum structured report events.
    pub max_report_entries: usize,
    /// Maximum provenance entries and origins combined.
    pub max_provenance_entries: usize,
}

impl Default for MaterializationLimits {
    fn default() -> Self {
        Self {
            max_input_nodes: 1_000_000,
            max_output_bytes: 64 * 1024 * 1024,
            max_depth: 256,
            max_report_entries: 100_000,
            max_provenance_entries: 2_000_000,
        }
    }
}

/// Complete immutable request for creating one new target document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationRequest {
    target_profile: ProfileId,
    style: MaterializationStyleId,
    encoding: SourceEncoding,
    newline: NewlinePolicy,
    mapping_policy: MappingPolicy,
    representability: RepresentabilityPolicy,
    limits: MaterializationLimits,
}

impl MaterializationRequest {
    /// Creates a strict request with UTF-8, LF, Object-only, and ExactOnly defaults.
    #[must_use]
    pub fn new(target_profile: ProfileId, style: MaterializationStyleId) -> Self {
        Self {
            target_profile,
            style,
            encoding: SourceEncoding::Utf8,
            newline: NewlinePolicy::Lf,
            mapping_policy: MappingPolicy::RequireObject,
            representability: RepresentabilityPolicy::ExactOnly,
            limits: MaterializationLimits::default(),
        }
    }

    /// Selects an explicit output encoding.
    #[must_use]
    pub const fn with_encoding(mut self, encoding: SourceEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Selects an explicit newline policy.
    #[must_use]
    pub const fn with_newline(mut self, newline: NewlinePolicy) -> Self {
        self.newline = newline;
        self
    }

    /// Selects explicit ordered-mapping behavior.
    #[must_use]
    pub const fn with_mapping_policy(mut self, policy: MappingPolicy) -> Self {
        self.mapping_policy = policy;
        self
    }

    /// Replaces immutable materialization limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: MaterializationLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Exact target Profile.
    #[must_use]
    pub const fn target_profile(&self) -> &ProfileId {
        &self.target_profile
    }

    /// Exact versioned target style.
    #[must_use]
    pub const fn style(&self) -> &MaterializationStyleId {
        &self.style
    }

    /// Selected output encoding.
    #[must_use]
    pub const fn encoding(&self) -> SourceEncoding {
        self.encoding
    }

    /// Selected newline behavior.
    #[must_use]
    pub const fn newline(&self) -> NewlinePolicy {
        self.newline
    }

    /// Ordered-mapping behavior.
    #[must_use]
    pub const fn mapping_policy(&self) -> MappingPolicy {
        self.mapping_policy
    }

    /// Representability behavior.
    #[must_use]
    pub const fn representability(&self) -> RepresentabilityPolicy {
        self.representability
    }

    /// Resource limits.
    #[must_use]
    pub const fn limits(&self) -> MaterializationLimits {
        self.limits
    }
}

/// Whole-operation semantic fidelity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MaterializationFidelity {
    /// Target projection reproduces the same portable representation.
    Exact,
    /// An explicitly authorized, reportable representation conversion occurred.
    Transformed,
}

/// Complete ordered materialization report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializationReport {
    events: Vec<Diagnostic>,
}

impl MaterializationReport {
    /// Creates a report after enforcing its configured event limit.
    pub fn new(
        events: Vec<Diagnostic>,
        limits: MaterializationLimits,
    ) -> Result<Self, MaterializationFailure> {
        if events.len() > limits.max_report_entries {
            return Err(MaterializationFailure::ResourceLimit("report-entries"));
        }
        Ok(Self { events })
    }

    /// Ordered structured events.
    #[must_use]
    pub fn events(&self) -> &[Diagnostic] {
        &self.events
    }
}

/// Portable input value or association location.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum MaterializationInputLocation {
    /// Portable value location.
    Value(ValuePath),
    /// Portable association location.
    Association(AssociationLocation),
}

/// Relationship from portable input fact to generated target syntax.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MaterializationRelation {
    /// Direct exact semantic representation.
    Direct,
    /// Deterministic target-native re-encoding.
    Reencoded,
    /// Syntax generated without a one-to-one input location.
    Generated,
}

/// One exact output origin in the newly materialized snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedOrigin {
    /// Target snapshot identity.
    pub snapshot: SnapshotIdentity,
    /// Target structural identity.
    pub node: NodeRef,
    /// Exact target raw span.
    pub span: Span,
    /// Input-to-output relationship.
    pub relation: MaterializationRelation,
}

/// One input location mapped to one or more target origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationProvenanceEntry {
    /// Portable input location.
    pub input: MaterializationInputLocation,
    /// One or more target origins.
    pub outputs: Vec<MaterializedOrigin>,
}

/// Complete input-to-output provenance map.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializationProvenanceMap {
    entries: Vec<MaterializationProvenanceEntry>,
}

impl MaterializationProvenanceMap {
    /// Validates snapshot binding, non-empty outputs, and configured size.
    pub fn new(
        entries: Vec<MaterializationProvenanceEntry>,
        target: SnapshotIdentity,
        limits: MaterializationLimits,
    ) -> Result<Self, MaterializationFailure> {
        let mut units = entries.len();
        for entry in &entries {
            if entry.outputs.is_empty() {
                return Err(MaterializationFailure::InvalidRequest(
                    "provenance entry has no output",
                ));
            }
            units = units
                .checked_add(entry.outputs.len())
                .ok_or(MaterializationFailure::ResourceLimit("provenance-entries"))?;
            if entry.outputs.iter().any(|origin| {
                origin.snapshot != target
                    || origin.node.snapshot() != target
                    || origin.span.snapshot() != target
            }) {
                return Err(MaterializationFailure::InvalidRequest(
                    "provenance origin uses another snapshot",
                ));
            }
        }
        if units > limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries"));
        }
        Ok(Self { entries })
    }

    /// Deterministically ordered provenance entries.
    #[must_use]
    pub fn entries(&self) -> &[MaterializationProvenanceEntry] {
        &self.entries
    }
}

/// Stable materialization failure category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationFailure {
    /// Request fields contradict the target contract.
    InvalidRequest(&'static str),
    /// Target profile is unavailable.
    UnsupportedProfile,
    /// Style is unavailable for the target profile.
    UnsupportedStyle,
    /// Encoding is unavailable for the target profile.
    UnsupportedEncoding,
    /// Newline policy is unavailable for the selected style.
    UnsupportedNewline,
    /// One complete input value cannot be represented.
    Unrepresentable {
        /// Stable portable input path.
        path: ValuePath,
        /// Unrepresentable core kind.
        kind: PortableValueKind,
    },
    /// A configured limit was reached.
    ResourceLimit(&'static str),
    /// Generated bytes did not form a target document.
    FormationFailed,
}

impl Display for MaterializationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MaterializationFailure {}

impl StableFailure for MaterializationFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Materialization
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::InvalidRequest(_) => FailureKind::InvalidInput,
            Self::UnsupportedProfile
            | Self::UnsupportedStyle
            | Self::UnsupportedEncoding
            | Self::UnsupportedNewline => FailureKind::Unsupported,
            Self::Unrepresentable { .. } => FailureKind::NotApplicable,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::FormationFailed => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::InvalidRequest(_) => "core.materialization.invalid-request@1",
            Self::UnsupportedProfile => "core.materialization.unsupported-profile@1",
            Self::UnsupportedStyle => "core.materialization.unsupported-style@1",
            Self::UnsupportedEncoding => "core.materialization.unsupported-encoding@1",
            Self::UnsupportedNewline => "core.materialization.unsupported-newline@1",
            Self::Unrepresentable { .. } => "core.materialization.unrepresentable@1",
            Self::ResourceLimit(_) => "core.materialization.resource-limit@1",
            Self::FormationFailed => "core.materialization.formation-failed@1",
        }
    }
}

/// Failed attempt without a Document or partial output bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedMaterializationAttempt {
    /// Stable failure.
    pub failure: MaterializationFailure,
    /// Events discovered before failure.
    pub report: MaterializationReport,
    /// Stable input paths analyzed before failure.
    pub analyzed_input_paths: Vec<ValuePath>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DocumentAuthority, NodeRole};
    use consema_core::AssociationRole;

    #[test]
    fn request_keeps_every_explicit_policy() {
        let request = MaterializationRequest::new(
            ProfileId::new("json.strict", 1),
            MaterializationStyleId::new("json.canonical-pretty", 1),
        )
        .with_encoding(SourceEncoding::Utf8)
        .with_newline(NewlinePolicy::CrLf)
        .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
        .with_limits(MaterializationLimits {
            max_output_bytes: 10,
            ..MaterializationLimits::default()
        });
        assert_eq!(request.target_profile().id(), "json.strict");
        assert_eq!(request.style().id(), "json.canonical-pretty");
        assert_eq!(request.newline(), NewlinePolicy::CrLf);
        assert_eq!(
            request.mapping_policy(),
            MappingPolicy::UniqueStringEntriesToObject
        );
        assert_eq!(request.limits().max_output_bytes, 10);
    }

    #[test]
    fn provenance_is_target_bound_and_limited() {
        let target = DocumentAuthority::fresh();
        let origin = MaterializedOrigin {
            snapshot: target.identity(),
            node: target.node_ref(0, NodeRole::Value),
            span: target.span(0, 1).unwrap(),
            relation: MaterializationRelation::Direct,
        };
        let entry = MaterializationProvenanceEntry {
            input: MaterializationInputLocation::Association(AssociationLocation::new(
                ValuePath::root(),
                0,
                AssociationRole::ObjectEntry,
            )),
            outputs: vec![origin],
        };
        assert_eq!(
            MaterializationProvenanceMap::new(
                vec![entry.clone()],
                target.identity(),
                MaterializationLimits::default(),
            )
            .unwrap()
            .entries(),
            &[entry]
        );
        assert!(matches!(
            MaterializationProvenanceMap::new(
                vec![MaterializationProvenanceEntry {
                    input: MaterializationInputLocation::Value(ValuePath::root()),
                    outputs: Vec::new(),
                }],
                target.identity(),
                MaterializationLimits::default(),
            ),
            Err(MaterializationFailure::InvalidRequest(_))
        ));
    }
}
