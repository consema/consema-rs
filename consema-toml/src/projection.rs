use crate::{Document, EntityKind, InternalItemKind, TomlDate, TomlDateTime, TomlOffset, TomlTime};
use consema_core::{
    AssociationLocation, AssociationRole, BigInteger, Date, Decimal, Diagnostic,
    DiagnosticCategory, DiagnosticSeverity, LocalDateTime, ObjectBuilder, OffsetDateTime,
    PortableValue, SequenceBuilder, Time, ValueBuildError, ValuePath, ValuePathSegment,
};
use consema_document::{NodeRef, NodeRole, SnapshotIdentity, Span};

/// Versioned TOML projection target contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Frozen exact-first TOML-to-core mapping.
    BestExactCoreV1,
}

/// Immutable explicit projection request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Creates an explicit request with default resource limits.
    #[must_use]
    pub fn new(target: ProjectionTarget) -> Self {
        Self {
            target,
            limits: ProjectionLimits::default(),
        }
    }

    /// Replaces immutable resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: ProjectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Frozen target contract.
    #[must_use]
    pub const fn target(self) -> ProjectionTarget {
        self.target
    }

    /// Projection resource limits.
    #[must_use]
    pub const fn limits(self) -> ProjectionLimits {
        self.limits
    }
}

/// Projection resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum produced PortableValue nodes.
    pub max_value_nodes: usize,
    /// Maximum report events.
    pub max_report_entries: usize,
    /// Maximum provenance locations and origins combined.
    pub max_provenance_entries: usize,
    /// Maximum recursive container depth.
    pub max_depth: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_value_nodes: 1_000_000,
            max_report_entries: 100_000,
            max_provenance_entries: 2_000_000,
            max_depth: 256,
        }
    }
}

/// Projection fidelity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fidelity {
    /// Target directly and completely represents TOML value semantics.
    Exact,
    /// Complete semantics survive an explicit reversible re-encoding.
    Transformed,
    /// At least one source fact cannot be recovered.
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
    /// Derived without a one-to-one literal origin.
    Derived,
}

/// One exact source origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOrigin {
    /// Source document snapshot.
    pub snapshot: SnapshotIdentity,
    /// Exact structural identity.
    pub node: NodeRef,
    /// Exact source range.
    pub span: Span,
    /// Source relation.
    pub relation: ProvenanceRelation,
}

/// One many-valued provenance mapping entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected value or association.
    pub projected: ProjectedLocation,
    /// One or more exact source origins.
    pub origins: Vec<SourceOrigin>,
}

/// Immutable multi-map from projected locations to source origins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceMap {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceMap {
    /// Deterministically generated entries.
    #[must_use]
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }
}

/// Complete ordered projection report.
///
/// Exact TOML 1.0 projections emit no transformation or loss events.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<Diagnostic>,
}

impl ProjectionReport {
    /// Ordered structured transformation/loss diagnostics.
    #[must_use]
    pub fn events(&self) -> &[Diagnostic] {
        &self.events
    }
}

/// Complete successful projection; its value is never partial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProjection {
    /// Complete immutable public value.
    pub value: PortableValue,
    /// Worst fidelity of the whole operation.
    pub fidelity: Fidelity,
    /// Machine-readable transformation/loss report.
    pub report: ProjectionReport,
    /// Value and object-association provenance.
    pub provenance: ProvenanceMap,
}

/// Failed attempt without a partial PortableValue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedProjectionAttempt {
    /// Ordered diagnostics explaining the failure.
    pub diagnostics: Vec<Diagnostic>,
    /// Events discovered before the failed completion check.
    pub report: ProjectionReport,
    /// Stable paths that were locally analyzed before failure.
    pub partial_analysis: Vec<String>,
}

/// Projection completion algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionResult {
    /// Complete success.
    Complete(CompleteProjection),
    /// Failed attempt with no value.
    Failed(FailedProjectionAttempt),
}

/// Stable projection failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// TOML temporal fields are outside PortableValue v1.
    UnrepresentableDateTime,
    /// Declared resource limit was reached.
    ResourceLimit(&'static str),
    /// A valid TOML table violated the core unique-key invariant.
    CoreInvariant,
}

impl Document {
    /// Applies an immutable explicit projection request.
    #[must_use]
    pub fn project(&self, request: ProjectionRequest) -> ProjectionResult {
        let mut context = Context {
            document: self,
            limits: request.limits,
            value_nodes: 0,
            provenance_units: 0,
            provenance: ProvenanceMap::default(),
        };
        match context.project_item(self.root, &ValuePath::root(), 0) {
            Ok(value) => ProjectionResult::Complete(CompleteProjection {
                value,
                fidelity: Fidelity::Exact,
                report: ProjectionReport::default(),
                provenance: context.provenance,
            }),
            Err(failure) => ProjectionResult::Failed(FailedProjectionAttempt {
                diagnostics: vec![failure_diagnostic(self, failure)],
                report: ProjectionReport::default(),
                partial_analysis: Vec::new(),
            }),
        }
    }
}

struct Context<'a> {
    document: &'a Document,
    limits: ProjectionLimits,
    value_nodes: usize,
    provenance_units: usize,
    provenance: ProvenanceMap,
}

impl Context<'_> {
    fn project_item(
        &mut self,
        index: usize,
        path: &ValuePath,
        depth: usize,
    ) -> Result<PortableValue, ProjectionFailure> {
        if depth > self.limits.max_depth {
            return Err(ProjectionFailure::ResourceLimit("max_depth"));
        }
        self.value_nodes = self.value_nodes.saturating_add(1);
        if self.value_nodes > self.limits.max_value_nodes {
            return Err(ProjectionFailure::ResourceLimit("max_value_nodes"));
        }

        let value = match &self.document.item_entity(index).kind {
            InternalItemKind::String(value) => PortableValue::string(value.clone()),
            InternalItemKind::Integer(value) => PortableValue::integer(BigInteger::from(*value)),
            InternalItemKind::Float(value) => PortableValue::binary_float64(*value),
            InternalItemKind::Boolean(value) => PortableValue::boolean(*value),
            InternalItemKind::DateTime(value) => project_datetime(*value)?,
            InternalItemKind::Array(elements) | InternalItemKind::ArrayOfTables(elements) => {
                let mut builder = SequenceBuilder::new();
                for (ordinal, element_index) in elements.iter().enumerate() {
                    let EntityKind::Element(element) = &self.document.entity(*element_index).kind
                    else {
                        unreachable!("typed TOML element");
                    };
                    let child_path = path.child(ValuePathSegment::SequenceElement(
                        u64::try_from(ordinal).expect("usize fits u64 on supported targets"),
                    ));
                    builder.push(self.project_item(
                        element.item,
                        &child_path,
                        depth.saturating_add(1),
                    )?);
                    self.add_origin(
                        ProjectedLocation::Value(child_path),
                        *element_index,
                        NodeRole::TomlArrayElement,
                        ProvenanceRelation::Direct,
                    )?;
                }
                builder.build()
            }
            InternalItemKind::InlineTable(entries) | InternalItemKind::Table { entries, .. } => {
                let mut builder = ObjectBuilder::new();
                for entry_index in entries {
                    let EntityKind::Entry(entry) = &self.document.entity(*entry_index).kind else {
                        unreachable!("typed TOML entry");
                    };
                    let EntityKind::Key(key) = &self.document.entity(entry.key).kind else {
                        unreachable!("typed TOML key");
                    };
                    let child_path =
                        path.child(ValuePathSegment::ObjectValue(key.name.to_string()));
                    let child =
                        self.project_item(entry.item, &child_path, depth.saturating_add(1))?;
                    builder
                        .insert(key.name.to_string(), child)
                        .map_err(|_| ProjectionFailure::CoreInvariant)?;
                    let ordinal =
                        u64::try_from(entry.ordinal).expect("usize fits u64 on supported targets");
                    self.add_origin(
                        ProjectedLocation::Association(AssociationLocation::new(
                            path.clone(),
                            ordinal,
                            AssociationRole::ObjectEntry,
                        )),
                        *entry_index,
                        NodeRole::TomlEntry,
                        ProvenanceRelation::Direct,
                    )?;
                    self.add_origin(
                        ProjectedLocation::Association(AssociationLocation::new(
                            path.clone(),
                            ordinal,
                            AssociationRole::ObjectKey,
                        )),
                        entry.key,
                        NodeRole::TomlKey,
                        ProvenanceRelation::Direct,
                    )?;
                }
                builder.build()
            }
        };
        self.add_origin(
            ProjectedLocation::Value(path.clone()),
            index,
            NodeRole::TomlItem,
            ProvenanceRelation::Direct,
        )?;
        Ok(value)
    }

    fn add_origin(
        &mut self,
        projected: ProjectedLocation,
        index: usize,
        role: NodeRole,
        relation: ProvenanceRelation,
    ) -> Result<(), ProjectionFailure> {
        self.provenance_units = self.provenance_units.saturating_add(1);
        if self.provenance_units > self.limits.max_provenance_entries {
            return Err(ProjectionFailure::ResourceLimit("max_provenance_entries"));
        }
        let origin = SourceOrigin {
            snapshot: self.document.snapshot_identity(),
            node: self.document.node_ref(index, role),
            span: self.document.entity(index).span,
            relation,
        };
        if let Some(entry) = self
            .provenance
            .entries
            .iter_mut()
            .find(|entry| entry.projected == projected)
        {
            entry.origins.push(origin);
        } else {
            self.provenance.entries.push(ProvenanceEntry {
                projected,
                origins: vec![origin],
            });
        }
        Ok(())
    }
}

fn project_datetime(value: TomlDateTime) -> Result<PortableValue, ProjectionFailure> {
    match (value.date, value.time, value.offset) {
        (Some(date), None, None) => Ok(PortableValue::date(core_date(date)?)),
        (None, Some(time), None) => Ok(PortableValue::time(core_time(time)?)),
        (Some(date), Some(time), None) => Ok(PortableValue::local_date_time(LocalDateTime::new(
            core_date(date)?,
            core_time(time)?,
        ))),
        (Some(date), Some(time), Some(offset)) => {
            let local = LocalDateTime::new(core_date(date)?, core_time(time)?);
            let offset_seconds = match offset {
                TomlOffset::Z => 0,
                TomlOffset::CustomMinutes(minutes) => i32::from(minutes) * 60,
            };
            Ok(PortableValue::offset_date_time(
                OffsetDateTime::new(local, offset_seconds).map_err(map_temporal_build_error)?,
            ))
        }
        _ => Err(ProjectionFailure::UnrepresentableDateTime),
    }
}

fn core_date(value: TomlDate) -> Result<Date, ProjectionFailure> {
    Date::new(
        BigInteger::from(i64::from(value.year)),
        value.month,
        value.day,
    )
    .map_err(map_temporal_build_error)
}

fn core_time(value: TomlTime) -> Result<Time, ProjectionFailure> {
    let fraction = Decimal::new(
        BigInteger::from(i64::from(value.nanosecond)),
        BigInteger::from(-9_i64),
    );
    Time::new(value.hour, value.minute, value.second, fraction).map_err(map_temporal_build_error)
}

fn map_temporal_build_error(_: ValueBuildError) -> ProjectionFailure {
    ProjectionFailure::UnrepresentableDateTime
}

fn failure_diagnostic(document: &Document, failure: ProjectionFailure) -> Diagnostic {
    let (code, category, primary) = match failure {
        ProjectionFailure::UnrepresentableDateTime => (
            "toml.projection.unrepresentable-datetime@1",
            DiagnosticCategory::Projection,
            Some(document.root().span().diagnostic_location()),
        ),
        ProjectionFailure::ResourceLimit(_) => (
            "core.projection.resource-limit@1",
            DiagnosticCategory::Resource,
            None,
        ),
        ProjectionFailure::CoreInvariant => (
            "toml.projection.core-invariant@1",
            DiagnosticCategory::Projection,
            None,
        ),
    };
    let mut diagnostic = Diagnostic::new(code, category, DiagnosticSeverity::Error, primary, 0);
    if let ProjectionFailure::ResourceLimit(name) = failure {
        diagnostic
            .arguments
            .insert("limit".to_owned(), name.to_owned());
    }
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TomlItemKind, TomlProfile, parse};
    use consema_core::PortableValueKind;
    use consema_document::ParseLimits;

    fn project(source: &[u8]) -> ProjectionResult {
        let document =
            parse(source, TomlProfile::Toml10V1, ParseLimits::default()).expect("valid TOML");
        document.project(ProjectionRequest::new(ProjectionTarget::BestExactCoreV1))
    }

    #[test]
    fn all_toml_value_categories_project_exactly_with_provenance() {
        let result = project(
            br#"string = "value"
integer = 42
float = -0.0
boolean = true
date = 1979-05-27
time = 07:32:00.123
local = 1979-05-27T07:32:00
offset = 1979-05-27T07:32:00-07:00
array = [1, 2]
inline = { x = 1 }
[[products]]
name = "one"
"#,
        );
        let ProjectionResult::Complete(complete) = result else {
            panic!("complete projection expected");
        };
        assert_eq!(complete.fidelity, Fidelity::Exact);
        assert!(complete.report.events().is_empty());
        let root = complete.value.as_object().expect("root object");
        assert_eq!(root.len(), 11);
        assert_eq!(root[2].value().kind(), PortableValueKind::BinaryFloat64);
        assert_eq!(
            root[2].value().as_binary_float64().expect("float").bits(),
            (-0.0_f64).to_bits()
        );
        assert_eq!(root[4].value().kind(), PortableValueKind::Date);
        assert_eq!(root[5].value().kind(), PortableValueKind::Time);
        assert_eq!(root[6].value().kind(), PortableValueKind::LocalDateTime);
        assert_eq!(root[7].value().kind(), PortableValueKind::OffsetDateTime);
        assert_eq!(root[10].value().kind(), PortableValueKind::Sequence);
        assert!(!complete.provenance.entries().is_empty());
        assert!(complete.provenance.entries().iter().all(|entry| {
            entry
                .origins
                .iter()
                .all(|origin| origin.snapshot == origin.span.snapshot())
        }));
    }

    #[test]
    fn leap_second_and_limits_fail_without_partial_values() {
        let leap = project(b"time = 23:59:60");
        let ProjectionResult::Failed(failure) = leap else {
            panic!("unrepresentable leap second must fail");
        };
        assert_eq!(
            failure.diagnostics[0].code,
            "toml.projection.unrepresentable-datetime@1"
        );

        let document = parse(
            b"a = 1\nb = 2".as_slice(),
            TomlProfile::Toml10V1,
            ParseLimits::default(),
        )
        .expect("valid TOML");
        let request = ProjectionRequest::new(ProjectionTarget::BestExactCoreV1).with_limits(
            ProjectionLimits {
                max_value_nodes: 1,
                ..ProjectionLimits::default()
            },
        );
        let ProjectionResult::Failed(failure) = document.project(request) else {
            panic!("limit must fail");
        };
        assert_eq!(
            failure.diagnostics[0].code,
            "core.projection.resource-limit@1"
        );
        assert!(failure.partial_analysis.is_empty());
        assert_eq!(document.root().kind(), TomlItemKind::RootTable);
    }
}
