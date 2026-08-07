//! HCL projection targets and explicit mapping policies (RFC 0014 §8).
//!
//! The default exact target is the versioned `hcl.projection.body@1` record:
//! one ordered `hcl.body@1` PortableValue record with a single ordered
//! `items` sequence, each item an attribute (`kind`/`name`/`value`) or a
//! block (`kind`/`type`/`labels`/`body`), where every attribute value is
//! literal-complete and rendered as a typed member — string (exact code
//! points), integer or real (exact canonical decimal), boolean, null, tuple,
//! or object — and every block carries its type, ordered labels, and a
//! nested `hcl.body@1` record (RFC 0014 §8.2). Attribute order, block order,
//! label order, and duplicate object-constructor keys are preserved exactly;
//! the single `items` sequence keeps attributes and blocks interleaved in
//! source order.
//!
//! A derived expression has no default rendering (RFC 0014 §8.2). Projection
//! of a body containing a derived expression fails atomically with
//! `hcl.projection.non-literal-expression@1` unless the caller supplies the
//! explicit [`ExpressionPolicy::ProjectExpression`] policy; under that policy
//! each derived expression is projected as the authorized `hcl.expression@1`
//! ExtendedValue record, built through the consema-core
//! [`ExtendedValue`]/[`ExtensionContract`] mechanism, and the projection
//! reports one `Transformed` event per substituted expression with value and
//! expression provenance. No other transformation exists: no
//! expression-to-string rendering, no error-to-value substitution, no
//! contextual guessing (hard gate 4). A Recovered Document never projects.
//!
//! The projection is atomic: a recovered source, a derived expression under
//! the default policy, an unrepresentable native fact, or a resource limit
//! returns no partial value, provenance, or report.
//!
//! # `hcl.body@1` record shape
//!
//! ```text
//! {
//!   "record": "hcl.body@1",
//!   "items":  [ <item>, ... ]
//! }
//!
//! attribute  { "kind": "attribute", "name": <string>,
//!              "value": <typed member> }
//! block      { "kind": "block", "type": <string>,
//!              "labels": [<string>, ...],
//!              "body": <nested hcl.body@1 record> }
//! ```
//!
//! The one ordered `items` sequence is the RFC 0014 §8.2 "one ordered body
//! of items": attributes and blocks stay interleaved in source order, so a
//! block between two attributes keeps its position, and every item carries
//! its `kind` member.
//!
//! The typed members are: string (exact decoded code points, including the
//! `<<-` indentation-stripped heredoc content), integer (`BigInteger`, the
//! canonical decimal without a fraction), real (`Decimal`, the exact
//! canonical decimal), boolean, null, tuple (`Sequence`), and object
//! (`EntryMapping`, because object-constructor keys may repeat and may be
//! non-identifier spellings; duplicate keys remain ordered entries).
//! Object keys render as strings: an identifier key keeps its spelling, a
//! number-literal key its exact canonical decimal, a quoted-literal-template
//! key its exact decoded text, and a parenthesized literal-complete
//! expression key the canonical spelling of its scalar value (canonical
//! decimal, `"true"`, `"false"`, `"null"`, or exact string text). A
//! parenthesized key whose literal value is a tuple or object has no
//! canonical string spelling and fails the projection atomically with
//! `hcl.projection.unrepresentable@1` (`object-key`), never silently
//! rendered (hard gate 4).
//!
//! # `hcl.expression@1` ExtendedValue
//!
//! [`HclExpressionContract`] is the formal contract: `type_id`
//! `hcl.expression`, semantic version `1`, payload codec
//! `hcl.expression.canonical@1`. The canonical payload is three
//! length-prefixed blobs:
//!
//! ```text
//! payload := blob(kind) || blob(text) || fingerprint
//! blob    := varint(len) || bytes
//! ```
//!
//! `kind` is the derived-expression family spelling (table below), `text`
//! the exact source text of the expression, and `fingerprint` the 8-byte
//! little-endian structural fingerprint (next section). The projected
//! `hcl.expression@1` record inside the body record is the PortableValue
//! rendering of the validated ExtendedValue:
//!
//! ```text
//! { "record": "hcl.expression@1", "kind": <string>,
//!   "text": <string>, "fingerprint": <16 lowercase hex digits> }
//! ```
//!
//! The kind family table (variable and traversal expressions are one
//! family, RFC 0014 §4.1; for-expressions are one family, RFC 0014 §4.6):
//!
//! ```text
//! number | boolean | null | template | function-call | variable
//! unary  | binary  | conditional | for | tuple | object | parenthesized
//! ```
//!
//! # Structural fingerprint
//!
//! The fingerprint is FNV-1a 64-bit (offset basis `0xcbf29ce484222325`,
//! prime `0x100000001b3`) over the canonical structural serialization of
//! the expression — kind tag, canonical decimals, exact literal texts,
//! operator spellings, heredoc mode and marker, with length-prefixed text
//! runs — which encodes exactly the RFC 0014 §6 structural equality:
//! recursive over kind and children, number equality as canonical-decimal
//! equality, template equality part-wise, constructor equality
//! element-wise, and node identity and source spans never part of value
//! equality. The serialization is the shared M6/M7 adaptation point of the
//! `hcl.expression@1` codec: it is defined in `materialization.rs` (the
//! reparse closure verifies it there), and [`structural_fingerprint`]
//! delegates to it so the projection writes exactly the fingerprint the
//! closure checks. Structurally equal expressions therefore fingerprint
//! identically, and the fingerprint never depends on spans, trivia, or
//! spelling variants that normalize to one canonical value. All multi-byte
//! integer writes are little-endian so the fingerprint is platform-stable.
//!
//! # Provenance
//!
//! [`ProvenanceMap`] maps every projected attribute value and block object
//! to its exact source origin: the projected location is the nested
//! `ValuePath` from the record root through `items`, the sequence ordinal,
//! and the `value`/`body` members; the origin is the
//! snapshot identity, a snapshot-bound `NodeRef`, and the exact raw source
//! span. Node ordinals follow one deterministic depth-first pre-order walk
//! of the body tree: the root body first, then each item in source order; an
//! attribute consumes one ordinal for itself and then every node of its
//! expression subtree (in `children()` source order) consumes one ordinal; a
//! block consumes one ordinal for itself, one per label, and then its nested
//! body's items. Roles are `HclAttribute`, `HclBlock`, `HclBlockLabel`, and
//! `HclExpression`.
//!
//! # Limits
//!
//! [`ProjectionLimits`] bounds inspected native constructs
//! (`max_source_nodes`: every attribute, block, label, and expression node),
//! produced PortableValue nodes (`max_value_nodes`: every constructed node,
//! entry keys included), report events, and provenance units. Limit failure
//! is atomic and never masquerades as a partial target (hard gate 4).
//!
//! The module is the crate's public projection API, re-exported by `lib.rs`
//! (M5-M8 integration milestone).

use crate::document::Document;
use crate::expression::{
    HclExpression, HclExpressionKindName, HclLiteralValue, is_literal_complete, literal_value,
};
use crate::native::{HclAttribute, HclBlock, HclBody, HclBodyItem};
use consema_core::{
    BigInteger, Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity, EntryMappingBuilder,
    ExtendedValue, ExtensionContract, ExtensionValidationError, FailureKind, ObjectBuilder,
    OperationKind, PortableValue, SequenceBuilder, StableFailure, ValuePath, ValuePathSegment,
};
use consema_document::{FormationStatus, NodeRef, NodeRole, SnapshotIdentity, Span};

/// Versioned `hcl.body@1` record spelling (RFC 0014 §8.2).
const HCL_BODY_RECORD: &str = "hcl.body@1";

/// Stable type identifier of the `hcl.expression@1` ExtendedValue (RFC 0014
/// §8.2, roadmap §5.5); the wire record spelling appends the semantic
/// version.
const HCL_EXPRESSION_TYPE_ID: &str = "hcl.expression";

/// Canonical payload codec of the `hcl.expression@1` ExtendedValue.
const HCL_EXPRESSION_CODEC: &str = "hcl.expression.canonical@1";

/// Versioned HCL projection target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionTarget {
    /// Exact `hcl.projection.body@1` record projection.
    BodyV1,
}

/// Derived-expression handling for the body target (RFC 0014 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpressionPolicy {
    /// A derived expression fails the projection atomically with
    /// `hcl.projection.non-literal-expression@1`.
    Fail,
    /// Each derived expression is projected as the authorized
    /// `hcl.expression@1` ExtendedValue, reported as one `Transformed`
    /// event per substituted expression.
    ProjectExpression,
}

/// Explicit HCL projection request; every policy is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    target: ProjectionTarget,
    expression_policy: ExpressionPolicy,
    limits: ProjectionLimits,
}

impl ProjectionRequest {
    /// Exact `hcl.projection.body@1` record request; a derived expression
    /// fails the projection atomically.
    #[must_use]
    pub fn body() -> Self {
        Self {
            target: ProjectionTarget::BodyV1,
            expression_policy: ExpressionPolicy::Fail,
            limits: ProjectionLimits::default(),
        }
    }

    /// Exact `hcl.projection.body@1` request with an explicit derived-
    /// expression policy (RFC 0014 §8.2, hard gate 4).
    #[must_use]
    pub fn body_with_expression_policy(policy: ExpressionPolicy) -> Self {
        Self {
            target: ProjectionTarget::BodyV1,
            expression_policy: policy,
            limits: ProjectionLimits::default(),
        }
    }

    /// Applies explicit resource limits to this request.
    #[must_use]
    pub const fn with_limits(self, limits: ProjectionLimits) -> Self {
        Self { limits, ..self }
    }

    /// Projection target.
    #[must_use]
    pub const fn target(&self) -> ProjectionTarget {
        self.target
    }

    /// Derived-expression policy consumed by the body target.
    #[must_use]
    pub const fn expression_policy(&self) -> ExpressionPolicy {
        self.expression_policy
    }

    /// Resource limits.
    #[must_use]
    pub const fn limits(&self) -> ProjectionLimits {
        self.limits
    }
}

/// HCL projection resource limits.
///
/// Field names stay aligned with the plist and XML crates' `ProjectionLimits`,
/// so the shared `max_` prefix is deliberate.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Maximum inspected native constructs: every attribute, block, block
    /// label, and expression node.
    pub max_source_nodes: usize,
    /// Maximum produced PortableValue nodes, entry keys included.
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

/// One many-valued provenance entry: one projected record location and its
/// ordered source origins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEntry {
    /// Projected location inside the `hcl.body@1` record.
    pub projected: ValuePath,
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
    /// One derived expression substituted by the authorized
    /// `hcl.expression@1` ExtendedValue under the explicit
    /// `ProjectExpression` policy (RFC 0014 §8.2).
    ExpressionSubstituted,
}

/// One explicit transformation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEvent {
    /// Stable event kind.
    pub kind: ProjectionEventKind,
    /// Source expression occurrence substituted.
    pub expression: NodeRef,
    /// Projected value location inside the `hcl.body@1` record.
    pub value: ValuePath,
    /// Fidelity impact.
    pub impact: Fidelity,
}

/// Complete ordered projection report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionReport {
    events: Vec<ProjectionEvent>,
}

impl ProjectionReport {
    /// Events in deterministic source order.
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
    /// Complete immutable projected `hcl.body@1` record.
    pub value: PortableValue,
    /// Worst operation fidelity.
    pub fidelity: Fidelity,
    /// Structured transformation report.
    pub report: ProjectionReport,
    /// Value provenance from the body to the record.
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

/// Stable HCL projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// A Recovered document cannot publish partial semantic values (RFC 0014
    /// §8.2: "A Recovered Document never projects").
    IncompleteDocument,
    /// A derived expression was projected without the explicit
    /// `ProjectExpression` policy (RFC 0014 §8.2).
    NonLiteralExpression {
        /// Exact source text of the first derived expression.
        text: String,
    },
    /// A native fact the record cannot represent, such as a parenthesized
    /// object key whose literal value is a tuple or object.
    Unrepresentable(&'static str),
    /// Declared projection resource limit was reached.
    ResourceLimit(&'static str),
    /// PortableValue or ExtendedValue construction invariant failed.
    CoreInvariant,
}

impl StableFailure for ProjectionFailure {
    fn operation_kind(&self) -> OperationKind {
        OperationKind::Projection
    }

    fn failure_kind(&self) -> FailureKind {
        match self {
            Self::IncompleteDocument
            | Self::NonLiteralExpression { .. }
            | Self::Unrepresentable(_) => FailureKind::InvalidInput,
            Self::ResourceLimit(_) => FailureKind::ResourceLimited,
            Self::CoreInvariant => FailureKind::Internal,
        }
    }

    fn diagnostic_code(&self) -> &str {
        match self {
            Self::IncompleteDocument => "hcl.projection.incomplete-document@1",
            Self::NonLiteralExpression { .. } => "hcl.projection.non-literal-expression@1",
            Self::Unrepresentable(_) => "hcl.projection.unrepresentable@1",
            Self::ResourceLimit(_) => "hcl.projection.resource-limit@1",
            Self::CoreInvariant => "hcl.projection.core-invariant@1",
        }
    }
}

/// Formal `hcl.expression@1` contract (RFC 0014 §8.2, roadmap §5.5).
///
/// The contract validates the canonical payload envelope: exactly three
/// length-prefixed blobs — the kind family spelling, the exact source text,
/// and the 8-byte structural fingerprint — with a closed-set kind spelling
/// and UTF-8 text. Semantic support is claimed only after
/// `validate_canonical` accepts the payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HclExpressionContract;

impl ExtensionContract for HclExpressionContract {
    fn type_id(&self) -> &str {
        HCL_EXPRESSION_TYPE_ID
    }

    fn semantic_version(&self) -> u32 {
        1
    }

    fn payload_codec_id(&self) -> &str {
        HCL_EXPRESSION_CODEC
    }

    fn validate_canonical(&self, payload: &[u8]) -> Result<(), ExtensionValidationError> {
        let mut cursor = PayloadCursor::new(payload);
        let kind = cursor
            .blob()
            .ok_or(ExtensionValidationError::InvalidCanonicalPayload)?;
        if !is_kind_family_spelling(kind) {
            return Err(ExtensionValidationError::InvalidCanonicalPayload);
        }
        let text = std::str::from_utf8(
            cursor
                .blob()
                .ok_or(ExtensionValidationError::InvalidCanonicalPayload)?,
        )
        .map_err(|_| ExtensionValidationError::InvalidCanonicalPayload)?;
        if text.is_empty() {
            // Every expression carries at least one source character, so the
            // exact source text of a substituted expression is never empty.
            return Err(ExtensionValidationError::InvalidCanonicalPayload);
        }
        let fingerprint = cursor
            .bytes(8)
            .ok_or(ExtensionValidationError::InvalidCanonicalPayload)?;
        if !cursor.finished() {
            return Err(ExtensionValidationError::InvalidCanonicalPayload);
        }
        let _ = u64::from_le_bytes(
            fingerprint
                .try_into()
                .map_err(|_| ExtensionValidationError::InvalidCanonicalPayload)?,
        );
        Ok(())
    }
}

/// Canonical payload of one `hcl.expression@1` ExtendedValue: the kind
/// family spelling, the exact source text, and the structural fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionPayload {
    /// Kind family spelling.
    pub kind: String,
    /// Exact source text.
    pub text: String,
    /// Structural fingerprint.
    pub fingerprint: u64,
}

impl ExpressionPayload {
    /// Encodes the canonical payload bytes under the `hcl.expression@1`
    /// codec.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        encode_blob(self.kind.as_bytes(), &mut payload);
        encode_blob(self.text.as_bytes(), &mut payload);
        payload.extend_from_slice(&self.fingerprint.to_le_bytes());
        payload
    }

    /// Decodes one canonical payload; `None` for an envelope violation.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut cursor = PayloadCursor::new(payload);
        let kind = cursor.blob()?;
        if !is_kind_family_spelling(kind) {
            return None;
        }
        let text = std::str::from_utf8(cursor.blob()?).ok()?.to_owned();
        let fingerprint = u64::from_le_bytes(cursor.bytes(8)?.try_into().ok()?);
        if !cursor.finished() {
            return None;
        }
        Some(Self {
            kind: String::from_utf8(kind.to_vec()).ok()?,
            text,
            fingerprint,
        })
    }
}

/// Structural fingerprint of one expression (RFC 0014 §6, §8.2).
///
/// FNV-1a 64-bit over the canonical structural serialization defined by the
/// materialization codec — the shared M6/M7 adaptation point of the
/// `hcl.expression@1` payload, so the projection writes exactly the value
/// the reparse closure verifies: two expressions equal under the RFC 0014
/// §6 structural equality always carry the same fingerprint, and the
/// fingerprint never depends on source spans.
#[must_use]
pub fn structural_fingerprint(expression: &HclExpression) -> u64 {
    crate::materialization::expression_fingerprint_value(expression)
}

/// Projects one complete HCL document under one explicit target and policy
/// contract (RFC 0014 §8).
///
/// The projection is atomic: a recovered source, a derived expression under
/// the default policy, an unrepresentable native fact, or a resource limit
/// returns no partial value, provenance, or report (hard gate 4). A
/// Recovered Document never projects (RFC 0014 §8.2).
#[must_use]
pub fn project(document: &Document, request: ProjectionRequest) -> ProjectionResult {
    if document.status() != FormationStatus::Complete {
        return failed(ProjectionFailure::IncompleteDocument);
    }
    let mut context = Context {
        document,
        limits: request.limits,
        expression_policy: request.expression_policy,
        report: ProjectionReport::default(),
        provenance: ProvenanceMap::default(),
        fidelity: Fidelity::Exact,
        value_nodes: 0,
        source_nodes: 0,
        next_ordinal: 0,
    };
    let result = match request.target {
        ProjectionTarget::BodyV1 => context.project_body_record(),
    };
    match result {
        Ok(value) => ProjectionResult::Complete(CompleteProjection {
            value,
            fidelity: context.fidelity,
            report: context.report,
            provenance: context.provenance,
        }),
        Err(failure) => failed(failure),
    }
}

struct Context<'a> {
    document: &'a Document,
    limits: ProjectionLimits,
    expression_policy: ExpressionPolicy,
    report: ProjectionReport,
    provenance: ProvenanceMap,
    fidelity: Fidelity,
    value_nodes: usize,
    source_nodes: usize,
    next_ordinal: u64,
}

impl<'a> Context<'a> {
    /// Native body tree, borrowed from the document snapshot rather than from
    /// `self`, so projection state can mutate while the tree is live.
    fn native(&self) -> &'a HclBody {
        self.document.document().body()
    }

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

    fn event(&mut self, expression: NodeRef, value: ValuePath) -> Result<(), ProjectionFailure> {
        self.report.push(
            ProjectionEvent {
                kind: ProjectionEventKind::ExpressionSubstituted,
                expression,
                value,
                impact: Fidelity::Transformed,
            },
            self.limits,
        )?;
        self.fidelity = Fidelity::Transformed;
        Ok(())
    }

    fn origin(
        &mut self,
        projected: ValuePath,
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

    /// Snapshot-bound handle of one native construct with the next walk
    /// ordinal.
    fn node_ref(&mut self, role: NodeRole) -> NodeRef {
        let ordinal = self.next_ordinal;
        self.next_ordinal = ordinal
            .checked_add(1)
            .expect("projection ordinals cannot overflow u64");
        self.document.authority().node_ref(ordinal, role)
    }

    /// Exact span of one attribute occurrence: the union of its name, equals,
    /// and expression spans.
    fn attribute_span(&self, attribute: &HclAttribute) -> Result<Span, ProjectionFailure> {
        self.document
            .authority()
            .span(
                attribute.name_span().start_byte(),
                attribute.expression().span().end_byte(),
            )
            .map_err(|_| ProjectionFailure::CoreInvariant)
    }

    /// Exact `hcl.body@1` record for the document root body.
    fn project_body_record(&mut self) -> Result<PortableValue, ProjectionFailure> {
        self.project_body(self.native(), &ValuePath::root())
    }

    /// One recursive body projection; `path` is the location of this body's
    /// record inside the projected tree.
    ///
    /// The record carries one ordered `items` sequence (RFC 0014 §8.2 "one
    /// ordered body of items"): attributes and blocks stay interleaved in
    /// source order, each item carrying its `kind` member.
    fn project_body(
        &mut self,
        body: &HclBody,
        path: &ValuePath,
    ) -> Result<PortableValue, ProjectionFailure> {
        self.reserve_value(1)?;
        let mut builder = ObjectBuilder::new();
        builder
            .insert("record", PortableValue::string(HCL_BODY_RECORD))
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        let mut items = SequenceBuilder::new();
        let mut item_ordinal = 0_u64;
        for item in body.items() {
            self.step()?;
            let ordinal = item_ordinal;
            item_ordinal = ordinal
                .checked_add(1)
                .ok_or(ProjectionFailure::CoreInvariant)?;
            let item_path = path
                .child(ValuePathSegment::ObjectValue("items".to_owned()))
                .child(ValuePathSegment::SequenceElement(ordinal));
            match item {
                HclBodyItem::Attribute(attribute) => {
                    let attribute_node = self.node_ref(NodeRole::HclAttribute);
                    let value_path = item_path
                        .clone()
                        .child(ValuePathSegment::ObjectValue("value".to_owned()));
                    self.origin(
                        value_path.clone(),
                        attribute_node,
                        self.attribute_span(attribute)?,
                        ProvenanceRelation::Direct,
                    )?;
                    let value = self.project_attribute(attribute, &value_path)?;
                    self.reserve_value(3)?;
                    let mut attribute_builder = ObjectBuilder::new();
                    attribute_builder
                        .insert("kind", PortableValue::string("attribute"))
                        .and_then(|builder| {
                            builder
                                .insert("name", PortableValue::string(attribute.name().to_owned()))
                        })
                        .and_then(|builder| builder.insert("value", value))
                        .map_err(|_| ProjectionFailure::CoreInvariant)?;
                    items.push(attribute_builder.build());
                }
                HclBodyItem::Block(block) => {
                    let block_node = self.node_ref(NodeRole::HclBlock);
                    self.origin(
                        item_path.clone(),
                        block_node,
                        block.span(),
                        ProvenanceRelation::Direct,
                    )?;
                    let block_value = self.project_block(block, &item_path)?;
                    items.push(block_value);
                }
            }
        }
        self.reserve_value(1)?;
        builder
            .insert("items", items.build())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        Ok(builder.build())
    }

    /// One attribute value projection: a typed literal member, or the
    /// authorized `hcl.expression@1` ExtendedValue record under the explicit
    /// policy.
    fn project_attribute(
        &mut self,
        attribute: &HclAttribute,
        value_path: &ValuePath,
    ) -> Result<PortableValue, ProjectionFailure> {
        let expression = attribute.expression();
        let expression_node = self.inspect_expression(expression)?;
        if is_literal_complete(expression) {
            let literal =
                literal_value(expression).map_err(|_| ProjectionFailure::CoreInvariant)?;
            return self.literal_to_value(&literal);
        }
        match self.expression_policy {
            ExpressionPolicy::Fail => Err(ProjectionFailure::NonLiteralExpression {
                text: expression
                    .text(self.document.source())
                    .map_err(|_| ProjectionFailure::CoreInvariant)?
                    .to_owned(),
            }),
            ExpressionPolicy::ProjectExpression => {
                let value = self.expression_record(expression)?;
                self.origin(
                    value_path.clone(),
                    expression_node,
                    expression.span(),
                    ProvenanceRelation::Direct,
                )?;
                self.event(expression_node, value_path.clone())?;
                Ok(value)
            }
        }
    }

    /// One block item projection: the `kind` member, the type, ordered
    /// labels, and the nested `hcl.body@1` record.
    fn project_block(
        &mut self,
        block: &HclBlock,
        block_path: &ValuePath,
    ) -> Result<PortableValue, ProjectionFailure> {
        for _ in block.labels() {
            self.step()?;
            self.node_ref(NodeRole::HclBlockLabel);
        }
        let body_path = block_path
            .clone()
            .child(ValuePathSegment::ObjectValue("body".to_owned()));
        let body_value = self.project_body(block.body(), &body_path)?;
        self.reserve_value(4 + block.labels().len())?;
        let mut builder = ObjectBuilder::new();
        builder
            .insert("kind", PortableValue::string("block"))
            .and_then(|builder| {
                builder.insert("type", PortableValue::string(block.block_type().to_owned()))
            })
            .and_then(|builder| {
                builder.insert(
                    "labels",
                    PortableValue::sequence(
                        block
                            .labels()
                            .iter()
                            .map(|label| PortableValue::string(label.text().to_owned()))
                            .collect::<Vec<_>>(),
                    ),
                )
            })
            .and_then(|builder| builder.insert("body", body_value))
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        Ok(builder.build())
    }

    /// Assigns walk ordinals to every node of one expression subtree in
    /// source order and returns the ordinal of the root node.
    fn inspect_expression(
        &mut self,
        expression: &HclExpression,
    ) -> Result<NodeRef, ProjectionFailure> {
        self.step()?;
        let node = self.node_ref(NodeRole::HclExpression);
        for child in expression.children() {
            self.inspect_expression(child)?;
        }
        Ok(node)
    }

    /// One literal-complete value mapped to its typed PortableValue member.
    fn literal_to_value(
        &mut self,
        literal: &HclLiteralValue,
    ) -> Result<PortableValue, ProjectionFailure> {
        self.reserve_value(1)?;
        Ok(match literal {
            HclLiteralValue::Integer(text) => PortableValue::integer(
                BigInteger::parse_decimal(text).map_err(|_| ProjectionFailure::CoreInvariant)?,
            ),
            HclLiteralValue::Decimal(text) => PortableValue::decimal(
                Decimal::parse_json_number(text).map_err(|_| ProjectionFailure::CoreInvariant)?,
            ),
            HclLiteralValue::String(text) => PortableValue::string(text.clone()),
            HclLiteralValue::Boolean(value) => PortableValue::boolean(*value),
            HclLiteralValue::Null => PortableValue::null(),
            HclLiteralValue::Tuple(elements) => {
                let mut builder = SequenceBuilder::new();
                for element in elements.iter() {
                    builder.push(self.literal_to_value(element)?);
                }
                builder.build()
            }
            HclLiteralValue::Object(entries) => {
                let mut builder = EntryMappingBuilder::new();
                for entry in entries.iter() {
                    let key = literal_key(entry.key())?;
                    self.reserve_value(1)?;
                    let value = self.literal_to_value(entry.value())?;
                    builder.push(PortableValue::string(key), value);
                }
                builder.build()
            }
        })
    }

    /// One `hcl.expression@1` ExtendedValue record for a derived expression,
    /// built through the formal contract.
    fn expression_record(
        &mut self,
        expression: &HclExpression,
    ) -> Result<PortableValue, ProjectionFailure> {
        let text = expression
            .text(self.document.source())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        let payload = ExpressionPayload {
            kind: kind_family(expression.kind().name()).to_owned(),
            text: text.to_owned(),
            fingerprint: structural_fingerprint(expression),
        };
        let extended = ExtendedValue::validated(&HclExpressionContract, payload.encode())
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        self.reserve_value(5)?;
        let mut builder = ObjectBuilder::new();
        builder
            .insert(
                "record",
                PortableValue::string(format!(
                    "{}@{}",
                    extended.type_id(),
                    extended.semantic_version()
                )),
            )
            .and_then(|builder| builder.insert("kind", PortableValue::string(payload.kind)))
            .and_then(|builder| builder.insert("text", PortableValue::string(payload.text)))
            .and_then(|builder| {
                builder.insert(
                    "fingerprint",
                    PortableValue::string(format!("{:016x}", payload.fingerprint)),
                )
            })
            .map_err(|_| ProjectionFailure::CoreInvariant)?;
        Ok(builder.build())
    }
}

/// Canonical string spelling of one object-constructor key.
fn literal_key(key: &crate::expression::HclLiteralKey) -> Result<String, ProjectionFailure> {
    Ok(match key {
        crate::expression::HclLiteralKey::Identifier(name) => name.clone(),
        crate::expression::HclLiteralKey::Number(canonical) => canonical.clone(),
        crate::expression::HclLiteralKey::String(text) => text.clone(),
        crate::expression::HclLiteralKey::Value(literal) => scalar_key(literal)?,
    })
}

/// Canonical scalar spelling of one parenthesized object key; a tuple or
/// object value has no canonical string spelling and fails atomically.
fn scalar_key(literal: &HclLiteralValue) -> Result<String, ProjectionFailure> {
    match literal {
        HclLiteralValue::Integer(text)
        | HclLiteralValue::Decimal(text)
        | HclLiteralValue::String(text) => Ok(text.clone()),
        HclLiteralValue::Boolean(value) => Ok(if *value { "true" } else { "false" }.to_owned()),
        HclLiteralValue::Null => Ok("null".to_owned()),
        HclLiteralValue::Tuple(_) | HclLiteralValue::Object(_) => {
            Err(ProjectionFailure::Unrepresentable("object-key"))
        }
    }
}

/// Kind family spelling of the `hcl.expression@1` record (RFC 0014 §4.1,
/// §4.6, §8.2).
///
/// Variable and traversal expressions are one family — the RFC's "variable
/// expression" is a traversal root and `foo.bar`, `foo[0]`, and `foo.*.bar`
/// are static traversal facts of that family — and for-expressions are one
/// family over the tuple and object forms.
#[must_use]
pub const fn kind_family(name: HclExpressionKindName) -> &'static str {
    match name {
        HclExpressionKindName::Number => "number",
        HclExpressionKindName::Boolean => "boolean",
        HclExpressionKindName::Null => "null",
        HclExpressionKindName::Template => "template",
        HclExpressionKindName::FunctionCall => "function-call",
        HclExpressionKindName::VariableRef | HclExpressionKindName::Traversal => "variable",
        HclExpressionKindName::Unary => "unary",
        HclExpressionKindName::Binary => "binary",
        HclExpressionKindName::Conditional => "conditional",
        HclExpressionKindName::ForTuple | HclExpressionKindName::ForObject => "for",
        HclExpressionKindName::Tuple => "tuple",
        HclExpressionKindName::Object => "object",
        HclExpressionKindName::Parenthesized => "parenthesized",
    }
}

/// Whether one spelling is in the closed kind family set.
fn is_kind_family_spelling(spelling: &[u8]) -> bool {
    matches!(
        spelling,
        b"number"
            | b"boolean"
            | b"null"
            | b"template"
            | b"function-call"
            | b"variable"
            | b"unary"
            | b"binary"
            | b"conditional"
            | b"for"
            | b"tuple"
            | b"object"
            | b"parenthesized"
    )
}

/// Cursor over the canonical payload envelope.
struct PayloadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0_u64;
        for shift in (0..).step_by(7) {
            if shift >= 63 {
                // The tenth byte may contribute the sixty-third bit only; an
                // eleventh byte or an overflowing tenth byte is malformed.
                let byte = *self.bytes.get(self.offset)?;
                self.offset += 1;
                let payload = u64::from(byte & 0x7f);
                if payload > 1 || byte & 0x80 != 0 {
                    return None;
                }
                return Some(value | (payload << 63));
            }
            let byte = *self.bytes.get(self.offset)?;
            self.offset += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn blob(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.varint()?).ok()?;
        let end = self.offset.checked_add(length)?;
        let blob = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(blob)
    }

    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Encodes one length-prefixed blob into the canonical payload envelope.
fn encode_blob(bytes: &[u8], output: &mut Vec<u8>) {
    write_varint(
        u64::try_from(bytes.len()).expect("blob lengths fit u64"),
        output,
    );
    output.extend_from_slice(bytes);
}

/// Encodes one unsigned LEB128 varint.
fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut octet = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            octet |= 0x80;
        }
        output.push(octet);
        if value == 0 {
            return;
        }
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
    match &failure {
        ProjectionFailure::NonLiteralExpression { text } => {
            diagnostic
                .arguments
                .insert("expression".to_owned(), text.clone());
        }
        ProjectionFailure::Unrepresentable(fact) => {
            diagnostic
                .arguments
                .insert("fact".to_owned(), (*fact).to_owned());
        }
        ProjectionFailure::ResourceLimit(name) => {
            diagnostic
                .arguments
                .insert("limit".to_owned(), (*name).to_owned());
        }
        _ => {}
    }
    ProjectionResult::Failed(FailedProjectionAttempt {
        diagnostics: vec![diagnostic],
        report: ProjectionReport::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HclProfile;
    use std::sync::Arc;

    fn parse(source: &[u8], profile: HclProfile) -> Document {
        crate::parse(
            Arc::<[u8]>::from(source),
            profile,
            crate::HclEncodingSelection::ProfileDefault,
            crate::HclParseLimits::default(),
        )
        .expect("formation of a valid UTF-8 source")
    }

    fn body(document: &Document) -> ProjectionResult {
        project(document, ProjectionRequest::body())
    }

    fn body_policy(document: &Document, policy: ExpressionPolicy) -> ProjectionResult {
        project(
            document,
            ProjectionRequest::body_with_expression_policy(policy),
        )
    }

    fn complete(result: ProjectionResult) -> CompleteProjection {
        match result {
            ProjectionResult::Complete(complete) => complete,
            ProjectionResult::Failed(failed) => {
                panic!("projection failed: {:?}", failed.diagnostics)
            }
        }
    }

    fn failed_code(result: &ProjectionResult) -> String {
        match result {
            ProjectionResult::Complete(_) => panic!("projection must fail"),
            ProjectionResult::Failed(failed) => failed.diagnostics[0].code.clone(),
        }
    }

    fn failed_arg(result: &ProjectionResult, name: &str) -> Option<String> {
        match result {
            ProjectionResult::Complete(_) => panic!("projection must fail"),
            ProjectionResult::Failed(failed) => failed.diagnostics[0].arguments.get(name).cloned(),
        }
    }

    fn record_parts(value: &PortableValue) -> (&str, &[consema_core::ObjectEntry]) {
        let object = value.as_object().expect("record object");
        let record = object
            .iter()
            .find(|entry| entry.key() == "record")
            .expect("record member");
        (record.value().as_string().expect("record spelling"), object)
    }

    fn items(value: &PortableValue) -> &[PortableValue] {
        value
            .as_object()
            .expect("record object")
            .iter()
            .find(|entry| entry.key() == "items")
            .expect("items member")
            .value()
            .as_sequence()
            .expect("items sequence")
    }

    fn item_kind(item: &PortableValue) -> &str {
        item.as_object()
            .expect("item object")
            .iter()
            .find(|entry| entry.key() == "kind")
            .expect("kind member")
            .value()
            .as_string()
            .expect("kind string")
    }

    fn item_member<'a>(item: &'a PortableValue, member: &str) -> &'a PortableValue {
        item.as_object()
            .expect("item object")
            .iter()
            .find(|entry| entry.key() == member)
            .expect("item member")
            .value()
    }

    fn attribute<'a>(value: &'a PortableValue, name: &str) -> &'a PortableValue {
        for item in items(value) {
            if item_kind(item) == "attribute" && item_member(item, "name").as_string() == Some(name)
            {
                return item_member(item, "value");
            }
        }
        panic!("attribute {name:?} not found");
    }

    fn attribute_names(value: &PortableValue) -> Vec<&str> {
        items(value)
            .iter()
            .filter(|item| item_kind(item) == "attribute")
            .map(|item| item_member(item, "name").as_string().expect("name string"))
            .collect()
    }

    fn blocks(value: &PortableValue) -> Vec<&PortableValue> {
        items(value)
            .iter()
            .filter(|item| item_kind(item) == "block")
            .collect()
    }

    fn block_value<'a>(record: &'a PortableValue, index: usize, member: &str) -> &'a PortableValue {
        blocks(record)[index]
            .as_object()
            .expect("block object")
            .iter()
            .find(|entry| entry.key() == member)
            .expect("block member")
            .value()
    }

    fn object_value<'a>(value: &'a PortableValue, key: &str) -> &'a PortableValue {
        value
            .as_object()
            .expect("object")
            .iter()
            .find(|entry| entry.key() == key)
            .expect("object entry exists")
            .value()
    }

    fn entry_value<'a>(value: &'a PortableValue, key: &str) -> &'a PortableValue {
        value
            .as_entry_mapping()
            .expect("entry mapping")
            .iter()
            .find(|entry| entry.key().as_string() == Some(key))
            .expect("entry exists")
            .value()
    }

    #[test]
    fn body_record_projects_the_literal_complete_matrix() {
        // The `hcl.projection.literal-complete-record` conformance case.
        let source = b"name = \"consema\"\ncount = 42\nratio = 1.50\nbig = 1e3\nsmall = 15e-1\nenabled = true\nnothing = null\ntags = [\"a\", \"b\"]\nlabels = { env = \"prod\" }\ndups = { a = 1, a = 2 }\nnumkeys = { 1 = \"one\", 2 = \"two\" }\nnested = { \"x\" = { y = [1, 2] } }\n";
        let projection = complete(body(&parse(source, HclProfile::NativeV1)));
        let (record, _) = record_parts(&projection.value);
        assert_eq!(record, "hcl.body@1");
        assert_eq!(
            attribute_names(&projection.value),
            [
                "name", "count", "ratio", "big", "small", "enabled", "nothing", "tags", "labels",
                "dups", "numkeys", "nested",
            ]
        );
        assert_eq!(
            attribute(&projection.value, "name").as_string(),
            Some("consema")
        );
        assert_eq!(
            attribute(&projection.value, "count")
                .as_integer()
                .expect("integer")
                .to_string(),
            "42"
        );
        assert_eq!(
            attribute(&projection.value, "ratio"),
            &PortableValue::decimal(Decimal::parse_json_number("1.5").expect("decimal"))
        );
        assert_eq!(
            attribute(&projection.value, "big")
                .as_integer()
                .expect("integer")
                .to_string(),
            "1000",
            "1e3 normalizes to an integer"
        );
        assert_eq!(
            attribute(&projection.value, "small"),
            &PortableValue::decimal(Decimal::parse_json_number("1.5").expect("decimal"))
        );
        assert_eq!(
            attribute(&projection.value, "enabled").as_boolean(),
            Some(true)
        );
        assert_eq!(
            attribute(&projection.value, "nothing").kind(),
            consema_core::PortableValueKind::Null
        );
        let tags = attribute(&projection.value, "tags")
            .as_sequence()
            .expect("tuple");
        assert_eq!(
            tags.iter()
                .map(|value| value.as_string().expect("string"))
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            entry_value(attribute(&projection.value, "labels"), "env").as_string(),
            Some("prod")
        );
        assert_eq!(projection.fidelity, Fidelity::Exact);
        assert!(projection.report.events().is_empty());
        assert!(blocks(&projection.value).is_empty());
    }

    #[test]
    fn duplicate_object_keys_are_preserved_in_order() {
        let projection = complete(body(&parse(
            b"dups = { a = 1, a = 2, b = 3 }\n",
            HclProfile::NativeV1,
        )));
        let mapping = attribute(&projection.value, "dups")
            .as_entry_mapping()
            .expect("duplicate keys force an entry mapping");
        assert_eq!(mapping.len(), 3);
        assert_eq!(mapping[0].key().as_string(), Some("a"));
        assert_eq!(
            mapping[0]
                .value()
                .as_integer()
                .expect("integer")
                .to_string(),
            "1"
        );
        assert_eq!(mapping[1].key().as_string(), Some("a"));
        assert_eq!(
            mapping[1]
                .value()
                .as_integer()
                .expect("integer")
                .to_string(),
            "2"
        );
        assert_eq!(mapping[2].key().as_string(), Some("b"));
        assert_eq!(projection.fidelity, Fidelity::Exact);
    }

    #[test]
    fn number_keys_project_as_canonical_decimal_strings() {
        let projection = complete(body(&parse(
            b"numkeys = { 1 = \"one\", 1.50 = \"ratio\", 1e3 = \"big\", 15e-1 = \"small\" }\n",
            HclProfile::NativeV1,
        )));
        let mapping = attribute(&projection.value, "numkeys")
            .as_entry_mapping()
            .expect("entry mapping");
        assert_eq!(
            mapping
                .iter()
                .map(|entry| entry.key().as_string().expect("string key"))
                .collect::<Vec<_>>(),
            ["1", "1.5", "1000", "1.5"],
            "number keys carry the exact canonical decimal spelling"
        );
    }

    #[test]
    fn parenthesized_scalar_keys_reduce_to_canonical_spellings() {
        let projection = complete(body(&parse(
            b"o = { (1) = \"int\", (true) = \"bool\", (null) = \"nul\", (\"s\") = \"str\", (-1.5) = \"neg\" }\n",
            HclProfile::NativeV1,
        )));
        let mapping = attribute(&projection.value, "o")
            .as_entry_mapping()
            .expect("entry mapping");
        assert_eq!(
            mapping
                .iter()
                .map(|entry| entry.key().as_string().expect("string key"))
                .collect::<Vec<_>>(),
            ["1", "true", "null", "s", "-1.5"]
        );
    }

    #[test]
    fn tuple_or_object_paren_keys_fail_atomically() {
        // A parenthesized key whose literal value is a tuple or object has no
        // canonical string spelling: the projection fails, never rendering a
        // guessed key.
        for source in [
            b"o = { ([1, 2]) = \"x\" }\n".as_slice(),
            b"o = { ({ a = 1 }) = \"x\" }\n".as_slice(),
        ] {
            let result = body(&parse(source, HclProfile::NativeV1));
            assert_eq!(
                failed_code(&result),
                "hcl.projection.unrepresentable@1",
                "tuple/object paren keys are unrepresentable"
            );
            assert_eq!(failed_arg(&result, "fact").as_deref(), Some("object-key"));
        }
    }

    #[test]
    fn derived_expressions_fail_atomically_without_policy() {
        // The `hcl.projection.non-literal-expression` conformance case.
        let samples = [
            b"count = 1 + 2\n".as_slice(),
            b"name = var.name\n".as_slice(),
            b"msg = \"hi ${name}\"\n".as_slice(),
            b"items = [for x in list : x]\n".as_slice(),
        ];
        for source in samples {
            let document = parse(source, HclProfile::NativeV1);
            assert_eq!(document.status(), FormationStatus::Complete);
            let result = body(&document);
            assert_eq!(
                failed_code(&result),
                "hcl.projection.non-literal-expression@1"
            );
            match &result {
                ProjectionResult::Failed(attempt) => {
                    assert!(
                        attempt.report.events().is_empty(),
                        "failed projections publish no partial report"
                    );
                    assert!(
                        attempt.diagnostics[0].arguments.contains_key("expression"),
                        "the diagnostic names the offending expression"
                    );
                }
                ProjectionResult::Complete(_) => panic!("projection must fail"),
            }
        }
    }

    #[test]
    fn literal_complete_boundary_matches_the_vector() {
        // The `hcl.projection.literal-complete-boundary` conformance case.
        let samples: &[(&[u8], bool)] = &[
            (b"a = -1\n", true),
            (b"a = 1 + 2\n", false),
            (b"a = {1 = \"a\"}\n", true),
            (b"a = \"no interpolation\"\n", true),
            (b"a = \"x${y}\"\n", false),
            (b"a = <<EOT\nplain\nEOT\n", true),
            (b"a = <<EOT\nhi ${x}\nEOT\n", false),
            (b"a = (42)\n", true),
            (b"a = -x\n", false),
            (b"a = [1, \"two\", {k = 3}]\n", true),
            (b"a = null\n", true),
            (b"a = !true\n", false),
            (b"a = max(1, 2)\n", false),
            (b"a = 15e-1\n", true),
        ];
        for (source, literal) in samples {
            let result = body(&parse(source, HclProfile::NativeV1));
            if *literal {
                let projection = complete(result);
                assert_eq!(projection.fidelity, Fidelity::Exact, "source {source:?}");
            } else {
                assert_eq!(
                    failed_code(&result),
                    "hcl.projection.non-literal-expression@1",
                    "source {source:?}"
                );
            }
        }
    }

    #[test]
    fn project_expression_policy_substitutes_extended_values() {
        // The `hcl.projection.project-expression-policy` conformance case.
        let source = b"count = 1 + 2\nname = var.name\nok = 42\n";
        let document = parse(source, HclProfile::NativeV1);
        let projection = complete(body_policy(&document, ExpressionPolicy::ProjectExpression));
        assert_eq!(projection.fidelity, Fidelity::Transformed);

        let count = attribute(&projection.value, "count");
        assert_eq!(
            object_value(count, "record").as_string(),
            Some("hcl.expression@1")
        );
        assert_eq!(object_value(count, "kind").as_string(), Some("binary"));
        assert_eq!(object_value(count, "text").as_string(), Some("1 + 2"));
        let fingerprint = object_value(count, "fingerprint")
            .as_string()
            .expect("fingerprint hex");
        assert_eq!(fingerprint.len(), 16, "16 lowercase hex digits");
        assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(fingerprint.to_lowercase(), fingerprint);

        let name = attribute(&projection.value, "name");
        assert_eq!(object_value(name, "kind").as_string(), Some("variable"));
        assert_eq!(object_value(name, "text").as_string(), Some("var.name"));

        assert_eq!(
            attribute(&projection.value, "ok")
                .as_integer()
                .expect("integer")
                .to_string(),
            "42",
            "literal-complete values stay typed members under the policy"
        );

        assert_eq!(projection.report.events().len(), 2);
        for event in projection.report.events() {
            assert_eq!(event.kind, ProjectionEventKind::ExpressionSubstituted);
            assert_eq!(event.impact, Fidelity::Transformed);
            assert_eq!(event.expression.role(), NodeRole::HclExpression);
            assert!(
                matches!(
                    event.value.segments(),
                    [
                        ValuePathSegment::ObjectValue(items),
                        ValuePathSegment::SequenceElement(_),
                        ValuePathSegment::ObjectValue(value),
                    ] if items == "items" && value == "value"
                ),
                "event value provenance descends to the attribute value: {:?}",
                event.value.segments()
            );
        }
    }

    #[test]
    fn expression_record_reproduces_the_validated_payload() {
        let document = parse(b"x = 1 + 2\n", HclProfile::NativeV1);
        let projection = complete(body_policy(&document, ExpressionPolicy::ProjectExpression));
        let expression_value = attribute(&projection.value, "x");
        let kind = object_value(expression_value, "kind")
            .as_string()
            .expect("kind")
            .to_owned();
        let text = object_value(expression_value, "text")
            .as_string()
            .expect("text")
            .to_owned();
        let fingerprint_hex = object_value(expression_value, "fingerprint")
            .as_string()
            .expect("fingerprint");
        let fingerprint = u64::from_str_radix(fingerprint_hex, 16).expect("hex fingerprint");
        let payload = ExpressionPayload {
            kind,
            text,
            fingerprint,
        };
        let extended = ExtendedValue::validated(&HclExpressionContract, payload.encode())
            .expect("the contract accepts the projection's own payload");
        assert_eq!(extended.type_id(), "hcl.expression");
        assert_eq!(extended.semantic_version(), 1);
        assert_eq!(extended.payload_codec_id(), "hcl.expression.canonical@1");
        assert_eq!(
            ExpressionPayload::decode(extended.canonical_payload()),
            Some(payload)
        );
        assert_eq!(
            object_value(expression_value, "record").as_string(),
            Some("hcl.expression@1"),
            "the wire record spelling is the type id plus the version"
        );
    }

    #[test]
    fn expression_contract_rejects_tampered_payloads() {
        let valid = ExpressionPayload {
            kind: "binary".to_owned(),
            text: "1 + 2".to_owned(),
            fingerprint: 42,
        }
        .encode();
        assert!(HclExpressionContract.validate_canonical(&valid).is_ok());

        let mut unknown_kind = valid.clone();
        unknown_kind[0] = 1; // length of "binary" (6) becomes 1: garbage blob
        assert!(
            HclExpressionContract
                .validate_canonical(&unknown_kind)
                .is_err()
        );

        let mut truncated = valid.clone();
        truncated.truncate(valid.len() - 4);
        assert!(
            HclExpressionContract
                .validate_canonical(&truncated)
                .is_err()
        );

        let mut extra = valid.clone();
        extra.push(0);
        assert!(HclExpressionContract.validate_canonical(&extra).is_err());

        let mut bad_kind = ExpressionPayload {
            kind: "binary".to_owned(),
            text: "1 + 2".to_owned(),
            fingerprint: 42,
        }
        .encode();
        bad_kind.splice(1..7, b"mystery".to_vec());
        assert!(HclExpressionContract.validate_canonical(&bad_kind).is_err());
    }

    #[test]
    fn fingerprint_is_structural_and_span_independent() {
        let first = parse(b"a = 1 + 2\n", HclProfile::NativeV1);
        let second = parse(b"a = 1 + 2\n", HclProfile::NativeV1);
        let projection = complete(body_policy(&first, ExpressionPolicy::ProjectExpression));
        let again = complete(body_policy(&second, ExpressionPolicy::ProjectExpression));
        let first_fingerprint = object_value(attribute(&projection.value, "a"), "fingerprint")
            .as_string()
            .expect("fingerprint");
        let second_fingerprint = object_value(attribute(&again.value, "a"), "fingerprint")
            .as_string()
            .expect("fingerprint");
        assert_eq!(
            first_fingerprint, second_fingerprint,
            "identical structure fingerprints identically across documents"
        );

        // A spelling variant that normalizes to one canonical value keeps
        // the same fingerprint; a real structural difference changes it.
        let alias = parse(b"a = 1.0 + 2\n", HclProfile::NativeV1);
        let alias_projection = complete(body_policy(&alias, ExpressionPolicy::ProjectExpression));
        assert_eq!(
            object_value(attribute(&alias_projection.value, "a"), "fingerprint")
                .as_string()
                .expect("fingerprint"),
            first_fingerprint,
            "canonical-decimal equality extends to the fingerprint"
        );
        let different = parse(b"a = 2 + 1\n", HclProfile::NativeV1);
        let different_projection =
            complete(body_policy(&different, ExpressionPolicy::ProjectExpression));
        assert_ne!(
            object_value(attribute(&different_projection.value, "a"), "fingerprint")
                .as_string()
                .expect("fingerprint"),
            first_fingerprint,
            "operator order is structural"
        );

        // The function exposed for materialization matches the record.
        let expression = first
            .document()
            .body()
            .items()
            .iter()
            .find_map(HclBodyItem::as_attribute)
            .expect("attribute")
            .expression();
        assert_eq!(
            format!("{:016x}", structural_fingerprint(expression)),
            first_fingerprint
        );
    }

    #[test]
    fn blocks_recurse_into_nested_body_records() {
        let source = b"a = 1\nresource \"web\" \"prod\" {\n  name = \"x\"\n  count = 2\n  child {\n    deep = true\n  }\n}\nb = 2\n";
        let projection = complete(body(&parse(source, HclProfile::NativeV1)));
        assert_eq!(attribute_names(&projection.value), ["a", "b"]);
        assert_eq!(
            items(&projection.value)
                .iter()
                .map(item_kind)
                .collect::<Vec<_>>(),
            ["attribute", "block", "attribute"],
            "the one ordered items sequence keeps the block interleaved in source order"
        );
        assert_eq!(blocks(&projection.value).len(), 1);
        assert_eq!(
            block_value(&projection.value, 0, "type").as_string(),
            Some("resource")
        );
        let labels = block_value(&projection.value, 0, "labels")
            .as_sequence()
            .expect("labels");
        assert_eq!(
            labels
                .iter()
                .map(|value| value.as_string().expect("label"))
                .collect::<Vec<_>>(),
            ["web", "prod"]
        );
        let nested = block_value(&projection.value, 0, "body");
        let (record, _) = record_parts(nested);
        assert_eq!(record, "hcl.body@1", "nested bodies are full records");
        assert_eq!(attribute_names(nested), ["name", "count"]);
        assert_eq!(
            attribute(nested, "count")
                .as_integer()
                .expect("integer")
                .to_string(),
            "2"
        );
        let grandchild = &blocks(nested)[0];
        assert_eq!(object_value(grandchild, "type").as_string(), Some("child"));
        let deepest = object_value(grandchild, "body");
        assert_eq!(attribute(deepest, "deep").as_boolean(), Some(true));
    }

    #[test]
    fn block_labels_carry_text_only() {
        let source = b"b web prod {\n  c = 1\n}\n";
        let projection = complete(body(&parse(source, HclProfile::NativeV1)));
        let labels = block_value(&projection.value, 0, "labels")
            .as_sequence()
            .expect("labels");
        assert_eq!(
            labels
                .iter()
                .map(|value| value.as_string().expect("label"))
                .collect::<Vec<_>>(),
            ["web", "prod"]
        );
    }

    #[test]
    fn empty_body_projects_an_empty_record() {
        let projection = complete(body(&parse(b"", HclProfile::NativeV1)));
        let (record, _) = record_parts(&projection.value);
        assert_eq!(record, "hcl.body@1");
        assert!(attribute_names(&projection.value).is_empty());
        assert!(blocks(&projection.value).is_empty());
        assert_eq!(projection.fidelity, Fidelity::Exact);
    }

    #[test]
    fn tfvars_complete_documents_project_the_same_record() {
        let source = b"region = \"us-east-1\"\ncount = 2\n";
        let document = parse(source, HclProfile::TfvarsV1);
        assert_eq!(document.status(), FormationStatus::Complete);
        let projection = complete(body(&document));
        assert_eq!(
            attribute(&projection.value, "region").as_string(),
            Some("us-east-1")
        );
        assert!(blocks(&projection.value).is_empty());
    }

    #[test]
    fn unary_minus_projects_typed_canonical_members() {
        let projection = complete(body(&parse(
            b"a = -1\nb = -1.50\nc = -0\nd = -15e-1\n",
            HclProfile::NativeV1,
        )));
        assert_eq!(
            attribute(&projection.value, "a")
                .as_integer()
                .expect("integer")
                .to_string(),
            "-1"
        );
        assert_eq!(
            attribute(&projection.value, "b"),
            &PortableValue::decimal(Decimal::parse_json_number("-1.5").expect("decimal"))
        );
        assert_eq!(
            attribute(&projection.value, "c")
                .as_integer()
                .expect("integer")
                .to_string(),
            "0",
            "-0 stays canonical zero"
        );
        assert_eq!(
            attribute(&projection.value, "d"),
            &PortableValue::decimal(Decimal::parse_json_number("-1.5").expect("decimal"))
        );
    }

    #[test]
    fn templates_project_exact_decoded_code_points() {
        // Escaped `$${` decodes to literal `${` text and stays literal.
        let escaped = complete(body(&parse(b"b = \"x$${y}\"\n", HclProfile::NativeV1)));
        assert_eq!(attribute(&escaped.value, "b").as_string(), Some("x${y}"));
        // Heredocs project their content; `<<-` strips the minimum indent.
        let plain = complete(body(&parse(
            b"c = <<EOT\n  line\nEOT\n",
            HclProfile::NativeV1,
        )));
        assert_eq!(attribute(&plain.value, "c").as_string(), Some("  line\n"));
        let strip = complete(body(&parse(
            b"d = <<-EOT\n    a\n      b\nEOT\n",
            HclProfile::NativeV1,
        )));
        assert_eq!(attribute(&strip.value, "d").as_string(), Some("a\n  b\n"));
        // An interpolation makes the template derived: atomic failure with
        // the exact source text in the diagnostic.
        let derived = body(&parse(b"a = \"caf\xC3\xA9 ${b}\"\n", HclProfile::NativeV1));
        assert_eq!(
            failed_code(&derived),
            "hcl.projection.non-literal-expression@1"
        );
        assert_eq!(
            failed_arg(&derived, "expression").as_deref(),
            Some("\"caf\u{e9} ${b}\"")
        );
    }

    #[test]
    fn provenance_uses_nested_value_paths() {
        let source = b"a = 1\nb {\n  c = 2\n}\n";
        let document = parse(source, HclProfile::NativeV1);
        let projection = complete(body(&document));
        let paths = projection
            .provenance
            .entries()
            .iter()
            .map(|entry| entry.projected.segments().to_vec())
            .collect::<Vec<_>>();
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(items),
                        ValuePathSegment::SequenceElement(0),
                        ValuePathSegment::ObjectValue(value),
                    ] if items == "items" && value == "value"
                )
            }),
            "root attribute value paths: {paths:?}"
        );
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(items),
                        ValuePathSegment::SequenceElement(1),
                    ] if items == "items"
                )
            }),
            "block object paths: {paths:?}"
        );
        assert!(
            paths.iter().any(|segments| {
                matches!(
                    segments.as_slice(),
                    [
                        ValuePathSegment::ObjectValue(items),
                        ValuePathSegment::SequenceElement(1),
                        ValuePathSegment::ObjectValue(body),
                        ValuePathSegment::ObjectValue(nested_items),
                        ValuePathSegment::SequenceElement(0),
                        ValuePathSegment::ObjectValue(_),
                    ] if items == "items" && body == "body" && nested_items == "items"
                )
            }),
            "nested body value paths descend through block/body: {paths:?}"
        );
        let origins = projection
            .provenance
            .entries()
            .iter()
            .map(|entry| entry.origins[0].node.role())
            .collect::<Vec<_>>();
        assert_eq!(
            origins,
            [
                NodeRole::HclAttribute,
                NodeRole::HclBlock,
                NodeRole::HclAttribute
            ],
            "one origin per attribute and block, in source order"
        );
        assert_eq!(projection.provenance.entries().len(), 3);
        // Ordinals follow the documented DFS walk: attribute `a` is ordinal
        // 0, its expression `1` ordinal 1, block `b` ordinal 2, then the
        // nested attribute `c` and its expression.
        let block_origin = &projection.provenance.entries()[1].origins[0];
        assert_eq!(block_origin.node.index(), 2);
        assert_eq!(block_origin.node.role(), NodeRole::HclBlock);
        let block = document
            .document()
            .body()
            .items()
            .iter()
            .find_map(HclBodyItem::as_block)
            .expect("block");
        assert_eq!(block_origin.span, block.span());
        // The attribute origins carry the exact union span.
        let attributes = document
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_attribute)
            .collect::<Vec<_>>();
        assert_eq!(
            projection.provenance.entries()[0].origins[0].span,
            span_of(&document, attributes[0])
        );
        let nested = projection.provenance.entries()[2].origins[0].span;
        let nested_attribute = block.body().items()[0]
            .as_attribute()
            .expect("nested attribute");
        assert_eq!(nested, span_of(&document, nested_attribute));
    }

    fn span_of(document: &Document, attribute: &crate::native::HclAttribute) -> Span {
        document
            .authority()
            .span(
                attribute.name_span().start_byte(),
                attribute.expression().span().end_byte(),
            )
            .expect("valid span")
    }

    #[test]
    fn substituted_expression_provenance_keeps_value_and_expression() {
        let source = b"a = 1\nb = var.x\n";
        let projection = complete(body_policy(
            &parse(source, HclProfile::NativeV1),
            ExpressionPolicy::ProjectExpression,
        ));
        let event = &projection.report.events()[0];
        let origin = projection
            .provenance
            .entries()
            .iter()
            .find(|entry| entry.origins[0].node == event.expression)
            .expect("the event expression has a provenance origin");
        assert_eq!(origin.projected, event.value);
        assert_eq!(origin.origins[0].node.role(), NodeRole::HclExpression);
        assert_eq!(origin.origins[0].relation, ProvenanceRelation::Direct);
        // The attribute and the substituted expression share the one
        // projected value location, each keeping its own Direct origin.
        assert_eq!(
            projection
                .provenance
                .entries()
                .iter()
                .filter(|entry| entry.projected == event.value)
                .count(),
            2
        );
    }

    #[test]
    fn recovered_documents_never_project() {
        // Duplicate attribute: Recovered with a proven body.
        let duplicate = parse(b"a = 1\na = 2\n", HclProfile::NativeV1);
        assert_eq!(duplicate.status(), FormationStatus::Recovered);
        for request in [
            ProjectionRequest::body(),
            ProjectionRequest::body_with_expression_policy(ExpressionPolicy::ProjectExpression),
        ] {
            let result = project(&duplicate, request);
            assert_eq!(failed_code(&result), "hcl.projection.incomplete-document@1");
        }
        // tfvars gate: a top-level block makes Recovered under the profile.
        let tfvars = parse(b"b {\n}\n", HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_eq!(
            failed_code(&body(&tfvars)),
            "hcl.projection.incomplete-document@1"
        );
    }

    #[test]
    fn projection_limits_are_atomic() {
        let document = parse(b"a = 1\nb = 2\n", HclProfile::NativeV1);
        let limits = ProjectionLimits {
            max_source_nodes: 1,
            ..ProjectionLimits::default()
        };
        let result = project(&document, ProjectionRequest::body().with_limits(limits));
        assert_eq!(failed_code(&result), "hcl.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_source_nodes")
        );

        let limits = ProjectionLimits {
            max_value_nodes: 3,
            ..ProjectionLimits::default()
        };
        let result = project(&document, ProjectionRequest::body().with_limits(limits));
        assert_eq!(failed_code(&result), "hcl.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_value_nodes")
        );

        let limits = ProjectionLimits {
            max_provenance_units: 1,
            ..ProjectionLimits::default()
        };
        let result = project(&document, ProjectionRequest::body().with_limits(limits));
        assert_eq!(failed_code(&result), "hcl.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_provenance_units")
        );

        let derived = parse(b"a = var.x\nb = var.y\n", HclProfile::NativeV1);
        let limits = ProjectionLimits {
            max_report_entries: 1,
            ..ProjectionLimits::default()
        };
        let result = project(
            &derived,
            ProjectionRequest::body_with_expression_policy(ExpressionPolicy::ProjectExpression)
                .with_limits(limits),
        );
        assert_eq!(failed_code(&result), "hcl.projection.resource-limit@1");
        assert_eq!(
            failed_arg(&result, "limit").as_deref(),
            Some("max_report_entries")
        );

        // Generous explicit limits still complete.
        let limits = ProjectionLimits {
            max_source_nodes: 20,
            max_value_nodes: 20,
            max_report_entries: 20,
            max_provenance_units: 20,
        };
        let result = project(&document, ProjectionRequest::body().with_limits(limits));
        assert!(matches!(result, ProjectionResult::Complete(_)));
    }

    #[test]
    fn kind_family_spellings_are_stable_and_closed() {
        let spellings = [
            ("number", b"number".as_slice()),
            ("boolean", b"boolean".as_slice()),
            ("null", b"null".as_slice()),
            ("template", b"template".as_slice()),
            ("function-call", b"function-call".as_slice()),
            ("variable", b"variable".as_slice()),
            ("unary", b"unary".as_slice()),
            ("binary", b"binary".as_slice()),
            ("conditional", b"conditional".as_slice()),
            ("for", b"for".as_slice()),
            ("tuple", b"tuple".as_slice()),
            ("object", b"object".as_slice()),
            ("parenthesized", b"parenthesized".as_slice()),
        ];
        for (spelling, bytes) in spellings {
            assert!(is_kind_family_spelling(bytes), "{spelling}");
        }
        assert!(!is_kind_family_spelling(b"variable-ref"));
        assert!(!is_kind_family_spelling(b"traversal"));
        assert!(!is_kind_family_spelling(b"for-tuple"));
        assert!(!is_kind_family_spelling(b"unknown"));
    }

    #[test]
    fn conformance_vector_literal_complete_record_round_trip() {
        // The record's members must reconstruct every value of the vector's
        // expected attributes through the PortableValue API.
        let source = b"name = \"consema\"\ncount = 42\nratio = 1.50\nbig = 1e3\nsmall = 15e-1\nenabled = true\nnothing = null\ntags = [\"a\", \"b\"]\nlabels = { env = \"prod\" }\ndups = { a = 1, a = 2 }\nnumkeys = { 1 = \"one\", 2 = \"two\" }\nnested = { \"x\" = { y = [1, 2] } }\n";
        let projection = complete(body(&parse(source, HclProfile::NativeV1)));
        assert_eq!(
            object_value(&projection.value, "record").as_string(),
            Some("hcl.body@1")
        );
        let dups = attribute(&projection.value, "dups")
            .as_entry_mapping()
            .expect("entry mapping");
        assert_eq!(
            dups.iter()
                .map(|entry| entry.key().as_string().expect("key"))
                .collect::<Vec<_>>(),
            ["a", "a"]
        );
        let nested = attribute(&projection.value, "nested")
            .as_entry_mapping()
            .expect("entry mapping");
        assert_eq!(nested.len(), 1);
        let inner = nested[0].value().as_entry_mapping().expect("inner mapping");
        assert_eq!(inner[0].key().as_string(), Some("y"));
        assert_eq!(
            inner[0]
                .value()
                .as_sequence()
                .expect("tuple")
                .iter()
                .map(|value| value.as_integer().expect("integer").to_string())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
    }
}
