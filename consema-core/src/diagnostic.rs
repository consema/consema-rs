//! Structured deterministic diagnostics.

use std::collections::BTreeMap;

/// Diagnostic category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticCategory {
    /// Source encoding or lexical issue.
    Lexical,
    /// Grammar or recovery issue.
    Syntax,
    /// Profile conformance issue.
    Conformance,
    /// Native semantic issue.
    Semantic,
    /// Query definition or execution issue.
    Query,
    /// Projection policy or loss event.
    Projection,
    /// Materialization request, representability, or transformation event.
    Materialization,
    /// Cross-profile projection-to-materialization composition event.
    Conversion,
    /// Edit validation or conflict issue.
    Edit,
    /// Resource limit issue.
    Resource,
    /// Encoding issue.
    Encoding,
}

/// Presentation severity, independent from control flow.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticSeverity {
    /// Informational message.
    Info,
    /// Warning that does not itself imply failure.
    Warning,
    /// Error presentation severity.
    Error,
}

/// A snapshot-neutral location used by common protocols.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DiagnosticLocation {
    /// Optional snapshot identity encoded by a document implementation.
    pub snapshot: Option<u64>,
    /// Half-open byte start.
    pub start_byte: u64,
    /// Half-open byte end.
    pub end_byte: u64,
}

/// A related diagnostic location and its stable role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedLocation {
    /// Stable namespaced relationship label.
    pub role: String,
    /// Related location.
    pub location: DiagnosticLocation,
}

/// Machine-readable diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    /// Stable namespaced code.
    pub code: String,
    /// Stable category.
    pub category: DiagnosticCategory,
    /// Presentation severity.
    pub severity: DiagnosticSeverity,
    /// Primary location when one exists.
    pub primary: Option<DiagnosticLocation>,
    /// Related locations in stable order.
    pub related: Vec<RelatedLocation>,
    /// Structured arguments sorted by key.
    pub arguments: BTreeMap<String, String>,
    /// Stable note identifiers or localized fallback text.
    pub notes: Vec<String>,
    /// Occurrence ordinal used as the final stable ordering key.
    pub occurrence: u64,
}

impl Diagnostic {
    /// Creates a minimal diagnostic.
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        category: DiagnosticCategory,
        severity: DiagnosticSeverity,
        primary: Option<DiagnosticLocation>,
        occurrence: u64,
    ) -> Self {
        Self {
            code: code.into(),
            category,
            severity,
            primary,
            related: Vec::new(),
            arguments: BTreeMap::new(),
            notes: Vec::new(),
            occurrence,
        }
    }

    /// Sorts diagnostics by source order, phase supplied by category, code and occurrence.
    pub fn sort_deterministically(diagnostics: &mut [Self]) {
        diagnostics.sort_by(|left, right| {
            let left_start = left
                .primary
                .as_ref()
                .map_or(u64::MAX, |item| item.start_byte);
            let right_start = right
                .primary
                .as_ref()
                .map_or(u64::MAX, |item| item.start_byte);
            left_start
                .cmp(&right_start)
                .then(left.category.cmp(&right.category))
                .then(left.code.cmp(&right.code))
                .then(left.occurrence.cmp(&right.occurrence))
        });
    }
}
