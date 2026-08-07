//! Lossless `hcl.native@1` and `hcl.tfvars@1` documents under the RFC 0014
//! boundary.
//!
//! The two profiles share one syntax system — the HCL Native Syntax as
//! frozen by HashiCorp's `hclsyntax/spec.md` — and one native semantic
//! model: body, attribute, block, label, expression, and template facts
//! (RFC 0014 §6). This differs from the plist family (RFC 0013), where two
//! profiles own disjoint syntax systems over one value model: here the two
//! profiles own one grammar, and `hcl.tfvars@1` is `hcl.native@1` under one
//! structural restriction — the top level of a tfvars document admits
//! attributes only, never blocks (RFC 0014 §5).
//!
//! The profile is selected by the caller before formation. Neither the `.tf`
//! nor the `.tfvars` extension ever selects a profile, representation, or
//! encoding, and Terraform's `.tfvars.json` convention (JSON-based HCL) is
//! an explicit v1 exclusion (RFC 0014 §1, §14).
//!
//! Both profiles are formation-only documents: Consema parses, preserves,
//! and queries HCL syntax and structure but never evaluates it. Variables,
//! function calls, template interpolation and directives, and
//! for-expressions are native content with exact source identity; no
//! evaluator exists anywhere in parse, query, projection, materialization,
//! or edit (RFC 0014 §1, hard gate 1).
//!
//! The source contract (RFC 0014 §2) is Unicode text in UTF-8 without a
//! byte-order mark: a BOM is Recovered with `hcl.parse.byte-order-mark@1`,
//! invalid UTF-8 is a fatal formation failure, a lone CR is never a
//! newline, and the encoding is always UTF-8, always selected before
//! formation.
//!
//! The feature map is complete: the native semantic model, the expression
//! AST with its exact-span double preservation, the literal-complete
//! boundary (RFC 0014 §8.1), and the canonical-decimal normalization (M1);
//! the self-owned tokenizer — the token stream, the 30-kind lossless piece
//! assembly (RFC 0014 §7.2), and the lexical half of the §12 divergence
//! inventory (M2); the parser — the body/expression grammar with recovery
//! semantics, the native tree assembly, and the [`HclFormed`] formation
//! result (M3); and the profile layer — the unified [`Document`] with the
//! profile as a field, the `hcl.tfvars@1` gate, and the frozen public API
//! (M4). Query (M5), projection (M6), materialization (M7), and edit (M8)
//! are implemented on these types unchanged. The caller-side explicit
//! encoding selection ([`HclEncodingSelection`]) is part of the frozen
//! surface: [`parse`] rejects any non-UTF-8 selection before formation with
//! the fatal `hcl.parse.encoding@1` source-contract diagnostic (RFC 0014
//! §2).

use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{FatalFormationFailure, ParseLimits, ProfileId, SourceEncoding};
use std::fmt;
use std::sync::Arc;

mod document;
mod edit;
mod expression;
mod lexer;
mod materialization;
mod native;
mod operation_registry;
mod parser;
mod projection;
mod query;

pub use document::Document;
pub use edit::{
    BodyPath, BodyPathStep, BodyPlacement, EditCommit, EditFailure, EditKey, EditOperation,
    EditTransaction, EditTransactionBuilder, EditValue, NodeRef,
};
pub use expression::{
    BinaryOp, HclCallArg, HclDirectiveKind, HclExpression, HclExpressionKind,
    HclExpressionKindName, HclForIntro, HclLiteralKey, HclLiteralObjectEntry, HclLiteralValue,
    HclNumber, HclObjectEntry, HclObjectKey, HclTemplateKey, HclTemplatePart, HclTraversalRoot,
    HclTraversalStep, HeredocFacts, HeredocMode, NonLiteralExpression, ObjectSeparator, UnaryOp,
    canonical_decimal, is_literal_complete, literal_value,
};
pub use lexer::{HclLexOutput, HclToken, HclTokenKind, lex};
pub use materialization::materialize;
pub use native::{
    HclAttribute, HclBlock, HclBlockLabel, HclBody, HclBodyItem, HclDocument, HclErrorRegion,
    HclSyntaxKind,
};
pub use operation_registry::format_operation_registry;
pub use parser::HclFormed;
pub use projection::{
    CompleteProjection, ExpressionPayload, ExpressionPolicy, FailedProjectionAttempt, Fidelity,
    HclExpressionContract, ProjectionEvent, ProjectionEventKind, ProjectionFailure,
    ProjectionLimits, ProjectionReport, ProjectionRequest, ProjectionResult, ProjectionTarget,
    ProvenanceEntry, ProvenanceMap, ProvenanceRelation, SourceOrigin, kind_family, project,
    structural_fingerprint,
};
pub use query::{
    HclMatch, HclSyntaxMatch, execute_hcl_native_query, execute_hcl_native_query_cursor,
    execute_hcl_syntax_query, execute_hcl_syntax_query_cursor,
};

/// Frozen HCL formation profiles (RFC 0014 §1).
///
/// The profile is selected by the caller before formation; neither the `.tf`
/// nor the `.tfvars` extension selects a profile, representation, or
/// encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HclProfile {
    /// The full HCL Native Syntax (RFC 0014 §4).
    NativeV1,
    /// `hcl.native@1` under the tfvars structural restriction: the top-level
    /// body admits attributes only, never blocks (RFC 0014 §5).
    TfvarsV1,
}

impl HclProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::NativeV1 => ProfileId::new("hcl.native", 1),
            Self::TfvarsV1 => ProfileId::new("hcl.tfvars", 1),
        }
    }
}

/// Explicit source-encoding selection for the UTF-8-only HCL source
/// contract (RFC 0014 §2).
///
/// HCL has no declaration, prolog, or encoding negotiation: the encoding is
/// always UTF-8 and always selected before formation. UTF-16, UTF-32,
/// Latin-1, Windows code pages, and any other encoding are explicit v1
/// exclusions. `ProfileDefault` and `Explicit(SourceEncoding::Utf8)` are
/// consistent with the profile; any other explicit encoding is a
/// source-contract conflict at formation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HclEncodingSelection {
    /// Apply the frozen profile default: UTF-8.
    ProfileDefault,
    /// Use one caller-selected encoding; only `SourceEncoding::Utf8` is
    /// consistent with the HCL source contract.
    Explicit(SourceEncoding),
}

impl HclEncodingSelection {
    /// Validates the selection against the UTF-8-only source contract and
    /// returns the effective encoding.
    ///
    /// A non-UTF-8 explicit selection is a source-contract conflict and a v1
    /// exclusion (RFC 0014 §2); formation rejects it before any byte is
    /// read.
    pub const fn validate(self) -> Result<SourceEncoding, HclEncodingSelectionError> {
        match self {
            Self::ProfileDefault | Self::Explicit(SourceEncoding::Utf8) => Ok(SourceEncoding::Utf8),
            Self::Explicit(_) => Err(HclEncodingSelectionError),
        }
    }
}

/// An HCL source-encoding selection is inconsistent with the UTF-8-only
/// source contract (RFC 0014 §2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HclEncodingSelectionError;

impl fmt::Display for HclEncodingSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("hcl source encoding must be UTF-8; other encodings are v1 exclusions")
    }
}

impl std::error::Error for HclEncodingSelectionError {}

/// HCL-specific formation, structure, recovery, and report limits (RFC 0014
/// §11).
///
/// The common limits bound source bytes, generic nesting, token and node
/// counts, and diagnostics; the flat fields bound the HCL-specific facts:
/// decoded text, body/expression/template depth, per-body item counts,
/// identifier/string/number/template/heredoc lengths, constructor extents,
/// and recovery/error/piece/report counts. Every limit failure is a fatal
/// formation failure or an atomic operation failure; a limit failure never
/// masquerades as an empty body, truncated expression, shortened query,
/// partial target, or successful edit (hard gate 4). All size arithmetic is
/// checked before allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HclParseLimits {
    /// Common source, nesting, token, node, and diagnostic limits; includes
    /// `max_source_bytes` and `max_diagnostics`.
    pub common: ParseLimits,
    /// Maximum decoded UTF-8 bytes.
    pub max_decoded_utf8_bytes: usize,
    /// Maximum decoded Unicode scalars.
    pub max_decoded_scalars: usize,
    /// Maximum body nesting depth (block nesting; the root body is depth 1).
    pub max_body_depth: usize,
    /// Maximum expression depth (the parse recursion budget, shared by
    /// structural equality and the literal predicate; stack-safe by
    /// default, see the [`Default`] impl).
    pub max_expression_depth: usize,
    /// Maximum template nesting depth (interpolations and directives may
    /// contain nested templates).
    pub max_template_depth: usize,
    /// Maximum attributes in one body.
    pub max_attribute_count: usize,
    /// Maximum blocks in one body.
    pub max_block_count: usize,
    /// Maximum labels on one block.
    pub max_label_count: usize,
    /// Maximum body items (attributes plus blocks) in one body.
    pub max_body_item_count: usize,
    /// Maximum identifier byte length (attributes, blocks, labels,
    /// variables, and functions).
    pub max_identifier_len: usize,
    /// Maximum quoted-template byte length.
    pub max_string_len: usize,
    /// Maximum canonical-decimal digit count of one number.
    pub max_number_digits: usize,
    /// Maximum template (quoted or heredoc content) byte length.
    pub max_template_len: usize,
    /// Maximum interpolation or directive sequences in one template.
    pub max_template_interpolations: usize,
    /// Maximum lines in one heredoc.
    pub max_heredoc_lines: usize,
    /// Maximum heredoc bytes; bounds the error region of an unterminated
    /// heredoc (RFC 0014 §3, §11).
    pub max_heredoc_bytes: usize,
    /// Maximum elements in one tuple constructor.
    pub max_tuple_elements: usize,
    /// Maximum entries in one object constructor.
    pub max_object_entries: usize,
    /// Maximum extent of one for-expression.
    pub max_for_extent: usize,
    /// Maximum recovery regions in one document.
    pub max_recovery_regions: usize,
    /// Maximum error regions in one document.
    pub max_error_regions: usize,
    /// Maximum lossless syntax pieces in one document (RFC 0014 §7.2).
    pub max_syntax_pieces: usize,
    /// Maximum projection, materialization, or edit report events.
    pub max_report_events: usize,
}

impl Default for HclParseLimits {
    /// Frozen R-3 defaults (plan §7.2, §11): the recursive depth budgets are
    /// stack-safe by measurement, not guesswork. On a 2 MB debug-build
    /// thread (`examples/depth_probe.rs`, 2026-08-07), the parse recursion
    /// dies of a stack overflow at 63–82 expression levels for the binding
    /// dimensions (call, template/heredoc region re-lexing, for, object,
    /// parens, tuple) and at 340 body levels; the defaults truncate at 24
    /// expression and 128 body levels, keeping at least a 2.5× margin.
    /// The flat count limits never recurse, so they stay generous.
    fn default() -> Self {
        Self {
            common: ParseLimits::default(),
            max_decoded_utf8_bytes: 128 * 1024 * 1024,
            max_decoded_scalars: 64 * 1024 * 1024,
            max_body_depth: 128,
            max_expression_depth: 24,
            max_template_depth: 256,
            max_attribute_count: 1_000_000,
            max_block_count: 1_000_000,
            max_label_count: 1_000_000,
            max_body_item_count: 1_000_000,
            max_identifier_len: 1024,
            max_string_len: 16 * 1024 * 1024,
            max_number_digits: 100_000,
            max_template_len: 16 * 1024 * 1024,
            max_template_interpolations: 1_000_000,
            max_heredoc_lines: 1_000_000,
            max_heredoc_bytes: 16 * 1024 * 1024,
            max_tuple_elements: 1_000_000,
            max_object_entries: 1_000_000,
            max_for_extent: 1_000_000,
            max_recovery_regions: 100_000,
            max_error_regions: 100_000,
            max_syntax_pieces: 2_000_000,
            max_report_events: 100_000,
        }
    }
}

/// Forms one `hcl.native@1` or `hcl.tfvars@1` document from raw bytes
/// (RFC 0014 §1, §3, §5).
///
/// Thin dispatch over [`Document::parse`]: the profile selects the
/// structural rule (the tfvars top-level restriction of RFC 0014 §5), the
/// encoding selection follows the frozen UTF-8 source contract of RFC 0014
/// §2, and the limits bound formation. Neither the `.tf` nor the `.tfvars`
/// extension selects a profile, representation, or encoding.
///
/// `ProfileDefault` and `Explicit(SourceEncoding::Utf8)` are consistent
/// with the profile; any other explicit selection is a caller-side
/// source-contract conflict and fails fatally with `hcl.parse.encoding@1`
/// before any byte is read (RFC 0014 §2). The selection gate is distinct
/// from BOM content recovery: a BOM in the source stays Recovered with
/// `hcl.parse.byte-order-mark@1` under either consistent selection.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: HclProfile,
    selection: HclEncodingSelection,
    limits: HclParseLimits,
) -> Result<Document, FatalFormationFailure> {
    match selection {
        HclEncodingSelection::ProfileDefault
        | HclEncodingSelection::Explicit(SourceEncoding::Utf8) => {}
        HclEncodingSelection::Explicit(_) => {
            return Err(FatalFormationFailure::from_diagnostic(Diagnostic::new(
                "hcl.parse.encoding@1",
                DiagnosticCategory::Encoding,
                DiagnosticSeverity::Error,
                None,
                0,
            )));
        }
    }
    Document::parse(source.into(), profile, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_document::{FormationStatus, WindowsCodePage};

    #[test]
    fn profile_ids_are_stable() {
        assert_eq!(HclProfile::NativeV1.id(), ProfileId::new("hcl.native", 1));
        assert_eq!(HclProfile::TfvarsV1.id(), ProfileId::new("hcl.tfvars", 1));
    }

    #[test]
    fn profiles_are_copy_and_distinct() {
        let first = HclProfile::NativeV1;
        let second = first;
        assert_eq!(first, second);
        assert_ne!(HclProfile::NativeV1, HclProfile::TfvarsV1);
    }

    #[test]
    fn encoding_selection_accepts_utf8_only() {
        assert_eq!(
            HclEncodingSelection::ProfileDefault.validate(),
            Ok(SourceEncoding::Utf8)
        );
        assert_eq!(
            HclEncodingSelection::Explicit(SourceEncoding::Utf8).validate(),
            Ok(SourceEncoding::Utf8)
        );
    }

    #[test]
    fn encoding_selection_rejects_non_utf8_exclusions() {
        for encoding in [
            SourceEncoding::Utf16Le,
            SourceEncoding::Utf16Be,
            SourceEncoding::Latin1,
            SourceEncoding::Binary,
            SourceEncoding::WindowsCodePage(
                WindowsCodePage::from_number(1252).expect("published code page"),
            ),
        ] {
            assert_eq!(
                HclEncodingSelection::Explicit(encoding).validate(),
                Err(HclEncodingSelectionError)
            );
        }
    }

    #[test]
    fn encoding_selection_error_is_displayed_stably() {
        let error = HclEncodingSelectionError;
        let message = error.to_string();
        assert!(message.contains("UTF-8"));
        assert!(!message.is_empty());
        let std_error: &dyn std::error::Error = &error;
        assert_eq!(std_error.to_string(), message);
    }

    #[test]
    fn parse_rejects_non_utf8_explicit_selection_before_any_byte_is_read() {
        // A non-UTF-8 explicit selection is a caller-side source-contract
        // conflict (RFC 0014 §2): formation fails fatally with
        // `hcl.parse.encoding@1` before any byte is read, under both
        // profiles.
        for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
            let error = parse(
                Arc::<[u8]>::from(b"a = 1\n".as_slice()),
                profile,
                HclEncodingSelection::Explicit(SourceEncoding::Utf16Le),
                HclParseLimits::default(),
            )
            .expect_err("non-UTF-8 explicit selection is a source-contract conflict");
            assert_eq!(error.diagnostics()[0].code, "hcl.parse.encoding@1");
        }
    }

    #[test]
    fn explicit_utf8_selection_never_disturbs_bom_content_recovery() {
        // The selection gate rejects explicit non-UTF-8 choices only; a BOM
        // in the source stays content-level recovery under either
        // consistent selection (RFC 0014 §2, §12 D-1).
        for selection in [
            HclEncodingSelection::ProfileDefault,
            HclEncodingSelection::Explicit(SourceEncoding::Utf8),
        ] {
            let document = parse(
                b"\xEF\xBB\xBFa = 1\n".as_slice(),
                HclProfile::NativeV1,
                selection,
                HclParseLimits::default(),
            )
            .expect("a consistent selection never conflicts with BOM content");
            assert_eq!(document.status(), FormationStatus::Recovered);
            assert!(
                document
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "hcl.parse.byte-order-mark@1")
            );
        }
    }

    #[test]
    fn parse_limits_defaults_are_frozen() {
        let limits = HclParseLimits::default();
        assert_eq!(limits.common, ParseLimits::default());
        assert_eq!(limits.max_decoded_utf8_bytes, 128 * 1024 * 1024);
        assert_eq!(limits.max_decoded_scalars, 64 * 1024 * 1024);
        assert_eq!(limits.max_body_depth, 128);
        assert_eq!(limits.max_expression_depth, 24);
        assert_eq!(limits.max_template_depth, 256);
        assert_eq!(limits.max_attribute_count, 1_000_000);
        assert_eq!(limits.max_block_count, 1_000_000);
        assert_eq!(limits.max_label_count, 1_000_000);
        assert_eq!(limits.max_body_item_count, 1_000_000);
        assert_eq!(limits.max_identifier_len, 1024);
        assert_eq!(limits.max_string_len, 16 * 1024 * 1024);
        assert_eq!(limits.max_number_digits, 100_000);
        assert_eq!(limits.max_template_len, 16 * 1024 * 1024);
        assert_eq!(limits.max_template_interpolations, 1_000_000);
        assert_eq!(limits.max_heredoc_lines, 1_000_000);
        assert_eq!(limits.max_heredoc_bytes, 16 * 1024 * 1024);
        assert_eq!(limits.max_tuple_elements, 1_000_000);
        assert_eq!(limits.max_object_entries, 1_000_000);
        assert_eq!(limits.max_for_extent, 1_000_000);
        assert_eq!(limits.max_recovery_regions, 100_000);
        assert_eq!(limits.max_error_regions, 100_000);
        assert_eq!(limits.max_syntax_pieces, 2_000_000);
        assert_eq!(limits.max_report_events, 100_000);
    }
}
