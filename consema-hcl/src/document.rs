//! Unified `hcl.native@1` / `hcl.tfvars@1` document layer (RFC 0014 §1, §3,
//! §5).
//!
//! The two profiles share one grammar and one native semantic model, so —
//! unlike the plist family (RFC 0013 §7), where two profiles own disjoint
//! syntax systems and `Document` is an enum over two formed representations
//! — [`Document`] is one structure with the profile as a field:
//! `hcl.tfvars@1` is `hcl.native@1` under one structural restriction, the
//! top-level body admits attributes only, never blocks (RFC 0014 §5).
//!
//! [`Document::parse`] dispatches on the profile: formation runs the frozen
//! native pipeline first, then the tfvars gate rejects any top-level block
//! with `hcl.tfvars.block-not-allowed@1` and Recovered status. The block
//! stays a native item of the Recovered document (RFC 0014 §3, §7):
//! recovery retains every independently proven construct, and the tfvars
//! restriction is a profile-level rule that does not break the native
//! model's invariants — the duplicate-attribute exclusion differs because
//! the per-body uniqueness constraint is a native-model invariant (RFC 0014
//! §3, §6).
//!
//! The encoding contract is the frozen UTF-8-only source contract (RFC 0014
//! §2), validated by formation: a BOM is Recovered with
//! `hcl.parse.byte-order-mark@1` (there is no `Bom` syntax kind, RFC 0014
//! §7.2), invalid UTF-8 is a fatal formation failure with
//! `hcl.parse.invalid-utf8@1`, and a lone CR is Recovered with
//! `hcl.parse.lone-cr@1`. The caller-side explicit selection surface is
//! [`crate::HclEncodingSelection`], which admits UTF-8 only.
//!
//! Every accessor returns an immutable snapshot fact. The native
//! [`HclDocument`], the lossless structural index, and the syntax kinds are
//! always present under both profiles: the two profiles own the one syntax
//! system, so no representation-specific accessor is ever absent. This
//! public surface is frozen for the M5-M8 operation milestones, which
//! consume these types unchanged.

use crate::native::{HclBodyItem, HclDocument, HclErrorRegion, HclSyntaxKind};
use crate::parser::HclFormed;
use crate::{HclParseLimits, HclProfile};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    DocumentAuthority, FatalFormationFailure, FormatFamilyId, FormationStatus,
    LosslessStructuralIndex, ProfileId, SnapshotIdentity, SourceSnapshot,
};
use std::sync::Arc;

/// Stable `hcl.tfvars.block-not-allowed@1` profile-restriction diagnostic
/// code (RFC 0014 §5, §11).
const T_FVARS_BLOCK_NOT_ALLOWED: &str = "hcl.tfvars.block-not-allowed@1";

/// One formed HCL document under one exact profile (RFC 0014 §1, §3).
///
/// The profile is a private field, not a representation choice: both
/// profiles share the one syntax system and the one native model, and the
/// profile gates Complete formation (the tfvars top-level restriction of
/// RFC 0014 §5) and the operation surface published over this document.
/// Every returned fact is an immutable snapshot fact.
#[derive(Clone, Debug)]
pub struct Document {
    profile: HclProfile,
    formed: HclFormed,
    /// Final formation status: the parser's own recovery plus the tfvars
    /// gate.
    status: FormationStatus,
    /// Merged diagnostics: the parser's ordered list plus the gate's, sorted
    /// deterministically.
    diagnostics: Vec<Diagnostic>,
}

impl Document {
    /// Forms one document from raw bytes under one exact profile (RFC 0014
    /// §1, §3, §5).
    ///
    /// The profile is selected by the caller before formation; neither the
    /// `.tf` nor the `.tfvars` extension selects a profile, representation,
    /// or encoding. The source contract is the frozen UTF-8 contract of RFC
    /// 0014 §2: a BOM is Recovered with `hcl.parse.byte-order-mark@1`,
    /// invalid UTF-8 is a fatal formation failure with
    /// `hcl.parse.invalid-utf8@1`, and a lone CR is Recovered with
    /// `hcl.parse.lone-cr@1`.
    ///
    /// Under `hcl.tfvars@1`, a block anywhere at the top level makes
    /// formation Recovered with one `hcl.tfvars.block-not-allowed@1`
    /// diagnostic per top-level block occurrence (RFC 0014 §5). The
    /// rejected block remains a native item of the Recovered document, so
    /// the document stays queryable over its proven parts (RFC 0014 §3,
    /// §7); the gate emits diagnostics, never error regions.
    pub fn parse(
        source: Arc<[u8]>,
        profile: HclProfile,
        limits: HclParseLimits,
    ) -> Result<Self, FatalFormationFailure> {
        let formed = crate::parser::parse_hcl(source, limits)?;
        let mut diagnostics = formed.diagnostics().to_vec();
        let mut status = formed.status();
        if profile == HclProfile::TfvarsV1 {
            for item in formed.document().body().items() {
                if let HclBodyItem::Block(block) = item {
                    status = FormationStatus::Recovered;
                    diagnostics.push(Diagnostic::new(
                        T_FVARS_BLOCK_NOT_ALLOWED,
                        DiagnosticCategory::Syntax,
                        DiagnosticSeverity::Error,
                        Some(block.span().diagnostic_location()),
                        0,
                    ));
                }
            }
        }
        Diagnostic::sort_deterministically(&mut diagnostics);
        Ok(Self {
            profile,
            formed,
            status,
            diagnostics,
        })
    }

    /// Formation status (RFC 0014 §3).
    #[must_use]
    pub const fn status(&self) -> FormationStatus {
        self.status
    }

    /// Complete or explicitly recovered formation state.
    #[must_use]
    pub const fn formation_status(&self) -> FormationStatus {
        self.status()
    }

    /// Immutable raw source with encoding facts.
    #[must_use]
    pub fn source(&self) -> &SourceSnapshot {
        self.formed.source()
    }

    /// Exact original bytes; unmodified rendering is byte-exact.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.formed.render()
    }

    /// Ordered diagnostics from formation, deterministically sorted; the
    /// tfvars gate diagnostics are merged with the parser's own.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Snapshot identity to which every handle and span of this document
    /// belongs.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.formed.authority().identity()
    }

    /// Exact source profile of the formed document.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Stable format family identity of the HCL family (RFC 0014 §1).
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("hcl", 1)
    }

    /// Native body tree bound to the frozen source; always present under
    /// both profiles, an empty body being a valid body (RFC 0014 §3, §6).
    #[must_use]
    pub const fn document(&self) -> &HclDocument {
        self.formed.document()
    }

    /// Exhaustive ordered lossless piece coverage of the raw bytes; always
    /// present under both profiles because both share the one syntax system
    /// (RFC 0014 §7.2).
    #[must_use]
    pub fn lossless_structural_index(&self) -> &LosslessStructuralIndex {
        self.formed.lossless_structural_index()
    }

    /// Ordered syntax kinds, parallel to the lossless structural pieces
    /// (RFC 0014 §7.2).
    #[must_use]
    pub fn lossless_syntax_kinds(&self) -> &[HclSyntaxKind] {
        self.formed.lossless_syntax_kinds()
    }

    /// Recovered error regions in source order (RFC 0014 §3, §7.2).
    ///
    /// The tfvars gate never contributes an error region: a rejected
    /// top-level block is a proven construct, not a recovered region.
    #[must_use]
    pub fn error_regions(&self) -> &[HclErrorRegion] {
        self.formed.error_regions()
    }

    /// Snapshot-bound identity authority for issuing query handles (M5-M8
    /// adaptation point).
    #[must_use]
    pub(crate) const fn authority(&self) -> &DocumentAuthority {
        self.formed.authority()
    }

    /// Limits applied during formation (M5-M8 adaptation point).
    #[must_use]
    pub(crate) const fn limits(&self) -> HclParseLimits {
        self.formed.limits()
    }

    /// Profile selector of the formed document (M5-M8 adaptation point).
    #[must_use]
    pub(crate) const fn selector(&self) -> HclProfile {
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{HclAttribute, HclBlock};

    fn parse(source: &[u8], profile: HclProfile) -> Document {
        Document::parse(
            Arc::<[u8]>::from(source),
            profile,
            HclParseLimits::default(),
        )
        .expect("formation of a valid UTF-8 source")
    }

    fn codes(document: &Document) -> Vec<String> {
        document
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    fn attributes(document: &Document) -> Vec<&HclAttribute> {
        document
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_attribute)
            .collect()
    }

    fn blocks(document: &Document) -> Vec<&HclBlock> {
        document
            .document()
            .body()
            .items()
            .iter()
            .filter_map(HclBodyItem::as_block)
            .collect()
    }

    fn assert_exact_coverage(document: &Document) {
        let pieces = document.lossless_structural_index().pieces();
        let kinds = document.lossless_syntax_kinds();
        assert_eq!(pieces.len(), kinds.len(), "kinds parallel pieces");
        let mut next = 0;
        for piece in pieces {
            assert_eq!(piece.span().start_byte(), next, "pieces are contiguous");
            next = piece.span().end_byte();
        }
        assert_eq!(
            next,
            document.source().len(),
            "pieces cover the source exactly"
        );
    }

    #[test]
    fn parse_dispatches_by_profile() {
        let native = parse(b"a = 1\n", HclProfile::NativeV1);
        let tfvars = parse(b"a = 1\n", HclProfile::TfvarsV1);
        assert_eq!(native.status(), FormationStatus::Complete);
        assert_eq!(tfvars.status(), FormationStatus::Complete);
        assert_eq!(native.profile(), ProfileId::new("hcl.native", 1));
        assert_eq!(tfvars.profile(), ProfileId::new("hcl.tfvars", 1));
        assert_eq!(native.format_family(), FormatFamilyId::new("hcl", 1));
        assert_eq!(tfvars.format_family(), FormatFamilyId::new("hcl", 1));
        assert_eq!(native.render(), b"a = 1\n");
    }

    #[test]
    fn native_profile_admits_top_level_blocks() {
        let native = parse(b"a = 1\nb \"web\" {\n  c = 2\n}\n", HclProfile::NativeV1);
        assert_eq!(native.status(), FormationStatus::Complete);
        assert!(native.diagnostics().is_empty());
        assert_eq!(attributes(&native).len(), 1);
        assert_eq!(blocks(&native).len(), 1);
        assert_eq!(blocks(&native)[0].block_type(), "b");
        assert_eq!(blocks(&native)[0].labels()[0].text(), "web");
    }

    #[test]
    fn tfvars_attribute_only_document_is_complete() {
        let tfvars = parse(
            b"a = 1\nb = [1, 2]\nc = { x = \"y\" }\n",
            HclProfile::TfvarsV1,
        );
        assert_eq!(tfvars.status(), FormationStatus::Complete);
        assert!(tfvars.diagnostics().is_empty());
        assert_eq!(attributes(&tfvars).len(), 3);
        assert!(blocks(&tfvars).is_empty());
        // RFC 0014 §5: no nested body can exist in a Complete tfvars
        // document, because nested bodies exist only inside blocks.
        assert!(
            tfvars
                .document()
                .body()
                .items()
                .iter()
                .all(|item| item.as_attribute().is_some())
        );
    }

    #[test]
    fn tfvars_accepts_the_full_expression_grammar() {
        // Terraform's static-only evaluation rule is application-layer
        // policy, never replicated at formation (RFC 0014 §5, hard gate 3).
        let tfvars = parse(
            b"region = var.region\ncount = length(locals.zones)\nmessage = \"hi ${var.name}\"\n",
            HclProfile::TfvarsV1,
        );
        assert_eq!(tfvars.status(), FormationStatus::Complete);
        assert_eq!(attributes(&tfvars).len(), 3);
    }

    #[test]
    fn tfvars_top_level_block_is_recovered_and_preserved() {
        let source: &[u8] = b"a = 1\nb {\n  c = 2\n}\n";
        let tfvars = parse(source, HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_eq!(codes(&tfvars), ["hcl.tfvars.block-not-allowed@1"]);
        // The block remains a native item of the Recovered document, so the
        // document stays queryable over its proven parts (RFC 0014 §3, §7).
        let items = tfvars.document().body().items();
        assert_eq!(items.len(), 2);
        assert!(items[0].as_attribute().is_some());
        let block = items[1].as_block().expect("block stays native");
        assert_eq!(block.block_type(), "b");
        assert_eq!(
            block.body().items()[0]
                .as_attribute()
                .expect("nested attribute")
                .name(),
            "c"
        );
        // The gate emits diagnostics, never error regions.
        assert!(tfvars.error_regions().is_empty());
        // Byte-exact rendering and exhaustive coverage still hold.
        assert_eq!(tfvars.render(), source);
        assert_exact_coverage(&tfvars);
    }

    #[test]
    fn tfvars_emits_one_diagnostic_per_top_level_block_in_source_order() {
        let source: &[u8] = b"b1 {\n}\nb2 {\n}\na = 1\n";
        let tfvars = parse(source, HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_eq!(
            codes(&tfvars),
            [
                "hcl.tfvars.block-not-allowed@1",
                "hcl.tfvars.block-not-allowed@1",
            ]
        );
        let items = tfvars.document().body().items();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_block().expect("block").block_type(), "b1");
        assert_eq!(items[1].as_block().expect("block").block_type(), "b2");
        assert_eq!(items[2].as_attribute().expect("attribute").name(), "a");
    }

    #[test]
    fn tfvars_nested_block_needs_no_own_diagnostic() {
        // Only top-level block occurrences trigger the gate; a block nested
        // inside the rejected top-level block is covered by its diagnostic.
        let tfvars = parse(b"b {\n  c {\n  }\n}\n", HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_eq!(codes(&tfvars), ["hcl.tfvars.block-not-allowed@1"]);
    }

    #[test]
    fn tfvars_block_labels_and_nested_body_survive_the_gate() {
        let source: &[u8] = b"resource \"web\" \"prod\" {\n  name = \"x\"\n}\n";
        let tfvars = parse(source, HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        let block = blocks(&tfvars)[0];
        assert_eq!(block.block_type(), "resource");
        assert_eq!(block.labels().len(), 2);
        assert!(block.labels()[0].quoted());
        assert_eq!(block.labels()[0].text(), "web");
        assert_eq!(block.labels()[1].text(), "prod");
        assert_eq!(block.body().items().len(), 1);
        assert_eq!(tfvars.render(), source);
    }

    #[test]
    fn tfvars_failed_block_is_parser_recovery_not_gate_rejection() {
        // An unclosed block never forms, so only the parser's own recovery
        // applies; the gate rejects proven blocks only.
        let tfvars = parse(b"b {\na = 1\n", HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert!(blocks(&tfvars).is_empty());
        assert!(
            codes(&tfvars)
                .iter()
                .any(|code| code == "hcl.parse.block@1")
        );
        assert!(
            !codes(&tfvars)
                .iter()
                .any(|code| code == "hcl.tfvars.block-not-allowed@1")
        );
    }

    #[test]
    fn profile_gate_diagnostics_merge_with_parse_diagnostics_deterministically() {
        // A parser-level recovery and the profile gate merge into one
        // deterministically sorted list, in source order.
        let tfvars = parse(b"b {\n}\na = 1\na = 2\n", HclProfile::TfvarsV1);
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_eq!(
            codes(&tfvars),
            [
                "hcl.tfvars.block-not-allowed@1",  // block at byte 0
                "hcl.parse.duplicate-attribute@1", // second `a` at byte 12
            ]
        );
    }

    #[test]
    fn duplicate_attribute_rule_applies_unchanged_under_tfvars() {
        // The per-body duplicate-attribute rule of RFC 0014 §3 applies
        // unchanged under the tfvars profile (RFC 0014 §5).
        for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
            let recovered = parse(b"a = 1\na = 2\n", profile);
            assert_eq!(recovered.status(), FormationStatus::Recovered);
            assert_eq!(codes(&recovered), ["hcl.parse.duplicate-attribute@1"]);
            assert_eq!(attributes(&recovered).len(), 1);
        }
    }

    #[test]
    fn bom_is_recovered_with_byte_order_mark_code() {
        // A BOM is a valid UTF-8 sequence but a profile violation: Recovered
        // with `hcl.parse.byte-order-mark@1`, never fatal and never
        // stripped (RFC 0014 §2, §12 D-1). The lexer recovers the BOM bytes
        // as an error region, and the parser's own item recovery reports the
        // same bytes at the body level.
        let source: &[u8] = b"\xEF\xBB\xBFa = 1\n";
        for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
            let recovered = parse(source, profile);
            assert_eq!(recovered.status(), FormationStatus::Recovered);
            assert!(
                codes(&recovered)
                    .iter()
                    .any(|code| code == "hcl.parse.byte-order-mark@1")
            );
            assert_eq!(recovered.render(), source);
        }
    }

    #[test]
    fn invalid_utf8_is_a_fatal_formation_failure() {
        // Invalid UTF-8 makes formation fatal with
        // `hcl.parse.invalid-utf8@1` before any byte is admitted (RFC 0014
        // §2, §3, §12 D-3).
        for profile in [HclProfile::NativeV1, HclProfile::TfvarsV1] {
            let error = Document::parse(
                Arc::<[u8]>::from(b"a = \xFF\n".as_slice()),
                profile,
                HclParseLimits::default(),
            )
            .expect_err("invalid UTF-8 is fatal");
            assert_eq!(error.diagnostics()[0].code, "hcl.parse.invalid-utf8@1");
        }
    }

    #[test]
    fn lone_cr_is_recovered() {
        // A lone CR is never a newline and never appears in a Complete
        // document (RFC 0014 §2, §12 D-2).
        let recovered = parse(b"a = 1\rb = 2\n", HclProfile::NativeV1);
        assert_eq!(recovered.status(), FormationStatus::Recovered);
        assert!(
            codes(&recovered)
                .iter()
                .any(|code| code == "hcl.parse.lone-cr@1")
        );
    }

    #[test]
    fn render_is_byte_exact_for_complete_and_recovered() {
        let cases: &[(&[u8], HclProfile)] = &[
            (b"a = 1\n", HclProfile::NativeV1),
            (b"a = 1\n", HclProfile::TfvarsV1),
            (b"a = 1\nb {\n  c = 2\n}\n", HclProfile::NativeV1),
            // Gate-recovered: the source stays untouched.
            (b"a = 1\nb {\n  c = 2\n}\n", HclProfile::TfvarsV1),
        ];
        for (source, profile) in cases {
            let document = parse(source, *profile);
            assert_eq!(document.render(), *source);
        }
    }

    #[test]
    fn snapshot_identity_is_fresh_per_document_and_stable() {
        let first = parse(b"a = 1\n", HclProfile::NativeV1);
        let second = parse(b"a = 1\n", HclProfile::NativeV1);
        let identity = first.snapshot_identity();
        assert_eq!(
            first.snapshot_identity(),
            identity,
            "identity is stable per snapshot"
        );
        assert_ne!(
            first.snapshot_identity(),
            second.snapshot_identity(),
            "every snapshot owns a fresh identity"
        );
    }

    #[test]
    fn lossless_index_and_kinds_are_parallel_and_exact() {
        let native = parse(
            b"# comment\na = \"${b.c}\"\nb \"x\" {\n  c = [1, 2]\n}\n",
            HclProfile::NativeV1,
        );
        assert_eq!(native.status(), FormationStatus::Complete);
        assert_exact_coverage(&native);
        let tfvars = parse(
            b"# comment\na = \"${b.c}\"\nb \"x\" {\n}\n",
            HclProfile::TfvarsV1,
        );
        assert_eq!(tfvars.status(), FormationStatus::Recovered);
        assert_exact_coverage(&tfvars);
    }

    #[test]
    fn frozen_public_surface_reports_consistent_facts() {
        // Every public accessor of the M4 frozen API, exercised on one
        // document.
        let document = parse(b"a = 1\n", HclProfile::TfvarsV1);
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.source().bytes(), b"a = 1\n");
        assert_eq!(document.render(), b"a = 1\n");
        assert!(document.diagnostics().is_empty());
        assert_eq!(document.snapshot_identity(), document.snapshot_identity());
        assert_eq!(document.profile(), ProfileId::new("hcl.tfvars", 1));
        assert_eq!(document.format_family(), FormatFamilyId::new("hcl", 1));
        assert_eq!(document.document().body().items().len(), 1);
        assert!(!document.lossless_structural_index().pieces().is_empty());
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            document.lossless_structural_index().pieces().len()
        );
        assert!(document.error_regions().is_empty());
    }

    #[test]
    fn crate_parse_entry_dispatches_thinly() {
        let source: &[u8] = b"a = 1\n";
        let direct = Document::parse(
            Arc::<[u8]>::from(source),
            HclProfile::NativeV1,
            HclParseLimits::default(),
        )
        .expect("forms");
        let via_entry = crate::parse(
            Arc::<[u8]>::from(source),
            HclProfile::NativeV1,
            crate::HclEncodingSelection::ProfileDefault,
            HclParseLimits::default(),
        )
        .expect("forms");
        assert_eq!(via_entry.status(), direct.status());
        assert_eq!(via_entry.profile(), direct.profile());
        assert_eq!(via_entry.render(), direct.render());
        assert_eq!(via_entry.diagnostics(), direct.diagnostics());
        // Every parse owns a fresh snapshot identity; the entry point is a
        // thin dispatch, so the two documents are equal in every fact
        // except their identities.
        assert_eq!(
            via_entry.document().body().items().len(),
            direct.document().body().items().len()
        );
    }
}
