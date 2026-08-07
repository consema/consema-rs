//! Frozen CLI exit classes and pure error classification.
//!
//! RFC 0015 §5 freezes the six exit classes, their codes (0-5), and the stable
//! mapping from error families to classes. The classification function is a
//! pure function: identical error objects always classify identically, so the
//! mapping can be driven by language-neutral vectors. The CLI binary only
//! applies the mapped code; it never invents new classification rules.

/// One of the six frozen CLI exit classes (RFC 0015 §5.1).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExitClass {
    /// The command completed and produced its full result. A Recovered state
    /// report, an ambiguity fact report, an unauthorized-loss report, and a
    /// plan manifest with per-file `failed` entries are all complete results.
    Success,
    /// Argument or syntax error: unknown command, unknown argument, rejected
    /// abbreviation, missing or invalid `--format`, missing `--profile` on a
    /// parse-class command, `--apply` without a prior plan, invalid
    /// `--redact-keys` pattern.
    Usage,
    /// The operation failed on the data itself: `FatalFormationFailure`
    /// (including `core.source.*` diagnostics), an encoding source-contract
    /// conflict, an unresolvable ambiguity, a strict request/plan decode
    /// failure, or an input-file read failure.
    Data,
    /// Any resource budget was exceeded: SDK limits (`ParseLimits`,
    /// `ProtocolLimits`, `SourcePatchLimits`), CLI file-size/batch/manifest
    /// limits, or a `ResourceLimit` raised while decoding a request.
    Limit,
    /// A write precondition failed: stale base digest, original-bytes
    /// mismatch, edit conflict, permission/disk failure, read-only target,
    /// symlink-policy rejection, an apply item that cannot continue after an
    /// interruption, or a user interrupt signal.
    Precondition,
    /// An unclassified internal error (a bug; the diagnostic template must
    /// name the command, the involved file, and the diagnostic code).
    Internal,
}

impl ExitClass {
    /// Frozen process exit code for the class (RFC 0015 §5.1 classification
    /// table). Codes 6-255 are reserved and never produced by v1.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Usage => 1,
            Self::Data => 2,
            Self::Limit => 3,
            Self::Precondition => 4,
            Self::Internal => 5,
        }
    }

    /// Canonical `exit_class` envelope name (RFC 0015 §4.1).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Usage => "usage",
            Self::Data => "data",
            Self::Limit => "limit",
            Self::Precondition => "precondition",
            Self::Internal => "internal",
        }
    }

    /// Parses one canonical envelope name into the closed class set.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "success" => Some(Self::Success),
            "usage" => Some(Self::Usage),
            "data" => Some(Self::Data),
            "limit" => Some(Self::Limit),
            "precondition" => Some(Self::Precondition),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Classifies one exit class into its frozen process exit code.
///
/// This is the identity table of RFC 0015 §5.1: `success -> 0`, `usage -> 1`,
/// `data -> 2`, `limit -> 3`, `precondition -> 4`, `internal -> 5`. The exit
/// code expresses whether the operation produced a complete result, never the
/// health of the data itself.
#[must_use]
pub const fn classify(exit_class: ExitClass) -> u8 {
    exit_class.exit_code()
}

/// Classifies a stable error code into its frozen exit class.
///
/// The mapping is the exhaustive family table of RFC 0015 §5.2:
///
/// - `cli.usage.*` -> [`ExitClass::Usage`] (1)
/// - `cli.data.*` and `cli.detection.*` (ambiguity) -> [`ExitClass::Data`] (2)
/// - `cli.limit.*` and any `*-resource-limit@1` (core or format-local) ->
///   [`ExitClass::Limit`] (3)
/// - `cli.write.*`, `cli.interrupted.signal@1`, the `core.source.patch-*-mismatch@1`
///   precondition family, and `core.edit.*` conflicts -> [`ExitClass::Precondition`]
///   (4); the stale/original-bytes/io rules all land here
/// - `cli.internal.unclassified@1` -> [`ExitClass::Internal`] (5)
/// - `core.protocol.*` strict-decode failures -> [`ExitClass::Data`] (2),
///   with `core.protocol.resource-limit@1` overridden to [`ExitClass::Limit`]
/// - `core.source.*` diagnostics carried by `FatalFormationFailure` ->
///   [`ExitClass::Data`] (2)
/// - any code outside these frozen families -> [`ExitClass::Data`] (2): the
///   operation did not produce a complete result. Format-layer codes are
///   passed through unchanged; they never invent new classes.
///
/// Report-as-result outcomes (Recovered state reports, ambiguity fact reports,
/// unauthorized-loss reports) classify as [`ExitClass::Success`] (0) at the
/// outcome level, not through error codes.
#[must_use]
pub fn classify_error_code(code: &str) -> ExitClass {
    if code.starts_with("cli.usage.") {
        return ExitClass::Usage;
    }
    if code.starts_with("cli.data.") || code.starts_with("cli.detection.") {
        return ExitClass::Data;
    }
    if code.starts_with("cli.limit.") {
        return ExitClass::Limit;
    }
    if code.starts_with("cli.write.") || code.starts_with("cli.interrupted.") {
        return ExitClass::Precondition;
    }
    if code.starts_with("cli.internal.") {
        return ExitClass::Internal;
    }
    if code.ends_with(".resource-limit@1") {
        return ExitClass::Limit;
    }
    if code.starts_with("core.source.patch-") && code.ends_with("-mismatch@1") {
        return ExitClass::Precondition;
    }
    if code.starts_with("core.edit.") {
        return ExitClass::Precondition;
    }
    ExitClass::Data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_to_code_table_is_exhaustive_and_closed() {
        // RFC 0015 §5.1 classification table; codes 6-255 stay reserved.
        let table = [
            (ExitClass::Success, 0),
            (ExitClass::Usage, 1),
            (ExitClass::Data, 2),
            (ExitClass::Limit, 3),
            (ExitClass::Precondition, 4),
            (ExitClass::Internal, 5),
        ];
        for (exit_class, code) in table {
            assert_eq!(classify(exit_class), code);
            assert_eq!(exit_class.exit_code(), code);
        }
        for code in 0..=5 {
            assert!(
                table
                    .iter()
                    .any(|(_, expected)| *expected == u8::try_from(code).unwrap())
            );
        }
    }

    #[test]
    fn report_as_result_rules_classify_success() {
        // Recovered state report, ambiguity fact report, and unauthorized-loss
        // report are complete results -> exit 0 (RFC 0015 §5.1 success row).
        assert_eq!(classify(ExitClass::Success), 0);
        assert_eq!(ExitClass::Success.name(), "success");
    }

    #[test]
    fn usage_family_classifies_one() {
        for code in [
            "cli.usage.invalid-argument@1",
            "cli.usage.invalid-format@1",
            "cli.usage.missing-plan@1",
            "cli.usage.missing-required@1",
            "cli.usage.redaction-pattern@1",
            "cli.usage.unknown-argument@1",
            "cli.usage.unknown-command@1",
        ] {
            assert_eq!(classify_error_code(code), ExitClass::Usage);
        }
        assert_eq!(
            classify_error_code("cli.usage.invalid-format@1").exit_code(),
            1
        );
    }

    #[test]
    fn data_family_and_formation_failures_classify_two() {
        // FatalFormationFailure (including core.source.invalid-utf8@1) -> 2.
        for code in [
            "cli.data.invalid-request@1",
            "cli.data.io@1",
            "cli.detection.ambiguous@1",
            "core.source.invalid-utf8@1",
            "core.source.code-page-required@1",
            "core.protocol.invalid-json@1",
            "core.protocol.schema-mismatch@1",
            "core.query.invalid-argument@1",
        ] {
            assert_eq!(classify_error_code(code), ExitClass::Data);
        }
        assert_eq!(
            classify_error_code("cli.data.invalid-request@1").exit_code(),
            2
        );
    }

    #[test]
    fn every_resource_limit_classifies_three() {
        // Any *-resource-limit@1, core or format-local, -> 3; the CLI-layer
        // cli.limit.* family lands here as well.
        for code in [
            "cli.limit.batch-count@1",
            "cli.limit.file-size@1",
            "cli.limit.manifest-size@1",
            "core.protocol.resource-limit@1",
            "core.parse.resource-limit@1",
            "core.query.resource-limit@1",
            "ini.parse.resource-limit@1",
            "xml.parse.resource-limit@1",
        ] {
            assert_eq!(classify_error_code(code), ExitClass::Limit);
        }
        assert_eq!(classify_error_code("cli.limit.file-size@1").exit_code(), 3);
        // The protocol resource-limit override beats the core.protocol rule.
        assert_eq!(
            classify_error_code("core.protocol.resource-limit@1"),
            ExitClass::Limit
        );
    }

    #[test]
    fn precondition_family_classifies_four() {
        // stale digest, original-bytes mismatch, write I/O, edit conflicts.
        for code in [
            "core.source.patch-base-mismatch@1",
            "core.source.patch-original-mismatch@1",
            "core.source.patch-target-mismatch@1",
            "core.edit.precondition-failed@1",
            "cli.write.io@1",
            "cli.write.permission@1",
            "cli.write.read-only@1",
            "cli.write.symlink-policy@1",
            "cli.write.target-is-directory@1",
            "cli.interrupted.signal@1",
        ] {
            assert_eq!(classify_error_code(code), ExitClass::Precondition);
        }
        assert_eq!(
            classify_error_code("core.source.patch-base-mismatch@1").exit_code(),
            4
        );
        assert_eq!(classify_error_code("cli.write.io@1").exit_code(), 4);
        assert_eq!(
            classify_error_code("core.source.patch-original-mismatch@1").exit_code(),
            4
        );
        assert_eq!(
            classify_error_code("cli.interrupted.signal@1").exit_code(),
            4
        );
    }

    #[test]
    fn internal_family_classifies_five() {
        assert_eq!(
            classify_error_code("cli.internal.unclassified@1"),
            ExitClass::Internal
        );
        assert_eq!(
            classify_error_code("cli.internal.unclassified@1").exit_code(),
            5
        );
    }

    #[test]
    fn unlisted_format_codes_pass_through_as_data() {
        // Format-layer codes are never rewritten and never invent new classes:
        // an unlisted code means the operation did not produce a complete
        // result -> data (2).
        for code in [
            "ini.parse.malformed-line@1",
            "json.parse.invalid-json@1",
            "yaml.parse.syntax@1",
            "example.unknown-code@1",
            "",
        ] {
            assert_eq!(classify_error_code(code), ExitClass::Data);
        }
    }

    #[test]
    fn envelope_names_round_trip() {
        for exit_class in [
            ExitClass::Success,
            ExitClass::Usage,
            ExitClass::Data,
            ExitClass::Limit,
            ExitClass::Precondition,
            ExitClass::Internal,
        ] {
            assert_eq!(ExitClass::parse(exit_class.name()), Some(exit_class));
        }
        assert_eq!(ExitClass::parse("unknown"), None);
    }
}
