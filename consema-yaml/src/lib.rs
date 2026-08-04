//! Lossless YAML 1.2 Core and YAML 1.1 compatibility documents.
//!
//! The parser backend is intentionally private: Consema owns profile decisions,
//! source identity, diagnostics, resource limits, native semantics, and graph
//! composition. No third-party parser type is part of the public contract.

use std::sync::Arc;

use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure, FormatFamilyId,
    ParseLimits, ProfileId, SnapshotIdentity, SourceEncoding, SourceLimits, SourceSnapshot,
};

mod backend;

use backend::{BackendError, BackendEventKind, parse_events};

/// Frozen YAML language profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum YamlProfile {
    /// YAML 1.2.2 presentation grammar with the Core schema.
    Yaml12CoreV1,
    /// Safe YAML 1.2-compatible presentation with frozen YAML 1.1 scalar resolution.
    Yaml11CompatV1,
}

impl YamlProfile {
    /// Stable profile identifier.
    #[must_use]
    pub fn id(self) -> ProfileId {
        match self {
            Self::Yaml12CoreV1 => ProfileId::new("yaml.1.2-core", 1),
            Self::Yaml11CompatV1 => ProfileId::new("yaml.1.1-compat", 1),
        }
    }

    const fn accepted_version(self) -> &'static str {
        match self {
            Self::Yaml12CoreV1 => "1.2",
            Self::Yaml11CompatV1 => "1.1",
        }
    }
}

/// Parses one exact YAML stream using BOM-detected UTF-8/UTF-16 source rules.
pub fn parse(
    source: impl Into<Arc<[u8]>>,
    profile: YamlProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    let bytes = source.into();
    if bytes.len() > limits.max_source_bytes {
        return Err(FatalFormationFailure::resource_limit(
            "source-bytes",
            bytes.len(),
            limits.max_source_bytes,
        ));
    }
    let source = SourceSnapshot::from_raw(
        bytes,
        EncodingRequest::new(SourceEncoding::Utf8),
        SourceLimits {
            max_raw_bytes: limits.max_source_bytes,
            ..SourceLimits::default()
        },
    )
    .map_err(FatalFormationFailure::source_error)?;
    let text = source
        .decoded_text()
        .expect("YAML profiles always request decoded text");
    validate_version_directives(text, profile)?;
    let events = parse_events(text, limits.max_token_count, limits.max_nesting_depth)
        .map_err(|error| backend_failure(error, &source))?;
    let document_count = events
        .iter()
        .filter(|event| matches!(event.kind, BackendEventKind::DocumentStart { .. }))
        .count();
    Ok(Document {
        authority: DocumentAuthority::fresh(),
        source,
        profile,
        stream_documents: document_count,
        parse_limits: limits,
    })
}

/// Immutable exact-source YAML stream snapshot.
#[derive(Clone, Debug)]
pub struct Document {
    authority: DocumentAuthority,
    source: SourceSnapshot,
    profile: YamlProfile,
    stream_documents: usize,
    parse_limits: ParseLimits,
}

impl Document {
    /// Snapshot identity to which future native handles and spans are bound.
    #[must_use]
    pub const fn snapshot_identity(&self) -> SnapshotIdentity {
        self.authority.identity()
    }

    /// Exact immutable raw source and decoded-location facts.
    #[must_use]
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Default rendering is byte-for-byte identical to the input.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        self.source.bytes()
    }

    /// YAML format-family contract.
    #[must_use]
    pub fn format_family(&self) -> FormatFamilyId {
        FormatFamilyId::new("yaml", 1)
    }

    /// Exact selected YAML profile.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile.id()
    }

    /// Number of independent YAML documents in this stream.
    #[must_use]
    pub const fn document_count(&self) -> usize {
        self.stream_documents
    }

    /// Resource contract used to form this stream.
    #[must_use]
    pub const fn parse_limits(&self) -> ParseLimits {
        self.parse_limits
    }
}

fn validate_version_directives(
    text: &str,
    profile: YamlProfile,
) -> Result<(), FatalFormationFailure> {
    for (line_index, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        let Some(rest) = line.strip_prefix("%YAML") else {
            continue;
        };
        let Some(separator) = rest.chars().next() else {
            continue;
        };
        if !matches!(separator, ' ' | '\t') {
            continue;
        }
        let version = rest
            .trim_start_matches([' ', '\t'])
            .split([' ', '\t', '#'])
            .next()
            .unwrap_or_default();
        if version != profile.accepted_version() {
            let mut diagnostic = Diagnostic::new(
                "yaml.profile.version-directive@1",
                DiagnosticCategory::Conformance,
                DiagnosticSeverity::Error,
                None,
                0,
            );
            diagnostic
                .arguments
                .insert("selected_profile".to_owned(), profile.id().id().to_owned());
            diagnostic
                .arguments
                .insert("declared_version".to_owned(), version.to_owned());
            diagnostic
                .arguments
                .insert("line".to_owned(), (line_index + 1).to_string());
            return Err(FatalFormationFailure::from_diagnostic(diagnostic));
        }
    }
    Ok(())
}

fn backend_failure(error: BackendError, source: &SourceSnapshot) -> FatalFormationFailure {
    match error {
        BackendError::ResourceLimit {
            name,
            observed,
            limit,
        } => FatalFormationFailure::resource_limit(name, observed, limit),
        BackendError::Syntax { scalar_offset } => {
            let location = source
                .raw_byte_at(DecodedOffset::UnicodeScalar(scalar_offset))
                .ok()
                .map(|byte| DiagnosticLocation {
                    snapshot: None,
                    start_byte: byte as u64,
                    end_byte: byte as u64,
                });
            FatalFormationFailure::from_diagnostic(Diagnostic::new(
                "yaml.parse.syntax@1",
                DiagnosticCategory::Syntax,
                DiagnosticSeverity::Error,
                location,
                0,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multidocument_stream_is_profile_bound() {
        let source = b"%YAML 1.2\n---\na: &x [1, *x]\n---\nb: |\n  text\n";
        let document = parse(
            source.as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.render(), source);
        assert_eq!(document.profile().id(), "yaml.1.2-core");
        assert_eq!(document.document_count(), 2);
    }

    #[test]
    fn utf16_bom_source_is_retained_and_location_aware() {
        let source = [0xff, 0xfe, b'a', 0, b':', 0, b' ', 0, b'1', 0];
        let document = parse(source, YamlProfile::Yaml12CoreV1, ParseLimits::default()).unwrap();
        assert_eq!(document.render(), &source);
        assert_eq!(document.source().decoded_text(), Some("\u{feff}a: 1"));
        assert_eq!(document.document_count(), 1);
    }

    #[test]
    fn profile_directives_are_not_silently_cross_loaded() {
        let error = parse(
            b"%YAML 1.1\n---\nyes\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            error.diagnostics()[0].code,
            "yaml.profile.version-directive@1"
        );

        let document = parse(
            b"%YAML 1.1\n---\nyes\n".as_slice(),
            YamlProfile::Yaml11CompatV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(document.profile().id(), "yaml.1.1-compat");

        let commented = parse(
            b"%YAML\t1.2 # profile\n---\nx\n".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(commented.document_count(), 1);
    }

    #[test]
    fn syntax_and_resource_failures_form_no_document() {
        let syntax = parse(
            b"[unterminated".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(syntax.diagnostics()[0].code, "yaml.parse.syntax@1");

        let limited = parse(
            b"[[x]]".as_slice(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits {
                max_nesting_depth: 1,
                ..ParseLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(limited.diagnostics()[0].code, "core.parse.resource-limit@1");
    }
}
