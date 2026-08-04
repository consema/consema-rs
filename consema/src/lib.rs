//! Consema public facade for core semantics, protocol, JSON, TOML and PVCE.

mod conversion;

pub use conversion::{
    CompleteConversion, ConversionFailure, ConversionFidelity, ConversionProjectionProvenance,
    ConversionProjectionReport, ConversionReport, ConversionResult, convert_json, convert_toml,
};

pub use consema_core as core;
pub use consema_document as document;
pub use consema_json as json;
pub use consema_protocol as protocol;
pub use consema_pvce as pvce;
pub use consema_toml as toml;

use std::sync::Arc;

/// Typed adapter failure on the common opaque facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatMismatch {
    /// The snapshot is not a JSON document.
    Json,
    /// The snapshot is not a TOML document.
    Toml,
}

/// Common opaque document snapshot over the supported format documents.
///
/// The concrete representation is private; format access is only possible
/// through the typed adapters. All returned facts are immutable snapshot facts.
#[derive(Clone, Debug)]
pub struct Document {
    inner: DocumentInner,
}

#[derive(Clone, Debug)]
enum DocumentInner {
    Json(json::Document),
    Toml(toml::Document),
}

impl Document {
    /// Parses one JSON/JSONC snapshot under an exact profile.
    pub fn parse_json(
        source: impl Into<Arc<[u8]>>,
        profile: json::JsonProfile,
        limits: document::ParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Json(json::parse(source, profile, limits)?),
        })
    }

    /// Parses one TOML snapshot under the exact profile.
    pub fn parse_toml(
        source: impl Into<Arc<[u8]>>,
        profile: toml::TomlProfile,
        limits: document::ParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Toml(toml::parse(source, profile, limits)?),
        })
    }

    /// Default rendering is byte-for-byte identical to the source.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        match &self.inner {
            DocumentInner::Json(document) => document.render(),
            DocumentInner::Toml(document) => document.render(),
        }
    }

    /// Formation status of the underlying snapshot.
    #[must_use]
    pub fn formation_status(&self) -> document::FormationStatus {
        match &self.inner {
            DocumentInner::Json(document) => document.formation_status(),
            DocumentInner::Toml(document) => document.formation_status(),
        }
    }

    /// Deterministically ordered document diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[core::Diagnostic] {
        match &self.inner {
            DocumentInner::Json(document) => document.diagnostics(),
            DocumentInner::Toml(document) => document.diagnostics(),
        }
    }

    /// Snapshot identity to which every handle and span belongs.
    #[must_use]
    pub fn snapshot_identity(&self) -> document::SnapshotIdentity {
        match &self.inner {
            DocumentInner::Json(document) => document.snapshot_identity(),
            DocumentInner::Toml(document) => document.snapshot_identity(),
        }
    }

    /// Exact source profile of the underlying format document.
    #[must_use]
    pub fn profile(&self) -> document::ProfileId {
        match &self.inner {
            DocumentInner::Json(document) => document.profile(),
            DocumentInner::Toml(document) => document.profile(),
        }
    }

    /// Typed JSON adapter; fails only when the snapshot is not JSON.
    pub fn as_json(&self) -> Result<&json::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Json(document) => Ok(document),
            DocumentInner::Toml(_) => Err(FormatMismatch::Json),
        }
    }

    /// Typed TOML adapter; fails only when the snapshot is not TOML.
    pub fn as_toml(&self) -> Result<&toml::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Json(_) => Err(FormatMismatch::Toml),
            DocumentInner::Toml(document) => Ok(document),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_document_facade_is_opaque_and_typed() {
        let json = Document::parse_json(
            br#"{"a":1}"#.as_slice(),
            json::JsonProfile::StrictV1,
            document::ParseLimits::default(),
        )
        .expect("JSON facade");
        assert_eq!(json.render(), br#"{"a":1}"#);
        assert_eq!(json.formation_status(), document::FormationStatus::Complete);
        assert_eq!(
            json.as_json().expect("json adapter").render(),
            br#"{"a":1}"#
        );
        assert!(matches!(json.as_toml(), Err(FormatMismatch::Toml)));

        let toml = Document::parse_toml(
            b"value = 1".as_slice(),
            toml::TomlProfile::Toml10V1,
            document::ParseLimits::default(),
        )
        .expect("TOML facade");
        assert_eq!(toml.render(), b"value = 1");
        assert!(matches!(toml.as_json(), Err(FormatMismatch::Json)));
        assert_eq!(toml.as_toml().expect("toml adapter").render(), b"value = 1");

        let other = Document::parse_json(
            b"{}".as_slice(),
            json::JsonProfile::StrictV1,
            document::ParseLimits::default(),
        )
        .expect("second JSON facade");
        assert_ne!(json.snapshot_identity(), other.snapshot_identity());
        assert!(json.diagnostics().is_empty());
    }

    #[test]
    fn facade_exposes_both_format_implementations() {
        let json = json::parse(
            b"{\"value\":1}".as_slice(),
            json::JsonProfile::StrictV1,
            document::ParseLimits::default(),
        )
        .expect("JSON through facade");
        let toml = toml::parse(
            b"value = 1".as_slice(),
            toml::TomlProfile::Toml10V1,
            document::ParseLimits::default(),
        )
        .expect("TOML through facade");
        assert_eq!(json.render(), b"{\"value\":1}");
        assert_eq!(toml.render(), b"value = 1");
    }

    #[test]
    fn facade_exposes_strict_dual_protocol_transports() {
        let completion =
            protocol::Completion::new(protocol::CompletionStatus::Success, 1, 1, None, None)
                .expect("valid completion");
        let message = protocol::ProtocolMessage::new(
            protocol::ContractId::new("core.completion", 1).expect("valid contract"),
            completion.to_value(),
            protocol::ContractRegistry::v1(),
        )
        .expect("validated payload");
        let limits = protocol::ProtocolLimits::default();
        assert_eq!(
            protocol::ProtocolMessage::from_json(
                &message.to_json(limits).expect("canonical JSON"),
                limits,
                protocol::ContractRegistry::v1(),
            )
            .expect("strict JSON decode"),
            message
        );
        assert_eq!(
            protocol::ProtocolMessage::from_pvce(
                &message.to_pvce(limits).expect("canonical PVCE"),
                limits,
                protocol::ContractRegistry::v1(),
            )
            .expect("strict PVCE decode"),
            message
        );
    }
}
