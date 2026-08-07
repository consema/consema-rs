//! Consema public facade for core semantics, protocol, INI, Java Properties,
//! JSON, TOML, YAML, XML, Property List, HCL, and PVCE.

mod conversion;

pub use conversion::{
    CompleteConversion, ConversionFailure, ConversionFidelity, ConversionProjectionProvenance,
    ConversionProjectionReport, ConversionReport, ConversionResult, convert_hcl, convert_ini,
    convert_json, convert_plist, convert_properties, convert_toml, convert_xml, convert_yaml,
};

pub use consema_core as core;
pub use consema_document as document;
pub use consema_graph as graph;
pub use consema_hcl as hcl;
pub use consema_ini as ini;
pub use consema_json as json;
pub use consema_plist as plist;
pub use consema_properties as properties;
pub use consema_protocol as protocol;
pub use consema_pvce as pvce;
pub use consema_toml as toml;
pub use consema_xml as xml;
pub use consema_yaml as yaml;

use std::sync::Arc;

/// Typed adapter failure on the common opaque facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatMismatch {
    /// The snapshot is not an INI document.
    Ini,
    /// The snapshot is not a Java Properties document.
    Properties,
    /// The snapshot is not a JSON document.
    Json,
    /// The snapshot is not a TOML document.
    Toml,
    /// The snapshot is not a YAML document.
    Yaml,
    /// The snapshot is not an XML document.
    Xml,
    /// The snapshot is not a Property List document.
    Plist,
    /// The snapshot is not an HCL document.
    Hcl,
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
    Hcl(Box<hcl::Document>),
    Ini(Box<ini::Document>),
    Json(json::Document),
    Plist(Box<plist::Document>),
    Properties(Box<properties::Document>),
    Toml(toml::Document),
    Xml(Box<xml::Document>),
    Yaml(Box<yaml::Document>),
}

impl Document {
    /// Parses one INI snapshot under an exact profile and explicit encoding selection.
    pub fn parse_ini(
        source: impl Into<Arc<[u8]>>,
        profile: ini::IniProfile,
        encoding: ini::IniEncodingSelection,
        limits: ini::IniParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Ini(Box::new(ini::parse(source, profile, encoding, limits)?)),
        })
    }

    /// Parses one Java Properties snapshot under an exact profile and source contract.
    pub fn parse_properties(
        source: impl Into<Arc<[u8]>>,
        profile: properties::PropertiesProfile,
        encoding: properties::PropertiesEncodingSelection,
        limits: properties::PropertiesParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Properties(Box::new(properties::parse(
                source, profile, encoding, limits,
            )?)),
        })
    }

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

    /// Parses one YAML stream under one exact frozen profile.
    pub fn parse_yaml(
        source: impl Into<Arc<[u8]>>,
        profile: yaml::YamlProfile,
        limits: document::ParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Yaml(Box::new(yaml::parse(source, profile, limits)?)),
        })
    }

    /// Parses one XML 1.0 safe snapshot under the exact profile and explicit
    /// encoding selection.
    pub fn parse_xml(
        source: impl Into<Arc<[u8]>>,
        profile: xml::XmlProfile,
        selection: xml::XmlEncodingSelection,
        limits: xml::XmlParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Xml(Box::new(xml::parse(source, profile, selection, limits)?)),
        })
    }

    /// Parses one Property List snapshot under an exact profile and explicit
    /// encoding selection.
    pub fn parse_plist(
        source: Arc<[u8]>,
        profile: plist::PlistProfile,
        selection: plist::PlistEncodingSelection,
        limits: plist::PlistParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Plist(Box::new(plist::parse(
                source, profile, selection, limits,
            )?)),
        })
    }

    /// Parses one HCL snapshot under the exact profile and explicit encoding
    /// selection.
    pub fn parse_hcl(
        source: Arc<[u8]>,
        profile: hcl::HclProfile,
        selection: hcl::HclEncodingSelection,
        limits: hcl::HclParseLimits,
    ) -> Result<Self, document::FatalFormationFailure> {
        Ok(Self {
            inner: DocumentInner::Hcl(Box::new(hcl::parse(source, profile, selection, limits)?)),
        })
    }

    /// Default rendering is byte-for-byte identical to the source.
    #[must_use]
    pub fn render(&self) -> &[u8] {
        match &self.inner {
            DocumentInner::Hcl(document) => document.render(),
            DocumentInner::Ini(document) => document.render(),
            DocumentInner::Json(document) => document.render(),
            DocumentInner::Plist(document) => document.render(),
            DocumentInner::Properties(document) => document.render(),
            DocumentInner::Toml(document) => document.render(),
            DocumentInner::Xml(document) => document.render(),
            DocumentInner::Yaml(document) => document.render(),
        }
    }

    /// Formation status of the underlying snapshot.
    #[must_use]
    pub fn formation_status(&self) -> document::FormationStatus {
        match &self.inner {
            DocumentInner::Hcl(document) => document.status(),
            DocumentInner::Ini(document) => document.formation_status(),
            DocumentInner::Json(document) => document.formation_status(),
            DocumentInner::Plist(document) => document.status(),
            DocumentInner::Properties(document) => document.formation_status(),
            DocumentInner::Toml(document) => document.formation_status(),
            DocumentInner::Xml(document) => document.status(),
            DocumentInner::Yaml(document) => document.formation_status(),
        }
    }

    /// Deterministically ordered document diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[core::Diagnostic] {
        match &self.inner {
            DocumentInner::Hcl(document) => document.diagnostics(),
            DocumentInner::Ini(document) => document.diagnostics(),
            DocumentInner::Json(document) => document.diagnostics(),
            DocumentInner::Plist(document) => document.diagnostics(),
            DocumentInner::Properties(document) => document.diagnostics(),
            DocumentInner::Toml(document) => document.diagnostics(),
            DocumentInner::Xml(document) => document.diagnostics(),
            DocumentInner::Yaml(document) => document.diagnostics(),
        }
    }

    /// Snapshot identity to which every handle and span belongs.
    #[must_use]
    pub fn snapshot_identity(&self) -> document::SnapshotIdentity {
        match &self.inner {
            DocumentInner::Hcl(document) => document.snapshot_identity(),
            DocumentInner::Ini(document) => document.snapshot_identity(),
            DocumentInner::Json(document) => document.snapshot_identity(),
            DocumentInner::Plist(document) => document.snapshot_identity(),
            DocumentInner::Properties(document) => document.snapshot_identity(),
            DocumentInner::Toml(document) => document.snapshot_identity(),
            DocumentInner::Xml(document) => document.snapshot_identity(),
            DocumentInner::Yaml(document) => document.snapshot_identity(),
        }
    }

    /// Exact source profile of the underlying format document.
    #[must_use]
    pub fn profile(&self) -> document::ProfileId {
        match &self.inner {
            DocumentInner::Hcl(document) => document.profile(),
            DocumentInner::Ini(document) => document.profile(),
            DocumentInner::Json(document) => document.profile(),
            DocumentInner::Plist(document) => document.profile(),
            DocumentInner::Properties(document) => document.profile(),
            DocumentInner::Toml(document) => document.profile(),
            DocumentInner::Xml(document) => document.profile(),
            DocumentInner::Yaml(document) => document.profile(),
        }
    }

    /// Typed JSON adapter; fails only when the snapshot is not JSON.
    pub fn as_json(&self) -> Result<&json::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Json(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Json),
        }
    }

    /// Typed TOML adapter; fails only when the snapshot is not TOML.
    pub fn as_toml(&self) -> Result<&toml::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Toml(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Toml),
        }
    }

    /// Typed YAML adapter; fails only when the snapshot is not YAML.
    pub fn as_yaml(&self) -> Result<&yaml::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Yaml(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_) => Err(FormatMismatch::Yaml),
        }
    }

    /// Typed INI adapter; fails only when the snapshot is not INI.
    pub fn as_ini(&self) -> Result<&ini::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Ini(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Ini),
        }
    }

    /// Typed Java Properties adapter; fails only when the snapshot is not Properties.
    pub fn as_properties(&self) -> Result<&properties::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Properties(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Properties),
        }
    }

    /// Typed XML adapter; fails only when the snapshot is not XML.
    pub fn as_xml(&self) -> Result<&xml::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Xml(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Xml),
        }
    }

    /// Typed Property List adapter; fails only when the snapshot is not a plist.
    pub fn as_plist(&self) -> Result<&plist::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Plist(document) => Ok(document),
            DocumentInner::Hcl(_)
            | DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Plist),
        }
    }

    /// Typed HCL adapter; fails only when the snapshot is not HCL.
    pub fn as_hcl(&self) -> Result<&hcl::Document, FormatMismatch> {
        match &self.inner {
            DocumentInner::Hcl(document) => Ok(document),
            DocumentInner::Ini(_)
            | DocumentInner::Json(_)
            | DocumentInner::Plist(_)
            | DocumentInner::Properties(_)
            | DocumentInner::Toml(_)
            | DocumentInner::Xml(_)
            | DocumentInner::Yaml(_) => Err(FormatMismatch::Hcl),
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
        assert!(matches!(json.as_ini(), Err(FormatMismatch::Ini)));
        assert!(matches!(
            json.as_properties(),
            Err(FormatMismatch::Properties)
        ));

        let toml = Document::parse_toml(
            b"value = 1".as_slice(),
            toml::TomlProfile::Toml10V1,
            document::ParseLimits::default(),
        )
        .expect("TOML facade");
        assert_eq!(toml.render(), b"value = 1");
        assert!(matches!(toml.as_json(), Err(FormatMismatch::Json)));
        assert!(matches!(toml.as_yaml(), Err(FormatMismatch::Yaml)));
        assert_eq!(toml.as_toml().expect("toml adapter").render(), b"value = 1");

        let yaml = Document::parse_yaml(
            b"value: 1\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            document::ParseLimits::default(),
        )
        .expect("YAML facade");
        assert_eq!(yaml.render(), b"value: 1\n");
        assert_eq!(
            yaml.as_yaml()
                .unwrap()
                .project_graph()
                .unwrap()
                .roots()
                .len(),
            1
        );
        assert!(matches!(yaml.as_json(), Err(FormatMismatch::Json)));
        assert!(matches!(yaml.as_toml(), Err(FormatMismatch::Toml)));
        assert_eq!(yaml.as_yaml().expect("yaml adapter").document_count(), 1);
        assert!(yaml.diagnostics().is_empty());

        let ini = Document::parse_ini(
            b"[section]\nvalue=1\n".as_slice(),
            ini::IniProfile::PortableV1,
            ini::IniEncodingSelection::ProfileDefault,
            ini::IniParseLimits::default(),
        )
        .expect("INI facade");
        assert_eq!(ini.render(), b"[section]\nvalue=1\n");
        assert_eq!(ini.profile().id(), "ini.portable");
        assert_eq!(ini.as_ini().unwrap().entries()[0].value(), "1");
        assert!(matches!(ini.as_json(), Err(FormatMismatch::Json)));

        let properties = Document::parse_properties(
            b"name=api\nport=8080\n".as_slice(),
            properties::PropertiesProfile::ReaderV1,
            properties::PropertiesEncodingSelection::Reader(document::SourceEncoding::Utf8),
            properties::PropertiesParseLimits::default(),
        )
        .expect("Properties facade");
        assert_eq!(properties.render(), b"name=api\nport=8080\n");
        assert_eq!(properties.profile().id(), "java-properties.reader");
        assert_eq!(
            properties.as_properties().unwrap().properties()[0]
                .value()
                .to_unicode()
                .unwrap(),
            "api"
        );
        assert!(matches!(properties.as_ini(), Err(FormatMismatch::Ini)));

        let xml = Document::parse_xml(
            b"<service><name>catalog</name></service>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .expect("XML facade");
        assert_eq!(xml.render(), b"<service><name>catalog</name></service>");
        assert_eq!(xml.formation_status(), document::FormationStatus::Complete);
        assert_eq!(xml.profile().id(), "xml.1.0-safe");
        assert_eq!(
            xml.as_xml().expect("xml adapter").render(),
            b"<service><name>catalog</name></service>"
        );
        assert!(matches!(xml.as_json(), Err(FormatMismatch::Json)));
        assert!(matches!(xml.as_plist(), Err(FormatMismatch::Plist)));
        assert!(matches!(xml.as_hcl(), Err(FormatMismatch::Hcl)));
        assert!(xml.diagnostics().is_empty());

        let plist = Document::parse_plist(
            Arc::from(b"<plist version=\"1.0\"><string>x</string></plist>".as_slice()),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .expect("plist facade");
        assert_eq!(
            plist.render(),
            b"<plist version=\"1.0\"><string>x</string></plist>"
        );
        assert_eq!(plist.profile().id(), "plist.xml");
        assert_eq!(
            plist.as_plist().expect("plist adapter").render(),
            b"<plist version=\"1.0\"><string>x</string></plist>"
        );
        assert!(matches!(plist.as_xml(), Err(FormatMismatch::Xml)));
        assert!(matches!(plist.as_hcl(), Err(FormatMismatch::Hcl)));

        let hcl = Document::parse_hcl(
            Arc::from(b"a = 1\n".as_slice()),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .expect("HCL facade");
        assert_eq!(hcl.render(), b"a = 1\n");
        assert_eq!(hcl.profile().id(), "hcl.native");
        assert_eq!(hcl.as_hcl().expect("hcl adapter").render(), b"a = 1\n");
        assert!(matches!(hcl.as_xml(), Err(FormatMismatch::Xml)));
        assert!(matches!(hcl.as_plist(), Err(FormatMismatch::Plist)));
        assert!(hcl.diagnostics().is_empty());

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
    fn facade_exposes_all_format_implementations() {
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
        let yaml = yaml::parse(
            b"value: 1\n".as_slice(),
            yaml::YamlProfile::Yaml12CoreV1,
            document::ParseLimits::default(),
        )
        .expect("YAML through facade");
        let ini = ini::parse(
            b"[section]\nvalue=1\n".as_slice(),
            ini::IniProfile::PortableV1,
            ini::IniEncodingSelection::ProfileDefault,
            ini::IniParseLimits::default(),
        )
        .expect("INI through facade");
        let properties = properties::parse_reader(
            b"value=1\n".as_slice(),
            document::SourceEncoding::Utf8,
            properties::PropertiesParseLimits::default(),
        )
        .expect("Properties through facade");
        let xml = xml::parse(
            b"<service><name>catalog</name></service>".as_slice(),
            xml::XmlProfile::SafeV1,
            xml::XmlEncodingSelection::ProfileDefault,
            xml::XmlParseLimits::default(),
        )
        .expect("XML through facade");
        let plist = plist::parse(
            Arc::from(b"<plist version=\"1.0\"><string>x</string></plist>".as_slice()),
            plist::PlistProfile::XmlV1,
            plist::PlistEncodingSelection::ProfileDefault,
            plist::PlistParseLimits::default(),
        )
        .expect("plist through facade");
        let hcl = hcl::parse(
            Arc::<[u8]>::from(b"a = 1\n".as_slice()),
            hcl::HclProfile::NativeV1,
            hcl::HclEncodingSelection::ProfileDefault,
            hcl::HclParseLimits::default(),
        )
        .expect("HCL through facade");
        assert_eq!(json.render(), b"{\"value\":1}");
        assert_eq!(toml.render(), b"value = 1");
        assert_eq!(yaml.render(), b"value: 1\n");
        assert_eq!(ini.render(), b"[section]\nvalue=1\n");
        assert_eq!(properties.render(), b"value=1\n");
        assert_eq!(xml.render(), b"<service><name>catalog</name></service>");
        assert_eq!(
            plist.render(),
            b"<plist version=\"1.0\"><string>x</string></plist>"
        );
        assert_eq!(hcl.render(), b"a = 1\n");
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
