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

/// Additive facade registry: the unified format-surface enumeration and the
/// single parse entry by profile id.
///
/// Milestone M4 of the 0.12.0 CLI plan adds this module as the documented
/// facade thin layer (implementation plan §1.2 "facade public API 按需小增"):
/// the CLI's registry/capabilities/explain/inspect commands must derive every
/// format fact from the facade public API (RFC 0015 hard gate 1; plan §3.1
/// "registry 是 facade 既有类型的薄枚举，不是新 registry"), and the facade
/// previously published no unified enumeration of families, profiles, or
/// query domains — the family ids exist only as `format_family()` facts on
/// parsed backend documents. This module is strictly additive: no existing
/// API is rewritten. The drift guard is the `tests` module below: every
/// enumerated family id is asserted against the `format_family()` of a parsed
/// backend document, so a backend family change fails this crate's own tests.
pub mod registry {
    use crate::core::QueryDomain;
    use crate::document::{
        FatalFormationFailure, FormatFamilyId, FormatOperationRegistry, ProfileId,
    };
    use crate::{Document, hcl, ini, json, plist, properties, toml, xml, yaml};
    use std::sync::Arc;

    /// One profile together with the format family that publishes it.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct FormatProfile {
        family: FormatFamilyId,
        profile: ProfileId,
    }

    impl FormatProfile {
        /// Format family of the profile.
        #[must_use]
        pub const fn family(&self) -> &FormatFamilyId {
            &self.family
        }

        /// The profile itself.
        #[must_use]
        pub const fn profile(&self) -> &ProfileId {
            &self.profile
        }
    }

    /// The eight format families (RFC 0015 §6.2 `families`), sorted by id.
    #[must_use]
    pub fn format_families() -> Vec<FormatFamilyId> {
        let mut families = vec![
            FormatFamilyId::new("hcl", 1),
            FormatFamilyId::new("ini", 1),
            FormatFamilyId::new("java-properties", 1),
            FormatFamilyId::new("json", 1),
            FormatFamilyId::new("plist", 1),
            FormatFamilyId::new("toml", 1),
            FormatFamilyId::new("xml", 1),
            FormatFamilyId::new("yaml", 1),
        ];
        families.sort_by(|left, right| left.id().cmp(right.id()));
        families
    }

    /// All sixteen profiles with their owning family (RFC 0015 §6.2
    /// `profiles`), sorted by profile id.
    #[must_use]
    pub fn profiles() -> Vec<FormatProfile> {
        let mut profiles = vec![
            family_profile("hcl", hcl::HclProfile::NativeV1.id()),
            family_profile("hcl", hcl::HclProfile::TfvarsV1.id()),
            family_profile("ini", ini::IniProfile::PortableV1.id()),
            family_profile("ini", ini::IniProfile::WindowsV1.id()),
            family_profile("ini", ini::IniProfile::PythonConfigParserV1.id()),
            family_profile(
                "java-properties",
                properties::PropertiesProfile::ReaderV1.id(),
            ),
            family_profile(
                "java-properties",
                properties::PropertiesProfile::Latin1V1.id(),
            ),
            family_profile("json", json::JsonProfile::StrictV1.id()),
            family_profile("json", json::JsonProfile::JsoncBoundedV1.id()),
            family_profile("json", json::JsonProfile::Json5StandardV1.id()),
            family_profile("plist", plist::PlistProfile::XmlV1.id()),
            family_profile("plist", plist::PlistProfile::BinaryV1.id()),
            family_profile("toml", toml::TomlProfile::Toml10V1.id()),
            family_profile("xml", xml::XmlProfile::SafeV1.id()),
            family_profile("yaml", yaml::YamlProfile::Yaml12CoreV1.id()),
            family_profile("yaml", yaml::YamlProfile::Yaml11CompatV1.id()),
        ];
        profiles.sort_by(|left, right| {
            left.profile
                .id()
                .cmp(right.profile.id())
                .then(left.profile.version().cmp(&right.profile.version()))
        });
        profiles
    }

    /// The query-domain constructor inventory (RFC 0015 §6.2
    /// `query_domains`), sorted by (id, version).
    #[must_use]
    pub fn query_domains() -> Vec<QueryDomain> {
        let mut domains = vec![
            QueryDomain::portable_value_v1(),
            QueryDomain::portable_graph_v1(),
            QueryDomain::json_native_v1(),
            QueryDomain::json_native_v2(),
            QueryDomain::toml_native_v1(),
            QueryDomain::yaml_native_v1(),
            QueryDomain::ini_native_v1(),
            QueryDomain::java_properties_native_v1(),
            QueryDomain::xml_native_v1(),
            QueryDomain::json_lossless_syntax_v1(),
            QueryDomain::json_lossless_syntax_v2(),
            QueryDomain::toml_lossless_syntax_v1(),
            QueryDomain::yaml_lossless_syntax_v1(),
            QueryDomain::ini_lossless_syntax_v1(),
            QueryDomain::java_properties_lossless_syntax_v1(),
            QueryDomain::xml_lossless_syntax_v1(),
            QueryDomain::plist_native_v1(),
            QueryDomain::plist_lossless_syntax_v1(),
            QueryDomain::plist_binary_structure_v1(),
            QueryDomain::hcl_native_v1(),
            QueryDomain::hcl_lossless_syntax_v1(),
        ];
        domains.sort_by(|left, right| {
            left.id()
                .cmp(right.id())
                .then(left.version().cmp(&right.version()))
        });
        domains
    }

    /// The per-profile operation registry of one exact profile (RFC 0015
    /// §6.2 `operations`); `None` for ids outside the facade surface.
    #[must_use]
    pub fn operation_registry(profile: &ProfileId) -> Option<FormatOperationRegistry> {
        let registry = match profile.id() {
            "hcl.native" => hcl::format_operation_registry(hcl::HclProfile::NativeV1),
            "hcl.tfvars" => hcl::format_operation_registry(hcl::HclProfile::TfvarsV1),
            "ini.portable" => ini::format_operation_registry(ini::IniProfile::PortableV1),
            "ini.windows" => ini::format_operation_registry(ini::IniProfile::WindowsV1),
            "ini.python-configparser" => {
                ini::format_operation_registry(ini::IniProfile::PythonConfigParserV1)
            }
            "java-properties.reader" => {
                properties::format_operation_registry(properties::PropertiesProfile::ReaderV1)
            }
            "java-properties.latin1" => {
                properties::format_operation_registry(properties::PropertiesProfile::Latin1V1)
            }
            "json.strict" => json::format_operation_registry(json::JsonProfile::StrictV1),
            "jsonc.bounded" => json::format_operation_registry(json::JsonProfile::JsoncBoundedV1),
            "json5.standard" => json::format_operation_registry(json::JsonProfile::Json5StandardV1),
            "plist.xml" => plist::format_operation_registry(plist::PlistProfile::XmlV1),
            "plist.binary" => plist::format_operation_registry(plist::PlistProfile::BinaryV1),
            "toml.1.0" => toml::format_operation_registry(toml::TomlProfile::Toml10V1),
            "xml.1.0-safe" => xml::format_operation_registry(xml::XmlProfile::SafeV1),
            "yaml.1.2-core" => yaml::format_operation_registry(yaml::YamlProfile::Yaml12CoreV1),
            "yaml.1.1-compat" => yaml::format_operation_registry(yaml::YamlProfile::Yaml11CompatV1),
            _ => return None,
        };
        Some(registry)
    }

    /// Parses one snapshot under an exact profile id through the single
    /// facade parse entry (inspect's `--profile` parse facts, RFC 0015 §7.1
    /// `cli.parse-facts@1`; plan §11 "每命令是参数 → facade 调用 → 渲染").
    ///
    /// The per-format encoding selection and limits use the frozen profile
    /// defaults (`ProfileDefault`; the properties reader profile uses an
    /// explicit UTF-8 selection because its contract has no profile default).
    /// An unknown profile id returns the same failure the typed adapters do:
    /// resolve ids against [`profiles`] first.
    pub fn parse_document(
        source: Arc<[u8]>,
        profile: &ProfileId,
    ) -> Result<Document, FatalFormationFailure> {
        match profile.id() {
            "ini.portable" => Document::parse_ini(
                source,
                ini::IniProfile::PortableV1,
                ini::IniEncodingSelection::ProfileDefault,
                ini::IniParseLimits::default(),
            ),
            "ini.windows" => Document::parse_ini(
                source,
                ini::IniProfile::WindowsV1,
                ini::IniEncodingSelection::ProfileDefault,
                ini::IniParseLimits::default(),
            ),
            "ini.python-configparser" => Document::parse_ini(
                source,
                ini::IniProfile::PythonConfigParserV1,
                ini::IniEncodingSelection::ProfileDefault,
                ini::IniParseLimits::default(),
            ),
            "java-properties.reader" => Document::parse_properties(
                source,
                properties::PropertiesProfile::ReaderV1,
                properties::PropertiesEncodingSelection::Reader(
                    crate::document::SourceEncoding::Utf8,
                ),
                properties::PropertiesParseLimits::default(),
            ),
            "java-properties.latin1" => Document::parse_properties(
                source,
                properties::PropertiesProfile::Latin1V1,
                properties::PropertiesEncodingSelection::Latin1,
                properties::PropertiesParseLimits::default(),
            ),
            "json.strict" => Document::parse_json(
                source,
                json::JsonProfile::StrictV1,
                crate::document::ParseLimits::default(),
            ),
            "jsonc.bounded" => Document::parse_json(
                source,
                json::JsonProfile::JsoncBoundedV1,
                crate::document::ParseLimits::default(),
            ),
            "json5.standard" => Document::parse_json(
                source,
                json::JsonProfile::Json5StandardV1,
                crate::document::ParseLimits::default(),
            ),
            "toml.1.0" => Document::parse_toml(
                source,
                toml::TomlProfile::Toml10V1,
                crate::document::ParseLimits::default(),
            ),
            "yaml.1.2-core" => Document::parse_yaml(
                source,
                yaml::YamlProfile::Yaml12CoreV1,
                crate::document::ParseLimits::default(),
            ),
            "yaml.1.1-compat" => Document::parse_yaml(
                source,
                yaml::YamlProfile::Yaml11CompatV1,
                crate::document::ParseLimits::default(),
            ),
            "xml.1.0-safe" => Document::parse_xml(
                source,
                xml::XmlProfile::SafeV1,
                xml::XmlEncodingSelection::ProfileDefault,
                xml::XmlParseLimits::default(),
            ),
            "plist.xml" => Document::parse_plist(
                source,
                plist::PlistProfile::XmlV1,
                plist::PlistEncodingSelection::ProfileDefault,
                plist::PlistParseLimits::default(),
            ),
            "plist.binary" => Document::parse_plist(
                source,
                plist::PlistProfile::BinaryV1,
                plist::PlistEncodingSelection::ProfileDefault,
                plist::PlistParseLimits::default(),
            ),
            "hcl.native" => Document::parse_hcl(
                source,
                hcl::HclProfile::NativeV1,
                hcl::HclEncodingSelection::ProfileDefault,
                hcl::HclParseLimits::default(),
            ),
            "hcl.tfvars" => Document::parse_hcl(
                source,
                hcl::HclProfile::TfvarsV1,
                hcl::HclEncodingSelection::ProfileDefault,
                hcl::HclParseLimits::default(),
            ),
            _ => Err(FatalFormationFailure::from_diagnostic(
                crate::core::Diagnostic::new(
                    "core.source.encoding-conflict@1",
                    crate::core::DiagnosticCategory::Encoding,
                    crate::core::DiagnosticSeverity::Error,
                    None,
                    0,
                ),
            )),
        }
    }

    fn family_profile(family_id: &str, profile: ProfileId) -> FormatProfile {
        FormatProfile {
            family: FormatFamilyId::new(family_id, 1),
            profile,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn registry_lists_eight_families_and_sixteen_profiles() {
            let families = format_families();
            assert_eq!(families.len(), 8, "eight format families");
            for pair in families.windows(2) {
                assert!(pair[0].id() < pair[1].id(), "families sorted by id");
            }
            let profiles = profiles();
            assert_eq!(profiles.len(), 16, "sixteen profiles across the families");
            for pair in profiles.windows(2) {
                assert!(
                    pair[0].profile().id() < pair[1].profile().id(),
                    "profiles sorted by id"
                );
            }
            let expected: Vec<&str> = vec![
                "hcl.native",
                "hcl.tfvars",
                "ini.portable",
                "ini.python-configparser",
                "ini.windows",
                "java-properties.latin1",
                "java-properties.reader",
                "json.strict",
                "json5.standard",
                "jsonc.bounded",
                "plist.binary",
                "plist.xml",
                "toml.1.0",
                "xml.1.0-safe",
                "yaml.1.1-compat",
                "yaml.1.2-core",
            ];
            let actual: Vec<&str> = profiles.iter().map(|entry| entry.profile().id()).collect();
            assert_eq!(actual, expected, "profile inventory");
            // Every profile id maps to a per-profile operation registry.
            for entry in &profiles {
                assert!(
                    operation_registry(entry.profile()).is_some(),
                    "{} must resolve an operation registry",
                    entry.profile().id()
                );
            }
        }

        #[test]
        fn registry_query_domains_are_sorted_and_unique() {
            let domains = query_domains();
            assert_eq!(domains.len(), 21, "query-domain constructor inventory");
            for pair in domains.windows(2) {
                assert!(
                    (pair[0].id(), pair[0].version()) < (pair[1].id(), pair[1].version()),
                    "domains sorted by (id, version)"
                );
            }
            assert!(
                domains
                    .iter()
                    .any(|d| d.id() == "core.portable-value-query")
            );
            assert!(
                domains
                    .iter()
                    .any(|d| d.id() == "hcl.native-semantic-query")
            );
            assert!(
                domains
                    .iter()
                    .any(|d| d.id() == "plist.binary-structure-query")
            );
        }

        #[test]
        fn registry_parse_document_round_trips_every_profile() {
            // Every profile parses its own minimal canonical document and
            // reports the exact profile id back.
            let cases: &[(&str, &[u8])] = &[
                ("ini.portable", b"[section]\nvalue=1\n"),
                ("ini.windows", b"[section]\nvalue=1\r\n"),
                ("ini.python-configparser", b"[section]\nvalue=1\n"),
                ("java-properties.reader", b"name=api\n"),
                ("java-properties.latin1", b"name=api\n"),
                ("json.strict", b"{\"a\":1}"),
                ("jsonc.bounded", b"{\"a\":1,}"),
                ("json5.standard", b"{a:1,}"),
                ("toml.1.0", b"value = 1\n"),
                ("yaml.1.2-core", b"value: 1\n"),
                ("yaml.1.1-compat", b"value: 1\n"),
                ("xml.1.0-safe", b"<service><name>catalog</name></service>"),
                (
                    "plist.xml",
                    b"<plist version=\"1.0\"><string>x</string></plist>",
                ),
                // Minimal hand-built binary plist: header, one ASCII string
                // object ("x"), a one-byte offset table, and the 32-byte
                // trailer (RFC 0013 §5). The offset table starts at byte 10.
                (
                    "plist.binary",
                    b"bplist00\x5f\x78\x08\
                      \x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\
                      \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a",
                ),
                ("hcl.native", b"a = 1\n"),
                ("hcl.tfvars", b"a = 1\n"),
            ];
            for (id, bytes) in cases {
                let profile = ProfileId::new(*id, 1);
                let document = parse_document(Arc::from(bytes.to_vec()), &profile)
                    .unwrap_or_else(|error| panic!("{id} must parse: {error:?}"));
                assert_eq!(document.profile().id(), *id, "{id} profile round trip");
            }
            // Unknown profile ids fail like the typed adapters.
            let unknown = ProfileId::new("example.unknown", 1);
            assert!(
                parse_document(Arc::from(b"x".to_vec()), &unknown).is_err(),
                "unknown profile id fails"
            );
        }

        #[test]
        fn registry_family_ids_match_parsed_backend_documents() {
            // Drift guard (R-8): the enumerated family ids must equal the
            // `format_family()` facts of the backend documents themselves.
            let cases: &[(&str, &str, &[u8])] = &[
                ("hcl", "hcl.native", b"a = 1\n"),
                ("ini", "ini.portable", b"value=1\n"),
                ("java-properties", "java-properties.reader", b"name=api\n"),
                ("json", "json.strict", b"{}"),
                (
                    "plist",
                    "plist.xml",
                    b"<plist version=\"1.0\"><string>x</string></plist>",
                ),
                ("toml", "toml.1.0", b"value = 1\n"),
                ("xml", "xml.1.0-safe", b"<a/>"),
                ("yaml", "yaml.1.2-core", b"value: 1\n"),
            ];
            for (family_id, profile_id, bytes) in cases {
                let profile = ProfileId::new(*profile_id, 1);
                let document = parse_document(Arc::from(bytes.to_vec()), &profile)
                    .unwrap_or_else(|error| panic!("{family_id} sample must parse: {error:?}"));
                // The facade exposes the family through each typed adapter.
                let observed = if let Ok(ini) = document.as_ini() {
                    ini.format_family()
                } else if let Ok(properties) = document.as_properties() {
                    properties.format_family()
                } else if let Ok(json) = document.as_json() {
                    json.format_family()
                } else if let Ok(toml) = document.as_toml() {
                    toml.format_family()
                } else if let Ok(yaml) = document.as_yaml() {
                    yaml.format_family()
                } else if let Ok(xml) = document.as_xml() {
                    xml.format_family()
                } else if let Ok(plist) = document.as_plist() {
                    plist.format_family()
                } else {
                    document.as_hcl().expect("hcl adapter").format_family()
                };
                assert_eq!(
                    observed.id(),
                    *family_id,
                    "family id {family_id} must match the backend format_family()"
                );
                assert_eq!(observed.version(), 1);
            }
        }
    }
}

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
