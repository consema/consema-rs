//! Consema 0.2 public facade for core protocols, JSON, TOML and PVCE.

pub use consema_core as core;
pub use consema_document as document;
pub use consema_json as json;
pub use consema_pvce as pvce;
pub use consema_toml as toml;

#[cfg(test)]
mod tests {
    use super::*;

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
}
