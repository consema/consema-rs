//! Consema 0.3 public facade for core semantics, protocol, JSON, TOML and PVCE.

pub use consema_core as core;
pub use consema_document as document;
pub use consema_json as json;
pub use consema_protocol as protocol;
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
