//! CLI-side thin enumeration over the facade registry (implementation plan
//! §3.1; RFC 0015 §6.2).
//!
//! Every format fact of the CLI derives from the facade public API — nothing
//! is redeclared here (plan §11 item 3): the profile inventory, the query
//! domains, and the per-profile operation registries come from
//! [`consema::registry`], the facade's unified format-surface enumeration
//! (plan §1.2 "facade public API 按需小增"). This module adapts that
//! enumeration into the deterministic shapes the CLI commands consume and
//! exposes the v7 contract/error-code registries the explain command reads.
//! The drift guard is the facade's own test suite (family ids asserted
//! against parsed backend documents) plus the registry-completeness tests in
//! this crate's `tests/cli_m4.rs`.

use consema::core::{BigInteger, ObjectBuilder, PortableValue};
use consema::document::ProfileId;
use consema::protocol::{ContractDescriptor, ContractRegistry, ErrorCodeRegistry};

/// One profile of the facade inventory with its owning format family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileEntry {
    /// Format family namespace of the profile.
    pub family_id: String,
    /// Format family version.
    pub family_version: u32,
    /// The profile itself.
    pub profile: ProfileId,
}

/// The full facade profile inventory, sorted by profile id (RFC 0015 §6.2
/// `profiles`).
#[must_use]
pub fn profile_entries() -> Vec<ProfileEntry> {
    consema::registry::profiles()
        .into_iter()
        .map(|entry| ProfileEntry {
            family_id: entry.family().id().to_owned(),
            family_version: entry.family().version(),
            profile: entry.profile().clone(),
        })
        .collect()
}

/// Resolves one bare profile id (`"ini.portable"`) from the facade inventory.
#[must_use]
pub fn profile_by_id(id: &str) -> Option<ProfileEntry> {
    profile_entries()
        .into_iter()
        .find(|entry| entry.profile.id() == id)
}

/// Parses one `"namespace.id@N"` reference into its (id, version) parts.
///
/// A malformed reference (no `@`, a zero version, a non-numeric version)
/// yields `None`; the callers treat that as a lookup failure.
#[must_use]
pub fn parse_versioned_id(text: &str) -> Option<(String, u32)> {
    let (id, version) = text.rsplit_once('@')?;
    let version = version.parse::<u32>().ok()?;
    if version == 0 || id.is_empty() {
        return None;
    }
    Some((id.to_owned(), version))
}

/// One `{id, version}` reference value (the `profile` shape of
/// `cli.inspect@1` candidates and `cli.explain@1`).
#[must_use]
pub fn reference_value(id: &str, version: u32) -> PortableValue {
    let mut object = ObjectBuilder::new();
    object
        .insert("id", PortableValue::string(id))
        .expect("unique keys");
    object
        .insert(
            "version",
            PortableValue::integer(BigInteger::from(i64::from(version))),
        )
        .expect("unique keys");
    object.build()
}

/// Every `ErrorCodeRegistry::v7()` code as a string; the registry itself is
/// strictly sorted, so the returned order is deterministic (RFC 0015 §6.2
/// `error_codes`).
#[must_use]
pub fn error_codes() -> Vec<&'static str> {
    ErrorCodeRegistry::v7()
        .codes()
        .iter()
        .map(|descriptor| descriptor.code)
        .collect()
}

/// The v7 contract descriptors in registry order (strictly sorted by
/// contract id; RFC 0015 §13.2).
#[must_use]
pub fn contracts() -> &'static [ContractDescriptor] {
    ContractRegistry::v7().contracts()
}

/// One deterministic non-negative integer value (read sizes are capped by
/// the CLI byte budget, so the `i64` conversion cannot fail in practice).
#[must_use]
pub fn u64_integer(value: u64) -> PortableValue {
    PortableValue::integer(BigInteger::from(
        i64::try_from(value).expect("CLI counts are capped by the CLI budgets"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_enumerates_all_sixteen_profiles_with_families() {
        let entries = profile_entries();
        assert_eq!(entries.len(), 16, "sixteen profiles");
        for pair in entries.windows(2) {
            assert!(
                pair[0].profile.id() < pair[1].profile.id(),
                "profiles sorted by id"
            );
        }
        let expected_families: Vec<&str> = vec![
            "hcl",
            "hcl",
            "ini",
            "ini",
            "ini",
            "java-properties",
            "java-properties",
            "json",
            "json",
            "json",
            "plist",
            "plist",
            "toml",
            "xml",
            "yaml",
            "yaml",
        ];
        let observed: Vec<&str> = entries
            .iter()
            .map(|entry| entry.family_id.as_str())
            .collect();
        assert_eq!(observed, expected_families, "family per sorted profile");
        for entry in &entries {
            assert_eq!(entry.family_version, 1);
            assert_eq!(entry.profile.version(), 1);
            assert!(
                consema::registry::operation_registry(&entry.profile).is_some(),
                "{} publishes an operation registry",
                entry.profile.id()
            );
        }
    }

    #[test]
    fn profile_by_id_resolves_only_facade_profiles() {
        assert_eq!(
            profile_by_id("ini.portable")
                .expect("registered")
                .profile
                .id(),
            "ini.portable"
        );
        assert_eq!(
            profile_by_id("jsonc.bounded")
                .expect("registered")
                .profile
                .id(),
            "jsonc.bounded"
        );
        assert!(profile_by_id("ini.unknown").is_none());
        assert!(profile_by_id("").is_none());
    }

    #[test]
    fn versioned_id_parsing_is_strict() {
        assert_eq!(
            parse_versioned_id("core.cli-output@1"),
            Some(("core.cli-output".to_owned(), 1))
        );
        assert_eq!(
            parse_versioned_id("ini.portable@1"),
            Some(("ini.portable".to_owned(), 1))
        );
        assert_eq!(parse_versioned_id("core.cli-output"), None);
        assert_eq!(parse_versioned_id("core.cli-output@0"), None);
        assert_eq!(parse_versioned_id("@1"), None);
        assert_eq!(parse_versioned_id("x@y"), None);
        assert_eq!(parse_versioned_id("x@1@2"), Some(("x@1".to_owned(), 2)));
    }

    #[test]
    fn v7_registries_expose_contracts_and_sorted_error_codes() {
        assert!(!contracts().is_empty());
        assert!(contracts().iter().any(|c| c.id == "core.cli-output"));
        let codes = error_codes();
        assert_eq!(codes.len(), 186, "v7 error-code count (RFC 0015 §13.2)");
        for pair in codes.windows(2) {
            assert!(pair[0] < pair[1], "error codes strictly sorted");
        }
        assert!(codes.contains(&"cli.data.io@1"));
        assert!(codes.contains(&"cli.detection.ambiguous@1"));
    }
}
