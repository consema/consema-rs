//! Secret detection and presentation redaction (RFC 0015 §11; implementation
//! plan §4.4).
//!
//! Redaction is **presentation-only** (RFC 0015 §11.1; hard gate 3): it
//! affects stderr diagnostics, human output, and the stdout envelope
//! presentation, and it **never removes the byte preconditions required to
//! apply a SourcePatch**. That boundary is enforced by construction: every
//! entry point of this module takes a presentation value ([`PortableValue`]
//! tree or key/value strings) and never accepts a patch, a snapshot, or raw
//! file bytes. The patch-precondition regression test in this module proves
//! that a `SourcePatch` whose presentation embedding is redacted still
//! applies byte-for-byte identically.
//!
//! Detection is the frozen v1 key-name pattern set of RFC 0015 §11.2 —
//! `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|auth)`
//! — matched case-insensitively, whole or as a substring of key names, plus
//! explicit `--redact-keys` globs. Value-shape inference is off and v1
//! provides no switch to enable it (RFC 0015 §17: rejected for
//! determinism); the false-positive direction is "redact more rather than
//! miss a secret". A value that merely looks like a key name (e.g. the
//! string `"password"` under the key `"name"`) is never redacted.
//!
//! A hit value is replaced by the string [`PLACEHOLDER`] (`$REDACTED$`); a
//! value that is literally `$REDACTED$` is indistinguishable — the accepted
//! v1 presentation-layer limitation of RFC 0015 §11.3, resolved only by
//! `--show-secrets`. [`RedactPolicy::show_secrets`] is the sole opt-out and
//! disables matching entirely (RFC 0015 §11.4).
//!
//! Case folding: the frozen patterns are pure ASCII and the matching
//! lowercases both sides with the Unicode lowercase mapping, which is
//! deterministic across platforms and equivalent to the `(?i)` flag for
//! ordinary key names. The exotic folds of regex simple case folding
//! (long s, Kelvin sign) are not applied; key names in configuration files
//! are ASCII in practice and the difference only ever reduces the hit set
//! on deliberately exotic spellings.

use consema::core::{EntryMappingBuilder, ObjectBuilder, PortableValue, SequenceBuilder};
use consema::protocol::Redaction;

/// The frozen presentation placeholder of RFC 0015 §11.3.
pub const PLACEHOLDER: &str = "$REDACTED$";

/// The frozen v1 key-name pattern set of RFC 0015 §11.2.
///
/// The RFC pattern is
/// `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|auth)`;
/// this array lists the exact expanded needle set (the `[_-]?` alternation
/// is expanded into its three literal forms). Matching is case-insensitive
/// substring containment against key names.
pub const FROZEN_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "privatekey",
    "private_key",
    "private-key",
    "accesskey",
    "access_key",
    "access-key",
    "credential",
    "auth",
];

/// One compiled `--redact-keys` glob (RFC 0015 §11.2).
///
/// Grammar: `*` matches any run (including the empty run), `?` matches
/// exactly one character, every other character matches itself. Matching is
/// case-insensitive like the frozen patterns. `[` and `]` are rejected as
/// reserved-but-unimplemented syntax (a bracket class would silently match
/// nothing as a literal, so v1 refuses it instead).
#[derive(Clone, Debug, Eq, PartialEq)]
struct Glob {
    /// The validated glob text (empty or bracket characters rejected).
    text: String,
}

impl Glob {
    fn compile(text: &str) -> Result<Self, RedactPatternError> {
        if text.is_empty() {
            return Err(RedactPatternError::Empty);
        }
        if text.contains(['[', ']']) {
            return Err(RedactPatternError::ReservedSyntax(text.to_owned()));
        }
        Ok(Self {
            text: text.to_owned(),
        })
    }

    /// Matches one whole lowercased key name against this glob.
    fn matches(&self, lowered_key: &str) -> bool {
        let pattern: Vec<char> = self.text.to_lowercase().chars().collect();
        let text: Vec<char> = lowered_key.chars().collect();
        // Classic glob DP: `matched[i][j]` is whether pattern[..i] matches
        // text[..j]; `*` is lazy (skip the star, or consume one text char),
        // `?` consumes exactly one char, literals must equal.
        let mut matched = vec![vec![false; text.len() + 1]; pattern.len() + 1];
        matched[0][0] = true;
        for (i, pattern_char) in pattern.iter().enumerate() {
            if *pattern_char == '*' {
                matched[i + 1][0] = matched[i][0];
            }
            for j in 0..=text.len() {
                if !matched[i][j] {
                    continue;
                }
                match pattern_char {
                    '*' => {
                        matched[i + 1][j] = true;
                        if j < text.len() {
                            matched[i][j + 1] = true;
                        }
                    }
                    '?' => {
                        if j < text.len() {
                            matched[i + 1][j + 1] = true;
                        }
                    }
                    literal => {
                        if j < text.len() && text[j] == *literal {
                            matched[i + 1][j + 1] = true;
                        }
                    }
                }
            }
        }
        matched[pattern.len()][text.len()]
    }
}

/// One frozen usage-class failure: an invalid `--redact-keys` pattern
/// (RFC 0015 §11.2, code `cli.usage.redaction-pattern@1`, exit 1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedactPatternError {
    /// The pattern is the empty string.
    Empty,
    /// The pattern uses `[`/`]` bracket-class syntax, which v1 does not
    /// implement; the pattern is rejected rather than silently treated as
    /// literals.
    ReservedSyntax(String),
}

impl RedactPatternError {
    /// The frozen `cli.usage.*` code of the failure (RFC 0015 §13.1).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Empty | Self::ReservedSyntax(_) => "cli.usage.redaction-pattern@1",
        }
    }

    /// Deterministic human diagnostic for stderr.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Empty => "--redact-keys pattern must not be empty".to_owned(),
            Self::ReservedSyntax(pattern) => format!(
                "--redact-keys pattern '{pattern}' uses '[' or ']' bracket syntax, \
                 which is not supported by v1 redaction globs"
            ),
        }
    }
}

/// One compiled redaction policy: the frozen patterns plus explicit
/// `--redact-keys` globs, and the `--show-secrets` sole opt-out.
///
/// The policy is immutable once compiled and cheap to clone; commands build
/// it once from their parsed arguments and share it across every rendering
/// path, so human output and machine output redact identically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactPolicy {
    show_secrets: bool,
    extra: Vec<Glob>,
}

impl RedactPolicy {
    /// The conservative default: redaction on, frozen v1 patterns only
    /// (RFC 0015 §11.2; the false-positive direction is "redact more").
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            show_secrets: false,
            extra: Vec::new(),
        }
    }

    /// The `--show-secrets` policy: the sole presentation opt-out
    /// (RFC 0015 §11.4). Matching is disabled entirely, so no value is ever
    /// replaced and the redaction facts are always zero.
    #[must_use]
    pub fn show_secrets() -> Self {
        Self {
            show_secrets: true,
            extra: Vec::new(),
        }
    }

    /// Appends explicit `--redact-keys` glob patterns.
    ///
    /// An invalid pattern (empty, or containing `[`/`]`) is a usage-class
    /// failure with the frozen `cli.usage.redaction-pattern@1` code; the
    /// whole call fails and the policy is left untouched.
    pub fn with_extra_patterns(
        mut self,
        patterns: &[impl AsRef<str>],
    ) -> Result<Self, RedactPatternError> {
        for pattern in patterns {
            self.extra.push(Glob::compile(pattern.as_ref())?);
        }
        Ok(self)
    }

    /// Whether `--show-secrets` disables redaction for this policy.
    #[must_use]
    pub const fn secrets_visible(&self) -> bool {
        self.show_secrets
    }
}

/// Pure key-name matcher over the frozen v1 pattern set plus the explicit
/// globs (RFC 0015 §11.2: matched case-insensitively, whole or as a
/// substring of key names).
///
/// This is the single truth for every redaction decision in the bin —
/// machine values, human renderings, and the per-file `redacted` fact of
/// batch results (RFC 0015 §9.2) all call it.
#[must_use]
pub fn key_matches(policy: &RedactPolicy, key: &str) -> bool {
    if policy.show_secrets {
        return false;
    }
    let lowered = key.to_lowercase();
    FROZEN_PATTERNS
        .iter()
        .any(|needle| lowered.contains(needle))
        || policy.extra.iter().any(|glob| glob.matches(&lowered))
}

/// The presentation text of one redacted key/value pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedText {
    /// The presentation text: [`PLACEHOLDER`] when the value was replaced,
    /// otherwise the original value verbatim.
    text: String,
    /// Whether the value was replaced by the placeholder.
    redacted: bool,
}

impl RedactedText {
    /// The presentation text (the `$REDACTED$` placeholder when redacted).
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the value was replaced by the placeholder.
    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.redacted
    }
}

/// Redacts one string value for human presentation when its key matches.
///
/// Human renderers call this for every `key = value` line; the value part is
/// replaced by [`PLACEHOLDER`] exactly when [`key_matches`] holds.
#[must_use]
pub fn redact_text(policy: &RedactPolicy, key: &str, value: &str) -> RedactedText {
    if key_matches(policy, key) {
        RedactedText {
            text: PLACEHOLDER.to_owned(),
            redacted: true,
        }
    } else {
        RedactedText {
            text: value.to_owned(),
            redacted: false,
        }
    }
}

/// Redaction facts of one redacted value (RFC 0015 §11.3).
///
/// [`Self::protocol`] always constructs the protocol `Redaction` record with
/// the frozen `redacted == (count > 0)` invariant (consema-protocol
/// `cli.rs`), so the invariant can never be violated by an output path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionFacts {
    /// Number of values replaced with [`PLACEHOLDER`] in this output.
    count: u64,
    /// Matching key names in first-seen document order, deduplicated.
    keys: Vec<String>,
}

impl RedactionFacts {
    /// Number of values replaced with the `$REDACTED$` placeholder.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// The matching key names in first-seen document order, deduplicated.
    ///
    /// Deterministic (document order) so stderr diagnostics can name the
    /// redacted keys without leaking the values.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// The protocol `Redaction` record of the envelope (`redacted ==
    /// (count > 0)` by construction; RFC 0015 §4.1).
    #[must_use]
    pub fn protocol(&self) -> Redaction {
        Redaction::new(self.count > 0, self.count)
            .expect("redaction invariant redacted == (count > 0) is preserved by construction")
    }

    fn record(&mut self, key: &str) {
        self.count += 1;
        if !self.keys.iter().any(|seen| seen == key) {
            self.keys.push(key.to_owned());
        }
    }
}

/// Redacts one presentation value for machine output (the envelope payload
/// view), returning the redacted tree plus the facts.
///
/// Semantics (frozen for v1, deterministic and reproducible):
///
/// - Under `--show-secrets` the value is returned untouched and the facts
///   are zero (RFC 0015 §11.4, sole opt-out).
/// - For every object entry whose key matches [`key_matches`], the entry's
///   value is replaced by the string [`PLACEHOLDER`] — any value type,
///   including containers (a matching container key hides its whole subtree
///   and counts as exactly one replacement, the conservative direction).
///   The key itself is never replaced.
/// - Entries whose key does not match are recursed into; sequences recurse
///   per item; entry mappings treat string keys like object keys.
/// - All other value kinds are copied verbatim: redaction never alters
///   non-presentation payload (bytes, integers, nested structures under
///   non-matching keys) — in particular, raw byte payloads such as patch
///   precondition facts are preserved exactly.
/// - The count is the number of replaced values; the matching keys are
///   recorded in first-seen document order.
///
/// The API takes only a [`PortableValue`] view — never a patch, snapshot, or
/// file — so the byte preconditions of a `SourcePatch` cannot be reached by
/// construction (RFC 0015 §11.4; hard gate 3).
#[must_use]
pub fn redact_value(
    policy: &RedactPolicy,
    value: &PortableValue,
) -> (PortableValue, RedactionFacts) {
    let mut facts = RedactionFacts {
        count: 0,
        keys: Vec::new(),
    };
    let redacted = redact_node(policy, value, &mut facts);
    (redacted, facts)
}

fn redact_node(
    policy: &RedactPolicy,
    value: &PortableValue,
    facts: &mut RedactionFacts,
) -> PortableValue {
    if policy.show_secrets {
        return value.clone();
    }
    match value.kind() {
        consema::core::PortableValueKind::Object => {
            let mut builder = ObjectBuilder::new();
            for entry in value.as_object().expect("object kind") {
                if key_matches(policy, entry.key()) {
                    facts.record(entry.key());
                    builder
                        .insert(entry.key(), PortableValue::string(PLACEHOLDER))
                        .expect("object entries keep their unique keys");
                } else {
                    builder
                        .insert(entry.key(), redact_node(policy, entry.value(), facts))
                        .expect("object entries keep their unique keys");
                }
            }
            builder.build()
        }
        consema::core::PortableValueKind::Sequence => {
            let mut builder = SequenceBuilder::new();
            for item in value.as_sequence().expect("sequence kind") {
                builder.push(redact_node(policy, item, facts));
            }
            builder.build()
        }
        consema::core::PortableValueKind::EntryMapping => {
            let mut builder = EntryMappingBuilder::new();
            for entry in value.as_entry_mapping().expect("entry-mapping kind") {
                if let Some(key) = entry
                    .key()
                    .as_string()
                    .filter(|key| key_matches(policy, key))
                {
                    facts.record(key);
                    builder.push(entry.key().clone(), PortableValue::string(PLACEHOLDER));
                    continue;
                }
                builder.push(
                    entry.key().clone(),
                    redact_node(policy, entry.value(), facts),
                );
            }
            builder.build()
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::{ObjectBuilder, PortableValue, SequenceBuilder};
    use consema::document::{
        ContentDigest, SourcePatch, SourcePatchLimits, SourceReplacement, SourceSnapshot,
    };
    use std::collections::BTreeMap;

    fn policy() -> RedactPolicy {
        RedactPolicy::conservative()
    }

    fn object(entries: &[(&str, &str)]) -> PortableValue {
        let mut builder = ObjectBuilder::new();
        for (key, value) in entries {
            builder
                .insert(*key, PortableValue::string(*value))
                .expect("unique keys");
        }
        builder.build()
    }

    fn redacted_of(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        let (value, _) = redact_value(&policy(), &object(entries));
        value
            .as_object()
            .expect("object")
            .iter()
            .map(|entry| {
                (
                    entry.key().to_owned(),
                    entry
                        .value()
                        .as_string()
                        .unwrap_or("<non-string>")
                        .to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn every_frozen_pattern_matches_its_key_names() {
        // RFC 0015 §11.2 pattern matrix: each frozen alternative hits as a
        // whole word, inside a longer key (substring), and in every case.
        let cases: &[(&str, &[&str])] = &[
            (
                "password",
                &["password", "Password", "DB_PASSWORD", "password_history"],
            ),
            ("passwd", &["passwd", "shadow_passwd", "PASSWD"]),
            (
                "secret",
                &["secret", "client_secret", "secrets", "SECRET_KEY"],
            ),
            ("token", &["token", "auth_token", "tokens", "TOKEN"]),
            (
                "api[_-]?key",
                &["apikey", "api_key", "api-key", "API_KEY", "my_api_key"],
            ),
            (
                "private[_-]?key",
                &["privatekey", "private_key", "private-key", "PRIVATE_KEY"],
            ),
            (
                "access[_-]?key",
                &["accesskey", "access_key", "access-key", "ACCESS_KEY"],
            ),
            (
                "credential",
                &["credential", "credentials", "CREDENTIAL", "aws_credentials"],
            ),
            ("auth", &["auth", "authorization", "authToken", "AUTH"]),
        ];
        for (pattern, keys) in cases {
            for key in *keys {
                assert!(key_matches(&policy(), key), "{pattern} must match {key}");
            }
        }
    }

    #[test]
    fn key_names_that_only_look_secretish_never_match() {
        // False-positive guard: a normal key that merely resembles a pattern
        // word (or contains a shared fragment) must stay. "username",
        // "hostname", "author" is deliberately not listed — it contains
        // "auth" and the conservative substring contract redacts it.
        for key in [
            "hostname",
            "username",
            "port",
            "url",
            "schema",
            "path",
            "description",
            "enabled",
            "value",
            "name",
            "old_start",
            "target",
            "digest",
            "bytes",
            "algorithm",
        ] {
            assert!(!key_matches(&policy(), key), "false positive on {key}");
        }
    }

    #[test]
    fn values_that_look_like_key_names_are_never_redacted() {
        // Value-shape inference is off (RFC 0015 §11.2): a normal value that
        // merely looks like a key name stays, even when it is a secret-shaped
        // string. Only the key decides.
        let value = object(&[
            ("name", "password"),
            ("url", "https://example.com/api_key"),
            ("description", "token bucket at auth.example.com"),
            ("username", "secret_user"),
        ]);
        let (redacted, facts) = redact_value(&policy(), &value);
        assert_eq!(facts.count(), 0);
        assert!(!facts.protocol().redacted());
        assert_eq!(redacted, value, "no key matched; the tree is unchanged");
    }

    #[test]
    fn redact_text_replaces_values_under_matching_keys_only() {
        let policy = policy();
        let hit = redact_text(&policy, "password", "hunter2");
        assert!(hit.redacted());
        assert_eq!(hit.text(), PLACEHOLDER);
        let miss = redact_text(&policy, "name", "password");
        assert!(!miss.redacted());
        assert_eq!(miss.text(), "password");
        let secrets = RedactPolicy::show_secrets();
        let revealed = redact_text(&secrets, "password", "hunter2");
        assert!(!revealed.redacted());
        assert_eq!(revealed.text(), "hunter2");
    }

    #[test]
    fn redact_value_replaces_values_and_counts_each_replacement() {
        let (redacted, facts) = redact_value(
            &policy(),
            &object(&[
                ("host", "db.internal"),
                ("password", "hunter2"),
                ("api_key", "k-1234"),
            ]),
        );
        assert_eq!(facts.count(), 2);
        assert_eq!(facts.keys(), &["password".to_owned(), "api_key".to_owned()]);
        assert_eq!(
            redacted_of(&[
                ("host", "db.internal"),
                ("password", "hunter2"),
                ("api_key", "k-1234"),
            ]),
            vec![
                ("host".to_owned(), "db.internal".to_owned()),
                ("password".to_owned(), PLACEHOLDER.to_owned()),
                ("api_key".to_owned(), PLACEHOLDER.to_owned()),
            ]
        );
        let entries = redacted.as_object().expect("object");
        assert_eq!(entries[0].key(), "host");
        assert_eq!(entries[0].value().as_string(), Some("db.internal"));
        assert_eq!(entries[1].key(), "password");
        assert_eq!(entries[1].value().as_string(), Some(PLACEHOLDER));
        assert_eq!(entries[2].key(), "api_key");
        assert_eq!(entries[2].value().as_string(), Some(PLACEHOLDER));
        assert_eq!(facts.protocol().count(), 2);
        assert!(facts.protocol().redacted());
    }

    #[test]
    fn redaction_facts_honor_the_redacted_equals_count_invariant() {
        // The protocol record is always constructible and always satisfies
        // redacted == (count > 0) (consema-protocol cli.rs invariant).
        let (_, none) = redact_value(&policy(), &object(&[("host", "db")]));
        assert_eq!(none.count(), 0);
        assert!(!none.protocol().redacted());
        assert_eq!(none.protocol().count(), 0);
        let (_, one) = redact_value(&policy(), &object(&[("token", "t")]));
        assert_eq!(one.count(), 1);
        assert!(one.protocol().redacted());
        assert_eq!(one.protocol().count(), 1);
        let mut three = SequenceBuilder::new();
        three.push(object(&[("token", "a")]));
        three.push(object(&[("api_key", "b")]));
        three.push(object(&[("secret", "c")]));
        let (_, many) = redact_value(&policy(), &three.build());
        assert_eq!(many.count(), 3);
        assert_eq!(many.protocol().count(), 3);
    }

    #[test]
    fn matching_keys_are_deduplicated_in_first_seen_order() {
        // The same key matching in several places of the tree counts each
        // replacement but records the key once, in first-seen order.
        let mut sequence = SequenceBuilder::new();
        sequence.push(object(&[("password", "a")]));
        sequence.push(object(&[("host", "x")]));
        sequence.push(object(&[("password", "b")]));
        let (_, facts) = redact_value(&policy(), &sequence.build());
        assert_eq!(facts.count(), 2);
        assert_eq!(facts.keys(), &["password".to_owned()]);
        let mut order = SequenceBuilder::new();
        order.push(object(&[("password", "a")]));
        order.push(object(&[("api_key", "b")]));
        order.push(object(&[("password", "c")]));
        let (_, ordered) = redact_value(&policy(), &order.build());
        assert_eq!(
            ordered.keys(),
            &["password".to_owned(), "api_key".to_owned()]
        );
    }

    #[test]
    fn nested_structures_redact_recursively() {
        // A matching container key hides its whole subtree as one
        // replacement (conservative direction).
        let mut outer = ObjectBuilder::new();
        outer
            .insert("secrets", object(&[("password", "x"), ("user", "y")]))
            .expect("unique keys");
        outer
            .insert("service", object(&[("name", "catalog"), ("token", "t")]))
            .expect("unique keys");
        let (redacted, facts) = redact_value(&policy(), &outer.build());
        assert_eq!(facts.count(), 2);
        assert_eq!(facts.keys(), &["secrets".to_owned(), "token".to_owned()]);
        let entries = redacted.as_object().expect("object");
        assert_eq!(entries[0].value().as_string(), Some(PLACEHOLDER));
        let service = entries[1].value().as_object().expect("service object");
        assert_eq!(service[0].value().as_string(), Some("catalog"));
        assert_eq!(service[1].value().as_string(), Some(PLACEHOLDER));
    }

    #[test]
    fn sequences_of_objects_redact_each_item() {
        let mut sequence = SequenceBuilder::new();
        sequence.push(object(&[("token", "a")]));
        sequence.push(object(&[("token", "b")]));
        sequence.push(object(&[("name", "x")]));
        let (redacted, facts) = redact_value(&policy(), &sequence.build());
        assert_eq!(facts.count(), 2);
        let items = redacted.as_sequence().expect("sequence");
        assert_eq!(
            items[0].as_object().expect("item")[0].value().as_string(),
            Some(PLACEHOLDER)
        );
        assert_eq!(
            items[1].as_object().expect("item")[0].value().as_string(),
            Some(PLACEHOLDER)
        );
        assert_eq!(
            items[2].as_object().expect("item")[0].value().as_string(),
            Some("x")
        );
    }

    #[test]
    fn non_string_values_under_matching_keys_are_replaced_too() {
        let mut builder = ObjectBuilder::new();
        builder
            .insert("token", PortableValue::integer(12345_i64.into()))
            .expect("unique keys");
        builder
            .insert("port", PortableValue::integer(8080_i64.into()))
            .expect("unique keys");
        let (redacted, facts) = redact_value(&policy(), &builder.build());
        assert_eq!(facts.count(), 1);
        let entries = redacted.as_object().expect("object");
        assert_eq!(entries[0].value().as_string(), Some(PLACEHOLDER));
        assert_eq!(
            entries[1].value().as_integer().map(ToString::to_string),
            Some("8080".to_owned())
        );
    }

    #[test]
    fn byte_payloads_under_non_matching_keys_are_preserved_exactly() {
        // Redaction never alters non-presentation payload: a Bytes value
        // under a non-matching key survives byte-for-byte.
        let precondition_bytes: [u8; 6] = [0x6f, 0x6c, 0x64, 0x0a, 0xff, 0x00];
        let mut builder = ObjectBuilder::new();
        builder
            .insert("original", PortableValue::bytes(precondition_bytes))
            .expect("unique keys");
        builder
            .insert("password", PortableValue::bytes(precondition_bytes))
            .expect("unique keys");
        let (redacted, facts) = redact_value(&policy(), &builder.build());
        assert_eq!(facts.count(), 1);
        let entries = redacted.as_object().expect("object");
        assert_eq!(entries[0].value().as_bytes(), Some(&precondition_bytes[..]));
        assert_eq!(entries[1].value().as_string(), Some(PLACEHOLDER));
    }

    #[test]
    fn show_secrets_is_the_sole_opt_out_and_returns_the_value_untouched() {
        let secrets = RedactPolicy::show_secrets();
        let value = object(&[("password", "hunter2"), ("host", "db")]);
        let (redacted, facts) = redact_value(&secrets, &value);
        assert_eq!(redacted, value, "show-secrets output equals the input tree");
        assert_eq!(facts.count(), 0);
        assert!(!facts.protocol().redacted());
        assert!(secrets.secrets_visible());
        assert!(!RedactPolicy::conservative().secrets_visible());
        assert!(!key_matches(&secrets, "password"));
    }

    #[test]
    fn extra_redact_keys_globs_compile_and_match_whole_key_names() {
        let policy = RedactPolicy::conservative()
            .with_extra_patterns(&["customer_*", "t?ken"])
            .expect("valid globs");
        for key in ["customer_id", "customer_token", "token", "taken"] {
            assert!(key_matches(&policy, key), "{key} matches an extra glob");
        }
        for key in ["customer", "hostname", "port"] {
            assert!(!key_matches(&policy, key), "{key} matches nothing");
        }
        // Globs are case-insensitive like the frozen patterns.
        let policy = RedactPolicy::conservative()
            .with_extra_patterns(&["Customer_*"])
            .expect("valid glob");
        assert!(key_matches(&policy, "customer_id"));
        // Explicit patterns coexist with the frozen set.
        assert!(key_matches(&policy, "password"));
    }

    #[test]
    fn invalid_redact_keys_patterns_are_frozen_usage_failures() {
        let empty = RedactPolicy::conservative()
            .with_extra_patterns(&[""])
            .expect_err("empty glob is invalid");
        assert_eq!(empty.code(), "cli.usage.redaction-pattern@1");
        assert_eq!(empty, RedactPatternError::Empty);
        assert!(!empty.message().is_empty());
        let bracket = RedactPolicy::conservative()
            .with_extra_patterns(&["ke[y]"])
            .expect_err("bracket classes are rejected");
        assert_eq!(bracket.code(), "cli.usage.redaction-pattern@1");
        assert_eq!(
            bracket,
            RedactPatternError::ReservedSyntax("ke[y]".to_owned())
        );
        // A failed compile leaves the policy untouched (no partial policy).
        let policy = RedactPolicy::conservative()
            .with_extra_patterns(&["a*", "ke[y]"])
            .expect_err("second pattern invalidates the batch");
        assert_eq!(
            policy,
            RedactPatternError::ReservedSyntax("ke[y]".to_owned())
        );
    }

    #[test]
    fn redaction_is_deterministic_across_calls() {
        let value = object(&[("password", "x"), ("host", "y")]);
        let (first, first_facts) = redact_value(&policy(), &value);
        let (second, second_facts) = redact_value(&policy(), &value);
        assert_eq!(first, second);
        assert_eq!(first_facts, second_facts);
    }

    #[test]
    fn redaction_never_touches_patch_precondition_bytes() {
        // RFC 0015 §11.4 / M6 acceptance gate: patch application bytes are
        // unchanged by any redaction setting. The presentation embedding of
        // the precondition bytes is redacted; the patch itself — the only
        // object that applies bytes — is out of reach of the redaction API
        // (it accepts only &PortableValue) and still applies byte-for-byte.
        let base = SourceSnapshot::from_utf8(*b"token = abc123\n").expect("base snapshot");
        let patch = SourcePatch::create(
            &base,
            vec![SourceReplacement::new(8, 14, *b"abc123", *b"xyz789")],
            BTreeMap::new(),
            SourcePatchLimits::default(),
        )
        .expect("valid patch");
        let applied_before = patch
            .apply(&base, SourcePatchLimits::default())
            .expect("apply")
            .bytes()
            .to_vec();

        // A plan-style presentation view embedding the precondition bytes
        // under a matching key name; the CLI presentation layer would show
        // this in the human/plan view.
        let view = object(&[("password", "abc123")]);
        let (redacted_view, facts) = redact_value(&policy(), &view);
        assert_eq!(facts.count(), 1);
        assert_eq!(
            redacted_view.as_object().expect("object")[0]
                .value()
                .as_string(),
            Some(PLACEHOLDER)
        );
        let (revealed_view, revealed_facts) = redact_value(&RedactPolicy::show_secrets(), &view);
        assert_eq!(revealed_facts.count(), 0);
        assert_eq!(revealed_view, view);

        // The patch bytes and their application are untouched by either
        // redaction setting.
        let applied_after = patch
            .apply(&base, SourcePatchLimits::default())
            .expect("apply after redaction")
            .bytes()
            .to_vec();
        assert_eq!(applied_before, applied_after);
        assert_eq!(applied_after, b"token = xyz789\n");
        assert_eq!(patch.base_digest(), ContentDigest::of(b"token = abc123\n"));
    }
}
