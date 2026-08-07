//! Facts-only file detection (implementation plan §3.2; RFC 0015 §7).
//!
//! Detection returns only deterministic facts: byte facts (size, digest),
//! BOM facts, leading-byte signature facts ("markers"), and the candidate
//! profile set each marker implies — every candidate carries its reason.
//! There is no parse, no conclusion, and no side effect (hard gate 2): a
//! marker never selects a Profile, representation, or encoding (RFC 0015
//! §7.2 rule 1), and a candidate set of more than one profile is a
//! first-class ambiguity result (`ambiguous: true`), never a silent guess
//! (RFC 0015 §7.2 rule 5; plan §3.2). The marker set and its judgments are
//! the deterministic table below; milestone M9 pins them with the
//! `consema.cli.conformance@1` vectors (RFC 0015 §16.1 `cli.detection@1`).

use consema::document::{ContentDigest, ProfileId};

use super::registry;

/// One candidate profile with the deterministic reason for its candidacy
/// (RFC 0015 §7.1 `candidates`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Candidate profile.
    pub profile: ProfileId,
    /// Deterministic marker judgment that produced the candidacy.
    pub reason: String,
}

/// The full fact inventory of one file's leading bytes (RFC 0015 §7.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectFacts {
    /// Number of bytes read from the file (the file size when fully read).
    pub size: u64,
    /// SHA-256 of the exact bytes; `None` when the read was capped.
    pub digest: Option<ContentDigest>,
    /// BOM fact: `"Utf8" | "Utf16Le" | "Utf16Be"`; `None` when absent.
    pub bom: Option<&'static str>,
    /// Signature facts determinable from leading bytes (zero or one).
    pub markers: Vec<&'static str>,
    /// Candidate set derived from the marker, each with a reason; an empty
    /// set means no candidate.
    pub candidates: Vec<Candidate>,
    /// Whether the candidate set has more than one entry (RFC 0015 §7.1).
    pub ambiguous: bool,
    /// Deterministic ambiguity explanations.
    pub ambiguity_reasons: Vec<String>,
}

/// One marker judgment: the signature fact, its reason, and the candidate
/// profile ids the signature is consistent with.
struct Marker {
    fact: &'static str,
    reason: &'static str,
    profiles: &'static [&'static str],
}

/// The candidate profiles per marker (the fixed detection table; plan §3.2's
/// candidate examples). Every profile id is resolved against the facade
/// profile inventory at detection time, so the table cannot publish a
/// profile the facade does not know; the marker-collision rows are the
/// frozen ambiguity cases of RFC 0015 §7.2 rule 5 (INI vs Properties, JSON
/// vs JSON5, XML vs plist.xml, TOML table vs INI section).
const PLIST_BINARY: &[&str] = &["plist.binary"];
const XML_PLIST: &[&str] = &["xml.1.0-safe", "plist.xml"];
const PLIST_XML: &[&str] = &["plist.xml"];
const JSON_FAMILY: &[&str] = &["json.strict", "jsonc.bounded", "json5.standard"];
const INI_TOML: &[&str] = &[
    "ini.portable",
    "ini.windows",
    "ini.python-configparser",
    "toml.1.0",
];
const INI_PROPERTIES: &[&str] = &[
    "ini.portable",
    "ini.windows",
    "ini.python-configparser",
    "java-properties.reader",
    "java-properties.latin1",
];
const YAML_FAMILY: &[&str] = &["yaml.1.2-core", "yaml.1.1-compat"];
const TOML_HCL: &[&str] = &["toml.1.0", "hcl.native", "hcl.tfvars"];

/// Builds the deterministic fact inventory of one byte buffer.
///
/// `fully_read` marks whether the buffer holds the complete file; when it is
/// false (a capped read), the digest fact is absent instead of a partial
/// digest, and the size is the read size — never a disguised full-file fact
/// (RFC 0015 §3.4, §12).
#[must_use]
pub fn detect(bytes: &[u8], fully_read: bool) -> DetectFacts {
    let size = u64::try_from(bytes.len()).expect("read sizes are capped");
    let digest = if fully_read {
        Some(ContentDigest::of(bytes))
    } else {
        None
    };
    let bom = detect_bom(bytes);
    let marker = marker(bytes);
    let mut markers = Vec::new();
    let mut candidates = Vec::new();
    let mut ambiguity_reasons = Vec::new();
    if let Some(marker) = marker {
        markers.push(marker.fact);
        for profile_id in marker.profiles {
            // Resolve against the facade inventory: a table id the facade
            // does not publish contributes no candidate (the facade tests
            // pin the inventory, so this is unreachable in practice).
            if let Some(entry) = registry::profile_by_id(profile_id) {
                candidates.push(Candidate {
                    profile: entry.profile,
                    reason: marker.reason.to_owned(),
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.profile
                .id()
                .cmp(right.profile.id())
                .then(left.profile.version().cmp(&right.profile.version()))
        });
        if candidates.len() > 1 {
            let mut families: Vec<String> = Vec::new();
            for profile_id in marker.profiles {
                if let Some(entry) = registry::profile_by_id(profile_id) {
                    if !families.iter().any(|family| family == &entry.family_id) {
                        families.push(entry.family_id);
                    }
                }
            }
            families.sort();
            if families.len() > 1 {
                ambiguity_reasons.push(format!(
                    "{} is consistent with format families: {}",
                    marker.fact,
                    families.join(", ")
                ));
            } else {
                ambiguity_reasons.push(format!(
                    "{} is consistent with multiple profiles of the {} family",
                    marker.fact, families[0]
                ));
            }
        }
    }
    let ambiguous = candidates.len() > 1;
    DetectFacts {
        size,
        digest,
        bom,
        markers,
        candidates,
        ambiguous,
        ambiguity_reasons,
    }
}

/// One BOM detection fact; no codepage guessing (RFC 0015 §7.1 `bom`).
#[must_use]
pub fn detect_bom(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some("Utf8")
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some("Utf16Le")
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some("Utf16Be")
    } else {
        None
    }
}

/// One deterministic marker judgment from the leading bytes, or `None`.
///
/// Judgments are exclusive (at most one marker): a `bplist00` header wins
/// over everything; otherwise the first content line (after an optional BOM
/// and leading whitespace) decides. The `[section]`-line judgment requires a
/// comma-free interior so that a leading JSON array (`[1, 2]`) stays a
/// `[`-fact; a `key = value` line with whitespace on both sides of `=` is
/// the `a = 1` shape (TOML/HCL), a bare `key=value` line is the INI /
/// Java-Properties shape.
fn marker(bytes: &[u8]) -> Option<Marker> {
    if bytes.starts_with(b"bplist00") {
        return Some(Marker {
            fact: "bplist00 header",
            reason: "leading bplist00 header bytes",
            profiles: PLIST_BINARY,
        });
    }
    let first = first_content_byte(bytes)?;
    let line_end = bytes[first..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| first + offset);
    let content = &bytes[first..line_end];
    let marker = if content.starts_with(b"<?xml") {
        Marker {
            fact: "XML declaration",
            reason: "leading XML declaration",
            profiles: XML_PLIST,
        }
    } else if content.starts_with(b"<plist")
        && content
            .get(6)
            .is_none_or(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>'))
    {
        Marker {
            fact: "plist root element",
            reason: "leading plist root element",
            profiles: PLIST_XML,
        }
    } else if content.starts_with(b"[")
        && content.ends_with(b"]")
        && content.len() > 2
        && !content[1..content.len() - 1].contains(&b',')
    {
        Marker {
            fact: "[section] line",
            reason: "leading [section] line",
            profiles: INI_TOML,
        }
    } else if content.starts_with(b"[") {
        Marker {
            fact: "first non-whitespace '['",
            reason: "first non-whitespace byte is '['",
            profiles: JSON_FAMILY,
        }
    } else if content.starts_with(b"{") {
        Marker {
            fact: "first non-whitespace '{'",
            reason: "first non-whitespace byte is '{'",
            profiles: JSON_FAMILY,
        }
    } else if content.starts_with(b"%YAML") {
        Marker {
            fact: "%YAML directive",
            reason: "leading %YAML directive",
            profiles: YAML_FAMILY,
        }
    } else if let Some(equal) = content.iter().position(|byte| *byte == b'=') {
        let spaced = equal > 0
            && content[equal - 1].is_ascii_whitespace()
            && content.get(equal + 1).is_some_and(u8::is_ascii_whitespace);
        if spaced {
            Marker {
                fact: "a = 1 shape",
                reason: "leading a = 1 assignment shape",
                profiles: TOML_HCL,
            }
        } else {
            Marker {
                fact: "key=value line",
                reason: "leading key=value line",
                profiles: INI_PROPERTIES,
            }
        }
    } else if content.contains(&b':') {
        Marker {
            fact: "key: value line",
            reason: "leading key: value line",
            profiles: YAML_FAMILY,
        }
    } else {
        return None;
    };
    Some(marker)
}

/// Index of the first byte that is neither a BOM nor whitespace.
fn first_content_byte(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF])
        || bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
    {
        index = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            3
        } else {
            2
        };
    }
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
        index += 1;
    }
    (index < bytes.len()).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_ids(facts: &DetectFacts) -> Vec<&str> {
        facts
            .candidates
            .iter()
            .map(|candidate| candidate.profile.id())
            .collect()
    }

    #[test]
    fn bplist00_header_is_a_plist_binary_fact() {
        let facts = detect(b"bplist00\x5f\x78", true);
        assert_eq!(facts.markers, vec!["bplist00 header"]);
        assert_eq!(candidate_ids(&facts), vec!["plist.binary"]);
        assert!(!facts.ambiguous);
        assert_eq!(facts.candidates[0].reason, "leading bplist00 header bytes");
    }

    #[test]
    fn xml_declaration_is_ambiguous_between_xml_and_plist() {
        let facts = detect(b"<?xml version=\"1.0\"?><a/>", true);
        assert_eq!(facts.markers, vec!["XML declaration"]);
        assert_eq!(candidate_ids(&facts), vec!["plist.xml", "xml.1.0-safe"]);
        assert!(facts.ambiguous);
        assert_eq!(
            facts.ambiguity_reasons,
            vec!["XML declaration is consistent with format families: plist, xml"]
        );
        // A plist root element without a declaration resolves to plist only.
        let facts = detect(b"<plist version=\"1.0\"><string>x</string></plist>", true);
        assert_eq!(facts.markers, vec!["plist root element"]);
        assert_eq!(candidate_ids(&facts), vec!["plist.xml"]);
        assert!(!facts.ambiguous);
    }

    #[test]
    fn leading_brace_and_bracket_are_json_family_facts() {
        let facts = detect(b"{\"a\": 1}", true);
        assert_eq!(facts.markers, vec!["first non-whitespace '{'"]);
        assert_eq!(
            candidate_ids(&facts),
            vec!["json.strict", "json5.standard", "jsonc.bounded"]
        );
        assert!(facts.ambiguous);
        assert_eq!(
            facts.ambiguity_reasons,
            vec![
                "first non-whitespace '{' is consistent with multiple profiles of the json family"
            ]
        );
        // A leading JSON array stays a '[' fact, not a section header.
        let facts = detect(b"[1, 2]", true);
        assert_eq!(facts.markers, vec!["first non-whitespace '['"]);
        assert_eq!(facts.candidates.len(), 3);
        // Leading whitespace and a UTF-8 BOM do not change the judgment.
        let facts = detect(b"\xef\xbb\xbf\n  { \"a\": 1 }", true);
        assert_eq!(facts.markers, vec!["first non-whitespace '{'"]);
    }

    #[test]
    fn section_line_is_ambiguous_between_ini_and_toml() {
        let facts = detect(b"[section]\nvalue=1\n", true);
        assert_eq!(facts.markers, vec!["[section] line"]);
        assert_eq!(
            candidate_ids(&facts),
            vec![
                "ini.portable",
                "ini.python-configparser",
                "ini.windows",
                "toml.1.0"
            ]
        );
        assert!(facts.ambiguous);
        assert_eq!(
            facts.ambiguity_reasons,
            vec!["[section] line is consistent with format families: ini, toml"]
        );
    }

    #[test]
    fn key_value_line_is_ambiguous_between_ini_and_properties() {
        let facts = detect(b"name=api\nport=8080\n", true);
        assert_eq!(facts.markers, vec!["key=value line"]);
        assert_eq!(
            candidate_ids(&facts),
            vec![
                "ini.portable",
                "ini.python-configparser",
                "ini.windows",
                "java-properties.latin1",
                "java-properties.reader"
            ]
        );
        assert!(facts.ambiguous);
    }

    #[test]
    fn spaced_assignment_is_the_toml_hcl_shape() {
        let facts = detect(b"a = 1\n", true);
        assert_eq!(facts.markers, vec!["a = 1 shape"]);
        assert_eq!(
            candidate_ids(&facts),
            vec!["hcl.native", "hcl.tfvars", "toml.1.0"]
        );
        assert!(facts.ambiguous);
    }

    #[test]
    fn yaml_markers_resolve_to_the_yaml_family() {
        let facts = detect(b"name: catalog\nport: 8080\n", true);
        assert_eq!(facts.markers, vec!["key: value line"]);
        assert_eq!(
            candidate_ids(&facts),
            vec!["yaml.1.1-compat", "yaml.1.2-core"]
        );
        assert!(facts.ambiguous);
        let facts = detect(b"%YAML 1.2\n---\nvalue: 1\n", true);
        assert_eq!(facts.markers, vec!["%YAML directive"]);
        assert_eq!(facts.candidates.len(), 2);
    }

    #[test]
    fn unknown_content_has_no_marker_and_no_candidates() {
        let facts = detect(b"# just a comment\n", true);
        assert!(facts.markers.is_empty());
        assert!(facts.candidates.is_empty());
        assert!(!facts.ambiguous);
        assert!(facts.ambiguity_reasons.is_empty());
        let facts = detect(b"", true);
        assert!(facts.markers.is_empty());
        assert!(facts.candidates.is_empty());
    }

    #[test]
    fn byte_facts_and_bom_facts_are_deterministic() {
        let facts = detect(b"\xef\xbb\xbf{\"a\":1}", true);
        assert_eq!(facts.size, 10);
        assert_eq!(facts.bom, Some("Utf8"));
        assert_eq!(
            facts.digest,
            Some(ContentDigest::of(b"\xef\xbb\xbf{\"a\":1}"))
        );
        assert_eq!(detect_bom(b"\xff\xfe\x7b\x00"), Some("Utf16Le"));
        assert_eq!(detect_bom(b"\xfe\xff\x00\x7b"), Some("Utf16Be"));
        assert_eq!(detect_bom(b"plain"), None);
        // A capped read never reports a partial digest.
        let facts = detect(b"\xef\xbb\xbf{\"a\":1}", false);
        assert_eq!(facts.digest, None);
    }
}
