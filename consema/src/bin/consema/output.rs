//! stdout/stderr separation and machine-envelope emission (RFC 0015 §3.3).
//!
//! Under `--json`, stdout carries exactly one line of canonical envelope
//! JSON ending in one LF (0x0A) and nothing else; `--json --pretty` applies
//! the self-written deterministic whitespace indenter first (implementation
//! plan §5.2 — pure formatting of canonical bytes, no parse or reorder).
//! Human result data is rendered by each command and written through the
//! same writer; diagnostics always go to stderr through `main.rs`. The
//! per-command human-renderer registry fills in milestone M4 once the first
//! renderer exists; M3 only needs the envelope writer.

use consema::protocol::{CliOutputMessage, ProtocolLimits};
use std::io::Write;

/// Envelope emission failure; each variant carries a human stderr message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    /// The envelope failed canonical transport encoding.
    Protocol(String),
    /// The canonical bytes are not indentation-safe.
    Indent(String),
    /// The output stream failed.
    Io(String),
}

impl EmitError {
    /// Human diagnostic for stderr.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Protocol(message) | Self::Indent(message) | Self::Io(message) => message,
        }
    }
}

/// Writes exactly one canonical `core.cli-output@1` line ending in one LF.
///
/// With `pretty` the canonical bytes first pass through
/// [`indent_canonical_json`]; the canonical semantics are unchanged (only
/// whitespace is inserted outside strings). The envelope may carry any
/// exit class except usage — usage failures never reach this writer
/// (RFC 0015 §4.2).
pub fn emit_envelope(
    envelope: &CliOutputMessage,
    pretty: bool,
    out: &mut dyn Write,
) -> Result<(), EmitError> {
    let limits = ProtocolLimits::default();
    let bytes = envelope
        .to_json(limits)
        .map_err(|error| EmitError::Protocol(error.to_string()))?;
    if pretty {
        let indented = indent_canonical_json(&bytes).map_err(EmitError::Indent)?;
        write_line(&indented, out)?;
    } else {
        write_line(&bytes, out)?;
    }
    Ok(())
}

fn write_line(bytes: &[u8], out: &mut dyn Write) -> Result<(), EmitError> {
    out.write_all(bytes)
        .map_err(|error| EmitError::Io(format!("stdout write failed: {error}")))?;
    out.write_all(b"\n")
        .map_err(|error| EmitError::Io(format!("stdout write failed: {error}")))?;
    out.flush()
        .map_err(|error| EmitError::Io(format!("stdout flush failed: {error}")))
}

/// Deterministic whitespace-only indenter for canonical tagged JSON bytes.
///
/// The input is the byte output of `encode_json` (RFC 0015 §3.1), which
/// contains no whitespace at all. This function inserts `\n` and two-space
/// indentation outside string literals and copies every other byte —
/// including string contents and escapes — verbatim. It never parses,
/// reorders, or re-encodes the value, so the canonical semantics are
/// byte-for-byte unchanged up to the inserted whitespace. A malformed
/// (unterminated-string) input is rejected instead of mangled.
pub fn indent_canonical_json(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 4);
    let mut depth = 0_usize;
    let mut at_line_start = true;
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'"' => {
                if at_line_start {
                    push_indent(&mut out, depth);
                    at_line_start = false;
                }
                let start = index;
                index += 1;
                let mut terminated = false;
                while index < input.len() {
                    if input[index] == b'\\' {
                        index += 2;
                    } else if input[index] == b'"' {
                        index += 1;
                        terminated = true;
                        break;
                    } else {
                        index += 1;
                    }
                }
                if !terminated {
                    return Err("unterminated string in canonical JSON".to_owned());
                }
                out.extend_from_slice(&input[start..index]);
            }
            b'{' | b'[' => {
                if at_line_start {
                    push_indent(&mut out, depth);
                }
                out.push(input[index]);
                depth += 1;
                out.push(b'\n');
                at_line_start = true;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if !at_line_start {
                    out.push(b'\n');
                }
                push_indent(&mut out, depth);
                out.push(input[index]);
                at_line_start = false;
                index += 1;
            }
            b',' => {
                out.push(b',');
                out.push(b'\n');
                at_line_start = true;
                index += 1;
            }
            b':' => {
                out.extend_from_slice(b": ");
                index += 1;
            }
            b'\n' => {
                // Only reachable when re-indenting already-indented bytes
                // (canonical transport bytes contain no whitespace). The
                // structure arms already emit their own newlines, so an
                // input newline only matters when it terminates a line of
                // content; skipping it at line starts keeps the indenter
                // idempotent.
                if !at_line_start {
                    out.push(b'\n');
                    at_line_start = true;
                }
                index += 1;
            }
            b' ' | b'\t' | b'\r' => {
                // Input whitespace outside strings is pure structure —
                // indentation, the space after ':' — which the arms above
                // regenerate; skipping it keeps re-indentation idempotent.
                // Canonical transport bytes contain no whitespace at all.
                index += 1;
            }
            byte => {
                if at_line_start {
                    push_indent(&mut out, depth);
                    at_line_start = false;
                }
                out.push(byte);
                index += 1;
            }
        }
    }
    Ok(out)
}

fn push_indent(out: &mut Vec<u8>, depth: usize) {
    for _ in 0..depth {
        out.extend_from_slice(b"  ");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema::core::{ObjectBuilder, PortableValue, SequenceBuilder};
    use consema::protocol::{CliCommand, ExitClass, Redaction};

    fn sample_envelope() -> CliOutputMessage {
        let mut passed = SequenceBuilder::new();
        passed.push(PortableValue::string("cli.envelope@1"));
        passed.push(PortableValue::string("cli.exit-code@1"));
        let failed = SequenceBuilder::new();
        let mut payload = ObjectBuilder::new();
        payload
            .insert("schema", PortableValue::string("cli.conformance@1"))
            .expect("unique keys");
        payload
            .insert("suite", PortableValue::string("consema.cli.conformance@1"))
            .expect("unique keys");
        payload
            .insert("passed", passed.build())
            .expect("unique keys");
        payload
            .insert("failed", failed.build())
            .expect("unique keys");
        CliOutputMessage::new(
            CliCommand::Conformance,
            ExitClass::Success,
            "0.12.0",
            payload.build(),
            Vec::new(),
            Redaction::new(false, 0).expect("redaction invariant"),
        )
        .expect("valid envelope")
    }

    /// Test-only inverse of the indenter: removes whitespace outside strings.
    fn collapse_whitespace(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut in_string = false;
        let mut index = 0;
        while index < input.len() {
            match input[index] {
                b'"' => {
                    in_string = !in_string;
                    out.push(b'"');
                    index += 1;
                }
                b'\\' if in_string => {
                    out.push(input[index]);
                    out.push(input[index + 1]);
                    index += 2;
                }
                b' ' | b'\n' | b'\r' | b'\t' if !in_string => index += 1,
                byte => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        out
    }

    #[test]
    fn indenter_inserts_only_whitespace_outside_strings() {
        let envelope = sample_envelope();
        let canonical = envelope
            .to_json(ProtocolLimits::default())
            .expect("canonical bytes");
        let indented = indent_canonical_json(&canonical).expect("indentable");
        assert_eq!(collapse_whitespace(&indented), canonical);
        // Deterministic and idempotent.
        assert_eq!(
            indent_canonical_json(&indented).expect("indentable"),
            indented
        );
        // Structural markers are present.
        assert!(indented.contains(&b'\n'));
        assert!(indented.windows(2).any(|pair| pair == b": "));
        // String contents are copied verbatim, escapes included.
        let escaped = br#"{"key":"a \"b\": c"}"#;
        assert_eq!(
            collapse_whitespace(&indent_canonical_json(escaped).expect("indentable")),
            escaped
        );
    }

    #[test]
    fn indenter_handles_empty_containers_and_primitives() {
        assert_eq!(indent_canonical_json(b"{}").expect("indentable"), b"{\n}");
        assert_eq!(indent_canonical_json(b"[]").expect("indentable"), b"[\n]");
        assert_eq!(
            indent_canonical_json(br#"{"a":1}"#).expect("indentable"),
            br#"{
  "a": 1
}"#
        );
        assert_eq!(
            indent_canonical_json(b"[1,2]").expect("indentable"),
            b"[\n  1,\n  2\n]"
        );
    }

    #[test]
    fn indenter_rejects_unterminated_strings() {
        assert!(indent_canonical_json(b"{\"a").is_err());
        assert!(indent_canonical_json(br#"{"a\":}"#).is_err());
    }

    #[test]
    fn emit_envelope_writes_one_canonical_line_ending_in_lf() {
        let envelope = sample_envelope();
        let mut out = Vec::new();
        emit_envelope(&envelope, false, &mut out).expect("emitted");
        assert!(out.ends_with(b"\n"));
        assert!(!out[..out.len() - 1].contains(&b'\n'));
        let limits = ProtocolLimits::default();
        let decoded = CliOutputMessage::from_json(&out[..out.len() - 1], limits)
            .expect("byte-valid envelope");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.exit_class(), ExitClass::Success);
    }

    #[test]
    fn emit_envelope_pretty_indents_and_keeps_semantics() {
        let envelope = sample_envelope();
        let mut compact = Vec::new();
        emit_envelope(&envelope, false, &mut compact).expect("emitted");
        let mut pretty = Vec::new();
        emit_envelope(&envelope, true, &mut pretty).expect("emitted");
        assert!(pretty.contains(&b'\n'));
        assert_ne!(compact, pretty);
        // Both lines end in one LF; collapsing the pretty line's inserted
        // whitespace (outside strings) reproduces the compact envelope bytes.
        assert_eq!(collapse_whitespace(&pretty), &compact[..compact.len() - 1]);
    }
}
