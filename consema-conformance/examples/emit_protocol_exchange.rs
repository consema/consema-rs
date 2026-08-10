//! emit_protocol_exchange — cross-language protocol exchange harness support
//! (milestone 0.19.0 G5.3; docs/go-implementation-plan.md §2.6 and §4.4;
//! roadmap §16.6 line 1549 and §22.2 line 1882: "protocol cross-encode/
//! decode 100%").
//!
//! Reads the differential case file
//! (`go/conformance/differential/protocol-exchange/cases.json`) and executes
//! every case with the public Rust SDK. Each case carries one RFC 0015
//! machine record as canonical transport JSON
//! (`{"schema":"core.portable-value-json@1","value":{...}}`) plus the
//! expected outcome (empty error code = accept, registered
//! `core.protocol.*@1` code = reject). The machine schema uses only the
//! protocol schema discriminators (core.cli-output@1, ...); no Rust type
//! names participate anywhere.
//!
//! Mode `emit` (`emit_protocol_exchange <cases.json> <out-dir>`): decodes
//! every case through the full typed record decoder, re-encodes the record
//! on both transports, and writes `<out-dir>/<case-id>.json.hex` and
//! `<out-dir>/<case-id>.pvce.hex` (accept cases) or
//! `<out-dir>/<case-id>.error.txt` with the recorded rejection code (reject
//! cases). The Go test
//! (`go/conformance/differential/protocol-exchange/exchange_test.go`)
//! compares these bytes with the Go encoder and decodes them back.
//!
//! Mode `verify` (`emit_protocol_exchange --verify <cases.json> <go-dir>`):
//! reads the Go encoder's files from `<go-dir>` and verifies the
//! Go-encode -> Rust-decode direction: every accept case decodes under the
//! Rust typed record decoder to an equivalent record (value-tree equality
//! through the record codec) and re-encodes byte-identically on both
//! transports; every reject case's Go-side rejection code matches the
//! expected code.
//!
//! Error texts never participate in any comparison: only the registered
//! codes (`core.protocol.*@1`) are compared for rejections.
//!
//! Why this example exists (justification): the G5.3 gate needs the Rust
//! reference codec's bytes and rejection codes for a data-driven set of 80+
//! machine records. No existing entry point decodes arbitrary protocol
//! records from a case file and emits bytes plus rejection codes, so a
//! minimal example is required. It reuses the published crate APIs only —
//! no new encoding or validation logic — and adds no dependency: the case
//! file is parsed with the same consema-json strict parser the conformance
//! runner uses.
//!
//! Usage: `emit_protocol_exchange [--verify] <cases.json> <dir>`
//! Exit code 0 = every case verified; 1 = a case failed; 2 = usage error.

use std::env;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

use consema_core::{PortableValue, QueryDefinition};
use consema_document::{ParseLimits, SourceLimits, SourcePatchLimits};
use consema_graph::PgceLimits;
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{
    BatchPlanMessage, BatchResultMessage, CancellationRequest, CapabilityDeclaration,
    ChangeSetMessage, CliOutputMessage, Completion, DiagnosticMessage, ErrorCodeRegistry,
    ExecutionPolicy, GraphProjectionResultMessage, GraphProvenanceMapMessage,
    GraphQueryResultMessage, IniQueryResultMessage, JavaPropertiesQueryResultMessage,
    JavaUtf16String, MaterializationRequestMessageV2, MaterializationResultMessageV2,
    PortableGraphMessage, ProfileDescriptor, ProjectionReportMessage, ProjectionRequestMessage,
    ProjectionResultMessage, ProtocolError, ProtocolErrorKind, ProtocolLimits,
    ProvenanceMapMessage, QueryResultMessage, RegistryManifest, SourceEncodingMessage,
    SourcePatchMessageV2, SourceSnapshotMessageV2, YamlQueryResultMessage, decode_json,
    decode_pvce, encode_json, encode_pvce, validate_error_code_manifest_value,
};

// ---------------------------------------------------------------------------
// Case file reading (the emit_parity_bytes precedent)
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1).peekable();
    let mut verify = false;
    if args.peek().map(String::as_str) == Some("--verify") {
        verify = true;
        args.next();
    }
    let (Some(cases_path), Some(dir)) = (args.next(), args.next()) else {
        eprintln!("usage: emit_protocol_exchange [--verify] <cases.json> <dir>");
        std::process::exit(2);
    };
    let dir = PathBuf::from(dir);
    fs::create_dir_all(&dir).expect("create dir");
    let text = fs::read_to_string(&cases_path)
        .unwrap_or_else(|error| panic!("cannot read case file {cases_path:?}: {error}"));

    let document = parse(
        text.as_bytes(),
        JsonProfile::StrictV1,
        ParseLimits::default(),
    )
    .expect("differential case file must form a strict JSON document");
    let request = ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
        .build()
        .expect("fixed projection request");
    let root = match document.project(&request) {
        ProjectionResult::Complete(result) => result.value,
        ProjectionResult::Failed(attempt) => {
            eprintln!("case file projection failed: {attempt:?}");
            std::process::exit(1);
        }
    };
    let root_object = root.as_object().expect("case file root object");
    let manifest = object_field(root_object, "manifest")
        .and_then(PortableValue::as_string)
        .expect("manifest field");
    if manifest != "consema.differential.protocol-exchange@1" {
        eprintln!("unexpected case file manifest {manifest:?}");
        std::process::exit(1);
    }
    let cases = object_field(root_object, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");

    let mut failures = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for case in cases {
        let fields = case.as_object().expect("case object");
        let id = object_string(fields, "id").to_owned();
        let record = object_string(fields, "record").to_owned();
        let json_text = object_string(fields, "json").to_owned();
        let expected = object_field(fields, "expected")
            .and_then(PortableValue::as_object)
            .and_then(|entries| object_field(entries, "error_code"))
            .and_then(PortableValue::as_string)
            .unwrap_or_default()
            .to_owned();

        if verify {
            if expected.is_empty() {
                match verify_accept(&id, &record, &json_text, &dir) {
                    Ok(()) => accepted += 1,
                    Err(error) => failures.push(format!("case {id}: {error}")),
                }
            } else {
                match read_error_file(&dir, &id) {
                    Ok(code) if code == expected => rejected += 1,
                    Ok(code) => failures.push(format!(
                        "case {id}: rejection codes diverge: Go {code}, Rust-want {expected}"
                    )),
                    Err(error) => failures.push(format!("case {id}: {error}")),
                }
            }
            continue;
        }

        if expected.is_empty() {
            match emit_accept(&id, &record, &json_text, &dir) {
                Ok(()) => accepted += 1,
                Err(error) => failures.push(format!("case {id}: {error}")),
            }
        } else {
            match emit_reject(&id, &record, &json_text, &expected, &dir) {
                Ok(()) => rejected += 1,
                Err(error) => failures.push(format!("case {id}: {error}")),
            }
        }
    }
    println!(
        "emit_protocol_exchange ({}): {accepted} accept cases and {rejected} reject cases verified into {:?}",
        if verify { "verify" } else { "emit" },
        dir
    );
    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("{failure}");
        }
        eprintln!("failed cases: {}", failures.len());
        std::process::exit(1);
    }
}

/// Emits the Rust encoder's bytes for one accept case and verifies the
/// record round-trips byte-identically on both transports.
fn emit_accept(id: &str, record: &str, json_text: &str, dir: &PathBuf) -> Result<(), String> {
    let value = decode_json(json_text.as_bytes(), ProtocolLimits::default())
        .map_err(|error| format!("transport decode failed: {error}"))?;
    let record_value =
        decode_record(record, &value).map_err(|error| format!("record decode failed: {error}"))?;
    let json_bytes = encode_json(&record_value, ProtocolLimits::default())
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    if json_bytes != json_text.as_bytes() {
        return Err("record re-encode is not byte-identical to the case json".to_owned());
    }
    let pvce_bytes = encode_pvce(&record_value, ProtocolLimits::default())
        .map_err(|error| format!("PVCE encode failed: {error}"))?;
    write_hex(dir, &format!("{id}.json"), &json_bytes)?;
    write_hex(dir, &format!("{id}.pvce"), &pvce_bytes)?;
    Ok(())
}

/// Verifies one accept case in the Go-encode -> Rust-decode direction: the
/// Go bytes decode under the Rust typed record decoder to a record
/// equivalent to the case record and re-encode byte-identically.
fn verify_accept(id: &str, record: &str, json_text: &str, dir: &PathBuf) -> Result<(), String> {
    let case_value = decode_json(json_text.as_bytes(), ProtocolLimits::default())
        .map_err(|error| format!("case transport decode failed: {error}"))?;
    let case_record = decode_record(record, &case_value)
        .map_err(|error| format!("case record decode failed: {error}"))?;
    let go_json = read_hex(dir, &format!("{id}.json"))?;
    let go_pvce = read_hex(dir, &format!("{id}.pvce"))?;

    let json_value = decode_json(&go_json, ProtocolLimits::default())
        .map_err(|error| format!("Go JSON bytes do not decode: {error}"))?;
    let json_record = decode_record(record, &json_value)
        .map_err(|error| format!("Go JSON record decode failed: {error}"))?;
    if json_record != case_record {
        return Err("Go JSON bytes decode to a different record than the case".to_owned());
    }
    let re_json = encode_json(&json_record, ProtocolLimits::default())
        .map_err(|error| format!("Go JSON re-encode failed: {error}"))?;
    if re_json != go_json {
        return Err("Go JSON bytes do not re-encode byte-identically".to_owned());
    }

    let pvce_value = decode_pvce(&go_pvce, ProtocolLimits::default())
        .map_err(|error| format!("Go PVCE bytes do not decode: {error}"))?;
    let pvce_record = decode_record(record, &pvce_value)
        .map_err(|error| format!("Go PVCE record decode failed: {error}"))?;
    if pvce_record != case_record {
        return Err("Go PVCE bytes decode to a different record than the case".to_owned());
    }
    let re_pvce = encode_pvce(&pvce_record, ProtocolLimits::default())
        .map_err(|error| format!("Go PVCE re-encode failed: {error}"))?;
    if re_pvce != go_pvce {
        return Err("Go PVCE bytes do not re-encode byte-identically".to_owned());
    }
    Ok(())
}

/// Verifies one reject case in emit mode: the Rust decoder must reject the
/// case JSON with exactly the expected code, which is recorded for the Go
/// side.
fn emit_reject(
    id: &str,
    record: &str,
    json_text: &str,
    expected: &str,
    dir: &PathBuf,
) -> Result<(), String> {
    let code = rejection_code(record, json_text)?;
    if code != expected {
        return Err(format!(
            "rejection code {code} != expected {expected} (both sides must agree)"
        ));
    }
    fs::write(dir.join(format!("{id}.error.txt")), format!("{code}\n"))
        .map_err(|error| format!("cannot write rejection file: {error}"))?;
    Ok(())
}

/// Runs the transport and typed record decoders and returns the registered
/// rejection code of one reject case.
fn rejection_code(record: &str, json_text: &str) -> Result<String, String> {
    match decode_json(json_text.as_bytes(), ProtocolLimits::default()) {
        Ok(value) => match decode_record(record, &value) {
            Ok(_) => Err("record must be rejected, but the Rust codec accepted it".to_owned()),
            Err(error) => Ok(error.kind().code().to_owned()),
        },
        Err(error) => Ok(error.kind().code().to_owned()),
    }
}

/// Dispatches one record schema to its full typed record decoder and returns
/// the record's re-encodeable value tree. The dispatch mirrors the
/// payload.rs validate_registered_payload table; the typed decode
/// re-validates every cross constraint. core.portable-value-json@1 has no
/// record-level decoder: the transported value is the record.
fn decode_record(record: &str, value: &PortableValue) -> Result<PortableValue, ProtocolError> {
    match record {
        "core.cli-output@1" => CliOutputMessage::from_value(value).map(|m| m.to_value()),
        "core.batch-plan@1" => BatchPlanMessage::from_value(value).and_then(|m| {
            m.to_value().map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorKind::InvalidValue,
                    "$.files",
                    error.to_string(),
                )
            })
        }),
        "core.batch-result@1" => BatchResultMessage::from_value(value).map(|m| m.to_value()),
        "core.cancellation-request@1" => {
            CancellationRequest::from_value(value).map(|m| m.to_value())
        }
        "core.capability-declaration@1" => {
            CapabilityDeclaration::from_value(value).map(|m| m.to_value())
        }
        "core.change-set@1" => ChangeSetMessage::from_value(value).map(|m| m.to_value()),
        "core.completion@1" => Completion::from_value(value).map(|m| m.to_value()),
        "core.diagnostic@1" => {
            DiagnosticMessage::from_value_with_registry(value, ErrorCodeRegistry::v7())
                .map(|m| m.to_value())
        }
        "core.error-code-registry@1" => {
            validate_error_code_manifest_value(value)?;
            Ok(value.clone())
        }
        "core.execution-policy@1" => ExecutionPolicy::from_value(value).map(|m| m.to_value()),
        "core.graph-projection-result@1" => {
            GraphProjectionResultMessage::from_value(value).map(|m| m.to_value())
        }
        "core.graph-provenance-map@1" => {
            GraphProvenanceMapMessage::from_value(value).map(|m| m.to_value())
        }
        "core.graph-query-result@1" => {
            GraphQueryResultMessage::from_value(value).map(|m| m.to_value())
        }
        "core.ini-query-result@1" => IniQueryResultMessage::from_value(value).map(|m| m.to_value()),
        "core.java-properties-query-result@1" => {
            JavaPropertiesQueryResultMessage::from_value(value).map(|m| m.to_value())
        }
        "core.java-utf16-string@1" => {
            JavaUtf16String::from_value(value, ProtocolLimits::default()).map(|m| m.to_value())
        }
        "core.materialization-request@2" => MaterializationRequestMessageV2::from_value(value)
            .and_then(|m| {
                m.to_value().map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorKind::InvalidValue,
                        "$.style",
                        error.to_string(),
                    )
                })
            }),
        "core.materialization-result@2" => {
            // The Go default registry for this record is v6; mirror it.
            MaterializationResultMessageV2::from_value_with_registry(value, ErrorCodeRegistry::v6())
                .map(|m| m.to_value())
        }
        "core.portable-graph@1" => {
            PortableGraphMessage::from_value(value, PgceLimits::default()).map(|m| m.to_value())
        }
        "core.portable-value-json@1" => Ok(value.clone()),
        "core.profile-descriptor@1" => ProfileDescriptor::from_value(value).map(|m| m.to_value()),
        "core.projection-report@1" => {
            ProjectionReportMessage::from_value(value).map(|m| m.to_value())
        }
        "core.projection-request@1" => {
            ProjectionRequestMessage::from_value(value).map(|m| m.to_value())
        }
        "core.projection-result@1" => {
            ProjectionResultMessage::from_value(value).map(|m| m.to_value())
        }
        "core.provenance-map@1" => ProvenanceMapMessage::from_value(value).map(|m| m.to_value()),
        "core.query-definition@1" => QueryDefinition::from_protocol_value(value)
            .map_err(|failure| {
                ProtocolError::new(
                    ProtocolErrorKind::InvalidValue,
                    "$.payload",
                    format!("invalid query definition: {failure:?}"),
                )
            })
            .and_then(|definition| {
                definition.to_protocol_value().map_err(|failure| {
                    ProtocolError::new(
                        ProtocolErrorKind::InvalidValue,
                        "$.payload",
                        format!("invalid query definition: {failure:?}"),
                    )
                })
            }),
        "core.query-result@1" => QueryResultMessage::from_value(value).map(|m| m.to_value()),
        "core.registry-manifest@1" => RegistryManifest::from_value(value).map(|m| m.to_value()),
        "core.source-encoding@1" => SourceEncodingMessage::from_value(value).map(|m| m.to_value()),
        "core.source-patch@2" => {
            SourcePatchMessageV2::from_value(value, SourcePatchLimits::default()).and_then(|m| {
                m.to_value().map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorKind::InvalidValue,
                        "$.replacements",
                        error.to_string(),
                    )
                })
            })
        }
        "core.source-snapshot@2" => {
            SourceSnapshotMessageV2::from_value(value, SourceLimits::default())
                .map(|m| m.to_value())
        }
        "core.yaml-query-result@1" => {
            YamlQueryResultMessage::from_value(value).map(|m| m.to_value())
        }
        other => Err(ProtocolError::new(
            ProtocolErrorKind::UnknownContract,
            "$.contract",
            format!("record {other} is not in the exchange inventory"),
        )),
    }
}

/// Writes one hex-encoded byte file.
fn write_hex(dir: &PathBuf, name: &str, bytes: &[u8]) -> Result<(), String> {
    fs::write(dir.join(format!("{name}.hex")), format!("{}\n", hex(bytes)))
        .map_err(|error| format!("cannot write {name}.hex: {error}"))
}

/// Reads and hex-decodes one byte file.
fn read_hex(dir: &PathBuf, name: &str) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(dir.join(format!("{name}.hex")))
        .map_err(|error| format!("missing Go byte file {name}.hex: {error}"))?;
    let text = text.trim();
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < text.len() {
        let pair = text
            .get(index..index + 2)
            .ok_or_else(|| format!("Go byte file {name}.hex is not valid hex"))?;
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| format!("Go byte file {name}.hex is not valid hex"))?,
        );
        index += 2;
    }
    Ok(bytes)
}

/// Reads one recorded rejection code file.
fn read_error_file(dir: &PathBuf, id: &str) -> Result<String, String> {
    fs::read_to_string(dir.join(format!("{id}.error.txt")))
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("missing rejection file {id}.error.txt: {error}"))
}

/// Reads one string field of an object (the runner's `object_string`).
fn object_string<'a>(entries: &'a [consema_core::ObjectEntry], key: &str) -> &'a str {
    object_field(entries, key)
        .and_then(PortableValue::as_string)
        .unwrap_or_else(|| panic!("missing string field {key:?}"))
}

/// Reads one field of an object (the runner's `object_field`,
/// crates/consema-conformance/src/lib.rs:195-203).
fn object_field<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Option<&'a PortableValue> {
    entries
        .iter()
        .find(|entry| entry.key() == key)
        .map(consema_core::ObjectEntry::value)
}

/// Lowercase hex of the bytes (the runner's `hex`,
/// crates/consema-conformance/src/lib.rs:377-386).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, octet| {
        write!(output, "{octet:02x}").expect("String write");
        output
    })
}
