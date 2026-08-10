//! emit_parity_bytes — cross-language PVCE/PGCE byte-parity harness support
//! (milestone 0.14.0 G0.5; docs/go-implementation-plan.md §4.4; roadmap
//! §16.1 hard gate: "Rust 与 Go 的 PVCE/PGCE bytes 完全一致").
//!
//! Reads the differential case file
//! (`go/conformance/differential/cases.json`) and emits the Rust reference
//! encoder's canonical bytes for every case as `<outdir>/<case-id>.hex`.
//! Orchestration: `scripts/go-verify-byte-parity.ps1`.
//!
//! Why this example exists (justification): the hard gate needs the Rust
//! encoder's bytes for a data-driven set of 40+ cases covering all fifteen
//! kinds, boundaries, and nesting. No existing entry point can encode
//! arbitrary values to PVCE/PGCE and print bytes (the CLI has no encode
//! command, and the cargo-test pins cover only in-code values), so a minimal
//! example is required. It reuses the published codecs only — no new
//! encoding logic — and adds no dependency: the case file is parsed with the
//! same consema-json strict parser the conformance runner uses.
//!
//! Usage: `emit_parity_bytes <cases.json> <out-dir>`
//! Exit code 0 = every case encoded and written; 1 = a case failed; 2 =
//! usage error.

use std::env;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

use consema_core::{BigInteger, PortableValue};
use consema_document::ParseLimits;
use consema_graph::{GraphBuilder, GraphLimits, GraphMappingEntry, encode_pgce};
use consema_json::{
    JsonProfile, ProjectionRequestBuilder, ProjectionResult, ProjectionTarget, parse,
};
use consema_protocol::{ProtocolLimits, decode_json};
use consema_pvce::{EncodeLimits, encode_bounded};

/// Emits one case's Rust encoder bytes as `<out-dir>/<case-id>.hex`.
fn main() {
    let mut args = env::args().skip(1);
    let (Some(cases_path), Some(out_dir)) = (args.next(), args.next()) else {
        eprintln!("usage: emit_parity_bytes <cases.json> <out-dir>");
        std::process::exit(2);
    };
    let out_dir = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir).expect("create out-dir");
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
    if manifest != "consema.differential.byte-parity@1" {
        eprintln!("unexpected case file manifest {manifest:?}");
        std::process::exit(1);
    }
    let cases = object_field(root_object, "cases")
        .and_then(PortableValue::as_sequence)
        .expect("cases field");

    let mut failures = Vec::new();
    let mut emitted = 0usize;
    for case in cases {
        let fields = case.as_object().expect("case object");
        let id = object_field(fields, "id")
            .and_then(PortableValue::as_string)
            .expect("case id")
            .to_owned();
        let codec = object_field(fields, "codec")
            .and_then(PortableValue::as_string)
            .expect("case codec")
            .to_owned();
        let bytes = match codec.as_str() {
            "pvce" => {
                let value_text = object_field(fields, "value")
                    .and_then(PortableValue::as_string)
                    .unwrap_or_else(|| panic!("case {id}: pvce case without a value"));
                let value = decode_json(value_text.as_bytes(), ProtocolLimits::default())
                    .unwrap_or_else(|error| panic!("case {id}: decode_json failed: {error}"));
                encode_bounded(&value, EncodeLimits::default())
                    .unwrap_or_else(|error| panic!("case {id}: PVCE encode failed: {error:?}"))
            }
            "pgce" => {
                let graph_value = object_field(fields, "graph")
                    .unwrap_or_else(|| panic!("case {id}: pgce case without a graph"));
                let graph = graph_from_value(graph_value)
                    .unwrap_or_else(|error| panic!("case {id}: graph build failed: {error}"));
                encode_pgce(&graph)
                    .unwrap_or_else(|error| panic!("case {id}: PGCE encode failed: {error}"))
            }
            other => {
                eprintln!("case {id}: unknown codec {other:?}");
                failures.push(id);
                continue;
            }
        };
        let hex_text = hex(&bytes);
        fs::write(out_dir.join(format!("{id}.hex")), format!("{hex_text}\n"))
            .unwrap_or_else(|error| panic!("case {id}: cannot write byte file: {error}"));
        emitted += 1;
    }
    println!(
        "emit_parity_bytes: {emitted} cases emitted into {}",
        out_dir.display()
    );
    if !failures.is_empty() {
        eprintln!("failed cases: {failures:?}");
        std::process::exit(1);
    }
}

/// Builds a PortableGraph from the neutral descriptor of the case file (the
/// mirror of the runner's `graph_from_value`,
/// crates/consema-conformance/src/portable_graph_v1.rs:235-309).
fn graph_from_value(value: &PortableValue) -> Result<consema_graph::PortableGraph, String> {
    let fields = value.as_object().ok_or("graph must be Object")?;
    let nodes = object_field(fields, "nodes")
        .and_then(PortableValue::as_sequence)
        .ok_or("graph.nodes must be Sequence")?;
    let roots = object_field(fields, "roots")
        .and_then(PortableValue::as_sequence)
        .ok_or("graph.roots must be Sequence")?;
    let mut builder = GraphBuilder::new(GraphLimits::default());
    let mut ids = Vec::with_capacity(nodes.len());
    for _ in nodes {
        ids.push(
            builder
                .reserve_node()
                .map_err(|error| format!("{error:?}"))?,
        );
    }
    for (index, node) in nodes.iter().enumerate() {
        let node_fields = node.as_object().ok_or("graph node must be Object")?;
        let kind = object_string(node_fields, "kind")?;
        let tag = object_string(node_fields, "tag")?;
        match kind {
            "Scalar" => {
                builder
                    .define_scalar(ids[index], tag, object_string(node_fields, "content")?)
                    .map_err(|error| format!("{error:?}"))?;
            }
            "Sequence" => {
                let items = object_field(node_fields, "items")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("sequence.items must be Sequence")?
                    .iter()
                    .map(|item| graph_reference(item, &ids))
                    .collect::<Result<Vec<_>, _>>()?;
                builder
                    .define_sequence(ids[index], tag, items)
                    .map_err(|error| format!("{error:?}"))?;
            }
            "Mapping" => {
                let entries = object_field(node_fields, "entries")
                    .and_then(PortableValue::as_sequence)
                    .ok_or("mapping.entries must be Sequence")?
                    .iter()
                    .map(|entry| {
                        let entry = entry.as_object().ok_or("mapping entry must be Object")?;
                        Ok(GraphMappingEntry::new(
                            graph_reference(
                                object_field(entry, "key").ok_or("mapping entry key missing")?,
                                &ids,
                            )?,
                            graph_reference(
                                object_field(entry, "value")
                                    .ok_or("mapping entry value missing")?,
                                &ids,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                builder
                    .define_mapping(ids[index], tag, entries)
                    .map_err(|error| format!("{error:?}"))?;
            }
            _ => return Err("unknown graph node kind".to_owned()),
        }
    }
    for root in roots {
        builder
            .push_root(graph_reference(root, &ids)?)
            .map_err(|error| format!("{error:?}"))?;
    }
    builder.build().map_err(|error| format!("{error:?}"))
}

/// Resolves one neutral node index into its builder id (the runner's
/// `graph_reference`, portable_graph_v1.rs:311-322).
fn graph_reference(
    value: &PortableValue,
    ids: &[consema_graph::GraphNodeId],
) -> Result<consema_graph::GraphNodeId, String> {
    value
        .as_integer()
        .and_then(BigInteger::to_usize)
        .and_then(|index| ids.get(index).copied())
        .ok_or_else(|| "graph reference out of range".to_owned())
}

/// Reads one string field of an object (the runner's `object_string`).
fn object_string<'a>(
    entries: &'a [consema_core::ObjectEntry],
    key: &str,
) -> Result<&'a str, String> {
    object_field(entries, key)
        .and_then(PortableValue::as_string)
        .ok_or_else(|| format!("missing string field {key:?}"))
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
