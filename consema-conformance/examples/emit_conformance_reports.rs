//! emit_conformance_reports — shared dual-runner conformance orchestration
//! support (milestone 0.19.0 G5.1; docs/go-implementation-plan.md §2.6,
//! §4.1 and §4.5; roadmap §16.6 line 1547).
//!
//! Runs every one of the 18 frozen language-neutral vector suites through
//! the reference runner's `run_*` entry points (each executes its embedded
//! `conformance/vectors` file) and emits the case-level verdicts as one
//! shared report document `<outdir>/shared-conformance.json` in the
//! `consema.shared-conformance@1` contract: `schema`, `runner` ("rust"),
//! and `suites[]` with `file` (vector basename), `suite` id, `passed` ids,
//! `skipped` (the Rust runner has no skip concept, so always empty), and
//! `failed` `{id, message}` records. The Go runner's orchestration report
//! hook (`go/conformance/shared.go`) emits the identical shape, so the
//! orchestrator (`scripts/go-verify-shared-conformance.ps1`) can compare
//! the two runners case by case.
//!
//! Why this example exists (justification): the dual-runner contract (§4.1)
//! requires case-id-level agreement between the Rust and Go runners, and no
//! existing entry point prints the reference runner's per-case verdicts for
//! all 18 suites — the cargo-test pins assert whole-suite
//! conformant/not-conformant only, and the `consema conformance` CLI
//! command is the embedded self-check subset, not the 18 shared suites
//! (crates/consema/src/bin/consema/conformance_cmd.rs). This example reuses
//! the published `run_*` entry points and consema-json materialization only
//! — no new execution or encoding logic — and adds no dependency.
//!
//! Usage: `emit_conformance_reports <out-dir>`
//! Exit code 0 = all 18 suites executed and the report written; 1 = a suite
//! failed or the report could not be materialized or written; 2 = usage
//! error.

use std::env;
use std::fs;
use std::path::PathBuf;

use consema_conformance::{
    ConformanceReport, run_cli_v1, run_hcl_v1, run_ini_v1, run_json_family_v2, run_operations_v1,
    run_plist_v1, run_portable_graph_v1, run_properties_v1, run_protocol_v1, run_protocol_v2,
    run_semantic_model_v5, run_semantic_model_v6, run_source_v1, run_syntax_query_v1, run_toml_v1,
    run_v1, run_xml_v1, run_yaml_v1,
};
use consema_core::{ObjectBuilder, PortableValue, SequenceBuilder};
use consema_document::{
    MaterializationLimits, MaterializationRequest, MaterializationResult, MaterializationStyleId,
    NewlinePolicy, ProfileId,
};
use consema_json::materialize;

/// One frozen (vector file basename, suite entry point) pair.
type SuiteEntry = (&'static str, fn() -> ConformanceReport);

/// The frozen 18-suite inventory in the fc-manifest order (the Go runner's
/// `allSuites` mirror, go/conformance/conformance.go:174-193).
const SUITES: &[SuiteEntry] = &[
    ("v1.json", run_v1),
    ("toml-v1.json", run_toml_v1),
    ("protocol-v1.json", run_protocol_v1),
    ("source-v1.json", run_source_v1),
    ("syntax-query-v1.json", run_syntax_query_v1),
    ("protocol-v2.json", run_protocol_v2),
    ("operations-v1.json", run_operations_v1),
    ("json-family-v2.json", run_json_family_v2),
    ("portable-graph-v1.json", run_portable_graph_v1),
    ("semantic-model-v5.json", run_semantic_model_v5),
    ("yaml-v1.json", run_yaml_v1),
    ("semantic-model-v6.json", run_semantic_model_v6),
    ("ini-v1.json", run_ini_v1),
    ("java-properties-v1.json", run_properties_v1),
    ("xml-1-0-safe-v1.json", run_xml_v1),
    ("plist-v1.json", run_plist_v1),
    ("hcl-v1.json", run_hcl_v1),
    ("cli-v1.json", run_cli_v1),
];

/// The frozen shared report contract identifier (the Go hook's mirror).
const SHARED_SCHEMA: &str = "consema.shared-conformance@1";

fn main() {
    let mut args = env::args().skip(1);
    let Some(out_dir) = args.next() else {
        eprintln!("usage: emit_conformance_reports <out-dir>");
        std::process::exit(2);
    };
    let out_dir = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir).expect("create out-dir");

    let mut suites = SequenceBuilder::new();
    let mut failed_suites = Vec::new();
    for (file, run) in SUITES {
        let report = run();
        suites.push(suite_value(file, &report));
        if !report.is_conformant() {
            failed_suites.push((*file).to_owned());
        }
    }

    let mut root = ObjectBuilder::new();
    root.insert("schema", PortableValue::string(SHARED_SCHEMA))
        .expect("schema key is unique");
    root.insert("runner", PortableValue::string("rust"))
        .expect("runner key is unique");
    root.insert("suites", suites.build())
        .expect("suites key is unique");

    let request = MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new("json.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None)
    .with_limits(MaterializationLimits::default());
    let bytes = match materialize(&root.build(), &request) {
        MaterializationResult::Complete(complete) => complete.document.render().to_vec(),
        MaterializationResult::Failed(attempt) => {
            eprintln!("shared report materialization failed: {attempt:?}");
            std::process::exit(1);
        }
    };
    fs::write(out_dir.join("shared-conformance.json"), bytes)
        .unwrap_or_else(|error| panic!("cannot write the shared report: {error}"));
    println!(
        "emit_conformance_reports: {} suites written to {}",
        SUITES.len(),
        out_dir.display()
    );
    if !failed_suites.is_empty() {
        eprintln!("failed suites: {failed_suites:?}");
        std::process::exit(1);
    }
}

/// Builds one suite entry of the shared report contract from the runner's
/// report.
fn suite_value(file: &str, report: &ConformanceReport) -> PortableValue {
    let mut passed = SequenceBuilder::new();
    for id in &report.passed {
        passed.push(PortableValue::string(id.as_str()));
    }
    let mut failed = SequenceBuilder::new();
    for (id, message) in &report.failed {
        let mut item = ObjectBuilder::new();
        item.insert("id", PortableValue::string(id.as_str()))
            .expect("id key is unique");
        item.insert("message", PortableValue::string(message.as_str()))
            .expect("message key is unique");
        failed.push(item.build());
    }

    let mut suite = ObjectBuilder::new();
    suite
        .insert("file", PortableValue::string(file))
        .expect("file key is unique");
    suite
        .insert("suite", PortableValue::string(report.suite.as_str()))
        .expect("suite key is unique");
    suite
        .insert("passed", passed.build())
        .expect("passed key is unique");
    suite
        .insert("skipped", SequenceBuilder::new().build())
        .expect("skipped key is unique");
    suite
        .insert("failed", failed.build())
        .expect("failed key is unique");
    suite.build()
}
