//! Process-level regression tests for audit finding F1: without `--json`,
//! envelope-class failures (data/limit/precondition) must write **zero
//! bytes** to stdout (RFC 0015 §3.3 — stdout carries only command-result
//! data; all diagnostics go to stderr), while the exit code keeps the frozen
//! RFC 0015 §5 classification. Each human-mode test asserts stdout EMPTY +
//! the exact exit code + the stderr diagnostic; the `--json` sibling keeps
//! writing the byte-valid `core.cli-output@1` envelope (pinned here and by
//! the existing `--json` tests in `cli_skeleton.rs` and the bin unit tests).
//!
//! Launches the built binary via `env!("CARGO_BIN_EXE_consema")` (cargo
//! built-in; zero dev-dependencies, implementation plan §8.3).

use consema::protocol::{CliOutputMessage, ExitClass, ProtocolLimits};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_consema"))
        .args(args)
        .output()
        .expect("spawn the built consema binary")
}

fn status(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process terminated by a signal")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

/// One unique scratch path under the temp dir (missing-file tests need
/// provably absent paths; fixtures must not collide under the parallel test
/// runner).
fn scratch_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "consema-human-mode-{name}-{}-{}",
        std::process::id(),
        NEXT_PATH.fetch_add(1, Ordering::Relaxed)
    ));
    path
}

#[test]
fn inspect_missing_file_human_mode_keeps_stdout_empty() {
    let missing = scratch_path("inspect-missing");
    let output = run(&["inspect", missing.to_str().unwrap()]);
    assert_eq!(status(&output), 2, "cli.data.io@1 classifies as data");
    assert!(
        output.stdout.is_empty(),
        "human-mode failure must not write the machine envelope to stdout"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("consema: error: inspect:"), "{stderr}");
    assert!(stderr.contains("(code cli.data.io@1)"), "{stderr}");
}

#[test]
fn inspect_limit_budget_human_mode_keeps_stdout_empty() {
    let path = scratch_path("inspect-limit");
    std::fs::write(&path, b"value=1\n").expect("write fixture");
    let output = run(&["inspect", path.to_str().unwrap(), "--max-bytes", "4"]);
    assert_eq!(
        status(&output),
        3,
        "cli.limit.file-size@1 classifies as limit"
    );
    assert!(
        output.stdout.is_empty(),
        "human-mode limit failure must not write the machine envelope to stdout"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("(code cli.limit.file-size@1)"), "{stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn query_missing_request_file_human_mode_keeps_stdout_empty() {
    let missing = scratch_path("query-request");
    let output = run(&[
        "query",
        "--profile",
        "ini.portable",
        "--request-file",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 2, "unreadable request is cli.data.io@1");
    assert!(
        output.stdout.is_empty(),
        "human-mode failure must not write the machine envelope to stdout"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("consema: error: query:"), "{stderr}");
    assert!(stderr.contains("(code cli.data.io@1)"), "{stderr}");
}

#[test]
fn apply_missing_plan_human_mode_keeps_stdout_empty() {
    let missing = scratch_path("apply-plan");
    let output = run(&["apply", missing.to_str().unwrap()]);
    assert_eq!(status(&output), 2, "missing plan manifest is cli.data.io@1");
    assert!(
        output.stdout.is_empty(),
        "human-mode failure must not write the machine envelope to stdout"
    );
    let stderr = stderr_text(&output);
    assert!(stderr.contains("consema: error: apply:"), "{stderr}");
    assert!(stderr.contains("(code cli.data.io@1)"), "{stderr}");
}

#[test]
fn explain_unknown_id_human_mode_keeps_stdout_empty() {
    let output = run(&["explain", "example.unknown@1"]);
    assert_eq!(
        status(&output),
        2,
        "unknown id is cli.data.invalid-request@1"
    );
    assert!(
        output.stdout.is_empty(),
        "human-mode failure must not write the machine envelope to stdout"
    );
    let stderr = stderr_text(&output);
    assert!(
        stderr.contains("(code cli.data.invalid-request@1)"),
        "{stderr}"
    );
}

#[test]
fn json_failure_sibling_still_emits_the_envelope() {
    // The gate is human-mode-only: the same data failure under --json must
    // keep writing the byte-valid failure envelope (RFC 0015 §4.2).
    let missing = scratch_path("inspect-missing-json");
    let output = run(&["inspect", missing.to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 2, "cli.data.io@1 classifies as data");
    assert!(!output.stdout.is_empty(), "data failures carry an envelope");
    let envelope = CliOutputMessage::from_json(
        &output.stdout[..output.stdout.len() - 1],
        ProtocolLimits::default(),
    )
    .expect("byte-valid failure envelope");
    assert_eq!(envelope.exit_class(), ExitClass::Data);
    assert_eq!(envelope.diagnostics()[0].code, "cli.data.io@1");
    assert!(
        stderr_text(&output).contains("(code cli.data.io@1)"),
        "the stderr diagnostic stays in both modes"
    );
}

#[test]
fn human_mode_success_paths_keep_writing_result_data() {
    // The gate touches only failure emission: success paths in human mode
    // must keep writing their result data to stdout.
    let path = scratch_path("inspect-success");
    std::fs::write(&path, b"[section]\nvalue=1\n").expect("write fixture");
    let output = run(&["inspect", path.to_str().unwrap()]);
    assert_eq!(
        status(&output),
        0,
        "ambiguity fact report is a complete result"
    );
    assert!(
        !output.stdout.is_empty(),
        "human-mode success keeps its result report on stdout"
    );
    assert!(output.stderr.is_empty(), "success writes no diagnostics");
    let _ = std::fs::remove_file(&path);
}
