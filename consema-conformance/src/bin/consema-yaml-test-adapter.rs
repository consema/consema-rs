//! Official yaml-test-suite acceptance and byte-roundtrip adapter.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use consema_document::FormationStatus;
use consema_yaml::{YamlProfile, parse};

const EXPECTED_COMMIT: &str = "6e6c296ae9c9d2d5c4134b4b64d01b29ac19ff6f";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expectation {
    Accept,
    Reject,
}

#[derive(Debug)]
struct Case {
    id: String,
    directory: PathBuf,
    expectation: Expectation,
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let suite_root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: consema-yaml-test-adapter SUITE_ROOT REPORT_TSV")?;
    let report_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: consema-yaml-test-adapter SUITE_ROOT REPORT_TSV")?;
    if arguments.next().is_some() {
        return Err("unexpected arguments".to_owned());
    }

    let cases = discover_cases(&suite_root)?;
    let mut report = String::from("case_id\texpectation\tprofile\tstatus\treason\n");
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    let mut excluded = 0_usize;
    let mut failures = Vec::new();
    for case in &cases {
        let source = fs::read(case.directory.join("in.yaml"))
            .map_err(|error| format!("{}: cannot read in.yaml: {error}", case.id))?;
        let profile = profile_for_source(&source);
        let exclusion = exclusion_reason(&source);
        let result = parse(
            source.clone(),
            profile,
            consema_document::ParseLimits::default(),
        );
        let (passed, status, reason) = match (case.expectation, result, exclusion) {
            (_, Err(error), Some(reason))
                if error
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "yaml.profile.version-directive@1") =>
            {
                excluded += 1;
                (true, "excluded", reason.to_owned())
            }
            (_, Ok(_), Some(_)) => (
                false,
                "failed",
                "profile-contract-exclusion-was-accepted".to_owned(),
            ),
            (_, Err(error), Some(_)) => (
                false,
                "failed",
                format!("profile-contract-exclusion-had-wrong-failure:{error:?}"),
            ),
            (Expectation::Accept, Ok(document), None)
                if document.formation_status() == FormationStatus::Complete
                    && document.render() == source =>
            {
                accepted += 1;
                (true, "passed", "accepted-complete-byte-exact".to_owned())
            }
            (Expectation::Accept, Ok(_), None) => (
                false,
                "failed",
                "accepted-with-incomplete-or-changed-source".to_owned(),
            ),
            (Expectation::Accept, Err(error), None) => {
                (false, "failed", format!("valid-input-rejected:{error:?}"))
            }
            (Expectation::Reject, Err(_), None) => {
                rejected += 1;
                (
                    true,
                    "passed",
                    "invalid-input-rejected-atomically".to_owned(),
                )
            }
            (Expectation::Reject, Ok(_), None) => {
                (false, "failed", "invalid-input-accepted".to_owned())
            }
        };
        let profile_name = match profile {
            YamlProfile::Yaml12CoreV1 => "yaml.1.2-core@1",
            YamlProfile::Yaml11CompatV1 => "yaml.1.1-compat@1",
        };
        let expectation = match case.expectation {
            Expectation::Accept => "accept",
            Expectation::Reject => "reject",
        };
        writeln!(
            report,
            "{}\t{}\t{}\t{}\t{}",
            case.id, expectation, profile_name, status, reason,
        )
        .expect("String write cannot fail");
        if !passed {
            failures.push(format!("{}: {reason}", case.id));
        }
    }
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create report directory: {error}"))?;
    }
    fs::write(&report_path, report)
        .map_err(|error| format!("cannot write {}: {error}", report_path.display()))?;

    println!("yaml-test-suite data-2022-01-17 ({EXPECTED_COMMIT})");
    println!("cases: {}", cases.len());
    println!("valid accepted byte-exactly: {accepted}");
    println!("invalid rejected atomically: {rejected}");
    println!("profile-contract exclusions: {excluded}");
    println!("report: {}", report_path.display());
    if failures.is_empty() {
        println!("result: conformant");
        Ok(())
    } else {
        for failure in failures.iter().take(100) {
            eprintln!("FAILED {failure}");
        }
        Err(format!("{} yaml-test-suite cases failed", failures.len()))
    }
}

fn discover_cases(root: &Path) -> Result<Vec<Case>, String> {
    if !root.is_dir() {
        return Err(format!("suite root is not a directory: {}", root.display()));
    }
    let mut directories = vec![root.to_path_buf()];
    let mut cases = Vec::new();
    while let Some(directory) = directories.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        if entries.iter().any(|entry| entry.file_name() == "in.yaml") {
            let relative = directory
                .strip_prefix(root)
                .map_err(|_| "case escaped suite root")?;
            let id = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let expectation = if directory.join("error").is_file() {
                Expectation::Reject
            } else {
                Expectation::Accept
            };
            cases.push(Case {
                id,
                directory,
                expectation,
            });
            continue;
        }
        for entry in entries.into_iter().rev() {
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect entry: {error}"))?;
            if file_type.is_dir()
                && !matches!(entry.file_name().to_str(), Some(".git" | "name" | "tags"))
            {
                directories.push(entry.path());
            }
        }
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    if cases.is_empty()
        || cases.windows(2).any(|pair| pair[0].id == pair[1].id)
        || cases.iter().any(|case| case.id.is_empty())
    {
        return Err("suite case discovery was empty or non-unique".to_owned());
    }
    Ok(cases)
}

fn profile_for_source(source: &[u8]) -> YamlProfile {
    let text = String::from_utf8_lossy(source);
    if text
        .lines()
        .filter_map(yaml_version_directive)
        .any(|version| version == "1.1")
    {
        YamlProfile::Yaml11CompatV1
    } else {
        YamlProfile::Yaml12CoreV1
    }
}

fn exclusion_reason(source: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(source);
    text.lines()
        .filter_map(yaml_version_directive)
        .find_map(|version| {
            (!matches!(version, "1.1" | "1.2"))
                .then_some("profile-contract-rejects-unsupported-YAML-version-directive")
        })
}

fn yaml_version_directive(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("%YAML")?;
    if !rest.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }
    rest.split('#').next()?.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_selection_is_only_driven_by_explicit_version() {
        assert_eq!(
            profile_for_source(b"%YAML 1.1\n---\nyes\n"),
            YamlProfile::Yaml11CompatV1
        );
        assert_eq!(profile_for_source(b"---\nyes\n"), YamlProfile::Yaml12CoreV1);
        assert_eq!(
            profile_for_source(b"%YAML  1.1 # comment\n---\n"),
            YamlProfile::Yaml11CompatV1
        );
        assert_eq!(
            exclusion_reason(b"%YAML 1.3\n---\n"),
            Some("profile-contract-rejects-unsupported-YAML-version-directive")
        );
    }
}
