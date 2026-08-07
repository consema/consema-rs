//! Deterministic zero-dependency argument parsing for the `consema` binary.
//!
//! The parser is hand-written (implementation plan §5.1; clap and its
//! transitive dependencies are rejected under the workspace dependency
//! policy). The surface is the 11 frozen commands of RFC 0015 §6.1 plus a
//! small closed flag set. Every rejection is a frozen usage-class failure:
//! unknown commands and abbreviations, unknown flags, duplicate flags,
//! missing or invalid values, and missing required arguments (RFC 0015 §5.1
//! usage row). There is no prefix guessing, no shell semantics, and no
//! ambiguity: identical argument vectors always parse identically.
//!
//! Flag conventions (deterministic): long flags only; values via
//! `--flag value` or `--flag=value`; `--` ends flag parsing and makes every
//! following token a positional (the only way to pass dash-prefixed
//! positionals); a flag value must be the next token and must not itself
//! look like a flag (dash-prefixed values require the `=` form). Non-UTF-8
//! arguments are rejected as usage errors (the wire path needs UTF-8
//! spellings; hardening coverage for non-UTF-8 file names is milestone M9).
//! Command-specific flags (`--request-file`, `--write`) are only valid after
//! their owning command; global flags are valid anywhere. `--help` and
//! `--version` skip post-scan semantic validation (positional counts,
//! required flags, `--pretty` without `--json`), but scan-time errors such
//! as an unknown command still fire.

use consema::protocol::CliCommand;

/// A fully parsed invocation, still missing nothing the dispatcher needs.
///
/// The flat boolean fields mirror the closed flag surface one-to-one
/// (`--json`, `--pretty`, `--help`, `--version`, `--show-secrets`,
/// `--write`); the pedantic bool-count lint is disabled because grouping
/// them would obscure the parser's determinism rather than clarify it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedArgs {
    /// Recognized RFC 0015 §6.1 command; `None` only with `--help`/`--version`.
    pub command: Option<CliCommand>,
    /// Positional arguments in command-line order (paths, plan files, ids).
    pub positionals: Vec<String>,
    /// Emit the machine envelope as one canonical JSON line on stdout.
    pub json: bool,
    /// Indent the envelope JSON (`--pretty`; only valid together with `--json`).
    pub pretty: bool,
    /// Explicit profile selection (`--profile` / `--format`).
    pub profile: Option<String>,
    /// Result or manifest write target (`--output`).
    pub output: Option<String>,
    /// Strict request input path (`--request-file`; query/project/materialize).
    pub request_file: Option<String>,
    /// Print the usage text instead of running anything.
    pub help: bool,
    /// Print the product version instead of running anything.
    pub version: bool,
    /// CLI-layer per-file read budget in bytes (`--max-bytes`, RFC 0015 §12).
    pub max_bytes: Option<u64>,
    /// CLI-layer batch file-count budget (`--max-files`, RFC 0015 §12).
    pub max_files: Option<u64>,
    /// Disable presentation-layer redaction (`--show-secrets`, RFC 0015 §11.3).
    pub show_secrets: bool,
    /// Extra key-name redaction patterns (`--redact-keys`, RFC 0015 §11.2).
    pub redact_keys: Option<String>,
    /// Authorize an edit commit (`--write`; edit only).
    pub write: bool,
}

impl ParsedArgs {
    fn empty() -> Self {
        Self {
            command: None,
            positionals: Vec::new(),
            json: false,
            pretty: false,
            profile: None,
            output: None,
            request_file: None,
            help: false,
            version: false,
            max_bytes: None,
            max_files: None,
            show_secrets: false,
            redact_keys: None,
            write: false,
        }
    }
}

/// One frozen usage-class parse failure (RFC 0015 §5.1 usage row).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// No command was given and no `--help`/`--version` was requested.
    MissingCommand,
    /// The first positional is not one of the 11 closed-set commands.
    UnknownCommand(String),
    /// A flag that is neither global nor allowed for the current command.
    UnknownArgument(String),
    /// A command-specific flag appeared without (or without permission of)
    /// its owning command.
    FlagNotAllowed {
        /// The flag without the leading dashes.
        flag: &'static str,
        /// The command in scope, if the flag came after one.
        command: Option<CliCommand>,
    },
    /// A value-taking flag was the last token (or its next token looks like
    /// a flag).
    MissingFlagValue(&'static str),
    /// A value-taking flag received the empty string.
    EmptyFlagValue(&'static str),
    /// A value-taking flag received a value of the wrong shape.
    InvalidFlagValue {
        /// The flag without the leading dashes.
        flag: &'static str,
        /// The offending value.
        value: String,
    },
    /// A required argument (a positional or `--profile`) is absent.
    MissingRequired(&'static str),
    /// More positionals than the command accepts.
    UnexpectedArgument(String),
    /// The same flag was given twice.
    DuplicateFlag(&'static str),
    /// `--profile` and `--format` were both given with different values.
    ConflictingProfile,
    /// `--pretty` without `--json`.
    PrettyWithoutJson,
    /// An argument is not valid UTF-8.
    NonUtf8Argument,
}

impl ParseError {
    /// The frozen `cli.usage.*` code of the failure (RFC 0015 §13.1).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCommand | Self::MissingRequired(_) => "cli.usage.missing-required@1",
            Self::UnknownCommand(_) => "cli.usage.unknown-command@1",
            Self::UnknownArgument(_) | Self::FlagNotAllowed { .. } => {
                "cli.usage.unknown-argument@1"
            }
            Self::EmptyFlagValue("profile" | "format") => "cli.usage.invalid-format@1",
            Self::MissingFlagValue(_)
            | Self::EmptyFlagValue(_)
            | Self::InvalidFlagValue { .. }
            | Self::UnexpectedArgument(_)
            | Self::DuplicateFlag(_)
            | Self::ConflictingProfile
            | Self::PrettyWithoutJson
            | Self::NonUtf8Argument => "cli.usage.invalid-argument@1",
        }
    }

    /// Deterministic human diagnostic for stderr.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::MissingCommand => "missing command (run 'consema --help')".to_owned(),
            Self::UnknownCommand(name) => format!("unknown command '{name}'"),
            Self::UnknownArgument(flag) => format!("unknown argument '{flag}'"),
            Self::FlagNotAllowed { flag, command } => match command {
                Some(command) => format!(
                    "flag '--{flag}' is not allowed for command '{}'",
                    command.name()
                ),
                None => format!("flag '--{flag}' is not valid before the command"),
            },
            Self::MissingFlagValue(flag) => format!("flag '--{flag}' requires a value"),
            Self::EmptyFlagValue(flag) => format!("flag '--{flag}' received an empty value"),
            Self::InvalidFlagValue { flag, value } => {
                format!("flag '--{flag}' received invalid value '{value}'")
            }
            Self::MissingRequired(what) => format!("missing required argument: {what}"),
            Self::UnexpectedArgument(argument) => format!("unexpected argument '{argument}'"),
            Self::DuplicateFlag(flag) => format!("duplicate flag '--{flag}'"),
            Self::ConflictingProfile => "conflicting --profile and --format values".to_owned(),
            Self::PrettyWithoutJson => "flag '--pretty' requires '--json'".to_owned(),
            Self::NonUtf8Argument => "argument is not valid UTF-8".to_owned(),
        }
    }
}

/// Static usage text (the version line is prepended by `main.rs`).
pub const HELP: &str = "\
Usage:
  consema [global options] <command> [args...]
  consema --help | --version

Commands (RFC 0015 §6.1):
  inspect        file facts (bytes/digest/encoding facts/candidate profiles)
  capabilities   facade capability inventory
  query          native/lossless query (request via --request-file or stdin)
  project        explicit projection request
  materialize    explicit materialization request
  convert        two-phase cross-format conversion
  edit           single-file structural edit (dry-run; --write commits)
  plan           batch plan manifest (read-only)
  apply          batch apply from a prior plan manifest; env injection seam
                 CONSEMA_APPLY_INTERRUPT_AFTER / CONSEMA_APPLY_WRITE_FAILURE
                 (documented in RFC 0015 §5.4; testing/CI only)
  conformance    embedded protocol self-check subset
  explain        authoritative contract/error-code/profile explanation

Global options:
  --json              emit the core.cli-output@1 machine envelope on stdout
  --pretty            indent the envelope JSON (requires --json)
  --profile <id>      explicit profile selection (required for parse-class
                      commands); --format is an alias
  --output <path>     result or manifest write target
  --request-file <path>  strict request input (query/project/materialize/
                         convert/edit/plan)
  --max-bytes <n>     CLI-layer per-file read budget in bytes
  --max-files <n>     CLI-layer batch file-count budget
  --redact-keys <glob>  extra redaction key-name patterns
  --show-secrets      reveal secret values (sole presentation opt-out)
  --write             commit an edit (edit only)
  --help              print this help and exit 0
  --version           print the product version and exit 0

Exit codes (RFC 0015 §5.1): 0 success, 1 usage, 2 data, 3 limit,
4 precondition, 5 internal; 6-255 reserved.
";

/// Parses one argument vector into a validated invocation.
///
/// Returns [`ParseError`] for every usage-class failure; the error carries
/// the frozen `cli.usage.*` code and a deterministic stderr message. No
/// abbreviation, prefix, or ordering ambiguity is ever accepted.
pub fn parse_args(args: &[String]) -> Result<ParsedArgs, ParseError> {
    let mut parsed = ParsedArgs::empty();
    let mut seen: Vec<&'static str> = Vec::new();
    let mut command: Option<CliCommand> = None;
    let mut end_of_flags = false;
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if end_of_flags {
            push_positional(&mut command, &mut parsed.positionals, token)?;
        } else if token == "--" {
            end_of_flags = true;
        } else if let Some(body) = token.strip_prefix("--") {
            let (name, inline_value) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (body, None),
            };
            parse_flag(
                name,
                inline_value,
                &mut parsed,
                &mut seen,
                &mut index,
                args,
                command,
            )?;
        } else if token.starts_with('-') && token.len() > 1 {
            // Single-dash tokens are never flags; there are no short options.
            return Err(ParseError::UnknownArgument(token.clone()));
        } else {
            push_positional(&mut command, &mut parsed.positionals, token)?;
        }
        index += 1;
    }
    finish(parsed, command)
}

fn push_positional(
    command: &mut Option<CliCommand>,
    positionals: &mut Vec<String>,
    token: &str,
) -> Result<(), ParseError> {
    if command.is_none() {
        *command = Some(
            CliCommand::parse(token).ok_or_else(|| ParseError::UnknownCommand(token.to_owned()))?,
        );
    } else {
        positionals.push(token.to_owned());
    }
    Ok(())
}

fn parse_flag(
    name: &str,
    inline_value: Option<String>,
    parsed: &mut ParsedArgs,
    seen: &mut Vec<&'static str>,
    index: &mut usize,
    args: &[String],
    command: Option<CliCommand>,
) -> Result<(), ParseError> {
    // Canonicalize the flag body to its static name so the error variants
    // can carry `&'static str`; anything else is an unknown argument.
    let flag: &'static str = match name {
        "help" => "help",
        "version" => "version",
        "json" => "json",
        "pretty" => "pretty",
        "show-secrets" => "show-secrets",
        "write" => "write",
        "profile" => "profile",
        "format" => "format",
        "output" => "output",
        "request-file" => "request-file",
        "redact-keys" => "redact-keys",
        "max-bytes" => "max-bytes",
        "max-files" => "max-files",
        _ => return Err(ParseError::UnknownArgument(format!("--{name}"))),
    };
    match flag {
        "help" => {
            mark_seen(seen, flag)?;
            parsed.help = true;
        }
        "version" => {
            mark_seen(seen, flag)?;
            parsed.version = true;
        }
        "json" => {
            mark_seen(seen, flag)?;
            reject_inline(flag, inline_value)?;
            parsed.json = true;
        }
        "pretty" => {
            mark_seen(seen, flag)?;
            reject_inline(flag, inline_value)?;
            parsed.pretty = true;
        }
        "show-secrets" => {
            mark_seen(seen, flag)?;
            reject_inline(flag, inline_value)?;
            parsed.show_secrets = true;
        }
        "write" => {
            mark_seen(seen, flag)?;
            reject_inline(flag, inline_value)?;
            command_specific_flag(flag, command)?;
            parsed.write = true;
        }
        "profile" | "format" => {
            mark_seen(seen, flag)?;
            let value = take_value(args, index, flag, inline_value)?;
            if value.is_empty() {
                return Err(ParseError::EmptyFlagValue(flag));
            }
            match &parsed.profile {
                None => parsed.profile = Some(value),
                Some(existing) if existing == &value => {}
                Some(_) => return Err(ParseError::ConflictingProfile),
            }
        }
        "output" | "request-file" | "redact-keys" => {
            mark_seen(seen, flag)?;
            if flag == "request-file" {
                command_specific_flag(flag, command)?;
            }
            let value = take_value(args, index, flag, inline_value)?;
            if value.is_empty() {
                return Err(ParseError::EmptyFlagValue(flag));
            }
            match flag {
                "output" => parsed.output = Some(value),
                "request-file" => parsed.request_file = Some(value),
                _ => parsed.redact_keys = Some(value),
            }
        }
        "max-bytes" | "max-files" => {
            mark_seen(seen, flag)?;
            let value = take_value(args, index, flag, inline_value)?;
            let budget = value
                .parse::<u64>()
                .map_err(|_| ParseError::InvalidFlagValue {
                    flag,
                    value: value.clone(),
                })?;
            if flag == "max-bytes" {
                parsed.max_bytes = Some(budget);
            } else {
                parsed.max_files = Some(budget);
            }
        }
        _ => unreachable!("flag body canonicalized to the closed set above"),
    }
    Ok(())
}

fn mark_seen(seen: &mut Vec<&'static str>, name: &'static str) -> Result<(), ParseError> {
    if seen.contains(&name) {
        return Err(ParseError::DuplicateFlag(name));
    }
    seen.push(name);
    Ok(())
}

fn reject_inline(flag: &'static str, inline_value: Option<String>) -> Result<(), ParseError> {
    if let Some(value) = inline_value {
        return Err(ParseError::InvalidFlagValue { flag, value });
    }
    Ok(())
}

fn take_value(
    args: &[String],
    index: &mut usize,
    flag: &'static str,
    inline_value: Option<String>,
) -> Result<String, ParseError> {
    if let Some(value) = inline_value {
        return Ok(value);
    }
    let Some(next) = args.get(*index + 1) else {
        return Err(ParseError::MissingFlagValue(flag));
    };
    if next.starts_with('-') && next.len() > 1 {
        return Err(ParseError::MissingFlagValue(flag));
    }
    *index += 1;
    Ok(next.clone())
}

fn command_specific_flag(
    flag: &'static str,
    command: Option<CliCommand>,
) -> Result<(), ParseError> {
    let allowed: &[CliCommand] = match flag {
        // convert's source is the positional path (RFC 0015 §6.1), but its
        // two-stage request (projection + materialization) arrives through
        // the same strict request input as the other request commands;
        // edit/plan (milestone M7) consume the cli.edit-request@1 operation
        // vocabulary through the same request input.
        "request-file" => &[
            CliCommand::Query,
            CliCommand::Project,
            CliCommand::Materialize,
            CliCommand::Convert,
            CliCommand::Edit,
            CliCommand::Plan,
        ],
        "write" => &[CliCommand::Edit],
        _ => return Ok(()),
    };
    if command.is_some_and(|command| allowed.contains(&command)) {
        Ok(())
    } else {
        Err(ParseError::FlagNotAllowed { flag, command })
    }
}

fn finish(mut parsed: ParsedArgs, command: Option<CliCommand>) -> Result<ParsedArgs, ParseError> {
    parsed.command = command;
    if parsed.help || parsed.version {
        // Help and version answer before semantic validation; scan-time
        // errors (unknown command/flag) already fired above. The recognized
        // command stays available for inspection.
        return Ok(parsed);
    }
    let Some(command) = parsed.command else {
        return Err(ParseError::MissingCommand);
    };
    if parsed.pretty && !parsed.json {
        return Err(ParseError::PrettyWithoutJson);
    }
    let (min_positionals, max_positionals, missing_message) = positional_bounds(command);
    if parsed.positionals.len() < min_positionals {
        return Err(ParseError::MissingRequired(missing_message));
    }
    if let Some(max) = max_positionals {
        if parsed.positionals.len() > max {
            return Err(ParseError::UnexpectedArgument(
                parsed.positionals[max].clone(),
            ));
        }
    }
    if parse_class_command(command) && parsed.profile.is_none() {
        return Err(ParseError::MissingRequired("--profile"));
    }
    Ok(parsed)
}

/// (minimum, maximum, message) positional contract of each command.
fn positional_bounds(command: CliCommand) -> (usize, Option<usize>, &'static str) {
    match command {
        CliCommand::Inspect | CliCommand::Edit => (1, Some(1), "a file path"),
        CliCommand::Capabilities
        | CliCommand::Conformance
        | CliCommand::Query
        | CliCommand::Project
        | CliCommand::Materialize => (0, Some(0), ""),
        CliCommand::Convert => (1, Some(1), "a source file path"),
        CliCommand::Plan => (1, None, "at least one file path"),
        CliCommand::Apply => (1, Some(1), "a plan manifest path"),
        CliCommand::Explain => (1, Some(2), "an explainable id (optionally with a kind)"),
    }
}

/// Commands that parse source documents and therefore demand an explicit
/// `--profile`/`--format` (RFC 0015 §7.2; missing = usage, never try-and-see).
fn parse_class_command(command: CliCommand) -> bool {
    matches!(
        command,
        CliCommand::Query
            | CliCommand::Project
            | CliCommand::Materialize
            | CliCommand::Convert
            | CliCommand::Edit
            | CliCommand::Plan
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<ParsedArgs, ParseError> {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        parse_args(&owned)
    }

    #[test]
    fn every_closed_set_command_parses_with_its_arguments() {
        let cases: &[(&str, &[&str])] = &[
            ("inspect", &["inspect", "app.conf"]),
            ("capabilities", &["capabilities"]),
            ("query", &["query", "--profile", "ini.portable"]),
            (
                "project",
                &[
                    "project",
                    "--profile",
                    "json.strict",
                    "--request-file",
                    "r.json",
                ],
            ),
            ("materialize", &["materialize", "--profile", "json.strict"]),
            (
                "convert",
                &["convert", "src.json", "--profile", "json.strict"],
            ),
            (
                "edit",
                &["edit", "app.conf", "--profile", "ini.portable", "--write"],
            ),
            (
                "plan",
                &[
                    "plan",
                    "a.conf",
                    "b.conf",
                    "--profile",
                    "ini.portable",
                    "--output",
                    "plan.json",
                ],
            ),
            ("apply", &["apply", "plan.json", "--output", "result.json"]),
            ("conformance", &["conformance"]),
            ("explain", &["explain", "error-code", "cli.data.io@1"]),
        ];
        for (name, args) in cases {
            let parsed = parse(args).unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let command = parsed.command.expect("command present");
            assert_eq!(command.name(), *name, "{name}");
        }
    }

    #[test]
    fn command_names_are_exact_and_abbreviations_are_rejected() {
        for name in ["ins", "inspectt", "capabil", "q", "conform", "pl"] {
            assert_eq!(
                parse(&[name]),
                Err(ParseError::UnknownCommand(name.to_owned()))
            );
        }
    }

    #[test]
    fn non_commands_are_rejected_including_detect_and_version() {
        // The RFC 0015 §6.1 closed set has 11 commands; "detect" (facts live
        // inside inspect) and "version" (surfaced as --version) are not
        // commands and must not parse.
        for name in ["frobnicate", "detect", "version", ""] {
            assert_eq!(
                parse(&[name]),
                Err(ParseError::UnknownCommand(name.to_owned()))
            );
        }
    }

    #[test]
    fn global_flags_parse_before_and_after_the_command() {
        let parsed = parse(&["--json", "conformance", "--pretty"]).unwrap();
        assert!(parsed.json);
        assert!(parsed.pretty);
        assert_eq!(parsed.command, Some(CliCommand::Conformance));
        let parsed = parse(&["--help"]).unwrap();
        assert!(parsed.help);
        assert_eq!(parsed.command, None);
        let parsed = parse(&["--version"]).unwrap();
        assert!(parsed.version);
        let parsed = parse(&["inspect", "app.conf", "--json"]).unwrap();
        assert!(parsed.json);
        assert_eq!(parsed.positionals, vec!["app.conf".to_owned()]);
    }

    #[test]
    fn help_and_version_skip_semantic_validation_but_not_scan_errors() {
        let parsed = parse(&["inspect", "--help"]).unwrap();
        assert!(parsed.help);
        assert_eq!(parsed.command, Some(CliCommand::Inspect));
        let parsed = parse(&["--help", "--pretty"]).unwrap();
        assert!(parsed.help);
        assert!(parsed.pretty);
        // Scan-time errors still fire: the unknown command precedes --help.
        assert_eq!(
            parse(&["frobnicate", "--help"]),
            Err(ParseError::UnknownCommand("frobnicate".to_owned()))
        );
    }

    #[test]
    fn missing_command_is_usage() {
        assert_eq!(parse(&[]), Err(ParseError::MissingCommand));
        assert_eq!(parse(&["--json"]), Err(ParseError::MissingCommand));
        assert_eq!(
            parse(&["--profile", "ini.portable"]),
            Err(ParseError::MissingCommand)
        );
    }

    #[test]
    fn unknown_arguments_and_single_dash_tokens_are_rejected() {
        assert_eq!(
            parse(&["--bogus"]),
            Err(ParseError::UnknownArgument("--bogus".to_owned()))
        );
        assert_eq!(
            parse(&["conformance", "--bogus"]),
            Err(ParseError::UnknownArgument("--bogus".to_owned()))
        );
        assert_eq!(
            parse(&["-x"]),
            Err(ParseError::UnknownArgument("-x".to_owned()))
        );
        // A lone dash is a positional, hence a command candidate.
        assert_eq!(
            parse(&["-"]),
            Err(ParseError::UnknownCommand("-".to_owned()))
        );
    }

    #[test]
    fn command_specific_flags_are_scoped_to_their_commands() {
        let parsed = parse(&["edit", "x.conf", "--profile", "ini.portable", "--write"]).unwrap();
        assert!(parsed.write);
        // Milestone M7: edit and plan consume the cli.edit-request@1
        // vocabulary through the same strict request input as the other
        // request commands.
        let parsed = parse(&[
            "edit",
            "x.conf",
            "--profile",
            "ini.portable",
            "--request-file",
            "r",
        ])
        .unwrap();
        assert_eq!(parsed.request_file.as_deref(), Some("r"));
        let parsed = parse(&[
            "plan",
            "a.conf",
            "--profile",
            "ini.portable",
            "--request-file",
            "r",
        ])
        .unwrap();
        assert_eq!(parsed.request_file.as_deref(), Some("r"));
        // inspect takes no request input.
        assert_eq!(
            parse(&["inspect", "x.conf", "--request-file", "r"]),
            Err(ParseError::FlagNotAllowed {
                flag: "request-file",
                command: Some(CliCommand::Inspect),
            })
        );
        assert_eq!(
            parse(&["query", "--write", "--profile", "x"]),
            Err(ParseError::FlagNotAllowed {
                flag: "write",
                command: Some(CliCommand::Query),
            })
        );
        assert_eq!(
            parse(&["--request-file", "r", "query", "--profile", "x"]),
            Err(ParseError::FlagNotAllowed {
                flag: "request-file",
                command: None,
            })
        );
    }

    #[test]
    fn missing_and_empty_flag_values_are_usage() {
        assert_eq!(
            parse(&["--profile"]),
            Err(ParseError::MissingFlagValue("profile"))
        );
        assert_eq!(
            parse(&["conformance", "--output"]),
            Err(ParseError::MissingFlagValue("output"))
        );
        assert_eq!(
            parse(&["--max-bytes"]),
            Err(ParseError::MissingFlagValue("max-bytes"))
        );
        // A value that looks like a flag is treated as a missing value.
        assert_eq!(
            parse(&["--profile", "--json", "conformance"]),
            Err(ParseError::MissingFlagValue("profile"))
        );
        assert_eq!(
            parse(&["--profile", ""]),
            Err(ParseError::EmptyFlagValue("profile"))
        );
        assert_eq!(
            parse(&["conformance", "--output", ""]),
            Err(ParseError::EmptyFlagValue("output"))
        );
    }

    #[test]
    fn equals_form_carries_dash_prefixed_values() {
        let parsed = parse(&["conformance", "--output=-weird.json"]).unwrap();
        assert_eq!(parsed.output.as_deref(), Some("-weird.json"));
        // Without the = form a dash-prefixed token is not a value.
        assert_eq!(
            parse(&["conformance", "--output", "-weird.json"]),
            Err(ParseError::MissingFlagValue("output"))
        );
        // Boolean flags never take inline values.
        assert_eq!(
            parse(&["--json=true", "conformance"]),
            Err(ParseError::InvalidFlagValue {
                flag: "json",
                value: "true".to_owned(),
            })
        );
    }

    #[test]
    fn numeric_flag_values_are_validated() {
        assert_eq!(
            parse(&["--max-bytes", "abc"]),
            Err(ParseError::InvalidFlagValue {
                flag: "max-bytes",
                value: "abc".to_owned(),
            })
        );
        let parsed = parse(&["--max-bytes", "0", "conformance"]).unwrap();
        assert_eq!(parsed.max_bytes, Some(0));
        assert_eq!(parsed.command, Some(CliCommand::Conformance));
        let parsed = parse(&["--max-bytes=64", "--max-files", "100", "conformance"]).unwrap();
        assert_eq!(parsed.max_bytes, Some(64));
        assert_eq!(parsed.max_files, Some(100));
    }

    #[test]
    fn duplicate_flags_are_rejected() {
        assert_eq!(
            parse(&["--json", "--json", "conformance"]),
            Err(ParseError::DuplicateFlag("json"))
        );
        assert_eq!(
            parse(&["--profile", "a", "--profile", "b", "inspect", "x"]),
            Err(ParseError::DuplicateFlag("profile"))
        );
    }

    #[test]
    fn profile_and_format_alias_conflicts_are_rejected() {
        assert_eq!(
            parse(&["--profile", "a", "--format", "b", "inspect", "x"]),
            Err(ParseError::ConflictingProfile)
        );
        let parsed = parse(&["--profile", "a", "--format", "a", "inspect", "x"]).unwrap();
        assert_eq!(parsed.profile.as_deref(), Some("a"));
    }

    #[test]
    fn pretty_requires_json() {
        assert_eq!(
            parse(&["conformance", "--pretty"]),
            Err(ParseError::PrettyWithoutJson)
        );
    }

    #[test]
    fn positional_bounds_are_enforced_per_command() {
        assert_eq!(
            parse(&["inspect"]),
            Err(ParseError::MissingRequired("a file path"))
        );
        assert_eq!(
            parse(&["inspect", "a", "b"]),
            Err(ParseError::UnexpectedArgument("b".to_owned()))
        );
        assert_eq!(
            parse(&["capabilities", "x"]),
            Err(ParseError::UnexpectedArgument("x".to_owned()))
        );
        assert_eq!(
            parse(&["plan"]),
            Err(ParseError::MissingRequired("at least one file path"))
        );
        let parsed = parse(&["plan", "a", "b", "--profile", "p"]).unwrap();
        assert_eq!(parsed.positionals, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            parse(&["apply"]),
            Err(ParseError::MissingRequired("a plan manifest path"))
        );
        assert_eq!(
            parse(&["apply", "a", "b"]),
            Err(ParseError::UnexpectedArgument("b".to_owned()))
        );
        assert_eq!(
            parse(&["explain"]),
            Err(ParseError::MissingRequired(
                "an explainable id (optionally with a kind)"
            ))
        );
        assert_eq!(
            parse(&["explain", "a", "b", "c"]),
            Err(ParseError::UnexpectedArgument("c".to_owned()))
        );
        assert_eq!(
            parse(&["convert"]),
            Err(ParseError::MissingRequired("a source file path"))
        );
        // Request commands take no positionals; the request arrives via
        // --request-file or stdin (RFC 0015 §3.2).
        assert_eq!(
            parse(&["query", "x.json", "--profile", "p"]),
            Err(ParseError::UnexpectedArgument("x.json".to_owned()))
        );
    }

    #[test]
    fn parse_class_commands_demand_an_explicit_profile() {
        for args in [
            &["query", "--request-file", "r.json"][..],
            &["project"][..],
            &["materialize"][..],
            &["convert", "src.json"][..],
            &["edit", "x.conf"][..],
            &["plan", "a.conf"][..],
        ] {
            assert_eq!(
                parse(args),
                Err(ParseError::MissingRequired("--profile")),
                "{args:?}"
            );
        }
        // inspect (facts only) and apply (manifest input) need no profile.
        let parsed = parse(&["inspect", "x.conf"]).unwrap();
        assert_eq!(parsed.command, Some(CliCommand::Inspect));
        let parsed = parse(&["apply", "plan.json"]).unwrap();
        assert_eq!(parsed.command, Some(CliCommand::Apply));
    }

    #[test]
    fn double_dash_ends_flag_parsing() {
        let parsed = parse(&["inspect", "--", "-weird"]).unwrap();
        assert_eq!(parsed.positionals, vec!["-weird".to_owned()]);
        // After --, every token is a positional, even flag-looking ones; the
        // first positional of "inspect" is the path.
        let parsed = parse(&["inspect", "--", "--json"]).unwrap();
        assert_eq!(parsed.positionals, vec!["--json".to_owned()]);
        assert!(!parsed.json);
        assert_eq!(
            parse(&["inspect", "--"]),
            Err(ParseError::MissingRequired("a file path"))
        );
    }

    #[test]
    fn every_usage_error_maps_to_a_frozen_cli_usage_code() {
        let errors = [
            ParseError::MissingCommand,
            ParseError::UnknownCommand("x".to_owned()),
            ParseError::UnknownArgument("--x".to_owned()),
            ParseError::FlagNotAllowed {
                flag: "write",
                command: None,
            },
            ParseError::MissingFlagValue("profile"),
            ParseError::EmptyFlagValue("profile"),
            ParseError::EmptyFlagValue("output"),
            ParseError::InvalidFlagValue {
                flag: "max-bytes",
                value: "x".to_owned(),
            },
            ParseError::MissingRequired("--profile"),
            ParseError::UnexpectedArgument("x".to_owned()),
            ParseError::DuplicateFlag("json"),
            ParseError::ConflictingProfile,
            ParseError::PrettyWithoutJson,
            ParseError::NonUtf8Argument,
        ];
        for error in errors {
            let code = error.code();
            assert!(code.starts_with("cli.usage."), "{error:?} -> {code}");
            assert!(!error.message().is_empty(), "{error:?}");
        }
    }

    #[test]
    fn non_utf8_arguments_are_rejected_at_collection() {
        let non_utf8 = crate::make_non_utf8_argument();
        let result = crate::collect_args([non_utf8]);
        assert_eq!(result, Err(ParseError::NonUtf8Argument));
        let ok = crate::collect_args(["a".into(), "b".into()]);
        assert_eq!(ok.unwrap(), vec!["a".to_owned(), "b".to_owned()]);
    }
}
