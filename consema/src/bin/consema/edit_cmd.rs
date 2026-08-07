//! `consema edit` (single-file dry-run) and the shared `cli.edit-request@1`
//! request vocabulary consumed by both the edit and the plan commands
//! (RFC 0015 §6.1 edit row; implementation plan §6 M7).
//!
//! The edit command is **dry-run only** in this milestone: parse the source
//! file under the `--profile` selection → build the format's typed
//! [`EditTransaction`] through the facade public API → `dry_run` → emit the
//! `cli.edit@1` payload record embedding the `core.edit-plan@1` record (whose
//! `core.source-patch@2` carries the exact replacement preconditions and the
//! target digest) and the `core.change-set@1` summary. `--write` is refused
//! as a usage error until milestone M8 wires the commit path through fsio
//! (the same refusal style milestone M5 uses for `--output` before fsio).
//!
//! # The request (`cli.edit-request@1`, CLI-local, not registered)
//!
//! The request arrives via `--request-file` or stdin as canonical tagged
//! JSON or PVCE/1 (RFC 0015 §3.2), strictly decoded; the source file is the
//! command's positional (the M3 args freeze: edit takes exactly one path),
//! and the profile is the `--profile` selection.
//!
//! ```text
//! cli.edit-request@1 (CLI-local, strict exact-fields decode):
//!   schema      String   "cli.edit-request@1" (first field)
//!   operations  [{
//!     operation  { id: String, version: Integer }   must be published by the
//!                                                   selected profile's facade
//!                                                   operation registry
//!     target     { kind: "document" | "section" | "entry",
//!                  ... per kind ... }               CLI-local stable locator
//!     arguments  { ... }                            exact per-operation fields
//!   }]
//! ```
//!
//! Target locators (deterministic, resolved against the parsed document):
//!
//! ```text
//! document:  { kind: "document" }
//! section:   { kind: "section", name: String, occurrence: Integer }
//!            the occurrence-th (0-based, source order) section with that name
//!            (the default section has the empty name)
//! entry:     { kind: "entry", section: String | null, key: String,
//!              occurrence: Integer }
//!            the occurrence-th entry (0-based, source order) in that section
//!            (null = the default section) with that key
//! ```
//!
//! The wired operation vocabulary is the frozen INI family surface
//! (consema-ini `format_operation_registry`): `ini.edit.replace-semantic-value@1`
//! (arguments `value`, `representation_policy`), `ini.edit.replace-literal-value@1`
//! (`literal`, lowercase hex), `ini.edit.remove-entry@1`, `ini.edit.rename-entry@1`
//! (`key`), `ini.edit.insert-section@1` (`name`, `placement`),
//! `ini.edit.remove-section@1`, `ini.edit.rename-section@1` (`name`), and
//! `ini.edit.insert-entry@1` (`key`, `value`, `placement`). `placement` is the
//! closed set {`start`, `end`}; anchor placement is not wired in this
//! milestone. Every operation id/version is validated against the facade's
//! per-profile operation registry (hard gate 1: the CLI declares no format
//! knowledge of its own; an id outside the registry is a data error).
//!
//! # Machine payload and failure algebra
//!
//! The `cli.edit@1` payload record of RFC 0015 §6.1:
//!
//! ```text
//! cli.edit@1:
//!   schema     "cli.edit@1"
//!   plan       core.edit-plan@1 record (embeds core.source-patch@2)
//!   change_set core.change-set@1 record
//!   committed  false (dry-run; --write is refused)
//! ```
//!
//! The change-set externalization re-commits the same validated transaction
//! in memory (the format crates prove the dry-run/commit equivalence of
//! replacements and target digest — implementation plan §6 M7); the commit
//! is a pure computation and never touches the filesystem.
//!
//! Failure classes: recovered base documents are data errors carrying the
//! format's own parse diagnostics (RFC 0015 §5.1); operations the request
//! vocabulary cannot express (other format families) are data errors
//! (`cli.data.invalid-request@1` — the closest registered code; the stderr
//! line explains the boundary); dry-run validation failures keep the
//! format's stable `core.edit.*` codes, which classify as precondition
//! (RFC 0015 §5.1 edit-conflict row). `--write`/`--output` are usage errors
//! (never an envelope, RFC 0015 §4.2).
//!
//! # Redaction in the human view
//!
//! The human view renders each operation's target locator and value-bearing
//! arguments through [`crate::redact`] (RFC 0015 §11): key and section names
//! matching the frozen patterns render as `$REDACTED$`, and value-bearing
//! arguments redact under the target entry's key name (conservative
//! direction). The machine payload is never redacted (RFC 0015 §8.3: the
//! patch bytes are apply's precondition facts; hard gate 3).

use crate::args::ParsedArgs;
use crate::query_cmd::{
    FlowError, emit_envelope, emit_failure, format_family, internal_failure, parse_document,
    protocol_error, read_request_bytes, read_source_capped, require_complete, resolve_profile,
    stable_failure,
};
use consema::core::{BigInteger, ObjectBuilder, PortableValue};
use consema::document::{AssociationPlacement, EditPlan, EditPlanSourceId, NodeRef, ProfileId};
use consema::ini::{self, EditTransaction, EditTransactionBuilder, RepresentationPolicy};
use consema::protocol::{
    ChangeSetMessage, CliCommand, DiagnosticMessage, EditPlanMessage, ErrorCodeRegistry, ExitClass,
    ProtocolLimits, decode_json, decode_pvce,
};
use std::io::Write;

use crate::redact::{RedactPolicy, redact_text};

/// The CLI-local edit-request schema shared by edit and plan.
pub(crate) const EDIT_REQUEST_SCHEMA: &str = "cli.edit-request@1";

/// One fully decoded strict edit request (`cli.edit-request@1`).
pub(crate) struct EditRequestInput {
    /// Resolved source profile (id and registry version).
    pub(crate) profile: ProfileId,
    /// Ordered operation requests.
    pub(crate) operations: Vec<OperationSpec>,
}

/// One decoded operation request (id/version validated against the facade
/// operation registry of the selected profile).
pub(crate) struct OperationSpec {
    /// Exact operation id (e.g. `ini.edit.replace-semantic-value`).
    pub(crate) id: String,
    /// Exact operation version.
    pub(crate) version: u32,
    /// CLI-local stable target locator.
    pub(crate) target: TargetLocator,
    /// Typed per-operation arguments.
    pub(crate) kind: OperationKind,
}

/// CLI-local stable target locator (RFC 0015 §8.2 `operations` target).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TargetLocator {
    /// The whole document (insert-section).
    Document,
    /// The occurrence-th section (0-based, source order) with the name.
    Section {
        /// Decoded section name (empty for the default section).
        name: String,
        /// Occurrence ordinal (0-based).
        occurrence: usize,
    },
    /// The occurrence-th entry (0-based, source order) with the key in the
    /// section.
    Entry {
        /// Section name, or `None` for the default section.
        section: Option<String>,
        /// Decoded entry key.
        key: String,
        /// Occurrence ordinal (0-based).
        occurrence: usize,
    },
}

/// Typed per-operation arguments of the wired INI vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OperationKind {
    /// `ini.edit.replace-semantic-value@1`.
    ReplaceSemanticValue {
        /// New stored string value.
        value: String,
        /// Explicit representation policy (never invented by the CLI).
        policy: RepresentationPolicy,
    },
    /// `ini.edit.replace-literal-value@1`.
    ReplaceLiteralValue {
        /// Exact replacement bytes.
        literal: Vec<u8>,
    },
    /// `ini.edit.remove-entry@1`.
    RemoveEntry,
    /// `ini.edit.rename-entry@1`.
    RenameEntry {
        /// New decoded key.
        key: String,
    },
    /// `ini.edit.insert-section@1`.
    InsertSection {
        /// New decoded section name.
        name: String,
        /// Placement among section occurrences.
        placement: AssociationPlacement,
    },
    /// `ini.edit.remove-section@1`.
    RemoveSection,
    /// `ini.edit.rename-section@1`.
    RenameSection {
        /// New decoded section name.
        name: String,
    },
    /// `ini.edit.insert-entry@1`.
    InsertEntry {
        /// New decoded entry key.
        key: String,
        /// Stored string value.
        value: String,
        /// Placement among direct entry occurrences.
        placement: AssociationPlacement,
    },
}

/// One per-file dry-run failure (never aborts a plan batch; RFC 0015 §8.2).
pub(crate) struct FilePlanFailure {
    /// Stable diagnostic code (format-owned codes pass through unchanged).
    pub(crate) code: String,
    /// Deterministic human message (stderr line).
    pub(crate) message: String,
    /// Ordered registry-bound envelope/manifest diagnostics.
    pub(crate) diagnostics: Vec<DiagnosticMessage>,
}

impl FilePlanFailure {
    /// An internal failure (unreachable state; the report names the file).
    fn internal(path: &str, message: impl Into<String>) -> Self {
        Self::from(FlowError::new(
            "cli.internal.unclassified@1",
            format!("{path}: {}", message.into()),
        ))
    }

    /// Back to the envelope failure form (the edit command's emit path).
    pub(crate) fn into_flow_error(self) -> FlowError {
        FlowError::new(self.code, self.message).with_diagnostics(self.diagnostics)
    }
}

impl From<FlowError> for FilePlanFailure {
    fn from(error: FlowError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            diagnostics: error.diagnostics,
        }
    }
}

/// One prepared per-file edit: the parsed document alive plus the validated
/// transaction (the edit command re-commits it in memory for the change-set
/// externalization; the plan command only dry-runs it).
pub(crate) struct PreparedEdit {
    /// The parsed facade document (INI).
    pub(crate) document: consema::Document,
    /// The typed INI edit transaction.
    pub(crate) transaction: EditTransaction,
}

/// One executed dry-run of one file.
pub(crate) struct DryRunResult {
    /// The SDK dry-run plan (replacements, digests, operation summaries).
    pub(crate) plan: EditPlan,
}

/// Reads, parses, complete-gates, and builds the typed INI transaction for
/// one file (the shared edit/plan per-file pipeline).
pub(crate) fn prepare_edit(
    input: &EditRequestInput,
    path: &str,
    parsed: &ParsedArgs,
) -> Result<PreparedEdit, FilePlanFailure> {
    let cap = parsed.max_bytes.unwrap_or_else(|| {
        u64::try_from(ProtocolLimits::default().max_bytes).expect("64 MiB fits u64")
    });
    let source = read_source_capped(path, cap)?;
    let document = parse_document(source, &input.profile)?;
    require_complete(&document, path)?;
    let ini_document = document.as_ini().map_err(|_| {
        FilePlanFailure::internal(path, "the parsed document is not an INI document")
    })?;
    let mut builder = EditTransactionBuilder::new(ini_document);
    for operation in &input.operations {
        apply_operation(&mut builder, ini_document, operation)?;
    }
    Ok(PreparedEdit {
        document,
        transaction: builder.build(),
    })
}

/// Dry-runs one prepared edit (the SDK's own dry-run/commit-equivalence
/// contract: the plan's replacements and target digest are exactly what a
/// future commit would write, implementation plan §6 M7).
pub(crate) fn dry_run_plan(
    prepared: &PreparedEdit,
    path: &str,
) -> Result<DryRunResult, FilePlanFailure> {
    let ini_document = prepared.document.as_ini().map_err(|_| {
        FilePlanFailure::internal(path, "the parsed document is not an INI document")
    })?;
    let source_id = EditPlanSourceId::new(path)
        .map_err(|_| FilePlanFailure::internal(path, "edit source id is invalid"))?;
    let plan = ini_document
        .dry_run(&prepared.transaction, source_id)
        .map_err(|failure| edit_failure(path, &failure))?;
    Ok(DryRunResult { plan })
}

/// Applies one operation request to the transaction builder.
///
/// Target resolution failures are `core.edit.target-not-found@1` — the SDK's
/// own stable code for exactly this condition (a target that does not exist
/// in the file), so the CLI never invents a code.
fn apply_operation(
    builder: &mut EditTransactionBuilder,
    document: &ini::Document,
    operation: &OperationSpec,
) -> Result<(), FilePlanFailure> {
    match &operation.kind {
        OperationKind::ReplaceSemanticValue { value, policy } => {
            builder.semantic_value(
                resolve_entry_target(document, &operation.target)?,
                value.as_str(),
                *policy,
            );
        }
        OperationKind::ReplaceLiteralValue { literal } => {
            builder.literal_value(
                resolve_entry_target(document, &operation.target)?,
                literal.as_slice(),
            );
        }
        OperationKind::RemoveEntry => {
            builder.remove_entry(resolve_entry_target(document, &operation.target)?);
        }
        OperationKind::RenameEntry { key } => {
            builder.rename_entry(
                resolve_entry_target(document, &operation.target)?,
                key.as_str(),
            );
        }
        OperationKind::InsertSection { name, placement } => {
            builder.insert_section(document.node_ref(), name.as_str(), *placement);
        }
        OperationKind::RemoveSection => {
            builder.remove_section(resolve_section_target(document, &operation.target)?);
        }
        OperationKind::RenameSection { name } => {
            builder.rename_section(
                resolve_section_target(document, &operation.target)?,
                name.as_str(),
            );
        }
        OperationKind::InsertEntry {
            key,
            value,
            placement,
        } => {
            builder.insert_entry(
                resolve_section_target(document, &operation.target)?,
                key.as_str(),
                value.as_str(),
                *placement,
            );
        }
    }
    Ok(())
}

/// Resolves the occurrence-th entry with the key in the section.
fn resolve_entry_target(
    document: &ini::Document,
    target: &TargetLocator,
) -> Result<NodeRef, FilePlanFailure> {
    let TargetLocator::Entry {
        section,
        key,
        occurrence,
    } = target
    else {
        return Err(FilePlanFailure::internal(
            "locator",
            "an entry operation requires an entry target",
        ));
    };
    let mut seen = 0usize;
    for entry in document.entries() {
        let entry_section = document.section(entry.section()).map_err(|_| {
            FilePlanFailure::internal("locator", "an entry references an unresolvable section")
        })?;
        let in_section = match section {
            None => entry_section.is_default(),
            Some(name) => entry_section.name() == name,
        };
        if in_section && entry.key() == key {
            if seen == *occurrence {
                return Ok(entry.node_ref());
            }
            seen += 1;
        }
    }
    Err(target_not_found(target))
}

/// Resolves the occurrence-th section with the name.
fn resolve_section_target(
    document: &ini::Document,
    target: &TargetLocator,
) -> Result<NodeRef, FilePlanFailure> {
    let TargetLocator::Section { name, occurrence } = target else {
        return Err(FilePlanFailure::internal(
            "locator",
            "a section operation requires a section target",
        ));
    };
    let mut seen = 0usize;
    for section in document.sections() {
        if section.name() == name {
            if seen == *occurrence {
                return Ok(section.node_ref());
            }
            seen += 1;
        }
    }
    Err(target_not_found(target))
}

fn target_not_found(target: &TargetLocator) -> FilePlanFailure {
    FilePlanFailure::from(FlowError::new(
        "core.edit.target-not-found@1",
        format!("edit target '{target}' does not exist in the source"),
    ))
}

impl std::fmt::Display for TargetLocator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document => write!(formatter, "document"),
            Self::Section { name, occurrence } => {
                write!(formatter, "section '{name}'#{occurrence}")
            }
            Self::Entry {
                section,
                key,
                occurrence,
            } => write!(
                formatter,
                "entry '{}':'{key}'#{occurrence}",
                section.as_deref().unwrap_or("(default)")
            ),
        }
    }
}

/// Maps one format-owned edit failure to its stable code (RFC 0015 §5.2:
/// format-layer codes pass through unchanged; the envelope binds only
/// registered codes, the stderr line keeps the true code).
fn edit_failure(path: &str, failure: &ini::EditFailure) -> FilePlanFailure {
    FilePlanFailure::from(stable_failure(
        failure,
        format!("edit dry-run failed for '{path}'"),
    ))
}

/// Strictly decodes one `cli.edit-request@1` and validates the whole
/// operation vocabulary against the facade registry of the selected profile.
///
/// The transport is chosen by magic (`PVCE` prefix -> PVCE/1, otherwise
/// strict canonical JSON, RFC 0015 §3.2). Unknown, reordered, or missing
/// fields, non-canonical representations, unknown operation ids, and
/// operations of format families outside the wired INI surface are all
/// rejected (`cli.data.invalid-request@1`); transport `ResourceLimit` is a
/// limit-class failure (exit 3).
pub(crate) fn decode_edit_request(
    bytes: &[u8],
    parsed: &ParsedArgs,
) -> Result<EditRequestInput, FlowError> {
    let limits = ProtocolLimits::default();
    let value = if bytes.starts_with(b"PVCE") {
        decode_pvce(bytes, limits)
    } else {
        decode_json(bytes, limits)
    }
    .map_err(protocol_error)?;
    let entries = value.as_object().ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            "cli.edit-request@1 must be an Object",
        )
    })?;
    if !matches!(entries.len(), 2)
        || entries[0].key() != "schema"
        || entries[0].value().as_string() != Some(EDIT_REQUEST_SCHEMA)
    {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "schema must be the first field with value \"cli.edit-request@1\"",
        ));
    }
    if entries[1].key() != "operations" {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            "operations must be the second field",
        ));
    }
    let profile = resolve_profile(
        parsed
            .profile
            .as_deref()
            .expect("args.rs requires --profile for parse-class commands"),
    )?;
    let family = format_family(profile.id()).ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("profile '{}' has no format family", profile.id()),
        )
    })?;
    if family != "ini" {
        return Err(FlowError::new(
            "cli.data.invalid-request@1",
            format!(
                "the {family} edit surface is not wired in this milestone: the request \
                 vocabulary maps the ini family only (the facade exposes typed edit \
                 transactions for {family}, but no operation request mapping yet)"
            ),
        ));
    }
    let operation_values = entries[1].value().as_sequence().ok_or_else(|| {
        FlowError::new(
            "cli.data.invalid-request@1",
            "operations must be a Sequence",
        )
    })?;
    let mut operations = Vec::new();
    for (index, item) in operation_values.iter().enumerate() {
        operations.push(decode_operation(item, &profile, index)?);
    }
    Ok(EditRequestInput {
        profile,
        operations,
    })
}

/// Decodes one operation request: exact fields [operation, target, arguments],
/// id/version validated against the facade operation registry, typed
/// arguments per operation.
fn decode_operation(
    value: &PortableValue,
    profile: &ProfileId,
    index: usize,
) -> Result<OperationSpec, FlowError> {
    let path = format!("operations[{index}]");
    let entries = value
        .as_object()
        .ok_or_else(|| invalid_request(format!("{path} must be an Object")))?;
    if !matches!(entries.len(), 3)
        || entries[0].key() != "operation"
        || entries[1].key() != "target"
        || entries[2].key() != "arguments"
    {
        return Err(invalid_request(format!(
            "{path} requires exactly operation/target/arguments in order"
        )));
    }
    let (id, version) = decode_reference(entries[0].value(), &format!("{path}.operation"))?;
    validate_registry_operation(profile, &id, version, &path)?;
    let target = decode_target(entries[1].value(), &format!("{path}.target"))?;
    let kind = decode_arguments(&id, entries[2].value(), &format!("{path}.arguments"))?;
    Ok(OperationSpec {
        id,
        version,
        target,
        kind,
    })
}

/// Decodes the `{id, version}` operation reference.
fn decode_reference(value: &PortableValue, path: &str) -> Result<(String, u32), FlowError> {
    let entries = value
        .as_object()
        .ok_or_else(|| invalid_request(format!("{path} must be an Object")))?;
    if !matches!(entries.len(), 2) || entries[0].key() != "id" || entries[1].key() != "version" {
        return Err(invalid_request(format!(
            "{path} requires exactly {{id, version}}"
        )));
    }
    let id = entries[0]
        .value()
        .as_string()
        .ok_or_else(|| invalid_request(format!("{path}.id must be a String")))?;
    let version = entries[1]
        .value()
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| invalid_request(format!("{path}.version must be an Integer")))?;
    Ok((id.to_owned(), version))
}

/// Validates the operation id/version against the profile's facade operation
/// registry (RFC 0015 hard gate 1: the CLI's only knowledge of operations
/// comes from the facade).
fn validate_registry_operation(
    profile: &ProfileId,
    id: &str,
    version: u32,
    path: &str,
) -> Result<(), FlowError> {
    let registry = consema::registry::operation_registry(profile).ok_or_else(|| {
        invalid_request(format!(
            "profile '{}' publishes no operation registry",
            profile.id()
        ))
    })?;
    let published = registry
        .operations()
        .iter()
        .any(|descriptor| descriptor.id().id() == id && descriptor.id().version() == version);
    if !published {
        return Err(invalid_request(format!(
            "{path}: operation '{id}@{version}' is not published by profile '{}'",
            profile.id()
        )));
    }
    Ok(())
}

/// Decodes the target locator (exact fields per kind).
fn decode_target(value: &PortableValue, path: &str) -> Result<TargetLocator, FlowError> {
    let entries = value
        .as_object()
        .ok_or_else(|| invalid_request(format!("{path} must be an Object")))?;
    if entries.is_empty() || entries[0].key() != "kind" {
        return Err(invalid_request(format!(
            "{path} requires kind as the first field"
        )));
    }
    let kind = entries[0]
        .value()
        .as_string()
        .ok_or_else(|| invalid_request(format!("{path}.kind must be a String")))?;
    match kind {
        "document" => {
            if entries.len() != 1 {
                return Err(invalid_request(format!(
                    "{path} document targets carry no further fields"
                )));
            }
            Ok(TargetLocator::Document)
        }
        "section" => {
            if !matches!(entries.len(), 3)
                || entries[1].key() != "name"
                || entries[2].key() != "occurrence"
            {
                return Err(invalid_request(format!(
                    "{path} section targets require exactly name/occurrence"
                )));
            }
            let name = string_field(entries[1].value(), &format!("{path}.name"))?;
            let occurrence = occurrence_field(entries[2].value(), &format!("{path}.occurrence"))?;
            Ok(TargetLocator::Section { name, occurrence })
        }
        "entry" => {
            if !matches!(entries.len(), 4)
                || entries[1].key() != "section"
                || entries[2].key() != "key"
                || entries[3].key() != "occurrence"
            {
                return Err(invalid_request(format!(
                    "{path} entry targets require exactly section/key/occurrence"
                )));
            }
            let section = if entries[1].value() == &PortableValue::null() {
                None
            } else {
                Some(string_field(
                    entries[1].value(),
                    &format!("{path}.section"),
                )?)
            };
            let key = string_field(entries[2].value(), &format!("{path}.key"))?;
            let occurrence = occurrence_field(entries[3].value(), &format!("{path}.occurrence"))?;
            Ok(TargetLocator::Entry {
                section,
                key,
                occurrence,
            })
        }
        _ => Err(invalid_request(format!(
            "{path}.kind must be \"document\", \"section\", or \"entry\""
        ))),
    }
}

fn occurrence_field(value: &PortableValue, path: &str) -> Result<usize, FlowError> {
    value
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|occurrence| usize::try_from(occurrence).ok())
        .ok_or_else(|| invalid_request(format!("{path} must be a non-negative Integer")))
}

fn string_field(value: &PortableValue, path: &str) -> Result<String, FlowError> {
    value
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| invalid_request(format!("{path} must be a String")))
}

/// Decodes the exact per-operation argument fields.
fn decode_arguments(
    id: &str,
    value: &PortableValue,
    path: &str,
) -> Result<OperationKind, FlowError> {
    let entries = value
        .as_object()
        .ok_or_else(|| invalid_request(format!("{path} must be an Object")))?;
    let names: Vec<&str> = entries
        .iter()
        .map(consema::core::ObjectEntry::key)
        .collect();
    let names_match = |expected: &[&str]| {
        names.len() == expected.len()
            && names
                .iter()
                .zip(expected.iter())
                .all(|(actual, expected)| *actual == *expected)
    };
    match id {
        "ini.edit.replace-semantic-value" => {
            if !names_match(&["value", "representation_policy"]) {
                return Err(invalid_request(format!(
                    "{path} requires exactly value/representation_policy"
                )));
            }
            let value = string_field(entries[0].value(), &format!("{path}.value"))?;
            let policy_name =
                string_field(entries[1].value(), &format!("{path}.representation_policy"))?;
            let policy = match policy_name.as_str() {
                "exact-literal" => RepresentationPolicy::ExactLiteral,
                "preserve-compatible" => RepresentationPolicy::PreserveCompatible,
                "canonical-for-profile" => RepresentationPolicy::CanonicalForProfile,
                "preserve-else-canonical" => RepresentationPolicy::PreserveElseCanonical,
                _ => {
                    return Err(invalid_request(format!(
                        "{path}.representation_policy must be exact-literal, \
                         preserve-compatible, canonical-for-profile, or \
                         preserve-else-canonical"
                    )));
                }
            };
            Ok(OperationKind::ReplaceSemanticValue { value, policy })
        }
        "ini.edit.replace-literal-value" => {
            if !names_match(&["literal"]) {
                return Err(invalid_request(format!("{path} requires exactly literal")));
            }
            let hex = string_field(entries[0].value(), &format!("{path}.literal"))?;
            let literal = decode_hex(&hex).ok_or_else(|| {
                invalid_request(format!("{path}.literal must be even-length lowercase hex"))
            })?;
            Ok(OperationKind::ReplaceLiteralValue { literal })
        }
        "ini.edit.remove-entry" => {
            if !names_match(&[]) {
                return Err(invalid_request(format!("{path} carries no arguments")));
            }
            Ok(OperationKind::RemoveEntry)
        }
        "ini.edit.rename-entry" => {
            if !names_match(&["key"]) {
                return Err(invalid_request(format!("{path} requires exactly key")));
            }
            let key = string_field(entries[0].value(), &format!("{path}.key"))?;
            Ok(OperationKind::RenameEntry { key })
        }
        "ini.edit.insert-section" => {
            if !names_match(&["name", "placement"]) {
                return Err(invalid_request(format!(
                    "{path} requires exactly name/placement"
                )));
            }
            let name = string_field(entries[0].value(), &format!("{path}.name"))?;
            let placement = placement_field(entries[1].value(), &format!("{path}.placement"))?;
            Ok(OperationKind::InsertSection { name, placement })
        }
        "ini.edit.remove-section" => {
            if !names_match(&[]) {
                return Err(invalid_request(format!("{path} carries no arguments")));
            }
            Ok(OperationKind::RemoveSection)
        }
        "ini.edit.rename-section" => {
            if !names_match(&["name"]) {
                return Err(invalid_request(format!("{path} requires exactly name")));
            }
            let name = string_field(entries[0].value(), &format!("{path}.name"))?;
            Ok(OperationKind::RenameSection { name })
        }
        "ini.edit.insert-entry" => {
            if !names_match(&["key", "value", "placement"]) {
                return Err(invalid_request(format!(
                    "{path} requires exactly key/value/placement"
                )));
            }
            let key = string_field(entries[0].value(), &format!("{path}.key"))?;
            let value = string_field(entries[1].value(), &format!("{path}.value"))?;
            let placement = placement_field(entries[2].value(), &format!("{path}.placement"))?;
            Ok(OperationKind::InsertEntry {
                key,
                value,
                placement,
            })
        }
        _ => Err(invalid_request(format!(
            "operation '{id}' is not wired in the request vocabulary"
        ))),
    }
}

/// Decodes the closed placement set {start, end} (anchor placement is not
/// wired in this milestone).
fn placement_field(value: &PortableValue, path: &str) -> Result<AssociationPlacement, FlowError> {
    match value.as_string() {
        Some("start") => Ok(AssociationPlacement::Start),
        Some("end") => Ok(AssociationPlacement::End),
        _ => Err(invalid_request(format!(
            "{path} must be \"start\" or \"end\" (anchor placement is not wired \
             in this milestone)"
        ))),
    }
}

/// Decodes even-length lowercase hex into bytes.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect()
}

fn invalid_request(message: impl Into<String>) -> FlowError {
    FlowError::new("cli.data.invalid-request@1", message)
}

/// Compiles the presentation redaction policy from the parsed arguments
/// (RFC 0015 §11.2: an invalid `--redact-keys` pattern is a usage error,
/// `cli.usage.redaction-pattern@1`, exit 1).
pub(crate) fn redact_policy(parsed: &ParsedArgs) -> Result<RedactPolicy, FlowError> {
    let mut policy = if parsed.show_secrets {
        RedactPolicy::show_secrets()
    } else {
        RedactPolicy::conservative()
    };
    if let Some(pattern) = &parsed.redact_keys {
        policy = policy
            .with_extra_patterns(&[pattern.as_str()])
            .map_err(|error| FlowError::usage(error.code(), error.message()))?;
    }
    Ok(policy)
}

/// The one deterministic human line of one operation request (target key and
/// section names redacted; value-bearing arguments redact under the target
/// entry's key name — the conservative direction of RFC 0015 §11.2).
///
/// Returns the rendered line and the number of values replaced in it.
#[must_use]
pub(crate) fn operation_line(policy: &RedactPolicy, operation: &OperationSpec) -> (String, u64) {
    let (target_text, mut count) = render_target(policy, &operation.target);
    let mut arguments = Vec::new();
    match &operation.kind {
        OperationKind::ReplaceSemanticValue { value, policy: rep } => {
            let rendered = render_value_argument(policy, operation, "value", value);
            count += u64::from(rendered.redacted());
            arguments.push(format!("value={}", rendered.text()));
            arguments.push(format!(
                "representation_policy={}",
                representation_policy_name(*rep)
            ));
        }
        OperationKind::ReplaceLiteralValue { literal } => {
            let rendered = render_value_argument(policy, operation, "literal", &hex_text(literal));
            count += u64::from(rendered.redacted());
            arguments.push(format!("literal={}", rendered.text()));
        }
        OperationKind::RenameEntry { key } => {
            let rendered = render_value_argument(policy, operation, "key", key);
            count += u64::from(rendered.redacted());
            arguments.push(format!("key={}", rendered.text()));
        }
        OperationKind::InsertSection { name, placement } => {
            let rendered = render_value_argument(policy, operation, "name", name);
            count += u64::from(rendered.redacted());
            arguments.push(format!("name={}", rendered.text()));
            arguments.push(format!("placement={}", placement_name(*placement)));
        }
        OperationKind::RenameSection { name } => {
            let rendered = render_value_argument(policy, operation, "name", name);
            count += u64::from(rendered.redacted());
            arguments.push(format!("name={}", rendered.text()));
        }
        OperationKind::InsertEntry {
            key,
            value,
            placement,
        } => {
            let rendered_key = render_value_argument(policy, operation, "key", key);
            count += u64::from(rendered_key.redacted());
            arguments.push(format!("key={}", rendered_key.text()));
            let rendered_value = render_value_argument(policy, operation, "value", value);
            count += u64::from(rendered_value.redacted());
            arguments.push(format!("value={}", rendered_value.text()));
            arguments.push(format!("placement={}", placement_name(*placement)));
        }
        OperationKind::RemoveEntry | OperationKind::RemoveSection => {}
    }
    let version = operation.version;
    let line = if arguments.is_empty() {
        format!("{}@{version} on {target_text}", operation.id)
    } else {
        format!(
            "{}@{version} on {target_text}  {}",
            operation.id,
            arguments.join(" ")
        )
    };
    (line, count)
}

/// The deterministic human spelling of one target locator (key and section
/// names pass through the redaction policy).
fn render_target(policy: &RedactPolicy, target: &TargetLocator) -> (String, u64) {
    match target {
        TargetLocator::Document => ("document".to_owned(), 0),
        TargetLocator::Section { name, occurrence } => {
            let name_text = redact_text(policy, name, name);
            let suffix = occurrence_suffix(*occurrence);
            (
                format!("section '{}{}'", name_text.text(), suffix),
                u64::from(name_text.redacted()),
            )
        }
        TargetLocator::Entry {
            section,
            key,
            occurrence,
        } => {
            let section_text = match section {
                None => "(default)".to_owned(),
                Some(name) => redact_text(policy, name, name).text().to_owned(),
            };
            let key_text = redact_text(policy, key, key);
            let suffix = occurrence_suffix(*occurrence);
            (
                format!("entry '{}':'{}{}'", section_text, key_text.text(), suffix),
                u64::from(key_text.redacted()),
            )
        }
    }
}

fn occurrence_suffix(occurrence: usize) -> String {
    if occurrence == 0 {
        String::new()
    } else {
        format!("#{occurrence}")
    }
}

/// Renders one value-bearing argument; the redaction key is the target
/// entry's key name when the operation targets an entry, else the argument
/// name (RFC 0015 §11.2 key-name matching; conservative direction).
fn render_value_argument(
    policy: &RedactPolicy,
    operation: &OperationSpec,
    argument_name: &str,
    value: &str,
) -> crate::redact::RedactedText {
    let redaction_key: &str = match &operation.target {
        TargetLocator::Entry { key, .. } => key.as_str(),
        _ => argument_name,
    };
    redact_text(policy, redaction_key, value)
}

fn representation_policy_name(policy: RepresentationPolicy) -> &'static str {
    match policy {
        RepresentationPolicy::ExactLiteral => "exact-literal",
        RepresentationPolicy::PreserveCompatible => "preserve-compatible",
        RepresentationPolicy::CanonicalForProfile => "canonical-for-profile",
        RepresentationPolicy::PreserveElseCanonical => "preserve-else-canonical",
    }
}

fn placement_name(placement: AssociationPlacement) -> &'static str {
    match placement {
        AssociationPlacement::Start => "start",
        AssociationPlacement::End => "end",
        // Unreachable in this milestone: the request vocabulary only accepts
        // start/end; anchor placement is rejected at decode time.
        AssociationPlacement::Before(_) | AssociationPlacement::After(_) => "anchor",
    }
}

fn hex_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use std::fmt::Write as FmtWrite;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Runs `consema edit` (dry-run only; the source file is the positional, the
/// operation request arrives via `--request-file` or stdin).
pub(crate) fn run(parsed: &ParsedArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if parsed.write {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--write' is not available in this build: edit is dry-run only \
             (the commit path lands with fsio in milestone M8)",
        );
        return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr);
    }
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available for edit: the dry-run result is \
             emitted to stdout only",
        );
        return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr);
    }
    let policy = match redact_policy(parsed) {
        Ok(policy) => policy,
        Err(error) => return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr),
    };
    let request = match read_request_bytes(parsed) {
        Ok(bytes) => bytes,
        Err(error) => return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr),
    };
    run_with_request(parsed, &request, &policy, stdout, stderr)
}

/// Runs `consema edit` against already-read request bytes (testable without
/// stdin or fixture files).
pub(crate) fn run_with_request(
    parsed: &ParsedArgs,
    request: &[u8],
    policy: &RedactPolicy,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    // The refusals live in both run() and run_with_request() so the
    // request-driven path (unit tests, embedded callers) can never reach a
    // write path either (the same double-guard milestone M5 uses for
    // --output before fsio).
    if parsed.write {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--write' is not available in this build: edit is dry-run only \
             (the commit path lands with fsio in milestone M8)",
        );
        return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr);
    }
    if parsed.output.is_some() {
        let error = FlowError::usage(
            "cli.usage.invalid-argument@1",
            "flag '--output' is not available for edit: the dry-run result is \
             emitted to stdout only",
        );
        return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr);
    }
    let input = match decode_edit_request(request, parsed) {
        Ok(input) => input,
        Err(error) => return emit_failure(CliCommand::Edit, parsed, &error, stdout, stderr),
    };
    let path = &parsed.positionals[0];
    let prepared = match prepare_edit(&input, path, parsed) {
        Ok(prepared) => prepared,
        Err(failure) => {
            return emit_failure(
                CliCommand::Edit,
                parsed,
                &failure.into_flow_error(),
                stdout,
                stderr,
            );
        }
    };
    let outcome = match dry_run_plan(&prepared, path) {
        Ok(outcome) => outcome,
        Err(failure) => {
            return emit_failure(
                CliCommand::Edit,
                parsed,
                &failure.into_flow_error(),
                stdout,
                stderr,
            );
        }
    };
    let plan_message =
        match EditPlanMessage::from_plan_with_registry(&outcome.plan, ErrorCodeRegistry::v7()) {
            Ok(message) => message,
            Err(error) => {
                return internal_failure(
                    "edit",
                    &format!("edit-plan externalization failed: {error}"),
                    stderr,
                );
            }
        };
    let change_set = match change_set_value(&prepared, path) {
        Ok(message) => message,
        Err(failure) => {
            return emit_failure(
                CliCommand::Edit,
                parsed,
                &failure.into_flow_error(),
                stdout,
                stderr,
            );
        }
    };
    let plan_value = match plan_message.to_value() {
        Ok(value) => value,
        Err(error) => {
            return internal_failure(
                "edit",
                &format!("edit-plan encoding failed: {error}"),
                stderr,
            );
        }
    };
    let payload = cli_edit_payload(plan_value, change_set.to_value());
    if parsed.json {
        match emit_envelope(
            CliCommand::Edit,
            ExitClass::Success,
            payload,
            Vec::new(),
            parsed,
            stdout,
        ) {
            Ok(()) => ExitClass::Success.exit_code(),
            Err(message) => internal_failure("edit", &message, stderr),
        }
    } else {
        match write_edit_report(&input, &outcome.plan, path, policy, stdout) {
            Ok((redacted_count, _)) => {
                redaction_notice("edit", redacted_count, stderr);
                ExitClass::Success.exit_code()
            }
            Err(message) => internal_failure("edit", &message, stderr),
        }
    }
}

/// Externalizes the `core.change-set@1` summary by re-committing the same
/// validated transaction in memory (pure computation; the format crates
/// prove the dry-run/commit equivalence). The locator closure resolves every
/// mapped node against the old and new INI documents with the CLI's stable
/// caller locators (`document`, `section:<name>`, `entry:<section>:<key>`),
/// so no process-local identity ever reaches the wire (RFC 0015 §3.3).
fn change_set_value(
    prepared: &PreparedEdit,
    path: &str,
) -> Result<ChangeSetMessage, FilePlanFailure> {
    let ini_document = prepared.document.as_ini().map_err(|_| {
        FilePlanFailure::internal(path, "the parsed document is not an INI document")
    })?;
    let commit = ini_document
        .commit(&prepared.transaction)
        .map_err(|failure| edit_failure(path, &failure))?;
    let old_document = ini_document;
    let new_document = &commit.document;
    let locator =
        |node: NodeRef| ini_locator(old_document, node).or_else(|| ini_locator(new_document, node));
    ChangeSetMessage::from_document_with_registry(
        &commit.change_set,
        path,
        path,
        locator,
        ErrorCodeRegistry::v7(),
    )
    .map_err(|error| {
        FilePlanFailure::internal(path, format!("change-set externalization failed: {error}"))
    })
}

/// The CLI-stable caller locator of one INI node (RFC 0015 §8.2/§3.3:
/// caller-defined stable locators, no process-local handles).
fn ini_locator(document: &ini::Document, node: NodeRef) -> Option<String> {
    if node == document.node_ref() {
        return Some("document".to_owned());
    }
    if let Ok(section) = document.section(node) {
        return Some(format!("section:{}", section.name()));
    }
    let entry = document.entry(node).ok()?;
    let section = document.section(entry.section()).ok()?;
    Some(format!("entry:{}:{}", section.name(), entry.key()))
}

/// The fixed `cli.edit@1` payload record (RFC 0015 §6.1); `committed` is
/// always false in this milestone (dry-run; `--write` is refused).
fn cli_edit_payload(plan: PortableValue, change_set: PortableValue) -> PortableValue {
    let mut record = ObjectBuilder::new();
    record
        .insert("schema", PortableValue::string("cli.edit@1"))
        .expect("unique key");
    record.insert("plan", plan).expect("unique key");
    record.insert("change_set", change_set).expect("unique key");
    record
        .insert("committed", PortableValue::boolean(false))
        .expect("unique key");
    record.build()
}

/// Deterministic human edit report (same facade result as the machine
/// payload; RFC 0015 §2.1 human/machine draw from the same call). Returns
/// the number of redacted values and the rendered text for tests.
fn write_edit_report(
    input: &EditRequestInput,
    plan: &EditPlan,
    path: &str,
    policy: &RedactPolicy,
    stdout: &mut dyn Write,
) -> Result<(u64, String), String> {
    use std::fmt::Write as FmtWrite;
    let mut text = String::new();
    let mut redacted = 0u64;
    let _ = writeln!(text, "edit dry-run ({}): {path}", input.profile.id());
    for operation in &input.operations {
        let (line, count) = operation_line(policy, operation);
        redacted += count;
        let _ = writeln!(text, "  {line}");
    }
    let replacements = plan.replacements().len();
    let _ = writeln!(
        text,
        "  base {} target {} replacements: {replacements}",
        plan.base_digest().to_hex(),
        plan.target_digest().to_hex()
    );
    text.push_str("  committed: no\n");
    stdout
        .write_all(text.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))?;
    Ok((redacted, text))
}

/// One deterministic stderr redaction notice (RFC 0015 §4.4: redaction hints
/// go to stderr; only when the human view replaced any value).
fn redaction_notice(command: &str, count: u64, stderr: &mut dyn Write) {
    if count > 0 {
        let _ = writeln!(
            stderr,
            "consema: {command}: redacted {count} value(s) in the human view \
             (--show-secrets reveals)"
        );
    }
}

/// The summary facts of one planned file for the human plan view.
pub(crate) struct PlanRenderItem {
    /// The user-supplied path spelling.
    pub(crate) path: String,
    /// Whether the file planned successfully.
    pub(crate) planned: bool,
    /// The operation request lines (redacted) of a planned file.
    pub(crate) operation_lines: Vec<(String, u64)>,
    /// The base digest hex of a planned file.
    pub(crate) base_digest: Option<String>,
    /// The target digest hex of a planned file.
    pub(crate) target_digest: Option<String>,
    /// Replacement count of a planned file.
    pub(crate) replacements: Option<usize>,
    /// The failure code of a failed file.
    pub(crate) failure_code: Option<String>,
    /// Number of values redacted in this item's lines.
    pub(crate) redacted: u64,
}

/// Builds the human plan-view item of one manifest file entry (rendering
/// from the same request operations and plan facts as the machine manifest;
/// RFC 0015 §2.4).
pub(crate) fn plan_render_item(
    input: &EditRequestInput,
    entry: &consema::protocol::BatchPlanFileEntry,
    policy: &RedactPolicy,
) -> PlanRenderItem {
    match entry.status() {
        consema::protocol::BatchPlanFileStatus::Planned => {
            let mut operation_lines = Vec::new();
            let mut redacted = 0u64;
            for operation in &input.operations {
                let (line, count) = operation_line(policy, operation);
                redacted += count;
                operation_lines.push((line, count));
            }
            let patch = entry.source_patch().expect("planned entries carry a patch");
            PlanRenderItem {
                path: entry.path().to_owned(),
                planned: true,
                operation_lines,
                base_digest: Some(entry.source_digest().expect("planned digest").to_hex()),
                target_digest: Some(patch.target_digest().to_hex()),
                replacements: Some(patch.replacements().len()),
                failure_code: None,
                redacted,
            }
        }
        consema::protocol::BatchPlanFileStatus::Failed => PlanRenderItem {
            path: entry.path().to_owned(),
            planned: false,
            operation_lines: Vec::new(),
            base_digest: None,
            target_digest: None,
            replacements: None,
            failure_code: Some(entry.failure_code().unwrap_or("unknown").to_owned()),
            redacted: 0,
        },
    }
}

/// Writes the deterministic human plan report (RFC 0015 §2.4; per-item
/// redaction). Returns the total number of redacted values.
pub(crate) fn write_plan_report(
    items: &[PlanRenderItem],
    stdout: &mut dyn Write,
) -> Result<u64, String> {
    use std::fmt::Write as FmtWrite;
    let mut total = 0u64;
    let mut text = String::new();
    let _ = writeln!(text, "consema plan: {} file(s)", items.len());
    for item in items {
        total += item.redacted;
        if item.planned {
            let _ = writeln!(text, "  {}: planned", item.path);
            for (line, _) in &item.operation_lines {
                let _ = writeln!(text, "    {line}");
            }
            let _ = writeln!(
                text,
                "    base sha256:{} target sha256:{} replacements: {}",
                item.base_digest.as_deref().unwrap_or("?"),
                item.target_digest.as_deref().unwrap_or("?"),
                item.replacements.unwrap_or(0)
            );
        } else {
            let _ = writeln!(
                text,
                "  {}: failed {}",
                item.path,
                item.failure_code.as_deref().unwrap_or("?")
            );
        }
    }
    stdout
        .write_all(text.as_bytes())
        .map_err(|error| format!("stdout write failed: {error}"))?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::PLACEHOLDER;
    use consema::core::{BigInteger, SequenceBuilder};
    use consema::document::ContentDigest;
    use consema::protocol::{ChangeSetMessage, CliOutputMessage, EditPlanMessage, encode_json};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    /// One isolated scratch directory, removed on drop.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "consema-{name}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create test scratch dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn parse(args: &[&str]) -> ParsedArgs {
        crate::args::parse_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("valid invocation")
    }

    fn run_request(args: &[&str], request: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let parsed = parse(args);
        let policy = redact_policy(&parsed).unwrap_or_else(|error| panic!("{}", error.message));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(&parsed, request, &policy, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    /// Applies the plan record's replacement facts to one base snapshot,
    /// reproducing the target bytes (the cli.edit@1 payload embeds the plan;
    /// its replacements are exactly the SourcePatch precondition facts, so
    /// re-applying them reproduces the target digest — the dry-run/commit
    /// equivalence contract, implementation plan §6 M7).
    fn apply_plan_replacements(plan: &EditPlanMessage, base: &[u8]) -> Vec<u8> {
        let snapshot =
            consema::document::SourceSnapshot::from_utf8(base.to_vec()).expect("base snapshot");
        let patch = consema::document::SourcePatch::create(
            &snapshot,
            plan.replacements().to_vec(),
            std::collections::BTreeMap::new(),
            consema::document::SourcePatchLimits::default(),
        )
        .expect("patch from the plan's replacement facts");
        patch
            .apply(&snapshot, consema::document::SourcePatchLimits::default())
            .expect("applies to its base")
            .bytes()
            .to_vec()
    }

    fn stderr_text(stderr: &[u8]) -> String {
        String::from_utf8_lossy(stderr).into_owned()
    }

    fn envelope_of(stdout: &[u8]) -> CliOutputMessage {
        assert!(stdout.ends_with(b"\n"), "envelope line ends in one LF");
        assert!(!stdout[..stdout.len() - 1].contains(&b'\n'));
        CliOutputMessage::from_json(&stdout[..stdout.len() - 1], ProtocolLimits::default())
            .expect("byte-valid envelope")
    }

    /// Builds one strict request value (`cli.edit-request@1`).
    fn request_value(operations: Vec<PortableValue>) -> PortableValue {
        let mut items = SequenceBuilder::new();
        for operation in operations {
            items.push(operation);
        }
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert("schema", PortableValue::string(EDIT_REQUEST_SCHEMA))
            .expect("unique");
        wrapper.insert("operations", items.build()).expect("unique");
        wrapper.build()
    }

    fn request_json(operations: Vec<PortableValue>) -> Vec<u8> {
        encode_json(&request_value(operations), ProtocolLimits::default())
            .expect("canonical request bytes")
    }

    /// One replace-semantic-value operation request.
    fn semantic_replace(section: Option<&str>, key: &str, value: &str) -> PortableValue {
        let mut reference = ObjectBuilder::new();
        reference
            .insert(
                "id",
                PortableValue::string("ini.edit.replace-semantic-value"),
            )
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("entry"))
            .expect("unique");
        target
            .insert(
                "section",
                section.map_or_else(PortableValue::null, PortableValue::string),
            )
            .expect("unique");
        target
            .insert("key", PortableValue::string(key))
            .expect("unique");
        target
            .insert("occurrence", PortableValue::integer(BigInteger::from(0)))
            .expect("unique");
        let mut arguments = ObjectBuilder::new();
        arguments
            .insert("value", PortableValue::string(value))
            .expect("unique");
        arguments
            .insert(
                "representation_policy",
                PortableValue::string("preserve-compatible"),
            )
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", arguments.build())
            .expect("unique");
        operation.build()
    }

    fn write_source(dir: &TestDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        path.to_string_lossy().into_owned()
    }

    fn source_db() -> &'static [u8] {
        // ini.portable rejects spaces around `=` (conservative ASCII
        // exchange subset); entries require a section header.
        b"[db]\nport=8080\npassword=hunter2\n"
    }

    #[test]
    fn edit_dry_run_emits_a_byte_valid_edit_payload() {
        let dir = TestDir::new("edit-ok");
        let path = write_source(&dir, "app.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request_json(vec![semantic_replace(Some("db"), "port", "9090")]),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty());
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.command(), CliCommand::Edit);
        assert_eq!(envelope.exit_class(), ExitClass::Success);
        // Byte-determinism: re-encoding reproduces the stdout bytes.
        let limits = ProtocolLimits::default();
        assert_eq!(
            envelope.to_json(limits).expect("re-encode"),
            &stdout[..stdout.len() - 1],
            "stdout envelope must be byte-deterministic"
        );
        // The cli.edit@1 payload record: plan + change_set + committed.
        let payload = envelope.payload();
        let fields = payload.as_object().expect("payload object");
        assert_eq!(fields[0].key(), "schema");
        assert_eq!(fields[0].value().as_string(), Some("cli.edit@1"));
        assert_eq!(fields[1].key(), "plan");
        assert_eq!(fields[2].key(), "change_set");
        assert_eq!(fields[3].key(), "committed");
        assert_eq!(fields[3].value().as_boolean(), Some(false));
        // The plan record decodes through the typed decoder (round-trip gate).
        let plan = EditPlanMessage::from_value(fields[1].value()).expect("core.edit-plan@1");
        assert_eq!(plan.profile().id(), "ini.portable");
        assert_eq!(plan.operations().len(), 1);
        assert_eq!(
            plan.operations()[0].operation.id(),
            "ini.edit.replace-semantic-value"
        );
        assert_eq!(plan.source_id(), path);
        // The change-set record decodes through its typed decoder too.
        let change_set =
            ChangeSetMessage::from_value(fields[2].value()).expect("core.change-set@1");
        assert_eq!(change_set.old_source_id(), path);
        assert_eq!(change_set.new_source_id(), path);
        // The plan embeds the exact SourcePatch facts: one replacement whose
        // re-application reproduces the target digest (dry-run/commit
        // equivalence contract, implementation plan §6 M7).
        assert_eq!(plan.base_digest(), ContentDigest::of(source_db()));
        assert_eq!(plan.replacements().len(), 1);
        let applied = apply_plan_replacements(&plan, source_db());
        assert_eq!(plan.target_digest(), ContentDigest::of(&applied));
        assert_eq!(applied, b"[db]\nport=9090\npassword=hunter2\n");
    }

    #[test]
    fn edit_write_flag_is_refused_as_usage_without_envelope() {
        let dir = TestDir::new("edit-write");
        let path = write_source(&dir, "app.conf", source_db());
        let args = &[
            "edit",
            &path,
            "--profile",
            "ini.portable",
            "--write",
            "--json",
        ];
        let parsed = parse(args);
        let policy = redact_policy(&parsed).unwrap_or_else(|error| panic!("{}", error.message));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(
            &parsed,
            &request_json(vec![semantic_replace(Some("db"), "port", "9090")]),
            &policy,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1, "usage: --write is a milestone-M8 feature");
        assert!(stdout.is_empty(), "usage failures never emit an envelope");
        assert!(stderr_text(&stderr).contains("--write"));
        assert!(stderr_text(&stderr).contains("cli.usage.invalid-argument@1"));
    }

    #[test]
    fn edit_output_flag_is_refused_as_usage() {
        let parsed = parse(&[
            "edit",
            "x.conf",
            "--profile",
            "ini.portable",
            "--output",
            "o",
        ]);
        let policy = redact_policy(&parsed).unwrap_or_else(|error| panic!("{}", error.message));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_request(
            &parsed,
            &request_json(vec![semantic_replace(Some("db"), "port", "9090")]),
            &policy,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(stderr_text(&stderr).contains("--output"));
    }

    #[test]
    fn edit_recovered_source_is_a_data_error_with_the_format_code() {
        let dir = TestDir::new("edit-recovered");
        // An unterminated section header recovers under ini.portable.
        let path = write_source(&dir, "broken.conf", b"[section\nvalue=1\n");
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request_json(vec![semantic_replace(Some("db"), "port", "9090")]),
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(
            stderr_text(&stderr).contains("Recovered"),
            "the stderr line names the recovered state"
        );
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Data);
        assert!(!envelope.diagnostics().is_empty());
    }

    #[test]
    fn edit_unwired_family_operations_are_data_errors() {
        // A JSON-profile operation request is not expressible: the request
        // vocabulary maps the ini family only in this milestone.
        let dir = TestDir::new("edit-unwired");
        let path = write_source(&dir, "app.json", b"{\"a\":1}");
        let mut reference = ObjectBuilder::new();
        reference
            .insert("id", PortableValue::string("json.edit.remove-member"))
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("document"))
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", ObjectBuilder::new().build())
            .expect("unique");
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "json.strict", "--json"],
            &request_json(vec![operation.build()]),
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));
        assert!(stderr_text(&stderr).contains("not wired in this milestone"));
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Data);
    }

    #[test]
    fn edit_unknown_operation_id_is_a_data_error() {
        // The RFC §8.4 example's `ini.edit.set-entry-value@1` is not part of
        // the frozen facade registry; the registry check rejects it (hard
        // gate 1: the CLI's only operation knowledge comes from the facade).
        let dir = TestDir::new("edit-unknown-op");
        let path = write_source(&dir, "app.conf", source_db());
        let mut reference = ObjectBuilder::new();
        reference
            .insert("id", PortableValue::string("ini.edit.set-entry-value"))
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("entry"))
            .expect("unique");
        target
            .insert("section", PortableValue::string("db"))
            .expect("unique");
        target
            .insert("key", PortableValue::string("port"))
            .expect("unique");
        target
            .insert("occurrence", PortableValue::integer(BigInteger::from(0)))
            .expect("unique");
        let mut arguments = ObjectBuilder::new();
        arguments
            .insert("value", PortableValue::string("9090"))
            .expect("unique");
        arguments
            .insert(
                "representation_policy",
                PortableValue::string("preserve-compatible"),
            )
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", arguments.build())
            .expect("unique");
        let (code, _, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request_json(vec![operation.build()]),
        );
        assert_eq!(code, 2, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("not published by profile 'ini.portable'"));
    }

    #[test]
    fn edit_missing_target_is_a_precondition_failure() {
        let dir = TestDir::new("edit-missing");
        let path = write_source(&dir, "app.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request_json(vec![semantic_replace(Some("db"), "missing", "9090")]),
        );
        assert_eq!(code, 4, "{}", stderr_text(&stderr));
        assert!(stderr_text(&stderr).contains("core.edit.target-not-found@1"));
        let envelope = envelope_of(&stdout);
        assert_eq!(envelope.exit_class(), ExitClass::Precondition);
    }

    #[test]
    fn edit_default_section_entry_is_targetable() {
        // Under ini.python-configparser the `[DEFAULT]` header opens the
        // default section; the null section locator targets its entries.
        let dir = TestDir::new("edit-default");
        let path = write_source(&dir, "default.conf", b"[DEFAULT]\nvalue=1\n");
        let (code, stdout, stderr) = run_request(
            &[
                "edit",
                &path,
                "--profile",
                "ini.python-configparser",
                "--json",
            ],
            &request_json(vec![semantic_replace(None, "value", "2")]),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope = envelope_of(&stdout);
        let payload = envelope.payload();
        let fields = payload.as_object().expect("payload");
        let plan = EditPlanMessage::from_value(fields[1].value()).expect("edit plan");
        assert_eq!(plan.profile().id(), "ini.python-configparser");
        let applied = apply_plan_replacements(&plan, b"[DEFAULT]\nvalue=1\n");
        assert_eq!(applied, b"[DEFAULT]\nvalue=2\n");
    }

    #[test]
    fn edit_human_view_renders_operations_and_redacts() {
        let dir = TestDir::new("edit-human");
        let path = write_source(&dir, "app.conf", source_db());
        // Replace the password entry: the human view must redact the key name
        // and the new value (conservative direction).
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable"],
            &request_json(vec![semantic_replace(Some("db"), "password", "hunter3")]),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("edit dry-run (ini.portable)"), "{text}");
        assert!(
            text.contains(PLACEHOLDER),
            "the matching key name is redacted: {text}"
        );
        assert!(!text.contains("password"), "the key name is hidden: {text}");
        assert!(!text.contains("hunter3"), "the new value is hidden: {text}");
        assert!(
            stderr_text(&stderr).contains("redacted 2 value(s)"),
            "the notice counts the replacements: {}",
            stderr_text(&stderr)
        );
        // --show-secrets is the sole opt-out.
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--show-secrets"],
            &request_json(vec![semantic_replace(Some("db"), "password", "hunter3")]),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(
            stderr.is_empty(),
            "no redaction notice under --show-secrets"
        );
        let text = String::from_utf8_lossy(&stdout);
        assert!(text.contains("password"), "{text}");
        assert!(text.contains("hunter3"), "{text}");
        assert!(!text.contains(PLACEHOLDER), "{text}");
    }

    #[test]
    fn edit_dry_run_equivalence_with_a_sdk_commit() {
        // M7 acceptance gate: the same input's plan and a future commit must
        // produce identical replacements and target digest. The CLI's plan
        // facts are compared against a direct SDK commit of the same
        // transaction.
        let dir = TestDir::new("edit-equiv");
        let path = write_source(&dir, "app.conf", source_db());
        let request = request_json(vec![semantic_replace(Some("db"), "port", "9090")]);
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request,
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        let envelope = envelope_of(&stdout);
        let plan_message = EditPlanMessage::from_value(
            envelope.payload().as_object().expect("payload")[1].value(),
        )
        .expect("plan record");
        // SDK side: parse the same file, build the same transaction, commit.
        let parsed = parse(&["edit", &path, "--profile", "ini.portable"]);
        let input = decode_edit_request(&request, &parsed)
            .unwrap_or_else(|error| panic!("{}", error.message));
        let prepared = prepare_edit(&input, &path, &parsed)
            .unwrap_or_else(|error| panic!("{}", error.message));
        let ini_document = prepared.document.as_ini().expect("ini adapter");
        let commit = ini_document
            .commit(&prepared.transaction)
            .expect("SDK commit succeeds");
        // The plan's replacements and digests equal the commit's patch.
        assert_eq!(
            plan_message.base_digest(),
            commit.source_patch.base_digest()
        );
        assert_eq!(
            plan_message.target_digest(),
            commit.source_patch.target_digest()
        );
        let planned_replacements: Vec<_> = plan_message
            .replacements()
            .iter()
            .map(|replacement| {
                (
                    replacement.old_start(),
                    replacement.old_end(),
                    replacement.original().to_vec(),
                    replacement.replacement().to_vec(),
                )
            })
            .collect();
        let committed_replacements: Vec<_> = commit
            .source_patch
            .replacements()
            .iter()
            .map(|replacement| {
                (
                    replacement.old_start(),
                    replacement.old_end(),
                    replacement.original().to_vec(),
                    replacement.replacement().to_vec(),
                )
            })
            .collect();
        assert_eq!(planned_replacements, committed_replacements);
        // The change-set's source edits reproduce the same byte transition.
        let change_set = ChangeSetMessage::from_value(
            envelope.payload().as_object().expect("payload")[2].value(),
        )
        .expect("change-set record");
        assert_eq!(change_set.source_edits().len(), 1);
        let edit = &change_set.source_edits()[0];
        // "[db]\n" is 5 bytes; "port=" is 5 bytes; the value "8080" spans
        // bytes 10..14 of the source.
        assert_eq!(edit.old_start, 10);
        assert_eq!(edit.old_end, 14);
        assert_eq!(edit.replacement, b"9090");
    }

    #[test]
    fn edit_request_negatives_are_rejected() {
        let dir = TestDir::new("edit-negatives");
        let path = write_source(&dir, "app.conf", source_db());
        // Malformed bytes are a data error.
        let (code, _, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            b"not-a-request",
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("cli.data.invalid-request@1"));
        // A wrong payload schema is rejected.
        let mut wrapper = ObjectBuilder::new();
        wrapper
            .insert("schema", PortableValue::string("cli.request@1"))
            .expect("unique");
        wrapper
            .insert("operations", SequenceBuilder::new().build())
            .expect("unique");
        let (code, _, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &encode_json(&wrapper.build(), ProtocolLimits::default()).expect("bytes"),
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("cli.edit-request@1"));
        // Unknown target kind is rejected.
        let mut reference = ObjectBuilder::new();
        reference
            .insert(
                "id",
                PortableValue::string("ini.edit.replace-semantic-value"),
            )
            .expect("unique");
        reference
            .insert("version", PortableValue::integer(BigInteger::from(1)))
            .expect("unique");
        let mut target = ObjectBuilder::new();
        target
            .insert("kind", PortableValue::string("node"))
            .expect("unique");
        let mut arguments = ObjectBuilder::new();
        arguments
            .insert("value", PortableValue::string("9090"))
            .expect("unique");
        arguments
            .insert(
                "representation_policy",
                PortableValue::string("preserve-compatible"),
            )
            .expect("unique");
        let mut operation = ObjectBuilder::new();
        operation
            .insert("operation", reference.build())
            .expect("unique");
        operation.insert("target", target.build()).expect("unique");
        operation
            .insert("arguments", arguments.build())
            .expect("unique");
        let (code, _, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable", "--json"],
            &request_json(vec![operation.build()]),
        );
        assert_eq!(code, 2);
        assert!(stderr_text(&stderr).contains("\"document\", \"section\", or \"entry\""));
    }

    #[test]
    fn edit_human_view_renders_operations_without_redaction_hits() {
        let dir = TestDir::new("edit-human-plain");
        let path = write_source(&dir, "app.conf", source_db());
        let (code, stdout, stderr) = run_request(
            &["edit", &path, "--profile", "ini.portable"],
            &request_json(vec![semantic_replace(Some("db"), "port", "9090")]),
        );
        assert_eq!(code, 0, "{}", stderr_text(&stderr));
        assert!(stderr.is_empty(), "no notice without redaction hits");
        let text = String::from_utf8_lossy(&stdout);
        assert!(
            text.contains("ini.edit.replace-semantic-value@1 on entry 'db':'port'"),
            "{text}"
        );
        assert!(text.contains("value=9090"), "{text}");
        assert!(text.contains("committed: no"), "{text}");
    }

    #[test]
    fn fixture_request_bytes_are_canonical_and_stable() {
        // The e2e fixtures must stay byte-exact: the CLI strictly rejects any
        // non-canonical request byte form (RFC 0015 §3.1). This test pins the
        // canonical bytes of the fixture requests.
        let replace_port = request_json(vec![semantic_replace(Some("db"), "port", "9090")]);
        let replace_password =
            request_json(vec![semantic_replace(Some("db"), "password", "hunter3")]);
        let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let port_bytes = std::fs::read(fixture_dir.join("m7_edit_request.json")).expect("fixture");
        let password_bytes =
            std::fs::read(fixture_dir.join("m7_redact_request.json")).expect("fixture");
        assert_eq!(
            String::from_utf8(replace_port).expect("utf8"),
            String::from_utf8(port_bytes).expect("utf8"),
            "tests/fixtures/m7_edit_request.json must stay byte-canonical"
        );
        assert_eq!(
            String::from_utf8(replace_password).expect("utf8"),
            String::from_utf8(password_bytes).expect("utf8"),
            "tests/fixtures/m7_redact_request.json must stay byte-canonical"
        );
    }
}
