//! Batch-manifest encoding and persistence — both sides of the manifest
//! state machine (RFC 0015 §8.3 plan side / §9 result side; implementation
//! plan §6 M7/M8).
//!
//! This module owns only the schema encoding, the strict decode, and the
//! byte persistence of `core.batch-plan@1` and `core.batch-result@1`; the
//! planning and applying semantics themselves are delegated to the SDK
//! (edit_cmd's `EditTransaction` dry-run pipeline for plan; `SourcePatch`
//! byte verification and fsio for apply; RFC 0015 §4.3 "CLI 不重新实现任何
//! digest、patch 或编辑语义").
//!
//! The manifest record is encoded once through the canonical tagged JSON
//! transport; the same bytes are carried by the `--json` envelope payload
//! line and, with `--output`, persisted to that path via the fsio atomic
//! engine (RFC 0015 §8.3: the file carries the same record without envelope
//! wrapping, byte-identical to the envelope payload; the on-disk manifest is
//! never redacted — RFC 0015 §8.3/§11.4, hard gate 3). The apply result
//! manifest is persisted through the same engine at every state-machine
//! transition (pending before a write, completed/failed after — RFC 0015
//! §9.3; risk point R-5, test-pinned by `tests/cli_plan_apply.rs`).
//!
//! Limits (RFC 0015 §12): the manifest size cap travels through the
//! transport `ProtocolLimits` and surfaces as `cli.limit.manifest-size@1`
//! (limit class, exit 3) — never truncated disguised success. A manifest
//! write failure keeps the fsio `cli.write.*` codes (precondition class,
//! exit 4). A plan manifest that fails strict decode is a data error
//! (`cli.data.invalid-request@1`, exit 2), except transport `ResourceLimit`
//! (limit class).

use crate::query_cmd::FlowError;
use consema::protocol::{
    BatchPlanMessage, BatchResultMessage, ProtocolErrorKind, ProtocolLimits, decode_json,
    decode_pvce, encode_json,
};
use std::path::Path;

/// Encodes one `core.batch-plan@1` manifest as the canonical tagged JSON
/// bytes (RFC 0015 §3.1). The same bytes are the envelope payload content
/// and the `--output` file content.
///
/// A transport `ResourceLimit` (the manifest exceeds the protocol byte cap)
/// is a limit-class failure with `cli.limit.manifest-size@1`.
pub(crate) fn encode_manifest(manifest: &BatchPlanMessage) -> Result<Vec<u8>, FlowError> {
    let value = manifest
        .to_value()
        .map_err(crate::query_cmd::protocol_error)?;
    let bytes = encode_json(&value, ProtocolLimits::default()).map_err(|error| {
        if error.kind() == ProtocolErrorKind::ResourceLimit {
            FlowError::new(
                "cli.limit.manifest-size@1",
                format!("plan manifest exceeds the transport byte cap: {error}"),
            )
        } else {
            crate::query_cmd::protocol_error(error)
        }
    })?;
    Ok(bytes)
}

/// Persists one plan manifest to `--output` through the fsio atomic engine
/// (RFC 0015 §10: atomic replacement, symlink/read-only/directory policy,
/// read-back digest verification; a write failure keeps the `cli.write.*`
/// codes, precondition class, exit 4).
pub(crate) fn persist_manifest(path: &str, bytes: &[u8]) -> Result<(), FlowError> {
    crate::fsio::write_atomic(Path::new(path), bytes, crate::fsio::WriteOptions::default())
        .map(|_| ())
        .map_err(|error| {
            FlowError::new(
                error.code(),
                format!("cannot write plan manifest '{path}': {}", error.message()),
            )
        })
}

/// Strictly decodes one apply-input plan manifest (`core.batch-plan@1`,
/// RFC 0015 §3.2/§8.3): the transport is chosen by magic (`PVCE` prefix ->
/// PVCE/1, otherwise strict canonical JSON), and the record is revalidated
/// through its typed decoder (cross constraints included: `source_digest ==
/// source_patch.base_digest`, per-entry presence rules, patch structure).
///
/// A decode failure is a data error with `cli.data.invalid-request@1`
/// (RFC 0015 §5.1), except transport `ResourceLimit`, which is a limit error
/// with `cli.limit.manifest-size@1` (RFC 0015 §12).
pub(crate) fn decode_plan_manifest(bytes: &[u8]) -> Result<BatchPlanMessage, FlowError> {
    let limits = ProtocolLimits::default();
    let value = if bytes.starts_with(b"PVCE") {
        decode_pvce(bytes, limits)
    } else {
        decode_json(bytes, limits)
    }
    .map_err(|error| {
        if error.kind() == ProtocolErrorKind::ResourceLimit {
            FlowError::new(
                "cli.limit.manifest-size@1",
                format!("plan manifest exceeds the transport byte cap: {error}"),
            )
        } else {
            crate::query_cmd::protocol_error(error)
        }
    })?;
    BatchPlanMessage::from_value(&value).map_err(|error| {
        FlowError::new(
            "cli.data.invalid-request@1",
            format!("plan manifest is not a byte-valid core.batch-plan@1 record: {error}"),
        )
    })
}

/// Encodes one `core.batch-result@1` manifest as the canonical tagged JSON
/// bytes (RFC 0015 §3.1). The same bytes are the envelope payload content
/// and the result-manifest file content (RFC 0015 §8.3, byte-identical).
///
/// A transport `ResourceLimit` is a limit-class failure with
/// `cli.limit.manifest-size@1`.
pub(crate) fn encode_result_manifest(manifest: &BatchResultMessage) -> Result<Vec<u8>, FlowError> {
    let value = manifest.to_value();
    let bytes = encode_json(&value, ProtocolLimits::default()).map_err(|error| {
        if error.kind() == ProtocolErrorKind::ResourceLimit {
            FlowError::new(
                "cli.limit.manifest-size@1",
                format!("result manifest exceeds the transport byte cap: {error}"),
            )
        } else {
            crate::query_cmd::protocol_error(error)
        }
    })?;
    Ok(bytes)
}

/// Persists one result manifest (pending, completed, failed, or interrupted
/// state; RFC 0015 §9.3) through the fsio atomic engine. A write failure
/// keeps the `cli.write.*` codes, precondition class, exit 4.
pub(crate) fn persist_result_manifest(path: &str, bytes: &[u8]) -> Result<(), FlowError> {
    crate::fsio::write_atomic(Path::new(path), bytes, crate::fsio::WriteOptions::default())
        .map(|_| ())
        .map_err(|error| {
            FlowError::new(
                error.code(),
                format!("cannot write result manifest '{path}': {}", error.message()),
            )
        })
}
