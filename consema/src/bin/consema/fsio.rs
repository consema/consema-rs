//! The atomic file-write engine (RFC 0015 §10; implementation plan §4.1;
//! milestone M6, consumed by the apply and edit commands of M7/M8).
//!
//! One atomic write is the sequence: same-directory unique temporary file
//! (`{name}.consema-{pid}-{nonce}.tmp`, exclusive creation) → restricted
//! permissions (POSIX 0600) → write + flush + fsync → copy the target's
//! existing permissions onto the temporary file → atomic replacement per OS
//! semantics (POSIX `rename`; Windows `std::fs::rename`, which is
//! `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`) → read back and verify the
//! target digest. On any failure the temporary file is removed by the
//! [`TempGuard`] drop guard before the error returns; no cross-filesystem or
//! multi-file atomicity is ever claimed (RFC 0015 §10: fsio promises only
//! single-file atomic replacement).
//!
//! ## Write policy (frozen v1)
//!
//! - **Symlink/junction refusal (R-4)**: write paths reject symlink and
//!   junction targets by default (`cli.write.symlink-policy@1`); the check
//!   walks every path component (the target and each ancestor prefix), so a
//!   junction or symlink anywhere in the write path is refused, not just the
//!   final component. `WriteOptions::follow_symlinks` (the future
//!   `--follow-symlinks` flag) authorizes writing; v1 resolves the whole
//!   path with `std::fs::canonicalize` and writes the real file.
//! - **Read-only targets (R-3)**: a target marked read-only is rejected with
//!   `cli.write.read-only@1` *before* any temporary file is created. On
//!   Windows "read-only" is the `FILE_ATTRIBUTE_READONLY` attribute; on
//!   POSIX it is a file mode with no write bit set for any class (`mode &
//!   0o222 == 0`). See the measurement record below for the measured
//!   platform behavior that motivates the pre-check.
//! - **Directories**: a target that is a directory →
//!   `cli.write.target-is-directory@1`.
//! - **Newline and encoding policy**: the engine never transcodes and never
//!   rewrites newlines — the exact bytes passed in are the exact bytes
//!   written, verified by the read-back digest (UTF-16 and ISO-8859-1 files
//!   pass through unchanged; R-11).
//! - **Failure algebra**: permission denial → `cli.write.permission@1`;
//!   every other I/O failure (disk full, missing directory) →
//!   `cli.write.io@1`; the read-back digest mismatch is the typed
//!   `ReadBackMismatch` variant with the same `cli.write.io@1` code (RFC
//!   0015 §9.3 step 5 — matched structurally, never by message text); symlink
//!   policy → §above; read-only → §above. All are precondition-class
//!   failures (exit 4, RFC 0015 §5.1).
//! - **Create-if-missing**: when the target does not exist the replacement
//!   still creates it (the atomic rename creates the final entry); a missing
//!   *parent directory* is a `cli.write.io@1` failure, never a silent create
//!   of intermediate directories.
//! - **Temporary-file races**: same directory + unique nonce + exclusive
//!   creation (`create_new`); on a collision the nonce advances and the
//!   create is retried (bounded); digest revalidation is the only
//!   concurrency defense (RFC 0015 §10; R-10).
//!
//! ## Windows measurement record (R-3, measured on Windows 11, 2026-08-07)
//!
//! 1. `std::fs::rename` over a destination with the `READONLY` attribute:
//!    fails with `ErrorKind::PermissionDenied` (raw `MoveFileExW`
//!    `MOVEFILE_REPLACE_EXISTING` behavior). The v1 policy therefore
//!    pre-checks the attribute and reports the deterministic
//!    `cli.write.read-only@1` instead of a generic access-denied.
//! 2. POSIX `rename` over a read-only-mode target **succeeds** (rename needs
//!    only directory write access) — the pre-check is what honors the RFC's
//!    deterministic read-only rejection on every platform.
//! 3. `std::fs::symlink_metadata().file_type().is_symlink()` reports
//!    junctions (`IO_REPARSE_TAG_MOUNT_POINT`) as symlinks, so the std-only
//!    engine detects junction targets and junction components without
//!    platform code (probe test `windows_junction_...`).
//! 4. Windows ACL copying is not possible through std and is out of scope
//!    for 0.12.0: the temporary file inherits the directory ACL, and the
//!    readonly attribute is never carried because readonly targets are
//!    rejected. Full cross-platform permission verification is the 0.13.0
//!    gate (implementation plan §10, R-3).
//!
//! ## Failure injection
//!
//! Every filesystem step goes through the private [`FsBackend`] seam. The
//! production path uses [`RealBackend`]; the unit tests use [`FakeBackend`]
//! to force failures that cannot be produced deterministically against a
//! real filesystem (disk full, rename failure, read-back corruption,
//! permission denials), and to assert the residue-cleanup and
//! truthful-reporting behavior.

use consema::document::ContentDigest;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Bounded retries when the exclusive temporary-file creation collides.
const TEMP_CREATE_ATTEMPTS: u8 = 16;

/// Per-write policy options (RFC 0015 §10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteOptions {
    /// Authorize writing through symlink/junction targets (the future
    /// `--follow-symlinks` flag; RFC 0015 §10). v1 resolves the whole path
    /// with `std::fs::canonicalize` and writes the real file; the target
    /// must exist (a missing target cannot be resolved).
    pub follow_symlinks: bool,
}

impl WriteOptions {
    /// The frozen default: symlink and junction targets are refused.
    #[must_use]
    pub const fn default_secure() -> Self {
        Self {
            follow_symlinks: false,
        }
    }
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self::default_secure()
    }
}

/// One underlying I/O failure normalized to cloneable facts (`io::Error`
/// itself is neither `Clone` nor `Eq`, so the engine records its kind and
/// display text).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoFailure {
    /// The `std::io::ErrorKind` of the underlying failure.
    pub kind: io::ErrorKind,
    /// The underlying failure's display text.
    pub message: String,
}

impl IoFailure {
    fn from_error(error: io::Error) -> Self {
        let message = error.to_string();
        Self {
            kind: error.kind(),
            message,
        }
    }

    fn new(kind: io::ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// One frozen `cli.write.*` failure of an atomic write (RFC 0015 §13.1).
///
/// Every variant names the write target path for deterministic diagnostics;
/// the `source` field carries the normalized underlying failure for the
/// permission/I/O variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteError {
    /// The target (or a path component) is a symlink or junction and the
    /// policy refuses it; `--follow-symlinks` authorizes explicitly.
    SymlinkPolicy {
        /// The offending symlink/junction path component.
        target: PathBuf,
    },
    /// The target carries the read-only attribute (Windows) or has no write
    /// bit for any class (POSIX); `cli.write.read-only@1`.
    ReadOnly {
        /// The read-only target path.
        target: PathBuf,
    },
    /// The target is a directory; `cli.write.target-is-directory@1`.
    TargetIsDirectory {
        /// The directory target path.
        target: PathBuf,
    },
    /// Permission denied somewhere in the write path;
    /// `cli.write.permission@1`.
    Permission {
        /// The write target path.
        target: PathBuf,
        /// The normalized underlying failure.
        source: IoFailure,
    },
    /// Any other I/O failure (disk full, missing parent directory);
    /// `cli.write.io@1`.
    Io {
        /// The write target path.
        target: PathBuf,
        /// The normalized underlying failure.
        source: IoFailure,
    },
    /// The read-back digest verification failed after the atomic replace
    /// (RFC 0015 §9.3 step 5): the file has been replaced and is not rolled
    /// back; `cli.write.io@1`. The typed variant exists so the failure is
    /// matched structurally, never by string-matching the diagnostic text.
    ReadBackMismatch {
        /// The write target path.
        target: PathBuf,
        /// The normalized underlying failure.
        source: IoFailure,
    },
}

impl WriteError {
    /// The frozen `cli.write.*` code of the failure (RFC 0015 §13.1; all
    /// precondition-class, exit 4 per §5.2).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SymlinkPolicy { .. } => "cli.write.symlink-policy@1",
            Self::ReadOnly { .. } => "cli.write.read-only@1",
            Self::TargetIsDirectory { .. } => "cli.write.target-is-directory@1",
            Self::Permission { .. } => "cli.write.permission@1",
            Self::Io { .. } | Self::ReadBackMismatch { .. } => "cli.write.io@1",
        }
    }

    /// The write target path the failure is about.
    #[must_use]
    pub fn target(&self) -> &Path {
        match self {
            Self::SymlinkPolicy { target }
            | Self::ReadOnly { target }
            | Self::TargetIsDirectory { target }
            | Self::Permission { target, .. }
            | Self::Io { target, .. }
            | Self::ReadBackMismatch { target, .. } => target,
        }
    }

    /// Deterministic human diagnostic for stderr (the `(code ...)` suffix is
    /// appended by the caller, per the bin's stderr convention).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::SymlinkPolicy { target } => format!(
                "refusing to write through symlink or junction target '{}' \
                 (--follow-symlinks authorizes explicitly)",
                target.display()
            ),
            Self::ReadOnly { target } => {
                format!("target '{}' is read-only", target.display())
            }
            Self::TargetIsDirectory { target } => {
                format!("target '{}' is a directory", target.display())
            }
            Self::Permission { target, source } => format!(
                "permission denied writing '{}': {}",
                target.display(),
                source.message
            ),
            Self::Io { target, source } | Self::ReadBackMismatch { target, source } => format!(
                "I/O failure writing '{}': {}",
                target.display(),
                source.message
            ),
        }
    }
}

/// One batch write request (RFC 0015 §10: raw rendered bytes are written
/// verbatim, never transcoded).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteRequest {
    /// Target path spelling, used verbatim (no canonicalization; RFC 0015
    /// §3.3 path rule).
    pub target: PathBuf,
    /// Exact rendered bytes to write (newline/encoding policy: bytes in,
    /// bytes out).
    pub bytes: Vec<u8>,
}

/// The verified outcome of one atomic write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteOutcome {
    /// SHA-256 of the exact bytes written, verified by the read-back step.
    pub digest: ContentDigest,
    /// The path actually written: the target spelling, or the resolved real
    /// file when `follow_symlinks` was authorized.
    pub actual_path: PathBuf,
}

/// One per-file batch result; a failure never aborts the batch and never
/// disguises success (implementation plan §3.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteResult {
    /// The request's target path spelling.
    pub target: PathBuf,
    /// The write outcome or the frozen `cli.write.*` failure.
    pub outcome: Result<WriteOutcome, WriteError>,
}

/// Writes one file atomically (RFC 0015 §10; see the module docs for the
/// full policy and the Windows measurement record).
///
/// Returns the read-back-verified target digest and the actual written path.
pub fn write_atomic(
    target: &Path,
    bytes: &[u8],
    options: WriteOptions,
) -> Result<WriteOutcome, WriteError> {
    write_atomic_with(&RealBackend, target, bytes, options)
}

/// Batch-friendly entry point: writes each file independently and returns
/// one result per request, in request order. A per-file failure never aborts
/// the remaining files (and no multi-file atomicity is claimed).
#[must_use]
pub fn write_many(requests: &[WriteRequest], options: WriteOptions) -> Vec<WriteResult> {
    requests
        .iter()
        .map(|request| WriteResult {
            target: request.target.clone(),
            outcome: write_atomic(&request.target, &request.bytes, options),
        })
        .collect()
}

/// The filesystem seam every atomic-write step goes through.
///
/// The production path uses [`RealBackend`]; the failure-injection unit
/// tests substitute a fake that can force failures at each step (disk full,
/// rename failure, permission denials, read-back corruption) which cannot be
/// produced deterministically against a real filesystem.
trait FsBackend {
    /// `std::fs::symlink_metadata` (never follows the final component).
    fn symlink_metadata(&self, path: &Path) -> io::Result<fs::Metadata>;
    /// `std::fs::canonicalize` (resolves every symlink/junction component).
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    /// Exclusive (`create_new`) creation of the temporary file.
    fn create_new(&self, path: &Path) -> io::Result<File>;
    /// Writes all bytes, flushes, and fsyncs the temporary file.
    fn write_and_sync(&self, file: &File, bytes: &[u8]) -> io::Result<()>;
    /// Sets the permissions of one path (temp restriction / target copy).
    fn set_permissions(&self, path: &Path, permissions: fs::Permissions) -> io::Result<()>;
    /// Atomic replacement of `to` by `from` (POSIX `rename`; Windows
    /// `MoveFileExW` `MOVEFILE_REPLACE_EXISTING`).
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Reads a whole file back for digest verification.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Removes one file (temp residue cleanup).
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// The target's permissions, for the copy-before-replace step.
    fn permissions_of(&self, metadata: &fs::Metadata) -> fs::Permissions;
    /// Whether the target metadata marks the file read-only per the policy
    /// (Windows: `FILE_ATTRIBUTE_READONLY`; POSIX: no write bit for any
    /// class).
    fn is_readonly(&self, metadata: &fs::Metadata) -> bool;
}

/// The real [`FsBackend`]: plain `std::fs` with no extra behavior.
struct RealBackend;

impl FsBackend for RealBackend {
    fn symlink_metadata(&self, path: &Path) -> io::Result<fs::Metadata> {
        fs::symlink_metadata(path)
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path)
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(path)
    }

    fn write_and_sync(&self, mut file: &File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()
    }

    fn set_permissions(&self, path: &Path, permissions: fs::Permissions) -> io::Result<()> {
        fs::set_permissions(path, permissions)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn permissions_of(&self, metadata: &fs::Metadata) -> fs::Permissions {
        metadata.permissions()
    }

    fn is_readonly(&self, metadata: &fs::Metadata) -> bool {
        #[cfg(windows)]
        {
            metadata.permissions().readonly()
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o222 == 0
        }
    }
}

/// Process-wide nonce for temporary file names (uniqueness within the
/// process; exclusive creation is the filesystem-level guard).
static NEXT_NONCE: AtomicU64 = AtomicU64::new(0);

fn next_nonce() -> u64 {
    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}

/// The frozen temporary-file shape `{name}.consema-{pid}-{nonce}.tmp`
/// (RFC 0015 §10; pid/nonce never appear in any output record).
fn temp_path(dir: &Path, name: &std::ffi::OsStr, nonce: u64) -> PathBuf {
    let mut file_name = name.to_os_string();
    file_name.push(format!(".consema-{}-{nonce}.tmp", std::process::id()));
    dir.join(file_name)
}

/// Removes the temporary file on drop unless the write succeeded.
///
/// Best-effort cleanup (drop cannot report I/O errors; the residue is also
/// covered by the apply manifest state machine at the command level). On
/// success [`Self::disarm`] keeps the renamed-away temp path from being
/// touched.
struct TempGuard<'a, B: FsBackend> {
    backend: &'a B,
    path: PathBuf,
    armed: bool,
}

impl<B: FsBackend> Drop for TempGuard<'_, B> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.backend.remove_file(&self.path);
        }
    }
}

impl<B: FsBackend> TempGuard<'_, B> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

/// Maps one raw I/O failure to the frozen `cli.write.*` algebra
/// (RFC 0015 §13.1: permission denial → permission, everything else → io).
fn classify(target: &Path, error: io::Error) -> WriteError {
    let source = IoFailure::from_error(error);
    match source.kind {
        io::ErrorKind::PermissionDenied => WriteError::Permission {
            target: target.to_path_buf(),
            source,
        },
        _ => WriteError::Io {
            target: target.to_path_buf(),
            source,
        },
    }
}

/// The core pipeline, parameterized over the backend for failure injection.
fn write_atomic_with<B: FsBackend>(
    backend: &B,
    target: &Path,
    bytes: &[u8],
    options: WriteOptions,
) -> Result<WriteOutcome, WriteError> {
    let resolved: PathBuf = if options.follow_symlinks {
        // v1 --follow-symlinks semantics: resolve the whole path and write
        // the real file; the target must exist.
        backend
            .canonicalize(target)
            .map_err(|error| classify(target, error))?
    } else {
        target.to_path_buf()
    };
    if !options.follow_symlinks {
        refuse_symlink_components(backend, &resolved)?;
    }
    // Target facts: symlink / directory / read-only (R-4, R-3). The symlink
    // check precedes the directory check so a junction (a directory reparse
    // point that std reports as symlink) is refused as a symlink, not
    // misreported as a directory target.
    let target_metadata: Option<fs::Metadata> = match backend.symlink_metadata(&resolved) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(WriteError::SymlinkPolicy {
                    target: resolved.clone(),
                });
            }
            if metadata.file_type().is_dir() {
                return Err(WriteError::TargetIsDirectory {
                    target: resolved.clone(),
                });
            }
            if backend.is_readonly(&metadata) {
                return Err(WriteError::ReadOnly {
                    target: resolved.clone(),
                });
            }
            Some(metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(classify(&resolved, error)),
    };
    let Some(name) = resolved.file_name() else {
        return Err(WriteError::Io {
            target: resolved.clone(),
            source: IoFailure::new(io::ErrorKind::InvalidInput, "target path has no file name"),
        });
    };
    let dir = resolved.parent().unwrap_or_else(|| Path::new(""));
    // Exclusive temporary-file creation with bounded nonce retries
    // (RFC 0015 §10: same directory + unique nonce + exclusive creation).
    let mut collision: Option<io::Error> = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let temp = temp_path(dir, name, next_nonce());
        match backend.create_new(&temp) {
            Ok(file) => {
                let mut guard = TempGuard {
                    backend,
                    path: temp.clone(),
                    armed: true,
                };
                return finish_write(
                    backend,
                    &mut guard,
                    &file,
                    &resolved,
                    bytes,
                    target_metadata.as_ref(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                collision = Some(error);
            }
            Err(error) => return Err(classify(&resolved, error)),
        }
    }
    Err(WriteError::Io {
        target: resolved,
        source: IoFailure::new(
            io::ErrorKind::AlreadyExists,
            collision.map_or_else(
                || "temporary-file nonce collisions exhausted".to_owned(),
                |error| format!("temporary-file nonce collisions exhausted: {error}"),
            ),
        ),
    })
}

/// Refuses any symlink or junction component in the write path (R-4): the
/// target itself and every ancestor prefix are inspected with
/// `symlink_metadata`, so a junction directory in the middle of the path is
/// refused, not just a final-component link. A prefix that does not exist
/// (a missing parent) is skipped — the temporary-file creation surfaces the
/// real failure with its own classification; any other inspection failure
/// (e.g. permission denial) is a refusal-worthy condition and classifies
/// normally.
///
/// macOS system-temp carve-out: the walk stops once it reaches the system
/// temp root, whose ancestors are exempt. On macOS `std::env::temp_dir()`
/// returns `/var/folders/...` and `/var → /private/var` is a system symlink
/// sitting in every temp-dir path, so without the carve-out every write
/// under the system temp tree would be refused. Components strictly inside
/// the temp tree (below the temp root) are still inspected, so
/// user-controlled symlink/junction targets and components — including the
/// probe tests' symlinks and junctions created under the temp dir — are
/// refused exactly as before; only the system-owned temp root and its
/// ancestors are exempt, and paths outside the temp root are still walked
/// to the filesystem root.
fn refuse_symlink_components<B: FsBackend>(backend: &B, target: &Path) -> Result<(), WriteError> {
    let mut prefix = target.to_path_buf();
    loop {
        // R-4 macOS system-temp carve-out: the walk reached the temp root —
        // every component strictly below it has already been inspected, and
        // the root and its ancestors are system-owned (macOS `/var →
        // /private/var`).
        if is_system_temp_prefix(&prefix) {
            return Ok(());
        }
        match backend.symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(WriteError::SymlinkPolicy { target: prefix });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(classify(target, error)),
        }
        if !prefix.pop() {
            break;
        }
    }
    Ok(())
}

/// `true` when `prefix` is the system temp root or one of its ancestors —
/// the exempt region of the R-4 walk (see [`refuse_symlink_components`]).
/// Both spellings are compared: the raw `std::env::temp_dir()` path (on
/// macOS `/var/folders/...`, from `$TMPDIR`) and its canonical form
/// (`/private/var/folders/...`, after resolving the `/var → /private/var`
/// system symlink). Resolved once per process.
fn is_system_temp_prefix(prefix: &Path) -> bool {
    static TEMP_ROOTS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    let (raw, canonical) = TEMP_ROOTS.get_or_init(|| {
        let raw = std::env::temp_dir();
        let canonical = fs::canonicalize(&raw).unwrap_or_else(|_| raw.clone());
        (raw, canonical)
    });
    raw.starts_with(prefix) || canonical.starts_with(prefix)
}

/// The steps after the temporary file exists, in the frozen order
/// (RFC 0015 §10): restricted permissions → write + fsync → copy target
/// permissions → atomic replace → read-back digest verification. Any error
/// returns through the guard, which removes the temporary file.
fn finish_write<B: FsBackend>(
    backend: &B,
    guard: &mut TempGuard<'_, B>,
    file: &File,
    resolved: &Path,
    bytes: &[u8],
    target_metadata: Option<&fs::Metadata>,
) -> Result<WriteOutcome, WriteError> {
    restrict_temp_permissions(backend, &guard.path, resolved)?;
    backend
        .write_and_sync(file, bytes)
        .map_err(|error| classify(resolved, error))?;
    if let Some(metadata) = target_metadata {
        copy_target_permissions(backend, &guard.path, metadata, resolved)?;
    }
    backend
        .rename(&guard.path, resolved)
        .map_err(|error| classify(resolved, error))?;
    // Read-back digest verification (RFC 0015 §9.3 step 5): a mismatch means
    // the file has been replaced and is not rolled back — the damage is
    // recorded truthfully, never disguised as success.
    let read_back = backend
        .read(resolved)
        .map_err(|error| classify(resolved, error))?;
    let digest = ContentDigest::of(&read_back);
    if digest != ContentDigest::of(bytes) {
        return Err(WriteError::ReadBackMismatch {
            target: resolved.to_path_buf(),
            source: IoFailure::new(
                io::ErrorKind::InvalidData,
                format!(
                    "read-back digest mismatch after atomic replace of '{}' \
                     (the file has been replaced and is not rolled back; \
                     expected {}, read {})",
                    resolved.display(),
                    ContentDigest::of(bytes).to_hex(),
                    digest.to_hex(),
                ),
            ),
        });
    }
    guard.disarm();
    Ok(WriteOutcome {
        digest,
        actual_path: resolved.to_path_buf(),
    })
}

/// Restricts the temporary file to POSIX 0600 before any content is written
/// (RFC 0015 §10). On Windows the temporary file inherits the directory ACL;
/// std offers no restricted-permission creation, recorded in the module's
/// measurement record (0.13.0 cross-platform gate).
#[cfg(unix)]
fn restrict_temp_permissions<B: FsBackend>(
    backend: &B,
    temp: &Path,
    target: &Path,
) -> Result<(), WriteError> {
    use std::os::unix::fs::PermissionsExt;
    backend
        .set_permissions(temp, fs::Permissions::from_mode(0o600))
        .map_err(|error| classify(target, error))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // the Windows v1 policy is a deliberate no-op
fn restrict_temp_permissions<B: FsBackend>(
    _backend: &B,
    _temp: &Path,
    _target: &Path,
) -> Result<(), WriteError> {
    Ok(())
}

/// Copies the target's existing permissions onto the temporary file before
/// the replacement (RFC 0015 §10, "when the OS supports it"). POSIX: the
/// full mode is copied. Windows v1: no-op — std cannot copy ACLs, and the
/// readonly attribute is never carried because readonly targets are rejected
/// upstream (module measurement record; 0.13.0 cross-platform gate).
#[cfg(unix)]
fn copy_target_permissions<B: FsBackend>(
    backend: &B,
    temp: &Path,
    metadata: &fs::Metadata,
    target: &Path,
) -> Result<(), WriteError> {
    backend
        .set_permissions(temp, backend.permissions_of(metadata))
        .map_err(|error| classify(target, error))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // the Windows v1 policy is a deliberate no-op
fn copy_target_permissions<B: FsBackend>(
    _backend: &B,
    _temp: &Path,
    _metadata: &fs::Metadata,
    _target: &Path,
) -> Result<(), WriteError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

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
            fs::create_dir_all(&path).expect("create test scratch dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Asserts the directory contains no leftover `*.consema-*.tmp` residue.
    fn assert_no_temp_residue(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read dir") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.contains(".consema-") || !name.ends_with(".tmp"),
                "temp residue left behind: {name}"
            );
        }
    }

    fn temp_file_names_in(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| {
                let name = entry.expect("dir entry").file_name();
                name.to_string_lossy().into_owned()
            })
            .filter(|name| {
                name.contains(".consema-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension == "tmp")
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // The injectable test backend
    // ------------------------------------------------------------------

    /// One injectable failure point of the write pipeline.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        /// `symlink_metadata` / `canonicalize` inspection.
        Inspect,
        /// Exclusive temporary-file creation.
        CreateTemp,
        /// Write + flush + fsync of the temporary file.
        WriteSync,
        /// Permission setting (restriction and target copy).
        SetPermissions,
        /// Atomic rename.
        Rename,
        /// Read-back verification.
        ReadBack,
    }

    /// The failure-injection backend: real filesystem behavior for every
    /// step except the explicitly injected ones, plus a tamper switch for
    /// the read-back digest check and an event log for residue/ordering
    /// assertions.
    struct FakeBackend {
        real: RealBackend,
        injections: RefCell<Vec<(Step, io::ErrorKind)>>,
        tamper_read: Cell<bool>,
        events: RefCell<Vec<String>>,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                real: RealBackend,
                injections: RefCell::new(Vec::new()),
                tamper_read: Cell::new(false),
                events: RefCell::new(Vec::new()),
            }
        }

        fn inject(&self, step: Step, kind: io::ErrorKind) {
            self.injections.borrow_mut().push((step, kind));
        }

        /// Makes the read-back return corrupted bytes (one flipped byte).
        fn tamper_read_back(&self) {
            self.tamper_read.set(true);
        }

        /// Consumes the first injection registered for the step, if any.
        fn take(&self, step: Step) -> Option<io::ErrorKind> {
            let mut injections = self.injections.borrow_mut();
            let index = injections.iter().position(|(s, _)| *s == step)?;
            Some(injections.remove(index).1)
        }

        fn record(&self, event: String) {
            self.events.borrow_mut().push(event);
        }

        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl FsBackend for FakeBackend {
        fn symlink_metadata(&self, path: &Path) -> io::Result<fs::Metadata> {
            if let Some(kind) = self.take(Step::Inspect) {
                return Err(io::Error::new(kind, "injected inspection failure"));
            }
            self.real.symlink_metadata(path)
        }

        fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
            if let Some(kind) = self.take(Step::Inspect) {
                return Err(io::Error::new(kind, "injected inspection failure"));
            }
            self.real.canonicalize(path)
        }

        fn create_new(&self, path: &Path) -> io::Result<File> {
            self.record(format!("create:{}", path.display()));
            if let Some(kind) = self.take(Step::CreateTemp) {
                return Err(io::Error::new(kind, "injected temp creation failure"));
            }
            self.real.create_new(path)
        }

        fn write_and_sync(&self, file: &File, bytes: &[u8]) -> io::Result<()> {
            self.record(format!("write:{}", bytes.len()));
            if let Some(kind) = self.take(Step::WriteSync) {
                return Err(io::Error::new(kind, "injected write failure"));
            }
            self.real.write_and_sync(file, bytes)
        }

        fn set_permissions(&self, path: &Path, permissions: fs::Permissions) -> io::Result<()> {
            self.record(format!("chmod:{}", path.display()));
            if let Some(kind) = self.take(Step::SetPermissions) {
                return Err(io::Error::new(kind, "injected permission failure"));
            }
            self.real.set_permissions(path, permissions)
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.record(format!("rename:{}->{}", from.display(), to.display()));
            if let Some(kind) = self.take(Step::Rename) {
                return Err(io::Error::new(kind, "injected rename failure"));
            }
            self.real.rename(from, to)
        }

        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.record(format!("read:{}", path.display()));
            if let Some(kind) = self.take(Step::ReadBack) {
                return Err(io::Error::new(kind, "injected read-back failure"));
            }
            let mut bytes = self.real.read(path)?;
            if self.tamper_read.get() {
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0xFF;
                } else {
                    bytes.push(0x01);
                }
            }
            Ok(bytes)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.record(format!("remove:{}", path.display()));
            self.real.remove_file(path)
        }

        fn permissions_of(&self, metadata: &fs::Metadata) -> fs::Permissions {
            self.real.permissions_of(metadata)
        }

        fn is_readonly(&self, metadata: &fs::Metadata) -> bool {
            self.real.is_readonly(metadata)
        }
    }

    // ------------------------------------------------------------------
    // Success matrix
    // ------------------------------------------------------------------

    #[test]
    fn write_atomic_creates_a_missing_target_and_verifies_the_digest() {
        let dir = TestDir::new("create");
        let target = dir.join("app.conf");
        let bytes = b"[section]\nvalue = 1\n";
        let outcome =
            write_atomic(&target, bytes, WriteOptions::default()).expect("create-if-missing write");
        assert_eq!(outcome.digest, ContentDigest::of(bytes));
        assert_eq!(outcome.actual_path, target);
        assert_eq!(fs::read(&target).expect("read back"), bytes);
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn write_atomic_replaces_an_existing_target_atomically() {
        let dir = TestDir::new("replace");
        let target = dir.join("app.conf");
        fs::write(&target, b"old content\n").expect("seed target");
        let bytes = b"new content\n";
        let outcome =
            write_atomic(&target, bytes, WriteOptions::default()).expect("replacement write");
        assert_eq!(outcome.digest, ContentDigest::of(bytes));
        assert_eq!(fs::read(&target).expect("read back"), bytes);
        assert_no_temp_residue(&dir.path);
        // Permissions survive the replacement on POSIX (0600 seeded target).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("set seed mode");
            write_atomic(&target, bytes, WriteOptions::default()).expect("second replace");
            let mode = fs::metadata(&target)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o640, "target mode is copied to the replacement");
        }
    }

    #[test]
    fn write_atomic_writes_empty_bytes() {
        let dir = TestDir::new("empty");
        let target = dir.join("empty.conf");
        let outcome = write_atomic(&target, b"", WriteOptions::default()).expect("empty write");
        assert_eq!(outcome.digest, ContentDigest::of(b""));
        assert_eq!(fs::read(&target).expect("read back"), b"");
    }

    #[test]
    fn write_atomic_never_transcodes_bytes_or_newlines() {
        // Newline/encoding policy (RFC 0015 §10; R-11): raw bytes in, raw
        // bytes out — CRLF newlines and a UTF-16LE BOM pass through exactly.
        let dir = TestDir::new("bytes");
        let target = dir.join("app.conf");
        let bytes: &[u8] = &[
            0xFF, 0xFE, // UTF-16LE BOM
            b'v', 0x00, b'a', 0x00, b'l', 0x00, b'u', 0x00, b'e', 0x00, b'=', 0x00, b'1', 0x00,
            b'\r', 0x00, b'\n', 0x00,
        ];
        let outcome = write_atomic(&target, bytes, WriteOptions::default()).expect("write");
        assert_eq!(outcome.digest, ContentDigest::of(bytes));
        assert_eq!(fs::read(&target).expect("read back"), bytes);
        // A second replacement with CRLF-only bytes is equally verbatim.
        let crlf: &[u8] = b"key = \"a\r\nb\"\r\n";
        write_atomic(&target, crlf, WriteOptions::default()).expect("crlf write");
        assert_eq!(fs::read(&target).expect("read back"), crlf);
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn write_atomic_digests_are_deterministic() {
        let dir = TestDir::new("determinism");
        let first = dir.join("a.conf");
        let second = dir.join("b.conf");
        let bytes = b"token = hunter2\n";
        let first_outcome = write_atomic(&first, bytes, WriteOptions::default()).expect("write a");
        let second_outcome =
            write_atomic(&second, bytes, WriteOptions::default()).expect("write b");
        assert_eq!(first_outcome.digest, second_outcome.digest);
        assert_eq!(first_outcome.digest, ContentDigest::of(bytes));
    }

    #[test]
    fn temp_file_names_follow_the_frozen_shape() {
        let name = std::ffi::OsStr::new("app.conf");
        let temp = temp_path(Path::new(r"C:\cfg"), name, 7);
        let file_name = temp.file_name().expect("temp file name").to_string_lossy();
        assert!(file_name.starts_with("app.conf.consema-"), "{file_name}");
        assert!(file_name.ends_with("-7.tmp"), "{file_name}");
        let middle = &file_name["app.conf.consema-".len()..file_name.len() - "-7.tmp".len()];
        assert_eq!(
            middle,
            std::process::id().to_string(),
            "the middle is the pid: {file_name}"
        );
    }

    // ------------------------------------------------------------------
    // Policy rejections (real filesystem)
    // ------------------------------------------------------------------

    #[test]
    fn write_atomic_rejects_a_directory_target() {
        let dir = TestDir::new("dir-target");
        let target = dir.join("subdir");
        fs::create_dir(&target).expect("seed directory");
        let error =
            write_atomic(&target, b"x", WriteOptions::default()).expect_err("directory target");
        assert_eq!(error.code(), "cli.write.target-is-directory@1");
        assert_eq!(error.target(), target);
        assert!(!error.message().is_empty());
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn write_atomic_rejects_a_missing_parent_directory() {
        let dir = TestDir::new("missing-dir");
        let target = dir.path.join("missing").join("app.conf");
        let error =
            write_atomic(&target, b"x", WriteOptions::default()).expect_err("missing parent");
        assert_eq!(error.code(), "cli.write.io@1");
        // Nothing is created silently (no intermediate directories).
        assert!(!target.exists());
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    // The clippy warning about `set_readonly(false)` targets Unix semantics
    // (world-writable); the call below is cfg(windows)-only and is the only
    // std way to clear the READONLY attribute before the test rewrite.
    #[allow(clippy::permissions_set_readonly_false)]
    fn write_atomic_rejects_a_readonly_target_and_measures_raw_rename() {
        let dir = TestDir::new("readonly");
        let target = dir.join("app.conf");
        let original = b"secret = hunter2\n";
        fs::write(&target, original).expect("seed target");
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&target).expect("metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&target, permissions).expect("mark readonly");
            assert!(
                fs::metadata(&target)
                    .expect("metadata")
                    .permissions()
                    .readonly(),
                "readonly attribute set"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o444))
                .expect("mark readonly mode");
        }

        // Measurement (R-3): what does the raw rename do over a read-only
        // destination, without the policy pre-check?
        let src = dir.join("raw-src.tmp");
        fs::write(&src, b"x").expect("seed raw source");
        let raw = fs::rename(&src, &target);
        #[cfg(windows)]
        {
            // Measured on Windows 11: MoveFileExW(MOVEFILE_REPLACE_EXISTING)
            // fails with PermissionDenied when the destination carries the
            // READONLY attribute.
            let error = raw.expect_err("raw rename over a readonly destination");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::read(&target).expect("target untouched"), original);
        }
        #[cfg(unix)]
        {
            // Measured: POSIX rename succeeds over a read-only-mode target
            // (rename needs only directory write access). This is exactly why
            // the policy pre-check exists — without it the RFC's read-only
            // rejection would be silently bypassed on POSIX.
            raw.expect("raw rename over a read-only-mode destination");
        }
        // Restore the read-only target for the policy outcome assertion
        // (the Windows attribute must be cleared before the rewrite).
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&target).expect("metadata").permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&target, permissions).expect("clear readonly");
        }
        fs::write(&target, original).expect("rewrite target");
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&target).expect("metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&target, permissions).expect("mark readonly");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o444))
                .expect("mark readonly mode");
        }

        // Policy outcome (both platforms): the pre-check rejects the target
        // before any temporary file exists, and the target bytes are
        // untouched.
        let error = write_atomic(&target, b"new content", WriteOptions::default())
            .expect_err("read-only target");
        assert_eq!(error.code(), "cli.write.read-only@1");
        assert_eq!(error.target(), target);
        assert_eq!(fs::read(&target).expect("target untouched"), original);
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    #[cfg(unix)]
    fn write_atomic_refuses_symlink_targets_and_components_by_default() {
        let dir = TestDir::new("symlink");
        let real = dir.join("real");
        fs::create_dir(&real).expect("real dir");
        fs::write(real.join("app.conf"), b"old").expect("seed real file");
        let link_dir = dir.join("link-dir");
        std::os::unix::fs::symlink(&real, &link_dir).expect("create directory symlink");

        // A symlink as the final component of the write path.
        let link_file = dir.join("link-file");
        std::os::unix::fs::symlink(real.join("app.conf"), &link_file).expect("create file symlink");
        let error = write_atomic(&link_file, b"new", WriteOptions::default())
            .expect_err("final-component symlink");
        assert_eq!(error.code(), "cli.write.symlink-policy@1");
        assert_eq!(error.target(), link_file);

        // A symlink as an intermediate component (write through the link dir).
        let through = link_dir.join("other.conf");
        let error = write_atomic(&through, b"new", WriteOptions::default())
            .expect_err("intermediate-component symlink");
        assert_eq!(error.code(), "cli.write.symlink-policy@1");
        assert_eq!(error.target(), link_dir, "the offending component is named");

        // Nothing was written through the link.
        assert_eq!(fs::read(real.join("app.conf")).expect("real file"), b"old");
        assert!(!real.join("other.conf").exists());
        assert_no_temp_residue(&real);
    }

    #[test]
    #[cfg(unix)]
    fn follow_symlinks_resolves_and_writes_the_real_file() {
        let dir = TestDir::new("follow");
        let real = dir.join("real");
        fs::create_dir(&real).expect("real dir");
        let real_file = real.join("app.conf");
        fs::write(&real_file, b"old").expect("seed real file");
        let link_dir = dir.join("link-dir");
        std::os::unix::fs::symlink(&real, &link_dir).expect("create directory symlink");
        let options = WriteOptions {
            follow_symlinks: true,
        };
        let bytes = b"new content";
        let outcome = write_atomic(&link_dir.join("app.conf"), bytes, options)
            .expect("authorized write through the link");
        assert_eq!(outcome.digest, ContentDigest::of(bytes));
        assert_eq!(
            outcome.actual_path,
            fs::canonicalize(&real_file).expect("canonical")
        );
        // The real file changed; the link entry is still a symlink.
        assert_eq!(fs::read(&real_file).expect("real file"), bytes);
        assert!(
            fs::symlink_metadata(&link_dir)
                .expect("link metadata")
                .file_type()
                .is_symlink()
        );
        assert_no_temp_residue(&real);
        // A missing target cannot be resolved.
        let error = write_atomic(&link_dir.join("missing.conf"), b"x", options)
            .expect_err("missing target with follow");
        assert_eq!(error.code(), "cli.write.io@1");
    }

    #[test]
    #[cfg(windows)]
    fn windows_junction_is_detected_as_symlink_and_refused() {
        // Probe (R-4): a junction created with `cmd /c mklink /J` (no
        // administrator rights needed) — measured on Windows 11.
        let dir = TestDir::new("junction");
        let real = dir.join("real");
        fs::create_dir(&real).expect("real dir");
        fs::write(real.join("app.conf"), b"old").expect("seed real file");
        let junction = dir.join("junction");
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction.to_str().expect("utf8 path"),
                real.to_str().expect("utf8 path"),
            ])
            .output()
            .expect("run mklink");
        if !output.status.success() {
            // Environment without cmd/mklink (unusual CI sandboxes): the
            // probe is skipped, not failed — the symlink policy itself is
            // covered by the POSIX symlink tests and the std
            // is_symlink() contract recorded in the module docs.
            eprintln!(
                "skipping junction probe: mklink unavailable ({})",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return;
        }

        // Measurement: Rust std reports the junction (a
        // IO_REPARSE_TAG_MOUNT_POINT reparse point) as a symlink.
        let metadata = fs::symlink_metadata(&junction).expect("junction metadata");
        assert!(
            metadata.file_type().is_symlink(),
            "measured: std::fs::symlink_metadata reports junctions as symlinks"
        );

        // The junction itself as the write target.
        let error =
            write_atomic(&junction, b"x", WriteOptions::default()).expect_err("junction target");
        assert_eq!(error.code(), "cli.write.symlink-policy@1");
        assert_eq!(error.target(), junction);

        // A write *through* the junction (intermediate component) is refused
        // too — the junction must not be used as a path segment.
        let through = junction.join("app.conf");
        let error = write_atomic(&through, b"new", WriteOptions::default())
            .expect_err("path through a junction");
        assert_eq!(error.code(), "cli.write.symlink-policy@1");
        assert_eq!(error.target(), junction, "the junction component is named");

        // Nothing was written into the real directory through the junction.
        assert_eq!(fs::read(real.join("app.conf")).expect("real file"), b"old");
        assert_no_temp_residue(&real);
    }

    // ------------------------------------------------------------------
    // Failure injection matrix
    // ------------------------------------------------------------------

    #[test]
    fn injected_temp_creation_failure_is_permission_or_io() {
        let dir = TestDir::new("inject-create");
        let target = dir.join("app.conf");
        let backend = FakeBackend::new();
        backend.inject(Step::CreateTemp, io::ErrorKind::PermissionDenied);
        let error = write_atomic_with(&backend, &target, b"x", WriteOptions::default())
            .expect_err("injected create failure");
        assert_eq!(error.code(), "cli.write.permission@1");
        assert_eq!(error.target(), target);
        assert_no_temp_residue(&dir.path);
        assert!(!target.exists(), "no file appears on a failed write");

        // Disk-full style failures classify as io, not permission.
        let backend = FakeBackend::new();
        backend.inject(Step::CreateTemp, io::ErrorKind::StorageFull);
        let error = write_atomic_with(&backend, &target, b"x", WriteOptions::default())
            .expect_err("injected disk full");
        assert_eq!(error.code(), "cli.write.io@1");
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn injected_write_disk_full_fails_and_cleans_the_temp_file() {
        let dir = TestDir::new("inject-write");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.inject(Step::WriteSync, io::ErrorKind::StorageFull);
        let error = write_atomic_with(&backend, &target, b"new content", WriteOptions::default())
            .expect_err("injected disk full on write");
        assert_eq!(error.code(), "cli.write.io@1");
        // The target is untouched and the temp file was removed by the guard.
        assert_eq!(fs::read(&target).expect("target untouched"), b"old");
        let events = backend.events();
        assert!(
            events.iter().any(|event| event.starts_with("remove:")),
            "guard removed the temp file: {events:?}"
        );
        assert_no_temp_residue(&dir.path);
        assert!(temp_file_names_in(&dir.path).is_empty());
    }

    #[test]
    fn injected_rename_failure_is_permission_and_leaves_no_residue() {
        let dir = TestDir::new("inject-rename");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.inject(Step::Rename, io::ErrorKind::PermissionDenied);
        let error = write_atomic_with(&backend, &target, b"new content", WriteOptions::default())
            .expect_err("injected rename failure");
        assert_eq!(error.code(), "cli.write.permission@1");
        assert_eq!(fs::read(&target).expect("target untouched"), b"old");
        let events = backend.events();
        assert!(
            events.iter().any(|event| event.starts_with("remove:")),
            "guard removed the temp file: {events:?}"
        );
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn injected_read_back_failure_is_reported_truthfully() {
        // RFC 0015 §9.3 step 5: the read-back verification failure is
        // recorded truthfully; the file has been replaced and is not rolled
        // back.
        let dir = TestDir::new("inject-readback");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.inject(Step::ReadBack, io::ErrorKind::PermissionDenied);
        let error = write_atomic_with(&backend, &target, b"new content", WriteOptions::default())
            .expect_err("injected read-back failure");
        assert_eq!(error.code(), "cli.write.permission@1");
        assert_eq!(
            fs::read(&target).expect("read back"),
            b"new content",
            "the file has been replaced and is not rolled back (RFC 0015 §9.3 step 5)"
        );
        let events = backend.events();
        assert!(
            events.iter().any(|event| event.starts_with("rename:")),
            "the replacement happened before the read-back: {events:?}"
        );
        // The guard still attempts best-effort cleanup of the (already
        // renamed-away) temp path; the real removal is a silent no-op because
        // the path no longer exists, and the directory holds no residue.
        assert_no_temp_residue(&dir.path);
        assert!(temp_file_names_in(&dir.path).is_empty());
    }

    #[test]
    fn injected_read_back_digest_mismatch_is_an_io_failure() {
        let dir = TestDir::new("inject-tamper");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.tamper_read_back();
        let error = write_atomic_with(&backend, &target, b"new content", WriteOptions::default())
            .expect_err("tampered read-back");
        assert!(
            matches!(&error, WriteError::ReadBackMismatch { .. }),
            "the mismatch is the typed ReadBackMismatch variant: {error:?}"
        );
        assert_eq!(error.code(), "cli.write.io@1");
        assert!(
            error.message().contains("read-back digest mismatch"),
            "the mismatch is named: {}",
            error.message()
        );
        assert!(
            error.message().contains("not rolled back"),
            "{}",
            error.message()
        );
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    #[cfg(unix)]
    fn injected_permission_set_failure_is_permission() {
        let dir = TestDir::new("inject-chmod");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.inject(Step::SetPermissions, io::ErrorKind::PermissionDenied);
        let error = write_atomic_with(&backend, &target, b"new", WriteOptions::default())
            .expect_err("injected permission failure");
        assert_eq!(error.code(), "cli.write.permission@1");
        assert_eq!(fs::read(&target).expect("target untouched"), b"old");
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn temp_creation_collisions_retry_with_a_fresh_nonce() {
        let dir = TestDir::new("collision");
        let target = dir.join("app.conf");
        let backend = FakeBackend::new();
        backend.inject(Step::CreateTemp, io::ErrorKind::AlreadyExists);
        let outcome =
            write_atomic_with(&backend, &target, b"ok", WriteOptions::default()).expect("retried");
        assert_eq!(outcome.digest, ContentDigest::of(b"ok"));
        assert_eq!(fs::read(&target).expect("read back"), b"ok");
        let events = backend.events();
        let creates: Vec<&String> = events
            .iter()
            .filter(|event| event.starts_with("create:"))
            .collect();
        assert_eq!(creates.len(), 2, "one collision, one retry: {events:?}");
        assert_ne!(creates[0], creates[1], "the nonce advanced");
        assert_no_temp_residue(&dir.path);
    }

    #[test]
    fn injected_inspection_failure_classifies_by_its_kind() {
        let dir = TestDir::new("inject-inspect");
        let target = dir.join("app.conf");
        fs::write(&target, b"old").expect("seed target");
        let backend = FakeBackend::new();
        backend.inject(Step::Inspect, io::ErrorKind::PermissionDenied);
        let error = write_atomic_with(&backend, &target, b"new", WriteOptions::default())
            .expect_err("injected inspection failure");
        assert_eq!(error.code(), "cli.write.permission@1");
        assert_no_temp_residue(&dir.path);
    }

    // ------------------------------------------------------------------
    // Batch semantics
    // ------------------------------------------------------------------

    #[test]
    fn write_many_reports_per_file_results_without_aborting_the_batch() {
        let dir = TestDir::new("batch");
        let good_a = dir.join("a.conf");
        let readonly = dir.join("b.conf");
        let good_c = dir.join("c.conf");
        fs::write(&readonly, b"old").expect("seed readonly target");
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&readonly).expect("metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&readonly, permissions).expect("mark readonly");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&readonly, fs::Permissions::from_mode(0o444))
                .expect("mark readonly mode");
        }
        let requests = vec![
            WriteRequest {
                target: good_a.clone(),
                bytes: b"one".to_vec(),
            },
            WriteRequest {
                target: readonly.clone(),
                bytes: b"two".to_vec(),
            },
            WriteRequest {
                target: good_c.clone(),
                bytes: b"three".to_vec(),
            },
        ];
        let results = write_many(&requests, WriteOptions::default());
        assert_eq!(results.len(), 3, "one result per request, in order");
        assert_eq!(results[0].target, good_a);
        assert_eq!(
            results[0].outcome.as_ref().expect("a succeeds").digest,
            ContentDigest::of(b"one")
        );
        assert_eq!(results[1].target, readonly);
        assert_eq!(
            results[1]
                .outcome
                .as_ref()
                .expect_err("b is read-only")
                .code(),
            "cli.write.read-only@1"
        );
        assert_eq!(results[2].target, good_c);
        assert_eq!(
            results[2].outcome.as_ref().expect("c succeeds").digest,
            ContentDigest::of(b"three")
        );
        // Successes landed; the failed file is untouched; no residue.
        assert_eq!(fs::read(&good_a).expect("a written"), b"one");
        assert_eq!(fs::read(&good_c).expect("c written"), b"three");
        assert_eq!(fs::read(&readonly).expect("b untouched"), b"old");
        assert_no_temp_residue(&dir.path);
    }
}
