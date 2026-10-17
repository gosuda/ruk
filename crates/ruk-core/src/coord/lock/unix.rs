//! POSIX ownership-file mechanics: no-follow open, mode 0600, lifetime
//! flock, and effective-user/regular-file/single-link/no-group-other
//! validation.
//!
//! Contention closes its handle and reports `None`; the common module then
//! reads the body for a contender snapshot. Real I/O failures are
//! [`ErrorCode::EIo`]; symlink, ownership, link-count, and mode violations
//! are [`ErrorCode::EForbidden`]. This module never chmods the file.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use crate::error::{CoreError, ErrorCode};

/// Owned lock guard: dropping closes the descriptor, releasing the flock.
/// Explicit release truncates and syncs before this guard drops.
#[derive(Debug)]
pub(super) struct HeldFile {
    file: File,
}

impl HeldFile {
    /// Borrowed handle for publish/release I/O. The accessor hides guard
    /// ownership instead of exposing a plain field.
    pub(super) fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for HeldFile {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Opens the lock file and takes the lifetime lock without blocking.
/// Contention yields `None` (the handle closes on drop); success yields the
/// owned guard after security validation.
pub(super) fn try_acquire(path: &Path) -> Result<Option<HeldFile>, CoreError> {
    let file = create_lock_file(path)?;
    match file.try_lock() {
        Ok(()) => {
            validate_lock_file(&file, path)?;
            Ok(Some(HeldFile { file }))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(err)) => Err(io_error(path, "lock", err)),
    }
}

/// Reads at most one byte past the body limit under the same security
/// validation, so overlong files decode as not-ready instead of being read
/// without a bound.
pub(super) fn read_body(path: &Path) -> Result<Vec<u8>, CoreError> {
    let mut file = open_existing_lock_file(path)?;
    validate_lock_file(&file, path)?;
    let limit = u64::try_from(super::MAX_READ_BYTES)
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "lock body"))?;
    let mut body = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|err| io_error(path, "read", err))?;
    Ok(body)
}

/// Creates the lock file with mode 0600 when absent, without truncation and
/// without following a final symlink.
fn create_lock_file(path: &Path) -> Result<File, CoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    open_validated(options, path)
}

/// Opens the existing lock file read-only, without truncation, creation, or
/// symlink following. A contender reads; it never writes through this
/// handle. An existing file keeps its mode (never chmodded). A file that
/// vanished since contention is `E_NOT_FOUND`, which the common module
/// reports as not-ready for the attach owner's bounded retry.
fn open_existing_lock_file(path: &Path) -> Result<File, CoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    open_validated(options, path)
}

fn open_validated(mut options: OpenOptions, path: &Path) -> Result<File, CoreError> {
    options.custom_flags(open_flags());
    options.open(path).map_err(|err| match err.kind() {
        kind if kind == ErrorKind::PermissionDenied
            || err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) =>
        {
            forbidden(path, "ownership lock is not safely openable")
        }
        ErrorKind::NotFound => CoreError::new(
            ErrorCode::ENotFound,
            format!("ownership lock is missing: {}", path.display()),
        ),
        _ => io_error(path, "open", err),
    })
}

/// No-follow plus nonblocking, no-controlling-terminal, close-on-exec.
/// Symlinks fail with `ELOOP`; special files cannot block or claim the
/// terminal; the descriptor never leaks across exec. The flag constants are
/// small positive values, so the cast to the kernel flag word preserves
/// every bit.
fn open_flags() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::NOCTTY
        | rustix::fs::OFlags::CLOEXEC)
        .bits() as i32
}

/// fstat validation on the opened descriptor: regular file, one hard link,
/// owned by the effective UID, no group/other permission bits. Same-user
/// processes with store write access are trusted; this is not a sandbox
/// against malicious peers holding that authority.
fn validate_lock_file(file: &File, path: &Path) -> Result<(), CoreError> {
    let metadata = file.metadata().map_err(|err| io_error(path, "stat", err))?;
    if !metadata.is_file() {
        return Err(forbidden(path, "ownership lock is not a regular file"));
    }
    if metadata.nlink() != 1 {
        return Err(forbidden(
            path,
            "ownership lock has more than one hard link",
        ));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(forbidden(
            path,
            "ownership lock is not owned by the effective user",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(forbidden(
            path,
            "ownership lock grants group or other access",
        ));
    }
    Ok(())
}

fn io_error(path: &Path, op: &'static str, err: std::io::Error) -> CoreError {
    CoreError::new(
        ErrorCode::EIo,
        format!("{op} ownership lock {}: {err}", path.display()),
    )
}

fn forbidden(path: &Path, reason: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::EForbidden,
        format!("{reason}: {}", path.display()),
    )
}
