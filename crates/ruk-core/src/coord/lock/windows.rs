//! Windows ownership-file platform implementation: atomic owner-only DACL
//! creation, regular disk file / single-link / no-reparse validation, and
//! LockFileEx sentinel range locking at offset 1 MiB.
//!
//! Contention on the sentinel range closes the handle and reports `None`; the
//! common [`crate::coord::lock`] module then reads the published body for a
//! contender snapshot. Bytes 0..512 remain fully readable under a held
//! sentinel lock.
//!
//! All unsafe Win32 FFI operations are delegated to [`crate::coord::windows`].
//! This module contains zero unsafe code.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::coord::windows::{
    LockOpenMode, lock_exclusive_range, open_lock_file, unlock_exclusive_range, validate_lock_file,
};
use crate::error::{CoreError, ErrorCode};

/// Owned lock guard holding the open lock file and sentinel range lock.
///
/// Dropping this guard releases the LockFileEx sentinel lock and closes the
/// file handle. Explicit release in the common module truncates and syncs
/// before this guard drops.
#[derive(Debug)]
pub(super) struct HeldFile {
    file: File,
}

impl HeldFile {
    /// Borrowed handle for publish and release I/O.
    pub(super) fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for HeldFile {
    fn drop(&mut self) {
        // Best-effort unlock before handle closure. If the file was closed or
        // process terminated, Windows automatically cleans up range locks.
        let _ = unlock_exclusive_range(&self.file);
    }
}

/// Attempts to acquire the lifetime sentinel lock on `path` without blocking.
///
/// 1. Atomically creates or opens the lock file with an owner-only protected
///    DACL (no `FILE_SHARE_DELETE`, no symlink following).
/// 2. Validates the opened handle: regular disk file, single hardlink, not a
///    reparse point, owned by the process user, and with a protected DACL
///    granting access to no other SID. Hostile files fail closed before any
///    locking or writing occurs.
/// 3. Takes a nonblocking exclusive LockFileEx lock on the sentinel byte at
///    offset 1 MiB (`LOCK_SENTINEL_OFFSET`).
///
/// Contention (`ERROR_LOCK_VIOLATION`) yields `Ok(None)`; success yields the
/// owned [`HeldFile`] guard.
pub(super) fn try_acquire(path: &Path) -> Result<Option<HeldFile>, CoreError> {
    let file = open_lock_file(path, LockOpenMode::CreateOrOpen)?;
    validate_lock_file(&file, path)?;

    match lock_exclusive_range(&file)? {
        true => Ok(Some(HeldFile { file })),
        false => Ok(None),
    }
}

/// Reads at most one byte past the body limit ([`super::MAX_READ_BYTES`]) under
/// the same handle and security validation as [`try_acquire`].
///
/// Because the sentinel lock is held at offset 1 MiB, bytes 0..512 remain
/// readable to contenders while the owner holds the lock.
pub(super) fn read_body(path: &Path) -> Result<Vec<u8>, CoreError> {
    let mut file = open_lock_file(path, LockOpenMode::OpenExisting)?;
    validate_lock_file(&file, path)?;

    let limit = u64::try_from(super::MAX_READ_BYTES)
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "lock body read limit"))?;

    let mut body = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("read ownership lock {}: {err}", path.display()),
            )
        })?;

    Ok(body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestStoreDir {
        dir: PathBuf,
    }

    impl TestStoreDir {
        fn new(tag: &str) -> Self {
            let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "ruk-win-lock-{}-{}-{tag}",
                std::process::id(),
                id,
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test store directory");
            Self { dir }
        }

        fn lock_path(&self) -> PathBuf {
            self.dir.join("lock")
        }
    }

    impl Drop for TestStoreDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_lock_contention_with_readable_body() {
        let store = TestStoreDir::new("contend");
        let lock_path = store.lock_path();

        // 1. Initial acquire must succeed.
        let owner = try_acquire(&lock_path)
            .expect("first try_acquire")
            .expect("must acquire fresh lock");

        // 2. Owner writes published body under the held sentinel lock.
        let body_bytes = b"ruk-lock 1\npid 1234\naddress pipe:\\\\.\\pipe\\ruk-test\nnonce 0000000000000000000000000000000000000000000000000000000000000000\n";
        owner
            .file()
            .write_all(body_bytes)
            .expect("write body bytes");
        owner.file().sync_all().expect("sync body bytes");

        // 3. Second acquire contends on sentinel range -> returns None.
        let contender_acquire = try_acquire(&lock_path).expect("contender try_acquire");
        assert!(
            contender_acquire.is_none(),
            "second acquire must report None on held lock",
        );

        // 4. Body remains fully readable under the held sentinel lock.
        let read_bytes = read_body(&lock_path).expect("read body under held lock");
        assert_eq!(read_bytes, body_bytes);

        // 5. Drop owner guard to release lock.
        drop(owner);

        // 6. Contender can now acquire ownership.
        let second_owner = try_acquire(&lock_path)
            .expect("re-acquire after drop")
            .expect("must acquire released lock");
        drop(second_owner);
    }

    #[test]
    fn test_hostile_hardlink_refused() {
        let store = TestStoreDir::new("hardlink");
        let lock_path = store.lock_path();

        // Create a target file.
        let target_path = store.dir.join("target_file");
        std::fs::write(&target_path, b"initial").expect("create target file");

        // Create a hardlink at lock_path pointing to target_path.
        std::fs::hard_link(&target_path, &lock_path).expect("create hardlink");

        // try_acquire must refuse the hardlink before locking or writing.
        let err = try_acquire(&lock_path).unwrap_err();
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(err.message.contains("hard link"));

        // Verify target file was untouched.
        let content = std::fs::read(&target_path).expect("read target");
        assert_eq!(content, b"initial");
    }

    #[test]
    fn test_hostile_directory_refused() {
        let store = TestStoreDir::new("dir");
        let lock_path = store.lock_path();

        // Create a directory where the lock file is expected.
        std::fs::create_dir(&lock_path).expect("create directory at lock path");

        let err = try_acquire(&lock_path).unwrap_err();
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[test]
    fn test_hostile_junction_or_symlink_refused() {
        let store = TestStoreDir::new("reparse");
        let lock_path = store.lock_path();

        // Target directory for junction / reparse point.
        let target_dir = store.dir.join("target_dir");
        std::fs::create_dir_all(&target_dir).expect("create target dir");

        // Attempt file symlink or directory junction creation.
        let created_reparse = std::os::windows::fs::symlink_file(&target_dir, &lock_path).is_ok()
            || std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&lock_path)
                .arg(&target_dir)
                .output()
                .is_ok_and(|out| out.status.success());

        if created_reparse {
            let err = try_acquire(&lock_path).unwrap_err();
            assert_eq!(err.code, ErrorCode::EForbidden);
            assert!(
                err.message.contains("reparse") || err.message.contains("directory"),
                "error message must cite reparse point or directory: {}",
                err.message,
            );
        }
    }

    #[test]
    fn test_hostile_dacl_refused() {
        let store = TestStoreDir::new("hostile_dacl");
        let lock_path = store.lock_path();

        // 1. Create a plain file at lock_path.
        std::fs::write(&lock_path, b"pre-created hostile content").expect("create hostile file");

        // 2. Modify DACL using icacls to add an unauthorized ACE or re-enable inheritance.
        let modified = std::process::Command::new("icacls")
            .arg(&lock_path)
            .args(["/grant", "Everyone:R"])
            .output()
            .is_ok_and(|out| out.status.success())
            || std::process::Command::new("icacls")
                .arg(&lock_path)
                .args(["/inheritance:e"])
                .output()
                .is_ok_and(|out| out.status.success());

        if modified {
            let err = try_acquire(&lock_path).unwrap_err();
            assert_eq!(err.code, ErrorCode::EForbidden);
        }
    }

    #[test]
    fn test_missing_lock_file_read_body_reports_not_found() {
        let store = TestStoreDir::new("missing");
        let lock_path = store.lock_path();

        let err = read_body(&lock_path).unwrap_err();
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn test_verbatim_local_path_works() {
        let store = TestStoreDir::new("verbatim");
        let raw_path = store.lock_path();

        // Construct verbatim path \\?\C:\...
        let verbatim_str = format!(r"\\?\{}", raw_path.display());
        let verbatim_path = PathBuf::from(verbatim_str);

        let owner = try_acquire(&verbatim_path)
            .expect("acquire via verbatim path")
            .expect("must acquire lock");

        let body = read_body(&verbatim_path).expect("read body via verbatim path");
        assert!(body.is_empty());

        drop(owner);
    }
}
