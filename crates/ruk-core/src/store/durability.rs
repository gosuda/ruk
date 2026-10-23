//! Durable file and namespace operations for the store.
//!
//! The single durability seam between the store and the host filesystem.
//! Every helper is fail-closed: an OS error propagates as
//! [`StoreError::Io`] and is never swallowed or turned into a no-op. The
//! claims below rest on documented platform behavior; no power-loss test
//! backs them.
//!
//! # Paths
//!
//! [`create_file_published`], [`create_dir_published`] and (POSIX only)
//! [`create_dir_all_synced`] resolve their argument against the working
//! directory once, with `std::path::absolute`:
//! no filesystem access, the process working directory is untouched, and
//! non-UTF-8 names are preserved. POSIX keeps `..` and symlinks for the
//! kernel to resolve; Windows collapses `.` and `..` lexically. An empty
//! path is `InvalidInput`. Windows paths with interior NULs are rejected
//! before any side effect, because the `atomicwrites` wrapper would truncate
//! them, and Windows temp/final names are built from the canonical verbatim
//! parent so long paths survive.
//!
//! # POSIX
//!
//! `fsync` on a file does not persist its directory entry; the directory
//! must be synced too (`fsync(2)`). `File::sync_all` is `fsync` on Linux and
//! `fcntl(F_FULLFSYNC)` on macOS (std, rustc 1.99.1).
//!
//! - [`create_file_published`] only creates the entry. The caller makes it
//!   durable with [`sync_file`], then [`sync_dir`] on the parent.
//! - [`create_dir_published`] creates exactly one directory, exclusively,
//!   and flushes it and its parent before returning. An existing name of any
//!   kind fails with `AlreadyExists`; nothing is adopted.
//! - [`create_dir_all_synced`] returns only after the whole chain is durable.
//!   First the deepest existing directory is canonicalized, and it and every
//!   ancestor up to the mount root of its filesystem are synced. No existing
//!   directory is trusted: another creator (a Ruk process, or a host's
//!   `MkdirAll`) may have made it visible without syncing it. Then the
//!   missing components are created top-down, each synced together with its
//!   parent before any child is created in it. A lost `mkdir` race is
//!   accepted only if the winner is a directory, and that component is still
//!   synced here. A failed sync fails the call.
//!
//! The bound is the mount root: entries above it, and the mount topology,
//! are deployment configuration. An ancestor that cannot be opened for
//! reading, or a filesystem that rejects directory `fsync`, fails the call:
//! durability cannot be established there, which is not data loss. Another
//! actor renaming or retargeting ancestors during the call is not fenced.
//!
//! # Windows
//!
//! No directory flush is used. A new file or directory is created under a
//! temporary name, synced, and published with `atomicwrites::move_atomic`
//! (`MoveFileExW(MOVEFILE_WRITE_THROUGH)`, no overwrite), so a creator's own
//! entry is durable when its call returns.
//!
//! No documented primitive proves that a directory some other actor made
//! visible is durable, so nothing here trusts one. There is no recursive
//! creation: [`create_dir_published`] requires its parent to exist already
//! and fails before any change when it does not, and an existing name fails
//! with `AlreadyExists`. The caller owns the durability of the parent: it
//! must have been provisioned, and made durable, before the call. Only the
//! one call whose move succeeds may build inside the new directory; a racing
//! creator fails rather than adopting it, so ownership never depends on how
//! far a loser got.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::store::error::StoreError;

/// Creates a new file at `path` as a durable namespace entry and returns a
/// handle positioned at the start of the empty file, failing if it exists.
///
/// POSIX: `create_new`; the caller seals the new entry with [`sync_file`]
/// plus [`sync_dir`] on the parent after writing. Windows: a temporary file
/// is created, synced, and published with
/// `MoveFileExW(MOVEFILE_WRITE_THROUGH)` (no overwrite), so the entry is
/// durable on return and the retained handle is used for appends.
/// `AlreadyExists` propagates either way.
///
/// The file is empty from the moment its entry is visible until the caller
/// writes and syncs it, on both platforms. A protocol that treats a file's
/// content as its commit point must read an empty or short file as
/// incomplete.
pub(crate) fn create_file_published(path: &Path) -> Result<File, StoreError> {
    resolve(path)
        .and_then(|path| create_file_published_inner(&path))
        .map_err(StoreError::from)
}

/// Writes and syncs a new file before publishing its final name.
///
/// An existing final name fails without replacement. A failed write leaves
/// no final entry. Failure after publication may leave the completed final
/// file in place. The parent directory must already satisfy this module's
/// platform-specific durability requirements.
pub fn install_file(
    path: &Path,
    write: impl FnOnce(&mut File) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let path = resolve(path)?;
    #[cfg(windows)]
    let path = canonical_join(parent_of(&path)?, child_of(&path)?)?;
    let parent = parent_of(&path)?;
    let temporary = parent.join(format!(".tmp-file-{}", uuid::Uuid::new_v4().simple()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        write(&mut file)?;
        sync_file(&file)?;
        publish_completed_file(&temporary, &path)?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn publish_completed_file(temporary: &Path, target: &Path) -> io::Result<()> {
    std::fs::hard_link(temporary, target)?;
    std::fs::remove_file(temporary)?;
    sync_dir_path(parent_of(target)?)
}

#[cfg(windows)]
fn publish_completed_file(temporary: &Path, target: &Path) -> io::Result<()> {
    atomicwrites::move_atomic(temporary, target)
}

/// Creates exactly one new directory at `path` as a durable namespace entry.
///
/// Exclusive: any existing name (directory, file, symlink) fails with
/// [`io::ErrorKind::AlreadyExists`] and is left untouched, and a directory
/// that a racing creator made visible is never adopted. The parent must
/// already exist; a missing parent fails (`NotFound`) before anything is
/// created. Exactly one of several concurrent callers succeeds. Every other
/// error, including a failed flush, propagates and nothing is deleted: a
/// directory left behind by a failed flush is not owned by a later call.
///
/// POSIX: `mkdir`, then the new directory and its parent are flushed. The
/// parent's own entry is not flushed here. Windows: a temporary directory
/// is created beside the target and moved into place with
/// `MoveFileExW(MOVEFILE_WRITE_THROUGH)` (no overwrite); a loser removes only
/// its own temporary directory. The parent's durability is a precondition
/// (see the module docs).
pub fn create_dir_published(path: &Path) -> Result<(), StoreError> {
    resolve(path)
        .and_then(|path| create_dir_published_inner(&path))
        .map_err(StoreError::from)
}

/// Opens an existing file for reading and appending without truncating or
/// creating it.
pub(crate) fn open_existing(path: &Path) -> Result<File, StoreError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(StoreError::from)
}

/// Flushes a file's contents and metadata to stable storage.
///
/// Linux: `fsync(2)`. macOS: `fcntl(F_FULLFSYNC)` (applied by the pinned
/// standard library on apple targets). Windows: `FlushFileBuffers`, the
/// documented mechanism for file data and file creation metadata.
pub(crate) fn sync_file(file: &File) -> Result<(), StoreError> {
    file.sync_all().map_err(StoreError::from)
}

/// Flushes a directory's entries after creating, renaming, or removing them.
///
/// POSIX only: opens the directory and issues `fsync`/`F_FULLFSYNC` on the
/// descriptor, the documented mechanism for making directory entries
/// durable. Windows callers do not call this at all — durability is
/// delivered by [`create_file_published`] and [`create_dir_published`] at
/// publication time.
#[cfg(unix)]
pub fn sync_dir(path: &Path) -> Result<(), StoreError> {
    sync_dir_path(path).map_err(StoreError::from)
}

/// Creates `path` and every missing ancestor as durable namespace entries,
/// failing if a non-directory component is in the way.
///
/// POSIX only: there is no Windows counterpart, because no documented
/// primitive makes an existing Windows ancestor provably durable (see the
/// module docs).
///
/// `path` may be relative (see the module docs). The existing ancestor chain
/// up to the mount root is flushed before anything is created, then each
/// missing component is published top-down, so every entry is durable before
/// any child is created in it. Idempotent: an existing directory (including
/// one a racing creator just made) is accepted after being flushed.
#[cfg(unix)]
pub(crate) fn create_dir_all_synced(path: &Path) -> Result<(), StoreError> {
    resolve(path)
        .and_then(|path| create_dir_all_synced_inner(&path))
        .map_err(StoreError::from)
}

#[cfg(unix)]
pub fn sync_dir_path(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    fault::check(path)?;
    let dir = File::open(path)?;
    dir.sync_all()
}

/// Test-only fault injection: makes directory syncs of one chosen directory
/// fail on the current thread. The directory is matched by identity (device
/// and inode), so symlinks and `..` in the synced path do not matter.
#[cfg(all(test, unix))]
pub(in crate::store) mod fault {
    use std::cell::Cell;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    thread_local! {
        static FAIL_DIR: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
    }

    /// Restores normal syncing when dropped.
    pub(in crate::store) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_DIR.set(None);
        }
    }

    /// Fails every directory sync of `dir` on this thread until the guard
    /// drops. The injected error kind is [`INJECTED_KIND`].
    pub(in crate::store) fn fail_sync_of(dir: &Path) -> Guard {
        let meta = std::fs::metadata(dir).expect("inject: directory must exist");
        FAIL_DIR.set(Some((meta.dev(), meta.ino())));
        Guard
    }

    pub(in crate::store) const INJECTED_KIND: io::ErrorKind = io::ErrorKind::StorageFull;

    pub(super) fn check(path: &Path) -> io::Result<()> {
        let Some((dev, ino)) = FAIL_DIR.get() else {
            return Ok(());
        };
        match std::fs::metadata(path) {
            Ok(meta) if (meta.dev(), meta.ino()) == (dev, ino) => {
                Err(io::Error::from(INJECTED_KIND))
            }
            _ => Ok(()),
        }
    }
}

/// Resolves `path` against the working directory without touching the
/// filesystem, so every later parent/child split sees a real containing
/// directory. Rejects an empty path and, on Windows, interior NULs before
/// any side effect.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(invalid_path("empty path"));
    }
    #[cfg(windows)]
    validate_windows_path(path)?;
    std::path::absolute(path)
}

#[cfg(unix)]
fn create_file_published_inner(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn create_dir_published_inner(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)?;
    sync_published_dir(path)
}

/// Flushes a freshly published directory, then its parent.
#[cfg(unix)]
fn sync_published_dir(path: &Path) -> io::Result<()> {
    sync_dir_path(path)?;
    sync_dir_path(parent_of(path)?)
}

#[cfg(unix)]
fn create_dir_all_synced_inner(path: &Path) -> io::Result<()> {
    let missing = missing_components(path)?;
    // The deepest existing directory: `path` itself when nothing is missing.
    let stop = match missing.last() {
        Some(&first) => parent_of(first)?,
        None => path,
    };
    sync_existing_chain(stop)?;
    // Top-down: each ancestor is durable before its children are created.
    for component in missing.into_iter().rev() {
        publish_dir(component)?;
    }
    Ok(())
}

/// Flushes `stop` and every ancestor up to the mount root of its filesystem
/// (the first directory with no parent or whose parent is on another
/// device).
///
/// Unconditional, even when nothing is missing: a creator that made any of
/// these directories visible may not have flushed it, and this call must not
/// acknowledge on its progress. `stop` is canonicalized first, so symlinks
/// and `..` cannot make the lexical `parent()` name the wrong directory.
#[cfg(unix)]
fn sync_existing_chain(stop: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let top = std::fs::canonicalize(stop)?;
    let dev = std::fs::metadata(&top)?.dev();
    let mut dir = top.as_path();
    loop {
        sync_dir_path(dir)?;
        let Some(parent) = dir.parent() else {
            return Ok(());
        };
        if std::fs::metadata(parent)?.dev() != dev {
            return Ok(());
        }
        dir = parent;
    }
}

/// Creates one directory and makes its entry durable: flushes the directory,
/// then its parent.
///
/// Losing the creation race is accepted only when the winner is a directory
/// (`is_dir` follows symlinks, as `create_dir_all` does). The winner may not
/// have flushed yet, so the loser flushes the same two directories before
/// the caller creates anything inside this one. A non-directory winner and
/// every other error, including a failed flush, propagate.
#[cfg(unix)]
fn publish_dir(path: &Path) -> io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(e) => return Err(e),
    }
    sync_published_dir(path)
}

/// Lists `path` and every ancestor that does not exist yet, deepest first,
/// stopping at the first existing directory. An existing non-directory is an
/// error.
#[cfg(unix)]
fn missing_components(path: &Path) -> io::Result<Vec<&Path>> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match std::fs::metadata(current) {
            Ok(meta) if meta.is_dir() => return Ok(missing),
            Ok(_) => return Err(not_a_directory(current)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(current),
            Err(e) => return Err(e),
        }
        current = parent_of(current)?;
    }
}

#[cfg(unix)]
fn not_a_directory(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{} exists and is not a directory", path.display()),
    )
}

fn parent_of(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| invalid_path("no parent directory"))
}

fn invalid_path(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid path: {what}"))
}

#[cfg(windows)]
fn validate_windows_path(path: &Path) -> io::Result<()> {
    // atomicwrites encodes paths to NUL-terminated wide strings without
    // rejecting interior NULs; MoveFileExW would silently act on the
    // truncated name. Reject before any side effect.
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(invalid_path("interior NUL"));
    }
    Ok(())
}

/// Joins `child` onto the canonical (verbatim `\\?\`) form of `dir` so
/// long paths stay valid through MoveFileExW without the wrapper adding a
/// prefix.
#[cfg(windows)]
fn canonical_join(dir: &Path, child: &std::ffi::OsStr) -> io::Result<std::path::PathBuf> {
    let canonical = dir.canonicalize()?;
    Ok(canonical.join(child))
}

#[cfg(windows)]
fn child_of(path: &Path) -> io::Result<&std::ffi::OsStr> {
    path.file_name().ok_or_else(|| invalid_path("no file name"))
}

#[cfg(windows)]
fn create_file_published_inner(path: &Path) -> io::Result<File> {
    let dir = parent_of(path)?;
    let name = child_of(path)?;
    let tmp_name = format!(".tmp-{}", uuid::Uuid::new_v4().simple());
    let tmp = canonical_join(dir, std::ffi::OsStr::new(&tmp_name))?;
    let target = canonical_join(dir, name)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match atomicwrites::move_atomic(&tmp, &target) {
        Ok(()) => Ok(file),
        Err(e) => {
            drop(file);
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(windows)]
fn create_dir_published_inner(dir_path: &Path) -> io::Result<()> {
    let dir = parent_of(dir_path)?;
    let name = child_of(dir_path)?;
    let tmp_name = format!(".tmp-dir-{}", uuid::Uuid::new_v4().simple());
    let tmp = canonical_join(dir, std::ffi::OsStr::new(&tmp_name))?;
    let target = canonical_join(dir, name)?;
    std::fs::create_dir(&tmp)?;
    match atomicwrites::move_atomic(&tmp, &target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_dir(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let dir = base.join(format!("ruk-durability-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    /// Sorted names of a directory's entries.
    fn entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn completed_file_is_invisible_until_sealed_and_never_replaced() {
        use std::io::Write;

        let root = temp_root("complete-install");
        let target = root.join("graph");
        install_file(&target, |file| {
            file.write_all(b"immutable graph")?;
            assert!(!target.exists());
            Ok(())
        })
        .expect("install completed file");
        assert_eq!(
            std::fs::read(&target).expect("read installed file"),
            b"immutable graph"
        );
        let error = install_file(&target, |file| {
            file.write_all(b"replacement")?;
            Ok(())
        })
        .expect_err("existing file must not be replaced");
        assert!(matches!(
            &error,
            StoreError::Io(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            std::fs::read(&target).expect("read original file"),
            b"immutable graph"
        );
        assert_eq!(entry_names(&root), vec!["graph"]);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn failed_content_write_never_publishes_partial_file() {
        use std::io::Write;

        let root = temp_root("failed-install");
        let target = root.join("graph");
        let error = install_file(&target, |file| {
            file.write_all(b"partial")?;
            Err(StoreError::Io(io::Error::other("content producer failed")))
        })
        .expect_err("producer failure must propagate");
        assert!(matches!(error, StoreError::Io(_)));
        assert!(!target.exists());
        assert!(entry_names(&root).is_empty());
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn creates_nested_dirs_and_is_idempotent() {
        let root = temp_root("nested");
        let target = root.join("a/b/c/store");
        create_dir_all_synced(&target).expect("create nested dirs");
        assert!(target.is_dir());
        create_dir_all_synced(&target).expect("idempotent");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn create_published_fails_when_file_exists_and_never_truncates() {
        let root = temp_root("create");
        let dir = root.join("segments");
        create_dir_published(&dir).expect("create segments dir");
        let seg = dir.join("seg_0000000000000001");
        let file = create_file_published(&seg).expect("create new file");
        sync_file(&file).expect("sync file");
        drop(file);
        let err = create_file_published(&seg).unwrap_err();
        match err {
            StoreError::Io(io) => {
                assert_eq!(io.kind(), io::ErrorKind::AlreadyExists);
            }
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        std::fs::write(&seg, b"payload").expect("write payload");
        let existing = open_existing(&seg).expect("open existing");
        assert_eq!(existing.metadata().expect("meta").len(), 7);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn sync_dir_makes_namespace_changes_durable_api() {
        let root = temp_root("syncdir");
        let gone = root.join("missing.bin");
        let file = File::create(&gone).expect("create file");
        sync_file(&file).expect("sync");
        drop(file);
        std::fs::remove_file(&gone).expect("remove");
        sync_dir(&root).expect("sync dir after remove");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Real flush failure: `/dev/null` opens, but `fsync(2)` on it fails with
    /// EINVAL, so only the flush can be the source of the error.
    #[cfg(target_os = "linux")]
    #[test]
    fn sync_failure_propagates() {
        match sync_dir(Path::new("/dev/null")) {
            Err(StoreError::Io(e)) => assert_ne!(
                e.kind(),
                io::ErrorKind::NotFound,
                "the open failed, not the flush: {e:?}"
            ),
            other => panic!("expected the flush error to propagate, got {other:?}"),
        }
    }

    #[test]
    fn empty_path_is_invalid_not_a_no_op() {
        #[cfg(unix)]
        {
            let err = create_dir_all_synced(Path::new("")).unwrap_err();
            assert!(
                matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
                "got {err:?}"
            );
        }
        let err = create_dir_published(Path::new("")).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
            "got {err:?}"
        );
        let err = create_file_published(Path::new("")).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
            "got {err:?}"
        );
    }

    #[test]
    fn create_dir_published_is_exclusive_and_leaves_the_existing_name_untouched() {
        let root = temp_root("dir-exclusive");
        let target = root.join("owned");
        create_dir_published(&target).expect("create a new directory");
        assert!(target.is_dir());
        let keep = target.join("keep");
        std::fs::write(&keep, b"payload").expect("seed content");

        let err = create_dir_published(&target).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "an existing directory is never adopted: {err:?}"
        );
        assert_eq!(std::fs::read(&keep).expect("read content"), b"payload");

        let blocker = root.join("file");
        std::fs::write(&blocker, b"keep").expect("write blocker");
        assert!(
            create_dir_published(&blocker).is_err(),
            "a file in the way must fail"
        );
        assert_eq!(std::fs::read(&blocker).expect("read blocker"), b"keep");
        assert_eq!(
            entry_names(&root),
            ["file", "owned"],
            "a failed call leaves no temporary name behind"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn create_dir_published_with_a_missing_parent_fails_before_any_change() {
        let root = temp_root("dir-no-parent");
        let err = create_dir_published(&root.join("absent/owned")).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::NotFound),
            "got {err:?}"
        );
        assert!(
            entry_names(&root).is_empty(),
            "a missing parent must not be created or adopted"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn exactly_one_concurrent_creator_publishes_a_directory() {
        let root = temp_root("dir-one-winner");
        for round in 0..24 {
            let target = root.join(format!("r{round}"));
            let results = race(6, |_| create_dir_published(&target));
            let winners = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(winners, 1, "round {round}: {results:?}");
            assert!(
                target.is_dir(),
                "round {round}: {} missing",
                target.display()
            );
            #[cfg(unix)]
            for loser in results.iter().filter_map(|result| result.as_ref().err()) {
                assert!(loser.contains("AlreadyExists"), "round {round}: {loser}");
            }
        }
        let names = entry_names(&root);
        assert_eq!(names.len(), 24, "losers leave no temporary name: {names:?}");
        assert!(names.iter().all(|name| name.starts_with('r')), "{names:?}");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn file_in_the_way_fails_and_is_left_untouched() {
        let root = temp_root("collision");
        let blocker = root.join("block");
        std::fs::write(&blocker, b"keep").expect("write blocker");
        let err = create_dir_all_synced(&blocker).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "got {err:?}"
        );
        let err = create_dir_all_synced(&blocker.join("child/leaf")).unwrap_err();
        assert!(matches!(err, StoreError::Io(_)), "got {err:?}");
        assert_eq!(std::fs::read(&blocker).expect("read blocker"), b"keep");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// A dangling symlink is invisible to `metadata` yet occupies the name, so
    /// `mkdir` reports AlreadyExists with no directory behind it: the
    /// observable state of losing a creation race to a non-directory.
    #[cfg(unix)]
    #[test]
    fn losing_the_race_to_a_non_directory_fails() {
        let root = temp_root("dangling");
        let link = root.join("link");
        let nowhere = root.join("nowhere");
        std::os::unix::fs::symlink(&nowhere, &link).expect("create dangling symlink");
        let err = create_dir_all_synced(&link).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "got {err:?}"
        );
        let err = create_dir_all_synced(&link.join("child")).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "got {err:?}"
        );
        assert!(!nowhere.exists(), "nothing may be created behind the link");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Asserts a directory-creation call failed with the injected sync error.
    #[cfg(unix)]
    fn assert_injected(result: Result<(), StoreError>, context: &str) {
        match result {
            Err(StoreError::Io(e)) => {
                assert_eq!(e.kind(), fault::INJECTED_KIND, "{context}: {e:?}")
            }
            other => panic!("{context}: expected the injected sync error, got {other:?}"),
        }
    }

    /// The parent's entry list changed by the new directory, so the parent is
    /// flushed too. A directory left behind by a failed flush is neither
    /// deleted nor adopted by a later call.
    #[cfg(unix)]
    #[test]
    fn create_dir_published_flushes_the_parent_and_never_adopts_its_leftover() {
        let root = temp_root("dir-parent-flush");
        let target = root.join("owned");
        let _inject = fault::fail_sync_of(&root);
        assert_injected(create_dir_published(&target), "parent flush");
        assert!(target.is_dir(), "a failed flush deletes nothing");
        let err = create_dir_published(&target).unwrap_err();
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "a leftover directory of uncertain durability is not adopted: {err:?}"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// An ancestor two levels above the stop directory (beyond its parent) is
    /// flushed before anything is created, so its failure stops the call.
    #[cfg(unix)]
    #[test]
    fn grandparent_flush_failure_stops_creation() {
        let root = temp_root("ancestor-fail");
        let stop = root.join("a/b/c");
        std::fs::create_dir_all(&stop).expect("existing chain");
        let _inject = fault::fail_sync_of(&root.join("a"));
        let target = stop.join("new1/new2");
        assert_injected(create_dir_all_synced(&target), "missing tail");
        assert!(
            !stop.join("new1").exists(),
            "nothing may be created below an unflushed ancestor"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// The ancestors of a directory that already exists are flushed too:
    /// another creator may have made them visible without flushing.
    #[cfg(unix)]
    #[test]
    fn existing_directory_still_flushes_its_ancestors() {
        let root = temp_root("existing-fail");
        let target = root.join("a/b/c");
        std::fs::create_dir_all(&target).expect("existing chain");
        let _inject = fault::fail_sync_of(&root.join("a"));
        assert_injected(create_dir_all_synced(&target), "nothing missing");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// The flushed chain is the real one: a stop directory reached through a
    /// symlink flushes the ancestors of the link target, not of the link.
    #[cfg(unix)]
    #[test]
    fn symlinked_stop_directory_flushes_the_real_ancestors() {
        let root = temp_root("symlink-fail");
        let real = root.join("real/x/y");
        std::fs::create_dir_all(&real).expect("real chain");
        std::os::unix::fs::symlink(&real, root.join("link")).expect("create symlink");
        let _inject = fault::fail_sync_of(&root.join("real/x"));
        assert_injected(
            create_dir_all_synced(&root.join("link/new")),
            "through symlink",
        );
        assert!(
            !real.join("new").exists(),
            "nothing may be created below an unflushed ancestor"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// The stop directory itself is flushed before anything is created in it.
    #[cfg(unix)]
    #[test]
    fn stop_directory_flush_failure_stops_creation() {
        let root = temp_root("stop-fail");
        let stop = root.join("stop");
        std::fs::create_dir(&stop).expect("create stop directory");
        let _inject = fault::fail_sync_of(&stop);
        assert_injected(create_dir_all_synced(&stop.join("n1/n2")), "stop directory");
        assert!(
            !stop.join("n1").exists(),
            "nothing may be created below an unflushed directory"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Releases `n` threads together and returns each `body(i)` outcome.
    fn race<F>(n: usize, body: F) -> Vec<Result<(), String>>
    where
        F: Fn(usize) -> Result<(), StoreError> + Sync,
    {
        let barrier = std::sync::Barrier::new(n);
        let (start, body) = (&barrier, &body);
        std::thread::scope(|scope| {
            let racers: Vec<_> = (0..n)
                .map(|i| {
                    scope.spawn(move || {
                        start.wait();
                        body(i).map_err(|e| format!("{e:?}"))
                    })
                })
                .collect();
            racers
                .into_iter()
                .map(|racer| racer.join().expect("racer panicked"))
                .collect::<Vec<_>>()
        })
    }

    #[cfg(unix)]
    fn assert_all_ok(results: &[Result<(), String>], context: &str) {
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok(), "{context}: racer {i} failed: {result:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_creators_of_one_nested_path_all_succeed() {
        let root = temp_root("race-same");
        for round in 0..24 {
            let target = root.join(format!("r{round}/a/b/c/d"));
            let results = race(6, |_| create_dir_all_synced(&target));
            assert_all_ok(&results, &format!("round {round}"));
            assert!(
                target.is_dir(),
                "round {round}: {} missing",
                target.display()
            );
        }
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_creators_sharing_ancestors_all_succeed() {
        let root = temp_root("race-shared");
        for round in 0..24 {
            let base = root.join(format!("s{round}/a/b"));
            let results = race(6, |i| {
                create_dir_all_synced(&base.join(format!("t{i}/leaf")))
            });
            assert_all_ok(&results, &format!("round {round}"));
            for i in 0..6 {
                let leaf = base.join(format!("t{i}/leaf"));
                assert!(leaf.is_dir(), "round {round}: {} missing", leaf.display());
            }
        }
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Environment variable carrying the relative path to the subprocess
    /// child; set only through `Command::env`, never in this process.
    const CHILD_DIR_ENV: &str = "RUK_DURABILITY_TEST_CHILD_DIR";

    /// Full libtest path (crate name excluded) of [`relative_root_child`],
    /// which is what `--exact` compares against.
    const CHILD_ENTRY: &str = "store::durability::tests::relative_root_child";

    /// Child of [`check_relative`]: runs with a working directory chosen by
    /// its parent and a relative path from the environment. Invoked any other
    /// way it fails loudly because the required child environment is absent.
    #[test]
    #[ignore = "subprocess child; only check_relative spawns it"]
    fn relative_root_child() {
        let rel = std::env::var_os(CHILD_DIR_ENV)
            .expect("child requires the relative path from its parent test");
        let dir = Path::new(&rel);
        assert!(dir.is_relative(), "child path must be relative: {dir:?}");
        #[cfg(unix)]
        {
            create_dir_all_synced(dir).expect("create relative chain");
            create_dir_all_synced(dir).expect("relative creation is idempotent");
        }
        #[cfg(not(unix))]
        {
            // No recursive creation here: the parents are test scaffolding.
            std::fs::create_dir_all(dir.parent().expect("relative case has a parent"))
                .expect("create relative parents");
            create_dir_published(dir).expect("publish relative directory");
        }
        let seg = create_file_published(&dir.join("seg")).expect("create file in relative dir");
        sync_file(&seg).expect("sync file");
        #[cfg(unix)]
        sync_dir(dir).expect("sync relative dir");
        let bare = create_file_published(Path::new("bare-file")).expect("create bare file");
        sync_file(&bare).expect("sync bare file");
    }

    /// Runs the child with `root/<case>/work` as its working directory and
    /// proves its relative paths landed there, so the parent never changes
    /// its own working directory.
    fn check_relative(root: &Path, case: &str, rel: &std::ffi::OsStr) {
        let work = root.join(case).join("work");
        std::fs::create_dir_all(&work).expect("create working directory");
        let output =
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .arg(CHILD_ENTRY)
                .arg("--exact")
                .arg("--ignored")
                .arg("--nocapture")
                .current_dir(&work)
                .env(CHILD_DIR_ENV, rel)
                .output()
                .expect("spawn relative-path child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child for {rel:?} failed: {:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
        assert!(
            stdout.contains("running 1 test"),
            "child filter {CHILD_ENTRY:?} matched no test; stdout: {stdout}"
        );
        let created = work.join(rel);
        assert!(created.is_dir(), "{} was not created", created.display());
        assert!(
            created.join("seg").is_file(),
            "no file under {}",
            created.display()
        );
        assert!(
            work.join("bare-file").is_file(),
            "no bare file in {}",
            work.display()
        );
    }

    #[test]
    fn relative_roots_resolve_against_the_working_directory() {
        let root = temp_root("relative");
        let cases = ["x/y/z", "../sibling/deep", "./dot/./dir/"];
        for (i, rel) in cases.iter().enumerate() {
            check_relative(&root, &format!("case{i}"), std::ffi::OsStr::new(rel));
        }
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Linux names are arbitrary bytes; macOS and Windows reject some.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_relative_names_are_preserved() {
        use std::os::unix::ffi::OsStrExt;
        let root = temp_root("non-utf8");
        check_relative(&root, "case", std::ffi::OsStr::from_bytes(b"n\xffx/m"));
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn rejects_interior_nul_before_any_side_effect() {
        use std::ffi::OsString;
        let root = temp_root("nul");
        let mut name = OsString::from("bad");
        name.push(std::ffi::OsStr::new("\0")); // interior NUL via WTF-8 bytes
        let path = root.join(name);
        let err = create_file_published(&path).unwrap_err();
        assert!(matches!(&err, StoreError::Io(io) if io.kind() == io::ErrorKind::InvalidInput));
        let err = create_dir_published(&path).unwrap_err();
        assert!(matches!(&err, StoreError::Io(io) if io.kind() == io::ErrorKind::InvalidInput));
        assert!(
            entry_names(&root).is_empty(),
            "no side effect before rejection"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn retained_handle_appends_after_publication() {
        use std::io::Write;
        let root = temp_root("retained");
        let target = root.join("seg_retained");
        let mut file = create_file_published(&target).expect("create published");
        file.write_all(b"tail").expect("append after move");
        sync_file(&file).expect("sync retained handle");
        drop(file);
        let content = std::fs::read(&target).expect("read target");
        assert_eq!(content, b"tail");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
