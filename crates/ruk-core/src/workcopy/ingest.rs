//! Hashing worktree bytes through the store's preparation path.
//!
//! A regular file is opened without following a final symlink (and without
//! blocking on a FIFO swapped in), checked to be the same file that was
//! observed, and streamed into [`Store::prepare`] for exactly the observed
//! length. The tuple is read again afterwards; if it moved, the bytes may
//! mix two versions, so the result is marked unstable and its row racy.
//! A file that shrinks while read, or is replaced by another type, is
//! observed again, a bounded number of times.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use super::crawl::{EntryKind, Observed, entry_kind, fs_path};
use super::io_error;
use super::statcache::FileStat;
use crate::ids::Oid;
use crate::index::FileMode;
use crate::store::{ObjectKind, PreparedObject, Store, StoreError};
use crate::{CoreError, ErrorCode};

/// Observation attempts for one path before it is reported as unstable.
const MAX_ATTEMPTS: usize = 4;

/// One hashed path.
#[derive(Debug)]
pub(crate) struct Hashed {
    pub(crate) blob: Oid,
    /// The prepared blob; publish it only when the blob is new to the tree.
    pub(crate) object: PreparedObject,
    pub(crate) stat: FileStat,
    pub(crate) kind: EntryKind,
    /// Whether the tuple was the same before and after the bytes were read.
    pub(crate) stable: bool,
}

/// What a path held when it was hashed.
#[derive(Debug)]
pub(crate) enum Ingested {
    Hashed(Hashed),
    /// It disappeared or became a directory or special file.
    Gone,
}

/// Hashes the current bytes of an observed path.
///
/// # Errors
/// `E_STALE` when the path keeps changing type or shrinking across every
/// attempt; `E_IO`, preparation admission (`E_LIMIT`, `E_CAPACITY`), and
/// quarantine.
pub(crate) fn ingest(
    store: &Store,
    root: &Path,
    observed: &Observed,
) -> Result<Ingested, CoreError> {
    let abs = fs_path(root, observed.path.as_bytes())?;
    let mut current = (observed.stat, observed.kind);
    for _ in 0..MAX_ATTEMPTS {
        let attempt = match current.1 {
            EntryKind::Symlink => hash_symlink(store, &abs, current.0),
            EntryKind::File { .. } => hash_file(store, &abs, current.0),
        };
        match attempt? {
            Attempt::Done(blob, object, stable_stat) => {
                return Ok(Ingested::Hashed(Hashed {
                    blob,
                    object,
                    stat: stable_stat.unwrap_or(current.0),
                    kind: current.1,
                    stable: stable_stat.is_some(),
                }));
            }
            Attempt::Moved => match relstat(&abs)? {
                Some(next) => current = next,
                None => return Ok(Ingested::Gone),
            },
        }
    }
    Err(CoreError::new(
        ErrorCode::EStale,
        format!(
            "{} kept changing while it was hashed",
            String::from_utf8_lossy(observed.path.as_bytes())
        ),
    ))
}

enum Attempt {
    /// The blob, its prepared object, and the tuple when it held still
    /// (`None`: it moved during the read).
    Done(Oid, PreparedObject, Option<FileStat>),
    /// The path is no longer the observed entry; observe it again.
    Moved,
}

fn relstat(abs: &Path) -> Result<Option<(FileStat, EntryKind)>, CoreError> {
    let meta = match fs::symlink_metadata(abs) {
        Ok(meta) => meta,
        Err(err) if is_absent(&err) => return Ok(None),
        Err(err) => return Err(io_error("reading worktree entry metadata", &err)),
    };
    match entry_kind(&meta) {
        Some(kind) => Ok(Some((FileStat::from_metadata(&meta)?, kind))),
        None => Ok(None),
    }
}

fn is_absent(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Whether two tuples name the same file object. Platforms without inode
/// numbers report zeros, which compare equal.
fn same_file(left: &FileStat, right: &FileStat) -> bool {
    left.data.dev == right.data.dev && left.data.ino == right.data.ino
}

fn hash_file(store: &Store, abs: &Path, observed: FileStat) -> Result<Attempt, CoreError> {
    let file = match open_no_follow(abs) {
        Ok(file) => file,
        Err(err) if is_absent(&err) || is_symlink_refusal(&err) => return Ok(Attempt::Moved),
        Err(err) => return Err(io_error("opening a worktree file", &err)),
    };
    let meta = file
        .metadata()
        .map_err(|err| io_error("reading open file metadata", &err))?;
    if !meta.file_type().is_file() {
        return Ok(Attempt::Moved);
    }
    let before = FileStat::from_metadata(&meta)?;
    if !same_file(&before, &observed) {
        return Ok(Attempt::Moved);
    }
    let len = before.data.size;
    let object = match store.prepare(ObjectKind::Blob, len, (&file).take(len), None) {
        Ok(object) => object,
        // A short read means the file shrank under the reader; anything
        // else wrong with an unchanged file is a real failure.
        Err(StoreError::Invalid(detail)) => {
            let unchanged = relstat(abs)?.is_some_and(|(now, _)| now == before);
            if unchanged {
                return Err(StoreError::Invalid(detail).into());
            }
            return Ok(Attempt::Moved);
        }
        Err(err) => return Err(err.into()),
    };
    let after = relstat(abs)?;
    let stable = after.is_some_and(|(now, _)| now == before);
    Ok(Attempt::Done(
        object.oid(),
        object,
        stable.then_some(before),
    ))
}

fn hash_symlink(store: &Store, abs: &Path, observed: FileStat) -> Result<Attempt, CoreError> {
    let target = match fs::read_link(abs) {
        Ok(target) => target,
        Err(err) if is_absent(&err) || err.kind() == io::ErrorKind::InvalidInput => {
            return Ok(Attempt::Moved);
        }
        Err(err) => return Err(io_error("reading a worktree symlink", &err)),
    };
    let bytes = link_bytes(&target)?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| CoreError::new(ErrorCode::ECapacity, "symlink target exceeds u64 bytes"))?;
    let object = store.prepare(ObjectKind::Blob, len, bytes.as_slice(), None)?;
    let after = relstat(abs)?;
    let stable = after.is_some_and(|(now, kind)| kind == EntryKind::Symlink && now == observed);
    Ok(Attempt::Done(
        object.oid(),
        object,
        stable.then_some(observed),
    ))
}

#[cfg(unix)]
fn link_bytes(target: &Path) -> Result<Vec<u8>, CoreError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(target.as_os_str().as_bytes().to_vec())
}

/// Git stores symlink targets with `/` separators.
#[cfg(not(unix))]
fn link_bytes(target: &Path) -> Result<Vec<u8>, CoreError> {
    let text = target.to_str().ok_or_else(|| {
        CoreError::new(
            ErrorCode::EInvalid,
            "a symlink target that is not Unicode cannot be recorded",
        )
    })?;
    Ok(text.replace('\\', "/").into_bytes())
}

#[cfg(unix)]
fn open_no_follow(abs: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "open flags out of range"))?;
    OpenOptions::new().read(true).custom_flags(flags).open(abs)
}

#[cfg(unix)]
fn is_symlink_refusal(err: &io::Error) -> bool {
    err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
}

/// Opens the reparse point itself rather than its target; the caller then
/// rejects anything that is not a regular file.
#[cfg(windows)]
fn open_no_follow(abs: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(abs)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(abs: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(abs)
}

#[cfg(not(unix))]
fn is_symlink_refusal(_err: &io::Error) -> bool {
    false
}

/// The tree mode of a hashed entry. Where the platform has no executable
/// bit, a regular file keeps the executable mode its base entry had.
#[must_use]
pub(crate) fn file_mode(kind: EntryKind, base: Option<FileMode>) -> FileMode {
    match kind {
        EntryKind::Symlink => FileMode::Symlink,
        EntryKind::File { executable: true } => FileMode::Executable,
        EntryKind::File { executable: false }
            if !cfg!(unix) && base == Some(FileMode::Executable) =>
        {
            FileMode::Executable
        }
        EntryKind::File { .. } => FileMode::Regular,
    }
}
