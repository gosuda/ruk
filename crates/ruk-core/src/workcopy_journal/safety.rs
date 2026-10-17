//! Path safety for materialization.
//!
//! Strategy (one, used everywhere): lexical join plus a no-follow walk.
//!
//! 1. Lexical: a [`RepoPath`] is already normalized (no empty, `.` or `..`
//!    component, no NUL, no leading `/`, no `.git`). [`check_repo_path`]
//!    adds the materialization rules: nothing under `.ruk` (ASCII
//!    case-insensitively, ignoring trailing dots and spaces), and on Windows
//!    no `\`, `:` or non-UTF-8 component, so no component can be rooted or
//!    name a drive or stream. Each component is joined to the canonical
//!    root one at a time.
//! 2. Live: before every observation or mutation, every strict ancestor is
//!    `lstat`ed from the root down. Only a real directory (not a symlink)
//!    is descended through; the walk stops at the first missing or
//!    non-directory component. Leaves are never followed: symlinks are read
//!    with `readlink`, replaced by rename, and removed with `unlink`, and
//!    regular files are opened with `O_NOFOLLOW` on POSIX and re-checked on
//!    the open handle.
//!
//! Residual window: an actor that swaps an ancestor directory for a symlink
//! between the walk and the following syscall is not fenced; workspace
//! actors with filesystem access are cooperating, not hostile (core
//! contract). Every write is followed by verification through a fresh walk
//! before the journal clears.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::RepoPath;

use super::journal::Shape;

/// The reserved metadata directory in every workspace root.
const RUK_DIR: &[u8] = b".ruk";

/// Rejects paths materialization may never touch.
pub(crate) fn check_repo_path(path: &RepoPath) -> Result<(), CoreError> {
    let invalid = |detail: &str| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("{}: {detail}", String::from_utf8_lossy(path.as_bytes())),
        )
    };
    if let Some(first) = path.components().next()
        && is_ruk_dir(first)
    {
        return Err(invalid("paths inside .ruk are never materialized"));
    }
    if cfg!(windows) {
        if path.to_utf8().is_none() {
            return Err(invalid("non-UTF-8 paths cannot be materialized on Windows"));
        }
        if path
            .components()
            .any(|component| component.iter().any(|byte| matches!(byte, b'\\' | b':')))
        {
            return Err(invalid("rooted, drive or stream component"));
        }
    }
    Ok(())
}

fn is_ruk_dir(component: &[u8]) -> bool {
    let trimmed = component
        .iter()
        .rposition(|byte| !matches!(byte, b'.' | b' '))
        .map_or(&component[..0], |last| &component[..=last]);
    trimmed.eq_ignore_ascii_case(RUK_DIR)
}

/// The canonical workspace root.
#[derive(Debug, Clone)]
pub(crate) struct WorkRoot {
    root: PathBuf,
}

/// Where the ancestor walk of a path stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ancestry {
    /// Every strict ancestor is a real directory.
    Clear,
    /// The first ancestor (`depth` components) does not exist.
    Missing { depth: usize },
    /// The first ancestor that is neither missing nor a real directory.
    Blocked { ancestor: Vec<u8> },
}

/// What a path physically is, observed without following any symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observed {
    Absent,
    File {
        executable: bool,
        oid: Oid,
    },
    Symlink {
        link: Vec<u8>,
        oid: Oid,
    },
    Dir,
    /// A FIFO, socket or device: never captured, never overwritten.
    Other,
}

impl WorkRoot {
    /// Canonicalizes `root`, which must be an existing directory.
    pub(crate) fn open(root: &Path) -> Result<Self, CoreError> {
        let root = fs::canonicalize(root).map_err(|err| io_error("canonicalize", root, &err))?;
        let meta = fs::symlink_metadata(&root).map_err(|err| io_error("stat", &root, &err))?;
        if !meta.is_dir() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("workspace root {} is not a directory", root.display()),
            ));
        }
        Ok(Self { root })
    }

    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }

    /// The physical path of a repository path or ancestor prefix, joined
    /// one component at a time.
    pub(crate) fn join(&self, bytes: &[u8]) -> Result<PathBuf, CoreError> {
        let mut full = self.root.clone();
        for component in bytes.split(|&byte| byte == b'/') {
            full.push(component_os(component)?);
        }
        Ok(full)
    }

    /// Walks every strict ancestor of `path` with `lstat`.
    pub(crate) fn ancestry(&self, path: &RepoPath) -> Result<Ancestry, CoreError> {
        let mut current = self.root.clone();
        let bytes = path.as_bytes();
        let components: Vec<&[u8]> = path.components().collect();
        let Some((_, parents)) = components.split_last() else {
            return Ok(Ancestry::Clear);
        };
        let mut end = 0_usize;
        for (depth, component) in parents.iter().enumerate() {
            end += component.len() + usize::from(depth > 0);
            current.push(component_os(component)?);
            match lstat(&current)? {
                None => return Ok(Ancestry::Missing { depth: depth + 1 }),
                Some(meta) if is_real_dir(&meta) => {}
                Some(_) => {
                    return Ok(Ancestry::Blocked {
                        ancestor: bytes[..end].to_vec(),
                    });
                }
            }
        }
        Ok(Ancestry::Clear)
    }

    /// The physical path of `path` when every ancestor is a real directory;
    /// `None` when an ancestor is missing; `E_INVALID` naming the blocker
    /// when an ancestor is a file or symlink, which nothing may traverse.
    pub(crate) fn resolve_clear(&self, path: &RepoPath) -> Result<Option<PathBuf>, CoreError> {
        match self.ancestry(path)? {
            Ancestry::Clear => self.join(path.as_bytes()).map(Some),
            Ancestry::Missing { .. } => Ok(None),
            Ancestry::Blocked { ancestor } => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "{} lies beyond non-directory {}; refusing to traverse it",
                    String::from_utf8_lossy(path.as_bytes()),
                    String::from_utf8_lossy(&ancestor)
                ),
            )),
        }
    }

    /// Observes `path` without following any symlink. A path behind a
    /// missing or non-directory ancestor is absent inside this workspace.
    pub(crate) fn observe(&self, kind: HashKind, path: &RepoPath) -> Result<Observed, CoreError> {
        if self.ancestry(path)? != Ancestry::Clear {
            return Ok(Observed::Absent);
        }
        let full = self.join(path.as_bytes())?;
        observe_leaf(kind, &full)
    }
}

/// Observes one leaf whose ancestors were already checked.
pub(crate) fn observe_leaf(kind: HashKind, full: &Path) -> Result<Observed, CoreError> {
    let Some(meta) = lstat(full)? else {
        return Ok(Observed::Absent);
    };
    let file_type = meta.file_type();
    // The symlink arm comes first: on Windows every symlink is also a
    // reparse point, so the reparse check below would otherwise swallow
    // them. `is_symlink` itself is tag-gated on Windows (junctions and
    // mounts are not symlinks), so only real links land here.
    if is_symlink(&file_type) {
        let link = read_link_bytes(full)?;
        let oid = kind
            .hash_git_object("blob", &link)
            .map_err(CoreError::from)?;
        return Ok(Observed::Symlink { link, oid });
    }
    if is_reparse_point(&meta) {
        // A remaining reparse point that reads as a directory is a
        // junction or mount: never descend through it.
        return Ok(Observed::Other);
    }
    if file_type.is_dir() {
        return Ok(Observed::Dir);
    }
    if !file_type.is_file() {
        return Ok(Observed::Other);
    }
    let file = open_no_follow(full)?;
    let meta = file
        .metadata()
        .map_err(|err| io_error("stat", full, &err))?;
    if !meta.is_file() {
        return Ok(Observed::Other);
    }
    let oid = hash_blob(kind, meta.len(), file).map_err(|err| io_error("read", full, &err))?;
    let Some(oid) = oid else {
        return Err(CoreError::new(
            ErrorCode::EDirty,
            format!("{} changed size while it was read", full.display()),
        ));
    };
    Ok(Observed::File {
        executable: is_executable(&meta),
        oid,
    })
}

/// Whether `file_type` (from `symlink_metadata`, so the leaf itself) is a
/// real symbolic link. On Windows this checks the reparse tag, not just
/// the attribute: junctions and mounts are excluded.
#[cfg(windows)]
fn is_symlink(file_type: &std::fs::FileType) -> bool {
    use std::os::windows::fs::FileTypeExt;
    file_type.is_symlink_dir() || file_type.is_symlink_file()
}

/// Whether `file_type` (from `symlink_metadata`, so the leaf itself) is a
/// real symbolic link. On Windows this checks the reparse tag, not just
/// the attribute: junctions and mounts are excluded.
#[cfg(not(windows))]
fn is_symlink(file_type: &std::fs::FileType) -> bool {
    file_type.is_symlink()
}

/// A physical directory this logic may descend through: never a symlink,
/// and never a Windows reparse point (junctions and mounts read as
/// directories otherwise).
pub(crate) fn is_real_dir(meta: &Metadata) -> bool {
    meta.is_dir() && !is_reparse_point(meta)
}

#[cfg(windows)]
fn is_reparse_point(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &Metadata) -> bool {
    false
}

impl Shape {
    /// Whether the observed state is exactly this shape. The executable bit
    /// is compared only where the platform records it.
    pub(crate) fn matches(&self, observed: &Observed) -> bool {
        match (self, observed) {
            (Self::Absent, Observed::Absent) | (Self::Dir, Observed::Dir) => true,
            (
                Self::File { executable, oid },
                Observed::File {
                    executable: seen_exec,
                    oid: seen_oid,
                },
            ) => oid == seen_oid && (!cfg!(unix) || executable == seen_exec),
            (Self::Symlink { link }, Observed::Symlink { link: seen, .. }) => link == seen,
            _ => false,
        }
    }
}

/// `lstat`, with absence (including a non-directory parent) as `None`.
pub(crate) fn lstat(path: &Path) -> Result<Option<Metadata>, CoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(io_error("stat", path, &err)),
    }
}

/// Streams a Git blob hash of exactly `len` bytes. `None` when the reader
/// yields a different length (the file changed while it was read).
pub(crate) fn hash_blob(
    kind: HashKind,
    len: u64,
    mut reader: impl Read,
) -> io::Result<Option<Oid>> {
    let mut hasher = gix_hash::hasher(kind.gix());
    hasher.update(format!("blob {len}\0").as_bytes());
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > len {
            return Ok(None);
        }
        hasher.update(&buffer[..read]);
    }
    if total != len {
        return Ok(None);
    }
    hasher
        .try_finalize()
        .map(|oid| Some(Oid::from(oid)))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

/// Opens an existing regular file for reading without following a final
/// symlink.
pub(crate) fn open_no_follow(path: &Path) -> Result<File, CoreError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    options
        .open(path)
        .map_err(|err| io_error("open", path, &err))
}

#[cfg(unix)]
fn is_executable(meta: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn component_os(component: &[u8]) -> Result<&std::ffi::OsStr, CoreError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::OsStr::from_bytes(component))
}

#[cfg(not(unix))]
fn component_os(component: &[u8]) -> Result<&std::ffi::OsStr, CoreError> {
    std::str::from_utf8(component)
        .map(std::ffi::OsStr::new)
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "non-UTF-8 path component"))
}

#[cfg(unix)]
fn read_link_bytes(path: &Path) -> Result<Vec<u8>, CoreError> {
    use std::os::unix::ffi::OsStringExt;
    fs::read_link(path)
        .map(|target| target.into_os_string().into_vec())
        .map_err(|err| io_error("readlink", path, &err))
}

#[cfg(not(unix))]
fn read_link_bytes(path: &Path) -> Result<Vec<u8>, CoreError> {
    let target = fs::read_link(path).map_err(|err| io_error("readlink", path, &err))?;
    target
        .into_os_string()
        .into_string()
        .map(|text| text.replace('\\', "/").into_bytes())
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "non-UTF-8 symlink target"))
}

/// An I/O failure on a worktree path, as `E_IO` naming the operation.
pub(crate) fn io_error(op: &str, path: &Path, err: &io::Error) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("{op} {}: {err}", path.display()))
}
