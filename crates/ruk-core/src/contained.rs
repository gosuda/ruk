//! Symlink-safe path containment for repository opens.
//!
//! Every hosted open resolves a caller-supplied path to a canonical path
//! beneath a configured root. A lexical prefix check after
//! [`std::fs::canonicalize`] cannot do that safely: a path component the
//! check approved can be swapped for a symlink before the caller opens the
//! result. On Linux this module resolves through `openat2` with
//! `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, so the kernel refuses
//! escapes and symlink components atomically instead of checking a string
//! the filesystem may already have changed. Off Linux (or on kernels
//! without `openat2`) it falls back to the canonicalize-and-prefix check.

use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, ErrorCode};

#[cfg(unix)]
use rustix::fd::OwnedFd;

/// A resolved repository directory with its kernel-pinned identity.
///
/// The directory file descriptor stays open from resolution through the
/// store open, so a symlink swapped in after resolution cannot redirect
/// the open: verification compares the opened directory against the
/// identity read from the pinned descriptor. Resolutions without a
/// descriptor (legacy fallback) carry no identity and skip verification.
#[derive(Debug)]
pub struct PinnedDir {
    path: PathBuf,
    #[cfg(unix)]
    dir: Option<OwnedFd>,
    dev: Option<u64>,
    ino: Option<u64>,
    uid: Option<u32>,
}

impl PinnedDir {
    /// The resolved canonical path to open.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The owner identity read from the pinned descriptor, if pinned.
    #[must_use]
    pub fn owner_uid(&self) -> Option<u32> {
        self.uid
    }

    /// The `/proc/self/fd` path opening through the pinned descriptor.
    /// File accesses through it cannot escape the pinned directory even
    /// when the recorded path components move afterward. Absent without
    /// a descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn open_path(&self) -> Option<PathBuf> {
        use std::os::unix::io::AsRawFd as _;
        self.dir
            .as_ref()
            .map(|fd| PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())))
    }

    /// A resolution without a kernel pin: legacy fallback paths verify
    /// nothing and keep their previous behavior.
    pub fn unverified(path: PathBuf) -> Self {
        Self {
            path,
            #[cfg(unix)]
            dir: None,
            dev: None,
            ino: None,
            uid: None,
        }
    }

    /// Rejects an opened store directory whose identity left the pinned
    /// one. A mismatch means the path moved between resolution and open,
    /// so the open is dropped and the path refused. Unpinned resolutions
    /// keep the legacy behavior.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when the opened directory is not the pinned one,
    /// `E_IO` when its identity is unreadable.
    pub fn verify_open(&self, opened: &Path) -> Result<(), CoreError> {
        #[cfg(unix)]
        {
            let (dev, ino) = match (self.dev, self.ino) {
                (Some(dev), Some(ino)) => (dev, ino),
                _ => return Ok(()),
            };
            use std::os::unix::fs::MetadataExt as _;
            let current = std::fs::metadata(opened).map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("opened store identity is not readable: {err}"),
                )
            })?;
            if current.dev() != dev || current.ino() != ino {
                return Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "repository path escapes the configured roots",
                ));
            }
        }
        let _ = opened;
        Ok(())
    }
}

/// Collapses `.` and `..` lexically, without touching the filesystem.
///
/// Routing only: containment itself is enforced by `openat2` (or, on
/// fallback, by the prefix check on the canonicalized path), never by this
/// normalization.
fn collapse_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    out
}

/// Makes `requested` absolute against the process working directory.
///
/// # Errors
/// `E_IO` when the working directory is unreadable.
fn absolute(requested: &Path) -> Result<PathBuf, CoreError> {
    if requested.is_absolute() {
        return Ok(requested.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("working directory is not readable: {err}"),
        )
    })?;
    Ok(cwd.join(requested))
}

/// Resolves `requested` to a canonical path beneath canonical `root`.
///
/// # Errors
/// `E_NOT_FOUND` for a missing path, `E_FORBIDDEN` outside `root` or
/// through a symlink component, `E_IO` when the path is inaccessible.
pub fn resolve_contained(root: &Path, requested: &Path) -> Result<PathBuf, CoreError> {
    Ok(resolve_contained_pinned(root, requested)?.path)
}

/// Resolves `requested` beneath canonical `root`, holding the kernel
/// pin: the returned descriptor stays open from resolution through the
/// store open, and its identity verifies the opened directory. Paths
/// the legacy fallback resolves carry no pin and skip verification.
///
/// # Errors
/// `E_NOT_FOUND` for a missing path, `E_FORBIDDEN` outside `root` or
/// through a symlink component, `E_IO` when the path is inaccessible.
pub fn resolve_contained_pinned(root: &Path, requested: &Path) -> Result<PinnedDir, CoreError> {
    let absolute = absolute(requested)?;
    let normalized = collapse_lexical(&absolute);
    let rel = match normalized.strip_prefix(root) {
        Ok(rel) => rel,
        Err(_) => return resolve_contained_unprefixed_pinned(root, &absolute),
    };
    if rel.as_os_str().is_empty() {
        return pin_root(root);
    }
    #[cfg(unix)]
    {
        match openat2_pinned(root, rel) {
            Ok((fd, canonical)) => {
                if canonical.starts_with(root) {
                    return pinned(fd, canonical);
                }
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "repository path escapes the configured roots",
                ))
            }
            Err(err) if err.code == ErrorCode::EHosted => {
                Ok(PinnedDir::unverified(resolve_legacy(root, &absolute)?))
            }
            Err(err) => {
                if err.code == ErrorCode::ENotFound {
                    return Err(err);
                }
                Err(err)
            }
        }
    }
    #[cfg(not(unix))]
    {
        Ok(PinnedDir::unverified(resolve_legacy(root, &absolute)?))
    }
}

/// Pins an already-canonical root directory itself.
fn pin_root(root: &Path) -> Result<PinnedDir, CoreError> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        let fd = open(root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("repository root is not accessible: {err}"),
            )
        })?;
        pinned(fd, root.to_path_buf())
    }
    #[cfg(not(unix))]
    {
        Ok(PinnedDir::unverified(root.to_path_buf()))
    }
}

/// Reads the kernel identity of a pinned descriptor.
#[cfg(unix)]
fn pinned(fd: OwnedFd, canonical: PathBuf) -> Result<PinnedDir, CoreError> {
    let stat = rustix::fs::fstat(&fd).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("pinned directory identity is not readable: {err}"),
        )
    })?;
    Ok(PinnedDir {
        path: canonical,
        dir: Some(fd),
        dev: Some(stat.st_dev),
        ino: Some(stat.st_ino),
        uid: Some(stat.st_uid),
    })
}

/// Handles paths no lexical prefix of `root` covers with the kernel pin
/// held: `..` spellings may still land beneath it, so canonicalize once
/// and re-route; anything else is outside.
///
/// # Errors
/// As for [`resolve_contained_pinned`].
fn resolve_contained_unprefixed_pinned(
    root: &Path,
    absolute: &Path,
) -> Result<PinnedDir, CoreError> {
    let canonical = match std::fs::canonicalize(absolute) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                "repository path is unknown",
            ));
        }
        Err(err) => {
            return Err(CoreError::new(
                ErrorCode::EIo,
                format!("repository path is not accessible: {err}"),
            ));
        }
    };
    let rel = canonical.strip_prefix(root).map_err(|_| {
        CoreError::new(
            ErrorCode::EForbidden,
            "repository path is outside the configured roots",
        )
    })?;
    if rel.as_os_str().is_empty() {
        return pin_root(root);
    }
    #[cfg(unix)]
    {
        match openat2_pinned(root, rel) {
            Ok((fd, canonical)) => {
                if canonical.starts_with(root) {
                    return pinned(fd, canonical);
                }
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "repository path escapes the configured roots",
                ))
            }
            Err(err) if err.code == ErrorCode::EHosted => {
                Ok(PinnedDir::unverified(resolve_legacy(root, absolute)?))
            }
            Err(err) => Err(err),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(PinnedDir::unverified(resolve_legacy(root, absolute)?))
    }
}

/// Legacy canonicalize-and-prefix resolution for kernels without
/// `openat2`.
///
/// # Errors
/// `E_NOT_FOUND` for a missing path, `E_IO` when the path is
/// inaccessible, `E_FORBIDDEN` outside `root`.
fn resolve_legacy(root: &Path, absolute: &Path) -> Result<PathBuf, CoreError> {
    let canonical = match std::fs::canonicalize(absolute) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                "repository path is unknown",
            ));
        }
        Err(err) => {
            return Err(CoreError::new(
                ErrorCode::EIo,
                format!("repository path is not accessible: {err}"),
            ));
        }
    };
    if canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(CoreError::new(
            ErrorCode::EForbidden,
            "repository path is outside the configured roots",
        ))
    }
}

/// Opens `rel` (already beneath `root`) through `openat2` with
/// `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, returning the held
/// directory descriptor plus the canonical path the kernel pinned.
/// Dropping the descriptor ends the pin; callers that verify after an
/// open keep it in a [`PinnedDir`].
///
/// # Errors
/// `E_NOT_FOUND` for a missing path, `E_FORBIDDEN` for symlink components
/// or escapes, `E_IO` for inaccessible paths, `E_HOSTED` where `openat2`
/// is unavailable so the caller falls back.
#[cfg(unix)]
fn openat2_pinned(root: &Path, rel: &Path) -> Result<(OwnedFd, PathBuf), CoreError> {
    use rustix::fd::AsFd;
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
    use std::os::unix::io::AsRawFd;

    let root_fd: OwnedFd =
        open(root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).map_err(|err| match err {
            rustix::io::Errno::NOENT => {
                CoreError::new(ErrorCode::ENotFound, "repository path is unknown")
            }
            _ => CoreError::new(
                ErrorCode::EIo,
                format!("repository root is not accessible: {err}"),
            ),
        })?;
    let fd = openat2(
        root_fd.as_fd(),
        rel,
        OFlags::PATH,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|err| match err {
        rustix::io::Errno::NOENT => {
            CoreError::new(ErrorCode::ENotFound, "repository path is unknown")
        }
        rustix::io::Errno::NOSYS => {
            CoreError::new(ErrorCode::EHosted, "openat2 is unavailable on this kernel")
        }
        rustix::io::Errno::LOOP | rustix::io::Errno::XDEV => CoreError::new(
            ErrorCode::EForbidden,
            "repository path escapes the configured roots",
        ),
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => CoreError::new(
            ErrorCode::EIo,
            format!("repository path is not accessible: {err}"),
        ),
        _ => CoreError::new(
            ErrorCode::EIo,
            format!("repository path is not accessible: {err}"),
        ),
    })?;
    let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let canonical = std::fs::read_link(&link).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("resolved path is not readable: {err}"),
        )
    })?;
    Ok((fd, canonical))
}

/// Resolves a not-yet-existing destination: canonicalizes the nearest
/// existing ancestor beneath `root` and refuses symlink components below
/// it. Trailing components that do not exist yet pass through; existing
/// ones must not be symlinks.
///
/// # Errors
/// `E_NOT_FOUND` when no ancestor exists beneath `root`, `E_FORBIDDEN`
/// for symlink components or paths outside `root`, `E_IO` when the path
/// is inaccessible.
pub fn resolve_new_destination(root: &Path, requested: &Path) -> Result<PathBuf, CoreError> {
    let absolute = absolute(requested)?;
    let normalized = collapse_lexical(&absolute);
    let mut ancestor = normalized.as_path();
    loop {
        if std::fs::symlink_metadata(ancestor).is_ok() {
            break;
        }
        match ancestor.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => ancestor = parent,
            _ => {
                return Err(CoreError::new(
                    ErrorCode::ENotFound,
                    "repository path is unknown",
                ));
            }
        }
    }
    let canonical = resolve_contained(root, ancestor)?;
    let rest = normalized
        .strip_prefix(ancestor)
        .map_err(|_| CoreError::new(ErrorCode::EIo, "internal: ancestor left its path"))?;
    let mut built = canonical;
    for component in rest.components() {
        built.push(component.as_os_str());
        match std::fs::symlink_metadata(&built) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "destination crosses a symlink",
                ));
            }
            _ => {}
        }
    }
    Ok(built)
}
