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
    let absolute = absolute(requested)?;
    let normalized = collapse_lexical(&absolute);
    let rel = match normalized.strip_prefix(root) {
        Ok(rel) => rel,
        Err(_) => return resolve_contained_unprefixed(root, &absolute),
    };
    if rel.as_os_str().is_empty() {
        return Ok(root.to_path_buf());
    }
    #[cfg(unix)]
    {
        match openat2_canonical(root, rel) {
            Ok(canonical) => {
                if canonical.starts_with(root) {
                    return Ok(canonical);
                }
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "repository path escapes the configured roots",
                ))
            }
            Err(err) if err.code == ErrorCode::EHosted => resolve_legacy(root, &absolute),
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
        let _ = rel;
        resolve_legacy(root, &absolute)
    }
}

/// Handles paths no lexical prefix of `root` covers: `..` spellings may
/// still land beneath it, so canonicalize once and re-route; anything else
/// is outside.
///
/// # Errors
/// As for [`resolve_contained`].
fn resolve_contained_unprefixed(root: &Path, absolute: &Path) -> Result<PathBuf, CoreError> {
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
        return Ok(root.to_path_buf());
    }
    #[cfg(unix)]
    {
        match openat2_canonical(root, rel) {
            Ok(canonical) => {
                if canonical.starts_with(root) {
                    return Ok(canonical);
                }
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "repository path escapes the configured roots",
                ))
            }
            Err(err) if err.code == ErrorCode::EHosted => resolve_legacy(root, absolute),
            Err(err) => Err(err),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = rel;
        resolve_legacy(root, absolute)
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

/// Resolves `rel` (already beneath `root`) through `openat2` with
/// `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, returning the canonical
/// path the kernel pinned.
///
/// # Errors
/// `E_NOT_FOUND` for a missing path, `E_FORBIDDEN` for symlink components
/// or escapes, `E_IO` for inaccessible paths, `E_HOSTED` where `openat2`
/// is unavailable so the caller falls back.
#[cfg(unix)]
fn openat2_canonical(root: &Path, rel: &Path) -> Result<PathBuf, CoreError> {
    use rustix::fd::{AsFd, OwnedFd};
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
    std::fs::read_link(&link).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("resolved path is not readable: {err}"),
        )
    })
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
