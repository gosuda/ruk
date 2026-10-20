//! Pinned store-directory file access.
//!
//! [`PinnedRoot`] keeps one directory descriptor for the store root,
//! opened when the store opens. Every later segment-file open, create,
//! metadata probe, unlink, and directory sync travels that descriptor
//! through `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, so a
//! symlink swapped into the recorded path after open cannot redirect the
//! access: the kernel refuses symlink components instead of following
//! them. A refused access fails closed as I/O; it never serves bytes
//! from outside the pinned directory.
//!
//! Without the descriptor (non-Linux builds, or callers that never
//! pinned) every helper falls back to the recorded path, preserving the
//! historical behavior. A kernel without `openat2` (`ENOSYS`) opens in
//! two steps against the held descriptor — the parent with `O_NOFOLLOW`,
//! then the final name with `O_NOFOLLOW` inside it — so no step traverses
//! a symlink there either. Any other refusal stays an error.
//!
//! Scope: segment files only. Scratch spools (`store_root/scratch`) and
//! LFS sidecars (`store_root/lfs/objects`) still travel the recorded
//! path by name.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::SEGMENTS_DIR;
use super::segment::segment_file_name;
use crate::store::error::StoreError;

/// The store root subdirectory holding the segment files.
fn segments_dir() -> &'static Path {
    Path::new(SEGMENTS_DIR)
}

/// The `segments/<file>` relative path of one segment id.
#[must_use]
pub(super) fn segment_rel(id: u64) -> PathBuf {
    segments_dir().join(segment_file_name(id))
}

/// One held store-root directory plus the recorded path it was opened
/// from. The descriptor pins every later segment access; the recorded
/// path serves the fallback and error display.
#[derive(Debug, Default)]
pub(super) struct PinnedRoot {
    record: PathBuf,
    #[cfg(unix)]
    fd: Option<rustix::fd::OwnedFd>,
}

impl PinnedRoot {
    /// Holds `dir` for later segment access. Fails closed when the
    /// directory cannot be held: without the descriptor no later access
    /// could be pinned. The descriptor is `O_PATH`: it names the
    /// directory for `openat2`/`openat`/`unlinkat` without data access,
    /// so it also reopens `/proc/self/fd` links of `O_PATH` descriptors
    /// the registry holds, where an `O_RDONLY` reopen is refused.
    ///
    /// # Errors
    /// [`StoreError::Io`] when `dir` is not an accessible directory.
    pub(super) fn open(dir: &Path) -> Result<Self, StoreError> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::open(
                dir,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|err| StoreError::Io(io::Error::from(err)))?;
            Ok(Self {
                record: dir.to_path_buf(),
                fd: Some(fd),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                record: dir.to_path_buf(),
            })
        }
    }

    /// A process-local path naming `name` inside the pinned directory:
    /// `/proc/self/fd/<n>/<name>` while a descriptor is held, so file
    /// APIs that only take paths (like the metadata database open) still
    /// travel the pin instead of the recorded path. Absent without a
    /// descriptor.
    #[must_use]
    pub(super) fn proc_subpath(&self, name: &str) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd as _;
            self.fd
                .as_ref()
                .map(|fd| PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())).join(name))
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            None
        }
    }

    /// Opens `rel` for reading through the pin, falling back to the
    /// recorded path without a descriptor or `openat2`.
    pub(super) fn open_read(&self, rel: &Path) -> io::Result<File> {
        #[cfg(unix)]
        if let Some(file) = self.open_at_optional(
            rel,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        )? {
            return Ok(file);
        }
        std::fs::File::open(self.record.join(rel))
    }

    /// Opens `rel` for reading and writing, without creating it, through
    /// the pin, falling back to the recorded path.
    pub(super) fn open_read_write(&self, rel: &Path) -> io::Result<File> {
        #[cfg(unix)]
        if let Some(file) =
            self.open_at_optional(rel, rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC)?
        {
            return Ok(file);
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.record.join(rel))
    }

    /// Creates `rel` exclusively for reading and writing through the pin,
    /// falling back to the recorded path. An existing name fails with
    /// `AlreadyExists` either way.
    pub(super) fn create_new(&self, rel: &Path) -> io::Result<File> {
        #[cfg(unix)]
        if let Some(file) = self.open_at_optional(
            rel,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC,
        )? {
            return Ok(file);
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.record.join(rel))
    }

    /// Unlinks `rel` through the pin, falling back to the recorded path
    /// without a descriptor. The parent opens first without following
    /// symlinks, then the final name unlinks inside it: neither step
    /// traverses a symlink, so a swapped `segments` link cannot divert
    /// the unlink outside the pinned directory. (Plain `unlinkat` over a
    /// multi-component relative path would still follow an intermediate
    /// symlink, so it is never used that way here.)
    pub(super) fn unlink(&self, rel: &Path) -> io::Result<()> {
        #[cfg(unix)]
        if let Some(fd) = self.fd.as_ref() {
            use rustix::fd::AsFd as _;
            check_rel(rel)?;
            let (parent, file) = split_final(rel)?;
            let dir = match parent {
                Some(dir_rel) => Some(self.open_dir_nosymlink(fd.as_fd(), dir_rel)?),
                None => None,
            };
            let dir_fd = match dir.as_ref() {
                Some(dir) => {
                    use rustix::fd::AsFd as _;
                    dir.as_fd()
                }
                None => fd.as_fd(),
            };
            return rustix::fs::unlinkat(dir_fd, file, rustix::fs::AtFlags::empty())
                .map_err(io::Error::from);
        }
        std::fs::remove_file(self.record.join(rel))
    }

    /// Stats `rel` through the pin, falling back to the recorded path.
    /// The identity comes from the pinned open itself, so a symlink
    /// swapped in after open reports the pinned file (or fails closed
    /// when a component is a symlink) instead of the swap target.
    pub(super) fn metadata(&self, rel: &Path) -> io::Result<std::fs::Metadata> {
        #[cfg(unix)]
        if self.fd.is_some() {
            return self.open_read(rel)?.metadata();
        }
        std::fs::metadata(self.record.join(rel))
    }

    /// Whether `rel` names an existing entry through the pin.
    pub(super) fn exists(&self, rel: &Path) -> bool {
        self.metadata(rel).is_ok()
    }

    /// Flushes the entries of the `rel` subdirectory through the pin,
    /// falling back to the recorded path without a descriptor or
    /// `openat2`. POSIX only flushes; elsewhere this is a no-op like
    /// the path-based sync it replaces.
    pub(super) fn sync_dir(&self, rel: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            if self.fd.is_some() {
                return self.open_at_dir(rel)?.sync_all();
            }
            super::durability::sync_dir(&self.record.join(rel)).map_err(|err| match err {
                StoreError::Io(inner) => inner,
                other => io::Error::other(other.to_string()),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = rel;
            Ok(())
        }
    }

    /// Flushes the segment directory entries after creates and unlinks.
    pub(super) fn sync_segments_dir(&self) -> io::Result<()> {
        self.sync_dir(segments_dir())
    }

    /// Opens `rel` through `openat2` with `RESOLVE_BENEATH |
    /// RESOLVE_NO_SYMLINKS`: `Ok(Some)` on success, `Ok(None)` when the
    /// caller must use the recorded path (no descriptor held), and `Err`
    /// for every other refusal, including symlink components and escapes.
    /// Without `openat2` (`ENOSYS`) the open goes through plain `openat`
    /// in two steps — the parent with `O_NOFOLLOW`, then the final name
    /// with `O_NOFOLLOW` inside it — so no step traverses a symlink.
    #[cfg(unix)]
    fn open_at_optional(&self, rel: &Path, flags: rustix::fs::OFlags) -> io::Result<Option<File>> {
        let Some(fd) = self.fd.as_ref() else {
            return Ok(None);
        };
        check_rel(rel)?;
        use rustix::fd::AsFd as _;
        match rustix::fs::openat2(
            fd.as_fd(),
            rel,
            flags,
            create_mode(flags),
            rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(child) => Ok(Some(File::from(child))),
            Err(rustix::io::Errno::NOSYS) => {
                Ok(Some(self.open_at_nosys(fd.as_fd(), rel, flags)?))
            }
            Err(err) => Err(io::Error::from(err)),
        }
    }

    /// Two-step fallback without `openat2`: the parent opens with
    /// `O_NOFOLLOW`, then the final name opens with `O_NOFOLLOW` inside
    /// it. Every caller shape here is `segments/<name>` or a bare
    /// `segments`, so one parent level suffices.
    #[cfg(unix)]
    fn open_at_nosys(
        &self,
        fd: rustix::fd::BorrowedFd<'_>,
        rel: &Path,
        flags: rustix::fs::OFlags,
    ) -> io::Result<File> {
        use rustix::fs::OFlags;
        let (parent, file) = split_final(rel)?;
        let dir: Option<rustix::fd::OwnedFd> = match parent {
            Some(dir_rel) => Some(
                rustix::fs::openat(
                    fd,
                    dir_rel,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io::Error::from)?,
            ),
            None => None,
        };
        let dir_fd = match dir.as_ref() {
            Some(dir) => {
                use rustix::fd::AsFd as _;
                dir.as_fd()
            }
            None => fd,
        };
        rustix::fs::openat(dir_fd, file, flags | OFlags::NOFOLLOW, create_mode(flags))
            .map(File::from)
            .map_err(io::Error::from)
    }

    /// Opens the single-component `dir` below the held descriptor without
    /// following a symlink, through `openat2` (`O_NOFOLLOW` without it).
    #[cfg(unix)]
    fn open_dir_nosymlink(
        &self,
        fd: rustix::fd::BorrowedFd<'_>,
        dir: &Path,
    ) -> io::Result<rustix::fd::OwnedFd> {
        use rustix::fs::OFlags;
        match rustix::fs::openat2(
            fd,
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(child) => Ok(child),
            Err(rustix::io::Errno::NOSYS) => rustix::fs::openat(
                fd,
                dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from),
            Err(err) => Err(io::Error::from(err)),
        }
    }

    /// Opens the `rel` subdirectory for syncing: through the pin when
    /// held (or when `openat2` is missing, the recorded path, whose sync
    /// matches the historical behavior), else the recorded path.
    #[cfg(unix)]
    fn open_at_dir(&self, rel: &Path) -> io::Result<File> {
        if let Some(file) = self.open_at_optional(
            rel,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
        )? {
            return Ok(file);
        }
        std::fs::File::open(self.record.join(rel))
    }
}

/// The mode for fd-relative opens: new files get the historical `0666`
/// masked by the umask (matching `create_new` path opens); anything else
/// ignores the mode.
#[cfg(unix)]
fn create_mode(flags: rustix::fs::OFlags) -> rustix::fs::Mode {
    use rustix::fs::{Mode, OFlags};
    if flags.contains(OFlags::CREATE) {
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
    } else {
        Mode::empty()
    }
}

/// Refuses anything but plain `dir/file` shapes: no absolute paths,
/// parent traversals, or current-dir components reach the fd-relative
/// calls. Every caller passes a generated `segments/<name>` path.
#[cfg(unix)]
fn check_rel(rel: &Path) -> io::Result<()> {
    use std::path::Component;
    if rel
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(())
    } else {
        Err(io::Error::other("refusing non-normal store-relative path"))
    }
}

/// Splits `rel` into its parent (absent for a bare name) and final
/// component for the two-step calls.
#[cfg(unix)]
fn split_final(rel: &Path) -> io::Result<(Option<&Path>, &std::ffi::OsStr)> {
    let file = rel
        .file_name()
        .ok_or_else(|| io::Error::other("store-relative path has no final name"))?;
    let parent = rel.parent().filter(|parent| !parent.as_os_str().is_empty());
    Ok((parent, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn scratch_dir(case: &str) -> PathBuf {
        let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ruk-pinned-{}-{seq}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("segments")).expect("scratch segments fits on disk");
        dir
    }

    #[test]
    fn segment_roundtrip_through_pin() {
        let dir = scratch_dir("roundtrip");
        let pin = PinnedRoot::open(&dir).expect("pin scratch dir");
        let rel = segment_rel(7);
        assert!(!pin.exists(&rel));
        let mut file = pin.create_new(&rel).expect("create through pin");
        use std::io::Write as _;
        file.write_all(b"seven").expect("write through pin");
        file.sync_all().expect("sync through pin");
        drop(file);
        let meta = pin.metadata(&rel).expect("created file stats through pin");
        assert_eq!(meta.len(), 5);
        assert!(pin.exists(&rel));
        let opened = pin.open_read(&rel).expect("open through pin");
        use std::io::Read as _;
        let mut got = Vec::new();
        std::io::BufReader::new(opened)
            .read_to_end(&mut got)
            .expect("read through pin");
        assert_eq!(got, b"seven");
        pin.unlink(&rel).expect("unlink through pin");
        assert!(!pin.exists(&rel));
        pin.sync_segments_dir().expect("segments dir syncs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn proc_subpath_survives_a_parent_swap() {
        let outer = std::env::temp_dir().join(format!("ruk-pinned-{}-procsub", std::process::id()));
        let _ = std::fs::remove_dir_all(&outer);
        std::fs::create_dir_all(outer.join("live")).expect("live dir fits on disk");
        std::fs::write(outer.join("live").join("marker"), b"pinned").expect("marker fits on disk");
        std::fs::create_dir_all(outer.join("shadow")).expect("shadow dir fits on disk");
        std::fs::write(outer.join("shadow").join("marker"), b"shadow")
            .expect("shadow marker fits on disk");
        let pin = PinnedRoot::open(&outer.join("live")).expect("pin live dir");
        let sub = pin.proc_subpath("marker").expect("proc subpath");
        assert_eq!(
            std::fs::read(&sub).expect("read through proc subpath"),
            b"pinned"
        );
        // Swap the name away and point it at the shadow: the previously
        // resolved subpath still names the pinned directory.
        std::fs::rename(outer.join("live"), outer.join("stashed")).expect("stash live");
        std::os::unix::fs::symlink(outer.join("shadow"), outer.join("live"))
            .expect("swap live link");
        assert_eq!(
            std::fs::read(&sub).expect("read through swap"),
            b"pinned",
            "a swapped parent cannot redirect the pinned subpath"
        );
        assert_eq!(
            std::fs::read(outer.join("live").join("marker")).expect("read by name"),
            b"shadow"
        );
        let _ = std::fs::remove_dir_all(&outer);
    }

    #[test]
    #[cfg(unix)]
    fn swapped_child_symlink_is_refused() {
        let dir = scratch_dir("swapchild");
        let pin = PinnedRoot::open(&dir).expect("pin scratch dir");
        let rel = segment_rel(9);
        pin.create_new(&rel).expect("create through pin");
        let outside = std::env::temp_dir().join(format!(
            "ruk-pinned-outside-{}-swapchild",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("outside dir fits on disk");
        std::fs::write(outside.join("seg_0000000000000009"), b"outside")
            .expect("outside file fits on disk");
        std::fs::rename(dir.join("segments"), dir.join("segments.real"))
            .expect("move segments aside");
        std::os::unix::fs::symlink(&outside, dir.join("segments")).expect("swap segments link");
        let read = pin.open_read(&rel);
        assert!(
            read.is_err(),
            "a swapped segments symlink fails closed instead of serving outside bytes"
        );
        let _ = std::fs::remove_file(dir.join("segments"));
        std::fs::rename(dir.join("segments.real"), dir.join("segments")).expect("restore segments");
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
