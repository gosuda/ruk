//! The bare repository layout.
//!
//! [`Layout`] creates the directories and installs every file through
//! `ruk_core::store::durability`: each file lands under a temporary name,
//! syncs, and publishes atomically, so a crash leaves a partial directory
//! with no `HEAD` — which Git does not recognize as a repository — rather
//! than a complete-looking corrupt one. Tests assert this order through the
//! recorded [`Layout::installed`] sequence: `HEAD` is always last, and the
//! pack precedes its index, which precedes the refs.
//!
//! The one canonical layout: `HEAD`, `config`, `description`,
//! `objects/{info,pack}`, `refs/{heads,tags}` (empty directories — every
//! direct ref lives in `packed-refs`), `packed-refs`, loose files only for
//! symbolic refs, `logs/<ref>` for exported refs with reflog rows, and
//! `shallow` when the closure has boundaries. No hooks or info/exclude
//! samples.
//!
//! `config` is the `git init --bare` shape: `core.repositoryformatversion`
//! 0, `core.filemode` true, `core.bare` true; a SHA-256 store uses version
//! 1 with `[extensions] objectformat = sha256`.

use std::path::{Path, PathBuf};

use ruk_core::ids::HashKind;
use ruk_core::refdata::RefName;
use ruk_core::store::durability::{create_dir_published, install_file};

use crate::GitError;

/// A file installed into the layout: its relative path and length, in
/// publication order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledFile {
    pub path: PathBuf,
    pub len: u64,
}

/// A bare repository under construction.
#[derive(Debug)]
pub struct Layout {
    root: PathBuf,
    kind: HashKind,
    /// Every installed file in publication order. Tests assert the order:
    /// first the pack, then its index, then the refs, and `HEAD` last.
    pub installed: Vec<InstalledFile>,
    /// Test-only failure point: when set, installing this relative path
    /// fails with [`GitError::Invalid`] before touching the filesystem.
    pub fail_at: Option<PathBuf>,
}

impl Layout {
    /// Creates the root and the fixed subdirectories. The root must not
    /// exist; its parent must exist (and, on Windows, be durable).
    ///
    /// # Errors
    /// [`GitError::Invalid`] when the root exists; [`GitError::Io`].
    pub fn create(root: &Path, kind: HashKind) -> Result<Self, GitError> {
        if std::fs::symlink_metadata(root)
            .map(|_| true)
            .or_else(|err| match err.kind() {
                std::io::ErrorKind::NotFound => Ok(false),
                _ => Err(super::pack::io_error(err)),
            })?
        {
            return Err(GitError::Invalid {
                detail: format!("export target {} already exists", root.display()),
            });
        }
        create_dir_published(root)?;
        for dir in [
            "objects",
            "objects/info",
            "objects/pack",
            "refs",
            "refs/heads",
            "refs/tags",
        ] {
            create_dir_published(&root.join(dir))?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            kind,
            installed: Vec::new(),
            fail_at: None,
        })
    }

    /// The hash kind this repository stores.
    #[must_use]
    pub const fn kind(&self) -> HashKind {
        self.kind
    }

    /// The repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The relative pack path for a stem: `objects/pack/<stem>.pack`.
    #[must_use]
    pub fn pack_relative(stem: &str) -> PathBuf {
        PathBuf::from(format!("objects/pack/{stem}.pack"))
    }

    /// The relative index path for a stem: `objects/pack/<stem>.idx`.
    #[must_use]
    pub fn idx_relative(stem: &str) -> PathBuf {
        PathBuf::from(format!("objects/pack/{stem}.idx"))
    }

    /// The absolute pack path for a stem.
    #[must_use]
    pub fn pack_path(&self, stem: &str) -> PathBuf {
        self.root.join(Self::pack_relative(stem))
    }

    /// The absolute index path for a stem.
    #[must_use]
    pub fn idx_path(&self, stem: &str) -> PathBuf {
        self.root.join(Self::idx_relative(stem))
    }

    /// Records a file installed outside [`Self::install`] (the pack, which
    /// streams through `install_file` under its final name) so the order
    /// assertion in tests sees the true publication sequence.
    pub(crate) fn note(&mut self, relative: &Path, len: u64) {
        self.installed.push(InstalledFile {
            path: relative.to_path_buf(),
            len,
        });
    }

    /// Installs one file, recording the order. Directories of the relative
    /// path are created on demand.
    ///
    /// # Errors
    /// [`GitError::Io`], or [`GitError::Invalid`] at the `fail_at` point.
    pub fn install(&mut self, relative: &Path, bytes: &[u8]) -> Result<(), GitError> {
        if self.fail_at.as_deref() == Some(relative) {
            return Err(GitError::Invalid {
                detail: format!("injected failure at {}", relative.display()),
            });
        }
        if let Some(parent) = relative.parent()
            && !parent.as_os_str().is_empty()
        {
            self.mkdirs(parent)?;
        }
        let path = self.root.join(relative);
        install_file(&path, |file| {
            use std::io::Write as _;
            file.write_all(bytes)?;
            Ok(())
        })
        .map_err(store_io)?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.note(relative, len);
        Ok(())
    }

    /// Creates each missing component of a relative directory, top-down.
    /// Existing directories (a prefix shared with an earlier file) are
    /// accepted: only one layout builder writes here.
    fn mkdirs(&mut self, relative: &Path) -> Result<(), GitError> {
        let mut current = PathBuf::new();
        for component in relative.components() {
            current.push(component);
            let path = self.root.join(&current);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    create_dir_published(&path)?;
                }
                Err(err) => return Err(super::pack::io_error(err)),
            }
        }
        Ok(())
    }
}

/// The `config` file for the hash kind.
#[must_use]
pub fn config_bytes(kind: HashKind) -> Vec<u8> {
    match kind {
        HashKind::Sha1 => b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n".to_vec(),
        HashKind::Sha256 => b"[core]\n\trepositoryformatversion = 1\n\tfilemode = true\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n"
            .to_vec(),
    }
}

/// The default `description` of an unnamed bare repository.
#[must_use]
pub fn description_bytes() -> Vec<u8> {
    b"Unnamed repository; edit this file 'description' to name the repository.\n".to_vec()
}

/// The reflog line for one entry: old and new ids, the committer identity,
/// its Unix time and zone, a tab, and the one-line message.
///
/// # Errors
/// [`GitError::Invalid`] for an id of another width.
pub fn reflog_line(
    old: Option<ruk_core::ids::Oid>,
    new: Option<ruk_core::ids::Oid>,
    committer: &ruk_core::conflict::Signature,
    message: &[u8],
    kind: HashKind,
) -> Result<Vec<u8>, GitError> {
    let zero = kind.zero_oid().to_hex();
    let mut line = Vec::new();
    match old {
        Some(oid) => {
            crate::require_kind(oid, kind)?;
            line.extend_from_slice(oid.to_hex().as_bytes());
        }
        None => line.extend_from_slice(zero.as_bytes()),
    }
    line.push(b' ');
    match new {
        Some(oid) => {
            crate::require_kind(oid, kind)?;
            line.extend_from_slice(oid.to_hex().as_bytes());
        }
        None => line.extend_from_slice(zero.as_bytes()),
    }
    line.push(b' ');
    line.extend_from_slice(&committer.render());
    line.push(b' ');
    line.extend_from_slice(committer.timestamp.to_string().as_bytes());
    line.push(b' ');
    line.extend_from_slice(committer.offset.to_string().as_bytes());
    line.push(b'\t');
    line.extend_from_slice(message);
    line.push(b'\n');
    Ok(line)
}

/// The relative log path for a ref: `logs/refs/heads/main`, byte-exact so
/// non-UTF-8 ref names survive.
#[must_use]
pub fn log_path(name: &RefName) -> PathBuf {
    let mut path = PathBuf::from("logs");
    for component in name.as_bytes().split(|&byte| byte == b'/') {
        path.push(os_component(component));
    }
    path
}

#[cfg(unix)]
fn os_component(bytes: &[u8]) -> &std::ffi::OsStr {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::OsStr::from_bytes(bytes)
}

#[cfg(not(unix))]
fn os_component(bytes: &[u8]) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt as _;
    let wide: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
    std::ffi::OsString::from_wide(&wide)
}

/// Lifts a store I/O error into the Git error surface.
pub(crate) fn store_io(err: ruk_core::store::StoreError) -> GitError {
    GitError::from(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_order_is_recorded_with_head_last() {
        let dir = std::env::temp_dir().join(format!(
            "ruk-layout-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut layout = Layout::create(&dir, HashKind::Sha1).unwrap();
        // The pipeline order: pack, index, refs, then HEAD last.
        layout.note(&Layout::pack_relative("pack-abc"), 100);
        layout.note(&Layout::idx_relative("pack-abc"), 50);
        layout.install(Path::new("packed-refs"), b"refs").unwrap();
        layout
            .install(Path::new("HEAD"), b"ref: refs/heads/main\n")
            .unwrap();
        let order: Vec<&str> = layout
            .installed
            .iter()
            .map(|file| file.path.to_str().unwrap())
            .collect();
        assert_eq!(
            order,
            [
                "objects/pack/pack-abc.pack",
                "objects/pack/pack-abc.idx",
                "packed-refs",
                "HEAD",
            ]
        );
        assert!(dir.join("HEAD").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn injected_failure_leaves_no_partial_file() {
        let dir = std::env::temp_dir().join(format!(
            "ruk-layout-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut layout = Layout::create(&dir, HashKind::Sha1).unwrap();
        layout.install(Path::new("packed-refs"), b"refs").unwrap();
        layout.fail_at = Some(PathBuf::from("HEAD"));
        let error = layout.install(Path::new("HEAD"), b"ref: refs/heads/main\n");
        assert!(matches!(error, Err(GitError::Invalid { .. })));
        assert!(!dir.join("HEAD").exists());
        assert!(dir.join("packed-refs").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn configs_match_git_init_bare() {
        let sha1 = String::from_utf8(config_bytes(HashKind::Sha1)).unwrap();
        assert_eq!(
            sha1,
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
        );
        let sha256 = String::from_utf8(config_bytes(HashKind::Sha256)).unwrap();
        assert!(sha256.contains("repositoryformatversion = 1"));
        assert!(sha256.contains("objectformat = sha256"));
        assert!(
            String::from_utf8(description_bytes())
                .unwrap()
                .starts_with("Unnamed repository;")
        );
    }
}
