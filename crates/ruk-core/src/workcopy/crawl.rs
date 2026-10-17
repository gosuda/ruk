//! Scoped, bounded-parallel worktree crawl and single-path probes.
//!
//! The crawl never follows symlinks: entry types come from the directory
//! listing, a symlink is reported as a symlink entry, and only real
//! directories are descended. It skips the internal directory at the root,
//! names that cannot be repository paths, nested repositories (a directory
//! holding `.git`), and directories the cone scope does not visit, so
//! out-of-scope trees are never read.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use super::statcache::FileStat;
use super::{INTERNAL_DIR, io_error, join};
use crate::index::RepoPath;
use crate::workspace::Scope;
use crate::{CoreError, ErrorCode};

/// The kind of a crawled non-directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// A regular file; `executable` is the owner-exec bit where the
    /// platform has one and `false` elsewhere.
    File { executable: bool },
    Symlink,
}

/// One in-scope file or symlink and the tuple observed for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) path: RepoPath,
    pub(crate) stat: FileStat,
    pub(crate) kind: EntryKind,
}

/// Bounds for one crawl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CrawlLimits {
    pub(crate) workers: NonZeroUsize,
    /// Most entries one crawl may report before it fails `E_CAPACITY`.
    pub(crate) max_entries: usize,
}

impl CrawlLimits {
    /// Up to eight workers and ten million entries.
    #[must_use]
    pub(crate) fn reference() -> Self {
        let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        Self {
            workers: NonZeroUsize::new(available.min(8)).unwrap_or(NonZeroUsize::MIN),
            max_entries: 10_000_000,
        }
    }
}

/// The filesystem path of a repository-relative byte path under `root`.
///
/// # Errors
/// `E_INVALID` on platforms whose paths are not byte strings, for a path
/// that is not UTF-8.
pub(crate) fn fs_path(root: &Path, rel: &[u8]) -> Result<PathBuf, CoreError> {
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    Ok(root.join(os_path(rel)?))
}

#[cfg(unix)]
fn os_path(rel: &[u8]) -> Result<PathBuf, CoreError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(rel)))
}

#[cfg(not(unix))]
fn os_path(rel: &[u8]) -> Result<PathBuf, CoreError> {
    let text = std::str::from_utf8(rel).map_err(|_| {
        CoreError::new(
            ErrorCode::EInvalid,
            "a non-UTF-8 path cannot be named on this platform",
        )
    })?;
    Ok(text.split('/').collect())
}

/// The bytes of one directory-entry name, or `None` when the platform name
/// has no byte form (unpaired UTF-16 on Windows); such entries are skipped.
#[cfg(unix)]
fn name_bytes(name: &std::ffi::OsStr) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Some(name.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn name_bytes(name: &std::ffi::OsStr) -> Option<Vec<u8>> {
    name.to_str().map(|text| text.as_bytes().to_vec())
}

/// Classifies lstat metadata. Directories and special files yield `None`.
#[must_use]
pub(crate) fn entry_kind(meta: &fs::Metadata) -> Option<EntryKind> {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Some(EntryKind::Symlink);
    }
    if !file_type.is_file() {
        return None;
    }
    Some(EntryKind::File {
        executable: executable_bit(meta),
    })
}

#[cfg(unix)]
fn executable_bit(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn executable_bit(_meta: &fs::Metadata) -> bool {
    false
}

/// Whether a real directory holds `.git`, making it a nested repository.
fn is_nested_repository(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(".git")).is_ok()
}

fn not_present(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

#[derive(Default)]
struct Queue {
    pending: Vec<Vec<u8>>,
    active: usize,
    found: Vec<Observed>,
    error: Option<CoreError>,
}

/// Crawls every visited directory below each start directory (an empty
/// slice means the whole worktree) and reports every in-scope file and
/// symlink. A start directory that vanished contributes nothing.
///
/// # Errors
/// `E_IO` for unreadable directories or entries, `E_CAPACITY` past
/// `limits.max_entries`.
pub(crate) fn crawl(
    root: &Path,
    starts: &[RepoPath],
    scope: &Scope,
    limits: CrawlLimits,
) -> Result<Vec<Observed>, CoreError> {
    let pending = if starts.is_empty() {
        vec![Vec::new()]
    } else {
        starts.iter().map(|path| path.as_bytes().to_vec()).collect()
    };
    let queue = Mutex::new(Queue {
        pending,
        ..Queue::default()
    });
    let ready = Condvar::new();
    std::thread::scope(|threads| {
        for _ in 0..limits.workers.get() {
            threads.spawn(|| crawl_worker(root, scope, limits, &queue, &ready));
        }
    });
    let queue = queue.into_inner().unwrap_or_else(PoisonError::into_inner);
    if let Some(error) = queue.error {
        return Err(error);
    }
    let mut found = queue.found;
    found.sort_by(|left, right| left.path.cmp(&right.path));
    found.dedup_by(|left, right| left.path == right.path);
    Ok(found)
}

fn crawl_worker(
    root: &Path,
    scope: &Scope,
    limits: CrawlLimits,
    queue: &Mutex<Queue>,
    ready: &Condvar,
) {
    while let Some(dir) = next_dir(queue, ready) {
        let lease = ActiveLease::new(queue, ready);
        let result = list_dir(root, &dir, scope);
        lease.release();
        let mut state = queue.lock().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok((dirs, files)) => {
                state.pending.extend(dirs);
                state.found.extend(files);
                if state.found.len() > limits.max_entries && state.error.is_none() {
                    state.error = Some(CoreError::new(
                        ErrorCode::ECapacity,
                        format!(
                            "worktree crawl exceeded {} entries",
                            limits.max_entries
                        ),
                    ));
                }
            }
            Err(error) => {
                state.error.get_or_insert(error);
            }
        }
        ready.notify_all();
    }
}

/// Claims the next pending directory, waiting while other workers may still
/// add some. `None` once the queue is drained with no active worker, or
/// after any worker failed.
fn next_dir(queue: &Mutex<Queue>, ready: &Condvar) -> Option<Vec<u8>> {
    let mut state = queue.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if state.error.is_some() {
            ready.notify_all();
            return None;
        }
        if let Some(dir) = state.pending.pop() {
            state.active += 1;
            return Some(dir);
        }
        if state.active == 0 {
            ready.notify_all();
            return None;
        }
        state = ready.wait(state).unwrap_or_else(PoisonError::into_inner);
    }
}

/// One worker's claimed directory. The claim is released (and waiters woken)
/// when the directory is done, including when listing it panics: without
/// this, a panic would leave `active` above zero and strand the pool in
/// `ready.wait` forever.
struct ActiveLease<'q> {
    queue: &'q Mutex<Queue>,
    ready: &'q Condvar,
    armed: bool,
}

impl<'q> ActiveLease<'q> {
    fn new(queue: &'q Mutex<Queue>, ready: &'q Condvar) -> Self {
        Self {
            queue,
            ready,
            armed: true,
        }
    }

    /// Releases the claim after the directory listed; the drop is then a
    /// no-op.
    fn release(mut self) {
        self.settle();
        self.armed = false;
    }

    fn settle(&self) {
        let mut state = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if state.active > 0 {
            state.active -= 1;
        }
        self.ready.notify_all();
    }
}

impl Drop for ActiveLease<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.settle();
        }
    }
}

/// Lists one directory: the visited subdirectories to crawl next and the
/// in-scope entries found directly inside it.
fn list_dir(
    root: &Path,
    dir: &[u8],
    scope: &Scope,
) -> Result<(Vec<Vec<u8>>, Vec<Observed>), CoreError> {
    let abs = fs_path(root, dir)?;
    let entries = match fs::read_dir(&abs) {
        Ok(entries) => entries,
        Err(err) if not_present(&err) => return Ok((Vec::new(), Vec::new())),
        Err(err) => return Err(io_error("listing a worktree directory", &err)),
    };
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| io_error("reading a directory entry", &err))?;
        let Some(name) = name_bytes(&entry.file_name()) else {
            continue;
        };
        if dir.is_empty() && name == INTERNAL_DIR {
            continue;
        }
        let Ok(path) = join(dir, &name) else {
            continue;
        };
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(err) if not_present(&err) => continue,
            Err(err) => return Err(io_error("reading worktree entry metadata", &err)),
        };
        if meta.file_type().is_dir() {
            if scope.includes_dir(&path) && !is_nested_repository(&entry.path()) {
                dirs.push(path.as_bytes().to_vec());
            }
            continue;
        }
        let Some(kind) = entry_kind(&meta) else {
            continue;
        };
        files.push(Observed {
            stat: FileStat::from_metadata(&meta)?,
            path,
            kind,
        });
    }
    Ok((dirs, files))
}

/// What one named path is on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    /// Nothing usable exists there: missing, a special file, or below an
    /// ancestor that is not a real directory.
    Absent,
    /// A real directory, to be crawled.
    Dir,
    /// A nested repository; left exactly as the tree records it.
    NestedRepository,
    Entry(Observed),
}

/// Probes named paths without following symlinks anywhere along them.
/// Ancestor checks are memoized across calls on one prober.
#[derive(Debug)]
pub(crate) struct Prober<'r> {
    root: &'r Path,
    real_dirs: HashMap<Vec<u8>, bool>,
}

impl<'r> Prober<'r> {
    #[must_use]
    pub(crate) fn new(root: &'r Path) -> Self {
        Self {
            root,
            real_dirs: HashMap::new(),
        }
    }

    /// # Errors
    /// `E_IO` for metadata failures other than absence.
    pub(crate) fn probe(&mut self, path: &RepoPath) -> Result<Probe, CoreError> {
        if let Some(parent) = path.parent()
            && !self.is_real_dir(parent)?
        {
            return Ok(Probe::Absent);
        }
        let abs = fs_path(self.root, path.as_bytes())?;
        let meta = match fs::symlink_metadata(&abs) {
            Ok(meta) => meta,
            Err(err) if not_present(&err) => return Ok(Probe::Absent),
            Err(err) => return Err(io_error("reading worktree entry metadata", &err)),
        };
        if meta.file_type().is_dir() {
            if is_nested_repository(&abs) {
                return Ok(Probe::NestedRepository);
            }
            return Ok(Probe::Dir);
        }
        let Some(kind) = entry_kind(&meta) else {
            return Ok(Probe::Absent);
        };
        Ok(Probe::Entry(Observed {
            path: path.clone(),
            stat: FileStat::from_metadata(&meta)?,
            kind,
        }))
    }

    /// Whether `dir` and each of its ancestors is a real directory and not a
    /// nested repository.
    fn is_real_dir(&mut self, dir: &[u8]) -> Result<bool, CoreError> {
        if let Some(known) = self.real_dirs.get(dir) {
            return Ok(*known);
        }
        let parent_ok = match dir.iter().rposition(|&byte| byte == b'/') {
            Some(cut) => self.is_real_dir(&dir[..cut])?,
            None => true,
        };
        let real = parent_ok && {
            let abs = fs_path(self.root, dir)?;
            match fs::symlink_metadata(&abs) {
                Ok(meta) => meta.file_type().is_dir() && !is_nested_repository(&abs),
                Err(err) if not_present(&err) => false,
                Err(err) => return Err(io_error("reading worktree directory metadata", &err)),
            }
        };
        self.real_dirs.insert(dir.to_vec(), real);
        Ok(real)
    }
}

/// Applies `f` to every item on at most `workers` scoped threads and
/// returns the results in input order. The first error stops the remaining
/// work and is returned.
///
/// # Errors
/// The first error `f` returns.
pub(crate) fn parallel_map<T, R, F>(
    items: &[T],
    workers: NonZeroUsize,
    f: F,
) -> Result<Vec<R>, CoreError>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> Result<R, CoreError> + Sync,
{
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let results: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));
    let first_error: Mutex<Option<CoreError>> = Mutex::new(None);
    let threads = workers.get().min(items.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while !failed.load(Ordering::Acquire) {
                    let index = next.fetch_add(1, Ordering::AcqRel);
                    let Some(item) = items.get(index) else {
                        return;
                    };
                    match f(item) {
                        Ok(value) => results
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((index, value)),
                        Err(error) => {
                            failed.store(true, Ordering::Release);
                            first_error
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .get_or_insert(error);
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(error) = first_error
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        return Err(error);
    }
    let mut results = results.into_inner().unwrap_or_else(PoisonError::into_inner);
    results.sort_by_key(|(index, _)| *index);
    Ok(results.into_iter().map(|(_, value)| value).collect())
}
