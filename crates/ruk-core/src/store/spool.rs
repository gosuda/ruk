//! Shared preparation budget and owned spools.
//!
//! Every live preparation buffer is charged to one [`PreparationBudget`]
//! shared by all stores of a process: prepared memory (global), scratch disk
//! (global) and scratch disk per store. A [`Spool`] holds decoded or encoded
//! bytes in memory up to a threshold and in one owned scratch file above it.
//!
//! Accounting rules:
//! - A reservation is taken before the bytes it covers exist; a refusal
//!   changes nothing (`E_LIMIT`).
//! - Every reservation is held by an RAII [`PreparationGuard`] that releases
//!   exactly what it acquired. A failed write keeps its charge until the
//!   spool is dropped, because the disk may already hold the bytes.
//! - A spool unlinks only the file it created. If that unlink fails the
//!   scratch bytes stay charged for the life of the budget: they still
//!   occupy disk.
//! - The per-store bucket is keyed by the canonical scratch directory, so a
//!   same-process reopen of the same store shares one bucket. The first
//!   registration of a bucket charges the bytes already present in that
//!   directory (crash leftovers) without deleting or rescanning them.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::store::error::StoreError;
use crate::store::pinned::PinnedRoot;

const SCRATCH_DIR: &str = "scratch";
/// The pin-relative scratch subdirectory: every spool file create goes
/// through the pinned store root, never by recorded path.
fn scratch_dir() -> &'static Path {
    Path::new(SCRATCH_DIR)
}
/// Smallest in-memory spool allocation step.
const MIN_MEMORY_CHUNK: usize = 4096;
/// Entries one occupancy scan may visit before it fails closed.
const MAX_SCAN_ENTRIES: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// A resource refusal that must stay typed while it crosses `std::io`
/// boundaries (zstd encoders and `io::copy` only carry `io::Error`).
#[derive(Debug)]
pub(crate) enum Refusal {
    Limit(String),
    Capacity(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(message) | Self::Capacity(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for StoreError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Limit(message) => Self::Limit(message),
            Refusal::Capacity(message) => Self::Capacity(message),
        }
    }
}

impl From<Refusal> for io::Error {
    fn from(refusal: Refusal) -> Self {
        Self::other(refusal)
    }
}

/// Recovers a typed refusal embedded by [`store_to_io`]; any other error is
/// a real I/O failure.
pub(crate) fn io_to_store(err: io::Error) -> StoreError {
    if let Some(refusal) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refusal>())
    {
        return match refusal {
            Refusal::Limit(message) => StoreError::Limit(message.clone()),
            Refusal::Capacity(message) => StoreError::Capacity(message.clone()),
        };
    }
    StoreError::Io(err)
}

/// Carries a store failure through a `std::io::Write` boundary.
pub(crate) fn store_to_io(err: StoreError) -> io::Error {
    match err {
        StoreError::Io(inner) => inner,
        StoreError::Limit(message) => Refusal::Limit(message).into(),
        StoreError::Capacity(message) => Refusal::Capacity(message).into(),
        other => io::Error::other(other.to_string()),
    }
}

/// `usize` to `u64` without a bare cast; every supported target has
/// `usize` no wider than 64 bits.
pub(crate) fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Resource limits of one [`PreparationBudget`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetLimits {
    /// Admission policy: largest decoded object accepted. `None` admits any
    /// size the other limits and the record format can carry.
    pub max_object_bytes: Option<u64>,
    /// Global bytes of live preparation memory, codec allowances included.
    pub max_prepared_memory: u64,
    /// Global bytes of scratch disk.
    pub max_scratch_total: u64,
    /// Scratch disk bytes per store (canonical scratch directory).
    pub max_scratch_per_store: u64,
    /// Largest spool kept in memory; bigger ones move to a scratch file.
    pub memory_spool_threshold: usize,
}

impl Default for BudgetLimits {
    /// The reference production profile: 2 GiB prepared memory, 512 GiB
    /// scratch, 128 GiB per store, 256 KiB memory/spool threshold.
    fn default() -> Self {
        Self {
            max_object_bytes: None,
            max_prepared_memory: 2 * GIB,
            max_scratch_total: 512 * GIB,
            max_scratch_per_store: 128 * GIB,
            memory_spool_threshold: 256 * 1024,
        }
    }
}

#[derive(Debug, Default)]
struct Usage {
    memory: u64,
    scratch: u64,
    /// Scratch bytes charged per canonical scratch directory, baseline of
    /// pre-existing files included.
    roots: HashMap<PathBuf, u64>,
}

/// Shared preparation reservations. One instance serves every store of a
/// process; it is cheap to clone behind an `Arc`.
#[derive(Debug)]
pub struct PreparationBudget {
    limits: BudgetLimits,
    usage: Mutex<Usage>,
}

impl Default for PreparationBudget {
    fn default() -> Self {
        Self::reference_defaults()
    }
}

impl PreparationBudget {
    #[must_use]
    pub fn new(limits: BudgetLimits) -> Self {
        Self {
            limits,
            usage: Mutex::new(Usage::default()),
        }
    }

    /// The reference production profile limits.
    #[must_use]
    pub fn reference_defaults() -> Self {
        Self::new(BudgetLimits::default())
    }

    #[must_use]
    pub fn limits(&self) -> &BudgetLimits {
        &self.limits
    }

    /// Charges the scratch bytes already present under `store_root/scratch`
    /// to that store's bucket. Idempotent; the scan runs once per canonical
    /// directory and never deletes anything.
    ///
    /// # Errors
    /// I/O failures and a directory too large to scan fail closed.
    pub(crate) fn register_scratch(
        &self,
        pin: &PinnedRoot,
        store_root: &Path,
    ) -> Result<(), StoreError> {
        self.open_scratch(pin, store_root).map(drop)
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> (u64, u64) {
        let usage = self.usage();
        (usage.memory, usage.scratch)
    }

    #[cfg(test)]
    pub(crate) fn scratch_in_use(&self, store_root: &Path) -> Option<u64> {
        let key = fs::canonicalize(store_root.join(SCRATCH_DIR)).ok()?;
        self.usage().roots.get(&key).copied()
    }

    /// Reserves `bytes` of prepared memory until the guard drops.
    pub(crate) fn reserve_memory(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<PreparationGuard, StoreError> {
        let mut guard = PreparationGuard::new(self);
        guard.grow(bytes, 0)?;
        Ok(guard)
    }

    fn usage(&self) -> MutexGuard<'_, Usage> {
        // The counters stay consistent under every single-step mutation, so
        // a poisoned lock is still safe to use.
        self.usage.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn acquire(&self, memory: u64, scratch: u64, root: Option<&Path>) -> Result<(), Refusal> {
        let mut usage = self.usage();
        let memory_after = usage
            .memory
            .checked_add(memory)
            .filter(|total| *total <= self.limits.max_prepared_memory)
            .ok_or_else(|| {
                Refusal::Limit(format!(
                    "prepared memory limit of {} bytes exceeded ({} in use, {memory} requested)",
                    self.limits.max_prepared_memory, usage.memory
                ))
            })?;
        if scratch == 0 {
            usage.memory = memory_after;
            return Ok(());
        }
        let global_after = usage
            .scratch
            .checked_add(scratch)
            .filter(|total| *total <= self.limits.max_scratch_total)
            .ok_or_else(|| {
                Refusal::Limit(format!(
                    "scratch disk limit of {} bytes exceeded ({} in use, {scratch} requested)",
                    self.limits.max_scratch_total, usage.scratch
                ))
            })?;
        let root = root.ok_or_else(|| {
            Refusal::Limit(
                "scratch reservation without a registered store scratch directory".into(),
            )
        })?;
        let root_used = usage.roots.get(root).copied().ok_or_else(|| {
            Refusal::Limit("scratch reservation for an unregistered store scratch directory".into())
        })?;
        let root_after = root_used
            .checked_add(scratch)
            .filter(|total| *total <= self.limits.max_scratch_per_store)
            .ok_or_else(|| {
                Refusal::Limit(format!(
                    "per-store scratch limit of {} bytes exceeded ({root_used} in use, {scratch} requested)",
                    self.limits.max_scratch_per_store
                ))
            })?;
        usage.memory = memory_after;
        usage.scratch = global_after;
        if let Some(slot) = usage.roots.get_mut(root) {
            *slot = root_after;
        }
        Ok(())
    }

    fn release(&self, memory: u64, scratch: u64, root: Option<&Path>) {
        let mut usage = self.usage();
        usage.memory = usage.memory.saturating_sub(memory);
        usage.scratch = usage.scratch.saturating_sub(scratch);
        if scratch > 0
            && let Some(root) = root
            && let Some(slot) = usage.roots.get_mut(root)
        {
            *slot = slot.saturating_sub(scratch);
        }
    }

    /// Creates the scratch directory if needed and returns its canonical
    /// path after registering its bucket (baseline scan on first use).
    /// The directory create and the key probe both travel the pin, so
    /// a symlink swapped in after open can neither divert the spill
    /// nor split the bucket; the recorded path serves only the
    /// no-descriptor fallback.
    fn open_scratch(&self, pin: &PinnedRoot, store_root: &Path) -> Result<PathBuf, StoreError> {
        pin.create_dir_all(scratch_dir()).map_err(StoreError::Io)?;
        let probe = pin
            .proc_subpath(SCRATCH_DIR)
            .unwrap_or_else(|| store_root.join(SCRATCH_DIR));
        let key = fs::canonicalize(&probe)?;
        if self.usage().roots.contains_key(&key) {
            return Ok(key);
        }
        // Scan outside the lock. No spool of this budget exists in an
        // unregistered bucket, so the sum counts only foreign leftovers; a
        // racing registration wins and this result is discarded.
        let baseline = scan_occupancy(&key)?;
        let mut usage = self.usage();
        if !usage.roots.contains_key(&key) {
            usage.scratch = usage.scratch.saturating_add(baseline);
            usage.roots.insert(key.clone(), baseline);
        }
        Ok(key)
    }
}

enum Found {
    Directory(PathBuf),
    Bytes(u64),
    Gone,
}

/// Classifies one directory entry without following symlinks. An entry
/// removed during the scan counts as nothing.
fn classify_entry(entry: &fs::DirEntry) -> Result<Found, StoreError> {
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Found::Gone),
        Err(err) => return Err(err.into()),
    };
    if file_type.is_dir() {
        return Ok(Found::Directory(entry.path()));
    }
    match entry.metadata() {
        Ok(metadata) => Ok(Found::Bytes(metadata.len())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Found::Gone),
        Err(err) => Err(err.into()),
    }
}

/// Sums the lengths of every non-directory entry below `dir` without
/// following symlinks and without a recursion stack.
fn scan_occupancy(dir: &Path) -> Result<u64, StoreError> {
    let mut total = 0_u64;
    let mut visited = 0_u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            visited += 1;
            if visited > MAX_SCAN_ENTRIES {
                return Err(StoreError::Limit(format!(
                    "scratch directory {} holds more than {MAX_SCAN_ENTRIES} entries; \
                     operator cleanup is required before new spools are admitted",
                    dir.display()
                )));
            }
            match classify_entry(&entry?)? {
                Found::Directory(path) => pending.push(path),
                Found::Bytes(len) => total = total.saturating_add(len),
                Found::Gone => {}
            }
        }
    }
    Ok(total)
}

/// RAII reservation. Dropping it releases exactly what it acquired.
#[derive(Debug)]
pub(crate) struct PreparationGuard {
    budget: Arc<PreparationBudget>,
    memory: u64,
    scratch: u64,
    root: Option<PathBuf>,
}

impl PreparationGuard {
    fn new(budget: &Arc<PreparationBudget>) -> Self {
        Self {
            budget: Arc::clone(budget),
            memory: 0,
            scratch: 0,
            root: None,
        }
    }

    /// Acquires more memory and/or scratch bytes; a refusal changes nothing.
    fn grow(&mut self, memory: u64, scratch: u64) -> Result<(), Refusal> {
        self.budget.acquire(memory, scratch, self.root.as_deref())?;
        self.memory = self.memory.saturating_add(memory);
        self.scratch = self.scratch.saturating_add(scratch);
        Ok(())
    }

    fn release_memory(&mut self) {
        let memory = std::mem::take(&mut self.memory);
        self.budget.release(memory, 0, None);
    }

    /// Leaves the scratch charge in the budget forever: the file it covers
    /// could not be removed and still occupies disk.
    fn keep_scratch(&mut self) {
        self.scratch = 0;
    }
}

impl Drop for PreparationGuard {
    fn drop(&mut self) {
        self.budget
            .release(self.memory, self.scratch, self.root.as_deref());
    }
}

enum Storage {
    Memory(Vec<u8>),
    File { file: File, path: PathBuf },
}

/// Owned bytes in memory or in one scratch file. Reading uses the spool's
/// own cursor (`Read + Seek`); [`Spool::view`] gives independent cursors
/// over a shared reference.
pub struct Spool {
    storage: Storage,
    len: u64,
    pos: u64,
    charge: PreparationGuard,
}

impl Spool {
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// An independent read cursor at offset 0. Never fails: a file-backed
    /// spool is reopened on the first read.
    pub(crate) fn view(&self) -> SpoolView<'_> {
        SpoolView {
            spool: self,
            pos: 0,
            file: None,
        }
    }

    /// The resident bytes when this spool never spilled to scratch disk:
    /// exactly `len` bytes grown in lockstep with the length. `None` for
    /// file-backed spools, whose bytes need a read cursor.
    pub(crate) fn memory_bytes(&self) -> Option<&[u8]> {
        match &self.storage {
            Storage::Memory(bytes) => Some(bytes),
            Storage::File { .. } => None,
        }
    }
}

impl fmt::Debug for Spool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spool")
            .field("len", &self.len)
            .field("on_disk", &matches!(self.storage, Storage::File { .. }))
            .finish_non_exhaustive()
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if let Storage::File { file, path } =
            std::mem::replace(&mut self.storage, Storage::Memory(Vec::new()))
        {
            drop(file);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(_) => self.charge.keep_scratch(),
            }
        }
    }
}

fn resolve_seek(len: u64, pos: u64, from: SeekFrom) -> io::Result<u64> {
    let target = match from {
        SeekFrom::Start(offset) => Some(offset),
        SeekFrom::End(delta) => len.checked_add_signed(delta),
        SeekFrom::Current(delta) => pos.checked_add_signed(delta),
    };
    target.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek before the start or past the largest offset",
        )
    })
}

fn memory_slice(bytes: &[u8], pos: u64, want: usize) -> io::Result<&[u8]> {
    let short = || {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "memory spool is shorter than its recorded length",
        )
    };
    let start = usize::try_from(pos).map_err(|_| short())?;
    let end = start.checked_add(want).ok_or_else(short)?;
    bytes.get(start..end).ok_or_else(short)
}

impl Read for Spool {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if want == 0 {
            return Ok(0);
        }
        let read = match &mut self.storage {
            Storage::Memory(bytes) => {
                buf[..want].copy_from_slice(memory_slice(bytes, self.pos, want)?);
                want
            }
            Storage::File { file, .. } => file.read(&mut buf[..want])?,
        };
        self.pos += to_u64(read);
        Ok(read)
    }
}

impl Seek for Spool {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = resolve_seek(self.len, self.pos, from)?;
        if let Storage::File { file, .. } = &mut self.storage {
            file.seek(SeekFrom::Start(target))?;
        }
        self.pos = target;
        Ok(target)
    }
}

/// An independent cursor over a shared [`Spool`].
pub(crate) struct SpoolView<'a> {
    spool: &'a Spool,
    pos: u64,
    file: Option<File>,
}

impl SpoolView<'_> {
    pub(crate) fn len(&self) -> u64 {
        self.spool.len
    }
}

impl fmt::Debug for SpoolView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpoolView")
            .field("len", &self.spool.len)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl Read for SpoolView<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let spool = self.spool;
        let remaining = spool.len.saturating_sub(self.pos);
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if want == 0 {
            return Ok(0);
        }
        let read = match &spool.storage {
            Storage::Memory(bytes) => {
                buf[..want].copy_from_slice(memory_slice(bytes, self.pos, want)?);
                want
            }
            // Clone the open description: the view reads its own
            // positions without ever resolving the spool path by
            // name, so a swapped parent cannot redirect the read.
            // `read_at` leaves the shared offset alone, so sibling
            // views never race.
            #[cfg(unix)]
            Storage::File { file, .. } => {
                use std::os::unix::fs::FileExt as _;
                if self.file.is_none() {
                    let cloned = file
                        .try_clone()
                        .map_err(|_| io::Error::other("spool view lost its file"))?;
                    self.file = Some(cloned);
                }
                let Some(opened) = self.file.as_ref() else {
                    return Err(io::Error::other("spool view lost its file"));
                };
                opened.read_at(&mut buf[..want], self.pos)?
            }
            #[cfg(not(unix))]
            Storage::File { path, .. } => {
                if self.file.is_none() {
                    let mut opened = File::open(path)?;
                    opened.seek(SeekFrom::Start(self.pos))?;
                    self.file = Some(opened);
                }
                match self.file.as_mut() {
                    Some(opened) => opened.read(&mut buf[..want])?,
                    None => return Err(io::Error::other("spool view lost its file")),
                }
            }
        };
        self.pos += to_u64(read);
        Ok(read)
    }
}

impl Seek for SpoolView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = resolve_seek(self.spool.len, self.pos, from)?;
        #[cfg(not(unix))]
        if let Some(file) = self.file.as_mut() {
            file.seek(SeekFrom::Start(target))?;
        }
        self.pos = target;
        Ok(target)
    }
}

/// Append-only builder of a [`Spool`]. Memory is charged as it grows;
/// crossing the threshold moves the bytes to one scratch file, charging the
/// disk before each write.
pub(crate) struct SpoolWriter {
    spool: Spool,
    store_root: PathBuf,
    pin: PinnedRoot,
    threshold: usize,
    failed: bool,
}

impl fmt::Debug for SpoolWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpoolWriter")
            .field("len", &self.spool.len)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl SpoolWriter {
    /// Starts an empty spool charged to `budget` with scratch files under
    /// `store_root/scratch`. Every scratch create travels `pin`, never
    /// the recorded path; only the accounting key still uses
    /// `store_root`. Performs no I/O.
    pub(crate) fn new(
        budget: &Arc<PreparationBudget>,
        store_root: &Path,
        pin: &PinnedRoot,
    ) -> Self {
        Self {
            spool: Spool {
                storage: Storage::Memory(Vec::new()),
                len: 0,
                pos: 0,
                charge: PreparationGuard::new(budget),
            },
            store_root: store_root.to_path_buf(),
            pin: pin.fork(),
            threshold: budget.limits.memory_spool_threshold,
            failed: false,
        }
    }

    /// Appends `data`. Resource refusals are typed; after any error the
    /// writer refuses further input.
    pub(crate) fn append(&mut self, data: &[u8]) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Invalid(
                "spool writer already failed".to_owned(),
            ));
        }
        let outcome = self.append_inner(data);
        if outcome.is_err() {
            self.failed = true;
        }
        outcome
    }

    fn append_inner(&mut self, data: &[u8]) -> Result<(), StoreError> {
        if data.is_empty() {
            return Ok(());
        }
        let new_len = self
            .spool
            .len
            .checked_add(to_u64(data.len()))
            .ok_or_else(|| StoreError::Capacity("spool length overflows u64".to_owned()))?;
        if matches!(self.spool.storage, Storage::Memory(_)) {
            if new_len <= to_u64(self.threshold) {
                return self.append_memory(data, new_len);
            }
            self.spill()?;
        }
        self.append_file(data, new_len)
    }

    fn append_memory(&mut self, data: &[u8], new_len: u64) -> Result<(), StoreError> {
        let need = usize::try_from(new_len)
            .map_err(|_| StoreError::Capacity("memory spool length overflows usize".to_owned()))?;
        let charged = usize::try_from(self.spool.charge.memory).unwrap_or(usize::MAX);
        if need > charged {
            let doubled = charged.saturating_mul(2).min(self.threshold);
            let target = need.max(doubled).max(MIN_MEMORY_CHUNK.min(self.threshold));
            self.spool.charge.grow(to_u64(target - charged), 0)?;
            if let Storage::Memory(bytes) = &mut self.spool.storage {
                bytes
                    .try_reserve_exact(target - bytes.len())
                    .map_err(|_| StoreError::Limit("memory spool allocation failed".to_owned()))?;
            }
        }
        if let Storage::Memory(bytes) = &mut self.spool.storage {
            bytes.extend_from_slice(data);
        }
        self.spool.len = new_len;
        Ok(())
    }

    /// Moves buffered bytes to a fresh scratch file. Scratch is charged for
    /// the buffered bytes before the file exists; the memory charge is
    /// released only after the copy.
    fn spill(&mut self) -> Result<(), StoreError> {
        let dir = self
            .spool
            .charge
            .budget
            .open_scratch(&self.pin, &self.store_root)?;
        self.spool.charge.root = Some(dir.clone());
        self.spool.charge.grow(0, self.spool.len)?;
        let (file, path) = create_spool_file(&self.pin, &dir)?;
        let previous = std::mem::replace(&mut self.spool.storage, Storage::File { file, path });
        let Storage::Memory(buffered) = previous else {
            return Err(StoreError::Invalid("spool already on disk".to_owned()));
        };
        if let Storage::File { file, .. } = &mut self.spool.storage {
            file.write_all(&buffered)?;
        }
        drop(buffered);
        self.spool.charge.release_memory();
        Ok(())
    }

    fn append_file(&mut self, data: &[u8], new_len: u64) -> Result<(), StoreError> {
        self.spool.charge.grow(0, to_u64(data.len()))?;
        if let Storage::File { file, .. } = &mut self.spool.storage {
            file.write_all(data)?;
        }
        self.spool.len = new_len;
        Ok(())
    }

    /// Ends the build and returns the spool with its cursor at offset 0.
    pub(crate) fn finish(mut self) -> Result<Spool, StoreError> {
        if self.failed {
            return Err(StoreError::Invalid(
                "spool writer failed before finish".to_owned(),
            ));
        }
        if let Storage::File { file, .. } = &mut self.spool.storage {
            file.seek(SeekFrom::Start(0))?;
        }
        self.spool.pos = 0;
        Ok(self.spool)
    }
}

impl Write for SpoolWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.append(buf).map_err(store_to_io)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Creates a new uniquely named scratch file through the pin. Never
/// opens or truncates an existing path. Returns the file and its
/// recorded absolute path: the recorded path serves cleanup and
/// non-Unix reads only — live Unix I/O travels the open file and its
/// clones, never the path, so a swapped parent cannot redirect it.
fn create_spool_file(pin: &PinnedRoot, record_dir: &Path) -> Result<(File, PathBuf), StoreError> {
    for _ in 0..8 {
        let name = format!("spool-{}.tmp", uuid::Uuid::new_v4().simple());
        match pin.create_new(&scratch_dir().join(&name)) {
            Ok(file) => return Ok((file, record_dir.join(&name))),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
    }
    Err(StoreError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique scratch file name",
    )))
}
