//! Journaled, stepwise materialization.
//!
//! Order of effects, each a separate durable or physical step:
//!
//! 1. [`begin_apply`]: capture preimages, then publish preimage blobs,
//!    caller target blobs, the `ws_apply` row (state Applying, expectation
//!    Absent) and a compare-and-swap guard on the workspace row, in one
//!    store transaction. No worktree byte changes before it commits.
//! 2. [`ApplySession::execute`]: a removal pass in reverse path order
//!    (children before parents) removes what the target does not want or
//!    what has the wrong kind (directory versus non-directory); a write
//!    pass in path order creates missing parent directories and writes
//!    each changed path through a same-directory temporary file (or
//!    temporary symlink) that is flushed and then renamed over the final
//!    name. Before every physical step the workspace row is re-read: a
//!    moved lease epoch stops the executor with `E_LEASE_LOST`.
//! 3. [`ApplySession::finish`]: flush every touched directory, re-observe
//!    every journaled path against the target manifest, then publish the
//!    completing batch: remove the exact `ws_apply` row and compare-and-swap
//!    the workspace row (optionally to the caller's successor row).
//!
//! Any failure after step 1 leaves the row Applying; [`super::recover`]
//! owns what happens next. No step promises a multi-file atomic rename.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::change::WorkspaceId;
use crate::error::{CoreError, ErrorCode};
use crate::index::{FileMode, RepoPath};
use crate::store::{
    FactExpectation, FactMutation, FactTable, ObjectKind, PreparedObject, Store, StoreError,
};
use crate::workcopy::lfs::{self, LfsMode, MAX_POINTER_BYTES};
use crate::workspace::{Scope, WorkspaceStamp};

use super::capture::{self, PlanEntry, lossy};
use super::journal::{
    self, ApplyJournal, ApplyState, ApplyStep, JOURNAL_VERSION, Shape, StepCursor, ancestors,
};
use super::safety::{self, Ancestry, Observed, WorkRoot};

/// Persist the advisory cursor after this many physical steps.
const CURSOR_INTERVAL: u64 = 4096;

/// Largest number of paths named in one `E_WORKSPACE_RECOVERY` message.
const RECOVERY_REPORT_LIMIT: usize = 32;

/// The caller's observation of the workspace row: its exact bytes and the
/// lease epoch they encode. The coordinator builds it from the row it
/// already decoded; this module never interprets the row, it only
/// compare-and-swaps those exact bytes, so a takeover (`ws.take`) between
/// any two steps is detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkspaceFence {
    workspace: WorkspaceId,
    row: Vec<u8>,
    lease_epoch: u64,
}

impl WorkspaceFence {
    #[must_use]
    pub(crate) fn new(workspace: WorkspaceId, row: Vec<u8>, stamp: WorkspaceStamp) -> Self {
        Self {
            workspace,
            row,
            lease_epoch: stamp.lease_epoch,
        }
    }

    #[must_use]
    pub(crate) const fn workspace(&self) -> WorkspaceId {
        self.workspace
    }

    #[must_use]
    pub(crate) const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    fn key(&self) -> Vec<u8> {
        self.workspace.as_bytes().to_vec()
    }

    /// Republishes the observed row unchanged: commits only if it is still
    /// exactly what the caller observed.
    fn guard(&self) -> FactMutation {
        self.replace(self.row.clone())
    }

    fn replace(&self, next: Vec<u8>) -> FactMutation {
        FactMutation {
            table: FactTable::Workspaces,
            key: self.key(),
            expected: FactExpectation::Value(self.row.clone()),
            value: Some(next),
        }
    }

    /// Fails with `code` unless the stored row is still the observed one.
    pub(crate) fn check(&self, store: &Store, code: ErrorCode) -> Result<(), CoreError> {
        match store.fact(FactTable::Workspaces, &self.key())? {
            Some(row) if row == self.row => Ok(()),
            Some(_) => Err(CoreError::new(
                code,
                "workspace row changed since it was observed; ownership or state moved",
            )),
            None => Err(CoreError::new(ErrorCode::ENotFound, "workspace is not registered")),
        }
    }
}

/// Mutations published with the completing batch.
#[derive(Debug, Default)]
pub(crate) struct FinishBatch {
    /// Successor workspace row (for example the moved head). `None` keeps
    /// the row as observed.
    pub(crate) next_row: Option<Vec<u8>>,
    /// Further facts (operation log, status cache refresh). They may not
    /// touch `ws_apply` or this workspace's row.
    pub(crate) extra: Vec<FactMutation>,
}

/// One materialization request.
#[derive(Debug)]
pub(crate) struct MaterializePlan {
    pub(crate) workspace: WorkspaceId,
    /// The workspace root directory (the directory containing `.ruk`).
    pub(crate) root: PathBuf,
    pub(crate) scope: Scope,
    pub(crate) entries: Vec<PlanEntry>,
    /// Paths whose unsafe overwrite the caller explicitly authorized.
    pub(crate) discard: BTreeSet<RepoPath>,
    /// Target blobs not yet committed (rendered conflict markers, new
    /// content); published atomically with the journal row.
    pub(crate) target_objects: Vec<PreparedObject>,
    /// How this store treats Git LFS pointer blobs. [`LfsMode::Deny`]
    /// rejects a pointer target before the journal is published.
    pub(crate) lfs: LfsMode,
}

/// What a completed materialization changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplyOutcome {
    /// Every journaled path; their stat-cache rows are stale.
    pub(crate) changed: Vec<RepoPath>,
    /// Paths left as external edits (abort only).
    pub(crate) unresolved: Vec<RepoPath>,
}

/// An open, committed journal and its executor.
#[derive(Debug)]
#[must_use = "a dropped session leaves the journal Applying until recovery"]
pub(crate) struct ApplySession<'a> {
    exec: Executor<'a>,
}

/// Captures preimages and commits the Applying journal row. Nothing in the
/// worktree changes before this returns `Ok`.
///
/// # Errors
/// `E_WORKSPACE_APPLYING` when a journal is already open; `E_STALE` when the
/// workspace row moved since `fence` was observed; `E_DIRTY` for unsafe
/// overwrites; `E_INVALID`, `E_CAPACITY`, `E_IO` and store errors.
pub(crate) fn begin_apply(
    store: &Store,
    plan: MaterializePlan,
    fence: WorkspaceFence,
    extra: Vec<FactMutation>,
) -> Result<ApplySession<'_>, CoreError> {
    let workspace = fence.workspace;
    if plan.workspace != workspace {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "plan and fence name different workspaces",
        ));
    }
    check_extra(workspace, &extra)?;
    if journal::load(store, workspace)?.is_some() {
        return Err(applying_error());
    }
    fence.check(store, ErrorCode::EStale)?;
    if plan.lfs == LfsMode::Deny {
        check_lfs_targets(store, &plan.entries, &plan.target_objects)?;
    }
    let root = WorkRoot::open(&plan.root)?;
    let captured = capture::capture(store, &root, plan.entries, &plan.discard, &plan.scope)?;
    let journal = ApplyJournal {
        version: JOURNAL_VERSION,
        workspace,
        nonce: uuid::Uuid::new_v4().into_bytes(),
        lease_epoch: fence.lease_epoch,
        state: ApplyState::Applying,
        cursor: StepCursor::START,
        entries: captured.entries,
    };
    journal
        .validate(store.hash_kind(), workspace)
        .map_err(|detail| CoreError::new(ErrorCode::EInvalid, detail))?;
    let row = journal::encode(&journal)?;
    let mut objects = plan.target_objects;
    objects.extend(captured.objects);
    let mut facts = vec![
        journal::insert_mutation(workspace, row.clone()),
        fence.guard(),
    ];
    facts.extend(extra);
    if let Err(err) = store.publish(objects, &facts) {
        return Err(begin_conflict(store, workspace, err));
    }
    Ok(ApplySession {
        exec: Executor::new(store, root, fence, journal, row),
    })
}

/// Begin, execute and finish in one call.
///
/// # Errors
/// See [`begin_apply`], [`ApplySession::execute`], [`ApplySession::finish`].
pub(crate) fn materialize(
    store: &Store,
    plan: MaterializePlan,
    fence: WorkspaceFence,
    begin_extra: Vec<FactMutation>,
    finish: FinishBatch,
) -> Result<ApplyOutcome, CoreError> {
    let mut session = begin_apply(store, plan, fence, begin_extra)?;
    session.execute()?;
    session.finish(finish)
}

impl ApplySession<'_> {
    #[must_use]
    pub(crate) fn journal(&self) -> &ApplyJournal {
        &self.exec.journal
    }

    /// Converges every journaled path to its target.
    ///
    /// # Errors
    /// `E_LEASE_LOST` when ownership moved; `E_WORKSPACE_RECOVERY` naming
    /// paths changed externally mid-apply; `E_IO`. The journal stays
    /// Applying.
    pub(crate) fn execute(&mut self) -> Result<(), CoreError> {
        self.exec.tick()?;
        self.exec
            .converge(Toward::Target, &BTreeSet::new(), Foreign::Fail)
            .map(drop)
    }

    /// Verifies the complete target manifest, then clears the journal.
    ///
    /// # Errors
    /// `E_WORKSPACE_RECOVERY` when a path does not match its target;
    /// `E_LEASE_LOST` when the workspace row moved; `E_INVALID` for extra
    /// mutations on reserved rows.
    pub(crate) fn finish(mut self, batch: FinishBatch) -> Result<ApplyOutcome, CoreError> {
        self.exec.verify(Toward::Target, &BTreeSet::new())?;
        self.exec.complete(batch, Vec::new())
    }
}

/// Which side of the journal the executor converges to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Toward {
    Target,
    Preimage,
}

/// What to do with a path that matches neither side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Foreign {
    /// Stop with `E_WORKSPACE_RECOVERY`.
    Fail,
    /// Leave it untouched and report it unresolved.
    Skip,
}

/// How a journaled path relates to the journal right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PathState {
    AtTarget,
    AtPreimage,
    /// Removed between a directory/non-directory swap's two halves.
    Between,
    Foreign,
}

#[derive(Debug)]
pub(super) struct Executor<'a> {
    pub(super) store: &'a Store,
    pub(super) root: WorkRoot,
    pub(super) fence: WorkspaceFence,
    pub(super) journal: ApplyJournal,
    pub(super) row: Vec<u8>,
    target_dirs: BTreeSet<Vec<u8>>,
    preimage_dirs: BTreeSet<Vec<u8>>,
    dirty_dirs: BTreeSet<PathBuf>,
    steps: u64,
}

impl<'a> Executor<'a> {
    pub(super) fn new(
        store: &'a Store,
        root: WorkRoot,
        fence: WorkspaceFence,
        journal: ApplyJournal,
        row: Vec<u8>,
    ) -> Self {
        Self {
            target_dirs: journal.target_dirs(),
            preimage_dirs: journal.preimage_dirs(),
            store,
            root,
            fence,
            journal,
            row,
            dirty_dirs: BTreeSet::new(),
            steps: 0,
        }
    }

    fn path(&self, index: usize) -> &RepoPath {
        &self.journal.entries[index].path
    }

    fn desired(&self, index: usize, toward: Toward) -> Shape {
        match toward {
            Toward::Target => self.journal.target_shape(index, &self.target_dirs),
            Toward::Preimage => self.journal.preimage_shape(index),
        }
    }

    fn observe(&self, index: usize) -> Result<Observed, CoreError> {
        self.root.observe(self.store.hash_kind(), self.path(index))
    }

    /// Classifies one path against both sides of the journal.
    pub(super) fn classify(&self, index: usize) -> Result<PathState, CoreError> {
        let seen = self.observe(index)?;
        let target = self.desired(index, Toward::Target);
        let preimage = self.desired(index, Toward::Preimage);
        Ok(if target.matches(&seen) {
            PathState::AtTarget
        } else if preimage.matches(&seen) {
            PathState::AtPreimage
        } else if seen == Observed::Absent && target.is_dir() != preimage.is_dir() {
            PathState::Between
        } else {
            PathState::Foreign
        })
    }

    /// Fault-injection point between physical steps (test builds).
    pub(super) fn tick(&mut self) -> Result<(), CoreError> {
        self.steps = self.steps.saturating_add(1);
        #[cfg(test)]
        fault::tick()?;
        Ok(())
    }

    /// Runs one physical step under the ownership fence.
    fn fenced(&self) -> Result<(), CoreError> {
        self.fence.check(self.store, ErrorCode::ELeaseLost)
    }

    /// Converges every journaled path toward one side. Returns the indices
    /// left unresolved under [`Foreign::Skip`].
    pub(super) fn converge(
        &mut self,
        toward: Toward,
        discard: &BTreeSet<RepoPath>,
        foreign: Foreign,
    ) -> Result<BTreeSet<usize>, CoreError> {
        let count = self.journal.entries.len();
        let mut unresolved = BTreeSet::new();
        self.persist_cursor(ApplyStep::Removing)?;
        for index in (0..count).rev() {
            self.clean_temp(index)?;
            let want = self.desired(index, toward);
            let seen = self.observe(index)?;
            if want.matches(&seen) {
                // An absent target can still leave parent directories the
                // crashed apply created: a crash between a parent's mkdir and
                // the file write yields an absent path inside orphan dirs.
                if want == Shape::Absent {
                    let p = self.path(index).clone();
                    self.prune(&p, toward)?;
                }
                continue;
            }
            if !self.acceptable(index, discard)? {
                self.foreign(index, foreign, &mut unresolved)?;
                continue;
            }
            let wrong_kind = want == Shape::Absent || want.is_dir() != (seen == Observed::Dir);
            if seen == Observed::Absent || !wrong_kind {
                continue;
            }
            if !self.remove(index, &seen, toward)? {
                self.foreign(index, foreign, &mut unresolved)?;
            }
        }
        self.persist_cursor(ApplyStep::Writing)?;
        for index in 0..count {
            if unresolved.contains(&index) {
                continue;
            }
            let want = self.desired(index, toward);
            if want.matches(&self.observe(index)?) {
                continue;
            }
            if !self.acceptable(index, discard)? || !self.ensure_parents(index)? {
                self.foreign(index, foreign, &mut unresolved)?;
                continue;
            }
            self.write(index, &want)?;
        }
        self.persist_cursor(ApplyStep::Verifying)?;
        Ok(unresolved)
    }

    fn acceptable(&self, index: usize, discard: &BTreeSet<RepoPath>) -> Result<bool, CoreError> {
        Ok(discard.contains(self.path(index)) || self.classify(index)? != PathState::Foreign)
    }

    fn foreign(
        &self,
        index: usize,
        foreign: Foreign,
        unresolved: &mut BTreeSet<usize>,
    ) -> Result<(), CoreError> {
        match foreign {
            Foreign::Fail => Err(recovery_error(&[self.path(index).clone()])),
            Foreign::Skip => {
                unresolved.insert(index);
                Ok(())
            }
        }
    }

    /// Removes the path's current object. `false` when a directory still
    /// holds content that is not ours.
    fn remove(&mut self, index: usize, seen: &Observed, toward: Toward) -> Result<bool, CoreError> {
        self.fenced()?;
        let path = self.path(index).clone();
        let Some(full) = self.root.resolve_clear(&path)? else {
            return Ok(true);
        };
        let result = if *seen == Observed::Dir {
            fs::remove_dir(&full)
        } else {
            fs::remove_file(&full)
        };
        match result {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => return Ok(false),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(err) => return Err(safety::io_error("remove", &full, &err)),
        }
        self.mark_parent(&full);
        self.tick()?;
        self.prune(&path, toward)?;
        Ok(true)
    }

    /// Removes parents emptied by a removal unless the converged side needs
    /// them. Never reaches the workspace root.
    fn prune(&mut self, path: &RepoPath, toward: Toward) -> Result<(), CoreError> {
        let keep = match toward {
            Toward::Target => &self.target_dirs,
            Toward::Preimage => &self.preimage_dirs,
        };
        let parents: Vec<Vec<u8>> = ancestors(path)
            .filter(|dir| !keep.contains(*dir))
            .map(<[u8]>::to_vec)
            .collect();
        for dir in parents.iter().rev() {
            let full = self.root.join(dir)?;
            match safety::lstat(&full)? {
                Some(meta) if safety::is_real_dir(&meta) => {}
                // A missing or non-directory ancestor cannot be pruned, but
                // ancestors above it may still be empty orphans the crashed
                // apply left behind, so keep walking upward.
                _ => continue,
            }
            match fs::remove_dir(&full) {
                Ok(()) => self.mark_parent(&full),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
                    ) =>
                {
                    return Ok(());
                }
                Err(err) => return Err(safety::io_error("remove", &full, &err)),
            }
        }
        Ok(())
    }

    /// Creates missing parents. `false` when a non-directory blocks one.
    fn ensure_parents(&mut self, index: usize) -> Result<bool, CoreError> {
        let path = self.path(index).clone();
        let depth = match self.root.ancestry(&path)? {
            Ancestry::Clear => return Ok(true),
            Ancestry::Blocked { .. } => return Ok(false),
            Ancestry::Missing { depth } => depth,
        };
        let parents: Vec<Vec<u8>> = ancestors(&path).map(<[u8]>::to_vec).collect();
        for dir in parents.iter().skip(depth.saturating_sub(1)) {
            self.fenced()?;
            let full = self.root.join(dir)?;
            match fs::create_dir(&full) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(safety::io_error("create directory", &full, &err)),
            }
            self.mark_parent(&full);
            self.tick()?;
        }
        Ok(self.root.ancestry(&path)? == Ancestry::Clear)
    }

    fn write(&mut self, index: usize, want: &Shape) -> Result<(), CoreError> {
        self.fenced()?;
        let path = self.path(index).clone();
        let full = self
            .root
            .resolve_clear(&path)?
            .ok_or_else(|| recovery_error(std::slice::from_ref(&path)))?;
        match want {
            Shape::Absent => return Ok(()),
            Shape::Dir => match fs::create_dir(&full) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(safety::io_error("create directory", &full, &err)),
            },
            Shape::File { executable, oid } => {
                let temp = self.temp_path(index, &full)?;
                write_blob(self.store, *oid, *executable, &temp)?;
                self.tick()?;
                self.fenced()?;
                rename_replace(&temp, &full)?;
            }
            Shape::Symlink { link } => {
                let temp = self.temp_path(index, &full)?;
                create_symlink(link, &temp)?;
                self.tick()?;
                self.fenced()?;
                rename_replace(&temp, &full)?;
            }
        }
        self.mark_parent(&full);
        self.tick()?;
        if self.steps.is_multiple_of(CURSOR_INTERVAL) {
            self.persist_cursor(ApplyStep::Writing)?;
        }
        Ok(())
    }

    fn temp_name(&self, index: usize) -> String {
        let nonce: String = self
            .journal
            .nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!(".ruk-apply-{nonce}-{index}")
    }

    fn temp_path(&self, index: usize, full: &Path) -> Result<PathBuf, CoreError> {
        let parent = full.parent().ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "journaled path has no parent directory")
        })?;
        Ok(parent.join(self.temp_name(index)))
    }

    /// Removes this journal's temporary file for `index`, if a crash left
    /// one. The nonce makes the name ours; nothing else is touched.
    pub(super) fn clean_temp(&mut self, index: usize) -> Result<(), CoreError> {
        let path = self.path(index).clone();
        let Ok(Some(full)) = self.root.resolve_clear(&path) else {
            return Ok(());
        };
        let temp = self.temp_path(index, &full)?;
        match safety::lstat(&temp)? {
            Some(meta) if !meta.is_dir() => {
                fs::remove_file(&temp).map_err(|err| safety::io_error("remove", &temp, &err))?;
                self.mark_parent(&temp);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn mark_parent(&mut self, full: &Path) {
        if let Some(parent) = full.parent() {
            self.dirty_dirs.insert(parent.to_path_buf());
        }
    }

    /// Advances and persists the advisory cursor; never moves it backward.
    fn persist_cursor(&mut self, step: ApplyStep) -> Result<(), CoreError> {
        let next = StepCursor {
            pass: self.journal.cursor.pass,
            step,
            done: self.steps,
        };
        if next <= self.journal.cursor {
            return Ok(());
        }
        let mut journal = self.journal.clone();
        journal.cursor = next;
        self.republish(journal)
    }

    /// Replaces the journal row under both fences.
    pub(super) fn republish(&mut self, journal: ApplyJournal) -> Result<(), CoreError> {
        let workspace = journal.workspace;
        let bytes = journal::encode(&journal)?;
        let facts = [
            journal::replace_mutation(workspace, self.row.clone(), bytes.clone()),
            self.fence.guard(),
        ];
        self.store.publish(Vec::new(), &facts).map_err(lease_conflict)?;
        self.journal = journal;
        self.row = bytes;
        Ok(())
    }

    /// Flushes every directory whose entries changed.
    fn flush_dirs(&mut self) -> Result<(), CoreError> {
        for dir in std::mem::take(&mut self.dirty_dirs) {
            sync_dir(&dir)?;
        }
        Ok(())
    }

    /// Flushes, then checks every path not in `skip` against one side.
    pub(super) fn verify(&mut self, toward: Toward, skip: &BTreeSet<usize>) -> Result<(), CoreError> {
        self.flush_dirs()?;
        let mut wrong = Vec::new();
        for index in 0..self.journal.entries.len() {
            if skip.contains(&index) {
                continue;
            }
            if !self.desired(index, toward).matches(&self.observe(index)?) {
                wrong.push(self.path(index).clone());
            }
        }
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(recovery_error(&wrong))
        }
    }

    /// Publishes the completing batch: journal row removed, workspace row
    /// compare-and-swapped, caller facts applied.
    pub(super) fn complete(
        self,
        batch: FinishBatch,
        unresolved: Vec<RepoPath>,
    ) -> Result<ApplyOutcome, CoreError> {
        let workspace = self.journal.workspace;
        check_extra(workspace, &batch.extra)?;
        if self.fence.lease_epoch != self.journal.lease_epoch {
            return Err(CoreError::new(
                ErrorCode::ELeaseLost,
                "journal is owned by another lease epoch",
            ));
        }
        let workspace_fact = match batch.next_row {
            Some(next) => self.fence.replace(next),
            None => self.fence.guard(),
        };
        let mut facts = vec![journal::remove_mutation(workspace, self.row), workspace_fact];
        facts.extend(batch.extra);
        self.store.publish(Vec::new(), &facts).map_err(lease_conflict)?;
        Ok(ApplyOutcome {
            changed: self.journal.entries.into_iter().map(|entry| entry.path).collect(),
            unresolved,
        })
    }
}

fn write_blob(
    store: &Store,
    oid: crate::ids::Oid,
    executable: bool,
    temp: &Path,
) -> Result<(), CoreError> {
    let mut object = store.read(oid)?;
    if object.kind != ObjectKind::Blob {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("materialization target {oid} is not a blob"),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o777 } else { 0o666 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    let mut file = options
        .open(temp)
        .map_err(|err| safety::io_error("create", temp, &err))?;
    io::copy(&mut object.bytes, &mut file).map_err(|err| safety::io_error("write", temp, &err))?;
    file.sync_all().map_err(|err| safety::io_error("flush", temp, &err))
}

#[cfg(unix)]
fn create_symlink(link: &[u8], temp: &Path) -> Result<(), CoreError> {
    use std::os::unix::ffi::OsStrExt;
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(link), temp)
        .map_err(|err| safety::io_error("symlink", temp, &err))
}

#[cfg(windows)]
fn create_symlink(link: &[u8], temp: &Path) -> Result<(), CoreError> {
    let text = std::str::from_utf8(link)
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "non-UTF-8 symlink target"))?;
    std::os::windows::fs::symlink_file(text.replace('/', "\\"), temp)
        .map_err(|err| safety::io_error("symlink", temp, &err))
}

#[cfg(unix)]
fn rename_replace(from: &Path, to: &Path) -> Result<(), CoreError> {
    fs::rename(from, to).map_err(|err| safety::io_error("rename", to, &err))
}

#[cfg(windows)]
fn rename_replace(from: &Path, to: &Path) -> Result<(), CoreError> {
    atomicwrites::replace_atomic(from, to).map_err(|err| safety::io_error("rename", to, &err))
}

/// POSIX flushes the directory entry changes; Windows publishes renames
/// with write-through and has no directory flush (removals and directory
/// creations there rely on the filesystem's own ordering).
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), CoreError> {
    match fs::File::open(dir) {
        Ok(handle) => handle
            .sync_all()
            .map_err(|err| safety::io_error("flush directory", dir, &err)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(safety::io_error("open directory", dir, &err)),
    }
}

#[cfg(windows)]
fn sync_dir(_dir: &Path) -> Result<(), CoreError> {
    Ok(())
}

fn check_extra(workspace: WorkspaceId, extra: &[FactMutation]) -> Result<(), CoreError> {
    let reserved = extra.iter().any(|fact| {
        fact.table == FactTable::WsApply
            || (fact.table == FactTable::Workspaces && fact.key == workspace.as_bytes())
    });
    if reserved {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "extra mutations may not touch ws_apply or the materializing workspace row",
        ));
    }
    Ok(())
}

fn begin_conflict(store: &Store, workspace: WorkspaceId, err: StoreError) -> CoreError {
    if !matches!(err, StoreError::StaleFact { .. }) {
        return err.into();
    }
    match store.fact(FactTable::WsApply, &journal::ws_apply_key(workspace)) {
        Ok(Some(_)) => applying_error(),
        Ok(None) => err.into(),
        Err(read) => read.into(),
    }
}

fn lease_conflict(err: StoreError) -> CoreError {
    if matches!(err, StoreError::StaleFact { .. }) {
        CoreError::new(
            ErrorCode::ELeaseLost,
            format!("journal or workspace row moved under the materialization: {err}"),
        )
    } else {
        err.into()
    }
}

pub(crate) fn applying_error() -> CoreError {
    CoreError::new(
        ErrorCode::EWorkspaceApplying,
        "workspace is materializing; its worktree is not a snapshot",
    )
    .with_hint("finish or run ws.recover before snapshotting or mutating the workspace")
}

/// `E_WORKSPACE_RECOVERY` naming the external edits.
pub(crate) fn recovery_error(paths: &[RepoPath]) -> CoreError {
    let mut names: Vec<String> = paths
        .iter()
        .take(RECOVERY_REPORT_LIMIT)
        .map(|path| lossy(path.as_bytes()))
        .collect();
    if paths.len() > RECOVERY_REPORT_LIMIT {
        names.push(format!("and {} more", paths.len() - RECOVERY_REPORT_LIMIT));
    }
    CoreError::new(
        ErrorCode::EWorkspaceRecovery,
        format!(
            "paths match neither the materialization target nor its preimage: {}",
            names.join(", ")
        ),
    )
    .with_hint("ws.recover abort keeps these edits; ws.recover discard with the paths overwrites them")
}

/// Under [`LfsMode::Deny`], no file target may hold a Git LFS pointer.
/// Committed blobs are checked by locator length first, then decoded only
/// when they can be pointers; prepared target objects decode through the
/// store. A missing target fails before the journal publishes.
///
/// # Errors
/// `E_UNSUPPORTED_LFS` naming the path; `E_INVALID` when a file target is
/// not a blob; `E_NOT_FOUND` for a target neither committed nor prepared;
/// store read errors.
fn check_lfs_targets(
    store: &Store,
    entries: &[PlanEntry],
    prepared: &[PreparedObject],
) -> Result<(), CoreError> {
    let mut checked = BTreeSet::new();
    for entry in entries {
        let Some(target) = entry.target.as_ref() else {
            continue;
        };
        if !matches!(target.mode, FileMode::Regular | FileMode::Executable)
            || !checked.insert(target.oid)
        {
            continue;
        }
        let bytes = target_bytes(store, prepared, target.oid)?;
        if lfs::is_pointer(&bytes) {
            return Err(lfs::unsupported(entry.path.as_bytes()));
        }
    }
    Ok(())
}

/// The decoded bytes of a file target small enough to be a pointer, from
/// the plan's prepared objects or the committed store. Larger or non-file
/// content never reaches [`lfs::is_pointer`].
fn target_bytes(
    store: &Store,
    prepared: &[PreparedObject],
    oid: crate::ids::Oid,
) -> Result<Vec<u8>, CoreError> {
    if let Some(object) = prepared.iter().find(|object| object.oid() == oid) {
        if object.kind() != ObjectKind::Blob {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("materialization target {oid} is not a blob"),
            ));
        }
        if object.decoded_len() >= MAX_POINTER_BYTES {
            return Ok(Vec::new());
        }
        let mut bytes = Vec::new();
        store
            .decode_prepared(object)?
            .read_to_end(&mut bytes)
            .map_err(|err| {
                CoreError::new(ErrorCode::EIo, format!("read prepared blob {oid}: {err}"))
            })?;
        return Ok(bytes);
    }
    let Some(len) = store.object_len(oid)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("materialization target {oid} is not committed"),
        ));
    };
    if len >= MAX_POINTER_BYTES {
        return Ok(Vec::new());
    }
    let mut object = store.read(oid)?;
    if object.kind != ObjectKind::Blob {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("materialization target {oid} is not a blob"),
        ));
    }
    let mut bytes = Vec::new();
    object
        .bytes
        .read_to_end(&mut bytes)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("read blob {oid}: {err}")))?;
    Ok(bytes)
}

/// Test-only crash injection: fails the N-th physical step on this thread
/// as if the process died after the previous one.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;

    use crate::error::{CoreError, ErrorCode};

    thread_local! {
        static CRASH_AT: Cell<Option<u64>> = const { Cell::new(None) };
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    /// Disarms and resets the counter when dropped.
    #[derive(Debug)]
    pub(in crate::workcopy_journal) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            CRASH_AT.set(None);
            COUNT.set(0);
        }
    }

    /// Counts steps from zero; `crash_at` fails that step.
    pub(in crate::workcopy_journal) fn arm(crash_at: Option<u64>) -> Armed {
        COUNT.set(0);
        CRASH_AT.set(crash_at);
        Armed
    }

    pub(in crate::workcopy_journal) fn count() -> u64 {
        COUNT.get()
    }

    pub(super) fn tick() -> Result<(), CoreError> {
        let step = COUNT.get();
        COUNT.set(step + 1);
        if CRASH_AT.get() == Some(step) {
            return Err(CoreError::new(ErrorCode::ECancelled, "injected crash"));
        }
        Ok(())
    }
}
