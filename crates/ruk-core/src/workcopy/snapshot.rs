//! Autosnapshot and status of a Native workspace.
//!
//! # Flow
//!
//! 1. Refuse a GitCompat workspace and an open journal; keep the journal
//!    guard for the publication.
//! 2. Read the `ws_status` meta row. The watcher batch is trusted only when
//!    the meta row describes the caller's base tree and the batch continues
//!    its token; otherwise the whole scope is crawled.
//! 3. Probe dirty paths, crawl dirty or rescanned subtrees, and walk the
//!    base tree under the same regions, so every path that can differ is a
//!    candidate.
//! 4. Trust unchanged, non-racy stat rows; hash every other candidate
//!    through the store's preparation path, in parallel.
//! 5. Compare each candidate with its base entry. Only differing paths
//!    become leaves; the tree is rebuilt along their ancestors.
//! 6. An unchanged root is `NoChange`, with at most a cache refresh that
//!    creates no operation. A changed root returns the new tree objects,
//!    the cache mutations, and a [`SnapshotDescriptor`] from which the
//!    caller rewrites the current change in the same publication.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::crawl::{CrawlLimits, Observed, Probe, Prober, crawl, parallel_map};
use super::ingest::{Ingested, file_mode, ingest};
use super::journal_state::{ApplyPhase, JournalState, ensure_idle};
use super::statcache::{StatClock, StatusMeta, StatusRow, Trust, decode_row, encode_row, trust};
use super::tree::{Dirs, Leaf, TreeMode, rebuild};
use super::watcher::{DirtySet, WatchBatch, WatchToken, reduce};
use super::{FactSet, IgnoreRule, cache_key, scan_prefix};
use crate::change::ChangeId;
use crate::heads::Head;
use crate::ids::Oid;
use crate::index::{FileMode, RepoPath};
use crate::store::{FactExpectation, FactMutation, FactTable, PreparedObject, Store};
use crate::workspace::{Scope, WorkspaceStamp, WorkspaceState};
use crate::{CoreError, ErrorCode, WorkspaceId};

/// Everything one snapshot or status pass reads.
#[derive(Debug)]
pub(crate) struct SnapshotInput<'a> {
    pub(crate) workspace: WorkspaceId,
    pub(crate) state: &'a WorkspaceState,
    /// The worktree root directory.
    pub(crate) root: &'a Path,
    /// The single tree of the workspace's current commit, resolved by the
    /// caller.
    pub(crate) base_tree: Oid,
    /// Events since the token the cache is current to, when a watcher runs.
    pub(crate) watch: Option<&'a WatchBatch>,
    /// Sampled before this pass stats anything.
    pub(crate) clock: StatClock,
    pub(crate) limits: CrawlLimits,
    pub(crate) ignore: &'a dyn IgnoreRule,
    pub(crate) journal: &'a dyn JournalState,
}

/// How the dirty set was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirtySource {
    Watcher,
    Crawl,
    /// Paths named by an explicit write.
    Explicit,
}

/// A path whose rendered conflict was edited or removed. Interpreting the
/// new bytes (intact markers, damaged markers, a resolution) belongs to the
/// caller; the snapshot records the bytes like any other file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConflictEdit {
    pub(crate) path: RepoPath,
    pub(crate) conflict: Oid,
    /// The new blob, or `None` when the path was removed.
    pub(crate) blob: Option<Oid>,
}

/// The operation a changed snapshot asks the caller to record: rewrite
/// `change` from `base_tree` to `tree`, fenced on `stamp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotDescriptor {
    pub(crate) workspace: WorkspaceId,
    pub(crate) change: ChangeId,
    pub(crate) head: Head,
    /// The stamp observed; the caller's mutation may fold only this
    /// immediately preceding snapshot into its own expectation.
    pub(crate) stamp: WorkspaceStamp,
    pub(crate) base_tree: Oid,
    pub(crate) tree: Oid,
    pub(crate) changed: Vec<RepoPath>,
    pub(crate) removed: Vec<RepoPath>,
    pub(crate) conflict_edits: Vec<ConflictEdit>,
    pub(crate) source: DirtySource,
}

/// A changed snapshot ready for one publication.
#[derive(Debug)]
pub(crate) struct PreparedSnapshot {
    /// New blobs and trees.
    pub(crate) objects: Vec<PreparedObject>,
    /// The journal guard, the meta compare-and-swap, and the `ws_status`
    /// and `ws_dirs` rows. The caller adds the workspace row and the
    /// commit/change rows of the rewritten current change.
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) descriptor: SnapshotDescriptor,
}

/// The result of an autosnapshot.
#[derive(Debug)]
pub(crate) enum SnapshotOutcome {
    /// The worktree matches the base tree. `cache` may refresh stat rows and
    /// the watcher token; publishing it records no operation and does not
    /// advance the workspace stamp. Empty when nothing needs refreshing.
    NoChange {
        cache: Vec<FactMutation>,
    },
    Changed(Box<PreparedSnapshot>),
}

/// A read-only status report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StatusReport {
    /// A journal is open; the directory is not a complete snapshot of any
    /// state and nothing about it is claimed.
    Materializing(ApplyPhase),
    Clean,
    Dirty {
        changed: Vec<RepoPath>,
        removed: Vec<RepoPath>,
        conflict_edits: Vec<ConflictEdit>,
    },
}

/// Runs the autosnapshot.
///
/// # Errors
/// `E_INVALID` for a GitCompat workspace; `E_WORKSPACE_APPLYING` or
/// `E_WORKSPACE_RECOVERY` while a journal is open; `E_OBJECT_FORMAT` for a
/// base tree of the wrong width; crawl, hashing, and store failures.
pub(crate) fn snapshot(
    store: &Store,
    input: &SnapshotInput<'_>,
) -> Result<SnapshotOutcome, CoreError> {
    let native = input.state.require_native()?;
    let guard = ensure_idle(input.journal, store, input.workspace)?;
    let computed = compute(store, input, &native.scope)?;
    let Some(computed) = computed else {
        return Ok(SnapshotOutcome::NoChange { cache: Vec::new() });
    };
    let Computed {
        mut facts,
        objects,
        tree,
        changed,
        removed,
        conflict_edits,
        source,
    } = computed;
    if tree == input.base_tree {
        if facts.is_empty() {
            return Ok(SnapshotOutcome::NoChange { cache: Vec::new() });
        }
        facts.push(guard);
        return Ok(SnapshotOutcome::NoChange {
            cache: facts.into_vec(),
        });
    }
    facts.push(guard);
    Ok(SnapshotOutcome::Changed(Box::new(PreparedSnapshot {
        objects,
        facts: facts.into_vec(),
        descriptor: SnapshotDescriptor {
            workspace: input.workspace,
            change: native.change,
            head: native.head,
            stamp: native.stamp,
            base_tree: input.base_tree,
            tree,
            changed,
            removed,
            conflict_edits,
            source,
        },
    })))
}

/// Reports how the worktree differs from the base tree without writing.
/// An open journal is reported, not refused.
///
/// # Errors
/// As [`snapshot`], except for the journal phase.
pub(crate) fn status(store: &Store, input: &SnapshotInput<'_>) -> Result<StatusReport, CoreError> {
    let native = input.state.require_native()?;
    let observation = input.journal.observe(store, input.workspace)?;
    if observation.phase != ApplyPhase::Idle {
        return Ok(StatusReport::Materializing(observation.phase));
    }
    let Some(computed) = compute(store, input, &native.scope)? else {
        return Ok(StatusReport::Clean);
    };
    if computed.tree == input.base_tree {
        return Ok(StatusReport::Clean);
    }
    Ok(StatusReport::Dirty {
        changed: computed.changed,
        removed: computed.removed,
        conflict_edits: computed.conflict_edits,
    })
}

/// The computed new state. `facts` excludes the journal guard.
#[derive(Debug)]
pub(crate) struct Computed {
    pub(crate) facts: FactSet,
    pub(crate) objects: Vec<PreparedObject>,
    pub(crate) tree: Oid,
    pub(crate) changed: Vec<RepoPath>,
    pub(crate) removed: Vec<RepoPath>,
    pub(crate) conflict_edits: Vec<ConflictEdit>,
    pub(crate) source: DirtySource,
}

/// `None` when the watcher proves nothing changed.
fn compute(
    store: &Store,
    input: &SnapshotInput<'_>,
    scope: &Scope,
) -> Result<Option<Computed>, CoreError> {
    input
        .base_tree
        .expect_kind(store.hash_kind(), "snapshot base tree")?;
    let meta = read_meta(store, input.workspace)?;
    let recorded = match &meta {
        Some((_, meta)) if meta.tree == input.base_tree => meta.token,
        _ => WatchToken::Invalid,
    };
    let dirty = match input.watch {
        Some(batch) => reduce(recorded, batch, scope),
        None => DirtySet::crawl(),
    };
    if dirty.is_clean() {
        return Ok(None);
    }
    let source = if dirty.exhaustive {
        DirtySource::Watcher
    } else {
        DirtySource::Crawl
    };
    let mut engine = Engine::new(store, input, scope, Policy::Snapshot);
    if dirty.exhaustive {
        engine.gather_paths(dirty.paths.iter().chain(&dirty.subtrees))?;
    } else {
        engine.gather_all()?;
    }
    // The crawl or probe pass observes the present, which includes
    // everything up to `until`, so the batch end is always safe to record;
    // a discontinuous batch was still resolved by crawling.
    let token = input.watch.map_or(WatchToken::Invalid, |batch| batch.until);
    let mut computed = engine.finish(source)?;
    let next_meta = StatusMeta {
        tree: computed.tree,
        token,
    };
    if meta.as_ref().is_none_or(|(_, old)| *old != next_meta) {
        computed.facts.push(meta_mutation(
            input.workspace,
            meta.map(|(bytes, _)| bytes),
            &next_meta,
        )?);
    }
    Ok(Some(computed))
}

/// The meta row's raw bytes and decoded value.
pub(crate) fn read_meta(
    store: &Store,
    workspace: WorkspaceId,
) -> Result<Option<(Vec<u8>, StatusMeta)>, CoreError> {
    let Some(bytes) = store.fact(FactTable::WsStatus, &cache_key(workspace, b""))? else {
        return Ok(None);
    };
    let meta = decode_row(store, "ws_status meta row", &bytes)?;
    Ok(Some((bytes, meta)))
}

/// Replaces the meta row under a compare-and-swap on the observed bytes.
///
/// # Errors
/// `E_INVALID` if the row cannot be encoded.
pub(crate) fn meta_mutation(
    workspace: WorkspaceId,
    observed: Option<Vec<u8>>,
    next: &StatusMeta,
) -> Result<FactMutation, CoreError> {
    Ok(FactMutation {
        table: FactTable::WsStatus,
        key: cache_key(workspace, b""),
        expected: observed.map_or(FactExpectation::Absent, FactExpectation::Value),
        value: Some(encode_row("ws_status meta row", next)?),
    })
}

/// Whether cached stat rows may stand in for hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    /// Trust clean, non-racy rows; consult the ignore rule for untracked
    /// files.
    Snapshot,
    /// Hash every observed path and never consult the ignore rule.
    Explicit,
}

/// Candidate collection and decision for one pass.
pub(crate) struct Engine<'a> {
    store: &'a Store,
    workspace: WorkspaceId,
    root: &'a Path,
    scope: &'a Scope,
    base: Oid,
    clock: StatClock,
    limits: CrawlLimits,
    ignore: Option<&'a dyn IgnoreRule>,
    policy: Policy,
    dirs: Dirs<'a>,
    prober: Prober<'a>,
    observed: BTreeMap<RepoPath, Observed>,
    /// Base blob-backed entries of every candidate region.
    tracked: BTreeMap<RepoPath, (FileMode, Oid)>,
    /// Named paths that are directories in the base and gone on disk.
    base_dirs_gone: BTreeSet<RepoPath>,
    /// Status rows of every candidate region: raw bytes and decoded row.
    rows: BTreeMap<RepoPath, (Vec<u8>, StatusRow)>,
    /// Named paths found absent.
    absent: BTreeSet<RepoPath>,
}

impl<'a> Engine<'a> {
    pub(crate) fn new(
        store: &'a Store,
        input: &SnapshotInput<'a>,
        scope: &'a Scope,
        policy: Policy,
    ) -> Self {
        Self::with_parts(
            store,
            Parts {
                workspace: input.workspace,
                root: input.root,
                scope,
                base: input.base_tree,
                clock: input.clock,
                limits: input.limits,
                ignore: Some(input.ignore),
            },
            policy,
        )
    }

    pub(crate) fn with_parts(store: &'a Store, parts: Parts<'a>, policy: Policy) -> Self {
        Self {
            store,
            workspace: parts.workspace,
            root: parts.root,
            scope: parts.scope,
            base: parts.base,
            clock: parts.clock,
            limits: parts.limits,
            ignore: parts.ignore,
            policy,
            dirs: Dirs::new(store, parts.workspace),
            prober: Prober::new(parts.root),
            observed: BTreeMap::new(),
            tracked: BTreeMap::new(),
            base_dirs_gone: BTreeSet::new(),
            rows: BTreeMap::new(),
            absent: BTreeSet::new(),
        }
    }

    /// Makes the whole scope the candidate region.
    pub(crate) fn gather_all(&mut self) -> Result<(), CoreError> {
        for found in crawl(self.root, &[], self.scope, self.limits)? {
            self.observed.insert(found.path.clone(), found);
        }
        let tracked = self.dirs.tracked_files(self.base, b"", self.scope)?;
        self.tracked.extend(tracked);
        self.load_rows(b"")
    }

    /// Makes named paths the candidate regions: a path that is a directory
    /// on disk is crawled together with its base subtree, anything else is
    /// probed alone. Rescanned subtrees and changed paths are handled alike,
    /// so a "subtree" that is now a file is still seen as a file.
    pub(crate) fn gather_paths<'p>(
        &mut self,
        paths: impl IntoIterator<Item = &'p RepoPath>,
    ) -> Result<(), CoreError> {
        let mut regions: BTreeSet<RepoPath> = BTreeSet::new();
        for path in paths {
            self.load_row(path)?;
            self.load_rows_below(path)?;
            let probe = self.prober.probe(path)?;
            let on_disk_dir = probe == Probe::Dir;
            match probe {
                Probe::Entry(found) => {
                    self.observed.insert(found.path.clone(), found);
                }
                Probe::Absent => {
                    self.absent.insert(path.clone());
                }
                Probe::Dir => {
                    regions.insert(path.clone());
                }
                Probe::NestedRepository => continue,
            }
            match self.dirs.lookup(self.base, path.as_bytes())? {
                Some((TreeMode::File(mode), oid)) if TreeMode::File(mode).is_blob() => {
                    self.tracked.insert(path.clone(), (mode, oid));
                }
                Some((TreeMode::Tree, _)) if !on_disk_dir => {
                    self.base_dirs_gone.insert(path.clone());
                }
                _ => {}
            }
        }
        let starts = outermost(&regions);
        // Only directory regions need a sweep; a list of file probes alone
        // observes exactly what the watcher reported and must not descend
        // into untouched subtrees.
        if !starts.is_empty() {
            for found in crawl(self.root, &starts, self.scope, self.limits)? {
                self.observed.insert(found.path.clone(), found);
            }
            for start in &starts {
                let tracked = self
                    .dirs
                    .tracked_files(self.base, start.as_bytes(), self.scope)?;
                self.tracked.extend(tracked);
            }
        }
        Ok(())
    }

    fn load_row(&mut self, path: &RepoPath) -> Result<(), CoreError> {
        let key = cache_key(self.workspace, path.as_bytes());
        if let Some(bytes) = self.store.fact(FactTable::WsStatus, &key)? {
            let row = decode_row(self.store, "ws_status row", &bytes)?;
            self.rows.insert(path.clone(), (bytes, row));
        }
        Ok(())
    }

    fn load_rows_below(&mut self, dir: &RepoPath) -> Result<(), CoreError> {
        let mut prefix = dir.as_bytes().to_vec();
        prefix.push(b'/');
        self.load_rows(&prefix)
    }

    /// Loads every status row whose path starts with `prefix` (empty for the
    /// whole workspace; the meta row is skipped).
    fn load_rows(&mut self, prefix: &[u8]) -> Result<(), CoreError> {
        let rows = scan_prefix(
            self.store,
            FactTable::WsStatus,
            &cache_key(self.workspace, prefix),
        )?;
        for (suffix, bytes) in rows {
            if prefix.is_empty() && suffix.is_empty() {
                continue;
            }
            let mut path = prefix.to_vec();
            path.extend_from_slice(&suffix);
            let Ok(path) = RepoPath::new(path) else {
                return Err(super::statcache::corrupt(
                    self.store,
                    "ws_status row with an invalid path".to_owned(),
                ));
            };
            let row = decode_row(self.store, "ws_status row", &bytes)?;
            self.rows.insert(path, (bytes, row));
        }
        Ok(())
    }

    /// Hashes, compares, and rebuilds.
    pub(crate) fn finish(mut self, source: DirtySource) -> Result<Computed, CoreError> {
        let mut hashed = self.hash_untrusted()?;
        let mut candidates: BTreeSet<RepoPath> = BTreeSet::new();
        candidates.extend(self.observed.keys().cloned());
        candidates.extend(self.tracked.keys().cloned());
        candidates.extend(self.rows.keys().cloned());
        candidates.extend(self.absent.iter().cloned());
        candidates.extend(self.base_dirs_gone.iter().cloned());

        let mut facts = FactSet::default();
        let mut leaves = BTreeMap::new();
        let mut keep_objects: BTreeMap<Oid, PreparedObject> = BTreeMap::new();
        let mut conflict_edits = Vec::new();
        for path in candidates {
            let row = self.rows.get(&path);
            if !self.scope.includes_file(&path) {
                if row.is_some() {
                    facts.push(remove_status(self.workspace, &path));
                }
                continue;
            }
            let base = self.tracked.get(&path).copied();
            let current = match self.observed.get(&path) {
                Some(found) if !self.untracked_ignored(&path) => {
                    self.current(found, row, base, &mut hashed)?
                }
                _ => None,
            };
            let Some(entry) = current else {
                if base.is_some() || self.base_dirs_gone.contains(&path) {
                    leaves.insert(path.clone(), Leaf::Absent);
                }
                if let Some(conflict) = row.and_then(|(_, old)| old.conflict) {
                    conflict_edits.push(ConflictEdit {
                        path: path.clone(),
                        conflict,
                        blob: None,
                    });
                }
                if row.is_some() {
                    facts.push(remove_status(self.workspace, &path));
                }
                continue;
            };
            let conflict = row.and_then(|(_, old)| old.conflict);
            if let Some(conflict) = conflict
                && row.is_some_and(|(_, old)| old.blob != entry.blob)
            {
                conflict_edits.push(ConflictEdit {
                    path: path.clone(),
                    conflict,
                    blob: Some(entry.blob),
                });
            }
            let next = StatusRow::observed(
                entry.stat,
                entry.mode,
                entry.blob,
                entry.stable,
                &self.clock,
                conflict,
            );
            let encoded = encode_row("ws_status row", &next)?;
            if row.is_none_or(|(bytes, _)| *bytes != encoded) {
                facts.push(FactMutation {
                    table: FactTable::WsStatus,
                    key: cache_key(self.workspace, path.as_bytes()),
                    expected: FactExpectation::Any,
                    value: Some(encoded),
                });
            }
            if base == Some((entry.mode, entry.blob)) && !self.base_dirs_gone.contains(&path) {
                continue;
            }
            if let Some(object) = entry.object {
                keep_objects.entry(entry.blob).or_insert(object);
            }
            leaves.insert(
                path,
                Leaf::File {
                    mode: entry.mode,
                    blob: entry.blob,
                },
            );
        }

        let mut changed = Vec::new();
        let mut removed = Vec::new();
        for (path, leaf) in &leaves {
            match leaf {
                Leaf::File { .. } => changed.push(path.clone()),
                Leaf::Absent => removed.push(path.clone()),
            }
        }
        let rebuilt = rebuild(&mut self.dirs, self.base, &leaves)?;
        let mut objects: Vec<PreparedObject> = keep_objects.into_values().collect();
        if rebuilt.root == self.base {
            objects.clear();
        } else {
            objects.extend(rebuilt.objects);
        }
        for dir in &rebuilt.removed_dirs {
            self.purge_dir(dir, &mut facts)?;
        }
        for fact in rebuilt.dirs {
            facts.push(fact);
        }
        Ok(Computed {
            facts,
            objects,
            tree: rebuilt.root,
            changed,
            removed,
            conflict_edits,
            source,
        })
    }

    /// An untracked path (no base entry, no status row) the ignore rule
    /// excludes. Explicit writes never ask.
    fn untracked_ignored(&self, path: &RepoPath) -> bool {
        self.policy == Policy::Snapshot
            && !self.tracked.contains_key(path)
            && !self.rows.contains_key(path)
            && self.ignore.is_some_and(|rule| rule.is_ignored(path))
    }

    /// Removes the cache rows of a directory that left the tree.
    fn purge_dir(&self, dir: &[u8], facts: &mut FactSet) -> Result<(), CoreError> {
        let exact = cache_key(self.workspace, dir);
        if self.store.fact(FactTable::WsDirs, &exact)?.is_some() {
            facts.push(remove(FactTable::WsDirs, exact));
        }
        let mut below = dir.to_vec();
        below.push(b'/');
        let prefix = cache_key(self.workspace, &below);
        for table in [FactTable::WsDirs, FactTable::WsStatus] {
            for suffix in scan_prefix(self.store, table, &prefix)?.into_keys() {
                let mut key = prefix.clone();
                key.extend_from_slice(&suffix);
                facts.push(remove(table, key));
            }
        }
        Ok(())
    }

    /// Hashes every observed path the cache cannot vouch for.
    fn hash_untrusted(&self) -> Result<BTreeMap<RepoPath, Ingested>, CoreError> {
        let untrusted: Vec<&Observed> = self
            .observed
            .values()
            .filter(|found| self.scope.includes_file(&found.path))
            .filter(|found| !self.untracked_ignored(&found.path))
            .filter(|found| {
                self.policy == Policy::Explicit
                    || trust(
                        self.rows.get(&found.path).map(|(_, row)| row),
                        &found.stat,
                        &self.clock,
                    ) == Trust::Rehash
            })
            .collect();
        let results = parallel_map(&untrusted, self.limits.workers, |found| {
            ingest(self.store, self.root, found)
        })?;
        Ok(untrusted
            .into_iter()
            .map(|found| found.path.clone())
            .zip(results)
            .collect())
    }

    /// The current content of an observed path: trusted from the cache or
    /// taken from its hash. `None` when it vanished while being hashed.
    fn current(
        &self,
        found: &Observed,
        row: Option<&(Vec<u8>, StatusRow)>,
        base: Option<(FileMode, Oid)>,
        hashed: &mut BTreeMap<RepoPath, Ingested>,
    ) -> Result<Option<Current>, CoreError> {
        if let Some(ingested) = hashed.remove(&found.path) {
            return Ok(from_ingested(ingested, base));
        }
        let Trust::Clean { blob, mode } = trust(row.map(|(_, row)| row), &found.stat, &self.clock)
        else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "an untrusted path was not hashed",
            ));
        };
        // A trusted blob that the base tree does not hold becomes a new
        // leaf; its bytes are read now so the publication carries the
        // object instead of relying on an earlier one surviving retention.
        if base != Some((mode, blob)) {
            return Ok(from_ingested(ingest(self.store, self.root, found)?, base));
        }
        Ok(Some(Current {
            mode,
            blob,
            stat: found.stat,
            stable: true,
            object: None,
        }))
    }
}

/// The construction inputs of an [`Engine`] that do not come from a
/// [`SnapshotInput`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Parts<'a> {
    pub(crate) workspace: WorkspaceId,
    pub(crate) root: &'a Path,
    pub(crate) scope: &'a Scope,
    pub(crate) base: Oid,
    pub(crate) clock: StatClock,
    pub(crate) limits: CrawlLimits,
    pub(crate) ignore: Option<&'a dyn IgnoreRule>,
}

fn from_ingested(ingested: Ingested, base: Option<(FileMode, Oid)>) -> Option<Current> {
    let Ingested::Hashed(done) = ingested else {
        return None;
    };
    Some(Current {
        mode: file_mode(done.kind, base.map(|(mode, _)| mode)),
        blob: done.blob,
        stat: done.stat,
        stable: done.stable,
        object: Some(done.object),
    })
}

/// What an observed path holds now.
struct Current {
    mode: FileMode,
    blob: Oid,
    stat: super::statcache::FileStat,
    stable: bool,
    /// The prepared blob when the bytes were hashed in this pass; it is
    /// published only if the path's leaf changes.
    object: Option<PreparedObject>,
}

fn remove(table: FactTable, key: Vec<u8>) -> FactMutation {
    FactMutation {
        table,
        key,
        expected: FactExpectation::Any,
        value: None,
    }
}

fn remove_status(workspace: WorkspaceId, path: &RepoPath) -> FactMutation {
    remove(FactTable::WsStatus, cache_key(workspace, path.as_bytes()))
}

/// The regions that have no proper ancestor among the regions.
fn outermost(regions: &BTreeSet<RepoPath>) -> Vec<RepoPath> {
    regions
        .iter()
        .filter(|region| {
            let bytes = region.as_bytes();
            !bytes
                .iter()
                .enumerate()
                .any(|(cut, &byte)| byte == b'/' && regions.contains(&bytes[..cut]))
        })
        .cloned()
        .collect()
}
