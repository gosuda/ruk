//! Native working copy: status, autosnapshot, and explicit write.
//!
//! A Native workspace follows the current-change model and has no index.
//! The authoritative state is a tree fact: the root tree a snapshot or an
//! explicit write records for the workspace's current change. Worktree bytes
//! are only cache inputs to that fact; the stat cache, watcher token, and
//! directory cache exist to avoid rehashing and re-encoding, and every one of
//! them is self-validating or fenced, so a stale cache can cost work but can
//! never produce a wrong tree.
//!
//! # Rows
//!
//! * `ws_status`: key `workspace id (16 bytes) ++ path` holds a
//!   [`statcache::StatusRow`]; the bare 16-byte workspace key holds the
//!   [`statcache::StatusMeta`] (the tree the worktree mirrors and the watcher
//!   token the cache is current to). Every snapshot and write replaces the
//!   meta row with a compare-and-swap expectation, which serializes them.
//! * `ws_dirs`: key `workspace id ++ directory path` (the root is the bare
//!   id) holds a [`tree::DirRow`]: a directory's tree id with its parsed
//!   entries. A row is used only when its tree id equals the id reached from
//!   the parent, so a stale row is ignored, never trusted.
//! * `ws_apply`: owned by the materialization journal; this module only
//!   reads it through [`journal_state::JournalState`] and fences on it.
//!
//! # Floor
//!
//! A watcher or stat comparison cannot prove content identity after an
//! external edit that preserves the whole stat tuple within one timestamp
//! tick and is not reported as an event. Racy entries are rehashed and
//! future or coarse timestamps are never trusted, which narrows that window
//! to edits that forge or exactly reproduce the tuple; explicit
//! [`write::write`] hashes bytes and is the remedy.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod crawl;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod ingest;
pub(crate) mod journal_state;
pub(crate) mod lfs;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod snapshot;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod statcache;
pub(crate) mod tree;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod watcher;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired subsystem; consumers land in later changeset rows"
    )
)]
pub(crate) mod write;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use crate::error::CoreModelError;
use crate::index::RepoPath;
use crate::store::{FactExpectation, FactMutation, FactPageBudget, FactTable, Store};
use crate::workspace::Scope;
use crate::{CoreError, WorkspaceId};

/// The workspace-internal directory at the worktree root. It and everything
/// below it are never snapshotted, crawled, or reported.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) const INTERNAL_DIR: &[u8] = b".ruk";

/// Fact-page bounds for prefix scans of the workspace cache tables.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
const PAGE_ROWS: usize = 4096;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
const PAGE_BYTES: usize = 32 * 1024 * 1024;

/// Maps an I/O failure to `E_IO` with what was being done.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn io_error(doing: &str, err: &std::io::Error) -> CoreError {
    CoreError::new(crate::ErrorCode::EIo, format!("{doing}: {err}"))
}

/// Whether `path` (relative, `/`-separated) names the internal directory or
/// anything inside it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn is_internal(path: &[u8]) -> bool {
    path == INTERNAL_DIR
        || (path.len() > INTERNAL_DIR.len()
            && path.starts_with(INTERNAL_DIR)
            && path.get(INTERNAL_DIR.len()) == Some(&b'/'))
}

/// Whether `path` is in a cone scope either as a file or as a directory the
/// scope descends into.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn in_scope(scope: &Scope, path: &RepoPath) -> bool {
    scope.includes_file(path) || scope.includes_dir(path)
}

/// Joins a directory (empty for the root) and one entry name into a
/// validated repository path.
///
/// # Errors
/// [`CoreModelError::Invalid`] when the result is not a valid [`RepoPath`]
/// (a `.git` component, an empty or dot component, a NUL byte).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn join(dir: &[u8], name: &[u8]) -> Result<RepoPath, CoreModelError> {
    let mut bytes = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        bytes.extend_from_slice(dir);
        bytes.push(b'/');
    }
    bytes.extend_from_slice(name);
    RepoPath::new(bytes)
}

/// The cache key of `path` (a file path for `ws_status`, a directory path
/// for `ws_dirs`; empty for the meta row or the root directory).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn cache_key(workspace: WorkspaceId, path: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + path.len());
    key.extend_from_slice(workspace.as_bytes());
    key.extend_from_slice(path);
    key
}

/// Every row of `table` whose key starts with `prefix`, in key order, read
/// in bounded pages. Returned keys are the suffixes after `prefix`.
///
/// # Errors
/// Store failures, including quarantine.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) fn scan_prefix(
    store: &Store,
    table: FactTable,
    prefix: &[u8],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError> {
    let mut rows = BTreeMap::new();
    if let Some(value) = store.fact(table, prefix)? {
        rows.insert(Vec::new(), value);
    }
    let mut after = prefix.to_vec();
    loop {
        let page = store.fact_page(
            table,
            Some(&after),
            FactPageBudget::new(PAGE_ROWS, PAGE_BYTES),
        )?;
        let mut finished = !page.more;
        for row in page.rows {
            if !row.key.starts_with(prefix) {
                finished = true;
                break;
            }
            after.clone_from(&row.key);
            rows.insert(row.key[prefix.len()..].to_vec(), row.value);
        }
        if finished {
            return Ok(rows);
        }
    }
}

/// Keyed mutations for one publication: table and key select the row.
type FactSetRows = BTreeMap<(FactTable, Vec<u8>), (FactExpectation, Option<Vec<u8>>)>;

/// Mutations keyed by table and key, so a publication never names one key
/// twice. A later insertion for the same key replaces the earlier one.
#[derive(Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) struct FactSet(FactSetRows);

impl fmt::Debug for FactSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FactSet")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
impl FactSet {
    pub(crate) fn push(&mut self, fact: FactMutation) {
        self.0
            .insert((fact.table, fact.key), (fact.expected, fact.value));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn into_vec(self) -> Vec<FactMutation> {
        self.0
            .into_iter()
            .map(|((table, key), (expected, value))| FactMutation {
                table,
                key,
                expected,
                value,
            })
            .collect()
    }
}

/// Decides which untracked paths a snapshot leaves out. Tracked paths (in
/// the base tree) are never ignored, and explicit write never consults it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) trait IgnoreRule: Sync + fmt::Debug {
    fn is_ignored(&self, path: &RepoPath) -> bool;
}

/// Ignores nothing: every untracked in-scope file is snapshotted.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unwired snapshot/write path; consumers land in later changeset rows"
    )
)]
pub(crate) struct NoIgnore;

impl IgnoreRule for NoIgnore {
    fn is_ignored(&self, _path: &RepoPath) -> bool {
        false
    }
}
