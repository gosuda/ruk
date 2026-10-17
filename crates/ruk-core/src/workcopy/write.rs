//! Explicit write: hash the named paths' current bytes into the current
//! change.
//!
//! Write does not autosnapshot and does not trust the stat cache: every
//! named file, and every file below a named directory, is read and hashed
//! through the store's preparation path. That is the remedy for the
//! watcher/stat floor. The ignore rule is not consulted, so an ignored path
//! can be written. A named path that is absent removes it from the tree.
//! Other dirty paths are left for the next snapshot.
//!
//! Native workspaces have no index, so write records a tree fact, not
//! `ws_index` rows: it refreshes the named paths' `ws_status` rows and
//! returns the rebuilt tree for the caller to record against the current
//! change, fenced on the caller's expected stamp.

use std::path::Path;

use super::crawl::CrawlLimits;
use super::journal_state::{JournalState, ensure_idle};
use super::snapshot::{ConflictEdit, DirtySource, Engine, Parts, Policy, meta_mutation, read_meta};
use super::statcache::{StatClock, StatusMeta};
use super::watcher::WatchToken;
use super::{in_scope, is_internal};
use crate::change::ChangeId;
use crate::heads::Head;
use crate::ids::Oid;
use crate::index::RepoPath;
use crate::store::{FactMutation, PreparedObject, Store};
use crate::workspace::{Scope, WorkspaceStamp, WorkspaceState};
use crate::{CoreError, ErrorCode, WorkspaceId};

/// Everything one explicit write reads.
#[derive(Debug)]
pub(crate) struct WriteInput<'a> {
    pub(crate) workspace: WorkspaceId,
    pub(crate) state: &'a WorkspaceState,
    /// The stamp the caller expects; checked lease epoch first, then
    /// sequence.
    pub(crate) expected: WorkspaceStamp,
    pub(crate) root: &'a Path,
    pub(crate) base_tree: Oid,
    pub(crate) paths: &'a [RepoPath],
    pub(crate) clock: StatClock,
    pub(crate) limits: CrawlLimits,
    pub(crate) journal: &'a dyn JournalState,
}

/// The operation a changed write asks the caller to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteDescriptor {
    pub(crate) workspace: WorkspaceId,
    pub(crate) change: ChangeId,
    pub(crate) head: Head,
    pub(crate) expected: WorkspaceStamp,
    pub(crate) base_tree: Oid,
    pub(crate) tree: Oid,
    pub(crate) written: Vec<RepoPath>,
    pub(crate) removed: Vec<RepoPath>,
    pub(crate) conflict_edits: Vec<ConflictEdit>,
}

/// A changed write ready for one publication.
#[derive(Debug)]
pub(crate) struct PreparedWrite {
    pub(crate) objects: Vec<PreparedObject>,
    /// The journal guard, the meta compare-and-swap, and cache rows. The
    /// caller adds the workspace row (advanced from `expected`) and the
    /// commit/change rows.
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) descriptor: WriteDescriptor,
}

/// The result of an explicit write.
#[derive(Debug)]
pub(crate) enum WriteOutcome {
    /// The named paths already match the base tree; `cache` refreshes
    /// their stat rows and records no operation.
    NoChange {
        cache: Vec<FactMutation>,
    },
    Changed(PreparedWrite),
}

/// Hashes the named paths and rebuilds the tree.
///
/// # Errors
/// `E_INVALID` for a GitCompat workspace, no paths, an internal path, or a
/// path outside the scope; `E_LEASE_LOST`/`E_STALE` from the stamp fence;
/// `E_WORKSPACE_APPLYING`/`E_WORKSPACE_RECOVERY` while a journal is open;
/// hashing and store failures.
pub(crate) fn write(store: &Store, input: &WriteInput<'_>) -> Result<WriteOutcome, CoreError> {
    let native = input.state.require_native()?;
    native.stamp.fence(input.expected)?;
    validate_paths(input, &native.scope)?;
    input
        .base_tree
        .expect_kind(store.hash_kind(), "write base tree")?;
    let guard = ensure_idle(input.journal, store, input.workspace)?;

    let mut engine = Engine::with_parts(
        store,
        Parts {
            workspace: input.workspace,
            root: input.root,
            scope: &native.scope,
            base: input.base_tree,
            clock: input.clock,
            limits: input.limits,
            ignore: None,
        },
        Policy::Explicit,
    );
    engine.gather_paths(input.paths)?;
    let mut computed = engine.finish(DirtySource::Explicit)?;

    let meta = read_meta(store, input.workspace)?;
    // The token stays valid only if the cache already mirrored the base:
    // the written paths now match the new tree, and every other path is
    // still reported by events after that token.
    let token = match &meta {
        Some((_, old)) if old.tree == input.base_tree => old.token,
        _ => WatchToken::Invalid,
    };
    let next_meta = StatusMeta {
        tree: computed.tree,
        token,
    };
    if meta.as_ref().is_none_or(|(_, old)| *old != next_meta) {
        let observed = meta.map(|(bytes, _)| bytes);
        computed
            .facts
            .push(meta_mutation(input.workspace, observed, &next_meta)?);
    }

    if computed.tree == input.base_tree {
        if computed.facts.is_empty() {
            return Ok(WriteOutcome::NoChange { cache: Vec::new() });
        }
        computed.facts.push(guard);
        return Ok(WriteOutcome::NoChange {
            cache: computed.facts.into_vec(),
        });
    }
    computed.facts.push(guard);
    Ok(WriteOutcome::Changed(PreparedWrite {
        objects: computed.objects,
        facts: computed.facts.into_vec(),
        descriptor: WriteDescriptor {
            workspace: input.workspace,
            change: native.change,
            head: native.head,
            expected: input.expected,
            base_tree: input.base_tree,
            tree: computed.tree,
            written: computed.changed,
            removed: computed.removed,
            conflict_edits: computed.conflict_edits,
        },
    }))
}

fn validate_paths(input: &WriteInput<'_>, scope: &Scope) -> Result<(), CoreError> {
    if input.paths.is_empty() {
        return Err(CoreError::new(ErrorCode::EInvalid, "write names no paths"));
    }
    for path in input.paths {
        let shown = String::from_utf8_lossy(path.as_bytes());
        if is_internal(path.as_bytes()) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("{shown} is inside the workspace's internal directory"),
            ));
        }
        if !in_scope(scope, path) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("{shown} is outside the workspace scope"),
            )
            .with_hint("widen the scope before writing out-of-scope paths"));
        }
    }
    Ok(())
}
