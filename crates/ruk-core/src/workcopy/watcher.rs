//! Watcher tokens and the reducer that turns filesystem events into a dirty
//! set.
//!
//! The watcher integration itself is outside this module: it supplies a
//! [`WatchBatch`] of events between two tokens of one watcher instance.
//! A token is a monotonically increasing cursor; a batch is trusted only
//! when it starts exactly at the token the cache is current to, both ends
//! belong to the same instance, the cursor did not go backwards, and the
//! watcher did not overflow. Anything else yields a non-exhaustive
//! [`DirtySet`], which callers resolve with a scoped crawl.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{in_scope, is_internal};
use crate::index::RepoPath;
use crate::workspace::Scope;

/// More events than this in one batch are treated as an overflow.
pub(crate) const MAX_WATCH_EVENTS: usize = 1 << 20;

/// A filesystem event cursor of one watcher instance, or no usable cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum WatchToken {
    /// No cursor: the next snapshot must crawl.
    Invalid,
    /// Events up to `cursor` of watcher `instance` are reflected.
    At { instance: [u8; 16], cursor: u64 },
}

impl WatchToken {
    /// Whether a batch from `self` to `next` is a forward step of one
    /// instance. The caller records the batch end after resolving it, so a
    /// non-forward step is handled by crawling, not by stepping.
    #[must_use]
    pub(crate) fn precedes(self, next: Self) -> bool {
        match (self, next) {
            (
                Self::At { instance, cursor },
                Self::At {
                    instance: next_instance,
                    cursor: next_cursor,
                },
            ) => instance == next_instance && cursor <= next_cursor,
            _ => false,
        }
    }
}

/// What happened at an event path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchEventKind {
    /// Created, modified, or had metadata changed (a rename target too).
    Changed,
    /// Removed (a rename source too).
    Removed,
    /// Events below this directory were lost; the subtree must be crawled.
    /// An empty path means the whole worktree.
    Rescan,
}

/// One event: a worktree-relative, `/`-separated byte path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WatchEvent {
    pub(crate) path: Vec<u8>,
    pub(crate) kind: WatchEventKind,
}

/// The events a watcher reports between two tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WatchBatch {
    pub(crate) since: WatchToken,
    pub(crate) until: WatchToken,
    pub(crate) events: Vec<WatchEvent>,
    /// The watcher dropped events in this range.
    pub(crate) overflowed: bool,
}

/// Paths that may differ from the cached tree.
///
/// When `exhaustive` is false the sets are meaningless and the whole scope
/// must be crawled. When true, every in-scope path that can differ is in
/// `paths` or below a directory in `subtrees`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirtySet {
    pub(crate) paths: BTreeSet<RepoPath>,
    pub(crate) subtrees: BTreeSet<RepoPath>,
    pub(crate) exhaustive: bool,
}

impl DirtySet {
    /// The result that requires a full scoped crawl.
    #[must_use]
    pub(crate) fn crawl() -> Self {
        Self::default()
    }

    /// Whether nothing can have changed.
    #[must_use]
    pub(crate) fn is_clean(&self) -> bool {
        self.exhaustive && self.paths.is_empty() && self.subtrees.is_empty()
    }
}

/// Reduces a batch against the token the cache is current to.
///
/// Out-of-scope paths, the internal directory, and paths that cannot be
/// repository paths (a `.git` component) are dropped.
#[must_use]
pub(crate) fn reduce(recorded: WatchToken, batch: &WatchBatch, scope: &Scope) -> DirtySet {
    let continuous = recorded == batch.since && batch.since.precedes(batch.until);
    if !continuous || batch.overflowed || batch.events.len() > MAX_WATCH_EVENTS {
        return DirtySet::crawl();
    }
    let mut dirty = DirtySet {
        exhaustive: true,
        ..DirtySet::default()
    };
    for event in &batch.events {
        let path = event.path.strip_suffix(b"/").unwrap_or(&event.path);
        if path.is_empty() {
            return DirtySet::crawl();
        }
        if is_internal(path) {
            continue;
        }
        let Ok(path) = RepoPath::new(path) else {
            continue;
        };
        if !in_scope(scope, &path) {
            continue;
        }
        match event.kind {
            WatchEventKind::Changed | WatchEventKind::Removed => dirty.paths.insert(path),
            WatchEventKind::Rescan => dirty.subtrees.insert(path),
        };
    }
    dirty
}
