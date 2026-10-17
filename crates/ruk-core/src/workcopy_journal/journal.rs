//! The v1 `ws_apply` row: one [`ApplyJournal`] per workspace, present only
//! while a materialization is open.
//!
//! Key: the 16 raw [`WorkspaceId`] bytes (the same layout as the
//! `workspaces` row). Value: the postcard encoding of [`ApplyJournal`].
//! The row is inserted with [`FactExpectation::Absent`] by
//! [`super::begin_apply`] and removed with the exact observed bytes by a
//! completing finish, abort, or recovery batch; there is no idle row.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::WorkspaceId;
use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath};
use crate::store::{FactExpectation, FactMutation, FactTable, Store, StoreError};
pub(crate) use crate::workcopy::journal_state::ws_apply_key;

use super::safety;

/// The only journal record version.
pub(crate) const JOURNAL_VERSION: u32 = 1;

/// Largest encoded journal row. A larger materialization is `E_CAPACITY`
/// before anything is written; it is never split, because a split would
/// expose an unjournaled hybrid worktree between the parts.
pub(crate) const MAX_JOURNAL_ROW_BYTES: usize = 256 * 1024 * 1024;

/// What a journaled path must physically become.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TargetEntry {
    pub(crate) mode: FileMode,
    /// Blob for regular, executable and symlink entries; the foreign commit
    /// for a gitlink, which is materialized as a directory only.
    pub(crate) oid: Oid,
    /// The exact link bytes, present iff `mode` is [`FileMode::Symlink`].
    pub(crate) link: Option<ByteString>,
}

/// The actual worktree content of a journaled path before the first write.
/// File and symlink bytes are blobs published with the journal, so they stay
/// rooted until the journal finishes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Preimage {
    Absent,
    File {
        executable: bool,
        oid: Oid,
    },
    Symlink {
        link: ByteString,
        oid: Oid,
    },
    /// A directory whose every non-directory descendant is itself journaled
    /// (or a gitlink directory left untouched).
    Directory,
}

/// The per-path transition, derived from preimage and target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Transition {
    Create,
    Delete,
    /// Created with the bytes and mode that `from` (journaled as a delete)
    /// held. Executed as a write from the store, never as an OS rename, so a
    /// half-done rename cannot strand the source.
    Rename {
        from: RepoPath,
    },
    Modify,
    ModeChange,
    SymlinkChange,
    DirFileSwap,
}

/// One journaled path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JournalEntry {
    pub(crate) path: RepoPath,
    /// `None`: the path must not exist as a file (it may remain a directory
    /// when another journaled target lies below it).
    pub(crate) target: Option<TargetEntry>,
    pub(crate) preimage: Preimage,
    pub(crate) transition: Transition,
}

/// The journal state. A row exists only while applying.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ApplyState {
    Applying,
}

/// The executor phase a cursor names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ApplyStep {
    Journaled,
    Removing,
    Writing,
    Verifying,
}

/// Monotonic progress cursor, ordered by `(pass, step, done)`. Advisory:
/// recovery classifies physical state and never trusts the cursor to skip a
/// path. `pass` rises on every recovery attempt so the cursor never moves
/// backward when an earlier phase is rerun.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct StepCursor {
    pub(crate) pass: u32,
    pub(crate) step: ApplyStep,
    pub(crate) done: u64,
}

impl StepCursor {
    pub(crate) const START: Self = Self {
        pass: 0,
        step: ApplyStep::Journaled,
        done: 0,
    };
}

/// The materialization journal (v1).
///
/// Invariant: `entries` is strictly ascending by path bytes and is the
/// single authority for target, preimage and transition of every path the
/// materialization may touch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApplyJournal {
    pub(crate) version: u32,
    pub(crate) workspace: WorkspaceId,
    /// Random per-journal nonce; names this journal's temporary files.
    pub(crate) nonce: [u8; 16],
    /// The workspace lease epoch that owns this materialization.
    pub(crate) lease_epoch: u64,
    pub(crate) state: ApplyState,
    pub(crate) cursor: StepCursor,
    pub(crate) entries: Vec<JournalEntry>,
}

/// The physical shape a path is compared against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    Absent,
    File { executable: bool, oid: Oid },
    Symlink { link: Vec<u8> },
    Dir,
}

impl Shape {
    pub(crate) const fn is_dir(&self) -> bool {
        matches!(self, Self::Dir)
    }
}

impl TargetEntry {
    pub(crate) fn shape(&self) -> Shape {
        match self.mode {
            FileMode::Regular => Shape::File {
                executable: false,
                oid: self.oid,
            },
            FileMode::Executable => Shape::File {
                executable: true,
                oid: self.oid,
            },
            FileMode::Symlink => Shape::Symlink {
                link: self
                    .link
                    .as_ref()
                    .map(|link| link.as_bytes().to_vec())
                    .unwrap_or_default(),
            },
            FileMode::Gitlink => Shape::Dir,
        }
    }
}

impl Preimage {
    pub(crate) fn shape(&self) -> Shape {
        match self {
            Self::Absent => Shape::Absent,
            Self::File { executable, oid } => Shape::File {
                executable: *executable,
                oid: *oid,
            },
            Self::Symlink { link, .. } => Shape::Symlink {
                link: link.as_bytes().to_vec(),
            },
            Self::Directory => Shape::Dir,
        }
    }

    pub(crate) const fn oid(&self) -> Option<Oid> {
        match self {
            Self::File { oid, .. } | Self::Symlink { oid, .. } => Some(*oid),
            Self::Absent | Self::Directory => None,
        }
    }
}

/// Strict ancestors of `path`, shallowest first, as byte prefixes.
pub(crate) fn ancestors(path: &RepoPath) -> impl Iterator<Item = &[u8]> {
    let bytes = path.as_bytes();
    bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .map(move |(index, _)| &bytes[..index])
}

impl ApplyJournal {
    /// Directories the target side requires: every strict ancestor of a
    /// path with a target.
    pub(crate) fn target_dirs(&self) -> BTreeSet<Vec<u8>> {
        let mut dirs = BTreeSet::new();
        for entry in &self.entries {
            if entry.target.is_some() {
                dirs.extend(ancestors(&entry.path).map(<[u8]>::to_vec));
            }
        }
        dirs
    }

    /// Directories the preimage side held: strict ancestors of every path
    /// whose preimage existed, plus preimage directories.
    pub(crate) fn preimage_dirs(&self) -> BTreeSet<Vec<u8>> {
        let mut dirs = BTreeSet::new();
        for entry in &self.entries {
            if entry.preimage != Preimage::Absent {
                dirs.extend(ancestors(&entry.path).map(<[u8]>::to_vec));
            }
            if entry.preimage == Preimage::Directory {
                dirs.insert(entry.path.as_bytes().to_vec());
            }
        }
        dirs
    }

    /// The shape entry `index` must have once the target is complete.
    pub(crate) fn target_shape(&self, index: usize, target_dirs: &BTreeSet<Vec<u8>>) -> Shape {
        let Some(entry) = self.entries.get(index) else {
            return Shape::Absent;
        };
        match &entry.target {
            Some(target) => target.shape(),
            None if target_dirs.contains(entry.path.as_bytes()) => Shape::Dir,
            None => Shape::Absent,
        }
    }

    /// The shape entry `index` had before the first write.
    pub(crate) fn preimage_shape(&self, index: usize) -> Shape {
        self.entries
            .get(index)
            .map_or(Shape::Absent, |entry| entry.preimage.shape())
    }

    /// Every object this journal keeps alive: preimage blobs and target
    /// blobs (gitlink commits name another repository and are excluded).
    /// Retention must treat these as roots while the row exists.
    pub(crate) fn root_oids(&self) -> impl Iterator<Item = Oid> + '_ {
        self.entries.iter().flat_map(|entry| {
            let target = entry
                .target
                .as_ref()
                .filter(|target| target.mode != FileMode::Gitlink)
                .map(|target| target.oid);
            entry.preimage.oid().into_iter().chain(target)
        })
    }

    /// Checks every structural invariant of a decoded or newly built row.
    pub(crate) fn validate(&self, kind: HashKind, workspace: WorkspaceId) -> Result<(), String> {
        if self.version != JOURNAL_VERSION {
            return Err(format!("unknown journal version {}", self.version));
        }
        if self.workspace != workspace {
            return Err("journal names a different workspace than its key".to_owned());
        }
        for pair in self.entries.windows(2) {
            if let [left, right] = pair
                && left.path.as_bytes() >= right.path.as_bytes()
            {
                return Err("journal entries are not strictly ascending".to_owned());
            }
        }
        for entry in &self.entries {
            safety::check_repo_path(&entry.path).map_err(|err| err.message)?;
            if let Some(target) = &entry.target {
                if target.oid.kind() != kind {
                    return Err("target oid has the wrong hash kind".to_owned());
                }
                if (target.mode == FileMode::Symlink) != target.link.is_some() {
                    return Err(
                        "symlink target bytes must be present exactly for symlinks".to_owned()
                    );
                }
            }
            if let Some(oid) = entry.preimage.oid()
                && oid.kind() != kind
            {
                return Err("preimage oid has the wrong hash kind".to_owned());
            }
        }
        for entry in &self.entries {
            if let Transition::Rename { from } = &entry.transition
                && !self
                    .entries
                    .iter()
                    .any(|other| other.path == *from && other.target.is_none())
            {
                return Err("rename source is not a journaled delete".to_owned());
            }
        }
        Ok(())
    }
}

/// Encodes a journal row, enforcing [`MAX_JOURNAL_ROW_BYTES`].
pub(crate) fn encode(journal: &ApplyJournal) -> Result<Vec<u8>, CoreError> {
    let bytes = crate::store::encode("apply journal", journal)?;
    if bytes.len() > MAX_JOURNAL_ROW_BYTES {
        return Err(CoreError::new(
            ErrorCode::ECapacity,
            format!(
                "apply journal of {} bytes exceeds the {MAX_JOURNAL_ROW_BYTES}-byte row limit",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Loads the open journal of `workspace` with its exact row bytes. A row
/// that does not decode or validate is committed corruption and latches
/// quarantine.
pub(crate) fn load(
    store: &Store,
    workspace: WorkspaceId,
) -> Result<Option<(ApplyJournal, Vec<u8>)>, CoreError> {
    let Some(bytes) = store.fact(FactTable::WsApply, &ws_apply_key(workspace))? else {
        return Ok(None);
    };
    let journal: ApplyJournal = store.observe(crate::store::decode("apply journal", &bytes))?;
    if let Err(detail) = journal.validate(store.hash_kind(), workspace) {
        let corrupt = StoreError::Corrupt(format!("apply journal: {detail}"));
        return store.observe(Err(corrupt)).map_err(CoreError::from);
    }
    Ok(Some((journal, bytes)))
}

/// Inserts a new journal row; fails if one is already open.
pub(crate) fn insert_mutation(workspace: WorkspaceId, bytes: Vec<u8>) -> FactMutation {
    FactMutation {
        table: FactTable::WsApply,
        key: ws_apply_key(workspace),
        expected: FactExpectation::Absent,
        value: Some(bytes),
    }
}

/// Replaces the exact observed row.
pub(crate) fn replace_mutation(workspace: WorkspaceId, old: Vec<u8>, new: Vec<u8>) -> FactMutation {
    FactMutation {
        table: FactTable::WsApply,
        key: ws_apply_key(workspace),
        expected: FactExpectation::Value(old),
        value: Some(new),
    }
}

/// Removes the exact observed row: the completing mutation.
pub(crate) fn remove_mutation(workspace: WorkspaceId, old: Vec<u8>) -> FactMutation {
    FactMutation {
        table: FactTable::WsApply,
        key: ws_apply_key(workspace),
        expected: FactExpectation::Value(old),
        value: None,
    }
}
