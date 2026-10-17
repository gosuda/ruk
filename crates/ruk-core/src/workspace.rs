//! Workspace state: the fixed-kind Native / GitCompat union, its stamp, scope,
//! and the GitCompat `HEAD`.
//!
//! [`WorkspaceState`] is a tagged union (core contract, "Ref and workspace
//! authority"):
//!
//! * `Native`: current change, current [`Head`], [`Scope`], [`WorkspaceStamp`].
//! * `GitCompat`: [`HeadRef`], [`IndexGeneration`], [`Scope`], stamp.
//!
//! The kind is fixed at creation: no method converts one into the other, every
//! transition returns the same variant, and [`WorkspaceState::check_successor`]
//! is the guard a store applies before persisting a replacement. Every
//! transition is a pure function from the current value and the caller's
//! expected stamp to the next value, so a coordinator can run it inside the
//! serialized publication lane and write the result in its one transaction.
//! Nothing here is durable, and nothing here pretends to be a coordinator.
//!
//! Stamps fence in a fixed order: the lease epoch first (an owner that was
//! displaced by `ws.take` learns it lost the lease), then the sequence (the
//! workspace changed under the caller). Both counters are checked and never
//! wrap.
//!
//! Wire forms are externally tagged (`{"native": {..}}`, `{"git_compat":
//! {..}}`) so the same derives serve JSON and postcard.

use std::collections::BTreeSet;
use std::ops::Bound;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::change::ChangeId;
use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::heads::Head;
use crate::ids::{HashKind, Oid};
use crate::index::{IndexGeneration, RepoPath, reject_null_oid};
use crate::refdata::{RefError, RefName, RefRead, ResolvedRef, resolve_from};

// ---------------------------------------------------------------------------
// Kind and stamp
// ---------------------------------------------------------------------------

/// The two workspace kinds. Fixed at creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceKind {
    Native,
    GitCompat,
}

impl WorkspaceKind {
    /// The wire spelling, for messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::GitCompat => "git_compat",
        }
    }
}

/// Why a caller's expected stamp was refused.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampMismatch {
    /// The lease epoch moved: another holder took the workspace.
    #[error("lease epoch is {actual}, caller holds {expected}: the workspace was taken")]
    LeaseLost { expected: u64, actual: u64 },
    /// Same holder, but the workspace changed since the caller read it.
    #[error("sequence is {actual}, caller expected {expected}: the workspace changed")]
    Stale { expected: u64, actual: u64 },
}

impl StampMismatch {
    /// `E_LEASE_LOST` or `E_STALE`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::LeaseLost { .. } => ErrorCode::ELeaseLost,
            Self::Stale { .. } => ErrorCode::EStale,
        }
    }
}

impl From<StampMismatch> for CoreError {
    fn from(err: StampMismatch) -> Self {
        Self::new(err.code(), err.to_string())
    }
}

/// A workspace's compare-and-swap token.
///
/// `sequence` counts committed mutations of this workspace; `lease_epoch`
/// counts ownership takeovers. Unrelated workspaces have unrelated stamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct WorkspaceStamp {
    pub sequence: u64,
    pub lease_epoch: u64,
}

impl WorkspaceStamp {
    /// The stamp of a newly created workspace.
    pub const INITIAL: Self = Self {
        sequence: 0,
        lease_epoch: 0,
    };

    /// The stamp after one more committed mutation.
    ///
    /// # Errors
    /// [`CoreModelError::Capacity`] at `u64::MAX`; the counter never wraps.
    pub fn advance(self) -> Result<Self, CoreModelError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| CoreModelError::Capacity("workspace sequence exhausted".to_owned()))?;
        Ok(Self { sequence, ..self })
    }

    /// The stamp after a takeover (`ws.take`): the epoch moves, the sequence
    /// does not, so a displaced holder's stamp can never match again.
    ///
    /// # Errors
    /// [`CoreModelError::Capacity`] at `u64::MAX`.
    pub fn take(self) -> Result<Self, CoreModelError> {
        let lease_epoch = self.lease_epoch.checked_add(1).ok_or_else(|| {
            CoreModelError::Capacity("workspace lease epoch exhausted".to_owned())
        })?;
        Ok(Self {
            lease_epoch,
            ..self
        })
    }

    /// Checks only ownership: the start and the finish of a materialization
    /// are each fenced by the epoch the journal recorded.
    ///
    /// # Errors
    /// [`StampMismatch::LeaseLost`] when the epoch differs.
    pub fn fence_epoch(self, held: u64) -> Result<(), StampMismatch> {
        if self.lease_epoch == held {
            Ok(())
        } else {
            Err(StampMismatch::LeaseLost {
                expected: held,
                actual: self.lease_epoch,
            })
        }
    }

    /// Checks the caller's `expected` stamp against this (the stored) one.
    /// Ownership first: when both fields differ the answer is `LeaseLost`.
    ///
    /// # Errors
    /// [`StampMismatch::LeaseLost`], then [`StampMismatch::Stale`].
    pub fn fence(self, expected: Self) -> Result<(), StampMismatch> {
        self.fence_epoch(expected.lease_epoch)?;
        if self.sequence == expected.sequence {
            Ok(())
        } else {
            Err(StampMismatch::Stale {
                expected: expected.sequence,
                actual: self.sequence,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// The directories a cone-mode scope lists, canonical: sorted bytewise, no
/// duplicates, and none below another (`a` already covers `a/b`).
///
/// Built through [`Scope::cone`]; deserialization canonicalizes, because a
/// redundant spelling means the same scope. A directory is never the empty
/// path: the root's files are always in scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ConeDirs(BTreeSet<RepoPath>);

fn has_proper_ancestor_in(set: &BTreeSet<RepoPath>, path: &[u8]) -> bool {
    path.iter()
        .enumerate()
        .any(|(index, &byte)| byte == b'/' && set.contains(&path[..index]))
}

impl ConeDirs {
    fn canonical(dirs: impl IntoIterator<Item = RepoPath>) -> Self {
        let all: BTreeSet<RepoPath> = dirs.into_iter().collect();
        let kept = all
            .iter()
            .filter(|dir| !has_proper_ancestor_in(&all, dir.as_bytes()))
            .cloned()
            .collect();
        Self(kept)
    }

    /// The directories in bytewise order.
    pub fn iter(&self) -> impl Iterator<Item = &RepoPath> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether files directly inside `dir` are in scope: `dir` is a cone
    /// directory or below one (everything is in), or `dir` is an ancestor of
    /// a cone directory (its own files are in, its other subdirectories are
    /// not).
    fn visits(&self, dir: &[u8]) -> bool {
        if self.0.contains(dir) || has_proper_ancestor_in(&self.0, dir) {
            return true;
        }
        let mut lower = dir.to_vec();
        lower.push(b'/');
        self.0
            .range::<[u8], _>((Bound::Included(lower.as_slice()), Bound::Unbounded))
            .next()
            .is_some_and(|cone| cone.as_bytes().starts_with(&lower))
    }
}

impl<'de> Deserialize<'de> for ConeDirs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let dirs = Vec::<RepoPath>::deserialize(deserializer)?;
        Ok(Self::canonical(dirs))
    }
}

/// Which part of the tree a workspace materializes. Out-of-scope trees stay
/// in the commit by id.
///
/// Cone semantics follow Git's: the root's files are always in; a listed
/// directory is in recursively; the files directly inside each ancestor of a
/// listed directory are in, its other subdirectories are not.
///
/// A scope change request is simply the new [`Scope`] value (set semantics);
/// the stamp fence on the workspace orders concurrent changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// No sparse checkout: everything is in scope.
    Full,
    /// Cone mode over the listed directories.
    Cone(ConeDirs),
}

impl Scope {
    /// A canonical cone scope. An empty set means the root's files only.
    #[must_use]
    pub fn cone(dirs: impl IntoIterator<Item = RepoPath>) -> Self {
        Self::Cone(ConeDirs::canonical(dirs))
    }

    /// Whether the directory `dir` is descended into: its immediate files are
    /// in scope. A directory that is not visited stays in the commit by tree
    /// id.
    #[must_use]
    pub fn includes_dir(&self, dir: &RepoPath) -> bool {
        match self {
            Self::Full => true,
            Self::Cone(cone) => cone.visits(dir.as_bytes()),
        }
    }

    /// Whether the file or symlink at `path` is in scope.
    #[must_use]
    pub fn includes_file(&self, path: &RepoPath) -> bool {
        match (self, path.parent()) {
            (Self::Full, _) | (Self::Cone(_), None) => true,
            (Self::Cone(cone), Some(dir)) => cone.visits(dir),
        }
    }
}

// ---------------------------------------------------------------------------
// HEAD
// ---------------------------------------------------------------------------

/// A GitCompat `HEAD`: a branch name or a detached commit.
///
/// A symbolic `HEAD` stores only the name. Whether it is born, and what it
/// resolves to, is read from the ref authority on demand ([`Self::resolve`]);
/// caching a second resolved OID beside the name would let the two disagree.
/// An unborn branch is simply a symbolic `HEAD` whose ref does not exist.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HeadRef {
    Symbolic(RefName),
    Detached(Oid),
}

/// What a [`HeadRef`] currently designates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResolvedHead {
    Detached(Oid),
    /// `oid` is `None` for an unborn branch; `terminal` is the ref a commit
    /// would create.
    Symbolic(ResolvedRef),
}

impl HeadRef {
    /// Checks a detached id against the repository hash kind.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for the null id,
    /// [`CoreModelError::ObjectFormat`] for the other width.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        match self {
            Self::Detached(oid) => {
                reject_null_oid(*oid, "detached HEAD")?;
                oid.expect_kind(kind, "detached HEAD")
            }
            Self::Symbolic(_) => Ok(()),
        }
    }

    /// Reads what `HEAD` designates. The `HEAD -> name` link counts toward the
    /// symbolic-chain bound.
    ///
    /// # Errors
    /// [`RefError::Cycle`], [`RefError::TooDeep`], or [`RefError::Read`].
    pub fn resolve<R: RefRead>(&self, refs: &R) -> Result<ResolvedHead, RefError> {
        match self {
            Self::Detached(oid) => Ok(ResolvedHead::Detached(*oid)),
            Self::Symbolic(name) => resolve_from(refs, name, 1).map(ResolvedHead::Symbolic),
        }
    }
}

impl<'de> Deserialize<'de> for HeadRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Raw {
            Symbolic(RefName),
            Detached(Oid),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Symbolic(name) => Ok(Self::Symbolic(name)),
            Raw::Detached(oid) => reject_null_oid(oid, "detached HEAD")
                .map(Self::Detached)
                .map_err(serde::de::Error::custom),
        }
    }
}

// ---------------------------------------------------------------------------
// The two kinds
// ---------------------------------------------------------------------------

/// A Native workspace: the current-change model, no index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NativeWorkspace {
    pub change: ChangeId,
    pub head: Head,
    pub scope: Scope,
    pub stamp: WorkspaceStamp,
}

impl NativeWorkspace {
    /// A new workspace at the initial stamp.
    #[must_use]
    pub fn new(change: ChangeId, head: Head, scope: Scope) -> Self {
        Self {
            change,
            head,
            scope,
            stamp: WorkspaceStamp::INITIAL,
        }
    }

    /// Checks the head against the repository hash kind.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] on a width mismatch.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        self.head.validate(kind)
    }

    /// Selects another current change and head, advancing the stamp once.
    ///
    /// # Errors
    /// `E_LEASE_LOST` / `E_STALE` from the fence; `E_CAPACITY` if the sequence
    /// is exhausted.
    pub fn move_to(
        &self,
        expected: WorkspaceStamp,
        change: ChangeId,
        head: Head,
    ) -> Result<Self, CoreError> {
        self.stamp.fence(expected)?;
        Ok(Self {
            change,
            head,
            scope: self.scope.clone(),
            stamp: self.stamp.advance()?,
        })
    }
}

/// A GitCompat workspace: real `HEAD`, index, and worktree, Git semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GitCompatWorkspace {
    pub head: HeadRef,
    pub index_generation: IndexGeneration,
    pub scope: Scope,
    pub stamp: WorkspaceStamp,
}

impl GitCompatWorkspace {
    /// A new workspace at the initial stamp and index generation.
    #[must_use]
    pub fn new(head: HeadRef, scope: Scope) -> Self {
        Self {
            head,
            index_generation: IndexGeneration(0),
            scope,
            stamp: WorkspaceStamp::INITIAL,
        }
    }

    /// Checks a detached head against the repository hash kind.
    ///
    /// # Errors
    /// See [`HeadRef::validate`].
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        self.head.validate(kind)
    }

    /// Moves `HEAD` without touching the index (`symbolic-ref`, `update-ref`
    /// on the current branch's `HEAD` binding, a detach).
    ///
    /// # Errors
    /// `E_LEASE_LOST` / `E_STALE` from the fence; `E_CAPACITY` if the stamp is
    /// exhausted. Nothing is returned partially applied.
    pub fn move_head(&self, expected: WorkspaceStamp, head: HeadRef) -> Result<Self, CoreError> {
        self.stamp.fence(expected)?;
        self.successor(head, self.index_generation)
    }

    /// Records an index mutation (`add`, `reset`, a conflict recorded or
    /// resolved): the generation bumps with the stamp, in the one transaction
    /// that writes the rows.
    ///
    /// # Errors
    /// As [`Self::move_head`]; also `E_CAPACITY` if the generation is exhausted.
    pub fn mutate_index(&self, expected: WorkspaceStamp) -> Result<Self, CoreError> {
        self.stamp.fence(expected)?;
        self.successor(self.head.clone(), self.index_generation.next()?)
    }

    /// Moves `HEAD` and rewrites the index in one step (`checkout`, `switch`,
    /// `reset --hard`, a merge or rebase step): one stamp tick, one generation
    /// tick.
    ///
    /// # Errors
    /// As [`Self::mutate_index`].
    pub fn checkout(&self, expected: WorkspaceStamp, head: HeadRef) -> Result<Self, CoreError> {
        self.stamp.fence(expected)?;
        self.successor(head, self.index_generation.next()?)
    }

    /// The next value: the stamp advances exactly once however many parts
    /// changed, so one durable transaction is one stamp step.
    fn successor(
        &self,
        head: HeadRef,
        index_generation: IndexGeneration,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            head,
            index_generation,
            scope: self.scope.clone(),
            stamp: self.stamp.advance()?,
        })
    }
}

/// A workspace of one fixed kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Native(NativeWorkspace),
    GitCompat(GitCompatWorkspace),
}

impl WorkspaceState {
    #[must_use]
    pub const fn kind(&self) -> WorkspaceKind {
        match self {
            Self::Native(_) => WorkspaceKind::Native,
            Self::GitCompat(_) => WorkspaceKind::GitCompat,
        }
    }

    #[must_use]
    pub const fn stamp(&self) -> WorkspaceStamp {
        match self {
            Self::Native(state) => state.stamp,
            Self::GitCompat(state) => state.stamp,
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        match self {
            Self::Native(state) => &state.scope,
            Self::GitCompat(state) => &state.scope,
        }
    }

    fn scope_and_stamp_mut(&mut self) -> (&mut Scope, &mut WorkspaceStamp) {
        match self {
            Self::Native(state) => (&mut state.scope, &mut state.stamp),
            Self::GitCompat(state) => (&mut state.scope, &mut state.stamp),
        }
    }

    /// Checks every hash width in the state against the repository kind.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] or [`CoreModelError::Invalid`].
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        match self {
            Self::Native(state) => state.validate(kind),
            Self::GitCompat(state) => state.validate(kind),
        }
    }

    /// The Native state, for a Native-only method.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for a GitCompat workspace: no implicit
    /// conversion exists.
    pub fn require_native(&self) -> Result<&NativeWorkspace, CoreModelError> {
        match self {
            Self::Native(state) => Ok(state),
            Self::GitCompat(_) => Err(wrong_kind(WorkspaceKind::Native, self.kind())),
        }
    }

    /// The GitCompat state, for a Git-compatible worktree method.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for a Native workspace.
    pub fn require_git_compat(&self) -> Result<&GitCompatWorkspace, CoreModelError> {
        match self {
            Self::GitCompat(state) => Ok(state),
            Self::Native(_) => Err(wrong_kind(WorkspaceKind::GitCompat, self.kind())),
        }
    }

    /// `ws.take`: a new holder fences the old one. Unconditional; whether the
    /// caller may take is policy.
    ///
    /// # Errors
    /// [`CoreModelError::Capacity`] when the epoch is exhausted.
    pub fn take(&self) -> Result<Self, CoreModelError> {
        let mut next = self.clone();
        let (_, stamp) = next.scope_and_stamp_mut();
        *stamp = WorkspaceStamp::take(*stamp)?;
        Ok(next)
    }

    /// `ws.scope`: replaces the scope, advancing the stamp once.
    ///
    /// # Errors
    /// `E_LEASE_LOST` / `E_STALE` from the fence; `E_CAPACITY`.
    pub fn rescope(&self, expected: WorkspaceStamp, scope: Scope) -> Result<Self, CoreError> {
        self.stamp().fence(expected)?;
        let mut next = self.clone();
        let (current_scope, stamp) = next.scope_and_stamp_mut();
        *current_scope = scope;
        *stamp = WorkspaceStamp::advance(*stamp)?;
        Ok(next)
    }

    /// The guard a store applies before persisting `next` over `self`: the
    /// kind is fixed at creation; stamps and index generations never move
    /// backward; and any persistent-content change (Native `change`/`head`/
    /// `scope`, GitCompat `head`/`scope`/`index_generation`) requires a
    /// strictly increased `sequence`, even when the lease epoch rises.
    /// Identical replacement and a pure lease takeover (epoch rise, unchanged
    /// sequence, unchanged content) pass.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] naming the violated rule.
    pub fn check_successor(&self, next: &Self) -> Result<(), CoreModelError> {
        let invalid = |detail: String| CoreModelError::Invalid {
            what: "workspace transition",
            detail,
        };
        if self.kind() != next.kind() {
            return Err(invalid(format!(
                "kind is fixed at creation: {} cannot become {}",
                self.kind().as_str(),
                next.kind().as_str()
            )));
        }
        let (old_stamp, new_stamp) = (self.stamp(), next.stamp());
        if new_stamp.lease_epoch < old_stamp.lease_epoch || new_stamp.sequence < old_stamp.sequence
        {
            return Err(invalid(format!(
                "stamp moved backward: (sequence {}, epoch {}) -> (sequence {}, epoch {})",
                old_stamp.sequence,
                old_stamp.lease_epoch,
                new_stamp.sequence,
                new_stamp.lease_epoch
            )));
        }
        if let (Self::GitCompat(old), Self::GitCompat(new)) = (self, next)
            && new.index_generation < old.index_generation
        {
            return Err(invalid(format!(
                "index generation moved backward: {} -> {}",
                old.index_generation.0, new.index_generation.0
            )));
        }
        let content_changed = match (self, next) {
            (Self::Native(old), Self::Native(new)) => {
                old.change != new.change || old.head != new.head || old.scope != new.scope
            }
            (Self::GitCompat(old), Self::GitCompat(new)) => {
                old.head != new.head
                    || old.scope != new.scope
                    || old.index_generation != new.index_generation
            }
            // Kind mismatch already returned above.
            _ => false,
        };
        if content_changed && new_stamp.sequence <= old_stamp.sequence {
            return Err(invalid(format!(
                "workspace content changed without a sequence advance: (sequence {}, epoch {}) -> (sequence {}, epoch {})",
                old_stamp.sequence,
                old_stamp.lease_epoch,
                new_stamp.sequence,
                new_stamp.lease_epoch
            )));
        }
        Ok(())
    }
}

fn wrong_kind(wanted: WorkspaceKind, actual: WorkspaceKind) -> CoreModelError {
    CoreModelError::Invalid {
        what: "workspace kind",
        detail: format!(
            "method needs a {} workspace, this one is {}",
            wanted.as_str(),
            actual.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refdata::{RefChange, RefExpect, RefTarget, RefUpdate};
    use proptest::prelude::*;

    fn oid(n: u8) -> Oid {
        Oid::from_hex(&format!("{:040x}", u16::from(n) + 1)).expect("oid")
    }

    fn git_head(n: u8) -> Head {
        Head::Git { oid: oid(n) }
    }

    fn change() -> ChangeId {
        ChangeId::from_bytes([7; 16])
    }

    fn path(text: &str) -> RepoPath {
        RepoPath::new(text).expect("valid path")
    }

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("valid ref name")
    }

    fn native() -> NativeWorkspace {
        NativeWorkspace::new(change(), git_head(1), Scope::Full)
    }

    fn git_compat() -> GitCompatWorkspace {
        GitCompatWorkspace::new(HeadRef::Symbolic(name("refs/heads/main")), Scope::Full)
    }

    fn stamp(sequence: u64, lease_epoch: u64) -> WorkspaceStamp {
        WorkspaceStamp {
            sequence,
            lease_epoch,
        }
    }

    fn has_hex_run(text: &str, len: usize) -> bool {
        let mut run = 0;
        for byte in text.bytes() {
            if byte.is_ascii_hexdigit() {
                run += 1;
                if run >= len {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    // ---- Stamp -----------------------------------------------------------

    #[test]
    fn advance_counts_and_refuses_to_wrap() {
        assert_eq!(
            WorkspaceStamp::INITIAL.advance().expect("advance"),
            stamp(1, 0)
        );
        assert_eq!(
            stamp(u64::MAX - 1, 3).advance().expect("advance"),
            stamp(u64::MAX, 3)
        );
        let err = stamp(u64::MAX, 3).advance().expect_err("exhausted");
        assert!(matches!(err, CoreModelError::Capacity(_)));
        assert_eq!(err.code(), ErrorCode::ECapacity);
    }

    #[test]
    fn take_moves_only_the_epoch_and_refuses_to_wrap() {
        assert_eq!(stamp(9, 0).take().expect("take"), stamp(9, 1));
        assert!(matches!(
            stamp(9, u64::MAX).take(),
            Err(CoreModelError::Capacity(_))
        ));
    }

    #[test]
    fn fence_checks_the_epoch_before_the_sequence() {
        let stored = stamp(5, 2);
        assert_eq!(stored.fence(stamp(5, 2)), Ok(()));
        assert_eq!(
            stored.fence(stamp(4, 2)),
            Err(StampMismatch::Stale {
                expected: 4,
                actual: 5
            })
        );
        // Both fields differ: the displaced owner is told it lost the lease.
        assert_eq!(
            stored.fence(stamp(4, 1)),
            Err(StampMismatch::LeaseLost {
                expected: 1,
                actual: 2
            })
        );
        // A caller holding a *newer* epoch than stored is just as wrong.
        assert_eq!(
            stored.fence(stamp(5, 3)),
            Err(StampMismatch::LeaseLost {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(stored.fence_epoch(2), Ok(()));
        assert!(stored.fence_epoch(1).is_err());
    }

    #[test]
    fn mismatches_report_the_contract_codes() {
        let lost: CoreError = StampMismatch::LeaseLost {
            expected: 0,
            actual: 1,
        }
        .into();
        let stale: CoreError = StampMismatch::Stale {
            expected: 0,
            actual: 1,
        }
        .into();
        assert_eq!(
            (lost.code, stale.code),
            (ErrorCode::ELeaseLost, ErrorCode::EStale)
        );
        assert_eq!((lost.code.exit_code(), stale.code.exit_code()), (3, 3));
    }

    // ---- Transitions -----------------------------------------------------

    #[test]
    fn a_move_advances_the_stamp_once_and_leaves_the_original_untouched() {
        let before = native();
        let after = before
            .move_to(WorkspaceStamp::INITIAL, change(), git_head(2))
            .expect("move");
        assert_eq!(after.stamp, stamp(1, 0));
        assert_eq!(after.head, git_head(2));
        assert_eq!(before.stamp, WorkspaceStamp::INITIAL);
        assert_eq!(before.head, git_head(1));
    }

    #[test]
    fn a_stale_expected_stamp_is_refused_and_a_displaced_holder_is_fenced() {
        let state = WorkspaceState::Native(native());
        let holder = state.stamp();
        let moved = state
            .require_native()
            .expect("native")
            .move_to(holder, change(), git_head(2))
            .expect("move");
        let stale = moved
            .move_to(holder, change(), git_head(3))
            .expect_err("sequence moved");
        assert_eq!(stale.code, ErrorCode::EStale);

        let taken = WorkspaceState::Native(moved).take().expect("take");
        assert_eq!(taken.stamp(), stamp(1, 1));
        let holder_native = taken.require_native().expect("native");
        // The old holder's stamp differs in both fields: ownership is reported first.
        let lost = holder_native
            .move_to(stamp(0, 0), change(), git_head(3))
            .expect_err("displaced");
        assert_eq!(lost.code, ErrorCode::ELeaseLost);
        // The old epoch with the *current* sequence is fenced too.
        let lost = holder_native
            .move_to(stamp(1, 0), change(), git_head(3))
            .expect_err("old epoch");
        assert_eq!(lost.code, ErrorCode::ELeaseLost);
        let ok = holder_native
            .move_to(taken.stamp(), change(), git_head(3))
            .expect("new holder");
        assert_eq!(ok.stamp, stamp(2, 1));
    }

    #[test]
    fn exhausted_counters_fail_without_a_partial_result() {
        let exhausted = NativeWorkspace {
            stamp: stamp(u64::MAX, 0),
            ..native()
        };
        let err = exhausted
            .move_to(stamp(u64::MAX, 0), change(), git_head(2))
            .expect_err("sequence exhausted");
        assert_eq!(err.code, ErrorCode::ECapacity);

        let full_generation = GitCompatWorkspace {
            index_generation: IndexGeneration(u64::MAX),
            ..git_compat()
        };
        let err = full_generation
            .mutate_index(WorkspaceStamp::INITIAL)
            .expect_err("generation exhausted");
        assert_eq!(err.code, ErrorCode::ECapacity);
        let err = full_generation
            .checkout(WorkspaceStamp::INITIAL, HeadRef::Detached(oid(1)))
            .expect_err("checkout also bumps the generation");
        assert_eq!(err.code, ErrorCode::ECapacity);
        // Without an index mutation the same workspace still moves.
        assert!(
            full_generation
                .move_head(WorkspaceStamp::INITIAL, HeadRef::Detached(oid(1)))
                .is_ok()
        );

        let exhausted_state = WorkspaceState::GitCompat(GitCompatWorkspace {
            stamp: stamp(0, u64::MAX),
            ..git_compat()
        });
        assert!(matches!(
            exhausted_state.take(),
            Err(CoreModelError::Capacity(_))
        ));
    }

    #[test]
    fn git_compat_index_mutation_bumps_generation_and_stamp_together() {
        let base = git_compat();
        let added = base
            .mutate_index(WorkspaceStamp::INITIAL)
            .expect("index mutation");
        assert_eq!(added.index_generation, IndexGeneration(1));
        assert_eq!(added.stamp, stamp(1, 0));
        assert_eq!(added.head, base.head);

        let switched = added
            .move_head(added.stamp, HeadRef::Detached(oid(4)))
            .expect("head move");
        assert_eq!(
            switched.index_generation,
            IndexGeneration(1),
            "no index mutation, no bump"
        );
        assert_eq!(switched.stamp, stamp(2, 0));
        assert_eq!(switched.head, HeadRef::Detached(oid(4)));

        // Checkout moves HEAD and rewrites the index in one step: one stamp tick, one generation tick.
        let both = switched
            .checkout(switched.stamp, HeadRef::Symbolic(name("refs/heads/topic")))
            .expect("checkout");
        assert_eq!(
            (both.stamp, both.index_generation),
            (stamp(3, 0), IndexGeneration(2))
        );

        let stale = added
            .mutate_index(WorkspaceStamp::INITIAL)
            .expect_err("stale");
        assert_eq!(stale.code, ErrorCode::EStale);
        // The fence runs before any counter is touched: a displaced holder with
        // an exhausted generation still learns it lost the lease.
        let exhausted = GitCompatWorkspace {
            index_generation: IndexGeneration(u64::MAX),
            stamp: stamp(0, 1),
            ..git_compat()
        };
        let lost = exhausted
            .mutate_index(stamp(0, 0))
            .expect_err("fenced first");
        assert_eq!(lost.code, ErrorCode::ELeaseLost);
    }

    #[test]
    fn rescope_replaces_the_scope_under_the_fence() {
        let state = WorkspaceState::GitCompat(git_compat());
        let scoped = state
            .rescope(WorkspaceStamp::INITIAL, Scope::cone([path("src")]))
            .expect("rescope");
        assert_eq!(scoped.scope(), &Scope::cone([path("src")]));
        assert_eq!(scoped.stamp(), stamp(1, 0));
        assert_eq!(state.scope(), &Scope::Full, "the original is unchanged");
        let err = scoped
            .rescope(WorkspaceStamp::INITIAL, Scope::Full)
            .expect_err("stale");
        assert_eq!(err.code, ErrorCode::EStale);
        // The kind survives every transition.
        assert_eq!(scoped.kind(), WorkspaceKind::GitCompat);
    }

    // ---- Kind is fixed ---------------------------------------------------

    #[test]
    fn kind_specific_methods_reject_the_other_kind() {
        let native_state = WorkspaceState::Native(native());
        let git_state = WorkspaceState::GitCompat(git_compat());
        assert!(native_state.require_native().is_ok());
        assert!(git_state.require_git_compat().is_ok());
        let err = git_state
            .require_native()
            .expect_err("git_compat is not native");
        assert!(matches!(
            err,
            CoreModelError::Invalid {
                what: "workspace kind",
                ..
            }
        ));
        assert!(native_state.require_git_compat().is_err());
        assert_eq!(native_state.kind(), WorkspaceKind::Native);
        assert_eq!(git_state.kind(), WorkspaceKind::GitCompat);
    }

    #[test]
    fn a_successor_must_keep_the_kind_and_never_move_counters_backward() {
        let old = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(3, 2),
            ..native()
        });
        assert!(old.check_successor(&old).is_ok());
        let forward = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(4, 2),
            ..native()
        });
        assert!(old.check_successor(&forward).is_ok());
        let taken = old.take().expect("take");
        assert!(old.check_successor(&taken).is_ok());

        let flipped = WorkspaceState::GitCompat(git_compat());
        assert!(old.check_successor(&flipped).is_err(), "kind is fixed");
        for backward in [stamp(2, 2), stamp(3, 1), stamp(0, 0)] {
            let next = WorkspaceState::Native(NativeWorkspace {
                stamp: backward,
                ..native()
            });
            assert!(old.check_successor(&next).is_err(), "accepted {backward:?}");
        }

        let git_old = WorkspaceState::GitCompat(GitCompatWorkspace {
            index_generation: IndexGeneration(5),
            ..git_compat()
        });
        let regressed = WorkspaceState::GitCompat(GitCompatWorkspace {
            index_generation: IndexGeneration(4),
            ..git_compat()
        });
        assert!(git_old.check_successor(&regressed).is_err());
        assert!(git_old.check_successor(&git_old).is_ok());
    }

    #[test]
    fn validate_checks_head_widths_in_both_kinds() {
        let sha256 = Oid::from_hex(&format!("{:064x}", 9)).expect("sha256 oid");
        let native_sha1 = WorkspaceState::Native(native());
        assert!(native_sha1.validate(HashKind::Sha1).is_ok());
        assert!(matches!(
            native_sha1.validate(HashKind::Sha256),
            Err(CoreModelError::ObjectFormat(_))
        ));
        let detached = WorkspaceState::GitCompat(GitCompatWorkspace::new(
            HeadRef::Detached(sha256),
            Scope::Full,
        ));
        assert!(detached.validate(HashKind::Sha256).is_ok());
        assert!(matches!(
            detached.validate(HashKind::Sha1),
            Err(CoreModelError::ObjectFormat(_))
        ));
        let symbolic = WorkspaceState::GitCompat(git_compat());
        assert!(
            symbolic.validate(HashKind::Sha256).is_ok(),
            "a name carries no width"
        );
        let null = HeadRef::Detached(HashKind::Sha1.zero_oid());
        assert!(null.validate(HashKind::Sha1).is_err());
    }

    // ---- HEAD ------------------------------------------------------------

    #[test]
    fn symbolic_head_stores_a_name_and_no_oid() {
        let state = WorkspaceState::GitCompat(git_compat());
        let json = sonic_rs::to_string(&state).expect("json");
        assert!(
            json.contains("{\"symbolic\":\"refs/heads/main\"}"),
            "{json}"
        );
        assert!(
            !has_hex_run(&json, 40),
            "a resolved id leaked beside the name: {json}"
        );
        let detached = WorkspaceState::GitCompat(GitCompatWorkspace::new(
            HeadRef::Detached(oid(2)),
            Scope::Full,
        ));
        assert!(has_hex_run(
            &sonic_rs::to_string(&detached).expect("json"),
            40
        ));
    }

    /// A ref store the write path would never produce, to model corruption and
    /// chains that grew after they were written.
    struct Fixed(Vec<(RefName, RefTarget)>);

    impl RefRead for Fixed {
        fn get(&self, wanted: &RefName) -> Result<Option<RefTarget>, CoreError> {
            Ok(self
                .0
                .iter()
                .find(|(stored, _)| stored == wanted)
                .map(|(_, target)| target.clone()))
        }

        fn seek(&self, lower: &[u8]) -> Result<Option<(RefName, RefTarget)>, CoreError> {
            Ok(self
                .0
                .iter()
                .filter(|(stored, _)| stored.as_bytes() >= lower)
                .min_by(|a, b| a.0.cmp(&b.0))
                .cloned())
        }
    }

    #[test]
    fn an_unborn_head_resolves_to_its_branch_name_without_an_oid() {
        let head = HeadRef::Symbolic(name("refs/heads/main"));
        let mut refs = crate::refdata::RefMap::new();
        assert_eq!(
            head.resolve(&refs).expect("resolve"),
            ResolvedHead::Symbolic(ResolvedRef {
                terminal: name("refs/heads/main"),
                oid: None
            })
        );
        let create = RefUpdate {
            name: name("refs/heads/main"),
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(oid(8))),
        };
        refs.apply(HashKind::Sha1, vec![create])
            .expect("first commit creates the branch");
        assert_eq!(
            head.resolve(&refs).expect("resolve"),
            ResolvedHead::Symbolic(ResolvedRef {
                terminal: name("refs/heads/main"),
                oid: Some(oid(8))
            })
        );
        // A detached HEAD ignores the ref namespace entirely.
        assert_eq!(
            HeadRef::Detached(oid(3)).resolve(&refs).expect("resolve"),
            ResolvedHead::Detached(oid(3))
        );
    }

    #[test]
    fn head_resolution_counts_the_head_link_and_ends_at_the_final_branch() {
        let sym = |from: &str, to: &str| (name(from), RefTarget::Symbolic(name(to)));
        let chain = Fixed(vec![
            sym("refs/heads/a", "refs/heads/b"),
            sym("refs/heads/b", "refs/heads/c"),
            sym("refs/heads/c", "refs/heads/d"),
            (name("refs/heads/d"), RefTarget::Direct(oid(6))),
        ]);
        // HEAD->a, a->b, b->c, c->d: four links.
        let head = HeadRef::Symbolic(name("refs/heads/a"));
        assert_eq!(
            head.resolve(&chain).expect("four links"),
            ResolvedHead::Symbolic(ResolvedRef {
                terminal: name("refs/heads/d"),
                oid: Some(oid(6))
            })
        );
        let longer = Fixed(vec![
            sym("refs/heads/a", "refs/heads/b"),
            sym("refs/heads/b", "refs/heads/c"),
            sym("refs/heads/c", "refs/heads/d"),
            sym("refs/heads/d", "refs/heads/e"),
            (name("refs/heads/e"), RefTarget::Direct(oid(6))),
        ]);
        assert!(matches!(
            head.resolve(&longer),
            Err(RefError::TooDeep { .. })
        ));
    }

    #[test]
    fn head_resolution_reports_cycles_and_dangling_chains() {
        let sym = |from: &str, to: &str| (name(from), RefTarget::Symbolic(name(to)));
        let looped = Fixed(vec![
            sym("refs/heads/a", "refs/heads/b"),
            sym("refs/heads/b", "refs/heads/a"),
        ]);
        let head = HeadRef::Symbolic(name("refs/heads/a"));
        assert!(matches!(head.resolve(&looped), Err(RefError::Cycle { .. })));
        let selfish = Fixed(vec![sym("refs/heads/a", "refs/heads/a")]);
        assert!(matches!(
            head.resolve(&selfish),
            Err(RefError::Cycle { .. })
        ));
        let dangling = Fixed(vec![sym("refs/heads/a", "refs/heads/gone")]);
        assert_eq!(
            head.resolve(&dangling).expect("dangling is unborn"),
            ResolvedHead::Symbolic(ResolvedRef {
                terminal: name("refs/heads/gone"),
                oid: None
            })
        );
    }

    #[test]
    fn head_ref_wire_forms_validate() {
        let sym: HeadRef = sonic_rs::from_str("{\"symbolic\":\"refs/heads/x\"}").expect("symbolic");
        assert_eq!(sym, HeadRef::Symbolic(name("refs/heads/x")));
        let det: HeadRef =
            sonic_rs::from_str(&format!("{{\"detached\":\"{:040x}\"}}", 3)).expect("detached");
        assert_eq!(
            det,
            HeadRef::Detached(Oid::from_hex(&format!("{:040x}", 3)).expect("oid"))
        );
        for bad in [
            format!("{{\"detached\":\"{}\"}}", "0".repeat(40)),
            "{\"detached\":\"abc\"}".to_owned(),
            "{\"symbolic\":\"HEAD\"}".to_owned(),
            "{\"symbolic\":\"refs/heads/x\",\"detached\":\"00\"}".to_owned(),
            "{\"unborn\":\"refs/heads/x\"}".to_owned(),
            "{}".to_owned(),
        ] {
            assert!(
                sonic_rs::from_str::<HeadRef>(&bad).is_err(),
                "accepted {bad}"
            );
        }
        for head in [sym, det] {
            let bytes = postcard::to_allocvec(&head).expect("encode");
            assert_eq!(
                postcard::from_bytes::<HeadRef>(&bytes).expect("decode"),
                head
            );
        }
    }

    // ---- Scope -----------------------------------------------------------

    #[test]
    fn cone_dirs_are_canonical() {
        let scope = Scope::cone([
            path("a/b"),
            path("a"),
            path("a/b/c"),
            path("ab"),
            path("a-b/x"),
            path("a"),
        ]);
        let Scope::Cone(cone) = &scope else {
            panic!("cone")
        };
        let listed: Vec<&[u8]> = cone.iter().map(RepoPath::as_bytes).collect();
        // `a` covers `a/b` and `a/b/c`; `ab` and `a-b/x` merely share bytes with `a`.
        assert_eq!(listed, [&b"a"[..], b"a-b/x", b"ab"]);
        assert_eq!(
            Scope::cone([path("b"), path("a")]),
            Scope::cone([path("a"), path("b"), path("a")])
        );
        assert!(matches!(Scope::cone([]), Scope::Cone(c) if c.is_empty()));
    }

    #[test]
    fn cone_membership_follows_git_cone_mode() {
        let scope = Scope::cone([path("a/b"), path("x")]);
        for (file, expected) in [
            ("top.txt", true),
            ("a/own.txt", true),
            ("a/b/f", true),
            ("a/b/deep/er/f", true),
            ("x/f", true),
            ("x/y/f", true),
            ("a/c/f", false),
            ("a/c", true),
            ("ab/f", false),
            ("a-b/f", false),
            ("y/f", false),
            ("xx/f", false),
            ("a/bb/f", false),
        ] {
            assert_eq!(scope.includes_file(&path(file)), expected, "{file}");
        }
        assert!(
            scope.includes_dir(&path("a")),
            "ancestor of a cone dir: its files are in"
        );
        assert!(scope.includes_dir(&path("a/b/c")));
        assert!(
            !scope.includes_dir(&path("a/c")),
            "a sibling subdirectory is not descended"
        );
        assert!(!scope.includes_dir(&path("ab")));
        for file in ["anything", "a/b/c", "z/z/z"] {
            assert!(Scope::Full.includes_file(&path(file)));
        }
        let root_only = Scope::cone([]);
        assert!(root_only.includes_file(&path("top.txt")));
        assert!(!root_only.includes_file(&path("a/f")));
    }

    #[test]
    fn scope_wire_forms_canonicalize_and_reject_bad_paths() {
        assert_eq!(sonic_rs::to_string(&Scope::Full).expect("json"), "\"full\"");
        let cone = Scope::cone([path("b/c"), path("a")]);
        let json = sonic_rs::to_string(&cone).expect("json");
        assert_eq!(json, "{\"cone\":[\"a\",\"b/c\"]}");
        let messy: Scope = sonic_rs::from_str("{\"cone\":[\"b/c/d\",\"b/c\",\"a\",\"a/x\",\"a\"]}")
            .expect("parse");
        assert_eq!(messy, cone);
        for bad in [
            "{\"cone\":[\"\"]}",
            "{\"cone\":[\"../escape\"]}",
            "{\"cone\":[\"a/.git\"]}",
            "{\"cone\":\"a\"}",
            "{\"cone\":null}",
            "{\"sparse\":[]}",
            "\"cone\"",
            "null",
        ] {
            assert!(sonic_rs::from_str::<Scope>(bad).is_err(), "accepted {bad}");
        }
        for scope in [Scope::Full, cone, Scope::cone([])] {
            let bytes = postcard::to_allocvec(&scope).expect("encode");
            assert_eq!(
                postcard::from_bytes::<Scope>(&bytes).expect("decode"),
                scope
            );
        }
    }

    #[test]
    fn non_utf8_scope_directories_round_trip() {
        let scope = Scope::cone([RepoPath::new(&b"d\xff/e"[..]).expect("path")]);
        let json = sonic_rs::to_string(&scope).expect("json");
        assert_eq!(sonic_rs::from_str::<Scope>(&json).expect("parse"), scope);
        assert!(scope.includes_file(&RepoPath::new(&b"d\xff/e/f"[..]).expect("path")));
        assert!(!scope.includes_file(&RepoPath::new(&b"d/e/f"[..]).expect("path")));
    }

    const PARTS: [&str; 4] = ["a", "ab", "b", "a-b"];

    fn join(parts: &[usize]) -> String {
        parts
            .iter()
            .map(|&i| PARTS[i])
            .collect::<Vec<_>>()
            .join("/")
    }

    fn is_prefix(shorter: &[usize], longer: &[usize]) -> bool {
        longer.starts_with(shorter)
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(2048))]

        /// The byte-slice cone implementation agrees with a component-wise
        /// oracle, including on non-canonical input (so canonicalization
        /// preserves meaning) and on names that share bytes without sharing
        /// directories.
        #[test]
        fn prop_cone_membership_matches_a_component_oracle(
            dirs in prop::collection::vec(prop::collection::vec(0_usize..4, 1..4), 0..5),
            file in prop::collection::vec(0_usize..4, 1..5),
        ) {
            let scope = Scope::cone(dirs.iter().map(|parts| path(&join(parts))));
            let parent = &file[..file.len() - 1];
            let expected = parent.is_empty()
                || dirs.iter().any(|dir| is_prefix(dir, parent) || is_prefix(parent, dir));
            prop_assert_eq!(scope.includes_file(&path(&join(&file))), expected);
            if !parent.is_empty() {
                prop_assert_eq!(scope.includes_dir(&path(&join(parent))), expected);
            }
        }
    }

    // ---- State wire forms ------------------------------------------------

    #[test]
    fn states_round_trip_and_name_their_kind() {
        let native_state = WorkspaceState::Native(NativeWorkspace {
            scope: Scope::cone([path("src")]),
            stamp: stamp(12, 3),
            ..native()
        });
        let git_state = WorkspaceState::GitCompat(GitCompatWorkspace {
            index_generation: IndexGeneration(41),
            stamp: stamp(7, 1),
            ..git_compat()
        });
        let native_json = sonic_rs::to_string(&native_state).expect("json");
        let git_json = sonic_rs::to_string(&git_state).expect("json");
        assert!(native_json.starts_with("{\"native\":{"), "{native_json}");
        assert!(git_json.starts_with("{\"git_compat\":{"), "{git_json}");
        for (state, json) in [(native_state, native_json), (git_state, git_json)] {
            assert_eq!(
                sonic_rs::from_str::<WorkspaceState>(&json).expect("parse"),
                state
            );
            let bytes = postcard::to_allocvec(&state).expect("encode");
            assert_eq!(
                postcard::from_bytes::<WorkspaceState>(&bytes).expect("decode"),
                state
            );
        }
    }

    #[test]
    fn malformed_states_are_rejected() {
        let change_text = change().to_reverse_hex();
        let head = format!("{{\"type\":\"git\",\"oid\":\"{:040x}\"}}", 1);
        let native_body = format!(
            "{{\"change\":\"{change_text}\",\"head\":{head},\"scope\":\"full\",\"stamp\":{{\"sequence\":0,\"lease_epoch\":0}}}}"
        );
        let git_body = "{\"head\":{\"symbolic\":\"refs/heads/main\"},\"index_generation\":0,\"scope\":\"full\",\"stamp\":{\"sequence\":0,\"lease_epoch\":0}}";
        assert!(
            sonic_rs::from_str::<WorkspaceState>(&format!("{{\"native\":{native_body}}}")).is_ok()
        );
        assert!(
            sonic_rs::from_str::<WorkspaceState>(&format!("{{\"git_compat\":{git_body}}}")).is_ok()
        );
        let as_native = |body: &str| format!("{{\"native\":{body}}}");
        let bad = [
            // A kind cannot be both, and the bodies are not interchangeable.
            format!("{{\"native\":{native_body},\"git_compat\":{git_body}}}"),
            as_native(git_body),
            format!("{{\"git_compat\":{native_body}}}"),
            format!("{{\"hybrid\":{native_body}}}"),
            "{}".to_owned(),
            // Missing or malformed stamp fields.
            as_native(&native_body.replace(
                "\"stamp\":{\"sequence\":0,\"lease_epoch\":0}",
                "\"stamp\":{\"sequence\":0}",
            )),
            as_native(&native_body.replace("\"sequence\":0", "\"sequence\":-1")),
            as_native(
                &native_body.replace("\"lease_epoch\":0", "\"lease_epoch\":18446744073709551616"),
            ),
            as_native(&native_body.replace("\"sequence\":0", "\"sequence\":\"0\"")),
            // Invalid embedded values.
            as_native(&native_body.replace("\"scope\":\"full\"", "\"scope\":{\"cone\":[\"..\"]}")),
            as_native(&native_body.replace("\"type\":\"git\"", "\"type\":\"tree\"")),
        ];
        for text in bad {
            assert!(
                sonic_rs::from_str::<WorkspaceState>(&text).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn counters_serialize_at_full_width() {
        let state = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(u64::MAX, u64::MAX - 1),
            ..native()
        });
        let json = sonic_rs::to_string(&state).expect("json");
        assert!(
            json.contains("18446744073709551615") && json.contains("18446744073709551614"),
            "{json}"
        );
        assert_eq!(
            sonic_rs::from_str::<WorkspaceState>(&json).expect("parse"),
            state
        );
        let bytes = postcard::to_allocvec(&state).expect("encode");
        assert_eq!(
            postcard::from_bytes::<WorkspaceState>(&bytes).expect("decode"),
            state
        );
    }

    // ---- Successor stamp guard (regression) -------------------------------
    // `check_successor` is the store replacement guard: persistent content may
    // only change when `sequence` advances. An epoch rise fences the old
    // holder but never excuses an unchanged-sequence content change. These
    // cases fail against the counters-only guard.

    #[test]
    fn check_successor_rejects_native_head_without_sequence_advance() {
        let old = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(old.stamp(), stamp(3, 2));
        let changed = WorkspaceState::Native(NativeWorkspace {
            head: git_head(2),
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(changed.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&changed)
            .expect_err("changed native head with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        // A lease-epoch rise fences the old holder; it does not bless the write.
        let changed_takeover = WorkspaceState::Native(NativeWorkspace {
            head: git_head(2),
            stamp: stamp(3, 3),
            ..native()
        });
        assert_eq!(changed_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&changed_takeover).expect_err(
            "changed native head with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_rejects_native_change_without_sequence_advance() {
        let old = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(old.stamp(), stamp(3, 2));
        let other = ChangeId::from_bytes([9; 16]);
        assert_ne!(old.require_native().expect("native").change, other);
        let changed = WorkspaceState::Native(NativeWorkspace {
            change: other,
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(changed.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&changed)
            .expect_err("changed native change with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        let changed_takeover = WorkspaceState::Native(NativeWorkspace {
            change: other,
            stamp: stamp(3, 3),
            ..native()
        });
        assert_eq!(changed_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&changed_takeover).expect_err(
            "changed native change with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_rejects_native_scope_without_sequence_advance() {
        let old = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(old.scope(), &Scope::Full);
        let changed = WorkspaceState::Native(NativeWorkspace {
            scope: Scope::cone([path("src")]),
            stamp: stamp(3, 2),
            ..native()
        });
        assert_eq!(changed.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&changed)
            .expect_err("changed native scope with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        let changed_takeover = WorkspaceState::Native(NativeWorkspace {
            scope: Scope::cone([path("src")]),
            stamp: stamp(3, 3),
            ..native()
        });
        assert_eq!(changed_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&changed_takeover).expect_err(
            "changed native scope with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_rejects_gitcompat_head_without_sequence_advance() {
        let old = WorkspaceState::GitCompat(GitCompatWorkspace {
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(old.stamp(), stamp(3, 2));
        let renamed = WorkspaceState::GitCompat(GitCompatWorkspace {
            head: HeadRef::Symbolic(name("refs/heads/topic")),
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(renamed.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&renamed)
            .expect_err("changed git_compat head with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        let renamed_takeover = WorkspaceState::GitCompat(GitCompatWorkspace {
            head: HeadRef::Symbolic(name("refs/heads/topic")),
            stamp: stamp(3, 3),
            ..git_compat()
        });
        assert_eq!(renamed_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&renamed_takeover).expect_err(
            "changed git_compat head with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        // Symbolic -> detached is the same persistent-head change.
        let detached = WorkspaceState::GitCompat(GitCompatWorkspace {
            head: HeadRef::Detached(oid(4)),
            stamp: stamp(3, 2),
            ..git_compat()
        });
        let err = old
            .check_successor(&detached)
            .expect_err("detached git_compat head with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_rejects_gitcompat_scope_without_sequence_advance() {
        let old = WorkspaceState::GitCompat(GitCompatWorkspace {
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(old.scope(), &Scope::Full);
        let changed = WorkspaceState::GitCompat(GitCompatWorkspace {
            scope: Scope::cone([path("src")]),
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(changed.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&changed)
            .expect_err("changed git_compat scope with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        let changed_takeover = WorkspaceState::GitCompat(GitCompatWorkspace {
            scope: Scope::cone([path("src")]),
            stamp: stamp(3, 3),
            ..git_compat()
        });
        assert_eq!(changed_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&changed_takeover).expect_err(
            "changed git_compat scope with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_rejects_gitcompat_generation_without_sequence_advance() {
        let old = WorkspaceState::GitCompat(GitCompatWorkspace {
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(
            old.require_git_compat()
                .expect("git_compat")
                .index_generation,
            IndexGeneration(0)
        );
        // A forward index generation still needs a sequence step: rows and the
        // generation publish atomically.
        let bumped = WorkspaceState::GitCompat(GitCompatWorkspace {
            index_generation: IndexGeneration(1),
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert_eq!(bumped.stamp(), stamp(3, 2));
        let err = old
            .check_successor(&bumped)
            .expect_err("changed index generation with unchanged sequence must be rejected");
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
        let bumped_takeover = WorkspaceState::GitCompat(GitCompatWorkspace {
            index_generation: IndexGeneration(1),
            stamp: stamp(3, 3),
            ..git_compat()
        });
        assert_eq!(bumped_takeover.stamp(), stamp(3, 3));
        let err = old.check_successor(&bumped_takeover).expect_err(
            "changed index generation with unchanged sequence must be rejected even when the epoch rises",
        );
        assert!(
            matches!(
                err,
                CoreModelError::Invalid {
                    what: "workspace transition",
                    ..
                }
            ),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn check_successor_allows_identical_and_pure_takeover() {
        let native_old = WorkspaceState::Native(NativeWorkspace {
            stamp: stamp(3, 2),
            ..native()
        });
        assert!(native_old.check_successor(&native_old).is_ok());
        let native_taken = native_old.take().expect("take");
        assert_eq!(native_taken.stamp(), stamp(3, 3));
        assert!(native_old.check_successor(&native_taken).is_ok());
        // Changed content with a sequence step is the legitimate write path.
        let native_advanced = WorkspaceState::Native(NativeWorkspace {
            head: git_head(2),
            stamp: stamp(4, 2),
            ..native()
        });
        assert_eq!(native_advanced.stamp(), stamp(4, 2));
        assert!(native_old.check_successor(&native_advanced).is_ok());

        let git_old = WorkspaceState::GitCompat(GitCompatWorkspace {
            stamp: stamp(3, 2),
            ..git_compat()
        });
        assert!(git_old.check_successor(&git_old).is_ok());
        let git_taken = git_old.take().expect("take");
        assert_eq!(git_taken.stamp(), stamp(3, 3));
        assert!(git_old.check_successor(&git_taken).is_ok());
        let git_advanced = WorkspaceState::GitCompat(GitCompatWorkspace {
            head: HeadRef::Symbolic(name("refs/heads/topic")),
            index_generation: IndexGeneration(1),
            stamp: stamp(4, 2),
            ..git_compat()
        });
        assert_eq!(git_advanced.stamp(), stamp(4, 2));
        assert!(git_old.check_successor(&git_advanced).is_ok());
    }
}
