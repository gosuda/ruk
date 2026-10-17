//! Crash-safe store-to-worktree materialization (core contract, "Native
//! working copy and materialization").
//!
//! Invariants:
//! - The `ws_apply` row ([`journal::ApplyJournal`]) is the single authority
//!   for the target, the captured preimage and the transition of every path
//!   a materialization may touch. It is committed before the first worktree
//!   write and removed only by a batch published after the complete side it
//!   converged to was verified on disk.
//! - While the row exists the worktree is a transitional state, never a
//!   snapshot: [`blocks::JournalReader`] reports Applying through
//!   [`crate::workcopy::journal_state::JournalState`], and snapshot, write
//!   and every workspace mutation refuse with `E_WORKSPACE_APPLYING`.
//! - Preimage bytes are blobs published with the row; with the target blobs
//!   they are retention roots ([`journal::ApplyJournal::root_oids`]) until
//!   the row is removed.
//! - Start and finish are fenced by the workspace lease epoch: every journal
//!   publication compare-and-swaps the observed workspace row, and every
//!   physical step re-reads it first.

mod apply;
mod blocks;
mod capture;
mod journal;
mod recover;
mod safety;

#[cfg(test)]
mod tests;

pub(crate) use apply::{
    ApplyOutcome, ApplySession, FinishBatch, MaterializePlan, WorkspaceFence, begin_apply,
    materialize,
};
pub(crate) use blocks::{JournalReader, current_journal, is_applying};
pub(crate) use capture::{ManifestEntry, PlanEntry};
pub(crate) use journal::{
    ApplyJournal, ApplyState, ApplyStep, JournalEntry, Preimage, StepCursor, TargetEntry,
    Transition,
};
pub(crate) use recover::{
    PathReport, RecoveryAction, RecoveryReport, inspect, open_journals, recover,
};
