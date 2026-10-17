//! Typed Store-backed boundary for commits, changes, and history.
//!
//! Provides the typed access and preparation layer for:
//! - Commits ([`crate::store::FactTable::Commits`])
//! - Changes ([`crate::store::FactTable::Changes`])
//! - Imported changes ([`crate::store::FactTable::ImportedChanges`])
//! - Change history ([`crate::store::FactTable::ChangeHistory`])
//!
//! Exposes exact CAS [`crate::store::FactMutation`]s and [`crate::store::PreparedObject`]s
//! for the coordinator's publication lane, and maintains an in-memory pending overlay
//! for multi-step batch operations.

pub mod codec;
pub mod import;
pub mod keys;
pub mod preparer;
pub mod reader;
pub mod types;

#[cfg(test)]
mod tests;

pub use import::ImportBatch;
pub use keys::{
    change_key, decode_change_key, decode_head_key, decode_history_key,
    decode_imported_change_key, head_key, history_key, imported_change_key,
    HEAD_TAG_CONFLICTED, HEAD_TAG_GIT,
};
pub use preparer::RecordBatchPreparer;
pub use reader::Records;
pub use types::{
    ChangeEntry, ChangeHistoryEntry, ChangeState, HistoryPage, ImportedChangeEntry, ImportOutcome,
    PreparedImport, PreparedNativeCommit, PreparedRecordBatch, RecordPage, RecordPageBudget,
};
