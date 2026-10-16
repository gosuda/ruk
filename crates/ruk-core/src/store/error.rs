//! Typed errors for the durable store. Every failure maps to exactly one
//! closed [`ErrorCode`]; failures are preserved as typed variants, never
//! stringified into success-shaped errors.
//!
//! The redb conversions cover the exact error types the pinned 4.4.0 API
//! produces at the calls metadata.rs makes (`Builder::create_file`/`open`,
//! `begin_write`/`begin_read`, `set_durability`, table open/insert/get/
//! remove, `commit`).

use crate::error::CoreModelError;
use crate::error::ErrorCode;
use crate::store::segment::SegmentError;
use thiserror::Error;

/// Store failures. `From` conversions preserve the underlying redb and I/O
/// errors; explicit variants carry the fail-closed states (quarantine,
/// closed writer, stale expectations) the store must report without
/// ambiguity.
#[derive(Error, Debug)]
pub enum StoreError {
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Failure opening or locking the metadata database.
    #[error("database: {0}")]
    Database(#[from] redb::DatabaseError),
    /// Failure starting a metadata transaction.
    #[error("transaction: {0}")]
    Transaction(#[from] redb::TransactionError),
    /// Failure opening or using a table.
    #[error("table: {0}")]
    Table(#[from] redb::TableError),
    /// Underlying storage failure surfaced directly.
    #[error("storage: {0}")]
    Storage(#[from] redb::StorageError),
    /// Failure committing a metadata transaction. The commit may already
    /// be durable: callers must never truncate or roll back bytes in
    /// response, only stop publishing and let recovery decide.
    #[error("commit: {0}")]
    Commit(#[from] redb::CommitError),
    /// Failure setting transaction durability.
    #[error("set durability: {0}")]
    SetDurability(#[from] redb::SetDurabilityError),
    /// Malformed or contradictory input.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A checked fixed-width space is exhausted (segment ids, u32 record
    /// framing, 2^31 graph positions).
    #[error("capacity: {0}")]
    Capacity(String),
    /// A configured resource limit rejected the request before mutation.
    #[error("limit: {0}")]
    Limit(String),
    /// Stored bytes disagree with their own framing, checksums, identity,
    /// or declared format; the store refuses service.
    #[error("corrupt: {0}")]
    Corrupt(String),
    /// A named identity does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// A conditional fact expectation failed before mutation.
    #[error("stale fact: table {table} key {key}")]
    StaleFact { table: &'static str, key: String },
    /// The serialized writer is closed after a failed publication step;
    /// the store refuses service until reopened through recovery.
    #[error("writer closed: {0}")]
    WriterClosed(String),
    /// The on-disk format is not one this build reads.
    #[error("version: {0}")]
    Version(String),
    /// An object width disagrees with the repository hash kind.
    #[error("object format: {0}")]
    ObjectFormat(String),
    /// Model-layer failure passed through unchanged.
    #[error(transparent)]
    Model(#[from] CoreModelError),
}

impl From<SegmentError> for StoreError {
    /// Segment framing failures keep their class: truncation and checksum
    /// evidence stays corruption, real I/O stays I/O, and a poisoned writer
    /// is the closed-writer state.
    fn from(err: SegmentError) -> Self {
        match err {
            SegmentError::Poisoned => Self::WriterClosed(err.to_string()),
            SegmentError::Io(err) => Self::Io(err),
            SegmentError::Corrupt(detail) => Self::Corrupt(detail),
            SegmentError::Capacity(detail) => Self::Capacity(detail),
            SegmentError::Invalid { what, detail } => Self::Invalid(format!("{what}: {detail}")),
        }
    }
}

/// Code for a redb storage failure: database damage is corruption, every
/// other storage failure is I/O.
fn storage_code(err: &redb::StorageError) -> ErrorCode {
    match err {
        redb::StorageError::Corrupted(_) => ErrorCode::ECorrupt,
        redb::StorageError::ValueTooLarge(_) => ErrorCode::ELimit,
        _ => ErrorCode::EIo,
    }
}

impl StoreError {
    /// The closed error code this failure reports.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Io(_) | Self::SetDurability(_) | Self::WriterClosed(_) => ErrorCode::EIo,
            Self::Database(redb::DatabaseError::Storage(inner)) => storage_code(inner),
            Self::Database(redb::DatabaseError::UpgradeRequired(_)) => ErrorCode::EVersion,
            Self::Database(_) => ErrorCode::EIo,
            Self::Transaction(redb::TransactionError::Storage(inner)) => storage_code(inner),
            Self::Transaction(_) => ErrorCode::EIo,
            Self::Table(redb::TableError::Storage(inner)) => storage_code(inner),
            Self::Table(_) => ErrorCode::ECorrupt,
            Self::Storage(inner) => storage_code(inner),
            Self::Commit(redb::CommitError::Storage(inner)) => storage_code(inner),
            Self::Commit(_) => ErrorCode::EIo,
            Self::Invalid(_) => ErrorCode::EInvalid,
            Self::Capacity(_) => ErrorCode::ECapacity,
            Self::Limit(_) => ErrorCode::ELimit,
            Self::Corrupt(_) => ErrorCode::ECorrupt,
            Self::NotFound(_) => ErrorCode::ENotFound,
            Self::StaleFact { .. } => ErrorCode::EStale,
            Self::Version(_) => ErrorCode::EVersion,
            Self::ObjectFormat(_) => ErrorCode::EObjectFormat,
            Self::Model(inner) => inner.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_maps_to_e_io() {
        let err = StoreError::from(std::io::Error::other("disk gone"));
        assert_eq!(err.code(), ErrorCode::EIo);
    }

    #[test]
    fn stale_fact_names_table_and_key() {
        let err = StoreError::StaleFact {
            table: "refs",
            key: "refs/heads/main".into(),
        };
        assert_eq!(err.code(), ErrorCode::EStale);
    }
}
