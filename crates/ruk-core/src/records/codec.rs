//! Postcard codecs and semantic invariant validation for records fact tables.
//!
//! Encodes and decodes values for:
//! - [`FactTable::Commits`] via [`CommitRecord`]
//! - [`FactTable::Changes`] via [`ChangeEntry`]
//! - [`FactTable::ImportedChanges`] via [`ImportedChangeEntry`]
//! - [`FactTable::ChangeHistory`] via [`ChangeHistoryEntry`]
//!
//! All reads validate decoded semantic invariants and call [`Store::observe`]
//! on committed corruption to latch quarantine.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::types::{ChangeEntry, ChangeHistoryEntry, ImportedChangeEntry};
use crate::MAX_CONTROL_FRAME_BYTES;
use crate::change::ChangeId;
use crate::commit::CommitRecord;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::store::{Store, StoreError};

/// Encodes a value with the store's postcard metadata encoder.
fn encode<T: Serialize>(what: &'static str, value: &T) -> Result<Vec<u8>, CoreError> {
    crate::store::encode(what, value).map_err(CoreError::from)
}

/// Decodes a value using the store's postcard decoder, observing any failure
/// through the store to latch quarantine on corrupt bytes.
fn decode<T: DeserializeOwned>(
    store: &Store,
    what: &'static str,
    bytes: &[u8],
) -> Result<T, CoreError> {
    store
        .observe(crate::store::decode(what, bytes))
        .map_err(CoreError::from)
}

/// Reports semantic corruption to the store's observer (latching quarantine)
/// and converts it to a [`CoreError`].
fn corrupt<T>(
    store: &Store,
    what: &'static str,
    detail: impl Into<String>,
) -> Result<T, CoreError> {
    store
        .observe(Err(StoreError::Corrupt(format!(
            "{what}: {}",
            detail.into()
        ))))
        .map_err(CoreError::from)
}

/// Encodes a [`CommitRecord`] for storage in `FactTable::Commits`.
pub fn encode_commit_record(record: &CommitRecord) -> Result<Vec<u8>, CoreError> {
    encode("commit record", record)
}

/// Decodes and semantically validates a [`CommitRecord`] from `FactTable::Commits`.
///
/// Verifies:
/// - Postcard byte decoding and lack of trailing bytes
/// - Hash kind agrees with the store format
/// - Computed record head matches the requested `head` key exactly
/// - Internal commit record structural invariants
///
/// # Errors
/// [`ErrorCode::ECorrupt`] if bytes are malformed or fail semantic verification;
/// latches quarantine on the store.
pub fn decode_commit_record(
    store: &Store,
    head: &Head,
    bytes: &[u8],
) -> Result<CommitRecord, CoreError> {
    let record: CommitRecord = decode(store, "commit record", bytes)?;

    if record.kind() != store.hash_kind() {
        return corrupt(
            store,
            "commit record",
            format!(
                "hash kind mismatch: store is {:?} but record is {:?}",
                store.hash_kind(),
                record.kind()
            ),
        );
    }

    let computed_head = match record.head() {
        Ok(h) => h,
        Err(err) => {
            return corrupt(
                store,
                "commit record",
                format!("failed to compute head identity: {err}"),
            );
        }
    };

    if computed_head != *head {
        return corrupt(
            store,
            "commit record",
            format!("head mismatch: key is {head:?} but record computed {computed_head:?}"),
        );
    }

    Ok(record)
}

/// Encodes a [`ChangeEntry`] for storage in `FactTable::Changes`.
///
/// # Errors
/// [`ErrorCode::ELimit`] if serialized bytes exceed [`MAX_CONTROL_FRAME_BYTES`].
pub fn encode_change_entry(entry: &ChangeEntry) -> Result<Vec<u8>, CoreError> {
    let bytes = encode("change entry", entry)?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!(
                "encoded change entry size {} exceeds limit of {MAX_CONTROL_FRAME_BYTES} bytes",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Decodes and semantically validates a [`ChangeEntry`] from `FactTable::Changes`.
///
/// # Errors
/// [`ErrorCode::ECorrupt`] if bytes are malformed, an `Active` entry has an
/// empty heads list, heads contain duplicates, or heads are incompatible with
/// the store's hash kind. A headless `Abandoned` entry is valid, not corrupt.
/// Latches quarantine on the store.
pub fn decode_change_entry(
    store: &Store,
    change_id: &ChangeId,
    bytes: &[u8],
) -> Result<ChangeEntry, CoreError> {
    let entry: ChangeEntry = decode(store, "change entry", bytes)?;

    if let Err(err) = entry.validate(store.hash_kind()) {
        return corrupt(
            store,
            "change entry",
            format!("semantic validation failed for change {change_id}: {err}"),
        );
    }

    Ok(entry)
}

/// Encodes a [`ChangeId`] for `FactTable::ImportedChanges`.
pub fn encode_imported_change(change_id: ChangeId) -> Result<Vec<u8>, CoreError> {
    encode("imported change", &ImportedChangeEntry { change_id })
}

/// Decodes an imported [`ChangeId`] from `FactTable::ImportedChanges`.
///
/// # Errors
/// [`ErrorCode::ECorrupt`] if bytes are malformed. Latches quarantine on the store.
pub fn decode_imported_change(
    store: &Store,
    _oid: &Oid,
    bytes: &[u8],
) -> Result<ChangeId, CoreError> {
    let entry: ImportedChangeEntry = decode(store, "imported change", bytes)?;
    Ok(entry.change_id)
}

/// Encodes a [`ChangeHistoryEntry`] for `FactTable::ChangeHistory`.
pub fn encode_change_history() -> Result<Vec<u8>, CoreError> {
    encode("change history", &ChangeHistoryEntry)
}

/// Decodes a [`ChangeHistoryEntry`] from `FactTable::ChangeHistory`.
///
/// # Errors
/// [`ErrorCode::ECorrupt`] if bytes are malformed. Latches quarantine on the store.
pub fn decode_change_history(
    store: &Store,
    _change_id: &ChangeId,
    _head: &Head,
    bytes: &[u8],
) -> Result<ChangeHistoryEntry, CoreError> {
    decode(store, "change history", bytes)
}
