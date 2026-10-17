//! Key encodings for records tables in `meta.redb`.
//!
//! Owns key serialization and deserialization for:
//! - [`FactTable::Commits`] keyed by [`Head`]
//! - [`FactTable::Changes`] keyed by [`ChangeId`]
//! - [`FactTable::ImportedChanges`] keyed by [`Oid`]
//! - [`FactTable::ChangeHistory`] keyed by `(ChangeId, Head)`
//!
//! Preserves tagged [`Head`] identity, fixed 32-byte native [`CommitKey`]
//! identity under both SHA-1 and SHA-256 hash kinds, and exact [`ChangeId`]
//! membership identity.

use crate::change::ChangeId;
use crate::error::CoreModelError;
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};

/// Tag byte for Git commit heads in keys.
pub const HEAD_TAG_GIT: u8 = 0;

/// Tag byte for native conflicted commit heads in keys.
pub const HEAD_TAG_CONFLICTED: u8 = 1;

/// Length of a ChangeId key in bytes.
pub const CHANGE_KEY_LEN: usize = ChangeId::LEN;

/// Encodes a [`Head`] into its canonical key bytes for [`crate::store::FactTable::Commits`].
///
/// Layout:
/// - Byte 0: `0` for Git, `1` for Conflicted
/// - Bytes 1..: digest bytes. For Git, 20 or 32 bytes according to hash kind.
///   For Conflicted, the native [`CommitKey`] digest bytes (preserving 32 bytes
///   even in a SHA-1 repository).
#[must_use]
pub fn head_key(head: &Head) -> Vec<u8> {
    match head {
        Head::Git { oid } => {
            let mut key = Vec::with_capacity(1 + oid.as_bytes().len());
            key.push(HEAD_TAG_GIT);
            key.extend_from_slice(oid.as_bytes());
            key
        }
        Head::Conflicted { key } => {
            let mut bytes = Vec::with_capacity(1 + key.as_bytes().len());
            bytes.push(HEAD_TAG_CONFLICTED);
            bytes.extend_from_slice(key.as_bytes());
            bytes
        }
    }
}

/// Decodes a [`Head`] from key bytes.
///
/// # Errors
/// [`CoreModelError::Invalid`] if the key is empty, has an unknown head tag,
/// or has an invalid digest length for an object id or commit key.
pub fn decode_head_key(bytes: &[u8]) -> Result<Head, CoreModelError> {
    if bytes.is_empty() {
        return Err(CoreModelError::Invalid {
            what: "head key",
            detail: "empty head key".to_owned(),
        });
    }
    match bytes[0] {
        HEAD_TAG_GIT => {
            let oid = Oid::from_bytes(&bytes[1..])?;
            Ok(Head::Git { oid })
        }
        HEAD_TAG_CONFLICTED => {
            let key = CommitKey::from_bytes(&bytes[1..])?;
            Ok(Head::Conflicted { key })
        }
        other => Err(CoreModelError::Invalid {
            what: "head key",
            detail: format!("unknown head tag {other}"),
        }),
    }
}

/// Encodes a [`ChangeId`] into its 16-byte raw key for [`crate::store::FactTable::Changes`].
#[must_use]
pub fn change_key(id: &ChangeId) -> [u8; CHANGE_KEY_LEN] {
    *id.as_bytes()
}

/// Decodes a [`ChangeId`] from a 16-byte key.
///
/// # Errors
/// [`CoreModelError::Invalid`] if `bytes` is not exactly 16 bytes.
pub fn decode_change_key(bytes: &[u8]) -> Result<ChangeId, CoreModelError> {
    let raw: [u8; CHANGE_KEY_LEN] =
        bytes
            .try_into()
            .map_err(|_| CoreModelError::Invalid {
                what: "change key",
                detail: format!("expected {CHANGE_KEY_LEN} bytes, found {}", bytes.len()),
            })?;
    Ok(ChangeId::from_bytes(raw))
}

/// Encodes an imported Git [`Oid`] into its raw key for [`crate::store::FactTable::ImportedChanges`].
#[must_use]
pub fn imported_change_key(oid: &Oid) -> Vec<u8> {
    oid.as_bytes().to_vec()
}

/// Decodes an imported Git [`Oid`] from key bytes.
///
/// # Errors
/// [`CoreModelError::Invalid`] if `bytes` length is invalid;
/// [`CoreModelError::ObjectFormat`] if `bytes` length disagrees with `kind`.
pub fn decode_imported_change_key(bytes: &[u8], kind: HashKind) -> Result<Oid, CoreModelError> {
    let oid = Oid::from_bytes(bytes)?;
    oid.expect_kind(kind, "imported change key")?;
    Ok(oid)
}

/// Encodes `(ChangeId, Head)` membership into a contiguous key for [`crate::store::FactTable::ChangeHistory`].
///
/// Layout:
/// - Bytes 0..16: 16-byte raw [`ChangeId`]
/// - Byte 16: `0` for Git, `1` for Conflicted
/// - Bytes 17..: digest bytes of the head
///
/// Because the change ID is a fixed 16-byte prefix, all membership entries for
/// a given change sort together contiguously in lexicographical order.
#[must_use]
pub fn history_key(change_id: &ChangeId, head: &Head) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHANGE_KEY_LEN + 1 + 32);
    key.extend_from_slice(change_id.as_bytes());
    match head {
        Head::Git { oid } => {
            key.push(HEAD_TAG_GIT);
            key.extend_from_slice(oid.as_bytes());
        }
        Head::Conflicted { key: ckey } => {
            key.push(HEAD_TAG_CONFLICTED);
            key.extend_from_slice(ckey.as_bytes());
        }
    }
    key
}

/// Decodes `(ChangeId, Head)` from history key bytes.
///
/// # Errors
/// [`CoreModelError::Invalid`] if the key is shorter than 17 bytes or has an
/// invalid change ID or head encoding.
pub fn decode_history_key(bytes: &[u8]) -> Result<(ChangeId, Head), CoreModelError> {
    if bytes.len() <= CHANGE_KEY_LEN {
        return Err(CoreModelError::Invalid {
            what: "history key",
            detail: format!(
                "history key must be longer than {CHANGE_KEY_LEN} bytes, found {}",
                bytes.len()
            ),
        });
    }
    let change_id = decode_change_key(&bytes[..CHANGE_KEY_LEN])?;
    let head = decode_head_key(&bytes[CHANGE_KEY_LEN..])?;
    Ok((change_id, head))
}
