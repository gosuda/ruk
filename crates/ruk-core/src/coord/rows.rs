//! Coordinator row census, key layouts, typed rows, and codecs.
//!
//! This module is the single owner of coordinator row key encodings, internal
//! row structures, and postcard codecs for metadata tables owned by the
//! coordinator ([`FactTable::Receipts`], [`FactTable::Sessions`],
//! [`FactTable::Workspaces`], [`FactTable::OpHead`], and [`FactTable::Ops`]).
//!
//! All durable row formats declared here are v1. Public protocol schemas and
//! public [`WorkspaceState`] do not expose coordinator-internal fields (such as
//! workspace session holders or retention accounting cursors).
//!
//! # Keys
//! - `op_head`: [`OP_HEAD_KEY`] (`b""`, single singleton row).
//! - `sessions`: [`session_key`] (16 raw UUID bytes).
//! - `receipts`: [`receipt_key`] (32 bytes: session UUID ‖ request UUID).
//! - `workspaces`: [`workspace_key`] (16 raw UUID bytes).
//! - `ops`: [`op_key`] (16 bytes: `OperationId` big-endian u64 ‖ part big-endian u64; part 0 = header).
//!
//! # Codecs and Quarantine
//! All encoding and decoding reuses the store's postcard metadata codecs
//! ([`crate::store::encode`] and [`crate::store::decode`]). Trailing bytes are
//! rejected by the underlying codec as corruption. Committed decoding failures
//! and semantic invariant violations are reported to [`Store::observe`], which
//! latches the store's quarantine state.

use core::fmt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::bytes::ByteString;
use crate::capability::Capabilities;
use crate::change::{OperationId, RequestId, SessionId, WorkspaceId};
use crate::commit::ProvenanceClaims;
use crate::coord::policy::Principal;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    IdentityClaim, Method, OperationEntry, ReceiptRef, Reply, SessionAuthority, Timestamp, Validate,
};
use crate::store::types::FactTable;
use crate::store::{Store, StoreError};
use crate::workspace::WorkspaceState;

// ---------------------------------------------------------------------------
// Constants and Key Layouts
// ---------------------------------------------------------------------------

/// The single key for [`FactTable::OpHead`].
pub(crate) const OP_HEAD_KEY: &[u8] = b"";

/// The maximum allowed byte length for any coordinator row, bounded by the
/// control frame limit.
pub(crate) const ROW_MAX_BYTES: u64 = MAX_CONTROL_FRAME_BYTES as u64;

/// Seven days retention horizon for mutation receipts and expired sessions.
pub(crate) const RECEIPT_HORIZON: jiff::SignedDuration = jiff::SignedDuration::from_hours(168);

/// 16-byte raw UUID key for [`FactTable::Sessions`].
#[must_use]
pub(crate) fn session_key(id: SessionId) -> [u8; 16] {
    *id.as_bytes()
}

/// 32-byte key for [`FactTable::Receipts`]: session UUID (16 bytes) followed by
/// request UUID (16 bytes).
#[must_use]
pub(crate) fn receipt_key(s: SessionId, r: RequestId) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(s.as_bytes());
    key[16..].copy_from_slice(r.as_bytes());
    key
}

/// 16-byte raw UUID key for [`FactTable::Workspaces`].
#[must_use]
pub(crate) fn workspace_key(id: WorkspaceId) -> [u8; 16] {
    *id.as_bytes()
}

/// 16-byte key for [`FactTable::Ops`]: 8-byte big-endian operation id followed
/// by 8-byte big-endian part number. Part 0 is [`OpHeader`]; parts 1..=N are
/// raw byte fragments of the operation stream.
#[must_use]
pub(crate) fn op_key(id: OperationId, part: u64) -> [u8; 16] {
    let mut key = [0_u8; 16];
    key[..8].copy_from_slice(&id.0.to_be_bytes());
    key[8..].copy_from_slice(&part.to_be_bytes());
    key
}

// ---------------------------------------------------------------------------
// Core Codecs
// ---------------------------------------------------------------------------

/// Encodes a coordinator row using the store's postcard metadata encoder.
///
/// # Errors
/// [`CoreError`] with code [`ErrorCode::EInvalid`] if serialization fails.
pub(crate) fn encode<T: Serialize>(what: &'static str, v: &T) -> Result<Vec<u8>, CoreError> {
    crate::store::encode(what, v).map_err(CoreError::from)
}

/// Decodes a coordinator row using the store's postcard metadata decoder.
///
/// Any decode failure (malformed bytes, trailing bytes, or truncation) is
/// observed by the store, latching quarantine on committed corruption.
///
/// # Errors
/// [`CoreError`] with code [`ErrorCode::ECorrupt`] on malformed data.
pub(crate) fn decode<T: DeserializeOwned>(
    store: &Store,
    what: &'static str,
    b: &[u8],
) -> Result<T, CoreError> {
    store
        .observe(crate::store::decode(what, b))
        .map_err(CoreError::from)
}

/// Reports semantic corruption to the store's observer (latching quarantine)
/// and converts it to [`CoreError`].
pub(crate) fn corrupt<T>(
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

// ---------------------------------------------------------------------------
// Session Row
// ---------------------------------------------------------------------------

/// Stored row for [`FactTable::Sessions`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRow {
    pub(crate) principal: Principal,
    pub(crate) identity: Option<IdentityClaim>,
    pub(crate) claims: ProvenanceClaims,
    pub(crate) capabilities: Capabilities,
    pub(crate) secret_hash: [u8; 32],
    pub(crate) authority: SessionAuthority,
}

impl fmt::Debug for SessionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRow")
            .field("principal", &self.principal)
            .field("identity", &self.identity)
            .field("claims", &self.claims)
            .field("capabilities", &self.capabilities)
            .field("secret_hash", &"<redacted>")
            .field("authority", &self.authority)
            .finish()
    }
}

impl SessionRow {
    /// Checks that immutable fields remain identical and that authority
    /// transitions satisfy the lifecycle invariants:
    /// - `principal`, `identity`, `claims`, `capabilities`, `secret_hash` are immutable.
    /// - Active expiry can only rise (`b >= a`).
    /// - Active can transition to `ReceiptsOnly` with exactly `expiry + 7 d`.
    /// - `ReceiptsOnly` never regains `Active`.
    /// - `ReceiptsOnly` horizon cannot change.
    ///
    /// # Errors
    /// `E_INVALID` on any violation.
    pub(crate) fn check_successor(&self, next: &Self) -> Result<(), CoreError> {
        if self.principal != next.principal {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "session principal is immutable",
            ));
        }
        if self.identity != next.identity {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "session identity is immutable",
            ));
        }
        if self.claims != next.claims {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "session claims are immutable",
            ));
        }
        if self.capabilities != next.capabilities {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "session capabilities are immutable",
            ));
        }
        if self.secret_hash != next.secret_hash {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "session secret_hash is immutable",
            ));
        }
        match (self.authority, next.authority) {
            (
                SessionAuthority::Active { idle_expires_at: a },
                SessionAuthority::Active { idle_expires_at: b },
            ) => {
                if b < a {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        format!("session active expiry cannot decrease: {a} -> {b}"),
                    ));
                }
                Ok(())
            }
            (
                SessionAuthority::Active { idle_expires_at: a },
                SessionAuthority::ReceiptsOnly { receipts_until: r },
            ) => {
                let expected = a
                    .instant()
                    .checked_add(RECEIPT_HORIZON)
                    .map(Timestamp::new)
                    .map_err(|err| {
                        CoreError::new(
                            ErrorCode::EInvalid,
                            format!("receipts_until timestamp arithmetic overflow: {err}"),
                        )
                    })?;
                if r != expected {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        format!(
                            "transition to receipts_only requires exactly expiry + 7d ({expected}), got {r}"
                        ),
                    ));
                }
                Ok(())
            }
            (
                SessionAuthority::ReceiptsOnly { receipts_until: a },
                SessionAuthority::ReceiptsOnly { receipts_until: b },
            ) => {
                if a != b {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        format!("receipts_only horizon cannot change: {a} -> {b}"),
                    ));
                }
                Ok(())
            }
            (SessionAuthority::ReceiptsOnly { .. }, SessionAuthority::Active { .. }) => {
                Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "session in receipts_only cannot regain active authority",
                ))
            }
        }
    }
}

/// Decodes and semantically validates a session row from committed bytes.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine if bytes are invalid or fail semantic validation.
pub(crate) fn decode_session(
    store: &Store,
    _key: &[u8; 16],
    b: &[u8],
) -> Result<SessionRow, CoreError> {
    let row: SessionRow = decode(store, "session row", b)?;
    if let Some(identity) = &row.identity
        && let Err(err) = identity.validate()
    {
        return corrupt(
            store,
            "session row",
            format!("invalid identity claim: {err}"),
        );
    }
    Ok(row)
}

// ---------------------------------------------------------------------------
// Receipt Row
// ---------------------------------------------------------------------------

/// Stored row for [`FactTable::Receipts`]. Transparently wraps a mutation [`Reply`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ReceiptRow(Reply);

impl ReceiptRow {
    /// Wraps a completed mutation reply into a durable receipt record.
    ///
    /// # Errors
    /// `E_INVALID` unless `reply.method().is_mutation()`, the receipt's
    /// session and request_id match `s` and `r`, and `replayed == false`.
    pub(crate) fn new(s: SessionId, r: RequestId, reply: Reply) -> Result<Self, CoreError> {
        if !reply.method().is_mutation() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "method `{}` is not a mutation; only mutations may be stored as receipts",
                    reply.method().as_str()
                ),
            ));
        }
        let Some(outcome) = reply.outcome() else {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "mutation reply is missing an outcome",
            ));
        };
        if outcome.receipt.session != s {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "receipt session mismatch: expected {s}, got {}",
                    outcome.receipt.session
                ),
            ));
        }
        if outcome.receipt.request_id != r {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "receipt request_id mismatch: expected {r}, got {}",
                    outcome.receipt.request_id
                ),
            ));
        }
        if outcome.receipt.replayed {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "cannot store a receipt with replayed == true",
            ));
        }
        Ok(Self(reply))
    }

    /// The durable receipt reference stored within the mutation reply.
    #[must_use]
    pub(crate) fn receipt(&self) -> &ReceiptRef {
        &self
            .0
            .outcome()
            .expect("ReceiptRow always wraps a mutation Reply")
            .receipt
    }

    /// Read-only access to the wrapped reply.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn reply(&self) -> &Reply {
        &self.0
    }

    /// Unwraps the replay reply, setting `replayed = true` and changing nothing else.
    #[must_use]
    pub(crate) fn into_replay(mut self) -> Reply {
        if let Some(outcome) = self.0.outcome_mut() {
            outcome.receipt.replayed = true;
        }
        self.0
    }
}

/// Decodes and semantically validates a receipt row from committed bytes.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine on byte corruption, key mismatch,
/// non-mutation method, or `replayed == true`.
pub(crate) fn decode_receipt(
    store: &Store,
    key: &[u8; 32],
    b: &[u8],
) -> Result<ReceiptRow, CoreError> {
    let reply: Reply = decode(store, "receipt row", b)?;
    let mut s_bytes = [0_u8; 16];
    s_bytes.copy_from_slice(&key[..16]);
    let s = SessionId::from_bytes(s_bytes);

    let mut r_bytes = [0_u8; 16];
    r_bytes.copy_from_slice(&key[16..]);
    let r = RequestId::from_bytes(r_bytes);

    if !reply.method().is_mutation() {
        return corrupt(
            store,
            "receipt row",
            format!(
                "stored reply for method `{}` is not a mutation",
                reply.method().as_str()
            ),
        );
    }
    let Some(outcome) = reply.outcome() else {
        return corrupt(store, "receipt row", "mutation reply missing outcome");
    };
    if outcome.receipt.session != s {
        return corrupt(
            store,
            "receipt row",
            format!(
                "receipt session mismatch with key: expected {s}, got {}",
                outcome.receipt.session
            ),
        );
    }
    if outcome.receipt.request_id != r {
        return corrupt(
            store,
            "receipt row",
            format!(
                "receipt request mismatch with key: expected {r}, got {}",
                outcome.receipt.request_id
            ),
        );
    }
    if outcome.receipt.replayed {
        return corrupt(store, "receipt row", "stored receipt has replayed == true");
    }
    Ok(ReceiptRow(reply))
}

// ---------------------------------------------------------------------------
// Workspace Row
// ---------------------------------------------------------------------------

/// Stored row for [`FactTable::Workspaces`].
///
/// `root` is the host directory the workspace materializes into, written by
/// `ws.new` from its wire args. Rows committed before the root field decode
/// through [`LegacyWorkspaceRow`] in [`decode_workspace`] and upgrade with an
/// empty root; postcard is positional, so a `#[serde(default)]` alone would
/// read those shorter rows as truncation and latch quarantine instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkspaceRow {
    pub(crate) state: WorkspaceState,
    pub(crate) holder: SessionId,
    pub(crate) root: ByteString,
}

/// Pre-root workspace row: `{state, holder}` only. Decoding only; new rows
/// always carry a root. Any postcard truncation of the current shape retries
/// as this shape before quarantine latches (see [`decode_workspace`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyWorkspaceRow {
    state: WorkspaceState,
    holder: SessionId,
}

impl WorkspaceRow {
    /// Validates the transition to `next`: delegates to
    /// [`WorkspaceState::check_successor`], enforces that the holder changes
    /// only when `lease_epoch` strictly increases, and pins the root: it is
    /// fixed at creation like the workspace kind, so a row write can never
    /// retarget another workspace's host directory.
    ///
    /// # Errors
    /// `E_INVALID` on any transition or fencing rule violation.
    pub(crate) fn check_successor(&self, next: &Self) -> Result<(), CoreError> {
        self.state
            .check_successor(&next.state)
            .map_err(CoreError::from)?;
        let old_epoch = self.state.stamp().lease_epoch;
        let new_epoch = next.state.stamp().lease_epoch;
        if self.holder != next.holder && new_epoch <= old_epoch {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "workspace holder changed from {} to {} without a lease epoch increase (epoch: {old_epoch} -> {new_epoch})",
                    self.holder, next.holder
                ),
            ));
        }
        if self.root != next.root {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "workspace root is fixed at creation and cannot be retargeted",
            ));
        }
        Ok(())
    }
}

/// Decodes and validates a workspace row from committed bytes.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine if bytes are invalid or workspace state fails format validation.
pub(crate) fn decode_workspace(
    store: &Store,
    _key: &[u8; 16],
    b: &[u8],
) -> Result<WorkspaceRow, CoreError> {
    // Decode the current shape without observing first: a pre-root row is
    // shorter, postcard reports truncation, and observing that expected
    // version skew would latch quarantine on a healthy store. Only the
    // legacy retry observes, so genuinely corrupt bytes still latch.
    let row: WorkspaceRow = match crate::store::decode("workspace row", b) {
        Ok(row) => row,
        Err(_) => {
            let legacy: LegacyWorkspaceRow = decode(store, "workspace row", b)?;
            WorkspaceRow {
                state: legacy.state,
                holder: legacy.holder,
                root: ByteString::from(""),
            }
        }
    };
    if let Err(err) = row.state.validate(store.hash_kind()) {
        return corrupt(
            store,
            "workspace row",
            format!("invalid workspace state: {err}"),
        );
    }
    Ok(row)
}

// ---------------------------------------------------------------------------
// Coordinator Head and Retention Accounting
// ---------------------------------------------------------------------------

/// Usage accounting for one coordinator-managed fact table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct Usage {
    pub(crate) rows: u64,
    pub(crate) stored_bytes: u64,
}

/// Logical retention ledger tracking rows and stored bytes across coordinator tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct Retained {
    pub(crate) receipts: Usage,
    pub(crate) sessions: Usage,
    pub(crate) ops: Usage,
}

/// Sweep progress cursors for periodic piggyback garbage collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct SweepCursors {
    pub(crate) receipts: Option<[u8; 32]>,
    pub(crate) sessions: Option<[u8; 16]>,
}

/// Stored singleton row for [`FactTable::OpHead`].
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct CoordinatorHead {
    pub(crate) last_op: Option<OperationId>,
    pub(crate) retained: Retained,
    pub(crate) sweep: SweepCursors,
}

/// Decodes and semantically validates the coordinator head row from committed bytes.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine on byte corruption or ledger contradiction.
pub(crate) fn decode_head(store: &Store, b: &[u8]) -> Result<CoordinatorHead, CoreError> {
    let head: CoordinatorHead = decode(store, "coordinator head", b)?;
    validate_usage(store, "receipts", &head.retained.receipts, 32)?;
    validate_usage(store, "sessions", &head.retained.sessions, 16)?;
    validate_usage(store, "ops", &head.retained.ops, 12)?;
    Ok(head)
}

fn validate_usage(
    store: &Store,
    what: &'static str,
    usage: &Usage,
    min_key_len: u64,
) -> Result<(), CoreError> {
    if usage.rows == 0 && usage.stored_bytes != 0 {
        return corrupt(
            store,
            "coordinator head",
            format!(
                "{what} usage has 0 rows but {} stored bytes",
                usage.stored_bytes
            ),
        );
    }
    if usage.rows > 0 && usage.stored_bytes < usage.rows.saturating_mul(min_key_len) {
        return corrupt(
            store,
            "coordinator head",
            format!(
                "{what} usage stored bytes ({}) is less than minimum key length times row count ({} * {min_key_len})",
                usage.stored_bytes, usage.rows
            ),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operation Header and Deltas
// ---------------------------------------------------------------------------

/// Maximum payload byte length of a single operation stream fragment (4 MiB).
pub(crate) const OP_FRAGMENT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on table name length in the FactTable census.
pub(crate) const MAX_TABLE_NAME_LEN: usize = 64;

/// Postcard framing overhead allowance for an OpDelta (discriminants and varint lengths).
pub(crate) const OP_DELTA_FRAMING_OVERHEAD: usize = 256;

/// Table-independent maximum encoded delta length.
/// Derived from two (key, value) pairs bounded by ROW_MAX_BYTES (32 MiB),
/// the finite table-name census, and postcard framing overhead.
pub(crate) const MAX_ENCODED_DELTA_BYTES: u64 =
    (2 * ROW_MAX_BYTES) + MAX_TABLE_NAME_LEN as u64 + OP_DELTA_FRAMING_OVERHEAD as u64;

/// Part 0 stored row for an operation in [`FactTable::Ops`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpHeader {
    pub(crate) entry: OperationEntry,
    pub(crate) deltas: u64,
    pub(crate) stream_bytes: u64,
    pub(crate) parts: u64,
}

/// Pre-provenance operation entry: the [`OperationEntry`] shape before the
/// trailing `on_behalf_of` field. Decode-only, for stores written before
/// provenance existed.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct OperationEntryV0 {
    id: OperationId,
    parent: Option<OperationId>,
    session: Option<SessionId>,
    method: Method,
    committed_at: Timestamp,
    undoes: Option<OperationId>,
}

/// Pre-provenance operation header: the [`OpHeader`] shape before the
/// trailing entry field. Decode-only, for stores written before provenance
/// existed.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct OpHeaderV0 {
    entry: OperationEntryV0,
    deltas: u64,
    stream_bytes: u64,
    parts: u64,
}

/// Validates one decoded operation header row.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine on operation ID mismatch,
/// non-positive delta count, non-positive stream size, or invalid parts count.
fn validate_op_header(store: &Store, id: OperationId, header: &OpHeader) -> Result<(), CoreError> {
    if header.entry.id != id {
        return corrupt(
            store,
            "op header",
            format!(
                "operation id mismatch: expected {}, got {}",
                id.0, header.entry.id.0
            ),
        );
    }
    if header.deltas == 0 {
        return corrupt(store, "op header", "deltas count must be positive");
    }
    if header.stream_bytes == 0 {
        return corrupt(store, "op header", "stream bytes must be positive");
    }
    let expected_parts = header
        .stream_bytes
        .checked_add(OP_FRAGMENT_MAX_BYTES as u64 - 1)
        .map(|v| v / (OP_FRAGMENT_MAX_BYTES as u64))
        .unwrap_or(u64::MAX);
    if header.parts != expected_parts {
        return corrupt(
            store,
            "op header",
            format!(
                "invalid parts count: expected {expected_parts}, got {}",
                header.parts
            ),
        );
    }
    Ok(())
}

/// Decodes and validates an operation header row from committed bytes.
/// Rows written before provenance existed decode through the v0 shape with
/// no provenance instead of latching quarantine.
///
/// # Errors
/// `E_CORRUPT` and latches quarantine on byte corruption, operation ID mismatch,
/// non-positive delta count, non-positive stream size, or invalid parts count.
pub(crate) fn decode_op_header(
    store: &Store,
    id: OperationId,
    b: &[u8],
) -> Result<OpHeader, CoreError> {
    let new_shape: Result<OpHeader, _> = crate::store::decode("op header", b);
    if let Ok(header) = new_shape {
        validate_op_header(store, id, &header)?;
        return Ok(header);
    }
    let old: OpHeaderV0 = match crate::store::decode("op header", b) {
        Ok(old) => old,
        Err(_) => return corrupt(store, "op header", "malformed op header"),
    };
    let header = OpHeader {
        entry: OperationEntry {
            id: old.entry.id,
            parent: old.entry.parent,
            session: old.entry.session,
            method: old.entry.method,
            committed_at: old.entry.committed_at,
            undoes: old.entry.undoes,
            on_behalf_of: None,
        },
        deltas: old.deltas,
        stream_bytes: old.stream_bytes,
        parts: old.parts,
    };
    validate_op_header(store, id, &header)?;
    Ok(header)
}

/// One table mutation delta recorded inside an operation stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpDelta {
    pub(crate) table: String,
    pub(crate) key: Vec<u8>,
    pub(crate) before: Option<Vec<u8>>,
    pub(crate) after: Option<Vec<u8>>,
}

/// Resolves a table name string to its approved [`FactTable`] enum variant.
#[must_use]
pub(crate) fn fact_table_from_name(name: &str) -> Option<FactTable> {
    FactTable::ALL
        .iter()
        .copied()
        .find(|t| t.table_name() == name)
}

// ---------------------------------------------------------------------------
// Tests and Byte Fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::change::ChangeId;
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::protocol::{
        BoundedList, Method, MutationOutcome, RequestDigest, SchemaArgs, SchemaReply,
        SchemaVersion, WsTakeReply,
    };
    use crate::store::PreparationBudget;
    use crate::workspace::{NativeWorkspace, Scope};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-coord-rows-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create test directory");
            Self(dir)
        }

        fn store_dir(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_store(tag: &str) -> (TempRoot, Store) {
        let temp = TempRoot::new(tag);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store =
            Store::create(&temp.store_dir(), HashKind::Sha1, budget).expect("create test store");
        (temp, store)
    }

    fn sample_oid() -> Oid {
        Oid::from_hex("0123456789abcdef0123456789abcdef01234567").expect("valid oid")
    }

    fn empty_bounded_list<T>() -> BoundedList<T> {
        BoundedList::complete(Vec::new()).expect("empty bounded list")
    }

    fn sample_workspace_state() -> WorkspaceState {
        WorkspaceState::Native(NativeWorkspace::new(
            ChangeId::from_bytes([7; 16]),
            Head::Git { oid: sample_oid() },
            Scope::Full,
        ))
    }

    #[test]
    fn key_encodings_are_exact_width_and_big_endian() {
        let s = SessionId::from_bytes([1; 16]);
        let r = RequestId::from_bytes([2; 16]);
        let w = WorkspaceId::from_bytes([3; 16]);
        let op = OperationId(0x0102_0304_0506_0708);

        assert_eq!(session_key(s), [1; 16]);
        assert_eq!(workspace_key(w), [3; 16]);

        let r_key = receipt_key(s, r);
        assert_eq!(&r_key[..16], [1; 16].as_slice());
        assert_eq!(&r_key[16..], [2; 16].as_slice());

        let o_key = op_key(op, 0x090a_0b0c_0d0e_0f10);
        assert_eq!(
            o_key,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ]
        );
        assert_eq!(OP_HEAD_KEY, b"");
    }

    #[test]
    fn session_row_successor_rules_and_redacted_debug() {
        let principal = Principal::from_peer_uid(1000);
        let t0 = Timestamp::new(jiff::Timestamp::UNIX_EPOCH);
        let t1 = Timestamp::new(
            jiff::Timestamp::UNIX_EPOCH
                .checked_add(jiff::SignedDuration::from_hours(1))
                .expect("add"),
        );
        let t_receipts = Timestamp::new(
            jiff::Timestamp::UNIX_EPOCH
                .checked_add(RECEIPT_HORIZON)
                .expect("add"),
        );

        let row_active = SessionRow {
            principal: principal.clone(),
            identity: None,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0xaa; 32],
            authority: SessionAuthority::Active {
                idle_expires_at: t0,
            },
        };

        // Debug output redacts secret_hash
        let debug_str = format!("{row_active:?}");
        assert!(!debug_str.contains("aa"));
        assert!(debug_str.contains("<redacted>"));

        // Active expiry increase is valid
        let mut row_active_advanced = row_active.clone();
        row_active_advanced.authority = SessionAuthority::Active {
            idle_expires_at: t1,
        };
        assert!(row_active.check_successor(&row_active_advanced).is_ok());

        // Active expiry decrease is invalid
        assert_eq!(
            row_active_advanced
                .check_successor(&row_active)
                .expect_err("decrease")
                .code,
            ErrorCode::EInvalid
        );

        // Transition from Active to ReceiptsOnly with exactly +7d is valid
        let mut row_receipts = row_active.clone();
        row_receipts.authority = SessionAuthority::ReceiptsOnly {
            receipts_until: t_receipts,
        };
        assert!(row_active.check_successor(&row_receipts).is_ok());

        // Transition from Active to ReceiptsOnly with wrong horizon is invalid
        let mut row_receipts_wrong = row_active.clone();
        row_receipts_wrong.authority = SessionAuthority::ReceiptsOnly { receipts_until: t1 };
        assert_eq!(
            row_active
                .check_successor(&row_receipts_wrong)
                .expect_err("wrong horizon")
                .code,
            ErrorCode::EInvalid
        );

        // ReceiptsOnly cannot regain Active
        assert_eq!(
            row_receipts
                .check_successor(&row_active)
                .expect_err("regain active")
                .code,
            ErrorCode::EInvalid
        );

        // Immutable fields cannot change
        let mut row_diff_principal = row_active.clone();
        row_diff_principal.principal = Principal::from_peer_uid(2000);
        assert_eq!(
            row_active
                .check_successor(&row_diff_principal)
                .expect_err("principal diff")
                .code,
            ErrorCode::EInvalid
        );

        let mut row_diff_secret = row_active.clone();
        row_diff_secret.secret_hash = [0xbb; 32];
        assert_eq!(
            row_active
                .check_successor(&row_diff_secret)
                .expect_err("secret diff")
                .code,
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn workspace_row_successor_and_holder_fencing() {
        let state0 = sample_workspace_state();
        let holder0 = SessionId::from_bytes([1; 16]);
        let holder1 = SessionId::from_bytes([2; 16]);

        let row0 = WorkspaceRow {
            state: state0.clone(),
            holder: holder0,
            root: ByteString::from("/tmp/ruk-rows-test"),
        };

        // Same holder, advance stamp sequence: valid
        let state_advanced = state0
            .rescope(state0.stamp(), Scope::Full)
            .expect("advance");
        let row_advanced = WorkspaceRow {
            state: state_advanced,
            holder: holder0,
            root: ByteString::from("/tmp/ruk-rows-test"),
        };
        assert!(row0.check_successor(&row_advanced).is_ok());

        // Holder changed with take (epoch increased): valid
        let state_taken = state0.take().expect("take");
        let row_taken = WorkspaceRow {
            state: state_taken,
            holder: holder1,
            root: ByteString::from("/tmp/ruk-rows-test"),
        };
        assert!(row0.check_successor(&row_taken).is_ok());

        // Holder changed without epoch increase: invalid
        let row_takeover_no_epoch = WorkspaceRow {
            state: state0.clone(),
            holder: holder1,
            root: ByteString::from("/tmp/ruk-rows-test"),
        };
        assert_eq!(
            row0.check_successor(&row_takeover_no_epoch)
                .expect_err("holder without epoch")
                .code,
            ErrorCode::EInvalid
        );

        // Root retargeting is invalid even on an identical replacement.
        let row_retargeted = WorkspaceRow {
            state: state0.clone(),
            holder: holder0,
            root: ByteString::from("/tmp/ruk-rows-elsewhere"),
        };
        assert_eq!(
            row0.check_successor(&row_retargeted)
                .expect_err("root retarget")
                .code,
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn pre_root_workspace_rows_decode_with_empty_root_and_no_quarantine() {
        let (_temp, store) = test_store("ws-legacy");
        let holder = SessionId::from_bytes([9; 16]);
        let state = sample_workspace_state();
        // Authentic pre-root bytes: the legacy shape only.
        let legacy = LegacyWorkspaceRow {
            state: state.clone(),
            holder,
        };
        let bytes = crate::store::encode("workspace row", &legacy).expect("encode legacy row");
        let key = workspace_key(WorkspaceId::from_bytes([4; 16]));
        let row = decode_workspace(&store, &key, &bytes).expect("legacy row upgrades");
        assert_eq!(row.state, state);
        assert_eq!(row.holder, holder);
        assert!(row.root.is_empty());

        // The fallback retry must not latch quarantine: the store still
        // serves reads after upgrading a shorter row.
        store
            .fact(FactTable::OpHead, OP_HEAD_KEY)
            .expect("store usable after legacy upgrade");

        // Genuine corruption still latches: trailing bytes fail both shapes.
        let mut corrupt = bytes.clone();
        corrupt.push(0xff);
        let err = decode_workspace(&store, &key, &corrupt).expect_err("trailing bytes fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);
    }

    #[test]
    fn receipt_row_schema_refusal_and_replay_preservation() {
        let s = SessionId::from_bytes([1; 16]);
        let r = RequestId::from_bytes([2; 16]);

        // Schema reply cannot enter a receipt
        let schema_reply = Reply::Schema(Box::new(SchemaReply {
            schema_version: SchemaVersion::current(),
            methods: Vec::new(),
            document: schemars::schema_for!(SchemaArgs),
        }));
        assert_eq!(
            ReceiptRow::new(s, r, schema_reply)
                .expect_err("schema reply")
                .code,
            ErrorCode::EInvalid
        );

        // Matching mutation reply is accepted
        let outcome = MutationOutcome {
            receipt: ReceiptRef {
                session: s,
                request_id: r,
                digest: RequestDigest::from_bytes([3; 32]),
                replayed: false,
                retained_until: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            },
            operation: Some(OperationId(1)),
            heads: empty_bounded_list(),
            stamps: empty_bounded_list(),
            warnings: empty_bounded_list(),
            merge: None,
            provenance: empty_bounded_list(),
            identity: None,
        };
        let ws_reply = Reply::WsTake(Box::new(WsTakeReply {
            outcome: outcome.clone(),
            state: sample_workspace_state(),
        }));

        let receipt_row = ReceiptRow::new(s, r, ws_reply).expect("receipt row");
        assert!(!receipt_row.receipt().replayed);
        assert_eq!(receipt_row.receipt().session, s);

        // into_replay changes ONLY replayed = true
        let replay = receipt_row.into_replay();
        let replay_outcome = replay.outcome().expect("outcome");
        assert!(replay_outcome.receipt.replayed);
        assert_eq!(replay_outcome.receipt.session, s);
        assert_eq!(replay_outcome.receipt.request_id, r);
        assert_eq!(replay_outcome.operation, Some(OperationId(1)));
    }

    #[test]
    fn store_observe_quarantine_on_trailing_bytes_and_corruption() {
        let (_temp, store) = test_store("quarantine");

        // Trailing bytes trigger store quarantine
        let head = CoordinatorHead::default();
        let mut encoded = encode("coordinator head", &head).expect("encode");
        encoded.push(0xff); // trailing byte

        let err = decode_head(&store, &encoded).expect_err("trailing bytes must fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);

        // Store must now be quarantined
        assert_eq!(
            store
                .fact(FactTable::OpHead, b"")
                .expect_err("quarantined")
                .code(),
            ErrorCode::ECorrupt
        );
    }

    #[test]
    fn receipt_key_mismatch_and_semantic_violations_quarantine() {
        let (_temp, store) = test_store("receipt-corrupt");

        let s1 = SessionId::from_bytes([1; 16]);
        let s2 = SessionId::from_bytes([2; 16]);
        let r = RequestId::from_bytes([3; 16]);

        let outcome = MutationOutcome {
            receipt: ReceiptRef {
                session: s1,
                request_id: r,
                digest: RequestDigest::from_bytes([4; 32]),
                replayed: false,
                retained_until: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            },
            operation: None,
            heads: empty_bounded_list(),
            stamps: empty_bounded_list(),
            warnings: empty_bounded_list(),
            merge: None,
            provenance: empty_bounded_list(),
            identity: None,
        };
        let reply = Reply::WsTake(Box::new(WsTakeReply {
            outcome,
            state: sample_workspace_state(),
        }));
        let receipt_row = ReceiptRow::new(s1, r, reply).expect("valid receipt");
        let bytes = encode("receipt row", &receipt_row).expect("encode");

        // Decoding with key for s2 instead of s1 must latch corruption
        let wrong_key = receipt_key(s2, r);
        let err = decode_receipt(&store, &wrong_key, &bytes).expect_err("key mismatch");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert_eq!(
            store
                .fact(FactTable::OpHead, b"")
                .expect_err("quarantined")
                .code(),
            ErrorCode::ECorrupt
        );
    }

    #[test]
    fn op_header_validation_failures_latch_quarantine() {
        let (_temp, store) = test_store("op-header-corrupt");

        let entry = OperationEntry {
            id: OperationId(1),
            parent: None,
            session: Some(SessionId::from_bytes([1; 16])),
            method: Method::WsTake,
            committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            undoes: None,
            on_behalf_of: None,
        };

        // Zero deltas count rejected
        let zero_deltas = OpHeader {
            entry: entry.clone(),
            deltas: 0,
            stream_bytes: 100,
            parts: 1,
        };
        let b = encode("op header", &zero_deltas).expect("encode");
        let err = decode_op_header(&store, OperationId(1), &b).expect_err("zero deltas");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert_eq!(
            store
                .fact(FactTable::OpHead, b"")
                .expect_err("quarantined")
                .code(),
            ErrorCode::ECorrupt
        );
    }

    // Exact committed byte constants protecting v1 on-disk format compatibility.
    const GOLDEN_COORDINATOR_HEAD: &[u8] = &[0x00; 9];
    const GOLDEN_OP_HEADER: &[u8] = &[
        1, 0, 1, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 0, 0, 0, 0, 1, 31, 1,
    ];
    const GOLDEN_OP_HEADER_V0: &[u8] = &[
        1, 0, 1, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 0, 0, 0, 1, 31, 1,
    ];
    const GOLDEN_OP_DELTA: &[u8] = &[
        10, 119, 111, 114, 107, 115, 112, 97, 99, 101, 115, 4, 1, 2, 3, 4, 0, 1, 4, 5, 6, 7, 8,
    ];
    const GOLDEN_SESSION_ACTIVE: &[u8] = &[
        9, 117, 110, 105, 120, 58, 49, 48, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 0, 0, 0,
    ];
    const GOLDEN_SESSION_RECEIPTS: &[u8] = &[
        9, 117, 110, 105, 120, 58, 49, 48, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 1, 128, 234, 73, 0,
    ];
    const GOLDEN_WS_TAKE_RECEIPT: &[u8] = &[
        5, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 16, 34, 34, 34, 34,
        34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 32, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 0, 20, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205,
        239, 1, 35, 69, 103, 0, 0, 0,
    ];

    #[test]
    fn persisted_table_names_survive_the_census_revision() {
        for table in FactTable::ALL {
            assert_eq!(
                fact_table_from_name(table.table_name()),
                Some(table),
                "{table:?} round-trips through its persisted name"
            );
        }
        assert_eq!(
            fact_table_from_name("released_tags"),
            Some(FactTable::ReleasedTags)
        );
        assert_eq!(fact_table_from_name("not_a_table"), None);
    }

    #[test]
    fn golden_byte_vectors_v1_compatibility() {
        let (_temp, store) = test_store("golden-v1");

        // 1. CoordinatorHead default: decode hardcoded constant, assert exact equality, re-encode
        let expected_head = CoordinatorHead::default();
        let decoded_head = decode_head(&store, GOLDEN_COORDINATOR_HEAD).expect("decode head");
        assert_eq!(decoded_head, expected_head);
        let head_bytes = encode("coordinator head", &expected_head).expect("encode head");
        assert_eq!(head_bytes.as_slice(), GOLDEN_COORDINATOR_HEAD);

        // 2. OpHeader and OpDelta: decode hardcoded constants, assert exact equality, re-encode
        let expected_entry = OperationEntry {
            id: OperationId(1),
            parent: None,
            session: Some(SessionId::from_bytes([1; 16])),
            method: Method::WsTake,
            committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            undoes: None,
            on_behalf_of: None,
        };
        let expected_header = OpHeader {
            entry: expected_entry,
            deltas: 1,
            stream_bytes: 31,
            parts: 1,
        };
        let decoded_header =
            decode_op_header(&store, OperationId(1), GOLDEN_OP_HEADER).expect("decode header");
        assert_eq!(decoded_header, expected_header);
        let header_bytes = encode("op header", &expected_header).expect("encode header");
        assert_eq!(header_bytes.as_slice(), GOLDEN_OP_HEADER);

        let decoded_v0 = decode_op_header(&store, OperationId(1), GOLDEN_OP_HEADER_V0)
            .expect("decode v0 header");
        assert_eq!(decoded_v0, expected_header);
        assert_eq!(decoded_v0.entry.on_behalf_of, None);

        let expected_delta = OpDelta {
            table: "workspaces".to_owned(),
            key: vec![1, 2, 3, 4],
            before: None,
            after: Some(vec![5, 6, 7, 8]),
        };
        let decoded_delta: OpDelta =
            decode(&store, "op delta", GOLDEN_OP_DELTA).expect("decode delta");
        assert_eq!(decoded_delta, expected_delta);
        let delta_bytes = encode("op delta", &expected_delta).expect("encode delta");
        assert_eq!(delta_bytes.as_slice(), GOLDEN_OP_DELTA);

        // 3. SessionRow Active & ReceiptsOnly: decode hardcoded constants, assert equality, re-encode
        let expected_session_active = SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity: None,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0x42; 32],
            authority: SessionAuthority::Active {
                idle_expires_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            },
        };
        let decoded_active = decode_session(
            &store,
            &session_key(SessionId::from_bytes([1; 16])),
            GOLDEN_SESSION_ACTIVE,
        )
        .expect("decode active");
        assert_eq!(decoded_active, expected_session_active);
        let active_bytes = encode("session row", &expected_session_active).expect("encode active");
        assert_eq!(active_bytes.as_slice(), GOLDEN_SESSION_ACTIVE);

        let expected_session_receipts = SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity: None,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0x42; 32],
            authority: SessionAuthority::ReceiptsOnly {
                receipts_until: Timestamp::new(
                    jiff::Timestamp::UNIX_EPOCH
                        .checked_add(RECEIPT_HORIZON)
                        .expect("add"),
                ),
            },
        };
        let decoded_receipts = decode_session(
            &store,
            &session_key(SessionId::from_bytes([1; 16])),
            GOLDEN_SESSION_RECEIPTS,
        )
        .expect("decode receipts");
        assert_eq!(decoded_receipts, expected_session_receipts);
        let receipts_bytes =
            encode("session row", &expected_session_receipts).expect("encode receipts");
        assert_eq!(receipts_bytes.as_slice(), GOLDEN_SESSION_RECEIPTS);

        // 4. ws.take ReceiptRow: decode hardcoded constant, assert equality, re-encode
        let s = SessionId::from_bytes([0x11; 16]);
        let r = RequestId::from_bytes([0x22; 16]);
        let outcome = MutationOutcome {
            receipt: ReceiptRef {
                session: s,
                request_id: r,
                digest: RequestDigest::from_bytes([0x33; 32]),
                replayed: false,
                retained_until: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            },
            operation: Some(OperationId(1)),
            heads: empty_bounded_list(),
            stamps: empty_bounded_list(),
            warnings: empty_bounded_list(),
            merge: None,
            provenance: empty_bounded_list(),
            identity: None,
        };
        let ws_reply = Reply::WsTake(Box::new(WsTakeReply {
            outcome,
            state: sample_workspace_state(),
        }));
        let expected_receipt_row = ReceiptRow::new(s, r, ws_reply).expect("receipt");
        let decoded_receipt = decode_receipt(&store, &receipt_key(s, r), GOLDEN_WS_TAKE_RECEIPT)
            .expect("decode receipt");
        assert_eq!(decoded_receipt, expected_receipt_row);
        let receipt_bytes = encode("receipt row", &expected_receipt_row).expect("encode receipt");
        assert_eq!(receipt_bytes.as_slice(), GOLDEN_WS_TAKE_RECEIPT);
    }
}
