//! Coordinator operation stream encoding, recording, and decoding.
//!
//! This module owns the operation stream implementation for the Ruk coordinator.
//! All durable row formats declared here are v1.
//!
//! # Architecture
//! In [`FactTable::Ops`], operation state is stored as:
//! - Part 0: [`OpHeader`] containing the [`OperationEntry`], total deltas count (`deltas: u64`),
//!   total stream byte size (`stream_bytes: u64`), and total stream parts count (`parts: u64`).
//! - Parts 1..=parts: Raw byte fragments of a single continuous operation stream.
//!   Each fragment is bounded by [`OP_FRAGMENT_MAX_BYTES`] (4 MiB).
//!   All intermediate fragments (`part < parts`) have length exactly [`OP_FRAGMENT_MAX_BYTES`].
//!   The terminal fragment (`part == parts`) has the exact remaining stream bytes.
//!
//! # Stream Layout
//! The operation stream is the concatenation of:
//! `[encoded_delta_length: u64 big-endian][postcard OpDelta]`
//! for each tracked mutation delta. No outer `Vec<OpDelta>` wrapper is stored on disk.
//! One delta can span across multiple fragment boundaries.
//!
//! # Quarantine on Corruption
//! Any structural defect (malformed headers, missing parts, oversized fragments,
//! forged lengths, unknown table names, untracked tables, empty deltas, or trailing data)
//! is committed corruption that reports to [`Store::observe`], latching quarantine.

use serde::Serialize;

use crate::change::{CheckedOperationId, OperationId, SessionId};
use crate::coord::rows::{
    MAX_ENCODED_DELTA_BYTES, OP_FRAGMENT_MAX_BYTES, OpDelta, OpHeader, ROW_MAX_BYTES, corrupt,
    decode, decode_op_header, encode, fact_table_from_name, op_key,
};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Method, OperationEntry, Timestamp};
use crate::store::Store;
use crate::store::types::{FactExpectation, FactMutation, FactTable};

// ---------------------------------------------------------------------------
// Tracked Table Census
// ---------------------------------------------------------------------------

/// Determines whether mutations to `table` are recorded in the coordinator operation log.
///
/// Exhaustive match with no wildcard per the state proposal section 8 contract.
/// Tracked tables: `Refs`, `RefConflicts`, `Changes`, `ChangeHistory`, `Workspaces`,
/// `WsIndex`, and `Pins`. All other 20 tables in the census are untracked.
#[must_use]
pub(crate) fn tracked(table: FactTable) -> bool {
    match table {
        FactTable::Refs => true,
        FactTable::RefConflicts => true,
        FactTable::Changes => true,
        FactTable::ChangeHistory => true,
        FactTable::Workspaces => true,
        FactTable::WsIndex => true,
        FactTable::Pins => true,

        FactTable::RemoteObservations => false,
        FactTable::ImportedChanges => false,
        FactTable::Commits => false,
        FactTable::Ops => false,
        FactTable::OpHead => false,
        FactTable::Claims => false,
        FactTable::WsStatus => false,
        FactTable::WsDirs => false,
        FactTable::Receipts => false,
        FactTable::Sessions => false,
        FactTable::Attestations => false,
        FactTable::PushPlans => false,
        FactTable::LandPlans => false,
        FactTable::PublishedHeads => false,
        FactTable::Leases => false,
        FactTable::WsApply => false,
        FactTable::Reflogs => false,
        FactTable::Promisor => false,
        FactTable::Shallow => false,
        FactTable::LfsObjects => false,
        FactTable::Events => false,
        FactTable::EventHead => false,
        FactTable::ServiceReceipts => false,
        FactTable::RepoMeta => false,
        FactTable::ReleasedTags => false,
    }
}

// ---------------------------------------------------------------------------
// Write Types and Serialization
// ---------------------------------------------------------------------------

/// Metadata required to record an operation entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpMeta {
    pub(crate) session: SessionId,
    pub(crate) method: Method,
    pub(crate) committed_at: Timestamp,
    pub(crate) undoes: Option<OperationId>,
    pub(crate) on_behalf_of: Option<String>,
}

/// Borrowed serialization view of a delta with postcard layout identical to [`OpDelta`].
///
/// Avoids whole-payload allocations or clones during serialization.
#[derive(Serialize)]
struct BorrowedOpDelta<'a> {
    table: &'a str,
    key: &'a [u8],
    before: Option<&'a [u8]>,
    after: Option<&'a [u8]>,
}

/// Bounded streaming fragment accumulator.
///
/// Flushes full 4 MiB buffers into completed fragments and preserves the exact
/// remaining stream bytes in the terminal fragment.
struct FragmentWriter {
    current: Vec<u8>,
    fragments: Vec<Vec<u8>>,
    total_bytes: u64,
}

impl FragmentWriter {
    fn new() -> Self {
        Self {
            current: Vec::with_capacity(OP_FRAGMENT_MAX_BYTES),
            fragments: Vec::new(),
            total_bytes: 0,
        }
    }

    fn push_bytes(&mut self, mut data: &[u8]) -> Result<(), CoreError> {
        let data_len = u64::try_from(data.len()).map_err(|_| {
            CoreError::new(
                ErrorCode::EInvalid,
                "data length: data slice length exceeds u64",
            )
        })?;
        self.total_bytes = self.total_bytes.checked_add(data_len).ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "stream bytes: stream bytes counter overflow",
            )
        })?;
        while !data.is_empty() {
            let available = OP_FRAGMENT_MAX_BYTES.saturating_sub(self.current.len());
            if available == 0 {
                let full =
                    std::mem::replace(&mut self.current, Vec::with_capacity(OP_FRAGMENT_MAX_BYTES));
                self.fragments.push(full);
                continue;
            }
            let to_copy = data.len().min(available);
            self.current.extend_from_slice(&data[..to_copy]);
            data = &data[to_copy..];
            if self.current.len() == OP_FRAGMENT_MAX_BYTES {
                let full =
                    std::mem::replace(&mut self.current, Vec::with_capacity(OP_FRAGMENT_MAX_BYTES));
                self.fragments.push(full);
            }
        }
        Ok(())
    }

    fn finish(mut self) -> (Vec<Vec<u8>>, u64) {
        if !self.current.is_empty() {
            self.fragments.push(self.current);
        }
        let total = self.total_bytes;
        (self.fragments, total)
    }
}

/// Postcard streaming flavor routing serialized bytes into [`FragmentWriter`].
struct FragmentFlavor<'w> {
    writer: &'w mut FragmentWriter,
}

impl<'w> postcard::ser_flavors::Flavor for FragmentFlavor<'w> {
    type Output = ();

    #[inline]
    fn try_push(&mut self, b: u8) -> postcard::Result<()> {
        self.writer
            .push_bytes(&[b])
            .map_err(|_| postcard::Error::SerializeBufferFull)
    }

    #[inline]
    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        self.writer
            .push_bytes(data)
            .map_err(|_| postcard::Error::SerializeBufferFull)
    }

    #[inline]
    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(())
    }
}

/// Records tracked fact changes into an operation log stream.
///
/// # Semantics
/// - Untracked table mutations are skipped.
/// - [`FactExpectation::Any`] is rejected for tracked mutations (`E_INVALID`).
/// - Guards and identical rewrites (`before == after`) are excluded.
/// - If no tracked changes remain, returns `Ok(None)` and leaves `ops` untouched.
/// - If tracked changes exist, allocates the next [`OperationId`] via `ops.allocate()`,
///   streams length-prefixed postcard deltas into 4 MiB fragments, and constructs
///   [`FactTable::Ops`] mutations with [`FactExpectation::Absent`].
///
/// # Errors
/// - [`crate::error::ErrorCode::EInvalid`] if an expectation is [`FactExpectation::Any`].
/// - [`crate::error::ErrorCode::ECapacity`] if the operation ID counter is exhausted.
pub(crate) fn record(
    ops: &mut CheckedOperationId,
    parent: Option<OperationId>,
    meta: OpMeta,
    changes: &[FactMutation],
) -> Result<Option<(OperationId, Vec<FactMutation>)>, CoreError> {
    let mut tracked_deltas: Vec<BorrowedOpDelta<'_>> = Vec::new();

    for mutation in changes {
        if !tracked(mutation.table) {
            continue;
        }

        let before = match &mutation.expected {
            FactExpectation::Any => {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "mutation expectation: FactExpectation::Any is rejected for tracked mutations: exact before-value expectation (Value or Absent) is required",
                ));
            }
            FactExpectation::Absent => None,
            FactExpectation::Value(b) => Some(b.as_slice()),
        };

        let after = mutation.value.as_deref();

        // Exclude guards and identical rewrites
        if before == after {
            continue;
        }

        tracked_deltas.push(BorrowedOpDelta {
            table: mutation.table.table_name(),
            key: mutation.key.as_slice(),
            before,
            after,
        });
    }

    if tracked_deltas.is_empty() {
        return Ok(None);
    }

    let id = ops.allocate().map_err(CoreError::from)?;
    let mut fragment_writer = FragmentWriter::new();
    let deltas_count = u64::try_from(tracked_deltas.len()).map_err(|_| {
        CoreError::new(
            ErrorCode::EInvalid,
            "deltas count: deltas count exceeds u64",
        )
    })?;

    for delta in &tracked_deltas {
        let delta_size =
            postcard::serialize_with_flavor(delta, postcard::ser_flavors::Size::default())
                .map_err(|e| {
                    CoreError::new(ErrorCode::EInvalid, format!("serialize delta: {e}"))
                })?;

        let delta_size_u64 = u64::try_from(delta_size).map_err(|_| {
            CoreError::new(ErrorCode::EInvalid, "delta size: delta size exceeds u64")
        })?;
        let length_prefix = delta_size_u64.to_be_bytes();
        fragment_writer.push_bytes(&length_prefix)?;

        postcard::serialize_with_flavor(
            delta,
            FragmentFlavor {
                writer: &mut fragment_writer,
            },
        )
        .map_err(|e| CoreError::new(ErrorCode::EInvalid, format!("serialize delta: {e}")))?;
    }

    let (fragments, stream_bytes) = fragment_writer.finish();
    let parts = u64::try_from(fragments.len())
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "parts count: parts count exceeds u64"))?;

    let entry = OperationEntry {
        id,
        parent,
        session: Some(meta.session),
        method: meta.method,
        committed_at: meta.committed_at,
        undoes: meta.undoes,
        on_behalf_of: meta.on_behalf_of,
    };
    let header = OpHeader {
        entry,
        deltas: deltas_count,
        stream_bytes,
        parts,
    };
    let header_bytes = encode("op header", &header)?;

    let mut mutations = Vec::with_capacity(fragments.len() + 1);
    mutations.push(FactMutation {
        table: FactTable::Ops,
        key: op_key(id, 0).to_vec(),
        expected: FactExpectation::Absent,
        value: Some(header_bytes),
    });

    for (idx, fragment) in fragments.into_iter().enumerate() {
        let idx_u64 = u64::try_from(idx).map_err(|_| {
            CoreError::new(
                ErrorCode::EInvalid,
                "fragment index: fragment index exceeds u64",
            )
        })?;
        let part_num = idx_u64.checked_add(1).ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "part number: part number counter overflow",
            )
        })?;
        mutations.push(FactMutation {
            table: FactTable::Ops,
            key: op_key(id, part_num).to_vec(),
            expected: FactExpectation::Absent,
            value: Some(fragment),
        });
    }

    Ok(Some((id, mutations)))
}

// ---------------------------------------------------------------------------
// Read Interface and Bounded Cursor
// ---------------------------------------------------------------------------

/// Reads and validates the operation header for `id`.
///
/// Returns `Ok(None)` if the operation does not exist. Malformed bytes or semantic
/// violations report to [`Store::observe`] and return `E_CORRUPT`.
pub(crate) fn read_header(store: &Store, id: OperationId) -> Result<Option<OpHeader>, CoreError> {
    let key = op_key(id, 0);
    let Some(bytes) = store.fact(FactTable::Ops, &key)? else {
        return Ok(None);
    };
    let header = decode_op_header(store, id, &bytes)?;
    Ok(Some(header))
}

/// Bounded operation delta stream reader.
///
/// Streams individual [`OpDelta`] records across length-fragmented operation parts
/// without aggregating the entire operation into memory.
pub(crate) struct OpDeltaReader<'a> {
    store: &'a Store,
    id: OperationId,
    header: OpHeader,
    current_part: u64,
    current_fragment: Option<Vec<u8>>,
    fragment_offset: usize,
    stream_bytes_read: u64,
    deltas_read: u64,
    delta_buffer: Vec<u8>,
    done: bool,
}

impl<'a> OpDeltaReader<'a> {
    /// Creates a reader for the validated `header` of operation `id`.
    #[must_use]
    pub(crate) fn new(store: &'a Store, id: OperationId, header: OpHeader) -> Self {
        Self {
            store,
            id,
            header,
            current_part: 1,
            current_fragment: None,
            fragment_offset: 0,
            stream_bytes_read: 0,
            deltas_read: 0,
            delta_buffer: Vec::new(),
            done: false,
        }
    }

    /// The validated header of this operation.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn header(&self) -> &OpHeader {
        &self.header
    }

    /// Number of deltas successfully read so far.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn deltas_read(&self) -> u64 {
        self.deltas_read
    }

    /// Number of raw stream bytes consumed so far.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn stream_bytes_read(&self) -> u64 {
        self.stream_bytes_read
    }

    /// Current part number being read.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn current_part(&self) -> u64 {
        self.current_part
    }

    /// Returns `true` when all deltas in the operation have been successfully read.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn is_finished(&self) -> bool {
        self.done
            || (self.deltas_read == self.header.deltas
                && self.stream_bytes_read == self.header.stream_bytes)
    }

    fn ensure_fragment_loaded(&mut self) -> Result<(), CoreError> {
        if let Some(f) = &self.current_fragment
            && self.fragment_offset < f.len()
        {
            return Ok(());
        }

        if self.current_part > self.header.parts {
            return corrupt(
                self.store,
                "op stream",
                "unexpected end of operation stream fragments",
            );
        }

        let key = op_key(self.id, self.current_part);
        let Some(part_bytes) = self.store.fact(FactTable::Ops, &key)? else {
            return corrupt(
                self.store,
                "op stream",
                format!("missing operation part {}", self.current_part),
            );
        };

        self.validate_and_store_fragment(part_bytes)
    }

    fn validate_and_store_fragment(&mut self, part_bytes: Vec<u8>) -> Result<(), CoreError> {
        if self.current_part < self.header.parts {
            if part_bytes.len() != OP_FRAGMENT_MAX_BYTES {
                return corrupt(
                    self.store,
                    "op stream",
                    format!(
                        "intermediate part {} has invalid length: expected {}, got {}",
                        self.current_part,
                        OP_FRAGMENT_MAX_BYTES,
                        part_bytes.len()
                    ),
                );
            }
            self.current_fragment = Some(part_bytes);
            self.fragment_offset = 0;
            self.current_part = self.current_part.checked_add(1).ok_or_else(|| {
                CoreError::new(ErrorCode::ECorrupt, "op stream: part counter overflow")
            })?;
            return Ok(());
        }

        let prior_parts = self.header.parts.saturating_sub(1);
        let prior_bytes = prior_parts
            .checked_mul(OP_FRAGMENT_MAX_BYTES as u64)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op stream: parts overflow in byte accounting",
                )
            })?;
        let expected_last_len = self
            .header
            .stream_bytes
            .checked_sub(prior_bytes)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op stream: stream bytes smaller than expected prior fragment quantum",
                )
            })?;
        let expected_usize = usize::try_from(expected_last_len).map_err(|_| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "op stream: terminal fragment size exceeds usize",
            )
        })?;
        if part_bytes.len() != expected_usize {
            return corrupt(
                self.store,
                "op stream",
                format!(
                    "terminal part {} has invalid length: expected {}, got {}",
                    self.current_part,
                    expected_usize,
                    part_bytes.len()
                ),
            );
        }

        self.current_fragment = Some(part_bytes);
        self.fragment_offset = 0;
        self.current_part = self.current_part.checked_add(1).ok_or_else(|| {
            CoreError::new(ErrorCode::ECorrupt, "op stream: part counter overflow")
        })?;
        Ok(())
    }

    /// Reads exactly `buf.len()` bytes from the stream fragments into `buf`.
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), CoreError> {
        while !buf.is_empty() {
            self.ensure_fragment_loaded()?;

            let Some(frag) = &self.current_fragment else {
                return corrupt(self.store, "op stream", "fragment missing after load");
            };
            let avail = frag.len() - self.fragment_offset;
            let to_copy = buf.len().min(avail);
            buf[..to_copy]
                .copy_from_slice(&frag[self.fragment_offset..self.fragment_offset + to_copy]);
            self.fragment_offset += to_copy;
            let to_copy_u64 = u64::try_from(to_copy).map_err(|_| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op stream: copied byte count exceeds u64",
                )
            })?;
            self.stream_bytes_read =
                self.stream_bytes_read
                    .checked_add(to_copy_u64)
                    .ok_or_else(|| {
                        CoreError::new(ErrorCode::ECorrupt, "op stream: stream bytes read overflow")
                    })?;
            buf = &mut buf[to_copy..];
        }
        Ok(())
    }

    /// Reads and validates the next [`OpDelta`] from the operation stream.
    ///
    /// # Errors
    /// Returns `E_CORRUPT` and latches quarantine on:
    /// - Announced delta length of zero or exceeding [`MAX_ENCODED_DELTA_BYTES`].
    /// - Announced delta length exceeding remaining stream bytes.
    /// - Postcard byte corruption or trailing bytes in delta envelope.
    /// - Table name not present in the [`FactTable`] census or not [`tracked`].
    /// - Delta missing both before and after content.
    /// - Delta with identical before and after content.
    /// - Row byte bounds exceeded (`ROW_MAX_BYTES`).
    /// - Stream length or deltas count mismatch.
    /// - Extra trailing parts or unconsumed stream bytes.
    pub(crate) fn next_delta(&mut self) -> Result<Option<OpDelta>, CoreError> {
        if self.done {
            return Ok(None);
        }

        if self.deltas_read == self.header.deltas {
            if self.stream_bytes_read != self.header.stream_bytes {
                return corrupt(
                    self.store,
                    "op stream",
                    format!(
                        "stream byte count mismatch: read {}, expected {}",
                        self.stream_bytes_read, self.header.stream_bytes
                    ),
                );
            }

            if let Some(frag) = &self.current_fragment
                && self.fragment_offset < frag.len()
            {
                return corrupt(
                    self.store,
                    "op stream",
                    "unconsumed trailing bytes in terminal fragment",
                );
            }

            let extra_key = op_key(self.id, self.header.parts + 1);
            if self.store.fact(FactTable::Ops, &extra_key)?.is_some() {
                return corrupt(
                    self.store,
                    "op stream",
                    format!("unexpected extra part {} in store", self.header.parts + 1),
                );
            }

            self.done = true;
            return Ok(None);
        }

        let mut len_buf = [0_u8; 8];
        self.read_exact(&mut len_buf)?;
        let delta_len = u64::from_be_bytes(len_buf);

        if delta_len == 0 {
            return corrupt(self.store, "op stream", "announced delta length is zero");
        }
        if delta_len > MAX_ENCODED_DELTA_BYTES {
            return corrupt(
                self.store,
                "op stream",
                format!(
                    "announced delta length {delta_len} exceeds maximum allowed bound {MAX_ENCODED_DELTA_BYTES}"
                ),
            );
        }

        let remaining_stream = self
            .header
            .stream_bytes
            .checked_sub(self.stream_bytes_read)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op stream: stream bytes read exceeded total",
                )
            })?;
        if delta_len > remaining_stream {
            return corrupt(
                self.store,
                "op stream",
                format!(
                    "announced delta length {delta_len} exceeds remaining stream bytes {remaining_stream}"
                ),
            );
        }

        let delta_len_usize = usize::try_from(delta_len).map_err(|_| {
            CoreError::new(ErrorCode::ECorrupt, "op stream: delta length exceeds usize")
        })?;
        self.delta_buffer.resize(delta_len_usize, 0);
        let mut buffer = std::mem::take(&mut self.delta_buffer);
        let filled = self.read_exact(&mut buffer).map(|()| buffer);
        self.delta_buffer = filled?;

        let delta: OpDelta = decode(self.store, "op delta", &self.delta_buffer)?;

        let Some(table) = fact_table_from_name(&delta.table) else {
            return corrupt(
                self.store,
                "op delta",
                format!("unknown table name `{}` in delta", delta.table),
            );
        };

        if !tracked(table) {
            return corrupt(
                self.store,
                "op delta",
                format!("untracked table `{}` in delta", delta.table),
            );
        }

        if delta.before.is_none() && delta.after.is_none() {
            return corrupt(
                self.store,
                "op delta",
                format!(
                    "delta for table `{}` has neither before nor after",
                    delta.table
                ),
            );
        }

        if let (Some(b), Some(a)) = (&delta.before, &delta.after)
            && b == a
        {
            return corrupt(
                self.store,
                "op delta",
                format!(
                    "delta for table `{}` has identical before and after content",
                    delta.table
                ),
            );
        }

        let key_len = u64::try_from(delta.key.len())
            .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "op delta: key length exceeds u64"))?;
        if key_len > ROW_MAX_BYTES {
            return corrupt(
                self.store,
                "op delta",
                format!("key length {key_len} exceeds ROW_MAX_BYTES"),
            );
        }
        if let Some(b) = &delta.before {
            let b_len = u64::try_from(b.len()).map_err(|_| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op delta: before value length exceeds u64",
                )
            })?;
            if key_len.saturating_add(b_len) > ROW_MAX_BYTES {
                return corrupt(
                    self.store,
                    "op delta",
                    "key plus before value exceeds ROW_MAX_BYTES",
                );
            }
        }
        if let Some(a) = &delta.after {
            let a_len = u64::try_from(a.len()).map_err(|_| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "op delta: after value length exceeds u64",
                )
            })?;
            if key_len.saturating_add(a_len) > ROW_MAX_BYTES {
                return corrupt(
                    self.store,
                    "op delta",
                    "key plus after value exceeds ROW_MAX_BYTES",
                );
            }
        }

        self.deltas_read = self.deltas_read.checked_add(1).ok_or_else(|| {
            CoreError::new(ErrorCode::ECorrupt, "op stream: deltas count overflow")
        })?;

        Ok(Some(delta))
    }
}

impl<'a> Iterator for OpDeltaReader<'a> {
    type Item = Result<OpDelta, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_delta() {
            Ok(Some(delta)) => Some(Ok(delta)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit and Adversarial Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::error::ErrorCode;
    use crate::ids::HashKind;
    use crate::store::PreparationBudget;

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-oplog-test-{tag}-{}-{}-{nanos}",
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

    fn test_meta() -> OpMeta {
        OpMeta {
            session: SessionId::from_bytes([0x42; 16]),
            method: Method::WsTake,
            committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
            undoes: None,
            on_behalf_of: None,
        }
    }

    #[test]
    fn tracked_table_census_is_exhaustive_and_accurate() {
        for table in FactTable::ALL {
            let is_tracked = tracked(table);
            match table {
                FactTable::Refs
                | FactTable::RefConflicts
                | FactTable::Changes
                | FactTable::ChangeHistory
                | FactTable::Workspaces
                | FactTable::WsIndex
                | FactTable::Pins => {
                    assert!(is_tracked, "expected {table:?} to be tracked");
                }
                FactTable::RemoteObservations
                | FactTable::ImportedChanges
                | FactTable::Commits
                | FactTable::Ops
                | FactTable::OpHead
                | FactTable::Claims
                | FactTable::WsStatus
                | FactTable::WsDirs
                | FactTable::Receipts
                | FactTable::Sessions
                | FactTable::Attestations
                | FactTable::PushPlans
                | FactTable::LandPlans
                | FactTable::PublishedHeads
                | FactTable::Leases
                | FactTable::WsApply
                | FactTable::Reflogs
                | FactTable::Promisor
                | FactTable::Shallow
                | FactTable::LfsObjects
                | FactTable::Events
                | FactTable::EventHead
                | FactTable::ServiceReceipts
                | FactTable::RepoMeta
                | FactTable::ReleasedTags => {
                    assert!(!is_tracked, "expected {table:?} to be untracked");
                }
            }
        }
    }

    #[test]
    fn record_no_tracked_changes_returns_none_and_leaves_counter() {
        let mut ops = CheckedOperationId::new(0, 100);

        // Untracked tables
        let untracked_changes = vec![
            FactMutation {
                table: FactTable::Receipts,
                key: vec![1, 2, 3],
                expected: FactExpectation::Absent,
                value: Some(vec![4, 5, 6]),
            },
            FactMutation {
                table: FactTable::Sessions,
                key: vec![7, 8, 9],
                expected: FactExpectation::Absent,
                value: Some(vec![10, 11, 12]),
            },
        ];
        let res = record(&mut ops, None, test_meta(), &untracked_changes).expect("record");
        assert!(res.is_none());
        assert_eq!(ops.last(), None);

        // Tracked tables with guards and identical rewrites
        let guard_changes = vec![
            FactMutation {
                table: FactTable::Refs,
                key: b"refs/heads/main".to_vec(),
                expected: FactExpectation::Absent,
                value: None, // Guard asserting absence
            },
            FactMutation {
                table: FactTable::Workspaces,
                key: vec![1; 16],
                expected: FactExpectation::Value(vec![10, 20]),
                value: Some(vec![10, 20]), // Identical rewrite
            },
        ];
        let res = record(&mut ops, None, test_meta(), &guard_changes).expect("record");
        assert!(res.is_none());
        assert_eq!(ops.last(), None);
    }

    #[test]
    fn record_rejects_any_expectation_on_tracked_tables() {
        let mut ops = CheckedOperationId::new(0, 100);

        let changes = vec![FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/main".to_vec(),
            expected: FactExpectation::Any,
            value: Some(vec![1, 2, 3]),
        }];

        let err = record(&mut ops, None, test_meta(), &changes).expect_err("reject Any");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert_eq!(ops.last(), None);
    }

    #[test]
    fn record_fails_on_checked_operation_id_exhaustion() {
        let mut ops = CheckedOperationId::new(5, 5);

        let changes = vec![FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/main".to_vec(),
            expected: FactExpectation::Absent,
            value: Some(vec![1, 2, 3]),
        }];

        let err = record(&mut ops, None, test_meta(), &changes).expect_err("exhausted");
        assert_eq!(err.code, ErrorCode::ECapacity);
        assert_eq!(ops.last(), Some(OperationId(5)));
    }

    #[test]
    fn byte_exact_roundtrip_single_and_multiple_deltas() {
        let (_temp, store) = test_store("roundtrip-single");
        let mut ops = CheckedOperationId::new(0, 100);

        let all_bytes: Vec<u8> = (0..=255).collect();
        let changes = vec![
            FactMutation {
                table: FactTable::Refs,
                key: b"refs/heads/main".to_vec(),
                expected: FactExpectation::Absent,
                value: Some(all_bytes.clone()),
            },
            FactMutation {
                table: FactTable::Workspaces,
                key: vec![0xaa; 16],
                expected: FactExpectation::Value(vec![1, 2, 3]),
                value: Some(vec![4, 5, 6]),
            },
            FactMutation {
                table: FactTable::Pins,
                key: b"pin-key".to_vec(),
                expected: FactExpectation::Value(vec![7, 8, 9]),
                value: None, // delete
            },
        ];

        let recorded = record(&mut ops, None, test_meta(), &changes)
            .expect("record")
            .expect("some mutations");

        assert_eq!(recorded.0, OperationId(1));
        assert_eq!(ops.last(), Some(OperationId(1)));

        // Publish to real store
        store.publish(Vec::new(), &recorded.1).expect("publish");

        // Read header
        let header = read_header(&store, OperationId(1))
            .expect("read header")
            .expect("header present");
        assert_eq!(header.entry.id, OperationId(1));
        assert_eq!(header.deltas, 3);
        assert_eq!(header.parts, 1);

        // Read deltas
        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);

        let d1 = reader.next_delta().expect("read d1").expect("d1 present");
        assert_eq!(d1.table, "refs");
        assert_eq!(d1.key, b"refs/heads/main");
        assert_eq!(d1.before, None);
        assert_eq!(d1.after, Some(all_bytes));

        let d2 = reader.next_delta().expect("read d2").expect("d2 present");
        assert_eq!(d2.table, "workspaces");
        assert_eq!(d2.key, vec![0xaa; 16]);
        assert_eq!(d2.before, Some(vec![1, 2, 3]));
        assert_eq!(d2.after, Some(vec![4, 5, 6]));

        let d3 = reader.next_delta().expect("read d3").expect("d3 present");
        assert_eq!(d3.table, "pins");
        assert_eq!(d3.key, b"pin-key");
        assert_eq!(d3.before, Some(vec![7, 8, 9]));
        assert_eq!(d3.after, None);

        assert!(reader.next_delta().expect("read end").is_none());
        assert!(reader.is_finished());
    }

    #[test]
    fn delta_crossing_multiple_fragment_boundaries() {
        let (_temp, store) = test_store("multi-fragment");
        let mut ops = CheckedOperationId::new(0, 100);

        // Create a large value that exceeds OP_FRAGMENT_MAX_BYTES (4 MiB)
        // 5 MiB payload to guarantee spanning 2 fragments (4 MiB + 1 MiB)
        let large_size = 5 * 1024 * 1024;
        let large_val = vec![0x7a; large_size];

        let changes = vec![FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/huge".to_vec(),
            expected: FactExpectation::Absent,
            value: Some(large_val.clone()),
        }];

        let recorded = record(&mut ops, None, test_meta(), &changes)
            .expect("record")
            .expect("recorded mutations");

        let id = recorded.0;
        let mutations = recorded.1;

        // Part 0 is header, plus fragments:
        // stream_bytes = 8-byte length prefix + delta serialization size (> 5 MiB)
        // fragments count must be exactly 2
        assert_eq!(mutations.len(), 3); // header + part 1 + part 2

        store.publish(Vec::new(), &mutations).expect("publish");

        let header = read_header(&store, id)
            .expect("read header")
            .expect("header present");
        assert_eq!(header.deltas, 1);
        assert_eq!(header.parts, 2);

        let mut reader = OpDeltaReader::new(&store, id, header);
        let delta = reader.next_delta().expect("read delta").expect("present");
        assert_eq!(delta.table, "refs");
        assert_eq!(delta.key, b"refs/heads/huge");
        assert_eq!(delta.before, None);
        assert_eq!(delta.after.expect("after").len(), large_size);
        assert!(reader.next_delta().expect("read end").is_none());
        assert!(reader.is_finished());
    }

    #[test]
    fn adversarial_unknown_table_latches_quarantine() {
        let (_temp, store) = test_store("adv-unknown-table");

        let delta = OpDelta {
            table: "non_existent_table".to_owned(),
            key: vec![1, 2, 3],
            before: None,
            after: Some(vec![4, 5]),
        };
        let delta_bytes = encode("op delta", &delta).expect("encode");
        let delta_len = delta_bytes.len() as u64;

        let mut stream = Vec::new();
        stream.extend_from_slice(&delta_len.to_be_bytes());
        stream.extend_from_slice(&delta_bytes);

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader.next_delta().expect_err("unknown table must fail");
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
    fn adversarial_untracked_table_in_stream_latches_quarantine() {
        let (_temp, store) = test_store("adv-untracked-table");

        let delta = OpDelta {
            table: "sessions".to_owned(), // Valid census table, but untracked
            key: vec![1, 2, 3],
            before: None,
            after: Some(vec![4, 5]),
        };
        let delta_bytes = encode("op delta", &delta).expect("encode");
        let delta_len = delta_bytes.len() as u64;

        let mut stream = Vec::new();
        stream.extend_from_slice(&delta_len.to_be_bytes());
        stream.extend_from_slice(&delta_bytes);

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader.next_delta().expect_err("untracked table must fail");
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
    fn adversarial_zero_delta_length_latches_quarantine() {
        let (_temp, store) = test_store("adv-zero-len");

        let mut stream = Vec::new();
        stream.extend_from_slice(&0_u64.to_be_bytes()); // 0 length announced

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader
            .next_delta()
            .expect_err("zero length delta must fail");
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
    fn adversarial_delta_length_exceeding_max_latches_quarantine() {
        let (_temp, store) = test_store("adv-oversized-len");

        let forged_len = MAX_ENCODED_DELTA_BYTES + 1;
        let mut stream = Vec::new();
        stream.extend_from_slice(&forged_len.to_be_bytes());
        stream.extend_from_slice(&[0_u8; 16]);

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader
            .next_delta()
            .expect_err("oversized delta length must fail");
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
    fn adversarial_missing_part_latches_quarantine() {
        let (_temp, store) = test_store("adv-missing-part");

        // Header claims 2 parts, but part 2 is omitted from store
        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: (OP_FRAGMENT_MAX_BYTES as u64) + 100,
            parts: 2,
        };

        let part1 = vec![0_u8; OP_FRAGMENT_MAX_BYTES];
        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(part1),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader.next_delta().expect_err("missing part must fail");
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
    fn adversarial_trailing_data_in_stream_latches_quarantine() {
        let (_temp, store) = test_store("adv-trailing-data");

        let delta = OpDelta {
            table: "refs".to_owned(),
            key: b"refs/heads/main".to_vec(),
            before: None,
            after: Some(vec![1, 2, 3]),
        };
        let delta_bytes = encode("op delta", &delta).expect("encode");
        let delta_len = delta_bytes.len() as u64;

        let mut stream = Vec::new();
        stream.extend_from_slice(&delta_len.to_be_bytes());
        stream.extend_from_slice(&delta_bytes);
        stream.extend_from_slice(b"trailing_garbage_bytes");

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1, // claims only 1 delta
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let d = reader.next_delta().expect("read delta 1").expect("present");
        assert_eq!(d.table, "refs");

        // Next delta call encounters unconsumed trailing stream bytes
        let err = reader.next_delta().expect_err("trailing bytes must fail");
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
    fn adversarial_extra_part_in_store_latches_quarantine() {
        let (_temp, store) = test_store("adv-extra-part");

        let delta = OpDelta {
            table: "refs".to_owned(),
            key: b"refs/heads/main".to_vec(),
            before: None,
            after: Some(vec![1, 2, 3]),
        };
        let delta_bytes = encode("op delta", &delta).expect("encode");
        let delta_len = delta_bytes.len() as u64;

        let mut stream = Vec::new();
        stream.extend_from_slice(&delta_len.to_be_bytes());
        stream.extend_from_slice(&delta_bytes);

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1, // Claims only 1 part
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
            // Illegal extra part 2 in store:
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 2).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(vec![1, 2, 3, 4]),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let d = reader.next_delta().expect("read delta 1").expect("present");
        assert_eq!(d.table, "refs");

        let err = reader.next_delta().expect_err("extra part must fail");
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
    fn adversarial_identical_before_after_in_stream_latches_quarantine() {
        let (_temp, store) = test_store("adv-identical-before-after");

        let delta = OpDelta {
            table: "refs".to_owned(),
            key: b"refs/heads/main".to_vec(),
            before: Some(vec![1, 2, 3]),
            after: Some(vec![1, 2, 3]), // Identical before and after!
        };
        let delta_bytes = encode("op delta", &delta).expect("encode");
        let delta_len = delta_bytes.len() as u64;

        let mut stream = Vec::new();
        stream.extend_from_slice(&delta_len.to_be_bytes());
        stream.extend_from_slice(&delta_bytes);

        let header = OpHeader {
            entry: OperationEntry {
                id: OperationId(1),
                parent: None,
                session: Some(SessionId::from_bytes([1; 16])),
                method: Method::WsTake,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
                on_behalf_of: None,
            },
            deltas: 1,
            stream_bytes: stream.len() as u64,
            parts: 1,
        };

        let mutations = vec![
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 0).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("op header", &header).expect("encode")),
            },
            FactMutation {
                table: FactTable::Ops,
                key: op_key(OperationId(1), 1).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(stream),
            },
        ];
        store.publish(Vec::new(), &mutations).expect("publish");

        let mut reader = OpDeltaReader::new(&store, OperationId(1), header);
        let err = reader
            .next_delta()
            .expect_err("identical before/after must fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert_eq!(
            store
                .fact(FactTable::OpHead, b"")
                .expect_err("quarantined")
                .code(),
            ErrorCode::ECorrupt
        );
    }
}
