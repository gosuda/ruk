//! Immutable v1 graph segment reader, writer, and binary codec.
//!
//! # Format specification (v1)
//!
//! A graph segment file is an immutable binary file consisting of fixed-size
//! headers, commit entries, lookup tables, and changed-path Bloom filter data,
//! sealed with a CRC32C checksum:
//!
//! ```text
//! [Header: 1064 bytes + parent_name_len]
//!   magic: [u8; 8] = b"RUKGRAPH"
//!   format_version: u32 = 1
//!   hash_kind: u8 (1 = SHA-1, 2 = SHA-256)
//!   reserved0: [u8; 3]
//!   parent_name_len: u32
//!   reserved1: [u8; 20]
//!   parent_name: [u8; parent_name_len]
//!   num_parent_commits: u32
//!   num_local_commits: u32
//!   num_local_change_ids: u32
//!   num_overflow_parents: u32
//!   num_overflow_change_ids: u32
//!   bloom_data_len: u32
//!   fanout: [u32; 256] (1024 bytes cumulative counts)
//! [Commit Entries: 52 * num_local_commits bytes]
//!   for each entry (in topological order):
//!     generation: u32
//!     parent1_raw: u32 (inlined global pos, or OVERFLOW_FLAG | offset)
//!     parent2_raw: u32 (inlined global pos, or OVERFLOW_FLAG | count)
//!     change_id_pos: u32 (offset in change IDs table)
//!     head_tag: u8 (0 = Git, 1 = Conflicted)
//!     head_digest: [u8; 32]
//!     reserved: [u8; 3]
//! [Head Lookup Table: 4 * num_local_commits bytes]
//!   sorted by (head_tag, head_digest), storing u32 local positions
//! [Change IDs Table: 16 * num_local_change_ids bytes]
//!   sorted by reverse-hex ascending, equivalently raw bytes descending,
//!   so exact-id and prefix lookups binary-search the same order
//! [Change ID Positions Table: 4 * num_local_change_ids bytes]
//!   inlined local pos or OVERFLOW_FLAG | offset
//! [Overflow Parents Table: 4 * num_overflow_parents bytes]
//!   consecutive u32 global positions for octopus parents
//! [Overflow Change IDs Table: 4 * num_overflow_change_ids bytes]
//!   encoded as runs: [count: u32, pos_0: u32, ..., pos_{count-1}: u32]
//! [Bloom Filter Offsets: 4 * (num_local_commits + 1) bytes]
//!   start/end offsets into bloom_data
//! [Bloom Filter Data: bloom_data_len bytes]
//! [Checksum: 4 bytes]
//!   CRC32C over all preceding bytes
//! ```

use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use crc32c::crc32c;
use smallvec::SmallVec;

use crate::budget::{ByteBudget, ByteReservation};
use crate::change::ChangeId;
use crate::error::{CoreError, ErrorCode};
use crate::graph::bloom::{build_bloom_filter, check_bloom_filter};
use crate::graph::types::{
    BloomMatch, GRAPH_SEGMENT_MAGIC, GRAPH_SEGMENT_V1_FORMAT, Generation, GlobalPosition,
    LocalPosition, MAX_GRAPH_POSITIONS, NO_PARENT, OVERFLOW_FLAG, PrefixResolution,
};
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};
use crate::store::durability::install_file;

pub(crate) const HEADER_PREFIX_LEN: usize = 40;
pub(crate) const COMMIT_ENTRY_LEN: usize = 52;
pub(crate) const MAX_SEGMENT_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[inline]
fn read_u32_at(slice: &[u8], offset: usize) -> Result<u32, CoreError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "offset overflow reading u32"))?;
    if end > slice.len() {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!(
                "slice length {} too short for u32 at offset {offset}",
                slice.len()
            ),
        ));
    }
    let bytes: [u8; 4] = slice[offset..end]
        .try_into()
        .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "failed converting slice to u32 bytes"))?;
    Ok(u32::from_le_bytes(bytes))
}

#[inline]
fn read_16_bytes_at(slice: &[u8], offset: usize) -> Result<[u8; 16], CoreError> {
    let end = offset
        .checked_add(16)
        .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "offset overflow reading 16 bytes"))?;
    if end > slice.len() {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!(
                "slice length {} too short for 16 bytes at offset {offset}",
                slice.len()
            ),
        ));
    }
    slice[offset..end]
        .try_into()
        .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "failed converting slice to 16 bytes"))
}

/// Fixed-size commit entry inside a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommitGraphEntry {
    pub(crate) generation: u32,
    pub(crate) parent1_raw: u32,
    pub(crate) parent2_raw: u32,
    pub(crate) change_id_pos: u32,
    pub(crate) head_tag: u8,
    pub(crate) head_digest: [u8; 32],
}

impl CommitGraphEntry {
    pub(crate) fn decode(bytes: &[u8; COMMIT_ENTRY_LEN]) -> Self {
        let generation = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let parent1_raw = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let parent2_raw = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let change_id_pos = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let head_tag = bytes[16];
        let mut head_digest = [0u8; 32];
        head_digest.copy_from_slice(&bytes[17..49]);
        Self {
            generation,
            parent1_raw,
            parent2_raw,
            change_id_pos,
            head_tag,
            head_digest,
        }
    }

    #[must_use]
    pub(crate) fn encode(&self) -> [u8; COMMIT_ENTRY_LEN] {
        let mut bytes = [0u8; COMMIT_ENTRY_LEN];
        bytes[0..4].copy_from_slice(&self.generation.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.parent1_raw.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.parent2_raw.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.change_id_pos.to_le_bytes());
        bytes[16] = self.head_tag;
        bytes[17..49].copy_from_slice(&self.head_digest);
        bytes
    }

    pub(crate) fn to_head(&self, kind: HashKind) -> Result<Head, CoreError> {
        match self.head_tag {
            0 => {
                let oid_len = kind.oid_len();
                let oid = Oid::from_bytes(&self.head_digest[..oid_len])
                    .map_err(|e| CoreError::new(ErrorCode::ECorrupt, e.to_string()))?;
                Ok(Head::Git { oid })
            }
            1 => {
                // Native CommitKey has fixed 32-byte identity regardless of store SHA-1
                let key = CommitKey::from_bytes(&self.head_digest[..32])
                    .map_err(|e| CoreError::new(ErrorCode::ECorrupt, e.to_string()))?;
                Ok(Head::Conflicted { key })
            }
            other => Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!("corrupt head tag in graph entry: {other}"),
            )),
        }
    }
}

/// Bounded page result for divergent change lookups.
pub(crate) struct ChangeIdPage<T> {
    pub(crate) items: SmallVec<[T; 16]>,
    pub(crate) total_count: usize,
    pub(crate) next_offset: Option<usize>,
}

/// In-memory representation of an immutable v1 graph segment.
pub(crate) struct GraphSegment {
    _reservation: ByteReservation,
    data: Vec<u8>,
    hash_kind: HashKind,
    parent_segment_name: String,
    parent_segment: Option<Arc<GraphSegment>>,
    num_parent_commits: u32,
    num_local_commits: u32,
    num_local_change_ids: u32,
    num_overflow_parents: u32,
    num_overflow_change_ids: u32,
    bloom_data_len: u32,
    fanout_offset: usize,
    entries_offset: usize,
    head_lookup_offset: usize,
    change_ids_offset: usize,
    change_id_positions_offset: usize,
    overflow_parents_offset: usize,
    overflow_change_ids_offset: usize,
    bloom_offsets_offset: usize,
    bloom_data_offset: usize,
}

impl Drop for GraphSegment {
    fn drop(&mut self) {
        // Iteratively unroll parent chain to prevent recursion stack overflow
        let mut curr = self.parent_segment.take();
        while let Some(parent) = curr {
            if let Ok(mut unique_parent) = Arc::try_unwrap(parent) {
                curr = unique_parent.parent_segment.take();
            } else {
                break;
            }
        }
    }
}

impl GraphSegment {
    /// Opens and validates an immutable graph segment from byte slice.
    pub(crate) fn open_from_bytes(
        bytes: Vec<u8>,
        expected_hash_kind: HashKind,
        parent_segment: Option<Arc<GraphSegment>>,
        budget: &Arc<ByteBudget>,
    ) -> Result<Arc<Self>, CoreError> {
        let total_size = bytes.len();
        let resident_memory = (total_size as u64) + (std::mem::size_of::<Self>() as u64);
        let reservation = budget.reserve(resident_memory)?;
        Self::open_from_reserved_bytes(bytes, reservation, expected_hash_kind, parent_segment)
    }

    /// Internal constructor using an already-reserved byte budget token.
    fn open_from_reserved_bytes(
        bytes: Vec<u8>,
        reservation: ByteReservation,
        expected_hash_kind: HashKind,
        parent_segment: Option<Arc<GraphSegment>>,
    ) -> Result<Arc<Self>, CoreError> {
        let total_size = bytes.len();
        if total_size < HEADER_PREFIX_LEN + 1024 + 4 {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!("graph segment file size {total_size} is smaller than minimum header"),
            ));
        }

        let checksum_offset = total_size - 4;
        let expected_crc = u32::from_le_bytes(
            bytes[checksum_offset..total_size]
                .try_into()
                .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "failed reading checksum"))?,
        );
        let actual_crc = crc32c(&bytes[..checksum_offset]);
        if expected_crc != actual_crc {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "graph segment checksum mismatch: expected {expected_crc:#x}, computed {actual_crc:#x}"
                ),
            ));
        }

        if bytes[..8] != GRAPH_SEGMENT_MAGIC {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "invalid graph segment magic header",
            ));
        }

        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != GRAPH_SEGMENT_V1_FORMAT {
            return Err(CoreError::new(
                ErrorCode::EVersion,
                format!("unsupported graph segment format version: {version}"),
            ));
        }

        let raw_kind = bytes[12];
        let hash_kind = match raw_kind {
            1 => HashKind::Sha1,
            2 => HashKind::Sha256,
            other => {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    format!("unsupported hash kind discriminant in segment: {other}"),
                ));
            }
        };
        if hash_kind != expected_hash_kind {
            return Err(CoreError::new(
                ErrorCode::EObjectFormat,
                format!(
                    "segment hash kind {hash_kind:?} disagrees with expected {expected_hash_kind:?}"
                ),
            ));
        }

        let parent_name_len =
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let parent_name_offset = HEADER_PREFIX_LEN;
        let parent_name_end = parent_name_offset
            .checked_add(parent_name_len)
            .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "parent name offset overflow"))?;
        if parent_name_end > checksum_offset {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "parent segment name extends beyond file length",
            ));
        }

        let parent_segment_name = std::str::from_utf8(&bytes[parent_name_offset..parent_name_end])
            .map_err(|_| {
                CoreError::new(ErrorCode::ECorrupt, "invalid UTF-8 in parent segment name")
            })?
            .to_string();

        let counts_offset = parent_name_end;
        if counts_offset + 24 > checksum_offset {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "segment counts header truncated",
            ));
        }

        let num_parent_commits = read_u32_at(&bytes, counts_offset)?;
        let num_local_commits = read_u32_at(&bytes, counts_offset + 4)?;
        let num_local_change_ids = read_u32_at(&bytes, counts_offset + 8)?;
        let num_overflow_parents = read_u32_at(&bytes, counts_offset + 12)?;
        let num_overflow_change_ids = read_u32_at(&bytes, counts_offset + 16)?;
        let bloom_data_len = read_u32_at(&bytes, counts_offset + 20)?;

        let total_commits = (num_parent_commits as u64) + (num_local_commits as u64);
        if total_commits > (MAX_GRAPH_POSITIONS as u64) {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("total indexed commits {total_commits} exceeds maximum capacity 2^31"),
            ));
        }

        if let Some(parent) = &parent_segment {
            if parent.num_total_commits() != num_parent_commits {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    format!(
                        "parent segment total commits {} does not match segment num_parent_commits {}",
                        parent.num_total_commits(),
                        num_parent_commits
                    ),
                ));
            }
        } else if num_parent_commits != 0 {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "segment claims {num_parent_commits} parent commits but no parent segment was provided"
                ),
            ));
        }

        let fanout_offset = counts_offset + 24;
        let fanout_len = 256 * 4;
        let entries_offset = fanout_offset + fanout_len;

        let entries_len = (num_local_commits as usize)
            .checked_mul(COMMIT_ENTRY_LEN)
            .ok_or_else(|| {
                CoreError::new(ErrorCode::ECapacity, "commit entries table length overflow")
            })?;
        let head_lookup_offset = entries_offset + entries_len;

        let head_lookup_len = (num_local_commits as usize).checked_mul(4).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "head lookup table length overflow")
        })?;
        let change_ids_offset = head_lookup_offset + head_lookup_len;

        let change_ids_len = (num_local_change_ids as usize)
            .checked_mul(16)
            .ok_or_else(|| {
                CoreError::new(ErrorCode::ECapacity, "change IDs table length overflow")
            })?;
        let change_id_positions_offset = change_ids_offset + change_ids_len;

        let change_id_positions_len =
            (num_local_change_ids as usize)
                .checked_mul(4)
                .ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::ECapacity,
                        "change ID positions table length overflow",
                    )
                })?;
        let overflow_parents_offset = change_id_positions_offset + change_id_positions_len;

        let overflow_parents_len =
            (num_overflow_parents as usize)
                .checked_mul(4)
                .ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::ECapacity,
                        "overflow parents table length overflow",
                    )
                })?;
        let overflow_change_ids_offset = overflow_parents_offset + overflow_parents_len;

        let overflow_change_ids_len = (num_overflow_change_ids as usize)
            .checked_mul(4)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECapacity,
                    "overflow change IDs table length overflow",
                )
            })?;
        let bloom_offsets_offset = overflow_change_ids_offset + overflow_change_ids_len;

        let bloom_offsets_len = ((num_local_commits as usize) + 1)
            .checked_mul(4)
            .ok_or_else(|| {
                CoreError::new(ErrorCode::ECapacity, "bloom offsets table length overflow")
            })?;
        let bloom_data_offset = bloom_offsets_offset + bloom_offsets_len;

        let bloom_data_len_usize = bloom_data_len as usize;
        let expected_total_bytes = bloom_data_offset
            .checked_add(bloom_data_len_usize)
            .and_then(|pos| pos.checked_add(4))
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "total segment size overflow"))?;

        if expected_total_bytes != total_size {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "computed segment size {expected_total_bytes} differs from actual size {total_size}"
                ),
            ));
        }

        Ok(Arc::new(Self {
            _reservation: reservation,
            data: bytes,
            hash_kind,
            parent_segment_name,
            parent_segment,
            num_parent_commits,
            num_local_commits,
            num_local_change_ids,
            num_overflow_parents,
            num_overflow_change_ids,
            bloom_data_len,
            fanout_offset,
            entries_offset,
            head_lookup_offset,
            change_ids_offset,
            change_id_positions_offset,
            overflow_parents_offset,
            overflow_change_ids_offset,
            bloom_offsets_offset,
            bloom_data_offset,
        }))
    }

    /// Opens an existing segment file from disk with pre-reserved memory allocation.
    pub(crate) fn open_file(
        path: &Path,
        expected_hash_kind: HashKind,
        parent_segment: Option<Arc<GraphSegment>>,
        budget: &Arc<ByteBudget>,
    ) -> Result<Arc<Self>, CoreError> {
        let mut file =
            File::open(path).map_err(|e| CoreError::new(ErrorCode::EIo, e.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|e| CoreError::new(ErrorCode::EIo, e.to_string()))?;
        let file_len = metadata.len();
        if file_len > MAX_SEGMENT_FILE_BYTES {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!(
                    "graph segment file size {file_len} exceeds maximum limit {MAX_SEGMENT_FILE_BYTES}"
                ),
            ));
        }

        // Pre-reserve memory BEFORE reading file into buffer
        let resident_memory = file_len
            .checked_add(std::mem::size_of::<Self>() as u64)
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "memory size overflow"))?;
        let reservation = budget.reserve(resident_memory)?;

        let mut bytes = Vec::with_capacity(file_len as usize);
        file.read_to_end(&mut bytes)
            .map_err(|e| CoreError::new(ErrorCode::EIo, e.to_string()))?;

        Self::open_from_reserved_bytes(bytes, reservation, expected_hash_kind, parent_segment)
    }

    #[must_use]
    pub(crate) const fn num_local_commits(&self) -> u32 {
        self.num_local_commits
    }

    #[must_use]
    pub(crate) const fn num_parent_commits(&self) -> u32 {
        self.num_parent_commits
    }

    #[must_use]
    pub(crate) const fn num_total_commits(&self) -> u32 {
        self.num_parent_commits + self.num_local_commits
    }

    #[must_use]
    pub(crate) fn parent_segment_name(&self) -> &str {
        &self.parent_segment_name
    }

    #[must_use]
    pub(crate) fn parent_segment(&self) -> Option<&Arc<GraphSegment>> {
        self.parent_segment.as_ref()
    }

    pub(crate) fn entry_at(&self, local_pos: LocalPosition) -> Result<CommitGraphEntry, CoreError> {
        let pos = local_pos.as_usize();
        if pos >= (self.num_local_commits as usize) {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                format!(
                    "local position {pos} out of range (num_local_commits = {})",
                    self.num_local_commits
                ),
            ));
        }
        let offset = self.entries_offset + pos * COMMIT_ENTRY_LEN;
        let slice: &[u8; COMMIT_ENTRY_LEN] = self.data[offset..offset + COMMIT_ENTRY_LEN]
            .try_into()
            .map_err(|_| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "failed reading commit graph entry slice",
                )
            })?;
        Ok(CommitGraphEntry::decode(slice))
    }

    pub(crate) fn head_at(&self, local_pos: LocalPosition) -> Result<Head, CoreError> {
        let entry = self.entry_at(local_pos)?;
        entry.to_head(self.hash_kind)
    }

    pub(crate) fn generation_at(&self, local_pos: LocalPosition) -> Result<Generation, CoreError> {
        let entry = self.entry_at(local_pos)?;
        Generation::new(entry.generation)
    }

    pub(crate) fn change_id_at(&self, local_pos: LocalPosition) -> Result<ChangeId, CoreError> {
        let entry = self.entry_at(local_pos)?;
        let cid_idx = entry.change_id_pos as usize;
        if cid_idx >= (self.num_local_change_ids as usize) {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "change_id_pos {cid_idx} exceeds num_local_change_ids {}",
                    self.num_local_change_ids
                ),
            ));
        }
        let offset = self.change_ids_offset + cid_idx * 16;
        let bytes = read_16_bytes_at(&self.data, offset)?;
        Ok(ChangeId::from_bytes(bytes))
    }

    pub(crate) fn parents_at(
        &self,
        local_pos: LocalPosition,
    ) -> Result<SmallVec<[GlobalPosition; 2]>, CoreError> {
        let entry = self.entry_at(local_pos)?;
        if entry.parent1_raw == NO_PARENT {
            return Ok(SmallVec::new());
        }

        if (entry.parent1_raw & OVERFLOW_FLAG) == 0 {
            let mut parents = SmallVec::new();
            parents.push(GlobalPosition::new(entry.parent1_raw)?);
            if entry.parent2_raw != NO_PARENT {
                parents.push(GlobalPosition::new(entry.parent2_raw)?);
            }
            return Ok(parents);
        }

        let overflow_offset = (entry.parent1_raw & !OVERFLOW_FLAG) as usize;
        let count = (entry.parent2_raw & !OVERFLOW_FLAG) as usize;

        let end = overflow_offset.checked_add(count).ok_or_else(|| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "overflow parents offset calculation overflow",
            )
        })?;
        if end > (self.num_overflow_parents as usize) {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "overflow parents range {overflow_offset}..{end} exceeds table length {}",
                    self.num_overflow_parents
                ),
            ));
        }

        let mut parents = SmallVec::new();
        for i in overflow_offset..end {
            let offset = self.overflow_parents_offset + i * 4;
            let raw_pos = read_u32_at(&self.data, offset)?;
            parents.push(GlobalPosition::new(raw_pos)?);
        }
        Ok(parents)
    }

    pub(crate) fn find_head(&self, head: &Head) -> Option<LocalPosition> {
        if self.num_local_commits == 0 {
            return None;
        }

        let (digest, head_tag, cmp_len) = match head {
            Head::Git { oid } => (oid.as_bytes(), 0u8, self.hash_kind.oid_len()),
            Head::Conflicted { key } => (key.as_bytes(), 1u8, 32),
        };
        let first_byte = digest[0] as usize;

        let fanout_slice = &self.data[self.fanout_offset..self.fanout_offset + 1024];
        let start = if first_byte == 0 {
            0usize
        } else {
            let prev_offset = (first_byte - 1) * 4;
            read_u32_at(fanout_slice, prev_offset).ok()? as usize
        };
        let end = {
            let curr_offset = first_byte * 4;
            read_u32_at(fanout_slice, curr_offset).ok()? as usize
        };

        if start >= end || end > (self.num_local_commits as usize) {
            return None;
        }

        let lookup_slice = &self.data[self.head_lookup_offset..];
        let mut low = start;
        let mut high = end;

        while low < high {
            let mid = low + (high - low) / 2;
            let local_pos_raw = read_u32_at(lookup_slice, mid * 4).ok()?;
            let local_pos = LocalPosition::from_raw_checked(local_pos_raw);

            let entry = self.entry_at(local_pos).ok()?;
            let cmp = match entry.head_tag.cmp(&head_tag) {
                Ordering::Equal => entry.head_digest[..cmp_len].cmp(&digest[..cmp_len]),
                other => other,
            };

            match cmp {
                Ordering::Equal => return Some(local_pos),
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid,
            }
        }

        None
    }

    /// Resumable bounded page lookup for commits associated with `change_id`.
    pub(crate) fn find_change_id_page(
        &self,
        change_id: &ChangeId,
        offset: usize,
        limit: usize,
    ) -> Result<ChangeIdPage<LocalPosition>, CoreError> {
        if self.num_local_change_ids == 0 {
            return Ok(ChangeIdPage {
                items: SmallVec::new(),
                total_count: 0,
                next_offset: None,
            });
        }

        // The table runs descending in raw bytes, ascending in reverse-hex.
        let target_bytes = change_id.as_bytes();
        let change_ids_slice = &self.data[self.change_ids_offset..];
        let mut low = 0usize;
        let mut high = self.num_local_change_ids as usize;

        let mut found_idx = None;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry_bytes = &change_ids_slice[mid * 16..mid * 16 + 16];
            match entry_bytes.cmp(target_bytes) {
                Ordering::Equal => {
                    found_idx = Some(mid);
                    break;
                }
                Ordering::Less => high = mid,
                Ordering::Greater => low = mid + 1,
            }
        }

        let Some(idx) = found_idx else {
            return Ok(ChangeIdPage {
                items: SmallVec::new(),
                total_count: 0,
                next_offset: None,
            });
        };

        let pos_offset = self.change_id_positions_offset + idx * 4;
        let raw_val = read_u32_at(&self.data, pos_offset)?;

        if (raw_val & OVERFLOW_FLAG) == 0 {
            let mut items = SmallVec::new();
            if offset == 0 && limit > 0 {
                items.push(LocalPosition::from_raw_checked(raw_val));
            }
            return Ok(ChangeIdPage {
                items,
                total_count: 1,
                next_offset: None,
            });
        }

        // Divergent change with entries in overflow table
        let overflow_offset = (raw_val & !OVERFLOW_FLAG) as usize;
        let overflow_slice = &self.data[self.overflow_change_ids_offset..];
        let count_raw = read_u32_at(overflow_slice, overflow_offset * 4)?;
        let total_count = usize::try_from(count_raw)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "overflow count exceeds usize"))?;

        if offset >= total_count {
            return Ok(ChangeIdPage {
                items: SmallVec::new(),
                total_count,
                next_offset: None,
            });
        }

        let page_limit = limit.min(64);
        let fetch_count = (total_count - offset).min(page_limit);
        let mut items = SmallVec::new();

        for i in 0..fetch_count {
            let item_offset = (overflow_offset + 1 + offset + i) * 4;
            let lpos_raw = read_u32_at(overflow_slice, item_offset)?;
            items.push(LocalPosition::from_raw_checked(lpos_raw));
        }

        let next_offset = if offset + fetch_count < total_count {
            Some(offset + fetch_count)
        } else {
            None
        };

        Ok(ChangeIdPage {
            items,
            total_count,
            next_offset,
        })
    }

    /// Indexed prefix lookup in sorted head lookup table; stops on first ambiguity.
    pub(crate) fn resolve_head_prefix(
        &self,
        prefix: &str,
    ) -> Result<PrefixResolution<Head>, CoreError> {
        if prefix.is_empty() {
            return Ok(PrefixResolution::AmbiguousMatch);
        }
        if self.num_local_commits == 0 {
            return Ok(PrefixResolution::NoMatch);
        }

        let prefix_bytes = prefix.as_bytes();
        for &b in prefix_bytes {
            if !b.is_ascii_hexdigit() {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "invalid hex character in prefix",
                ));
            }
        }

        let (start, end) = if prefix_bytes.len() >= 2 {
            let byte_val = u8::from_str_radix(&prefix[..2], 16)
                .map_err(|_| CoreError::new(ErrorCode::EInvalid, "invalid hex prefix byte"))?
                as usize;
            let fanout_slice = &self.data[self.fanout_offset..self.fanout_offset + 1024];
            let s = if byte_val == 0 {
                0usize
            } else {
                read_u32_at(fanout_slice, (byte_val - 1) * 4)? as usize
            };
            let e = read_u32_at(fanout_slice, byte_val * 4)? as usize;
            (s, e)
        } else {
            let nibble = u8::from_str_radix(&prefix[..1], 16)
                .map_err(|_| CoreError::new(ErrorCode::EInvalid, "invalid hex prefix nibble"))?
                as usize;
            let low_byte = nibble << 4;
            let high_byte = (nibble << 4) | 0x0F;
            let fanout_slice = &self.data[self.fanout_offset..self.fanout_offset + 1024];
            let s = if low_byte == 0 {
                0usize
            } else {
                read_u32_at(fanout_slice, (low_byte - 1) * 4)? as usize
            };
            let e = read_u32_at(fanout_slice, high_byte * 4)? as usize;
            (s, e)
        };

        if start >= end || end > (self.num_local_commits as usize) {
            return Ok(PrefixResolution::NoMatch);
        }

        let lookup_slice = &self.data[self.head_lookup_offset..];
        let mut matched: Option<Head> = None;

        for idx in start..end {
            let lpos_raw = read_u32_at(lookup_slice, idx * 4)?;
            let lpos = LocalPosition::from_raw_checked(lpos_raw);
            let head = self.head_at(lpos)?;
            let hex_str = match &head {
                Head::Git { oid } => oid.to_hex(),
                Head::Conflicted { key } => key.to_hex(),
            };

            if hex_str.starts_with(prefix) {
                if let Some(prev) = matched {
                    if prev != head {
                        // Stop immediately on ambiguity without scanning remainder
                        return Ok(PrefixResolution::AmbiguousMatch);
                    }
                } else {
                    matched = Some(head);
                }
            }
        }

        match matched {
            Some(h) => Ok(PrefixResolution::SingleMatch(h)),
            None => Ok(PrefixResolution::NoMatch),
        }
    }

    /// Indexed prefix lookup in sorted change IDs table; stops on ambiguity.
    pub(crate) fn resolve_change_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<PrefixResolution<ChangeId>, CoreError> {
        if prefix.is_empty() {
            return Ok(PrefixResolution::AmbiguousMatch);
        }
        if self.num_local_change_ids == 0 {
            return Ok(PrefixResolution::NoMatch);
        }

        let change_ids_slice = &self.data[self.change_ids_offset..];
        let total = self.num_local_change_ids as usize;

        // Binary search lower bound
        let mut low = 0usize;
        let mut high = total;
        while low < high {
            let mid = low + (high - low) / 2;
            let bytes = read_16_bytes_at(change_ids_slice, mid * 16)?;
            let cid = ChangeId::from_bytes(bytes);
            let hex = cid.to_reverse_hex();
            if hex.as_str() < prefix {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        let mut matched: Option<ChangeId> = None;
        for i in low..total {
            let bytes = read_16_bytes_at(change_ids_slice, i * 16)?;
            let cid = ChangeId::from_bytes(bytes);
            let hex = cid.to_reverse_hex();
            if hex.starts_with(prefix) {
                if let Some(prev) = matched {
                    if prev != cid {
                        return Ok(PrefixResolution::AmbiguousMatch);
                    }
                } else {
                    matched = Some(cid);
                }
            } else {
                break;
            }
        }

        match matched {
            Some(cid) => Ok(PrefixResolution::SingleMatch(cid)),
            None => Ok(PrefixResolution::NoMatch),
        }
    }

    #[must_use]
    pub(crate) fn bloom_filter_candidate(
        &self,
        local_pos: LocalPosition,
        path: &[u8],
    ) -> BloomMatch {
        let pos = local_pos.as_usize();
        if pos >= (self.num_local_commits as usize) {
            return BloomMatch::Candidate;
        }

        let offsets_slice = &self.data[self.bloom_offsets_offset..];
        let Ok(start_raw) = read_u32_at(offsets_slice, pos * 4) else {
            return BloomMatch::Candidate;
        };
        let Ok(end_raw) = read_u32_at(offsets_slice, (pos + 1) * 4) else {
            return BloomMatch::Candidate;
        };
        let Ok(start_offset) = usize::try_from(start_raw) else {
            return BloomMatch::Candidate;
        };
        let Ok(end_offset) = usize::try_from(end_raw) else {
            return BloomMatch::Candidate;
        };

        if start_offset > end_offset || end_offset > (self.bloom_data_len as usize) {
            return BloomMatch::Candidate;
        }

        let filter_data =
            &self.data[self.bloom_data_offset + start_offset..self.bloom_data_offset + end_offset];
        check_bloom_filter(filter_data, path)
    }
}

/// Staged commit data used to construct a new immutable graph segment.
#[derive(Clone, Debug)]
pub(crate) struct StagedCommit {
    pub(crate) head: Head,
    pub(crate) change_id: ChangeId,
    pub(crate) generation: Generation,
    pub(crate) parents: SmallVec<[GlobalPosition; 2]>,
    pub(crate) changed_paths: Vec<Vec<u8>>,
}

/// Builder that serializes staged commits into an immutable v1 segment.
pub(crate) struct GraphSegmentWriter {
    hash_kind: HashKind,
    parent_segment_name: String,
    num_parent_commits: u32,
    commits: Vec<StagedCommit>,
}

impl GraphSegmentWriter {
    #[must_use]
    pub(crate) fn new(
        hash_kind: HashKind,
        parent_segment_name: String,
        num_parent_commits: u32,
    ) -> Self {
        Self {
            hash_kind,
            parent_segment_name,
            num_parent_commits,
            commits: Vec::new(),
        }
    }

    pub(crate) fn add_commit(&mut self, commit: StagedCommit) {
        self.commits.push(commit);
    }

    pub(crate) fn build(self) -> Result<Vec<u8>, CoreError> {
        let num_local_commits = u32::try_from(self.commits.len()).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "too many local commits in segment")
        })?;

        let total_commits = (self.num_parent_commits as u64) + (num_local_commits as u64);
        if total_commits > (MAX_GRAPH_POSITIONS as u64) {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("total indexed commits {total_commits} exceeds maximum capacity 2^31"),
            ));
        }

        let mut change_map: std::collections::BTreeMap<ChangeId, Vec<u32>> =
            std::collections::BTreeMap::new();
        for (i, commit) in self.commits.iter().enumerate() {
            change_map
                .entry(commit.change_id)
                .or_default()
                .push(i as u32);
        }

        let num_local_change_ids = u32::try_from(change_map.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "too many change IDs in segment"))?;

        let mut overflow_parents = Vec::new();
        let mut entries = Vec::with_capacity(self.commits.len());

        // The on-disk change IDs table is emitted in reverse map order, so
        // each commit's change_pos is its rank in that reversed order.
        let change_rank: std::collections::BTreeMap<ChangeId, u32> = change_map
            .keys()
            .rev()
            .enumerate()
            .map(|(rank, cid)| {
                (
                    *cid,
                    u32::try_from(rank).expect("bounded by num_local_change_ids check"),
                )
            })
            .collect();

        for commit in &self.commits {
            let change_pos = change_rank
                .get(&commit.change_id)
                .copied()
                .expect("rank covers every staged change id");

            let (p1_raw, p2_raw) = match commit.parents.len() {
                0 => (NO_PARENT, NO_PARENT),
                1 => (commit.parents[0].as_u32(), NO_PARENT),
                2 => (commit.parents[0].as_u32(), commit.parents[1].as_u32()),
                _ => {
                    let overflow_offset = u32::try_from(overflow_parents.len()).map_err(|_| {
                        CoreError::new(ErrorCode::ECapacity, "overflow parents count exceeded")
                    })?;
                    let num_parents = u32::try_from(commit.parents.len()).map_err(|_| {
                        CoreError::new(ErrorCode::ECapacity, "parent count exceeded")
                    })?;
                    for p in &commit.parents {
                        overflow_parents.push(p.as_u32());
                    }
                    (OVERFLOW_FLAG | overflow_offset, OVERFLOW_FLAG | num_parents)
                }
            };

            let head_tag = match commit.head {
                Head::Git { .. } => 0u8,
                Head::Conflicted { .. } => 1u8,
            };
            let mut head_digest = [0u8; 32];
            let digest_src = match &commit.head {
                Head::Git { oid } => oid.as_bytes(),
                Head::Conflicted { key } => key.as_bytes(),
            };
            head_digest[..digest_src.len()].copy_from_slice(digest_src);

            entries.push(CommitGraphEntry {
                generation: commit.generation.as_u32(),
                parent1_raw: p1_raw,
                parent2_raw: p2_raw,
                change_id_pos: change_pos,
                head_tag,
                head_digest,
            });
        }

        let num_overflow_parents = u32::try_from(overflow_parents.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "too many overflow parents"))?;

        let mut head_sort_indices: Vec<u32> = (0..num_local_commits).collect();
        let oid_len = self.hash_kind.oid_len();
        head_sort_indices.sort_by(|&a, &b| {
            let ea = &entries[a as usize];
            let eb = &entries[b as usize];
            match ea.head_tag.cmp(&eb.head_tag) {
                Ordering::Equal => {
                    let cmp_len = if ea.head_tag == 0 { oid_len } else { 32 };
                    ea.head_digest[..cmp_len].cmp(&eb.head_digest[..cmp_len])
                }
                other => other,
            }
        });

        let mut fanout = [0u32; 256];
        for &idx in &head_sort_indices {
            let entry = &entries[idx as usize];
            let first_byte = entry.head_digest[0] as usize;
            fanout[first_byte] += 1;
        }
        let mut cumulative = 0u32;
        for count in &mut fanout {
            cumulative += *count;
            *count = cumulative;
        }

        let mut change_id_bytes = Vec::with_capacity(change_map.len() * 16);
        let mut change_id_positions = Vec::with_capacity(change_map.len());
        let mut overflow_change_ids = Vec::new();

        for (cid, positions) in change_map.iter().rev() {
            change_id_bytes.extend_from_slice(cid.as_bytes());
            if positions.len() == 1 {
                change_id_positions.push(positions[0]);
            } else {
                let overflow_offset = u32::try_from(overflow_change_ids.len()).map_err(|_| {
                    CoreError::new(ErrorCode::ECapacity, "overflow change IDs count exceeded")
                })?;
                overflow_change_ids.push(positions.len() as u32);
                overflow_change_ids.extend_from_slice(positions);
                change_id_positions.push(OVERFLOW_FLAG | overflow_offset);
            }
        }

        let num_overflow_change_ids = u32::try_from(overflow_change_ids.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "too many overflow change IDs"))?;

        let mut bloom_offsets = Vec::with_capacity(self.commits.len() + 1);
        let mut bloom_data = Vec::new();
        bloom_offsets.push(0u32);

        for commit in &self.commits {
            let path_refs: Vec<&[u8]> = commit.changed_paths.iter().map(|p| p.as_slice()).collect();
            let filter_bytes = build_bloom_filter(&path_refs);
            bloom_data.extend_from_slice(&filter_bytes);
            let next_offset = u32::try_from(bloom_data.len()).map_err(|_| {
                CoreError::new(ErrorCode::ECapacity, "bloom filter data size overflow")
            })?;
            bloom_offsets.push(next_offset);
        }

        let bloom_data_len = u32::try_from(bloom_data.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "bloom data length exceeds u32"))?;

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&GRAPH_SEGMENT_MAGIC);
        buffer.extend_from_slice(&GRAPH_SEGMENT_V1_FORMAT.to_le_bytes());
        buffer.push(match self.hash_kind {
            HashKind::Sha1 => 1,
            HashKind::Sha256 => 2,
        });
        buffer.extend_from_slice(&[0u8; 3]);

        let parent_name_bytes = self.parent_segment_name.as_bytes();
        let parent_name_len = u32::try_from(parent_name_bytes.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "parent name too long"))?;
        buffer.extend_from_slice(&parent_name_len.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 20]);
        buffer.extend_from_slice(parent_name_bytes);

        buffer.extend_from_slice(&self.num_parent_commits.to_le_bytes());
        buffer.extend_from_slice(&num_local_commits.to_le_bytes());
        buffer.extend_from_slice(&num_local_change_ids.to_le_bytes());
        buffer.extend_from_slice(&num_overflow_parents.to_le_bytes());
        buffer.extend_from_slice(&num_overflow_change_ids.to_le_bytes());
        buffer.extend_from_slice(&bloom_data_len.to_le_bytes());

        for val in fanout {
            buffer.extend_from_slice(&val.to_le_bytes());
        }

        for entry in entries {
            buffer.extend_from_slice(&entry.encode());
        }

        for idx in head_sort_indices {
            buffer.extend_from_slice(&idx.to_le_bytes());
        }

        buffer.extend_from_slice(&change_id_bytes);

        for pos in change_id_positions {
            buffer.extend_from_slice(&pos.to_le_bytes());
        }

        for p in overflow_parents {
            buffer.extend_from_slice(&p.to_le_bytes());
        }

        for c in overflow_change_ids {
            buffer.extend_from_slice(&c.to_le_bytes());
        }

        for off in bloom_offsets {
            buffer.extend_from_slice(&off.to_le_bytes());
        }

        buffer.extend_from_slice(&bloom_data);

        let checksum = crc32c(&buffer);
        buffer.extend_from_slice(&checksum.to_le_bytes());

        Ok(buffer)
    }

    pub(crate) fn install_to_disk(self, target_path: &Path) -> Result<(), CoreError> {
        let bytes = self.build()?;
        install_file(target_path, |file| {
            file.write_all(&bytes)?;
            Ok(())
        })
        .map_err(|e| CoreError::new(ErrorCode::EIo, e.to_string()))
    }
}
