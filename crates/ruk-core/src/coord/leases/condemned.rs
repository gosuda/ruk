//! Bounded immutable condemned-set file membership for collection.
//!
//! The collector builds the candidate set outside the registry lock with
//! [`CondemnedBuilder`] and seals it into an immutable [`CondemnedSet`].
//! Membership consults a small charged in-memory block index plus at most one
//! block read from the scratch file, so lookups never hold the registry mutex
//! and never scan the whole set. Every byte is reserved from the
//! caller-supplied [`ByteBudget`] before it exists; refusal is `E_LIMIT`.
//!
//! v1 record layout (fixed [`RECORD_LEN`] bytes, bytewise sorted):
//! `[tag:1][digest_len:1][digest:32 zero-padded]`. Tag `0` is a Git object,
//! `1` is a conflicted native commit. Blocks hold [`BLOCK_RECORDS`] records;
//! the index stores the first record of every block.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use uuid::Uuid;

use crate::budget::{ByteBudget, ByteReservation};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;

/// v1 condemned record length: tag + digest length + 32-byte zero-padded digest.
pub(crate) const RECORD_LEN: usize = 34;

/// Records per lookup block: 128 records read as one ~4 KiB page.
pub(crate) const BLOCK_RECORDS: usize = 128;

/// Bytes per lookup block.
pub(crate) const BLOCK_LEN: usize = RECORD_LEN * BLOCK_RECORDS;

/// Tag byte for a Git object record.
const TAG_GIT: u8 = 0;

/// Tag byte for a conflicted native commit record.
const TAG_CONFLICTED: u8 = 1;

/// Scratch file name prefix for sealed condemned sets.
const CONDEMNED_PREFIX: &str = "condemned-";

/// Encodes one root identity as a fixed v1 record.
#[must_use]
pub(crate) fn encode_record(head: &Head) -> [u8; RECORD_LEN] {
    let mut record = [0_u8; RECORD_LEN];
    let (tag, digest) = match head {
        Head::Git { oid } => (TAG_GIT, oid.as_bytes()),
        Head::Conflicted { key } => (TAG_CONFLICTED, key.as_bytes()),
    };
    record[0] = tag;
    // Digest widths are 20 or 32 by construction; the length byte keeps the
    // two widths distinct under bytewise order.
    let len = u8::try_from(digest.len()).unwrap_or(u8::MAX);
    record[1] = len;
    record[2..2 + digest.len()].copy_from_slice(digest);
    record
}

/// Converts a precise byte count into the budget charge form.
fn charge_len(len: usize) -> Result<u64, CoreError> {
    u64::try_from(len)
        .map_err(|_| CoreError::new(ErrorCode::ECapacity, "condemned size overflows u64"))
}

/// Reserves `bytes` from `books` before the bytes exist.
fn reserve_before(books: &Arc<ByteBudget>, bytes: u64) -> Result<ByteReservation, CoreError> {
    books.reserve(bytes).map_err(|refused| {
        CoreError::new(
            ErrorCode::ELimit,
            format!("condemned budget refused: {refused}"),
        )
    })
}

/// Builder collecting candidate condemned roots outside the registry lock.
///
/// Every push reserves exactly [`RECORD_LEN`] bytes before the record exists.
/// Refusal poisons the builder against further input and reports `E_LIMIT`.
pub(crate) struct CondemnedBuilder {
    books: Arc<ByteBudget>,
    scratch_dir: PathBuf,
    records: Vec<[u8; RECORD_LEN]>,
    charges: Vec<ByteReservation>,
    failed: bool,
}

impl CondemnedBuilder {
    /// Starts an empty candidate; performs no I/O and reserves nothing yet.
    #[must_use]
    pub(crate) fn new(books: &Arc<ByteBudget>, scratch_dir: &Path) -> Self {
        Self {
            books: Arc::clone(books),
            scratch_dir: scratch_dir.to_path_buf(),
            records: Vec::new(),
            charges: Vec::new(),
            failed: false,
        }
    }

    /// Appends one root identity, reserving its exact record bytes first.
    pub(crate) fn push(&mut self, head: &Head) -> Result<(), CoreError> {
        if self.failed {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "condemned builder already failed",
            ));
        }
        let record_charge = charge_len(RECORD_LEN)?;
        match reserve_before(&self.books, record_charge) {
            Ok(charge) => {
                self.records.push(encode_record(head));
                self.charges.push(charge);
                Ok(())
            }
            Err(err) => {
                self.failed = true;
                Err(err)
            }
        }
    }

    /// Whether no record has been pushed.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Sorts, deduplicates, writes the sealed file, and builds the charged
    /// block index. File I/O runs here, outside any registry lock.
    pub(crate) fn seal(mut self, cycle: u64) -> Result<CondemnedSet, CoreError> {
        if self.failed {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "condemned builder already failed",
            ));
        }
        self.records.sort_unstable();
        self.records.dedup();
        // Return unused duplicate charges before sizing the index: only live
        // records keep their file charge.
        let live = self.records.len();
        self.charges.truncate(live);
        let index_len = self.records.len().div_ceil(BLOCK_RECORDS);
        let index_bytes = charge_len(index_len.checked_mul(RECORD_LEN).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "condemned index size overflows")
        })?)?;
        let index_charge = reserve_before(&self.books, index_bytes)?;
        let mut index = Vec::with_capacity(index_len);
        for chunk in self.records.chunks(BLOCK_RECORDS) {
            let first = chunk.first().ok_or_else(|| {
                CoreError::new(ErrorCode::ECorrupt, "condemned chunk lost its first record")
            })?;
            index.push(*first);
        }
        let path = write_sealed_file(&self.scratch_dir, &self.records)?;
        let len = u64::try_from(self.records.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "condemned set overflows u64"))?;
        Ok(CondemnedSet {
            path,
            index,
            file_charges: std::mem::take(&mut self.charges),
            _index_charge: Some(index_charge),
            len,
            cycle,
        })
    }
}

/// Writes sorted records to a uniquely named scratch file.
fn write_sealed_file(dir: &Path, records: &[[u8; RECORD_LEN]]) -> Result<PathBuf, CoreError> {
    fs::create_dir_all(dir).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("condemned scratch dir failed: {err}"),
        )
    })?;
    for _ in 0..8 {
        let path = dir.join(format!("{CONDEMNED_PREFIX}{}.tmp", Uuid::new_v4().simple()));
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    format!("condemned file create failed: {err}"),
                ));
            }
        };
        use std::io::Write as _;
        for record in records {
            if let Err(err) = file.write_all(record) {
                let _ = fs::remove_file(&path);
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    format!("condemned file write failed: {err}"),
                ));
            }
        }
        return Ok(path);
    }
    Err(CoreError::new(
        ErrorCode::EIo,
        "condemned file could not take a unique name",
    ))
}

/// Immutable sealed condemned set: scratch file plus charged block index.
///
/// `contains` takes `&self` and performs at most one block read through a
/// freshly opened file handle, so concurrent lookups never touch the registry
/// mutex. Callers must revalidate `(phase, cycle)` under the registry lock
/// after any lookup that performed I/O.
pub(crate) struct CondemnedSet {
    path: PathBuf,
    index: Vec<[u8; RECORD_LEN]>,
    file_charges: Vec<ByteReservation>,
    _index_charge: Option<ByteReservation>,
    len: u64,
    cycle: u64,
}

impl CondemnedSet {
    /// An empty set bound to `cycle`: no file, no I/O, never a member.
    /// Reserves nothing because an empty index and zero records charge zero.
    #[must_use]
    pub(crate) fn empty(cycle: u64) -> Self {
        Self {
            path: PathBuf::new(),
            index: Vec::new(),
            file_charges: Vec::new(),
            _index_charge: None,
            len: 0,
            cycle,
        }
    }

    /// The collection cycle this set was sealed for.
    #[must_use]
    pub(crate) fn cycle(&self) -> u64 {
        self.cycle
    }

    /// Number of distinct condemned roots.
    #[must_use]
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Whether the set holds no roots.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Real membership: binary-search the block index in memory, then read at
    /// most one block from the scratch file. Empty sets answer without I/O.
    pub(crate) fn contains(&self, head: &Head) -> Result<bool, CoreError> {
        if self.len == 0 {
            return Ok(false);
        }
        let needle = encode_record(head);
        let mut low = 0_usize;
        let mut high = self.index.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let slot = self.index.get(mid).ok_or_else(|| {
                CoreError::new(ErrorCode::ECorrupt, "condemned index mid out of bounds")
            })?;
            match slot.cmp(&needle) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok(true),
            }
        }
        // `low` is the first block starting above the needle; the needle can
        // only hide in the preceding block.
        let Some(block) = low.checked_sub(1) else {
            return Ok(false);
        };
        let block_u64 = u64::try_from(block)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "condemned block overflows u64"))?;
        let block_len = u64::try_from(BLOCK_LEN).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "condemned block size overflows u64")
        })?;
        let offset = block_u64.checked_mul(block_len).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "condemned block offset overflows")
        })?;
        let mut file = std::fs::File::open(&self.path).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("condemned block open failed: {err}"),
            )
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("condemned block seek failed: {err}"),
            )
        })?;
        let file_len = file
            .metadata()
            .map_err(|err| CoreError::new(ErrorCode::EIo, format!("condemned stat failed: {err}")))?
            .len();
        // Fail closed on any truncation or extension: a partial trailing
        // record must never read as absent and grant a condemned root.
        let record_len = u64::try_from(RECORD_LEN).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "condemned record size overflows u64")
        })?;
        let expected = self.len.checked_mul(record_len).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "condemned file size overflows u64")
        })?;
        if file_len != expected {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "condemned file length disagrees with its sealed count",
            ));
        }
        let want = file_len.saturating_sub(offset).min(block_len);
        let want = usize::try_from(want).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "condemned block size overflows usize")
        })?;
        let mut buf = vec![0_u8; want];
        file.read_exact(&mut buf).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("condemned block read failed: {err}"),
            )
        })?;
        Ok(buf.chunks_exact(RECORD_LEN).any(|chunk| chunk == needle))
    }
}

impl std::fmt::Debug for CondemnedSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CondemnedSet")
            .field("len", &self.len)
            .field("cycle", &self.cycle)
            .field("blocks", &self.index.len())
            .finish_non_exhaustive()
    }
}

impl Drop for CondemnedSet {
    fn drop(&mut self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        // Best-effort unlink of our own file. Leftovers stay charged through
        // the budget reservations above and the store's scratch baseline scan
        // re-charges them on reopen; the registry never deletes anything else.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Oid;

    fn books() -> Arc<ByteBudget> {
        ByteBudget::new(1 << 20)
    }

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("ruk-leases-test-{}", Uuid::new_v4().simple()))
    }

    fn git_head(byte: u8) -> Head {
        let digest = [byte; 20];
        Head::Git {
            oid: Oid::from_bytes(&digest).expect("20-byte digest"),
        }
    }

    #[test]
    fn empty_set_contains_nothing_without_io() {
        let set = CondemnedSet::empty(3);
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.cycle(), 3);
        assert!(!set.contains(&git_head(1)).expect("lookup"));
    }

    #[test]
    fn seal_sorts_dedupes_and_finds_members() {
        let books = books();
        let dir = scratch();
        let mut builder = CondemnedBuilder::new(&books, &dir);
        builder.push(&git_head(9)).expect("push");
        builder.push(&git_head(1)).expect("push");
        builder.push(&git_head(9)).expect("duplicate push");
        let set = builder.seal(11).expect("seal");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&git_head(9)).expect("member"));
        assert!(set.contains(&git_head(1)).expect("member"));
        assert!(!set.contains(&git_head(2)).expect("nonmember"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiblock_set_searches_blocks_and_partial_tail() {
        let books = books();
        let dir = scratch();
        let mut builder = CondemnedBuilder::new(&books, &dir);
        // 300 members: two full 128-record blocks plus a 44-record tail.
        for n in 0..300_u32 {
            let mut digest = [0_u8; 20];
            digest[..4].copy_from_slice(&n.to_le_bytes());
            builder
                .push(&Head::Git {
                    oid: Oid::from_bytes(&digest).expect("20-byte digest"),
                })
                .expect("push");
        }
        let set = builder.seal(5).expect("seal");
        // Member at the start of the second block (index 128).
        let mut digest = [0_u8; 20];
        digest[..4].copy_from_slice(&128_u32.to_le_bytes());
        let block_start = Head::Git {
            oid: Oid::from_bytes(&digest).expect("20-byte digest"),
        };
        assert!(set.contains(&block_start).expect("block start member"));
        // Member inside the partial tail (index 299).
        let mut digest = [0_u8; 20];
        digest[..4].copy_from_slice(&299_u32.to_le_bytes());
        let tail = Head::Git {
            oid: Oid::from_bytes(&digest).expect("20-byte digest"),
        };
        assert!(set.contains(&tail).expect("tail member"));
        // Absent needle between member keys.
        let mut digest = [0_u8; 20];
        digest[..4].copy_from_slice(&300_u32.to_le_bytes());
        let absent = Head::Git {
            oid: Oid::from_bytes(&digest).expect("20-byte digest"),
        };
        assert!(!set.contains(&absent).expect("nonmember"));
        assert_eq!(set.len(), 300);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_file_removed_with_set_drop() {
        let books = books();
        let dir = scratch();
        let mut builder = CondemnedBuilder::new(&books, &dir);
        builder.push(&git_head(3)).expect("push");
        let set = builder.seal(6).expect("seal");
        let path = set.path.clone();
        assert!(path.exists());
        drop(set);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn budget_refusal_fails_push_before_allocation() {
        let books = Arc::new(ByteBudget::new(0));
        let dir = scratch();
        let mut builder = CondemnedBuilder::new(&books, &dir);
        let err = builder.push(&git_head(1)).expect_err("zero budget refuses");
        assert_eq!(err.code, ErrorCode::ELimit);
        assert!(builder.is_empty());
    }

    #[test]
    fn width_mismatch_encodes_distinctly() {
        let sha1 = git_head(4);
        let digest32 = [4_u8; 32];
        let sha256 = Head::Git {
            oid: Oid::from_bytes(&digest32).expect("32-byte digest"),
        };
        assert_ne!(encode_record(&sha1), encode_record(&sha256));
    }
}
