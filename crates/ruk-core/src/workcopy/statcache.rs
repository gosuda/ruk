//! The stat cache: the full stat tuple, the blob it was hashed to, and the
//! racy flag that decides whether an unchanged tuple may be trusted.
//!
//! Trust rule: a path is clean without hashing only when its cached row is
//! not racy, its full tuple (ctime, mtime, dev, ino, uid, gid, size, mode)
//! equals the current one, and the current timestamps are not in the
//! future. A row is racy when either recorded timestamp falls within one
//! filesystem timestamp tick of the moment the observation was made, or
//! after it: a later same-tick edit could then keep the tuple unchanged.
//! Racy rows are rehashed at the next snapshot, which may clear the flag.

use std::fs::Metadata;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::watcher::WatchToken;
use crate::ids::Oid;
use crate::index::{FileMode, StatData, StatTime};
use crate::store::{Store, StoreError};
use crate::{CoreError, ErrorCode};

const NANOS_PER_SEC: u32 = 1_000_000_000;

/// The stat tuple as the filesystem reported it, plus the raw mode bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct FileStat {
    pub(crate) data: StatData,
    pub(crate) mode: u32,
}

impl FileStat {
    /// Reads the tuple from metadata taken without following symlinks.
    ///
    /// POSIX reports every field. Other platforms have no portable device,
    /// inode, or owner, so those fields are zero; the creation time stands in
    /// for ctime and the mode is synthesized from the file type.
    ///
    /// # Errors
    /// `E_INVALID` when a timestamp is not representable.
    pub(crate) fn from_metadata(meta: &Metadata) -> Result<Self, CoreError> {
        platform_stat(meta)
    }
}

#[cfg(unix)]
fn platform_stat(meta: &Metadata) -> Result<FileStat, CoreError> {
    use std::os::unix::fs::MetadataExt;
    Ok(FileStat {
        data: StatData {
            ctime: unix_time(meta.ctime(), meta.ctime_nsec())?,
            mtime: unix_time(meta.mtime(), meta.mtime_nsec())?,
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.size(),
        },
        mode: meta.mode(),
    })
}

#[cfg(unix)]
fn unix_time(secs: i64, nsec: i64) -> Result<StatTime, CoreError> {
    let nanos = u32::try_from(nsec)
        .ok()
        .filter(|nanos| *nanos < NANOS_PER_SEC)
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                format!("filesystem reported {nsec} nanoseconds"),
            )
        })?;
    Ok(StatTime { secs, nanos })
}

#[cfg(not(unix))]
fn platform_stat(meta: &Metadata) -> Result<FileStat, CoreError> {
    let mtime = system_time(
        meta.modified()
            .map_err(|err| super::io_error("reading a modification time", &err))?,
    )?;
    let ctime = match meta.created() {
        Ok(created) => system_time(created)?,
        Err(_) => mtime,
    };
    let file_type = meta.file_type();
    let mode = if file_type.is_symlink() {
        0o120_000
    } else if file_type.is_dir() {
        0o040_000
    } else {
        0o100_644
    };
    Ok(FileStat {
        data: StatData {
            ctime,
            mtime,
            dev: 0,
            ino: 0,
            uid: 0,
            gid: 0,
            size: meta.len(),
        },
        mode,
    })
}

/// Converts a wall-clock time to a [`StatTime`], before or after the epoch.
///
/// # Errors
/// `E_INVALID` when the time is beyond the `i64` second range.
pub(crate) fn system_time(time: SystemTime) -> Result<StatTime, CoreError> {
    let out_of_range = || {
        CoreError::new(
            ErrorCode::EInvalid,
            "timestamp is out of the supported range",
        )
    };
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => Ok(StatTime {
            secs: i64::try_from(after.as_secs()).map_err(|_| out_of_range())?,
            nanos: after.subsec_nanos(),
        }),
        Err(before) => {
            let before = before.duration();
            let secs = i64::try_from(before.as_secs()).map_err(|_| out_of_range())?;
            if before.subsec_nanos() == 0 {
                return Ok(StatTime {
                    secs: -secs,
                    nanos: 0,
                });
            }
            Ok(StatTime {
                secs: -secs - 1,
                nanos: NANOS_PER_SEC - before.subsec_nanos(),
            })
        }
    }
}

fn total_nanos(time: StatTime) -> i128 {
    i128::from(time.secs) * i128::from(NANOS_PER_SEC) + i128::from(time.nanos)
}

/// The moment an observation was made and the filesystem's timestamp
/// granularity. Sample it before the first stat of a pass: a file changed
/// during the pass then carries a timestamp at or after `now` and is racy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StatClock {
    now: StatTime,
    resolution_ns: u64,
}

impl StatClock {
    /// The granularity assumed when the filesystem's is unknown: FAT's two
    /// seconds, the coarsest supported, so no coarse timestamp is trusted.
    pub(crate) const COARSE_RESOLUTION_NS: u64 = 2_000_000_000;

    /// # Errors
    /// `E_INVALID` when `now.nanos` is not below 1e9.
    pub(crate) fn new(now: StatTime, resolution_ns: u64) -> Result<Self, CoreError> {
        if now.nanos >= NANOS_PER_SEC {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "observation time nanoseconds must be below 1e9",
            ));
        }
        Ok(Self { now, resolution_ns })
    }

    /// The current system time with the given granularity.
    ///
    /// # Errors
    /// `E_INVALID` when the system clock is out of range.
    pub(crate) fn system(resolution_ns: u64) -> Result<Self, CoreError> {
        Self::new(system_time(SystemTime::now())?, resolution_ns)
    }

    /// Whether a tuple observed at this clock cannot later be trusted
    /// unchanged: either timestamp is within one tick of `now` or after it.
    #[must_use]
    pub(crate) fn is_racy(&self, stat: &FileStat) -> bool {
        let floor = total_nanos(self.now) - i128::from(self.resolution_ns);
        total_nanos(stat.data.mtime) >= floor || total_nanos(stat.data.ctime) >= floor
    }

    /// Whether either timestamp is after `now`.
    #[must_use]
    pub(crate) fn is_future(&self, stat: &FileStat) -> bool {
        let now = total_nanos(self.now);
        total_nanos(stat.data.mtime) > now || total_nanos(stat.data.ctime) > now
    }
}

/// One `ws_status` path row: what the bytes at the path hashed to when this
/// tuple was observed, and the rendered conflict the materializer wrote
/// there, if any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatusRow {
    pub(crate) stat: FileStat,
    pub(crate) mode: FileMode,
    pub(crate) blob: Oid,
    pub(crate) racy: bool,
    pub(crate) conflict: Option<Oid>,
}

impl StatusRow {
    /// A row for bytes hashed to `blob` under `stat`. `stable` is false when
    /// the tuple moved while the bytes were read; such a row is always racy.
    #[must_use]
    pub(crate) fn observed(
        stat: FileStat,
        mode: FileMode,
        blob: Oid,
        stable: bool,
        clock: &StatClock,
        conflict: Option<Oid>,
    ) -> Self {
        Self {
            stat,
            mode,
            blob,
            racy: !stable || clock.is_racy(&stat),
            conflict,
        }
    }
}

/// The `ws_status` meta row: the tree the worktree mirrors, except for paths
/// reported dirty since `token`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatusMeta {
    pub(crate) tree: Oid,
    pub(crate) token: WatchToken,
}

/// What the cache says about one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trust {
    /// The bytes are known without reading them.
    Clean { blob: Oid, mode: FileMode },
    /// The bytes must be hashed.
    Rehash,
}

/// Applies the trust rule to a cached row and the current tuple.
#[must_use]
pub(crate) fn trust(cached: Option<&StatusRow>, current: &FileStat, clock: &StatClock) -> Trust {
    match cached {
        Some(row) if !row.racy && row.stat == *current && !clock.is_future(current) => {
            Trust::Clean {
                blob: row.blob,
                mode: row.mode,
            }
        }
        _ => Trust::Rehash,
    }
}

/// Encodes a cache row with the store's metadata codec.
///
/// # Errors
/// `E_INVALID` if the value cannot be encoded.
pub(crate) fn encode_row<T: Serialize>(what: &str, value: &T) -> Result<Vec<u8>, CoreError> {
    crate::store::encode(what, value).map_err(CoreError::from)
}

/// Decodes a cache row; a malformed row is committed corruption and latches
/// the store's quarantine.
///
/// # Errors
/// `E_CORRUPT` for malformed bytes.
pub(crate) fn decode_row<T: serde::de::DeserializeOwned>(
    store: &Store,
    what: &str,
    bytes: &[u8],
) -> Result<T, CoreError> {
    store
        .observe(crate::store::decode(what, bytes))
        .map_err(CoreError::from)
}

/// Reports corrupt committed cache state: latches the store's quarantine
/// and returns `E_CORRUPT`. `observe` returns its input, so the `Ok` arm is
/// unreachable in content but required for totality.
#[must_use]
pub(crate) fn corrupt(store: &Store, detail: String) -> CoreError {
    match store.observe::<()>(Err(StoreError::Corrupt(detail))) {
        Err(err) => CoreError::from(err),
        Ok(()) => CoreError::new(ErrorCode::ECorrupt, "committed workcopy cache is corrupt"),
    }
}
