//! Git LFS payload sidecar: content-addressed payload bytes outside the object graph.
//!
//! An LFS oid is always sha256 (pointer spec) while the store keys objects
//! by Git [`Oid`](crate::ids::Oid) whose width follows `object_format`, so a
//! payload cannot be a first-class blob without an identity lie. Payloads
//! therefore live in `<store>/lfs/objects/<aa>/<bb>/<sha256-hex>`, mirroring
//! `.git/lfs/objects/` so `ruk migrate` can copy verbatim, with presence
//! tracked in the [`FactTable::LfsObjects`](super::types::FactTable) table as
//! postcard-encoded [`LfsObjectRecord`] rows keyed by the 64 hex digits.
//!
//! All writes are atomic per object (temp file + rename + one fact-row
//! publication); there is no cross-object transaction. A bad download is
//! staged-bytes failure — the temp file is discarded and store quarantine
//! never latches.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::error::StoreError;
use super::types::{FactExpectation, FactMutation, FactTable};

/// Payload presence row: declared size and whether the sidecar file has
/// been hash-verified. `complete=false` rows mark pointers whose payload
/// is known but absent (push arrived before the payload, or a fetch
/// failed); they are never fatal to the push.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LfsObjectRecord {
    /// Declared payload byte size from the pointer's `size` line.
    pub size: u64,
    /// The sidecar file exists and verified against sha256 + size.
    pub complete: bool,
}

/// Whether `hex` is a canonical LFS identity: exactly 64 ASCII hex digits.
#[must_use]
pub fn valid_oid_hex(hex: &str) -> bool {
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The sidecar path for `hex` under `store_root`, or `None` for a
/// non-canonical identity (rejected before any I/O).
#[must_use]
pub fn sidecar_path(store_root: &Path, hex: &str) -> Option<PathBuf> {
    if !valid_oid_hex(hex) {
        return None;
    }
    Some(
        store_root
            .join("lfs")
            .join("objects")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(hex),
    )
}

/// The fact-row key for `hex`: the 64 hex digit bytes.
#[must_use]
pub fn record_key(hex: &str) -> Vec<u8> {
    hex.as_bytes().to_vec()
}

/// Encodes one presence row for the fact table.
#[must_use]
pub fn encode_record(record: &LfsObjectRecord) -> Vec<u8> {
    postcard::to_allocvec(record).expect("LfsObjectRecord encodes")
}

/// Decodes one presence row, or `None` for foreign bytes.
#[must_use]
pub fn decode_record(bytes: &[u8]) -> Option<LfsObjectRecord> {
    postcard::from_bytes(bytes).ok()
}

/// One unconditional fact-row publication for `hex`.
#[must_use]
pub fn upsert_mutation(hex: &str, record: &LfsObjectRecord) -> FactMutation {
    FactMutation {
        table: FactTable::LfsObjects,
        key: record_key(hex),
        expected: FactExpectation::Any,
        value: Some(encode_record(record)),
    }
}

/// Streams `path` through sha256, returning `(hex, bytes)`.
fn hash_file(path: &Path) -> Result<(String, u64), StoreError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut chunk = [0_u8; 65536];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        size += u64::try_from(read)
            .map_err(|_| StoreError::Invalid("file read exceeds u64".to_owned()))?;
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
        hex.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("hex digit"));
    }
    Ok((hex, size))
}

/// Whether the sidecar file for `hex` exists with matching sha256 and
/// `size`. A missing file, an I/O failure, or any mismatch reads as
/// absent — never an error — so reconciliation treats unverified payloads
/// as work to do, not damage.
#[must_use]
pub fn sidecar_verified(store_root: &Path, hex: &str, size: u64) -> bool {
    let Some(path) = sidecar_path(store_root, hex) else {
        return false;
    };
    match hash_file(&path) {
        Ok((found_hex, found_size)) => found_hex == hex.to_ascii_lowercase() && found_size == size,
        Err(_) => false,
    }
}

/// Copies `src` into the sidecar for `hex` with streaming sha256 + size
/// verification and an atomic rename.
///
/// Idempotent: when the sidecar file already verifies, the copy is
/// skipped and `Ok` returns without touching it. On a hash or size
/// mismatch the temp file is discarded and [`StoreError::Invalid`] names
/// the failure; partial transfers never touch the sidecar path.
///
/// # Errors
/// [`StoreError::Invalid`] for a non-canonical `hex` or a verification
/// mismatch; filesystem failures propagate as [`StoreError::Io`].
pub fn stage_verified(
    store_root: &Path,
    hex: &str,
    size: u64,
    src: &Path,
) -> Result<PathBuf, StoreError> {
    let hex = hex.to_ascii_lowercase();
    let Some(final_path) = sidecar_path(store_root, &hex) else {
        return Err(StoreError::Invalid(format!(
            "lfs oid is not 64 hex digits: {hex:?}"
        )));
    };
    if sidecar_verified(store_root, &hex, size) {
        return Ok(final_path);
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = final_path.with_extension(format!("tmp.{}", std::process::id()));
    let staged = stage_copy(src, &tmp_path)?;
    if staged != (hex.clone(), size) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StoreError::Invalid(format!(
            "lfs payload {hex} verifies as {} with {staged_size} bytes (want {size})",
            staged.0,
            staged_size = staged.1,
        )));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    #[cfg(unix)]
    if let Some(parent) = final_path.parent() {
        super::durability::sync_dir(parent)?;
    }
    Ok(final_path)
}

/// Streams an HTTP download body into the sidecar for `hex` with
/// streaming sha256 + size verification and an atomic rename: the same
/// guarantee as [`stage_verified`], but the bytes arrive from a reader
/// (the batch-API payload GET) instead of a source file, so multi-hundred
/// MiB payloads never sit buffered in memory.
///
/// Idempotent and mismatch behavior match [`stage_verified`]: a verified
/// sidecar file short-circuits to `Ok`, a mismatch discards the temp file
/// with [`StoreError::Invalid`], and partial transfers never touch the
/// sidecar path.
///
/// # Errors
/// [`StoreError::Invalid`] for a non-canonical `hex` or a verification
/// mismatch; filesystem failures propagate as [`StoreError::Io`].
pub fn stage_stream_verified(
    store_root: &Path,
    hex: &str,
    size: u64,
    stream: &mut impl Read,
) -> Result<PathBuf, StoreError> {
    let hex = hex.to_ascii_lowercase();
    let Some(final_path) = sidecar_path(store_root, &hex) else {
        return Err(StoreError::Invalid(format!(
            "lfs oid is not 64 hex digits: {hex:?}"
        )));
    };
    if sidecar_verified(store_root, &hex, size) {
        return Ok(final_path);
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = final_path.with_extension(format!("tmp.{}", std::process::id()));
    let staged = copy_stream(stream, &tmp_path)?;
    if staged != (hex.clone(), size) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StoreError::Invalid(format!(
            "lfs payload {hex} verifies as {} with {staged_size} bytes (want {size})",
            staged.0,
            staged_size = staged.1,
        )));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    #[cfg(unix)]
    if let Some(parent) = final_path.parent() {
        super::durability::sync_dir(parent)?;
    }
    Ok(final_path)
}

/// Streams `src` to `tmp`, returning the observed `(hex, bytes)`.
fn stage_copy(src: &Path, tmp: &Path) -> Result<(String, u64), StoreError> {
    let mut input = std::fs::File::open(src)?;
    copy_stream(&mut input, tmp)
}

/// Streams `input` to `tmp`, returning the observed `(hex, bytes)`.
fn copy_stream(input: &mut impl Read, tmp: &Path) -> Result<(String, u64), StoreError> {
    let mut output = std::fs::File::create(tmp)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut chunk = [0_u8; 65536];
    loop {
        let read = input.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        std::io::Write::write_all(&mut output, &chunk[..read])?;
        hasher.update(&chunk[..read]);
        size += u64::try_from(read)
            .map_err(|_| StoreError::Invalid("file read exceeds u64".to_owned()))?;
    }
    std::io::Write::flush(&mut output)?;
    // Durability before the rename publishes the name: a crash must never
    // leave a complete=true row pointing at a torn payload file.
    output.sync_all()?;
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
        hex.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("hex digit"));
    }
    Ok((hex, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ruk-lfs-sidecar-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("seed dir");
        dir
    }

    #[test]
    fn canonical_hex_only() {
        assert!(valid_oid_hex(&"a".repeat(64)));
        assert!(!valid_oid_hex("abc"));
        assert!(!valid_oid_hex(&"z".repeat(64)));
        assert!(sidecar_path(Path::new("/s"), "abc").is_none());
        let hex = "ab".repeat(32);
        let path = sidecar_path(Path::new("/s"), &hex).unwrap();
        assert_eq!(
            path,
            Path::new("/s")
                .join("lfs")
                .join("objects")
                .join("ab")
                .join("ab")
                .join(&hex)
        );
    }

    #[test]
    fn stage_round_trip_and_idempotent() {
        let dir = test_dir("roundtrip");
        let src = dir.join("payload.bin");
        std::fs::write(&src, b"hello lfs").expect("seed");
        let (hex, size) = hash_file(&src).expect("hash");
        let store_root = dir.join("store");
        let final_path = stage_verified(&store_root, &hex, size, &src).expect("stage");
        assert!(sidecar_verified(&store_root, &hex, size));
        assert!(!sidecar_verified(&store_root, &hex, size + 1));
        // Second run is a no-op success.
        assert_eq!(
            stage_verified(&store_root, &hex, size, &src).expect("restage"),
            final_path
        );
        let record = LfsObjectRecord {
            size,
            complete: true,
        };
        let back = decode_record(&encode_record(&record)).expect("decode");
        assert_eq!(back, record);
        assert_eq!(upsert_mutation(&hex, &record).table, FactTable::LfsObjects);
    }

    #[test]
    fn stream_stage_verifies_without_a_source_file() {
        let dir = test_dir("stream");
        let payload = b"streamed lfs payload";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
            hex.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("hex digit"));
        }
        let store_root = dir.join("store");
        let mut stream: &[u8] = payload;
        let staged = stage_stream_verified(&store_root, &hex, payload.len() as u64, &mut stream)
            .expect("stage");
        assert!(sidecar_verified(&store_root, &hex, payload.len() as u64));
        assert_eq!(std::fs::read(&staged).expect("bytes"), payload);
        // A short stream fails verification and leaves no sidecar file.
        let bad_hex = "c".repeat(64);
        let mut short: &[u8] = b"too short";
        assert!(stage_stream_verified(&store_root, &bad_hex, 999, &mut short).is_err());
        assert!(sidecar_path(&store_root, &bad_hex).is_some_and(|path| !path.exists()));
    }

    #[test]
    fn mismatch_discards_temp() {
        let dir = test_dir("mismatch");
        let src = dir.join("payload.bin");
        std::fs::write(&src, b"real bytes").expect("seed");
        let store_root = dir.join("store");
        let wrong = "b".repeat(64);
        let err = stage_verified(&store_root, &wrong, 10, &src).expect_err("mismatch");
        assert!(matches!(err, StoreError::Invalid(_)));
        assert!(sidecar_path(&store_root, &wrong).is_some_and(|path| !path.exists()));
    }
}
