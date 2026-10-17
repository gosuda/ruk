//! Pack v2 and index v2 emission.
//!
//! [`PackWriter`] streams full (undeltified) entries: `PACK`, version 2,
//! the declared object count, each entry's type/size varint header and zlib
//! payload, then the trailer hash over every preceding byte
//! (`gitformat-pack.adoc`). Export writes only full entries, so the stored
//! pack is self-contained; [`PackWriter::append_ref_delta`] exists for the
//! push client, whose thin packs are wire-only. Delta search is not
//! implemented in gix and is not needed for correctness.
//!
//! [`write_idx_v2`] writes the version-2 index: magic, version, 256-entry
//! fan-out, sorted object ids, CRC32 per entry, 31-bit offsets with the
//! 64-bit overflow table, the pack checksum, and the index checksum. The
//! layout is identical for SHA-1 and SHA-256; only the id width differs.

use std::io::{self, Read, Write};

use flate2::Compression;
use flate2::Crc;
use flate2::write::ZlibEncoder;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::ObjectKind;

use crate::GitError;

const PACK_SIGNATURE: &[u8; 4] = b"PACK";
const PACK_VERSION: u32 = 2;
const IDX_MAGIC: &[u8; 4] = b"\xfftOc";
const IDX_VERSION: u32 = 2;
/// Largest offset stored inline in the 4-byte table; larger offsets go to
/// the 8-byte table and the 4-byte slot holds `MSB | index`.
const MAX_INLINE_OFFSET: u64 = 0x7fff_ffff;
const OFFSET_OVERFLOW_BIT: u32 = 0x8000_0000;
const REF_DELTA: u8 = 7;
const COPY_CHUNK: usize = 64 * 1024;

/// One written entry: the identity of the resolved object, where its entry
/// header starts, and the CRC32 over the entry's packed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedEntry {
    pub oid: Oid,
    pub offset: u64,
    pub crc32: u32,
}

/// The Git pack type code of a Git object kind.
///
/// # Errors
/// [`GitError::Invalid`] for a native conflict record, which has no Git
/// object type and is never written to a pack.
pub fn pack_type(kind: ObjectKind) -> Result<u8, GitError> {
    match kind {
        ObjectKind::Commit => Ok(1),
        ObjectKind::Tree => Ok(2),
        ObjectKind::Blob => Ok(3),
        ObjectKind::Tag => Ok(4),
        ObjectKind::Conflict => Err(GitError::Invalid {
            detail: "a native conflict record has no Git pack type".to_owned(),
        }),
    }
}

/// Counts and hashes every byte written to the pack.
struct Sink<W> {
    out: W,
    hasher: gix_hash::Hasher,
    offset: u64,
}

impl<W: Write> Write for Sink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.out.write(buf)?;
        if let Some(done) = buf.get(..written) {
            self.hasher.update(done);
        }
        self.offset = self
            .offset
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// CRCs the bytes of one entry on their way into the sink.
struct EntryWriter<'a, W> {
    sink: &'a mut Sink<W>,
    crc: Crc,
}

impl<W: Write> Write for EntryWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.sink.write(buf)?;
        if let Some(done) = buf.get(..written) {
            self.crc.update(done);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// A streaming pack v2 writer for a declared number of entries.
pub struct PackWriter<W: Write> {
    sink: Sink<W>,
    kind: HashKind,
    declared: u32,
    entries: Vec<PackedEntry>,
}

impl<W: Write> std::fmt::Debug for PackWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackWriter")
            .field("kind", &self.kind)
            .field("declared", &self.declared)
            .field("written", &self.entries.len())
            .field("offset", &self.sink.offset)
            .finish()
    }
}

impl<W: Write> PackWriter<W> {
    /// Writes the pack header for `count` entries.
    ///
    /// # Errors
    /// [`GitError::Io`] when the header cannot be written.
    pub fn new(out: W, kind: HashKind, count: u32) -> Result<Self, GitError> {
        let mut sink = Sink {
            out,
            hasher: gix_hash::hasher(kind.gix()),
            offset: 0,
        };
        let mut header = [0u8; 12];
        header[..4].copy_from_slice(PACK_SIGNATURE);
        header[4..8].copy_from_slice(&PACK_VERSION.to_be_bytes());
        header[8..].copy_from_slice(&count.to_be_bytes());
        sink.write_all(&header).map_err(io_error)?;
        Ok(Self {
            sink,
            kind,
            declared: count,
            entries: Vec::with_capacity(usize::try_from(count).unwrap_or(0)),
        })
    }

    /// Appends one full object from memory.
    ///
    /// # Errors
    /// [`GitError::Invalid`] for a conflict record, a wrong-width id, or more
    /// entries than declared; [`GitError::Io`] for write failures.
    pub fn append(
        &mut self,
        oid: Oid,
        kind: ObjectKind,
        data: &[u8],
    ) -> Result<PackedEntry, GitError> {
        self.append_stream(oid, kind, to_u64(data.len()), data)
    }

    /// Appends one full object of exactly `len` bytes read from `reader`.
    ///
    /// # Errors
    /// As [`Self::append`]; [`GitError::Corrupt`] when `reader` yields a
    /// different number of bytes than `len`.
    pub fn append_stream(
        &mut self,
        oid: Oid,
        kind: ObjectKind,
        len: u64,
        reader: impl Read,
    ) -> Result<PackedEntry, GitError> {
        let type_code = pack_type(kind)?;
        self.admit(oid)?;
        let offset = self.sink.offset;
        let mut entry = EntryWriter {
            sink: &mut self.sink,
            crc: Crc::new(),
        };
        entry
            .write_all(&entry_header(type_code, len))
            .map_err(io_error)?;
        let mut encoder = ZlibEncoder::new(entry, Compression::default());
        let copied = copy_exact(reader, &mut encoder, len)?;
        if copied != len {
            return Err(GitError::Corrupt {
                detail: format!("object {oid} yielded {copied} bytes, expected {len}"),
            });
        }
        let entry = encoder.finish().map_err(io_error)?;
        let packed = PackedEntry {
            oid,
            offset,
            crc32: entry.crc.sum(),
        };
        self.entries.push(packed);
        Ok(packed)
    }

    /// Appends a `REF_DELTA` entry for `oid` against `base`. Only for thin
    /// wire packs; a stored pack never contains one.
    ///
    /// # Errors
    /// As [`Self::append`].
    pub fn append_ref_delta(
        &mut self,
        oid: Oid,
        base: Oid,
        delta: &[u8],
    ) -> Result<PackedEntry, GitError> {
        self.admit(oid)?;
        crate::require_kind(base, self.kind)?;
        let offset = self.sink.offset;
        let mut entry = EntryWriter {
            sink: &mut self.sink,
            crc: Crc::new(),
        };
        entry
            .write_all(&entry_header(REF_DELTA, to_u64(delta.len())))
            .map_err(io_error)?;
        entry.write_all(base.as_bytes()).map_err(io_error)?;
        let mut encoder = ZlibEncoder::new(entry, Compression::default());
        encoder.write_all(delta).map_err(io_error)?;
        let entry = encoder.finish().map_err(io_error)?;
        let packed = PackedEntry {
            oid,
            offset,
            crc32: entry.crc.sum(),
        };
        self.entries.push(packed);
        Ok(packed)
    }

    /// Writes the trailer and returns the entries and the pack checksum.
    ///
    /// # Errors
    /// [`GitError::Invalid`] when fewer entries were appended than declared;
    /// [`GitError::Io`] for write failures; [`GitError::Corrupt`] when the
    /// SHA-1 collision detector refuses the pack bytes.
    pub fn finish(self) -> Result<(Vec<PackedEntry>, Oid), GitError> {
        let Self {
            sink,
            declared,
            entries,
            ..
        } = self;
        if to_u64(entries.len()) != u64::from(declared) {
            return Err(GitError::Invalid {
                detail: format!(
                    "pack declared {declared} entries, {} written",
                    entries.len()
                ),
            });
        }
        let checksum = seal(sink)?;
        Ok((entries, checksum))
    }

    fn admit(&self, oid: Oid) -> Result<(), GitError> {
        crate::require_kind(oid, self.kind)?;
        if to_u64(self.entries.len()) >= u64::from(self.declared) {
            return Err(GitError::Invalid {
                detail: format!("pack declared {} entries; {oid} exceeds it", self.declared),
            });
        }
        Ok(())
    }
}

/// The type/size varint that starts every pack entry.
fn entry_header(type_code: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    let mut rest = size >> 4;
    let low = u8::try_from(size & 0x0f).unwrap_or(0);
    let mut byte = (type_code << 4) | low;
    while rest != 0 {
        out.push(byte | 0x80);
        byte = u8::try_from(rest & 0x7f).unwrap_or(0);
        rest >>= 7;
    }
    out.push(byte);
    out
}

/// Copies at most `limit` bytes and reports how many arrived; one more byte
/// than `limit` is probed so an over-long source is detected.
fn copy_exact(reader: impl Read, out: &mut impl Write, limit: u64) -> Result<u64, GitError> {
    let mut reader = reader.take(limit.saturating_add(1));
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        };
        total = total.saturating_add(to_u64(read));
        if total > limit {
            return Ok(total);
        }
        out.write_all(buf.get(..read).unwrap_or_default())
            .map_err(io_error)?;
    }
}

/// Writes an index v2 for `entries` (sorted here by object id) of a pack
/// whose trailer is `pack_checksum`, returning the index checksum.
///
/// # Errors
/// [`GitError::Invalid`] for duplicate ids or ids of another width;
/// [`GitError::Limit`] for more than 2^32 - 1 entries; [`GitError::Io`].
pub fn write_idx_v2(
    entries: &mut [PackedEntry],
    pack_checksum: Oid,
    kind: HashKind,
    out: impl Write,
) -> Result<Oid, GitError> {
    crate::require_kind(pack_checksum, kind)?;
    entries.sort_unstable_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    for pair in entries.windows(2) {
        if let [a, b] = pair
            && a.oid == b.oid
        {
            return Err(GitError::Invalid {
                detail: format!("object {} appears twice in one pack", a.oid),
            });
        }
    }
    u32::try_from(entries.len()).map_err(|_| GitError::Limit {
        detail: format!("{} objects exceed one pack index", entries.len()),
    })?;
    let mut sink = Sink {
        out,
        hasher: gix_hash::hasher(kind.gix()),
        offset: 0,
    };
    let mut per_byte = [0u32; 256];
    for entry in entries.iter() {
        crate::require_kind(entry.oid, kind)?;
        let first = usize::from(entry.oid.as_bytes().first().copied().unwrap_or(0));
        if let Some(slot) = per_byte.get_mut(first) {
            *slot += 1;
        }
    }
    let mut head = Vec::with_capacity(8 + 256 * 4);
    head.extend_from_slice(IDX_MAGIC);
    head.extend_from_slice(&IDX_VERSION.to_be_bytes());
    let mut cumulative = 0u32;
    for count in per_byte {
        cumulative += count;
        head.extend_from_slice(&cumulative.to_be_bytes());
    }
    sink.write_all(&head).map_err(io_error)?;
    let mut writer = io::BufWriter::new(&mut sink);
    for entry in entries.iter() {
        writer.write_all(entry.oid.as_bytes()).map_err(io_error)?;
    }
    for entry in entries.iter() {
        writer
            .write_all(&entry.crc32.to_be_bytes())
            .map_err(io_error)?;
    }
    let mut large = Vec::new();
    for entry in entries.iter() {
        let slot = if entry.offset > MAX_INLINE_OFFSET {
            let index = u32::try_from(large.len()).map_err(|_| GitError::Limit {
                detail: "too many large pack offsets".to_owned(),
            })?;
            large.push(entry.offset);
            OFFSET_OVERFLOW_BIT | index
        } else {
            u32::try_from(entry.offset).unwrap_or(0)
        };
        writer.write_all(&slot.to_be_bytes()).map_err(io_error)?;
    }
    for offset in large {
        writer.write_all(&offset.to_be_bytes()).map_err(io_error)?;
    }
    writer
        .write_all(pack_checksum.as_bytes())
        .map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    drop(writer);
    seal(sink)
}

/// Appends the trailer hash over everything written so far.
fn seal<W: Write>(sink: Sink<W>) -> Result<Oid, GitError> {
    let Sink {
        mut out, hasher, ..
    } = sink;
    let checksum = finish_hash(hasher)?;
    out.write_all(checksum.as_bytes()).map_err(io_error)?;
    out.flush().map_err(io_error)?;
    Ok(checksum)
}

/// Git's legacy pack name: the hash of the sorted object ids. Readers do
/// not check pack names, and this one is known before the pack is written,
/// so the pack can be installed under its final name in one pass.
///
/// # Errors
/// [`GitError::Corrupt`] when the SHA-1 collision detector refuses.
pub fn pack_name(kind: HashKind, sorted: &[Oid]) -> Result<Oid, GitError> {
    let mut hasher = gix_hash::hasher(kind.gix());
    for oid in sorted {
        hasher.update(oid.as_bytes());
    }
    finish_hash(hasher)
}

fn finish_hash(hasher: gix_hash::Hasher) -> Result<Oid, GitError> {
    hasher
        .try_finalize()
        .map(Oid::from)
        .map_err(|err| GitError::Corrupt {
            detail: format!("hash refused: {err}"),
        })
}

pub(crate) fn io_error(err: io::Error) -> GitError {
    GitError::Io {
        detail: err.to_string(),
    }
}

pub(crate) fn to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_header_matches_git_varint() {
        // Size 3 blob: a single byte, type 3 in bits 6-4.
        assert_eq!(entry_header(3, 3), vec![0x33]);
        // Size 16 needs a continuation byte: low nibble 0, then 1.
        assert_eq!(entry_header(1, 16), vec![0x90, 0x01]);
        // 0x1234 = low 4, then 0x123 >> 0 & 0x7f = 0x23, then 0x02.
        assert_eq!(entry_header(2, 0x1234), vec![0xa4, 0xa3, 0x02]);
    }

    #[test]
    fn declared_count_is_enforced_both_ways() {
        let kind = HashKind::Sha1;
        let oid = kind.hash_git_object("blob", b"x").unwrap();
        let mut short = PackWriter::new(Vec::new(), kind, 2).unwrap();
        short.append(oid, ObjectKind::Blob, b"x").unwrap();
        assert!(matches!(short.finish(), Err(GitError::Invalid { .. })));

        let mut over = PackWriter::new(Vec::new(), kind, 1).unwrap();
        over.append(oid, ObjectKind::Blob, b"x").unwrap();
        assert!(matches!(
            over.append(oid, ObjectKind::Blob, b"x"),
            Err(GitError::Invalid { .. })
        ));
    }

    #[test]
    fn conflict_records_are_never_packed() {
        let kind = HashKind::Sha1;
        let oid = kind.hash_git_object("blob", b"x").unwrap();
        let mut writer = PackWriter::new(Vec::new(), kind, 1).unwrap();
        assert!(matches!(
            writer.append(oid, ObjectKind::Conflict, b"x"),
            Err(GitError::Invalid { .. })
        ));
    }

    #[test]
    fn short_stream_is_corrupt() {
        let kind = HashKind::Sha1;
        let oid = kind.hash_git_object("blob", b"abc").unwrap();
        let mut writer = PackWriter::new(Vec::new(), kind, 1).unwrap();
        assert!(matches!(
            writer.append_stream(oid, ObjectKind::Blob, 4, &b"abc"[..]),
            Err(GitError::Corrupt { .. })
        ));
        let mut writer = PackWriter::new(Vec::new(), kind, 1).unwrap();
        assert!(matches!(
            writer.append_stream(oid, ObjectKind::Blob, 2, &b"abc"[..]),
            Err(GitError::Corrupt { .. })
        ));
    }

    #[test]
    fn large_offsets_use_the_overflow_table() {
        let kind = HashKind::Sha1;
        let a = kind.hash_git_object("blob", b"a").unwrap();
        let b = kind.hash_git_object("blob", b"b").unwrap();
        let pack = kind.hash_git_object("blob", b"pack").unwrap();
        let mut entries = vec![
            PackedEntry {
                oid: a,
                offset: 12,
                crc32: 1,
            },
            PackedEntry {
                oid: b,
                offset: 0x1_0000_0000,
                crc32: 2,
            },
        ];
        let mut idx = Vec::new();
        write_idx_v2(&mut entries, pack, kind, &mut idx).unwrap();
        let file = gix_pack::index::File::from_data(idx, "mem.idx".into(), kind.gix()).unwrap();
        assert_eq!(file.num_objects(), 2);
        let ia = file.lookup(gix_hash::ObjectId::from(a)).unwrap();
        let ib = file.lookup(gix_hash::ObjectId::from(b)).unwrap();
        assert_eq!(file.pack_offset_at_index(ia), 12);
        assert_eq!(file.pack_offset_at_index(ib), 0x1_0000_0000);
        assert_eq!(file.crc32_at_index(ib), Some(2));
        assert_eq!(Oid::from(file.pack_checksum()), pack);
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let kind = HashKind::Sha1;
        let a = kind.hash_git_object("blob", b"a").unwrap();
        let mut entries = vec![
            PackedEntry {
                oid: a,
                offset: 12,
                crc32: 1,
            },
            PackedEntry {
                oid: a,
                offset: 40,
                crc32: 2,
            },
        ];
        assert!(matches!(
            write_idx_v2(&mut entries, a, kind, Vec::new()),
            Err(GitError::Invalid { .. })
        ));
    }
}
