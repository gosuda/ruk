//! Segment record framing, seal footers, and committed-extent validation.
//!
//! This is the byte-format leaf of the durable store. It knows nothing about
//! metadata, fsync, compression, or object identity: it frames encoded
//! payloads into records, writes and verifies the seal footer, and checks
//! that bytes inside a committed extent really are the records and footer the
//! manifest claims. The store owner decides *when* to append, seal, sync and
//! truncate; decompression and object-hash verification happen after a record
//! has been read through [`RecordPayload`] and its checksum accepted.
//!
//! # Wire format (all integers little-endian)
//!
//! ```text
//! record := len:u32  kind:u8  flags:u8  crc:u32  payload[len]
//! crc    := CRC32C(len ‖ kind ‖ flags ‖ payload)      -- header bytes 0..6, then payload
//! footer := "RUKSEAL1"  records_extent:u64  records_crc:u32  footer_crc:u32   (24 bytes)
//! records_crc := CRC32C over every record byte in [0, records_extent)
//! footer_crc  := CRC32C over the first 20 footer bytes
//! ```
//!
//! `len` counts the encoded payload only, never the 10-byte header. `kind`
//! is an [`ObjectKind`] discriminant (1..=5) and `flags` an [`Encoding`]
//! discriminant (0, 1 or 3); every other byte is corruption. A segment is a
//! dense run of records with no gaps, optionally followed by exactly one
//! footer; nothing follows a footer.
//!
//! # Extents
//!
//! A manifest carries `records_end` (end of the last record) and
//! `committed_end` (equal to `records_end` while open, `records_end + 24`
//! once sealed). Every offset and length is handled with checked `u64`
//! arithmetic. A record must lie entirely inside `records_end`, never in the
//! footer and never beyond the committed bytes. Memory is bounded: records
//! stream through fixed-size chunks and no function allocates in proportion
//! to a segment or a record.
//!
//! # Trust
//!
//! Bytes read through [`RecordPayload`] are untrusted until
//! [`RecordPayload::finish`] returns `Ok`: a caller that decompresses and
//! hashes while reading must still call `finish` before accepting the result.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

use crc32c::{crc32c, crc32c_append, crc32c_combine};

use crate::store::types::{Encoding, ObjectKind};

/// Bytes in a record header: `len`, `kind`, `flags`, `crc`.
pub(crate) const HEADER_LEN: usize = 10;
/// Bytes in a seal footer.
pub(crate) const FOOTER_LEN: usize = 24;
/// First eight footer bytes.
pub(crate) const SEAL_MAGIC: [u8; 8] = *b"RUKSEAL1";
/// Largest encoded payload a record can frame (`len` is a `u32`).
pub(crate) const MAX_RECORD_PAYLOAD: u64 = 0xFFFF_FFFF;
/// Target segment size. A record that cannot fit under it in a non-empty
/// segment goes to a fresh segment; a single larger record gets a dedicated
/// segment. It is a placement hint, never a format limit.
pub(crate) const SEGMENT_TARGET_BYTES: u64 = 256 * 1024 * 1024;

/// Header bytes covered by the record CRC ahead of the payload.
const HEADER_PREFIX_LEN: usize = 6;
/// Streaming chunk for appends and verification passes.
const IO_CHUNK: usize = 64 * 1024;
/// Chunk for draining the unread tail of a record in [`RecordPayload::finish`].
const DRAIN_CHUNK: usize = 16 * 1024;
// Widening usize -> u64 of small literals; lossless on every supported target.
const HEADER_LEN_U64: u64 = HEADER_LEN as u64;
const FOOTER_LEN_U64: u64 = FOOTER_LEN as u64;

/// Failures of segment framing and verification.
///
/// The store maps these into its own error: `Io` to I/O, `Corrupt` to
/// corruption evidence, `Capacity` to `E_CAPACITY`, `Invalid` to invalid
/// input, and `Poisoned` to writer closed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SegmentError {
    #[error("io: {0}")]
    Io(io::Error),
    /// Stored bytes disagree with the framing, checksums or manifest extents.
    #[error("corrupt segment: {0}")]
    Corrupt(String),
    /// A fixed-width length or offset cannot represent the request.
    #[error("segment capacity exceeded: {0}")]
    Capacity(String),
    /// The caller broke a precondition (inconsistent declaration, wrong
    /// stream, writer already sealed).
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
    /// An earlier write failure on this writer may have left bytes past the
    /// committed extent; the writer is closed to further appends and seals.
    #[error(
        "segment writer poisoned: an earlier write may have left bytes past the committed extent"
    )]
    Poisoned,
}

impl From<io::Error> for SegmentError {
    /// Recovers a [`SegmentError`] that a [`Read`] implementation embedded in
    /// an `io::Error` (decoders and `io::copy` wrap errors that way), so
    /// truncation of committed bytes stays `Corrupt` end to end.
    fn from(err: io::Error) -> Self {
        match err.downcast::<Self>() {
            Ok(inner) => inner,
            Err(err) => Self::Io(err),
        }
    }
}

fn corrupt(detail: impl Into<String>) -> SegmentError {
    SegmentError::Corrupt(detail.into())
}

fn invalid(what: &'static str, detail: impl Into<String>) -> SegmentError {
    SegmentError::Invalid {
        what,
        detail: detail.into(),
    }
}

/// Converts a read error to a [`SegmentError`], replacing a plain
/// end-of-stream with `on_eof()`. An embedded [`SegmentError`] wins, so a
/// nested record reader's own diagnosis is never overwritten.
fn eof_or(err: io::Error, on_eof: impl FnOnce() -> SegmentError) -> SegmentError {
    match SegmentError::from(err) {
        SegmentError::Io(io) if io.kind() == io::ErrorKind::UnexpectedEof => on_eof(),
        other => other,
    }
}

/// Exactly `buf.len()` committed bytes, or `Corrupt` when the stream ends
/// early (committed bytes are missing), or `Io` for a real I/O failure.
fn read_exact_or_corrupt(
    src: &mut impl Read,
    buf: &mut [u8],
    what: &str,
    at: u64,
) -> Result<(), SegmentError> {
    src.read_exact(buf)
        .map_err(|err| eof_or(err, || corrupt(format!("truncated {what} at offset {at}"))))
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

/// The u32 framing length of a payload, or `E_CAPACITY` (never truncated).
fn checked_payload_len(payload_len: u64) -> Result<u32, SegmentError> {
    u32::try_from(payload_len).map_err(|_| {
        SegmentError::Capacity(format!(
            "encoded payload of {payload_len} bytes exceeds the {MAX_RECORD_PAYLOAD}-byte record limit"
        ))
    })
}

fn payload_usize(len: u32) -> Result<usize, SegmentError> {
    usize::try_from(len).map_err(|_| {
        SegmentError::Capacity(format!(
            "payload length {len} exceeds the address space of this platform"
        ))
    })
}

fn extent_after(start: u64, len: u64) -> Result<u64, SegmentError> {
    start.checked_add(len).ok_or_else(|| {
        SegmentError::Capacity(format!(
            "segment extent overflows u64: {start} plus {len} bytes"
        ))
    })
}

/// Total record bytes (header plus payload) for an encoded payload length.
///
/// # Errors
/// `Capacity` when the payload exceeds the u32 framing limit.
pub(crate) fn record_len_for(payload_len: u64) -> Result<u64, SegmentError> {
    checked_payload_len(payload_len).map(|len| HEADER_LEN_U64 + u64::from(len))
}

fn header_prefix(
    payload_len: u32,
    kind: ObjectKind,
    encoding: Encoding,
) -> [u8; HEADER_PREFIX_LEN] {
    let len = payload_len.to_le_bytes();
    [
        len[0],
        len[1],
        len[2],
        len[3],
        kind.to_repr(),
        encoding.to_repr(),
    ]
}

/// A decoded record header. The checksum is verified against the payload by
/// [`RecordPayload::finish`], not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordHeader {
    /// Encoded payload length in bytes (excludes the header).
    pub(crate) payload_len: u32,
    pub(crate) kind: ObjectKind,
    pub(crate) encoding: Encoding,
    /// Stored CRC32C over header bytes 0..6 followed by the payload.
    pub(crate) crc: u32,
}

impl RecordHeader {
    /// Total record bytes, header included. Cannot overflow: at most
    /// `u32::MAX + 10`.
    pub(crate) fn record_len(&self) -> u64 {
        HEADER_LEN_U64 + u64::from(self.payload_len)
    }

    fn decode(bytes: &[u8; HEADER_LEN], offset: u64) -> Result<Self, SegmentError> {
        let kind = ObjectKind::from_repr(bytes[4]).ok_or_else(|| {
            corrupt(format!(
                "record at {offset}: unknown object kind {}",
                bytes[4]
            ))
        })?;
        let encoding = Encoding::from_repr(bytes[5]).ok_or_else(|| {
            corrupt(format!(
                "record at {offset}: unknown flags {:#04x}",
                bytes[5]
            ))
        })?;
        Ok(Self {
            payload_len: le_u32(bytes, 0),
            kind,
            encoding,
            crc: le_u32(bytes, HEADER_PREFIX_LEN),
        })
    }

    fn prefix(&self) -> [u8; HEADER_PREFIX_LEN] {
        header_prefix(self.payload_len, self.kind, self.encoding)
    }
}

/// Where [`SegmentWriter::append`] placed a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordAppended {
    /// Start of the record header inside the segment.
    pub(crate) offset: u64,
    /// Header plus payload bytes.
    pub(crate) record_len: u64,
}

/// Append-only writer for one segment file.
///
/// It is the single owner of the segment's record extent: `records_end`
/// advances only after a record's final byte was written, so the extent never
/// has a hole. After any failure past argument validation the writer is
/// poisoned: bytes may sit beyond `records_end` and only recovery (truncating
/// to the committed extent) may reuse the file. No operation syncs; the
/// owner syncs through [`Self::get_ref`] and then commits the manifest.
#[derive(Debug)]
pub(crate) struct SegmentWriter<W> {
    inner: W,
    records_end: u64,
    records_crc: u32,
    sealed: bool,
    poisoned: bool,
    /// Known stream position when `Some`: construction leaves the stream at
    /// `records_end`, and every successful record or seal write advances it
    /// in lockstep, so the next write can skip its positioning seek. `None`
    /// forces a seek. The stream is never exposed mutably (`get_ref` lends
    /// `&W`), so nothing else can move it behind this record.
    position: Option<u64>,
    /// Bounded append scratch reused across `append` calls. At most
    /// `IO_CHUNK` bytes; empty until the first record, freed on `seal`.
    scratch: Vec<u8>,
}

impl<W: Write + Seek> SegmentWriter<W> {
    /// A writer over an empty stream.
    ///
    /// # Errors
    /// `Invalid` when the stream already holds bytes; `Io` on seek failure.
    pub(crate) fn fresh(inner: W) -> Result<Self, SegmentError> {
        Self::resumed(inner, 0, 0)
    }

    /// A writer continuing a verified open segment. `records_end` and
    /// `records_crc` come from [`validate_segment_file`], after the caller
    /// truncated any uncommitted tail.
    ///
    /// # Errors
    /// `Invalid` unless the stream length equals `records_end`; a sealed
    /// file is refused because its footer makes it longer.
    pub(crate) fn resumed(
        mut inner: W,
        records_end: u64,
        records_crc: u32,
    ) -> Result<Self, SegmentError> {
        let len = inner.seek(SeekFrom::End(0))?;
        if len != records_end {
            return Err(invalid(
                "segment stream",
                format!(
                    "stream holds {len} bytes but the committed record extent is {records_end}; \
                     truncate the uncommitted tail first, and never reopen a sealed segment"
                ),
            ));
        }
        Ok(Self {
            inner,
            records_end,
            records_crc,
            sealed: false,
            poisoned: false,
            // The length probe above leaves the stream exactly here.
            position: Some(records_end),
            scratch: Vec::new(),
        })
    }

    /// End of the last complete record.
    pub(crate) fn records_end(&self) -> u64 {
        self.records_end
    }

    /// CRC32C over every record byte in `[0, records_end)`. Production code
    /// takes this value from [`VerifiedSegment`]; the getter exists so tests
    /// can pin the incremental chain.
    #[cfg(test)]
    pub(crate) fn records_crc(&self) -> u32 {
        self.records_crc
    }

    pub(crate) fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// The manifest `committed_end` this writer's state implies: the footer is
    /// included once sealed. Cannot overflow: an append reserves footer room.
    pub(crate) fn committed_end(&self) -> u64 {
        if self.sealed {
            self.records_end + FOOTER_LEN_U64
        } else {
            self.records_end
        }
    }

    /// Whether a record of `record_len` bytes still fits under
    /// [`SEGMENT_TARGET_BYTES`]. The owner seals and rolls over when it does
    /// not and the segment is non-empty.
    pub(crate) fn fits_target(&self, record_len: u64) -> bool {
        self.fits_sized(record_len, SEGMENT_TARGET_BYTES)
    }

    /// Whether a record of `record_len` bytes still fits under `target`.
    /// Compaction rolls its fresh segments by the same rule against the
    /// store's effective target, which tests may shrink per store.
    pub(crate) fn fits_sized(&self, record_len: u64, target: u64) -> bool {
        self.records_end
            .checked_add(record_len)
            .is_some_and(|end| end <= target)
    }

    /// The underlying stream, for the owner's fsync.
    pub(crate) fn get_ref(&self) -> &W {
        &self.inner
    }

    fn ensure_open(&self) -> Result<(), SegmentError> {
        if self.poisoned {
            return Err(SegmentError::Poisoned);
        }
        if self.sealed {
            return Err(invalid(
                "sealed segment",
                "nothing may be appended after a seal",
            ));
        }
        Ok(())
    }

    /// Appends one record whose encoded payload is the next `payload_len`
    /// bytes of `payload`, in bounded chunks.
    ///
    /// `payload_crc` is the CRC32C of exactly those bytes; it is verified
    /// against what was actually streamed. The header CRC is combined from it
    /// before the payload is written, so a mismatch is detected only after
    /// the bytes landed: the writer is then poisoned and the record is not
    /// part of the extent.
    ///
    /// # Errors
    /// `Capacity` (nothing written, writer still usable) when the payload
    /// exceeds the u32 framing limit or the segment extent plus footer would
    /// overflow `u64`. `Invalid` when sealed, or when `payload`
    /// ends before `payload_len` bytes. `Corrupt` when the streamed bytes do
    /// not match `payload_crc`. `Io` on stream failure. `Poisoned` when an
    /// earlier write on this writer failed. Every failure after
    /// validation poisons the writer.
    pub(crate) fn append(
        &mut self,
        kind: ObjectKind,
        encoding: Encoding,
        payload_len: u64,
        payload_crc: u32,
        mut payload: impl Read,
    ) -> Result<RecordAppended, SegmentError> {
        self.ensure_open()?;
        let len = checked_payload_len(payload_len)?;
        let record_len = HEADER_LEN_U64 + u64::from(len);
        let new_end = extent_after(self.records_end, record_len)?;
        // A sealed segment must stay representable: reserve the footer now.
        extent_after(new_end, FOOTER_LEN_U64)?;
        let offset = self.records_end;
        match self.write_record(kind, encoding, len, payload_crc, &mut payload) {
            Ok(records_crc) => {
                self.records_end = new_end;
                self.records_crc = records_crc;
                // The record's final byte landed here; the next write
                // starts exactly at the new extent.
                self.position = Some(new_end);
                Ok(RecordAppended { offset, record_len })
            }
            Err(err) => {
                self.poisoned = true;
                self.position = None;
                Err(err)
            }
        }
    }

    /// Writes one record at `records_end` and returns the new records CRC.
    fn write_record(
        &mut self,
        kind: ObjectKind,
        encoding: Encoding,
        len: u32,
        payload_crc: u32,
        payload: &mut impl Read,
    ) -> Result<u32, SegmentError> {
        let prefix = header_prefix(len, kind, encoding);
        let header_crc = crc32c_combine(crc32c(&prefix), payload_crc, payload_usize(len)?);
        let total = HEADER_LEN_U64 + u64::from(len);
        // Small records leave in one write; large ones in IO_CHUNK pieces.
        // Reuse one bounded scratch across appends; only growth zeroes.
        let buf_len = usize::try_from(total).map_or(IO_CHUNK, |total| total.min(IO_CHUNK));
        let Self {
            inner,
            scratch,
            records_end,
            records_crc,
            position,
            ..
        } = &mut *self;
        if scratch.len() < buf_len {
            scratch.resize(buf_len, 0);
        }
        let buf: &mut [u8] = &mut scratch[..buf_len];
        buf[..HEADER_PREFIX_LEN].copy_from_slice(&prefix);
        buf[HEADER_PREFIX_LEN..HEADER_LEN].copy_from_slice(&header_crc.to_le_bytes());

        if *position != Some(*records_end) {
            inner.seek(SeekFrom::Start(*records_end))?;
            *position = Some(*records_end);
        }
        let mut next_crc = *records_crc;
        let mut seen_crc = 0_u32;
        let mut remaining = payload_usize(len)?;
        let mut filled = HEADER_LEN;
        loop {
            let take = remaining.min(buf.len() - filled);
            let end = filled + take;
            payload.read_exact(&mut buf[filled..end]).map_err(|err| {
                eof_or(err, || {
                    invalid(
                        "record payload",
                        format!("source ended before the declared {len} bytes"),
                    )
                })
            })?;
            seen_crc = crc32c_append(seen_crc, &buf[filled..end]);
            next_crc = crc32c_append(next_crc, &buf[..end]);
            inner.write_all(&buf[..end])?;
            remaining -= take;
            filled = 0;
            if remaining == 0 {
                break;
            }
        }
        if seen_crc != payload_crc {
            return Err(corrupt(format!(
                "prepared payload checksum {payload_crc:#010x} does not match its {len} streamed bytes ({seen_crc:#010x})"
            )));
        }
        Ok(next_crc)
    }

    /// Writes the seal footer after the last record and returns the manifest
    /// `committed_end` (`records_end + 24`). Nothing may be appended after.
    ///
    /// # Errors
    /// `Poisoned` when an earlier write failed, `Invalid` when already sealed,
    /// `Capacity` on extent overflow, `Io` on write failure (which poisons the writer).
    pub(crate) fn seal(&mut self) -> Result<u64, SegmentError> {
        self.ensure_open()?;
        let committed_end = extent_after(self.records_end, FOOTER_LEN_U64)?;
        let footer = SealFooter {
            records_extent: self.records_end,
            records_crc: self.records_crc,
        }
        .encode();
        if self.position != Some(self.records_end) {
            // A failed positioning seek poisons, exactly as the
            // unconditional seek did before the position tracking.
            if let Err(err) = self.inner.seek(SeekFrom::Start(self.records_end)) {
                self.poisoned = true;
                return Err(err.into());
            }
            self.position = Some(self.records_end);
        }
        let written = self.inner.write_all(&footer);
        match written {
            Ok(()) => {
                self.sealed = true;
                self.position = Some(committed_end);
                // `Batch.sealed` retains writers until the manifest commits;
                // drop the scratch so each historical segment keeps no buffer.
                self.scratch = Vec::new();
                Ok(committed_end)
            }
            Err(err) => {
                self.poisoned = true;
                self.position = None;
                Err(err.into())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SealFooter {
    records_extent: u64,
    records_crc: u32,
}

impl SealFooter {
    fn encode(self) -> [u8; FOOTER_LEN] {
        let mut out = [0_u8; FOOTER_LEN];
        out[..8].copy_from_slice(&SEAL_MAGIC);
        out[8..16].copy_from_slice(&self.records_extent.to_le_bytes());
        out[16..20].copy_from_slice(&self.records_crc.to_le_bytes());
        let crc = crc32c(&out[..20]);
        out[20..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8; FOOTER_LEN]) -> Result<Self, SegmentError> {
        if bytes[..8] != SEAL_MAGIC {
            return Err(corrupt("seal footer magic is not RUKSEAL1"));
        }
        let computed = crc32c(&bytes[..20]);
        let stored = le_u32(bytes, 20);
        if computed != stored {
            return Err(corrupt(format!(
                "seal footer checksum mismatch: stored {stored:#010x}, computed {computed:#010x}"
            )));
        }
        Ok(Self {
            records_extent: le_u64(bytes, 8),
            records_crc: le_u32(bytes, 16),
        })
    }
}

/// Reads and decodes the record header at `offset`, checking that the whole
/// record fits inside `records_end` (the *records* extent, never the
/// committed one, so a record cannot reach into a footer). Leaves the stream
/// at the first payload byte.
///
/// The header CRC covers the payload, so it is verified later by
/// [`RecordPayload::finish`]; unknown kind/flag bytes and extent violations
/// are rejected here, before anything is decompressed.
///
/// # Errors
/// `Corrupt` for a header or payload that would cross `records_end`, a
/// truncated header, or an unknown kind or flags byte; `Io` otherwise.
pub(crate) fn read_record_header<S: Read + Seek>(
    src: &mut S,
    offset: u64,
    records_end: u64,
) -> Result<RecordHeader, SegmentError> {
    let header_end = offset
        .checked_add(HEADER_LEN_U64)
        .filter(|end| *end <= records_end)
        .ok_or_else(|| {
            corrupt(format!(
                "record header at offset {offset} does not fit the committed record extent {records_end}"
            ))
        })?;
    src.seek(SeekFrom::Start(offset))?;
    let mut raw = [0_u8; HEADER_LEN];
    read_exact_or_corrupt(src, &mut raw, "record header", offset)?;
    let header = RecordHeader::decode(&raw, offset)?;
    let available = records_end - header_end;
    if u64::from(header.payload_len) > available {
        return Err(corrupt(format!(
            "record at offset {offset} claims {} payload bytes but only {available} remain inside the committed record extent {records_end}",
            header.payload_len
        )));
    }
    Ok(header)
}

/// A bounded reader over one record's encoded payload.
///
/// It never yields a byte outside the record, folds every byte into the
/// record checksum, and reports committed bytes that are missing as an
/// `io::Error` of kind `UnexpectedEof` carrying a [`SegmentError::Corrupt`]
/// (recoverable through `SegmentError::from`). Decoders may stop early; call
/// [`Self::finish`] to verify the rest of the record and the checksum.
#[derive(Debug)]
pub(crate) struct RecordPayload<R> {
    src: R,
    header: RecordHeader,
    offset: u64,
    remaining: usize,
    crc: u32,
    truncated: bool,
}

impl<R: Read + Seek> RecordPayload<R> {
    /// Reads the header at `offset` (see [`read_record_header`]) and returns
    /// the payload reader positioned at its first byte.
    ///
    /// # Errors
    /// As [`read_record_header`].
    pub(crate) fn open(mut src: R, offset: u64, records_end: u64) -> Result<Self, SegmentError> {
        let header = read_record_header(&mut src, offset, records_end)?;
        Ok(Self {
            src,
            crc: crc32c(&header.prefix()),
            remaining: payload_usize(header.payload_len)?,
            header,
            offset,
            truncated: false,
        })
    }
}

/// A positional (`pread`) read head over a shared segment file.
///
/// [`RecordPayload`] seeks its source to the record offset before reading;
/// seeking a shared [`File`] would move one process-wide cursor under every
/// concurrent reader, so this head keeps its own position and never touches
/// the file cursor: every read is one positional read at the head's own
/// offset. Any number of heads over one cached `File` read concurrently
/// without disturbing each other.
///
/// `Seek` moves only the head's own position; `End` resolves against the
/// file's current length.
#[derive(Debug)]
pub(crate) struct PreadReader<'a> {
    file: &'a File,
    pos: u64,
}

impl<'a> PreadReader<'a> {
    pub(crate) fn new(file: &'a File) -> Self {
        Self { file, pos: 0 }
    }
}

impl Read for PreadReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let read = read_at(self.file, buf, self.pos)?;
        self.pos += u64::try_from(read).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "pread byte count overflows u64")
        })?;
        Ok(read)
    }
}

impl Seek for PreadReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::Current(delta) => relative_pos(self.pos, delta, "seek")?,
            SeekFrom::End(delta) => {
                let len = self.file.metadata()?.len();
                relative_pos(len, delta, "seek")?
            }
        };
        self.pos = next;
        Ok(next)
    }
}

/// Resolves a signed seek delta against `base` without wrapping.
fn relative_pos(base: u64, delta: i64, what: &str) -> io::Result<u64> {
    u64::try_from(i128::from(base) + i128::from(delta)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} would go before the start of the segment"),
        )
    })
}

/// One positional read: the shared-descriptor primitive. Never moves the
/// file cursor, so concurrent heads over one cached `File` stay independent.
#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

/// One positional read: the shared-descriptor primitive. Never moves the
/// file cursor, so concurrent heads over one cached `File` stay independent.
#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

impl<R> RecordPayload<R> {
    pub(crate) fn header(&self) -> &RecordHeader {
        &self.header
    }

    fn truncation_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            corrupt(format!(
                "record at offset {} is truncated: {} of {} payload bytes are missing",
                self.offset, self.remaining, self.header.payload_len
            )),
        )
    }
}

impl<R: Read> Read for RecordPayload<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.truncated {
            return Err(self.truncation_error());
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let cap = self.remaining.min(buf.len());
        let read = self.src.read(&mut buf[..cap])?;
        if read == 0 {
            self.truncated = true;
            return Err(self.truncation_error());
        }
        self.crc = crc32c_append(self.crc, &buf[..read]);
        self.remaining -= read;
        Ok(read)
    }
}

impl<R: Read> RecordPayload<R> {
    /// Drains the payload while verifying the stored checksum, returning the
    /// CRC32C over the payload alone. Compaction feeds that checksum back
    /// into [`SegmentWriter::append`] so the copied record carries identical
    /// framing without re-encoding its payload.
    ///
    /// # Errors
    /// `Corrupt` on missing bytes or a checksum mismatch; `Io` on I/O failure.
    pub(crate) fn finish_with_payload_crc(mut self) -> Result<u32, SegmentError> {
        let mut payload_crc = 0_u32;
        let mut scratch = [0_u8; DRAIN_CHUNK];
        while self.remaining > 0 {
            let amount = self.remaining.min(scratch.len());
            self.read_exact(&mut scratch[..amount])?;
            payload_crc = crc32c_append(payload_crc, &scratch[..amount]);
        }
        if self.crc != self.header.crc {
            return Err(corrupt(format!(
                "record checksum mismatch at offset {}: stored {:#010x}, computed {:#010x}",
                self.offset, self.header.crc, self.crc
            )));
        }
        Ok(payload_crc)
    }

    /// Consumes whatever the reader left unread, then checks the record
    /// checksum. Success means the entire record is intact.
    ///
    /// # Errors
    /// `Corrupt` on missing bytes or a checksum mismatch; `Io` on I/O failure.
    pub(crate) fn finish(mut self) -> Result<(), SegmentError> {
        let mut scratch = [0_u8; DRAIN_CHUNK];
        while self.remaining > 0 {
            let amount = self.remaining.min(scratch.len());
            self.read_exact(&mut scratch[..amount])?;
        }
        if self.crc != self.header.crc {
            return Err(corrupt(format!(
                "record checksum mismatch at offset {}: stored {:#010x}, computed {:#010x}",
                self.offset, self.header.crc, self.crc
            )));
        }
        Ok(())
    }
}

/// Walks every record in `[0, records_end)` of `src`, verifying boundaries,
/// kind/flags, extents and each record checksum, calling `visit(offset,
/// header)` for each record in order. Returns the CRC32C over all record
/// bytes (the value the seal footer stores and a resumed writer needs).
///
/// Memory use is one fixed buffer. The stream position is unspecified
/// afterwards.
///
/// # Errors
/// `Corrupt` for stray bytes that cannot hold a header, a record crossing
/// `records_end`, an unknown kind or flags byte, truncation, or a checksum
/// mismatch; `Io` otherwise.
pub(crate) fn scan_records<S: Read + Seek>(
    src: &mut S,
    records_end: u64,
    mut visit: impl FnMut(u64, &RecordHeader),
) -> Result<u32, SegmentError> {
    src.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::with_capacity(IO_CHUNK, &mut *src);
    let mut scratch = vec![0_u8; IO_CHUNK];
    let mut offset = 0_u64;
    let mut region_crc = 0_u32;
    while offset < records_end {
        let left = records_end - offset;
        if left < HEADER_LEN_U64 {
            return Err(corrupt(format!(
                "{left} stray bytes at offset {offset} cannot hold a record header"
            )));
        }
        let mut raw = [0_u8; HEADER_LEN];
        read_exact_or_corrupt(&mut reader, &mut raw, "record header", offset)?;
        let header = RecordHeader::decode(&raw, offset)?;
        let record_len = header.record_len();
        if record_len > left {
            return Err(corrupt(format!(
                "record at offset {offset} spans {record_len} bytes but only {left} remain inside the committed record extent {records_end}"
            )));
        }
        let mut record_crc = crc32c(&raw[..HEADER_PREFIX_LEN]);
        region_crc = crc32c_append(region_crc, &raw);
        let mut remaining = payload_usize(header.payload_len)?;
        while remaining > 0 {
            let take = remaining.min(scratch.len());
            let chunk = &mut scratch[..take];
            read_exact_or_corrupt(&mut reader, chunk, "record payload", offset)?;
            record_crc = crc32c_append(record_crc, chunk);
            region_crc = crc32c_append(region_crc, chunk);
            remaining -= take;
        }
        if record_crc != header.crc {
            return Err(corrupt(format!(
                "record checksum mismatch at offset {offset}: stored {:#010x}, computed {record_crc:#010x}",
                header.crc
            )));
        }
        visit(offset, &header);
        // record_len <= left, so this stays within records_end.
        offset += record_len;
    }
    Ok(region_crc)
}

/// Reads the footer at `records_end` and checks its magic, its own checksum
/// and that the extent it records equals the manifest's.
fn read_seal_footer<S: Read + Seek>(
    src: &mut S,
    records_end: u64,
) -> Result<SealFooter, SegmentError> {
    records_end.checked_add(FOOTER_LEN_U64).ok_or_else(|| {
        corrupt(format!(
            "records extent {records_end} leaves no room for a seal footer"
        ))
    })?;
    src.seek(SeekFrom::Start(records_end))?;
    let mut raw = [0_u8; FOOTER_LEN];
    read_exact_or_corrupt(src, &mut raw, "seal footer", records_end)?;
    let footer = SealFooter::decode(&raw)?;
    if footer.records_extent != records_end {
        return Err(corrupt(format!(
            "inconsistent sealed extent: the footer records {} but the manifest records {records_end}",
            footer.records_extent
        )));
    }
    Ok(footer)
}

/// Verifies a sealed segment: the footer at `records_end` is intact and
/// consistent, every record before it is valid, and the footer's records CRC
/// equals the one recomputed in a single bounded pass. Returns that CRC.
///
/// # Errors
/// As [`scan_records`], plus `Corrupt` for any footer defect or an extent or
/// CRC disagreement.
pub(crate) fn verify_seal<S: Read + Seek>(
    src: &mut S,
    records_end: u64,
) -> Result<u32, SegmentError> {
    let footer = read_seal_footer(src, records_end)?;
    let records_crc = scan_records(src, records_end, |_, _| ())?;
    if records_crc != footer.records_crc {
        return Err(corrupt(format!(
            "seal footer records checksum {:#010x} does not match the recomputed {records_crc:#010x}",
            footer.records_crc
        )));
    }
    Ok(records_crc)
}

/// Checks that manifest extents are self-consistent: an open segment's
/// committed end is its records end; a sealed one adds exactly the footer.
///
/// # Errors
/// `Corrupt`: committed metadata that contradicts itself is corruption.
pub(crate) fn validate_segment_layout(
    committed_end: u64,
    records_end: u64,
    sealed: bool,
) -> Result<(), SegmentError> {
    if sealed {
        let expected = records_end.checked_add(FOOTER_LEN_U64).ok_or_else(|| {
            corrupt(format!(
                "sealed records extent {records_end} leaves no room for a seal footer"
            ))
        })?;
        if committed_end != expected {
            return Err(corrupt(format!(
                "sealed segment committed end {committed_end} must be records end {records_end} plus the {FOOTER_LEN}-byte footer ({expected})"
            )));
        }
    } else if committed_end != records_end {
        return Err(corrupt(format!(
            "open segment committed end {committed_end} must equal its records end {records_end}"
        )));
    }
    Ok(())
}

/// What [`validate_segment_file`] proved about a segment file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedSegment {
    /// CRC32C over all record bytes; resume appends with it.
    pub(crate) records_crc: u32,
    /// Current file length. For an open segment, `file_len - committed_end`
    /// bytes are an uncommitted tail the owner may truncate; a sealed file
    /// never has one (validation fails instead).
    pub(crate) file_len: u64,
}

/// Verifies a segment file against its manifest extents with bounded memory.
///
/// Open: layout is consistent, the file holds at least `committed_end` bytes,
/// and every record in `[0, records_end)` is valid. Sealed: layout is
/// consistent, the file is exactly `committed_end` long, and [`verify_seal`]
/// passes. Missing bytes are never extended and trailing bytes after a seal
/// are never ignored. A retired segment's file is the owner's concern; call
/// this only for files that must exist.
///
/// # Errors
/// `Corrupt` for every violation above; `Io` for real I/O failures.
pub(crate) fn validate_segment_file<S: Read + Seek>(
    src: &mut S,
    committed_end: u64,
    records_end: u64,
    sealed: bool,
) -> Result<VerifiedSegment, SegmentError> {
    validate_segment_layout(committed_end, records_end, sealed)?;
    let file_len = src.seek(SeekFrom::End(0))?;
    if file_len < committed_end {
        return Err(corrupt(format!(
            "committed bytes are missing: the file holds {file_len} of {committed_end} bytes"
        )));
    }
    if sealed && file_len != committed_end {
        return Err(corrupt(format!(
            "sealed segment holds {} bytes after its footer",
            file_len - committed_end
        )));
    }
    let records_crc = if sealed {
        verify_seal(src, records_end)?
    } else {
        scan_records(src, records_end, |_, _| ())?
    };
    Ok(VerifiedSegment {
        records_crc,
        file_len,
    })
}

/// The file name of segment `id`: `seg_` and sixteen lowercase hex digits.
pub(crate) fn segment_file_name(id: u64) -> String {
    format!("seg_{id:016x}")
}
