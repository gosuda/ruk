//! Streaming object preparation and verified record decode.
//!
//! Preparation turns exact input bytes into one stored payload: zstd level 3,
//! or a zstd-compressed canonical Git delta over a known local predecessor
//! when the full stored payload (base digest included) is strictly below half
//! the raw length. The object identity is hashed while the input streams.
//! Nothing is read before the declared length passes admission, and nothing
//! is allocated from the declared length: input flows through one bounded
//! chunk into a charged [`SpoolWriter`] sink.
//!
//! Decode is the exact inverse and is the only way stored payloads become
//! trusted bytes. It rejects malformed zstd (truncated, trailing bytes,
//! concatenated frames, frames needing a window above the level 3 maximum),
//! output above the declared length, malformed deltas and identity
//! mismatches.
//!
//! Memory accounting: spools, the I/O chunk and a fixed codec allowance are
//! charged to the shared budget. The allowance is an estimate of the heap
//! libzstd allocates outside the Rust allocator (window, tables, buffers); it
//! is conservative but not measured.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;

use zstd::stream::read::Decoder;
use zstd::stream::write::Encoder;

use crate::ids::{HashKind, Oid};
use crate::store::MAX_DELTA_DEPTH;
use crate::store::delta::{self, IO_CHUNK, classify_read};
use crate::store::error::StoreError;
use crate::store::pinned::PinnedRoot;
use crate::store::spool::{PreparationBudget, Spool, SpoolView, SpoolWriter, io_to_store, to_u64};
use crate::store::types::{Encoding, ObjectKind, PreparedObject, ReadObject};

/// The one ordinary compression level.
const ENCODE_LEVEL: i32 = 3;
/// Largest window any frame we accept may need: zstd level 3 uses
/// `windowLog` 21 in every size class, so a larger window is hostile.
const ZSTD_WINDOW_LOG_MAX: u32 = 21;
/// Chunk buffers, hasher state and the delta instruction frame.
const IO_ALLOWANCE: u64 = 1 << 20;
/// Level 3 encoder heap for a pledged source of at most [`SMALL_OBJECT`].
const ENCODE_ALLOWANCE_SMALL: u64 = 2 << 20;
/// Level 3 encoder heap with the full 2 MiB window and streaming buffers.
const ENCODE_ALLOWANCE_LARGE: u64 = 10 << 20;
/// Decoder heap for a frame of at most the 2 MiB window cap.
const DECODE_ALLOWANCE: u64 = 4 << 20;
const SMALL_OBJECT: u64 = 128 * 1024;
/// Largest encoded payload the u32 record framing can carry.
const MAX_RECORD_PAYLOAD: u64 = 0xffff_ffff;

/// Marker: the delta payload crossed the keep threshold; fall back to zstd.
#[derive(Debug, thiserror::Error)]
#[error("delta payload exceeds the keep threshold")]
struct OverThreshold;

/// Marker: the encoded payload cannot be framed in a u32 length.
#[derive(Debug, thiserror::Error)]
#[error("encoded payload exceeds the u32 record framing")]
struct FrameOverflow;

/// Encoded-payload sink: counts and checksums every stored byte and refuses
/// both the u32 framing overflow and (for deltas) the keep threshold before
/// the byte is written.
pub(super) struct EncodedSink {
    out: SpoolWriter,
    crc: u32,
    written: u64,
    keep_limit: Option<u64>,
}

/// A finished encoded payload.
struct Encoded {
    payload: Spool,
    crc: u32,
    len: u64,
}

impl EncodedSink {
    pub(super) fn new(out: SpoolWriter, keep_limit: Option<u64>) -> Self {
        Self {
            out,
            crc: 0,
            written: 0,
            keep_limit,
        }
    }

    #[cfg(test)]
    pub(super) fn preset_written(&mut self, written: u64) {
        self.written = written;
    }

    fn finish(self) -> Result<Encoded, StoreError> {
        let payload = self.out.finish()?;
        Ok(Encoded {
            payload,
            crc: self.crc,
            len: self.written,
        })
    }
}

impl Write for EncodedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let total = self
            .written
            .checked_add(to_u64(buf.len()))
            .filter(|total| *total <= MAX_RECORD_PAYLOAD)
            .ok_or_else(|| io::Error::other(FrameOverflow))?;
        if self.keep_limit.is_some_and(|limit| total > limit) {
            return Err(io::Error::other(OverThreshold));
        }
        self.out
            .append(buf)
            .map_err(crate::store::spool::store_to_io)?;
        self.crc = crc32c::crc32c_append(self.crc, buf);
        self.written = total;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a failed write into an [`EncodedSink`] means.
pub(super) enum Failure {
    OverThreshold,
    Store(StoreError),
}

pub(super) fn classify_sink(err: io::Error) -> Failure {
    match err.get_ref() {
        Some(inner) if inner.is::<OverThreshold>() => Failure::OverThreshold,
        Some(inner) if inner.is::<FrameOverflow>() => Failure::Store(StoreError::Capacity(
            "encoded payload exceeds the u32 record framing limit".to_owned(),
        )),
        _ => Failure::Store(io_to_store(err)),
    }
}

impl Failure {
    /// For callers whose sink has no keep threshold.
    fn into_store(self) -> StoreError {
        match self {
            Self::OverThreshold => {
                StoreError::Invalid("unexpected delta threshold abort".to_owned())
            }
            Self::Store(err) => err,
        }
    }
}

/// Hashes everything written through it, then forwards it.
struct HashTee<W: Write> {
    hasher: gix_hash::Hasher,
    out: W,
    count: u64,
}

impl<W: Write> HashTee<W> {
    fn new(hasher: gix_hash::Hasher, out: W) -> Self {
        Self {
            hasher,
            out,
            count: 0,
        }
    }
}

impl<W: Write> Write for HashTee<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.write_all(buf)?;
        self.hasher.update(buf);
        self.count += to_u64(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Canonical object hash start: Git kinds hash `<kind> <len>\0` first;
/// native conflict bytes arrive already framed and are hashed as they are.
fn start_hasher(hash_kind: HashKind, kind: ObjectKind, decoded_len: u64) -> gix_hash::Hasher {
    let mut hasher = gix_hash::hasher(hash_kind.gix());
    if let Some(name) = kind.git_header_name() {
        hasher.update(format!("{name} {decoded_len}\0").as_bytes());
    }
    hasher
}

/// The object hasher refused to finish (SHA-1 collision detection).
#[derive(Debug, thiserror::Error)]
#[error("object hash refused: {0}")]
struct HashRefused(String);

fn finish_hasher(hasher: gix_hash::Hasher) -> Result<Oid, HashRefused> {
    hasher
        .try_finalize()
        .map(Oid::from)
        .map_err(|err| HashRefused(err.to_string()))
}

fn corrupt(detail: impl Into<String>) -> StoreError {
    StoreError::Corrupt(detail.into())
}

fn chunk_len(decoded_len: u64) -> usize {
    usize::try_from(decoded_len)
        .unwrap_or(usize::MAX)
        .clamp(1, IO_CHUNK)
}

fn read_input<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<usize, StoreError> {
    loop {
        match input.read(buf) {
            Ok(read) => return Ok(read),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(StoreError::Io(err)),
        }
    }
}

enum Ingest {
    Input(StoreError),
    Sink(io::Error),
}

fn ingest_error(err: Ingest) -> StoreError {
    match err {
        Ingest::Input(err) => err,
        Ingest::Sink(err) => classify_sink(err).into_store(),
    }
}

/// Copies exactly `declared` bytes from `input` to `sink` in bounded chunks
/// and proves the input ends there. Shorter and longer inputs are
/// `E_INVALID`.
fn ingest<R: Read, W: Write>(
    input: &mut R,
    declared: u64,
    sink: &mut W,
    chunk: &mut [u8],
) -> Result<(), Ingest> {
    let mut remaining = declared;
    while remaining > 0 {
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        let read = read_input(input, &mut chunk[..want]).map_err(Ingest::Input)?;
        if read == 0 {
            return Err(Ingest::Input(StoreError::Invalid(format!(
                "input ended {remaining} bytes before the declared length of {declared}"
            ))));
        }
        sink.write_all(&chunk[..read]).map_err(Ingest::Sink)?;
        remaining -= to_u64(read);
    }
    let mut probe = [0_u8; 1];
    if read_input(input, &mut probe).map_err(Ingest::Input)? != 0 {
        return Err(Ingest::Input(StoreError::Invalid(format!(
            "input is longer than the declared length of {declared}"
        ))));
    }
    Ok(())
}

fn new_encoder<W: Write>(sink: W, pledged: Option<u64>) -> Result<Encoder<'static, W>, StoreError> {
    let mut encoder = Encoder::new(sink, ENCODE_LEVEL)?;
    if pledged.is_some() {
        encoder.set_pledged_src_size(pledged)?;
    }
    Ok(encoder)
}

/// Everything one preparation shares across its phases.
struct Job<'a> {
    hash_kind: HashKind,
    kind: ObjectKind,
    decoded_len: u64,
    budget: &'a Arc<PreparationBudget>,
    store_root: &'a Path,
    pin: &'a PinnedRoot,
}

impl Job<'_> {
    fn writer(&self) -> SpoolWriter {
        SpoolWriter::new(self.budget, self.store_root, self.pin)
    }

    fn prepared(
        &self,
        oid: Oid,
        encoding: Encoding,
        encoded: Encoded,
        base: Option<(Oid, u8)>,
    ) -> PreparedObject {
        PreparedObject {
            oid,
            kind: self.kind,
            decoded_len: self.decoded_len,
            encoding,
            payload: encoded.payload,
            payload_crc: encoded.crc,
            base: base.map(|(oid, _)| oid),
            depth: base.map_or(0, |(_, depth)| depth),
        }
    }
}

/// Predecessor eligibility. A malformed predecessor is an error; one that
/// merely cannot pay off (chain at its depth cap, empty base, target too
/// small for any payload below half) is ignored and the object is stored
/// as zstd.
fn vet_predecessor<'a>(
    job: &Job<'_>,
    predecessor: Option<(Oid, &'a ReadObject)>,
) -> Result<Option<(Oid, &'a ReadObject)>, StoreError> {
    let Some((oid, read)) = predecessor else {
        return Ok(None);
    };
    if oid.kind() != job.hash_kind {
        return Err(StoreError::ObjectFormat(format!(
            "predecessor {oid} is not a {} object id",
            job.hash_kind
        )));
    }
    if read.kind != job.kind {
        return Err(StoreError::Invalid(format!(
            "predecessor {oid} is a {:?} object, not a {:?}",
            read.kind, job.kind
        )));
    }
    let oid_len = to_u64(job.hash_kind.oid_len());
    let worthwhile = read.depth < MAX_DELTA_DEPTH
        && !read.bytes.is_empty()
        && job.decoded_len > 2 * (oid_len + 1);
    Ok(worthwhile.then_some((oid, read)))
}

/// Prepares one object from exactly `decoded_len` input bytes.
///
/// Order: admission against `max_object_bytes`, predecessor checks, working
/// reservation, then the streaming read. A predecessor, when supplied, must
/// already be verified decoded bytes of the same kind; preparation never
/// opens metadata.
///
/// # Errors
/// `E_LIMIT` for admission or an exhausted budget, `E_CAPACITY` when the
/// encoded payload cannot be framed, `E_INVALID` when the input length
/// differs from `decoded_len` or the predecessor is unusable, `E_IO` for
/// read or scratch failures. A failure leaves no visible state: every spool
/// and reservation is released.
#[expect(
    clippy::too_many_arguments,
    reason = "the frozen store integration contract names each of these inputs"
)]
pub(crate) fn prepare_object(
    hash_kind: HashKind,
    kind: ObjectKind,
    decoded_len: u64,
    mut input: impl Read,
    predecessor: Option<(Oid, &ReadObject)>,
    budget: &Arc<PreparationBudget>,
    store_root: &Path,
    pin: &PinnedRoot,
) -> Result<PreparedObject, StoreError> {
    if let Some(max) = budget.limits().max_object_bytes
        && decoded_len > max
    {
        return Err(StoreError::Limit(format!(
            "object of {decoded_len} bytes exceeds the admission limit of {max} bytes"
        )));
    }
    let job = Job {
        hash_kind,
        kind,
        decoded_len,
        budget,
        store_root,
        pin,
    };
    let base = vet_predecessor(&job, predecessor)?;
    let encode_allowance = if decoded_len <= SMALL_OBJECT && base.is_none() {
        ENCODE_ALLOWANCE_SMALL
    } else {
        ENCODE_ALLOWANCE_LARGE
    };
    let _working = budget.reserve_memory(IO_ALLOWANCE + encode_allowance)?;
    let mut chunk = vec![0_u8; chunk_len(decoded_len)];
    let hasher = start_hasher(hash_kind, kind, decoded_len);
    match base {
        None => prepare_direct(&job, &mut input, hasher, &mut chunk),
        Some(base) => prepare_with_base(&job, &mut input, hasher, &mut chunk, base),
    }
}

/// No predecessor: one pass hashes and compresses; the raw bytes are never
/// stored.
fn prepare_direct<R: Read>(
    job: &Job<'_>,
    input: &mut R,
    hasher: gix_hash::Hasher,
    chunk: &mut [u8],
) -> Result<PreparedObject, StoreError> {
    let sink = EncodedSink::new(job.writer(), None);
    let encoder = new_encoder(sink, Some(job.decoded_len))?;
    let mut tee = HashTee::new(hasher, encoder);
    ingest(input, job.decoded_len, &mut tee, chunk).map_err(ingest_error)?;
    let HashTee {
        hasher,
        out: encoder,
        ..
    } = tee;
    let encoded = encoder
        .finish()
        .map_err(|err| classify_sink(err).into_store())?
        .finish()?;
    let oid = finish_hasher(hasher).map_err(|err| StoreError::Invalid(err.to_string()))?;
    Ok(job.prepared(oid, Encoding::Zstd, encoded, None))
}

/// With a predecessor: spool the raw bytes once (they are needed for the
/// suffix comparison and for the zstd fallback), then try the delta.
fn prepare_with_base<R: Read>(
    job: &Job<'_>,
    input: &mut R,
    hasher: gix_hash::Hasher,
    chunk: &mut [u8],
    base: (Oid, &ReadObject),
) -> Result<PreparedObject, StoreError> {
    let mut tee = HashTee::new(hasher, job.writer());
    ingest(input, job.decoded_len, &mut tee, chunk).map_err(ingest_error)?;
    let HashTee {
        hasher, out: raw, ..
    } = tee;
    let raw = raw.finish()?;
    let oid = finish_hasher(hasher).map_err(|err| StoreError::Invalid(err.to_string()))?;
    let (base_oid, base_read) = base;
    if let Some(encoded) = try_delta(job, &raw, base_oid, base_read)? {
        let depth = base_read.depth.saturating_add(1);
        return Ok(job.prepared(oid, Encoding::Delta, encoded, Some((base_oid, depth))));
    }
    let encoded = compress_spool(job, &raw, chunk)?;
    Ok(job.prepared(oid, Encoding::Zstd, encoded, None))
}

/// Builds `[base digest][zstd(delta)]` and keeps it only when it stays
/// strictly below half the raw length. The sink aborts the moment the
/// payload crosses that bound, so a hopeless delta costs bounded work and
/// disk.
fn try_delta(
    job: &Job<'_>,
    raw: &Spool,
    base_oid: Oid,
    base: &ReadObject,
) -> Result<Option<Encoded>, StoreError> {
    let oid_len = to_u64(job.hash_kind.oid_len());
    // Largest stored size S with 2 * S < decoded_len.
    let stored_max = (job.decoded_len - 1) / 2;
    if stored_max <= oid_len {
        return Ok(None);
    }
    let mut sink = EncodedSink::new(job.writer(), Some(stored_max));
    sink.write_all(base_oid.as_bytes())
        .map_err(|err| classify_sink(err).into_store())?;
    let mut encoder = new_encoder(sink, None)?;
    let mut base_view = base.bytes.view();
    let mut raw_view = raw.view();
    let finished = delta::encode_delta(
        &mut base_view,
        base.bytes.len(),
        &mut raw_view,
        job.decoded_len,
        &mut encoder,
    )
    .and_then(|()| encoder.finish());
    let sink = match finished {
        Ok(sink) => sink,
        Err(err) => {
            return match classify_sink(err) {
                Failure::OverThreshold => Ok(None),
                Failure::Store(err) => Err(err),
            };
        }
    };
    let encoded = sink.finish()?;
    if encoded.len.saturating_mul(2) >= job.decoded_len {
        return Ok(None);
    }
    Ok(Some(encoded))
}

/// zstd level 3 over an already verified raw spool.
fn compress_spool(job: &Job<'_>, raw: &Spool, chunk: &mut [u8]) -> Result<Encoded, StoreError> {
    let sink = EncodedSink::new(job.writer(), None);
    let mut encoder = new_encoder(sink, Some(job.decoded_len))?;
    let mut view = raw.view();
    loop {
        let read = read_input(&mut view, chunk)?;
        if read == 0 {
            break;
        }
        encoder
            .write_all(&chunk[..read])
            .map_err(|err| classify_sink(err).into_store())?;
    }
    encoder
        .finish()
        .map_err(|err| classify_sink(err).into_store())?
        .finish()
}

/// Reads at most `limit` bytes from `inner` and, at the limit, proves that
/// `inner` ends there. Asking `inner` for end-of-stream is what lets a
/// record reader finish its own checksum verification.
struct BoundedSource<R: Read> {
    inner: R,
    consumed: u64,
    limit: u64,
}

impl<R: Read> Read for BoundedSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let left = self.limit - self.consumed;
        if left == 0 {
            let mut probe = [0_u8; 1];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored payload is longer than its declared length",
                ))
            };
        }
        let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
        let read = self.inner.read(&mut buf[..want])?;
        self.consumed += to_u64(read);
        Ok(read)
    }
}

/// Keeps the original error of the stored-bytes reader so a decoder that
/// flattens it into its own error does not hide a segment diagnosis.
struct SourceGuard<R: Read> {
    inner: R,
    failure: Option<io::Error>,
}

impl<R: Read> Read for SourceGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(read) => Ok(read),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => Err(err),
            Err(err) => {
                let echo = io::Error::new(err.kind(), err.to_string());
                self.failure = Some(err);
                Err(echo)
            }
        }
    }
}

/// One zstd frame, nothing else. The decoder window is capped at the level 3
/// maximum, decoding stops after the first frame, and [`Self::finish`]
/// proves no byte follows it. `zstd::Decoder::finish` ignores
/// `finish_frame` errors, so it is not used.
struct FrameReader<R: Read> {
    decoder: Decoder<'static, BufReader<SourceGuard<R>>>,
}

impl<R: Read> FrameReader<R> {
    fn new(source: R) -> Result<Self, StoreError> {
        let mut decoder = Decoder::new(SourceGuard {
            inner: source,
            failure: None,
        })?;
        decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
        Ok(Self {
            decoder: decoder.single_frame(),
        })
    }

    fn finish(self) -> Result<(), StoreError> {
        let mut buffered = self.decoder.into_inner();
        match buffered.fill_buf().map(<[u8]>::is_empty) {
            Ok(true) => Ok(()),
            Ok(false) => Err(corrupt("bytes follow the zstd frame")),
            Err(err) => {
                let original = buffered.get_mut().failure.take().unwrap_or(err);
                Err(classify_read(original, "zstd payload"))
            }
        }
    }
}

impl<R: Read> Read for FrameReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.decoder.read(buf) {
            Ok(read) => Ok(read),
            Err(err) => match self.decoder.get_mut().get_mut().failure.take() {
                Some(source) => Err(source),
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("zstd: {err}"),
                )),
            },
        }
    }
}

/// Copies exactly `len` bytes from `source` to `sink` and proves `source`
/// ends there, so surplus output of a decompression bomb is refused after
/// one extra byte.
fn copy_exact<R: Read, W: Write>(
    source: &mut R,
    len: u64,
    sink: &mut W,
    chunk: &mut [u8],
    what: &str,
) -> Result<(), StoreError> {
    let mut remaining = len;
    while remaining > 0 {
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        let read = match source.read(&mut chunk[..want]) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(classify_read(err, what)),
        };
        if read == 0 {
            return Err(corrupt(format!(
                "{what} ends {remaining} bytes before its declared length of {len}"
            )));
        }
        sink.write_all(&chunk[..read]).map_err(io_to_store)?;
        remaining -= to_u64(read);
    }
    let mut probe = [0_u8; 1];
    loop {
        match source.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(corrupt(format!(
                    "{what} is longer than its declared length of {len}"
                )));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(classify_read(err, what)),
        }
    }
}

fn check_delta_prefix<R: Read>(
    source: &mut R,
    hash_kind: HashKind,
    base_oid: &Oid,
) -> Result<(), StoreError> {
    if base_oid.kind() != hash_kind {
        return Err(StoreError::ObjectFormat(format!(
            "delta base {base_oid} is not a {hash_kind} object id"
        )));
    }
    let width = hash_kind.oid_len();
    let mut digest = [0_u8; 32];
    source
        .read_exact(&mut digest[..width])
        .map_err(|err| classify_read(err, "delta base digest"))?;
    if digest[..width] != *base_oid.as_bytes() {
        return Err(corrupt(format!(
            "delta payload names a different base than the recorded {base_oid}"
        )));
    }
    Ok(())
}

/// Decodes and verifies one stored record payload.
///
/// `encoded` is positioned at the first payload byte and yields exactly
/// `encoded_len` bytes. For [`Encoding::Delta`], `base` is the already
/// decoded and verified base with its identity; the payload's embedded base
/// digest must equal it. The decoded bytes are hashed while they stream and
/// must equal `oid`; the returned spool exists only after that check.
///
/// # Errors
/// `E_CORRUPT` for every malformed or mismatching stored byte (including
/// truncation reported by the record reader), `E_IO` for real read failures
/// of the stored bytes or scratch, `E_LIMIT` when the budget refuses the
/// output. A failure releases every reservation and spool.
#[expect(
    clippy::too_many_arguments,
    reason = "the frozen store integration contract names each of these inputs"
)]
pub(crate) fn decode_record(
    hash_kind: HashKind,
    kind: ObjectKind,
    oid: &Oid,
    encoding: Encoding,
    encoded: impl Read,
    encoded_len: u64,
    decoded_len: u64,
    base: Option<(Oid, SpoolView<'_>)>,
    budget: &Arc<PreparationBudget>,
    store_root: &Path,
    pin: &PinnedRoot,
) -> Result<Spool, StoreError> {
    if oid.kind() != hash_kind {
        return Err(StoreError::ObjectFormat(format!(
            "object {oid} is not a {hash_kind} object id"
        )));
    }
    let codec = match encoding {
        Encoding::Raw => 0,
        Encoding::Zstd | Encoding::Delta => DECODE_ALLOWANCE,
    };
    let _working = budget.reserve_memory(IO_ALLOWANCE + codec)?;
    let mut source = BoundedSource {
        inner: encoded,
        consumed: 0,
        limit: encoded_len,
    };
    let mut tee = HashTee::new(
        start_hasher(hash_kind, kind, decoded_len),
        SpoolWriter::new(budget, store_root, pin),
    );
    // The streaming chunk lives only in the arms that copy through it. The
    // Delta arm decodes via `apply_delta`'s own bounded buffers and must not
    // pay for a chunk it never uses.
    match (encoding, base) {
        (Encoding::Raw, None) => {
            if encoded_len != decoded_len {
                return Err(corrupt(format!(
                    "raw payload of {encoded_len} bytes declares {decoded_len} decoded bytes"
                )));
            }
            let mut chunk = vec![0_u8; chunk_len(decoded_len)];
            copy_exact(
                &mut source,
                decoded_len,
                &mut tee,
                &mut chunk,
                "raw payload",
            )?;
        }
        (Encoding::Zstd, None) => {
            let mut chunk = vec![0_u8; chunk_len(decoded_len)];
            let mut frame = FrameReader::new(&mut source)?;
            copy_exact(
                &mut frame,
                decoded_len,
                &mut tee,
                &mut chunk,
                "zstd payload",
            )?;
            frame.finish()?;
        }
        (Encoding::Delta, Some((base_oid, mut base_view))) => {
            check_delta_prefix(&mut source, hash_kind, &base_oid)?;
            let base_len = base_view.len();
            let mut frame = FrameReader::new(&mut source)?;
            delta::apply_delta(&mut base_view, base_len, &mut frame, decoded_len, &mut tee)?;
            frame.finish()?;
        }
        (Encoding::Delta, None) => return Err(corrupt("delta record without a base")),
        (_, Some(_)) => return Err(corrupt("non-delta record with a delta base")),
    }
    if source.consumed != encoded_len {
        return Err(corrupt(format!(
            "stored payload ends after {} of its declared {encoded_len} bytes",
            source.consumed
        )));
    }
    if tee.count != decoded_len {
        return Err(corrupt(format!(
            "record decodes to {} bytes, not the declared {decoded_len}",
            tee.count
        )));
    }
    let HashTee {
        hasher, out: spool, ..
    } = tee;
    let actual = finish_hasher(hasher).map_err(|err| StoreError::Corrupt(err.to_string()))?;
    if actual != *oid {
        return Err(corrupt(format!("stored object {oid} hashes to {actual}")));
    }
    spool.finish()
}
