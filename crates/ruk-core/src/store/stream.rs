//! Chunked streaming object reads over committed segments.
//!
//! [`Store::read_chunks`] decodes one object through bounded buffers and
//! delivers its bytes to a caller callback in [`IO_CHUNK`] slices. It is the
//! streaming counterpart to the buffered [`Store::read`]: large blobs never
//! sit fully in memory, while small objects keep the [`Spool`] path that
//! [`Store::read`] returns.
//!
//! # Memory bound
//!
//! The target object is never materialized. The call holds one fixed working
//! reservation ([`STREAM_WORKING_MEMORY`], covering the chunk buffer, the
//! hasher state and the zstd decoder heap) plus the zstd decoder's own
//! fixed heap. A delta target additionally holds its decoded base as one
//! [`Spool`], fetched through the verified [`Store::read`]; deeper chains
//! resolve through the same call, so the steady-state extra cost is exactly
//! one base object. Non-delta objects hold no spool at all.
//!
//! # Verification
//!
//! Stored bytes stream through [`RecordPayload`], which folds every byte
//! into the record checksum incrementally; the checksum, the declared
//! lengths, and the object identity hash are all verified before a complete
//! result returns. A callback that stops early ([`ChunkDecision::Stop`])
//! gets an explicit incomplete result whose bytes are unverified: stopping
//! is a caller choice, never silent truncation. Any mid-stream damage or
//! I/O failure propagates as a typed [`StoreError`] and latches quarantine
//! exactly like [`Store::read`]; a successful complete result always
//! carries exactly `decoded_len` bytes.
//!
//! Reads release every metadata transaction before payload I/O and hold one
//! physical reader guard across the whole chunk loop, so retired segments
//! stay pinned exactly as they do for [`Store::read`]. Completed streams
//! count toward the same I/O counters; stopped streams count only the
//! metadata lookup.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::atomic::Ordering;

use zstd::stream::read::Decoder;

#[cfg(test)]
use super::SEGMENTS_DIR;
use super::Store;
use super::delta::{IO_CHUNK, apply_delta, classify_read};
use super::error::StoreError;
use super::segment::{PreadReader, RecordPayload};
use super::spool::to_u64;
use super::types::{Encoding, ObjectKind, ReadObject};
use crate::ids::{HashKind, Oid};

/// Largest window any accepted frame may need: zstd level 3 uses
/// `windowLog` 21 in every size class, so a larger window is hostile.
/// Mirrors the preparation decoder, which owns the window policy.
const ZSTD_WINDOW_LOG_MAX: u32 = 21;
/// Fixed working reservation of one stream: the chunk buffer, the hasher
/// state and the instruction frame (1 MiB, mirroring the preparation
/// decoder's I/O allowance) plus the zstd decoder heap for a frame at the
/// window cap (4 MiB, mirroring its decode allowance). Never proportional
/// to the object: the target is decoded, not stored.
const STREAM_WORKING_MEMORY: u64 = 5 << 20;

/// Whether the chunk callback wants more bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkDecision {
    /// Deliver the next chunk.
    Continue,
    /// Stop after the delivered prefix. The stream returns an incomplete
    /// [`StreamMeta`] whose bytes carry no identity proof.
    Stop,
}

/// What one [`Store::read_chunks`] call delivered and proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamMeta {
    /// The streamed object identity.
    pub oid: Oid,
    /// The streamed object kind.
    pub kind: ObjectKind,
    /// Declared decoded length in bytes.
    pub decoded_len: u64,
    /// Delta chain depth of the stored record (0 for non-delta).
    pub depth: u8,
    /// Bytes delivered to the callback.
    pub streamed_bytes: u64,
    /// Whether the whole object verified. True only after the record
    /// checksum, the declared lengths, and the object identity all checked
    /// out; a stopped stream reports false with whatever prefix it got.
    pub complete: bool,
}

impl Store {
    /// Streams one committed object to `on_chunk` in slices of at most
    /// [`IO_CHUNK`] bytes, without materializing the decoded object.
    ///
    /// The callback returns [`ChunkDecision::Continue`] for the next slice
    /// or [`ChunkDecision::Stop`] to end early with an incomplete,
    /// unverified [`StreamMeta`]. A callback failure aborts the stream with
    /// that exact error. A complete result verified the record checksum
    /// incrementally, then the lengths and the object identity, and always
    /// carries exactly `decoded_len` bytes, byte-identical to [`Store::read`].
    ///
    /// Delta targets decode over their verified base, which is the only
    /// object-sized allocation a stream may hold; every other buffer is
    /// bounded by [`IO_CHUNK`] plus the fixed [`STREAM_WORKING_MEMORY`]
    /// reservation.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unpublished id;
    /// [`StoreError::ObjectFormat`] for a digest of the wrong width;
    /// [`StoreError::Corrupt`] for any damage, which also latches
    /// quarantine; [`StoreError::Limit`] when the working reservation is
    /// refused. Quarantine refuses before any of these.
    pub fn read_chunks(
        &self,
        oid: Oid,
        on_chunk: &mut dyn FnMut(&[u8]) -> Result<ChunkDecision, StoreError>,
    ) -> Result<StreamMeta, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.metadata_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.stream_target(oid, on_chunk);
        if let Ok(meta) = &result
            && meta.complete
        {
            self.io.object_reads.fetch_add(1, Ordering::Relaxed);
            self.io
                .object_decoded_bytes
                .fetch_add(meta.streamed_bytes, Ordering::Relaxed);
        }
        self.observe(result)
    }

    /// Captures the target snapshot, resolves a delta base when the locator
    /// names one, and pumps the target record through the chunk callback.
    /// The metadata transaction is released before the first payload byte;
    /// the reader guard stays held until the callback loop ends.
    fn stream_target(
        &self,
        oid: Oid,
        on_chunk: &mut dyn FnMut(&[u8]) -> Result<ChunkDecision, StoreError>,
    ) -> Result<StreamMeta, StoreError> {
        let committed = self.committed();
        committed.check_width(oid)?;
        let _working = self.budget.reserve_memory(STREAM_WORKING_MEMORY)?;
        let guard = self.guards.register();
        let snapshot = self.meta.snapshot_object_chain(self.format.kind, &oid)?;
        let Some(target) = snapshot.links().first() else {
            return Err(corrupt(format!("delta chain of {oid} is empty")));
        };
        if let Some(base_oid) = target.location.base {
            let chained = snapshot
                .links()
                .get(1)
                .is_some_and(|link| link.oid == base_oid);
            if !chained {
                return Err(corrupt(format!(
                    "delta chain of {oid} is inconsistent with its base"
                )));
            }
        }
        let base = match target.location.base {
            Some(base_oid) => Some(self.read(base_oid)?),
            None => None,
        };
        let location = &target.location;
        let manifest = &target.manifest;
        location
            .offset
            .checked_add(location.record_len)
            .filter(|end| *end <= manifest.records_end)
            .ok_or_else(|| {
                corrupt(format!(
                    "object {oid} record [{}, +{}) leaves segment {} record extent {}",
                    location.offset, location.record_len, manifest.id, manifest.records_end
                ))
            })?;
        // The cached read-only handle: positional reads keep the shared
        // cursor untouched, so concurrent streams stay independent.
        let file = committed.open_committed(location.segment)?;
        let mut payload = RecordPayload::open(
            BufReader::with_capacity(IO_CHUNK, PreadReader::new(&file)),
            location.offset,
            manifest.records_end,
        )?;
        let header = *payload.header();
        if header.kind != location.kind
            || header.record_len() != location.record_len
            || (header.encoding == Encoding::Delta) != location.base.is_some()
        {
            return Err(corrupt(format!(
                "record at {} in segment {} disagrees with the locator of {oid}",
                location.offset, manifest.id
            )));
        }
        let target = StreamTarget {
            oid,
            kind: snapshot.target_kind(),
            decoded_len: location.decoded_len,
            depth: snapshot.target_depth(),
        };
        let encoded_len = u64::from(header.payload_len);
        let mut sink = ChunkSink::new(
            start_stream_hasher(self.format.kind, target.kind, target.decoded_len),
            on_chunk,
        );
        let mut chunk = vec![0_u8; stream_chunk_len(target.decoded_len)];
        let step = match (header.encoding, location.base) {
            (Encoding::Raw, None) => {
                pump_raw(payload, &mut sink, &mut chunk, &target, encoded_len)?
            }
            (Encoding::Zstd, None) => pump_zstd(payload, &mut sink, &mut chunk, &target)?,
            (Encoding::Delta, Some(base_oid)) => pump_delta(
                payload,
                &mut sink,
                base.as_ref(),
                &target,
                self.format.kind,
                base_oid,
            )?,
            (Encoding::Delta, None) => return Err(corrupt("delta record without a base")),
            (_, Some(_)) => return Err(corrupt("non-delta record with a delta base")),
        };
        let (payload, consumed) = match step {
            Step::Stopped => return Ok(stopped_meta(&target, &sink)),
            Step::Complete(payload, consumed) => (payload, consumed),
        };
        if consumed != encoded_len {
            return Err(corrupt(format!(
                "stored payload ends after {consumed} of its declared {encoded_len} bytes"
            )));
        }
        if sink.count != target.decoded_len {
            return Err(corrupt(format!(
                "record decodes to {} bytes, not the declared {}",
                sink.count, target.decoded_len
            )));
        }
        let ChunkSink { hasher, .. } = sink;
        let actual = Oid::from(
            hasher
                .try_finalize()
                .map_err(|err| corrupt(format!("object hash refused: {err}")))?,
        );
        if actual != target.oid {
            return Err(corrupt(format!(
                "stored object {} hashes to {actual}",
                target.oid
            )));
        }
        payload.finish()?;
        drop(guard);
        Ok(StreamMeta {
            oid: target.oid,
            kind: target.kind,
            decoded_len: target.decoded_len,
            depth: target.depth,
            streamed_bytes: target.decoded_len,
            complete: true,
        })
    }
}

/// What one per-encoding pump proved: the full record with its payload and
/// consumed stored-byte count, or a clean callback stop with nothing left
/// to verify.
enum Step<'a> {
    Complete(StoredPayload<'a>, u64),
    Stopped,
}

/// One stored record positioned for decoding.
type StoredPayload<'a> = RecordPayload<BufReader<PreadReader<'a>>>;

/// Identity of the streaming target, shared by the per-encoding pumps.
struct StreamTarget {
    oid: Oid,
    kind: ObjectKind,
    decoded_len: u64,
    depth: u8,
}

fn corrupt(detail: impl Into<String>) -> StoreError {
    StoreError::Corrupt(detail.into())
}

/// Canonical object hash start, mirroring the preparation encoder: Git
/// kinds hash `<kind> <len>\0` first; native conflict bytes arrive already
/// framed and are hashed as they are.
fn start_stream_hasher(
    hash_kind: HashKind,
    kind: ObjectKind,
    decoded_len: u64,
) -> gix_hash::Hasher {
    let mut hasher = gix_hash::hasher(hash_kind.gix());
    if let Some(name) = kind.git_header_name() {
        hasher.update(format!("{name} {decoded_len}\0").as_bytes());
    }
    hasher
}

/// Streaming chunk length for a declared output: bounded above by
/// [`IO_CHUNK`], so every callback slice fits one buffer whatever the
/// object size. Mirrors the preparation decoder's chunk choice.
fn stream_chunk_len(decoded_len: u64) -> usize {
    usize::try_from(decoded_len)
        .unwrap_or(usize::MAX)
        .clamp(1, IO_CHUNK)
}

/// An incomplete result for a callback that stopped: the delivered prefix
/// with no verification claim.
fn stopped_meta(target: &StreamTarget, sink: &ChunkSink<'_>) -> StreamMeta {
    StreamMeta {
        oid: target.oid,
        kind: target.kind,
        decoded_len: target.decoded_len,
        depth: target.depth,
        streamed_bytes: sink.count,
        complete: false,
    }
}

/// Folds the sink state after a failed decoder write into the next step: a
/// stashed callback failure wins with its exact type, a callback stop ends
/// the stream cleanly, and only a decoder error of its own propagates.
/// Resolves a sink I/O failure for decoder pumps returning [`Pump`].
fn sink_pump(sink: &mut ChunkSink<'_>, err: StoreError) -> Result<Pump, StoreError> {
    if let Some(failure) = sink.failure.take() {
        return Err(failure);
    }
    if sink.stopped {
        return Ok(Pump::Stopped);
    }
    Err(err)
}

fn sink_step<'a>(
    sink: &mut ChunkSink<'_>,
    target: &StreamTarget,
    err: StoreError,
) -> Result<Step<'a>, StoreError> {
    if let Some(failure) = sink.failure.take() {
        return Err(failure);
    }
    if sink.stopped {
        return Ok(Step::Stopped);
    }
    Err(err)
}

/// Hashes accepted chunks, counts them, and forwards them to the callback.
/// A callback stop or failure is recorded on the sink so the decoder loop
/// can tell caller intent apart from stored-byte damage.
struct ChunkSink<'a> {
    hasher: gix_hash::Hasher,
    count: u64,
    on_chunk: &'a mut dyn FnMut(&[u8]) -> Result<ChunkDecision, StoreError>,
    failure: Option<StoreError>,
    stopped: bool,
}

impl<'a> ChunkSink<'a> {
    fn new(
        hasher: gix_hash::Hasher,
        on_chunk: &'a mut dyn FnMut(&[u8]) -> Result<ChunkDecision, StoreError>,
    ) -> Self {
        Self {
            hasher,
            count: 0,
            on_chunk,
            failure: None,
            stopped: false,
        }
    }
}

impl Write for ChunkSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match (self.on_chunk)(buf) {
            Ok(ChunkDecision::Continue) => {
                self.hasher.update(buf);
                self.count += to_u64(buf.len());
                Ok(buf.len())
            }
            Ok(ChunkDecision::Stop) => {
                // The stopping chunk reaches the caller and counts toward the
                // unverified prefix; it never enters the hash.
                self.stopped = true;
                self.count += to_u64(buf.len());
                Err(io::Error::other(EarlyStop))
            }
            Err(err) => {
                self.failure = Some(err);
                Err(io::Error::other(EarlyStop))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Marker: the chunk callback stopped the stream or failed. The real
/// failure, when there is one, waits stashed on the sink; this marker only
/// crosses the decoder's `Write` boundary.
#[derive(Debug, thiserror::Error)]
#[error("the chunk callback stopped the stream")]
struct EarlyStop;

/// Counts stored bytes pulled through it, so the stream proves the decoder
/// consumed exactly the declared payload. Sits directly above the record
/// reader, below the frame decoder's read-ahead buffer, exactly where the
/// preparation decoder's bounded source sits.
struct Counted<R: Read> {
    inner: R,
    consumed: u64,
}

impl<R: Read> Counted<R> {
    fn new(inner: R) -> Self {
        Self { inner, consumed: 0 }
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.consumed += to_u64(read);
        Ok(read)
    }
}

/// Keeps the original error of the stored-bytes reader so a decoder that
/// flattens it into its own error does not hide a segment diagnosis.
/// Mirrors the preparation decoder's source guard.
struct GuardedSource<R: Read> {
    inner: R,
    failure: Option<io::Error>,
}

impl<R: Read> Read for GuardedSource<R> {
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

/// One zstd frame, nothing else: the window stays capped at the level 3
/// maximum, decoding stops after the first frame, and [`Self::finish`]
/// proves no byte follows it. Mirrors the preparation decoder's frame
/// reader, over the counted stored bytes instead of its bounded source.
struct FrameReader<R: Read> {
    decoder: Decoder<'static, BufReader<GuardedSource<Counted<R>>>>,
}

impl<R: Read> FrameReader<R> {
    fn over(source: Counted<R>) -> Result<Self, StoreError> {
        let mut decoder = Decoder::new(GuardedSource {
            inner: source,
            failure: None,
        })?;
        decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
        Ok(Self {
            decoder: decoder.single_frame(),
        })
    }

    /// Proves no byte follows the frame, then returns the counted source
    /// for the consumed-length and checksum proofs.
    fn finish(self) -> Result<Counted<R>, StoreError> {
        let mut buffered = self.decoder.into_inner();
        match buffered.fill_buf().map(<[u8]>::is_empty) {
            Ok(true) => Ok(buffered.into_inner().inner),
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

/// Copies exactly `len` decoded bytes to the chunk sink and proves the
/// decoder ends there, so surplus output of a decompression bomb is refused
/// after one extra byte, and short output is corruption, never truncation.
/// Mirrors the preparation decoder's exact copy.
/// Pumps one raw record: the stored bytes are the decoded bytes, so the
/// lengths must agree before the first byte moves.
fn pump_raw<'p>(
    mut payload: StoredPayload<'p>,
    sink: &mut ChunkSink<'_>,
    chunk: &mut [u8],
    target: &StreamTarget,
    encoded_len: u64,
) -> Result<Step<'p>, StoreError> {
    if encoded_len != target.decoded_len {
        return Err(corrupt(format!(
            "raw payload of {encoded_len} bytes declares {} decoded bytes",
            target.decoded_len
        )));
    }
    match copy_to_chunks(&mut payload, sink, chunk, target, "raw payload")? {
        Pump::Complete => Ok(Step::Complete(payload, encoded_len)),
        Pump::Stopped => Ok(Step::Stopped),
    }
}

/// Pumps one zstd record through a single capped frame.
fn pump_zstd<'p>(
    payload: StoredPayload<'p>,
    sink: &mut ChunkSink<'_>,
    chunk: &mut [u8],
    target: &StreamTarget,
) -> Result<Step<'p>, StoreError> {
    let mut frame = FrameReader::over(Counted::new(payload))?;
    match copy_to_chunks(&mut frame, sink, chunk, target, "zstd payload")? {
        Pump::Complete => {
            let source = frame.finish()?;
            Ok(Step::Complete(source.inner, source.consumed))
        }
        Pump::Stopped => Ok(Step::Stopped),
    }
}

/// Pumps one delta record over its decoded base. The base is the only
/// object-sized allocation the stream holds; the target itself is never
/// stored.
fn pump_delta<'p>(
    payload: StoredPayload<'p>,
    sink: &mut ChunkSink<'_>,
    base: Option<&ReadObject>,
    target: &StreamTarget,
    hash_kind: HashKind,
    base_oid: Oid,
) -> Result<Step<'p>, StoreError> {
    let Some(base_object) = base else {
        return Err(corrupt("delta record without a decoded base"));
    };
    let mut base_view = base_object.bytes.view();
    let base_len = base_object.bytes.len();
    let mut source = Counted::new(payload);
    check_stream_prefix(&mut source, hash_kind, &base_oid)?;
    let mut frame = FrameReader::over(source)?;
    match apply_delta(
        &mut base_view,
        base_len,
        &mut frame,
        target.decoded_len,
        sink,
    ) {
        Ok(()) => {
            let source = frame.finish()?;
            Ok(Step::Complete(source.inner, source.consumed))
        }
        Err(err) => sink_step(sink, target, err),
    }
}

/// Copies exactly the declared decoded bytes to the chunk sink and proves
/// the decoder ends there, so surplus output of a decompression bomb is
/// refused after one extra byte, and short output is corruption, never
/// truncation. Mirrors the preparation decoder's exact copy.
fn copy_to_chunks(
    source: &mut impl Read,
    sink: &mut ChunkSink<'_>,
    chunk: &mut [u8],
    target: &StreamTarget,
    what: &str,
) -> Result<Pump, StoreError> {
    let len = target.decoded_len;
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
        if let Err(err) = sink.write_all(&chunk[..read]) {
            return sink_pump(sink, StoreError::Io(err));
        }
        remaining -= to_u64(read);
    }
    let mut probe = [0_u8; 1];
    loop {
        match source.read(&mut probe) {
            Ok(0) => return Ok(Pump::Complete),
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

/// Whether the exact copy reached the declared end or the callback stopped.
enum Pump {
    Complete,
    Stopped,
}

/// Checks the delta payload's embedded base digest against the recorded
/// base before any instruction decodes. Mirrors the preparation decoder's
/// prefix check.
fn check_stream_prefix(
    source: &mut impl Read,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::store::PreparationBudget;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// A unique temporary directory removed on drop. The directory exists
    /// from the start: it is the store root's parent, which creation
    /// requires the caller to provide.
    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-stream-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create the test parent directory");
            Self(dir)
        }

        fn store_dir(&self) -> std::path::PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn budget() -> Arc<PreparationBudget> {
        Arc::new(PreparationBudget::reference_defaults())
    }

    fn create(temp: &TempRoot, kind: HashKind) -> Store {
        Store::create(&temp.store_dir(), kind, budget()).expect("create store")
    }

    fn len_of(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("length fits u64")
    }

    fn publish_blob(store: &Store, bytes: &[u8]) -> Oid {
        let prepared = store
            .prepare(ObjectKind::Blob, len_of(bytes), bytes, None)
            .expect("prepare blob");
        let oid = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish blob");
        oid
    }

    fn read_all_bytes(store: &Store, oid: Oid) -> Vec<u8> {
        let mut object = store.read(oid).expect("read object");
        let mut bytes = Vec::new();
        object.bytes.read_to_end(&mut bytes).expect("read spool");
        bytes
    }

    fn collect_stream(store: &Store, oid: Oid) -> (StreamMeta, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut on_chunk = |chunk: &[u8]| -> Result<ChunkDecision, StoreError> {
            bytes.extend_from_slice(chunk);
            Ok(ChunkDecision::Continue)
        };
        let meta = store
            .read_chunks(oid, &mut on_chunk)
            .expect("stream object");
        (meta, bytes)
    }

    /// Deterministic pseudo-random bytes: the same LCG the store tests use,
    /// whose high byte compresses poorly enough to exercise real payloads.
    fn pseudo(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect()
    }

    fn assert_complete_meta(meta: &StreamMeta, oid: Oid, bytes: &[u8], depth: u8) {
        assert_eq!(meta.oid, oid, "stream reports the requested identity");
        assert_eq!(meta.kind, ObjectKind::Blob, "stream reports the blob kind");
        assert_eq!(meta.decoded_len, len_of(bytes), "stream reports the length");
        assert_eq!(meta.depth, depth, "stream reports the chain depth");
        assert_eq!(
            meta.streamed_bytes,
            len_of(bytes),
            "a complete stream delivers the full length"
        );
        assert!(meta.complete, "a full stream verifies");
    }

    #[test]
    fn streams_agree_with_buffered_reads_for_small_and_empty_blobs() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let temp = TempRoot::new("small");
            let store = create(&temp, kind);
            for (tag, bytes) in [("small", pseudo(5000, 1)), ("empty", Vec::new())] {
                let oid = publish_blob(&store, &bytes);
                let (meta, streamed) = collect_stream(&store, oid);
                assert_complete_meta(&meta, oid, &bytes, 0);
                assert_eq!(streamed, bytes, "{tag} streams byte-exact with {kind}");
                assert_eq!(
                    streamed,
                    read_all_bytes(&store, oid),
                    "{tag} matches the buffered read with {kind}"
                );
            }
        }
    }

    #[test]
    fn streams_agree_over_a_delta_chain_larger_than_one_chunk() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let temp = TempRoot::new("delta");
            let store = create(&temp, kind);
            let base_bytes = pseudo(200_000, 7);
            let base_oid = publish_blob(&store, &base_bytes);
            let mut target_bytes = base_bytes.clone();
            let patch = pseudo(1000, 8);
            target_bytes[100_000..101_000].copy_from_slice(&patch);
            let prepared = store
                .prepare(
                    ObjectKind::Blob,
                    len_of(&target_bytes),
                    &target_bytes[..],
                    Some(base_oid),
                )
                .expect("prepare delta");
            assert_eq!(
                prepared.encoding(),
                Encoding::Delta,
                "the similar target stores as a delta"
            );
            let target_oid = prepared.oid();
            store.publish(vec![prepared], &[]).expect("publish delta");
            let (base_meta, base_streamed) = collect_stream(&store, base_oid);
            assert_complete_meta(&base_meta, base_oid, &base_bytes, 0);
            assert_eq!(base_streamed, base_bytes, "the base streams byte-exact");
            let mut chunks = 0_usize;
            let mut target_streamed = Vec::new();
            let mut on_chunk = |chunk: &[u8]| -> Result<ChunkDecision, StoreError> {
                assert!(
                    chunk.len() <= IO_CHUNK,
                    "every streamed slice fits one chunk buffer"
                );
                chunks += 1;
                target_streamed.extend_from_slice(chunk);
                Ok(ChunkDecision::Continue)
            };
            let target_meta = store
                .read_chunks(target_oid, &mut on_chunk)
                .expect("stream delta");
            assert_complete_meta(&target_meta, target_oid, &target_bytes, 1);
            assert_eq!(
                target_streamed, target_bytes,
                "the delta streams byte-exact"
            );
            assert_eq!(
                target_streamed,
                read_all_bytes(&store, target_oid),
                "the delta matches the buffered read"
            );
            assert!(chunks > 1, "a 200 KiB object streams in several chunks");
        }
    }

    #[test]
    fn large_blob_streams_in_bounded_chunks_without_payload_buffers() {
        let temp = TempRoot::new("large");
        let shared = budget();
        let store = Store::create(&temp.store_dir(), HashKind::Sha1, Arc::clone(&shared))
            .expect("create store");
        let bytes = pseudo(8 << 20, 99);
        let oid = publish_blob(&store, &bytes);
        let (base_mem, base_scratch) = shared.in_use();
        let mut chunks = 0_usize;
        let mut total = 0_usize;
        let mut first = true;
        let mut on_chunk = |chunk: &[u8]| -> Result<ChunkDecision, StoreError> {
            assert!(
                chunk.len() <= IO_CHUNK,
                "every streamed slice fits one chunk buffer"
            );
            if first {
                first = false;
                let (mem, scratch) = shared.in_use();
                assert_eq!(
                    scratch, base_scratch,
                    "streaming holds no scratch spool for the target"
                );
                assert!(
                    mem <= base_mem + STREAM_WORKING_MEMORY + (1 << 20),
                    "streaming reserves only its fixed working set mid-stream"
                );
            }
            chunks += 1;
            total += chunk.len();
            Ok(ChunkDecision::Continue)
        };
        let meta = store
            .read_chunks(oid, &mut on_chunk)
            .expect("stream large blob");
        assert_complete_meta(&meta, oid, &bytes, 0);
        assert_eq!(total, bytes.len(), "the chunks cover the whole object");
        assert!(chunks > 1, "an 8 MiB object streams in many chunks");
        assert_eq!(
            read_all_bytes(&store, oid).len(),
            bytes.len(),
            "the buffered read agrees on the length"
        );
    }

    #[test]
    fn stopping_early_reports_an_unverified_prefix() {
        let temp = TempRoot::new("stop");
        let store = create(&temp, HashKind::Sha1);
        let bytes = pseudo(200_000, 11);
        let oid = publish_blob(&store, &bytes);
        let mut delivered = Vec::new();
        let mut calls = 0_u64;
        let mut on_chunk = |chunk: &[u8]| -> Result<ChunkDecision, StoreError> {
            calls += 1;
            delivered.extend_from_slice(chunk);
            if calls >= 2 {
                Ok(ChunkDecision::Stop)
            } else {
                Ok(ChunkDecision::Continue)
            }
        };
        let meta = store
            .read_chunks(oid, &mut on_chunk)
            .expect("early stop succeeds");
        assert!(!meta.complete, "a stopped stream claims no verification");
        assert_eq!(
            meta.streamed_bytes,
            len_of(&delivered),
            "the prefix length is reported"
        );
        assert!(delivered.len() < bytes.len(), "stopping skips the tail");
        assert_eq!(
            &delivered[..],
            &bytes[..delivered.len()],
            "the prefix is exact"
        );
        assert!(!store.quarantine(), "stopping early is not damage");
        let (_, full) = collect_stream(&store, oid);
        assert_eq!(full, bytes, "the store still streams fully afterwards");
    }

    #[test]
    fn damaged_stored_bytes_fail_the_stream_and_quarantine_the_store() {
        let temp = TempRoot::new("damage");
        let store = create(&temp, HashKind::Sha1);
        let oid = publish_blob(&store, &pseudo(5000, 13));
        let mut names: Vec<std::path::PathBuf> =
            std::fs::read_dir(temp.store_dir().join(SEGMENTS_DIR))
                .expect("segments dir")
                .map(|entry| entry.expect("segment entry").path())
                .collect();
        assert_eq!(names.len(), 1, "one object lands in one segment");
        let path = names.pop().expect("one segment file");
        let mut file_bytes = std::fs::read(&path).expect("read segment");
        file_bytes[10] ^= 0xFF;
        std::fs::write(&path, &file_bytes).expect("damage segment");
        let err = store
            .read_chunks(oid, &mut |_| Ok(ChunkDecision::Continue))
            .expect_err("damaged payload fails");
        assert!(
            matches!(err, StoreError::Corrupt(_)),
            "mid-stream damage is corruption, got {err:?}"
        );
        assert!(store.quarantine(), "committed damage latches quarantine");
        assert!(
            matches!(store.read(oid), Err(StoreError::Corrupt(_))),
            "the quarantined store refuses further reads"
        );
    }

    #[test]
    fn missing_and_wrong_width_ids_fail_before_any_io() {
        let temp = TempRoot::new("missing");
        let store = create(&temp, HashKind::Sha1);
        let unknown = HashKind::Sha1
            .hash_git_object("blob", b"never published")
            .expect("hash blob");
        assert!(
            matches!(
                store.read_chunks(unknown, &mut |_| Ok(ChunkDecision::Continue)),
                Err(StoreError::NotFound(_))
            ),
            "an unpublished id is not found"
        );
        let wide = HashKind::Sha256
            .hash_git_object("blob", b"wide")
            .expect("hash blob");
        assert!(
            matches!(
                store.read_chunks(wide, &mut |_| Ok(ChunkDecision::Continue)),
                Err(StoreError::ObjectFormat(_))
            ),
            "a digest of the wrong width is refused"
        );
        assert!(!store.quarantine(), "lookup failures are not damage");
    }
}
