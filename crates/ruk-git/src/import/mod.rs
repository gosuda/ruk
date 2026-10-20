//! Exact Git object import into the Ruk store.
//!
//! An explicit command points at a source Git directory (a bare repository
//! or a `.git` directory, read only and never adopted as an authority) and
//! this module stages every reachable object and ref into the store:
//!
//! 1. [`SourceObjects`](objects::SourceObjects) reads loose zlib objects,
//!    pack v2/v3 with idx v1/v2, and alternates, verifying every OID by
//!    re-hashing the exact header plus payload bytes.
//! 2. [`Walker`](walk::Walker) emits the closure depth-first in post order,
//!    so an object publishes only after everything it links to.
//! 3. Verified payloads become [`PreparedObject`]s (commits flow through
//!    the native records boundary, which preserves their bytes, mints no
//!    predecessor, and applies the divergence rules) and publish in bounded
//!    batches through the caller's [`PublishSink`].
//! 4. [`plan_refs`](refs::plan_refs) plans every source ref three-way
//!    against the stored ref and the last observation, and ref facts
//!    publish only in the final batch, after the closure is complete.
//!
//! Invariants: imported bytes and OIDs are preserved exactly; only
//! import-derived facts are written; a failure (corrupt, missing, cancel,
//! limit) publishes no ref fact; cancellation stops the import at the next
//! object or batch boundary.

pub mod commits;
pub mod notes;
pub mod objects;
pub mod progress;
pub mod refs;
pub mod walk;

#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;

use ruk_core::ByteString;
use ruk_core::change::OperationId;
use ruk_core::conflict::Signature;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::records::ImportBatch;
use ruk_core::refdata::RefTarget;
use ruk_core::store::{
    EventContext, EventSource, FactExpectation, FactMutation, FactTable, ObjectKind,
    PreparedObject, Publication, Store,
};

use crate::GitError;

pub use commits::CommitTally;
pub use progress::{ImportProgress, ProgressSnapshot};
pub use refs::{RefDecision, RefOutcome, SourceHead, SourceRef, SourceRefs};

/// Widening length conversion that cannot silently truncate.
pub(crate) fn u64_len(len: usize, what: &str) -> Result<u64, GitError> {
    u64::try_from(len).map_err(|_| GitError::Limit {
        detail: format!("{what} length {len} exceeds u64"),
    })
}

/// Batch admission of one import. Every batch holds at most
/// [`ImportLimits::batch_objects`] objects and [`ImportLimits::batch_bytes`]
/// decoded bytes; the walk never holds the whole repository in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportLimits {
    /// Objects per batch, at most 1000 (the contract's prefetch bound).
    pub batch_objects: usize,
    /// Decoded payload bytes per batch.
    pub batch_bytes: u64,
    /// Largest single object accepted.
    pub max_object_bytes: u64,
    /// Largest walk work stack (frontier entries).
    pub max_frontier: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            batch_objects: 1000,
            batch_bytes: 64 << 20,
            max_object_bytes: 2 << 30,
            max_frontier: 4_000_000,
        }
    }
}

impl ImportLimits {
    fn validate(&self) -> Result<(), GitError> {
        if self.batch_objects == 0 || self.batch_objects > 1000 {
            return Err(GitError::Invalid {
                detail: format!("batch_objects {} is outside 1..=1000", self.batch_objects),
            });
        }
        if self.batch_bytes == 0 || self.max_object_bytes == 0 || self.max_frontier == 0 {
            return Err(GitError::Invalid {
                detail: "import limits must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// What to import and where its observations live.
///
/// Preconditions: the caller holds sole lane ownership for the repository
/// (ref planning prepares a checked transaction); `operation` is fresh (no
/// reflog row uses it yet); `observation_source` is a non-empty,
/// NUL-free namespace such as the remote name; every published batch is
/// durable before the next is prepared (the sink is called synchronously).
#[derive(Clone, Debug)]
pub struct ImportRequest<'a> {
    /// A bare repository directory or a `.git` directory. Read only.
    pub git_dir: &'a std::path::Path,
    /// Namespace of the `remote_observations` rows for this source.
    pub observation_source: &'a [u8],
    /// Lane-allocated operation id; reflog keys use it.
    pub operation: OperationId,
    /// Reflog committer for changed refs.
    pub committer: Signature,
    /// Reflog message for changed refs.
    pub message: ByteString,
    /// Batch and size bounds.
    pub limits: ImportLimits,
}

/// Durable publication of one import batch. The standalone command and the
/// tests use [`DirectPublish`]; the coordinator lane supplies its own sink
/// that joins the batch with the lane transaction.
pub trait PublishSink {
    /// Publishes `objects` with `facts` atomically.
    ///
    /// # Errors
    /// Any store failure the sink cannot absorb.
    fn publish(
        &mut self,
        objects: Vec<PreparedObject>,
        facts: Vec<FactMutation>,
    ) -> Result<Publication, GitError>;
}

/// A [`PublishSink`] that publishes straight into `store`.
#[derive(Debug)]
pub struct DirectPublish<'a>(pub &'a Store);

impl PublishSink for DirectPublish<'_> {
    fn publish(
        &mut self,
        objects: Vec<PreparedObject>,
        facts: Vec<FactMutation>,
    ) -> Result<Publication, GitError> {
        self.0
            .publish(
                objects,
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .map_err(GitError::from)
    }
}

/// The durable result of one import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportReport {
    /// The object format both sides agreed on.
    pub object_format: HashKind,
    /// Source refs enumerated.
    pub refs_seen: u64,
    /// Objects verified and handed to the sink.
    pub objects: u64,
    /// Batches durably published (zero for an empty source).
    pub batches: u64,
    /// Per-ref outcome, in source name order.
    pub refs: Vec<RefOutcome>,
    /// The source HEAD, followed one symbolic level.
    pub head: Option<SourceHead>,
    /// Per-commit record outcomes.
    pub commits: CommitTally,
    /// Shallow boundary OIDs recorded.
    pub shallow: Vec<Oid>,
}

/// Imports one source repository into `store`.
///
/// Objects publish in closure-first batches; refs, ref conflicts,
/// observations, reflogs, and shallow rows publish only in the final batch
/// together with the remaining objects. An empty source publishes nothing.
///
/// This call performs blocking filesystem I/O with no async boundary; the
/// lane must run it under `spawn_blocking` rather than `await` it on the
/// executor.
///
/// # Errors
/// [`GitError::ObjectFormat`] for a cross-format source,
/// [`GitError::Corrupt`] for an undecodable object or a hash mismatch,
/// [`GitError::NotFound`] naming a missing object,
/// [`GitError::Cancelled`] on cooperative cancellation,
/// [`GitError::Limit`] for a bound the source exceeds, and store or model
/// failures as their own codes.
pub fn import_repository(
    store: &Store,
    request: &ImportRequest<'_>,
    progress: &ImportProgress,
    sink: &mut dyn PublishSink,
) -> Result<ImportReport, GitError> {
    request.limits.validate()?;
    if request.observation_source.is_empty() || request.observation_source.contains(&0x00) {
        return Err(GitError::Invalid {
            detail: "observation_source must be non-empty and NUL-free".to_owned(),
        });
    }
    if progress.is_cancelled() {
        return Err(GitError::Cancelled {
            detail: "import cancelled".to_owned(),
        });
    }

    let source = objects::SourceObjects::open(
        request.git_dir,
        store.hash_kind(),
        request.limits.max_object_bytes,
    )?;
    let (source_refs, head) = refs::read_source_refs(request.git_dir, store.hash_kind())?;
    progress.refs_seen(u64_len(source_refs.refs.len(), "source refs")?);
    let shallow = walk::ShallowSet::read_shallow_file(request.git_dir, store.hash_kind())?;

    let mut walker = walk::Walker::new(&source, request.limits.max_frontier);
    walker.seed(
        source_refs
            .refs
            .iter()
            .filter_map(|candidate| match &candidate.target {
                RefTarget::Direct(oid) => Some((*oid, None, None)),
                RefTarget::Symbolic(_) => None,
            }),
    )?;
    if let Some(SourceHead::Detached(oid)) = &head {
        walker.seed(core::iter::once((*oid, None, None)))?;
    }

    let mut batcher = Batcher::new(store, request.limits, progress);
    let mut tally = CommitTally::empty();
    let mut peeled: HashMap<Oid, Oid> = HashMap::new();

    // Ordered prepare waves: the walk still discovers objects serially
    // (closure order is inherently sequential), but the CPU-heavy staging
    // of each drained chunk — hashing and zstd compression in
    // `Store::prepare` plus tag parsing — runs across `import_threads`
    // workers. Results rejoin strictly in walk order below, so batch
    // boundaries, tally order, peel mapping, progress counts, and the
    // first-error position are identical to the serial import. Publication
    // keeps today's single-batch transaction shape; every prepared object
    // is content-addressed with no predecessor, hence never a delta, so
    // `check_delta_base` is vacuous here regardless of order.
    let width = walk::import_threads();
    let profile = std::env::var_os("RUK_PROFILE").is_some_and(|value| value == "1");
    let import_start = profile.then(std::time::Instant::now);
    let (mut walk_ms, mut prepare_ms, mut rejoin_ms) = (0.0_f64, 0.0_f64, 0.0_f64);
    let mut waves = 0_u64;
    loop {
        let mut chunk = Vec::new();
        let walk_start = profile.then(std::time::Instant::now);
        while chunk.len() < PREPARE_CHUNK {
            match walker.next(&source, progress)? {
                Some(emit) => chunk.push(emit),
                None => break,
            }
        }
        if let Some(start) = walk_start {
            walk_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
        if chunk.is_empty() {
            break;
        }
        waves += 1;
        let prepare_start = profile.then(std::time::Instant::now);
        let staged = prepare_chunk(store, progress, &chunk, width)?;
        if let Some(start) = prepare_start {
            prepare_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
        let rejoin_start = profile.then(std::time::Instant::now);
        for (emit, staged) in chunk.into_iter().zip(staged) {
            match staged? {
                Staged::Ready(ready) => {
                    batcher.accept_ready(&source, sink, &mut peeled, ready)?;
                }
                Staged::Serial => batcher.accept(&source, sink, &mut tally, &mut peeled, emit)?,
            }
        }
        if let Some(start) = rejoin_start {
            rejoin_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
    }

    let plan_start = profile.then(std::time::Instant::now);
    let plan = refs::plan_refs(store, request, &source_refs, &peeled)?;
    let plan_refs_ms = plan_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);

    let mut shallow_seen = Vec::new();
    let mut shallow_facts = Vec::new();
    for oid in shallow.oids() {
        if source.locate(oid)?.is_none() {
            return Err(GitError::NotFound {
                detail: format!("shallow boundary {oid} is missing from the source"),
            });
        }
        shallow_seen.push(oid);
        let key = refs::shallow_key(oid);
        if store
            .fact(FactTable::Shallow, &key)
            .map_err(GitError::from)?
            .is_none()
        {
            shallow_facts.push(FactMutation {
                table: FactTable::Shallow,
                key,
                expected: FactExpectation::Absent,
                value: Some(Vec::new()),
            });
        }
    }

    let mut facts = plan.facts;
    facts.extend(shallow_facts);
    let finish_start = profile.then(std::time::Instant::now);
    let (objects, batches) = batcher.finish(sink, facts)?;
    if let Some(start) = import_start {
        eprintln!(
            "[ruk-profile] import waves={waves} walk={walk_ms:.1}ms prepare={prepare_ms:.1}ms rejoin={rejoin_ms:.1}ms plan_refs={plan_refs_ms:.1}ms finish={:.1}ms total={:.1}ms width={width}",
            finish_start
                .map(|start| start.elapsed().as_secs_f64() * 1000.0)
                .unwrap_or(0.0),
            start.elapsed().as_secs_f64() * 1000.0,
        );
    }

    Ok(ImportReport {
        object_format: store.hash_kind(),
        refs_seen: u64_len(source_refs.refs.len(), "source refs")?,
        objects,
        batches,
        refs: plan.outcomes,
        head,
        commits: tally,
        shallow: shallow_seen,
    })
}

/// Emissions drained per prepare wave. One scoped wave of at most sixteen
/// workers stages a chunk while the serial walk refills the next, so the
/// wave count stays near `objects / PREPARE_CHUNK` instead of scaling with
/// the object count. Bounded: a chunk holds at most this many payloads
/// plus their staged objects, on the order of today's batch buffer.
const PREPARE_CHUNK: usize = 256;

/// One drained emission after the thread-safe part of its staging: either
/// a prepared object ready to push in walk order, or the original emission
/// for the serial path. Commits stay serial — observing them mutates the
/// records overlay in order — and large blobs stay serial, streaming from
/// the source inside the batcher as today.
// 264 bytes per item worst case, times a 256-item chunk: boxed indirection
// would only trade one transient allocation per emission for nothing.
#[expect(clippy::large_enum_variant)]
enum Staged {
    Ready(ReadyObject),
    Serial,
}

/// One wave-prepared object rejoining the serial batcher in walk order.
/// Carries its OID, its staged store object, its decoded size, and the
/// tag target the wave parsed, if any.
struct ReadyObject {
    oid: Oid,
    prepared: PreparedObject,
    size: u64,
    tag: Option<Oid>,
}

/// Stages a drained chunk's thread-safe work: non-commit hashing,
/// compression, and tag parsing. Pure per emission except for the shared
/// preparation budget (mutex-guarded) and uniquely named scratch spools,
/// so workers share only `store` and `progress`. Commits and streams defer
/// to the serial path. The returned vector aligns 1:1 with `chunk`; the
/// first error in walk order wins when the caller applies it with `?` in
/// sequence. The scoped wave joins before returning: no task outlives the
/// call that owns it, and a cancelled wave stops at the next chunk — the
/// serial walk and batcher keep polling per object and per batch.
fn prepare_chunk(
    store: &Store,
    progress: &ImportProgress,
    chunk: &[walk::Emit],
    width: usize,
) -> Result<Vec<Result<Staged, GitError>>, GitError> {
    fn stage_one(
        store: &Store,
        progress: &ImportProgress,
        emit: &walk::Emit,
    ) -> Result<Staged, GitError> {
        if progress.is_cancelled() {
            return Err(GitError::Cancelled {
                detail: "import cancelled".to_owned(),
            });
        }
        let walk::Emit::Memory { oid, object } = emit else {
            return Ok(Staged::Serial);
        };
        if object.kind == ObjectKind::Commit {
            return Ok(Staged::Serial);
        }
        let size = u64_len(object.payload.len(), "object payload")?;
        let tag = if object.kind == ObjectKind::Tag {
            refs::tag_target(object, store.hash_kind())?
        } else {
            None
        };
        let prepared = store
            .prepare(object.kind, size, &object.payload[..], None)
            .map_err(GitError::from)?;
        if prepared.oid() != *oid {
            return Err(GitError::Corrupt {
                detail: format!("object {oid} hashes to {}", prepared.oid()),
            });
        }
        Ok(Staged::Ready(ReadyObject {
            oid: *oid,
            prepared,
            size,
            tag,
        }))
    }

    if width <= 1 {
        return Ok(chunk
            .iter()
            .map(|emit| stage_one(store, progress, emit))
            .collect());
    }
    let piece = chunk.len().div_ceil(width);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for part in chunk.chunks(piece) {
            handles.push(scope.spawn(move || {
                part.iter()
                    .map(|emit| stage_one(store, progress, emit))
                    .collect::<Vec<_>>()
            }));
        }
        let mut staged = Vec::with_capacity(chunk.len());
        for handle in handles {
            match handle.join() {
                Ok(part) => staged.extend(part),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        Ok(staged)
    })
}

/// One in-flight batch: prepared non-commit objects plus the records
/// boundary's staged commit objects and mutations. `finish` publishes the
/// remainder with the final facts; intermediate `flush` calls publish
/// objects with only their record facts, never ref facts.
struct Batcher<'a, 'p> {
    store: &'a Store,
    limits: ImportLimits,
    progress: &'p ImportProgress,
    objects: Vec<PreparedObject>,
    bytes: u64,
    records: ImportBatch<'a>,
    published_objects: u64,
    batches: u64,
}

impl<'a, 'p> Batcher<'a, 'p> {
    fn new(store: &'a Store, limits: ImportLimits, progress: &'p ImportProgress) -> Self {
        Self {
            store,
            limits,
            progress,
            objects: Vec::new(),
            bytes: 0,
            records: ImportBatch::new(store),
            published_objects: 0,
            batches: 0,
        }
    }

    fn accept(
        &mut self,
        source: &objects::SourceObjects,
        sink: &mut dyn PublishSink,
        tally: &mut CommitTally,
        peeled: &mut HashMap<Oid, Oid>,
        emit: walk::Emit,
    ) -> Result<(), GitError> {
        match emit {
            walk::Emit::Stream { oid, .. } => {
                let location = source.locate(oid)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("object {oid} vanished from the source"),
                })?;
                let body = source.read(oid, location)?;
                let objects::Body::Stream(stream) = body else {
                    return Err(GitError::Corrupt {
                        detail: format!("object {oid} changed kind mid-import"),
                    });
                };
                let size = stream.size();
                let prepared = stream.stage(self.store, oid)?;
                self.push(prepared, size)?;
            }
            walk::Emit::Memory { oid, object, .. } => {
                let size = u64_len(object.payload.len(), "object payload")?;
                if object.kind == ObjectKind::Commit {
                    commits::observe_commit(&mut self.records, oid, object.payload, tally)?;
                    self.bytes += size;
                } else {
                    if object.kind == ObjectKind::Tag
                        && let Some(target) = refs::tag_target(&object, source.hash_kind())?
                    {
                        peeled.insert(oid, peel_final(source, target)?);
                    }
                    let prepared = self
                        .store
                        .prepare(object.kind, size, &object.payload[..], None)
                        .map_err(GitError::from)?;
                    if prepared.oid() != oid {
                        return Err(GitError::Corrupt {
                            detail: format!("object {oid} hashes to {}", prepared.oid()),
                        });
                    }
                    self.push(prepared, size)?;
                }
            }
        }
        self.maybe_flush(sink)?;
        Ok(())
    }

    /// Pushes one wave-prepared object in walk order: records a tag peel
    /// when the wave parsed one, then stages exactly as the serial path
    /// would have after preparing the same bytes.
    fn accept_ready(
        &mut self,
        source: &objects::SourceObjects,
        sink: &mut dyn PublishSink,
        peeled: &mut HashMap<Oid, Oid>,
        ready: ReadyObject,
    ) -> Result<(), GitError> {
        if let Some(target) = ready.tag {
            peeled.insert(ready.oid, peel_final(source, target)?);
        }
        self.push(ready.prepared, ready.size)?;
        self.maybe_flush(sink)?;
        Ok(())
    }

    /// Publishes the in-flight batch once it reaches either admission bound.
    fn maybe_flush(&mut self, sink: &mut dyn PublishSink) -> Result<(), GitError> {
        if self.objects.len() >= self.limits.batch_objects || self.bytes >= self.limits.batch_bytes
        {
            self.flush(sink, Vec::new())?;
        }
        Ok(())
    }

    fn push(&mut self, prepared: PreparedObject, size: u64) -> Result<(), GitError> {
        if self.progress.is_cancelled() {
            return Err(GitError::Cancelled {
                detail: "import cancelled".to_owned(),
            });
        }
        self.bytes += size;
        self.objects.push(prepared);
        Ok(())
    }

    /// Publishes everything staged with `extra` facts. Empty batches
    /// publish nothing and advance no generation.
    fn flush(
        &mut self,
        sink: &mut dyn PublishSink,
        extra: Vec<FactMutation>,
    ) -> Result<(), GitError> {
        if self.progress.is_cancelled() {
            return Err(GitError::Cancelled {
                detail: "import cancelled".to_owned(),
            });
        }
        let pending = core::mem::take(&mut self.objects);
        self.bytes = 0;
        let staged = core::mem::replace(&mut self.records, ImportBatch::new(self.store));
        let (mut staged_objects, mut staged_facts) = staged.into_parts().map_err(GitError::from)?;
        if pending.is_empty()
            && staged_objects.is_empty()
            && staged_facts.is_empty()
            && extra.is_empty()
        {
            return Ok(());
        }
        let count = u64_len(pending.len() + staged_objects.len(), "batch objects")?;
        let mut objects = pending;
        objects.append(&mut staged_objects);
        staged_facts.extend(extra);
        sink.publish(objects, staged_facts)?;
        self.published_objects += count;
        self.batches += 1;
        self.progress.batch_published(count);
        Ok(())
    }

    /// Publishes the remainder with the final facts.
    fn finish(
        mut self,
        sink: &mut dyn PublishSink,
        facts: Vec<FactMutation>,
    ) -> Result<(u64, u64), GitError> {
        self.flush(sink, facts)?;
        Ok((self.published_objects, self.batches))
    }
}

impl fmt::Debug for Batcher<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batcher")
            .field("limits", &self.limits)
            .field("objects", &self.objects.len())
            .field("bytes", &self.bytes)
            .field("published_objects", &self.published_objects)
            .field("batches", &self.batches)
            .finish_non_exhaustive()
    }
}

/// Follows a tag chain from its first hop to the final target.
fn peel_final(source: &objects::SourceObjects, target: Oid) -> Result<Oid, GitError> {
    let mut current = target;
    loop {
        let object = source.read_in_memory(current)?;
        let Some(next) = refs::tag_target(&object, source.hash_kind())? else {
            return Ok(current);
        };
        current = next;
    }
}
