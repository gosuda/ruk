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
pub mod objects;
pub mod progress;
pub mod refs;
pub mod walk;

#[cfg(test)]
mod fixtures;
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
    FactExpectation, FactMutation, FactTable, ObjectKind, PreparedObject, Publication, Store,
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
        self.0.publish(objects, &facts).map_err(GitError::from)
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

    while let Some(emit) = walker.next(&source, progress)? {
        batcher.accept(&source, sink, &mut tally, &mut peeled, emit)?;
    }

    let plan = refs::plan_refs(store, request, &source_refs, &peeled)?;

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
    let (objects, batches) = batcher.finish(sink, facts)?;

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
