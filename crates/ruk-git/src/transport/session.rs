//! Transport sessions: the seam and the local native transport.
//!
//! [`Transport`] is the trait a later HTTPS adapter implements: open a
//! duplex stream to one service. SSH and git-daemon transports already live
//! in [`super::net`], whose streams feed the owned wire clients directly.
//! [`Remote`] stays local-only on purpose: [`Remote::parse`] accepts bare
//! paths and `file://` URLs and refuses network schemes with
//! [`GitError::Unsupported`], pointing at [`super::net::parse_endpoint`].
//!
//! A local native repository avoids the wire round-trip where it can:
//! [`local_fetch`] stages the negotiated closure straight into the
//! destination through [`super::pack::stage_local_objects`], while
//! [`local_push`] builds real pack bytes from the source store and ingests
//! them into the destination through [`ingest_pack`]; both then publish
//! objects and ref deltas atomically. No
//! shell, no subprocess, no raw segment bytes. Reading a local Git-format
//! source and writing a local Git-format destination belong to the
//! import/export slices; [`open_local_store`] says so explicitly instead
//! of misreading those directories.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{
    RefChange, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate,
};
use ruk_core::refs::{StoreRefs, page_refs, prepare_checked_transaction};
use ruk_core::store::types::{ObjectKind, Publication};
use ruk_core::store::{PreparationBudget, Store};

use super::fetch::observation_mutations;
use super::fetch::{Filter, promisor_facts, shallow_facts};
use super::pack::{
    IngestLimits, Links, PackEntry, StagedPack, ingest_pack, object_links, pack_threads, write_pack,
};
use super::push::{
    PushPlanRecord, PushUpdate, PushWireRequest, RefOutcome, RefResult, push_closure,
};
use super::{Interrupt, read_object};
use crate::GitError;

/// A Git service on the far end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// `git-upload-pack`: the server sends objects.
    UploadPack,
    /// `git-receive-pack`: the server accepts objects.
    ReceivePack,
    /// `git-upload-archive`: the server streams a tar archive.
    UploadArchive,
}

impl Service {
    /// The service name on the wire.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
            Self::UploadArchive => "git-upload-archive",
        }
    }
}

/// A duplex byte stream. Blanket-implemented so adapters name one trait.
pub trait Duplex: Read + Write {}

impl<T: Read + Write + ?Sized> Duplex for T {}

/// The trait later network adapters implement: open one duplex stream to
/// one service, negotiating `preferred` first.
pub trait Transport {
    /// The opened stream.
    type Conn: Duplex;
    /// Opens the stream.
    ///
    /// # Errors
    /// [`GitError::Offline`] when the network is absent, [`GitError::Io`]
    /// when the peer cannot be reached.
    fn connect(
        &mut self,
        service: Service,
        preferred: super::refadv::ProtocolVersion,
    ) -> Result<Self::Conn, GitError>;
}

/// Where to fetch from or push to: a local path only. Network schemes are
/// refused, naming the network endpoint parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remote {
    /// The local repository path.
    pub path: PathBuf,
}

impl Remote {
    /// Parses `spec`: a `file://` URL, a bare path, or an explicit refusal
    /// for network schemes.
    ///
    /// # Errors
    /// [`GitError::Unsupported`] for `ssh://`, `https?://`, `git://` and
    /// other schemes; [`GitError::Invalid`] for an empty path.
    pub fn parse(spec: &str) -> Result<Self, GitError> {
        if spec.is_empty() {
            return Err(GitError::Invalid {
                detail: "empty remote".to_owned(),
            });
        }
        if let Some(rest) = spec.strip_prefix("file://") {
            if rest.is_empty() {
                return Err(GitError::Invalid {
                    detail: "empty file:// remote".to_owned(),
                });
            }
            return Ok(Self {
                path: PathBuf::from(rest),
            });
        }
        if let Some(scheme_end) = spec.find("://") {
            let scheme = &spec[..scheme_end];
            return Err(GitError::Unsupported {
                command: format!("{scheme} transports (network adapters are a later slice)"),
            });
        }
        Ok(Self {
            path: PathBuf::from(spec),
        })
    }
}

/// A preparation budget for stores opened by transport tests and tools.
#[must_use]
pub fn default_budget() -> Arc<PreparationBudget> {
    Arc::new(PreparationBudget::reference_defaults())
}

/// Opens the native store at `path`: either `path` itself or
/// `path/.ruk/store`. A Git-format directory is refused naming the
/// import/export slice; anything else propagates the open failure.
///
/// # Errors
/// [`GitError::Unsupported`] for Git-format endpoints, [`GitError::NotFound`]
/// for a missing path, and store failures otherwise.
pub fn open_local_store(path: &Path) -> Result<Store, GitError> {
    for candidate in [path.join(".ruk").join("store"), path.to_path_buf()] {
        if candidate.is_dir() && looks_like_native(&candidate) {
            return Ok(Store::open(&candidate, default_budget())?);
        }
    }
    if !path.exists() {
        return Err(GitError::NotFound {
            detail: format!("local remote {} does not exist", path.display()),
        });
    }
    if looks_like_git_format(path) {
        return Err(GitError::Unsupported {
            command: format!(
                "local Git-format endpoint {} (the import/export slice owns Git-format readers and writers)",
                path.display()
            ),
        });
    }
    Err(GitError::Invalid {
        detail: format!(
            "{} is neither a Ruk store nor a Git repository",
            path.display()
        ),
    })
}

fn looks_like_native(dir: &Path) -> bool {
    dir.join("format").is_file() && dir.join("meta.redb").is_file()
}

fn looks_like_git_format(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && (dir.join("objects").is_dir() || dir.join("refs").is_dir())
}

/// One advertised local ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedLocalRef {
    /// Full ref name bytes.
    pub name: Vec<u8>,
    /// Its target.
    pub target: RefTarget,
}

/// Lists every ref of `store` in name order for local advertisement.
///
/// # Errors
/// Store failures.
pub fn advertise(store: &Store) -> Result<Vec<AdvertisedLocalRef>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = page_refs(store, after.as_deref(), 1000)?;
        for entry in &page.entries {
            out.push(AdvertisedLocalRef {
                name: entry.name.as_bytes().to_vec(),
                target: entry.target.clone(),
            });
        }
        if !page.more {
            return Ok(out);
        }
        after = out.last().map(|e| e.name.clone());
    }
}

/// What to fetch from a local store.
#[derive(Clone, Debug)]
pub struct LocalFetchRequest {
    /// Tips to download.
    pub wants: Vec<Oid>,
    /// Authorized local tips excluded from the pack.
    pub haves: Vec<Oid>,
    /// Partial-clone filter, native default `blob:none`.
    pub filter: Option<Filter>,
    /// Shallow depth; `None` is a complete fetch.
    pub depth: Option<u32>,
}

/// What a local fetch published.
#[derive(Clone, Debug)]
pub struct FetchReport {
    /// The atomic publication of objects and facts.
    pub publication: Publication,
    /// Every wanted tip now available.
    pub delivered: Vec<Oid>,
    /// New shallow boundaries recorded.
    pub shallow: Vec<Oid>,
    /// Non-fatal downgrades (filter/depth refused are impossible locally;
    /// kept for wire symmetry).
    pub warnings: Vec<String>,
}

/// Fetches from one native store into another without a pack round-trip:
/// the closure is staged from `src` straight into `dest` staging,
/// verified, and published with promisor/shallow/observation facts and the
/// caller's ref mutations in one transaction.
///
/// `tracking` maps remote ref names to their new targets for observation
/// rows; `ref_mutations` are lane-prepared ref CAS mutations (the lane owns
/// ref serialization through `refs::prepare_checked_transaction`).
///
/// # Errors
/// Closure, ingest, verification and store failures; nothing is published
/// on failure.
pub fn local_fetch(
    dest: &Store,
    src: &Store,
    remote: &[u8],
    req: &LocalFetchRequest,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[ruk_core::store::types::FactMutation],
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<FetchReport, GitError> {
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let kind = dest.hash_kind();
    if src.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "local source uses another object format".to_owned(),
        });
    }
    let profile = std::env::var_os("RUK_PROFILE").is_some_and(|value| value == "1");
    let fetch_start = profile.then(std::time::Instant::now);
    let closure_start = profile.then(std::time::Instant::now);
    let LocalClosure { objects, shallow } = local_closure(src, kind, req, interrupt)?;
    let closure_ms = closure_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let object_count = objects.len();
    let mut raw_bytes = 0u64;
    for (_, _, bytes) in &objects {
        let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
            detail: "object length does not fit in 64 bits".to_owned(),
        })?;
        raw_bytes = raw_bytes.saturating_add(len);
    }
    let stage_start = profile.then(std::time::Instant::now);
    let staged = super::pack::stage_local_objects(objects, dest, limits, interrupt)?;
    let stage_ms = stage_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let verify_start = profile.then(std::time::Instant::now);
    let report =
        super::fetch::verify_closure(dest, &staged, &req.wants, req.filter, &shallow, interrupt)?;
    let verify_ms = verify_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let mut facts: Vec<ruk_core::store::types::FactMutation> = Vec::new();
    if let Some(filter) = req.filter {
        facts.extend(promisor_facts(remote, filter, &report.missing_promisor)?);
    }
    facts.extend(shallow_facts(&shallow, &[]));
    facts.extend(observation_mutations(remote, tracking));
    facts.extend(ref_mutations.iter().cloned());
    let records_start = profile.then(std::time::Instant::now);
    facts.extend(super::fetch::commit_record_facts(dest, &staged)?);
    let records_ms = records_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let publication = dest.publish(staged.into_objects(), &facts)?;
    if let Some(start) = fetch_start {
        eprintln!(
            "[ruk-profile] local_fetch objects={object_count} raw_bytes={raw_bytes} closure={closure_ms:.1}ms stage={stage_ms:.1}ms verify={verify_ms:.1}ms records={records_ms:.1}ms local_fast=1 total={:.1}ms",
            start.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(FetchReport {
        publication,
        delivered: report.wanted,
        shallow,
        warnings: Vec::new(),
    })
}

/// The packed closure of a local fetch with its shallow cutoffs.
///
/// Shared with the `upload-pack` serve half, which negotiates the same
/// wants-minus-haves walk over the wire.
pub(crate) struct LocalClosure {
    pub(crate) objects: Vec<(Oid, ObjectKind, Vec<u8>)>,
    pub(crate) shallow: Vec<Oid>,
}

/// Point reads per closure batch: small frontiers stay serial, larger ones
/// fan out (order-preserving, errors positional for in-order surfacing).
const READ_BATCH: usize = 256;

/// Batches below this stay serial: a channel round-trip for a handful of
/// reads costs more than it saves.
const READ_SERIAL_BELOW: usize = 8;

/// Refuses bodies larger than this before buffering them, matching the
/// transport's per-object read bound.
const CLOSURE_READ_MAX: u64 = 512 << 20;

/// One closure point read plus its link parse: interruptible, pure against
/// `src` (parsing is a pure function of the bytes, so it parallelizes
/// while queue extension stays serial in batch order). A read failure and
/// a corrupt payload both surface as the item error, in the same order the
/// serial walk produced them: the caller maps `NotFound` and lets any
/// other error (read or parse) through untouched.
type ClosureRead = (ObjectKind, Vec<u8>, Links);

fn read_one(
    src: &Store,
    oid: Oid,
    hash: HashKind,
    interrupt: &Interrupt,
) -> Result<ClosureRead, GitError> {
    interrupt.check("computing the local fetch closure")?;
    let (kind, bytes) = read_object(src, oid, CLOSURE_READ_MAX)?;
    let links = object_links(kind, &bytes, hash)?;
    Ok((kind, bytes, links))
}

/// Long-lived closure readers inside one thread scope.
///
/// Spawning an OS thread per batch (a scope per batch) measured ~2ms of
/// spawn overhead per 64-object batch, dwarfing the reads; these workers
/// spawn once per closure and serve every batch over dedicated channels.
/// Each worker owns its lane: the main thread splits a batch across lanes
/// and rejoins lane by lane, so results align 1:1 with the batch with no
/// shared mutable state. Stop-and-wait keeps at most one chunk per lane in
/// flight, and each lane is a rendezvous (`sync_channel(1)`): a slow lane
/// backpressures the main thread instead of buffering, so lane queues hold
/// at most one chunk (bounded by `READ_BATCH` across lanes) with no shed
/// policy needed. Dropping the pool disconnects the lanes and the scope
/// rejoins them.
struct ClosureReadPool {
    jobs: Vec<SyncSender<Vec<Oid>>>,
    results: Vec<Receiver<Vec<Result<ClosureRead, GitError>>>>,
    hash: HashKind,
}

impl ClosureReadPool {
    fn spawn<'scope, 'env>(
        scope: &'scope std::thread::Scope<'scope, 'env>,
        src: &'env Store,
        hash: HashKind,
        interrupt: &'env Interrupt,
    ) -> Self {
        let mut jobs = Vec::new();
        let mut results = Vec::new();
        for _ in 0..pack_threads() {
            let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<Vec<Oid>>(1);
            let (res_tx, res_rx) =
                std::sync::mpsc::sync_channel::<Vec<Result<ClosureRead, GitError>>>(1);
            scope.spawn(move || {
                while let Ok(oids) = job_rx.recv() {
                    let out = oids
                        .iter()
                        .map(|oid| read_one(src, *oid, hash, interrupt))
                        .collect::<Vec<_>>();
                    if res_tx.send(out).is_err() {
                        break;
                    }
                }
            });
            jobs.push(job_tx);
            results.push(res_rx);
        }
        Self {
            jobs,
            results,
            hash,
        }
    }

    /// Reads `oids` in batch order. Small batches (and single-lane pools)
    /// go serial; larger ones split across lanes and rejoin in order.
    /// A dead lane is a hard [`GitError::Io`], never a panic: the caller
    /// fails the fetch instead of crashing it.
    fn read(
        &self,
        src: &Store,
        oids: &[Oid],
        interrupt: &Interrupt,
    ) -> Result<Vec<Result<ClosureRead, GitError>>, GitError> {
        if oids.len() < READ_SERIAL_BELOW || self.jobs.len() <= 1 {
            return Ok(oids
                .iter()
                .map(|oid| read_one(src, *oid, self.hash, interrupt))
                .collect());
        }
        let lanes = self.jobs.len().min(oids.len());
        let piece = oids.len().div_ceil(lanes);
        for (lane, part) in oids.chunks(piece).enumerate() {
            if self.jobs[lane].send(part.to_vec()).is_err() {
                return Err(GitError::Io {
                    detail: "closure read lane died mid-batch".to_owned(),
                });
            }
        }
        let mut out = Vec::with_capacity(oids.len());
        for (lane, part) in oids.chunks(piece).enumerate() {
            match self.results[lane].recv() {
                Ok(reads) => {
                    debug_assert_eq!(reads.len(), part.len());
                    out.extend(reads);
                }
                Err(_) => {
                    // A lane died mid-batch: surface one error per unread
                    // object so the caller still fails in batch order.
                    out.extend(part.iter().map(|oid| {
                        Err(GitError::Io {
                            detail: format!("closure read lane died while reading object {oid}"),
                        })
                    }));
                }
            }
        }
        Ok(out)
    }
}

/// Computes wants-minus-haves in `src`, depth-bounded when asked.
///
/// Both walks batch their point reads through one [`ClosureReadPool`]:
/// reads fan out over long-lived lanes, discovery stays serial in batch
/// order, so observable behavior (visited order, first error in BFS order,
/// cutoff set) matches the old serial walk. The 2026-10-18 convoy note
/// that used to live here described a walk sharing discovery state across
/// threads; batching keeps no shared mutable state on the hot path, and
/// the lanes are scoped to this call (one spawn per closure, not per
/// batch).
pub(crate) fn local_closure(
    src: &Store,
    kind: HashKind,
    req: &LocalFetchRequest,
    interrupt: &Interrupt,
) -> Result<LocalClosure, GitError> {
    std::thread::scope(|scope| {
        // Parse with the caller's `kind`, exactly as the serial walk did:
        // on a kind mismatch the same objects fail the same way.
        let pool = ClosureReadPool::spawn(scope, src, kind, interrupt);
        local_closure_scoped(src, req, interrupt, &pool)
    })
}

/// The two wants-minus-haves walks, reading through `pool`.
fn local_closure_scoped(
    src: &Store,
    req: &LocalFetchRequest,
    interrupt: &Interrupt,
    pool: &ClosureReadPool,
) -> Result<LocalClosure, GitError> {
    let haves: HashSet<Oid> = req.haves.iter().copied().collect();
    let mut uninteresting = HashSet::new();
    let mut frontier: VecDeque<Oid> = haves.iter().copied().collect();
    while !frontier.is_empty() {
        interrupt.check("computing the local fetch closure")?;
        let mut batch = Vec::new();
        while let Some(oid) = frontier.pop_front() {
            if !uninteresting.insert(oid) {
                continue;
            }
            batch.push(oid);
            if batch.len() >= READ_BATCH {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }
        let reads = pool.read(src, &batch, interrupt)?;
        for (_, read) in batch.into_iter().zip(reads) {
            let links = match read {
                Ok((ObjectKind::Commit, _, links)) => links,
                Ok(_) => continue,
                Err(err) if matches!(err, GitError::NotFound { .. }) => continue,
                Err(err) => return Err(err),
            };
            frontier.extend(links.parents.iter().copied());
        }
    }
    let mut objects = Vec::new();
    let mut shallow = Vec::new();
    let mut visited = HashSet::new();
    let profile = std::env::var_os("RUK_PROFILE").is_some_and(|value| value == "1");
    let mut read_ms = 0.0f64;
    let mut link_ms = 0.0f64;
    let mut collect_ms = 0.0f64;
    let mut serial_items = 0u64;
    let mut parallel_items = 0u64;
    // (oid, commit depth from the wants; non-commits ride along).
    let mut queue: VecDeque<(Oid, u32)> = req.wants.iter().map(|oid| (*oid, 0)).collect();
    while !queue.is_empty() {
        interrupt.check("computing the local fetch closure")?;
        let collect_start = profile.then(std::time::Instant::now);
        let mut batch = Vec::new();
        while let Some((oid, depth)) = queue.pop_front() {
            if !visited.insert(oid) || uninteresting.contains(&oid) {
                continue;
            }
            batch.push((oid, depth));
            if batch.len() >= READ_BATCH {
                break;
            }
        }
        collect_ms += collect_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        if batch.is_empty() {
            break;
        }
        let oids: Vec<Oid> = batch.iter().map(|(oid, _)| *oid).collect();
        if batch.len() < READ_SERIAL_BELOW {
            serial_items += u64::try_from(batch.len()).expect("batch is bounded by READ_BATCH");
        } else {
            parallel_items += u64::try_from(batch.len()).expect("batch is bounded by READ_BATCH");
        }
        let read_start = profile.then(std::time::Instant::now);
        let reads = pool.read(src, &oids, interrupt)?;
        read_ms += read_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let link_start = profile.then(std::time::Instant::now);
        for ((oid, depth), read) in batch.into_iter().zip(reads) {
            let (obj_kind, bytes, links) = read.map_err(|err| match err {
                GitError::NotFound { .. } => GitError::NotFound {
                    detail: format!("local source lacks wanted object {oid}"),
                },
                other => other,
            })?;
            let cutoff = req
                .depth
                .is_some_and(|max| obj_kind == ObjectKind::Commit && depth >= max);
            if cutoff {
                shallow.push(oid);
            }
            if let Some(tree) = links.tree {
                queue.push_back((tree, depth));
            }
            if !cutoff {
                queue.extend(links.parents.iter().map(|parent| (*parent, depth + 1)));
            }
            queue.extend(links.entries.iter().map(|(entry, _)| (*entry, depth)));
            if let Some((target, _)) = links.tag_target {
                queue.push_back((target, depth));
            }
            objects.push((oid, obj_kind, bytes));
        }
        link_ms += link_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
    }
    let sort_start = profile.then(std::time::Instant::now);
    objects.sort_by(|a, b| a.0.cmp(&b.0));
    let sort_ms = sort_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    if profile {
        eprintln!(
            "[ruk-profile] local_closure reads={read_ms:.1}ms links={link_ms:.1}ms collect={collect_ms:.1}ms sort={sort_ms:.1}ms serial_items={serial_items} parallel_items={parallel_items}"
        );
    }
    Ok(LocalClosure { objects, shallow })
}

/// Pushes from one native store into another through a real pack, driving
/// `plan` through its states in `dest`.
///
/// Ref application uses one checked transaction for atomic pushes and
/// per-ref transactions otherwise; a CAS failure rejects that ref without
/// touching the others.
///
/// # Errors
/// Closure, ingest, CAS and store failures. Failures after the destination
/// publish persist `Uncertain` best-effort.
pub fn local_push(
    dest: &Store,
    src: &Store,
    kind: HashKind,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    if req.updates.is_empty() {
        return Err(GitError::Invalid {
            detail: "push needs at least one update".to_owned(),
        });
    }
    if plan.updates != req.updates || plan.atomic != req.atomic {
        return Err(GitError::Invalid {
            detail: "push plan does not match the push request".to_owned(),
        });
    }
    persist_plan(dest, plan, kind, None)?;
    let outcome = local_push_inner(dest, src, kind, plan, req, interrupt);
    match outcome {
        Ok(outcomes) => Ok(outcomes),
        Err(err) => {
            plan.mark_uncertain();
            persist_plan_best_effort(dest, plan, kind);
            Err(err)
        }
    }
}

fn persist_plan(
    store: &Store,
    plan: &PushPlanRecord,
    kind: HashKind,
    previous: Option<Vec<u8>>,
) -> Result<(), GitError> {
    store.publish(Vec::new(), &[plan.persist_mutation(kind, previous)?])?;
    Ok(())
}

fn persist_plan_best_effort(store: &Store, plan: &PushPlanRecord, kind: HashKind) {
    let current = store
        .fact(
            ruk_core::store::types::FactTable::PushPlans,
            plan.id.as_bytes(),
        )
        .ok()
        .flatten();
    if let Ok(mutation) = plan.persist_mutation(kind, current) {
        let _ = store.publish(Vec::new(), &[mutation]);
    }
}

fn plan_encoding(store: &Store, plan: &PushPlanRecord) -> Result<Option<Vec<u8>>, GitError> {
    Ok(store.fact(
        ruk_core::store::types::FactTable::PushPlans,
        plan.id.as_bytes(),
    )?)
}

fn local_push_inner(
    dest: &Store,
    src: &Store,
    kind: HashKind,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    if src.hash_kind() != kind || dest.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "local push needs matching object formats".to_owned(),
        });
    }
    let zero = kind.zero_oid();
    let refs = StoreRefs::new(dest);
    let mut current: HashMap<Vec<u8>, Option<RefTarget>> = HashMap::new();
    for update in &req.updates {
        let name = RefName::new(update.name.clone()).map_err(|err| GitError::Invalid {
            detail: format!("malformed ref name: {err}"),
        })?;
        current.insert(
            update.name.clone(),
            refs.get(&name).map_err(GitError::from)?,
        );
    }
    let mut live: Vec<&PushUpdate> = Vec::with_capacity(req.updates.len());
    let mut outcomes: Vec<RefOutcome> = Vec::with_capacity(req.updates.len());
    for update in &req.updates {
        let at = current.get(update.name.as_slice()).cloned().flatten();
        let expected = if update.old == zero {
            None
        } else {
            Some(RefTarget::Direct(update.old))
        };
        if at != expected {
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: "destination ref moved".to_owned(),
                },
            });
        } else {
            live.push(update);
        }
    }
    if !outcomes.is_empty() && req.atomic {
        for update in live {
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: "atomic push refused locally: a sibling ref moved".to_owned(),
                },
            });
        }
        plan.refuse_locally(outcomes.clone())?;
        persist_plan(dest, plan, kind, plan_encoding(dest, plan)?)?;
        return Ok(outcomes);
    }
    if live.is_empty() {
        plan.refuse_locally(outcomes.clone())?;
        persist_plan(dest, plan, kind, plan_encoding(dest, plan)?)?;
        return Ok(outcomes);
    }
    plan.begin_send()?;
    persist_plan(dest, plan, kind, plan_encoding(dest, plan)?)?;
    let entries = push_closure(src, kind, &live, interrupt)?;
    if !entries.is_empty() {
        let pack_entries: Vec<PackEntry<'_>> = entries
            .iter()
            .map(|entry| PackEntry {
                oid: entry.oid,
                kind: entry.kind,
                bytes: &entry.bytes,
                base: None,
            })
            .collect();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, interrupt)?;
        let staged: StagedPack =
            ingest_pack(&pack[..], kind, dest, IngestLimits::default(), interrupt)?;
        let facts = super::fetch::commit_record_facts(dest, &staged)?;
        dest.publish(staged.into_objects(), &facts)?;
    }
    let mut report = apply_refs(dest, kind, &live, req.atomic)?;
    report.extend(outcomes);
    plan.finalize(report.clone())?;
    persist_plan(dest, plan, kind, plan_encoding(dest, plan)?)?;
    Ok(report)
}

/// Applies ref updates to `dest`: one checked transaction for atomic
/// pushes, per-ref transactions otherwise. CAS failures become per-ref
/// rejections.
///
/// Shared with the `receive-pack` serve half, which applies wire commands
/// through the same CAS path. Callers pre-validate ref names: a malformed
/// name fails the whole batch here.
pub(crate) fn apply_refs(
    dest: &Store,
    kind: HashKind,
    live: &[&PushUpdate],
    atomic: bool,
) -> Result<Vec<RefOutcome>, GitError> {
    let zero = kind.zero_oid();
    let to_update = |update: &PushUpdate| -> Result<RefUpdate, GitError> {
        let name = RefName::new(update.name.clone()).map_err(|err| GitError::Invalid {
            detail: format!("malformed ref name: {err}"),
        })?;
        Ok(RefUpdate {
            expected: if update.old == zero {
                RefExpect::Absent
            } else {
                RefExpect::Present(RefTarget::Direct(update.old))
            },
            change: if update.new == zero {
                RefChange::Delete
            } else {
                RefChange::Set(RefTarget::Direct(update.new))
            },
            name,
        })
    };
    if atomic {
        let updates: Vec<RefUpdate> = live
            .iter()
            .map(|u| to_update(u))
            .collect::<Result<_, _>>()?;
        let transaction = RefTransaction::new(kind, updates).map_err(map_ref_error)?;
        let prepared = prepare_checked_transaction(dest, &transaction).map_err(GitError::from)?;
        match dest.publish(Vec::new(), &prepared.into_mutations()) {
            Ok(_) => Ok(live
                .iter()
                .map(|u| RefOutcome {
                    name: u.name.clone(),
                    result: RefResult::Ok,
                })
                .collect()),
            Err(err) if err.code() == ruk_core::error::ErrorCode::EStale => Ok(live
                .iter()
                .map(|u| RefOutcome {
                    name: u.name.clone(),
                    result: RefResult::Rejected {
                        reason: "destination ref moved during apply".to_owned(),
                    },
                })
                .collect()),
            Err(err) => Err(err.into()),
        }
    } else {
        let mut outcomes = Vec::with_capacity(live.len());
        for update in live {
            let transaction =
                RefTransaction::new(kind, vec![to_update(update)?]).map_err(map_ref_error)?;
            let outcome =
                match prepare_checked_transaction(dest, &transaction).map_err(GitError::from) {
                    Ok(prepared) => match dest.publish(Vec::new(), &prepared.into_mutations()) {
                        Ok(_) => RefResult::Ok,
                        Err(err) if err.code() == ruk_core::error::ErrorCode::EStale => {
                            RefResult::Rejected {
                                reason: "destination ref moved during apply".to_owned(),
                            }
                        }
                        Err(err) => return Err(err.into()),
                    },
                    Err(GitError::Stale { .. }) => RefResult::Rejected {
                        reason: "destination ref moved".to_owned(),
                    },
                    Err(err) => return Err(err),
                };
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: outcome,
            });
        }
        Ok(outcomes)
    }
}

fn map_ref_error(err: ruk_core::refdata::RefError) -> GitError {
    use ruk_core::refdata::RefError as E;
    match err {
        E::Stale { name } => GitError::Stale {
            detail: format!("ref {name} does not hold the expected value"),
        },
        other => GitError::Invalid {
            detail: other.to_string(),
        },
    }
}

/// Re-exports for the wire tests: the scripted peer and received-pack
/// plumbing live here so fetch and push tests share one harness.
#[cfg(test)]
pub mod test_support {
    use super::super::fetch::{FetchWireRequest, ReceivedPack};
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// An in-memory duplex stream: reads serve `script`, writes accumulate
    /// in `written` for exact request assertions.
    #[derive(Debug)]
    pub struct ScriptedPeer {
        script: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedPeer {
        /// Serves `script` to reads.
        #[must_use]
        pub fn new(script: Vec<u8>) -> Self {
            Self {
                script: Cursor::new(script),
                written: Vec::new(),
            }
        }

        /// Bytes the client wrote, in order.
        #[must_use]
        pub fn written(&self) -> &[u8] {
            &self.written
        }
    }

    impl Read for ScriptedPeer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.script.read(buf)
        }
    }

    impl Write for ScriptedPeer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh empty store in a unique scratch directory.
    pub fn test_store(kind: HashKind) -> Store {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ruk-transport-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Store::create(&dir, kind, default_budget()).expect("test store")
    }

    /// Stages every object of a fixture pack into a fresh store and
    /// publishes them, returning the store.
    pub fn store_with_pack(kind: HashKind, pack: &[u8]) -> Store {
        let store = test_store(kind);
        let staged = ingest_pack(
            pack,
            kind,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("fixture stages");
        store
            .publish(staged.into_objects(), &[])
            .expect("fixture publishes");
        store
    }

    /// The `ReceivedPack` plumbing shared by wire tests: runs `receive`
    /// against a scripted peer.
    pub fn receive_from_script(
        script: Vec<u8>,
        kind: HashKind,
        store: &Store,
        req: &FetchWireRequest,
    ) -> (ReceivedPack, Vec<u8>) {
        let mut peer = ScriptedPeer::new(script);
        let out = super::super::fetch::receive(
            &mut peer,
            kind,
            store,
            req,
            IngestLimits::default(),
            &Interrupt::none(),
        );
        let written = peer.written().to_vec();
        (out.expect("receive"), written)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{store_with_pack, test_store};
    use super::*;
    use crate::transport::fetch::verify_closure;
    use crate::transport::push::PushState;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    const THREE: &str = "7a4943e466a7ce4f4c56d9eeb89c8909b1c43d22";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn remote_parsing_accepts_local_and_refuses_network() {
        assert_eq!(
            Remote::parse("file:///srv/repos/a").expect("file url").path,
            PathBuf::from("/srv/repos/a")
        );
        assert_eq!(
            Remote::parse("/srv/repos/a").expect("path").path,
            PathBuf::from("/srv/repos/a")
        );
        assert!(Remote::parse("").is_err());
        for scheme in ["ssh://git@h/x", "https://h/x.git", "git://h/x"] {
            assert!(
                matches!(Remote::parse(scheme), Err(GitError::Unsupported { .. })),
                "{scheme} must name the later slice"
            );
        }
    }

    #[test]
    fn local_fetch_publishes_closure_directly() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let tracking_name = RefName::new(b"refs/remotes/origin/main".to_vec()).expect("name");
        let req = LocalFetchRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: Some(Filter::BlobNone),
            depth: None,
        };
        let report = local_fetch(
            &dest,
            &src,
            b"origin",
            &req,
            &[(tracking_name.clone(), RefTarget::Direct(oid(FOUR)))],
            &[],
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("local fetch");
        assert_eq!(report.delivered, vec![oid(FOUR)]);
        assert!(dest.read(oid(FOUR)).is_ok());
        let row = dest
            .fact(
                ruk_core::store::types::FactTable::RemoteObservations,
                &super::super::observation_key(b"origin", &tracking_name),
            )
            .expect("read")
            .expect("observation recorded");
        assert_eq!(
            super::super::decode_observation(&row, kind).expect("decode"),
            RefTarget::Direct(oid(FOUR))
        );
    }

    #[test]
    fn local_fetch_depth_records_boundaries() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let req = LocalFetchRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: Some(1),
        };
        let report = local_fetch(
            &dest,
            &src,
            b"origin",
            &req,
            &[],
            &[],
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("shallow local fetch");
        // Depth 1 keeps the tip, its tree and its blobs; the parent is the
        // recorded boundary, excluded with its history.
        assert_eq!(report.shallow, vec![oid(THREE)]);
        assert!(super::super::is_shallow(&dest, oid(THREE)).expect("read"));
        assert!(!super::super::is_shallow(&dest, oid(FOUR)).expect("read"));
    }

    #[test]
    fn local_push_applies_refs_with_cas() {
        use ruk_core::change::PlanId;

        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let name = b"refs/heads/main".to_vec();
        let updates = vec![PushUpdate {
            name: name.clone(),
            old: kind.zero_oid(),
            new: oid(FOUR),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"peer".to_vec(), false, updates);
        let outcomes =
            local_push(&dest, &src, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, RefResult::Ok);
        assert_eq!(plan.state, PushState::Confirmed);
        assert!(
            dest.fact(ruk_core::store::types::FactTable::Refs, &name)
                .expect("read")
                .is_some(),
            "ref published"
        );
        // A repeat create against the moved ref is refused, not forced.
        let updates = vec![PushUpdate {
            name: name.clone(),
            old: kind.zero_oid(),
            new: oid(THREE),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"peer".to_vec(), false, updates);
        let outcomes =
            local_push(&dest, &src, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert!(matches!(outcomes[0].result, RefResult::Rejected { .. }));
    }

    #[test]
    fn open_local_store_names_its_boundaries() {
        let missing = std::env::temp_dir().join("ruk-transport-test-no-such-dir-xyz");
        assert!(matches!(
            open_local_store(&missing),
            Err(GitError::NotFound { .. })
        ));
        // A Git-format directory is refused naming the import/export slice.
        let dir =
            std::env::temp_dir().join(format!("ruk-transport-test-gitfmt-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("objects")).expect("scratch");
        std::fs::write(dir.join("HEAD"), b"ref: refs/heads/main\n").expect("scratch");
        assert!(matches!(
            open_local_store(&dir),
            Err(GitError::Unsupported { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncated_closure_is_corrupt_on_any_path() {
        // The same verifier guards wire and local staging: a pack holding
        // only a commit, without its tree, cannot publish.
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let (_, commit) = read_object(&src, oid(FOUR), 1 << 20).expect("commit");
        let entry = PackEntry {
            oid: oid(FOUR),
            kind: ObjectKind::Commit,
            bytes: &commit,
            base: None,
        };
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &[entry], &Interrupt::none()).expect("pack");
        let staged = ingest_pack(
            &pack[..],
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("ingest");
        let err = verify_closure(&dest, &staged, &[oid(FOUR)], None, &[], &Interrupt::none())
            .expect_err("tree is missing");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }
}
