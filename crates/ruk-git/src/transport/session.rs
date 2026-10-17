//! Transport sessions: the network seam and the local native transport.
//!
//! [`Transport`] is the trait later HTTPS/SSH adapters implement: open a
//! duplex stream to one service. There are no network adapters in this
//! slice, and deliberately no `Network` remote variant: [`Remote::parse`]
//! accepts local paths and `file://` URLs and refuses network schemes with
//! [`GitError::Unsupported`], which names the later slice instead of
//! stubbing it.
//!
//! A local native repository uses the same core streaming transfer path as
//! the wire: [`local_fetch`] and [`local_push`] build real pack bytes from
//! the source store and ingest them into the destination through
//! [`ingest_pack`], then publish objects and ref deltas atomically. No
//! shell, no subprocess, no raw segment bytes. Reading a local Git-format
//! source and writing a local Git-format destination belong to the
//! import/export slices; [`open_local_store`] says so explicitly instead
//! of misreading those directories.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate};
use ruk_core::refs::{StoreRefs, page_refs, prepare_checked_transaction};
use ruk_core::store::types::{ObjectKind, Publication};
use ruk_core::store::{PreparationBudget, Store};

use super::fetch::{FetchWireRequest, Filter, promisor_facts, shallow_facts};
use super::pack::{IngestLimits, PackEntry, StagedPack, ingest_pack, object_links, write_pack};
use super::push::{PushPlanRecord, PushUpdate, PushWireRequest, RefOutcome, RefResult, push_closure, reconcile};
use super::fetch::observation_mutations;
use super::{Interrupt, read_object};
use crate::GitError;

/// A Git service on the far end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// `git-upload-pack`: the server sends objects.
    UploadPack,
    /// `git-receive-pack`: the server accepts objects.
    ReceivePack,
}

impl Service {
    /// The service name on the wire.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
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
/// refused, naming the later slice.
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
            return Ok(Self { path: PathBuf::from(rest) });
        }
        if let Some(scheme_end) = spec.find("://") {
            let scheme = &spec[..scheme_end];
            return Err(GitError::Unsupported {
                command: format!("{scheme} transports (network adapters are a later slice)"),
            });
        }
        Ok(Self { path: PathBuf::from(spec) })
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
        detail: format!("{} is neither a Ruk store nor a Git repository", path.display()),
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

/// Fetches from one native store into another through a real pack: the
/// closure is packed from `src`, ingested into `dest` staging, verified,
/// and published with promisor/shallow/observation facts and the caller's
/// ref mutations in one transaction.
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
    let closure = local_closure(src, kind, req, interrupt)?;
    let pack_entries: Vec<PackEntry<'_>> = closure
        .objects
        .iter()
        .map(|(oid, obj_kind, bytes)| PackEntry {
            oid: *oid,
            kind: *obj_kind,
            bytes,
            base: None,
        })
        .collect();
    let mut pack = Vec::new();
    write_pack(&mut pack, kind, &pack_entries, interrupt)?;
    let staged = ingest_pack(&pack[..], kind, dest, limits, interrupt)?;
    let report = super::fetch::verify_closure(dest, &staged, &req.wants, req.filter, &closure.shallow, interrupt)?;
    let mut facts: Vec<ruk_core::store::types::FactMutation> = Vec::new();
    if let Some(filter) = req.filter {
        facts.extend(promisor_facts(remote, filter, &report.missing_promisor)?);
    }
    facts.extend(shallow_facts(&closure.shallow, &[]));
    facts.extend(observation_mutations(remote, tracking));
    facts.extend(ref_mutations.iter().cloned());
    let publication = dest.publish(staged.into_objects(), &facts)?;
    Ok(FetchReport {
        publication,
        delivered: report.wanted,
        shallow: closure.shallow,
        warnings: Vec::new(),
    })
}

/// The packed closure of a local fetch with its shallow cutoffs.
struct LocalClosure {
    objects: Vec<(Oid, ObjectKind, Vec<u8>)>,
    shallow: Vec<Oid>,
}

/// Computes wants-minus-haves in `src`, depth-bounded when asked.
fn local_closure(
    src: &Store,
    kind: HashKind,
    req: &LocalFetchRequest,
    interrupt: &Interrupt,
) -> Result<LocalClosure, GitError> {
    const MAX: u64 = 512 << 20;
    let haves: HashSet<Oid> = req.haves.iter().copied().collect();
    let mut uninteresting = HashSet::new();
    let mut frontier: VecDeque<Oid> = haves.iter().copied().collect();
    while let Some(oid) = frontier.pop_front() {
        interrupt.check("computing the local fetch closure")?;
        if !uninteresting.insert(oid) {
            continue;
        }
        let bytes = match read_object(src, oid, MAX) {
            Ok((ObjectKind::Commit, bytes)) => bytes,
            Ok(_) => continue,
            Err(err) if matches!(err, GitError::NotFound { .. }) => continue,
            Err(err) => return Err(err),
        };
        frontier.extend(object_links(ObjectKind::Commit, &bytes, kind)?.parents.iter().copied());
    }
    let mut objects = Vec::new();
    let mut shallow = Vec::new();
    let mut visited = HashSet::new();
    // (oid, commit depth from the wants; non-commits ride along).
    let mut queue: VecDeque<(Oid, u32)> =
        req.wants.iter().map(|oid| (*oid, 0)).collect();
    while let Some((oid, depth)) = queue.pop_front() {
        interrupt.check("computing the local fetch closure")?;
        if !visited.insert(oid) || uninteresting.contains(&oid) {
            continue;
        }
        let (obj_kind, bytes) = read_object(src, oid, MAX).map_err(|err| match err {
            GitError::NotFound { .. } => GitError::NotFound {
                detail: format!("local source lacks wanted object {oid}"),
            },
            other => other,
        })?;
        let links = object_links(obj_kind, &bytes, kind)?;
        let cutoff = req.depth.is_some_and(|max| obj_kind == ObjectKind::Commit && depth >= max);
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
    objects.sort_by(|a, b| a.0.cmp(&b.0));
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
    let current = store.fact(ruk_core::store::types::FactTable::PushPlans, plan.id.as_bytes()).ok().flatten();
    if let Ok(mutation) = plan.persist_mutation(kind, current) {
        let _ = store.publish(Vec::new(), &[mutation]);
    }
}

fn plan_encoding(store: &Store, plan: &PushPlanRecord) -> Result<Option<Vec<u8>>, GitError> {
    Ok(store.fact(ruk_core::store::types::FactTable::PushPlans, plan.id.as_bytes())?)
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
        current.insert(update.name.clone(), refs.get(&name).map_err(GitError::from)?);
    }
    let mut live: Vec<&PushUpdate> = Vec::with_capacity(req.updates.len());
    let mut outcomes: Vec<RefOutcome> = Vec::with_capacity(req.updates.len());
    for update in &req.updates {
        let at = current.get(update.name.as_slice()).cloned().flatten();
        let expected = if update.old == zero { None } else { Some(RefTarget::Direct(update.old)) };
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
        let pack_entries: Vec<PackEntry<'_>> = entries.iter().map(|entry| PackEntry {
            oid: entry.oid,
            kind: entry.kind,
            bytes: &entry.bytes,
            base: None,
        }).collect();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, interrupt)?;
        let staged: StagedPack = ingest_pack(&pack[..], kind, dest, IngestLimits::default(), interrupt)?;
        dest.publish(staged.into_objects(), &[])?;
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
fn apply_refs(
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
        let updates: Vec<RefUpdate> = live.iter().map(|u| to_update(u)).collect::<Result<_, _>>()?;
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
            let outcome = match prepare_checked_transaction(dest, &transaction).map_err(GitError::from) {
                Ok(prepared) => match dest.publish(Vec::new(), &prepared.into_mutations()) {
                    Ok(_) => RefResult::Ok,
                    Err(err) if err.code() == ruk_core::error::ErrorCode::EStale => RefResult::Rejected {
                        reason: "destination ref moved during apply".to_owned(),
                    },
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

/// Reconciles an uncertain local plan against the destination's refs.
#[must_use]
pub fn reconcile_local(
    plan: &PushPlanRecord,
    kind: HashKind,
    dest: &Store,
) -> Vec<super::push::ReconciledRef> {
    let mut observed = Vec::with_capacity(plan.updates.len());
    for update in &plan.updates {
        let oid = RefName::new(update.name.clone())
            .ok()
            .and_then(|name| StoreRefs::new(dest).get(&name).ok().flatten())
            .and_then(|target| match target {
                RefTarget::Direct(oid) => Some(oid),
                RefTarget::Symbolic(_) => None,
            });
        observed.push((update.name.clone(), oid));
    }
    reconcile(plan, kind, &observed)
}

/// Builds a [`FetchWireRequest`] against one [`Reconnectable`] prefetch
/// note: promisor servers accept bare blob wants (reachable SHAs are
/// allowed by default); see [`super::fetch::prefetch`].
#[must_use]
pub fn prefetch_request(wants: Vec<Oid>) -> FetchWireRequest {
    FetchWireRequest {
        wants,
        haves: Vec::new(),
        filter: None,
        depth: None,
        shallow: Vec::new(),
        list_refs: false,
        ref_prefixes: Vec::new(),
    }
}

/// Re-exports for the wire tests: the scripted peer and received-pack
/// plumbing live here so fetch and push tests share one harness.
#[cfg(test)]
pub mod test_support {
    use super::*;
    use super::super::fetch::ReceivedPack;
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
        let dir = std::env::temp_dir().join(format!("ruk-transport-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Store::create(&dir, kind, default_budget()).expect("test store")
    }

    /// Stages every object of a fixture pack into a fresh store and
    /// publishes them, returning the store.
    pub fn store_with_pack(kind: HashKind, pack: &[u8]) -> Store {
        let store = test_store(kind);
        let staged = ingest_pack(pack, kind, &store, IngestLimits::default(), &Interrupt::none())
            .expect("fixture stages");
        store.publish(staged.into_objects(), &[]).expect("fixture publishes");
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
        let out = super::super::fetch::receive(&mut peer, kind, store, req, IngestLimits::default(), &Interrupt::none());
        let written = peer.written().to_vec();
        (out.expect("receive"), written)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{store_with_pack, test_store};
    use crate::transport::push::PushState;
    use super::*;
    use crate::transport::fetch::verify_closure;

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
    fn local_fetch_publishes_through_a_real_pack() {
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
        let report =
            local_fetch(&dest, &src, b"origin", &req, &[], &[], IngestLimits::default(), &Interrupt::none())
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
        let req = PushWireRequest { updates: updates.clone(), atomic: false };
        let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"peer".to_vec(), false, updates);
        let outcomes = local_push(&dest, &src, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, RefResult::Ok);
        assert_eq!(plan.state, PushState::Confirmed);
        assert!(
            dest
                .fact(ruk_core::store::types::FactTable::Refs, &name)
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
        let req = PushWireRequest { updates: updates.clone(), atomic: false };
        let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"peer".to_vec(), false, updates);
        let outcomes = local_push(&dest, &src, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert!(matches!(outcomes[0].result, RefResult::Rejected { .. }));
    }

    #[test]
    fn open_local_store_names_its_boundaries() {
        let missing = std::env::temp_dir().join("ruk-transport-test-no-such-dir-xyz");
        assert!(matches!(open_local_store(&missing), Err(GitError::NotFound { .. })));
        // A Git-format directory is refused naming the import/export slice.
        let dir = std::env::temp_dir().join(format!("ruk-transport-test-gitfmt-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("objects")).expect("scratch");
        std::fs::write(dir.join("HEAD"), b"ref: refs/heads/main\n").expect("scratch");
        assert!(matches!(open_local_store(&dir), Err(GitError::Unsupported { .. })));
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
        let staged =
            ingest_pack(&pack[..], kind, &dest, IngestLimits::default(), &Interrupt::none()).expect("ingest");
        let err = verify_closure(&dest, &staged, &[oid(FOUR)], None, &[], &Interrupt::none())
            .expect_err("tree is missing");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }
}
