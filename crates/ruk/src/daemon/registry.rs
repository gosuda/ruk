//! Hosted multi-repository registry: authorized open plus coordinators.
//!
//! The registry owns the canonicalized repository roots of one daemon
//! process. Every open resolves a caller-supplied path or opaque handle to
//! a canonical repository path beneath those roots, then hands out the one
//! hosted coordinator of that repository. Coordinators open lazily on first
//! open: the store opens on the canonical path, the publication lane runner
//! spawns once on the daemon runtime bound through `set_runtime`, one periodic
//! retention task spawns alongside it unless the interval is zero, and idle
//! eviction or registry drop retires the coordinator through `shutdown`.
//! Eviction skips entries with invocations still in flight, so retiring
//! never cancels a live submission. Full serve shutdown goes further
//! through `shutdown_and_drain`, which awaits every lane runner so the
//! drain completes before the runtime drops.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ruk_core::MAX_CONTROL_FRAME_BYTES;
use ruk_core::change::{PlanId, RequestId, SessionId};
use ruk_core::coord::{HostedCoordinator, Principal, cancellation};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::search::{SearchPool, SearchPoolConfig};
use ruk_core::store::{FactPageBudget, FactTable, PreparationBudget, Store};
use ruk_git::transport::net::EgressPolicy;
use ruk_git::transport::push::{PushPlanRecord, PushState};

/// One registered repository: its canonical path, its hosted coordinator
/// once opened, and its last-use instant for idle eviction.
struct RepoEntry {
    /// The canonical repository path beneath a configured root.
    path: PathBuf,
    /// The one hosted coordinator of this repository; `None` until first open.
    coordinator: Option<Arc<HostedCoordinator>>,
    /// The spawned lane runner; awaited by full shutdown so the drain
    /// completes before the runtime drops. Eviction drops it detached:
    /// the runner still drains while the runtime lives.
    runner: Option<tokio::task::JoinHandle<Result<(), CoreError>>>,
    /// The last instant this entry served an open.
    last_used: Instant,
}

/// The mutable handle table behind [`Registry`].
struct RegistryInner {
    /// Opaque handle to repository entry.
    entries: HashMap<String, RepoEntry>,
    /// Canonical repository paths mid-deletion: the entry is gone and the
    /// tombstone rename has not completed, so opening rejects with
    /// `E_CONFLICTED` instead of re-registering a store deletion then
    /// removes. Cleared once the rename lands or fails.
    deleting: HashSet<PathBuf>,
    /// Refs blocked by an unresolved push plan: `(canonical repo path,
    /// ref name)` to the `Uncertain` plan that owns the block. A new push
    /// to a blocked ref refuses with `E_PUSH_UNCERTAIN` until the owning
    /// plan reaches a terminal `Confirmed`/`Rejected` state or a reconcile
    /// observes the remote and clears the block. Restored from durable
    /// `PushPlans` rows when the repository is opened.
    uncertain_pushes: HashMap<(PathBuf, Vec<u8>), PlanId>,
    /// Push idempotency keys with a job past replay: `(session, request
    /// id)` to the entry its waiters sleep on. A duplicate waits for
    /// the owner's terminal receipt instead of sending twice, so two
    /// concurrent pushes coalesce under one key. In-memory only, like
    /// the uncertain blocks above: the terminal receipt answers retries
    /// once the first job commits it.
    inflight_pushes: HashMap<(SessionId, RequestId), InFlightPush>,
}

/// The hosted repository registry of one daemon process.
pub(crate) struct Registry {
    /// Canonicalized repository roots; every open must land beneath one.
    roots: Vec<PathBuf>,
    /// Handle and path bindings.
    inner: Mutex<RegistryInner>,
    /// Counter for fresh opaque handles.
    next_handle: AtomicU64,
    /// The daemon runtime hosting every lane runner; bound before serving.
    runtime: Mutex<Option<tokio::runtime::Handle>>,
    /// Milliseconds between per-coordinator retention sweeps; zero disables them.
    retention_interval_ms: AtomicU64,
    /// Seconds pruning event rows on each sweep.
    event_retention_seconds: AtomicU64,
    /// Milliseconds a hosted hook callback waits before failing closed.
    hook_timeout_ms: AtomicU64,
    /// Commit visits each hosted `compare` may spend.
    compare_max_commits: AtomicU64,
    /// Cap of ref commands accepted per hosted push batch.
    hook_max_commands: AtomicUsize,
    /// Cap of archive bytes served per streamed read.
    archive_max_bytes: AtomicU64,
    /// Default branch new repositories record in `RepoMeta`.
    default_branch: Mutex<String>,
    /// Permits of the search worker pool new coordinators scan with.
    search_pool_size: AtomicUsize,
    /// Decoded bytes new coordinators scan per `search` page.
    search_max_scan_bytes: AtomicU64,
    /// Operator allowlist widening outbound dials past the default-deny
    /// of private and loopback addresses; set once from the daemon
    /// configuration before serving.
    egress_policy: Mutex<EgressPolicy>,
}

impl fmt::Debug for Registry {
    /// Formats the roots and the entry count without exposing coordinators.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self
            .inner
            .lock()
            .map(|inner| inner.entries.len())
            .unwrap_or(0);
        f.debug_struct("Registry")
            .field("roots", &self.roots)
            .field("entries", &entries)
            .finish()
    }
}

impl Registry {
    /// Builds one registry over `roots`, canonicalizing every root.
    ///
    /// # Errors
    /// `E_INVALID` for an empty root set, `E_IO` when a root is missing or
    /// inaccessible.
    pub(crate) fn new(roots: Vec<PathBuf>) -> Result<Self, CoreError> {
        if roots.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "daemon needs at least one repository root",
            ));
        }
        let mut canonical = Vec::with_capacity(roots.len());
        for root in &roots {
            let resolved = std::fs::canonicalize(root).map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("repository root is not accessible: {err}"),
                )
            })?;
            if !canonical.contains(&resolved) {
                canonical.push(resolved);
            }
        }
        let registry = Self {
            roots: canonical,
            inner: Mutex::new(RegistryInner {
                entries: HashMap::new(),
                deleting: HashSet::new(),
                uncertain_pushes: HashMap::new(),
                inflight_pushes: HashMap::new(),
            }),
            next_handle: AtomicU64::new(1),
            runtime: Mutex::new(None),
            retention_interval_ms: AtomicU64::new(super::DEFAULT_RETENTION_INTERVAL_MS),
            event_retention_seconds: AtomicU64::new(super::DEFAULT_EVENT_RETENTION_SECONDS),
            hook_timeout_ms: AtomicU64::new(super::DEFAULT_HOOK_TIMEOUT_MS),
            compare_max_commits: AtomicU64::new(
                super::DEFAULT_COMPARE_MAX_COMMITS
                    .try_into()
                    .expect("compare budget fits u64"),
            ),
            hook_max_commands: AtomicUsize::new(super::MAX_HOOK_MAX_COMMANDS),
            archive_max_bytes: AtomicU64::new(super::DEFAULT_ARCHIVE_MAX_BYTES),
            default_branch: Mutex::new(String::from(super::DEFAULT_DEFAULT_BRANCH)),
            search_pool_size: AtomicUsize::new(super::DEFAULT_SEARCH_POOL_SIZE),
            search_max_scan_bytes: AtomicU64::new(super::DEFAULT_SEARCH_MAX_SCAN_BYTES),
            egress_policy: Mutex::new(EgressPolicy::deny_private()),
        };
        registry.sweep_tombstones();
        Ok(registry)
    }

    /// Removes crash-left tombstone directories beneath every root.
    ///
    /// A delete that crashes between the tombstone rename and the removal
    /// leaves the tombstone behind; the next startup sweeps it. Only
    /// directories in the reserved `.tombstone-` prefix namespace are
    /// removed, and failures are reported to stderr without refusing
    /// startup.
    fn sweep_tombstones(&self) {
        for root in &self.roots {
            let entries = match std::fs::read_dir(root) {
                Ok(entries) => entries,
                Err(err) => {
                    eprintln!("ruk tombstone: cannot list {}: {err}", root.display());
                    continue;
                }
            };
            for entry in entries.flatten() {
                if !is_tombstone(&entry) {
                    continue;
                }
                if let Err(err) = std::fs::remove_dir_all(entry.path()) {
                    eprintln!(
                        "ruk tombstone: cannot remove {}: {err}",
                        entry.path().display()
                    );
                }
            }
            if let Err(err) = fsync_dir(root) {
                eprintln!("ruk tombstone: cannot sync {}: {err}", root.display());
            }
        }
    }

    /// Binds the daemon runtime hosting every lane runner.
    ///
    /// `serve` calls this once before accepting; [`Registry::open`] refuses
    /// with `E_HOSTED` until it runs.
    pub(crate) fn set_runtime(&self, handle: tokio::runtime::Handle) {
        if let Ok(mut runtime) = self.runtime.lock() {
            *runtime = Some(handle);
        }
    }

    /// Sets the interval between per-coordinator retention sweeps.
    ///
    /// `serve` calls this once from the daemon configuration before serving;
    /// each coordinator opened afterwards sweeps on this period. Zero disables
    /// the per-coordinator tasks. The atomic read in `coordinator_for` keeps
    /// opens lock-free with respect to this setting.
    pub(crate) fn set_retention_interval(&self, interval: Duration) {
        self.retention_interval_ms.store(
            u64::try_from(interval.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Sets the horizon pruning event rows, in seconds.
    ///
    /// `serve` calls this once from the daemon configuration before serving;
    /// each coordinator opened afterwards sweeps events to this horizon.
    pub(crate) fn set_event_retention_seconds(&self, seconds: u64) {
        self.event_retention_seconds
            .store(seconds, Ordering::Relaxed);
    }

    /// Sets the per-compare commit visit budget.
    ///
    /// `serve` calls this once from the daemon configuration before serving;
    /// each coordinator opened afterwards bounds its compares to this many
    /// commit visits.
    pub(crate) fn set_compare_max_commits(&self, commits: u64) {
        self.compare_max_commits.store(commits, Ordering::Relaxed);
    }

    /// Sets the hosted hook callback deadline.
    ///
    /// `serve` calls this once from the daemon configuration before
    /// serving; each hosted push waits this long for hook verdicts
    /// before failing closed.
    pub(crate) fn set_hook_timeout(&self, timeout: Duration) {
        self.hook_timeout_ms.store(
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Reads the hosted hook callback deadline.
    pub(crate) fn hook_timeout(&self) -> Duration {
        Duration::from_millis(self.hook_timeout_ms.load(Ordering::Relaxed))
    }

    /// Sets the outbound dial allowlist from the daemon configuration.
    ///
    /// `serve` calls this once before serving; a `Registry` built for
    /// tests keeps the default-deny.
    pub(crate) fn set_egress_policy(&self, policy: EgressPolicy) {
        *self.egress_policy.lock().expect("egress policy lock") = policy;
    }

    /// The outbound dial allowlist transport jobs run under.
    pub(crate) fn egress_policy(&self) -> EgressPolicy {
        self.egress_policy
            .lock()
            .expect("egress policy lock")
            .clone()
    }

    /// Sets the cap of ref commands accepted per hosted push batch.
    ///
    /// `serve` calls this once from the daemon configuration before serving.
    pub(crate) fn set_hook_max_commands(&self, max: usize) {
        self.hook_max_commands.store(max, Ordering::Relaxed);
    }

    /// Reads the cap of ref commands accepted per hosted push batch.
    pub(crate) fn hook_max_commands(&self) -> usize {
        self.hook_max_commands.load(Ordering::Relaxed)
    }

    /// Sets the cap of archive bytes served per streamed read.
    ///
    /// `serve` calls this once from the daemon configuration before serving.
    pub(crate) fn set_archive_max_bytes(&self, max: u64) {
        self.archive_max_bytes.store(max, Ordering::SeqCst);
    }

    /// Reads the cap of archive bytes served per streamed read.
    pub(crate) fn archive_max_bytes(&self) -> u64 {
        self.archive_max_bytes.load(Ordering::SeqCst)
    }

    /// Sets the default branch new repositories record in `RepoMeta`.
    ///
    /// `serve` calls this once from the daemon configuration before
    /// serving; every `repo.init` afterwards records this branch unless
    /// its arguments name one.
    pub(crate) fn set_default_branch(&self, branch: String) {
        if let Ok(mut configured) = self.default_branch.lock() {
            *configured = branch;
        }
    }

    /// Sets the permits of the search worker pool.
    ///
    /// `serve` calls this once from the daemon configuration before
    /// serving; each coordinator opened afterwards scans with this pool.
    pub(crate) fn set_search_pool_size(&self, permits: usize) {
        self.search_pool_size.store(permits, Ordering::Relaxed);
    }

    /// Sets the decoded bytes new coordinators scan per `search` page.
    ///
    /// `serve` calls this once from the daemon configuration before
    /// serving; each coordinator opened afterwards seals pages at this
    /// ceiling with a cursor instead of refusing.
    pub(crate) fn set_search_max_scan_bytes(&self, bytes: u64) {
        self.search_max_scan_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Refuses a push whose ref is blocked by an unresolved plan: returns
    /// the owning `Uncertain` plan when any of `refs` is blocked for
    /// `repo`, so the job fails `E_PUSH_UNCERTAIN` before sending.
    ///
    /// # Errors
    /// `E_PUSH_UNCERTAIN` naming the blocking plan, `E_IO` when the guard
    /// lock is poisoned.
    pub(crate) fn push_guard_check(&self, repo: &Path, refs: &[Vec<u8>]) -> Result<(), CoreError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "push guard lock is poisoned"))?;
        for name in refs {
            let key = (repo.to_path_buf(), name.clone());
            if let Some(plan) = inner.uncertain_pushes.get(&key) {
                let noun = String::from_utf8_lossy(name);
                return Err(CoreError::new(
                    ErrorCode::EPushUncertain,
                    format!("ref {noun} is blocked by uncertain push plan {plan}"),
                ));
            }
        }
        Ok(())
    }

    /// Records the terminal state of one push plan on the guard: an
    /// `Uncertain` plan blocks its refs, while `Confirmed`/`Rejected`
    /// clears the entries that plan owns so the next push may proceed.
    ///
    /// # Errors
    /// `E_IO` when the guard lock is poisoned.
    pub(crate) fn note_push_terminal(
        &self,
        repo: &Path,
        plan: PlanId,
        refs: &[Vec<u8>],
        uncertain: bool,
    ) -> Result<(), CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "push guard lock is poisoned"))?;
        for name in refs {
            let key = (repo.to_path_buf(), name.clone());
            if uncertain {
                inner.uncertain_pushes.insert(key, plan);
            } else if inner.uncertain_pushes.get(&key) == Some(&plan) {
                inner.uncertain_pushes.remove(&key);
            }
        }
        Ok(())
    }

    /// Clears the guard `plan` owns for `refs` after a reconcile observed
    /// the remote: the observation resolves the uncertainty the block
    /// stood for, so a follow-up push may proceed on the observed state.
    /// Entries owned by another plan stay blocked, mirroring
    /// [`Registry::note_push_terminal`].
    ///
    /// # Errors
    /// `E_IO` when the guard lock is poisoned.
    pub(crate) fn note_push_reconciled(
        &self,
        repo: &Path,
        plan: PlanId,
        refs: &[Vec<u8>],
    ) -> Result<(), CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "push guard lock is poisoned"))?;
        for name in refs {
            let key = (repo.to_path_buf(), name.clone());
            if inner.uncertain_pushes.get(&key) == Some(&plan) {
                inner.uncertain_pushes.remove(&key);
            }
        }
        Ok(())
    }

    /// Reserves one push's idempotency key before discovery or dial: the
    /// first claimant owns the send, and a concurrent duplicate waits for
    /// the owner's terminal receipt instead of sending twice, so matching
    /// in-flight pushes coalesce under one key.
    ///
    /// # Errors
    /// `E_IO` when the guard lock is poisoned.
    pub(crate) fn claim_push_request(
        &self,
        session: SessionId,
        request: RequestId,
    ) -> Result<PushKeyClaim<'_>, CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "push guard lock is poisoned"))?;
        let key = (session, request);
        if let Some(entry) = inner.inflight_pushes.get(&key) {
            return Ok(PushKeyClaim::Wait(Arc::clone(&entry.notify)));
        }
        inner.inflight_pushes.insert(
            key,
            InFlightPush {
                notify: Arc::new(tokio::sync::Notify::new()),
                holders: 1,
            },
        );
        Ok(PushKeyClaim::Owner(PushKeyGuard {
            registry: self,
            session,
            request,
        }))
    }

    /// Adds the bulkhead worker's half of one claimed key: the send
    /// closure owns it, so a dropped invocation cannot release the key
    /// while its orphaned worker still sends. The lane half releases at
    /// the invocation's end; the key frees only once both halves drop.
    ///
    /// # Errors
    /// `E_IO` when the guard lock is poisoned or the key is unclaimed.
    pub(crate) fn add_push_holder(
        self: &Arc<Self>,
        session: SessionId,
        request: RequestId,
    ) -> Result<PushKeyWorkerHalf, CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "push guard lock is poisoned"))?;
        let Some(entry) = inner.inflight_pushes.get_mut(&(session, request)) else {
            return Err(CoreError::new(
                ErrorCode::EIo,
                "push key released under its owner",
            ));
        };
        entry.holders = entry.holders.saturating_add(1);
        Ok(PushKeyWorkerHalf {
            registry: Arc::clone(self),
            session,
            request,
        })
    }

    /// Drops one half of a push key's claim: the key frees, waking its
    /// waiters, only once the last half drops. A committed receipt
    /// answers the waiters; a miss lets one waiter claim the key and run
    /// the push itself. Lock poison skips the release; the waiters still
    /// observe cancellation on their own tokens.
    fn release_push_request(&self, session: SessionId, request: RequestId) {
        if let Ok(mut inner) = self.inner.lock() {
            let key = (session, request);
            let last = inner.inflight_pushes.get_mut(&key).is_some_and(|entry| {
                entry.holders = entry.holders.saturating_sub(1);
                entry.holders == 0
            });
            if last && let Some(entry) = inner.inflight_pushes.remove(&key) {
                entry.notify.notify_waiters();
            }
        }
    }

    /// Restores one rename's source binding after its filesystem move
    /// fails. The entry is found by its destination path: a concurrent
    /// rename that moved it elsewhere misses the lookup and keeps its
    /// newer binding, while lock poison leaves the stale destination in
    /// place and the error below still reports the failed move.
    fn restore_rename_binding(&self, updated: &Path, prior: PathBuf) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(entry) = entry_by_path_mut(&mut inner, updated)
        {
            entry.path = prior;
        }
    }

    /// Resolves `requested` to a canonical path beneath a configured root,
    /// refusing escapes and symlink components through `openat2`
    /// containment (see `ruk_core::contained`).
    ///
    /// # Errors
    /// `E_NOT_FOUND` for a missing path, `E_IO` when the path is
    /// inaccessible, `E_FORBIDDEN` outside the configured roots or through
    /// a symlink component.
    pub(crate) fn resolve(&self, requested: &Path) -> Result<PathBuf, CoreError> {
        let mut refused: Option<CoreError> = None;
        for root in &self.roots {
            match ruk_core::contained::resolve_contained(root, requested) {
                Ok(canonical) => return Ok(canonical),
                Err(err) if err.code == ErrorCode::ENotFound => continue,
                Err(err) => {
                    refused = Some(err);
                }
            }
        }
        Err(refused
            .unwrap_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository path is unknown")))
    }

    /// Resolves `requested` with its kernel pin held: the descriptor
    /// stays open through the store open so verification can tell a
    /// swapped path from the resolved directory.
    ///
    /// # Errors
    /// As for [`Registry::resolve`].
    pub(crate) fn resolve_pinned(
        &self,
        requested: &Path,
    ) -> Result<ruk_core::contained::PinnedDir, CoreError> {
        let mut refused: Option<CoreError> = None;
        for root in &self.roots {
            match ruk_core::contained::resolve_contained_pinned(root, requested) {
                Ok(pinned) => return Ok(pinned),
                Err(err) if err.code == ErrorCode::ENotFound => continue,
                Err(err) => {
                    refused = Some(err);
                }
            }
        }
        Err(refused
            .unwrap_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository path is unknown")))
    }

    /// Resolves `requested` to the pinned store directory. A `.ruk` child
    /// marks `requested` as a repository root whose store sits inside it;
    /// its absence means `requested` is already the store.
    ///
    /// # Errors
    /// As for [`Registry::resolve_pinned`].
    fn store_pinned(&self, requested: &Path) -> Result<ruk_core::contained::PinnedDir, CoreError> {
        let pinned = self.resolve_pinned(requested)?;
        let store = pinned.path().join(".ruk");
        if store.is_dir() {
            drop(pinned);
            return self.resolve_pinned(&store);
        }
        Ok(pinned)
    }

    /// Resolves `requested` naming either a repository root or its store
    /// directly, returning `(repo_root, store)`.
    ///
    /// Both spellings collapse to the one registered store key through
    /// [`Registry::store_pinned`], so delete and rename hit the same busy
    /// check and the same handle entry. A store ending in `.ruk` belongs
    /// to its parent repository root; any other store is its own root.
    ///
    /// # Errors
    /// As for [`Registry::resolve_pinned`].
    fn resolve_repo_and_store(&self, requested: &Path) -> Result<(PathBuf, PathBuf), CoreError> {
        let pinned = self.store_pinned(requested)?;
        let store = pinned.path().to_path_buf();
        drop(pinned);
        let repo_root = if store.file_name().is_some_and(|name| name == ".ruk") {
            store
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| store.clone())
        } else {
            store.clone()
        };
        Ok((repo_root, store))
    }

    /// Refuses destructive repository operations on anything but an actual
    /// store: the derived repository root must not be a configured root,
    /// and the resolved store directory must carry its format file or
    /// already back an opened coordinator. A bare registered handle is not
    /// enough: handles are created for any path before the store opens,
    /// and a failed open leaves the handle behind. A namespace directory
    /// merely containing repositories has neither marker, and a `root/.ruk`
    /// spelling derives the configured root itself, so both refuse before
    /// any tombstone rename or removal runs.
    ///
    /// # Errors
    /// `E_FORBIDDEN` for a configured root, `E_INVALID` when the target
    /// is not a repository store, `E_IO` when the registry lock is poisoned.
    fn validate_store_target(&self, repo_root: &Path, store: &Path) -> Result<(), CoreError> {
        if self.roots.iter().any(|root| repo_root == root.as_path()) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository is a configured root",
            ));
        }
        // Mirrors the `format` marker `Store::create` writes at the store
        // root (`FORMAT_FILE` stays private to `ruk_core::store`).
        if store.join("format").is_file() {
            return Ok(());
        }
        let opened = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?
            .entries
            .values()
            .any(|entry| entry.path == store && entry.coordinator.is_some());
        if opened {
            return Ok(());
        }
        Err(CoreError::new(
            ErrorCode::EInvalid,
            "repository path is not a repository store",
        ))
    }

    /// Creates one repository beneath `args.root` at `args.path`.
    ///
    /// The destination must be absent; `Store::create` enforces the same
    /// for its format files, so a racing init fails instead of merging.
    /// The default branch comes from the arguments or the daemon
    /// configuration and is persisted in the `RepoMeta` row, so `repo.stat`
    /// reports it before any ref exists. The new repository registers its
    /// handle, so later opens by path resolve without a second lookup.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unconfigured root or an unreachable parent,
    /// `E_FORBIDDEN` outside the configured roots, `E_INVALID` for an
    /// existing destination, a non-UTF-8 path, or a bad branch name, plus
    /// store creation and publication failures.
    pub(crate) fn create_repo(
        &self,
        args: &ruk_core::protocol::RepoInitArgs,
    ) -> Result<ruk_core::protocol::RepoInitReply, CoreError> {
        use ruk_core::protocol::RepoInitReply;
        let claimed = std::fs::canonicalize(&args.root)
            .map_err(|_| CoreError::new(ErrorCode::ENotFound, "repository root is unknown"))?;
        if !self.roots.contains(&claimed) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository root is not configured",
            ));
        }
        let requested = Path::new(&args.root).join(&args.path);
        if Path::new(&args.path)
            .components()
            .any(|component| match component {
                std::path::Component::Normal(name) => is_tombstone_name(&name.to_string_lossy()),
                _ => false,
            })
        {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        let destination = self.resolve_destination(&requested)?;
        if !destination.starts_with(&claimed) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository path escapes its root",
            ));
        }
        if destination
            .file_name()
            .is_some_and(|name| is_tombstone_name(&name.to_string_lossy()))
        {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        if destination.exists() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository already exists",
            ));
        }
        let path = destination
            .to_str()
            .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "repository path is not UTF-8"))?;
        let kind = args
            .object_format
            .unwrap_or(ruk_core::ids::HashKind::DEFAULT);
        let branch = match &args.default_branch {
            Some(branch) => branch.clone(),
            None => {
                let configured = self.default_branch.lock().map_err(|_| {
                    CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned")
                })?;
                ruk_core::refdata::RefName::new(configured.clone()).map_err(|err| {
                    CoreError::new(
                        ErrorCode::EInvalid,
                        format!("default branch is not a valid ref name: {err}"),
                    )
                })?
            }
        };
        let store_dir = destination.join(".ruk");
        let store = ruk_core::store::Store::create(
            &store_dir,
            kind,
            Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        store
            .write_repo_meta(branch.clone())
            .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        let store_id = store.store_id();
        drop(store);
        let store_canonical = std::fs::canonicalize(&store_dir)
            .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
        self.handle_for_path(&store_canonical)?;
        Ok(RepoInitReply {
            path: path.to_owned(),
            store_id,
            object_format: kind,
            default_branch: branch,
        })
    }

    /// Deletes one repository after refusing in-flight invocations.
    ///
    /// Either the repository root or its `.ruk` store names the same
    /// repository: both resolve to the one registered store key before
    /// the busy check, and the filesystem tombstone renames the
    /// repository root. The entry leaves the handle table under the
    /// registry lock while no invocation holds its coordinator (counted
    /// through the shared ownership the eviction pass uses), so new opens
    /// miss and racing deletes serialize. The coordinator shuts down
    /// outside the lock, then the directory renames to a tombstone and is
    /// removed: a crash between the two leaves the tombstone for the
    /// startup sweep. `confirm_path` must name the same repository.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for a missing repository, `E_INVALID` for a
    /// confirmation mismatch, `E_CONFLICTED` while invocations are in
    /// flight, plus shutdown and removal failures.
    pub(crate) fn remove_repo(
        &self,
        args: &ruk_core::protocol::RepoDeleteArgs,
    ) -> Result<ruk_core::protocol::RepoDeleteReply, CoreError> {
        use ruk_core::protocol::RepoDeleteReply;
        if args.confirm_path != args.repo {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "confirmation path does not match the repository",
            ));
        }
        let (repo_root, store) = self.resolve_repo_and_store(Path::new(&args.repo))?;
        self.validate_store_target(&repo_root, &store)?;
        let path = repo_root
            .to_str()
            .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "repository path is not UTF-8"))?;
        let retired = {
            let mut inner = self.inner.lock().map_err(|_| {
                CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned")
            })?;
            if inner.deleting.contains(&repo_root) || inner.deleting.contains(&store) {
                return Err(CoreError::new(
                    ErrorCode::EConflicted,
                    "repository deletion or rename is already in flight",
                ));
            }
            inner.deleting.insert(repo_root.clone());
            inner.deleting.insert(store.clone());
            let taken = take_entry_by_path(&mut inner, &store);
            if let Some((_, entry)) = &taken {
                let busy = entry
                    .coordinator
                    .as_ref()
                    .is_some_and(|coordinator| Arc::strong_count(coordinator) > 1);
                if busy {
                    if let Some((handle, entry)) = taken {
                        inner.entries.insert(handle, entry);
                        inner.deleting.remove(&repo_root);
                        inner.deleting.remove(&store);
                    }
                    return Err(CoreError::new(
                        ErrorCode::EConflicted,
                        "repository has invocations in flight",
                    ));
                }
            }
            taken.and_then(|(_, entry)| entry.coordinator)
        };
        if let Some(coordinator) = retired {
            coordinator.shutdown();
        }
        let tombstone = tombstone_for(&repo_root, self.next_handle.fetch_add(1, Ordering::Relaxed));
        let clear_deleting = |root: &Path, store_path: &Path| {
            if let Ok(mut inner) = self.inner.lock() {
                inner.deleting.remove(root);
                inner.deleting.remove(store_path);
            }
        };
        let renamed = std::fs::rename(&repo_root, &tombstone).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("repository tombstone failed: {err}"),
            )
        });
        clear_deleting(&repo_root, &store);
        renamed?;
        std::fs::remove_dir_all(&tombstone).map_err(|err| {
            CoreError::new(ErrorCode::EIo, format!("repository removal failed: {err}"))
        })?;
        if let Some(parent) = repo_root.parent() {
            fsync_dir(parent)?;
        }
        Ok(RepoDeleteReply {
            deleted_path: path.to_owned(),
        })
    }

    /// Moves one repository within its root, keeping its store id.
    ///
    /// Either the repository root or its `.ruk` store names the source;
    /// both resolve to the one registered store key before the busy check,
    /// and the filesystem rename moves the repository root. Both paths
    /// resolve under the same configured root; the destination must be
    /// absent. An idle open coordinator shuts down and reopens lazily
    /// under the kept handle; invocations in flight refuse with
    /// `E_CONFLICTED`. Parents on both sides fsync after the rename.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for a missing repository, `E_FORBIDDEN` across roots,
    /// `E_INVALID` for an existing destination, `E_CONFLICTED` while
    /// invocations are in flight, plus rename failures.
    fn clear_deleting(&self, paths: &[&Path]) {
        if let Ok(mut inner) = self.inner.lock() {
            for path in paths {
                inner.deleting.remove(*path);
            }
        }
    }

    pub(crate) fn rename_repo(
        &self,
        args: &ruk_core::protocol::RepoRenameArgs,
    ) -> Result<ruk_core::protocol::RepoRenameReply, CoreError> {
        use ruk_core::protocol::RepoRenameReply;
        let (repo_root, store) = self.resolve_repo_and_store(Path::new(&args.repo))?;
        self.validate_store_target(&repo_root, &store)?;
        let root = self
            .roots
            .iter()
            .find(|root| repo_root.starts_with(root))
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EForbidden,
                    "repository escapes the configured roots",
                )
            })?;
        let new_path = Path::new(&args.new_path);
        if new_path.components().any(|component| match component {
            std::path::Component::Normal(name) => is_tombstone_name(&name.to_string_lossy()),
            _ => false,
        }) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        let requested = if new_path.is_absolute() {
            new_path.to_path_buf()
        } else {
            root.join(new_path)
        };
        let destination = self.resolve_destination(&requested)?;
        if destination
            .file_name()
            .is_some_and(|name| is_tombstone_name(&name.to_string_lossy()))
        {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        if destination.exists() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository destination already exists",
            ));
        }
        if !destination.starts_with(root) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository rename stays within one root",
            ));
        }
        let previous = repo_root
            .to_str()
            .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "repository path is not UTF-8"))?;
        let moved = destination
            .to_str()
            .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "repository path is not UTF-8"))?;
        // The entry moves to the destination before the filesystem does,
        // so a failed rename must restore the source binding: the source
        // directory is untouched and the old handle must keep resolving.
        let updated = if store == repo_root {
            destination.clone()
        } else {
            destination.join(".ruk")
        };
        let (retired, prior) = {
            let mut inner = self.inner.lock().map_err(|_| {
                CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned")
            })?;
            if inner.deleting.contains(&repo_root) || inner.deleting.contains(&store) {
                return Err(CoreError::new(
                    ErrorCode::EConflicted,
                    "repository deletion or rename is already in flight",
                ));
            }
            inner.deleting.insert(repo_root.clone());
            inner.deleting.insert(store.clone());
            if let Some(entry) = entry_by_path_mut(&mut inner, &store) {
                let busy = entry
                    .coordinator
                    .as_ref()
                    .is_some_and(|coordinator| Arc::strong_count(coordinator) > 1);
                if busy {
                    drop(inner);
                    self.clear_deleting(&[&repo_root, &store]);
                    return Err(CoreError::new(
                        ErrorCode::EConflicted,
                        "repository has invocations in flight",
                    ));
                }
                let coordinator = entry.coordinator.take();
                entry.runner.take();
                let prior = std::mem::replace(&mut entry.path, updated.clone());
                entry.last_used = Instant::now();
                (coordinator, Some(prior))
            } else {
                (None, None)
            }
        };
        if let Some(coordinator) = retired {
            coordinator.shutdown();
        }
        if let Err(err) = std::fs::rename(&repo_root, &destination) {
            if let Some(prior) = prior {
                self.restore_rename_binding(&updated, prior);
            }
            self.clear_deleting(&[&repo_root, &store]);
            return Err(CoreError::new(
                ErrorCode::EIo,
                format!("repository rename failed: {err}"),
            ));
        }
        self.clear_deleting(&[&repo_root, &store]);
        if let Some(parent) = repo_root.parent() {
            fsync_dir(parent)?;
        }
        if let Some(parent) = destination.parent() {
            fsync_dir(parent)?;
        }
        Ok(RepoRenameReply {
            path: moved.to_owned(),
            previous_path: previous.to_owned(),
        })
    }

    /// Copies one repository into a fresh store id through a staging sibling.
    ///
    /// The source resolves beneath the configured roots and the destination
    /// stays within the source root. A staging sibling holds the fresh
    /// store: sealed segments hardlink (a cross-device link copies
    /// instead), the sealed snapshot installs with the forked generation,
    /// tail objects re-publish by content in base-first order, validated
    /// fact rows follow, and verified LFS payloads relink. The staging
    /// handles close, both parents fsync, the staging directory renames
    /// atomically into the destination, and only the destination-rooted
    /// store opens and registers: a staging-rooted handle never registers
    /// and never survives the rename. Any failure before the rename removes
    /// the staging directory best-effort; a leftover staging directory
    /// never blocks a retry, which mints a fresh name. Released-tag freeze
    /// markers, attestations, and all other live coordination state stay
    /// behind; the default branch carries over.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unknown source, `E_FORBIDDEN` outside the
    /// roots, `E_INVALID` for an existing destination, `E_STALE` when the
    /// source moves under the photograph, plus store and I/O failures.
    pub(crate) fn fork_repo(
        &self,
        args: &ruk_core::protocol::RepoForkArgs,
    ) -> Result<ruk_core::protocol::RepoForkReply, CoreError> {
        self.fork_repo_with_link(
            args,
            &|from, to| std::fs::hard_link(from, to),
            &staging_sibling,
        )
    }

    /// Serves `repo.fork` with an injectable segment link: production passes
    /// the filesystem hard link, and the cross-device fallback copies.
    ///
    /// # Errors
    /// As for [`Registry::fork_repo`].
    pub(crate) fn fork_repo_with_link(
        &self,
        args: &ruk_core::protocol::RepoForkArgs,
        link: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
        mint: &dyn Fn(&Path) -> PathBuf,
    ) -> Result<ruk_core::protocol::RepoForkReply, CoreError> {
        use ruk_core::protocol::ForkRefs;
        let (repo_root, source_store_dir) = self.resolve_repo_and_store(Path::new(&args.source))?;
        let root = self
            .roots
            .iter()
            .find(|root| repo_root.starts_with(root))
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EForbidden,
                    "repository escapes the configured roots",
                )
            })?;
        let new_path = Path::new(&args.path);
        if new_path.components().any(|component| match component {
            std::path::Component::Normal(name) => is_tombstone_name(&name.to_string_lossy()),
            _ => false,
        }) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        let requested = if new_path.is_absolute() {
            new_path.to_path_buf()
        } else {
            root.join(new_path)
        };
        let destination = self.resolve_destination(&requested)?;
        if destination
            .file_name()
            .is_some_and(|name| is_tombstone_name(&name.to_string_lossy()))
        {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository name is reserved",
            ));
        }
        if !destination.starts_with(root) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository fork stays within one root",
            ));
        }
        if destination.exists() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "repository already exists",
            ));
        }
        let fallback = self
            .default_branch
            .lock()
            .map(|guard| guard.clone().into_bytes())
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?;
        let live = {
            let inner = self.inner.lock().map_err(|_| {
                CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned")
            })?;
            inner
                .entries
                .values()
                .find(|entry| entry.path == source_store_dir)
                .and_then(|entry| entry.coordinator.clone())
        };
        let source = match live {
            Some(coordinator) => ForkSource::Live(coordinator),
            None => {
                let store = Store::open(
                    &source_store_dir,
                    Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
                )
                .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
                ForkSource::Cold(Box::new(store))
            }
        };
        let mode = args.refs.unwrap_or(ForkRefs::All);
        let _fork_pin = source.store().pin_for_fork();
        let snapshot = Self::photograph_fork_source(source.store(), mode, &fallback)?;
        let (container, staging, staging_store) =
            Self::stage_fork_store(&destination, snapshot.kind, mint)?;
        let destination_store = destination.join(".ruk");
        let install = ForkInstall {
            source: source.store(),
            source_store: &source_store_dir,
            destination: &destination,
            destination_store: &destination_store,
            container: &container,
            staging: &staging,
            link,
        };
        let outcome = self.finish_fork(&install, staging_store, &snapshot);
        drop(source);
        if outcome.is_err() {
            let _ = std::fs::remove_dir_all(&container);
        }
        outcome
    }

    /// Photographs one fork snapshot with full CAS revalidation: the source
    /// generation plus every copied fact row must read back unchanged, and
    /// the copied key sets must match a fresh page, otherwise the source
    /// moved and the attempt retries. Three attempts fail with `E_STALE`.
    ///
    /// # Errors
    /// `E_STALE` when the source moves under the photograph, plus store
    /// failures.
    fn photograph_fork_source(
        store: &Store,
        mode: ruk_core::protocol::ForkRefs,
        fallback_default: &[u8],
    ) -> Result<ForkSnapshot, CoreError> {
        use ruk_core::protocol::ForkRefs;
        use ruk_core::store::{FactTable, REPO_META_KEY};
        let map_err =
            |err: ruk_core::store::StoreError| CoreError::new(err.code(), err.to_string());
        for _ in 0..3 {
            let generation = store.generation().map_err(map_err)?;
            let default_branch = store
                .default_branch()
                .map_err(map_err)?
                .map(|name| name.as_bytes().to_vec())
                .unwrap_or_else(|| fallback_default.to_vec());
            let manifests = store.all_manifests().map_err(map_err)?;
            let mut sealed_manifests: Vec<ruk_core::store::SegmentManifest> = manifests
                .into_iter()
                .filter(|manifest| manifest.sealed && !manifest.retired)
                .collect();
            sealed_manifests.sort_by_key(|manifest| manifest.id);
            let sealed_ids: std::collections::HashSet<u64> = sealed_manifests
                .iter()
                .map(|manifest| manifest.id)
                .collect();
            let mut sealed = Vec::new();
            let mut tail = Vec::new();
            for (oid, location) in store.all_object_locations().map_err(map_err)? {
                if sealed_ids.contains(&location.segment) {
                    sealed.push((oid, location));
                } else {
                    tail.push((oid, location));
                }
            }
            sealed.sort_by_key(|(oid, _)| *oid);
            tail.sort_by(|left, right| {
                left.1
                    .depth
                    .cmp(&right.1.depth)
                    .then_with(|| left.0.cmp(&right.0))
            });
            let mut rows: Vec<(FactTable, Vec<u8>, Vec<u8>)> =
                Self::page_fork_table(store, FactTable::Commits, map_err)?;
            rows.extend(Self::page_fork_table(store, FactTable::Changes, map_err)?);
            rows.extend(Self::page_fork_table(
                store,
                FactTable::ChangeHistory,
                map_err,
            )?);
            rows.extend(Self::page_fork_table(
                store,
                FactTable::ImportedChanges,
                map_err,
            )?);
            rows.extend(Self::page_fork_table(store, FactTable::Shallow, map_err)?);
            rows.extend(Self::page_fork_table(
                store,
                FactTable::LfsObjects,
                map_err,
            )?);
            for row in Self::page_fork_table(store, FactTable::Refs, map_err)? {
                let (_, key, _) = &row;
                let keep = match mode {
                    ForkRefs::All => true,
                    ForkRefs::None => false,
                    ForkRefs::DefaultAndTags => {
                        key.as_slice() == default_branch.as_slice()
                            || key.starts_with(b"refs/tags/")
                    }
                };
                if keep {
                    rows.push(row);
                }
            }
            if let Some(raw) = store
                .fact(FactTable::RepoMeta, REPO_META_KEY)
                .map_err(map_err)?
            {
                rows.push((FactTable::RepoMeta, REPO_META_KEY.to_vec(), raw));
            }
            if Self::fork_snapshot_moved(store, mode, &default_branch, generation, &rows, map_err)?
            {
                continue;
            }
            let refs_copied = fork_count(
                rows.iter()
                    .filter(|(table, _, _)| *table == FactTable::Refs)
                    .count(),
            )?;
            return Ok(ForkSnapshot {
                kind: store.hash_kind(),
                generation,
                sealed_manifests,
                sealed,
                tail,
                rows,
                refs_copied,
                mode,
                default_branch,
            });
        }
        Err(CoreError::new(
            ErrorCode::EStale,
            "source moved during fork; retry",
        ))
    }

    /// Pages one whole fact table in bounded pages for the fork snapshot.
    ///
    /// # Errors
    /// Store failures mapped to [`CoreError`].
    fn page_fork_table(
        store: &Store,
        table: ruk_core::store::FactTable,
        map_err: impl Fn(ruk_core::store::StoreError) -> CoreError + Copy,
    ) -> Result<ForkRows, CoreError> {
        use ruk_core::store::FactPageBudget;
        let mut out = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = store
                .fact_page(
                    table,
                    after.as_deref(),
                    FactPageBudget::new(1024, 4 * 1024 * 1024),
                )
                .map_err(map_err)?;
            let more = page.more;
            let last = page.rows.last().map(|row| row.key.clone());
            out.extend(page.rows.into_iter().map(|row| (table, row.key, row.value)));
            if !more {
                return Ok(out);
            }
            match last {
                Some(key) => after = Some(key),
                None => return Ok(out),
            }
        }
    }

    /// Whether the source moved under a fork snapshot: the generation must
    /// still match, every photographed fact row must read back unchanged,
    /// and the copied key sets must match a fresh page. Facts-only source
    /// publications never advance the locator generation, so the
    /// generation check alone cannot catch them.
    ///
    /// # Errors
    /// Store failures mapped to [`CoreError`].
    fn fork_snapshot_moved(
        store: &Store,
        mode: ruk_core::protocol::ForkRefs,
        default_branch: &[u8],
        generation: u64,
        rows: &ForkRows,
        map_err: impl Fn(ruk_core::store::StoreError) -> CoreError + Copy,
    ) -> Result<bool, CoreError> {
        if store.generation().map_err(map_err)? != generation {
            return Ok(true);
        }
        for (table, key, value) in rows {
            match store.fact(*table, key).map_err(map_err)? {
                Some(current) if current == *value => {}
                _ => return Ok(true),
            }
        }
        if !Self::fork_key_sets_match(store, mode, default_branch, rows, map_err)? {
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether the photographed rows still match a fresh page of every
    /// copied table: an inserted or removed row outside the point-checked
    /// keys counts as movement.
    ///
    /// # Errors
    /// Store failures mapped to [`CoreError`].
    fn fork_key_sets_match(
        store: &Store,
        mode: ruk_core::protocol::ForkRefs,
        default_branch: &[u8],
        rows: &ForkRows,
        map_err: impl Fn(ruk_core::store::StoreError) -> CoreError + Copy,
    ) -> Result<bool, CoreError> {
        use ruk_core::protocol::ForkRefs;
        use ruk_core::store::FactTable;
        let mut fresh: Vec<(FactTable, Vec<u8>)> = Vec::new();
        for table in [
            FactTable::Commits,
            FactTable::Changes,
            FactTable::ChangeHistory,
            FactTable::ImportedChanges,
            FactTable::Shallow,
            FactTable::LfsObjects,
        ] {
            for (row_table, key, _) in Self::page_fork_table(store, table, map_err)? {
                fresh.push((row_table, key));
            }
        }
        for (_, key, _) in Self::page_fork_table(store, FactTable::Refs, map_err)? {
            let keep = match mode {
                ForkRefs::All => true,
                ForkRefs::None => false,
                ForkRefs::DefaultAndTags => {
                    key.as_slice() == default_branch || key.starts_with(b"refs/tags/")
                }
            };
            if keep {
                fresh.push((FactTable::Refs, key));
            }
        }
        fresh.sort();
        let mut staged: Vec<(FactTable, Vec<u8>)> = rows
            .iter()
            .filter(|(table, _, _)| *table != FactTable::RepoMeta)
            .map(|(table, key, _)| (*table, key.clone()))
            .collect();
        staged.sort();
        Ok(fresh == staged)
    }

    /// Creates one staging sibling holding a fresh store, minting a fresh
    /// name on every attempt so a leftover staging directory never blocks a
    /// retry.
    ///
    /// # Errors
    /// `E_IO` when no staging name stays free, plus store creation
    /// failures.
    fn stage_fork_store(
        destination: &Path,
        kind: ruk_core::ids::HashKind,
        mint: &dyn Fn(&Path) -> PathBuf,
    ) -> Result<(PathBuf, PathBuf, Store), CoreError> {
        for _ in 0..8 {
            let container = mint(destination);
            if container.exists() {
                continue;
            }
            if let Some(parent) = container.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    CoreError::new(
                        ErrorCode::EIo,
                        format!("fork staging parent is not created: {err}"),
                    )
                })?;
            }
            std::fs::create_dir(&container).map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("fork staging directory is not created: {err}"),
                )
            })?;
            let staging = container.join("store");
            return match Store::create(
                &staging,
                kind,
                Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
            ) {
                Ok(store) => Ok((container, staging, store)),
                Err(err) => {
                    let _ = std::fs::remove_dir_all(&container);
                    Err(CoreError::new(err.code(), err.to_string()))
                }
            };
        }
        Err(CoreError::new(
            ErrorCode::EIo,
            "fork staging is never free; retry",
        ))
    }

    /// Installs the snapshot into staging, closes the staging handles,
    /// fsyncs, renames into the destination, then opens, verifies, and
    /// registers the destination-rooted store.
    ///
    /// # Errors
    /// `E_STALE` when the source moves under the tail copy, plus link,
    /// store, and I/O failures. The caller removes the staging directory
    /// best-effort on any error.
    fn finish_fork(
        &self,
        install: &ForkInstall<'_>,
        staging_store: Store,
        snapshot: &ForkSnapshot,
    ) -> Result<ruk_core::protocol::RepoForkReply, CoreError> {
        use ruk_core::store::{
            EventContext, EventSource, FactExpectation, FactMutation, FactTable,
        };
        let map_err =
            |err: ruk_core::store::StoreError| CoreError::new(err.code(), err.to_string());
        let stale = |detail: &str| CoreError::new(ErrorCode::EStale, detail.to_owned());
        let mut linked = Vec::new();
        let mut copied = Vec::new();
        for manifest in &snapshot.sealed_manifests {
            let from = install.source.segment_path(manifest.id);
            let to = staging_store.segment_path(manifest.id);
            match link_or_copy(install.link, &from, &to) {
                Ok(LinkOutcome::Linked) => linked.push(manifest.id),
                Ok(LinkOutcome::Copied) => {
                    sync_copied_file(&to, manifest.id)?;
                    copied.push(manifest.id);
                }
                Err(err) => {
                    return Err(CoreError::new(
                        ErrorCode::EIo,
                        format!("fork links segment {}: {err}", manifest.id),
                    ));
                }
            }
        }
        sync_copied_dirs(&copied, |id| staging_store.segment_path(id))?;
        let tail_oids: Vec<ruk_core::ids::Oid> =
            snapshot.tail.iter().map(|(oid, _)| *oid).collect();
        staging_store
            .import_sealed_snapshot(
                &snapshot.sealed_manifests,
                &snapshot.sealed,
                &tail_oids,
                snapshot.generation,
            )
            .map_err(map_err)?;
        if install.source.generation().map_err(map_err)? != snapshot.generation {
            return Err(stale("source moved during fork; retry"));
        }
        let mut committed: std::collections::HashSet<ruk_core::ids::Oid> =
            snapshot.sealed.iter().map(|(oid, _)| *oid).collect();
        let mut pending: std::collections::HashSet<ruk_core::ids::Oid> =
            std::collections::HashSet::new();
        let mut batch = Vec::new();
        for (oid, location) in &snapshot.tail {
            let read = install.source.read(*oid).map_err(|err| {
                if err.code() == ErrorCode::ENotFound {
                    stale("source moved during fork; retry")
                } else {
                    map_err(err)
                }
            })?;
            if read.kind != location.kind || read.bytes.len() != location.decoded_len {
                return Err(stale("source moved during fork; retry"));
            }
            // A delta reads its base from the staging store, so a base still
            // in the pending batch must commit before this object prepares.
            let predecessor = match location.base {
                Some(base) if pending.contains(&base) => {
                    flush_fork_batch(&staging_store, &mut batch, &mut committed, &mut pending)?;
                    Some(base)
                }
                Some(base) if committed.contains(&base) => Some(base),
                Some(base) => {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        format!("tail object {oid} names base {base} absent from the fork"),
                    ));
                }
                None => None,
            };
            let object = staging_store
                .prepare(read.kind, read.bytes.len(), read.bytes, predecessor)
                .map_err(map_err)?;
            if object.oid() != *oid {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    format!("tail object {oid} re-hashes to {}", object.oid()),
                ));
            }
            pending.insert(*oid);
            batch.push(object);
            if batch.len() >= 256 {
                flush_fork_batch(&staging_store, &mut batch, &mut committed, &mut pending)?;
            }
        }
        flush_fork_batch(&staging_store, &mut batch, &mut committed, &mut pending)?;
        if Self::fork_snapshot_moved(
            install.source,
            snapshot.mode,
            &snapshot.default_branch,
            snapshot.generation,
            &snapshot.rows,
            map_err,
        )? {
            return Err(stale("source moved during fork; retry"));
        }
        let mut facts = Vec::new();
        let mut lfs_linked = 0u64;
        for (table, key, value) in &snapshot.rows {
            let mut publish = true;
            if *table == FactTable::LfsObjects {
                publish = link_lfs_payload(install, key, value)?;
                if publish {
                    lfs_linked += 1;
                }
            }
            if publish {
                facts.push(FactMutation {
                    table: *table,
                    key: key.clone(),
                    expected: FactExpectation::Absent,
                    value: Some(value.clone()),
                });
            }
        }
        for chunk in facts.chunks(512) {
            staging_store
                .publish(
                    Vec::new(),
                    chunk,
                    EventSource::Fork,
                    &EventContext::default(),
                )
                .map_err(map_err)?;
        }
        if snapshot
            .rows
            .iter()
            .all(|(table, _, _)| *table != FactTable::RepoMeta)
        {
            let fallback = self
                .default_branch
                .lock()
                .map(|guard| guard.clone())
                .map_err(|_| {
                    CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned")
                })?;
            let branch = ruk_core::refdata::RefName::new(fallback).map_err(|err| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    format!("default branch is not a valid ref name: {err}"),
                )
            })?;
            staging_store.write_repo_meta(branch).map_err(map_err)?;
        }
        let generation = staging_store.generation().map_err(map_err)?;
        staging_store.close().map_err(map_err)?;
        drop(staging_store);
        fsync_dir(install.staging)?;
        if let Some(parent) = install.staging.parent() {
            fsync_dir(parent)?;
        }
        std::fs::create_dir(install.destination).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("repository fork root is not created: {err}"),
            )
        })?;
        std::fs::rename(install.staging, install.destination_store).map_err(|err| {
            CoreError::new(ErrorCode::EIo, format!("repository fork failed: {err}"))
        })?;
        let _ = std::fs::remove_dir(install.container);
        let verified = (|| {
            if let Some(parent) = install.destination.parent() {
                fsync_dir(parent)?;
            }
            Self::verify_fork_destination(self, install)
        })();
        let store_id = match verified {
            Ok(store_id) => store_id,
            Err(err) => {
                let _ = std::fs::remove_dir_all(install.destination);
                return Err(err);
            }
        };
        let sealed_objects = fork_count(snapshot.sealed.len())?;
        let tail_objects = fork_count(snapshot.tail.len())?;
        let objects = sealed_objects
            .checked_add(tail_objects)
            .ok_or_else(|| CoreError::new(ErrorCode::EIo, "fork object count overflows u64"))?;
        Ok(ruk_core::protocol::RepoForkReply {
            path: install
                .destination
                .to_str()
                .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "repository path is not UTF-8"))?
                .to_owned(),
            store_id,
            source_generation: snapshot.generation,
            objects,
            sealed_objects,
            tail_objects,
            refs_copied: snapshot.refs_copied,
            segments_linked: linked,
            segments_copied: copied,
            lfs_linked,
            generation,
        })
    }

    /// Opens the renamed destination to run the standard recovery and
    /// verification pass, then registers its destination-rooted handle.
    /// The caller removes the destination best-effort when this fails, so
    /// a failed open never leaves an unverified destination behind.
    ///
    /// # Errors
    /// Store failures mapped to [`CoreError`], plus handle registration
    /// failures.
    fn verify_fork_destination(
        &self,
        install: &ForkInstall<'_>,
    ) -> Result<ruk_core::change::StoreId, CoreError> {
        let dest = Store::open(
            install.destination_store,
            Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        let store_id = dest.store_id();
        dest.close()
            .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        drop(dest);
        let store_canonical = std::fs::canonicalize(install.destination_store)
            .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
        self.handle_for_path(&store_canonical)?;
        Ok(store_id)
    }
}

/// One fork install: the validated snapshot plus the staging container, the
/// staged store path inside it, and the link it installs through. The
/// staging store travels by value so the install drops it before the
/// rename: no staging-rooted handle survives the rename into the
/// destination.
struct ForkInstall<'a> {
    source: &'a Store,
    source_store: &'a Path,
    destination: &'a Path,
    destination_store: &'a Path,
    container: &'a Path,
    staging: &'a Path,
    link: &'a dyn Fn(&Path, &Path) -> std::io::Result<()>,
}

/// Publishes the pending tail batch into the staging store and records its
/// identities as committed, so later deltas may name them as bases.
///
/// # Errors
/// Publication failures mapped to [`CoreError`].
fn flush_fork_batch(
    staging: &Store,
    batch: &mut Vec<ruk_core::store::PreparedObject>,
    committed: &mut std::collections::HashSet<ruk_core::ids::Oid>,
    pending: &mut std::collections::HashSet<ruk_core::ids::Oid>,
) -> Result<(), CoreError> {
    if batch.is_empty() {
        return Ok(());
    }
    let publishing = std::mem::take(batch);
    staging
        .publish(
            publishing,
            &[],
            ruk_core::store::EventSource::Fork,
            &ruk_core::store::EventContext::default(),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
    committed.extend(pending.drain());
    Ok(())
}

/// Counts fork items for the reply without a truncating cast.
fn fork_count(items: usize) -> Result<u64, CoreError> {
    u64::try_from(items).map_err(|_| CoreError::new(ErrorCode::EIo, "fork count overflows u64"))
}

/// One fork source: the live coordinator's store when the repository is
/// open, or a short-lived directly opened store otherwise.
enum ForkSource {
    Live(Arc<HostedCoordinator>),
    Cold(Box<Store>),
}

impl ForkSource {
    /// The source store fork reads observe.
    fn store(&self) -> &Store {
        match self {
            Self::Live(coordinator) => coordinator.store(),
            Self::Cold(store) => store,
        }
    }
}

/// One fork snapshot's validated fact rows: the table, key, and value of
/// every copied row.
type ForkRows = Vec<(ruk_core::store::FactTable, Vec<u8>, Vec<u8>)>;

/// One validated fork snapshot: the forked generation, the partitioned
/// locator sets, the CAS-revalidated fact rows, and the ref filter they
/// were photographed under for revalidation after the tail copy.
struct ForkSnapshot {
    kind: ruk_core::ids::HashKind,
    generation: u64,
    sealed_manifests: Vec<ruk_core::store::SegmentManifest>,
    sealed: Vec<(ruk_core::ids::Oid, ruk_core::store::ObjectLocation)>,
    tail: Vec<(ruk_core::ids::Oid, ruk_core::store::ObjectLocation)>,
    rows: ForkRows,
    refs_copied: u64,
    mode: ruk_core::protocol::ForkRefs,
    default_branch: Vec<u8>,
}

/// Whether a fork byte-share linked or copied.
enum LinkOutcome {
    Linked,
    Copied,
}

/// Hardlinks one sealed segment or verified LFS payload, copying when the
/// link crosses devices. Only a cross-device link falls back to a copy;
/// every other link failure fails the fork closed.
///
/// The Unix cross-device errno is `EXDEV` (18): hard links never span
/// filesystems, so the copy keeps the same bytes under a fresh inode.
fn link_or_copy(
    link: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
    source: &Path,
    destination: &Path,
) -> std::io::Result<LinkOutcome> {
    match link(source, destination) {
        Ok(()) => Ok(LinkOutcome::Linked),
        Err(err) if is_cross_device(&err) => {
            std::fs::copy(source, destination).map(|_| LinkOutcome::Copied)?;
            Ok(LinkOutcome::Copied)
        }
        Err(err) => Err(err),
    }
}

/// Whether an I/O error names a cross-device link.
fn is_cross_device(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(18)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Links one verified complete LFS payload into staging: hardlinks (or
/// copies cross-device) the sidecar file, reporting whether the presence
/// row travels into the fork. Incomplete, undecodable, or unverified rows
/// never travel: the fork re-resolves them lazily.
///
/// # Errors
/// Staging and link I/O failures.
fn link_lfs_payload(
    install: &ForkInstall<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<bool, CoreError> {
    let Some(record) = ruk_core::store::lfs::decode_record(value) else {
        return Ok(false);
    };
    if !record.complete {
        return Ok(false);
    }
    let Ok(hex) = std::str::from_utf8(key) else {
        return Ok(false);
    };
    if !ruk_core::store::lfs::sidecar_verified(install.source_store, hex, record.size) {
        return Ok(false);
    }
    let Some(from) = ruk_core::store::lfs::sidecar_path(install.source_store, hex) else {
        return Ok(false);
    };
    let Some(to) = ruk_core::store::lfs::sidecar_path(install.staging, hex) else {
        return Ok(false);
    };
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("fork stages lfs payload {hex}: {err}"),
            )
        })?;
    }
    let outcome = link_or_copy(install.link, &from, &to).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("fork links lfs payload {hex}: {err}"),
        )
    })?;
    if matches!(outcome, LinkOutcome::Copied) {
        sync_copied_payload(&to, hex)?;
        let mut curr = to.parent();
        while let Some(parent) = curr {
            if parent == install.staging {
                fsync_dir(parent)?;
                break;
            }
            fsync_dir(parent)?;
            curr = parent.parent();
        }
    }
    Ok(true)
}

fn sync_copied_file(path: &Path, segment_id: u64) -> Result<(), CoreError> {
    let file = std::fs::File::open(path).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("fork cannot reopen copied segment {segment_id}: {err}"),
        )
    })?;
    file.sync_all().map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("fork cannot sync copied segment {segment_id}: {err}"),
        )
    })
}

fn sync_copied_payload(path: &Path, hex: &str) -> Result<(), CoreError> {
    let file = std::fs::File::open(path).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("fork cannot reopen copied lfs payload {hex}: {err}"),
        )
    })?;
    file.sync_all().map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("fork cannot sync copied lfs payload {hex}: {err}"),
        )
    })
}

fn sync_copied_dirs<F: Fn(u64) -> PathBuf>(ids: &[u64], path_fn: F) -> Result<(), CoreError> {
    let mut synced: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for id in ids {
        if let Some(parent) = path_fn(*id).parent() {
            let parent = parent.to_path_buf();
            if synced.insert(parent.clone()) {
                fsync_dir(&parent)?;
            }
        }
    }
    Ok(())
}

/// One fork staging sibling for `destination`: the file name plus a fresh
/// random uuid, so every attempt mints a fresh name and a leftover staging
/// directory never blocks a retry.
pub(crate) fn staging_sibling(destination: &Path) -> PathBuf {
    let file = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    destination.with_file_name(format!(
        "{file}.fork-{}",
        ruk_core::change::StoreId::generate()
    ))
}

/// Removes and returns the entry bound to `canonical`, if any.
fn take_entry_by_path(inner: &mut RegistryInner, canonical: &Path) -> Option<(String, RepoEntry)> {
    let handle = inner
        .entries
        .iter()
        .find(|(_, entry)| entry.path == canonical)
        .map(|(handle, _)| handle.clone())?;
    inner.entries.remove_entry(&handle)
}

/// One claimed push idempotency key: the wakeup its waiters sleep on
/// plus the halves outstanding against it. The lane half releases at
/// the invocation's end and the worker half when the send closure
/// returns; the key frees only once both halves drop, so a dropped
/// invocation cannot hand the key to a waiter while its orphaned
/// worker still sends.
struct InFlightPush {
    notify: Arc<tokio::sync::Notify>,
    holders: u32,
}

/// One push idempotency key's claim state: the first claimant owns the
/// send, and a concurrent duplicate waits for the owner's terminal
/// receipt instead of sending twice.
pub(crate) enum PushKeyClaim<'a> {
    /// This caller owns the send and releases the lane half on drop.
    Owner(PushKeyGuard<'a>),
    /// Another job owns the send; sleep on this wakeup, then replay.
    Wait(Arc<tokio::sync::Notify>),
}

/// One push's lane-half ownership of its idempotency key: dropping the
/// guard releases the lane half, and the key frees once the worker
/// half drops too, waking the waiters.
pub(crate) struct PushKeyGuard<'a> {
    registry: &'a Registry,
    session: SessionId,
    request: RequestId,
}

impl Drop for PushKeyGuard<'_> {
    fn drop(&mut self) {
        self.registry
            .release_push_request(self.session, self.request);
    }
}

/// One push's worker-half ownership of its idempotency key: the send
/// closure owns it, so the key survives a dropped invocation until
/// the orphaned worker finishes. `'static`, unlike the lane half.
pub(crate) struct PushKeyWorkerHalf {
    registry: Arc<Registry>,
    session: SessionId,
    request: RequestId,
}

impl Drop for PushKeyWorkerHalf {
    fn drop(&mut self) {
        self.registry
            .release_push_request(self.session, self.request);
    }
}

/// Returns the entry bound to `canonical`, if any.
fn entry_by_path_mut<'a>(
    inner: &'a mut RegistryInner,
    canonical: &Path,
) -> Option<&'a mut RepoEntry> {
    inner
        .entries
        .values_mut()
        .find(|entry| entry.path == canonical)
}

/// Whether a file name sits in the reserved tombstone namespace.
fn is_tombstone_name(name: &str) -> bool {
    name.starts_with(".tombstone-")
}

/// Names the tombstone a deleted repository renames to before removal.
///
/// Tombstones live in the reserved `.tombstone-` prefix namespace, which
/// [`Registry::create_repo`] rejects, so the startup sweep only removes
/// directories the daemon renamed and never a legitimately named
/// repository containing `.tombstone-` elsewhere in its name.
fn tombstone_for(canonical: &Path, nonce: u64) -> PathBuf {
    let name = canonical
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.is_empty() {
        canonical.with_file_name(format!(".tombstone-{nonce}"))
    } else {
        canonical.with_file_name(format!(".tombstone-{nonce}-{name}"))
    }
}

/// Whether a directory entry is a delete tombstone.
fn is_tombstone(entry: &std::fs::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy().into_owned();
    is_tombstone_name(&name) && entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
}

/// Persists one directory's entries.
fn fsync_dir(dir: &Path) -> Result<(), CoreError> {
    let file = std::fs::File::open(dir)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("directory is not open: {err}")))?;
    file.sync_all()
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("directory is not synced: {err}")))
}

impl Registry {
    /// Resolves a not-yet-existing destination beneath a configured root:
    /// the nearest existing ancestor is canonicalized and symlink
    /// components below it are refused (see `ruk_core::contained`).
    ///
    /// # Errors
    /// `E_NOT_FOUND` when no ancestor exists beneath a root, `E_FORBIDDEN`
    /// for symlink components or paths outside the roots, `E_IO` when the
    /// path is inaccessible.
    pub(crate) fn resolve_destination(&self, requested: &Path) -> Result<PathBuf, CoreError> {
        let mut refused: Option<CoreError> = None;
        for root in &self.roots {
            match ruk_core::contained::resolve_new_destination(root, requested) {
                Ok(destination) => return Ok(destination),
                Err(err) if err.code == ErrorCode::ENotFound => continue,
                Err(err) => {
                    refused = Some(err);
                }
            }
        }
        Err(refused
            .unwrap_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository path is unknown")))
    }

    /// Opens `repo_ref` by path or handle, returning its handle, path, and coordinator.
    ///
    /// A reference starting with `/` is an absolute repository path;
    /// anything else is an opaque handle from a previous open. The first
    /// open of a repository opens its store and spawns its lane runner;
    /// later opens share the one coordinator. Callers run this on the
    /// blocking pool: resolution canonicalizes paths, the store opens, and
    /// the registry lock is held throughout, none of which belongs on the
    /// async runtime.
    ///
    /// # Errors
    /// As for [`Registry::resolve`] for paths, `E_NOT_FOUND` for unknown
    /// handles, `E_FORBIDDEN` outside the configured roots, `E_HOSTED` when
    /// the daemon runtime is not bound yet.
    pub(crate) fn open(
        &self,
        repo_ref: &str,
    ) -> Result<(String, PathBuf, Arc<HostedCoordinator>), CoreError> {
        let (handle, pinned) = if repo_ref.starts_with('/') {
            let pinned = self.store_pinned(Path::new(repo_ref))?;
            let handle = self.handle_for_path(pinned.path())?;
            (handle, pinned)
        } else {
            let stored = self.open_by_handle(repo_ref)?;
            let pinned = self.store_pinned(&stored)?;
            (repo_ref.to_string(), pinned)
        };
        let path = pinned.path().to_path_buf();
        let coordinator = self.coordinator_for(&handle, pinned)?;
        Ok((handle, path, coordinator))
    }

    /// Returns the hosted coordinator of `handle`, opening it on first use.
    ///
    /// The store opens on the canonical path, the coordinator binds the
    /// repository owner's policy file, and the lane runner spawns once on
    /// the bound runtime. The registry lock is held throughout so two
    /// racing first opens cannot spawn two runners.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unknown handle, `E_HOSTED` when the daemon
    /// runtime is not bound yet, store and coordinator failures otherwise.
    fn coordinator_for(
        &self,
        handle: &str,
        pinned: ruk_core::contained::PinnedDir,
    ) -> Result<Arc<HostedCoordinator>, CoreError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?
            .clone()
            .ok_or_else(|| CoreError::new(ErrorCode::EHosted, "daemon runtime is not bound yet"))?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?;
        let canonical = pinned.path().to_path_buf();
        let reserved = inner.deleting.contains(&canonical)
            || inner
                .entries
                .get(handle)
                .is_none_or(|entry| entry.path != canonical);
        if reserved {
            return Err(CoreError::new(
                ErrorCode::EConflicted,
                "repository deletion or rename is in flight",
            ));
        }
        {
            let entry = inner.entries.get_mut(handle).ok_or_else(|| {
                CoreError::new(ErrorCode::ENotFound, "repository handle is unknown")
            })?;
            if let Some(coordinator) = entry.coordinator.as_ref() {
                entry.last_used = Instant::now();
                return Ok(Arc::clone(coordinator));
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let store = match pinned.open_path() {
            Some(proc_root) => Store::open_pinned(
                &proc_root,
                &canonical,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .map_err(|err| CoreError::new(err.code(), err.to_string()))?,
            None => Store::open(
                &canonical,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .map_err(|err| CoreError::new(err.code(), err.to_string()))?,
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let store = Store::open(
            &canonical,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        pinned.verify_open(&canonical)?;
        Self::restore_uncertain_pushes(&mut inner.uncertain_pushes, &canonical, &store)?;
        let owner = match pinned.owner_uid() {
            Some(uid) => Principal::from_peer_uid(uid),
            None => Self::repository_owner(&canonical)?,
        };
        let pool = SearchPool::new(SearchPoolConfig {
            permits: u32::try_from(self.search_pool_size.load(Ordering::Relaxed)).map_err(
                |_| CoreError::new(ErrorCode::EInvalid, "search pool size overflows u32"),
            )?,
        })?;
        let coordinator = Arc::new(
            HostedCoordinator::open(Arc::new(store), owner, canonical)?.with_search_pool(pool),
        );
        coordinator.set_search_max_scan_bytes(self.search_max_scan_bytes.load(Ordering::Relaxed));
        let runner = coordinator.spawn_on(&runtime)?;
        coordinator
            .set_event_retention_seconds(self.event_retention_seconds.load(Ordering::Relaxed));
        coordinator.set_compare_max_commits(self.compare_max_commits.load(Ordering::Relaxed));
        spawn_retention(&runtime, &coordinator, self.retention_interval_ms());
        let entry = inner
            .entries
            .get_mut(handle)
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository handle is unknown"))?;
        entry.coordinator = Some(Arc::clone(&coordinator));
        entry.runner = Some(runner);
        entry.last_used = Instant::now();
        Ok(coordinator)
    }

    /// Reads the retention sweep period in milliseconds.
    fn retention_interval_ms(&self) -> u64 {
        self.retention_interval_ms.load(Ordering::Relaxed)
    }

    /// Reads the owner principal of one canonical repository path.
    ///
    /// The coordinator policy source resolves its `owner` alias against
    /// this principal, so the on-disk owner of the repository root is the
    /// honest choice without new platform dependencies: in normal
    /// deployments the daemon user owns its roots, and explicit
    /// `policy.toml` files govern every other layout.
    ///
    /// # Errors
    /// `E_IO` when the path metadata is unreadable, `E_HOSTED` where no
    /// Unix owner identity exists.
    #[cfg(unix)]
    fn repository_owner(canonical: &Path) -> Result<Principal, CoreError> {
        use std::os::unix::fs::MetadataExt as _;
        let uid = std::fs::metadata(canonical)
            .map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("repository owner is not readable: {err}"),
                )
            })?
            .uid();
        Ok(Principal::from_peer_uid(uid))
    }

    /// Reads the owner principal of one canonical repository path.
    ///
    /// # Errors
    /// Always `E_HOSTED`: coordinator hosting needs a Unix owner identity.
    #[cfg(not(unix))]
    fn repository_owner(canonical: &Path) -> Result<Principal, CoreError> {
        let _ = canonical;
        Err(CoreError::new(
            ErrorCode::EHosted,
            "coordinator hosting needs a Unix owner identity",
        ))
    }

    /// Restores outstanding uncertain push guards from durable plan state.
    fn restore_uncertain_pushes(
        uncertain_pushes: &mut HashMap<(PathBuf, Vec<u8>), PlanId>,
        canonical: &Path,
        store: &Store,
    ) -> Result<(), CoreError> {
        let kind = store.hash_kind();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let budget = FactPageBudget::new(1024, MAX_CONTROL_FRAME_BYTES);
            let page = store
                .fact_page(FactTable::PushPlans, after.as_deref(), budget)
                .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
            for row in &page.rows {
                let raw_id = <[u8; 16]>::try_from(row.key.as_slice()).map_err(|_| {
                    CoreError::new(ErrorCode::ECorrupt, "stored push plan key is not 16 bytes")
                })?;
                let plan_id = PlanId::from_bytes(raw_id);
                let plan = PushPlanRecord::decode(plan_id, kind, &row.value).map_err(|err| {
                    CoreError::new(
                        ErrorCode::ECorrupt,
                        format!("stored push plan {plan_id} is corrupt: {err}"),
                    )
                })?;
                if matches!(plan.state, PushState::Uncertain | PushState::Sending) {
                    let marker_key = super::push_job::reconciliation_marker_key(plan.id);
                    let marker_row = store
                        .fact(FactTable::RemoteObservations, &marker_key)
                        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
                    let reconciled = match marker_row {
                        None => false,
                        Some(bytes) if bytes == [0x01] => true,
                        Some(_) => {
                            return Err(CoreError::new(
                                ErrorCode::ECorrupt,
                                format!(
                                    "stored reconciliation marker for plan {plan_id} is corrupt"
                                ),
                            ));
                        }
                    };
                    if !reconciled {
                        for update in &plan.updates {
                            let key = (canonical.to_path_buf(), update.name.clone());
                            uncertain_pushes.insert(key, plan.id);
                        }
                    }
                }
            }
            if !page.more || page.rows.is_empty() {
                break;
            }
            let Some(last) = page.rows.last() else {
                break;
            };
            after = Some(last.key.clone());
        }
        Ok(())
    }

    /// Opens `requested` by path, returning its opaque handle.
    ///
    /// # Errors
    /// As for [`Registry::resolve`].
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn open_by_path(&self, requested: &Path) -> Result<String, CoreError> {
        let canonical = self.resolve(requested)?;
        self.handle_for_path(&canonical)
    }

    /// Opens `handle`, returning its canonical repository path.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unknown handle, `E_FORBIDDEN` when the bound
    /// path no longer sits beneath a configured root.
    pub(crate) fn open_by_handle(&self, handle: &str) -> Result<PathBuf, CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?;
        let entry = inner
            .entries
            .get_mut(handle)
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository handle is unknown"))?;
        if !self.roots.iter().any(|root| entry.path.starts_with(root)) {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "repository handle escapes the configured roots",
            ));
        }
        let path = entry.path.clone();
        entry.last_used = Instant::now();
        let reserved = inner.deleting.contains(&path);
        if reserved {
            return Err(CoreError::new(
                ErrorCode::EConflicted,
                "repository deletion or rename is in flight",
            ));
        }
        Ok(path)
    }

    /// Returns the handle bound to `canonical`, registering it when new.
    ///
    /// # Errors
    /// `E_IO` when the registry lock is poisoned.
    fn handle_for_path(&self, canonical: &Path) -> Result<String, CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?;
        if inner.deleting.contains(canonical) {
            return Err(CoreError::new(
                ErrorCode::EConflicted,
                "repository deletion is in flight",
            ));
        }
        for (handle, entry) in inner.entries.iter_mut() {
            if entry.path == canonical {
                entry.last_used = Instant::now();
                return Ok(handle.clone());
            }
        }
        let handle = format!("repo-{}", self.next_handle.fetch_add(1, Ordering::Relaxed));
        inner.entries.insert(
            handle.clone(),
            RepoEntry {
                path: canonical.to_path_buf(),
                coordinator: None,
                runner: None,
                last_used: Instant::now(),
            },
        );
        Ok(handle)
    }

    /// Drops entries idle longer than `max_idle`, returning the count.
    ///
    /// An entry holding more than the registry's own coordinator reference
    /// still serves an invocation, so eviction keeps it. Retired
    /// coordinators shut down after the lock releases: the lane closes to
    /// new submissions and the runner drains.
    ///
    /// # Errors
    /// `E_IO` when the registry lock is poisoned.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn evict_idle(&self, max_idle: Duration) -> Result<usize, CoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))?;
        let before = inner.entries.len();
        let mut retired = Vec::new();
        inner.entries.retain(|_, entry| {
            if entry.last_used.elapsed() < max_idle {
                return true;
            }
            let busy = entry
                .coordinator
                .as_ref()
                .is_some_and(|coordinator| Arc::strong_count(coordinator) > 1);
            if busy {
                return true;
            }
            if let Some(coordinator) = entry.coordinator.take() {
                retired.push(coordinator);
            }
            false
        });
        let evicted = before - inner.entries.len();
        drop(inner);
        for coordinator in retired {
            coordinator.shutdown();
        }
        Ok(evicted)
    }

    /// Returns the count of registered handles.
    ///
    /// # Errors
    /// `E_IO` when the registry lock is poisoned.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn len(&self) -> Result<usize, CoreError> {
        self.inner
            .lock()
            .map(|inner| inner.entries.len())
            .map_err(|_| CoreError::new(ErrorCode::EIo, "repository registry lock is poisoned"))
    }

    /// True when no handle is registered.
    ///
    /// # Errors
    /// `E_IO` when the registry lock is poisoned.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn is_empty(&self) -> Result<bool, CoreError> {
        self.len().map(|len| len == 0)
    }
}

/// Spawns one periodic retention task for a freshly opened coordinator.
///
/// One task per coordinator means a slow repository stalls only its own
/// sweeps, never another repository's. The task holds only a [`Weak`]
/// handle: idle eviction drops the registry's `Arc`, in-flight invocations
/// drain, and the next tick finds the upgrade failed and exits — so sweeps
/// never pin a retired coordinator alive. The daemon runtime owns the task
/// itself, matching the spawned-connection pattern: leaving `serve_async`
/// drops the runtime and ends every sweep with it. Per-tick failures are
/// reported to stderr and never end the task.
fn spawn_retention(
    runtime: &tokio::runtime::Handle,
    coordinator: &Arc<HostedCoordinator>,
    interval_ms: u64,
) {
    use std::sync::Weak;
    if interval_ms == 0 {
        return;
    }
    let weak: Weak<HostedCoordinator> = Arc::downgrade(coordinator);
    let interval = Duration::from_millis(interval_ms);
    runtime.spawn(async move {
        let (_cancel_guard, cancel) = cancellation();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(coordinator) = weak.upgrade() else {
                break;
            };
            if let Err(err) = coordinator.retention_sweep(&cancel).await {
                eprintln!("ruk retention: sweep failed: {err}");
            }
        }
    });
}

impl Registry {
    /// Retires every hosted coordinator through `shutdown`: each lane
    /// closes to new submissions, in-flight and queued work drains, and
    /// each store handle flushes. Idempotent: shutting down twice retires
    /// nothing the second time beyond repeating the idempotent calls.
    pub(crate) fn shutdown_all(&self) {
        let retired: Vec<Arc<HostedCoordinator>> = self
            .inner
            .lock()
            .map(|inner| {
                inner
                    .entries
                    .values()
                    .filter_map(|entry| entry.coordinator.clone())
                    .collect()
            })
            .unwrap_or_default();
        for coordinator in retired {
            coordinator.shutdown();
        }
    }
}

impl Registry {
    /// Retires every coordinator and awaits each lane runner to completion.
    ///
    /// `shutdown_all` signals the drain; this waits for it, so no runner
    /// is still committing when the daemon runtime drops. Runner outcomes
    /// are already delivered per submission; join failures (a runtime
    /// tearing down around the wait) report nowhere new. Evicted entries
    /// keep no handle: their runners drain detached while the runtime
    /// lives, exactly as before.
    pub(crate) async fn shutdown_and_drain(&self) {
        self.shutdown_all();
        let runners: Vec<tokio::task::JoinHandle<Result<(), CoreError>>> = self
            .inner
            .lock()
            .map(|mut inner| {
                inner
                    .entries
                    .values_mut()
                    .filter_map(|entry| entry.runner.take())
                    .collect()
            })
            .unwrap_or_default();
        for runner in runners {
            let _ = runner.await;
        }
    }
}

impl Drop for Registry {
    /// Retires every hosted coordinator through `shutdown`.
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{PushKeyClaim, Registry};
    use std::io::Read;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ruk_core::ids::Oid;
    use ruk_core::protocol::{ForkRefs, RepoForkArgs};
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;
    use ruk_core::store::lfs;
    use ruk_core::store::{
        EventContext, EventSource, FactExpectation, FactMutation, FactPageBudget, FactTable,
        ObjectKind, PreparationBudget, Store,
    };

    static SIBLING: AtomicU64 = AtomicU64::new(1);

    fn scratch_root() -> std::path::PathBuf {
        let tag = SIBLING.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("ruk-daemon-registry-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(root.join("repo-a")).expect("scratch repository fits on disk");
        root
    }

    fn init_args(root: &std::path::Path, path: &str) -> ruk_core::protocol::RepoInitArgs {
        ruk_core::protocol::RepoInitArgs {
            root: root.to_str().expect("scratch root is UTF-8").to_owned(),
            path: path.to_owned(),
            object_format: None,
            default_branch: None,
        }
    }

    #[test]
    fn empty_roots_are_rejected() {
        assert!(Registry::new(Vec::new()).is_err());
    }

    #[test]
    fn create_repo_persists_default_branch_and_registers() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "acme/hello"))
            .expect("init creates");
        assert_eq!(
            created.path,
            canonical.join("acme/hello").to_str().expect("utf8 path")
        );
        assert_eq!(created.default_branch.as_bytes(), b"refs/heads/main");
        let store_id = created.store_id;
        let meta = ruk_core::store::Store::open(
            &canonical.join("acme/hello").join(".ruk"),
            std::sync::Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
        )
        .expect("created store opens")
        .repo_meta()
        .expect("repo meta reads")
        .expect("init persists repo meta");
        assert_eq!(meta.default_branch.as_bytes(), b"refs/heads/main");
        let again = registry.create_repo(&init_args(&root, "acme/hello"));
        let err = again.expect_err("duplicate init refuses");
        assert_eq!(err.code, ErrorCode::EInvalid);
        let custom = {
            let mut args = init_args(&root, "acme/custom");
            args.default_branch =
                Some(ruk_core::refdata::RefName::new("refs/heads/trunk").expect("branch name"));
            registry.create_repo(&args).expect("custom branch inits")
        };
        assert_eq!(custom.default_branch.as_bytes(), b"refs/heads/trunk");
        assert_ne!(custom.store_id, store_id);
    }

    #[test]
    fn remove_repo_refuses_in_flight_and_tombstones() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "gone"))
            .expect("init creates");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let (_handle, _path, held) = registry.open(&created.path).expect("open coordinates");
        let refused = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: created.path.clone(),
                confirm_path: created.path.clone(),
            })
            .expect_err("in-flight delete refuses");
        assert_eq!(refused.code, ErrorCode::EConflicted);
        drop(held);
        let deleted = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: created.path.clone(),
                confirm_path: created.path.clone(),
            })
            .expect("idle delete removes");
        assert_eq!(deleted.deleted_path, created.path);
        assert!(
            !canonical.join("gone").exists(),
            "repository directory is gone"
        );
        assert!(
            std::fs::read_dir(&canonical)
                .expect("root lists")
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tombstone-")),
            "no tombstone remains"
        );
        let missing = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: created.path.clone(),
                confirm_path: created.path.clone(),
            })
            .expect_err("missing delete refuses");
        assert_eq!(missing.code, ErrorCode::ENotFound);
        let mismatch = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: "acme/other".to_owned(),
                confirm_path: "acme/different".to_owned(),
            })
            .expect_err("confirmation mismatch refuses");
        assert_eq!(mismatch.code, ErrorCode::EInvalid);
    }

    #[test]
    fn rename_repo_moves_within_one_root() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "acme/old"))
            .expect("init creates");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let renamed = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: created.path.clone(),
                new_path: "acme/new".to_owned(),
            })
            .expect("rename moves");
        assert!(renamed.path.ends_with("acme/new"));
        assert_eq!(renamed.previous_path, created.path);
        assert!(
            !canonical.join("acme/old").exists(),
            "old repository path is gone"
        );
        assert!(
            std::path::Path::new(&renamed.path).exists(),
            "renamed repository exists"
        );
        let reopened = registry
            .open(&renamed.path)
            .expect("renamed repository opens");
        assert_ne!(reopened.0, "", "renamed repository keeps a handle");
        let store_id = reopened.2.store().store_id();
        assert_eq!(store_id, created.store_id, "store id survives rename");
        let clash = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: renamed.path.clone(),
                new_path: "acme/new".to_owned(),
            })
            .expect_err("existing destination refuses");
        assert_eq!(clash.code, ErrorCode::EInvalid);
    }

    #[test]
    fn rename_repo_refuses_other_roots() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let other =
            std::env::temp_dir().join(format!("ruk-daemon-registry-other-{}", std::process::id()));
        std::fs::create_dir_all(&other).expect("second root exists");
        let registry =
            Registry::new(vec![root.clone(), other.clone()]).expect("roots canonicalize");
        let created = registry
            .create_repo(&init_args(&root, "acme/old"))
            .expect("init creates");
        let err = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: created.path.clone(),
                new_path: other
                    .join("acme/new")
                    .to_str()
                    .expect("utf8 path")
                    .to_owned(),
            })
            .expect_err("cross-root rename refuses");
        assert_eq!(err.code, ErrorCode::EForbidden);
        std::fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn remove_repo_via_store_path_hits_busy_and_tombstones_entry() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "gone"))
            .expect("init creates");
        let store_path = canonical.join("gone").join(".ruk");
        assert!(store_path.is_dir(), "store exists before delete");
        let store_arg = store_path.to_str().expect("utf8 path").to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let (_handle, _path, held) = registry.open(&created.path).expect("open coordinates");
        let refused = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: store_arg.clone(),
                confirm_path: store_arg.clone(),
            })
            .expect_err("direct-store delete refuses while busy");
        assert_eq!(refused.code, ErrorCode::EConflicted);
        drop(held);
        let deleted = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: store_arg.clone(),
                confirm_path: store_arg.clone(),
            })
            .expect("idle direct-store delete removes");
        assert_eq!(deleted.deleted_path, created.path);
        assert!(!canonical.join("gone").exists(), "repository root is gone");
        assert!(
            !canonical.join("gone").join(".ruk").exists(),
            "no nested store survives"
        );
        assert!(
            std::fs::read_dir(&canonical)
                .expect("root lists")
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tombstone-")),
            "no tombstone remains"
        );
    }

    #[test]
    fn destructive_windows_are_exclusive_and_handle_opens_refuse() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        registry
            .create_repo(&init_args(&root, "acme/busy"))
            .expect("repo inits");
        let repo_root = root.join("acme/busy");
        let store = repo_root.join(".ruk");
        let handle = registry
            .open_by_path(&repo_root)
            .expect("open registers the repository");

        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.insert(repo_root.clone());
            inner.deleting.insert(store.clone());
        }
        let err = registry
            .open_by_handle(&handle)
            .expect_err("handle opens refuse during the window");
        assert_eq!(err.code, ruk_core::ErrorCode::EConflicted);

        let delete = ruk_core::protocol::RepoDeleteArgs {
            repo: repo_root.to_str().expect("utf8").to_string(),
            confirm_path: repo_root.to_str().expect("utf8").to_string(),
        };
        let err = registry
            .remove_repo(&delete)
            .expect_err("a second destructive op refuses the reserved window");
        assert_eq!(err.code, ruk_core::ErrorCode::EConflicted);

        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.remove(&repo_root);
            inner.deleting.remove(&store);
        }
    }

    #[test]
    fn open_refuses_source_while_rename_is_in_flight() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        registry
            .create_repo(&init_args(&root, "acme/moving"))
            .expect("repo inits");
        let repo_root = root.join("acme/moving");
        let store = repo_root.join(".ruk");

        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.insert(repo_root.clone());
            inner.deleting.insert(store.clone());
        }
        let err = registry
            .open_by_path(&repo_root)
            .expect_err("open of the rename source refuses");
        assert_eq!(err.code, ruk_core::ErrorCode::EConflicted);

        // The reservation clears when the rename resolves.
        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.remove(&repo_root);
            inner.deleting.remove(&store);
        }
        registry
            .open_by_path(&repo_root)
            .expect("open after the window resumes");
    }

    #[test]
    fn open_refuses_while_deletion_is_in_flight() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        registry
            .create_repo(&init_args(&root, "acme/racy"))
            .expect("repo inits");
        let repo_root = root.join("acme/racy");
        let store = repo_root.join(".ruk");

        // Simulate the delete window: entry taken, rename not yet run.
        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.insert(repo_root.clone());
            inner.deleting.insert(store.clone());
        }
        let err = registry
            .open_by_path(&repo_root)
            .expect_err("open during deletion refuses");
        assert_eq!(err.code, ruk_core::ErrorCode::EConflicted);

        // The reservation clears and the open succeeds again.
        {
            let mut inner = registry.inner.lock().expect("lock");
            inner.deleting.remove(&repo_root);
            inner.deleting.remove(&store);
        }
        registry
            .open_by_path(&repo_root)
            .expect("open after the window resumes");
    }

    #[test]
    fn remove_and_rename_refuse_namespace_dirs_and_roots() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        registry
            .create_repo(&init_args(&root, "acme/one"))
            .expect("first repo inits");
        registry
            .create_repo(&init_args(&root, "acme/two"))
            .expect("second repo inits");
        let namespace = canonical
            .join("acme")
            .to_str()
            .expect("utf8 path")
            .to_owned();
        let refused = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: namespace.clone(),
                confirm_path: namespace.clone(),
            })
            .expect_err("namespace delete refuses");
        assert_eq!(refused.code, ErrorCode::EInvalid);
        assert!(
            canonical.join("acme/one").join(".ruk").is_dir(),
            "first repo survives the refused delete"
        );
        assert!(
            canonical.join("acme/two").join(".ruk").is_dir(),
            "second repo survives the refused delete"
        );
        let rename_refused = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: namespace.clone(),
                new_path: "acme/renamed".to_owned(),
            })
            .expect_err("namespace rename refuses");
        assert_eq!(rename_refused.code, ErrorCode::EInvalid);
        assert!(
            !canonical.join("acme/renamed").exists(),
            "no rename destination appears"
        );
        let root_arg = canonical.to_str().expect("utf8 root").to_owned();
        let root_refused = registry
            .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                repo: root_arg.clone(),
                confirm_path: root_arg.clone(),
            })
            .expect_err("root delete refuses");
        assert_eq!(root_refused.code, ErrorCode::EForbidden);
        // A `.ruk` child directly under the root must not turn the root
        // into a deletion target: the derived repository root is still the
        // configured root itself.
        std::fs::create_dir_all(canonical.join(".ruk")).expect("root store dir stages");
        let dotted = canonical
            .join(".ruk")
            .to_str()
            .expect("utf8 path")
            .to_owned();
        for spelling in [&root_arg, &dotted] {
            let err = registry
                .remove_repo(&ruk_core::protocol::RepoDeleteArgs {
                    repo: spelling.to_string(),
                    confirm_path: spelling.to_string(),
                })
                .expect_err("root with a .ruk child still refuses");
            assert_eq!(err.code, ErrorCode::EForbidden);
        }
        assert!(
            canonical.join("acme/one").join(".ruk").is_dir(),
            "first repo survives the refused root delete"
        );
    }

    #[test]
    fn rename_repo_via_store_path_hits_busy_and_moves_root() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "acme/old"))
            .expect("init creates");
        let idle = registry
            .create_repo(&init_args(&root, "acme/old2"))
            .expect("second repo inits");
        let store_arg = canonical
            .join("acme/old")
            .join(".ruk")
            .to_str()
            .expect("utf8 path")
            .to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let (_handle, _path, held) = registry.open(&created.path).expect("open coordinates");
        let refused = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: store_arg.clone(),
                new_path: "acme/new".to_owned(),
            })
            .expect_err("direct-store rename refuses while busy");
        assert_eq!(refused.code, ErrorCode::EConflicted);
        drop(held);
        let idle_store = canonical
            .join("acme/old2")
            .join(".ruk")
            .to_str()
            .expect("utf8 path")
            .to_owned();
        let renamed = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: idle_store,
                new_path: "acme/new2".to_owned(),
            })
            .expect("idle direct-store rename moves");
        assert!(renamed.path.ends_with("acme/new2"));
        assert_eq!(renamed.previous_path, idle.path);
        assert!(!canonical.join("acme/old2").exists(), "old root is gone");
        assert!(
            !canonical.join("acme/old2").join(".ruk").exists(),
            "no nested store survives"
        );
        assert!(canonical.join("acme/new2").join(".ruk").is_dir());
        let reopened = registry.open(&renamed.path).expect("renamed opens");
        assert_eq!(reopened.2.store().store_id(), idle.store_id);
    }

    #[test]
    fn startup_sweep_removes_tombstones() {
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        std::fs::create_dir_all(canonical.join(".tombstone-7-dead")).expect("tombstone stages");
        Registry::new(vec![root.clone()]).expect("startup sweeps tombstones");
        assert!(
            !canonical.join(".tombstone-7-dead").exists(),
            "tombstone is swept at startup"
        );
    }

    #[test]
    fn repo_named_with_tombstone_substring_survives_restart() {
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "customer.tombstone-backup"))
            .expect("tombstone-substring name inits");
        assert!(
            canonical
                .join("customer.tombstone-backup")
                .join(".ruk")
                .is_dir()
        );
        drop(registry);
        Registry::new(vec![root.clone()]).expect("restart sweeps");
        assert!(
            canonical
                .join("customer.tombstone-backup")
                .join(".ruk")
                .is_dir(),
            "legitimately named repo survives restart"
        );
        assert_eq!(
            created.path,
            canonical
                .join("customer.tombstone-backup")
                .to_str()
                .expect("utf8")
        );
    }

    #[test]
    fn reserved_tombstone_prefix_is_rejected() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let err = registry
            .create_repo(&init_args(&root, ".tombstone-1-evil"))
            .expect_err("reserved prefix refuses");
        assert_eq!(err.code, ErrorCode::EInvalid);
        let created = registry
            .create_repo(&init_args(&root, "acme/old"))
            .expect("init creates");
        let clash = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: created.path.clone(),
                new_path: ".tombstone-2-new".to_owned(),
            })
            .expect_err("reserved rename destination refuses");
        assert_eq!(clash.code, ErrorCode::EInvalid);
    }

    #[test]
    fn repo_fork_refuses_tombstone_destination() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/hello");
        for dest in [
            root.join(".tombstone-1-evil"),
            root.join("acme/.tombstone-2-evil"),
        ] {
            let err = registry
                .fork_repo(&fork_args(&seed.canonical, &dest, None))
                .expect_err("tombstone destination refuses");
            assert_eq!(err.code, ErrorCode::EInvalid);
            assert!(!dest.exists(), "no staging survives the refused fork");
        }
    }

    #[test]
    fn repo_rename_restores_binding_when_the_move_fails() {
        use ruk_core::error::ErrorCode;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let created = registry
            .create_repo(&init_args(&root, "acme/hello"))
            .expect("repo inits");
        // A destination beneath a missing parent resolves but cannot
        // move: the error below proves the failure reaches the rename.
        let err = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: created.path.clone(),
                new_path: "missing-parent/new-name".to_owned(),
            })
            .expect_err("rename to a missing parent fails");
        assert_eq!(err.code, ErrorCode::EIo);
        let reopened = registry
            .open(&created.path)
            .expect("the old handle still resolves");
        assert!(
            reopened.1.ends_with("acme/hello/.ruk"),
            "the old handle still resolves: {}",
            reopened.1.display()
        );
        drop(reopened);
        let moved = registry
            .rename_repo(&ruk_core::protocol::RepoRenameArgs {
                repo: created.path.clone(),
                new_path: "acme/world".to_owned(),
            })
            .expect("a later rename still moves");
        assert!(moved.path.ends_with("acme/world"));
    }

    #[tokio::test]
    async fn push_key_claim_coalesces_duplicates() {
        use ruk_core::change::{RequestId, SessionId};
        let root = scratch_root();
        let registry = Arc::new(Registry::new(vec![root]).expect("scratch root canonicalizes"));
        let session = SessionId::generate();
        let request = RequestId::generate();
        let guard = match registry
            .claim_push_request(session, request)
            .expect("first claimant owns the key")
        {
            PushKeyClaim::Owner(guard) => guard,
            PushKeyClaim::Wait(_) => panic!("first claimant must not wait"),
        };
        let notify = match registry
            .claim_push_request(session, request)
            .expect("duplicate claim resolves")
        {
            PushKeyClaim::Wait(notify) => notify,
            PushKeyClaim::Owner(_) => panic!("duplicate must wait for the owner"),
        };
        // An unrelated key stays free while the first is held.
        assert!(matches!(
            registry
                .claim_push_request(session, RequestId::generate())
                .expect("other key resolves"),
            PushKeyClaim::Owner(_)
        ));
        // The worker half pins the key past the lane half's drop: no
        // wakeup fires until the send closure returns too.
        let worker = registry
            .add_push_holder(session, request)
            .expect("worker half splits");
        drop(guard);
        tokio::time::timeout(Duration::from_millis(100), notify.notified())
            .await
            .expect_err("lane-half drop alone wakes nobody");
        // The waiter future predates the release: `notify_waiters`
        // stores no permit, so creating it afterwards would miss the
        // wakeup the production path avoids with its claim re-check.
        let wake = notify.notified();
        drop(worker);
        tokio::time::timeout(Duration::from_secs(5), wake)
            .await
            .expect("release wakes the waiter");
        assert!(matches!(
            registry
                .claim_push_request(session, request)
                .expect("released key resolves"),
            PushKeyClaim::Owner(_)
        ));
    }

    #[test]
    fn missing_root_is_rejected() {
        let missing =
            std::env::temp_dir().join(format!("ruk-daemon-missing-{}", std::process::id()));
        assert!(Registry::new(vec![missing]).is_err());
    }

    #[test]
    fn paths_outside_roots_are_forbidden() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let outside = std::env::temp_dir();
        assert_ne!(
            std::fs::canonicalize(&outside).expect("temp dir exists"),
            std::fs::canonicalize(&root).expect("scratch root exists")
        );
        let denied = registry.resolve(&outside);
        assert!(denied.is_err());
        assert!(registry.open_by_path(&outside).is_err());
    }

    #[test]
    fn dotdot_escape_is_forbidden() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let escape = root.join("repo-a").join("..").join("..");
        assert!(registry.resolve(&escape).is_err());
    }

    #[test]
    fn missing_path_is_not_found() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let missing = root.join("no-such-repo");
        assert!(registry.resolve(&missing).is_err());
    }

    #[test]
    fn open_by_path_is_stable() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let first = registry
            .open_by_path(&root.join("repo-a"))
            .expect("inside path opens");
        let second = registry
            .open_by_path(&root.join("repo-a"))
            .expect("repeat open reuses the handle");
        assert_eq!(first, second);
        let path = registry
            .open_by_handle(&first)
            .expect("known handle resolves");
        assert_eq!(
            path,
            std::fs::canonicalize(root.join("repo-a")).expect("scratch repo exists")
        );
        assert!(registry.open_by_handle("repo-unknown").is_err());
        assert!(registry.open("repo-unknown").is_err());
        assert_eq!(registry.len().expect("registry lock holds"), 1);
        assert!(!registry.is_empty().expect("registry lock holds"));
    }

    #[test]
    fn open_shares_one_coordinator_and_evicts_it_idle() {
        use ruk_core::HashKind;
        use ruk_core::store::{PreparationBudget, Store};
        use std::sync::Arc;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        Store::create(
            &root.join("repo-a"),
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("scratch store initializes");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let path = root.join("repo-a");
        let handle = registry.open_by_path(&path).expect("inside path opens");
        let (first, _, first_coord) = registry.open(&handle).expect("first open coordinates");
        assert_eq!(first, handle);
        let (second, resolved, second_coord) = registry
            .open(path.to_str().expect("scratch path is UTF-8"))
            .expect("path open reuses the coordinator");
        assert_eq!(second, handle);
        assert_eq!(
            resolved,
            std::fs::canonicalize(&path).expect("scratch repo exists")
        );
        assert!(Arc::ptr_eq(&first_coord, &second_coord));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            registry
                .evict_idle(Duration::from_millis(1))
                .expect("registry lock holds"),
            0
        );
        drop(first_coord);
        drop(second_coord);
        assert_eq!(
            registry
                .evict_idle(Duration::from_millis(1))
                .expect("registry lock holds"),
            1
        );
        assert!(registry.is_empty().expect("registry lock holds"));
    }

    #[test]
    fn shutdown_all_retires_coordinators() {
        use ruk_core::HashKind;
        use ruk_core::coord::cancellation;
        use ruk_core::error::ErrorCode;
        use ruk_core::store::{PreparationBudget, Store};
        use std::sync::Arc;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        Store::create(
            &root.join("repo-a"),
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("scratch store initializes");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let handle = registry
            .open_by_path(&root.join("repo-a"))
            .expect("inside path opens");
        let (_, _, coordinator) = registry.open(&handle).expect("open coordinates");
        let (_guard, cancel) = cancellation();
        runtime
            .block_on(coordinator.retention_sweep(&cancel))
            .expect("sweep serves before shutdown");
        registry.shutdown_all();
        let refused = runtime
            .block_on(coordinator.retention_sweep(&cancel))
            .expect_err("sweep after shutdown is refused");
        assert_eq!(refused.code, ErrorCode::ECancelled);
        drop(coordinator);
        registry.shutdown_all();
    }

    #[test]
    fn shutdown_and_drain_awaits_runner_completion() {
        use ruk_core::HashKind;
        use ruk_core::coord::cancellation;
        use ruk_core::error::ErrorCode;
        use ruk_core::store::{PreparationBudget, Store};
        use std::sync::Arc;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        Store::create(
            &root.join("repo-a"),
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("scratch store initializes");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());
        let handle = registry
            .open_by_path(&root.join("repo-a"))
            .expect("inside path opens");
        let (_, _, coordinator) = registry.open(&handle).expect("open coordinates");
        let (_guard, cancel) = cancellation();
        // Awaiting the drain returns: the runner exited instead of
        // hanging, and a second call finds no handles left.
        runtime.block_on(registry.shutdown_and_drain());
        runtime.block_on(registry.shutdown_and_drain());
        let refused = runtime
            .block_on(coordinator.retention_sweep(&cancel))
            .expect_err("sweep after drained shutdown is refused");
        assert_eq!(refused.code, ErrorCode::ECancelled);
    }

    #[test]
    fn retention_interval_defaults_and_disables() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        assert_eq!(
            registry.retention_interval_ms(),
            super::super::DEFAULT_RETENTION_INTERVAL_MS
        );
        registry.set_retention_interval(Duration::from_millis(250));
        assert_eq!(registry.retention_interval_ms(), 250);
        registry.set_retention_interval(Duration::ZERO);
        assert_eq!(registry.retention_interval_ms(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_components_are_refused() {
        use std::os::unix::fs::symlink;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let target = root.join("repo-a");
        let link = root.join("link");
        symlink(&target, &link).expect("scratch symlink fits on disk");
        assert!(
            registry.resolve(&link).is_err(),
            "a symlink resolves inside yet is refused"
        );
        assert!(
            registry.resolve(&link.join("..").join("repo-a")).is_ok(),
            "lexical dotdot collapses before containment"
        );
        let outside = std::env::temp_dir().join(format!(
            "ruk-daemon-registry-outside-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&outside).expect("outside dir fits on disk");
        let evil = root.join("evil");
        symlink(&outside, &evil).expect("scratch symlink fits on disk");
        assert!(registry.resolve(&evil).is_err());
        assert!(registry.resolve(&evil.join("x")).is_err());
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn dotdot_spellings_stay_contained() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let sub = root.join("repo-a").join("sub");
        std::fs::create_dir_all(&sub).expect("scratch subdir fits on disk");
        let resolved = registry
            .resolve(&sub.join("..").join("."))
            .expect("dotdot spelling resolves");
        assert_eq!(
            resolved,
            std::fs::canonicalize(root.join("repo-a")).expect("scratch repo exists")
        );
    }

    /// A rename swap races resolve, open, and segment reads: the victim
    /// directory alternates between the real store and a symlink to an
    /// outside store. Every successful open must serve the inside store
    /// id, and every segment read through it must return the inside
    /// bytes: the recorded path may name the shadow after the pin, but
    /// no store file access travels it. The loop asserts at least one
    /// successful open so the test cannot pass vacuously.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn symlink_swap_never_resolves_outside() {
        use ruk_core::ids::{HashKind, Oid};
        use ruk_core::store::types::ObjectKind;
        use ruk_core::store::{EventContext, EventSource, PreparationBudget, Store};
        use std::io::Read as _;
        use std::os::unix::fs::symlink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let root = scratch_root();
        let stashed = root.join("stashed");
        let shadow = root.join("shadow");
        let victim = root.join("victim");
        for dir in [&victim, &shadow] {
            std::fs::create_dir_all(dir.join(".ruk")).expect("scratch dir fits on disk");
        }
        let budget = || Arc::new(PreparationBudget::reference_defaults());
        let sentinel: &[u8] = b"inside payload that the shadow never holds";
        let (inside, oid): (ruk_core::change::StoreId, Oid) = {
            let store = Store::create(&victim.join(".ruk"), HashKind::Sha1, budget())
                .expect("inside store creates");
            let prepared = store
                .prepare(
                    ObjectKind::Blob,
                    sentinel.len() as u64,
                    std::io::Cursor::new(sentinel.to_vec()),
                    None,
                )
                .expect("sentinel prepares");
            let oid = prepared.oid();
            store
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("sentinel publishes");
            (store.store_id(), oid)
        };
        Store::create(&shadow.join(".ruk"), HashKind::Sha1, budget())
            .expect("outside store creates");
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let victim = victim.clone();
            let stashed = stashed.clone();
            let shadow = shadow.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut to_live = false;
                while !stop.load(Ordering::Relaxed) {
                    if to_live {
                        let _ = std::fs::remove_file(&victim);
                        let _ = std::fs::rename(&stashed, &victim);
                    } else {
                        let _ = std::fs::rename(&victim, &stashed);
                        let _ = symlink(&shadow, &victim);
                    }
                    to_live = !to_live;
                }
            })
        };
        let registry = Registry::new(vec![root.clone()]).expect("scratch root registers");
        let target = victim.join(".ruk");
        // Attempt-bounded, not fixed-count: under suite load opens are
        // slower and flips land mid-open more often, so a fixed 200
        // iterations can observe zero successes without any regression.
        let mut oks = 0u32;
        let mut attempts = 0u32;
        while oks < 25 && attempts < 5000 {
            attempts += 1;
            let pinned = match registry.resolve_pinned(&target) {
                Ok(pinned) => pinned,
                Err(_) => continue,
            };
            let Some(proc_root) = pinned.open_path() else {
                continue;
            };
            let store = match Store::open_pinned(&proc_root, pinned.path(), budget()) {
                Ok(store) => store,
                Err(_) => continue,
            };
            if pinned.verify_open(pinned.path()).is_err() {
                continue;
            }
            oks += 1;
            assert_eq!(
                store.store_id(),
                inside,
                "an open through the swap never serves the outside store"
            );
            // Smoke-read the sentinel through the swap. Recovery warms
            // the segment cache at open, so post-open reads rarely
            // re-open here; the forced post-open swap in
            // `store_open_pins_later_segment_access` is the read-path
            // guard, and the unit tests pin the helpers.
            let mut spool = store
                .read(oid)
                .expect("a segment read through the swap serves the pinned store")
                .bytes;
            let mut got = Vec::new();
            spool.read_to_end(&mut got).expect("sentinel bytes read");
            assert_eq!(
                got, sentinel,
                "a segment read through the swap never serves outside bytes"
            );
        }
        assert!(oks > 0, "the race exercised at least one open");
        stop.store(true, Ordering::Relaxed);
        worker.join().expect("swapper thread joins");
    }

    /// A swap after `Store::open` cannot redirect later segment access:
    /// with the victim directory renamed aside and replaced by a symlink
    /// to an outside store, reads still serve the pinned bytes and writes
    /// still land in the pinned directory.
    #[test]
    #[cfg(unix)]
    fn store_open_pins_later_segment_access() {
        use ruk_core::ids::HashKind;
        use ruk_core::store::types::ObjectKind;
        use ruk_core::store::{EventContext, EventSource, PreparationBudget, Store};
        use std::io::Read as _;
        use std::sync::Arc;
        let root = scratch_root();
        let victim = root.join("victim");
        let stashed = root.join("stashed");
        let shadow = root.join("shadow");
        for dir in [&victim, &shadow] {
            std::fs::create_dir_all(dir.join(".ruk")).expect("scratch dir fits on disk");
        }
        let budget = || Arc::new(PreparationBudget::reference_defaults());
        let publish = |store: &Store, bytes: &[u8]| {
            let prepared = store
                .prepare(
                    ObjectKind::Blob,
                    bytes.len() as u64,
                    std::io::Cursor::new(bytes.to_vec()),
                    None,
                )
                .expect("blob prepares");
            let oid = prepared.oid();
            store
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("blob publishes");
            oid
        };
        let read_bytes = |store: &Store, oid: ruk_core::ids::Oid| {
            let mut spool = store.read(oid).expect("pinned read serves bytes").bytes;
            let mut got = Vec::new();
            spool.read_to_end(&mut got).expect("bytes read");
            got
        };
        let first: &[u8] = b"first payload";
        let second: &[u8] = b"second payload after the swap";
        Store::create(&shadow.join(".ruk"), HashKind::Sha1, budget())
            .expect("outside store creates");
        let first_oid = {
            let store = Store::create(&victim.join(".ruk"), HashKind::Sha1, budget())
                .expect("inside store creates");
            publish(&store, first)
        };
        let store = Store::open(&victim.join(".ruk"), budget()).expect("reopen store");
        std::fs::rename(&victim, &stashed).expect("move victim aside");
        std::os::unix::fs::symlink(&shadow, &victim).expect("swap victim link");
        assert_eq!(
            read_bytes(&store, first_oid),
            first,
            "a read after the swap serves the pinned bytes"
        );
        let second_oid = publish(&store, second);
        assert_eq!(
            read_bytes(&store, second_oid),
            second,
            "a write after the swap lands in the pinned directory"
        );
        drop(store);
        std::fs::remove_file(&victim).expect("remove victim link");
        std::fs::rename(&stashed, &victim).expect("restore victim");
        let reopened = Store::open(&victim.join(".ruk"), budget()).expect("reopen restored");
        assert_eq!(read_bytes(&reopened, first_oid), first);
        assert_eq!(
            read_bytes(&reopened, second_oid),
            second,
            "the swapped write survived in the real directory"
        );
    }

    #[test]
    fn destination_beneath_missing_dirs_resolves() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let fresh = root.join("repo-a").join("new-child");
        let resolved = registry
            .resolve_destination(&fresh)
            .expect("missing leaf resolves through its ancestor");
        assert_eq!(
            resolved,
            std::fs::canonicalize(root.join("repo-a"))
                .expect("scratch repo exists")
                .join("new-child")
        );
        assert!(registry.resolve(&fresh).is_err());
    }

    #[test]
    fn store_pinned_descends_into_a_repository_named_dot_ruk() {
        let root = scratch_root();
        let canonical = std::fs::canonicalize(&root).expect("scratch root exists");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let created = registry
            .create_repo(&init_args(&root, "team/.ruk"))
            .expect("init creates a repository named .ruk");
        let pinned = registry
            .store_pinned(std::path::Path::new(&created.path))
            .expect("repository root resolves to its store");
        assert_eq!(
            pinned.path(),
            canonical.join("team/.ruk/.ruk").as_path(),
            "the .ruk store inside the repository wins"
        );
        let direct = registry
            .store_pinned(&canonical.join("team/.ruk/.ruk"))
            .expect("a store path resolves to itself");
        assert_eq!(direct.path(), pinned.path());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn destination_across_symlink_is_refused() {
        use std::os::unix::fs::symlink;
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let link = root.join("link");
        symlink(root.join("repo-a"), &link).expect("scratch symlink fits on disk");
        assert!(
            registry
                .resolve_destination(&link.join("new-child"))
                .is_err()
        );
    }

    #[test]
    fn idle_entries_evict() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        registry
            .open_by_path(&root.join("repo-a"))
            .expect("inside path opens");
        assert_eq!(registry.len().expect("registry lock holds"), 1);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            registry
                .evict_idle(Duration::from_millis(1))
                .expect("registry lock holds"),
            1
        );
        assert!(registry.is_empty().expect("registry lock holds"));
    }

    /// One seeded fork source: two blobs, three refs, one verified plus
    /// one known-absent LFS payload, and planted freeze, attestation, and
    /// claim rows that a fork must leave behind.
    struct ForkSeed {
        canonical: std::path::PathBuf,
        store_id: ruk_core::change::StoreId,
        blob_a: Oid,
        blob_b: Oid,
        main_raw: Vec<u8>,
        tag_raw: Vec<u8>,
        feature_raw: Vec<u8>,
        generation: u64,
    }

    fn seed_fork_source(registry: &Registry, root: &Path, path: &str) -> ForkSeed {
        use ruk_core::store::lfs::LfsObjectRecord;
        let created = registry
            .create_repo(&init_args(root, path))
            .expect("seed source creates");
        let canonical = std::path::PathBuf::from(&created.path);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::open(&canonical.join(".ruk"), budget).expect("seed store opens");
        let prepared_a = store
            .prepare(ObjectKind::Blob, 10, &b"hello fork"[..], None)
            .expect("blob prepares");
        let blob_a = prepared_a.oid();
        let prepared_b = store
            .prepare(ObjectKind::Blob, 18, &b"second fork object"[..], None)
            .expect("blob prepares");
        let blob_b = prepared_b.oid();
        store
            .publish(
                vec![prepared_a, prepared_b],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("blobs publish");
        let updates = vec![
            RefUpdate {
                name: RefName::new("refs/heads/main").expect("branch name"),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(blob_a)),
            },
            RefUpdate {
                name: RefName::new("refs/heads/feature").expect("branch name"),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(blob_b)),
            },
            RefUpdate {
                name: RefName::new("refs/tags/v1").expect("tag name"),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(blob_a)),
            },
        ];
        let transaction = RefTransaction::new(store.hash_kind(), updates).expect("ref transaction");
        let prepared = prepare_checked_transaction(&store, &transaction).expect("refs prepare");
        store
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("refs publish");
        let main_raw = store
            .fact(FactTable::Refs, b"refs/heads/main")
            .expect("ref reads")
            .expect("main stored");
        let tag_raw = store
            .fact(FactTable::Refs, b"refs/tags/v1")
            .expect("ref reads")
            .expect("tag stored");
        let feature_raw = store
            .fact(FactTable::Refs, b"refs/heads/feature")
            .expect("ref reads")
            .expect("branch stored");
        store
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::ReleasedTags,
                        key: b"refs/tags/v1".to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(b"frozen".to_vec()),
                    },
                    FactMutation {
                        table: FactTable::Attestations,
                        key: b"planted-attestation".to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(b"attested".to_vec()),
                    },
                    FactMutation {
                        table: FactTable::Claims,
                        key: b"planted-claim".to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(b"claimed".to_vec()),
                    },
                ],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("liveness plants");
        let lfs_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sidecar =
            lfs::sidecar_path(&canonical.join(".ruk"), lfs_hex).expect("lfs path resolves");
        std::fs::create_dir_all(sidecar.parent().expect("sidecar has a parent"))
            .expect("lfs dirs create");
        std::fs::write(&sidecar, b"").expect("empty payload stages");
        assert!(lfs::sidecar_verified(&canonical.join(".ruk"), lfs_hex, 0));
        let absent_hex = "ab".repeat(32);
        store
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::LfsObjects,
                        key: lfs::record_key(lfs_hex),
                        expected: FactExpectation::Absent,
                        value: Some(lfs::encode_record(&LfsObjectRecord {
                            size: 0,
                            complete: true,
                        })),
                    },
                    FactMutation {
                        table: FactTable::LfsObjects,
                        key: lfs::record_key(absent_hex.as_str()),
                        expected: FactExpectation::Absent,
                        value: Some(lfs::encode_record(&LfsObjectRecord {
                            size: 7,
                            complete: false,
                        })),
                    },
                ],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("lfs rows publish");
        let seed = ForkSeed {
            canonical,
            store_id: store.store_id(),
            blob_a,
            blob_b,
            main_raw,
            tag_raw,
            feature_raw,
            generation: store.generation().expect("generation reads"),
        };
        drop(store);
        seed
    }

    fn fork_args(source: &Path, dest: &Path, refs: Option<ForkRefs>) -> RepoForkArgs {
        RepoForkArgs {
            source: source.to_str().expect("utf8 source").to_owned(),
            path: dest.to_str().expect("utf8 dest").to_owned(),
            refs,
        }
    }

    fn read_blob(store: &Store, oid: Oid) -> Vec<u8> {
        let mut read = store.read(oid).expect("object reads");
        let mut bytes = Vec::new();
        read.bytes.read_to_end(&mut bytes).expect("object decodes");
        bytes
    }

    #[test]
    fn repo_fork_stages_when_the_destination_parent_is_absent() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/hello");
        let dest = root.join("fresh-owner/nested/fork");
        let reply = registry
            .fork_repo(&fork_args(&seed.canonical, &dest, None))
            .expect("fork stages without the parent directory");
        assert!(reply.refs_copied >= 1);
        assert!(dest.join(".ruk").join("format").exists());
    }

    #[test]
    fn repo_fork_copies_all_heads_and_tags() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/hello");
        let dest = root.join("acme/fork");
        let reply = registry
            .fork_repo(&fork_args(&seed.canonical, &dest, None))
            .expect("fork serves");
        assert_eq!(reply.source_generation, seed.generation);
        assert!(reply.generation >= reply.source_generation);
        assert_eq!(reply.objects, reply.sealed_objects + reply.tail_objects);
        assert_eq!(reply.sealed_objects, 0);
        assert_eq!(reply.tail_objects, 2);
        assert_eq!(reply.refs_copied, 3);
        assert_ne!(reply.store_id, seed.store_id);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let forked = Store::open(&dest.join(".ruk"), budget).expect("fork opens");
        assert_eq!(
            forked
                .default_branch()
                .expect("meta reads")
                .expect("meta present")
                .as_bytes(),
            b"refs/heads/main"
        );
        for (key, want) in [
            ("refs/heads/main".as_bytes(), &seed.main_raw),
            ("refs/tags/v1".as_bytes(), &seed.tag_raw),
            ("refs/heads/feature".as_bytes(), &seed.feature_raw),
        ] {
            assert_eq!(
                &forked
                    .fact(FactTable::Refs, key)
                    .expect("ref reads")
                    .expect("ref present"),
                want
            );
        }
        assert_eq!(read_blob(&forked, seed.blob_a), b"hello fork");
        assert_eq!(read_blob(&forked, seed.blob_b), b"second fork object");
        for table in [
            FactTable::ReleasedTags,
            FactTable::Attestations,
            FactTable::Claims,
        ] {
            let page = forked
                .fact_page(table, None, FactPageBudget::new(16, 65536))
                .expect("table pages");
            assert!(page.rows.is_empty());
        }
        let lfs_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sidecar =
            lfs::sidecar_path(&dest.join(".ruk"), lfs_hex).expect("forked sidecar resolves");
        assert_eq!(
            std::fs::read(&sidecar).expect("payload links"),
            b"",
            "verified payload hardlinks"
        );
        assert!(
            forked
                .fact(
                    FactTable::LfsObjects,
                    &lfs::record_key("ab".repeat(32).as_str())
                )
                .expect("lfs reads")
                .is_none(),
            "known-absent payloads stay behind"
        );
        drop(forked);
        let tags_dest = root.join("acme/fork-tags");
        let tags_reply = registry
            .fork_repo(&fork_args(
                &seed.canonical,
                &tags_dest,
                Some(ForkRefs::DefaultAndTags),
            ))
            .expect("filtered fork serves");
        assert_eq!(tags_reply.refs_copied, 2);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let tags_only = Store::open(&tags_dest.join(".ruk"), budget).expect("filtered fork opens");
        assert!(
            tags_only
                .fact(FactTable::Refs, b"refs/heads/main")
                .expect("ref reads")
                .is_some()
        );
        assert!(
            tags_only
                .fact(FactTable::Refs, b"refs/tags/v1")
                .expect("ref reads")
                .is_some()
        );
        assert!(
            tags_only
                .fact(FactTable::Refs, b"refs/heads/feature")
                .expect("ref reads")
                .is_none()
        );
        drop(tags_only);
        let none_dest = root.join("acme/fork-none");
        let none_reply = registry
            .fork_repo(&fork_args(
                &seed.canonical,
                &none_dest,
                Some(ForkRefs::None),
            ))
            .expect("ref-free fork serves");
        assert_eq!(none_reply.refs_copied, 0);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let ref_free = Store::open(&none_dest.join(".ruk"), budget).expect("ref-free fork opens");
        let page = ref_free
            .fact_page(FactTable::Refs, None, FactPageBudget::new(16, 65536))
            .expect("refs page");
        assert!(page.rows.is_empty());
    }

    #[test]
    fn repo_fork_copies_shallow_markers() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/hello");
        let shallow_key = seed.blob_a.as_bytes().to_vec();
        {
            let budget = Arc::new(PreparationBudget::reference_defaults());
            let store = Store::open(&seed.canonical.join(".ruk"), budget).expect("source opens");
            store
                .publish(
                    Vec::new(),
                    &[FactMutation {
                        table: FactTable::Shallow,
                        key: shallow_key.clone(),
                        expected: FactExpectation::Absent,
                        value: Some(Vec::new()),
                    }],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("shallow marker publishes");
        }
        let dest = root.join("acme/fork-shallow");
        registry
            .fork_repo(&fork_args(&seed.canonical, &dest, None))
            .expect("fork serves");
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let forked = Store::open(&dest.join(".ruk"), budget).expect("fork opens");
        assert_eq!(
            forked
                .fact(FactTable::Shallow, &shallow_key)
                .expect("shallow reads"),
            Some(Vec::new()),
            "the shallow marker survives the fork"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repo_fork_exdev_falls_back_to_copy() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch_root();
        let a = root.join("seg-a");
        let b = root.join("seg-b");
        std::fs::write(&a, b"segment bytes").expect("fixture writes");
        match super::link_or_copy(&|from, to| std::fs::hard_link(from, to), &a, &b)
            .expect("link works")
        {
            super::LinkOutcome::Linked => {}
            super::LinkOutcome::Copied => panic!("same-device link must not copy"),
        }
        assert_eq!(
            std::fs::metadata(&a).expect("meta reads").ino(),
            std::fs::metadata(&b).expect("meta reads").ino()
        );
        std::fs::remove_file(&b).expect("fixture resets");
        let exdev = |_: &Path, _: &Path| -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(18))
        };
        match super::link_or_copy(&exdev, &a, &b).expect("fallback copies") {
            super::LinkOutcome::Copied => {}
            super::LinkOutcome::Linked => panic!("cross-device link must copy"),
        }
        assert_ne!(
            std::fs::metadata(&a).expect("meta reads").ino(),
            std::fs::metadata(&b).expect("meta reads").ino()
        );
        assert_eq!(std::fs::read(&b).expect("copy reads"), b"segment bytes");
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/exdev");
        let dest = root.join("acme/exdev-fork");
        let reply = registry
            .fork_repo_with_link(
                &fork_args(&seed.canonical, &dest, None),
                &exdev,
                &super::staging_sibling,
            )
            .expect("fork serves");
        assert_eq!(reply.lfs_linked, 1);
        assert!(reply.segments_copied.is_empty());
        let lfs_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let from =
            lfs::sidecar_path(&seed.canonical.join(".ruk"), lfs_hex).expect("source path resolves");
        let to = lfs::sidecar_path(&dest.join(".ruk"), lfs_hex).expect("dest path resolves");
        assert_ne!(
            std::fs::metadata(&from).expect("meta reads").ino(),
            std::fs::metadata(&to).expect("meta reads").ino()
        );
        assert_eq!(std::fs::read(&to).expect("payload reads"), b"");
        assert_eq!(
            read_blob(
                &Store::open(
                    &dest.join(".ruk"),
                    Arc::new(PreparationBudget::reference_defaults())
                )
                .expect("fork opens"),
                seed.blob_a
            ),
            b"hello fork"
        );
    }

    #[test]
    fn repo_fork_staging_crash_retry_mints_fresh_name() {
        let root = scratch_root();
        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let seed = seed_fork_source(&registry, &root, "acme/retry");
        let dest = root.join("acme/fork");
        let stale = root.join("acme/fork.fork-stale");
        let fresh = root.join("acme/fork.fork-fresh");
        std::fs::create_dir_all(&stale).expect("stale staging stages");
        std::fs::write(stale.join("marker"), b"crash leftover").expect("marker writes");
        let mints = std::cell::Cell::new(0_u32);
        // The first mint collides with the leftover; only a retry that
        // mints again reaches the fresh name.
        let mint = |_destination: &Path| {
            let call = mints.get();
            mints.set(call + 1);
            if call == 0 {
                stale.clone()
            } else {
                fresh.clone()
            }
        };
        let reply = registry
            .fork_repo_with_link(
                &fork_args(&seed.canonical, &dest, Some(ForkRefs::None)),
                &|from, to| std::fs::hard_link(from, to),
                &mint,
            )
            .expect("retry serves");
        assert_eq!(mints.get(), 2, "the colliding first name forces one retry");
        assert_eq!(reply.refs_copied, 0);
        assert_eq!(
            std::fs::read(stale.join("marker")).expect("marker survives"),
            b"crash leftover"
        );
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(root.join("acme")).expect("parent lists") {
            let name = entry
                .expect("entry reads")
                .file_name()
                .to_string_lossy()
                .into_owned();
            if name.contains(".fork-") {
                leftovers.push(name);
            }
        }
        assert_eq!(leftovers, vec!["fork.fork-stale".to_owned()]);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let forked = Store::open(&dest.join(".ruk"), budget).expect("fork opens");
        assert_eq!(read_blob(&forked, seed.blob_a), b"hello fork");
    }

    #[test]
    fn open_restores_uncertain_push_guards_across_restart() {
        use ruk_core::HashKind;
        use ruk_core::change::PlanId;
        use ruk_core::error::ErrorCode;
        use ruk_git::transport::push::{PushPlanRecord, PushUpdate};

        let root = scratch_root();
        let repo_path = root.join("repo-a");
        let store_dir = repo_path.join(".ruk");
        let store = Store::create(
            &store_dir,
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("scratch store initializes");

        let plan_id = PlanId::generate();
        let guarded_ref = b"refs/heads/main".to_vec();
        let unguarded_ref = b"refs/heads/feature".to_vec();
        let updates = vec![PushUpdate {
            name: guarded_ref.clone(),
            old: HashKind::Sha256.zero_oid(),
            new: HashKind::Sha256.zero_oid(),
        }];
        let mut plan = PushPlanRecord::prepare(plan_id, b"origin".to_vec(), false, updates);
        plan.begin_send().expect("begin_send");
        plan.mark_uncertain();
        let mutation = plan
            .persist_mutation(HashKind::Sha256, None)
            .expect("mutation encodes");
        store
            .publish(
                Vec::new(),
                &[mutation],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("plan persists");
        drop(store);

        let registry = Registry::new(vec![root.clone()]).expect("scratch root canonicalizes");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        registry.set_runtime(runtime.handle().clone());

        let (_handle, path, _coord) = registry
            .open(repo_path.to_str().expect("scratch path is UTF-8"))
            .expect("open restores repository and guards");

        let err = registry
            .push_guard_check(&path, std::slice::from_ref(&guarded_ref))
            .expect_err("uncertain push plan guards ref after restart");
        assert_eq!(err.code, ErrorCode::EPushUncertain);
        assert!(err.to_string().contains(&plan_id.to_string()));

        registry
            .push_guard_check(&path, std::slice::from_ref(&unguarded_ref))
            .expect("unguarded ref passes");

        registry
            .note_push_reconciled(&path, plan_id, std::slice::from_ref(&guarded_ref))
            .expect("reconcile clears guard");
        registry
            .push_guard_check(&path, std::slice::from_ref(&guarded_ref))
            .expect("cleared ref passes");
    }
}
