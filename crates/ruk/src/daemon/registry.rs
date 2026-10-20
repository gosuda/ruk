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

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ruk_core::coord::{HostedCoordinator, Principal, cancellation};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::store::{PreparationBudget, Store};

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
    /// Cap of ref commands accepted per hosted push batch.
    hook_max_commands: AtomicUsize,
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
        Ok(Self {
            roots: canonical,
            inner: Mutex::new(RegistryInner {
                entries: HashMap::new(),
            }),
            next_handle: AtomicU64::new(1),
            runtime: Mutex::new(None),
            retention_interval_ms: AtomicU64::new(super::DEFAULT_RETENTION_INTERVAL_MS),
            event_retention_seconds: AtomicU64::new(super::DEFAULT_EVENT_RETENTION_SECONDS),
            hook_timeout_ms: AtomicU64::new(super::DEFAULT_HOOK_TIMEOUT_MS),
            hook_max_commands: AtomicUsize::new(super::MAX_HOOK_MAX_COMMANDS),
        })
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

    /// Resolves a not-yet-existing destination beneath a configured root:
    /// the nearest existing ancestor is canonicalized and symlink
    /// components below it are refused (see `ruk_core::contained`).
    ///
    /// # Errors
    /// `E_NOT_FOUND` when no ancestor exists beneath a root, `E_FORBIDDEN`
    /// for symlink components or paths outside the roots, `E_IO` when the
    /// path is inaccessible.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no creator at this commit; wired in CS-R23/CS-R24 repo lifecycle rows"
        )
    )]
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
            let pinned = self.resolve_pinned(Path::new(repo_ref))?;
            let handle = self.handle_for_path(pinned.path())?;
            (handle, pinned)
        } else {
            let stored = self.open_by_handle(repo_ref)?;
            let pinned = self.resolve_pinned(&stored)?;
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
        let entry = inner
            .entries
            .get_mut(handle)
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "repository handle is unknown"))?;
        if let Some(coordinator) = entry.coordinator.as_ref() {
            entry.last_used = Instant::now();
            return Ok(Arc::clone(coordinator));
        }
        let canonical = pinned.path().to_path_buf();
        #[cfg(unix)]
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
        #[cfg(not(unix))]
        let store = Store::open(
            &canonical,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
        pinned.verify_open(&canonical)?;
        let owner = match pinned.owner_uid() {
            Some(uid) => Principal::from_peer_uid(uid),
            None => Self::repository_owner(&canonical)?,
        };
        let coordinator = Arc::new(HostedCoordinator::open(Arc::new(store), owner, canonical)?);
        let runner = coordinator.spawn_on(&runtime)?;
        coordinator
            .set_event_retention_seconds(self.event_retention_seconds.load(Ordering::Relaxed));
        spawn_retention(&runtime, &coordinator, self.retention_interval_ms());
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
        entry.last_used = Instant::now();
        Ok(entry.path.clone())
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
    use super::Registry;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static SIBLING: AtomicU64 = AtomicU64::new(1);

    fn scratch_root() -> std::path::PathBuf {
        let tag = SIBLING.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("ruk-daemon-registry-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(root.join("repo-a")).expect("scratch repository fits on disk");
        root
    }

    #[test]
    fn empty_roots_are_rejected() {
        assert!(Registry::new(Vec::new()).is_err());
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
    #[cfg(unix)]
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
        let mut oks = 0u32;
        for _ in 0..200 {
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
}
