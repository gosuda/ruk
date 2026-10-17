//! Process admission for coordinator work: one scheduler per process, one
//! handle per registered repository, permits in five request classes, and the
//! single `spawn_blocking` call site.
//!
//! Interactive, bulk, hook, and maintenance work share the process through
//! deficit round-robin over repositories. Each grant is debited a prediction
//! and settled against measured CPU and payload work when its permit drops.
//! Control has a separate FIFO capacity and never waits behind ordinary
//! admission.
//!
//! Blocking closures own their permits. An abandoned caller never frees them
//! early, and no scheduler preempts a running closure: callers bound each
//! closure's input and check the supplied [`Cancel`] at their own chunk
//! boundaries. Scheduler state lives in [`scheduler`].

mod scheduler;

use std::io;
use std::panic::resume_unwind;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use self::scheduler::{Shared, Submission, Ticket};
use super::cancel::Cancel;
use crate::budget::ByteBudget;
use crate::error::{CoreError, ErrorCode};

/// Request class. The dispatcher selects it; a client never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RequestClass {
    Control,
    Interactive,
    Bulk,
    Hook,
    Maintenance,
}

/// Scarce downstream resources a request consumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WorkResources {
    Compute,
    Storage,
}

/// Admission bounds of one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassLimits {
    /// Permits of this class that may execute at once.
    pub(crate) slots: usize,
    /// Waiting entries this class may hold.
    pub(crate) queued: usize,
    /// Longest wait before an entry is refused with `E_LIMIT`.
    pub(crate) max_wait: Duration,
}

/// Execution caps one repository may hold across the ordinary classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepoCaps {
    /// Interactive plus bulk permits of one repository.
    pub(crate) ordinary: usize,
    /// Bulk permits of one repository, within `ordinary`.
    pub(crate) bulk: usize,
    /// Hook permits of one repository.
    pub(crate) hook: usize,
    /// Maintenance permits of one repository.
    pub(crate) maintenance: usize,
}

/// Storage-intensive permits per class. Each is a share of that class's slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoragePermits {
    pub(crate) interactive: usize,
    pub(crate) bulk: usize,
    pub(crate) hook: usize,
    pub(crate) maintenance: usize,
}

/// Every admission bound of one process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionLimits {
    pub(crate) control: ClassLimits,
    pub(crate) interactive: ClassLimits,
    pub(crate) bulk: ClassLimits,
    pub(crate) hook: ClassLimits,
    pub(crate) maintenance: ClassLimits,
    pub(crate) repo: RepoCaps,
    pub(crate) storage: StoragePermits,
    /// Blocking threads reserved for control work.
    pub(crate) control_blocking: usize,
    /// Blocking threads for ordinary work. Control work never uses them.
    pub(crate) ordinary_blocking: usize,
    /// Event-loop threads of the runtime from [`build_runtime`].
    pub(crate) event_loop_threads: usize,
    /// Queued payload bytes across the process.
    pub(crate) queued_payload_bytes: u64,
    /// Queued payload bytes of one repository.
    pub(crate) queued_payload_repo_bytes: u64,
    /// Repositories registered at once.
    pub(crate) open_repositories: usize,
}

impl AdmissionLimits {
    /// The approved reference production profile.
    #[must_use]
    pub(crate) fn reference_profile() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            control: ClassLimits {
                slots: 32,
                queued: 128,
                max_wait: Duration::from_millis(100),
            },
            interactive: ClassLimits {
                slots: 16,
                queued: 2048,
                max_wait: Duration::from_millis(250),
            },
            bulk: ClassLimits {
                slots: 6,
                queued: 256,
                max_wait: Duration::from_secs(5),
            },
            hook: ClassLimits {
                slots: 4,
                queued: 64,
                max_wait: Duration::from_secs(1),
            },
            maintenance: ClassLimits {
                slots: 2,
                queued: 32,
                max_wait: Duration::from_secs(30),
            },
            repo: RepoCaps {
                ordinary: 8,
                bulk: 2,
                hook: 2,
                maintenance: 1,
            },
            storage: StoragePermits {
                interactive: 4,
                bulk: 2,
                hook: 1,
                maintenance: 1,
            },
            control_blocking: 4,
            ordinary_blocking: 12,
            event_loop_threads: 4,
            queued_payload_bytes: 256 * MIB,
            queued_payload_repo_bytes: 16 * MIB,
            open_repositories: 128,
        }
    }

    /// Checks every bound the scheduler depends on. Runs before any state exists.
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        let classes = [
            ("control", self.control),
            ("interactive", self.interactive),
            ("bulk", self.bulk),
            ("hook", self.hook),
            ("maintenance", self.maintenance),
        ];
        for (name, limits) in classes {
            if limits.slots == 0 || limits.queued == 0 || limits.max_wait.is_zero() {
                return Err(invalid(format!(
                    "{name} class needs slots, queue capacity, and a wait bound"
                )));
            }
        }
        let shares = [
            (
                "interactive",
                self.storage.interactive,
                self.interactive.slots,
            ),
            ("bulk", self.storage.bulk, self.bulk.slots),
            ("hook", self.storage.hook, self.hook.slots),
            (
                "maintenance",
                self.storage.maintenance,
                self.maintenance.slots,
            ),
        ];
        for (name, share, slots) in shares {
            if share == 0 || share > slots {
                return Err(invalid(format!(
                    "{name} storage permits must be 1 to the class slots"
                )));
            }
        }
        self.validate_repo_caps()?;
        if self.control_blocking == 0
            || self.ordinary_blocking == 0
            || self.event_loop_threads == 0
            || self.open_repositories == 0
        {
            return Err(invalid("runtime and registration bounds must be nonzero"));
        }
        if self.queued_payload_repo_bytes == 0
            || self.queued_payload_repo_bytes > self.queued_payload_bytes
        {
            return Err(invalid(
                "repository payload budget must be nonzero and within the process budget",
            ));
        }
        Ok(())
    }

    fn validate_repo_caps(&self) -> Result<(), CoreError> {
        let ordinary_slots = self.interactive.slots.saturating_add(self.bulk.slots);
        let repo = self.repo;
        let fits = repo.ordinary >= 1
            && repo.ordinary <= ordinary_slots
            && repo.bulk >= 1
            && repo.bulk <= repo.ordinary.min(self.bulk.slots)
            && repo.hook >= 1
            && repo.hook <= self.hook.slots
            && repo.maintenance >= 1
            && repo.maintenance <= self.maintenance.slots;
        if fits {
            Ok(())
        } else {
            Err(invalid("repository caps must fit within the class slots"))
        }
    }

    fn blocking_threads(&self) -> usize {
        self.control_blocking.saturating_add(self.ordinary_blocking)
    }
}

/// Builds the coordinator runtime: bounded event-loop threads, and a blocking
/// pool whose size equals the two blocking reservations. I/O and time are enabled.
///
/// # Errors
/// Invalid limits are reported as `InvalidInput`; runtime construction
/// failures are reported as they occur.
pub(crate) fn build_runtime(limits: &AdmissionLimits) -> io::Result<Runtime> {
    limits
        .validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.message))?;
    Builder::new_multi_thread()
        .worker_threads(limits.event_loop_threads)
        .max_blocking_threads(limits.blocking_threads())
        .thread_name("ruk-coordinator")
        .enable_io()
        .enable_time()
        .build()
}

/// Blocking-thread reservations. Control and ordinary work never share permits.
#[derive(Debug)]
struct BlockingPools {
    control: Arc<Semaphore>,
    ordinary: Arc<Semaphore>,
}

/// The process admission scheduler.
#[derive(Debug)]
pub(crate) struct Admission {
    shared: Arc<Shared>,
    pools: Arc<BlockingPools>,
}

impl Admission {
    /// Validates `limits` and builds the scheduler.
    ///
    /// # Errors
    /// Returns `E_INVALID` when any bound is inconsistent.
    pub(crate) fn new(limits: AdmissionLimits) -> Result<Arc<Self>, CoreError> {
        limits.validate()?;
        let pools = BlockingPools {
            control: Arc::new(Semaphore::new(limits.control_blocking)),
            ordinary: Arc::new(Semaphore::new(limits.ordinary_blocking)),
        };
        Ok(Arc::new(Self {
            shared: Arc::new(Shared::new(limits)),
            pools: Arc::new(pools),
        }))
    }

    /// Registers one repository. Its coordinator keeps the returned handle and
    /// uses it for every request.
    ///
    /// # Errors
    /// `E_LIMIT` when the open-repository bound is reached; `E_CANCELLED` after close.
    pub(crate) fn repo(self: &Arc<Self>) -> Result<RepoAdmission, CoreError> {
        let key = self.shared.register()?;
        Ok(RepoAdmission {
            key,
            shared: Arc::clone(&self.shared),
            payload: ByteBudget::new(self.shared.repo_payload_limit()),
        })
    }

    /// Stops new admission and wakes queued callers with `E_CANCELLED`.
    /// Granted permits keep running until they drop.
    pub(crate) fn close(&self) {
        self.shared.close();
    }

    /// Waits for a permit for `request` in its class.
    ///
    /// The effective wait ends at the earlier of `request.deadline` and the
    /// class queue bound. Dropping the returned future before it resolves
    /// releases any queue entry or unclaimed grant it held.
    ///
    /// # Errors
    /// `E_LIMIT` for a full queue, an exhausted payload budget, or a wait that
    /// ran out. `E_CANCELLED` for caller cancellation or orderly shutdown.
    /// `E_INVALID` for a control request with storage resources or a handle
    /// from another admission.
    pub(crate) async fn admit(
        self: &Arc<Self>,
        repo: &RepoAdmission,
        request: AdmissionRequest,
        cancel: &Cancel,
    ) -> Result<Admitted, CoreError> {
        cancel.check()?;
        if !Arc::ptr_eq(&self.shared, &repo.shared) {
            return Err(invalid("repository handle belongs to another admission"));
        }
        if request.class == RequestClass::Control && request.resources == WorkResources::Storage {
            return Err(invalid("control admission carries no storage permits"));
        }
        let request_bytes = u64::try_from(request.payload_bytes)
            .map_err(|_| invalid("payload size does not fit 64 bits"))?;
        let submission = Submission {
            class: request.class,
            resources: request.resources,
            request_bytes,
            deadline: request.deadline,
        };
        let mut queued =
            self.shared
                .enqueue(repo.key, &repo.payload, submission, Instant::now())?;
        let ticket = queued.wait(cancel).await?;
        Ok(Admitted {
            ticket,
            pools: Arc::clone(&self.pools),
        })
    }
}

/// One registered repository. Dropping the handle retires its scheduler entry
/// once no permit or waiter still refers to it.
#[derive(Debug)]
#[must_use = "dropping a RepoAdmission retires the repository's scheduler entry"]
pub(crate) struct RepoAdmission {
    key: u64,
    shared: Arc<Shared>,
    payload: Arc<ByteBudget>,
}

impl Drop for RepoAdmission {
    fn drop(&mut self) {
        self.shared.retire(self.key);
    }
}

/// One admission request. `deadline` is absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionRequest {
    pub(crate) class: RequestClass,
    pub(crate) resources: WorkResources,
    pub(crate) payload_bytes: usize,
    pub(crate) deadline: Instant,
}

/// A granted admission. It holds its class slot, storage permit, repository
/// share, or control slot until it drops.
#[derive(Debug)]
#[must_use = "dropping an Admitted releases its admission and blocking permits"]
pub(crate) struct Admitted {
    ticket: Ticket,
    pools: Arc<BlockingPools>,
}

impl Admitted {
    /// Records one completed chunk of work. The CPU time and the processed
    /// payload bytes both count toward the repository's measured cost.
    pub(crate) fn record_chunk(&mut self, cpu: Duration, payload_bytes: u64) {
        self.ticket.record(cpu.as_nanos());
        self.ticket.record(u128::from(payload_bytes));
    }
}

/// Runs `work` on the blocking pool, owned by the closure.
///
/// The closure takes ownership of `admitted` and of a blocking-pool permit
/// from the reservation for the request's class, so the permits release when
/// the closure returns, never when the caller gives up. Cancellation while
/// waiting for the permit or the closure returns `E_CANCELLED`; the closure
/// keeps its permits and observes the same [`Cancel`] at its own chunk
/// boundaries. The closure's wall-clock run time is recorded as measured work
/// before it returns, because the closure itself cannot reach the admission.
/// A panic in the closure is resumed on the awaiting task.
///
/// # Errors
/// `E_CANCELLED` when cancellation fires first or the runtime aborts the task.
pub(crate) async fn run_blocking<F, T>(
    mut admitted: Admitted,
    cancel: Cancel,
    work: F,
) -> Result<(Admitted, T), CoreError>
where
    F: FnOnce(&Cancel) -> T + Send + 'static,
    T: Send + 'static,
{
    cancel.check()?;
    let pool = if admitted.ticket.is_control() {
        Arc::clone(&admitted.pools.control)
    } else {
        Arc::clone(&admitted.pools.ordinary)
    };
    let permit: OwnedSemaphorePermit = cancel
        .until(pool.acquire_owned())
        .await?
        .map_err(|_| CoreError::new(ErrorCode::ECancelled, "blocking pool is closed"))?;
    let worker_cancel = cancel.clone();
    let task = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        let value = work(&worker_cancel);
        admitted.record_chunk(started.elapsed(), 0);
        drop(permit);
        (admitted, value)
    });
    match cancel.until(task).await? {
        Ok(output) => Ok(output),
        Err(join) if join.is_panic() => resume_unwind(join.into_panic()),
        Err(_) => Err(CoreError::new(
            ErrorCode::ECancelled,
            "blocking task was aborted by runtime shutdown",
        )),
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EInvalid, message)
}

fn limit(message: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::ELimit, message)
}
#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::mpsc;

    use tokio::runtime::{Builder, Runtime};
    use tokio::time::timeout;

    use super::*;
    use crate::coord::cancel::cancellation;

    fn runtime() -> Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    }

    fn small_limits() -> AdmissionLimits {
        let class = |slots| ClassLimits {
            slots,
            queued: 16,
            max_wait: Duration::from_secs(5),
        };
        AdmissionLimits {
            control: class(2),
            interactive: class(1),
            bulk: class(1),
            hook: class(1),
            maintenance: class(1),
            repo: RepoCaps {
                ordinary: 1,
                bulk: 1,
                hook: 1,
                maintenance: 1,
            },
            storage: StoragePermits {
                interactive: 1,
                bulk: 1,
                hook: 1,
                maintenance: 1,
            },
            control_blocking: 1,
            ordinary_blocking: 1,
            event_loop_threads: 1,
            queued_payload_bytes: 4096,
            queued_payload_repo_bytes: 1024,
            open_repositories: 2,
        }
    }

    fn request(class: RequestClass, payload_bytes: usize) -> AdmissionRequest {
        AdmissionRequest {
            class,
            resources: WorkResources::Compute,
            payload_bytes,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn submission(class: RequestClass, request_bytes: u64) -> Submission {
        Submission {
            class,
            resources: WorkResources::Compute,
            request_bytes,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    #[test]
    fn reference_profile_validates_and_inconsistent_bounds_are_refused() {
        assert!(AdmissionLimits::reference_profile().validate().is_ok());
        assert!(small_limits().validate().is_ok());

        let mut storage_over_slots = small_limits();
        storage_over_slots.storage.interactive = 2;
        let error = Admission::new(storage_over_slots).unwrap_err();
        assert_eq!(error.code, ErrorCode::EInvalid);

        let mut repo_bulk_over_ordinary = small_limits();
        repo_bulk_over_ordinary.repo.bulk = 2;
        assert!(Admission::new(repo_bulk_over_ordinary).is_err());

        let mut repo_budget_over_process = small_limits();
        repo_budget_over_process.queued_payload_repo_bytes = 8192;
        assert!(Admission::new(repo_budget_over_process).is_err());
    }

    #[test]
    fn repository_registration_is_bounded_and_retired_on_drop() {
        let admission = Admission::new(small_limits()).expect("admission");
        let first = admission.repo().expect("first repository");
        let second = admission.repo().expect("second repository");
        assert_eq!(admission.repo().unwrap_err().code, ErrorCode::ELimit);
        drop(first);
        let third = admission
            .repo()
            .expect("a dropped handle frees a registration");
        drop(second);
        drop(third);
        for _ in 0..1000 {
            drop(admission.repo().expect("churned registration"));
        }
        assert_eq!(admission.shared.tracked_repos(), 0);
    }

    #[test]
    fn abandoned_waiters_release_queue_entries_and_payload_reservations() {
        let admission = Admission::new(small_limits()).expect("admission");
        let repo = admission.repo().expect("repo");
        let now = Instant::now();
        let mut occupant = admission
            .shared
            .enqueue(
                repo.key,
                &repo.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("occupant");
        let scheduler::Claim::Granted(ticket) = occupant.poll(now) else {
            panic!("the first request takes the only interactive permit");
        };
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let waiter = admission
                .shared
                .enqueue(
                    repo.key,
                    &repo.payload,
                    submission(RequestClass::Interactive, 256),
                    now,
                )
                .expect("within the repository payload budget");
            waiters.push(waiter);
        }
        let refused = admission.shared.enqueue(
            repo.key,
            &repo.payload,
            submission(RequestClass::Interactive, 256),
            now,
        );
        assert_eq!(
            refused.err().map(|error| error.code),
            Some(ErrorCode::ELimit)
        );

        drop(waiters.pop());
        admission
            .shared
            .enqueue(
                repo.key,
                &repo.payload,
                submission(RequestClass::Interactive, 256),
                now,
            )
            .expect("the abandoned waiter released its payload reservation");
        drop(ticket);
    }

    #[test]
    fn run_blocking_returns_the_permit_with_its_result() {
        let rt = runtime();
        rt.block_on(async {
            let admission = Admission::new(small_limits()).expect("admission");
            let repo = admission.repo().expect("repo");
            let (_handle, cancel) = cancellation();
            let mut admitted = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("admit");
            admitted.record_chunk(Duration::from_millis(3), 10);
            let (admitted, value) = run_blocking(admitted, cancel.clone(), |_cancel| 7_u32)
                .await
                .expect("blocking work completes");
            assert_eq!(value, 7);
            drop(admitted);
            admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("the permit returns when the admitted value drops");
        });
    }

    #[test]
    fn abandoned_caller_leaves_blocking_permits_with_the_closure() {
        let rt = runtime();
        rt.block_on(async {
            let admission = Admission::new(small_limits()).expect("admission");
            let repo = admission.repo().expect("repo");
            let (_handle, cancel) = cancellation();
            let (started_tx, started_rx) = mpsc::channel::<()>();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let admitted = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("admit");
            let pending = run_blocking(admitted, cancel.clone(), move |_cancel| {
                started_tx.send(()).expect("report start");
                release_rx.recv().expect("wait for release");
            });
            let abandoned = timeout(Duration::from_millis(50), pending).await;
            assert!(abandoned.is_err(), "the closure is still running");
            started_rx.recv().expect("the closure started");

            let blocked = AdmissionRequest {
                deadline: Instant::now() + Duration::from_millis(30),
                ..request(RequestClass::Interactive, 0)
            };
            let refused = admission.admit(&repo, blocked, &cancel).await;
            assert_eq!(refused.unwrap_err().code, ErrorCode::ELimit);

            release_tx.send(()).expect("release the closure");
            admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("the permit returns when the closure finishes");
        });
    }

    #[test]
    fn closure_panic_resumes_on_the_awaiting_task() {
        let rt = runtime();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            rt.block_on(async {
                let admission = Admission::new(small_limits()).expect("admission");
                let repo = admission.repo().expect("repo");
                let (_handle, cancel) = cancellation();
                let admitted = admission
                    .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                    .await
                    .expect("admit");
                let _ = run_blocking(admitted, cancel.clone(), |_cancel| -> () {
                    panic!("closure failure")
                })
                .await;
            });
        }));
        assert!(outcome.is_err(), "the closure panic reaches the caller");
    }

    #[test]
    fn control_admission_is_not_blocked_by_saturated_ordinary_classes() {
        let rt = runtime();
        rt.block_on(async {
            let admission = Admission::new(small_limits()).expect("admission");
            let repo = admission.repo().expect("repo");
            let (_handle, cancel) = cancellation();
            let held = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("ordinary permit");
            let mut waiter = admission
                .shared
                .enqueue(
                    repo.key,
                    &repo.payload,
                    submission(RequestClass::Interactive, 0),
                    Instant::now(),
                )
                .expect("queued behind saturation");
            assert!(matches!(
                waiter.poll(Instant::now()),
                scheduler::Claim::Pending
            ));
            let control = admission
                .admit(&repo, request(RequestClass::Control, 0), &cancel)
                .await
                .expect("control is admissible under ordinary saturation");
            drop(control);
            drop(waiter);
            drop(held);
        });
    }

    #[test]
    fn close_refuses_queued_callers_and_keeps_granted_permits() {
        let rt = runtime();
        rt.block_on(async {
            let admission = Admission::new(small_limits()).expect("admission");
            let repo = admission.repo().expect("repo");
            let (_handle, cancel) = cancellation();
            let held = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("granted permit");
            let mut queued = admission
                .shared
                .enqueue(
                    repo.key,
                    &repo.payload,
                    submission(RequestClass::Interactive, 0),
                    Instant::now(),
                )
                .expect("queued");
            admission.close();
            let error = queued
                .wait(&cancel)
                .await
                .expect_err("a closed admission refuses queued callers");
            assert_eq!(error.code, ErrorCode::ECancelled);
            let refused = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await;
            assert_eq!(refused.unwrap_err().code, ErrorCode::ECancelled);
            drop(held);
        });
    }

    #[test]
    fn measured_overrun_leaves_debt_on_the_repository() {
        let admission = Admission::new(small_limits()).expect("admission");
        let repo = admission.repo().expect("repo");
        let now = Instant::now();
        let mut queued = admission
            .shared
            .enqueue(
                repo.key,
                &repo.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("queued");
        let scheduler::Claim::Granted(mut ticket) = queued.poll(now) else {
            panic!("the request runs on an idle admission");
        };
        ticket.record(Duration::from_millis(500).as_nanos());
        drop(ticket);
        let balance = admission
            .shared
            .deficit_of(repo.key, RequestClass::Interactive)
            .expect("the repository is registered");
        assert!(
            balance < 0,
            "measured work beyond the prediction stays owed"
        );
    }

    #[test]
    fn saturated_repository_does_not_block_an_eligible_quiet_one() {
        let mut limits = small_limits();
        limits.interactive.slots = 2;
        let admission = Admission::new(limits).expect("admission");
        let busy = admission.repo().expect("busy repository");
        let quiet = admission.repo().expect("quiet repository");
        let now = Instant::now();

        let mut first = admission
            .shared
            .enqueue(
                busy.key,
                &busy.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("first");
        let scheduler::Claim::Granted(_holding) = first.poll(now) else {
            panic!("the busy repository takes its cap");
        };
        let mut second = admission
            .shared
            .enqueue(
                busy.key,
                &busy.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("second");
        assert!(matches!(second.poll(now), scheduler::Claim::Pending));

        let mut other = admission
            .shared
            .enqueue(
                quiet.key,
                &quiet.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("quiet");
        assert!(matches!(other.poll(now), scheduler::Claim::Granted(_)));
    }

    #[test]
    fn zero_reported_work_is_not_refunded() {
        let admission = Admission::new(small_limits()).expect("admission");
        let repo = admission.repo().expect("repo");
        let now = Instant::now();
        let mut queued = admission
            .shared
            .enqueue(
                repo.key,
                &repo.payload,
                submission(RequestClass::Interactive, 0),
                now,
            )
            .expect("queued");
        let scheduler::Claim::Granted(ticket) = queued.poll(now) else {
            panic!("the request runs on an idle admission");
        };
        drop(ticket);
        let balance = admission
            .shared
            .deficit_of(repo.key, RequestClass::Interactive)
            .expect("the repository is registered");
        assert!(
            balance <= 0,
            "a job that reports no work earns no credit back"
        );
    }

    #[test]
    fn blocking_work_is_charged_by_its_measured_run_time() {
        let rt = runtime();
        rt.block_on(async {
            let admission = Admission::new(small_limits()).expect("admission");
            let repo = admission.repo().expect("repo");
            let (_handle, cancel) = cancellation();
            let admitted = admission
                .admit(&repo, request(RequestClass::Interactive, 0), &cancel)
                .await
                .expect("admit");
            let (admitted, ()) = run_blocking(admitted, cancel.clone(), |_cancel| {
                std::thread::sleep(Duration::from_millis(20));
            })
            .await
            .expect("blocking work completes");
            drop(admitted);
            let balance = admission
                .shared
                .deficit_of(repo.key, RequestClass::Interactive)
                .expect("the repository is registered");
            assert!(
                balance < 0,
                "a 20 ms closure is charged beyond its 1 ms prediction"
            );
        });
    }
}
