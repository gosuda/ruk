//! Scheduler state behind [`super::Admission`]: deficit round-robin over
//! repositories for the four non-control classes, FIFO admission for control,
//! and RAII tickets that release what they hold.
//!
//! One `std::sync::Mutex` guards every decision. The lock is never held across
//! an await or a blocking call, and it is always released before a ticket is
//! dropped, because a ticket's drop re-enters the lock. A grant stores its
//! ticket in the waiter's slot under that lock and wakes the waiter through the
//! slot's `Notify`; a permit stored by `notify_one` before the waiter sleeps is
//! not lost.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;
use tokio::time::Instant;

use super::{AdmissionLimits, ClassLimits, RequestClass, WorkResources, invalid, limit};
use crate::budget::{ByteBudget, ByteReservation};
use crate::coord::cancel::Cancel;
use crate::error::{CoreError, ErrorCode};

/// Number of ordinary (non-control) classes; every per-class array has this length.
const ORDINARY: usize = 4;
const INTERACTIVE: usize = 0;
const BULK: usize = 1;
const HOOK: usize = 2;
const MAINTENANCE: usize = 3;
const ORDINARY_CLASSES: [RequestClass; ORDINARY] = [
    RequestClass::Interactive,
    RequestClass::Bulk,
    RequestClass::Hook,
    RequestClass::Maintenance,
];

/// Deficit credited to a backlogged repository per round, in cost units. One
/// unit is one nanosecond of measured CPU or one byte of processed payload, so
/// the quantum is ten milliseconds of CPU: the largest chunk that can yield.
const QUANTUM: i128 = 10_000_000;

/// Largest positive credit a repository banks: eight quanta. A repository
/// whose head is blocked by resources can bank this much and then spend it
/// across several visits. Debt (negative deficit) is never capped.
const CREDIT_CAP: i128 = 8 * QUANTUM;

/// Predicted cost of a request before measurement: one millisecond of CPU plus
/// one unit per request byte. The prediction is debited at grant and settled
/// against measured work at release.
const PREDICTED_BASE: u64 = 1_000_000;

/// Admission state of one process. Owns the limits, the process-wide queued
/// payload budget, and the mutable scheduler core.
pub(super) struct Shared {
    limits: AdmissionLimits,
    process_payload: Arc<ByteBudget>,
    core: Mutex<Core>,
}

#[derive(Default)]
struct Core {
    closed: bool,
    /// Repositories currently registered and not retired.
    open: usize,
    next_repo: u64,
    next_waiter: u64,
    /// Registered repositories plus retired ones that still hold permits.
    repos: HashMap<u64, RepoCore>,
    classes: [ClassCore; ORDINARY],
    control_running: usize,
    control_queue: VecDeque<Waiter>,
}

#[derive(Default)]
struct ClassCore {
    running: usize,
    storage_running: usize,
    queued: usize,
    /// Repositories with queued work in this class, in rotation order.
    active: VecDeque<u64>,
    /// Visit interrupted by class capacity; it resumes without new credit.
    current: Option<u64>,
}

#[derive(Default)]
struct RepoCore {
    retired: bool,
    running: [usize; ORDINARY],
    queues: [VecDeque<Waiter>; ORDINARY],
    in_active: [bool; ORDINARY],
    /// Deficit round-robin credit per class. Positive values are bounded by
    /// [`CREDIT_CAP`]; negative values are measured debt and persist while the
    /// repository is idle.
    deficit: [i128; ORDINARY],
}

impl RepoCore {
    fn is_idle(&self) -> bool {
        self.running.iter().all(|&count| count == 0)
            && self.queues.iter().all(VecDeque::is_empty)
    }
}

/// One waiting request. Its payload reservations count against the queued
/// payload budgets until the waiter is granted, refused, or removed.
struct Waiter {
    id: u64,
    repo: u64,
    slot: Arc<Slot>,
    resources: WorkResources,
    predicted: u64,
    request_bytes: u64,
    deadline: Instant,
    process_payload: ByteReservation,
    repo_payload: ByteReservation,
}

/// Handoff cell between the scheduler and one waiter.
pub(super) struct Slot {
    notify: Notify,
    state: Mutex<SlotState>,
}

enum SlotState {
    Waiting,
    Granted(Ticket),
    Refused(CoreError),
}

/// Request parameters after validation at the public boundary.
pub(super) struct Submission {
    pub(super) class: RequestClass,
    pub(super) resources: WorkResources,
    pub(super) request_bytes: u64,
    pub(super) deadline: Instant,
}

/// One granted admission. Dropping it releases the class slot, the storage
/// permit, and the repository share it holds, and settles the repository's
/// deficit against the measured cost.
#[derive(Debug)]
#[must_use = "dropping a Ticket releases its class slot, storage permit, and repository share"]
pub(super) struct Ticket {
    shared: Arc<Shared>,
    repo: u64,
    class: RequestClass,
    resources: WorkResources,
    predicted: u64,
    request_bytes: u64,
    /// Measured units recorded by chunks, saturating at `u128::MAX`.
    measured: u128,
}

impl Ticket {
    pub(super) fn record(&mut self, units: u128) {
        self.measured = self.measured.checked_add(units).unwrap_or(u128::MAX);
    }

    pub(super) fn is_control(&self) -> bool {
        self.class == RequestClass::Control
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.shared.release(self);
    }
}

/// Outcome of inspecting a waiter.
pub(super) enum Claim {
    Pending,
    Granted(Ticket),
    Refused(CoreError),
}

/// A waiter in its class queue. Dropping it before the outcome is observed
/// removes it from the queue, or returns a grant that was never claimed.
#[must_use = "dropping a Queued entry withdraws the waiting request"]
pub(super) struct Queued {
    shared: Arc<Shared>,
    slot: Arc<Slot>,
    id: u64,
    repo: u64,
    class: RequestClass,
    deadline: Instant,
    armed: bool,
}

impl Shared {
    pub(super) fn new(limits: AdmissionLimits) -> Self {
        Self {
            process_payload: ByteBudget::new(limits.queued_payload_bytes),
            limits,
            core: Mutex::new(Core::default()),
        }
    }

    pub(super) fn repo_payload_limit(&self) -> u64 {
        self.limits.queued_payload_repo_bytes
    }

    #[cfg(test)]
    pub(super) fn tracked_repos(&self) -> usize {
        self.lock().repos.len()
    }

    #[cfg(test)]
    pub(super) fn deficit_of(&self, repo: u64, class: RequestClass) -> Option<i128> {
        let index = ordinary_index(class)?;
        self.lock().repos.get(&repo).map(|state| state.deficit[index])
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn class_limits(&self, class: RequestClass) -> ClassLimits {
        match class {
            RequestClass::Control => self.limits.control,
            RequestClass::Interactive => self.limits.interactive,
            RequestClass::Bulk => self.limits.bulk,
            RequestClass::Hook => self.limits.hook,
            RequestClass::Maintenance => self.limits.maintenance,
        }
    }

    /// Registers one repository and returns its stable scheduler key.
    pub(super) fn register(&self) -> Result<u64, CoreError> {
        let mut core = self.lock();
        if core.closed {
            return Err(closed_error());
        }
        if core.open >= self.limits.open_repositories {
            return Err(limit(format!(
                "{} repositories are already open",
                self.limits.open_repositories
            )));
        }
        let key = core.next_repo;
        core.next_repo = key
            .checked_add(1)
            .ok_or_else(|| limit("repository keys are exhausted"))?;
        core.open += 1;
        core.repos.insert(key, RepoCore::default());
        Ok(key)
    }

    /// Marks a repository handle dropped. Its state leaves the table once no
    /// permit or waiter still refers to it.
    pub(super) fn retire(&self, key: u64) {
        let mut core = self.lock();
        core.open = core.open.saturating_sub(1);
        let remove = match core.repos.get_mut(&key) {
            Some(repo) => {
                repo.retired = true;
                repo.is_idle()
            }
            None => false,
        };
        if remove {
            core.repos.remove(&key);
        }
    }

    /// Queues one request. Payload reservations are taken before the entry
    /// is queued; a refusal changes nothing.
    pub(super) fn enqueue(
        self: &Arc<Self>,
        repo: u64,
        repo_payload: &Arc<ByteBudget>,
        submission: Submission,
        now: Instant,
    ) -> Result<Queued, CoreError> {
        let Submission {
            class,
            resources,
            request_bytes,
            deadline,
        } = submission;
        let limits = self.class_limits(class);
        let predicted = predicted_cost(request_bytes)?;
        let wait_deadline = deadline.min(now.checked_add(limits.max_wait).unwrap_or(deadline));
        let process_payload = self
            .process_payload
            .reserve(request_bytes)
            .map_err(|_| limit("queued payload exceeds the process budget"))?;
        let repo_payload = repo_payload
            .reserve(request_bytes)
            .map_err(|_| limit("queued payload exceeds the repository budget"))?;

        let slot = Arc::new(Slot {
            notify: Notify::new(),
            state: Mutex::new(SlotState::Waiting),
        });
        let mut core = self.lock();
        if core.closed {
            return Err(closed_error());
        }
        let id = core.next_waiter;
        core.next_waiter = id
            .checked_add(1)
            .ok_or_else(|| limit("waiter identifiers are exhausted"))?;
        let waiter = Waiter {
            id,
            repo,
            slot: Arc::clone(&slot),
            resources,
            predicted,
            request_bytes,
            deadline: wait_deadline,
            process_payload,
            repo_payload,
        };
        match ordinary_index(class) {
            None => {
                if core.control_queue.len() >= limits.queued {
                    return Err(queue_full(class));
                }
                core.control_queue.push_back(waiter);
                dispatch_control(self, &mut core, now);
            }
            Some(c) => {
                if core.classes[c].queued >= limits.queued {
                    return Err(queue_full(class));
                }
                let Core { repos, classes, .. } = &mut *core;
                let repo_core = repos
                    .get_mut(&repo)
                    .ok_or_else(|| invalid("repository is not registered with admission"))?;
                repo_core.queues[c].push_back(waiter);
                if !repo_core.in_active[c] {
                    repo_core.in_active[c] = true;
                    classes[c].active.push_back(repo);
                }
                classes[c].queued += 1;
                dispatch_class(self, &mut core, c, now);
            }
        }
        Ok(Queued {
            shared: Arc::clone(self),
            slot,
            id,
            repo,
            class,
            deadline: wait_deadline,
            armed: true,
        })
    }

    /// Stops admission and refuses every queued waiter. Granted tickets keep
    /// their permits until they drop.
    pub(super) fn close(&self) {
        let mut core = self.lock();
        if core.closed {
            return;
        }
        core.closed = true;
        let Core {
            repos,
            classes,
            control_queue,
            ..
        } = &mut *core;
        for waiter in control_queue.drain(..) {
            refuse(waiter, closed_error());
        }
        for repo in repos.values_mut() {
            repo.in_active = [false; ORDINARY];
            for queue in &mut repo.queues {
                for waiter in queue.drain(..) {
                    refuse(waiter, closed_error());
                }
            }
        }
        for class in classes.iter_mut() {
            class.queued = 0;
            class.active.clear();
            class.current = None;
        }
    }

    /// Settles a ticket and dispatches whatever its release made eligible.
    fn release(self: &Arc<Self>, ticket: &Ticket) {
        let now = Instant::now();
        let mut core = self.lock();
        match ordinary_index(ticket.class) {
            None => core.control_running = core.control_running.saturating_sub(1),
            Some(c) => {
                let Core { repos, classes, .. } = &mut *core;
                let class = &mut classes[c];
                class.running = class.running.saturating_sub(1);
                if ticket.resources == WorkResources::Storage {
                    class.storage_running = class.storage_running.saturating_sub(1);
                }
                let mut idle = false;
                if let Some(repo) = repos.get_mut(&ticket.repo) {
                    repo.running[c] = repo.running[c].saturating_sub(1);
                    repo.deficit[c] = settle(repo.deficit[c], ticket);
                    idle = repo.retired && repo.is_idle();
                }
                if idle {
                    repos.remove(&ticket.repo);
                }
            }
        }
        dispatch_all(self, &mut core, now);
    }
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Queued {
    /// Inspects the outcome at `now`, removing this waiter from its queue when
    /// its wait has run out.
    pub(super) fn poll(&mut self, now: Instant) -> Claim {
        let mut core = self.shared.lock();
        let claim = match take_state(&self.slot) {
            SlotState::Granted(ticket) => Claim::Granted(ticket),
            SlotState::Refused(error) => Claim::Refused(error),
            SlotState::Waiting if now < self.deadline => Claim::Pending,
            SlotState::Waiting => {
                drop(remove_waiter(&mut core, self.class, self.repo, self.id));
                Claim::Refused(limit("queue wait exceeded the class admission bound"))
            }
        };
        if !matches!(claim, Claim::Pending) {
            self.armed = false;
        }
        claim
    }

    /// Waits until the scheduler grants, refuses, or times out this waiter, or
    /// until `cancel` fires. Dropping the returned future before it resolves
    /// releases the queue entry or the grant it had not yet claimed.
    pub(super) async fn wait(&mut self, cancel: &Cancel) -> Result<Ticket, CoreError> {
        loop {
            match self.poll(Instant::now()) {
                Claim::Granted(ticket) => return Ok(ticket),
                Claim::Refused(error) => return Err(error),
                Claim::Pending => {}
            }
            let woken = self.slot.notify.notified();
            let _ = cancel
                .until(tokio::time::timeout_at(self.deadline, woken))
                .await?;
        }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let leftover = {
            let mut core = self.shared.lock();
            match take_state(&self.slot) {
                SlotState::Granted(ticket) => Some(ticket),
                SlotState::Refused(_) => None,
                SlotState::Waiting => {
                    drop(remove_waiter(&mut core, self.class, self.repo, self.id));
                    None
                }
            }
        };
        drop(leftover);
    }
}

/// Deficit round-robin over the repositories with queued work in one class.
///
/// The rotation front is the next repository whose visit starts. A fresh visit
/// credits one quantum when its head can run, then grants while the deficit
/// stays positive, so one visit spends its credit across several chunks. A
/// visit that class capacity interrupts stays open and resumes without new
/// credit. A repository blocked by its own caps or its storage share ends its
/// visit without credit. A full round of visits that grants nothing skips the
/// rounds in which nothing can be granted, in one step proportional to the
/// number of active repositories.
fn dispatch_class(shared: &Arc<Shared>, core: &mut Core, c: usize, now: Instant) {
    let Core { repos, classes, .. } = &mut *core;
    let class = &mut classes[c];
    let slots = ordinary_slots(&shared.limits, c);
    let mut idle_visits = 0;
    let mut needed: Option<i128> = None;
    loop {
        if class.running >= slots {
            return;
        }
        let served = if let Some(key) = class.current.take() {
            let Some(repo) = repos.get_mut(&key) else {
                continue;
            };
            resume_visit(shared, class, repo, key, c, now)
        } else if idle_visits < class.active.len() {
            let Some(key) = class.active.pop_front() else {
                return;
            };
            let Some(repo) = repos.get_mut(&key) else {
                continue;
            };
            start_visit(shared, class, repo, key, c, now)
        } else {
            let Some(rounds) = needed.take() else {
                return;
            };
            fast_forward(shared, class, repos, c, rounds - 1);
            idle_visits = 0;
            continue;
        };
        match served {
            Served::Interrupted => return,
            Served::Finished(outcome) if outcome.granted => {
                idle_visits = 0;
                needed = None;
            }
            Served::Finished(outcome) => {
                idle_visits += 1;
                needed = earliest(needed, outcome.needed);
            }
        }
    }
}

/// Result of one visit to a repository's class queue.
#[derive(Default)]
struct Outcome {
    granted: bool,
    /// Credits the blocked head still needs when its deficit is not positive.
    needed: Option<i128>,
}

enum Served {
    /// Class capacity ran out mid-visit; the visit resumes on the next dispatch.
    Interrupted,
    Finished(Outcome),
}

/// Starts a visit: credits one quantum when the head can run, then serves.
fn start_visit(
    shared: &Arc<Shared>,
    class: &mut ClassCore,
    repo: &mut RepoCore,
    key: u64,
    c: usize,
    now: Instant,
) -> Served {
    refuse_expired(class, repo, c, now);
    if head_ready(&shared.limits, class, repo, c) {
        repo.deficit[c] = repo.deficit[c].saturating_add(QUANTUM).min(CREDIT_CAP);
    }
    run_visit(shared, class, repo, key, c, now)
}

/// Resumes an interrupted visit. It already holds its credit.
fn resume_visit(
    shared: &Arc<Shared>,
    class: &mut ClassCore,
    repo: &mut RepoCore,
    key: u64,
    c: usize,
    now: Instant,
) -> Served {
    run_visit(shared, class, repo, key, c, now)
}

/// Grants the visit's heads while they can run and the deficit stays positive.
fn run_visit(
    shared: &Arc<Shared>,
    class: &mut ClassCore,
    repo: &mut RepoCore,
    key: u64,
    c: usize,
    now: Instant,
) -> Served {
    let mut outcome = Outcome::default();
    loop {
        refuse_expired(class, repo, c, now);
        if !head_ready(&shared.limits, class, repo, c) {
            break;
        }
        if class.running >= ordinary_slots(&shared.limits, c) {
            class.current = Some(key);
            return Served::Interrupted;
        }
        if repo.deficit[c] <= 0 {
            outcome.needed = earliest(outcome.needed, Some(rounds_needed(repo.deficit[c])));
            break;
        }
        let Some(waiter) = repo.queues[c].pop_front() else {
            break;
        };
        class.queued = class.queued.saturating_sub(1);
        grant(shared, class, repo, key, c, waiter);
        outcome.granted = true;
    }
    if repo.queues[c].is_empty() {
        repo.in_active[c] = false;
        repo.deficit[c] = repo.deficit[c].min(0);
    } else {
        class.active.push_back(key);
    }
    Served::Finished(outcome)
}

/// Refuses heads whose deadline has passed, from the front of one queue.
fn refuse_expired(class: &mut ClassCore, repo: &mut RepoCore, c: usize, now: Instant) {
    while repo.queues[c].front().is_some_and(|head| head.deadline <= now) {
        let Some(expired) = repo.queues[c].pop_front() else {
            return;
        };
        class.queued = class.queued.saturating_sub(1);
        refuse(expired, limit("queue wait exceeded the class admission bound"));
    }
}

/// The head can be granted once class capacity exists: it has a waiter, its
/// repository caps allow another permit, and its storage share is free.
fn head_ready(limits: &AdmissionLimits, class: &ClassCore, repo: &RepoCore, c: usize) -> bool {
    repo.queues[c].front().is_some_and(|head| {
        repo_allows(limits, repo, c) && storage_allows(limits, class, c, head.resources)
    })
}

/// Whether the repository's own caps admit one more permit of class `c`.
fn repo_allows(limits: &AdmissionLimits, repo: &RepoCore, c: usize) -> bool {
    let ordinary_total = repo.running[INTERACTIVE].saturating_add(repo.running[BULK]);
    match c {
        INTERACTIVE => ordinary_total < limits.repo.ordinary,
        BULK => ordinary_total < limits.repo.ordinary && repo.running[BULK] < limits.repo.bulk,
        HOOK => repo.running[HOOK] < limits.repo.hook,
        _ => repo.running[MAINTENANCE] < limits.repo.maintenance,
    }
}

/// Compute work never needs a storage permit; storage work needs a free share.
fn storage_allows(
    limits: &AdmissionLimits,
    class: &ClassCore,
    c: usize,
    resources: WorkResources,
) -> bool {
    resources == WorkResources::Compute || class.storage_running < storage_share(limits, c)
}

fn ordinary_slots(limits: &AdmissionLimits, c: usize) -> usize {
    match c {
        INTERACTIVE => limits.interactive.slots,
        BULK => limits.bulk.slots,
        HOOK => limits.hook.slots,
        _ => limits.maintenance.slots,
    }
}

fn storage_share(limits: &AdmissionLimits, c: usize) -> usize {
    match c {
        INTERACTIVE => limits.storage.interactive,
        BULK => limits.storage.bulk,
        HOOK => limits.storage.hook,
        _ => limits.storage.maintenance,
    }
}

/// Credits needed before a non-positive deficit turns positive.
fn rounds_needed(deficit: i128) -> i128 {
    i128::try_from(deficit.unsigned_abs() / QUANTUM.unsigned_abs() + 1).unwrap_or(i128::MAX)
}

/// Credits `rounds` silent rounds to every active repository whose head is
/// ready. Ready heads stay ready across silent rounds, so this equals the
/// credit those rounds would have given one at a time.
fn fast_forward(
    shared: &Arc<Shared>,
    class: &ClassCore,
    repos: &mut HashMap<u64, RepoCore>,
    c: usize,
    rounds: i128,
) {
    let add = rounds.checked_mul(QUANTUM).unwrap_or(CREDIT_CAP);
    for key in &class.active {
        let Some(repo) = repos.get_mut(key) else {
            continue;
        };
        if head_ready(&shared.limits, class, repo, c) {
            repo.deficit[c] = repo.deficit[c].saturating_add(add).min(CREDIT_CAP);
        }
    }
}

/// The smaller of two optional credit requirements; `None` means nothing pending.
fn earliest(current: Option<i128>, next: Option<i128>) -> Option<i128> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (single, None) | (None, single) => single,
    }
}

/// Moves one waiter to the granted state, charging its class, storage, and
/// repository counts and debiting the predicted cost.
fn grant(
    shared: &Arc<Shared>,
    class: &mut ClassCore,
    repo: &mut RepoCore,
    key: u64,
    c: usize,
    waiter: Waiter,
) {
    class.running += 1;
    if waiter.resources == WorkResources::Storage {
        class.storage_running += 1;
    }
    repo.running[c] += 1;
    repo.deficit[c] = repo
        .deficit[c]
        .checked_sub(i128::from(waiter.predicted))
        .unwrap_or(i128::MIN);
    issue(shared, ORDINARY_CLASSES[c], waiter);
}

/// Dispatches the control FIFO: strictly first come first served, bounded by
/// the control slots, and never blocked by ordinary admission.
fn dispatch_control(shared: &Arc<Shared>, core: &mut Core, now: Instant) {
    while core.control_running < shared.limits.control.slots {
        let Some(waiter) = core.control_queue.pop_front() else {
            return;
        };
        if waiter.deadline <= now {
            refuse(waiter, limit("control queue wait exceeded its admission bound"));
            continue;
        }
        core.control_running += 1;
        issue(shared, RequestClass::Control, waiter);
    }
}

fn dispatch_all(shared: &Arc<Shared>, core: &mut Core, now: Instant) {
    dispatch_control(shared, core, now);
    for c in 0..ORDINARY {
        dispatch_class(shared, core, c, now);
    }
}

/// Converts a waiter into a ticket. The queued payload reservations are
/// released here, at the transfer to admitted ownership.
fn issue(shared: &Arc<Shared>, class: RequestClass, waiter: Waiter) {
    let Waiter {
        repo,
        slot,
        resources,
        predicted,
        request_bytes,
        process_payload,
        repo_payload,
        ..
    } = waiter;
    drop(process_payload);
    drop(repo_payload);
    let ticket = Ticket {
        shared: Arc::clone(shared),
        repo,
        class,
        resources,
        predicted,
        request_bytes,
        measured: 0,
    };
    publish(&slot, SlotState::Granted(ticket));
}

fn refuse(waiter: Waiter, error: CoreError) {
    publish(&waiter.slot, SlotState::Refused(error));
}

fn publish(slot: &Slot, state: SlotState) {
    *lock_state(slot) = state;
    slot.notify.notify_one();
}

fn take_state(slot: &Slot) -> SlotState {
    std::mem::replace(&mut *lock_state(slot), SlotState::Waiting)
}

fn lock_state(slot: &Slot) -> MutexGuard<'_, SlotState> {
    slot.state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn remove_waiter(core: &mut Core, class: RequestClass, repo: u64, id: u64) -> Option<Waiter> {
    match ordinary_index(class) {
        None => take_from(&mut core.control_queue, id),
        Some(c) => {
            let repo_core = core.repos.get_mut(&repo)?;
            let removed = take_from(&mut repo_core.queues[c], id)?;
            core.classes[c].queued = core.classes[c].queued.saturating_sub(1);
            Some(removed)
        }
    }
}

fn take_from(queue: &mut VecDeque<Waiter>, id: u64) -> Option<Waiter> {
    let index = queue.iter().position(|waiter| waiter.id == id)?;
    queue.remove(index)
}

/// Settles a finished ticket. The grant already debited the prediction, which
/// is the floor of the charge and is never refunded. Only the overrun beyond
/// the prediction is charged here: measured work plus request bytes, minus the
/// prediction. So the total charge is request bytes plus the larger of measured
/// work and the base prediction. Overflow saturates to the largest debt.
fn settle(deficit: i128, ticket: &Ticket) -> i128 {
    let total = ticket
        .measured
        .checked_add(u128::from(ticket.request_bytes))
        .unwrap_or(u128::MAX);
    let overrun = total.checked_sub(u128::from(ticket.predicted)).unwrap_or(0);
    let overrun = i128::try_from(overrun).unwrap_or(i128::MAX);
    deficit.checked_sub(overrun).unwrap_or(i128::MIN)
}

fn predicted_cost(request_bytes: u64) -> Result<u64, CoreError> {
    PREDICTED_BASE
        .checked_add(request_bytes)
        .ok_or_else(|| limit("request cost overflows the scheduler"))
}

fn ordinary_index(class: RequestClass) -> Option<usize> {
    match class {
        RequestClass::Control => None,
        RequestClass::Interactive => Some(INTERACTIVE),
        RequestClass::Bulk => Some(BULK),
        RequestClass::Hook => Some(HOOK),
        RequestClass::Maintenance => Some(MAINTENANCE),
    }
}

fn queue_full(class: RequestClass) -> CoreError {
    limit(format!("{class:?} admission queue is full"))
}

fn closed_error() -> CoreError {
    CoreError::new(ErrorCode::ECancelled, "admission is closed")
}
