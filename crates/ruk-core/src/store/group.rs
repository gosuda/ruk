//! Group commit for concurrent publications on one open store.
//!
//! Every [`Store::publish`] call queues its objects and facts before it asks
//! for the writer. The caller that holds the writer drains the queue and
//! commits it in groups. A group shares one publication transaction, so its
//! pending reservation, its segment syncs and its metadata commit are paid
//! once for all of its members instead of once per call.
//!
//! A group holds only submissions that cannot observe one another: no two
//! share a `(table, key)` fact, an object identity, or a delta base edge. Under
//! that rule the group's single transaction gives every member the outcome it
//! would have had alone, in arrival order. A submission that conflicts with the
//! open group starts the next group, so conflicting callers keep their order.
//!
//! When a group fails before its first append, nothing was written. Each member
//! is then published alone and receives its own outcome, so one stale
//! expectation or one refused quota cannot fail its neighbours. When a group
//! fails after the first append, the writer is closed and every member receives
//! that failure, as each would have on its own.
//!
//! Members of one group share the generation that group committed under.
//!
//! The queue holds at most `MAX_QUEUED` submissions. A publisher that finds it
//! full does not wait in the queue: once it holds the writer, it commits its
//! own publication alone. Nothing is dropped, and the queue's memory is bounded.
//!
//! `RUK_COMMIT_LINGER_MS` sets how long the writer holder waits before it
//! drains, so publishers that arrive in that window join its group. The default
//! is zero: a lone publisher pays no delay, and grouping still happens whenever
//! publishers queue behind a busy writer. The value is capped at 50 ms.

use std::collections::HashSet;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::error::ErrorCode;
use crate::ids::Oid;

use super::{
    EventContext, EventSource, FactMutation, FactTable, PreparedObject, Publication, Store,
    StoreError, WriterState,
};

/// Environment variable naming the linger window in milliseconds.
const LINGER_ENV: &str = "RUK_COMMIT_LINGER_MS";

/// Longest accepted linger window; a larger configured value is clamped.
const MAX_LINGER: Duration = Duration::from_millis(50);

pub(super) type Outcome = Result<Publication, StoreError>;

/// Most submissions the queue holds at once. See the module documentation for
/// the policy applied to a publisher that finds the queue full.
const MAX_QUEUED: usize = 64;

/// The linger window configured by `RUK_COMMIT_LINGER_MS`. Unset, empty or
/// unparsable values mean zero.
pub(super) fn linger_from_env() -> Duration {
    std::env::var(LINGER_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(Duration::ZERO, |millis| {
            Duration::from_millis(millis).min(MAX_LINGER)
        })
}

/// A duration as the nanosecond count the store keeps in an atomic.
pub(super) fn nanos(linger: Duration) -> u64 {
    u64::try_from(linger.as_nanos()).unwrap_or(u64::MAX)
}

/// Where one publisher finds the outcome of its submission.
#[derive(Default)]
pub(super) struct Ticket {
    outcome: Mutex<Option<Outcome>>,
}

impl Ticket {
    fn complete(&self, outcome: Outcome) {
        *lock(&self.outcome) = Some(outcome);
    }

    fn take(&self) -> Option<Outcome> {
        lock(&self.outcome).take()
    }
}

/// One publication waiting for the writer. `attribution` aligns 1:1 with
/// `facts`: the source and context each fact commits under.
pub(super) struct Submission {
    objects: Vec<PreparedObject>,
    facts: Vec<FactMutation>,
    attribution: Vec<(EventSource, EventContext)>,
    ticket: Arc<Ticket>,
}

/// The publications waiting for the writer, in arrival order.
#[derive(Default)]
pub(super) struct Queue {
    waiting: Mutex<Vec<Submission>>,
}

impl Queue {
    /// Queues a submission, or hands it back when the queue is full.
    fn push(
        &self,
        objects: Vec<PreparedObject>,
        facts: Vec<FactMutation>,
        attribution: Vec<(EventSource, EventContext)>,
    ) -> Result<Arc<Ticket>, Submission> {
        let ticket = Arc::new(Ticket::default());
        let submission = Submission {
            objects,
            facts,
            attribution,
            ticket: Arc::clone(&ticket),
        };
        let mut waiting = lock(&self.waiting);
        if waiting.len() >= MAX_QUEUED {
            return Err(submission);
        }
        waiting.push(submission);
        Ok(ticket)
    }

    /// Removes a submission whose publisher gave up before it was drained.
    fn withdraw(&self, ticket: &Arc<Ticket>) {
        lock(&self.waiting).retain(|submission| !Arc::ptr_eq(&submission.ticket, ticket));
    }

    fn take_all(&self) -> Vec<Submission> {
        std::mem::take(&mut *lock(&self.waiting))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Splits arrival-ordered submissions into groups. A submission that touches
/// anything the open group already touches starts the next group.
fn partition(batch: Vec<Submission>) -> Vec<Vec<Submission>> {
    let mut groups: Vec<Vec<Submission>> = Vec::new();
    let mut touched = Touched::default();
    for submission in batch {
        if groups.is_empty() || touched.conflicts_with(&submission) {
            groups.push(Vec::new());
            touched = Touched::default();
        }
        touched.add(&submission);
        if let Some(group) = groups.last_mut() {
            group.push(submission);
        }
    }
    groups
}

/// Every key the open group reads or writes.
#[derive(Default)]
struct Touched {
    facts: HashSet<(FactTable, Vec<u8>)>,
    objects: HashSet<Oid>,
    bases: HashSet<Oid>,
}

impl Touched {
    fn conflicts_with(&self, submission: &Submission) -> bool {
        submission
            .facts
            .iter()
            .any(|fact| self.facts.contains(&(fact.table, fact.key.clone())))
            || submission.objects.iter().any(|object| {
                let oid = object.oid();
                self.objects.contains(&oid) || self.bases.contains(&oid)
            })
            || submission
                .objects
                .iter()
                .filter_map(|object| object.base())
                .any(|base| self.objects.contains(&base))
    }

    fn add(&mut self, submission: &Submission) {
        for fact in &submission.facts {
            self.facts.insert((fact.table, fact.key.clone()));
        }
        for object in &submission.objects {
            self.objects.insert(object.oid());
            self.bases.extend(object.base());
        }
    }
}

impl StoreError {
    /// A copy with the same variant and error code, handed to every member of
    /// a failed group. A source that cannot be copied keeps its message.
    fn replica(&self) -> StoreError {
        match self {
            Self::Io(err) => Self::Io(io::Error::new(err.kind(), err.to_string())),
            Self::Invalid(detail) => Self::Invalid(detail.clone()),
            Self::Capacity(detail) => Self::Capacity(detail.clone()),
            Self::Limit(detail) => Self::Limit(detail.clone()),
            Self::Corrupt(detail) => Self::Corrupt(detail.clone()),
            Self::NotFound(detail) => Self::NotFound(detail.clone()),
            Self::StaleFact { table, key } => Self::StaleFact {
                table,
                key: key.clone(),
            },
            Self::WriterClosed(reason) => Self::WriterClosed(reason.clone()),
            Self::Version(detail) => Self::Version(detail.clone()),
            Self::ObjectFormat(detail) => Self::ObjectFormat(detail.clone()),
            other if other.code() == ErrorCode::ECorrupt => Self::Corrupt(other.to_string()),
            other => Self::Io(io::Error::other(other.to_string())),
        }
    }
}

impl Store {
    /// Queues one publication and commits the queue once the writer is held.
    ///
    /// The caller first checks whether a writer holder already committed its
    /// submission. Otherwise it is the holder: it lingers if configured, then
    /// drains and commits everything queued, its own submission included.
    pub(super) fn publish_grouped(
        &self,
        objects: Vec<PreparedObject>,
        facts: &[FactMutation],
        attribution: Vec<(EventSource, EventContext)>,
    ) -> Outcome {
        let ticket = match self.queue.push(objects, facts.to_vec(), attribution) {
            Ok(ticket) => ticket,
            Err(submission) => return self.publish_alone(submission),
        };
        let mut writer = match self.lock_writer() {
            Ok(writer) => writer,
            Err(err) => {
                self.queue.withdraw(&ticket);
                return Err(err);
            }
        };
        if let Some(outcome) = ticket.take() {
            return outcome;
        }
        let linger = Duration::from_nanos(self.commit_linger_nanos.load(Ordering::SeqCst));
        if !linger.is_zero() {
            std::thread::sleep(linger);
        }
        for group in partition(self.queue.take_all()) {
            self.commit_group(&mut writer, group);
        }
        ticket.take().unwrap_or_else(|| {
            Err(StoreError::WriterClosed(
                "publication was not committed".to_owned(),
            ))
        })
    }

    /// Commits one submission on its own, once the writer is held. Used when
    /// the queue is full; the submission never enters the queue. Everything
    /// already queued commits first, so the queue keeps its order.
    fn publish_alone(&self, submission: Submission) -> Outcome {
        let mut writer = self.lock_writer()?;
        for group in partition(self.queue.take_all()) {
            self.commit_group(&mut writer, group);
        }
        let objects: Vec<&PreparedObject> = submission.objects.iter().collect();
        self.publish_locked(
            &mut writer,
            &objects,
            &submission.facts,
            &submission.attribution,
        )
    }

    /// Commits one group and completes every member's ticket.
    fn commit_group(&self, writer: &mut WriterState, group: Vec<Submission>) {
        let outcomes = self.group_outcomes(writer, &group);
        for (submission, outcome) in group.iter().zip(outcomes) {
            submission.ticket.complete(outcome);
        }
    }

    /// The outcome of each member, in member order.
    fn group_outcomes(&self, writer: &mut WriterState, group: &[Submission]) -> Vec<Outcome> {
        if let Err(err) = self.refuse_if_quarantined() {
            return group.iter().map(|_| Err(err.replica())).collect();
        }
        if let Some(reason) = writer.closed.clone() {
            return group
                .iter()
                .map(|_| Err(StoreError::WriterClosed(reason.clone())))
                .collect();
        }
        if group.len() > 1 {
            let objects: Vec<&PreparedObject> = group
                .iter()
                .flat_map(|submission| submission.objects.iter())
                .collect();
            let facts: Vec<FactMutation> = group
                .iter()
                .flat_map(|submission| submission.facts.iter().cloned())
                .collect();
            let attribution: Vec<(EventSource, EventContext)> = group
                .iter()
                .flat_map(|submission| submission.attribution.iter().cloned())
                .collect();
            match self.publish_locked(writer, &objects, &facts, &attribution) {
                Ok(publication) => {
                    return group
                        .iter()
                        .map(|submission| {
                            Ok(Publication {
                                objects: submission
                                    .objects
                                    .iter()
                                    .map(PreparedObject::oid)
                                    .collect(),
                                generation: publication.generation,
                            })
                        })
                        .collect();
                }
                Err(err) if writer.closed.is_some() || self.quarantine() => {
                    return group.iter().map(|_| Err(err.replica())).collect();
                }
                // Nothing was appended, so each member is published alone
                // below and receives its own outcome.
                Err(_) => {}
            }
        }
        let mut outcomes = Vec::with_capacity(group.len());
        for submission in group {
            let objects: Vec<&PreparedObject> = submission.objects.iter().collect();
            outcomes.push(self.publish_locked(
                writer,
                &objects,
                &submission.facts,
                &submission.attribution,
            ));
        }
        outcomes
    }

    /// Sets the linger window. Test-only: production reads
    /// `RUK_COMMIT_LINGER_MS` once, when the store is opened or created.
    #[cfg(test)]
    pub(crate) fn set_commit_linger(&self, linger: Duration) {
        self.commit_linger_nanos
            .store(nanos(linger), Ordering::SeqCst);
    }
}
