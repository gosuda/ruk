//! Coordinator publication lane and bounded group commit.
//!
//! Provides the single serialized publication owner per open repository, with
//! bounded group commit (2ms linger, at most 64 requests, at most 64 MiB ordinary
//! aggregation cap). Enforces sole publication ownership, replay-first idempotency,
//! seal-time authority and policy validation, workspace fencing, semantic ref
//! transactions, oplog and 7-day receipt generation, and fail-closed storage
//! error handling with consumed-spool semantics.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use crate::coord::admission::run_blocking;
use crate::coord::cancel::{Cancel, cancellation};
use crate::coord::clock::Clock;
use crate::coord::policy::PolicySource;
use crate::coord::session::SessionTable;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::Reply;
use crate::store::Store;

mod batch;
mod candidate;
mod commit;

#[cfg(test)]
mod tests;

pub(crate) use batch::{
    BatchAccumulator, BatchItem, MAX_BATCH_BYTES, MAX_BATCH_LINGER, MAX_BATCH_REQUESTS,
};
pub(crate) use candidate::{InternalCandidate, InternalPayload, MutationCandidate, WorkspaceFence};
pub(crate) use commit::{StoreFailureKind, classify_store_error, commit_batch};

/// Queue bound for pending submissions to the publication lane.
///
/// Bounded by the reference profile's class queue limits; admission precedes the lane.
pub(crate) const LANE_QUEUE_BOUND: usize = 256;

/// Internal commands processed by the publication lane worker.
pub(crate) enum LaneCommand {
    Submit(BatchItem),
    Close,
}

/// Shared cloneable handle to the repository publication lane.
#[derive(Clone)]
pub(crate) struct PublicationLane {
    tx: mpsc::Sender<LaneCommand>,
    closed: Arc<AtomicBool>,
    closed_reason: Arc<Mutex<Option<String>>>,
}

impl PublicationLane {
    /// Submits an admitted mutation candidate for serialized publication.
    ///
    /// # Errors
    /// Returns `CoreError` if the lane is closed or if validation/publication fails.
    pub(crate) async fn submit_mutation(
        &self,
        candidate: MutationCandidate,
    ) -> Result<Reply, CoreError> {
        self.check_open()?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let item = BatchItem::Mutation {
            candidate: Box::new(candidate),
            reply_tx: Some(reply_tx),
        };

        self.tx
            .send(LaneCommand::Submit(item))
            .await
            .map_err(|_| self.closed_error())?;

        reply_rx.await.map_err(|_| self.closed_error())?
    }

    /// Submits an admitted coordinator-internal transaction for serialized publication.
    ///
    /// # Errors
    /// Returns `CoreError` if the lane is closed or if publication fails.
    pub(crate) async fn submit_internal(
        &self,
        candidate: InternalCandidate,
    ) -> Result<(), CoreError> {
        self.check_open()?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let item = BatchItem::Internal {
            candidate: Box::new(candidate),
            reply_tx: Some(reply_tx),
        };

        self.tx
            .send(LaneCommand::Submit(item))
            .await
            .map_err(|_| self.closed_error())?;

        reply_rx.await.map_err(|_| self.closed_error())?
    }

    /// Requests orderly closure of the publication lane.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.tx.try_send(LaneCommand::Close);
    }

    fn check_open(&self) -> Result<(), CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(self.closed_error());
        }
        Ok(())
    }

    fn closed_error(&self) -> CoreError {
        let reason = self
            .closed_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        let message = reason.unwrap_or_else(|| "publication lane is closed".to_owned());
        CoreError::new(ErrorCode::ECoordinatorUnresponsive, message)
    }
}

/// The single publication owner background runner.
pub(crate) struct PublicationLaneRunner {
    store: Arc<Store>,
    session_table: SessionTable,
    policy_source: Arc<PolicySource>,
    clock: Clock,
    rx: mpsc::Receiver<LaneCommand>,
    closed: Arc<AtomicBool>,
    closed_reason: Arc<Mutex<Option<String>>>,
}

impl PublicationLaneRunner {
    /// Runs the publication lane event loop until closed or cancelled, then
    /// drains every queued submission before returning.
    ///
    /// Shutdown never cancels an in-flight commit: each batch commits under
    /// a fresh uncancelled token, so orderly shutdown settles admitted work
    /// instead of failing it. The drain after the loop commits whatever the
    /// loop did not reach (a deferred item plus every submit still queued)
    /// the same way. Only a fatal storage failure stops the drain early and
    /// latches the lane.
    ///
    /// # Errors
    /// Returns `CoreError` if a fatal or ambiguous storage failure closes the lane.
    pub(crate) async fn run(mut self, cancel: Cancel) -> Result<(), CoreError> {
        let mut deferred: Option<BatchItem> = None;
        let outcome = self.run_loop(&cancel, &mut deferred).await;
        self.drain(deferred).await?;
        outcome
    }

    /// The batching event loop. Returns when the lane closes, the channel
    /// ends, or shutdown cancels a receive wait.
    async fn run_loop(
        &mut self,
        cancel: &Cancel,
        deferred: &mut Option<BatchItem>,
    ) -> Result<(), CoreError> {
        loop {
            cancel.check()?;

            if self.closed.load(Ordering::Acquire) {
                break;
            }

            // Retrieve the first item (either previously deferred or from the channel).
            let first_item = match deferred.take() {
                Some(item) => item,
                None => match cancel.until(self.rx.recv()).await? {
                    Some(LaneCommand::Submit(item)) => item,
                    Some(LaneCommand::Close) | None => break,
                },
            };

            let mut accumulator = BatchAccumulator::new();
            accumulator.add(first_item);

            // Collect additional items up to 2ms linger, 64 requests, or 64 MiB cap.
            if !accumulator.is_full() {
                let deadline = tokio::time::Instant::now() + MAX_BATCH_LINGER;

                while !accumulator.is_full() {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    let recv_res = tokio::time::timeout(remaining, self.rx.recv()).await;
                    match recv_res {
                        Ok(Some(LaneCommand::Submit(next_item))) => {
                            if accumulator.can_admit(&next_item) {
                                accumulator.add(next_item);
                            } else {
                                *deferred = Some(next_item);
                                break;
                            }
                        }
                        Ok(Some(LaneCommand::Close)) | Ok(None) => {
                            self.closed.store(true, Ordering::Release);
                            break;
                        }
                        Err(_elapsed) => {
                            break;
                        }
                    }
                }
            }

            let batch = accumulator.drain();
            if batch.is_empty() {
                continue;
            }
            self.commit_items(batch).await?;
        }

        Ok(())
    }

    /// Commits every submission the loop did not reach: a deferred overflow
    /// item plus each submit still queued, in accumulator-sized rounds.
    /// Close commands and a dead channel end the drain; anything committed
    /// reports to its original submitter.
    async fn drain(&mut self, deferred: Option<BatchItem>) -> Result<(), CoreError> {
        let mut accumulator = BatchAccumulator::new();
        let mut pending = deferred.is_some();
        if let Some(item) = deferred {
            accumulator.add(item);
        }
        while let Ok(LaneCommand::Submit(item)) = self.rx.try_recv() {
            if !accumulator.can_admit(&item) {
                let full = std::mem::replace(&mut accumulator, BatchAccumulator::new()).drain();
                self.commit_items(full).await?;
            }
            accumulator.add(item);
            pending = true;
        }
        if pending {
            self.commit_items(accumulator.drain()).await?;
        }
        Ok(())
    }

    /// Commits one batch under a fresh uncancelled token so shutdown waits
    /// settle admitted work. A fatal storage failure latches the lane and
    /// stops the caller; every other outcome already replied per item.
    async fn commit_items(&mut self, mut batch: Vec<BatchItem>) -> Result<(), CoreError> {
        let store = Arc::clone(&self.store);
        let session_table = self.session_table.clone();
        let policy_source = Arc::clone(&self.policy_source);
        let clock = self.clock.clone();
        let (_commit_guard, commit_cancel) = cancellation();

        let mut chosen_admitted = None;
        for item in &mut batch {
            let extracted = match item {
                BatchItem::Mutation { candidate, .. } => candidate.admitted.take(),
                BatchItem::Internal { candidate, .. } => candidate.admitted.take(),
            };
            if let Some(admitted) = extracted {
                chosen_admitted = Some(admitted);
                break;
            }
        }

        let commit_outcome = match chosen_admitted {
            Some(admitted) => {
                let (_admitted, outcome) =
                    run_blocking(admitted, commit_cancel, move |cancel_ref| {
                        commit_batch(
                            &store,
                            &session_table,
                            &policy_source,
                            &clock,
                            batch,
                            cancel_ref,
                        )
                    })
                    .await?;
                outcome
            }
            None => commit_batch(
                &store,
                &session_table,
                &policy_source,
                &clock,
                batch,
                &commit_cancel,
            ),
        };

        if let Err(err) = commit_outcome
            && err.code == ErrorCode::ECoordinatorUnresponsive
        {
            self.closed.store(true, Ordering::Release);
            if let Ok(mut guard) = self.closed_reason.lock() {
                *guard = Some(err.message.clone());
            }
            return Err(err);
        }
        Ok(())
    }
}

/// Creates a new publication lane and its background runner.
#[must_use]
pub(crate) fn create_publication_lane(
    store: Arc<Store>,
    session_table: SessionTable,
    policy_source: Arc<PolicySource>,
    clock: Clock,
) -> (PublicationLane, PublicationLaneRunner) {
    let (tx, rx) = mpsc::channel(LANE_QUEUE_BOUND);
    let closed = Arc::new(AtomicBool::new(false));
    let closed_reason = Arc::new(Mutex::new(None));

    let lane = PublicationLane {
        tx,
        closed: Arc::clone(&closed),
        closed_reason: Arc::clone(&closed_reason),
    };

    let runner = PublicationLaneRunner {
        store,
        session_table,
        policy_source,
        clock,
        rx,
        closed,
        closed_reason,
    };

    (lane, runner)
}
