//! Level-triggered cancellation tokens and fail-closed owner handles.
//!
//! A cancellation channel coordinates cooperative cancellation between the
//! repository coordinator, background workers, and long-lived operations.
//! Cancellation is level-triggered and irreversible: once cancelled, the token
//! remains permanently cancelled. Dropping the owner [`CancelHandle`] cancels
//! the channel automatically to enforce fail-closed semantics across owner
//! disconnects or unexpected task termination.

use std::future::poll_fn;
use std::pin::pin;
use std::task::Poll;

use tokio::sync::watch;

use crate::error::{CoreError, ErrorCode};

/// The exclusive owner half of a cancellation channel.
///
/// Dropping the handle cancels the channel, ensuring fail-closed semantics
/// on owner disconnect or abnormal termination. This handle cannot be cloned.
#[must_use = "dropping a CancelHandle cancels the operation"]
#[derive(Debug)]
pub struct CancelHandle {
    sender: watch::Sender<bool>,
}

/// The clonable observer half of a cancellation channel.
///
/// Receives cancellation signals broadcast by [`CancelHandle`]. Once
/// cancelled, the token remains permanently cancelled. Cloned instances share
/// the same underlying channel state.
#[derive(Clone, Debug)]
pub struct Cancel {
    receiver: watch::Receiver<bool>,
}

/// Creates a new cancellation pair starting in the uncancelled state.
pub fn cancellation() -> (CancelHandle, Cancel) {
    let (sender, receiver) = watch::channel(false);
    (CancelHandle { sender }, Cancel { receiver })
}

impl CancelHandle {
    /// Explicitly cancels the channel, notifying all current and future observers.
    ///
    /// This operation is level-triggered, irreversible, and idempotent.
    pub fn cancel(&self) {
        let _ = self.sender.send_if_modified(|cancelled| {
            if *cancelled {
                return false;
            }
            *cancelled = true;
            true
        });
    }
}

impl Drop for CancelHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl Cancel {
    fn is_cancelled(&self) -> bool {
        *self.receiver.borrow() || self.receiver.has_changed().is_err()
    }

    /// Returns `Ok(())` if uncancelled, or [`ErrorCode::ECancelled`] once cancelled.
    pub fn check(&self) -> Result<(), CoreError> {
        if self.is_cancelled() {
            return Err(CoreError::new(ErrorCode::ECancelled, "operation cancelled"));
        }
        Ok(())
    }

    /// Asynchronously waits until cancellation is signalled or the channel is closed.
    ///
    /// If the channel is already cancelled prior to this call, returns immediately.
    /// Channel closure is treated as cancellation and unblocks without spinning or panicking.
    pub async fn cancelled(&mut self) {
        if self.is_cancelled() {
            return;
        }
        let _ = self.receiver.wait_for(|&is_cancelled| is_cancelled).await;
    }

    /// Polls work until it completes or this scope is cancelled.
    ///
    /// Cancellation drops the future. The caller must discard partially read
    /// streams and keep blocking-work ownership inside the blocking closure.
    pub(crate) async fn until<F: Future>(&self, work: F) -> Result<F::Output, CoreError> {
        let mut observer = self.clone();
        let mut cancelled = pin!(observer.cancelled());
        let mut work = pin!(work);
        poll_fn(|cx| {
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(CoreError::new(
                    ErrorCode::ECancelled,
                    "operation cancelled",
                )));
            }
            work.as_mut().poll(cx).map(Ok)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::runtime::Builder;
    use tokio::time::{sleep, timeout};

    #[test]
    fn explicit_cancel_before_waiting() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, mut cancel) = cancellation();

            // Initial state: uncancelled
            assert_eq!(cancel.check(), Ok(()));

            // Explicitly cancel before any waiter registers
            handle.cancel();

            assert_eq!(
                cancel.check().expect_err("should be cancelled").code,
                ErrorCode::ECancelled
            );

            // Waiting on already-cancelled token returns immediately without blocking
            timeout(Duration::from_millis(500), cancel.cancelled())
                .await
                .expect("cancelled() should return immediately");

            // Repeated checks and waits remain permanently cancelled (level-triggered)
            assert_eq!(
                cancel.check().expect_err("should stay cancelled").code,
                ErrorCode::ECancelled
            );

            timeout(Duration::from_millis(500), cancel.cancelled())
                .await
                .expect("second cancelled() should also return immediately");
        });
    }

    #[test]
    fn dropping_owner_unblocks_waiter() {
        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, mut cancel) = cancellation();
            let clone = cancel.clone();

            let waiter_started = Arc::new(AtomicBool::new(false));
            let waiter_finished = Arc::new(AtomicBool::new(false));

            let started_flag = Arc::clone(&waiter_started);
            let finished_flag = Arc::clone(&waiter_finished);

            let waiter_task = tokio::spawn(async move {
                let mut c = clone;
                started_flag.store(true, Ordering::Release);
                c.cancelled().await;
                finished_flag.store(true, Ordering::Release);
            });

            // Wait until the spawned waiter has started
            while !waiter_started.load(Ordering::Acquire) {
                sleep(Duration::from_millis(5)).await;
            }

            // Give the waiter time to enter the wait_for loop
            sleep(Duration::from_millis(30)).await;

            // Before dropping the handle, waiter must not have finished
            assert!(!waiter_finished.load(Ordering::Acquire));
            assert_eq!(cancel.check(), Ok(()));

            // Drop the owner handle: fail-closed must trigger cancellation
            drop(handle);

            // Waiter must unblock and complete promptly
            timeout(Duration::from_secs(2), waiter_task)
                .await
                .expect("waiter should not time out")
                .expect("waiter task should join successfully");

            assert!(waiter_finished.load(Ordering::Acquire));
            assert_eq!(
                cancel
                    .check()
                    .expect_err("should be cancelled after drop")
                    .code,
                ErrorCode::ECancelled
            );

            // Another waiter on the remaining cancel also returns immediately
            timeout(Duration::from_millis(500), cancel.cancelled())
                .await
                .expect("cancel after drop must return immediately");
        });
    }

    #[test]
    fn cancellation_concurrent_with_registration_visible_to_all_clones() {
        let rt = Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, cancel) = cancellation();
            const NUM_WAITERS: usize = 8;

            let mut tasks = Vec::with_capacity(NUM_WAITERS);
            let registered_count = Arc::new(AtomicUsize::new(0));

            for _ in 0..NUM_WAITERS {
                let mut c = cancel.clone();
                let reg = Arc::clone(&registered_count);
                tasks.push(tokio::spawn(async move {
                    reg.fetch_add(1, Ordering::SeqCst);
                    c.cancelled().await;
                    // Immediately upon waking, check must observe ECancelled
                    assert_eq!(
                        c.check().expect_err("expected ECancelled after wake").code,
                        ErrorCode::ECancelled
                    );
                }));
            }

            // Concurrently cancel while registration and waiting is in-flight
            let handle_arc = Arc::new(handle);
            let h = Arc::clone(&handle_arc);
            let canceller_task = tokio::spawn(async move {
                // Ensure at least some tasks started registering
                while registered_count.load(Ordering::SeqCst) < NUM_WAITERS / 2 {
                    tokio::task::yield_now().await;
                }
                h.cancel();
            });

            canceller_task
                .await
                .expect("canceller task should complete");

            // All waiting clones must observe cancellation and unblock
            for task in tasks {
                timeout(Duration::from_secs(3), task)
                    .await
                    .expect("task timed out awaiting cancellation")
                    .expect("task panicked");
            }

            // Late-created clone after cancellation also immediately sees cancelled
            let mut late_clone = cancel.clone();
            assert_eq!(
                late_clone
                    .check()
                    .expect_err("expected ECancelled on late clone")
                    .code,
                ErrorCode::ECancelled
            );

            timeout(Duration::from_millis(500), late_clone.cancelled())
                .await
                .expect("late clone cancelled() must return immediately");

            // Repeated cancel calls are idempotent and never reset false
            handle_arc.cancel();
            assert_eq!(
                late_clone
                    .check()
                    .expect_err("expected ECancelled after idempotent cancel")
                    .code,
                ErrorCode::ECancelled
            );
        });
    }

    #[test]
    fn until_with_already_cancelled_token_never_polls_future() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, cancel) = cancellation();
            handle.cancel();

            let polled = Arc::new(AtomicBool::new(false));
            let polled_flag = Arc::clone(&polled);

            let work = std::future::poll_fn(move |_cx| {
                polled_flag.store(true, Ordering::SeqCst);
                Poll::Ready("polled")
            });

            let outcome = cancel.until(work).await;
            assert_eq!(
                outcome.expect_err("must be cancelled").code,
                ErrorCode::ECancelled
            );
            assert!(
                !polled.load(Ordering::SeqCst),
                "already-cancelled token must never poll supplied future"
            );
        });
    }

    #[derive(Debug)]
    struct TrackedResource {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TrackedResource {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn until_cancellation_drops_pending_future_and_releases_resource() {
        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, cancel) = cancellation();
            let dropped = Arc::new(AtomicBool::new(false));
            let resource = TrackedResource {
                dropped: Arc::clone(&dropped),
            };

            let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
            let work = async move {
                let _held = resource;
                rx.await.expect("channel stays open")
            };

            let task = tokio::spawn(async move { cancel.until(work).await });

            // Allow the work future to start and enter rx.await
            sleep(Duration::from_millis(30)).await;

            // Resource must still be held by the pending future
            assert!(
                !dropped.load(Ordering::SeqCst),
                "resource should not be dropped while pending"
            );

            // Trigger cancellation
            handle.cancel();

            let outcome = timeout(Duration::from_secs(2), task)
                .await
                .expect("task did not time out")
                .expect("task joined successfully");

            assert_eq!(
                outcome.expect_err("should return ECancelled").code,
                ErrorCode::ECancelled
            );

            // Cancellation must have dropped the pending future and released the resource
            assert!(
                dropped.load(Ordering::SeqCst),
                "cancellation must drop pending future and release owned resource"
            );

            drop(tx);
        });
    }

    #[test]
    fn until_completed_work_returns_result_while_owner_live() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let (handle, cancel) = cancellation();
            let (tx, rx) = tokio::sync::oneshot::channel::<&'static str>();

            let work = async move { rx.await.expect("channel receive") };

            tx.send("finished").expect("send to channel");

            let outcome = cancel.until(work).await;
            assert_eq!(outcome.expect("work should complete"), "finished");

            // Owner remains live and uncancelled
            assert_eq!(cancel.check(), Ok(()));

            // Explicit cancel afterwards still works normally
            handle.cancel();
            assert_eq!(
                cancel.check().expect_err("cancelled").code,
                ErrorCode::ECancelled
            );
        });
    }
}
