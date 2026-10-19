//! Bounded shared executor for daemon blocking work.
//!
//! One executor serves every repository lane of the daemon process.
//! Filesystem and store work runs on Tokio's blocking pool behind a
//! semaphore bulkhead, so a burst of bulk requests cannot starve control
//! traffic and no repository owns an idle thread.

use std::sync::Arc;

use tokio::sync::Semaphore;

use ruk_core::error::{CoreError, ErrorCode};

/// The shared bounded blocking pool of one daemon process.
#[derive(Clone, Debug)]
pub(crate) struct BoundedExecutor {
    /// Bulkhead permits for blocking work.
    semaphore: Arc<Semaphore>,
    /// The permit count, retained for introspection.
    #[expect(
        dead_code,
        reason = "no reader at this commit; retained for later changeset rows"
    )]
    pool_size: usize,
}

impl BoundedExecutor {
    /// Builds one executor with `pool_size` blocking permits.
    ///
    /// # Errors
    /// `E_INVALID` for a zero pool.
    pub(crate) fn new(pool_size: usize) -> Result<Self, CoreError> {
        if pool_size == 0 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "blocking pool needs at least one permit",
            ));
        }
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(pool_size)),
            pool_size,
        })
    }

    /// Returns the blocking permit count.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) const fn permits(&self) -> usize {
        self.pool_size
    }

    /// Runs `work` on the blocking pool behind one bulkhead permit.
    ///
    /// The permit covers the whole run: cancellation while queued reports
    /// `E_CANCELLED` without running the closure.
    ///
    /// # Errors
    /// `E_CANCELLED` when the queue sheds the request or the worker is
    /// cancelled, `E_IO` when the worker fails to report.
    pub(crate) async fn run<F, T>(&self, work: F) -> Result<T, CoreError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = std::sync::Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| {
                CoreError::new(ErrorCode::ECancelled, "blocking pool shed its queued work")
            })?;
        let outcome = tokio::task::spawn_blocking(work).await;
        drop(permit);
        match outcome {
            Ok(value) => Ok(value),
            Err(err) if err.is_cancelled() => Err(CoreError::new(
                ErrorCode::ECancelled,
                "blocking worker was cancelled",
            )),
            Err(err) => Err(CoreError::new(
                ErrorCode::EIo,
                format!("blocking worker failed to report: {err}"),
            )),
        }
    }
}
