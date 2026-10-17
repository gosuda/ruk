use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{CoreError, ErrorCode};

#[derive(Debug)]
pub(crate) struct ByteBudget {
    limit: u64,
    used: AtomicU64,
}

#[derive(Debug)]
#[must_use = "the reservation must live at least as long as the charged allocation"]
pub(crate) struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: u64,
}

impl ByteBudget {
    pub(crate) fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
        })
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> Result<ByteReservation, CoreError> {
        self.used
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map_err(|used| {
                CoreError::new(
                    ErrorCode::ELimit,
                    format!(
                        "byte budget exhausted: {} limit, {used} reserved, {bytes} requested",
                        self.limit
                    ),
                )
            })?;
        Ok(ByteReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        let previous = self.budget.used.fetch_sub(self.bytes, Ordering::SeqCst);
        assert!(
            previous >= self.bytes,
            "byte reservation accounting underflow"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn overflow_and_failed_admission_do_not_spend_capacity() {
        let budget = ByteBudget::new(u64::MAX);
        let held = budget.reserve(u64::MAX - 1).expect("initial reservation");
        assert_eq!(
            budget.reserve(2).expect_err("sum overflows").code,
            ErrorCode::ELimit
        );
        let last = budget.reserve(1).expect("failed reservation spent nothing");
        assert_eq!(
            budget.reserve(1).expect_err("full budget").code,
            ErrorCode::ELimit
        );
        drop(held);
        drop(last);
        let _all = budget.reserve(u64::MAX).expect("all capacity returned");
    }

    #[test]
    fn concurrent_reservations_cannot_overbook_or_release_each_other() {
        let budget = ByteBudget::new(7);
        let start = Arc::new(Barrier::new(17));
        let held = Arc::new(Barrier::new(17));
        let release = Arc::new(Barrier::new(17));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..16 {
                let budget = Arc::clone(&budget);
                let start = Arc::clone(&start);
                let held = Arc::clone(&held);
                let release = Arc::clone(&release);
                workers.push(scope.spawn(move || {
                    start.wait();
                    let reservation = budget.reserve(1);
                    held.wait();
                    release.wait();
                    reservation.is_ok()
                }));
            }
            start.wait();
            held.wait();
            let while_held = budget.reserve(1);
            release.wait();
            assert_eq!(
                while_held
                    .expect_err("held reservations fill the budget")
                    .code,
                ErrorCode::ELimit
            );
            let accepted = workers
                .into_iter()
                .map(|worker| usize::from(worker.join().expect("reservation worker")))
                .sum::<usize>();
            assert_eq!(accepted, 7);
        });
        let _all = budget
            .reserve(7)
            .expect("workers released their own reservations");
    }
}
