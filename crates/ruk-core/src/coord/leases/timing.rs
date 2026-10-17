//! Frozen lease lifetimes from the reference production profile.
//!
//! Interactive view/cursor leases last 30 seconds. Bulk, scratch, and export
//! leases renew their interval (at most 15 minutes) only on admitted progress,
//! cancel their owner after 30 seconds without progress, and die at two hours
//! total. All evaluation is pure over caller-supplied [`Instant`] pairs, so
//! the coordinator's rollback-safe [`Clock`] stays the only time source and
//! these rules are unit-testable without I/O.

use std::time::{Duration, Instant};

/// Interactive view/cursor authority: 30 seconds from creation, no renewal.
pub(crate) const INTERACTIVE_TTL: Duration = Duration::from_secs(30);

/// Bulk interval renewed only while the admitted owner makes progress.
pub(crate) const BULK_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Bulk owner silence that cancels the owner: 30 seconds without progress.
pub(crate) const BULK_NO_PROGRESS: Duration = Duration::from_secs(30);

/// Bulk total logical lifetime: at most two hours; renewals never extend it.
pub(crate) const BULK_TOTAL: Duration = Duration::from_secs(2 * 60 * 60);

/// Gray byte allowance for one Mark cycle, grounded in the frozen control
/// frame bound ([`crate::MAX_CONTROL_FRAME_BYTES`]), not a fresh profile knob.
/// The `as` cast widens `usize` to `u64`: it cannot narrow on any supported
/// target (`u64` is at least as wide as `usize`), so no value change is possible.
pub(crate) const GRAY_ALLOWANCE_BYTES: u64 = crate::MAX_CONTROL_FRAME_BYTES as u64;

/// Authority state of one lease at a sampled instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Authority {
    /// Use is authorized; carries the current authority deadline.
    Live { deadline: Instant },
    /// Authority lapsed; the owner must observe cancellation. The RAII owner
    /// guard still retains protection until the owned task terminates.
    Expired,
}

impl Authority {
    /// Whether use is currently authorized.
    #[must_use]
    pub(crate) const fn is_live(self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

/// Evaluates an interactive lease created at `created` against `now`.
#[must_use]
pub(crate) fn interactive_authority(created: Instant, now: Instant) -> Authority {
    match created.checked_add(INTERACTIVE_TTL) {
        Some(deadline) if now < deadline => Authority::Live { deadline },
        _ => Authority::Expired,
    }
}

/// Evaluates a bulk lease created at `created` with last admitted progress at
/// `progress` against `now`.
///
/// A bulk lease that has never admitted work (`progress == created`) lives
/// only for the no-progress window `BULK_NO_PROGRESS`: the owner has 30
/// seconds to produce its first admitted page. Once work is admitted, each
/// progress stamp re-arms the full `BULK_INTERVAL` (15 minutes), and every
/// deadline stays capped at `created + BULK_TOTAL`. Checked addition
/// overflow fails closed to `Expired`; callers surface counter overflow
/// separately as `E_CAPACITY`.
#[must_use]
pub(crate) fn bulk_authority(created: Instant, progress: Instant, now: Instant) -> Authority {
    let Some(total) = created.checked_add(BULK_TOTAL) else {
        return Authority::Expired;
    };
    if now >= total {
        return Authority::Expired;
    }
    // A lease that has never admitted work renews on the no-progress window:
    // contact alone keeps it alive for 30 seconds at a time, matching the
    // profile's "no-progress timeout is 30 seconds". The first admitted page
    // or report re-arms the full interval.
    let window = if progress == created {
        BULK_NO_PROGRESS
    } else {
        BULK_INTERVAL
    };
    let interval = match progress.checked_add(window) {
        Some(interval) => interval.min(total),
        None => total,
    };
    if now < interval {
        Authority::Live { deadline: interval }
    } else {
        Authority::Expired
    }
}
/// Whether a bulk owner that last reported admitted progress at `progress`
/// has been silent long enough to cancel at `now`.
#[must_use]
pub(crate) fn bulk_progress_lapsed(progress: Instant, now: Instant) -> bool {
    match progress.checked_add(BULK_NO_PROGRESS) {
        Some(silence) => now >= silence,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst() -> Instant {
        Instant::now()
    }

    #[test]
    fn interactive_expires_at_thirty_seconds() {
        let created = inst();
        match interactive_authority(created, created) {
            Authority::Live { deadline } => assert_eq!(deadline, created + INTERACTIVE_TTL),
            Authority::Expired => panic!("fresh interactive lease must be live"),
        }
        assert!(interactive_authority(created, created).is_live());
        assert!(interactive_authority(created, created + INTERACTIVE_TTL - Duration::from_nanos(1)).is_live());
        assert!(!interactive_authority(created, created + INTERACTIVE_TTL).is_live());
    }

    #[test]
    fn bulk_total_caps_interval_renewal() {
        let created = inst();
        // Fresh progress just before the total deadline still dies at total.
        let late = created + BULK_TOTAL - Duration::from_secs(1);
        assert!(bulk_authority(created, late, late).is_live());
        assert!(!bulk_authority(created, late, created + BULK_TOTAL).is_live());
        // Renewal after total is dead even with brand-new progress.
        assert!(!bulk_authority(created, created + BULK_TOTAL, created + BULK_TOTAL).is_live());
    }

    #[test]
    fn bulk_no_progress_lapses_at_thirty_seconds() {
        let progress = inst();
        assert!(!bulk_progress_lapsed(progress, progress));
        assert!(!bulk_progress_lapsed(progress, progress + BULK_NO_PROGRESS - Duration::from_nanos(1)));
        assert!(bulk_progress_lapsed(progress, progress + BULK_NO_PROGRESS));
    }

    #[test]
    fn bulk_interval_renews_on_progress() {
        let created = inst();
        let first = created + BULK_INTERVAL - Duration::from_secs(1);
        assert!(!bulk_authority(created, created, first).is_live());
        // Admitted progress just in time re-arms the interval.
        assert!(bulk_authority(created, first, first).is_live());
    }
}
