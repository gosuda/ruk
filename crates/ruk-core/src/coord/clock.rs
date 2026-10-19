//! Process-lifetime monotonic wall clock for the coordinator.
//!
//! Within a single coordinator process lifetime, effective wall time never
//! rolls backward: on every sample, it advances the prior effective wall by
//! the monotonic elapsed duration since the previous sample, taking the maximum
//! with the current OS wall time.
//!
//! This prevents wall-clock rollback from extending session or lease authority,
//! even when all active connections disconnect and sessions are reloaded.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jiff::SignedDuration;

use crate::error::{CoreError, ErrorCode};
use crate::protocol::Timestamp;

/// A sampled wall-and-monotonic timestamp pair for the coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Times {
    pub(crate) wall: jiff::Timestamp,
    pub(crate) mono: Instant,
}

impl Times {
    /// Creates a new `Times` sample from explicit wall and monotonic instants.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) const fn new(wall: jiff::Timestamp, mono: Instant) -> Self {
        Self { wall, mono }
    }

    /// Converts the effective wall time into a protocol [`Timestamp`].
    #[must_use]
    pub(crate) fn timestamp(&self) -> Timestamp {
        Timestamp::new(self.wall)
    }

    /// Checked addition of a signed duration to the effective wall time.
    ///
    /// # Errors
    /// [`ErrorCode::EIo`] on timestamp overflow.
    pub(crate) fn checked_add_signed(
        &self,
        duration: SignedDuration,
    ) -> Result<jiff::Timestamp, CoreError> {
        self.wall.checked_add(duration).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("effective wall clock overflow: {err}"),
            )
        })
    }
}

#[derive(Debug)]
enum ClockSource {
    System,
    #[cfg(test)]
    Injected {
        wall: jiff::Timestamp,
        mono: Instant,
    },
}

#[derive(Debug)]
struct ClockState {
    last_wall: jiff::Timestamp,
    last_mono: Instant,
    source: ClockSource,
}

/// The process-lifetime clock for a coordinator instance.
///
/// Sampling is thread-safe and guarantees that returned effective wall times
/// are monotonically non-decreasing.
#[derive(Clone, Debug)]
pub(crate) struct Clock {
    inner: Arc<Mutex<ClockState>>,
}

impl Clock {
    /// Creates a system-backed coordinator clock initialized to the current
    /// OS wall time and monotonic instant.
    #[must_use]
    pub(crate) fn system() -> Self {
        let wall = jiff::Timestamp::now();
        let mono = Instant::now();
        Self {
            inner: Arc::new(Mutex::new(ClockState {
                last_wall: wall,
                last_mono: mono,
                source: ClockSource::System,
            })),
        }
    }

    /// Samples current effective wall and monotonic times.
    ///
    /// The effective wall time advances by the monotonic elapsed time since
    /// the last sample and takes the maximum with the current OS wall time.
    ///
    /// # Errors
    /// [`ErrorCode::EIo`] if mutex poisoning occurs or if timestamp
    /// arithmetic overflows.
    pub(crate) fn sample(&self) -> Result<Times, CoreError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "clock lock poisoned"))?;

        let (raw_wall, raw_mono) = match state.source {
            ClockSource::System => (jiff::Timestamp::now(), Instant::now()),
            #[cfg(test)]
            ClockSource::Injected { wall, mono } => (wall, mono),
        };

        let elapsed_duration = raw_mono
            .checked_duration_since(state.last_mono)
            .unwrap_or(Duration::ZERO);

        let signed_elapsed = SignedDuration::try_from(elapsed_duration).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("elapsed monotonic duration overflow: {err}"),
            )
        })?;

        let advanced_wall = state.last_wall.checked_add(signed_elapsed).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("effective wall clock overflow: {err}"),
            )
        })?;

        let effective_wall = std::cmp::max(advanced_wall, raw_wall);

        state.last_wall = effective_wall;
        state.last_mono = raw_mono;

        Ok(Times {
            wall: effective_wall,
            mono: raw_mono,
        })
    }

    /// Creates a deterministic injected clock for testing.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected(initial_wall: jiff::Timestamp, initial_mono: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClockState {
                last_wall: initial_wall,
                last_mono: initial_mono,
                source: ClockSource::Injected {
                    wall: initial_wall,
                    mono: initial_mono,
                },
            })),
        }
    }

    /// Updates the injected time source for deterministic testing.
    #[cfg(test)]
    pub(crate) fn set_injected(&self, wall: jiff::Timestamp, mono: Instant) {
        if let Ok(mut state) = self.inner.lock() {
            state.source = ClockSource::Injected { wall, mono };
        }
    }

    /// Advances the injected clock by a monotonic duration and optionally sets
    /// an explicit OS wall timestamp (to test wall rollbacks or forward jumps).
    #[cfg(test)]
    pub(crate) fn advance_injected(
        &self,
        duration: Duration,
        os_wall_override: Option<jiff::Timestamp>,
    ) -> Result<Times, CoreError> {
        let (current_wall, current_mono) = {
            let state = self
                .inner
                .lock()
                .map_err(|_| CoreError::new(ErrorCode::EIo, "clock lock poisoned"))?;
            match state.source {
                ClockSource::System => (jiff::Timestamp::now(), Instant::now()),
                ClockSource::Injected { wall, mono } => (wall, mono),
            }
        };

        let new_mono = current_mono + duration;
        let new_wall = match os_wall_override {
            Some(w) => w,
            None => {
                let signed = SignedDuration::try_from(duration).map_err(|err| {
                    CoreError::new(ErrorCode::EIo, format!("duration overflow: {err}"))
                })?;
                current_wall.checked_add(signed).map_err(|err| {
                    CoreError::new(ErrorCode::EIo, format!("wall overflow: {err}"))
                })?
            }
        };

        self.set_injected(new_wall, new_mono);
        self.sample()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(iso: &str) -> jiff::Timestamp {
        iso.parse().expect("valid iso timestamp")
    }

    #[test]
    fn effective_wall_advances_monotonically_under_wall_rollback() {
        let start_wall = ts("2026-10-17T12:00:00Z");
        let start_mono = Instant::now();
        let clock = Clock::injected(start_wall, start_mono);

        // Initial sample is exact.
        let t0 = clock.sample().expect("initial sample");
        assert_eq!(t0.wall, start_wall);
        assert_eq!(t0.mono, start_mono);

        // 1 hour passes monotonically, but host OS clock rolls back by 2 hours.
        let rolled_back_wall = ts("2026-10-17T10:00:00Z");
        let t1 = clock
            .advance_injected(Duration::from_secs(3600), Some(rolled_back_wall))
            .expect("advance");

        let expected_wall = ts("2026-10-17T13:00:00Z");
        assert_eq!(
            t1.wall, expected_wall,
            "effective wall must advance by monotonic elapsed time even under OS rollback"
        );
        assert_eq!(t1.mono, start_mono + Duration::from_secs(3600));

        // Another 30 minutes pass monotonically; OS wall is still behind.
        let t2 = clock
            .advance_injected(Duration::from_secs(1800), Some(rolled_back_wall))
            .expect("advance 2");
        let expected_wall_2 = ts("2026-10-17T13:30:00Z");
        assert_eq!(t2.wall, expected_wall_2);
    }

    #[test]
    fn forward_jump_updates_baseline_and_continues_monotonically() {
        let start_wall = ts("2026-10-17T12:00:00Z");
        let start_mono = Instant::now();
        let clock = Clock::injected(start_wall, start_mono);

        // 1 second passes monotonically, but OS wall jumps forward 3 hours.
        let jumped_wall = ts("2026-10-17T15:00:00Z");
        let t1 = clock
            .advance_injected(Duration::from_secs(1), Some(jumped_wall))
            .expect("advance");
        assert_eq!(t1.wall, jumped_wall);

        // 10 seconds pass monotonically; OS wall stays at 15:00:00Z.
        let t2 = clock
            .advance_injected(Duration::from_secs(10), Some(jumped_wall))
            .expect("advance 2");
        let expected_wall = ts("2026-10-17T15:00:10Z");
        assert_eq!(t2.wall, expected_wall);
    }

    #[test]
    fn times_helpers_and_overflow_protection() {
        let t = Times::new(ts("2026-10-17T12:00:00Z"), Instant::now());
        assert_eq!(
            t.timestamp().to_string(),
            "\"2026-10-17T12:00:00Z\"".trim_matches('"')
        );

        let advanced = t
            .checked_add_signed(SignedDuration::from_hours(24))
            .expect("add 24h");
        assert_eq!(advanced, ts("2026-10-18T12:00:00Z"));

        let overflow_res = t.checked_add_signed(SignedDuration::MAX);
        assert!(overflow_res.is_err());
        assert_eq!(overflow_res.unwrap_err().code, ErrorCode::EIo);
    }

    #[test]
    fn concurrent_sampling_monotonicity() {
        let start_wall = ts("2026-10-17T12:00:00Z");
        let start_mono = Instant::now();
        let clock = Clock::injected(start_wall, start_mono);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let clk = clock.clone();
            handles.push(std::thread::spawn(move || {
                let mut prev_wall = start_wall;
                for _ in 0..100 {
                    let s = clk.sample().expect("sample");
                    assert!(
                        s.wall >= prev_wall,
                        "effective wall must be non-decreasing: {} vs prev {}",
                        s.wall,
                        prev_wall
                    );
                    prev_wall = s.wall;
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }
    }
}
