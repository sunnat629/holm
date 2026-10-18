//! The unlock throttle: free tries, then a growing wait.
//!
//! The first [`FREE_FAILURES`] − 1 failures cost nothing. From the third on, each failure
//! sets a wait of 2, 4, 8, 16, 32 s and then [`MAX_DELAY_SECS`]. Times are values from
//! [`Clock::monotonic`](crate::clock::Clock::monotonic), so changing the wall clock
//! does not shorten a wait. The caller must record **every** failed unlock attempt,
//! whatever the error, so a corrupt-file error cannot be used to dodge the throttle.

use std::time::Duration;

/// The failure count at which the waits begin.
pub const FREE_FAILURES: u32 = 3;
/// The longest wait in seconds.
pub const MAX_DELAY_SECS: u64 = 60;

/// The wait that follows the `failures`-th consecutive failure: zero below
/// [`FREE_FAILURES`], else `min(2^(failures-2), 60)` seconds.
#[must_use]
pub fn delay_after(failures: u32) -> Duration {
    if failures < FREE_FAILURES {
        return Duration::ZERO;
    }
    // failures >= 3, so the exponent is at least 1. 2^6 = 64 is already over the cap,
    // so any larger exponent is capped without shifting.
    let exp = failures.saturating_sub(2);
    let secs = 1u64
        .checked_shl(exp)
        .map_or(MAX_DELAY_SECS, |v| v.min(MAX_DELAY_SECS));
    Duration::from_secs(secs)
}

/// What a UI shows about the throttle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThrottleStatus {
    /// Failures since the last success.
    pub consecutive_failures: u32,
    /// Time left before the next attempt is allowed, if any.
    pub retry_after: Option<Duration>,
}

/// Counts failed unlocks and refuses attempts made too soon.
#[derive(Debug, Default)]
pub struct Throttle {
    failures: u32,
    not_before: Option<Duration>,
}

impl Throttle {
    /// A throttle with no failures.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `Ok` if an attempt may run at `now`; otherwise `Err` with the time left. Does
    /// not count anything.
    ///
    /// # Errors
    /// Returns the remaining wait while the throttle is active.
    pub fn check(&self, now: Duration) -> Result<(), Duration> {
        match self.not_before {
            Some(t) if now < t => Err(t.saturating_sub(now)),
            _ => Ok(()),
        }
    }

    /// Counts a failed attempt at `now` and sets the next wait.
    pub fn record_failure(&mut self, now: Duration) {
        self.failures = self.failures.saturating_add(1);
        let delay = delay_after(self.failures);
        self.not_before = (!delay.is_zero()).then(|| now.saturating_add(delay));
    }

    /// Clears the count and the wait after a successful unlock.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.not_before = None;
    }

    /// The failure count and the time left at `now`.
    #[must_use]
    pub fn status(&self, now: Duration) -> ThrottleStatus {
        ThrottleStatus {
            consecutive_failures: self.failures,
            retry_after: self.check(now).err(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn delay_table() {
        let want = [
            (1, 0),
            (2, 0),
            (3, 2),
            (4, 4),
            (5, 8),
            (6, 16),
            (7, 32),
            (8, 60),
            (9, 60),
        ];
        for (f, secs) in want {
            assert_eq!(delay_after(f), s(secs), "failures {f}");
        }
        assert_eq!(delay_after(0), Duration::ZERO);
        assert_eq!(delay_after(u32::MAX), s(60));
    }

    #[test]
    fn first_three_failures_have_no_wait() {
        let mut t = Throttle::new();
        t.record_failure(s(1));
        assert_eq!(t.check(s(1)), Ok(()));
        t.record_failure(s(1));
        assert_eq!(t.check(s(1)), Ok(()));
    }

    #[test]
    fn attempt_inside_delay_refused_with_time_left() {
        let mut t = Throttle::new();
        for _ in 0..3 {
            t.record_failure(s(10));
        }
        assert_eq!(t.check(s(11)), Err(s(1)));
        assert_eq!(t.check(s(12)), Ok(()));
    }

    #[test]
    fn check_does_not_count() {
        let mut t = Throttle::new();
        for _ in 0..3 {
            t.record_failure(s(10));
        }
        let _ = t.check(s(11));
        let _ = t.check(s(11));
        assert_eq!(t.status(s(11)).consecutive_failures, 3);
    }

    #[test]
    fn success_resets() {
        let mut t = Throttle::new();
        for _ in 0..5 {
            t.record_failure(s(10));
        }
        t.record_success();
        assert_eq!(t.check(s(10)), Ok(()));
        assert_eq!(
            t.status(s(10)),
            ThrottleStatus {
                consecutive_failures: 0,
                retry_after: None
            }
        );
    }

    #[test]
    fn status_reports_failures_and_wait() {
        let mut t = Throttle::new();
        for _ in 0..4 {
            t.record_failure(s(100));
        }
        assert_eq!(
            t.status(s(101)),
            ThrottleStatus {
                consecutive_failures: 4,
                retry_after: Some(s(3))
            }
        );
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let mut t = Throttle::new();
        for _ in 0..4 {
            t.record_failure(Duration::MAX);
        }
        assert_eq!(t.check(Duration::MAX), Ok(()));
        t.failures = u32::MAX;
        t.record_failure(s(0));
        assert_eq!(t.status(s(0)).consecutive_failures, u32::MAX);
    }
}
