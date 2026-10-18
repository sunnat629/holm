//! Time sources and the idle timer.
//!
//! Everything that waits (the unlock throttle, auto-lock) reads the **monotonic**
//! clock, which only moves forward and ignores wall-clock changes. The wall clock is
//! used only to stamp items. Code asks a [`Clock`] for the time, so tests can swap in
//! a fake one.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::item::Timestamp;
use crate::settings::{AUTO_LOCK_MAX_SECS, AUTO_LOCK_MIN_SECS};

/// A source of time.
pub trait Clock: Send {
    /// Wall-clock seconds since 1970, for item timestamps only. Never use it to
    /// measure a wait: the user can change it.
    fn now_unix(&self) -> Timestamp;
    /// Time since the clock was created. Never decreases, whatever the wall clock does.
    fn monotonic(&self) -> Duration;
}

/// The real clock: [`Instant`] for `monotonic`, [`SystemTime`] for `now_unix`.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Starts the monotonic clock at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> Timestamp {
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            // Before 1970: report 0 rather than a negative or wrapped value.
            Err(_) => 0,
        };
        Timestamp(secs)
    }

    fn monotonic(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Tracks the last activity and says when auto-lock is due. All times are values from
/// [`Clock::monotonic`].
#[derive(Debug, Clone, Copy)]
pub struct IdleTimer {
    last: Duration,
}

impl IdleTimer {
    /// Starts the timer at `now`.
    #[must_use]
    pub fn new(now: Duration) -> Self {
        Self { last: now }
    }

    /// Records activity at `now`. A `now` earlier than the last touch is ignored, so
    /// the timer can never move backwards.
    pub fn touch(&mut self, now: Duration) {
        self.last = self.last.max(now);
    }

    /// True once `limit_secs` have passed since the last touch. The limit is clamped
    /// to the settings range (60 to 3600 s), so a bad value can never mean "never".
    #[must_use]
    pub fn expired(&self, now: Duration, limit_secs: u32) -> bool {
        let limit = limit_secs.clamp(AUTO_LOCK_MIN_SECS, AUTO_LOCK_MAX_SECS);
        now.saturating_sub(self.last) >= Duration::from_secs(u64::from(limit))
    }
}

/// A clock the tests control.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeClock {
    unix: std::sync::Arc<std::sync::atomic::AtomicI64>,
    mono_nanos: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn set_unix(&self, secs: i64) {
        self.unix.store(secs, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        let _ = self.mono_nanos.try_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |v| Some(v.saturating_add(nanos)),
        );
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp(self.unix.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.mono_nanos.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_expires_at_limit() {
        let t = IdleTimer::new(Duration::ZERO);
        assert!(!t.expired(Duration::from_secs(299), 300));
        assert!(t.expired(Duration::from_secs(300), 300));
    }

    #[test]
    fn touch_restarts_and_never_goes_back() {
        let mut t = IdleTimer::new(Duration::ZERO);
        t.touch(Duration::from_secs(200));
        assert!(!t.expired(Duration::from_secs(499), 300));
        t.touch(Duration::from_secs(10));
        assert!(!t.expired(Duration::from_secs(499), 300));
        assert!(t.expired(Duration::from_secs(500), 300));
    }

    #[test]
    fn limit_is_clamped_and_now_before_last_is_safe() {
        let t = IdleTimer::new(Duration::from_secs(100));
        assert!(!t.expired(Duration::from_secs(50), 60));
        assert!(t.expired(Duration::from_secs(160), 0));
        assert!(!t.expired(Duration::from_secs(3699), u32::MAX));
        assert!(t.expired(Duration::from_secs(3700), u32::MAX));
    }

    #[test]
    fn fake_clock_is_shared_between_handles() {
        let a = FakeClock::default();
        let b = a.clone();
        a.set_unix(-5);
        a.advance(Duration::from_secs(3));
        assert_eq!(b.now_unix(), Timestamp(-5));
        assert_eq!(b.monotonic(), Duration::from_secs(3));
        a.advance(Duration::MAX);
        assert!(b.monotonic() >= Duration::from_secs(3));
    }

    #[test]
    fn system_clock_monotonic_never_decreases() {
        let c = SystemClock::new();
        let mut prev = c.monotonic();
        for _ in 0..1000 {
            let now = c.monotonic();
            assert!(now >= prev);
            prev = now;
        }
        assert!(c.now_unix().0 > 1_600_000_000);
    }
}
