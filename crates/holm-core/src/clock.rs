//! Time sources and the idle timer.
//!
//! The unlock throttle reads the **monotonic** clock only, which moves forward and
//! ignores wall-clock changes. Auto-lock reads both: the monotonic clock can stand
//! still while the computer sleeps, so [`IdleTimer`] also watches the wall clock, but
//! only to lock **sooner** (a forward jump counts, a backward jump is ignored). Code
//! asks a [`Clock`] for the time, so tests can swap in a fake one.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::item::Timestamp;
use crate::settings::{AUTO_LOCK_MAX_SECS, AUTO_LOCK_MIN_SECS};

/// A source of time.
pub trait Clock: Send {
    /// Wall-clock seconds since 1970. Used for item timestamps, and by [`IdleTimer`]
    /// only to lock sooner. Never use it to measure a wait that must not be shortened:
    /// the user can change it.
    fn now_unix(&self) -> Timestamp;
    /// Time since the clock was created. Never decreases, whatever the wall clock
    /// does. It may not advance while the computer sleeps (`Instant` on macOS and
    /// Linux leaves suspend out), which is why [`IdleTimer`] also checks wall time.
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

/// Tracks the last activity and says when auto-lock is due.
///
/// It records both clocks at each touch and reports expiry when **either** the
/// monotonic idle time **or** the forward wall-clock gap reaches the limit. The wall
/// clock catches a sleep (monotonic time stands still), and it can only make the lock
/// come sooner: setting the clock back gives a zero gap and the monotonic path still
/// fires.
#[derive(Debug, Clone, Copy)]
pub struct IdleTimer {
    last: Duration,
    last_unix: i64,
}

impl IdleTimer {
    /// Starts the timer at the clock's current time.
    #[must_use]
    pub fn new(clock: &dyn Clock) -> Self {
        Self {
            last: clock.monotonic(),
            last_unix: clock.now_unix().0,
        }
    }

    /// Records activity now. The monotonic mark never moves backwards. The wall mark
    /// is always replaced, so a backward wall jump cannot stretch the timer: the
    /// gap is measured from the new, earlier mark and the monotonic path still counts.
    pub fn touch(&mut self, clock: &dyn Clock) {
        self.last = self.last.max(clock.monotonic());
        self.last_unix = clock.now_unix().0;
    }

    /// True once `limit_secs` have passed since the last touch on the monotonic clock,
    /// or the wall clock has moved forward by that much. The limit is clamped to the
    /// settings range (60 to 3600 s), so a bad value can never mean "never".
    #[must_use]
    pub fn expired(&self, clock: &dyn Clock, limit_secs: u32) -> bool {
        let limit = limit_secs.clamp(AUTO_LOCK_MIN_SECS, AUTO_LOCK_MAX_SECS);
        let mono_idle = clock.monotonic().saturating_sub(self.last);
        let mono_hit = mono_idle >= Duration::from_secs(u64::from(limit));
        // A backward wall jump saturates to 0 and never reaches the limit.
        let wall_gap = clock.now_unix().0.saturating_sub(self.last_unix).max(0);
        let wall_hit = u64::try_from(wall_gap).unwrap_or(0) >= u64::from(limit);
        mono_hit || wall_hit
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

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn idle_expires_at_limit() {
        let c = FakeClock::default();
        let t = IdleTimer::new(&c);
        c.advance(secs(299));
        assert!(!t.expired(&c, 300));
        c.advance(secs(1));
        assert!(t.expired(&c, 300));
    }

    #[test]
    fn touch_restarts_the_timer() {
        let c = FakeClock::default();
        let mut t = IdleTimer::new(&c);
        c.advance(secs(200));
        t.touch(&c);
        c.advance(secs(299));
        assert!(!t.expired(&c, 300));
        c.advance(secs(1));
        assert!(t.expired(&c, 300));
    }

    #[test]
    fn limit_is_clamped() {
        let c = FakeClock::default();
        let t = IdleTimer::new(&c);
        c.advance(secs(60));
        assert!(t.expired(&c, 0));
        c.advance(secs(3539));
        assert!(!t.expired(&c, u32::MAX));
        c.advance(secs(1));
        assert!(t.expired(&c, u32::MAX));
    }

    #[test]
    fn simulated_sleep_locks_through_the_wall_clock() {
        let c = FakeClock::default();
        c.set_unix(1_000_000);
        let t = IdleTimer::new(&c);
        // Eight hours asleep: wall time jumps, monotonic barely moves.
        c.set_unix(1_000_000 + 8 * 3600);
        c.advance(secs(1));
        assert!(t.expired(&c, 300));
    }

    #[test]
    fn backward_wall_jump_neither_unlocks_nor_extends() {
        let c = FakeClock::default();
        c.set_unix(1_000_000);
        let t = IdleTimer::new(&c);
        c.set_unix(1_000_000 - 3600);
        c.advance(secs(299));
        assert!(!t.expired(&c, 300));
        c.advance(secs(1));
        assert!(t.expired(&c, 300), "monotonic path must still fire");
    }

    #[test]
    fn small_wall_drift_does_not_lock_early() {
        let c = FakeClock::default();
        c.set_unix(1_000_000);
        let t = IdleTimer::new(&c);
        c.set_unix(1_000_000 + 299);
        c.advance(secs(10));
        assert!(!t.expired(&c, 300));
    }

    #[test]
    fn extreme_wall_values_do_not_overflow() {
        let c = FakeClock::default();
        c.set_unix(i64::MIN);
        let t = IdleTimer::new(&c);
        c.set_unix(i64::MAX);
        assert!(t.expired(&c, 300));
        c.set_unix(i64::MIN);
        assert!(!t.expired(&c, 300));
    }

    #[test]
    fn set_unix_backwards_leaves_monotonic_unchanged() {
        let c = FakeClock::default();
        c.set_unix(1_000);
        c.advance(secs(7));
        c.set_unix(10);
        assert_eq!(c.monotonic(), secs(7));
        assert_eq!(c.now_unix(), Timestamp(10));
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
