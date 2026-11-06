//! One clipboard clear for every Holm client (CLI, shell and GUI).
//!
//! The clipboard is a [`Clip`] trait object, so the same clear runs against the real
//! pasteboard and against a test fake. [`clear_copied`] is the rule: empty the
//! clipboard if it still holds Holm's value or cannot be read (fail closed), and leave
//! another app's copy alone. [`PendingClear`] is a copied value waiting for its time.
//! This module uses the standard library, holm-core and zeroize only; it never touches
//! the system clipboard itself.

#![forbid(unsafe_code)]

use std::time::Duration;

use holm_core::clock::Clock;
use holm_core::item::Timestamp;
use holm_core::settings::{CLIPBOARD_MAX_SECS, CLIPBOARD_MIN_SECS};
use zeroize::Zeroizing;

/// Why the clipboard can't be used. No library text is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardError {
    /// There is no clipboard to talk to on this system, or it could not be opened.
    Unavailable,
    /// The clipboard was there but did not take the text.
    Refused,
}

/// What [`Clip::check`] found on the clipboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipCheck {
    /// Exactly the text asked about.
    Holds,
    /// Other text, something that is not text, or nothing.
    Other,
    /// The clipboard could not be read, so what it holds is unknown. A caller that
    /// put a secret there clears it anyway.
    Unreadable,
}

/// The clipboard as a trait, so tests swap in a fake one.
pub trait Clip {
    /// Puts `text` on the clipboard, marked concealed.
    ///
    /// # Errors
    /// [`ClipboardError`] if the clipboard did not take it.
    fn set(&mut self, text: &str) -> Result<(), ClipboardError>;
    /// Whether the clipboard holds exactly `text`, or could not be read.
    fn check(&mut self, text: &str) -> ClipCheck;
    /// Empties the clipboard.
    fn clear(&mut self);
}

/// What [`clear_copied`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearOutcome {
    /// Holm's value was there and is gone now.
    Cleared,
    /// Another app's copy replaced Holm's value, so nothing was touched.
    LeftAlone,
    /// The clipboard could not be read before the clear, but could after it.
    ClearedUnreadable,
    /// The clipboard could not be read after the clear.
    ClearedUnchecked,
    /// Holm's value is still there after the clear.
    StillThere,
}

/// The clear after a copy: empties the clipboard if it holds `value` or can't be read
/// (fail closed: Holm never leaves its value there because a read failed), and leaves
/// another app's copy alone.
pub fn clear_copied(clip: &mut dyn Clip, value: &str) -> ClearOutcome {
    let before = clip.check(value);
    if before == ClipCheck::Other {
        return ClearOutcome::LeftAlone;
    }
    clip.clear();
    match (before, clip.check(value)) {
        (_, ClipCheck::Holds) => ClearOutcome::StillThere,
        (_, ClipCheck::Unreadable) => ClearOutcome::ClearedUnchecked,
        (ClipCheck::Unreadable, ClipCheck::Other) => ClearOutcome::ClearedUnreadable,
        (_, ClipCheck::Other) => ClearOutcome::Cleared,
    }
}

/// A copied value waiting to be cleared. No `Debug`: it holds the value.
pub struct PendingClear {
    value: Zeroizing<String>,
    due_mono: Duration,
    due_wall: Timestamp,
}

impl PendingClear {
    /// Schedules the clear of `value` in `secs` seconds on `clock`, clamped to the
    /// settings range (`CLIPBOARD_MIN_SECS` to `CLIPBOARD_MAX_SECS`), so a bad number
    /// can neither clear at once nor never.
    #[must_use]
    pub fn new(value: Zeroizing<String>, secs: u32, clock: &dyn Clock) -> PendingClear {
        let secs = secs.clamp(CLIPBOARD_MIN_SECS, CLIPBOARD_MAX_SECS);
        PendingClear {
            value,
            due_mono: clock.monotonic() + Duration::from_secs(u64::from(secs)),
            due_wall: Timestamp(clock.now_unix().0.saturating_add(i64::from(secs))),
        }
    }

    /// Whether the time has come on either clock. The wall clock catches a sleep,
    /// when the monotonic clock stands still; it can only make the clear sooner.
    #[must_use]
    pub fn is_due(&self, clock: &dyn Clock) -> bool {
        clock.monotonic() >= self.due_mono || clock.now_unix() >= self.due_wall
    }

    /// The monotonic time of the clear, for a caller that waits until then.
    #[must_use]
    pub fn due(&self) -> Duration {
        self.due_mono
    }

    /// The value waiting to be cleared.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Runs the clear and wipes the value.
    pub fn run(self, clip: &mut dyn Clip) -> ClearOutcome {
        clear_copied(clip, &self.value)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct FakeClock {
        mono: Cell<Duration>,
        wall: Cell<i64>,
    }

    impl FakeClock {
        fn new() -> FakeClock {
            FakeClock {
                mono: Cell::new(Duration::from_secs(1000)),
                wall: Cell::new(1_700_000_000),
            }
        }

        fn advance(&self, mono: u64, wall: i64) {
            self.mono.set(self.mono.get() + Duration::from_secs(mono));
            self.wall.set(self.wall.get() + wall);
        }
    }

    // The trait demands `Send`; `Cell` is Send, so this is fine.
    impl Clock for FakeClock {
        fn now_unix(&self) -> Timestamp {
            Timestamp(self.wall.get())
        }

        fn monotonic(&self) -> Duration {
            self.mono.get()
        }
    }

    /// A clipboard with scripted reads.
    struct Fake {
        contents: Option<String>,
        reads: Vec<ClipCheck>,
        clears: usize,
        clear_works: bool,
    }

    impl Clip for Fake {
        fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
            self.contents = Some(text.to_owned());
            Ok(())
        }

        fn check(&mut self, text: &str) -> ClipCheck {
            if !self.reads.is_empty() {
                return self.reads.remove(0);
            }
            if self.contents.as_deref() == Some(text) {
                ClipCheck::Holds
            } else {
                ClipCheck::Other
            }
        }

        fn clear(&mut self) {
            self.clears += 1;
            if self.clear_works {
                self.contents = None;
            }
        }
    }

    fn fake(reads: &[ClipCheck], clear_works: bool) -> Fake {
        Fake {
            contents: Some("EXAMPLE".to_owned()),
            reads: reads.to_vec(),
            clears: 0,
            clear_works,
        }
    }

    #[test]
    fn clear_truth_table() {
        use ClipCheck::{Holds, Other, Unreadable};
        let cases = [
            (vec![Other], ClearOutcome::LeftAlone, 0),
            (vec![Holds, Other], ClearOutcome::Cleared, 1),
            (vec![Holds, Holds], ClearOutcome::StillThere, 1),
            (vec![Holds, Unreadable], ClearOutcome::ClearedUnchecked, 1),
            (vec![Unreadable, Other], ClearOutcome::ClearedUnreadable, 1),
            (vec![Unreadable, Holds], ClearOutcome::StillThere, 1),
            (
                vec![Unreadable, Unreadable],
                ClearOutcome::ClearedUnchecked,
                1,
            ),
        ];
        for (reads, want, clears) in cases {
            let mut clip = fake(&reads, true);
            assert_eq!(clear_copied(&mut clip, "EXAMPLE"), want, "{reads:?}");
            assert_eq!(clip.clears, clears, "{reads:?}");
        }
    }

    #[test]
    fn pending_clear_clamps_secs() {
        let clock = FakeClock::new();
        let low = PendingClear::new(Zeroizing::new("x".to_owned()), 0, &clock);
        assert_eq!(low.due(), Duration::from_secs(1005));
        let high = PendingClear::new(Zeroizing::new("x".to_owned()), 600, &clock);
        assert_eq!(high.due(), Duration::from_secs(1090));
        let huge = PendingClear::new(Zeroizing::new("x".to_owned()), u32::MAX, &clock);
        assert_eq!(huge.due(), Duration::from_secs(1090));
        clock.advance(4, 4);
        assert!(!low.is_due(&clock));
        clock.advance(1, 1);
        assert!(low.is_due(&clock));
    }

    #[test]
    fn pending_clear_due_on_wall_clock_after_sleep() {
        let clock = FakeClock::new();
        let p = PendingClear::new(Zeroizing::new("x".to_owned()), 30, &clock);
        clock.advance(1, 120);
        assert!(p.is_due(&clock));
    }

    #[test]
    fn pending_clear_due_on_monotonic_if_wall_set_back() {
        let clock = FakeClock::new();
        let p = PendingClear::new(Zeroizing::new("x".to_owned()), 30, &clock);
        clock.advance(30, -3600);
        assert!(p.is_due(&clock));
    }

    #[test]
    fn pending_clear_not_due_early() {
        let clock = FakeClock::new();
        let p = PendingClear::new(Zeroizing::new("x".to_owned()), 30, &clock);
        clock.advance(29, 29);
        assert!(!p.is_due(&clock));
    }

    #[test]
    fn run_clears_only_holms_value() {
        let clock = FakeClock::new();
        let p = PendingClear::new(Zeroizing::new("EXAMPLE".to_owned()), 30, &clock);
        assert_eq!(p.value(), "EXAMPLE");
        let mut clip = fake(&[], true);
        assert_eq!(p.run(&mut clip), ClearOutcome::Cleared);
        assert_eq!(clip.contents, None);

        let p = PendingClear::new(Zeroizing::new("EXAMPLE".to_owned()), 30, &clock);
        let mut other = fake(&[], true);
        other.contents = Some("someone else".to_owned());
        assert_eq!(p.run(&mut other), ClearOutcome::LeftAlone);
        assert_eq!(other.contents.as_deref(), Some("someone else"));
    }
}
