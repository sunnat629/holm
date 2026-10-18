# Lesson 14: Time and saturating maths

## What we built

Holm needs to measure two waits: the pause after failed unlocks, and the idle time before auto-lock. `clock.rs` holds a `Clock` trait, the real `SystemClock`, and `IdleTimer`. `throttle.rs` holds `delay_after`, `Throttle` (with `attempt`, the one way to run a guarded action) and `ThrottleStatus`. The code is in `crates/holm-core/src/`.

Honesty note: the throttle lives in memory, so restarting Holm resets it. It slows a person at the keyboard; the real defence against offline guessing is Argon2id (lesson 04 and the crypto crate).

## Rust ideas in this task

### `Duration`, and two kinds of clock

```rust
pub trait Clock: Send {
    fn now_unix(&self) -> Timestamp;   // wall clock: stamps, and "lock sooner"
    fn monotonic(&self) -> Duration;   // for every wait
}
```

- `Duration` is a span of time (seconds plus nanoseconds), not a point in time. Holm's monotonic clock is just "how long since the clock was made", as a `Duration`.
- `SystemTime` is the wall clock. The user, or an attacker with a few minutes at the machine, can set it back. `Instant` is monotonic: it never goes backwards, whatever the wall clock does.
- So the throttle uses only `monotonic()`. If it used wall time, setting the clock back an hour would erase a 60-second wait, and a quick brute-force script would not need to wait at all.
- `Instant` has a catch: on macOS and Linux it may not count time asleep. So `IdleTimer` also records wall time, and locks when **either** the monotonic idle time **or** a forward wall-clock gap reaches the limit. A backward wall jump gives a gap of zero and is ignored, so wall time can only make the lock come sooner, never later.
- `SystemTime::duration_since` returns a `Result`, because the time may be before 1970. Holm turns that error into 0.

In Kotlin you'd write: `System.nanoTime()` for waits (monotonic) and `System.currentTimeMillis()` for stamps (wall). Kotlin's `TimeSource.Monotonic` is the same split. Rust puts the two in different types, so you cannot mix them by accident.

### `saturating_*` and `checked_*`

```rust
let secs = 1u64.checked_shl(exp).map_or(MAX_DELAY_SECS, |v| v.min(MAX_DELAY_SECS));
self.failures = self.failures.saturating_add(1);
now.saturating_sub(self.last)
```

- In a release build, `a + b` on integers wraps silently; in a debug build it panics. Neither is acceptable for a security counter.
- `saturating_add` stops at the maximum instead. After `u32::MAX` failures the count stays there, it never wraps to 0 and unlocks the throttle.
- `checked_shl` returns `None` when the shift is too big, and the code turns `None` into the 60 s cap. `u32::MAX` failures give 60 s, with no panic.
- `Duration::saturating_sub` gives zero when the result would be negative, so a `now` earlier than `last` is harmless.

In Kotlin you'd write: `Math.addExact(a, b)` throws on overflow (the `checked` idea), and there is no standard saturating add, so you write `if (a > Int.MAX_VALUE - b) Int.MAX_VALUE else a + b` by hand.

### `Default`

```rust
#[derive(Debug, Default)]
pub struct Throttle { failures: u32, not_before: Option<Duration> }
```

- `#[derive(Default)]` fills every field with its own default: `0` and `None`. That is exactly "no failures, no wait", so `new()` is just `Self::default()`.
- The fields are private. Outside code can only call `record_failure` and `record_success`, so it cannot set `failures` to 0 by hand.

In Kotlin you'd write: a data class with default arguments, `data class Throttle(val failures: Int = 0, ...)`. That one has a public `copy(failures = 0)`; the Rust struct does not.

### A trait as a test seam

```rust
#[cfg(test)]
pub(crate) struct FakeClock {
    unix: Arc<AtomicI64>,
    mono_nanos: Arc<AtomicU64>,
}
```

- Code that needs the time takes a `&dyn Clock`, not `Instant::now()`. `FakeClock` holds `Arc`s of atomics, so a test keeps one handle and moves time with `advance` and `set_unix`, while the code under test holds another handle (`Clone` copies the `Arc`, not the number).
- `#[cfg(test)]` means the struct is not compiled into the release library at all.
- A test of a 60 s wait takes microseconds and is exact. A simulated sleep is `set_unix(+8 h)` with `advance(1 s)`: wall time jumps, monotonic time barely moves, and the idle timer must lock.

In Kotlin you'd write: `interface Clock { fun now(): Long }` with a `FakeClock` in the test source set, or `kotlinx-datetime`'s `Clock` with a test implementation. Same pattern.

### The `Send` bound

```rust
pub trait Clock: Send {
```

- `: Send` after the trait name says every type that implements `Clock` must be safe to move to another thread. The GUI will probably hold the vault on one thread and run timers on another.
- The compiler checks it for each implementation. `Arc<AtomicI64>` is `Send`, so `FakeClock` passes. An `Rc<Cell<i64>>` field would fail to compile.

In Kotlin you'd write: nothing. The JVM lets you share any object across threads, and thread safety is a convention you document. In Rust it is a type-level fact.

### One door for guarded actions

```rust
pub fn attempt<T, E>(&mut self, now: Duration, f: impl FnOnce() -> Result<T, E>)
    -> Result<T, Throttled<E>>
```

- `impl FnOnce() -> Result<T, E>` takes a closure that runs at most once. `attempt` refuses without calling it while a wait is active, counts the failure **before** calling it, and resets only on `Ok`.
- `check` and `record_failure` are private, so a caller cannot forget one of them or skip the count with an early `?`.

In Kotlin you'd write: `fun <T> attempt(f: () -> T): T` with `try/finally`. Rust makes the helper methods private so the safe path is the only path.

## Why this matters for security

Every unlock error counts as a failure (F16), so a damaged file cannot be used to retry without a pause. Task 7 routes unlock through `attempt`, which makes that rule hard to forget. The throttle runs on monotonic time and the idle timer can only be made shorter by the wall clock, so changing the date never helps an attacker.

## Try it

1. Run the clock and throttle tests.
   - Run: `cargo test -p holm-core --locked --lib -- throttle clock`
   - Check: the last line says `21 passed; 0 failed`.
   - Undo: nothing to undo, it only reads.
2. Break the cap and watch the table test catch it.
   - Run: `sed -i.bak 's/MAX_DELAY_SECS: u64 = 60/MAX_DELAY_SECS: u64 = 600/' crates/holm-core/src/throttle.rs && cargo test -p holm-core --locked --lib delay_table`
   - Check: `delay_table ... FAILED`, and the message names `failures 8`.
   - Undo: `rm crates/holm-core/src/throttle.rs.bak && git checkout -- crates/holm-core/src/throttle.rs`
3. Replace a saturating add with a plain one and see the overflow test panic.
   - Run: `sed -i.bak 's/self.failures.saturating_add(1)/self.failures + 1/' crates/holm-core/src/throttle.rs && cargo test -p holm-core --locked --lib extreme_values`
   - Check: `extreme_values_do_not_overflow ... FAILED` with `attempt to add with overflow`.
   - Undo: `rm crates/holm-core/src/throttle.rs.bak && git checkout -- crates/holm-core/src/throttle.rs`

## Read next

- [std::time::Instant](https://doc.rust-lang.org/std/time/struct.Instant.html), and why it differs from `SystemTime`.
- [std::time::Duration](https://doc.rust-lang.org/std/time/struct.Duration.html), see `saturating_add` and `checked_add`.
- [The Rust book, ch16-04: Send and Sync](https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html)

Next lesson: none yet. Lesson 15 arrives with the next task.
