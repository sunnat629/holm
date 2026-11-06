# Lesson 38: One clear for every client

## Why this matters

A copied password sits on the clipboard where any app can read it. Holm copies from three
places: the CLI, the shell and the GUI. If each had its own clear code, one could be
wrong while the others were right. So the rule lives once, in `holm-platform`.

## What we built

`crates/holm-platform/src/clip_clear.rs` holds:

- `Clip`: a small trait with set, check and clear. The real clipboard implements it, and
  tests use a fake, so no test touches the real clipboard. This module never touches the
  system clipboard itself.
- `clear_copied`: clears only if the clipboard still holds Holm's value. If another app
  copied since, it leaves that alone. If it cannot read the clipboard, it clears anyway,
  and the `ClearOutcome` says it could not check. The clipboard fails closed.
- `PendingClear`: owns the copied value and when to clear it. The shell keeps one inside
  its `Pending`, next to the clipboard handle, and the GUI keeps one too.

The time comes from the vault's `clipboard_clear_secs`. `PendingClear::new` clamps it to
`CLIPBOARD_MIN_SECS..=CLIPBOARD_MAX_SECS` (5 to 90 seconds), so a bad number can neither
clear at once nor never.

## Rust ideas in this task

### 1. A trait in a shared crate

```rust
pub trait Clip {
    fn set(&mut self, text: &str) -> Result<(), ClipboardError>;
    fn check(&mut self, text: &str) -> ClipCheck;
    fn clear(&mut self);
}
```

Callers take `&mut dyn Clip`. Kotlin: an `interface Clipboard` in a shared Gradle module,
with the Android class and a test double both implementing it. Same idea, but Rust
checks it with no reflection and no mocking library: the fake is a plain struct.

### 2. Owning the secret with `run(self)`

`PendingClear::run(self)` takes `self` by value. After it runs, the value is gone: the
compiler stops anyone from running a clear twice or reading the value afterwards. The
`Zeroizing<String>` inside wipes the text when it drops. Kotlin cannot say "this object
is used up"; a `val` can still be read after use.

### 3. Two clocks

The deadline is checked on two clocks, both read through the `Clock` trait from
`holm-core`: `monotonic()` returns a `Duration` that never goes back, and `now_unix()`
returns a wall-clock `Timestamp`.

```rust
pub fn is_due(&self, clock: &dyn Clock) -> bool {
    clock.monotonic() >= self.due_mono || clock.now_unix() >= self.due_wall
}
```

`is_due` is true if either passed. A Mac asleep may stop the monotonic clock, while the wall
clock keeps going, so the wall clock catches the sleep.
Kotlin parallel: `SystemClock.elapsedRealtime()` (monotonic, counts sleep on Android) against
`System.currentTimeMillis()` (wall, can be changed by the user). Holm uses both and clears
when either says so, because clearing early is safe and clearing late is not.

Because the clock is a trait, the tests use a `FakeClock` and move time forward with
`advance` instead of sleeping.

### 4. `forbid(unsafe_code)` as a fence

The file starts with `#![forbid(unsafe_code)]`. Whatever the rest of the crate does, this
module can never contain `unsafe`. Unlike `deny`, a `forbid` cannot be turned off again by an
`#[allow]` further in, and the compiler enforces it.

## Try it

1. Add a test that `run` on a fake whose `clear_works` is `false` returns
   `ClearOutcome::StillThere`. Use `fake(&[], false)`. Check:
   `cargo test -p holm-platform --locked clip_clear`
2. Change `clear_copied` to skip when `check` cannot read the clipboard. Which test fails?
   Put it back. Check: `cargo test --workspace --locked`

## Read next

- Previous: [Lesson 37: Hold to reveal](37-hold-to-reveal.md)
- Next: Lesson 39, listed in [the index](README.md)
- [The index](README.md)
- [`std::time::Duration`](https://doc.rust-lang.org/std/time/struct.Duration.html)
