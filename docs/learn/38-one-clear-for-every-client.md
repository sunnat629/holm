# Lesson 38: One clear for every client

## Why this matters

A copied password sits on the clipboard where any app can read it. Holm copies from three
places: the CLI, the shell and the GUI. If each had its own clear code, one could be
wrong while the others were right. So the rule lives once, in `holm-platform`.

## What we built

`crates/holm-platform/src/clip_clear.rs` holds:

- `Clip`: a small trait with set, check and clear. The real one is `ConcealedClipboard`
  (arboard, macOS). Tests use a fake, so no test touches the real clipboard.
- `clear_copied`: clears only if the clipboard still holds Holm's value. If another app
  copied since, it leaves that alone. If it cannot read the clipboard, it clears anyway
  and says it could not check. The clipboard fails closed.
- `PendingClear`: owns the copied value and a deadline. The GUI keeps one, and runs it
  from the frame tick, on every lock and on quit.

The CLI wait, the shell prompt deadline and the GUI all call the same code. The GUI time
comes from the vault's `clipboard_clear_secs`, clamped to 5..=90.

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

The deadline is checked on a monotonic clock (`Instant`, never goes back) and on the wall
clock (`SystemTime`). `is_due` is true if either passed. A Mac asleep may stop the
monotonic clock, while the wall clock keeps going, so the wall clock catches the sleep.
Kotlin parallel: `SystemClock.elapsedRealtime()` (monotonic, counts sleep on Android) against
`System.currentTimeMillis()` (wall, can be changed by the user). Holm uses both and clears
when either says so, because clearing early is safe and clearing late is not.

A clock is also a trait here, so a test moves time forward without sleeping.

### 4. `forbid(unsafe_code)` as a fence

The file starts with `#![forbid(unsafe_code)]`. The crate allows unsafe elsewhere only
for one OS call; this module can never grow any, and the compiler enforces it.

## Exercises

1. Add a test that a `PendingClear` is due when only the wall clock has passed. Check:
   `cargo test -p holm-platform --locked clip_clear`
2. Change the clear to skip when `check` cannot read the clipboard. Which test fails?
   Put it back. Check: `cargo test --workspace --locked`

## Read next

- [Lesson 37: Hold to reveal](37-hold-to-reveal.md)
- [`std::time::Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html)
