# Lesson 43: Listening to the OS

## Why this matters

A vault left open on a Mac that sleeps, locks its screen or switches user is open to
whoever wakes it. Holm already locks when idle and when minimised. This task makes it
lock when the operating system says "the person stepped away": sleep, screens asleep,
screen lock, and the session going inactive (fast user switch, logout).

The GUI hears these from AppKit. The terminal shell has no AppKit run loop, so it
notices a sleep another way: the clocks disagree when it wakes.

## What we built

- `crates/holm-platform/src/window.rs`: `LockEvents`. It adds four notification
  observers (three on the workspace center, one on the distributed center for
  `com.apple.screenIsLocked`). Each sets one shared flag. `take()` reads and resets it.
  Dropping `LockEvents` removes every observer.
- `crates/holm-core/src/clock.rs`: `SleepWatch`. It remembers both clocks and says
  "slept" when the wall clock gained more than `SLEEP_GAP_SECS` (5 s) on the monotonic
  clock since the last mark.
- `crates/holm-gui/src/app.rs`: `logic` takes the flag once per frame and passes it into
  `tick`, which locks before any vault row is drawn. `tick` also asks the `SleepWatch`.
- `crates/holm-cli/src/shell.rs` and `crates/holm-platform/src/tty.rs`: the prompt
  polls every 0.1 s with an interrupt that asks the `SleepWatch`. If it fires, the
  half-typed line is wiped and the shell locks.

All of it obeys the vault's `lock_on_sleep` setting, and every sleep lock clears a
copied password through `PendingClear`.

## Rust ideas in this task

### 1. Observers and blocks

Kotlin on Android:

```kotlin
val receiver = object : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) { screenOff.set(true) }
}
context.registerReceiver(receiver, IntentFilter(Intent.ACTION_SCREEN_OFF))
// later
context.unregisterReceiver(receiver)
```

macOS has the same shape. A notification center delivers named events, and you register
a callback. The callback is an Objective-C *block*, a closure the Objective-C runtime can
call. In Rust, `block2::RcBlock::new(move |_note| { ... })` makes one from a Rust
closure:

```rust
let flag = Arc::clone(&self.flag);
let block = RcBlock::new(move |_note: NonNull<NSNotification>| {
    flag.store(true, Ordering::SeqCst);
});
let token = unsafe {
    center.addObserverForName_object_queue_usingBlock(Some(name), None, Some(&queue), &block)
};
```

Two differences from Kotlin:

- **Unregistering is your job, and `Drop` does it.** Android leaks a receiver you forget
  to unregister and logs a warning. Here `impl Drop for LockEvents` removes every
  token, so the observers live exactly as long as the value. You cannot forget.
- **The call is `unsafe`.** The compiler cannot check Objective-C's rules, so each
  `unsafe` block has a `// SAFETY:` comment that says why this call is fine. Holm keeps
  all of them in one file, `window.rs`, and every other module forbids `unsafe`.

### 2. `Arc<AtomicBool>` as a one-bit mailbox

The block captures nothing but an `Arc<AtomicBool>`. It cannot see the vault, the
session or the window. The worst a notification can do is set one bit.

```rust
pub fn take(&self) -> bool {
    self.flag.swap(false, Ordering::SeqCst)
}
```

`swap(false)` reads the old value and clears it in one step, so an event that lands
between a read and a reset is never lost. The GUI calls `take` once per frame. Kotlin:
an `AtomicBoolean` with `getAndSet(false)`, written from the receiver and read on the
main thread.

Why `Arc` and not `Rc`? The block may be called by AppKit on any thread it chooses for
the queue. `Arc<AtomicBool>` is `Send + Sync`, so that is safe whatever thread it runs on.
`Rc<Cell<bool>>` would not compile there, which is the point.

`LockEvents::install()` returns `None` off the main thread
(`MainThreadMarker::new()?`), because AppKit's workspace belongs to the main thread.
`?` on an `Option` is Kotlin's `?: return null`.

### 3. The two clocks

A Mac asleep stops the monotonic clock (`Instant`) but not the wall clock
(`SystemTime`). So after a wake, the wall clock has moved further than the monotonic
one. `SleepWatch` stores both at each mark and compares the two distances:

```rust
// gained = (wall now - wall then) - (mono now - mono then)
.is_some_and(|gained| gained > SLEEP_GAP_SECS)
```

Every step uses `checked_sub` / `checked_add`, so a strange clock gives `None`, not a
panic or a wrap. A wall clock set *back* gives a negative gain, which is "no sleep". A
wall clock set *forward* by more than 5 s reads as a sleep and locks: a false lock is
safe, a missed one is not.

Kotlin parallel from lesson 38: `System.currentTimeMillis()` against
`SystemClock.uptimeMillis()`, which also stops in deep sleep. The difference between
the two is how long the device slept.

This is how the shell sees a sleep without any OS callback. It cannot see a screen lock
that comes without a sleep, and the docs say so.

### 4. A closure borrowed per call

The shell passes the check into the terminal read as `Option<&dyn Fn() -> bool>`:

```rust
pub type Interrupt<'a> = Option<&'a dyn Fn() -> bool>;
```

The terminal never stores it, so there is no lifetime to manage past the call and no
`Rc<RefCell<..>>` to share. Kotlin: passing a `() -> Boolean` lambda as a parameter
instead of setting a listener field.

`LineOpts` holds that reference, so it cannot `#[derive(Debug)]` (a closure has no
`Debug`). It gets a hand-written one that prints only whether an interrupt is set.

## Exercises

1. Set `SLEEP_GAP_SECS` to 0 and run `cargo test -p holm-core --locked sleep_watch`.
   `sleep_watch_ignores_small_skew` fails. Why would a gap that small lock on ordinary
   clock skew (the wall clock counts whole seconds, NTP nudges it)? Put it back.
2. In `LockEvents::take`, replace `swap(false, ..)` with a `load` followed by a
   `store(false, ..)`. Describe the event that could be lost between the two lines.
   Put it back.
3. Remove the `impl Drop for LockEvents`. Nothing in the tests fails. Why is it still
   wrong? (Hint: what calls the block after the app is gone?)

## Read next

- [Lesson 38: One clear for every client](38-one-clear-for-every-client.md)
- [Lesson 27: Locking without a frame](27-locking-without-a-frame.md)
- [`std::sync::atomic::AtomicBool`](https://doc.rust-lang.org/std/sync/atomic/struct.AtomicBool.html)
