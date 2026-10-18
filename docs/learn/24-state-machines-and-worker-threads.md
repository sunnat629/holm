# Lesson 24: State machines and worker threads

## Why this matters

Argon2 is meant to be slow: with Holm's default costs it takes about a second and 256 MiB. If that ran on the UI thread the window would freeze, macOS would show the spinning cursor, and a user might force-quit in the middle of creating a vault. Moving the work to another thread is easy; moving it without sharing the session between two threads, and without a hung screen when the thread dies, is what this task is about.

## What we built

`HolmApp` owns the `Session`, the instance lock and one `Screen` enum: `Create`, `Unlock`, `Working`, `Vault` or `Fatal`. A submit moves the master password and the session into a thread named `holm-work`, which runs `create` or `unlock` and sends the session back in a `WorkDone`. The UI polls that channel once per frame with `try_recv`, so it never blocks, and a closed channel shows a fixed "something went wrong" line instead of spinning forever. Every error the user can see comes from `messages.rs`, a table of fixed lines with no paths and no library error text.

## Rust ideas in this task

### An enum as a screen state machine

```rust
enum Screen {
    Create(CreateForm),
    Unlock(UnlockForm),
    Working { job: JobKind, rx: Receiver<WorkDone> },
    Vault(VaultView),
    Fatal(&'static str),
}
```

Each variant carries only the data its screen needs. The create form's two password buffers exist only inside `Screen::Create`; when the app sets `self.screen = Screen::Working { .. }`, the old value is dropped, and `SecretInput`'s `Drop` wipes the buffers. There is no "the form is hidden but its fields still hold the password" state, because the type has no way to say it.

`show` matches on `&mut self.screen` and returns an `Option<Job>` out of the match, then acts on it afterwards. Changing `self.screen` inside the match arm would not compile: the arm still borrows the form it is drawing.

In Kotlin you'd write a `sealed class Screen` with `data class Create(val form: CreateForm) : Screen()` and a `when (screen)`. The difference is the drop: Kotlin's old form waits for the garbage collector, Rust's is wiped at the assignment.

### Moving a value into a thread and getting it back

```rust
let rx = worker::spawn(session, job, wake);   // session moved in
// ... later, in tick():
Ok(done) => { self.session = Some(done.session); ... }   // moved back
```

`thread::Builder::spawn` takes a `move` closure, so `session` and the `MasterPassword` inside `job` are moved into the new thread. `Session<FsStore>` is `Send` (its clock is `Box<dyn Clock>` and `Clock: Send`), so the compiler allows it. While the worker runs, `HolmApp::session` is `None`: the UI cannot touch the vault even by mistake, because it has nothing to touch. The worker drops the password (and so wipes it) right after `create` or `unlock` returns, before it sends anything.

In Kotlin you'd write `withContext(Dispatchers.Default) { session.unlock(pw) }`, and the session object would stay reachable from both threads the whole time.

### Why the session has exactly one owner

The obvious alternative is `Arc<Mutex<Session>>`. It works, but then the UI thread has to lock the mutex every frame to read `throttle_status`, and while Argon2 holds the lock for a second the UI either blocks (a frozen window) or needs `try_lock` everywhere. Ownership that moves is simpler: the session is in exactly one place, the type system proves it, and no lock exists to forget or to deadlock.

### `mpsc::Receiver::try_recv`

```rust
match rx.try_recv() {
    Ok(done) => self.finish(done),
    Err(TryRecvError::Empty) => ctx.request_repaint_after(WORKER_POLL),
    Err(TryRecvError::Disconnected) => self.screen = Screen::Fatal(messages::WORKER_LOST),
}
```

`recv` would block the UI thread until the worker answers. `try_recv` returns at once with one of three answers, and the third is the important one: `Disconnected` means every `Sender` is gone without sending. That is exactly what a panic on the worker looks like, because unwinding drops the closure's `tx`. So a crashed worker becomes a fixed error screen instead of "Unlocking..." forever.

The worker also holds a small guard, created first in the closure so it drops last, that calls `wake` on the way out. Whether the thread sends or panics, the UI is woken after `tx` is gone.

In Kotlin you'd write `channel.tryReceive()` on a `kotlinx.coroutines.channels.Channel`, and check `isClosed` for the same signal.

### `request_repaint_after`

egui only draws a new frame when something happens: input, or a repaint request. Two things here need frames without input:

- The worker finishing. The wake closure calls `ctx.request_repaint()` from the worker thread (`Context` is `Clone + Send`), and `tick` also asks for a repaint every 200 ms while `Working`, in case a wake is missed.
- The throttle countdown. While a wait is due, `tick` asks for a repaint exactly when the shown whole-second number will change: the part of the wait below one second, or a full second if the wait is whole.

There is no spinner on the working screen on purpose: an animated spinner asks for a repaint every frame, and the test harness's `run()` would never settle.

### Discarding a pass when the screen changes

The submit is noticed while the form is being drawn, so that pass has already drawn the fields. `ui.ctx().request_discard(..)` tells egui to throw that pass away and run another one right away, which draws the working screen. The test `fields_cleared_when_work_starts` checks that the accessibility tree has no `PasswordInput` node after the step that starts the work.

### Mapping errors to fixed text

```rust
pub fn unlock_error(e: &CoreError) -> &'static str {
    match e {
        CoreError::WrongPassword | CoreError::Vault(VaultError::WrongPasswordOrCorrupt) => WRONG_PASSWORD,
        CoreError::Store(StoreError::NotARegularFile) => NOT_A_VAULT,
        // ...
        _ => UNLOCK_FAILED,
    }
}
```

The return type is `&'static str`, so the function can only return text written in the program, never a formatted path or an OS error message. The only formatted line, `throttle_line`, takes a `ThrottleStatus` (a count and a duration), so the only thing it can print is numbers. A table test covers every mapping, and another test checks each line is plain text that ends with a full stop.

In Kotlin you'd write a `when (e) { is WrongPassword -> R.string.wrong_password ... }` that returns a string resource id.

## Exercises

1. In `HolmApp::tick`, make the `Disconnected` arm do what the `Empty` arm does (`ctx.request_repaint_after(WORKER_POLL)`) and run the test. How long does it take to fail, and what would a user see on screen in the meantime? Undo the change.
   Check: `cargo test -p holm-gui --locked --test create_unlock worker_panic_is_fatal_not_hang`
2. In `UnlockForm::can_submit`, remove `throttle.retry_after.is_none() &&` and run the throttle test. What does the core do with a try during a wait, and why should the button still be disabled? Undo the change.
   Check: `cargo test -p holm-gui --locked --test create_unlock throttle_wait_shown_and_button_disabled`
3. In `HolmApp::show`, delete the `request_discard` line and run the test. Which assertion fails, and what would a screen reader have seen for one frame? Undo the change.
   Check: `cargo test -p holm-gui --locked --test create_unlock fields_cleared_when_work_starts`

## Read next

- [`std::sync::mpsc::Receiver::try_recv`](https://doc.rust-lang.org/std/sync/mpsc/struct.Receiver.html#method.try_recv)
- [`std::thread::Builder`](https://doc.rust-lang.org/std/thread/struct.Builder.html)
- [`egui::Context::request_repaint_after`](https://docs.rs/egui/0.37.0/egui/struct.Context.html#method.request_repaint_after)
