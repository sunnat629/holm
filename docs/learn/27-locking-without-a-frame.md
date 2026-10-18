# Lesson 27: Locking without a frame

## Why this matters

An open vault left on an unattended Mac is the easiest attack there is: no exploit is needed, just a chair. Auto-lock only helps if it fires when nobody is looking, which is exactly when the window is hidden and the GUI library draws nothing. And a lock that leaves a half-typed password in some form buffer, or a revealed password in some widget state, has only locked the door while leaving the key on the table.

## What we built

`HolmApp::lock` calls `session.lock()`, which wipes the keys and data in the core, then replaces the vault screen with an empty unlock form. That drops the whole `VaultView` and everything it owns. The vault locks in three ways: the Lock button or Cmd+L (`Manual`), the idle timer running out (`Idle`), and the window being minimised (`Minimised`). The unlock screen then says why, with text built by `messages::lock_line` from the vault's own auto-lock setting. A manual lock with unsaved changes first asks "Save and lock", "Lock anyway" or "Cancel"; the idle and minimise locks never ask, and 30 seconds before an idle lock an amber line warns that it is coming.

## Rust ideas in this task

### `logic` and `ui`: two halves of a frame

```rust
impl eframe::App for HolmApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick(ctx);
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}
```

eframe 0.37 splits a frame in two. `logic` gets only the `Context` and runs on every pass, even while the window is hidden. `ui` gets a `Ui` to draw into, and eframe skips it when there is nothing to show. Holm puts the lock checks in `tick` (called from `logic`) and the drawing in `show` (called from `ui`).

In Kotlin with Compose you'd keep the idle timer in a `ViewModel` coroutine, not in a `@Composable`, for the same reason: a composable only runs when something is on screen to recompose.

### Why the idle check must run when nothing is drawn

```rust
if matches!(self.screen, Screen::Vault(_)) {
    if ctx.input(|i| i.viewport().minimized == Some(true)) {
        self.lock(LockReason::Minimised);
    } else if self.session.as_ref().is_some_and(Session::idle_expired) {
        self.lock(LockReason::Idle);
    }
}
// ...
ctx.request_repaint_after(OPEN_TICK); // one second
```

If the idle check lived in `show`, a vault behind another window could stay open for hours, because no frame would be drawn to run the check. `request_repaint_after` asks eframe for another pass within a second even without input, so `tick` keeps checking. The core's `idle_expired` also adds forward jumps of the wall clock, so a Mac that slept for an hour locks on its first frame after waking.

`tick` never records activity. Input that arrives while the window is hidden may be stale or not from the user. `record_activity` runs in `show`, and only when `viewport().visible()` is not `Some(false)` and the frame has events or pointer movement.

In Kotlin you'd write `if (minimized == true)` against a `Boolean?`. Rust's `Option<bool>` compares the same way: `== Some(true)` is false for both `Some(false)` and `None` ("unknown").

### `Drop` does the wiping

```rust
let outcome = session.lock();
self.screen = Screen::Unlock(UnlockForm::new());
```

There is no `view.wipe()` call. Assigning a new `Screen` drops the old one, and Rust drops a value's fields in turn: the `VaultView`, its open form, the form's `SecretInput` (which overwrites its bytes in its own `Drop`), and the reveal deadline. A field added to `VaultView` next year is wiped too, without anyone remembering to add it to a wipe list.

In Kotlin you'd write `override fun close()` and call it yourself, or rely on `use { }`. Forget one call and the secret stays on the heap until the garbage collector runs, and even then it is not overwritten.

### A keyboard shortcut that the text field never sees

```rust
const LOCK_SHORTCUT: egui::KeyboardShortcut =
    egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::L);

if ui.ctx().input_mut(|i| i.consume_shortcut(&LOCK_SHORTCUT)) {
    self.request_lock();
}
```

`KeyboardShortcut::new` is a `const fn`, so the shortcut is built at compile time. `consume_shortcut` removes the key event from this frame's input when it matches. It runs before any widget is drawn, so a focused text field never receives the "l". `Modifiers::COMMAND` means Cmd on macOS and Ctrl elsewhere.

In Kotlin you'd write `Modifier.onPreviewKeyEvent { ... true }` to handle a key before the focused child and stop it there.

### An enum instead of a flag

```rust
pub enum LockReason { Manual, Idle, Minimised }
pub struct LockNote { pub reason: LockReason, pub discarded_unsaved: bool }
```

The unlock screen's line is a `match` on the reason, so a fourth reason will not compile until it has its own text. The auto-lock time in "Locked after 10 minutes without use." comes from `session.settings()`; no UI text hard-codes "5 minutes".

## The dirty-lock dialog

A manual lock with unsaved changes would discard them, so it asks first. "Save and lock" calls `session.save()`. If the save fails, the dialog closes, the Not saved banner shows and the vault stays open: a lock that silently threw the changes away would be worse than no lock. The idle and minimise locks never ask, because nobody may be there to answer. They lock at once, and the unlock screen adds "Unsaved changes were discarded."

## Exercises

1. In `tests/lock.rs`, delete the `clock.advance(a)` line from `idle_lock_runs_without_ui`. See it fail, then undo. Check: `cargo test -p holm-gui --locked --test lock idle_lock_runs`.
2. In `app.rs`, remove the `viewport().visible() != Some(false)` part of `record_activity`. Which test fails, and why? Undo it. Check: `cargo test -p holm-gui --locked --test lock stale_input`.
3. Add a unit test in `messages.rs` for a 3600 s auto-lock and check that the line says "60 minutes". Check: `cargo test -p holm-gui --locked lock_lines`.

## Read next

- [`eframe::App`](https://docs.rs/eframe/0.37.0/eframe/trait.App.html)
- [`egui::InputState::consume_shortcut`](https://docs.rs/egui/0.37.0/egui/struct.InputState.html#method.consume_shortcut)
- [The Rust Book: running code on cleanup with `Drop`](https://doc.rust-lang.org/book/ch15-03-drop.html)
