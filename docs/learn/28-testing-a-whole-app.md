# Lesson 28: Testing a whole app

## Why this matters

Every piece of Phase 3 has its own tests, but a user never meets a piece: they meet the
whole app, from the first window to the file left on disk. A vault that encrypts
perfectly in a unit test is still broken if the app leaves a temp file with the
password in it, or opens the wrong path after a restart. And some promises, such as
"the clipboard manager skipped it", can't be checked by any test that runs without a
screen, so they need a written list and a person.

## What we built

`tests/walking_skeleton.rs` drives the real `HolmApp` headless through the Phase 3 done
flow: create a vault, add a login, copy its password, lock, then start a brand new app
on the same path, refuse a wrong password, unlock with the right one and see the login.
A second test runs the same flow and then inspects the folder: only `holm.vault` and
`holm.lock`, owner-only modes, an empty lock file, and none of the item text or
passwords in either file's bytes. `docs/manual/phase-3-macos-checklist.md` lists what
only a person at a real Mac can check, and records what was checked automatically.

## Rust ideas in this task

### An integration test is its own crate

```rust
#![cfg(target_os = "macos")]
mod common;

use holm_gui::app::{HolmApp, ScreenKind};
```

Each file in `tests/` is compiled as a separate crate that sees only `holm_gui`'s public
API, as any other user would. `mod common;` pulls in `tests/common/mod.rs`, so the files
share a fake clock, a fake clipboard and a harness builder without making them part of
the library. The `#![cfg]` line removes the whole file on Linux and Windows, where there
is no egui to test.

In Kotlin you'd write the same test under `src/test` with a `testFixtures` source set for
the shared fakes; here the folder layout does that job.

### Dropping a value to end its job

```rust
// Quit: dropping the app releases the instance lock.
drop(harness);

let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
let mut harness = common::harness(app);
```

The first app holds `holm.lock` through an `InstanceLock` field. Nothing calls
`unlock()` on it: the lock is released when the `File` inside it drops. `drop(harness)`
ends the harness, the app and the lock at that line, so the second app can take the lock.
Leave the `drop` out and the second app shows "Holm is already open", which is exactly
what the single-instance test in Task 3 checks.

In Kotlin you'd write `firstApp.use { … }` and rely on `close()` running at the end of
the block. Rust runs `Drop` at the end of every scope, with no `use` to forget.

### A fake that the test and the app share

```rust
#[derive(Clone, Default)]
pub struct FakeClipboard(pub Rc<RefCell<FakeClipboardState>>);

let fake = FakeClipboard::default();
let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
// … click Copy …
assert_eq!(fake.0.borrow().sets.len(), 1, "one set_secret call");
```

The app owns a `Box<dyn SecretClipboard>`, so the test can't reach into it afterwards.
Cloning the `Rc` gives both sides a handle to the same state: the app writes through
its clone, the test reads through its own. `RefCell` moves the borrow check to run time,
which is fine on one thread. The same fake goes to the second app, so the test can also
check that unlocking and viewing copied nothing.

In Kotlin you'd write `val fake = FakeClipboard()` and pass the same object to both,
because every object is a shared reference. Rust makes the sharing explicit.

### Reading what is on disk, not what the app says

```rust
fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}
```

`symlink_metadata` reports on the entry itself, so a symlink can't stand in for the
real file. `PermissionsExt::mode()` is Unix-only, which is fine in a macOS-only file;
`& 0o777` keeps the permission bits and drops the file-type bits. `windows(n)` yields
every run of `n` bytes, overlapping, so `contains` finds a needle at any offset. The
failure message prints the needle's length, never the needle: a test that leaks the
secret into CI logs while proving it isn't on disk would be its own leak.

In Kotlin you'd write `Files.getPosixFilePermissions(path)` and
`bytes.toString(Charsets.ISO_8859_1).contains(needle)`.

### Tests that only a person runs

```rust
#[test]
#[ignore = "uses the real pasteboard; run by hand"]
fn system_clipboard_marks_concealed() { … }
```

`#[ignore]` keeps a test compiled (so it can't rot) but out of `cargo test`. It runs only
when asked: `cargo test … -- --ignored system_clipboard_marks_concealed`. This one
replaces the user's real clipboard, so it must never run inside the CI gate.

In Kotlin you'd write `@Disabled("uses the real pasteboard")` in JUnit 5.

## What the headless test proves, and what it can't

The harness runs the same `tick` and `show` code that eframe runs, feeds it the same
input events and reads the same AccessKit tree a screen reader would. So it proves the
logic: screen order, fixed texts, that secrets leave the form when work starts, that the
throttle and the idle lock fire, and what lands on disk.

It can't prove anything outside the process. Only a person can see that the window
title says "Holm", that TextEdit.app receives the pasted password, that a clipboard
manager skipped it, that minimising with the yellow button really reports
`minimized`, that a second Holm started from a terminal shows the fixed text, that
macOS saved no window state, and that Activity Monitor shows no network use. Those are
the unchecked boxes in the manual checklist.

## How the Phase 3 pieces connect

```text
main.rs ── default path or --vault ── HolmApp::new
   │                                      ├─ ensure_vault_dir (0700, refuse 0o022)
   │                                      ├─ InstanceLock::acquire (holm.lock)
   │                                      └─ Create or Unlock screen
   ├─ logic → tick: worker result, throttle countdown, idle and minimise lock
   └─ ui    → show: SecretField (wiping SecretInput), rows, login form, Copy
                    │
                    └─ Session<FsStore> ── Argon2 on the holm-work thread ── holm.vault
```

The walking-skeleton test walks this whole picture once, from `HolmApp::new` to the
bytes of `holm.vault`.

## Exercises

1. In `walking_skeleton.rs`, comment out `drop(harness);` before the second app is made.
   Which assertion fails, and which fixed text does the second app show instead? Undo.
   Check: `cargo test -p holm-gui --locked --test walking_skeleton walking_skeleton_create`.
2. Extend `no_plaintext_on_disk` to check that the temp folder above `Holm` holds only
   `Holm`, using the same `read_dir` and sort pattern. It should pass.
   Check: `cargo test -p holm-gui --locked --test walking_skeleton no_plaintext`.
3. Write a stray file `holm.vault.tmp-0000000000000000` into the folder at the start of
   the on-disk checks and confirm the folder assertion fails with both names listed.
   Undo. Check: `cargo test -p holm-gui --locked --test walking_skeleton no_plaintext`.

## Read next

- [The Rust Book: test organisation and integration tests](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
- [`egui_kittest`](https://docs.rs/egui_kittest/0.37.0/egui_kittest/)
- [The Rust Book: `Rc<T>` and `RefCell<T>`](https://doc.rust-lang.org/book/ch15-05-interior-mutability.html)
