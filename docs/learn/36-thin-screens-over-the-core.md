# Lesson 36: Thin screens over the core

## Why this matters

A password manager's screens should do almost nothing. The rules (what a valid row is, what
the export warning says, when a duplicate is skipped) live in `holm-core`, where tests and the
command line share them. A screen only collects input, starts work, and shows a fixed answer.
The less a screen knows, the less it can get wrong, and the less it can leak.

## What we built

The vault screen got a Search box, an `Import...` button and an `Export...` button. The search
box calls `Session::search`. Import and export open the screens in
`crates/holm-gui/src/screens/transfer.rs`. They take a typed file path (no file dialog: a
dialog needs a new crate and hands path handling to the OS).

Import has three steps: type a path, read a preview (counts, and skipped rows by row number),
then a report. Export shows `EXPORT_WARNING`, asks for the master password again, and keeps the
button off until the user ticks "I understand this file is not encrypted".

## Rust ideas in this task

### 1. Moving owned data through a worker `Job`

Reading a 16 MiB file and hashing a password must not freeze the window. The `Session` moves
into a background thread together with a `Job`, and comes back inside `WorkDone`:

```rust
pub(crate) enum Job {
    PreviewImport(PathBuf),
    Import(Box<ImportBatch>),
    Export { path: PathBuf, password: MasterPassword },
}
```

Ownership is the lock. While the job runs, the UI does not hold the session at all, so it
cannot touch it: no `Mutex`, no flag to forget. The `ImportBatch` is moved in (boxed, so the
enum stays small) and the export password is moved in, so the screen's own buffer is already
empty. When the thread finishes it sends the session back and the UI takes it again.

Kotlin comparison: `viewModelScope.launch(Dispatchers.Default) { ... }` with state copied in.
Kotlin shares the object and relies on you not to touch it; Rust makes the move explicit and
the compiler refuses a second use.

### 2. A GUI flow as a state enum

Each screen is one variant of `Transfer`: `Pick`, `Preview`, `Report`, `Export`, `Exported`,
`Busy`. Data that only exists in one step lives in that variant, so it cannot be read in the
wrong step. `Busy` holds nothing, because the job owns the data. The answer arrives as a
`TransferResult` and `on_result` picks the next variant:

```rust
match result {
    TransferResult::Previewed(batch, preview) => *self = Transfer::Preview(/* ... */),
    TransferResult::Imported(report) => *self = Transfer::Report(report),
    TransferResult::Exported => *self = Transfer::Exported,
    TransferResult::Failed(fail) => { /* put the fixed error text on the form */ }
}
```

`match` must cover every variant, so a new result kind is a compile error until a screen
decides what to do with it. Kotlin: `sealed class UiState` with `when (state)`.

### 3. The warning is a core constant

`EXPORT_WARNING` and `IMPORT_DELETE_SOURCE_WARNING` are `const` strings in `holm-core`. The CLI
and the GUI both print them, and a core test checks that the export warning names
spreadsheets. If the text lived in the GUI, the CLI could drift from it, and a test in one
crate could not guard the other.

For the same reason, no screen line ever contains a path or a file value. Every line is a fixed
message or a count. `transfer_texts_hold_no_values` walks the whole screen and checks that a
planted secret is nowhere in it.

## Exercises

1. Add a count of rows by category to the preview. Keep the text a number only. Check:
   `cargo test -p holm-gui --locked --test transfer`
2. Make the report screen also show the number of one-time-password secrets that were not
   stored. Check: `cargo test -p holm-gui --locked --test transfer`
3. Add a test that the Search box is empty again after a lock. Look at `search_cleared_on_lock`
   first. Check: `cargo test -p holm-gui --locked --test search`

## Read next

- [Enums and pattern matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [`std::thread::spawn` and `move` closures](https://doc.rust-lang.org/book/ch16-01-threads.html)
- [Lesson 35: A read-eval loop with a deadline](35-a-read-eval-loop-with-a-deadline.md)
