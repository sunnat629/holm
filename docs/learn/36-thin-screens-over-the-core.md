# Lesson 36: Thin screens over the core

## Why this matters

A password manager's screens should do almost nothing. The rules (what a valid row is, what
the export warning says, when a duplicate is skipped) live in `holm-core`, where tests and the
command line share them. A screen only collects input, starts work, and shows a fixed answer.
The less a screen knows, the less it can get wrong, and the less it can leak.

## What we built

The vault screen got a Search box, an `Import...` button and an `Export...` button. The search
box calls `Session::search`. Import and export open the screens in
`crates/holm-gui/src/screens/transfer.rs`. They take a typed file path, or one picked with
`Choose…` in the native file dialog. A picked path lands in the same field and goes through
the same checks as a typed one. A third screen, backup, writes an encrypted copy of the vault
the same way.

Import has three steps: type a path, read a preview (counts, and skipped rows by row number),
then a report. Export shows `EXPORT_WARNING`, asks for the master password again, and keeps the
button off until the user ticks "I understand this file is not encrypted".

## Rust ideas in this task

### 1. Moving owned data through a worker `Job`

Reading a large file and hashing a password must not freeze the window. The `Session` moves
into a background thread together with a `Job`, and comes back when the job is done. The
transfer screens build these jobs:

```rust
Job::PreviewImport(path)
Job::Import(batch)
Job::Export { path, password: self.password.take_master_password() }
Job::Backup { path }
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
`Backup`, `BackedUp`, `Busy` and `Choosing`. Data that only exists in one step lives in that
variant, so it cannot be read in the wrong step. `Busy` holds nothing, because the job owns
the data. `Choosing` holds the form to go back to as `prev: Box<Transfer>`: an enum cannot hold
itself directly, because its size would be endless, so the inner one is boxed. The answer
arrives as a `TransferResult` and `on_result` picks the next variant:

```rust
match result {
    TransferResult::Previewed(batch, preview) => { /* *self = Transfer::Preview(...) */ }
    TransferResult::Imported(report) => *self = Transfer::Report(report),
    TransferResult::Exported => *self = Transfer::Exported,
    TransferResult::BackedUp => *self = Transfer::BackedUp,
    TransferResult::Failed(fail) => { /* put the fixed error text on the form */ }
}
```

`match` must cover every variant, so a new result kind is a compile error until a screen
decides what to do with it. Kotlin: `sealed class UiState` with `when (state)`.

### 3. The warning is a core constant

`EXPORT_WARNING` and `IMPORT_DELETE_SOURCE_WARNING` are `const` strings in `holm-core`
(`holm_core::export` and `holm_core::import`). The GUI shows them with `ui.label`, and the CLI
can print the very same constant. If the text lived in the GUI, the CLI could drift from it.

For the same reason, no screen text ever holds a value from the file or the typed path. Every
line is a fixed message or a count. `problem_text` turns a `RowProblem` into a fixed line, and
the preview prints only numbers:

```rust
ui.label(format!("{} duplicates will be skipped.", p.duplicates));
```

## Try it

1. Add a count of rows by category to the preview. Keep the text a number only. Check:
   `cargo test -p holm-gui --locked`
2. The preview prints `Row {}: {}.`, so the three `problem_text` lines that end in a full stop
   show two. Make them short lowercase phrases like the others. Check:
   `cargo test -p holm-gui --locked`
3. Set `ISSUE_LIST_MAX` to 5 and import a file with more bad rows than that. Where does
   "And more." show? Put it back.

## Read next

- Previous: [Lesson 35: A read-eval loop with a deadline](35-a-read-eval-loop-with-a-deadline.md)
- Next: [Lesson 37: Hold to reveal](37-hold-to-reveal.md)
- [The index](README.md)
- [Enums and pattern matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [`std::thread::spawn` and `move` closures](https://doc.rust-lang.org/book/ch16-01-threads.html)
