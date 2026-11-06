# Lesson 39: One flow, two front ends

## Why this matters

Import and export touch the most sensitive things Holm does: they read a file the user
points at, and they write every password to disk. The CLI and the GUI each had their own
copy of that code. Two copies drift: one refuses an existing file, the other overwrites it.
So the flow now lives once, in `crates/holm-platform/src/transfer.rs`.

## What we built

- `typed_path(&str)`: a path typed into a form must be absolute. It never trims, because
  a trailing space is a legal file name.
- `format_for`, `read_import`: pick JSON or CSV by extension and read with a size cap
  (`MAX_IMPORT_BYTES`). A folder, a pipe or a device is refused as `NotAFile`.
- `refuse_existing`: checks the destination before the password is asked.
- `export_plain`: writes the plain CSV file (mode 0600) and returns the item count.
- `export_backup`: writes an encrypted backup that opens with the same master password.
- `TransferError`: why it failed, with no path and no content inside.

The CLI and the GUI worker both call these. Each front end only turns a `TransferError`
into its own words. In the GUI those words are fixed constants in
`crates/holm-gui/src/messages.rs`, such as `EXPORT_EXISTS` and `IMPORT_NOT_A_FILE`. They
never hold a path or a library error's `Display`. In the CLI, `dispatch` in
`crates/holm-cli/src/lib.rs` sends `holm import` and `holm export` to the
`commands::transfer` module, and `holm shell` calls the same module on the session it
keeps open (`crates/holm-cli/src/shell.rs`).

`export_plain` writes CSV only. `holm export --format json` exists too (see `USAGE` in
`lib.rs`), so that path is not in the shared module.

## Rust ideas in this lesson

**Generic over `S: VaultStore`.** `export_plain<S: VaultStore>(session: &mut Session<S>, ..)`
works with any store that implements the `VaultStore` trait. The tests in `transfer.rs`
use `FsStore` in a temporary folder. The compiler makes one copy of the function per store
type, so there is no run-time cost. In Kotlin this is a shared use-case class that takes a
repository interface.

**Error enums with no path inside.** Most variants, such as `TransferError::NotFound`,
carry nothing. The two that do, `Import(ImportError)` and `Core(CoreError)`, carry another
error enum, not a path or file content. A path inside an error can leak into a log or a
screen. Without such a field there is nothing to leak, and a test
(`errors_hold_no_path`) checks the `Debug` text. The Kotlin comparison is a sealed class
of errors, where each front end does an exhaustive `when` to pick its message. Rust
`match` on an enum does the same, and the compiler fails the build if a case is missing.

**`symlink_metadata`.** `Path::exists` follows links, so a dangling link (one that points
at nothing) looks like "nothing here". `symlink_metadata` looks at the link itself, so any
entry at that name counts as taken:

```rust
match fs::symlink_metadata(dest) {
    Ok(_) => Err(TransferError::Exists),
    Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
    Err(_) => Err(TransferError::WriteFailed),
}
```

## Try it

1. Run the shared tests, then the front-end tests:

   ```
   cargo test -p holm-platform --locked transfer
   cargo test -p holm-gui --locked --test transfer
   cargo test -p holm-cli --locked --test transfer_commands
   ```

2. Read `export_refuses_existing_before_password` in `transfer.rs`. Move the
   `refuse_existing(dest)?;` line in `export_plain` below the `export_csv` call and run
   the test again. Which assert fails, and why does that matter? Undo the change.
3. Add a `TransferError` variant, then build `holm-gui` and `holm-cli`. If a front end
   matches with no `_` arm, the compiler names the missing case. If it builds, find the
   `_` arm that caught the new variant. Remove the variant afterwards.

## Read next

- Previous: [Lesson 38](38-one-clear-for-every-client.md)
- Next: [Lesson 40](40-a-native-dialog-from-egui.md)
- [the index](README.md)
