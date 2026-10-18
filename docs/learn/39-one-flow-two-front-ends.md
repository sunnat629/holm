# Lesson 39: One flow, two front ends

## Why this matters

Import and export touch the most sensitive things Holm does: they read a file the user
points at, and they write every password to disk. The CLI and the GUI each had their own
copy of that code. Two copies drift: one refuses an existing file, the other overwrites it.
So the flow now lives once, in `crates/holm-platform/src/transfer.rs`.

## What we built

- `typed_path(&str)`: a path typed into a form must be absolute. It never trims, because
  a trailing space is a legal file name.
- `format_for`, `read_import`: pick JSON or CSV by extension and read with a size cap.
- `refuse_existing`: checks the destination before the password is asked.
- `export_plain`, `export_backup`: write the file, and return the item count.
- `TransferError`: why it failed, with no path and no content inside.

The CLI and the GUI worker both call these. Each front end only turns a `TransferError`
into its own words.

## Rust ideas in this task

**Generic over `S: VaultStore`.** `export_plain<S: VaultStore>(session: &mut Session<S>, ..)`
works with any store. Production passes the file store; tests pass an in-memory one. The
compiler makes one copy per store type, so there is no run-time cost. In Kotlin this is a
shared use-case class that takes a repository interface.

**Error enums with no payload.** `TransferError::NotFound` carries nothing. A path inside
an error can leak into a log or a screen. Without a field there is nothing to leak, and a
test (`errors_hold_no_path`) checks the `Debug` text. The Kotlin comparison is a sealed
class of errors, where each front end does an exhaustive `when` to pick its message. Rust
`match` on an enum does the same, and the compiler fails the build if a case is missing.

**`symlink_metadata`.** `Path::exists` follows links, so a dangling link looks like "nothing
here" and a write would go through it. `symlink_metadata` looks at the link itself, so any
entry at that name counts as taken.

## Try it

```
cargo test -p holm-platform --locked transfer
cargo test -p holm-gui --locked --test transfer
cargo test -p holm-cli --locked --test transfer_commands
```
