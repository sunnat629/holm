# Lesson 41: Backups and the Trash

## Why this matters

A password vault you cannot copy is a vault you will lose. Holm's backup is an encrypted
save of the vault under the same master password, so it needs no new password and holds
no plain text. The Trash has the opposite problem: the commands that act on it (`restore`,
`empty-trash`) can destroy data, so they must be hard to trigger by accident.

## What we built

- GUI: a "Back up…" toolbar button (`BACKUP_BUTTON` in `crates/holm-gui/src/messages.rs`),
  a typed-path form, and a `BackedUp` result screen that shows `BACKUP_DONE`: "Backup
  saved. It opens with this vault's master password."
- CLI: `holm restore ID`, `holm empty-trash`, and `holm list --trash`.
- Shell: the same two commands. `Shell::command` in `crates/holm-cli/src/shell.rs` calls
  `write::restore_in` and `write::empty_trash_in` on the session it keeps open, while the
  one-shot commands call `write::restore` and `write::empty_trash` with a vault path.

## Rust ideas in this lesson

**Confirm by typing.** `empty-trash` prints how many items it will delete, then reads a line.
Only the exact word `empty` goes ahead; anything else prints "Nothing deleted." and returns
`Ok`. A refusal is not an error: the user changed their mind, which is a normal outcome.
Typing a word is slower than a y/n key, and a stray Enter cannot confirm it.

**Scoping a lookup with a view.** `restore` calls `vault::resolve(.., View::Trash)`, which
looks an ID prefix up among the trashed items only. A prefix that names an active item gets
`CliError::NotInTrash` ("That item isn't in the Trash"), and a prefix that matches nothing
gets the plain not-found text. Two different mistakes give two different errors, and neither
can touch the wrong item, because the lookup is scoped before it matches. (`resolve_any`
spans both views, for commands that accept either.)

**An exhaustive `match`.** `Command` is an enum, and `dispatch` in
`crates/holm-cli/src/lib.rs` runs it with a `match` that has no `_` arm:

```rust
Command::Restore(args) => {
    write::restore(&vault_path(vault, env)?, &args, env, term, out, err)
}
Command::EmptyTrash => write::empty_trash(&vault_path(vault, env)?, env, term, out, err),
```

Adding the `Restore` variant made the compiler flag `dispatch`, and the second `match` on
`Command` in `Shell::command`, until each one handled it.

`Shell::command` does have a `_` arm, but it has a guard:

```rust
_ if !session.is_unlocked() => {
    writeln!(err, "{LOCKED}")?;
    Ok(())
}
```

The compiler cannot know when a guard is true, so a guarded arm never counts toward
exhaustiveness. Every variant still needs an arm of its own below it. The help text (`USAGE` and
`SHELL_HELP`) is only strings, so the compiler cannot flag it: it must be updated by hand.
Kotlin's `when` over a sealed class gives the same guarantee (for statements too, since
Kotlin 1.7). In Rust every `match` must be exhaustive, always.

**Why an encrypted copy needs no re-entry.** Export writes plain text, so it asks for the
master password again: the user proves they are present and accepts a warning. In
`transfer.rs`, `export_plain` takes a `&MasterPassword` and `export_backup` does not. The
backup is written through `session.save_backup`, encrypted under the same master
password, so a thief with the file gets nothing they did not already get from the vault
file. The password is only needed when the copy is opened, and then it is the vault's own
unlock. The tests check this by opening the copy with `Session::unlock`
(`backup_opens_with_same_password`) and by searching the bytes for a known item name.

## Try it

1. Run `cargo test -p holm-cli --test trash_commands` and read the empty-trash tests.
   Which inputs other than `empty` do they try?
2. Run `cargo test -p holm-gui --test transfer backup` and read
   `backup_holds_no_plaintext`.
3. In `backup_opens_with_same_password` (`crates/holm-platform/src/transfer.rs`), find
   the second `export_backup` call. What error does it expect, and why?

## Read next

- Previous: [Lesson 40](40-a-native-dialog-from-egui.md)
- Next: [Lesson 42](42-one-list-four-shapes.md)
- [the index](README.md)
