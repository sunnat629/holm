# Lesson 41: Backups and the Trash

## Why this matters

A password vault you cannot copy is a vault you will lose. Holm's backup is the vault file
itself, copied while it is still encrypted, so it needs no new password and holds no plain
text. The Trash has the opposite problem: the commands that act on it (`restore`,
`empty-trash`) can destroy data, so they must be hard to trigger by accident.

## What we built

- GUI: a "Back up..." toolbar button, a typed-path form, and a `BackedUp` result screen.
- CLI: `holm restore ID`, `holm empty-trash`, and `holm list --trash`.
- Shell: the same two commands, from the same function bodies.

## Rust ideas in this task

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

**An exhaustive `match`.** `Command` is an enum, and `dispatch` in `lib.rs` runs it with a
`match` that has no `_` arm. Adding `Restore(RefArgs)` made the compiler flag the
non-exhaustive `match` in `dispatch` and in `Command::name`. The help text (`USAGE` and
`SHELL_HELP`) is only strings, so the compiler cannot flag it: it must be updated by hand.
Kotlin's `when` over a sealed class gives the same guarantee, but only when `when` is used
as an expression. Here the `match` has this guarantee by default for every enum.

**Why an encrypted copy needs no re-entry.** Export writes plain text, so it asks for the
master password again: the user proves they are present and accepts a warning. A backup
copies bytes that are already encrypted under the master password, so a thief with the
file gets nothing they did not already get from the vault file. The password is only
needed when the copy is opened, and then it is the vault's own unlock. The tests check
this by opening the copy with `Session::unlock` and by searching the bytes for a known
item name.

## Try it

Run `cargo test -p holm-cli --test trash_commands` and read the empty-trash tests. Then
run `cargo test -p holm-gui --test transfer backup` and read `backup_holds_no_plaintext`.
