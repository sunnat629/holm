# Lesson 69: Migrate and keep a way back (B8 to B10)

## What we built

- Unlock of a v1 file makes a new data key and re-seals every item as a record.
- The first save writes the old bytes to `<vault>.v1-<hex>.bak`, then replaces the vault.
- A note in the index, three store methods (`keep_backup_copy`, `remove_backup_copy`,
  `backup_copy_exists`) and a GUI prompt. Nothing is deleted without a yes.

## Rust ideas, with Kotlin comparisons

- **Traits with default methods.** `keep_backup_copy` defaults to `Unsupported`, so a store
  that cannot do it fails closed. Like a Kotlin interface default, but a missing override is
  safe here by design.
- **Enums that carry state.** `BackupPrompt::{AfterUnlock, AfterPasswordChange, Done}` makes
  illegal prompts unrepresentable. A Kotlin enum class works the same way.
- **Test doubles by trait.** `MemStore` fails on cue (`backup write fails`, `replace fails`),
  so crash order is tested without a disk.
- **Closures that undo.** The `restore` closure puts back the old migration note when a save
  fails, so a retry sees the same state.

## Why this matters for security

The vault file changes in exactly one step, and only after a durable backup exists. A crash
leaves v1 plus a backup, or v1 or v2, never a mix. The backup still opens with the old
password, so Holm tells the user and asks again after a password change.

## Try it

1. Read `migration_replace_fails_then_retry`. What is on disk after the failed replace?
2. Why does a leftover `.bak` with other bytes stop migration instead of being overwritten?
3. Write a test where the password changes twice before the prompt is answered.

## Read next

Spec section 4, and lesson 41 (backups and the trash).
