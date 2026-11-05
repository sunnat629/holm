# 51: Closing the small gaps

## Why this matters

A successful write does not guarantee that a new file's name survives a power loss.
A harmless-looking title can contain invisible separators. Parsed fields also need
wiping while a prompt waits or a command fails.

## What we built

Exports sync their data and then their parent folder on Unix. Terminal output drops
Unicode separators and selected invisible characters. Add and edit arguments own
wiping strings until those strings move into the vault.

We also bounded imported timestamps, checked the current password before asking for
a new one, and stopped hung-up terminals after three consecutive fast zero-byte reads.
Normal 100 ms poll timeouts keep waiting. Tests use injected reads and time, not sleeps.

## Rust ideas in this task

`File::sync_all` on the file persists its data; syncing the parent persists the new
directory entry. Kotlin's `FileChannel.force` serves the file part, but portable
folder syncing needs platform support. Truncation and deletion are best effort,
not secure erasure: APFS can keep freed blocks or snapshots.

Rust's `char::is_control` does not catch every invisible character. We match the
specific separators and zero-width characters too. Kotlin's `Character.getType`
can classify characters, but a terminal filter still needs an explicit policy.

`Zeroizing<String>` wipes its allocation on drop, including an early error return.
`mem::take(&mut *field)` moves the string into the vault's wiping `Text` without a
copy. Kotlin's immutable `String` offers no equivalent wipe-on-drop guarantee.
