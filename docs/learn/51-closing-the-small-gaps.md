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

## Rust ideas in this lesson

### Syncing a file and its folder

`File::sync_all` on the file persists its data. Syncing the parent folder persists the
new directory entry. Kotlin's `FileChannel.force` serves the file part, but portable
folder syncing needs platform support. Truncation and deletion are best effort,
not secure erasure: APFS can keep freed blocks or snapshots.

### Invisible characters

Rust's `char::is_control` only matches control characters (Unicode category Cc), so it
does not catch every invisible character. We match the specific separators and
zero-width characters too. Kotlin's `Character.getType` can classify characters, but a
terminal filter still needs an explicit policy.

### Moving a wiping string without a copy

`Zeroizing<String>` wipes its allocation on drop, including on an early error return.
`mem::take(&mut *field)` moves the string out and leaves an empty one behind.
`Text::new` takes that `String` by value, so its buffer moves into the vault's wiping
`Text` without a copy. Kotlin's immutable `String` offers no equivalent wipe-on-drop
guarantee.

## Try it

1. In a scratch project, print `'\u{7}'.is_control()`, `'\u{200B}'.is_control()` and
   `'\u{2028}'.is_control()`. Which ones are `false`, and why would a terminal filter
   still want to drop them?
2. With the `zeroize` crate, make `Zeroizing::new(String::from("EXAMPLE-secret"))`,
   then `std::mem::take(&mut *z)`. Print whether `z` is empty and what the taken string
   holds. Which value will be wiped when it drops?

## Read next

- Previous: [Lesson 50](50-dev-unlock-feature.md)
- Next: [Lesson 52](52-a-second-schema.md)
- [The index](README.md)
