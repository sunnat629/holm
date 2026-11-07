# Lesson 67: One record per item (B1 to B4)

## What we built

- `envelope_v2`: a 172-byte header, an encrypted index and a region of per-item records.
- A record AAD built from a domain tag, the key block, the item id and a generation.
- `RecordRef` in the index: generation, nonce and length for each record.
- Golden bytes for one index entry and one record, plus `golden-v2.vault`.

## Rust ideas, with Kotlin comparisons

- **Newtypes for ids.** `ItemId([u8; 16])` is not a `String` or a `Uuid` you can mix up. In
  Kotlin you would reach for a `@JvmInline value class`. Rust newtypes cost nothing at run time.
- **`checked_add` and friends.** Sizes come from untrusted bytes, so `a.checked_add(b)` returns
  `Option<u64>` instead of wrapping. Kotlin's `Math.addExact` throws; Rust makes you handle the
  `None`.
- **Builders that consume.** `seal(self, ...)` takes the nonce by value, so safe code cannot seal
  twice with one nonce. Kotlin has no move semantics to enforce this; you would rely on review.
- **Property tests.** `proptest` generates vaults and checks `open(seal(x)) == x`, like Kotest
  property testing, but with shrinking built in.

## Why this matters for security

An AEAD tag only proves "someone with the key made this". AAD says "for this place". Putting
the item id and generation in the AAD, and pinning each nonce in the authenticated index, stops
swapping, rolling back and splicing records, even from a backup copy that shares the key.
Every length is checked before the allocation it controls.

## Try it

1. Change one byte of a record in a test vault and see which `tamper_*` test would catch it.
2. Add a `u8` to the record AAD in a scratch branch. Which golden test fails first, and why?
3. Why does a backup copy defeat the AAD alone? Read `tamper_record_from_backup_copy`.

## Read next

`docs/CRYPTO.md` "Format v2" and spec section 2.5.
