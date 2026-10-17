# Lesson 02: Ownership, Drop and secret types

## What we built

Three types in `crates/holm-crypto/src/secret.rs` that hold secrets safely:

- `SecretKey`: a 32-byte key. It lives on the heap inside a `Box`.
- `SecretBuf`: a secret byte buffer of any length.
- `MasterPassword`: the password text. `to_kdf_bytes()` turns it into the exact bytes the key-derivation step will use.

All three share four habits. They overwrite their memory with zeros when they are dropped.
They print `[REDACTED]` instead of their contents. They cannot be cloned or copied by
accident. And the password is normalised so the same letters always give the same bytes.

## Rust ideas

**Ownership and moves.** Every value in Rust has exactly one owner. Assigning it or passing
it to a function *moves* it, and the old name stops working. This is the core of Rust, and
it is why "who holds the secret right now?" always has one answer.
([Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html))

**A move copies bytes.** For a `[u8; 32]`, a move copies all 32 bytes to a new place and
leaves the old ones lying around. For a `Box<[u8; 32]>`, a move copies only the pointer; the
key bytes stay where they are on the heap. That is why `SecretKey` holds a `Box`. It is also
why `SecretKey::from_bytes` takes `&mut [u8; 32]` (a borrow) instead of the array by value:
passing the array by value would leave a copy in the function's argument slot that nobody
can wipe. With the borrow, we copy once into the box and then wipe the caller's array.
([References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html))

**`Drop`.** A type can run code when its owner goes out of scope. Rust calls this
automatically, exactly once, even on early returns. Kotlin has `finalize` and `Closeable`,
but you must remember `use { }`, and the garbage collector decides when memory goes away.
In Rust the compiler decides, and it is always at the closing brace.
([The Drop Trait](https://doc.rust-lang.org/book/ch15-03-drop.html))

**Zeroize.** The [`zeroize`](https://docs.rs/zeroize) crate overwrites memory in a way the
optimiser may not remove. A plain "set it to zero, then never read it again" can be deleted
by the compiler as dead code; `zeroize` is built to prevent that. `#[derive(Zeroize, ZeroizeOnDrop)]`
writes the wipe and the `Drop` for us. `Zeroizing<T>` is a wrapper that wipes `T` when it drops;
`SecretBuf` and `MasterPassword` use it.

**Derive macros.** `#[derive(...)]` asks the compiler to generate a trait implementation.
`Debug` can be derived too, but for secrets the derived version would print the bytes, so we
write `Debug` by hand and print `SecretKey([REDACTED])`.
([Derivable Traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html))

**Traits we leave out.** `Clone` makes a second copy of the secret that also needs wiping, and
`Copy` would make that happen silently on every assignment. We simply do not implement them,
so `let b = key.clone();` does not compile. The tests pin this down with
`static_assertions::assert_not_impl_any!`, which fails the build if someone adds `Clone` later.

**Unicode NFC.** The text "café" can be stored two ways: with one character `é`
(U+00E9), or with `e` followed by a combining accent (U+0301). They look identical and
have different bytes. Different keyboards and operating systems produce different forms, so
without a fix a user could lock themselves out by typing the same password on another device.
*Normalisation Form C* (NFC) rewrites both to the same form before we hash. The
[`unicode-normalization`](https://docs.rs/unicode-normalization) crate does it.
([Unicode UAX #15](https://unicode.org/reports/tr15/))

**No reallocation.** A `String` that grows may move to a bigger allocation, and the old one
is freed without being wiped. NFC can grow UTF-8 by at most 3 times, so `to_kdf_bytes`
reserves `3 * len` bytes first and never reallocates while password bytes are inside.

## Why this matters for security

On the JVM, passwords often end up in `String` objects. Strings are immutable, so you cannot
overwrite them; they sit in memory until the garbage collector reuses the space, and
the collector may also have copied them around. That is why Java guidance says to use
`char[]` for passwords. In Rust we get to say precisely where a secret lives, who owns it,
and when it is wiped.

Be honest about the limits, though. Wiping helps, but it does not make us safe from everything:

- The operating system and the allocator can still hold copies (swap files, crash dumps, freed pages).
- The `String` the caller passes to `MasterPassword::new` may have been copied before it reached us (for example by the terminal or the UI toolkit). We wipe only what we own.
- The memory is wiped but not *locked*, so the OS may still write it to swap. Locking comes in Phase 4.

## Try it

1. Run `cargo test -p holm-crypto secret` and read the six test names. Which one proves the caller's array is wiped?
2. In `secret.rs`, temporarily add `Clone` to the derive list of `SecretKey` and run the tests. Read the error from the build, then undo it with `git checkout crates/holm-crypto/src/secret.rs`.
3. Write a tiny test that formats a `MasterPassword` containing `"hunter2"` with `{:?}` and checks that the text `hunter2` does not appear in the output.

## Read next

- [The Rust Programming Language, ch. 4: Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [ch. 15.3: Running Code on Cleanup with the Drop Trait](https://doc.rust-lang.org/book/ch15-03-drop.html)
- [zeroize documentation](https://docs.rs/zeroize)
