# Lesson 05: Slices, arrays and borrowing

## What we built

`crates/holm-crypto/src/aead.rs` encrypts and decrypts with XChaCha20-Poly1305, an
*authenticated* cipher (AEAD): the output is the encrypted bytes plus a 16-byte tag, and
decryption checks the tag first. If anything was changed, decryption fails and returns no
plaintext at all. `seal` encrypts, `open` decrypts. Tests check it against the official
Wycheproof vectors and the IETF draft's example (`mod kat` in `aead.rs`), and against
libsodium on random inputs (`oracle/tests/xchacha.rs`).

## Rust ideas in this task

### Slices, arrays and `Vec`: three ways to hold bytes

From the signature of `seal`:

```rust
pub fn seal(
    key: &SecretKey,
    nonce: Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError>
```

Line by line:

- `Nonce` wraps an *array*, `[u8; NONCE_LEN]`: exactly 24 bytes, and the length is part of the
  type. `open` takes the bare form, `&[u8; NONCE_LEN]`, a reference to such an array. Arrays
  live on the stack or inside another value.
- `&[u8]` is a *slice*: a reference to some bytes in memory plus a length that is known only
  at run time. It can point into an array, a `Vec`, or part of either.
- `Vec<u8>` (the return type) is an owned, growable buffer on the heap. `seal` creates new
  bytes, so it must hand back something it owns.

In Kotlin you'd write: `fun seal(key: SecretKey, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray`.
Kotlin has one type, `ByteArray`, for all three jobs, and nothing checks the nonce length
until the code runs.

([Arrays and slices](https://doc.rust-lang.org/book/ch03-02-data-types.html#the-array-type),
[The Slice Type](https://doc.rust-lang.org/book/ch04-03-slices.html),
[Vectors](https://doc.rust-lang.org/book/ch08-01-vectors.html))

### Why a fixed-size nonce turns a bug into a compile error

XChaCha20 needs a nonce of exactly 24 bytes. Because `Nonce` and `open` use `[u8; 24]`, the
compiler rejects any other length. From `mod kat` in `aead.rs`:

```rust
let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(iv.as_slice()) else {
    // Not 24 bytes: the API cannot even be called with it.
    // (abridged: the real block also checks the case is `invalid` and flagged)
    skipped += 1;
    continue;
};
```

Line by line:

- `iv.as_slice()` views the test vector's nonce as a `&[u8]`, whose length is only known at
  run time.
- `<[u8; NONCE_LEN]>::try_from(...)` asks "can these bytes become a 24-byte array?" It returns
  `Result`: `Ok(array)` if the length is 24, `Err` otherwise (see lesson 03).
- `let Ok(nonce) = ... else { ... };` is `let`-`else`: take the `Ok` value, or run the `else`
  block, which must leave the loop iteration (`continue` here).
- The Wycheproof file contains nonces of the wrong length on purpose, to test libraries that
  accept any length. In our API those calls cannot be written, so the test counts them as
  *skipped* and asserts that every skipped case is one that must fail anyway. The exact
  number is recorded in `crates/holm-crypto/tests/vectors/README.md`.

The test above can pass a fixed nonce only because `Nonce::from_bytes` exists under
`#[cfg(test)]`: it is compiled out of the real library, so no shipped code can call it.

The cost: a caller holding a `&[u8]` or `Vec<u8>` must convert it once, with `try_from`, and
handle the length error there. After that, no later code needs to check.

In Kotlin you'd write: `require(nonce.size == 24)`, which throws at run time. Kotlin has no
way to put the length in the type of a `ByteArray`.

([`TryFrom`](https://doc.rust-lang.org/std/convert/trait.TryFrom.html),
[`let`-`else`](https://doc.rust-lang.org/book/ch06-03-if-let.html#staying-on-the-happy-path-with-letelse))

### Why `seal` takes the nonce by value

Using one nonce for two different messages under the same key breaks the cipher. We make
that impossible to write:

```rust
pub struct Nonce([u8; NONCE_LEN]);   // no Clone, no Copy

impl Nonce {
    pub fn random() -> Result<Self, CryptoError> { /* OS RNG */ }
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] { &self.0 }
}
```

- The field is private and the only public constructor is `Nonce::random()`, so a caller
  cannot pick a number such as `[0; 24]` by accident.
- There is no `Clone` and no `Copy`, so a `Nonce` cannot be duplicated.
- `seal(key, nonce, ...)` takes `nonce: Nonce` *by value*. Passing it *moves* it into the
  function, and the caller no longer has it. A second `seal(key, nonce, ...)` with the same
  variable does not compile: ``error[E0382]: use of moved value: `nonce` ``.
- To store the nonce in the file, call `nonce.as_bytes()` (a borrow) *before* sealing.
- `open` takes `&[u8; 24]` because reading a stored nonce back is not reuse.

In Kotlin you'd write: `fun seal(key: SecretKey, nonce: ByteArray, ...)`. Nothing stops
`seal(key, n, a, m1); seal(key, n, a, m2)`, because the same array can be passed any number of
times. Kotlin has no move-only values, so you would need a runtime flag inside a `Nonce` class
and a thrown exception on the second use. In Rust the compiler rejects the program.

([Ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html),
[Moves](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html#variables-and-data-interacting-with-move))

### Borrowing (`&`) versus owning

From `open`:

```rust
let cipher = XChaCha20Poly1305::new(key.expose().into());
let mut buf = Zeroizing::new(ciphertext.to_vec());
cipher
    .decrypt_in_place(nonce.into(), aad, &mut *buf)
    .map_err(|_| CryptoError::Aead)?;
Ok(SecretBuf::from_vec(std::mem::take(&mut *buf)))
```

Line by line:

- `key.expose()` returns `&[u8; 32]`, a borrow of the key's bytes. `.into()` turns that
  reference into the reference type the cipher wants. Our code makes no extra copy of the key.
  The cipher struct that `new` builds does hold its own copy, and the crate wipes it when the
  cipher is dropped. Moves and crate internals can still leave short-lived residue on the
  stack, which no Rust code at this level can fully rule out.
- `ciphertext.to_vec()` makes an owned copy of the input, because we are about to change the
  bytes in place and the caller's slice is read-only (`&`, not `&mut`).
- `Zeroizing::new(...)` wraps that owned copy so its memory is wiped when `buf` goes out of
  scope, whichever way the function exits (lesson 02).
- `&mut *buf` is a *mutable borrow* of the `Vec` inside the wrapper. `decrypt_in_place` may
  change it, and Rust allows only one `&mut` at a time, so nothing else can touch the buffer
  meanwhile.
- `?` returns early on error (lesson 03), and `buf` is dropped, and wiped, on that path.
- `std::mem::take(&mut *buf)` moves the bytes out and leaves an empty `Vec` behind, so the
  wrapper has nothing left to wipe and the plaintext now belongs to the `SecretBuf`.

In Kotlin you'd write: `val buf = ciphertext.copyOf()`. Every `ByteArray` parameter is a
shared reference, and nothing stops a callee from changing it or keeping it. Rust spells out
who may read, who may write, and who owns.

([References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html),
[`std::mem::take`](https://doc.rust-lang.org/std/mem/fn.take.html))

### Why `seal` takes `&SecretKey`

`seal` and `open` take `key: &SecretKey`, not `key: SecretKey`. A parameter without `&` would
*move* the key into the function and drop it at the end, so the caller could never encrypt a
second record with it. Borrowing lets the caller keep the one key it has and lend it for the
length of the call.

`SecretKey` also has no `Clone` and no `Copy` (lesson 02), so the only way to use it twice is
to borrow it. The same rule keeps the code honest inside `aead.rs`: it reads the key bytes
with `key.expose()`, which hands out a borrow, and never writes `*key.expose()`, which would
copy 32 secret bytes onto the stack where nothing wipes them.

In Kotlin you'd write: `fun seal(key: SecretKey, ...)`. Passing an object never copies it, but
nothing stops the callee from storing it, and nothing marks where the secret may end up.

([Ownership and functions](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html#ownership-and-functions))

### A first look at lifetimes

Every reference has a *lifetime*: the stretch of code during which the thing it points to is
guaranteed to exist. Usually the compiler works it out itself. From `secret.rs`:

```rust
pub fn expose(&self) -> &[u8; 32]
```

Written out in full, this is:

```rust
pub fn expose<'a>(&'a self) -> &'a [u8; 32]
```

Line by line:

- `'a` is a lifetime name. It is not a value; it labels a region of code.
- `&'a self` says: this borrow of the `SecretKey` lasts for `'a`.
- `&'a [u8; 32]` says: the returned reference is valid only for that same `'a`.
- So the returned bytes cannot outlive the `SecretKey`. If the key is dropped (and wiped), the
  compiler refuses any code that still holds a reference into it. Writing `'a` yourself is
  rare: when a function has one input reference, Rust fills it in (*lifetime elision*).

In Kotlin you'd write: nothing. The garbage collector keeps an object alive while anything
references it, so a `ByteArray` view of key bytes can stay in use long after you meant the key
to be gone. Rust has no garbage collector, and lifetimes are how it proves no reference
outlives its data.

([Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html))

### All or nothing: no partial plaintext

AEAD means (see [RFC 8439 section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8) for the
construction) the tag covers the ciphertext and the associated data (`aad`, bytes that are
authenticated but not encrypted, such as the vault header). `open` checks the tag before it
gives back any plaintext, and it returns `Result<SecretBuf, CryptoError>`:

- `Ok(SecretBuf)` means every byte was checked and is genuine.
- `Err(CryptoError::Aead)` means something failed. The one error does not say whether the key,
  the nonce, the AAD or the data was wrong, so it cannot be used as a hint by an attacker.

There is no third case such as "here are the first 10 bytes, the rest looked bad". The return
type cannot express it, and that is deliberate: a program that receives half-checked
plaintext will, sooner or later, use it. In the tests, `flipping_any_ciphertext_byte_fails`
changes each byte in turn and expects `Err(CryptoError::Aead)` every time.

In Kotlin you'd write: a function that returns `ByteArray?` or throws. Kotlin's null-safety does
force the caller to handle a `ByteArray?`, but `null` carries no reason, and thrown exceptions
are unchecked, so nothing makes the caller handle them. A Rust `Result` forces handling and
can carry a typed error.

([Recoverable Errors with `Result`](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html))

## Why this matters for security

A nonce of the wrong length is the kind of mistake that survives code review and then
weakens or breaks encryption. Here the compiler rules it out, and it also rules out a second
hidden owner of the key, and a reused nonce. Because our working buffers are wiped on every exit path and failure
is one opaque error, a failed decryption hands the attacker no plaintext and no hint about
what was wrong.

## Try it

1. Add this test inside `mod tests` in `aead.rs`:

   ```rust
   #[test]
   fn short_nonce_does_not_compile() {
       let nonce = vec![0u8; 12];
       let _ = seal(&key(1), &nonce, AAD, MSG);
   }
   ```

   Check: `cargo test -p holm-crypto --lib` fails to build with ``error[E0308]: mismatched types``,
   pointing at `&nonce`. Then change it to `&nonce[..]` and see that the error now names a
   slice, not an array. (It also complains that `seal` wants a `Nonce`, not a reference.) Undo with `git checkout crates/holm-crypto/src/aead.rs`.
2. Add this function inside `mod tests` in `aead.rs`:

   ```rust
   fn broken() -> &'static Vec<u8> {
       let v = vec![1u8, 2, 3];
       &v
   }
   ```

   Check: `cargo test -p holm-crypto --lib` fails with
   ``error[E0515]: cannot return reference to local variable `v` ``. The `Vec` is dropped when
   the function ends, so a reference to it would dangle. Undo with the same `git checkout`.
3. Add this test inside `mod tests` in `aead.rs`:

   ```rust
   #[test]
   fn nonce_reuse_does_not_compile() {
       let nonce = Nonce::random().unwrap();
       let _a = seal(&key(1), nonce, AAD, MSG);
       let _b = seal(&key(1), nonce, AAD, MSG);
   }
   ```

   Check: ``error[E0382]: use of moved value: `nonce` ``. Undo with the same `git checkout`.
4. Read the tests in `aead.rs` whose names end in `fails`. Check:
   `cargo test -p holm-crypto --lib fails` prints one `... ok` line per such test.

## Read next

- [The Rust Programming Language, ch. 4: Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [ch. 10.3: Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html)
