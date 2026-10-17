# Lesson 05: Slices, arrays and borrowing

## What we built

`crates/holm-crypto/src/aead.rs` encrypts and decrypts with XChaCha20-Poly1305, an
*authenticated* cipher (AEAD): the output is the encrypted bytes plus a 16-byte tag, and
decryption checks the tag first. If anything was changed, decryption fails and returns no
plaintext at all. `seal` encrypts, `open` decrypts. Tests check it against Wycheproof
and IETF vectors (`mod kat` in `aead.rs`) and against libsodium (`oracle/tests/xchacha.rs`).

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
- `&[u8]` is a *slice*: a reference to bytes plus a run-time length. It can point into an
  array, a `Vec`, or part of either.
- `Vec<u8>` (the return type) is an owned, growable heap buffer. `seal` creates new bytes, so
  it hands back something it owns.

In Kotlin you'd write: `fun seal(key: SecretKey, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray`.
Kotlin has one type for all three jobs, and the nonce length is checked only at run time.

([Arrays and slices](https://doc.rust-lang.org/book/ch03-02-data-types.html#the-array-type),
[The Slice Type](https://doc.rust-lang.org/book/ch04-03-slices.html),
[Vectors](https://doc.rust-lang.org/book/ch08-01-vectors.html))

### Why a fixed-size nonce turns a bug into a compile error

XChaCha20 needs a nonce of exactly 24 bytes. Because `Nonce` and `open` use `[u8; 24]`, the
compiler rejects any other length. From `mod kat` in `aead.rs`:

```rust
let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(iv.as_slice()) else {
    // Not 24 bytes: the API cannot be called with it (abridged).
    skipped += 1;
    continue;
};
```

Line by line:

- `iv.as_slice()` views the vector's nonce as a `&[u8]` of run-time length.
- `<[u8; NONCE_LEN]>::try_from(...)` returns `Ok(array)` if the length is 24, `Err` otherwise
  (lesson 03).
- `let Ok(nonce) = ... else { ... };` is `let`-`else`: take the `Ok` value, or run the `else`
  block, which must leave the iteration (`continue` here).
- Wycheproof has wrong-length nonces on purpose. Our API cannot take them, so the test counts
  them as *skipped* and asserts each skipped case must fail anyway (count in
  `crates/holm-crypto/tests/vectors/README.md`).

The cost: a caller holding a `&[u8]` must convert it once with `try_from` and handle the
length error there. After that, no later code checks. (Tests build fixed nonces with
`Nonce::from_bytes`, which exists only under `#[cfg(test)]`.)

In Kotlin you'd write: `require(nonce.size == 24)`, which throws at run time. Kotlin has no
way to put the length in the type of a `ByteArray`.

([`TryFrom`](https://doc.rust-lang.org/std/convert/trait.TryFrom.html),
[`let`-`else`](https://doc.rust-lang.org/book/ch06-03-if-let.html#staying-on-the-happy-path-with-letelse))

### Why `seal` takes the nonce by value

One nonce for two messages under the same key breaks the cipher. We make that impossible to write:

```rust
pub struct Nonce([u8; NONCE_LEN]);   // no Clone, no Copy

impl Nonce {
    pub fn random() -> Result<Self, CryptoError> { /* OS RNG */ }
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] { &self.0 }
}
```

- The field is private and the only public constructor is `Nonce::random()`, so a caller
  cannot pick `[0; 24]` by accident. With no `Clone` or `Copy`, a `Nonce` cannot be duplicated.
- `seal(key, nonce, ...)` takes `nonce: Nonce` *by value*: passing it *moves* it, and the
  caller no longer has it. A second `seal` with the same variable does not compile:
  ``error[E0382]: use of moved value: `nonce` ``.
- To store the nonce in the file, call `nonce.as_bytes()` (a borrow) *before* sealing.
- `open` takes `&[u8; 24]` because reading a stored nonce back is not reuse.

In Kotlin you'd write: `fun seal(key: SecretKey, nonce: ByteArray, ...)`. Nothing stops
`seal(key, n, a, m1); seal(key, n, a, m2)`. Kotlin has no move-only values, so you would need a
runtime flag in a `Nonce` class. In Rust the compiler rejects the program.

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

- `key.expose()` returns `&[u8; 32]`, a borrow of the key's bytes; `.into()` converts it to the
  cipher's reference type. Our code makes no extra copy of the key.
  The cipher struct holds its own copy, which the crate wipes on drop. Short-lived stack
  residue from moves can still remain; no Rust code at this level can rule that out.
- `ciphertext.to_vec()` makes an owned copy, because we change the bytes in place and the
  caller's slice is read-only (`&`, not `&mut`).
- `Zeroizing::new(...)` wipes that copy when `buf` goes out of scope, on any exit (lesson 02).
- `&mut *buf` is a *mutable borrow* of the `Vec` inside the wrapper. Rust allows only one
  `&mut` at a time, so nothing else touches the buffer meanwhile.
- `?` returns early on error (lesson 03); `buf` is dropped, and wiped, on that path.
- `std::mem::take(&mut *buf)` moves the bytes out and leaves an empty `Vec`, so the plaintext
  now belongs to the `SecretBuf`.

In Kotlin you'd write: `val buf = ciphertext.copyOf()`. Every `ByteArray` parameter is a
shared reference that a callee may change or keep. Rust spells out who reads, writes and owns.

([References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html),
[`std::mem::take`](https://doc.rust-lang.org/std/mem/fn.take.html))

### Why `seal` takes `&SecretKey`

`seal` and `open` take `key: &SecretKey`. Without `&` the key would *move* into the function
and be dropped there, so the caller could not encrypt a second record. `SecretKey` has no
`Clone` or `Copy` (lesson 02), so borrowing is the only way to use it twice. Inside `aead.rs`
the code calls `key.expose()` (a borrow) and never writes `*key.expose()`, which would copy
32 secret bytes onto the stack where nothing wipes them.

In Kotlin you'd write: `fun seal(key: SecretKey, ...)`. Nothing stops the callee from storing
the key, and nothing marks where the secret may end up.

([Ownership and functions](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html#ownership-and-functions))

### A first look at lifetimes

A *lifetime* is the stretch of code during which a reference's target is guaranteed to exist.
Usually the compiler works it out. From `secret.rs`:

```rust
pub fn expose(&self) -> &[u8; 32]
```

In full, this is:

```rust
pub fn expose<'a>(&'a self) -> &'a [u8; 32]
```

Line by line:

- `'a` names a region of code. `&'a self` is the borrow of the `SecretKey`; `&'a [u8; 32]`
  says the returned reference is valid only for that same `'a`.
- So the bytes cannot outlive the `SecretKey`. If the key is dropped (and wiped), the compiler
  refuses any code still holding a reference into it. You rarely write `'a` yourself: with one
  input reference Rust fills it in (*lifetime elision*).

In Kotlin you'd write: nothing. The garbage collector keeps an object alive while anything
references it, so key bytes can outlive the key. Rust has no garbage collector; lifetimes prove
no reference outlives its data.

([Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html))

### All or nothing: no partial plaintext

The tag covers the ciphertext and the associated data (`aad`: bytes authenticated but not
encrypted, such as the vault header; see [RFC 8439 section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8)).
`open` checks the tag before it gives back any plaintext and returns `Result<SecretBuf, CryptoError>`:

- `Ok(SecretBuf)` means every byte was checked and is genuine.
- `Err(CryptoError::Aead)` means something failed. It does not say whether the key, nonce, AAD
  or data was wrong, so it gives an attacker no hint.

There is no "first 10 bytes, the rest looked bad" case. The return type cannot express it,
deliberately: half-checked plaintext gets used sooner or later. In the tests, `flipping_any_ciphertext_byte_fails`
changes each byte in turn and expects `Err(CryptoError::Aead)` every time. Run
`cargo test -p holm-crypto --lib fails` to see those tests pass.

In Kotlin you'd write: a function that returns `ByteArray?` or throws. `null` carries no
reason and exceptions are unchecked. A Rust `Result` forces handling and carries a typed error.

([Recoverable Errors with `Result`](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html))

## Why this matters for security

A wrong-length or reused nonce survives code review and then breaks encryption. Here the
compiler rules both out, and a second hidden owner of the key. Working buffers are wiped on
every exit path and failure is one opaque error, so a failed decryption gives the attacker no
plaintext and no hint.

## Try it

1. Add this test inside `mod tests` in `aead.rs`:

   ```rust
   #[test]
   fn short_nonce_does_not_compile() {
       let nonce = vec![0u8; 12];
       let _ = open(&key(1), &nonce, AAD, &[]);
   }
   ```

   Check: `cargo test -p holm-crypto --lib` fails with ``error[E0308]: mismatched types`` at
   `&nonce`: expected `&[u8; 24]`, found `&Vec<u8>`. Change it to `&nonce[..]` and the error
   names `&[u8]` instead. Undo with `git checkout crates/holm-crypto/src/aead.rs`.
2. Add this function inside `mod tests` in `aead.rs`:

   ```rust
   fn broken() -> &'static Vec<u8> {
       let v = vec![1u8, 2, 3];
       &v
   }
   ```

   Check: ``error[E0515]: cannot return reference to local variable `v` ``. The `Vec` is dropped
   when the function ends, so the reference would dangle. Undo as above.
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

## Read next

- [The Rust Programming Language, ch. 4: Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [ch. 10.3: Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html)
