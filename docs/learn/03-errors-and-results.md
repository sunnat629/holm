# Lesson 03: Errors, Result and randomness

## What we built

Two small files and two new functions in `crates/holm-crypto`:

- `src/error.rs`: `CryptoError` and `KdfParamsError`, the error types for the whole crate.
- `src/random.rs`: `fill_random` and `random_array`, which ask the operating system for random bytes.
- `SecretKey::generate()` and `SecretKey::from_slice()` in `src/secret.rs`.

Every function that can fail now returns a `Result`, and no error message contains a key,
a password or plaintext. The decryption error is deliberately vague.

## Rust ideas in this task

### Enums that carry data, and thiserror

The real code from `error.rs`:

```rust
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("the operating system could not provide random bytes")]
    Rng,
    #[error("invalid key-derivation parameters: {0}")]
    KdfParams(KdfParamsError),
    #[error("decryption failed")]
    Aead,
    #[error("key must be exactly 32 bytes")]
    InvalidKeyLength,
    // (the Kdf variant is left out here for space)
}
```

Line by line:

- `pub enum CryptoError` declares a type that is exactly one of its listed *variants*.
- `Rng`, `Aead` and `InvalidKeyLength` carry nothing. `KdfParams(KdfParamsError)` carries one
  value inside it, here a second enum saying which parameter check failed.
- `#[error("...")]` comes from the [`thiserror`](https://docs.rs/thiserror) crate. It writes the
  `Display` implementation, which is what `to_string()` and `println!("{e}")` use.
  `{0}` inserts the first field of the variant.
- `thiserror::Error` also implements the standard `std::error::Error` trait.
- `Debug` is needed by `unwrap()` and by test failure output. `PartialEq` and `Eq` let us
  compare two errors with `==`; more on that below.

In Kotlin you'd write: a `sealed class CryptoError : Exception()` with `object Rng`,
`object Aead` and `class KdfParams(val why: KdfParamsError)` as subclasses. Kotlin's sealed
class is the closest match to a Rust enum with data. One difference: you write the message
logic yourself, while `thiserror` generates it from the attribute.

([Defining an Enum](https://doc.rust-lang.org/book/ch06-01-defining-an-enum.html))

### Result, the `?` operator and `match`

```rust
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}
```

Line by line:

- `Result<(), CryptoError>` is an enum from the standard library with two variants:
  `Ok(value)` and `Err(error)`. `()` is the empty value, so `Ok(())` means "it worked and
  there is nothing to return".
- `buf: &mut [u8]` borrows a slice of bytes that the function may overwrite.
- `getrandom::fill(buf)` returns its own `Result` with the `getrandom` crate's error type.
  `.map_err(|_| CryptoError::Rng)` replaces whatever error came back with ours. `|_|` is a
  closure that ignores its argument. We drop the original error on purpose so that we expose
  a single stable error type.
- In `random_array`, `fill_random(&mut out)?` means: if the result is `Err`, return that error
  from the whole function right now; if it is `Ok`, continue. The `?` is shorthand for a
  `match`. Expanded, it looks roughly like this (the real expansion also converts the error
  type with `From`):

  ```rust
  match fill_random(&mut out) {
      Ok(v) => v,
      Err(e) => return Err(e),
  }
  ```

- `Ok(out)` on the last line has no semicolon, so it is the return value.

Nothing here is thrown. A function that can fail says so in its return type, and the caller
must handle it: the compiler warns about an ignored `Result`.

In Kotlin you'd write: `fun fillRandom(buf: ByteArray) { try { SecureRandom().nextBytes(buf) } catch (e: Exception) { throw CryptoError.Rng() } }`.
Kotlin signatures do not show that a function throws, so a caller can forget the `try`. The closest Kotlin equivalent of Rust's approach is the standard library's `Result<T>` or a sealed class you return.

([Recoverable Errors with Result](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html))

### Const generics: `[u8; N]`

In `random_array<const N: usize>()` the `N` is a number known at compile time. The call
`random_array::<24>()` (used in our test `random_nonces_differ`) makes `N` equal to 24, so the
return type is exactly `[u8; 24]`, an array whose length is part of its type. `[0u8; N]`
creates N zero bytes on the stack.

This function is for salts and nonces only, which are not secret. The array lives on the stack
and is returned by value, so it may be copied. That would be wrong for a key, which is why keys
use `SecretKey::generate()` instead (next section).

In Kotlin you'd write: `fun randomArray(n: Int): ByteArray`. The length is a runtime value
and the type is just `ByteArray`, so the compiler cannot tell a 24-byte nonce from a 32-byte
key. Java and Kotlin have no way to put an array length in a type.

([Generic Data Types](https://doc.rust-lang.org/book/ch10-01-syntax.html),
[const generics in the Rust Reference](https://doc.rust-lang.org/reference/items/generics.html#const-generics))

### Writing a key straight into the heap

```rust
pub fn generate() -> Result<SecretKey, CryptoError> {
    let mut k = SecretKey::zeroed();
    fill_random(k.expose_mut())?;
    Ok(k)
}

pub fn from_slice(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut key = SecretKey::zeroed();
    key.0.copy_from_slice(bytes);
    Ok(key)
}
```

Line by line:

- `SecretKey::zeroed()` makes a box of 32 zero bytes (from lesson 02).
- `k.expose_mut()` lends out a `&mut [u8; 32]` pointing into that box. `fill_random` writes the
  random bytes there directly, so the key is never built on the stack first.
- The `?` returns early on error. If it does, `k` is dropped on the way out and wiped.
- In `from_slice`, `bytes: &[u8]` is a read-only view of bytes owned by someone else. We check
  the length first and return `Err(InvalidKeyLength)` if it is not 32.
- `copy_from_slice` panics if the lengths differ, so the check above is what makes it safe to call.
  It copies into the box with no temporary buffer. The caller still owns `bytes` and must wipe
  them if they are secret; we do not do that for them.

In Kotlin you'd write: `fun fromSlice(b: ByteArray): SecretKey { require(b.size == 32); return SecretKey(b.copyOf()) }`.
`require` throws an exception, and the copy lives in the garbage-collected heap where it cannot
be reliably wiped.

([Slices](https://doc.rust-lang.org/book/ch04-03-slices.html))

### Comparing errors in tests

```rust
#[test]
fn from_slice_rejects_wrong_length() {
    assert_eq!(
        SecretKey::from_slice(&[0u8; 31]).unwrap_err(),
        CryptoError::InvalidKeyLength
    );
}
```

`assert_eq!` needs both sides to implement `PartialEq` (to compare) and `Debug` (to print on
failure). We derived both on `CryptoError`, so a test can say exactly which error it expects
instead of just "some error". `unwrap_err()` takes the `Err` out of a `Result` and panics if
it was `Ok`. Panicking in a test is fine; in library code we return errors instead.

`unwrap_err()` needs the `Ok` type to implement `Debug`, because on failure it prints the
`Ok` value. Here that value would be a `SecretKey`, and that is safe only because lesson 02
made its `Debug` print `[REDACTED]`.

Note that `SecretKey` has no `PartialEq`, so we cannot write `assert_eq!` on a
`Result<SecretKey, _>` directly. That is why the test calls `unwrap_err()` first.

In Kotlin you'd write: `assertEquals(CryptoError.InvalidKeyLength, assertFailsWith<CryptoError> { ... })`.
With exceptions you must catch first and then inspect.

([Derivable Traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html))

## Why this matters for security

Error messages end up in logs and bug tickets, so every `CryptoError` message is a fixed string with no place to put key or password bytes. Decryption has one error, `"decryption failed"`, which a test pins exactly: if we said "wrong key" in one case and "data was changed" in another, an attacker who can try many inputs would learn something from each answer (a padding oracle). Randomness has no fallback in Holm's code: if the OS generator fails we return `CryptoError::Rng` and stop, and the `getrandom` crate only ever uses the operating system's generator, never the clock. The limits are that `generate` avoids a stack copy only in our own code, and nothing but the doc comment and code review stops someone calling `random_array` for a key.

## Try it

1. Run `cargo test -p holm-crypto from_slice`. Check: both `from_slice` tests show `ok` and the summary line reads `2 passed`.
2. In `random.rs`, replace the body of `fill_random` with `let _ = buf; Ok(())` (a "random" function that does nothing) and run `cargo test -p holm-crypto differ`. Check: the summary line reads `3 failed` (`random::random_nonces_differ`, `aead::random_nonces_differ` and `secret::two_generated_keys_differ`). Explain in one sentence why a broken generator that leaves zeros is caught. Undo with `git checkout crates/holm-crypto/src/random.rs`.
3. In `error.rs`, add a variant to `CryptoError`, with a doc line because the crate uses `deny(missing_docs)`:

   ```rust
   /// The input was too short.
   #[error("data is too short")]
   Truncated,
   ```

   Then add this test inside the existing `mod tests` block in the same file:

   ```rust
   #[test]
   fn truncated_message() {
       assert_eq!(CryptoError::Truncated.to_string(), "data is too short");
   }
   ```

   Run `cargo test -p holm-crypto truncated`. Check: `1 passed`. (If you leave out the `///` line, the compiler stops with `missing documentation for a variant`; that is the `deny(missing_docs)` lint at work.) Then undo with `git checkout crates/holm-crypto/src/error.rs`.

## Read next

- [The Rust Programming Language, ch. 6: Enums and Pattern Matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [ch. 9: Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- [thiserror documentation](https://docs.rs/thiserror)
- [getrandom documentation](https://docs.rs/getrandom)
