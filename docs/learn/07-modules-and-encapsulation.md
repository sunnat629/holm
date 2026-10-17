# Lesson 07: Modules and encapsulation

## What we built

`crates/holm-core/src/envelope.rs` ties the earlier pieces together into a vault you can
use. `create` makes a new vault file from a password and a body, `open` reads one back,
`reseal` saves new contents under the same keys, `rekey` changes the password, and
`verify_password` checks a password against an open vault. `crates/holm-core/src/padding.rs`
pads the body to a multiple of 16 KiB so the file size reveals little about what is
inside. `docs/CRYPTO.md` describes the whole design.

The key idea of this lesson: the data key (DEK) lives inside a struct whose fields no other
module can touch, and the compiler enforces that.

## Rust ideas in this task

### 1. Modules and `use`

From `crates/holm-core/src/lib.rs` and the top of `envelope.rs`:

```rust
pub mod envelope;
pub mod format;
pub mod padding;
```

```rust
use crate::format::{FormatError, HEADER_LEN, Header, WRAP_AAD_LEN};
use crate::padding::{pad, unpad};
```

Line by line:
- `pub mod envelope;` tells the compiler that a module named `envelope` lives in
  `src/envelope.rs`. One file is one module.
- `pub` makes the module visible to other crates, so a fuzz target outside `holm-core` can
  call `holm_core::padding::unpad`. Without `pub`, only this crate could use it.
- `use crate::format::{...}` brings names from another module into scope. `crate` means
  "the root of this crate", like an absolute path.
- The braces import several names at once. After this line, `Header` means
  `crate::format::Header`.

In Kotlin you'd write: `package holm.core.envelope` at the top of the file and
`import holm.core.format.Header`. The difference is that a Kotlin package comes from a
declaration in each file, while a Rust module exists only because a parent declares it
with `mod`. ([Defining modules](https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html))

### 2. Private fields

```rust
pub struct VaultKeys {
    dek: SecretKey,
    header: Header,
}
```

Line by line:
- `pub struct VaultKeys` makes the type visible everywhere, so the GUI can hold a
  `VaultKeys` and pass it back to `reseal`.
- `dek: SecretKey` has no `pub`, so only code inside the `envelope` module (and modules
  nested in it, such as its `tests`) can read or write it. Every other module, in this
  crate or outside it, gets a compile error.
- The same holds for `header`. Outside code cannot swap in a header that does not match
  the DEK.
- Because the fields are private, outside code also cannot build a `VaultKeys` with
  `VaultKeys { dek, header }`. The public ways to get one are `create`, `open` and `rekey`.

In Kotlin you'd write: `class VaultKeys internal constructor(private val dek: SecretKey,
private val header: Header)`. Close, but Kotlin's `private` is per class, while Rust's
privacy is per module: every function in `envelope.rs` can see `dek`, and nothing outside
that module can. ([Privacy of struct fields](https://doc.rust-lang.org/book/ch07-03-paths-for-referring-to-an-item-in-the-module-tree.html#making-structs-and-enums-public))

### 3. `pub(crate)` and `#[cfg(test)]`

```rust
impl VaultKeys {
    /// The data key. Tests only.
    #[cfg(test)]
    pub(crate) fn dek(&self) -> &SecretKey {
        &self.dek
    }
}
```

```rust
pub(crate) fn open_with_kek(
    file: &[u8],
    kek: &SecretKey,
) -> Result<(VaultKeys, SecretBuf), VaultError> {
```

Line by line:
- `#[cfg(test)]` means "compile this only when building tests". In a normal build the
  `dek()` method does not exist at all, so no release code can call it by mistake.
- `pub(crate)` means visible anywhere in `holm-core`, but not to other crates. The tests in
  `padding.rs` could call `dek()`; the GUI crate never can.
- `&self` borrows the keys, and `&SecretKey` lends out the key without copying it.
- `open_with_kek` is `pub(crate)` with no `cfg(test)`: `open` uses it in real builds, after
  deriving the key. Tests call it directly to flip every byte of a file while running
  Argon2 only once.

In Kotlin you'd write: `internal fun openWithKek(...)` for module-wide visibility, and
`@VisibleForTesting` for the test accessor. But `@VisibleForTesting` is only a hint for
lint; the method is still in the shipped class. `#[cfg(test)]` removes it from the build.
([Visibility and privacy](https://doc.rust-lang.org/reference/visibility-and-privacy.html),
[Test organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html))

### 4. Taking ownership: the old keys are gone after `rekey`

```rust
pub fn rekey(
    keys: VaultKeys,
    new_password: &MasterPassword,
    params: &KdfParams,
    body: &[u8],
) -> Result<(VaultKeys, Vec<u8>), VaultError> {
    // The old DEK is wiped here, whatever the outcome.
    drop(keys);
    create(new_password, params, body)
}
```

Line by line:
- `keys: VaultKeys` has no `&`. The caller hands over ownership, the same idea as a method
  that takes `self` by value.
- After the call, the caller's variable is "moved from". Using it again is a compile error,
  `borrow of moved value`.
- `drop(keys)` ends the old value now, and `SecretKey`'s drop wipes the old DEK.
- `create(...)` makes a fresh salt, a fresh DEK and fresh nonces, and returns new keys. The
  caller must use those from now on, because the compiler will not let them touch the old
  ones.

In Kotlin you'd write: `fun rekey(keys: VaultKeys, ...)`. The caller still holds `keys`
afterwards, and nothing stops it from calling `reseal(keys, ...)` with the old DEK.
Rust turns that mistake into a build error. ([What is ownership?](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html))

### 5. `From` and `?`

```rust
impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::KdfParams(k) => VaultError::KdfPolicy(k),
            CryptoError::Aead => VaultError::WrongPasswordOrCorrupt,
            CryptoError::Rng | CryptoError::Kdf | CryptoError::InvalidKeyLength => {
                VaultError::Crypto
            }
        }
    }
}
```

and, in `create`:

```rust
let kek = derive_kek(password, &salt, params)?;
```

Line by line:
- `impl From<CryptoError> for VaultError` teaches Rust how to turn a `CryptoError` into a
  `VaultError`.
- `match e` lists every `CryptoError` variant with no `_` arm. If `holm-crypto` adds a
  variant, this stops compiling until someone decides where it goes.
- `CryptoError::Aead` becomes `WrongPasswordOrCorrupt`. A failed body decrypt arrives here
  as `Aead` and leaves as the same error that `open_with_kek` returns when the DEK unwrap
  fails.
- In `create`, `derive_kek` returns `Result<SecretKey, CryptoError>`, but `create` returns
  `Result<_, VaultError>`. On `Err`, `?` calls `VaultError::from` and returns early. On
  `Ok`, it unwraps the key.

In Kotlin you'd write: `try { deriveKek(...) } catch (e: CryptoException) { throw
e.toVaultError() }` at each call. In Rust the conversion is written once and `?` applies
it at every call site. ([The `?` operator](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html#a-shortcut-for-propagating-errors-the--operator))

### 6. Why these `From` impls are written by hand

```rust
impl From<FormatError> for VaultError {
    fn from(e: FormatError) -> Self {
        match e {
            FormatError::KdfPolicy(k) => VaultError::KdfPolicy(k),
            other => VaultError::Format(other),
        }
    }
}
```

Line by line:
- thiserror can generate a `From` impl if you write `#[from]` on a variant, as in
  `Format(#[from] FormatError)`. That impl wraps every `FormatError` the same way.
- Here the parser's `FormatError::KdfPolicy(k)` is unpacked and becomes
  `VaultError::KdfPolicy(k)`. `create` reports a bad cost as `KdfPolicy` too, so callers
  see one error for one problem, wherever it was found.
- `other => VaultError::Format(other)` wraps every remaining format error unchanged.
- With `#[from]`, a too-expensive header would come out as `Format(KdfPolicy(..))`, and a
  `match` on `VaultError::KdfPolicy` in the GUI would miss it.

In Kotlin you'd write: a `when (e) { is FormatError.KdfPolicy -> VaultError.KdfPolicy(e.reason); else -> VaultError.Format(e) }` helper. Same idea; the Rust version is picked up by
`?` automatically. ([Traits](https://doc.rust-lang.org/book/ch10-02-traits.html),
[`From`](https://doc.rust-lang.org/std/convert/trait.From.html))

## Why this matters for security

The DEK decrypts everything in the vault, so the fewer places that can touch it, the fewer
places can leak it. Private fields, `pub(crate)` and `#[cfg(test)]` let the compiler
check that, in a release build, only `envelope.rs` can reach the DEK inside `VaultKeys`.
Taking the old keys by value in `rekey` means a password change cannot leave the old DEK
in use, and the error mapping sends a wrong password and a tampered file to the same
error.

## Try it

Run each one from the repo root. Undo after each: `git checkout crates/holm-core/src/`

1. Add this test at the end of `mod tests` in `crates/holm-core/src/padding.rs`, then run
   `cargo test -p holm-core peek_at_dek`:

   ```rust
   #[test]
   fn peek_at_dek() {
       let password = holm_crypto::MasterPassword::new("p".to_owned());
       let params = holm_crypto::kdf::KdfParams::FLOOR;
       let (keys, _) = crate::envelope::create(&password, &params, b"x").unwrap();
       assert_eq!(keys.dek.expose().len(), 32);
   }
   ```

   Check: the build fails with ``error[E0616]: field `dek` of struct `envelope::VaultKeys`
   is private``. Change `keys.dek.expose()` to `keys.dek().expose()` and run the same
   command. It passes, because `dek()` is `pub(crate)` and this is a test build.
2. Add this test inside `mod tests` in `crates/holm-core/src/envelope.rs`, then run
   `cargo test -p holm-core use_after_rekey`:

   ```rust
   #[test]
   fn use_after_rekey() {
       let (keys, _) = new_vault(b"x");
       let _ = rekey(keys, &pw("new"), &FLOOR, b"x").unwrap();
       let _ = verify_password(&keys, &pw("new"));
   }
   ```

   Check: the build fails with ``error[E0382]: borrow of moved value: `keys` ``, pointing at
   `rekey` with "this parameter takes ownership of the value". The compiler also suggests
   implementing `Clone` for `VaultKeys`; for a type that holds a key, that would be the
   wrong fix. Instead, change the second line to
   `let (keys, _) = rekey(keys, &pw("new"), &FLOOR, b"x").unwrap();` and the third to
   `assert_eq!(verify_password(&keys, &pw("new")), Ok(()));`. It passes.
3. In `envelope.rs`, delete the line
   `FormatError::KdfPolicy(k) => VaultError::KdfPolicy(k),` from `impl From<FormatError>`
   and run `cargo test -p holm-core kdf_above_ceiling`.
   Check: `kdf_above_ceiling_is_policy_error_not_wrong_password` fails with
   `left: Format(KdfPolicy(AboveCeiling))` and `right: KdfPolicy(AboveCeiling)`. This is
   what a `#[from]` would have produced.

## Read next

- *The Rust Programming Language* [chapter 7, Managing Growing Projects with Packages,
  Crates, and Modules](https://doc.rust-lang.org/book/ch07-00-managing-growing-projects-with-packages-crates-and-modules.html)
- [Chapter 4.1, What Is Ownership?](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html)
- [Chapter 11.3, Test Organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
- [Chapter 10.2, Traits: Defining Shared Behavior](https://doc.rust-lang.org/book/ch10-02-traits.html)

Next lesson (written when its task lands): property tests and fuzzing.
