# Lesson 07: Modules and encapsulation

## What we built

`crates/holm-core/src/envelope.rs` turns the earlier pieces into a usable vault: `create`,
`open`, `reseal` (save), `rekey` (change the password) and `verify_password`. `open` and
`verify_password` are `pub(crate)`: only `Session` calls them, so the throttle cannot be skipped.
`padding.rs` pads the body to a multiple of 16 KiB. `docs/CRYPTO.md` describes the design.
The key idea: the data key (DEK) lives in a struct whose fields no other module can touch,
and the compiler enforces that.

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
  `src/envelope.rs`. Each `mod x;` loads one file, and a file can nest more modules
  inside it, such as `mod tests`.
- `pub` makes the module visible to other crates, so a fuzz target outside `holm-core` can
  call `holm_core::padding::unpad`. Without `pub`, only this crate could use it.
- `use crate::format::{...}` brings several names from another module into scope. `crate`
  means "the root of this crate", so `Header` now means `crate::format::Header`.

In Kotlin you'd write: `package holm.core.envelope` and `import holm.core.format.Header`.
But a Kotlin package is declared by each file, while a Rust module exists only because a
parent declares it with `mod`. ([Defining modules](https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html))

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
  nested in it, such as its `tests`) can read or write it. Any other module gets a compile
  error.
- The same holds for `header`, so outside code cannot swap in a header that does not match
  the DEK, or build a `VaultKeys` itself. The public ways to get one are `create` and
  `open`.

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
  `padding.rs` could call `dek()`; the GUI crate never can. It lends the key (`&SecretKey`)
  without copying it.
- `open_with_kek` is `pub(crate)` with no `cfg(test)`: `open` uses it in real builds, after
  deriving the key. Tests call it directly to flip every byte of a file while running
  Argon2 only once.

In Kotlin you'd write: `internal fun openWithKek(...)`, and `@VisibleForTesting` for the
accessor. That annotation is only a lint hint and the method still ships; `#[cfg(test)]`
removes it from the build.
([Visibility and privacy](https://doc.rust-lang.org/reference/visibility-and-privacy.html),
[Test organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html))

### 4. Replacing a value through `&mut`

```rust
pub fn rekey(
    keys: &mut VaultKeys,
    new_password: &MasterPassword,
    params: &KdfParams,
    body: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let (new_keys, file) = create(new_password, params, body)?;
    *keys = new_keys;
    Ok(file)
}
```

Line by line:
- `keys: &mut VaultKeys` borrows the caller's keys mutably. The caller keeps ownership.
- `create(...)?` builds a fresh salt, DEK and nonces first. If it fails, `?` returns
  before `keys` is touched, so the old keys still work with the old password.
- `*keys = new_keys;` writes through the reference. The old value is dropped right there,
  and `SecretKey`'s drop wipes the old DEK.
- While the `&mut` borrow lasts, no other reference to `keys` may exist, so no code can
  still be holding the old DEK when it is replaced (exercise 2 shows the error).

In Kotlin you'd write: `vault.keys = newKeys`. The old object stays in memory until the
garbage collector frees it, unwiped, and any other reference to its key keeps working.
([References and borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html))

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
  `VaultError`. `match e` has no `_` arm, so a new `CryptoError` variant stops the build
  until someone decides where it goes.
- `CryptoError::Aead` becomes `WrongPasswordOrCorrupt`. A failed DEK unwrap and a failed
  body decrypt both arrive here as `Aead`, so they leave as the same error.
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
- Here the parser's `FormatError::KdfPolicy(k)` becomes `VaultError::KdfPolicy(k)`, the
  same error `create` gives for a bad cost. `other => ...` wraps every other format error.
- With `#[from]`, a too-expensive header would come out as `Format(KdfPolicy(..))`, and a
  `match` on `VaultError::KdfPolicy` in the GUI would miss it.

In Kotlin you'd write: a helper with `when (e) { is FormatError.KdfPolicy -> ...; else ->
VaultError.Format(e) }`. Same idea, but `?` picks up the Rust version automatically. ([Traits](https://doc.rust-lang.org/book/ch10-02-traits.html),
[`From`](https://doc.rust-lang.org/std/convert/trait.From.html))

## Why this matters for security

The DEK decrypts everything in the vault, so the fewer places that can touch it, the fewer
places can leak it. Private fields, `pub(crate)` and `#[cfg(test)]` let the compiler
check that, in a release build, only `envelope.rs` can reach the DEK inside `VaultKeys`.
Replacing the keys through `&mut` in `rekey` means a password change cannot leave the old
DEK in use, and the error mapping sends a wrong password and a tampered file to the same
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
   `cargo test -p holm-core hold_old_dek`:

   ```rust
   #[test]
   fn hold_old_dek_across_rekey() {
       let (mut keys, _) = new_vault(b"x");
       let old = keys.dek();
       rekey(&mut keys, &pw("new"), &FLOOR, b"x").unwrap();
       assert_eq!(old.expose().len(), 32);
   }
   ```

   Check: the build fails with ``error[E0502]: cannot borrow `keys` as mutable because it
   is also borrowed as immutable``: `old` still points into `keys`. Change the `let old`
   line to `let old = SecretKey::from_slice(keys.dek().expose()).unwrap();` (an explicit
   copy) and the last line to `assert_ne!(old.expose(), keys.dek().expose());`. It passes.
3. In `envelope.rs`, delete the line
   `FormatError::KdfPolicy(k) => VaultError::KdfPolicy(k),` from `impl From<FormatError>`
   and run `cargo test -p holm-core kdf_above_ceiling`.
   Check: `kdf_above_ceiling_is_policy_error_not_wrong_password` fails with
   `left: Format(KdfPolicy(AboveCeiling))` and `right: KdfPolicy(AboveCeiling)`. This is
   what a `#[from]` would have produced.

## Read next

- *The Rust Programming Language* [chapter 7, Managing Growing Projects with Packages,
  Crates, and Modules](https://doc.rust-lang.org/book/ch07-00-managing-growing-projects-with-packages-crates-and-modules.html)
- [Chapter 4.2, References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html)
- [Chapter 9.2, Recoverable Errors with `Result`](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)

Next lesson: [08, property tests and fuzzing](08-property-tests-and-fuzzing.md).
