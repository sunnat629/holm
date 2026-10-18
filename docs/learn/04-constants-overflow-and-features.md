# Lesson 04: Constants, integer overflow and Cargo features

## What we built

`crates/holm-crypto/src/kdf.rs` turns the master password into a 32-byte key with Argon2id,
a deliberately slow and memory-hungry hash (RFC 9106). The costs (memory, passes, lanes) are
stored in the vault header, so an attacker can edit them. `KdfParams::validate` checks them
against a floor and a ceiling before any memory is allocated. Tests check our Argon2id against
the RFC's published answer, and a separate `oracle/` workspace checks it against libsodium, a
second, independent implementation.

## Rust ideas in this task

### `const` and associated constants

From `kdf.rs`:

```rust
pub const MAX_M_KIB: u32 = 1_048_576;

impl KdfParams {
    pub const FLOOR: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };
}
```

Line by line:

- `pub const MAX_M_KIB: u32 = 1_048_576;` is a compile-time constant. The type is required.
  The `_` separators are ignored by the compiler and only help the reader (1 GiB in KiB).
- `impl KdfParams { ... }` adds items to the `KdfParams` type.
- `pub const FLOOR: Self = Self { ... };` is an *associated constant*: a constant that belongs
  to the type, used as `KdfParams::FLOOR`. `Self` means `KdfParams` here.
- A `const` has no fixed address. The compiler pastes the value in wherever it is used, so it
  costs nothing at run time and can never be changed.

In Kotlin you'd write: `const val MAX_M_KIB = 1_048_576` at the top level, and for the
associated one `companion object { val FLOOR = KdfParams(65_536, 3, 1) }`. Kotlin's
`const val` only allows primitives and strings, so `FLOOR` would be an ordinary `val` created
at run time. Rust's `const` can hold a whole struct.

([Constants](https://doc.rust-lang.org/book/ch03-01-variables-and-mutability.html#constants),
[associated constants in the Reference](https://doc.rust-lang.org/reference/items/associated-items.html#associated-constants))

### Struct update syntax: `..KdfParams::DEFAULT`

From the test `parallelism_must_be_one`:

```rust
KdfParams {
    parallelism: 2,
    ..KdfParams::DEFAULT
}
.validate()
```

Line by line:

- `KdfParams { parallelism: 2, ... }` builds a new value and sets `parallelism` by hand.
- `..KdfParams::DEFAULT` says "take every field I did not name from `DEFAULT`". So this is the
  default costs with only the lane count changed, which isolates the rule being tested.
- `.validate()` is then called on that new value.

Each use of a `const` makes a fresh value, so `..KdfParams::DEFAULT` never moves anything out
of `DEFAULT`; it would compile even without `Copy`. `Copy` matters when you write
`..some_variable`: the fields you did not name are moved out of that variable, unless they are
`Copy`. Ours are all `u32`, and `KdfParams` derives `Copy` (it holds three numbers and no
secret). Secret types never derive `Copy`, as lesson 02 explained.

In Kotlin you'd write: `KdfParams.DEFAULT.copy(parallelism = 2)`, using the `copy` method that
every `data class` gets.

([Creating Instances with Struct Update Syntax](https://doc.rust-lang.org/book/ch05-01-defining-structs.html#creating-instances-from-other-instances-with-struct-update-syntax))

### Integer overflow, and why we widen to `u64`

From `validate`:

```rust
match u64::from(self.memory_kib).checked_mul(u64::from(self.iterations)) {
    Some(work) if work <= MAX_WORK => Ok(()),
    _ => Err(KdfParamsError::TooMuchWork),
}
```

Line by line:

- `self.memory_kib` and `self.iterations` are `u32`: unsigned, at most 4,294,967,295.
- `u64::from(...)` widens each to 64 bits. `From` exists only for conversions that cannot lose
  data, so this can never truncate. (`as` would also compile, but `as` silently truncates when
  narrowing, so we avoid it.)
- `.checked_mul(...)` returns `Option<u64>`: `Some(product)`, or `None` if the product did not fit.
- `Some(work) if work <= MAX_WORK` is a pattern with a *guard*: it matches only when the
  multiplication fit and the result is within the cap.
- `_` matches everything else: too much work, or an overflow. Both are refused.

What happens on overflow depends on the build. With plain `*`, a debug build (`cargo test`,
`cargo build`) panics with "attempt to multiply with overflow". A release build does not check
by default and wraps around: in `u32`, 65536 × 65536 is exactly 2^32, which wraps to 0. If the
work check were the only check, a header asking for an absurd cost would compute a "work" of 0
and pass. In this file the earlier per-field caps already keep the product small, so `u32`
would not overflow today. Widening plus `checked_mul` keeps the check correct even if someone
later reorders or removes those caps.

In Kotlin you'd write: `val work = memoryKib.toLong() * iterations.toLong()`. Kotlin `Int`
overflow wraps silently in every build, so widening to `Long` is the usual fix. The checked
version is `Math.multiplyExact(a, b)`, which throws `ArithmeticException` instead of returning
an `Option`.

([Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow),
[`u64::checked_mul`](https://doc.rust-lang.org/std/primitive.u64.html#method.checked_mul))

### `#[cfg(test)]` and a Cargo feature

From `kdf.rs` and `crates/holm-crypto/Cargo.toml`:

```rust
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
pub fn argon2id_raw(
```

```toml
[features]
test-vectors = []
```

Line by line:

(The `#[expect(clippy::too_many_arguments, ...)]` attribute between `doc(hidden)` and the
function is left out here for space.)

- `#[cfg(...)]` is conditional compilation. When the condition is false, the function is not
  compiled at all, as if it were never written.
- `test` is true only while compiling this crate's own unit tests (`cargo test`).
- `feature = "test-vectors"` is true only when someone turns that feature on.
- `any(a, b)` means either one. So `argon2id_raw`, which skips the cost policy, is absent from
  a normal build of the library, and so absent from the shipped app.
- `#[doc(hidden)]` keeps it out of the generated documentation as well.
- In `Cargo.toml`, `test-vectors = []` declares the feature. The empty list means turning it on
  pulls in no extra dependencies. It is off by default. Only `oracle/Cargo.toml` asks for it
  (`features = ["test-vectors"]`), apart from commands run with `--all-features`.

In Kotlin you'd write: there is no direct match. The nearest is an `internal fun`: other
modules cannot call it, but it is still compiled into the app. A Rust `cfg` removes the code
from the build entirely.

([Features in the Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html),
[Conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html))

### Unit tests, integration tests and a separate workspace

The RFC check is a *unit test*, a module inside `kdf.rs`:

```rust
#[cfg(test)]
mod rfc9106_kat {
    use super::*;
```

The libsodium check is an *integration test*, in `oracle/tests/argon2.rs`:

```rust
use holm_crypto::kdf::{KdfParams, argon2id_raw};
use holm_oracle::{argon2id13, sodium_init};
```

Line by line:

- `#[cfg(test)] mod rfc9106_kat` compiles the module only under `cargo test`. It sits inside
  the crate, so `use super::*;` brings in everything from `kdf.rs`, private items included.
- A file in a `tests/` folder is compiled as a separate crate that uses the library like any
  outside user. It sees only `pub` items, and the library is built *without* `cfg(test)`.
- That is why `argon2id_raw` needs the feature as well as `test`: from an integration test,
  `test` is false inside `holm-crypto`, so only `test-vectors` makes the function exist.
- `use holm_oracle::{...}` imports the oracle's safe wrappers around libsodium.

Why is `oracle/` a separate workspace, with its own `Cargo.toml` and `Cargo.lock`?
`libsodium-sys-stable` has `ureq`, an HTTP client, as a build dependency, and Holm's
`cargo deny` policy bans network crates such as `ureq`. Cargo has no "optional dev-dependency", so a dev-dependency of `holm-crypto` would join
the main dependency graph and fail `cargo deny`. As its own workspace, the oracle keeps that
crate out of the product's graph. `scripts/ci-local.sh` runs its gates separately.

In Kotlin you'd write: unit tests in `src/test/kotlin` with `internal` access, and a separate
Gradle module (say `:oracle`, with a `testImplementation` dependency on libsodium bindings)
that the app module never depends on.

([Test Organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html),
[Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html))

## Why this matters for security

A vault file can come from anywhere, so its costs are attacker input: we refuse a cheap
setting that would make password guessing fast and an expensive one that would hang or crash
the machine, and we decide before allocating anything. Overflow checks matter because a
wrapped number can turn "too big" into "tiny" and get past a limit. We wipe Argon2's work
memory (64 MiB to 1 GiB of password-derived data) before freeing it, but we do not lock it in
RAM, so the operating system can still write it to swap while the derivation runs. Since
lesson 09 the BLAKE2b hash state inside argon2 wipes too, but argon2's and BLAKE2b's stack
temporaries (1 KiB blocks and short hash outputs) are not wiped; `docs/CRYPTO.md` lists them.

## Try it

1. Read the tests in `kdf.rs`. Which one proves that the largest possible `u32` values are
   refused without a panic? Check: `cargo test -p holm-crypto max_u32_does_not_overflow`
   prints `test kdf::tests::max_u32_does_not_overflow ... ok`.
2. Add this test inside `mod tests` in `kdf.rs`:

   ```rust
   #[test]
   #[should_panic(expected = "attempt to multiply with overflow")]
   fn u32_overflow_panics_in_debug() {
       let m: u32 = std::hint::black_box(65536);
       let _work = m * 65536;
   }
   ```

   `black_box` hides the value from the compiler, so it cannot spot the overflow while
   compiling. Check: `cargo test -p holm-crypto u32_overflow` prints
   `test kdf::tests::u32_overflow_panics_in_debug - should panic ... ok`.
   Then run `cargo test -p holm-crypto --release u32_overflow`. Check: it fails with
   `test did not panic as expected`, because release builds wrap instead of panicking. Undo
   with `git checkout crates/holm-crypto/src/kdf.rs`.
3. In `oracle/Cargo.toml`, change the `holm-crypto` line to
   `holm-crypto = { path = "../crates/holm-crypto" }` (no feature). Check:
   `cargo test --manifest-path oracle/Cargo.toml --locked` fails with
   ``unresolved import `holm_crypto::kdf::argon2id_raw` ``, plus a note
   `found an item that was configured out` that points at the `#[cfg(...)]` line in `kdf.rs`. The first build compiles libsodium and takes a while.
   Undo with `git checkout oracle/Cargo.toml`.

## Read next

- [The Rust Programming Language, ch. 3.2: Data Types (integer overflow)](https://doc.rust-lang.org/book/ch03-02-data-types.html)
- [ch. 11.3: Test Organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
- [ch. 14.3: Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
