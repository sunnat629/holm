# Lesson 21: Fuzzing structured inputs

## Why this matters

The vault body decoder reads bytes that an attacker may have written, so it must refuse anything hostile without panicking and without allocating what a length field claims. Unit tests check the cases we thought of; a fuzzer runs millions of cases nobody thought of. And a set of unit tests that each pass can still miss a bug that only shows when create, save, lock, unlock and back up run one after another on a real disk.

## What we built

Two new fuzz targets: `decode_body` throws raw bytes at `VaultData::decode`, and `open_fixed_key` runs the whole open (envelope, padding, body decode) on raw or damaged files. A test-only Cargo feature, `fuzzing`, lets the second target skip Argon2 by handing in the key directly. A property test, `body_roundtrip_any`, generates valid vault bodies of every item type and checks `decode(encode())` gives the same data back. Finally `tests/round_trip.rs` in `holm-platform` drives a whole session (create, add, lock, unlock, edit, change password, back up) on `FsStore` in a temp directory and on an in-memory store. The fuzz workspace has since grown more targets (`parse_header_structured`, `unpad`, `decode_body_v1`, `import_csv`, `import_json`), and `scripts/ci-local.sh` runs every one of them.

## Rust ideas in this task

### `arbitrary`: let the fuzzer build a value, not bytes

```rust
#[derive(Arbitrary, Debug)]
enum Input {
    RawFile(Vec<u8>),
    Sealed { body: Vec<u8>, edits: Vec<(u32, u8)> },
}

fuzz_target!(|input: Input| { /* ... */ });
```

libFuzzer only knows byte strings. `#[derive(Arbitrary)]` writes a function that reads a value out of those bytes, so the fuzzer can mutate bytes while our code sees a typed `Input`. For an enum it reads a `u32` and maps it onto the variants; for a `Vec` it reads a "one more?" byte before each element. That is why the seed writer in `body.rs` starts a `Sealed` seed with `u32::MAX` and puts a `1` before every body byte.

Why bother? Raw bytes would almost never form a file that passes the AEAD check, so the fuzzer would never get past "wrong key". With `Sealed`, the target seals the fuzzer's body itself, so every run reaches the body decoder, and the `edits` then damage it to test that a changed file never opens.

In Kotlin you'd write a Jazzer test with `FuzzedDataProvider` and call `data.consumeInt()` and `data.consumeBytes(n)` by hand. `arbitrary` derives that code from the type.

### A Cargo feature that exposes test-only API

```toml
[features]
# Only the test-only `fuzz/` workspace turns this on.
# Never enable it in a shipping build.
fuzzing = []
```

```rust
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
```

`holm_core::fuzzing::open_with_kek` opens a vault with a raw key and no Argon2. That makes one open take microseconds instead of a second, which a fuzzer needs. It is also exactly the shortcut an attacker would want inside a real build, because it skips the password policy and the cost. So the module only exists when `cfg(test)` is on (our own unit tests) or when someone asks for the feature. Only `fuzz/Cargo.toml` does: `holm-core = { path = "...", features = ["fuzzing"] }`.

Features are additive and unify across a build: if any crate in one build turns `fuzzing` on, everyone in that build gets it. That is why `fuzz/` is its own workspace. It is also why the feature cannot build on its own: cargo-fuzz passes `--cfg fuzzing` to rustc, and holm-core refuses the feature without it:

```rust
#[cfg(all(feature = "fuzzing", not(fuzzing)))]
compile_error!("the fuzzing feature is only for cargo-fuzz builds (needs --cfg fuzzing)");
```

A feature is something any crate in the graph can ask for, but a `--cfg` comes only from whoever runs the build. So a stray `features = ["fuzzing"]` or `--all-features` stops the build instead of shipping the shortcut. The workspace declares `cfg(fuzzing)` under `unexpected_cfgs` so rustc does not warn about an unknown name. `scripts/ci-local.sh` proves the guard with its `fuzzing-guard` gate (a plain `cargo check --features fuzzing` must fail on that message) and lints the module in `clippy-fuzzing` with `RUSTFLAGS="--cfg fuzzing"`.

In Kotlin you'd put the helper in a `testFixtures` source set. A Cargo feature is closer to a build flag that changes the library itself, which is why it needs the warning comment.

### Bounding allocation, and proving it

```rust
let hint = seq.size_hint().unwrap_or(0);
if hint > MAX {
    return Err(de::Error::invalid_length(hint, &self));
}
let mut v = Vec::with_capacity(hint.min(PREALLOC_CAP));
```

A postcard length is a varint with 7 bits per byte, so 6 bytes can claim over four trillion items. `BoundedVec<T, MAX>` in `crates/holm-core/src/wire.rs` guards against that twice:

- A declared length above the list's own cap (`MAX_ITEMS`, `MAX_URLS` and so on) is refused before any element is read.
- An allowed length still reserves at most `PREALLOC_CAP` (1024) slots up front. The list grows only as real elements arrive.

Strings get a cap too: `WireStr` refuses any string longer than `MAX_WIRE_STR_BYTES`. The fuzz gate proves the bounds hold. Every run passes `-malloc_limit_mb=64`, so one allocation over 64 MiB counts as a crash. The `huge_count` seed starts the fuzzer right at that case.

In Kotlin you'd write `ArrayList(min(count, 1024))`. Same fix; the difference is that a Rust fuzzer can enforce it.

### Properties over examples

```rust
proptest! {
    #[test]
    fn body_roundtrip_any(data in vault()) {
        let encoded = data.encode().expect("generated data is valid");
        let back = VaultData::decode(encoded.expose()).expect("decodes");
        // ... every field equal, and re-encoding gives the same bytes
    }
}
```

The strategy `vault()` builds only valid data: titles that are not blank, URLs with no outer spaces, categories that exist, unique ids. Generating only valid inputs is the hard part of a property test. If the strategy is too loose, `encode` refuses and the test proves nothing; too tight, and it misses cases. We checked it bites by flipping one field in the decoder: the test failed at once.

In Kotlin you'd write a Kotest `checkAll(Arb.bind(...))`. proptest also shrinks a failure to the smallest input that still fails.

### What an end-to-end test proves

Each unit test checks one piece, with fakes around it. `full_round_trip_on_disk` uses no fakes: real files, the system clock, real Argon2 at two costs. It checks things no unit test can see, such as that a password change still opens after a lock, that a backup written by one session opens in a new one, and that no temp file is left in the folder afterwards. Running the same scenario on an in-memory store too tells you, when it fails, whether to look at the core or at the file code.

## Try it

1. In `BoundedVec`'s visitor in `crates/holm-core/src/wire.rs`, delete the `if hint > MAX { ... }` check and change `hint.min(PREALLOC_CAP)` to `hint`. Run the `huge_count` seed and read the crash report. Then undo both changes. (With only one of the two changes, the other guard still stops the huge length.)
   Check: `cargo +nightly-2026-10-12 fuzz run decode_body fuzz/seeds/decode_body/huge_count -- -malloc_limit_mb=64`
2. Show that the `fuzzing` feature is off in the product workspace and on in `fuzz/`.
   Check: `cargo tree -p holm-core -e features --locked | grep -c fuzzing; cargo tree --manifest-path fuzz/Cargo.toml -e features -i holm-core | grep fuzzing`
3. Print what the fuzzer sees in a `Sealed` seed. How many edits does it hold, and why?
   Check: `cargo +nightly-2026-10-12 fuzz fmt open_fixed_key fuzz/seeds/open_fixed_key/sealed_default`

## Read next

- Previous: [Lesson 18](18-files-fsync-and-processes.md)
- Next: [Lesson 22](22-a-gui-crate-and-its-supply-chain.md)
- [The index](README.md)
- [Rust Fuzz Book: structure-aware fuzzing](https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html)
- [The `arbitrary` crate](https://docs.rs/arbitrary/latest/arbitrary/)
- [The Cargo Book: features](https://doc.rust-lang.org/cargo/reference/features.html)
