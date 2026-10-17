# Phase 0–1: Foundation, Crypto and File Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust workspace with supply-chain gates (run locally by `scripts/ci-local.sh`; GitHub Actions is manual-only until the repo is public), a `holm-crypto` crate (secret types, randomness, Argon2id, XChaCha20-Poly1305) proven by known-answer tests, and the v1 vault file format with sealed open/save/re-key in `holm-core`, plus one Rust lesson per task for an owner who is new to Rust.

**Architecture:** Cargo workspace. `holm-crypto` wraps RustCrypto primitives behind a tiny API with wipe-on-drop secret types and forbids `unsafe`. `holm-core::format` parses and encodes the fixed 164-byte header; `holm-core::envelope` does the key hierarchy (password → Argon2id KEK → wraps random DEK → DEK seals padded body). No disk I/O yet: everything works on byte slices.

**Tech Stack:** Rust 1.99.1, edition 2024; `argon2` 0.6, `chacha20poly1305` 0.11, `zeroize` 1.9, `getrandom` 0.4, `unicode-normalization` 0.1, `thiserror` 2, `subtle` 2.6; dev: `proptest` 1.12, `hex` 0.4, `serde_json`, `static_assertions`; `libsodium-sys-stable` 1.24 (test-only oracle, only in the separate `oracle/` workspace, never in the main graph); fuzz only: `libfuzzer-sys`, `arbitrary`; `cargo-deny`, `cargo-audit`, `cargo-vet`, `cargo-fuzz`. Feature flags: `argon2` and `chacha20poly1305` with `default-features = false, features = ["alloc", "zeroize"]`; `zeroize` with `features = ["derive"]`.

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md`

## Global Constraints

- Licence: MIT OR Apache-2.0 on every crate (`license = "MIT OR Apache-2.0"`).
- `#![forbid(unsafe_code)]` at the top of `holm-crypto`, `holm-core` and `holm-cli` `lib.rs`/`main.rs`, and `unsafe_code = "forbid"` in root `[workspace.lints.rust]` with `[lints] workspace = true` in every member, so tests and build scripts are covered too.
- No networking crates anywhere in the main workspace graph; `cargo deny check` must fail if any crate on the `deny.toml` ban list appears (`reqwest`, `hyper`, `ureq`, `isahc`, `curl`, `surf`, `attohttpc`, `tokio`, `openssl`, `openssl-sys` and the wider list added in Task 2). Never weaken the ban list to make a test dependency fit.
- `libsodium-sys-stable` lives only in the separate, excluded `oracle/` workspace (Task 5), with its own lockfile and `publish = false`. It is never a dependency, dev-dependency or optional dependency of any main-workspace crate.
- Secret types: no `Clone`, no `Copy`, wipe on drop, `Debug` prints `[REDACTED]`.
- Passwords: NFC-normalise, then UTF-8. No other encoding.
- Argon2id v1.3 (0x13). DEFAULT 262144 KiB / t3 / p1. FLOOR 65536 KiB / t3 / p1. Caps (constants, not a `KdfParams` value): `MAX_M_KIB = 1_048_576`, `MAX_T = 16`, `MAX_WORK = 4_194_304` (`memory_kib × iterations`, computed in `u64`). Parallelism must equal 1. Never call `Argon2::default()` (it is 19 MiB / t2).
- XChaCha20-Poly1305: 32-byte key, 24-byte random nonce per seal, 16-byte tag.
- Header: 164 bytes, little-endian, magic `HOLMVLT\0`, version 1, flags 0, KDF id 1, reserved zero. Wrap AAD = bytes 0..60, body AAD = bytes 0..164. No CRC. Trailing bytes rejected. Max file 64 MiB (67108864 bytes), enforced on read **and** on write (Holm never writes a file it would refuse to open).
- Body padding: u32 LE length prefix + plaintext, rounded up (ceil) to a multiple of 16384 bytes.
- No optional key file in v1 (deferred to v2; a v2 file would bump the format version). Do not add a key-file input, flag bit or header field.
- A KDF-cost rejection is never reported as a wrong password.
- `clippy -D warnings` and `rustfmt --check` clean.
- Verification before every push: commit first (the script needs a clean tree), then run `scripts/ci-local.sh` (must pass) before push. GitHub Actions is manual-only (owner ruling) and is never the gate.
- Every task writes one lesson in `docs/learn/` (format in "Lesson format" below). The owner has never written Rust; lessons assume zero Rust and compare to Kotlin.

## Lesson format

Every `docs/learn/NN-topic.md` has exactly these sections:
1. **What we built** (3–5 sentences, plain English).
2. **Rust ideas in this task**: each idea shown with a real snippet from this task's code, explained line by line, with "In Kotlin you'd write…" next to it.
3. **Why this matters for security** (2–4 sentences).
4. **Try it**: 3 small exercises the owner can do in the repo, each with the command to check the answer.
5. **Read next**: 1–3 chapters of *The Rust Programming Language* (doc.rust-lang.org/book) with links.

Keep each lesson under 250 lines. Never paste secrets or real passwords in examples.

## Review Focus

- Composed vs decomposed Unicode passwords (`"é"` vs `"e\u{301}"`) must open the same vault → KEK-level test in Task 5, whole-vault test in Task 8.
- A vault with zero items (empty body plaintext) must seal and open → test in Task 8.
- A file exactly 67108864 bytes long parses its header checks; 67108865 bytes is rejected as too large → test in Task 7.
- A truncated file (download cut short) whose `body_len` is bigger than the bytes present is rejected as a format error, not a panic → test in Task 7.
- Creating two vaults with the same password produces different salts, DEKs and files → test in Task 8 (DEKs compared through a `#[cfg(test)]` accessor, not via the wrapped DEK).

---

### Task 1: Workspace, open-source files, lesson 00

**Files:**
- Create: `Cargo.toml` (workspace), `rust-toolchain.toml`, `.gitignore`, `rustfmt.toml`
- Create: `crates/holm-crypto/{Cargo.toml,src/lib.rs}`, `crates/holm-core/{Cargo.toml,src/lib.rs}`, `crates/holm-cli/{Cargo.toml,src/main.rs}`
- Create: `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CHANGELOG.md`
- Create: `docs/THREAT-MODEL.md` (from spec section 3, expanded with the "never claim" list)
- Create: `docs/learn/README.md` (course index), `docs/learn/00-setup-and-cargo.md`

**Interfaces:**
- Produces: workspace members `crates/holm-crypto`, `crates/holm-core`, `crates/holm-cli`; `holm-core` depends on `holm-crypto` by path.

- [ ] **Step 1:** Workspace `Cargo.toml` with `resolver = "3"`, `[workspace.package]` (edition 2024, licence, `rust-version = "1.99.1"`, repository `https://github.com/sunnat629/holm`), `[workspace.dependencies]` for every crate in Tech Stack, and `[profile.dev.package."*"] opt-level = 3` so Argon2 tests are not painfully slow in debug builds. `rust-toolchain.toml`: channel `1.99.1`, components `rustfmt`, `clippy`.
- [ ] **Step 2:** Each crate's `lib.rs`/`main.rs` starts with `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` (libraries only). `holm-cli` main prints `holm 0.0.0`.
- [ ] **Step 3:** Add a smoke test in `crates/holm-cli/tests/version.rs` that runs the binary (`env!("CARGO_BIN_EXE_holm")`) and asserts stdout starts with `holm `.
- [ ] **Step 4:** Run `cargo test --workspace`. Expected: 1 passed.
- [ ] **Step 5:** `SECURITY.md`: report privately via GitHub private vulnerability reporting; acknowledge within 7 days; no bounty yet; scope = this repo. `README.md`: one-paragraph intent, "pre-alpha, do not trust with real secrets yet", build command, link to threat model and course.
- [ ] **Step 6:** Write `docs/learn/00-setup-and-cargo.md` for someone who has never written Rust: installing rustup, `cargo build/run/test`, what a workspace and crate are, reading `Cargo.toml`, `fn main`, `println!`, `let` vs `let mut`, and what `#![forbid(unsafe_code)]` means. `docs/learn/README.md` lists lessons 00–08 with one line each.
- [ ] **Step 7:** Commit: `chore: workspace skeleton, open-source files, lesson 00`.

### Task 2: CI and supply-chain gates, lesson 01

**Files:**
- Create: `.github/workflows/ci.yml`, `deny.toml`, `docs/learn/01-dependencies-and-supply-chain.md`

**Interfaces:**
- Consumes: Task 1 workspace.

- [ ] **Step 1:** `deny.toml`: `[bans] deny` = the ten crates in Global Constraints; `[licenses] allow` = MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0; `[sources] unknown-registry = "deny"`, `unknown-git = "deny"`; `[advisories]` default (deny vulnerabilities and unmaintained).
- [ ] **Step 2:** Prove the ban works: temporarily `cargo add ureq -p holm-cli`, run `cargo deny check bans`. Expected: FAIL naming `ureq`. Then `cargo remove ureq -p holm-cli` and re-run. Expected: PASS.
- [ ] **Step 3:** `ci.yml` on push and PR: matrix `ubuntu-latest`, `macos-latest`, `windows-latest`; steps `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Separate Linux job: `cargo deny check` and `cargo audit` (via `EmbarkStudios/cargo-deny-action` and `rustsec/audit-check`). Pin every action by full commit SHA with the tag in a comment. `permissions: contents: read`.
- [ ] **Step 4:** `cargo vet init`, then `cargo vet import` the published audit sets from Mozilla, Google and the Bytecode Alliance. Add a CI step `cargo vet --locked`. Unaudited crates go into `supply-chain/config.toml` exemptions, each with a one-line reason; the list is reviewed again in Phase 6.
- [ ] **Step 5:** Push to a branch, open a PR, confirm all jobs green: `gh pr checks --watch`.
- [ ] **Step 6:** Write lesson 01: `Cargo.toml` dependency syntax, semver, `Cargo.lock` and why we commit it, features, crates.io trust, what `cargo deny`, `cargo audit` and `cargo vet` check, why actions are pinned by SHA.
- [ ] **Step 7:** Commit: `ci: three-OS CI, cargo-deny network ban, cargo-audit, cargo-vet`.

### Task 3: Secret types, lesson 02

**Files:**
- Create: `crates/holm-crypto/src/secret.rs`, `docs/learn/02-ownership-and-drop.md`
- Modify: `crates/holm-crypto/src/lib.rs` (add `pub mod secret;` and re-exports)
- Modify: root `Cargo.toml` (`[workspace.dependencies]`: `zeroize = { version = "1.9", features = ["derive"] }`), `crates/holm-crypto/Cargo.toml` (`zeroize`, `unicode-normalization` with `.workspace = true`; dev-dep `static_assertions`). Keep `[lints] workspace = true`.

**Interfaces:**
- Produces:
  - `pub struct SecretKey` (32 bytes, **heap-backed**: private field `Box<[u8; 32]>`, zeroed at construction, so the key never moves around on the stack and Phase 4 can swap in a locked allocation):
    - `SecretKey::from_bytes(bytes: &mut [u8; 32]) -> SecretKey`: copies into the box, then wipes the caller's array with `zeroize`. It takes `&mut`, not the array by value, because a by-value array leaves an unwiped copy in the argument slot.
    - `pub(crate) fn zeroed() -> SecretKey` and `pub(crate) fn expose_mut(&mut self) -> &mut [u8; 32]`: crate-private, so `generate` (Task 4) and `derive_kek` (Task 5) write key bytes straight into the box.
    - `fn expose(&self) -> &[u8; 32]`. `ZeroizeOnDrop`, no `Clone`/`Copy`, `Debug` → `SecretKey([REDACTED])`.
    - `SecretKey::from_slice` is added in Task 4 (it needs `CryptoError`).
  - `pub struct SecretBuf` (variable length, wraps `zeroize::Zeroizing<Vec<u8>>`): `SecretBuf::from_vec(v: Vec<u8>) -> SecretBuf`, `fn expose(&self) -> &[u8]`, `fn len(&self) -> usize`, `fn is_empty(&self) -> bool`. `Debug` → `SecretBuf([REDACTED], len = N)`.
  - `pub struct MasterPassword` (wraps `zeroize::Zeroizing<String>`): `MasterPassword::new(s: String) -> MasterPassword`, `fn to_kdf_bytes(&self) -> SecretBuf` (NFC, then UTF-8). `Debug` → `MasterPassword([REDACTED])`.

- [ ] **Step 1: Write failing tests** in `secret.rs` `#[cfg(test)] mod tests`:

```rust
#[test] fn debug_never_shows_key_bytes() {
    let k = SecretKey::from_bytes(&mut [0xAB; 32]);
    let s = format!("{k:?}");
    assert_eq!(s, "SecretKey([REDACTED])");
}
#[test] fn from_bytes_wipes_source() {
    let mut src = [0xAB; 32];
    let k = SecretKey::from_bytes(&mut src);
    assert_eq!(src, [0u8; 32]);
    assert_eq!(k.expose(), &[0xAB; 32]);
}
#[test] fn zeroed_then_filled_in_place() {
    let mut k = SecretKey::zeroed();
    assert_eq!(k.expose(), &[0u8; 32]);
    k.expose_mut()[0] = 7;
    assert_eq!(k.expose()[0], 7);
}
#[test] fn secretbuf_debug_shows_len_only() {
    assert_eq!(format!("{:?}", SecretBuf::from_vec(vec![7; 5])), "SecretBuf([REDACTED], len = 5)");
}
#[test] fn nfc_composed_and_decomposed_match() {
    let a = MasterPassword::new("caf\u{e9}".into()).to_kdf_bytes();
    let b = MasterPassword::new("cafe\u{301}".into()).to_kdf_bytes();
    assert_eq!(a.expose(), b.expose());
    assert_eq!(a.expose(), "caf\u{e9}".as_bytes());
}
static_assertions::assert_not_impl_any!(SecretKey: Clone, Copy);
static_assertions::assert_not_impl_any!(SecretBuf: Clone, Copy);
static_assertions::assert_not_impl_any!(MasterPassword: Clone, Copy);
```

- [ ] **Step 2:** `cargo test -p holm-crypto secret`. Expected: FAIL (types not defined).
- [ ] **Step 3:** Implement the three types in `secret.rs`.
  - `SecretKey(Box<[u8; 32]>)`: build with `Box::new([0u8; 32])` (zeros on the stack are harmless), then fill in place. Wipe on drop with `#[derive(Zeroize, ZeroizeOnDrop)]` (needs the `derive` feature from the Files list) or a hand-written `Drop` that calls `zeroize`. Hand-write `Debug`.
  - `to_kdf_bytes` must not reallocate while password bytes are in the buffer (each reallocation frees an unwiped copy): create `Zeroizing::new(String::with_capacity(3 * len))` (NFC grows UTF-8 by at most 3×), `extend` it from `.nfc()`, then copy its bytes into a `SecretBuf` built from `Vec::with_capacity(exact_len)`. The `Zeroizing<String>` wipes itself on drop.
- [ ] **Step 4:** `cargo test -p holm-crypto secret`. Expected: PASS.
- [ ] **Step 5:** Write lesson 02: ownership and moves, `Drop`, derive macros, traits (`Debug`), why "no `Clone`" stops accidental copies, why the key lives in a `Box` and `from_bytes` takes `&mut` (moving an array copies it; moving a `Box` copies only a pointer), how this fixes the JVM problem (immutable `String`s you can't wipe). Include the honest limits: wiping helps, but the OS and allocator can still hold copies; the caller's original `String` passed to `MasterPassword::new` may have been copied before it reached us; memory is wiped, not locked (locking comes in Phase 4).
- [ ] **Step 6:** Commit: `feat(crypto): wipe-on-drop secret types with redacted Debug`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 4: Errors and randomness, lesson 03

**Files:**
- Create: `crates/holm-crypto/src/error.rs`, `crates/holm-crypto/src/random.rs`, `docs/learn/03-errors-and-results.md`
- Modify: `crates/holm-crypto/src/lib.rs` (`pub mod error; pub mod random;` and re-exports), `crates/holm-crypto/src/secret.rs` (`generate`, `from_slice`), `crates/holm-crypto/Cargo.toml` (`getrandom`, `thiserror` with `.workspace = true`)

**Interfaces:**
- Produces:
  - `#[derive(Debug, PartialEq, Eq, thiserror::Error)] pub enum CryptoError { Rng, KdfParams(KdfParamsError), Kdf, Aead, InvalidKeyLength }`. `Aead` message is exactly `"decryption failed"`, never more detail. No message contains key, password or plaintext bytes.
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum KdfParamsError { BelowFloor, AboveCeiling, TooMuchWork, UnsupportedParallelism }`.
  - `pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError>` (getrandom; maps failure to `Rng`).
  - `pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError>` (for salts and nonces only, which are not secret; never for keys).
  - `impl SecretKey { pub fn generate() -> Result<SecretKey, CryptoError>; pub fn from_slice(bytes: &[u8]) -> Result<SecretKey, CryptoError> }`. `from_slice` returns `InvalidKeyLength` unless `bytes.len() == 32`, and copies straight into the box (used in Task 8 to turn the unwrapped DEK `SecretBuf` into a `SecretKey` without a stack copy).

- [ ] **Step 1: Failing tests:** `two_generated_keys_differ` (`assert_ne!(a.expose(), b.expose())`), `random_nonces_differ` (`random_array::<24>()` twice), `aead_error_message_is_opaque` (`assert_eq!(CryptoError::Aead.to_string(), "decryption failed")`), `from_slice_accepts_32_bytes` (round-trips the bytes), `from_slice_rejects_wrong_length` (31 and 33 bytes → `Err(CryptoError::InvalidKeyLength)`).
- [ ] **Step 2:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 3:** Implement. `generate` = `let mut k = SecretKey::zeroed(); fill_random(k.expose_mut())?; Ok(k)`, so key bytes are written straight into the heap box and no stack copy exists. Do not route keys through `random_array`.
- [ ] **Step 4:** `cargo test -p holm-crypto`. Expected: PASS.
- [ ] **Step 5:** Lesson 03: `Result<T, E>`, `?`, enums with data, `match`, `thiserror`, deriving `PartialEq` so tests can compare errors, const generics (`[u8; N]`), why errors must not leak secrets or say *which* check failed in decryption. Kotlin comparison: exceptions vs `Result`.
- [ ] **Step 6:** Commit: `feat(crypto): error types and OS randomness`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 5: Argon2id KDF with cost policy, lesson 04

**Files:**
- Create: `crates/holm-crypto/src/kdf.rs`, `docs/learn/04-constants-overflow-and-features.md`
- Create (oracle, a separate workspace excluded from the root, like `fuzz/`): `oracle/Cargo.toml`, `oracle/Cargo.lock` (committed), `oracle/src/lib.rs`, `oracle/tests/argon2.rs`
- Modify: root `Cargo.toml` (`[workspace.dependencies]`: `argon2 = { version = "0.6", default-features = false, features = ["alloc", "zeroize"] }`; `exclude` already lists `oracle`), `crates/holm-crypto/Cargo.toml` (`argon2.workspace = true`; `[features] test-vectors = []`), `crates/holm-crypto/src/lib.rs` (`pub mod kdf;`), `scripts/ci-local.sh` (oracle gate)
- Do **not** add `libsodium-sys-stable` to any main-workspace `Cargo.toml`, and do not add an `oracle` feature to `holm-crypto`. Cargo forbids optional dev-dependencies, and libsodium-sys-stable build-depends on `ureq`, which the network ban rejects.

**Interfaces:**
- Consumes: `MasterPassword::to_kdf_bytes`, `SecretKey::zeroed`/`expose_mut`, `CryptoError`, `KdfParamsError`.
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct KdfParams { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 }`
  - `impl KdfParams { pub const DEFAULT: Self /* 262144, 3, 1 */; pub const FLOOR: Self /* 65536, 3, 1 */; pub fn validate(&self) -> Result<(), KdfParamsError> }`. There is **no** `CEILING` value: 1048576 × 16 exceeds the work cap, so it would not pass `validate`.
  - `pub const MAX_M_KIB: u32 = 1_048_576; pub const MAX_T: u32 = 16; pub const MAX_WORK: u64 = 4_194_304;` (work = `memory_kib × iterations` in `u64`).
  - `pub fn derive_kek(password: &MasterPassword, salt: &[u8; 32], params: &KdfParams) -> Result<SecretKey, CryptoError>`: calls `validate` first and returns `CryptoError::KdfParams(_)` without allocating Argon2 memory.
  - `argon2id_raw(password: &[u8], salt: &[u8], secret: &[u8], ad: &[u8], m_kib: u32, t: u32, p: u32, out: &mut [u8]) -> Result<(), CryptoError>`: no policy checks. Declared `#[cfg(any(test, feature = "test-vectors"))] #[doc(hidden)] pub fn` with a doc comment saying it bypasses the cost policy: it is compiled only for holm-crypto's own unit tests or with the non-default `test-vectors` feature, so the shipping library never contains it. Only the `oracle/` workspace enables `test-vectors`.

- [ ] **Step 1: Failing policy tests** in `kdf.rs`:

```rust
#[test] fn default_and_floor_are_valid() { assert!(KdfParams::DEFAULT.validate().is_ok()); assert!(KdfParams::FLOOR.validate().is_ok()); }
#[test] fn default_and_floor_exact_values() {
    assert_eq!(KdfParams::DEFAULT, KdfParams { memory_kib: 262144, iterations: 3, parallelism: 1 });
    assert_eq!(KdfParams::FLOOR, KdfParams { memory_kib: 65536, iterations: 3, parallelism: 1 });
}
#[test] fn below_floor_rejected() { assert_eq!(KdfParams { memory_kib: 65535, iterations: 3, parallelism: 1 }.validate(), Err(KdfParamsError::BelowFloor)); }
#[test] fn too_few_iterations_rejected() { assert_eq!(KdfParams { memory_kib: 65536, iterations: 2, parallelism: 1 }.validate(), Err(KdfParamsError::BelowFloor)); }
#[test] fn above_memory_cap_rejected() { assert_eq!(KdfParams { memory_kib: MAX_M_KIB + 1, iterations: 3, parallelism: 1 }.validate(), Err(KdfParamsError::AboveCeiling)); }
#[test] fn above_iteration_cap_rejected() { assert_eq!(KdfParams { memory_kib: 65536, iterations: MAX_T + 1, parallelism: 1 }.validate(), Err(KdfParamsError::AboveCeiling)); }
#[test] fn combined_work_rejected() { assert_eq!(KdfParams { memory_kib: 1048576, iterations: 5, parallelism: 1 }.validate(), Err(KdfParamsError::TooMuchWork)); }
#[test] fn work_cap_edges_accepted() {
    assert!(KdfParams { memory_kib: 1048576, iterations: 4, parallelism: 1 }.validate().is_ok());
    assert!(KdfParams { memory_kib: 262144, iterations: 16, parallelism: 1 }.validate().is_ok());
}
#[test] fn max_u32_does_not_overflow() { assert!(KdfParams { memory_kib: u32::MAX, iterations: u32::MAX, parallelism: 1 }.validate().is_err()); }
#[test] fn parallelism_must_be_one() { assert_eq!(KdfParams { parallelism: 2, ..KdfParams::DEFAULT }.validate(), Err(KdfParamsError::UnsupportedParallelism)); }
#[test] fn policy_error_before_any_work() {
    let bad = KdfParams { memory_kib: MAX_M_KIB + 1, iterations: 3, parallelism: 1 };
    assert_eq!(derive_kek(&MasterPassword::new("x".into()), &[0; 32], &bad).unwrap_err(), CryptoError::KdfParams(KdfParamsError::AboveCeiling));
}
#[test] fn nfc_forms_give_same_kek() {
    let salt = [9u8; 32];
    let a = derive_kek(&MasterPassword::new("caf\u{e9}".into()), &salt, &KdfParams::FLOOR).unwrap();
    let b = derive_kek(&MasterPassword::new("cafe\u{301}".into()), &salt, &KdfParams::FLOOR).unwrap();
    assert_eq!(a.expose(), b.expose());
}
#[test] fn derive_kek_uses_exact_params() {
    // derive_kek must use the params it is given, not crate defaults (Argon2::default() is 19 MiB / t2).
    let pw = MasterPassword::new("correct horse".into());
    let salt = [5u8; 32];
    let kek = derive_kek(&pw, &salt, &KdfParams::FLOOR).unwrap();
    let mut raw = [0u8; 32];
    argon2id_raw(pw.to_kdf_bytes().expose(), &salt, &[], &[], 65536, 3, 1, &mut raw).unwrap();
    assert_eq!(kek.expose(), &raw);
    let mut other = [0u8; 32];
    argon2id_raw(pw.to_kdf_bytes().expose(), &salt, &[], &[], 65536, 4, 1, &mut other).unwrap();
    assert_ne!(kek.expose(), &other);
}
```

- [ ] **Step 2: Failing KAT** as a unit test module in `kdf.rs` (`#[cfg(test)] mod rfc9106_kat`; a unit test so it can call the crate-private `argon2id_raw` and always runs in `cargo test --workspace`): `rfc9106_argon2id_vector` calls `argon2id_raw` with the RFC 9106 §5.3 Argon2id inputs (password 32×`0x01`, salt 16×`0x02`, secret 8×`0x03`, ad 12×`0x04`, m=32, t=3, p=4, 32-byte tag) and compares to the tag. **Copy the expected hex from the RFC text itself, not from memory**, and put the RFC URL in a comment.
- [ ] **Step 3:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 4:** Implement.
  - `validate` order: parallelism (`!= 1` → `UnsupportedParallelism`), then floor (`memory_kib < 65536` or `iterations < 3` → `BelowFloor`), then per-field caps (`memory_kib > MAX_M_KIB` or `iterations > MAX_T` → `AboveCeiling`), then `u64::from(memory_kib) * u64::from(iterations) > MAX_WORK` → `TooMuchWork`.
  - `derive_kek`: `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m, t, p, Some(32))?)`. Never `Argon2::default()`. Allocate the work area yourself as `Zeroizing::new(vec![argon2::Block::default(); params.block_count()])` and call `hash_password_into_with_memory(pw.expose(), salt, key.expose_mut(), &mut blocks[..])`, where `key = SecretKey::zeroed()`. The argon2 crate frees its own work area **without** wiping it, and that 64–256 MiB of password-derived memory could reach swap; the `Zeroizing` buffer wipes it. Map argon2 errors to `CryptoError::Kdf`.
  - `argon2id_raw`: `Argon2::new_with_secret` with `ParamsBuilder::data(ad)`. Gate it as described in Interfaces.
- [ ] **Step 5:** `cargo test -p holm-crypto`. Expected: PASS.
- [ ] **Step 6: libsodium oracle** in the separate `oracle/` workspace (it never ships, and its `ureq` build-dependency stays out of the main graph):
  - `oracle/Cargo.toml`: its own empty `[workspace]`, package `holm-oracle`, `publish = false`, licence `MIT OR Apache-2.0`; deps `holm-crypto = { path = "../crates/holm-crypto", features = ["test-vectors"] }` and `libsodium-sys-stable = "1.24"`. Commit `oracle/Cargo.lock`.
  - `oracle/src/lib.rs`: `#![deny(unsafe_code)]` at crate level; the FFI calls live in one `#[allow(unsafe_code)] mod ffi` with a `// SAFETY:` comment on every `unsafe` block and `#![deny(unsafe_op_in_unsafe_fn)]`. Expose safe wrappers only: `sodium_init()`, `argon2id13(pwd: &[u8], salt: &[u8; 16], opslimit: u64, memlimit_bytes: usize) -> [u8; 32]`. This is the only handwritten `unsafe` in the repo until `holm-platform`.
  - `oracle/tests/argon2.rs`: for 20 seeded pseudo-random passwords (lengths 0–64, including non-ASCII; use a small SplitMix64 in the test file, no `rand` dependency) and 16-byte salts, compare `holm_crypto::kdf::argon2id_raw` (empty secret and ad, m = 65536, t = 3, p = 1) with libsodium `crypto_pwhash` (`ALG_ARGON2ID13`, opslimit = iterations, memlimit = memory_kib × 1024). Both sides get the **NFC bytes** from `MasterPassword::to_kdf_bytes()`, or non-ASCII cases diverge. (libsodium only takes 16-byte salts; `derive_kek == argon2id_raw` for 32-byte salts is covered inside holm-crypto by `derive_kek_uses_exact_params`.)
  - `scripts/ci-local.sh`: add an `oracle` gate after `vet`: `cargo fmt --manifest-path oracle/Cargo.toml --check`, `cargo clippy --manifest-path oracle/Cargo.toml --all-targets --locked -- -D warnings`, `cargo test --manifest-path oracle/Cargo.toml --locked`, and `cargo audit --file oracle/Cargo.lock`. Skip it with a printed `SKIP oracle` on Windows shells (`uname -s` matching `MINGW*|MSYS*|CYGWIN*`), because libsodium-sys-stable downloads a prebuilt zip over HTTP there. Update the script's header comment: it runs the `ci.yml` gates plus local-only gates. The root `cargo deny` ban list does not apply to `oracle/` (separate workspace); never copy `ureq` exceptions into the root `deny.toml`.
- [ ] **Step 7:** `cargo test --manifest-path oracle/Cargo.toml --locked`. Expected: PASS.
- [ ] **Step 8:** Lesson 04: `const`, associated constants, struct update syntax (`..DEFAULT`), integer overflow in Rust (debug panics, release wraps) and why we widen to `u64`, `#[cfg(test)]` and cargo features (`test-vectors`), why the oracle is its own workspace (optional dev-deps don't exist; a test dependency must not drag a network crate into the product graph), integration tests vs unit tests. Honest limit: the Argon2 work memory is wiped after use but not locked, so it can still reach swap while the KDF runs.
- [ ] **Step 9:** Commit: `feat(crypto): Argon2id KDF with floor/ceiling policy and KATs`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 6: XChaCha20-Poly1305 AEAD, lesson 05

**Files:**
- Create: `crates/holm-crypto/src/aead.rs`, `crates/holm-crypto/tests/xchacha_kat.rs`, `crates/holm-crypto/tests/vectors/xchacha20_poly1305_test.json`, `crates/holm-crypto/tests/vectors/README.md`, `oracle/tests/xchacha.rs`, `docs/learn/05-slices-and-borrowing.md`
- Modify: root `Cargo.toml` (`[workspace.dependencies]`: `chacha20poly1305 = { version = "0.11", default-features = false, features = ["alloc", "zeroize"] }`), `crates/holm-crypto/Cargo.toml` (`chacha20poly1305.workspace = true`; dev-deps `serde_json`, `hex`), `crates/holm-crypto/src/lib.rs` (`pub mod aead;`), `oracle/src/lib.rs` (safe `xchacha_encrypt` wrapper), `oracle/Cargo.lock` if it changes

**Interfaces:**
- Consumes: `SecretKey`, `SecretBuf`, `CryptoError`.
- Produces:
  - `pub const NONCE_LEN: usize = 24; pub const TAG_LEN: usize = 16; pub const KEY_LEN: usize = 32;`
  - `pub fn seal(key: &SecretKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>` (output = ciphertext ‖ tag)
  - `pub fn open(key: &SecretKey, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<SecretBuf, CryptoError>` (any failure → `CryptoError::Aead`)

- [ ] **Step 1: Vectors.** Download Wycheproof `testvectors_v1/xchacha20_poly1305_test.json` from `github.com/C2SP/wycheproof` at a fixed commit. Record commit SHA, URL and file SHA-256 in `vectors/README.md`, plus the counts the test asserts (at preflight: `numberOfTests` = 315, of which 9 are `invalid` `InvalidNonceSize` cases with nonce lengths other than 24 bytes; re-count from the pinned file and write the real numbers).
- [ ] **Step 2: Failing tests:** in `aead.rs`: `roundtrip`, `empty_plaintext_roundtrip`, `wrong_key_fails`, `flipping_any_ciphertext_byte_fails` (loop every byte, flip = `^= 0x01`), `flipping_any_aad_byte_fails`, `wrong_nonce_fails`, `truncated_below_tag_fails`. All failures assert `Err(CryptoError::Aead)` (needs the Task 4 `PartialEq` derive). In `tests/xchacha_kat.rs`: `draft_xchacha_a3_1` (draft-irtf-cfrg-xchacha-03 Appendix A.3.1, values copied from the draft with its URL in a comment) and `wycheproof_all_cases` (parse JSON with `serde_json`; `valid` must round-trip to the given ciphertext and tag, `invalid` must fail). Cases whose nonce is not 24 bytes cannot reach `open(&[u8; 24])`: count them as **skipped** when `<[u8; 24]>::try_from(iv)` fails, assert every skipped case is `invalid`, and assert both `checked + skipped == numberOfTests` and `skipped == 9` (the exact count from `vectors/README.md`). A `valid` case that cannot be fed to the API fails the test.
- [ ] **Step 3:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 4:** Implement with `chacha20poly1305::XChaCha20Poly1305` and `Payload { msg, aad }`. Build the cipher from `key.expose()` (no extra key copy); the crate's `zeroize` feature wipes its internal key state on drop. Decrypt into a buffer that is wiped if decryption fails, and return it as a `SecretBuf`.
- [ ] **Step 5: libsodium oracle** in `oracle/tests/xchacha.rs`: `libsodium_matches_for_random_inputs` (100 seeded inputs: random key, nonce, AAD of 0–64 bytes and plaintext of 0–1024 bytes; compare `holm_crypto::aead::seal` with `crypto_aead_xchacha20poly1305_ietf_encrypt`, and check `open` recovers the plaintext). The FFI call goes in the existing `ffi` module behind a safe wrapper with a `// SAFETY:` comment.
- [ ] **Step 6:** `cargo test -p holm-crypto` and `cargo test --manifest-path oracle/Cargo.toml --locked`. Expected: PASS.
- [ ] **Step 7:** Lesson 05: slices (`&[u8]`) vs arrays (`[u8; 24]`) vs `Vec<u8>`, borrowing (`&`) vs owning, why the API takes `&SecretKey`, intro to lifetimes, why a fixed-size `&[u8; 24]` parameter turns "wrong nonce length" into a compile-time error (and why 9 Wycheproof cases are skipped), and why an AEAD fails "all or nothing" (no partial plaintext).
- [ ] **Step 8:** Commit: `feat(crypto): XChaCha20-Poly1305 seal/open with Wycheproof and draft KATs`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 7: Vault header format, lesson 06

**Files:**
- Create: `crates/holm-core/src/format.rs`, `docs/learn/06-parsing-bytes-safely.md`
- Modify: `crates/holm-core/src/lib.rs` (`pub mod format;`), `crates/holm-core/Cargo.toml` (`thiserror.workspace = true`)

**Interfaces:**
- Consumes: `KdfParams`, `KdfParamsError`, `TAG_LEN`.
- Produces:
  - `pub const MAGIC: [u8; 8] = *b"HOLMVLT\0"; pub const FORMAT_VERSION: u16 = 1; pub const KDF_ID_ARGON2ID: u8 = 1; pub const HEADER_LEN: usize = 164; pub const WRAP_AAD_LEN: usize = 60; pub const MAX_FILE_LEN: usize = 67_108_864;`
  - `#[derive(Clone, Debug, PartialEq, Eq)] pub struct Header { pub kdf: KdfParams, pub salt: [u8; 32], pub wrap_nonce: [u8; 24], pub wrapped_dek: [u8; 48], pub body_nonce: [u8; 24], pub body_len: u64 }` (no secret fields: the DEK is only present wrapped)
  - `impl Header { pub fn encode(&self) -> [u8; HEADER_LEN]; pub fn parse(file: &[u8]) -> Result<(Header, &[u8]), FormatError> }` (returns header and the body ciphertext slice)
  - `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)] pub enum FormatError { TooLarge, TooShort, BadMagic, UnsupportedVersion(u16), BadFlags, UnknownKdf(u8), ReservedNotZero, KdfPolicy(KdfParamsError), LengthMismatch, BodyTooShort }`

Layout (offset, size): magic 0/8, version 8/2, flags 10/2, kdf_id 12/1, reserved 13/3, memory_kib 16/4, iterations 20/4, parallelism 24/4, salt 28/32, wrap_nonce 60/24, wrapped_dek 84/48, body_nonce 132/24, body_len 156/8. Integers little-endian. Flags stay 0 in v1: no key-file bit (key files are deferred to v2, which would bump `FORMAT_VERSION`).

- [ ] **Step 1: Failing tests** (helper `valid_header()` uses FLOOR params and `body_len = 16`; helper `file(h, body)` concatenates):
  - `encode_then_parse_roundtrip` (header equal, returned body slice equal to the body passed in)
  - `kdf_params_round_trip_exactly` (a header with `{131072, 4, 1}` parses back to exactly those values, and bytes 16..28 are their little-endian encodings)
  - `encoded_length_is_164` and `wrap_aad_is_first_60_bytes` (fields after offset 60 do not change bytes 0..60)
  - one rejection test per `FormatError` variant, mutating exactly one byte or length (e.g. `byte[12] = 2` → `UnknownKdf(2)`, `byte[13] = 1` → `ReservedNotZero`, memory_kib 65535 → `KdfPolicy(BelowFloor)`)
  - `kdf_caps_enforced_in_parse` (memory 2097152 → `KdfPolicy(AboveCeiling)`; 1048576 × t5 → `KdfPolicy(TooMuchWork)`)
  - `trailing_byte_rejected` → `LengthMismatch`
  - `truncated_body_rejected` (`body_len = 1000`, 16 bytes present) → `LengthMismatch`
  - `body_len_u64_max_rejected_without_panic` → `LengthMismatch`
  - `file_of_exactly_max_len_passes_size_check` (vec of `MAX_FILE_LEN` bytes with a valid header and matching `body_len` → `Ok`) and `file_one_over_max_rejected` → `TooLarge`
  - `body_shorter_than_tag_rejected` (`body_len = 15`, 15 body bytes present) → `BodyTooShort`, and `body_len_15_with_16_bytes_present` → `BodyTooShort` too (the `body_len < TAG_LEN` check comes before the total-length check)
- [ ] **Step 2:** `cargo test -p holm-core format`. Expected: FAIL.
- [ ] **Step 3:** Implement. Check order: size (`TooLarge` if `file.len() > MAX_FILE_LEN`, `TooShort` if `< HEADER_LEN`), magic, version, flags, kdf id, reserved, KDF policy (`KdfParams::validate`, wrapped as `KdfPolicy`), then `body_len < TAG_LEN as u64` → `BodyTooShort`, then lengths with `usize::try_from` and `checked_add` (a failed `try_from` on 32-bit also gives `LengthMismatch`; never `as` casts, never indexing past checked bounds), and `HEADER_LEN + body_len != file.len()` → `LengthMismatch`. Read fields with `u32::from_le_bytes(bytes[a..b].try_into()?)` style.
- [ ] **Step 4:** `cargo test -p holm-core format`. Expected: PASS.
- [ ] **Step 5:** Lesson 06: byte order, `from_le_bytes`, `try_into`, why slice indexing can panic and how `get`/checked maths avoid it, why check order matters (cheap checks and the KDF cost caps run before any expensive work), `match` on enums, returning a borrowed slice from a function (first real lifetime example).
- [ ] **Step 6:** Commit: `feat(core): v1 vault header encode/parse with strict validation`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 8: Envelope: create, open, re-save, re-key, lesson 07

**Files:**
- Create: `crates/holm-core/src/envelope.rs`, `crates/holm-core/src/padding.rs`, `docs/CRYPTO.md`, `docs/learn/07-modules-and-encapsulation.md`
- Modify: `crates/holm-core/src/lib.rs` (`pub mod envelope; pub mod padding;`, so fuzz targets and property tests outside the crate can call `unpad`), `crates/holm-core/Cargo.toml` (`subtle`, `zeroize` with `.workspace = true`)

**Interfaces:**
- Consumes: Task 3–7 items.
- Produces:
  - In `padding.rs`: `pub const PAD_BLOCK: usize = 16384; pub const MAX_PADDED_LEN: usize = 67_092_480;` (the largest multiple of 16384 with `HEADER_LEN + MAX_PADDED_LEN + TAG_LEN <= MAX_FILE_LEN`, i.e. 4095 blocks; add a `const` assertion that checks this), `pub const MAX_BODY_LEN: usize = MAX_PADDED_LEN - 4;`
  - `pub fn pad(plaintext: &[u8]) -> Result<SecretBuf, VaultError>` (u32 LE length prefix, then plaintext, then zeros, rounded up (ceil) to a multiple of 16384; empty input gives 16384 bytes; 16380 bytes gives 16384; 16381 gives 32768). Returns `VaultError::TooLargeToSave` if `plaintext.len() > MAX_BODY_LEN`. Build into `Vec::with_capacity(padded_len)` and move it into the `SecretBuf` (no reallocation, no unwiped copy).
  - `pub fn unpad(padded: &[u8]) -> Result<SecretBuf, VaultError>`: `VaultError::BadPadding` if the length is 0 or not a multiple of 16384, the prefix is larger than `padded.len() - 4`, or any padding byte is non-zero.
  - `pub struct VaultKeys` (private fields: `dek: SecretKey`, `header: Header`); no `Clone`; `Debug` redacted. `#[cfg(test)] pub(crate) fn dek(&self) -> &SecretKey` accessor for tests only.
  - `pub fn create(password: &MasterPassword, params: &KdfParams, body: &[u8]) -> Result<(VaultKeys, Vec<u8>), VaultError>` (fresh salt, DEK, wrap nonce, body nonce; writes `params` into the header exactly as given)
  - `pub fn open(file: &[u8], password: &MasterPassword) -> Result<(VaultKeys, SecretBuf), VaultError>` (returns the unpadded body)
  - `pub(crate) fn open_with_kek(file: &[u8], kek: &SecretKey) -> Result<(VaultKeys, SecretBuf), VaultError>`: everything `open` does after key derivation (parse, unwrap DEK, open body, unpad). `open` = `Header::parse` (size, header and KDF checks before any Argon2 work) → `derive_kek` → `open_with_kek`. It exists so tests can flip every byte without one Argon2 run per flip.
  - `pub fn reseal(keys: &mut VaultKeys, body: &[u8]) -> Result<Vec<u8>, VaultError>` (new body nonce every call; updates `keys.header` only on success)
  - `pub fn rekey(keys: VaultKeys, new_password: &MasterPassword, params: &KdfParams, body: &[u8]) -> Result<(VaultKeys, Vec<u8>), VaultError>` (new salt **and new DEK**; consumes the old keys)
  - `pub fn verify_password(keys: &VaultKeys, password: &MasterPassword) -> Result<(), VaultError>` (re-derive KEK, unwrap DEK, compare with `subtle::ConstantTimeEq`; used later for recovery-phrase reveal)
  - `#[derive(Debug, PartialEq, Eq, thiserror::Error)] pub enum VaultError { Format(FormatError), KdfPolicy(KdfParamsError), WrongPasswordOrCorrupt, BadPadding, TooLargeToSave, Crypto }`.
    - **No `#[from]` on `VaultError`.** Write `From<FormatError>` and `From<CryptoError>` by hand: `FormatError::KdfPolicy(e)` and `CryptoError::KdfParams(e)` both map to `VaultError::KdfPolicy(e)` (a `#[from]` would produce `Format(KdfPolicy(..))` instead); every other `FormatError` maps to `Format(e)`; `CryptoError::Aead` maps to `WrongPasswordOrCorrupt`; `Rng`, `Kdf` and `InvalidKeyLength` map to `Crypto`.
    - `KdfPolicy` message: "this vault needs more resources than allowed" style; it never says "password". `WrongPasswordOrCorrupt` is the only error a wrong password or a tampered file can produce.
    - `BadPadding` is distinct from `WrongPasswordOrCorrupt`: `unpad` only runs on plaintext that already passed AEAD authentication, so it signals a malformed body written by a buggy writer, never a wrong password, and it leaks nothing to someone without the DEK.
    - `TooLargeToSave` is the write-side 64 MiB cap, distinct from the read-side `Format(TooLarge)`.
  - No key-file parameter anywhere (deferred to v2).

- [ ] **Step 1: Failing tests** (all with `KdfParams::FLOOR` unless stated; flip always means `^= 0x01`):
  - `create_then_open_returns_body`
  - `empty_body_roundtrip`
  - `nfc_forms_open_same_vault` (create with `"caf\u{e9}"`, open with `"cafe\u{301}"`)
  - `wrong_password_is_opaque` → `WrongPasswordOrCorrupt`
  - `header_stores_exact_kdf_params` (for FLOOR and for `{131072, 4, 1}`: `Header::parse(&file)` gives exactly those params and `file[16..28]` is their LE encoding) and `default_params_written_as_262144_3_1` (one `create` with `KdfParams::DEFAULT`, then check the parsed header and bytes 16..28)
  - `create_rejects_params_outside_policy` (FLOOR with `memory_kib - 1` → `KdfPolicy(BelowFloor)`; `{1048576, 5, 1}` → `KdfPolicy(TooMuchWork)`; no Argon2 run)
  - `every_header_byte_flip_fails_fast` (derive the KEK once with `derive_kek`, then flip each of bytes 0..164 in turn and call `open_with_kek`; assert `Err`, never `Ok`, never panics)
  - `every_body_byte_flip_fails` (same KEK-once approach through `open_with_kek`, every body byte including the tag)
  - `sampled_flips_fail_end_to_end` (real `open` with the KDF: all 164 header bytes, plus body bytes 0, 1, every 4096th, and the last 16 tag bytes; each → `Err`)
  - `reseal_uses_fresh_nonce` (two reseals of the same body differ in bytes 132..156 and ciphertext)
  - `same_password_two_vaults_differ` (salt, wrapped DEK, whole file **and the DEKs themselves** differ; compare DEKs through the `#[cfg(test)]` `dek()` accessor)
  - `padding_hides_small_size_differences` (1-byte and 16000-byte bodies give the same file length)
  - `rekey_old_password_fails_new_password_opens`
  - `rekey_rotates_dek` (old DEK, via the `#[cfg(test)]` `dek()` accessor, cannot `aead::open` the new file's body)
  - `kdf_above_ceiling_is_policy_error_not_wrong_password` (hand-built header with memory 2097152 → `KdfPolicy(AboveCeiling)`)
  - `verify_password_accepts_right_rejects_wrong`
  - `oversize_body_rejected_on_save` (`create`, `reseal` and `rekey` with a body of `MAX_BODY_LEN + 1` bytes → `TooLargeToSave`, before any KDF run or encryption; `reseal` leaves `keys` unchanged)
  - `max_body_saves_and_opens` (body of exactly `MAX_BODY_LEN` bytes: the file is `<= MAX_FILE_LEN` and opens)
  - `pad_boundaries` (0 → 16384, 16380 → 16384, 16381 → 32768) in `padding.rs`
  - `unpad_rejects_length_prefix_larger_than_buffer`, `unpad_rejects_non_block_length`, `unpad_rejects_nonzero_padding`, each → `BadPadding`, in `padding.rs`
- [ ] **Step 2:** `cargo test -p holm-core`. Expected: FAIL. (Use the crate-wide run, not the `envelope` filter, so the `padding.rs` tests run too.)
- [ ] **Step 3:** Implement.
  - Order in `create`/`reseal`/`rekey`: `params.validate()` (create/rekey) and `pad(body)` first, so policy and size errors happen before any Argon2 run or encryption. Then: DEK = `SecretKey::generate()`; wrap = `aead::seal(kek, wrap_nonce, &encoded[0..60], dek.expose())`; body = `aead::seal(dek, body_nonce, &encoded[0..164], padded)`. `body_len` must be set before encoding the AAD, so compute ciphertext length as `padded.len() + TAG_LEN` first.
  - Open: `Header::parse` → `derive_kek` → `open_with_kek` (unwrap DEK with `aead::open`, then `SecretKey::from_slice(unwrapped.expose())` so the DEK goes from `SecretBuf` into the heap key without a stack copy → open body → `unpad`).
  - Never write a file that `Header::parse` would reject: the `pad` cap guarantees `HEADER_LEN + padded + TAG_LEN <= MAX_FILE_LEN`.
- [ ] **Step 4:** `cargo test -p holm-core`. Expected: PASS.
- [ ] **Step 5:** Write `docs/CRYPTO.md` from spec section 5 and this task: key diagram, header table, AAD ranges, exact KDF policy (DEFAULT, FLOOR, `MAX_M_KIB`, `MAX_T`, `MAX_WORK`, p = 1), why re-key rotates the DEK, the 64 MiB cap on read and write, why `BadPadding` is post-authentication, and what is **not** claimed (memory wiped but not locked yet, including the Argon2 work area; no key file in v1, deferred to v2).
- [ ] **Step 6:** Lesson 07: modules and `pub`/private fields, why `VaultKeys` hides the DEK, `pub(crate)` and `#[cfg(test)]` helpers (`open_with_kek`, `dek()`), consuming `self` in `rekey` (the old keys can't be used afterwards, enforced by the compiler), `From` and `?` for error conversion, and why these `From` impls are hand-written instead of `#[from]`.
- [ ] **Step 7:** Commit: `feat(core): vault envelope with DEK wrap, padding, reseal and rekey`. Then run `scripts/ci-local.sh` (must pass) before push.

### Task 9: Property tests and fuzzing, lesson 08

**Files:**
- Create: `crates/holm-core/tests/format_props.rs`, `fuzz/Cargo.toml`, `fuzz/Cargo.lock` (committed), `fuzz/fuzz_targets/parse_header.rs`, `fuzz/fuzz_targets/parse_header_structured.rs`, `fuzz/fuzz_targets/unpad.rs`, `fuzz/seeds/parse_header/valid_floor` (one valid file), `fuzz/README.md` (the local fuzz commands), `.github/workflows/fuzz.yml` (manual-only), `docs/learn/08-property-tests-and-fuzzing.md`
- Modify: `crates/holm-core/Cargo.toml` (dev-dep `proptest.workspace = true`), `scripts/ci-local.sh` (fuzz gate)

**Interfaces:**
- Consumes: `Header::parse`, `Header::encode`, `pad`, `unpad`, `KdfParams`.

- [ ] **Step 1: Property tests** with `proptest`, structure-aware (purely random bytes almost never get past the 8-byte magic, so they test nothing):
  - `valid_file()` strategy: `parallelism = 1`; `iterations` in `3..=16` then `memory_kib` in `65536..=min(MAX_M_KIB, MAX_WORK / iterations)` (via `prop_flat_map`); random salt and nonces; `body_len` in `16..=64` with exactly that many random body bytes appended.
  - `encode_parse_roundtrip(valid_file)`: parse returns the same `Header` (including `body_len` and p = 1) and a body slice equal to the generated body bytes.
  - `parse_never_panics_on_mutations(valid_file, 1–4 edits)`: each edit is a random byte overwrite, a truncation or an extension. Assert no panic; if parse returns `Ok`, re-encoding the header gives back the first 164 input bytes.
  - `parse_never_panics_on_random(bytes in vec(any::<u8>(), 0..400))`: kept as a cheap extra case.
  - `pad_unpad_roundtrip(plaintext in vec(any::<u8>(), 0..40000))` and `unpad_never_panics` (mutated `pad` output plus random lengths).
  - `#[ignore] write_seed_corpus`: writes `fuzz/seeds/parse_header/valid_floor` (FLOOR header, `body_len = 16`, 16 body bytes). Run it once and commit the file.
- [ ] **Step 2:** `cargo test -p holm-core --test format_props`. Expected: PASS (fix any panic found as a bug in Task 7/8 code, with a regression unit test).
- [ ] **Step 3:** `cargo fuzz init` layout under `fuzz/` (the root `Cargo.toml` already has `exclude = ["oracle", "fuzz"]`; `fuzz/Cargo.toml` keeps its own `[workspace]` and lockfile; keep the generated `fuzz/.gitignore` for `target`, `corpus`, `artifacts`, `coverage`). Deps: `libfuzzer-sys`, `arbitrary` (with `derive`), `holm-core` and `holm-crypto` by path. No handwritten `unsafe`. Targets:
  - `parse_header`: raw bytes into `Header::parse`, seeded from `fuzz/seeds/parse_header/`.
  - `parse_header_structured`: an `arbitrary` struct with header fields, a body of 16–64 bytes and up to 4 edits (offset, xor value, truncate or extend); it builds a valid file with `encode`, applies the edits, calls `Header::parse`, and on `Ok` asserts the re-encoded header equals the input's first 164 bytes.
  - `unpad`: an `arbitrary` choice between raw bytes and `pad(plaintext)` output with up to 4 edits, into `unpad`.
- [ ] **Step 4:** Run locally, every target: `cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=120` (seeds dir only where it exists). Expected: no crash. A crash becomes a regression input under `fuzz/seeds/<target>/` plus a unit test, then gets fixed.
- [ ] **Step 5: Local fuzzing gate and docs** (owner ruling: GitHub Actions is manual-only, so nothing here runs on a schedule):
  - `scripts/ci-local.sh`: add a `fuzz` gate after `oracle`. It checks for `cargo +nightly` and `cargo fuzz` with install hints (`rustup toolchain install nightly`, `cargo install --locked cargo-fuzz --version 0.13.2`), then runs `cargo fmt --manifest-path fuzz/Cargo.toml --check`, `cargo audit --file fuzz/Cargo.lock`, and a 30 s smoke run of each target with the command from Step 4 and `-max_total_time=30`. New corpus entries land in the git-ignored `fuzz/corpus/`, so the tree stays clean.
  - `fuzz/README.md`: the long run, as documented local commands: each target 600 s (`-max_total_time=600`), weekly and before the Phase 1 security review; how to reproduce a crash from `fuzz/artifacts/` and turn it into a seed plus a unit test.
  - `.github/workflows/fuzz.yml`: `workflow_dispatch` only (same pattern as `ci.yml`), Linux, nightly toolchain, each target 600 s, upload crash artifacts on failure, actions pinned by full commit SHA with the tag in a comment, `permissions: contents: read`, `persist-credentials: false`. A comment says to add the weekly `schedule:` when the repo goes public. It is not a gate.
  - Deferred, not in this plan (write both into `fuzz/README.md` so the Phase 1 security review sees them): the `open_fixed_key` fuzz target for full open with a fixed key (spec §12) moves to **Phase 2**, built on the Task 8 `open_with_kek` helper; the `cargo-cyclonedx` SBOM moves to **Phase 6**.
- [ ] **Step 6:** Lesson 08: `panic!` vs `Result`, why a panic in a parser is a security bug, what property testing and fuzzing find, why mutating a valid input finds more than random bytes (structure-aware fuzzing), how to read a fuzz crash and turn it into a test.
- [ ] **Step 7:** Commit: `test: property tests and fuzz targets for header and padding`. Then run `scripts/ci-local.sh` (must pass) before push.

---

Phases 2–6 get their own plans after this one ships.
