# Phase 0–1: Foundation, Crypto and File Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust workspace with supply-chain gates in CI, a `holm-crypto` crate (secret types, randomness, Argon2id, XChaCha20-Poly1305) proven by known-answer tests, and the v1 vault file format with sealed open/save/re-key in `holm-core`, plus one Rust lesson per task for an owner who is new to Rust.

**Architecture:** Cargo workspace. `holm-crypto` wraps RustCrypto primitives behind a tiny API with wipe-on-drop secret types and forbids `unsafe`. `holm-core::format` parses and encodes the fixed 164-byte header; `holm-core::envelope` does the key hierarchy (password → Argon2id KEK → wraps random DEK → DEK seals padded body). No disk I/O yet: everything works on byte slices.

**Tech Stack:** Rust 1.93.1, edition 2024; `argon2` 0.6, `chacha20poly1305` 0.11, `zeroize` 1.9, `getrandom` 0.4, `unicode-normalization` 0.1, `thiserror` 2, `subtle` 2.6; dev: `proptest` 1.12, `hex` 0.4, `serde_json`, `static_assertions`, `libsodium-sys-stable` 1.24 (test-only oracle); `cargo-deny`, `cargo-audit`, `cargo-vet`, `cargo-fuzz`.

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md`

## Global Constraints

- Licence: MIT OR Apache-2.0 on every crate (`license = "MIT OR Apache-2.0"`).
- `#![forbid(unsafe_code)]` at the top of `holm-crypto`, `holm-core` and `holm-cli` `lib.rs`/`main.rs`.
- No networking crates anywhere in the graph; `cargo deny check` must fail if `reqwest`, `hyper`, `ureq`, `isahc`, `curl`, `surf`, `attohttpc`, `tokio`, `openssl` or `openssl-sys` appears.
- `libsodium-sys-stable` is a dev-dependency behind the `oracle` feature only; never a normal dependency.
- Secret types: no `Clone`, no `Copy`, wipe on drop, `Debug` prints `[REDACTED]`.
- Passwords: NFC-normalise, then UTF-8. No other encoding.
- Argon2id v1.3 (0x13). DEFAULT 262144 KiB / t3 / p1. FLOOR 65536 KiB / t3 / p1. CEILING 1048576 KiB / t16 / p1, and `memory_kib × iterations ≤ 4194304`. Parallelism must equal 1.
- XChaCha20-Poly1305: 32-byte key, 24-byte random nonce per seal, 16-byte tag.
- Header: 164 bytes, little-endian, magic `HOLMVLT\0`, version 1, flags 0, KDF id 1, reserved zero. Wrap AAD = bytes 0..60, body AAD = bytes 0..164. No CRC. Trailing bytes rejected. Max file 64 MiB (67108864 bytes).
- Body padding: multiple of 16384 bytes.
- A KDF-cost rejection is never reported as a wrong password.
- `clippy -D warnings` and `rustfmt --check` clean.
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

- Composed vs decomposed Unicode passwords (`"é"` vs `"e\u{301}"`) must open the same vault → test in Task 5.
- A vault with zero items (empty body plaintext) must seal and open → test in Task 8.
- A file exactly 67108864 bytes long parses its header checks; 67108865 bytes is rejected as too large → test in Task 7.
- A truncated file (download cut short) whose `body_len` is bigger than the bytes present is rejected as a format error, not a panic → test in Task 7.
- Creating two vaults with the same password produces different salts, DEKs and files → test in Task 8.

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

- [ ] **Step 1:** Workspace `Cargo.toml` with `resolver = "3"`, `[workspace.package]` (edition 2024, licence, `rust-version = "1.93.1"`, repository `https://github.com/sunnat629/holm`), `[workspace.dependencies]` for every crate in Tech Stack, and `[profile.dev.package."*"] opt-level = 3` so Argon2 tests are not painfully slow in debug builds. `rust-toolchain.toml`: channel `1.93.1`, components `rustfmt`, `clippy`.
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

**Interfaces:**
- Produces:
  - `pub struct SecretKey` (32 bytes): `SecretKey::from_bytes(bytes: [u8; 32]) -> SecretKey`, `fn expose(&self) -> &[u8; 32]`. `ZeroizeOnDrop`, no `Clone`/`Copy`, `Debug` → `SecretKey([REDACTED])`.
  - `pub struct SecretBuf` (variable length, wraps `zeroize::Zeroizing<Vec<u8>>`): `SecretBuf::from_vec(v: Vec<u8>) -> SecretBuf`, `fn expose(&self) -> &[u8]`, `fn len(&self) -> usize`, `fn is_empty(&self) -> bool`. `Debug` → `SecretBuf([REDACTED], len = N)`.
  - `pub struct MasterPassword` (wraps `zeroize::Zeroizing<String>`): `MasterPassword::new(s: String) -> MasterPassword`, `fn to_kdf_bytes(&self) -> SecretBuf` (NFC, then UTF-8). `Debug` → `MasterPassword([REDACTED])`.

- [ ] **Step 1: Write failing tests** in `secret.rs` `#[cfg(test)] mod tests`:

```rust
#[test] fn debug_never_shows_key_bytes() {
    let k = SecretKey::from_bytes([0xAB; 32]);
    let s = format!("{k:?}");
    assert_eq!(s, "SecretKey([REDACTED])");
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
- [ ] **Step 3:** Implement the three types in `secret.rs`. Use `#[derive(Zeroize, ZeroizeOnDrop)]` on `SecretKey`; hand-write `Debug`. `to_kdf_bytes` collects `.nfc()` into a `String` held in `Zeroizing`, then copies its bytes into a fresh `SecretBuf`.
- [ ] **Step 4:** `cargo test -p holm-crypto secret`. Expected: PASS.
- [ ] **Step 5:** Write lesson 02: ownership and moves, `Drop`, derive macros, traits (`Debug`), why "no `Clone`" stops accidental copies, how this fixes the JVM problem (immutable `String`s you can't wipe). Include the honest limit: wiping helps, but the OS and allocator can still hold copies.
- [ ] **Step 6:** Commit: `feat(crypto): wipe-on-drop secret types with redacted Debug`.

### Task 4: Errors and randomness, lesson 03

**Files:**
- Create: `crates/holm-crypto/src/error.rs`, `crates/holm-crypto/src/random.rs`, `docs/learn/03-errors-and-results.md`

**Interfaces:**
- Produces:
  - `pub enum CryptoError { Rng, KdfParams(KdfParamsError), Kdf, Aead }` (thiserror; `Aead` message is exactly `"decryption failed"`, never more detail).
  - `pub enum KdfParamsError { BelowFloor, AboveCeiling, TooMuchWork, UnsupportedParallelism }`.
  - `pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError>` (getrandom; maps failure to `Rng`).
  - `pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError>`.
  - `impl SecretKey { pub fn generate() -> Result<SecretKey, CryptoError> }`.

- [ ] **Step 1: Failing tests:** `two_generated_keys_differ` (`assert_ne!(a.expose(), b.expose())`), `random_nonces_differ` (`random_array::<24>()` twice), `aead_error_message_is_opaque` (`assert_eq!(CryptoError::Aead.to_string(), "decryption failed")`).
- [ ] **Step 2:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 3:** Implement. Generate keys by filling a `Zeroizing<[u8; 32]>` then building the `SecretKey`, so no unwiped stack copy is left behind by our code.
- [ ] **Step 4:** `cargo test -p holm-crypto`. Expected: PASS.
- [ ] **Step 5:** Lesson 03: `Result<T, E>`, `?`, enums with data, `match`, `thiserror`, const generics (`[u8; N]`), why errors must not leak secrets or say *which* check failed in decryption. Kotlin comparison: exceptions vs `Result`.
- [ ] **Step 6:** Commit: `feat(crypto): error types and OS randomness`.

### Task 5: Argon2id KDF with cost policy, lesson 04

**Files:**
- Create: `crates/holm-crypto/src/kdf.rs`, `crates/holm-crypto/tests/argon2_kat.rs`, `crates/holm-crypto/tests/oracle_libsodium.rs`, `docs/learn/04-constants-overflow-and-features.md`
- Modify: `crates/holm-crypto/Cargo.toml` (feature `oracle = []`, dev-dep `libsodium-sys-stable`, optional)

**Interfaces:**
- Consumes: `MasterPassword::to_kdf_bytes`, `SecretKey`, `CryptoError`, `KdfParamsError`.
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct KdfParams { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 }`
  - `impl KdfParams { pub const DEFAULT: Self; pub const FLOOR: Self; pub const CEILING: Self; pub fn validate(&self) -> Result<(), KdfParamsError> }`
  - `pub fn derive_kek(password: &MasterPassword, salt: &[u8; 32], params: &KdfParams) -> Result<SecretKey, CryptoError>`: calls `validate` first and returns `CryptoError::KdfParams(_)` without allocating Argon2 memory.
  - `#[doc(hidden)] pub fn argon2id_raw(password: &[u8], salt: &[u8], secret: &[u8], ad: &[u8], m_kib: u32, t: u32, p: u32, out: &mut [u8]) -> Result<(), CryptoError>`: no policy checks; used only by KAT tests.

- [ ] **Step 1: Failing policy tests** in `kdf.rs`:

```rust
#[test] fn default_and_floor_are_valid() { assert!(KdfParams::DEFAULT.validate().is_ok()); assert!(KdfParams::FLOOR.validate().is_ok()); }
#[test] fn below_floor_rejected() { assert_eq!(KdfParams { memory_kib: 65535, iterations: 3, parallelism: 1 }.validate(), Err(KdfParamsError::BelowFloor)); }
#[test] fn too_few_iterations_rejected() { assert_eq!(KdfParams { memory_kib: 65536, iterations: 2, parallelism: 1 }.validate(), Err(KdfParamsError::BelowFloor)); }
#[test] fn above_ceiling_rejected() { assert_eq!(KdfParams { memory_kib: 1048577, iterations: 3, parallelism: 1 }.validate(), Err(KdfParamsError::AboveCeiling)); }
#[test] fn combined_work_rejected() { assert_eq!(KdfParams { memory_kib: 1048576, iterations: 5, parallelism: 1 }.validate(), Err(KdfParamsError::TooMuchWork)); }
#[test] fn max_u32_does_not_overflow() { assert!(KdfParams { memory_kib: u32::MAX, iterations: u32::MAX, parallelism: 1 }.validate().is_err()); }
#[test] fn parallelism_must_be_one() { assert_eq!(KdfParams { parallelism: 2, ..KdfParams::DEFAULT }.validate(), Err(KdfParamsError::UnsupportedParallelism)); }
#[test] fn nfc_forms_give_same_kek() {
    let salt = [9u8; 32];
    let a = derive_kek(&MasterPassword::new("caf\u{e9}".into()), &salt, &KdfParams::FLOOR).unwrap();
    let b = derive_kek(&MasterPassword::new("cafe\u{301}".into()), &salt, &KdfParams::FLOOR).unwrap();
    assert_eq!(a.expose(), b.expose());
}
```

- [ ] **Step 2: Failing KAT** in `tests/argon2_kat.rs`: `rfc9106_argon2id_vector` calls `argon2id_raw` with the RFC 9106 §5.3 Argon2id inputs (password 32×`0x01`, salt 16×`0x02`, secret 8×`0x03`, ad 12×`0x04`, m=32, t=3, p=4, 32-byte tag) and compares to the tag. **Copy the expected hex from the RFC text itself, not from memory**, and put the RFC URL in a comment.
- [ ] **Step 3:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 4:** Implement. `validate` order: parallelism, then floor, then ceiling, then `u64::from(memory_kib) * u64::from(iterations) <= 4_194_304`. `derive_kek` uses `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(..., Some(32)))` and writes into a `Zeroizing<[u8; 32]>`.
- [ ] **Step 5:** `cargo test -p holm-crypto`. Expected: PASS.
- [ ] **Step 6: libsodium oracle** in `tests/oracle_libsodium.rs` behind `#![cfg(feature = "oracle")]`: for 20 seeded pseudo-random passwords (lengths 0–64, including non-ASCII) and salts, compare `derive_kek` at FLOOR with libsodium `crypto_pwhash` (`ALG_ARGON2ID13`, opslimit = iterations, memlimit = memory_kib × 1024). libsodium takes a 16-byte salt, so the oracle covers salts through `argon2id_raw` with 16-byte salts and the same params, and separately asserts `derive_kek` equals `argon2id_raw` for 32-byte salts. Add the CI job `cargo test -p holm-crypto --features oracle` on Linux.
- [ ] **Step 7:** `cargo test -p holm-crypto --features oracle`. Expected: PASS.
- [ ] **Step 8:** Lesson 04: `const`, associated constants, struct update syntax (`..DEFAULT`), integer overflow in Rust (debug panics, release wraps) and why we widen to `u64`, `#[cfg(test)]` and cargo features, integration tests vs unit tests.
- [ ] **Step 9:** Commit: `feat(crypto): Argon2id KDF with floor/ceiling policy and KATs`.

### Task 6: XChaCha20-Poly1305 AEAD, lesson 05

**Files:**
- Create: `crates/holm-crypto/src/aead.rs`, `crates/holm-crypto/tests/xchacha_kat.rs`, `crates/holm-crypto/tests/vectors/xchacha20_poly1305_test.json`, `crates/holm-crypto/tests/vectors/README.md`, `docs/learn/05-slices-and-borrowing.md`

**Interfaces:**
- Consumes: `SecretKey`, `SecretBuf`, `CryptoError`.
- Produces:
  - `pub const NONCE_LEN: usize = 24; pub const TAG_LEN: usize = 16; pub const KEY_LEN: usize = 32;`
  - `pub fn seal(key: &SecretKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>` (output = ciphertext ‖ tag)
  - `pub fn open(key: &SecretKey, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<SecretBuf, CryptoError>` (any failure → `CryptoError::Aead`)

- [ ] **Step 1: Vectors.** Download Wycheproof `testvectors_v1/xchacha20_poly1305_test.json` from `github.com/C2SP/wycheproof` at a fixed commit. Record commit SHA, URL and file SHA-256 in `vectors/README.md`.
- [ ] **Step 2: Failing tests:** in `aead.rs`: `roundtrip`, `empty_plaintext_roundtrip`, `wrong_key_fails`, `flipping_any_ciphertext_byte_fails` (loop every byte), `flipping_any_aad_byte_fails`, `wrong_nonce_fails`, `truncated_below_tag_fails`. All failures assert `Err(CryptoError::Aead)`. In `tests/xchacha_kat.rs`: `draft_xchacha_a3_1` (draft-irtf-cfrg-xchacha-03 Appendix A.3.1, values copied from the draft with its URL in a comment) and `wycheproof_all_cases` (parse JSON with `serde_json`; `valid` must round-trip to the given ciphertext and tag, `invalid` must fail; assert the number of cases checked equals the file's `numberOfTests`). The `oracle` feature adds `libsodium_matches_for_random_inputs` (100 seeded inputs, compare with `crypto_aead_xchacha20poly1305_ietf_encrypt`).
- [ ] **Step 3:** `cargo test -p holm-crypto`. Expected: FAIL.
- [ ] **Step 4:** Implement with `chacha20poly1305::XChaCha20Poly1305` and `Payload { msg, aad }`. Decrypt into a buffer that is wiped if decryption fails.
- [ ] **Step 5:** `cargo test -p holm-crypto` and `cargo test -p holm-crypto --features oracle`. Expected: PASS.
- [ ] **Step 6:** Lesson 05: slices (`&[u8]`) vs arrays (`[u8; 24]`) vs `Vec<u8>`, borrowing (`&`) vs owning, why the API takes `&SecretKey`, intro to lifetimes, and why an AEAD fails "all or nothing" (no partial plaintext).
- [ ] **Step 7:** Commit: `feat(crypto): XChaCha20-Poly1305 seal/open with Wycheproof and draft KATs`.

### Task 7: Vault header format, lesson 06

**Files:**
- Create: `crates/holm-core/src/format.rs`, `docs/learn/06-parsing-bytes-safely.md`
- Modify: `crates/holm-core/src/lib.rs`

**Interfaces:**
- Consumes: `KdfParams`, `KdfParamsError`.
- Produces:
  - `pub const MAGIC: [u8; 8] = *b"HOLMVLT\0"; pub const FORMAT_VERSION: u16 = 1; pub const KDF_ID_ARGON2ID: u8 = 1; pub const HEADER_LEN: usize = 164; pub const WRAP_AAD_LEN: usize = 60; pub const MAX_FILE_LEN: usize = 67_108_864;`
  - `#[derive(Clone, Debug, PartialEq, Eq)] pub struct Header { pub kdf: KdfParams, pub salt: [u8; 32], pub wrap_nonce: [u8; 24], pub wrapped_dek: [u8; 48], pub body_nonce: [u8; 24], pub body_len: u64 }`
  - `impl Header { pub fn encode(&self) -> [u8; HEADER_LEN]; pub fn parse(file: &[u8]) -> Result<(Header, &[u8]), FormatError> }` (returns header and the body ciphertext slice)
  - `pub enum FormatError { TooLarge, TooShort, BadMagic, UnsupportedVersion(u16), BadFlags, UnknownKdf(u8), ReservedNotZero, KdfPolicy(KdfParamsError), LengthMismatch, BodyTooShort }`

Layout (offset, size): magic 0/8, version 8/2, flags 10/2, kdf_id 12/1, reserved 13/3, memory_kib 16/4, iterations 20/4, parallelism 24/4, salt 28/32, wrap_nonce 60/24, wrapped_dek 84/48, body_nonce 132/24, body_len 156/8. Integers little-endian.

- [ ] **Step 1: Failing tests** (helper `valid_header()` uses FLOOR params and `body_len = 16`; helper `file(h, body)` concatenates):
  - `encode_then_parse_roundtrip`
  - `encoded_length_is_164` and `wrap_aad_is_first_60_bytes` (fields after offset 60 do not change bytes 0..60)
  - one rejection test per `FormatError` variant, mutating exactly one byte or length (e.g. `byte[12] = 2` → `UnknownKdf(2)`, `byte[13] = 1` → `ReservedNotZero`, memory_kib 65535 → `KdfPolicy(BelowFloor)`)
  - `trailing_byte_rejected` → `LengthMismatch`
  - `truncated_body_rejected` (`body_len = 1000`, 16 bytes present) → `LengthMismatch`
  - `body_len_u64_max_rejected_without_panic` → `LengthMismatch`
  - `file_of_exactly_max_len_passes_size_check` (vec of `MAX_FILE_LEN` bytes with a valid header and matching `body_len` → `Ok`) and `file_one_over_max_rejected` → `TooLarge`
  - `body_shorter_than_tag_rejected` (`body_len = 15`) → `BodyTooShort`
- [ ] **Step 2:** `cargo test -p holm-core format`. Expected: FAIL.
- [ ] **Step 3:** Implement. Check order: size (`TooLarge`, `TooShort`), magic, version, flags, kdf id, reserved, KDF policy, then lengths with `usize::try_from` and `checked_add` (never `as` casts, never indexing past checked bounds). Read fields with `u32::from_le_bytes(bytes[a..b].try_into()?)` style.
- [ ] **Step 4:** `cargo test -p holm-core format`. Expected: PASS.
- [ ] **Step 5:** Lesson 06: byte order, `from_le_bytes`, `try_into`, why slice indexing can panic and how `get`/checked maths avoid it, `match` on enums, returning a borrowed slice from a function (first real lifetime example).
- [ ] **Step 6:** Commit: `feat(core): v1 vault header encode/parse with strict validation`.

### Task 8: Envelope: create, open, re-save, re-key, lesson 07

**Files:**
- Create: `crates/holm-core/src/envelope.rs`, `crates/holm-core/src/padding.rs`, `docs/CRYPTO.md`, `docs/learn/07-modules-and-encapsulation.md`

**Interfaces:**
- Consumes: Task 3–7 items.
- Produces:
  - `pub fn pad(plaintext: &[u8]) -> SecretBuf` (u32 LE length prefix, then plaintext, then zeros to the next multiple of 16384; empty input gives 16384 bytes) and `pub fn unpad(padded: &[u8]) -> Result<SecretBuf, VaultError>`.
  - `pub struct VaultKeys` (private fields: `dek: SecretKey`, `header: Header`); no `Clone`; `Debug` redacted.
  - `pub fn create(password: &MasterPassword, params: &KdfParams, body: &[u8]) -> Result<(VaultKeys, Vec<u8>), VaultError>` (fresh salt, DEK, wrap nonce, body nonce)
  - `pub fn open(file: &[u8], password: &MasterPassword) -> Result<(VaultKeys, SecretBuf), VaultError>` (returns the unpadded body)
  - `pub fn reseal(keys: &mut VaultKeys, body: &[u8]) -> Result<Vec<u8>, VaultError>` (new body nonce every call; updates `keys.header`)
  - `pub fn rekey(keys: VaultKeys, new_password: &MasterPassword, params: &KdfParams, body: &[u8]) -> Result<(VaultKeys, Vec<u8>), VaultError>` (new salt **and new DEK**; consumes the old keys)
  - `pub fn verify_password(keys: &VaultKeys, password: &MasterPassword) -> Result<(), VaultError>` (re-derive KEK, unwrap DEK, compare with `subtle::ConstantTimeEq`; used later for recovery-phrase reveal)
  - `pub enum VaultError { Format(FormatError), KdfPolicy(KdfParamsError), WrongPasswordOrCorrupt, Crypto }` with `From<FormatError>`. Both `FormatError::KdfPolicy(e)` and `CryptoError::KdfParams(e)` map to `VaultError::KdfPolicy(e)`; any AEAD failure maps to `WrongPasswordOrCorrupt`; `Rng` and `Kdf` map to `Crypto`.

- [ ] **Step 1: Failing tests** (all with `KdfParams::FLOOR`):
  - `create_then_open_returns_body`
  - `empty_body_roundtrip`
  - `wrong_password_is_opaque` → `WrongPasswordOrCorrupt`
  - `every_header_byte_flip_fails` (flip each of bytes 0..164 in turn; assert `open` is `Err`, never `Ok`, never panics)
  - `every_body_byte_flip_fails`
  - `reseal_uses_fresh_nonce` (two reseals of the same body differ in bytes 132..156 and ciphertext)
  - `same_password_two_vaults_differ` (salt, wrapped DEK and whole file differ)
  - `padding_hides_small_size_differences` (1-byte and 16000-byte bodies give the same file length)
  - `rekey_old_password_fails_new_password_opens`
  - `rekey_rotates_dek` (old DEK, via a `#[cfg(test)]` accessor, cannot `aead::open` the new file's body)
  - `kdf_above_ceiling_is_policy_error_not_wrong_password` (hand-built header with memory 2097152 → `KdfPolicy(AboveCeiling)`)
  - `verify_password_accepts_right_rejects_wrong`
  - `unpad_rejects_length_prefix_larger_than_buffer`
- [ ] **Step 2:** `cargo test -p holm-core envelope`. Expected: FAIL.
- [ ] **Step 3:** Implement. Wrap = `aead::seal(kek, wrap_nonce, &encoded[0..60], dek_bytes)`; body = `aead::seal(dek, body_nonce, &encoded[0..164], padded)`. `body_len` must be set before encoding the AAD, so compute ciphertext length as `padded.len() + TAG_LEN` first. Open: `Header::parse` → `derive_kek` → unwrap DEK → open body → `unpad`.
- [ ] **Step 4:** `cargo test -p holm-core`. Expected: PASS.
- [ ] **Step 5:** Write `docs/CRYPTO.md` from spec section 5 and this task: key diagram, header table, AAD ranges, why re-key rotates the DEK, what is **not** claimed.
- [ ] **Step 6:** Lesson 07: modules and `pub`/private fields, why `VaultKeys` hides the DEK, consuming `self` in `rekey` (the old keys can't be used afterwards, enforced by the compiler), `From` and `?` for error conversion.
- [ ] **Step 7:** Commit: `feat(core): vault envelope with DEK wrap, padding, reseal and rekey`.

### Task 9: Property tests and fuzzing, lesson 08

**Files:**
- Create: `crates/holm-core/tests/format_props.rs`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/parse_header.rs`, `fuzz/fuzz_targets/unpad.rs`, `.github/workflows/fuzz.yml`, `docs/learn/08-property-tests-and-fuzzing.md`

**Interfaces:**
- Consumes: `Header::parse`, `Header::encode`, `unpad`.

- [ ] **Step 1: Property tests** with `proptest`: `parse_never_panics(bytes in vec(any::<u8>(), 0..400))`; `encode_parse_roundtrip(valid header strategy: memory 65536..=1048576, iterations 3..=4, random salts/nonces)`; `unpad_never_panics`.
- [ ] **Step 2:** `cargo test -p holm-core --test format_props`. Expected: PASS (fix any panic found as a bug in Task 7/8 code, with a regression unit test).
- [ ] **Step 3:** `cargo fuzz init` layout under `fuzz/` (excluded from the workspace); two targets that call `Header::parse` and `unpad` on raw input. Seed corpus: one valid header file.
- [ ] **Step 4:** Run locally: `cargo +nightly fuzz run parse_header -- -max_total_time=120`. Expected: no crash.
- [ ] **Step 5:** `fuzz.yml`: weekly schedule plus manual trigger, Linux, nightly toolchain, each target 600 s, upload crash artifacts on failure. Actions pinned by SHA.
- [ ] **Step 6:** Lesson 08: `panic!` vs `Result`, why a panic in a parser is a security bug, what property testing and fuzzing find, how to read a fuzz crash and turn it into a test.
- [ ] **Step 7:** Commit: `test: property tests and fuzz targets for header and padding`.

---

Phases 2–6 get their own plans after this one ships.
