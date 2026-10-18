# Phase 2: holm-core vault, items, generator, import/export, throttle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `holm-core` that holds a whole working vault (four item types, categories, trash, search, settings, password generator, strength check, unlock throttle, import, plaintext export and encrypted backup) behind one `Session` handle, saved to disk by a crash-safe `FsStore`, so that a full create → edit → lock → unlock → change password → export → import round trip passes and a save killed at any step leaves the old or the new vault.

**Architecture:** `holm-core` stays I/O-free: it reaches the disk through the `VaultStore` trait and time through the `Clock` trait, so tests inject faults. The decrypted body is a versioned `postcard` encoding of `VaultData`, sealed by the Phase 1 envelope. `Session<S: VaultStore>` is the single owner of keys, data and the throttle. A new `holm-platform` crate brings a std-only durable `FsStore` forward from Phase 4 (still `forbid(unsafe_code)`), so crash tests run against real files.

**Tech Stack:** Rust 1.99.1, edition 2024. New runtime deps: `serde` 1 (`derive`), `postcard` 1 (`alloc`, no default features), `csv` 1, `serde_json` 1 (moves from dev to runtime), `blake2` 0.11 (feature unification only). Dev: `tempfile` 3 (already in the lockfile through proptest), `zxcvbn` 3 (test oracle for the strength check only; COS ruling on #16). Fuzz workspace: existing `libfuzzer-sys`, `arbitrary`. Data: EFF large word list (CC-BY-3.0-US).

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md` (§4, §7, §8.1–8.9, §9 durable save, §11, §12 tests, §13, §14 Phase 2). UI data needs: `docs/design/ui-final-notes.md`. Decisions: `docs/DECISIONS.md`.

## Global Constraints

- Licence `MIT OR Apache-2.0` on every crate; every member has `[lints] workspace = true`, so `unsafe_code = "forbid"` covers `holm-platform` too in this phase.
- Libraries start with `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- No networking crates (the `deny.toml` ban list is never weakened). Every cargo command in plans, scripts and docs uses `--locked`.
- Every new dependency goes in root `[workspace.dependencies]`, passes `cargo deny --all-features --locked check` and `cargo vet --locked`. Prefer imported audits; an exemption needs a one-line reason in `supply-chain/config.toml` and a line in `docs/DECISIONS.md`. A new licence goes on the `deny.toml` allowlist only with its reason in the same commit; never a copyleft licence.
- Separate lockfiles: a task that changes the dependencies of `holm-crypto` also refreshes `oracle/Cargo.lock`, and a task that changes the dependencies of `holm-crypto` or `holm-core` also refreshes `fuzz/Cargo.lock`, each with `cargo update -p <crate> --manifest-path <oracle|fuzz>/Cargo.toml`, committed with the dependency change. The oracle gate runs `--locked`, and `cargo fuzz` would otherwise rewrite the fuzz lockfile during the gate and leave the tree dirty.
- Secret types: no `Clone`, no `Copy`, wipe on drop, `Debug` prints `[REDACTED]`. Every text field of an item, secret or not, wipes on drop, and no `Debug` impl prints item text. No error carries item data, passwords or file paths.
- Only the master password is NFC-normalised. Item passwords, phrases, addresses and notes are stored byte-exact: never trimmed, normalised or re-encoded.
- Search reads only title, username, URL, chain and category name. Never a secret field.
- Master password: score 4 on zxcvbn's scale (Holm's own estimate of ≥ 1e10 guesses) **and** 12 to 1,024 characters (counted as `char`s of the NFC form; longer input is refused unscored). No override. (Raised from score 3 / 1e8 in fix round 1 of #16.)
- Throttle (spec §11): 3 failures free, then 2, 4, 8 … s, capped at 60 s; in memory only; resets on success; measured on the monotonic clock.
- Recovery phrases are only readable through the two password-gated paths: `Session::reveal_phrase` and `Session::export_csv`.
- Settings ceilings (spec §10): auto-lock ≤ 3600 s with no "never", clipboard clear ≤ 90 s; weakening any setting needs the master password.
- Generator randomness comes only from the OS (`holm_crypto::fill_random`), sampled uniformly by rejection.
- File cap 64 MiB on read and write (`MAX_FILE_LEN`), unchanged from Phase 1.
- Tests use `KdfParams::FLOOR` unless a step says otherwise, and only fake data (`example.com`, values containing `EXAMPLE`).
- `clippy -D warnings` and `rustfmt --check` clean.
- Commit first, then `scripts/ci-local.sh` must print `ALL GATES PASSED` before every push. GitHub Actions is manual-only and never the gate.
- One GitHub issue per task (labels `phase-2`, `security`, `lesson`), listed in `docs/tasks/BACKLOG.md`.
- Every task writes one lesson in `docs/learn/` (format below) and adds its line to `docs/learn/README.md`.

## Lesson format

Same as Phase 0–1. Every `docs/learn/NN-topic.md`, numbered from 09, has exactly these sections, and stays under 250 lines:
1. **What we built** (3–5 sentences).
2. **Rust ideas in this task**: real snippets from this task's code, explained line by line, each with "In Kotlin you'd write…".
3. **Why this matters for security** (2–4 sentences).
4. **Try it**: 3 exercises, each with the command that checks the answer.
5. **Read next**: 1–3 links (The Rust Programming Language, or the std/crate docs).

Never paste real secrets in examples.

## Security decisions

Made by the security COS under the owner's delegation; each is also a line in `docs/DECISIONS.md`.

- **Security decision (throttle):** in memory inside `Session`, so it survives lock and unlock but not a restart (spec §11). EVERY unlock error counts as a failure (F16), enforced through `Throttle::attempt`: wrong password, format, policy, crypto, out-of-memory and store errors alike (the error shown to the user is still specific). One counter covers unlock, recovery-phrase reveal, password change, settings weakening and CSV export. A refused attempt runs no Argon2 and is not counted. Monotonic clock only, so changing the wall clock cannot skip a delay.
- **Security decision (generator):** OS randomness only, through `holm_crypto::fill_random`; there is no public API that takes a seed or an RNG. Indices use rejection sampling. Minimum digit and symbol counts are met by redrawing the whole password, so the result is uniform over all passwords that satisfy the spec. Passwords are 12–128 characters, the required counts are at most half the length, and the estimate `length × log2(pool)` must be at least 64 bits. Passphrases are 6–20 words from the EFF large list (≥ 77 bits). Usernames are not secrets and have no floor.
- **Security decision (import):** the input is hostile. Size cap 16 MiB checked before parsing; strict UTF-8 (a leading BOM is removed); at most 50 000 rows and 64 columns; unknown or duplicate columns reject the whole file; each row passes the same field rules as manual entry, and a bad row is skipped and reported by row number and reason only, never by value; categories match existing names only (no auto-create; owner answer: unmatched → Uncategorised); the apply is all-or-nothing; a secret the format carries but Holm cannot store (Safari OTP) is dropped and counted. A row that duplicates an existing item or an earlier row of the same file (same type, title, username and URLs after canonicalisation; owner answer 2026-10-18) is skipped and counted, never merged. Unlike the old Kotlin importer, a recovery row never takes its phrase from `password` or `notes`, and a blank `chain` stays blank: Holm never guesses where a secret goes. The parsers' internal scratch copies are not wiped (documented gap: the source file is plaintext on disk anyway).
- **Security decision (export):** plaintext CSV needs the master password (throttled), shows the fixed `EXPORT_WARNING` text, leaves out Trash, is built in one wiping allocation, and is written only by `write_new_private_file` (create-new, never overwrite, mode 0600 on Unix). Cells are not formula-escaped: escaping would change passwords that start with `=`, `+`, `-` or `@` and break migration; the warning says not to open the file in a spreadsheet. After the 11 import columns the export adds `favourite`, `created` and `updated` (owner answer 2026-10-18), which import reads when present.
- **Security decision (durable writes):** a save writes a temp file in the vault's directory (random name `<file>.tmp-<16 hex>`, created exclusively, mode 0600 on Unix), writes it, `sync_all` (std uses `F_FULLFSYNC` on macOS), renames over the vault, then syncs the directory (Unix). Any failure before the rename removes the temp and leaves the vault untouched. A directory sync that returns `ErrorKind::Unsupported` (some FAT/exFAT volumes, such as a USB stick, spec §8.0) counts as success; any other directory-sync error fails the save. `create_new` never overwrites (hard link as an atomic no-replace, falling back to an exclusive create where links are unsupported, such as FAT), and it removes its temp in every branch. The vault path must be a regular file, never a symlink. Unlock removes only temps matching the exact pattern. Crash tests stop a child process at each step with `std::process::exit`; that matches a killed process, not power loss, which stays on the Phase 4 per-OS checklist with Windows write-through, directory sync and the file lock.
- **Security decision (holm-platform now):** the crate is created in Phase 2 with only the std-based `FsStore` and `write_new_private_file`, under `forbid(unsafe_code)`. Phase 4 relaxes that per module when OS code arrives.
- **Security decision (item text):** every string in an item, including title, username and URLs, wipes on drop (`Text` / `SecretText`). `Debug` prints lengths only. Display fields (title, username, URL, chain, category name) reject C0/C1 controls and bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) to stop spoofed titles. Single-line secrets (password, address, memo) reject NUL, CR and LF; multi-line ones (notes, body, phrase) reject NUL only. A URL is optional; when present it is non-empty and has no leading or trailing whitespace, so a URL is always in canonical form and survives export and import byte-exact.
- **Security decision (limits):** 50 000 items; 256 categories (names ≤ 64 characters); display fields and address/memo ≤ 1024 bytes; password and phrase ≤ 4096 bytes; notes and note body ≤ 65 536 bytes; ≤ 32 URLs per login. A change that would push the file past 64 MiB is rolled back.
- **Security decision (phrase gate):** enforced in core. `GatedSecret` has no public accessor; `Session::reveal_phrase` checks the master password through the throttle every time.
- **Security decision (settings):** auto-lock 60–3600 s (default 300), clipboard clear 5–90 s (default 30), lock on sleep default on. "Weaker" means a longer auto-lock or clipboard time, turning off lock-on-sleep, or a lower generator entropy estimate; it needs the password. Out-of-range values found in an authenticated body are clamped toward the strict end, not rejected, so a vault never becomes unopenable over a setting.
- **Security decision (body schema):** plaintext = `u16` LE schema version (1), then `postcard`. Trailing bytes are rejected, the data is validated after decoding, and a newer schema is refused rather than rewritten, so an old Holm never silently drops new fields.
- **Security decision (strength check, COS ruling on #16):** no `zxcvbn` in production. `holm-core` has its own check: NFC, ≥ 12 characters, zxcvbn's MIT frequency lists embedded with `include_str!` (SHA-256 in `NOTICE`, gated in `scripts/ci-local.sh`), matchers for case, l33t, `holm`, repeats, sequences, keyboard walks, years and dates, a minimum-guesses split with random gaps, and acceptance only at ≥ 1e10 guesses (score 4) and 12 to 1,024 characters. Every derived buffer is `Zeroizing`; feedback is fixed text; the whole password is scored with bounded work. The `zxcvbn` crate is a dev-dependency used as a test oracle (`tests/strength_oracle.rs`): zxcvbn < 4 ⇒ Holm refuses, on a fixed corpus and a fixed-seed generated corpus. Its tree is dev-only, so it needs only `safe-to-run`. Replaces the earlier "accept zxcvbn's un-wiped copies" decision.
- **Security decision (blake2):** a direct `blake2` dependency with `zeroize` turns on wiping of the BLAKE2b state that `argon2` uses, through feature unification (same pattern as `poly1305`).
- **Security decision (vet):** replace exemptions with imported audits first; `cargo vet trust` only for crates whose publisher is the Rust project or a long-standing maintainer already trusted by an imported set; exemptions may remain only for dev-only or unused-target crates, each with its reason. `libc` (runtime) and `syn` (build-time, both versions) must leave the exemption list.
- **Security decision (fuzzing feature):** `holm-core` gets a `fuzzing` feature exposing fixed-key seal and open. Only `fuzz/` enables it; the Phase 6 `--all-features` release guard covers it as it covers `test-vectors`.
- **Security decision (Argon2 memory):** the work area is already reserved with `try_reserve_exact` (Phase 1, reported as `CryptoError::Kdf`); Phase 2 reports a refused allocation as `OutOfMemory` (the unlock screen's "not enough memory" state) instead, where the OS reports it.
- **Security decision (dirty flag):** an undo after `TooLargeToSave` restores the dirty flag the session had before the method; it never marks the session clean, so an earlier unsaved edit still shows as unsaved at lock.
- **Security decision (`rekey`):** `Session::change_password` does not use `envelope::rekey`, because `rekey` swaps the keys before the caller writes. It calls `envelope::create`, then `store.replace`, then swaps, so a failed write leaves the old password working. `rekey` stays as a tested Phase 1 API.

## Review Focus

- A login password with leading/trailing spaces, a tab and decomposed Unicode must come back byte-exact after save, reopen, CSV export and re-import → test in Task 8 and Task 12.
- A CSV saved by a spreadsheet (UTF-8 BOM, CRLF line ends, quoted multi-line notes, a trailing blank line) must import → test in Task 11.
- A search for `cafe\u{301}` or `CAFÉ` must find the title `Café Login` → test in Task 9.
- A save that fails (read-only directory, disk full) must leave the old file intact, keep the edit in memory as unsaved, and succeed on retry → tests in Task 7 (fault store) and Task 10 (real read-only directory).
- Stale-temp cleanup must delete only this vault's own temps: never another vault's, never a symlink, never a near-miss name → test in Task 10.
- A vault on an exFAT volume (a USB stick) must save and reopen, and a save must never leave a temp behind → test in Task 10 (macOS, real exFAT disk image).
- An undo after an oversize change must not hide an earlier unsaved edit → test in Task 8.
- Re-importing the same file must skip every row as a duplicate and say how many → test in Task 11.

---

### Task 1: Dependency hygiene: BLAKE2 wiping and cargo vet exemptions

**Issue:** [#13](https://github.com/sunnat629/holm/issues/13)

**Files:**
- Modify: `Cargo.toml` (`blake2 = { version = "0.11", default-features = false, features = ["zeroize"] }` with a comment like the `poly1305` one), `crates/holm-crypto/Cargo.toml` (`blake2.workspace = true`)
- Modify: `crates/holm-crypto/src/kdf.rs` (test, and the `derive_kek` doc comment that still says the BLAKE2b state is not wiped), `supply-chain/config.toml`, `supply-chain/audits.toml`, `supply-chain/imports.lock`
- Modify: `oracle/Cargo.lock` and `fuzz/Cargo.lock` (both record holm-crypto's dependency list; see Global Constraints, separate lockfiles)
- Modify: `docs/CRYPTO.md` (known gaps), `docs/DECISIONS.md` (vet line), `docs/tasks/BACKLOG.md` (close the two Phase 2 deferrals)
- Create: `docs/learn/09-feature-unification-and-vet.md`

**Interfaces:**
- Produces: no new API. `blake2` resolves with its `zeroize` feature on (`cargo tree -e features -i blake2 --locked` lists `zeroize`).

- [ ] **Step 1: Failing test** in `kdf.rs` tests: `static_assertions::assert_impl_all!(blake2::Blake2bVarCore: zeroize::ZeroizeOnDrop);` and the same for `blake2::Blake2b512`. If `Blake2b512` (the wrapper) does not implement it even with the feature, keep only the core assertion and name the unwiped wrapper buffer in `docs/CRYPTO.md`.
- [ ] **Step 2:** `cargo test -p holm-crypto --locked`. Expected: FAIL (`blake2` is not a dependency of holm-crypto).
- [ ] **Step 3:** Add the dependency (Files). Then `cargo tree -e features -i blake2 --locked`. Expected: `blake2 feature "zeroize"` appears. Refresh the other lockfiles: `cargo update -p holm-crypto --manifest-path oracle/Cargo.toml` and `cargo update -p holm-crypto --manifest-path fuzz/Cargo.toml`; then `cargo test --manifest-path oracle/Cargo.toml --locked` builds.
- [ ] **Step 4:** `cargo test -p holm-crypto --locked`. Expected: PASS. Edit the CRYPTO.md gap and the `derive_kek` doc comment to "the argon2 crate's 1 KiB stack buffer is not wiped" (BLAKE2b state now wiped).
- [ ] **Step 5: Vet.** `cargo vet regenerate imports`, then `cargo vet prune`, then `cargo vet suggest`. For each of the 12 exemptions: drop it if an import now covers it. `libc` (rust-lang-owner) and `syn` 2 and 3 (dtolnay) must leave the list: import an audit, or `cargo vet trust`. For the dev-only crates `rustix`/`linux-raw-sys` (sunfishcode), `windows-sys` (kennykerr) and `toml_edit`/`toml_parser`/`winnow` (epage), `cargo vet trust` only if an imported set already trusts that publisher; otherwise keep the exemption with its dev-only reason. `r-efi` (unused target), `borsh-derive` and `proptest` (dev-only) stay as exemptions with their reason.
- [ ] **Step 6:** `cargo vet --locked`. Expected: `Vetting Succeeded`. Check that no exemption remains for `libc` or `syn`, and that every remaining exemption's `notes` says "dev-only" or "unused target" with its reason. Write the outcome as one line in DECISIONS.md, replacing the "12 exemptions" line.
- [ ] **Step 7:** Lesson 09: features and feature unification (why a direct dependency can switch on a feature inside a transitive one), `cargo tree -e features`, vet criteria (`safe-to-run` vs `safe-to-deploy`), imports vs trust vs exemptions.
- [ ] **Step 8:** Commit `build(crypto): wipe argon2's BLAKE2b state; replace vet exemptions`, run `scripts/ci-local.sh`, push.

### Task 2: Text types, items and categories

**Issue:** [#14](https://github.com/sunnat629/holm/issues/14)

**Files:**
- Create: `crates/holm-core/src/text.rs`, `crates/holm-core/src/item.rs`, `crates/holm-core/src/category.rs`, `docs/learn/10-enums-newtypes-and-validation.md`
- Modify: `crates/holm-core/src/lib.rs`, root `Cargo.toml` (`serde = { version = "1", default-features = false, features = ["std", "derive"] }`), `crates/holm-core/Cargo.toml` (`serde`, `unicode-normalization` with `.workspace = true`), `fuzz/Cargo.lock`, `supply-chain/*` (serde, serde_derive), `deny.toml` only if a new licence is needed (with reason)

**Interfaces:**
- Consumes: `holm_crypto::{fill_random, CryptoError}`.
- Produces:
  - `text.rs`: `pub struct Text(Zeroizing<String>)` (`Clone`, `PartialEq`, `Eq`; `Debug` → `Text(len = N)`; serde as a plain string) with `Text::new(String) -> Text`, `as_str(&self) -> &str`, `is_empty(&self) -> bool`. `pub struct SecretText(Zeroizing<String>)` (no `Clone`/`Copy`/`PartialEq`; `Debug` → `SecretText([REDACTED])`; serde as a string) with `SecretText::new(String)`, `expose(&self) -> &str`, `len`, `is_empty`. `pub struct GatedSecret(SecretText)` with `GatedSecret::new(SecretText)`, **`pub(crate)`** `expose(&self) -> &str`, `pub fn is_empty(&self) -> bool`; `Debug` → `GatedSecret([REDACTED])`; serde as a plain string through the inner `SecretText` (hand-written impls inside the crate, so there is still no public accessor). `pub(crate) fn fold(s: &str) -> Zeroizing<String>` (NFC, then `to_lowercase`). Deserialize moves the decoded `String` in; no extra copy.
  - `item.rs`: `pub struct ItemId([u8; 16])` (`Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord`, serde; `Debug`/`Display` = 32 lowercase hex) with `ItemId::random() -> Result<ItemId, CryptoError>`, `to_hex(&self) -> String`, `from_hex(&str) -> Option<ItemId>`. `pub struct Timestamp(pub i64)` (Unix seconds; `Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord`, serde). `pub enum ItemType { Login, CryptoAddress, RecoveryPhrase, SecureNote }` (`Clone, Copy, Debug, PartialEq, Eq, Hash`, serde).
  - `pub enum ItemData { Login { username: Text, password: SecretText, urls: Vec<Text>, notes: SecretText }, CryptoAddress { chain: Text, address: SecretText, memo: SecretText, notes: SecretText }, RecoveryPhrase { phrase: GatedSecret, notes: SecretText }, SecureNote { body: SecretText } }` (serde, no `Clone`, `Debug` prints the variant name only) with `item_type(&self) -> ItemType`.
  - `pub struct Item` (fields `pub(crate)`: `id, title: Text, category: Option<CategoryId>, favourite: bool, created: Timestamp, updated: Timestamp, trashed: Option<Timestamp>, data: ItemData`; serde; no `Clone`; `Debug` → `Item { id: …, item_type: …, .. }`) with getters `id`, `title -> &str`, `category`, `favourite`, `created`, `updated`, `trashed`, `data -> &ItemData`, `item_type`.
  - `pub struct ItemInput { pub title: Text, pub category: Option<CategoryId>, pub favourite: bool, pub data: ItemData }` with `validate(&self) -> Result<(), FieldError>` and `pub(crate) fn validate_for_update(&self)` (the same, except an empty phrase is allowed and means "keep the stored phrase").
  - `pub(crate) enum PhraseRule { Required, EmptyKeeps }` and `pub(crate) fn validate_item(title: &Text, data: &ItemData, phrase: PhraseRule) -> Result<(), FieldError>`: the one implementation of the field rules. `validate`, `validate_for_update` and `VaultData::decode` (Task 5) all call it; nothing else re-implements them.
  - `pub enum Field { Title, Username, Password, Url, Notes, Chain, Address, Memo, Phrase, Body, CategoryName }`; `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum FieldError { Empty(Field), TooLong(Field), ForbiddenChar(Field), TooManyUrls, Reserved(Field) }`.
  - Constants: `MAX_ITEMS = 50_000`, `MAX_LINE_BYTES = 1024` (title, username, each URL, chain, address, memo), `MAX_SECRET_BYTES = 4096` (password, phrase), `MAX_NOTE_BYTES = 65_536` (notes, body), `MAX_URLS = 32`.
  - `category.rs`: `pub struct CategoryId(pub(crate) u32)` (`Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord`, serde); `pub struct Category` (`pub(crate) id`, `pub(crate) name: Text`; getters `id`, `name -> &str`; serde); `pub const BUILT_IN_CATEGORIES: [&str; 3] = ["Personal", "Work", "Community"]`, `pub const UNCATEGORISED: &str = "Uncategorised"`, `pub const MAX_CATEGORIES: usize = 256`, `pub const MAX_CATEGORY_NAME_CHARS: usize = 64`; `pub fn validate_category_name(name: &str) -> Result<(), FieldError>`; `pub(crate) fn name_key(name: &str) -> Zeroizing<String>` (= `fold(name.trim())`).

Rules: title must be non-empty after trim; crypto address non-empty; phrase non-empty (except in `validate_for_update`); password and body may be empty. A login may have no URLs; each URL entry present must be non-empty (`Empty(Url)`) with no leading or trailing whitespace (`ForbiddenChar(Url)`). Character rules and limits as in Security decisions (item text, limits). Values are stored as given; trimming is only for the emptiness check. Category names follow the display-field character rules and count `char`s of the name as given (no NFC) against `MAX_CATEGORY_NAME_CHARS`.

- [ ] **Step 1: Failing tests** (unit tests in each file):
  - `secret_text_debug_is_redacted` → `"SecretText([REDACTED])"`; `text_debug_shows_len_only` (`Text::new("abcd".into())` → `"Text(len = 4)"`); `gated_debug_is_redacted`.
  - `item_debug_has_no_text`: an `Item` with title `"Example Mail"` and username `"ada@example.com"`; its `Debug` contains neither.
  - `static_assertions::assert_not_impl_any!` for `SecretText`, `GatedSecret`, `ItemData`, `Item`: `Clone, Copy`.
  - `item_id_random_differs_and_hex_roundtrips` (two ids differ; `from_hex(to_hex(x)) == Some(x)`; `from_hex("zz")` is `None`).
  - `title_required` (`"  "` → `Empty(Title)`); `crypto_address_required`; `phrase_required_on_add` and `empty_phrase_allowed_on_update`.
  - `display_fields_reject_controls_and_bidi`: title with `'\u{202E}'`, `'\u{7}'`, `'\n'`, `'\u{85}'` → `ForbiddenChar(Title)`; username with `'\u{2066}'` → `ForbiddenChar(Username)`.
  - `password_allows_spaces_tabs_unicode`: `" pa\u{301}ss\tword "` validates; `"a\nb"` and `"a\0b"` → `ForbiddenChar(Password)`.
  - `notes_allow_newlines_and_tabs`; `notes_reject_nul`.
  - `length_limits_exact`: title 1024 bytes OK, 1025 → `TooLong(Title)`; password 4096/4097; notes 65 536/65 537; 32 URLs OK, 33 → `TooManyUrls`.
  - `url_rules`: no URLs OK; `"https://example.com"` OK; `""` → `Empty(Url)`; `" https://example.com"` and `"https://example.com "` → `ForbiddenChar(Url)`.
  - `category_name_rules`: `""` → `Empty(CategoryName)`; 64 chars OK, 65 → `TooLong(CategoryName)`; `"uncategorised"` and `" UNCATEGORISED "` → `Reserved(CategoryName)`; `"Work\u{202E}"` → `ForbiddenChar(CategoryName)`.
  - `name_key_folds_case_and_composition`: `name_key("Café") == name_key(" CAFE\u{301} ")`.
- [ ] **Step 2:** `cargo test -p holm-core --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement the three modules. `Text`/`SecretText` Serialize with `serialize_str`, Deserialize via `String::deserialize` then wrap. `fold` builds into `Zeroizing<String>::with_capacity(3 * s.len())` so it does not reallocate.
- [ ] **Step 4:** `cargo test -p holm-core --locked`. Expected: PASS. `cargo deny --all-features --locked check` and `cargo vet --locked` pass (serde, serde_derive).
- [ ] **Step 5:** Lesson 10: enums with data, `match`, newtypes, `derive` vs hand-written `Debug`, `char` ranges, why validation returns the field but never the value.
- [ ] **Step 6:** Commit `feat(core): item, category and wiping text types with field rules`, run `scripts/ci-local.sh`, push.

### Task 3: Password, passphrase and username generator

**Issue:** [#15](https://github.com/sunnat629/holm/issues/15)

**Files:**
- Create: `crates/holm-core/src/generator.rs`, `crates/holm-core/src/eff_large_wordlist.txt` (byte-exact copy of `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`), `NOTICE` (repo root: EFF list, CC-BY-3.0-US, source URL, SHA-256 of the file), `docs/learn/11-randomness-without-bias.md`
- Modify: `crates/holm-core/src/lib.rs`

**Interfaces:**
- Consumes: `fill_random`, `CryptoError`, `Text`, `SecretText`.
- Produces:
  - `pub struct PasswordSpec { pub length: u16, pub lowercase: bool, pub uppercase: bool, pub digits: bool, pub symbols: bool, pub avoid_lookalikes: bool, pub min_digits: u8, pub min_symbols: u8 }`, `pub struct PassphraseSpec { pub words: u8, pub separator: char, pub capitalise: bool, pub add_number: bool }`, `pub struct UsernameSpec { pub words: u8, pub digits: u8 }`. All `Clone, Copy, Debug, PartialEq, Eq`, serde. Each has `pub const DEFAULT` and `validate(&self) -> Result<(), GeneratorError>`; the first two have `entropy_bits(&self) -> f64`.
  - `PasswordSpec::DEFAULT = { 20, true, true, true, true, false, 1, 1 }`; `PassphraseSpec::DEFAULT = { 6, '-', false, false }`; `UsernameSpec::DEFAULT = { 2, 3 }`.
  - `pub fn generate_password(spec: &PasswordSpec) -> Result<SecretText, GeneratorError>`, `pub fn generate_passphrase(spec: &PassphraseSpec) -> Result<SecretText, GeneratorError>`, `pub fn generate_username(spec: &UsernameSpec) -> Result<Text, GeneratorError>`: each validates, then calls its `pub(crate) fn …_with(rng: &mut dyn RandomSource, spec)` with `OsRandom`.
  - `pub(crate) trait RandomSource { fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>; }`, `pub(crate) struct OsRandom` (calls `fill_random`), `pub(crate) fn uniform_below(rng: &mut dyn RandomSource, n: NonZeroU32) -> Result<u32, GeneratorError>`, `pub(crate) fn wordlist() -> &'static [&'static str]` (parsed once with `OnceLock` from `include_str!`).
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum GeneratorError { LengthOutOfRange, NoCharacterSets, RequiredSetDisabled, TooManyRequired, BelowEntropyFloor, WordsOutOfRange, DigitsOutOfRange, BadSeparator, Unsatisfiable, Rng }`.
  - Constants: `MIN_PASSWORD_LEN: u16 = 12`, `MAX_PASSWORD_LEN: u16 = 128`, `MIN_ENTROPY_BITS: f64 = 64.0`, `MIN_PASSPHRASE_WORDS: u8 = 6`, `MAX_PASSPHRASE_WORDS: u8 = 20`, `LOOKALIKES: &str = "0Oo1lI|"`, `SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"` (the 32 printable ASCII symbols), `WORDLIST_LEN: usize = 7776`, `MAX_ATTEMPTS: u32 = 10_000`.

Rules: password length 12–128 (`LengthOutOfRange`); at least one set (`NoCharacterSets`); a minimum for a disabled set → `RequiredSetDisabled`; `min_digits + min_symbols > length / 2` → `TooManyRequired`; `length × log2(pool) < 64` → `BelowEntropyFloor` (pool after removing look-alikes). Passphrase words 6–20, separator `' '` or ASCII punctuation (`BadSeparator`); entropy `words × log2(7776)`, plus `log2(10 × words)` with `add_number`. Username words 1–3, digits 0–6.

`uniform_below` (the algorithm the tests pin):

```rust
let bound = (1u64 << 32) / u64::from(n.get()) * u64::from(n.get());
loop {
    let mut b = [0u8; 4];
    rng.fill(&mut b).map_err(|_| GeneratorError::Rng)?;
    let x = u64::from(u32::from_le_bytes(b));
    if x < bound { return Ok((x % u64::from(n.get())) as u32); }
}
```

Password: build the pool in fixed order (lower, upper, digits, symbols, minus look-alikes); up to `MAX_ATTEMPTS` times fill a pre-allocated `Zeroizing<String>` of `length` chars, accept when the minimums hold, else `Unsatisfiable`. Passphrase: draw each word; `capitalise` upper-cases each word's first ASCII letter; `add_number` appends one random digit to one random word; join with the separator. Username: words concatenated lowercase, then the digits.

- [ ] **Step 1: Failing tests** (unit tests; a test-only `SeqSource` returns given `u32`s and a `SplitMix64Source` is seeded):
  - `uniform_below_rejects_biased_tail`: `SeqSource[u32::MAX, 5]`, `n = 3` → `Ok(2)` (the first value is rejected).
  - proptest `uniform_below_in_range` (seeded source, any `n`).
  - `defaults_exact` (the three `DEFAULT`s above) and `default_password_entropy` (`(20.0 * 94f64.log2() - entropy).abs() < 1e-9`).
  - `password_spec_rejections`: length 11 and 129 → `LengthOutOfRange`; no sets → `NoCharacterSets`; `min_digits = 1` with digits off → `RequiredSetDisabled`; length 12, 4 + 3 required → `TooManyRequired`; digits only with `min_symbols = 0`, length 12 → `BelowEntropyFloor`; digits only with `min_symbols = 0`, length 20 → OK.
  - `password_meets_spec` (200 seeded runs: exact length, only pool chars, minimums met, no look-alikes when `avoid_lookalikes`).
  - `password_chars_uniform`: seeded, 200 000 chars from the 94-char pool, chi-square statistic < 140 (df = 93).
  - `passphrase_shape` (through `passphrase_with` and the seeded source, separator `' '` so that hyphenated list words such as `t-shirt` cannot split: exactly 6 words, each in the list; the default spec gives 6 words joined by `-`; `capitalise` → each word starts uppercase; `add_number` → exactly one ASCII digit in the whole phrase); `passphrase_rejections` (5 and 21 words, separator `'a'`).
  - `username_shape` (default matches `^[a-z-]+[0-9]{3}$`), `username_rejections` (0 and 4 words, 7 digits).
  - `wordlist_integrity`: 7776 entries, all unique, each 3–9 chars of `[a-z-]`, the source lines' dice numbers run 11111…66666 in order, first `abacus`, last `zoom`.
- [ ] **Step 2:** `cargo test -p holm-core generator --locked`. Expected: FAIL.
- [ ] **Step 3:** Download the list, record its SHA-256 in `NOTICE`, check which entries contain `-` (expected a few, such as `t-shirt`), implement.
- [ ] **Step 4:** `cargo test -p holm-core generator --locked`. Expected: PASS.
- [ ] **Step 5:** Lesson 11: why `% n` is biased and rejection is not, `NonZeroU32` (an invalid input that cannot be built), `dyn Trait` as a test seam kept `pub(crate)`, `include_str!` and `OnceLock`, `f64::log2`.
- [ ] **Step 6:** Commit `feat(core): uniform password, passphrase and username generator`, run `scripts/ci-local.sh`, push.

### Task 4: Master password strength check

**Issue:** [#16](https://github.com/sunnat629/holm/issues/16)

**Files:**
- Create: `crates/holm-core/src/strength.rs` and `crates/holm-core/src/strength/` (`lists.rs`, `frequency_lists.coffee`, `matching.rs`, `keyboard.rs`, `scoring.rs`), `crates/holm-core/tests/strength_oracle.rs`, `docs/learn/12-owning-the-strength-check.md`
- Modify: root `Cargo.toml` (`zxcvbn = { version = "3", default-features = false }`, used as a holm-core dev-dependency only), `crates/holm-core/Cargo.toml`, `crates/holm-core/src/lib.rs`, `NOTICE`, `scripts/ci-local.sh` (hash gate), `docs/CRYPTO.md`, `supply-chain/*`, `fuzz/Cargo.lock`

**Interfaces:**
- Consumes: `MasterPassword::to_kdf_bytes` (NFC bytes).
- Produces: `pub const MIN_MASTER_CHARS: usize = 12; pub const MAX_MASTER_CHARS: usize = 1024; pub const MIN_MASTER_SCORE: u8 = 4;` `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct StrengthVerdict { pub score: u8, pub chars: usize, pub acceptable: bool }`; `#[derive(Debug)] pub struct StrengthReport { pub verdict: StrengthVerdict, pub warning: Option<String>, pub suggestions: Vec<String> }`; `pub fn check(password: &MasterPassword) -> StrengthReport`.

`chars` counts `char`s of the NFC form; `acceptable = score >= 4 && (12..=1024).contains(&chars)`; over 1,024 the password is refused unscored with fixed text. An empty password returns score 0. `holm` is a rank-1 context word, as zxcvbn's user inputs would make it. The report holds only Holm's fixed feedback text, never the password.

- [ ] **Step 1: Failing tests:** `empty_refused` (score 0, not acceptable); `common_password_refused` (`"password1234"` → not acceptable, score ≤ 2); `eleven_strong_chars_refused_for_length` (`"Xk#9vQ!2mLp"` → chars 11, not acceptable); `long_random_accepted` (`"q7#Vt9!mZ2@rL5$w"` → score 4, acceptable); `chars_counted_after_nfc` (twelve `"e\u{301}"` → chars 12); `report_debug_has_no_password` (the `Debug` of the report for `"q7#Vt9!mZ2@rL5$w"` does not contain it).
- [ ] **Step 2:** `cargo test -p holm-core strength --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement the in-house estimator; add zxcvbn as a dev-dependency and the oracle test; run `cargo deny --all-features --locked check` and `cargo vet --locked` (dev-only crates need only `safe-to-run`; no self-audits). `cargo tree -e normal -p holm-core` must show no zxcvbn.
- [ ] **Step 4:** `cargo test -p holm-core strength --locked`. Expected: PASS. Describe the check and its limits in CRYPTO.md.
- [ ] **Step 5:** Lesson 12: owning a small check instead of wrapping a library, `include_str!` data, `Zeroizing` scratch buffers, dynamic programming over a `&[char]`, a dev-only oracle test.
- [ ] **Step 6:** Commit `feat(core): zxcvbn master password strength check` (rework: `feat(core): in-house master password strength check`), run `scripts/ci-local.sh`, push.

### Task 5: Settings and the vault body codec

**Issue:** [#17](https://github.com/sunnat629/holm/issues/17)

**Files:**
- Create: `crates/holm-core/src/settings.rs`, `crates/holm-core/src/body.rs`, `docs/learn/13-serde-and-versioned-formats.md`
- Modify: root `Cargo.toml` (`postcard = { version = "1", default-features = false, features = ["alloc"] }`), `crates/holm-core/Cargo.toml`, `crates/holm-core/src/lib.rs`, `fuzz/Cargo.lock`, `supply-chain/*` (postcard and its deps), `deny.toml` only if a new licence is needed (with reason)

**Interfaces:**
- Consumes: Task 2 types, Task 3 specs, `SecretBuf`.
- Produces:
  - `settings.rs`: `AUTO_LOCK_MIN_SECS = 60`, `AUTO_LOCK_MAX_SECS = 3600`, `AUTO_LOCK_DEFAULT_SECS = 300`, `CLIPBOARD_MIN_SECS = 5`, `CLIPBOARD_MAX_SECS = 90`, `CLIPBOARD_DEFAULT_SECS = 30` (all `u32`). `#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)] pub struct Settings { pub auto_lock_secs: u32, pub clipboard_clear_secs: u32, pub lock_on_sleep: bool, pub password: PasswordSpec, pub passphrase: PassphraseSpec, pub username: UsernameSpec }` with `Default` (300, 30, true, the three `DEFAULT`s), `validate(&self) -> Result<(), SettingsError>`, `is_weaker_than(&self, current: &Settings) -> bool`, `pub(crate) fn clamp_to_policy(&mut self)`. `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum SettingsError { AutoLockOutOfRange, ClipboardOutOfRange, Generator(GeneratorError) }`.
  - `body.rs`: `pub const BODY_SCHEMA_VERSION: u16 = 1;` `pub struct VaultData { pub(crate) settings: Settings, pub(crate) categories: Vec<Category>, pub(crate) items: Vec<Item>, pub(crate) next_category_id: u32 }` (serde; no `Clone`; `Debug` prints counts only) with `pub fn new_default() -> VaultData`, `pub fn encode(&self) -> Result<SecretBuf, BodyError>`, `pub fn decode(plaintext: &[u8]) -> Result<VaultData, BodyError>`, `pub fn item_count(&self) -> usize`. `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum BodyError { TooShort, NewerSchema(u16), UnknownSchema(u16), Malformed, Invalid, Encode }`.

Rules: `is_weaker_than` is true if auto-lock or clipboard time grows, `lock_on_sleep` goes from true to false, or either generator `entropy_bits` falls; username changes never count. `clamp_to_policy` clamps both times into range and replaces an invalid generator spec with its `DEFAULT`. `new_default`: default settings, categories Personal=1, Work=2, Community=3, `next_category_id = 4`, no items. `encode`: measure the postcard size first (postcard's size flavor), allocate `2 + size` zeroed bytes once inside a `Zeroizing<Vec<u8>>`, write the LE version then `postcard::to_slice`, move into `SecretBuf` (no reallocation of plaintext). `decode` order: length < 2 → `TooShort`; version > 1 → `NewerSchema(v)`; version 0 → `UnknownSchema(0)`; `postcard::take_from_bytes` with leftover bytes → `Malformed`; then validate (≤ `MAX_ITEMS`, ≤ `MAX_CATEGORIES`, unique item ids, unique category ids and name keys, every category name passes `validate_category_name`, every item category exists or is `None`, every item passes `validate_item(title, data, PhraseRule::Required)` from Task 2 (no second copy of the rules), `next_category_id` greater than every id) → `Invalid`; then `clamp_to_policy`.

- [ ] **Step 1: Failing tests:**
  - settings: `defaults_exact`; `validate_ranges` (59, 3601 → `AutoLockOutOfRange`; 4, 91 → `ClipboardOutOfRange`; 60, 3600, 5, 90 OK); `weaker_table` (300→600 weaker; 600→300 not; clipboard 30→60 weaker; lock_on_sleep true→false weaker, false→true not; password length 20→16 weaker; passphrase 6→7 words not; username change not; identical not).
  - body: `default_data_exact`; `roundtrip_every_item_type` (one of each type with non-ASCII text, empty notes, a 4096-byte phrase, 32 URLs; every field equal after `decode(encode())`, phrase compared through `expose()`); `encoded_starts_with_version` (`[1, 0]`); `empty_is_too_short`; `newer_schema_refused` (`[2, 0, …]` → `NewerSchema(2)`); `schema_zero_refused`; `trailing_byte_malformed`; `every_prefix_fails_without_panic`; `huge_length_prefix_no_alloc` (version, settings bytes, then the 6-byte postcard varint for a category count of 2^40, then zero bytes to 20 bytes after the settings → `Malformed`, returns promptly); `duplicate_item_ids_invalid`; `dangling_category_invalid`; `bidi_title_invalid` (built with `pub(crate)` fields, bypassing `ItemInput`); `bidi_category_name_invalid`; `out_of_range_settings_clamped` (0 → 60 and 999 999 → 3600; clipboard 0 → 5 and 1000 → 90; password length 3 → `PasswordSpec::DEFAULT`).
- [ ] **Step 2:** `cargo test -p holm-core --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement; postcard passes deny and vet.
- [ ] **Step 4:** `cargo test -p holm-core --locked`. Expected: PASS.
- [ ] **Step 5:** Lesson 13: serde derive, a non-self-describing format, a version prefix, "decode, then validate", why trailing bytes are rejected, measuring before allocating so secrets are never copied by a growing `Vec`.
- [ ] **Step 6:** Commit `feat(core): settings and versioned postcard vault body`, run `scripts/ci-local.sh`, push.

### Task 6: Clock, throttle and idle timer

**Issue:** [#18](https://github.com/sunnat629/holm/issues/18)

**Files:**
- Create: `crates/holm-core/src/clock.rs`, `crates/holm-core/src/throttle.rs`, `docs/learn/14-time-and-saturating-maths.md`
- Modify: `crates/holm-core/src/lib.rs`

**Interfaces:**
- Consumes: `Timestamp`.
- Produces:
  - `pub trait Clock: Send { fn now_unix(&self) -> Timestamp; fn monotonic(&self) -> Duration; }`; `pub struct SystemClock` with `SystemClock::new()` (`monotonic` = `Instant` elapsed since `new`; `now_unix` from `SystemTime`, 0 before 1970). `#[cfg(test)] pub(crate) struct FakeClock` (clonable handle over `Arc` atomics) with `set_unix(i64)` and `advance(Duration)`.
  - `pub struct IdleTimer` with `new(clock: &dyn Clock)`, `touch(&mut self, clock: &dyn Clock)`, `expired(&self, clock: &dyn Clock, limit_secs: u32) -> bool` (true when the monotonic idle time or a forward wall-clock gap reaches the clamped limit, saturating; a backward wall jump is ignored).
  - `pub const FREE_FAILURES: u32 = 3; pub const MAX_DELAY_SECS: u64 = 60;` `pub fn delay_after(failures: u32) -> Duration` (0 below 3, else `min(2^(failures-2), 60)` s, no overflow). `#[derive(Debug, Default)] pub struct Throttle` (private `failures: u32`, `not_before: Option<Duration>`) with `new()`, `attempt<T, E>(&mut self, now, f: impl FnOnce() -> Result<T, E>) -> Result<T, Throttled<E>>` (refuses with `Throttled::Wait(left)` without running `f`; counts the failure before running `f`; resets only on Ok; `check`, `record_failure`, `record_success` are private), `status(&self, now: Duration) -> ThrottleStatus`. `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct ThrottleStatus { pub consecutive_failures: u32, pub retry_after: Option<Duration> }`.

- [ ] **Step 1: Failing tests:** `delay_table` (1 → 0, 2 → 0, 3 → 2 s, 4 → 4, 5 → 8, 6 → 16, 7 → 32, 8 → 60, 9 → 60, `u32::MAX` → 60); `first_three_failures_have_no_wait` (after failures 1 and 2 `check` is `Ok`); `attempt_inside_delay_refused_with_time_left` (3 failures at 10 s → `check(11 s) == Err(1 s)`, `check(12 s) == Ok`); `check_does_not_count` (failure count unchanged after a refused `check`); `success_resets`; `status_reports_failures_and_wait`; `idle_expires_at_limit` (touch at 0 → `expired(299 s, 300)` false, `expired(300 s, 300)` true); `system_clock_monotonic_never_decreases`.
- [ ] **Step 2:** `cargo test -p holm-core --locked -- throttle clock`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 14: `Duration`, `Instant` vs `SystemTime` (and why the throttle must not use wall time), `saturating_*` and `checked_*`, `Default`, a trait as a test seam, the `Send` bound.
- [ ] **Step 6:** Commit `feat(core): monotonic clock, unlock throttle and idle timer`, run `scripts/ci-local.sh`, push.

### Task 7: Vault store trait and session lifecycle

**Issue:** [#19](https://github.com/sunnat629/holm/issues/19)

**Files:**
- Create: `crates/holm-core/src/store.rs`, `crates/holm-core/src/session.rs`, `crates/holm-core/src/error.rs`, `docs/learn/15-generics-and-trait-objects.md`
- Modify: `crates/holm-core/src/lib.rs`, `crates/holm-core/src/envelope.rs` (`VaultError::OutOfMemory`; `From<CryptoError>` maps `OutOfMemory` to it), `crates/holm-crypto/src/error.rs` (`CryptoError::OutOfMemory`), `crates/holm-crypto/src/kdf.rs` (the work area is already reserved with `Vec::try_reserve_exact`; change only its failure from `CryptoError::Kdf` to `CryptoError::OutOfMemory`, and the doc comment)

**Interfaces:**
- Consumes: envelope `create`, `open`, `reseal`, `verify_password`, `VaultKeys`; Tasks 2–6.
- Produces:
  - `store.rs`: `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)] pub enum StoreError { NotFound, AlreadyExists, TooLarge, NotARegularFile, Io(std::io::ErrorKind) }`; `pub trait VaultStore { fn read(&mut self) -> Result<Vec<u8>, StoreError>; fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError>; fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError>; fn remove_stale_temps(&mut self) -> Result<usize, StoreError>; }`. The doc comments are the contract: `read` refuses a file over `MAX_FILE_LEN` before reading it; `replace` leaves the old or the new bytes after a crash at any point; `create_new` never overwrites; writes over `MAX_FILE_LEN` → `TooLarge`. `#[cfg(test)] pub(crate) struct MemStore` (`bytes: Option<Vec<u8>>`, `fail_next_write: Option<StoreError>`, `fail_temp_cleanup: bool`, `temp_cleanups: usize`).
  - `error.rs`: `#[derive(Debug, PartialEq, Eq, thiserror::Error)] pub enum CoreError { Locked, AlreadyUnlocked, NoVault, VaultExists, Vault(VaultError), Store(StoreError), Body(BodyError), Throttled { retry_after_secs: u64 }, WrongPassword, PasswordRequired, WeakPassword(StrengthVerdict), NotFound, UnknownCategory, InTrash, NotInTrash, TypeChange, NotAPhrase, CategoryNameTaken, TooManyCategories, TooManyItems, Field(FieldError), Settings(SettingsError) }` with `From` for `VaultError`, `StoreError`, `BodyError`, `FieldError`, `SettingsError`, and `From<CryptoError>` through `VaultError::from` (so `ItemId::random()?` gives `Vault(Crypto)` or `Vault(OutOfMemory)`). `Vault(WrongPasswordOrCorrupt)` displays "That password didn't open this vault. Either the password is wrong, or the file was changed or damaged."
  - `session.rs`: `pub struct Session<S: VaultStore>` (private `store: S`, `clock: Box<dyn Clock>`, `throttle: Throttle`, `open: Option<Unlocked>`; `Unlocked { keys: VaultKeys, data: VaultData, dirty: bool, idle: IdleTimer }`; `Debug` redacted). `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct LockOutcome { pub discarded_unsaved: bool }`.
  - `impl<S: VaultStore> Session<S>`: `pub fn new(store: S, clock: Box<dyn Clock>) -> Session<S>`; `pub fn create(&mut self, password: &MasterPassword, params: &KdfParams) -> Result<(), CoreError>`; `pub fn unlock(&mut self, password: &MasterPassword) -> Result<(), CoreError>`; `pub fn lock(&mut self) -> LockOutcome`; `pub fn is_unlocked(&self) -> bool`; `pub fn throttle_status(&self) -> ThrottleStatus`; `pub fn save(&mut self) -> Result<(), CoreError>`; `pub fn is_dirty(&self) -> bool`; `pub fn save_backup(&mut self, dest: &mut dyn VaultStore) -> Result<(), CoreError>`; `pub fn change_password(&mut self, current: &MasterPassword, new: &MasterPassword, params: &KdfParams) -> Result<(), CoreError>`; `pub fn note_activity(&mut self)`; `pub fn idle_expired(&self) -> bool`; `pub fn store(&self) -> &S`; `pub(crate)` helpers that Tasks 8, 9, 11 and 12 call from other modules: `check_password(&mut self, &MasterPassword) -> Result<(), CoreError>` (runs `verify_password` inside `Throttle::attempt`: refused → `Throttled`; `WrongPasswordOrCorrupt` → `WrongPassword`; any other error → `Vault(e)`; every error counts (F16); success → reset), `unlocked(&self)`, `unlocked_mut(&mut self)` (→ `Locked` when locked), `now_unix(&self) -> Timestamp` (from the clock) and `commit(&mut self) -> Result<(), CoreError>` (mark dirty, encode, `reseal`, `store.replace`, clear dirty on success). `Unlocked` and its fields are `pub(crate)`. Tasks 9, 11 and 12 add `impl Session` blocks in sibling modules (`search.rs`, `import/`, `export.rs`), so they reach state only through these helpers.

Order rules: `create` checks state, then strength (`WeakPassword`, before any Argon2 or store call), then `envelope::create` with `VaultData::new_default()`, then `store.create_new` (`AlreadyExists` → `VaultExists`). On success the session is **unlocked** and clean, with the idle timer touched and the throttle unchanged (Tasks 10 and 13 add items straight after `create`). `unlock`: state → `remove_stale_temps` → `Throttle::attempt` wrapping `read` (`NotFound` → `NoVault`) → `envelope::open` → `VaultData::decode`. Refused while waiting (`Throttled { retry_after_secs }`, rounded up) without running anything; every error counts as a failure (F16); only `Ok` resets. A `remove_stale_temps` error is discarded on purpose (cleanup must never block unlock; Security decision, durable writes): write it as an explicit `if let Err(_) = …` with a comment naming that decision, never a bare `let _`. `change_password`: `check_password(current)` → strength of `new` → `envelope::create(new, params, body)` → `store.replace` → only then swap the keys and clear the dirty flag, so a failed write leaves the old password working in memory and on disk. It does not call `envelope::rekey` (Security decision, `rekey`); say so in a comment. `save_backup`: `reseal` the data in memory (unsaved edits included), then `dest.create_new` (`AlreadyExists` → `VaultExists`), so a backup never overwrites a file; the session's own store and dirty flag are untouched. `lock` drops (wipes) the unlocked state and reports whether it was dirty.

- [ ] **Step 1: Failing tests** (in `session.rs`, `MemStore` + `FakeClock`, test password `"correct-Horse-battery-staple-EXAMPLE-9"`):
  - `create_then_unlock_roundtrip` (`is_unlocked()` and not dirty straight after `create`; then lock and unlock); `create_refuses_weak_password_before_any_work` (`"password1234"` → `WeakPassword(_)`, store still empty); `create_refuses_existing_vault` (→ `VaultExists`, bytes unchanged).
  - `unlock_wrong_password_counts_failure`; `fourth_try_inside_delay_is_throttled` (3 wrong at 0 s; 4th at 1 s → `Throttled { retry_after_secs: 1 }`, failures still 3; at 2 s a try runs); `throttle_ignores_wall_clock_jump` (unix time set back one day, monotonic +1 s → still throttled); `success_resets_throttle`; `throttle_survives_lock` (a failed `check_password` in a session, then lock and a wrong unlock → failures 2).
  - `missing_file_is_no_vault_and_not_counted`; `tampered_file_counts_as_failure`; `policy_error_not_counted` (header memory 2 097 152 → `Vault(KdfPolicy(AboveCeiling))`, failures 0); `newer_body_schema_reported` (vault sealed by `envelope::create` around body `[2, 0]` → `Body(NewerSchema(2))`).
  - `failed_save_keeps_file_and_retry_works` (`fail_next_write = Io(StorageFull)` → `save` errors, stored bytes unchanged and still open the old data, `is_dirty()`; second `save` OK, not dirty).
  - `lock_reports_unsaved_and_locks` (dirty → `discarded_unsaved: true`; then `save()` → `Locked`).
  - `change_password_rotates_and_requires_current` (wrong current → `WrongPassword`, counted; weak new → `WeakPassword`; success → lock, old password fails, new opens).
  - `change_password_write_failure_keeps_old_password`.
  - `backup_opens_with_same_password` (`save_backup` into a second `MemStore`; `envelope::open` of its bytes succeeds); `backup_never_overwrites` (a second `save_backup` into the same store → `VaultExists`, bytes unchanged).
  - `idle_expires_after_default_five_minutes`; `unlock_removes_stale_temps` (`temp_cleanups == 1`); `unlock_succeeds_when_temp_cleanup_fails` (MemStore set to fail `remove_stale_temps` → unlock still OK).
  - In holm-core `envelope.rs` tests (`VaultError` lives in holm-core, which holm-crypto cannot depend on): `out_of_memory_maps_to_vault_error` (`VaultError::from(CryptoError::OutOfMemory) == VaultError::OutOfMemory`).
- [ ] **Step 2:** `cargo test -p holm-core -p holm-crypto --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 15: generics with a trait bound (`Session<S: VaultStore>`) vs a trait object (`Box<dyn Clock>`), `Option` as a small state machine, `&mut self`, `From` + `?` into one error enum, why `change_password` swaps keys only after the write (and so cannot use `envelope::rekey`).
- [ ] **Step 6:** Commit `feat(core): vault store trait and session lifecycle`, run `scripts/ci-local.sh`, push.

### Task 8: Items, trash, categories, settings and the phrase gate

**Issue:** [#20](https://github.com/sunnat629/holm/issues/20)

**Files:**
- Create: `crates/holm-core/src/session/items.rs`, `crates/holm-core/src/session/categories.rs` (turn `session.rs` into `session/mod.rs`), `docs/learn/16-borrowing-in-practice.md`
- Modify: `crates/holm-core/src/session/mod.rs`, `crates/holm-core/src/text.rs` (the `GatedSecret` doctests)

**Interfaces:**
- Consumes: Task 7 `Session`, `commit`, `check_password`, `unlocked_mut`, `now_unix`.
- Produces for Task 11 (one implementation, no second copy): `pub(crate) fn insert_new(data: &mut VaultData, input: ItemInput, now: Timestamp) -> Result<ItemId, CoreError>` (draws `ItemId::random()`, redrawn on collision; sets `created = updated = now`; pushes) and `pub(crate) fn commit_or_undo(&mut self, undo: impl FnOnce(&mut VaultData)) -> Result<(), CoreError>` (remembers the dirty flag, calls `commit`; on `Vault(TooLargeToSave)` runs `undo` and **restores the remembered dirty flag**, never forcing it to false; any other error keeps the change and leaves the session dirty).
- Produces (`impl<S: VaultStore> Session<S>`): `item(&self, id: ItemId) -> Result<&Item, CoreError>`; `add_item(&mut self, input: ItemInput) -> Result<ItemId, CoreError>`; `update_item(&mut self, id: ItemId, input: ItemInput) -> Result<(), CoreError>`; `set_favourite(&mut self, id: ItemId, favourite: bool) -> Result<(), CoreError>`; `trash(&mut self, id: ItemId) -> Result<(), CoreError>`; `restore(&mut self, id: ItemId) -> Result<(), CoreError>`; `delete_forever(&mut self, id: ItemId) -> Result<(), CoreError>`; `empty_trash(&mut self) -> Result<usize, CoreError>`; `categories(&self) -> Result<&[Category], CoreError>`; `add_category(&mut self, name: &str) -> Result<CategoryId, CoreError>`; `rename_category(&mut self, id: CategoryId, name: &str) -> Result<(), CoreError>`; `delete_category(&mut self, id: CategoryId) -> Result<usize, CoreError>` (items moved, trashed ones included); `settings(&self) -> Result<&Settings, CoreError>`; `update_settings(&mut self, new: Settings, password: Option<&MasterPassword>) -> Result<(), CoreError>`; `reveal_phrase(&mut self, id: ItemId, password: &MasterPassword) -> Result<&str, CoreError>`.

Rules: every mutation validates, applies, then calls `commit_or_undo` with a closure that undoes its change (put back what `std::mem::replace` returned, or remove the index it pushed). After `Vault(TooLargeToSave)` the change is gone and `is_dirty()` is what it was before the call (Security decision, dirty flag); any other error keeps the change and leaves the session dirty. New items go through `insert_new`; updates set `updated` only; `trash` sets `trashed`. `update_item`: missing id → `NotFound`; trashed → `InTrash`; another type → `TypeChange`; an empty phrase keeps the stored one. `restore` and `delete_forever` need a trashed item (`NotInTrash`). An unknown `category` → `UnknownCategory`. Category names: `validate_category_name`, unique by `name_key` (`CategoryNameTaken`), at most `MAX_CATEGORIES` (`TooManyCategories`); ids from `next_category_id` (overflow → `TooManyCategories`). Built-in categories (Personal, Work, Community) can be renamed and deleted exactly like user categories (owner answer 2026-10-18, spec §7); nothing in core treats them specially after `new_default`. `update_settings`: `validate` → `Settings(_)`; if `is_weaker_than(current)`: `None` → `PasswordRequired`, `Some(pw)` → `check_password`. `reveal_phrase`: not a phrase item → `NotAPhrase`; then `check_password`; then the phrase.

- [ ] **Step 1: Failing tests:**
  - `every_type_survives_save_and_reopen` (add one of each, lock, unlock, compare every field; phrase via `reveal_phrase`).
  - `password_is_stored_byte_exact` (Review Focus): `" pa\u{301}ss\tword "` comes back with identical bytes after lock and unlock.
  - `update_rules` (`TypeChange`, `InTrash`, `NotFound`); `empty_phrase_on_update_keeps_phrase`; `update_sets_updated_not_created` (clock advanced 10 s).
  - `trash_restore_delete_forever_flow`; `delete_forever_requires_trash`; `empty_trash_counts`.
  - `deleted_forever_secret_absent_from_new_file`: a login password `"EXAMPLE-zq9-unique"` is deleted forever; `envelope::open` of the stored bytes gives a plaintext without that byte string.
  - `delete_category_moves_items_including_trashed`: a trashed item in the deleted category is restored into `None`.
  - `built_in_categories_rename_and_delete`: rename `Work` to `Office`, delete `Personal` (its items move to `None`), and both survive lock and unlock.
  - `category_names_unique` (`"work"` vs built-in `"Work"`, `"Café"` vs `"CAFE\u{301}"` → `CategoryNameTaken`); `uncategorised_is_reserved`; `category_limit` (256 OK, 257th → `TooManyCategories`); `unknown_category_rejected`.
  - `item_limit` (seed `VaultData` directly with 50 000 items; `add_item` → `TooManyItems`).
  - `oversize_change_rolled_back`: encode one login with 65 536-byte notes once to learn its size `s`; seed `n` such items directly into `VaultData` so that `MAX_BODY_LEN - encode().len() < s` (compute `n`, do not re-encode after every seed); assert `encode().len() + s > MAX_BODY_LEN`; then one more `add_item` → `Vault(TooLargeToSave)`, item count unchanged, not dirty, stored bytes unchanged.
  - `undo_keeps_earlier_unsaved_edit` (Review Focus): on the same seeded data, make one small edit with `fail_next_write = Io(StorageFull)` (session dirty), then an oversize add → `TooLargeToSave`, the small edit is still there, `is_dirty()` is still true, and `lock()` reports `discarded_unsaved: true`.
  - `weakening_settings_needs_password` (300 → 600 with `None` → `PasswordRequired`; wrong → `WrongPassword`, counted; right → OK); `strengthening_needs_no_password`; `invalid_settings_rejected` (`Settings(AutoLockOutOfRange)`).
  - `reveal_phrase_is_gated_and_throttled` (3 wrong; 4th at once → `Throttled`; right after the delay → the phrase); `reveal_on_login_is_not_a_phrase`.
  - In `text.rs`: a `compile_fail,E0624` doctest on `GatedSecret` showing that `expose()` is not callable outside the crate, and a sibling doctest that compiles (`GatedSecret::new(SecretText::new(…)).is_empty()`), so the failure comes from the private method and not from a typo (the Phase 1 `Nonce` pattern).
  - `mutations_when_locked_return_locked`.
- [ ] **Step 2:** `cargo test -p holm-core session --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command, then `cargo test -p holm-core --doc GatedSecret --locked`. Expected: PASS.
- [ ] **Step 5:** Lesson 16: returning `&str` from a `&mut self` method, `iter_mut`/`position`/`retain`, `std::mem::replace` for undo, splitting a module into a folder, `compile_fail` doctests.
- [ ] **Step 6:** Commit `feat(core): item, trash, category and settings operations with phrase gate`, run `scripts/ci-local.sh`, push.

### Task 9: Search, filter and sort

**Issue:** [#21](https://github.com/sunnat629/holm/issues/21)

**Files:**
- Create: `crates/holm-core/src/search.rs`, `docs/learn/17-iterators-and-lifetimes.md`
- Modify: `crates/holm-core/src/lib.rs`

**Interfaces:**
- Consumes: `fold`, `Session::unlocked`.
- Produces: `#[derive(Clone, Default)] pub struct Query { pub text: String, pub item_type: Option<ItemType>, pub category: CategoryFilter, pub favourites_only: bool, pub view: View, pub sort: Sort }`; `#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub enum CategoryFilter { #[default] All, Uncategorised, Only(CategoryId) }`, `pub enum View { #[default] Active, Trash }`, `pub enum Sort { #[default] TitleAsc, UpdatedDesc, CreatedDesc }` (same derives); `#[derive(Clone, Copy, PartialEq, Eq)] pub struct ItemSummary<'a> { pub id: ItemId, pub item_type: ItemType, pub title: &'a str, pub subtitle: Option<&'a str>, pub favourite: bool, pub category: Option<CategoryId>, pub created: Timestamp, pub updated: Timestamp, pub trashed: Option<Timestamp> }` with a hand-written `Debug` that prints `id`, `item_type`, `favourite`, `category`, the timestamps and only the **lengths** of `title` and `subtitle` (Global Constraint: no `Debug` prints item text); `Query` also gets a hand-written `Debug` that prints the text's length, not the text; `impl<S: VaultStore> Session<S> { pub fn search(&self, query: &Query) -> Result<Vec<ItemSummary<'_>>, CoreError> }`; `pub(crate) fn cmp_title_asc(a: &Item, b: &Item) -> Ordering` (folded title, then `id`), the one `TitleAsc` ordering that `search` and Task 12's export both use.

Rules: `fold(query.text.trim())`; empty matches all. Otherwise substring match on `fold` of the title, a login's username and each URL, a crypto item's chain, and the item's category name. Subtitle: login → username, or the first URL if the username is empty; crypto → chain; others → `None`. Sorting: `TitleAsc` through `cmp_title_asc`, `UpdatedDesc`, `CreatedDesc`; ties by `id`.

- [ ] **Step 1: Failing tests:** `matches_each_public_field` (one query per field); `never_matches_secret_fields` (`"zebra"` inside a password, notes, address, memo, phrase and note body → empty result); `case_and_composition_insensitive` (Review Focus: `"Café Login"` found by `"cafe\u{301}"` and `"CAFÉ"`); `empty_query_lists_active_only`; `trash_view_lists_trashed_only`; `filters_combine` (type + favourites + `Uncategorised`); `sort_orders_with_id_ties`; `subtitle_rules`; `summary_and_query_debug_have_no_text` (title `"Example Mail"`, username `"ada@example.com"`, query text `"secretquery"`: none appears in `format!("{:?}")`).
- [ ] **Step 2:** `cargo test -p holm-core search --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 17: a struct with a lifetime (`ItemSummary<'a>`), iterator chains, closures, `sort_by` with `Ordering::then_with`, `#[default]` on enums.
- [ ] **Step 6:** Commit `feat(core): search, filter and sort over public fields only`, run `scripts/ci-local.sh`, push.

### Task 10: holm-platform durable file store and crash tests

**Issue:** [#22](https://github.com/sunnat629/holm/issues/22)

**Files:**
- Create: `crates/holm-platform/Cargo.toml`, `crates/holm-platform/src/lib.rs`, `crates/holm-platform/src/fs_store.rs`, `crates/holm-platform/tests/fs_store.rs`, `crates/holm-platform/tests/crash.rs`, `crates/holm-platform/tests/exfat.rs`, `docs/learn/18-files-fsync-and-processes.md`
- Modify: root `Cargo.toml` (member and `holm-platform = { path = "crates/holm-platform", version = "0.0.0" }`; `tempfile = "3"` in workspace deps)

**Interfaces:**
- Consumes: `VaultStore`, `StoreError`, `MAX_FILE_LEN`, `random_array`; in tests `Session`, `SystemClock`.
- Produces: `pub struct FsStore` with `FsStore::new(path: impl Into<PathBuf>) -> FsStore`, `FsStore::with_observer(path: impl Into<PathBuf>, observer: Box<dyn FnMut(SaveStep) + Send>) -> FsStore`, `path(&self) -> &Path`, and `impl VaultStore for FsStore`. `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum SaveStep { TempCreated, TempHalfWritten, TempWritten, TempSynced, Renamed, DirSynced }` with `pub const ALL: [SaveStep; 6]` and `name(&self) -> &'static str`. `lib.rs`: `#![forbid(unsafe_code)]` plus a comment that Phase 4 moves to a per-module `allow`.

Rules (Security decision, durable writes): temp name `<file_name>.tmp-<hex of random_array::<8>()>`, opened with `create_new` and mode 0o600 on Unix; `replace` emits the steps in order (`TempHalfWritten` after writing the first `len / 2` bytes; `DirSynced` only on Unix); before writing it refuses an existing path that is a symlink or not a regular file (`NotARegularFile`). `read` uses `symlink_metadata` (missing → `NotFound`, symlink or not a file → `NotARegularFile`, longer than `MAX_FILE_LEN` → `TooLarge` before opening), then reads through `take(MAX_FILE_LEN + 1)` and checks again. `create_new` writes and syncs a temp, then `std::fs::hard_link(temp, path)`, and removes the temp in every branch: after a successful link, on `AlreadyExists` (then returns it), and before any other link error falls back to an exclusive create of `path`, write, sync; then the directory sync. Directory sync (in `replace` and `create_new`): `ErrorKind::Unsupported` counts as success; any other error fails the call (Security decision, durable writes). `remove_stale_temps` deletes only regular files (not symlinks) in the vault's directory named exactly `<file_name>.tmp-` + 16 lowercase hex digits. I/O errors become `Io(kind)` with no path.

- [ ] **Step 1: Failing tests** in `tests/fs_store.rs` (each in its own `tempfile::tempdir()`): `create_new_then_read` (and no `*.tmp-*` file is left); `create_new_refuses_existing` (bytes unchanged, no `*.tmp-*` file left); `replace_swaps_and_leaves_no_temp`; `read_refuses_oversize_without_reading` (`set_len(MAX_FILE_LEN + 1)` sparse file → `TooLarge`); `replace_refuses_oversize`; `observer_sees_steps_in_order` (Unix: all six); `stale_temp_cleanup_is_exact` (Review Focus: removes `holm.vault.tmp-0123456789abcdef`; keeps `other.vault.tmp-0123456789abcdef`, `holm.vault.tmp-XYZ`, `holm.vault.tmp-0123456789ABCDEF`, and a symlink named `holm.vault.tmp-aaaaaaaaaaaaaaaa` and its target; returns 1). Unix only: `symlinked_vault_refused` (`read` and `replace` → `NotARegularFile`, target untouched); `files_are_owner_only` (mode `& 0o777 == 0o600` after `create_new` and after `replace`); `read_only_dir_keeps_old_file` (Review Focus: dir set to 0o555 → `replace` is `Io(PermissionDenied)`, `read` returns the old bytes; restore the mode, then a second `replace` succeeds and `read` returns the new bytes; skip when running as root).
- [ ] **Step 1b: exFAT test** in `tests/exfat.rs` (Review Focus, Security decision durable writes), `#[cfg(target_os = "macos")]`; on every other OS the test prints `SKIP exfat: macOS only (needs hdiutil)` and returns. On macOS: `hdiutil create -size 32m -fs ExFAT -volname HOLMEXFAT <tempdir>/holm-exfat.dmg`, then `hdiutil attach -nobrowse -mountpoint <tempdir>/mnt <image>`; `FsStore` on `<mnt>/holm.vault`: `create_new`, `replace` twice, `read` gives the last bytes, and no `*.tmp-*` file is left; a `Session<FsStore>` creates (FLOOR), adds an item, locks and unlocks there. Always `hdiutil detach` (a drop guard), even on failure. If `hdiutil` itself is missing, print `SKIP exfat: hdiutil not found` and return; any other `hdiutil` failure fails the test.
- [ ] **Step 2: Failing crash test** in `tests/crash.rs`:
  - `child_save_then_crash`: `#[ignore]` (it is the child process, not a test of its own, so a normal run never executes it), and it panics if `HOLM_CRASH_DIR` is not set. It unlocks the vault there with `Session<FsStore>` built by `FsStore::with_observer` whose observer calls `std::process::exit(86)` when the step equals `HOLM_CRASH_STEP`, then adds a login titled `"new"`.
  - `crash_at_every_save_step_leaves_old_or_new`: for each step in `SaveStep::ALL` (skip `DirSynced` off Unix): new tempdir; create a vault (FLOOR) holding one login `"old"`; run `std::env::current_exe()` with `["child_save_then_crash", "--exact", "--ignored", "--nocapture", "--test-threads=1"]` and the two env vars; assert exit code 86; then a new `Session<FsStore>` unlocks and lists titles: `["old"]` for steps up to `TempSynced`, `["new", "old"]` (sorted) for `Renamed` and `DirSynced`; and no `*.tmp-*` file is left in the directory.
- [ ] **Step 3:** `cargo test -p holm-platform --locked`. Expected: FAIL.
- [ ] **Step 4:** Implement.
- [ ] **Step 5:** `cargo test -p holm-platform --locked`. Expected: PASS.
- [ ] **Step 6:** Lesson 18: `std::fs::OpenOptions` (`create_new`, `mode`), why write-sync-rename-sync is atomic and what each sync protects, `#[cfg(unix)]`, spawning yourself with `std::process::Command`, exit codes, why `exit` in a child is not the same as pulling the power.
- [ ] **Step 7:** Commit `feat(platform): durable FsStore with crash tests`, run `scripts/ci-local.sh`, push.

### Task 11: Import from CSV and JSON

**Issue:** [#23](https://github.com/sunnat629/holm/issues/23)

**Files:**
- Create: `crates/holm-core/src/import/mod.rs`, `crates/holm-core/src/import/csv.rs`, `crates/holm-core/src/import/json.rs`, `crates/holm-core/src/import/row.rs`, `crates/holm-core/tests/fixtures/import/{holm.csv,holm.json,chrome.csv,firefox.csv,safari.csv,spreadsheet.csv}` (fake data only), `docs/learn/19-parsing-untrusted-text.md`
- Modify: root `Cargo.toml` (`csv = "1"`; `serde_json` stays `"1"`), `crates/holm-core/Cargo.toml` (`csv`, `serde_json` as runtime deps), `crates/holm-core/src/lib.rs`, `fuzz/Cargo.lock`, `supply-chain/*` (csv and its deps; serde_json now at runtime), `deny.toml` only if a new licence is needed (with reason)

**Interfaces:**
- Consumes: `ItemInput`, `ItemData`, `Text`, `SecretText`, `GatedSecret`, `name_key`, `fold`, `Session::{unlocked, unlocked_mut, now_unix, commit_or_undo}`, `insert_new` (Task 8). Import never re-implements id drawing, insertion or rollback.
- Produces:
  - `pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024; pub const MAX_IMPORT_ROWS: usize = 50_000; pub const MAX_IMPORT_COLUMNS: usize = 64;` `pub const IMPORT_DELETE_SOURCE_WARNING: &str = "Import finished. The file you imported from is not encrypted. Delete it now, and empty your trash or recycle bin.";`
  - `pub enum ImportFormat { Csv, Json }`, `pub enum Dialect { Holm, Chrome, Firefox, Safari }` (`Clone, Copy, Debug, PartialEq, Eq`).
  - `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)] pub enum ImportError { TooLarge, NotUtf8, Empty, UnknownColumns { count: usize }, DuplicateColumn, TooManyColumns, TooManyRows, Malformed { line: u64 } }` (no message contains file content).
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum RowProblem { Field(FieldError), UnknownType, MissingAddress, MissingPhrase, EmptyRow, ExtraFields, UnusedField, BadFavourite, BadTimestamp }`; `pub struct RowIssue { pub row: usize, pub problem: RowProblem }` (same derives; `row` is the 1-based data row).
  - `pub struct ImportBatch` (private: `dialect`, `rows: Vec<ImportRow>`, `issues: Vec<RowIssue>`, `otp_ignored: usize`; `ImportRow { input: ItemInput, category_name: Option<Text>, created: Option<Timestamp>, updated: Option<Timestamp> }`; no `Clone`; `Debug` prints counts only) with `dialect()`, `ready() -> usize`, `issues() -> &[RowIssue]`, `otp_ignored() -> usize`.
  - `pub fn parse(bytes: &[u8], format: ImportFormat) -> Result<ImportBatch, ImportError>`.
  - `#[derive(Clone, Debug, PartialEq, Eq)] pub struct ImportPreview { pub dialect: Dialect, pub ready: usize, pub issues: usize, pub logins: usize, pub crypto: usize, pub phrases: usize, pub notes: usize, pub unmatched_category_rows: usize, pub duplicates: usize, pub otp_ignored: usize }`; `#[derive(Clone, Debug, PartialEq, Eq)] pub struct ImportReport { pub imported: usize, pub uncategorised: usize, pub duplicates: usize, pub skipped: usize }` (`skipped` = rows with a `RowIssue`; `duplicates` counted separately, so the summary can say how many duplicates were skipped).
  - `pub(crate) fn dedup_key(item_type, title: &str, username: &str, urls: &[&str]) -> Zeroizing<String>`: `fold` of the trimmed title, `fold` of the username (empty for non-logins) and `fold` of each URL joined by `\n` (empty for non-logins), with the item type, separated by `\0`. Built for every existing item (active or in Trash) and every ready row.
  - `impl<S: VaultStore> Session<S> { pub fn preview_import(&self, batch: &ImportBatch) -> Result<ImportPreview, CoreError>; pub fn import(&mut self, batch: ImportBatch) -> Result<ImportReport, CoreError> }`.

Rules:
- Before parsing: `> MAX_IMPORT_BYTES` → `TooLarge`; `std::str::from_utf8` failure → `NotUtf8`; strip one leading U+FEFF; blank → `Empty`.
- Header checks run in this order: more than 64 columns → `TooManyColumns` (counted first, before aliasing); then a column named twice after aliasing → `DuplicateColumn`; then dialect detection.
- Holm columns (header trimmed, case-insensitive): `title`, `username`, `password`, `url` (alias `website`), `notes`, `category`, `type`, `chain`, `address`, `memo`, `recovery` (aliases `recovery_secret`, `phrase`), plus the optional metadata columns `favourite`, `created`, `updated` that Holm's export writes (owner answer 2026-10-18).
- Metadata cells, when the column is present: `favourite` is `true`, `false` or empty (= false), else `BadFavourite`; `created` and `updated` are decimal Unix seconds (`i64`) or empty (= now), else `BadTimestamp`; `updated` earlier than `created` → `BadTimestamp`. Without the columns, `favourite = false` and `created = updated = now`.
- Dialect by header set: Firefox = exactly `url, username, password, httprealm, formactionorigin, guid, timecreated, timelastused, timepasswordchanged`; Safari = `title, url, username, password, otpauth` plus optional `notes`; Chrome = `name, url, username, password` plus optional `note`; Holm = has `title` and only known columns; otherwise `UnknownColumns { count }` of the unknown names.
- `type` values: `login`; `note`/`secure_note`; `crypto`/`crypto_address`/`cryptocurrency`; `recovery`/`recovery_phrase`/`seed` (case-insensitive); other → `UnknownType`. Empty type: recovery → phrase; else address → crypto; else password, username or url → login; else notes → secure note (body = notes); else `EmptyRow`.
- Crypto without address → `MissingAddress`; recovery without phrase → `MissingPhrase` (these run first). Then a secret column filled on a row whose type does not use it (e.g. password on a note) → `UnusedField`, never silently dropped. Then `ItemInput::validate` → `Field(e)`. `url` splits on `\n`; each part is trimmed and empty parts dropped, and only then validated (Task 2 URL rules), so a spreadsheet's `\r` or stray spaces never reach the vault and a canonical URL comes back unchanged. Secret values are never trimmed. A recovery row takes its phrase only from `recovery` (and its aliases), never from `password` or `notes`; a blank `chain` stays blank (Security decision, import).
- Duplicates: a ready row whose `dedup_key` matches an existing item or an earlier ready row of the same file is not imported and counts in `duplicates` (preview and report); it is not a `RowIssue`.
- Browser rows are logins. Title = `name`/`Title`; if empty, the URL's host (text after `://`, cut at `/`, `?` or `#`, after the last `@`, without `:port`, lowercased); if that is empty, `"Imported login"`. A non-empty Safari `OTPAuth` adds to `otp_ignored` and is not stored. Firefox's extra columns are ignored.
- CSV: `csv::ReaderBuilder` with headers, `flexible(true)`, no trimming; a row longer than the header → `ExtraFields`; shorter rows read missing cells as empty; a parse error → `Malformed { line }`; row `MAX_IMPORT_ROWS + 1` → `TooManyRows`.
- JSON: `serde_json::from_slice::<Vec<JsonRow>>`, `JsonRow` with `#[serde(deny_unknown_fields)]`, `Option<String>` fields (the metadata keys too, as strings, with the same cell rules) and the same aliases; any serde error (unknown key, duplicate key, non-string value, not an array, nesting) → `Malformed { line }`; more than `MAX_IMPORT_ROWS` → `TooManyRows`. Strings move into `Text`/`SecretText`.
- Category: matched by `name_key` against existing categories at preview/apply time; no match or empty → `None` and counted. No categories are created.
- `import`: drop duplicates first; if `item_count + remaining > MAX_ITEMS` → `TooManyItems` with nothing added; add every remaining row through `insert_new` (then set `favourite`, `created` and `updated` from the row's metadata when present); `commit_or_undo` with an undo that removes them again (dirty flag restored, Security decision dirty flag).

- [ ] **Step 1: Failing tests:**
  - `holm_csv_all_types` (fixture in the spike's shape: 4 rows, right types, `Work` and `Personal` matched to the built-ins); `columns_case_insensitive_any_order_and_aliases` (`Website`, `Recovery_Secret`).
  - `spreadsheet_quirks` (Review Focus: BOM, CRLF, quoted notes `"line one\r\nline two"` kept exactly, trailing blank line).
  - `file_level_errors`: `b"title\n\xff\n"` → `NotUtf8`; `MAX_IMPORT_BYTES + 1` bytes → `TooLarge`; `"  \n"` → `Empty`; `"title,colour"` → `UnknownColumns { count: 1 }`; `"title,url,website"` → `DuplicateColumn`; 65 columns → `TooManyColumns`; 50 001 rows → `TooManyRows`.
  - `malformed_error_has_line_not_content` (unclosed quote containing `EXAMPLE-leak` → `Malformed { line }` whose `Display` and `Debug` lack `EXAMPLE-leak`).
  - `bad_rows_skipped_and_reported`: rows with a U+202E title, crypto without address, recovery without phrase, type `"bogus"`, an extra field, and a note with a password → those `RowProblem`s at the right row numbers; other rows ready; `format!("{batch:?}")` and the issues contain no cell values.
  - `password_kept_byte_exact` (`"  sp ace\t"` in quotes).
  - `chrome_firefox_safari_detected` (Firefox title from `https://user@accounts.example.com:8443/login?x` is `accounts.example.com`; Safari row with OTPAuth → `otp_ignored == 1`, no OTP stored anywhere).
  - `json_holm_array` (same 4 items as the CSV); `json_rejections`: unknown key, duplicate key, number value, top-level object, and `"["` × 100 000 → all `Malformed`, no stack overflow.
  - `preview_counts_and_unmatched_category` (`"Gardening"` → `unmatched_category_rows == 1`; categories unchanged after `import`).
  - `url_parts_trimmed_then_validated` (`" https://a.example.com \r\nhttps://b.example.com\n\n"` → exactly the two canonical URLs).
  - `reimport_skips_duplicates` (Review Focus): import the 4-row fixture, then the same file again → second report `imported == 0`, `duplicates == 4`; a row repeated inside one file counts once as imported and once as a duplicate; `"CAFE\u{301} Login"` vs an existing `"Café Login"` with the same username and URL is a duplicate.
  - `metadata_columns_read` (`favourite = true`, `created = 1700000000`, `updated = 1700000100` land on the item; `favourite = "yes"` → `BadFavourite`; `created = "x"` and `updated < created` → `BadTimestamp`; a file without the columns gives `favourite = false`, `created = updated = now`).
  - `recovery_never_from_password` (a `type = recovery` row with only `password` filled → one `RowIssue` with `MissingPhrase`, because missing-field checks run before `UnusedField`; the password is never used as the phrase).
  - `import_is_atomic_on_item_limit`; `import_then_reopen_persists`.
- [ ] **Step 2:** `cargo test -p holm-core import --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement; csv and serde_json pass deny and vet.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 19: `str::from_utf8` and the BOM, header maps with `HashMap`, serde attributes (`alias`, `deny_unknown_fields`), mapping library errors to your own without leaking content, why a bad row is reported by number only, and why Holm departs from the old importer (no phrase from `password`/`notes`, no default `ETH` chain).
- [ ] **Step 6:** Commit `feat(core): hostile-input-safe CSV and JSON import`, run `scripts/ci-local.sh`, push.

### Task 12: Plaintext CSV export

**Issue:** [#24](https://github.com/sunnat629/holm/issues/24)

**Files:**
- Create: `crates/holm-core/src/export.rs`, `crates/holm-platform/src/private_file.rs`, `docs/learn/20-building-output-safely.md`
- Modify: `crates/holm-core/src/lib.rs`, `crates/holm-platform/src/lib.rs`

**Interfaces:**
- Consumes: `check_password`, `cmp_title_asc` (Task 9), `GatedSecret::expose` (crate-private).
- Produces:
  - `pub const EXPORT_WARNING: &str = "This file will hold every password in this vault in plain text. Anyone who can read it can use them. Save it only on an encrypted disk, do not open it in a spreadsheet app, and delete it as soon as you are done.";`
  - `pub const EXPORT_COLUMNS: [&str; 14] = ["title", "username", "password", "url", "notes", "category", "type", "chain", "address", "memo", "recovery", "favourite", "created", "updated"];` (the 11 import columns of spec §8.7, then the three metadata columns; owner answer 2026-10-18).
  - `impl<S: VaultStore> Session<S> { pub fn export_csv(&mut self, password: &MasterPassword) -> Result<SecretBuf, CoreError> }` and `pub(crate) fn write_csv(items: &[&Item], categories: &[Category]) -> SecretBuf`.
  - holm-platform: `pub fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), StoreError>` (exclusive create, so an existing file or symlink → `AlreadyExists`; mode 0o600 on Unix; `write_all`; `sync_all`).

Rules: `check_password` first. Rows: non-trashed items in `cmp_title_asc` order; every cell quoted, `"` doubled; `\r\n` after each row, header first; `type` cell `login`/`note`/`crypto`/`recovery`; a secure note's body goes in `notes`; URLs joined by `\n`; category name or empty; `favourite` is `true` or `false`; `created` and `updated` are decimal Unix seconds. Cells are written verbatim (no formula escaping). `write_csv` computes the exact length first and allocates once into the `SecretBuf`. Trash state is not exported (Trash is left out).

- [ ] **Step 1: Failing tests:** `export_needs_password_and_is_throttled` (wrong → `WrongPassword`, counted); `export_excludes_trash`; `export_header_exact` (`"\"title\",\"username\",\"password\",\"url\",\"notes\",\"category\",\"type\",\"chain\",\"address\",\"memo\",\"recovery\",\"favourite\",\"created\",\"updated\"\r\n"`); `export_quotes_everything` (a value with `"`, `,` and `\n`); `export_does_not_escape_formulas` (password `"=SUM(A1)"` verbatim); `export_import_roundtrip_all_types` (export → `parse(Csv)` → `import` into a fresh session → every field equal: title, type, username, password, the two canonical URLs, notes, chain, address, memo, the phrase via `reveal_phrase`, favourite, created and updated; the Review Focus password `" pa\u{301}ss\tword "` byte-exact; categories compared by name, using built-in categories only, because import never creates categories). Platform: `write_new_private_file_refuses_existing_and_symlink`, `write_new_private_file_is_owner_only` (Unix).
- [ ] **Step 2:** `cargo test -p holm-core -p holm-platform --locked -- export write_new_private_file`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 20: building a string with a known length, escaping rules, why measuring first keeps secrets out of freed memory, `Path` and exclusive create.
- [ ] **Step 6:** Commit `feat(core): password-gated plaintext CSV export`, run `scripts/ci-local.sh`, push.

### Task 13: Fuzzing, property tests, full round trip and docs

**Issue:** [#25](https://github.com/sunnat629/holm/issues/25)

**Files:**
- Create: `crates/holm-core/src/fuzzing.rs`, `fuzz/fuzz_targets/{open_fixed_key.rs,decode_body.rs,import_csv.rs,import_json.rs}`, `fuzz/seeds/{open_fixed_key,decode_body,import_csv,import_json}/…`, `crates/holm-core/tests/import_props.rs`, `crates/holm-platform/tests/round_trip.rs`, `docs/learn/21-fuzzing-structured-inputs.md`
- Modify: `crates/holm-core/Cargo.toml` (`[features] fuzzing = []` with a never-ship comment), `crates/holm-core/src/lib.rs`, `crates/holm-core/src/envelope.rs` (split out `pub(crate) fn create_with_kek`), `crates/holm-core/src/export.rs` (property test), `crates/holm-core/src/body.rs` (property test), `fuzz/Cargo.toml` (4 bins; `holm-core` with `features = ["fuzzing"]`), `fuzz/Cargo.lock`, `fuzz/README.md`, `scripts/ci-local.sh` (fuzz target list, and a clippy gate for the `fuzzing` feature), `docs/CRYPTO.md`, `docs/THREAT-MODEL.md`, `docs/DECISIONS.md`, `docs/tasks/BACKLOG.md`

**Interfaces:**
- Consumes: everything above.
- Produces: `pub(crate) fn create_with_kek(kek: &SecretKey, salt: [u8; 32], params: &KdfParams, body: &[u8]) -> Result<(VaultKeys, Vec<u8>), VaultError>` (`create` = validate params, size check, derive KEK, `create_with_kek`; behaviour unchanged). `#[cfg(feature = "fuzzing")] #[doc(hidden)] pub mod fuzzing { pub fn seal_with_kek(kek: &SecretKey, body_plaintext: &[u8]) -> Result<Vec<u8>, VaultError>; pub fn open_with_kek(file: &[u8], kek: &SecretKey) -> Result<VaultData, CoreError>; }` (FLOOR params and a zero salt in the header; `open_with_kek` = envelope open then `VaultData::decode`).

- [ ] **Step 1: Property tests** in `tests/import_props.rs`: `csv_never_panics` (bytes 0..4096), `csv_mutations_never_panic` (fixture bytes with 1–4 edits), `json_never_panics`; in `export.rs`: `csv_roundtrip_any_fields` (generated valid logins, crypto, notes and phrases, with canonical URLs only (Task 2 URL rules) and any favourite and timestamps → `write_csv` → `parse` → equal fields, metadata included); in `body.rs`: `body_roundtrip_any` (generated valid `VaultData` → `decode(encode())` gives equal data; spec §12 format round trips).
- [ ] **Step 2:** `cargo test -p holm-core --locked`. Expected: PASS (a panic found is a bug in Tasks 5 or 11: fix it with a regression unit test).
- [ ] **Step 3: Fuzz targets:** `open_fixed_key` (arbitrary `RawFile(Vec<u8>)` or `Sealed { body: Vec<u8>, edits: up to 4 (offset, xor) }`; sealed bodies go through `seal_with_kek` with KEK `[7; 32]` (an `Err` input is skipped, not unwrapped); then `open_with_kek`; on `Ok` with no edits, `decode(encode())` succeeds with the same item count); `decode_body` (raw bytes → `VaultData::decode`); `import_csv` and `import_json` (raw bytes → `parse`). An `#[ignore] write_fuzz_seeds` test writes encoded default and four-item bodies and sealed files; import seeds are the Task 11 fixtures. Add the four names to the `for t in …` list in `scripts/ci-local.sh`; document all seven targets and the 600 s long run before the Phase 2 security review in `fuzz/README.md`, and remove its "Deferred: open_fixed_key" line.
- [ ] **Step 4:** For each new target: `cargo +nightly-2026-10-12 fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=120`. Expected: no crash.
- [ ] **Step 5: Full round trip** `full_round_trip_on_disk` in `crates/holm-platform/tests/round_trip.rs`, on `FsStore` in a tempdir with `SystemClock`: create; add one item of each type plus a user category and a favourite; add a login whose password comes from `generate_password(&PasswordSpec::DEFAULT)`; lock; unlock; edit; trash and restore; weaken a setting with the password; change the password (FLOOR → `{131072, 3, 1}`); lock; the old password fails and the new one opens; `save_backup` to a second `FsStore` and open it in a new `Session`; `export_csv` → `write_new_private_file` → read back → `parse` → create the same user category in a new vault → `import` into it → every exported field equal (title, type, username, password, URLs, notes, chain, address, memo, phrase via `reveal_phrase`, favourite, created, updated, and category by name); import it a second time → `imported == 0`, `duplicates` equal to the item count; the vault directory holds no temps at the end (backup and export files included). Run `cargo test -p holm-platform --locked`. Expected: PASS.
- [ ] **Step 6: Docs.** `docs/CRYPTO.md`: body schema v1, the store contract and durable save, throttle, phrase gate, generator sampling, import/export rules (duplicate skipping, the metadata columns, no phrase from `password`/`notes`), and the new known gaps (csv and serde_json scratch copies; `exit` ≠ power loss; a directory sync that a volume does not support is skipped; Windows write-through, directory sync and the file lock wait for Phase 4). The zxcvbn gap is already there from Task 4; do not add it again. `scripts/ci-local.sh`: add `gate clippy-fuzzing cargo clippy -p holm-core --features fuzzing --all-targets --locked -- -D warnings` after the clippy gate, because no other gate compiles the `fuzzing` code with clippy. `docs/THREAT-MODEL.md`: the throttle slows a person at the keyboard but does nothing against a stolen file; a plaintext export or import file is outside Holm's protection. `docs/DECISIONS.md`: close "Full-open fuzzing is deferred to Phase 2"; extend the Phase 6 `--all-features` guard to `fuzzing`. `docs/tasks/BACKLOG.md`: tick the Phase 2 deferrals.
- [ ] **Step 7:** Lesson 21: fuzzing structured inputs with `arbitrary`, a Cargo feature that exposes test-only API (and why it must never ship), what an end-to-end test proves that unit tests do not.
- [ ] **Step 8:** Commit `test: fixed-key open, body and import fuzzing; full round trip`, run `scripts/ci-local.sh` (now 7 fuzz targets), push.

---

Phase 3 (`holm-cli`) gets its own plan after this one ships. It builds on `Session`, `FsStore`, the generator and `write_new_private_file`.
