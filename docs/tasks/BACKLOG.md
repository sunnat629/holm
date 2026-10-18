# Backlog

Source of truth: GitHub issues. This file mirrors them for offline reading.

| # | Task | Phase | Lesson | Status |
|---|---|---|---|---|
| [#1](https://github.com/sunnat629/holm/issues/1) | Workspace, open-source files, lesson 00 | 0 | `00-setup-and-cargo.md` | todo |
| [#2](https://github.com/sunnat629/holm/issues/2) | CI and supply-chain gates (deny, audit, vet) | 0 | `01-dependencies-and-supply-chain.md` | todo |
| [#3](https://github.com/sunnat629/holm/issues/3) | Secret types (wipe on drop, redacted Debug, NFC password) | 1 | `02-ownership-and-drop.md` | todo |
| [#4](https://github.com/sunnat629/holm/issues/4) | Errors and OS randomness | 1 | `03-errors-and-results.md` | todo |
| [#5](https://github.com/sunnat629/holm/issues/5) | Argon2id KDF with floor/ceiling policy and KATs | 1 | `04-constants-overflow-and-features.md` | todo |
| [#6](https://github.com/sunnat629/holm/issues/6) | XChaCha20-Poly1305 AEAD with Wycheproof KATs | 1 | `05-slices-and-borrowing.md` | todo |
| [#7](https://github.com/sunnat629/holm/issues/7) | Vault header format v1 (strict parser) | 1 | `06-parsing-bytes-safely.md` | todo |
| [#8](https://github.com/sunnat629/holm/issues/8) | Envelope: create, open, reseal, rekey | 1 | `07-modules-and-encapsulation.md` | todo |
| [#9](https://github.com/sunnat629/holm/issues/9) | Property tests and fuzzing | 1 | `08-property-tests-and-fuzzing.md` | todo |
| [#13](https://github.com/sunnat629/holm/issues/13) | Dependency hygiene: BLAKE2 wiping and cargo vet exemptions | 2 | `09-feature-unification-and-vet.md` | todo |
| [#14](https://github.com/sunnat629/holm/issues/14) | Text types, items and categories | 2 | `10-enums-newtypes-and-validation.md` | todo |
| [#15](https://github.com/sunnat629/holm/issues/15) | Password, passphrase and username generator | 2 | `11-randomness-without-bias.md` | todo |
| [#16](https://github.com/sunnat629/holm/issues/16) | Master password strength check (in-house, zxcvbn as test oracle) | 2 | `12-owning-the-strength-check.md` | todo |
| [#17](https://github.com/sunnat629/holm/issues/17) | Settings and the vault body codec | 2 | `13-serde-and-versioned-formats.md` | todo |
| [#18](https://github.com/sunnat629/holm/issues/18) | Clock, throttle and idle timer | 2 | `14-time-and-saturating-maths.md` | todo |
| [#19](https://github.com/sunnat629/holm/issues/19) | Vault store trait and session lifecycle | 2 | `15-generics-and-trait-objects.md` | todo |
| [#20](https://github.com/sunnat629/holm/issues/20) | Items, trash, categories, settings and the phrase gate | 2 | `16-borrowing-in-practice.md` | todo |
| [#21](https://github.com/sunnat629/holm/issues/21) | Search, filter and sort | 4 | `29-iterators-and-lifetimes.md` (lessons 17, 19, 20 retired) | todo |
| [#22](https://github.com/sunnat629/holm/issues/22) | holm-platform durable file store and crash tests | 2 | `18-files-fsync-and-processes.md` | todo |
| [#23](https://github.com/sunnat629/holm/issues/23) | Import from CSV and JSON | 4 | `31-hostile-input-all-or-nothing.md` (lessons 17, 19, 20 retired) | todo |
| [#24](https://github.com/sunnat629/holm/issues/24) | Plaintext CSV export | 4 | `32-building-output-safely.md` (lessons 17, 19, 20 retired) | todo |
| [#25](https://github.com/sunnat629/holm/issues/25) | Fuzzing, property tests, full round trip and docs (2a part) | 2 | `21-fuzzing-structured-inputs.md` | todo |
| [#35](https://github.com/sunnat629/holm/issues/35) | Std-only CSV and JSON readers and the CSV writer | 4 | `30-parsing-untrusted-text.md` | todo |
| [#36](https://github.com/sunnat629/holm/issues/36) | holm-cli foundation: terminal prompt, instance lock, init, list, get, gen | 4 | `33-a-cli-without-a-framework.md` | todo |
| [#37](https://github.com/sunnat629/holm/issues/37) | holm-cli write commands: add, edit, rm, passwd, copy, import, export | 4 | `34-moving-secrets-in-and-out.md` | todo |
| [#38](https://github.com/sunnat629/holm/issues/38) | holm shell | 4 | `35-a-read-eval-loop-with-a-deadline.md` | todo |
| [#39](https://github.com/sunnat629/holm/issues/39) | GUI search, import and export; Phase 4 docs | 4 | `36-thin-screens-over-the-core.md` | todo |

## Deferred

One line per deferral. Each names the phase or trigger that closes it. Reasons and accepted risks are in [DECISIONS.md](../DECISIONS.md).

- Re-enable GitHub Actions (3-OS CI, scheduled fuzzing). Trigger: before the repo goes public. Until then `scripts/ci-local.sh` on macOS is the merge gate.
- Enable GitHub private vulnerability reporting (needed by SECURITY.md). Trigger: before the repo goes public.
- Add Actions jobs for `oracle/` and `fuzz/`. Trigger: when Actions is re-enabled.
- Replace the cargo-deny-action download with a checksummed install. Trigger: when Actions is re-enabled.
- [x] Fixed-key full-open fuzz target. Done in Phase 2 Task 13 (#25): `open_fixed_key` and `decode_body`.
- SBOM with `cargo-cyclonedx`. Closes in Phase 6 (release work).
- `--all-features` release guard (`test-vectors` and `fuzzing` must not ship). Closes in Phase 6.
- Linux and Windows are untested until Actions returns. Trigger: Actions re-enabled.
- Upstream `chacha20` does not wipe its HChaCha20 subkey. Track an upstream issue or PR; revisit on each chacha20 bump.
- NFD stale-temp: a stale temp file left by a name that differs only by Unicode normalisation (NFD) is not found by the stale-temp sweep. Trigger: Phase 5 platform hardening.
- `mlock` for Argon2 memory and keys. Closes in the `holm-platform` phase.
- Remove the oracle-only `cargo audit` ignores (RUSTSEC-2026-0367, -0368, -0369, zip 8.6.0). Trigger: `libsodium-sys-stable` moves to zip 9.
- Optional: a separate `deny.toml` for `fuzz/` and `oracle/`. Trigger: if their dependency graphs drift from the product's.

## Phase 4 (moved from Phase 2)

Phase 2a ships the core, the durable store and the fuzzing above. These run in Phase 4 under the Phase 4 plan (lessons 17, 19 and 20 are retired), before `holm-cli`:

- Plan Task 1 (#21, was Phase 2 Task 9): search, filter and sort. Lesson 29.
- Plan Task 3 (#23, was Phase 2 Task 11): import from CSV and JSON. Lesson 31.
- Plan Task 4 (#24, was Phase 2 Task 12): plaintext CSV export. Lesson 32.
- The moved parts of Task 13 (#25): the `import_csv` and `import_json` fuzz targets, `tests/import_props.rs`, the `csv_roundtrip_any_fields` property test, and the export and import half of the full round trip.

## Deferred from Phase 3 (macOS walking skeleton)

From the Phase 3 plan's Deferred list and the Task 7 known gaps (`docs/CRYPTO.md`, "The macOS app (Phase 3)"). Phase 3 ships the single-instance lock and the 30 s idle warning; they are not deferred.

Phase 4

- Search in the GUI (Task 9, #21).
- Import and export in the GUI (Tasks 11 and 12, #23 and #24).
- `holm-cli` must take the `holm.lock` single-instance lock before opening a vault (today only `holm-gui` does).

Phase 5 (platform hardening and GUI polish)

- Clipboard auto-clear and clear-on-lock. Until then a copied password stays on the clipboard and macOS Universal Clipboard (Handoff) can carry it to other devices; the Copy button says so.
- macOS Secure Event Input while a password field has focus.
- Vault folder owner and ACL check (today only the mode is checked).
- Paste of a copied password into a plain field (Title, Username, Web address): refuse or warn (Task 5 M1).
- Strip a foreign `Event::Paste` (Task 5 M2).
- Clear egui `TextEdit` undo memory after a lock (Task 6 M9).
- IME preedit strings while a SecretField has focus.
- Existing vault folder that others can read (0755, the owner's has an old `harbor.vault`) is accepted and never tightened: warn or tighten.
- After a minimise lock the last vault frame stays painted and in the Dock thumbnail: paint a locked frame before the window hides (Task 6 M3).
- Clipboard clear on lock and the Universal Clipboard / Handoff exposure check (see first item).
- Crash-atomic `create_new` on FAT and exFAT (today an exclusive-create fallback).
- Keychain and Touch ID option.
- Memory locking (`mlock`).
- OS sleep, screen-lock and logout events.
- `holm shell`: lock on OS sleep, screen lock and logout (today it locks on idle, `lock` and exit only).
- Screen-capture exclusion (`with_content_protected`).
- Per-OS durable save.
- Windows and Linux GUI (winit `x11` and `wayland` features), and compiling the Linux and Windows builds at all (nothing compiles them while Actions is off).
- A change-password screen that handles `PasswordChangeUncertain` (the session may already hold the new keys; say so, don't just report failure).
- The three-pane layout, categories, trash, settings, generator UI and the other 16 screens.
- Recovery phrase, crypto address and secure note items; notes on logins (an edit keeps existing notes unchanged until then).
- Icons (Phosphor subset).
- Latin subsetting of the fonts.
- The spec §8.0 last-used vault path (Phase 3 uses the default path or `--vault`).
- Revealed text: drop egui's galley and AccessKit copies sooner, if egui allows it (F11).
- After a save error the new item's id is not selected: find it by comparing row ids before and after the rebuild (Task 4 M-1).
- Non-store errors (`TooManyItems`, RNG failure, `NotFound`) get the "change is open in Holm" copy though nothing was committed: give them their own text (Task 4 M-2).
- Re-hide and countdown repaint fire up to 1 s late: reuse `until_next_second` (Task 4 M-3; same for the lock warning countdown, Task 6 M8).
- Add the missing `field_error_messages_have_no_values` test and the reveal tests (not selectable, hides on leaving the item or on Edit) (Task 4 M-9, M-10).
- `char_limit(MAX_LINE_BYTES / 4)` cuts a long paste at 256 chars while the core allows 1024 bytes: drop it or size it in bytes (Task 4 M-11).
- Prompt before an open edit form is discarded by a row click or New login (Task 4 M-12).
- Manual lock drops typed, unsubmitted edits without asking: ask or note "discarded" when the form buffers are not empty (Task 6 M1).
- `record_activity` counts every event, including focus loss and AccessKit requests: count user-input events only (Task 6 M2).
- Cmd+L pressed during a running job is lost: add a pending-lock flag that `finish` honours (Task 6 M3).
- "Save and lock" saves on the UI thread, so a hung volume freezes the window and blocks the idle lock: send it through `Job::Save` with a lock-after flag (Task 6 M4).
- Error-path tests for `LockError::Io` and a failed worker spawn; `PermissionDenied` copy is shown for every EACCES (Task 3 M8, M9).
- Quitting mid-Argon2 drops the instance lock while the worker owns the session; harmless (`create_new` never overwrites), revisit with the lock work (Task 3 M10).

Phase 3 final review Minors

- m1: `O_NOFOLLOW` is wrong on riscv64 Linux (`fs_store.rs:162-171`). Fix: move riscv64 to the `0o400000` branch or return `None`.
- m2: no guard against drift between holm-platform `[lints.rust]` and `[workspace.lints.rust]`. Fix: add a ci-local grep or a test, and `#![forbid(unsafe_code)]` to holm-platform's integration tests.
- m3: the manual checklist sets `$V` only on the throwaway path. Fix: add `V="$HOME/Library/Application Support/Holm/holm.vault"` for the default route (checklist lines 73, 120, 126, 133).
- m4: `create_then_sync_fails` (holm-gui `tests/create_unlock.rs`) leaves the fake session unlocked. Fix: `session.lock()` in the fake, then unlock with `PASSWORD` and expect Vault.
- m5: no test that Escape or a backdrop click cancels the lock dialog (`vault.rs:300-303`).
- m6: two comment lines in `holm-platform/Cargo.toml` (19 and 22) run past 100 columns.
- owed: the owner's real-Mac minimise run. If it does not lock, it is Critical.

Phase 6 (release)

- Clear the 206 `cargo vet` exemptions noted `gui-only, pre-release; audit or replace before Phase 6`, and renew or drop the 49 GUI `trusted` entries that end 2026-12-31.
- Code signing and notarisation (owner approval).
