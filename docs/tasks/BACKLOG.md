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
| [#21](https://github.com/sunnat629/holm/issues/21) | Search, filter and sort | 4 | `29-iterators-and-lifetimes.md` (lessons 17, 19, 20 retired) | done |
| [#22](https://github.com/sunnat629/holm/issues/22) | holm-platform durable file store and crash tests | 2 | `18-files-fsync-and-processes.md` | todo |
| [#23](https://github.com/sunnat629/holm/issues/23) | Import from CSV and JSON | 4 | `31-hostile-input-all-or-nothing.md` (lessons 17, 19, 20 retired) | done |
| [#24](https://github.com/sunnat629/holm/issues/24) | Plaintext CSV export | 4 | `32-building-output-safely.md` (lessons 17, 19, 20 retired) | done |
| [#25](https://github.com/sunnat629/holm/issues/25) | Fuzzing, property tests, full round trip and docs (2a part) | 2 | `21-fuzzing-structured-inputs.md` | todo |
| [#35](https://github.com/sunnat629/holm/issues/35) | Std-only CSV and JSON readers and the CSV writer | 4 | `30-parsing-untrusted-text.md` | done |
| [#36](https://github.com/sunnat629/holm/issues/36) | holm-cli foundation: terminal prompt, instance lock, init, list, get, gen | 4 | `33-a-cli-without-a-framework.md` | done |
| [#37](https://github.com/sunnat629/holm/issues/37) | holm-cli write commands: add, edit, rm, passwd, copy, import, export | 4 | `34-moving-secrets-in-and-out.md` | done |
| [#38](https://github.com/sunnat629/holm/issues/38) | holm shell | 4 | `35-a-read-eval-loop-with-a-deadline.md` | done |
| [#39](https://github.com/sunnat629/holm/issues/39) | GUI search, import and export; Phase 4 docs | 4 | `36-thin-screens-over-the-core.md` | done |

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

- [x] Plan Task 1 (#21, was Phase 2 Task 9): search, filter and sort. Lesson 29.
- [x] Plan Task 3 (#23, was Phase 2 Task 11): import from CSV and JSON. Lesson 31.
- [x] Plan Task 4 (#24, was Phase 2 Task 12): plaintext CSV export. Lesson 32.
- [x] The moved parts of Task 13 (#25): the `import_csv` and `import_json` fuzz targets, `tests/import_props.rs`, the `csv_roundtrip_any_fields` property test, and the export and import half of the full round trip.

## Deferred from Phase 3 (macOS walking skeleton)

From the Phase 3 plan's Deferred list and the Task 7 known gaps (`docs/CRYPTO.md`, "The macOS app (Phase 3)"). Phase 3 ships the single-instance lock and the 30 s idle warning; they are not deferred.

Phase 4

- [x] Search in the GUI (Task 9, #21). Done in Phase 4 Task 8.
- [x] Import and export in the GUI (Tasks 11 and 12, #23 and #24). Done in Phase 4 Task 8.
- [x] `holm-cli` must take the `holm.lock` single-instance lock before opening a vault (today only `holm-gui` does). Done in Phase 4 Task 5.

Phase 5 (platform hardening and GUI polish)

- Clipboard auto-clear and clear-on-lock. Until then a copied password stays on the clipboard and macOS Universal Clipboard (Handoff) can carry it to other devices; the Copy button says so.
- macOS Secure Event Input while a password field has focus.
- Vault folder owner and ACL check (today only the mode is checked).
- Paste of a copied password into a plain field (Title, Username, Web address): refuse or warn (Task 5 M1).
- Strip a foreign `Event::Paste` (Task 5 M2).
- Clear egui `TextEdit` undo memory after a lock (Task 6 M9). Covers the import and export path fields and the vault search box.
- IME preedit strings while a SecretField has focus.
- Existing vault folder that others can read (0755, the owner's has an old `harbor.vault`) is accepted and never tightened: warn or tighten.
- After a minimise lock the last vault frame stays painted and in the Dock thumbnail: paint a locked frame before the window hides (Task 6 M3).
- Clipboard clear on lock and the Universal Clipboard / Handoff exposure check (see first item).
- Crash-atomic `create_new` on FAT and exFAT (today an exclusive-create fallback).
- Keychain and Touch ID option.
- Memory locking (`mlock`).
- Password Show or reveal toggle in the CLI or the GUI: open owner decision.
- GUI clipboard auto-clear and clear-on-lock, and moving `holm-gui`'s `SystemClipboard` onto `holm_platform::clipboard` (the CLI clears already).
- Native file dialogs for import and export in the GUI: needs a new crate (`rfd`); the Phase 4 screens take a typed path.
- GUI encrypted backup button: thin GUI; the CLI has `holm export --backup`.
- Restore from Trash and empty Trash in the CLI: not in spec section 8.10's command list; the GUI trash screen is Phase 5.
- Multi-line notes and note bodies typed in the CLI: a hidden prompt reads one line; multi-line text comes in by import or the Phase 5 GUI.
- `--copy` on Linux and Windows: their clipboards need a process that stays alive; comes with the Phase 5 per-OS work.
- Windows ACLs on the plaintext export file (today 0600 on Unix only).
- Show the other item types (crypto, recovery phrase, notes) in the GUI list; today a count line only.
- Password from a file descriptor for scripts (Phase 6 at the earliest; needs an owner call).
- OS sleep, screen-lock and logout events.
- `holm shell`: lock on OS sleep, screen lock and logout (today it locks on idle, `lock` and exit only).
- P5 T7 review M8: no GUI or CLI control for the `lock_on_sleep` setting (on by default; only tests turn it off). Add a toggle with the settings screen.
- P5 T7 review M8: Phase 6 option: a background `CFRunLoop` thread in `holm shell` to hear the full OS events (screen lock with Ctrl-Cmd-Q, logout), as the GUI does. Today the shell sees a sleep (two clocks) and a user switch or the login window (the `/dev/console` owner, added in the T7 fix round) only.
- P5 T7 review M8: the shell's `/dev/console` owner check treats a read error as no change (never locks on it), and re-takes the owner at each unlock, so over SSH it watches whoever owns the screen. Revisit if a stricter rule is wanted.
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

Phase 4 parked Minors

From the Phase 4 per-task reviews, re-reviews and the final review. The final fix wave closed final I1 (with T4 M1), M1 (T6 M6), M2 (T7 M1), M3, M4 (documented in DECISIONS), the M5 wording and M8, and the T2 `Cell` Debug and `push_quoted` items. Earlier rounds closed T2 M3, T3 I1, T3 (a), T3 M4, T5 M1, T7 I1, T7 M5, T8 I1-I4, T8 M2 and T8 M9. None of these is security-load-bearing.

- T1 M1: `cmp_title_asc` re-folds both titles on every compare. Fix: fold once per item (`sort_by_cached_key` style).
- T1 M2: search `fold` is per-char lowercase, not full case folding (`STRASSE` vs `straße`, final sigma). Fix: document it, or case-fold properly.
- T1 M3: `Query.text` is a public field and `Query` is `Clone` (each clone is a wiping copy). Note only.
- T1 M4: search allocates a fresh `Zeroizing<String>` per field per item per keystroke. Fix: one scratch buffer, if it shows in profiles.
- T1 M5: `Sort::TitleAsc` wraps `cmp_title_asc` in a needless closure. Style only.
- T2 M1: a 16 MiB JSON import peaks near 182 MB RSS (about 10x input; bounded by the caps). Fix: note the bound, or consume rows as parsed.
- T2 M2: the JSON duplicate-key check is O(k^2) per object (safe at 64 keys). Fix: a doc line on `parse_json_rows` that `max_fields` must stay small.
- T2 M5: DECISIONS "Own CSV and JSON code" says both readers cap rows; `CsvReader` caps cells only, its caller caps rows. Fix: reword.
- T2 M6: `cells_allocated_once_at_final_size` asserts `capacity() == len()`, an allocator detail. Fix: `>=` plus the ptr and capacity-unchanged check.
- T3 (b): a header with no `title` reports `UnknownColumns { count: 0 }` ("0 column names Holm does not know"). Fix: own text or variant.
- T3 (c): the `data.items.truncate(start)` undo after a failed `insert_new` has no test (needs an RNG seam).
- T3 M5: imported timestamps are unbounded (`i64::MIN`/`MAX` accepted), so a file can pin items in "recently updated". Fix: clamp to `[0, now]` or refuse future dates.
- T3 M6 / final M10: the import fuzz targets run at libFuzzer's default `max_len` and never reach the column, row or cell caps. Fix: `-max_len=1048576` or seeds near the caps.
- T3 M7: `fuzz/README.md` says `.github/workflows/fuzz.yml` "does the same", but its matrix lists 3 of the 7 targets. Fix the matrix or the sentence.
- T3 M8: a max-size import is slow: `find_category` re-folds every category name per row, and `insert_new` scans ids linearly (O(n^2) at 50k). Fix: precompute category keys once per call.
- T3 M9: `generated_rows_parse_to_same_fields` uses a local `quote`, not the crate's `push_quoted` (the T4 round trip covers the writer).
- T3 M10: lesson 31 §5 leaves out that a username or URL alone infers a login and notes alone a secure note.
- T3 re-review M1: lesson 31 §5 "Duplicates follow the same rule" sentence is glued onto the "A password is never moved" line. Fix: reflow.
- T3 re-review M2: a row whose category name matches no category compares as uncategorised, so it can be a duplicate of an uncategorised item. Note only.
- T3 re-review M3: `dedup_key` now takes 5 arguments; only `key_of` calls it outside tests. Note only.
- T4 M2: `private_file::io_err` duplicates `fs_store::io_err`. Fix: make the fs_store one `pub(crate)` and reuse it.
- T4 M3: `read_capped`'s re-checks on the open handle (type swapped after `metadata`, length changed) have no direct test. Fix: a seam that swaps the path between the two checks.
- T4 M4: `read_capped`'s rustdoc does not say callers must show their own text for `TooLarge` (`StoreError`'s Display says 64 MiB and names the vault).
- T4 M5: on macOS, an inherited ACL on the parent folder can give other users read access to the 0600 export. Fix: add macOS ACL inheritance to the Phase 5 per-OS checklist.
- T4 M6: the parent folder is not fsynced after the export file is created, so a power loss can lose the file; lesson 32's snippet calls the buffer `out`, the code `text`.
- T5 M2: `gen` prints the generated password through `writeln!`, so it sits in stdout's unwiped `LineWriter` buffer. Fix: one pre-sized `Zeroizing` buffer plus `write_all`, or document it.
- T5 M3: with a deadline, a tty read of 0 bytes is treated as a poll timeout, so after a hangup the prompt spins until the deadline (in the shell the idle lock then fires). Fix: treat an early `Ok(0)` as closed.
- T5 M4: `init_refuses_weak_and_mismatched`'s "No terminal" case gets `Cancelled` (now `EndOfInput`) from an empty fake, not `NoTerminal`, and checks no message. Fix: a fake with a set error, or rename.
- T5 M5: unrequested surface: `--uncategorized`/`--favorites` aliases (not in `USAGE`), `resolve_any`, `match_reference`.
- T5 M6: `init` prints "Choose a master password…" to stdout before the terminal is opened, so with no tty the user sees it and then the error.
- T5 M7: `output.rs` `clean()` lets U+2028/U+2029 and zero-width or invisible characters (U+200B-U+200D, U+2060, U+FEFF) through (CRYPTO now says so). Fix: add them to the filter.
- T5 M8 / final M9: `--new-password=VALUE` is refused as an unknown flag, not as `PASSWORD_FLAG`, so the user is not told a password went on the command line. Fix: treat any `=value` on a prompt-only flag as `PASSWORD_FLAG`.
- T6 M1: the TCSAFLUSH typeahead fix has only the ignored manual test. Fix: a pty-based test (rustix `pty`, dev-only).
- T6 M2: arboard sets the concealed marker after the value is written, so a polling clipboard manager could record it unconcealed. Phase 6 audit, or write both types at once.
- T6 M3: `import`'s `Err(_) => ImportNotSaved` also catches errors raised before any row was added. Fix: match only save errors, map the rest to `Failed`.
- T6 M4: `write_error` is used for read-only operations (`export_csv`, `reveal_phrase`, the `passwd` current-password check), so their text talks about a change that could not be saved. Fix: a `read_error` mapper.
- T6 M5: untested paths: `edit` and `rm` on a trashed item, the `ImportNotSaved` mapping, `ClearFailed`, and the clear after `wait_for_key` errors.
- T6 (impl): `passwd` asks for the new password before verifying the current one (documented in DECISIONS). Fix: a core `verify_password` first.
- T7 M2: parsed shell `Command` strings (title, username, URLs, chain, category, paths) are plain `String`/`PathBuf`, not wiped. Optional: `Zeroizing` text fields in `AddArgs`/`EditArgs`.
- T7 M3: a clipboard-clear deadline at `holm>` drops (and wipes) a half-typed line. Fix: clear without ending the read, or document it.
- T7 M4: the shell deadlines are monotonic, so on macOS the idle lock and the clipboard clear fire late after sleep (typed lines are still checked against the wall clock). Cheap hardening: also compare `PendingClear` with `now_unix`.
- T7 M6: `cargo test -p holm-cli --locked shell` filters by name and runs 4 of the shell tests. Fix: use `--test shell` in plans and CI notes.
- T7 re-review M1: `copy.rs` `wait_for_key` is not idle-bounded; its own `until` deadline bounds it. Note only.
- T7 re-review M2: a pending clipboard clear does not wake an inner prompt; it waits up to the auto-lock time.
- T7 re-review M3: untested: the Ctrl-D discard-prompt timeout path, and the `IdleTerm::ended` branch where the caller's earlier deadline wins.
- T8 M1: the GUI export form draws the password field before the confirm tick (the CLI asks confirm, then password). Fix: move the tick above the password field.
- T8 M3: some user-visible GUI strings are not constants in `messages.rs`/`ALL` (transfer notes, `problem_text`, "And more.", headings); `OTHER_TYPES_HINT` shows literal backticks.
- T8 M4: the other-types count follows the search text, not the whole vault. Fix: count unfiltered, or say "matching".
- T8 M5: `search_cleared_on_lock` checks the rows, not that the Search field is empty after unlock.
- T8 M6: weak GUI tests: the re-import test does not assert the duplicate count or button state; `transfer_texts_hold_no_values` never asserts the Report screen and lacks the memo needles; the oversize test cannot tell which cap fired; no empty-path export case.
- T8 M7: `Transfer::Busy` has no exit if a transfer job ever comes back with `transfer: None`. Fix: reset to `None`.
- T8 M8: lesson 36 shows `pub(crate) enum Job` (code: `pub`) and asks for a test that already exists; CRYPTO says a bad import file fails "with a line number", but the GUI shows none.
- T8 re-review M1: a session already dirty from an earlier failed save plus a pre-insert import failure (for example `TooManyItems`) is shown as "added, unsaved" with a stale banner.
- T8 re-review M2: a stray `/// The central panel.` doc line sits above `show_save_banner` in `vault.rs`.
- T8 re-review M3: the ReadOnly GUI test (0o500 folder) fails when run as root.
- Final M6: the GUI import and export path is used as typed (`PathBuf::from(path.trim())`), so a relative path resolves against the app's working folder and a trailing space is trimmed. Fix: refuse relative paths with fixed text; do not trim.
- Final M7: `vault::lock_folder` creates the vault folder (0700) before the exists check, so `holm --vault /new/dir/x.vault list` creates `/new/dir` and then reports NoVault. Fix: check the folder first for every command except `init`.

Phase 6 (release)

- Clear the 206 `cargo vet` exemptions noted `gui-only, pre-release; audit or replace before Phase 6`, and renew or drop the 49 GUI `trusted` entries that end 2026-12-31.
- Code signing and notarisation (owner approval).
