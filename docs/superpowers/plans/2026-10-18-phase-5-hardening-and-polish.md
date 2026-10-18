# Phase 5 (wave 1): hardening and polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A polished macOS app built on the owner-approved Phase 5 list:
- a press-and-hold eye on every master-password field (#40);
- all four item types in the GUI;
- native file dialogs, a backup button, and CLI restore and empty-trash;
- clipboard auto-clear everywhere from one shared piece of code;
- lock on sleep and screen lock in the GUI and in `holm shell`;
- list polish and a local, unsigned `Holm.app` with an icon;
- the docs Minors N1–N4 and the security-relevant parked Minors.

**Architecture:**
- `holm-core` stays I/O-free. It gains one pure helper, `SleepWatch`, next to `IdleTimer`.
- `holm-platform` gains two std-only modules that the CLI and the GUI now share:
  - `clip_clear`: the `Clip` trait, `clear_copied` and `PendingClear`;
  - `transfer`: reading an import file, writing exports and backups, and checking paths.
- `window.rs` (the one module allowed `unsafe`) gains the AppKit sleep, screen-lock and logout observers.
- `holm-gui` keeps `#![forbid(unsafe_code)]`. It gets the reveal eye, the item detail views for all types, `rfd` dialogs and the new lock reason.
- `holm-cli` gets `restore`, `empty-trash` and `list --trash`, and the shell gets lock on sleep.

**Tech Stack:**
- Rust 1.99.1, edition 2024; eframe/egui `=0.37.0`, egui_kittest `=0.37.0`.
- **One new crate:** `rfd`, macOS target only, `default-features = false`, pinned `=X.Y.Z` to the newest release that is at least 14 days old when Task 4 starts.
- New features on crates already in `Cargo.lock`, with no new versions:
  - `objc2-foundation =0.3.2` and `block2 =0.6.2` become direct optional dependencies of `holm-platform` under `gui-window`;
  - `objc2-app-kit` gains the `NSWorkspace` feature.
- Packaging uses only tools that ship with macOS: `sips`, `iconutil`, `plutil`, `qlmanage` and `codesign -s -`.

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md` (§3 threat model rows 45–47, §7 Trash, §8 items 2, 4, 8, 9, §9 table rows "Clipboard history hint" and "Lock on sleep / screen lock", §10, §14 Phase 5). Owner decisions: `.superpowers/sdd/2026-10-18-phase-4-search-import-export-cli/progress.md` lines 57–59 (in `holm-p4`). Doc Minors: same folder, `final-rereview.md` N1–N4. Backlog: `docs/tasks/BACKLOG.md`. Decisions: `docs/DECISIONS.md`. Gaps: `docs/CRYPTO.md`, `docs/THREAT-MODEL.md`.

## Global Constraints

**Branch and merging**
- Branch `phase-5`, cut from `main` at `a7dde73` (Phases 0–4 merged). One PR at the end.
- Nothing merges without an Opus yes on the phase.

**Security floor (binding)**
- No plaintext on disk except an export file the user asked for.
- Every secret lives in a wiping type (`SecretText`, `GatedSecret`, `MasterPassword`, `SecretBuf`, `Zeroizing`, `SecretInput`).
- No logging of secrets. Never derive `Debug` on a type that holds a secret.
- Every unlock, phrase reveal, export and password change goes through `Throttle::attempt`.

**Unsafe code**
- `holm-gui`, `holm-cli`, `holm-core` and `holm-crypto` stay `unsafe_code = "forbid"`.
- In `holm-platform`, only `src/window.rs` (feature `gui-window`) may hold `unsafe`, and every block carries a `// SAFETY:` comment.
- Each new `holm-platform` module starts with `#![forbid(unsafe_code)]`.

**Network**
- No network, ever: no crate, feature or script may open a socket or fetch anything.
- Item avatars are drawn locally and never use favicons.
- The `.app` build never downloads anything.

**Parsers and dependencies**
- Parsers stay std-only.
- `holm-core` and `holm-crypto` get no new normal dependencies: `cargo tree -p holm-core -e normal --locked` is identical before and after.

**Spec §10 limits (verbatim)**
> "Auto-lock is at most 60 minutes, with no "Never". The clipboard clears after at most 90 s. Revealed passwords hide again after 30 s and recovery phrases after 60 s. Everything revealed hides when the window loses focus and when the vault locks. Weakening a setting (longer limits, turning off lock-on-sleep) needs the master password. The window title is always "Holm"."

Use these constants, never literals:
- `REHIDE_PASSWORD_SECS` = 30 and `REHIDE_PHRASE_SECS` = 60;
- `CLIPBOARD_MIN_SECS` = 5, `CLIPBOARD_MAX_SECS` = 90, `CLIPBOARD_DEFAULT_SECS` = 30;
- `AUTO_LOCK_MIN_SECS` = 60, `AUTO_LOCK_MAX_SECS` = 3600.

**Clipboard (spec §8 item 4)**
- "auto-clear (default 30 s). It clears only if the clipboard still holds what Holm put there."
- macOS hint: `org.nspasteboard.ConcealedType`.

**Revealing secrets**
- A revealed secret is drawn read-only, straight from the wiping buffer.
- It is never put into a `TextEdit`, never selectable, and never placed in an AccessKit value.

**Vetting new dependencies**
- Each `[workspace.dependencies]` change passes `cargo deny --all-features --locked check` and `cargo vet --locked`.
- Vet order: imports first, then `cargo vet trust` only for publishers an imported set already trusts, then exemptions with the note `gui-only, pre-release; audit or replace before Phase 6`.
- Never write a Holm audit just to get past vet.
- `--locked` on every cargo command.

**Tests**
- `KdfParams::FLOOR`, tempdir vaults and fake data (`example.com`, values containing `EXAMPLE`). Binaries use `KdfParams::DEFAULT`.
- GUI tests run headless with `egui_kittest`. Every file under `crates/holm-gui/tests/` starts with `#![cfg(target_os = "macos")]`.

**Every task**
- TDD first.
- `clippy -D warnings` and `rustfmt --check` clean.
- Commit with the trailers from the COS.
- `scripts/ci-local.sh` must print `ALL GATES PASSED`, then `git push` (never force).
- GitHub Actions is never run.

**Issues and lessons**
- One GitHub issue per task, labelled `phase-5`. Task 1 is the existing #40; the COS opens the others at dispatch and lists them in `docs/tasks/BACKLOG.md`.
- Every task writes one lesson (format below) and adds its row to `docs/learn/README.md`.

**Model routing (CLAUDE.md)**
- grok writes code.
- Haiku writes lessons and doc-only edits.
- Sonnet reviews the GUI look and Tasks 8, 9 and P1–P3.
- Opus reviews Tasks 1–7 and 10 and the whole phase.
- Only Critical or Important findings block, with one fix round per task. Nits go to the final fix wave.

**Pending tasks**
- Tasks P1–P3 are **PENDING OWNER YES — do not dispatch until approved**.
- Tasks 1–10 never depend on them.

## Lesson format

Lessons go in `docs/learn/NN-topic.md`, numbered from **37** (Tasks 1–10 are 37–46; P1–P3 take 47–49 if approved). Each is under 250 lines, with these sections in this order:
1. `## Why this matters` (2–4 sentences).
2. `## What we built` (3–5 sentences).
3. `## Rust ideas in this task`: real snippets from the task's code, each with an "In Kotlin you'd write…" comparison.
4. `## Exercises`: exactly 3, each ending with the command that checks the answer.
5. `## Read next`: 1–3 links (The Rust Programming Language, std or crate docs).

No real secrets in examples.

## Security decisions

The planner proposes these to the security COS. Each becomes a line in `docs/DECISIONS.md` in the task named.

- **Hold-to-reveal (Task 1, owner decision 2026-10-18).**
  - The eye shows the typed text only while it is pressed in the current frame. No reveal flag is stored, so nothing can be left on.
  - Release, window blur and lock hide the text, because nothing draws it on the next frame.
  - The text is painted from `SecretInput` as one non-selectable galley and is never put into AccessKit.
  - Known gap: egui caches the galley briefly (CRYPTO F11).
- **One clipboard clear for every client (Task 2).**
  - The CLI, the shell and the GUI all use `holm_platform::clip_clear::clear_copied`, so "clear only if Holm's value is still there" has one implementation and one test set.
  - The GUI copies through `ConcealedClipboard`, so it gets the concealed type.
  - It clears after the vault's `clipboard_clear_secs` (clamped to 5–90), on lock and on quit.
  - The deadline is checked on both the monotonic and the wall clock, so a sleep cannot stretch it (T7 M4).
- **Typed paths must be absolute (Task 3, Final M6).** A typed import, export or backup path is used exactly as typed: it is not trimmed and must be absolute, or it is refused with fixed text. A relative path would resolve against the app's working folder, which the user cannot see.
- **Native file dialogs (Task 4).**
  - `rfd`'s blocking `FileDialog` runs on the main thread, which pauses frames while it is open. The vault view first paints one "Choosing a file…" frame with the list and detail hidden, then opens the panel.
  - When the panel returns, `tick` runs before anything is drawn, so an idle or OS lock that came due takes effect first. A path picked into a locked vault is dropped.
  - Cost: the idle lock cannot fire while the panel is open. The window behind it shows only the placeholder.
- **Lock on sleep, screen lock and logout (Task 7).**
  - The GUI observes `NSWorkspaceWillSleepNotification`, `NSWorkspaceScreensDidSleepNotification`, `NSWorkspaceSessionDidResignActiveNotification` and the distributed `com.apple.screenIsLocked`.
  - Both the GUI and the shell also run `SleepWatch`, which treats a wall-clock jump of more than 5 s past the monotonic clock as a sleep.
  - Both lock only when `lock_on_sleep` is true (the default). Turning it off is a weakening and needs the password (Settings UI is a later wave).
- **Backup and empty trash (Task 5).**
  - The encrypted backup needs no password re-entry, because it holds no plaintext.
  - `holm empty-trash` asks the user to type `empty` first.
  - `holm restore` acts only on items in Trash.
- **Ad-hoc code seal (Task 9).**
  - `codesign --sign - --force` (no identity, no Apple account) seals the local bundle, because Apple Silicon will not run an unsealed bundle.
  - This is not Phase 6 signing or notarisation. The bundle is for this Mac only.

## Deferred (not in this wave)

Task 10 moves each item into `docs/tasks/BACKLOG.md` under "Phase 5 wave 2", with its reason:
- Spec §14 Phase 5 items the owner did not list for this wave: keychain and Touch ID, `mlock`, screen-capture exclusion, per-OS durable save, Windows and Linux builds, and the per-OS checklist on real machines (owner call: wave 2 or Phase 6).
- Secure Event Input, IME preedit in secret fields, plain-field paste of a copied password, and stripping a foreign `Event::Paste` (BACKLOG Phase 5).
- Painting a locked frame before a minimise hides the window; Cmd+L pending lock; Save and lock off the UI thread; `record_activity` counting every event (BACKLOG Phase 5, Phase 3 Task 6 M1–M4).
- Creating and editing crypto, phrase and note items in the GUI, plus the Trash, Settings, Generator and change-password screens.
- A 0755 vault folder (warn or tighten), the folder owner and ACL check, crash-atomic `create_new` on FAT.
- The style-only Phase 4 parked Minors (T1 M1–M5, T2 M1/M2/M5/M6, T3 (b)/(c)/M6–M10/re-review M1–M3, T4 M2–M4, T5 M4–M6, T6 M1/M5, T7 M3/M6/re-review M1–M3, T8 M3/M5/M6/M8/re-review M2): they stay in BACKLOG.

## Review Focus

Each line names a risk and the tests that pin it:

1. **A revealed master password stays on screen.** The text must leave the screen when the pointer is released, when the pointer is dragged off the eye, when the window loses focus while the eye is held, and when an idle or sleep lock fires mid-hold. A second click must never latch it on.
   - Task 1: `eye_release_hides`, `eye_drag_off_hides`, `eye_hides_on_window_blur`, `eye_is_not_a_toggle`, `eye_hides_on_lock`.
2. **The clipboard clear goes wrong after a sleep or a change.** A copied secret must be cleared even when the Mac sleeps past the deadline. It must not be cleared when another app has since replaced the clipboard. A lock must clear it at once.
   - Task 2: `pending_clear_due_on_wall_clock_after_sleep`, `gui_copy_left_alone_when_changed`, `gui_lock_clears_clipboard_now`.
3. **The GUI reads or writes the wrong file through a typed path.** Paths with a trailing space, relative paths and a path to an existing file must be refused with fixed text before any write.
   - Task 3: `typed_path_must_be_absolute`, `typed_path_is_not_trimmed`, `export_refuses_existing_before_password`.
4. **A recovery phrase is shown or copied too easily.** It must never appear or reach the clipboard without a fresh master password. A wrong password counts against the throttle. It must hide after 60 s, on blur, on leaving the item and on lock.
   - Task 6: `phrase_needs_password_each_time`, `phrase_wrong_password_throttled`, `phrase_hides_after_60s_blur_leave_lock`.
5. **The vault stays open after sleep, screen lock or logout.** It must be locked before the next frame is drawn after wake, and the shell must lock while it is sitting at `holm>` or at any inner prompt.
   - Task 7: `os_lock_event_locks_before_draw`, `wall_jump_locks_gui`, `shell_locks_on_sleep_at_prompt`, `shell_keeps_typed_line_until_sleep_lock`.

---

### Task 1: Press-and-hold eye on every SecretInput

**Issue:** [#40](https://github.com/sunnat629/holm/issues/40)

**Files:**
- Modify:
  - `crates/holm-gui/src/widgets/secret_field.rs` (eye button, revealed paint, tests);
  - `crates/holm-gui/src/secret_input.rs` (read-only accessor);
  - `crates/holm-gui/src/screens/mod.rs` (`FieldIo::secret_field` passes `revealing` through);
  - `crates/holm-gui/src/messages.rs` (`EYE_LABEL`, added to `ALL`);
  - `docs/DECISIONS.md`;
  - `docs/learn/README.md`.
- Create:
  - `crates/holm-gui/tests/reveal.rs`;
  - `docs/learn/37-hold-to-reveal.md`.

**Interfaces:**
- Consumes: the existing `secret_field(ui, id_salt, label, buf) -> SecretFieldOutput`, `FieldIo::secret_field`, and `HolmApp::{lock, tick, show}`.
- Produces:
  - `SecretFieldOutput` gains `pub revealing: bool`.
  - `pub(crate) fn expose_for_paint(&self) -> &str` on `SecretInput`. Its only caller is the paint path in `secret_field`.
  - `pub const EYE_LABEL: &str = "Show password while held";`

Behaviour:
- The eye is an `egui::Button` inside the right end of the 280 × 30 box. The dots area shrinks to fit, and `DOTS` stays 12.
- `revealing = eye.is_pointer_button_down_on() && ui.input(|i| i.viewport().focused != Some(false))`. Holding Space while the eye has keyboard focus also counts (`eye.has_focus() && key_down(Space)`).
- While `revealing`, the box paints the text left-aligned in one line, clipped to the box, with no circles. Otherwise it paints the 12 dots exactly as today.
- Typing still goes to the buffer. The field's AccessKit node stays `PasswordInput` with the label only. The eye's node is a `Button` labelled `EYE_LABEL`.
- No state is stored anywhere.
- It applies to every caller: create (both fields), unlock, export re-entry, and the login form password field.

- [ ] **Step 1: Write the failing unit tests** in `secret_field.rs` (same harness as `dots_hide_the_length`):
  - `eye_hold_paints_text_not_dots`: buffer `"EXAMPLE-pw"`, pointer down on the eye rect. The output has 0 `Shape::Circle`, one `Shape::Text` whose galley text is `"EXAMPLE-pw"`, and `revealing == true`.
  - `eye_release_hides`: the next frame with the pointer up has 12 circles, no text shape holding `"EXAMPLE"`, and `revealing == false`.
  - `eye_drag_off_hides`: pointer pressed on the eye, then moved outside the box while still down: 12 circles.
  - `eye_is_not_a_toggle`: two full clicks, then a frame with no pointer: 12 circles.
  - `eye_hides_on_window_blur`: pointer held, `viewport().focused = Some(false)`: 12 circles.
  - `eye_label_and_role`: an AccessKit node with role `Button` and label `EYE_LABEL` exists. The `PasswordInput` node has no value.
- [ ] **Step 2: Write the failing kittest tests** in `crates/holm-gui/tests/reveal.rs`:
  - `eye_on_create_unlock_and_export`: a node labelled `EYE_LABEL` exists on Create (2), Unlock (1) and the Export form (1).
  - `eye_hides_on_lock`: hold the eye on the export password, call `HolmApp::lock(LockReason::Idle)`, run a frame. `secret_buffers_empty()` is true and no text node or shape holds `"EXAMPLE"`.
- [ ] **Step 3: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-gui --locked secret_field` and `cargo test -p holm-gui --locked --test reveal`
  - Expected: FAIL, because `revealing` and `EYE_LABEL` do not exist.
- [ ] **Step 4: Implement** the eye, `expose_for_paint` and the paint switch in `secret_field.rs`, as described in Behaviour.
- [ ] **Step 5: Run the tests and confirm they pass**
  - Run: the same two commands as Step 3.
  - Expected: PASS. The existing `dots_hide_the_length` also still passes.
- [ ] **Step 6: Record and teach**
  - Add the "Hold-to-reveal" line to DECISIONS. Add this check to `docs/manual/phase-3-macos-checklist.md`: on a real Mac, hold the eye, then press Cmd+Tab while holding, and the text is hidden.
  - Write lesson 37 "Hold to reveal": immediate mode means no stored flag, `Response::is_pointer_button_down_on`, and painting a galley versus a `TextEdit`. The Kotlin comparison is `Modifier.pointerInput { detectTapGestures(onPress = …) }`.
- [ ] **Step 7: Commit and push**
  - Commit `feat(gui): press-and-hold eye on secret fields (#40)`.
  - Run `scripts/ci-local.sh`, then push.

### Task 2: One clipboard clear for CLI, shell and GUI, plus GUI auto-clear

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `crates/holm-platform/src/clip_clear.rs` (std-only, `#![forbid(unsafe_code)]`, no feature);
  - `crates/holm-gui/tests/clipboard_clear.rs`;
  - `docs/learn/38-one-clear-for-every-client.md`.
- Modify:
  - `crates/holm-platform/src/{lib.rs,clipboard.rs}` (`ClipboardError` and `ClipCheck` move to `clip_clear` and are re-exported from `clipboard`; `ConcealedClipboard` implements `Clip` and gains `get_text`);
  - `crates/holm-cli/src/commands/copy.rs` and `crates/holm-cli/src/shell.rs` (use the shared `clear_copied` and `PendingClear`; the CLI messages stay in the CLI);
  - `crates/holm-gui/src/clipboard.rs` (`SecretClipboard: Clip + get_text`; `SystemClipboard` wraps `ConcealedClipboard`);
  - `crates/holm-gui/Cargo.toml` (drop the direct `arboard`; `holm-platform` with feature `clipboard` on macOS);
  - `crates/holm-gui/src/{app.rs,screens/vault.rs,messages.rs}`;
  - `docs/{DECISIONS.md,THREAT-MODEL.md,CRYPTO.md}`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes: `holm_core::clock::Clock`, `holm_core::item::Timestamp`, `Settings::clipboard_clear_secs`, and `CLIPBOARD_MIN_SECS`/`CLIPBOARD_MAX_SECS`.
- Produces, in `holm_platform::clip_clear`:
  - `pub enum ClipCheck { Holds, Other, Unreadable }`
  - `pub enum ClipboardError { Unavailable, Refused }` (both moved here unchanged)
  - `pub trait Clip { fn set(&mut self, text: &str) -> Result<(), ClipboardError>; fn check(&mut self, text: &str) -> ClipCheck; fn clear(&mut self); }`
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ClearOutcome { Cleared, LeftAlone, ClearedUnreadable, ClearedUnchecked, StillThere }`
  - `pub fn clear_copied(clip: &mut dyn Clip, value: &str) -> ClearOutcome`. It carries the same truth table as today's CLI `clear_copied`; `StillThere` replaces `Err(ClearFailed)`.
  - `pub struct PendingClear`. It has no `Debug`, and its fields are `value: Zeroizing<String>`, `due_mono: Duration` and `due_wall: Timestamp`. Methods:
    - `pub fn new(value: Zeroizing<String>, secs: u32, clock: &dyn Clock) -> PendingClear` clamps `secs` to 5..=90.
    - `pub fn is_due(&self, clock: &dyn Clock) -> bool` is true when **either** clock has passed its deadline.
    - `pub fn run(self, clip: &mut dyn Clip) -> ClearOutcome`.
    - `pub fn value(&self) -> &str`.
- Produces, in `holm-gui`:
  - `trait SecretClipboard: Clip { fn get_text(&mut self) -> Option<Zeroizing<String>>; }`
  - `HolmApp` holds `pending_clear: Option<PendingClear>`. It runs on `tick` when due, in `lock` before the screen changes, and from `eframe::App::on_exit`.
  - Messages: `COPIED` becomes `"Copied. Holm clears the clipboard in {n} seconds."`. Build it with a `fn copied_note(secs: u32) -> String`; no value is ever interpolated. `CLIPBOARD_CHANGED` is `"The clipboard changed, so Holm left it alone."`

- [ ] **Step 1: Write the failing tests** in `clip_clear.rs` (fake `Clip`, fake `Clock`):
  - `clear_truth_table`: the four `(before, after)` rows from today's CLI tests map to `Cleared`, `LeftAlone`, `ClearedUnreadable` and `ClearedUnchecked`. `Holds` after the clear gives `StillThere`.
  - `pending_clear_clamps_secs`: `secs` = 0 gives due at 5 s, and 600 gives due at 90 s.
  - `pending_clear_due_on_wall_clock_after_sleep`: monotonic +1 s and wall +120 s give `is_due` true.
  - `pending_clear_not_due_early`: both clocks at +29 s with secs 30 give false.
- [ ] **Step 2: Write the failing GUI tests** in `tests/clipboard_clear.rs` (fake clipboard, fake `ui_clock`):
  - `gui_copy_clears_after_vault_secs`: the vault has `clipboard_clear_secs = 30`. Copy a password, advance 29 s and the value is still there; advance to 31 s and it is gone. The note reads `copied_note(30)`.
  - `gui_copy_left_alone_when_changed`: after the copy, the fake clipboard is set to `"other"`. At 31 s it still holds `"other"`.
  - `gui_lock_clears_clipboard_now`: copy, then `lock(LockReason::Manual)`, and the clipboard is empty with no time advanced.
  - `gui_copy_uses_concealed_clipboard`: `SystemClipboard::new` is built on `ConcealedClipboard` (a compile-level test through the type).
- [ ] **Step 3: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-platform --locked clip_clear` and `cargo test -p holm-gui --locked --test clipboard_clear`
  - Expected: FAIL.
- [ ] **Step 4: Implement** `clip_clear` and move the CLI over: `copy.rs` maps `ClearOutcome` to its existing message constants and to `CliError::ClearFailed`; the shell's `PendingClear` becomes the shared one plus its `Box<dyn Clip>`. Then make the GUI changes.
- [ ] **Step 5: Run the tests and confirm they pass**
  - Run: `cargo test -p holm-platform --features clipboard --locked`, `cargo test -p holm-cli --locked`, `cargo test -p holm-gui --locked`
  - Expected: PASS, with no CLI test edited except imports.
- [ ] **Step 6: Run the dependency gates**
  - Run: `cargo vet --locked` and `cargo deny --all-features --locked check`
  - Expected: PASS. If an `arboard` entry needs more than a note change, stop and report to the COS.
- [ ] **Step 7: Update the docs and write the lesson**
  - DECISIONS: add "One clipboard clear for every client" and fix N4 (DECISIONS:89 adds "or cannot read it").
  - THREAT-MODEL: "Auto-clear (from Phase 5)" becomes present tense. The Phase 3 clipboard limit line becomes "the GUI clears after the vault's clipboard time, on lock and on quit".
  - CRYPTO: update the GUI clipboard paragraph.
  - Write lesson 38 "One clear for every client": trait objects across crates, `Zeroizing` ownership in `PendingClear::run(self)`, and two clocks. The Kotlin comparison is an interface in a shared module and `SystemClock` vs `elapsedRealtime`.
- [ ] **Step 8: Commit and push**
  - Commit `feat(platform): shared clipboard clear; GUI auto-clear and clear on lock`.
  - Run `scripts/ci-local.sh`, then push.

### Task 3: One import and export flow; typed-path rules; transfer Minors

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `crates/holm-platform/src/transfer.rs` (std-only, `#![forbid(unsafe_code)]`);
  - `docs/learn/39-one-flow-two-front-ends.md`.
- Modify:
  - `crates/holm-platform/src/lib.rs`;
  - `crates/holm-cli/src/commands/transfer.rs` (calls the shared functions; its `problem_text` and `print_preview` text unchanged);
  - `crates/holm-gui/src/{worker.rs,screens/transfer.rs,messages.rs}`;
  - `crates/holm-gui/tests/transfer.rs`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes: `read_capped`, `write_new_private_file`, `holm_core::import::{parse, ImportFormat, ImportBatch, ImportError, MAX_IMPORT_BYTES}`, `Session::{export_csv, save_backup}` and `FsStore::new`.
- Produces, in `holm_platform::transfer`:
  - `#[derive(Debug, PartialEq, Eq)] pub enum TransferError { NotFound, Exists, NotAbsolute, ReadFailed, WriteFailed, TooLarge, Import(ImportError), Core(CoreError) }`. It holds no path and no content. The GUI's `TransferFail` becomes this type.
  - `pub fn typed_path(text: &str) -> Result<PathBuf, TransferError>` refuses an empty or relative path with `NotAbsolute` and never trims.
  - `pub fn format_for(path: &Path, forced: Option<ImportFormat>) -> ImportFormat` returns JSON for a `.json` extension (case-insensitive) and CSV otherwise.
  - `pub fn read_import(path: &Path, forced: Option<ImportFormat>) -> Result<ImportBatch, TransferError>`
  - `pub fn refuse_existing(dest: &Path) -> Result<(), TransferError>` uses `symlink_metadata`.
  - `pub fn export_plain<S: VaultStore>(session: &mut Session<S>, password: &MasterPassword, dest: &Path) -> Result<usize, TransferError>` returns the item count.
  - `pub fn export_backup<S: VaultStore>(session: &mut Session<S>, dest: &Path) -> Result<(), TransferError>`
- The GUI's `preview_file` and `export_file` in `worker.rs` are deleted; `Job::Export` calls `export_plain`.
- `Job` gains `Backup { path: PathBuf }`. Its `JobKind::Backup` has `is_transfer() == true`; Task 5 adds the screen.

Minors closed here:
- Final M6 (typed path).
- T8 M1: the export form draws the confirm tick above the password field.
- T8 M7: a transfer job that comes back with `transfer: None` resets `Transfer::Busy` to `None` and shows `WORKER_LOST`.
- T6 M3: the CLI `import` maps only save errors to `ImportNotSaved`; earlier errors map to `Failed`.
- T8 re-review M1: the "added, unsaved" banner shows only if `is_dirty()` turned true during this import (compare before and after).

- [ ] **Step 1: Write the failing tests**
  - In `transfer.rs` (holm-platform), tempdir:
    - `typed_path_must_be_absolute`: `"x.csv"` and `""` give `NotAbsolute`, and `"/tmp/x.csv"` is Ok.
    - `typed_path_is_not_trimmed`: `"/tmp/x.csv "` gives a path ending in `"x.csv "`.
    - `format_by_extension`: `a.JSON` gives JSON, and `a.txt` and `a` give CSV.
    - `export_refuses_existing_before_password`: the file exists, so the result is `Exists`, `Throttle` is not touched and the file is unchanged.
    - `backup_opens_with_same_password`.
    - `errors_hold_no_path`: no `TransferError` `Debug` contains `"EXAMPLE"`.
  - In `tests/transfer.rs` (GUI):
    - `export_tick_drawn_above_password`: the tick node's rect.top is less than the password node's rect.top.
    - `busy_resets_when_transfer_missing`: a fake spawner returns `transfer: None`, and the screen leaves Busy with `WORKER_LOST`.
    - `relative_import_path_refused`: the form shows `PATH_NOT_ABSOLUTE` and no job is sent.
    - `dirty_before_import_not_reported_as_import`.
  - In the CLI tests: `import_core_error_before_rows_is_failed_not_unsaved`.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-platform --locked transfer`, `cargo test -p holm-gui --locked --test transfer`, `cargo test -p holm-cli --locked --test transfer_commands`
  - Expected: FAIL.
- [ ] **Step 3: Implement** the shared module, then move the CLI and the GUI onto it. Add `PATH_NOT_ABSOLUTE: "Type the full path, starting with /."` to `messages.rs` and `ALL`.
- [ ] **Step 4: Run the tests and confirm they pass**
  - Run: the same three commands plus `cargo test --workspace --locked`.
  - Expected: PASS.
- [ ] **Step 5: Record and teach**
  - Add the "Typed paths must be absolute" line to DECISIONS.
  - Write lesson 39 "One flow, two front ends": generic functions over `S: VaultStore`, error enums with no payload, and `symlink_metadata`. The Kotlin comparison is a shared use-case class and a sealed class of errors.
- [ ] **Step 6: Commit and push**
  - Commit `refactor: one import and export flow for CLI and GUI`.
  - Run `scripts/ci-local.sh`, then push.

### Task 4: Native file dialog for Import and Export (rfd)

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `crates/holm-gui/src/file_dialog.rs`;
  - `docs/learn/40-a-native-dialog-from-egui.md`.
- Modify:
  - `Cargo.toml` (`rfd` in `[workspace.dependencies]`);
  - `crates/holm-gui/Cargo.toml` (macOS target);
  - `crates/holm-gui/src/{lib.rs,app.rs,screens/transfer.rs,messages.rs}`;
  - `crates/holm-gui/tests/transfer.rs`;
  - `supply-chain/{config.toml,imports.lock,audits.toml}`;
  - `docs/DECISIONS.md`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes: Task 3 (`typed_path`, `TransferError`, `Job::{PreviewImport, Export, Backup}`).
- Produces:
  - `pub trait FileDialog { fn pick_import(&mut self) -> Option<PathBuf>; fn pick_save(&mut self, suggested_name: &str) -> Option<PathBuf>; }`
    - `RfdDialog` is the real one: `rfd::FileDialog::new().add_filter("CSV or JSON", &["csv", "json"]).pick_file()` and `.set_file_name(..).save_file()`.
    - `NoDialog` is the test one and returns a queued `Option<PathBuf>`.
  - `AppConfig` gains `pub file_dialog: Box<dyn FileDialog>`.
  - `Transfer` gains `Choosing(DialogKind)` with `pub enum DialogKind { Import, Export, Backup }`.

Behaviour:
- Each path form shows "Choose…" next to the typed path field, which stays and still goes through `typed_path`.
- Clicking "Choose…" sets `Transfer::Choosing(kind)` and requests a repaint.
- That frame paints only `CHOOSING_FILE` ("Choosing a file…") in the left and central panels. It hides the rows, the detail and the search box.
- The next frame calls the dialog; it blocks on the main thread.
- On return, `tick` runs first. If the vault locked, the path is dropped. Otherwise the path goes into the form's field. A save path that exists is refused at once (`refuse_existing`).
- A dialog that is cancelled returns to the form unchanged.

- [ ] **Step 1: Write the failing kittest tests** in `tests/transfer.rs`:
  - `choose_paints_placeholder_first`: after clicking Choose, the frame has no row node and no detail node, the `CHOOSING_FILE` node is present, and `NoDialog` has not been called yet.
  - `chosen_path_fills_field`: the queued `/tmp/EXAMPLE.csv` lands in the field and the preview job is sent.
  - `cancelled_dialog_keeps_form`.
  - `locked_while_choosing_drops_path`: the fake idle clock passes the limit inside `pick_import`. Afterwards the screen is Unlock and no job was sent.
  - `typed_path_still_works`.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-gui --locked --test transfer`
  - Expected: FAIL.
- [ ] **Step 3: Add `rfd` and check it**
  - In `Cargo.toml`, set `rfd = { version = "=X.Y.Z", default-features = false }`. Use the newest version at least 14 days old whose macOS backend builds with no default features.
  - Run `cargo tree -p holm-gui -e normal --locked --target aarch64-apple-darwin -i <crate>` for each crate that is new in `Cargo.lock`. Expected: no `reqwest`, `hyper`, `ureq`, `url`, `zbus`, `ashpd`, `tokio` or `async-std`.
  - If any network or async runtime crate appears, stop and report to the COS.
- [ ] **Step 4: Implement** `file_dialog.rs` and the `Choosing` flow.
- [ ] **Step 5: Run the tests and the dependency gates**
  - Run: the Step 2 command, then `cargo deny --all-features --locked check` and `cargo vet --locked`.
  - Expected: PASS. Each new exemption carries the note `gui-only, pre-release; audit or replace before Phase 6`.
- [ ] **Step 6: Record and teach**
  - DECISIONS: add "Native file dialogs" and "rfd added (gui-only)", listing the new crates.
  - Manual checklist: the dialog opens as a sheet, Cancel works, and a locked vault never shows the list behind the panel.
  - Write lesson 40: trait seams for OS dialogs, a two-frame state machine, and why blocking in `update` is allowed. The Kotlin comparison is `ActivityResultContracts.OpenDocument`.
- [ ] **Step 7: Commit and push**
  - Commit `feat(gui): native file dialogs for import and export (rfd)`.
  - Run `scripts/ci-local.sh`, then push.

### Task 5: GUI backup button; CLI restore, empty-trash and list --trash

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `crates/holm-cli/tests/trash_commands.rs`;
  - `docs/learn/41-backups-and-the-trash.md`.
- Modify:
  - `crates/holm-gui/src/screens/{vault.rs,transfer.rs}` and `messages.rs`;
  - `crates/holm-gui/tests/transfer.rs`;
  - `crates/holm-cli/src/{args.rs,lib.rs}` and `src/commands/write.rs` (`USAGE` too);
  - `docs/DECISIONS.md`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes:
  - Task 3: `export_backup`, `refuse_existing`, `Job::Backup`.
  - Task 4: `DialogKind::Backup`, `FileDialog::pick_save`.
  - `Session::{restore, empty_trash, save}` and the existing `resolve_any`.
- Produces:
  - GUI: a toolbar button "Back up…" (`BACKUP_BUTTON`) opens `Transfer::Backup(BackupForm { path: LineBuf, error: Option<&'static str> })`. On Ok it shows `BACKUP_DONE`: "Backup saved. It opens with this vault's master password."
  - CLI:
    - `Command::Restore(RefArg)` and `Command::EmptyTrash`.
    - `ListArgs` gains `pub trash: bool` (`--trash`), which sets `Query.view = View::Trash`.
    - `holm restore REF` resolves among trashed items only, then restores and saves. It prints `Restored <8-hex>.`.
    - `holm empty-trash` with N = 0 prints `Trash is empty.`. Otherwise it shows a visible prompt `Type empty to delete N items forever:`. Anything else prints `Nothing deleted.`. On `empty` it calls `empty_trash()`, saves, and prints `Deleted N items forever.`.
    - The shell runs both commands through its existing dispatch.

- [ ] **Step 1: Write the failing tests**
  - In `tests/trash_commands.rs` (FakeTerminal, tempdir):
    - `list_trash_shows_only_trashed`.
    - `restore_moves_item_back_and_saves`: after reopening, the item is active.
    - `restore_refuses_active_item`.
    - `empty_trash_needs_typed_word`: `"yes"` gives `Nothing deleted.` and the count is unchanged; `"empty"` gives `Deleted 2 items forever.` and reopening shows 0 in Trash.
    - `empty_trash_when_empty`.
    - `shell_runs_restore_and_empty_trash`.
  - In GUI `tests/transfer.rs`:
    - `backup_button_writes_encrypted_copy`: the copy opens with `PASSWORD` through `Session::unlock` and holds the same item count.
    - `backup_refuses_existing_file`.
    - `backup_holds_no_plaintext`: the file bytes do not contain `"EXAMPLE"`.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-cli --locked --test trash_commands` and `cargo test -p holm-gui --locked --test transfer`
  - Expected: FAIL.
- [ ] **Step 3: Implement** the CLI commands and the GUI backup form.
- [ ] **Step 4: Run the tests and confirm they pass**
  - Run: the same two commands, plus `cargo test -p holm-cli --locked --test shell`.
  - Expected: PASS.
- [ ] **Step 5: Record and teach**
  - Add the "Backup and empty trash" line to DECISIONS, and note that the CLI commands go beyond spec §8's list.
  - Write lesson 41: confirm-by-typing, `resolve_any` scoping, and why an encrypted copy needs no re-entry. The Kotlin comparison is a `when` over a sealed `Command`.
- [ ] **Step 6: Commit and push**
  - Commit `feat: GUI backup; CLI restore, empty-trash and list --trash`.
  - Run `scripts/ci-local.sh`, then push.

### Task 6: All item types in the GUI, each with a detail view

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `crates/holm-gui/src/screens/item_view.rs`;
  - `crates/holm-gui/tests/item_types.rs`;
  - `docs/learn/42-one-list-four-shapes.md`.
- Modify:
  - `crates/holm-gui/src/{rows.rs,worker.rs,messages.rs}` and `src/screens/{mod.rs,vault.rs}`;
  - `crates/holm-gui/tests/{items.rs,search.rs}`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes:
  - `ItemData::{Login, CryptoAddress, RecoveryPhrase, SecureNote}`, `Session::reveal_phrase(id, &pw)`, `REHIDE_PASSWORD_SECS` and `REHIDE_PHRASE_SECS`.
  - Task 1 (`secret_field` with the eye) and Task 2 (copy goes through `PendingClear`).
- Produces:
  - `ItemRow` gains `pub kind: ItemType`. `build_rows` keeps every type, with the same sort.
  - `subtitle` by type: login gives the username; crypto gives the chain, or `"Crypto address"`; phrase gives `"Recovery phrase"`; note gives `"Secure note"`.
  - `pub(crate) fn show_item(ui, item: &Item, view: &mut ItemView, io: &mut FieldIo<'_>) -> ItemAction` lives in `item_view.rs`. The login branch moves here unchanged.
  - `pub(crate) struct ItemView { revealed: Option<(RevealField, Duration)>, phrase_gate: Option<SecretInput> }` has no `Debug`. `pub(crate) enum RevealField { Password, Notes, Address, Memo, Body, Phrase }`.
  - `Job::RevealPhrase { id: ItemId, password: MasterPassword }` runs on the worker. Its result is `WorkDone.phrase: Option<SecretText>`, which is wiped when the view hides it.

Behaviour:
- Login: unchanged, plus a Reveal and Copy row for the notes.
- Crypto: the chain is shown plainly. Address, memo and notes each have a Reveal (30 s) and a Copy.
- Secure note: the body has a Reveal (30 s) that shows a multi-line read-only painted text, and a Copy.
- Recovery phrase:
  - "Reveal…" opens a `secret_field` labelled `PHRASE_PASSWORD_LABEL` and sends `Job::RevealPhrase`. A wrong password shows `WRONG_PASSWORD` and the throttle counts it.
  - On success the words show for `REHIDE_PHRASE_SECS`, with a Copy button. Copy is allowed only while revealed.
  - Every new reveal asks for the password again.
- Every reveal hides on its timer, on window blur, on selecting another item, on Edit, and on lock.
- Edit is offered for logins only. Other types show `EDIT_IN_CLI`: "Edit this item with the holm command for now."
- The other-types count line and `OTHER_TYPES_*` are removed, which closes T8 M4.

- [ ] **Step 1: Write the failing kittest tests** in `tests/item_types.rs`, using a vault seeded with one item of each type through `Session::add_item`:
  - `list_shows_all_four_types_with_subtitles`.
  - `crypto_reveal_and_copy_address`: after 31 s it is hidden.
  - `note_reveal_multiline_read_only`: no `TextEdit` node holds the body.
  - `phrase_needs_password_each_time`: reveal, wait for the hide, then reveal again and the gate is asked again.
  - `phrase_wrong_password_throttled`: after 3 wrong tries, `throttle_status().retry_after` is `Some`.
  - `phrase_hides_after_60s_blur_leave_lock`: four sub-cases.
  - `phrase_copy_only_while_revealed`.
  - `edit_hidden_for_non_login`.
  - `search_finds_non_login_by_title`.
  - `views_hold_no_secret_in_accesskit`: no AccessKit value or label holds `"EXAMPLE"` in any view.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-gui --locked --test item_types`
  - Expected: FAIL.
- [ ] **Step 3: Implement** `item_view.rs`, the row changes and `Job::RevealPhrase`.
- [ ] **Step 4: Run the tests and confirm they pass**
  - Run: `cargo test -p holm-gui --locked`
  - Expected: PASS. Existing tests that asserted the other-types line are updated to assert the rows.
- [ ] **Step 5: Write lesson 42** "One list, four shapes": exhaustive `match` on `ItemData`, a gated secret behind a worker job, and timers as `Option<Duration>`. The Kotlin comparison is `when` over a sealed class.
- [ ] **Step 6: Commit and push**
  - Commit `feat(gui): crypto, recovery phrase and note items with detail views`.
  - Run `scripts/ci-local.sh`, then push.

### Task 7: Lock on sleep, screen lock and logout (GUI and shell)

**Issue:** new, `phase-5`

**Files:**
- Modify:
  - `crates/holm-core/src/clock.rs` (`SleepWatch`);
  - `Cargo.toml` (`objc2-app-kit` features `+ "NSWorkspace"`; `objc2-foundation =0.3.2`, `default-features = false`, features `std`, `NSNotification`, `NSDistributedNotificationCenter`, `NSOperation`, `NSString`, `block2`; `block2 =0.6.2`);
  - `crates/holm-platform/Cargo.toml` (`gui-window` adds `dep:objc2-foundation` and `dep:block2`) and `src/window.rs`;
  - `crates/holm-platform/src/tty.rs` (`LineOpts.interrupt`);
  - `crates/holm-cli/src/{term.rs,shell.rs,main.rs}`;
  - `crates/holm-gui/src/{app.rs,main.rs,messages.rs}`;
  - `crates/holm-gui/tests/lock.rs` and `crates/holm-cli/tests/shell.rs`;
  - `supply-chain/*` (if needed);
  - `docs/{DECISIONS.md,THREAT-MODEL.md,CRYPTO.md}`;
  - `docs/learn/README.md`.
- Create: `docs/learn/43-listening-to-the-os.md`.

**Interfaces:**
- Consumes: `Clock`, `Settings::lock_on_sleep`, `HolmApp::lock`, the shell's `idle_lock`, and Task 2's `PendingClear`.
- Produces:
  - In `holm_core::clock`:
    - `pub const SLEEP_GAP_SECS: i64 = 5;`
    - `pub struct SleepWatch { mono: Duration, wall: Timestamp }` with `pub fn new(clock: &dyn Clock) -> SleepWatch`.
    - `pub fn slept(&self, clock: &dyn Clock) -> bool` is true when the wall clock moved more than 5 s past the monotonic clock since the mark.
    - `pub fn mark(&mut self, clock: &dyn Clock)`.
  - In `holm_platform::window`, `pub struct LockEvents` (no `Debug` needed; it holds no secret; it removes its observers on `Drop`):
    - `pub fn install() -> Option<LockEvents>` works on the main thread only and returns `None` otherwise.
    - `pub fn take(&self) -> bool` reads and resets an `Arc<AtomicBool>` that the four observers set.
  - `trait WindowState` gains `fn os_lock_event(&self) -> bool { false }`. `AppKitWindow` becomes `pub struct AppKitWindow<'a> { pub frame: &'a eframe::Frame, pub events: Option<&'a LockEvents> }`.
  - `LockReason` gains `Sleep`. `LOCKED_SLEEP` is "Holm locked because the Mac slept, the screen locked or you logged out."
  - `tick` order: a minimise lock first; then, if `os_lock_event() || sleep_watch.slept(ui_clock)` and `lock_on_sleep`, `lock(Sleep)`; then the idle lock; `mark` on every frame.
  - In `holm_platform::tty`: `LineOpts` gains `pub interrupt: Option<&'a dyn Fn() -> bool>`. While waiting, the reader polls in slices of at most 1 s and returns `Ok(None)` without discarding typed bytes from the caller's view: the shell prompt re-shows them. `wait_for_key` gets the same treatment.
  - In `holm_cli::Terminal`: `fn set_interrupt(&mut self, interrupt: Option<Box<dyn Fn() -> bool>>) {}`, a default no-op that the real terminal implements.
  - Shell: `IdleTerm` installs an interrupt closure over the shell's `SleepWatch`. On interrupt or between lines, `slept && lock_on_sleep` leads to `sleep_lock`, which clears the clipboard, locks and prints `Locked because the computer slept.` (plus `DISCARDED` when needed).

- [ ] **Step 1: Write the failing tests**
  - In `clock.rs` (fake clock):
    - `sleep_watch_detects_wall_jump`: mono +1 s and wall +60 s give true.
    - `sleep_watch_ignores_small_skew`: mono +10 s and wall +14 s give false.
    - `sleep_watch_ignores_backward_wall`.
    - `mark_resets`.
  - In GUI `tests/lock.rs` (fake `WindowState` with a settable `os_lock_event`):
    - `os_lock_event_locks_before_draw`: after the frame, the screen is Unlock, the note reason is `Sleep`, and no row node was drawn in that frame.
    - `wall_jump_locks_gui`.
    - `lock_on_sleep_false_ignores_event`.
    - `sleep_lock_clears_clipboard`.
  - In `window.rs` unit tests: `install_off_main_thread_is_none`.
  - In CLI `tests/shell.rs` (fake terminal and fake clock; the interrupt fires on the fake's next poll):
    - `shell_locks_on_sleep_at_prompt`.
    - `shell_locks_on_sleep_inside_inner_prompt`.
    - `shell_keeps_typed_line_until_sleep_lock`: the partial line is wiped on the lock and not run.
    - `shell_lock_on_sleep_false_stays_open`.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-core --locked sleep_watch`, `cargo test -p holm-gui --locked --test lock`, `cargo test -p holm-cli --locked --test shell`
  - Expected: FAIL.
- [ ] **Step 3: Implement**
  - `SleepWatch` first.
  - Then the observers in `window.rs`, using `NSWorkspace::sharedWorkspace().notificationCenter()` and `NSDistributedNotificationCenter::defaultCenter()` with `addObserverForName_object_queue_usingBlock` on `NSOperationQueue::mainQueue()`. Each `unsafe` block gets a `// SAFETY:` comment. The block captures only an `Arc<AtomicBool>`.
  - Then the GUI wiring (`main.rs` installs `LockEvents` before `run_native` and passes it to `AppKitWindow`).
  - Then the tty interrupt and the shell.
- [ ] **Step 4: Run the tests and the gates**
  - Run: the same three commands, plus `cargo test -p holm-platform --features gui-window --locked`, `cargo deny --all-features --locked check` and `cargo vet --locked`.
  - Expected: PASS, with no new crate in `Cargo.lock`.
- [ ] **Step 5: Update the docs and write the lesson**
  - DECISIONS: add "Lock on sleep, screen lock and logout".
  - THREAT-MODEL: "lock on sleep and screen lock (from Phase 5)" becomes present tense.
  - CRYPTO: note that a sleep shorter than 5 s with no notification is missed.
  - Manual checklist: sleep the lid; Ctrl-Cmd-Q; fast user switch. Each one locks both the GUI and `holm shell`.
  - Write lesson 43 "Listening to the OS": notification observers and blocks, `Arc<AtomicBool>` as a one-bit mailbox, and the two clocks. The Kotlin comparison is `BroadcastReceiver` for `ACTION_SCREEN_OFF`.
- [ ] **Step 6: Commit and push**
  - Commit `feat: lock on sleep, screen lock and logout in the GUI and holm shell`.
  - Run `scripts/ci-local.sh`, then push.

### Task 8: Item list polish: scroll bar, counts, undo memory cleared on lock

**Issue:** new, `phase-5`

**Files:**
- Modify:
  - `crates/holm-gui/src/screens/vault.rs`, `src/app.rs` and `messages.rs`;
  - `crates/holm-gui/tests/{search.rs,lock.rs}`;
  - `docs/learn/README.md`.
- Create: `docs/learn/44-the-list-and-its-memory.md`.

**Interfaces:**
- Consumes: Task 6 (`ItemRow.kind`, every type in the rows) and `HolmApp::lock`.
- Produces:
  - The list is `ScrollArea::vertical().id_salt("item-list").auto_shrink([false, false]).scroll_bar_visibility(ScrollBarVisibility::AlwaysVisible)`, and it fills the panel height above the footer.
  - The footer counts the whole vault, not the search: `fn count_line(logins: usize, others: usize, shown: Option<usize>) -> String`. It reads `"12 logins, 3 other items"`, with `", 4 shown"` added while a search is active.
  - `HolmApp::lock` calls `ctx.data_mut(|d| d.remove_by_type::<egui::text_edit::TextEditState>())`. `lock` now takes the `egui::Context`, or stores a flag that `show` applies before drawing. Pick one, and document it in the lesson.

- [ ] **Step 1: Write the failing kittest tests**
  - `list_scrolls_with_200_items`: seed 200 logins and scroll the wheel down over the list. The last title's node becomes visible and the first is off-screen.
  - `scroll_bar_is_always_drawn`: with 200 items and no hover, the list's scroll bar handle rect is non-empty.
  - `count_line_counts_vault_not_search`: 3 logins and 1 note give `"3 logins, 1 other item"`; search `"zzz"` gives `"3 logins, 1 other item, 0 shown"`.
  - `undo_memory_cleared_on_lock`: type `"EXAMPLE"` in Search and in the import path, lock, unlock, focus Search and press Cmd+Z. The field stays empty.
  - `search_field_empty_after_unlock`, which closes T8 M5.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test -p holm-gui --locked --test search` and `cargo test -p holm-gui --locked --test lock`
  - Expected: FAIL.
- [ ] **Step 3: Implement.** Plural rules: `1 login` / `2 logins`, `1 other item` / `2 other items`.
- [ ] **Step 4: Run the tests and confirm they pass**
  - Run: the same two commands.
  - Expected: PASS.
- [ ] **Step 5: Write lesson 44** "The list and its memory": egui's `IdTypeMap`, `ScrollArea` options and why undo history is a copy of typed text. The Kotlin comparison is `rememberSaveable` state outliving a screen.
- [ ] **Step 6: Commit and push**
  - Commit `feat(gui): visible scroll bar, vault counts, clear undo memory on lock`.
  - Run `scripts/ci-local.sh`, then push.

### Task 9: Holm.app bundle with an app icon (unsigned, local)

**Issue:** new, `phase-5`

**Files:**
- Create:
  - `packaging/macos/Info.plist.in`;
  - `packaging/macos/holm-icon.svg` (hand-written, flat: a rounded square with a geometric "H", in the app's two theme colours; no font, no external reference);
  - `packaging/macos/holm-icon-1024.png` (rendered once from the SVG, committed);
  - `scripts/make-icns.sh`;
  - `scripts/bundle-macos.sh`;
  - `docs/learn/45-shipping-a-mac-app-by-hand.md`.
- Modify:
  - `scripts/ci-local.sh` (adds the gate `bundle-macos.sh --check`);
  - `.gitignore` (`target/` already covers the output);
  - `docs/manual/phase-3-macos-checklist.md`;
  - `docs/learn/README.md`.

**Interfaces:**
- Consumes: the `holm-gui` binary from `cargo build --release --locked -p holm-gui`.
- Produces:
  - `scripts/make-icns.sh` turns `holm-icon-1024.png` into `target/bundle/Holm.icns`. It uses `sips -z` for 16, 32, 64, 128, 256, 512 and 1024 plus the @2x pairs, then `iconutil -c icns`.
    - The header comment records how the PNG was made: `qlmanage -t -s 1024 -o . holm-icon.svg`.
  - `scripts/bundle-macos.sh [--check]` builds the release binary and lays out `target/bundle/Holm.app/Contents/{MacOS/Holm, Resources/Holm.icns, Info.plist}`. It then runs `plutil -lint` and `codesign --sign - --force --timestamp=none target/bundle/Holm.app`.
    - With `--check`, it only lints the template and checks the PNG is 1024×1024 (`sips -g pixelWidth -g pixelHeight`), so CI stays fast.
  - Info.plist keys:
    - `CFBundleName` Holm, `CFBundleDisplayName` Holm, `CFBundleExecutable` Holm;
    - `CFBundleIdentifier` `io.github.sunnat629.holm`;
    - `CFBundleShortVersionString` and `CFBundleVersion` from `holm-gui`'s Cargo version (`cargo metadata --no-deps --format-version 1 --locked`, parsed with `plutil`-safe `sed`);
    - `CFBundleIconFile` Holm, `LSMinimumSystemVersion` 11.0, `NSHighResolutionCapable` true;
    - `LSApplicationCategoryType` `public.app-category.utilities`.
  - No network calls: the script uses no `curl`, `wget`, `git` or `cargo install`.

- [ ] **Step 1: Write the failing check**
  - Run: `scripts/bundle-macos.sh --check`
  - Expected: FAIL, because the file does not exist.
- [ ] **Step 2: Create the SVG, the PNG, the plist template and both scripts.**
- [ ] **Step 3: Check the scripts**
  - Run: `scripts/bundle-macos.sh --check`
  - Expected: `bundle check OK`.
  - Then run: `grep -nE 'curl|wget|https?://|cargo install' scripts/bundle-macos.sh scripts/make-icns.sh`
  - Expected: no output.
- [ ] **Step 4: Build the bundle**
  - Run: `scripts/bundle-macos.sh`
  - Then run: `codesign --verify --strict target/bundle/Holm.app`
  - Expected: exit 0.
  - Then run: `plutil -p target/bundle/Holm.app/Contents/Info.plist | grep CFBundleIconFile`
  - Expected: it prints the key.
- [ ] **Step 5: Manual check and design review**
  - Manual checklist: double-click `Holm.app`. The Dock shows the icon, the window title is "Holm", and the minimise lock and the sleep lock still work from the bundle.
  - Sonnet reviews the icon at 16 and 1024 px. The owner sees a screenshot.
- [ ] **Step 6: Write lesson 45** "Shipping a Mac app by hand": the bundle layout, Info.plist, ad-hoc sealing versus Developer ID, and why `cargo-bundle` is not used (a new crate). The Kotlin comparison is jpackage and the Gradle `application` plugin.
- [ ] **Step 7: Commit and push**
  - Commit `build: unsigned local Holm.app bundle with app icon`.
  - Run `scripts/ci-local.sh`, then push.

### Task 10: Security-relevant parked Minors and docs N1–N4

**Issue:** new, `phase-5`

**Files:**
- Modify:
  - `crates/holm-core/src/import/mod.rs` (T3 M5);
  - `crates/holm-core/src/session/mod.rs` (`verify_password`);
  - `crates/holm-platform/src/{private_file.rs,fs_store.rs,tty.rs,lib.rs}`;
  - `crates/holm-platform/tests/*.rs` (`#![forbid(unsafe_code)]`);
  - `crates/holm-cli/src/{output.rs,args.rs,vault.rs,commands/read.rs,commands/write.rs,commands/transfer.rs}`;
  - `crates/holm-cli/tests/*.rs`;
  - `scripts/ci-local.sh` (lint-drift gate);
  - `docs/{DECISIONS.md,CRYPTO.md}`, `docs/tasks/BACKLOG.md`, `docs/manual/phase-4-cli-checklist.md`;
  - `docs/learn/README.md`.
- Create: `docs/learn/46-closing-the-small-gaps.md`.

**Interfaces:**
- Consumes: Task 3 (`transfer`), so this task goes after it.
- Produces: `pub fn verify_password(&mut self, password: &MasterPassword) -> Result<(), CoreError>` on `Session`. It goes through `Throttle::attempt` and leaves the session unlocked and unchanged.

Items, each with its test:

| Item | Change | Test |
|---|---|---|
| T3 M5 | Imported `created`/`updated` are clamped to `[0, now_unix]` | `import_clamps_timestamps` (`i64::MIN` and `MAX` both land in range) |
| T4 M6 | `write_new_private_file` fsyncs the parent folder after the data fsync | `write_new_private_file_syncs_parent` (a seam counts the sync calls) |
| T4 M5 | Phase 4 checklist: "on macOS check `ls -le` on the export folder for inherited ACLs" | doc only |
| T5 M2 | `gen` writes from one pre-sized `Zeroizing<Vec<u8>>` with `write_all` and a flush; no `writeln!` | `gen_output_written_once` (the fake writer sees one write) |
| T5 M3 | An `Ok(0)` read before the deadline means `EndOfInput` | `zero_byte_read_is_end_of_input` |
| T5 M7 | `clean()` also drops U+2028, U+2029, U+200B–U+200D, U+2060, U+FEFF | `clean_drops_invisible_and_separators` |
| T5 M8 | Any `--flag=value` on a prompt-only flag gives `PASSWORD_FLAG` | `password_flag_with_value_named` (`--new-password=EXAMPLE`; the error text names no value) |
| T6 M4 | New `read_error` mapper for `export_csv`, `reveal_phrase` and the passwd check | `read_only_errors_say_nothing_about_saving` |
| T6 (impl) | `passwd` calls `verify_password` before asking for the new password | `passwd_checks_current_first` (a wrong current password gives no new-password prompt) |
| T7 M2 | `AddArgs`/`EditArgs` text fields become `Zeroizing<String>` | `args_text_fields_are_zeroizing` (a type assertion) |
| Final M7 | `lock_folder` checks the folder exists before creating it, for every command except `init` | `list_on_missing_folder_creates_nothing` |
| P3 m1 | riscv64 `O_NOFOLLOW` moves to the `0o400000` branch | `o_nofollow_values_per_arch` (cfg table test) |
| P3 m2 | ci-local fails if holm-platform `[lints.rust]` drifts from `[workspace.lints.rust]` | ci gate prints `lint drift OK` |
| N1 | DECISIONS:80 and the `private_file.rs:5-7` module doc say the truncate is best effort and that APFS may keep freed blocks | doc only |
| N2 | `docs/tasks/BACKLOG.md` records "optional: keep the vault open on `EndOfInput` at the discard prompt" (owner call) | doc only |
| N3 | The three named tests skip with a note when `rustix::process::geteuid().is_root()`; BACKLOG T8 re-review M3 widened to name them | run as non-root: unchanged |
| N4 | done in Task 2 | none |

- [ ] **Step 1: Write the failing tests** named in the table.
- [ ] **Step 2: Run the tests and confirm they fail**
  - Run: `cargo test --workspace --locked`
  - Expected: those tests FAIL.
- [ ] **Step 3: Implement** each change in the table.
- [ ] **Step 4: Run the tests and the gates**
  - Run: `cargo test --workspace --locked` and `cargo tree -p holm-core -e normal --locked` (identical to `a7dde73`).
  - Expected: PASS.
- [ ] **Step 5: Update the backlog**
  - In `docs/tasks/BACKLOG.md`, tick the closed items, add the "Phase 5 wave 2" list from this plan's Deferred section, and keep the style-only Minors where they are.
  - Update CRYPTO for T4 M6 and T5 M7.
- [ ] **Step 6: Write lesson 46** "Closing the small gaps": `fsync` on a folder, Unicode invisibles, and `Zeroizing` in argument structs. The Kotlin comparison is `FileChannel.force` and `Character.getType`.
- [ ] **Step 7: Commit and push**
  - Commit `fix: security-relevant Phase 4 Minors and docs N1-N4`.
  - Run `scripts/ci-local.sh`, then push.

---

## Proposed tasks: PENDING OWNER YES — do not dispatch until approved

These come from the owner's UX asks (2026-10-18). The COS dispatches each one only after the owner says yes. They run after Task 8, because P2 and P3 change the rows that Task 8 tests.

### Task P1: One-line toolbar (PENDING OWNER YES — do not dispatch until approved)

**Files:**
- Modify: `crates/holm-gui/src/screens/vault.rs` (top panel) and `crates/holm-gui/tests/walking_skeleton.rs`.
- Create: `docs/learn/47-…`.

**Interfaces:** none new. The `ui.heading("Holm")` label is removed (the window title still reads "Holm"). Lock, Import…, Export…, Back up… and New login sit on one `ui.horizontal` row, and the left panel loses its New login button.

- [ ] **Step 1: Write the failing tests**
  - `toolbar_is_one_row`: all five button nodes share one rect row, measured as top within 2 px.
  - `no_holm_heading_in_toolbar`.
  - `new_login_button_once`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Check, review and push**
  - Run `cargo test -p holm-gui --locked`. Expected: PASS.
  - Sonnet does a UI review with a screenshot.
  - Write the lesson, commit `feat(gui): one-line toolbar`, run ci-local, and push.

### Task P2: Category filter chips and badges (PENDING OWNER YES — do not dispatch until approved)

**Files:**
- Modify: `crates/holm-gui/src/{rows.rs,screens/vault.rs,messages.rs}` and `crates/holm-gui/tests/search.rs`.
- Create: `docs/learn/48-…`.

**Interfaces:**
- Consumes: `Session::categories()`, `Query.category: CategoryFilter` (Phase 4 search) and Task 6's rows.
- Produces:
  - `VaultView.chip: CategoryFilter`, the existing `holm_core::search::CategoryFilter { All, Uncategorised, Only(CategoryId) }` (no new enum).
  - The chips sit in a wrapping row above the list. Search runs as `Query { text, category }`, so the chips and the search box combine.
  - `ItemRow` gains `category: Option<Text>`, drawn as a small badge on the row's right.
  - The chip resets to All on lock.

- [ ] **Step 1: Write the failing tests**
  - `chips_list_all_then_categories`.
  - `chip_and_search_combine`: Work + `"git"` gives only the Work rows that match `"git"`.
  - `badge_shows_category_name`.
  - `chip_resets_on_lock`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Check, review and push**
  - Run `cargo test -p holm-gui --locked`. Expected: PASS.
  - Sonnet reviews the UI.
  - Write the lesson, commit `feat(gui): category chips and badges`, run ci-local, and push.

### Task P3: Letter avatars per item, coloured by category, offline only (PENDING OWNER YES — do not dispatch until approved)

**Files:**
- Modify: `crates/holm-gui/src/{rows.rs,screens/vault.rs}`.
- Create: `crates/holm-gui/src/widgets/avatar.rs` and `docs/learn/49-…`.

**Interfaces:**
- `pub fn avatar_letter(title: &str) -> char` returns the first alphanumeric character upper-cased, or `'•'`.
- `pub fn avatar_colour(slot: Option<usize>, dark: bool) -> egui::Color32` picks `PALETTE[slot % 8]` from a fixed 8-colour palette, where `slot` is the category's index in `Session::categories()` (`CategoryId`'s field is crate-private). Uncategorised items (`None`) are grey.
- `pub fn avatar(ui, letter, colour)` draws a 24 px circle with the letter. The avatar is never a secret and never an image, and nothing is ever fetched.

- [ ] **Step 1: Write the failing tests**
  - `letter_from_title` covers `"github"` → `'G'`, `"  9lives"` → `'9'`, `"---"` → `'•'`, and `"ßeta"` → `'S'`, since the upper case of ß is SS.
  - `colour_stable_per_category`.
  - `uncategorised_is_grey`.
  - `avatar_draws_no_image_shape`.
  - `no_network_crate_in_tree`: `cargo tree -p holm-gui -e normal` has no `reqwest`, `ureq`, `hyper` or `url`, checked in ci-local.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Check, review and push**
  - Run `cargo test -p holm-gui --locked`. Expected: PASS.
  - Sonnet reviews the UI.
  - Write the lesson, commit `feat(gui): letter avatars`, run ci-local, and push.
