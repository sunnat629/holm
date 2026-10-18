# Phase 3: macOS walking skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A thin, runnable macOS app. `cargo run -p holm-gui --locked` opens a window titled "Holm" that can create a vault (with a strength meter), unlock it (showing the throttle wait), list items, add, edit and view a login, copy its password, lock by hand, and lock itself when idle or minimised. Done when, on a real Mac, create → add → lock → unlock → see item works by hand and the same flow passes headless in `egui_kittest`.

**Architecture:** a new `holm-gui` crate (binary plus a small library for tests) on eframe 0.37 with the `glow` renderer. It talks to the vault only through `holm_core::Session<holm_platform::FsStore>`. Argon2 work (create, unlock) runs on a worker thread that takes the `Session` by value and sends it back over an `mpsc` channel, so the UI never blocks and the session has one owner at a time. Secrets are typed into Holm's own `SecretField` widget (never `TextEdit`), held in a pre-allocated wiping `SecretBuf`, and painted as dots. Lock means dropping the unlocked view state and calling `Session::lock`. The vault lives at `~/Library/Application Support/Holm/holm.vault`, found by a std-only `holm_platform::paths` module. eframe and arboard are macOS-only target dependencies, so the workspace still builds on Linux and Windows, where the binary prints that the GUI is macOS-only for now.

**Tech Stack:** Rust 1.99.1, edition 2024. New runtime deps (macOS target only): `eframe =0.37.0` (`default-features = false`, `features = ["glow", "accesskit"]`; egui comes through `eframe::egui`, no direct `egui` dep), `arboard =3.7.0` (`default-features = false`). Dev (macOS only): `egui_kittest =0.37.0` (`default-features = false`). Existing: `holm-core`, `holm-crypto`, `holm-platform`, `zeroize`, `tempfile`. Data: Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono (OFL-1.1). Guide: `docs/learn/gui/README.md`.

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md` (§8.0 default path, §9, §10 GUI, §11 throttle, §14 Phase 3). UI: `docs/design/ui-final-notes.md` (StrengthMeter, unlock copy, create checkbox). Decisions: `docs/DECISIONS.md`. Builds on the merged Phase 2a (`docs/superpowers/plans/2026-10-18-phase-2-holm-core.md`, including `Session::active_items` from Task 10).

## Global Constraints

- Phase 2a is merged first. Phase 3 changes no file format, no crypto and no `holm-core` behaviour; any core change it needs is a separate, Opus-reviewed commit.
- **Security floor (owner ruling, binding):** no plaintext on disk (only the encrypted vault and its temps); every secret in a wiping type (`SecretBuf`, `SecretText`, `MasterPassword`, `Zeroizing`); no logging of secrets; every unlock goes through `Session::unlock` and so through `Throttle`. The GUI never reads the vault file or calls `envelope` directly.
- Licence `MIT OR Apache-2.0`; `[lints] workspace = true`, so `unsafe_code = "forbid"` covers `holm-gui`. `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` in `lib.rs`.
- Secret entry uses `SecretField` only. `egui::TextEdit` is allowed only for title, username and URL, each backed by a `Zeroizing<String>` pre-allocated to `MAX_LINE_BYTES` with `char_limit(MAX_LINE_BYTES / 4)`, so it never reallocates.
- eframe features exactly `glow` and `accesskit`. Off: `default_fonts`, `persistence`, `clipboard`, `wgpu`, `wayland`, `x11`, `web_screen_reader`. `App::save` is not implemented. `cargo tree -p holm-gui -e features --target aarch64-apple-darwin --locked` must show none of the off features.
- No log backend and no `tracing` subscriber: `holm-gui` depends on no `env_logger`, `tracing-subscriber` or similar. No `println!`/`eprintln!`/`dbg!` of anything from the vault. Every type holding item or secret data has a hand-written `Debug` with lengths only.
- Window title is always `"Holm"`. Item titles never go into the title, notifications or OS recent-items lists.
- Every error message shown is fixed text from `holm-gui`, never a path, a field value or a library error's `Display`.
- Every new dependency goes in root `[workspace.dependencies]` with an exact `=` pin and passes `cargo deny --all-features --locked check` and `cargo vet --locked`. `--locked` on every cargo command. The `holm-core`, `holm-crypto` and `holm-platform` dependency trees do not change: `cargo tree -p holm-core -e normal --locked` is identical before and after Task 1 (no GUI crate ever reaches the core).
- Tests use `KdfParams::FLOOR`, a tempdir vault and fake data only (`example.com`, values containing `EXAMPLE`). The binary uses `KdfParams::DEFAULT`.
- `clippy -D warnings` and `rustfmt --check` clean. Commit first, then `scripts/ci-local.sh` must print `ALL GATES PASSED` before every push. GitHub Actions is manual-only and never the gate.
- One GitHub issue per task (labels `phase-3`, `security`, `lesson`), listed in `docs/tasks/BACKLOG.md`. Every task writes one lesson in `docs/learn/` (numbered from 22, same five-part format as Phase 2, under 250 lines) and adds its line to `docs/learn/README.md`.
- **Process (2026-10-18):** review depth follows risk. Opus reviews crypto, password, file-format and `unsafe` work: here Tasks 1 (supply chain), 2, 3, 4, 5 and 6. Sonnet reviews mechanical and UI work (Task 7, and the UI look of every task). Only Critical or Important code or security findings block, with at most one fix round per task; doc and style nits go into the phase's final fix wave. The next task's implementation runs while the previous task's review runs. Lessons and issue upkeep never block a merge. Nothing merges without an Opus yes on the phase.

## Deferred (not in Phase 3)

To Phase 5 unless noted: clipboard auto-clear and clear-on-lock (the owner ruled it out of Phase 3; the copy button says the clipboard is not cleared yet); keychain and Touch ID option; memory locking; OS sleep, screen-lock and logout events; screen-capture exclusion (`with_content_protected`); per-OS durable save; Windows and Linux GUI (x11/wayland features); the three-pane layout, categories, trash, settings, generator UI and the other 16 screens; recovery phrase, crypto address and secure note items; notes on logins (an edit keeps existing notes unchanged); icons (Phosphor subset); Latin subsetting of the fonts; status-bar amber warning before auto-lock; search (Phase 4, Task 9); import and export (Phase 4); code signing and notarisation (Phase 6, owner approval).

## Security decisions

Proposed by the planner for the security COS; each becomes a line in `docs/DECISIONS.md` when its task lands.

- **Security decision (GUI dependencies):** eframe with `glow` and `accesskit` only, arboard without default features, both macOS-only target dependencies. eframe's `clipboard` feature stays off: it pulls arboard's image decoders (11 extra crates, including tiff and jpeg parsers). Holm calls arboard itself, plain text only. AccessKit stays on because spec §10 requires screen-reader support (3 extra crates).
- **Security decision (clipboard in Phase 3):** copy uses arboard with `SetExtApple::exclude_from_history()` (macOS `org.nspasteboard.ConcealedType`, best effort). There is no auto-clear yet; the button's confirmation says so. `NativeOptions::clipboard_shortcuts = false`, so egui never turns Cmd+C/X into copy events: nothing in Holm's window can be copied except through the Copy button. Cmd+V is handled by Holm: into a `SecretField` straight from arboard into the wiping buffer (the arboard `String` is wiped after), into a plain field as an injected `Event::Paste`.
- **Security decision (revealed text):** a revealed password is drawn with an egui label, so egui's text layout holds a non-wiping copy until its cache drops it. Reveal hides after 30 s, on focus loss and on lock. Spec §10 already says the widget reduces copies and cannot promise none.
- **Security decision (plain fields):** title, username and URL use `TextEdit`, which keeps an undo history in plain `String`s. These are display fields, not secrets (spec §8 item text rules); the gap is written down in `docs/CRYPTO.md`.
- **Security decision (vet for GUI crates):** the current rule allows exemptions only for dev-only or unused-target crates. About 87 new runtime crates (macOS) arrive. Order: imported audits first; then `cargo vet trust` only for publishers an imported set already trusts; whatever remains gets an exemption whose note reads `gui-only, pre-release; audit or replace before Phase 6`, listed in `docs/DECISIONS.md`. Needs a COS yes before Task 1 merges (it widens the exemption rule).

## Review Focus

- Typing a master password must never create a `String`, a text layout or an AccessKit value holding it, and the password must be wiped from the field after create or unlock starts → tests in Task 2 (`secret_field_publishes_no_value`, `buffer_wiped_after_take`) and Task 3 (`fields_cleared_when_work_starts`).
- A wrong password three times, then a fourth try at once, must show a live wait and run no unlock → test in Task 3 (`throttle_wait_shown_and_button_disabled`).
- The vault directory must hold only `holm.vault` after create, add, lock and quit, with modes 0700 (directory) and 0600 (file), and its bytes must not contain the item's title or password → tests in Task 1 (`vault_dir_is_owner_only`) and Task 7 (`no_plaintext_on_disk`).
- Idle for the auto-lock time (default 300 s) must lock even when no frame runs `ui`, and minimising must lock at once → tests in Task 6.
- A revealed password must hide after 30 s, on focus loss and on lock → test in Task 4 and Task 6.
- Copy must use the concealed pasteboard type and never egui's `copy_text` → test in Task 5 (`copy_uses_secret_clipboard_only`).

---

### Task 1: holm-gui crate, dependency gates, fonts and the vault path

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/Cargo.toml`, `crates/holm-gui/src/lib.rs`, `crates/holm-gui/src/main.rs`, `crates/holm-gui/src/fonts.rs`, `crates/holm-gui/assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf`, `crates/holm-gui/assets/fonts/AtkinsonHyperlegibleMono-Regular.ttf`, `LICENSES/OFL-1.1.txt`, `crates/holm-platform/src/paths.rs`, `docs/learn/22-a-gui-crate-and-its-supply-chain.md`
- Modify: root `Cargo.toml` (member `crates/holm-gui`; workspace deps `eframe`, `arboard`, `egui_kittest` with the exact pins in Tech Stack), `Cargo.lock`, `crates/holm-platform/src/lib.rs` (`pub mod paths;`), `deny.toml`, `supply-chain/config.toml`, `supply-chain/audits.toml`, `supply-chain/imports.lock`, `NOTICE` (both fonts: source URL at a pinned commit, OFL-1.1, copyright line, SHA-256), `scripts/ci-local.sh` (the two font hashes join `wordlist_gate`), `docs/DECISIONS.md` (the GUI dependency and vet lines)

**Interfaces:**
- holm-platform `paths.rs` (std only, `forbid(unsafe_code)` unchanged): `pub const APP_DIR_NAME: &str = "Holm";` `pub const VAULT_FILE_NAME: &str = "holm.vault";` `pub fn vault_path_under(home: &Path) -> PathBuf` (`<home>/Library/Application Support/Holm/holm.vault`); `pub fn default_vault_path() -> Option<PathBuf>` (macOS: from `std::env::var_os("HOME")`, `None` if unset, empty or not absolute; every other OS: `None` in Phase 3); `pub fn ensure_vault_dir(vault_path: &Path) -> Result<(), StoreError>` (creates only the last directory, `Holm`, with `DirBuilder` mode 0o700 on Unix, not recursive; an existing entry must be a real directory, not a symlink → else `NotARegularFile`; a missing parent → `Io(NotFound)`; no path in any error).
- holm-gui `Cargo.toml`: `[[bin]] name = "holm-gui"`; `[target.'cfg(target_os = "macos")'.dependencies] eframe.workspace = true, arboard.workspace = true`; `holm-core`, `holm-crypto`, `holm-platform`, `zeroize` for every target; `[target.'cfg(target_os = "macos")'.dev-dependencies] egui_kittest.workspace = true`; `tempfile.workspace = true` as a dev-dependency.
- `lib.rs`: `#![cfg(target_os = "macos")]` on the GUI modules (`#[cfg(target_os = "macos")] pub mod …`), so other OSes compile an empty library. `fonts.rs`: `pub fn install_fonts(ctx: &egui::Context)` (an empty `FontDefinitions`, then the two fonts by `include_bytes!` as `Proportional` and `Monospace`, nothing else).
- `main.rs`: `fn main() -> std::process::ExitCode`. On macOS: parse an optional `--vault <path>` (for manual testing; anything else → usage text, exit 2), else `default_vault_path()`; run `eframe::run_native("Holm", options, …)` with `ViewportBuilder::default().with_title("Holm").with_inner_size([900.0, 600.0])`, `clipboard_shortcuts: false`, renderer `Glow`. In this task the app shows only a centred "Holm" heading. Other OSes: print `Holm's window runs on macOS only for now.` and exit 1.

`deny.toml`: add `targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]` under `[graph]` (without it, winit's wasm-only path pulls the banned `tokio` through `wasm-bindgen-futures`); add `ISC` (reason: `libloading`, through glutin and wayland's `dlib`) and `BSL-1.0` (reason: `clipboard-win` and `error-code`, arboard on Windows) to the allowlist. Both are permissive. Measured 2026-10-18: with these, `bans` and `licenses` pass; the ban list is not touched.

- [ ] **Step 1: Failing tests** in `paths.rs`: `vault_path_under_is_app_support` (`/Users/example` → `/Users/example/Library/Application Support/Holm/holm.vault`); `relative_or_empty_home_is_none` (through a private `from_home(Option<OsString>) -> Option<PathBuf>` that `default_vault_path` calls); Unix: `vault_dir_is_owner_only` (tempdir as the parent; mode `& 0o777 == 0o700`; a second call is OK); `vault_dir_symlink_refused` (a symlink named `Holm` → `NotARegularFile`, target untouched); `missing_parent_is_not_found`.
- [ ] **Step 2:** `cargo test -p holm-platform paths --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement `paths.rs`. Add the crate, workspace deps and fonts (download from the pinned upstream commit; if upstream ships only variable fonts, use them and check by hand that egui draws the regular weight). Run `cargo tree -p holm-gui -e features --target aarch64-apple-darwin --locked` and check the feature list (Global Constraints).
- [ ] **Step 4: Gates.** `cargo deny --all-features --locked check` (after the `deny.toml` change). `cargo vet regenerate imports`, `cargo vet suggest`, then the vet order in Security decisions; every exemption added has the `gui-only, pre-release` note. `cargo vet --locked`. Expected: both pass. `cargo tree -p holm-core -e normal --locked` unchanged.
- [ ] **Step 5:** `cargo test -p holm-platform paths --locked` PASS; `cargo build -p holm-gui --locked` on macOS; `cargo run -p holm-gui --locked -- --vault /tmp/holm-try.vault` opens a window titled "Holm" (by hand, once).
- [ ] **Step 6:** Lesson 22: a binary and a library in one crate, target-specific dependencies, `include_bytes!`, what each new crate is for and why the feature list is short, how `deny` targets and vet exemptions work for a big new graph.
- [ ] **Step 7:** Commit `feat(gui): holm-gui crate, fonts, vault path and dependency gates`, run `scripts/ci-local.sh`, push.

### Task 2: SecretBuf, SecretField and StrengthMeter

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/src/secret.rs`, `crates/holm-gui/src/widgets/mod.rs`, `crates/holm-gui/src/widgets/secret_field.rs`, `crates/holm-gui/src/widgets/strength_meter.rs`, `docs/learn/23-a-password-widget-that-wipes.md`
- Modify: `crates/holm-gui/src/lib.rs`

**Interfaces:**
- `secret.rs`: `pub struct SecretBuf { bytes: Vec<u8>, cap: usize }` (no `Clone`; `Debug` → `SecretBuf(<N chars hidden>)`; wipes on drop and on `clear`). `pub const MASTER_CAP: usize = 4 * holm_core::strength::MAX_MASTER_CHARS;` `pub const ITEM_SECRET_CAP: usize = holm_core::item::MAX_SECRET_BYTES;` Methods: `pub fn with_capacity(cap: usize) -> SecretBuf` (reserves exactly once); `pub fn push_str(&mut self, s: &str)` (skips control chars, stops when the next char would pass `cap`, never reallocates, wipes its 4-byte scratch on every path); `pub fn pop_char(&mut self)`; `pub fn char_count(&self) -> usize`; `pub fn is_empty(&self) -> bool`; `pub fn clear(&mut self)`; `pub fn eq_secret(&self, other: &SecretBuf) -> bool`; `pub fn to_master_password(&self) -> MasterPassword` (one exact-size copy into a new `String`, moved into `MasterPassword`); `pub fn take_master_password(&mut self) -> MasterPassword` (moves the allocation out with `std::mem::replace`, leaves a fresh buffer of the same `cap`; no copy); `pub fn take_secret_text(&mut self) -> SecretText` (the same move); `pub fn from_secret(text: &str, cap: usize) -> SecretBuf` (pre-fills for editing). Invalid UTF-8 cannot occur (only `push_str` writes); the `String::from_utf8` error branch wipes the bytes it gets back and returns an empty secret, never `expect`.
- `secret_field.rs`: `pub struct SecretFieldOutput { pub submitted: bool, pub changed: bool, pub has_focus: bool, pub paste_requested: bool }`; `pub fn secret_field(ui: &mut egui::Ui, id_salt: &str, label: &'static str, buf: &mut SecretBuf) -> SecretFieldOutput`. Allocates a fixed rect, `Sense::click()` plus focus on click, `widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, label))` with no value (use the 0.37 password role if `WidgetInfo` offers one), reads `Event::Text`, Backspace and Enter only while focused, sets `paste_requested` on `Key::V` with `modifiers.command` (Task 5 does the paste), ignores every other event (no selection, undo, copy or cut), paints exactly 12 dots when non-empty and none when empty (the length never shows).
- `strength_meter.rs`: `pub fn meter_segments(verdict: &StrengthVerdict) -> u8` (`score.min(4)`; 0 when `chars == 0`); `pub fn meter_word(verdict: &StrengthVerdict) -> &'static str` (`chars == 0` → `""`; not acceptable and `chars < MIN_MASTER_CHARS` → `"Too short"`; score 0–1 → `"Very weak"`, 2 → `"Weak"`, 3 → `"Fair"`, 4 and acceptable → `"Strong"`); `pub fn strength_meter(ui: &mut egui::Ui, report: &StrengthReport)` (4 painted segments, the word, then `report.warning` as fixed text; colour is never the only signal).

- [ ] **Step 1: Failing tests:**
  - `secret.rs`: `push_pop_utf8` (`"aé€😀"` → 4 chars; pop twice → 2); `never_reallocates` (capacity and pointer unchanged after filling to `cap`; the char that would pass `cap` is refused); `controls_skipped`; `debug_redacted` (`format!("{:?}")` of a buffer holding `"EXAMPLE-pw"` lacks it); `buffer_wiped_after_take` (after `take_master_password`, `is_empty()`, same capacity, and the returned password's `to_kdf_bytes` equals the input); `eq_secret_works`; `static_assertions::assert_not_impl_any!(SecretBuf: Clone, Copy)`.
  - `strength_meter.rs`: `meter_table` (empty → 0, `""`; `"Xk#9vQ!2mLp"` → `"Too short"`; `"password1234"` → ≤ 2 segments, not `"Strong"`; `"q7#Vt9!mZ2@rL5$w"` → 4, `"Strong"`).
  - `secret_field.rs` (kittest, `Harness::new_ui_state` over a small test state): `typing_fills_buffer` (click the field by label, push `Event::Text("abc")`, step → 3 chars; Backspace → 2); `unfocused_field_ignores_text`; `secret_field_publishes_no_value` (the AccessKit node for the label has no value and its label is the fixed text); `copy_cut_and_selection_ignored` (push `Event::Copy`, `Event::Cut`, Cmd+A: buffer and platform output unchanged, no `OutputCommand::CopyText`); `cmd_v_requests_paste`.
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement. Where an egui 0.37 name differs from this plan (`WidgetType`, focus calls), use the 0.37 one and note it in the lesson; behaviour stays as written.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 23: why `TextEdit` is not for secrets, `Vec::with_capacity` and never growing, `std::mem::replace` to move a secret out without a copy, reading raw input events, painting instead of laying out text, testing a widget that has no value.
- [ ] **Step 6:** Commit `feat(gui): wiping secret buffer, secret field and strength meter`, run `scripts/ci-local.sh`, push.

### Task 3: App state, worker thread, create and unlock screens

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/src/app.rs`, `crates/holm-gui/src/worker.rs`, `crates/holm-gui/src/messages.rs`, `crates/holm-gui/src/screens/mod.rs`, `crates/holm-gui/src/screens/create.rs`, `crates/holm-gui/src/screens/unlock.rs`, `crates/holm-gui/tests/common/mod.rs` (`TestClock`, `test_app`, `run_until`), `crates/holm-gui/tests/create_unlock.rs`, `docs/learn/24-state-machines-and-worker-threads.md`
- Modify: `crates/holm-gui/src/lib.rs`, `crates/holm-gui/src/main.rs`

**Interfaces:**
- `app.rs`: `pub struct AppConfig { pub vault_path: PathBuf, pub kdf: KdfParams, pub session_clock: Box<dyn Clock>, pub ui_clock: Box<dyn Clock>, pub clipboard: Box<dyn SecretClipboard> }` (`SecretClipboard` is a trait stub in this task: Task 5 fills it; `NoClipboard` does nothing). `pub struct HolmApp` (private fields: `session: Option<Session<FsStore>>` (`None` only while the worker owns it), `screen: Screen`, `kdf`, `ui_clock`, `clipboard`, `secret_focused: bool`, `lock_note: Option<LockNote>`; `Debug` redacted). `pub fn new(config: AppConfig) -> HolmApp` (calls `ensure_vault_dir`; first screen is `Unlock` if `symlink_metadata(vault_path)` finds a file, else `Create`; an `ensure_vault_dir` error → `Screen::Fatal(DIR_ERROR)`). `pub fn tick(&mut self, ctx: &egui::Context)` (called from `App::logic`; this task: polls the worker). `pub fn show(&mut self, ui: &mut egui::Ui)` (called from `App::ui`). `pub fn screen_kind(&self) -> ScreenKind` (`#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ScreenKind { Create, Unlock, Working, Vault, Fatal }`, for tests). `impl eframe::App for HolmApp` (`logic` → `tick`, `ui` → `show`; no `save`).
- `enum Screen { Create(CreateForm), Unlock(UnlockForm), Working { job: JobKind, rx: Receiver<WorkDone> }, Vault(VaultView), Fatal(&'static str) }` (private; `VaultView` is an empty placeholder until Task 4). `CreateForm { password: SecretBuf, confirm: SecretBuf, understood: bool, report: Option<StrengthReport>, error: Option<&'static str> }`; `UnlockForm { password: SecretBuf, error: Option<&'static str> }`.
- `worker.rs`: `pub enum Job { Create(MasterPassword, KdfParams), Unlock(MasterPassword) }` (`Debug` redacted); `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum JobKind { Create, Unlock }`; `pub struct WorkDone { pub session: Session<FsStore>, pub kind: JobKind, pub result: Result<(), CoreError> }`; `pub fn spawn(session: Session<FsStore>, job: Job, wake: impl Fn() + Send + 'static) -> Receiver<WorkDone>` (one `std::thread::Builder::new().name("holm-kdf")` thread; runs `session.create`/`unlock`, drops the `MasterPassword` (wiped) before sending, sends, calls `wake`). A disconnected channel (the thread panicked) → `Screen::Fatal(WORKER_LOST)`; the file on disk is untouched.
- `messages.rs` (pure, no egui): `pub const WRONG_PASSWORD: &str = "That password didn't open this vault. Either the password is wrong, or the file was changed or damaged.";` and fixed texts for the rest; `pub fn unlock_error(e: &CoreError) -> &'static str` (`WrongPassword` and `Vault(WrongPasswordOrCorrupt)` → `WRONG_PASSWORD`; `Vault(OutOfMemory)` → not enough memory; `Vault(KdfPolicy(_))` → cost outside what Holm accepts; `Vault(Format(_))` and `Vault(BadPadding)` → not a Holm vault or damaged; `Body(NewerSchema(_))` → made by a newer Holm; `NoVault` → no vault here; `Store(_)` → could not read the file; anything else → a generic line); `pub fn create_error(e: &CoreError) -> &'static str`; `pub fn throttle_line(status: &ThrottleStatus) -> Option<String>` (`None` with no failures; `"1 failed try."` style after the first failure; `"Too many tries. Try again in N s."` while `retry_after` is `Some`, seconds rounded up; numbers only, no secret).

Rules: Create is enabled only when the report is acceptable, both fields match (`eq_secret`) and "I understand Holm can't recover my vault" is ticked; a mismatch shows on submit, not while typing. Create and unlock call `take_master_password` (both fields cleared, the confirm field cleared with `clear`) before spawning, so no secret stays in the form. The strength report is recomputed only when the password field reports `changed`. Unlock is disabled while `session.throttle_status().retry_after` is `Some`; while waiting, `tick` calls `request_repaint_after(1 s)` so the countdown moves without input. On `Throttled` from the core (a race), show the same line. Success → `Screen::Vault`, which calls `session.note_activity()`. `main.rs` builds `AppConfig` with `KdfParams::DEFAULT`, two `SystemClock::new()` and the real clipboard (Task 5; `NoClipboard` until then), and installs fonts in the creation closure.

- [ ] **Step 1: Failing tests:**
  - `messages.rs`: `unlock_error_table` (each mapping above); `messages_have_no_placeholders` (every const is plain text; `throttle_line` for 3 failures at 2 s left → `"Too many tries. Try again in 2 s."`).
  - `tests/create_unlock.rs` (kittest; `common::test_app(dir)` = `HolmApp` with FLOOR, a tempdir path, a shared `TestClock` (an `Arc<AtomicU64>` pair implementing `holm_core::clock::Clock`), `NoClipboard`; `run_until(&mut harness, pred, 30 s)` steps until `pred(app)`; test password `"correct-Horse-battery-staple-EXAMPLE-9"`, typed with `Event::Text` after clicking the field): `first_run_shows_create`; `create_needs_strong_match_and_checkbox` (weak → button disabled; mismatch → error on submit; strong + match + box → `Working`, then `Vault`, and `holm.vault` exists); `fields_cleared_when_work_starts` (both buffers empty while `Working`); `existing_vault_shows_unlock`; `wrong_password_shows_message` (`WRONG_PASSWORD`, back on `Unlock`); `throttle_wait_shown_and_button_disabled` (Review Focus: three wrong; at once the line says `Try again in 2 s`, the Unlock button is disabled and no `Working` screen appears; advance the `TestClock` 2 s → enabled; the right password then unlocks); `worker_panic_is_fatal_not_hang` (through a test-only `spawn` hook that drops the sender).
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 24: an enum as a screen state machine, moving a value into a thread and getting it back, `mpsc::Receiver::try_recv`, why the session has exactly one owner, `request_repaint_after`, mapping errors to fixed text.
- [ ] **Step 6:** Commit `feat(gui): create and unlock screens on a worker thread`, run `scripts/ci-local.sh`, push.

### Task 4: Item list and login add, edit and view

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/src/screens/vault.rs`, `crates/holm-gui/src/screens/login_form.rs`, `crates/holm-gui/src/rows.rs`, `crates/holm-gui/tests/items.rs`, `docs/learn/25-borrowing-across-a-frame.md`
- Modify: `crates/holm-gui/src/app.rs`, `crates/holm-gui/src/messages.rs`

**Interfaces:**
- `rows.rs`: `pub struct ItemRow { pub id: ItemId, pub title: Text, pub subtitle: Text }` (no `Debug` of text: hand-written, id and lengths only); `pub fn build_rows<'a>(items: impl Iterator<Item = &'a Item>) -> Vec<ItemRow>` (logins only in Phase 3; subtitle = username, or the first URL when the username is empty; sorted by title compared char by char through `char::to_lowercase` with no allocation, then by id). This is the Phase 3 "plain in-memory list of item summaries"; there is no search.
- `vault.rs`: `pub(crate) struct VaultView { rows: Vec<ItemRow>, rows_stale: bool, selected: Option<ItemId>, mode: DetailMode, reveal_until: Option<Duration>, status: Option<&'static str> }`; `enum DetailMode { Empty, View, Edit(LoginForm) }`. Left panel (`egui::Panel::left`): "New login" button, then one selectable row per `ItemRow` (title, subtitle). Top panel: "Lock" button (Task 6 wires the lock). Central panel: the selected login read-only (title, username, URL, password as 12 dots with "Reveal" and "Copy" (Task 5), "Edit"), or the form, or `"Select a login, or add one."`. `rows_stale` is set after unlock and after every successful add or update, and rows are rebuilt from `session.active_items()` once, not every frame.
- `login_form.rs`: `pub(crate) struct LoginForm { id: Option<ItemId>, title: Zeroizing<String>, username: Zeroizing<String>, url: Zeroizing<String>, password: SecretBuf, error: Option<&'static str> }` (`Debug` redacted); `pub(crate) fn new_blank() -> LoginForm`; `pub(crate) fn from_item(item: &Item) -> LoginForm` (`Zeroizing` strings pre-allocated to `MAX_LINE_BYTES`, password via `SecretBuf::from_secret(…, ITEM_SECRET_CAP)`); `pub(crate) fn to_input(&mut self, kept_notes: SecretText, kept_urls: Vec<Text>) -> ItemInput` (moves the field contents out with `std::mem::replace`; URL field empty → no URL, else it replaces the first URL and `kept_urls` follow; `category: None`, `favourite: false`); `messages::field_error(e: &FieldError) -> &'static str` (`Empty(Title)` → `"Add a title."`, `TooLong(_)`, `ForbiddenChar(Url)` → `"Remove the spaces at the start or end of the address."`, and so on, never echoing the value).

Rules: save calls `session.add_item` or `session.update_item`; on `Field(e)` the form stays with `field_error(e)`; on any other error the form stays with a fixed save-failed line and the item stays unsaved in memory (the core keeps it dirty); success → `View` of that item, rows stale. An edit keeps the stored notes (`SecretText::new(item notes .expose().to_owned())`) and any URLs after the first. "Reveal" sets `reveal_until = ui_clock.monotonic() + 30 s` and shows the password in the monospace font with the line `"Visible · hides in 30 s"` counting down; `tick` hides it when the time passes and when the viewport loses focus, and calls `request_repaint_after` for the next second while visible. Leaving the item, editing, or locking hides it. The edit form's password field shows dots only; there is no reveal inside the form in Phase 3.

- [ ] **Step 1: Failing tests:**
  - `rows.rs`: `rows_sorted_case_insensitive_then_id`; `subtitle_rules`; `row_debug_has_no_text` (`"Example Mail"`, `"ada@example.com"` absent).
  - `login_form.rs`: `to_input_moves_fields_and_keeps_notes_and_extra_urls`; `blank_url_means_no_url`; `field_error_messages_have_no_values`.
  - `tests/items.rs` (kittest, unlocked through the Task 3 helpers): `add_login_shows_in_list` (title `"Example Mail"`, username `"ada@example.com"`, URL `"https://mail.example.com"`, password `"EXAMPLE-zq9-pass"` → row visible, view shows title and username, password as dots only: no label in the AccessKit tree contains `EXAMPLE-zq9-pass`); `empty_title_shows_field_error`; `edit_changes_title_and_keeps_password`; `reveal_shows_then_hides_after_30_s` (Review Focus: after Reveal a label with the password exists; `TestClock` +30 s and a step → gone); `reveal_hides_on_focus_loss` (viewport `focused = Some(false)` in the harness input → gone).
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 25: why rows are built once and owned (borrowing the session across a frame and mutating it on a click do not mix), `std::mem::replace` again, panels and `CentralPanel` last, `TextEdit` with a capped, pre-allocated buffer.
- [ ] **Step 6:** Commit `feat(gui): item list and login add, edit and view`, run `scripts/ci-local.sh`, push.

### Task 5: Copy password and paste through Holm's own clipboard

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/src/clipboard.rs`, `crates/holm-gui/tests/clipboard.rs`, `docs/learn/26-the-clipboard-is-shared.md`
- Modify: `crates/holm-gui/src/app.rs` (`raw_input_hook`), `crates/holm-gui/src/screens/vault.rs`, `crates/holm-gui/src/screens/create.rs`, `crates/holm-gui/src/screens/unlock.rs`, `crates/holm-gui/src/main.rs`

**Interfaces:**
- `pub trait SecretClipboard { fn set_secret(&mut self, text: &str) -> Result<(), ClipboardError>; fn get_text(&mut self) -> Option<Zeroizing<String>>; }` (no `Send` bound; lives on the UI thread). `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ClipboardError { Unavailable, Refused }`. `pub struct SystemClipboard` (`Option<arboard::Clipboard>`, opened lazily) with `new()`; `set_secret` = `clipboard.set().exclude_from_history().text(Cow::Borrowed(text))` through `arboard::SetExtApple`; `get_text` = `get_text()` moved straight into `Zeroizing`. `pub struct NoClipboard`. A test-only `FakeClipboard` in `tests/common` records `set_secret` calls and serves `get_text`.
- `impl eframe::App for HolmApp { fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) }`: for a `Key::V` press with `modifiers.command` when `!self.secret_focused`, read `get_text()` and push `Event::Paste(text.to_string())` (plain fields only; the `Zeroizing` copy is wiped, egui's copy is not, which is acceptable for title, username and URL). `HolmApp::paste_into(buf: &mut SecretBuf)` is called when `SecretFieldOutput::paste_requested`: `get_text()`, `buf.push_str`, the `Zeroizing` drops and wipes; `\r\n` and `\n` are skipped by `push_str` as controls.
- Copy button in the item view: `set_secret(password.expose())`; success shows `"Password copied. Holm doesn't clear the clipboard yet, so copy something else when you're done."` (fixed text, Phase 3 only); an error shows `"Couldn't copy. Try again."`. The app never calls `ctx.copy_text`.

- [ ] **Step 1: Failing tests** (`tests/clipboard.rs`, `FakeClipboard`): `copy_uses_secret_clipboard_only` (Review Focus: one `set_secret` call with the password; the frame's platform output has no `CopyText` command); `copy_failure_shows_message`; `cmd_v_pastes_into_secret_field` (fake text `"EXAMPLE-pasted"` → the unlock buffer has 14 chars; no `Event::Paste` reached egui); `cmd_v_pastes_into_title` (through `raw_input_hook` called by the test before the step; the title field holds the text); `cmd_c_in_title_copies_nothing` (no `CopyText` output, no `set_secret`). A manual-only `#[ignore] system_clipboard_marks_concealed` test sets a value with `SystemClipboard` and checks with `NSPasteboard` through `osascript` that `org.nspasteboard.ConcealedType` is present; it is run once by hand in Task 7.
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement. `main.rs` passes `SystemClipboard::new()`.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 26: a trait as a seam for the OS, `Cow<str>`, extension traits (`SetExtApple`), why every app can read the clipboard, what "concealed" asks of clipboard managers and why it is best effort, what auto-clear will add in Phase 5.
- [ ] **Step 6:** Commit `feat(gui): copy password and paste through a secret clipboard`, run `scripts/ci-local.sh`, push.

### Task 6: Lock, idle auto-lock and lock on minimise

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/tests/lock.rs`, `docs/learn/27-locking-without-a-frame.md`
- Modify: `crates/holm-gui/src/app.rs`, `crates/holm-gui/src/screens/vault.rs`, `crates/holm-gui/src/screens/unlock.rs`, `crates/holm-gui/src/messages.rs`

**Interfaces:**
- `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum LockReason { Manual, Idle, Minimised }`; `pub(crate) struct LockNote { reason: LockReason, discarded_unsaved: bool }`; `pub fn lock(&mut self, reason: LockReason)` on `HolmApp`: `session.lock()` (keys and data wiped by the core), then `self.screen = Screen::Unlock(UnlockForm::new())`, which drops the `VaultView` (rows, form and secret buffers wipe on drop), and stores the note. `messages::lock_line(note) -> &'static str` (`"Locked."`, `"Locked after 5 minutes without use."`, `"Locked when the window was minimised."`, plus `" Unsaved changes were discarded."` when `discarded_unsaved`).
- `tick` (from `App::logic`, which eframe runs even while the window is hidden): when the vault is open, lock with `Minimised` if `viewport().minimized == Some(true)`; else lock with `Idle` if `session.idle_expired()` (the core's `IdleTimer`, monotonic plus forward wall-clock gaps, so a Mac waking from sleep locks on its first frame); while open, `request_repaint_after(1 s)`. `tick` never records activity.
- `record_activity` (from `show`, before drawing): when `viewport().visible() != Some(false)` and this frame has input events or pointer movement, `session.note_activity()`.
- Lock button and Cmd+L (`ctx.input_mut(|i| i.consume_shortcut(…))`) lock with `Manual`. While `Working` (an unlock in progress) nothing locks; there is nothing open.

- [ ] **Step 1: Failing tests** (`tests/lock.rs`, kittest, harness closure calls `tick(ctx)` then `show(ui)`, as eframe does): `lock_button_returns_to_unlock` (screen `Unlock`, line `"Locked."`, `session.is_unlocked()` false); `cmd_l_locks`; `idle_locks_after_auto_lock_time` (Review Focus: `TestClock` +299 s → still open; +1 s more → `Unlock` with the idle line); `idle_lock_runs_without_ui` (advance 300 s and call only `tick` → locked; `show` never ran); `activity_resets_idle` (+200 s, a pointer move frame, +200 s → still open); `stale_input_in_tick_does_not_reset` (events present only when `tick` runs, viewport `visible = Some(false)` → no `note_activity`; lock still fires at 300 s); `minimise_locks_at_once`; `reveal_hidden_by_lock` (Reveal, then lock, unlock → the item view shows dots); `unlock_after_lock_sees_item` (the Phase 3 done flow at the GUI level, see Task 7).
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Lesson 27: `logic` versus `ui` in eframe, why the idle check must run when no frame is drawn, `Drop` doing the wiping when a screen is replaced, keyboard shortcuts.
- [ ] **Step 6:** Commit `feat(gui): manual, idle and minimise lock`, run `scripts/ci-local.sh`, push.

### Task 7: End-to-end flow, on-disk check, manual macOS run and docs

**Issue:** new, `phase-3`.

**Files:**
- Create: `crates/holm-gui/tests/walking_skeleton.rs`, `docs/manual/phase-3-macos-checklist.md`, `docs/learn/28-testing-a-whole-app.md`
- Modify: `crates/holm-gui/README.md` (create; how to run, `--vault`, what is deferred), `docs/CRYPTO.md` (GUI known gaps), `docs/THREAT-MODEL.md` (clipboard without auto-clear in Phase 3), `docs/DECISIONS.md` (the Task 4–5 security decisions), `docs/tasks/BACKLOG.md` (the Deferred list above, under Phases 4–6)

- [ ] **Step 1: Failing test** `walking_skeleton_create_add_lock_unlock_see_item` (kittest, FLOOR, tempdir, `FakeClipboard`): create with the test password; add the Task 4 login; copy (one `set_secret`); lock with the button; a **new** `HolmApp` on the same path shows `Unlock`; a wrong password shows `WRONG_PASSWORD`; the right one opens; the row `"Example Mail"` is listed and its view shows `"ada@example.com"`. `no_plaintext_on_disk` (Review Focus): after the flow, the directory holds exactly `holm.vault` (no temps, nothing else), modes 0700 and 0600, and the file bytes contain none of `"Example Mail"`, `"ada@example.com"`, `"mail.example.com"`, `"EXAMPLE-zq9-pass"` or the master password.
- [ ] **Step 2:** `cargo test -p holm-gui --locked`. Expected: PASS (it fails only if Tasks 1–6 have a gap; fix it with a regression test in the task's own test file).
- [ ] **Step 3: Manual checklist** `docs/manual/phase-3-macos-checklist.md`, run once on a real Mac by the implementer and once by the owner, with the date, macOS version and chip: `cargo run -p holm-gui --locked` (default path, `KdfParams::DEFAULT`); create (meter moves; weak refused; checkbox needed); add a login; copy and paste into TextEdit.app; check a clipboard-history tool (if installed) skipped it; Reveal hides after 30 s; lock; unlock with a wrong password three times and see the wait; unlock and see the item; minimise → locked; leave it 5 minutes → locked; close the window; `ls -la ~/Library/Application\ Support/Holm` shows only `holm.vault`, `drwx------` and `-rw-------`; no `~/Library/Saved Application State` entry for Holm; the window title was "Holm" throughout; Activity Monitor shows no network use. Run `system_clipboard_marks_concealed` by hand.
- [ ] **Step 4: Docs.** `docs/CRYPTO.md` known gaps: revealed text and plain-field undo copies in egui; the paste `String`s egui and arboard create; `Event::Text` strings from winit; no clipboard auto-clear yet. `docs/THREAT-MODEL.md`: a copied password stays on the clipboard until replaced in Phase 3 builds. `docs/DECISIONS.md`: the Security decisions of this plan, one line each. `docs/tasks/BACKLOG.md`: the Deferred list.
- [ ] **Step 5:** Lesson 28: what an end-to-end UI test proves and what only a person at a real Mac can check, and how the phase's pieces connect.
- [ ] **Step 6:** Commit `test(gui): walking skeleton end to end; macOS checklist`, run `scripts/ci-local.sh`, push. Then the Phase 3 final fix wave (batched nits), the Opus phase review, and merge.

---

## New crates (measured 2026-10-18, eframe 0.37.0 `glow` + `accesskit`, arboard 3.7.0, macOS aarch64, normal and build edges)

87 crate names not yet in `Cargo.lock`. What they are for:

- egui and eframe: `eframe`, `egui`, `egui-winit`, `egui_glow`, `epaint`, `emath`, `ecolor`, `nohash-hasher`, `self_cell`, `profiling`, `document-features`, `litrs`.
- Window and events (winit): `winit`, `dpi`, `cursor-icon`, `smol_str`, `raw-window-handle`, `web-time`, `dispatch`, `dispatch2`.
- macOS bindings (objc2 family): `objc2`, `objc-sys`, `objc2-encode`, `objc2-foundation`, `objc2-app-kit`, `objc2-core-foundation`, `objc2-core-graphics`, `block2`, `core-foundation`, `core-graphics`, `core-graphics-types`, `foreign-types`, `foreign-types-macros`, `foreign-types-shared`.
- OpenGL: `glow`, `glutin`, `glutin-winit`, `cgl`, `libloading`.
- Text and fonts: `skrifa`, `read-fonts`, `font-types`, `harfrust`, `unicode-segmentation`, `unicode-properties`, `unicode-general-category`.
- 2D raster (egui 0.37 text and shapes): `vello_cpu`, `vello_common`, `peniko`, `kurbo`, `color`, `linebender_resource_handle`, `fearless_simd`, `polycool`, `guillotiere`, `euclid`.
- Image decode (eframe's PNG icon path): `image`, `png`, `fdeflate`, `flate2`, `miniz_oxide`, `adler2`, `crc32fast`, `simd-adler32`, `moxcms`, `pxfm`, `byteorder-lite`.
- Accessibility: `accesskit`, `accesskit_consumer`, `accesskit_macos`, `accesskit_winit`.
- Clipboard: `arboard`.
- General utilities: `ahash`, `foldhash`, `smallvec`, `arrayvec`, `bytemuck`, `bytemuck_derive`, `parking_lot`, `parking_lot_core`, `lock_api`, `scopeguard`, `uuid`, `zerocopy`, `version_check`, `tracing`, `tracing-core` (no subscriber is ever installed).

Dev only (`egui_kittest`, `safe-to-run`): `egui_kittest`, `kittest`, `toml`, `toml_datetime`, `toml_parser`, `serde_spanned`, `winnow` (some already present).

Windows and Linux bring winit's own back ends into the `deny` graph (hence `ISC` and `BSL-1.0`), but they are never built in Phase 3. Cost of the features left off: eframe `clipboard` +11 (image decoders such as tiff and jpeg), `wgpu` far more; `accesskit` costs 3 and stays on.
