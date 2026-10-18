# Phase 4 ("2b"): search, import, export and holm-cli Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Daily use from the terminal. `holm-core` gains search, filter and sort over public fields, hostile-input-safe CSV and JSON import, and a password-gated plaintext CSV export. A new `holm` command-line app does init, list and search, get and copy, add, edit, rm, gen, import, export, passwd and an interactive `holm shell`. The macOS GUI gets a search box and thin import and export screens. Done when (spec §14) a vault can be created, filled by import, searched, used and exported from the terminal alone, and the `import_csv` and `import_json` fuzzers run in `scripts/ci-local.sh`.

**Architecture:** `holm-core` stays I/O-free. Import and export parse and build text with Holm's own std-only CSV and JSON code (`holm_core::plain`), so every cell lives in a wiping buffer that is allocated once at its final size. `holm-platform` gains three small std-first modules: `private_file` (capped read, exclusive owner-only write), `tty` (no-echo line editor on `/dev/tty` through `rustix::termios`, feature `tty`) and `clipboard` (arboard, concealed type, feature `clipboard`). `holm-cli` is a library plus a thin `main`: hand-written argument parsing, a `Terminal` trait (real tty or a test fake), and one `Session<FsStore>` per process behind the `holm.lock` single-instance lock. There is no background agent (spec §8.10): every one-shot command asks for the password and locks on exit; `holm shell` is the only long-lived unlocked session.

**Tech Stack:** Rust 1.99.1, edition 2024. **No new crates.** `rustix =1.1.5` (`default-features = false`, features `std`, `termios`) and `arboard =3.7.0` move from GUI-only to `holm-platform` optional features; both are already in `Cargo.lock` and trusted or exempt in `supply-chain/`. `serde_json` stays a dev-dependency (test oracle only). The `csv` crate that the Phase 2 plan named is **not** added.

**Spec:** `docs/superpowers/specs/2026-10-17-holm-v1-design.md` (§4, §7 search, §8.4 copy, §8.7 import, §8.8 export, §8.10 CLI, §9 single instance, §10, §11 throttle, §14 Phase 4). Reused task text: `docs/superpowers/plans/2026-10-18-phase-2-holm-core.md` Tasks 9, 11 and 12 and the moved parts of Task 13. Decisions: `docs/DECISIONS.md`. Gaps: `docs/CRYPTO.md`. Backlog: `docs/tasks/BACKLOG.md`.

## Global Constraints

- Branch `phase-4`, cut from `main` at `32249f4` (Phases 0–3 merged). One PR at the end; nothing merges without an Opus yes on the phase.
- **Security floor (owner ruling, binding):** no plaintext on disk except the export file the user asked for; every secret in a wiping type (`SecretText`, `GatedSecret`, `MasterPassword`, `SecretBuf`, `Zeroizing`); no logging of secrets; every unlock, phrase reveal, export and password change goes through `Throttle::attempt`.
- Every crate but `holm-platform` keeps `[lints] workspace = true` (`unsafe_code = "forbid"`). `holm-platform`'s new modules start with `#![forbid(unsafe_code)]`. No `unsafe` anywhere in Phase 4.
- **No new crates.** A dependency already in `Cargo.lock` may gain a new dependent only as listed in Tech Stack. Each `[workspace.dependencies]` change passes `cargo deny --all-features --locked check` and `cargo vet --locked`. Vet order as in Phase 3: imports, then `cargo vet trust` only for publishers an imported set already trusts, then exemptions with a note. Never write a Holm audit to get past vet. `holm-core` and `holm-crypto` get no exemptions and no new normal dependencies: `cargo tree -p holm-core -e normal --locked` is identical before and after Phase 4.
- `--locked` on every cargo command. A change to `holm-core`'s dependencies or to a fuzz target refreshes `fuzz/Cargo.lock` in the same commit.
- **Passwords in the CLI** (spec §8.10): read only from the controlling terminal (`/dev/tty`) with echo off. Never from argv, an environment variable, stdin or a file. No flag takes a password. Every other secret field (item password, address, memo, phrase, note body, notes) is read the same way.
- **Output never holds a secret:** no secret field is printed by any CLI command or shown by the GUI in Phase 4 (the Show toggle is an open owner decision and is out of scope). The only secret that leaves Holm is through the clipboard (concealed type) or the export file.
- No `Debug`, `Display` or error text contains item text, file content, a password or a file path. Rows are reported by number and fixed reason only.
- Import is hostile input (DECISIONS, "Security decision (import)"): 16 MiB, strict UTF-8, ≤ 50,000 rows, ≤ 64 columns, all-or-nothing apply, categories never created.
- Export (DECISIONS, "Security decision (export)"): master password re-entry, fixed `EXPORT_WARNING`, Trash left out, one wiping allocation, `write_new_private_file` only (exclusive create, mode 0600), no formula escaping.
- Tests use `KdfParams::FLOOR`, tempdir vaults and fake data (`example.com`, values containing `EXAMPLE`). Binaries use `KdfParams::DEFAULT`.
- Every file under `crates/holm-gui/tests/` keeps `#![cfg(target_os = "macos")]`. `holm-cli` builds and tests on every OS; `--copy` is macOS-only for now and says so elsewhere.
- `clippy -D warnings` and `rustfmt --check` clean. Each task: TDD, then commit, then `scripts/ci-local.sh` must print `ALL GATES PASSED`, then `git push`. GitHub Actions is never run.
- One GitHub issue per task (label `phase-4`; #21, #23 and #24 keep their Phase 2 labels and are not edited), listed in `docs/tasks/BACKLOG.md`. Every task writes one lesson (format below) and adds its row to `docs/learn/README.md`.
- Review depth (2026-10-18 process): Opus reviews Tasks 2, 3, 4, 5 and 6 (parsers, secrets, files, terminal) and the whole phase; Sonnet reviews Tasks 1, 7 and 8 plus the GUI look. Only Critical or Important findings block, one fix round per task; nits go to the phase's final fix wave.

## Lesson format

`docs/learn/NN-topic.md`, numbered from **29** (lessons 17, 19 and 20 that the Phase 2 plan reserved are retired, not written). Under 250 lines, these sections in this order:
1. `## Why this matters` (2–4 sentences).
2. `## What we built` (3–5 sentences).
3. `## Rust ideas in this task`: real snippets from the task's code, each with an "In Kotlin you'd write…" comparison.
4. `## Exercises`: exactly 3, each ending with the command that checks the answer.
5. `## Read next`: 1–3 links (The Rust Programming Language, std or crate docs).

No real secrets in examples.

## Security decisions

Proposed by the planner for the security COS; each becomes a line in `docs/DECISIONS.md` in the task named.

- **Own CSV and JSON code (Task 2).** Holm parses and writes CSV and its narrow JSON import shape with std-only code in `holm_core::plain` instead of the `csv` crate (not in `Cargo.lock`) and `serde_json` at runtime. Every cell is decoded into a `Zeroizing<String>` sized once from its raw span, so no reallocation leaves a copy. This closes the DECISIONS gap "csv and serde_json scratch copies are not wiped" and adds no crate to `holm-core`. Cost: about 400 lines of parser to fuzz and review; `serde_json` stays as a dev-only differential oracle.
- **Formula injection (Task 4): no escaping, unchanged.** Prefixing `'` or a tab to cells starting with `=`, `+`, `-`, `@` would change real passwords and break re-import into Holm or another manager (spec §8.8: no lock-in). Instead: every cell is quoted, the fixed `EXPORT_WARNING` says not to open the file in a spreadsheet app, and both the CLI and the GUI require the master password plus an explicit confirmation after showing it. A test pins `=SUM(A1)` round-tripping verbatim.
- **Reading an import file (Task 4).** `read_capped` checks the size before reading, opens non-blocking so a FIFO cannot hang it, refuses anything but a regular file, reads into one wiping buffer of the exact size, and refuses a file that grows while it is read.
- **Terminal input (Task 5).** `holm_platform::tty` reads from `/dev/tty` only, with `ECHO`, `ICANON`, `ISIG` and `IEXTEN` off, into a pre-sized wiping buffer, and restores the saved terminal mode on every exit path (drop guard). Ctrl-C arrives as a byte and means Cancel, so no signal handler is needed and Ctrl-C never leaves the terminal silent. A process killed by another signal can leave echo off (`stty sane` fixes it); recorded in `docs/CRYPTO.md`. `rustix::termios` is a safe API, so `holm-platform` stays free of `unsafe` outside `window`. Not a pipe or stdin: scripting with a password from a file descriptor is deferred and needs an owner call.
- **Per-process throttle in the CLI (Task 5).** The throttle lives in memory (spec §11), so each one-shot `holm` process starts with a fresh counter. A one-shot command allows 3 tries; after that it exits. A script that loops `holm list` still pays one full Argon2 per guess, which is the real protection spec §11 names. `holm shell` keeps one throttle for its whole life.
- **Single instance (Task 5).** Every CLI command that opens a vault takes `holm_platform::lock::acquire` on the vault's folder first and holds it until exit, so the CLI and the GUI never write the same vault at once (closes CRYPTO.md "holm-cli must take it too").
- **CLI copy (Task 6).** `--copy` writes through arboard with the concealed pasteboard type, then the process stays in the foreground for the vault's `clipboard_clear_secs` and clears the clipboard only if it still holds Holm's value (spec §8.4). Enter or Ctrl-C clears at once and exits. The session is locked before the wait, so only the copied value is in memory. A recovery phrase is copied only after the master password is typed again (`reveal_phrase`), even right after unlock.
- **vet notes for desktop crates (Task 5, Task 6).** `rustix` and `arboard` (and their already-vetted trees) now reach `holm-cli` too. Criteria and end dates stay; the notes of the affected `trusted` and exemption entries change from "GUI-only" / `gui-only, pre-release; …` to "desktop clients (holm-gui, holm-cli)" / `desktop-only, pre-release; audit or replace before Phase 6`, and DECISIONS records the widened scope. If `cargo vet` asks for any entry beyond a note change, stop and report to the COS.

## Deferred (not in Phase 4)

One line each, with the reason; Task 8 copies them into `docs/tasks/BACKLOG.md` under Phase 5 unless noted.

- Password Show or reveal toggle in the CLI or the GUI: open owner decision.
- GUI clipboard auto-clear and clear-on-lock, and moving `holm-gui`'s `SystemClipboard` onto `holm_platform::clipboard`: Phase 5 platform hardening (the CLI clears already, Task 6).
- Native file dialogs for import and export in the GUI: needs a new crate (`rfd`); the Phase 4 screens take a typed path.
- GUI encrypted backup button: thin GUI; the CLI has `holm export --backup`.
- Restore from Trash and empty Trash in the CLI: not in spec §8.10's command list; the GUI trash screen is Phase 5.
- Multi-line notes and note bodies typed in the CLI: a hidden prompt reads one line; multi-line text comes in by import or the Phase 5 GUI.
- `--copy` on Linux and Windows: their clipboards need a process that stays alive; comes with the Phase 5 per-OS work.
- Password from a file descriptor for scripts: spec §8.10 says terminal only; needs an owner call (Phase 6 at the earliest).
- Lock on sleep or screen lock in `holm shell`: needs the Phase 5 OS events.

## Review Focus

- A CSV export whose cells start with `=`, `+`, `-` or `@` must come back byte-exact on re-import, and the user must have seen `EXPORT_WARNING` (which names spreadsheets) and typed the master password before any byte is written → tests in Task 4 (`export_does_not_escape_formulas`, `export_warning_names_spreadsheets`), Task 6 (`export_shows_warning_then_asks_password_then_confirms`) and Task 8 (`export_button_needs_password_and_checkbox`).
- A hostile import file (16 MiB + 1 byte, 50,001 rows, a 1,000,000-comma row, `"["` × 100,000, an unclosed quote, invalid UTF-8, a FIFO, a file that grows mid-read) must fail fast with fixed text, bounded memory and no partial import → tests in Task 2 (`wide_row_allocates_no_cells_past_cap`, `deep_nesting_is_malformed_without_recursion`), Task 3 (`file_level_errors`, `import_is_atomic_on_item_limit`), Task 4 (`read_capped_refuses_fifo_dir_and_oversize`, `read_capped_refuses_growing_file`) and the two fuzz targets.
- The plaintext export file must be created new (never over an existing file or through a symlink), mode 0600, and a failed write must remove the partial file → tests in Task 4 (`write_new_private_file_refuses_existing_and_symlink`, `write_new_private_file_is_owner_only`, `failed_write_removes_partial_file`).
- Secret bytes read during import (cells, the file buffer) must sit in wiping buffers that never reallocate, and no import error, row issue or `Debug` may contain a cell value → tests in Task 2 (`cells_allocated_once_at_final_size`), Task 3 (`malformed_error_has_line_not_content`, `bad_rows_skipped_and_reported`) and `tests/import_props.rs` (`errors_never_contain_input`).
- No CLI path may echo a password, take one from argv or the environment, or print any secret field, and Ctrl-C at a prompt must restore the terminal → tests in Task 5 (`no_flag_takes_a_password`, `env_is_never_read_for_secrets`, `editor_handles_backspace_ctrl_u_ctrl_c`, `get_prints_no_secret_field`) and Task 6 (`no_command_output_holds_a_secret`).
- A second Holm (CLI or GUI) on the same vault must refuse with fixed text before any password prompt → test in Task 5 (`second_instance_refused_before_prompt`).

---

### Task 1: Search, filter and sort; Phase 3 Minors to the backlog

**Issue:** [#21](https://github.com/sunnat629/holm/issues/21) (read-only; scope as below)

**Files:**
- Create: `crates/holm-core/src/search.rs`, `docs/learn/29-iterators-and-lifetimes.md`
- Modify: `crates/holm-core/src/lib.rs` (`pub mod search;`), `docs/tasks/BACKLOG.md`, `docs/learn/README.md`

**Interfaces:**
- Consumes: `text::fold` (`pub(crate)`), `Session::unlocked`, `Category::name`, `Item` getters.
- Produces: exactly the Phase 2 plan Task 9 **Interfaces** block (`Query`, `CategoryFilter`, `View`, `Sort`, `ItemSummary<'a>`, `Session::search`, `pub(crate) fn cmp_title_asc`), with one change: `Query::text` is `Zeroizing<String>` (it holds typed text; `Zeroizing<String>` is `Clone + Default`). Task 4 uses `cmp_title_asc`; Tasks 5 and 8 use `search`.

Rules: the Phase 2 plan Task 9 Rules, unchanged.

- [ ] **Step 1: Failing tests** in `search.rs`: the nine tests named in Phase 2 plan Task 9 Step 1, with their assertions, plus `query_text_with_controls_matches_nothing_and_does_not_panic` (query `"\u{202E}\u{0}"` and a 5,000-char query → `Ok(empty)`).
- [ ] **Step 2:** `cargo test -p holm-core --locked search`. Expected: FAIL (no `search` module).
- [ ] **Step 3:** Implement `search.rs`. One `fold` per field per item; match with `str::contains` on the folded strings.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5: Backlog.** In `docs/tasks/BACKLOG.md`:
  - table: rows #21, #23, #24 get lessons `29-…`, `31-…`, `32-…` and a note "lessons 17, 19, 20 retired"; add rows #35–#39 (Phase 4) with their lesson files from this plan;
  - "Phase 4 (moved from Phase 2)": point each line at this plan's task;
  - a new "Phase 3 final review Minors" list under Phase 5, one line each, with the reviewer's fix:
    - m1: `O_NOFOLLOW` is wrong on riscv64 Linux (`fs_store.rs:162-171`): move riscv64 to the `0o400000` branch or return `None`;
    - m2: no guard against drift between holm-platform `[lints.rust]` and `[workspace.lints.rust]`: add a ci-local grep or a test, and `#![forbid(unsafe_code)]` to holm-platform's integration tests;
    - m3: the manual checklist sets `$V` only on the throwaway path: add `V="$HOME/Library/Application Support/Holm/holm.vault"` for the default route (checklist lines 73, 120, 126, 133);
    - m4: `create_then_sync_fails` (holm-gui `tests/create_unlock.rs`) leaves the fake session unlocked: `session.lock()` in the fake, then unlock with `PASSWORD` and expect Vault;
    - m5: no test that Escape or a backdrop click cancels the lock dialog (`vault.rs:300-303`);
    - m6: two comment lines in `holm-platform/Cargo.toml` (19 and 22) run past 100 columns;
    - owed: the owner's real-Mac minimise run (if it does not lock, it is Critical).
- [ ] **Step 6:** Lesson 29 "Iterators and lifetimes": `ItemSummary<'a>` borrowing from the session, iterator chains with `filter`/`map`/`collect`, closures, `sort_by` with `Ordering::then_with`, `#[default]` on enum variants. Kotlin comparisons: `asSequence().filter{}.map{}`, `compareBy().thenBy()`.
- [ ] **Step 7:** Commit `feat(core): search, filter and sort over public fields only`, run `scripts/ci-local.sh` (expect `ALL GATES PASSED`), `git push`.

### Task 2: Std-only CSV and JSON readers and the CSV writer

**Issue:** [#35](https://github.com/sunnat629/holm/issues/35)

**Files:**
- Create: `crates/holm-core/src/plain/mod.rs`, `crates/holm-core/src/plain/csv.rs`, `crates/holm-core/src/plain/json.rs`, `docs/learn/30-parsing-untrusted-text.md`
- Modify: `crates/holm-core/src/lib.rs` (`pub(crate) mod plain;`), `docs/DECISIONS.md` (own CSV and JSON code; close the "scratch copies are not wiped" risk line), `docs/learn/README.md`

**Interfaces:**
- Consumes: nothing new (std, `zeroize`).
- Produces (all `pub(crate)`):
  - `type Cell = Zeroizing<String>;`
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] enum PlainError { Malformed { line: u64 }, TooManyRows, TooManyColumns }` (no content in any variant).
  - `struct CsvReader<'a>` with `fn new(src: &'a str) -> CsvReader<'a>` and `fn next_record(&mut self, out: &mut Vec<Cell>, max_cells: usize) -> Result<Option<Record>, PlainError>`; `#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct Record { line: u64, cells_seen: usize }`. `out` is cleared first; at most `max_cells` cells are allocated, and the rest of the record is scanned (quotes still checked) and only counted in `cells_seen`. `Ok(None)` at end of input.
  - `fn quoted_len(cell: &str) -> usize` (= 2 + `cell.len()` + number of `"` in it) and `fn push_quoted(out: &mut String, cell: &str)` (no reallocation: `debug_assert!` that capacity suffices). Rows end with `"\r\n"`.
  - `struct JsonObject { line: u64, fields: Vec<(Cell, Option<Cell>)> }` (`None` = JSON `null`; hand-written `Debug`: line and field count) and `fn parse_json_rows(src: &str, max_rows: usize, max_fields: usize) -> Result<Vec<JsonObject>, PlainError>`.

Rules:
- CSV (RFC 4180, strict): `,` separates cells; a record ends at `\r\n`, `\n` or a lone `\r`; a cell is quoted only if its first byte is `"`; inside quotes `""` is `"` and line ends are kept verbatim; after a closing quote only `,`, a line end or end of input may follow; a `"` inside an unquoted cell, or an unclosed quote, is `Malformed { line }` (1-based physical line where the bad cell starts). A record that is a single empty line is skipped. Cells are never trimmed.
- JSON: whitespace, then `[`, then zero or more objects separated by `,`, then `]`, whitespace, end. An object holds `"key": value` pairs where value is a string or `null`. Numbers, `true`, `false`, nested arrays or objects, trailing commas, an exact duplicate key in one object, raw control characters in a string, invalid escapes and lone surrogates are `Malformed { line }`. Escapes: `\" \\ \/ \b \f \n \r \t \uXXXX` (surrogate pairs joined). More than `max_rows` objects → `TooManyRows`; more than `max_fields` keys in one object → `TooManyColumns`. Fixed depth, no recursion.
- **One allocation per cell:** scan the cell's raw span first, compute its decoded length (CSV: exact; JSON: the raw length is an upper bound, because escapes only shrink), then `String::with_capacity` and fill. No `push` past the reserved capacity.

- [ ] **Step 1: Failing tests** in `plain/csv.rs` and `plain/json.rs`:
  - `csv_rfc4180_basics` (`a,"b,c","d""e"\r\nf,,"g\nh"\n` → `[["a","b,c","d\"e"],["f","","g\nh"]]`, lines 1 and 2);
  - `csv_line_ends_and_blank_lines` (CRLF, LF, lone CR, a trailing blank line, a blank line between records);
  - `csv_strictness` (`a"b`, `"a"b`, `"abc` each → `Malformed` with the right line; `"x\nEXAMPLE-leak` → the error's `Debug` lacks `EXAMPLE`);
  - `wide_row_allocates_no_cells_past_cap` (one record of 1,000,000 commas, `max_cells = 64` → `out.len() == 64`, `cells_seen == 1_000_001`);
  - `cells_allocated_once_at_final_size` (for CSV `"a""b",plain` and JSON `"xé\n"`: every cell has `capacity() == len()` for CSV and `capacity() >= len()` with no growth for JSON, checked by recording `as_ptr()` before and after filling);
  - `writer_quotes_and_measures` (`quoted_len` equals the bytes `push_quoted` writes, for `""`, `a"b`, `,\n`);
  - property `csv_roundtrip_any_fields` (moved from Phase 2 Task 13): any `Vec<Vec<String>>` of 1–8 non-empty-row cells over any Unicode including `"`, `,`, `\r`, `\n` → write with `quoted_len`/`push_quoted` into one exact-size `String` → `CsvReader` returns the same cells;
  - `json_flat_objects` (strings, `null`, escapes, surrogate pair, empty array, empty object, line numbers);
  - `json_rejections` (number value, `true`, nested object, nested array, trailing comma, top-level object, duplicate key, raw `\u{1}` in a string, lone `\ud800`, 65 keys with `max_fields = 64` → `TooManyColumns`);
  - `deep_nesting_is_malformed_without_recursion` (`"["` × 100,000 and `"[{\"a\":"` + `"["` × 100,000 → `Malformed`, test runs on a thread with a 64 KiB stack);
  - property `json_agrees_with_serde_json`: any `Vec<BTreeMap<String, Option<String>>>` serialised by `serde_json` (dev-dependency) parses to the same pairs.
- [ ] **Step 2:** `cargo test -p holm-core --locked plain`. Expected: FAIL.
- [ ] **Step 3:** Implement `plain/`. Both readers work on byte offsets into the `&str` and copy out only through the one-allocation rule.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** DECISIONS: add the "Own CSV and JSON code" decision; mark the "csv and serde_json scratch copies are not wiped" risk as closed (the caller's file buffer is the only remaining copy, and Task 4 makes it wiping too).
- [ ] **Step 6:** Lesson 30 "Parsing untrusted text": byte offsets vs `char` indices in a `&str`, a small state machine with `match`, measuring before allocating, why errors carry a line and never content, a property test against an oracle crate. Kotlin: `String.indexOf`, `sealed class` states, `buildString(capacity)`.
- [ ] **Step 7:** Commit `feat(core): std-only CSV and JSON readers with wiping cells`, run `scripts/ci-local.sh`, push.

### Task 3: Import from CSV and JSON, with fuzz targets

**Issue:** [#23](https://github.com/sunnat629/holm/issues/23) (read-only; scope as below)

**Files:**
- Create: `crates/holm-core/src/import/{mod.rs,csv.rs,json.rs,row.rs}`, `crates/holm-core/tests/fixtures/import/{holm.csv,holm.json,chrome.csv,firefox.csv,safari.csv,spreadsheet.csv}` (fake data only), `crates/holm-core/tests/import_props.rs`, `fuzz/fuzz_targets/{import_csv.rs,import_json.rs}`, `fuzz/seeds/{import_csv,import_json}/…` (copied from the fixtures), `docs/learn/31-hostile-input-all-or-nothing.md`
- Modify: `crates/holm-core/src/lib.rs` (`pub mod import;`), `fuzz/Cargo.toml` (2 bins), `fuzz/Cargo.lock`, `fuzz/README.md`, `scripts/ci-local.sh` (fuzz list), `docs/learn/README.md`

**Interfaces:**
- Consumes: Task 2 (`CsvReader`, `parse_json_rows`, `PlainError`, `Cell`), `ItemInput`, `ItemData`, `Text`, `SecretText`, `GatedSecret`, `category::name_key`, `text::fold`, `Session::{unlocked, unlocked_mut, now_unix, commit_or_undo}`, `session::items::insert_new`.
- Produces: exactly the Phase 2 plan Task 11 **Interfaces** block (`MAX_IMPORT_BYTES`, `MAX_IMPORT_ROWS`, `MAX_IMPORT_COLUMNS`, `IMPORT_DELETE_SOURCE_WARNING`, `ImportFormat`, `Dialect`, `ImportError`, `RowProblem`, `RowIssue`, `ImportBatch`, `parse`, `ImportPreview`, `ImportReport`, `dedup_key`, `Session::preview_import`, `Session::import`). Tasks 6 and 8 use all public items.

Rules: the Phase 2 plan Task 11 Rules, with these changes:
- CSV goes through `CsvReader` (`max_cells = MAX_IMPORT_COLUMNS` for the header, header width + 1 for data rows): `PlainError::Malformed` → `ImportError::Malformed`; a header with `cells_seen > 64` → `TooManyColumns`; a data row with `cells_seen` > header width → `RowProblem::ExtraFields`; shorter rows read missing cells as empty.
- JSON goes through `parse_json_rows(src, MAX_IMPORT_ROWS, MAX_IMPORT_COLUMNS)`: keys use the CSV header aliases; a key that is not a Holm column, or two keys that alias to one column, → `Malformed { line }` of that object; `null` = empty; `TooManyRows` and `TooManyColumns` map to the same `ImportError` variants.
- Cells move into `Text`/`SecretText` with `std::mem::take(&mut *cell)`, never cloned. A cell that is dropped (unused browser column, OTP) wipes on drop because it is a `Cell`.
- `ImportBatch` has no `Clone`, and its `Debug` prints counts only.

- [ ] **Step 1: Failing tests** in `import/`: the Step 1 list of Phase 2 plan Task 11, with its assertions and fixtures. In `tests/import_props.rs` (moved from Phase 2 Task 13): `errors_never_contain_input` (any bytes with `EXAMPLE-leak` planted → `parse` returns, and neither the error nor the batch `Debug` nor any `RowIssue` contains `EXAMPLE`); `generated_rows_parse_to_same_fields` (generated valid rows of all four types written with `push_quoted` → `parse(Csv)` → `ready()` rows equal the generated fields byte-exact, secrets included).
- [ ] **Step 2:** `cargo test -p holm-core --locked import`. Expected: FAIL.
- [ ] **Step 3:** Implement `import/`.
- [ ] **Step 4:** Same command, then `cargo test -p holm-core --locked`. Expected: PASS.
- [ ] **Step 5: Fuzz targets.** `import_csv` and `import_json`: raw bytes → `holm_core::import::parse(data, fmt)`; on `Ok(batch)`, assert `batch.ready() + batch.issues().len()` ≤ `MAX_IMPORT_ROWS`. No `fuzzing` feature is needed (`parse` is public). Add both names to the `for t in …` list in `scripts/ci-local.sh` (7 targets) and to `fuzz/README.md`. Run `cargo +nightly-2026-10-12 fuzz run import_csv fuzz/corpus/import_csv fuzz/seeds/import_csv -- -max_total_time=120 -malloc_limit_mb=64` and the same for `import_json`. Expected: no crash, no OOM.
- [ ] **Step 6:** Lesson 31 "Hostile input, all or nothing": header maps with `HashMap`, `mem::take` to move out of a wiping buffer without a copy, an undo closure for an all-or-nothing change, why a bad row is reported by number only, and why Holm never guesses where a secret goes. Kotlin: `associateBy`, `also {}`, a transaction lambda.
- [ ] **Step 7:** Commit `feat(core): hostile-input-safe CSV and JSON import`, run `scripts/ci-local.sh`, push.

### Task 4: Plaintext CSV export, private files and the full round trip

**Issue:** [#24](https://github.com/sunnat629/holm/issues/24) (read-only; scope as below)

**Files:**
- Create: `crates/holm-core/src/export.rs`, `crates/holm-platform/src/private_file.rs`, `docs/learn/32-building-output-safely.md`
- Modify: `crates/holm-core/src/lib.rs`, `crates/holm-platform/src/lib.rs`, `crates/holm-platform/tests/round_trip.rs`, `docs/DECISIONS.md` (formula decision restated with the tests that pin it; reading an import file), `docs/THREAT-MODEL.md` (the export file is plaintext the user chose to create), `docs/learn/README.md`

**Interfaces:**
- Consumes: `Session::check_password`, `cmp_title_asc` (Task 1), `GatedSecret::expose` (`pub(crate)`), `quoted_len` and `push_quoted` (Task 2), `import::parse` and `Session::import` (Task 3).
- Produces:
  - exactly the Phase 2 plan Task 12 **Interfaces** block (`EXPORT_WARNING`, `EXPORT_COLUMNS`, `Session::export_csv`, `pub(crate) fn write_csv`, `holm_platform::private_file::write_new_private_file`);
  - `holm_platform::private_file::read_capped(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, StoreError>`: `StoreError::TooLarge` over `max` (callers show their own text, not the 64 MiB `Display`), `NotARegularFile` for anything but a regular file after following symlinks, `Io(kind)` otherwise. Tasks 6 and 8 use both functions.

Rules: the Phase 2 plan Task 12 Rules, plus:
- `write_csv` computes the total from `quoted_len` and allocates the `SecretBuf`'s `Vec` once.
- `write_new_private_file`: `OpenOptions` with `write`, `create_new` (refuses an existing file and any symlink, dangling or not) and `mode(0o600)` on Unix; `write_all`, `sync_all`; on any error after the create, remove the file before returning.
- `read_capped`: `fs::metadata` size check before opening; open read-only with `O_NONBLOCK` on Unix (`custom_flags`, value from the same table as `lock.rs`); `file.metadata()` must be a regular file of size ≤ `max`; `Zeroizing::new(vec![0; len])`, `read_exact`, then one more `read` must return 0, else `Io(ErrorKind::InvalidData)`.

- [ ] **Step 1: Failing tests:** the Step 1 list of Phase 2 plan Task 12 (incl. `export_does_not_escape_formulas` with passwords `=SUM(A1)`, `+1`, `-1`, `@x`, each verbatim, and `export_import_roundtrip_all_types` with the Review Focus password `" pa\u{301}ss\tword "`), plus:
  - `export_warning_names_spreadsheets` (`EXPORT_WARNING` contains `"plain text"` and `"spreadsheet"`);
  - `export_buffer_allocated_once` (`buf.expose().len() == ` the sum of `quoted_len` over all cells plus `2 × rows`);
  - platform: the Phase 2 `write_new_private_file_refuses_existing_and_symlink` covers three cases (existing file, symlink to a missing target, symlink to an existing file → `AlreadyExists`, target bytes unchanged, nothing created at the missing target); `failed_write_removes_partial_file` (through a `#[cfg(test)] pub(crate) fn write_new_private_file_with(path, bytes, write: &mut dyn FnMut(&mut File, &[u8]) -> io::Result<()>)` seam that `write_new_private_file` calls with `write_all`; a writer that writes 3 bytes then returns `Err` → the error comes back and `path` does not exist);
  - `read_capped_refuses_fifo_dir_and_oversize` (Unix FIFO via `mkfifo` through `std::process::Command`, a directory, `max + 1` bytes; the FIFO test must return within 1 s);
  - `read_capped_refuses_growing_file` (through the same kind of `#[cfg(test)]` seam: a reader that yields one byte more than the size).
- [ ] **Step 2:** `cargo test -p holm-core -p holm-platform --locked -- export write_new_private_file read_capped failed_write`. Expected: FAIL.
- [ ] **Step 3:** Implement `export.rs` and `private_file.rs` (`#![forbid(unsafe_code)]`).
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5: Full round trip** (moved from Phase 2 Task 13): extend `full_round_trip_on_disk` in `crates/holm-platform/tests/round_trip.rs`: after the password change, `export_csv` → `write_new_private_file` into the tempdir → the file's mode is 0600 → `read_capped(MAX_IMPORT_BYTES)` → `parse(Csv)` → `import` into a second, fresh `FsStore` vault → every field equal (phrase via `reveal_phrase`), favourites and timestamps kept, categories matched by built-in name. Run `cargo test -p holm-platform --locked`. Expected: PASS.
- [ ] **Step 6:** Lesson 32 "Building output safely": measure-then-fill to keep secrets out of freed memory, quoting rules, `OpenOptions::create_new` and `OpenOptionsExt::mode`, why Holm does not formula-escape. Kotlin: `StringBuilder(capacity)`, `Files.newOutputStream(path, CREATE_NEW)`.
- [ ] **Step 7:** Commit `feat(core,platform): password-gated plaintext export and private files`, run `scripts/ci-local.sh`, push.

### Task 5: holm-cli foundation: terminal prompt, instance lock, init, list, get, gen

**Issue:** [#36](https://github.com/sunnat629/holm/issues/36)

**Files:**
- Create: `crates/holm-platform/src/tty.rs`, `crates/holm-cli/src/{lib.rs,args.rs,term.rs,vault.rs,commands/mod.rs,commands/read.rs,output.rs}`, `crates/holm-cli/tests/{common/mod.rs,read_commands.rs,binary.rs}`, `docs/learn/33-a-cli-without-a-framework.md`
- Modify: root `Cargo.toml` (`rustix = { version = "=1.1.5", default-features = false, features = ["std", "termios"] }` in `[workspace.dependencies]`), `crates/holm-platform/Cargo.toml` (feature `tty = ["dep:rustix"]`, `rustix` optional under `[target.'cfg(unix)'.dependencies]`), `crates/holm-platform/src/lib.rs`, `crates/holm-cli/Cargo.toml` (deps `holm-core`, `holm-crypto`, `holm-platform` with `features = ["tty"]`, `zeroize`; dev `tempfile`), `crates/holm-cli/src/main.rs`, `crates/holm-cli/tests/version.rs` (keep passing), `supply-chain/audits.toml` and `supply-chain/config.toml` (notes only, see Security decisions), `docs/DECISIONS.md`, `docs/CRYPTO.md` (CLI section: tty, per-process throttle, instance lock), `docs/learn/README.md`

**Interfaces:**
- Consumes: `Session`, `FsStore::new`, `holm_platform::{lock::acquire, paths::{default_vault_path, ensure_vault_dir}}`, `search` (Task 1), `strength::check`, `generator::{generate_password, generate_passphrase, generate_username}` with `PasswordSpec::DEFAULT` etc., `Settings`.
- Produces:
  - `holm_platform::tty` (feature `tty`): `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum TtyError { NoTerminal, Cancelled, TooLong, NotUtf8, Unsupported, Io(ErrorKind) }`; `#[derive(Clone, Copy, Debug)] pub struct LineOpts { pub echo: bool, pub max_bytes: usize, pub deadline: Option<Instant> }`; `pub fn read_line(prompt: &str, opts: LineOpts) -> Result<Option<Zeroizing<String>>, TtyError>` (`Ok(None)` when `deadline` passes); `pub fn wait_for_key(until: Instant) -> Result<bool, TtyError>` (true if Enter or Ctrl-C came first); `pub(crate) fn edit(bytes: &mut dyn Iterator<Item = u8>, buf: &mut Zeroizing<Vec<u8>>, opts: &LineOpts, echo_out: &mut dyn Write) -> Result<EditEnd, TtyError>` with `enum EditEnd { Enter, Eof }` (the testable editor). Non-Unix: every function returns `Err(TtyError::Unsupported)`.
  - `holm_cli::term::Terminal` trait: `fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError>; fn line(&mut self, prompt: &str, max_bytes: usize, deadline: Option<Instant>) -> Result<Option<Zeroizing<String>>, TtyError>; fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError>;` with `RealTerminal` (over `holm_platform::tty`) and, in `tests/common`, `FakeTerminal` (queued answers, records prompts).
  - `holm_cli::args::{parse(args: &[OsString]) -> Result<Invocation, UsageError>, Invocation { vault: Option<PathBuf>, command: Command }, Command}`: `Command` covers every spec §8.10 command; Task 5 parses `Init`, `List(ListArgs)`, `Get(GetArgs)`, `Gen(GenArgs)`; Tasks 6 and 7 add their variants' handlers. `UsageError` carries a fixed `&'static str`.
  - `holm_cli::Env { kdf: KdfParams, clock: Box<dyn Fn() -> Box<dyn Clock>>, default_vault: Option<PathBuf> }` and `holm_cli::run(inv: Invocation, env: &Env, term: &mut dyn Terminal, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode` (0 ok, 1 failure, 2 usage).
  - `holm_cli::vault::Opened { _lock: InstanceLock, session: Session<FsStore> }` and `fn open(path: &Path, env: &Env, term: &mut dyn Terminal, err: &mut dyn Write) -> Result<Opened, CliError>`: `ensure_vault_dir` → `acquire` (Held → fixed text, before any prompt) → `Session::new` → up to 3 `term.secret("Master password: ", MAX_MASTER_CHARS * 4)` + `unlock` tries; `Throttled { retry_after_secs }` → fixed text with the seconds, exit 1.
  - `holm_cli::vault::resolve(session: &Session<FsStore>, reference: &str, view: View) -> Result<ItemId, CliError>`: a reference is 6 to 32 lowercase hex digits, a prefix of exactly one item's `ItemId::to_hex()`; else `NotFound` or `Ambiguous { count }`.
  - `#[derive(Debug)] enum CliError` with fixed `Display` text per variant; never a path, a value or a library message.

Commands in this task (flag names are the builder's call, spec §15; these are the plan's):
- `holm [--vault PATH] init`: refuses if the vault exists; two hidden prompts; mismatch → fixed text; `strength::check` warning and suggestions printed (fixed text); `Session::create(&pw, &env.kdf)`.
- `holm list [--search TEXT] [--type login|crypto|phrase|note] [--category NAME | --uncategorised] [--favourites] [--trash] [--sort title|updated|created]` → `search`; one line per item: first 8 hex of the id, type, title, subtitle (tab-separated). `--category` matches by `name_key`; unknown name → fixed text, exit 1.
- `holm get REF`: public fields (title, type, username, URLs, chain, category, favourite, created, updated, in Trash) and every secret field as the fixed `(hidden)`; never its length.
- `holm gen [password|passphrase|username]`: no vault; prints one value from the `DEFAULT` spec to stdout (a new value, not a stored secret; `--copy` comes in Task 6).

- [ ] **Step 1: Failing tests:**
  - `tty::tests`: `editor_handles_backspace_ctrl_u_ctrl_c` (bytes `a b DEL c CR` → `"ac"`; `x y 0x15 z CR` → `"z"`; `a 0x03` → `Cancelled`; `0x04` on empty → `Cancelled`; multi-byte `é DEL` removes both bytes; other control bytes ignored); `editor_never_echoes_when_echo_off` (`echo_out` stays empty); `editor_refuses_past_max` (`max_bytes = 4`, `abcde` → `TooLong`, buffer wiped); `editor_buffer_never_grows` (`capacity()` and `as_ptr()` unchanged after 1,024 bytes into a `with_capacity(1024)` buffer); `#[ignore] manual_prompt_on_a_real_tty`.
  - `args::tests`: `no_flag_takes_a_password` (`--password x`, `-p x`, `--pass=x`, `--master x` → usage error; the error text says passwords are only typed at the prompt); `every_spec_command_parses` (`init list get add edit rm gen import export passwd shell`); `unknown_or_missing_values_are_usage_errors`.
  - `tests/read_commands.rs` (FakeTerminal, tempdir vault, `KdfParams::FLOOR`): `init_then_list_empty`; `init_refuses_weak_and_mismatched`; `init_refuses_existing_vault`; `list_search_filters_and_sorts` (fixtures added through `Session` directly); `get_prints_no_secret_field` (password `EXAMPLE-pw-1`, notes `EXAMPLE-note`, address, memo, phrase and body canaries absent from `out` and `err` bytes); `ref_prefix_rules` (5 hex → usage; unique 6 → ok; shared prefix → `Ambiguous`); `three_wrong_passwords_then_exit` (exit 1, prompts recorded == 3, no more `unlock` calls); `second_instance_refused_before_prompt` (hold `acquire` on the dir → exit 1, FakeTerminal saw no prompt); `env_is_never_read_for_secrets` (a test that reads every `.rs` file under `crates/holm-cli/src` and `crates/holm-platform/src/tty.rs` and asserts none contains `env::var`, `var_os` or `std::io::stdin`; `main.rs` may only call `env::args_os`).
  - `tests/binary.rs`: `binary_rejects_password_flag` (`holm --password x list` → exit 2, stderr has no `x` echo beyond the flag name).
- [ ] **Step 2:** `cargo test -p holm-platform --features tty --locked tty && cargo test -p holm-cli --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement. `tty::read_line`: open `/dev/tty` read+write (missing → `NoTerminal`), `tcgetattr`, guard that `tcsetattr`s the saved mode on drop, clear `ECHO | ICANON | ISIG | IEXTEN`, `VMIN = 0`, `VTIME = 1` (0.1 s polls for the deadline), prompt written to the tty (never stdout), then `edit`; `tcflush(TCIFLUSH)` before restoring on `TooLong`/`Cancelled`. `main.rs`: parse `std::env::args_os()`, build `Env` (`DEFAULT` KDF, `SystemClock`, `default_vault_path()`), `RealTerminal`, locked stdout and stderr, return `run`'s `ExitCode`.
- [ ] **Step 4:** Same commands. Expected: PASS. Then `cargo vet --locked` and `cargo deny --all-features --locked check`: PASS with notes-only changes in `supply-chain/` (rustix and its target tree already trusted safe-to-deploy). If vet wants anything else, stop and report.
- [ ] **Step 5:** DECISIONS: terminal input, per-process throttle, single instance in the CLI, vet note scope. CRYPTO.md: replace "holm-cli must take it too (Phase 4)" with the done state; add the gaps (a killed process can leave echo off; the one-shot throttle starts fresh per process).
- [ ] **Step 6:** Lesson 33 "A CLI without a framework": `OsString` and `args_os`, matching on slices of arguments, a trait object for the terminal so tests swap it, RAII guards that restore state in `Drop`, `ExitCode`. Kotlin: `when` over `args`, an interface + fake, `use {}` / `try-finally`.
- [ ] **Step 7:** Commit `feat(cli): no-echo prompt, instance lock, init, list, get and gen`, run `scripts/ci-local.sh`, push.

### Task 6: holm-cli write commands: add, edit, rm, passwd, copy, import, export

**Issue:** [#37](https://github.com/sunnat629/holm/issues/37)

**Files:**
- Create: `crates/holm-platform/src/clipboard.rs`, `crates/holm-cli/src/commands/{write.rs,transfer.rs,copy.rs}`, `crates/holm-cli/tests/{write_commands.rs,transfer_commands.rs}`, `docs/learn/34-moving-secrets-in-and-out.md`
- Modify: `crates/holm-platform/Cargo.toml` (feature `clipboard = ["dep:arboard"]`, `arboard` optional under `[target.'cfg(target_os = "macos")'.dependencies]`), `crates/holm-platform/src/lib.rs`, `crates/holm-cli/Cargo.toml` (`features = ["tty", "clipboard"]`), `crates/holm-cli/src/{args.rs,commands/mod.rs,lib.rs}`, `supply-chain/*` (notes only), `docs/DECISIONS.md`, `docs/learn/README.md`

**Interfaces:**
- Consumes: Task 5 (`Terminal`, `open`, `resolve`, `run`, `CliError`), `Session::{add_item, update_item, trash, delete_forever, change_password, reveal_phrase, save, save_backup, settings}`, Task 3 (`parse`, `preview_import`, `import`, `IMPORT_DELETE_SOURCE_WARNING`, `MAX_IMPORT_BYTES`), Task 4 (`EXPORT_WARNING`, `export_csv`, `read_capped`, `write_new_private_file`), `generate_password(&settings.password)`.
- Produces:
  - `holm_platform::clipboard` (feature `clipboard`): `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ClipboardError { Unavailable, Refused }`; `pub struct ConcealedClipboard` with `pub fn open() -> Result<ConcealedClipboard, ClipboardError>`, `pub fn set(&mut self, text: &str) -> Result<(), ClipboardError>` (`SetExtApple::exclude_from_history`), `pub fn holds(&mut self, text: &str) -> bool` (reads into `Zeroizing<String>`, compares), `pub fn clear(&mut self)`. On non-macOS `open` returns `Unavailable`.
  - `holm_cli::Clip` trait (`set`, `holds`, `clear`) with the real one over `ConcealedClipboard` and a test fake; `Env` gains `clip: Box<dyn Fn() -> Result<Box<dyn Clip>, ClipboardError>>`.
  - `fn copy_and_wait(value: Zeroizing<String>, secs: u32, clip: &mut dyn Clip, term: &mut dyn Terminal, err: &mut dyn Write) -> Result<(), CliError>` (Task 7 reuses the pieces with a shell deadline instead of waiting).

Commands:
- `holm add login --title T [--username U] [--url URL]… [--category NAME] [--favourite] [--generate] [--with-notes]`: password from two hidden prompts, or `--generate` (vault's `settings().password`); notes from one hidden prompt only with `--with-notes`.
  `holm add crypto --title T [--chain C] …` (address required, memo optional: hidden prompts); `holm add phrase --title T …` (phrase twice, hidden); `holm add note --title T …` (body, hidden, one line). Save; print the new id's 8-hex prefix.
- `holm edit REF [--title T] [--username U] [--url URL]… [--clear-urls] [--category NAME | --uncategorised] [--favourite | --no-favourite] [--new-password | --generate] [--new-notes]`: builds an `ItemInput` from the item, unchanged secrets copied as `SecretText::new(x.expose().to_owned())` (the GUI's pattern), a phrase kept by `update_item`'s keep rule; save.
- `holm rm REF` → `trash`; `holm rm --forever REF` (item must be in Trash; the user types `delete` at a visible prompt) → `delete_forever`; save.
- `holm passwd`: open, then current password again, new twice; `change_password(&current, &new, &env.kdf)`; `PasswordChangeUncertain` → fixed text that the new password may now be needed.
- `holm get REF --copy password|username|url|address|memo|notes|body|phrase`: value into a `Zeroizing<String>`; `phrase` needs `reveal_phrase` with a fresh hidden prompt; read `clipboard_clear_secs`, lock and drop the session, then `copy_and_wait`. Non-macOS → fixed text, exit 1. `holm gen … --copy` copies a generated value the same way (30 s default, no vault).
- `holm import FILE [--format csv|json]` (default: `.json` extension → JSON, else CSV): `read_capped(MAX_IMPORT_BYTES)` before any prompt → `parse` → open vault → preview counts and each `RowIssue` as `row N: <fixed reason>` → visible prompt `Type import to add N items:` → `import` → `save` → report counts → `IMPORT_DELETE_SOURCE_WARNING`.
- `holm export FILE`: refuse at once if `FILE` exists (`symlink_metadata`); open vault; print `EXPORT_WARNING`; visible prompt `Type export to continue:`; hidden master password; `export_csv`; `write_new_private_file`; print the item count. `holm export --backup FILE`: `save_backup(&mut FsStore::new(FILE))`; refuses an existing file.

- [ ] **Step 1: Failing tests** (FakeTerminal, fake `Clip`, tempdir):
  - `add_each_type_then_get` (fields land; `get` shows `(hidden)`); `add_login_generate_uses_vault_spec`; `add_password_mismatch_adds_nothing`;
  - `edit_keeps_unchanged_secrets` (edit title only → password, notes, phrase unchanged, checked via `export_csv`); `edit_type_change_impossible`;
  - `rm_trashes_and_forever_needs_typed_confirm`;
  - `passwd_changes_and_old_fails`; `passwd_weak_refused`;
  - `copy_waits_then_clears_only_if_unchanged` (fake clock-free: `wait_for_key` returns `false`; fake clip still holds → cleared; fake clip changed by "someone else" → not cleared); `copy_enter_clears_now`; `copy_phrase_asks_password_again` (2 hidden prompts total; wrong second password → `WrongPassword`, nothing copied, throttle counted);
  - `import_preview_confirm_report_and_warning` (`holm.csv` fixture; declined confirm → vault unchanged); `import_oversize_refused_before_prompt`; `import_reports_rows_by_number_only` (no cell values in `out`/`err`);
  - `export_shows_warning_then_asks_password_then_confirms` (order of prompts and output: warning text, then confirm, then password; wrong password → no file); `export_refuses_existing_file_before_prompt`; `export_file_is_0600_and_reimports` (Unix); `export_backup_opens_with_same_password`;
  - `no_command_output_holds_a_secret`: run every command above with canary secrets; no canary in any `out` or `err` byte.
- [ ] **Step 2:** `cargo test -p holm-cli --locked`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command, plus `cargo test -p holm-platform --features clipboard --locked`. Expected: PASS. `cargo vet --locked` and `cargo deny --all-features --locked check`: PASS with notes-only `supply-chain/` changes.
- [ ] **Step 5:** DECISIONS: CLI copy (foreground wait, clear only if unchanged, phrase re-entry), arboard's widened scope. Manual check added to `docs/manual/phase-4-cli-checklist.md` (new): on a real Mac, `holm get REF --copy password`, paste once, wait for the clear; clipboard manager skipped it.
- [ ] **Step 6:** Lesson 34 "Moving secrets in and out": `std::mem::take`, why `to_owned()` straight into a wiping type is acceptable, `Box<dyn Fn>` factories for test seams, `Instant` deadlines. Kotlin: `CharArray.fill`, factory lambdas, `Duration`.
- [ ] **Step 7:** Commit `feat(cli): add, edit, rm, passwd, copy, import and export`, run `scripts/ci-local.sh`, push.

### Task 7: holm shell

**Issue:** [#38](https://github.com/sunnat629/holm/issues/38)

**Files:**
- Create: `crates/holm-cli/src/shell.rs`, `crates/holm-cli/tests/shell.rs`, `docs/learn/35-a-read-eval-loop-with-a-deadline.md`
- Modify: `crates/holm-cli/src/{args.rs,commands/mod.rs,lib.rs}`, `docs/CRYPTO.md` (shell section), `docs/learn/README.md`

**Interfaces:**
- Consumes: Tasks 5 and 6 (`Terminal::line` with a deadline, `open`'s lock and unlock steps, every command handler, `Clip`), `Session::{lock, is_unlocked, note_activity, idle_expired, settings, throttle_status}`.
- Produces: `pub fn tokenize(line: &str) -> Result<Vec<Zeroizing<String>>, UsageError>` (whitespace splits; `"…"` and `'…'` group; `\` escapes the next char; unclosed quote → usage error) and `pub fn run_shell(path: &Path, env: &Env, term: &mut dyn Terminal, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode`.

Rules:
- `holm [--vault PATH] shell` takes the instance lock once and holds it until exit; it starts locked and runs `unlock` at once.
- Prompt `holm> ` when unlocked, `holm (locked)> ` when locked, read with `echo: true`, `max_bytes = 4096`, deadline = the earlier of the idle deadline (last activity + `settings().auto_lock_secs`) and a pending clipboard clear.
- Commands: every one-shot command except `init` and `shell` (same parser, without `--vault`), plus `unlock`, `lock`, `help`, `exit`/`quit`; Ctrl-D at an empty prompt = `exit`. Commands that need the vault while locked print fixed text.
- A one-shot command's "ask for the master password" step is skipped in the shell (the session is open), except where the spec asks for re-entry: `export`, `passwd`, `--copy phrase`.
- After each command: `note_activity()`; every command saves before returning, so the session is never dirty at a prompt.
- Deadline reached: if `idle_expired()` → `lock()` and print fixed text; if the clipboard deadline passed → clear if `holds`. `--copy` in the shell does not wait: it schedules the clear and returns to the prompt.
- `exit` and Ctrl-D: lock, clear Holm's clipboard value if still held, release the lock.
- `Throttled { retry_after_secs }` at `unlock` → fixed text with the seconds; the next `unlock` is refused by `Session` until then (one throttle for the life of the shell).

- [ ] **Step 1: Failing tests** in `tests/shell.rs` (FakeTerminal whose `line` returns queued lines or `Ok(None)` for a deadline; fake clock): `tokenize_quotes_and_escapes`; `unlock_list_lock_exit`; `locked_commands_refuse`; `idle_deadline_locks` (fake clock past `auto_lock_secs`, `line` returns `None` → session locked, fixed text printed); `copy_schedules_clear_and_prompt_returns`; `exit_clears_clipboard_and_locks`; `throttle_survives_lock_and_unlock` (4 wrong `unlock` lines → `Throttled`; `lock`; `unlock` still throttled); `export_in_shell_asks_password_again`; `shell_output_holds_no_secret` (canaries as in Task 6).
- [ ] **Step 2:** `cargo test -p holm-cli --locked shell`. Expected: FAIL.
- [ ] **Step 3:** Implement `shell.rs`.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** CRYPTO.md: the shell keeps one unlocked session in one process, locks on idle and exit; it does not lock on OS sleep yet (Phase 5). Add a shell section to `docs/manual/phase-4-cli-checklist.md` (idle lock on a real terminal; Ctrl-C at a prompt restores echo).
- [ ] **Step 6:** Lesson 35 "A read-eval loop with a deadline": `loop` with `match` on an enum outcome, `Option<Instant>` and `min`, a tokenizer as a small state machine, keeping state out of a long-lived struct. Kotlin: `while (true) when (…)`, `minOf`, `generateSequence`.
- [ ] **Step 7:** Commit `feat(cli): holm shell with idle auto-lock`, run `scripts/ci-local.sh`, push.

### Task 8: GUI search, import and export; Phase 4 docs

**Issue:** [#39](https://github.com/sunnat629/holm/issues/39)

**Files:**
- Create: `crates/holm-gui/src/screens/transfer.rs` (import and export screens), `crates/holm-gui/tests/transfer.rs`, `crates/holm-gui/tests/search.rs`, `docs/learn/36-thin-screens-over-the-core.md`
- Modify: `crates/holm-gui/src/{rows.rs,screens/vault.rs,screens/mod.rs,worker.rs,messages.rs,app.rs}` (no `Cargo.toml` change: `private_file` needs no feature), `docs/CRYPTO.md`, `docs/DECISIONS.md`, `docs/THREAT-MODEL.md`, `docs/tasks/BACKLOG.md`, `fuzz/README.md` (long-run note for the 7 targets), `docs/learn/README.md`

**Interfaces:**
- Consumes: `Session::search` and `Query` (Task 1), Task 3 (`parse`, `preview_import`, `import`, `ImportPreview`, `ImportReport`, `IMPORT_DELETE_SOURCE_WARNING`, `MAX_IMPORT_BYTES`), Task 4 (`EXPORT_WARNING`, `export_csv`, `read_capped`, `write_new_private_file`), the Phase 3 worker, `SecretField`, `SecretInput`, `messages`.
- Produces: `rows::build_rows(summaries: &[ItemSummary<'_>]) -> Vec<ItemRow>` (replaces the items-based one); `Job::{PreviewImport(PathBuf, ImportFormat), Import(ImportBatch), Export(PathBuf, MasterPassword)}` with `JobKind` variants and `Debug` that prints no path or password; `WorkDone` carries `ImportPreview`/`ImportReport`/export result as fixed-shape data.

Rules:
- Search: a single-line `TextEdit` above the list, backed by a `Zeroizing<String>` pre-allocated to `MAX_LINE_BYTES` (Phase 3 plain-field rule). Each frame the text changed, rows = `search(&Query { text, item_type: Some(ItemType::Login), ..Default })`. A fixed line under the list says how many items of other types the vault holds and that `holm get` shows them (the GUI shows logins only until Phase 5). The search text is wiped on lock (the view drops).
- Import screen (menu button "Import…"): a path field, format by extension, "Read file" → `Job::PreviewImport` (worker: `read_capped`, `parse`, `preview_import`) → counts and issues by row number → "Import N items" → `Job::Import` (import, then save) → report and `IMPORT_DELETE_SOURCE_WARNING`.
- Export screen ("Export…"): shows `EXPORT_WARNING` verbatim, a path field, a `SecretField` for the master password and a checkbox "I understand this file is not encrypted". The button is enabled only with a path, a password and the box ticked. `Job::Export` runs `export_csv` (Argon2, so on the worker) then `write_new_private_file`; the password field is wiped when the job starts. Errors: fixed text per case (`AlreadyExists`, `WrongPassword`, `Throttled` with the live wait, other I/O).
- Every new message is a constant in `messages.rs` and in `ALL`, so the existing plain-text test covers it.

- [ ] **Step 1: Failing tests** (`egui_kittest`, tempdir vault, FLOOR):
  - `tests/search.rs`: `search_box_filters_rows` (3 logins; type `mail` → 1 row); `search_cleared_on_lock`; `other_types_count_line` (import a crypto item through `Session` → the fixed line shows 1).
  - `tests/transfer.rs`: `import_preview_then_import_then_warning` (fixture `holm.csv`); `import_oversize_shows_fixed_text`; `export_button_needs_password_and_checkbox`; `export_wrong_password_writes_nothing`; `export_writes_0600_file_that_reimports`; `export_existing_path_refused`; `transfer_texts_hold_no_values` (no fixture value or path in any AccessKit node).
- [ ] **Step 2:** `cargo test -p holm-gui --locked -- search transfer`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Same command, then `cargo test -p holm-gui --locked`. Expected: PASS.
- [ ] **Step 5: Phase docs.** `docs/CRYPTO.md`: an "Import and export (Phase 4)" section (own parsers in wiping buffers; capped read; export file 0600 and plaintext; no formula escaping and why; the GUI path field keeps the path in a plain `TextEdit` undo history, a display field). `docs/THREAT-MODEL.md`: the export file and the import source are plaintext on disk by the user's choice; full-disk encryption advice applies. `docs/DECISIONS.md`: GUI import and export screens without a file dialog. `docs/tasks/BACKLOG.md`: tick the Phase 4 lines (including the CLI lock), add this plan's Deferred list under Phase 5 (or Phase 6 where noted), set #21, #23, #24, #35–#39 to done when merged. `fuzz/README.md`: the 600 s long run for all 7 targets before the Phase 4 security review.
- [ ] **Step 6:** Lesson 36 "Thin screens over the core": moving owned data through a worker `Job`, keeping a GUI flow a state enum, why the warning text is a core constant. Kotlin: `sealed class UiState`, `viewModelScope.launch(Dispatchers.Default)`.
- [ ] **Step 7:** Commit `feat(gui): search box, import and export screens; Phase 4 docs`, run `scripts/ci-local.sh`, push.

---

Phase 4 ends with the Opus whole-branch security review, the final fix wave, and a 600 s run of each of the 7 fuzz targets. Then the PR from `phase-4` to `main`. Phase 5 (platform hardening and GUI polish) starts from the BACKLOG lists Task 1 and Task 8 maintain.
