# P5b: custom fields Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Any item can hold up to 10 custom fields (label, kind, value, optional expiry). Opening a schema-1 vault still works and the next save writes schema 2. Secrets stay hidden, unsearchable, out of `Debug`, and out of AccessKit.

**Architecture:**
- `holm-core` stays I/O-free. Schema 2 is a second postcard body, not a new field on the schema-1 struct. `VaultData::decode` reads version 1 with the current wire types and version 2 with a new struct. `encode` always writes version 2.
- Custom fields live on `Item`, not inside `ItemData`, so all four kinds share one list. The kind is the value enum, so a secret cannot be stored under a text tag.
- Search, expiry, and the field rules are pure. "Today" is the UTC date of `Clock::now_unix()`, passed in. No clock read inside the pure helpers.
- Export and import stay on the flat CSV and flat JSON that already exist. A custom field is four string cells, not a nested object.
- The CLI prints secret values as `HIDDEN` and copies them only through `copy_and_wait` / `PendingClear`. The GUI paints them with `paint_secret` and copies them through `FieldIo::copied`.

**Tech Stack:**
- Rust 2024, the crates already in the workspace. No new dependency. `holm-core` and `holm-crypto` stay as they are on `cargo tree -p holm-core -e normal --locked`.
- Postcard stays the body codec. No `#[serde(default)]` on the body. Postcard writes values in order and does not say that a field is missing, so a default would read the next real value as the new field.
- No `chrono`. Dates are a checked year, month, and day.
- GUI tests that open a window stay `egui_kittest` and `#![cfg(target_os = "macos")]`.

**Spec:** Owner decisions in this file are binding. The format they extend is `docs/superpowers/specs/2026-10-17-holm-v1-design.md` (body, items, import, export) and `docs/CRYPTO.md` ("The vault body (schema v1)", "Import and export"). Record choices in `docs/DECISIONS.md`. The sealed golden vault stays the schema-1 file.

## Global Constraints

**Branch and merging**
- Branch `p5b-custom-fields`, cut from the tip of this worktree. One PR at the end.
- Nothing merges without an Opus yes on that task, and nothing merges to the base branch without an Opus yes on the branch.
- Do not edit `FORMAT_VERSION`, `HEADER_LEN`, `MAGIC`, the KDF, or anything in `envelope.rs` except a test that still expects them unchanged.

**Security floor**
- No plaintext on disk except an export the user asked for.
- A custom secret is a `SecretText`. It is not a `GatedSecret`. Copying one does not re-ask for the master password. That matches a login password, not a recovery phrase.
- No `Debug` derive on `CustomField`, `FieldValue`, or `Item`. `SecretText`'s `Debug` stays `[REDACTED]`.
- Labels are display text. Secret and multiline values are never searched, never copied into a `TextEdit`, and never placed in an AccessKit label or value.
- `holm-gui`, `holm-cli`, `holm-core`, and `holm-crypto` stay `unsafe_code = "forbid"`.

**Limits already in the crate. Use the constants, never a literal copy of the number.**
- `MAX_SECRET_BYTES` = 4096 (`rules.rs`). Custom `Text` and `Secret` values use it.
- `MAX_NOTE_BYTES` = 65536. `MAX_WIRE_STR_BYTES` stays equal to it. Do not raise it.
- `MAX_LINE_BYTES` = 1024, `MAX_URLS` = 32, `MAX_ITEMS` = 50000.
- `MAX_BODY_LEN` = 67092476, `PAD_BLOCK` = 16384, `MAX_FILE_LEN` = 67108864.
- `MAX_IMPORT_COLUMNS` = 64, `MAX_IMPORT_BYTES` = 16 MiB, `MAX_IMPORT_ROWS` = 50000.
- `REHIDE_PASSWORD_SECS` = 30. A revealed custom secret uses this, not the phrase timer.
- `BODY_SCHEMA_VERSION` becomes 2. Add `BODY_SCHEMA_V1: u16 = 1`. `FORMAT_VERSION` stays 1.

**Parsers and dependencies**
- Parsers stay std-only. The JSON writer is hand-rolled next to `plain::json`, same as the reader. Do not call `serde_json` to build an export.
- Measure, then fill, as `export::build` does. A growing `String` would leave a second copy of a secret.

**Tests**
- `KdfParams::FLOOR`, `FakeClock`, and fake values that contain `EXAMPLE`. No real secrets.
- TDD first. `clippy -D warnings` and `rustfmt --check` clean. `--locked` on every cargo command.
- `scripts/ci-local.sh` must print `ALL GATES PASSED` before the task is done. GitHub Actions is never run.

**Every task**
- grok writes the code. Haiku writes the lesson. Opus reviews the diff.
- Only Critical or Important findings block, with one fix round. Nits wait.
- Commit with the trailers from the COS. The message below is the subject.
- One lesson per task in `docs/learn/NN-topic.md`, numbered from **52**. Add its row to `docs/learn/README.md` in that task.

## Lesson format

Same five sections as `docs/learn/README.md`, in this order, each lesson under 250 lines:
1. `## Why this matters`
2. `## What we built`
3. `## Rust ideas in this task` (real snippets, each with "In Kotlin you'd write…")
4. `## Exercises` (exactly 3, each ending with the command that checks it)
5. `## Read next`

No real secrets in examples. Lessons: 52 format, 53 fields, 54 export, 55 CLI, 56 editor, 57 badge, 58 the body chapter.

## Owner decisions (binding)

- Up to 10 fields on any item. Add, remove, and reorder. Order is the position.
- Label: free text, at most 64 Unicode scalar values (`chars().count()`, same rule as `MAX_CATEGORY_NAME_CHARS`). Not blank. No control and no bidi (`is_forbidden_display_char`). Not from a fixed list.
- Kind is the value: `Text`, `Secret`, `MultilineSecret`, `Date`.
- `Text` and `Secret` values are at most `MAX_SECRET_BYTES`. `Text` is one line (same character rule as `line_secret` plus the display-character rule: no control, no bidi). `Secret` uses `line_secret` (no NUL, CR, or LF).
- `MultilineSecret` uses `multi_line` (no NUL, newlines allowed). Its own cap is `MAX_MULTILINE_SECRET_BYTES` = 16384. See the size budget.
- `Date` is a calendar date, not a `Timestamp`. Optional expiry is a second date on the field, also date-only. Empty expiry means no reminder.
- Secret and multiline values: hidden until reveal, copied through the existing clear, never searched, never in `Debug`, never in AccessKit. Labels are searched. Text values and date values are not searched.
- The list badge is the soonest field expiry. Wording: `Expires in N days` (N ≥ 2), `Expires in 1 day`, `Expires today`, `Expired`. In-app only.
- The Expiring chip is on when the soonest expiry is within `EXPIRING_WITHIN_DAYS` = 30, or already past. Items with no expiry stay out. The chip combines with the category chip. It does not replace it.
- Presets fill labels and kinds only. Values stay empty. Custom is an empty list.
- Version 1 decodes as version 2 with `fields` empty. The next save writes version 2. A body whose version is above 2 is `BodyError::NewerSchema` and is not rewritten. Version 0 stays `UnknownSchema`.

## Size budget

`MAX_MULTILINE_SECRET_BYTES` is 16 KiB, not `MAX_SECRET_BYTES`. An OpenSSH ed25519 private key is a few hundred bytes. An RSA-4096 PKCS#8 PEM is about 3.2 KiB. 16 KiB covers those and a comment block. It is far under `MAX_NOTE_BYTES` (64 KiB) and under `MAX_WIRE_STR_BYTES`, so the existing string cap still bites first on a hostile length, and the field rule bites at 16385.

Worst one item, all caps, labels as 64 chars of 4-byte scalars (256 bytes each):

| Piece | Bytes |
|---|---|
| Title | 1024 |
| Login username | 1024 |
| Login password | 4096 |
| 32 URLs | 32768 |
| Login notes | 65536 |
| 10 labels | 2560 |
| 10 multiline values | 163840 |
| **Text total** | **270848** |

Framing on top of that text is about 220 bytes: postcard length prefixes (a 16384-byte string is a 3-byte varint, a 65536-byte string is a 3-byte varint), the 16-byte `ItemId`, the two timestamps, and 10 expiry structs. Budget the encoded item at **≤ 272000 bytes** (about 271 KiB). The test records the real length and fails outside `270849..=272000`.

`MAX_BODY_LEN` is 67092476. 246 items of 272000 bytes are 66912000 bytes, which still fits. The 247th does not have to. `pad` already returns `VaultError::TooLargeToSave`, and `Session::commit_or_undo` rolls the change back. The 50000-item cap is unchanged and is not reachable at this size. Padding stays 16 KiB blocks. The file cap stays `MAX_FILE_LEN`. Crypto and the envelope do not move.

## Date

Store `CalendarDate { year: u16, month: u8, day: u8 }` with year in 1..=9999 and a real Gregorian day (leap years: divisible by 4, not by 100, unless by 400). Wire order is year, month, day. That order is the format.

A `Timestamp` is a unix instant. The calendar day of an instant depends on the offset, and Holm stores no offset. An expiry has no time, so there is nothing for a timestamp to mean. Days-since-epoch would compare just as well, and would hide a bad month inside the conversion. Year, month, and day make `BadDate` a check on the three numbers, and `YYYY-MM-DD` in CSV is the same three numbers.

`epoch_day` uses Howard Hinnant's civil algorithm (public domain, no crate) so "N days" is a subtraction. `from_unix_secs` divides a unix instant by 86400 in UTC. `Clock::now_unix` is that instant. East or west of UTC, "today" can be one local day off for a few hours. holm-core does not read the OS timezone. That is the accepted risk.

## CSV and JSON rules

Keep the 14 `EXPORT_COLUMNS` in their current order. Append forty columns, slots 1 through 10:

`field1_label`, `field1_kind`, `field1_value`, `field1_expiry`, … `field10_expiry`.

54 columns. `MAX_IMPORT_COLUMNS` stays 64. Do not raise it.

- Export writes the kind in lower case: `text`, `secret`, `multiline`, `date`. Import accepts any ASCII case.
- Expiry is empty or `YYYY-MM-DD`. Never unix seconds. A date field's value is the same form.
- A slot whose four cells are empty is absent. Slots are packed from 1. A later slot filled while an earlier one is empty is `RowProblem::FieldGap`.
- If any cell in the slot is filled, the label and the kind are required. An unknown kind is `RowProblem::BadFieldKind`. Expiry may be empty. Text, secret, and multiline values may be empty. A date value must parse.
- Cells go through `push_quoted` / `quoted_len`. A newline stays inside the quoted cell. `"` is doubled. Cells that start with `=`, `+`, `-`, or `@` are still not prefixed. `EXPORT_WARNING` already covers that.
- A 14-column Holm file imports as an item with no custom fields. Names are matched by `canonical`, not by column position. A duplicate header is still `DuplicateColumn`. An unknown header is still `UnknownColumns`.
- Browser dialects do not gain these columns. A Chrome, Firefox, or Safari file with no `field1_label` is unchanged.
- JSON is the same keys on the flat objects `plain::json` already accepts (string or null). Null is an empty cell. No nested object and no array value. The new `Session::export_json` writes one array of those objects, keys in column order, items in the same title order as CSV.
- `same_item` also compares custom fields: label bytes, kind, value bytes, expiry. The dedup hash key does not gain the secret. A row that matches an item except in a custom field is not a duplicate.

## Security decisions

The planner proposes these. Each becomes one line in `docs/DECISIONS.md` in the task named.

- **Body schema 2 (Task 1).** Version byte, then postcard. Version 1 is read with the old wire structs and gets an empty field list. Version 2 is a different struct with `fields` last on the item. Encode writes 2. Above 2 is `NewerSchema` and is not rewritten. Why not `serde(default)`: the codec has no field names. Risk: a program that still has `BODY_SCHEMA_VERSION = 1` refuses the file (`NewerSchema(2)`), which is the point. Revisit: the next body change.
- **Custom secrets are item secrets, not phrases (Task 2).** `SecretText`, reveal for 30 s, copy through the shared clear, no throttle. Labels are the only custom text that search reads. Risk: a text field can hold something the user thinks of as a secret, and it will sit in the clear on screen. Changing kind wipes the value so a secret is not left in a plain box. Revisit: if a custom field needs the phrase gate.
- **Expiry is a civil date in UTC (Task 2).** No notifications. The chip's window is 30 days, including already expired. Risk: the badge can be one local day early or late. Revisit: if the GUI learns a timezone without putting I/O in core.
- **Custom columns on the flat export (Task 3).** Four cells a slot, quoted, secrets in the clear because the user asked for the file. Password re-entry stays on `export_csv` and `export_json` through `check_password`. Risk: the same spreadsheet risk as today. Revisit: if 54 columns are too wide to round-trip through a spreadsheet. Holm's own reader does not need one.
- **CLI never takes a custom secret as an argument (Task 4).** `term.secret`, then `PendingClear`. `get` prints `HIDDEN`. Risk: a text field's `--value` is on the process list. The kind is the user's. Revisit: never put secret kinds on argv.
- **Revealed custom secrets are painted (Task 5).** `paint_secret`, fixed button labels, user label is a separate node. The known galley-cache gap (CRYPTO, revealed passwords) applies and is not made worse. Multiline entry keeps `\n` and `\r` and still drops `\0`. Risk: egui's galley. Revisit: with the password field, if egui grows a way to drop a galley.
- **The badge carries no field value (Task 6).** It is the status enum rendered in the GUI. Risk: none beyond the UTC day. Revisit: with the date decision.

## Review focus

1. **A schema-2 file opened by an old reader, or a schema-1 file dropped on save.** Version 1 round-trips to version 2 with zero fields. Version 3 is `NewerSchema` and the file is not written back. `reject_if_newer(2, BODY_SCHEMA_V1)` is `NewerSchema(2)`.
   - Task 1: `v1_item_roundtrip_has_no_fields`, `v1_then_encode_is_v2`, `v1_reader_refuses_v2`, `schema_three_is_newer`.
2. **A secret in `Debug`, search, or a too-large field accepted.** Labels match. Secret and text values do not. 11 fields, a 65-character label, a 4097-byte secret, and a 16385-byte multiline value are refused.
   - Task 1: `custom_secret_absent_from_debug`, `eleven_fields_malformed`, `label_65_chars_invalid`. Task 2: `search_matches_label_not_secret`, `search_skips_text_value`.
3. **Export changes a secret, or import guesses a column.** Quoted multiline round-trips. A gap in the slots is a row error. A 14-column file gains no fields. Browser files still parse.
   - Task 3: `export_import_roundtrip_custom_fields`, `field_gap_is_a_row_error`, `old_csv_has_no_fields`.
4. **The CLI prints a custom secret.** `get` shows `HIDDEN`. `--copy field=N` uses `PendingClear` and does not write the value to stdout. `--value` on a secret kind is a usage error.
   - Task 4: `get_hides_custom_secrets`, `copy_custom_does_not_print_the_secret`, `secret_value_rejected_on_command_line`.
5. **AccessKit or a text edit holds the secret.** Hidden and revealed, the node tree has no `EXAMPLE-field-secret`. Copy sets `io.copied`. Kind change leaves the buffer empty.
   - Task 5: `custom_secret_not_in_accesskit`, `kind_change_wipes_the_value`, `login_edit_keeps_custom_fields`.

## Risks and open questions

- UTC versus the user's local midnight. Decided: UTC. The badge can be a day off near midnight. Not blocking.
- "Expires today" and "1 day" are the zero and one cases of "Expires in N days". Decided, so the UI does not say "1 days".
- Text values are not searched. The owner said labels are searched and secrets are not, and was silent on text values. Decided: labels only. Flip this only with an owner yes. It is one extra call in `text_matches`, and it must stay out until then.
- A bank-card number is a `Secret`, so the list cannot show the last four digits. A hint field is not in this wave.
- The card's expiry (a `Date` value) and the optional reminder (the field's expiry) are two dates. The editor labels the reminder `Remind on` so they are not the same box.
- `paint_secret` does `text.to_owned()` into a galley. That copy is not wiped. Same gap as a revealed login password. Do not also put the text in a widget.
- `SecretInput::push_str` drops every control character, including newlines. A PEM pasted into the password widget would be stored wrong. Multiline fields use the new constructor. They must not call the single-line path.
- 54 columns will confuse a spreadsheet. The warning already says not to open the file in one. No formula escaping, same decision as Phase 4.
- `newer_body_schema_reported` seals the bytes `[2, 0]` and expects `NewerSchema(2)`. After this work those bytes are a short schema-2 body (`Malformed`), not a future file. The test moves to `[3, 0]`. Leaving it would hide a real regression.
- The fuzz targets treat "re-encodes" as stable, not as "bytes in equals bytes out". A version-1 input re-encodes as version 2. Do not "fix" `decode_body` to require the input back.

No open question blocks the branch. The choices above are the ones an implementer would otherwise invent.

## Deferred

- OS notifications, email, or any timer outside the app. The chip and the badge are the whole reminder.
- A timezone from the OS.
- Drag-and-drop reorder. Up and Down buttons only.
- Creating or editing crypto, phrase, and note items in the GUI. Those items can gain custom fields here. Their built-in fields stay on the CLI (`EDIT_IN_CLI` stays for the built-in part).
- Searching text values, or showing a secret's last four characters.
- Putting a custom secret behind `Session::reveal_phrase`.
- Nested JSON. The flat object stays the format.
- Raising `MAX_IMPORT_COLUMNS`, `MAX_BODY_LEN`, or `MAX_ITEMS`.
- A new sealed golden file. The schema-1 golden stays, and it must still open. The plaintext golden gains a version-2 sibling and keeps the 51 version-1 bytes.
- A new fuzz target. `decode_body` already calls `VaultData::decode`.

---

### Task 1: Body schema 2 and migration

**Issue:** new, label `p5b`. holm-core only, plus the mechanical `fields: Vec::new()` listed below so the workspace still builds.

**Files:**
- Modify:
  - `crates/holm-core/src/rules.rs` (`MAX_CUSTOM_FIELDS`, `MAX_LABEL_CHARS`, `MAX_MULTILINE_SECRET_BYTES`, `Field::{CustomLabel, CustomValue, CustomDate}`, `FieldError::{TooManyFields, BadDate, NoSuchIndex}`);
  - `crates/holm-core/src/body.rs` (`BODY_SCHEMA_VERSION`, `decode`, the golden tests);
  - `crates/holm-core/src/wire.rs` (v1 structs kept, v2 structs added);
  - `crates/holm-core/src/item.rs` (`Item` and `ItemInput` gain `fields`);
  - `crates/holm-core/src/session/items.rs` (copy `fields` through `insert_new` and `update_item`);
  - `crates/holm-core/src/session/mod.rs` (`newer_body_schema_reported`);
  - `crates/holm-core/src/lib.rs` (module docs only if a path changes);
  - `docs/DECISIONS.md`, `docs/learn/README.md`.
- Create:
  - `crates/holm-core/src/fields.rs`;
  - `docs/learn/52-a-second-schema.md`.
- Mechanical `fields: Vec::new()` and nothing else, so `Item` / `ItemInput` literals still compile:
  - `crates/holm-core/src/{search.rs, export/tests.rs, session/categories.rs, session/items/tests.rs, import/row.rs, import/tests.rs}`;
  - `crates/holm-gui/src/{rows.rs, screens/login_form.rs, screens/vault.rs, worker.rs}`;
  - `crates/holm-gui/tests/{item_types.rs, search.rs}`;
  - `crates/holm-cli/src/commands/write.rs`;
  - `crates/holm-cli/tests/{read_commands.rs, write_commands.rs, shell.rs}`;
  - `crates/holm-platform/tests/{round_trip.rs, exfat.rs, crash.rs}`.
  - `LoginForm::from_input` must name `fields` in the destructure and put them back. Dropping them would delete fields on a failed save. The behaviour test for that is Task 5. This task only keeps the value.

**Interfaces:**
- Consumes: `VaultData::decode`, `VaultData::encode`, `BodyError`, `WireStr`, `BoundedVec`, `MAX_WIRE_STR_BYTES`, `validate_item`, `Text`, `SecretText`.
- Produces, in `rules`:
  - `pub const MAX_CUSTOM_FIELDS: usize = 10;`
  - `pub const MAX_LABEL_CHARS: usize = 64;`
  - `pub const MAX_MULTILINE_SECRET_BYTES: usize = 16 * 1024;`
  - `Field::CustomLabel`, `Field::CustomValue`, `Field::CustomDate`.
  - `FieldError::TooManyFields`, `FieldError::BadDate`, `FieldError::NoSuchIndex`. No variant holds bytes. Messages name the field, never the value, same as the existing `thiserror` lines.
- Produces, in `fields`:
  - `pub struct CalendarDate { year: u16, month: u8, day: u8 }` with `Copy`, `Debug`, `PartialEq`, `Eq`, `Ord`. No serde on this public type.
  - `pub fn parse_date(s: &str) -> Option<CalendarDate>` accepts exactly `YYYY-MM-DD`.
  - `pub fn format_date(d: CalendarDate) -> [u8; 10]` writes the ten ASCII bytes. No heap.
  - `pub fn epoch_day(d: CalendarDate) -> i32`
  - `pub fn from_unix_secs(secs: i64) -> Option<CalendarDate>` UTC. `None` when the year falls outside 1..=9999.
  - `pub enum FieldKind { Text, Secret, MultilineSecret, Date }`
  - `pub enum FieldValue { Text(Text), Secret(SecretText), MultilineSecret(SecretText), Date(CalendarDate) }`
  - `pub struct CustomField` with private fields. No `Clone`, no `Debug` derive, no serde.
  - `pub fn try_field(label: Text, value: FieldValue, expiry: Option<CalendarDate>) -> Result<CustomField, FieldError>`
  - `impl CustomField { pub fn label(&self) -> &str; pub fn kind(&self) -> FieldKind; pub fn value(&self) -> &FieldValue; pub fn expiry(&self) -> Option<CalendarDate>; }`
  - Manual `Debug`: kind, `label_len`, `value_len`, and whether expiry is set. No label text and no value bytes.
- Produces, in `body` / `wire`:
  - `pub const BODY_SCHEMA_VERSION: u16 = 2;`
  - `pub const BODY_SCHEMA_V1: u16 = 1;`
  - `pub(crate) fn reject_if_newer(version: u16, newest: u16) -> Result<(), BodyError>` returns `NewerSchema(version)` when `version > newest`, `UnknownSchema(0)` when `version == 0`, and `Ok(())` otherwise.
  - `Item` gains `pub(crate) fields: Vec<CustomField>`. `Item::fields(&self) -> &[CustomField]`.
  - `ItemInput` gains `pub fields: Vec<CustomField>`. `validate` and `validate_for_update` call `validate_fields` after `validate_item`.
  - `pub(crate) fn validate_fields(fields: &[CustomField]) -> Result<(), FieldError>`
  - Wire, v2 only, field order fixed: `CustomFieldOut { position: u8, label: &str, value: CustomValueOut, expiry: Option<DateWire> }` where `CustomValueOut` is `Text`, `Secret`, `MultilineSecret`, `Date(DateWire { year, month, day })` and `DateWire` order is year, month, day. `ItemOut` gains `fields` as its last field. `ItemIn` uses `BoundedVec<CustomFieldIn, MAX_CUSTOM_FIELDS>`.
  - The current `ItemIn`, `ItemOut`, `DataIn`, `DataOut`, `BodyIn`, and `BodyOut` stay as the v1 types, renamed with a `V1` suffix. `#[cfg(test)] fn encode_v1_for_test(data: &VaultData) -> SecretBuf` writes them under version byte 1.
- `decode` order stays: `TooShort` under 2 bytes, then the version. 1 reads `BodyInV1` and sets `fields` empty. 2 reads `BodyIn`. Anything above 2 is `NewerSchema`. 0 is `UnknownSchema`. Then the same field rules and `check_structure`. Positions must be exactly `0..len` with no duplicates and no gap. Any other set is `Invalid`. A permutation is sorted into that order before it is returned, so a later encode is stable. An unknown kind tag fails postcard and is `Malformed`. A date that is not a real day is `Invalid` (`BadDate`). A string over `MAX_WIRE_STR_BYTES` is `Malformed` inside `WireStr`. A string the wire accepts and the field rule rejects is `Invalid`.

Behaviour of the empty vault: the 51-byte `default_body_golden` array is still the version-1 body. The version-2 encoding of `VaultData::new_default()` is those same 51 bytes with byte 0 set to 2. No item is written, so the new list does not appear. Keep the version-1 array as `V1_DEFAULT_GOLDEN`. Do not regenerate `tests/golden_vault.rs`'s sealed file. `golden_vault_opens_and_decodes_to_schema_v1` must still open it.

`newer_body_schema_reported` seals `[3, 0]` and expects `CoreError::Body(BodyError::NewerSchema(3))`, the vault stays locked, and the throttle counts one failure. `errors_name_no_data` may keep a `NewerSchema(2)` display check. It does not decode.

Fuzz note, not a new target: `fuzz/fuzz_targets/decode_body.rs` already requires that an accepted body re-encodes and that a second encode matches the first. A version-1 input re-encodes as version 2, and that second encode matches. Do not require the input bytes back. After the tests pass, re-seed with the ignored `write_fuzz_seeds` (`cargo test -p holm-core --lib write_fuzz_seeds -- --ignored`). Add one saved version-1 body and one version-2 body that has a field to `fuzz/seeds/decode_body/`. `open_fixed_key` compares item counts only. Leave it. Do not run a long fuzz session in this task. `ci-local.sh` already smokes the targets.

| Test | Expect |
|---|---|
| `v1_default_golden_still_decodes` | `V1_DEFAULT_GOLDEN` decodes, 0 items, `encode` starts `[2, 0]` |
| `v2_default_golden_is_v1_with_version_byte_2` | byte 0 is 2, bytes 2.. equal the old golden |
| `v1_item_roundtrip_has_no_fields` | `encode_v1_for_test` of one login decodes with `fields` empty and the login intact |
| `v1_then_encode_is_v2` | that encode starts `[2, 0]`, decodes again, fields still empty |
| `v2_roundtrip_keeps_fields` | one field of each kind, plus an expiry, survives `decode(encode())` |
| `v1_reader_refuses_v2` | `reject_if_newer(2, BODY_SCHEMA_V1)` is `NewerSchema(2)` |
| `schema_three_is_newer` | bytes `[3, 0]` plus a valid tail is `NewerSchema(3)`. `u16::MAX` stays `NewerSchema` |
| `schema_zero_still_unknown` | version 0 is `UnknownSchema(0)` |
| `header_untouched` | `FORMAT_VERSION == 1` and `HEADER_LEN == 164` |
| `eleven_fields_malformed` | a v2 body whose field count is 11 is `Malformed` |
| `label_65_chars_invalid` | 64 chars ok, 65 is `Invalid` |
| `label_control_invalid` | a newline or `\u{202E}` in a label is `Invalid` |
| `secret_4097_invalid` | `MAX_SECRET_BYTES + 1` on `Text` and on `Secret` is `Invalid` |
| `multiline_16385_invalid` | 16384 ok, 16385 is `Invalid` |
| `multiline_over_wire_cap_is_malformed` | a string of `MAX_WIRE_STR_BYTES + 1` is `Malformed` |
| `bad_kind_tag_malformed` | kind tag 4 on an otherwise valid field is `Malformed` |
| `bad_dates_invalid` | month 13, day 0, 2026-02-29, year 0, year 10000 are `Invalid`. 2024-02-29 and 2000-02-29 are ok. 1900-02-29 is `Invalid` |
| `duplicate_positions_invalid` | two fields at position 0 is `Invalid` |
| `position_gap_invalid` | positions 0 and 2 with no 1 is `Invalid` |
| `truncated_v2_is_malformed` | every proper prefix of a v2 body that contains one field is `Err`, and `decode` does not panic |
| `custom_secret_absent_from_debug` | `Debug` of the field, the item, and `VaultData` does not contain `EXAMPLE-field-secret` |
| `multiline_secret_absent_from_debug` | `Debug` does not contain `BEGIN OPENSSH PRIVATE KEY` |
| `maxed_login_with_ten_keys_fits_one_body` | encoded length is in `270849..=272000`, and that length is `<= MAX_BODY_LEN` |
| `unix_epoch_is_1970_01_01` | `from_unix_secs(0)` is 1970-01-01. `from_unix_secs(86400)` is 1970-01-02. `epoch_day` of 2024-03-01 minus 2024-02-28 is 2 |
| `public_types_are_not_serde` | `assert_not_impl_any!(CustomField: Serialize, DeserializeOwned)` and the same for `FieldValue` and `CalendarDate` |

- [ ] **Step 1: Write the failing tests** in `body.rs`, `fields.rs`, and `item.rs` under the names in the table. Point `newer_schema_refused`'s version-2 case at version 3, and point `encoded_starts_with_version` at `[2, 0]`.
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-core --locked --lib fields` and `cargo test -p holm-core --locked --lib body`
  - Expected: FAIL, because version 2 is still `NewerSchema` and `CustomField` does not exist.
- [ ] **Step 3: Implement** the types, the v1 and v2 wire split, and `decode`'s version branch. Update every `Item` and `ItemInput` literal with `fields: Vec::new()`. Update `field_word` and `field_message` in `crates/holm-cli/src/output.rs`, and `field_error` in `crates/holm-gui/src/messages.rs`, with one arm each, so the new `Field` and `FieldError` variants compile. Fixed sentences only: "The field name can't be empty", "The field value is too long", "That date is not a real calendar day", "An item can have at most 10 custom fields", "That field is not on the item". No value in the sentence.
- [ ] **Step 4: Run the tests and confirm they pass**
  - Run: the Step 2 commands, plus `cargo test -p holm-core --locked --lib session::tests::newer_body_schema_reported` and `cargo test -p holm-core --locked --test golden_vault`.
  - Expected: PASS. The sealed golden still opens.
- [ ] **Step 5: Record and teach**
  - DECISIONS line for schema 2. Lesson 52: why a postcard struct cannot grow a field, the version byte as the switch, and the Kotlin comparison (a `serialVersionUid` plus a second DTO, not a defaulted property on the old one).
- [ ] **Step 6: Opus security review of this task's diff.** Schema split, hostile lengths, `Debug`, and the version-3 refusal. Nothing merges without an Opus yes.
- [ ] **Step 7: Commit**
  - `feat(core): read body schema 1 and write schema 2`

### Task 2: Field edits, search, and expiry

**Issue:** new, label `p5b`. holm-core, plus the `Query` literals and the `FieldError` arms from Task 1 if any arm is still missing.

**Files:**
- Modify:
  - `crates/holm-core/src/fields.rs`
  - `crates/holm-core/src/search.rs` (`Query`, `ItemSummary`, `text_matches`)
  - `crates/holm-core/src/session/items.rs` (`set_custom_fields`)
  - `crates/holm-core/src/rules.rs` (`EXPIRING_WITHIN_DAYS`)
  - `docs/DECISIONS.md`, `docs/learn/README.md`
- Create:
  - `docs/learn/53-labels-dates-and-secrets.md`
- `Query { ... }` literals gain `expiring_only: false` (or `..Query::default()` where the rest is already default):
  - `crates/holm-core/src/search.rs`
  - `crates/holm-cli/src/{vault.rs, commands/read.rs, commands/write.rs}`
  - `crates/holm-cli/tests/{trash_commands.rs, write_commands.rs}`
  - `crates/holm-gui/src/screens/vault.rs`

**Interfaces:**
- Consumes: `Session::commit_or_undo`, `Clock::now_unix`, `FakeClock`, `fold`, `text_matches`, `FieldError`.
- Produces:
  - `pub const EXPIRING_WITHIN_DAYS: u32 = 30;`
  - `pub fn insert_field(fields: &mut Vec<CustomField>, index: usize, field: CustomField) -> Result<(), FieldError>`
  - `pub fn remove_field(fields: &mut Vec<CustomField>, index: usize) -> Result<CustomField, FieldError>`
  - `pub fn move_field(fields: &mut Vec<CustomField>, from: usize, to: usize) -> Result<(), FieldError>`
  - `insert_field` at `len` appends. An index above `len`, or a `from` / `to` outside the vec, is `NoSuchIndex`. The eleventh field is `TooManyFields`. Each helper re-runs `validate_fields`.
  - `pub enum ExpiryStatus { InDays(u32), Expired }`
  - `pub fn expiry_status(expiry: CalendarDate, today: CalendarDate) -> ExpiryStatus` with `InDays(0)` when the dates are equal.
  - `pub fn soonest_expiry(fields: &[CustomField]) -> Option<CalendarDate>` is the minimum expiry. Fields with `None` are skipped. It does not read `FieldValue`.
  - `pub fn is_expiring(fields: &[CustomField], today: CalendarDate, within_days: u32) -> bool` is true when the soonest expiry's `epoch_day` is `<= today.epoch_day + within_days as i32`.
  - `pub enum FieldPreset { Email, Cloudflare, GitHub, Server, Database, Aws, ApiKey, WiFi, BankCard, Custom }`
  - `pub struct PresetField { pub label: &'static str, pub kind: FieldKind }`
  - `pub fn preset_fields(preset: FieldPreset) -> &'static [PresetField]`
  - Preset rows, values not included: Email is Username/`Text`, Password/`Secret`, Server/`Text`. Cloudflare is Email/`Text`, Global API key/`Secret`, Origin CA key/`MultilineSecret`, Account ID/`Text`. GitHub is Username/`Text`, Personal access token/`Secret`, SSH private key/`MultilineSecret`. Server is Host/`Text`, Port/`Text`, Username/`Text`, Password/`Secret`, SSH private key/`MultilineSecret`. Database is Host/`Text`, Port/`Text`, Database/`Text`, Username/`Text`, Password/`Secret`. Aws is Access key ID/`Text`, Secret access key/`Secret`, Region/`Text`. ApiKey is Service/`Text`, API key/`Secret`, Endpoint/`Text`. WiFi is Network name/`Text`, Password/`Secret`. BankCard is Cardholder/`Text`, Number/`Secret`, Expiry/`Date`, CVV/`Secret`. Custom is an empty slice.
  - `Query` gains `pub expiring_only: bool`. `Debug` prints the flag and still prints `text_len` only.
  - `ItemSummary` gains `pub soonest_expiry: Option<CalendarDate>`. `Debug` may show the date. It is not a secret.
  - `Session::set_custom_fields(&mut self, id: ItemId, fields: Vec<CustomField>) -> Result<(), CoreError>` validates, refuses `InTrash` and `NotFound`, replaces `item.fields`, sets `updated` to `now_unix`, and saves through `commit_or_undo`. The undo puts the old vec back.
  - `Session::search` computes `today` once from `self.now_unix()` via `from_unix_secs`. When `expiring_only` is set, it keeps items for which `is_expiring(..., EXPIRING_WITHIN_DAYS)` is true. `text_matches` also returns true when any field label contains the needle. It must not call `value()` for the match.

| Test | Expect |
|---|---|
| `insert_remove_move_roundtrip` | insert at 0, move to the end, remove, and the vec is what those operations say |
| `eleventh_field_refused` | `insert_field` on 10 fields is `TooManyFields` and the vec is unchanged |
| `bad_index_refused` | `remove_field` at `len` is `NoSuchIndex` |
| `search_matches_label_not_secret` | needle `recovery-email` hits. Needle `EXAMPLE-field-secret` does not |
| `search_skips_text_value` | a `Text` value `public-note-EXAMPLE` does not hit. Its label does |
| `search_still_skips_password` | the existing password-not-searched case still passes |
| `soonest_of_three` | expiries on day 10, day 3, and none. Soonest is day 3. No expiry is `None` |
| `expiry_status_days` | tomorrow is `InDays(1)`, today is `InDays(0)`, yesterday is `Expired` |
| `expiring_window` | day 30 is in, day 31 is out, yesterday is in, no expiry is out |
| `expiring_uses_injected_clock` | `FakeClock` moved by one UTC day changes the hit, with no `SystemClock` |
| `set_fields_bumps_updated_and_undoes` | a store that fails the write leaves the old fields and the old `updated` |
| `set_fields_refuses_trash` | `InTrash` |
| `preset_server_is_labels_and_kinds` | five rows, the SSH row is `MultilineSecret`, and `preset_fields` has no value to read |
| `preset_custom_is_empty` | empty slice |
| `presets_fit_in_ten` | every preset's length is `<= MAX_CUSTOM_FIELDS` |

- [ ] **Step 1: Write the failing tests** in `fields.rs`, `search.rs`, and `session/items/tests.rs`.
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-core --locked --lib fields::` and `cargo test -p holm-core --locked --lib search::`
  - Expected: FAIL on the missing functions.
- [ ] **Step 3: Implement** the helpers, the search change, and `set_custom_fields`.
- [ ] **Step 4: Run the tests and confirm they pass.** Same commands. Also `cargo test -p holm-core --locked --lib session::items`.
- [ ] **Step 5: Record and teach**
  - DECISIONS lines for secrets-versus-labels and for the civil date. Lesson 53: a pure function that takes `today` instead of reading the clock, and why the search loop must not call `expose`. Kotlin: passing a `Clock` into a `UseCase`, not calling `System.currentTimeMillis` inside the matcher.
- [ ] **Step 6: Opus security review.** Search must be shown not to read `SecretText`. Nothing merges without an Opus yes.
- [ ] **Step 7: Commit**
  - `feat(core): edit custom fields, search labels, and compute expiry`

### Task 3: Export and import

**Issue:** new, label `p5b`.

**Files:**
- Modify:
  - `crates/holm-core/src/export.rs` and `crates/holm-core/src/export/tests.rs`
  - `crates/holm-core/src/import/{mod.rs, row.rs, csv.rs, json.rs, tests.rs}`
  - `crates/holm-core/src/plain/json.rs` (a writer next to the reader)
  - `crates/holm-cli/src/commands/transfer.rs` (`problem_text` arms only, so the new `RowProblem` variants compile)
  - `docs/DECISIONS.md`, `docs/learn/README.md`
- Create:
  - `docs/learn/54-four-cells-a-field.md`
- Do not change the browser fixtures except to confirm they still parse.

**Interfaces:**
- Consumes: `EXPORT_COLUMNS`, `write_csv`, `with_cells`, `push_quoted`, `quoted_len`, `ROW_END`, `Col`, `NAMES`, `RawRow`, `same_item`, `Session::export_csv`, `Session::check_password`, `parse`.
- Produces:
  - `EXPORT_COLUMNS` grows from 14 to 54, the new names in the CSV section of this plan, in slot order. `COLUMNS` and `SEPARATORS` follow `EXPORT_COLUMNS.len()` as they do now.
  - `pub fn export_json(&mut self, password: &MasterPassword) -> Result<SecretBuf, CoreError>` on `Session`. Same password check, same trash exclusion, same title order, same warning. The bytes are one JSON array of flat string objects.
  - `RowProblem::BadFieldKind`, `RowProblem::BadDate`, `RowProblem::FieldGap`. No variant holds a cell.
  - `Col` gains the forty field columns. `NAMES` gains one `holm(...)` row per column. `COLS` becomes 54. `RawRow`'s array grows with `COLS`.
  - `build` in `import/row.rs` fills `ItemInput.fields` from the packed slots after the type checks it already does.

| Test | Expect |
|---|---|
| `export_header_has_54_columns` | the header row is `EXPORT_COLUMNS` in order, and the first 14 names are unchanged |
| `export_import_roundtrip_custom_fields` | one item, four kinds, one expiry, a multiline value with a quote and a newline. CSV out and back matches bytes of each secret |
| `json_export_import_roundtrip` | the same item through `export_json` and `parse(..., Json)` |
| `old_csv_has_no_fields` | a 14-column row imports with `fields` empty |
| `field_gap_is_a_row_error` | `field2_label` set and slot 1 empty is `FieldGap`, and the row is skipped |
| `bad_kind_is_a_row_error` | kind `password` is `BadFieldKind` |
| `bad_expiry_is_a_row_error` | `2026-13-01` and `2026-11-05T00:00:00Z` are `BadDate` |
| `empty_secret_slot_imports` | label and kind set, value empty, is an empty `SecretText` |
| `ten_fields_import` | slot 10 imports. A header that repeats `field1_label` is still `DuplicateColumn` |
| `formula_still_unescaped` | a secret starting with `=` is exported unchanged |
| `browser_fixtures_unchanged` | the Chrome, Firefox, and Safari fixtures still parse to the same row counts |
| `same_item_sees_custom_fields` | two rows equal except in a custom secret are not duplicates |
| `export_json_needs_password` | a wrong password is `WrongPassword` and is throttled, same as CSV |
| `export_debug_has_no_secret` | a failed import error's `Display` and `Debug` do not contain `EXAMPLE` |

- [ ] **Step 1: Write the failing tests** in `export/tests.rs` and `import/tests.rs`.
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-core --locked --lib export::` and `cargo test -p holm-core --locked --lib import::`
  - Expected: FAIL. The header is still 14 columns.
- [ ] **Step 3: Implement** the columns, the JSON writer, and the row builder. `problem_text` gains three arms with fixed sentences and no cell text.
- [ ] **Step 4: Run the tests and confirm they pass.** Same commands, plus `cargo test -p holm-core --locked --test import_props` if a property mentions columns.
- [ ] **Step 5: Re-seed note.** Add one CSV and one JSON seed that contain `field1_label` under `fuzz/seeds/import_csv/` and `fuzz/seeds/import_json/`. The targets already call `import::parse`. No new target.
- [ ] **Step 6: Record and teach**
  - DECISIONS line for the four cells. Lesson 54: measure-then-fill when a cell can hold a newline, and why a nested JSON object would be a second parser. Kotlin: a column list, not a `JsonObject` inside the cell.
- [ ] **Step 7: Opus security review.** Quoting, duplicates, and "no secret in the error". Nothing merges without an Opus yes.
- [ ] **Step 8: Commit**
  - `feat(core): import and export custom fields as flat cells`

### Task 4: CLI show, add, and edit

**Issue:** new, label `p5b`.

**Files:**
- Modify:
  - `crates/holm-cli/src/lib.rs` (`USAGE`)
  - `crates/holm-cli/src/args.rs`
  - `crates/holm-cli/src/commands/{read.rs, write.rs, copy.rs, transfer.rs}`
  - `crates/holm-cli/src/output.rs` (the arms Task 1 added, if a sentence is still a stub)
  - `docs/DECISIONS.md`, `docs/learn/README.md`
- Create:
  - `docs/learn/55-secrets-at-the-prompt.md`
- Tests live in `crates/holm-cli/tests/`. The shell uses `parse`, so a new flag works there without a second parser.

**Interfaces:**
- Consumes: `HIDDEN`, `CopyField`, `value_of`, `copy_and_wait`, `PendingClear`, `GetArgs`, `AddArgs`, `EditArgs`, `ExportArgs`, `term.secret`, `clean`, `preset_fields`, `set_custom_fields`.
- Produces:
  - `CopyField::Custom(u8)` stores a 0-based index.
  - Parse `--copy field=N` with N in 1..=10. Anything else is `BAD_FIELD`.
  - `pub enum FieldEdit { None, Add { label: String, kind: FieldKind, expiry: Option<CalendarDate> }, Remove { position: u8 }, Move { from: u8, to: u8 }, Set { position: u8, expiry: ExpiryEdit } }`
  - `pub enum ExpiryEdit { Unchanged, Clear, Set(CalendarDate) }`
  - `EditArgs` gains `pub fields: FieldEdit`. `AddArgs` gains `pub preset: Option<FieldPreset>`.
  - `ExportArgs` gains `pub format: Option<ImportFormat>`. `--format json` calls `export_json`. `--format csv` stays `export_csv`. `--format` together with `--backup` is `CONFLICT`. The default with no flag stays CSV.
  - `ListArgs` gains `pub expiring: bool` from `--expiring`. It sets `Query.expiring_only`. `list` still prints four tab-separated columns.
  - New usage errors, fixed text: `SECRET_ON_COMMAND_LINE` = "A secret is typed at the prompt, not on the command line." `BAD_PRESET` = "The preset must be email, cloudflare, github, server, database, aws, api-key, wifi, bank-card or custom." `BAD_KIND` = "The kind must be text, secret, multiline or date." `BAD_DATE` = "The date must be YYYY-MM-DD."
  - `get` prints, after the built-in fields, one line per custom field: `field {n}: {label} ({kind}) = {shown}` and, when set, `field {n} expiry: {YYYY-MM-DD}`. `shown` is `clean(text)` for text, `format_date` for a date, and `HIDDEN` for secret and multiline. `n` is 1-based.
  - `--copy field=N` loads the value in `value_of` and passes it to `copy_and_wait`. It never writes the value to stdout. An empty value is `EmptyField`. An index past the item's fields is `NoSuchField`. No second master-password prompt.
  - `holm add --preset NAME` stores that preset's fields with empty values (a date field stores no date value: skip date rows on add, or store them only when the user later sets them). Date rows in a preset are stored with an empty reminder and a value of `CalendarDate` only when the user sets one. On add, a `Date` preset row is omitted until `edit` sets it, so we never invent a day. Print `Added {n} custom fields with empty values.` when `n > 0`. Do not prompt for each one during `add`.
  - `holm edit --field-add LABEL --kind KIND [--expiry YYYY-MM-DD]`. For `secret` and `multiline`, the value comes from `term.secret` and `--value` is `SECRET_ON_COMMAND_LINE`. For `text` and `date`, `--value` is required. `--field-remove N`, `--field-move N --to M`, `--field-set N` with the same value rule. Positions are 1-based on the command line and 0-based in `insert_field`.
  - `Debug` of `EditArgs` and `AddArgs` prints lengths and kinds, not label text the user might have used as a secret. It must not be able to hold a secret value, because the secret never enters the struct.

| Test | Expect |
|---|---|
| `get_hides_custom_secrets` | stdout contains the label and `(hidden)`, and does not contain `EXAMPLE-field-secret` |
| `get_shows_custom_text_and_date` | the text value and `2026-11-05` are shown |
| `copy_custom_does_not_print_the_secret` | stdout has no secret. The fake clipboard receives it. After the wait, `PendingClear` clears it |
| `copy_custom_empty_is_an_error` | `EmptyField` |
| `add_preset_empty_values` | `--preset server` stores five fields, secrets empty, kinds as in `preset_fields` |
| `edit_field_add_prompts_for_secret` | the hidden prompt is used, and argv has no secret |
| `secret_value_rejected_on_command_line` | `--kind secret --value EXAMPLE` is `SECRET_ON_COMMAND_LINE` and the vault is unchanged |
| `edit_field_remove_and_move` | remove and move match `remove_field` and `move_field` |
| `list_stays_four_columns` | a line still has three tabs. `--expiring` drops an item whose expiry is 31 days out |
| `search_finds_label` | `--search` hits a label and misses a secret value |
| `export_format_json` | `--format json` writes `[` and round-trips through `parse`. `--format json --backup` is `CONFLICT` |
| `args_debug_has_no_secret` | `Debug` of a parsed edit does not contain `EXAMPLE` |

- [ ] **Step 1: Write the failing tests** in `crates/holm-cli/tests/read_commands.rs` and `write_commands.rs`.
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-cli --locked --test read_commands` and `cargo test -p holm-cli --locked --test write_commands`
  - Expected: FAIL. `--preset` is an unknown flag.
- [ ] **Step 3: Implement** the flags, `get`, and the edit path. Update `USAGE` so `--search` mentions a custom field's name, and `--copy` mentions `field=N`.
- [ ] **Step 4: Run the tests and confirm they pass.** Same commands, plus `cargo test -p holm-cli --locked --test shell`.
- [ ] **Step 5: Record and teach**
  - DECISIONS line for the prompt. Lesson 55: a secret that never enters the args struct cannot appear in `Debug`. Kotlin: reading a password with `Console.readPassword`, not `args`.
- [ ] **Step 6: Opus security review.** Stdout, argv, and the clipboard clear. Nothing merges without an Opus yes.
- [ ] **Step 7: Commit**
  - `feat(cli): show and edit custom fields without printing secrets`

### Task 5: GUI detail and editor

**Issue:** new, label `p5b`.

**Files:**
- Modify:
  - `crates/holm-gui/src/screens/item_view.rs`
  - `crates/holm-gui/src/screens/login_form.rs` (keep `fields` on take and fill)
  - `crates/holm-gui/src/screens/mod.rs`
  - `crates/holm-gui/src/secret_input.rs`
  - `crates/holm-gui/src/widgets/secret_field.rs`
  - `crates/holm-gui/src/messages.rs` (`ALL` grows with every new constant)
  - `docs/DECISIONS.md`, `docs/learn/README.md`
- Create:
  - `crates/holm-gui/src/screens/fields.rs`
  - `crates/holm-gui/tests/custom_fields.rs` (`#![cfg(target_os = "macos")]`)
  - `docs/learn/56-paint-the-secret.md`

**Interfaces:**
- Consumes: `paint_secret`, `copy`, `RevealField`, `ItemView`, `secret_field`, `expose_for_paint`, `ITEM_SECRET_CAP`, `REHIDE_PASSWORD_SECS`, `DOTS`, `FieldIo`, `preset_fields`, `try_field`.
- Produces:
  - `pub const MULTILINE_SECRET_CAP: usize = holm_core::rules::MAX_MULTILINE_SECRET_BYTES;`
  - `SecretInput::with_multiline_capacity(cap: usize) -> SecretInput`. `push_str` and `try_push_str` on that buffer keep `\n` and `\r` and still drop `\0` and every other control. `with_capacity` stays single-line. `from_secret` keeps the buffer's newline flag so a reload does not change the rule.
  - `pub(crate) fn secret_area(...)` in `secret_field.rs`, same `PasswordInput` AccessKit role and the same "label only, no value" rule as `secret_field`. The box is tall enough for several lines of dots. Hold-to-reveal paints with `paint_secret`, not a single clipped line. Do not use `egui::TextEdit` for this buffer.
  - `RevealField::Custom(u8)`. `shows_for` is `REHIDE_PASSWORD_SECS`.
  - `pub(crate) struct FieldEditor` in `screens/fields.rs`. It owns the draft `Vec` of label `LineBuf`s, kind, secret buffers, date text, and reminder text. `Debug` prints lengths and kinds only.
  - Buttons, all fixed `&str` constants: `ADD_FIELD` = "Add field", `REMOVE_FIELD` = "Remove", `MOVE_UP` = "Move up", `MOVE_DOWN` = "Move down", `PRESET_LABEL` = "Preset", `REMIND_ON` = "Remind on". Reveal and Copy reuse `REVEAL_LABEL` and `COPY_LABEL`. The user-written label is a separate `ui.label`, never the button name and never concatenated with the value.
  - `pub(crate) const LABEL_SUGGESTIONS: &[&str]` is the preset labels plus `URL`, `Certificate`, `PIN`, `Recovery code`. Picking one fills the label buffer. The buffer stays editable. A label that is not in the list is saved if it passes `try_field`.
  - The preset picker is shown only while the draft list is empty. Applying it calls `preset_fields` and builds empty values. It does not run when the list is non-empty.
  - Changing kind clears that row's value buffers (`clear` on the `SecretInput`, empty the text). The old bytes are wiped by `SecretInput`'s own clear.
  - Save calls `set_custom_fields` with the draft moved into `CustomField`s. Cancel drops the editor. Drop wipes the secret buffers.
  - The detail view lists every field for every item type. Text is a plain label. A date is `format_date`. Secret and multiline use the `secret_row` path: `DOTS`, Reveal, Copy, and `paint_secret` while revealed. Copy calls the existing `copy`, which sets `io.copied`, so `HolmApp` builds the `PendingClear`.
  - `LoginForm` carries `fields` through `from_item`, `take_input`, and `from_input`. A new login shows the preset picker. Editing a login does not drop fields that were already stored.
  - Built-in fields of crypto, phrase, and note items stay read-only (`EDIT_IN_CLI`). Their custom fields still use `FieldEditor`.

| Test | Expect |
|---|---|
| `custom_secret_hidden_until_reveal` | the detail view shows `DOTS` and no `EXAMPLE-field-secret`. After Reveal, `paint_secret` has drawn it |
| `custom_secret_not_in_accesskit` | hidden and revealed, no AccessKit node label or value contains `EXAMPLE-field-secret`. The Reveal button's label is `REVEAL_LABEL` |
| `custom_copy_sets_pending_clear` | Copy sets `io.copied` to the secret and does not use egui `copy_text` |
| `reveal_hides_after_30s` | at 29 s it still shows. At 30 s `ItemView::tick` hides it. Blur hides it |
| `preset_fills_labels_and_kinds_only` | Server fills five rows, secret buffers empty |
| `preset_hidden_when_fields_exist` | a stored field means no preset button |
| `reorder_up_down` | Move down swaps two rows. Move up is disabled on the first row |
| `add_field_stops_at_10` | the Add button is disabled at 10 |
| `label_suggestion_fills_and_free_text_stays` | a suggestion fills the box, then typed text replaces it and still saves |
| `kind_change_wipes_the_value` | Secret to Text leaves the text buffer empty and `SecretInput` empty |
| `multiline_keeps_newlines` | a paste of `-----BEGIN OPENSSH PRIVATE KEY-----\nEXAMPLE\n` round-trips with the newline |
| `login_edit_keeps_custom_fields` | save of a login title leaves the custom secret in place |
| `date_field_shows_iso` | the detail view shows `2026-11-05` and the reminder under `Remind on` |
| `editor_debug_has_no_secret` | `Debug` of `FieldEditor` does not contain `EXAMPLE` |

- [ ] **Step 1: Write the failing tests** in `custom_fields.rs` and, for the buffer, `secret_input.rs` (`multiline_keeps_newlines` can live there).
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-gui --locked --test custom_fields` and `cargo test -p holm-gui --locked --lib secret_input`
  - Expected: FAIL. The detail view has no custom rows.
- [ ] **Step 3: Implement** the editor, the detail rows, and the multiline buffer. Add every new message constant to `ALL`.
- [ ] **Step 4: Run the tests and confirm they pass.** Same commands. Also `cargo test -p holm-gui --locked --test item_types` so the four built-in views still open.
- [ ] **Step 5: Record and teach**
  - DECISIONS line for paint versus AccessKit. Lesson 56: `paint_secret` allocates no widget, so AccessKit has no node to put the secret in. Kotlin: a `Canvas` draw, not a `BasicTextField`.
- [ ] **Step 6: Opus security review.** AccessKit tree, kind-change wipe, and the login form keeping fields. Nothing merges without an Opus yes.
- [ ] **Step 7: Commit**
  - `feat(gui): edit custom fields without putting secrets in AccessKit`

### Task 6: List badge and the Expiring chip

**Issue:** new, label `p5b`.

**Files:**
- Modify:
  - `crates/holm-gui/src/rows.rs`
  - `crates/holm-gui/src/screens/vault.rs`
  - `crates/holm-gui/src/messages.rs`
  - `docs/DECISIONS.md`, `docs/learn/README.md`
- Create:
  - `crates/holm-gui/tests/expiring.rs` (`#![cfg(target_os = "macos")]`)
  - `docs/learn/57-a-badge-from-a-date.md`

**Interfaces:**
- Consumes: `ItemSummary::soonest_expiry`, `ExpiryStatus`, `expiry_status`, `is_expiring`, `Query.expiring_only`, `build_rows`, `CHIP_ALL`, `CHIP_NONE`, the chip row in `VaultView::show_list`.
- Produces:
  - `pub enum ExpiryBadge { InDays(u32), Expired }` on the GUI side, copied from `ExpiryStatus` so a row does not borrow the session.
  - `ItemRow` gains `pub expiry_badge: Option<ExpiryBadge>`. `Debug` prints the badge and still prints title length, not the title.
  - `build_rows` takes `today: CalendarDate` and fills the badge from `soonest_expiry` via `expiry_status`. No call to `FieldValue`.
  - `pub(crate) fn expiry_badge_line(badge: ExpiryBadge) -> String` in `messages.rs`. `InDays(0)` is `Expires today`. `InDays(1)` is `Expires in 1 day`. `InDays(n)` is `Expires in {n} days`. `Expired` is `Expired`.
  - `pub(crate) const CHIP_EXPIRING: &str = "Expiring";`
  - `VaultView` gains `expiring: bool`, next to `chip`, not inside `CategoryFilter`. The chip is its own `selectable_label`. Turning it on sets `Query.expiring_only` and leaves the category chip as it was. The badge is a `ui.small` under the subtitle. It is ordinary text. It contains no field value, so AccessKit may read it.

| Test | Expect |
|---|---|
| `badge_expired` | yesterday's expiry renders `Expired` |
| `badge_in_n_days` | 5 days out renders `Expires in 5 days`. 1 day out renders `Expires in 1 day` |
| `badge_today` | the UTC date of the fake clock renders `Expires today` |
| `badge_is_the_soonest` | expiries in 9 days and 2 days render `Expires in 2 days` |
| `badge_omitted_when_no_expiry` | no `Expires` node on that row |
| `expiring_chip_filters` | the chip hides an item at 31 days and shows one at 30 days and one already expired |
| `expiring_chip_combines_with_category` | Work plus Expiring shows only the Work item that is expiring |
| `badge_has_no_secret` | the row's AccessKit text does not contain `EXAMPLE-field-secret` or the field label's value |

- [ ] **Step 1: Write the failing tests** in `rows.rs` (the badge value) and `expiring.rs` (the chip and the drawn line).
- [ ] **Step 2: Run them and confirm they fail**
  - Run: `cargo test -p holm-gui --locked --lib rows` and `cargo test -p holm-gui --locked --test expiring`
  - Expected: FAIL. `ItemRow` has no badge.
- [ ] **Step 3: Implement** the badge and the chip. Add `CHIP_EXPIRING` to `ALL`.
- [ ] **Step 4: Run the tests and confirm they pass.** Same commands. Also `cargo test -p holm-gui --locked --test search` so the category chips still filter.
- [ ] **Step 5: Record and teach**
  - DECISIONS line for the badge. Lesson 57: a `Copy` enum computed once when the rows are built, so a frame does not walk the vault. Kotlin: mapping a list in the `ViewModel`, not in composition.
- [ ] **Step 6: Opus security review.** The badge text and the chip's filter. Nothing merges without an Opus yes.
- [ ] **Step 7: Commit**
  - `feat(gui): show the soonest field expiry on the list`

### Task 7: Docs

**Issue:** new, label `p5b`. Docs only. No code unless a comment in `CRYPTO.md` is wrong about a name from Tasks 1 to 6.

**Files:**
- Modify:
  - `docs/CRYPTO.md` (the body section and the import/export section)
  - `docs/DECISIONS.md` (the old "revisit on the first schema bump" line points at the Task 1 decision. Do not delete it)
  - `docs/learn/README.md` (rows 52 through 58, if a row was missed)
  - `fuzz/README.md` (one sentence: a version-1 body re-encodes as version 2, and stability is the second encode)
- Create:
  - `docs/learn/58-the-chapter-and-the-bytes.md`
- Do not rewrite the sealed golden. Do not bump `FORMAT_VERSION`.

The body section keeps the schema-1 description and adds schema 2 beside it:
- Version byte 1 or 2. Encode writes 2.
- Version 1 items have no `fields` list. They decode as an empty list.
- Version 2 adds `fields` last on each item: position, label, value enum (`Text`, `Secret`, `MultilineSecret`, `Date`), optional expiry.
- Above 2 is refused and not rewritten. Version 0 is unknown.
- The string cap, the trailing-byte rule, and the post-decode field rules are unchanged.
- `MAX_MULTILINE_SECRET_BYTES`, the 270848-byte text total, and the 272000-byte item ceiling.
- Dates are `CalendarDate`, UTC "today", no notifications.

The import/export section lists the forty columns, the packing rule, the kind strings, `YYYY-MM-DD`, and `export_json`.

Lesson 58: why this chapter and `default_body_golden` have to name the same bytes, and why the sealed golden file stays schema 1. Kotlin: a format note checked against a fixture, not against memory.

- [ ] **Step 1: Update the docs** to the names and numbers the code actually uses after Tasks 1 to 6.
- [ ] **Step 2: Check**
  - Run: `cargo test -p holm-core --locked --lib body::tests::default_body_golden` and `cargo test -p holm-core --locked --test golden_vault`
  - Expected: PASS. The docs quote those bytes.
- [ ] **Step 3: Opus security review of the branch.** Diff against the base, with the five review-focus items. Nothing merges without an Opus yes.
- [ ] **Step 4: Commit**
  - `docs: describe body schema 2 and custom fields`

## Last check before the PR

- `cargo tree -p holm-core -e normal --locked` matches the base.
- `FORMAT_VERSION` is 1. `BODY_SCHEMA_VERSION` is 2.
- `scripts/ci-local.sh` prints `ALL GATES PASSED`.
- Opus has said yes on each task and on the branch.
