# Phase B plan: decrypt on demand (format v2, body v4)

**Spec:** `docs/superpowers/specs/2026-11-07-phase-b-decrypt-on-demand-design.md`. Section
numbers below (§) refer to it. If this plan and the spec disagree, the spec wins and the plan
is fixed.

**Goal:** while unlocked, RAM holds the DEK, the header, a non-secret index and per-item
ciphertexts. A secret is decrypted only for a reveal, copy, edit, export or password change.

**Rules (same as Phase A and P5c):** one cargo or CI run at a time under `nice -n 19`; one
issue and one Rust lesson in `docs/learn` per task; push only when `scripts/ci-local.sh` is
green; no GitHub Actions; no new dependency (none is needed); `holm-crypto` is not changed.
Opus security review on B2, B3, B5, B8, B9 and B10 before merge; code review on the rest. Nothing
merges without an Opus yes.

**Order:** B1 to B5 add format code that nothing calls yet. B6 (after B3 and B4, which give it
`ItemEntry` and the split) and B7 move every caller to the new read API while the session still
holds today's data, so the GUI and CLI change without a format change. B8 adds the store
methods. B9 swaps the session internals to format v2. B10 adds the backup prompts. B11 and B12
measure and document. Task ids B1 to B9 are the same as in the first draft.

## Tasks

| # | Task | Depends on |
|---|---|---|
| B1 | Padding with a block size | none |
| B2 | Header v2 | none |
| B3 | Index and record wire | B1 |
| B4 | Split and join | B3 |
| B5 | Envelope v2, tamper tests, golden v2 | B2, B4 |
| B6 | Read API on today's session; CLI | B3, B4 (parallel with B5) |
| B7 | GUI on the read API; Q1 Text hint | B6 |
| B8 | `VaultStore::keep_backup_copy`, `remove_backup_copy` | none |
| B9 | Session on format v2, migration, write gate | B5, B7, B8 |
| B10 | Migration backup prompts (Q2) | B9 |
| B11 | Performance, compat and memory checks | B9 |
| B12 | Docs | B10, B11 |

---

### B1 Padding with a block size

**Files:** `crates/holm-core/src/padding.rs`.

**Interfaces:**
- `pub(crate) fn pad_to(plaintext: &[u8], block: usize, max_padded: usize) -> Result<SecretBuf, VaultError>`
- `pub(crate) fn unpad_from(padded: &[u8], block: usize) -> Result<SecretBuf, VaultError>`
- `pad` and `unpad` stay, as thin calls with `PAD_BLOCK` and `MAX_PADDED_LEN`, so v1 behaviour
  and its tests do not move.
- `pub const RECORD_PAD_BLOCK: usize = 256;` `pub const MAX_RECORD_PADDED: usize = 262_144;`
- Compile-time asserts: `MAX_RECORD_PADDED % RECORD_PAD_BLOCK == 0`, and the worst record (§2.8)
  plus framing fits.

**Tests:** existing padding tests unchanged; `record_pad_canonical` (only one padded form per
input at block 256), `record_pad_boundaries` (0, 252, 253 bytes), `record_pad_cap`,
`unpad_from_rejects_extra_block`, proptest `pad_to_roundtrip_any_block`.

**Done when:** v1 golden still opens; no caller changed.

---

### B2 Header v2

**Files:** `crates/holm-core/src/format.rs`, `fuzz/fuzz_targets/parse_header_v2.rs`,
`fuzz/Cargo.toml`, `fuzz/seeds/parse_header_v2/`.

**Interfaces:**
- `pub const FORMAT_V1: u16 = 1; pub const FORMAT_V2: u16 = 2;` (`FORMAT_VERSION` becomes the
  write version, 2, at B9; until then it stays 1).
- `pub const HEADER_LEN_V2: usize = 172; pub const KEY_BLOCK_LEN: usize = 132;`
- `pub enum ParsedHeader<'a> { V1(Header, &'a [u8]), V2(HeaderV2, &'a [u8], &'a [u8]) }`
  (v2 gives the index ciphertext and the records region as slices of the file).
- `pub fn parse_any(file: &[u8]) -> Result<ParsedHeader<'_>, FormatError>`: shared checks for
  bytes 0..132, then version dispatch. `Header::parse` keeps its v1-only behaviour and compares
  against `FORMAT_V1`, not `FORMAT_VERSION`, so it stays v1-only when `FORMAT_VERSION` becomes 2.
- `pub struct HeaderV2 { kdf, salt, wrap_nonce, wrapped_dek, index_nonce, index_len, records_len }`
  with `encode() -> [u8; HEADER_LEN_V2]` and `key_block(&self) -> [u8; KEY_BLOCK_LEN]`.
- New `FormatError` variants: `IndexLength`, `RecordsLength` (framing). A version above 2 stays
  `UnsupportedVersion(v)`; its message changes to say a newer Holm is needed.

**Tests:** `header_v2_golden` (exact 172 bytes for fixed fields), `header_v2_roundtrip`,
`v2_framing_exact_sum`, `v2_index_len_not_block_multiple`, `v2_records_len_not_block_multiple`,
`v2_lengths_overflow_u64`, `v2_shares_v1_key_block_checks` (flags, KDF id, reserved, policy),
`version_3_unsupported`, `header_parse_is_v1_only` (a valid v2 header gives
`UnsupportedVersion(2)` from `Header::parse` both before and after the B9 bump), proptest in `tests/format_props.rs`:
`parse_any_never_panics`, `v2_accepted_reencodes_identical`.

**Done when:** fuzz target runs 10 minutes clean locally; v1 parse tests unchanged.

---

### B3 Index and record wire

**Files:** `crates/holm-core/src/wire.rs` (new structs beside the v1 to v3 ones),
new `crates/holm-core/src/index.rs` (types), new `crates/holm-core/src/record.rs` (types),
`fuzz/fuzz_targets/decode_index.rs`, `fuzz/fuzz_targets/decode_record.rs`, seeds.

**Interfaces (types, all without `Clone`, `Debug` prints counts and kinds only):**
- `pub struct ItemEntry` with `pub(crate)` fields per §2.6 and public getters mirroring
  today's `Item` getters (`id`, `title`, `category`, `favourite`, `created`, `updated`,
  `trashed`, `item_type`) plus `public(&self) -> &EntryPublic` and `fields(&self) -> &[FieldEntry]`.
- `pub enum EntryPublic { Login { username: Text, urls: Vec<Text>, has_password: bool, has_notes: bool }, CryptoAddress { chain: Text, has_address: bool, has_memo: bool, has_notes: bool }, RecoveryPhrase { has_notes: bool }, SecureNote { has_body: bool } }`
- `pub struct FieldEntry { position, label: Text, kind: FieldEntryKind, expiry: Option<CalendarDate> }`;
  `pub enum FieldEntryKind { Text(Text), Secret, MultilineSecret, Date(CalendarDate), RecoveryCodes { used: Vec<bool> } }`
- `pub(crate) struct RecordRef { generation: u64, nonce: [u8; 24], ct_len: u32 }` inside each entry.
- `pub(crate) struct Index { settings, categories, entries: Vec<ItemEntry>, next_category_id, migration_backup: Option<BackupNote> }`;
  `pub(crate) struct BackupNote { tag: String, prompt: BackupPrompt }`,
  `pub(crate) enum BackupPrompt { AfterUnlock, AfterPasswordChange, Done }` (§4.3).
  with `encode() -> Result<SecretBuf, BodyError>` and `decode(&[u8]) -> Result<Index, BodyError>`.
- `pub(crate) struct RecordSecrets` (type tag, sealed built-in values, sealed custom values),
  every value a `SecretText` or `GatedSecret`;
  `encode() -> Result<SecretBuf, BodyError>`, `decode(&[u8], &ItemEntry) -> Result<RecordSecrets, BodyError>`
  (decode includes the §2.6 cross-check).
- `pub const BODY_SCHEMA_V4: u16 = 4; pub const RECORD_SCHEMA_V1: u16 = 1;`

**Rules:** `BoundedVec` for entries (`MAX_ITEMS`), URLs, fields, codes, used flags; at most 1024
reserved up front; `WireStr` for every string; trailing bytes refused; `ct_len` and generation
ranges per §2.8; schema below 4 is `Malformed`, above 4 `NewerSchema`.

**Tests:** `default_index_golden` (52 bytes, §2.6), `index_backup_note_roundtrip`,
`index_backup_note_bad_tag_malformed`, `index_rejects_schema_3`,
`index_rejects_newer_schema`, `index_entry_count_cap_before_reserve`,
`index_ct_len_out_of_range`, `index_generation_zero_malformed`, `record_cross_check_type`,
`record_cross_check_positions`, `record_cross_check_code_count`,
`record_cross_check_presence_flags`, `record_trailing_bytes`, `maxed_record_fits_cap`,
`entry_debug_has_no_text`, `record_debug_has_no_text`; proptests in a new
`tests/index_props.rs`: `index_roundtrip_any`, `record_roundtrip_any`.

---

### B4 Split and join

**Files:** `crates/holm-core/src/record.rs`, `crates/holm-core/src/index.rs`,
`crates/holm-core/src/item.rs` (only `pub(crate)` constructors).

**Interfaces:**
- `pub(crate) fn split(item: Item) -> (ItemEntry without RecordRef, RecordSecrets)`; consumes
  the item so no second copy of its secrets exists.
- `pub(crate) fn join(entry: &ItemEntry, secrets: RecordSecrets) -> Item`.
- `pub(crate) fn take_slot(secrets: RecordSecrets, slot: SecretSlot) -> Result<SecretText, CoreError>`
  (moves the one value out; the rest drops).
- `pub enum SecretSlot { Password, Notes, Address, Memo, Body, Field { position: u8 }, Code { position: u8, index: u8 } }`

**Tests:** proptest `split_join_identity_any` (every item kind, fields and codes),
`split_sets_presence_flags`, `take_slot_each_kind`, `take_slot_wrong_kind_refused`,
`take_slot_phrase_refused`.

---

### B5 Envelope v2, tamper tests, golden v2

**Files:** new `crates/holm-core/src/envelope_v2.rs`, `crates/holm-core/src/fuzzing.rs`
(v2 helpers behind the existing `fuzzing` feature), new `crates/holm-core/tests/tamper_v2.rs`,
new `crates/holm-core/tests/golden_vault_v2.rs`, new `crates/holm-core/tests/vectors/golden-v2.vault`,
`fuzz/fuzz_targets/open_v2_fixed_key.rs`.

**Interfaces (all `pub(crate)` unless noted):**
- `pub(crate) struct SealedRecord { generation: u64, nonce: [u8; 24], ct: Box<[u8]> }`
- `fn record_aad(key_block: &[u8; 132], id: ItemId, generation: u64) -> [u8; 164]`
- `fn seal_record(dek, key_block, id, generation, secrets: &RecordSecrets) -> Result<SealedRecord, VaultError>`
  (encode, `pad_to` 256, `aead::seal` with `Nonce::random()`)
- `fn open_record(dek, key_block, id, &SealedRecord, &ItemEntry) -> Result<RecordSecrets, CoreError>`
  (`DamagedItem` on any failure)
- `fn assemble(keys: &mut VaultKeys, index: &Index, records: &[&SealedRecord]) -> Result<Vec<u8>, VaultError>`
  (size check first, then seal index, header, records, filler)
- `fn open_v2_with_kek(file, kek) -> Result<(VaultKeys, Index, Vec<SealedRecord>), VaultError>`
  and `open_v2(file, password)` (KDF, unwrap, index, framing, slice copy).
- `VaultKeys` gains the v2 header and a `key_block()` getter; `holm-crypto` is untouched.

**Tests:** `record_aad_golden`; every tamper test in spec §7.3; `records_never_share_a_nonce`;
`golden_v2_opens` and `golden_v2_rebuilds` (independent writer calls `chacha20poly1305`
directly with fixed fills, as `golden_vault.rs` does; `write_golden_v2` is `#[ignore]`);
`v2_file_never_over_cap` (assemble refuses before sealing).

**Done when:** fuzz `open_v2_fixed_key`, `decode_index`, `decode_record` each run 10 minutes clean.

---

### B6 Read API on today's session; CLI

The new calls are added over the current resident `VaultData`, so callers can move before the
format does.

**Files:** `crates/holm-core/src/session/items.rs`, `crates/holm-core/src/search.rs`,
`crates/holm-core/src/error.rs`, `crates/holm-cli/src/commands/{read,copy,write}.rs`.

**Interfaces:**
- `Session::entry(&self, id) -> Result<EntryView<'_>, CoreError>` and
  `Session::active_entries(&self)`. `EntryView<'a>` is a permanent borrowed wrapper with the
  `ItemEntry` getters and presence flags, no secret. In B6 it wraps the resident `Item`; in B9
  it wraps `&ItemEntry`. Its type and getters never change, so callers do not change again.
- `Session::reveal(&self, id, SecretSlot) -> Result<SecretText, CoreError>` (B6: copies the
  one value into a new `SecretText`).
- `Session::open_item(&self, id) -> Result<Item, CoreError>` (B6: deep copy into wiping types).
- `Session::set_code_used(&mut self, id, position: u8, index: u8, used: bool) -> Result<(), CoreError>`
- `CoreError::DamagedItem(ItemId)`, `CoreError::GenerationExhausted(ItemId)` and
  `CoreError::MigrationFailed` (unused until B9, mapped in the CLI and GUI messages now).
- `ItemSummary` built from entries; `soonest_expiry` and `codes_left` from field entries.
- `Session::item` and `active_items` become `pub(crate)` (tests and export only).

**CLI:** `holm get` reads entries and prints `(hidden)` for secrets; `--copy` uses `reveal`;
`holm edit` uses `open_item`; outputs byte-identical to today.

**Tests:** `reveal_each_slot`, `reveal_phrase_slot_refused`, `open_item_equals_stored`,
`set_code_used_saves`, `set_code_used_out_of_range`; existing CLI snapshot tests unchanged.

---

### B7 GUI on the read API

**Files:** `crates/holm-gui/src/screens/{item_view,vault,login_form,fields}.rs`,
`crates/holm-gui/src/rows.rs`, `crates/holm-gui/src/worker.rs`, `crates/holm-gui/src/messages.rs`.

**Changes:**
- `ItemView.revealed: Option<Revealed>` with `struct Revealed { slot: SecretSlot, until: Duration, text: SecretText }`.
  Reveal calls `session.reveal` once; paint reads `text`; every hide path sets `None`.
- Copy calls `session.reveal`, passes `expose()` to the clipboard, drops the value that frame.
- `show_item` takes the entry; empty rows hidden by presence flags.
- Edit: `session.open_item(id)` into `LoginForm::from_item`, then drop. `save_form` takes notes
  and extra URLs from one `open_item` call.
- Mark used or unused: `Job::SetCodeUsed { id, position, index, used }` replaces the deep-copy
  `SetFields` path.
- `messages::ITEM_DAMAGED` for `DamagedItem` (names the item), `messages::ITEM_EDIT_LIMIT`
  for `GenerationExhausted`, `messages::MIGRATION_FAILED`.
- Q1 hint: the custom field editor shows "Use a Secret field for sensitive values." under the
  Text kind (`messages::TEXT_FIELD_HINT`).

**Tests:** `item_view_holds_no_secret_before_reveal`, `reveal_drops_on_timer`,
`reveal_drops_on_blur`, `reveal_drops_on_select`, `copy_keeps_no_secret`,
`mark_used_sends_set_code_used`, `damaged_item_message`, `text_field_shows_secret_hint`; Phase A painting and AccessKit tests
unchanged and green.

---

### B8 `VaultStore::keep_backup_copy`, `remove_backup_copy`

**Files:** `crates/holm-core/src/store.rs`, `crates/holm-platform/src/fs_store.rs`,
`crates/holm-platform/tests/crash.rs`.

**Interface:** `fn keep_backup_copy(&mut self, tag: &str, bytes: &[u8]) -> Result<(), StoreError>`.
Writes `<vault file>.<tag>.bak` beside the vault: exclusive create, 0600, sync, directory sync.
Exists with equal bytes: `Ok`. Exists with other bytes: `StoreError::AlreadyExists`. `tag` is
checked to be `[a-z0-9-]{1,32}` so it cannot form a path. `MemStore` gets the same with
failure injection (`fail_backup_copy`).

`fn remove_backup_copy(&mut self, tag: &str) -> Result<(), StoreError>`: same tag check, removes
`<vault file>.<tag>.bak` only (no follow of symlinks), directory sync; missing file is
`StoreError::NotFound`. `backup_copy_exists(&self, tag) -> Result<bool, StoreError>` for the
prompt.

**Tests:** `backup_copy_creates_0600`, `backup_copy_same_bytes_ok`,
`backup_copy_other_bytes_refused`, `backup_copy_bad_tag_refused`,
`backup_copy_symlink_refused`, `remove_backup_copy_only_that_file`,
`remove_backup_copy_bad_tag_refused`, `remove_backup_copy_missing`, crash test `crash_during_backup_copy`.

---

### B9 Session on format v2, migration

The largest task. Split into commits in this order, each green: (a) state and v2 unlock,
(b) the write gate and commit with reuse, (c) v1 unlock with in-RAM migration, (d) migrating
first save, (e) export, import, backup, password change.

**Files:** `crates/holm-core/src/session/{mod,items,categories}.rs`,
`crates/holm-core/src/export.rs`, `crates/holm-core/src/import/mod.rs`,
new `crates/holm-core/src/migrate.rs`, `crates/holm-core/src/format.rs`
(`FORMAT_VERSION = 2`), `crates/holm-core/tests/golden_vault.rs` (add `golden_v1_migrates`),
`crates/holm-platform/tests/crash.rs`. `golden_v1_migrates` reopens the saved v2 bytes in a
new `Session` through `Session::unlock` with the password (Argon2 at `FLOOR`), not a fixed key.

**State:** `Unlocked { state: VaultState, dirty, idle, migration: Option<V1Origin> }`,
`VaultState { keys: VaultKeys, index: Index, records: Vec<SealedRecord> (index order) }`
(swapped only as a whole), `V1Origin { bytes: Vec<u8>, tag: String }`.

**Write gate:** `fn write_vault(&mut self, bytes: &[u8]) -> Result<(), CoreError>` is the only
caller of `store.replace` (commit, import, change_password). While `migration` is `Some`, it
first runs `keep_backup_copy(tag, v1 bytes)` and returns `MigrationFailed` without replacing if
that fails; after a good replace it sets the backup note and clears `migration`.

**Unlock:** the `KdfPolicy` pre-check (session/mod.rs ~201) uses `parse_any`, so a v2 file with
bad costs is refused before the throttle counts it. The v1 path (`migrate.rs`), while the KEK
exists: new random DEK, fresh wrap nonce, v2 key block, wrap under the v2 AAD; unwrap again and
compare in constant time; drop the KEK and the v1 DEK; seal and check every record; drop
`VaultData`. Any failure is `MigrationFailed`, nothing written.

**Behaviour:** per spec §3 and §4. Mutations seal the changed record before `commit_or_undo`;
the undo closure restores the old entry and the old `SealedRecord`. `export` opens one item at a
time and stops on the first `DamagedItem(id)`. `change_password` re-seals one record at a time
into a new `VaultState`, stops on `DamagedItem(id)` with nothing written, writes through the
gate, then swaps the whole `VaultState` on success and on `PasswordChangeUncertain`.
An edit of a record at generation `u64::MAX` returns `GenerationExhausted(id)` before sealing.
`EntryView` now wraps `&ItemEntry`. `Session::migration_pending()`.
Test-only `Session::resident_bytes()`.

**Tests:** all existing session, search, export, import and golden tests green unchanged;
`edit_reseals_only_that_record`, `public_change_reseals_no_record`,
`oversize_change_restores_old_record`, `change_password_reseals_all_new_key_block`,
`change_password_write_fails_keeps_old`, `backup_reuses_record_bytes`,
`migration_v3_to_v4_any`, `migration_from_v1_and_v2_bodies`, `golden_v1_migrates`,
`migration_backup_write_fails_vault_untouched`, `migration_replace_fails_then_retry`,
`migration_backup_exists_same_bytes`, `migration_backup_exists_other_bytes_refuses`,
`migration_lock_before_save_writes_nothing`, `migration_self_check_fails_writes_nothing`,
`migration_rewraps_under_v2_aad`, `v1_wrap_in_v2_header_fails`,
`change_password_while_migration_pending`, `import_while_migration_pending_takes_backup`,
`only_write_gate_replaces`, `change_password_uncertain_adopts_records`,
`change_password_damaged_record_stops`, `export_damaged_record_stops`,
`edit_at_max_generation_refused`, `kdf_policy_precheck_v2_uncounted`,
`newer_format_version_refused_untouched`, `damaged_record_reveal_is_damaged_item`,
`resident_state_has_no_secret_marker`, crash tests `crash_migration_after_backup`,
`crash_migration_during_replace`.

**Review:** Opus security review of the whole task, with the manual core check of §7.6.

---

### B10 Migration backup prompts (Q2)

Provisional owner ruling; the owner may override it (spec §13).

**Files:** `crates/holm-core/src/session/mod.rs`, `crates/holm-gui/src/screens/vault.rs`,
new `crates/holm-gui/src/screens/backup_prompt.rs`, `crates/holm-gui/src/messages.rs`,
`crates/holm-cli/src/main.rs`.

**Interfaces:** `Session::backup_prompt(&self) -> Option<BackupPrompt>`;
`Session::delete_migration_backup(&mut self) -> Result<(), CoreError>` (calls
`remove_backup_copy`, sets the note to `Done`, saves through the gate);
`Session::dismiss_backup_prompt(&mut self)` (keeps the file, keeps the note at the current
step). A good v2 unlock with a note shows `AfterUnlock`; a password change moves it to
`AfterPasswordChange`. A missing file clears the note. Holm never deletes without the user's
yes. The prompt text says deleting does not remove Time Machine copies or SSD remnants.
The CLI prints one stderr line when a note is pending and never deletes.

**Tests:** `backup_note_prompts`, `backup_prompt_after_unlock`,
`backup_prompt_stronger_after_password_change`, `backup_delete_clears_note`,
`backup_missing_file_clears_note`, `backup_never_deleted_without_yes`,
`cli_prints_backup_line`, `backup_prompt_mentions_snapshots`.

---

### B11 Performance, compat and memory checks

**Files:** ignored timing tests in `crates/holm-core/src/session/mod.rs` tests or a new
`crates/holm-core/tests/timing.rs`; `scripts/ci-local.sh` (compat step); new
`scripts/compat-old-binary.sh`; `scripts/measure-macos.sh` (v2 vault option).

**Tests:** `unlock_post_kdf_timing_10k`, `open_item_worst_timing`, `search_10k_timing`,
`save_one_edit_10k_timing` (targets in spec §8). `compat-old-binary.sh` builds the last 0.1.x
tag in a temp worktree, runs `holm list` on `golden-v2.vault`, and expects
`unsupported vault format version 2` with the file unchanged.

**Done when:** all three targets met in release, numbers in DECISIONS; if search misses, add
folded keys to `ItemEntry` and rerun.

---

### B12 Docs

**Files:** `docs/CRYPTO.md` (new "File layout (v2)", "Index and records", "Migration" sections;
v1 sections kept as the read path), `docs/THREAT-MODEL.md` (partial memory capture row, hibernation and
crash dumps as not closed, change-pattern note with count, boundaries and secret-versus-public
edits, backup copies sharing the key block, migration backup), `docs/DECISIONS.md` (Phase B section: spec §11, measured numbers),
`docs/manual/` (migration notice, how to revert), `docs/ROADMAP.md` (B done), README row, one
lesson per task in `docs/learn`.

**Done when:** every claim in CRYPTO.md and THREAT-MODEL.md for Phase B points at a test or is
marked as a limit.

## Done when (phase)

- `scripts/ci-local.sh` green, fuzz targets 10 minutes clean each, timing targets met.
- An unlocked vault holds no secret plaintext in resident state (test) and only the revealed
  value in a release core dump (manual check).
- The v1 golden still opens and migrates; the v2 golden opens and rebuilds.
- Opus yes on B2, B3, B5, B8, B9 and B10.
