# Phase B: decrypt on demand (format v2, body v4)

Date: 2026-11-07
Status: design, for review. Nothing here is built yet. Security decisions need an Opus yes before any code merges.
Builds on: `docs/CRYPTO.md` (format v1, body schema 3), `docs/THREAT-MODEL.md`, `docs/DECISIONS.md` (Phase A), `docs/ROADMAP.md` (Phase B row).

## 1. Goal

Today `Session::unlock` decrypts the whole body and keeps every item, secrets included, in
`Unlocked.data: VaultData` until lock. Every password, note, phrase and custom secret sits in
RAM for the whole unlocked time, in wiping types but in plaintext.

Phase B changes that. While the vault is unlocked, RAM holds:

- the data key (DEK) and the header, as today;
- a decrypted **index**: settings, categories and the public part of each item;
- each item's **sealed record**: ciphertext, not plaintext.

A secret is decrypted only when the user reveals or copies it, or opens the item to edit it.
The plaintext lives in a wiping type for as long as it is shown, then it is dropped.

Out of scope: protecting the DEK itself in RAM (see section 6), `mlock` (Phase A, A4 skipped),
whole-file rollback, and any change to the KDF or the AEAD.

## 2. The on-disk format

### 2.1 Overview

```
file = header v2 (172 bytes)
     || index ciphertext   (XChaCha20-Poly1305 under the DEK, padded to 16 KiB blocks)
     || records region     (record ciphertexts back to back, in index order, then zero filler)
```

The file has no public record boundaries. Where each record starts and ends, how many there
are and how long each one is: all of that is inside the encrypted index. Someone holding the
file sees three lengths: the header, the index ciphertext and the records region.

### 2.2 Header v2

All integers little-endian. Bytes 0 to 131 have exactly the v1 layout and meaning, so the
KDF, the salt and the DEK wrap do not change.

| Offset | Size | Field | Checked by |
|---|---|---|---|
| 0 | 8 | magic `HOLMVLT\0` | parser |
| 8 | 2 | format version, **2** | parser |
| 10 | 2 | flags, must be 0 | parser |
| 12 | 1 | KDF id, must be 1 | parser |
| 13 | 3 | reserved, zero | parser |
| 16 | 12 | Argon2 memory, iterations, parallelism | parser (policy), all AEADs |
| 28 | 32 | salt | all AEADs |
| 60 | 24 | wrap nonce | wrap AEAD, index AEAD, record AEADs |
| 84 | 48 | wrapped DEK | wrap AEAD, index AEAD, record AEADs |
| 132 | 24 | index nonce | index AEAD (nonce and AAD) |
| 156 | 8 | index ciphertext length, tag included | parser framing, index AEAD |
| 164 | 8 | records region length | parser framing, index AEAD |
| 172 | | end of header (`HEADER_LEN_V2` = 172) | |

- **Wrap AAD** is bytes `0..60`, unchanged from v1.
- **Index AAD** is bytes `0..172`, the whole header.
- **Key block** is bytes `0..132`: magic, version, KDF costs, salt, wrap nonce and wrapped DEK.
  It changes only on create and on a password change (which also makes a new DEK). It is part
  of every record's AAD.

### 2.3 What goes in the index and what is sealed

**Rule:** the index holds what Holm shows without a Reveal button. A record holds everything
behind Reveal, Copy or the phrase gate.

| Data | Where | Why |
|---|---|---|
| Settings, categories, next category id | index | Not secret. Needed at once. |
| Item id, type, title, category, favourite, created, updated, trashed | index | List, sort, filters. |
| Login username and URLs | index | Shown in the clear, searched, used as the list subtitle. Spec §8 treats them as display text, not secrets. Sealing them would make every keystroke in the search box decrypt every record. |
| Crypto chain | index | Shown in the clear, searched. |
| Custom field position, label, kind, expiry | index | Labels are searched; expiry drives the badge and the Expiring filter. |
| Custom `Text` and `Date` values | index | Shown in the clear today (DECISIONS P5b: "that text sits in the clear on screen"). |
| Recovery code `used` flags | index | "N of M left" and the list badge read them. Mark used becomes an index-only change. |
| Presence flags: has password, has notes, has address, has memo, has body | index | The detail view hides empty rows without decrypting. One bit each. |
| Record table entry: generation, nonce, ciphertext length | index | Integrity and framing (2.5). |
| Login password and notes | record | Behind Reveal. |
| Crypto address, memo, notes | record | Behind Reveal. |
| Recovery phrase and its notes | record | The phrase stays a `GatedSecret`. |
| Secure note body | record | Behind Reveal. |
| Custom `Secret` and `MultilineSecret` values | record | Behind Reveal. |
| Recovery code strings | record | Copy only, never painted. |

So the answer to "is username in the index?" is yes. The cost is stated in section 6: a memory
dump shows which accounts exist (titles, usernames, URLs), not their secrets.

**One record per item**, not one per field. Every item has exactly one record, even one with
no secret (an empty login), so the record count equals the item count and says nothing about
which items hold secrets. A reveal decrypts the item's record, takes the one field, and wipes
the rest within the same call.

### 2.4 Keys and nonces

Every record is sealed with the **DEK** and a **fresh random 24-byte nonce** from
`Nonce::random()`. No HKDF, no per-item subkeys.

Why:

- `hkdf`, `hmac` and `sha2` are not in `Cargo.lock` (checked 2026-11-07). Adding them is a new
  dependency and a new primitive. BLAKE2b is in the graph (Argon2 uses it, and `blake2` is a
  direct dependency for its `zeroize` feature), but using it as a KDF would be a new construction
  that needs its own review.
- XChaCha20-Poly1305's 192-bit nonce is made for random nonces. A vault that seals ten million
  records over its life has a nonce collision chance below 2^-140.
- Subkeys would buy no isolation. Every subkey would be derived from the DEK, which stays in
  RAM while unlocked, so a leak of the DEK leaks every subkey too.
- Only one data key exists per vault, so Poly1305 not being key-committing does not matter:
  there is no second key to steer a ciphertext towards.
- The existing `Nonce` type (no `Clone`, no `Copy`, consumed by `seal`, made only by `random()`)
  keeps working unchanged. A record's nonce is stored as plain bytes and is only ever passed to
  `aead::open`, which takes `&[u8; 24]`.

### 2.5 Associated data and integrity

**Record AAD** (164 bytes):

```
"HOLMREC\0"                 8 bytes, domain tag
header key block            132 bytes (header bytes 0..132)
item id                     16 bytes
generation                  u64 LE, 8 bytes
```

**Index table entry**, per item, inside the encrypted index: `generation: u64`,
`nonce: [u8; 24]`, `ct_len: u32`. Records are laid out in index order, so offsets are prefix
sums and are not stored.

What each part stops:

| Attack | What catches it | When |
|---|---|---|
| Swap two records | Each record's AAD has its own item id; the index pins each nonce. | First reveal of either item |
| Move a record to another vault | Other vault: other DEK. Same vault before a password change: other key block in the AAD. | First reveal |
| Roll back one record to an older version | The index pins the current generation and nonce. An older record has an older generation and another nonce. | First reveal |
| Delete a record | The lengths in the index no longer sum to the region. | Unlock, before any record is touched |
| Insert or append a record | Same framing check. | Unlock |
| Reorder records | Offsets come from index order, so each slice now holds another record's bytes and fails its AEAD. | First reveal |
| Truncate or extend the file | Header framing: `172 + index_len + records_len` must equal the file length. | Parse, before Argon2 |
| Swap in an old index (with its header) over new records | The old header's `records_len` and the old table do not match the new region; any changed record has a different nonce. | Unlock or first reveal |
| Use the index blob as a record, or the reverse | Different AAD (`HOLMVLT\0`… vs `HOLMREC\0`…, different length). | Open |
| Use a v1 body as a v2 index (same DEK after migration) | v1 body AAD is the 164-byte v1 header with version 1; the v2 index AAD is 172 bytes with version 2. | Open |
| Change the zero filler | Filler must be all zero and exactly `roundup(sum, 16384) - sum` bytes. | Unlock |
| Replace the whole file with an older copy | Not caught. Needs state outside the file. Unchanged non-goal (THREAT-MODEL, Rollback row). | Never |

The nonce pins the record: nonces never repeat under one DEK, so for a given (DEK, nonce, AAD)
exactly one ciphertext authenticates. The generation in the AAD is a second, readable guard:
an older record of the same item fails even if a nonce were somehow repeated. No hash and no
file-level MAC are added. The index is already the authenticated commitment to the set, and
a hash would be a new primitive in the format.

**Record authentication is lazy.** Unlock authenticates the header and the index and checks
the framing. It does not decrypt the records, because doing so would put every secret in RAM
at unlock, which is what Phase B removes. A damaged record is found when it is opened (reveal,
copy, edit, export, password change) and gives `CoreError::DamagedItem`. Only someone who can
write the file can cause that, and they can also delete the file, so the loss is the same.

### 2.6 Plaintexts

**Index plaintext** (body schema 4): `u16` version 4, then postcard of settings, categories,
the entry list and the next category id, then the existing canonical 16 KiB padding (`pad`,
`unpad`, unchanged). Each entry, in this order: id, type and type-specific public data
(Login: username, URLs, has-password, has-notes; Crypto: chain, has-address, has-memo,
has-notes; Phrase: has-notes; Note: has-body), title, category, favourite, created, updated,
trashed, custom field entries (position, label, kind, Text or Date value if public, used flags
for codes, expiry), and the table entry (generation, nonce, ct_len).

The empty vault's index is the same 51 bytes as the schema-1 golden with byte 0 set to 4,
because with no items the entry layout never appears.

**Record plaintext** (record schema 1): `u16` version 1, then postcard of the item type tag,
the type's sealed values (Login: password, notes; Crypto: address, memo, notes; Phrase:
phrase, notes; Note: body), then the sealed custom values in position order (position, and
`Secret`, `MultilineSecret` or a list of code strings). Then canonical padding to a multiple
of `RECORD_PAD_BLOCK`.

After a record decodes, it is cross-checked against its index entry. Any mismatch is
`DamagedItem`: a different type; a sealed field position that is not a secret-kind field in
the entry, or a missing one; a code list whose length differs from the entry's used flags; a
presence flag that disagrees with the value; any existing field rule broken.

A body schema below 4 inside format 2 is `Malformed` (schemas 1 to 3 exist only in format 1).
A body schema above 4 is `NewerSchema`, never rewritten. A record schema other than 1 is
`DamagedItem` in this build; a later record schema would come with a body schema bump, so an
old build stops at `NewerSchema` first.

### 2.7 Padding and size hiding

- **Records:** each record plaintext is padded canonically (u32 length prefix, zeros) to a
  multiple of `RECORD_PAD_BLOCK` = 256 bytes. A typical login (password plus short notes) is
  one block, so password length does not show in a record's size.
- **Index:** padded to 16 KiB blocks, as the v1 body.
- **Region:** after the last record, zero filler up to the next multiple of 16 KiB. The filler
  length is not stored: the parser computes it from the index and requires it to be exact, so
  there is one valid file per state.
- What the file still shows: the index size in 16 KiB blocks and the records size in 16 KiB
  blocks. Record count and record boundaries are not visible in one file.
- What a series of copies shows (Time Machine snapshots, backups): unchanged records keep
  their exact bytes, so comparing two copies shows which byte ranges changed, roughly how many
  records were re-sealed, and their size in 256-byte blocks. This is forced by "re-seal only
  what changed": re-sealing everything on every save needs every plaintext in RAM. It is
  accepted and documented (section 6).

### 2.8 Parser limits

Every check runs before the allocation it guards. Arithmetic is checked `u64`.

| Stage | Check |
|---|---|
| Read | File at most `MAX_FILE_LEN` = 64 MiB (unchanged). |
| Header v2 | v1 checks for bytes 0..132; `index_len >= PAD_BLOCK + TAG_LEN` and `(index_len - TAG_LEN) % PAD_BLOCK == 0`; `records_len % PAD_BLOCK == 0`; `172 + index_len + records_len == file.len()`. |
| Index decode | Entries at most `MAX_ITEMS` (50 000) through `BoundedVec`, at most 1024 reserved up front; categories and strings capped as today; per entry `generation >= 1`; `ct_len` between `RECORD_PAD_BLOCK + TAG_LEN` and `MAX_RECORD_PADDED + TAG_LEN`, with `(ct_len - TAG_LEN) % RECORD_PAD_BLOCK == 0`; running sum of `ct_len` at most `records_len`. |
| Framing | `records_len == roundup(sum, PAD_BLOCK)`; filler all zero; ids unique (existing cross-check). Only then are record slices copied out. |
| Record decode | Plaintext at most `MAX_RECORD_PADDED` = 262 144 bytes (256 KiB); fields at most 10, codes at most 20, strings at their caps, all before reserving. |

`MAX_RECORD_PADDED` holds the worst record with room to spare: a login with a 4096-byte
password, 65 536-byte notes and ten 16 384-byte multiline secrets is 233 472 bytes of text plus
under 1 KiB of framing. A compile-time assertion and the test `maxed_record_fits_cap` check it.
The write side checks `172 + index_ct + records_len <= MAX_FILE_LEN` before the index is
sealed, so Holm never writes a file it would refuse to read; a change past it is
`TooLargeToSave` and is undone in memory, as today.

## 3. Save path

Every change is still saved at once (`commit`), with the same atomic store contract:
exclusive temp file, sync, rename, sync directory (`FsStore`, unchanged).

1. **Change in memory.** A change that touches a sealed value (add, update, set fields with a
   secret kind, import, password change) builds the new record plaintext in a wiping buffer,
   seals it with a fresh `Nonce::random()` and `generation + 1` (1 for a new item), and
   replaces that item's sealed record. The plaintext buffer is dropped before the call
   returns. A change that touches only public data (title, category, favourite, trash,
   restore, mark code used, settings, categories) changes the index only.
2. **Size check.** Compute the file length from the index plaintext length and the record
   lengths. Over the cap: `TooLargeToSave`; the undo closure puts back the old entry and the
   old sealed record.
3. **Seal the index** with a fresh nonce; the header carries the new index nonce and lengths.
4. **Assemble** header, index ciphertext, record ciphertexts in index order, filler.
5. **Replace** through `VaultStore::replace`. Dirty is cleared only on success.

**Nonce rules.**

- An unchanged record is not re-encrypted. Its ciphertext bytes, nonce and generation are
  copied as they are. Copying a ciphertext is not nonce reuse: nothing new is encrypted.
- A changed record always gets a new random nonce and a higher generation, even if the new
  plaintext equals the old one, and even if the previous save of that change failed. There
  is no code path that seals with a stored nonce: stored nonces are bytes, and `seal` only
  takes a `Nonce`, which only `Nonce::random()` makes.
- The index is sealed fresh on every save.
- Generation is a `u64` that only goes up. Reaching `u64::MAX` is refused (it cannot happen in
  practice).

**Backup** (`save_backup`) writes the current index, sealed fresh, and the same record bytes
to the backup store. **Password change** makes a new KEK, DEK and key block, then opens each
record with the old DEK and re-seals it with the new DEK and the new key block, one record at a
time, so one item's plaintext is in RAM at a time. Keys and records are swapped only after the
write succeeds, as `change_password` does today.

## 4. Migration from format v1 (body v1 to v3)

### 4.1 Reading

`unlock` reads the header version first:

- **Version 1:** open as today (`envelope::open`, `VaultData::decode`). Then, still inside
  `unlock`, split each item into its index entry and its record and seal the record under the
  **same DEK**. Right after sealing, open the record again and compare it with the item's
  secrets, while that plaintext is in RAM anyway. Then drop `VaultData`, which wipes it. The
  session now holds the same state as a v2 unlock, plus the original file bytes (ciphertext,
  not secret) for the backup. `migration_pending()` is true. Not dirty: locking without an
  edit loses nothing and writes nothing.
- **Version 2:** parse, unwrap, open the index, check framing, copy record slices.
- **Any other version:** `Format(UnsupportedVersion(v))`, as today. Nothing is written.

Why keep the DEK: the KEK is gone by the first save, so a new DEK cannot be wrapped then
without asking for the password again. Keeping it exposes nothing new: an old v1 copy plus the
password already gives the DEK, and a normal save keeps the DEK today too. The index and record
AADs differ from the v1 body AAD, so nothing sealed under v1 can be read as v2.

### 4.2 Writing (the first save)

1. Build the full v2 file in memory (section 3).
2. Self-check: `Header::parse` on the new bytes, open the index with the in-memory DEK, check
   framing. Records were already checked at unlock. A failure stops here: `MigrationFailed`,
   nothing written, session dirty.
3. Keep a backup of the **original v1 bytes**: `VaultStore::keep_backup_copy(tag, bytes)`. The
   file is `<vault file>.v1-<16 hex>.bak` next to the vault, where the hex is the first 8 bytes
   of the v1 body nonce (public, unique per v1 save). Exclusive create, mode 0600, sync, sync
   directory. If that name exists with the same bytes, it counts as done. If it exists with
   other bytes, stop: `MigrationFailed`, nothing else written.
4. `replace` the vault with the v2 bytes. On error, as today: old or new is on disk, the
   session stays dirty, a later save retries. The backup stays either way.
5. On success: drop the kept v1 bytes, `migration_pending()` becomes false.

Fail-closed: the vault file changes only in step 4, and only after a durable backup exists.
A crash between 3 and 4 leaves a v1 vault plus its backup. A crash during 4 leaves v1 or v2,
never a mix.

### 4.3 Reversing

The backup is a byte-for-byte v1 vault. Any Holm, old or new, opens it with the password it had
at migration. To go back: quit Holm, move the v2 file away, rename the backup to the vault name,
install the older Holm. Edits made after migration are not in the backup, and the manual says
so. Holm writes no v1 files after Phase B; CSV export stays the escape hatch to another tool.

The backup is never deleted by Holm. Like any backup it keeps deleted items and still opens
with the old password after a password change (THREAT-MODEL, Never claim 4). The GUI says this
once, after the migrating save.

### 4.4 Old binaries

A Holm built before Phase B reads bytes 8..10, sees 2, and returns
`Format(UnsupportedVersion(2))` before Argon2 and before any write. It cannot rewrite the file.
This build adds a clearer message for a version above 2 ("needs a newer version of Holm"); the
old message is what shipped builds show, and the release notes say so.

## 5. Memory model

### 5.1 Resident while unlocked

| Value | Type | Secret? |
|---|---|---|
| DEK | `SecretKey` in `VaultKeys` | yes, the one key; see section 6 |
| Header v2 | `Header` | no |
| Index | `Index { settings, categories, entries: Vec<ItemEntry>, next_category_id }` with `Text` (wiping) strings | no secrets by the 2.3 rule; personal data |
| Sealed records | `SealedRecord { generation, nonce: [u8; 24], ct: Box<[u8]> }`, one per entry | no, ciphertext |
| v1 bytes, migration only | `Vec<u8>` | no, ciphertext; dropped after the migrating save |

`ItemEntry` has no `SecretText`, `GatedSecret` or `SecretBuf` field. That is enforced by
review and by the test `resident_state_has_no_secret_marker` (section 7).

Ciphertexts stay in RAM rather than being read again from disk at reveal time. Re-reading would
put file I/O in every reveal and open a gap where the file could change under the session. The
single-instance lock already keeps other Holm processes off the file; the extra memory is the
file size, at most 64 MiB, usually under 1 MiB.

### 5.2 Core API

- `Session::entry(id) -> Result<&ItemEntry, CoreError>` and `active_entries()`: replace
  `item()` and `active_items()`. Search, the list, badges and the detail view's public rows
  read entries only.
- `Session::reveal(id, slot: SecretSlot) -> Result<SecretText, CoreError>`: decrypts the
  record into a `SecretBuf`, decodes it into wiping types, moves the one requested value out
  as a `SecretText`, drops the rest. `SecretSlot` is `Password`, `Notes`, `Address`, `Memo`,
  `Body`, `Field { position }` or `Code { position, index }`. The phrase is not a slot:
  `reveal` refuses it, and only `reveal_phrase(id, password)` returns it, after the
  throttled password check (unchanged gate).
- `Session::open_item(id) -> Result<Item, CoreError>`: the whole item, owned, in wiping types.
  For editing, CLI edit and export only. The caller drops it when the form takes its values.
- `Session::set_code_used(id, position, index, used)`: index-only change.
- `Session::migration_pending() -> bool`.
- `CoreError::DamagedItem`: a record failed to open or failed its cross-check. Not
  `WrongPasswordOrCorrupt`: the password was already proven by the index.

`Item`, `ItemInput`, `ItemData` and `CustomField` keep their types and rules. They are now the
"open item", not the resident one.

### 5.3 Lifetime of a decrypted value (GUI)

| Moment | What exists |
|---|---|
| Select an item | `ItemView` for that id. Rows drawn from the `ItemEntry`: public text, dots for secrets. No decrypt. |
| Reveal | `reveal(id, slot)` once. `ItemView.revealed = Some(Revealed { slot, until, text: SecretText })`. Painted from `text` each frame, never in a `Label`, `TextEdit` or AccessKit node (unchanged rule). |
| Reveal ends | Timer (`REHIDE_PASSWORD_SECS`), Hide, window blur, another reveal, another selection, Edit, lock: `revealed` is set to `None` or the `ItemView` is dropped. The `SecretText` wipes. |
| Copy | `reveal(id, slot)`, hand `expose()` to the clipboard, drop the `SecretText` in the same frame. The clipboard copy and its clear are unchanged (`PendingClear`). |
| Edit | `open_item(id)`, `LoginForm::from_item(&item)`, drop `item`. The form's `SecretInput` buffers hold the values while editing, as today. Cancel or Save drops the form. |
| Recovery phrase | `Job::RevealPhrase` on the worker, as today; the words come back as `SecretText` and drop when hidden. |
| Lock, idle lock, sleep | `Session::lock` drops keys, index and records; the vault screen is replaced, so every `ItemView` and form drops; Phase A clears egui memory. |

The GUI never holds a secret in a `String`. It receives `SecretText` and keeps it or drops it.
Painting creates egui galleys that hold the shown text. That is the one copy outside Holm's
types, and it is why Phase A matters: the zero-on-free allocator wipes the galley and every
other freed block when egui evicts it, and lock wipes egui's id-keyed memory.

### 5.4 Inside a reveal call

For the length of one `reveal` call (well under a millisecond for a typical record), the whole
record plaintext of that one item is in RAM: the AEAD working buffer, the decoded values and
the requested one. All are wiping types; the decoded values drop before `reveal` returns.
postcard decodes into `WireStr` (`Zeroizing<String>`) as today. Anything that escapes,
such as a temporary in a dependency, is caught by the Phase A allocator when it is freed.
Registers and stack slots are still not wiped (unchanged limit in CRYPTO.md).

### 5.5 CLI

`holm get` prints public fields from the entry and `(hidden)` for secrets; `--copy FIELD` uses
`reveal`. `holm edit` uses `open_item`. `holm export` opens one item at a time while writing
into the export buffer. The CLI is one-shot, so this mostly shortens how long secrets sit in
RAM in `holm shell`.

## 6. Threats

### 6.1 Closed or reduced

- **Plaintext secrets in a memory capture while unlocked.** A swapped-out page, a hibernation
  image, a crash report from a dependency, a heap read bug, or a dump grepped for strings shows
  no password, note, phrase or custom secret, except the one value currently revealed (and,
  during a reveal call, that one item's record). Today every secret is there.
- **Secrets lingering after use.** A revealed value is dropped when it hides, not at lock.
- **Size of what leaks per item from the file.** Record boundaries and count are hidden in the
  encrypted index; per-record padding hides secret lengths from snapshot comparison.

### 6.2 Not closed

- **The DEK is in RAM.** Anyone who gets a full memory image while unlocked, plus the format
  description, can find the 32-byte key (try each aligned window against the index AEAD) and
  decrypt every record, which is also in that image. Phase B moves the attack from "grep the
  dump" to "find the key and decrypt". It does not stop a full dump. Protecting the key needs
  locked, guarded pages or OS key storage, which Phase A decided against for now (A4).
- **Malware with debugger rights, or as the same user, while unlocked.** It can read the DEK,
  read each value as it is revealed, read the screen and the clipboard, and log the master
  password. Unchanged: out of scope.
- **The revealed value.** It is in Holm's buffer and in egui's galley while shown.
- **Index metadata in RAM.** Titles, usernames, URLs, chains, labels, custom text values,
  dates, used flags and presence flags are resident in the clear while unlocked.
- **Change pattern across copies.** Two copies of the file show which records changed and their
  256-byte size class (2.7). v1 showed only that something changed. Accepted.
- **Whole-file rollback.** Unchanged non-goal.
- **The migration backup.** It is a full v1 vault on disk with the old password, kept until
  the user deletes it.
- **Lazy record authentication.** A damaged record is only found when opened.

THREAT-MODEL.md gets a row for "memory capture while unlocked" (Partly: no plaintext secrets
except the shown one; the key is resident) and the change-pattern note. Never claim 5 stays.

## 7. Test and fuzz plan

### 7.1 Fuzz targets (new, in `fuzz/`)

| Target | Input | Asserts |
|---|---|---|
| `parse_header_v2` | any bytes | `Header::parse` never panics; any accepted header re-encodes to the same 172 bytes. |
| `decode_index` | index plaintext | no panic; accepted input re-encodes byte-identical; no allocation over the 64 MiB limit. |
| `decode_record` | record plaintext, plus a fixed entry | no panic; cross-check never accepts a record that disagrees with the entry. |
| `open_v2_fixed_key` | whole file, fixed KEK | header, unwrap, index, framing, then `open_item` for every entry; no panic, only typed errors. |

Seeds: the v2 golden, a maxed record, an index with 10 entries, empty vault. The existing
targets stay (v1 files are still read).

### 7.2 Property tests

- `index_roundtrip_any`: any valid index decodes to itself.
- `record_roundtrip_any`: any valid item splits into entry plus record and joins back equal.
- `vault_v2_roundtrip_any`: any valid `VaultData` sealed as v2 opens, and every `open_item`
  equals the original.
- `migration_v3_to_v4_any`: any valid schema-3 body sealed as v1, unlocked, saved, reopened:
  every item equal, the backup equals the original bytes.
- `migration_from_v1_and_v2_bodies`: the same from schema-1 and schema-2 bodies.
- `edit_reseals_only_that_record`: after editing item k, every other record keeps its bytes,
  nonce and generation; record k has a new nonce and generation + 1.
- `public_change_reseals_no_record`: title, favourite, trash, category and mark-used leave all
  record bytes unchanged.
- `records_never_share_a_nonce`: over many random edits, every stored nonce is distinct.

### 7.3 Tamper tests (fixed key, no Argon2)

`tamper_swap_records`, `tamper_delete_record`, `tamper_insert_record`,
`tamper_reorder_records`, `tamper_rollback_one_record` (same length, older generation),
`tamper_old_index_new_records`, `tamper_record_from_other_vault`,
`tamper_record_after_password_change`, `tamper_truncate_every_length`, `tamper_append_byte`,
`tamper_flip_every_byte` (small file: every flip is refused at parse, unlock or the reveal of
the one item it hit, never returns changed data), `tamper_filler_nonzero`,
`tamper_records_len_not_canonical`, `tamper_index_ct_len_out_of_range`,
`tamper_v1_body_as_v2_index`.

### 7.4 Migration, compat and crash tests

`migration_backup_write_fails_vault_untouched`, `migration_replace_fails_then_retry`,
`migration_backup_exists_same_bytes`, `migration_backup_exists_other_bytes_refuses`,
`migration_lock_before_save_writes_nothing`, `newer_format_version_refused_untouched`,
`body_schema_below_4_in_v2_malformed`, crash tests at each migration step in the existing
`holm-platform` crash harness, and a local CI script step that runs the last released `holm`
(0.1.x tag) on the v2 golden and expects `unsupported vault format version 2` and an unchanged
file.

### 7.5 Golden vectors

- `tests/vectors/golden-v2.vault`: deterministic (fixed salt, DEK and nonce fills, as the v1
  golden), holding the default settings, a login with password, notes and a recovery-code field,
  and a secure note. It is built by an **independent test-only writer** that calls
  `chacha20poly1305` directly, not Holm's writer, so writer and reader check each other.
  `golden_v2_opens` checks every field; `golden_v2_rebuilds` checks the bytes.
- `golden_v1_migrates`: the existing v1 golden unlocks, saves as v2, and the backup equals the
  golden bytes. The v1 golden file itself never changes.
- `record_aad_golden` and `header_v2_golden`: exact bytes of an AAD and a header.
- `default_index_golden`: the 51-byte empty index with byte 0 = 4.

### 7.6 Memory tests

- `resident_state_has_no_secret_marker`: a test-only `Session::resident_bytes()` concatenates
  every resident buffer (index strings, ciphertexts, header); after unlocking a vault with
  marker secrets, no marker appears. Then reveal one: still not in resident state (it is in the
  returned `SecretText` only).
- `item_view_holds_no_secret_before_reveal` (GUI, headless egui harness as in Phase A).
- Manual check for the security review: attach `lldb` to a release `holm-gui` with a marker
  vault unlocked, `process save-core`, grep the core for markers: only the revealed one may
  appear. Not automated (needs debugger rights).

## 8. Performance targets

Measured release build, Apple Silicon, ignored timing tests (the Phase A pattern) plus
`scripts/measure-macos.sh`.

| Target | Test | Notes |
|---|---|---|
| Unlock time unchanged | `unlock_post_kdf_timing_10k`: post-Argon2 work for 10 000 items, v2 not slower than v1 by more than 10 % | Argon2 is unchanged and dominates (hundreds of ms). v2 decrypts a smaller index and copies ciphertext slices. |
| Open an item under 5 ms | `open_item_worst_timing`: `reveal` and `open_item` on a maxed 256 KiB record, p99 < 5 ms | XChaCha20 on 256 KiB is well under 1 ms. |
| Search 10 000 items under 10 ms | `search_10k_timing`: typical items, 3-letter query, p99 < 10 ms | Index only. If it misses, store folded search keys in the entry at unlock (wiping), and say so in DECISIONS. |
| Save after one edit | `save_one_edit_10k_timing`, informational | One record sealed, index sealed, file assembled. |

## 9. Task breakdown (order)

Each task builds, passes `scripts/ci-local.sh`, and is testable alone. The plan file has the
details: `docs/superpowers/plans/2026-11-07-phase-b-decrypt-on-demand.md`.

1. **B1 Padding with a block size.** `pad_to`, `unpad_from` with a block parameter; record
   constants; compile-time asserts.
2. **B2 Header v2.** Parse and encode format 2 next to 1; framing rules; golden; fuzz target.
3. **B3 Index and record wire.** Schema-4 index and schema-1 record structs, bounded decoders,
   cross-checks; fuzz targets.
4. **B4 Split and join.** `Item` to `(ItemEntry, RecordSecrets)` and back; property tests.
5. **B5 Envelope v2.** Record and index seal and open with the AADs; file assemble and parse;
   tamper tests; golden v2 with the independent writer.
6. **B6 Read API on today's session.** `entry`, `reveal`, `open_item`, `set_code_used`, over
   the current resident data; CLI moves to it. No format change yet.
7. **B7 GUI on the read API.** `ItemView` holds `Revealed`; copy, edit and codes through the
   new calls; `item()` removed.
8. **B8 Store backup copy.** `VaultStore::keep_backup_copy` in `FsStore` and `MemStore`.
9. **B9 Session on format v2.** `Unlocked` holds index and records; v2 unlock; v1 unlock with
   in-RAM migration; commit with record reuse; backup, password change, import, export; the
   migrating first save.
10. **B10 Perf, compat and memory checks.** Timing tests, old-binary script, resident test, manual
    core check.
11. **B11 Docs.** CRYPTO.md v2 section, THREAT-MODEL rows, DECISIONS, manual (migration and
    reverting), ROADMAP status.

## 10. What stays exactly the same

- Argon2id v1.3, `KdfParams::DEFAULT`, `FLOOR`, `MAX_M_KIB`, `MAX_T`, `MAX_WORK`, p = 1, and
  `validate` before any work.
- KEK from the NFC UTF-8 password; DEK random 32 bytes; DEK wrap with wrap AAD = bytes 0..60;
  the 48-byte wrapped DEK; `verify_password` in constant time.
- XChaCha20-Poly1305 through `holm_crypto::aead::{seal, open}`, `Nonce::random()` only.
- NFC password handling and the strength policy.
- `MAX_FILE_LEN` 64 MiB, 16 KiB index padding (canonical), `MAX_ITEMS` and every field cap.
- `VaultStore` atomic replace, `FsStore` durable save, the single-instance lock, the throttle,
  the phrase gate, clipboard clear, the Phase A allocator and lock wipe.
- Reading every existing file: format 1 with body schemas 1, 2 and 3.
- Error rules: wrong password and a damaged header or index are one error;
  `KdfPolicy` and `Format` are their own.

## 11. Decisions

Judgment calls made in this design. Each needs the Opus security review.

1. **Index rule: what is shown without Reveal is in the index.** Username, URLs, chain, labels,
   custom Text and Date values, used flags and presence flags are in the index. Why: search and
   the list need them per keystroke, and they are on screen in the clear already. Cost: they are
   resident (6.2).
2. **One record per item, always present.** Simpler than per-field records, and hides which
   items hold secrets. Cost: a reveal briefly decrypts the whole item.
3. **DEK with random nonces, no HKDF.** No new dependency or primitive; subkeys give no
   isolation while the DEK is resident.
4. **Record AAD binds the header key block, not a new vault id.** The key block already
   identifies the vault and its key epoch and changes exactly when the DEK changes.
5. **The index is the integrity commitment.** It pins id, generation, nonce and length of every
   record, and the header framing pins the region. No hash, no file MAC.
6. **Generation in the AAD as well as the nonce in the index.** Redundant on purpose: a readable
   guard against a rolled-back record that does not rest on nonce uniqueness alone.
7. **Record boundaries are hidden inside the encrypted index.** No public framing per record.
8. **Record padding 256 bytes; index and region 16 KiB; filler implicit and canonical.**
9. **Lazy record authentication.** Eager checking would decrypt every secret at unlock.
   Damaged records show as `DamagedItem` when opened.
10. **`DamagedItem` is a new error, separate from `WrongPasswordOrCorrupt`.** The password is
    already proven by the index; telling the user one item is damaged reveals nothing.
11. **Ciphertexts stay in RAM.** No re-read at reveal: no I/O in core reveals, no file-swap gap.
12. **Migration seals records at unlock and writes at the first save.** The v1 plaintext leaves
    RAM at once; an unlock without an edit writes nothing.
13. **Migration keeps the DEK.** The KEK is gone by then; nothing new is exposed.
14. **Backup named by the v1 body nonce; same bytes count as done; other bytes stop.** No
    overwrite, and no wedge after a downgrade-and-save.
15. **Reverting is by the backup only; no v1 writer.** Less code in the security core.
16. **Mark used is index-only.** Avoids decrypting every code to flip one flag.
17. **Unchanged records are copied, never re-sealed.** Forced by the memory goal; the snapshot
    diff leak (2.7) is accepted.
18. **Header v2 keeps bytes 0..132 identical** so the wrap path and the KDF parser are shared.
19. **Search stays a scan of the index.** Folded keys are precomputed only if the 10 ms target
    misses.

## 12. Open risks

- The DEK in RAM makes a full memory image enough to read everything (6.2). Phase B is a
  defence against partial captures and string scanning, and the docs must say so plainly.
- Snapshot comparison shows the change pattern.
- Metadata (titles, usernames, URLs, custom text) stays resident.
- Old builds show a terse "unsupported vault format version 2".
- The migration backup lingers with the old password and deleted items.
- B9 is the largest task and touches every session path; it gets the deepest review.

## 13. Owner questions

1. Custom **Text** values: keep them in the index (shown without Reveal, as today), or move them
   into the record and decrypt on opening the detail view? The design keeps them in the index.
2. The migration **backup**: keep it until the user deletes it (the design), or offer to delete
   it after the next successful unlock of the v2 file?
