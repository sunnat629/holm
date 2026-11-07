# Holm vault file format

This page describes the file format byte by byte: format version 2, with body schema 4 for the index. The numbers come from the code in `crates/holm-core/src` (`format.rs`, `envelope_v2.rs`, `index.rs`, `record.rs`, `padding.rs`, `migrate.rs`) and from [CRYPTO.md](CRYPTO.md). Where this page and the code disagree, the code is right and this page has a bug.

If you are new to the ideas, read [HOW-ENCRYPTION-WORKS.md](HOW-ENCRYPTION-WORKS.md) first.

All multi-byte integers in the header are little-endian.

## The whole file

```
offset 0                172                       172 + index_len
  | header (172 bytes)  | index ciphertext        | records region          |
  |                     | (index_len bytes)       | (records_len bytes)     |
```

The file length must equal `172 + index_len + records_len` exactly. Any other length is refused as `LengthMismatch`. The file may not be larger than 64 MiB (`MAX_FILE_LEN` = 67,108,864 bytes). When a save would go over that, it fails with `TooLargeToSave` and nothing is written.

## The header: 172 bytes

| Offset | Size | Field | Value or meaning |
|---|---|---|---|
| 0 | 8 | magic | `HOLMVLT\0` |
| 8 | 2 | version | 2 |
| 10 | 2 | flags | 0 (any other value is refused as `BadFlags`) |
| 12 | 1 | KDF id | 1 (Argon2id v1.3) |
| 13 | 3 | reserved | 0 |
| 16 | 4 | memory | Argon2 memory in KiB |
| 20 | 4 | iterations | Argon2 passes |
| 24 | 4 | parallelism | must be 1 |
| 28 | 32 | salt | Argon2 salt |
| 60 | 24 | wrap nonce | nonce for the wrapped DEK |
| 84 | 48 | wrapped DEK | 32-byte DEK encrypted under the KEK, plus a 16-byte tag |
| 132 | 24 | index nonce | nonce for the index |
| 156 | 8 | index length | `index_len`: bytes of index ciphertext, tag included |
| 164 | 8 | records length | `records_len`: bytes of the records region |

Bytes 0 to 131 are called the key block (`KEY_BLOCK_LEN` = 132). It holds everything needed to turn a password into the DEK. It is the same layout as in format v1, except for the version number. Bytes 132 to 171 describe the index and the records.

The Argon2 settings are checked against the cost policy (at least 64 MiB with 3 passes, at most 1 GiB, 16 passes and 4 GiB of total memory passes) before any Argon2 work starts.

Format v1 for comparison: a 164-byte header (`HEADER_LEN`). The key block is the same 132 bytes, then at 132 a 24-byte body nonce and at 156 an 8-byte body length. The ciphertext starts at 164 and holds the whole vault as one sealed blob.

## The index

The index is one sealed unit: `index_len` bytes of ciphertext, starting at byte 172.

**Plaintext.** A 2-byte little-endian body schema number (4 for this format), followed by the [postcard](https://docs.rs/postcard) encoding of these fields in order: settings, categories, entries, the next category id, and an optional note about a migration backup.

**Padding.** The plaintext is padded to a multiple of 16 KiB (`PAD_BLOCK` = 16,384): a 4-byte little-endian length, then the plaintext, then zero bytes. The result is sealed with XChaCha20-Poly1305 under the DEK, using the index nonce from byte 132. The tag adds 16 bytes, so:

- `index_len - 16` is a multiple of 16,384 and at least 16,384. The smallest index is 16,400 bytes. Anything else is refused as `IndexLength`.

**Index AAD.** The whole 172-byte header, exactly as it appears in the file. Holm uses the bytes it read, not a re-encoding. This authenticates the index nonce, the index length, the records length and the key block in one step.

**Entries.** Each entry holds the public fields of one item, in this postcard field order: id, public, title, category, favourite, created, updated, trashed, fields, record. `public` holds the type-specific public values, such as a username and a URL, plus flags such as "has a password". `fields` describes the custom fields (their labels and kinds, and for plain fields their values). The secrets themselves are never in the index.

**The pin.** The last field, `record`, is a `RecordRef`:

| Part | Type | Rule |
|---|---|---|
| generation | u64 | at least 1. Zero is reserved for "not sealed yet" and is refused when encoding. |
| nonce | 24 bytes | the nonce the record was sealed with |
| ct_len | u32 | between 272 and 262,160 (`MIN_RECORD_CT` and `MAX_RECORD_CT`), and `ct_len - 16` is a multiple of 256 |

Postcard writes the integers as variable-length numbers, so on disk the generation and `ct_len` take only as many bytes as they need. The ranges above apply to the decoded values. The nonce is 24 raw bytes.

## The records region

The records region follows the index and is `records_len` bytes long. It holds each record's ciphertext, one after another, in the order of the entries in the index, followed by zero filler.

There is no table of offsets. The offset of a record is the sum of the `ct_len` values of the entries before it. So reading the index tells you where everything is.

Rules for the region:

- `records_len` is a multiple of 16,384, else `RecordsLength`.
- `records_len` equals the sum of all `ct_len`, rounded up to the next 16 KiB. After the index opens, Holm checks this. A mismatch is `Format(RecordsLength)`.
- The filler after the last record must be all zero bytes, else `Format(Filler)`. It is checked over the whole filler without an early exit.

### One record

Each item has one record. It holds the item's secrets: password, notes, address, memo, recovery phrase, note body, secret custom fields and recovery code strings.

**Plaintext.** A 2-byte little-endian record schema number (1), then the postcard encoding of the item type tag and its secret values, then the secret custom values in position order.

**Padding.** The plaintext is padded to a multiple of 256 bytes (`RECORD_PAD_BLOCK`), using the same form as the index: a 4-byte little-endian length, the plaintext, then zeros. The padded size is at most 262,144 bytes (`MAX_RECORD_PADDED`, 256 KiB). A test (`maxed_record_fits_cap`) builds the largest possible record and checks it fits.

**Sealing.** XChaCha20-Poly1305 under the DEK, with a fresh random 24-byte nonce for every seal. The ciphertext is the padded size plus the 16-byte tag. That is the `ct_len` in the index.

### Record AAD

The record AAD is 164 bytes (`RECORD_AAD_LEN`):

| Offset | Size | Part |
|---|---|---|
| 0 | 8 | `HOLMREC\0` |
| 8 | 132 | the key block, as encoded in a v2 header (version 2) |
| 140 | 16 | the item id |
| 156 | 8 | the generation, as a u64 little-endian |

Because the key block is in the AAD, a record from another vault does not open. Because the item id is in the AAD, a record from another item does not open. Because the generation is in the AAD, a record from another version of the same item does not open.

### The three AADs together

| Seal | AAD | Bytes |
|---|---|---|
| Wrapped DEK | header bytes 0 to 59 (`WRAP_AAD_LEN` = 60) | magic, version, flags, KDF id, reserved, the three KDF settings, salt |
| Index | the whole header | 172 |
| Record | `HOLMREC\0` + key block + item id + generation | 164 |

The version number sits inside the wrap AAD, so a DEK wrapped for v1 does not open under a v2 header. The test `migration_rewraps_under_v2_aad` covers this.

## Generation pinning

Each record has a generation counter that starts at 1 and goes up by one every time the item is saved. The index stores the generation, the nonce and the ciphertext length for each record. When Holm opens a record, it checks that the bytes it found match all three, and only then decrypts with the generation in the AAD.

This closes a hole that the AAD alone leaves open. A backup copy of a vault holds older versions of the same records, with the same key block, the same item ids and possibly the same generation. If you spliced such a record into the current file, the AAD would still look right. But its nonce is not the nonce the current index pins, so Holm refuses it. The test is `tamper_record_from_backup_copy`.

The tamper tests in `crates/holm-core/src/envelope_v2/tamper.rs` try the other attacks: swapping, deleting, inserting and reordering records, rolling back one record, pairing an old index with new records, and truncating or extending the file at every length.

## Padding at a glance

| What | Block size | Layout before sealing |
|---|---|---|
| Index | 16 KiB (16,384) | 4-byte length, plaintext, zeros |
| Record | 256 B | 4-byte length, plaintext, zeros |
| Records region | 16 KiB (16,384) | records back to back, then zero filler |
| v1 body | 16 KiB (16,384) | 4-byte length, plaintext, zeros |

Padding hides exact sizes. It does not hide that a record changed, or its size to the nearest 256 bytes, from someone who holds two copies of the file.

## A worked example

The test vault `crates/holm-core/tests/vectors/golden-v2.vault` is 32,956 bytes. Its header says:

| Field | Value |
|---|---|
| version | 2 |
| KDF id | 1 |
| memory, iterations, parallelism | 65,536 KiB, 3, 1 (the floor, so tests are fast) |
| index length | 16,400 (one 16 KiB block plus the 16-byte tag) |
| records length | 16,384 (one 16 KiB block) |

And 172 + 16,400 + 16,384 = 32,956.

## Migrating from v1 to v2

Holm opens both versions. A v1 vault is migrated the first time you save, never before.

1. On unlock of a v1 file, Holm makes a new DEK and wraps it under the v2 AAD. It seals each item as a record with generation 1 (`FIRST_GENERATION`) and builds the v2 index. It then opens its own result and compares it with the original items (`read_back`). Nothing has been written yet. If you lock before saving, the file on disk is the unchanged v1 file.
2. At the first save, `commit` adds a backup note to the index and assembles the v2 file. It checks the result again (`self_check`).
3. `write_gate` then asks the store to keep a copy of the original v1 bytes, and only after that does it replace the vault file. If the backup fails, the result is `MigrationFailed` and the vault file is not touched.

**The backup name** is `<vault file name>.<tag>.bak` where the tag is `v1-` followed by 16 lowercase hex characters (the first 8 bytes of the v1 body nonce). For a vault called `my.vault` it looks like `my.vault.v1-0123456789abcdef.bak`.

- It is created exclusively (it never overwrites), with owner-only permissions (0600), and synced to disk.
- A retry with the same bytes succeeds. A different file under the same name is an `AlreadyExists` error.
- Tags use only `a` to `z`, `0` to `9` and `-`, at most 32 characters (`check_backup_tag`, `MAX_BACKUP_TAG_LEN`).
- Holm never deletes the backup without a yes from you (`delete_migration_backup`). The app asks after the first good unlock, asks again after a password change, and stops asking once you have chosen.

An older Holm that does not know format 2 refuses a v2 file with its generic "This file isn't a Holm vault, or it is damaged." message and leaves the file as it was. The script `scripts/compat-old-binary.sh` checks this in local CI.

Lesson 69 tells the story of this migration.

## Error cases

| Error | When | Notes |
|---|---|---|
| `WrongPasswordOrCorrupt` | The DEK unwrap fails, or the index fails to open. | One error for both on purpose. |
| `Format(...)` | The framing is wrong: `IndexLength`, `RecordsLength`, `LengthMismatch`, `Filler` and similar. | Found before or right after the index opens, without any record plaintext. |
| `DamagedItem(id)` | Opening one record fails. Message: "item {id} is damaged and cannot be opened". | See below. |
| `GenerationExhausted(id)` | An item's generation counter is at its maximum and cannot go up. Message: "item {id} cannot be changed again". | See below. |
| `VaultError::TooLargeToSave` | The new file would be over 64 MiB. | The change is taken back. |
| `MigrationFailed` | The v1 backup could not be written. | The vault file is not replaced. |

**DamagedItem.** Unlock does not open records, so one broken record does not stop you from opening the vault. The error appears when you open that item. It is the same error for every cause: the pinned generation, nonce or length does not match; the AEAD tag fails; the padding is bad; or the decoded item disagrees with its index entry. The rest of the vault stays usable.

**GenerationExhausted.** The generation is a u64 and is raised with a checked add. If it ever reached the maximum, Holm would refuse the edit rather than wrap around and reuse a generation. The test `edit_at_max_generation_refused` sets the counter to its maximum and checks that nothing changes. In practice you cannot reach this by editing.

## Where to look in the code

| Topic | File |
|---|---|
| Header consts and parsing | `crates/holm-core/src/format.rs` |
| Assembling and opening v2 | `crates/holm-core/src/envelope_v2.rs` |
| Index and `RecordRef` | `crates/holm-core/src/index.rs` |
| Record sealing and the AAD | `crates/holm-core/src/record.rs` |
| Padding | `crates/holm-core/src/padding.rs` |
| Migration and the backup tag | `crates/holm-core/src/migrate.rs` |
| Golden and tamper tests | `crates/holm-core/src/envelope_v2/` |

Lessons 06 (parsing bytes safely), 13 (serde and versioned formats), 58 (the chapter and the bytes), 67 (one record per item) and 69 (migrate and keep a way back) cover the same ground from the learner's side.
