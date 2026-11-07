# Holm cryptography

How a Holm vault file is built and opened, what each check is for, and what we do not
claim. It describes the code in `crates/holm-crypto` and `crates/holm-core` as of
Phase 0-1. The binding design is section 5 and 6 of
`docs/superpowers/specs/2026-10-17-holm-v1-design.md`; this page must agree with it and
with the code. If they disagree, that is a bug.

## Primitives

| Job | Algorithm | Crate |
|---|---|---|
| Password to key | Argon2id v1.3 (RFC 9106) | `argon2` |
| Encryption | XChaCha20-Poly1305 (AEAD, 24-byte nonce, 16-byte tag) | `chacha20poly1305` |
| Randomness | Operating system source, no fallback | `getrandom` |
| Wiping memory | Zero on drop | `zeroize` |
| Comparing keys | Constant-time equality | `subtle` |
| Password bytes | Unicode NFC, then UTF-8 | `unicode-normalization` |

## Keys

```
master password --NFC + UTF-8--> Argon2id(salt, m, t, p=1) --> KEK (32 bytes)

DEK (32 random bytes, made when the vault is created or re-keyed)

header field "wrapped DEK" = XChaCha20-Poly1305(KEK, wrap nonce, DEK,  aad = header bytes 0..60)
body                       = XChaCha20-Poly1305(DEK, body nonce, pad(plaintext), aad = header bytes 0..164)
```

- The KEK (key-encryption key) exists only while a vault is being created, opened,
  re-keyed or checked with `verify_password`. It is wiped when dropped.
- The DEK (data key) encrypts the body. An open vault keeps it in `VaultKeys`, whose
  fields are private and which has no `Clone`. It is wiped when `VaultKeys` is dropped.
- Every seal uses a fresh random 24-byte nonce from the OS. The `Nonce` type cannot be
  copied or cloned and `seal` consumes it, so safe code cannot seal twice with one nonce.

## File layout (v1)

All integers are little-endian.

| Offset | Size | Field | Checked by |
|---|---|---|---|
| 0 | 8 | magic `HOLMVLT\0` | parser |
| 8 | 2 | format version, must be 1 | parser |
| 10 | 2 | flags, must be 0 | parser |
| 12 | 1 | KDF id, must be 1 (Argon2id v1.3) | parser |
| 13 | 3 | reserved, must be zero | parser |
| 16 | 4 | Argon2 memory, KiB | parser (policy) and both AEADs |
| 20 | 4 | Argon2 iterations | parser (policy) and both AEADs |
| 24 | 4 | Argon2 parallelism | parser (policy) and both AEADs |
| 28 | 32 | salt | both AEADs |
| 60 | 24 | wrap nonce | wrap AEAD (as nonce), body AEAD |
| 84 | 48 | wrapped DEK (32 bytes plus 16-byte tag) | wrap AEAD, body AEAD |
| 132 | 24 | body nonce | body AEAD (as nonce and AAD) |
| 156 | 8 | body ciphertext length, tag included | parser (exact framing), body AEAD |
| 164 | n | body ciphertext | body AEAD |

- **Wrap AAD** is bytes `0..60`: everything before the wrap nonce, including the salt
  and the KDF costs. Changing a cost or the salt makes the DEK unwrap fail.
- **Body AAD** is bytes `0..164`: the whole header. Changing any header byte makes the
  body fail to open.
- On open, the AAD is taken from the file's own bytes, not from a re-encoding of the
  parsed header.
- There is no checksum. The AEAD tags are the only integrity check.

## Argon2id cost policy

| Name in code | Memory (KiB) | Iterations | Parallelism |
|---|---|---|---|
| `KdfParams::DEFAULT` (new vaults, provisional) | 262144 (256 MiB) | 3 | 1 |
| `KdfParams::FLOOR` (refused below this) | 65536 (64 MiB) | 3 | 1 |
| Ceiling | `MAX_M_KIB` = 1048576 (1 GiB) | `MAX_T` = 16 | 1 |

- `MAX_WORK` = 4194304: `memory_kib × iterations`, computed in `u64`, must not exceed it
  (4 GiB of memory passes). So 1 GiB with 4 passes is accepted and 1 GiB with 5 is not.
- Parallelism must be exactly 1 in v1, so every accepted setting can be cross-checked
  against libsodium.
- `KdfParams::validate` checks these rules without hashing or allocating. It runs in the
  parser, before any Argon2 work, and again in `create`, `rekey` and `derive_kek`.
- `create` and `rekey` write the costs into the header exactly as given.

## Opening a vault

`envelope::open` (crate-private; callers outside holm-core use `Session`) does these steps, in this order:

1. `Header::parse`: file size at most 64 MiB, then magic, version, flags, KDF id,
   reserved bytes, the cost policy, and exact framing (`body_len` must match the bytes
   present, with room for the tag). Nothing secret is touched yet.
2. `derive_kek`: Argon2id with the header's salt and costs.
3. Unwrap the DEK with the KEK (wrap AAD = bytes `0..60`).
4. Open the body with the DEK (body AAD = bytes `0..164`).
5. `unpad` the authenticated plaintext.

Steps 3 to 5 are `open_with_kek`, which is `pub(crate)` so tests can flip every byte of a
file without running Argon2 once per flip.

**Timing.** A wrong password fails at step 3, before the body is decrypted, so it can
return sooner than a damaged body, which fails at step 4. Both give the same error. We
accept this difference for two reasons. First, Argon2 in step 2 takes far longer than
either AEAD step. Second, the timing difference only shows whether the key unwrap
succeeded. Anyone in a position to measure it already holds the file and can test that
offline for any candidate password at the same Argon2 cost, so timing reveals nothing
they could not compute. Holm makes no claim of equal timing.

## Saving

- `create(password, params, body)`: check the cost policy and the size cap first, then
  draw a fresh salt, DEK, wrap nonce and body nonce.
- `reseal(keys, body)`: a normal save. Same salt, KEK wrap and DEK; a new body nonce on
  every call. `keys` is updated to the new header only if the call succeeds.
- `rekey(keys, new_password, params, body)`: a password change. New salt, new costs, a
  **new DEK** and new nonces. Everything new is built first; `keys` is replaced only if
  the call succeeds, and the replacement wipes the old DEK. On error, `keys` is unchanged
  and still works with the old password.

**Why re-key rotates the DEK.** If a password change only re-wrapped the same DEK,
anyone holding an old copy of the file and the old password could unwrap the DEK from
that copy and then read every later version of the vault, whatever the new password.
With a new DEK, the old password opens only the old copies.

`body_len` is set from the real ciphertext length before the header is encoded, because
it is part of the body AAD. The size cap below keeps every saved file within what
`Header::parse` accepts, and the tests parse and open the files they create.

## Padding

The plaintext is padded before encryption:
`u32 length (LE) || plaintext || zero bytes`, rounded up to a multiple of 16384 bytes
(`PAD_BLOCK`, 16 KiB). An empty body becomes 16384 bytes; 16380 bytes also become
16384; 16381 bytes become 32768.

This hides small size differences: a 1-byte body and a 16000-byte body give files of the
same length. The file size still shows how many 16 KiB blocks the body needs.

Padding is canonical: each body has exactly one padded form. `unpad` returns
`BadPadding` if the length is zero or not a multiple of 16384, if the length prefix is
larger than the bytes after it, if the buffer has more blocks than the body needs, or if
any padding byte is not zero.

**Why `BadPadding` comes only after authentication.** `unpad` runs only on plaintext that
the body AEAD has already authenticated under the DEK. An attacker without the DEK cannot
make a body that authenticates, so they can never reach `unpad`, and every edit they make
fails earlier as `WrongPasswordOrCorrupt`. `BadPadding` therefore means a buggy writer
produced the file. It reveals nothing about the password, and it is not a padding oracle.

## The 64 MiB cap

- **Read:** `Header::parse` refuses a file larger than `MAX_FILE_LEN` = 67108864 bytes
  (64 MiB) with `Format(TooLarge)`, before anything else.
- **Write:** `pad` refuses a body larger than `MAX_BODY_LEN` = 67092476 bytes with
  `TooLargeToSave`. The largest padded body, `MAX_PADDED_LEN` = 67092480 bytes (4095
  blocks), plus the 164-byte header and the 16-byte tag still fits under `MAX_FILE_LEN`.
  A compile-time assertion checks this, so Holm never writes a file it would refuse to
  read.
- `create`, `reseal` and `rekey` check the size before any key derivation or encryption.

## Errors

| Error | When | Says anything about the password? |
|---|---|---|
| `Format(..)` | The public bytes are not a valid v1 file. | No |
| `KdfPolicy(..)` | Costs outside the policy, from the header or from the caller. Message: "this vault's key-derivation settings are outside Holm's policy". | No |
| `WrongPasswordOrCorrupt` | The DEK unwrap failed (wrong password, or a changed salt, in-policy cost, wrap nonce or wrapped DEK) or the body failed to open (any other change). | It is the only error a wrong password can cause. |
| `BadPadding` | The body authenticated but its padding is malformed. | No |
| `TooLargeToSave` | The body is over the write cap. | No |
| `Crypto` | The OS random source failed, or Argon2 failed (for example, it could not allocate its memory). | No |

A wrong password and a damaged file give the same error on purpose. Telling them apart
would reveal which part of the file an edit touched, or that a guessed password was right.

The `From` conversions into `VaultError` are written by hand instead of with thiserror's
`#[from]`. A cost-policy error from the parser becomes `KdfPolicy`, the same as one from
`create`, instead of `Format(KdfPolicy)`, and every AEAD failure becomes
`WrongPasswordOrCorrupt`.

`verify_password` derives the KEK again, unwraps the DEK and compares it with the DEK
held in `VaultKeys` using `subtle::ConstantTimeEq`.

## Master password strength

`holm_core::strength::check` decides whether a new master password is accepted. It is
Holm's own code (no production dependency), a port of zxcvbn's guess model:

- The NFC form must have from 12 to 1,024 `char`s, and the estimate must reach 1e10
  guesses (score 4, zxcvbn's top band). There is no override. Score 3 (1e8) was the
  first rule; it accepted word + year + symbol shapes such as `Summer2026!!`, which
  rule-based cracking reaches in far fewer guesses, so the maintainer raised it to score 4.
- Input over 1,024 characters (after NFC) is refused with fixed text before it is scored.
  Input over 4,096 raw characters is refused first, before NFC copies it, so a huge paste
  costs one pass to count it (about 10 ms for 1,000,000 characters).
- Pieces it recognises: words from zxcvbn's MIT frequency lists (30,000 leaked passwords,
  30,000 English Wikipedia words, 19,160 TV and film words, 10,000 surnames, 4,695 first
  names; `NOTICE` has the provenance and SHA-256, and `scripts/ci-local.sh` checks the
  hash), in any case, reversed or with l33t symbols; the word `holm` at rank 1; keyboard
  walks on QWERTY, Dvorak and two keypads; repeats, found at every start inside a run;
  letter and digit sequences; years and dates.
- The estimate is the cheapest way to build the whole password from those pieces, with
  any gap priced as random characters (`10^length`), using zxcvbn's formula
  `l! x product + 10000^(l-1)`. Holm finds that minimum exactly for the pieces it found.
  Every matcher aims to find at least what zxcvbn finds and price it no higher, but that
  is checked by tests, not proved: a piece Holm misses can make its estimate higher than
  zxcvbn's. The first version of the repeat matcher did exactly that (`yoyohellohello`
  was accepted), and the generated oracle corpus below now covers that shape.
- Work is bounded. Two bounds cannot change the result: at most 4 pieces, and random
  gaps of at most 10 characters (more pieces or a longer gap cost over 1e10 on their
  own). One errs towards refusing: after 16,384 characters of repeat units have been
  priced in depth, later units count as 1 guess (ordinary passwords use a tiny
  fraction of it; only long, crafted repeats run it out). One can miss a pattern: the
  dictionary search stops after 4,096 steps per start position (realistic input never
  reaches it). Repeat units up to 512 characters
  are searched, which is every unit with two copies in 1,024 characters. The worst case
  measured at 1,024 characters is about 28 ms and 12 MB (release build, Apple silicon).
- Years are priced from a fixed reference year (2026), so results never depend on the
  clock. Years after 2026 get the minimum price.
- Feedback is fixed text chosen from the cheapest split; it never contains the password.
- A dev-only test (`crates/holm-core/tests/strength_oracle.rs`) runs the `zxcvbn` crate
  as an oracle on two corpora under 100 characters: about 12,000 weak candidates built
  from word lists and suffixes, and 6,000 generated compositions from a fixed seed
  (doubled words, prefix + repeat, walks and dates in the middle, l33t + year,
  capitalised word + digits + symbols, three-piece mixes). Every candidate zxcvbn scores
  below 4 must be refused, and Holm's score must never be above zxcvbn's. Strong
  passphrases, random strings and a few passwords just over zxcvbn's 1e10 line must be
  accepted, and the generator's default password and passphrase must pass.

Limits, honestly: this is an estimate of one attacker model, not a proof. The lists are
English-centric, so words from other languages, local names and newer leaks are priced as
random characters. The oracle bounds disagreement with zxcvbn on its corpora only. Score
4 still accepts some guessable shapes, for example word + date + word, because zxcvbn's
model prices them just over 1e10. The model also prices a repeat by its copy count, so a
long run of copies (a 10-character date repeated 100 times) can score 4 although an
attacker who tries repeats would find it sooner; the 1,024-character limit caps this.

## The vault body (schema v1)

The padded plaintext is the body: inside the padding, a `u16` little-endian schema
version (1), then the `postcard` encoding of the settings, the categories, the items and the next category id.
Holm still reads this schema, but it now writes schema 3 (next section).
`VaultData::decode` treats it as hostile even though the AEAD has authenticated it,
because a buggy or newer writer is enough to produce bad bytes:

- a newer schema is refused (`NewerSchema`), never rewritten, so its fields are not lost;
  version 0 is `UnknownSchema`;
- every string and list length is capped while parsing (a string at most 64 KiB, the
  item and category counts at their limits), and no list reserves more than 1024 slots
  up front, so a huge declared length costs no memory;
- trailing bytes are refused;
- every field rule and cross-check (unique ids and names, known categories, the next
  category id above every id in use) runs again before anything is returned;
- out-of-range settings are clamped toward strict, not refused, so a vault never becomes
  unopenable over a setting.

`VaultData::encode` runs the same checks first, so Holm never writes a body it would
refuse to open. A property test (`body_roundtrip_any`) checks that any valid body
survives `decode(encode())`, and the `decode_body` and `open_fixed_key` fuzz targets
run the decoder on hostile bytes with a 64 MiB per-allocation limit.

## The vault body (schema v3)

Holm writes schema 3 and reads schemas 1, 2 and 3. The header, the envelope, the KDF and
the padding do not change. This is the body of format v1. Format v2 (`FORMAT_VERSION` 2, a 172-byte header) keeps the
same schemas only to read and migrate a v1 vault; v2 itself stores an index (schema 4) and
one sealed record per item. See "Format v2" in the Phase B design.

- The first two bytes are the body version, a `u16` little-endian. `BODY_SCHEMA_VERSION`
  is 3, `BODY_SCHEMA_V2` is 2 and `BODY_SCHEMA_V1` is 1. The `postcard` encoding follows.
- Version 1 is read with the original wire structs, kept unchanged under a `V1` name.
  Its items get an empty list of custom fields. The next save writes version 3. Holm
  never writes version 1 or 2 again.
- Version 2 uses a second set of wire structs. Each item is the version-1 item with one
  more value at the end: its list of custom fields.
- Version 3 is the version-2 layout with one more custom value variant appended: tag 4,
  `RecoveryCodes`. Versions 2 and 3 share one set of wire structs. Appending at the end
  keeps every schema-2 byte decodable, because postcard writes an enum tag as the variant
  index, so tags 0 to 3 mean what they always meant. A schema-2 body that holds tag 4 is
  `Malformed`, because an old Holm could not have written it.
- A version above 3 is `NewerSchema`, and the file is not rewritten, so the fields of a
  newer Holm are not lost. Version 0 is `UnknownSchema`. A Holm built before schema 3
  refuses a schema-3 vault with `NewerSchema(3)`.
- Why two structs and not `#[serde(default)]`: postcard writes values in order, with no
  field names and no marker for a missing value. A default on the old struct would read
  the next real value as the new field.

A custom field on the wire is, in this order:

| Part | Encoding | Rule after parsing |
|---|---|---|
| position | `u8` | the positions on one item are exactly `0..len`, with no duplicate and no gap |
| label | string | not blank, at most `MAX_LABEL_CHARS` (64) characters, no control or bidi character |
| value | enum tag, then the value: 0 `Text`, 1 `Secret`, 2 `MultilineSecret`, 3 `Date`, 4 `RecoveryCodes` | see below |
| expiry | `Option` of a date | absent, or a real day |

A date is `year: u16`, `month: u8`, `day: u8`, in that order. It must be a real Gregorian
day in years 1 through 9999 (leap years: divisible by 4, not by 100, unless by 400).

Value rules:

- `Text`: one line, at most `MAX_SECRET_BYTES` (4096), no control and no bidi character.
- `Secret`: one line, at most 4096 bytes, no NUL, CR or LF.
- `MultilineSecret`: at most `MAX_MULTILINE_SECRET_BYTES` (16384), newlines allowed, no NUL.
- `Date`: a real day, as above.
- `RecoveryCodes`: a list written as a postcard length, then each entry as
  `{code: string, used: bool}`. It holds 1 to `MAX_RECOVERY_CODES` (20) codes. More than
  20 fails while parsing, before anything is reserved: `Malformed`. An empty list is
  `Invalid`. Each code is one line, not blank, at most `MAX_RECOVERY_CODE_BYTES` (64)
  bytes, already trimmed, must not start with `*`, and has no control or bidi character.
  Each code is a `SecretText`, wiped on drop. `Debug` shows only `used`.

What the decoder refuses, and how:

- More than `MAX_CUSTOM_FIELDS` (10) fields on one item, an unknown value tag, or a
  string over the 64 KiB wire cap fails while parsing: `Malformed`. The count is checked
  before anything is reserved.
- A label or value that parses but breaks its rule, a date that is not a real day, or a
  duplicate or missing position: `Invalid`.
- Fields that arrive in another order, with exactly the positions `0..len`, are sorted
  into position order before the body is returned, so the next encode is stable.
- The string cap, the trailing-byte rule, the count caps and the cross-checks of schema
  1 are unchanged. `encode` runs the same field rules first, so Holm never writes a field
  it would refuse to read.

A custom `Secret` or `MultilineSecret` value is a `SecretText`: wiped on drop and
`[REDACTED]` in `Debug`. `CustomField` and `FieldValue` have no `Clone` and no serde.
Their `Debug` prints the kind, the label length, and whether an expiry is set. It
never prints the label, the value, or the value's length. Search reads labels only.

**Size.** The worst single item is a login with every cap reached: title 1024 bytes,
username 1024, password 4096, 32 URLs of 1024 (32768), notes 65536, ten labels of 64
four-byte characters (2560) and ten multiline values of 16384 (163840). That is 270848
bytes of text. Framing adds about 220 bytes. `maxed_login_with_ten_keys_fits_one_body`
checks that a body holding that one item encodes to between 270849 and 272000 bytes.
`MAX_BODY_LEN` holds 246 such items. A change that goes past it is `TooLargeToSave` and
is undone in memory.

**Dates.** An expiry is a date with no time and no offset. "Today" is the UTC day of
`Clock::now_unix`, converted by `from_unix_secs` and passed into pure helpers. Core
reads no timezone, so near local midnight the badge can be one day early or late. There
are no notifications. The list badge and the Expiring filter (`EXPIRING_WITHIN_DAYS` =
30, past dates included) are the whole reminder.

**The empty vault, byte for byte.** A new vault encodes to these 51 bytes under
version 1. `default_body_golden` holds them as `V1_DEFAULT_GOLDEN` and checks the
test-only version-1 writer against them, byte for byte:

```
1, 0                          schema version 1, little-endian
172, 2, 30, 1                 auto-lock 300 (varint), clipboard 30, lock on sleep
20, 1, 1, 1, 1, 0, 1, 1       password: length 20, sets, no look-alike filter, minimums
6, 1, 45, 0, 0                passphrase: 6 words, separator "-", flags
2, 3                          username: 2 words, 3 digits
3                             3 categories
1, 8, "Personal"
2, 4, "Work"
3, 9, "Community"
0                             no items
4                             next category id
```

The current encoding of a new vault is the same 51 bytes with byte 0 set to 3
(`current_default_golden_is_v1_with_version_byte_3`). An empty vault has no item, so the
fields list never appears. If either test fails, the body format changed, and that
needs a schema bump, not an edit to the test.

**The sealed golden stays schema 1.** `tests/golden_vault.rs` seals the schema-1 default
body with fixed key material, and it must still open. It is the proof that a file
written before schema 2 opens. A vault that is opened and saved becomes schema 3. The
golden test never saves. The `decode_body` fuzz seeds include a version-1 body with
items (`v1_items`), a version-2 body with fields (`v2_fields`) and a version-3 body with
recovery codes (`v3_codes`).

## Storing the file

`VaultStore` is the only way the core touches storage. Its contract: `read` refuses a
file over 64 MiB before reading any of it; `replace` is atomic against a crash (old bytes
or new bytes, never a mix); `create_new` never overwrites; `remove_stale_temps` removes
only the store's own temp files.

`holm-platform::FsStore` keeps it on disk with a durable save: write a new temp file
(`<file>.tmp-<16 hex>`, exclusive create, mode 0600 on Unix) in the same directory, sync
it, rename it over the vault, then sync the directory. The vault must be a regular file;
a symlink is refused, never followed. A `replace` error after the rename may leave the new
bytes in place, so the session treats any `replace` error as "old or new" and stays dirty.
Every change in a `Session` is saved at once. A change too large to save is undone in
memory; after any other save error the change is kept and the session stays dirty, so a
later save retries.

## Unlock throttle

`Session` keeps an in-memory throttle: two free failures, then waits of 2, 4, 8, 16 and
32 s, then 60 s for every later failure, measured on the monotonic clock. Every unlock
error counts, except a missing file and KDF costs refused on public bytes (neither runs
Argon2). It also guards phrase reveal, password change and weakening a setting. The
throttle slows a person at the keyboard. It does nothing against a stolen file: an
attacker with a copy runs Argon2 offline, as fast as their hardware allows, so the
Argon2 cost and the strength check are the real defence.

## Recovery phrase gate

A recovery phrase is stored as a `GatedSecret`, which has no public accessor.
`Session::reveal_phrase` re-checks the master password through the throttle every time
before it returns the phrase, so a UI bug cannot show one by accident.

## Generator sampling

The password, passphrase and username generators take every choice from OS randomness
through `uniform_below`, which uses rejection sampling: a 32-bit draw in the biased tail
is thrown away and drawn again, so no value is more likely than another. Minimum digit
and symbol counts are met by redrawing the whole password, so the output is uniform over
the passwords that meet the spec. There is no userspace PRNG to seed.

## Memory hygiene

Wiped when dropped: the KEK, the DEK, the master password and its NFC bytes, the Argon2
work area, the padded plaintext, the decrypted body, the unwrapped DEK buffer, and the
AEAD working buffers on both success and failure. Keys go from a wiped buffer straight
into the key's heap box, without a copy on the stack. No error carries secret bytes, and
`Debug` for `VaultKeys`, `SecretKey`, `SecretBuf` and `MasterPassword` prints no secret.

Rust cannot guarantee that temporary copies on the stack or in registers are wiped; Holm
wipes every buffer it owns and keeps secrets in heap boxes to limit copies.

Known gaps:

- Nothing is locked in RAM yet. Secrets, including the 64 MiB to 1 GiB Argon2 work area,
  can be swapped to disk by the OS while they are in use.
- The upstream `chacha20` crate does not wipe its HChaCha20 subkey, so a short-lived copy
  can remain after each seal or open.
- `argon2` and BLAKE2b leave password-derived stack temporaries unwiped: 1 KiB blocks
  in argon2's first-block init and in every compression (`r`, `q` and the result), the
  64-byte `blake2b_long` outputs (one holds a copy of the KEK), and BLAKE2b's 128-byte
  padded final block and its message words. The BLAKE2b hash state itself
  (`Blake2bVarCore` and the block buffer inside `Blake2b512`) wipes on drop, because
  Holm's direct `blake2` dependency turns on its `zeroize` feature.
- Copies made before a secret reaches Holm's types (for example, the caller's `String`
  for the password, or the normaliser's scratch space) are outside our control.
- The plaintext body passed to `create`, `reseal` and `rekey` belongs to the caller, who
  must wipe it.
- The strength check wipes every heap buffer it derives from the candidate password
  (characters, lower-cased copy, matches, search stack, split table), but like the rest of
  Holm it cannot wipe stack slots and registers that briefly hold characters or prices.
- The crash tests stop a child process with `exit` at each save step. That models a
  killed process, not a power loss: what a disk does with data still in its cache when
  power fails is not tested.
- A directory sync that the volume does not support (some FAT, exFAT and network
  volumes) is skipped, so on those volumes a completed rename may not survive a power loss.
- Windows write-through and the Windows directory sync wait for Phase 5. The lock that
  stops two Holm processes opening the same vault (`holm.lock`, see below) arrived in
  Phase 3. `holm-gui` and `holm-cli` (Phase 4) both take it before asking for a password;
  `FsStore` and `Session` do not, so any new client must take it too.

## The macOS app (Phase 3)

`holm-gui` reaches the vault only through `Session<FsStore>`. Master passwords and item
passwords are typed into Holm's own `SecretField`, which keeps them in a pre-allocated
`SecretInput` that never grows and wipes on drop, paints dots instead of laying out
text, and gives AccessKit a fixed label with no value. Create and unlock move the
password out of the field before Argon2 starts. Title, username and URL are display
text, not secrets (spec §8), and use egui's `TextEdit` with a capped, pre-allocated
`Zeroizing<String>`. A second Holm on the same vault folder finds `holm.lock` held
(std `File::try_lock`) and shows fixed text without reading the vault.

Known gaps:

- A revealed password reaches egui's text layout (galley) cache and the AccessKit tree.
  While it is shown, the reveal label's AccessKit node holds the password as its label,
  until the next frame without it replaces the node (review finding F11). Neither copy
  is wiped. Reveal hides after `REHIDE_PASSWORD_SECS`, on focus loss and on lock; the
  label is not selectable.
- `TextEdit` keeps an undo history of the title, username and URL in plain `String`s,
  which are not wiped.
- Paste makes copies Holm cannot wipe: arboard reads the pasteboard into a `String`
  (Holm moves it into `Zeroizing` at once, but the OS and arboard may keep their own),
  and a paste into a plain field becomes an egui `Event::Paste(String)`.
- Typed text arrives from winit as `Event::Text(String)` before `SecretField` copies it
  into its buffer; those event strings are not wiped.
- The GUI clears a copied value after the vault's clipboard time, on every lock and on
  quit, if the clipboard still holds Holm's value (or cannot be read back). If Holm is
  killed first, the value stays, and macOS Universal Clipboard (Handoff) may already
  have carried it to the user's other Apple devices. The copy is marked `org.nspasteboard.ConcealedType`, which
  clipboard managers may honour; that is a request, not a control.
- Holm does not turn on macOS Secure Event Input while a password field has focus, so
  an app with input-monitoring permission can read the keystrokes. Phase 5.
- The vault folder check refuses a folder that group or others can write, but checks
  neither the folder's owner nor its ACL. Phase 5.
- `holm.lock` is opened with `O_NOFOLLOW` and `O_NONBLOCK` (std only, per-target
  constants), after an `lstat`, and checked again with a device and inode match. A
  symlink swapped in is refused. What remains is the owner and ACL check on the folder
  (above). The lock is advisory, and some network filesystems ignore it.
- After a minimise lock, the last vault frame stays drawn (GL buffer, AccessKit tree,
  galley cache) until the window is restored, and the Dock thumbnail shows the vault.
  Phase 5.
- A copied password pasted into a plain field (Title, Username, Web address) shows as
  plain text, lands in the AccessKit value and the `TextEdit` undo state, and is saved
  as display text. Holm does not guard it. Phase 5.
- A foreign `Event::Paste` (not made by Holm's own Cmd+V hook) is not stripped. Phase 5.
- `TextEdit` undo state stays in egui memory after a lock, until the next frame replaces
  it or the app quits. Phase 5.
- IME `Event::Ime` preedit strings are not routed to a `SecretField` (IME is off while
  one has focus), but are not wiped if they reach egui elsewhere. Phase 5.
- A vault folder that already exists and that others can read (0755) is accepted and
  never tightened. The files inside stay 0600. Phase 5.
- On FAT and exFAT, where hard links fail, `create_new` falls back to an exclusive
  create that is not crash-atomic (see `FsStore::create_new`). Phase 5.
- The Linux and Windows builds are not compiled: local CI runs on macOS and GitHub
  Actions is off. Phase 5.
- `PasswordChangeUncertain` has no GUI: there is no change-password screen yet, and the
  Phase 5 screen must say the new password may already be needed. Phase 5.
- 206 `cargo vet` exemptions cover the GUI crates (note `gui-only, pre-release; audit or
  replace before Phase 6`). They must be audited or replaced before Phase 6.

## The command line (Phase 4)

`holm-cli` is one-shot: each command takes `holm.lock`, asks for the master password,
does its work and locks the vault on exit. There is no background agent.

- Passwords are read only from `/dev/tty`, never from argv, an environment variable,
  stdin or a pipe. With no controlling terminal the command stops with fixed text. A
  flag that looks like a password flag is a usage error that never repeats its value.
- `holm_platform::tty` puts the terminal in raw mode with echo off (safe rustix termios
  API, no `unsafe`) and edits the line itself into one pre-sized `Zeroizing` buffer that
  never grows. The bytes are moved into the `String` without a copy and on into
  `MasterPassword`. The single-byte read buffer is wiped.
- A guard restores the saved terminal mode on return, on error and on panic. After a
  refusal or Ctrl-C it flushes unread input first, so the rest of a pasted password
  does not reach the shell. `ISIG` is off, so Ctrl-C arrives as a byte and takes the
  same path.
- `get` prints every secret field as `(hidden)`, never its value or length. Display text
  goes through a filter that replaces control characters (Unicode `Cc`) and the bidi
  marks and overrides (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069). It also
  drops U+2028/U+2029, U+200B-U+200D, U+2060 and U+FEFF. Core already refuses control
  and bidi characters in display fields; this output filter also covers separators
  and invisible characters.
- In polling mode (`VMIN = 0`, `VTIME = 1`), a zero-byte read normally means a
  roughly 100 ms timeout. Three consecutive zero-byte reads taking less than 50 ms
  each mean a closed terminal (`Stop::Closed`, then `EndOfInput`). A slower zero,
  a byte, or an interrupted read resets the count. This bounds a hangup spin without
  ending an idle prompt on a real poll timeout. Outside polling mode, one zero-byte
  read means closed. Reader and clock seams cover these cases without sleeps.
- `gen` writes the value and newline from one pre-sized `Zeroizing<Vec<u8>>` with
  `write_all`, then flushes. The terminal and OS may still retain their own copies.
- `passwd` verifies the current password through `Session::verify_password` before
  asking for a new one. It shares the session throttle and leaves keys, data, dirty
  state and idle time unchanged. Read and password-check errors make no save claim.
- Messages are fixed text: never a path, a value or a library message.

`holm shell` keeps one unlocked session in one process, for many commands:

- It takes `holm.lock` once and holds it until it ends. It keeps one `Session` for its
  whole life, and `Session::lock` drops only the keys and the data, so the unlock
  throttle carries over a lock and an unlock: within one shell, the fourth wrong
  password waits.
- It locks when the vault's auto-lock time passes without a typed line (the session's
  idle timer, monotonic or a forward wall-clock jump), on `lock`, and on `exit`, `quit`,
  Ctrl-D or Ctrl-C at the prompt. Each prompt waits with a deadline, and the idle check
  runs before a typed line does, so a line typed after the idle time runs against a
  locked vault. An idle lock never waits or asks: unsaved changes are discarded and the
  message says so. `lock` and `exit` save first, and if that fails they lock only after
  `discard` is typed. After Ctrl-D or Ctrl-C at the prompt, the discard prompt drops
  the changes only if the input ends there too (Ctrl-D, or the terminal closes);
  Ctrl-C there keeps the vault open. Every lock clears the clipboard if it still
  holds Holm's value, or if it can't be read back (then Holm says it could not check).
- A command's own prompts (a hidden entry, `Type … to continue`, the discard prompt)
  wait with a deadline too: the auto-lock time from when the prompt starts. If it
  passes, the command is cancelled before it changes anything, and the shell idle-locks
  (wipes the session, clears the clipboard) before the line counts as activity.
- Inside the shell the master password is asked again only where the spec asks: export
  (again), `passwd` (the current one) and copying a recovery phrase.
- `--copy` returns to the prompt at once and schedules the clear for the vault's clear
  time, which the prompt's deadline then runs.
- There is no history. Each line and each word lives in a wiping buffer; the words reach
  the parser by moving, not copying, and are wiped after it. Passwords are never read
  from a line; they are typed at the hidden prompt.

Known gaps:

- A process killed by a signal from outside (`kill`, SIGTERM, SIGHUP) skips the guard
  and can leave the terminal with echo off until `stty sane`. Handling signals would
  need `unsafe` or a new crate. Phase 5.
- The unlock throttle lives in the `Session`, so it starts fresh in every process, and
  three tries in one command never reach its first wait. A `holm shell` keeps its
  throttle until it ends, but a new shell starts fresh. A script that runs `holm` in a
  loop is limited only by Argon2 and the instance lock: the same bound as an attacker
  with a copy of the file.
- The terminal driver, the shell's line discipline before raw mode starts, and the
  kernel's tty buffers can hold typed bytes Holm cannot wipe.
- `tty` is not built on Windows yet; there every prompt fails with fixed text. Phase 5.
- `holm shell` locks on sleep (with `lock_on_sleep` on) by watching the wall clock gain
  on the monotonic clock while it waits at a prompt; a partly typed line is wiped, not
  run. It also locks when `/dev/console` gets a new owner (fast user switching, or the
  login window, which root owns), read with `std::fs::metadata` at most once a second
  while it waits; the owner is taken at shell start and at each unlock, and an owner
  that can't be read is no change, so an error never locks. It has no run loop, so it
  cannot see a screen lock (Ctrl-Cmd-Q) that neither sleeps nor switches users; there
  the idle lock is the guard. A sleep shorter than
  `SLEEP_GAP_SECS` (5 s) with no notification is missed, in the shell and in the GUI
  alike (the GUI still gets the OS notification). A wall clock moved forward by more
  than 5 s locks too, which errs on the safe side.
- Parsed `AddArgs` and `EditArgs` text lives in `Zeroizing<String>`, including each
  URL and named category. Fields move into vault text without another copy. Paths
  and other command references still use ordinary `PathBuf` and `String` values;
  operating-system argument storage is outside this wiping guarantee.

## Import and export (Phase 4)

- Import reads CSV and JSON with Holm's own std-only parsers. Cells land in wiping
  buffers that are sized once and never reallocate. The file is read through a capped
  reader (16 MiB, regular files only, no FIFO, no growing file). A bad file fails
  whole, with fixed text and a line number, never a cell value. Rows with problems are
  skipped and reported by row number only. Imported creation and update times are
  clamped to `[0, now_unix]`; a pre-epoch local clock uses zero as the upper bound.
- Export writes plaintext CSV or JSON: every password, in the clear. The file is created new
  (never over an existing file or through a symlink) with mode 0600 on Unix. The
  data is synced before the parent folder is synced on Unix. A volume that cannot
  sync a directory follows the vault store's unsupported-directory rule; other
  parent-sync errors fail the export. There is no portable directory sync elsewhere.
  On any write or sync failure, Holm tries to truncate, sync and remove the file.
  All cleanup steps are best effort and may leave plaintext. APFS may retain freed
  blocks or snapshots even if cleanup succeeds; this is not secure erasure. The
  master password is asked again first and `EXPORT_WARNING` is shown before any
  byte is written.
- Export does not escape cells that start with `=`, `+`, `-` or `@`. Escaping would
  change the stored value, so a re-import would not match byte for byte. The warning
  names spreadsheets instead, because that is where formula injection happens.
- Custom fields (body schema 2) travel as flat cells. The 14 earlier columns keep their
  names and order. Ten slots of four columns follow: `field1_label`, `field1_kind`,
  `field1_value`, `field1_expiry`, and so on through `field10_expiry`. That makes 54
  columns, under `MAX_IMPORT_COLUMNS` (64). Slot N holds the field at position N - 1.
- The kind cell is `text`, `secret`, `multiline` or `date` on export. Import accepts
  any ASCII case. A date value and an expiry are `YYYY-MM-DD`, never Unix seconds. An
  empty expiry means no reminder.
- On import, a slot whose four cells are all empty is absent. Slots are packed from 1:
  a filled slot after an empty one is `FieldGap`. If any cell of a slot is filled, the
  label and the kind are required. An unknown kind is `BadFieldKind`. A date value or an
  expiry that is not a real `YYYY-MM-DD` day is `BadDate`. Text, secret and multiline
  values may be empty. Like every row problem, these carry the row number only, never a
  cell.
- A Holm file with only the 14 earlier columns imports with no custom fields. Columns
  are matched by name, not by position. A duplicate header is still `DuplicateColumn`.
  Chrome, Firefox and Safari files gain no columns.
- The duplicate check compares custom fields too: label bytes, kind, value bytes and
  expiry. A row that differs from an item only in a custom field is not a duplicate.
  The dedup hash key does not include any secret.
- `Session::export_json` writes the same rows as one JSON array of flat objects. Keys
  are `EXPORT_COLUMNS` in order, and every value is a string. An empty cell is `""`.
  Import reads `null` as an empty cell. There is no nested object and no array value.
  It has the same throttled password check, the same Trash exclusion, the same title
  order and the same `EXPORT_WARNING` as CSV. The writer is hand-written next to the
  JSON reader, not `serde_json`.
- Both writers measure the whole text first, then fill one buffer of exactly that size,
  so a growing `String` never leaves a copy of a secret behind. A custom secret is
  borrowed for the fill, not copied. A custom secret is in the clear in both formats,
  because the user asked for the file.
- The GUI takes the file path as typed text (no file dialog, so no new crate). The path
  sits in a plain egui `TextEdit`, so it stays in that widget's undo history until the
  app closes. It is a display field, not a secret. The vault search box is a plain
  `TextEdit` too and shares this exposure: what the user typed to search (a title,
  username or URL fragment) stays in its undo history after a lock until the app closes.
  Windows file permissions on the export file are Phase 5.

## Not claimed

- Memory is not fully wiped and not locked; see above.
- No key file. v1 uses the master password only; a key file is deferred to v2.
- No rollback protection. An older copy of the vault, with its old password, still opens.
- No forward secrecy between normal saves. `reseal` keeps the DEK, so the current
  password opens every copy saved since the last password change.
- No equal timing. A wrong password returns before the body is decrypted, so it can be
  faster than a damaged body (see "Opening a vault"). Format and policy errors are decided
  on public bytes and are returned early by design.
- Argon2id makes guessing expensive. It does not make a weak password safe.
