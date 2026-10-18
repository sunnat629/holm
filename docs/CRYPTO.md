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

`envelope::open` does these steps, in this order:

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
  rule-based cracking reaches in far fewer guesses, so the COS raised it to score 4.
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

The padded plaintext is a `u16` little-endian schema version (1), then the `postcard`
encoding of the settings, the categories, the items and the next category id.
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
- Windows write-through, the Windows directory sync and the file lock that stops two
  Holm processes saving the same vault wait for Phase 5.

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
