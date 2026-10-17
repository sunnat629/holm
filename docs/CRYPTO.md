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
- The `argon2` crate's own small temporaries (its BLAKE2b state and a 1 KiB stack
  buffer) are not wiped.
- Copies made before a secret reaches Holm's types (for example, the caller's `String`
  for the password, or the normaliser's scratch space) are outside our control.
- The plaintext body passed to `create`, `reseal` and `rekey` belongs to the caller, who
  must wipe it.

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
