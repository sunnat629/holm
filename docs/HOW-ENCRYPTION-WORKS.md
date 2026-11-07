# How Holm's encryption works

This is a walkthrough from the master password you type to the bytes on disk. It assumes you know what a hash and a key are, and nothing more. For the exact rules, see [CRYPTO.md](CRYPTO.md) and [THREAT-MODEL.md](THREAT-MODEL.md). For the byte layout, see [FILE-FORMAT.md](FILE-FORMAT.md).

Holm has had no third-party audit. Nothing here is a promise that it is free of mistakes. It is an explanation of what the code does and why.

## The shape of it

```
master password
      |  Argon2id (slow on purpose, needs 256 MiB)
      v
   KEK  (32 bytes, never stored)
      |  unwraps
      v
   DEK  (32 random bytes, stored only in wrapped form)
      |  encrypts
      v
   index + one record per item
```

Two keys, not one. The KEK comes from your password. The DEK is random and does the real work. The file stores the DEK encrypted under the KEK.

## Step 1: the password becomes a key

Your master password is first normalised to Unicode NFC and encoded as UTF-8. This makes `e` plus a combining accent and the single character `e with accent` produce the same bytes, so a password typed on two keyboards still opens the vault.

Then Holm runs Argon2id, version 1.3, with:

| Setting | Value |
|---|---|
| Memory | 256 MiB (262144 KiB) |
| Iterations | 3 |
| Parallelism | 1 |
| Salt | 32 random bytes, stored in the header |
| Output | 32 bytes, the KEK |

Why Argon2id: it is designed to be expensive in memory, not only in CPU time. A person unlocking once waits a fraction of a second. An attacker who guesses billions of passwords has to pay that memory cost on every guess, and memory is hard to scale on a GPU or a custom chip.

Why these numbers: 256 MiB is large enough to hurt a guessing rig and small enough for any Mac. On the developer's machine (an Apple M3 Pro) one run takes about 0.36 seconds. RFC 9106's lower-memory recommendation also uses 3 passes (with 64 MiB and 4 lanes), and Holm's floor is the same 64 MiB and 3 passes. Parallelism is 1 so that every accepted setting can be cross-checked against libsodium in the `oracle/` tests. The default is marked provisional in CRYPTO.md, so expect it to be tuned.

The file also records the settings it was made with. Holm refuses to open a file that asks for less than 64 MiB with 3 iterations, and a file that asks for too much (over 1 GiB, over 16 iterations, or more than 4 GiB of total memory passes). The check runs on public header bytes before Argon2 starts, so a hostile file cannot make Holm allocate 100 GiB.

The salt is not secret. It is there so two people with the same password get different keys, and so an attacker cannot reuse one precomputed table.

## Step 2: the KEK wraps a random DEK

When you create a vault, Holm draws 32 bytes from the operating system's random source. That is the DEK, the data encryption key. There is no fallback random source. If the OS fails to give random bytes, Holm stops.

The file stores the DEK as 48 bytes: the 32-byte DEK encrypted with the KEK, plus a 16-byte authentication tag. This is called wrapping.

Why not encrypt the vault straight under the password-derived key? Because of the password change. The design lets you change the password by deriving a new KEK from the new password and a new salt, then wrapping the same DEK again. The 48 wrapped bytes change and the data does not. That is the cheap path, and it is the reason for having two keys.

Holm deliberately does not take that cheap path. A password change makes a new DEK and re-seals every record and the index under it. Here is why. Suppose someone kept an old copy of the file and knows the old password. If only the wrap changed, they could unwrap the DEK from their old copy and use it to read every later version of the vault, whatever the new password is. With a new DEK, the old password opens only the old copies. Those old copies stay readable with the old password, which cannot be avoided, because the copy is already in their hands.

The cost is small: one Argon2 run, an in-memory re-seal of the items, and one file write. The write is atomic, so a failure leaves the old file in place.

## Step 3: XChaCha20-Poly1305

Everything is sealed with XChaCha20-Poly1305. It does two jobs at once:

- Confidentiality: the ciphertext looks random without the key.
- Integrity: a 16-byte tag proves nobody changed the ciphertext or the associated data. If one bit is wrong, opening fails. There is no partial result.

Every seal takes a 24-byte nonce. Holm draws a fresh random nonce for every seal and stores it in the file next to the ciphertext.

Is a random 24-byte nonce safe? The danger of a nonce is using the same one twice with the same key. With 24 random bytes (192 bits) the chance of a repeat is far below anything that matters, even after billions of seals under one key. A 12-byte nonce, as in plain ChaCha20-Poly1305 or AES-GCM, does not have this room, which is why those designs need counters or care. With XChaCha20, a random nonce is the simple, standard choice.

Holm adds a guard in the type system. The `Nonce` type cannot be copied or cloned, and `seal` takes it by value. Safe code cannot seal twice with the same nonce object. Lesson 05 walks through the AEAD code and lesson 02 explains why the type works this way.

## Step 4: AAD, the part that binds things together

AEAD takes an optional input called AAD, additional authenticated data. It is not encrypted, but it is covered by the tag. If the AAD at open time differs from the AAD at seal time, the open fails.

Holm uses it so that a ciphertext only opens in the exact place it was made for.

| What | AAD | What it stops |
|---|---|---|
| The wrapped DEK | Header bytes 0 to 59 (magic, version, flags, KDF settings, salt) | Changing the salt or the Argon2 settings to trick Holm. A v1 wrap does not open under a v2 header, because the version number is in the AAD. |
| The index | The whole 172-byte header | Changing the index nonce or either length field. |
| Each record | `HOLMREC\0`, the 132-byte key block, the 16-byte item id, and the record generation | Moving a record to another item, or into another vault, or back to an older version. |

What these checks stop in practice:

- Swapping two records. The item id is in the AAD, so a record cut from item A fails to open as item B.
- Moving a record into a different vault. The key block, which holds the salt and the wrapped DEK, is in the AAD, so it does not match.
- Rolling one record back to an older copy. The index pins the generation, nonce and length of each record. An older record has a different generation and nonce, so it is refused.
- Truncating or extending the file. The header says how long the index and the records are, and those lengths are authenticated, so any cut or appended byte makes the file fail to parse or fail to open.
- Replacing the index with an older one. An older index does not match the records on disk, and a mismatch shows up as a damaged item when you open it.

What it does not stop: someone who replaces the whole file with an older whole file. That is a valid file from the past, and Holm has no place to remember "newer". This is listed in the threat model.

## Step 5: decrypt on demand

A vault is not one encrypted blob. It has an index and one record per item.

- The index holds what the list needs: title, username, URL, category, dates, flags. It is sealed as one unit.
- Each record holds the secrets of one item: password, notes, recovery codes, secret custom fields. Each record is sealed on its own.

When you unlock, Holm opens the index and keeps the records sealed. When you reveal a password, Holm opens that one record, copies the one secret you asked for into a buffer that wipes itself, and drops the rest. When you edit an item, only that item's record is re-sealed. The other records keep their old ciphertext byte for byte.

Both the index and the records are padded before sealing, so the file size does not show exact lengths. Records are padded to 256-byte steps and the index to 16 KiB steps. A copy of the file still shows that something changed and roughly how big it is.

## What stays in RAM while unlocked

Be clear about this part. While the vault is unlocked, these are in memory:

- The DEK.
- The index, which means every title, username, URL, label, date and flag in the vault.
- The sealed records, which are ciphertext.

So a full memory dump of the Holm process while it is unlocked gives an attacker the DEK. With the DEK they can open every record. Holm opens records on demand to keep plaintext secrets short-lived, but this does not help against someone who can read all of the process memory.

Holm tries to limit the damage. It wipes keys and secret buffers when they are dropped, uses a global allocator that zeroes freed blocks, turns off core dumps, and locks the vault after idle time, on quit, and on sleep when that setting is on. These are best effort. They do not cover the stack, AppKit internals, the GPU or swap, and Holm does not pin memory with `mlock`.

## What Holm does not protect against

- Malware running as you. If something runs as your user, it can read Holm's memory, watch the screen and read what you type. Encryption at rest cannot help once the vault is open.
- A keylogger. It records the master password as you type it.
- A weak master password. Argon2id makes each guess expensive. It does not make a short or common password safe. Holm's strength check refuses very weak passwords at creation, but a long random phrase is still the best defence.
- A stolen file with a lot of money behind the guessing. The unlock delay in the app (waits after the third wrong try) only slows a person at the keyboard. An attacker with a copy of the file runs Argon2 offline.
- An old backup. A copy made before a password change still opens with the old password.
- Hibernation images and crash dumps. These are not covered.
- A vault file replaced by an older valid vault file (rollback of the whole file).

There is no claim here that brute force is impossible, that screenshots are blocked, that memory is fully wiped, or that deleted items vanish from old copies. The full list is in [THREAT-MODEL.md](THREAT-MODEL.md).

## Where to read next

| Topic | Lesson |
|---|---|
| Argon2 and the constants | 04 |
| AEAD and slices | 05 |
| Parsing the header | 06 |
| Secret types and `Drop` | 02 |
| One record per item | 67 |
| Opening one item at a time | 68 |
| Memory hygiene | 66 |
| Migrating v1 to v2 and keeping a way back | 69 |

Next: [FILE-FORMAT.md](FILE-FORMAT.md).
