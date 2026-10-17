# Holm v1 design (Rust)

Date: 2026-10-17
Status: draft for owner review
Repo: `~/IdeaProjects/holm`, licence MIT OR Apache-2.0

## 1. Intent

Holm is a local-only, offline password and secrets vault. One encrypted file, no account, no cloud, no network. v1 is written from zero in Rust and published as open source once v1 is done.

Security is the main concern. Looks are secondary: the UI should be plain and clear, not fancy.

The earlier Kotlin/JVM project (`~/IdeaProjects/harbor`) was a draft. No code, build tooling or file format carries over. What carries over is knowledge: the threat model, crypto choices, test vectors and the bugs it found. Section 13 lists those lessons.

## 2. Goals, non-goals, anti-goals

**Goals**
- Strong, boring, well-reviewed cryptography. No custom constructions.
- A security core small enough for an outside auditor to read in a few days.
- Honest claims. Every security statement in the docs is backed by a test or marked as a limit.
- Desktop first: macOS, Windows, Linux. Then Android, then iOS, all sharing the same Rust core.
- Open source that people can verify: public code, signed and reproducible releases, published threat model.

**Non-goals for v1**
- Sync, cloud, accounts, sharing, browser extension, autofill.
- Mobile apps (designed for, not built).
- Biometric unlock, hardware keys, TOTP codes, attachments.
- Opening vaults from the old Kotlin app.

**Anti-goals (failure even if it works)**
- Any network code in the app, including telemetry, crash reporting or update checks.
- Plaintext secrets written to disk at any point (temp files, logs, caches, UI state files).
- Secrets in logs, panic messages or `Debug` output.
- Marketing claims such as "unhackable" or "military-grade".
- A large dependency tree nobody has reviewed.

## 3. Threat model (summary)

Full version goes in `docs/THREAT-MODEL.md`, adapted from the old project.

| Attacker | In scope? | What Holm does |
|---|---|---|
| Steals or copies the vault file (laptop theft, backup leak) | Yes, primary | Argon2id plus XChaCha20-Poly1305. Security then rests on master password strength |
| Edits the vault file to weaken it or crash Holm | Yes | Every header field is authenticated; KDF costs are bounded before any work; the parser is fuzzed |
| Person at an unlocked, unattended computer | Partly | Auto-lock, lock on sleep and screen lock, password re-entry for recovery phrases and settings changes |
| Clipboard snooping and clipboard history | Partly | Auto-clear, plus OS hints that ask clipboard managers not to record |
| Screen recording or screenshots | Partly, best effort | Exclude the window from capture where the OS allows (Windows yes, macOS partly, Linux no) |
| Malicious or fake Holm build, poisoned dependency | Yes, via process | Signed releases, reproducible builds, dependency audit gates |
| Malware running as the same user while unlocked | No | Cannot be defended against. Documented plainly |
| Rollback (swapping in an older copy of the file) | No | Documented. Needs outside state Holm does not have |

Never claim: brute force is impossible; backoff protects a stolen file; desktop screenshots are blocked; deleted items vanish from old copies or backups; memory is fully wiped.

## 4. Architecture

One Cargo workspace. Security code sits in the smallest crates, with the fewest dependencies.

| Crate | Job | `unsafe` |
|---|---|---|
| `holm-crypto` | Argon2id, XChaCha20-Poly1305, key types, random numbers, secret types that wipe on drop | Forbidden |
| `holm-core` | File format, vault open/save/lock, items, search, generator, password strength, import/export, session rules | Forbidden |
| `holm-platform` | OS-specific code: data paths, file lock, durable writes, clipboard, idle and screen-lock events, memory locking, capture exclusion, core-dump disable | Allowed only here, every block commented and reviewed |
| `holm-cli` | Command-line app. Built first; used for testing and scripting | Forbidden |
| `holm-gui` | egui (eframe) desktop app, thin layer over `holm-core` | Forbidden |
| `holm-ffi` (later) | UniFFI bindings so Android (Kotlin) and iOS (Swift) can use `holm-core` | n/a |

Rules:
- `holm-core` reaches the disk and the OS only through traits, so tests can inject faults and mobile can plug in its own storage later.
- Core API is synchronous and single-owner. The GUI runs slow work (Argon2) on a worker thread and talks to the core through one session handle.
- Mobile UIs will be native (Jetpack Compose on Android, SwiftUI on iOS) over `holm-ffi`. egui is for desktop only.

## 5. Cryptography

### 5.1 Primitives

| Job | Choice | Crate |
|---|---|---|
| Password to key | Argon2id v1.3 (RFC 9106) | `argon2` (RustCrypto) |
| Encryption | XChaCha20-Poly1305 (AEAD) | `chacha20poly1305` (RustCrypto; its ChaCha20-Poly1305 code had an NCC Group audit in 2020) |
| Randomness | OS random source | `getrandom` / `rand_core::OsRng` |
| Wiping memory | Zero on drop | `zeroize`, `secrecy` |
| Unicode cleanup | NFC normalisation | `unicode-normalization` |
| Password strength | zxcvbn estimate | `zxcvbn` |

The `argon2` crate has no published outside audit that we know of. To cover that, tests check it against RFC 9106 vectors, and a test-only cross-check against libsodium (`libsodium-sys-stable`, never shipped) runs in CI. libsodium only supports parallelism 1, which is one reason v1 fixes parallelism at 1 (section 5.3).

### 5.2 Keys

```
master password --NFC + UTF-8--> Argon2id(salt, m, t, p) --> KEK (32 bytes)
random DEK (32 bytes, made at create)
header holds:  wrap = XChaCha20-Poly1305(KEK, wrap_nonce, DEK, aad = header fields before the wrap)
body:          XChaCha20-Poly1305(DEK, body_nonce, padded plaintext, aad = whole header)
```

- The KEK is derived from the password with Argon2id. The DEK is a separate random key that encrypts the vault body.
- **Changing the master password rotates the DEK as well**, with a fresh salt and nonces. If only the wrap changed, someone holding an old copy of the file plus the old password could recover the DEK and read every later version.
- Every save uses a fresh random 24-byte body nonce. Random nonces are safe at this size for XChaCha.
- Passwords are NFC-normalised before UTF-8 encoding, so the same password typed on macOS, Windows or a phone produces the same bytes. The old project had real trouble with password byte encoding.

### 5.3 Argon2id costs

| | Memory | Iterations | Parallelism |
|---|---|---|---|
| Default for new vaults (provisional) | 256 MiB | 3 | 1 |
| Floor (refuse to create or open below) | 64 MiB | 3 | 1 |
| Ceiling (refuse to open above, checked before any work) | 1 GiB | 16 | 1, and memory × iterations ≤ 4 GiB |

Parallelism is fixed at 1 in v1 (my call): every value Holm accepts can then be cross-checked against libsodium, and the header field leaves room to allow more later.

The builder measures the default on a slow reference machine. Target: unlock under about 1.5 s on that machine. The default must also be openable on a mid-range phone later; if not, lower it, but never below the floor. Costs are stored in the header, so later versions can raise them. A cost rejection is its own error ("this vault needs more resources than allowed"), never reported as "wrong password".

## 6. Vault file format v1

One file, default name `holm.vault`. Little-endian, fixed-size header, exact framing. Trailing bytes are rejected.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `HOLMVLT\0` |
| 8 | 2 | format version = 1 |
| 10 | 2 | flags = 0 (any other value rejected) |
| 12 | 1 | KDF id = 1 (Argon2id v1.3) |
| 13 | 3 | reserved, must be zero |
| 16 | 4 | Argon2 memory, KiB |
| 20 | 4 | Argon2 iterations |
| 24 | 4 | Argon2 parallelism |
| 28 | 32 | salt |
| 60 | 24 | wrap nonce |
| 84 | 48 | wrapped DEK (32 + 16 tag) |
| 132 | 24 | body nonce |
| 156 | 8 | body ciphertext length |
| 164 | n | body ciphertext (includes 16-byte tag) |

- Wrap AAD = bytes 0..60. Body AAD = bytes 0..164.
- There's no CRC. The AEAD tag is the only integrity check, so nobody can mistake a CRC for authentication.
- Opening order: check file size is at most 64 MiB; read and check the fixed header; check KDF costs against floor and ceiling; check length fields with checked arithmetic; only then run Argon2.
- Body plaintext is `postcard` (serde) with its own schema version, padded to a multiple of 16 KiB so the file size reveals little about the item count.
- A wrong password and a tampered file give the same error. That's unavoidable and correct.

The exact field layout is the builder's to finalise. The rules above are not.

## 7. Data model (v1)

- **Login**: title, username, password, URLs, notes.
- **Crypto address**: title, chain, address, memo, notes.
- **Recovery phrase**: title, phrase, notes. Showing or copying the phrase needs the master password again; it is never copied by default.
- **Secure note**: title, body.
- Shared fields: id (random 128-bit), category, favourite, created and updated times, trashed time.
- **Categories**: built-in Personal, Work, Community, plus user-made. Rename and delete; deleting moves items to "Uncategorised".
- **Trash**: delete moves to trash. Restore, delete forever, empty trash. Because the whole body is rewritten on every save, deleted-forever items are gone from the new file (not from old copies or backups).
- **Search**: title, username, URL, chain, category. Never secret fields.

Every secret field (passwords, phrases, note bodies, addresses) uses a type that wipes on drop and prints `[REDACTED]` in `Debug`.

## 8. Feature list (v1)

0. **Vault location** (owner decision): one vault open at a time. A default path per OS (macOS `~/Library/Application Support/Holm/holm.vault`, Windows `%APPDATA%\Holm\holm.vault`, Linux `~/.local/share/Holm/holm.vault`), and the user can also create or open a vault file anywhere, such as a USB stick. The last-used path is remembered in the UI config file. No vault switcher or vault list in v1.
1. Create vault, with strength check (zxcvbn score at least 3 and at least 12 characters). Weak passwords are refused outright; no override.
2. Unlock, lock, auto-lock on idle (default 5 min), lock on OS sleep and screen lock, lock on quit.
3. Add, edit, view, search, sort and filter items across all four types. Categories, favourites, trash.
4. Copy to clipboard with auto-clear (default 30 s). It clears only if the clipboard still holds what Holm put there. Recovery phrases are never copied without re-entering the master password.
5. Generator: passwords (length, character sets, avoid look-alikes, minimum digits and symbols), passphrases (EFF large word list, separator, capitals, number), usernames. Uniform sampling by rejection, OS randomness only.
6. Change master password (rotates DEK; section 5.2).
7. Import: generic CSV/JSON using the column schema of the old Kotlin importer (`harbor/spikes/spike-import-v1.md`: title, username, password, url, notes, category, type, chain, address, memo, recovery), and browser CSV (Chrome, Firefox, Safari). Size-limited, with a warning to delete the source file afterwards.
8. Export: encrypted backup copy of the vault. Plaintext CSV export only after master password re-entry and a clear warning (my call: people should never be locked in to an open-source tool).
9. Settings: auto-lock time, clipboard time, lock on sleep, generator defaults. These security settings live **inside the encrypted body** (my call), so nobody can weaken them by editing a file; making any of them weaker needs the master password again. A separate plain config file holds only harmless UI preferences (window size, theme, last vault path).
10. CLI: `holm init`, `list`, `get`, `add`, `edit`, `rm`, `gen`, `import`, `export`, `passwd`, `shell`. Passwords are read from the terminal with no echo, never from flags. There is **no background agent** (my call): each one-shot command asks for the password and opens the vault, and `holm shell` keeps one unlocked session inside a single interactive process, with the same throttle and auto-lock as the GUI. An agent would add IPC and client-authentication surface for little gain in v1.

## 9. Desktop security controls

| Control | macOS | Windows | Linux |
|---|---|---|---|
| Durable save | temp file in same dir, `sync_all` (F_FULLFSYNC), rename, sync dir | temp file, flush, rename with replace, write-through | temp file, fsync, rename, fsync dir |
| One process per vault | OS file lock on `holm.vault.lock` | same | same |
| Clipboard history hint | `org.nspasteboard.ConcealedType` | `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0` | `x-kde-passwordManagerHint: secret` |
| Screen capture | `NSWindow.sharingType = none` (newer capture APIs may ignore it) | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` | none available |
| Lock on sleep / screen lock | workspace notifications | session and power notifications | logind D-Bus signals |
| Core dumps off | `setrlimit(RLIMIT_CORE, 0)` | best effort | `prctl(PR_SET_DUMPABLE, 0)` and rlimit |
| Key memory kept out of swap | `mlock` on key pages | `VirtualLock` | `mlock` |

Only the KEK and DEK are locked in memory (my call). `holm-platform` provides the locked allocation and `holm-crypto` uses it through a small trait, so `holm-crypto` stays free of `unsafe`. The decrypted vault body, item secrets and GUI buffers are wiped on drop but **not** locked, so swap or hibernation files may hold them. The docs say so and recommend full-disk encryption (FileVault, BitLocker, LUKS).

Leftover temp files from a crash are deleted on the next open. There is no backup-file juggling: the old project's bugs came from that, and atomic rename works on all three targets.

The vault is not excluded from Time Machine or other backups (my call). An encrypted copy in a backup is covered by the threat model, and losing your only copy of every password is the bigger risk.

## 10. GUI (egui)

- Three panes: menu (Vault, Generator, Settings, Lock), list (search, category chips, sort, New), detail (view or edit). Locked state shows only the unlock screen.
- Plain look, system-like font, light and dark themes, keyboard shortcuts. Accessibility through egui's AccessKit support.
- Secret entry uses Holm's own small password widget, not egui's `TextEdit` (my call). `TextEdit` keeps its own copies through undo history, the layout cache and the accessibility tree. The Holm widget has no undo, lays out only mask characters, exposes no value to accessibility tools, and keeps text in a pre-allocated buffer that wipes itself. A revealed secret is shown read-only, straight from the wiping buffer. This **reduces** copies; it can't promise there are none (font and GPU layers may still hold rendered glyphs).
- egui's built-in state saving (`persistence` feature) is **off**, so titles and search text never land on disk.
- The secrets never appear in the window title, notifications or OS recent-items lists.
- Unlock and password-change run on a worker thread with a progress state. The UI stays responsive and the session handle is the only route to the core.

## 11. Unlock limits

- The real protection against a stolen file is Argon2 plus a strong password. The doc says so.
- In-app throttle: after 3 failures in a row, wait 2, 4, 8 … seconds, capped at 60 s, before the next try. It resets on success. It's kept in memory only (my call): the old project's on-disk lockout record was tamperable and caused many edge cases, and a restart only saves a person at the keyboard a little time when every guess already costs a full Argon2 run.
- The same throttle covers recovery-phrase reveal and password change, so an unattended unlocked session can't be used to guess the password quickly.

## 12. Supply chain and open source

**Code rules**
- `#![forbid(unsafe_code)]` in every crate except `holm-platform`.
- `clippy -D warnings`, `rustfmt`, pinned toolchain in `rust-toolchain.toml`, `Cargo.lock` committed.
- No networking crates anywhere in the dependency graph. `cargo-deny` bans them (`reqwest`, `hyper`, `ureq` and similar) and fails CI if one appears.

**Dependency gates**: `cargo-deny` (licences, advisories, bans, sources), `cargo-audit`, `cargo-vet` (reusing published audits from Mozilla, Google and others), SBOM via `cargo-cyclonedx`.

**Tests**
- Known-answer tests: RFC 9106 Argon2id vectors, draft-irtf-cfrg-xchacha vectors, the Wycheproof XChaCha20-Poly1305 file, libsodium cross-check (test-only).
- Property tests (`proptest`) for format round trips, generator distribution and import parsing.
- Fuzzing (`cargo-fuzz`) on header parsing, full open with a fixed key, body decoding, CSV and JSON import. Runs in CI on a schedule.
- Hostile-file fixtures: too large, truncated, trailing bytes, out-of-range costs, flipped bits in every header field.
- Crash tests: a child process is killed at each save step, then a fresh process must open either the old or the new vault, never neither (method taken from the old project).
- `holm-platform` `unsafe` code is checked by line-by-line review and by tests on real machines for each OS. Miri can't run FFI or system calls, so it gives no real assurance there and isn't counted.
- CI on macOS, Windows and Linux.

**Releases**
- macOS: Developer ID signing and notarisation, `.dmg`. The owner already has an Apple Developer account.
- Windows: Authenticode signing, `.msi`. No certificate yet; Phase 6 includes getting one (a paid certificate, or Azure Trusted Signing).
- Linux: AppImage and Flatpak.
- Every release: checksums, a signature (minisign or Sigstore), GitHub build provenance attestation, and documented steps to reproduce the build. "Reproducible" means the **unsigned binaries** rebuild bit-for-bit (my call). Signed installers can't be identical, so anyone can strip the signature and compare the binary inside.
- No auto-updater in v1 (it would need network code). Users download signed releases.

**Open source pack** (what "going open source" needs): `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, `SECURITY.md` (private reporting address and response promise), `THREAT-MODEL.md`, `CRYPTO.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, public CI, and an outside security audit before the release is called 1.0.

## 13. Lessons carried over from the old project

| Old problem | v1 answer |
|---|---|
| Hand-written HChaCha20 glue needed its own review | Use the crate's built-in XChaCha type |
| JVM strings could not be wiped | Rust wipe-on-drop types; secret text buffers in the GUI |
| SQLite temp files and free pages could hold plaintext | No SQLite; serialised structs held in memory |
| Recovery-phrase save wrote zeros (buffer wiped too early) | Rust ownership, plus a save-then-reopen test for every item type |
| Unbounded Argon2 costs from an unauthenticated header | Floor and ceiling checked before any work |
| CRC mistaken for integrity | No CRC |
| Backup-file juggling after crashes, with unauthenticated recovery | Atomic rename only; crash tests |
| Tamperable on-disk lockout record | In-memory throttle; honest docs |
| Malformed Unicode password bytes | NFC plus UTF-8 only; Rust strings are always valid UTF-8 |
| Black or blank screenshots in CI smoke tests | Core logic tested headless; GUI smoke tests check images are not blank |

## 14. Build phases

Each phase ends with a security review before merge.

| Phase | Output | Done when |
|---|---|---|
| 0 | Repo, workspace, CI on three OSes, deny/audit/vet gates, open-source files | CI green on an empty workspace |
| 1 | `holm-crypto` plus file format | All known-answer tests pass, fuzzers run, hostile fixtures rejected |
| 2 | `holm-core`: vault, items, generator, import/export, throttle | Full round trip; crash tests pass |
| 3 | `holm-cli` | Daily use possible from the terminal |
| 4 | `holm-platform`: lock, durable save, clipboard, OS events, capture exclusion | Per-OS manual checklist passed on real machines |
| 5 | `holm-gui` (egui) | All v1 features through the GUI |
| 6 | Hardening and release | Internal review, long fuzz run, outside audit, signed installers, public repo |
| Later | Android (`holm-ffi` + Compose), then iOS (SwiftUI) | Separate design |

Team process, from the shared rules: grok CLI writes the code, Sonnet reviews UI, and Opus does the security review that gates every merge.

## 15. Left to the builder

- Exact crate versions, internal module layout, error type design.
- Exact header byte layout, within the rules in section 6.
- The final Argon2 default after measuring.
- egui theme details and icons.
- CLI flag names.
