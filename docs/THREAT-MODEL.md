# Threat model

Holm is a local-only, offline password and secrets vault: one encrypted file, no account,
no cloud, no network. This page says who we defend against, who we do not, and which
claims we refuse to make.

**Status:** this page describes the v1 design. Memory hygiene (Phase A), decrypt on demand (Phase B) and the trust tooling
(Phase C) are in the repository; the signed release and the independent audit are not done yet.
Each defence is backed by a test, or marked as a limit.

## What we protect

The contents of the vault file: logins, crypto addresses, recovery phrases and notes.
Item contents are encrypted. The header is not secret, but every header field is authenticated.

## Attackers

| Attacker | In scope? | What Holm does |
|---|---|---|
| Steals or copies the vault file (laptop theft, backup leak) | Yes, primary | Argon2id plus XChaCha20-Poly1305. Security then rests on master password strength. |
| Edits the vault file to weaken it or crash Holm | Yes | Every header field is authenticated. KDF costs are bounded before any work. The header parser, padding, body decode and the full open with a fixed key are fuzzed (`fuzz/`). |
| Person at an unlocked, unattended computer | Partly | Auto-lock, lock on minimise, lock on sleep, screen lock and logout (the GUI listens for all four; `holm shell` locks on sleep and on a fast user switch or the login window, seen as a new `/dev/console` owner, but not on a screen lock (Ctrl-Cmd-Q) with neither, where it relies on auto-lock), password re-entry for recovery phrases and settings changes. |
| Clipboard snooping and clipboard history | Partly | Auto-clear in the CLI, the shell and the GUI, plus OS hints that ask clipboard managers not to record. |
| Screen recording or screenshots | Partly, best effort | Exclude the window from capture where the OS allows it (Windows yes, macOS partly, Linux no). |
| Malicious or fake Holm build, poisoned dependency | Yes, via process | Dependency gates (cargo-deny, cargo-audit, cargo-vet) run locally before every merge. Phase C adds: a local reproducible-build check (`scripts/repro-check.sh`: two rebuilds on one machine match; the signed app and the DMG do not), a CycloneDX SBOM per binary (`scripts/sbom.sh`, also written next to the DMG), long fuzz runs (`scripts/fuzz-long.sh`), mutation testing (cargo-mutants on `holm-crypto` and `holm-core`, report in `docs/security/`) and timing gates (`scripts/bench-gates.sh`). Signed releases are a Phase 6 step. These let a reviewer rebuild and compare; they do not prove the source is free of bugs. |
| Crash dump or freed memory read later (same machine) | Partly | Core dumps are off from the first line of `holm-gui` and `holm` (`RLIMIT_CORE` 0). A global allocator zeroes every block before it is freed, and a lock wipes the window state. Stack copies, AppKit and GPU driver memory and the OS swap are not covered. No `mlock` (see DECISIONS). |
| Malware running as the same user while unlocked | No | Cannot be defended against. Documented plainly. |
| Rollback (swapping in an older copy of the file) | No | Documented. Needs outside state Holm does not have. |
| Partial memory capture while unlocked (one swapped page, a heap read bug, freed memory handed to other code, a dump grepped for strings) | Partly (Phase B) | Passwords, notes, phrases and secret custom fields are sealed per item and decrypted only when shown or copied, then dropped. A capture without the data key shows none of them except the value on screen. Tests: the session read API tests (`reveal`, `open_item`), `eye_release_hides` and `custom_field_hides_after_thirty_seconds`. The data key and the index (titles, usernames, URLs, labels, dates) stay in RAM while unlocked, so a full dump still opens everything. |
| Hibernation image or crash dump | No (not closed by Phase B) | Both hold the key and every record together. Advice: FileVault, and no crash-dump upload. Holm sets `RLIMIT_CORE` to 0 (Phase A), which does not cover the OS. |

## Limits we state plainly

- A weak master password is the weakest link. Argon2id slows guessing; it does not stop it.
- The unlock throttle slows a person at the keyboard. It does nothing against a stolen file: a copy is attacked offline at the Argon2 cost alone.
- Tampering with the encrypted data, or with any header field that still parses, looks the same as a wrong password. That is unavoidable and correct. Format errors and KDF cost rejections are their own errors, never reported as a wrong password.
- A deleted item is gone from the new file, not from old copies or backups of it.
- Format 2 hides record count and sizes inside one file, but two copies of the file (Time Machine snapshots, the migration backup, any backup) show which record changed, its size in 256-byte steps, the record count and boundaries (from spans that stay the same), and whether an edit touched a secret (the record changes) or only public fields (the index changes). Contents stay hidden. Accepted: re-sealing only what changed is what keeps secrets out of RAM.
- A vault and its copies made before the next password change share one key block and data key. A record from such a copy has a valid tag in the other, and only the nonce pinned in the index stops a splice (`tamper_record_from_backup_copy`). A password change makes a new data key and ends this.
- Public item fields (title, category, username, URLs, labels, custom Text and Date values, used flags, whether a password or note exists) are in the index and in RAM while unlocked. Secret fields are in records. Editing a public field changes only the index; editing a secret re-seals that item's record.
- Records are checked when opened, not at unlock. A damaged record shows as a damaged item when you open it; unlock does not find it. A whole-file rollback to an older copy is still not detected.
- The migration backup (`<vault>.v1-<hex>.bak`) is a full old-format vault that opens with the old password. It keeps deleted items and, after a password change, still opens with the old password (Never claim 4). Holm never deletes it without a yes and offers to after unlock and again after a password change. Deleting it does not remove Time Machine copies or SSD remnants.
- Wiping memory is best effort. See the claims below.
- Holm cannot see or stop what the operating system, other programs or hardware do.
- A CSV export is every password in plain text, in a file the user chose to create. Holm asks for the master password, shows a warning first, creates the file new with owner-only permissions (0600 on Unix) and never overwrites one, but after that the file is outside Holm's protection: backups, sync folders, spreadsheet apps and anyone with the user's file access can read it. Full-disk encryption and deleting the file promptly are the only defences.
- The import source file is also plaintext on disk, by the user's choice. Holm reads it and never changes it, and tells the user to delete it after a good import. The GUI path field keeps the typed path in egui's undo history; it is a path, not a secret.
- A copied password stays on the clipboard until something else replaces it. any app can read it, and macOS Universal Clipboard (Handoff) can send it to the user's other Apple devices. The Copy button says so. From Phase 5 the GUI clears it after the vault's clipboard time, on lock and on quit, if it still holds Holm's value.

## Never claim

Holm's documentation, website and release notes must never say any of these:

1. Brute force is impossible. It is only made expensive.
2. Backoff or lockout protects a stolen file. A copied file can be attacked offline with no limits.
3. Desktop screenshots are blocked. Capture exclusion is best effort and differs by OS.
4. Deleted items vanish from old copies or backups. Only the new file drops them.
5. Memory is fully wiped. Wiping on drop reduces exposure but copies may remain in swap,
   crash dumps or CPU caches.

Also avoid vague marketing such as "unhackable" or "military-grade".

## Design anti-goals

Failures even if everything else works: any network code (including telemetry, crash reports
or update checks); plaintext secrets on disk at any point; secrets in logs, panic messages or
`Debug` output; a large dependency tree nobody has reviewed.
