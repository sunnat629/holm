# Threat model

Holm is a local-only, offline password and secrets vault: one encrypted file, no account,
no cloud, no network. This page says who we defend against, who we do not, and which
claims we refuse to make.

**Status:** this page describes the v1 design. Defences listed below are planned, not
shipped, until v1 is released. Each one will be backed by a test, or marked as a limit.

## What we protect

The contents of the vault file: logins, crypto addresses, recovery phrases and notes.
Item contents are encrypted. The header is not secret, but every header field is authenticated.

## Attackers

| Attacker | In scope? | What Holm does |
|---|---|---|
| Steals or copies the vault file (laptop theft, backup leak) | Yes, primary | Argon2id plus XChaCha20-Poly1305. Security then rests on master password strength. |
| Edits the vault file to weaken it or crash Holm | Yes | Every header field is authenticated. KDF costs are bounded before any work. Planned: fuzz the parser. |
| Person at an unlocked, unattended computer | Partly | Auto-lock, lock on sleep and screen lock, password re-entry for recovery phrases and settings changes. |
| Clipboard snooping and clipboard history | Partly | Auto-clear, plus OS hints that ask clipboard managers not to record. |
| Screen recording or screenshots | Partly, best effort | Exclude the window from capture where the OS allows it (Windows yes, macOS partly, Linux no). |
| Malicious or fake Holm build, poisoned dependency | Yes, via process | Planned: signed releases, reproducible builds, dependency audit gates. |
| Malware running as the same user while unlocked | No | Cannot be defended against. Documented plainly. |
| Rollback (swapping in an older copy of the file) | No | Documented. Needs outside state Holm does not have. |

## Limits we state plainly

- A weak master password is the weakest link. Argon2id slows guessing; it does not stop it.
- Tampering with the encrypted data looks the same as a wrong password. That is unavoidable and correct. Format errors and KDF cost rejections are their own errors, never reported as a wrong password.
- A deleted item is gone from the new file, not from old copies or backups of it.
- Wiping memory is best effort. See the claims below.
- Holm cannot see or stop what the operating system, other programs or hardware do.

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
