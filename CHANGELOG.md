# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] - 2026-11-07

The first open-source release. Holm now keeps less secret data in memory, stores each secret
in its own sealed record, and ships the tooling that lets you check a build yourself.

### Read this before you upgrade

- **Older Holm versions cannot open a v2 vault.** When Holm 0.5.0 saves a vault made by an
  older version, it moves the file to format 2. Holm 0.1.x then shows "This file isn't a Holm
  vault, or it is damaged." and leaves the file unchanged. The file is fine.
- **Migration is automatic and keeps a backup.** On the first save, Holm writes the original
  file next to the vault as `<vault>.v1-<id>.bak`, then replaces it. After a later unlock Holm
  asks whether to delete the backup. It never deletes it without your yes.
- **To go back,** quit Holm, move the new vault aside, rename the `.bak` copy to the vault's
  name, and open it with the older Holm and your old password. Edits made after the move are
  not in the backup. See [the migration check](docs/manual/phase-b-migration-checklist.md).

### Added

- Phase A, memory hygiene: a global allocator that zeroes every block before it is freed,
  a lock that wipes all window state (text-edit history, scroll offsets, focus, cached
  images), and core dumps switched off at startup.
- Phase B, format v2: each item's secrets are sealed in a separate record, so only the value
  on screen is plaintext in memory. Holm decrypts on demand, when you show or copy a value.
  A v1 vault migrates on its first save and keeps a backup copy.
- Phase C, trust tooling: a reproducible-build check (`scripts/repro-check.sh`), an SBOM
  (`scripts/sbom.sh`, CycloneDX), long fuzz runs, a mutation-testing report, and benchmark
  gates in the local CI.
- Hide from screenshots: an optional setting that asks macOS to exclude the Holm window from
  screenshots and screen sharing. It is off by default and does not stop cameras or every
  capture tool.
- `SECURITY.md` with a private disclosure process, plus contributing guidelines, a code of
  conduct and issue and pull request templates.

### Changed

- The Holm icon now stays in the Dock, and the app uses a new flat logo.
- The release profile uses fat LTO and strips symbols: `holm-gui` went from 8.64 MB to
  5.55 MB and `holm` from 2.35 MB to 1.89 MB.
- Unlock after key derivation is about 17% slower with format 2 (4.8 ms to 5.7 ms). The
  Argon2id step still dominates the wait.
- The README is rewritten for public readers.

## [0.1.1] and earlier

The history of 0.1.0 and 0.1.1 was never written down here, so this is the combined list.

### Added
- Cargo workspace with `holm-crypto`, `holm-core` and `holm-cli`.
- Open-source files, threat model and the first lesson of the Rust course.
- `holm-crypto`: XChaCha20-Poly1305 seal and open with non-reusable nonces, Argon2id key
  derivation, zeroizing secret types.
- `holm-core`: vault file format, header parser, key envelope (create, reseal, rekey, open),
  canonical padding and cost policy limits.
- Local CI (`scripts/ci-local.sh`) with cargo-deny, cargo-audit and cargo-vet supply-chain
  gates.
- Oracle (Argon2id cross-check against libsodium) and a fuzz workspace for the parser.
- `docs/CRYPTO.md`, the cryptography reference, and `docs/DECISIONS.md`.
- Rust lessons 00 to 08 under `docs/learn/`.
