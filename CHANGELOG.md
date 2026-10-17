# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
