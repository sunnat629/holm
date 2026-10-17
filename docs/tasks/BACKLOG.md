# Backlog

Source of truth: GitHub issues. This file mirrors them for offline reading.

| # | Task | Phase | Lesson | Status |
|---|---|---|---|---|
| [#1](https://github.com/sunnat629/holm/issues/1) | Workspace, open-source files, lesson 00 | 0 | `00-setup-and-cargo.md` | todo |
| [#2](https://github.com/sunnat629/holm/issues/2) | CI and supply-chain gates (deny, audit, vet) | 0 | `01-dependencies-and-supply-chain.md` | todo |
| [#3](https://github.com/sunnat629/holm/issues/3) | Secret types (wipe on drop, redacted Debug, NFC password) | 1 | `02-ownership-and-drop.md` | todo |
| [#4](https://github.com/sunnat629/holm/issues/4) | Errors and OS randomness | 1 | `03-errors-and-results.md` | todo |
| [#5](https://github.com/sunnat629/holm/issues/5) | Argon2id KDF with floor/ceiling policy and KATs | 1 | `04-constants-overflow-and-features.md` | todo |
| [#6](https://github.com/sunnat629/holm/issues/6) | XChaCha20-Poly1305 AEAD with Wycheproof KATs | 1 | `05-slices-and-borrowing.md` | todo |
| [#7](https://github.com/sunnat629/holm/issues/7) | Vault header format v1 (strict parser) | 1 | `06-parsing-bytes-safely.md` | todo |
| [#8](https://github.com/sunnat629/holm/issues/8) | Envelope: create, open, reseal, rekey | 1 | `07-modules-and-encapsulation.md` | todo |
| [#9](https://github.com/sunnat629/holm/issues/9) | Property tests and fuzzing | 1 | `08-property-tests-and-fuzzing.md` | todo |

## Deferred

One line per deferral. Each names the phase or trigger that closes it. Reasons and accepted risks are in [DECISIONS.md](../DECISIONS.md).

- Re-enable GitHub Actions (3-OS CI, scheduled fuzzing). Trigger: before the repo goes public. Until then `scripts/ci-local.sh` on macOS is the merge gate.
- Enable GitHub private vulnerability reporting (needed by SECURITY.md). Trigger: before the repo goes public.
- Add Actions jobs for `oracle/` and `fuzz/`. Trigger: when Actions is re-enabled.
- Replace the cargo-deny-action download with a checksummed install. Trigger: when Actions is re-enabled.
- Fixed-key full-open fuzz target. Closes in Phase 2, when the body decoder exists.
- SBOM with `cargo-cyclonedx`. Closes in Phase 6 (release work).
- `--all-features` release guard (`test-vectors` must not ship). Closes in Phase 6.
- Linux and Windows are untested until Actions returns. Trigger: Actions re-enabled.
- Upstream `chacha20` does not wipe its HChaCha20 subkey. Track an upstream issue or PR; revisit on each chacha20 bump.
- `mlock` for Argon2 memory and keys. Closes in the `holm-platform` phase.
- Remove the oracle-only `cargo audit` ignores (RUSTSEC-2026-0367, -0368, -0369, zip 8.6.0). Trigger: `libsodium-sys-stable` moves to zip 9.
- Replace the 12 remaining `cargo vet` exemptions (libc, syn 2 and 3 first). Closes in Phase 2 review.
