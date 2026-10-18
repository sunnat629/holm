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
| [#13](https://github.com/sunnat629/holm/issues/13) | Dependency hygiene: BLAKE2 wiping and cargo vet exemptions | 2 | `09-feature-unification-and-vet.md` | todo |
| [#14](https://github.com/sunnat629/holm/issues/14) | Text types, items and categories | 2 | `10-enums-newtypes-and-validation.md` | todo |
| [#15](https://github.com/sunnat629/holm/issues/15) | Password, passphrase and username generator | 2 | `11-randomness-without-bias.md` | todo |
| [#16](https://github.com/sunnat629/holm/issues/16) | Master password strength check (in-house, zxcvbn as test oracle) | 2 | `12-owning-the-strength-check.md` | todo |
| [#17](https://github.com/sunnat629/holm/issues/17) | Settings and the vault body codec | 2 | `13-serde-and-versioned-formats.md` | todo |
| [#18](https://github.com/sunnat629/holm/issues/18) | Clock, throttle and idle timer | 2 | `14-time-and-saturating-maths.md` | todo |
| [#19](https://github.com/sunnat629/holm/issues/19) | Vault store trait and session lifecycle | 2 | `15-generics-and-trait-objects.md` | todo |
| [#20](https://github.com/sunnat629/holm/issues/20) | Items, trash, categories, settings and the phrase gate | 2 | `16-borrowing-in-practice.md` | todo |
| [#21](https://github.com/sunnat629/holm/issues/21) | Search, filter and sort | 4 | `17-iterators-and-lifetimes.md` | todo |
| [#22](https://github.com/sunnat629/holm/issues/22) | holm-platform durable file store and crash tests | 2 | `18-files-fsync-and-processes.md` | todo |
| [#23](https://github.com/sunnat629/holm/issues/23) | Import from CSV and JSON | 4 | `19-parsing-untrusted-text.md` | todo |
| [#24](https://github.com/sunnat629/holm/issues/24) | Plaintext CSV export | 4 | `20-building-output-safely.md` | todo |
| [#25](https://github.com/sunnat629/holm/issues/25) | Fuzzing, property tests, full round trip and docs (2a part) | 2 | `21-fuzzing-structured-inputs.md` | todo |

## Deferred

One line per deferral. Each names the phase or trigger that closes it. Reasons and accepted risks are in [DECISIONS.md](../DECISIONS.md).

- Re-enable GitHub Actions (3-OS CI, scheduled fuzzing). Trigger: before the repo goes public. Until then `scripts/ci-local.sh` on macOS is the merge gate.
- Enable GitHub private vulnerability reporting (needed by SECURITY.md). Trigger: before the repo goes public.
- Add Actions jobs for `oracle/` and `fuzz/`. Trigger: when Actions is re-enabled.
- Replace the cargo-deny-action download with a checksummed install. Trigger: when Actions is re-enabled.
- [x] Fixed-key full-open fuzz target. Done in Phase 2 Task 13 (#25): `open_fixed_key` and `decode_body`.
- SBOM with `cargo-cyclonedx`. Closes in Phase 6 (release work).
- `--all-features` release guard (`test-vectors` must not ship). Closes in Phase 6.
- Linux and Windows are untested until Actions returns. Trigger: Actions re-enabled.
- Upstream `chacha20` does not wipe its HChaCha20 subkey. Track an upstream issue or PR; revisit on each chacha20 bump.
- `mlock` for Argon2 memory and keys. Closes in the `holm-platform` phase.
- Remove the oracle-only `cargo audit` ignores (RUSTSEC-2026-0367, -0368, -0369, zip 8.6.0). Trigger: `libsodium-sys-stable` moves to zip 9.
- Optional: a separate `deny.toml` for `fuzz/` and `oracle/`. Trigger: if their dependency graphs drift from the product's.

## Phase 4 (moved from Phase 2)

Phase 2a ships the core, the durable store and the fuzzing above. These keep their task and lesson numbers and run in Phase 4, before `holm-cli`:

- Task 9 (#21): search, filter and sort. Lesson 17.
- Task 11 (#23): import from CSV and JSON. Lesson 19.
- Task 12 (#24): plaintext CSV export. Lesson 20.
- The moved parts of Task 13 (#25): the `import_csv` and `import_json` fuzz targets, `tests/import_props.rs`, the `csv_roundtrip_any_fields` property test, and the export and import half of the full round trip.
