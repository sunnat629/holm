# Fuzzing

cargo-fuzz (libFuzzer) targets for the Holm file format. This is its own Cargo
workspace with its own `Cargo.lock`, so libFuzzer stays out of the product graph.

Needs nightly Rust and cargo-fuzz:

```sh
rustup toolchain install nightly-2026-10-12 --profile minimal
cargo install --locked cargo-fuzz --version 0.13.2
```

## Targets

| Target | Input | Checks |
|---|---|---|
| `parse_header` | raw bytes (seeded from `fuzz/seeds/parse_header/`) | `Header::parse` never panics; on `Ok` the header re-encodes to the first 164 input bytes |
| `parse_header_structured` | arbitrary header fields, 16 to 64 body bytes, up to 4 edits | same checks, but the input starts valid so it reaches the checks behind the magic |
| `unpad` | raw bytes, or `pad(plaintext)` output with up to 4 edits | `unpad` never panics; an accepted buffer is the canonical padding of what it returns |
| `open_fixed_key` | a raw file, or a body sealed with `seal_with_kek` under the fixed KEK `[7; 32]` with up to 4 `(offset, xor)` edits (seeded) | the full open (envelope, padding, body decode) never panics; a changed file never opens; an unchanged one is never refused by the envelope, and a body it decodes re-encodes with the same item count |
| `decode_body` | raw bytes (seeded from `fuzz/seeds/decode_body/`) | `VaultData::decode` never panics and never makes one allocation over 64 MiB (`-malloc_limit_mb=64`); an accepted body re-encodes, and that encoding is stable |
| `import_csv` | raw bytes as a CSV import file (seeded from the import fixtures) | `import::parse` never panics or allocates over 64 MiB; an accepted file never yields more than `MAX_IMPORT_ROWS` rows |
| `import_json` | raw bytes as a JSON import file (seeded from the import fixtures) | the same checks for the JSON importer |

`open_fixed_key` skips Argon2 through `holm_core::fuzzing`, which exists only with
holm-core's `fuzzing` feature. Only this workspace turns it on; it must never be
enabled in a shipping build. The feature also needs `--cfg fuzzing`, which cargo-fuzz
sets by default: any other build with the feature on stops with a `compile_error!`
(do not pass `--no-cfg-fuzzing`).

The seeds for the two body targets are written by an ignored test. Re-run it after
a change to the body or the envelope (the sealed seeds use fresh nonces, so the
files change every run):

```sh
cargo test -p holm-core --lib write_fuzz_seeds -- --ignored
```

## Smoke run (the gate)

`scripts/ci-local.sh` runs each target for 30 s with `-malloc_limit_mb=64`. By
hand, from the repo root:

```sh
cargo +nightly-2026-10-12 fuzz run parse_header fuzz/corpus/parse_header fuzz/seeds/parse_header -- -max_total_time=30
cargo +nightly-2026-10-12 fuzz run parse_header_structured fuzz/corpus/parse_header_structured -- -max_total_time=30
cargo +nightly-2026-10-12 fuzz run unpad fuzz/corpus/unpad -- -max_total_time=30
cargo +nightly-2026-10-12 fuzz run open_fixed_key fuzz/corpus/open_fixed_key fuzz/seeds/open_fixed_key -- -max_total_time=30 -malloc_limit_mb=64
cargo +nightly-2026-10-12 fuzz run decode_body fuzz/corpus/decode_body fuzz/seeds/decode_body -- -max_total_time=30 -malloc_limit_mb=64
cargo +nightly-2026-10-12 fuzz run import_csv fuzz/corpus/import_csv fuzz/seeds/import_csv -- -max_total_time=30 -malloc_limit_mb=64
cargo +nightly-2026-10-12 fuzz run import_json fuzz/corpus/import_json fuzz/seeds/import_json -- -max_total_time=30 -malloc_limit_mb=64
```

## Long run

All seven targets for 600 s each, weekly, before the Phase 2a security review and before the Phase 4 security review
(all seven targets, including `import_csv` and `import_json`).
Same commands with `-max_total_time=600`. The manual workflow
`.github/workflows/fuzz.yml` does the same on GitHub. Fuzzing finds bugs; a clean
run does not prove there are none.

## Reproduce a crash

A crash writes its input to `fuzz/artifacts/<target>/crash-<hash>`.

1. Reproduce: `cargo +nightly-2026-10-12 fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
2. Minimise: `cargo +nightly-2026-10-12 fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
3. Copy the minimised file to `fuzz/seeds/<target>/regression_<short-name>` and commit it.
4. For `parse_header` the bytes can go straight into a unit test with `Header::parse`.
   For the structured targets, print the decoded input with `cargo +nightly-2026-10-12 fuzz fmt <target> <file>`
   and write a unit test that builds the same bytes.
5. Fix the bug. The unit test must fail before the fix and pass after it.

## Deferred

- The `cargo-cyclonedx` SBOM moves to Phase 6.
