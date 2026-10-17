# Fuzzing

cargo-fuzz (libFuzzer) targets for the Holm file format. This is its own Cargo
workspace with its own `Cargo.lock`, so libFuzzer stays out of the product graph.

Needs nightly Rust and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz --version 0.13.2
```

## Targets

| Target | Input | Checks |
|---|---|---|
| `parse_header` | raw bytes (seeded from `fuzz/seeds/parse_header/`) | `Header::parse` never panics; on `Ok` the header re-encodes to the first 164 input bytes |
| `parse_header_structured` | arbitrary header fields, 16 to 64 body bytes, up to 4 edits | same checks, but the input starts valid so it reaches the checks behind the magic |
| `unpad` | raw bytes, or `pad(plaintext)` output with up to 4 edits | `unpad` never panics; an accepted buffer is the canonical padding of what it returns |

## Smoke run (the gate)

`scripts/ci-local.sh` runs each target for 30 s. By hand, from the repo root:

```sh
cargo +nightly fuzz run parse_header fuzz/corpus/parse_header fuzz/seeds/parse_header -- -max_total_time=30
cargo +nightly fuzz run parse_header_structured fuzz/corpus/parse_header_structured -- -max_total_time=30
cargo +nightly fuzz run unpad fuzz/corpus/unpad -- -max_total_time=30
```

## Long run

Each target for 600 s, weekly and before the Phase 1 security review. Same
commands with `-max_total_time=600`. The manual workflow
`.github/workflows/fuzz.yml` does the same on GitHub. Fuzzing finds bugs; a clean
run does not prove there are none.

## Reproduce a crash

A crash writes its input to `fuzz/artifacts/<target>/crash-<hash>`.

1. Reproduce: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
2. Minimise: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
3. Copy the minimised file to `fuzz/seeds/<target>/regression_<short-name>` and commit it.
4. For `parse_header` the bytes can go straight into a unit test with `Header::parse`.
   For the structured targets, print the decoded input with `cargo +nightly fuzz fmt <target> <file>`
   and write a unit test that builds the same bytes.
5. Fix the bug. The unit test must fail before the fix and pass after it.

## Deferred

- The `open_fixed_key` target (full open with a fixed key, spec section 12) moves to
  Phase 2, built on the Task 8 `open_with_kek` helper.
- The `cargo-cyclonedx` SBOM moves to Phase 6.
