# Lesson 71: Proving it ourselves

## Why this matters

"Trust me" is not a security property. Phase C gives a reviewer five things they can run: rebuild
the binary on the same machine and get the same bytes, list every dependency, throw hostile input at the parsers for
hours, check that the tests would notice a broken line, and see that the program did not get
slower. None of them proves Holm is correct. Each one makes a certain kind of mistake easier to
find.

## What we built

- `scripts/repro-check.sh`: two clean release builds, compare SHA-256.
- `scripts/sbom.sh`: a CycloneDX 1.5 JSON file per binary.
- `scripts/fuzz-long.sh`: every fuzz target for N minutes, crashes kept apart.
- cargo-mutants runs on `holm-crypto` and `holm-core`, with a report in `docs/security/`.
- `scripts/bench-gates.sh` and `scripts/bench-budgets.env`: timing budgets in one file.

## Reproducible builds

A build is reproducible when the same source, tools and flags give the same bytes. What breaks it:

- Absolute paths baked into the binary (panic messages, debug info). `--remap-path-prefix`
  rewrites them.
- Timestamps. `SOURCE_DATE_EPOCH` fixes the clock tools may read.
- Incremental build state. `CARGO_INCREMENTAL=0`.
- Your shell. `env -i` starts from nothing, then passes only what is needed.

The script exports `HEAD` with `git archive` into two different directories, so the two builds do not share a checkout path.
Our result: two local rebuilds gave identical binaries. This shows the build is repeatable on one machine; it does not prove no path leaks, and it says nothing about another machine. The control
experiment (no remap) was also identical for workspace code, because cargo passes workspace paths
relative; the remap matters for `$CARGO_HOME` and registry paths, which are user specific.
What stays different on purpose: the Developer ID signature, its timestamp, the notarisation
ticket and the DMG container.

## SBOMs

A software bill of materials lists every crate in the binary with its version and licence.
When an advisory lands, you can answer "are we affected?" by searching a file. CycloneDX is one
of the two common formats. `cargo cyclonedx` reads `Cargo.lock`, so the list is the real one.
The version of the tool is pinned, and the output is deterministic with `SOURCE_DATE_EPOCH`.

## Fuzzing

A fuzzer mutates inputs and watches coverage: an input that reaches new code is kept in the
corpus. `-malloc_limit_mb=64` makes a huge allocation count as a crash, so a parser that trusts a
length field fails the run. The 30 second smoke run in CI catches regressions; the long run goes
deeper. A crash in core or crypto is a release blocker.

## Mutation testing

Coverage says a line ran. It does not say a test would fail if the line were wrong.
cargo-mutants changes the code (`+` to `-`, `true` to `false`, a body to `Default::default()`)
and reruns the tests. A mutant that survives is a gap: either a missing test or code that does
nothing. We read the missed list, wrote tests for the ones in parsing and crypto, and noted the
rest. Miri runs the unit tests under an interpreter that catches undefined behaviour; Argon2 is
too slow there, so the heavy tests are skipped.

## Benchmark gates

A timing test is flaky if it takes one sample. We take the minimum of several runs (noise only
makes a run slower) and for process start the median of 15. Budgets live in one file, so
changing a limit is a visible diff.

## Kotlin comparison

On the JVM you would reach for Gradle's reproducible archives, `cyclonedx-gradle-plugin`,
Jazzer for fuzzing, PIT for mutation testing and JMH for benchmarks. The ideas are the same; the
Rust tools run on the native binary, with no warm-up to account for.

## Try it

1. `bash scripts/repro-check.sh --keep`, then `diff` the two `holm` binaries yourself.
2. Remove the `--remap-path-prefix` flags and add a `panic!` that prints `file!()`. Does it differ?
3. In `holm-crypto`, break a check on purpose and run `cargo mutants -p holm-crypto -f src/kdf.rs`.
   Is the mutant caught?

## Read next

- [Lesson 66: Memory hygiene and release profiles](66-memory-hygiene-and-release-profiles.md)
- [The index](README.md)
