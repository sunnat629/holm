# Task 9 report: property tests, fuzz targets, lesson 08

Status: DONE_WITH_CONCERNS
Commit: 4d75165 test: property tests and fuzz targets for header and padding (pushed to phase-0-1, no force)

## Implemented
- crates/holm-core/tests/format_props.rs: structure-aware valid_file() strategy (prop_flat_map), encode_parse_roundtrip, parse_never_panics_on_mutations, parse_never_panics_on_random, pad_unpad_roundtrip, unpad_never_panics, ignored write_seed_corpus.
- fuzz/: own workspace and lockfile, targets parse_header, parse_header_structured, unpad, seed fuzz/seeds/parse_header/valid_floor, .gitignore (target, corpus, artifacts, coverage), README.md (long run, crash reproduction, deferred items).
- scripts/ci-local.sh: fuzz gate after oracle (fmt check, cargo audit on fuzz/Cargo.lock, 30 s per target).
- .github/workflows/fuzz.yml: manual only, 600 s per target, SHA-pinned actions, contents: read, persist-credentials false.
- docs/learn/08-property-tests-and-fuzzing.md (225 lines), README row and link, lesson 07 tail link.
- Deferred and written into fuzz/README.md: open_fixed_key target to Phase 2 (on open_with_kek), cargo-cyclonedx SBOM to Phase 6.

## Gates (scripts/ci-local.sh on clean tree after commit)
PASS fmt, clippy, test, deny, audit, vet, oracle, fuzz
ALL GATES PASSED

## Fuzz executions
Manual 120 s runs (no crash):
- parse_header: 97,410,079
- parse_header_structured: 12,172,236
- unpad: 2,592,800
ci-local 30 s smoke runs (no crash, in target order):
- parse_header: 22,424,468
- parse_header_structured: 2,387,004
- unpad: 689,977

## cargo-vet exemptions (regenerated, each given a Task 9 note)
Added: autocfg, bitflags, borsh, borsh-derive, bytes, equivalent, errno, fastrand, hashbrown 0.14.5, indexmap, linux-raw-sys, once_cell, proc-macro-crate, proptest, rand, rand_core, rand_xorshift, regex-syntax, rustix, rusty-fork, toml_datetime, toml_edit, toml_parser, windows-link, windows-sys, winnow.
Removed: hex 0.4.3 (dropped by regeneration).
Result: Vetting Succeeded (14 fully audited, 1 partially audited, 66 exempted). cargo-deny: no new exemptions.

## Concerns
- `cargo vet regenerate exemptions` dropped the hex exemption and moved hashbrown to 0.14.5; vet still passes, but the Opus supply-chain audit should re-check both.
- unpad_never_panics did not catch a deliberately removed "minimal block count" check when tried (mutations rarely add whole blocks). Unit tests in padding.rs cover it; a generator that appends zero blocks would strengthen the property.
- Fuzzing is evidence, not proof: runs above found no crash.

## Fix round 1

Commit f270d04. I1 (extra/dropped block tests, AppendBlocks/DropBlock edits, mutation check: removing the minimal-block check made extra_or_missing_blocks_are_rejected and unpad_never_panics fail, then restored), 6 Minors done, fuzz nightly pinned to nightly-2026-10-12.

ALL GATES PASSED
