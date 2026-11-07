# Mutation testing report, November 2026

Tool: cargo-mutants 27.1.0, run on this Mac under `nice -n 19` with at most 2 jobs.
Toolchain 1.99.1. Tested tree: the `src` of every crate is identical to commit
`7f751d88e35c9b27aa5a2a678d2bfab00534befe` (main before Phase B; the Phase C base). This run is
**pre-Phase-B**: it says nothing about format v2 or the code Phase B added or changed. File and
line references below are to that commit. A mutant is a small code change (an operator swapped, a body replaced
by a default). "Caught" means a test failed. "Missed" means every test still passed.
"Unviable" means the mutant did not compile.

## Result

| Crate | Scope | Mutants | Caught | Unviable | Missed |
|---|---|---|---|---|---|
| holm-crypto | whole crate | 56 | 44 | 9 | 3 (all killed, see below) |
| holm-core | format, envelope, body, wire, padding, throttle | 157 | 98 | 47 | 12 (3 killed, 9 left) |

After the new tests, a re-run of the changed functions (`check_structure`, `unpad`, 19 mutants)
gave 16 caught, 1 unviable and 2 missed. Both are equivalent mutants (below).

## holm-crypto: 3 missed, all killed

| Mutant | Why it mattered | Killer test |
|---|---|---|
| `secret.rs:108` `SecretBuf::is_empty` replaced with `true` | A buffer that reports itself empty could skip a length check. | `crates/holm-crypto/tests/secret_len.rs` |
| `secret.rs:135` `MasterPassword::raw_char_count` replaced with `0` | The count shown to the user for the typed password (before Unicode normalisation). | same: 0, 1, 5, "caf\u{e9}" = 4, "cafe\u{301}" = 5, two emoji = 2 |
| `secret.rs:135` `MasterPassword::raw_char_count` replaced with `1` | Same. | same |

## holm-core: missed mutants

Killed with new tests (test files only, no `src` change):

| Location | Mutant | Test |
|---|---|---|
| `body.rs` `check_structure` (item cap check) | `>` to `>=` and `>` to `==` on the item cap | `crates/holm-core/tests/body_limits.rs`: exactly 50,000 items decode; 50,001 are refused |
| `padding.rs:98` `unpad` | `acc \| b` to `acc ^ b` in the padding fold | `crates/holm-core/tests/padding_tail.rs`: two equal non-zero tail bytes, and bytes that cancel under XOR, are refused |

Left, with the reason (none is a security gap):

| Location | Mutant | Why it is not a gap |
|---|---|---|
| `body.rs` `check_structure`, the `\|\|` in the second cap check | `\|\|` to `&&` | Equivalent. The list readers (`BoundedVec<_, MAX_ITEMS>` and `<_, MAX_CATEGORIES>`) already refuse an over-cap list before `check_structure` runs, so the second check cannot fire from `decode`. It is kept as a second line of defence for `encode`. |
| `padding.rs:83:26` | `\|\|` to `&&` in `unpad` | Equivalent. For an empty buffer the next line, `split_first_chunk`, returns `BadPadding` anyway. |
| `wire.rs:49` and `wire.rs:103` | `expecting` returns `Ok(Default)` | Only the wording of a serde error that Holm turns into the opaque `Malformed`. No behaviour changes. |
| `wire.rs:113` (2 mutants) | `MAX + 1` becomes `MAX - 1` or `MAX * 1` | Only the number inside the same error text. |
| `wire.rs:60` (3 mutants) | `>` changed in `visit_string` | Postcard hands strings to `visit_str`/`visit_borrowed_str`, never `visit_string`, so this path is not reachable from our decoder. The same cap in `visit_str` (line 55) is caught. |

## Not run

**Follow-up after Phase B (deferred, not run).** Phase B added or changed these
`holm-core` files. None of them was mutation-tested. The files tested above (`body`, `envelope`,
`format`, `padding`, `wire`, `error`) also changed in Phase B, so their results above describe the
old versions and need a re-run on the post-Phase-B tree. Files Phase B added: `envelope_v2`,
`record`, `index`, `migrate`, `store`, `view`. Files Phase B changed: `body`, `envelope`, `error`,
`export`, `fields`, `format`, `import/mod`, `item`, `padding`, `search`, `session/categories`,
`session/items`, `session/mod`, `text`, `wire`. Highest value first: `envelope_v2`, `record`,
`index`, `migrate`, `store`, `view`, then the changed `session/*`, `search`, `body`, `envelope`.
The same command below applies. Do not treat v2 as mutation-tested until this is done.

These `holm-core` files were left out for time (the run copies the tree for every mutant and
the machine was busy): `rules`, `text`, `settings`, `category`, `error`, `search`,
`session/mod`, `session/items`, `import/csv`, `import/json`, `fields`, `generator`,
`export`, `strength/*`, `plain/*`, `import/mod`. A first partial run of the broader list
(15 of 384 mutants finished before it was stopped) had no misses. Run the rest with:

    nice -n 19 cargo mutants -p holm-core --jobs 2 --timeout 180 -f crates/holm-core/src/<file>.rs

`holm-core/src/fuzzing.rs` is test-only API and is not a target.

## Miri

`cargo +nightly-2026-10-12 miri test -p holm-crypto --lib -- --skip kdf:: --skip wycheproof --skip rfc9106`
runs 23 tests clean (no undefined behaviour reported); 17 were skipped. The nightly was added
with `rustup component add miri rust-src --toolchain nightly-2026-10-12`. `rust-toolchain.toml`
(1.99.1) is untouched. The skipped tests run Argon2id at 19 MiB or more, or the 100s of
Wycheproof vectors, which take minutes each under the interpreter; they still run natively in
`ci-local.sh`. `holm-crypto` forbids `unsafe`, so this run mainly confirms that its
dependencies behave on the paths the unit tests reach.
