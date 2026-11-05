# Contributing

Thanks for helping. Holm is a security tool, so a few rules are strict.

## Before you send a change

Run `scripts/ci-local.sh` before every push. Until the repo is public it is the merge
gate (GitHub Actions is manual-only for now; see spec section 12 and
[docs/DECISIONS.md](docs/DECISIONS.md)). It runs 8 gates and tells you how to install
any missing tool:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo test --workspace --locked`
4. `cargo deny` (licences, bans, sources)
5. `cargo audit` (known advisories)
6. `cargo vet --locked` (supply-chain audits)
7. the oracle (`oracle/`): Argon2id cross-checked against libsodium
8. the fuzz workspace (`fuzz/`): build and a short run on the pinned nightly

The oracle and fuzz gates are skipped on Windows. The script needs a clean tree, unsets
`RUSTFLAGS`-style environment overrides, refuses a `.cargo/config` that changes how
tests run, and checks `CARGO_TARGET_*_RUNNER` cannot hide a failing test. Run
`scripts/ci-local.sh --preflight` to self-test those checks.

## Dev unlock (debug builds only)

To skip typing the master password while developing the GUI, set `HOLM_DEV_PASSWORD` and
build with the `dev-unlock` feature:

```sh
HOLM_DEV_PASSWORD=... cargo run -p holm-gui --features dev-unlock -- --vault /tmp/dev/holm.vault
```

- Use it only with a throwaway test vault, never with your real master password.
  Environment variables are visible to other processes of your user and can end up in
  your shell history.
- It unlocks an existing vault, once per start. A wrong password or a later lock does not
  try again, and with no vault the create screen shows as usual.
- Release builds refuse the feature (a `compile_error!`), and `scripts/ci-local.sh` greps
  the release binary to check the variable name is not in it.

## Rules

- No `unsafe` code outside `holm-platform` (when it exists). `unsafe_code = "forbid"` is
  set through `[workspace.lints]` and in `fuzz/Cargo.toml`. The one exception is the
  test-only FFI in `oracle/`, which never ships.
- No networking crates in the product's dependency graph (see spec section 12 for the
  oracle exception).
- Keep dependencies few. Every new one needs a reason in the pull request.
- Secrets must never appear in logs, errors, panic messages or `Debug` output.
- Every security claim needs a test, or must be written down as a limit.
- Do not write your own cryptography. Use the well-reviewed primitives already chosen (RustCrypto). Never add a custom construction.
- Never put real passwords or keys in tests, examples or issues.

## Licence

By contributing you agree your work is licensed under MIT OR Apache-2.0, like the rest of the project.

## Security problems

Do not file them as issues. See [SECURITY.md](SECURITY.md).

## Conduct

Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).
