# Contributing

Thanks for helping. Holm is a security tool, so a few rules are strict.

## Before you send a change

Run `scripts/ci-local.sh` before every push. It runs the same gates as the CI
workflow (fmt, clippy, tests, cargo-deny, cargo-audit, cargo-vet) and tells you how
to install any missing tool. GitHub Actions is manual-only for now. The gates are:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## Rules

- No `unsafe` code outside `holm-platform` (when it exists). Each crate has
  `#![forbid(unsafe_code)]`.
- No networking crates, anywhere in the dependency graph.
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
