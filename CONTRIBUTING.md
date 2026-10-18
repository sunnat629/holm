# Contributing

Thanks for helping. Holm is a security tool, so some rules are strict.

## Build and test

Install [rustup](https://rustup.rs). The pinned toolchain installs itself on first use.

The merge gate is the local CI script:

```sh
bash scripts/ci-local.sh
```

It runs formatting, clippy, the tests, the supply-chain checks (cargo-deny, cargo-audit,
cargo-vet), a libsodium cross-check in `oracle/` and a short fuzz run in `fuzz/`. It needs
the exact tool versions it checks, and it prints the install command for anything missing.
To check your setup without running the gates, use `bash scripts/ci-local.sh --preflight`.

The script only passes on a clean working tree, so commit or stash first.

## Pull requests

- Keep each pull request small and about one topic.
- Add or update tests with every change.
- Run `bash scripts/ci-local.sh` before you push.
- Explain in the pull request why any new dependency is needed.

## Security rules

- No new network code. Holm stays offline.
- No `unsafe` code, except the one allowed file, `crates/holm-platform/src/window.rs`.
  The test-only FFI in `oracle/` is the other exception, and it never ships.
- Secrets live in wiping types (`zeroize`).
- Never log secrets, including in errors, panic messages and `Debug` output.
- Every security claim needs a test, or must be written down as a limit.
- New dependencies need a cargo-vet entry.
- Do not write your own cryptography. Use the RustCrypto primitives already chosen.
- Never put real passwords or keys in tests, examples or issues.

## Good first issues

Look for issues labelled [good first issue](https://github.com/sunnat629/holm/labels/good%20first%20issue).

## Licence

By contributing you agree your work is licensed under MIT OR Apache-2.0, like the rest of the project.

## Security problems

Do not file them as issues. Report them privately, as [SECURITY.md](SECURITY.md) explains.

## Conduct

Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
