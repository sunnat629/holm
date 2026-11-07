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

A pass ends with the line `ALL GATES PASSED`. Paste it into your pull request.

## No GitHub Actions minutes needed

The workflows in `.github/workflows/` only run by hand. Every gate runs on your own machine
through `scripts/ci-local.sh`, so you do not need Actions minutes to contribute.

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

## Releases

Maintainers only. `scripts/release-macos.sh` builds, signs, notarises and staples
`target/release-macos/Holm-<version>.dmg`. The version comes from the one `version` line in
the workspace `Cargo.toml`.

One-time setup on the release Mac:

1. The Account Holder creates the signing certificate in Xcode: Settings > Accounts >
   Manage Certificates > + > Developer ID Application. The App Store Connect API cannot.
2. Store the notary credentials in the keychain from an App Store Connect API key. Read the
   values from files or the environment; never paste them into a shared terminal or a log:
   `xcrun notarytool store-credentials holm-notary --key <AuthKey .p8> --key-id <id> --issuer <issuer>`.

Each release:

1. Bump `version` in `Cargo.toml` (and the internal `holm-*` versions next to it), update the
   lockfiles in `Cargo.lock`, `oracle/` and `fuzz/`, and run `bash scripts/ci-local.sh`.
2. Run `scripts/release-macos.sh --preflight`, then `scripts/release-macos.sh`.
3. The script signs with the hardened runtime and a secure timestamp, with no entitlements,
   waits for notarisation, staples the ticket and checks the DMG and the app with `codesign`
   and `spctl`. It stops at the first failure and never signs ad-hoc instead.
4. Publish the DMG together with its `.sha256` file.

## Pull requests

- Keep each pull request small and about one topic.
- Add or update tests with every change.
- Run `bash scripts/ci-local.sh` before you push.
- Explain in the pull request why any new dependency is needed.
- Open an issue first for anything bigger than a small fix, so we can agree on the approach.
- Add a line to `CHANGELOG.md` under `[Unreleased]` when a user would notice the change.
- Changes to the file format or the cryptography also need an entry in `docs/DECISIONS.md`
  and `docs/CRYPTO.md`.
- Never put secrets, real vault files, email addresses or personal paths in code, tests,
  logs or screenshots.

Maintainers review every pull request. Changes that touch crypto, the file format, passwords
or `unsafe` get a closer security review. Nits do not block a merge.

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
