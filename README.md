# Holm

Your passwords in one encrypted file on your own computer. No account, no cloud, no network.

> **Status: pre-alpha. Do not trust Holm with real secrets yet.**
> The file format and the code can still change. Nothing has had an outside audit.

<!-- screenshot: added before launch -->

## Why Holm

- **Offline only.** Holm has no network code and never sends your data anywhere itself. Until clipboard auto-clear lands, a password you copy in the macOS app stays on the clipboard, where macOS Universal Clipboard can reach your other Apple devices.
- **One file you own.** Your vault is a single encrypted file. Copy it, back it up or delete it.
- **Pure Rust.** `unsafe` is forbidden everywhere except one small macOS window file.
- **Checked.** Fuzzed, with a local CI gate and dependency audits (cargo-deny, cargo-audit, cargo-vet).
- **Open.** Dual licensed under MIT or Apache-2.0.

## Features today

- Create and unlock a vault, with a password strength meter and an unlock throttle.
- Logins, crypto addresses, recovery phrases and secure notes. The macOS app lists logins
  today. Other types arrive in the next update.
- Categories, trash, search, filter and sort.
- Password generator.
- Copy password. Only the CLI clears the clipboard today; the macOS app gets clipboard auto-clear in the next update.
- Idle auto-lock.
- Import from CSV or JSON. Exports are plaintext, and Holm warns you about it.
- Command-line tool (`holm`) with an interactive shell.

## Platform support

| Platform | Desktop app | CLI | How to get it |
|---|---|---|---|
| macOS | ✅ works | ✅ works | Build from source today; a downloadable app is coming next |
| Windows | ⏳ planned | ⏳ planned | Not supported yet |
| Linux | ⏳ planned | ⏳ planned | Not supported yet |
| Android / iOS | 🗓 later | — | Separate design after desktop v1 |

## Build from source (macOS)

1. Install [rustup](https://rustup.rs). The pinned toolchain installs itself on first use.
2. Run the app or the CLI:

```sh
cargo run -p holm-gui --release --locked
cargo run -p holm-cli --release --locked -- --help
```

To build a local `Holm.app` (arm64, ad-hoc signed, not notarised), run
`scripts/bundle-macos.sh`. It writes `target/bundle/Holm.app`; add `--zip` for a zip and
its SHA-256.

The release build is a signed and notarised DMG (arm64, version 0.1.0 beta):
`scripts/release-macos.sh` writes `target/release-macos/Holm-<version>.dmg` and its SHA-256.
It needs a Developer ID Application identity and the `holm-notary` notary profile, and stops
if either is missing. See [CONTRIBUTING.md](CONTRIBUTING.md#releases).

On Windows and Linux, `holm-gui` builds but only reports that it is macOS-only for now.
The CLI is not supported there yet.
Windows: see [docs/BUILD-WINDOWS.md](docs/BUILD-WINDOWS.md) (untested, test vaults only).

## Roadmap

- [x] Encryption core and file format
- [x] Vault core
- [x] macOS app
- [x] Search, import/export, CLI
- [ ] Hardening and polish: clipboard auto-clear, lock on sleep, all item types in the app, a downloadable macOS app
- [ ] Release: signed installers (macOS DMG script ready for 0.1.0 beta), an outside security audit, then Windows and Linux. Mobile comes later.

See [CHANGELOG.md](CHANGELOG.md) for what has changed so far.

## Security

Report problems privately, as [SECURITY.md](SECURITY.md) explains. Read
[THREAT-MODEL.md](docs/THREAT-MODEL.md) for what Holm does and does not protect against,
and [CRYPTO.md](docs/CRYPTO.md) for how the vault is encrypted.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. New to the project?
Start with issues labelled [good first issue](https://github.com/sunnat629/holm/labels/good%20first%20issue).

## Learn Rust with Holm

New to Rust? [Learn Rust with Holm](docs/learn/README.md) is a short course that uses this code.

## Licence

Dual licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
