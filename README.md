# Holm

Holm is an offline password vault for macOS, written in Rust. Your secrets live in one encrypted file on your own computer. There is no account, no cloud and no network code.

> **Holm is young software.** It has not had an outside audit yet. Keep a second copy of anything you cannot lose, and read the [threat model](docs/THREAT-MODEL.md) before you trust it.

## What it stores

| Item | Holds |
|---|---|
| Login | Username, password, web addresses, notes |
| Secure note | Free text |
| Crypto address | Chain, address, memo, notes |
| Recovery phrase | A seed phrase or recovery codes, notes |

Every item can carry up to ten custom fields (text, secret, multiline secret, date or recovery codes) and a category. You can mark favourites, search, filter, sort, and move items to the Trash and back.

## Features

- Desktop app and command-line tool (`holm`), both on the same vault file.
- Password, passphrase and username generator.
- Copy a password and Holm clears the clipboard after a set time.
- Auto-lock when idle, on minimise, on sleep, on screen lock and on logout.
- Expiry reminders on custom fields, such as a card or a certificate date.
- Import from CSV or JSON. Export to CSV or JSON, or make an encrypted backup. Plain exports are unencrypted and Holm warns you before it writes one.
- Optional: hide the window from screenshots and screen sharing (off by default, best effort).
- Secrets are decrypted one item at a time, only when you show or copy them.

## Install

**DMG (Apple silicon).** Download `Holm-<version>.dmg` from the [Releases](https://github.com/sunnat629/holm/releases) page, open it and drag Holm to Applications. Check the SHA-256 that sits next to the download. If a release has no DMG yet, build from source.

**From source.** You need [rustup](https://rustup.rs). The pinned toolchain installs itself on first use.

```sh
git clone https://github.com/sunnat629/holm.git
cd holm
cargo run -p holm-gui --release --locked          # the app
cargo run -p holm-cli --release --locked -- --help  # the command-line tool
```

`scripts/bundle-macos.sh` builds a local `Holm.app` (ad-hoc signed, not notarised). `scripts/release-macos.sh` builds the signed and notarised DMG and needs a Developer ID identity.

Windows and Linux are not supported yet. [docs/BUILD-WINDOWS.md](docs/BUILD-WINDOWS.md) has the current status.

## Quick start

1. Open Holm and choose a master password. The strength meter shows how it holds up. If you forget it, nobody can recover your vault, including us.
2. Use **New** to add a login, note, crypto address or recovery phrase.
3. Click an item to see it. Passwords stay hidden until you reveal or copy them.

The same from a terminal:

```sh
holm init                                   # make a vault
holm add login --title "Example" --generate  # add a login with a generated password
holm list --search example                   # find it
holm get 1a2b3c --copy password             # copy the password, then it is cleared
holm shell                                  # unlock once, run many commands
```

The vault is `~/Library/Application Support/Holm/holm.vault`. Use `--vault PATH` to point at another file.

## Upgrading from an older Holm

Holm 0.5.0 stores each secret in its own record (vault format 2). A vault from 0.1.x moves to the new format on its first save, and Holm keeps a backup copy next to it. **Older Holm versions cannot open a format 2 vault.** They show "This file isn't a Holm vault, or it is damaged." and leave the file alone. See the [changelog](CHANGELOG.md) for how to go back.

## Security

- Argon2id turns your master password into a key. XChaCha20-Poly1305 encrypts the vault and authenticates every header field.
- Heap blocks are zeroed on free (not stack, AppKit or GPU memory). Core dumps are off, and the lock clears window state.
- `unsafe` code is forbidden in the crypto and core crates. The platform crate keeps a few reviewed blocks for macOS windows and the wiping allocator.
- `scripts/ci-local.sh` runs the dependency audits (cargo-deny, cargo-audit, cargo-vet), a short fuzz run and the benchmark gates. Mutation testing, the SBOM, the reproducible-build check and long fuzz runs have their own scripts and notes in `docs/DECISIONS.md` (Phase C).

Read [docs/CRYPTO.md](docs/CRYPTO.md) for how the file is built and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what Holm does and does not defend against. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, ideas and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to build, test and open a pull request. Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

New to Rust? [Learn Rust with Holm](docs/learn/README.md) is a short course that uses this code.

## Roadmap

[docs/ROADMAP.md](docs/ROADMAP.md) lists what is done and what comes next: an independent audit, then Windows and Linux. Mobile comes later.

## Licence

Dual licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
