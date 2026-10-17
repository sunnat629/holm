# Holm

Holm is a local-only, offline password and secrets vault. It keeps everything in one
encrypted file, with no account, no cloud and no network code. It is written in pure Rust,
and security matters more than looks.

> **Status: pre-alpha. Do not trust Holm with real secrets yet.**
> The file format and the code can still change, and nothing has had an outside audit.

## Build

You need [rustup](https://rustup.rs). The pinned toolchain installs itself on first use.

```sh
cargo build --workspace
cargo test --workspace
```

## Read more

- [Threat model](docs/THREAT-MODEL.md): what Holm defends against, and what it does not.
- [Learn Rust with Holm](docs/learn/README.md): a course for beginners, one lesson per task.
- [Security policy](SECURITY.md): how to report a vulnerability.
- [Contributing](CONTRIBUTING.md) and [changelog](CHANGELOG.md).

## Licence

Dual licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
