# Lesson 01: Dependencies and the supply chain

## What we built

We added the gates that keep bad code out of Holm. A GitHub Actions workflow builds and
tests on Linux, macOS and Windows, then runs three checks on our dependencies:
`cargo deny`, `cargo audit` and `cargo vet`. `deny.toml` bans a long list of well-known
networking crates, and a clippy rule rejects the `std::net` socket types, which makes
accidental network code in Holm loud. It is a tripwire, not a proof (see below). The
workflow's actions are pinned to exact commits, and the cargo tools are installed with
`--locked` at fixed versions. GitHub Actions minutes are limited, so the workflow is
manual-only for now and you run `scripts/ci-local.sh` before every push; it runs the same
gates. There is still no cryptography; this lesson is about trusting code you did not write.

## Why this matters for security

Most real attacks on software now come through dependencies and build systems, not through
the program's own code. A vault that depends on a hijacked crate is a vault that leaks.
These gates make the risky moves loud: a new crate, a banned crate, an unreviewed licence or
a known vulnerability all turn `scripts/ci-local.sh` red. Nothing blocks a merge yet, so a
human must run it and look at the result before pushing.

## Try it

1. Prove the ban works. Run `cargo add ureq -p holm-cli`, then `cargo deny check bans`.
   It should fail and name `ureq`. Undo with `git checkout Cargo.toml Cargo.lock crates/holm-cli/Cargo.toml`
   and check `git status` is clean.
2. Look at the lock file: `grep -c '^name' Cargo.lock` counts the crates in the build.
   Today it is only our three, since no third-party crate is used yet. Say why that is a good place to start.
3. Install it with `cargo install --locked cargo-vet`, then run `cargo vet --locked` and read the one-line answer. Then open
   `supply-chain/config.toml` and find the audit sources we import (three at first, nine since the
   Phase 1 supply-chain audit). Each crate that is still exempted has a `notes` line saying why,
   what risk we accept and when to revisit it. Our own audits live in `supply-chain/audits.toml`.

## Read next

- [Specifying Dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) (The Cargo Book)
- [The Rust Programming Language, ch. 14: More about Cargo and crates.io](https://doc.rust-lang.org/book/ch14-00-more-about-cargo.html)
