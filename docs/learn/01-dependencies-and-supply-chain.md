# Lesson 01: Dependencies and the supply chain

## What we built

We added the gates that keep bad code out of Holm. A GitHub Actions workflow builds and
tests on Linux, macOS and Windows, then runs three checks on our dependencies:
`cargo deny`, `cargo audit` and `cargo vet`. `deny.toml` bans a long list of well-known
networking crates, and a clippy rule rejects the `std::net` socket types, which makes
accidental network code in Holm loud. It is a tripwire, not a proof (see below). The
workflow's actions are pinned to exact commits. CI reports results on the pull request;
it does not block merges yet, because a private repo on the free plan has no branch
protection. There is still no cryptography; this lesson is about trusting code you did not write.

## Rust ideas in this task

### Dependency syntax in `Cargo.toml`

From our root `Cargo.toml`:

```toml
[workspace.dependencies]
holm-crypto = { path = "crates/holm-crypto", version = "0.0.0" }
argon2 = "0.6"
```

The first line is a dependency on a crate in our own repo (`path`). The second says "the
`argon2` crate from crates.io, version 0.6". A crate then opts in with
`argon2.workspace = true`. In Kotlin you'd write: `implementation(libs.argon2)` using a
Gradle version catalog.

### Semver

`"0.6"` is shorthand for `^0.6`, meaning "0.6.0 or newer, but below 0.7.0". Rust uses
semantic versioning: `MAJOR.MINOR.PATCH`. For `0.x` versions the minor number acts like a
major one, so `0.6` to `0.7` may break things. For `1.x` and up, `"1.9"` allows `1.9.0` up to
(not including) `2.0.0`. In Kotlin you'd write: `"1.9.+"` in Gradle, which allows any 1.9.x patch; Cargo's `"1.9"` is
wider, since it also allows 1.10 and later 1.x releases, but never 2.0.

### `Cargo.lock` and why we commit it

A range like `"0.6"` is not one version. `Cargo.lock` records the exact version and checksum
of every crate that was actually chosen. Libraries often skip it; programs should commit it.
Holm is a program that guards secrets, so we commit it: every build, on every machine, uses
the same bytes, and a changed lock file shows up in code review. In Kotlin you'd write:
Gradle dependency locking (`gradle.lockfile`).

### Features

A crate can have optional parts called features, switched on per dependency with a
`features = [...]` list. Features add code, and code adds risk, so we turn on only what we
need. Holm's `Cargo.toml` uses none yet. In Kotlin you'd write: optional modules or Gradle
capabilities, but Cargo features compile code in or out. `cargo deny` runs with
`all-features = true` so it sees the biggest possible dependency tree.

### Workspace lints

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

Each crate adds `[lints] workspace = true` and inherits it. This covers integration tests
and build scripts, which `#![forbid(unsafe_code)]` inside `lib.rs` would miss. In Kotlin
you'd write: a shared detekt config applied by a convention plugin.

### crates.io trust

Anyone can publish to crates.io, and a crate you depend on pulls in its own dependencies.
That chain is the **supply chain**. Attacks include a stolen maintainer account, a
look-alike name, or a harmless crate that turns hostile in a later release. Maven Central
has the same problem. Three tools check different parts of it:

- **`cargo deny`** reads `deny.toml` and enforces our policy: banned crates (the network
  ban), allowed licences, and only crates.io as a source. It also runs the advisory check.
- **`cargo audit`** compares `Cargo.lock` with the RustSec advisory database of known
  vulnerable or unmaintained crates. It tells you "this version is known bad".
- **`cargo vet`** asks "has a trusted human actually read this code?". We import audit
  results published by Mozilla, Google and the Bytecode Alliance. Any crate nobody we trust
  has audited needs an exemption in `supply-chain/config.toml`, with a reason, and we
  review that list again in Phase 6.

Here is part of the ban list from `deny.toml`:

```toml
deny = [
    { crate = "reqwest" },
    { crate = "ureq" },
    { crate = "openssl" },
    { crate = "minreq" },
]
```

Each entry names a crate that must never appear anywhere in the dependency tree, even deep
inside another dependency. The matching rule in `clippy.toml` lists `std::net::TcpStream`,
`TcpListener` and `UdpSocket` under `disallowed-types`, so CI's `clippy -D warnings` fails if
Holm's own code opens a socket. Together they catch the common ways to reach the network:
an HTTP, TLS or async-runtime crate on the list, or the standard library's socket types.

They cannot catch everything. A network crate that is not on the list passes. A call into C
through FFI can open a socket with no Rust crate involved. The `std::net` rule only sees
the types and methods we named. Treat the lists as tripwires; the real defence is reading
every new dependency in review, which is what `cargo vet` records.

### Why actions are pinned by SHA

A workflow line like `uses: actions/checkout@v7` follows a tag, and a tag can be moved. If
an action's repository is hijacked, the tag can point to malicious code that runs in our CI
with access to our repo. A full 40-character commit SHA cannot be moved:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

The comment keeps it readable. In Kotlin you'd write: depending on a Gradle plugin by exact
version plus checksum verification, instead of `latest`.

## Why this matters for security

Most real attacks on software now come through dependencies and build systems, not through
the program's own code. A vault that depends on a hijacked crate is a vault that leaks.
These gates make the risky moves loud: a new crate, a banned crate, an unreviewed licence or
a known vulnerability all turn the build red on the pull request. Today CI reports and does
not block, so a human must still look at the result before merging.

## Try it

1. Prove the ban works. Run `cargo add ureq -p holm-cli`, then `cargo deny check bans`.
   It should fail and name `ureq`. Undo with `git checkout Cargo.toml Cargo.lock crates/holm-cli/Cargo.toml`
   and check `git status` is clean.
2. Look at the lock file: `grep -c '^name' Cargo.lock` counts the crates in the build.
   Today it is only our three, since no third-party crate is used yet. Say why that is a good place to start.
3. Install it with `cargo install --locked cargo-vet`, then run `cargo vet --locked` and read the one-line answer. Then open
   `supply-chain/config.toml` and find the three audit sources we import.

## Read next

- [Specifying Dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) (The Cargo Book)
- [The Rust Programming Language, ch. 14: More about Cargo and crates.io](https://doc.rust-lang.org/book/ch14-00-more-about-cargo.html)
