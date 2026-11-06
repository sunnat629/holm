# Lesson 01: Dependencies and the supply chain

## What we built

We added the gates that keep bad code out of Holm. A GitHub Actions workflow builds and
tests on Linux, macOS and Windows, then runs three checks on our dependencies:
`cargo deny`, `cargo audit` and `cargo vet`. `deny.toml` bans a long list of well-known
networking crates, and a clippy rule rejects the `std::net` socket types, which makes
accidental network code in Holm loud. It is a tripwire, not a proof (see below). The
workflow's actions are pinned to exact commits. GitHub Actions is manual-only until the
repo is public, so the merge gate is `scripts/ci-local.sh` on macOS (a project decision;
see `docs/DECISIONS.md`). The script refuses a dirty tree, so a pass describes exactly the
commit you push. It also unsets environment variables such as `RUSTFLAGS` that could weaken
a gate, and it refuses to run when a cargo config file could change the build. It also
requires exact versions of cargo-deny (0.20.2), cargo-audit (0.22.2) and cargo-vet (0.10.2).
There is still no cryptography; this lesson is about trusting code you did not write.

## Rust ideas in this lesson

### Dependency syntax in `Cargo.toml`

From our root `Cargo.toml`:

```toml
[workspace.dependencies]
holm-crypto = { path = "crates/holm-crypto", version = "0.0.0" }
getrandom = "0.4"
```

The first line is a dependency on a crate in our own repo (`path`). The second says "the
`getrandom` crate from crates.io, version 0.4". A crate then opts in with a line such as
`zeroize.workspace = true` (from `crates/holm-cli/Cargo.toml`). In Kotlin you'd write:
`implementation(libs.getrandom)` using a Gradle version catalog.

### Semver

`"0.4"` is shorthand for `^0.4`, meaning "0.4.0 or newer, but below 0.5.0". Rust uses
semantic versioning: `MAJOR.MINOR.PATCH`. For `0.x` versions the minor number acts like a
major one, so `0.4` to `0.5` may break things. For `1.x` and up, `"1.9"` allows `1.9.0` up to
(not including) `2.0.0`. In Kotlin you'd write: `"1.9.+"` in Gradle, which allows any 1.9.x patch; Cargo's `"1.9"` is
wider, since it also allows 1.10 and later 1.x releases, but never 2.0.

### `Cargo.lock` and why we commit it

A range like `"0.4"` is not one version. `Cargo.lock` records the exact version and checksum
of every crate that was actually chosen. Libraries often skip it; programs should commit it.
Holm is a program that guards secrets, so we commit it: every build, on every machine, uses
the same bytes, and a changed lock file shows up in code review. In Kotlin you'd write:
Gradle dependency locking (`gradle.lockfile`).

### Features

A crate can have optional parts called features, switched on per dependency with a
`features = [...]` list. Features add code, and code adds risk, so we turn on only what we
need. Holm's `Cargo.toml` already uses them: for example `argon2 = { ..., default-features = false, features = ["alloc", "zeroize"] }` turns the default features off and picks only what we need. In Kotlin you'd write: optional modules or Gradle
capabilities, but Cargo features compile code in or out. The local gate runs
`cargo deny --all-features`, so it sees the biggest possible dependency tree.

### Workspace lints

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

Each crate adds `[lints] workspace = true` and inherits it. This covers integration tests
and build scripts, which `#![forbid(unsafe_code)]` inside `lib.rs` would miss. One crate,
`holm-platform`, keeps its own `[lints.rust]` table with `unsafe_code = "deny"`, so one
reviewed AppKit module can opt in. The `lint-drift` gate in `scripts/ci-local.sh` checks
that every other lint in that table still matches the workspace. In Kotlin
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
  results published by nine organisations (Mozilla, Google, the Bytecode Alliance, ISRG,
  Zcash and four others; see `[imports.*]` in `supply-chain/config.toml`). Any crate nobody
  we trust has audited needs an exemption in `supply-chain/config.toml`, with a reason, and
  we review that list as the project grows.

Here is part of the ban list from `deny.toml`:

```toml
deny = [
    { crate = "reqwest" },
    { crate = "ureq" },
    { crate = "openssl" },
    { crate = "minreq" },
    # Deliberate: mio is the socket event loop under tokio. The ban also blocks crossterm
    # and notify; a TUI or file-watch task must decide that on purpose.
    { crate = "mio" },
    { crate = "smol" },
    { crate = "async-net" },
]
```

The list also bans `smol` and `async-net` (extra async runtimes with network code) and
`mio`. The `mio` ban is deliberate, and it has a cost: it also blocks `crossterm` and
`notify`, so a terminal UI or file watcher needs a conscious decision to lift it.

Each entry names a crate that must never appear anywhere in the dependency tree, even deep
inside another dependency. The matching rule in `clippy.toml` lists `std::net::TcpStream`,
`TcpListener` and `UdpSocket` under `disallowed-types`, so CI's `clippy -D warnings` fails if
Holm's own code opens a socket. Together they catch the common ways to reach the network:
an HTTP, TLS or async-runtime crate on the list, or the standard library's socket types.

`scripts/ci-local.sh` adds one more check, the `no-network` gate. It runs `cargo tree` on
`holm-gui` for the shipped macOS target and fails if `reqwest`, `ureq`, `hyper` or `url`
appears in the normal dependency tree.

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
a known vulnerability all turn `scripts/ci-local.sh` red. Nothing blocks a merge for you
yet, so a human must run it and look at the result before pushing.

## Try it

1. Prove the ban works. Run `cargo add ureq -p holm-cli`, then `cargo deny check bans`.
   It should fail and name `ureq`. Undo with `git checkout Cargo.toml Cargo.lock crates/holm-cli/Cargo.toml`
   and check `git status` is clean.
2. Look at the lock file. `grep -c '^name' Cargo.lock` counts the crates in the lock file,
   the GUI's dependencies included. Check: you get one number. Say why every crate in that
   count is something deny, audit and vet must check.
3. Install the pinned version with `cargo install --locked cargo-vet --version 0.10.2`, then
   run `cargo vet --locked` and read the one-line answer. Then open `supply-chain/config.toml`
   and find the `[imports.*]` tables, the audit sources we trust. Check: there are nine.
   Each exempted crate has a `notes` line saying why it is exempt. The longer notes, such as
   the one for `proptest`, also say what risk we accept and when to revisit it.

## Read next

- [Specifying Dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) (The Cargo Book)
- [The Rust Programming Language, ch. 14: More about Cargo and crates.io](https://doc.rust-lang.org/book/ch14-00-more-about-cargo.html)
- Previous: [Lesson 00](00-setup-and-cargo.md)
- Next: [Lesson 02](02-ownership-and-drop.md)
- [The index](README.md)
