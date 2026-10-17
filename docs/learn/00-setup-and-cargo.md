# Lesson 00: Setup and Cargo

## What we built

We made the empty skeleton of Holm: a Cargo workspace with three crates (`holm-crypto`,
`holm-core`, `holm-cli`), a toolchain pinned to one Rust version, and a first program that
prints `holm 0.0.0`. We also added a test that runs that program and checks its output.
There is no cryptography yet. This lesson is about how a Rust project is laid out and how
you build, run and test it.

## Rust ideas in this task

### Installing Rust with rustup

`rustup` is the Rust installer and version manager (a bit like SDKMAN for the JVM). Install
it from <https://rustup.rs>, then open a new terminal:

```sh
rustup --version
cargo --version
```

Our `rust-toolchain.toml` pins the exact compiler, so everyone builds with the same one:

```toml
[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
```

`rustfmt` formats code; `clippy` is a linter that catches common mistakes. In Kotlin you'd
write: a Gradle wrapper that pins the Gradle version, plus ktlint and detekt.

### Cargo: build, run, test

Cargo is the build tool and package manager in one. It is Gradle, Maven Central and the test
runner together.

```sh
cargo build --workspace   # compile everything
cargo run -p holm-cli     # run the program in crate holm-cli
cargo test --workspace    # run all tests
```

### Crates and workspaces

A **crate** is one compilation unit: a library or a program. It is like a Gradle module. A
**workspace** groups several crates that share one lock file and one build folder (`target/`).
Our root `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/holm-crypto", "crates/holm-core", "crates/holm-cli"]
```

Line by line: `[workspace]` starts the workspace section. `resolver` picks how Cargo
chooses dependency versions (3 is the current one). `members` lists the crate folders. In
Kotlin you'd write: `include(":holm-crypto", ":holm-core", ":holm-cli")` in `settings.gradle.kts`.

### Reading a crate's `Cargo.toml`

```toml
[package]
name = "holm-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
```

`version.workspace = true` means "take this value from the workspace root". The root holds
`[workspace.package]` with `edition = "2024"` (the language edition) and
`license = "MIT OR Apache-2.0"`. One place to change, many crates follow. In Kotlin you'd write:
shared values in `gradle.properties` or a convention plugin.

The root also has `[workspace.dependencies]`, a shared catalogue of library versions. In
Kotlin you'd write: a Gradle version catalog (`libs.versions.toml`).

### `fn main` and `println!`

This is the whole program, `crates/holm-cli/src/main.rs`:

```rust
fn main() {
    println!("holm {}", env!("CARGO_PKG_VERSION"));
}
```

`fn` declares a function. `main` is where every Rust program starts. The `!` in `println!`
means it is a **macro**, not a plain function. It prints a line, and `{}` is where the
next argument goes. `env!("CARGO_PKG_VERSION")` reads a value at compile time: Cargo sets
it from the `version` field in `Cargo.toml`, so the program prints the version it was built
with and the text can never drift from the manifest. In Kotlin you'd write:
`fun main() { println("holm ${BuildConfig.VERSION}") }`. They look alike on purpose.

### `let` versus `let mut`

Variables in Rust are **immutable by default**:

```rust
let name = "holm";        // cannot be changed later
let mut count = 0;        // `mut` allows changing it
count += 1;
```

In Kotlin you'd write: `val name = "holm"` and `var count = 0`. Rust's `let` is `val`;
`let mut` is `var`. If you try to change a plain `let`, the compiler refuses. That default
helps security: less changing state means fewer surprises.

### `#![forbid(unsafe_code)]`

The first lines of our crates:

```rust
#![forbid(unsafe_code)]
#![deny(missing_docs)]
```

The `#![...]` form is an **attribute** that applies to the whole crate. `unsafe` is a Rust
keyword that switches off some of the compiler's memory safety checks so you can do
low-level things. `forbid(unsafe_code)` makes any `unsafe` block a compile error, and unlike
`deny` it cannot be overridden further down. `deny(missing_docs)` makes a public item
without a doc comment (`///` or `//!`) an error. In Kotlin you'd write: nothing close. The
JVM has no `unsafe` keyword in the language; the nearest idea is a lint rule that bans
`sun.misc.Unsafe`.

### A test that runs the program

`crates/holm-cli/tests/version.rs` has:

```rust
#[test]
fn prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .output()
        .expect("failed to run holm binary");
    assert!(output.status.success());
}
```

`#[test]` marks a test function. `Command::new(...)` starts a process. `env!` reads a value
at compile time: Cargo sets `CARGO_BIN_EXE_holm` to the path of the built binary.
`.expect("...")` means "stop with this message if it failed". `assert!` fails the test if
its condition is false. In Kotlin you'd write: a JUnit `@Test` that uses `ProcessBuilder`.

## Why this matters for security

Pinning the compiler version, and committing `Cargo.lock` (which records the exact version of
every dependency), makes builds repeatable. That is the first step toward builds others can
verify. `forbid(unsafe_code)` means that, in our own crates, the compiler proves a whole class
of memory bugs (buffer overflows, use after free) cannot happen. It does not cover our
dependencies, which do use `unsafe` internally; that is why we keep the dependency list short
and checked by the local gates in `scripts/ci-local.sh`.

## Try it

1. Run the program and read its output.
   Check: `cargo run -p holm-cli` prints `holm 0.0.0`.
2. In `crates/holm-cli/src/main.rs`, add `let message = "hi";` as the first line of `main`,
   then try `message = "bye";` on the next line. Read the compiler error, then fix it with
   `let mut`. Check: `cargo build -p holm-cli` fails before the fix and passes after. Undo
   your change when done (`git checkout crates/holm-cli/src/main.rs`).
3. Add `unsafe { }` (an empty block) inside `main`. Check: `cargo build -p holm-cli` fails
   with a message about `forbid(unsafe_code)`. Undo it with `git checkout`.

## Read next

- [The Rust Programming Language, ch. 1: Getting Started](https://doc.rust-lang.org/book/ch01-00-getting-started.html)
- [Ch. 3.1: Variables and Mutability](https://doc.rust-lang.org/book/ch03-01-variables-and-mutability.html)
- [Ch. 14.3: Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
