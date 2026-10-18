# Lesson 09: Feature unification and cargo vet

## What we built

Argon2 hashes the password with BLAKE2b, and the `blake2` crate only wipes its hash state
when its `zeroize` feature is on. The `argon2` crate does not turn that feature on, so we
added `blake2` as a direct dependency of `holm-crypto` with the feature switched on, and
Cargo now builds the one shared copy of `blake2` with wiping. Compile-time tests prove the
BLAKE2b types wipe on drop. We also cut the `cargo vet` exemptions from 12 to 3: `libc` and
`syn` are now covered by trust in their publishers, and only dev-only or unused-target
crates stay exempt.

## Rust ideas in this task

### A direct dependency that only exists to turn on a feature

From the root `Cargo.toml` and `crates/holm-crypto/Cargo.toml`:

```toml
# Direct dep only to unify features: argon2 does not enable blake2/zeroize itself,
# so its BLAKE2b hash state would not be wiped. Keep this line.
blake2 = { version = "0.11", default-features = false, features = ["zeroize"] }
```

```toml
# Turns on blake2/zeroize through feature unification (see root Cargo.toml).
blake2.workspace = true
```

Line by line:

- `blake2 = { ... }` in `[workspace.dependencies]` declares the version and features once,
  for every crate in the workspace.
- `version = "0.11"` must match what `argon2` already uses (0.11.0 in `Cargo.lock`), or Cargo
  would build a second, separate `blake2` and our feature would land on the wrong copy.
- `default-features = false` keeps the crate's `alloc` default off; we ask only for what we need.
- `features = ["zeroize"]` is the point of the line. Inside `blake2` it turns on
  `digest/zeroize`, which in turn turns on `block-buffer/zeroize`.
- `blake2.workspace = true` makes `holm-crypto` depend on it with those settings.
  `holm-crypto` never calls `blake2` in normal code. The line exists only for its effect.

That effect is *feature unification*. Within one build, Cargo compiles each crate version
once, with the union of every feature anyone asked for. `argon2` asks for `blake2` with no
features, we ask for `zeroize`, so the single `blake2` that `argon2` links against has
`zeroize`. Features are additive: they can switch code on, never off, which is why a crate
must stay correct under any combination.

In Kotlin you'd write: there is no real match. The nearest is adding a direct Gradle
dependency on a newer version of a transitive library so conflict resolution picks it for
everyone. Gradle unifies *versions*; Cargo also unifies *features*.

([Feature unification in the Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification))

### Seeing features with `cargo tree -e features`

```text
$ cargo tree -e features -i blake2 --locked
blake2 v0.11.0
└── argon2 v0.6.0
    ├── argon2 feature "alloc"
    │   └── holm-crypto v0.0.0 (/…/crates/holm-crypto)
    ...
└── blake2 feature "zeroize"
    └── holm-crypto v0.0.0 (/…/crates/holm-crypto) (*)
```

Line by line:

- `-i blake2` inverts the tree: it shows who depends on `blake2`, not what `blake2` uses.
- `-e features` adds feature nodes, so each line can say which feature pulled a crate in.
- The first branch is the old path: `argon2` uses `blake2`, with no feature line under it.
- `blake2 feature "zeroize"` with `holm-crypto` under it is the new line: our crate asked for
  the feature. Before this task that line did not exist.
- `--locked` refuses to change `Cargo.lock`, so the answer describes the committed lockfile.

In Kotlin you'd write: `./gradlew :app:dependencyInsight --dependency blake2`. It explains
which version won and why, but Gradle has no feature nodes to show.

([`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html))

### Proving a trait at compile time

From the tests in `kdf.rs`:

```rust
static_assertions::assert_impl_all!(blake2::Blake2bVarCore: zeroize::ZeroizeOnDrop);
static_assertions::assert_impl_all!(
    blake2::digest::block_api::CtOutWrapper<blake2::Blake2bVarCore, blake2::digest::consts::U64>:
        zeroize::ZeroizeOnDrop
);
static_assertions::assert_impl_all!(
    blake2::digest::block_api::Buffer<blake2::Blake2bVarCore>: zeroize::ZeroizeOnDrop
);
```

Line by line:

- `assert_impl_all!(Type: Trait)` expands to code that compiles only if `Type` implements
  `Trait`. It has no runtime part; a failure is a build error, so `cargo test` cannot run.
- `ZeroizeOnDrop` is a marker trait: it has no methods, it is a promise that the type wipes
  its memory when dropped. `blake2` implements it only under `cfg(feature = "zeroize")`.
- `Blake2bVarCore` is the core state (the chaining value `h` and counter `t`) that `argon2`
  uses directly in `blake2b_long`.
- `argon2` also uses `Blake2b512`, a wrapper with two fields: a `CtOutWrapper` around the core,
  and a `Buffer` that holds the input block not yet hashed. The wrapper itself has no
  `ZeroizeOnDrop` marker, so we assert both of its fields instead. Dropping the wrapper drops
  both fields, and each wipes.
- If someone deletes `features = ["zeroize"]`, all three lines fail with
  ``the trait bound `Blake2bVarCore: ZeroizeOnDrop` is not satisfied`` and its two siblings.

In Kotlin you'd write: a test that does
`assertTrue(AutoCloseable::class.java.isAssignableFrom(Blake2b::class.java))`. That check
runs only when the test runs; the Rust one stops the build.

([`static_assertions::assert_impl_all`](https://docs.rs/static_assertions/1.1.0/static_assertions/macro.assert_impl_all.html))

### cargo vet: criteria, imports, trust and exemptions

`cargo vet` fails the build unless every crate in `Cargo.lock` is covered for the
*criteria* it needs:

- `safe-to-deploy`: fine to ship in the product, even against hostile input. Runtime and
  build-time crates of `holm-crypto` and `holm-core` need this.
- `safe-to-run`: fine to run on a developer or CI machine, for example during `cargo test`.
  Dev-only crates such as `proptest` and its tree need only this.

A crate can be covered in four ways, in the order we prefer them:

1. **Our own audit** in `supply-chain/audits.toml` (`[[audits.blake2]]` and friends).
2. **An imported audit**: `[imports.mozilla]` and others in `supply-chain/config.toml`
   fetch other organisations' audits; `imports.lock` pins what was fetched.
3. **Trust in a publisher**, for crates too big to read line by line. From `audits.toml`:

   ```toml
   [[trusted.syn]]
   criteria = "safe-to-deploy"
   user-id = 3618 # David Tolnay (dtolnay)
   start = "2019-03-01"
   end = "2027-10-17"
   ```

   - `[[trusted.syn]]`: a trust entry for the crate `syn` only, not every crate by this person.
   - `user-id = 3618`: any version published to crates.io by that account is accepted.
   - `start` and `end`: only versions published in this window count, and the entry expires,
     so the decision gets revisited.
   - For `libc` we used `trusted-publisher = "github:rust-lang/libc"`: since 0.2.190 it is
     published by crates.io *trusted publishing* from the official repository's CI, not by
     the `rust-lang-owner` account that the imported sets trust.
   - The six dev-only trust entries use `criteria = "safe-to-run"`. If one of those crates
     ever enters the shipped tree, vet fails again, because it then needs `safe-to-deploy`.

4. **An exemption** in `config.toml`: "not vetted, accepted for now". Ours must say why:

   ```toml
   [[exemptions.r-efi]]
   version = "6.0.0"
   criteria = "safe-to-deploy"
   notes = """Unused target, kept exempt (safe-to-deploy). ..."""
   ```

   An exemption names one exact `version`, so an update of that crate fails vet until
   someone looks again.

We trusted a publisher only where isrg, mozilla and ariel-os already trust that same
publisher (`cargo vet suggest`, which fetches the imported audits over the network, prints
a `NOTE:` line when they do). `borsh-derive` and
`proptest` have no such publisher, and `r-efi` is never built for Holm, so those three stay
exempt with their reasons.

In Kotlin you'd write: Gradle dependency verification (`verification-metadata.xml`) with
`<trusted-key>` entries for PGP signing keys. That is the "trust a publisher" step; Gradle
has no shared audit records to import and no `safe-to-run` versus `safe-to-deploy` split.

([The cargo vet book](https://mozilla.github.io/cargo-vet/))

## Why this matters for security

The BLAKE2b state inside Argon2 is derived from the master password, so leaving it in freed
memory gave a memory dump one more place to find password-derived bytes; feature
unification fixed that without forking `argon2`. Small gaps remain and are listed in
`docs/CRYPTO.md`: argon2's 1 KiB blocks in block init and compression, the 64-byte
`blake2b_long` outputs (one holds a copy of the KEK), and BLAKE2b's 128-byte padded final
block and message words, all on the stack. On the supply
side, an exemption means "nobody checked", while trust names who we rely on and when that
reliance ends, so every crate in the shipped tree now has a recorded reason to be there.

## Try it

1. Find the line that proves `holm-crypto` switched on `blake2`'s wiping. Check:
   `cargo tree -e features -i blake2 --locked` prints `blake2 feature "zeroize"` with
   `holm-crypto` under it.
2. In the root `Cargo.toml`, delete `, features = ["zeroize"]` from the `blake2` line. Check:
   `cargo test -p holm-crypto --offline` fails to compile with
   ``the trait bound `Blake2bVarCore: ZeroizeOnDrop` is not satisfied``. This one command
   uses `--offline` instead of `--locked`: dropping the feature changes `Cargo.lock`, which
   `--locked` would refuse, and `--offline` still keeps Cargo off the network. Undo with
   `git checkout Cargo.toml Cargo.lock`.
3. In `supply-chain/audits.toml`, delete the `[[trusted.syn]]` entry (its header and the
   lines under it), then run `cargo vet fmt` so the file is tidy. Check: `cargo vet --locked` prints `Vetting Failed!` and
   `syn:2.0.119 missing ["safe-to-deploy"]` (and the same for 3.0.9). Undo with
   `git checkout supply-chain/audits.toml`.

## Read next

- [The Cargo Book: Features, and Feature unification](https://doc.rust-lang.org/cargo/reference/features.html)
- [The cargo vet book: Audit criteria and trusting publishers](https://mozilla.github.io/cargo-vet/audit-criteria.html)
- [The Rust Programming Language, ch. 14.3: Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
