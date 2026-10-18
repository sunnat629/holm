# Lesson 22: A GUI crate and its supply chain

## Why this matters

Before this task Holm's shipped code pulled in a few dozen crates, and every one of them was audited or trusted. A GUI toolkit brings more than two hundred new crates into the lockfile, and each one runs with the same rights as the code that holds your passwords. If we let them in carelessly, the effort spent on the vault format counts for little. This task adds a window, and keeps that new code fenced, counted and dated.

## What we built

A new `holm-gui` crate that is both a library (fonts, later the screens) and a binary that opens a window titled "Holm" on macOS. The GUI stack (`eframe`, `arboard`) is a macOS-only dependency, so Linux and Windows build an empty library and a binary that prints one line. Two OFL fonts are built into the binary with `include_bytes!`, and CI checks their SHA-256. `holm-platform` gained `paths` (the default vault path and an owner-only vault folder) and `lock` (one Holm per vault folder, using std's `File::try_lock`). `cargo deny` now checks only the five desktop targets, and `cargo vet` covers every new crate through imported audits, dated trust, or dated exemptions.

## Rust ideas in this task

### A library and a binary in one crate

```toml
[[bin]]
name = "holm-gui"
path = "src/main.rs"
```

A package can hold one library (`src/lib.rs`) and any number of binaries. The binary is a separate crate that depends on the library, so `main.rs` writes `holm_gui::fonts::install_fonts`, exactly as an outside user would. Logic that lives in `lib.rs` can be tested without starting a window; `main.rs` stays a thin shell that reads arguments and calls `eframe::run_native`.

In Kotlin you'd write a Gradle module with an `application` plugin and a `mainClass`, and keep the logic in a separate library module so tests do not need `main`.

### Dependencies for one target only

```toml
[target.'cfg(target_os = "macos")'.dependencies]
eframe.workspace = true
arboard.workspace = true
```

Cargo resolves this table per target. On Linux, `eframe` is not compiled at all, so the code that uses it must also be behind `#[cfg(target_os = "macos")]`, or the build fails with "unresolved import". `lib.rs` writes `#[cfg(target_os = "macos")] pub mod fonts;`, and `main.rs` has two `main` functions, one per `cfg`.

The lockfile is still shared by every target. That is why `Cargo.lock` gained Wayland, X11 and Windows crates even though a macOS build never touches them: Cargo writes one lockfile that works for any target someone might build.

In Kotlin you'd write separate source sets in Kotlin Multiplatform (`macosMain`, `jvmMain`), each with its own `dependencies { }` block.

### Why the feature list is short

```toml
eframe = { version = "=0.37.0", default-features = false, features = ["glow", "accesskit"] }
```

`default-features = false` turns off everything, then we turn on two things: `glow` (draw with OpenGL) and `accesskit` (screen reader support). Left off: `default_fonts` (we bring our own), `persistence` (it would write window state to disk next to a password vault), `clipboard` (Holm will copy through `arboard` with history exclusion, not egui's own path), `wgpu` (a second, much bigger renderer), `wayland`/`x11` (Linux, later), `links` (opening URLs from the UI) and `system_fonts`. Every feature we leave off is code that is never compiled into the binary. Check it with:

```sh
cargo tree -p holm-gui -e features --target aarch64-apple-darwin --locked
```

The new macOS runtime graph is 87 crates. Roughly: `winit` and the `objc2-*` family talk to Cocoa; `glutin`, `glow` and `libloading` load OpenGL; `egui`, `epaint`, `emath` and `ecolor` are the UI itself; `skrifa` and `read-fonts` read the font files; `accesskit*` speaks to VoiceOver; `arboard` is the clipboard. The rest are their small helpers (`bitflags`, `smallvec`, `ahash` and similar).

### Bytes in the binary: `include_bytes!`

```rust
static TEXT_FONT: &[u8] = include_bytes!("../assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf");
```

The macro reads the file at compile time and puts its bytes into the binary as a `&'static [u8]`. The path is relative to the source file, not to the crate root. At run time nothing is read from disk, so no other app can swap the font, and the app does not depend on what fonts the Mac has. `FontData::from_static` then hands egui those bytes without a copy.

Because the bytes are code now, they get the same check as the wordlist: `scripts/ci-local.sh` runs `shasum -a 256 -c` on both `.ttf` files, and `NOTICE` names the upstream commit, the licence and the hash.

In Kotlin you'd write `javaClass.getResourceAsStream("/fonts/x.ttf")`, which reads the jar at run time. Rust has no jar; the bytes go straight into the executable.

### One instance: `File::try_lock`

```rust
match file.try_lock() {
    Ok(()) => Ok(InstanceLock { file }),
    Err(TryLockError::WouldBlock) => Err(LockError::Held),
    Err(TryLockError::Error(e)) => Err(LockError::Io(e.kind())),
}
```

Since Rust 1.89, `std::fs::File` has advisory locks (`flock` on macOS, `LockFileEx` on Windows). `try_lock` never waits: it returns `WouldBlock` if someone else holds the lock. The lock lives as long as the `File`, so `InstanceLock` just keeps the file in a field. When it drops, the file closes and the lock goes. If the process crashes, the OS closes the file and drops the lock too, so there is no stale lock to clean up.

The lock file is opened like the vault: `lstat` first so a symlink is never followed, `O_NONBLOCK` so a FIFO cannot hang the open, then `fstat` and `lstat` again to check that the path still names the very file we opened. `InstanceLock`'s `Debug` is written by hand, because `File`'s `Debug` prints the path.

In Kotlin you'd write `FileChannel.open(path, WRITE, CREATE).tryLock()`, which returns `null` when another process holds it.

### `cargo deny`: which targets count

```toml
[graph]
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
           "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
```

Without `targets`, `cargo deny` walks the graph for every target at once. Then `winit`'s wasm-only path pulls in `tokio`, which Holm bans. With the five desktop triples, the ban still stops anyone adding `tokio` to a real build, but a dependency of a target we never build does not trip it.

Licences work the same way, with one twist. `BSL-1.0` is allowed because only `clipboard-win` and `error-code` use it, and those are Windows-only parts of `arboard`, which we build on macOS only. `ISC`, though, is used by `libloading`, and `libloading` IS built on macOS. So `ISC` is allowed for that one crate (`exceptions`), not for every crate. A new ISC crate still has to be looked at.

Three advisories for the `zbus` family are ignored with a reason: they are "unmaintained" notices on the Linux screen reader path, which no Holm build compiles today.

### `cargo vet` for a big new graph

`cargo vet` is stricter: it checks every crate in `Cargo.lock`, on every target. For 260 new crate versions we used a fixed order:

1. **Imported audits.** `cargo vet regenerate imports` pulls audits that Mozilla, Google, the Bytecode Alliance and others already published. 39 new versions were covered this way, or by a trust we already had.
2. **Trust a publisher, but only one an imported set already trusts.** 49 `[[trusted.*]]` entries (53 versions), such as Kenny Kerr for the `windows-*` crates. Each entry says who, from when, and ends 2026-12-31, so it expires before Phase 6 instead of living forever.
3. **Exemptions last.** 206 entries noted `gui-only, pre-release; audit or replace before Phase 6`. An exemption says "we have not checked this", in writing, so it shows up in review.

Two rules hold this together. No new exemption may cover a normal dependency of `holm-core`, `holm-crypto` or `holm-platform`, and `cargo tree -p holm-core -e normal --locked` must print the same tree before and after. And we never write an audit we did not do: an AI skim is not a `safe-to-deploy` audit.

In Kotlin you'd write a Gradle `verification-metadata.xml` with checksums and trusted PGP keys. That proves who published a jar; `cargo vet` also records whether someone reviewed it.

## Exercises

1. Show that Linux never compiles `eframe`, while macOS does. (The Linux query prints "nothing to print".)
   Check: `cargo tree -p holm-gui --target x86_64-unknown-linux-gnu --locked -i eframe; cargo tree -p holm-gui --target aarch64-apple-darwin --locked -i eframe | head -3`
2. Change one byte of the mono font in a copy, point the hash check at it, and read the failure. Then delete the copy.
   Check: `T=$(mktemp) && cp crates/holm-gui/assets/fonts/AtkinsonHyperlegibleMono-Regular.ttf "$T" && printf 'x' | dd of="$T" bs=1 seek=100 conv=notrunc && echo "2c9a7b9fabebd5c746a808d8a1ef2f52e618850caad6ec4fd9f5c48f56e1c1af  $T" | shasum -a 256 -c -; rm "$T"`
3. Remove `targets` from `[graph]` in `deny.toml` and run deny. Which crate is banned, and through which path does it arrive? Undo the change.
   Check: `cargo deny --all-features --locked check bans`

## Read next

- [The Cargo Book: platform-specific dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies)
- [`std::fs::File::try_lock`](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
- [cargo-vet: recording audits, trust and exemptions](https://mozilla.github.io/cargo-vet/recording-audits.html)
