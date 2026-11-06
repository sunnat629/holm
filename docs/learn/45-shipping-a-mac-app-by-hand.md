# Lesson 45: Shipping a Mac app by hand

## Why this matters

A Rust GUI program is a single file. A Mac user expects an app: something to double-click, with
an icon in the Dock and a name in the menu bar. The gap between the two is a folder with a
fixed shape and one small text file. Doing it by hand with a short script means no new crate
to trust, and you see every step.

## What we built

`scripts/bundle-macos.sh` builds `holm-gui` in release mode and lays out `target/bundle/Holm.app`.
With `--zip` it also writes `Holm-<version>-macos-arm64.zip` and a `.sha256` file next to it.
`--check` is fast (no build) and runs as the `bundle-check` gate in `scripts/ci-local.sh`: it
lints the plist template and checks the icon PNG is 1024x1024.

## The bundle layout

```
Holm.app/
  Contents/
    Info.plist          the app's identity card
    MacOS/Holm          the executable (our holm-gui, renamed)
    Resources/Holm.icns the icon
```

Finder treats any folder ending in `.app` with this shape as one clickable thing. The file name
in `MacOS/` must match `CFBundleExecutable` in the plist.

## Info.plist

It is XML with key and value pairs. The template is `packaging/macos/Info.plist.in`. It sets
the name (`Holm`), the identifier (`io.github.sunnat629.holm`, a reverse-domain string that
must be unique), the version, the executable name (`Holm`), the icon name (`Holm`, which
macOS finds as `Resources/Holm.icns`), a minimum macOS of 11.0, `NSHighResolutionCapable` so
the window is sharp on Retina screens, and the Utilities category
(`public.app-category.utilities`). It has no network, camera or other permission keys, on
purpose: Holm is offline.

The template holds `@VERSION@` in place of the version. The script reads the first
`version = "..."` line of the workspace `Cargo.toml` with `sed` and fills it in, so there is one
source of truth. `plutil -lint` checks the result is a valid plist.

## The icon

`packaging/macos/holm-icon.svg` is hand-written: a rounded square in the app's dark panel
colour (`#1b1b1b`) with an H made of three rectangles in the strength-meter green
(`#2e9d4f`). It was rendered once to `holm-icon-1024.png` with
`sips -s format png holm-icon.svg --out holm-icon-1024.png`, and that PNG is committed. The
check step reads its size with `sips` and stops unless it is exactly 1024x1024.

`scripts/make-icns.sh` makes ten sizes (16 to 1024, with the @2x pairs) and packs them:

```bash
for spec in icon_16x16:16 icon_16x16@2x:32 ... icon_512x512@2x:1024; do
  sips -z "${spec#*:}" "${spec#*:}" "$src" --out "$set_dir/${spec%%:*}.png" >/dev/null
done
iconutil -c icns "$set_dir" -o "$out"
```

Each `spec` is `name:size`. `${spec#*:}` cuts everything up to the colon, which leaves the
size. `${spec%%:*}` cuts everything from the colon, which leaves the name. `iconutil -c icns`
turns the folder of PNGs into one `.icns` file.

## Keeping the builder out of the binary

A release binary can carry file paths from the machine that built it, in panic messages and
debug info. Those paths can hold your home folder and user name. The script builds with
`--remap-path-prefix`, which rewrites `$HOME/.cargo`, `$HOME/.rustup` and the checkout path to
short neutral names. It builds into its own target folder, `target/bundle-build`, so the
changed `RUSTFLAGS` do not throw away the normal build cache.

After the build, the script counts how often `$HOME` and the user name (as a path segment)
appear in the binary with `grep -c`. If either count is not 0, it stops. It prints only the
counts, never the matches.

## Ad-hoc signing against Developer ID

`codesign --sign - --force --timestamp=none` seals the bundle with no identity, and
`codesign --verify --deep --strict` checks the seal. macOS can tell if a file inside was
changed afterwards, but it does not know who made it. Apple Silicon refuses to run unsigned
code, so the ad-hoc seal is the minimum. A Developer ID signature plus notarisation (Apple
scans the upload) costs a paid account and is what lets Gatekeeper open the app without a
warning. Ours is the first kind, so a downloaded copy needs approval the first time. On macOS
14 and earlier: right-click, Open. On macOS 15 and later: open the app once (it is refused),
then System Settings, Privacy & Security, "Open Anyway".

## The zip and its checksum

With `--zip`, `ditto -c -k --keepParent` packs the app, with flags that leave out resource
forks and extended attributes. The script then lists the zip with `unzip -Z1` and stops if any
entry is outside `Holm.app/`, so no `__MACOSX/` files slip in. `shasum -a 256` writes the
`.sha256` file, which lets a person check the download was not damaged or swapped.

## Why not cargo-bundle

`cargo-bundle` does this job, but it is another crate to install and trust, and Holm puts
security first. Under a hundred lines of shell do the same thing, and every line is readable.

## Kotlin comparison

On the JVM, `jpackage` (or the Gradle `application` plugin plus a jpackage task) makes the
`.app` for you and bundles a runtime. Rust needs no runtime, so the bundle is just the binary,
a plist and an icon. The Gradle version field you would bump maps to the one `version` line in
`Cargo.toml`.

## Try it

1. Run `scripts/bundle-macos.sh --check`. Then copy `packaging/macos/Info.plist.in` to
   `/tmp/broken.plist`, delete one `</string>` from the copy, and run
   `plutil -lint /tmp/broken.plist`. What does it report?
2. Build the bundle and run `codesign --verify --deep --strict target/bundle/Holm.app`. Then
   change one byte of `Holm.app/Contents/Info.plist` and run the verify again. What does it say?
3. Run `grep -c -a -F -- "$HOME" target/bundle/Holm.app/Contents/MacOS/Holm`. Then build
   once with plain `cargo build --release -p holm-gui` and run the same count on
   `target/release/holm-gui`. Compare the two numbers.

## Read next

- [Lesson 44: The list and its memory](44-the-list-and-its-memory.md)
- [Lesson 47: One row of buttons](47-one-row-of-buttons.md)
- [The index](README.md)
