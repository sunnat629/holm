# Lesson 45: Shipping a Mac app by hand

## Why this matters

A Rust GUI program is a single file. A Mac user expects an app: something to double-click, with
an icon in the Dock and a name in the menu bar. The gap between the two is a folder with a
fixed shape and one small text file. Doing it by hand with a short script means no new crate
to trust, and you see every step.

## What we built

`scripts/bundle-macos.sh` builds `holm-gui` in release mode and lays out `target/bundle/Holm.app`.
With `--zip` it also writes `Holm-<version>-macos-arm64.zip` and a `.sha256` file next to it.
`--check` is fast (no build) and runs in `ci-local.sh`: it lints the plist template and checks
the icon PNG is 1024x1024.

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

It is XML with key and value pairs. Ours sets the name (`Holm`), the identifier
(`io.github.sunnat629.holm`, a reverse-domain string that must be unique), the version
(read from the workspace `Cargo.toml` with `sed`, so there is one source of truth), the icon
name, a minimum macOS of 11.0, `NSHighResolutionCapable` so the window is sharp on Retina
screens, and the Utilities category. It has no network, camera or other permission keys, on
purpose: Holm is offline. `plutil -lint` checks the file is valid.

## The icon

`holm-icon.svg` is hand-written: a rounded square in the app's dark panel colour with an H made
of three rectangles in the strength-meter green. It is rendered once to a 1024 pixel PNG and
that PNG is committed. `make-icns.sh` uses `sips -z` to make ten sizes (16 to 1024, with the
@2x pairs), and `iconutil -c icns` packs them into one `.icns` file.

## Ad-hoc signing against Developer ID

`codesign --sign -` seals the bundle with no identity: macOS can tell if a file inside was
changed afterwards, but it does not know who made it. Apple Silicon refuses to run unsigned
code, so the ad-hoc seal is the minimum. A Developer ID signature plus notarisation (Apple
scans the upload) costs a paid account and is what lets Gatekeeper open the app without a
warning. Ours is the first kind, so a downloaded copy needs right-click, Open the first time.
The `.sha256` file lets a person check the download was not damaged or swapped.

## Why not cargo-bundle

`cargo-bundle` does this job, but it is another crate to install and trust, and Holm puts
security first. Fifty lines of shell do the same thing, and every line is readable.

## Kotlin comparison

On the JVM, `jpackage` (or the Gradle `application` plugin plus a jpackage task) makes the
`.app` for you and bundles a runtime. Rust needs no runtime, so the bundle is just the binary,
a plist and an icon. The Gradle version field you would bump maps to the one `version` line in
`Cargo.toml`.
