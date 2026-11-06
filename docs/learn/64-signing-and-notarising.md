# Lesson 64: Signing, notarising and the hardened runtime

## Why this matters

Lesson 45 built a `Holm.app` with an ad-hoc seal. That seal proves the files did not change since
the seal was made, but it does not say who made them. Gatekeeper on a user's Mac wants two more
things before it opens a downloaded app without a scary warning: a signature from a known
developer, and a ticket from Apple saying the app was scanned. This lesson walks through
`scripts/release-macos.sh`, which adds both and ships the result as a DMG.

## What we built

`scripts/release-macos.sh` checks two things first and stops if either is missing:

1. Exactly one valid `Developer ID Application: ... (G4685Q3YAY)` identity in the keychain.
2. A working notarytool keychain profile called `holm-notary`.

Only then does it build. It runs `bundle-macos.sh`, signs the app with the Developer ID identity,
builds `Holm-<version>.dmg`, signs that, sends it to Apple, staples the ticket and checks the result
with the same tools a user's Mac uses. `--preflight` runs only the two checks.

## Three kinds of signature

| Signature | Who can make it | What Gatekeeper says |
|---|---|---|
| Ad-hoc (`--sign -`) | anyone, no certificate | "cannot be verified", user must approve |
| Apple Development | any team member | only for your own test devices |
| Developer ID Application | the Account Holder creates the certificate | opens once notarised |

The Developer ID certificate is special. Apple lets only the Account Holder of a team create it,
in Xcode (Settings > Accounts > Manage Certificates > + > Developer ID Application) or on the
developer website. The App Store Connect API answers `403 ... can only be performed by the Account
Holder` to anyone else, even an admin key. That is why the script never tries to make the
certificate itself.

## Fail closed

The script reads the identity list with `security find-identity -v -p codesigning` and keeps only
lines that match the Developer ID name and our team ID. If none match, it stops with the steps to
fix it. There is no `else` that signs ad-hoc instead. After signing it checks again: it reads
`codesign -d --verbose=4` and insists on an `Authority=Developer ID Application:` line, the right
`TeamIdentifier`, a `Timestamp=` line and no `Signature=adhoc`. A quiet fallback would ship an app
that looks fine on the build Mac and fails on every other one.

## The hardened runtime

`codesign --options runtime` turns on the hardened runtime. With it, macOS refuses to let the
process:

- map memory that is both writable and executable (no JIT),
- load a library signed by another team,
- accept `DYLD_*` environment variables that inject code,
- be attached to by a debugger.

Notarisation requires it. Each of those can be turned back on with an entitlement, for example
`com.apple.security.cs.allow-jit`. Holm needs none: it is plain compiled Rust with no JIT and no
plug-ins. So the script passes no entitlements file and fails if the signed app carries any. The
smallest set of exceptions is the safest one, and zero is the smallest.

## The secure timestamp

`--timestamp` asks Apple's timestamp server to countersign the signature with the current time.
A Developer ID certificate lasts five years. With a timestamp, the app still verifies after the
certificate expires, because the signature was made while it was valid. Notarisation rejects a
signature without one.

## Notarising

`xcrun notarytool submit Holm-0.1.0.dmg --keychain-profile holm-notary --wait` uploads the DMG.
Apple scans it for malware and checks every signature inside, then returns `Accepted` or
`Invalid`. The script reads only the `status` field of the JSON result and, on failure, prints the
notary log so you can see which file failed.

The profile is made once with `xcrun notarytool store-credentials`. It stores an App Store Connect
API key (the `.p8` file, its key ID and the issuer ID) in the login keychain. After that the
release script never sees a key or a password; it only names the profile. That is the same idea as
the vault itself: keep the secret in one guarded place and pass a handle around.

## Stapling

Gatekeeper can look up the ticket online, but a user may be offline, and Holm is an offline app.
`xcrun stapler staple` writes the ticket into the DMG so the check works with no network.
`stapler validate` proves it is there.

## What a user's Mac checks

The last part of the script runs:

```sh
codesign --verify --strict Holm-0.1.0.dmg
spctl -a -vvv -t install Holm-0.1.0.dmg      # source=Notarized Developer ID
codesign --verify --deep --strict /Volumes/.../Holm.app
spctl -a -vv /Volumes/.../Holm.app           # accepted
```

`spctl` is the Gatekeeper policy tool. `-t install` asks "would you open this downloaded file?";
the default type asks "would you run this app?". Then the script writes a `.sha256` file, so a
user can check that the DMG they downloaded is the one we built.

## Rust angle

None of this needs a crate. Rust gives us one static binary, so the signature covers one
executable and one plist, with no bundled runtime or frameworks to sign one by one. The version
comes from the single `version` line in the workspace `Cargo.toml`, which `cargo` also uses for
every crate through `version.workspace = true`.

## Kotlin comparison

A Compose Desktop app does the same steps through Gradle: `macOS { signing { sign.set(true) } }`
and `notarization { ... }` in `build.gradle.kts`, then `./gradlew notarizeDmg`. The JVM bundle needs
`allow-jit` and `allow-unsigned-executable-memory` entitlements because the JIT compiler writes
machine code at run time. A Rust binary has no JIT, so it runs under the full hardened runtime.

## Try it

1. Run `scripts/release-macos.sh --preflight` on a Mac without a Developer ID identity. Read the
   message. Does anything get built?
2. Sign a copy of `/bin/echo` with `codesign --force --sign - --options runtime` and run
   `codesign -d --verbose=4` on it. Find the `flags=` value and the `Signature=` line.
3. On a release DMG, run `spctl -a -vvv -t install` and find the `source=` line. Then run
   `xcrun stapler validate` on it.

## Read next

- [Lesson 45: Shipping a Mac app by hand](45-shipping-a-mac-app-by-hand.md)
- [Lesson 63: Codes you cross off](63-codes-you-cross-off.md)
- [The index](README.md)
