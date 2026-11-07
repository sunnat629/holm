#!/usr/bin/env bash
# Builds the signed, notarised and stapled release DMG: target/release-macos/Holm-<version>.dmg.
#
#   scripts/release-macos.sh              preflight, build, sign, notarise, staple, verify
#   scripts/release-macos.sh --preflight  only check the signing identity and the notary profile
#
# After the DMG is done, an SBOM per binary (CycloneDX JSON, scripts/sbom.sh) is written next
# to it. This step is optional: it is skipped with a note when cargo-cyclonedx is missing, and
# a failure there never undoes the DMG. HOLM_SBOM=0 skips it, HOLM_SBOM=1 makes it required.
#
# Needs, on this Mac, before anything is built:
#   - exactly one valid "Developer ID Application: ... (G4685Q3YAY)" identity in the keychain
#     (set HOLM_SIGN_IDENTITY to its SHA-1 hash when there is more than one), and
#   - the notarytool keychain profile "holm-notary" (override the name with HOLM_NOTARY_PROFILE).
# Without either one the script stops. It never falls back to ad-hoc signing.
#
# The script handles no secrets itself: the private key stays in the keychain and the notary
# credentials stay in the notarytool profile. Do not add `set -x` here.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"
case "$mode" in "" | --preflight) ;; *) echo "usage: $0 [--preflight]" >&2; exit 2 ;; esac

team="G4685Q3YAY"
bundle_id="io.github.sunnat629.holm"
profile="${HOLM_NOTARY_PROFILE:-holm-notary}"

die() { echo "release: $*" >&2; exit 1; }

# Version: the single source is the workspace Cargo.toml (same read as bundle-macos.sh).
version="$(sed -n -E 's/^version = "([0-9][0-9A-Za-z.+-]*)"$/\1/p' Cargo.toml | head -n 1)"
[ -n "$version" ] || die "could not read the version from Cargo.toml"
[ "$version" != "0.0.0" ] || die "version is 0.0.0; set a real version in Cargo.toml first"

# --- Preflight: fail closed before any build. ---
[ "$(uname -s)" = "Darwin" ] || die "macOS only"
for tool in codesign hdiutil xcrun security spctl shasum plutil; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done

# Valid code-signing identities whose name is Developer ID Application for our team.
ids="$(security find-identity -v -p codesigning |
  sed -n -E "s/^ *[0-9]+\) ([0-9A-F]{40}) \"Developer ID Application: .* \\($team\\)\"$/\\1/p" | sort -u)"
if [ -n "${HOLM_SIGN_IDENTITY:-}" ]; then
  printf '%s\n' "$ids" | grep -q -x -F -- "$HOLM_SIGN_IDENTITY" ||
    die "HOLM_SIGN_IDENTITY is not a valid Developer ID Application identity for team $team"
  identity="$HOLM_SIGN_IDENTITY"
else
  n_ids="$(printf '%s' "$ids" | grep -c . || true)"
  [ "$n_ids" != "0" ] || die "no valid 'Developer ID Application: ... ($team)' identity in the keychain.
  The Account Holder creates it in Xcode: Settings > Accounts > Manage Certificates > + > Developer ID Application."
  [ "$n_ids" = "1" ] || die "$n_ids Developer ID Application identities found; set HOLM_SIGN_IDENTITY to one SHA-1 hash"
  identity="$ids"
fi

# The profile check talks to Apple, so it needs the network. Output is discarded.
xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 ||
  die "notarytool profile '$profile' is missing or does not work.
  Create it with: xcrun notarytool store-credentials $profile --key <AuthKey .p8> --key-id <id> --issuer <issuer>"

echo "preflight OK (version $version, team $team, profile $profile)"
[ "$mode" = "--preflight" ] && exit 0

# --- Build the bundle (bundle-macos.sh lays it out and ad-hoc seals it; we re-sign below). ---
bash scripts/bundle-macos.sh
app="target/bundle/Holm.app"
[ -d "$app" ] || die "bundle-macos.sh did not produce $app"
plist_id="$(plutil -extract CFBundleIdentifier raw "$app/Contents/Info.plist")"
[ "$plist_id" = "$bundle_id" ] || die "Info.plist bundle id is $plist_id, expected $bundle_id"
plist_ver="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
[ "$plist_ver" = "$version" ] || die "Info.plist version is $plist_ver, expected $version"

# Developer ID signature, hardened runtime, secure timestamp. No entitlements: Holm needs none
# (no JIT, no unsigned memory, no library validation exceptions, no network).
codesign --force --sign "$identity" --options runtime --timestamp --identifier "$bundle_id" "$app"

# Prove the signature really is Developer ID with the hardened runtime, not ad-hoc.
check_sig() { # path
  local info
  info="$(codesign -d --verbose=4 "$1" 2>&1)"
  printf '%s\n' "$info" | grep -q -E "^Authority=Developer ID Application: .* \\($team\\)$" ||
    die "$1 is not signed with a Developer ID Application identity"
  printf '%s\n' "$info" | grep -q -x "TeamIdentifier=$team" || die "$1 has the wrong team identifier"
  printf '%s\n' "$info" | grep -q -E '^Timestamp=' || die "$1 has no secure timestamp"
  if printf '%s\n' "$info" | grep -q -E '^Signature=adhoc'; then die "$1 is ad-hoc signed"; fi
}
check_sig "$app"
# Read into variables first: `cmd | grep -q` under pipefail fails when grep exits early (SIGPIPE).
app_info="$(codesign -d --verbose=4 "$app" 2>&1)"
printf '%s\n' "$app_info" | grep -q -E '^CodeDirectory .*flags=0x[0-9a-f]*\(runtime\)' ||
  die "$app does not have the hardened runtime flag"
app_ents="$(codesign -d --entitlements - "$app" 2>/dev/null || true)"
if printf '%s\n' "$app_ents" | grep -q '<key>'; then
  die "$app carries entitlements; Holm ships with none"
fi
codesign --verify --deep --strict --verbose=2 "$app"

# --- DMG: Holm.app plus an Applications link, compressed (UDZO), then signed. ---
out="target/release-macos"
dmg="$out/Holm-$version.dmg"
stage="$out/stage"
rm -rf "$stage" "$dmg" "$dmg.sha256"
mkdir -p "$stage"
ditto --norsrc --noextattr --noqtn --noacl "$app" "$stage/Holm.app"
ln -s /Applications "$stage/Applications"
hdiutil create -quiet -volname "Holm $version" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
rm -rf "$stage"
codesign --force --sign "$identity" --timestamp --identifier "$bundle_id.dmg" "$dmg"
check_sig "$dmg"

# --- Notarise and staple. Only the submission status is read from the result. ---
result="$(xcrun notarytool submit "$dmg" --keychain-profile "$profile" --wait --output-format json)" ||
  die "notarytool submit failed"
status="$(printf '%s' "$result" | plutil -extract status raw - 2>/dev/null || true)"
sub_id="$(printf '%s' "$result" | plutil -extract id raw - 2>/dev/null || true)"
if [ "$status" != "Accepted" ]; then
  echo "notarisation status: ${status:-unknown}. Details:" >&2
  [ -n "$sub_id" ] && xcrun notarytool log "$sub_id" --keychain-profile "$profile" >&2 || true
  die "notarisation was not accepted"
fi
echo "notarisation: Accepted"
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"

# --- Verify what a user's Mac will check. ---
codesign --verify --strict --verbose=2 "$dmg"
spctl -a -vvv -t install "$dmg"
mnt="$(mktemp -d)"
trap 'hdiutil detach -quiet "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$dmg"
codesign --verify --deep --strict --verbose=2 "$mnt/Holm.app"
spctl -a -vv "$mnt/Holm.app"
hdiutil detach -quiet "$mnt"
rmdir "$mnt"
trap - EXIT

(cd "$out" && shasum -a 256 "$(basename "$dmg")" >"$(basename "$dmg").sha256")
echo "wrote $dmg"
cat "$dmg.sha256"

# --- Optional: SBOM next to the DMG (Holm-<version>-holm-gui.cdx.json, ...-holm-cli.cdx.json). ---
sbom_mode="${HOLM_SBOM:-auto}"
if [ "$sbom_mode" = "0" ]; then
  echo "sbom: skipped (HOLM_SBOM=0)"
elif [ "$sbom_mode" = "1" ] || cargo cyclonedx --version >/dev/null 2>&1; then
  if bash scripts/sbom.sh "$out" "Holm-$version-"; then
    (cd "$out" && shasum -a 256 "Holm-$version-"*.cdx.json)
  elif [ "$sbom_mode" = "1" ]; then
    die "SBOM step failed and HOLM_SBOM=1 requires it"
  else
    echo "sbom: FAILED; the DMG is fine, run scripts/sbom.sh by hand" >&2
  fi
else
  echo "sbom: skipped (cargo-cyclonedx not installed; see scripts/sbom.sh)"
fi
