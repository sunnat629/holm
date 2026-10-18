#!/usr/bin/env bash
# Builds an unsigned (ad-hoc sealed) local Holm.app: target/bundle/Holm.app.
#
#   scripts/bundle-macos.sh           build the release binary and lay out the bundle
#   scripts/bundle-macos.sh --zip     the same, then also write
#                                     target/bundle/Holm-<version>-macos-arm64.zip and its .sha256
#   scripts/bundle-macos.sh --check   fast, no build: lint the plist template and check the icon PNG
#
# arm64 only. No network access in this script.
# Ad-hoc signing (`codesign --sign -`) is not Developer ID signing or notarisation, so Gatekeeper
# still asks the user to approve the first launch.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"
case "$mode" in "" | --zip | --check) ;; *) echo "usage: $0 [--zip|--check]" >&2; exit 2 ;; esac

tpl="packaging/macos/Info.plist.in"
png="packaging/macos/holm-icon-1024.png"
svg="packaging/macos/holm-icon.svg"

# Version from the workspace Cargo.toml, a plain text read (the first `version = "..."` line).
version="$(sed -n -E 's/^version = "([0-9][0-9A-Za-z.+-]*)"$/\1/p' Cargo.toml | head -n 1)"
[ -n "$version" ] || { echo "could not read the version from Cargo.toml" >&2; exit 1; }

check() {
  [ -f "$svg" ] || { echo "missing $svg" >&2; exit 1; }
  [ -f "$png" ] || { echo "missing $png" >&2; exit 1; }
  [ -f "$tpl" ] || { echo "missing $tpl" >&2; exit 1; }
  local tmp dims
  tmp="$(mktemp)"
  sed "s/@VERSION@/$version/g" "$tpl" >"$tmp"
  plutil -lint "$tmp" >/dev/null || { rm -f "$tmp"; echo "Info.plist.in is not a valid plist" >&2; exit 1; }
  rm -f "$tmp"
  dims="$(sips -g pixelWidth -g pixelHeight "$png" | sed -n -E 's/^ *pixel(Width|Height): ([0-9]+)$/\2/p' | tr '\n' 'x')"
  [ "$dims" = "1024x1024x" ] || { echo "$png must be 1024x1024, got: $dims" >&2; exit 1; }
  echo "bundle check OK"
}

check
[ "$mode" = "--check" ] && exit 0

app="target/bundle/Holm.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

cargo build --release --locked -p holm-gui
cp target/release/holm-gui "$app/Contents/MacOS/Holm"
sed "s/@VERSION@/$version/g" "$tpl" >"$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
bash scripts/make-icns.sh "$app/Contents/Resources/Holm.icns"

codesign --sign - --force --timestamp=none "$app"
codesign --verify --deep --strict "$app"
echo "built $app (version $version)"

if [ "$mode" = "--zip" ]; then
  zip="target/bundle/Holm-$version-macos-arm64.zip"
  rm -f "$zip" "$zip.sha256"
  ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
  (cd target/bundle && shasum -a 256 "$(basename "$zip")" >"$(basename "$zip").sha256")
  echo "wrote $zip"
  cat "$zip.sha256"
fi
