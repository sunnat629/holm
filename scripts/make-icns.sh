#!/usr/bin/env bash
# Turns packaging/macos/holm-icon-1024.png into target/bundle/Holm.icns (sips + iconutil).
#
# How the PNG was made: packaging/macos/holm-icon.svg is hand-written. The intended render
# command was `qlmanage -t -s 1024 -o . holm-icon.svg`, but qlmanage hung with no output on
# this Mac, so the PNG was rendered once with
# `sips -s format png holm-icon.svg --out holm-icon-1024.png` instead. The result is
# 1024x1024 with a transparent border around the rounded square.
set -euo pipefail
cd "$(dirname "$0")/.."

src="packaging/macos/holm-icon-1024.png"
out="${1:-target/bundle/Holm.icns}"
work="$(mktemp -d)"
set_dir="$work/Holm.iconset"
mkdir -p "$set_dir" "$(dirname "$out")"

# name:pixel-size
for spec in icon_16x16:16 icon_16x16@2x:32 icon_32x32:32 icon_32x32@2x:64 \
  icon_128x128:128 icon_128x128@2x:256 icon_256x256:256 icon_256x256@2x:512 \
  icon_512x512:512 icon_512x512@2x:1024; do
  sips -z "${spec#*:}" "${spec#*:}" "$src" --out "$set_dir/${spec%%:*}.png" >/dev/null
done
iconutil -c icns "$set_dir" -o "$out"
rm -rf "$work"
echo "wrote $out"
