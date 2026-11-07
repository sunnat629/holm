#!/usr/bin/env bash
# Reproducible-build check: builds the release binaries twice, each from a fresh export of
# HEAD in its own directory with its own empty target dir, then compares SHA-256 of the
# unsigned binaries. Identical hashes mean the build config leaks no path, time or order.
#
#   scripts/repro-check.sh            holm (CLI) and holm-gui
#   scripts/repro-check.sh --keep     keep the work dir (printed at the end)
#
# Only committed files count (git archive HEAD), so run it on a clean commit. The code
# signature added later by release-macos.sh is NOT reproducible (docs/DECISIONS.md, C1).
set -euo pipefail
cd "$(dirname "$0")/.."
keep=0
case "${1:-}" in "") ;; --keep) keep=1 ;; *) echo "usage: $0 [--keep]" >&2; exit 2 ;; esac

command -v shasum >/dev/null || { echo "MISSING shasum" >&2; exit 1; }
src="$(pwd -P)"
work="$(mktemp -d "${TMPDIR:-/tmp}/holm-repro.XXXXXX")"
if [ "$keep" = 0 ]; then trap 'rm -rf "$work"' EXIT; fi

# Same inputs for both builds: the commit time pins every timestamp a tool may embed.
epoch="$(git log -1 --format=%ct HEAD)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
bins="holm holm-gui"

build() { # label
  local dir="$work/$1/holm-src"
  mkdir -p "$dir"
  git -C "$src" archive HEAD | tar -x -C "$dir"
  # --remap-path-prefix hides the checkout and cargo registry paths, which differ per run.
  # The remap order matters: rustc applies the last matching rule first, so the more
  # specific cargo home comes last.
  (
    cd "$dir"
    env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
      CARGO_HOME="$cargo_home" \
      CARGO_INCREMENTAL=0 \
      SOURCE_DATE_EPOCH="$epoch" \
      CARGO_TARGET_DIR="$work/$1/target" \
      RUSTFLAGS="--remap-path-prefix=$dir=/holm-src --remap-path-prefix=$cargo_home=/cargo-home --remap-path-prefix=$HOME/.rustup=/rustup" \
      cargo build --release --locked -p holm-cli -p holm-gui
  )
}

echo "repro: build A (epoch $epoch)"
build a
echo "repro: build B"
build b

status=0
for b in $bins; do
  ha="$(shasum -a 256 "$work/a/target/release/$b" | cut -d' ' -f1)"
  hb="$(shasum -a 256 "$work/b/target/release/$b" | cut -d' ' -f1)"
  if [ "$ha" = "$hb" ]; then
    echo "SAME  $b  $ha"
  else
    echo "DIFF  $b  A=$ha  B=$hb" >&2
    status=1
  fi
done
if [ "$status" = 0 ]; then echo "repro: reproducible"; else echo "repro: NOT reproducible" >&2; fi
[ "$keep" = 1 ] && echo "repro: work dir kept at $work"
exit "$status"
