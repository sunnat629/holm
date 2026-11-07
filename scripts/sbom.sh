#!/usr/bin/env bash
# Writes a CycloneDX 1.5 SBOM (JSON) for each shipped binary: holm-gui and holm-cli.
#
#   scripts/sbom.sh                       -> target/sbom/holm-gui.cdx.json, holm-cli.cdx.json
#   scripts/sbom.sh OUT_DIR [PREFIX]      -> OUT_DIR/PREFIXholm-gui.cdx.json, ...
#
# cargo-cyclonedx is a developer tool only: it is not a dependency of Holm and never enters
# Cargo.lock. Install the pinned version once:
#   cargo install --locked cargo-cyclonedx --version 0.5.10
# The lists cover the shipped target (aarch64-apple-darwin), build-time crates included, so
# they match what `cargo tree --target aarch64-apple-darwin` shows. Each file carries a
# timestamp taken from SOURCE_DATE_EPOCH (default: the last commit time).
set -euo pipefail
cd "$(dirname "$0")/.."

PIN="0.5.10"
TARGET="aarch64-apple-darwin"
out="${1:-target/sbom}"
prefix="${2:-}"

if ! have="$(cargo cyclonedx --version 2>/dev/null)"; then
  echo "MISSING cargo-cyclonedx. Install: cargo install --locked cargo-cyclonedx --version $PIN" >&2
  exit 2
fi
case "$have" in
  *" $PIN") ;;
  *) echo "FAIL  cargo-cyclonedx must be exactly $PIN, got: $have. Install: cargo install --locked cargo-cyclonedx --version $PIN" >&2; exit 2 ;;
esac

mkdir -p "$out"
# The tool has no package switch: from a workspace it writes one <crate>.cdx.json next to
# every member's manifest. Run it once, keep the two shipped binaries, delete the rest.
# SOURCE_DATE_EPOCH (the last commit time) pins the timestamp the tool writes.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}" \
  cargo cyclonedx --manifest-path Cargo.toml --format json --spec-version 1.5 \
  --target "$TARGET" -q
for crate in holm-gui holm-cli; do
  produced="crates/$crate/$crate.cdx.json"
  [ -f "$produced" ] || { echo "FAIL  cargo cyclonedx did not write $produced" >&2; exit 1; }
  mv -f "$produced" "$out/${prefix}${crate}.cdx.json"
  echo "wrote $out/${prefix}${crate}.cdx.json"
done
rm -f crates/*/*.cdx.json
