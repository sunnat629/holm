# Shared path remap for release builds. Sourced by scripts/repro-check.sh and
# scripts/bundle-macos.sh, so the shipped app is built with the same rules the rebuild check uses.
# Usage: RUSTFLAGS="$(holm_remap_flags CHECKOUT_DIR CARGO_HOME)"
# rustc applies the last matching rule first, so the more specific cargo home comes after the
# checkout.
holm_remap_flags() {
  printf '%s' "--remap-path-prefix=$1=/holm-src --remap-path-prefix=$2=/cargo-home --remap-path-prefix=$HOME/.rustup=/rustup"
}
