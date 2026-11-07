#!/usr/bin/env bash
# Runs the gates from .github/workflows/ci.yml plus local-only gates (the libsodium
# oracle in oracle/), in order. Stops at the first failure.
#
# Self-test of the environment guard (expect "PREFLIGHT OK" and a NOTE naming the variable,
# and no effect on the gates, because the variable is unset before cargo runs):
#   CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=true bash scripts/ci-local.sh --preflight
#   RUSTUP_TOOLCHAIN=1.93.1 bash scripts/ci-local.sh --preflight
# A cargo config file in any ancestor directory or in CARGO_HOME makes the script exit 1.
set -euo pipefail
cd "$(dirname "$0")/.."

# Build flags from the environment could weaken or skip checks, so start from a clean
# slate. A stray variable such as CARGO_TARGET_<TRIPLE>_RUNNER=true makes every test
# "pass" without running, so these names are removed too. Only names are printed, never values.
cleared=""
for v in RUSTFLAGS RUSTDOCFLAGS RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTUP_TOOLCHAIN \
  $(env | sed -n -E 's/^(CARGO_(TARGET|BUILD|PROFILE|ENCODED|REGISTRIES|ALIAS)_[A-Za-z0-9_]*)=.*/\1/p' | sort -u); do
  if printenv "$v" >/dev/null 2>&1; then
    cleared="$cleared $v"
  fi
  unset "$v"
done
echo "NOTE  unset build-affecting environment variables:${cleared:- (none were set)}"

# A cargo config file can also change what is built or run (runners, flags, aliases,
# source replacement). Refuse to run if one is visible from the repo root or in CARGO_HOME.
fail_config=0
check_dir="$(pwd -P)"
while :; do
  for f in "$check_dir/.cargo/config" "$check_dir/.cargo/config.toml"; do
    if [ -e "$f" ]; then echo "FAIL  cargo config file present: $f" >&2; fail_config=1; fi
  done
  [ "$check_dir" = "/" ] && break
  check_dir="$(dirname "$check_dir")"
done
for f in "${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml"; do
  if [ -e "$f" ]; then echo "FAIL  cargo config file present: $f" >&2; fail_config=1; fi
done
if [ "$fail_config" -ne 0 ]; then exit 1; fi

# Exact toolchain and tool versions, so a gate result means the same thing on every run.
# Keep EXPECT_RUSTC equal to rust-toolchain.toml.
EXPECT_RUSTC="1.99.1"
case "$(rustc -V 2>/dev/null || true)" in
  "rustc $EXPECT_RUSTC "*) ;;
  *) echo "FAIL  expected rustc $EXPECT_RUSTC (rust-toolchain.toml), got: $(rustc -V 2>&1 || true)" >&2; exit 1 ;;
esac
# SODIUM_* variables make libsodium-sys-stable link a system libsodium or use another
# source archive instead of the vendored, signature-checked one pinned by oracle/Cargo.lock.
sodium_vars="$(env | sed -n 's/^\(SODIUM_[A-Za-z0-9_]*\)=.*/\1/p' | sort -u | tr '\n' ' ')"
# shellcheck disable=SC2086 # word splitting is intended: one name per word
unset SODIUM_LIB_DIR SODIUM_USE_PKG_CONFIG SODIUM_SHARED SODIUM_DIST_DIR SODIUM_DISABLE_PIE $sodium_vars
echo "NOTE  unset SODIUM_LIB_DIR, SODIUM_USE_PKG_CONFIG, SODIUM_SHARED, SODIUM_DIST_DIR, SODIUM_DISABLE_PIE and any other SODIUM_* variables"

need() { # tool, expected version, install hint
  local out
  if ! out="$(cargo "$1" --version 2>/dev/null)"; then
    echo "MISSING cargo-$1. Install: $3" >&2
    exit 2
  fi
  case "$out" in
    *" $2") ;;
    *) echo "FAIL  cargo-$1 must be exactly $2, got: $out. Install: $3" >&2; exit 2 ;;
  esac
}
need deny 0.20.2 "cargo install --locked cargo-deny --version 0.20.2"
need audit 0.22.2 "cargo install --locked cargo-audit --version 0.22.2"
need vet 0.10.2 "cargo install --locked cargo-vet --version 0.10.2"

# "--preflight" stops here: environment, config files and versions are checked, no gate runs.
# It prints PREFLIGHT OK, never ALL GATES PASSED, so it cannot be mistaken for a pass.
if [ "${1:-}" = "--preflight" ]; then
  echo "PREFLIGHT OK (no gates were run)"
  exit 0
fi

# Only a clean tree counts, so a pass always describes the commit that gets pushed.
if [ -n "$(git status --porcelain)" ]; then
  echo "FAIL  working tree not clean (commit or stash first)" >&2
  git status --short >&2
  exit 1
fi

gate() { # name, command...
  local name="$1"; shift
  echo "RUN   $name"
  if "$@"; then
    echo "PASS  $name"
  else
    echo "FAIL  $name" >&2
    exit 1
  fi
}

# Platform alone permits its reviewed AppKit module to opt into unsafe code.
# Every other Rust lint must match the workspace table.
lint_drift_gate() {
  python3 - <<'PYTHON'
import sys
try:
    import tomllib
except ImportError:
    sys.exit("FAIL  lint drift gate needs Python 3.11 or newer")

with open("Cargo.toml", "rb") as source:
    workspace = tomllib.load(source)["workspace"]["lints"]["rust"]
with open("crates/holm-platform/Cargo.toml", "rb") as source:
    platform = tomllib.load(source)["lints"]["rust"]
if workspace.pop("unsafe_code", None) != "forbid":
    sys.exit("FAIL  workspace unsafe_code must be forbid")
if platform.pop("unsafe_code", None) != "deny":
    sys.exit("FAIL  holm-platform unsafe_code must be deny")
if platform != workspace:
    sys.exit("FAIL  holm-platform Rust lints drifted from the workspace")
print("lint drift OK")
PYTHON
}
# Structural checks the lint table cannot make: both binaries install the zeroing
# allocator, and unsafe code is allowed in exactly two platform files.
alloc_unsafe_gate() {
  local f n
  for f in crates/holm-gui/src/main.rs crates/holm-cli/src/main.rs; do
    n=$(grep -c '^#\[global_allocator\]' "$f")
    if [ "$n" != 1 ]; then
      echo "$f: expected one #[global_allocator], found $n" >&2
      return 1
    fi
  done
  local found
  found=$(grep -rlzE 'allow\(\s*unsafe_code' crates fuzz --include='*.rs' | sort | tr '\n' ' ')
  if [ "$found" != "crates/holm-platform/src/window.rs crates/holm-platform/src/zeroing_alloc.rs " ]; then
    echo "allow(unsafe_code) must appear only in window.rs and zeroing_alloc.rs, found: $found" >&2
    return 1
  fi
}

gate lint-drift lint_drift_gate
gate alloc-unsafe alloc_unsafe_gate

# The EFF wordlist and the zxcvbn common-password lists are include_str!'d into the binary.
# Their pinned SHA-256 values (also in NOTICE) must match, and a missing shasum or file fails
# the gate, so this fails closed.
wordlist_gate() {
  command -v shasum >/dev/null 2>&1 || { echo "MISSING shasum" >&2; return 1; }
  printf '%s\n' \
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e  crates/holm-core/src/eff_large_wordlist.txt" \
    "664d32190713e42b7726072a5cf7533bd4a469e5588c7c1bd2ff9485cdf83276  crates/holm-core/src/strength/frequency_lists.coffee" \
    "88ed5c31a71584c7772963b02d04bef1eb7e3d2e9c8b9cb204339b1f82cf432c  crates/holm-gui/assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf" \
    "2c9a7b9fabebd5c746a808d8a1ef2f52e618850caad6ec4fd9f5c48f56e1c1af  crates/holm-gui/assets/fonts/AtkinsonHyperlegibleMono-Regular.ttf" \
    | shasum -a 256 -c -
}
gate wordlist wordlist_gate
gate bundle-check bash scripts/bundle-macos.sh --check
gate fmt cargo fmt --all --check
gate clippy cargo clippy --workspace --all-targets --locked -- -D warnings
# Without holm-gui, `gui-window` stays off, so this checks the default feature set.
gate clippy-default cargo clippy -p holm-platform -p holm-cli --locked -- -D warnings
# holm-core's `fuzzing` feature (seal and open with a raw KEK, no Argon2) only builds with
# `--cfg fuzzing`, which cargo-fuzz sets by default. A normal build that turns the feature
# on must stop with holm-core's compile_error!, and this gate proves it does.
FUZZING_GUARD_MSG="the fuzzing feature is only for cargo-fuzz builds"
fuzzing_guard_gate() {
  local out
  # Clear inherited RUSTFLAGS, so a shell that already sets --cfg fuzzing cannot hide a failure.
  if out=$(env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo check -p holm-core --features fuzzing --locked 2>&1); then
    echo "holm-core built with --features fuzzing and no --cfg fuzzing" >&2
    return 1
  fi
  printf '%s\n' "$out" | grep -qF "$FUZZING_GUARD_MSG" || {
    printf '%s\n' "$out" >&2
    echo "the build failed, but not on the fuzzing guard" >&2
    return 1
  }
}
gate fuzzing-guard fuzzing_guard_gate
# holm-gui's `dev-unlock` feature (unlock from HOLM_DEV_PASSWORD) is for debug builds only.
# A release build that turns the feature on must stop with holm-gui's compile_error!, and
# this gate proves it does.
DEV_UNLOCK_GUARD_MSG="the dev-unlock feature is for debug builds only"
dev_unlock_guard_gate() {
  local out
  if out=$(cargo check -p holm-gui --release --features dev-unlock --locked 2>&1); then
    echo "holm-gui built in release mode with --features dev-unlock" >&2
    return 1
  fi
  printf '%s\n' "$out" | grep -qF "$DEV_UNLOCK_GUARD_MSG" || {
    printf '%s\n' "$out" >&2
    echo "the build failed, but not on the dev-unlock guard" >&2
    return 1
  }
}
gate dev-unlock-guard dev_unlock_guard_gate
gate dev-unlock-test cargo test -p holm-gui --features dev-unlock --test dev_unlock --locked
# Proves a release binary carries no dev-unlock code: the variable name is only in the
# feature's module, so it must not appear in the normal release build.
dev_unlock_absent_gate() {
  cargo build -p holm-gui --release --locked || return 1
  if grep -qa HOLM_DEV_PASSWORD target/release/holm-gui; then
    echo "HOLM_DEV_PASSWORD is in the release binary" >&2
    return 1
  fi
}
gate dev-unlock-absent dev_unlock_absent_gate
# No other gate compiles holm-core's `fuzzing` module (test-only API for fuzz/) with clippy.
# Its own target dir, so the changed RUSTFLAGS do not force the other gates to rebuild.
gate clippy-fuzzing env RUSTFLAGS="--cfg fuzzing" CARGO_TARGET_DIR=target/cfg-fuzzing \
  cargo clippy -p holm-core --features fuzzing --all-targets --locked -- -D warnings
gate test cargo test --workspace --locked
gate deny cargo deny --all-features --locked check
gate audit cargo audit
gate vet cargo vet --locked
# Holm is offline: no HTTP or URL crate may enter the GUI's normal dependency tree.
# Pinned to the shipped target, so Linux-only crates do not show up (preflight F28).
no_network_gate() {
  local tree
  tree="$(cargo tree -p holm-gui -e normal --target aarch64-apple-darwin --locked --prefix none)" || return 1
  if grep -E '^(reqwest|ureq|hyper|url) v' <<<"$tree"; then
    echo "network crate in holm-gui's tree" >&2
    return 1
  fi
}
gate no-network no_network_gate
# Timing budgets (unlock KDF within 25% of the recorded baseline, search over 10,000 items,
# `holm --version` startup). Budgets live in scripts/bench-budgets.env. Release build.
gate bench bash scripts/bench-gates.sh

# The oracle is its own workspace (oracle/Cargo.toml), so the root gates above do not
# cover it. The root cargo-deny ban list does not apply there either: libsodium-sys-stable
# build-depends on ureq, and that is why the oracle is kept out of the product graph.
oracle_gate() {
  cargo fmt --manifest-path oracle/Cargo.toml --check &&
    cargo clippy --manifest-path oracle/Cargo.toml --all-targets --locked -- -D warnings &&
    cargo test --manifest-path oracle/Cargo.toml --locked &&
    cargo audit --file oracle/Cargo.lock \
      --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369 --ignore RUSTSEC-2026-0429
}
# Those four advisories are for zip 8.6.0 (fixed in 9.0), ignored for the oracle only.
# zip is a build-dependency of libsodium-sys-stable 1.24.3, the latest release, which
# requires zip 8.x. Its build script uses zip only for *-windows-msvc targets, where this
# gate is skipped, and only on an archive it has minisign-verified first. Remove the
# ignores once libsodium-sys-stable moves to zip 9.
# The fuzz targets are their own workspace (fuzz/Cargo.toml) and need nightly Rust and
# cargo-fuzz (libFuzzer), so the root gates do not cover them. A 30 s smoke run per target,
# and any single allocation over 64 MiB counts as a crash (the decoders must stay bounded);
# new corpus entries land in the git-ignored fuzz/corpus/, so the tree stays clean.
# Dated nightly, so a gate result does not drift with the day. Bump it on purpose.
FUZZ_NIGHTLY="nightly-2026-10-12"
fuzz_gate() {
  if ! cargo "+$FUZZ_NIGHTLY" --version >/dev/null 2>&1; then
    echo "MISSING nightly toolchain. Install: rustup toolchain install $FUZZ_NIGHTLY --profile minimal" >&2
    return 1
  fi
  if ! cargo fuzz --version >/dev/null 2>&1; then
    echo "MISSING cargo-fuzz. Install: cargo install --locked cargo-fuzz --version 0.13.2" >&2
    return 1
  fi
  cargo fmt --manifest-path fuzz/Cargo.toml --check || return 1
  cargo audit --file fuzz/Cargo.lock || return 1
  local t seeds
  for t in parse_header parse_header_structured unpad open_fixed_key decode_body decode_body_v1 import_csv import_json; do
    mkdir -p "fuzz/corpus/$t"
    seeds=""
    if [ -d "fuzz/seeds/$t" ]; then seeds="fuzz/seeds/$t"; fi
    # shellcheck disable=SC2086 # $seeds is empty or one path without spaces
    cargo "+$FUZZ_NIGHTLY" fuzz run "$t" "fuzz/corpus/$t" $seeds -- -max_total_time=30 -malloc_limit_mb=64 || return 1
  done
}
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # On Windows libsodium-sys-stable downloads a prebuilt zip over HTTP.
    echo "SKIP oracle (Windows shell: libsodium-sys-stable would download a prebuilt library)"
    echo "SKIP fuzz (Windows shell: libFuzzer is not supported here)"
    echo "ALL GATES PASSED (oracle and fuzz skipped)"
    ;;
  *)
    gate oracle oracle_gate
    gate fuzz fuzz_gate
    echo "ALL GATES PASSED"
    ;;
esac
