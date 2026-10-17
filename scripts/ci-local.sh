#!/usr/bin/env bash
# Runs the gates from .github/workflows/ci.yml plus local-only gates (the libsodium
# oracle in oracle/), in order. Stops at the first failure.
set -euo pipefail
cd "$(dirname "$0")/.."

# Build flags from the environment could weaken or skip checks. Start from a clean slate.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
echo "NOTE  unset RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER"

# Only a clean tree counts, so a pass always describes the commit that gets pushed.
if [ -n "$(git status --porcelain)" ]; then
  echo "FAIL  working tree not clean (commit or stash first)" >&2
  git status --short >&2
  exit 1
fi

need() { # tool, install hint
  if ! cargo "$1" --version >/dev/null 2>&1; then
    echo "MISSING cargo-$1. Install: $2" >&2
    exit 2
  fi
}
need deny "cargo install --locked cargo-deny --version 0.20.2"
need audit "cargo install --locked cargo-audit --version 0.22.2"
need vet "cargo install --locked cargo-vet --version 0.10.2"

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

gate fmt cargo fmt --all --check
gate clippy cargo clippy --workspace --all-targets --locked -- -D warnings
gate test cargo test --workspace --locked
gate deny cargo deny --all-features --locked check
gate audit cargo audit
gate vet cargo vet --locked

# The oracle is its own workspace (oracle/Cargo.toml), so the root gates above do not
# cover it. The root cargo-deny ban list does not apply there either: libsodium-sys-stable
# build-depends on ureq, and that is why the oracle is kept out of the product graph.
oracle_gate() {
  cargo fmt --manifest-path oracle/Cargo.toml --check &&
    cargo clippy --manifest-path oracle/Cargo.toml --all-targets --locked -- -D warnings &&
    cargo test --manifest-path oracle/Cargo.toml --locked &&
    cargo audit --file oracle/Cargo.lock \
      --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369
}
# Those three advisories are for zip 8.6.0 (fixed in 9.0), ignored for the oracle only.
# zip is a build-dependency of libsodium-sys-stable 1.24.3, the latest release, which
# requires zip 8.x. Its build script uses zip only for *-windows-msvc targets, where this
# gate is skipped, and only on an archive it has minisign-verified first. Remove the
# ignores once libsodium-sys-stable moves to zip 9.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # On Windows libsodium-sys-stable downloads a prebuilt zip over HTTP.
    echo "SKIP oracle (Windows shell: libsodium-sys-stable would download a prebuilt library)"
    ;;
  *)
    gate oracle oracle_gate
    ;;
esac
echo "ALL GATES PASSED"
