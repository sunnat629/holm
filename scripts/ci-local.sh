#!/usr/bin/env bash
# Runs the same gates as .github/workflows/ci.yml, in order. Stops at the first failure.
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
echo "ALL GATES PASSED"
