#!/usr/bin/env bash
# Runs the same gates as .github/workflows/ci.yml, in order. Stops at the first failure.
set -euo pipefail
cd "$(dirname "$0")/.."

need() { # tool, install hint
  if ! cargo "$1" --version >/dev/null 2>&1; then
    echo "MISSING cargo-$1. Install: $2" >&2
    exit 2
  fi
}
need deny "cargo install --locked cargo-deny"
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
