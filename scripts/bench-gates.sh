#!/usr/bin/env bash
# Benchmark gates: checks three budgets from scripts/bench-budgets.env and fails when one is
# broken. No benchmark crate: the timings come from ignored release-mode tests
# (crates/holm-core/tests/bench_gates.rs) and from timing `holm --version`.
#
#   scripts/bench-gates.sh            check the budgets (retries once: a busy machine only slows runs)
#   scripts/bench-gates.sh --record   measure and write KDF_BASELINE_MS in the budgets file
#
# Timings depend on the machine. Run on a quiet Mac. The KDF baseline is per machine.
set -euo pipefail
cd "$(dirname "$0")/.."
budgets="scripts/bench-budgets.env"
# shellcheck disable=SC1090
. "$budgets"

mode="${1:-}"
case "$mode" in "" | --record) ;; *) echo "usage: $0 [--record]" >&2; exit 2 ;; esac

measure() { # prints "name=value" lines
  local out
  out="$(cargo test -p holm-core --release --locked --test bench_gates -- --ignored --nocapture --test-threads=1 2>&1)" ||
    { printf '%s\n' "$out" >&2; return 1; }
  printf '%s\n' "$out" | sed -n -E 's/^.*BENCH ([a-z0-9_]+)=([0-9.]+)$/\1=\2/p'
  cargo build -p holm-cli --release --locked >/dev/null 2>&1 || { echo "build of holm-cli failed" >&2; return 1; }
  # Median of 15 process starts. python3 is already needed by ci-local.sh.
  python3 - <<'PYTHON'
import statistics, subprocess, time
runs = []
for _ in range(15):
    t = time.perf_counter()
    subprocess.run(["target/release/holm", "--version"], check=True, stdout=subprocess.DEVNULL)
    runs.append((time.perf_counter() - t) * 1000)
print("startup_ms=%.1f" % statistics.median(runs))
PYTHON
}

get() { printf '%s\n' "$1" | sed -n -E "s/^$2=(.*)$/\1/p"; }

if [ "$mode" = "--record" ]; then
  res="$(measure)"
  kdf="$(get "$res" kdf_default_ms)"
  [ -n "$kdf" ] || { echo "no kdf measurement" >&2; exit 1; }
  machine="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m) / $(uname -sr)"
  sed -i.bak -E "s/^KDF_BASELINE_MS=.*/KDF_BASELINE_MS=${kdf%.*}/; s|^KDF_BASELINE_MACHINE=.*|KDF_BASELINE_MACHINE=\"$machine\"|" "$budgets"
  rm -f "$budgets.bak"
  echo "recorded KDF_BASELINE_MS=${kdf%.*} ($machine)"
  exit 0
fi

[ "$KDF_BASELINE_MS" -gt 0 ] || { echo "FAIL  KDF_BASELINE_MS is not recorded (run --record)" >&2; exit 1; }

check() { # returns 0 when every budget holds; prints one line per budget
  local res kdf search start ok=0
  res="$(measure)" || return 1
  kdf="$(get "$res" kdf_default_ms)"; search="$(get "$res" search_10k_ms)"; start="$(get "$res" startup_ms)"
  for v in "$kdf" "$search" "$start"; do [ -n "$v" ] || { echo "missing measurement" >&2; return 1; }; done
  within() { awk -v v="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(v >= lo && v <= hi) }'; }
  lo=$(awk -v b="$KDF_BASELINE_MS" -v p="$KDF_TOLERANCE_PCT" 'BEGIN { print b * (100 - p) / 100 }')
  hi=$(awk -v b="$KDF_BASELINE_MS" -v p="$KDF_TOLERANCE_PCT" 'BEGIN { print b * (100 + p) / 100 }')
  if within "$kdf" "$lo" "$hi"; then echo "ok    kdf_default   ${kdf} ms (allowed ${lo} to ${hi})"
  else echo "FAIL  kdf_default   ${kdf} ms (allowed ${lo} to ${hi})" >&2; ok=1; fi
  if within "$search" 0 "$SEARCH_10K_MAX_MS"; then echo "ok    search_10k    ${search} ms (max ${SEARCH_10K_MAX_MS})"
  else echo "FAIL  search_10k    ${search} ms (max ${SEARCH_10K_MAX_MS})" >&2; ok=1; fi
  if within "$start" 0 "$STARTUP_MAX_MS"; then echo "ok    startup       ${start} ms (max ${STARTUP_MAX_MS})"
  else echo "FAIL  startup       ${start} ms (max ${STARTUP_MAX_MS})" >&2; ok=1; fi
  return "$ok"
}

if check; then exit 0; fi
echo "bench: retrying once (a busy machine only makes runs slower)" >&2
check
