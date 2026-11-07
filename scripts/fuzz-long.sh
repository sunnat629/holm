#!/usr/bin/env bash
# Long fuzz run over every target in fuzz/fuzz_targets, one after the other, at the lowest
# CPU priority (nice -n 19).
#
#   scripts/fuzz-long.sh [minutes-per-target]     default 1440 (24 h per target), for pre-release
#
# Corpora are kept in fuzz/corpus/<target> (git-ignored) and grow between runs, so a later run
# starts where the last one stopped. Crashes, timeouts and out-of-memory inputs are saved by
# libFuzzer in fuzz/artifacts/<target>/ (git-ignored); the logs of this run go to
# fuzz/artifacts/long-<UTC time>/<target>.log. Any single allocation over 64 MiB counts as a
# crash, as in the ci-local fuzz gate. The script goes on to the next target after a crash, prints
# a summary at the end and exits 1 if anything crashed.
#
# A crash in holm-core or holm-crypto code is a release blocker: stop, keep the artifact file,
# and report it. Do not run this while scripts/ci-local.sh runs (both use fuzz/target).
set -uo pipefail
cd "$(dirname "$0")/.."

# Keep equal to FUZZ_NIGHTLY in scripts/ci-local.sh.
NIGHTLY="nightly-2026-10-12"
minutes="${1:-1440}"
case "$minutes" in "" | *[!0-9]* | 0) echo "usage: $0 [minutes-per-target]" >&2; exit 2 ;; esac

cargo "+$NIGHTLY" --version >/dev/null 2>&1 ||
  { echo "MISSING nightly toolchain. Install: rustup toolchain install $NIGHTLY --profile minimal" >&2; exit 2; }
cargo fuzz --version >/dev/null 2>&1 ||
  { echo "MISSING cargo-fuzz. Install: cargo install --locked cargo-fuzz --version 0.13.2" >&2; exit 2; }

stamp="$(date -u +%Y%m%dT%H%MZ)"
logdir="fuzz/artifacts/long-$stamp"
mkdir -p "$logdir"
targets="$(cd fuzz/fuzz_targets && ls ./*.rs 2>/dev/null | sed -E 's|^\./||; s|\.rs$||')"
[ -n "$targets" ] || { echo "fuzz-long: no targets found in fuzz/fuzz_targets" >&2; exit 2; }
echo "fuzz-long: $(echo "$targets" | wc -w | tr -d ' ') targets, $minutes min each, logs in $logdir"

bad=0
summary=""
for t in $targets; do
  mkdir -p "fuzz/corpus/$t"
  seeds=""
  if [ -d "fuzz/seeds/$t" ]; then seeds="fuzz/seeds/$t"; fi
  before="$(find "fuzz/artifacts/$t" -type f 2>/dev/null | wc -l | tr -d ' ')"
  echo "fuzz-long: $t start $(date -u +%H:%MZ)"
  # shellcheck disable=SC2086 # $seeds is empty or one path without spaces
  nice -n 19 cargo "+$NIGHTLY" fuzz run "$t" "fuzz/corpus/$t" $seeds -- \
    -max_total_time=$((minutes * 60)) -malloc_limit_mb=64 -print_final_stats=1 >"$logdir/$t.log" 2>&1
  rc=$?
  after="$(find "fuzz/artifacts/$t" -type f 2>/dev/null | wc -l | tr -d ' ')"
  execs="$(sed -n -E 's/^stat::number_of_executed_units: *([0-9]+)$/\1/p' "$logdir/$t.log" | tail -n 1)"
  cov="$(grep -E '^#[0-9]+.*(DONE|cov:)' "$logdir/$t.log" | tail -n 1 | sed -E 's/.*cov: ([0-9]+).*ft: ([0-9]+).*corp: ([0-9]+).*/cov=\1 ft=\2 corp=\3/')"
  new=$((after - before))
  if [ "$rc" -ne 0 ] || [ "$new" -gt 0 ]; then
    bad=1
    status="CRASH (exit $rc, $new new file(s) in fuzz/artifacts/$t)"
  else
    status="ok"
  fi
  line="$t: $status execs=${execs:-?} ${cov:-}"
  echo "fuzz-long: $line"
  summary="$summary$line
"
done

echo "---- fuzz-long summary ($minutes min per target) ----"
printf '%s' "$summary"
if [ "$bad" -ne 0 ]; then echo "fuzz-long: CRASHES FOUND. Keep fuzz/artifacts/ and report." >&2; exit 1; fi
echo "fuzz-long: no crashes"
