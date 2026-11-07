#!/usr/bin/env bash
# Phase B compat check: an OLD Holm CLI must refuse a v2 vault and leave it byte-identical.
# Builds the old CLI from a git ref in a temp worktree (removed on exit), then runs
# `holm --vault COPY list` on crates/holm-core/tests/vectors/golden-v2.vault through a pty
# (the CLI reads the password only from /dev/tty). Expected: non-zero exit, the old
# "isn't a Holm vault" message (old binaries do not know format version 2, so they cannot
# say "newer version"), and an unchanged file.
# Usage: scripts/compat-old-binary.sh [REF]   REF defaults to the newest v0.1.* tag, else the pinned
# commit OLD_MAIN_FALLBACK (the last main before Phase B, which cannot read v2). origin/main is
# no longer old: it contains Phase B.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(pwd -P)"
ref="${1:-}"
if [ -z "$ref" ]; then
  ref="$(git tag --list 'v0.1.*' --sort=-v:refname | head -n 1)"
  [ -n "$ref" ] || ref="7f751d88e35c9b27aa5a2a678d2bfab00534befe" # OLD_MAIN_FALLBACK: merge of perf/phase-a, no format v2
fi
git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "FAIL  compat: unknown ref $ref"; exit 1; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/holm-compat.XXXXXX")"
wt="$tmp/old"
cleanup() {
  git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

git worktree add --detach "$wt" "$ref" >/dev/null 2>&1
echo "NOTE  compat: building old CLI from $ref"
(cd "$wt" && nice -n 19 cargo build --release -p holm-cli --locked --offline -j2 >/dev/null)
bin="$wt/target/release/holm"
[ -x "$bin" ] || { echo "FAIL  compat: old binary missing"; exit 1; }

vault="$tmp/golden-v2.vault"
cp "$root/crates/holm-core/tests/vectors/golden-v2.vault" "$vault"
before="$(shasum -a 256 "$vault" | cut -d' ' -f1)"

set +e
out="$(python3 -I - "$bin" "$vault" <<'PY'
import os, pty, select, sys
binary, vault = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execv(binary, [binary, "--vault", vault, "list"])
buf, sent = b"", False
while True:
    r, _, _ = select.select([fd], [], [], 20)
    if not r:
        break
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
    if not sent and b"password" in buf.lower():
        os.write(fd, "caf\u00e9 golden v2\n".encode())  # public golden-vector password
        sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(buf.decode("utf-8", "replace"))
sys.exit(os.waitstatus_to_exitcode(status))
PY
)"
code=$?
set -e

after="$(shasum -a 256 "$vault" | cut -d' ' -f1)"
[ "$before" = "$after" ] || { echo "FAIL  compat: old binary changed the v2 file"; exit 1; }
[ "$code" -ne 0 ] || { echo "FAIL  compat: old binary exited 0 on a v2 file"; exit 1; }
case "$out" in
  *"isn't a Holm vault"*|*"newer version"*|*"unsupported"*) ;;
  *) echo "FAIL  compat: unexpected old-binary output"; exit 1 ;;
esac
echo "PASS  compat: $ref refuses golden-v2.vault (exit $code) and leaves it unchanged"
