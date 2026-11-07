#!/usr/bin/env bash
# BEFORE baseline, without changing the release profile or any crate source.
# Usage: scripts/measure-macos.sh [/tmp/holm-measure.md]
# Needs macOS, the installed Rust toolchain/dependencies, and Python 3 (stdlib only).
# Run from a graphical terminal with Accessibility permission for unlock measurements.
set +x
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd -P)"
report="${1:-/tmp/holm-measure.md}"
if [ "$#" -gt 1 ] || [ "$(uname -s)" != Darwin ]; then
  echo 'Usage: scripts/measure-macos.sh [report.md outside the repository] (macOS only)' >&2
  exit 2
fi
command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 2; }

# Resolve symlinks before accepting an output path. Do not write to personal folders.
report="$(python3 - "$root" "$report" <<'PY'
import os, sys
root, requested = sys.argv[1:]
dest = os.path.realpath(os.path.abspath(requested))
for forbidden in [root] + [os.path.expanduser('~/' + p) for p in ('Library', 'Documents', 'Desktop')]:
    forbidden = os.path.realpath(forbidden)
    if os.path.commonpath([dest, forbidden]) == forbidden:
        sys.exit('Report must be outside the repository and personal folders.')
if os.path.islink(requested) or not os.path.isdir(os.path.dirname(dest)):
    sys.exit('Report must have an existing parent directory and must not be a symlink.')
if os.path.exists(dest) and (not os.path.isfile(dest) or os.stat(dest).st_nlink != 1):
    sys.exit('Report must be a regular file with one link.')
print(dest)
PY
)"

work="$(mktemp -d /tmp/holm-measure.XXXXXX)"
worker_pid=''
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
  trap - EXIT INT TERM HUP
  if [ -n "$worker_pid" ]; then
    kill -TERM "$worker_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Keep all fixtures, private transcripts, helper files, and bundle scratch files in /tmp.
export TMPDIR="$work/"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$root/target"
unset CARGO_BUILD_TARGET

cat >"$work/measure.py" <<'PY'
import csv
import ctypes as C
import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import statistics
import subprocess
import sys
import threading
import time

ROOT, REPORT, WORK = map(Path, sys.argv[1:])
# The holm-cli package names its executable `holm` in [[bin]].
CLI, GUI = ROOT / 'target/release/holm', ROOT / 'target/release/holm-gui'
PASSWORD = 'measure-test-pw-123'  # Public, disposable fixture password. Never log it.
ACCESS = 'blocked: needs Accessibility permission for the terminal'
children = set()
pty_children = set()
rows, notes = [], []
SAMPLE_INTERVAL = 0.100
OBSERVE_SECONDS = 10.0


def progress(message):
    print(message, file=sys.stderr, flush=True)


def spawn(args, **kw):
    proc = subprocess.Popen([str(a) for a in args], cwd=ROOT, **kw)
    children.add(proc)
    return proc


def stop(proc):
    # Only an unreaped child PID owned by this run can reach kill(). Never match a name.
    if proc.poll() is None:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait()
        except ProcessLookupError:
            proc.wait()
    children.discard(proc)


def run(args, timeout=30):
    proc = spawn(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode(errors='replace'), err.decode(errors='replace')
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout'
    finally:
        stop(proc)


def logged(args, name):
    with (WORK / name).open('wb') as log:
        proc = spawn(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            return proc.wait()
        finally:
            stop(proc)


def row(label, amount='unavailable', categories='n/a', status=''):
    rows.append([label, amount, categories, status])


def amount(value):
    return f'{value / 1048576:.2f} MiB ({value:,} B)'


def stop_pty(pid):
    if pid in pty_children:
        try:
            # WNOHANG reaps an exited child before any signal can target a reused PID.
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        pty_children.discard(pid)


def cli(vault, args, prompts, expected=None):
    # Holm reads /dev/tty, never stdin, environment variables, or password flags.
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execv(str(CLI), [str(CLI), '--vault', str(vault), *map(str, args)])
    pty_children.add(pid)
    transcript = bytearray()
    pending = bytearray()
    step = 0
    deadline = time.monotonic() + 90
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    chunk = b''
                if not chunk:
                    _, status = os.waitpid(pid, 0)
                    pty_children.discard(pid)
                    break
                transcript.extend(chunk)
                pending.extend(chunk)
                if step < len(prompts) and prompts[step][0] in pending:
                    marker, reply = prompts[step]
                    del pending[:pending.index(marker) + len(marker)]
                    os.write(fd, reply.encode() + b'\r')
                    step += 1
        else:
            raise RuntimeError('CLI prompt timed out')
        if b'This master password is too easy to guess.' in transcript:
            raise RuntimeError('fixture password rejected by strength policy')
        if b'Holm needs a terminal to ask for the password.' in transcript:
            raise RuntimeError('CLI cannot access its controlling terminal in this session')
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0 or step != len(prompts):
            raise RuntimeError('CLI fixture command failed')
        if expected is not None and expected not in transcript:
            raise RuntimeError('CLI did not confirm the expected fixture count')
        return bytes(transcript)
    finally:
        stop_pty(pid)
        os.close(fd)
        # Do not persist or print the PTY transcript, even on errors.
        transcript[:] = b'\0' * len(transcript)
        pending[:] = b'\0' * len(pending)


def fixtures():
    if run([CLI, '--help'])[0]:
        raise RuntimeError('release CLI help failed')
    for name, count in [('small', 5), ('large', 1000)]:
        folder = WORK / name
        folder.mkdir(mode=0o700)
        vault, source = folder / 'holm.vault', folder / 'items.csv'
        with source.open('w', newline='') as out:
            writer = csv.writer(out)
            writer.writerow(['title', 'username', 'password', 'type'])
            for i in range(count):
                writer.writerow([f'Measure {i:04d}', f'fixture-{i:04d}', PASSWORD, 'login'])
        cli(vault, ['init'], [(b'New master password: ', PASSWORD),
                             (b'Repeat the master password: ', PASSWORD)], b'Made a new vault.')
        cli(vault, ['import', source, '--format', 'csv'],
            [(b'Master password: ', PASSWORD), (f'Type import to add {count} items: '.encode(), 'import')],
            f'Imported {count} items.'.encode())
        listing = cli(vault, ['list'], [(b'Master password: ', PASSWORD)])
        if len(re.findall(rb'(?:^|[\r\n])[0-9a-f]{8}\tlogin\tMeasure [0-9]{4}\t', listing)) != count:
            raise RuntimeError('CLI list did not verify the fixture count')
        source.unlink()
    notes.append('Release CLI imports and a fresh CLI list verified 5 and 1,000 items. Vaults are format v2 (header, index and per-item records), so the unlock, memory and list rows measure the v2 read path. Default Argon2id: 256 MiB, 3 passes, 1 lane.')


class NativeUI:
    # Window metadata and AX labels only. No screenshots, secret values, or UI dumps.
    def __init__(self):
        self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.cg = C.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')
        self.ax = C.CDLL('/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices')
        def bind(lib, name, result, args):
            f = getattr(lib, name)
            f.restype, f.argtypes = result, args
            return f
        P, L = C.c_void_p, C.c_long
        self.release = bind(self.cf, 'CFRelease', None, [P])
        self.string = bind(self.cf, 'CFStringCreateWithCString', P, [P, C.c_char_p, C.c_uint32])
        self.to_string = bind(self.cf, 'CFStringGetCString', C.c_bool, [P, C.c_char_p, L, C.c_uint32])
        self.type_id = bind(self.cf, 'CFGetTypeID', C.c_ulong, [P])
        self.string_id = bind(self.cf, 'CFStringGetTypeID', C.c_ulong, [])()
        self.count = bind(self.cf, 'CFArrayGetCount', L, [P])
        self.at = bind(self.cf, 'CFArrayGetValueAtIndex', P, [P, L])
        self.get = bind(self.cf, 'CFDictionaryGetValue', P, [P, P])
        self.number = bind(self.cf, 'CFNumberGetValue', C.c_bool, [P, C.c_int, P])
        self.windows = bind(self.cg, 'CGWindowListCopyWindowInfo', P, [C.c_uint32, C.c_uint32])
        self.app = bind(self.ax, 'AXUIElementCreateApplication', P, [C.c_int])
        self.attr = bind(self.ax, 'AXUIElementCopyAttributeValue', C.c_int, [P, P, C.POINTER(P)])
        self.trusted = bind(self.ax, 'AXIsProcessTrusted', C.c_bool, [])
        self.keys = {}

    def key(self, text):
        if text not in self.keys:
            self.keys[text] = self.string(None, text.encode(), 0x08000100)
        return self.keys[text]

    def integer(self, dictionary, key):
        obj = self.get(dictionary, self.key(key))
        number = C.c_int64()
        if obj:
            self.number(obj, 4, C.byref(number))
        return number.value

    def window(self, pid):
        windows = self.windows(1 | 16, 0)
        if not windows:
            return False
        try:
            return any(self.integer(self.at(windows, i), 'kCGWindowOwnerPID') == pid
                       and self.integer(self.at(windows, i), 'kCGWindowLayer') == 0
                       for i in range(self.count(windows)))
        finally:
            self.release(windows)

    def attribute(self, node, key):
        value = C.c_void_p()
        if self.attr(node, self.key(key), C.byref(value)) != 0:
            return None
        return value.value

    def unlocked(self, pid):
        if not self.trusted():
            return False
        labels = set()
        visited = [0]
        def walk(node, depth=0):
            visited[0] += 1
            if depth > 20 or visited[0] > 3000:
                return
            for name in ('AXTitle', 'AXDescription'):
                value = self.attribute(node, name)
                if value:
                    try:
                        if self.type_id(value) == self.string_id:
                            buffer = C.create_string_buffer(256)
                            if self.to_string(value, buffer, len(buffer), 0x08000100):
                                labels.add(buffer.value.decode(errors='replace'))
                    finally:
                        self.release(value)
            children = self.attribute(node, 'AXChildren')
            if children:
                try:
                    for i in range(self.count(children)):
                        walk(self.at(children, i), depth + 1)
                finally:
                    self.release(children)
        app = self.app(pid)
        try:
            wins = self.attribute(app, 'AXWindows')
            if wins:
                try:
                    for i in range(self.count(wins)):
                        walk(self.at(wins, i))
                finally:
                    self.release(wins)
            if os.environ.get('MEASURE_DEBUG'):
                print('AX labels:', sorted(labels)[:15], 'trusted', file=sys.stderr)
            return 'Lock' in labels and ('Search' in labels or 'Measure 0000' in labels)
        finally:
            self.release(app)


def apple(pid, typing=False):
    # No password in argv or the environment. osascript consumes its program on stdin.
    action = ('keystroke ' + json.dumps(PASSWORD) + '\nkey code 36\nreturn "sent"') if typing else '''
set frontmost to true
repeat 40 times
    if frontmost then exit repeat
    delay 0.05
end repeat
if not frontmost then error "Could not focus the measurement app"
delay 0.5
return "focused"
'''
    source = '''on run argv
tell application "System Events"
    set targetProcess to first application process whose unix id is (item 1 of argv as integer)
    tell targetProcess
''' + ('if not frontmost then error "Measurement app lost focus"\n' if typing else '') + action + '''
    end tell
end tell
end run
'''
    proc = spawn(['/usr/bin/osascript', '-', str(pid)], stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(source.encode(), timeout=15)
        if proc.returncode == 0:
            return None
        error = err.decode(errors='replace').lower()
        if any(token in error for token in ('1002', '1743', '25211', 'not allowed', 'not authorized', 'assistive', 'accessibility', 'permission')):
            return ACCESS
        if '-10827' in error or '-600' in error:
            return 'blocked: System Events unavailable in this session'
        if os.environ.get('MEASURE_DEBUG') and not typing:
            print('osascript focus error:', error.strip()[:300], file=sys.stderr)
        return 'blocked: could not focus or type into the measurement app'
    except subprocess.TimeoutExpired:
        return 'blocked: System Events timed out'
    finally:
        stop(proc)


def parse_size(text):
    match = re.match(r'([\d,]+(?:\.\d+)?)\s*([KMGT]?(?:i?B)?|bytes)?', text.strip(), re.I)
    if not match:
        raise ValueError('unrecognized size')
    unit = (match[2] or '').upper()
    power = 'KMGT'.find(unit[:1]) + 1 if unit[:1] in ('K', 'M', 'G', 'T') else 0
    return round(float(match[1].replace(',', '')) * 1024 ** power)


def footprint(pid, categories=True):
    args = ['/usr/bin/footprint', '-f', 'bytes']
    if not categories:
        args.append('--noCategories')
    code, out, err = run([*args, str(pid)], timeout=10)
    if code:
        reason = 'blocked: footprint process inspection unavailable'
        return {'error': reason}
    match = re.search(r'\bFootprint:\s*([\d,.]+\s*(?:[KMGT]?B))', out, re.I)
    if not match:
        return {'error': 'unavailable: footprint total format not recognized'}
    total = parse_size(match[1])
    top = []
    for line in out.splitlines():
        m = re.match(r'^\s*([\d,.]+\s*[KMGT]?B)\s+[\d,.]+\s*[KMGT]?B\s+[\d,.]+\s*[KMGT]?B\s+\d+\s+(.+?)\s*$', line, re.I)
        if not m:
            continue
        name = m[2]
        if name.upper().startswith('TOTAL'):
            continue
        # Categories can include file paths. Report only a basename, never a home path.
        if '/' in name:
            name = name.rsplit('/', 1)[-1]
        name = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[redacted]', name)
        top.append((parse_size(m[1]), name))
    top.sort(reverse=True)
    return {'total': total, 'top': top[:5]}


def memory_row(label, sample, status=''):
    if 'error' in sample:
        row(label, sample['error'], sample['error'], status)
    else:
        top = '; '.join(f'{name}: {amount(size)}' for size, name in sample['top'])
        row(label, amount(sample['total']), top or 'unavailable: category format not recognized', status)


def launch(name, ui):
    log = (WORK / (name + '-gui.log')).open('wb')
    try:
        proc = spawn([GUI, '--vault', WORK / name / 'holm.vault'],
                     stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    finally:
        log.close()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return proc, False, 'blocked: GUI exited before its window opened'
        if ui.window(proc.pid):
            time.sleep(3)
            return proc, True, ''
        time.sleep(0.1)
    return proc, False, 'blocked: could not verify a GUI window in this session'


def unlock(proc, ui, label, before):
    blocked = apple(proc.pid)
    if blocked:
        row(label + ' before unlock', before.get('error', amount(before.get('total', 0))), 'n/a', blocked)
        row(label + ' unlock peak', blocked, blocked, blocked)
        row(label + ' after unlock + 3 s', blocked, blocked, blocked)
        return blocked
    memory_row(label + ' before unlock', before)
    samples, stamps, series = [], [], []
    halt = threading.Event()
    def sample_loop():
        due = time.monotonic()
        while not halt.is_set():
            start = time.monotonic()
            sample = footprint(proc.pid, categories=False)
            stamps.append(start)
            if 'total' in sample:
                samples.append(sample['total'])
                series.append((start, sample['total']))
            due += SAMPLE_INTERVAL
            # Never overlap footprint processes; expose overruns in the report.
            if due < time.monotonic():
                due = time.monotonic()
            halt.wait(max(0, due - time.monotonic()))
    sampler = threading.Thread(target=sample_loop)
    sampler.start()
    started = time.monotonic()
    confirmed, elapsed = False, None
    try:
        blocked = apple(proc.pid, typing=True)
        if not blocked:
            deadline = time.monotonic() + OBSERVE_SECONDS
            while time.monotonic() < deadline and proc.poll() is None:
                if ui.unlocked(proc.pid):
                    confirmed = True
                    elapsed = time.monotonic() - started
                    break
                time.sleep(0.1)
            if not confirmed:
                elapsed = time.monotonic() - started
    finally:
        halt.set()
        sampler.join()
    if blocked:
        row(label + ' unlock peak', blocked, blocked, blocked)
        row(label + ' after unlock + 3 s', blocked, blocked, blocked)
        return blocked
    if confirmed:
        timing = f'<= {elapsed:.3f} s to AX item-list controls (includes osascript dispatch)'
    else:
        timing = f'unverified; {elapsed:.3f} s sleep-bounded observation, not a proven unlock time'
    # Argon2 phase estimate from the footprint series: first sample 20 MiB above the
    # pre-unlock footprint until the first later sample back under it (100 ms steps).
    base = before.get('total', 0) if 'total' in before else 0
    hi = [t for t, v in series if v > base + 20 * 2**20]
    if hi and base:
        end = next((t for t, v in series if t > hi[0] and v < base + 20 * 2**20), series[-1][0])
        timing += f'; Argon2 phase (footprint +20 MiB) {end - hi[0]:.2f} s'
    peak = amount(max(samples)) if samples else 'unavailable: no valid footprint samples'
    row(label + ' unlock peak (100 ms target)', peak, 'totals only during sampling', timing)
    if len(stamps) > 1:
        gaps = [(b - a) * 1000 for a, b in zip(stamps, stamps[1:])]
        notes.append(f'{label}: {len(samples)} valid samples; actual interval median {statistics.median(gaps):.1f} ms, max {max(gaps):.1f} ms. Peak is sampled and includes dispatch/detection overhead.')
    time.sleep(3)
    after = footprint(proc.pid)
    memory_row(label + ' after unlock + 3 s', after, timing)
    if not confirmed:
        notes.append(f'{label}: if the window is occluded or on another Space, winit stops redrawing and the unlock screen stays in the accessibility tree; run with the Holm window visible on the current Space.')
        notes.append(f'{label}: item-list visibility could not be confirmed. The after value is only an attempted-unlock observation; footprint growth alone does not prove success.')
    return None


def measure():
    progress('Creating and verifying disposable CLI vaults under /tmp...')
    try:
        fixtures()
    except (OSError, RuntimeError) as exc:
        reason = ('blocked: PTY unavailable in this session' if isinstance(exc, PermissionError)
                  else 'blocked: release CLI fixture setup or count verification failed')
        if isinstance(exc, RuntimeError):
            # Our own fixed error strings, never the transcript or a library exception.
            reason = 'blocked: ' + str(exc)
        for label in ('Locked, small vault', 'Unlocked, small vault', 'Unlocked, 1,000 items'):
            row(label, reason, reason, reason)
        return
    ui = NativeUI()
    blocked = None
    for name, label in [('small', 'Small vault (5 items)'), ('large', 'Large vault (1,000 items)')]:
        if blocked:
            row(label + ' before unlock', blocked, blocked, blocked)
            row(label + ' unlock peak', blocked, blocked, blocked)
            row(label + ' after unlock + 3 s', blocked, blocked, blocked)
            continue
        progress('Measuring ' + label + '...')
        proc, visible, problem = launch(name, ui)
        try:
            before = footprint(proc.pid) if proc.poll() is None else {'error': problem}
            if name == 'small':
                memory_row('Locked, small vault', before, 'window observed; settled 3 s' if visible else problem)
            if visible:
                blocked = unlock(proc, ui, label, before)
            else:
                blocked = problem
                row(label + ' unlock peak', blocked, blocked, blocked)
                row(label + ' after unlock + 3 s', blocked, blocked, blocked)
        finally:
            stop(proc)
    if blocked:
        notes.append(blocked + '. No security settings were changed.')


def main():
    _, sha, _ = run(['git', 'rev-parse', '--short', 'HEAD'])
    notes.append('BEFORE baseline at ' + sha.strip() + '. Release profile is unchanged; this script adds no LTO or optimization flags.')
    progress('Building release GUI and CLI offline in target/...')
    code = logged(['cargo', 'build', '--release', '--locked', '-p', 'holm-gui', '-p', 'holm-cli'], 'build.log')
    if code:
        row('Release build', 'failed', 'n/a', 'offline build failed; no stale binaries measured')
        for label in ('Locked, small vault', 'Unlocked, small vault', 'Unlocked, 1,000 items', 'Holm.app size'):
            row(label, 'blocked: build failed', 'n/a', 'blocked: build failed')
        return
    row('Release build', 'passed', 'n/a', 'offline; default target/; no profile edits')
    measure()
    progress('Building the local app bundle offline (no DMG)...')
    code = logged(['bash', 'scripts/bundle-macos.sh'], 'bundle.log')
    if code:
        log = (WORK / 'bundle.log').read_text(errors='replace').lower()
        reason = 'bundle script failed'
        for marker, explanation in [('invalid iconset', 'iconutil rejected the generated iconset'),
                                    ('operation not permitted', 'bundle step denied by this session'),
                                    ('leaks the builder path', 'bundle path-remapping check failed')]:
            if marker in log:
                reason = explanation
                break
        app = ROOT / 'target/bundle/Holm.app'
        if app.is_dir():
            status, out, _ = run(['du', '-sk', app])
            row('Holm.app (du -sk, incomplete)', out.split()[0] + ' KiB' if status == 0 else 'unavailable',
                'n/a', 'blocked: ' + reason + '; not a finished app bundle')
            binary = app / 'Contents/MacOS/Holm'
            if binary.is_file():
                row('Bundled Holm binary (incomplete bundle)', amount(binary.stat().st_size))
        else:
            row('Holm.app (du -sk)', 'blocked: ' + reason, 'n/a', 'bundle unavailable')
    else:
        app = ROOT / 'target/bundle/Holm.app'
        status, out, _ = run(['du', '-sk', app])
        row('Holm.app (du -sk)', out.split()[0] + ' KiB' if status == 0 else 'unavailable')
        row('Bundled Holm binary', amount((app / 'Contents/MacOS/Holm').stat().st_size))
    row('Release holm-gui binary', amount(GUI.stat().st_size))
    row('Release holm CLI binary', amount(CLI.stat().st_size))
    notes.append('Bundle uses the existing bundle script and its separate target/bundle-build cache with path remapping. GUI memory measurements use target/release/holm-gui.')


def interrupted(signum, frame):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGHUP, interrupted)
exit_code = 0
try:
    main()
except KeyboardInterrupt:
    row('Run', 'interrupted', 'n/a', 'partial results only')
    exit_code = 130
except Exception:
    # Never dump an exception, subprocess output, password, key, or UI content.
    row('Run', 'failed', 'n/a', 'measurement tool failed; partial results only')
    exit_code = 1
finally:
    for proc in list(children):
        stop(proc)
    for pid in list(pty_children):
        stop_pty(pid)

def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')

text = '| Measurement | Footprint / size | Top 5 categories by dirty bytes | Unlock time / status |\n'
text += '|---|---|---|---|\n'
text += '\n'.join('| ' + ' | '.join(map(cell, values)) + ' |' for values in rows) + '\n'
text += '\n' + '\n\n'.join(notes) + '\n'
text += '\nOnly this run\'s child PIDs are stopped. Temporary vaults and helper files are removed by the shell EXIT trap.\n'
fd = os.open(REPORT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as out:
    out.write(text)
print(text, end='', flush=True)
sys.exit(exit_code)
PY

python3 "$work/measure.py" "$root" "$report" "$work" &
worker_pid=$!
status=0
wait "$worker_pid" || status=$?
worker_pid=''
exit "$status"
