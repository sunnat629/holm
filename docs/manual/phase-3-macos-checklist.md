# Phase 3 manual check on macOS

The headless tests (`cargo test -p holm-gui --locked`) drive the whole app through
egui_kittest. They can't see the real window, the real pasteboard, a clipboard
manager, the Dock or Activity Monitor. This list covers those. Run it once on a real
Mac before the Phase 3 merge, and write down who ran it, the date, the macOS version
and the chip.

## Runs

| Run | Who | Date | macOS | Chip | Result |
|---|---|---|---|---|---|
| 1 | Implementer (agent, no screen) | 2026-10-18 | 26.4.1 (25E253) | Apple M3 Pro (arm64) | Automatic parts only: see below |
| 2 | Owner | | | | |

## Before you start

- The default vault folder is `~/Library/Application Support/Holm`. On the
  implementer's Mac it already existed on 2026-10-18 with mode `drwxr-xr-x` (0755), an
  older `harbor.vault` (from the earlier project, mode 0644) and an empty `holm.lock`.
  Holm accepts a 0755 folder (it refuses only a folder that group or others can write,
  and never changes a folder's mode), so the folder check at the end would show
  `drwxr-xr-x` and the extra file. Before run 2, either move `harbor.vault` out and run
  `chmod 700 ~/Library/Application\ Support/Holm`, or run every step below with
  `-- --vault "$(mktemp -d)/Holm/holm.vault"` and check that folder instead.
- Holm makes a real vault with `KdfParams::DEFAULT`, so create and unlock take about a
  second each.
- Use only fake data, for example the login below.

## Run 1: what was checked without a person at the screen

The implementer could not watch a window, so it did not start the app. These were
checked from a terminal or by test instead:

- [x] `cargo build -p holm-gui --locked` builds the binary.
- [x] `holm-gui --bogus` prints `usage: holm-gui [--vault <path>]` and exits 2 without
  opening a window.
- [x] The window title is set in one place, `main.rs`
  (`ViewportBuilder::with_title("Holm")`), and no code changes it.
- [x] The whole flow runs headless: `tests/walking_skeleton.rs`
  (`walking_skeleton_create_add_lock_unlock_see_item`: create, add, copy, lock, a new
  app shows Unlock, a wrong password, the right one, the item is listed and shows its
  username).
- [x] On disk after that flow (`no_plaintext_on_disk`): the folder `Holm` holds only
  `holm.vault` and `holm.lock`; folder 0700, both files 0600; `holm.lock` is empty;
  neither file contains the title, username, URL host, item password or master
  password.
- [x] No network crates in the app: `cargo tree -p holm-gui -e normal --target
  aarch64-apple-darwin --locked` has no HTTP, TLS, socket or async runtime crate.
- [x] The eframe feature list: `cargo tree -p holm-gui -e features --target
  aarch64-apple-darwin --locked` shows none of `default_fonts`, `persistence`,
  `clipboard`, `wgpu`, `web_screen_reader`, `links`, `system_fonts`, and winit's own
  `default` is off. (winit's `wayland` and `x11` features show, turned on by
  `accesskit_winit`'s defaults; they are target-gated and compile nothing on macOS.
  Known since Task 1.)
- [x] No `~/Library/Saved Application State` entry for Holm, after the app had been
  run on the default path earlier the same day (the `holm.lock` there is dated
  2026-10-18 13:38).
- [x] `system_clipboard_marks_concealed` run by hand:
  `cargo test -p holm-gui --locked --test clipboard -- --ignored
  system_clipboard_marks_concealed` → `1 passed`. The pasteboard carried
  `org.nspasteboard.ConcealedType` and read back the fake value. Plain text was put
  back on the clipboard afterwards.

## Run 2: steps for a person at the Mac

Start: `cargo run -p holm-gui --locked` (default path, `KdfParams::DEFAULT`).

Create

- [ ] The window opens on the create screen. The title bar says "Holm".
- [ ] Typing a master password moves the strength meter (four segments and a word).
- [ ] A weak password, such as `password1234` in both fields, leaves "Create vault"
  disabled.
- [ ] A strong password in both fields still needs the box "I understand Holm can't
  recover my vault" before "Create vault" turns on.
- [ ] "Create vault" opens the empty vault.

Add and copy

- [ ] "New login": title `Example Mail`, username `ada@example.com`, web address
  `https://mail.example.com`, password `EXAMPLE-zq9-pass`. Save. The row shows in the
  list.
- [ ] "Copy" shows the line that Holm doesn't clear the clipboard yet.
- [ ] Paste into TextEdit.app: the password arrives.
- [ ] If a clipboard-history tool is installed (Raycast, Alfred, Maccy, Paste), it did
  not keep the password. Tool and version: ______
- [ ] Copy some plain text afterwards, so the password leaves the clipboard.
- [ ] "Reveal" shows the password, then hides it by itself after
  `REHIDE_PASSWORD_SECS` (30 s by default). It also hides when another window takes
  focus.

Lock and unlock

- [ ] "Lock" goes to the unlock screen with "Locked."
- [ ] A wrong password three times: the third try is followed by a live wait ("Too
  many tries. Try again in N s.") and the Unlock button stays disabled until it ends.
- [ ] The right password opens the vault and the login is there.
- [ ] Minimise the window (yellow button or Cmd+M), bring it back: it is locked, with
  "Locked when the window was minimised."
- [ ] Unlock and leave Holm alone for the auto-lock time from the settings (5 minutes
  by default). The amber line "Locking in N s because of no activity." shows 30 s
  before, then it locks with "Locked after 5 minutes without use."

One window only

- [ ] With Holm open, start a second copy in another terminal
  (`cargo run -p holm-gui --locked`). It shows "Holm is already open. Close the other
  window first." and no password field.
- [ ] Close the second window, then the first.

After quitting

- [ ] `ls -la ~/Library/Application\ Support/Holm` shows only `holm.vault` and
  `holm.lock`, the folder `drwx------`, both files `-rw-------` (see "Before you
  start").
- [ ] `ls ~/Library/Saved\ Application\ State | grep -i holm` prints nothing.
- [ ] The title bar said "Holm" the whole time, never an item title.
- [ ] Activity Monitor, Network tab: Holm (`holm-gui`) sent and received 0 bytes.

Sign off: ______ (name, date, macOS version, chip)
