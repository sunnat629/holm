# Phase 4 manual check: the CLI clipboard and shell

The holm-cli tests (`cargo test -p holm-cli --locked`) drive every command through a
fake terminal and a fake clipboard. They can't see the real macOS pasteboard, a
clipboard manager, a real terminal waiting for Enter, or a shell that sits idle. This
list covers those. Run it once on a real Mac before the Phase 4 merge, and write down
who ran it, the date, the macOS version and the chip.

## Runs

| Run | Who | Date | macOS | Chip | Result |
|---|---|---|---|---|---|
| 1 | Implementer (agent, no screen) | 2026-10-18 | 26.4.1 (25E253) | Apple M3 Pro (arm64) | Automatic parts only: see below |
| 2 | Owner | | | | |

## Before you start

- Use a throwaway vault: set it once, print it, and pass the same value to every
  command below.

  ```
  V="$(mktemp -d)/Holm/holm.vault"; echo "$V"
  cargo build -p holm-cli --locked
  alias holm="$PWD/target/debug/holm --vault \"\$V\""
  ```
  If the alias gives trouble, type `./target/debug/holm --vault "$V"` in its place.
- Holm makes a real vault with `KdfParams::DEFAULT`, so `init` and every unlock take
  about a second each.
- Use only fake data, for example the login below.
- Have TextEdit.app open with an empty document to paste into.

## Run 1: what was checked without a person at the screen

The implementer had no one to paste or watch a clipboard manager, and running the
real-clipboard test would have replaced what was on the owner's clipboard, so it did
not touch the real pasteboard. These were checked from a terminal or by test instead:

- [x] `cargo build -p holm-cli --locked` builds `target/debug/holm`; `otool -L` shows it
  links AppKit (arboard's pasteboard).
- [x] `holm get abc --copy bogus` prints a usage error and exits 2 before any prompt.
- [x] Copy, wait, clear, with a fake clipboard (`tests/write_commands.rs`):
  `copy_waits_then_clears_only_if_unchanged` (the clear time passes, then "Clipboard
  cleared."; a clipboard changed meanwhile is left alone), `copy_enter_clears_now`,
  and `copy_phrase_asks_password_again`.
- [x] `no_command_output_holds_a_secret`: no command prints a copied or stored secret.
- [x] Every copy goes through `ConcealedClipboard::set`, which marks it
  `org.nspasteboard.ConcealedType` (arboard's `exclude_from_history`).
- [x] No network crates in the CLI: `cargo tree -p holm-cli -e normal --target
  aarch64-apple-darwin --locked` has no HTTP, TLS, socket or async runtime crate.
- [ ] Not run: `cargo test -p holm-platform --features clipboard --locked
  real_round_trip -- --ignored` (it replaces the clipboard). Run it in run 2.

## Run 2: steps for a person at the Mac

Setup

- [ ] `holm init` with a strong fake master password. It prints "Made a new vault."
- [ ] `holm add login --title "Example Mail" --username ada@example.com --url
  https://mail.example.com`, password `EXAMPLE-zq9-pass` twice. It prints
  `Added XXXXXXXX.`; that id is `REF` below.
- [ ] `cargo test -p holm-platform --features clipboard --locked real_round_trip --
  --ignored` → `1 passed`.

Copy and wait

- [ ] `holm get REF --copy password`, master password. It prints "Copied. Holm clears
  the clipboard in 30 seconds. Press Enter to clear it now." and does not print the
  password.
- [ ] Paste into TextEdit once: `EXAMPLE-zq9-pass` arrives.
- [ ] Wait without pressing anything. After about 30 s it prints "Clipboard
  cleared." and exits. Paste again: nothing arrives.
- [ ] If a clipboard-history tool is installed (Raycast, Alfred, Maccy, Paste), it did
  not keep the password. Tool and version: ______

Enter, Ctrl-C and a changed clipboard

- [ ] `holm get REF --copy password` again, then press Enter at once: "Clipboard
  cleared." at once, and a paste gives nothing.
- [ ] Again, and press Ctrl-C during the wait: the clipboard is cleared the same way.
- [ ] Again, and during the wait copy a word from TextEdit with Cmd+C. When the wait
  ends it prints "The clipboard changed since Holm copied to it, so Holm left it
  alone." and a paste gives your word.
- [ ] While a copy waits, `holm list` in a second terminal opens the vault (the folder
  lock was released before the wait).

Other copies

- [ ] `holm gen --copy`: no password is printed; a paste gives a new password; it
  clears after 30 s like above.
- [ ] `holm add phrase --title "Example Wallet"` with a fake phrase, then
  `holm get REF2 --copy phrase`: it asks "Master password again: " before copying.

After

- [ ] The terminal scrollback shows no password, phrase or master password.
- [ ] Activity Monitor, Network tab: `holm` sent and received 0 bytes.

`holm shell`

- [ ] `holm shell`, master password. It prints "Type help to see the commands, and
  exit to leave." and the prompt `holm> `. `list` shows the items; no password is
  asked again.
- [ ] `lock`: it prints "Locked." and the prompt becomes `holm (locked)> `. `list`
  prints "The vault is locked. Type unlock to open it." `unlock`, master password:
  back to `holm> `.
- [ ] `get REF --copy password`: "Copied. Holm clears the clipboard in 30 seconds."
  and the prompt is back at once. Paste gives the password. About 30 s later, without
  typing, it prints "Clipboard cleared." and a paste gives nothing.
- [ ] Idle lock on a real terminal: leave the shell untouched for 5 minutes (the
  default auto-lock time). It prints "Locked after 5 minutes without use." by itself,
  and the prompt becomes `holm (locked)> `.
- [ ] Idle lock at a command's own prompt: type `add note --title Test`, then leave the
  hidden `Note: ` prompt for 5 minutes. It prints "Locked after 5 minutes without use."
  by itself, the prompt becomes `holm (locked)> `, and no note was added.
- [ ] Ctrl-C at the prompt: the shell ends with "Locked.", and typing in the same
  terminal echoes normally (echo restored).
- [ ] While a shell runs, `holm list` in a second terminal says Holm is already open
  on this vault; after `exit` it opens.
- [ ] `export` inside the shell asks "Type export to continue: " and then "Master
  password again: ". Delete the file afterwards.
- [ ] The scrollback shows no password typed at a hidden prompt, and there is no
  history: the up arrow does not bring back a line.

Clean up: `rm -r "$(dirname "$V")"`, then copy some plain text so nothing from the run
stays on the clipboard.

Sign off: ______ (name, date, macOS version, chip)
