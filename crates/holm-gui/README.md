# holm-gui

Holm's desktop app, built on egui (eframe 0.37, `glow` renderer). Phase 3 is a walking
skeleton for macOS: create a vault, unlock it, list logins, add, edit and view a login,
copy its password, and lock by hand, when idle or when the window is minimised.

The app reaches the vault only through `holm_core::Session<holm_platform::FsStore>`.
It never reads the vault file itself. Create and unlock run Argon2 on a worker thread
so the window keeps drawing.

## Run it

```sh
cargo run -p holm-gui --locked
```

The vault lives at `~/Library/Application Support/Holm/holm.vault`. Holm creates the
`Holm` folder (mode 0700) if it is missing and refuses a folder that group or others can
write. Next to the vault sits `holm.lock`, an empty file that stops a second Holm
opening the same vault.

For manual testing, point it at another vault with `--vault`:

```sh
cargo run -p holm-gui --locked -- --vault "$(mktemp -d)/Holm/holm.vault"
```

The parent folder must exist; Holm creates only the last folder. Any other argument
prints the usage line and exits with code 2.

On Linux and Windows the crate builds, but the binary only prints `Holm's window runs on
macOS only for now.` and exits 1.

## Test it

```sh
cargo test -p holm-gui --locked
```

The tests run the whole app headless with `egui_kittest`, a fake clock, a fake
clipboard, a temporary vault and `KdfParams::FLOOR`. `tests/walking_skeleton.rs` is the
end-to-end flow and the on-disk check. One test touches the real pasteboard and is
ignored by default; run it by hand:

```sh
cargo test -p holm-gui --locked --test clipboard -- --ignored system_clipboard_marks_concealed
```

It replaces what is on your clipboard. The steps a person must check at a real Mac are
in [`docs/manual/phase-3-macos-checklist.md`](../../docs/manual/phase-3-macos-checklist.md).

## Known gaps in Phase 3

Security gaps in memory are listed in [`docs/CRYPTO.md`](../../docs/CRYPTO.md) under
"The macOS app (Phase 3)". In short:

- A copied password stays on the clipboard until something else is copied. Holm
  doesn't clear it yet, and macOS Universal Clipboard (Handoff) can send it to your
  other Apple devices. The Copy button says so. Phase 5.
- Holm doesn't turn on macOS Secure Event Input while a password field has focus, so
  other apps with input-monitoring permission can see keystrokes. Phase 5.
- The vault folder check looks at its mode only, not its owner or its ACL. Phase 5.
- `holm.lock` is opened without `O_NOFOLLOW`. It is checked with `lstat` before and
  after the open, but a symlink swapped in between could make Holm create an empty
  file somewhere else before it refuses. Phase 5.
- On exFAT and FAT volumes, creating a new vault is not crash-atomic: a crash at the
  wrong moment can leave a short vault file. Phase 5.
- Nothing compiles the Linux or Windows build of this crate (the stub binary and the
  empty library): local CI runs on macOS and GitHub Actions is off. The GUI for those
  systems is Phase 5.
- There is no change-password screen yet, so `PasswordChangeUncertain` (the session may
  already hold the new keys) has no GUI. Phase 5.
- 206 `cargo vet` exemptions for the GUI crates must be cleared before Phase 6.
- The spec §8.0 last-used vault path is not remembered: Holm uses the default path or
  `--vault`. Phase 5.
- No search, no item types other than logins, no notes on logins, no trash, settings
  or generator screens. Phases 4 and 5.

The full list, with the phase for each, is in
[`docs/tasks/BACKLOG.md`](../../docs/tasks/BACKLOG.md).
