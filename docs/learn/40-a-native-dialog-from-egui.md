# Lesson 40: A native dialog from egui

## Why this matters

Typing `/Users/me/export.csv` into a form works, but people expect a Choose button that
opens the system file panel. The panel is OS code, not egui, and opening one inside tests would
hang a headless run. It also touches secrets: while the panel is open, the vault could
lock, and the item list must not sit visible behind it. A copied password also
cannot be cleared on time, because the clipboard timer runs in `tick`, which does not
run while the dialog blocks; so opening a dialog clears a pending copy first.

Without a parent window, macOS shows this as an app-modal panel, not a sheet attached
to the window. Attaching it (`set_parent`) is possible later polish.

## What we built

- `FileDialog`: a trait with `pick_import()` and `pick_save(suggested_name)`.
- `RfdDialog`: the real one, using the `rfd` crate (`pick_file`, `save_file`).
- `NoDialog`: the test one. It returns a queued `Option<PathBuf>` and counts calls.
- `Transfer::Choosing`: a screen state that lasts two frames.

## Rust ideas in this lesson

**A trait seam around the OS.** `AppConfig` holds `Box<dyn FileDialog>`. Production passes
`RfdDialog`; tests pass `NoDialog`. The app never names `rfd` outside one file. In Kotlin
this is the same idea as `ActivityResultContracts.OpenDocument`: the screen asks a
contract for a file and a test registry can answer without a real picker.

**A two-frame state machine.** Frame 1: the click sets `Choosing` and asks for a repaint.
That frame paints only "Choosing a file…". Frame 2: the app calls the dialog. Why two?
The dialog blocks, and the window cannot repaint while it blocks. If we called it in
frame 1, the old screen (rows, search box) would stay painted behind the panel. Painting
the placeholder first means the frozen picture is harmless.

**Blocking in `update` is allowed here.** `update` runs on the main thread, and on macOS
a native panel must be shown from the main thread, so a worker thread is not an option.
Blocking is fine because there is nothing to animate and the placeholder is already on
screen.

**Check the world after you come back.** When the dialog returns, `tick` runs before the
path is used. If the idle clock locked the vault meanwhile, the path is dropped. A
cancelled dialog (`None`) leaves the form as it was.

## Try it

1. Run `cargo test -p holm-gui --test transfer` and read
   `locked_while_choosing_drops_path`: the fake dialog moves the clock past the limit
   inside `pick_import`.
2. Find where `RfdDialog` is built. Search the GUI crate for `rfd` and check that it is
   named in only one file.

## Read next

- Previous: [Lesson 39](39-one-flow-two-front-ends.md)
- Next: [Lesson 41](41-backups-and-the-trash.md)
- [the index](README.md)
