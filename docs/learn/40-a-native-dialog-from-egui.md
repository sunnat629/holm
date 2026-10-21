# Lesson 40: A native dialog from egui

## Why this matters

Typing `/Users/me/export.csv` into a form works, but people expect a Choose button that
opens the system sheet. The sheet is OS code, not egui, and opening one inside tests would
hang a headless run. It also touches secrets: while the sheet is open, the vault could
lock, and the item list must not sit visible behind it.

## What we built

- `FileDialog`: a trait with `pick_import()` and `pick_save(suggested_name)`.
- `RfdDialog`: the real one, using the `rfd` crate (`pick_file`, `save_file`).
- `NoDialog`: the test one. It returns a queued `Option<PathBuf>` and counts calls.
- `Transfer::Choosing`: a screen state that lasts two frames.

## Rust ideas in this task

**A trait seam around the OS.** `AppConfig` holds `Box<dyn FileDialog>`. Production passes
`RfdDialog`; tests pass `NoDialog`. The app never names `rfd` outside one file. In Kotlin
this is the same idea as `ActivityResultContracts.OpenDocument`: the screen asks a
contract for a file and a test registry can answer without a real picker.

**A two-frame state machine.** Frame 1: the click sets `Choosing` and asks for a repaint.
That frame paints only "Choosing a file…". Frame 2: the app calls the dialog. Why two?
The dialog blocks, and the window cannot repaint while it blocks. If we called it in
frame 1, the old screen (rows, search box) would stay painted behind the sheet. Painting
the placeholder first means the frozen picture is harmless.

**Blocking in `update` is allowed here.** egui is immediate mode: `update` runs on the main
thread, and a native sheet must be shown from the main thread on macOS. Blocking is fine
because there is nothing to animate and the placeholder is already on screen. A worker
thread would be wrong: AppKit panels must come from the main thread.

**Check the world after you come back.** When the dialog returns, `tick` runs before the
path is used. If the idle clock locked the vault meanwhile, the path is dropped. A
cancelled dialog (`None`) leaves the form as it was.

## Try it

Run `cargo test -p holm-gui --test transfer` and read `locked_while_choosing_drops_path`:
the fake dialog moves the clock past the limit inside `pick_import`.
