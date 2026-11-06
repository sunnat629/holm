# Lesson 37: Hold to reveal

## Why this matters

People mistype passwords they cannot see. A reveal button helps, but a toggle is risky: the
password stays on screen after the user looks away. Holm's eye button shows the text only
while the mouse button is held on it. The safest state to store is none at all.

## What we built

Every password box (create, unlock, export re-entry, login form) now has a small eye at the
right end, drawn in `crates/holm-gui/src/widgets/secret_field.rs`. While you hold the mouse
down on it, the box paints the secret as text instead of the 12 fixed dots. Let go, drag off
it, switch window (Cmd+Tab) or lock, and the dots come back at once.

Space held on the keyboard-focused eye also reveals. It never types a space into the secret.
The rule is an allowlist: only Space, Tab (which moves focus on) and key releases stay on the
eye. Every other key press, text, paste or cut moves focus to the field in that same frame, so
Cmd+V, Enter and Backspace still work.

A multiline box (`secret_area`, for a private key) works the same way, but while the eye is
held the secret is painted under the box, wrapped, on as many lines as it has.

## Rust ideas in this task

### 1. Immediate mode means no stored flag

egui redraws the whole UI every frame and keeps no "revealed" field. Each frame asks the live
pointer state again:

```rust
let held_by_pointer =
    eye.is_pointer_button_down_on() && eye.contains_pointer() && window_focused;
let held_by_key = eye.has_focus() && window_focused && ui.input(|i| i.key_down(Key::Space));
let revealing = held_by_pointer || held_by_key;
```

There is nothing to forget to reset. A lock drops the screen, the pointer state goes with it,
and the next frame computes `false`. Kotlin Compose: `Modifier.pointerInput { detectTapGestures(onPress = { show = true; tryAwaitRelease(); show = false }) }`
keeps a `show` state you must clear on every exit path. Here the "state" is the hardware.

### 2. `Response::is_pointer_button_down_on`

It is true while egui still tracks the press as a click or a drag on the widget. A
click-only widget (`Sense::click()`) loses that after `max_click_duration` (0.8 s) or a
move of more than 6 pt, so a long hold would end early. The eye therefore uses
`Sense::click_and_drag()`, which keeps the press alive for the whole hold. A drag keeps
it true even when the pointer leaves the widget, so Holm also checks `contains_pointer()`.
Without it, dragging off the eye would keep the text visible.

### 3. Painting a galley versus a TextEdit

A `TextEdit` owns a `String` and a cursor, which is why Holm never uses it for secrets
(lesson 23). To reveal, the widget borrows the wiping buffer as `&str` through
`expose_for_paint` and hands it to `painter.text` for one frame, clipped to the box. A
multiline area hands it to `paint_secret` instead, which lays out a wrapped galley with
`painter.layout` and paints it. Either way the borrow ends with the frame. Honest limit: the
galley egui lays out is a plain copy of the text that is not wiped, outside Holm's control.
The hold-only rule keeps that window short.

### 4. Drawing without a glyph

The app has one font and no eye character, and an emoji would show as a box. The eye is two
curves and a small diamond, built from line segments. It avoids circles on purpose: the test
helper counts circles to prove there are exactly 12 dots.

## Try it

1. Make the eye brighter while held. Look at `paint_eye`. Check:
   `cargo test -p holm-gui --locked --lib secret_field`
2. Add a test next to `eye_hold_paints_text_not_dots` that a 20-character secret such as
   `EXAMPLE-twenty-chars` paints as one text shape while the eye is held. Check:
   `cargo test -p holm-gui --locked --lib secret_field`

## Read next

- Previous: [Lesson 36: Thin screens over the core](36-thin-screens-over-the-core.md)
- Next: [Lesson 38: One clear for every client](38-one-clear-for-every-client.md)
- [The index](README.md)
- [Lesson 23: A password widget that wipes](23-a-password-widget-that-wipes.md)
- [`egui::Response`](https://docs.rs/egui/latest/egui/struct.Response.html)
