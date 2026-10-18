# Lesson 23: A password widget that wipes

## Why this matters

The master password is the one secret that unlocks everything, and the moment it is typed is when it is most exposed: it sits in plain memory, one key at a time. A normal text box copies that text into growing strings, undo history, layout caches and the screen reader tree, and none of those copies are wiped. If the widget leaks, the careful key handling in `holm-crypto` protects a password that is already lying around in freed memory.

## What we built

`SecretInput` is a byte buffer that reserves its whole capacity once, never grows, wipes every byte it removes, and wipes itself on drop. `secret_field` is Holm's own password widget: it reads raw key events while focused, writes them into a `SecretInput`, and paints exactly 12 dots for any non-empty secret. Its accessibility node has the `PasswordInput` role and a fixed label, never a value, so VoiceOver can announce the field without reading the secret. `strength_meter` turns `holm_core::strength::check`'s verdict into four painted segments, a word and core's warning. All three are tested headless with `egui_kittest`, including a test that proves the widget publishes no value.

## Rust ideas in this task

### Why `TextEdit` is not for secrets

`egui::TextEdit` edits a `String` you own (or any `TextBuffer`). On every edit it may grow that string, which means a new allocation and a copy, and the old block is freed without being wiped. It also keeps an undo history of earlier states, lays the text out into a galley that egui caches, sets the AccessKit value to the text, and supports select, copy and cut. Each of those is a copy we cannot wipe.

So the rule (Global Constraints) is: secrets go through `secret_field` only. `TextEdit` is allowed for title, username and URL, which are not secrets.

In Kotlin you'd write a Compose `TextField` with `visualTransformation = PasswordVisualTransformation()`, which hides the characters on screen but still keeps the text in an immutable `String` that lives until the garbage collector gets to it.

### `Vec::with_capacity` and never growing

```rust
pub fn with_capacity(cap: usize) -> SecretInput {
    SecretInput { bytes: Vec::with_capacity(cap), cap }
}
```

`Vec::with_capacity` allocates once. As long as the length stays at or below the capacity, `extend_from_slice` writes in place and the pointer never moves. `push_str` checks each character against `cap` before writing it and stops at the first one that would not fit, so the vector never asks for more memory. The `never_reallocates` test fills a buffer to its cap and checks that the pointer and the capacity are unchanged.

Removing bytes is where most "wiping" code goes wrong. `Vec::truncate` only changes the length; the old bytes stay in the allocation. So `pop_char` zeroes the bytes first, then truncates:

```rust
self.bytes[start..].zeroize();
self.bytes.truncate(start);
```

`clear` and `Drop` call `Vec::zeroize`, which zeroes the whole capacity, not only the used part.

Each typed character passes through a 4-byte scratch for `char::encode_utf8`. It is a `Zeroizing<[u8; 4]>`, so it is wiped when it goes out of scope on every path, including an early `break` and a panic.

In Kotlin you'd write `val buf = CharArray(MAX)` plus your own length counter, and `buf.fill('\u0000')` before you drop it, because a `CharArray` (unlike a `String`) can be cleared.

### `std::mem::replace`: moving a secret out without a copy

When the user presses Unlock, the secret has to leave the widget and go into a `MasterPassword`. Copying would make a second plaintext. Instead we move the allocation itself:

```rust
fn take_bytes(&mut self) -> Vec<u8> {
    std::mem::replace(&mut self.bytes, Vec::with_capacity(self.cap))
}
```

`mem::replace` puts a fresh, empty buffer in the field and returns the old one. `String::from_utf8` takes that `Vec<u8>` by value and reuses its allocation, and `MasterPassword::new` takes the `String` by value. The bytes never move in memory. We cannot simply move `self.bytes` out, because `SecretInput` implements `Drop`, and Rust does not let you move a field out of a type with a destructor.

`from_utf8` can only fail on invalid UTF-8, which cannot happen because `push_str` is the only writer and writes whole characters. If it ever did, the error hands the bytes back, we wipe them and return an empty secret. There is no `expect`, so no panic message can carry anything.

In Kotlin you'd write `val out = buffer; buffer = CharArray(MAX)`, which swaps references just like this. The difference is that Rust's type system guarantees nobody else still holds the old reference.

### Reading raw input events

`secret_field` does not use any egui text widget. While it has focus, it walks the frame's events in place:

```rust
ui.input(|input| {
    for event in &input.events {
        match event {
            Event::Text(text) => buf.push_str(text),
            Event::Key { key: Key::Backspace, pressed: true, .. } => buf.pop_char(),
            Event::Key { key: Key::Enter, pressed: true, .. } => out.submitted = true,
            Event::Key { key: Key::V, pressed: true, modifiers, .. }
                if modifiers.command => out.paste_requested = true,
            _ => {}
        }
    }
});
```

(Simplified; the real code also records `changed`.) The events are borrowed, never cloned, so this widget makes no extra copy of what was typed. `Event::Copy`, `Event::Cut`, `Event::Paste` and Cmd+A fall into `_ => {}`: there is nothing to select, and nothing goes to the clipboard.

Cmd+V arrives as a key event only because Task 1 set `clipboard_shortcuts: false` in `NativeOptions`. With the default, `egui-winit` turns Cmd+V into `Event::Paste(String)` by reading the system clipboard itself. Here the field only reports `paste_requested`, and Task 5 decides what to paste.

`egui-winit` still builds a `String` for each `Event::Text` it delivers, and egui drops those strings without wiping them. That copy is outside our control; we keep it to one short string per key press and make no more.

In Kotlin you'd write `Modifier.onKeyEvent { … }` on a plain `Box` instead of using `TextField`, and handle each `KeyEvent` yourself.

### Painting instead of laying out text

The dots are `painter.circle_filled` calls, not a `"••••"` label. A label would put a galley in egui's layout cache, and a string of bullets as long as the password would show its length. We paint exactly 12 circles for any non-empty secret and none for an empty one, so neither the screen nor the shape list says how long it is. The `dots_hide_the_length` test counts `Shape::Circle` in the harness output for 1 and 26 characters: 12 both times.

The field label is painted with `painter.text` too, so the only accessibility node is the field's own. A separate `ui.label` would add a second node with the same text.

In Kotlin you'd write a `Canvas { drawCircle(…) }` instead of a `Text`.

### The accessibility node: a role, a label, no value

egui 0.37 creates an AccessKit node for every focusable widget. We fill it in ourselves instead of calling `Response::widget_info`, because `WidgetInfo` would set a value for a text edit:

```rust
ui.ctx().accesskit_node_builder(id, |node| {
    node.set_role(Role::PasswordInput);
    node.set_label(label);
});
```

`label` is `&'static str`, so it can only be fixed text from our code, never data. egui 0.37 re-exports `accesskit::Role` as `egui::Role`, and `WidgetType` is now only a deprecated alias for it, so the code names the role directly. The focus calls (`Response::request_focus`, `Response::has_focus`) kept their names. `PasswordInput` tells screen readers such as VoiceOver that this is a secure field.

In Kotlin you'd write `Modifier.semantics { password(); contentDescription = "Master password" }`.

### Testing a widget that has no value

You cannot assert on what a password field shows, because it shows nothing. So the tests check the buffer through the test state and the accessibility tree through kittest:

```rust
let node = harness.get_by_label(LABEL);
assert_eq!(node.accesskit_node().role(), Role::PasswordInput);
assert_eq!(node.value(), None);
```

`build_ui_state` gives the closure a `&mut Form` that holds two `SecretInput`s and counts submits and paste requests, so a test can type, step a frame, and read the buffer. `copy_cut_and_selection_ignored` sends `Event::Copy`, `Event::Cut` and Cmd+A, then checks that the platform output has no `OutputCommand::CopyText`. Every harness installs Holm's fonts first, because `default_fonts` is off and kittest panics on a missing glyph.

The strength meter is split the same way: `meter_segments` and `meter_word` are plain functions over a `StrengthVerdict` with a table test, and only `strength_meter` touches egui. The meter never calls a password "Strong" unless core's `acceptable` is true, and the word always comes with the coloured segments, so colour is never the only signal.

In Kotlin you'd write a Compose UI test with `onNodeWithContentDescription("Master password").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))`.

## Exercises

1. In `with_capacity`, replace `Vec::with_capacity(cap)` with `Vec::new()` and run the test. Which assertion fails first, and if the buffer were allowed to grow, what would each reallocation leave behind in the old block? Undo the change.
   Check: `cargo test -p holm-gui --locked never_reallocates`
2. In `secret_field`, add `node.set_value("EXAMPLE");` inside the `accesskit_node_builder` closure and run the test. A real leak would pass the buffer's text here; the test catches it either way. Undo the change.
   Check: `cargo test -p holm-gui --locked secret_field_publishes_no_value`
3. Delete the `chars > MAX_MASTER_CHARS` branch from `meter_word`. Which word does a 1,025-character password get instead, and why is that misleading? Undo the change.
   Check: `cargo test -p holm-gui --locked meter_table`

## Read next

- [`std::mem::replace`](https://doc.rust-lang.org/std/mem/fn.replace.html)
- [The `zeroize` crate](https://docs.rs/zeroize/1.9.1/zeroize/)
- [AccessKit `Role`](https://docs.rs/accesskit/0.25.1/accesskit/enum.Role.html)
