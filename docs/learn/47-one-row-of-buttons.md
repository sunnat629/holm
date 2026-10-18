# Lesson 47: One row of buttons

## Why this matters

A toolbar looks like a small thing, but it is where a screen's actions live. If the same
action sits in two places (a New login button in the toolbar and another in the list), the two
copies drift: one gets a new reset step and the other does not. This task moves the action to
one place, and writes the layout down as tests, so a later change cannot quietly break it.

## What we built

The vault screen's top panel is now one row: `Lock`, `Import...`, `Export...`, `New login`.
The `Holm` heading is gone (the window title still says Holm, and the heading used up space on
the row). The left panel keeps only the Search box and the list. A later task adds a `Back up`
button to the same row.

The code is in `crates/holm-gui/src/screens/vault.rs`, in the `vault-top` panel. The tests are
in `crates/holm-gui/tests/walking_skeleton.rs`.

## Rust ideas in this task

### 1. Pull a body out into a method so the call site stays small

The old New login button had five lines of state resets inline in `show_list`. Moving the
button meant moving those lines. Instead of pasting them into the toolbar closure, they became
a method:

```rust
fn start_new_login(&mut self) {
    self.selected = None;
    self.reveal_until = None;
    self.status = None;
    self.copy_note = None;
    self.mode = DetailMode::Edit(LoginForm::new_blank());
}
```

The toolbar then reads `if ui.button(NEW_LABEL).clicked() { self.start_new_login(); }`. Inside
the `ui.horizontal(|ui| { ... })` closure, `self` is borrowed mutably by the closure, and a
method call on `self` is fine because the closure is the only user. Kotlin comparison: an
extracted private function on a ViewModel, called from a click handler.

### 2. Test layout with rectangles, not pictures

egui draws into an accessibility tree even in a headless test. Each node has a `rect()`, its
position on screen. To say "these buttons share a row" the test compares the top edge of each:

```rust
let tops: Vec<f32> = TOOLBAR_LABELS
    .iter()
    .map(|label| harness.get_by_label(label).rect().min.y)
    .collect();
for top in &tops {
    assert!((top - tops[0]).abs() <= 2.0, "not one row: {tops:?}");
}
```

The 2 pixel slack allows for buttons of slightly different height. When the test failed before
the change, the message showed `[11.0, 11.0, 11.0, 38.0]`: the failure text names the exact
problem, because the assertion prints the whole `Vec`. A `{tops:?}` in a message costs nothing
and saves a debugging session.

### 3. A label that must appear exactly once

`get_by_label` panics when it finds zero or more than one node. That makes it a quiet
"exactly one" check. For "exactly zero" or a count, use `query_all_by_label(..).count()`:

```rust
assert_eq!(harness.query_all_by_label("Holm").count(), 0);
assert_eq!(harness.query_all_by_label("New login").count(), 1);
```

Note that `new_login_button_once` passed even before the change, because the toolbar did not
yet have the button. A test that passes first time is only a guard, not proof of progress: its
value is to fail if someone adds the button back to the list later.

### 4. Easy to extend

The test file keeps the labels in one array, `TOOLBAR_LABELS`, and the code has a comment
where the next button goes. Adding `Back up` means one more `if ui.button(..)` in the row and
one more string in the array.

## Exercises

1. Add a fifth button `Settings` to the row and the array. Run the tests and see which one
   fails if you put it in the left panel by mistake.
   Check: `cargo test -p holm-gui --locked --test walking_skeleton`
2. Change the 2 pixel slack to 0. Does the test still pass? Explain what that says about the
   heights of the buttons.
3. Write a test that the Search box is still in the left panel, below the toolbar (its top is
   greater than the toolbar's top).
   Check: `cargo test -p holm-gui --locked --test walking_skeleton`

## Read next

- [Closures and capturing](https://doc.rust-lang.org/book/ch13-01-closures.html)
- [Method syntax](https://doc.rust-lang.org/book/ch05-03-method-syntax.html)
- [Lesson 36: Thin screens over the core](36-thin-screens-over-the-core.md)
