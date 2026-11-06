# Lesson 47: One row of buttons

## Why this matters

A toolbar looks like a small thing, but it is where a screen's actions live. If the same
action sits in two places (a New login button in the toolbar and another in the list), the two
copies drift: one gets a new reset step and the other does not. This task moves the action to
one place, and writes the layout down as tests, so a later change cannot quietly break it.

## What we built

The vault screen's top panel is one row. Today it holds `Lock`, `Import...`, `Export...`, a
back-up button and a `New` menu. The menu offers four kinds of item: Login, Crypto address,
Recovery phrase and Secure note. The `Holm` heading is gone, because it used up space on the
row. The left panel keeps the Search box, the filter chips and the list, with no New button
of its own.

The code is in `crates/holm-gui/src/screens/vault.rs`, in the `vault-top` panel. The tests are
in `crates/holm-gui/tests/walking_skeleton.rs`.

## Rust ideas in this task

### 1. Pull a body out into a method so the call site stays small

Opening a blank form takes a few lines of state resets. Moving the button meant moving those
lines. Instead of pasting them into the toolbar closure, they live in a method:

```rust
fn start_new(&mut self, kind: NewKind) {
    self.selected = None;
    self.item = ItemView::new();
    self.status = None;
    self.mode = DetailMode::Edit(Box::new(LoginForm::new_blank_kind(kind)));
}
```

Replacing `self.item` with a fresh `ItemView` drops the old one, so whatever the detail pane
showed is hidden and wiped. The toolbar calls it from the `New` menu:

```rust
let menu = ui.menu_button(NEW_LABEL, |ui| {
    for (label, kind) in NEW_ENTRIES {
        if ui.button(label).clicked() {
            self.start_new(kind);
            ui.close();
        }
    }
});
```

The menu closure sits inside the `ui.horizontal(|ui| { ... })` closure, and both capture
`self` mutably. That is fine because only one closure runs at a time, and nothing else uses
`self` while they do. Kotlin comparison: an extracted private function on a ViewModel, called
from a click handler.

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

The 2 point slack allows for buttons of slightly different height. If one button lands on a
second row, its top is far below the others, and the failure text names the exact problem
because the assertion prints the whole `Vec`. A `{tops:?}` in a message costs nothing and
saves a debugging session.

### 3. A label that must appear exactly once

`get_by_label` panics when it finds zero or more than one node. That makes it a quiet
"exactly one" check. For "exactly zero" or a count, use `query_all_by_label(..).count()`:

```rust
assert_eq!(harness.query_all_by_label("Holm").count(), 0);
assert_eq!(harness.query_all_by_label("New").count(), 1);
```

A test like `new_login_button_once` can pass the first time it runs. That makes it a guard,
not proof of progress: its value is to fail if someone adds a second New button to the list
later.

### 4. Easy to extend

The test file keeps the labels in one array, `TOOLBAR_LABELS`. Each button in the row is one
`if ui.add_enabled(..).clicked()` or `if ui.button(..).clicked()` in the `vault-top` panel.
The back-up button was added that way, after `Export...`. The array in the test still lists
four labels, so the back-up button is not yet part of the one-row check.

## Try it

1. Add the back-up button's label to `TOOLBAR_LABELS` (look up `messages::BACKUP_BUTTON` for
   the text). Run the test and check it still passes.
   Check: `cargo test -p holm-gui --locked --test walking_skeleton toolbar_is_one_row`
2. Change the 2 point slack to 0. Does the test still pass? Explain what that says about the
   heights of the buttons.
3. Write a test that the Search box is in the left panel, below the toolbar (its top is
   greater than the toolbar's top).
   Check: `cargo test -p holm-gui --locked --test walking_skeleton`

## Read next

- [Closures and capturing](https://doc.rust-lang.org/book/ch13-01-closures.html)
- [Method syntax](https://doc.rust-lang.org/book/ch05-03-method-syntax.html)
- [Lesson 36: Thin screens over the core](36-thin-screens-over-the-core.md)
- [Lesson 45: Shipping a Mac app by hand](45-shipping-a-mac-app-by-hand.md)
- [Lesson 48: Category chips and badges](48-category-chips-and-badges.md)
- [The index](README.md)
- [Lesson 45: Shipping a Mac app by hand](45-shipping-a-mac-app-by-hand.md)
- [Lesson 48: Category chips and badges](48-category-chips-and-badges.md)
- [The index](README.md)
