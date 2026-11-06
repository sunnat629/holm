# Lesson 44: The list and its memory

## Why this matters

Two small things hide in a password list. A list with 200 rows must scroll, and the owner
must be able to see that it does. And text typed into a box is remembered by the toolkit
(for undo), so a lock that wipes the vault but not that memory leaves a copy of what was
typed. Holm handles both.

## What we built

- The item list is a `ScrollArea` with a fixed id, `auto_shrink([false, false])` and a bar that
  is always drawn. It fills the panel height above a footer.
- The footer, `count_line`, says `12 logins, 3 other items`, and appends `, 4 shown` while a
  search, a category chip or the Expiring chip is on. The counts are the whole vault; only
  `shown` follows the filter.
- On every lock the next frame drops all text-edit state and all scroll state, so Cmd+Z
  after unlock restores nothing in any text field, and the list reopens at the top.

Code: `crates/holm-gui/src/screens/vault.rs` (`show_list`, `count_line`),
`crates/holm-gui/src/app.rs` (`forget_text_state`, `apply_forget`),
`crates/holm-gui/src/messages.rs`. Tests: `crates/holm-gui/tests/`.

## Rust ideas here

### 1. Plural strings are a function, not a format trick

`messages::login_count` is a plain function:

```rust
pub fn login_count(n: usize) -> String {
    if n == 1 {
        "1 login".to_owned()
    } else {
        format!("{n} logins")
    }
}
```

`count_line` joins `login_count`, `other_count` and, while filtering, `shown_count`. Its
unit test, `count_line_plurals_and_shown`, uses plain `assert_eq!`. Kotlin
comparison: `pluralStringResource` in Compose. Here the text lives in `messages.rs`
like every other user-facing string.

### 2. Why a ScrollArea "does not scroll"

A `ScrollArea` scrolls only when it is given a bounded height. Inside a parent that grows to
fit its children, the area is as tall as its content and has nothing to scroll. Two settings
matter: `auto_shrink([false, false])` makes it take all the room it is offered, and the footer
goes in a `Panel::bottom` shown first, so the area gets only the height left over:

```rust
egui::Panel::bottom("vault-list-footer")
    .show_separator_line(true)
    .show(ui, |ui| {
        ui.label(count_line(self.totals.0, self.totals.1, shown));
    });
ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
egui::ScrollArea::vertical()
    .id_salt("item-list")
    .auto_shrink([false, false])
    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
    .show(ui, |ui| { /* one card per row */ });
```

One trap: `ScrollBarVisibility::AlwaysVisible` alone is not enough to see the bar. egui's
default "floating" scroll style paints the bar fully transparent until the pointer comes
near, so the user saw nothing. The list therefore sets `ScrollStyle::solid()` on its own
`ui`, which paints the bar solid. The detail pane does the same.

### 3. egui's `IdTypeMap` and undo history

egui keeps per-widget state in `ctx.data`, an `IdTypeMap`: a map from (widget id, Rust type)
to a value. A `TextEdit` stores a `TextEditState` there, and that holds the undo history,
which is a copy of the typed text. A field has the same id after lock and unlock, so the old
history is found again and Cmd+Z brings the text back. The fix is one call per type, in
`apply_forget`:

```rust
ctx.data_mut(|d| {
    d.remove_by_type::<egui::text_edit::TextEditState>();
    // The list reopens at the top, not where the user was.
    d.remove_by_type::<egui::scroll_area::State>();
});
```

Kotlin comparison: `rememberSaveable` state that outlives the screen it was made for.

### 4. A flag, not a parameter

`lock(&mut self, reason)` takes no `Context`: it is called from many places, some of them
(like `save_and_lock` and `finish`) with no `Context` at hand. So `lock` sets
`forget_text_state`, and `tick` and `show` call `apply_forget` before anything is drawn,
which clears it again. One bool, every lock reason (Manual, Idle, Minimised, Sleep) goes
through the same path, and the signature of `lock` did not change.

## Try it

1. In `apply_forget`, comment out the `TextEditState` line and run
   `cargo test -p holm-gui --locked --test lock`. Read which tests fail and why.
2. Change `auto_shrink([false, false])` to `[false, true]` and watch what the list does.
3. Make `shown_count` say `items shown` instead of `shown`, run
   `cargo test -p holm-gui --locked --lib count_line`, and read the failure. Put it back.

## Read next

- Previous: [Lesson 43: Listening to the OS](43-listening-to-the-os.md)
- Next: Lesson 45, from [the index](README.md)
- [The index](README.md)
