# Lesson 44: The list and its memory

## Why this matters

Two small things hide in a password list. A list with 200 rows must scroll, and the owner
must be able to see that it does. And text typed into a box is remembered by the toolkit
(for undo), so a lock that wipes the vault but not that memory leaves a copy of what was
typed. This task fixes the first and closes the second.

## What we built

- The item list is a `ScrollArea` with a fixed id, `auto_shrink([false, false])` and a bar that
  is always drawn. It fills the panel height above a footer.
- The footer, `count_line`, says `12 logins, 3 other items`, and appends `, 4 shown` while a
  search is on. The counts are the whole vault; only `shown` follows the search.
- On every lock the next frame drops all text-edit state, so Cmd+Z after unlock restores
  nothing, in Search or in the import path field.

Code: `crates/holm-gui/src/screens/vault.rs` (`show_list`, `count_line`), `app.rs`
(`forget_text_state`, `apply_forget`), `messages.rs`. Tests: `tests/search.rs`, `tests/lock.rs`.

## Rust ideas in this task

### 1. Plural strings are a function, not a format trick

```rust
pub fn login_count(n: usize) -> String {
    if n == 1 { "1 login".to_owned() } else { format!("{n} logins") }
}
```

`count_line` joins three of these and has a unit test with plain `assert_eq!`. Kotlin
comparison: `pluralStringResource` in Compose. Here the text lives in `messages.rs`
like every other user-facing string.

### 2. Why a ScrollArea "does not scroll"

A `ScrollArea` scrolls only when it is given a bounded height. Inside a parent that grows to
fit its children, the area is as tall as its content and has nothing to scroll. Two settings
matter: `auto_shrink([false, false])` makes it take all the room it is offered, and the footer
goes in a `Panel::bottom` shown first, so the area gets only the height left over.
The test proves it: the bar must end inside the screen, and after 80 wheel events the last
row is in view and the first one is not.

One trap: `ScrollBarVisibility::AlwaysVisible` only keeps the bar's hit area alive. egui's
default "floating" scroll style paints the bar at opacity 0 until the pointer comes near, so
the owner saw nothing. The list therefore sets `ScrollStyle::solid()` on its own `ui`, which
paints the bar at full opacity. The test checks painted shapes (an opaque rect at least 4 pt
wide inside the bar area, no pointer), not just the accessibility node. The scroll offset is
also dropped on lock, so the list reopens at the top.

### 3. egui's `IdTypeMap` and undo history

egui keeps per-widget state in `ctx.data`, an `IdTypeMap`: a map from (widget id, Rust type)
to a value. A `TextEdit` stores a `TextEditState` there, and that holds the undo history,
which is a copy of the typed text. A field has the same id after lock and unlock, so the old
history is found again and Cmd+Z brings the text back. The fix is one call:

```rust
ctx.data_mut(|d| d.remove_by_type::<egui::text_edit::TextEditState>());
```

Kotlin comparison: `rememberSaveable` state that outlives the screen it was made for.

### 4. A flag, not a parameter

`lock(&mut self, reason)` has no `Context`: the idle lock runs in `tick`, and some tests call
`lock` with no UI at all. So `lock` sets `forget_text_state`, and `tick` and `show` apply it
before anything is drawn, then clear it. One bool, every `LockReason` (Manual, Idle,
Minimised, Sleep) goes through the same path, and the signature of `lock` did not change.

## Try it

1. In `apply_forget`, comment out the `remove_by_type` call and run
   `cargo test -p holm-gui --locked --test lock undo_memory`. All three tests fail.
2. Change `auto_shrink([false, false])` to `[false, true]` and watch what the list does.
