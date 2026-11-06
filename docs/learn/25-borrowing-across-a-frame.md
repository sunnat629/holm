# Lesson 25: Borrowing across a frame

## Why this matters

An immediate-mode UI runs the whole screen function about sixty times a second, and every pass wants to read the vault's items. If each pass asked the session for the items again, the UI would hold borrows of the session while the worker thread might be changing it, and secrets would be copied into temporary strings sixty times a second. Rust's ownership rules push you to decide who owns what, once, and the answer here is also the secure one.

## What we built

When the vault unlocks, the app builds a list of `ItemRow` values one time, on the next draw after the worker's result arrives, and the `VaultView` owns them. Each row holds the item's id, kind, title, a subtitle, its category, a reminder badge, a low-codes count and an "updated" label. The list on the left and the detail pane on the right read those rows; neither touches the session. The login form uses fixed-size `LineBuf` buffers that wipe themselves, so typing never reallocates and leaves a copy behind. When a save job starts, the view is moved out of the screen with `mem::replace` and kept inside `Screen::Working`, so the screen shows "Saving." while the job runs and the form's buffers are gone before it starts. When the job finishes, the rows are rebuilt from the returned session.

## Rust ideas in this task

### Build once, own it, borrow it per frame

From `crates/holm-gui/src/rows.rs`, trimmed:

```rust
pub struct ItemRow {
    pub id: ItemId,
    pub kind: ItemType,
    pub title: Text,
    pub subtitle: Text,
    pub category: Option<Text>,
    // ... badges and the "updated" label
}

pub fn build_rows(
    summaries: &[ItemSummary<'_>],
    categories: &[Category],
    today: CalendarDate,
    now: Timestamp,
    utc_offset_secs: i32,
) -> Vec<ItemRow> { /* ... */ }
```

`build_rows` reads `ItemSummary` values from `Session::search`, not whole items. The subtitle is never a secret: a login's username (else its first web address), a crypto address's chain, or a fixed word for a phrase or a note. The text fields are still zeroizing `Text` values, not plain `String`: a row is a copy of vault data, and the habit is that every copy wipes on drop. The password is not in the row at all: the reveal fetches it from the session on demand. Each frame, the list borrows the view's rows and draws one entry per row.

In Kotlin you'd write a `data class ItemRow` inside a `StateFlow<List<ItemRow>>` and let Compose read it. The difference is that Rust makes you say who owns the list: here the view does, and a frame can only borrow it for as long as the frame lasts.

### `mem::replace` to move out of a borrowed enum

```rust
let old = std::mem::replace(&mut self.screen, Screen::Fatal(messages::WORKER_LOST));
if let Screen::Vault(view) = old { /* move view into Working */ }
```

You cannot move a field out of `&mut self` and leave nothing behind. `mem::replace` swaps in a placeholder and hands you the old value by ownership. Afterwards the code assigns the real new screen, so the placeholder is never drawn.

In Kotlin you'd write `val old = screen; screen = Placeholder`, which works because everything is a reference. In Rust a move really empties the source, so you must put something there.

### Panels, and the central panel last

```rust
egui::Panel::top("vault-top").show(ui, |ui| { /* toolbar */ });
egui::Panel::left("vault-list").show(ui, |ui| self.show_list(ui));
egui::CentralPanel::default().show(ui, |ui| self.show_detail(ui));
```

Panels cut space off the edges of the window in the order you add them. The central panel takes whatever is left, so it must come last. If you add it first it takes everything and the side panel has no room.

In Kotlin you'd write a `Row { Column(Modifier.width(240.dp)) {..}; Column(Modifier.weight(1f)) {..} }`. The weight does the same job as the central panel.

### A capped, pre-allocated text buffer

```rust
struct LineBuf(Zeroizing<String>);
impl egui::TextBuffer for LineBuf { /* insert_text stops at the cap */ }
```

A `String` that grows reallocates, and the old block is freed without being wiped. `LineBuf` reserves its whole capacity at creation and refuses input past the cap, so the buffer never moves and `Zeroizing` wipes the one block on drop. egui edits it through the `TextBuffer` trait, so no copy of the secret goes into a normal `String`.

In Kotlin you'd write `CharArray(1024)` and `fill('\u0000')` yourself, because `String` is immutable and cannot be wiped at all.

## Try it

1. Read `build_rows` and list which `ItemSummary` fields it copies. Confirm no password is among them. Check: `grep -n "password" crates/holm-gui/src/rows.rs`. Every hit is inside the `tests` module, where a test item or a master password is built.
2. Temporarily change `Panel::left` and `CentralPanel` in `show` so the central panel is added first. Run the tests and see what breaks, then undo. Check: `cargo test -p holm-gui --locked --test items`.
3. In `rows.rs`, change `CODES_LOW_AT` from 2 to 3 and run the badge test. Which row now gets a badge it should not have? Undo the change. Check: `cargo test -p holm-gui --locked codes_badge_shows_at_two_or_fewer`.

## Read next

- Previous: [Lesson 24](24-state-machines-and-worker-threads.md)
- Next: [Lesson 26](26-the-clipboard-is-shared.md)
- [The index](README.md)
- [`std::mem::replace`](https://doc.rust-lang.org/std/mem/fn.replace.html)
- [`egui::Panel`](https://docs.rs/egui/0.37.0/egui/containers/panel/struct.Panel.html)
- [`egui::TextBuffer`](https://docs.rs/egui/0.37.0/egui/trait.TextBuffer.html)
