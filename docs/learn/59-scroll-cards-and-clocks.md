# Scroll, cards and clocks

## Why this matters

The item list shows a title the user typed and a time the Mac supplied. Neither
may change what is stored, and neither may make a test depend on the machine it
runs on. The detail pane can also hold a long item, and it must not remember
where the user was after a lock.

Holm maps text only for display, takes the time zone as an argument, and tells
egui to forget scroll positions when it locks.

## What we built

Each card in the list shows when the item last changed. The same local day shows
`HH:MM`. The same local year shows `D Mon`. Any other day shows `D Mon YYYY`.

The title is passed through `display` before it is drawn. The font has no glyph
for two hyphen characters, so they are shown as `-`. The stored title is
untouched.

The detail pane is wrapped in a vertical `ScrollArea` with a bar that is always
drawn. Lock clears its state, so the pane reopens at the top.

## Rust ideas in this task

### `Cow`: borrow unless you must change

```rust
pub fn display(text: &str) -> Cow<'_, str> {
    const MAPPED: [char; 2] = ['\u{2010}', '\u{2011}'];
    if text.contains(MAPPED) {
        Cow::Owned(text.replace(MAPPED, "-"))
    } else {
        Cow::Borrowed(text)
    }
}
```

`Cow` means clone on write. Most titles have no odd hyphen, so they come back as
`Cow::Borrowed` and nothing is allocated. Only a title with a mapped hyphen
becomes `Cow::Owned`. The caller uses either one as a `&str`.

In Kotlin you'd return the same `String` when nothing changed, and call
`replace` only when it did. A Kotlin `String` is shared for free, so there is no
type to say which case you got.

### A pure function with the offset passed in

```rust
let local = updated.0.saturating_add(offset);
let secs = local.rem_euclid(86_400);
return format!("{:02}:{:02}", secs / 3_600, secs % 3_600 / 60);
```

`updated_label(updated, now, utc_offset_secs)` never asks for the time or the
zone. The app reads both once per frame and hands them in. A test passes
`3_600` or `-3_600` and gets the same answer on every machine.

`saturating_add` stops at the largest `i64` instead of wrapping, so a hostile
timestamp cannot panic or produce a wrong day. `rem_euclid` gives a result from
0 to 86,399 even when `local` is negative, where `%` would give a negative
number. A time outside years 1 through 9999 gives an empty string.

In Kotlin you'd pass a `Clock` and a `ZoneOffset` into the function, not call
`ZoneId.systemDefault()` inside it.

### A scroll area that has a name, and a forget on lock

```rust
egui::ScrollArea::vertical()
    .id_salt("detail-pane")
    .auto_shrink([false, false])
```

egui keeps scroll offsets in a map, keyed by id. `id_salt` gives the pane a
fixed id, so two scroll areas never share one. After a lock the id is the same,
so the old offset would come back. `apply_forget` removes it:

```rust
d.remove_by_type::<egui::scroll_area::State>();
```

It runs once, in the frame after a lock, together with the text edit history.

In Kotlin you'd see this as `rememberSaveable` outliving a screen: state keyed
by a stable id is kept unless you clear it on purpose.

## Try it

1. In `updated_offset_can_cross_midnight` (in `rows.rs`), add a case where
   `updated` is `2026-11-05` at 00:30, `now` is `2026-11-05` at 12:00, and the
   offset is `-3_600`. Expect `"4 Nov"`.
   `cargo test -p holm-gui --locked --lib rows::tests::updated`
2. In `fonts.rs`, add a test that `display("a\u{2011}b")` matches
   `Cow::Owned(_)` and that `display("ab")` matches `Cow::Borrowed(_)`.
   `cargo test -p holm-gui --locked --lib fonts::tests`

## Read next

- [Row labels](../../crates/holm-gui/src/rows.rs)
- [Fonts and `display`](../../crates/holm-gui/src/fonts.rs)
- [Forgetting state on lock](../../crates/holm-gui/src/app.rs)
- [Enums and `Cow`](https://doc.rust-lang.org/std/borrow/enum.Cow.html)
