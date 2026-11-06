# Codes you cross off

## Why this matters

A recovery code works once. The user needs to see which ones are left, and they
need to cross one off after using it. The window must do that without ever
showing a code, and without losing the codes already stored when the user edits
the item.

Holm draws dots for every code, strikes through the dots of a used one, and
saves a mark as a whole new field list. The badge and the count read the `used`
flags only.

## What we built

A recovery codes field shows a line like `2 of 5 left`. Under it is one row per
code: its number, dots, a Copy button for an unused code, and Mark used or Mark
unused.

A used code is shown as struck-through dots with no Copy button. Marking a code
sends a `Job::SetFields` to the worker, which saves the item.

In the editor, a codes row has one box. Leave it empty and the stored codes stay,
used flags included. Paste new codes and they replace the list, all unused.

Once an item is down to two codes or fewer, the item list shows a badge with the
count, such as `2 codes left`.

## Rust ideas in this task

### `push_id` for buttons in a loop

```rust
for (i, code) in codes.iter().enumerate() {
    ui.push_id((position, i), |ui| {
        ui.horizontal(|ui| {
            ui.label(format!("{}.", i + 1));
            // dots, Copy and the mark button
        });
    });
}
```

egui gives a widget its id from where it was added and from its text. Every row
here has a button named "Mark used", so two rows would share an id and egui
would mix up their clicks. `push_id` adds a salt to every id made inside the
closure. The salt is a tuple, `(position, i)`: the field's place on the item and
the code's place in the list. Two codes fields on one item cannot clash either.

Any value that is `Hash` works as a salt, and a tuple of two integers is one.

In Compose you'd wrap each loop body in `key(position, i) { ... }` so the
runtime can tell the rows apart.

### A mark is a whole new list, with one bit flipped

```rust
let code_index = flip?;
let fields = item
    .fields()
    .iter()
    .enumerate()
    .map(|(n, field)| copy_field_flipping(field, (n == index).then_some(code_index)))
    .collect::<Result<Vec<_>, _>>()
    .ok()?;
Some(Job::SetFields(item.id(), fields))
```

The row loop only records which button was pressed, in `flip`. After the loop,
`flip?` returns `None` when nothing was pressed. Otherwise every field is copied
and the one code is flipped.

`(n == index).then_some(code_index)` is `Some(code_index)` for the field that was
marked and `None` for all the others. `collect` into `Result<Vec<_>, _>` stops at
the first error, and `.ok()?` turns that into "no job".

The copy does the flip:

```rust
FieldValue::RecoveryCodes(codes) => FieldValue::RecoveryCodes(
    codes
        .iter()
        .enumerate()
        .map(|(i, code)| {
            RecoveryCode::new(
                SecretText::new(code.code().expose().to_owned()),
                code.used() ^ (flip == Some(i)),
            )
        })
        .collect(),
),
```

`^` is exclusive or. For a `bool`, `used ^ true` is the opposite of `used`, and
`used ^ false` is `used`. So one expression gives an exact copy for every code
except the flipped one. `flip == Some(i)` is true for at most one `i`.

`RecoveryCode` has no `Clone`, and neither has `SecretText`, so a secret is never
copied by accident. Holm rebuilds it: `to_owned()` makes one new `String`, and
`SecretText::new` moves it straight into a wiping type. `Job::SetFields` carries
the list to the worker, where it is saved and then dropped, which wipes every
code.

In Kotlin you'd write `code.copy(used = !code.used)` on a data class. Holm has no
`copy` to call, on purpose.

### Kept codes: `Option<Vec<RecoveryCode>>`

The editor has one text box per row. It cannot show stored codes, because it
must never hold them as text. So the row keeps a copy on the side:

```rust
Kind::Codes => FieldValue::RecoveryCodes(match &self.kept {
    Some(kept) if self.secret.is_empty() => copy_codes(kept),
    _ => parse_recovery_codes(self.secret.expose_for_paint())?,
}),
```

`kept` is `Some` only for a row made from a stored codes field. The match arm has
a guard: `Some(kept) if self.secret.is_empty()`. An empty box keeps the stored
list. Any typed text, or no `kept` at all, goes to the other arm and is parsed,
and every parsed code starts unused.

A new row with an empty box has `kept == None`, so it falls to `parse`, which
refuses an empty list. The user gets a fixed line, not an empty field.

Changing the kind sets `self.kept = None`, so kept codes never carry over to
another kind.

In Kotlin this is a nullable `List<Code>?` and a `when` with a condition. The
difference is that the `None` case here is also the "no stored list" case, and
the compiler makes you handle it.

### `Option::filter` for the badge

```rust
codes_low: s.codes_left.filter(|left| *left <= CODES_LOW_AT),
```

`s.codes_left` is an `Option<usize>`. `filter` keeps the `Some` when the closure
says yes and turns it into `None` otherwise. So an item with no codes is `None`,
an item with three left is `None`, and an item with two or fewer left is
`Some(n)`.

`CODES_LOW_AT` is a named constant, so the edge is in one place.

In Kotlin it is `takeIf { it <= LOW }` on a nullable value.

### Only the flags are read

The count comes from core:

```rust
pub fn fewest_codes_left(fields: &[CustomField]) -> Option<usize> {
    fields
        .iter()
        .filter_map(|field| match field.value() {
            FieldValue::RecoveryCodes(codes) => Some(codes_left(codes).0),
            _ => None,
        })
        .min()
}
```

`filter_map` skips every field that is not a codes list. `min` of an empty
iterator is `None`, so an item with no codes gives `None`. An item with two codes
lists takes the smaller count.

`codes_left` counts `used` flags. Nothing here calls `code()`. The row, the badge
and `Debug` can show a number, because the number holds no code.

### Dots, struck through

```rust
let dots = egui::RichText::new(DOTS);
if code.used() {
    ui.label(dots.strikethrough().weak());
} else {
    ui.label(dots);
    // Copy button
}
```

A used code needs to look used without being shown. The same twelve dots are
drawn, with `strikethrough()` and `weak()`. The dots say nothing about the code,
so any screen reader may read them. The code is read only inside the Copy
button's handler, which hands it to the clipboard and never to a label.

Colour is not the only signal here. The strike line and the missing Copy button
say "used" too, and the button reads Mark unused.

## Kotlin side

In Kotlin the same screen is a `LazyColumn` with `key(position, i)` on each row.
A mark is `copy(used = !used)` on a data class, and the badge is
`codesLeft?.takeIf { it <= 2 }`. The Rust differences are `push_id` instead of a
`key` block, a rebuild instead of `copy` because a secret has no `Clone`, and
`^` on two `bool`s instead of `!used`.

## Try it

1. In `codes_badge_shows_at_two_or_fewer` (in `rows.rs`), add `with_codes("e", 2)`
   to the list and expect `Some(1)` for that row.
   `cargo test -p holm-gui --locked --lib rows::tests::codes`
2. In `worker.rs`, add a test that builds a codes field with three codes, calls
   `copy_field_flipping(&field, Some(1))`, and checks that only the second flag
   changed. Then call it with `None` and check that the copy is exact.
   `cargo test -p holm-gui --locked --lib worker::tests`

## Read next

- [Lesson 62](62-one-form-four-kinds.md), the lesson before this one
- [the index](README.md)
- [Rows and the codes badge](../../crates/holm-gui/src/rows.rs)
- [`code_rows` and the item view](../../crates/holm-gui/src/screens/item_view.rs)
- [The copy that flips one flag](../../crates/holm-gui/src/worker.rs)
- [The editor's kept codes](../../crates/holm-gui/src/screens/fields.rs)
- [Pattern guards in `match`](https://doc.rust-lang.org/book/ch19-03-pattern-syntax.html#extra-conditionals-with-match-guards)
- [`Option::filter`](https://doc.rust-lang.org/std/option/enum.Option.html#method.filter)
