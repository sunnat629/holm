# 49: Letter avatars

## Why this matters

A row with a small coloured letter is easier to find in a long list. Many apps fetch each
site's favicon for this, but that tells a server which sites you have logins for. Holm
fetches nothing: the avatar is painted from the title's first letter and a fixed palette,
so it works offline and leaks nothing.

## What we built

Each row in the list starts with a 24-point circle holding the first letter of its title.
The fill follows the item's category, so items in one category share a colour, and items
with no category are grey. There are two palettes of eight fills, deeper ones for the light
theme, and white letters read on all of them. The widget paints a circle and some text, adds
no accessibility label (the row title already names the item) and never touches a secret.

## Rust ideas in this lesson

### `char::to_uppercase` returns an iterator

One character can upper-case to several: `ß` becomes `SS`. So the standard library returns
an iterator, and we take the first letter:

```rust
title
    .chars()
    .find(|c| c.is_alphanumeric())
    .and_then(|c| c.to_uppercase().next())
    .unwrap_or('•')
```

In Kotlin you'd write `title.firstOrNull { it.isLetterOrDigit() }?.uppercaseChar() ?: '•'`.
`uppercaseChar()` keeps `ß` as it is. Kotlin's `uppercase()` returns a `String` ("SS"), which
is closer to what Rust gives you.

### `% len` for a stable palette slot

The slot is an index, and the remainder wraps it into the palette, so slot 8 reuses the
first colour. The same slot always gives the same colour:

```rust
slot.map_or(grey, |i| palette[i % palette.len()])
```

In Kotlin you'd write `slot?.let { palette[it % palette.size] } ?: grey`. `map_or` takes the
value for `None` first, then the function for `Some`.

### `Option<&Category>` from `iter().find`

`build_rows` looks up a row's category once. `find` returns a borrow of the first match, or
`None`. The slot comes from the category's id (`colour_index`), not from its place in the
list:

```rust
let found = s
    .category
    .and_then(|id| categories.iter().find(|c| c.id() == id));
// ...
category: found.map(|c| Text::new(c.name().to_owned())),
category_slot: found.map(|c| c.id().colour_index()),
```

`found` is an `Option<&Category>`. A shared reference is `Copy`, so an `Option` holding one
is `Copy` too, and `found.map` can run twice without moving anything. If the category is not
in the list, both fields are `None`.

In Kotlin you'd write `val found = categories.firstOrNull { it.id == id }`, then
`found?.name`. Rust's `Option` makes the "not found" case impossible to forget.

## Try it

1. Add the case `"émile"` (expecting `'É'`) to `letter_from_title`, then add `"😀 smile"`
   and decide what the test should expect and why.
   `cargo test -p holm-gui --lib widgets::avatar::tests::letter_from_title`
2. Copy `row_carries_the_category_name` in `rows.rs`, but pass an empty category list
   (`&[]`) to `build_rows`. Check that the item with a category now has both `category`
   and `category_slot` set to `None`.
   `cargo test -p holm-gui --lib rows::`
3. Read `every_fill_reads_with_white_text`. Change one entry of `PALETTE_LIGHT` to a pale
   yellow such as `egui::Color32::from_rgb(253, 224, 71)` and run the tests. Which test
   fails, and what ratio does it print? Put the colour back afterwards.
   `cargo test -p holm-gui --lib widgets::avatar::`

## Read next

- [Storing UTF-8 text in strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- [`char::to_uppercase`](https://doc.rust-lang.org/std/primitive.char.html#method.to_uppercase)
- [Processing a series of items with iterators](https://doc.rust-lang.org/book/ch13-02-iterators.html)
- Previous: Lesson 48 (find it in [the index](README.md))
- Next: [Lesson 50](50-dev-unlock-feature.md)
- [The index](README.md)
