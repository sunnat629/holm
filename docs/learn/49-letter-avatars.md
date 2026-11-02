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

## Rust ideas in this task

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

The slot is an index, and the remainder wraps it into the palette, so a ninth category
reuses the first colour. The same slot always gives the same colour:

```rust
slot.map_or(grey, |i| palette[i % palette.len()])
```

In Kotlin you'd write `slot?.let { palette[it % palette.size] } ?: grey`. `map_or` takes the
value for `None` first, then the function for `Some`.

### `Option<usize>` from `iter().position`

`CategoryId` has a private field, so a row stores the category's index in the session's list
instead. `position` returns the index of the first match, or `None`:

```rust
let slot = s
    .category
    .and_then(|id| categories.iter().position(|c| c.id() == id));
```

In Kotlin you'd write `categories.indexOfFirst { it.id == id }.takeIf { it >= 0 }`, because
`indexOfFirst` returns `-1` for "not found". Rust's `Option` makes that case impossible to
forget. The name lookup then reuses the slot with `categories.get(i)`, which also returns an
`Option` instead of panicking.

## Exercises

1. Add the case `"émile"` (expecting `'É'`) to `letter_from_title`, then add `"😀 smile"`
   and decide what the test should expect and why.
   `cargo test -p holm-gui --lib widgets::avatar::tests::letter_from_title`
2. Add a unit test in `rows.rs` that builds rows for an item whose category id is not in the
   list and checks both `category` and `category_slot` are `None`.
   `cargo test -p holm-gui --lib rows::`
3. Add a test that computes the contrast ratio of every colour in both palettes against white
   and checks it is at least 4.5.
   `cargo test -p holm-gui --lib widgets::avatar::`

## Read next

- [Storing UTF-8 text in strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- [`char::to_uppercase`](https://doc.rust-lang.org/std/primitive.char.html#method.to_uppercase)
- [Processing a series of items with iterators](https://doc.rust-lang.org/book/ch13-02-iterators.html)
