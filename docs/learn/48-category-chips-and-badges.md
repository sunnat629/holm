# 48: Category chips and badges

## Why this matters

A password manager lists many items, and people sort them into categories to find them
fast. A filter that is wrong can hide an item or show the wrong set, so the rules for how a
chip and the search box combine must be exact. The category name is shown in the list, so it
is public text, and the code must never put it in a log or a `Debug` line.

## What we built

The list now has a wrapping row of chips under the Search box: "All", "No category", then
one chip per category. The chosen chip joins the search text in one `Query`, so both filters
apply together. Each row with a category shows its name, small and right-aligned, as a badge.
The chip lives in `VaultView`, so locking drops it and the next unlock starts at "All".

## Rust ideas in this task

### Reuse an enum as UI state

The core already has `CategoryFilter { All, Uncategorised, Only(CategoryId) }`. The screen
stores it as is, so there is no second enum and no conversion that could drift:

```rust
chip: CategoryFilter,
// ...
let query = Query { text, category: self.chip, ..Query::default() };
```

In Kotlin you'd write a `sealed interface` for the filter in the core module and keep a
`var chip by mutableStateOf<CategoryFilter>(All)` in the view model, instead of making a
UI-only copy of the type.

### Copy enums and `!=` for staleness

`CategoryFilter` derives `Copy` and `PartialEq`, so the view keeps the chip the rows were
built with and compares it each frame:

```rust
if self.search.as_str() != self.searched.as_str() || self.chip != self.searched_chip {
    self.rows_stale = true;
}
```

In Kotlin you'd write `if (query != lastQuery) reload()` with a `data class`. Rust needs the
derive to be written out, and `Copy` lets `self.searched_chip = self.chip` work without
`.clone()`.

### `Option<Text>` from `iter().find`

A row stores the category name, if there is one, in a wiping `Text`:

```rust
category: s
    .category
    .and_then(|id| categories.iter().find(|c| c.id() == id))
    .map(|c| Text::new(c.name().to_owned())),
```

`s.category` is an `Option<CategoryId>`. `and_then` runs the lookup only for `Some`, and
`find` returns `None` when the id is unknown. In Kotlin you'd write
`s.category?.let { id -> categories.firstOrNull { it.id == id } }?.name`. The `Debug` impl
for the row prints `category_len`, not the name.

## Exercises

1. Add a test `no_category_chip` to `crates/holm-gui/tests/search.rs`. Seed one item in a
   category and one without, click "No category", and check only the second row is listed.
   `cargo test -p holm-gui --test search no_category_chip`
2. Make the badge show nothing when the active chip already is that category, since the chip
   already says it. Update `badge_shows_category_name` to match.
   `cargo test -p holm-gui --test search badge_shows_category_name`
3. Add a unit test in `rows.rs` that checks an item whose category id is not in the list
   gets `category: None` instead of a panic.
   `cargo test -p holm-gui --lib rows::`

## Read next

- [Enums and pattern matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [Processing a series of items with iterators](https://doc.rust-lang.org/book/ch13-02-iterators.html)
- [Derivable traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html)
