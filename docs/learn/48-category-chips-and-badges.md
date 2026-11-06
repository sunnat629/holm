# Lesson 48: Category chips and badges

## Why this matters

A password manager lists many items, and people sort them into categories to find them
fast. A filter that is wrong can hide an item or show the wrong set, so the rules for how a
chip and the search box combine must be exact. The category name comes from inside the
encrypted vault, so the code keeps it in a wiping `Text` and never puts it in a log or a
`Debug` line.

## What we built

The list has a wrapping row of chips under the Search box: "All", "No category", then one
chip per category. The chosen chip joins the search text in one `Query`, so both filters
apply together. Each row with a category shows its name, small and right-aligned, as a badge.
The chip lives in `VaultView`, so locking drops it and the next unlock starts at "All".
(A later lesson adds a separate Expiring chip at the end of the row, which combines with the
category chip instead of replacing it.)

## Rust ideas in this task

### Reuse an enum as UI state

The core already has `CategoryFilter { All, Uncategorised, Only(CategoryId) }`. The screen
stores it as is, so there is no second enum and no conversion that could drift:

```rust
chip: CategoryFilter,
// ...
let query = Query {
    text: Zeroizing::new(self.searched.as_str().to_owned()),
    category: self.chip,
    expiring_only: self.expiring,
    ..Query::default()
};
```

`..Query::default()` fills every field not named with its default value.

In Kotlin you'd write a `sealed interface` for the filter in the core module and keep a
`var chip by mutableStateOf<CategoryFilter>(All)` in the view model, instead of making a
UI-only copy of the type.

### Copy enums and `!=` for staleness

`CategoryFilter` is `Copy` and `PartialEq`, so the view keeps the chip the rows were built
with and compares it each frame:

```rust
if self.search.as_str() != self.searched.as_str()
    || self.chip != self.searched_chip
    || self.expiring != self.searched_expiring
    || today != self.built_day
{
    self.rows_stale = true;
}
```

The first two lines are this lesson's part. The other two came later: the Expiring chip, and
a new day, which changes the expiry badges.

In Kotlin you'd write `if (query != lastQuery) reload()` with a `data class`. Rust needs the
derive to be written out, and `Copy` lets `self.searched_chip = self.chip` work without
`.clone()`.

### `Option<Text>` from `iter().find`

A row (`ItemRow` in `crates/holm-gui/src/rows.rs`) stores the category name, if there is one,
in a wiping `Text`. `build_rows` looks the category up once per item:

```rust
let found = s
    .category
    .and_then(|id| categories.iter().find(|c| c.id() == id));
ItemRow {
    // ...
    category: found.map(|c| Text::new(c.name().to_owned())),
    category_slot: found.map(|c| c.id().colour_index()),
    // ...
}
```

`s.category` is an `Option<CategoryId>`. `and_then` runs the lookup only for `Some`, and
`find` returns `None` when the id is unknown. `found` is an `Option<&Category>`, a borrow into
the `categories` slice. A shared reference is `Copy`, so `Option<&Category>` is too, and
`found.map(..)` can run twice without moving it. In Kotlin you'd write
`s.category?.let { id -> categories.firstOrNull { it.id == id } }?.name`.

`ItemRow` writes its own `Debug` impl, which prints the name's length, not the name:

```rust
.field(
    "category_len",
    &self.category.as_ref().map(|c| c.as_str().len()),
)
```

The list then draws the badge only when there is a name:

```rust
if let Some(name) = &row.category {
    ui.small(name.as_str());
}
```

## Try it

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
- [Lesson 47: One row of buttons](47-one-row-of-buttons.md)
- [Lesson 49: Letter avatars](49-letter-avatars.md)
- [The index](README.md)
- [Lesson 47: One row of buttons](47-one-row-of-buttons.md)
- [Lesson 49: Letter avatars](49-letter-avatars.md)
- [The index](README.md)
