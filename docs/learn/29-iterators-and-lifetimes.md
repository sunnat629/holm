# Lesson 29: Iterators and lifetimes

## Why this matters

A vault search runs over every item on each keystroke, so it must be cheap and must never copy
secrets around. Rust gives two tools for that: iterator chains that work on borrowed data without
building temporary lists, and lifetimes that let the compiler prove a result cannot outlive the
data it points into. Together they let search hand back titles without cloning them.

## What we built

`crates/holm-core/src/search.rs` adds `Session::search(&Query)`. The query holds typed text, an
optional item type, a category filter, a favourites flag, a view (active or trash) and a sort. The
result is a list of `ItemSummary<'a>` values that borrow their title and subtitle straight from the
unlocked session. Only public fields are matched (title, username, URLs, chain, category name);
passwords, notes, addresses and phrases are never read. Ties always break by item id, so the order
is stable.

## Rust ideas in this task

### 1. A struct that borrows: `ItemSummary<'a>`

```rust
pub struct ItemSummary<'a> {
    pub id: ItemId,
    pub title: &'a str,
    pub subtitle: Option<&'a str>,
    // ...
}

pub fn search(&self, query: &Query) -> Result<Vec<ItemSummary<'_>>, CoreError>
```

`'a` is a lifetime: a name for "as long as the thing I point into lives". `'_` in the return type
means "the lifetime of `&self`". While you hold the summaries, the session cannot be locked or
changed, because that would free the strings. The compiler checks this; no copy is needed.

In Kotlin you'd write `data class ItemSummary(val title: String)`. The JVM keeps the string alive
for you with the garbage collector, so there is no lifetime to name. Rust has no collector, so the
borrow itself is the proof.

### 2. Iterator chains: `filter`, `map`, `collect`

```rust
let mut hits: Vec<&Item> = data
    .items
    .iter()
    .filter(|i| query.item_type.is_none_or(|t| i.item_type() == t))
    .filter(|i| !query.favourites_only || i.favourite())
    .collect();
```

Each `filter` is lazy: nothing runs until `collect` pulls items through. No intermediate `Vec` is
built between the filters. `.iter()` yields `&Item`, so `hits` holds references, not copies.

In Kotlin you'd write `items.asSequence().filter { ... }.filter { ... }.toList()`. The
`asSequence()` there is what makes Kotlin lazy too; Rust iterators are lazy by default.

### 3. Closures

```rust
.filter(|i| match query.view {
    View::Active => i.trashed().is_none(),
    View::Trash => i.trashed().is_some(),
})
```

`|i| ...` is a closure. It reads `query` from the surrounding function without being passed it
(it borrows `query`). The compiler picks the lightest way to capture: by reference here.

In Kotlin you'd write `filter { i -> ... }`, and `it` is the implicit name. Same idea, but Rust
states the borrow rules at compile time.

### 4. Sorting with `Ordering::then_with`

```rust
hits.sort_by(|a, b| {
    b.updated()
        .cmp(&a.updated())
        .then_with(|| a.id().cmp(&b.id()))
});
```

`cmp` returns an `Ordering` (`Less`, `Equal`, `Greater`). `then_with` runs its closure only when
the first comparison is `Equal`, so it is a tie-breaker. Swapping `a` and `b` in the first
comparison sorts newest first.

In Kotlin you'd write `sortedWith(compareByDescending<Item> { it.updated }.thenBy { it.id })`.
Kotlin's `thenBy` is the same tie-break idea.

### 5. `#[default]` on enum variants

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    TitleAsc,
    UpdatedDesc,
    CreatedDesc,
}
```

`#[derive(Default)]` on an enum needs to know which variant is the default; `#[default]` marks it.
`Query::default()` then gives "all active items, by title" with no extra code.

In Kotlin you'd write a default parameter value, `sort: Sort = Sort.TitleAsc`. Rust has no default
arguments, so the default lives on the type.

### 6. A Debug that hides the text

`Query` has a hand-written `Debug` that prints `text_len` and never the text, so a stray
`{:?}` in a log cannot leak what the user typed. A test pins this.

## Exercises

1. In `search.rs`, add a `Sort::TitleDesc` variant (reverse of `TitleAsc`, ties still by id) and a
   test for it. Check: `cargo test -p holm-core --locked search`
2. Write a function `fn longest<'a>(a: &'a str, b: &'a str) -> &'a str` in a scratch test and try
   to return it from a block where one input has already been dropped. Read the compiler error,
   then fix it. Check: `cargo test -p holm-core --locked --lib`
3. Replace the three `filter` calls on type, favourites and view with one `filter` that uses `&&`.
   Does the behaviour change? Does it read better? Check: `cargo test -p holm-core --locked search`

## Read next

- [The Rust Programming Language, ch. 10.3: Validating references with lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html)
- [The Rust Programming Language, ch. 13.2: Processing a series of items with iterators](https://doc.rust-lang.org/book/ch13-02-iterators.html)
- [std::cmp::Ordering](https://doc.rust-lang.org/std/cmp/enum.Ordering.html)
