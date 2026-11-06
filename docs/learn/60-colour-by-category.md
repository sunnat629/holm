# Colour by category

## Why this matters

A category colour is a hint, not a fact. Some users cannot tell two hues apart,
and a colour that moves when the user deletes a category would be a bad hint.

Holm takes the colour from the category's own id, keeps every label on screen,
and has a unit test that checks white text can be read on every fill.

## What we built

Each category now has a colour index, which comes from its `CategoryId` and not
from its place in the list. The avatar on a card uses it. The chip for the
category shows a small dot in the same colour, next to the label.

The palette has 8 colours for each theme. The index wraps modulo 8. An item with
no category stays grey.

Colour is never the only signal. The category name stays in the chip and on the
card. A test checks that white text on every fill has a contrast ratio of at
least 4.5 to 1, in both themes. A colour stays put when other categories are
added or removed, because the id does not change.

## Rust ideas in this task

### A newtype with one public accessor

```rust
pub struct CategoryId(pub(crate) u32);

impl CategoryId {
    #[must_use]
    pub fn colour_index(self) -> usize {
        usize::try_from(self.0).unwrap_or(0)
    }
}
```

The field is `pub(crate)`, so only `holm-core` can read the number. The GUI gets
one method that answers one question. It cannot build an id or do sums on it.
`CategoryId` is `Copy`, so `self` by value costs nothing.

In Kotlin you'd use a `@JvmInline value class CategoryId(private val raw: Int)`
with a `colourIndex()` function, and keep `raw` private.

### `usize::try_from(..).unwrap_or(..)`

`usize` has no `From<u32>`, because on a 16-bit target a `u32` may not fit.
`try_from` returns a `Result`. `unwrap_or(0)` turns the failure into colour 0
and never panics. On a Mac the conversion always works, and the fallback is a
colour, not a crash.

In Kotlin `Int.toUInt()` and `toLong()` never fail, so there is no type that
asks you what to do when a number does not fit.

### A pure function for contrast

```rust
fn linearise(channel: u8) -> f32 {
    let c = f32::from(channel) / 255.0;
    if c <= 0.04045 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
}

pub fn contrast_ratio(a: egui::Color32, b: egui::Color32) -> f32 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (lighter, darker) = if la >= lb { (la, lb) } else { (lb, la) };
    (lighter + 0.05) / (darker + 0.05)
}
```

This is the WCAG 2 formula. `f32::from(u8)` is lossless, so no cast is needed.
The function reads no state, so a test can feed it any two colours. White on
black must give 21, and swapping the arguments must give the same number. The
test `every_fill_reads_with_white_text` loops over both palettes and the two
greys and asserts a ratio of at least 4.5. A new palette entry that is too light
fails the build.

In Kotlin you'd use `ColorUtils.calculateContrast` from AndroidX, and a unit
test that loops over your theme colours.

### A closure that takes an `Option` and captures `pick` mutably

```rust
let mut chip = |filter: CategoryFilter, label: &str, dot: Option<egui::Color32>| {
    let clicked = match dot {
        Some(colour) => ui.horizontal(|ui| { /* dot, then label */ }).inner,
        None => ui.selectable_label(current == filter, label).clicked(),
    };
    if clicked {
        pick = Some(filter);
    }
};
```

The closure writes to `pick`, so it borrows `pick` mutably and must be `mut`.
The borrow ends after the last call, so the code after the loop can read `pick`.
`None` draws the All and Uncategorised chips with no dot. `Some(colour)` draws a
category chip with one. One closure covers both, so the click logic is written
once.

In Kotlin a lambda that assigns to a captured `var` is allowed freely. Rust
makes you say `mut` and checks that nobody else reads `pick` while the closure
is alive.

## Check yourself

1. In `avatar.rs` tests, add a case that `avatar_colour(Some(3), true)` equals
   `avatar_colour(Some(11), true)`. Why does it pass?
   `cargo test -p holm-gui --locked --lib widgets::avatar::tests`
2. In `contrast_of_white_and_black_is_21`, add a check that
   `contrast_ratio(c, c)` is 1.0 for any colour `c`. Use a tolerance, not `==`.
3. In `rows.rs`, find the test that reads `category_slot`. Why does it compare
   with `work.colour_index()` and not a list position?

## Read next

- [Colour index](../../crates/holm-core/src/category.rs)
- [Avatar colours and contrast](../../crates/holm-gui/src/widgets/avatar.rs)
- [The category chips](../../crates/holm-gui/src/screens/vault.rs)
- [Closures](https://doc.rust-lang.org/book/ch13-01-closures.html)
