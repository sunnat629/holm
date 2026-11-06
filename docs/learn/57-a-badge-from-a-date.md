# 57. A badge from a date

## Why this matters

A reminder only helps if you see it without going to look for it. Holm adds two things
to the list:
- one short line under an item, such as "Expires in 5 days";
- an **Expiring** chip that keeps only the items whose reminder is close or already
  past.

Two rules shape the work:

- **A frame must not walk the vault.** egui redraws many times a second. If each frame
  searched every item and compared dates, a big vault would make the window slow.
  Instead the badge is worked out once, when the rows are built, and stored as a small
  `Copy` value.
- **The badge must not carry a secret.** A custom field can hold a password or an SSH
  key. The badge reads only the reminder date, never the field's value or label. Its
  text is just a day count, so it is safe for AccessKit (the screen-reader tree) to
  read it aloud.

Days are counted in UTC, because Holm stores no timezone. Near midnight the badge can
be one local day early or late. That is an accepted risk.

## What we built

- `ExpiryBadge` in `crates/holm-gui/src/rows.rs`: `InDays(u32)` or `Expired`. It is a
  copy of the core's `ExpiryStatus`, so a row never borrows the session.
- A new field on `ItemRow`: `expiry_badge: Option<ExpiryBadge>`. `build_rows` takes
  `today: CalendarDate` and fills the badge from `ItemSummary::soonest_expiry`.
- `expiry_badge_line` in `messages.rs`, which gives the wording: `Expires today`,
  `Expires in 1 day`, `Expires in N days` or `Expired`.
- The `CHIP_EXPIRING` label and an `expiring: bool` on `VaultView`. The chip sets
  `Query.expiring_only`. It sits beside the category chips and does not replace them.
- Before each frame, `HolmApp` hands the view today's UTC day from its own clock. The
  session's search reads the same wall time, so the badge and the chip always agree.
  When the day changes, the rows are rebuilt.

## Rust ideas in this task

### A `Copy` enum as a snapshot

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryBadge {
    InDays(u32),
    Expired,
}
```

A `Copy` type is duplicated bit for bit when you assign it, the way an integer is.
This enum owns no heap memory, so a copy costs nothing.

It holds only a number, so deriving `Debug` is safe. On a type that holds secrets,
Holm writes `Debug` by hand.

In Kotlin you'd write a `sealed interface ExpiryBadge` with
`data class InDays(val n: Int)` and `object Expired`. You would map it in the
`ViewModel` when building the list, not inside a `@Composable`.

### `From` to copy between layers

```rust
impl From<ExpiryStatus> for ExpiryBadge {
    fn from(status: ExpiryStatus) -> ExpiryBadge {
        match status {
            ExpiryStatus::InDays(n) => ExpiryBadge::InDays(n),
            ExpiryStatus::Expired => ExpiryBadge::Expired,
        }
    }
}
```

This `match` has no `_` arm. If the core ever adds a third status, this code stops
compiling until someone decides how the GUI shows it.

In Kotlin you'd write `fun ExpiryStatus.toBadge() = when (this) { … }`, an exhaustive
`when` over a sealed type.

### Pass today in, don't read the clock

```rust
pub fn build_rows(
    summaries: &[ItemSummary<'_>],
    categories: &[Category],
    today: CalendarDate,
    now: Timestamp,
    utc_offset_secs: i32,
) -> Vec<ItemRow> {
```

`build_rows` never reads the time. The caller passes the day in, so a test can choose
the day and get the same answer every run. (`now` and `utc_offset_secs` came later,
for the "updated" label in [Lesson 59](59-scroll-cards-and-clocks.md). They follow
the same rule.)

In the app, the day comes from the clock that `HolmApp` already owns. The headless
tests swap that clock for a `TestClock`, which the test can control.

In Kotlin you'd inject a `java.time.Clock`, or pass in a `LocalDate`, rather than
call `LocalDate.now()` inside the mapper.

### Literal patterns before the general one

```rust
match badge {
    ExpiryBadge::InDays(0) => "Expires today".to_owned(),
    ExpiryBadge::InDays(1) => "Expires in 1 day".to_owned(),
    ExpiryBadge::InDays(n) => format!("Expires in {n} days"),
    ExpiryBadge::Expired => "Expired".to_owned(),
}
```

Rust tries the arms from top to bottom. The `0` and `1` arms match before `n` catches
everything else, which is why the list never says "1 days".

In Kotlin you'd write `when { n == 0 -> …; n == 1 -> …; else -> … }`.

### Two filters, two fields

The category chip is a `CategoryFilter` value. The Expiring chip is a separate
`bool`.

If "expiring" were a `CategoryFilter` variant, you could pick only one of the two.
As two fields they combine: Work plus Expiring shows only the Work items that are
due.

In Kotlin you'd keep two `StateFlow`s and `combine` them, rather than add an
`EXPIRING` value to a category enum.

## Try it

1. Delete the `InDays(1)` arm in `expiry_badge_line`, run the tests and see which one
   fails. Then put the arm back.
   `cargo test -p holm-gui --locked --lib messages`
2. In `badge_comes_from_the_soonest_reminder` (in `rows.rs`), add an item titled `d`
   with `reminder(0)`, and one titled `e` with `reminder(5)` and `reminder(-3)`.
   Predict both badges first: `InDays(0)` and `Expired`. Remember the rows are sorted
   by title.
   `cargo test -p holm-gui --locked --lib rows`
3. In `tests/expiring.rs`, add a test with an item that has no category and a
   reminder exactly 30 days away. Click the "No category" chip, then the Expiring
   chip. Decide first whether the item should still show, then check.
   `cargo test -p holm-gui --locked --test expiring`

## Read next

- The Rust Book, 6.2: [The `match` control flow construct](https://doc.rust-lang.org/book/ch06-02-match.html).
- The Rust Book, 10.2: [Traits](https://doc.rust-lang.org/book/ch10-02-traits.html), for `From`.
- Lesson [53](53-labels-dates-and-secrets.md), where `expiry_status` and the UTC day
  were built.
- Previous: [Lesson 56](56-paint-the-secret.md), paint the secret.
- Next: [Lesson 58](58-the-chapter-and-the-bytes.md), the chapter and the bytes.
- All lessons: [the index](README.md).
