# Labels, dates and secrets

## Why this matters

Search folds text into a buffer so it can compare it. If that loop called
`SecretText::expose`, the secret would be copied into the buffer. A reminder
check that called the clock itself could not be moved one day in a test, and it
could disagree with a caller that had already chosen "today".

## What we built

`insert_field`, `remove_field` and `move_field` edit the list in place and check
it again. The eleventh field and a bad index are errors, and the list stays as
it was. Presets supply labels and kinds only.

`expiry_status`, `soonest_expiry` and `is_expiring` take a `CalendarDate` for
today. They do not read a clock. `Session::search` asks the session clock once,
keeps an item when `expiring_only` is set and the soonest reminder is inside the
`EXPIRING_WITHIN_DAYS` window (including dates already past), and matches custom
labels. It does not match
secret values, text values or dates.

`Session::set_custom_fields` replaces the list and bumps `updated`. If the vault
has no room to save, the previous list and the previous `updated` are put back.

## Rust ideas in this task

### Pass today in

```rust
pub fn expiry_status(expiry: CalendarDate, today: CalendarDate) -> ExpiryStatus {
    let delta = i64::from(epoch_day(expiry)) - i64::from(epoch_day(today));
    if delta < 0 {
        return ExpiryStatus::Expired;
    }
    ExpiryStatus::InDays(u32::try_from(delta).unwrap_or(u32::MAX))
}
```

The function is pure. A test picks two dates and asserts the status. In Kotlin
you'd pass a `Clock` into the use case and call `clock.instant()` at the edge,
not `System.currentTimeMillis()` inside the matcher.

### The search loop does not call `expose`

```rust
if item
    .fields()
    .iter()
    .any(|field| contains(needle, field.label()))
{
    return true;
}
```

`label` is ordinary display text. `CustomField::value` is not called, so a
`SecretText` never enters `fold`. In Kotlin you'd read `field.label` and leave
`field.secret` untouched, instead of `secret.use { it.contains(needle) }`.

### `mem::replace` moves the old value out

`std::mem::replace` puts a new value behind a `&mut` and hands back the old one.
The command line uses it to take the field edit out of its arguments:

```rust
match mem::replace(&mut args.fields, FieldEdit::None) {
```

Nothing is copied: the old value moves out and a placeholder moves in.
`Session::set_custom_fields` uses the same kind of move. The new list goes into
the item and the old list is kept, so it can be put back if the save fails.
There is no `Clone` on `CustomField`, so no secret is copied. In Kotlin you'd
keep the previous list and assign it back only for the failure you can roll
back.

## Try it

1. Add a date 400 days after `2026-11-05` to `expiry_status_days` and expect
   `InDays(400)`.
   `cargo test -p holm-core --locked --lib fields::tests::expiry_status_days`
2. In `search_skips_text_value`, store a date field whose value is `2026-11-05`
   and show that searching that text misses while the label hits.
   `cargo test -p holm-core --locked --lib search::tests::search_skips_text_value`
3. Extend `insert_remove_move_roundtrip` so the last field moves to index 0, and
   check the new order.
   `cargo test -p holm-core --locked --lib fields::tests::insert_remove_move_roundtrip`

## Read next

- Previous: [Lesson 52](52-a-second-schema.md)
- Next: [Lesson 54](54-four-cells-a-field.md)
- [The index](README.md)

- [Custom fields and calendar dates](../../crates/holm-core/src/fields.rs)
- [Search](../../crates/holm-core/src/search.rs)
- [Writing tests](https://doc.rust-lang.org/book/ch11-01-writing-tests.html)
