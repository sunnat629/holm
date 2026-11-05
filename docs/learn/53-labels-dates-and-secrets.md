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
keeps an item when `expiring_only` is set and the soonest reminder is inside 30
days (including dates already past), and matches custom labels. It does not match
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

### `mem::replace` keeps the old list for undo

```rust
let old_fields = std::mem::replace(&mut data.items[pos].fields, fields);
data.items[pos].updated = now;
self.commit_or_undo(move |d| {
    d.items[pos].fields = old_fields;
    d.items[pos].updated = old_updated;
})
```

The new list moves in. The old list moves into the undo closure. There is no
`Clone` on `CustomField`, so the secret is not copied. In Kotlin you'd keep the
previous list and assign it back in a `finally` only for the failure you can
roll back. Here that failure is "the vault has no room".

## Exercises

1. Add a date 400 days after `2026-11-05` to `expiry_status_days` and expect
   `InDays(400)`.
   `cargo test -p holm-core --locked --lib fields::expiry_status_days`
2. In `search_skips_text_value`, store a date field whose value is `2026-11-05`
   and show that searching that text misses while the label hits.
   `cargo test -p holm-core --locked --lib search::search_skips_text_value`
3. Extend `insert_remove_move_roundtrip` so the last field moves to index 0, and
   check the new order.
   `cargo test -p holm-core --locked --lib fields::insert_remove_move_roundtrip`

## Read next

- [Custom fields and calendar dates](../../crates/holm-core/src/fields.rs)
- [Search](../../crates/holm-core/src/search.rs)
- [Writing tests](https://doc.rust-lang.org/book/ch11-01-writing-tests.html)
