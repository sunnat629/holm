# A second schema

## Why this matters

Postcard writes fields in order without field names. Adding `fields` to the old item
DTO would make its decoder consume the next item's bytes as a field list. A serde
default cannot tell it where the old item ended.

## What we built

The two-byte little-endian body version selects a separate wire type. Schema 1
keeps its original structs and gives each decoded item an empty field list. Schema 2
puts custom fields last on each item. Today every save writes schema 3, which has the
same layout plus recovery codes ([Lesson 61](61-recovery-codes-and-schema-3.md)). The sealed schema-1
golden stays unchanged. The header and encryption format stay at version 1.

Custom values keep secrets in wiping wrappers. The decoder bounds lists and
strings, validates dates and labels, and sorts a valid permutation of field
positions. Duplicate or missing positions fail. Debug output shows kinds and
lengths, never labels or values.

## Rust ideas in this task

### A version selects a DTO

```rust
let (wire, leftover) = postcard::take_from_bytes::<BodyInV1>(rest)
    .map_err(|_| BodyError::Malformed)?;
```

Schema 2 uses `BodyIn` at the same point. Both reject leftover bytes and validate
the decoded values. In Kotlin you'd write an explicit version discriminator and
a second DTO, analogous to a `serialVersionUID` plus a migration, rather than a
defaulted property on the old DTO. The identifier alone does not migrate data.

### The enum owns the kind

```rust
pub enum FieldValue {
    Text(Text),
    Secret(SecretText),
    MultilineSecret(SecretText),
    Date(CalendarDate),
    RecoveryCodes(Vec<RecoveryCode>),
}
```

`RecoveryCodes` came later, in schema 3. There is no separate kind flag that could
label a secret as plain text.
In Kotlin you'd write a `sealed interface FieldValue` with one class per kind.
Rust also prevents accidental copies: `FieldValue` has no `Clone` implementation,
so a secret value is moved, never duplicated. A test in `fields.rs` checks this.
Rust also prevents accidental copies: these values have no `Clone` implementation.

### UTC days need floor division

```rust
let days = secs.div_euclid(86_400);
```

One second before the Unix epoch belongs to the previous day. Truncating division
would put it on day zero. In Kotlin you'd write `Math.floorDiv(secs, 86_400L)`.
Holm checks the supported year range before converting back to a calendar date.

## Try it

1. Add a schema-1 migration case with a trashed login and confirm its timestamps
   survive. `cargo test -p holm-core --locked --lib v1_then_encode_is_v2`
2. Add a three-field permutation and check that the second encoding is stable.
   `cargo test -p holm-core --locked --lib permuted_positions_encode_in_order`
3. Add checks for the last second of 1999 and the first second of 2000.
   `cargo test -p holm-core --locked --lib unix_epoch_is_1970_01_01`

## Read next

- Previous: [Lesson 51](51-custom-fields.md)
- Next: [Lesson 53](53-labels-dates-and-secrets.md)
- [The index](README.md)

- [The body codec](../../crates/holm-core/src/body.rs)
- [Wire types and bounds](../../crates/holm-core/src/wire.rs)
- [Custom fields and calendar dates](../../crates/holm-core/src/fields.rs)
