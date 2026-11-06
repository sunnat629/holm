# Recovery codes and schema 3

## Why this matters

Many sites give out one-time recovery codes. The user prints them, or keeps them
somewhere safe, and crosses each one off after use. A vault is a good place for them,
but a code is a secret like any other.

A new kind of field must not break the vaults people already have. It must not let a
crafted file ask for a huge list. It must not show a code in a log or a debug print.

Holm appends one enum variant, caps the count while it parses, and gives the type a
`Debug` that hides the code.

## What we built

A custom field can now hold recovery codes: 1 to 20 of them, each marked used or not.
A code is one line, at most 64 bytes, with no outer spaces, and it may not start with
`*`.

This is body schema 3. It is the schema 2 layout plus one more value kind. A vault
saved as schema 2 still opens, and the next save writes schema 3.

In an export, the codes go in one cell, one code per line. A used code has a `*` in
front. That is why no code may start with `*`.

## Rust ideas in this task

### Append a variant, keep the bytes

```rust
/// Variant order is the postcard index. Index 4, `RecoveryCodes`, is new in schema 3.
#[derive(Deserialize)]
enum CustomValueIn {
    Text(WireStr),
    Secret(WireStr),
    MultilineSecret(WireStr),
    Date(DateWire),
    RecoveryCodes(BoundedVec<RecoveryCodeIn, MAX_RECOVERY_CODES>),
}
```

Postcard has no field names. An enum is written as its variant index, then the value.
`Text` is 0, `Secret` is 1, `MultilineSecret` is 2 and `Date` is 3. So the new variant
goes last, as 4. Every old byte keeps its meaning.

One code `A`, unused, is written as 4 (the tag), 1 (one entry), 1 (a string of one
byte), 65 (`A`) and 0 (`used` is false).

If we had put the new variant in the middle, every later tag would shift, and old
vaults would decode as the wrong kind. The order of the variants is the file format.

An old Holm cannot write tag 4. So a schema 2 body that holds it is wrong, and
`decode` says so:

```rust
if version == BODY_SCHEMA_V2 && wire.items.iter().any(|i| i.has_recovery_codes()) {
    return Err(BodyError::Malformed);
}
```

A Holm built before schema 3 reads the version number first and refuses with
`NewerSchema(3)`. It never tries to guess what tag 4 means.

In Kotlin you'd add one more subclass to a `sealed interface`, and the compiler would
flag every `when` that has no `else`. A protobuf `oneof` is different. Its tags are
field numbers you choose, and an old reader skips a number it does not know. Postcard
cannot skip, because it does not say how long a value is. So Holm checks the version
first.

### Cap the count while parsing

```rust
let hint = seq.size_hint().unwrap_or(0);
if hint > MAX {
    return Err(de::Error::invalid_length(hint, &self));
}
let mut v = Vec::with_capacity(hint.min(PREALLOC_CAP));
while let Some(x) = seq.next_element()? {
    if v.len() == MAX {
        return Err(de::Error::invalid_length(MAX + 1, &self));
    }
    v.push(x);
}
```

`BoundedVec<RecoveryCodeIn, MAX_RECOVERY_CODES>` is a list with its limit in the type.
The `const MAX` is part of the type, so the code list can never accept 21.

The file says how many entries follow. Holm reads that number first. If it is over 20,
the list is refused before one entry is read or one slot is reserved. A list that lies
about its length, and runs on past 20, is refused at the 21st.

In Kotlin you'd check `count` before you call `ArrayList(count)`. A list built from a
number in the file can ask for gigabytes.

### A `Debug` that hides the code

```rust
impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCode")
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}
```

`#[derive(Debug)]` would print every field, and the code is a field. So we write the
trait by hand and list only `used`. `finish_non_exhaustive` adds `..` to show that
something was left out.

`SecretText` already prints `[REDACTED]`. This gives a second guard: even if someone
later changes the field type, the print still has no code in it. A test checks that
`EXAMPLE` never shows up in the output.

In Kotlin you'd override `toString` in a `data class`, because the generated one
prints every property.

### `take(MAX + 1)`: stop reading a paste early

```rust
let codes: Vec<RecoveryCode> = text
    .lines()
    .map(str::trim)
    .filter(|line| !line.is_empty())
    .take(MAX_RECOVERY_CODES + 1)
    .map(|line| {
        // ...
        RecoveryCode::new(SecretText::new(code.to_owned()), used)
    })
    .collect();
check_codes(&codes)?;
```

Iterators in Rust are lazy. Nothing runs until `collect` pulls a value, and `take`
stops pulling after 21. A paste of 10 000 lines allocates 21 entries, and the other
9 979 lines are never read.

Why 21 and not 20? The limit is 20, so 21 is the first count that proves the paste is
too long. `check_codes` sees 21 and returns `BadCodeCount`. If we took only 20, a
paste of 21 lines would pass as if it had 20.

In Kotlin, `lines().asSequence().take(21)` is the same idea. Without `asSequence`, a
Kotlin `map` builds the whole list first.

### One line per code, one buffer for the cell

```rust
// '*' marks a used code in export, so a code may not start with it.
if text != text.trim()
    || text.starts_with('*')
    || text.chars().any(is_forbidden_display_char)
{
    return Err(FieldError::ForbiddenChar(Field::CustomValue));
}
```

The export cell has no room for a second column. So the format is plain: the codes
joined by `\n`, and a `*` in front of a used code. Reading is the reverse. A rule
that a code may not start with `*` keeps the two directions the same. A code that is
not trimmed is refused too, because reading would trim it, and the round trip would
change it.

The cell holds secrets, so it must not grow:

```rust
let mut out = Zeroizing::new(String::with_capacity(len));
for (i, code) in codes.iter().enumerate() {
    if i > 0 {
        out.push('\n');
    }
    if code.used {
        out.push('*');
    }
    out.push_str(code.code.expose());
}
debug_assert_eq!(out.len(), len, "codes cell measure and fill disagree");
```

`len` is worked out first from the codes. The `String` is made at its final size, so
`push_str` never has to move it to bigger memory. A move would leave an old copy of
the codes behind, and nothing would wipe it. `Zeroizing<String>` wipes the one buffer
when the cell is dropped. The test checks that `capacity` equals `len`.

In Kotlin you'd use `StringBuilder(len)`. The difference is that the JVM may copy a
`String` at any time, and you cannot wipe it.

## Try it

1. In `fields.rs`, add a test that `parse_recovery_codes` of 10 000 lines of
   `EXAMPLE` gives `FieldError::BadCodeCount`.
   `cargo test -p holm-core --locked --lib fields::tests`
2. In `code_65_bytes_invalid` (in `body.rs`, inside `mod schema2`), add `"EXAMPLE "`
   to the list of bad codes. Expect `BodyError::Invalid`.
   `cargo test -p holm-core --locked --lib body::tests::schema2::code_65`

## Read next

- [Custom fields and recovery codes](../../crates/holm-core/src/fields.rs)
- [Wire types and `BoundedVec`](../../crates/holm-core/src/wire.rs)
- [Body decode and the schema 2 check](../../crates/holm-core/src/body.rs)
- [Iterators are lazy](https://doc.rust-lang.org/book/ch13-02-iterators.html)
