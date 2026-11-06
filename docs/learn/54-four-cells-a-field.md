# Four cells a field

## Why this matters

A custom field can hold a newline, a quote, or both. If the export buffer grows
while that text is being written, the old allocation is freed with the secret
still in it. Holm wipes the buffer it keeps. It cannot wipe a copy it already
dropped.

A nested JSON object for the same field would be a second parser. The reader
Holm already has accepts a flat object whose values are strings or null.

## What we built

The CSV header keeps its first 14 names, then adds four cells for each of the
10 slots: `field1_label`, `field1_kind`, `field1_value`, `field1_expiry`,
through `field10_expiry`. That is 54 columns, which fits under
`MAX_IMPORT_COLUMNS`.

`Session::export_json` writes one JSON array of those same keys, in that order,
after the same password check as CSV. Every value is a JSON string. An empty
cell is `""`.

Kind cells are `text`, `secret`, `multiline`, `date` or `codes`. Dates are
`YYYY-MM-DD`.
An empty slot is absent. Slots are packed from 1, so a later slot filled while
an earlier one is empty is `FieldGap` and the row is skipped. A bad kind is
`BadFieldKind`. A bad date is `BadDate`. None of those errors carries the cell.

A secret value is moved out of its cell. It is not trimmed.

Browser files do not gain these columns.

## Rust ideas in this task

### Measure, then fill, when the cell holds a newline

Every cell is quoted. A newline counts as one byte, the quotes around the cell
add two, and each `"` inside the cell becomes `""`, which adds one more. The
export adds those lengths up first:

```rust
let mut total = row_len(&EXPORT_COLUMNS);
for item in items {
    total = total.saturating_add(with_cells(item, categories, row_len));
}

let mut out = Zeroizing::new(String::with_capacity(total));
```

Then it fills that one `String` and checks that the length came out the same.

The buffer never grows, so the secret is not copied into a discarded
allocation. In Kotlin you'd size a `StringBuilder` before you append, instead
of letting `append` grow and copy.

### The JSON count and the JSON write share one length

```rust
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}
```

A newline in a cell is the two characters `\` and `n` in the file, so the JSON
array stays one line. `json_string_len` sums `escaped_len`. `push_json_string`
writes those same escapes and then checks that the length matches and that the
`String` did not grow. In Kotlin you'd keep one function that both counts and
writes the escapes. Two copies of the rules drift.

### Flat keys, one parser

```rust
for (i, (key, cell)) in EXPORT_COLUMNS.iter().zip(cells.iter()).enumerate() {
    if i > 0 {
        push_fitting(out, ",");
    }
    push_fitting(out, "\"");
    push_fitting(out, key);
    push_fitting(out, "\":");
    push_json_string(out, cell);
}
```

Each custom field is four string columns on the same object. The keys are
ASCII, so they are copied in raw. Only the cell goes through the escape
counter. In Kotlin you'd write a list of column strings. A `JsonObject` nested
in the cell would need its own parser beside the one that already reads flat
objects.

## Try it

1. In `export_header_has_54_columns`, assert that `EXPORT_COLUMNS[18]` is
   `field2_label`.
   `cargo test -p holm-core --locked --lib export::tests::export_header_has_54_columns`
2. In `writer_length_matches_fill`, add a sample that holds a quote and a
   newline in one string, `one "two"\nthree`, and keep the length check.
   `cargo test -p holm-core --locked --lib plain::json::tests::writer_length_matches_fill`
3. In `field_gap_is_a_row_error`, add a second row that fills slot 1 and slot 3
   and leaves slot 2 empty, and expect `FieldGap` on that row too.
   `cargo test -p holm-core --locked --lib import::tests::field_gap_is_a_row_error`

## Read next

- Previous: [Lesson 53](53-labels-dates-and-secrets.md)
- Next: [Lesson 55](55-secrets-at-the-prompt.md)
- [The index](README.md)

- [Export](../../crates/holm-core/src/export.rs)
- [JSON reader and writer](../../crates/holm-core/src/plain/json.rs)
- [Import rows](../../crates/holm-core/src/import/row.rs)
- [Strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
