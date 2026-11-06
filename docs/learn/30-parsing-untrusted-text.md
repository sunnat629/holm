# Lesson 30: Parsing untrusted text

## Why this matters

An import file comes from outside Holm and is full of passwords. A parser for it must never
crash, never run out of stack, never echo what it read into an error, and never leave a copy of a
password in freed memory. Off-the-shelf CSV and JSON crates do none of the last part, so Holm
reads both formats with a small amount of its own std-only code.

## What we built

`crates/holm-core/src/plain/` holds three pieces. `CsvReader` reads strict RFC 4180 CSV one record
at a time. `parse_json_rows` reads one JSON array of flat objects whose values are strings or
`null`. `quoted_len` and `push_quoted` write a CSV cell. Every decoded cell is a `Cell`
(`Zeroizing<String>`), allocated once and wiped on drop. Errors are `PlainError`: a line number or
a fixed reason, never any text from the file.

## Rust ideas in this task

### 1. Byte offsets, not `char` indices

```rust
let bytes = self.src.as_bytes();
let mut i = start;
while let Some(&b) = bytes.get(i) {
    match b {
        b',' | b'\r' | b'\n' => break,
        b'"' => return Err(bad),
        _ => i += 1,
    }
}
self.pos = i;
return Ok(Span::Plain { start, end: i });
```

A Rust `&str` is UTF-8 bytes. `é` is two bytes and an emoji is four, so "the 5th character" costs a
walk from the start. The reader keeps byte offsets instead and looks at bytes with `get(i)`, which
returns `None` past the end instead of panicking.

Slicing `&src[start..end]` panics if an end falls inside a multi-byte character. The reader is
safe because it only ever stops on ASCII bytes (`"`, `,`, `\r`, `\n`). In UTF-8 every byte of a
multi-byte character is 0x80 or higher, so an ASCII byte is always a character boundary.

In Kotlin you'd write `src.indexOf(',', start)`. Kotlin strings are UTF-16, so an index counts
16-bit units and an emoji takes two. Either way, an index is a position in an encoding, not a count of
what a person sees.

### 2. A small state machine with `match`

```rust
loop {
    match bytes.get(i) {
        None => return Err(bad),
        Some(b'"') if bytes.get(i + 1) == Some(&b'"') => i += 2,
        Some(b'"') => break,
        Some(b'\r') if bytes.get(i + 1) == Some(&b'\n') => {
            i += 2;
            self.line += 1;
        }
        Some(b'\r' | b'\n') => {
            i += 1;
            self.line += 1;
        }
        Some(_) => i += 1,
    }
}
```

This is the inside of a quoted CSV cell. Each arm is one rule: end of input means the quote was
never closed, `""` is an escaped quote, a lone `"` closes the cell, and a line end is kept but
counted. Guards (`if ...`) look one byte ahead. The compiler checks that the arms cover every
case, so there is no forgotten state.

The JSON reader has a fixed shape (an array of flat objects), so its states are just the loops in
`parse_json_rows` and `Parser::object`. There is no recursion: a `[` or `{` where a value should be
is refused on the spot. A file of 100,000 `[` is an error, not a stack overflow.

In Kotlin you'd write a `sealed class State` with `InQuotes`, `AfterQuote` and so on, and a
`when (state)` over it. Rust's `match` on bytes plus position does the same job without objects.

### 3. Measure before you allocate

```rust
let raw = &self.src[start..end];
let mut cell = Cell::new(String::with_capacity(quoted_decoded_len(raw)));
fill_quoted(&mut cell, raw);
```

When a `String` runs out of room it moves its bytes to a bigger buffer and frees the old one.
`Zeroizing` wipes only the buffer it holds when it drops, so the freed copy would keep the
password in memory. The fix is to scan the cell first, compute its final length, allocate once,
and fill without growing.

For CSV the length is exact: the raw text minus one byte per `""` pair. For JSON the raw length is
an upper bound, because every escape gets shorter when decoded (`\n` is 2 bytes for 1, `é` is
6 bytes for 2). The fill functions end with `debug_assert_eq!(out.capacity(), cap)`, so every test
run checks that nothing grew. The writer works the same way: `quoted_len` says how many bytes
`push_quoted` will write, so export can allocate the whole file once.

A cell past `max_cells` is still scanned (a bad quote there is still an error) but never
allocated. One line of 1,000,000 commas allocates at most `max_cells` empty cells, not a million.

In Kotlin you'd write `buildString(capacity) { ... }`. The capacity there is a hint for speed.
Here it is a security rule.

### 4. Errors carry a line, never content

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlainError {
    Malformed { line: u64 },
    TooManyRows,
    TooManyColumns,
}
```

Errors end up in logs, dialogs and bug reports. If an error held the bad cell, a malformed
password line would print the password. `PlainError` is `Copy` and holds only numbers, so it
cannot hold text even by mistake. `JsonObject` has a hand-written `Debug` that prints the line and
the field count, and `CsvReader` has no `Debug` at all, because it holds the whole source. A test
plants `EXAMPLE-leak` in a broken file and checks that the error's `Debug` lacks `EXAMPLE`.

In Kotlin you'd write `sealed class PlainError { data class Malformed(val line: Long) : PlainError() }`
and resist the urge to add `val text: String`.

### 5. A property test against an oracle crate

```rust
let src = if pretty {
    serde_json::to_string_pretty(&rows).unwrap()
} else {
    serde_json::to_string(&rows).unwrap()
};
let parsed = parse_json_rows(&src, 6, 6).unwrap();
```

`serde_json` is a well-tested JSON library. It is a dev-dependency only, so it never ships. The
property test lets `proptest` invent maps of random Unicode keys and values (quotes, backslashes,
control characters, emoji), has `serde_json` write them, and checks that Holm reads back the same
pairs. A second property runs the other way: anything Holm accepts, `serde_json` must accept too.
For CSV there is no oracle, so the test is a round trip: write with `push_quoted`, read with
`CsvReader`, compare.

In Kotlin you'd write a Kotest `checkAll(Arb.list(Arb.map(...)))` and compare against
kotlinx.serialization.

## Try it

1. Add a test that `CsvReader` reads `"a""""b"` as the cell `a""b`, and that its capacity equals
   its length. Check: `cargo test -p holm-core --locked plain::csv`
2. Change `fill_string` to allocate `raw.len() / 2` instead of `raw.len()` for a quick
   experiment, run the JSON tests, and read which assertion fails and why. Then undo it.
   Check: `cargo test -p holm-core --locked plain::json`
3. A UTF-8 byte order mark (`\u{feff}`) at the start of a JSON file is refused today. Write a test
   that pins this, then decide whether a spreadsheet's CSV export with a BOM should keep it in the
   first header cell. Check: `cargo test -p holm-core --locked plain`

## Read next

- [The Rust Programming Language, ch. 8.2: Storing UTF-8 encoded text with strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- [std::string::String::with_capacity](https://doc.rust-lang.org/std/string/struct.String.html#method.with_capacity)
- [RFC 4180: Common format for CSV files](https://www.rfc-editor.org/rfc/rfc4180)
- Previous: [Lesson 29: Iterators and lifetimes](29-iterators-and-lifetimes.md)
- Next: [Lesson 31: Hostile input, all or nothing](31-hostile-input-all-or-nothing.md)
- [The index](README.md)
