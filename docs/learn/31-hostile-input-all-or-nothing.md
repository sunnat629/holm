# Lesson 31: Hostile input, all or nothing

## Why this matters

An import file is the most dangerous thing Holm reads. It comes from another app, a spreadsheet or
an attacker. It is plain text full of passwords. Holm has to read it without crashing, without
copying a secret into freed memory, without printing a secret in an error, and without leaving the
vault half-imported if something goes wrong at row 4,000.

## What we built

`crates/holm-core/src/import/` turns the cells from lesson 30's parsers into vault items.

- `parse(bytes, format)` checks the size, checks UTF-8, strips one byte order mark and returns an
  `ImportBatch`: the rows that are ready plus a list of rows it skipped (row number and reason).
- A CSV header decides the dialect: Holm's own columns, or a Chrome, Firefox or Safari export.
  JSON is always Holm's own column names.
- `Session::preview_import` counts what would happen. `Session::import` adds the rows, skips
  any row identical in every field to an item already in the vault (or to an earlier row),
  saves, and takes every new item back if the vault grew too large to save.
- Two fuzz targets (`import_csv`, `import_json`) feed random bytes to `parse`.

## Rust ideas in this task

### 1. A header map with `HashMap`

```rust
let mut known: HashMap<&'static str, usize> = HashMap::with_capacity(cells.len());
for (i, cell) in cells.iter().enumerate() {
    match row::canonical(cell) {
        Some(name) => {
            if known.insert(name, i).is_some() {
                return Err(ImportError::DuplicateColumn);
            }
        }
        None => { /* counted as unknown */ }
    }
}
```

`canonical` trims a header cell, compares it case-insensitively against a static table, and
returns the table's `&'static str`. So `URL`, ` url ` and `Website` all become the key `"url"`.
The map stores positions, never header text. That matters: a file with no header row has a
password in row one, and Holm must not copy it into a map.

`insert` returns the old value if the key was already there. Two columns for one field is a file
error, because Holm cannot know which one the user meant.

In Kotlin you'd write `header.withIndex().associateBy({ canonical(it.value) }, { it.index })`, but
`associateBy` keeps the last duplicate silently. Here the duplicate is the error.

### 2. `mem::take` out of a wiping buffer

```rust
fn take(&mut self, col: Col) -> String {
    std::mem::take(&mut *self.cells[col as usize])
}
```

Each cell is a `Zeroizing<String>` that wipes its buffer when dropped. `mem::take` swaps an empty
`String` in and hands back the full one. The heap buffer moves; no byte is copied, so no second
copy of the password exists. The empty `String` left behind owns no buffer, so there is nothing to
wipe. The taken `String` goes straight into a `Text` or a `Secret`, which wipe on drop too.

`.clone()` would also work and would leave a copy of the password for the allocator to reuse.

In Kotlin you'd write `cells[i].also { cells[i] = "" }`. On the JVM that does not help: strings are
immutable and the old one stays on the heap until the garbage collector runs.

### 3. All or nothing with an undo closure

```rust
let start = data.items.len();
for row in rows {
    if let Err(e) = insert_new(data, input, now) {
        data.items.truncate(start);
        return Err(e);
    }
}
self.commit_or_undo(move |d| d.items.truncate(start))?;
```

New items are appended to the end, so "undo" is "cut the list back to its old length". If one
insert fails, the loop cuts and returns. If every insert works but the vault is now too large to
save, `commit_or_undo` runs the closure and the vault in memory matches the file on disk again.
The closure is `move` so it owns `start`, a plain number, and borrows nothing.

Only "too large" undoes. Any other save error (disk full, no permission) keeps the new items in
memory, unsaved, and the session stays dirty, so the user can free space and save again instead
of importing twice. A screen must not say "nothing was imported" after such an error.

The checks that can fail cheaply (the item limit) run before the first insert, so the common
failure never touches the vault at all.

In Kotlin you'd write `db.transaction { rows.forEach { insert(it) } }`, and the database rolls back
on an exception. Holm has no database, so the rollback is a closure you write yourself.

### 4. A bad row is reported by number only

```rust
pub struct RowIssue {
    pub row: usize,
    pub problem: RowProblem,
}
```

`RowProblem` is a list of fixed reasons: `MissingAddress`, `UnusedField`, `ExtraFields` and so
on. None of them holds text from the file. The user sees "row 6: too many fields" and opens the
file to look. A `Cell` prints its content in `Debug`, so no import type that holds one derives
`Debug`; `ImportBatch` has a hand-written `Debug` that prints counts. A property test plants
`EXAMPLE` in random files and checks that no error or `Debug` output contains it.

In Kotlin you'd write `data class RowIssue(val row: Int, val problem: RowProblem)` with an enum,
and never `val line: String`.

### 5. Never guess where a secret goes

A row says what it is (`type`), or Holm infers it from which secret column is filled: `recovery`
means a recovery phrase, `address` means a crypto address, otherwise it is a login. A filled
column that the row's type does not use (a `recovery` cell on a login, a `username` on a note)
is an error for that row, not a silent drop. The user is told to delete the file afterwards, so
a value Holm quietly left out would be gone.

Duplicates follow the same rule. A row is skipped only if it matches an existing item in every
field: type, title, username, URLs, chain, category and every secret. Two recovery phrases both
called "Ledger" are two items. The title and other display fields go into a hash to find
candidates; secrets are then compared in place, never hashed. A password is never moved into the phrase field "because the phrase was
empty". If Holm guessed wrong, a seed phrase could end up in a field that is shown on screen.

Browser exports are logins only, and their extra columns (`guid`, `timeLastUsed`) are ignored by
name. A Safari one-time-password secret is counted and dropped, never stored as a note.

## Exercises

1. Add a test that a Holm CSV with the header `title,URL,website` is refused with
   `ImportError::DuplicateColumn`. Check: `cargo test -p holm-core --locked import::tests`
2. In `Session::import`, change the undo closure to `move |_| {}` and run the tests. Read which
   test fails and why the vault in memory now holds items the file on disk does not. Then undo it.
   Check: `cargo test -p holm-core --locked import_rolls_back`
3. Write a property test that any CSV whose first line is a single random word either fails with
   `UnknownColumns` or parses with zero rows, and that the error's `Debug` never contains the
   word. Check: `cargo test -p holm-core --locked --test import_props`

## Read next

- [std::mem::take](https://doc.rust-lang.org/std/mem/fn.take.html)
- [std::collections::HashMap::insert](https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.insert)
- [Lesson 30: Parsing untrusted text](30-parsing-untrusted-text.md)
